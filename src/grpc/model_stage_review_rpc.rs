//! Experimental model stage review RPCs (#3159): SubmitModelStageReview and
//! DecideModelStageReview.
//!
//! A principal with namespace write submits a version for review at a stage;
//! another principal with namespace write approves or rejects it. The
//! submitter never decides, even as namespace administrator. A decision is
//! final. A submission and a decision each record an operation receipt, and a
//! replay records none. `PromoteModelVersion` reads the review.

use super::model_stage_rpc::{
    authorize_namespace_write, require_stage_key, review_key, visible_version,
};
use super::*;
use crate::sekai::model_stage::{self as domain_stage, ModelStageReview, ReviewState};
use crate::sekai::model_version as domain_model;
use sekai_domain::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind,
};
use std::collections::BTreeMap;

/// The caller's identity and the stage a review request names, after the
/// namespace write check.
struct ReviewCaller {
    principals: Vec<String>,
    actor: String,
    stage: domain_stage::ModelStage,
}

fn review_caller<T: 'static>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    namespace: &str,
    model_name: &str,
    stage: &str,
) -> Result<ReviewCaller, Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let actor = principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let tenant_context = request_tenant_context(service.db.runtime(), req)?;
    authorize_namespace_write(service, &principals, tenant_context.as_ref(), namespace)?;
    require_stage_key(model_name, stage)?;
    let stage = service
        .db
        .runtime()
        .get_model_stage(namespace, model_name, stage)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found(domain_stage::MODEL_STAGE_NOT_FOUND))?;
    Ok(ReviewCaller {
        principals,
        actor,
        stage,
    })
}

async fn submit_model_stage_review(
    service: &SekaiServiceImpl,
    req: Request<SubmitModelStageReviewRequest>,
) -> Result<Response<SubmitModelStageReviewResponse>, Status> {
    let caller = {
        let inner = req.get_ref();
        review_caller(
            service,
            &req,
            &inner.namespace,
            &inner.model_name,
            &inner.stage,
        )?
    };
    let inner = req.into_inner();
    let db = service.db.runtime();
    let version = visible_version(db, &caller.principals, &caller.stage, &inner.version_id)?;
    let review = ModelStageReview {
        namespace: caller.stage.namespace.clone(),
        model_name: caller.stage.model_name.clone(),
        stage: caller.stage.stage.clone(),
        version_id: version.version_id.clone(),
        state: ReviewState::Pending,
        submitted_by: caller.actor.clone(),
        submitted_at_ms: now_millis(),
        decided_by: String::new(),
        reason: String::new(),
        decided_at_ms: 0,
    };
    let operation_id = format!("model-review-{}", uuid::Uuid::new_v4());
    let receipt = review_receipt(&operation_id, &caller.actor, &review, &version);
    if db
        .submit_model_stage_review(&review, &receipt)
        .map_err(Status::internal)?
    {
        return Ok(Response::new(SubmitModelStageReviewResponse {
            review: Some(to_proto_review(review)),
            operation_id,
            replay: false,
        }));
    }
    let existing = db
        .get_model_stage_review(&review_key(&caller.stage, &version.version_id))
        .map_err(Status::internal)?
        .ok_or_else(|| Status::internal("model stage review vanished after submit"))?;
    Ok(Response::new(SubmitModelStageReviewResponse {
        review: Some(to_proto_review(existing)),
        operation_id: String::new(),
        replay: true,
    }))
}

async fn decide_model_stage_review(
    service: &SekaiServiceImpl,
    req: Request<DecideModelStageReviewRequest>,
) -> Result<Response<DecideModelStageReviewResponse>, Status> {
    let caller = {
        let inner = req.get_ref();
        review_caller(
            service,
            &req,
            &inner.namespace,
            &inner.model_name,
            &inner.stage,
        )?
    };
    let inner = req.into_inner();
    let state = match inner.decision.trim() {
        "approve" => ReviewState::Approved,
        "reject" => ReviewState::Rejected,
        _ => {
            return Err(Status::invalid_argument(
                "decision must be approve or reject",
            ));
        }
    };
    let db = service.db.runtime();
    let version = visible_version(db, &caller.principals, &caller.stage, &inner.version_id)?;
    let key = review_key(&caller.stage, &version.version_id);
    let review = db
        .get_model_stage_review(&key)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found(domain_stage::MODEL_STAGE_REVIEW_NOT_FOUND))?;
    if !domain_stage::may_decide_review(&review.submitted_by, &caller.principals) {
        return Err(Status::permission_denied(
            "the submitter of a model stage review cannot decide it",
        ));
    }
    if review.state != ReviewState::Pending {
        return settled(review, state, &caller.principals);
    }
    let decided = ModelStageReview {
        state,
        decided_by: caller.actor.clone(),
        reason: inner.reason.trim().to_string(),
        decided_at_ms: now_millis(),
        ..review
    };
    let operation_id = format!("model-review-{}", uuid::Uuid::new_v4());
    let receipt = review_receipt(&operation_id, &caller.actor, &decided, &version);
    if db
        .decide_model_stage_review(&decided, &receipt)
        .map_err(Status::internal)?
    {
        return Ok(Response::new(DecideModelStageReviewResponse {
            review: Some(to_proto_review(decided)),
            operation_id,
            replay: false,
        }));
    }
    // Another decision won the race.
    let current = db
        .get_model_stage_review(&key)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::internal("model stage review vanished after decide"))?;
    settled(current, state, &caller.principals)
}

/// The answer to a decision on a review that is no longer pending: a replay
/// when the caller already made this decision, otherwise a refusal.
fn settled(
    review: ModelStageReview,
    state: ReviewState,
    principals: &[String],
) -> Result<Response<DecideModelStageReviewResponse>, Status> {
    if review.state == state && principals.contains(&review.decided_by) {
        return Ok(Response::new(DecideModelStageReviewResponse {
            review: Some(to_proto_review(review)),
            operation_id: String::new(),
            replay: true,
        }));
    }
    Err(Status::failed_precondition(
        "model stage review is already decided",
    ))
}

/// The receipt of a submission (an action) or a decision (an approval). The
/// decision's free-text reason stays on the review, not the receipt.
fn review_receipt(
    operation_id: &str,
    actor: &str,
    review: &ModelStageReview,
    version: &domain_model::ModelVersion,
) -> OperationReceipt {
    let kind = if review.state == ReviewState::Pending {
        ReceiptEventKind::ActionPerformed
    } else {
        ReceiptEventKind::ApprovalDecided
    };
    let at_ms = if review.state == ReviewState::Pending {
        review.submitted_at_ms
    } else {
        review.decided_at_ms
    };
    let attributes = BTreeMap::from([
        ("model_name".to_string(), review.model_name.clone()),
        ("stage".to_string(), review.stage.clone()),
        ("version_id".to_string(), review.version_id.clone()),
        ("state".to_string(), review.state.as_str().to_string()),
        ("submitted_by".to_string(), review.submitted_by.clone()),
    ]);
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.into(),
        parent_operation_id: None,
        namespace: review.namespace.clone(),
        operation_class: domain_stage::REVIEW_OPERATION_CLASS.into(),
        initiating_actor: actor.into(),
        schema_version: "model_stage/v1".into(),
        policy_version: "model_stage/v1".into(),
        started_at_ms: at_ms,
        completed_at_ms: Some(at_ms),
        events: vec![OperationReceiptEvent {
            event_id: format!("{operation_id}-{}", review.state.as_str()),
            operation_id: operation_id.into(),
            parent_event_id: None,
            timestamp_ms: at_ms,
            kind,
            surface: kind.surface(),
            actor: actor.into(),
            references: vec![GovernedReference {
                kind: "model_version".into(),
                reference: version.version_id.clone(),
                content_hash: Some(version.digest.clone()),
                disclosed_fields: Vec::new(),
                omitted: false,
                omission_reason: None,
            }],
            attributes,
        }],
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    }
}

fn to_proto_review(review: ModelStageReview) -> super::ModelStageReview {
    super::ModelStageReview {
        namespace: review.namespace,
        model_name: review.model_name,
        stage: review.stage,
        version_id: review.version_id,
        state: review.state.as_str().to_string(),
        submitted_by: review.submitted_by,
        submitted_at_ms: review.submitted_at_ms,
        decided_by: review.decided_by,
        reason: review.reason,
        decided_at_ms: review.decided_at_ms,
    }
}

/// Trait routes for the facade's `delegate_rpcs!` list.
impl SekaiServiceImpl {
    pub(super) async fn submit_model_stage_review_rpc(
        &self,
        req: Request<SubmitModelStageReviewRequest>,
    ) -> Result<Response<SubmitModelStageReviewResponse>, Status> {
        submit_model_stage_review(self, req).await
    }
    pub(super) async fn decide_model_stage_review_rpc(
        &self,
        req: Request<DecideModelStageReviewRequest>,
    ) -> Result<Response<DecideModelStageReviewResponse>, Status> {
        decide_model_stage_review(self, req).await
    }
}
