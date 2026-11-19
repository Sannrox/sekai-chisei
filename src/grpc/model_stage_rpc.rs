//! Experimental model stage RPCs (#3023): PutModelStage, ListModelStages and
//! PromoteModelVersion.
//!
//! Stages are read with namespace read and changed with namespace write. A
//! promotion to a gated stage needs an evaluation run of the stage's suite
//! against the version in which every case passed (ADR 0079). Every promotion,
//! admitted or refused, records an operation receipt; a refusal leaves the
//! stage on its previous version.

use super::model_version_rpc::{authorize_namespace_read, version_visible};
use super::*;
use crate::chisei_store::ChiseiRuntimeDb as _;
use crate::sekai::model_stage as domain_stage;
use crate::sekai::model_version as domain_model;
use sekai_domain::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind, ReceiptSurface,
};
use std::collections::BTreeMap;

fn authorize_namespace_write(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
) -> Result<(), Status> {
    if namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace is required"));
    }
    if tenant_context.is_some() {
        enforce_namespace_tenant_context(service.db.runtime(), tenant_context, namespace, true)
            .map_err(|_| Status::not_found(domain_stage::MODEL_STAGE_NOT_FOUND))?;
    }
    check_team_namespace(service.db.runtime(), principals, namespace, true)
}

fn require_stage_key(model_name: &str, stage: &str) -> Result<(), Status> {
    if model_name.trim().is_empty() {
        return Err(Status::invalid_argument("model_name is required"));
    }
    domain_stage::validate_stage_name(stage).map_err(Status::invalid_argument)
}

async fn put_model_stage(
    service: &SekaiServiceImpl,
    req: Request<PutModelStageRequest>,
) -> Result<Response<PutModelStageResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    authorize_namespace_write(
        service,
        &principals,
        tenant_context.as_ref(),
        &inner.namespace,
    )?;
    require_stage_key(&inner.model_name, &inner.stage)?;
    let stage = service
        .db
        .runtime()
        .put_model_stage(&domain_stage::ModelStage {
            namespace: inner.namespace,
            model_name: inner.model_name,
            stage: inner.stage,
            evaluation_suite_id: inner.evaluation_suite_id.trim().to_string(),
            version_id: String::new(),
            updated_at_ms: now_millis(),
        })
        .map_err(Status::internal)?;
    Ok(Response::new(PutModelStageResponse {
        stage: Some(to_proto_stage(stage)),
    }))
}

async fn list_model_stages(
    service: &SekaiServiceImpl,
    req: Request<ListModelStagesRequest>,
) -> Result<Response<ListModelStagesResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    authorize_namespace_read(
        service,
        &principals,
        tenant_context.as_ref(),
        &inner.namespace,
    )?;
    let stages = service
        .db
        .runtime()
        .list_model_stages(&inner.namespace, &inner.model_name)
        .map_err(Status::internal)?;
    Ok(Response::new(ListModelStagesResponse {
        stages: stages.into_iter().map(to_proto_stage).collect(),
    }))
}

async fn promote_model_version(
    service: &SekaiServiceImpl,
    req: Request<PromoteModelVersionRequest>,
) -> Result<Response<PromoteModelVersionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let actor = principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    authorize_namespace_write(
        service,
        &principals,
        tenant_context.as_ref(),
        &inner.namespace,
    )?;
    require_stage_key(&inner.model_name, &inner.stage)?;
    let db = service.db.runtime();
    let current = db
        .get_model_stage(&inner.namespace, &inner.model_name, &inner.stage)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found(domain_stage::MODEL_STAGE_NOT_FOUND))?;
    // A version of another model, or one the caller may not see, reads as missing.
    let version = db
        .get_model_version(&inner.namespace, &inner.version_id)
        .map_err(Status::internal)?
        .filter(|version| version.model_name == current.model_name)
        .ok_or_else(|| Status::not_found(domain_model::MODEL_VERSION_NOT_FOUND))?;
    if !version_visible(db, &principals, &version)? {
        return Err(Status::not_found(domain_model::MODEL_VERSION_NOT_FOUND));
    }
    let now = now_millis();
    let promotion = Promotion {
        operation_id: format!("model-promotion-{}", uuid::Uuid::new_v4()),
        actor,
        current: &current,
        version: &version,
        evaluation_run_id: inner.evaluation_run_id.trim(),
        at_ms: now,
    };
    let refusal = match evaluation_gate(db, &current, &version, promotion.evaluation_run_id) {
        Ok(()) => {
            let promoted = domain_stage::ModelStage {
                version_id: version.version_id.clone(),
                updated_at_ms: now,
                ..current.clone()
            };
            if db
                .promote_model_stage(&promoted, &current.version_id, &promotion.receipt(None))
                .map_err(Status::internal)?
            {
                return Ok(Response::new(PromoteModelVersionResponse {
                    promoted: true,
                    stage: Some(to_proto_stage(promoted)),
                    operation_id: promotion.operation_id,
                    refusal: String::new(),
                }));
            }
            domain_stage::REFUSAL_STAGE_MOVED
        }
        Err(refusal) => refusal,
    };
    db.put_operation_receipt(&promotion.receipt(Some(refusal)))
        .map_err(Status::internal)?;
    let stage = db
        .get_model_stage(&inner.namespace, &inner.model_name, &inner.stage)
        .map_err(Status::internal)?
        .unwrap_or_else(|| current.clone());
    Ok(Response::new(PromoteModelVersionResponse {
        promoted: false,
        stage: Some(to_proto_stage(stage)),
        operation_id: promotion.operation_id,
        refusal: refusal.to_string(),
    }))
}

/// Whether the stage's gate admits `version`. A gateless stage admits any
/// version of its model; a gated one needs a passing run of its suite against
/// the version. Missing, dry-run and shadow runs never count.
fn evaluation_gate(
    db: &RuntimeDb,
    stage: &domain_stage::ModelStage,
    version: &domain_model::ModelVersion,
    evaluation_run_id: &str,
) -> Result<(), &'static str> {
    if stage.is_gateless() {
        return Ok(());
    }
    if evaluation_run_id.is_empty() {
        return Err(domain_stage::REFUSAL_SUITE_MISSING);
    }
    let run = db
        .get_eval_run_record(evaluation_run_id)
        .ok()
        .flatten()
        .ok_or(domain_stage::REFUSAL_SUITE_MISSING)?;
    if crate::sekai::agent_dry_run::run_is_dry_run(&run.config_ref, &run.suite_id)
        || crate::sekai::agent_shadow::run_is_shadow(&run.config_ref, &run.suite_id)
    {
        return Err(domain_stage::REFUSAL_SUITE_MISSING);
    }
    let cases: Vec<bool> = run.results.iter().map(|result| result.passed).collect();
    domain_stage::evaluation_admits(
        &stage.evaluation_suite_id,
        &version.version_id,
        &run.suite_id,
        &run.config_ref,
        &cases,
    )
}

/// The facts one promotion attempt records on its receipt.
struct Promotion<'a> {
    operation_id: String,
    actor: String,
    current: &'a domain_stage::ModelStage,
    version: &'a domain_model::ModelVersion,
    evaluation_run_id: &'a str,
    at_ms: i64,
}

impl Promotion<'_> {
    /// The receipt: a policy decision naming the gate's outcome, then, when
    /// admitted, the stage move as the performed action.
    fn receipt(&self, refusal: Option<&str>) -> OperationReceipt {
        let mut attributes = BTreeMap::from([
            ("model_name".to_string(), self.current.model_name.clone()),
            ("stage".to_string(), self.current.stage.clone()),
            ("version_id".to_string(), self.version.version_id.clone()),
            (
                "previous_version_id".to_string(),
                self.current.version_id.clone(),
            ),
            (
                "evaluation_suite_id".to_string(),
                self.current.evaluation_suite_id.clone(),
            ),
            (
                "evaluation_run_id".to_string(),
                self.evaluation_run_id.to_string(),
            ),
            (
                "decision".to_string(),
                if refusal.is_some() {
                    "refused"
                } else {
                    "admitted"
                }
                .to_string(),
            ),
        ]);
        if let Some(refusal) = refusal {
            attributes.insert("refusal".to_string(), refusal.to_string());
        }
        let mut references = vec![GovernedReference {
            kind: "model_version".into(),
            reference: self.version.version_id.clone(),
            content_hash: Some(self.version.digest.clone()),
            disclosed_fields: Vec::new(),
            omitted: false,
            omission_reason: None,
        }];
        if !self.evaluation_run_id.is_empty() {
            references.push(GovernedReference {
                kind: "evaluation_run".into(),
                reference: self.evaluation_run_id.to_string(),
                content_hash: None,
                disclosed_fields: Vec::new(),
                omitted: false,
                omission_reason: None,
            });
        }
        let decided = format!("{}-policy", self.operation_id);
        let mut events = vec![OperationReceiptEvent {
            event_id: decided.clone(),
            operation_id: self.operation_id.clone(),
            parent_event_id: None,
            timestamp_ms: self.at_ms,
            kind: ReceiptEventKind::PolicyDecided,
            surface: ReceiptSurface::Policy,
            actor: self.actor.clone(),
            references: references.clone(),
            attributes: attributes.clone(),
        }];
        if refusal.is_none() {
            events.push(OperationReceiptEvent {
                event_id: format!("{}-action", self.operation_id),
                operation_id: self.operation_id.clone(),
                parent_event_id: Some(decided),
                timestamp_ms: self.at_ms,
                kind: ReceiptEventKind::ActionPerformed,
                surface: ReceiptSurface::Action,
                actor: self.actor.clone(),
                references,
                attributes,
            });
        }
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: self.operation_id.clone(),
            parent_operation_id: None,
            namespace: self.current.namespace.clone(),
            operation_class: domain_stage::PROMOTION_OPERATION_CLASS.into(),
            initiating_actor: self.actor.clone(),
            schema_version: "model_stage/v1".into(),
            policy_version: "model_stage/v1".into(),
            started_at_ms: self.at_ms,
            completed_at_ms: Some(self.at_ms),
            events,
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        }
    }
}

fn to_proto_stage(stage: domain_stage::ModelStage) -> ModelStage {
    ModelStage {
        namespace: stage.namespace,
        model_name: stage.model_name,
        stage: stage.stage,
        evaluation_suite_id: stage.evaluation_suite_id,
        version_id: stage.version_id,
        updated_at_ms: stage.updated_at_ms,
    }
}

/// Trait routes for the facade's `delegate_rpcs!` list.
impl SekaiServiceImpl {
    pub(super) async fn put_model_stage_rpc(
        &self,
        req: Request<PutModelStageRequest>,
    ) -> Result<Response<PutModelStageResponse>, Status> {
        put_model_stage(self, req).await
    }
    pub(super) async fn list_model_stages_rpc(
        &self,
        req: Request<ListModelStagesRequest>,
    ) -> Result<Response<ListModelStagesResponse>, Status> {
        list_model_stages(self, req).await
    }
    pub(super) async fn promote_model_version_rpc(
        &self,
        req: Request<PromoteModelVersionRequest>,
    ) -> Result<Response<PromoteModelVersionResponse>, Status> {
        promote_model_version(self, req).await
    }
}
