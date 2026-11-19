//! `GetEvaluationRationale` (#2630, ADR 0012): the only read path for judge
//! rationale a `rationale/v1` stochastic step retained.
//!
//! A rationale carries the markings of the evidence it was derived from, so a
//! read needs namespace read access plus clearance for every source evidence
//! object. Every refusal reads as not found, so a denied principal cannot
//! learn that a rationale exists. An expired rationale, or one whose source
//! evidence is gone or withdrawn, is deleted on read. Each disclosure is
//! audited before the rationale is returned, and a failed audit refuses it.

use super::*;
use crate::chisei::evaluation_rationale::{
    EvaluationRationale, EvaluationRationaleStore, sources_present,
};
use crate::chisei::principal::MarkingClearance;

const NOT_FOUND: &str = "evaluation rationale not found";

pub(super) async fn get_evaluation_rationale(
    service: &ChiseiServiceImpl,
    req: Request<GetEvaluationRationaleRequest>,
) -> Result<Response<GetEvaluationRationaleResponse>, Status> {
    let actor = authenticated_actor(&req);
    let request = req.into_inner();
    let validated = evaluation_execution_domain::prepare_execution_request(
        evaluation_execution_domain::EvaluationExecutionRequest {
            contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
            executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
            namespace: request.namespace,
            manifest_digest: request.manifest_digest,
            max_total_duration_ms: evaluation_execution_domain::DEFAULT_TOTAL_DURATION_MS,
        },
    )
    .map_err(map_evaluation_resource_error)?;
    if request.node_id.trim().is_empty() {
        return Err(Status::invalid_argument("node_id is required"));
    }
    let facts = service.sekai_facts.reader();
    require_namespace_access(facts, &actor, &validated.namespace)?;
    let operation_id =
        evaluation_execution_domain::execution_operation_id(&validated.manifest_digest);
    let rationale = service
        .db
        .runtime()
        .get_evaluation_rationale(&operation_id, &request.node_id, request.trial_index)
        .map_err(Status::internal)?
        .filter(|rationale| rationale.namespace == validated.namespace)
        .ok_or_else(|| Status::not_found(NOT_FOUND))?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    if rationale.expires_at_ms <= now_ms
        || !sources_present(facts, &rationale).map_err(Status::unavailable)?
    {
        service
            .db
            .runtime()
            .delete_evaluation_rationale(
                &rationale.operation_id,
                &rationale.node_id,
                rationale.trial_index,
            )
            .map_err(Status::internal)?;
        return Err(Status::not_found(NOT_FOUND));
    }
    if !cleared_for_sources(service, &actor, &rationale)? {
        return Err(Status::not_found(NOT_FOUND));
    }
    service
        .db
        .record_decisions_idempotently(&[read_decision(&actor, &rationale, now_ms)])
        .map_err(|error| Status::unavailable(format!("cannot audit rationale read: {error}")))?;
    Ok(Response::new(GetEvaluationRationaleResponse {
        rationale: rationale.rationale,
        rationale_digest: rationale.rationale_digest,
        expires_at_ms: rationale.expires_at_ms,
        classification: rationale.classification,
    }))
}

/// Whether `actor` may read every evidence object the rationale was derived
/// from. Sekai decides each marking; an error refuses.
fn cleared_for_sources(
    service: &ChiseiServiceImpl,
    actor: &str,
    rationale: &EvaluationRationale,
) -> Result<bool, Status> {
    let facts = service.sekai_facts.reader();
    for object_id in &rationale.evidence_object_ids {
        let Some(object) = facts
            .get_object(object_id)
            .map_err(|error| Status::unavailable(error.to_string()))?
        else {
            return Ok(false);
        };
        let clearance = facts.marking_clearance(&rationale.operation_id, &object, actor);
        if !matches!(
            clearance,
            Ok(MarkingClearance::Cleared | MarkingClearance::Unmarked)
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One audit decision per disclosure; the timestamp keeps repeat reads apart.
fn read_decision(
    actor: &str,
    rationale: &EvaluationRationale,
    now_ms: i64,
) -> crate::sekai::audit::Decision {
    let target_id = format!(
        "{}/{}/{}",
        rationale.operation_id, rationale.node_id, rationale.trial_index
    );
    crate::sekai::audit::Decision {
        id: format!(
            "evaluation-rationale-read:{target_id}:{actor}:{now_ms}:{}",
            uuid::Uuid::new_v4().simple()
        ),
        timestamp: now_ms,
        actor: actor.to_string(),
        action: "evaluation_rationale/read".into(),
        reason: "retained judge rationale disclosed".into(),
        evidence: HashMap::from([
            ("namespace".into(), rationale.namespace.clone()),
            (
                "rationale_digest".into(),
                rationale.rationale_digest.clone(),
            ),
            ("classification".into(), rationale.classification.clone()),
        ]),
        target_id,
        outcome: "disclosed".into(),
    }
}
