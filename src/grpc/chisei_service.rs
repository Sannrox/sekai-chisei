use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use tonic::{Request, Response, Status};

use super::llm_service::{
    estimate_chat_request, execute_chat_request, execute_chat_request_stream,
};
use super::pb::chisei::chisei_service_server::ChiseiService;
use super::pb::chisei::*;
use crate::chisei::budget::BudgetTracker;
use crate::chisei::controller::ActivePromotions;
use crate::chisei::eval::EvalStore;
use crate::chisei::pipeline as pipe;
use crate::chisei::policy::{Policy, PolicyResolver};
use crate::chisei::portfolio::{
    Objective, ObjectiveMode, Observation, PortfolioStore, TaskDemand as PortfolioDemand,
};
use crate::chisei::privacy::{DataClass, LeakAction, LeakFinding, LeakRule, TaskClass};
use crate::chisei::promotion::CandidateStore;
use crate::chisei::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind, ReceiptSurface, UncoveredSurface,
};
use crate::config::Config;
use crate::db::chisei_budget::{METRIC_REQUESTS, METRIC_TOKENS};
use crate::db::sekai::SekaiDb;
use crate::domain::{ListFilter, Object};
use crate::sekai::coordination::{
    RESERVATION_STATUS_ACTIVE, ReservationFilter, WORK_UNIT_STATUS_RUNNING,
};

pub struct ChiseiServiceImpl {
    budget: Arc<BudgetTracker>,
    policy: Arc<PolicyResolver>,
    pipeline: pipe::Pipeline,
    eval: Arc<EvalStore>,
    portfolio: Arc<PortfolioStore>,
    planned_executions: Arc<Mutex<HashMap<String, ExecutionPlan>>>,
    evolve_history: Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    evolve_enhancements: Arc<Mutex<HashMap<String, String>>>,
    candidates: Arc<CandidateStore>,
    active_promotions: Arc<ActivePromotions>,
    db: Arc<SekaiDb>,
    config: Config,
    provider_registry_state_path: Option<PathBuf>,
}

const MAX_CACHED_EXECUTION_PLANS: usize = 128;
const MAX_CACHED_EXECUTION_PLAN_AGE_MS: i64 = 15 * 60 * 1000;
const POLICY_KIND: &str = "policy";
const PIPELINE_CONTEXT_EXPANSION_PROFILE_VERSION: &str = "pipeline-v1";
const MIN_EVIDENCE_CONTEXT_EVAL_CASES: usize = 3;
const EXECUTION_SCHEMA_VERSION: &str = "chisei.execution/v1";
const GATEWAY_RECEIPT_ACTION: &str = "operation.receipt.upsert";
const AUTH_SOURCE_HEADER: &str = "x-sekai-auth-source";
const KIOKU_MIN_SAMPLES_PER_ARM: usize = 3;
const KIOKU_REGRESSION_THRESHOLD: f64 = 0.05;
const KIOKU_TRUSTED_OUTCOME_ATTRIBUTE: &str = "kioku_trusted_outcome";

fn record_reported_memory_outcomes(
    db: &SekaiDb,
    receipt: &OperationReceipt,
    actor: &str,
    now_ms: i64,
    require_trusted_outcome: bool,
    outcome_event_id: Option<&str>,
    validate_only: bool,
) -> Result<Vec<crate::chisei::kioku::MemoryImpactEvaluation>, String> {
    let request_id = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .and_then(|event| event.attributes.get("request_id"))
        .map(String::as_str)
        .map(str::trim)
        .filter(|request_id| !request_id.is_empty())
        .ok_or_else(|| "Kioku receipt lacks a non-empty request_id".to_string())?;
    let selected_outcome_metric = outcome_event_id
        .map(|event_id| {
            receipt
                .events
                .iter()
                .find(|event| event.event_id == event_id)
                .and_then(|event| event.attributes.get("outcome_metric"))
                .map(|metric| metric.trim().to_string())
                .ok_or_else(|| format!("Kioku outcome event {event_id} has no outcome metric"))
        })
        .transpose()?;
    let mut outcomes = HashMap::new();
    for outcome in receipt.events.iter().filter(|event| {
        matches!(
            event.kind,
            ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
        ) && ["outcome_metric", "outcome_value", "passed"]
            .iter()
            .all(|attribute| event.attributes.contains_key(*attribute))
            && (!require_trusted_outcome
                || event
                    .attributes
                    .get(KIOKU_TRUSTED_OUTCOME_ATTRIBUTE)
                    .is_some_and(|value| value == "true"))
    }) {
        let outcome_metric = outcome.attributes["outcome_metric"].trim().to_string();
        let outcome_value = outcome.attributes["outcome_value"]
            .parse::<f64>()
            .map_err(|_| "Kioku outcome value must be finite".to_string())?;
        if !outcome_value.is_finite() {
            return Err("Kioku outcome value must be finite".into());
        }
        let passed = outcome.attributes["passed"]
            .parse::<bool>()
            .map_err(|_| "Kioku outcome passed flag must be boolean".to_string())?;
        if outcomes
            .insert(outcome_metric.clone(), (outcome_value, passed))
            .is_some_and(|previous| previous != (outcome_value, passed))
        {
            return Err(format!(
                "conflicting Kioku outcomes for metric {outcome_metric}"
            ));
        }
    }
    if outcomes.is_empty() {
        return Ok(Vec::new());
    }
    let attempt_recorded_at_ms = receipt
        .events
        .iter()
        .filter(|event| event.kind == ReceiptEventKind::AttemptStarted)
        .map(|event| event.timestamp_ms)
        .min();
    let mut assignments = db
        .list_kioku_outcome_assignments(&receipt.operation_id)?
        .into_iter()
        .map(|assignment| {
            (
                (assignment.memory_id, assignment.memory_version),
                assignment.memory_applied,
            )
        })
        .collect::<HashMap<_, _>>();
    let assignment_reason = format!("pipeline operation {}", receipt.operation_id);
    let legacy_assignment_reason = format!("pipeline request {request_id}");
    let mut pending_lifecycle_events = Vec::new();
    for ((memory_id, memory_version), memory_applied) in assignments.clone() {
        let Some(memory) = db.get_kioku_memory(&memory_id, memory_version)? else {
            assignments.remove(&(memory_id, memory_version));
            continue;
        };
        if receipt.namespace != memory.namespace
            || !memory
                .operation_classes
                .iter()
                .any(|class| class == &receipt.operation_class)
        {
            return Err(format!(
                "memory {memory_id}@{memory_version} does not match receipt scope"
            ));
        }
        let lifecycle = db.list_kioku_lifecycle_events(&memory_id, memory_version)?;
        let assignment_action = if memory_applied {
            "injected"
        } else {
            "held_out"
        };
        let assignment_recorded_at_ms = lifecycle
            .iter()
            .filter(|event| event.action == assignment_action && event.reason == assignment_reason)
            .map(|event| event.recorded_at_ms)
            .max()
            .or_else(|| {
                lifecycle
                    .iter()
                    .filter(|event| {
                        event.action == assignment_action
                            && event.reason == legacy_assignment_reason
                    })
                    .map(|event| event.recorded_at_ms)
                    .max()
            });
        let Some(assignment_recorded_at_ms) = assignment_recorded_at_ms else {
            assignments.remove(&(memory_id, memory_version));
            continue;
        };
        let eligibility_recorded_at_ms = if memory_applied {
            assignment_recorded_at_ms
        } else {
            attempt_recorded_at_ms
                .ok_or_else(|| "Kioku receipt lacks an attempt-start event".to_string())?
        };
        let active_at_eligibility = lifecycle
            .into_iter()
            .filter(|event| event.recorded_at_ms <= eligibility_recorded_at_ms)
            .filter(|event| event.from_state.as_deref() != Some(event.to_state.as_str()))
            .max_by_key(|event| event.recorded_at_ms)
            .is_some_and(|event| event.to_state == "active");
        if !active_at_eligibility
            || memory.created_at_ms > eligibility_recorded_at_ms
            || memory
                .expires_at_ms
                .is_some_and(|expires| expires <= eligibility_recorded_at_ms)
            || memory
                .retention_until_ms
                .is_some_and(|retention| retention <= eligibility_recorded_at_ms)
        {
            pending_lifecycle_events.push(crate::chisei::kioku::MemoryLifecycleEvent {
                memory_id: memory_id.clone(),
                memory_version,
                action: "assignment_invalidated".into(),
                from_state: Some(memory.state.as_str().into()),
                to_state: memory.state.as_str().into(),
                actor: actor.into(),
                reason: format!("pipeline operation {}", receipt.operation_id),
                recorded_at_ms: now_ms,
            });
            assignments.remove(&(memory_id, memory_version));
        }
    }
    let governed_memories = receipt
        .events
        .iter()
        .filter(|event| event.kind == ReceiptEventKind::ContextGoverned)
        .flat_map(|event| {
            event
                .references
                .iter()
                .map(move |reference| (event.timestamp_ms, reference))
        })
        .filter(|(_, reference)| reference.kind == "kioku_memory" && !reference.omitted)
        .collect::<Vec<_>>();
    if assignments.is_empty() && governed_memories.is_empty() {
        return Err("Kioku outcome matches no eligible memory assignment".into());
    }
    let attempt_recorded_at_ms = attempt_recorded_at_ms
        .ok_or_else(|| "Kioku receipt lacks an attempt-start event".to_string())?;
    for (context_recorded_at_ms, reference) in governed_memories {
        if context_recorded_at_ms > attempt_recorded_at_ms {
            return Err("Kioku context was recorded after execution started".into());
        }
        let Some(pinned) = reference.reference.strip_prefix("memory:") else {
            return Err(format!(
                "memory reference {} has no memory prefix",
                reference.reference
            ));
        };
        let Some((memory_id, version)) = pinned.rsplit_once('@') else {
            return Err(format!(
                "memory reference {} does not pin a version",
                reference.reference
            ));
        };
        let version = version.parse::<u32>().map_err(|_| {
            format!(
                "memory reference {} has an invalid version",
                reference.reference
            )
        })?;
        let key = (memory_id.to_string(), version);
        if assignments.get(&key) == Some(&false) {
            return Err(format!(
                "memory {memory_id}@{version} is both held out and present in the receipt"
            ));
        }
        if assignments.get(&key) == Some(&true) {
            continue;
        }
        let memory = db
            .get_kioku_memory(memory_id, version)?
            .ok_or_else(|| format!("memory {memory_id}@{version} not found"))?;
        if receipt.namespace != memory.namespace
            || !memory
                .operation_classes
                .iter()
                .any(|class| class == &receipt.operation_class)
        {
            return Err(format!(
                "memory {memory_id}@{version} does not match receipt scope"
            ));
        }
        let active_at_context = db
            .list_kioku_lifecycle_events(memory_id, version)?
            .into_iter()
            .filter(|event| event.recorded_at_ms <= context_recorded_at_ms)
            .filter(|event| event.from_state.as_deref() != Some(event.to_state.as_str()))
            .max_by_key(|event| event.recorded_at_ms)
            .is_some_and(|event| event.to_state == "active");
        let active_at_attempt = db
            .list_kioku_lifecycle_events(memory_id, version)?
            .into_iter()
            .filter(|event| event.recorded_at_ms <= attempt_recorded_at_ms)
            .filter(|event| event.from_state.as_deref() != Some(event.to_state.as_str()))
            .max_by_key(|event| event.recorded_at_ms)
            .is_some_and(|event| event.to_state == "active");
        if !active_at_context
            || !active_at_attempt
            || memory.created_at_ms > context_recorded_at_ms
            || memory
                .expires_at_ms
                .is_some_and(|expires| expires <= context_recorded_at_ms)
            || memory
                .retention_until_ms
                .is_some_and(|retention| retention <= context_recorded_at_ms)
            || memory
                .expires_at_ms
                .is_some_and(|expires| expires <= attempt_recorded_at_ms)
            || memory
                .retention_until_ms
                .is_some_and(|retention| retention <= attempt_recorded_at_ms)
        {
            return Err(format!(
                "memory {memory_id}@{version} was not active when execution started"
            ));
        }
        let authorized_ceiling = db
            .kioku_authorized_classification_ceiling(&memory.namespace, &receipt.initiating_actor)
            .map_err(|_| {
                format!("initiating actor is not authorized for memory {memory_id}@{version}")
            })?;
        if memory.classification > authorized_ceiling {
            return Err(format!(
                "memory {memory_id}@{version} exceeds initiating actor authorization"
            ));
        }
        if reference.content_hash.as_deref()
            != Some(crate::chisei::kioku::memory_claim_digest(&memory).as_str())
        {
            return Err(format!(
                "memory {memory_id}@{version} digest does not match"
            ));
        }
        pending_lifecycle_events.push(crate::chisei::kioku::MemoryLifecycleEvent {
            memory_id: memory_id.into(),
            memory_version: version,
            action: "injected".into(),
            from_state: Some("active".into()),
            to_state: "active".into(),
            actor: receipt.initiating_actor.clone(),
            reason: format!("pipeline operation {}", receipt.operation_id),
            recorded_at_ms: context_recorded_at_ms,
        });
        assignments.insert(key, true);
    }
    let mut assignment_metrics = HashMap::new();
    let mut known_metrics = HashSet::new();
    for (memory_id, memory_version) in assignments.keys() {
        let evidence = db.list_kioku_evidence(memory_id, *memory_version)?;
        let outcome_metric = evidence
            .first()
            .map(|link| link.outcome_metric.trim())
            .filter(|metric| !metric.is_empty())
            .ok_or_else(|| format!("memory {memory_id}@{memory_version} has no outcome metric"))?;
        if !evidence
            .iter()
            .all(|link| link.outcome_metric.trim() == outcome_metric)
        {
            return Err(format!(
                "memory {memory_id}@{memory_version} has conflicting outcome metrics"
            ));
        }
        known_metrics.insert(outcome_metric.to_string());
        assignment_metrics.insert(
            (memory_id.clone(), *memory_version),
            outcome_metric.to_string(),
        );
    }
    if let Some(unmatched_metric) = outcomes
        .keys()
        .find(|metric| !known_metrics.contains(*metric))
    {
        return Err(format!(
            "Kioku outcome metric {unmatched_metric} matches no assigned memory"
        ));
    }
    if let Some(selected_outcome_metric) = selected_outcome_metric {
        outcomes.retain(|metric, _| metric == &selected_outcome_metric);
    }
    if validate_only {
        return Ok(Vec::new());
    }
    for event in pending_lifecycle_events {
        db.record_kioku_lifecycle_event(&event)?;
    }
    let mut evaluations = Vec::new();
    for ((memory_id, memory_version), memory_applied) in assignments {
        let outcome_metric = &assignment_metrics[&(memory_id.clone(), memory_version)];
        let Some(&(outcome_value, passed)) = outcomes.get(outcome_metric) else {
            continue;
        };
        let recorded =
            db.record_kioku_outcome(&crate::chisei::kioku::MemoryOutcomeObservation {
                memory_id: memory_id.clone(),
                memory_version,
                operation_id: receipt.operation_id.clone(),
                request_id: request_id.into(),
                memory_applied,
                outcome_metric: outcome_metric.clone(),
                outcome_value,
                passed,
                recorded_at_ms: now_ms,
            })?;
        if recorded
            && let Some(evaluation) = db.evaluate_kioku_impact_if_ready(
                &memory_id,
                memory_version,
                KIOKU_MIN_SAMPLES_PER_ARM,
                KIOKU_REGRESSION_THRESHOLD,
                actor,
                now_ms,
            )?
        {
            evaluations.push(evaluation);
        }
    }
    Ok(evaluations)
}

fn authenticated_actor<T>(request: &Request<T>) -> String {
    request
        .metadata()
        .get("x-principal")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local")
        .to_string()
}

fn require_eval_admin<T>(request: &Request<T>) -> Result<(), Status> {
    if matches!(authenticated_actor(request).as_str(), "root" | "local") {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "evaluation mutation requires control-plane administration",
        ))
    }
}

fn authorize_statistics_namespaces(
    db: &SekaiDb,
    actor: &str,
    namespaces: &[String],
) -> Result<(), Status> {
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    for namespace in namespaces {
        let mut targets = Vec::new();
        for prefix in ["namespace", "project", "policy"] {
            if let Some(target) = db
                .find_by_external_id(&format!("{prefix}:{namespace}"))
                .map_err(Status::internal)?
            {
                targets.push(target);
            }
        }
        if targets.is_empty() {
            return Err(Status::permission_denied(
                "namespace statistics access is not authorized",
            ));
        }
        let mut explicitly_authorized = false;
        for target in targets {
            let grants = db.list_grants(&target.id).map_err(Status::internal)?;
            let actor_has_grant = grants.iter().any(|grant| grant.principal == actor);
            if !grants.is_empty() && !actor_has_grant {
                return Err(Status::permission_denied(
                    "namespace statistics access is not authorized",
                ));
            }
            explicitly_authorized |= actor_has_grant;
        }
        if !explicitly_authorized {
            return Err(Status::permission_denied(
                "namespace statistics access is not authorized",
            ));
        }
    }
    Ok(())
}

fn auth_source<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get(AUTH_SOURCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn context_evidence_reference(
    reference: &pipe::EvidenceContextReference,
) -> ContextEvidenceReference {
    ContextEvidenceReference {
        submission_id: reference.submission_id.clone(),
        source_type: reference.source_type.clone(),
        source_instance: reference.source_instance.clone(),
        source_version: reference.source_version.clone(),
        source_sequence: reference.source_sequence,
        evidence_type: reference.evidence_type.clone(),
        schema_id: reference.schema_id.clone(),
        schema_version: reference.schema_version.clone(),
        content_digest: reference.content_digest.clone(),
        observed_at_ms: reference.observed_at_ms,
        classification: reference.classification.clone(),
        projection_version: reference.projection_version.clone(),
        disclosed_fields: reference.disclosed_fields.clone(),
    }
}

fn memory_context_reference(reference: &pipe::MemoryContextReference) -> MemoryContextReference {
    MemoryContextReference {
        memory_id: reference.memory_id.clone(),
        memory_version: reference.memory_version,
        classification: reference.classification.clone(),
        confidence_bps: u32::from(reference.confidence_bps),
        applicability: reference.applicability.clone(),
        evidence_operation_ids: reference.evidence_operation_ids.clone(),
        content_digest: reference.content_digest.clone(),
    }
}

fn memory_lifecycle_allows_execution(
    state: crate::chisei::kioku::MemoryLifecycleState,
    expires_at_ms: Option<i64>,
    retention_until_ms: Option<i64>,
    now_ms: i64,
) -> bool {
    state == crate::chisei::kioku::MemoryLifecycleState::Active
        && expires_at_ms.is_none_or(|expires_at_ms| expires_at_ms > now_ms)
        && retention_until_ms.is_none_or(|retention_until_ms| retention_until_ms > now_ms)
}

fn receipt_mutation_transport_allowed<T>(request: &Request<T>, config: &Config) -> bool {
    match auth_source(request).as_deref() {
        Some("token") => true,
        Some("local") => config.insecure,
        _ => false,
    }
}

fn reportable_receipt_kind(kind: ReceiptEventKind) -> bool {
    matches!(
        kind,
        ReceiptEventKind::AttemptStarted
            | ReceiptEventKind::ModelCalled
            | ReceiptEventKind::ActionPerformed
            | ReceiptEventKind::ApprovalDecided
            | ReceiptEventKind::ArtifactProduced
            | ReceiptEventKind::VerificationRecorded
            | ReceiptEventKind::HumanIntervened
            | ReceiptEventKind::OutcomeRecorded
    )
}

fn content_hash(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        let bytes = part.as_ref();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    format!("{:x}", hasher.finalize())
}

fn planned_response_hash(response: &PlannedChatResponse) -> String {
    let tool_calls = response
        .tool_calls
        .iter()
        .map(|call| (&call.id, &call.name, &call.args_json))
        .collect::<Vec<_>>();
    let canonical_tool_calls = serde_json::to_vec(&tool_calls).unwrap_or_default();
    content_hash([response.content.as_bytes(), canonical_tool_calls.as_slice()])
}

fn receipt_event(
    operation_id: &str,
    suffix: &str,
    parent_suffix: Option<&str>,
    timestamp_ms: i64,
    kind: ReceiptEventKind,
    actor: &str,
    attributes: BTreeMap<String, String>,
) -> OperationReceiptEvent {
    OperationReceiptEvent {
        event_id: format!("{operation_id}:{suffix}"),
        operation_id: operation_id.to_string(),
        parent_event_id: parent_suffix.map(|parent| format!("{operation_id}:{parent}")),
        timestamp_ms,
        surface: kind.surface(),
        kind,
        actor: actor.to_string(),
        references: Vec::new(),
        attributes,
    }
}

fn record_completed_operation_on(
    db: &SekaiDb,
    plan: &ExecutionPlan,
    actor: &str,
    response: &PlannedChatResponse,
    attempt_started_at_ms: i64,
    completed_at_ms: i64,
) -> Result<(), String> {
    let cost_usd_micros = crate::cost_estimate::pricing_from_env()
        .ok()
        .and_then(|pricing| native_execution_cost(plan, response, &pricing));
    db.update_operation_receipt(&plan.plan_id, |receipt| {
        if receipt.completed_at_ms.is_some() {
            return Err("operation receipt already has a terminal outcome".into());
        }
        let canonical_egress_id = format!("{}:egress", receipt.operation_id);
        let parent = if receipt.events.iter().any(|event| {
            event.event_id == canonical_egress_id && event.kind == ReceiptEventKind::EgressDecided
        }) {
            "egress"
        } else {
            "budget"
        };
        receipt.events.extend([
            receipt_event(
                &receipt.operation_id,
                "attempt-1",
                Some(parent),
                attempt_started_at_ms,
                ReceiptEventKind::AttemptStarted,
                actor,
                BTreeMap::from([("attempt".into(), "1".into())]),
            ),
            receipt_event(
                &receipt.operation_id,
                "model-call-1",
                Some("attempt-1"),
                completed_at_ms,
                ReceiptEventKind::ModelCalled,
                "chisei.llm",
                {
                    let mut attributes = BTreeMap::from([
                        ("provider".into(), response.provider.clone()),
                        ("model".into(), plan.resolved_model.clone()),
                        ("input_tokens".into(), response.input_tokens.to_string()),
                        ("output_tokens".into(), response.output_tokens.to_string()),
                    ]);
                    if let Some(cost_usd_micros) = cost_usd_micros {
                        attributes.insert("cost_usd_micros".into(), cost_usd_micros.to_string());
                    }
                    attributes
                },
            ),
            receipt_event(
                &receipt.operation_id,
                "artifact-1",
                Some("model-call-1"),
                completed_at_ms,
                ReceiptEventKind::ArtifactProduced,
                "chisei.llm",
                BTreeMap::from([
                    ("artifact_type".into(), "model_response".into()),
                    ("content_hash".into(), planned_response_hash(response)),
                    ("content_stored".into(), "false".into()),
                ]),
            ),
            receipt_event(
                &receipt.operation_id,
                "verification",
                Some("artifact-1"),
                completed_at_ms,
                ReceiptEventKind::VerificationRecorded,
                "chisei.execution",
                BTreeMap::from([("status".into(), "not_requested".into())]),
            ),
            receipt_event(
                &receipt.operation_id,
                "outcome",
                Some("verification"),
                completed_at_ms,
                ReceiptEventKind::OutcomeRecorded,
                actor,
                BTreeMap::from([
                    ("status".into(), "succeeded".into()),
                    ("completion_reason".into(), response.stop_reason.clone()),
                    (
                        "latency_ms".into(),
                        completed_at_ms
                            .saturating_sub(receipt.started_at_ms)
                            .to_string(),
                    ),
                ]),
            ),
        ]);
        receipt.completed_at_ms = Some(completed_at_ms);
        receipt.uncovered_surfaces.clear();
        Ok(())
    })?;
    Ok(())
}

fn native_execution_cost(
    plan: &ExecutionPlan,
    response: &PlannedChatResponse,
    pricing: &HashMap<String, crate::gateway::ModelPricing>,
) -> Option<i64> {
    let (priced_model, rates) =
        crate::gateway::lookup_pricing_entry(pricing, &plan.resolved_model)?;
    crate::cost_estimate::cost_usd_micros(
        priced_model,
        rates,
        i64::from(response.input_tokens),
        i64::from(response.output_tokens),
        0,
        0,
    )
}

fn record_failed_operation_on(
    db: &SekaiDb,
    plan: &ExecutionPlan,
    actor: &str,
    completion_reason: &str,
) -> Result<(), String> {
    if db.get_operation_receipt(&plan.plan_id)?.is_none() {
        return Ok(());
    }
    let completed_at_ms = chrono::Utc::now().timestamp_millis();
    db.update_operation_receipt(&plan.plan_id, |receipt| {
        if receipt.completed_at_ms.is_some() {
            return Ok(());
        }
        let canonical_egress_id = format!("{}:egress", receipt.operation_id);
        let parent = if receipt.events.iter().any(|event| {
            event.event_id == canonical_egress_id && event.kind == ReceiptEventKind::EgressDecided
        }) {
            "egress"
        } else {
            "budget"
        };
        receipt.events.push(receipt_event(
            &receipt.operation_id,
            "outcome",
            Some(parent),
            completed_at_ms,
            ReceiptEventKind::OutcomeRecorded,
            actor,
            BTreeMap::from([
                ("status".into(), "denied".into()),
                ("completion_reason".into(), completion_reason.into()),
                (
                    "latency_ms".into(),
                    completed_at_ms
                        .saturating_sub(receipt.started_at_ms)
                        .to_string(),
                ),
            ]),
        ));
        receipt.completed_at_ms = Some(completed_at_ms);
        receipt.uncovered_surfaces.clear();
        Ok(())
    })?;
    Ok(())
}

fn pipeline_context_expansion_profile_key(namespace: &str) -> String {
    format!(
        "context-expansion:{}:{}",
        PIPELINE_CONTEXT_EXPANSION_PROFILE_VERSION,
        namespace.trim()
    )
}

fn evidence_context_profile_key(namespace: &str, source_type: &str, evidence_type: &str) -> String {
    let namespace = namespace.trim();
    let source_type = source_type.trim();
    let evidence_type = evidence_type.trim();
    format!(
        "context-expansion:{}:{}:{}:evidence:{}:{}:{}:{}",
        PIPELINE_CONTEXT_EXPANSION_PROFILE_VERSION,
        namespace.len(),
        namespace,
        source_type.len(),
        source_type,
        evidence_type.len(),
        evidence_type
    )
}

fn evidence_context_config_ref(
    source_type: &str,
    evidence_type: &str,
    with_evidence: bool,
) -> String {
    let source_type = source_type.trim();
    let evidence_type = evidence_type.trim();
    format!(
        "evidence-context:{}:{}:{}:{}:{}:{}",
        PIPELINE_CONTEXT_EXPANSION_PROFILE_VERSION,
        if with_evidence { "with" } else { "without" },
        source_type.len(),
        source_type,
        evidence_type.len(),
        evidence_type
    )
}

#[derive(Debug, Clone)]
struct EvidenceClassGate {
    source_type: String,
    evidence_type: String,
    gate: crate::chisei::eval::ContextExpansionGate,
    effective_allowed: bool,
}

struct FinishStreamedExecution<'a> {
    db: &'a SekaiDb,
    evolve_history: &'a Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    request_id: &'a str,
    namespace: &'a str,
    enriched_spec: &'a str,
    original_spec: Option<&'a str>,
    resolved_model: &'a str,
    sampled: bool,
    sample_rate: f64,
    sample_reason: &'a str,
    scoring_enabled: bool,
    task_class: &'a str,
    response: &'a PlannedChatResponse,
}

struct EvolveTaskRecord<'a> {
    request_id: &'a str,
    namespace: &'a str,
    spec: &'a str,
    original_spec: Option<&'a str>,
    status: &'a str,
    tokens_used: i32,
}

fn record_evolve_task_on(
    db: &SekaiDb,
    evolve_history: &Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    task: EvolveTaskRecord<'_>,
) -> Result<(), String> {
    if task.request_id.is_empty() {
        return Ok(());
    }
    let mut history = evolve_history.lock().expect("evolve history poisoned");
    let entry = history
        .entry(task.request_id.to_string())
        .or_insert_with(|| crate::chisei::evolve::TaskRecord {
            id: task.request_id.to_string(),
            spec: task.spec.to_string(),
            status: task.status.to_string(),
            namespace: task.namespace.to_string(),
            tokens_used: task.tokens_used,
            original_spec: task.original_spec.map(ToOwned::to_owned),
            created: chrono::Utc::now().timestamp(),
        });
    entry.namespace = task.namespace.to_string();
    entry.spec = task.spec.to_string();
    entry.status = task.status.to_string();
    entry.tokens_used = task.tokens_used;
    entry.original_spec = task.original_spec.map(ToOwned::to_owned);
    db.put_evolve_task(entry)?;
    Ok(())
}
fn finish_streamed_execution(execution: &FinishStreamedExecution) -> Result<(), String> {
    record_evolve_task_on(
        execution.db,
        execution.evolve_history,
        EvolveTaskRecord {
            request_id: execution.request_id,
            namespace: execution.namespace,
            spec: execution.enriched_spec,
            original_spec: execution.original_spec,
            status: "done",
            tokens_used: execution.response.input_tokens + execution.response.output_tokens,
        },
    )?;
    if execution.sampled {
        let mut evidence = HashMap::new();
        evidence.insert("model".to_string(), execution.resolved_model.to_string());
        evidence.insert(
            "input_tokens".to_string(),
            execution.response.input_tokens.to_string(),
        );
        evidence.insert(
            "output_tokens".to_string(),
            execution.response.output_tokens.to_string(),
        );
        evidence.insert(
            "stop_reason".to_string(),
            execution.response.stop_reason.clone(),
        );
        evidence.insert("sample_rate".to_string(), execution.sample_rate.to_string());
        let _ = execution
            .db
            .record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.sampling".into(),
                action: "sample_observed".into(),
                reason: execution.sample_reason.to_string(),
                evidence,
                target_id: execution.request_id.to_string(),
                outcome: "observed".into(),
            });
        if execution.scoring_enabled {
            let _ =
                execution
                    .db
                    .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                        request_id: execution.request_id.to_string(),
                        namespace: execution.namespace.to_string(),
                        spec: execution.enriched_spec.to_string(),
                        resolved_model: execution.resolved_model.to_string(),
                        output_content: execution.response.content.clone(),
                        sample_reason: execution.sample_reason.to_string(),
                        input_tokens: execution.response.input_tokens,
                        output_tokens: execution.response.output_tokens,
                        stop_reason: execution.response.stop_reason.clone(),
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        scored: false,
                        task_class: execution.task_class.to_string(),
                        cost_usd_micros: 0,
                    });
        }
    }
    Ok(())
}

fn persist_namespace_policy(db: &SekaiDb, namespace: &str, policy: &Policy) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let external_id = format!("policy:{namespace}");
    let mut properties = policy_properties(policy);
    properties.insert("namespace".to_string(), namespace.to_string());

    if let Some(mut existing) = db.find_by_external_id(&external_id)? {
        existing.name = namespace.to_string();
        existing.namespace = namespace.to_string();
        existing.properties = properties;
        existing.updated = now;
        db.update_object(&existing)
    } else {
        db.create_object(&Object {
            id: format!("policy-{namespace}"),
            kind: POLICY_KIND.to_string(),
            name: namespace.to_string(),
            namespace: namespace.to_string(),
            external_id,
            properties,
            created: now,
            updated: now,
        })
    }
}

impl ChiseiServiceImpl {
    pub fn new(db: Arc<SekaiDb>, config: Config) -> Self {
        let provider_registry_state_path = (config.db_path != ":memory:")
            .then(|| crate::provider_profile::provider_registry_state_path(&config.db_path));
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        let eval = Arc::new(EvalStore::with_db(db.clone()));
        let evolve_history = Arc::new(Mutex::new(
            db.list_evolve_task_records()
                .unwrap_or_default()
                .into_iter()
                .map(|task| (task.id.clone(), task))
                .collect(),
        ));
        let evolve_enhancements = Arc::new(Mutex::new(
            db.list_evolve_enhancements().unwrap_or_default(),
        ));
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        Self {
            budget: Arc::new(BudgetTracker::new(db.clone())),
            policy,
            pipeline: pipe::default_pipeline_with(config.sample_rate, config.sample_risk_threshold),
            eval,
            portfolio: Arc::new(PortfolioStore::new(db.clone())),
            planned_executions: Arc::new(Mutex::new(HashMap::new())),
            evolve_history,
            evolve_enhancements,
            candidates: Arc::new(CandidateStore::new()),
            active_promotions: Arc::new(ActivePromotions::new()),
            db,
            config,
            provider_registry_state_path,
        }
    }

    fn pipeline_context_expansion_gate(
        &self,
        namespace: &str,
    ) -> crate::chisei::eval::ContextExpansionGate {
        self.eval
            .context_expansion_gate(&pipeline_context_expansion_profile_key(namespace))
    }

    fn evidence_context_gate(
        &self,
        namespace: &str,
        source_type: &str,
        evidence_type: &str,
        namespace_gate_allowed: bool,
    ) -> EvidenceClassGate {
        let mut gate = self
            .eval
            .context_expansion_gate(&evidence_context_profile_key(
                namespace,
                source_type,
                evidence_type,
            ));
        if !gate.baseline_run_id.is_empty() && !gate.candidate_run_id.is_empty() {
            let baseline = self.eval.get_run(&gate.baseline_run_id);
            let candidate = self.eval.get_run(&gate.candidate_run_id);
            let expected_baseline = evidence_context_config_ref(source_type, evidence_type, false);
            let expected_candidate = evidence_context_config_ref(source_type, evidence_type, true);
            let invalid_reason = match (baseline.as_ref(), candidate.as_ref()) {
                (Some(baseline), Some(candidate)) => {
                    let baseline_cases = baseline
                        .results
                        .iter()
                        .map(|result| result.case_id.as_str())
                        .collect::<HashSet<_>>();
                    let candidate_cases = candidate
                        .results
                        .iter()
                        .map(|result| result.case_id.as_str())
                        .collect::<HashSet<_>>();
                    if baseline.config_ref != expected_baseline
                        || candidate.config_ref != expected_candidate
                    {
                        Some("evidence comparison must use the expected without/with config refs")
                    } else if baseline_cases.len() != baseline.results.len()
                        || candidate_cases.len() != candidate.results.len()
                    {
                        Some("evidence comparison contains duplicate case results")
                    } else if baseline_cases.len() < MIN_EVIDENCE_CONTEXT_EVAL_CASES
                        || candidate_cases.len() < MIN_EVIDENCE_CONTEXT_EVAL_CASES
                    {
                        Some("evidence comparison has too few matched cases")
                    } else if baseline_cases != candidate_cases {
                        Some("evidence comparison cases do not match")
                    } else {
                        None
                    }
                }
                _ => Some("evidence comparison runs are unavailable"),
            };
            if let Some(reason) = invalid_reason {
                gate.allowed = false;
                gate.verdict = "invalid_comparison".into();
                gate.reason = reason.into();
            }
        }
        EvidenceClassGate {
            source_type: source_type.to_string(),
            evidence_type: evidence_type.to_string(),
            effective_allowed: namespace_gate_allowed && gate.allowed,
            gate,
        }
    }

    fn applicable_evidence_context_gates(
        &self,
        request: &pipe::PipelineRequest,
        namespace_gate_allowed: bool,
    ) -> Result<Vec<EvidenceClassGate>, Status> {
        pipe::applicable_evidence_classes(request, &self.db)
            .map_err(Status::internal)
            .map(|evidence_types| {
                evidence_types
                    .into_iter()
                    .map(|class| {
                        self.evidence_context_gate(
                            &request.namespace,
                            &class.source_type,
                            &class.evidence_type,
                            namespace_gate_allowed,
                        )
                    })
                    .collect()
            })
    }

    fn record_evidence_context_gates(
        &self,
        request_id: &str,
        namespace: &str,
        gates: &[EvidenceClassGate],
        references: &[pipe::EvidenceContextReference],
    ) -> Result<(), Status> {
        for class_gate in gates {
            let used_count = references
                .iter()
                .filter(|reference| reference.evidence_type == class_gate.evidence_type)
                .filter(|reference| reference.source_type == class_gate.source_type)
                .count();
            self.db
                .record_decision(&crate::sekai::audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis(),
                    actor: "chisei.pipeline".into(),
                    action: "chisei.evidence_context_admission".into(),
                    reason: if class_gate.effective_allowed {
                        class_gate.gate.reason.clone()
                    } else if class_gate.gate.allowed {
                        "namespace context-expansion gate is not allowed".into()
                    } else {
                        class_gate.gate.reason.clone()
                    },
                    evidence: HashMap::from([
                        ("request_id".into(), request_id.to_string()),
                        ("source_type".into(), class_gate.source_type.clone()),
                        ("evidence_type".into(), class_gate.evidence_type.clone()),
                        ("profile_key".into(), class_gate.gate.profile_key.clone()),
                        ("iteration_id".into(), class_gate.gate.iteration_id.clone()),
                        (
                            "baseline_run_id".into(),
                            class_gate.gate.baseline_run_id.clone(),
                        ),
                        (
                            "candidate_run_id".into(),
                            class_gate.gate.candidate_run_id.clone(),
                        ),
                        ("verdict".into(), class_gate.gate.verdict.clone()),
                        (
                            "class_gate_allowed".into(),
                            class_gate.gate.allowed.to_string(),
                        ),
                        ("allowed".into(), class_gate.effective_allowed.to_string()),
                        ("used_evidence_count".into(), used_count.to_string()),
                        (
                            "expected_baseline_config_ref".into(),
                            evidence_context_config_ref(
                                &class_gate.source_type,
                                &class_gate.evidence_type,
                                false,
                            ),
                        ),
                        (
                            "expected_candidate_config_ref".into(),
                            evidence_context_config_ref(
                                &class_gate.source_type,
                                &class_gate.evidence_type,
                                true,
                            ),
                        ),
                    ]),
                    target_id: namespace.to_string(),
                    outcome: if class_gate.effective_allowed {
                        "allowed"
                    } else {
                        "skipped"
                    }
                    .into(),
                })
                .map_err(Status::internal)?;
        }
        Ok(())
    }

    fn record_context_expansion_gate(
        &self,
        request_id: &str,
        namespace: &str,
        gate: &crate::chisei::eval::ContextExpansionGate,
        expanded_context_items: usize,
    ) -> Result<(), Status> {
        self.db
            .record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.pipeline".into(),
                action: "chisei.context_expansion".into(),
                reason: gate.reason.clone(),
                evidence: HashMap::from([
                    ("request_id".into(), request_id.to_string()),
                    ("profile_key".into(), gate.profile_key.clone()),
                    ("iteration_id".into(), gate.iteration_id.clone()),
                    ("baseline_run_id".into(), gate.baseline_run_id.clone()),
                    ("candidate_run_id".into(), gate.candidate_run_id.clone()),
                    ("verdict".into(), gate.verdict.clone()),
                    ("allowed".into(), gate.allowed.to_string()),
                    (
                        "expanded_context_items".into(),
                        expanded_context_items.to_string(),
                    ),
                ]),
                target_id: namespace.to_string(),
                outcome: if gate.allowed { "allowed" } else { "skipped" }.into(),
            })
            .map_err(Status::internal)
    }

    /// Build a background scoring job sharing this service's DB, in-memory eval store, budget,
    /// and config — so emitted runs are visible to live regression checks immediately.
    pub fn scoring_job(&self) -> crate::chisei::scoring::ScoringJob {
        crate::chisei::scoring::ScoringJob::new(
            self.db.clone(),
            self.eval.clone(),
            self.config.clone(),
            self.budget.clone(),
        )
    }

    /// This service's live candidate store, for propose/gate/promote workflows that need to share
    /// its DB and in-memory `EvalStore` (e.g. a periodic promotion-controller driver, or direct
    /// RPC-triggered promotion).
    pub fn candidate_store(&self) -> Arc<CandidateStore> {
        self.candidates.clone()
    }

    /// This service's live active-promotions registry — the same one `resolve_policy` consults,
    /// so promotions/rollbacks driven through `candidate_store()` have a real, immediate effect on
    /// live routing.
    pub fn active_promotions(&self) -> Arc<ActivePromotions> {
        self.active_promotions.clone()
    }

    fn record_portfolio_shift(
        &self,
        scope: &str,
        task_class: &str,
        selection: &crate::chisei::portfolio::RouteSelection,
        objective: &Objective,
        outcome: &str,
    ) {
        if !selection.shifted {
            return;
        }
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.portfolio".into(),
            action: "chisei.portfolio_route_shift".into(),
            reason: selection.reason.clone(),
            evidence: HashMap::from([
                ("task_class".into(), task_class.to_string()),
                ("previous_model".into(), selection.previous_model.clone()),
                ("selected_model".into(), selection.model.clone()),
                ("objective_mode".into(), objective.mode.as_str().into()),
                (
                    "budget_usd_micros".into(),
                    objective.budget_usd_micros.to_string(),
                ),
                ("quality_bar".into(), objective.quality_bar.to_string()),
                ("min_samples".into(), objective.min_samples.to_string()),
            ]),
            target_id: scope.to_string(),
            outcome: outcome.to_string(),
        });
    }

    pub fn with_budget(db: Arc<SekaiDb>, config: Config, budget: Arc<BudgetTracker>) -> Self {
        let provider_registry_state_path = (config.db_path != ":memory:")
            .then(|| crate::provider_profile::provider_registry_state_path(&config.db_path));
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        let eval = Arc::new(EvalStore::with_db(db.clone()));
        let evolve_history = Arc::new(Mutex::new(
            db.list_evolve_task_records()
                .unwrap_or_default()
                .into_iter()
                .map(|task| (task.id.clone(), task))
                .collect(),
        ));
        let evolve_enhancements = Arc::new(Mutex::new(
            db.list_evolve_enhancements().unwrap_or_default(),
        ));
        let policy = Arc::new(PolicyResolver::new());
        load_namespace_policies(&db, &policy);
        Self {
            budget,
            policy,
            pipeline: pipe::default_pipeline_with(config.sample_rate, config.sample_risk_threshold),
            eval,
            portfolio: Arc::new(PortfolioStore::new(db.clone())),
            planned_executions: Arc::new(Mutex::new(HashMap::new())),
            evolve_history,
            evolve_enhancements,
            candidates: Arc::new(CandidateStore::new()),
            active_promotions: Arc::new(ActivePromotions::new()),
            db,
            config,
            provider_registry_state_path,
        }
    }

    async fn plan_from_input(
        &self,
        input: ExecutionInput,
        authenticated_actor: &str,
    ) -> Result<ExecutionPlan, Status> {
        let plan_id = uuid::Uuid::new_v4().to_string();
        let normalized_user_id = if input.user_id.is_empty() {
            "default".to_string()
        } else {
            input.user_id.clone()
        };
        let budget_pressure = self.budget.namespace_pressure(&input.namespace);
        let namespace_hint = input.namespace.trim().to_string();
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&input.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        let template_only =
            data_class == DataClass::Sensitive && task_class == TaskClass::TemplateOnly;
        let mut pipeline_req = pipe::PipelineRequest {
            request_id: input.request_id.clone(),
            namespace: input.namespace.clone(),
            spec: input.spec.clone(),
            model: input.preferred_model.clone(),
            runtime: input.preferred_runtime.clone(),
            task_type: input.task_type.clone(),
            priority: input.priority,
            risk_score: 0.0,
            budget_pressure: budget_pressure.clone(),
            review_model: String::new(),
            egress_records: vec![],
            external_egress: !safe_only,
            template_only,
            expanded_context_items: 0,
            evidence_references: vec![],
            memory_references: vec![],
            memory_holdouts: vec![],
            memory_actor: authenticated_actor.into(),
            memory_assignment_id: plan_id.clone(),
            memory_token_budget: 512,
            allowed_evidence_classes: std::collections::HashSet::new(),
        };
        let affinity = crate::chisei::affinity::get_affinity(&self.db, namespace_hint.as_str());
        let context_expansion_gate = self.pipeline_context_expansion_gate(&input.namespace);
        let evidence_context_gates =
            self.applicable_evidence_context_gates(&pipeline_req, context_expansion_gate.allowed)?;
        let allowed_evidence_classes = evidence_context_gates
            .iter()
            .filter(|class_gate| class_gate.effective_allowed)
            .map(|class_gate| pipe::EvidenceContextClass {
                source_type: class_gate.source_type.clone(),
                evidence_type: class_gate.evidence_type.clone(),
            })
            .collect::<HashSet<_>>();
        let initial_run = self.pipeline.run_with_context_admission(
            &mut pipeline_req,
            &self.db,
            context_expansion_gate.allowed,
            allowed_evidence_classes.clone(),
        );
        let fallback_runtime = pipeline_req.runtime.clone();
        let (initial_runtime, initial_model) = self
            .resolve_model_for_run(
                &input,
                &fallback_runtime,
                &initial_run,
                effective_policy.as_ref(),
                safe_only,
                &safe_providers,
            )
            .await?;
        let initial_provider = crate::llm::provider_name(&initial_model).to_string();
        let initial_provider_is_external =
            crate::chisei::egress::is_external_provider(&initial_provider);
        let (run, resolved_runtime, resolved_model, provider, provider_is_external) =
            if initial_provider_is_external || safe_only || template_only {
                (
                    initial_run,
                    initial_runtime,
                    initial_model,
                    initial_provider,
                    true,
                )
            } else {
                let mut local_pipeline_req = pipe::PipelineRequest {
                    request_id: input.request_id.clone(),
                    namespace: input.namespace.clone(),
                    spec: input.spec.clone(),
                    model: input.preferred_model.clone(),
                    runtime: input.preferred_runtime.clone(),
                    task_type: input.task_type.clone(),
                    priority: input.priority,
                    risk_score: 0.0,
                    budget_pressure: budget_pressure.clone(),
                    review_model: String::new(),
                    egress_records: vec![],
                    external_egress: false,
                    template_only,
                    expanded_context_items: 0,
                    evidence_references: vec![],
                    memory_references: vec![],
                    memory_holdouts: vec![],
                    memory_actor: authenticated_actor.into(),
                    memory_assignment_id: plan_id.clone(),
                    memory_token_budget: 512,
                    allowed_evidence_classes: std::collections::HashSet::new(),
                };
                let local_run = self.pipeline.run_with_context_admission(
                    &mut local_pipeline_req,
                    &self.db,
                    context_expansion_gate.allowed,
                    allowed_evidence_classes,
                );
                let (local_runtime, local_model) = self
                    .resolve_model_for_run(
                        &input,
                        &local_pipeline_req.runtime,
                        &local_run,
                        effective_policy.as_ref(),
                        safe_only,
                        &safe_providers,
                    )
                    .await?;
                let local_provider = crate::llm::provider_name(&local_model).to_string();
                if crate::chisei::egress::is_external_provider(&local_provider) {
                    (
                        initial_run,
                        initial_runtime,
                        initial_model,
                        initial_provider,
                        true,
                    )
                } else {
                    (local_run, local_runtime, local_model, local_provider, false)
                }
            };
        self.record_context_expansion_gate(
            &input.request_id,
            &input.namespace,
            &context_expansion_gate,
            run.expanded_context_items,
        )?;
        self.record_evidence_context_gates(
            &input.request_id,
            &input.namespace,
            &evidence_context_gates,
            &run.evidence_references,
        )?;
        let egress_decisions =
            build_egress_decisions(&run.egress_records, &provider, provider_is_external);
        let prepared_messages = build_prepared_messages(&input, &run.prepared_spec);
        let estimate_req = super::pb::llm::ChatRequest {
            model: resolved_model.clone(),
            system: input.system.clone(),
            messages: prepared_messages
                .iter()
                .map(|m| super::pb::llm::Message {
                    role: m.role.clone(),
                    content: m.content.clone(),
                    tool_call_id: m.tool_call_id.clone(),
                    tool_calls: m
                        .tool_calls
                        .iter()
                        .map(|tc| super::pb::llm::ToolCall {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            args_json: tc.args_json.clone(),
                        })
                        .collect(),
                })
                .collect(),
            tools: input
                .tools
                .iter()
                .map(|t| super::pb::llm::ToolDef {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema_json: t.input_schema_json.clone(),
                })
                .collect(),
            max_tokens: input.max_tokens,
            user_id: Some(normalized_user_id.clone()),
        };
        let estimated_tokens = estimate_chat_request(&estimate_req);
        let allowed = self
            .budget
            .check_with_metric(&normalized_user_id, estimated_tokens, METRIC_TOKENS)
            .is_ok();
        let usage = self
            .budget
            .get_usage_with_metric(&normalized_user_id, METRIC_TOKENS);
        let budget_reason = if allowed {
            String::new()
        } else {
            format!(
                "budget exceeded: used {} + {} > {}",
                usage.tokens_used, estimated_tokens, usage.max_tokens
            )
        };
        let mut normalized_input = input.clone();
        normalized_input.user_id = normalized_user_id;
        normalized_input.estimated_tokens = estimated_tokens;
        let mut warnings = run.warnings();
        let final_route_bias_value =
            crate::chisei::model_routing::route_bias(&run.steps).map(str::to_string);
        let final_route_bias = final_route_bias_value.as_deref();
        let review_policy = if let Some(p) = run.review_policy.as_ref() {
            let model = if p.model.is_empty() {
                resolved_model.clone()
            } else {
                self.resolve_live_model(
                    &p.model,
                    effective_policy.as_ref(),
                    final_route_bias,
                    safe_only,
                    &safe_providers,
                )
                .await
                .unwrap_or_else(|_| resolved_model.clone())
            };
            Some(ReviewPolicy {
                confidence_threshold: p.confidence_threshold,
                max_cycles: p.max_cycles,
                model,
            })
        } else {
            None
        };
        let namespace_eval_signal = if namespace_hint.is_empty() {
            None
        } else {
            self.eval.namespace_regression_signal(&namespace_hint)
        };
        if let Some(signal) = namespace_eval_signal
            .as_ref()
            .filter(|signal| signal.regressed)
        {
            warnings.push(signal.reason.clone());
        }
        let eval_regressed = namespace_eval_signal
            .as_ref()
            .map(|signal| signal.regressed)
            .unwrap_or(false);
        let eval_regression_reason = namespace_eval_signal
            .as_ref()
            .filter(|signal| signal.regressed)
            .map(|signal| signal.reason.clone())
            .unwrap_or_default();
        let mut executable = allowed && !eval_regressed;
        let low_success_namespace = affinity.low_success;
        // Sampling: the pipeline decides from request metadata; the eval-driven
        // adaptive trigger (oversample regressed namespaces) is applied here since the
        // eval store lives on the service.
        let mut sampling = crate::chisei::sampling::decode_sampling(&run.steps).unwrap_or(
            crate::chisei::sampling::SamplingDecision {
                sampled: false,
                effective_rate: self.config.sample_rate,
                reason: "not_sampled".into(),
            },
        );
        if eval_regressed && !sampling.sampled {
            sampling.sampled = true;
            sampling.effective_rate = 1.0;
            sampling.reason = "eval_regressed".into();
        }
        if sampling.sampled {
            let mut evidence = std::collections::HashMap::new();
            evidence.insert(
                "effective_rate".to_string(),
                sampling.effective_rate.to_string(),
            );
            evidence.insert("risk_score".to_string(), run.risk_score.to_string());
            evidence.insert("model".to_string(), resolved_model.clone());
            let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.sampling".into(),
                action: "sample".into(),
                reason: sampling.reason.clone(),
                evidence,
                target_id: input.request_id.clone(),
                outcome: "sampled".into(),
            });
        }
        if safe_only {
            let provider_safe =
                crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers);
            if !provider_safe {
                self.record_privacy_audit(
                    "blocked",
                    &input.request_id,
                    &provider,
                    data_class,
                    task_class,
                    "unsafe_provider",
                );
                return Err(Status::failed_precondition(
                    crate::chisei::privacy::gate_reason(data_class, task_class, &provider),
                ));
            }
            self.record_privacy_audit(
                "forced_local",
                &input.request_id,
                &provider,
                data_class,
                task_class,
                "safe_provider_required",
            );
        } else if template_only && provider_is_external {
            self.record_privacy_audit(
                "allowed_template_only",
                &input.request_id,
                &provider,
                data_class,
                task_class,
                "template_only_sanitization_contract",
            );
        }
        let mut egress_decisions = egress_decisions;
        let leak_findings = self.leak_findings_for_payload(
            &input.namespace,
            &provider,
            data_class,
            &payload_for_leak_check(&input.system, &prepared_messages, &input.tools),
        );
        if !leak_findings.is_empty() {
            egress_decisions.extend(leak_findings_to_decisions(
                &provider,
                provider_is_external,
                &leak_findings,
            ));
            self.record_leak_audit("leak_check", &input.request_id, &provider, &leak_findings);
            if leak_findings
                .iter()
                .any(|finding| finding.action == LeakAction::Block)
            {
                executable = false;
                warnings.push("privacy leak checker blocked outbound payload".into());
            }
        }
        if data_class == DataClass::Sensitive
            && task_class == TaskClass::TemplateOnly
            && !crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers)
            && let Some(warning) = self
                .run_leak_reviewer(&input.request_id, &provider, &input.spec)
                .await
        {
            warnings.push(warning);
        }
        self.record_egress_audit(
            "prepare_context",
            &input.request_id,
            &provider,
            &resolved_model,
            &egress_decisions,
        );
        Ok(ExecutionPlan {
            plan_id,
            input: Some(normalized_input),
            resolved_runtime,
            resolved_model: resolved_model.clone(),
            enriched_spec: run.prepared_spec.clone(),
            prepared_system: input.system.clone(),
            prepared_messages,
            tools: input.tools.clone(),
            budget: Some(BudgetVerdict {
                allowed,
                usage: Some(BudgetUsage {
                    user_id: usage.user_id,
                    tokens_used: usage.tokens_used,
                    max_tokens: usage.max_tokens,
                    period_type: usage.period_type.as_str().into(),
                    period_start: usage.period_start,
                }),
                reason: budget_reason,
            }),
            steps: run
                .steps
                .iter()
                .map(|s| StepDecision {
                    step: s.step.clone(),
                    action: s.action.clone(),
                    reasoning: s.reasoning.clone(),
                    confidence: s.confidence,
                    suggestion: s.suggestion.clone(),
                    value: s.value.clone(),
                })
                .collect(),
            review_policy,
            risk_score: run.risk_score,
            low_success_namespace,
            executable,
            warnings,
            max_tokens: input.max_tokens,
            created_at: chrono::Utc::now().timestamp_millis(),
            affinity_namespaces: affinity.namespaces,
            eval_regressed,
            eval_regression_reason,
            sampled: sampling.sampled,
            sample_rate: sampling.effective_rate,
            sample_reason: sampling.reason,
            egress_decisions,
            task_class: task_class.as_str().into(),
            evidence_references: run
                .evidence_references
                .iter()
                .map(context_evidence_reference)
                .collect(),
            memory_references: run
                .memory_references
                .iter()
                .map(memory_context_reference)
                .collect(),
            planning_actor: authenticated_actor.into(),
            memory_holdouts: run
                .memory_holdouts
                .iter()
                .map(|holdout| super::pb::chisei::MemoryHoldoutReference {
                    memory_id: holdout.memory_id.clone(),
                    memory_version: holdout.memory_version,
                    classification: holdout.classification.clone(),
                    content_digest: holdout.content_digest.clone(),
                })
                .collect(),
        })
    }

    fn cache_plan(&self, plan: ExecutionPlan) {
        let mut plans = self
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        prune_expired_plans(&mut plans);
        let inserted_plan_id = plan.plan_id.clone();
        plans.insert(inserted_plan_id.clone(), plan);
        prune_excess_plans(&mut plans, Some(&inserted_plan_id));
    }

    fn record_execution_memory_injections(
        &self,
        operation_id: &str,
        actor: &str,
        references: &[MemoryContextReference],
    ) -> Result<(), Status> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        for reference in references {
            let memory = self
                .db
                .get_kioku_memory(&reference.memory_id, reference.memory_version)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("planned memory version not found"))?;
            if !memory_lifecycle_allows_execution(
                memory.state,
                memory.expires_at_ms,
                memory.retention_until_ms,
                now_ms,
            ) {
                return Err(Status::failed_precondition(
                    "planned memory version is no longer active",
                ));
            }
            let authorized_ceiling = self
                .db
                .kioku_authorized_classification_ceiling(&memory.namespace, actor)
                .map_err(|_| {
                    Status::permission_denied(
                        "executing actor is not authorized for planned memory",
                    )
                })?;
            if memory.classification > authorized_ceiling {
                return Err(Status::permission_denied(
                    "planned memory classification exceeds executing actor grant",
                ));
            }
            if crate::chisei::kioku::memory_claim_digest(&memory) != reference.content_digest {
                return Err(Status::failed_precondition(
                    "planned memory digest no longer matches the cached reference",
                ));
            }
        }
        for reference in references {
            self.db
                .record_kioku_lifecycle_event(&crate::chisei::kioku::MemoryLifecycleEvent {
                    memory_id: reference.memory_id.clone(),
                    memory_version: reference.memory_version,
                    action: "injected".into(),
                    from_state: Some("active".into()),
                    to_state: "active".into(),
                    actor: actor.into(),
                    reason: format!("pipeline operation {operation_id}"),
                    recorded_at_ms: now_ms,
                })
                .map_err(Status::internal)?;
        }
        Ok(())
    }

    fn invalidate_ineligible_execution_memory_holdouts(
        &self,
        operation_id: &str,
        actor: &str,
        references: &[super::pb::chisei::MemoryHoldoutReference],
    ) -> Result<(), Status> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        for reference in references {
            let Some(memory) = self
                .db
                .get_kioku_memory(&reference.memory_id, reference.memory_version)
                .map_err(Status::internal)?
            else {
                continue;
            };
            let authorized = self
                .db
                .kioku_authorized_classification_ceiling(&memory.namespace, actor)
                .is_ok_and(|ceiling| memory.classification <= ceiling);
            let eligible = memory_lifecycle_allows_execution(
                memory.state,
                memory.expires_at_ms,
                memory.retention_until_ms,
                now_ms,
            ) && authorized
                && memory.classification.as_str() == reference.classification
                && crate::chisei::kioku::memory_claim_digest(&memory) == reference.content_digest;
            if !eligible {
                self.db
                    .record_kioku_lifecycle_event(&crate::chisei::kioku::MemoryLifecycleEvent {
                        memory_id: reference.memory_id.clone(),
                        memory_version: reference.memory_version,
                        action: "holdout_invalidated".into(),
                        from_state: Some(memory.state.as_str().into()),
                        to_state: memory.state.as_str().into(),
                        actor: actor.into(),
                        reason: format!("pipeline operation {operation_id}"),
                        recorded_at_ms: now_ms,
                    })
                    .map_err(Status::internal)?;
            }
        }
        Ok(())
    }

    fn record_planned_operation(&self, plan: &ExecutionPlan, actor: &str) -> Result<(), String> {
        let input = plan
            .input
            .as_ref()
            .ok_or_else(|| "plan input required".to_string())?;
        let operation_id = plan.plan_id.clone();
        let policy_version = self
            .policy
            .effective_policy(&input.namespace)
            .map(|policy| policy.version())
            .unwrap_or_else(|| "implicit-allow/v1".to_string());
        let started = plan.created_at;
        let mut events = vec![
            receipt_event(
                &operation_id,
                "intent",
                None,
                started,
                ReceiptEventKind::IntentRecorded,
                actor,
                {
                    let mut attributes = BTreeMap::from([
                        ("request_id".into(), input.request_id.clone()),
                        ("task_type".into(), input.task_type.clone()),
                        ("intent_hash".into(), content_hash([input.spec.as_bytes()])),
                    ]);
                    if !input.logical_operation_id.trim().is_empty() {
                        attributes.insert(
                            "logical_operation_id".into(),
                            input.logical_operation_id.trim().into(),
                        );
                    }
                    if !input.attempt_id.trim().is_empty() {
                        attributes.insert("attempt_id".into(), input.attempt_id.trim().into());
                    }
                    attributes
                },
            ),
            receipt_event(
                &operation_id,
                "context",
                Some("intent"),
                started,
                ReceiptEventKind::ContextGoverned,
                "chisei.pipeline",
                BTreeMap::from([
                    (
                        "prepared_context_hash".into(),
                        content_hash(
                            std::iter::once(plan.prepared_system.as_bytes()).chain(
                                plan.prepared_messages
                                    .iter()
                                    .map(|message| message.content.as_bytes()),
                            ),
                        ),
                    ),
                    ("raw_context_stored".into(), "false".into()),
                ]),
            ),
            receipt_event(
                &operation_id,
                "policy",
                Some("context"),
                started,
                ReceiptEventKind::PolicyDecided,
                "chisei.policy",
                BTreeMap::from([
                    ("policy_version".into(), policy_version.clone()),
                    ("executable".into(), plan.executable.to_string()),
                    ("risk_score".into(), plan.risk_score.to_string()),
                ]),
            ),
            receipt_event(
                &operation_id,
                "route",
                Some("policy"),
                started,
                ReceiptEventKind::RouteSelected,
                "chisei.routing",
                BTreeMap::from([
                    ("runtime".into(), plan.resolved_runtime.clone()),
                    ("model".into(), plan.resolved_model.clone()),
                ]),
            ),
            receipt_event(
                &operation_id,
                "budget",
                Some("route"),
                started,
                ReceiptEventKind::BudgetDecided,
                "chisei.budget",
                BTreeMap::from([
                    (
                        "allowed".into(),
                        plan.budget
                            .as_ref()
                            .is_some_and(|budget| budget.allowed)
                            .to_string(),
                    ),
                    (
                        "estimated_tokens".into(),
                        input.estimated_tokens.to_string(),
                    ),
                ]),
            ),
        ];
        let mut context = GovernedReference {
            kind: "execution_context".into(),
            reference: format!("operation:{operation_id}:context"),
            content_hash: events[1].attributes.get("prepared_context_hash").cloned(),
            disclosed_fields: vec!["system".into(), "messages.content".into()],
            omitted: true,
            omission_reason: Some("raw private context is not copied into receipts".into()),
        };
        context.disclosed_fields.sort();
        events[1].references.push(context);
        events[1]
            .references
            .extend(
                plan.evidence_references
                    .iter()
                    .map(|reference| GovernedReference {
                        kind: "external_evidence".into(),
                        reference: format!(
                            "evidence:{}@{}",
                            reference.submission_id, reference.source_version
                        ),
                        content_hash: Some(reference.content_digest.clone()),
                        disclosed_fields: reference.disclosed_fields.clone(),
                        omitted: false,
                        omission_reason: None,
                    }),
            );
        events[1]
            .references
            .extend(
                plan.memory_references
                    .iter()
                    .map(|reference| GovernedReference {
                        kind: "kioku_memory".into(),
                        reference: format!(
                            "memory:{}@{}",
                            reference.memory_id, reference.memory_version
                        ),
                        content_hash: Some(reference.content_digest.clone()),
                        disclosed_fields: vec!["claim".into()],
                        omitted: false,
                        omission_reason: None,
                    }),
            );
        if !plan.egress_decisions.is_empty() {
            events.push(receipt_event(
                &operation_id,
                "egress",
                Some("budget"),
                started,
                ReceiptEventKind::EgressDecided,
                "chisei.egress",
                BTreeMap::from([
                    (
                        "decision_count".into(),
                        plan.egress_decisions.len().to_string(),
                    ),
                    (
                        "redacted_field_count".into(),
                        plan.egress_decisions
                            .iter()
                            .map(|decision| decision.redacted.len())
                            .sum::<usize>()
                            .to_string(),
                    ),
                ]),
            ));
        }
        let (completed_at_ms, uncovered_surfaces) = if plan.executable {
            (
                None,
                vec![
                    UncoveredSurface {
                        surface: ReceiptSurface::Attempt,
                        reason: "operation is planned but has not started".into(),
                    },
                    UncoveredSurface {
                        surface: ReceiptSurface::ModelCall,
                        reason: "operation is planned but has not called a model".into(),
                    },
                    UncoveredSurface {
                        surface: ReceiptSurface::Outcome,
                        reason: "operation is planned but has no terminal outcome".into(),
                    },
                ],
            )
        } else {
            let parent = if plan.egress_decisions.is_empty() {
                "budget"
            } else {
                "egress"
            };
            events.push(receipt_event(
                &operation_id,
                "outcome",
                Some(parent),
                started,
                ReceiptEventKind::OutcomeRecorded,
                actor,
                BTreeMap::from([
                    ("status".into(), "denied".into()),
                    ("completion_reason".into(), "plan_not_executable".into()),
                    ("warning_count".into(), plan.warnings.len().to_string()),
                ]),
            ));
            (Some(started), Vec::new())
        };
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id,
            parent_operation_id: None,
            namespace: input.namespace.clone(),
            operation_class: if input.task_type.trim().is_empty() {
                "model_inference".into()
            } else {
                input.task_type.trim().into()
            },
            initiating_actor: actor.to_string(),
            schema_version: EXECUTION_SCHEMA_VERSION.into(),
            policy_version,
            started_at_ms: started,
            completed_at_ms,
            events,
            uncovered_surfaces,
            reporter_grants: Vec::new(),
        };
        let holdouts = plan
            .memory_holdouts
            .iter()
            .map(|holdout| (holdout.memory_id.clone(), holdout.memory_version))
            .collect::<Vec<_>>();
        self.db
            .put_operation_receipt_with_kioku_holdouts(&receipt, &holdouts, actor, started)?;
        Ok(())
    }

    fn record_completed_operation(
        &self,
        plan: &ExecutionPlan,
        actor: &str,
        response: &PlannedChatResponse,
        attempt_started_at_ms: i64,
        completed_at_ms: i64,
    ) -> Result<(), String> {
        record_completed_operation_on(
            &self.db,
            plan,
            actor,
            response,
            attempt_started_at_ms,
            completed_at_ms,
        )
    }

    async fn resolve_model_for_run(
        &self,
        input: &ExecutionInput,
        fallback_runtime: &str,
        run: &pipe::RunResult,
        policy: Option<&crate::chisei::policy::Policy>,
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
    ) -> Result<(String, String), Status> {
        let recommended_model = run
            .recommended_model()
            .map(|(model, _)| model.to_string())
            .unwrap_or_else(|| input.preferred_model.clone());
        let route_bias_value =
            crate::chisei::model_routing::route_bias(&run.steps).map(str::to_string);
        let route_bias = route_bias_value.as_deref();
        let preferred_model = choose_preferred_model(
            &input.preferred_model,
            &recommended_model,
            route_bias,
            policy,
        );
        let preferred_runtime = if input.preferred_runtime.is_empty() {
            fallback_runtime
        } else {
            &input.preferred_runtime
        };
        let (runtime, model) = self
            .policy
            .resolve(&input.namespace, preferred_runtime, &preferred_model)
            .map_err(Status::invalid_argument)?;
        let model = self
            .resolve_live_model(&model, policy, route_bias, safe_only, safe_providers)
            .await
            .map_err(Status::failed_precondition)?;
        let runtime = final_runtime_for_model(policy, &runtime, &model)
            .map_err(Status::failed_precondition)?;
        Ok((runtime, model))
    }

    fn data_class(&self, policy: Option<&crate::chisei::policy::Policy>) -> DataClass {
        policy
            .map(|policy| DataClass::parse(&policy.data_class))
            .filter(|class| *class != DataClass::Unclassified)
            .unwrap_or_else(|| DataClass::parse(&self.config.default_data_class))
    }

    fn leak_findings_for_payload(
        &self,
        namespace: &str,
        provider: &str,
        data_class: DataClass,
        payload: &str,
    ) -> Vec<LeakFinding> {
        let safe = crate::chisei::privacy::safe_providers(&self.config);
        if crate::chisei::privacy::provider_safe_to_send(provider, &safe) {
            return vec![];
        }
        let rules = self.leak_rules(namespace);
        let entities = if data_class == DataClass::Sensitive {
            self.sensitive_entities(namespace)
        } else {
            vec![]
        };
        crate::chisei::privacy::check_payload(payload, &rules, &entities)
    }

    fn leak_rules(&self, namespace: &str) -> Vec<LeakRule> {
        let mut rules = Vec::new();
        for ns in ["", namespace] {
            let Ok(objects) = self.db.list_all_objects(&ListFilter {
                kind: Some("leak_rule".into()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            }) else {
                continue;
            };
            for obj in objects {
                let Some(pattern) = obj.properties.get("pattern") else {
                    continue;
                };
                let Ok(pattern) = Regex::new(pattern) else {
                    continue;
                };
                rules.push(LeakRule {
                    id: obj.id,
                    label: obj
                        .properties
                        .get("label")
                        .cloned()
                        .filter(|value| !value.is_empty())
                        .unwrap_or(obj.name),
                    pattern,
                    action: LeakAction::parse(
                        obj.properties
                            .get("action")
                            .map(String::as_str)
                            .unwrap_or("block"),
                    ),
                });
            }
        }
        rules
    }

    fn sensitive_entities(&self, namespace: &str) -> Vec<String> {
        let objects = self
            .db
            .list_all_objects(&ListFilter {
                namespace: Some(namespace.to_string()),
                ..Default::default()
            })
            .unwrap_or_default();
        crate::chisei::privacy::entity_scan_literals(&objects)
    }

    fn record_egress_audit(
        &self,
        action: &str,
        request_id: &str,
        provider: &str,
        model: &str,
        decisions: &[EgressDecision],
    ) {
        let included_count: usize = decisions.iter().map(|d| d.included.len()).sum();
        let redacted_count: usize = decisions.iter().map(|d| d.redacted.len()).sum();
        let mut evidence = std::collections::HashMap::new();
        evidence.insert("provider".to_string(), provider.to_string());
        evidence.insert("model".to_string(), model.to_string());
        evidence.insert("decisions".to_string(), decisions.len().to_string());
        evidence.insert("included_count".to_string(), included_count.to_string());
        evidence.insert("redacted_count".to_string(), redacted_count.to_string());
        evidence.insert(
            "included_fields".to_string(),
            serde_json::to_string(
                &decisions
                    .iter()
                    .flat_map(|decision| decision.included.iter())
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".into()),
        );
        evidence.insert(
            "redacted_fields".to_string(),
            serde_json::to_string(
                &decisions
                    .iter()
                    .flat_map(|decision| decision.redacted.iter())
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".into()),
        );
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.egress".into(),
            action: action.into(),
            reason: "context egress policy applied".into(),
            evidence,
            target_id: request_id.into(),
            outcome: if redacted_count > 0 {
                "redacted".into()
            } else {
                "included".into()
            },
        });
    }

    fn record_privacy_audit(
        &self,
        outcome: &str,
        request_id: &str,
        provider: &str,
        data_class: DataClass,
        task_class: TaskClass,
        reason: &str,
    ) {
        let mut evidence = std::collections::HashMap::new();
        evidence.insert("provider".to_string(), provider.to_string());
        evidence.insert("data_class".to_string(), data_class.as_str().to_string());
        evidence.insert("task_class".to_string(), task_class.as_str().to_string());
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.privacy".into(),
            action: "gate".into(),
            reason: reason.into(),
            evidence,
            target_id: request_id.into(),
            outcome: outcome.into(),
        });
    }

    fn record_leak_audit(
        &self,
        action: &str,
        request_id: &str,
        provider: &str,
        findings: &[LeakFinding],
    ) {
        let mut evidence = std::collections::HashMap::new();
        evidence.insert("provider".to_string(), provider.to_string());
        evidence.insert("finding_count".to_string(), findings.len().to_string());
        evidence.insert(
            "block_count".to_string(),
            findings
                .iter()
                .filter(|finding| finding.action == LeakAction::Block)
                .count()
                .to_string(),
        );
        evidence.insert(
            "labels".to_string(),
            findings
                .iter()
                .map(|finding| format!("{}:{}", finding.rule_label, finding.match_count))
                .collect::<Vec<_>>()
                .join(","),
        );
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.privacy".into(),
            action: action.into(),
            reason: "leak checker evaluated outbound payload".into(),
            evidence,
            target_id: request_id.into(),
            outcome: if findings
                .iter()
                .any(|finding| finding.action == LeakAction::Block)
            {
                "leak_blocked".into()
            } else {
                "leak_warned".into()
            },
        });
    }

    async fn run_leak_reviewer(
        &self,
        request_id: &str,
        provider: &str,
        abstract_task: &str,
    ) -> Option<String> {
        let model = self.config.leak_review_model.as_ref()?;
        let safe = crate::chisei::privacy::safe_providers(&self.config);
        let reviewer_provider = crate::llm::provider_name(model);
        if !crate::chisei::privacy::provider_safe_to_send(reviewer_provider, &safe) {
            self.record_leak_reviewer_audit(
                request_id,
                provider,
                model,
                "reviewer_error",
                "reviewer model is not safe to send sensitive-review prompts",
            );
            return Some("local leak reviewer was skipped because its model is not safe".into());
        }
        let registry_state_path =
            crate::provider_profile::provider_registry_state_path(&self.config.db_path);
        let registry =
            match crate::provider_profile::refresh_provider_registry_async(&registry_state_path)
                .await
            {
                Ok(registry) => registry,
                Err(_) => {
                    self.record_leak_reviewer_audit(
                        request_id,
                        provider,
                        model,
                        "reviewer_error",
                        "provider registry is unavailable",
                    );
                    return Some("local leak reviewer could not run".into());
                }
            };
        let Ok(reviewer) = crate::llm::resolve_with_registry(
            model,
            &registry,
            Some(&registry_state_path),
            self.config.anthropic_api_key.as_deref(),
            self.config.openai_api_key.as_deref(),
            &self.config.ollama_url,
            self.config.native_llm_url.as_deref(),
        ) else {
            self.record_leak_reviewer_audit(
                request_id,
                provider,
                model,
                "reviewer_error",
                "reviewer provider is not configured",
            );
            return Some("local leak reviewer could not run".into());
        };
        let req = crate::llm::ChatRequest {
            model: model.clone(),
            system: "You are a local privacy reviewer. Answer only SAFE or RISK with one short reason. Does this abstract request reveal sector, position, timing, or proprietary intent?".into(),
            messages: vec![crate::llm::Message {
                role: "user".into(),
                content: abstract_task.to_string(),
                tool_call_id: String::new(),
                tool_calls: vec![],
            }],
            tools: vec![],
            max_tokens: 64,
        };
        match reviewer.chat(&req).await {
            Ok(resp) => {
                let lower = resp.content.to_ascii_lowercase();
                let risky = lower.contains("risk") || lower.contains("unsafe");
                self.record_leak_reviewer_audit(
                    request_id,
                    provider,
                    model,
                    if risky { "warn" } else { "pass" },
                    if risky {
                        "reviewer flagged template-inversion risk"
                    } else {
                        "reviewer did not flag template-inversion risk"
                    },
                );
                risky.then(|| "local leak reviewer flagged template-inversion risk".into())
            }
            Err(_) => {
                self.record_leak_reviewer_audit(
                    request_id,
                    provider,
                    model,
                    "reviewer_error",
                    "reviewer call failed",
                );
                Some("local leak reviewer could not run".into())
            }
        }
    }

    fn record_leak_reviewer_audit(
        &self,
        request_id: &str,
        provider: &str,
        reviewer_model: &str,
        outcome: &str,
        reason: &str,
    ) {
        let mut evidence = std::collections::HashMap::new();
        evidence.insert("provider".to_string(), provider.to_string());
        evidence.insert("reviewer_model".to_string(), reviewer_model.to_string());
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.privacy".into(),
            action: "leak_review".into(),
            reason: reason.into(),
            evidence,
            target_id: request_id.into(),
            outcome: outcome.into(),
        });
    }

    async fn resolve_live_model(
        &self,
        model: &str,
        policy: Option<&crate::chisei::policy::Policy>,
        route_bias: Option<&str>,
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
    ) -> Result<String, String> {
        validate_explicit_requested_model(model)?;
        let empty_allowed = Vec::new();
        let allowed_models = policy
            .map(|policy| policy.allowed_models.as_slice())
            .unwrap_or(empty_allowed.as_slice());
        let base_context = crate::chisei::model_routing::RoutingContext {
            requested: model,
            allowed_models,
            route_bias,
            config: &self.config,
            ollama_models: &[],
            safe_only,
            safe_providers,
        };
        let needs_ollama_first = !model.contains('/')
            && model != "native-default"
            && model != "cheap"
            && model != "capable"
            && crate::llm::provider_name(model) == "native";
        if !needs_ollama_first
            && let Ok(resolved) = crate::chisei::model_routing::resolve_model(base_context.clone())
        {
            return Ok(resolved);
        }

        let ollama_models = crate::llm::ollama::list_models(&self.config.ollama_url)
            .await
            .unwrap_or_default();
        crate::chisei::model_routing::resolve_model(crate::chisei::model_routing::RoutingContext {
            ollama_models: &ollama_models,
            ..base_context
        })
    }

    async fn refresh_provider_registry_for_resolution(
        &self,
    ) -> Result<crate::provider_profile::ProviderRegistry, Status> {
        let Some(path) = self.provider_registry_state_path.as_deref() else {
            return Ok(crate::provider_profile::provider_registry_snapshot());
        };
        crate::provider_profile::refresh_provider_registry_async(path)
            .await
            .map_err(|error| Status::unavailable(format!("provider registry unavailable: {error}")))
    }

    fn evolve_tasks(&self) -> Vec<crate::chisei::evolve::TaskRecord> {
        let mut tasks: Vec<_> = self
            .evolve_history
            .lock()
            .expect("evolve history poisoned")
            .values()
            .cloned()
            .collect();
        tasks.sort_by(|a, b| a.id.cmp(&b.id));
        tasks
    }

    fn evolve_task(&self, request_id: &str) -> Option<crate::chisei::evolve::TaskRecord> {
        self.evolve_history
            .lock()
            .expect("evolve history poisoned")
            .get(request_id)
            .cloned()
    }

    fn record_evolve_task(
        &self,
        request_id: &str,
        namespace: &str,
        spec: &str,
        original_spec: Option<&str>,
        status: &str,
        tokens_used: i32,
    ) -> Result<(), String> {
        record_evolve_task_on(
            &self.db,
            &self.evolve_history,
            EvolveTaskRecord {
                request_id,
                namespace,
                spec,
                original_spec,
                status,
                tokens_used,
            },
        )
    }

    fn tracked_original_spec(
        &self,
        request_id: &str,
        submitted_spec: &str,
        prepared_spec: &str,
    ) -> Option<String> {
        if prepared_spec != submitted_spec {
            return Some(submitted_spec.to_string());
        }
        self.evolve_enhancements
            .lock()
            .expect("evolve enhancements poisoned")
            .get(request_id)
            .cloned()
    }
}

fn choose_preferred_model(
    explicit_model: &str,
    recommended_model: &str,
    route_bias: Option<&str>,
    policy: Option<&crate::chisei::policy::Policy>,
) -> String {
    if !explicit_model.is_empty() {
        return explicit_model.to_string();
    }
    let Some(route_bias) = route_bias else {
        return recommended_model.to_string();
    };
    let alias = format!("ollama/{route_bias}");
    if let Some(policy) = policy {
        if policy.default_model == alias
            || policy.allowed_models.iter().any(|model| model == &alias)
        {
            return alias;
        }
        if policy.default_model == route_bias
            || policy
                .allowed_models
                .iter()
                .any(|model| model == route_bias)
        {
            return route_bias.to_string();
        }
    }
    recommended_model.to_string()
}

fn budget_metric(metric: &str) -> Result<&'static str, Status> {
    if metric.trim().eq_ignore_ascii_case(METRIC_REQUESTS) {
        Ok(METRIC_REQUESTS)
    } else if metric.trim().is_empty() || metric.trim().eq_ignore_ascii_case(METRIC_TOKENS) {
        Ok(METRIC_TOKENS)
    } else {
        Err(Status::invalid_argument(
            "unsupported budget metric; use tokens or requests",
        ))
    }
}

/// Builds the budget scope id for a request. An explicit `subject` bypasses
/// hierarchy construction entirely (kept for legacy/direct callers and any
/// caller that wants a flat, non-nested scope) and chains only through the
/// unset `global` root. Otherwise the scope is built from whichever of
/// project/agent/work_unit are present, in that nesting order, so that
/// `CheckBudget`/`RecordUsage` walk and deduct the whole ancestor chain
/// (project -> agent -> work_unit) atomically — see `db::chisei_budget`.
fn budget_subject(
    subject: &str,
    project: &str,
    agent: &str,
    key_id: &str,
    work_unit: &str,
    legacy_user_id: &str,
) -> Result<String, Status> {
    if !subject.trim().is_empty() {
        return Ok(subject.trim().to_string());
    }
    let mut segments = Vec::new();
    if !project.trim().is_empty() {
        segments.push(format!("project:{}", project.trim()));
    }
    if !agent.trim().is_empty() {
        segments.push(format!("agent:{}", agent.trim()));
    }
    if !work_unit.trim().is_empty() {
        segments.push(format!("work_unit:{}", work_unit.trim()));
    }
    if !segments.is_empty() {
        return Ok(segments.join("/"));
    }
    if !key_id.trim().is_empty() {
        return Ok(format!("gateway_key:{}", key_id.trim()));
    }
    if !legacy_user_id.trim().is_empty() {
        return Ok(legacy_user_id.trim().to_string());
    }
    Err(Status::invalid_argument("budget subject required"))
}

fn active_continuation_allocation(
    db: &SekaiDb,
    work_unit_id: &str,
    budget_identities: &[&str],
    now_ms: i64,
) -> bool {
    let Ok(Some(work_unit)) = db.get_work_unit(work_unit_id) else {
        return false;
    };
    if work_unit.status != WORK_UNIT_STATUS_RUNNING
        || !budget_identities.iter().any(|identity| {
            *identity == work_unit.owner_principal || *identity == work_unit.creator_principal
        })
    {
        return false;
    }
    db.list_reservations(&ReservationFilter {
        work_unit_id: Some(work_unit_id.to_string()),
        status: Some(RESERVATION_STATUS_ACTIVE.to_string()),
        ..Default::default()
    })
    .is_ok_and(|reservations| {
        reservations.iter().any(|reservation| {
            reservation.released_at == 0
                && reservation.expires_at > now_ms
                && budget_identities
                    .iter()
                    .any(|identity| *identity == reservation.lease_owner)
        })
    })
}

fn policy_scopes(req: &ResolvePolicyRequest) -> Vec<String> {
    let mut scopes = Vec::new();
    push_scope(&mut scopes, req.subject.trim());
    if !req.agent.trim().is_empty() {
        push_scope(&mut scopes, &format!("agent:{}", req.agent.trim()));
    }
    if !req.key_id.trim().is_empty() {
        push_scope(&mut scopes, &format!("gateway_key:{}", req.key_id.trim()));
    }
    push_scope(&mut scopes, req.namespace.trim());
    push_scope(&mut scopes, req.project.trim());
    if !req.project.trim().is_empty() {
        push_scope(&mut scopes, &format!("project:{}", req.project.trim()));
    }
    scopes
}

/// Map a request's task class to a cost-tier route bias. Only explicit bulk
/// task classes route to the cheaper tier, and only while no eval regression is
/// active for the scope — a regression fails safe back to the capable tier.
/// Unknown or primary classes never bias to cheap.
fn cheap_route_bias(task_class: &str, eval_regressed: bool) -> Option<&'static str> {
    if eval_regressed {
        return None;
    }
    if crate::chisei::model_routing::is_cheap_eligible_task_class(task_class) {
        Some("cheap")
    } else {
        None
    }
}

/// Whether a runtime supports automatic cheap-tier routing. Limited to the
/// hosted providers whose model tiers are reliably ordered by
/// `named_model_cost_rank` (the metric the demotion gate compares). Ollama and
/// native models are excluded: their cost depends on installed parameter size,
/// not the model name, so the name-based gate cannot tell tiers apart and would
/// silently discard the cheaper choice. Cost tiering for those runtimes is a
/// follow-up. This also guards against non-provider runtimes (e.g. the "kiro"
/// default) producing a bogus alias or a runtime/model mismatch.
fn is_known_provider_runtime(runtime: &str) -> bool {
    matches!(runtime.trim(), "openai" | "anthropic")
}

fn is_registry_provider_runtime(runtime: &str) -> bool {
    matches!(runtime.trim(), "openai" | "anthropic" | "ollama" | "native")
}

fn portfolio_model_allowed(policy: Option<&Policy>, model: &str) -> bool {
    policy.is_none_or(|policy| {
        policy.allowed_models.is_empty()
            || policy.allowed_models.iter().any(|allowed| allowed == model)
    })
}

fn portfolio_runtime_for_model(
    policy: Option<&Policy>,
    current_runtime: &str,
    model: &str,
) -> Option<String> {
    let model_runtime = crate::llm::provider_name(model);
    if model_runtime == current_runtime.trim() {
        return Some(model_runtime.to_string());
    }
    policy
        .filter(|policy| {
            policy.allowed_runtimes.is_empty()
                || policy
                    .allowed_runtimes
                    .iter()
                    .any(|allowed| allowed == model_runtime)
        })
        .map(|_| model_runtime.to_string())
}

fn local_free_runtime_for_model(policy: Option<&Policy>, model: &str) -> Option<String> {
    let runtime = crate::llm::provider_name(model);
    if runtime != "ollama" {
        return None;
    }
    match policy {
        None => Some(runtime.to_string()),
        Some(policy)
            if policy.allowed_runtimes.is_empty()
                || policy
                    .allowed_runtimes
                    .iter()
                    .any(|allowed| allowed == runtime) =>
        {
            Some(runtime.to_string())
        }
        Some(_) => None,
    }
}

fn final_runtime_for_model(
    policy: Option<&Policy>,
    current_runtime: &str,
    model: &str,
) -> Result<String, String> {
    let explicitly_registry_routed = ["openai/", "anthropic/", "ollama/", "native/"]
        .iter()
        .any(|prefix| model.starts_with(prefix));
    if !is_registry_provider_runtime(current_runtime) && !explicitly_registry_routed {
        if model.contains('/') {
            crate::chisei::policy::validate_resolved_route(current_runtime, model)?;
            return Ok(current_runtime.to_string());
        }
        let identity =
            crate::provider_profile::ProviderRegistry::built_in().resolve_model(model)?;
        if identity.provider == "native" {
            crate::provider_profile::resolve_registered_model(model)?;
            return Ok("native".to_string());
        }
    }
    let runtime = crate::llm::provider_name(model);
    if runtime == "unknown" {
        return Err(format!(
            "model {model:?} has no registered provider runtime"
        ));
    }
    if policy.is_some_and(|policy| {
        !(policy.allowed_runtimes.is_empty()
            || policy
                .allowed_runtimes
                .iter()
                .any(|allowed| allowed == runtime)
            || runtime == "native"
                && policy
                    .allowed_runtimes
                    .iter()
                    .any(|allowed| allowed == "kiro"))
    }) {
        return Err(format!(
            "model runtime {runtime:?} is not allowed by policy"
        ));
    }
    crate::chisei::policy::validate_resolved_route(runtime, model)?;
    Ok(runtime.to_string())
}

fn push_scope(scopes: &mut Vec<String>, scope: &str) {
    if scope.is_empty() || scopes.iter().any(|existing| existing == scope) {
        return;
    }
    scopes.push(scope.to_string());
}

fn prune_cached_plans(plans: &mut HashMap<String, ExecutionPlan>) {
    prune_expired_plans(plans);
    prune_excess_plans(plans, None);
}

fn prune_expired_plans(plans: &mut HashMap<String, ExecutionPlan>) {
    let cutoff = chrono::Utc::now().timestamp_millis() - MAX_CACHED_EXECUTION_PLAN_AGE_MS;
    plans.retain(|_, plan| plan.created_at >= cutoff);
}

fn prune_excess_plans(plans: &mut HashMap<String, ExecutionPlan>, protected_plan_id: Option<&str>) {
    while plans.len() > MAX_CACHED_EXECUTION_PLANS {
        let Some(oldest_id) = plans
            .iter()
            .filter(|(plan_id, _)| protected_plan_id != Some(plan_id.as_str()))
            .min_by(|left, right| {
                left.1
                    .created_at
                    .cmp(&right.1.created_at)
                    .then_with(|| left.0.cmp(right.0))
            })
            .map(|(plan_id, _)| plan_id.clone())
        else {
            break;
        };
        plans.remove(&oldest_id);
    }
}

fn load_namespace_policies(db: &SekaiDb, resolver: &PolicyResolver) {
    for kind in ["policy", "namespace_policy"] {
        let Ok(objects) = db.list_all_objects(&ListFilter {
            kind: Some(kind.into()),
            ..Default::default()
        }) else {
            continue;
        };
        for obj in objects {
            let namespace = policy_namespace(&obj);
            if namespace.is_empty() {
                continue;
            }
            resolver.set_namespace_policy(
                &namespace,
                normalize_persisted_legacy_policy(policy_from_properties(&obj.properties)),
            );
        }
    }
}

fn policy_namespace(obj: &crate::domain::Object) -> String {
    if !obj.namespace.trim().is_empty() {
        return obj.namespace.trim().to_string();
    }
    for prefix in ["namespace_policy:", "policy:", "namespace:"] {
        if let Some(value) = obj.external_id.strip_prefix(prefix)
            && !value.trim().is_empty()
        {
            return value.trim().to_string();
        }
    }
    obj.name.trim().to_string()
}

fn policy_from_properties(properties: &std::collections::HashMap<String, String>) -> Policy {
    Policy {
        allowed_runtimes: csv_property(properties.get("allowed_runtimes")),
        allowed_models: csv_property(properties.get("allowed_models")),
        default_runtime: properties
            .get("default_runtime")
            .cloned()
            .unwrap_or_default(),
        default_model: properties.get("default_model").cloned().unwrap_or_default(),
        data_class: properties.get("data_class").cloned().unwrap_or_default(),
    }
}

fn policy_properties(policy: &Policy) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("allowed_runtimes".into(), policy.allowed_runtimes.join(",")),
        ("allowed_models".into(), policy.allowed_models.join(",")),
        ("default_runtime".into(), policy.default_runtime.clone()),
        ("default_model".into(), policy.default_model.clone()),
        ("data_class".into(), policy.data_class.clone()),
    ])
}

fn policy_from_request(r: &SetNamespacePolicyRequest) -> Policy {
    Policy {
        allowed_runtimes: r.allowed_runtimes.clone(),
        allowed_models: r.allowed_models.clone(),
        default_runtime: r.default_runtime.clone(),
        default_model: r.default_model.clone(),
        data_class: DataClass::parse(&r.data_class).as_str().into(),
    }
}

fn normalize_legacy_policy_provider_pairs(mut policy: Policy) -> Policy {
    let provider_for = |model: &str| {
        let explicitly_native = model.starts_with("native/")
            || model.starts_with("native-")
            || model.starts_with("fallback:");
        let explicitly_ollama = model.starts_with("ollama/");
        crate::provider_profile::resolve_provider_id(model)
            .ok()
            .filter(|provider| {
                (*provider == "native" && explicitly_native)
                    || (*provider == "ollama" && explicitly_ollama)
            })
            .map(str::to_string)
    };
    if policy.default_runtime == "openai"
        && let Some(provider) = provider_for(&policy.default_model)
        && matches!(provider.as_str(), "ollama" | "native")
    {
        policy.default_runtime = provider;
    }
    if policy
        .allowed_runtimes
        .iter()
        .any(|runtime| runtime == "openai")
    {
        let mut providers = policy
            .allowed_models
            .iter()
            .filter_map(|model| provider_for(model))
            .filter(|provider| matches!(provider.as_str(), "ollama" | "native"))
            .collect::<Vec<_>>();
        if matches!(policy.default_runtime.as_str(), "ollama" | "native") {
            providers.push(policy.default_runtime.clone());
        }
        for provider in providers {
            if !policy.allowed_runtimes.contains(&provider) {
                policy.allowed_runtimes.push(provider);
            }
        }
    }
    policy
}

fn normalize_persisted_legacy_policy(mut policy: Policy) -> Policy {
    let runtime_unspecified =
        policy.default_runtime.is_empty() && policy.allowed_runtimes.is_empty();
    let openai_only_allowed = !policy.allowed_runtimes.is_empty()
        && policy
            .allowed_runtimes
            .iter()
            .all(|runtime| runtime == "openai");
    let legacy_namespace = if policy.default_runtime == "openai"
        || policy.default_runtime.is_empty() && openai_only_allowed
    {
        Some("openai")
    } else if runtime_unspecified
        || matches!(policy.default_runtime.as_str(), "native" | "kiro")
        || policy
            .allowed_runtimes
            .iter()
            .any(|runtime| matches!(runtime.as_str(), "native" | "kiro"))
    {
        Some("native")
    } else {
        None
    };
    let canonicalize = |model: &mut String| {
        if let Some(namespace) = legacy_namespace
            && !model.is_empty()
            && !model.contains('/')
            && !model.eq_ignore_ascii_case("kiro")
            && model != "auto"
            && crate::provider_profile::resolve_provider_id(model).is_err()
        {
            *model = format!("{namespace}/{model}");
        }
    };
    canonicalize(&mut policy.default_model);
    for model in &mut policy.allowed_models {
        canonicalize(model);
    }
    if policy.default_runtime == "kiro" {
        policy.default_runtime = "native".into();
    }
    for runtime in &mut policy.allowed_runtimes {
        if runtime == "kiro" {
            *runtime = "native".into();
        }
    }
    policy.allowed_runtimes.sort();
    policy.allowed_runtimes.dedup();
    normalize_legacy_policy_provider_pairs(policy)
}

fn validate_policy_provider_pairs(policy: &Policy) -> Result<(), String> {
    for model in policy
        .allowed_models
        .iter()
        .chain((!policy.default_model.is_empty()).then_some(&policy.default_model))
    {
        validate_policy_model_alias(model)?;
    }
    for runtime in policy
        .allowed_runtimes
        .iter()
        .chain((!policy.default_runtime.is_empty()).then_some(&policy.default_runtime))
    {
        if !matches!(
            runtime.as_str(),
            "openai" | "anthropic" | "ollama" | "native" | "xai" | "meta"
        ) {
            return Err(format!("unsupported policy runtime {runtime:?}"));
        }
    }
    if !policy.default_runtime.is_empty()
        && !policy.allowed_runtimes.is_empty()
        && !policy.allowed_runtimes.contains(&policy.default_runtime)
    {
        return Err(format!(
            "default runtime {:?} is not in allowed runtimes",
            policy.default_runtime
        ));
    }
    if !policy.default_model.is_empty()
        && !policy.allowed_models.is_empty()
        && !policy
            .allowed_models
            .iter()
            .any(|allowed| models_have_same_identity(allowed, &policy.default_model))
    {
        return Err(format!(
            "default model {:?} is not in allowed models",
            policy.default_model
        ));
    }
    if !policy.default_model.is_empty() && !policy.default_runtime.is_empty() {
        crate::chisei::policy::validate_resolved_route(
            &policy.default_runtime,
            &policy.default_model,
        )?;
    } else if !policy.default_model.is_empty() {
        let provider =
            crate::provider_profile::resolve_registered_model(&policy.default_model)?.provider;
        if !policy.allowed_runtimes.is_empty() && !policy.allowed_runtimes.contains(&provider) {
            return Err(format!(
                "default model provider {provider:?} is not in allowed runtimes"
            ));
        }
    }
    for model in &policy.allowed_models {
        if policy.allowed_runtimes.is_empty() {
            if let Some((runtime, _)) = model.split_once('/') {
                crate::chisei::policy::validate_resolved_route(runtime, model)?;
            } else {
                crate::provider_profile::resolve_registered_model(model)?;
            }
            continue;
        }
        if !policy
            .allowed_runtimes
            .iter()
            .any(|runtime| crate::chisei::policy::validate_resolved_route(runtime, model).is_ok())
        {
            return Err(format!(
                "allowed model {model:?} cannot be routed by any allowed runtime"
            ));
        }
    }
    Ok(())
}

fn validate_policy_model_alias(model: &str) -> Result<(), String> {
    let provider = crate::provider_profile::resolve_provider_id(model)?;
    if provider == "native"
        && !model.starts_with("native/")
        && !model.starts_with("native-")
        && !model.starts_with("fallback:")
    {
        return Err(format!(
            "native policy model {model:?} must use an advertised native alias"
        ));
    }
    Ok(())
}

fn models_have_same_identity(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let registry = crate::provider_profile::ProviderRegistry::built_in();
    match (registry.resolve_model(left), registry.resolve_model(right)) {
        (Ok(left), Ok(right)) => left.canonical_model == right.canonical_model,
        _ => false,
    }
}

fn validate_explicit_requested_model(model: &str) -> Result<(), String> {
    if model.is_empty() || model == "auto" {
        return Ok(());
    }
    let Some((namespace, _)) = model.split_once('/') else {
        return crate::provider_profile::resolve_registered_model(model).map(|_| ());
    };
    match crate::provider_profile::resolve_registered_model(model) {
        Ok(_) => Ok(()),
        Err(error)
            if crate::provider_profile::ProviderRegistry::built_in()
                .profile(namespace)
                .is_some() =>
        {
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn csv_property(value: Option<&String>) -> Vec<String> {
    value
        .map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn build_egress_decisions(
    records: &[crate::chisei::egress::ContextEgressRecord],
    provider: &str,
    external: bool,
) -> Vec<EgressDecision> {
    if records.is_empty() {
        return vec![EgressDecision {
            provider: provider.into(),
            external,
            included: vec![],
            redacted: vec![],
            reasons: vec!["no sekai context selected".into()],
        }];
    }
    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let object_ref = if record
                .included_fields
                .iter()
                .any(|field| field == "identity")
            {
                record.object_ref.clone()
            } else {
                format!("object#{}", index + 1)
            };
            EgressDecision {
                provider: provider.into(),
                external,
                included: record
                    .included_fields
                    .iter()
                    .map(|field| format!("{object_ref}.{field}"))
                    .collect(),
                redacted: record
                    .redacted_fields
                    .iter()
                    .map(|field| format!("{object_ref}.{field}"))
                    .collect(),
                reasons: record.reasons.clone(),
            }
        })
        .collect()
}

fn payload_for_leak_check(system: &str, messages: &[ChatMessage], tools: &[ToolDef]) -> String {
    let mut payload = String::new();
    payload.push_str(system);
    for message in messages {
        payload.push('\n');
        payload.push_str(&message.role);
        payload.push_str(": ");
        payload.push_str(&message.content);
    }
    for tool in tools {
        payload.push('\n');
        payload.push_str(&tool.name);
        payload.push_str(": ");
        payload.push_str(&tool.description);
        payload.push('\n');
        payload.push_str(&tool.input_schema_json);
    }
    payload
}

fn leak_findings_to_decisions(
    provider: &str,
    external: bool,
    findings: &[LeakFinding],
) -> Vec<EgressDecision> {
    findings
        .iter()
        .map(|finding| EgressDecision {
            provider: provider.into(),
            external,
            included: vec![],
            redacted: vec![],
            reasons: vec![format!(
                "leak_checker {} {} match(es)",
                finding.rule_label, finding.match_count
            )],
        })
        .collect()
}

fn build_prepared_messages(input: &ExecutionInput, enriched_spec: &str) -> Vec<ChatMessage> {
    let mut messages = input.messages.clone();
    if messages.is_empty() {
        return vec![ChatMessage {
            role: "user".into(),
            content: enriched_spec.into(),
            tool_call_id: String::new(),
            tool_calls: vec![],
        }];
    }
    if !enriched_spec.is_empty() && enriched_spec != input.spec {
        messages.push(ChatMessage {
            role: "user".into(),
            content: format!("[Task spec]\n{enriched_spec}"),
            tool_call_id: String::new(),
            tool_calls: vec![],
        });
    }
    messages
}

fn eval_iteration_pb(iteration: crate::chisei::eval::Iteration) -> EvalIteration {
    EvalIteration {
        id: iteration.id,
        run_id: iteration.run_id,
        suite_id: iteration.suite_id,
        changed_file: iteration.changed_file,
        diff_hash: iteration.diff_hash,
        parent_iteration_id: iteration.parent_iteration_id,
        baseline_run_id: iteration.baseline_run_id,
        candidate_run_id: iteration.candidate_run_id,
        delta: iteration.delta,
        regressed: iteration.regressed,
        created: iteration.created,
    }
}

fn portfolio_point_pb(point: crate::chisei::portfolio::FrontierPoint) -> PortfolioPoint {
    PortfolioPoint {
        model: point.model,
        quality_score: point.quality_score,
        cost_usd_micros: point.cost_usd_micros,
        sample_count: point.sample_count,
        updated_at: point.updated_at,
    }
}

fn portfolio_objective_pb(objective: &Objective) -> PortfolioObjective {
    PortfolioObjective {
        namespace: objective.namespace.clone(),
        mode: objective.mode.as_str().into(),
        budget_usd_micros: objective.budget_usd_micros,
        quality_bar: objective.quality_bar,
        min_samples: objective.min_samples,
        updated_at: objective.updated_at,
    }
}

#[tonic::async_trait]
impl ChiseiService for ChiseiServiceImpl {
    type ExecutePlanStreamStream =
        Pin<Box<dyn futures_util::Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send>>;

    async fn check_budget(
        &self,
        req: Request<CheckBudgetRequest>,
    ) -> Result<Response<CheckBudgetResponse>, Status> {
        let r = req.into_inner();
        let metric = budget_metric(&r.metric)?;
        let budget_subject = budget_subject(
            &r.subject,
            &r.project,
            &r.agent,
            &r.key_id,
            &r.work_unit,
            &r.user_id,
        )?;
        let within_cap = self
            .budget
            .check_with_metric(&budget_subject, r.estimated_tokens, metric)
            .is_ok();
        let pressure = self
            .budget
            .projected_pressure_percent(&budget_subject, r.estimated_tokens, metric)
            .unwrap_or(0);
        let mut route_bias = self
            .budget
            .route_bias(&budget_subject, r.estimated_tokens, metric, &r.task_class)
            .as_str()
            .to_string();
        // Continuation authority is derived entirely from durable server-side
        // coordination state. `mid_task` is compatibility metadata only and
        // must never authorize a hard-cap exception.
        let continuation_started = !r.work_unit.trim().is_empty()
            && active_continuation_allocation(
                &self.db,
                &r.work_unit,
                &[r.agent.as_str(), r.key_id.as_str(), r.user_id.as_str()],
                chrono::Utc::now().timestamp_millis(),
            )
            && self
                .budget
                .get_usage_with_metric(&budget_subject, metric)
                .tokens_used
                > 0;
        let (allowed, degradation_level, warning) = if within_cap {
            if continuation_started || pressure >= 90 {
                (
                    true,
                    if route_bias == "cheap" {
                        "cheap_cloud"
                    } else {
                        "warn"
                    },
                    true,
                )
            } else if route_bias == "cheap" {
                (true, "cheap_cloud", false)
            } else {
                (true, "capable", false)
            }
        } else if metric == crate::db::chisei_budget::METRIC_TOKENS && continuation_started {
            (true, "warn", true)
        } else if metric == crate::db::chisei_budget::METRIC_TOKENS
            && r.local_free_available
            && crate::chisei::model_routing::is_cheap_eligible_task_class(&r.task_class)
        {
            route_bias = "local_free".to_string();
            // This is a provisional route recommendation, not permission to
            // exceed the cap. The gateway must resolve it to a verified local
            // model before execution; direct CheckBudget consumers still see
            // the hard enforcement decision in `allowed`.
            (false, "local_free", true)
        } else {
            (false, "hard_cap", true)
        };
        let u = self
            .budget
            .most_constrained_usage_with_metric(&budget_subject, metric);
        Ok(Response::new(CheckBudgetResponse {
            allowed,
            usage: Some(BudgetUsage {
                user_id: u.user_id,
                tokens_used: u.tokens_used,
                max_tokens: u.max_tokens,
                period_type: u.period_type.as_str().into(),
                period_start: u.period_start,
            }),
            route_bias,
            degradation_level: degradation_level.to_string(),
            warning,
        }))
    }

    async fn record_usage(
        &self,
        req: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        let r = req.into_inner();
        let metric = budget_metric(&r.metric)?;
        let budget_subject = budget_subject(
            &r.subject,
            &r.project,
            &r.agent,
            &r.key_id,
            &r.work_unit,
            &r.user_id,
        )?;
        self.budget
            .record_idempotent_with_metric(
                &budget_subject,
                r.tokens_used,
                metric,
                &r.idempotency_key,
            )
            .map_err(Status::internal)?;
        let u = self.budget.get_usage_with_metric(&budget_subject, metric);
        Ok(Response::new(RecordUsageResponse {
            usage: Some(BudgetUsage {
                user_id: u.user_id,
                tokens_used: u.tokens_used,
                max_tokens: u.max_tokens,
                period_type: u.period_type.as_str().into(),
                period_start: u.period_start,
            }),
        }))
    }

    async fn set_budget_limit(
        &self,
        req: Request<SetBudgetLimitRequest>,
    ) -> Result<Response<SetBudgetLimitResponse>, Status> {
        let r = req.into_inner();
        let metric = budget_metric(&r.metric)?;
        let period = crate::chisei::budget::PeriodType::parse_strict(&r.period_type)
            .map_err(Status::invalid_argument)?;
        let budget_subject = budget_subject(
            &r.subject,
            &r.project,
            &r.agent,
            &r.key_id,
            &r.work_unit,
            &r.user_id,
        )?;
        self.budget
            .set_limit_with_metric(&budget_subject, metric, r.max_tokens, period)
            .map_err(Status::internal)?;
        Ok(Response::new(SetBudgetLimitResponse {}))
    }

    async fn record_portfolio_observation(
        &self,
        req: Request<RecordPortfolioObservationRequest>,
    ) -> Result<Response<RecordPortfolioObservationResponse>, Status> {
        let r = req.into_inner();
        let updated_at = if r.updated_at > 0 {
            r.updated_at
        } else {
            chrono::Utc::now().timestamp_millis()
        };
        self.portfolio
            .record(&Observation {
                namespace: r.namespace.clone(),
                task_class: r.task_class.clone(),
                model: r.model,
                quality_score: r.quality_score,
                cost_usd_micros: r.cost_usd_micros,
                sample_count: r.sample_count,
                updated_at,
            })
            .map_err(Status::invalid_argument)?;
        let frontier = self
            .portfolio
            .frontier(&r.namespace, &r.task_class)
            .map_err(Status::internal)?
            .into_iter()
            .map(portfolio_point_pb)
            .collect();
        Ok(Response::new(RecordPortfolioObservationResponse {
            frontier,
        }))
    }

    async fn get_portfolio_frontier(
        &self,
        req: Request<GetPortfolioFrontierRequest>,
    ) -> Result<Response<GetPortfolioFrontierResponse>, Status> {
        let r = req.into_inner();
        if r.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("portfolio namespace required"));
        }
        let frontier = self
            .portfolio
            .frontier(&r.namespace, &r.task_class)
            .map_err(Status::internal)?
            .into_iter()
            .map(portfolio_point_pb)
            .collect();
        Ok(Response::new(GetPortfolioFrontierResponse { frontier }))
    }

    async fn set_portfolio_objective(
        &self,
        req: Request<SetPortfolioObjectiveRequest>,
    ) -> Result<Response<SetPortfolioObjectiveResponse>, Status> {
        let r = req
            .into_inner()
            .objective
            .ok_or_else(|| Status::invalid_argument("portfolio objective required"))?;
        let objective = Objective {
            namespace: r.namespace.trim().to_string(),
            mode: ObjectiveMode::parse(&r.mode).map_err(Status::invalid_argument)?,
            budget_usd_micros: r.budget_usd_micros,
            quality_bar: r.quality_bar,
            min_samples: r.min_samples,
            updated_at: if r.updated_at > 0 {
                r.updated_at
            } else {
                chrono::Utc::now().timestamp_millis()
            },
        };
        self.portfolio
            .set_objective(&objective)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(SetPortfolioObjectiveResponse {
            objective: Some(portfolio_objective_pb(&objective)),
        }))
    }

    async fn allocate_portfolio(
        &self,
        req: Request<AllocatePortfolioRequest>,
    ) -> Result<Response<AllocatePortfolioResponse>, Status> {
        let r = req.into_inner();
        let objective = self
            .portfolio
            .objective(&r.namespace)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::failed_precondition("portfolio objective not configured"))?;
        let demands: Vec<_> = r
            .demands
            .into_iter()
            .map(|demand| PortfolioDemand {
                task_class: demand.task_class,
                expected_calls: demand.expected_calls,
                quality_bar: demand.has_quality_bar.then_some(demand.quality_bar),
            })
            .collect();
        let plan = self
            .portfolio
            .allocate(&objective, &demands)
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(AllocatePortfolioResponse {
            objective: Some(portfolio_objective_pb(&objective)),
            allocations: plan
                .allocations
                .into_iter()
                .map(|allocation| PortfolioAllocation {
                    task_class: allocation.task_class,
                    model: allocation.model,
                    quality_score: allocation.quality_score,
                    cost_per_call_usd_micros: allocation.cost_per_call_usd_micros,
                    expected_calls: allocation.expected_calls,
                })
                .collect(),
            total_cost_usd_micros: plan.total_cost_usd_micros,
            total_value: plan.total_value,
        }))
    }

    async fn set_namespace_policy(
        &self,
        req: Request<SetNamespacePolicyRequest>,
    ) -> Result<Response<SetNamespacePolicyResponse>, Status> {
        let registry = self.refresh_provider_registry_for_resolution().await?;
        let validated_registry_version = registry.state_version;
        crate::provider_profile::with_provider_registry_snapshot(registry, async {
            let r = req.into_inner();
            if r.namespace.trim().is_empty() {
                return Err(Status::invalid_argument("namespace required"));
            }
            let policy = normalize_legacy_policy_provider_pairs(policy_from_request(&r));
            validate_policy_provider_pairs(&policy).map_err(Status::invalid_argument)?;
            let policy_data_class = policy.data_class.clone();
            let policy_version = policy.version();
            let current_registry = self.refresh_provider_registry_for_resolution().await?;
            if current_registry.state_version != validated_registry_version {
                return Err(Status::aborted(
                    "provider registry changed while validating namespace policy",
                ));
            }
            persist_namespace_policy(&self.db, &r.namespace, &policy).map_err(Status::internal)?;
            let default_runtime = policy.default_runtime.clone();
            let default_model = policy.default_model.clone();
            self.policy.set_namespace_policy(&r.namespace, policy);
            let (runtime, model) = self
                .policy
                .resolve(&r.namespace, &default_runtime, &default_model)
                .map_err(Status::invalid_argument)?;
            Ok(Response::new(SetNamespacePolicyResponse {
                resolution: Some(PolicyResolution {
                    runtime,
                    model,
                    data_class: policy_data_class,
                    eval_regressed: false,
                    eval_regression_reason: String::new(),
                    route_bias: String::new(),
                    policy_scope: r.namespace,
                    policy_version,
                    fallback_models: Vec::new(),
                }),
            }))
        })
        .await
    }

    async fn resolve_policy(
        &self,
        req: Request<ResolvePolicyRequest>,
    ) -> Result<Response<ResolvePolicyResponse>, Status> {
        let registry = self.refresh_provider_registry_for_resolution().await?;
        crate::provider_profile::with_provider_registry_snapshot(registry, async {
        let r = req.into_inner();
        let scopes = policy_scopes(&r);
        let (policy_scope, effective_policy) = self
            .policy
            .effective_policy_for_scopes(&scopes)
            .map(|(scope, policy)| (scope, Some(policy)))
            .unwrap_or_else(|| {
                let fallback = if r.namespace.trim().is_empty() {
                    r.project.trim().to_string()
                } else {
                    r.namespace.trim().to_string()
                };
                (fallback, None)
            });
        let mut regression_scopes = vec![policy_scope.as_str()];
        if !r.namespace.trim().is_empty() && r.namespace != policy_scope {
            regression_scopes.push(r.namespace.as_str());
        }
        let mut regression_reasons = Vec::new();
        for scope in regression_scopes {
            let namespace_signal = self
                .eval
                .namespace_regression_signal(scope)
                .filter(|signal| signal.regressed);
            let task_class_signal = crate::chisei::scoring::task_class_regression_signal(
                &self.db,
                scope,
                &r.task_class,
            );
            let namespace_created = namespace_signal
                .as_ref()
                .and_then(|signal| signal.iteration.as_ref())
                .map(|iteration| iteration.created)
                .unwrap_or(i64::MIN);
            if let Some(signal) = task_class_signal
                && signal.observed_at >= namespace_created
            {
                if signal.regressed {
                    regression_reasons.push(signal.reason);
                }
                continue;
            }
            if let Some(signal) = namespace_signal {
                regression_reasons.push(signal.reason);
            }
        }
        let eval_regressed = !regression_reasons.is_empty();
        let eval_regression_reason = regression_reasons.join(" | ");
        validate_explicit_requested_model(&r.preferred_model).map_err(Status::invalid_argument)?;
        let requested_preferred_model = &r.preferred_model;
        let preferred_model = eval_regressed
            .then_some(())
            .as_ref()
            .and(effective_policy.as_ref())
            .map(|policy| policy.default_model.as_str())
            .filter(|model| !model.is_empty())
            .unwrap_or(requested_preferred_model);
        validate_explicit_requested_model(preferred_model).map_err(Status::invalid_argument)?;
        let (mut runtime, model) = if let Some(policy) = effective_policy.as_ref() {
            self.policy
                .apply_policy(policy, &r.preferred_runtime, preferred_model)
                .map_err(Status::invalid_argument)?
        } else {
            self.policy
                .resolve(&policy_scope, &r.preferred_runtime, preferred_model)
                .map_err(Status::invalid_argument)?
        };

        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&r.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        // Resolve the capable-tier model first; this is the baseline the request
        // would get with no cost tiering.
        let capable_model = if r.preferred_model == "auto" && effective_policy.is_none() {
            let resolved = crate::provider_profile::resolve_registered_model(&model)
                .map_err(Status::failed_precondition)?;
            if resolved.provider != runtime {
                return Err(Status::failed_precondition(
                    "automatic model default does not match the requested runtime",
                ));
            }
            if safe_only
                && !crate::chisei::privacy::provider_safe_to_send(
                    &resolved.provider,
                    &safe_providers,
                )
            {
                return Err(Status::permission_denied(
                    crate::chisei::privacy::gate_reason(data_class, task_class, &resolved.provider),
                ));
            }
            resolved.canonical_model
        } else {
            self.resolve_live_model(
                &model,
                effective_policy.as_ref(),
                None,
                safe_only,
                &safe_providers,
            )
            .await
            .map_err(|err| {
                if safe_only {
                    Status::permission_denied(format!(
                        "{}: {err}",
                        crate::chisei::privacy::gate_reason(data_class, task_class, "unsafe")
                    ))
                } else {
                    Status::failed_precondition(err)
                }
            })?
        };

        // Eval-gated cost tiering: only explicit bulk task classes route to the
        // cheaper tier, and only while no eval regression is active for the
        // scope. Everything else (primary/unknown) stays on the capable tier.
        // A bare "cheap" is rejected by apply_policy, so the cheaper tier is
        // selected via the provider-scoped "{runtime}/cheap" alias, which only
        // resolves for a recognized provider family. Cheap resolution is
        // best-effort: any failure falls back to the capable model.
        //
        // A promoted "capable" revert (chisei::controller) overrides the static heuristic even
        // when it would otherwise say cheap: it's evidence-backed (gated against held eval
        // history, not just the live per-request signal) and stays active until an operator or a
        // later promotion clears it, covering gaps the live regression check alone can't (e.g. a
        // regressed iteration since pruned). Promotions are written under the candidate's raw
        // namespace (from sampled observations), which may differ from `policy_scope` (the first
        // *matching policy* scope - subject/agent/gateway-key rank ahead of namespace); check both
        // so a subject/agent-scoped policy doesn't silently hide the override. Normalize the class
        // the same way promotion/scoring do (trim + lowercase) - the override is keyed by the
        // normalized class, but `cheap_route_bias` below normalizes internally, so an unnormalized
        // lookup here would miss the override for non-canonical casing/whitespace.
        let normalized_task_class = crate::chisei::scoring::normalize_task_class(&r.task_class);
        let capable_override_active = self
            .active_promotions
            .capable_override_active(&policy_scope, &normalized_task_class)
            || self
                .active_promotions
                .capable_override_active(&r.namespace, &normalized_task_class);
        let wants_local_free = r.budget_route_bias == "local_free";
        if wants_local_free && (eval_regressed || capable_override_active) {
            let safety_reason = if eval_regressed {
                eval_regression_reason.as_str()
            } else {
                "an active capable-tier override"
            };
            return Err(Status::resource_exhausted(format!(
                "hard budget cap reached and the local-free tier is blocked by the quality safety net: {safety_reason}"
            )));
        }
        let local_free_model = if wants_local_free {
            self.resolve_live_model(
                "ollama/cheap",
                effective_policy.as_ref(),
                Some("cheap"),
                safe_only,
                &safe_providers,
            )
            .await
            .ok()
            .and_then(|model| {
                local_free_runtime_for_model(effective_policy.as_ref(), &model)
                    .map(|local_runtime| (local_runtime, model))
            })
        } else {
            None
        };
        if wants_local_free && local_free_model.is_none() {
            return Err(Status::resource_exhausted(
                "hard budget cap reached and no policy-allowed local-free model is available",
            ));
        }
        let wants_cheap = !capable_override_active
            && cheap_route_bias(&r.task_class, eval_regressed) == Some("cheap");
        let cheap_model = if wants_cheap && is_known_provider_runtime(&runtime) {
            self.resolve_live_model(
                &format!("{}/cheap", runtime.trim()),
                effective_policy.as_ref(),
                Some("cheap"),
                safe_only,
                &safe_providers,
            )
            .await
            .ok()
        } else {
            None
        };
        // Record the cheap bias only when it produced an actual demotion to a
        // strictly cheaper cost tier, so the audited route_bias reflects
        // realized cost reductions rather than intent or equal-cost swaps.
        let (mut model, mut route_bias) = match local_free_model {
            Some((_local_runtime, local_model)) => (local_model, Some("local_free")),
            None => match cheap_model {
                Some(cheap)
                    if crate::chisei::model_routing::named_model_cost_rank(&cheap)
                        < crate::chisei::model_routing::named_model_cost_rank(&capable_model) =>
                {
                    (cheap, Some("cheap"))
                }
                _ => (capable_model.clone(), None),
            },
        };

        // Portfolio routing supersedes the static cheap/capable heuristic when
        // a scope has an objective and sufficiently sampled frontier data.
        // A regressed eval or promoted capable override reverts immediately;
        // ordinary changes require repeated confirmation plus a cooldown.
        let objective = self
            .portfolio
            .objective(&policy_scope)
            .ok()
            .flatten()
            .map(|objective| (policy_scope.clone(), objective))
            .or_else(|| {
                if r.namespace.trim().is_empty() || r.namespace == policy_scope {
                    None
                } else {
                    self.portfolio
                        .objective(&r.namespace)
                        .ok()
                        .flatten()
                        .map(|objective| (r.namespace.clone(), objective))
                }
            });
        if !wants_local_free && let Some((portfolio_scope, objective)) = objective {
            let now = chrono::Utc::now().timestamp_millis();
            if eval_regressed || capable_override_active {
                if let Ok(selection) = self.portfolio.damped_route(
                    &portfolio_scope,
                    &normalized_task_class,
                    &capable_model,
                    now,
                    true,
                ) {
                    self.record_portfolio_shift(
                        &portfolio_scope,
                        &normalized_task_class,
                        &selection,
                        &objective,
                        "reverted",
                    );
                    model = capable_model.clone();
                    route_bias = None;
                }
            } else {
                let demand = PortfolioDemand {
                    task_class: normalized_task_class.clone(),
                    expected_calls: r.expected_calls.max(1),
                    quality_bar: None,
                };
                if let Ok(plan) = self.portfolio.allocate(&objective, &[demand])
                    && let Some(allocation) = plan.allocations.first()
                    && portfolio_model_allowed(effective_policy.as_ref(), &allocation.model)
                    && portfolio_runtime_for_model(
                        effective_policy.as_ref(),
                        &runtime,
                        &allocation.model,
                    )
                    .is_some()
                    && let Ok(proposed) = self
                        .resolve_live_model(
                            &allocation.model,
                            effective_policy.as_ref(),
                            None,
                            safe_only,
                            &safe_providers,
                        )
                        .await
                    && proposed == allocation.model
                    && let Ok(selection) = self.portfolio.damped_route(
                        &portfolio_scope,
                        &normalized_task_class,
                        &proposed,
                        now,
                        false,
                    )
                    && portfolio_model_allowed(effective_policy.as_ref(), &selection.model)
                    && portfolio_runtime_for_model(
                        effective_policy.as_ref(),
                        &runtime,
                        &selection.model,
                    )
                    .is_some()
                    && let Ok(selected) = self
                        .resolve_live_model(
                            &selection.model,
                            effective_policy.as_ref(),
                            None,
                            safe_only,
                            &safe_providers,
                        )
                        .await
                    && selected == selection.model
                {
                    self.record_portfolio_shift(
                        &portfolio_scope,
                        &normalized_task_class,
                        &selection,
                        &objective,
                        "shifted",
                    );
                    model = selected;
                    route_bias = Some("portfolio");
                }
            }
        }

        runtime = final_runtime_for_model(effective_policy.as_ref(), &runtime, &model)
            .map_err(Status::failed_precondition)?;
        let provider = runtime.as_str();
        if safe_only && !crate::chisei::privacy::provider_safe_to_send(provider, &safe_providers) {
            return Err(Status::permission_denied(
                crate::chisei::privacy::gate_reason(data_class, task_class, provider),
            ));
        }
        let fallback_models = effective_policy
            .as_ref()
            .into_iter()
            .flat_map(|policy| policy.allowed_models.iter())
            .filter_map(|candidate| {
                crate::provider_profile::resolve_registered_model(candidate)
                    .ok()
                    .map(|resolved| resolved.canonical_model)
            })
            .filter(|candidate| candidate != &model)
            .filter(|candidate| {
                final_runtime_for_model(effective_policy.as_ref(), &runtime, candidate).is_ok()
            })
            .filter(|candidate| {
                let provider = crate::llm::provider_name(candidate);
                !safe_only
                    || crate::chisei::privacy::provider_safe_to_send(provider, &safe_providers)
            })
            .take(8)
            .collect();

        Ok(Response::new(ResolvePolicyResponse {
            resolution: Some(PolicyResolution {
                runtime,
                model,
                eval_regressed,
                eval_regression_reason,
                data_class: data_class.as_str().into(),
                route_bias: route_bias.unwrap_or_default().to_string(),
                policy_scope: effective_policy
                    .as_ref()
                    .map(|_| policy_scope.clone())
                    .unwrap_or_default(),
                policy_version: effective_policy
                    .as_ref()
                    .map(|policy| policy.version())
                    .unwrap_or_default(),
                fallback_models,
            }),
        }))
        })
        .await
    }

    async fn check_egress(
        &self,
        req: Request<CheckEgressRequest>,
    ) -> Result<Response<CheckEgressResponse>, Status> {
        let r = req.into_inner();
        let effective_policy = self.policy.effective_policy(&r.namespace);
        let policy_version = effective_policy
            .as_ref()
            .map(|policy| policy.version())
            .unwrap_or_default();
        let data_class = self.data_class(effective_policy.as_ref());
        let provider_is_external = crate::chisei::egress::is_external_provider(&r.provider);
        let task_class = TaskClass::parse(&r.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let mut findings = Vec::new();
        if !crate::chisei::privacy::external_allowed(data_class, task_class)
            && !crate::chisei::privacy::provider_safe_to_send(&r.provider, &safe_providers)
        {
            findings.push(EgressDecision {
                provider: r.provider.clone(),
                external: provider_is_external,
                included: vec![],
                redacted: vec![],
                reasons: vec![crate::chisei::privacy::gate_reason(
                    data_class,
                    task_class,
                    &r.provider,
                )],
            });
            return Ok(Response::new(CheckEgressResponse {
                allowed: false,
                findings,
                policy_version,
            }));
        }
        let findings =
            self.leak_findings_for_payload(&r.namespace, &r.provider, data_class, &r.payload);
        let allowed = !findings
            .iter()
            .any(|finding| finding.action == LeakAction::Block);
        Ok(Response::new(CheckEgressResponse {
            allowed,
            findings: leak_findings_to_decisions(&r.provider, provider_is_external, &findings),
            policy_version,
        }))
    }

    async fn run_pipeline(
        &self,
        req: Request<RunPipelineRequest>,
    ) -> Result<Response<RunPipelineResponse>, Status> {
        let actor = authenticated_actor(&req);
        let r = req
            .into_inner()
            .request
            .ok_or(Status::invalid_argument("request required"))?;
        let mut pr = pipe::PipelineRequest {
            request_id: r.request_id,
            namespace: r.namespace,
            spec: r.spec,
            model: r.model,
            runtime: r.runtime,
            task_type: r.task_type,
            priority: r.priority,
            risk_score: 0.0,
            budget_pressure: self.budget.namespace_pressure(""),
            review_model: String::new(),
            egress_records: vec![],
            external_egress: true,
            template_only: TaskClass::parse(&r.task_class) == TaskClass::TemplateOnly,
            expanded_context_items: 0,
            evidence_references: vec![],
            memory_references: vec![],
            memory_holdouts: vec![],
            memory_actor: actor.clone(),
            memory_assignment_id: String::new(),
            memory_token_budget: 512,
            allowed_evidence_classes: std::collections::HashSet::new(),
        };
        let context_expansion_gate = self.pipeline_context_expansion_gate(&pr.namespace);
        let evidence_context_gates =
            self.applicable_evidence_context_gates(&pr, context_expansion_gate.allowed)?;
        let allowed_evidence_classes = evidence_context_gates
            .iter()
            .filter(|class_gate| class_gate.effective_allowed)
            .map(|class_gate| pipe::EvidenceContextClass {
                source_type: class_gate.source_type.clone(),
                evidence_type: class_gate.evidence_type.clone(),
            })
            .collect::<HashSet<_>>();
        let result = self.pipeline.run_with_context_admission(
            &mut pr,
            &self.db,
            context_expansion_gate.allowed,
            allowed_evidence_classes,
        );
        self.record_context_expansion_gate(
            &pr.request_id,
            &pr.namespace,
            &context_expansion_gate,
            result.expanded_context_items,
        )?;
        self.record_evidence_context_gates(
            &pr.request_id,
            &pr.namespace,
            &evidence_context_gates,
            &result.evidence_references,
        )?;
        let steps = result
            .steps
            .iter()
            .map(|s| StepDecision {
                step: s.step.clone(),
                action: s.action.clone(),
                reasoning: s.reasoning.clone(),
                confidence: s.confidence,
                suggestion: s.suggestion.clone(),
                value: s.value.clone(),
            })
            .collect();
        Ok(Response::new(RunPipelineResponse {
            result: Some(PipelineRunResult {
                request_id: result.request_id,
                steps,
                timestamp: result.timestamp,
                prepared_spec: result.prepared_spec,
                evidence_references: result
                    .evidence_references
                    .iter()
                    .map(context_evidence_reference)
                    .collect(),
                memory_references: result
                    .memory_references
                    .iter()
                    .map(memory_context_reference)
                    .collect(),
            }),
        }))
    }

    async fn list_pipeline_runs(
        &self,
        _r: Request<ListPipelineRunsRequest>,
    ) -> Result<Response<ListPipelineRunsResponse>, Status> {
        Ok(Response::new(ListPipelineRunsResponse { runs: vec![] }))
    }

    async fn record_sample_observation(
        &self,
        req: Request<RecordSampleObservationRequest>,
    ) -> Result<Response<RecordSampleObservationResponse>, Status> {
        let observation = req
            .into_inner()
            .observation
            .ok_or(Status::invalid_argument("observation required"))?;
        if observation.request_id.trim().is_empty() {
            return Err(Status::invalid_argument("request_id required"));
        }
        if observation.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        if observation.spec.trim().is_empty() {
            return Err(Status::invalid_argument("spec required"));
        }
        if observation.output_content.trim().is_empty() {
            return Err(Status::invalid_argument("output_content required"));
        }
        if !self.config.scoring_enabled {
            return Ok(Response::new(RecordSampleObservationResponse {
                recorded: false,
            }));
        }
        self.db
            .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                request_id: observation.request_id,
                namespace: observation.namespace,
                spec: observation.spec,
                resolved_model: observation.resolved_model,
                output_content: observation.output_content,
                sample_reason: observation.sample_reason,
                input_tokens: observation.input_tokens,
                output_tokens: observation.output_tokens,
                stop_reason: observation.stop_reason,
                timestamp: observation.timestamp,
                scored: false,
                task_class: crate::chisei::scoring::normalize_task_class(&observation.task_class),
                cost_usd_micros: observation.cost_usd_micros,
            })
            .map_err(Status::internal)?;
        Ok(Response::new(RecordSampleObservationResponse {
            recorded: true,
        }))
    }

    async fn record_gateway_audit(
        &self,
        req: Request<RecordGatewayAuditRequest>,
    ) -> Result<Response<RecordGatewayAuditResponse>, Status> {
        let authenticated_principal = authenticated_actor(&req);
        let auth_source = auth_source(&req);
        let mut event = req
            .into_inner()
            .event
            .ok_or(Status::invalid_argument("event required"))?;
        if event.actor.trim().is_empty() {
            return Err(Status::invalid_argument("actor required"));
        }
        if event.action.trim().is_empty() {
            return Err(Status::invalid_argument("action required"));
        }
        if event.outcome.trim().is_empty() {
            return Err(Status::invalid_argument("outcome required"));
        }
        if event.id.trim().is_empty() {
            event.id = uuid::Uuid::new_v4().to_string();
        }
        // Clamp to server time: a future timestamp would pin the purgeable
        // prefix of the hash-chained ledger and silently stop retention.
        let now = chrono::Utc::now().timestamp_millis();
        if event.timestamp <= 0 || event.timestamp > now {
            event.timestamp = now;
        }
        // Reserved keys: only the server-side attestation binding may claim
        // one, otherwise a caller could dress up an arbitrary audit event as
        // policy-attested.
        event
            .evidence
            .remove(crate::sekai::attestation::EVIDENCE_ATTESTATION_ID);
        event
            .evidence
            .remove(crate::sekai::attestation::EVIDENCE_ATTESTATION_HASH);
        if event.target_id.trim().is_empty() {
            event.target_id = "llm_calls".to_string();
        }
        if event.action == GATEWAY_RECEIPT_ACTION {
            let configured_gateway = self
                .config
                .gateway_receipt_principals
                .iter()
                .any(|principal| principal == &authenticated_principal);
            let local_insecure_gateway = self.config.insecure
                && auth_source.as_deref() == Some("local")
                && authenticated_principal == "chisei-gateway";
            if !local_insecure_gateway
                && (auth_source.as_deref() != Some("token")
                    || (!configured_gateway
                        && !matches!(authenticated_principal.as_str(), "chisei-gateway" | "root")))
            {
                return Err(Status::permission_denied(
                    "operation receipt writes require an authorized gateway service principal",
                ));
            }
            let receipt_json = event
                .evidence
                .get("receipt_json")
                .ok_or(Status::invalid_argument("receipt_json required"))?;
            let receipt: OperationReceipt = serde_json::from_str(receipt_json)
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            if receipt.initiating_actor != event.actor {
                return Err(Status::invalid_argument(
                    "receipt initiating actor must match gateway audit actor",
                ));
            }
            if event.target_id != receipt.operation_id {
                return Err(Status::invalid_argument(
                    "gateway audit target must match receipt operation id",
                ));
            }
            let completeness = receipt.completeness();
            if !completeness.complete {
                return Err(Status::invalid_argument(format!(
                    "gateway receipt is incomplete: missing={:?} errors={:?}",
                    completeness.missing_surfaces, completeness.errors
                )));
            }
            let has_kioku_context = receipt.events.iter().any(|receipt_event| {
                receipt_event.kind == ReceiptEventKind::ContextGoverned
                    && receipt_event
                        .references
                        .iter()
                        .any(|reference| reference.kind == "kioku_memory" && !reference.omitted)
            }) || !self
                .db
                .list_kioku_outcome_assignments(&receipt.operation_id)
                .map_err(Status::internal)?
                .is_empty();
            let existing = self
                .db
                .get_operation_receipt(&receipt.operation_id)
                .map_err(Status::internal)?;
            if existing
                .as_ref()
                .is_some_and(|existing| existing != &receipt)
            {
                return Err(Status::already_exists(
                    "operation receipt already exists with different evidence",
                ));
            }
            if existing.is_none() && has_kioku_context {
                record_reported_memory_outcomes(
                    &self.db,
                    &receipt,
                    &authenticated_principal,
                    now,
                    false,
                    None,
                    true,
                )
                .map_err(|error| {
                    Status::invalid_argument(format!("Kioku outcome attribution invalid: {error}"))
                })?;
            }
            self.db
                .put_operation_receipt(&receipt)
                .map_err(Status::internal)?;
            if has_kioku_context
                && let Err(error) = record_reported_memory_outcomes(
                    &self.db,
                    &receipt,
                    &authenticated_principal,
                    now,
                    false,
                    None,
                    false,
                )
            {
                let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now,
                    actor: "chisei.kioku".into(),
                    action: "kioku.outcome_attribution".into(),
                    reason: error,
                    evidence: std::collections::HashMap::from([
                        ("operation_id".into(), receipt.operation_id.clone()),
                        ("gateway_audit_event_id".into(), event.id.clone()),
                    ]),
                    target_id: receipt.operation_id.clone(),
                    outcome: "failed".into(),
                });
            }
        }
        self.db
            .record_decision(&crate::sekai::audit::Decision {
                id: event.id.clone(),
                timestamp: event.timestamp,
                actor: event.actor.clone(),
                action: event.action.clone(),
                reason: event.reason.clone(),
                evidence: event.evidence.clone(),
                target_id: event.target_id.clone(),
                outcome: event.outcome.clone(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(RecordGatewayAuditResponse {
            event: Some(event),
        }))
    }

    async fn plan_execution(
        &self,
        req: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status> {
        let registry = self.refresh_provider_registry_for_resolution().await?;
        crate::provider_profile::with_provider_registry_snapshot(registry, async {
            let actor = authenticated_actor(&req);
            let input = req
                .into_inner()
                .input
                .ok_or(Status::invalid_argument("input required"))?;
            let plan = self.plan_from_input(input, &actor).await?;
            if let Some(plan_input) = &plan.input {
                let namespace_hint = plan_input.namespace.trim().to_string();
                self.record_evolve_task(
                    &plan_input.request_id,
                    &namespace_hint,
                    &plan.enriched_spec,
                    self.tracked_original_spec(
                        &plan_input.request_id,
                        &plan_input.spec,
                        &plan.enriched_spec,
                    )
                    .as_deref(),
                    if plan.executable { "planned" } else { "failed" },
                    plan_input.estimated_tokens,
                )
                .map_err(Status::internal)?;
            }
            self.record_planned_operation(&plan, &actor)
                .map_err(Status::internal)?;
            self.cache_plan(plan.clone());
            Ok(Response::new(PlanExecutionResponse { plan: Some(plan) }))
        })
        .await
    }

    async fn execute_plan(
        &self,
        req: Request<ExecutePlanRequest>,
    ) -> Result<Response<ExecutePlanResponse>, Status> {
        let actor = authenticated_actor(&req);
        let requested_plan = req
            .into_inner()
            .plan
            .ok_or(Status::invalid_argument("plan required"))?;
        let plan = {
            let mut plans = self
                .planned_executions
                .lock()
                .expect("planned executions poisoned");
            prune_cached_plans(&mut plans);
            let plan = plans
                .get(&requested_plan.plan_id)
                .ok_or(Status::not_found("execution plan not found"))?;
            if plan.planning_actor != actor {
                return Err(Status::permission_denied(
                    "execution plan belongs to a different planning principal",
                ));
            }
            plans.remove(&requested_plan.plan_id).unwrap()
        };
        if !plan.executable {
            return Err(Status::failed_precondition(
                "execution plan is not executable",
            ));
        }
        let input = plan
            .input
            .clone()
            .ok_or(Status::invalid_argument("plan input required"))?;
        let namespace_hint = input.namespace.trim().to_string();
        let provider = crate::llm::provider_name(&plan.resolved_model).to_string();
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&plan.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        if safe_only && !crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers) {
            self.record_privacy_audit(
                "blocked",
                &input.request_id,
                &provider,
                data_class,
                task_class,
                "cached_plan_unsafe_provider",
            );
            record_failed_operation_on(&self.db, &plan, &actor, "provider_became_unsafe")
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                crate::chisei::privacy::gate_reason(data_class, task_class, &provider),
            ));
        }
        if crate::chisei::egress::is_external_provider(&provider)
            && plan.egress_decisions.is_empty()
        {
            record_failed_operation_on(&self.db, &plan, &actor, "egress_evidence_missing")
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "external execution plan missing egress decisions",
            ));
        }
        if let Some(signal) = self
            .eval
            .namespace_regression_signal(&namespace_hint)
            .filter(|signal| signal.regressed)
        {
            record_failed_operation_on(
                &self.db,
                &plan,
                &actor,
                "evaluation_regressed_after_planning",
            )
            .map_err(Status::internal)?;
            return Err(Status::failed_precondition(signal.reason));
        }
        let normalized_user_id = if input.user_id.is_empty() {
            "default".to_string()
        } else {
            input.user_id.clone()
        };
        let payload =
            payload_for_leak_check(&plan.prepared_system, &plan.prepared_messages, &plan.tools);
        let leak_findings =
            self.leak_findings_for_payload(&input.namespace, &provider, data_class, &payload);
        if leak_findings
            .iter()
            .any(|finding| finding.action == LeakAction::Block)
        {
            self.record_leak_audit(
                "execute_leak_check",
                &input.request_id,
                &provider,
                &leak_findings,
            );
            record_failed_operation_on(
                &self.db,
                &plan,
                &actor,
                "privacy_leak_detected_after_planning",
            )
            .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "privacy leak checker blocked outbound payload",
            ));
        }
        self.record_egress_audit(
            "execute_context",
            &input.request_id,
            &provider,
            &plan.resolved_model,
            &plan.egress_decisions,
        );
        let llm_req = super::pb::llm::ChatRequest {
            model: plan.resolved_model.clone(),
            system: plan.prepared_system.clone(),
            messages: plan
                .prepared_messages
                .iter()
                .map(|m| super::pb::llm::Message {
                    role: m.role.clone(),
                    content: m.content.clone(),
                    tool_call_id: m.tool_call_id.clone(),
                    tool_calls: m
                        .tool_calls
                        .iter()
                        .map(|tc| super::pb::llm::ToolCall {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            args_json: tc.args_json.clone(),
                        })
                        .collect(),
                })
                .collect(),
            tools: plan
                .tools
                .iter()
                .map(|t| super::pb::llm::ToolDef {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema_json: t.input_schema_json.clone(),
                })
                .collect(),
            max_tokens: plan.max_tokens,
            user_id: Some(normalized_user_id),
        };
        let attempt_started_at_ms = chrono::Utc::now().timestamp_millis();
        self.invalidate_ineligible_execution_memory_holdouts(
            &plan.plan_id,
            &actor,
            &plan.memory_holdouts,
        )?;
        self.record_execution_memory_injections(&plan.plan_id, &actor, &plan.memory_references)?;
        let chat = match execute_chat_request(&self.config, self.budget.clone(), llm_req).await {
            Ok(chat) => chat,
            Err(status) => {
                record_failed_operation_on(&self.db, &plan, &actor, "model_call_failed")
                    .map_err(Status::internal)?;
                return Err(status);
            }
        };
        let response = PlannedChatResponse {
            content: chat.content.clone(),
            tool_calls: chat
                .tool_calls
                .iter()
                .map(|tc| ToolCall {
                    id: tc.id.clone(),
                    name: tc.name.clone(),
                    args_json: tc.args_json.clone(),
                })
                .collect(),
            input_tokens: chat.input_tokens,
            output_tokens: chat.output_tokens,
            stop_reason: chat.stop_reason.clone(),
            provider: provider.clone(),
        };
        if let Err(error) = self.record_evolve_task(
            &input.request_id,
            &namespace_hint,
            &plan.enriched_spec,
            self.tracked_original_spec(&input.request_id, &input.spec, &plan.enriched_spec)
                .as_deref(),
            "done",
            chat.input_tokens + chat.output_tokens,
        ) {
            record_failed_operation_on(&self.db, &plan, &actor, "execution_bookkeeping_failed")
                .map_err(Status::internal)?;
            return Err(Status::internal(error));
        }
        let completed_at_ms = chrono::Utc::now().timestamp_millis();
        self.record_completed_operation(
            &plan,
            &actor,
            &response,
            attempt_started_at_ms,
            completed_at_ms,
        )
        .map_err(Status::internal)?;
        // Sampling consumption: a sampled request was selected for deeper
        // observation, so capture its actual execution outcome as a durable
        // audit record keyed to the request. Unsampled executions skip this —
        // bounded overhead is the whole point of sampling.
        if plan.sampled {
            let mut evidence = std::collections::HashMap::new();
            evidence.insert("model".to_string(), plan.resolved_model.clone());
            evidence.insert("input_tokens".to_string(), chat.input_tokens.to_string());
            evidence.insert("output_tokens".to_string(), chat.output_tokens.to_string());
            evidence.insert("stop_reason".to_string(), chat.stop_reason.clone());
            evidence.insert("sample_rate".to_string(), plan.sample_rate.to_string());
            let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.sampling".into(),
                action: "sample_observed".into(),
                reason: plan.sample_reason.clone(),
                evidence,
                target_id: input.request_id.clone(),
                outcome: "observed".into(),
            });
            // Durable, judge-able record (spec + output) that the scoring job consumes to
            // produce real eval runs. Kept in its own table so large content stays out of the
            // audit evidence JSON. Only captured when scoring is enabled — otherwise there is no
            // consumer and the (full-content) rows would accumulate as dead data.
            if self.config.scoring_enabled {
                let _ =
                    self.db
                        .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                            request_id: input.request_id.clone(),
                            namespace: namespace_hint.clone(),
                            spec: plan.enriched_spec.clone(),
                            resolved_model: plan.resolved_model.clone(),
                            output_content: chat.content.clone(),
                            sample_reason: plan.sample_reason.clone(),
                            input_tokens: chat.input_tokens,
                            output_tokens: chat.output_tokens,
                            stop_reason: chat.stop_reason.clone(),
                            timestamp: chrono::Utc::now().timestamp_millis(),
                            scored: false,
                            // NOTE: `plan.task_class` holds the *privacy* class ("private"/
                            // "template_only" — see `plan_from_input`), not the routing/cost-tier
                            // class; the raw caller-supplied routing class lives on `input`.
                            task_class: crate::chisei::scoring::normalize_task_class(
                                &input.task_class,
                            ),
                            cost_usd_micros: 0,
                        });
            }
        }
        Ok(Response::new(ExecutePlanResponse {
            response: Some(response),
            executed_at: completed_at_ms / 1000,
        }))
    }

    async fn execute_plan_stream(
        &self,
        req: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::ExecutePlanStreamStream>, Status> {
        let actor = authenticated_actor(&req);
        let requested_plan = req
            .into_inner()
            .plan
            .ok_or(Status::invalid_argument("plan required"))?;
        let plan = {
            let mut plans = self
                .planned_executions
                .lock()
                .expect("planned executions poisoned");
            prune_cached_plans(&mut plans);
            let plan = plans
                .get(&requested_plan.plan_id)
                .ok_or(Status::not_found("execution plan not found"))?;
            if plan.planning_actor != actor {
                return Err(Status::permission_denied(
                    "execution plan belongs to a different planning principal",
                ));
            }
            plans.remove(&requested_plan.plan_id).unwrap()
        };
        if !plan.executable {
            return Err(Status::failed_precondition(
                "execution plan is not executable",
            ));
        }
        let input = plan
            .input
            .clone()
            .ok_or(Status::invalid_argument("plan input required"))?;
        let namespace_hint = input.namespace.trim().to_string();
        let provider = crate::llm::provider_name(&plan.resolved_model).to_string();
        if crate::chisei::egress::is_external_provider(&provider)
            && plan.egress_decisions.is_empty()
        {
            record_failed_operation_on(&self.db, &plan, &actor, "egress_evidence_missing")
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "external execution plan missing egress decisions",
            ));
        }
        if let Some(signal) = self
            .eval
            .namespace_regression_signal(&namespace_hint)
            .filter(|signal| signal.regressed)
        {
            record_failed_operation_on(
                &self.db,
                &plan,
                &actor,
                "evaluation_regressed_after_planning",
            )
            .map_err(Status::internal)?;
            return Err(Status::failed_precondition(signal.reason));
        }
        let normalized_user_id = if input.user_id.is_empty() {
            "default".to_string()
        } else {
            input.user_id.clone()
        };
        self.record_egress_audit(
            "execute_context",
            &input.request_id,
            &provider,
            &plan.resolved_model,
            &plan.egress_decisions,
        );
        let llm_req = super::pb::llm::ChatRequest {
            model: plan.resolved_model.clone(),
            system: plan.prepared_system.clone(),
            messages: plan
                .prepared_messages
                .iter()
                .map(|m| super::pb::llm::Message {
                    role: m.role.clone(),
                    content: m.content.clone(),
                    tool_call_id: m.tool_call_id.clone(),
                    tool_calls: m
                        .tool_calls
                        .iter()
                        .map(|tc| super::pb::llm::ToolCall {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            args_json: tc.args_json.clone(),
                        })
                        .collect(),
                })
                .collect(),
            tools: plan
                .tools
                .iter()
                .map(|t| super::pb::llm::ToolDef {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema_json: t.input_schema_json.clone(),
                })
                .collect(),
            max_tokens: plan.max_tokens,
            user_id: Some(normalized_user_id),
        };
        let attempt_started_at_ms = chrono::Utc::now().timestamp_millis();
        self.invalidate_ineligible_execution_memory_holdouts(
            &plan.plan_id,
            &actor,
            &plan.memory_holdouts,
        )?;
        self.record_execution_memory_injections(&plan.plan_id, &actor, &plan.memory_references)?;
        let chat_stream =
            match execute_chat_request_stream(&self.config, self.budget.clone(), llm_req).await {
                Ok(stream) => stream,
                Err(status) => {
                    record_failed_operation_on(
                        &self.db,
                        &plan,
                        &actor,
                        "model_stream_start_failed",
                    )
                    .map_err(Status::internal)?;
                    return Err(status);
                }
            };
        let db = self.db.clone();
        let evolve_history = self.evolve_history.clone();
        let request_id = input.request_id.clone();
        let enriched_spec = plan.enriched_spec.clone();
        let original_spec =
            self.tracked_original_spec(&input.request_id, &input.spec, &plan.enriched_spec);
        let resolved_model = plan.resolved_model.clone();
        let sampled = plan.sampled;
        let sample_rate = plan.sample_rate;
        let sample_reason = plan.sample_reason.clone();
        let scoring_enabled = self.config.scoring_enabled;
        let receipt_plan = plan.clone();
        // `plan.task_class` holds the *privacy* class here (see `plan_from_input`); the routing/
        // cost-tier class the caller supplied is on the original `input`.
        let task_class = crate::chisei::scoring::normalize_task_class(&input.task_class);

        let stream = async_stream::stream! {
            let mut content = String::new();
            let mut tool_calls = Vec::new();
            let mut input_tokens = 0;
            let mut output_tokens = 0;
            let mut stop_reason = String::new();
            let mut finished = false;

            futures_util::pin_mut!(chat_stream);
            while let Some(next) = chat_stream.next().await {
                let chunk = match next {
                    Ok(chunk) => chunk,
                    Err(err) => {
                        if let Err(receipt_error) = record_failed_operation_on(
                            &db,
                            &receipt_plan,
                            &actor,
                            "model_stream_failed",
                        ) {
                            yield Err(Status::internal(receipt_error));
                            return;
                        }
                        yield Err(err);
                        return;
                    }
                };
                if !chunk.content.is_empty() {
                    content = chunk.content.clone();
                } else if !chunk.content_delta.is_empty() {
                    content.push_str(&chunk.content_delta);
                }
                if !chunk.tool_calls.is_empty() {
                    tool_calls = chunk.tool_calls.clone();
                }
                if chunk.input_tokens > 0 {
                    input_tokens = chunk.input_tokens;
                }
                if chunk.output_tokens > 0 {
                    output_tokens = chunk.output_tokens;
                }
                if !chunk.stop_reason.is_empty() {
                    stop_reason = chunk.stop_reason.clone();
                }
                if chunk.done && !finished {
                    finished = true;
                    let response = PlannedChatResponse {
                        content: content.clone(),
                        tool_calls: tool_calls
                            .iter()
                            .map(|tc| ToolCall {
                                id: tc.id.clone(),
                                name: tc.name.clone(),
                                args_json: tc.args_json.clone(),
                            })
                            .collect(),
                        input_tokens,
                        output_tokens,
                        stop_reason: stop_reason.clone(),
                        provider: provider.clone(),
                    };
                    let execution = FinishStreamedExecution {
                        db: &db,
                        evolve_history: &evolve_history,
                        request_id: &request_id,
                        namespace: &namespace_hint,
                        enriched_spec: &enriched_spec,
                        original_spec: original_spec.as_deref(),
                        resolved_model: &resolved_model,
                        sampled,
                        sample_rate,
                        sample_reason: &sample_reason,
                        scoring_enabled,
                        task_class: &task_class,
                        response: &response,
                    };
                    let _ = finish_streamed_execution(&execution);
                    let completed_at_ms = chrono::Utc::now().timestamp_millis();
                    if let Err(error) = record_completed_operation_on(
                        &db,
                        &receipt_plan,
                        &actor,
                        &response,
                        attempt_started_at_ms,
                        completed_at_ms,
                    ) {
                        yield Err(Status::internal(error));
                        return;
                    }
                    yield Ok(ExecutePlanStreamEvent {
                        content_delta: chunk.content_delta,
                        response: Some(response),
                        done: true,
                        executed_at: completed_at_ms / 1000,
                    });
                } else {
                    yield Ok(ExecutePlanStreamEvent {
                        content_delta: chunk.content_delta,
                        response: None,
                        done: false,
                        executed_at: 0,
                    });
                }
            }
            if !finished {
                let response = PlannedChatResponse {
                    content,
                    tool_calls: tool_calls
                        .into_iter()
                        .map(|tc| ToolCall {
                            id: tc.id,
                            name: tc.name,
                            args_json: tc.args_json,
                        })
                        .collect(),
                    input_tokens,
                    output_tokens,
                    stop_reason,
                    provider,
                };
                let execution = FinishStreamedExecution {
                    db: &db,
                    evolve_history: &evolve_history,
                    request_id: &request_id,
                    namespace: &namespace_hint,
                    enriched_spec: &enriched_spec,
                    original_spec: original_spec.as_deref(),
                    resolved_model: &resolved_model,
                    sampled,
                    sample_rate,
                    sample_reason: &sample_reason,
                    scoring_enabled,
                    task_class: &task_class,
                    response: &response,
                };
                let _ = finish_streamed_execution(&execution);
                let completed_at_ms = chrono::Utc::now().timestamp_millis();
                if let Err(error) = record_completed_operation_on(
                    &db,
                    &receipt_plan,
                    &actor,
                    &response,
                    attempt_started_at_ms,
                    completed_at_ms,
                ) {
                    yield Err(Status::internal(error));
                    return;
                }
                yield Ok(ExecutePlanStreamEvent {
                    content_delta: String::new(),
                    response: Some(response),
                    done: true,
                    executed_at: completed_at_ms / 1000,
                });
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn authorize_operation_reporter(
        &self,
        req: Request<AuthorizeOperationReporterRequest>,
    ) -> Result<Response<AuthorizeOperationReporterResponse>, Status> {
        let actor = authenticated_actor(&req);
        if !receipt_mutation_transport_allowed(&req, &self.config) {
            return Err(Status::permission_denied(
                "operation reporter authorization requires authenticated transport",
            ));
        }
        let request = req.into_inner();
        if request.operation_id.trim().is_empty() || request.principal.trim().is_empty() {
            return Err(Status::invalid_argument(
                "operation_id and principal are required",
            ));
        }
        let receipt = self
            .db
            .get_operation_receipt(&request.operation_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("operation receipt not found"))?;
        if actor != receipt.initiating_actor && actor != "root" {
            return Err(Status::permission_denied(
                "only the initiating actor or root may authorize reporters",
            ));
        }
        if request.event_kinds.is_empty() {
            return Err(Status::invalid_argument("event_kinds required"));
        }
        let event_kinds = request
            .event_kinds
            .iter()
            .map(|kind| {
                ReceiptEventKind::parse(kind)
                    .filter(|kind| reportable_receipt_kind(*kind))
                    .ok_or_else(|| {
                        Status::invalid_argument(format!("unsupported event kind {kind:?}"))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let changed = self
            .db
            .authorize_operation_reporter(
                &request.operation_id,
                request.principal.trim(),
                event_kinds,
            )
            .map_err(Status::internal)?;
        Ok(Response::new(AuthorizeOperationReporterResponse {
            authorized: true,
            changed,
        }))
    }

    async fn list_kioku_candidates(
        &self,
        req: Request<ListKiokuCandidatesRequest>,
    ) -> Result<Response<ListKiokuCandidatesResponse>, Status> {
        require_eval_admin(&req)?;
        let request = req.into_inner();
        if request.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace is required"));
        }
        let limit = match request.limit {
            0 => 50,
            1..=100 => request.limit as usize,
            _ => return Err(Status::invalid_argument("limit must not exceed 100")),
        };
        let operation_class = (!request.operation_class.trim().is_empty())
            .then_some(request.operation_class.as_str());
        let memories = self
            .db
            .list_kioku_candidates(&request.namespace, operation_class, limit)
            .map_err(Status::internal)?;
        let candidates = memories
            .into_iter()
            .map(|memory| -> Result<KiokuCandidateRecord, Status> {
                let evidence = self
                    .db
                    .list_kioku_evidence(&memory.id, memory.version)
                    .map_err(Status::internal)?;
                let validation = self
                    .db
                    .validate_kioku_candidate(&memory.id, memory.version)
                    .map_err(Status::internal)?;
                Ok(KiokuCandidateRecord {
                    memory_json: serde_json::to_string(&memory).map_err(|error| {
                        Status::internal(format!("failed to serialize memory: {error}"))
                    })?,
                    evidence_json: evidence
                        .iter()
                        .map(serde_json::to_string)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| {
                            Status::internal(format!("failed to serialize evidence: {error}"))
                        })?,
                    valid: validation.valid,
                    validation_errors: validation.errors,
                    supporting_evidence: validation.supporting_evidence as u32,
                    contradicting_evidence: validation.contradicting_evidence as u32,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListKiokuCandidatesResponse { candidates }))
    }

    async fn review_kioku_memory(
        &self,
        req: Request<ReviewKiokuMemoryRequest>,
    ) -> Result<Response<ReviewKiokuMemoryResponse>, Status> {
        require_eval_admin(&req)?;
        let actor = authenticated_actor(&req);
        let request = req.into_inner();
        if request.memory_id.trim().is_empty()
            || request.memory_version == 0
            || request.rationale.trim().is_empty()
        {
            return Err(Status::invalid_argument(
                "memory id, version, and rationale are required",
            ));
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        let memory = match request.action.as_str() {
            "promote" | "reject" | "supersede" => {
                let memory = self
                    .db
                    .get_kioku_memory(&request.memory_id, request.memory_version)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::not_found("memory version not found"))?;
                if request.action == "supersede" && memory.supersedes.is_none() {
                    return Err(Status::failed_precondition(
                        "supersede requires candidate lineage to an active memory",
                    ));
                }
                self.db
                    .review_kioku_candidate(
                        &request.memory_id,
                        request.memory_version,
                        crate::chisei::kioku::HumanMemoryReview {
                            action: if request.action == "reject" {
                                crate::chisei::kioku::HumanReviewAction::Reject
                            } else {
                                crate::chisei::kioku::HumanReviewAction::Promote
                            },
                            reviewer: actor,
                            rationale: request.rationale,
                            reviewed_at_ms: now_ms,
                        },
                    )
                    .map_err(Status::failed_precondition)?
            }
            "disable" => self
                .db
                .disable_kioku_memory(
                    &request.memory_id,
                    request.memory_version,
                    &actor,
                    &request.rationale,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?,
            _ => {
                return Err(Status::invalid_argument(
                    "action must be promote, reject, supersede, or disable",
                ));
            }
        };
        let lifecycle_events = self
            .db
            .list_kioku_lifecycle_events(&memory.id, memory.version)
            .map_err(Status::internal)?;
        Ok(Response::new(ReviewKiokuMemoryResponse {
            memory_json: serde_json::to_string(&memory)
                .map_err(|error| Status::internal(error.to_string()))?,
            lifecycle_events_json: lifecycle_events
                .iter()
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| Status::internal(error.to_string()))?,
        }))
    }

    async fn report_operation_event(
        &self,
        req: Request<ReportOperationEventRequest>,
    ) -> Result<Response<ReportOperationEventResponse>, Status> {
        let actor = authenticated_actor(&req);
        let request_auth_source = auth_source(&req);
        let configured_gateway = self
            .config
            .gateway_receipt_principals
            .iter()
            .any(|principal| principal == &actor);
        let trusted_outcome_reporter = (request_auth_source.as_deref() == Some("token")
            && (configured_gateway || matches!(actor.as_str(), "chisei-gateway" | "root")))
            || (self.config.insecure
                && request_auth_source.as_deref() == Some("local")
                && actor == "chisei-gateway");
        if !receipt_mutation_transport_allowed(&req, &self.config) {
            return Err(Status::permission_denied(
                "operation event reporting requires authenticated transport",
            ));
        }
        let mut request = req.into_inner();
        if request.operation_id.trim().is_empty() {
            return Err(Status::invalid_argument("operation_id required"));
        }
        let receipt = self
            .db
            .get_operation_receipt(&request.operation_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("operation receipt not found"))?;
        let receipt_was_complete = receipt.completeness().complete;
        let kind = ReceiptEventKind::parse(&request.kind)
            .ok_or(Status::invalid_argument("unsupported operation event kind"))?;
        if !reportable_receipt_kind(kind) {
            return Err(Status::invalid_argument(
                "event kind is not reportable through this API",
            ));
        }
        let receipt_has_kioku_context = !self
            .db
            .list_kioku_outcome_assignments(&receipt.operation_id)
            .map_err(Status::internal)?
            .is_empty()
            || receipt.events.iter().any(|event| {
                event.kind == ReceiptEventKind::ContextGoverned
                    && event
                        .references
                        .iter()
                        .any(|reference| reference.kind == "kioku_memory" && !reference.omitted)
            });
        let supplies_kioku_outcome = ["outcome_metric", "outcome_value"]
            .iter()
            .any(|attribute| request.attributes.contains_key(*attribute));
        let complete_kioku_outcome = ["outcome_metric", "outcome_value", "passed"]
            .iter()
            .all(|attribute| request.attributes.contains_key(*attribute));
        if kind == ReceiptEventKind::OutcomeRecorded
            && receipt_has_kioku_context
            && supplies_kioku_outcome
            && !complete_kioku_outcome
        {
            return Err(Status::invalid_argument(
                "Kioku outcomes require outcome_metric, outcome_value, and passed",
            ));
        }
        if kind == ReceiptEventKind::OutcomeRecorded
            && receipt_has_kioku_context
            && complete_kioku_outcome
        {
            let outcome_metric = request.attributes["outcome_metric"].trim().to_string();
            if outcome_metric.is_empty() {
                return Err(Status::invalid_argument(
                    "Kioku outcome_metric must not be empty",
                ));
            }
            request
                .attributes
                .insert("outcome_metric".into(), outcome_metric);
            let outcome_value = request.attributes["outcome_value"]
                .parse::<f64>()
                .map_err(|_| Status::invalid_argument("Kioku outcome_value must be finite"))?;
            if !outcome_value.is_finite() {
                return Err(Status::invalid_argument(
                    "Kioku outcome_value must be finite",
                ));
            }
            request.attributes["passed"]
                .parse::<bool>()
                .map_err(|_| Status::invalid_argument("Kioku passed must be boolean"))?;
        }
        if kind == ReceiptEventKind::OutcomeRecorded
            && receipt_has_kioku_context
            && supplies_kioku_outcome
            && !trusted_outcome_reporter
        {
            return Err(Status::permission_denied(
                "Kioku outcome reporting requires a trusted gateway principal",
            ));
        }
        let stored_kind = if let Some(existing_kind) = receipt
            .events
            .iter()
            .find(|event| event.event_id == request.event_id)
            .map(|event| event.kind)
        {
            existing_kind
        } else if kind == ReceiptEventKind::OutcomeRecorded
            && receipt_was_complete
            && receipt_has_kioku_context
            && complete_kioku_outcome
            && trusted_outcome_reporter
        {
            ReceiptEventKind::MemoryOutcomeRecorded
        } else {
            kind
        };
        let explicitly_granted = receipt
            .reporter_grants
            .iter()
            .any(|grant| grant.principal == actor && grant.event_kinds.contains(&kind));
        let trusted_kioku_outcome = kind == ReceiptEventKind::OutcomeRecorded
            && receipt_has_kioku_context
            && complete_kioku_outcome
            && trusted_outcome_reporter;
        if actor != receipt.initiating_actor
            && actor != "root"
            && !explicitly_granted
            && !trusted_kioku_outcome
        {
            return Err(Status::permission_denied(
                "operation event reporter is not authorized for this event kind",
            ));
        }
        if request.parent_event_id.trim().is_empty() {
            return Err(Status::invalid_argument("parent_event_id required"));
        }
        let parent = receipt
            .events
            .iter()
            .find(|event| event.event_id == request.parent_event_id)
            .ok_or(Status::failed_precondition("causal parent not found"))?;
        let now = chrono::Utc::now().timestamp_millis();
        let timestamp_ms = if request.timestamp_ms <= 0 {
            now
        } else if request.timestamp_ms > now {
            return Err(Status::invalid_argument(
                "event timestamp must not be in the future",
            ));
        } else if request.timestamp_ms < parent.timestamp_ms {
            return Err(Status::invalid_argument(
                "event timestamp must not precede its causal parent",
            ));
        } else {
            request.timestamp_ms
        };
        if request.attributes.len() > 64 {
            return Err(Status::invalid_argument(
                "at most 64 attributes are allowed",
            ));
        }
        let sensitive_attribute = request.attributes.keys().find(|key| {
            let key = key.to_ascii_lowercase().replace('-', "_");
            let compact_key = key.replace('_', "");
            [
                "authorization",
                "api_key",
                "credential",
                "cookie",
                "secret",
                "password",
                "passwd",
                "passphrase",
                "private_key",
                "token",
            ]
            .iter()
            .any(|sensitive| {
                let compact_sensitive = sensitive.replace('_', "");
                key == *sensitive
                    || key.ends_with(&format!("_{sensitive}"))
                    || compact_key == compact_sensitive
                    || compact_key.ends_with(&compact_sensitive)
            })
        });
        if let Some(key) = sensitive_attribute {
            return Err(Status::invalid_argument(format!(
                "sensitive attribute {key:?} is not allowed"
            )));
        }
        if request
            .attributes
            .iter()
            .any(|(key, value)| key.len() > 128 || value.len() > 4096)
        {
            return Err(Status::invalid_argument("attribute exceeds size limit"));
        }
        if request.references.len() > 32 {
            return Err(Status::invalid_argument(
                "at most 32 references are allowed",
            ));
        }
        let references = request
            .references
            .into_iter()
            .map(|reference| {
                if reference.kind.trim().is_empty() || reference.reference.trim().is_empty() {
                    return Err(Status::invalid_argument(
                        "reference kind and reference are required",
                    ));
                }
                if reference.omitted && reference.omission_reason.trim().is_empty() {
                    return Err(Status::invalid_argument(
                        "omitted reference requires omission_reason",
                    ));
                }
                if !reference.content_hash.is_empty()
                    && (reference.content_hash.len() != 64
                        || !reference
                            .content_hash
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit()))
                {
                    return Err(Status::invalid_argument(
                        "content_hash must be a 64-character hexadecimal digest",
                    ));
                }
                Ok(GovernedReference {
                    kind: reference.kind,
                    reference: reference.reference,
                    content_hash: (!reference.content_hash.is_empty())
                        .then_some(reference.content_hash),
                    disclosed_fields: reference.disclosed_fields,
                    omitted: reference.omitted,
                    omission_reason: (!reference.omission_reason.is_empty())
                        .then_some(reference.omission_reason),
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        let reported_event_prefix = format!("report:{}:", request.operation_id);
        let event_id = if request.event_id.trim().is_empty() {
            format!("{reported_event_prefix}{}", uuid::Uuid::new_v4())
        } else if request.event_id.starts_with(&reported_event_prefix) {
            request.event_id
        } else {
            return Err(Status::invalid_argument(format!(
                "reported event_id must start with {reported_event_prefix:?}"
            )));
        };
        let mut attributes = request.attributes.into_iter().collect::<BTreeMap<_, _>>();
        attributes.remove(KIOKU_TRUSTED_OUTCOME_ATTRIBUTE);
        if matches!(
            stored_kind,
            ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
        ) && trusted_outcome_reporter
            && complete_kioku_outcome
        {
            attributes.insert(KIOKU_TRUSTED_OUTCOME_ATTRIBUTE.into(), "true".into());
        }
        let event = OperationReceiptEvent {
            event_id: event_id.clone(),
            operation_id: request.operation_id.clone(),
            parent_event_id: Some(request.parent_event_id),
            timestamp_ms,
            kind: stored_kind,
            surface: stored_kind.surface(),
            actor: actor.clone(),
            references,
            attributes,
        };
        let mut prospective_receipt = receipt.clone();
        let prospective_event_recorded = !prospective_receipt
            .events
            .iter()
            .any(|existing| existing.event_id == event.event_id);
        if prospective_event_recorded {
            prospective_receipt
                .uncovered_surfaces
                .retain(|entry| entry.surface != event.surface);
            if event.kind == ReceiptEventKind::OutcomeRecorded {
                prospective_receipt.completed_at_ms = Some(event.timestamp_ms);
            }
            prospective_receipt.events.push(event.clone());
        }
        let prospective_completeness = prospective_receipt.completeness();
        let should_preflight_attribution = prospective_event_recorded
            && receipt_has_kioku_context
            && prospective_completeness.complete
            && ((!receipt_was_complete)
                || (trusted_outcome_reporter
                    && complete_kioku_outcome
                    && matches!(
                        stored_kind,
                        ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
                    )));
        if should_preflight_attribution {
            record_reported_memory_outcomes(
                &self.db,
                &prospective_receipt,
                &actor,
                now,
                true,
                (stored_kind == ReceiptEventKind::MemoryOutcomeRecorded)
                    .then_some(event_id.as_str()),
                true,
            )
            .map_err(|error| {
                Status::failed_precondition(format!("Kioku outcome attribution invalid: {error}"))
            })?;
        }
        let (receipt, recorded) = self
            .db
            .append_operation_receipt_event(&request.operation_id, event)
            .map_err(|error| {
                if error.contains("not found") {
                    Status::not_found(error)
                } else if error.contains("already exists") {
                    Status::already_exists(error)
                } else {
                    Status::failed_precondition(error)
                }
            })?;
        let completeness = receipt.completeness();
        let should_attribute = receipt_has_kioku_context
            && completeness.complete
            && ((recorded && !receipt_was_complete)
                || (trusted_outcome_reporter
                    && complete_kioku_outcome
                    && matches!(
                        stored_kind,
                        ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
                    )));
        if should_attribute
            && let Err(error) = record_reported_memory_outcomes(
                &self.db,
                &receipt,
                &actor,
                now,
                true,
                (stored_kind == ReceiptEventKind::MemoryOutcomeRecorded)
                    .then_some(event_id.as_str()),
                false,
            )
        {
            let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                actor: "chisei.kioku".into(),
                action: "kioku.outcome_attribution".into(),
                reason: error,
                evidence: std::collections::HashMap::from([
                    ("operation_id".into(), receipt.operation_id.clone()),
                    ("receipt_event_id".into(), event_id.clone()),
                ]),
                target_id: receipt.operation_id.clone(),
                outcome: "failed".into(),
            });
        }
        Ok(Response::new(ReportOperationEventResponse {
            event_id,
            recorded,
            complete: completeness.complete,
            missing_surfaces: completeness
                .missing_surfaces
                .into_iter()
                .map(|surface| surface.as_str().to_string())
                .collect(),
        }))
    }

    async fn reserve_gateway_request_alias(
        &self,
        req: Request<ReserveGatewayRequestAliasRequest>,
    ) -> Result<Response<ReserveGatewayRequestAliasResponse>, Status> {
        let actor = authenticated_actor(&req);
        let auth_source = req
            .metadata()
            .get(AUTH_SOURCE_HEADER)
            .and_then(|value| value.to_str().ok());
        let configured_gateway = self
            .config
            .gateway_receipt_principals
            .iter()
            .any(|principal| principal == &actor)
            && auth_source == Some("token");
        if !configured_gateway && !matches!(actor.as_str(), "root" | "local" | "chisei-gateway") {
            return Err(Status::permission_denied(
                "gateway request alias reservation requires a gateway service principal",
            ));
        }
        let request = req.into_inner();
        if request.caller_scope.trim().is_empty()
            || request.request_alias.trim().is_empty()
            || request.request_id.trim().is_empty()
            || request.operation_id.trim().is_empty()
        {
            return Err(Status::invalid_argument(
                "caller_scope, request_alias, request_id, and operation_id are required",
            ));
        }
        let reserved = self
            .db
            .reserve_gateway_request_alias(
                &request.caller_scope,
                &request.request_alias,
                &request.request_id,
                &request.operation_id,
            )
            .map_err(Status::internal)?;
        Ok(Response::new(ReserveGatewayRequestAliasResponse {
            reserved,
        }))
    }

    async fn claim_gateway_request_alias_dispatch(
        &self,
        req: Request<ClaimGatewayRequestAliasDispatchRequest>,
    ) -> Result<Response<ClaimGatewayRequestAliasDispatchResponse>, Status> {
        let actor = authenticated_actor(&req);
        let auth_source = req
            .metadata()
            .get(AUTH_SOURCE_HEADER)
            .and_then(|value| value.to_str().ok());
        let configured_gateway = self
            .config
            .gateway_receipt_principals
            .iter()
            .any(|principal| principal == &actor)
            && auth_source == Some("token");
        if !configured_gateway && !matches!(actor.as_str(), "root" | "local" | "chisei-gateway") {
            return Err(Status::permission_denied(
                "gateway request alias dispatch requires a gateway service principal",
            ));
        }
        let request = req.into_inner();
        if request.caller_scope.trim().is_empty()
            || request.request_alias.trim().is_empty()
            || request.request_id.trim().is_empty()
            || request.operation_id.trim().is_empty()
            || request.dispatch_token.trim().is_empty()
        {
            return Err(Status::invalid_argument(
                "caller_scope, request_alias, request_id, operation_id, and dispatch_token are required",
            ));
        }
        let claimed = self
            .db
            .claim_gateway_request_alias_dispatch(
                &request.caller_scope,
                &request.request_alias,
                &request.request_id,
                &request.operation_id,
                &request.dispatch_token,
            )
            .map_err(Status::internal)?;
        Ok(Response::new(ClaimGatewayRequestAliasDispatchResponse {
            claimed,
        }))
    }

    async fn get_operation_receipt(
        &self,
        req: Request<GetOperationReceiptRequest>,
    ) -> Result<Response<GetOperationReceiptResponse>, Status> {
        let actor = authenticated_actor(&req);
        let request = req.into_inner();
        let operation_id = request.operation_id.trim();
        let request_id = request.request_id.trim();
        let caller_scope = request.caller_scope.trim();
        let attempt = (request.attempt > 0).then_some(request.attempt);
        if operation_id.is_empty() == request_id.is_empty() {
            return Err(Status::invalid_argument(
                "exactly one of operation_id or request_id is required",
            ));
        }
        let receipt = if !operation_id.is_empty() {
            if let Some(attempt) = attempt {
                match self
                    .db
                    .find_gateway_receipt_by_logical_operation_id(operation_id, Some(attempt))
                {
                    Ok(Some(receipt)) => Ok(Some(receipt)),
                    Ok(None) if attempt == 1 => self.db.get_operation_receipt(operation_id),
                    Ok(None) => Ok(None),
                    Err(error) => Err(error),
                }
            } else {
                let exact = self.db.get_operation_receipt(operation_id);
                let derived = self
                    .db
                    .find_gateway_receipt_by_logical_operation_id(operation_id, None);
                match (exact, derived) {
                    (Ok(Some(_)), Ok(Some(_))) => Err(
                        "logical operation id matches multiple legacy and attempt receipts".into(),
                    ),
                    (Ok(Some(receipt)), Ok(None)) | (Ok(None), Ok(Some(receipt))) => {
                        Ok(Some(receipt))
                    }
                    (Ok(None), Ok(None)) => Ok(None),
                    (Err(error), _) | (_, Err(error)) => Err(error),
                }
            }
        } else {
            let privileged = matches!(actor.as_str(), "root" | "local" | "chisei-gateway");
            if !privileged {
                return Err(Status::permission_denied(
                    "opaque request alias lookup requires administrative inspection access",
                ));
            }
            let alias_lookup = || {
                self.db.find_operation_receipt_by_lookup_request_id(
                    request_id,
                    (!caller_scope.is_empty()).then_some(caller_scope),
                    None,
                )
            };
            if caller_scope.is_empty() {
                match self.db.find_operation_receipt_by_request_id(request_id) {
                    Ok(Some(receipt)) => Ok(Some(receipt)),
                    Ok(None) => alias_lookup(),
                    Err(error) => Err(error),
                }
            } else {
                match alias_lookup() {
                    Ok(Some(receipt)) => Ok(Some(receipt)),
                    Ok(None) => self.db.find_operation_receipt_by_request_id(request_id),
                    Err(error) => Err(error),
                }
            }
        }
        .map_err(|error| {
            if error.contains("matches multiple") {
                Status::failed_precondition(error)
            } else {
                Status::internal(error)
            }
        })?
        .ok_or(Status::not_found("operation receipt not found"))?;
        if actor != receipt.initiating_actor
            // The UDS interceptor assigns `local`; local socket access is the
            // administrative inspection boundary used by sekaictl. This
            // exception is read-only and is not accepted by mutation RPCs.
            && !matches!(actor.as_str(), "root" | "local" | "chisei-gateway")
        {
            return Err(Status::permission_denied(
                "operation receipt is not visible to this principal",
            ));
        }
        let completeness = receipt.completeness();
        let receipt_json =
            serde_json::to_string(&receipt).map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(GetOperationReceiptResponse {
            receipt_json,
            complete: completeness.complete,
            missing_surfaces: completeness
                .missing_surfaces
                .into_iter()
                .map(|surface| surface.as_str().to_string())
                .collect(),
        }))
    }

    async fn query_operation_statistics(
        &self,
        req: Request<QueryOperationStatisticsRequest>,
    ) -> Result<Response<QueryOperationStatisticsResponse>, Status> {
        let actor = authenticated_actor(&req);
        let request = req.into_inner();
        if request.namespaces.is_empty() {
            return Err(Status::invalid_argument(
                "at least one namespace is required",
            ));
        }
        if request.start_timestamp_ms < 0 || request.end_timestamp_ms <= request.start_timestamp_ms
        {
            return Err(Status::invalid_argument(
                "statistics require an inclusive start before the exclusive end",
            ));
        }
        if request
            .end_timestamp_ms
            .saturating_sub(request.start_timestamp_ms)
            > crate::operation_statistics::MAX_STATISTICS_WINDOW_MS
        {
            return Err(Status::invalid_argument(
                "statistics window must not exceed one year",
            ));
        }
        let mut namespaces = request
            .namespaces
            .into_iter()
            .map(|namespace| namespace.trim().to_string())
            .collect::<Vec<_>>();
        if namespaces.iter().any(String::is_empty) {
            return Err(Status::invalid_argument(
                "namespace values must not be empty",
            ));
        }
        namespaces.sort();
        namespaces.dedup();
        if namespaces.len() > 100 {
            return Err(Status::invalid_argument(
                "statistics queries support at most 100 namespaces",
            ));
        }
        authorize_statistics_namespaces(&self.db, &actor, &namespaces)?;
        let statistics = crate::operation_statistics::query_operation_statistics(
            &self.db,
            &namespaces,
            request.start_timestamp_ms,
            request.end_timestamp_ms,
        )
        .map_err(|error| {
            if error.starts_with("statistics receipt limit exceeded") {
                Status::resource_exhausted(error)
            } else {
                Status::internal(error)
            }
        })?;
        let totals = statistics.totals;
        let outcomes = statistics.outcomes;
        let learning = statistics.learning;
        Ok(Response::new(QueryOperationStatisticsResponse {
            totals: Some(OperationStatisticsTotals {
                logical_operations: totals.logical_operations,
                receipts: totals.receipts,
                model_calls: totals.model_calls,
                priced_model_calls: totals.priced_model_calls,
                unpriced_model_calls: totals.unpriced_model_calls,
                model_calls_without_model: totals.model_calls_without_model,
                total_cost_usd_micros: totals.total_cost_usd_micros,
                waiting_operations: totals.waiting_operations,
                waiting_time_ms: totals.waiting_time_ms,
            }),
            daily_spend: statistics
                .daily_spend
                .into_iter()
                .map(|(day, value)| OperationStatisticValue {
                    labels: HashMap::from([("date".into(), day)]),
                    value,
                })
                .collect(),
            namespace_model_spend: statistics
                .namespace_model_spend
                .into_iter()
                .map(|((namespace, model), value)| OperationStatisticValue {
                    labels: HashMap::from([
                        ("namespace".into(), namespace),
                        ("model".into(), model),
                    ]),
                    value,
                })
                .collect(),
            // No namespace policy currently defines a monetary cap and period.
            // Portfolio objectives and token budgets are intentionally not
            // relabeled as spend caps.
            spend_caps: Vec::new(),
            outcomes: Some(OperationOutcomeCounts {
                verified: outcomes.verified,
                failed: outcomes.failed,
                parked: outcomes.parked,
                rejected: outcomes.rejected,
                unverified: outcomes.unverified,
                unknown: outcomes.unknown,
            }),
            learning: Some(OperationLearningCounts {
                learnings_admitted: learning.learnings_admitted,
                enrichments_served: learning.enrichments_served,
                escalations_answered: learning.escalations_answered,
            }),
        }))
    }

    async fn get_affinity(
        &self,
        req: Request<GetAffinityRequest>,
    ) -> Result<Response<GetAffinityResponse>, Status> {
        let r = req.into_inner();
        let a = crate::chisei::affinity::get_affinity(&self.db, &r.namespace);
        Ok(Response::new(GetAffinityResponse {
            result: Some(AffinityResult {
                namespaces: a.namespaces,
                best_model: a.best_model,
                low_success: a.low_success,
            }),
        }))
    }

    async fn create_eval_suite(
        &self,
        req: Request<CreateEvalSuiteRequest>,
    ) -> Result<Response<CreateEvalSuiteResponse>, Status> {
        require_eval_admin(&req)?;
        let s = req
            .into_inner()
            .suite
            .ok_or(Status::invalid_argument("suite required"))?;
        let suite = crate::chisei::eval::Suite {
            id: s.id.clone(),
            name: s.name.clone(),
            description: s.description.clone(),
            cases: s
                .cases
                .iter()
                .map(|c| crate::chisei::eval::Case {
                    id: c.id.clone(),
                    name: c.name.clone(),
                    namespace: c.namespace.clone(),
                    spec: c.spec.clone(),
                    assertions: c
                        .assertions
                        .iter()
                        .map(|a| crate::chisei::eval::Assertion {
                            assert_type: a.r#type.clone(),
                            value: a.value.clone(),
                        })
                        .collect(),
                })
                .collect(),
        };
        self.eval.put_suite(suite).map_err(Status::internal)?;
        Ok(Response::new(CreateEvalSuiteResponse { suite: Some(s) }))
    }

    async fn list_eval_suites(
        &self,
        _r: Request<ListEvalSuitesRequest>,
    ) -> Result<Response<ListEvalSuitesResponse>, Status> {
        let suites = self.eval.list_suites();
        let pb: Vec<EvalSuite> = suites
            .iter()
            .map(|s| EvalSuite {
                id: s.id.clone(),
                name: s.name.clone(),
                description: s.description.clone(),
                cases: vec![],
            })
            .collect();
        Ok(Response::new(ListEvalSuitesResponse { suites: pb }))
    }

    async fn get_eval_suite(
        &self,
        req: Request<GetEvalSuiteRequest>,
    ) -> Result<Response<GetEvalSuiteResponse>, Status> {
        let s = self
            .eval
            .get_suite(&req.into_inner().id)
            .ok_or(Status::not_found("not found"))?;
        Ok(Response::new(GetEvalSuiteResponse {
            suite: Some(EvalSuite {
                id: s.id,
                name: s.name,
                description: s.description,
                cases: s
                    .cases
                    .into_iter()
                    .map(|case| EvalCase {
                        id: case.id,
                        name: case.name,
                        namespace: case.namespace,
                        spec: case.spec,
                        assertions: case
                            .assertions
                            .into_iter()
                            .map(|assertion| EvalAssertion {
                                r#type: assertion.assert_type,
                                value: assertion.value,
                            })
                            .collect(),
                    })
                    .collect(),
            }),
        }))
    }

    async fn create_eval_run(
        &self,
        req: Request<CreateEvalRunRequest>,
    ) -> Result<Response<CreateEvalRunResponse>, Status> {
        require_eval_admin(&req)?;
        let req = req.into_inner();
        let r = req.run.ok_or(Status::invalid_argument("run required"))?;
        let run = crate::chisei::eval::Run {
            id: r.id.clone(),
            suite_id: r.suite_id.clone(),
            config_ref: r.config_ref.clone(),
            results: r
                .results
                .iter()
                .map(|cr| crate::chisei::eval::CaseResult {
                    case_id: cr.case_id.clone(),
                    passed: cr.passed,
                    status: cr.status.clone(),
                    result: cr.result.clone(),
                    score: cr.score,
                    reason: cr.reason.clone(),
                    elapsed: cr.elapsed,
                })
                .collect(),
            timestamp: r.timestamp,
        };
        self.eval.put_run(run).map_err(Status::internal)?;
        if !req.changed_file.is_empty() {
            self.eval
                .track_iteration(&r.suite_id, &r.id, &req.changed_file, &req.diff_hash)
                .map_err(Status::internal)?;
        }
        Ok(Response::new(CreateEvalRunResponse { run: Some(r) }))
    }

    async fn get_eval_run(
        &self,
        req: Request<GetEvalRunRequest>,
    ) -> Result<Response<GetEvalRunResponse>, Status> {
        let run = self
            .eval
            .get_run(&req.into_inner().id)
            .ok_or(Status::not_found("not found"))?;
        Ok(Response::new(GetEvalRunResponse {
            run: Some(EvalRun {
                id: run.id,
                suite_id: run.suite_id,
                config_ref: run.config_ref,
                results: run
                    .results
                    .into_iter()
                    .map(|result| CaseResult {
                        case_id: result.case_id,
                        passed: result.passed,
                        status: result.status,
                        result: result.result,
                        score: result.score,
                        reason: result.reason,
                        elapsed: result.elapsed,
                    })
                    .collect(),
                timestamp: run.timestamp,
            }),
        }))
    }

    async fn list_eval_runs(
        &self,
        req: Request<ListEvalRunsRequest>,
    ) -> Result<Response<ListEvalRunsResponse>, Status> {
        let runs = self.eval.list_runs(&req.into_inner().suite_id);
        let pb: Vec<EvalRun> = runs
            .iter()
            .map(|r| EvalRun {
                id: r.id.clone(),
                suite_id: r.suite_id.clone(),
                config_ref: r.config_ref.clone(),
                results: vec![],
                timestamp: r.timestamp,
            })
            .collect();
        Ok(Response::new(ListEvalRunsResponse { runs: pb }))
    }

    async fn track_eval_iteration(
        &self,
        req: Request<TrackEvalIterationRequest>,
    ) -> Result<Response<TrackEvalIterationResponse>, Status> {
        require_eval_admin(&req)?;
        let r = req.into_inner();
        if r.suite_id.is_empty() || r.run_id.is_empty() || r.changed_file.is_empty() {
            return Err(Status::invalid_argument(
                "suite_id, run_id, and changed_file are required",
            ));
        }
        let iteration = self
            .eval
            .track_iteration(&r.suite_id, &r.run_id, &r.changed_file, &r.diff_hash)
            .map_err(Status::internal)?;
        Ok(Response::new(TrackEvalIterationResponse {
            iteration: Some(eval_iteration_pb(iteration)),
        }))
    }

    async fn get_latest_eval_iteration(
        &self,
        req: Request<GetLatestEvalIterationRequest>,
    ) -> Result<Response<GetLatestEvalIterationResponse>, Status> {
        let iteration = self
            .eval
            .latest_iteration_for_file(&req.into_inner().changed_file)
            .ok_or(Status::not_found("iteration not found"))?;
        Ok(Response::new(GetLatestEvalIterationResponse {
            iteration: Some(eval_iteration_pb(iteration)),
        }))
    }

    async fn list_eval_iterations(
        &self,
        req: Request<ListEvalIterationsRequest>,
    ) -> Result<Response<ListEvalIterationsResponse>, Status> {
        let r = req.into_inner();
        let mut iterations = if r.changed_file.is_empty() {
            self.eval.list_iterations(&r.suite_id)
        } else {
            self.eval.list_iterations_for_file(&r.changed_file)
        };
        if !r.suite_id.is_empty() {
            iterations.retain(|iteration| iteration.suite_id == r.suite_id);
        }
        Ok(Response::new(ListEvalIterationsResponse {
            iterations: iterations.into_iter().map(eval_iteration_pb).collect(),
        }))
    }

    async fn compare_runs(
        &self,
        req: Request<CompareRunsRequest>,
    ) -> Result<Response<CompareRunsResponse>, Status> {
        let r = req.into_inner();
        let d = self
            .eval
            .compare_runs(&r.baseline_id, &r.candidate_id)
            .ok_or(Status::not_found("runs not found"))?;
        Ok(Response::new(CompareRunsResponse {
            decision: Some(GateDecision {
                verdict: d.verdict,
                reason: d.reason,
                baseline_score: d.baseline_score,
                candidate_score: d.candidate_score,
            }),
        }))
    }

    async fn get_evidence_context_gate(
        &self,
        req: Request<GetEvidenceContextGateRequest>,
    ) -> Result<Response<GetEvidenceContextGateResponse>, Status> {
        let request = req.into_inner();
        let namespace = request.namespace.trim();
        let source_type = request.source_type.trim();
        let evidence_type = request.evidence_type.trim();
        if namespace.is_empty() || source_type.is_empty() || evidence_type.is_empty() {
            return Err(Status::invalid_argument(
                "namespace, source_type, and evidence_type are required",
            ));
        }
        let namespace_gate = self.pipeline_context_expansion_gate(namespace);
        let class_gate = self.evidence_context_gate(
            namespace,
            source_type,
            evidence_type,
            namespace_gate.allowed,
        );
        let reason = if class_gate.effective_allowed {
            class_gate.gate.reason.clone()
        } else if class_gate.gate.allowed {
            "namespace context-expansion gate is not allowed".into()
        } else {
            class_gate.gate.reason.clone()
        };
        Ok(Response::new(GetEvidenceContextGateResponse {
            gate: Some(EvidenceContextGate {
                source_type: class_gate.source_type,
                evidence_type: class_gate.evidence_type,
                profile_key: class_gate.gate.profile_key,
                allowed: class_gate.effective_allowed,
                verdict: class_gate.gate.verdict,
                reason,
                iteration_id: class_gate.gate.iteration_id,
                baseline_run_id: class_gate.gate.baseline_run_id,
                candidate_run_id: class_gate.gate.candidate_run_id,
                expected_baseline_config_ref: evidence_context_config_ref(
                    source_type,
                    evidence_type,
                    false,
                ),
                expected_candidate_config_ref: evidence_context_config_ref(
                    source_type,
                    evidence_type,
                    true,
                ),
            }),
        }))
    }

    async fn eval_variance(
        &self,
        req: Request<EvalVarianceRequest>,
    ) -> Result<Response<EvalVarianceResponse>, Status> {
        let r = req.into_inner();
        let variance = self.eval.variance(&r.suite_id, &r.config_ref);
        Ok(Response::new(EvalVarianceResponse {
            variance: Some(EvalVariance {
                suite_id: variance.suite_id,
                config_ref: variance.config_ref,
                run_count: variance.run_count,
                mean_score: variance.mean_score,
                std_dev: variance.std_dev,
                min_score: variance.min_score,
                max_score: variance.max_score,
                cases: variance
                    .cases
                    .into_iter()
                    .map(|case| EvalVarianceCase {
                        case_id: case.case_id,
                        run_count: case.run_count,
                        pass_rate: case.pass_rate,
                        mean_score: case.mean_score,
                        min_score: case.min_score,
                        max_score: case.max_score,
                        std_dev: case.std_dev,
                    })
                    .collect(),
            }),
        }))
    }

    async fn eval_model_compare(
        &self,
        req: Request<EvalModelCompareRequest>,
    ) -> Result<Response<EvalModelCompareResponse>, Status> {
        let r = req.into_inner();
        let comparison = self.eval.model_compare(&r.suite_id);
        Ok(Response::new(EvalModelCompareResponse {
            comparison: Some(EvalModelComparison {
                suite_id: comparison.suite_id,
                models: comparison
                    .models
                    .into_iter()
                    .map(|model| EvalModelVariance {
                        model_id: model.model_id,
                        variance: Some(EvalVariance {
                            suite_id: model.variance.suite_id,
                            config_ref: model.variance.config_ref,
                            run_count: model.variance.run_count,
                            mean_score: model.variance.mean_score,
                            std_dev: model.variance.std_dev,
                            min_score: model.variance.min_score,
                            max_score: model.variance.max_score,
                            cases: model
                                .variance
                                .cases
                                .into_iter()
                                .map(|case| EvalVarianceCase {
                                    case_id: case.case_id,
                                    run_count: case.run_count,
                                    pass_rate: case.pass_rate,
                                    mean_score: case.mean_score,
                                    min_score: case.min_score,
                                    max_score: case.max_score,
                                    std_dev: case.std_dev,
                                })
                                .collect(),
                        }),
                    })
                    .collect(),
            }),
        }))
    }

    async fn evolve_suggest(
        &self,
        r: Request<EvolveSuggestRequest>,
    ) -> Result<Response<EvolveSuggestResponse>, Status> {
        let request_id = r.into_inner().request_id;
        let task = self
            .evolve_task(&request_id)
            .ok_or(Status::not_found("task not found"))?;
        let tasks = self.evolve_tasks();
        let namespace_tasks: Vec<_> = tasks
            .into_iter()
            .filter(|candidate| candidate.namespace == task.namespace)
            .collect();
        let patterns = crate::chisei::evolve::mine_patterns(&namespace_tasks);
        let suggestions = crate::chisei::evolve::suggest(&task, &patterns);
        Ok(Response::new(EvolveSuggestResponse {
            suggestions: suggestions
                .into_iter()
                .map(|suggestion| EvolveSuggestion {
                    message: suggestion.message,
                    confidence: suggestion.confidence,
                    category: suggestion.category,
                })
                .collect(),
        }))
    }

    async fn evolve_enhance(
        &self,
        req: Request<EvolveEnhanceRequest>,
    ) -> Result<Response<EvolveEnhanceResponse>, Status> {
        let r = req.into_inner();
        let tasks = self.evolve_tasks();
        let patterns = self
            .evolve_task(&r.request_id)
            .map(|task| {
                tasks
                    .into_iter()
                    .filter(|candidate| candidate.namespace == task.namespace)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| self.evolve_tasks());
        let mined_patterns = crate::chisei::evolve::mine_patterns(&patterns);
        let (enhanced, modified) = crate::chisei::evolve::enhance_spec(&r.spec, &mined_patterns);
        if modified && !r.request_id.is_empty() {
            self.evolve_enhancements
                .lock()
                .expect("evolve enhancements poisoned")
                .insert(r.request_id.clone(), r.spec.clone());
            self.db
                .put_evolve_enhancement(&r.request_id, &r.spec)
                .map_err(Status::internal)?;
        }
        Ok(Response::new(EvolveEnhanceResponse {
            enhanced_spec: enhanced,
            modified,
        }))
    }

    async fn evolve_recommend(
        &self,
        req: Request<EvolveRecommendRequest>,
    ) -> Result<Response<EvolveRecommendResponse>, Status> {
        let task = self
            .evolve_task(&req.into_inner().request_id)
            .ok_or(Status::not_found("task not found"))?;
        let recommendation = crate::chisei::evolve::recommend(&task).ok_or(
            Status::failed_precondition("task does not need a recommendation"),
        )?;
        Ok(Response::new(EvolveRecommendResponse {
            recommendation: Some(EvolveRecommendation {
                action: recommendation.action,
                reason: recommendation.reason,
            }),
        }))
    }

    async fn evolve_report(
        &self,
        _r: Request<EvolveReportRequest>,
    ) -> Result<Response<EvolveReportResponse>, Status> {
        let summary = crate::chisei::evolve::report(&self.evolve_tasks());
        Ok(Response::new(EvolveReportResponse {
            report: Some(EvolveReport {
                total_tasks: summary.total_tasks,
                succeeded: summary.succeeded,
                failed: summary.failed,
                success_rate: summary.success_rate,
                patterns: summary
                    .patterns
                    .into_iter()
                    .map(|pattern| EvolvePattern {
                        pattern: pattern.pattern,
                        occurrences: pattern.occurrences,
                        success_rate: pattern.success_rate,
                        category: pattern.category,
                    })
                    .collect(),
            }),
        }))
    }

    async fn evolve_patterns(
        &self,
        _r: Request<EvolvePatternsRequest>,
    ) -> Result<Response<EvolvePatternsResponse>, Status> {
        let patterns = crate::chisei::evolve::mine_patterns(&self.evolve_tasks());
        Ok(Response::new(EvolvePatternsResponse {
            patterns: patterns
                .into_iter()
                .map(|pattern| EvolvePattern {
                    pattern: pattern.pattern,
                    occurrences: pattern.occurrences,
                    success_rate: pattern.success_rate,
                    category: pattern.category,
                })
                .collect(),
        }))
    }

    async fn evolve_variance(
        &self,
        _r: Request<EvolveVarianceRequest>,
    ) -> Result<Response<EvolveVarianceResponse>, Status> {
        let report = crate::chisei::evolve::analyze_variance(
            &self.evolve_tasks(),
            chrono::Utc::now().timestamp(),
        );
        Ok(Response::new(EvolveVarianceResponse {
            report: Some(EvolveVarianceReport {
                patterns: report
                    .patterns
                    .into_iter()
                    .map(|pattern| EvolvePatternVariance {
                        pattern: pattern.pattern,
                        sample_size: pattern.sample_size,
                        mean_success_rate: pattern.mean_success_rate,
                        std_dev: pattern.std_dev,
                        ci_95_lower: pattern.ci_95_lower,
                        ci_95_upper: pattern.ci_95_upper,
                        risk_flag: pattern.risk_flag,
                        trend: pattern.trend,
                        windows: pattern
                            .windows
                            .into_iter()
                            .map(|window| EvolveVarianceWindow {
                                window: window.window,
                                total: window.total,
                                succeeded: window.succeeded,
                                success_rate: window.success_rate,
                            })
                            .collect(),
                    })
                    .collect(),
                insights: report.insights,
            }),
        }))
    }

    async fn evolve_ab_results(
        &self,
        _r: Request<EvolveAbResultsRequest>,
    ) -> Result<Response<EvolveAbResultsResponse>, Status> {
        let report = crate::chisei::evolve::compute_ab_results(&self.evolve_tasks());
        Ok(Response::new(EvolveAbResultsResponse {
            report: Some(EvolveAbReport {
                enhanced: Some(EvolveAbGroup {
                    total: report.enhanced.total,
                    succeeded: report.enhanced.succeeded,
                    success_rate: report.enhanced.success_rate,
                }),
                non_enhanced: Some(EvolveAbGroup {
                    total: report.non_enhanced.total,
                    succeeded: report.non_enhanced.succeeded,
                    success_rate: report.non_enhanced.success_rate,
                }),
            }),
        }))
    }

    async fn evolve_templates(
        &self,
        _r: Request<EvolveTemplatesRequest>,
    ) -> Result<Response<EvolveTemplatesResponse>, Status> {
        let templates = crate::chisei::evolve::generate_templates(&self.evolve_tasks());
        Ok(Response::new(EvolveTemplatesResponse {
            templates: templates
                .into_iter()
                .map(|template| EvolveTemplate {
                    id: template.name.clone(),
                    name: template.name,
                    content: template.content,
                    created: chrono::Utc::now().timestamp(),
                })
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use std::fs;
    use std::sync::Arc;

    #[test]
    fn receipt_hash_preserves_part_boundaries() {
        assert_ne!(
            content_hash([b"a\0b".as_slice()]),
            content_hash([b"a".as_slice(), b"b".as_slice()])
        );
    }

    #[test]
    fn native_cost_uses_gateway_pricing_alias_resolution() {
        let plan = ExecutionPlan {
            resolved_model: "openai/gpt-5.5".into(),
            ..Default::default()
        };
        let response = PlannedChatResponse {
            input_tokens: 100,
            output_tokens: 10,
            ..Default::default()
        };
        let pricing = crate::gateway::parse_pricing_table("gpt-5.5=3:15").unwrap();
        assert_eq!(native_execution_cost(&plan, &response, &pricing), Some(450));
    }

    #[test]
    fn response_artifact_hash_covers_tool_calls() {
        let response = |name: &str| PlannedChatResponse {
            content: String::new(),
            tool_calls: vec![ToolCall {
                id: "call-1".into(),
                name: name.into(),
                args_json: r#"{"value":1}"#.into(),
            }],
            input_tokens: 1,
            output_tokens: 1,
            stop_reason: "tool_use".into(),
            provider: "native".into(),
        };
        assert_ne!(
            planned_response_hash(&response("read")),
            planned_response_hash(&response("write"))
        );
    }

    #[test]
    fn cheap_route_bias_only_for_bulk_classes_and_not_when_regressed() {
        // Explicit bulk classes route to the cheaper tier.
        for class in [
            "background",
            "bulk",
            "batch",
            "small_fast",
            "small-fast",
            "Background",
        ] {
            assert_eq!(cheap_route_bias(class, false), Some("cheap"), "{class}");
        }
        // Primary/unknown/empty never route cheap (fail safe to capable).
        for class in ["primary", "reasoning", "", "unknown"] {
            assert_eq!(cheap_route_bias(class, false), None, "{class}");
        }
        // An active eval regression reverts every class to the capable tier.
        assert_eq!(cheap_route_bias("background", true), None);
        assert_eq!(cheap_route_bias("bulk", true), None);
    }

    #[test]
    fn portfolio_cross_provider_runtime_requires_explicit_policy_allowance() {
        let mut policy = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["anthropic".into()],
            allowed_models: vec!["claude-sonnet-4-20250514".into(), "gpt-5.5".into()],
            default_runtime: "anthropic".into(),
            default_model: "claude-sonnet-4-20250514".into(),
            data_class: String::new(),
        };
        assert_eq!(
            portfolio_runtime_for_model(Some(&policy), "anthropic", "gpt-5.5"),
            None
        );
        assert!(final_runtime_for_model(Some(&policy), "anthropic", "openai/gpt-5.5").is_err());
        policy.allowed_runtimes.push("openai".into());
        assert_eq!(
            portfolio_runtime_for_model(Some(&policy), "anthropic", "gpt-5.5"),
            Some("openai".into())
        );
        assert_eq!(
            final_runtime_for_model(Some(&policy), "anthropic", "openai/gpt-5.5").unwrap(),
            "openai"
        );
        policy.allowed_runtimes.clear();
        assert_eq!(
            portfolio_runtime_for_model(Some(&policy), "anthropic", "gpt-5.5"),
            Some("openai".into())
        );
    }

    #[test]
    fn final_runtime_tracks_live_model_provider() {
        let policy = crate::chisei::policy::Policy {
            allowed_runtimes: vec![
                "openai".into(),
                "anthropic".into(),
                "native".into(),
                "ollama".into(),
            ],
            allowed_models: vec!["gpt-5.5".into(), "claude-sonnet-4".into()],
            default_runtime: String::new(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        };

        assert_eq!(
            final_runtime_for_model(Some(&policy), "openai", "anthropic/claude-sonnet-4").unwrap(),
            "anthropic"
        );
        assert_eq!(
            final_runtime_for_model(Some(&policy), "anthropic", "openai/gpt-5.5").unwrap(),
            "openai"
        );
        assert_eq!(
            final_runtime_for_model(Some(&policy), "kiro", "native/native-default").unwrap(),
            "native"
        );
        assert_eq!(
            final_runtime_for_model(Some(&policy), "kiro", "ollama/qwen:14b").unwrap(),
            "ollama"
        );
        assert_eq!(
            final_runtime_for_model(Some(&policy), "kiro", "gpt-5.5").unwrap(),
            "openai"
        );
        assert!(final_runtime_for_model(Some(&policy), "kiro", "kiro/claude-sonnet-4").is_err());
    }

    #[test]
    fn policy_validation_handles_empty_and_opaque_runtimes() {
        let invalid_implicit = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: String::new(),
            default_model: "native-default".into(),
            data_class: String::new(),
        };
        assert!(validate_policy_provider_pairs(&invalid_implicit).is_err());

        let opaque = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["kiro".into()],
            allowed_models: vec!["kiro/private-model".into()],
            default_runtime: "kiro".into(),
            default_model: "kiro/private-model".into(),
            data_class: String::new(),
        };
        assert!(validate_policy_provider_pairs(&opaque).is_err());
        let unknown_runtime = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["bogus".into()],
            allowed_models: vec![],
            default_runtime: "bogus".into(),
            default_model: String::new(),
            data_class: String::new(),
        };
        assert!(validate_explicit_requested_model("bogus/model").is_err());
        assert!(validate_policy_provider_pairs(&unknown_runtime).is_err());

        let mut disallowed_opaque = opaque;
        disallowed_opaque.allowed_runtimes = vec!["openai".into()];
        assert!(validate_policy_provider_pairs(&disallowed_opaque).is_err());
        disallowed_opaque.default_model.clear();
        assert!(validate_policy_provider_pairs(&disallowed_opaque).is_err());

        let unroutable_allowlist = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["kiro".into()],
            allowed_models: vec!["gpt-5.5".into()],
            default_runtime: "kiro".into(),
            default_model: String::new(),
            data_class: String::new(),
        };
        assert!(validate_policy_provider_pairs(&unroutable_allowlist).is_err());

        let default_outside_allowlist = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["gpt-5.5-mini".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        };
        assert!(validate_policy_provider_pairs(&default_outside_allowlist).is_err());

        let canonical_alias = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["openai/gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        };
        assert_eq!(validate_policy_provider_pairs(&canonical_alias), Ok(()));

        let hosted = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["xai".into()],
            allowed_models: vec!["xai/grok-4.5".into()],
            default_runtime: "xai".into(),
            default_model: "xai/grok-4.5".into(),
            data_class: String::new(),
        };
        assert_eq!(validate_policy_provider_pairs(&hosted), Ok(()));
    }

    #[test]
    fn legacy_openai_family_policies_normalize_to_exact_providers() {
        let normalized = normalize_legacy_policy_provider_pairs(crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec![
                "gpt-5.5".into(),
                "native-default".into(),
                "fallback:cheap".into(),
                "ollama/qwen:14b".into(),
            ],
            default_runtime: "openai".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        });

        assert_eq!(normalized.default_runtime, "native");
        assert!(normalized.allowed_runtimes.contains(&"openai".to_string()));
        assert!(normalized.allowed_runtimes.contains(&"native".to_string()));
        assert!(normalized.allowed_runtimes.contains(&"ollama".to_string()));
        assert_eq!(validate_policy_provider_pairs(&normalized), Ok(()));

        let fallback = normalize_legacy_policy_provider_pairs(crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["fallback:cheap".into()],
            default_runtime: "openai".into(),
            default_model: "fallback:cheap".into(),
            data_class: String::new(),
        });
        assert_eq!(fallback.default_runtime, "native");
        assert!(fallback.allowed_runtimes.contains(&"native".to_string()));
        assert_eq!(validate_policy_provider_pairs(&fallback), Ok(()));

        let kiro = normalize_legacy_policy_provider_pairs(crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["kiro".into()],
            default_runtime: "openai".into(),
            default_model: "kiro".into(),
            data_class: String::new(),
        });
        assert_eq!(kiro.default_runtime, "openai");
        assert_eq!(kiro.allowed_runtimes, vec!["openai"]);
        assert!(validate_policy_provider_pairs(&kiro).is_err());

        let mixed = normalize_legacy_policy_provider_pairs(crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["fallback:cheap".into(), "Kiro".into()],
            default_runtime: "openai".into(),
            default_model: "fallback:cheap".into(),
            data_class: String::new(),
        });
        assert!(mixed.allowed_runtimes.contains(&"native".to_string()));
        assert!(validate_policy_provider_pairs(&mixed).is_err());
    }

    #[test]
    fn persisted_bare_native_models_are_canonicalized_without_accepting_kiro() {
        let migrated = normalize_persisted_legacy_policy(crate::chisei::policy::Policy {
            allowed_runtimes: vec!["kiro".into()],
            allowed_models: vec!["mistral".into(), "Kiro".into()],
            default_runtime: "kiro".into(),
            default_model: "mistral".into(),
            data_class: String::new(),
        });

        assert_eq!(migrated.default_runtime, "native");
        assert_eq!(migrated.default_model, "native/mistral");
        assert!(migrated.allowed_models.contains(&"native/mistral".into()));
        assert!(migrated.allowed_models.contains(&"Kiro".into()));
        assert!(validate_policy_provider_pairs(&migrated).is_err());

        let model_only = normalize_persisted_legacy_policy(crate::chisei::policy::Policy {
            allowed_runtimes: vec![],
            allowed_models: vec!["mistral".into()],
            default_runtime: String::new(),
            default_model: "mistral".into(),
            data_class: String::new(),
        });
        assert_eq!(model_only.default_model, "native/mistral");
        assert_eq!(model_only.allowed_models, vec!["native/mistral"]);
        assert_eq!(validate_policy_provider_pairs(&model_only), Ok(()));

        let openai = normalize_persisted_legacy_policy(crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["mistral-large".into()],
            default_runtime: "openai".into(),
            default_model: "mistral-large".into(),
            data_class: String::new(),
        });
        assert_eq!(openai.default_model, "openai/mistral-large");
        assert_eq!(openai.allowed_models, vec!["openai/mistral-large"]);
        assert_eq!(validate_policy_provider_pairs(&openai), Ok(()));

        let duplicate_openai = normalize_persisted_legacy_policy(crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into(), "openai".into()],
            allowed_models: vec!["mistral-large".into()],
            default_runtime: String::new(),
            default_model: "mistral-large".into(),
            data_class: String::new(),
        });
        assert_eq!(duplicate_openai.default_model, "openai/mistral-large");
        assert_eq!(
            duplicate_openai.allowed_models,
            vec!["openai/mistral-large"]
        );
        assert_eq!(duplicate_openai.allowed_runtimes, vec!["openai"]);
        assert_eq!(validate_policy_provider_pairs(&duplicate_openai), Ok(()));
    }

    #[test]
    fn budget_metric_accepts_tokens_and_requests_case_insensitive() {
        assert_eq!(budget_metric("").unwrap(), METRIC_TOKENS);
        assert_eq!(budget_metric("tokens").unwrap(), METRIC_TOKENS);
        assert_eq!(budget_metric("Tokens").unwrap(), METRIC_TOKENS);
        assert_eq!(budget_metric("requests").unwrap(), METRIC_REQUESTS);
        assert_eq!(budget_metric("REQUESTS").unwrap(), METRIC_REQUESTS);
    }

    #[test]
    fn budget_metric_rejects_unknown_values() {
        let err = budget_metric("characters").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message()
                .contains("unsupported budget metric; use tokens or requests")
        );
    }

    #[test]
    fn local_free_runtime_is_allowed_without_policy_and_respects_explicit_policy() {
        assert_eq!(
            local_free_runtime_for_model(None, "ollama/qwen:14b"),
            Some("ollama".to_string())
        );
        assert_eq!(local_free_runtime_for_model(None, "gpt-5.5"), None);
        let cloud_only = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec![],
            default_runtime: "openai".into(),
            default_model: "gpt-5.5".into(),
            data_class: String::new(),
        };
        assert_eq!(
            local_free_runtime_for_model(Some(&cloud_only), "ollama/qwen:14b"),
            None
        );
    }

    #[tokio::test]
    async fn resolve_policy_rejects_unknown_explicit_provider_without_policy() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let svc = ChiseiServiceImpl::new(db, config(":memory:"));
        let request = resolve_policy_request("unscoped", "bogus", "bogus/model");

        let error = svc.resolve_policy(Request::new(request)).await.unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("unknown provider namespace"));

        svc.policy.set_namespace_policy(
            "unscoped",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: String::new(),
                default_model: String::new(),
                data_class: String::new(),
            },
        );
        let request = resolve_policy_request("unscoped", "bogus", "bogus/model");
        let error = svc.resolve_policy(Request::new(request)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("unknown provider namespace"));
    }

    #[tokio::test]
    async fn resolve_policy_keeps_auto_provider_compatible_without_policy() {
        let svc = memory_service();

        let resolution = svc
            .resolve_policy(Request::new(resolve_policy_request(
                "unscoped", "openai", "auto",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolution.runtime, "openai");
        assert_eq!(resolution.model, "openai/gpt-5.5");
    }

    #[tokio::test]
    async fn resolve_policy_refreshes_registry_before_policy_validation() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-chisei-provider-registry-{}",
            uuid::Uuid::new_v4()
        ));
        let db_path = directory.join("sekai.db");
        let db_path = db_path.to_str().expect("temporary database path is UTF-8");
        let registry_path = crate::provider_profile::provider_registry_state_path(db_path);
        crate::provider_profile::refresh_provider_registry(&registry_path).unwrap();
        let svc = file_service(db_path);
        std::fs::remove_file(&registry_path).unwrap();

        let error = svc
            .resolve_policy(Request::new(resolve_policy_request(
                "unscoped",
                "bogus",
                "bogus/model",
            )))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(error.message().contains("provider registry unavailable"));
        drop(svc);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn live_model_resolution_rejects_unknown_explicit_provider() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let svc = ChiseiServiceImpl::new(db, config(":memory:"));

        let error = svc
            .resolve_live_model(
                "bogus/model",
                None,
                None,
                false,
                &std::collections::HashSet::new(),
            )
            .await
            .unwrap_err();

        assert!(error.contains("unknown provider namespace"));
    }

    #[tokio::test]
    async fn resolve_policy_normalizes_loaded_legacy_native_runtime() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let svc = ChiseiServiceImpl::new(db, config(":memory:"));
        svc.policy.set_namespace_policy(
            "private",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["kiro".into()],
                allowed_models: vec!["native-default".into()],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: String::new(),
            },
        );
        let request = resolve_policy_request("private", "kiro", "native-default");

        let resolution = svc
            .resolve_policy(Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolution.runtime, "native");
        assert_eq!(resolution.model, "native-default");

        let request = resolve_policy_request("private", "native", "native/native-default");
        let resolution = svc
            .resolve_policy(Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.runtime, "native");
        assert_eq!(resolution.model, "native/native-default");
    }

    #[tokio::test]
    async fn resolve_policy_routes_bulk_task_class_to_cheaper_model() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        // Treat openai as available without a key so routing can resolve.
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );

        // Primary work stays on the capable default model, no bias.
        let mut primary = resolve_policy_request("proj", "openai", "gpt-5.5");
        primary.task_class = "primary".into();
        let resolution = svc
            .resolve_policy(Request::new(primary))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.model, "gpt-5.5");
        assert_eq!(resolution.route_bias, "");

        // Bulk/background work routes to the cheaper allowed model and records
        // the cheap bias.
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
        background.task_class = "background".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.model, "gpt-5.5-mini");
        assert_eq!(resolution.route_bias, "cheap");
        assert_eq!(resolution.runtime, "openai");
    }

    #[tokio::test]
    async fn resolve_policy_reverts_only_the_regressed_task_class_to_capable() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );
        create_suite(&svc, "proj").await;
        for (id, score, timestamp) in [("class-run-1", 95, 100), ("class-run-2", 50, 200)] {
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(eval_run(id, "suite-1", score, timestamp)),
                changed_file: "proj".into(),
                diff_hash: id.into(),
            }))
            .await
            .unwrap();
        }
        assert!(
            svc.eval
                .namespace_regression_signal("proj")
                .unwrap()
                .regressed
        );
        let now = chrono::Utc::now().timestamp_millis();
        for (task_class, delta, regressed) in [("background", -80.0, true), ("bulk", 0.0, false)] {
            svc.db
                .record_decision(&crate::sekai::audit::Decision {
                    id: format!("class-signal-{task_class}"),
                    timestamp: now,
                    actor: "chisei.scoring".into(),
                    action: "task_class_signal".into(),
                    reason: format!("test signal for {task_class}"),
                    evidence: HashMap::from([
                        ("delta".into(), format!("{delta:.1}")),
                        ("regressed".into(), regressed.to_string()),
                    ]),
                    target_id: serde_json::to_string(&("proj", task_class)).unwrap(),
                    outcome: if regressed {
                        "regressed".into()
                    } else {
                        "stable".into()
                    },
                })
                .unwrap();
        }
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
        background.task_class = "background".into();
        let reverted = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(reverted.model, "gpt-5.5");
        assert_eq!(reverted.route_bias, "");
        assert!(reverted.eval_regressed);
        assert!(reverted.eval_regression_reason.contains("background"));

        let mut invalid = resolve_policy_request("proj", "openai", "bad model");
        invalid.task_class = "background".into();
        let error = svc.resolve_policy(Request::new(invalid)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);

        let mut bulk = resolve_policy_request("proj", "openai", "gpt-5.5");
        bulk.task_class = "bulk".into();
        let healthy = svc
            .resolve_policy(Request::new(bulk))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(healthy.model, "gpt-5.5-mini");
        assert_eq!(healthy.route_bias, "cheap");
        assert!(!healthy.eval_regressed);
    }

    #[tokio::test]
    async fn request_namespace_regression_is_not_masked_by_stable_policy_scope() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        svc.policy.set_namespace_policy(
            "project-scope",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );
        let now = chrono::Utc::now().timestamp_millis();
        for (scope, delta, regressed) in
            [("project-scope", 0.0, false), ("request-ns", -80.0, true)]
        {
            svc.db
                .record_decision(&crate::sekai::audit::Decision {
                    id: format!("class-signal-{scope}"),
                    timestamp: now,
                    actor: "chisei.scoring".into(),
                    action: "task_class_signal".into(),
                    reason: format!("test signal for {scope}"),
                    evidence: HashMap::from([
                        ("delta".into(), format!("{delta:.1}")),
                        ("regressed".into(), regressed.to_string()),
                    ]),
                    target_id: serde_json::to_string(&(scope, "background")).unwrap(),
                    outcome: if regressed {
                        "regressed".into()
                    } else {
                        "stable".into()
                    },
                })
                .unwrap();
        }

        let mut request = resolve_policy_request("request-ns", "openai", "gpt-5.5");
        request.project = "project-scope".into();
        request.task_class = "background".into();
        let resolved = svc
            .resolve_policy(Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolved.model, "gpt-5.5");
        assert_eq!(resolved.route_bias, "");
        assert!(resolved.eval_regressed);
        assert!(resolved.eval_regression_reason.contains("request-ns"));
    }

    #[tokio::test]
    async fn resolve_policy_respects_a_promoted_capable_override() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );

        // Promote a "capable" revert for (proj, background) directly through the service's own
        // candidate store/active-promotions registry, exactly as a promotion controller would.
        let candidate = crate::chisei::promotion::Candidate {
            id: "candidate-1".into(),
            kind: crate::chisei::promotion::KIND_ROUTING_BIAS.to_string(),
            namespace: "proj".into(),
            task_class: "background".into(),
            payload: serde_json::to_string(&crate::chisei::promotion::RoutingBiasPayload {
                bias: "capable".into(),
            })
            .unwrap(),
            rationale: "test".into(),
            status: crate::chisei::promotion::STATUS_GATE_PASSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        svc.candidate_store().upsert(candidate.clone());
        crate::chisei::controller::promote_candidate(
            &svc.candidate_store(),
            &svc.active_promotions(),
            &svc.db,
            &candidate.id,
        )
        .expect("gate_passed candidate should promote");

        // Without the override, background would route to the cheaper model (as the sibling test
        // above confirms); the active "capable" promotion must force the capable model instead.
        // Non-canonical casing/whitespace on the request's task_class must still hit the
        // (normalized) override - `cheap_route_bias` normalizes internally, so an unnormalized
        // lookup here would otherwise miss the override and route cheap right past it.
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
        background.task_class = " Background ".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.model, "gpt-5.5");
        assert_eq!(resolution.route_bias, "");

        let mut local_free = resolve_policy_request("proj", "openai", "gpt-5.5");
        local_free.task_class = "background".into();
        local_free.budget_route_bias = "local_free".into();
        let error = svc
            .resolve_policy(Request::new(local_free))
            .await
            .expect_err("capable override must block local-free degradation");
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert!(error.message().contains("active capable-tier override"));
    }

    #[tokio::test]
    async fn resolve_policy_records_no_bias_when_no_cheaper_model_exists() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        // Only one allowed model, so the cheap tier resolves to the same model.
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            },
        );
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5");
        background.task_class = "background".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        // No actual demotion happened, so no cheap bias is recorded.
        assert_eq!(resolution.model, "gpt-5.5");
        assert_eq!(resolution.route_bias, "");
    }

    #[tokio::test]
    async fn resolve_policy_records_no_bias_for_equal_cost_models() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        // Both allowed models are the same cost tier ("mini"), so the cheap
        // alias finds nothing strictly cheaper than the capable default.
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5-mini".into(), "gpt-4.1-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5-mini".into(),
                data_class: String::new(),
            },
        );
        let mut background = resolve_policy_request("proj", "openai", "gpt-5.5-mini");
        background.task_class = "background".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        // Capable default is kept; no equal-cost swap is recorded as a demotion.
        assert_eq!(resolution.model, "gpt-5.5-mini");
        assert_eq!(resolution.route_bias, "");
    }

    #[tokio::test]
    async fn resolve_policy_skips_cheap_routing_for_native_runtime() {
        // native/ollama runtimes are excluded from automatic cheap tiering
        // (their cost tiers are not name-rankable), so a bulk task class stays
        // on the capable tier with no bias even without an eval regression.
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "proj",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["native".into()],
                allowed_models: vec!["native-default".into(), "native-cheap".into()],
                default_runtime: "native".into(),
                default_model: "native-default".into(),
                data_class: String::new(),
            },
        );
        let mut background = resolve_policy_request("proj", "native", "native-default");
        background.task_class = "background".into();
        let resolution = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolution.model, "native-default");
        assert_eq!(resolution.route_bias, "");
    }

    fn config(db_path: &str) -> Config {
        Config {
            grpc_port: 0,
            sekai_bind: None,
            ops_port: None,
            ops_bind: "127.0.0.1".into(),
            sekai_socket: None,
            db_path: db_path.to_string(),
            anthropic_api_key: None,
            openai_api_key: None,
            ollama_url: "http://127.0.0.1:11434".into(),
            native_llm_url: Some("http://127.0.0.1:9999".into()),
            auth_token: None,
            sample_rate: 0.0,
            sample_risk_threshold: 0.7,
            scoring_enabled: false,
            scoring_interval_secs: 60,
            scoring_model: "claude-opus-4-8".into(),
            scoring_batch_size: 16,
            default_data_class: "unclassified".into(),
            safe_egress_providers: vec![],
            gateway_provided_providers: vec![],
            gateway_receipt_principals: vec![],
            leak_review_model: None,
            tls_cert: None,
            tls_key: None,
            allow_plaintext: false,
            insecure: false,
        }
    }

    fn memory_service() -> ChiseiServiceImpl {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        ChiseiServiceImpl::new(db, config(":memory:"))
    }

    fn file_service(path: &str) -> ChiseiServiceImpl {
        let db = Arc::new(SekaiDb::new(path).unwrap());
        ChiseiServiceImpl::new(db, config(path))
    }

    #[tokio::test]
    async fn portfolio_rpcs_persist_frontier_and_allocate_objective() {
        let svc = memory_service();
        for (model, quality, cost) in [("small", 80.0, 10), ("large", 95.0, 30)] {
            svc.record_portfolio_observation(Request::new(RecordPortfolioObservationRequest {
                namespace: "acme".into(),
                task_class: "primary".into(),
                model: model.into(),
                quality_score: quality,
                cost_usd_micros: cost,
                sample_count: 5,
                updated_at: 1,
            }))
            .await
            .unwrap();
        }
        svc.set_portfolio_objective(Request::new(SetPortfolioObjectiveRequest {
            objective: Some(PortfolioObjective {
                namespace: "acme".into(),
                mode: "minimize_cost".into(),
                budget_usd_micros: 100,
                quality_bar: 90.0,
                min_samples: 3,
                updated_at: 1,
            }),
        }))
        .await
        .unwrap();

        let response = svc
            .allocate_portfolio(Request::new(AllocatePortfolioRequest {
                namespace: "acme".into(),
                demands: vec![PortfolioTaskDemand {
                    task_class: "primary".into(),
                    expected_calls: 2,
                    quality_bar: 0.0,
                    has_quality_bar: false,
                }],
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.allocations[0].model, "large");
        assert_eq!(response.total_cost_usd_micros, 60);
    }

    fn resolve_policy_request(
        namespace: &str,
        preferred_runtime: &str,
        preferred_model: &str,
    ) -> ResolvePolicyRequest {
        ResolvePolicyRequest {
            namespace: namespace.into(),
            preferred_runtime: preferred_runtime.into(),
            preferred_model: preferred_model.into(),
            subject: String::new(),
            project: String::new(),
            agent: String::new(),
            key_id: String::new(),
            task_class: String::new(),
            user_id: String::new(),
            expected_calls: 1,
            budget_route_bias: String::new(),
        }
    }

    async fn create_suite(svc: &ChiseiServiceImpl, namespace: &str) {
        svc.create_eval_suite(Request::new(CreateEvalSuiteRequest {
            suite: Some(EvalSuite {
                id: "suite-1".into(),
                name: "suite".into(),
                description: String::new(),
                cases: std::iter::once(EvalCase {
                    id: "case-1".into(),
                    name: "case".into(),
                    namespace: namespace.into(),
                    spec: "spec".into(),
                    assertions: vec![],
                })
                .chain((1..=MIN_EVIDENCE_CONTEXT_EVAL_CASES).map(|case| EvalCase {
                    id: format!("evidence-case-{case}"),
                    name: format!("evidence case {case}"),
                    namespace: namespace.into(),
                    spec: "compare decision quality with and without evidence".into(),
                    assertions: vec![],
                }))
                .collect(),
            }),
        }))
        .await
        .unwrap();
    }

    fn eval_run(id: &str, suite_id: &str, score: i32, timestamp: i64) -> EvalRun {
        EvalRun {
            id: id.into(),
            suite_id: suite_id.into(),
            config_ref: "native-default".into(),
            results: vec![CaseResult {
                case_id: "case-1".into(),
                passed: score >= 80,
                status: if score >= 80 { "done" } else { "failed" }.into(),
                result: "result".into(),
                score,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp,
        }
    }

    fn evidence_eval_run(
        id: &str,
        suite_id: &str,
        source_type: &str,
        evidence_type: &str,
        with_evidence: bool,
        score: i32,
        timestamp: i64,
    ) -> EvalRun {
        EvalRun {
            id: id.into(),
            suite_id: suite_id.into(),
            config_ref: evidence_context_config_ref(source_type, evidence_type, with_evidence),
            results: (1..=MIN_EVIDENCE_CONTEXT_EVAL_CASES)
                .map(|case| CaseResult {
                    case_id: format!("evidence-case-{case}"),
                    passed: score >= 80,
                    status: if score >= 80 { "done" } else { "failed" }.into(),
                    result: "result".into(),
                    score,
                    reason: String::new(),
                    elapsed: 10,
                })
                .collect(),
            timestamp,
        }
    }

    #[tokio::test]
    async fn evaluation_mutations_require_control_plane_administration() {
        let svc = memory_service();
        let mut suite_request = Request::new(CreateEvalSuiteRequest {
            suite: Some(EvalSuite {
                id: "forged-suite".into(),
                name: "forged".into(),
                description: String::new(),
                cases: vec![],
            }),
        });
        suite_request
            .metadata_mut()
            .insert("x-principal", "agent:untrusted".parse().unwrap());
        assert_eq!(
            svc.create_eval_suite(suite_request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );

        let mut run_request = Request::new(CreateEvalRunRequest {
            run: Some(eval_run("forged-run", "forged-suite", 100, 1)),
            changed_file: "context-expansion:pipeline-v1:acme".into(),
            diff_hash: "forged".into(),
        });
        run_request
            .metadata_mut()
            .insert("x-principal", "agent:untrusted".parse().unwrap());
        assert_eq!(
            svc.create_eval_run(run_request).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );

        let mut iteration_request = Request::new(TrackEvalIterationRequest {
            suite_id: "forged-suite".into(),
            run_id: "forged-run".into(),
            changed_file: "context-expansion:pipeline-v1:acme".into(),
            diff_hash: "forged".into(),
        });
        iteration_request
            .metadata_mut()
            .insert("x-principal", "agent:untrusted".parse().unwrap());
        assert_eq!(
            svc.track_eval_iteration(iteration_request)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    fn project_test_evidence(svc: &ChiseiServiceImpl) -> String {
        project_test_evidence_from_source(
            svc,
            "verification_system",
            "eval-primary",
            "producer:eval",
            "check-1",
            "eval-delivery-1",
        )
    }

    fn project_test_evidence_from_source(
        svc: &ChiseiServiceImpl,
        source_type: &str,
        source_instance: &str,
        producer_identity: &str,
        source_record_id: &str,
        idempotency_key: &str,
    ) -> String {
        use crate::sekai::evidence::{
            EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
            EvidenceSignal, EvidenceTarget, SchemaCompatibility,
        };
        use crate::sekai::evidence_store::{
            EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
        };

        svc.db
            .upsert_evidence_producer(
                &EvidenceProducerCapability {
                    producer_identity: producer_identity.into(),
                    config_version: 1,
                    source_types: vec![source_type.into()],
                    source_instances: vec![source_instance.into()],
                    namespaces: vec!["acme".into()],
                    evidence_types: vec!["verification.result".into()],
                    target_kinds: vec!["ticker".into()],
                    classification_ceiling: EvidenceClassification::Public,
                    allowed_intents: vec![EvidenceIntent::Upsert],
                    allow_operation_attachment: false,
                    replay_window_ms: 60_000,
                    max_clock_skew_ms: 1_000,
                    max_payload_bytes: 1_024,
                    max_relationships: 4,
                    rate_limit_per_minute: 20,
                    max_retained_submissions: 100_000,
                    revoked: false,
                },
                1,
            )
            .unwrap();
        svc.db
            .register_evidence_schema(
                &EvidenceSchemaDefinition {
                    schema_id: "verification.result".into(),
                    schema_version: "1.0.0".into(),
                    evidence_type: "verification.result".into(),
                    compatible_versions: vec![],
                },
                1,
            )
            .unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let content = serde_json::json!({"result": "passed"});
        let envelope = EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: source_type.into(),
            source_instance: source_instance.into(),
            source_record_id: source_record_id.into(),
            source_version: "attempt-1".into(),
            source_sequence: 1,
            target: EvidenceTarget {
                namespace: "acme".into(),
                object_external_id: "ticker:AAPL".into(),
                object_kind: "ticker".into(),
            },
            evidence_type: "verification.result".into(),
            signal: EvidenceSignal::Verification,
            schema_id: "verification.result".into(),
            schema_version: "1.0.0".into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: now - 1,
            collected_at_ms: now,
            expires_at_ms: Some(now + 60_000),
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: producer_identity.into(),
            confidence_bps: 9_500,
            classification: EvidenceClassification::Public,
            provenance: BTreeMap::new(),
            idempotency_key: idempotency_key.into(),
            intent: EvidenceIntent::Upsert,
            causality: None,
        };
        let admission = svc
            .db
            .submit_evidence(&envelope, producer_identity, now)
            .unwrap();
        svc.db
            .project_evidence_submission(&admission.submission.id, now)
            .unwrap();
        admission.submission.id
    }

    #[tokio::test]
    async fn run_pipeline_audits_and_applies_the_context_expansion_gate() {
        let svc = memory_service();
        svc.db
            .create_object(&Object {
                id: "ticker-aapl".into(),
                kind: "ticker".into(),
                name: "AAPL".into(),
                namespace: "acme".into(),
                external_id: "ticker:AAPL".into(),
                properties: HashMap::from([
                    ("score".into(), "0.82".into()),
                    (
                        crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                        "score".into(),
                    ),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_object(&Object {
                id: "analysis-aapl".into(),
                kind: "analysis".into(),
                name: "AAPL analysis".into(),
                namespace: "acme".into(),
                external_id: "analysis:AAPL".into(),
                properties: HashMap::from([
                    ("verdict".into(), "validate the filing date".into()),
                    (
                        crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                        "verdict".into(),
                    ),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_link(&crate::domain::Link {
                id: "analysis-touches-aapl".into(),
                from_id: "analysis-aapl".into(),
                to_id: "ticker-aapl".into(),
                relation: crate::domain::REL_TOUCHES.into(),
                created: 1,
            })
            .unwrap();
        let evidence_submission_id = project_test_evidence(&svc);

        let request = |id: &str| RunPipelineRequest {
            request: Some(PipelineRequest {
                request_id: id.into(),
                namespace: "acme".into(),
                spec: "inspect ticker:AAPL".into(),
                model: String::new(),
                runtime: String::new(),
                task_type: String::new(),
                priority: 0,
                task_class: String::new(),
            }),
        };
        let denied = svc
            .run_pipeline(Request::new(request("before-eval")))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(denied.prepared_spec.contains("score: 0.82"));
        assert!(!denied.prepared_spec.contains("validate the filing date"));
        assert!(denied.evidence_references.is_empty());

        create_suite(&svc, "acme").await;
        let profile = pipeline_context_expansion_profile_key("acme");
        for (id, score, timestamp) in [("context-base", 90, 1), ("context-pass", 95, 2)] {
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(eval_run(id, "suite-1", score, timestamp)),
                changed_file: profile.clone(),
                diff_hash: format!("hash-{id}"),
            }))
            .await
            .unwrap();
        }
        let allowed = svc
            .run_pipeline(Request::new(request("after-eval")))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(allowed.prepared_spec.contains("validate the filing date"));
        assert!(allowed.evidence_references.is_empty());
        assert!(!allowed.prepared_spec.contains("result=passed"));

        let class_profile =
            evidence_context_profile_key("acme", "verification_system", "verification.result");
        for (id, with_evidence, score, timestamp) in [
            ("evidence-base", false, 90, 3),
            ("evidence-pass", true, 95, 4),
        ] {
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(evidence_eval_run(
                    id,
                    "suite-1",
                    "verification_system",
                    "verification.result",
                    with_evidence,
                    score,
                    timestamp,
                )),
                changed_file: class_profile.clone(),
                diff_hash: format!("hash-{id}"),
            }))
            .await
            .unwrap();
        }
        let class_gate = svc
            .get_evidence_context_gate(Request::new(GetEvidenceContextGateRequest {
                namespace: "acme".into(),
                source_type: "verification_system".into(),
                evidence_type: "verification.result".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .gate
            .unwrap();
        assert!(class_gate.allowed);
        assert_eq!(class_gate.verdict, "pass");
        assert_eq!(class_gate.profile_key, class_profile);
        assert_eq!(
            class_gate.expected_baseline_config_ref,
            evidence_context_config_ref("verification_system", "verification.result", false)
        );

        let invalid_profile = evidence_context_profile_key(
            "acme",
            "verification_system",
            "operations.health_snapshot",
        );
        for (id, score, timestamp) in [("invalid-base", 90, 5), ("invalid-pass", 95, 6)] {
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(eval_run(id, "suite-1", score, timestamp)),
                changed_file: invalid_profile.clone(),
                diff_hash: format!("hash-{id}"),
            }))
            .await
            .unwrap();
        }
        let invalid_gate = svc
            .get_evidence_context_gate(Request::new(GetEvidenceContextGateRequest {
                namespace: "acme".into(),
                source_type: "verification_system".into(),
                evidence_type: "operations.health_snapshot".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .gate
            .unwrap();
        assert!(!invalid_gate.allowed);
        assert_eq!(invalid_gate.verdict, "invalid_comparison");

        let evidence_allowed = svc
            .run_pipeline(Request::new(request("after-evidence-eval")))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(evidence_allowed.prepared_spec.contains("result=passed"));
        assert_eq!(evidence_allowed.evidence_references.len(), 1);
        assert_eq!(
            evidence_allowed.evidence_references[0].submission_id,
            evidence_submission_id
        );

        let decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("chisei.context_expansion".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 3);
        assert!(decisions.iter().any(|decision| {
            decision.evidence["request_id"] == "before-eval"
                && decision.evidence["verdict"] == "missing"
                && decision.evidence["allowed"] == "false"
        }));
        let evidence_decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("chisei.evidence_context_admission".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(evidence_decisions.len(), 3);
        assert!(evidence_decisions.iter().any(|decision| {
            decision.evidence["request_id"] == "after-eval"
                && decision.evidence["verdict"] == "missing"
                && decision.evidence["allowed"] == "false"
                && decision.evidence["used_evidence_count"] == "0"
        }));
        assert!(evidence_decisions.iter().any(|decision| {
            decision.evidence["request_id"] == "after-evidence-eval"
                && decision.evidence["verdict"] == "pass"
                && decision.evidence["allowed"] == "true"
                && decision.evidence["used_evidence_count"] == "1"
        }));
        assert!(decisions.iter().any(|decision| {
            decision.evidence["request_id"] == "after-eval"
                && decision.evidence["verdict"] == "pass"
                && decision.evidence["allowed"] == "true"
                && decision.evidence["expanded_context_items"] != "0"
        }));
    }

    #[tokio::test]
    async fn evidence_context_gate_rejects_duplicate_case_results() {
        let svc = memory_service();
        create_suite(&svc, "acme").await;
        let evidence_type = "verification.result";
        let profile = evidence_context_profile_key("acme", "verification_system", evidence_type);
        let baseline = evidence_eval_run(
            "duplicate-base",
            "suite-1",
            "verification_system",
            evidence_type,
            false,
            90,
            1,
        );
        let mut candidate = evidence_eval_run(
            "duplicate-pass",
            "suite-1",
            "verification_system",
            evidence_type,
            true,
            95,
            2,
        );
        candidate.results.push(candidate.results[0].clone());
        for run in [baseline, candidate] {
            let id = run.id.clone();
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(run),
                changed_file: profile.clone(),
                diff_hash: format!("hash-{id}"),
            }))
            .await
            .unwrap();
        }

        let gate = svc.evidence_context_gate("acme", "verification_system", evidence_type, true);
        assert!(!gate.effective_allowed);
        assert_eq!(gate.gate.verdict, "invalid_comparison");
        assert!(gate.gate.reason.contains("duplicate"));
    }

    #[test]
    fn evidence_context_keys_do_not_alias_delimited_source_classes() {
        assert_ne!(
            evidence_context_profile_key("acme", "native:harness", "verification.result"),
            evidence_context_profile_key("acme", "native", "harness:verification.result")
        );
        assert_ne!(
            evidence_context_config_ref("native:harness", "verification.result", true),
            evidence_context_config_ref("native", "harness:verification.result", true)
        );
        assert_ne!(
            evidence_context_profile_key("x", "a:evidence:1:b", "c"),
            evidence_context_profile_key("x:evidence:14:a", "b", "c")
        );
    }

    #[tokio::test]
    async fn native_harness_evidence_requires_its_own_baseline_comparison() {
        let svc = memory_service();
        svc.db
            .create_object(&Object {
                id: "ticker-aapl".into(),
                kind: "ticker".into(),
                name: "AAPL".into(),
                namespace: "acme".into(),
                external_id: "ticker:AAPL".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        let verification_id = project_test_evidence(&svc);
        let native_id = project_test_evidence_from_source(
            &svc,
            "native_harness",
            "bugyo-tauri",
            "producer:bugyo",
            "bugyo-check-1",
            "bugyo-delivery-1",
        );
        create_suite(&svc, "acme").await;

        let context_profile = pipeline_context_expansion_profile_key("acme");
        for (id, score, timestamp) in [("context-base", 90, 1), ("context-pass", 95, 2)] {
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(eval_run(id, "suite-1", score, timestamp)),
                changed_file: context_profile.clone(),
                diff_hash: format!("hash-{id}"),
            }))
            .await
            .unwrap();
        }

        let verification_profile =
            evidence_context_profile_key("acme", "verification_system", "verification.result");
        for (id, with_evidence, score, timestamp) in [
            ("verification-base", false, 90, 3),
            ("verification-pass", true, 95, 4),
        ] {
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(evidence_eval_run(
                    id,
                    "suite-1",
                    "verification_system",
                    "verification.result",
                    with_evidence,
                    score,
                    timestamp,
                )),
                changed_file: verification_profile.clone(),
                diff_hash: format!("hash-{id}"),
            }))
            .await
            .unwrap();
        }

        let request = |request_id: &str| RunPipelineRequest {
            request: Some(PipelineRequest {
                request_id: request_id.into(),
                namespace: "acme".into(),
                spec: "inspect ticker:AAPL".into(),
                model: String::new(),
                runtime: String::new(),
                task_type: "analysis".into(),
                priority: 0,
                task_class: "analysis".into(),
            }),
        };
        let before_native_comparison = svc
            .run_pipeline(Request::new(request("before-native-comparison")))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(
            before_native_comparison
                .evidence_references
                .iter()
                .any(|reference| reference.submission_id == verification_id)
        );
        assert!(
            !before_native_comparison
                .evidence_references
                .iter()
                .any(|reference| reference.submission_id == native_id)
        );
        assert!(before_native_comparison.memory_references.is_empty());
        assert!(svc.portfolio.points("acme", "analysis").unwrap().is_empty());

        let native_profile =
            evidence_context_profile_key("acme", "native_harness", "verification.result");
        for (id, with_evidence, score, timestamp) in
            [("native-base", false, 90, 5), ("native-pass", true, 95, 6)]
        {
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(evidence_eval_run(
                    id,
                    "suite-1",
                    "native_harness",
                    "verification.result",
                    with_evidence,
                    score,
                    timestamp,
                )),
                changed_file: native_profile.clone(),
                diff_hash: format!("hash-{id}"),
            }))
            .await
            .unwrap();
        }
        let after_native_comparison = svc
            .run_pipeline(Request::new(request("after-native-comparison")))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert!(
            after_native_comparison
                .evidence_references
                .iter()
                .any(|reference| reference.submission_id == native_id)
        );
        assert!(after_native_comparison.memory_references.is_empty());
        assert!(svc.portfolio.points("acme", "analysis").unwrap().is_empty());
    }

    #[tokio::test]
    async fn record_usage_is_idempotent_for_replayed_keys() {
        let svc = memory_service();
        let request = RecordUsageRequest {
            user_id: "agent:codex-app".into(),
            tokens_used: 8,
            subject: String::new(),
            project: "sekai-chisei".into(),
            agent: "codex-app".into(),
            key_id: "codex-app".into(),
            work_unit: "wu-idempotent".into(),
            metric: String::new(),
            idempotency_key: "request-1:tokens".into(),
        };

        for _ in 0..2 {
            let response = svc
                .record_usage(Request::new(request.clone()))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.usage.unwrap().tokens_used, 8);
        }

        let response = svc
            .record_usage(Request::new(RecordUsageRequest {
                idempotency_key: "request-2:tokens".into(),
                ..request
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.usage.unwrap().tokens_used, 16);

        let mismatch = svc
            .record_usage(Request::new(RecordUsageRequest {
                user_id: "agent:other".into(),
                tokens_used: 1,
                idempotency_key: "request-1:tokens".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(mismatch.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn budget_rpcs_accept_gateway_subject_metadata() {
        let svc = memory_service();
        svc.set_budget_limit(Request::new(SetBudgetLimitRequest {
            user_id: String::new(),
            max_tokens: 10,
            period_type: "day".into(),
            subject: String::new(),
            project: "sekai-chisei".into(),
            agent: "codex-app".into(),
            key_id: "codex-app".into(),
            work_unit: String::new(),
            metric: String::new(),
        }))
        .await
        .unwrap();

        let allowed = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 5,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: String::new(),
                metric: String::new(),
                task_class: "background".into(),
                mid_task: false,
                local_free_available: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(allowed.allowed);
        assert_eq!(allowed.route_bias, "capable");
        assert_eq!(allowed.degradation_level, "capable");
        assert!(!allowed.warning);
        assert_eq!(
            allowed.usage.unwrap().user_id,
            "project:sekai-chisei/agent:codex-app"
        );

        svc.record_usage(Request::new(RecordUsageRequest {
            user_id: String::new(),
            tokens_used: 8,
            subject: String::new(),
            project: "sekai-chisei".into(),
            agent: "codex-app".into(),
            key_id: "codex-app".into(),
            work_unit: "wu-existing".into(),
            metric: String::new(),
            idempotency_key: "test-existing-usage".into(),
        }))
        .await
        .unwrap();

        let near_cap = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 1,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: String::new(),
                metric: String::new(),
                task_class: "background".into(),
                mid_task: false,
                local_free_available: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(near_cap.allowed);
        assert_eq!(near_cap.route_bias, "cheap");
        assert_eq!(near_cap.degradation_level, "cheap_cloud");
        assert!(near_cap.warning);

        let denied = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 3,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: String::new(),
                metric: String::new(),
                task_class: "background".into(),
                mid_task: false,
                local_free_available: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!denied.allowed);
        assert_eq!(denied.route_bias, "cheap");
        assert_eq!(denied.degradation_level, "hard_cap");
        assert!(denied.warning);

        let forged_continuation = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 3,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: "wu-new".into(),
                metric: String::new(),
                task_class: "reasoning".into(),
                mid_task: true,
                local_free_available: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!forged_continuation.allowed);
        assert_eq!(forged_continuation.degradation_level, "hard_cap");

        let reused_finished_id = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 3,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: "wu-existing".into(),
                metric: String::new(),
                task_class: "reasoning".into(),
                mid_task: true,
                local_free_available: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!reused_finished_id.allowed);
        assert_eq!(reused_finished_id.degradation_level, "hard_cap");

        let local_floor = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 3,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: String::new(),
                metric: String::new(),
                task_class: "background".into(),
                mid_task: false,
                local_free_available: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!local_floor.allowed);
        assert_eq!(local_floor.route_bias, "local_free");
        assert_eq!(local_floor.degradation_level, "local_free");
        assert!(local_floor.warning);

        let reasoning_has_no_cheap_local_floor = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 3,
                subject: String::new(),
                project: "sekai-chisei".into(),
                agent: "codex-app".into(),
                key_id: "codex-app".into(),
                work_unit: String::new(),
                metric: String::new(),
                task_class: "reasoning".into(),
                mid_task: false,
                local_free_available: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!reasoning_has_no_cheap_local_floor.allowed);
        assert_eq!(reasoning_has_no_cheap_local_floor.route_bias, "capable");
        assert_eq!(
            reasoning_has_no_cheap_local_floor.degradation_level,
            "hard_cap"
        );

        let now = chrono::Utc::now().timestamp_millis();
        svc.db
            .create_contention_scope(&crate::sekai::coordination::ContentionScope {
                id: "scope-budget-test".into(),
                name: "budget test".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: crate::sekai::coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: "codex-app".into(),
                created: now,
                updated: now,
            })
            .unwrap();
        svc.db
            .create_work_unit(&crate::sekai::coordination::WorkUnit {
                id: "wu-existing".into(),
                kind: "test".into(),
                actor: "codex-app".into(),
                target_object_id: String::new(),
                status: crate::sekai::coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "continue existing work".into(),
                scope_id: "scope-budget-test".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: now,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: "codex-app".into(),
                creator_principal: "codex-app".into(),
                idempotency_key: String::new(),
                updated_at: now,
            })
            .unwrap();
        assert!(
            svc.db
                .try_admit_work_unit("wu-existing", "codex-app", now)
                .unwrap()
                .admitted
        );
        let wrong_identity = svc
            .check_budget(Request::new(CheckBudgetRequest {
                user_id: String::new(),
                estimated_tokens: 3,
                subject: "project:sekai-chisei/agent:codex-app".into(),
                project: "sekai-chisei".into(),
                agent: "attacker".into(),
                key_id: "attacker".into(),
                work_unit: "wu-existing".into(),
                metric: String::new(),
                task_class: "reasoning".into(),
                mid_task: true,
                local_free_available: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!wrong_identity.allowed);
        assert_eq!(wrong_identity.degradation_level, "hard_cap");

        let continuation_request = Request::new(CheckBudgetRequest {
            user_id: String::new(),
            estimated_tokens: 3,
            subject: String::new(),
            project: "sekai-chisei".into(),
            agent: "codex-app".into(),
            key_id: "codex-app".into(),
            work_unit: "wu-existing".into(),
            metric: String::new(),
            task_class: "reasoning".into(),
            mid_task: false,
            local_free_available: false,
        });
        let continuation = svc
            .check_budget(continuation_request)
            .await
            .unwrap()
            .into_inner();
        assert!(continuation.allowed);
        assert_eq!(continuation.route_bias, "capable");
        assert_eq!(continuation.degradation_level, "warn");
        assert!(continuation.warning);
    }

    #[tokio::test]
    async fn record_gateway_audit_writes_decision_log() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let svc = ChiseiServiceImpl::new(db.clone(), config(":memory:"));
        let response = svc
            .record_gateway_audit(Request::new(RecordGatewayAuditRequest {
                event: Some(GatewayAuditEvent {
                    id: String::new(),
                    timestamp: 0,
                    actor: "codex-app".into(),
                    action: "gateway.model_rewrite".into(),
                    reason: "policy resolved a different model".into(),
                    evidence: HashMap::from([("request_id".into(), "req-1".into())]),
                    target_id: String::new(),
                    outcome: "routed".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .event
            .unwrap();

        assert!(!response.id.is_empty());
        assert!(response.timestamp > 0);
        assert_eq!(response.target_id, "llm_calls");
        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("gateway.model_rewrite".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].actor, "codex-app");
        assert_eq!(
            decisions[0].evidence.get("request_id").map(String::as_str),
            Some("req-1")
        );
    }

    #[tokio::test]
    async fn record_gateway_audit_strips_reserved_attestation_evidence_keys() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let svc = ChiseiServiceImpl::new(db.clone(), config(":memory:"));
        let event = svc
            .record_gateway_audit(Request::new(RecordGatewayAuditRequest {
                event: Some(GatewayAuditEvent {
                    id: String::new(),
                    timestamp: 0,
                    actor: "codex-app".into(),
                    action: "gateway.model_rewrite".into(),
                    reason: String::new(),
                    evidence: HashMap::from([
                        ("attestation_id".into(), "forged".into()),
                        ("attestation_hash".into(), "forged".into()),
                        ("request_id".into(), "req-1".into()),
                    ]),
                    target_id: String::new(),
                    outcome: "routed".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .event
            .unwrap();
        assert!(!event.evidence.contains_key("attestation_id"));
        assert!(!event.evidence.contains_key("attestation_hash"));
        assert_eq!(event.evidence["request_id"], "req-1");
        let stored = db.get_decision(&event.id).unwrap().unwrap();
        assert!(!stored.evidence.contains_key("attestation_id"));
        assert!(!stored.evidence.contains_key("attestation_hash"));
    }

    #[tokio::test]
    async fn record_gateway_audit_clamps_future_timestamp() {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        let svc = ChiseiServiceImpl::new(db, config(":memory:"));
        let future = chrono::Utc::now().timestamp_millis() + 86_400_000;
        let event = svc
            .record_gateway_audit(Request::new(RecordGatewayAuditRequest {
                event: Some(GatewayAuditEvent {
                    id: String::new(),
                    timestamp: future,
                    actor: "codex-app".into(),
                    action: "gateway.model_rewrite".into(),
                    reason: String::new(),
                    evidence: HashMap::new(),
                    target_id: String::new(),
                    outcome: "routed".into(),
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .event
            .unwrap();
        // A future timestamp would pin the ledger's purgeable prefix forever.
        assert!(event.timestamp < future);
        assert!(event.timestamp <= chrono::Utc::now().timestamp_millis());
    }

    #[tokio::test]
    async fn set_namespace_policy_applies_to_resolve_policy() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();

        let resolved = svc
            .resolve_policy(Request::new(resolve_policy_request(
                "sekai-chisei",
                "openai",
                "gpt-5.5",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolved.runtime, "native");
        assert_eq!(resolved.model, "native-default");
        assert_eq!(resolved.policy_scope, "sekai-chisei");
        assert_eq!(resolved.policy_version.len(), 64);
    }

    #[tokio::test]
    async fn set_namespace_policy_normalizes_legacy_openai_family_defaults() {
        let svc = memory_service();
        let resolution = svc
            .set_namespace_policy(Request::new(SetNamespacePolicyRequest {
                namespace: "sekai-chisei".into(),
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["native-default".into()],
                default_runtime: "openai".into(),
                default_model: "native-default".into(),
                data_class: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolution.runtime, "native");
        assert_eq!(resolution.model, "native-default");
        assert_eq!(
            svc.policy
                .effective_policy_for_scopes(&["sekai-chisei".into()])
                .unwrap()
                .1
                .default_runtime,
            "native"
        );

        let error = svc
            .set_namespace_policy(Request::new(SetNamespacePolicyRequest {
                namespace: "opaque-hosted".into(),
                allowed_runtimes: vec!["kiro".into()],
                allowed_models: vec!["gpt-5.5".into()],
                default_runtime: "kiro".into(),
                default_model: "gpt-5.5".into(),
                data_class: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            svc.policy
                .effective_policy_for_scopes(&["opaque-hosted".into()])
                .is_none()
        );
    }

    #[tokio::test]
    async fn resolve_policy_prefers_agent_context_over_project_policy() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-mini".into()],
            default_runtime: "native".into(),
            default_model: "native-mini".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "agent:codex-app".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();

        let mut request = resolve_policy_request("sekai-chisei", "native", "native-mini");
        request.project = "sekai-chisei".into();
        request.agent = "codex-app".into();
        let resolved = svc
            .resolve_policy(Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolved.runtime, "native");
        assert_eq!(resolved.model, "native-default");
    }

    #[tokio::test]
    async fn resolve_policy_biases_to_default_model_when_namespace_regressed() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into(), "native-cheap".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        create_suite(&svc, "sekai-chisei").await;
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "sekai-chisei".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "sekai-chisei".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        let resolved = svc
            .resolve_policy(Request::new(resolve_policy_request(
                "sekai-chisei",
                "native",
                "native-cheap",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolved.runtime, "native");
        assert_eq!(resolved.model, "native-default");
        assert!(resolved.eval_regressed);
        assert!(resolved.eval_regression_reason.contains("sekai-chisei"));
    }

    #[tokio::test]
    async fn resolve_policy_reverts_bulk_class_to_capable_when_namespace_regressed() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into(), "native-cheap".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        create_suite(&svc, "sekai-chisei").await;
        // Two runs with a score drop mark the namespace as regressed.
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "sekai-chisei".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "sekai-chisei".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        // A bulk task class would normally route cheap, but the active
        // regression forces it back to the capable default tier with no bias.
        let mut background = resolve_policy_request("sekai-chisei", "native", "native-cheap");
        background.task_class = "background".into();
        let resolved = svc
            .resolve_policy(Request::new(background))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolved.model, "native-default");
        assert_eq!(resolved.route_bias, "");
        assert!(resolved.eval_regressed);
    }

    #[tokio::test]
    async fn portfolio_route_is_audited_and_eval_regression_reverts_it() {
        let svc = memory_service();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["native".into()],
            allowed_models: vec!["native-default".into(), "native-cheap".into()],
            default_runtime: "native".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        for (model, quality, cost) in [("native-cheap", 85.0, 10), ("native-default", 95.0, 30)] {
            svc.record_portfolio_observation(Request::new(RecordPortfolioObservationRequest {
                namespace: "sekai-chisei".into(),
                task_class: "primary".into(),
                model: model.into(),
                quality_score: quality,
                cost_usd_micros: cost,
                sample_count: 5,
                updated_at: 1,
            }))
            .await
            .unwrap();
        }
        svc.set_portfolio_objective(Request::new(SetPortfolioObjectiveRequest {
            objective: Some(PortfolioObjective {
                namespace: "sekai-chisei".into(),
                mode: "minimize_cost".into(),
                budget_usd_micros: 100,
                quality_bar: 80.0,
                min_samples: 3,
                updated_at: 1,
            }),
        }))
        .await
        .unwrap();

        let routed = svc
            .resolve_policy(Request::new(resolve_policy_request(
                "sekai-chisei",
                "native",
                "native-default",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(routed.model, "native-cheap");
        assert_eq!(routed.route_bias, "portfolio");

        create_suite(&svc, "sekai-chisei").await;
        for (id, score, timestamp) in [("run-1", 95, 100), ("run-2", 60, 200)] {
            svc.create_eval_run(Request::new(CreateEvalRunRequest {
                run: Some(eval_run(id, "suite-1", score, timestamp)),
                changed_file: "sekai-chisei".into(),
                diff_hash: id.into(),
            }))
            .await
            .unwrap();
        }
        let reverted = svc
            .resolve_policy(Request::new(resolve_policy_request(
                "sekai-chisei",
                "native",
                "native-default",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(reverted.model, "native-default");
        assert_eq!(reverted.route_bias, "");
        assert!(reverted.eval_regressed);

        let decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("chisei.portfolio_route_shift".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 2);
        assert!(
            decisions
                .iter()
                .any(|decision| decision.outcome == "shifted")
        );
        assert!(
            decisions
                .iter()
                .any(|decision| decision.outcome == "reverted")
        );
    }

    #[tokio::test]
    async fn namespace_policy_reloads_from_sekai_object_store() {
        let path = std::env::temp_dir()
            .join(format!("sekai-policy-{}.db", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let svc = file_service(&path);
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "openai".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
        }))
        .await
        .unwrap();
        drop(svc);

        let reloaded = file_service(&path);
        let resolved = reloaded
            .resolve_policy(Request::new(resolve_policy_request(
                "sekai-chisei",
                "openai",
                "gpt-5.5",
            )))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();

        assert_eq!(resolved.runtime, "native");
        assert_eq!(resolved.model, "native-default");
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn create_eval_run_auto_tracks_iteration() {
        let svc = memory_service();
        create_suite(&svc, "context-a").await;

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 90, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 70, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        let latest = svc
            .get_latest_eval_iteration(Request::new(GetLatestEvalIterationRequest {
                changed_file: "skills/context-a.md".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .iteration
            .unwrap();
        assert_eq!(latest.baseline_run_id, "run-1");
        assert_eq!(latest.candidate_run_id, "run-2");
        assert!(latest.regressed);

        let listed = svc
            .list_eval_iterations(Request::new(ListEvalIterationsRequest {
                suite_id: "suite-1".into(),
                changed_file: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.iterations.len(), 2);
    }

    #[tokio::test]
    async fn sqlite_reload_restores_iterations_and_regression_gate() {
        let path = format!(
            "{}/sekai-chisei-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let svc = file_service(&path);
        create_suite(&svc, "context-a").await;

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        drop(svc);

        let svc = file_service(&path);
        let latest = svc
            .get_latest_eval_iteration(Request::new(GetLatestEvalIterationRequest {
                changed_file: "skills/context-a.md".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .iteration
            .unwrap();
        assert!(latest.regressed);

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-1".into(),
                    namespace: "context-a".into(),
                    spec: "ship context-a fix".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: String::new(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert!(plan.eval_regressed);
        assert!(!plan.executable);
        assert!(plan.eval_regression_reason.contains("context-a"));
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("regressed"))
        );
        let denied_receipt = svc
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .unwrap();
        assert!(denied_receipt.completeness().complete);
        assert!(denied_receipt.events.iter().any(|event| {
            event.kind == ReceiptEventKind::OutcomeRecorded
                && event.attributes.get("status").map(String::as_str) == Some("denied")
        }));

        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn configured_gateway_principal_can_reserve_request_aliases() {
        let mut svc = memory_service();
        svc.config.gateway_receipt_principals = vec!["Gateway-Prod".into()];
        let reservation = ReserveGatewayRequestAliasRequest {
            caller_scope: "gateway:prod".into(),
            request_alias: "attempt-1".into(),
            request_id: "request-1".into(),
            operation_id: "operation-1".into(),
        };
        let mut configured = Request::new(reservation.clone());
        configured
            .metadata_mut()
            .insert("x-principal", "Gateway-Prod".parse().unwrap());
        configured
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
        assert!(
            svc.reserve_gateway_request_alias(configured)
                .await
                .unwrap()
                .into_inner()
                .reserved
        );

        let mut intruder = Request::new(ReserveGatewayRequestAliasRequest {
            request_alias: "attempt-2".into(),
            request_id: "request-2".into(),
            ..reservation
        });
        intruder
            .metadata_mut()
            .insert("x-principal", "agent:intruder".parse().unwrap());
        assert_eq!(
            svc.reserve_gateway_request_alias(intruder)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn plan_execution_persists_causal_receipt_with_authenticated_actor() {
        let mut svc = memory_service();
        svc.config.gateway_receipt_principals = vec!["Gateway-Prod".into()];
        let mut request = Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "receipt-task-1".into(),
                namespace: "receipt-ns".into(),
                spec: "summarize governed context".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: "summary".into(),
                priority: 0,
                user_id: "caller-supplied-actor".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: "do not disclose raw context".into(),
                max_tokens: 128,
                task_class: String::new(),
                logical_operation_id: "external-operation-7".into(),
                attempt_id: "retry-b".into(),
            }),
        });
        request
            .metadata_mut()
            .insert("x-principal", "agent:authenticated".parse().unwrap());
        let plan = svc
            .plan_execution(request)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        let receipt = svc
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .expect("planned receipt");
        assert_eq!(receipt.initiating_actor, "agent:authenticated");
        assert_eq!(receipt.operation_id, plan.plan_id);
        assert_eq!(receipt.namespace, "receipt-ns");
        let intent = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .unwrap();
        assert_eq!(
            intent.attributes["logical_operation_id"],
            "external-operation-7"
        );
        assert_eq!(intent.attributes["attempt_id"], "retry-b");
        assert!(receipt.completed_at_ms.is_none());
        assert!(!receipt.completeness().complete);
        assert!(receipt.events.iter().all(|event| {
            event.operation_id == receipt.operation_id
                && !event.attributes.values().any(|value| {
                    value.contains("summarize governed context")
                        || value.contains("do not disclose raw context")
                })
        }));

        let mut without_canonical_egress = svc
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .unwrap();
        without_canonical_egress
            .events
            .retain(|event| event.kind != ReceiptEventKind::EgressDecided);
        svc.db
            .put_operation_receipt(&without_canonical_egress)
            .unwrap();
        svc.db
            .append_operation_receipt_event(
                &plan.plan_id,
                OperationReceiptEvent {
                    event_id: format!("report:{}:tool-egress", plan.plan_id),
                    operation_id: plan.plan_id.clone(),
                    parent_event_id: Some(format!("{}:budget", plan.plan_id)),
                    timestamp_ms: plan.created_at,
                    kind: ReceiptEventKind::ActionPerformed,
                    surface: ReceiptSurface::Action,
                    actor: "agent:authenticated".into(),
                    references: vec![],
                    attributes: BTreeMap::new(),
                },
            )
            .unwrap();

        svc.record_completed_operation(
            &plan,
            "agent:authenticated",
            &PlannedChatResponse {
                content: "private response body".into(),
                tool_calls: Vec::new(),
                input_tokens: 10,
                output_tokens: 4,
                stop_reason: "end_turn".into(),
                provider: "native".into(),
            },
            plan.created_at,
            plan.created_at,
        )
        .unwrap();
        let completed = svc
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .expect("completed receipt");
        assert!(completed.completeness().complete);
        assert_eq!(completed.completed_at_ms, Some(plan.created_at));
        assert!(completed.events.iter().any(|event| {
            event.kind == ReceiptEventKind::OutcomeRecorded
                && event.parent_event_id.as_deref()
                    == Some(format!("{}:verification", plan.plan_id).as_str())
        }));
        assert!(completed.events.iter().any(|event| {
            event.event_id.ends_with(":attempt-1")
                && event.timestamp_ms == plan.created_at
                && event.parent_event_id.as_deref()
                    == Some(format!("{}:budget", plan.plan_id).as_str())
        }));
        assert!(completed.events.iter().all(|event| {
            !event
                .attributes
                .values()
                .any(|value| value.contains("private response body"))
        }));
        let mut gateway_request = Request::new(RecordGatewayAuditRequest {
            event: Some(GatewayAuditEvent {
                id: "gateway-receipt-audit".into(),
                timestamp: plan.created_at + 26,
                actor: "agent:authenticated".into(),
                action: GATEWAY_RECEIPT_ACTION.into(),
                reason: "gateway operation completed".into(),
                evidence: HashMap::from([(
                    "receipt_json".into(),
                    serde_json::to_string(&completed).unwrap(),
                )]),
                target_id: plan.plan_id.clone(),
                outcome: "recorded".into(),
            }),
        });
        gateway_request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let local_write = svc.record_gateway_audit(gateway_request).await.unwrap_err();
        assert_eq!(local_write.code(), tonic::Code::PermissionDenied);

        svc.config.insecure = true;
        let mut insecure_gateway_replay = Request::new(RecordGatewayAuditRequest {
            event: Some(GatewayAuditEvent {
                id: "gateway-receipt-insecure-local-replay".into(),
                timestamp: plan.created_at + 26,
                actor: "agent:authenticated".into(),
                action: GATEWAY_RECEIPT_ACTION.into(),
                reason: "insecure local gateway replay".into(),
                evidence: HashMap::from([(
                    "receipt_json".into(),
                    serde_json::to_string(&completed).unwrap(),
                )]),
                target_id: plan.plan_id.clone(),
                outcome: "recorded".into(),
            }),
        });
        insecure_gateway_replay
            .metadata_mut()
            .insert("x-principal", "chisei-gateway".parse().unwrap());
        insecure_gateway_replay
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "local".parse().unwrap());
        svc.record_gateway_audit(insecure_gateway_replay)
            .await
            .unwrap();
        svc.config.insecure = false;

        let mut root_replay = Request::new(RecordGatewayAuditRequest {
            event: Some(GatewayAuditEvent {
                id: "gateway-receipt-root-replay".into(),
                timestamp: plan.created_at + 27,
                actor: "agent:authenticated".into(),
                action: GATEWAY_RECEIPT_ACTION.into(),
                reason: "legacy root gateway replay".into(),
                evidence: HashMap::from([(
                    "receipt_json".into(),
                    serde_json::to_string(&completed).unwrap(),
                )]),
                target_id: plan.plan_id.clone(),
                outcome: "recorded".into(),
            }),
        });
        root_replay
            .metadata_mut()
            .insert("x-principal", "root".parse().unwrap());
        let spoofed_root = svc.record_gateway_audit(root_replay).await.unwrap_err();
        assert_eq!(spoofed_root.code(), tonic::Code::PermissionDenied);

        let mut root_replay = Request::new(RecordGatewayAuditRequest {
            event: Some(GatewayAuditEvent {
                id: "gateway-receipt-root-token-replay".into(),
                timestamp: plan.created_at + 27,
                actor: "agent:authenticated".into(),
                action: GATEWAY_RECEIPT_ACTION.into(),
                reason: "authenticated root gateway replay".into(),
                evidence: HashMap::from([(
                    "receipt_json".into(),
                    serde_json::to_string(&completed).unwrap(),
                )]),
                target_id: plan.plan_id.clone(),
                outcome: "recorded".into(),
            }),
        });
        root_replay
            .metadata_mut()
            .insert("x-principal", "root".parse().unwrap());
        root_replay
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
        svc.record_gateway_audit(root_replay).await.unwrap();

        let mut configured_gateway_replay = Request::new(RecordGatewayAuditRequest {
            event: Some(GatewayAuditEvent {
                id: "gateway-receipt-configured-replay".into(),
                timestamp: plan.created_at + 27,
                actor: "agent:authenticated".into(),
                action: GATEWAY_RECEIPT_ACTION.into(),
                reason: "configured gateway replay".into(),
                evidence: HashMap::from([(
                    "receipt_json".into(),
                    serde_json::to_string(&completed).unwrap(),
                )]),
                target_id: plan.plan_id.clone(),
                outcome: "recorded".into(),
            }),
        });
        configured_gateway_replay
            .metadata_mut()
            .insert("x-principal", "Gateway-Prod".parse().unwrap());
        configured_gateway_replay
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
        svc.record_gateway_audit(configured_gateway_replay)
            .await
            .unwrap();

        let mut forged_request = Request::new(RecordGatewayAuditRequest {
            event: Some(GatewayAuditEvent {
                id: "forged-gateway-receipt".into(),
                timestamp: plan.created_at + 27,
                actor: "agent:authenticated".into(),
                action: GATEWAY_RECEIPT_ACTION.into(),
                reason: "forged".into(),
                evidence: HashMap::from([(
                    "receipt_json".into(),
                    serde_json::to_string(&completed).unwrap(),
                )]),
                target_id: plan.plan_id.clone(),
                outcome: "recorded".into(),
            }),
        });
        forged_request
            .metadata_mut()
            .insert("x-principal", "agent:intruder".parse().unwrap());
        forged_request
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
        let unauthorized = svc.record_gateway_audit(forged_request).await.unwrap_err();
        assert_eq!(unauthorized.code(), tonic::Code::PermissionDenied);

        let mut conflicting = completed.clone();
        conflicting.namespace = "forged-namespace".into();
        let mut conflicting_request = Request::new(RecordGatewayAuditRequest {
            event: Some(GatewayAuditEvent {
                id: "conflicting-gateway-receipt".into(),
                timestamp: plan.created_at + 28,
                actor: "agent:authenticated".into(),
                action: GATEWAY_RECEIPT_ACTION.into(),
                reason: "conflicting replay".into(),
                evidence: HashMap::from([(
                    "receipt_json".into(),
                    serde_json::to_string(&conflicting).unwrap(),
                )]),
                target_id: plan.plan_id.clone(),
                outcome: "recorded".into(),
            }),
        });
        conflicting_request
            .metadata_mut()
            .insert("x-principal", "chisei-gateway".parse().unwrap());
        conflicting_request
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
        let conflict = svc
            .record_gateway_audit(conflicting_request)
            .await
            .unwrap_err();
        assert_eq!(conflict.code(), tonic::Code::AlreadyExists);

        let authorization = || {
            let mut request = Request::new(AuthorizeOperationReporterRequest {
                operation_id: plan.plan_id.clone(),
                principal: "agent:reporter".into(),
                event_kinds: vec!["action_performed".into()],
            });
            request
                .metadata_mut()
                .insert("x-principal", "agent:authenticated".parse().unwrap());
            request
                .metadata_mut()
                .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
            request
        };
        let first_authorization = svc
            .authorize_operation_reporter(authorization())
            .await
            .unwrap()
            .into_inner();
        assert!(first_authorization.authorized);
        assert!(first_authorization.changed);
        let replayed_authorization = svc
            .authorize_operation_reporter(authorization())
            .await
            .unwrap()
            .into_inner();
        assert!(replayed_authorization.authorized);
        assert!(!replayed_authorization.changed);
        let report = || {
            let mut request = Request::new(ReportOperationEventRequest {
                operation_id: plan.plan_id.clone(),
                event_id: format!("report:{}:reported-action", plan.plan_id),
                parent_event_id: format!("{}:outcome", plan.plan_id),
                timestamp_ms: plan.created_at,
                kind: "action_performed".into(),
                attributes: HashMap::from([("action_type".into(), "tool.read".into())]),
                references: vec![],
            });
            request
                .metadata_mut()
                .insert("x-principal", "agent:reporter".parse().unwrap());
            request
                .metadata_mut()
                .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
            request
        };
        let first = svc
            .report_operation_event(report())
            .await
            .unwrap()
            .into_inner();
        assert!(first.recorded);
        assert!(first.complete);
        let replay = svc
            .report_operation_event(report())
            .await
            .unwrap()
            .into_inner();
        assert!(!replay.recorded);
        let mut colliding_report = report();
        colliding_report.get_mut().event_id = format!("{}:outcome", plan.plan_id);
        let collision = svc
            .report_operation_event(colliding_report)
            .await
            .unwrap_err();
        assert_eq!(collision.code(), tonic::Code::InvalidArgument);
        let updated = svc
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .unwrap();
        assert!(updated.events.iter().any(|event| {
            event.event_id.ends_with(":reported-action")
                && event.actor == "agent:reporter"
                && event.timestamp_ms == plan.created_at
        }));
        let terminal_conflict = svc
            .db
            .append_operation_receipt_event(
                &plan.plan_id,
                OperationReceiptEvent {
                    event_id: format!("report:{}:late-outcome", plan.plan_id),
                    operation_id: plan.plan_id.clone(),
                    parent_event_id: Some(format!("report:{}:reported-action", plan.plan_id)),
                    timestamp_ms: plan.created_at,
                    kind: ReceiptEventKind::OutcomeRecorded,
                    surface: ReceiptSurface::Outcome,
                    actor: "agent:authenticated".into(),
                    references: vec![],
                    attributes: BTreeMap::new(),
                },
            )
            .unwrap_err();
        assert!(terminal_conflict.contains("terminal outcome"));

        let mut get_request = Request::new(GetOperationReceiptRequest {
            operation_id: plan.plan_id.clone(),
            request_id: String::new(),
            caller_scope: String::new(),
            attempt: 0,
        });
        get_request
            .metadata_mut()
            .insert("x-principal", "agent:reporter".parse().unwrap());
        let reporter_read = svc.get_operation_receipt(get_request).await.unwrap_err();
        assert_eq!(reporter_read.code(), tonic::Code::PermissionDenied);

        let mut initiator_get = Request::new(GetOperationReceiptRequest {
            operation_id: plan.plan_id.clone(),
            request_id: String::new(),
            caller_scope: String::new(),
            attempt: 0,
        });
        initiator_get
            .metadata_mut()
            .insert("x-principal", "agent:authenticated".parse().unwrap());
        let retrieved = svc
            .get_operation_receipt(initiator_get)
            .await
            .unwrap()
            .into_inner();
        assert!(retrieved.complete);
        assert!(retrieved.receipt_json.contains(":reported-action"));
        assert!(
            svc.get_operation_receipt(Request::new(GetOperationReceiptRequest {
                operation_id: plan.plan_id.clone(),
                request_id: String::new(),
                caller_scope: String::new(),
                attempt: 0,
            }))
            .await
            .unwrap()
            .into_inner()
            .complete
        );

        let mut denied_get = Request::new(GetOperationReceiptRequest {
            operation_id: plan.plan_id.clone(),
            request_id: String::new(),
            caller_scope: String::new(),
            attempt: 0,
        });
        denied_get
            .metadata_mut()
            .insert("x-principal", "agent:intruder".parse().unwrap());
        let denied = svc.get_operation_receipt(denied_get).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let mut configured_writer_get = Request::new(GetOperationReceiptRequest {
            operation_id: plan.plan_id.clone(),
            request_id: String::new(),
            caller_scope: String::new(),
            attempt: 0,
        });
        configured_writer_get
            .metadata_mut()
            .insert("x-principal", "Gateway-Prod".parse().unwrap());
        let denied = svc
            .get_operation_receipt(configured_writer_get)
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let mut unauthorized_report = report();
        unauthorized_report.get_mut().event_id = format!("report:{}:forged-action", plan.plan_id);
        unauthorized_report
            .metadata_mut()
            .insert("x-principal", "agent:intruder".parse().unwrap());
        let denied = svc
            .report_operation_event(unauthorized_report)
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn planned_receipt_pins_external_evidence_and_memory_provenance() {
        let svc = memory_service();
        let digest = "a".repeat(64);
        let plan = ExecutionPlan {
            plan_id: "plan-with-evidence".into(),
            input: Some(ExecutionInput {
                request_id: "request-with-evidence".into(),
                namespace: "acme".into(),
                spec: "use governed evidence".into(),
                task_type: " verification ".into(),
                ..Default::default()
            }),
            created_at: 100,
            evidence_references: vec![ContextEvidenceReference {
                submission_id: "submission-7".into(),
                source_version: "attempt-2".into(),
                content_digest: digest.clone(),
                disclosed_fields: vec!["content.result".into(), "signal".into()],
                ..Default::default()
            }],
            memory_references: vec![MemoryContextReference {
                memory_id: "memory-7".into(),
                memory_version: 3,
                classification: "internal".into(),
                confidence_bps: 9_000,
                applicability: "verification".into(),
                evidence_operation_ids: vec!["operation-7".into()],
                content_digest: "b".repeat(64),
            }],
            ..Default::default()
        };

        svc.record_planned_operation(&plan, "agent:test").unwrap();
        let receipt = svc
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.operation_class, "verification");
        let evidence = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::ContextGoverned)
            .and_then(|event| {
                event
                    .references
                    .iter()
                    .find(|reference| reference.kind == "external_evidence")
            })
            .expect("pinned external evidence reference");
        assert_eq!(evidence.reference, "evidence:submission-7@attempt-2");
        assert_eq!(evidence.content_hash.as_deref(), Some(digest.as_str()));
        assert_eq!(
            evidence.disclosed_fields,
            vec!["content.result".to_string(), "signal".to_string()]
        );
        let memory = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::ContextGoverned)
            .and_then(|event| {
                event
                    .references
                    .iter()
                    .find(|reference| reference.kind == "kioku_memory")
            })
            .expect("pinned memory reference");
        assert_eq!(memory.reference, "memory:memory-7@3");
        assert_eq!(
            memory.content_hash.as_deref(),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(memory.disclosed_fields, ["claim"]);
        assert!(
            svc.db
                .list_kioku_lifecycle_events("memory-7", 3)
                .unwrap()
                .is_empty(),
            "planning must not record a treatment assignment"
        );
    }

    #[test]
    fn execution_memory_injection_revalidates_cached_versions() {
        let svc = memory_service();
        let error = svc
            .record_execution_memory_injections(
                "request-stale-memory",
                "agent:test",
                &[MemoryContextReference {
                    memory_id: "purged-memory".into(),
                    memory_version: 4,
                    classification: "internal".into(),
                    confidence_bps: 9_000,
                    applicability: "verification".into(),
                    evidence_operation_ids: vec![],
                    content_digest: "c".repeat(64),
                }],
            )
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(
            svc.db
                .list_kioku_lifecycle_events("purged-memory", 4)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn missing_execution_memory_holdout_does_not_block_execution() {
        let svc = memory_service();
        svc.invalidate_ineligible_execution_memory_holdouts(
            "operation-1",
            "agent:test",
            &[MemoryHoldoutReference {
                memory_id: "purged-memory".into(),
                memory_version: 4,
                classification: "internal".into(),
                content_digest: "c".repeat(64),
            }],
        )
        .unwrap();
    }

    #[test]
    fn cached_memory_must_remain_active_unexpired_and_retained() {
        use crate::chisei::kioku::MemoryLifecycleState;

        assert!(memory_lifecycle_allows_execution(
            MemoryLifecycleState::Active,
            Some(201),
            Some(201),
            200,
        ));
        assert!(!memory_lifecycle_allows_execution(
            MemoryLifecycleState::Active,
            Some(200),
            Some(201),
            200,
        ));
        assert!(!memory_lifecycle_allows_execution(
            MemoryLifecycleState::Active,
            Some(201),
            Some(200),
            200,
        ));
        assert!(!memory_lifecycle_allows_execution(
            MemoryLifecycleState::Rejected,
            None,
            None,
            200,
        ));
    }

    #[tokio::test]
    async fn execute_plan_rechecks_regression_gate() {
        let svc = memory_service();
        create_suite(&svc, "context-a").await;

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        let mut plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-1".into(),
                    namespace: "context-a".into(),
                    spec: "ship context-a fix".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: String::new(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert!(plan.eval_regressed);
        assert!(!plan.executable);

        plan.executable = true;
        if let Some(input) = plan.input.as_mut() {
            input.namespace = "context-b".into();
        }
        let err = svc
            .execute_plan(Request::new(ExecutePlanRequest { plan: Some(plan) }))
            .await
            .expect_err("forged executable flag should be rejected");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("not executable"));
    }

    #[tokio::test]
    async fn eval_regressed_context_is_force_sampled_and_audited() {
        let svc = memory_service();
        create_suite(&svc, "context-a").await;

        // Two runs whose drop trips the regression signal for context-a.
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-sample".into(),
                    namespace: "context-a".into(),
                    spec: "ship context-a fix".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: String::new(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        // Base rate is 0.0 in the test config, so sampling here is purely the
        // eval-driven adaptive trigger.
        assert!(plan.sampled);
        assert_eq!(plan.sample_reason, "eval_regressed");
        assert_eq!(plan.sample_rate, 1.0);

        // A matching audit decision was recorded.
        let decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("sample".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions
                .iter()
                .any(|d| d.target_id == "task-sample" && d.reason == "eval_regressed"),
            "expected a sampling audit decision for task-sample"
        );
    }

    #[tokio::test]
    async fn plan_execution_exposes_and_audits_egress_decisions() {
        let svc = memory_service();
        svc.db
            .create_object(&Object {
                id: "asset-secret".into(),
                kind: "asset".into(),
                name: "SecretCo".into(),
                namespace: "".into(),
                external_id: "asset:SECRET".into(),
                properties: std::collections::HashMap::from([
                    ("verdict".into(), "approved".into()),
                    ("score".into(), "99".into()),
                    (
                        crate::chisei::egress::EXTERNAL_PROPERTIES_KEY.into(),
                        "verdict".into(),
                    ),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-egress".into(),
                    namespace: "asset:SECRET".into(),
                    spec: "analyze the referenced asset".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: String::new(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        assert!(plan.egress_decisions.iter().any(|decision| {
            decision.provider == "native"
                && decision.external
                && decision.included.contains(&"object#1.verdict".into())
                && decision.redacted.contains(&"object#1.score".into())
                && decision.redacted.contains(&"object#1.identity".into())
        }));
        assert!(plan.enriched_spec.contains("prior_verdict: approved"));
        assert!(!plan.enriched_spec.contains("score: 99"));
        assert!(!plan.enriched_spec.contains("SecretCo"));
        let egress_text = format!("{:?}", plan.egress_decisions);
        assert!(!egress_text.contains("asset:SECRET"));

        let decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                actor: Some("chisei.egress".into()),
                action: Some("prepare_context".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(decisions.iter().any(|d| {
            d.target_id == "task-egress"
                && d.evidence.get("provider") == Some(&"native".to_string())
                && d.evidence.get("redacted_count") == Some(&"2".to_string())
        }));
    }

    #[test]
    fn namespace_policy_reloads_data_class_from_sekai_object_store() {
        let path = format!(
            "{}/sekai-chisei-policy-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        {
            let db = SekaiDb::new(&path).unwrap();
            db.create_object(&Object {
                id: "policy-alpha".into(),
                kind: "policy".into(),
                name: "alpha".into(),
                namespace: String::new(),
                external_id: "policy:alpha".into(),
                properties: std::collections::HashMap::from([
                    (
                        "allowed_models".into(),
                        "native-default,ollama/capable".into(),
                    ),
                    ("default_runtime".into(), "kiro".into()),
                    ("default_model".into(), "native-default".into()),
                    ("data_class".into(), "sensitive".into()),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();
        }

        let svc = file_service(&path);
        let policy = svc
            .policy
            .effective_policy("alpha")
            .expect("policy should load from object store");
        assert_eq!(policy.data_class, "sensitive");
        assert_eq!(
            policy.allowed_models,
            vec!["native-default", "ollama/capable"]
        );

        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn set_namespace_policy_persists_data_class() {
        let path = format!(
            "{}/sekai-chisei-policy-rpc-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let svc = file_service(&path);
        let response = svc
            .set_namespace_policy(Request::new(SetNamespacePolicyRequest {
                namespace: "alpha".into(),
                allowed_runtimes: vec!["native".into()],
                allowed_models: vec!["native-default".into()],
                default_runtime: "native".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.resolution.unwrap().data_class, "sensitive");
        drop(svc);

        let reloaded = file_service(&path);
        let policy = reloaded
            .policy
            .effective_policy("alpha")
            .expect("policy should reload");
        assert_eq!(policy.data_class, "sensitive");
        assert_eq!(policy.default_model, "native-default");

        let _ = fs::remove_file(&path);
    }

    #[tokio::test]
    async fn sensitive_private_rejects_unsafe_provider() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "anthropic".into(),
                default_model: "anthropic/claude-sonnet-4".into(),
                data_class: "sensitive".into(),
            },
        );

        let err = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-sensitive-private".into(),
                    namespace: "alpha".into(),
                    spec: "analyze private holdings".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: String::new(),
                    ..Default::default()
                }),
            }))
            .await
            .expect_err("unsafe provider should be rejected for sensitive private work");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("not safe"));
    }

    #[tokio::test]
    async fn resolve_policy_denies_sensitive_private_unsafe_provider() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );

        let err = svc
            .resolve_policy(Request::new(ResolvePolicyRequest {
                namespace: "alpha".into(),
                preferred_runtime: "anthropic".into(),
                preferred_model: "anthropic/claude-sonnet-4".into(),
                subject: String::new(),
                project: String::new(),
                agent: String::new(),
                key_id: String::new(),
                task_class: String::new(),
                user_id: String::new(),
                expected_calls: 1,
                budget_route_bias: String::new(),
            }))
            .await
            .expect_err("sensitive private preflight should deny unsafe provider");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn sensitive_template_only_skips_context_enrichment() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );
        svc.db
            .create_object(&Object {
                id: "asset-secret".into(),
                kind: "asset".into(),
                name: "SecretCo".into(),
                namespace: "alpha".into(),
                external_id: "asset:SECRET".into(),
                properties: std::collections::HashMap::from([(
                    "verdict".into(),
                    "approved".into(),
                )]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-template".into(),
                    namespace: "alpha".into(),
                    spec: "write a generic evaluation rubric".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: "template_only".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        assert_eq!(plan.task_class, "template_only");
        assert!(plan.executable);
        assert!(
            plan.steps
                .iter()
                .any(|step| { step.step == "object_context_enrich" && step.action == "skipped" })
        );
        assert!(!plan.enriched_spec.contains("SecretCo"));
        assert!(!plan.enriched_spec.contains("approved"));
    }

    #[tokio::test]
    async fn template_only_plan_blocks_known_entity_leak() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );
        svc.db
            .create_object(&Object {
                id: "asset-secret".into(),
                kind: "asset".into(),
                name: "SecretCo".into(),
                namespace: "alpha".into(),
                external_id: "asset:SECRET".into(),
                properties: std::collections::HashMap::new(),
                created: 0,
                updated: 0,
            })
            .unwrap();
        svc.db
            .create_object(&Object {
                id: "leak-rule-secretco".into(),
                kind: "leak_rule".into(),
                name: "company-name".into(),
                namespace: "alpha".into(),
                external_id: "leak_rule:secretco".into(),
                properties: std::collections::HashMap::from([
                    ("pattern".into(), "SecretCo".into()),
                    ("label".into(), "company_name".into()),
                    ("action".into(), "block".into()),
                ]),
                created: 0,
                updated: 0,
            })
            .unwrap();

        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-leak".into(),
                    namespace: "alpha".into(),
                    spec: "write a generic rubric for SecretCo".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: "template_only".into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        assert!(!plan.executable);
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.contains("leak checker blocked"))
        );
        assert!(plan.egress_decisions.iter().any(|decision| {
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("known_entity:SecretCo"))
        }));
        assert!(plan.egress_decisions.iter().any(|decision| {
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("company_name"))
        }));
        let decisions = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                actor: Some("chisei.privacy".into()),
                action: Some("leak_check".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(decisions.iter().any(|decision| {
            decision.target_id == "task-leak"
                && decision.outcome == "leak_blocked"
                && decision
                    .evidence
                    .get("labels")
                    .is_some_and(|labels| labels.contains("company_name"))
        }));
    }

    #[tokio::test]
    async fn check_egress_denies_sensitive_private_unsafe_provider() {
        let svc = memory_service();
        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );

        let response = svc
            .check_egress(Request::new(CheckEgressRequest {
                namespace: "alpha".into(),
                payload: "generic payload".into(),
                provider: "native".into(),
                task_class: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(!response.allowed);
        assert_eq!(response.policy_version.len(), 64);
        assert!(response.findings.iter().any(|decision| {
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("privacy gate"))
        }));
    }

    #[tokio::test]
    async fn execute_plan_rejects_after_policy_flips_sensitive() {
        let svc = memory_service();
        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-stale-policy".into(),
                    namespace: "alpha".into(),
                    spec: "do ordinary work".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: String::new(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert!(plan.executable);

        svc.policy.set_namespace_policy(
            "alpha",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec![],
                allowed_models: vec![],
                default_runtime: "kiro".into(),
                default_model: "native-default".into(),
                data_class: "sensitive".into(),
            },
        );

        let err = svc
            .execute_plan(Request::new(ExecutePlanRequest {
                plan: Some(plan.clone()),
            }))
            .await
            .expect_err("stale external plan should be blocked after policy flip");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("privacy gate"));

        let receipt = svc
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .expect("rejected execution receipt");
        assert!(receipt.completeness().complete);
        assert!(receipt.events.iter().any(|event| {
            event.kind == ReceiptEventKind::OutcomeRecorded
                && event.attributes.get("status").map(String::as_str) == Some("denied")
                && event
                    .attributes
                    .get("completion_reason")
                    .map(String::as_str)
                    == Some("provider_became_unsafe")
        }));
    }

    #[tokio::test]
    async fn execute_plan_rejects_external_plan_without_egress_decisions() {
        let svc = memory_service();
        let plan = ExecutionPlan {
            plan_id: "plan-forged-egress".into(),
            input: Some(ExecutionInput {
                request_id: "task-forged-egress".into(),
                namespace: "ns".into(),
                spec: "do work".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                task_class: String::new(),
                ..Default::default()
            }),
            resolved_runtime: "kiro".into(),
            resolved_model: "native-default".into(),
            enriched_spec: "do work".into(),
            prepared_system: String::new(),
            prepared_messages: vec![ChatMessage {
                role: "user".into(),
                content: "do work".into(),
                tool_call_id: String::new(),
                tool_calls: vec![],
            }],
            tools: vec![],
            budget: Some(BudgetVerdict {
                allowed: true,
                usage: None,
                reason: String::new(),
            }),
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 512,
            created_at: chrono::Utc::now().timestamp_millis(),
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
            task_class: String::new(),
            evidence_references: vec![],
            memory_references: vec![],
            planning_actor: "local".into(),
            memory_holdouts: vec![],
        };
        svc.cache_plan(plan.clone());

        let err = svc
            .execute_plan(Request::new(ExecutePlanRequest { plan: Some(plan) }))
            .await
            .expect_err("external plan without egress decisions should be rejected");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("missing egress decisions"));
    }

    #[tokio::test]
    async fn cached_plans_remain_bound_to_the_planning_principal() {
        let svc = memory_service();
        let plan = ExecutionPlan {
            plan_id: "actor-bound-plan".into(),
            planning_actor: "agent:planner".into(),
            memory_holdouts: vec![],
            executable: true,
            created_at: chrono::Utc::now().timestamp_millis(),
            ..Default::default()
        };
        svc.cache_plan(plan.clone());
        let mut request = Request::new(ExecutePlanRequest { plan: Some(plan) });
        request
            .metadata_mut()
            .insert("x-principal", "agent:intruder".parse().unwrap());

        let error = svc.execute_plan(request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(
            svc.planned_executions
                .lock()
                .unwrap()
                .contains_key("actor-bound-plan")
        );
    }

    #[tokio::test]
    async fn execute_plan_stream_rejects_external_plan_without_egress_decisions() {
        let svc = memory_service();
        let plan = ExecutionPlan {
            plan_id: "stream-external-plan".into(),
            input: Some(ExecutionInput {
                request_id: "stream-external-plan".into(),
                namespace: "sekai-chisei".into(),
                spec: "do work".into(),
                preferred_model: "gpt-5.5".into(),
                preferred_runtime: "openai".into(),
                task_type: String::new(),
                priority: 0,
                user_id: "user-1".into(),
                task_class: String::new(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 512,
                ..Default::default()
            }),
            resolved_runtime: "openai".into(),
            resolved_model: "gpt-5.5".into(),
            enriched_spec: "do work".into(),
            prepared_system: String::new(),
            prepared_messages: vec![ChatMessage {
                role: "user".into(),
                content: "do work".into(),
                tool_call_id: String::new(),
                tool_calls: vec![],
            }],
            tools: vec![],
            budget: Some(BudgetVerdict {
                allowed: true,
                usage: None,
                reason: String::new(),
            }),
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 512,
            created_at: chrono::Utc::now().timestamp_millis(),
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
            task_class: String::new(),
            evidence_references: vec![],
            memory_references: vec![],
            planning_actor: "local".into(),
            memory_holdouts: vec![],
        };
        svc.cache_plan(plan.clone());

        let result = svc
            .execute_plan_stream(Request::new(ExecutePlanRequest { plan: Some(plan) }))
            .await;
        let err = result
            .err()
            .expect("external stream plan without egress decisions should be rejected");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("missing egress decisions"));
    }

    #[tokio::test]
    async fn sqlite_reload_backfills_legacy_iteration_context_gates() {
        let path = format!(
            "{}/sekai-chisei-legacy-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let svc = file_service(&path);
        create_suite(&svc, "context-a").await;

        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-1", "suite-1", 92, 100)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-a".into(),
        }))
        .await
        .unwrap();
        svc.create_eval_run(Request::new(CreateEvalRunRequest {
            run: Some(eval_run("run-2", "suite-1", 60, 200)),
            changed_file: "skills/context-a.md".into(),
            diff_hash: "hash-b".into(),
        }))
        .await
        .unwrap();

        svc.db
            .conn()
            .execute("UPDATE chisei_eval_iterations SET namespace = ''", [])
            .unwrap();
        drop(svc);

        let svc = file_service(&path);
        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-1".into(),
                    namespace: "context-a".into(),
                    spec: "ship context-a fix".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    task_type: String::new(),
                    priority: 0,
                    user_id: "user-1".into(),
                    estimated_tokens: 0,
                    messages: vec![],
                    tools: vec![],
                    system: String::new(),
                    max_tokens: 512,
                    task_class: String::new(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert!(plan.eval_regressed);
        assert!(plan.eval_regression_reason.contains("context-a"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cache_plan_keeps_newest_inserted_plan() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        for i in 0..MAX_CACHED_EXECUTION_PLANS {
            svc.cache_plan(ExecutionPlan {
                plan_id: format!("plan-{i:03}"),
                input: None,
                resolved_runtime: String::new(),
                resolved_model: String::new(),
                enriched_spec: String::new(),
                prepared_system: String::new(),
                prepared_messages: vec![],
                tools: vec![],
                budget: None,
                steps: vec![],
                review_policy: None,
                risk_score: 0.0,
                low_success_namespace: false,
                executable: true,
                warnings: vec![],
                max_tokens: 0,
                created_at: now,
                affinity_namespaces: vec![],
                eval_regressed: false,
                eval_regression_reason: String::new(),
                sampled: false,
                sample_rate: 0.0,
                sample_reason: String::new(),
                egress_decisions: vec![],
                task_class: String::new(),
                evidence_references: vec![],
                memory_references: vec![],
                planning_actor: String::new(),
                memory_holdouts: vec![],
            });
        }
        let newest = ExecutionPlan {
            plan_id: "plan-new".into(),
            input: None,
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            enriched_spec: String::new(),
            prepared_system: String::new(),
            prepared_messages: vec![],
            tools: vec![],
            budget: None,
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 0,
            created_at: now,
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
            task_class: String::new(),
            evidence_references: vec![],
            memory_references: vec![],
            planning_actor: String::new(),
            memory_holdouts: vec![],
        };
        svc.cache_plan(newest.clone());

        let plans = svc
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        assert_eq!(plans.len(), MAX_CACHED_EXECUTION_PLANS);
        assert!(plans.contains_key(&newest.plan_id));
    }

    #[test]
    fn cache_plan_prunes_expired_entries() {
        let svc = memory_service();
        let expired = ExecutionPlan {
            plan_id: "plan-old".into(),
            input: None,
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            enriched_spec: String::new(),
            prepared_system: String::new(),
            prepared_messages: vec![],
            tools: vec![],
            budget: None,
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 0,
            created_at: chrono::Utc::now().timestamp_millis()
                - MAX_CACHED_EXECUTION_PLAN_AGE_MS
                - 1,
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
            task_class: String::new(),
            evidence_references: vec![],
            memory_references: vec![],
            planning_actor: String::new(),
            memory_holdouts: vec![],
        };
        let fresh = ExecutionPlan {
            plan_id: "plan-fresh".into(),
            created_at: chrono::Utc::now().timestamp_millis(),
            ..expired.clone()
        };
        svc.cache_plan(expired);
        svc.cache_plan(fresh.clone());

        let plans = svc
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        assert!(!plans.contains_key("plan-old"));
        assert!(plans.contains_key(&fresh.plan_id));
    }

    #[test]
    fn cache_plan_keeps_inserted_plan_when_timestamps_tie() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        for i in 0..MAX_CACHED_EXECUTION_PLANS {
            svc.cache_plan(ExecutionPlan {
                plan_id: format!("plan-z{i:03}"),
                input: None,
                resolved_runtime: String::new(),
                resolved_model: String::new(),
                enriched_spec: String::new(),
                prepared_system: String::new(),
                prepared_messages: vec![],
                tools: vec![],
                budget: None,
                steps: vec![],
                review_policy: None,
                risk_score: 0.0,
                low_success_namespace: false,
                executable: true,
                warnings: vec![],
                max_tokens: 0,
                created_at: now,
                affinity_namespaces: vec![],
                eval_regressed: false,
                eval_regression_reason: String::new(),
                sampled: false,
                sample_rate: 0.0,
                sample_reason: String::new(),
                egress_decisions: vec![],
                task_class: String::new(),
                evidence_references: vec![],
                memory_references: vec![],
                planning_actor: String::new(),
                memory_holdouts: vec![],
            });
        }
        let inserted = ExecutionPlan {
            plan_id: "plan-a".into(),
            input: None,
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            enriched_spec: String::new(),
            prepared_system: String::new(),
            prepared_messages: vec![],
            tools: vec![],
            budget: None,
            steps: vec![],
            review_policy: None,
            risk_score: 0.0,
            low_success_namespace: false,
            executable: true,
            warnings: vec![],
            max_tokens: 0,
            created_at: now,
            affinity_namespaces: vec![],
            eval_regressed: false,
            eval_regression_reason: String::new(),
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            egress_decisions: vec![],
            task_class: String::new(),
            evidence_references: vec![],
            memory_references: vec![],
            planning_actor: String::new(),
            memory_holdouts: vec![],
        };
        svc.cache_plan(inserted.clone());

        let plans = svc
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        assert_eq!(plans.len(), MAX_CACHED_EXECUTION_PLANS);
        assert!(plans.contains_key(&inserted.plan_id));
    }
}
