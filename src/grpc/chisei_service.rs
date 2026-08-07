use base64::Engine as _;
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use prost::Message as _;
use sha2::Digest;
use tokio::sync::Mutex as AsyncMutex;
use tonic::{Request, Response, Status};

use super::pb::chisei::chisei_service_server::ChiseiService;
use super::pb::chisei::*;
use super::provider_execution::{
    ProviderExecutionRequest, estimate_chat_request, execute_native_chat_request_stream,
};
use crate::chisei::budget::BudgetTracker;
use crate::chisei::controller::ActivePromotions;
use crate::chisei::epistemic_descriptor::EPISTEMIC_DESCRIPTOR_VERSION;
use crate::chisei::eval::EvalStore;
use crate::chisei::evaluation_execution as evaluation_execution_domain;
use crate::chisei::evaluation_manifest as evaluation_manifest_domain;
use crate::chisei::evaluation_plan as evaluation_plan_domain;
use crate::chisei::external_action as external;
use crate::chisei::external_permit as permit;
use crate::chisei::governed_subject as subject;
use crate::chisei::governed_subject_provenance as subject_provenance;
use crate::chisei::lookup_first;
use crate::chisei::pipeline as pipe;
use crate::chisei::policy::{ContextAdmissionAction, Policy, PolicyResolver};
use crate::chisei::portfolio::{Objective, PortfolioStore, TaskDemand as PortfolioDemand};
use crate::chisei::privacy::{DataClass, LeakAction, LeakFinding, LeakRule, TaskClass};
use crate::chisei::promotion::CandidateStore;
use crate::chisei::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind, ReceiptSurface, UncoveredSurface,
};
use crate::config::Config;
use crate::db::chisei_budget::{METRIC_REQUESTS, METRIC_TOKENS};
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::domain::{ListFilter, Object};
use crate::sekai::action::RiskClass;
use crate::sekai::action_policy::ActionDecision;
use crate::sekai::coordination::{
    RESERVATION_STATUS_ACTIVE, ReservationFilter, WORK_UNIT_STATUS_RUNNING,
};
use crate::sekai::governed_facts::{self as governed_fact_domain, GovernedFactType};
use crate::sekai::markings;

pub struct ChiseiServiceImpl {
    budget: Arc<BudgetTracker>,
    policy: Arc<PolicyResolver>,
    pipeline: pipe::Pipeline,
    eval: Arc<EvalStore>,
    portfolio: Arc<PortfolioStore>,
    planned_executions: Arc<Mutex<HashMap<String, CachedExecutionPlan>>>,
    evolve_history: Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    candidates: Arc<CandidateStore>,
    active_promotions: Arc<ActivePromotions>,
    evaluator_registry: Arc<evaluation_execution_domain::DeterministicEvaluatorRegistry>,
    stochastic_evaluator_registry: Arc<evaluation_execution_domain::StochasticEvaluatorRegistry>,
    evaluation_cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    evaluation_execution_locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
    db: Arc<RuntimeDb>,
    config: Config,
    provider_registry_state_path: Option<PathBuf>,
}

#[derive(Clone)]
struct CachedExecutionPlan {
    plan: ExecutionPlan,
    enterprise_authority: Option<String>,
}

struct BoundGunshiAllocation {
    issuance_id: String,
    plan: crate::chisei::gunshi::AllocationPlan,
}

struct EvaluationExecutionRuntime<'a> {
    deterministic_registry: &'a evaluation_execution_domain::DeterministicEvaluatorRegistry,
    stochastic_registry: &'a evaluation_execution_domain::StochasticEvaluatorRegistry,
    stochastic_egress_reasons: &'a BTreeMap<String, String>,
    budget: &'a BudgetTracker,
}

const MAX_CACHED_EXECUTION_PLANS: usize = 128;
const MAX_CACHED_EXECUTION_PLAN_AGE_MS: i64 = 15 * 60 * 1000;
const POLICY_KIND: &str = "policy";
const PIPELINE_CONTEXT_EXPANSION_PROFILE_VERSION: &str = "pipeline-v1";
const MIN_EVIDENCE_CONTEXT_EVAL_CASES: usize = 3;
const EXECUTION_SCHEMA_VERSION: &str = "chisei.execution/v1";
const GATEWAY_RECEIPT_ACTION: &str = "operation.receipt.upsert";
const AUTH_SOURCE_HEADER: &str = "x-sekai-auth-source";
const DELEGATED_PRINCIPAL_HEADER: &str = "x-sekai-delegated-principal";
const KIOKU_MIN_SAMPLES_PER_ARM: usize = 3;
const KIOKU_REGRESSION_THRESHOLD: f64 = 0.05;
const KIOKU_TRUSTED_OUTCOME_ATTRIBUTE: &str = "kioku_trusted_outcome";
const CHISEI_EXECUTE_SCOPE: &str = "chisei.execute";
const EVALUATION_GATE_STATUS_FOUND: &str = "found";
const EVALUATION_GATE_STATUS_SUITE_NOT_FOUND: &str = "suite_not_found";
const EVALUATION_GATE_STATUS_NO_MATCHING_RUN: &str = "no_matching_run";
// Tenkai sends its local 60-second gate window; the additional 60 seconds
// allows bounded clock skew between the Tenkai and Chisei hosts.
const EVALUATION_GATE_MAX_FUTURE_SKEW_MS: i64 = 120_000;
const MAX_EVALUATION_GATE_CASES: usize = 4096;
const MAX_EVALUATION_GATE_RESULTS: usize = 4096;

#[derive(Clone, PartialEq, prost::Message)]
struct EvaluationGateSuiteSnapshot {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    description: String,
    #[prost(message, repeated, tag = "4")]
    cases: Vec<EvaluationGateCaseSnapshot>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EvaluationGateCaseSnapshot {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    namespace: String,
    #[prost(string, tag = "4")]
    spec: String,
    #[prost(message, repeated, tag = "5")]
    assertions: Vec<EvaluationGateAssertionSnapshot>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EvaluationGateAssertionSnapshot {
    #[prost(string, tag = "1")]
    assert_type: String,
    #[prost(string, tag = "2")]
    value: String,
}

fn evaluation_gate_suite_digest(suite: &crate::chisei::eval::Suite) -> String {
    let snapshot = EvaluationGateSuiteSnapshot {
        id: suite.id.clone(),
        name: suite.name.clone(),
        description: suite.description.clone(),
        cases: suite
            .cases
            .iter()
            .map(|case| EvaluationGateCaseSnapshot {
                id: case.id.clone(),
                name: case.name.clone(),
                namespace: case.namespace.clone(),
                spec: case.spec.clone(),
                assertions: case
                    .assertions
                    .iter()
                    .map(|assertion| EvaluationGateAssertionSnapshot {
                        assert_type: assertion.assert_type.clone(),
                        value: assertion.value.clone(),
                    })
                    .collect(),
            })
            .collect(),
    };
    format!("{:x}", sha2::Sha256::digest(snapshot.encode_to_vec()))
}

fn evaluation_gate_config_ref(
    release_digest: &str,
    artifact_digest: &str,
    suite_digest: &str,
) -> String {
    let mut hasher = sha2::Sha256::new();
    for value in [
        b"tenkai-gate-v1".as_slice(),
        release_digest.as_bytes(),
        artifact_digest.as_bytes(),
        suite_digest.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    format!("tenkai:{:x}", hasher.finalize())
}

fn record_reported_memory_outcomes(
    db: &RuntimeDb,
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
    if let Some(context) = request
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        return context.principal.subject.clone();
    }
    request
        .metadata()
        .get("x-principal")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local")
        .to_string()
}

fn enterprise_authenticated_context<T>(
    request: &Request<T>,
) -> Result<Option<&crate::enterprise::AuthenticatedContext>, Status> {
    if request
        .metadata()
        .get(AUTH_SOURCE_HEADER)
        .and_then(|value| value.to_str().ok())
        != Some("enterprise")
    {
        return Ok(None);
    }
    request
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
        .map(Some)
        .ok_or_else(|| Status::unauthenticated("enterprise execution credential rejected"))
}

fn enterprise_execution_authority(
    context: Option<&crate::enterprise::AuthenticatedContext>,
) -> Option<String> {
    context.map(|context| match context.tenant.as_ref() {
        Some(tenant) => format!("tenant:{}", tenant.tenant_id),
        None => format!("credential:{}", context.principal.credential_id),
    })
}

fn required_authenticated_actor<T>(request: &Request<T>) -> Result<String, Status> {
    request
        .metadata()
        .get("x-principal")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Status::unauthenticated("authenticated principal required"))
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

fn required_lookup_promotion_admin<T>(request: &Request<T>) -> Result<String, Status> {
    let source = auth_source(request)
        .ok_or_else(|| Status::unauthenticated("authenticated request source required"))?;
    let metadata_actor = required_authenticated_actor(request)?;
    let actor = if let Some(context) = request
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        if context.principal.subject != metadata_actor {
            return Err(Status::unauthenticated(
                "authenticated principal does not match request context",
            ));
        }
        context.principal.subject.clone()
    } else if source == "local" {
        metadata_actor
    } else {
        return Err(Status::unauthenticated(
            "authenticated request context required",
        ));
    };
    if matches!(actor.as_str(), "root" | "local") {
        Ok(actor)
    } else {
        Err(Status::permission_denied(
            "evaluation mutation requires control-plane administration",
        ))
    }
}

fn require_eval_reader<T>(request: &Request<T>, config: &Config) -> Result<(), Status> {
    let actor = authenticated_actor(request);
    if matches!(actor.as_str(), "root" | "local" | "chisei-gateway")
        || config
            .gateway_receipt_principals
            .iter()
            .any(|principal| principal == &actor)
    {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "evaluation reads require an authorized service principal",
        ))
    }
}

fn require_telemetry_reader<T>(request: &Request<T>, config: &Config) -> Result<String, Status> {
    let actor = authenticated_actor(request);
    let allowed = matches!(actor.as_str(), "root" | "local" | "chisei-gateway")
        || config
            .gateway_receipt_principals
            .iter()
            .any(|principal| principal == &actor);
    if allowed {
        Ok(actor)
    } else {
        Err(Status::permission_denied(
            "telemetry readback requires an authorized service principal",
        ))
    }
}

fn require_control_plane_admin<T>(request: &Request<T>, mutation: &str) -> Result<(), Status> {
    if matches!(authenticated_actor(request).as_str(), "root" | "local") {
        Ok(())
    } else {
        Err(Status::permission_denied(format!(
            "{mutation} requires control-plane administration"
        )))
    }
}

fn canonical_namespace(namespace: &str) -> Result<&str, Status> {
    let canonical = namespace.trim();
    if canonical.is_empty() {
        return Err(Status::invalid_argument("namespace required"));
    }
    if canonical != namespace {
        return Err(Status::invalid_argument(
            "namespace must not contain leading or trailing whitespace",
        ));
    }
    Ok(canonical)
}

fn content_version(value: &impl serde::Serialize) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(value).unwrap_or_default());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(serde::Serialize)]
struct SampleObservationReadbackDigest<'a> {
    version: &'static str,
    request_id: &'a str,
    namespace: &'a str,
    state: &'a str,
    observed_at: i64,
}

fn sample_observation_readback_digest(
    request_id: &str,
    namespace: &str,
    state: &str,
    observed_at: i64,
) -> String {
    let projection = SampleObservationReadbackDigest {
        version: "chisei.sample_observation.readback.v1",
        request_id,
        namespace,
        state,
        observed_at,
    };
    format!("sha256:{}", content_version(&projection))
}

fn external_request_from_proto(request: ExternalActionRequest) -> external::ExternalActionRequest {
    external::ExternalActionRequest {
        version: request.version,
        operation_id: request.operation_id,
        parent_operation_id: request.parent_operation_id,
        attempt_id: request.attempt_id,
        request_id: request.request_id,
        actor: request.actor,
        namespace: request.namespace,
        requesting_harness: request.requesting_harness,
        intended_executor: request.intended_executor,
        action_type: request.action_type,
        parameter_schema: request.parameter_schema,
        canonical_arguments_digest: request.canonical_arguments_digest,
        policy_summary: request.policy_summary.into_iter().collect(),
        target_selectors: request.target_selectors,
        immutable_preconditions: request.immutable_preconditions.into_iter().collect(),
        risk_class: request.risk_class,
        expected_effects: request.expected_effects,
        requested_invocation_count: request.requested_invocation_count,
        deadline_ms: request.deadline_ms,
        estimated_cost_micros: request.estimated_cost_micros,
        estimated_volume: request.estimated_volume,
        affected_resource_count: request.affected_resource_count,
        rollback_capability: request.rollback_capability,
        required_host_capabilities: request.required_host_capabilities,
        idempotency_key: request.idempotency_key,
        policy_project: request.policy_project,
    }
}

fn external_decision_to_proto(
    decision: &external::ExternalActionDecision,
) -> ExternalActionDecision {
    ExternalActionDecision {
        version: decision.version.clone(),
        authorization_id: decision.authorization_id.clone(),
        request_digest: decision.request_digest.clone(),
        decision: decision.decision.clone(),
        reason: decision.reason.clone(),
        approval_id: decision.approval_id.clone(),
        policy_scope: decision.policy_scope.clone(),
        policy_version: decision.policy_version.clone(),
        created_at_ms: decision.created_at_ms,
        expires_at_ms: decision.expires_at_ms,
        cancelled_at_ms: decision.cancelled_at_ms,
        assurance: Some(ExternalActionAssuranceDeclaration {
            version: decision.assurance.version.clone(),
            authorization_only: decision.assurance.authorization_only,
            host_must_verify_permit: decision.assurance.host_must_verify_permit,
            host_must_enforce_constraints: decision.assurance.host_must_enforce_constraints,
            physical_effect_verified: decision.assurance.physical_effect_verified,
        }),
        permit: None,
    }
}

fn permit_signing_key(config: &Config) -> Result<ed25519_dalek::SigningKey, Status> {
    permit::signing_key_from_hex(config.permit_signing_key.as_deref().ok_or_else(|| {
        Status::failed_precondition("external-action permit signing is not configured")
    })?)
    .map_err(Status::failed_precondition)
}

fn external_permit_to_proto(value: &permit::Permit) -> ExternalActionPermit {
    ExternalActionPermit {
        version: value.version.clone(),
        permit_id: value.permit_id.clone(),
        authorization_id: value.authorization_id.clone(),
        request_digest: value.request_digest.clone(),
        signature: value.signature.clone(),
        expires_at_ms: value.expires_at_ms,
        constraints: value.constraints.clone(),
        issuer: value.issuer.clone(),
        subject_actor: value.subject_actor.clone(),
        namespace: value.namespace.clone(),
        operation_id: value.operation_id.clone(),
        requesting_harness: value.requesting_harness.clone(),
        executor: value.executor.clone(),
        action_type: value.action_type.clone(),
        parameter_schema: value.parameter_schema.clone(),
        canonical_arguments_digest: value.canonical_arguments_digest.clone(),
        target_selectors: value.target_selectors.clone(),
        immutable_preconditions: value.immutable_preconditions.clone().into_iter().collect(),
        allowed_effects: value.allowed_effects.clone(),
        risk_class: value.risk_class.clone(),
        budget_micros: value.budget_micros,
        volume_limit: value.volume_limit,
        blast_radius_limit: value.blast_radius_limit,
        max_invocations: value.max_invocations,
        not_before_ms: value.not_before_ms,
        redemption_mode: value.redemption_mode.clone(),
        approval_identities: value.approval_identities.clone(),
        policy_version: value.policy_version.clone(),
        schema_version: value.schema_version.clone(),
        capability_version: value.capability_version.clone(),
        pricing_version: value.pricing_version.clone(),
        nonce: value.nonce.clone(),
        delegation_depth: value.delegation_depth,
        parent_permit_id: value.parent_permit_id.clone(),
        revocation_handle: value.revocation_handle.clone(),
        signature_algorithm: value.signature_algorithm.clone(),
        key_id: value.key_id.clone(),
        signed_digest: value.signed_digest.clone(),
        public_key: value.public_key.clone(),
        issued_at_ms: value.issued_at_ms,
        revocation_latency_ms: value.revocation_latency_ms,
        required_host_capabilities: value.required_host_capabilities.clone(),
        parent_chain: value.parent_chain.clone(),
        initiating_actor: value.initiating_actor.clone(),
        offline_revocation_unavailable: value.offline_revocation_unavailable,
        policy_scope: value.policy_scope.clone(),
        site_id: value.site_id.clone(),
    }
}

fn external_permit_from_proto(value: ExternalActionPermit) -> permit::Permit {
    permit::Permit {
        version: value.version,
        permit_id: value.permit_id,
        authorization_id: value.authorization_id,
        request_digest: value.request_digest,
        issuer: value.issuer,
        subject_actor: value.subject_actor,
        namespace: value.namespace,
        operation_id: value.operation_id,
        requesting_harness: value.requesting_harness,
        executor: value.executor,
        action_type: value.action_type,
        parameter_schema: value.parameter_schema,
        canonical_arguments_digest: value.canonical_arguments_digest,
        target_selectors: value.target_selectors,
        immutable_preconditions: value.immutable_preconditions.into_iter().collect(),
        allowed_effects: value.allowed_effects,
        required_host_capabilities: value.required_host_capabilities,
        parent_chain: value.parent_chain,
        initiating_actor: value.initiating_actor,
        offline_revocation_unavailable: value.offline_revocation_unavailable,
        policy_scope: value.policy_scope,
        constraints: value.constraints,
        risk_class: value.risk_class,
        budget_micros: value.budget_micros,
        volume_limit: value.volume_limit,
        blast_radius_limit: value.blast_radius_limit,
        max_invocations: value.max_invocations,
        not_before_ms: value.not_before_ms,
        expires_at_ms: value.expires_at_ms,
        redemption_mode: value.redemption_mode,
        approval_identities: value.approval_identities,
        policy_version: value.policy_version,
        schema_version: value.schema_version,
        capability_version: value.capability_version,
        pricing_version: value.pricing_version,
        nonce: value.nonce,
        delegation_depth: value.delegation_depth,
        parent_permit_id: value.parent_permit_id,
        revocation_handle: value.revocation_handle,
        signature_algorithm: value.signature_algorithm,
        key_id: value.key_id,
        public_key: value.public_key,
        issued_at_ms: value.issued_at_ms,
        revocation_latency_ms: value.revocation_latency_ms,
        site_id: if value.site_id.trim().is_empty() {
            crate::sekai::lease::DEFAULT_SITE_ID.into()
        } else {
            value.site_id
        },
        signed_digest: value.signed_digest,
        signature: value.signature,
    }
}

fn external_permit_policy_to_proto(value: &permit::ExternalPermitPolicy) -> ExternalPermitPolicy {
    ExternalPermitPolicy {
        scope: value.scope.clone(),
        offline_action_types: value.offline_action_types.clone(),
        offline_max_duration_ms: value.offline_max_duration_ms,
        offline_max_invocations: value.offline_max_invocations,
        permitted_delegators: value.permitted_delegators.clone(),
        max_delegation_depth: value.max_delegation_depth,
    }
}

fn external_host_context(
    executor: String,
    harness: String,
    digest: String,
    targets: Vec<String>,
    preconditions: HashMap<String, String>,
    capabilities: Vec<String>,
) -> permit::HostContext {
    permit::HostContext {
        executor,
        requesting_harness: harness,
        canonical_arguments_digest: digest,
        target_selectors: targets,
        observed_preconditions: preconditions.into_iter().collect(),
        host_capabilities: capabilities,
    }
}

fn external_policy_version(policy: Option<&crate::sekai::action_policy::ActionPolicy>) -> String {
    let canonical: BTreeMap<String, String> = policy
        .map(|policy| policy.to_properties().into_iter().collect())
        .unwrap_or_default();
    content_version(&canonical)
}

fn external_audit_evidence(record: &external::AuthorizationRecord) -> HashMap<String, String> {
    HashMap::from([
        (
            "authorization_id".into(),
            record.decision.authorization_id.clone(),
        ),
        (
            "request_digest".into(),
            record.decision.request_digest.clone(),
        ),
        ("namespace".into(), record.request.namespace.clone()),
        ("action_type".into(), record.request.action_type.clone()),
        ("risk_class".into(), record.request.risk_class.clone()),
        ("decision".into(), record.decision.decision.clone()),
        ("policy_scope".into(), record.decision.policy_scope.clone()),
        (
            "policy_version".into(),
            record.decision.policy_version.clone(),
        ),
    ])
}

fn ensure_external_action_audit(
    db: &RuntimeDb,
    record: &external::AuthorizationRecord,
) -> Result<(), Status> {
    let lifecycle = if record.approval_status.is_empty() {
        record.decision.decision.as_str()
    } else {
        record.approval_status.as_str()
    };
    db.record_decisions_idempotently(&[crate::sekai::audit::Decision {
        id: format!("{}:audit:{}", record.decision.authorization_id, lifecycle),
        timestamp: record.decision_updated_at_ms,
        actor: record.decision_actor.clone(),
        action: format!("external_action/{}", record.request.action_type),
        reason: format!("external_action_authorization_{lifecycle}"),
        evidence: external_audit_evidence(record),
        target_id: record.decision.authorization_id.clone(),
        outcome: record.decision.decision.clone(),
    }])
    .map_err(Status::internal)
}

fn external_budget_scope(request: &external::ExternalActionRequest) -> String {
    format!(
        "project:{}/agent:{}/external-action:{}",
        request.namespace, request.actor, request.risk_class
    )
}

fn issue_external_permit(
    service: &ChiseiServiceImpl,
    authorization: &external::AuthorizationRecord,
    actor: &str,
    idempotency_key: &str,
    offline: bool,
) -> Result<permit::Permit, Status> {
    if idempotency_key.trim().is_empty() {
        return Err(Status::invalid_argument("idempotency_key required"));
    }
    if actor != authorization.request.actor && !matches!(actor, "root" | "local") {
        return Err(Status::permission_denied("permit issuance denied"));
    }
    require_namespace_write_access(&service.db, actor, &authorization.request.namespace)?;
    if let Some(value) = service
        .db
        .replay_permit(&authorization.decision.authorization_id, idempotency_key)
        .map_err(|error| {
            if error.contains("different idempotency") {
                Status::already_exists(error)
            } else {
                Status::internal(error)
            }
        })?
    {
        let requested_mode = if offline {
            permit::OFFLINE_REDEMPTION_MODE
        } else {
            permit::REDEMPTION_MODE
        };
        if value.redemption_mode != requested_mode {
            return Err(Status::already_exists(
                "authorization already issued with a different redemption mode",
            ));
        }
        return Ok(value);
    }
    let key = permit_signing_key(&service.config)?;
    let approvals = if authorization.approval_status == "approved" {
        vec![authorization.decision_actor.clone()]
    } else {
        Vec::new()
    };
    let issuance = permit::Issuance {
        approval_identities: approvals,
        issuer: &service.config.permit_issuer,
        key_id: &service.config.permit_key_id,
        permit_id: format!("permit-{}", uuid::Uuid::new_v4().simple()),
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        now_ms: chrono::Utc::now().timestamp_millis(),
        site_id: &service.config.site_id,
    };
    let value = if offline {
        let policy = service
            .db
            .get_external_permit_policy(&authorization.decision.policy_scope)
            .map_err(Status::internal)?;
        permit::issue_offline(authorization, &policy, &key, issuance)
    } else {
        permit::issue(authorization, &key, issuance)
    }
    .map_err(Status::failed_precondition)?;
    service
        .db
        .put_permit(&value, idempotency_key, actor)
        .map_err(|error| {
            if error.contains("different idempotency") {
                Status::already_exists(error)
            } else {
                Status::internal(error)
            }
        })
}

fn persist_gateway_operation_receipt(
    service: &ChiseiServiceImpl,
    receipt_json: &str,
    authenticated_principal: &str,
) -> Result<(), Status> {
    let receipt: OperationReceipt = serde_json::from_str(receipt_json)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    let completeness = receipt.completeness();
    if !completeness.complete {
        return Err(Status::invalid_argument(format!(
            "gateway receipt is incomplete: missing={:?} errors={:?}",
            completeness.missing_surfaces, completeness.errors
        )));
    }
    let now = chrono::Utc::now().timestamp_millis();
    let has_kioku_context = receipt.events.iter().any(|receipt_event| {
        receipt_event.kind == ReceiptEventKind::ContextGoverned
            && receipt_event
                .references
                .iter()
                .any(|reference| reference.kind == "kioku_memory" && !reference.omitted)
    }) || !service
        .db
        .list_kioku_outcome_assignments(&receipt.operation_id)
        .map_err(Status::internal)?
        .is_empty();
    let existing = service
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
            &service.db,
            &receipt,
            authenticated_principal,
            now,
            false,
            None,
            true,
        )
        .map_err(|error| {
            Status::invalid_argument(format!("Kioku outcome attribution invalid: {error}"))
        })?;
    }
    service
        .db
        .put_operation_receipt(&receipt)
        .map_err(Status::internal)?;
    if existing.is_none()
        && has_kioku_context
        && let Err(error) = record_reported_memory_outcomes(
            &service.db,
            &receipt,
            authenticated_principal,
            now,
            false,
            None,
            false,
        )
    {
        let _ = service.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now,
            actor: "chisei.kioku".into(),
            action: "kioku.outcome_attribution".into(),
            reason: error,
            evidence: HashMap::from([("operation_id".into(), receipt.operation_id.clone())]),
            target_id: receipt.operation_id.clone(),
            outcome: "failed".into(),
        });
    }
    service
        .db
        .record_decisions_idempotently(&[crate::sekai::audit::Decision {
            id: format!("{}:gateway-receipt", receipt.operation_id),
            timestamp: now,
            actor: authenticated_principal.into(),
            action: GATEWAY_RECEIPT_ACTION.into(),
            reason: "gateway operation completed".into(),
            evidence: HashMap::from([("operation_id".into(), receipt.operation_id.clone())]),
            target_id: receipt.operation_id,
            outcome: "recorded".into(),
        }])
        .map_err(Status::internal)
}

fn release_external_reservations(
    db: &RuntimeDb,
    budget: &BudgetTracker,
    record: &mut external::AuthorizationRecord,
) -> Result<(), Status> {
    let units = i32::try_from(record.request.requested_invocation_count).unwrap_or(i32::MAX);
    if record.budget_reserved {
        budget
            .record_idempotent_with_metric(
                &external_budget_scope(&record.request),
                -units,
                METRIC_TOKENS,
                &format!(
                    "external-action-release:{}",
                    record.decision.authorization_id
                ),
            )
            .map_err(Status::internal)?;
        record.budget_reserved = false;
    }
    if record.blast_radius_reserved {
        db.release_external_action_blast_radius(&record.decision.authorization_id, &record.request)
            .map_err(Status::internal)?;
        record.blast_radius_reserved = false;
    }
    Ok(())
}

fn persist_released_external_flags(
    db: &RuntimeDb,
    reserved: &external::AuthorizationRecord,
    released: &external::AuthorizationRecord,
) -> Result<(), Status> {
    if reserved != released {
        let _ = db
            .compare_and_swap_external_action_authorization(reserved, released)
            .map_err(Status::internal)?;
    }
    Ok(())
}

fn reclaim_expired_external_action_reservations(
    db: &RuntimeDb,
    budget: &BudgetTracker,
    now_ms: i64,
) -> Result<(), Status> {
    for expected in db
        .list_external_action_authorizations()
        .map_err(Status::internal)?
        .into_iter()
        .filter(|record| {
            (record.budget_reserved || record.blast_radius_reserved)
                && record.decision.expires_at_ms <= now_ms
        })
    {
        let mut expired = expected.clone();
        expired.decision.decision = "deny".into();
        expired.decision.reason = "external-action authorization expired".into();
        expired.approval_status = "expired".into();
        expired.decision_actor = "chisei.external_action_expiry".into();
        expired.decision_updated_at_ms = now_ms;
        if db
            .compare_and_swap_external_action_authorization(&expected, &expired)
            .map_err(Status::internal)?
        {
            let reserved = expired.clone();
            release_external_reservations(db, budget, &mut expired)?;
            persist_released_external_flags(db, &reserved, &expired)?;
            ensure_external_action_audit(db, &expired)?;
        }
    }
    Ok(())
}

fn require_namespace_access(db: &RuntimeDb, actor: &str, namespace: &str) -> Result<(), Status> {
    let namespace = canonical_namespace(namespace)?;
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    let boundary = db
        .find_namespace_boundary(namespace)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::permission_denied("namespace access denied"))?;
    let granted = db
        .list_grants(&boundary.id)
        .map_err(Status::internal)?
        .into_iter()
        .any(|grant| grant.principal == actor);
    if granted {
        Ok(())
    } else {
        Err(Status::permission_denied("namespace access denied"))
    }
}

fn require_namespace_write_access(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
) -> Result<(), Status> {
    let namespace = canonical_namespace(namespace)?;
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    let boundary = db
        .find_namespace_boundary(namespace)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::permission_denied("namespace write access denied"))?;
    let granted = db
        .list_grants(&boundary.id)
        .map_err(Status::internal)?
        .into_iter()
        .any(|grant| {
            grant.principal == actor
                && matches!(
                    grant.role,
                    crate::sekai::security::Role::Editor | crate::sekai::security::Role::Admin
                )
        });
    if granted {
        Ok(())
    } else {
        Err(Status::permission_denied("namespace write access denied"))
    }
}

fn require_external_project_access(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    project: &str,
) -> Result<(), Status> {
    if project == namespace {
        return Ok(());
    }
    let project_object = db
        .find_by_external_id(&format!("project:{project}"))
        .map_err(Status::internal)?
        .filter(|object| object.namespace == namespace)
        .ok_or_else(|| Status::permission_denied("external-action project access denied"))?;
    if matches!(actor, "root" | "local") {
        return Ok(());
    }
    let granted = db
        .list_grants(&project_object.id)
        .map_err(Status::internal)?
        .into_iter()
        .any(|grant| {
            grant.principal == actor
                && matches!(
                    grant.role,
                    crate::sekai::security::Role::Editor | crate::sekai::security::Role::Admin
                )
        });
    if granted {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "external-action project access denied",
        ))
    }
}

fn require_team_namespace_access<T>(
    db: &RuntimeDb,
    _config: &Config,
    request: &Request<T>,
    namespace: &str,
) -> Result<(), Status> {
    let actor = authenticated_actor(request);
    let trusted_service = matches!(actor.as_str(), "root" | "local" | "chisei-gateway");
    if trusted_service {
        return Ok(());
    }
    let boundary = db
        .find_namespace_boundary(namespace)
        .map_err(Status::internal)?;
    let team_managed_namespace = boundary.as_ref().is_some_and(|object| {
        object
            .properties
            .get("team_managed")
            .is_some_and(|value| value == "true")
    });
    if team_managed_namespace || db.is_team_principal(&actor).map_err(Status::internal)? {
        require_namespace_access(db, &actor, namespace)?;
    }
    Ok(())
}

fn encode_kioku_candidate_page_token(
    namespace: &str,
    operation_class: &str,
    cursor: &crate::chisei::kioku::KiokuCandidateCursor,
) -> String {
    let token = serde_json::json!({
        "namespace": namespace,
        "operation_class": operation_class,
        "id": cursor.id,
        "version": cursor.version,
    });
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&token).expect("Kioku candidate page token is serializable"))
}

fn require_execution_namespace_access(
    db: &RuntimeDb,
    _config: &Config,
    actor: &str,
    namespace: &str,
) -> Result<(), Status> {
    if actor == "chisei-gateway" {
        canonical_namespace(namespace).map(|_| ())
    } else {
        require_namespace_access(db, actor, namespace)
    }
}

fn require_execution_namespace_access_with_context(
    db: &RuntimeDb,
    config: &Config,
    actor: &str,
    context: Option<&crate::enterprise::AuthenticatedContext>,
    namespace: &str,
) -> Result<(), Status> {
    if let Some(context) = context {
        let scope_permitted = match context.credential_kind {
            crate::enterprise::CredentialKind::Machine => context
                .scopes
                .iter()
                .any(|scope| scope == CHISEI_EXECUTE_SCOPE),
            crate::enterprise::CredentialKind::HumanSession => {
                context.scopes.iter().any(|scope| scope == "sekai.write")
            }
        };
        if !scope_permitted {
            return Err(Status::permission_denied(
                "enterprise execution authorization denied",
            ));
        }
        let extension = db
            .enterprise_extension()
            .ok_or_else(|| Status::unauthenticated("enterprise execution credential rejected"))?;
        canonical_namespace(namespace)?;
        return extension
            .authorize_authenticated_context(
                context,
                namespace,
                crate::enterprise::NamespaceAction::Write,
            )
            .map_err(enterprise_execution_status);
    }
    require_execution_namespace_access(db, config, actor, namespace)
}

fn enterprise_execution_status(error: crate::enterprise::ExtensionError) -> Status {
    match error {
        crate::enterprise::ExtensionError::CredentialNotFound
        | crate::enterprise::ExtensionError::Unauthenticated
        | crate::enterprise::ExtensionError::Expired
        | crate::enterprise::ExtensionError::Revoked
        | crate::enterprise::ExtensionError::Replayed
        | crate::enterprise::ExtensionError::IssuerMismatch
        | crate::enterprise::ExtensionError::ResourceMismatch => {
            Status::unauthenticated("enterprise execution credential rejected")
        }
        crate::enterprise::ExtensionError::PermissionDenied
        | crate::enterprise::ExtensionError::MembershipRevoked
        | crate::enterprise::ExtensionError::TenantSuspended
        | crate::enterprise::ExtensionError::InvalidState
        | crate::enterprise::ExtensionError::InvalidNonce
        | crate::enterprise::ExtensionError::InvalidRedirectUri
        | crate::enterprise::ExtensionError::InvalidPkce => {
            Status::permission_denied("enterprise execution authorization denied")
        }
        crate::enterprise::ExtensionError::UnsupportedVersion => {
            Status::failed_precondition("unsupported enterprise identity contract version")
        }
        crate::enterprise::ExtensionError::Unavailable(_) => {
            Status::unavailable("enterprise execution authorization unavailable")
        }
    }
}

fn execution_budget_scope(namespace: &str, actor: &str, requested_user_id: &str) -> String {
    if matches!(actor, "root" | "local") {
        return if requested_user_id.trim().is_empty() {
            "default"
        } else {
            requested_user_id.trim()
        }
        .to_string();
    }
    format!("project:{}/agent:{}", namespace.trim(), actor.trim())
}

fn strongest_pressure(
    left: crate::chisei::budget::PressureLevel,
    right: crate::chisei::budget::PressureLevel,
) -> crate::chisei::budget::PressureLevel {
    use crate::chisei::budget::PressureLevel;
    match (left, right) {
        (PressureLevel::Critical, _) | (_, PressureLevel::Critical) => PressureLevel::Critical,
        (PressureLevel::Moderate, _) | (_, PressureLevel::Moderate) => PressureLevel::Moderate,
        _ => PressureLevel::None,
    }
}

fn execution_context_actor(
    db: &RuntimeDb,
    _config: &Config,
    actor: &str,
    delegated: Option<&str>,
    namespace: &str,
) -> Result<String, Status> {
    let Some(delegated) = delegated.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(actor.to_string());
    };
    if actor != "chisei-gateway" {
        return Err(Status::permission_denied(
            "delegated execution identity requires a gateway service principal",
        ));
    }
    if db.is_team_principal(delegated).map_err(Status::internal)? {
        require_namespace_access(db, delegated, namespace)?;
        Ok(delegated.to_string())
    } else {
        Ok(actor.to_string())
    }
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
        descriptor: Some(epistemic_descriptor_to_pb(&reference.descriptor)),
    }
}

fn epistemic_descriptor_to_pb(
    descriptor: &crate::chisei::epistemic_descriptor::EpistemicDescriptor,
) -> super::pb::chisei::EpistemicDescriptor {
    debug_assert!(descriptor.validate().is_ok());
    super::pb::chisei::EpistemicDescriptor {
        contract_version: descriptor.contract_version.clone(),
        origin_class: descriptor.origin_class.as_str().into(),
        evidence_status: descriptor.evidence_status.as_str().into(),
        lifecycle_status: descriptor.lifecycle_status.as_str().into(),
        producer_confidence_bps: descriptor.producer_confidence_bps.map(u32::from),
        confidence_basis: descriptor.confidence_basis.clone().unwrap_or_default(),
        observed_at_ms: descriptor.observed_at_ms,
        derivation_ref: descriptor.derivation_ref.clone().unwrap_or_default(),
        source_refs: descriptor.source_refs.clone(),
        source_digests: descriptor.source_digests.clone(),
        source_row_count: descriptor.source_row_count,
        source_rows_truncated: descriptor.source_rows_truncated,
        supporting_evidence_count: descriptor.supporting_evidence_count,
        contradicting_evidence_count: descriptor.contradicting_evidence_count,
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
        descriptor: Some(epistemic_descriptor_to_pb(&reference.descriptor)),
    }
}

fn context_bytes(system: &str, messages: &[ChatMessage]) -> u64 {
    let message_bytes = messages
        .iter()
        .map(|message| {
            let tool_call_bytes = message
                .tool_calls
                .iter()
                .map(|tool_call| {
                    (tool_call.id.len() + tool_call.name.len() + tool_call.args_json.len()) as u64
                })
                .fold(0_u64, u64::saturating_add);
            ((message.role.len() + message.content.len() + message.tool_call_id.len()) as u64)
                .saturating_add(tool_call_bytes)
        })
        .fold(0_u64, u64::saturating_add);
    (system.len() as u64).saturating_add(message_bytes)
}

fn estimate_context_tokens(system: &str, messages: &[ChatMessage]) -> u64 {
    context_bytes(system, messages).div_ceil(4)
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

fn epistemic_descriptor_receipt_attributes(plan: &ExecutionPlan) -> BTreeMap<String, String> {
    let descriptors = plan
        .evidence_references
        .iter()
        .filter_map(|reference| reference.descriptor.as_ref())
        .chain(
            plan.memory_references
                .iter()
                .filter_map(|reference| reference.descriptor.as_ref()),
        )
        .collect::<Vec<_>>();
    let source_rows = descriptors
        .iter()
        .filter_map(|descriptor| descriptor.source_row_count)
        .map(u64::from)
        .sum::<u64>();
    let source_refs = descriptors
        .iter()
        .map(|descriptor| descriptor.source_refs.len() as u64)
        .sum::<u64>();
    let source_digests = descriptors
        .iter()
        .map(|descriptor| descriptor.source_digests.len() as u64)
        .sum::<u64>();
    let truncated = descriptors
        .iter()
        .any(|descriptor| descriptor.source_rows_truncated);
    let mut evidence_status_counts = BTreeMap::<String, u64>::new();
    let mut lifecycle_status_counts = BTreeMap::<String, u64>::new();
    for descriptor in &descriptors {
        *evidence_status_counts
            .entry(descriptor.evidence_status.clone())
            .or_default() += 1;
        *lifecycle_status_counts
            .entry(descriptor.lifecycle_status.clone())
            .or_default() += 1;
    }
    let encode_counts = |counts: &BTreeMap<String, u64>| {
        counts
            .iter()
            .map(|(status, count)| format!("{status}={count}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut attributes = BTreeMap::from([
        (
            "epistemic_accounting_version".into(),
            "chisei.epistemic-context-operations/v1".into(),
        ),
        (
            "epistemic_descriptor_version".into(),
            EPISTEMIC_DESCRIPTOR_VERSION.into(),
        ),
        (
            "epistemic_descriptor_count".into(),
            descriptors.len().min(128).to_string(),
        ),
        (
            "epistemic_descriptor_source_rows".into(),
            source_rows.min(128 * 128).to_string(),
        ),
        (
            "epistemic_descriptor_source_refs".into(),
            source_refs.min(128 * 8).to_string(),
        ),
        (
            "epistemic_descriptor_source_digests".into(),
            source_digests.min(128 * 8).to_string(),
        ),
        (
            "epistemic_descriptor_source_rows_truncated".into(),
            truncated.to_string(),
        ),
        (
            "epistemic_evidence_status_counts".into(),
            encode_counts(&evidence_status_counts),
        ),
        (
            "epistemic_lifecycle_status_counts".into(),
            encode_counts(&lifecycle_status_counts),
        ),
        (
            "epistemic_context_bytes".into(),
            plan.context_bytes.to_string(),
        ),
        (
            "epistemic_context_tokens".into(),
            plan.context_tokens.to_string(),
        ),
        (
            "epistemic_projection_latency_ms".into(),
            plan.context_projection_latency_ms.to_string(),
        ),
        (
            "epistemic_context_truncated".into(),
            plan.context_truncated.to_string(),
        ),
    ]);
    if !plan.context_admission_policy_version.is_empty() {
        attributes.insert(
            "context_admission_policy_version".into(),
            plan.context_admission_policy_version.clone(),
        );
        attributes.insert(
            "context_admission_descriptor_version".into(),
            plan.context_admission_descriptor_version.clone(),
        );
    }
    if !plan.context_admission_decision.is_empty() {
        attributes.insert(
            "context_admission_decision".into(),
            plan.context_admission_decision.clone(),
        );
        attributes.insert(
            "context_admission_reasons".into(),
            plan.context_admission_reasons.join(","),
        );
        attributes.insert(
            "context_admission_source_digests".into(),
            plan.context_admission_source_digests.join(","),
        );
    }
    attributes
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

/// Complete an operation that was fully answered by structured lookup (#281).
/// Records `answer_path=lookup_hit`, zero provider tokens, and no billable model call.
#[allow(clippy::too_many_arguments)]
fn record_completed_lookup_operation_on(
    db: &RuntimeDb,
    plan: &ExecutionPlan,
    actor: &str,
    response: &PlannedChatResponse,
    attempt_started_at_ms: i64,
    completed_at_ms: i64,
    capability: &str,
    provenance: &BTreeMap<String, String>,
) -> Result<(), String> {
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
        let mut artifact_attrs = BTreeMap::from([
            ("artifact_type".into(), "structured_lookup".into()),
            ("content_hash".into(), planned_response_hash(response)),
            ("content_stored".into(), "false".into()),
            (
                crate::chisei::lookup_first::ANSWER_PATH_ATTR.into(),
                crate::chisei::lookup_first::ANSWER_PATH_LOOKUP_HIT.into(),
            ),
            ("capability".into(), capability.into()),
            (
                "provider".into(),
                crate::chisei::lookup_first::LOOKUP_PROVIDER.into(),
            ),
            ("input_tokens".into(), "0".into()),
            ("output_tokens".into(), "0".into()),
        ]);
        for (key, value) in provenance {
            artifact_attrs.insert(format!("provenance_{key}"), value.clone());
        }
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
                "artifact-1",
                Some("attempt-1"),
                completed_at_ms,
                ReceiptEventKind::ArtifactProduced,
                "chisei.lookup_first",
                artifact_attrs,
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
                    (
                        "completion_reason".into(),
                        crate::chisei::lookup_first::LOOKUP_HIT_STOP_REASON.into(),
                    ),
                    (
                        crate::chisei::lookup_first::ANSWER_PATH_ATTR.into(),
                        crate::chisei::lookup_first::ANSWER_PATH_LOOKUP_HIT.into(),
                    ),
                    ("provider_tokens".into(), "0".into()),
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
        // ModelCall remains uncovered by design: zero provider tokens, no adapter call.
        receipt.uncovered_surfaces = vec![UncoveredSurface {
            surface: ReceiptSurface::ModelCall,
            reason: "answered by structured lookup without a provider model call".into(),
        }];
        Ok(())
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_completed_operation_on_with_path(
    db: &RuntimeDb,
    plan: &ExecutionPlan,
    actor: &str,
    response: &PlannedChatResponse,
    attempt_started_at_ms: i64,
    completed_at_ms: i64,
    answer_path: Option<&str>,
    lookup_refusal: Option<&str>,
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
                    if let Some(path) = answer_path {
                        attributes.insert(
                            crate::chisei::lookup_first::ANSWER_PATH_ATTR.into(),
                            path.into(),
                        );
                    }
                    if let Some(reason) = lookup_refusal {
                        attributes.insert(
                            crate::chisei::lookup_first::LOOKUP_REFUSAL_ATTR.into(),
                            reason.into(),
                        );
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
                {
                    let mut attributes = BTreeMap::from([
                        ("status".into(), "succeeded".into()),
                        ("completion_reason".into(), response.stop_reason.clone()),
                        (
                            "latency_ms".into(),
                            completed_at_ms
                                .saturating_sub(receipt.started_at_ms)
                                .to_string(),
                        ),
                    ]);
                    if let Some(path) = answer_path {
                        attributes.insert(
                            crate::chisei::lookup_first::ANSWER_PATH_ATTR.into(),
                            path.into(),
                        );
                    }
                    if let Some(reason) = lookup_refusal {
                        attributes.insert(
                            crate::chisei::lookup_first::LOOKUP_REFUSAL_ATTR.into(),
                            reason.into(),
                        );
                    }
                    attributes
                },
            ),
        ]);
        receipt.completed_at_ms = Some(completed_at_ms);
        receipt.uncovered_surfaces.clear();
        Ok(())
    })?;
    Ok(())
}

/// Result of the post-authz lookup-first attempt on ExecutePlanStream.
#[derive(Debug)]
enum ExecuteLookupFirst {
    /// Full structured answer; caller must return without a provider call.
    Hit {
        response: PlannedChatResponse,
        capability: String,
        provenance: BTreeMap<String, String>,
    },
    /// Fail closed to the model path; record `lookup_refusal` on the receipt.
    ModelPath { lookup_refusal: Option<String> },
}

/// After namespace authz, try allow-listed structured lookup before provider routing.
fn evaluate_execute_lookup_first(
    db: &RuntimeDb,
    input: &ExecutionInput,
    actor: &str,
) -> ExecuteLookupFirst {
    if !crate::chisei::lookup_first::is_lookup_first_capability(&input.task_type) {
        return ExecuteLookupFirst::ModelPath {
            lookup_refusal: None,
        };
    }
    match crate::chisei::lookup_first::try_lookup_first(
        &input.task_type,
        &input.namespace,
        actor,
        &input.spec,
        db,
    ) {
        Ok(crate::chisei::lookup_first::LookupDecision::Hit {
            answer_json,
            capability,
            provenance,
        }) => {
            crate::chisei::lookup_first::record_lookup_hit();
            ExecuteLookupFirst::Hit {
                response: PlannedChatResponse {
                    content: answer_json,
                    tool_calls: Vec::new(),
                    input_tokens: 0,
                    output_tokens: 0,
                    stop_reason: crate::chisei::lookup_first::LOOKUP_HIT_STOP_REASON.into(),
                    provider: crate::chisei::lookup_first::LOOKUP_PROVIDER.into(),
                    cache_read_input_tokens: 0,
                    cache_creation_input_tokens: 0,
                },
                capability,
                provenance,
            }
        }
        Ok(crate::chisei::lookup_first::LookupDecision::Refusal { reason, .. }) => {
            crate::chisei::lookup_first::record_model_path(true);
            ExecuteLookupFirst::ModelPath {
                lookup_refusal: Some(reason),
            }
        }
        Ok(crate::chisei::lookup_first::LookupDecision::NotEligible) => {
            ExecuteLookupFirst::ModelPath {
                lookup_refusal: None,
            }
        }
        Err(error) => {
            crate::chisei::lookup_first::record_model_path(true);
            ExecuteLookupFirst::ModelPath {
                lookup_refusal: Some(format!("storage_error:{error}")),
            }
        }
    }
}

fn native_execution_cost(
    plan: &ExecutionPlan,
    response: &PlannedChatResponse,
    pricing: &HashMap<String, crate::pricing::ModelPricing>,
) -> Option<i64> {
    let (priced_model, rates) =
        crate::pricing::lookup_pricing_entry(pricing, &plan.resolved_model)?;
    crate::cost_estimate::cost_usd_micros(
        priced_model,
        rates,
        i64::from(response.input_tokens),
        i64::from(response.output_tokens),
        i64::from(response.cache_read_input_tokens),
        i64::from(response.cache_creation_input_tokens),
    )
}

fn record_failed_operation_on(
    db: &RuntimeDb,
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

struct GatewayPipelineInput<'a> {
    actor: &'a str,
    delegated_principal: Option<&'a str>,
    request_id: &'a str,
    namespace: &'a str,
    spec: &'a str,
    model: &'a str,
    runtime: &'a str,
    task_class: &'a str,
}

struct GatewayPipelineDecision {
    run: pipe::RunResult,
    sampling: crate::chisei::sampling::SamplingDecision,
}

struct FinishStreamedExecution<'a> {
    db: &'a RuntimeDb,
    evolve_history: &'a Arc<Mutex<HashMap<String, crate::chisei::evolve::TaskRecord>>>,
    request_id: &'a str,
    namespace: &'a str,
    enriched_spec: &'a str,
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
    status: &'a str,
    tokens_used: i32,
}

fn record_evolve_task_on(
    db: &RuntimeDb,
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
            created: chrono::Utc::now().timestamp(),
        });
    entry.namespace = task.namespace.to_string();
    entry.spec = task.spec.to_string();
    entry.status = task.status.to_string();
    entry.tokens_used = task.tokens_used;
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

fn persist_namespace_policy(
    db: &RuntimeDb,
    namespace: &str,
    policy: &Policy,
    context_admission_policy: Option<&crate::chisei::policy::ContextAdmissionPolicy>,
) -> Result<(), String> {
    let now = chrono::Utc::now().timestamp_millis();
    let external_id = format!("policy:{namespace}");
    let mut properties = policy_properties(policy, context_admission_policy);
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

fn from_proto_evaluator_definition(
    value: EvaluatorDefinition,
) -> Result<evaluation_plan_domain::EvaluatorDefinition, Status> {
    let limits = value
        .resource_limits
        .ok_or_else(|| Status::invalid_argument("evaluator resource_limits required"))?;
    Ok(evaluation_plan_domain::EvaluatorDefinition {
        contract_version: value.contract_version,
        definition_id: value.definition_id,
        namespace: value.namespace,
        evaluator_id: value.evaluator_id,
        version: value.version,
        implementation_digest: value.implementation_digest,
        execution_class: value.execution_class,
        supported_predicate_kinds: value.supported_predicate_kinds,
        supported_input_schemas: value.supported_input_schemas,
        supported_result_schemas: value.supported_result_schemas,
        parameter_schema_json: value.parameter_schema_json,
        evidence_classifications: value.evidence_classifications,
        resource_limits: evaluation_plan_domain::EvaluatorResourceLimits {
            timeout_ms: limits.timeout_ms,
            max_input_bytes: limits.max_input_bytes,
            max_output_bytes: limits.max_output_bytes,
            max_evidence_items: limits.max_evidence_items,
        },
        adapter_endpoint: value.adapter_endpoint,
        stochastic_policy: value
            .stochastic_policy
            .map(from_proto_stochastic_evaluator_policy),
        source_ref: value.source_ref,
        content_digest: value.content_digest,
        created_by: value.created_by,
        created_at_ms: value.created_at_ms,
    })
}

fn to_proto_evaluator_definition(
    value: &evaluation_plan_domain::EvaluatorDefinition,
) -> EvaluatorDefinition {
    EvaluatorDefinition {
        contract_version: value.contract_version.clone(),
        definition_id: value.definition_id.clone(),
        namespace: value.namespace.clone(),
        evaluator_id: value.evaluator_id.clone(),
        version: value.version.clone(),
        implementation_digest: value.implementation_digest.clone(),
        execution_class: value.execution_class.clone(),
        supported_predicate_kinds: value.supported_predicate_kinds.clone(),
        supported_input_schemas: value.supported_input_schemas.clone(),
        supported_result_schemas: value.supported_result_schemas.clone(),
        parameter_schema_json: value.parameter_schema_json.clone(),
        evidence_classifications: value.evidence_classifications.clone(),
        resource_limits: Some(EvaluatorResourceLimits {
            timeout_ms: value.resource_limits.timeout_ms,
            max_input_bytes: value.resource_limits.max_input_bytes,
            max_output_bytes: value.resource_limits.max_output_bytes,
            max_evidence_items: value.resource_limits.max_evidence_items,
        }),
        adapter_endpoint: value.adapter_endpoint.clone(),
        stochastic_policy: value
            .stochastic_policy
            .as_ref()
            .map(to_proto_stochastic_evaluator_policy),
        source_ref: value.source_ref.clone(),
        content_digest: value.content_digest.clone(),
        created_by: value.created_by.clone(),
        created_at_ms: value.created_at_ms,
    }
}

fn from_proto_stochastic_evaluator_policy(
    value: StochasticEvaluatorPolicy,
) -> evaluation_plan_domain::StochasticEvaluatorPolicy {
    evaluation_plan_domain::StochasticEvaluatorPolicy {
        provider: value.provider,
        model: value.model,
        prompt_profile: value.prompt_profile,
        prompt_profile_digest: value.prompt_profile_digest,
        result_schema: value.result_schema,
        trial_count: value.trial_count,
        temperature_millis: value.temperature_millis,
        top_p_millionths: value.top_p_millionths,
        seed_supported: value.seed_supported,
        base_seed: value.base_seed,
        aggregation_rule: value.aggregation_rule,
        minimum_mean_score_micros: value.minimum_mean_score_micros,
        minimum_pass_rate_basis_points: value.minimum_pass_rate_basis_points,
        maximum_score_variance_micros_squared: value.maximum_score_variance_micros_squared,
        gate_eligible: value.gate_eligible,
        max_retries_per_trial: value.max_retries_per_trial,
        max_tokens_per_trial: value.max_tokens_per_trial,
        max_total_tokens: value.max_total_tokens,
        egress_policy: value.egress_policy,
        raw_response_retention: value.raw_response_retention,
    }
}

fn to_proto_stochastic_evaluator_policy(
    value: &evaluation_plan_domain::StochasticEvaluatorPolicy,
) -> StochasticEvaluatorPolicy {
    StochasticEvaluatorPolicy {
        provider: value.provider.clone(),
        model: value.model.clone(),
        prompt_profile: value.prompt_profile.clone(),
        prompt_profile_digest: value.prompt_profile_digest.clone(),
        result_schema: value.result_schema.clone(),
        trial_count: value.trial_count,
        temperature_millis: value.temperature_millis,
        top_p_millionths: value.top_p_millionths,
        seed_supported: value.seed_supported,
        base_seed: value.base_seed,
        aggregation_rule: value.aggregation_rule.clone(),
        minimum_mean_score_micros: value.minimum_mean_score_micros,
        minimum_pass_rate_basis_points: value.minimum_pass_rate_basis_points,
        maximum_score_variance_micros_squared: value.maximum_score_variance_micros_squared,
        gate_eligible: value.gate_eligible,
        max_retries_per_trial: value.max_retries_per_trial,
        max_tokens_per_trial: value.max_tokens_per_trial,
        max_total_tokens: value.max_total_tokens,
        egress_policy: value.egress_policy.clone(),
        raw_response_retention: value.raw_response_retention.clone(),
    }
}

fn to_proto_evaluator_availability(
    value: &evaluation_plan_domain::EvaluatorAvailability,
) -> EvaluatorAvailability {
    EvaluatorAvailability {
        definition_id: value.definition_id.clone(),
        state: value.state.clone(),
        superseded_by_definition_id: value.superseded_by_definition_id.clone(),
        reason: value.reason.clone(),
        request_id: value.request_id.clone(),
        request_digest: value.request_digest.clone(),
        changed_by: value.changed_by.clone(),
        changed_at_ms: value.changed_at_ms,
    }
}

fn evaluator_record(
    db: &RuntimeDb,
    definition: &evaluation_plan_domain::EvaluatorDefinition,
    implementation_executable: bool,
    implementation_status: &str,
) -> Result<EvaluatorDefinitionRecord, Status> {
    let availability = db
        .get_evaluator_availability(&definition.definition_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::data_loss("evaluator availability is missing"))?;
    Ok(evaluator_record_with_availability(
        definition,
        &availability,
        implementation_executable,
        implementation_status,
    ))
}

fn evaluator_record_with_availability(
    definition: &evaluation_plan_domain::EvaluatorDefinition,
    availability: &evaluation_plan_domain::EvaluatorAvailability,
    implementation_executable: bool,
    implementation_status: &str,
) -> EvaluatorDefinitionRecord {
    EvaluatorDefinitionRecord {
        definition: Some(to_proto_evaluator_definition(definition)),
        availability: Some(to_proto_evaluator_availability(availability)),
        implementation_executable,
        implementation_status: implementation_status.into(),
    }
}

fn from_proto_evaluation_plan(value: EvaluationPlan) -> evaluation_plan_domain::EvaluationPlan {
    evaluation_plan_domain::EvaluationPlan {
        contract_version: value.contract_version,
        plan_version_id: value.plan_version_id,
        namespace: value.namespace,
        plan_id: value.plan_id,
        version: value.version,
        accepted_subject_profiles: value.accepted_subject_profiles,
        nodes: value
            .nodes
            .into_iter()
            .map(|node| evaluation_plan_domain::EvaluationPlanNode {
                node_id: node.node_id,
                evaluator_definition_id: node.evaluator_definition_id,
                depends_on_node_ids: node.depends_on_node_ids,
                input_bindings: node
                    .input_bindings
                    .into_iter()
                    .map(|binding| evaluation_plan_domain::EvaluationInputBinding {
                        name: binding.name,
                        source_kind: binding.source_kind,
                        schema_id: binding.schema_id,
                    })
                    .collect(),
                parameters_json: node.parameters_json,
                invariant_version_ids: node.invariant_version_ids,
                classification: node.classification,
            })
            .collect(),
        reducer: value.reducer,
        source_ref: value.source_ref,
        content_digest: value.content_digest,
        created_by: value.created_by,
        created_at_ms: value.created_at_ms,
    }
}

fn to_proto_evaluation_plan(value: &evaluation_plan_domain::EvaluationPlan) -> EvaluationPlan {
    EvaluationPlan {
        contract_version: value.contract_version.clone(),
        plan_version_id: value.plan_version_id.clone(),
        namespace: value.namespace.clone(),
        plan_id: value.plan_id.clone(),
        version: value.version.clone(),
        accepted_subject_profiles: value.accepted_subject_profiles.clone(),
        nodes: value
            .nodes
            .iter()
            .map(|node| EvaluationPlanNode {
                node_id: node.node_id.clone(),
                evaluator_definition_id: node.evaluator_definition_id.clone(),
                depends_on_node_ids: node.depends_on_node_ids.clone(),
                input_bindings: node
                    .input_bindings
                    .iter()
                    .map(|binding| EvaluationInputBinding {
                        name: binding.name.clone(),
                        source_kind: binding.source_kind.clone(),
                        schema_id: binding.schema_id.clone(),
                    })
                    .collect(),
                parameters_json: node.parameters_json.clone(),
                invariant_version_ids: node.invariant_version_ids.clone(),
                classification: node.classification.clone(),
            })
            .collect(),
        reducer: value.reducer.clone(),
        source_ref: value.source_ref.clone(),
        content_digest: value.content_digest.clone(),
        created_by: value.created_by.clone(),
        created_at_ms: value.created_at_ms,
    }
}

fn from_proto_evaluation_resolution(
    value: EvaluationResolutionRequest,
) -> evaluation_manifest_domain::EvaluationResolutionRequest {
    evaluation_manifest_domain::EvaluationResolutionRequest {
        contract_version: value.contract_version,
        resolver_version: value.resolver_version,
        namespace: value.namespace,
        request_id: value.request_id,
        plan_version_id: value.plan_version_id,
        subject_profile: value.subject_profile,
        subject_identity: value.subject_identity,
        subject_content_digest: value.subject_content_digest,
        evidence_object_ids: value.evidence_object_ids,
        evaluation_time_ms: value.evaluation_time_ms,
    }
}

fn to_proto_evaluation_manifest(
    value: &evaluation_manifest_domain::ResolvedEvaluationManifest,
) -> ResolvedEvaluationManifest {
    ResolvedEvaluationManifest {
        contract_version: value.contract_version.clone(),
        resolver_version: value.resolver_version.clone(),
        manifest_id: value.manifest_id.clone(),
        manifest_digest: value.manifest_digest.clone(),
        namespace: value.namespace.clone(),
        plan_version_id: value.plan_version_id.clone(),
        plan_digest: value.plan_digest.clone(),
        subject_profile: value.subject_profile.clone(),
        subject_identity: value.subject_identity.clone(),
        subject_content_digest: value.subject_content_digest.clone(),
        invariant_set_id: value.invariant_set_id.clone(),
        invariant_set_digest: value.invariant_set_digest.clone(),
        invariant_profile_digest: value.invariant_profile_digest.clone(),
        evaluation_time_ms: value.evaluation_time_ms,
        resolved_by: value.resolved_by.clone(),
        requirements: value
            .requirements
            .iter()
            .map(|requirement| ResolvedRequirementBinding {
                requirement_version_id: requirement.requirement_version_id.clone(),
                content_digest: requirement.content_digest.clone(),
                provenance_evidence_object_ids: requirement.provenance_evidence_object_ids.clone(),
            })
            .collect(),
        nodes: value
            .nodes
            .iter()
            .map(|node| ResolvedEvaluationNode {
                node_id: node.node_id.clone(),
                evaluator: Some(ResolvedEvaluatorBinding {
                    definition_id: node.evaluator.definition_id.clone(),
                    definition_digest: node.evaluator.definition_digest.clone(),
                    implementation_digest: node.evaluator.implementation_digest.clone(),
                    stochastic_policy: node
                        .evaluator
                        .stochastic_policy
                        .as_ref()
                        .map(to_proto_stochastic_evaluator_policy),
                }),
                depends_on_node_ids: node.depends_on_node_ids.clone(),
                input_bindings: node
                    .input_bindings
                    .iter()
                    .map(|binding| ResolvedInputBinding {
                        name: binding.name.clone(),
                        source_kind: binding.source_kind.clone(),
                        schema_id: binding.schema_id.clone(),
                    })
                    .collect(),
                parameters_json: node.parameters_json.clone(),
                invariants: node
                    .invariants
                    .iter()
                    .map(|invariant| ResolvedInvariantBinding {
                        invariant_version_id: invariant.invariant_version_id.clone(),
                        content_digest: invariant.content_digest.clone(),
                        predicate_kind: invariant.predicate_kind.clone(),
                        input_schema: invariant.input_schema.clone(),
                        result_schema: invariant.result_schema.clone(),
                        evidence_types: invariant.evidence_types.clone(),
                        provenance_evidence_object_ids: invariant
                            .provenance_evidence_object_ids
                            .clone(),
                        waiver_version_ids: invariant.waiver_version_ids.clone(),
                    })
                    .collect(),
                evidence_object_ids: node.evidence_object_ids.clone(),
                classification: node.classification.clone(),
            })
            .collect(),
        evidence: value
            .evidence
            .iter()
            .map(|evidence| ResolvedEvidenceBinding {
                evidence_object_id: evidence.evidence_object_id.clone(),
                submission_id: evidence.submission_id.clone(),
                content_digest: evidence.content_digest.clone(),
                evidence_type: evidence.evidence_type.clone(),
                schema_id: evidence.schema_id.clone(),
                schema_version: evidence.schema_version.clone(),
                classification: evidence.classification.clone(),
                observed_at_ms: evidence.observed_at_ms,
                expires_at_ms: evidence.expires_at_ms,
                source_identity_digest: evidence.source_identity_digest.clone(),
            })
            .collect(),
        waivers: value
            .waivers
            .iter()
            .map(|waiver| ResolvedWaiverBinding {
                waiver_version_id: waiver.waiver_version_id.clone(),
                content_digest: waiver.content_digest.clone(),
                evidence_object_ids: waiver.evidence_object_ids.clone(),
                invariant_version_ids: waiver.invariant_version_ids.clone(),
            })
            .collect(),
        created_at_ms: value.created_at_ms,
    }
}

fn to_proto_evaluation_resolution(
    outcome: &evaluation_manifest_domain::EvaluationResolutionOutcome,
) -> ResolveEvaluationPlanResponse {
    ResolveEvaluationPlanResponse {
        status: outcome.status.clone(),
        manifest: outcome.manifest.as_ref().map(to_proto_evaluation_manifest),
        findings: outcome
            .findings
            .iter()
            .map(|finding| EvaluationResolutionFinding {
                code: finding.code.clone(),
                severity: finding.severity.clone(),
                node_id: finding.node_id.clone(),
                invariant_version_id: finding.invariant_version_id.clone(),
            })
            .collect(),
    }
}

fn from_proto_evaluation_execution(
    value: EvaluationExecutionRequest,
) -> evaluation_execution_domain::EvaluationExecutionRequest {
    evaluation_execution_domain::EvaluationExecutionRequest {
        contract_version: value.contract_version,
        executor_version: value.executor_version,
        namespace: value.namespace,
        manifest_digest: value.manifest_digest,
        max_total_duration_ms: value.max_total_duration_ms,
    }
}

fn to_proto_evaluation_step(
    value: &evaluation_execution_domain::EvaluationStepReceipt,
) -> EvaluationStepReceipt {
    EvaluationStepReceipt {
        contract_version: value.contract_version.clone(),
        manifest_digest: value.manifest_digest.clone(),
        node_id: value.node_id.clone(),
        classification: value.classification.clone(),
        status: value.status.clone(),
        reason_code: value.reason_code.clone(),
        input_digest: value.input_digest.clone(),
        parameters_digest: value.parameters_digest.clone(),
        evaluator_definition_digest: value.evaluator_definition_digest.clone(),
        implementation_digest: value.implementation_digest.clone(),
        evidence_digests: value.evidence_digests.clone(),
        dependency_result_digests: value.dependency_result_digests.clone(),
        result_digest: value.result_digest.clone(),
        step_receipt_digest: value.step_receipt_digest.clone(),
        stochastic_evidence: value.stochastic_evidence.as_ref().map(|evidence| {
            StochasticStepEvidence {
                contract_version: evidence.contract_version.clone(),
                provider: evidence.provider.clone(),
                model: evidence.model.clone(),
                prompt_profile: evidence.prompt_profile.clone(),
                prompt_profile_digest: evidence.prompt_profile_digest.clone(),
                result_schema: evidence.result_schema.clone(),
                trial_count: evidence.trial_count,
                aggregation_rule: evidence.aggregation_rule.clone(),
                minimum_mean_score_micros: evidence.minimum_mean_score_micros,
                minimum_pass_rate_basis_points: evidence.minimum_pass_rate_basis_points,
                maximum_score_variance_micros_squared: evidence
                    .maximum_score_variance_micros_squared,
                gate_eligible: evidence.gate_eligible,
                completed_trial_count: evidence.completed_trial_count,
                mean_score_micros: evidence.mean_score_micros,
                pass_rate_basis_points: evidence.pass_rate_basis_points,
                score_variance_micros_squared: evidence.score_variance_micros_squared,
                total_input_tokens: evidence.total_input_tokens,
                total_output_tokens: evidence.total_output_tokens,
                total_retry_accounted_tokens: evidence.total_retry_accounted_tokens,
                trials: evidence
                    .trials
                    .iter()
                    .map(|trial| StochasticTrialEvidence {
                        trial_index: trial.trial_index,
                        seed: trial.seed,
                        attempt_count: trial.attempt_count,
                        status: trial.status.clone(),
                        reason_code: trial.reason_code.clone(),
                        score_micros: trial.score_micros,
                        input_tokens: trial.input_tokens,
                        output_tokens: trial.output_tokens,
                        retry_accounted_tokens: trial.retry_accounted_tokens,
                        result_digest: trial.result_digest.clone(),
                    })
                    .collect(),
                aggregate_digest: evidence.aggregate_digest.clone(),
            }
        }),
    }
}

fn to_proto_evaluation_gate(
    value: &evaluation_execution_domain::EvaluationGateDecision,
) -> EvaluationGateDecision {
    EvaluationGateDecision {
        contract_version: value.contract_version.clone(),
        manifest_digest: value.manifest_digest.clone(),
        reducer: value.reducer.clone(),
        verdict: value.verdict.clone(),
        reason_code: value.reason_code.clone(),
        step_receipt_digests: value.step_receipt_digests.clone(),
        invariant_coverage: value
            .invariant_coverage
            .iter()
            .map(|coverage| InvariantCoverageDecision {
                invariant_version_id: coverage.invariant_version_id.clone(),
                covered_by_node_ids: coverage.covered_by_node_ids.clone(),
                waiver_version_ids: coverage.waiver_version_ids.clone(),
                satisfied: coverage.satisfied,
            })
            .collect(),
        decision_digest: value.decision_digest.clone(),
    }
}

fn to_proto_evaluation_execution_projection(
    value: &evaluation_execution_domain::EvaluationExecutionProjection,
) -> EvaluationExecutionProjection {
    EvaluationExecutionProjection {
        manifest_digest: value.manifest_digest.clone(),
        operation_id: value.operation_id.clone(),
        namespace: value.namespace.clone(),
        status: value.status.clone(),
        steps: value.steps.iter().map(to_proto_evaluation_step).collect(),
        decision: value.decision.as_ref().map(to_proto_evaluation_gate),
    }
}

fn evaluation_operation_id(manifest_digest: &str) -> String {
    format!(
        "evaluation-execution:{}",
        manifest_digest
            .strip_prefix("sha256:")
            .unwrap_or(manifest_digest)
    )
}

fn evaluation_manifest_reference(manifest_digest: &str) -> GovernedReference {
    GovernedReference {
        kind: "evaluation_manifest".into(),
        reference: manifest_digest.into(),
        content_hash: Some(manifest_digest.into()),
        disclosed_fields: vec!["manifest_digest".into()],
        omitted: false,
        omission_reason: None,
    }
}

fn initial_evaluation_receipt(
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    actor: &str,
    now_ms: i64,
    max_total_duration_ms: u64,
    topological_order: &[String],
) -> Result<OperationReceipt, Status> {
    let operation_id = evaluation_operation_id(&manifest.manifest_digest);
    let manifest_reference = evaluation_manifest_reference(&manifest.manifest_digest);
    let intent_id = format!("{operation_id}:intent");
    let policy_id = format!("{operation_id}:policy");
    let routing_id = format!("{operation_id}:routing");
    let budget_id = format!("{operation_id}:budget");
    let events = vec![
        OperationReceiptEvent {
            event_id: intent_id.clone(),
            operation_id: operation_id.clone(),
            parent_event_id: None,
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::IntentRecorded,
            surface: ReceiptSurface::Intent,
            actor: actor.into(),
            references: vec![manifest_reference.clone()],
            attributes: BTreeMap::from([
                ("manifest_digest".into(), manifest.manifest_digest.clone()),
                (
                    "executor_version".into(),
                    evaluation_execution_domain::EXECUTOR_VERSION.into(),
                ),
            ]),
        },
        OperationReceiptEvent {
            event_id: policy_id.clone(),
            operation_id: operation_id.clone(),
            parent_event_id: Some(intent_id),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::PolicyDecided,
            surface: ReceiptSurface::Policy,
            actor: "chisei.evaluation-executor".into(),
            references: vec![manifest_reference.clone()],
            attributes: BTreeMap::from([(
                "reducer".into(),
                evaluation_plan_domain::FIXED_REDUCER.into(),
            )]),
        },
        OperationReceiptEvent {
            event_id: routing_id.clone(),
            operation_id: operation_id.clone(),
            parent_event_id: Some(policy_id),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::RouteSelected,
            surface: ReceiptSurface::Routing,
            actor: "chisei.evaluation-executor".into(),
            references: vec![manifest_reference.clone()],
            attributes: BTreeMap::from([(
                "topological_order_json".into(),
                serde_json::to_string(topological_order)
                    .map_err(|error| Status::internal(error.to_string()))?,
            )]),
        },
        OperationReceiptEvent {
            event_id: budget_id,
            operation_id: operation_id.clone(),
            parent_event_id: Some(routing_id),
            timestamp_ms: now_ms,
            kind: ReceiptEventKind::BudgetDecided,
            surface: ReceiptSurface::Budget,
            actor: "chisei.evaluation-executor".into(),
            references: vec![manifest_reference],
            attributes: BTreeMap::from([
                (
                    "max_total_duration_ms".into(),
                    max_total_duration_ms.to_string(),
                ),
                ("node_count".into(), manifest.nodes.len().to_string()),
            ]),
        },
    ];
    Ok(OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id,
        parent_operation_id: None,
        namespace: manifest.namespace.clone(),
        operation_class: evaluation_execution_domain::EXECUTION_OPERATION_CLASS.into(),
        initiating_actor: actor.into(),
        schema_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
        policy_version: evaluation_plan_domain::FIXED_REDUCER.into(),
        started_at_ms: now_ms,
        completed_at_ms: None,
        events,
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
    })
}

fn evaluation_total_budget_ms(receipt: &OperationReceipt) -> Result<u64, Status> {
    let mut budgets = receipt.events.iter().filter(|event| {
        event.kind == ReceiptEventKind::BudgetDecided
            && event.surface == ReceiptSurface::Budget
            && event.actor == "chisei.evaluation-executor"
    });
    let budget = budgets
        .next()
        .and_then(|event| event.attributes.get("max_total_duration_ms"))
        .ok_or_else(|| Status::data_loss("evaluation execution budget is missing"))?
        .parse::<u64>()
        .map_err(|_| Status::data_loss("evaluation execution budget is invalid"))?;
    if budgets.next().is_some()
        || budget == 0
        || budget > evaluation_execution_domain::MAX_TOTAL_DURATION_MS
    {
        return Err(Status::data_loss(
            "evaluation execution budget is not canonical",
        ));
    }
    Ok(budget)
}

fn evaluation_step_event(
    operation_id: &str,
    node: &evaluation_manifest_domain::ResolvedEvaluationNode,
    step: &evaluation_execution_domain::EvaluationStepReceipt,
    now_ms: i64,
) -> Result<OperationReceiptEvent, Status> {
    let parent_event_id = node
        .depends_on_node_ids
        .iter()
        .max()
        .map(|dependency| format!("{operation_id}:step:{dependency}"))
        .unwrap_or_else(|| format!("{operation_id}:budget"));
    Ok(OperationReceiptEvent {
        event_id: format!("{operation_id}:step:{}", node.node_id),
        operation_id: operation_id.into(),
        parent_event_id: Some(parent_event_id),
        timestamp_ms: now_ms,
        kind: ReceiptEventKind::VerificationRecorded,
        surface: ReceiptSurface::Verification,
        actor: "chisei.evaluation-executor".into(),
        references: vec![
            evaluation_manifest_reference(&step.manifest_digest),
            GovernedReference {
                kind: "evaluator_definition".into(),
                reference: node.evaluator.definition_id.clone(),
                content_hash: Some(node.evaluator.definition_digest.clone()),
                disclosed_fields: vec![
                    "definition_id".into(),
                    "definition_digest".into(),
                    "implementation_digest".into(),
                ],
                omitted: false,
                omission_reason: None,
            },
        ],
        attributes: BTreeMap::from([
            (
                "evaluation_step_receipt".into(),
                serde_json::to_string(step).map_err(|error| Status::internal(error.to_string()))?,
            ),
            ("node_id".into(), step.node_id.clone()),
            ("status".into(), step.status.clone()),
            ("reason_code".into(), step.reason_code.clone()),
            ("result_digest".into(), step.result_digest.clone()),
            (
                "step_receipt_digest".into(),
                step.step_receipt_digest.clone(),
            ),
        ]),
    })
}

fn evaluation_gate_event(
    operation_id: &str,
    parent_event_id: String,
    decision: &evaluation_execution_domain::EvaluationGateDecision,
    now_ms: i64,
) -> Result<OperationReceiptEvent, Status> {
    Ok(OperationReceiptEvent {
        event_id: format!("{operation_id}:gate"),
        operation_id: operation_id.into(),
        parent_event_id: Some(parent_event_id),
        timestamp_ms: now_ms,
        kind: ReceiptEventKind::OutcomeRecorded,
        surface: ReceiptSurface::Outcome,
        actor: "chisei.evaluation-executor".into(),
        references: vec![evaluation_manifest_reference(&decision.manifest_digest)],
        attributes: BTreeMap::from([
            (
                "evaluation_gate_decision".into(),
                serde_json::to_string(decision)
                    .map_err(|error| Status::internal(error.to_string()))?,
            ),
            ("verdict".into(), decision.verdict.clone()),
            ("reason_code".into(), decision.reason_code.clone()),
            ("decision_digest".into(), decision.decision_digest.clone()),
        ]),
    })
}

fn evaluation_cancellation_event(
    receipt: &OperationReceipt,
    actor: &str,
    now_ms: i64,
) -> OperationReceiptEvent {
    let parent_event_id = receipt
        .events
        .iter()
        .rev()
        .find(|event| event.kind == ReceiptEventKind::VerificationRecorded)
        .map(|event| event.event_id.clone())
        .unwrap_or_else(|| format!("{}:budget", receipt.operation_id));
    OperationReceiptEvent {
        event_id: format!("{}:cancel", receipt.operation_id),
        operation_id: receipt.operation_id.clone(),
        parent_event_id: Some(parent_event_id),
        timestamp_ms: now_ms,
        kind: ReceiptEventKind::HumanIntervened,
        surface: ReceiptSurface::Intervention,
        actor: actor.into(),
        references: Vec::new(),
        attributes: BTreeMap::from([("evaluation_cancel_requested".into(), "true".into())]),
    }
}

fn evaluation_cancellation_requested(receipt: &OperationReceipt) -> bool {
    receipt.events.iter().any(|event| {
        event
            .attributes
            .get("evaluation_cancel_requested")
            .is_some_and(|value| value == "true")
    })
}

fn order_parent_event_id(
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    operation_id: &str,
) -> String {
    evaluation_execution_domain::deterministic_topological_order(manifest)
        .ok()
        .and_then(|order| order.last().cloned())
        .map(|node_id| format!("{operation_id}:step:{node_id}"))
        .unwrap_or_else(|| format!("{operation_id}:budget"))
}

fn evaluation_projection_from_receipt(
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    index: &evaluation_execution_domain::EvaluationExecutionIndex,
    receipt: &OperationReceipt,
) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, String> {
    if receipt.operation_id != index.operation_id
        || receipt.namespace != index.namespace
        || receipt.operation_class != evaluation_execution_domain::EXECUTION_OPERATION_CLASS
    {
        return Err("evaluation execution receipt binding is invalid".into());
    }
    let mut steps = receipt
        .events
        .iter()
        .filter_map(|event| event.attributes.get("evaluation_step_receipt"))
        .map(|json| {
            serde_json::from_str::<evaluation_execution_domain::EvaluationStepReceipt>(json)
                .map_err(|error| format!("invalid evaluation step receipt: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    steps.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let decision = receipt
        .events
        .iter()
        .find_map(|event| event.attributes.get("evaluation_gate_decision"))
        .map(|json| {
            serde_json::from_str::<evaluation_execution_domain::EvaluationGateDecision>(json)
                .map_err(|error| format!("invalid evaluation gate decision: {error}"))
        })
        .transpose()?;
    let cancellation_requested = evaluation_cancellation_requested(receipt);
    if let Some(decision) = &decision
        && (decision.reason_code == evaluation_execution_domain::REASON_EXECUTION_CANCELLED)
            != cancellation_requested
    {
        return Err("evaluation cancellation and terminal decision are inconsistent".into());
    }
    let status = decision
        .as_ref()
        .map(|decision| decision.verdict.clone())
        .unwrap_or_else(|| {
            if cancellation_requested {
                evaluation_execution_domain::STATUS_CANCELLED.into()
            } else {
                evaluation_execution_domain::STATUS_RUNNING.into()
            }
        });
    let projection = evaluation_execution_domain::EvaluationExecutionProjection {
        manifest_digest: manifest.manifest_digest.clone(),
        operation_id: index.operation_id.clone(),
        namespace: index.namespace.clone(),
        status,
        steps,
        decision,
    };
    evaluation_execution_domain::validate_projection(manifest, &projection)?;
    if projection.decision.is_some() {
        let completeness = receipt.completeness();
        if !completeness.complete {
            return Err(format!(
                "terminal evaluation receipt is incomplete: {:?}",
                completeness.errors
            ));
        }
    }
    Ok(projection)
}

fn map_evaluation_resource_error(error: String) -> Status {
    if error.contains("already exists") {
        Status::already_exists(error)
    } else if error.contains("not found")
        || error.contains("disabled")
        || error.contains("superseded")
        || error.contains("incompatible")
        || error.contains("unavailable")
    {
        Status::failed_precondition(error)
    } else if error.contains("exceeds") {
        Status::resource_exhausted(error)
    } else {
        Status::invalid_argument(error)
    }
}

fn map_evaluation_manifest_storage_error(error: String) -> Status {
    if error.contains("already exists") {
        Status::already_exists(error)
    } else if error.contains("persisted evaluation manifest")
        || error.contains("manifest digest conflicts")
    {
        Status::data_loss(error)
    } else {
        Status::internal(error)
    }
}

fn principal_authority(
    db: &RuntimeDb,
    actor: &str,
) -> Result<markings::PrincipalAuthority, String> {
    if let Some(authority) = markings::trusted_service_authority(actor) {
        return Ok(authority);
    }
    let profile = db.find_by_external_id(&markings::principal_profile_external_id(actor))?;
    markings::principal_authority_from_profile(actor, profile.as_ref())
}

fn object_visible_to_actor(db: &RuntimeDb, object: &Object, actor: &str) -> Result<bool, String> {
    if matches!(actor, "root" | "local") {
        return Ok(true);
    }
    let grants = db.list_grants(&object.id)?;
    if !grants.is_empty() && !grants.iter().any(|grant| grant.principal == actor) {
        return Ok(false);
    }
    let marking = markings::object_classification(object)?;
    let authority = principal_authority(db, actor)?;
    Ok(
        markings::evaluate_marking_access("evaluation-plan-read", marking, &authority).decision
            != markings::MarkingDecision::Deny,
    )
}

fn invariant_reference_visible(
    db: &RuntimeDb,
    namespace: &str,
    invariant_id: &str,
    actor: &str,
    visibility_cache: &mut HashMap<String, bool>,
    visibility_work: &mut usize,
) -> Result<bool, String> {
    const MAX_VISIBILITY_OBJECTS: usize = 4_096;
    let mut pending = vec![invariant_id.to_string()];
    while let Some(object_id) = pending.pop() {
        if let Some(visible) = visibility_cache.get(&object_id) {
            if !visible {
                return Ok(false);
            }
            continue;
        }
        *visibility_work += 1;
        if *visibility_work > MAX_VISIBILITY_OBJECTS {
            return Ok(false);
        }
        let Some(object) = db.get_object(&object_id)? else {
            visibility_cache.insert(object_id, false);
            return Ok(false);
        };
        if object.namespace != namespace || !object_visible_to_actor(db, &object, actor)? {
            visibility_cache.insert(object_id, false);
            return Ok(false);
        }
        visibility_cache.insert(object_id, true);
        if object.kind == governed_fact_domain::FACT_KIND {
            let fact = governed_fact_domain::fact_from_object(&object)?;
            pending.extend(fact.input.requirement_version_ids);
            pending.extend(fact.input.evidence_refs);
            if !fact.input.supersedes_object_id.is_empty() {
                pending.push(fact.input.supersedes_object_id);
            }
        } else if object.kind == governed_fact_domain::WAIVER_KIND {
            let waiver = governed_fact_domain::waiver_from_object(&object)?;
            pending.extend(waiver.input.invariant_version_ids);
            pending.extend(waiver.input.evidence_refs);
            if !waiver.input.supersedes_object_id.is_empty() {
                pending.push(waiver.input.supersedes_object_id);
            }
        }
    }
    Ok(true)
}

fn evaluation_plan_visible(
    db: &RuntimeDb,
    plan: &evaluation_plan_domain::EvaluationPlan,
    actor: &str,
) -> Result<bool, String> {
    let mut visibility_cache = HashMap::new();
    let mut visibility_work = 0;
    for invariant_id in plan
        .nodes
        .iter()
        .flat_map(|node| node.invariant_version_ids.iter())
    {
        if !invariant_reference_visible(
            db,
            &plan.namespace,
            invariant_id,
            actor,
            &mut visibility_cache,
            &mut visibility_work,
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn fact_evidence_classifications(
    db: &RuntimeDb,
    namespace: &str,
    fact_id: &str,
    fact_cache: &mut HashMap<String, HashSet<String>>,
    evidence_cache: &mut HashMap<String, String>,
    visiting: &mut HashSet<String>,
    work: &mut usize,
) -> Result<HashSet<String>, Status> {
    const MAX_CLASSIFICATION_OBJECTS: usize = 4_096;
    if let Some(classifications) = fact_cache.get(fact_id) {
        return Ok(classifications.clone());
    }
    if !visiting.insert(fact_id.to_string()) {
        return Err(Status::failed_precondition(
            "governed fact evidence closure contains a cycle",
        ));
    }
    *work += 1;
    if *work > MAX_CLASSIFICATION_OBJECTS {
        return Err(Status::resource_exhausted(
            "governed fact evidence closure exceeds the validation bound",
        ));
    }
    let object = db
        .get_object(fact_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::failed_precondition("governed fact reference unavailable"))?;
    if object.namespace != namespace || object.kind != governed_fact_domain::FACT_KIND {
        return Err(Status::failed_precondition(
            "governed fact reference unavailable",
        ));
    }
    let fact = governed_fact_domain::fact_from_object(&object).map_err(Status::data_loss)?;
    let mut classifications = HashSet::new();
    for evidence_id in &fact.input.evidence_refs {
        let classification = if let Some(classification) = evidence_cache.get(evidence_id) {
            classification.clone()
        } else {
            *work += 1;
            if *work > MAX_CLASSIFICATION_OBJECTS {
                return Err(Status::resource_exhausted(
                    "governed fact evidence closure exceeds the validation bound",
                ));
            }
            let evidence = db
                .get_object(evidence_id)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("evidence reference unavailable"))?;
            if evidence.namespace != namespace
                || evidence.kind != crate::domain::KIND_EXTERNAL_EVIDENCE
            {
                return Err(Status::failed_precondition(
                    "evidence reference unavailable",
                ));
            }
            let classification = evidence
                .properties
                .get("classification")
                .ok_or_else(|| {
                    Status::failed_precondition("evidence reference lacks a valid classification")
                })
                .and_then(|value| {
                    markings::parse_classification(value).map_err(|_| {
                        Status::failed_precondition(
                            "evidence reference lacks a valid classification",
                        )
                    })
                })?
                .as_str()
                .to_string();
            evidence_cache.insert(evidence_id.clone(), classification.clone());
            classification
        };
        classifications.insert(classification);
    }
    for requirement_id in &fact.input.requirement_version_ids {
        classifications.extend(fact_evidence_classifications(
            db,
            namespace,
            requirement_id,
            fact_cache,
            evidence_cache,
            visiting,
            work,
        )?);
    }
    visiting.remove(fact_id);
    fact_cache.insert(fact_id.to_string(), classifications.clone());
    Ok(classifications)
}

fn validate_evaluation_plan_references(
    db: &RuntimeDb,
    plan: &evaluation_plan_domain::EvaluationPlan,
    actor: &str,
) -> Result<(), Status> {
    let mut visibility_cache = HashMap::new();
    let mut visibility_work = 0;
    let mut fact_classification_cache = HashMap::new();
    let mut evidence_classification_cache = HashMap::new();
    let mut classification_work = 0;
    for node in &plan.nodes {
        let definition = db
            .get_evaluator_definition(&node.evaluator_definition_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::failed_precondition("unknown evaluator definition"))?;
        if definition.namespace != plan.namespace {
            return Err(Status::failed_precondition(
                "evaluator definition is in a different namespace",
            ));
        }
        let availability = db
            .get_evaluator_availability(&definition.definition_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluator availability is missing"))?;
        if availability.state != evaluation_plan_domain::AVAILABILITY_ENABLED {
            return Err(Status::failed_precondition(
                "evaluator definition is unavailable for new plans",
            ));
        }
        evaluation_plan_domain::validate_parameters(
            &definition.parameter_schema_json,
            &node.parameters_json,
        )
        .map_err(Status::invalid_argument)?;
        for binding in &node.input_bindings {
            if !definition
                .supported_input_schemas
                .contains(&binding.schema_id)
            {
                return Err(Status::failed_precondition(format!(
                    "node {:?} binds unsupported input schema {:?}",
                    node.node_id, binding.schema_id
                )));
            }
        }
        for invariant_id in &node.invariant_version_ids {
            if !invariant_reference_visible(
                db,
                &plan.namespace,
                invariant_id,
                actor,
                &mut visibility_cache,
                &mut visibility_work,
            )
            .map_err(Status::internal)?
            {
                return Err(Status::failed_precondition(
                    "governed invariant reference unavailable",
                ));
            }
            let object = db
                .get_object(invariant_id)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("unknown invariant version"))?;
            if object.kind != governed_fact_domain::FACT_KIND {
                return Err(Status::failed_precondition(
                    "evaluation plans may cover only governed invariant versions",
                ));
            }
            let invariant =
                governed_fact_domain::fact_from_object(&object).map_err(Status::data_loss)?;
            if invariant.input.fact_type != GovernedFactType::Invariant
                || invariant.input.status != "active"
            {
                return Err(Status::failed_precondition(
                    "evaluation plans require active invariant versions",
                ));
            }
            if !invariant.input.applicability.subject_refs.is_empty() {
                return Err(Status::failed_precondition(
                    "profile-wide evaluation plans cannot cover subject-specific invariants",
                ));
            }
            if !plan.accepted_subject_profiles.iter().all(|profile| {
                invariant
                    .input
                    .applicability
                    .subject_profiles
                    .contains(profile)
            }) {
                return Err(Status::failed_precondition(
                    "invariant applicability does not cover every accepted subject profile",
                ));
            }
            let verification = &invariant.input.verification;
            if !definition
                .supported_predicate_kinds
                .contains(&verification.predicate_kind)
                || !definition
                    .supported_input_schemas
                    .contains(&verification.input_schema)
                || !definition
                    .supported_result_schemas
                    .contains(&verification.result_schema)
            {
                return Err(Status::failed_precondition(
                    "evaluator definition is incompatible with invariant verification contract",
                ));
            }
            if !node.input_bindings.iter().any(|binding| {
                binding.source_kind == evaluation_plan_domain::INPUT_INVARIANT
                    && binding.schema_id == verification.input_schema
            }) {
                return Err(Status::failed_precondition(
                    "node lacks a typed invariant binding for its covered input schema",
                ));
            }
            let evidence_classifications = fact_evidence_classifications(
                db,
                &plan.namespace,
                invariant_id,
                &mut fact_classification_cache,
                &mut evidence_classification_cache,
                &mut HashSet::new(),
                &mut classification_work,
            )?;
            if evidence_classifications
                .iter()
                .any(|classification| !definition.evidence_classifications.contains(classification))
            {
                return Err(Status::failed_precondition(
                    "evaluator definition does not admit the invariant evidence classification",
                ));
            }
        }
    }
    Ok(())
}

fn resolution_outcome(
    status: &str,
    code: &str,
) -> evaluation_manifest_domain::EvaluationResolutionOutcome {
    evaluation_manifest_domain::blocked_outcome(status, code)
}

fn resolve_invariant_set_for_manifest(
    db: &RuntimeDb,
    request: &evaluation_manifest_domain::PreparedResolutionRequest,
) -> Result<
    (
        governed_fact_domain::ResolvedInvariantSet,
        Vec<governed_fact_domain::GovernedFactVersion>,
        Vec<governed_fact_domain::GovernedWaiverVersion>,
        bool,
    ),
    Status,
> {
    let profile_object = db
        .get_object(&governed_fact_domain::profile_object_id(
            &request.request.namespace,
        ))
        .map_err(Status::internal)?
        .ok_or_else(|| Status::failed_precondition("governed fact resolution unavailable"))?;
    if !object_visible_to_actor(db, &profile_object, &request.actor).map_err(Status::internal)? {
        return Err(Status::failed_precondition(
            "governed fact resolution unavailable",
        ));
    }
    let profile =
        governed_fact_domain::profile_from_object(&profile_object).map_err(Status::data_loss)?;
    let all_facts = governed_fact_domain::list_facts(db, &request.request.namespace)
        .map_err(Status::internal)?;
    let all_waivers = governed_fact_domain::list_waivers(db, &request.request.namespace)
        .map_err(Status::internal)?;
    let all_set = governed_fact_domain::resolve_invariant_set(
        &profile,
        all_facts.clone(),
        all_waivers.clone(),
        &request.request.subject_profile,
        &request.request.subject_identity,
        request.request.evaluation_time_ms,
        governed_fact_domain::MAX_RESOLUTION_LIMIT,
    )
    .map_err(map_invariant_resolution_error)?;
    let mut visibility_cache = HashMap::new();
    let mut visibility_work = 0;
    let mut visible_facts = Vec::new();
    for fact in all_facts {
        if invariant_reference_visible(
            db,
            &request.request.namespace,
            &fact.object_id,
            &request.actor,
            &mut visibility_cache,
            &mut visibility_work,
        )
        .map_err(Status::internal)?
        {
            visible_facts.push(fact);
        }
    }
    let mut visible_waivers = Vec::new();
    for waiver in all_waivers {
        if invariant_reference_visible(
            db,
            &request.request.namespace,
            &waiver.object_id,
            &request.actor,
            &mut visibility_cache,
            &mut visibility_work,
        )
        .map_err(Status::internal)?
        {
            visible_waivers.push(waiver);
        }
    }
    let visible_set = governed_fact_domain::resolve_invariant_set(
        &profile,
        visible_facts.clone(),
        visible_waivers.clone(),
        &request.request.subject_profile,
        &request.request.subject_identity,
        request.request.evaluation_time_ms,
        governed_fact_domain::MAX_RESOLUTION_LIMIT,
    )
    .map_err(map_invariant_resolution_error)?;
    let resolution_incomplete = all_set.set_digest != visible_set.set_digest;
    Ok((
        visible_set,
        visible_facts,
        visible_waivers,
        resolution_incomplete,
    ))
}

fn map_invariant_resolution_error(error: String) -> Status {
    if error.contains("exceeds") {
        Status::resource_exhausted(error)
    } else if error.contains("invalid") || error.contains("must") {
        Status::invalid_argument(error)
    } else {
        Status::failed_precondition("governed fact resolution unavailable")
    }
}

fn resolve_manifest_evidence(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    evidence_object_id: &str,
    subject_identity: &str,
    require_subject_binding: bool,
    evaluation_time_ms: i64,
) -> Result<Result<evaluation_manifest_domain::ResolvedEvidenceBinding, &'static str>, Status> {
    let Some(object) = db
        .get_object(evidence_object_id)
        .map_err(Status::internal)?
    else {
        return Ok(Err("evidence_unavailable"));
    };
    if object.namespace != namespace
        || object.kind != crate::domain::KIND_EXTERNAL_EVIDENCE
        || !object_visible_to_actor(db, &object, actor).map_err(Status::internal)?
    {
        return Ok(Err("evidence_unavailable"));
    }
    let Some(submission_id) = object.properties.get("submission_id") else {
        return Ok(Err("evidence_unavailable"));
    };
    let Some(submission) = db
        .get_evidence_submission(submission_id)
        .map_err(Status::internal)?
    else {
        return Ok(Err("evidence_unavailable"));
    };
    if submission.namespace != namespace {
        return Ok(Err("evidence_unavailable"));
    }
    if submission.lifecycle_state != crate::sekai::evidence::EvidenceLifecycleState::Available
        || submission.observed_at_ms > evaluation_time_ms
        || submission
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= evaluation_time_ms)
    {
        return Ok(Err("evidence_stale"));
    }
    if require_subject_binding && submission.target_external_id != subject_identity {
        return Ok(Err("evidence_subject_mismatch"));
    }
    let envelope = submission
        .envelope
        .as_ref()
        .ok_or_else(|| Status::data_loss("admitted evidence envelope is missing"))?;
    let computed_digest = crate::sekai::evidence_store::canonical_content_digest(&envelope.content)
        .map_err(Status::data_loss)?;
    if computed_digest != submission.content_digest
        || envelope.content_digest != submission.content_digest
        || object
            .properties
            .get("content_digest")
            .is_none_or(|digest| digest != &submission.content_digest)
        || object
            .properties
            .get("classification")
            .is_none_or(|classification| classification != submission.classification.as_str())
    {
        return Err(Status::data_loss(
            "admitted evidence content binding is invalid",
        ));
    }
    let source_identity_digest = evaluation_manifest_domain::digest_json(&(
        submission.producer_identity.as_str(),
        submission.source_type.as_str(),
        submission.source_instance.as_str(),
        submission.source_record_id.as_str(),
        submission.source_version.as_str(),
        submission.source_sequence,
        submission.target_external_id.as_str(),
        submission.target_kind.as_str(),
    ))
    .map_err(Status::internal)?;
    Ok(Ok(evaluation_manifest_domain::ResolvedEvidenceBinding {
        evidence_object_id: evidence_object_id.into(),
        submission_id: submission.id,
        // Evidence admission stores canonical SHA-256 as lowercase hex. The
        // manifest qualifies the algorithm for unambiguous later binding.
        content_digest: format!("sha256:{}", submission.content_digest),
        evidence_type: submission.evidence_type,
        schema_id: submission.schema_id,
        schema_version: submission.schema_version,
        classification: submission.classification.as_str().into(),
        observed_at_ms: submission.observed_at_ms,
        expires_at_ms: submission.expires_at_ms.unwrap_or(0),
        source_identity_digest,
    }))
}

fn resolve_evaluation_manifest_live(
    db: &RuntimeDb,
    request: &evaluation_manifest_domain::PreparedResolutionRequest,
    now_ms: i64,
) -> Result<evaluation_manifest_domain::EvaluationResolutionOutcome, Status> {
    let Some(plan) = db
        .get_evaluation_plan(&request.request.plan_version_id)
        .map_err(Status::internal)?
    else {
        return Err(Status::not_found("evaluation plan not found"));
    };
    if plan.namespace != request.request.namespace
        || !evaluation_plan_visible(db, &plan, &request.actor).map_err(Status::internal)?
    {
        return Err(Status::not_found("evaluation plan not found"));
    }
    let canonical_plan =
        evaluation_plan_domain::prepare_plan(plan.clone(), &plan.created_by, plan.created_at_ms)
            .map_err(Status::data_loss)?;
    if canonical_plan != plan {
        return Err(Status::data_loss(
            "persisted evaluation plan content binding is invalid",
        ));
    }
    if !plan
        .accepted_subject_profiles
        .contains(&request.request.subject_profile)
    {
        return Ok(resolution_outcome(
            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
            "subject_profile_unsupported",
        ));
    }
    let (invariant_set, _, _, hidden_applicable_invariant) =
        match resolve_invariant_set_for_manifest(db, request) {
            Ok(resolved) => resolved,
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::FailedPrecondition | tonic::Code::NotFound
                ) =>
            {
                return Ok(resolution_outcome(
                    evaluation_manifest_domain::RESOLUTION_UNKNOWN,
                    "invariant_resolution_unavailable",
                ));
            }
            Err(status) => return Err(status),
        };
    if hidden_applicable_invariant {
        return Ok(resolution_outcome(
            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
            "invariant_resolution_incomplete",
        ));
    }
    let invariants = invariant_set
        .invariants
        .iter()
        .map(|invariant| (invariant.object_id.clone(), invariant))
        .collect::<HashMap<_, _>>();
    let plan_coverage = plan
        .nodes
        .iter()
        .flat_map(|node| node.invariant_version_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    if plan_coverage
        .iter()
        .any(|invariant_id| !invariants.contains_key(invariant_id))
    {
        return Ok(resolution_outcome(
            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
            "plan_invariant_unavailable",
        ));
    }
    let required_coverage = plan
        .nodes
        .iter()
        .filter(|node| node.classification == evaluation_plan_domain::NODE_REQUIRED)
        .flat_map(|node| node.invariant_version_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut waivers_by_invariant: HashMap<String, Vec<String>> = HashMap::new();
    for waiver in &invariant_set.waivers {
        for invariant_id in &waiver.input.invariant_version_ids {
            if invariants.contains_key(invariant_id) {
                waivers_by_invariant
                    .entry(invariant_id.clone())
                    .or_default()
                    .push(waiver.object_id.clone());
            }
        }
    }
    let uncovered_invariants = invariants
        .keys()
        .filter(|invariant_id| {
            !required_coverage.contains(*invariant_id)
                && !waivers_by_invariant.contains_key(*invariant_id)
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    if !uncovered_invariants.is_empty() {
        return Ok(evaluation_manifest_domain::EvaluationResolutionOutcome {
            status: evaluation_manifest_domain::RESOLUTION_UNKNOWN.into(),
            manifest: None,
            findings: uncovered_invariants
                .into_iter()
                .map(|invariant_version_id| {
                    evaluation_manifest_domain::EvaluationResolutionFinding {
                        code: "invariant_uncovered".into(),
                        severity: evaluation_manifest_domain::FINDING_BLOCKING.into(),
                        node_id: String::new(),
                        invariant_version_id,
                    }
                })
                .collect(),
        });
    }

    let requested_evidence = request
        .request
        .evidence_object_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut all_evidence_ids = requested_evidence.clone();
    for fact in invariant_set
        .requirements
        .iter()
        .chain(invariant_set.invariants.iter())
    {
        all_evidence_ids.extend(fact.input.evidence_refs.iter().cloned());
    }
    for waiver in &invariant_set.waivers {
        all_evidence_ids.extend(waiver.input.evidence_refs.iter().cloned());
    }
    if all_evidence_ids.len() > evaluation_manifest_domain::MAX_MANIFEST_EVIDENCE {
        return Err(Status::resource_exhausted(
            "resolved evidence exceeds the manifest bound",
        ));
    }
    let mut admitted_evidence = Vec::with_capacity(all_evidence_ids.len());
    for evidence_id in &all_evidence_ids {
        match resolve_manifest_evidence(
            db,
            &request.request.namespace,
            &request.actor,
            evidence_id,
            &request.request.subject_identity,
            requested_evidence.contains(evidence_id),
            request.request.evaluation_time_ms,
        )? {
            Ok(evidence) => admitted_evidence.push(evidence),
            Err(code) => {
                return Ok(resolution_outcome(
                    evaluation_manifest_domain::RESOLUTION_UNKNOWN,
                    code,
                ));
            }
        }
    }
    let evidence_by_id = admitted_evidence
        .iter()
        .map(|evidence| (evidence.evidence_object_id.clone(), evidence))
        .collect::<HashMap<_, _>>();
    let mut consumed_requested_evidence = BTreeSet::new();
    let mut resolved_nodes = Vec::with_capacity(plan.nodes.len());
    for node in &plan.nodes {
        let Some(definition) = db
            .get_evaluator_definition(&node.evaluator_definition_id)
            .map_err(Status::internal)?
        else {
            return Ok(resolution_outcome(
                evaluation_manifest_domain::RESOLUTION_UNAVAILABLE,
                "evaluator_unavailable",
            ));
        };
        if definition.namespace != request.request.namespace {
            return Ok(resolution_outcome(
                evaluation_manifest_domain::RESOLUTION_UNAVAILABLE,
                "evaluator_unavailable",
            ));
        }
        let canonical_definition = evaluation_plan_domain::prepare_definition(
            definition.clone(),
            &definition.created_by,
            definition.created_at_ms,
        )
        .map_err(Status::data_loss)?;
        if canonical_definition != definition {
            return Err(Status::data_loss(
                "persisted evaluator definition content binding is invalid",
            ));
        }
        let availability = db
            .get_evaluator_availability(&definition.definition_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluator availability is missing"))?;
        if availability.state != evaluation_plan_domain::AVAILABILITY_ENABLED {
            return Ok(resolution_outcome(
                evaluation_manifest_domain::RESOLUTION_UNAVAILABLE,
                "evaluator_unavailable",
            ));
        }
        if node.classification == evaluation_plan_domain::NODE_REQUIRED
            && definition.execution_class == evaluation_plan_domain::STOCHASTIC_EXECUTION_CLASS
            && !definition
                .stochastic_policy
                .as_ref()
                .is_some_and(|policy| policy.gate_eligible)
        {
            return Err(Status::data_loss(
                "required stochastic plan node lacks explicit gate eligibility",
            ));
        }
        evaluation_plan_domain::validate_parameters(
            &definition.parameter_schema_json,
            &node.parameters_json,
        )
        .map_err(Status::data_loss)?;
        let evidence_binding_schemas = node
            .input_bindings
            .iter()
            .filter(|binding| binding.source_kind == evaluation_plan_domain::INPUT_EVIDENCE)
            .map(|binding| binding.schema_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut node_evidence_ids = BTreeSet::new();
        let mut resolved_invariants = Vec::with_capacity(node.invariant_version_ids.len());
        for invariant_id in &node.invariant_version_ids {
            let invariant = invariants
                .get(invariant_id)
                .ok_or_else(|| Status::data_loss("plan invariant binding disappeared"))?;
            for evidence_type in &invariant.input.verification.evidence_types {
                let matching = requested_evidence
                    .iter()
                    .filter_map(|evidence_id| evidence_by_id.get(evidence_id))
                    .filter(|evidence| {
                        evidence.evidence_type == *evidence_type
                            && evidence_binding_schemas.contains(evidence.schema_id.as_str())
                    })
                    .collect::<Vec<_>>();
                if matching.is_empty() {
                    return Ok(resolution_outcome(
                        evaluation_manifest_domain::RESOLUTION_UNKNOWN,
                        "evidence_missing",
                    ));
                }
                for evidence in matching {
                    if !definition
                        .evidence_classifications
                        .contains(&evidence.classification)
                    {
                        return Ok(resolution_outcome(
                            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
                            "evidence_classification_mismatch",
                        ));
                    }
                    node_evidence_ids.insert(evidence.evidence_object_id.clone());
                    consumed_requested_evidence.insert(evidence.evidence_object_id.clone());
                }
            }
            let mut waiver_ids = waivers_by_invariant
                .get(invariant_id)
                .cloned()
                .unwrap_or_default();
            waiver_ids.sort();
            resolved_invariants.push(evaluation_manifest_domain::ResolvedInvariantBinding {
                invariant_version_id: invariant.object_id.clone(),
                content_digest: invariant.content_digest.clone(),
                predicate_kind: invariant.input.verification.predicate_kind.clone(),
                input_schema: invariant.input.verification.input_schema.clone(),
                result_schema: invariant.input.verification.result_schema.clone(),
                evidence_types: invariant.input.verification.evidence_types.clone(),
                provenance_evidence_object_ids: invariant.input.evidence_refs.clone(),
                waiver_version_ids: waiver_ids,
            });
        }
        if node_evidence_ids.len() > definition.resource_limits.max_evidence_items as usize {
            return Err(Status::resource_exhausted(
                "resolved node evidence exceeds evaluator resource limits",
            ));
        }
        resolved_nodes.push(evaluation_manifest_domain::ResolvedEvaluationNode {
            node_id: node.node_id.clone(),
            evaluator: evaluation_manifest_domain::ResolvedEvaluatorBinding {
                definition_id: definition.definition_id,
                definition_digest: definition.content_digest,
                implementation_digest: definition.implementation_digest,
                stochastic_policy: definition.stochastic_policy,
            },
            depends_on_node_ids: node.depends_on_node_ids.clone(),
            input_bindings: node
                .input_bindings
                .iter()
                .map(|binding| evaluation_manifest_domain::ResolvedInputBinding {
                    name: binding.name.clone(),
                    source_kind: binding.source_kind.clone(),
                    schema_id: binding.schema_id.clone(),
                })
                .collect(),
            parameters_json: node.parameters_json.clone(),
            invariants: resolved_invariants,
            evidence_object_ids: node_evidence_ids.into_iter().collect(),
            classification: node.classification.clone(),
        });
    }
    if consumed_requested_evidence != requested_evidence {
        return Ok(resolution_outcome(
            evaluation_manifest_domain::RESOLUTION_UNKNOWN,
            "evidence_unbound",
        ));
    }
    let waivers = invariant_set
        .waivers
        .iter()
        .map(|waiver| evaluation_manifest_domain::ResolvedWaiverBinding {
            waiver_version_id: waiver.object_id.clone(),
            content_digest: waiver.content_digest.clone(),
            evidence_object_ids: waiver.input.evidence_refs.clone(),
            invariant_version_ids: waiver.input.invariant_version_ids.clone(),
        })
        .collect();
    let requirements = invariant_set
        .requirements
        .iter()
        .map(
            |requirement| evaluation_manifest_domain::ResolvedRequirementBinding {
                requirement_version_id: requirement.object_id.clone(),
                content_digest: requirement.content_digest.clone(),
                provenance_evidence_object_ids: requirement.input.evidence_refs.clone(),
            },
        )
        .collect();
    let manifest = evaluation_manifest_domain::prepare_manifest(
        evaluation_manifest_domain::ResolvedEvaluationManifest {
            contract_version: evaluation_manifest_domain::MANIFEST_CONTRACT.into(),
            resolver_version: request.request.resolver_version.clone(),
            manifest_id: String::new(),
            manifest_digest: String::new(),
            namespace: request.request.namespace.clone(),
            plan_version_id: plan.plan_version_id,
            plan_digest: plan.content_digest,
            subject_profile: request.request.subject_profile.clone(),
            subject_identity: request.request.subject_identity.clone(),
            subject_content_digest: request.request.subject_content_digest.clone(),
            invariant_set_id: invariant_set.set_id,
            invariant_set_digest: invariant_set.set_digest,
            invariant_profile_digest: invariant_set.profile_digest,
            evaluation_time_ms: request.request.evaluation_time_ms,
            resolved_by: request.actor.clone(),
            requirements,
            nodes: resolved_nodes,
            evidence: admitted_evidence,
            waivers,
            created_at_ms: now_ms,
        },
    )
    .map_err(map_evaluation_resource_error)?;
    Ok(evaluation_manifest_domain::resolved_outcome(manifest))
}

/// Complete result used by local embedding/test callers of the streaming path.
/// This is intentionally not part of the public gRPC contract.
#[derive(Debug)]
pub struct LocalExecutionResponse {
    pub response: Option<PlannedChatResponse>,
    pub executed_at: i64,
}

impl ChiseiServiceImpl {
    /// Internal test/embedding adapter for the streaming-only execution path.
    /// The public gRPC contract exposes `ExecutePlanStream`; this helper is not
    /// a service method and exists only for local callers that need a complete
    /// response in one future.
    pub async fn execute_plan(
        &self,
        req: Request<ExecutePlanRequest>,
    ) -> Result<Response<LocalExecutionResponse>, Status> {
        let mut stream = <Self as ChiseiService>::execute_plan_stream(self, req)
            .await?
            .into_inner();
        let mut response = None;
        let mut executed_at = 0;
        while let Some(event) = stream.next().await {
            let event = event?;
            executed_at = event.executed_at;
            if event.response.is_some() {
                response = event.response;
            }
        }
        let response =
            response.ok_or_else(|| Status::internal("execution stream omitted response"))?;
        Ok(Response::new(LocalExecutionResponse {
            response: Some(response),
            executed_at,
        }))
    }

    pub fn new(db: Arc<RuntimeDb>, config: Config) -> Self {
        Self::new_with_evaluator_registries(
            db,
            config.clone(),
            Arc::new(
                evaluation_execution_domain::production_evaluator_registry()
                    .expect("compiled production evaluator registry must be valid"),
            ),
            Arc::new(
                crate::chisei::stochastic_evaluation::production_stochastic_evaluator_registry(
                    config,
                )
                .expect("compiled stochastic evaluator registry must be valid"),
            ),
        )
    }

    pub fn new_with_evaluator_registry(
        db: Arc<RuntimeDb>,
        config: Config,
        evaluator_registry: Arc<evaluation_execution_domain::DeterministicEvaluatorRegistry>,
    ) -> Self {
        Self::new_with_evaluator_registries(
            db,
            config,
            evaluator_registry,
            Arc::new(evaluation_execution_domain::StochasticEvaluatorRegistry::default()),
        )
    }

    pub fn new_with_evaluator_registries(
        db: Arc<RuntimeDb>,
        config: Config,
        evaluator_registry: Arc<evaluation_execution_domain::DeterministicEvaluatorRegistry>,
        stochastic_evaluator_registry: Arc<
            evaluation_execution_domain::StochasticEvaluatorRegistry,
        >,
    ) -> Self {
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
            candidates: Arc::new(CandidateStore::new()),
            active_promotions: Arc::new(ActivePromotions::new()),
            evaluator_registry,
            stochastic_evaluator_registry,
            evaluation_cancellations: Arc::new(Mutex::new(HashMap::new())),
            evaluation_execution_locks: Arc::new(Mutex::new(HashMap::new())),
            db,
            config,
            provider_registry_state_path,
        }
    }

    fn ensure_external_evaluator_registered(
        &self,
        definition: &evaluation_plan_domain::EvaluatorDefinition,
    ) {
        if definition.execution_class != evaluation_plan_domain::EXTERNAL_ADAPTER_EXECUTION_CLASS {
            return;
        }
        if let Err(error) = self.evaluator_registry.register_external_adapter(
            &definition.namespace,
            &definition.content_digest,
            &definition.implementation_digest,
            &definition.adapter_endpoint,
        ) {
            tracing::warn!(
                namespace = %definition.namespace,
                implementation_digest = %definition.implementation_digest,
                error = %error,
                "external evaluator adapter is not executable"
            );
        }
    }

    fn evaluator_capability(
        &self,
        definition: &evaluation_plan_domain::EvaluatorDefinition,
    ) -> (bool, String) {
        self.ensure_external_evaluator_registered(definition);
        let executable = match definition.execution_class.as_str() {
            evaluation_plan_domain::DETERMINISTIC_EXECUTION_CLASS => self
                .evaluator_registry
                .contains(&definition.implementation_digest),
            evaluation_plan_domain::EXTERNAL_ADAPTER_EXECUTION_CLASS => {
                evaluation_execution_domain::external_adapter_secret_configured()
                    && self.evaluator_registry.contains_external_adapter(
                        &definition.namespace,
                        &definition.content_digest,
                        &definition.implementation_digest,
                    )
            }
            evaluation_plan_domain::STOCHASTIC_EXECUTION_CLASS => self
                .stochastic_evaluator_registry
                .contains(&definition.implementation_digest),
            _ => false,
        };
        (
            executable,
            if executable {
                "executable"
            } else if matches!(
                definition.execution_class.as_str(),
                evaluation_plan_domain::DETERMINISTIC_EXECUTION_CLASS
                    | evaluation_plan_domain::EXTERNAL_ADAPTER_EXECUTION_CLASS
                    | evaluation_plan_domain::STOCHASTIC_EXECUTION_CLASS
            ) {
                "unavailable"
            } else {
                "unsupported"
            }
            .into(),
        )
    }

    fn get_evaluation_projection(
        db: &RuntimeDb,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        index: &evaluation_execution_domain::EvaluationExecutionIndex,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, Status> {
        let receipt = db
            .get_operation_receipt(&index.operation_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
        evaluation_total_budget_ms(&receipt)?;
        evaluation_projection_from_receipt(manifest, index, &receipt).map_err(Status::data_loss)
    }

    fn ensure_evaluation_execution(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        actor: &str,
        max_total_duration_ms: u64,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionIndex, Status> {
        if let Some(index) = self
            .db
            .get_evaluation_execution_index(&manifest.manifest_digest)
            .map_err(Status::internal)?
        {
            if index.namespace != manifest.namespace
                || index.executor_version != evaluation_execution_domain::EXECUTOR_VERSION
                || index.operation_id != evaluation_operation_id(&manifest.manifest_digest)
            {
                return Err(Status::data_loss(
                    "evaluation execution index binding is invalid",
                ));
            }
            return Ok(index);
        }
        let topological_order =
            evaluation_execution_domain::deterministic_topological_order(manifest)
                .map_err(Status::data_loss)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let receipt = initial_evaluation_receipt(
            manifest,
            actor,
            now_ms,
            max_total_duration_ms,
            &topological_order,
        )?;
        let index = evaluation_execution_domain::EvaluationExecutionIndex {
            manifest_digest: manifest.manifest_digest.clone(),
            operation_id: receipt.operation_id.clone(),
            namespace: manifest.namespace.clone(),
            executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
            started_by: actor.into(),
            created_at_ms: now_ms,
        };
        self.db
            .create_evaluation_execution(&index, &receipt)
            .map_err(Status::internal)
    }

    fn request_evaluation_cancellation(
        &self,
        index: &evaluation_execution_domain::EvaluationExecutionIndex,
        receipt: &OperationReceipt,
        actor: &str,
    ) -> Result<(), Status> {
        let append = self.db.append_operation_receipt_event(
            &index.operation_id,
            evaluation_cancellation_event(receipt, actor, chrono::Utc::now().timestamp_millis()),
        );
        if let Err(error) = append {
            let reconciled = self
                .db
                .get_operation_receipt(&index.operation_id)
                .map_err(Status::internal)?
                .is_some_and(|receipt| {
                    receipt.completed_at_ms.is_some() || evaluation_cancellation_requested(&receipt)
                });
            if !reconciled {
                return Err(Status::internal(error));
            }
        }
        Ok(())
    }

    fn load_evaluation_node_evidence(
        db: &RuntimeDb,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        node: &evaluation_manifest_domain::ResolvedEvaluationNode,
    ) -> Result<Vec<evaluation_execution_domain::EvaluationEvidenceInput>, String> {
        let by_object = manifest
            .evidence
            .iter()
            .map(|evidence| (evidence.evidence_object_id.as_str(), evidence))
            .collect::<BTreeMap<_, _>>();
        let mut inputs = Vec::with_capacity(node.evidence_object_ids.len());
        for object_id in &node.evidence_object_ids {
            let binding = by_object
                .get(object_id.as_str())
                .ok_or_else(|| "manifest node evidence binding is missing".to_string())?;
            let submission = db
                .get_evidence_submission(&binding.submission_id)?
                .ok_or_else(|| {
                    evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE.to_string()
                })?;
            let envelope = submission.envelope.ok_or_else(|| {
                evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE.to_string()
            })?;
            let retained_content_digest = crate::sekai::evidence_store::canonical_content_digest(
                &envelope.content,
            )
            .map_err(|_| evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE.to_string())?;
            if submission.id != binding.submission_id
                || submission.namespace != manifest.namespace
                || submission.content_digest != binding.content_digest
                || submission.schema_id != binding.schema_id
                || submission.schema_version != binding.schema_version
                || envelope.content_digest != binding.content_digest
                || retained_content_digest != binding.content_digest
                || envelope.schema_id != binding.schema_id
                || envelope.schema_version != binding.schema_version
            {
                return Err(evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE.into());
            }
            inputs.push(evaluation_execution_domain::EvaluationEvidenceInput {
                evidence_object_id: binding.evidence_object_id.clone(),
                submission_id: binding.submission_id.clone(),
                content_digest: binding.content_digest.clone(),
                schema_id: binding.schema_id.clone(),
                schema_version: binding.schema_version.clone(),
                content: envelope.content,
            });
        }
        Ok(inputs)
    }

    fn unavailable_evaluation_node_evidence(
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        node: &evaluation_manifest_domain::ResolvedEvaluationNode,
    ) -> Result<Vec<evaluation_execution_domain::EvaluationEvidenceInput>, String> {
        let by_object = manifest
            .evidence
            .iter()
            .map(|evidence| (evidence.evidence_object_id.as_str(), evidence))
            .collect::<BTreeMap<_, _>>();
        node.evidence_object_ids
            .iter()
            .map(|object_id| {
                let binding = by_object
                    .get(object_id.as_str())
                    .ok_or_else(|| "manifest node evidence binding is missing".to_string())?;
                Ok(evaluation_execution_domain::EvaluationEvidenceInput {
                    evidence_object_id: binding.evidence_object_id.clone(),
                    submission_id: binding.submission_id.clone(),
                    content_digest: binding.content_digest.clone(),
                    schema_id: binding.schema_id.clone(),
                    schema_version: binding.schema_version.clone(),
                    content: serde_json::Value::Null,
                })
            })
            .collect()
    }

    fn stochastic_egress_reasons(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    ) -> BTreeMap<String, String> {
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let mut reasons = BTreeMap::new();
        for node in &manifest.nodes {
            let Some(policy) = &node.evaluator.stochastic_policy else {
                continue;
            };
            if policy.egress_policy
                == evaluation_plan_domain::STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL
                && !crate::chisei::privacy::provider_safe_to_send(&policy.provider, &safe_providers)
            {
                reasons.insert(
                    node.node_id.clone(),
                    evaluation_execution_domain::REASON_STOCHASTIC_EGRESS_DENIED.into(),
                );
            }
        }
        reasons
    }

    fn stochastic_budget_reason(
        budget: &BudgetTracker,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        node: &evaluation_manifest_domain::ResolvedEvaluationNode,
    ) -> Option<String> {
        let policy = node.evaluator.stochastic_policy.as_ref()?;
        let Ok(amount) = i32::try_from(policy.max_total_tokens) else {
            return Some(evaluation_execution_domain::REASON_STOCHASTIC_TOKEN_BUDGET.into());
        };
        let scope = format!(
            "project:{}/stochastic-evaluation:{}",
            manifest.namespace, node.node_id
        );
        let idempotency_key = format!(
            "stochastic-evaluation-reserve:{}:{}",
            manifest.manifest_digest, node.node_id
        );
        budget
            .check_and_reserve_idempotent(&scope, amount, &idempotency_key)
            .err()
            .map(|_| evaluation_execution_domain::REASON_STOCHASTIC_TOKEN_BUDGET.into())
    }

    fn run_evaluation_execution(
        db: &RuntimeDb,
        runtime: EvaluationExecutionRuntime<'_>,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        index: &evaluation_execution_domain::EvaluationExecutionIndex,
        max_total_duration_ms: u64,
        cancelled: Arc<AtomicBool>,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, Status> {
        let existing = Self::get_evaluation_projection(db, manifest, index)?;
        if existing.decision.is_some() {
            return Ok(existing);
        }
        let invocation_started = Instant::now();
        let total_budget = Duration::from_millis(max_total_duration_ms);
        let elapsed_before_invocation_ms = chrono::Utc::now()
            .timestamp_millis()
            .saturating_sub(index.created_at_ms)
            .max(0) as u64;
        let elapsed_before_invocation = Duration::from_millis(elapsed_before_invocation_ms);
        let order = evaluation_execution_domain::deterministic_topological_order(manifest)
            .map_err(Status::data_loss)?;
        let nodes = manifest
            .nodes
            .iter()
            .map(|node| (node.node_id.as_str(), node))
            .collect::<BTreeMap<_, _>>();
        let mut prior_steps = existing
            .steps
            .into_iter()
            .map(|step| (step.node_id.clone(), step))
            .collect::<BTreeMap<_, _>>();

        for node_id in order {
            if prior_steps.contains_key(&node_id) {
                continue;
            }
            if db
                .get_operation_receipt(&index.operation_id)
                .map_err(Status::internal)?
                .is_some_and(|receipt| evaluation_cancellation_requested(&receipt))
            {
                cancelled.store(true, Ordering::Release);
            }
            let node = nodes
                .get(node_id.as_str())
                .ok_or_else(|| Status::data_loss("evaluation node is missing"))?;
            let evidence = Self::load_evaluation_node_evidence(db, manifest, node);
            let evaluator_evidence = match &evidence {
                Ok(evidence) => evidence.clone(),
                Err(_) => Self::unavailable_evaluation_node_evidence(manifest, node)
                    .map_err(Status::data_loss)?,
            };
            let input = evaluation_execution_domain::build_evaluator_input(
                manifest,
                node,
                evaluator_evidence,
                &prior_steps,
            )
            .map_err(Status::data_loss)?;
            let mut execution = if cancelled.load(Ordering::Acquire) {
                evaluation_execution_domain::make_nonexecuted_node(
                    manifest,
                    node,
                    &input,
                    evaluation_execution_domain::STATUS_SKIPPED,
                    evaluation_execution_domain::REASON_EXECUTION_CANCELLED,
                )
            } else if let Some((status, reason)) =
                evaluation_execution_domain::dependency_blocking_status(node, &prior_steps)
            {
                evaluation_execution_domain::make_nonexecuted_node(
                    manifest, node, &input, status, reason,
                )
            } else if evidence.is_err() {
                evaluation_execution_domain::make_nonexecuted_node(
                    manifest,
                    node,
                    &input,
                    evaluation_execution_domain::STATUS_UNKNOWN,
                    evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE,
                )
            } else {
                let definition = db
                    .get_evaluator_definition(&node.evaluator.definition_id)
                    .map_err(Status::internal)?;
                let definition = definition.and_then(|definition| {
                    let canonical = evaluation_plan_domain::prepare_definition(
                        definition.clone(),
                        &definition.created_by,
                        definition.created_at_ms,
                    )
                    .ok()?;
                    (canonical == definition
                        && definition.content_digest == node.evaluator.definition_digest
                        && definition.implementation_digest == node.evaluator.implementation_digest
                        && definition.stochastic_policy == node.evaluator.stochastic_policy)
                        .then_some(definition)
                });
                if let Some(definition) = definition {
                    let remaining = total_budget
                        .saturating_sub(elapsed_before_invocation)
                        .saturating_sub(invocation_started.elapsed());
                    if definition.execution_class
                        == evaluation_plan_domain::EXTERNAL_ADAPTER_EXECUTION_CLASS
                        && !runtime.deterministic_registry.contains_external_adapter(
                            &definition.namespace,
                            &definition.content_digest,
                            &definition.implementation_digest,
                        )
                    {
                        evaluation_execution_domain::make_nonexecuted_node(
                            manifest,
                            node,
                            &input,
                            evaluation_execution_domain::STATUS_UNAVAILABLE,
                            evaluation_execution_domain::REASON_EVALUATOR_UNAVAILABLE,
                        )
                    } else if definition.execution_class
                        == evaluation_plan_domain::STOCHASTIC_EXECUTION_CLASS
                    {
                        if let Some(reason) = runtime.stochastic_egress_reasons.get(&node.node_id) {
                            evaluation_execution_domain::make_nonexecuted_node(
                                manifest,
                                node,
                                &input,
                                evaluation_execution_domain::STATUS_UNAVAILABLE,
                                reason,
                            )
                        } else if !runtime
                            .stochastic_registry
                            .contains(&definition.implementation_digest)
                        {
                            evaluation_execution_domain::execute_stochastic_node(
                                runtime.stochastic_registry,
                                manifest,
                                node,
                                input.clone(),
                                &definition.resource_limits,
                                remaining,
                                cancelled.clone(),
                            )
                        } else if let Some(reason) =
                            Self::stochastic_budget_reason(runtime.budget, manifest, node)
                        {
                            evaluation_execution_domain::make_nonexecuted_node(
                                manifest,
                                node,
                                &input,
                                evaluation_execution_domain::STATUS_UNAVAILABLE,
                                &reason,
                            )
                        } else {
                            evaluation_execution_domain::execute_stochastic_node(
                                runtime.stochastic_registry,
                                manifest,
                                node,
                                input.clone(),
                                &definition.resource_limits,
                                remaining,
                                cancelled.clone(),
                            )
                        }
                    } else {
                        evaluation_execution_domain::execute_registered_node(
                            runtime.deterministic_registry,
                            manifest,
                            node,
                            input.clone(),
                            &definition.resource_limits,
                            remaining,
                            cancelled.clone(),
                        )
                    }
                } else {
                    evaluation_execution_domain::make_nonexecuted_node(
                        manifest,
                        node,
                        &input,
                        evaluation_execution_domain::STATUS_UNAVAILABLE,
                        evaluation_execution_domain::REASON_EVALUATOR_UNAVAILABLE,
                    )
                }
            }
            .map_err(Status::internal)?;
            if db
                .get_operation_receipt(&index.operation_id)
                .map_err(Status::internal)?
                .is_some_and(|receipt| evaluation_cancellation_requested(&receipt))
                && execution.receipt.reason_code
                    != evaluation_execution_domain::REASON_EXECUTION_CANCELLED
            {
                cancelled.store(true, Ordering::Release);
                execution = evaluation_execution_domain::make_nonexecuted_node(
                    manifest,
                    node,
                    &input,
                    evaluation_execution_domain::STATUS_SKIPPED,
                    evaluation_execution_domain::REASON_EXECUTION_CANCELLED,
                )
                .map_err(Status::internal)?;
            }
            let event = evaluation_step_event(
                &index.operation_id,
                node,
                &execution.receipt,
                chrono::Utc::now().timestamp_millis(),
            )?;
            let (receipt, recorded) = match db
                .append_operation_receipt_event(&index.operation_id, event)
            {
                Ok(result) => result,
                Err(error) => {
                    let receipt = db
                        .get_operation_receipt(&index.operation_id)
                        .map_err(Status::internal)?
                        .ok_or_else(|| {
                            Status::data_loss("evaluation execution receipt is missing")
                        })?;
                    let projection = evaluation_projection_from_receipt(manifest, index, &receipt)
                        .map_err(Status::data_loss)?;
                    let durable_step = projection
                        .steps
                        .iter()
                        .find(|step| step.node_id == node.node_id);
                    let durable_step_matches =
                        durable_step.is_some_and(|step| step == &execution.receipt);
                    let durable_cancellation_won =
                        evaluation_cancellation_requested(&receipt) && durable_step.is_some();
                    if projection.decision.is_some()
                        || durable_step_matches
                        || durable_cancellation_won
                    {
                        (receipt, false)
                    } else if evaluation_cancellation_requested(&receipt) {
                        cancelled.store(true, Ordering::Release);
                        execution = evaluation_execution_domain::make_nonexecuted_node(
                            manifest,
                            node,
                            &input,
                            evaluation_execution_domain::STATUS_SKIPPED,
                            evaluation_execution_domain::REASON_EXECUTION_CANCELLED,
                        )
                        .map_err(Status::internal)?;
                        let cancellation_event = evaluation_step_event(
                            &index.operation_id,
                            node,
                            &execution.receipt,
                            chrono::Utc::now().timestamp_millis(),
                        )?;
                        db.append_operation_receipt_event(&index.operation_id, cancellation_event)
                            .map_err(Status::internal)?
                    } else {
                        return Err(Status::internal(error));
                    }
                }
            };
            let projection = evaluation_projection_from_receipt(manifest, index, &receipt)
                .map_err(Status::data_loss)?;
            if recorded {
                let durable_step = projection
                    .steps
                    .iter()
                    .find(|step| step.node_id == node.node_id)
                    .ok_or_else(|| Status::data_loss("durable evaluation step is missing"))?;
                let (metrics_evaluator, metrics_version) =
                    if node.evaluator.stochastic_policy.is_some() {
                        runtime
                            .stochastic_registry
                            .metric_labels(&node.evaluator.implementation_digest)
                    } else {
                        runtime.deterministic_registry.metric_labels_for_namespace(
                            &manifest.namespace,
                            &node.evaluator.definition_digest,
                            &node.evaluator.implementation_digest,
                        )
                    };
                crate::obs::signals::record_evaluation_step(
                    metrics_evaluator,
                    metrics_version,
                    &durable_step.status,
                    execution.elapsed,
                );
            }
            prior_steps = projection
                .steps
                .into_iter()
                .map(|step| (step.node_id.clone(), step))
                .collect();
        }

        let steps = prior_steps.values().cloned().collect::<Vec<_>>();
        let decision = evaluation_execution_domain::reduce_gate(manifest, &steps)
            .map_err(Status::data_loss)?;
        let parent_event_id = order_parent_event_id(manifest, &index.operation_id);
        let event = evaluation_gate_event(
            &index.operation_id,
            parent_event_id.clone(),
            &decision,
            chrono::Utc::now().timestamp_millis(),
        )?;
        let receipt = match db.append_operation_receipt_event(&index.operation_id, event) {
            Ok((receipt, _)) => receipt,
            Err(error) => {
                let receipt = db
                    .get_operation_receipt(&index.operation_id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
                let projection = evaluation_projection_from_receipt(manifest, index, &receipt)
                    .map_err(Status::data_loss)?;
                if projection.decision.is_some() {
                    receipt
                } else {
                    if !evaluation_cancellation_requested(&receipt) {
                        return Err(Status::internal(error));
                    }
                    cancelled.store(true, Ordering::Release);
                    let cancellation_decision =
                        evaluation_execution_domain::reduce_cancelled_gate(manifest, &steps)
                            .map_err(Status::data_loss)?;
                    let cancellation_event = evaluation_gate_event(
                        &index.operation_id,
                        parent_event_id,
                        &cancellation_decision,
                        chrono::Utc::now().timestamp_millis(),
                    )?;
                    db.append_operation_receipt_event(&index.operation_id, cancellation_event)
                        .map_err(Status::internal)?
                        .0
                }
            }
        };
        evaluation_projection_from_receipt(manifest, index, &receipt).map_err(Status::data_loss)
    }

    fn resolve_evaluation_plan_internal(
        &self,
        prepared: &evaluation_manifest_domain::PreparedResolutionRequest,
    ) -> Result<evaluation_manifest_domain::EvaluationResolutionOutcome, Status> {
        let (mut outcome, stored) = self.db.with_evaluation_resolution_snapshot(
            || {
                require_namespace_write_access(
                    &self.db,
                    &prepared.actor,
                    &prepared.request.namespace,
                )?;
                if let Some(replay) = self
                    .db
                    .get_evaluation_manifest_for_request(
                        &prepared.request.namespace,
                        &prepared.actor,
                        &prepared.request.request_id,
                    )
                    .map_err(Status::internal)?
                {
                    if replay.request_digest != prepared.request_digest {
                        return Err(Status::already_exists(
                            "evaluation resolution request already exists with different content",
                        ));
                    }
                    return Ok((
                        evaluation_manifest_domain::resolved_outcome(replay.manifest),
                        None,
                    ));
                }
                let resolution_time_ms = chrono::Utc::now().timestamp_millis();
                let outcome =
                    resolve_evaluation_manifest_live(&self.db, prepared, resolution_time_ms)?;
                let write = outcome.manifest.as_ref().map(|manifest| {
                    crate::db::runtime_db::EvaluationManifestWrite {
                        manifest: manifest.clone(),
                        request_id: prepared.request.request_id.clone(),
                        request_digest: prepared.request_digest.clone(),
                    }
                });
                Ok((outcome, write))
            },
            map_evaluation_manifest_storage_error,
        )?;
        if let Some(stored) = stored {
            outcome.manifest = Some(stored);
        }
        Ok(outcome)
    }

    async fn execute_evaluation_manifest_internal(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        actor: &str,
        max_total_duration_ms: u64,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, Status> {
        for node in &manifest.nodes {
            if let Some(definition) = self
                .db
                .get_evaluator_definition(&node.evaluator.definition_id)
                .map_err(Status::internal)?
            {
                self.ensure_external_evaluator_registered(&definition);
            }
        }
        let index = self.ensure_evaluation_execution(manifest, actor, max_total_duration_ms)?;
        let receipt = self
            .db
            .get_operation_receipt(&index.operation_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
        let frozen_total_duration_ms = evaluation_total_budget_ms(&receipt)?;
        if frozen_total_duration_ms > max_total_duration_ms {
            return Err(Status::failed_precondition(
                "existing evaluation execution budget exceeds the requested bound",
            ));
        }
        let cancelled = {
            let mut cancellations = self
                .evaluation_cancellations
                .lock()
                .map_err(|_| Status::internal("evaluation cancellation lock poisoned"))?;
            cancellations
                .entry(manifest.manifest_digest.clone())
                .or_insert_with(|| Arc::new(AtomicBool::new(false)))
                .clone()
        };
        let execution_lock = {
            let mut locks = self
                .evaluation_execution_locks
                .lock()
                .map_err(|_| Status::internal("evaluation execution lock poisoned"))?;
            locks
                .entry(manifest.manifest_digest.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _guard = execution_lock.lock().await;
        let worker_db = self.db.clone();
        let worker_budget = self.budget.clone();
        let worker_registry = self.evaluator_registry.clone();
        let worker_stochastic_registry = self.stochastic_evaluator_registry.clone();
        let stochastic_egress_reasons = self.stochastic_egress_reasons(manifest);
        let worker_manifest = manifest.clone();
        let worker_index = index;
        let projection = tokio::task::spawn_blocking(move || {
            Self::run_evaluation_execution(
                &worker_db,
                EvaluationExecutionRuntime {
                    deterministic_registry: &worker_registry,
                    stochastic_registry: &worker_stochastic_registry,
                    stochastic_egress_reasons: &stochastic_egress_reasons,
                    budget: &worker_budget,
                },
                &worker_manifest,
                &worker_index,
                frozen_total_duration_ms,
                cancelled,
            )
        })
        .await
        .map_err(|error| Status::internal(format!("evaluation worker failed: {error}")))??;
        if projection.decision.is_some() {
            self.evaluation_cancellations
                .lock()
                .map_err(|_| Status::internal("evaluation cancellation lock poisoned"))?
                .remove(&manifest.manifest_digest);
            let mut locks = self
                .evaluation_execution_locks
                .lock()
                .map_err(|_| Status::internal("evaluation execution lock poisoned"))?;
            if locks
                .get(&manifest.manifest_digest)
                .is_some_and(|lock| Arc::ptr_eq(lock, &execution_lock))
            {
                locks.remove(&manifest.manifest_digest);
            }
        }
        Ok(projection)
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

    fn gateway_pipeline_decision(
        &self,
        input: GatewayPipelineInput<'_>,
    ) -> Result<GatewayPipelineDecision, Status> {
        let context_actor = execution_context_actor(
            &self.db,
            &self.config,
            input.actor,
            input.delegated_principal,
            input.namespace,
        )?;
        let context_admission_policy = self
            .policy
            .context_admission_policy(input.namespace)
            .map_err(Status::failed_precondition)?;
        let mut request = pipe::PipelineRequest {
            request_id: input.request_id.to_string(),
            namespace: input.namespace.to_string(),
            spec: input.spec.to_string(),
            model: input.model.to_string(),
            runtime: input.runtime.to_string(),
            task_type: "gateway_llm_call".into(),
            priority: 0,
            risk_score: 0.0,
            budget_pressure: self.budget.namespace_pressure(input.namespace),
            review_model: String::new(),
            egress_records: vec![],
            external_egress: true,
            template_only: TaskClass::parse(input.task_class) == TaskClass::TemplateOnly,
            expanded_context_items: 0,
            evidence_references: vec![],
            memory_references: vec![],
            memory_holdouts: vec![],
            memory_actor: context_actor,
            memory_assignment_id: String::new(),
            memory_token_budget: 512,
            allowed_evidence_classes: HashSet::new(),
            context_admission_policy,
            context_admission: pipe::ContextAdmissionSummary::default(),
            risk_score_ready: false,
            risk_signals: vec![],
            operation_risk_override: None,
        };
        let context_expansion_gate = self.pipeline_context_expansion_gate(input.namespace);
        let evidence_context_gates =
            self.applicable_evidence_context_gates(&request, context_expansion_gate.allowed)?;
        let allowed_evidence_classes = evidence_context_gates
            .iter()
            .filter(|class_gate| class_gate.effective_allowed)
            .map(|class_gate| pipe::EvidenceContextClass {
                source_type: class_gate.source_type.clone(),
                evidence_type: class_gate.evidence_type.clone(),
            })
            .collect::<HashSet<_>>();
        let run = self.pipeline.run_with_context_admission(
            &mut request,
            &self.db,
            context_expansion_gate.allowed,
            allowed_evidence_classes,
        );
        self.record_context_expansion_gate(
            input.request_id,
            input.namespace,
            &context_expansion_gate,
            run.expanded_context_items,
        )?;
        self.record_evidence_context_gates(
            input.request_id,
            input.namespace,
            &evidence_context_gates,
            &run.evidence_references,
        )?;
        let sampling = crate::chisei::sampling::decode_sampling(&run.steps).unwrap_or(
            crate::chisei::sampling::SamplingDecision {
                sampled: false,
                effective_rate: self.config.sample_rate,
                reason: "not_sampled".into(),
            },
        );
        Ok(GatewayPipelineDecision { run, sampling })
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
                (
                    "previous_prompt_variant".into(),
                    selection.previous_prompt_variant.clone(),
                ),
                ("selected_model".into(), selection.model.clone()),
                (
                    "selected_prompt_variant".into(),
                    selection.prompt_variant.clone(),
                ),
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

    pub fn with_budget(db: Arc<RuntimeDb>, config: Config, budget: Arc<BudgetTracker>) -> Self {
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
            candidates: Arc::new(CandidateStore::new()),
            active_promotions: Arc::new(ActivePromotions::new()),
            evaluator_registry: Arc::new(
                evaluation_execution_domain::DeterministicEvaluatorRegistry::default(),
            ),
            stochastic_evaluator_registry: Arc::new(
                crate::chisei::stochastic_evaluation::production_stochastic_evaluator_registry(
                    config.clone(),
                )
                .expect("compiled stochastic evaluator registry must be valid"),
            ),
            evaluation_cancellations: Arc::new(Mutex::new(HashMap::new())),
            evaluation_execution_locks: Arc::new(Mutex::new(HashMap::new())),
            db,
            config,
            provider_registry_state_path,
        }
    }

    fn bind_gunshi_allocation(
        &self,
        mut input: ExecutionInput,
        binding: GunshiAllocationBinding,
    ) -> Result<(ExecutionInput, BoundGunshiAllocation), Status> {
        let issuance_id = binding.issuance_id.trim();
        if issuance_id.is_empty()
            || issuance_id.len() > 128
            || issuance_id != binding.issuance_id
            || !issuance_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.:".contains(character))
        {
            return Err(Status::invalid_argument(
                "Gunshi issuance_id must be a canonical identifier of at most 128 characters",
            ));
        }
        if binding.allocation_json.len() > 256 * 1024 {
            return Err(Status::invalid_argument(
                "Gunshi allocation exceeds the size limit",
            ));
        }
        let allocation: crate::chisei::gunshi::AllocationPlan =
            serde_json::from_str(&binding.allocation_json).map_err(|error| {
                Status::invalid_argument(format!("invalid Gunshi allocation: {error}"))
            })?;
        allocation.validate().map_err(Status::invalid_argument)?;
        crate::chisei::gunshi_feedback::require_issued_plan(&self.db, issuance_id, &allocation)
            .map_err(Status::failed_precondition)?;

        if input.namespace.trim() != allocation.namespace {
            return Err(Status::failed_precondition(
                "Gunshi allocation namespace does not match execution input",
            ));
        }
        let current_policy_version = self
            .policy
            .effective_policy(&allocation.namespace)
            .map(|policy| policy.version())
            .unwrap_or_else(|| "implicit-allow/v1".into());
        if allocation.policy_version != current_policy_version {
            return Err(Status::failed_precondition(
                "Gunshi allocation policy version is no longer current",
            ));
        }
        if !input.logical_operation_id.trim().is_empty()
            && input.logical_operation_id.trim() != allocation.operation_id
        {
            return Err(Status::failed_precondition(
                "Gunshi allocation operation does not match execution input",
            ));
        }
        if !input.task_class.trim().is_empty()
            && input.task_class.trim() != allocation.operation_class
        {
            return Err(Status::failed_precondition(
                "Gunshi allocation operation class does not match execution input",
            ));
        }
        let allocation_priority = i32::from(allocation.priority);
        if input.priority != 0 && input.priority != allocation_priority {
            return Err(Status::failed_precondition(
                "Gunshi allocation priority does not match execution input",
            ));
        }
        for (name, requested, allocated) in [
            (
                "preferred runtime",
                input.preferred_runtime.trim(),
                allocation.selection.runtime.as_str(),
            ),
            (
                "preferred model",
                input.preferred_model.trim(),
                allocation.selection.model.as_str(),
            ),
            (
                "route override",
                input.route_override.trim(),
                allocation.selection.model.as_str(),
            ),
        ] {
            if !requested.is_empty() && requested != "auto" && requested != allocated {
                return Err(Status::failed_precondition(format!(
                    "execution {name} conflicts with the Gunshi allocation"
                )));
            }
        }
        let requested_tools = input
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<BTreeSet<_>>();
        let allocated_tools = allocation
            .selection
            .tools
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if requested_tools.len() != input.tools.len() || requested_tools != allocated_tools {
            return Err(Status::failed_precondition(
                "execution tools must exactly match the Gunshi allocation",
            ));
        }

        input.logical_operation_id = allocation.operation_id.clone();
        input.task_class = allocation.operation_class.clone();
        input.priority = allocation_priority;
        input.preferred_runtime = allocation.selection.runtime.clone();
        input.preferred_model = allocation.selection.model.clone();
        input.route_override.clear();
        Ok((
            input,
            BoundGunshiAllocation {
                issuance_id: issuance_id.into(),
                plan: allocation,
            },
        ))
    }

    async fn plan_from_input(
        &self,
        input: ExecutionInput,
        authenticated_actor: &str,
    ) -> Result<ExecutionPlan, Status> {
        let plan_id = uuid::Uuid::new_v4().to_string();
        let mut context_projection_latency_ms = 0_u64;
        let normalized_user_id =
            execution_budget_scope(&input.namespace, authenticated_actor, &input.user_id);
        let scoped_pressure = self.budget.scope_pressure(&normalized_user_id);
        let namespace_pressure = self
            .budget
            .scope_pressure(&format!("project:{}", input.namespace.trim()));
        let budget_pressure = strongest_pressure(scoped_pressure, namespace_pressure);
        let namespace_hint = input.namespace.trim().to_string();
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let context_admission_policy = self
            .policy
            .context_admission_policy(&input.namespace)
            .map_err(Status::failed_precondition)?;
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
            context_admission_policy: context_admission_policy.clone(),
            context_admission: pipe::ContextAdmissionSummary::default(),
            risk_score_ready: false,
            risk_signals: vec![],
            operation_risk_override: None,
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
        let projection_started = Instant::now();
        let initial_run = self.pipeline.run_with_context_admission(
            &mut pipeline_req,
            &self.db,
            context_expansion_gate.allowed,
            allowed_evidence_classes.clone(),
        );
        context_projection_latency_ms = context_projection_latency_ms.saturating_add(
            u64::try_from(projection_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        );
        let fallback_runtime = pipeline_req.runtime.clone();
        let (initial_runtime, initial_model, initial_pref_runtime, initial_pref_model) = self
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
        let (
            run,
            resolved_runtime,
            resolved_model,
            provider,
            provider_is_external,
            effective_preferred_runtime,
            effective_preferred_model,
        ) = if initial_provider_is_external || safe_only || template_only {
            (
                initial_run,
                initial_runtime,
                initial_model,
                initial_provider,
                true,
                initial_pref_runtime,
                initial_pref_model,
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
                context_admission_policy: context_admission_policy.clone(),
                context_admission: pipe::ContextAdmissionSummary::default(),
                risk_score_ready: false,
                risk_signals: vec![],
                operation_risk_override: None,
            };
            let projection_started = Instant::now();
            let local_run = self.pipeline.run_with_context_admission(
                &mut local_pipeline_req,
                &self.db,
                context_expansion_gate.allowed,
                allowed_evidence_classes,
            );
            context_projection_latency_ms = context_projection_latency_ms.saturating_add(
                u64::try_from(projection_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
            let (local_runtime, local_model, local_pref_runtime, local_pref_model) = self
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
                    initial_pref_runtime,
                    initial_pref_model,
                )
            } else {
                (
                    local_run,
                    local_runtime,
                    local_model,
                    local_provider,
                    false,
                    local_pref_runtime,
                    local_pref_model,
                )
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
        let estimate_req = ProviderExecutionRequest {
            model: resolved_model.clone(),
            system: input.system.clone(),
            messages: prepared_messages.clone(),
            tools: input.tools.clone(),
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
        // Persist the pre-policy preference actually used for resolve (request,
        // route override, recommendation, bias, or runtime fallback)—not only
        // empty raw request fields—so historical dry-run can replay accurately.
        normalized_input.preferred_runtime = effective_preferred_runtime;
        normalized_input.preferred_model = effective_preferred_model;
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
                    None,
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
        if run.context_admission.blocks_provider() {
            executable = false;
            if run.context_admission.requires_review {
                warnings.push("context admission requires review".into());
            }
            if run.context_admission.requires_verification {
                warnings.push("context admission requires verification".into());
            }
        }
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
        let context_bytes = context_bytes(&input.system, &prepared_messages);
        let context_tokens = estimate_context_tokens(&input.system, &prepared_messages);
        let context_truncated = run
            .evidence_references
            .iter()
            .any(|reference| reference.descriptor.source_rows_truncated)
            || run
                .memory_references
                .iter()
                .any(|reference| reference.descriptor.source_rows_truncated);
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
            context_admission_policy_version: run.context_admission.policy_version.clone(),
            context_admission_descriptor_version: run.context_admission.descriptor_version.clone(),
            context_admission_decision: run.context_admission.decision.clone(),
            context_admission_reasons: run.context_admission.reason_codes.clone(),
            context_admission_source_digests: run.context_admission.source_digests.clone(),
            context_admission_requires_review: run.context_admission.requires_review,
            context_admission_requires_verification: run.context_admission.requires_verification,
            context_bytes,
            context_tokens,
            context_projection_latency_ms,
            context_truncated,
            gunshi_issuance_id: String::new(),
            gunshi_allocation_id: String::new(),
            gunshi_agent_id: String::new(),
            gunshi_policy_version: String::new(),
            gunshi_input_fingerprint: String::new(),
            gunshi_budget_ceiling_usd_micros: 0,
            gunshi_max_attempts: 0,
            gunshi_human_review_required: false,
        })
    }

    #[cfg(test)]
    fn cache_plan(&self, plan: ExecutionPlan) {
        self.cache_plan_for_enterprise_authority(plan, None);
    }

    fn cache_plan_for_enterprise_authority(
        &self,
        plan: ExecutionPlan,
        enterprise_authority: Option<String>,
    ) {
        let mut plans = self
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        prune_expired_plans(&mut plans);
        let inserted_plan_id = plan.plan_id.clone();
        plans.insert(
            inserted_plan_id.clone(),
            CachedExecutionPlan {
                plan,
                enterprise_authority,
            },
        );
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
                        // Effective pre-policy preference (request, override,
                        // recommendation, bias, or runtime fallback).
                        ("preferred_runtime".into(), input.preferred_runtime.clone()),
                        ("preferred_model".into(), input.preferred_model.clone()),
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
                    if !plan.gunshi_allocation_id.is_empty() {
                        attributes.extend([
                            ("gunshi_issuance_id".into(), plan.gunshi_issuance_id.clone()),
                            (
                                "gunshi_allocation_id".into(),
                                plan.gunshi_allocation_id.clone(),
                            ),
                            ("gunshi_agent_id".into(), plan.gunshi_agent_id.clone()),
                            (
                                "gunshi_policy_version".into(),
                                plan.gunshi_policy_version.clone(),
                            ),
                            (
                                "gunshi_input_fingerprint".into(),
                                plan.gunshi_input_fingerprint.clone(),
                            ),
                        ]);
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
                {
                    let mut attributes = BTreeMap::from([
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
                    ]);
                    attributes.extend(epistemic_descriptor_receipt_attributes(plan));
                    attributes
                },
            ),
            receipt_event(
                &operation_id,
                "policy",
                Some("context"),
                started,
                ReceiptEventKind::PolicyDecided,
                "chisei.policy",
                {
                    let mut attributes = BTreeMap::from([
                        ("policy_version".into(), policy_version.clone()),
                        ("executable".into(), plan.executable.to_string()),
                        ("risk_score".into(), plan.risk_score.to_string()),
                        (
                            "route_policy_decision".into(),
                            if plan.resolved_runtime.is_empty() && plan.resolved_model.is_empty() {
                                "deny".into()
                            } else {
                                "allow".into()
                            },
                        ),
                    ]);
                    if !plan.context_admission_policy_version.is_empty() {
                        attributes.insert(
                            "context_admission_policy_version".into(),
                            plan.context_admission_policy_version.clone(),
                        );
                        attributes.insert(
                            "context_admission_descriptor_version".into(),
                            plan.context_admission_descriptor_version.clone(),
                        );
                        attributes.insert(
                            "context_admission_decision".into(),
                            plan.context_admission_decision.clone(),
                        );
                        attributes.insert(
                            "context_admission_reasons".into(),
                            plan.context_admission_reasons.join(","),
                        );
                        attributes.insert(
                            "context_admission_source_digests".into(),
                            plan.context_admission_source_digests.join(","),
                        );
                    }
                    attributes
                },
            ),
            receipt_event(
                &operation_id,
                "route",
                Some("policy"),
                started,
                ReceiptEventKind::RouteSelected,
                "chisei.routing",
                {
                    let mut attributes = BTreeMap::from([
                        ("runtime".into(), plan.resolved_runtime.clone()),
                        ("model".into(), plan.resolved_model.clone()),
                        // Effective pre-policy preference (also on Intent) for dry-run.
                        ("preferred_runtime".into(), input.preferred_runtime.clone()),
                        ("preferred_model".into(), input.preferred_model.clone()),
                        (
                            "route_override".into(),
                            if input.route_override.trim().is_empty() {
                                String::new()
                            } else {
                                input.route_override.trim().into()
                            },
                        ),
                        (
                            "bias_bypassed".into(),
                            (!input.route_override.trim().is_empty()).to_string(),
                        ),
                    ]);
                    if !plan.gunshi_allocation_id.is_empty() {
                        attributes.insert(
                            "gunshi_allocation_id".into(),
                            plan.gunshi_allocation_id.clone(),
                        );
                        attributes.insert("gunshi_agent_id".into(), plan.gunshi_agent_id.clone());
                    }
                    attributes
                },
            ),
            receipt_event(
                &operation_id,
                "budget",
                Some("route"),
                started,
                ReceiptEventKind::BudgetDecided,
                "chisei.budget",
                {
                    let mut attributes = BTreeMap::from([
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
                    ]);
                    if !plan.gunshi_allocation_id.is_empty() {
                        attributes.insert(
                            "gunshi_budget_ceiling_usd_micros".into(),
                            plan.gunshi_budget_ceiling_usd_micros.to_string(),
                        );
                        attributes.insert(
                            "gunshi_max_attempts".into(),
                            plan.gunshi_max_attempts.to_string(),
                        );
                        attributes.insert(
                            "gunshi_human_review_required".into(),
                            plan.gunshi_human_review_required.to_string(),
                        );
                    }
                    attributes
                },
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

    /// Resolve runtime/model and return the effective pre-policy preference
    /// that was fed into policy resolution: `(resolved_runtime, resolved_model,
    /// preferred_runtime, preferred_model)`.
    async fn resolve_model_for_run(
        &self,
        input: &ExecutionInput,
        fallback_runtime: &str,
        run: &pipe::RunResult,
        policy: Option<&crate::chisei::policy::Policy>,
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
    ) -> Result<(String, String, String, String), Status> {
        let route_override = input.route_override.trim();
        if !route_override.is_empty() && !route_override_allowed(policy, route_override) {
            return Err(Status::invalid_argument(format!(
                "route override {route_override:?} is not allowed by namespace policy"
            )));
        }
        let recommended_model = run
            .recommended_model()
            .map(|(model, _)| model.to_string())
            .unwrap_or_else(|| input.preferred_model.clone());
        let route_bias_value =
            crate::chisei::model_routing::route_bias(&run.steps).map(str::to_string);
        let route_bias = route_bias_value.as_deref();
        let preferred_model = if route_override.is_empty() {
            choose_preferred_model(
                &input.preferred_model,
                &recommended_model,
                route_bias,
                policy,
            )
        } else {
            route_override.to_string()
        };
        let override_runtime = (!route_override.is_empty())
            .then(|| crate::provider_resolution::resolve_model(route_override))
            .transpose()
            .map_err(Status::invalid_argument)?
            .map(|model| model.provider);
        let preferred_runtime = if let Some(runtime) = override_runtime.as_deref() {
            runtime.to_string()
        } else if input.preferred_runtime.is_empty() {
            fallback_runtime.to_string()
        } else {
            input.preferred_runtime.clone()
        };
        let (runtime, model) = self
            .policy
            .resolve(&input.namespace, &preferred_runtime, &preferred_model)
            .map_err(Status::invalid_argument)?;
        let model = self
            .resolve_live_model_with_override(
                &model,
                policy,
                if route_override.is_empty() {
                    route_bias
                } else {
                    None
                },
                safe_only,
                safe_providers,
                None,
                !route_override.is_empty(),
            )
            .await
            .map_err(Status::failed_precondition)?;
        let runtime = final_runtime_for_model(policy, &runtime, &model)
            .map_err(Status::failed_precondition)?;
        // Single-plane residency (#289): fail closed before any provider contact.
        let data_class = policy
            .map(|policy| policy.data_class.as_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("unclassified");
        let provider = crate::llm::provider_name(&model);
        self.policy
            .enforce_residency(&input.namespace, provider, &model, data_class)
            .map_err(Status::permission_denied)?;
        Ok((runtime, model, preferred_runtime, preferred_model))
    }

    fn data_class(&self, policy: Option<&crate::chisei::policy::Policy>) -> DataClass {
        policy
            .map(|policy| DataClass::parse(&policy.data_class))
            .filter(|class| *class != DataClass::Unclassified)
            .unwrap_or_else(|| DataClass::parse(&self.config.default_data_class))
    }

    fn enforce_execution_provider_privacy(
        &self,
        plan: &ExecutionPlan,
        input: &ExecutionInput,
        actor: &str,
        provider: &str,
        data_class: DataClass,
    ) -> Result<(), Status> {
        let task_class = TaskClass::parse(&plan.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        if safe_only && !crate::chisei::privacy::provider_safe_to_send(provider, &safe_providers) {
            self.record_privacy_audit(
                "blocked",
                &input.request_id,
                provider,
                data_class,
                task_class,
                "cached_plan_unsafe_provider",
            );
            record_failed_operation_on(&self.db, plan, actor, "provider_became_unsafe")
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                crate::chisei::privacy::gate_reason(data_class, task_class, provider),
            ));
        }
        Ok(())
    }

    fn enforce_execution_payload_privacy(
        &self,
        plan: &ExecutionPlan,
        input: &ExecutionInput,
        actor: &str,
        provider: &str,
        data_class: DataClass,
    ) -> Result<(), Status> {
        let payload =
            payload_for_leak_check(&plan.prepared_system, &plan.prepared_messages, &plan.tools);
        let leak_findings =
            self.leak_findings_for_payload(&input.namespace, provider, data_class, &payload);
        if leak_findings
            .iter()
            .any(|finding| finding.action == LeakAction::Block)
        {
            self.record_leak_audit(
                "execute_leak_check",
                &input.request_id,
                provider,
                &leak_findings,
            );
            record_failed_operation_on(
                &self.db,
                plan,
                actor,
                "privacy_leak_detected_after_planning",
            )
            .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "privacy leak checker blocked outbound payload",
            ));
        }
        Ok(())
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
            match crate::provider_resolution::snapshot_for_execution(Some(&registry_state_path))
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
            prompt_cache: Default::default(),
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
        requirements: Option<&crate::provider_profile::CapabilityRequirements>,
    ) -> Result<String, String> {
        self.resolve_live_model_with_override(
            model,
            policy,
            route_bias,
            safe_only,
            safe_providers,
            requirements,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_live_model_with_override(
        &self,
        model: &str,
        policy: Option<&crate::chisei::policy::Policy>,
        route_bias: Option<&str>,
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
        requirements: Option<&crate::provider_profile::CapabilityRequirements>,
        exact_override: bool,
    ) -> Result<String, String> {
        validate_explicit_requested_model(model)?;
        let discovery = crate::chisei::model_availability::ModelDiscoveryConfig {
            openai_base_url: std::env::var("CHISEI_OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com/v1".into()),
            openai_api_key: self.config.openai_api_key.clone(),
            anthropic_base_url: std::env::var("CHISEI_ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com/v1".into()),
            anthropic_api_key: self.config.anthropic_api_key.clone(),
            ollama_url: self.config.ollama_url.clone(),
            native_configured: self.config.native_llm_url.is_some(),
        };
        let availability =
            crate::chisei::model_availability::refresh_model_availability(&discovery, false).await;
        let available_models = availability
            .models_by_provider
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let discovered_ollama = crate::chisei::model_availability::ollama_models(&availability);
        let empty_allowed = Vec::new();
        let allowed_models = policy
            .map(|policy| policy.allowed_models.as_slice())
            .unwrap_or(empty_allowed.as_slice());
        let base_context = crate::chisei::model_routing::RoutingContext {
            requested: model,
            allowed_models,
            route_bias,
            config: &self.config,
            ollama_models: &discovered_ollama,
            available_models: &available_models,
            authoritative_providers: &availability.authoritative_providers,
            requirements,
            safe_only,
            safe_providers,
        };
        let needs_ollama_first = !model.contains('/')
            && model != "native-default"
            && model != "cheap"
            && model != "capable"
            && crate::llm::provider_name(model) == "native";
        if exact_override {
            return crate::chisei::model_routing::resolve_override(base_context);
        }
        if !needs_ollama_first
            && let Ok(resolved) = crate::chisei::model_routing::resolve_model(base_context.clone())
        {
            return Ok(resolved);
        }

        crate::chisei::model_routing::resolve_model(crate::chisei::model_routing::RoutingContext {
            ..base_context
        })
    }

    async fn refresh_provider_registry_for_resolution(
        &self,
    ) -> Result<crate::provider_profile::ProviderRegistry, Status> {
        let Some(path) = self.provider_registry_state_path.as_deref() else {
            return Ok(crate::provider_profile::provider_registry_snapshot());
        };
        crate::provider_resolution::snapshot_for_execution(Some(path))
            .await
            .map_err(|error| Status::unavailable(format!("provider registry unavailable: {error}")))
    }

    fn record_evolve_task(
        &self,
        request_id: &str,
        namespace: &str,
        spec: &str,
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
                status,
                tokens_used,
            },
        )
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
/// Canonical gateway decisions and `RecordUsage` walk and deduct the whole ancestor chain
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
    db: &RuntimeDb,
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

/// Internal policy-resolution request used by the canonical fat-decide path.
/// It deliberately is not a public protobuf message or RPC.
#[derive(Clone, Debug, Default)]
struct ResolvePolicyRequest {
    namespace: String,
    preferred_runtime: String,
    preferred_model: String,
    subject: String,
    project: String,
    agent: String,
    key_id: String,
    task_class: String,
    #[allow(dead_code)]
    user_id: String,
    expected_calls: i64,
    budget_route_bias: String,
    route_override: String,
    capability_requirements_json: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct ResolvePolicyResponse {
    resolution: Option<PolicyResolution>,
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

fn route_override_allowed(policy: Option<&Policy>, model: &str) -> bool {
    policy.is_none_or(|policy| {
        policy.allowed_models.is_empty()
            || policy
                .allowed_models
                .iter()
                .any(|allowed| models_have_same_identity(allowed, model))
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
        let identity = crate::provider_resolution::resolve_model(model)?;
        if identity.provider == "native" {
            crate::provider_resolution::resolve_model(model)?;
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

fn prune_cached_plans(plans: &mut HashMap<String, CachedExecutionPlan>) {
    prune_expired_plans(plans);
    prune_excess_plans(plans, None);
}

fn prune_expired_plans(plans: &mut HashMap<String, CachedExecutionPlan>) {
    let cutoff = chrono::Utc::now().timestamp_millis() - MAX_CACHED_EXECUTION_PLAN_AGE_MS;
    plans.retain(|_, cached| cached.plan.created_at >= cutoff);
}

fn prune_excess_plans(
    plans: &mut HashMap<String, CachedExecutionPlan>,
    protected_plan_id: Option<&str>,
) {
    while plans.len() > MAX_CACHED_EXECUTION_PLANS {
        let Some(oldest_id) = plans
            .iter()
            .filter(|(plan_id, _)| protected_plan_id != Some(plan_id.as_str()))
            .min_by(|left, right| {
                left.1
                    .plan
                    .created_at
                    .cmp(&right.1.plan.created_at)
                    .then_with(|| left.0.cmp(right.0))
            })
            .map(|(plan_id, _)| plan_id.clone())
        else {
            break;
        };
        plans.remove(&oldest_id);
    }
}

fn load_namespace_policies(db: &RuntimeDb, resolver: &PolicyResolver) {
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
            match context_admission_policy_from_properties(&obj.properties) {
                Ok(Some(policy)) => {
                    let _ = resolver.set_context_admission_policy(&namespace, policy);
                }
                Ok(None) => resolver.clear_context_admission_policy(&namespace),
                Err(error) => resolver.set_context_admission_error(&namespace, error),
            }
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

fn context_admission_policy_from_properties(
    properties: &std::collections::HashMap<String, String>,
) -> Result<Option<crate::chisei::policy::ContextAdmissionPolicy>, String> {
    let Some(encoded) = properties
        .get("context_admission_policy_json")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if encoded == "null" {
        return Ok(None);
    }
    let policy = serde_json::from_str::<crate::chisei::policy::ContextAdmissionPolicy>(encoded)
        .map_err(|error| format!("invalid context admission policy: {error}"))?;
    policy.validate()?;
    Ok(Some(policy))
}

fn policy_properties(
    policy: &Policy,
    context_admission_policy: Option<&crate::chisei::policy::ContextAdmissionPolicy>,
) -> std::collections::HashMap<String, String> {
    let mut properties = std::collections::HashMap::from([
        ("allowed_runtimes".into(), policy.allowed_runtimes.join(",")),
        ("allowed_models".into(), policy.allowed_models.join(",")),
        ("default_runtime".into(), policy.default_runtime.clone()),
        ("default_model".into(), policy.default_model.clone()),
        ("data_class".into(), policy.data_class.clone()),
    ]);
    if let Some(context_admission_policy) = context_admission_policy {
        properties.insert(
            "context_admission_policy_json".into(),
            serde_json::to_string(context_admission_policy).unwrap_or_default(),
        );
    }
    properties
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
        let provider = crate::provider_resolution::resolve_model(&policy.default_model)?.provider;
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
                crate::provider_resolution::resolve_model(model)?;
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
    let provider = crate::provider_resolution::provider_id(model)?;
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
    crate::provider_resolution::models_have_same_identity(left, right)
}

fn validate_explicit_requested_model(model: &str) -> Result<(), String> {
    if model.is_empty() || model == "auto" {
        return Ok(());
    }
    let Some((namespace, _)) = model.split_once('/') else {
        return crate::provider_resolution::resolve_model(model).map(|_| ());
    };
    match crate::provider_resolution::resolve_model(model) {
        Ok(_) => Ok(()),
        Err(error)
            if crate::provider_profile::provider_registry_snapshot()
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
    let prepared_spec = if enriched_spec.is_empty() {
        input.spec.as_str()
    } else {
        enriched_spec
    };
    if prepared_spec.is_empty() {
        return messages;
    }
    if messages.is_empty() {
        return vec![ChatMessage {
            role: "user".into(),
            content: prepared_spec.into(),
            tool_call_id: String::new(),
            tool_calls: vec![],
        }];
    }
    let task_message = ChatMessage {
        role: "user".into(),
        content: format!("[Task spec]\n{prepared_spec}"),
        tool_call_id: String::new(),
        tool_calls: vec![],
    };
    // A pending assistant tool call must remain adjacent to its tool result.
    // Such a history is not cacheable across the current governed task spec.
    if messages
        .last()
        .is_some_and(|message| !message.tool_calls.is_empty())
    {
        messages.insert(0, task_message);
    } else {
        messages.push(task_message);
    }
    messages
}

fn native_cacheable_message_count(input: &ExecutionInput, prepared: &[ChatMessage]) -> usize {
    let has_dynamic_spec = !input.spec.is_empty() || prepared.len() > input.messages.len();
    if has_dynamic_spec
        && prepared
            .first()
            .is_some_and(|message| message.content.starts_with("[Task spec]\n"))
    {
        0
    } else if has_dynamic_spec {
        input.messages.len().min(prepared.len())
    } else {
        prepared.len().saturating_sub(1)
    }
}

fn subject_reference_from_proto(
    value: GovernedSubjectReference,
) -> subject::GovernedSubjectReference {
    subject::GovernedSubjectReference {
        kind: value.kind,
        reference: value.reference,
        content_digest: value.content_digest,
        observed_at_ms: value.observed_at_ms,
    }
}

fn governed_subject_result_from_receipt(
    receipt: &OperationReceipt,
) -> Result<GovernedSubjectResult, Status> {
    let intent = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .ok_or_else(|| Status::internal("governed-subject receipt has no intent"))?;
    let outcome = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        .ok_or_else(|| Status::internal("governed-subject receipt has no outcome"))?;
    let references = intent
        .references
        .iter()
        .map(|reference| {
            let observed_at_ms = intent
                .attributes
                .get(&format!("reference_observed_at_ms.{}", reference.kind))
                .ok_or_else(|| Status::internal("governed-subject receipt lost evidence time"))?
                .parse()
                .map_err(|_| {
                    Status::internal("governed-subject receipt has invalid evidence time")
                })?;
            Ok(GovernedSubjectReference {
                kind: reference.kind.clone(),
                reference: reference.reference.clone(),
                content_digest: reference.content_hash.clone().unwrap_or_default(),
                observed_at_ms,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let receipt_bytes =
        serde_json::to_vec(receipt).map_err(|error| Status::internal(error.to_string()))?;
    Ok(GovernedSubjectResult {
        version: subject::RESULT_VERSION.into(),
        decision: outcome
            .attributes
            .get("decision")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        operation_id: receipt.operation_id.clone(),
        receipt_schema: receipt.schema_version.clone(),
        receipt_digest: format!("sha256:{:x}", sha2::Sha256::digest(receipt_bytes)),
        references,
        fresh: outcome
            .attributes
            .get("fresh")
            .is_some_and(|value| value == "true"),
        failure_code: outcome
            .attributes
            .get("failure_code")
            .cloned()
            .unwrap_or_default(),
        failure_message: outcome
            .attributes
            .get("failure_message")
            .cloned()
            .unwrap_or_default(),
    })
}

fn subject_provenance_envelope_to_proto(
    value: &subject_provenance::ProvenanceEnvelope,
) -> GovernedSubjectProvenanceEnvelope {
    GovernedSubjectProvenanceEnvelope {
        profile: value.profile.clone(),
        issuer: value.issuer.clone(),
        issuer_key_id: value.issuer_key_id.clone(),
        subject: value.subject.clone(),
        content_digest: value.content_digest.clone(),
        decision: value.decision.clone(),
        receipt_schema: value.receipt_schema.clone(),
        receipt_digest: value.receipt_digest.clone(),
        governed_references: value
            .governed_references
            .iter()
            .map(|reference| GovernedSubjectProvenanceReference {
                kind: reference.kind.clone(),
                id: reference.id.clone(),
                digest: reference.digest.clone(),
            })
            .collect(),
        observed_at_unix_ms: value.observed_at_unix_ms,
        expires_at_unix_ms: value.expires_at_unix_ms,
        signature: value.signature.clone(),
    }
}

fn subject_provenance_response(
    record: &subject_provenance::ExportRecord,
    replayed: bool,
    now_ms: i64,
) -> Result<ExportGovernedSubjectProvenanceResponse, Status> {
    record
        .envelope
        .validate(now_ms)
        .map_err(Status::failed_precondition)?;
    Ok(ExportGovernedSubjectProvenanceResponse {
        envelope: Some(subject_provenance_envelope_to_proto(&record.envelope)),
        envelope_digest: record.envelope.digest().map_err(Status::data_loss)?,
        replayed,
        trust_root: Some(GovernedSubjectProvenanceTrustRoot {
            version: subject_provenance::TRUST_ROOT_VERSION,
            key_id: record.envelope.issuer_key_id.clone(),
            identity: subject_provenance::ISSUER.into(),
            public_key: record.public_key.clone(),
        }),
    })
}

fn load_subject_provenance_record(
    db: &RuntimeDb,
    actor: &str,
    export_id: &str,
) -> Result<Option<subject_provenance::ExportRecord>, Status> {
    db.get_governed_subject_provenance_export(actor, export_id)
        .map_err(Status::internal)
}

fn reconcile_subject_provenance_receipt(
    receipt: &OperationReceipt,
    binding: &subject_provenance::ExportRequestBinding,
    now_ms: i64,
) -> Result<(String, String), Status> {
    if receipt.operation_id != binding.operation_id
        || receipt.operation_class != "governed_subject_evaluation"
        || receipt.schema_version != subject::RECEIPT_SCHEMA_VERSION
        || receipt.completed_at_ms.is_none()
    {
        return Err(Status::failed_precondition(
            "operation is not a complete governed-subject receipt",
        ));
    }
    let result = governed_subject_result_from_receipt(receipt).map_err(|_| {
        Status::data_loss("governed-subject receipt is incomplete or internally inconsistent")
    })?;
    if result.decision != "allow" || !result.fresh {
        return Err(Status::failed_precondition(
            "governed-subject receipt is not an authoritative allow",
        ));
    }
    let receipt_bytes = serde_json::to_vec(receipt)
        .map_err(|_| Status::data_loss("governed-subject receipt cannot be reconciled"))?;
    let receipt_digest = format!("sha256:{:x}", sha2::Sha256::digest(receipt_bytes));
    if receipt_digest != binding.expected_receipt_digest {
        return Err(Status::failed_precondition(
            "governed-subject receipt digest does not match the requested export",
        ));
    }
    let intent = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .ok_or_else(|| Status::data_loss("governed-subject receipt intent is missing"))?;
    if intent.attributes.get("subject_identity") != Some(&binding.expected_subject_identity)
        || intent.attributes.get("content_digest") != Some(&binding.expected_subject_content_digest)
        || intent.attributes.get("subject_profile").map(String::as_str)
            != Some(subject::SOFTWARE_RELEASE_PROFILE)
    {
        return Err(Status::failed_precondition(
            "governed-subject identity does not match the requested software release",
        ));
    }
    let reference = |kind: &str| {
        intent
            .references
            .iter()
            .find(|reference| reference.kind == kind)
            .ok_or_else(|| {
                Status::data_loss("governed-subject receipt lacks required release evidence")
            })
    };
    let manifest = reference("manifest")?;
    let artifact = reference("artifact")?;
    if manifest.content_hash.as_deref() != Some(&binding.expected_manifest_digest)
        || artifact.content_hash.as_deref() != Some(&binding.expected_artifact_digest)
    {
        return Err(Status::failed_precondition(
            "governed-subject release evidence does not match the requested export",
        ));
    }
    for governed_reference in &result.references {
        if governed_reference.observed_at_ms <= 0
            || governed_reference.observed_at_ms > now_ms
            || now_ms - governed_reference.observed_at_ms > subject::MAX_EVIDENCE_AGE_MS
        {
            return Err(Status::failed_precondition(
                "governed-subject release evidence is stale",
            ));
        }
    }
    let content_digest = subject_provenance::release_content_digest(
        &binding.expected_manifest_digest,
        &binding.expected_artifact_digest,
    )
    .map_err(Status::invalid_argument)?;
    Ok((receipt.namespace.clone(), content_digest))
}

impl ChiseiServiceImpl {
    async fn resolve_policy(
        &self,
        req: Request<ResolvePolicyRequest>,
    ) -> Result<Response<ResolvePolicyResponse>, Status> {
        let requested_namespace = if req.get_ref().namespace.trim().is_empty() {
            req.get_ref().project.trim()
        } else {
            req.get_ref().namespace.trim()
        };
        require_team_namespace_access(&self.db, &self.config, &req, requested_namespace)?;
        let registry = self.refresh_provider_registry_for_resolution().await?;
        crate::provider_profile::with_provider_registry_snapshot(registry, async {
        let r = req.into_inner();
        let capability_requirements = if r.capability_requirements_json.is_empty() {
            None
        } else {
            Some(
                serde_json::from_slice::<crate::provider_profile::CapabilityRequirements>(
                    &r.capability_requirements_json,
                )
                .map_err(|error| {
                    Status::invalid_argument(format!(
                        "invalid capability requirements: {error}"
                    ))
                })?,
            )
        };
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
        let route_override = r.route_override.trim();
        if !route_override.is_empty() {
            validate_explicit_requested_model(route_override).map_err(Status::invalid_argument)?;
            if !route_override_allowed(effective_policy.as_ref(), route_override) {
                return Err(Status::invalid_argument(format!(
                    "route override {route_override:?} is not allowed by effective policy"
                )));
            }
        }
        let requested_preferred_model = &r.preferred_model;
        let preferred_model = if !route_override.is_empty() {
            route_override
        } else { eval_regressed
            .then_some(())
            .as_ref()
            .and(effective_policy.as_ref())
            .map(|policy| policy.default_model.as_str())
            .filter(|model| !model.is_empty())
            .unwrap_or(requested_preferred_model) };
        validate_explicit_requested_model(preferred_model).map_err(Status::invalid_argument)?;
        let override_runtime = (!route_override.is_empty())
            .then(|| crate::provider_resolution::resolve_model(route_override))
            .transpose()
            .map_err(Status::invalid_argument)?
            .map(|model| model.provider);
        let preferred_runtime = override_runtime.as_deref().unwrap_or(&r.preferred_runtime);
        let (mut runtime, model) = if let Some(policy) = effective_policy.as_ref() {
            self.policy
                .apply_policy(policy, preferred_runtime, preferred_model)
                .map_err(Status::invalid_argument)?
        } else {
            self.policy
                .resolve(&policy_scope, preferred_runtime, preferred_model)
                .map_err(Status::invalid_argument)?
        };

        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&r.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        // Resolve the capable-tier model first; this is the baseline the request
        // would get with no cost tiering.
        let capable_model = if r.preferred_model == "auto"
            && effective_policy.is_none()
            && capability_requirements.is_none()
        {
            let resolved = crate::provider_resolution::resolve_model(&model)
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
            self.resolve_live_model_with_override(
                &model,
                effective_policy.as_ref(),
                None,
                safe_only,
                &safe_providers,
                capability_requirements.as_ref(),
                !route_override.is_empty(),
            )
            .await
            .map_err(|err| {
                if err.starts_with("capability_unsupported:") {
                    Status::failed_precondition(err)
                } else if safe_only {
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
        if !route_override.is_empty() && wants_local_free {
            return Err(Status::resource_exhausted(
                "hard budget cap reached; a route override cannot fall back to local-free routing",
            ));
        }
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
                capability_requirements.as_ref(),
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
        let wants_cheap = route_override.is_empty() && !capable_override_active
            && cheap_route_bias(&r.task_class, eval_regressed) == Some("cheap");
        let cheap_model = if wants_cheap && is_known_provider_runtime(&runtime) {
            self.resolve_live_model(
                &format!("{}/cheap", runtime.trim()),
                effective_policy.as_ref(),
                Some("cheap"),
                safe_only,
                &safe_providers,
                capability_requirements.as_ref(),
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
        if route_override.is_empty() && !wants_local_free && let Some((portfolio_scope, objective)) = objective {
            let now = chrono::Utc::now().timestamp_millis();
            if eval_regressed || capable_override_active {
                if let Ok(selection) = self.portfolio.damped_route(
                    &portfolio_scope,
                    &normalized_task_class,
                    &capable_model,
                    crate::chisei::portfolio::LEGACY_PROMPT_VARIANT,
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
                            capability_requirements.as_ref(),
                        )
                        .await
                    && proposed == allocation.model
                    && let Ok(selection) = self.portfolio.damped_route(
                        &portfolio_scope,
                        &normalized_task_class,
                        &proposed,
                        &allocation.prompt_variant,
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
                            capability_requirements.as_ref(),
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
        let fallback_models = if route_override.is_empty() {
            effective_policy
                .as_ref()
                .into_iter()
                .flat_map(|policy| policy.allowed_models.iter())
                .filter_map(|candidate| {
                    crate::provider_resolution::resolve_model(candidate)
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
                .collect()
        } else {
            Vec::new()
        };

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
}

#[tonic::async_trait]
impl ChiseiService for ChiseiServiceImpl {
    type ExecutePlanStreamStream =
        Pin<Box<dyn futures_util::Stream<Item = Result<ExecutePlanStreamEvent, Status>> + Send>>;

    async fn evaluate_governed_subject(
        &self,
        req: Request<EvaluateGovernedSubjectRequest>,
    ) -> Result<Response<EvaluateGovernedSubjectResponse>, Status> {
        let actor = required_authenticated_actor(&req)?;
        let value = req
            .into_inner()
            .subject
            .ok_or_else(|| Status::invalid_argument("subject required"))?;
        let envelope = subject::GovernedSubjectEnvelope {
            version: value.version,
            namespace: value.namespace,
            request_id: value.request_id,
            subject_profile: value.subject_profile,
            subject_identity: value.subject_identity,
            content_digest: value.content_digest,
            references: value
                .references
                .into_iter()
                .map(subject_reference_from_proto)
                .collect(),
            evaluation_profile: value.evaluation_profile,
        };
        require_namespace_write_access(&self.db, &actor, &envelope.namespace)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let fresh = subject::validate_envelope(&envelope, &actor, now_ms)
            .map_err(Status::invalid_argument)?;
        if !matches!(actor.as_str(), "root" | "local") {
            return Err(Status::permission_denied(
                "governed-subject conformance evaluation requires control-plane administration",
            ));
        }
        let binding_digest = subject::binding_digest(&envelope, &actor);
        let operation_id = subject::operation_id(&envelope.namespace, &actor, &envelope.request_id);
        if let Some(existing) = self
            .db
            .get_operation_receipt(&operation_id)
            .map_err(Status::internal)?
        {
            let existing_binding = existing
                .events
                .iter()
                .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
                .and_then(|event| event.attributes.get("binding_digest"));
            if existing_binding != Some(&binding_digest) {
                return Err(Status::already_exists(
                    "request_id is already bound to different governed-subject evidence",
                ));
            }
            return Ok(Response::new(EvaluateGovernedSubjectResponse {
                result: Some(governed_subject_result_from_receipt(&existing)?),
            }));
        }

        let (decision, failure_code) = subject::evaluation(&envelope.evaluation_profile, fresh);
        let governed_references = envelope
            .references
            .iter()
            .map(|reference| GovernedReference {
                kind: reference.kind.clone(),
                reference: reference.reference.clone(),
                content_hash: Some(reference.content_digest.clone()),
                disclosed_fields: Vec::new(),
                omitted: true,
                omission_reason: Some("subject payload remains externally owned".into()),
            })
            .collect::<Vec<_>>();
        let event = |suffix: &str,
                     parent: Option<&str>,
                     kind: ReceiptEventKind,
                     attributes: BTreeMap<String, String>,
                     references: Vec<GovernedReference>| {
            OperationReceiptEvent {
                event_id: format!("{operation_id}:{suffix}"),
                operation_id: operation_id.clone(),
                parent_event_id: parent.map(|value| format!("{operation_id}:{value}")),
                timestamp_ms: now_ms,
                kind,
                surface: kind.surface(),
                actor: actor.clone(),
                references,
                attributes,
            }
        };
        let mut intent_attributes = BTreeMap::from([
            ("request_id".into(), operation_id.clone()),
            ("lookup_request_id".into(), envelope.request_id.clone()),
            (
                "caller_scope".into(),
                subject::caller_scope(&envelope.namespace, &actor),
            ),
            ("binding_digest".into(), binding_digest),
            ("subject_profile".into(), envelope.subject_profile.clone()),
            ("subject_identity".into(), envelope.subject_identity.clone()),
            ("content_digest".into(), envelope.content_digest.clone()),
            (
                "evaluation_profile".into(),
                envelope.evaluation_profile.clone(),
            ),
        ]);
        intent_attributes.insert(
            "reference_count".into(),
            envelope.references.len().to_string(),
        );
        for reference in &envelope.references {
            intent_attributes.insert(
                format!("reference_observed_at_ms.{}", reference.kind),
                reference.observed_at_ms.to_string(),
            );
        }
        let policy_attributes = BTreeMap::from([
            ("decision".into(), decision.into()),
            (
                "profile_registry".into(),
                "chisei.governed-subject-registry/v1".into(),
            ),
        ]);
        let mut outcome_attributes = BTreeMap::from([
            ("decision".into(), decision.into()),
            ("fresh".into(), fresh.to_string()),
        ]);
        if let Some(code) = failure_code {
            outcome_attributes.insert("failure_code".into(), code.into());
            outcome_attributes.insert(
                "failure_message".into(),
                match code {
                    "stale_evidence" => "governed evidence is stale",
                    "evaluation_unavailable" => "governed evaluation is unavailable",
                    "evaluation_timeout" => "governed evaluation timed out",
                    _ => "governed evaluation failed",
                }
                .into(),
            );
        }
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.clone(),
            parent_operation_id: None,
            namespace: envelope.namespace.clone(),
            operation_class: "governed_subject_evaluation".into(),
            initiating_actor: actor.clone(),
            schema_version: subject::RECEIPT_SCHEMA_VERSION.into(),
            policy_version: envelope.evaluation_profile.clone(),
            started_at_ms: now_ms,
            completed_at_ms: Some(now_ms),
            events: vec![
                event(
                    "intent",
                    None,
                    ReceiptEventKind::IntentRecorded,
                    intent_attributes,
                    governed_references,
                ),
                event(
                    "policy",
                    Some("intent"),
                    ReceiptEventKind::PolicyDecided,
                    policy_attributes,
                    Vec::new(),
                ),
                event(
                    "route",
                    Some("policy"),
                    ReceiptEventKind::RouteSelected,
                    BTreeMap::from([("route".into(), "registered_profile".into())]),
                    Vec::new(),
                ),
                event(
                    "budget",
                    Some("route"),
                    ReceiptEventKind::BudgetDecided,
                    BTreeMap::from([("budget_effect".into(), "none".into())]),
                    Vec::new(),
                ),
                event(
                    "outcome",
                    Some("budget"),
                    ReceiptEventKind::OutcomeRecorded,
                    outcome_attributes,
                    Vec::new(),
                ),
            ],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
        };
        if let Err(error) = self.db.insert_operation_receipt(&receipt) {
            if let Some(existing) = self
                .db
                .get_operation_receipt(&operation_id)
                .map_err(Status::internal)?
            {
                let same_binding = existing
                    .events
                    .iter()
                    .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
                    .and_then(|event| event.attributes.get("binding_digest"))
                    == receipt.events[0].attributes.get("binding_digest");
                if same_binding {
                    return Ok(Response::new(EvaluateGovernedSubjectResponse {
                        result: Some(governed_subject_result_from_receipt(&existing)?),
                    }));
                }
                return Err(Status::already_exists(
                    "request_id is already bound to different governed-subject evidence",
                ));
            }
            return Err(Status::aborted(format!(
                "governed-subject receipt could not be committed: {error}"
            )));
        }
        Ok(Response::new(EvaluateGovernedSubjectResponse {
            result: Some(governed_subject_result_from_receipt(&receipt)?),
        }))
    }

    async fn export_governed_subject_provenance(
        &self,
        req: Request<ExportGovernedSubjectProvenanceRequest>,
    ) -> Result<Response<ExportGovernedSubjectProvenanceResponse>, Status> {
        let actor = required_authenticated_actor(&req)?;
        let request = req.into_inner();
        let binding = subject_provenance::ExportRequestBinding {
            actor: actor.clone(),
            export_id: request.export_id,
            operation_id: request.operation_id,
            expected_subject_identity: request.expected_subject_identity,
            expected_subject_content_digest: request.expected_subject_content_digest,
            expected_manifest_digest: request.expected_manifest_digest,
            expected_artifact_digest: request.expected_artifact_digest,
            expected_receipt_digest: request.expected_receipt_digest,
        };
        let binding_digest =
            subject_provenance::binding_digest(&binding).map_err(Status::invalid_argument)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        if let Some(existing) =
            load_subject_provenance_record(&self.db, &binding.actor, &binding.export_id)?
        {
            if existing.binding_digest != binding_digest {
                return Err(Status::already_exists(
                    "export_id is already bound to different governed-subject evidence",
                ));
            }
            require_namespace_access(&self.db, &actor, &existing.namespace)?;
            return Ok(Response::new(subject_provenance_response(
                &existing, true, now_ms,
            )?));
        }

        let receipt = self
            .db
            .get_operation_receipt(&binding.operation_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("governed-subject receipt not found"))?;
        require_namespace_write_access(&self.db, &actor, &receipt.namespace)?;
        let (namespace, content_digest) =
            reconcile_subject_provenance_receipt(&receipt, &binding, now_ms)?;
        let key_hex = self
            .config
            .governed_subject_provenance_signing_key
            .as_deref()
            .ok_or_else(|| {
                Status::failed_precondition("governed-subject provenance signing is not configured")
            })?;
        let signing_key = subject_provenance::signing_key_from_hex(key_hex)
            .map_err(Status::failed_precondition)?;
        if now_ms < self.config.governed_subject_provenance_key_not_before_ms
            || now_ms >= self.config.governed_subject_provenance_key_expires_at_ms
        {
            return Err(Status::failed_precondition(
                "governed-subject provenance signing key is not active",
            ));
        }
        let ttl_ms = self.config.governed_subject_provenance_ttl_ms;
        if ttl_ms <= 0 || ttl_ms > subject_provenance::MAX_ENVELOPE_TTL_MS {
            return Err(Status::failed_precondition(
                "governed-subject provenance TTL is invalid",
            ));
        }
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .unwrap_or(i64::MAX)
            .min(self.config.governed_subject_provenance_key_expires_at_ms);
        if expires_at_ms <= now_ms {
            return Err(Status::failed_precondition(
                "governed-subject provenance signing key expires too soon",
            ));
        }
        let envelope = subject_provenance::ProvenanceEnvelope::issue(
            &signing_key,
            binding.expected_subject_identity.clone(),
            content_digest,
            binding.expected_receipt_digest.clone(),
            binding.operation_id.clone(),
            now_ms,
            expires_at_ms,
        )
        .map_err(Status::internal)?;
        envelope
            .verify(&signing_key.verifying_key().to_bytes(), now_ms)
            .map_err(Status::internal)?;
        let record = subject_provenance::ExportRecord {
            binding_digest,
            namespace,
            envelope,
            public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes()),
            created_at_ms: now_ms,
        };
        let (stored, inserted) = self
            .db
            .put_governed_subject_provenance_export(
                &binding.actor,
                &binding.export_id,
                &record,
            )
            .map_err(|error| {
                if error.contains("already bound") {
                    Status::already_exists(
                        "export_id is already bound to different governed-subject evidence",
                    )
                } else {
                    tracing::warn!(error = %error, "governed-subject provenance export persistence failed");
                    Status::aborted(
                        "governed-subject provenance export could not be committed",
                    )
                }
            })?;
        Ok(Response::new(subject_provenance_response(
            &stored, !inserted, now_ms,
        )?))
    }

    async fn authorize_external_action(
        &self,
        req: Request<AuthorizeExternalActionRequest>,
    ) -> Result<Response<AuthorizeExternalActionResponse>, Status> {
        let actor = required_authenticated_actor(&req)?;
        let input = req.into_inner();
        let offline = input.offline;
        let request = input
            .request
            .ok_or_else(|| Status::invalid_argument("request required"))?;
        let request = external_request_from_proto(request);
        request.validate().map_err(Status::invalid_argument)?;
        if request.actor != actor {
            return Err(Status::permission_denied(
                "external-action actor must match authenticated principal",
            ));
        }
        require_namespace_write_access(&self.db, &actor, &request.namespace)?;
        require_external_project_access(
            &self.db,
            &actor,
            &request.namespace,
            &request.policy_project,
        )?;
        let now = chrono::Utc::now().timestamp_millis();
        reclaim_expired_external_action_reservations(&self.db, &self.budget, now)?;
        let request_digest = request
            .canonical_digest()
            .map_err(Status::invalid_argument)?;
        let mut authorization_id = format!("external-auth-{}", uuid::Uuid::new_v4().simple());
        match self
            .db
            .claim_external_action_authorization(&request, &request_digest, &authorization_id, now)
            .map_err(Status::internal)?
        {
            external::AuthorizationClaim::Claimed(claimed_id) => {
                authorization_id = claimed_id;
            }
            external::AuthorizationClaim::Existing(existing) => {
                ensure_external_action_audit(&self.db, &existing)?;
                let permit = (existing.decision.decision == "permit")
                    .then(|| {
                        issue_external_permit(
                            self,
                            &existing,
                            &actor,
                            &existing.request.idempotency_key,
                            offline,
                        )
                    })
                    .transpose()?
                    .map(|permit| external_permit_to_proto(&permit));
                return Ok(Response::new(AuthorizeExternalActionResponse {
                    decision: Some(external_decision_to_proto(&existing.decision)),
                    permit,
                }));
            }
            external::AuthorizationClaim::Conflict => {
                return Err(Status::already_exists(
                    "idempotency key was reused with a different canonical request digest",
                ));
            }
            external::AuthorizationClaim::InProgress => {
                return Err(Status::unavailable(
                    "external-action authorization decision is in progress",
                ));
            }
        }

        let risk = RiskClass::parse(
            request
                .authoritative_risk_class()
                .map_err(Status::invalid_argument)?,
        )
        .ok_or_else(|| Status::invalid_argument("invalid risk_class"))?;
        let policy =
            match self
                .db
                .resolve_action_policy(&actor, &request.namespace, &request.policy_project)
            {
                Ok(policy) => policy,
                Err(error) => {
                    let _ = self
                        .db
                        .abandon_external_action_claim(&request, &request_digest);
                    return Err(Status::internal(error));
                }
            };
        let policy_scope = policy
            .as_ref()
            .map(|policy| policy.scope.clone())
            .unwrap_or_default();
        let policy_version = external_policy_version(policy.as_ref());
        let external_action_name = format!("external_action/{}", request.action_type);
        let mut policy_decision = policy
            .as_ref()
            .map(|policy| policy.decide(&external_action_name, risk))
            .unwrap_or(ActionDecision::Allow);
        let mut reason = "external action satisfies current policy".to_string();

        if request.deadline_ms <= now {
            policy_decision = ActionDecision::Deny;
            reason = "external-action request expired".into();
        }
        let approval_id = if policy_decision == ActionDecision::RequireApproval {
            format!("external-approval-{}", uuid::Uuid::new_v4().simple())
        } else {
            String::new()
        };
        let mut record = external::AuthorizationRecord {
            request: request.clone(),
            decision: external::ExternalActionDecision {
                version: external::DECISION_VERSION.into(),
                authorization_id: authorization_id.clone(),
                request_digest: request_digest.clone(),
                decision: String::new(),
                reason,
                approval_id,
                policy_scope,
                policy_version,
                created_at_ms: now,
                expires_at_ms: request.deadline_ms,
                cancelled_at_ms: 0,
                assurance: external::AssuranceDeclaration::default(),
            },
            approval_status: if policy_decision == ActionDecision::RequireApproval {
                "pending".into()
            } else {
                String::new()
            },
            budget_reserved: false,
            blast_radius_reserved: false,
            decision_actor: actor.clone(),
            decision_updated_at_ms: now,
        };
        if policy_decision != ActionDecision::Deny {
            let max_mutations = policy
                .as_ref()
                .and_then(|policy| policy.max_mutations_per_work_unit);
            let max_deletes = (risk == RiskClass::Destructive)
                .then(|| {
                    policy
                        .as_ref()
                        .and_then(|policy| policy.max_deletes_per_work_unit)
                })
                .flatten();
            if max_mutations.is_some() || max_deletes.is_some() {
                match self.db.reserve_external_action_blast_radius(
                    &authorization_id,
                    &request,
                    max_mutations,
                    max_deletes,
                ) {
                    Ok(()) => record.blast_radius_reserved = true,
                    Err(_) => {
                        policy_decision = ActionDecision::Deny;
                        record.decision.reason =
                            "external-action cumulative blast-radius cap exceeded".into();
                    }
                }
            }
        }
        if policy_decision != ActionDecision::Deny {
            let requested_units =
                i32::try_from(request.requested_invocation_count).unwrap_or(i32::MAX);
            if self
                .budget
                .check_and_reserve_idempotent(
                    &external_budget_scope(&request),
                    requested_units,
                    &format!("external-action-reserve:{authorization_id}"),
                )
                .is_ok()
            {
                record.budget_reserved = true;
            } else {
                policy_decision = ActionDecision::Deny;
                record.decision.reason = "external-action budget exhausted".into();
                release_external_reservations(&self.db, &self.budget, &mut record)?;
            }
        }
        record.decision.decision = match policy_decision {
            ActionDecision::Allow => "permit",
            ActionDecision::Deny => "deny",
            ActionDecision::RequireApproval => "require_approval",
        }
        .into();
        if policy_decision == ActionDecision::Deny {
            record.decision.approval_id.clear();
            record.approval_status.clear();
        }
        if let Err(error) = self.db.put_external_action_authorization(&record) {
            let _ = self
                .db
                .abandon_external_action_claim(&request, &request_digest);
            release_external_reservations(&self.db, &self.budget, &mut record)?;
            return Err(Status::internal(error));
        }
        ensure_external_action_audit(&self.db, &record)?;
        let permit = (record.decision.decision == "permit")
            .then(|| {
                issue_external_permit(
                    self,
                    &record,
                    &actor,
                    &record.request.idempotency_key,
                    offline,
                )
            })
            .transpose()?
            .map(|permit| external_permit_to_proto(&permit));
        Ok(Response::new(AuthorizeExternalActionResponse {
            decision: Some(external_decision_to_proto(&record.decision)),
            permit,
        }))
    }

    async fn transition_external_action(
        &self,
        req: Request<TransitionExternalActionRequest>,
    ) -> Result<Response<TransitionExternalActionResponse>, Status> {
        let actor = required_authenticated_actor(&req)?;
        let input = req.into_inner();
        match input.transition.as_str() {
            "approve" | "deny" => {
                if !matches!(actor.as_str(), "root" | "local") {
                    return Err(Status::permission_denied(
                        "external-action approval requires control-plane administration",
                    ));
                }
                let mut record = self
                    .db
                    .get_external_action_authorization_by_id(&input.authorization_id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::not_found("external-action authorization not found"))?;
                if record.approval_status != "pending"
                    || record.decision.decision != "require_approval"
                {
                    return Err(Status::failed_precondition(
                        "external-action approval is not pending",
                    ));
                }
                let expected = record.clone();
                let now = chrono::Utc::now().timestamp_millis();
                let current_policy = self
                    .db
                    .resolve_action_policy(
                        &record.request.actor,
                        &record.request.namespace,
                        &record.request.policy_project,
                    )
                    .map_err(Status::internal)?;
                let access_revoked = require_namespace_write_access(
                    &self.db,
                    &record.request.actor,
                    &record.request.namespace,
                )
                .and_then(|_| {
                    require_external_project_access(
                        &self.db,
                        &record.request.actor,
                        &record.request.namespace,
                        &record.request.policy_project,
                    )
                })
                .is_err();
                if access_revoked {
                    record.decision.decision = "deny".into();
                    record.decision.reason =
                        "external-action requester no longer has namespace access".into();
                    record.approval_status = "revoked".into();
                } else if now >= record.decision.expires_at_ms {
                    record.decision.decision = "deny".into();
                    record.decision.reason = "external-action approval expired".into();
                    record.approval_status = "expired".into();
                } else if external_policy_version(current_policy.as_ref())
                    != record.decision.policy_version
                {
                    record.decision.decision = "deny".into();
                    record.decision.reason =
                        "external-action approval is stale after policy change".into();
                    record.approval_status = "stale".into();
                } else if input.transition == "approve" {
                    record.decision.decision = "permit".into();
                    record.decision.reason = "external action approved".into();
                    record.approval_status = "approved".into();
                } else {
                    record.decision.decision = "deny".into();
                    record.decision.reason = if input.reason.trim().is_empty() {
                        "external action denied by approver".into()
                    } else {
                        input.reason.clone()
                    };
                    record.approval_status = "denied".into();
                }
                record.decision_actor = actor.clone();
                record.decision_updated_at_ms = now;
                if !self
                    .db
                    .compare_and_swap_external_action_authorization(&expected, &record)
                    .map_err(Status::internal)?
                {
                    return Err(Status::aborted(
                        "external-action authorization changed concurrently",
                    ));
                }
                if record.decision.decision != "permit" {
                    let reserved = record.clone();
                    release_external_reservations(&self.db, &self.budget, &mut record)?;
                    persist_released_external_flags(&self.db, &reserved, &record)?;
                }
                ensure_external_action_audit(&self.db, &record)?;
                let permit = (record.decision.decision == "permit")
                    .then(|| {
                        issue_external_permit(
                            self,
                            &record,
                            &record.request.actor,
                            &record.request.idempotency_key,
                            input.offline,
                        )
                    })
                    .transpose()?
                    .map(|permit| external_permit_to_proto(&permit));
                Ok(Response::new(TransitionExternalActionResponse {
                    decision: Some(external_decision_to_proto(&record.decision)),
                    permit,
                    changed: true,
                }))
            }
            "cancel" => {
                let mut record = self
                    .db
                    .get_external_action_authorization_by_id(&input.authorization_id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::not_found("external-action authorization not found"))?;
                if actor != record.request.actor && !matches!(actor.as_str(), "root" | "local") {
                    return Err(Status::permission_denied(
                        "external-action cancellation denied",
                    ));
                }
                let changed = record.decision.cancelled_at_ms == 0;
                if changed {
                    let expected = record.clone();
                    let now = chrono::Utc::now().timestamp_millis();
                    record.decision.cancelled_at_ms = now;
                    record.decision.decision = "deny".into();
                    record.decision.reason = if input.reason.trim().is_empty() {
                        "external-action authorization cancelled".into()
                    } else {
                        input.reason
                    };
                    record.approval_status = "cancelled".into();
                    record.decision_actor = actor;
                    record.decision_updated_at_ms = now;
                    if !self
                        .db
                        .compare_and_swap_external_action_authorization(&expected, &record)
                        .map_err(Status::internal)?
                    {
                        return Err(Status::aborted(
                            "external-action authorization changed concurrently",
                        ));
                    }
                }
                let reserved = record.clone();
                release_external_reservations(&self.db, &self.budget, &mut record)?;
                persist_released_external_flags(&self.db, &reserved, &record)?;
                ensure_external_action_audit(&self.db, &record)?;
                Ok(Response::new(TransitionExternalActionResponse {
                    decision: Some(external_decision_to_proto(&record.decision)),
                    permit: None,
                    changed,
                }))
            }
            "revoke" => {
                if !matches!(actor.as_str(), "root" | "local") {
                    return Err(Status::permission_denied(
                        "permit revocation requires control-plane administration",
                    ));
                }
                if input.revocation_handle.trim().is_empty() || input.reason.trim().is_empty() {
                    return Err(Status::invalid_argument(
                        "revocation_handle and reason required",
                    ));
                }
                let now = chrono::Utc::now().timestamp_millis();
                let changed = self
                    .db
                    .revoke_permit(&input.revocation_handle, &input.reason, now)
                    .map_err(Status::internal)?;
                if changed {
                    self.db
                        .record_decisions_idempotently(&[crate::sekai::audit::Decision {
                            id: format!("{}:audit:revoked", input.revocation_handle),
                            timestamp: now,
                            actor,
                            action: "external_action_permit/revoke".into(),
                            reason: input.reason,
                            evidence: HashMap::from([(
                                "revocation_handle".into(),
                                input.revocation_handle.clone(),
                            )]),
                            target_id: input.revocation_handle,
                            outcome: "revoked".into(),
                        }])
                        .map_err(Status::internal)?;
                }
                Ok(Response::new(TransitionExternalActionResponse {
                    decision: None,
                    permit: None,
                    changed,
                }))
            }
            "delegate" => {
                let parent = external_permit_from_proto(
                    input
                        .parent
                        .ok_or_else(|| Status::invalid_argument("parent permit required"))?,
                );
                if actor != parent.subject_actor {
                    return Err(Status::permission_denied(
                        "delegation requires the current permit subject",
                    ));
                }
                require_namespace_write_access(&self.db, &actor, &parent.namespace)?;
                let key = permit_signing_key(&self.config)?;
                parent
                    .verify_trust(&self.config.permit_issuer, &self.config.permit_key_id)
                    .and_then(|_| parent.verify_signature(&key.verifying_key()))
                    .map_err(Status::failed_precondition)?;
                self.db
                    .validate_permit_for_delegation(&parent)
                    .and_then(|_| self.db.validate_delegation_chain(&parent))
                    .map_err(Status::failed_precondition)?;
                let policy = self
                    .db
                    .get_external_permit_policy(&parent.policy_scope)
                    .map_err(Status::internal)?;
                let child = permit::delegate(
                    &parent,
                    &policy,
                    &key,
                    permit::Delegation {
                        delegator: &actor,
                        subject_actor: &input.subject_actor,
                        permit_id: format!("permit-{}", uuid::Uuid::new_v4().simple()),
                        nonce: uuid::Uuid::new_v4().simple().to_string(),
                        now_ms: chrono::Utc::now().timestamp_millis(),
                        expires_at_ms: input.expires_at_ms,
                        target_selectors: input.target_selectors,
                        allowed_effects: input.allowed_effects,
                        budget_micros: input.budget_micros,
                        volume_limit: input.volume_limit,
                        blast_radius_limit: input.blast_radius_limit,
                        max_invocations: input.max_invocations,
                        risk_class: &input.risk_class,
                    },
                )
                .map_err(Status::failed_precondition)?;
                let child = self
                    .db
                    .put_delegated_permit(&child, &actor)
                    .map_err(Status::failed_precondition)?;
                Ok(Response::new(TransitionExternalActionResponse {
                    decision: None,
                    permit: Some(external_permit_to_proto(&child)),
                    changed: true,
                }))
            }
            _ => Err(Status::invalid_argument(
                "transition must be approve, deny, cancel, revoke, or delegate",
            )),
        }
    }

    async fn redeem_external_action_permit(
        &self,
        req: Request<RedeemExternalActionPermitRequest>,
    ) -> Result<Response<RedeemExternalActionPermitResponse>, Status> {
        let actor = required_authenticated_actor(&req)?;
        let input = req.into_inner();
        if input.idempotency_key.trim().is_empty() || input.execution_id.trim().is_empty() {
            return Err(Status::invalid_argument(
                "idempotency_key and execution_id required",
            ));
        }
        let value = external_permit_from_proto(
            input
                .permit
                .ok_or_else(|| Status::invalid_argument("permit required"))?,
        );
        if actor != value.executor && !matches!(actor.as_str(), "root" | "local") {
            return Err(Status::permission_denied(
                "permit redemption requires the bound executor",
            ));
        }
        if let Some(redemption) = self
            .db
            .replay_redemption(&value, &input.idempotency_key, &input.execution_id)
            .map_err(Status::failed_precondition)?
        {
            return Ok(Response::new(RedeemExternalActionPermitResponse {
                redemption: Some(ExternalActionRedemption {
                    version: redemption.version,
                    permit_id: redemption.permit_id,
                    redemption_id: redemption.redemption_id,
                    executor: redemption.executor,
                    redeemed_at_ms: redemption.redeemed_at_ms,
                    invocation_ordinal: redemption.invocation_ordinal,
                    evidence_due_at_ms: redemption.evidence_due_at_ms,
                    site_id: redemption.site_id,
                }),
            }));
        }
        let context = external_host_context(
            input.executor,
            input.requesting_harness,
            input.canonical_arguments_digest,
            input.target_selectors,
            input.observed_preconditions,
            input.host_capabilities,
        );
        let key = permit_signing_key(&self.config)?.verifying_key();
        value
            .verify_trust(&self.config.permit_issuer, &self.config.permit_key_id)
            .map_err(Status::failed_precondition)?;
        let redemption = self
            .db
            .redeem_or_reconcile_permit(
                &value,
                &context,
                &key,
                &input.idempotency_key,
                &input.execution_id,
                &self.config.site_id,
                crate::chisei::external_permit::RedemptionTiming {
                    invoked_at_ms: input.invoked_at_ms,
                    reconciled_at_ms: chrono::Utc::now().timestamp_millis(),
                },
            )
            .map_err(Status::failed_precondition)?;
        Ok(Response::new(RedeemExternalActionPermitResponse {
            redemption: Some(ExternalActionRedemption {
                version: redemption.version,
                permit_id: redemption.permit_id,
                redemption_id: redemption.redemption_id,
                executor: redemption.executor,
                redeemed_at_ms: redemption.redeemed_at_ms,
                invocation_ordinal: redemption.invocation_ordinal,
                evidence_due_at_ms: redemption.evidence_due_at_ms,
                site_id: redemption.site_id,
            }),
        }))
    }

    async fn set_external_action_policy(
        &self,
        req: Request<SetExternalActionPolicyRequest>,
    ) -> Result<Response<SetExternalActionPolicyResponse>, Status> {
        require_control_plane_admin(&req, "external action policy mutation")?;
        let actor = required_authenticated_actor(&req)?;
        let input = req.into_inner();
        match input.operation.as_str() {
            "set_policy" => {
                let input_policy = input
                    .policy
                    .ok_or_else(|| Status::invalid_argument("policy required"))?;
                let policy = permit::ExternalPermitPolicy {
                    scope: input_policy.scope,
                    offline_action_types: input_policy.offline_action_types,
                    offline_max_duration_ms: input_policy.offline_max_duration_ms,
                    offline_max_invocations: input_policy.offline_max_invocations,
                    permitted_delegators: input_policy.permitted_delegators,
                    max_delegation_depth: input_policy.max_delegation_depth,
                };
                self.db
                    .set_external_permit_policy(&policy, chrono::Utc::now().timestamp_millis())
                    .map_err(Status::invalid_argument)?;
                Ok(Response::new(SetExternalActionPolicyResponse {
                    policy: Some(external_permit_policy_to_proto(&policy)),
                    changed: true,
                }))
            }
            "kill_switch" => {
                if input.scope_value.trim().is_empty() || input.reason.trim().is_empty() {
                    return Err(Status::invalid_argument("scope_value and reason required"));
                }
                let now = chrono::Utc::now().timestamp_millis();
                let changed = self
                    .db
                    .set_permit_kill_switch(
                        &input.scope_kind,
                        &input.scope_value,
                        input.enabled,
                        &input.reason,
                        now,
                    )
                    .map_err(Status::invalid_argument)?;
                self.db
                    .record_decisions_idempotently(&[crate::sekai::audit::Decision {
                        id: format!("external-kill-{}", uuid::Uuid::new_v4().simple()),
                        timestamp: now,
                        actor,
                        action: "external_action_permit/kill_switch".into(),
                        reason: input.reason,
                        evidence: HashMap::from([
                            ("scope_kind".into(), input.scope_kind.clone()),
                            ("scope_value".into(), input.scope_value.clone()),
                        ]),
                        target_id: input.scope_value,
                        outcome: if input.enabled {
                            "enabled".into()
                        } else {
                            "disabled".into()
                        },
                    }])
                    .map_err(Status::internal)?;
                Ok(Response::new(SetExternalActionPolicyResponse {
                    policy: None,
                    changed,
                }))
            }
            _ => Err(Status::invalid_argument(
                "operation must be set_policy or kill_switch",
            )),
        }
    }

    async fn decide_gateway_execution(
        &self,
        req: Request<DecideGatewayExecutionRequest>,
    ) -> Result<Response<DecideGatewayExecutionResponse>, Status> {
        use crate::chisei::gateway_decide::{
            GATEWAY_DECIDE_CONTRACT_VERSION, GatewayDecideDenyReason, GatewayDecideInputs,
            GatewayDecideOutcome, GatewayDecideRequest, budget_grant_id, compose_gateway_decide,
        };

        let actor = authenticated_actor(&req);
        let delegated_principal = req
            .metadata()
            .get(DELEGATED_PRINCIPAL_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let r = req.into_inner();
        let namespace = r.namespace.trim();
        if namespace.is_empty() {
            return Ok(Response::new(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: GatewayDecideDenyReason::InvalidRequest.as_str().into(),
                deny_message: "namespace is required".into(),
                ..Default::default()
            }));
        }
        if let Err(status) =
            require_execution_namespace_access(&self.db, &self.config, &actor, namespace)
        {
            let reason = if status.code() == tonic::Code::PermissionDenied {
                GatewayDecideDenyReason::Unauthorized
            } else {
                GatewayDecideDenyReason::InvalidRequest
            };
            return Ok(Response::new(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: reason.as_str().into(),
                deny_message: status.message().to_string(),
                ..Default::default()
            }));
        }

        let domain_request = GatewayDecideRequest {
            contract_version: r.contract_version.clone(),
            namespace: namespace.into(),
            principal: actor.clone(),
            requested_model: r.requested_model.trim().to_string(),
            operation_class: r.operation_class.trim().to_string(),
            estimated_cost_usd_micros: r.estimated_cost_usd_micros,
            correlation_operation_id: r.correlation_operation_id.trim().to_string(),
            correlation_attempt: r.correlation_attempt,
        };
        if let Err(message) = domain_request.validate() {
            return Ok(Response::new(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: GatewayDecideDenyReason::InvalidRequest.as_str().into(),
                deny_message: message,
                ..Default::default()
            }));
        }
        let context_admission_policy = match self.policy.context_admission_policy(namespace) {
            Ok(policy) => policy,
            Err(_error) => {
                return Ok(Response::new(DecideGatewayExecutionResponse {
                    contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                    admitted: false,
                    deny_reason: GatewayDecideDenyReason::PolicyDenied.as_str().into(),
                    deny_message: "context admission policy unavailable".into(),
                    context_admission_reasons: vec!["context_admission:unavailable".into()],
                    ..Default::default()
                }));
            }
        };
        let context_admission_policy_version = context_admission_policy
            .as_ref()
            .map(crate::chisei::policy::ContextAdmissionPolicy::version)
            .unwrap_or_default();
        let context_admission_descriptor_version =
            crate::chisei::epistemic_descriptor::EPISTEMIC_DESCRIPTOR_VERSION.to_string();
        let operation_risk =
            crate::chisei::policy::OperationRisk::from_labels(&r.operation_class, &r.task_class);
        let operation_context_gate = context_admission_policy
            .as_ref()
            .map(|policy| policy.operation_gate(operation_risk))
            .transpose()
            .map_err(Status::failed_precondition)?
            .flatten();
        if let Some(gate) = operation_context_gate
            .as_ref()
            .filter(|gate| gate.blocks_provider())
        {
            return Ok(Response::new(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: GatewayDecideDenyReason::PolicyDenied.as_str().into(),
                deny_message: "context admission policy requires review or verification".into(),
                context_admission_policy_version: gate.policy_version.clone(),
                context_admission_descriptor_version: gate.descriptor_version.clone(),
                context_admission_decision: gate.action.as_str().into(),
                context_admission_reasons: vec![gate.reason_code.clone()],
                ..Default::default()
            }));
        }

        let project = if r.project.trim().is_empty() {
            namespace
        } else {
            r.project.trim()
        };
        let trusted_gateway = matches!(actor.as_str(), "root" | "local" | "chisei-gateway");
        if project != namespace
            || (!trusted_gateway
                && ((!r.agent.trim().is_empty() && r.agent.trim() != actor)
                    || (!r.user_id.trim().is_empty() && r.user_id.trim() != actor)
                    || !r.key_id.trim().is_empty()))
        {
            return Ok(Response::new(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: GatewayDecideDenyReason::Unauthorized.as_str().into(),
                deny_message: "gateway decision scopes are not authorized for the caller".into(),
                ..Default::default()
            }));
        }
        let budget_subject = budget_subject(
            "",
            project,
            r.agent.trim(),
            r.key_id.trim(),
            r.work_unit.trim(),
            "",
        )
        .unwrap_or_else(|_| format!("project:{project}"));
        let estimated_tokens = r.estimated_tokens.max(0);
        let metric = crate::db::chisei_budget::METRIC_TOKENS;
        let token_budget_check =
            self.budget
                .check_with_metric(&budget_subject, estimated_tokens, metric);
        let request_budget_check = self.budget.check_with_metric(
            &budget_subject,
            i32::try_from(r.expected_calls.max(1)).unwrap_or(i32::MAX),
            crate::db::chisei_budget::METRIC_REQUESTS,
        );
        let within_cap = token_budget_check.is_ok() && request_budget_check.is_ok();
        let decision_budget_scope = request_budget_check
            .as_ref()
            .err()
            .or_else(|| token_budget_check.as_ref().err())
            .as_ref()
            .and_then(|error| {
                error
                    .strip_prefix("budget exceeded at ")
                    .and_then(|rest| rest.split_once(": used"))
                    .map(|(scope, _)| scope.to_string())
            })
            .unwrap_or_else(|| budget_subject.clone());
        let mut route_bias = self
            .budget
            .route_bias(
                &budget_subject,
                estimated_tokens,
                metric,
                r.task_class.trim(),
            )
            .as_str()
            .to_string();
        let continuation_started = !r.work_unit.trim().is_empty()
            && active_continuation_allocation(
                &self.db,
                r.work_unit.trim(),
                &[
                    actor.as_str(),
                    r.agent.as_str(),
                    r.key_id.as_str(),
                    r.user_id.as_str(),
                ],
                chrono::Utc::now().timestamp_millis(),
            )
            && self
                .budget
                .get_usage_with_metric(&budget_subject, metric)
                .tokens_used
                > 0;
        let (budget_allowed, degradation_level, budget_warning) = if within_cap {
            (
                true,
                if route_bias == "cheap" {
                    "cheap_cloud"
                } else {
                    "capable"
                },
                false,
            )
        } else if request_budget_check.is_ok() && continuation_started {
            (true, "warn", true)
        } else if request_budget_check.is_ok()
            && r.local_free_available
            && crate::chisei::model_routing::is_cheap_eligible_task_class(r.task_class.trim())
        {
            route_bias = "local_free".to_string();
            // The canonical decision may admit only after policy resolution
            // proves that this recommendation resolves to a local-free model.
            // The gateway independently rejects any non-local result.
            (true, "local_free", true)
        } else {
            (false, "hard_cap", true)
        };

        // Keep the gateway decision on the same policy-resolution path as
        // the internal policy resolver. The retired edge fallback previously
        // supplied scoped policies, eval regressions, lifecycle checks, and
        // canonical live-model resolution; the canonical PDP must preserve
        // those semantics itself.
        let mut policy_request = Request::new(ResolvePolicyRequest {
            namespace: namespace.to_string(),
            preferred_runtime: r.preferred_runtime.trim().to_string(),
            preferred_model: r.requested_model.trim().to_string(),
            subject: String::new(),
            project: project.to_string(),
            agent: r.agent.trim().to_string(),
            key_id: r.key_id.trim().to_string(),
            task_class: r.task_class.trim().to_string(),
            user_id: r.user_id.trim().to_string(),
            expected_calls: r.expected_calls.max(1),
            budget_route_bias: route_bias.clone(),
            route_override: r.route_override.trim().to_string(),
            capability_requirements_json: r.capability_requirements_json.clone(),
        });
        if let Ok(principal) = actor.parse() {
            policy_request
                .metadata_mut()
                .insert("x-principal", principal);
        }
        let (route, policy_resolution) = match self.resolve_policy(policy_request).await {
            Ok(response) => match response.into_inner().resolution {
                Some(resolution) => {
                    if !resolution.route_bias.trim().is_empty() {
                        route_bias = resolution.route_bias.clone();
                    }
                    (
                        Ok((
                            resolution.runtime.clone(),
                            resolution.model.clone(),
                            resolution.policy_version.clone(),
                        )),
                        Some(resolution),
                    )
                }
                None => (
                    Err((
                        GatewayDecideDenyReason::PolicyDenied,
                        "policy resolution returned no decision".into(),
                    )),
                    None,
                ),
            },
            Err(status) => {
                let reason = match status.code() {
                    tonic::Code::ResourceExhausted => GatewayDecideDenyReason::BudgetDenied,
                    tonic::Code::FailedPrecondition => {
                        GatewayDecideDenyReason::CapabilityUnsupported
                    }
                    tonic::Code::PermissionDenied => GatewayDecideDenyReason::ResidencyDenied,
                    tonic::Code::InvalidArgument => GatewayDecideDenyReason::PolicyDenied,
                    _ => GatewayDecideDenyReason::PolicyDenied,
                };
                (Err((reason, status.message().to_string())), None)
            }
        };

        let grant = budget_grant_id(
            &budget_subject,
            &domain_request.correlation_operation_id,
            domain_request.correlation_attempt,
        );
        let composed = compose_gateway_decide(GatewayDecideInputs {
            request: domain_request.clone(),
            route,
            budget_allowed,
            budget_scope: decision_budget_scope.clone(),
            budget_grant_id: grant.clone(),
            route_bias: route_bias.clone(),
            degradation_level: degradation_level.into(),
            budget_warning,
        });

        let mut response = DecideGatewayExecutionResponse {
            contract_version: composed.contract_version.clone(),
            admitted: composed.allows_upstream(),
            deny_reason: String::new(),
            deny_message: String::new(),
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            policy_version: String::new(),
            budget_scope: decision_budget_scope.clone(),
            budget_grant_id: grant,
            route_bias,
            degradation_level: degradation_level.into(),
            budget_warning,
            policy_scope: policy_resolution
                .as_ref()
                .map(|resolution| resolution.policy_scope.clone())
                .unwrap_or_default(),
            data_class: policy_resolution
                .as_ref()
                .map(|resolution| resolution.data_class.clone())
                .unwrap_or_default(),
            fallback_models: policy_resolution
                .as_ref()
                .map(|resolution| resolution.fallback_models.clone())
                .unwrap_or_default(),
            eval_regressed: policy_resolution
                .as_ref()
                .is_some_and(|resolution| resolution.eval_regressed),
            eval_regression_reason: policy_resolution
                .as_ref()
                .map(|resolution| resolution.eval_regression_reason.clone())
                .unwrap_or_default(),
            context_admission_policy_version: context_admission_policy_version.clone(),
            context_admission_descriptor_version: context_admission_descriptor_version.clone(),
            context_admission_decision: operation_context_gate
                .as_ref()
                .map(|gate| gate.action.as_str().to_string())
                .unwrap_or_else(|| {
                    context_admission_policy
                        .as_ref()
                        .map(|_| ContextAdmissionAction::Include.as_str().to_string())
                        .unwrap_or_default()
                }),
            context_admission_reasons: operation_context_gate
                .as_ref()
                .map(|gate| vec![gate.reason_code.clone()])
                .unwrap_or_default(),
            sampling_evaluated: false,
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            prepared_spec: String::new(),
        };
        match &composed.outcome {
            GatewayDecideOutcome::Admit(admit) => {
                response.resolved_runtime = admit.resolved_runtime.clone();
                response.resolved_model = admit.resolved_model.clone();
                response.policy_version = admit.policy_version.clone();
                response.budget_grant_id = admit.budget_grant_id.clone();
            }
            GatewayDecideOutcome::Deny(deny) => {
                response.deny_reason = deny.reason.as_str().into();
                response.deny_message = deny.message.clone();
            }
        }
        if response.admitted && !r.pipeline_spec.trim().is_empty() {
            match self.gateway_pipeline_decision(GatewayPipelineInput {
                actor: &actor,
                delegated_principal: delegated_principal.as_deref(),
                request_id: &domain_request.correlation_operation_id,
                namespace,
                spec: &r.pipeline_spec,
                model: &response.resolved_model,
                runtime: &response.resolved_runtime,
                task_class: &r.task_class,
            }) {
                Ok(decision) => {
                    response.sampling_evaluated = true;
                    response.sampled = decision.sampling.sampled;
                    response.sample_rate = decision.sampling.effective_rate;
                    response.sample_reason = decision.sampling.reason;
                    response.prepared_spec = decision.run.prepared_spec;
                }
                Err(error) => {
                    tracing::warn!(%error, "gateway sampling decision unavailable");
                }
            }
        }

        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: format!(
                "gateway-decide:{}:{}:{}",
                namespace,
                domain_request.correlation_operation_id,
                domain_request.correlation_attempt
            ),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor,
            action: "gateway.decide".into(),
            reason: if response.admitted {
                "gateway fat-decide admitted".into()
            } else {
                response.deny_message.clone()
            },
            evidence: std::collections::HashMap::from([
                ("namespace".into(), namespace.into()),
                (
                    "correlation_operation_id".into(),
                    domain_request.correlation_operation_id.clone(),
                ),
                ("admitted".into(), response.admitted.to_string()),
                ("deny_reason".into(), response.deny_reason.clone()),
                ("resolved_model".into(), response.resolved_model.clone()),
                ("budget_scope".into(), response.budget_scope.clone()),
                (
                    "contract_version".into(),
                    GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                ),
            ]),
            target_id: domain_request.correlation_operation_id,
            outcome: if response.admitted {
                "admitted".into()
            } else {
                "denied".into()
            },
        });

        Ok(Response::new(response))
    }

    async fn record_usage(
        &self,
        req: Request<RecordUsageRequest>,
    ) -> Result<Response<RecordUsageResponse>, Status> {
        let actor = authenticated_actor(&req);
        let trusted_accounting_principal =
            matches!(actor.as_str(), "root" | "local" | "chisei-gateway")
                || self
                    .config
                    .gateway_receipt_principals
                    .iter()
                    .any(|principal| principal == &actor);
        if !trusted_accounting_principal {
            return Err(Status::permission_denied(
                "usage recording requires an authorized accounting principal",
            ));
        }
        let r = req.into_inner();
        if r.tokens_used < 0 && !matches!(actor.as_str(), "root" | "local") {
            return Err(Status::permission_denied(
                "negative usage adjustments require control-plane administration",
            ));
        }
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
        if !r.operation_receipt_json.trim().is_empty() {
            persist_gateway_operation_receipt(self, &r.operation_receipt_json, &actor)?;
        }
        let sample_recorded = if let Some(observation) = r.sample_observation {
            if observation.request_id.trim().is_empty()
                || observation.namespace.trim().is_empty()
                || observation.spec.trim().is_empty()
                || observation.output_content.trim().is_empty()
            {
                return Err(Status::invalid_argument(
                    "sample observation requires request_id, namespace, spec, and output_content",
                ));
            }
            if self.config.scoring_enabled {
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
                        task_class: crate::chisei::scoring::normalize_task_class(
                            &observation.task_class,
                        ),
                        cost_usd_micros: observation.cost_usd_micros,
                    })
                    .map_err(Status::internal)?;
                true
            } else {
                false
            }
        } else {
            false
        };
        let u = self.budget.get_usage_with_metric(&budget_subject, metric);
        Ok(Response::new(RecordUsageResponse {
            usage: Some(BudgetUsage {
                user_id: u.user_id,
                tokens_used: u.tokens_used,
                max_tokens: u.max_tokens,
                period_type: u.period_type.as_str().into(),
                period_start: u.period_start,
            }),
            sample_recorded,
        }))
    }

    async fn set_budget_limit(
        &self,
        req: Request<SetBudgetLimitRequest>,
    ) -> Result<Response<SetBudgetLimitResponse>, Status> {
        require_control_plane_admin(&req, "budget mutation")?;
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

    async fn set_namespace_policy(
        &self,
        req: Request<SetNamespacePolicyRequest>,
    ) -> Result<Response<SetNamespacePolicyResponse>, Status> {
        require_control_plane_admin(&req, "namespace policy mutation")?;
        let registry = self.refresh_provider_registry_for_resolution().await?;
        let validated_registry_version = registry.state_version;
        crate::provider_profile::with_provider_registry_snapshot(registry, async {
            let r = req.into_inner();
            if r.namespace.trim().is_empty() {
                return Err(Status::invalid_argument("namespace required"));
            }
            let policy = normalize_legacy_policy_provider_pairs(policy_from_request(&r));
            validate_policy_provider_pairs(&policy).map_err(Status::invalid_argument)?;
            let context_admission_policy = if r.context_admission_policy_json.trim().is_empty() {
                self.policy
                    .context_admission_policy(&r.namespace)
                    .map_err(Status::failed_precondition)?
            } else if r.context_admission_policy_json.trim() == "null" {
                None
            } else {
                let context_policy = serde_json::from_str::<
                    crate::chisei::policy::ContextAdmissionPolicy,
                >(&r.context_admission_policy_json)
                .map_err(|error| {
                    Status::invalid_argument(format!("invalid context admission policy: {error}"))
                })?;
                context_policy
                    .validate()
                    .map_err(Status::invalid_argument)?;
                Some(context_policy)
            };
            let policy_data_class = policy.data_class.clone();
            let policy_version = policy.version();
            let current_registry = self.refresh_provider_registry_for_resolution().await?;
            if current_registry.state_version != validated_registry_version {
                return Err(Status::aborted(
                    "provider registry changed while validating namespace policy",
                ));
            }
            persist_namespace_policy(
                &self.db,
                &r.namespace,
                &policy,
                context_admission_policy.as_ref(),
            )
            .map_err(Status::internal)?;
            let default_runtime = policy.default_runtime.clone();
            let default_model = policy.default_model.clone();
            self.policy.set_namespace_policy(&r.namespace, policy);
            if let Some(context_policy) = context_admission_policy {
                self.policy
                    .set_context_admission_policy(&r.namespace, context_policy)
                    .map_err(Status::invalid_argument)?;
            } else {
                self.policy.clear_context_admission_policy(&r.namespace);
            }
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

    async fn get_effective_policy_summary(
        &self,
        req: Request<GetEffectivePolicySummaryRequest>,
    ) -> Result<Response<GetEffectivePolicySummaryResponse>, Status> {
        let actor = required_authenticated_actor(&req)?;
        let namespace = canonical_namespace(&req.get_ref().namespace)?.to_string();
        require_namespace_access(&self.db, &actor, &namespace)?;

        let routing = self.policy.effective_policy(&namespace).map_or_else(
            || EffectiveRoutingSummary {
                configured: false,
                status: "unconfigured".into(),
                ..Default::default()
            },
            |policy| EffectiveRoutingSummary {
                configured: true,
                status: "configured".into(),
                runtime: policy.default_runtime.clone(),
                model: policy.default_model.clone(),
                policy_scope: namespace.clone(),
                policy_version: policy.version(),
            },
        );

        let raw_limits = self
            .db
            .budget_limits_for_scope(&format!("project:{namespace}"))
            .map_err(Status::internal)?;
        let budget_version = content_version(&raw_limits);
        let limits = raw_limits
            .into_iter()
            .map(
                |(scope, metric, max_amount, period_type)| EffectiveBudgetLimit {
                    metric,
                    max_amount,
                    period_type,
                    policy_scope: scope,
                },
            )
            .collect::<Vec<_>>();
        let budgets = EffectiveBudgetSummary {
            configured: !limits.is_empty(),
            status: if limits.is_empty() {
                "unconfigured"
            } else {
                "configured"
            }
            .into(),
            limits,
            policy_version: budget_version,
        };

        let project_action_scope = format!("project:{namespace}");
        let action_policy = match self
            .db
            .get_action_policy(&project_action_scope)
            .map_err(Status::internal)?
        {
            some @ Some(_) => some,
            None => self
                .db
                .get_action_policy(&namespace)
                .map_err(Status::internal)?,
        };
        let actions = action_policy.map_or_else(
            || EffectiveActionPolicySummary {
                configured: false,
                status: "unconfigured".into(),
                ..Default::default()
            },
            |policy| {
                use crate::sekai::action_policy::ActionDecision;
                let canonical_properties = policy
                    .to_properties()
                    .into_iter()
                    .collect::<BTreeMap<_, _>>();
                let decisions = policy
                    .action_overrides
                    .values()
                    .chain(policy.risk_overrides.values());
                let (mut allow, mut deny, mut approval) = (0, 0, 0);
                for decision in decisions {
                    match decision {
                        ActionDecision::Allow => allow += 1,
                        ActionDecision::Deny => deny += 1,
                        ActionDecision::RequireApproval => approval += 1,
                    }
                }
                EffectiveActionPolicySummary {
                    configured: true,
                    status: "configured".into(),
                    allow_rule_count: allow,
                    deny_rule_count: deny,
                    require_approval_rule_count: approval,
                    default_decision: policy.default_decision.as_str().into(),
                    policy_scope: policy.scope.clone(),
                    policy_version: content_version(&canonical_properties),
                }
            },
        );

        let provider = req.get_ref().provider.trim();
        let discovery = crate::chisei::model_availability::ModelDiscoveryConfig {
            openai_base_url: std::env::var("CHISEI_OPENAI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com/v1".into()),
            openai_api_key: self.config.openai_api_key.clone(),
            anthropic_base_url: std::env::var("CHISEI_ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com/v1".into()),
            anthropic_api_key: self.config.anthropic_api_key.clone(),
            ollama_url: self.config.ollama_url.clone(),
            native_configured: self.config.native_llm_url.is_some(),
        };
        let availability =
            crate::chisei::model_availability::refresh_model_availability(&discovery, false).await;
        let view = availability.public_models((!provider.is_empty()).then_some(provider));
        let models = view
            .models
            .into_iter()
            .map(|model| AvailableModelRecord {
                provider: model.provider,
                upstream_model: model.upstream_model,
                canonical_model: model.canonical_model,
                lifecycle: model.lifecycle,
                capabilities: model.capabilities.map(|value| AvailableModelCapabilities {
                    responses: value.responses,
                    streaming: value.streaming,
                    tools: value.tools,
                    parallel_tools: value.parallel_tools,
                    structured_output: value.structured_output,
                    reasoning_controls: value.reasoning_controls,
                    modalities: value.modalities,
                    provider_continuation: value.provider_continuation,
                    reports_usage: value.reports_usage,
                    partial_usage: value.partial_usage,
                    context_tokens: value.context_tokens,
                    output_tokens: value.output_tokens,
                    built_in_tools: value.built_in_tools,
                }),
                pricing: model.pricing.map(|value| AvailableModelPricing {
                    version: value.version,
                    source: value.source,
                    observed_at: value.observed_at,
                    dimensions: value.dimensions,
                }),
            })
            .collect();

        Ok(Response::new(GetEffectivePolicySummaryResponse {
            namespace,
            routing: Some(routing),
            budgets: Some(budgets),
            actions: Some(actions),
            available_models_version: view.version,
            models,
        }))
    }

    async fn plan_execution(
        &self,
        req: Request<PlanExecutionRequest>,
    ) -> Result<Response<PlanExecutionResponse>, Status> {
        let registry = self.refresh_provider_registry_for_resolution().await?;
        crate::provider_profile::with_provider_registry_snapshot(registry, async {
            let actor = authenticated_actor(&req);
            let context = enterprise_authenticated_context(&req)?.cloned();
            let request = req.into_inner();
            let mut input = request
                .input
                .ok_or(Status::invalid_argument("input required"))?;
            if context.is_some()
                && (!input.route_override.trim().is_empty() || request.gunshi_allocation.is_some())
            {
                return Err(Status::permission_denied(
                    "enterprise execution route override or Gunshi allocation binding denied",
                ));
            }
            require_execution_namespace_access_with_context(
                &self.db,
                &self.config,
                &actor,
                context.as_ref(),
                &input.namespace,
            )?;
            let bound_allocation = if let Some(binding) = request.gunshi_allocation {
                let (bound_input, allocation) = self.bind_gunshi_allocation(input, binding)?;
                input = bound_input;
                Some(allocation)
            } else {
                None
            };
            let mut plan = self.plan_from_input(input, &actor).await?;
            if let Some(allocation) = bound_allocation {
                let live_policy_version = self
                    .policy
                    .effective_policy(&allocation.plan.namespace)
                    .map(|policy| policy.version())
                    .unwrap_or_else(|| "implicit-allow/v1".into());
                if live_policy_version != allocation.plan.policy_version {
                    return Err(Status::failed_precondition(
                        "Gunshi allocation policy changed while planning",
                    ));
                }
                if plan.resolved_runtime != allocation.plan.selection.runtime
                    || plan.resolved_model != allocation.plan.selection.model
                {
                    return Err(Status::failed_precondition(
                        "live policy or provider state no longer permits the Gunshi allocation",
                    ));
                }
                plan.gunshi_issuance_id = allocation.issuance_id;
                plan.gunshi_allocation_id = allocation.plan.allocation_id;
                plan.gunshi_agent_id = allocation.plan.selection.agent_id;
                plan.gunshi_policy_version = allocation.plan.policy_version;
                plan.gunshi_input_fingerprint = allocation.plan.input_fingerprint;
                plan.gunshi_budget_ceiling_usd_micros = allocation.plan.budget_ceiling_usd_micros;
                plan.gunshi_max_attempts = allocation.plan.attempts.max_attempts;
                plan.gunshi_human_review_required =
                    allocation.plan.verification.human_review_required;
            }
            if let Some(plan_input) = &plan.input {
                let namespace_hint = plan_input.namespace.trim().to_string();
                self.record_evolve_task(
                    &plan_input.request_id,
                    &namespace_hint,
                    &plan.enriched_spec,
                    if plan.executable { "planned" } else { "failed" },
                    plan_input.estimated_tokens,
                )
                .map_err(Status::internal)?;
            }
            self.record_planned_operation(&plan, &actor)
                .map_err(Status::internal)?;
            self.cache_plan_for_enterprise_authority(
                plan.clone(),
                enterprise_execution_authority(context.as_ref()),
            );
            Ok(Response::new(PlanExecutionResponse { plan: Some(plan) }))
        })
        .await
    }

    async fn execute_plan_stream(
        &self,
        req: Request<ExecutePlanRequest>,
    ) -> Result<Response<Self::ExecutePlanStreamStream>, Status> {
        let actor = authenticated_actor(&req);
        let context = enterprise_authenticated_context(&req)?.cloned();
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
            let cached = plans
                .get(&requested_plan.plan_id)
                .ok_or(Status::not_found("execution plan not found"))?;
            if cached.plan.planning_actor != actor
                || cached.enterprise_authority != enterprise_execution_authority(context.as_ref())
            {
                return Err(Status::permission_denied(
                    "execution plan belongs to a different planning principal",
                ));
            }
            cached.plan.clone()
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
        require_execution_namespace_access_with_context(
            &self.db,
            &self.config,
            &actor,
            context.as_ref(),
            &input.namespace,
        )?;
        {
            let mut plans = self
                .planned_executions
                .lock()
                .expect("planned executions poisoned");
            plans
                .remove(&requested_plan.plan_id)
                .ok_or(Status::not_found("execution plan not found"))?;
        }
        let namespace_hint = input.namespace.trim().to_string();
        let attempt_started_at_ms = chrono::Utc::now().timestamp_millis();

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

        // Lookup-first short-circuit for stream execute (#281 S2). This is
        // deliberately after namespace authorization and plan ownership
        // checks and the live evaluation-regression gate, but before provider
        // selection, residency, egress, or model payload preparation. A
        // complete structured hit must not enter the provider-routing path at
        // all.
        let lookup_refusal = match evaluate_execute_lookup_first(&self.db, &input, &actor) {
            ExecuteLookupFirst::Hit {
                response,
                capability,
                provenance,
            } => {
                self.invalidate_ineligible_execution_memory_holdouts(
                    &plan.plan_id,
                    &actor,
                    &plan.memory_holdouts,
                )?;
                self.record_execution_memory_injections(
                    &plan.plan_id,
                    &actor,
                    &plan.memory_references,
                )?;
                if let Err(error) = self.record_evolve_task(
                    &input.request_id,
                    &namespace_hint,
                    &plan.enriched_spec,
                    "done",
                    0,
                ) {
                    record_failed_operation_on(
                        &self.db,
                        &plan,
                        &actor,
                        "execution_bookkeeping_failed",
                    )
                    .map_err(Status::internal)?;
                    return Err(Status::internal(error));
                }
                let completed_at_ms = chrono::Utc::now().timestamp_millis();
                record_completed_lookup_operation_on(
                    &self.db,
                    &plan,
                    &actor,
                    &response,
                    attempt_started_at_ms,
                    completed_at_ms,
                    &capability,
                    &provenance,
                )
                .map_err(Status::internal)?;
                let content = response.content.clone();
                let stream = async_stream::stream! {
                    yield Ok(ExecutePlanStreamEvent {
                        content_delta: content,
                        response: Some(response),
                        done: true,
                        executed_at: completed_at_ms / 1000,
                    });
                };
                return Ok(Response::new(Box::pin(stream)));
            }
            ExecuteLookupFirst::ModelPath { lookup_refusal } => lookup_refusal,
        };

        let provider = crate::llm::provider_name(&plan.resolved_model).to_string();
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let data_class = self.data_class(effective_policy.as_ref());
        if let Err(error) = self.policy.enforce_residency(
            &input.namespace,
            &provider,
            &plan.resolved_model,
            data_class.as_str(),
        ) {
            record_failed_operation_on(&self.db, &plan, &actor, "residency_denied")
                .map_err(Status::internal)?;
            return Err(Status::permission_denied(error));
        }
        self.enforce_execution_provider_privacy(&plan, &input, &actor, &provider, data_class)?;
        if crate::chisei::egress::is_external_provider(&provider)
            && plan.egress_decisions.is_empty()
        {
            record_failed_operation_on(&self.db, &plan, &actor, "egress_evidence_missing")
                .map_err(Status::internal)?;
            return Err(Status::failed_precondition(
                "external execution plan missing egress decisions",
            ));
        }
        let normalized_user_id = if input.user_id.is_empty() {
            "default".to_string()
        } else {
            input.user_id.clone()
        };
        self.enforce_execution_payload_privacy(&plan, &input, &actor, &provider, data_class)?;
        self.record_egress_audit(
            "execute_context",
            &input.request_id,
            &provider,
            &plan.resolved_model,
            &plan.egress_decisions,
        );
        let llm_req = ProviderExecutionRequest {
            model: plan.resolved_model.clone(),
            system: plan.prepared_system.clone(),
            messages: plan.prepared_messages.clone(),
            tools: plan.tools.clone(),
            max_tokens: plan.max_tokens,
            user_id: Some(normalized_user_id),
        };
        self.invalidate_ineligible_execution_memory_holdouts(
            &plan.plan_id,
            &actor,
            &plan.memory_holdouts,
        )?;
        self.record_execution_memory_injections(&plan.plan_id, &actor, &plan.memory_references)?;

        let cacheable_message_count =
            native_cacheable_message_count(&input, &plan.prepared_messages);
        let chat_stream = match execute_native_chat_request_stream(
            &self.config,
            self.budget.clone(),
            self.db.as_ref(),
            context.as_ref(),
            llm_req,
            cacheable_message_count,
        )
        .await
        {
            Ok(stream) => stream,
            Err(status) => {
                record_failed_operation_on(&self.db, &plan, &actor, "model_stream_start_failed")
                    .map_err(Status::internal)?;
                return Err(status);
            }
        };
        let db = self.db.clone();
        let evolve_history = self.evolve_history.clone();
        let request_id = input.request_id.clone();
        let enriched_spec = plan.enriched_spec.clone();
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
            let mut cache_read_input_tokens = 0;
            let mut cache_creation_input_tokens = 0;
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
                if chunk.cache_read_input_tokens > 0 {
                    cache_read_input_tokens = chunk.cache_read_input_tokens;
                }
                if chunk.cache_creation_input_tokens > 0 {
                    cache_creation_input_tokens = chunk.cache_creation_input_tokens;
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
                        cache_read_input_tokens,
                        cache_creation_input_tokens,
                    };
                    let execution = FinishStreamedExecution {
                        db: db.as_ref(),
                        evolve_history: &evolve_history,
                        request_id: &request_id,
                        namespace: &namespace_hint,
                        enriched_spec: &enriched_spec,
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
                    let answer_path = lookup_refusal
                        .as_ref()
                        .map(|_| crate::chisei::lookup_first::ANSWER_PATH_MODEL);
                    if let Err(error) = record_completed_operation_on_with_path(
                        db.as_ref(),
                        &receipt_plan,
                        &actor,
                        &response,
                        attempt_started_at_ms,
                        completed_at_ms,
                        answer_path,
                        lookup_refusal.as_deref(),
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
                    cache_read_input_tokens,
                    cache_creation_input_tokens,
                };
                let execution = FinishStreamedExecution {
                    db: db.as_ref(),
                    evolve_history: &evolve_history,
                    request_id: &request_id,
                    namespace: &namespace_hint,
                    enriched_spec: &enriched_spec,
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
                let answer_path = lookup_refusal
                    .as_ref()
                    .map(|_| crate::chisei::lookup_first::ANSWER_PATH_MODEL);
                if let Err(error) = record_completed_operation_on_with_path(
                    &db,
                    &receipt_plan,
                    &actor,
                    &response,
                    attempt_started_at_ms,
                    completed_at_ms,
                    answer_path,
                    lookup_refusal.as_deref(),
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

    async fn list_kioku_candidates(
        &self,
        req: Request<ListKiokuCandidatesRequest>,
    ) -> Result<Response<ListKiokuCandidatesResponse>, Status> {
        require_team_namespace_access(&self.db, &self.config, &req, &req.get_ref().namespace)?;
        let actor = authenticated_actor(&req);
        let request = req.into_inner();
        if request.namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace is required"));
        }
        let limit = match request.limit {
            0 => 50,
            1..=100 => request.limit as usize,
            _ => return Err(Status::invalid_argument("limit must not exceed 100")),
        };
        let operation_class = request.operation_class.trim().to_string();
        let page_token = request.page_token.trim();
        let mut cursor = None;
        if !page_token.is_empty() {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(page_token)
                .map_err(|_| Status::invalid_argument("invalid Kioku candidate page token"))?;
            let token: serde_json::Value = serde_json::from_slice(&decoded)
                .map_err(|_| Status::invalid_argument("invalid Kioku candidate page token"))?;
            let token_namespace = token
                .get("namespace")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Status::invalid_argument("invalid Kioku candidate page token"))?;
            let token_operation_class = token
                .get("operation_class")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Status::invalid_argument("invalid Kioku candidate page token"))?;
            let token_id = token
                .get("id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| Status::invalid_argument("invalid Kioku candidate page token"))?;
            let token_version = token
                .get("version")
                .and_then(serde_json::Value::as_u64)
                .and_then(|version| u32::try_from(version).ok())
                .filter(|version| *version > 0)
                .ok_or_else(|| Status::invalid_argument("invalid Kioku candidate page token"))?;
            if token_namespace != request.namespace.trim()
                || token_operation_class != operation_class
            {
                return Err(Status::invalid_argument(
                    "Kioku candidate page token does not match the request filters",
                ));
            }
            cursor = Some(crate::chisei::kioku::KiokuCandidateCursor {
                id: token_id.to_string(),
                version: token_version,
            });
        }
        const CANDIDATE_PAGE_SIZE: usize = 100;
        const MAX_CANDIDATE_PAGES: usize = 4;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut memories = Vec::new();
        let mut seen = HashSet::new();
        let classification_ceiling = self
            .db
            .kioku_authorized_classification_ceiling(&request.namespace, &actor)
            .ok();
        let mut has_more = false;
        for _ in 0..MAX_CANDIDATE_PAGES {
            let page = self
                .db
                .list_kioku_candidate_page(&request.namespace, CANDIDATE_PAGE_SIZE, cursor.as_ref())
                .map_err(Status::internal)?;
            let page_len = page.len();
            if page_len == 0 {
                break;
            }
            let page_last = page
                .last()
                .map(|memory| crate::chisei::kioku::KiokuCandidateCursor {
                    id: memory.id.clone(),
                    version: memory.version,
                });
            let mut last_examined = None;
            let mut stopped_early = false;
            for memory in page {
                let current_cursor = crate::chisei::kioku::KiokuCandidateCursor {
                    id: memory.id.clone(),
                    version: memory.version,
                };
                last_examined = Some(current_cursor);
                if !seen.insert((memory.id.clone(), memory.version)) {
                    continue;
                }
                if !operation_class.is_empty()
                    && !memory
                        .operation_classes
                        .iter()
                        .any(|candidate| candidate == &operation_class)
                {
                    continue;
                }
                let authorized = classification_ceiling.is_some_and(|ceiling| {
                    memory.classification <= ceiling
                        && memory
                            .retention_until_ms
                            .is_none_or(|retention| retention > now_ms)
                        && memory.expires_at_ms.is_none_or(|expires| expires > now_ms)
                });
                if !authorized {
                    continue;
                }
                let evidence_authorized = memory.evidence_basis.iter().all(|basis| {
                    basis.source_submission_id.is_empty()
                        || self
                            .db
                            .authorize_kioku_evidence(
                                &crate::chisei::kioku::KiokuEvidenceAuthorizationRequest {
                                    source_submission_id: basis.source_submission_id.clone(),
                                    namespace: memory.namespace.clone(),
                                    memory_classification: memory.classification,
                                    evidence_digest: basis.evidence_digest.clone(),
                                    lifecycle_state: basis.lifecycle_state,
                                    observed_at_ms: basis.observed_at_ms,
                                    actor: actor.clone(),
                                    now_ms,
                                },
                            )
                            .is_ok()
                });
                if evidence_authorized {
                    memories.push(memory);
                    if memories.len() >= limit {
                        stopped_early = true;
                        break;
                    }
                }
            }
            cursor = last_examined.or(page_last.clone());
            has_more = if stopped_early {
                cursor.as_ref() != page_last.as_ref() || page_len == CANDIDATE_PAGE_SIZE
            } else {
                page_len == CANDIDATE_PAGE_SIZE
            };
            if memories.len() >= limit || !has_more {
                break;
            }
        }
        let returned_count = memories.len();
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
        let next_page_token = if has_more {
            cursor.as_ref().map_or_else(String::new, |cursor| {
                encode_kioku_candidate_page_token(
                    request.namespace.trim(),
                    &operation_class,
                    cursor,
                )
            })
        } else {
            String::new()
        };
        debug_assert_eq!(returned_count, candidates.len());
        Ok(Response::new(ListKiokuCandidatesResponse {
            candidates,
            next_page_token,
        }))
    }

    async fn issue_gunshi_recommendations(
        &self,
        req: Request<IssueGunshiRecommendationsRequest>,
    ) -> Result<Response<IssueGunshiRecommendationsResponse>, Status> {
        let actor = authenticated_actor(&req);
        let issuance_id = req.get_ref().issuance_id.trim();
        if issuance_id.is_empty()
            || issuance_id.len() > 128
            || issuance_id != req.get_ref().issuance_id
            || !issuance_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.:".contains(character))
        {
            return Err(Status::invalid_argument(
                "issuance_id must be a canonical identifier of at most 128 characters",
            ));
        }
        let issuance_id = issuance_id.to_string();
        let mut input: crate::chisei::gunshi::RecommendationInput =
            serde_json::from_str(&req.get_ref().input_json).map_err(|error| {
                Status::invalid_argument(format!("invalid recommendation input: {error}"))
            })?;
        if input.contract_version != crate::chisei::gunshi::RECOMMENDATION_INPUT_VERSION {
            return Err(Status::invalid_argument(format!(
                "unsupported recommendation input contract {}",
                input.contract_version
            )));
        }
        if !input.kioku_evidence.is_empty() {
            return Err(Status::invalid_argument(
                "server-issued recommendations load governed Kioku evidence; inline evidence is not accepted",
            ));
        }
        if input.request.operations.is_empty() {
            return Err(Status::invalid_argument(
                "server-issued recommendations require at least one operation",
            ));
        }
        let mut scopes = input
            .request
            .operations
            .iter()
            .map(|operation| {
                (
                    operation.namespace.clone(),
                    operation.operation_class.clone(),
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        for (namespace, _) in &scopes {
            require_namespace_write_access(&self.db, &actor, namespace)?;
        }
        for (namespace, operation_class) in std::mem::take(&mut scopes) {
            input.kioku_evidence.extend(
                crate::chisei::gunshi::load_kioku_evidence(&self.db, &namespace, &operation_class)
                    .map_err(Status::internal)?,
            );
        }
        input
            .kioku_evidence
            .sort_by(|left, right| left.memory_id.cmp(&right.memory_id));
        input
            .kioku_evidence
            .dedup_by(|left, right| left.memory_id == right.memory_id);
        let request_digest = {
            use sha2::Digest;
            let input_json =
                serde_json::to_vec(&input).map_err(|error| Status::internal(error.to_string()))?;
            format!("{:x}", sha2::Sha256::digest(input_json))
        };
        let allocation = crate::chisei::gunshi::recommend_advisory(
            &input.request,
            &input.kioku_evidence,
            &input.advisory_policy,
        )
        .map_err(Status::failed_precondition)?;
        crate::chisei::gunshi_feedback::record_issued_recommendations(
            &self.db,
            &actor,
            &issuance_id,
            &request_digest,
            &allocation.plans,
            chrono::Utc::now().timestamp_millis(),
            input.request.capacity.captured_at_ms,
        )
        .map_err(Status::failed_precondition)?;
        let operations = input
            .request
            .operations
            .iter()
            .map(|operation| (operation.operation_id.as_str(), operation))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut auto_dispatch_authorization_json = Vec::with_capacity(allocation.plans.len());
        let mut receipt_attributes_json = Vec::with_capacity(allocation.plans.len());
        for plan in &allocation.plans {
            let operation = operations.get(plan.operation_id.as_str()).ok_or_else(|| {
                Status::internal("Gunshi allocation references an unknown operation")
            })?;
            let (mut authorization, mut attributes) =
                crate::chisei::gunshi_auto::authorize_namespace_auto_dispatch(
                    &self.db,
                    &plan.namespace,
                    plan,
                    operation,
                    &input.request.capacity,
                )
                .map_err(Status::failed_precondition)?;
            let data_class = self
                .policy
                .effective_policy(&plan.namespace)
                .map(|policy| policy.data_class)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unclassified".into());
            let provider = crate::llm::provider_name(&plan.selection.model);
            match self.policy.enforce_residency(
                &plan.namespace,
                provider,
                &plan.selection.model,
                &data_class,
            ) {
                Ok(decision) => {
                    attributes.extend(self.policy.residency_receipt_attributes(&decision));
                }
                Err(error) => {
                    authorization.authorized = false;
                    authorization.mode = crate::chisei::gunshi_dispatch::DispatchMode::AdvisoryOnly;
                    authorization.reasons.push(error);
                    attributes.insert("residency_allowed".into(), "false".into());
                    attributes.insert(
                        "residency_denial_reasons".into(),
                        authorization.reasons.last().cloned().unwrap_or_default(),
                    );
                }
            }
            auto_dispatch_authorization_json.push(
                serde_json::to_string(&authorization)
                    .map_err(|error| Status::internal(error.to_string()))?,
            );
            receipt_attributes_json.push(
                serde_json::to_string(&attributes)
                    .map_err(|error| Status::internal(error.to_string()))?,
            );
        }
        Ok(Response::new(IssueGunshiRecommendationsResponse {
            allocation_json: serde_json::to_string(&allocation)
                .map_err(|error| Status::internal(error.to_string()))?,
            issuance_id,
            auto_dispatch_authorization_json,
            receipt_attributes_json,
        }))
    }

    async fn set_gunshi_allocation_policy(
        &self,
        req: Request<SetGunshiAllocationPolicyRequest>,
    ) -> Result<Response<SetGunshiAllocationPolicyResponse>, Status> {
        let actor = authenticated_actor(&req);
        let input = req.into_inner();
        require_namespace_write_access(&self.db, &actor, &input.namespace)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let status = match input.operation.as_str() {
            "install" => {
                let snapshot = serde_json::from_str(&input.snapshot_json).map_err(|error| {
                    Status::invalid_argument(format!("invalid allocation snapshot: {error}"))
                })?;
                let gate = serde_json::from_str(&input.gate_json).map_err(|error| {
                    Status::invalid_argument(format!("invalid evaluation gate: {error}"))
                })?;
                let status = crate::chisei::gunshi_auto::install_baseline(
                    &self.db,
                    &actor,
                    &input.namespace,
                    snapshot,
                    gate,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?;
                serde_json::to_value(status).map_err(|error| Status::internal(error.to_string()))?
            }
            "promote" => {
                let candidate = serde_json::from_str(&input.candidate_json).map_err(|error| {
                    Status::invalid_argument(format!("invalid candidate snapshot: {error}"))
                })?;
                let baseline =
                    serde_json::from_str(&input.baseline_evaluation_json).map_err(|error| {
                        Status::invalid_argument(format!("invalid baseline evaluation: {error}"))
                    })?;
                let candidate_evaluation = serde_json::from_str(&input.candidate_evaluation_json)
                    .map_err(|error| {
                    Status::invalid_argument(format!("invalid candidate evaluation: {error}"))
                })?;
                let status = crate::chisei::gunshi_auto::promote(
                    &self.db,
                    crate::chisei::gunshi_auto::PromoteRequest {
                        actor,
                        namespace: input.namespace,
                        candidate,
                        baseline,
                        candidate_evaluation,
                        expected_revision: input.expected_revision,
                        now_ms,
                    },
                )
                .map_err(Status::failed_precondition)?;
                serde_json::to_value(status).map_err(|error| Status::internal(error.to_string()))?
            }
            "rollback" => serde_json::to_value(
                crate::chisei::gunshi_auto::rollback(
                    &self.db,
                    &actor,
                    &input.namespace,
                    &input.expected_revision,
                    &input.reason,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?,
            )
            .map_err(|error| Status::internal(error.to_string()))?,
            "auto_opt_in" => serde_json::to_value(
                crate::chisei::gunshi_auto::set_auto_opt_in(
                    &self.db,
                    &actor,
                    &input.namespace,
                    input.enabled,
                    &input.expected_revision,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?,
            )
            .map_err(|error| Status::internal(error.to_string()))?,
            "kill_switch" => serde_json::to_value(
                crate::chisei::gunshi_auto::set_kill_switch(
                    &self.db,
                    &actor,
                    &input.namespace,
                    input.enabled,
                    &input.reason,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?,
            )
            .map_err(|error| Status::internal(error.to_string()))?,
            "feedback" => {
                let plan: crate::chisei::gunshi::AllocationPlan =
                    serde_json::from_str(&input.allocation_json).map_err(|error| {
                        Status::invalid_argument(format!("invalid allocation plan: {error}"))
                    })?;
                if plan.namespace != input.namespace {
                    return Err(Status::invalid_argument(
                        "feedback allocation namespace does not match the policy namespace",
                    ));
                }
                let choice = serde_json::from_str(&input.choice_json).map_err(|error| {
                    Status::invalid_argument(format!("invalid operator choice: {error}"))
                })?;
                let outcome = (!input.outcome_json.trim().is_empty())
                    .then(|| serde_json::from_str(&input.outcome_json))
                    .transpose()
                    .map_err(|error| {
                        Status::invalid_argument(format!("invalid observed outcome: {error}"))
                    })?;
                serde_json::to_value(
                    crate::chisei::gunshi_feedback::record_feedback(
                        &self.db,
                        &actor,
                        &input.issuance_id,
                        &plan,
                        &choice,
                        outcome.as_ref(),
                    )
                    .map_err(Status::failed_precondition)?,
                )
                .map_err(|error| Status::internal(error.to_string()))?
            }
            "promote_feedback" => {
                let result = crate::chisei::gunshi_feedback_eval::promote_feedback_to_eval(
                    &self.db,
                    &actor,
                    &input.suite_id,
                    &input.issuance_id,
                    &input.allocation_id,
                    &input.namespace,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?;
                if let Err(error) = self.eval.put_suite(result.suite.clone())
                    && self.eval.get_suite(&result.suite_id).as_ref() != Some(&result.suite)
                {
                    tracing::warn!(
                        %error,
                        suite_id = %result.suite_id,
                        "eval store sync after feedback promotion"
                    );
                }
                serde_json::to_value(result).map_err(|error| Status::internal(error.to_string()))?
            }
            _ => {
                return Err(Status::invalid_argument(
                    "operation must be install, promote, rollback, auto_opt_in, kill_switch, feedback, or promote_feedback",
                ));
            }
        };
        Ok(Response::new(SetGunshiAllocationPolicyResponse {
            status_json: serde_json::to_string(&status)
                .map_err(|error| Status::internal(error.to_string()))?,
        }))
    }

    async fn get_gunshi_allocation_status(
        &self,
        req: Request<GetGunshiAllocationStatusRequest>,
    ) -> Result<Response<GetGunshiAllocationStatusResponse>, Status> {
        let actor = authenticated_actor(&req);
        let namespace = req.get_ref().namespace.clone();
        require_namespace_access(&self.db, &actor, &namespace)?;
        let status = crate::chisei::gunshi_auto::get_status(&self.db, &namespace)
            .map_err(Status::internal)?;
        let status_json = match status {
            Some(status) => serde_json::to_string(&status)
                .map_err(|error| Status::internal(error.to_string()))?,
            None => "{}".into(),
        };
        let scorecard = crate::chisei::gunshi_feedback::advisory_scorecard(&self.db, &namespace)
            .map_err(Status::internal)?;
        Ok(Response::new(GetGunshiAllocationStatusResponse {
            status_json,
            scorecard_json: serde_json::to_string(&scorecard)
                .map_err(|error| Status::internal(error.to_string()))?,
        }))
    }

    async fn review_kioku_memory(
        &self,
        req: Request<ReviewKiokuMemoryRequest>,
    ) -> Result<Response<ReviewKiokuMemoryResponse>, Status> {
        require_eval_admin(&req)?;
        let actor = authenticated_actor(&req);
        let request = req.into_inner();
        if request.memory_id.trim().is_empty() || request.memory_version == 0 {
            return Err(Status::invalid_argument(
                "memory id and version are required",
            ));
        }
        if request.action == "reassess" {
            if request.reassessment_key.trim().is_empty()
                || request.evidence_basis_json.is_empty()
                || request.evidence_basis_json.len() > 128
            {
                return Err(Status::invalid_argument(
                    "reassess requires a key and one to 128 evidence basis records",
                ));
            }
            let evidence_basis = request
                .evidence_basis_json
                .iter()
                .map(|json| {
                    serde_json::from_str::<crate::chisei::kioku::KiokuEvidenceBasis>(json).map_err(
                        |error| {
                            Status::invalid_argument(format!("invalid evidence basis: {error}"))
                        },
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let result = self
                .db
                .reassess_kioku_memory(crate::chisei::kioku::KiokuEvidenceReassessmentRequest {
                    memory_id: request.memory_id,
                    memory_version: request.memory_version,
                    reassessment_key: request.reassessment_key,
                    actor,
                    evidence_basis,
                    now_ms: chrono::Utc::now().timestamp_millis(),
                })
                .map_err(Status::failed_precondition)?;
            let lifecycle_events = self
                .db
                .list_kioku_lifecycle_events(&result.candidate.id, result.candidate.version)
                .map_err(Status::internal)?;
            return Ok(Response::new(ReviewKiokuMemoryResponse {
                memory_json: serde_json::to_string(&result.candidate)
                    .map_err(|error| Status::internal(error.to_string()))?,
                lifecycle_events_json: lifecycle_events
                    .iter()
                    .map(serde_json::to_string)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| Status::internal(error.to_string()))?,
                evidence_json: result
                    .evidence
                    .iter()
                    .map(serde_json::to_string)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| Status::internal(error.to_string()))?,
                idempotent: result.idempotent,
            }));
        }
        if request.rationale.trim().is_empty() {
            return Err(Status::invalid_argument("review rationale is required"));
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
            evidence_json: Vec::new(),
            idempotent: false,
        }))
    }

    async fn get_sample_observation(
        &self,
        req: Request<GetSampleObservationRequest>,
    ) -> Result<Response<GetSampleObservationResponse>, Status> {
        let actor = require_telemetry_reader(&req, &self.config)?;
        let request = req.into_inner();
        let request_id = request.request_id.as_str();
        let namespace = request.namespace.as_str();
        if request_id.trim().is_empty() {
            return Err(Status::invalid_argument("request_id required"));
        }
        if namespace.trim().is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        if !matches!(actor.as_str(), "root" | "local") {
            require_namespace_access(&self.db, &actor, namespace.trim())?;
        }
        let observation = self
            .db
            .get_sample_observation_in_namespace(request_id, namespace)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("sample observation not found"))?;
        let state = "recorded";
        Ok(Response::new(GetSampleObservationResponse {
            observation: Some(SampleObservationReadback {
                request_id: observation.request_id.clone(),
                namespace: observation.namespace.clone(),
                observation_digest: sample_observation_readback_digest(
                    &observation.request_id,
                    &observation.namespace,
                    state,
                    observation.timestamp,
                ),
                state: state.into(),
                observed_at: observation.timestamp,
                read_at: chrono::Utc::now().timestamp_millis(),
            }),
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
        if matches!(
            receipt.operation_class.as_str(),
            evaluation_execution_domain::EXECUTION_OPERATION_CLASS
        ) {
            return Err(Status::permission_denied(
                "evaluation authority receipts accept only internal events",
            ));
        }
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
        let trusted_kioku_outcome = kind == ReceiptEventKind::OutcomeRecorded
            && receipt_has_kioku_context
            && complete_kioku_outcome
            && trusted_outcome_reporter;
        let namespace_writer =
            require_namespace_write_access(&self.db, &actor, &receipt.namespace).is_ok();
        if actor != receipt.initiating_actor
            && actor != "root"
            && !namespace_writer
            && !trusted_kioku_outcome
        {
            return Err(Status::permission_denied(
                "operation event reporter lacks namespace write authority",
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

    async fn claim_gateway_dispatch(
        &self,
        req: Request<ClaimGatewayDispatchRequest>,
    ) -> Result<Response<ClaimGatewayDispatchResponse>, Status> {
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
                "gateway dispatch claim requires a gateway service principal",
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
        let reserved = self
            .db
            .reserve_gateway_request_alias(
                &request.caller_scope,
                &request.request_alias,
                &request.request_id,
                &request.operation_id,
            )
            .map_err(Status::internal)?;
        if !reserved {
            return Ok(Response::new(ClaimGatewayDispatchResponse {
                claimed: false,
            }));
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
        Ok(Response::new(ClaimGatewayDispatchResponse { claimed }))
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

    async fn put_evaluator_definition(
        &self,
        req: Request<PutEvaluatorDefinitionRequest>,
    ) -> Result<Response<PutEvaluatorDefinitionResponse>, Status> {
        require_eval_admin(&req)?;
        let actor = authenticated_actor(&req);
        let request = req.into_inner();
        if request.definition.is_none() {
            let definition = self
                .db
                .get_evaluator_definition(&request.definition_id)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::failed_precondition("evaluator definition not found"))?;
            require_namespace_write_access(&self.db, &actor, &definition.namespace)?;
            let availability = self
                .db
                .set_evaluator_availability(
                    &request.definition_id,
                    &request.availability_state,
                    &request.superseded_by_definition_id,
                    &request.reason,
                    &request.request_id,
                    &actor,
                    chrono::Utc::now().timestamp_millis(),
                )
                .map_err(map_evaluation_resource_error)?;
            let (implementation_executable, implementation_status) =
                self.evaluator_capability(&definition);
            return Ok(Response::new(PutEvaluatorDefinitionResponse {
                record: Some(evaluator_record_with_availability(
                    &definition,
                    &availability,
                    implementation_executable,
                    &implementation_status,
                )),
            }));
        }
        if !request.availability_state.is_empty() {
            return Err(Status::invalid_argument(
                "definition publication and availability transition are separate writes",
            ));
        }
        let definition = from_proto_evaluator_definition(request.definition.unwrap())?;
        require_namespace_write_access(&self.db, &actor, &definition.namespace)?;
        let definition = self
            .db
            .put_evaluator_definition(definition, &actor, chrono::Utc::now().timestamp_millis())
            .map_err(map_evaluation_resource_error)?;
        let (implementation_executable, implementation_status) =
            self.evaluator_capability(&definition);
        Ok(Response::new(PutEvaluatorDefinitionResponse {
            record: Some(evaluator_record(
                &self.db,
                &definition,
                implementation_executable,
                &implementation_status,
            )?),
        }))
    }

    async fn put_evaluation_plan(
        &self,
        req: Request<PutEvaluationPlanRequest>,
    ) -> Result<Response<PutEvaluationPlanResponse>, Status> {
        require_eval_admin(&req)?;
        let actor = authenticated_actor(&req);
        let plan = from_proto_evaluation_plan(
            req.into_inner()
                .plan
                .ok_or_else(|| Status::invalid_argument("evaluation plan required"))?,
        );
        require_namespace_write_access(&self.db, &actor, &plan.namespace)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let plan = evaluation_plan_domain::prepare_plan(plan, &actor, now_ms)
            .map_err(map_evaluation_resource_error)?;
        if let Some(existing) = self
            .db
            .get_evaluation_plan(&plan.plan_version_id)
            .map_err(Status::internal)?
        {
            if existing.content_digest != plan.content_digest {
                return Err(Status::already_exists(
                    "evaluation plan version already exists with different content",
                ));
            }
            if !evaluation_plan_visible(&self.db, &existing, &actor).map_err(Status::internal)? {
                return Err(Status::failed_precondition(
                    "governed invariant reference unavailable",
                ));
            }
            return Ok(Response::new(PutEvaluationPlanResponse {
                plan: Some(to_proto_evaluation_plan(&existing)),
            }));
        }
        validate_evaluation_plan_references(&self.db, &plan, &actor)?;
        let plan = self
            .db
            .put_evaluation_plan(plan, &actor, now_ms)
            .map_err(map_evaluation_resource_error)?;
        Ok(Response::new(PutEvaluationPlanResponse {
            plan: Some(to_proto_evaluation_plan(&plan)),
        }))
    }

    async fn resolve_evaluation_plan(
        &self,
        req: Request<ResolveEvaluationPlanRequest>,
    ) -> Result<Response<ResolveEvaluationPlanResponse>, Status> {
        let actor = authenticated_actor(&req);
        let request = from_proto_evaluation_resolution(
            req.into_inner()
                .resolution
                .ok_or_else(|| Status::invalid_argument("evaluation resolution required"))?,
        );
        let prepared = evaluation_manifest_domain::prepare_resolution_request(request, &actor)
            .map_err(map_evaluation_resource_error)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        if prepared.request.evaluation_time_ms > now_ms {
            return Err(Status::invalid_argument(
                "evaluation_time_ms cannot be in the future",
            ));
        }
        let outcome = self.resolve_evaluation_plan_internal(&prepared)?;
        Ok(Response::new(to_proto_evaluation_resolution(&outcome)))
    }

    async fn get_evaluation_gate_evidence(
        &self,
        req: Request<GetEvaluationGateEvidenceRequest>,
    ) -> Result<Response<GetEvaluationGateEvidenceResponse>, Status> {
        require_eval_reader(&req, &self.config)?;
        let request = req.into_inner();
        let suite_id = request.suite_id.trim();
        let release_digest = request.release_digest.trim();
        let artifact_digest = request.artifact_digest.trim();
        if suite_id.is_empty() {
            return Err(Status::invalid_argument("suite_id is required"));
        }
        if release_digest.is_empty() {
            return Err(Status::invalid_argument("release_digest is required"));
        }
        if artifact_digest.is_empty() {
            return Err(Status::invalid_argument("artifact_digest is required"));
        }
        if request.max_timestamp_ms <= 0 {
            return Err(Status::invalid_argument(
                "max_timestamp_ms must be positive",
            ));
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        if request.max_timestamp_ms > now_ms.saturating_add(EVALUATION_GATE_MAX_FUTURE_SKEW_MS) {
            return Err(Status::invalid_argument(
                "max_timestamp_ms is too far in the future",
            ));
        }

        let suite = self.eval.read_suite_for_gate(suite_id).map_err(|error| {
            Status::unavailable(format!("evaluation gate evidence unavailable: {error}"))
        })?;
        let Some(suite) = suite else {
            return Ok(Response::new(GetEvaluationGateEvidenceResponse {
                status: EVALUATION_GATE_STATUS_SUITE_NOT_FOUND.into(),
                evidence: None,
            }));
        };
        if suite.cases.len() > MAX_EVALUATION_GATE_CASES {
            return Err(Status::resource_exhausted(
                "evaluation suite exceeds the gate evidence case limit",
            ));
        }
        let expected_case_ids = suite
            .cases
            .iter()
            .map(|case| case.id.clone())
            .collect::<Vec<_>>();
        let mut seen_case_ids = BTreeSet::new();
        if expected_case_ids
            .iter()
            .any(|case_id| case_id.trim().is_empty() || !seen_case_ids.insert(case_id.clone()))
        {
            return Err(Status::failed_precondition(
                "evaluation suite has empty or duplicate case ids",
            ));
        }

        let suite_digest = evaluation_gate_suite_digest(&suite);
        let expected_config_ref =
            evaluation_gate_config_ref(release_digest, artifact_digest, &suite_digest);
        let run = self
            .eval
            .read_latest_run_for_gate(suite_id, &expected_config_ref, request.max_timestamp_ms)
            .map_err(|error| {
                Status::unavailable(format!("evaluation gate evidence unavailable: {error}"))
            })?;
        let Some(run) = run else {
            return Ok(Response::new(GetEvaluationGateEvidenceResponse {
                status: EVALUATION_GATE_STATUS_NO_MATCHING_RUN.into(),
                evidence: None,
            }));
        };
        if run.results.len() > MAX_EVALUATION_GATE_RESULTS {
            return Err(Status::resource_exhausted(
                "evaluation run exceeds the gate evidence result limit",
            ));
        }
        let actual_case_ids = run
            .results
            .iter()
            .map(|result| result.case_id.as_str())
            .collect::<BTreeSet<_>>();
        let expected_case_ids_set = expected_case_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if actual_case_ids.len() != run.results.len() || actual_case_ids != expected_case_ids_set {
            return Err(Status::failed_precondition(
                "selected evaluation run does not contain exactly one result for every suite case",
            ));
        }

        Ok(Response::new(GetEvaluationGateEvidenceResponse {
            status: EVALUATION_GATE_STATUS_FOUND.into(),
            evidence: Some(EvaluationGateEvidence {
                suite_id: suite.id,
                release_digest: release_digest.into(),
                artifact_digest: artifact_digest.into(),
                suite_digest,
                config_ref: expected_config_ref,
                run_id: run.id,
                run_timestamp: run.timestamp,
                expected_case_ids,
                results: run
                    .results
                    .into_iter()
                    .map(|result| EvaluationGateCaseResult {
                        case_id: result.case_id,
                        passed: result.passed,
                    })
                    .collect(),
            }),
        }))
    }

    async fn run_lookup_first_promotion_gate(
        &self,
        req: Request<RunLookupFirstPromotionGateRequest>,
    ) -> Result<Response<RunLookupFirstPromotionGateResponse>, Status> {
        let actor = required_lookup_promotion_admin(&req)?;
        let request = req.into_inner();
        if request.contract_version != lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION {
            return Err(Status::invalid_argument(format!(
                "lookup promotion gate contract must be {}",
                lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION
            )));
        }
        let namespace = canonical_namespace(&request.namespace)?;
        require_namespace_access(&self.db, &actor, namespace)?;
        if request.suite_json.len() > lookup_first::LOOKUP_FIRST_GATE_MAX_SUITE_BYTES {
            return Err(Status::resource_exhausted(format!(
                "lookup promotion suite exceeds {} bytes",
                lookup_first::LOOKUP_FIRST_GATE_MAX_SUITE_BYTES
            )));
        }
        let suite = lookup_first::parse_lookup_promotion_gate_suite(&request.suite_json)
            .map_err(Status::invalid_argument)?;
        if suite.namespace != namespace {
            return Err(Status::invalid_argument(
                "lookup promotion suite namespace does not match request namespace",
            ));
        }
        for case in &suite.cases {
            require_namespace_access(&self.db, &case.actor, namespace)?;
        }

        let mut report = lookup_first::run_lookup_promotion_gate(&suite, &self.db)
            .map_err(Status::failed_precondition)?;
        let decision_id = lookup_first::record_lookup_promotion_gate(&self.db, &actor, &report)
            .map_err(Status::internal)?;
        report.audit_decision_id = decision_id;

        Ok(Response::new(RunLookupFirstPromotionGateResponse {
            report: Some(LookupFirstPromotionGateReport {
                contract_version: report.contract_version,
                suite_id: report.suite_id,
                namespace: report.namespace,
                suite_digest: report.suite_digest,
                audit_decision_id: report.audit_decision_id,
                verdict: report.verdict,
                lookup_hits: report.lookup_hits,
                model_path: report.model_path,
                lookup_refusals: report.lookup_refusals,
                passed: report.passed,
                failed: report.failed,
                cases: report
                    .cases
                    .into_iter()
                    .map(|case| LookupFirstPromotionGateCaseResult {
                        id: case.id,
                        answer_path: case.answer_path,
                        lookup_refusal: case.lookup_refusal.unwrap_or_default(),
                        passed: case.passed,
                        detail: case.detail.unwrap_or_default(),
                    })
                    .collect(),
            }),
        }))
    }

    async fn execute_evaluation_manifest(
        &self,
        req: Request<ExecuteEvaluationManifestRequest>,
    ) -> Result<Response<ExecuteEvaluationManifestResponse>, Status> {
        let actor = authenticated_actor(&req);
        let request = evaluation_execution_domain::prepare_execution_request(
            from_proto_evaluation_execution(
                req.into_inner()
                    .execution
                    .ok_or_else(|| Status::invalid_argument("evaluation execution required"))?,
            ),
        )
        .map_err(map_evaluation_resource_error)?;
        require_namespace_write_access(&self.db, &actor, &request.namespace)?;
        let manifest = self
            .db
            .get_evaluation_manifest(&request.manifest_digest)
            .map_err(Status::internal)?
            .filter(|manifest| manifest.namespace == request.namespace)
            .ok_or_else(|| Status::not_found("evaluation manifest not found"))?;
        let projection = self
            .execute_evaluation_manifest_internal(&manifest, &actor, request.max_total_duration_ms)
            .await?;
        Ok(Response::new(ExecuteEvaluationManifestResponse {
            execution: Some(to_proto_evaluation_execution_projection(&projection)),
        }))
    }

    async fn cancel_evaluation_execution(
        &self,
        req: Request<CancelEvaluationExecutionRequest>,
    ) -> Result<Response<CancelEvaluationExecutionResponse>, Status> {
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
        require_namespace_write_access(&self.db, &actor, &validated.namespace)?;
        let manifest = self
            .db
            .get_evaluation_manifest(&validated.manifest_digest)
            .map_err(Status::internal)?
            .filter(|manifest| manifest.namespace == validated.namespace)
            .ok_or_else(|| Status::not_found("evaluation execution not found"))?;
        let index = self
            .db
            .get_evaluation_execution_index(&validated.manifest_digest)
            .map_err(Status::internal)?
            .filter(|index| index.namespace == validated.namespace)
            .ok_or_else(|| Status::not_found("evaluation execution not found"))?;
        let cancelled = {
            let mut cancellations = self
                .evaluation_cancellations
                .lock()
                .map_err(|_| Status::internal("evaluation cancellation lock poisoned"))?;
            let cancelled = cancellations
                .entry(manifest.manifest_digest.clone())
                .or_insert_with(|| Arc::new(AtomicBool::new(false)))
                .clone();
            cancelled.store(true, Ordering::Release);
            cancelled
        };
        let receipt = self
            .db
            .get_operation_receipt(&index.operation_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
        let max_total_duration_ms = evaluation_total_budget_ms(&receipt)?;
        if receipt.completed_at_ms.is_none() && !evaluation_cancellation_requested(&receipt) {
            self.request_evaluation_cancellation(&index, &receipt, &actor)?;
        }
        let execution_lock = {
            let mut locks = self
                .evaluation_execution_locks
                .lock()
                .map_err(|_| Status::internal("evaluation execution lock poisoned"))?;
            locks
                .entry(manifest.manifest_digest.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        let _guard = execution_lock.lock().await;
        let worker_db = self.db.clone();
        let worker_budget = self.budget.clone();
        let worker_registry = self.evaluator_registry.clone();
        let worker_stochastic_registry = self.stochastic_evaluator_registry.clone();
        let stochastic_egress_reasons = BTreeMap::new();
        let worker_manifest = manifest.clone();
        let worker_index = index.clone();
        let projection = tokio::task::spawn_blocking(move || {
            Self::run_evaluation_execution(
                &worker_db,
                EvaluationExecutionRuntime {
                    deterministic_registry: &worker_registry,
                    stochastic_registry: &worker_stochastic_registry,
                    stochastic_egress_reasons: &stochastic_egress_reasons,
                    budget: &worker_budget,
                },
                &worker_manifest,
                &worker_index,
                max_total_duration_ms,
                cancelled,
            )
        })
        .await
        .map_err(|error| Status::internal(format!("evaluation worker failed: {error}")))??;
        if projection.decision.is_some() {
            self.evaluation_cancellations
                .lock()
                .map_err(|_| Status::internal("evaluation cancellation lock poisoned"))?
                .remove(&manifest.manifest_digest);
            let mut locks = self
                .evaluation_execution_locks
                .lock()
                .map_err(|_| Status::internal("evaluation execution lock poisoned"))?;
            if locks
                .get(&manifest.manifest_digest)
                .is_some_and(|lock| Arc::ptr_eq(lock, &execution_lock))
            {
                locks.remove(&manifest.manifest_digest);
            }
        }
        Ok(Response::new(CancelEvaluationExecutionResponse {
            execution: Some(to_proto_evaluation_execution_projection(&projection)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_execution::{
        DeterministicEvaluator, DeterministicEvaluatorOutput, EVALUATOR_RESULT_CONTRACT,
        STATUS_PASS,
    };
    use crate::domain::Object;
    use crate::sekai::security::{Grant, Role};
    use axum::body::Body;
    use axum::extract::State;
    use axum::response::Response as AxumResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn user_message(content: &str) -> ChatMessage {
        ChatMessage {
            role: "user".into(),
            content: content.into(),
            ..Default::default()
        }
    }

    #[test]
    fn prepared_messages_deliver_a_non_empty_spec_exactly_once() {
        let input = ExecutionInput {
            spec: "original task".into(),
            ..Default::default()
        };
        assert_eq!(
            build_prepared_messages(&input, "original task"),
            vec![user_message("original task")]
        );
        assert_eq!(
            build_prepared_messages(&input, "enriched task"),
            vec![user_message("enriched task")]
        );

        let input = ExecutionInput {
            spec: "original task".into(),
            messages: vec![user_message("conversation context")],
            ..Default::default()
        };
        assert_eq!(
            build_prepared_messages(&input, "original task"),
            vec![
                user_message("conversation context"),
                user_message("[Task spec]\noriginal task"),
            ]
        );
        assert_eq!(
            build_prepared_messages(&input, "enriched task"),
            vec![
                user_message("conversation context"),
                user_message("[Task spec]\nenriched task"),
            ]
        );
        assert_eq!(
            build_prepared_messages(&input, ""),
            vec![
                user_message("conversation context"),
                user_message("[Task spec]\noriginal task"),
            ]
        );
    }

    #[test]
    fn prepared_spec_preserves_pending_tool_call_order() {
        let assistant_message = ChatMessage {
            role: "assistant".into(),
            tool_calls: vec![ToolCall {
                id: "call-1".into(),
                name: "lookup".into(),
                args_json: r#"{"value":1}"#.into(),
            }],
            ..Default::default()
        };
        let input = ExecutionInput {
            spec: "original task".into(),
            messages: vec![assistant_message.clone()],
            ..Default::default()
        };

        assert_eq!(
            build_prepared_messages(&input, "original task"),
            vec![
                user_message("[Task spec]\noriginal task"),
                assistant_message
            ]
        );
    }

    #[test]
    fn prepared_messages_do_not_add_an_empty_spec_message() {
        let input = ExecutionInput {
            messages: vec![user_message("conversation context")],
            ..Default::default()
        };

        assert_eq!(
            build_prepared_messages(&input, ""),
            vec![user_message("conversation context")]
        );
    }

    #[tokio::test]
    async fn gunshi_issuance_rejects_an_empty_authorization_scope() {
        let svc = memory_service();
        let input = serde_json::json!({
            "contract_version": crate::chisei::gunshi::RECOMMENDATION_INPUT_VERSION,
            "request": {
                "capacity": {
                    "captured_at_ms": 1,
                    "policy_version": "policy",
                    "agents": [],
                    "model_profiles": [],
                    "budget_remaining_usd_micros": 0,
                    "max_parallel_attempts": 0,
                    "human_attention_minutes": 0
                },
                "operations": [],
                "strategy": {
                    "strategy_id": "baseline",
                    "version": "1",
                    "baseline": "conservative"
                }
            },
            "advisory_policy": {
                "max_memory_age_ms": 0,
                "min_score": 0.0,
                "max_evidence_references": 1
            },
            "kioku_evidence": []
        });
        let mut request = Request::new(IssueGunshiRecommendationsRequest {
            input_json: input.to_string(),
            issuance_id: "empty-scope".into(),
        });
        request
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());

        let error = svc.issue_gunshi_recommendations(request).await.unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            svc.db
                .list_decisions(&Default::default())
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn gunshi_issuance_returns_aligned_dispatch_decisions() {
        let svc = memory_service();
        let input = serde_json::json!({
            "contract_version": crate::chisei::gunshi::RECOMMENDATION_INPUT_VERSION,
            "request": {
                "capacity": {
                    "captured_at_ms": 2_000,
                    "policy_version": "policy-v1",
                    "agents": [{
                        "agent_id": "agent-a",
                        "runtime": "native",
                        "models": ["native-default"],
                        "tools": ["search"],
                        "operation_classes": ["triage"],
                        "available_slots": 1,
                        "healthy": true
                    }],
                    "model_profiles": [{
                        "model": "native-default",
                        "quality": 0.9,
                        "cost_per_attempt_usd_micros": 20,
                        "latency_ms": 30,
                        "uncertainty": 0.1
                    }],
                    "budget_remaining_usd_micros": 40,
                    "max_parallel_attempts": 1,
                    "human_attention_minutes": 5
                },
                "operations": [{
                    "operation_id": "op-1",
                    "namespace": "support",
                    "operation_class": "triage",
                    "priority": 10,
                    "risk": "low",
                    "submitted_at_ms": 1_000,
                    "required_tools": ["search"],
                    "allowed_models": ["native-default"],
                    "max_attempts": 1,
                    "budget_ceiling_usd_micros": 40,
                    "acceptance_criteria": ["classified"],
                    "approval_required": false,
                    "human_attention_minutes_required": 0
                }],
                "strategy": {
                    "strategy_id": "priority",
                    "version": "1",
                    "baseline": "priority_first"
                }
            },
            "advisory_policy": {
                "max_memory_age_ms": 2_000,
                "min_score": 0.5,
                "max_evidence_references": 4
            },
            "kioku_evidence": []
        });

        let response = svc
            .issue_gunshi_recommendations(Request::new(IssueGunshiRecommendationsRequest {
                input_json: input.to_string(),
                issuance_id: "aligned-dispatch".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        let allocation: crate::chisei::gunshi::BaselineAllocation =
            serde_json::from_str(&response.allocation_json).unwrap();

        assert_eq!(allocation.plans.len(), 1);
        assert_eq!(response.auto_dispatch_authorization_json.len(), 1);
        assert_eq!(response.receipt_attributes_json.len(), 1);
        let authorization: crate::chisei::gunshi_dispatch::DispatchAuthorization =
            serde_json::from_str(&response.auto_dispatch_authorization_json[0]).unwrap();
        assert!(!authorization.authorized);
        assert_eq!(authorization.operation_id, "op-1");
    }

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
        let pricing = crate::pricing::parse_pricing_table("gpt-5.5=3:15").unwrap();
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
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
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
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
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
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let svc = ChiseiServiceImpl::new(db, config(":memory:"));

        let error = svc
            .resolve_live_model(
                "bogus/model",
                None,
                None,
                false,
                &std::collections::HashSet::new(),
                None,
            )
            .await
            .unwrap_err();

        assert!(error.contains("unknown provider namespace"));
    }

    #[tokio::test]
    async fn resolve_policy_normalizes_loaded_legacy_native_runtime() {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
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
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
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
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
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
        create_suite(&svc, "proj");
        for (id, score, timestamp) in [("class-run-1", 95, 100), ("class-run-2", 50, 200)] {
            seed_eval_run(&svc, eval_run(id, "suite-1", score, timestamp), "proj", id);
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
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
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
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
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
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
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
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
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
            permit_signing_key: Some("07".repeat(32)),
            permit_issuer: "issuer:test".into(),
            permit_key_id: "key-1".into(),
            governed_subject_provenance_signing_key: Some("09".repeat(32)),
            governed_subject_provenance_key_not_before_ms: 0,
            governed_subject_provenance_key_expires_at_ms: i64::MAX,
            governed_subject_provenance_ttl_ms: 24 * 60 * 60 * 1_000,
            site_id: "local".into(),
            budget_topology: Default::default(),
        }
    }

    fn stochastic_admission_manifest(
        provider: &str,
        egress_policy: &str,
        max_total_tokens: u32,
    ) -> evaluation_manifest_domain::ResolvedEvaluationManifest {
        let digest = |byte: char| format!("sha256:{}", byte.to_string().repeat(64));
        evaluation_manifest_domain::ResolvedEvaluationManifest {
            contract_version: evaluation_manifest_domain::MANIFEST_CONTRACT.into(),
            resolver_version: evaluation_manifest_domain::RESOLVER_VERSION.into(),
            manifest_id: "manifest:stochastic-admission".into(),
            manifest_digest: digest('a'),
            namespace: "acme".into(),
            plan_version_id: "plan:stochastic-admission".into(),
            plan_digest: digest('b'),
            subject_profile: "document/v1".into(),
            subject_identity: "document:42".into(),
            subject_content_digest: digest('c'),
            invariant_set_id: "set:stochastic-admission".into(),
            invariant_set_digest: digest('d'),
            invariant_profile_digest: digest('e'),
            evaluation_time_ms: 1,
            resolved_by: "operator".into(),
            requirements: vec![],
            nodes: vec![evaluation_manifest_domain::ResolvedEvaluationNode {
                node_id: "model-review".into(),
                evaluator: evaluation_manifest_domain::ResolvedEvaluatorBinding {
                    definition_id: "definition:model-review".into(),
                    definition_digest: digest('f'),
                    implementation_digest: digest('1'),
                    stochastic_policy: Some(evaluation_plan_domain::StochasticEvaluatorPolicy {
                        provider: provider.into(),
                        model: format!("{provider}/fixture"),
                        prompt_profile: "chisei.fixture/v1".into(),
                        prompt_profile_digest: digest('2'),
                        result_schema: "chisei.stochastic-trial-result/v1".into(),
                        trial_count: 2,
                        temperature_millis: 200,
                        top_p_millionths: 900_000,
                        seed_supported: provider != "anthropic",
                        base_seed: if provider == "anthropic" { 0 } else { 7 },
                        aggregation_rule:
                            evaluation_plan_domain::STOCHASTIC_AGGREGATION_MEAN_VARIANCE.into(),
                        minimum_mean_score_micros: 0,
                        minimum_pass_rate_basis_points: 0,
                        maximum_score_variance_micros_squared: 1_000_000_000_000,
                        gate_eligible: false,
                        max_retries_per_trial: 0,
                        max_tokens_per_trial: 1,
                        max_total_tokens,
                        egress_policy: egress_policy.into(),
                        raw_response_retention:
                            evaluation_plan_domain::STOCHASTIC_RAW_RETENTION_NONE.into(),
                    }),
                },
                depends_on_node_ids: vec![],
                input_bindings: vec![],
                parameters_json: "{}".into(),
                invariants: vec![],
                evidence_object_ids: vec![],
                classification: evaluation_plan_domain::NODE_ADVISORY.into(),
            }],
            evidence: vec![],
            waivers: vec![],
            created_at_ms: 1,
        }
    }

    #[test]
    fn stochastic_admission_fails_closed_before_external_or_unbudgetable_calls() {
        let svc = memory_service();
        let denied = stochastic_admission_manifest(
            "openai",
            evaluation_plan_domain::STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL,
            2,
        );
        assert_eq!(
            svc.stochastic_egress_reasons(&denied)
                .get("model-review")
                .map(String::as_str),
            Some(evaluation_execution_domain::REASON_STOCHASTIC_EGRESS_DENIED)
        );

        let mut allowed_config = config(":memory:");
        allowed_config.safe_egress_providers = vec!["openai".into()];
        let allowed = ChiseiServiceImpl::new(svc.db.clone(), allowed_config);
        let unbudgetable = stochastic_admission_manifest(
            "openai",
            evaluation_plan_domain::STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL,
            u32::MAX,
        );
        assert_eq!(
            ChiseiServiceImpl::stochastic_budget_reason(
                &allowed.budget,
                &unbudgetable,
                &unbudgetable.nodes[0],
            )
            .as_deref(),
            Some(evaluation_execution_domain::REASON_STOCHASTIC_TOKEN_BUDGET)
        );
    }

    fn memory_service() -> ChiseiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        ChiseiServiceImpl::new(db, config(":memory:"))
    }

    fn gunshi_planning_service() -> ChiseiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let mut config = config(":memory:");
        config.gateway_provided_providers = vec!["openai".into()];
        ChiseiServiceImpl::new(db, config)
    }

    fn issue_native_gunshi_plan(
        service: &ChiseiServiceImpl,
        issuance_id: &str,
        policy_version: &str,
    ) -> crate::chisei::gunshi::AllocationPlan {
        use crate::chisei::gunshi::{
            AgentCapacity, AllocationRequest, BaselineStrategy, CapacityEnvelope, ModelProfile,
            OperationRisk, PendingOperation, Strategy,
        };

        let plan = crate::chisei::gunshi::recommend_baseline(&AllocationRequest {
            capacity: CapacityEnvelope {
                captured_at_ms: 1,
                policy_version: policy_version.into(),
                agents: vec![AgentCapacity {
                    agent_id: "agent:local".into(),
                    runtime: "openai".into(),
                    models: BTreeSet::from(["openai/gpt-5.5".into()]),
                    tools: BTreeSet::new(),
                    operation_classes: BTreeSet::from(["triage".into()]),
                    available_slots: 1,
                    healthy: true,
                }],
                model_profiles: vec![ModelProfile {
                    model: "openai/gpt-5.5".into(),
                    quality: 0.8,
                    cost_per_attempt_usd_micros: 10,
                    latency_ms: 20,
                    uncertainty: 0.1,
                }],
                budget_remaining_usd_micros: 10,
                max_parallel_attempts: 1,
                human_attention_minutes: 1,
            },
            operations: vec![PendingOperation {
                operation_id: "operation:triage-1".into(),
                namespace: "support".into(),
                operation_class: "triage".into(),
                priority: 7,
                risk: OperationRisk::Low,
                submitted_at_ms: 1,
                required_tools: BTreeSet::new(),
                allowed_models: BTreeSet::new(),
                max_attempts: 1,
                budget_ceiling_usd_micros: 10,
                acceptance_criteria: vec!["receipt is complete".into()],
                approval_required: false,
                human_attention_minutes_required: 0,
            }],
            strategy: Strategy {
                strategy_id: "baseline".into(),
                version: "1".into(),
                baseline: BaselineStrategy::Conservative,
            },
        })
        .unwrap()
        .plans
        .remove(0);
        crate::chisei::gunshi_feedback::record_issued_recommendations(
            &service.db,
            "local",
            issuance_id,
            "request-digest",
            std::slice::from_ref(&plan),
            1,
            1,
        )
        .unwrap();
        plan
    }

    fn gunshi_plan_request(
        issuance_id: &str,
        plan: &crate::chisei::gunshi::AllocationPlan,
    ) -> PlanExecutionRequest {
        PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "request:triage-1".into(),
                namespace: plan.namespace.clone(),
                spec: "Triage the governed operation.".into(),
                max_tokens: 64,
                ..Default::default()
            }),
            gunshi_allocation: Some(GunshiAllocationBinding {
                issuance_id: issuance_id.into(),
                allocation_json: serde_json::to_string(plan).unwrap(),
            }),
        }
    }

    #[tokio::test]
    async fn issued_gunshi_allocation_feeds_native_planning_before_kioku_enrichment() {
        let service = gunshi_planning_service();
        let policy = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["openai/gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "openai/gpt-5.5".into(),
            data_class: String::new(),
        };
        let policy_version = policy.version();
        service.policy.set_namespace_policy("support", policy);
        let allocation = issue_native_gunshi_plan(&service, "issuance:triage-1", &policy_version);

        let plan = service
            .plan_execution(Request::new(gunshi_plan_request(
                "issuance:triage-1",
                &allocation,
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        assert_eq!(plan.resolved_runtime, allocation.selection.runtime);
        assert_eq!(plan.resolved_model, allocation.selection.model);
        assert_eq!(plan.gunshi_issuance_id, "issuance:triage-1");
        assert_eq!(plan.gunshi_allocation_id, allocation.allocation_id);
        assert_eq!(plan.gunshi_agent_id, allocation.selection.agent_id);
        assert_eq!(plan.gunshi_policy_version, policy_version);
        assert_eq!(plan.gunshi_input_fingerprint, allocation.input_fingerprint);
        assert_eq!(plan.gunshi_budget_ceiling_usd_micros, 10);
        assert_eq!(plan.gunshi_max_attempts, 1);
        assert!(plan.steps.iter().any(|step| step.step == "kioku_enrich"));
        let input = plan.input.as_ref().unwrap();
        assert_eq!(input.logical_operation_id, allocation.operation_id);
        assert_eq!(input.task_class, allocation.operation_class);
        assert_eq!(input.priority, i32::from(allocation.priority));

        let receipt = service
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .unwrap();
        let intent = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .unwrap();
        assert_eq!(
            intent.attributes.get("logical_operation_id"),
            Some(&allocation.operation_id)
        );
        assert_eq!(
            intent.attributes.get("gunshi_allocation_id"),
            Some(&allocation.allocation_id)
        );
        let budget = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::BudgetDecided)
            .unwrap();
        assert_eq!(
            budget
                .attributes
                .get("gunshi_budget_ceiling_usd_micros")
                .map(String::as_str),
            Some("10")
        );
    }

    #[tokio::test]
    async fn gunshi_binding_rejects_a_modified_issued_allocation() {
        let service = gunshi_planning_service();
        let policy = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["openai/gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "openai/gpt-5.5".into(),
            data_class: String::new(),
        };
        let policy_version = policy.version();
        service.policy.set_namespace_policy("support", policy);
        let issued = issue_native_gunshi_plan(&service, "issuance:tamper", &policy_version);
        let mut modified = issued.clone();
        modified.selection.agent_id = "agent:forged".into();

        let error = service
            .plan_execution(Request::new(gunshi_plan_request(
                "issuance:tamper",
                &modified,
            )))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("does not match"));
    }

    #[tokio::test]
    async fn gunshi_binding_rejects_an_allocation_after_policy_changes() {
        let service = gunshi_planning_service();
        let policy = crate::chisei::policy::Policy {
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["openai/gpt-5.5".into()],
            default_runtime: "openai".into(),
            default_model: "openai/gpt-5.5".into(),
            data_class: String::new(),
        };
        let policy_version = policy.version();
        service.policy.set_namespace_policy("support", policy);
        let allocation = issue_native_gunshi_plan(&service, "issuance:stale", &policy_version);
        service.policy.set_namespace_policy(
            "support",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["openai/gpt-5.5".into()],
                default_runtime: "openai".into(),
                default_model: "openai/gpt-5.5".into(),
                data_class: "internal".into(),
            },
        );

        let error = service
            .plan_execution(Request::new(gunshi_plan_request(
                "issuance:stale",
                &allocation,
            )))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("policy version"));
    }

    struct ManagedExecutionExtension;

    impl crate::enterprise::EnterpriseExtension for ManagedExecutionExtension {
        fn authenticate_bearer(
            &self,
            _bearer_token: &str,
        ) -> Result<crate::enterprise::AuthenticatedPrincipal, crate::enterprise::ExtensionError>
        {
            Err(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn authenticate_context(
            &self,
            _bearer_token: &str,
        ) -> Result<crate::enterprise::AuthenticatedContext, crate::enterprise::ExtensionError>
        {
            Err(crate::enterprise::ExtensionError::CredentialNotFound)
        }

        fn tenant_context(
            &self,
            _principal: &crate::enterprise::AuthenticatedPrincipal,
        ) -> Result<crate::enterprise::TenantContext, crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::Unauthenticated)
        }

        fn authorize_namespace(
            &self,
            _context: &crate::enterprise::TenantContext,
            _namespace: &str,
            _action: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::PermissionDenied)
        }

        fn authorize_unscoped_namespace(
            &self,
            _principal: &crate::enterprise::AuthenticatedPrincipal,
            _namespace: &str,
            _action: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            Err(crate::enterprise::ExtensionError::PermissionDenied)
        }

        fn authorize_authenticated_context(
            &self,
            context: &crate::enterprise::AuthenticatedContext,
            namespace: &str,
            _action: crate::enterprise::NamespaceAction,
        ) -> Result<(), crate::enterprise::ExtensionError> {
            context.validate(
                chrono::Utc::now().timestamp(),
                "https://issuer.test",
                "sekai:control-plane",
            )?;
            if context.credential_kind != crate::enterprise::CredentialKind::Machine
                || context
                    .tenant
                    .as_ref()
                    .is_none_or(|tenant| !tenant.tenant_id.starts_with("tenant-managed"))
                || namespace != "managed-conformance"
            {
                return Err(crate::enterprise::ExtensionError::PermissionDenied);
            }
            Ok(())
        }
    }

    fn managed_execution_context(
        scopes: Vec<String>,
        resource: &str,
        expires_at: i64,
    ) -> crate::enterprise::AuthenticatedContext {
        managed_execution_context_for_tenant(scopes, resource, expires_at, "tenant-managed")
    }

    fn managed_execution_context_for_tenant(
        scopes: Vec<String>,
        resource: &str,
        expires_at: i64,
        tenant_id: &str,
    ) -> crate::enterprise::AuthenticatedContext {
        crate::enterprise::AuthenticatedContext {
            contract_version: crate::enterprise::IDENTITY_EXTENSION_VERSION,
            principal: crate::enterprise::AuthenticatedPrincipal {
                subject: "service:managed-shikigami".into(),
                credential_id: "credential:managed-shikigami".into(),
            },
            credential_kind: crate::enterprise::CredentialKind::Machine,
            tenant: Some(crate::enterprise::TenantContext {
                tenant_id: tenant_id.into(),
                subject: "service:managed-shikigami".into(),
            }),
            scopes,
            issuer: "https://issuer.test".into(),
            resource: resource.into(),
            expires_at,
        }
    }

    fn attach_managed_context<T>(
        request: &mut Request<T>,
        context: crate::enterprise::AuthenticatedContext,
    ) {
        request.metadata_mut().insert(
            AUTH_SOURCE_HEADER,
            tonic::metadata::MetadataValue::from_static("enterprise"),
        );
        request.extensions_mut().insert(context);
    }

    fn managed_execution_service() -> ChiseiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(ManagedExecutionExtension)),
            )
            .unwrap(),
        )));
        let mut managed_config = config(":memory:");
        managed_config.openai_api_key = Some("synthetic-server-side-key".into());
        let service = ChiseiServiceImpl::new(db, managed_config);
        service.policy.set_namespace_policy(
            "managed-conformance",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["openai/gpt-5.5".into()],
                default_runtime: "openai".into(),
                default_model: "openai/gpt-5.5".into(),
                data_class: "unclassified".into(),
            },
        );
        service
    }

    fn managed_plan_request(request_id: &str) -> PlanExecutionRequest {
        PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: request_id.into(),
                namespace: "managed-conformance".into(),
                spec: "Use the governed tool loop.".into(),
                max_tokens: 64,
                tools: vec![ToolDef {
                    name: "read".into(),
                    description: "Read a synthetic fixture.".into(),
                    input_schema_json: r#"{"type":"object"}"#.into(),
                }],
                ..Default::default()
            }),
            gunshi_allocation: None,
        }
    }

    #[tokio::test]
    async fn managed_machine_context_owns_plan_identity_and_namespace_authority() {
        let service = managed_execution_service();
        let mut valid = Request::new(managed_plan_request("managed-plan-valid"));
        valid
            .metadata_mut()
            .insert("x-principal", "attacker".parse().unwrap());
        attach_managed_context(
            &mut valid,
            managed_execution_context(
                vec!["chisei.execute".into()],
                "sekai:control-plane",
                i64::MAX,
            ),
        );

        let plan = service
            .plan_execution(valid)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert_eq!(plan.planning_actor, "service:managed-shikigami");
        assert_eq!(plan.resolved_runtime, "openai");
        assert_eq!(plan.resolved_model, "openai/gpt-5.5");
        assert!(plan.input.unwrap().route_override.is_empty());

        let mut injected_route = managed_plan_request("managed-plan-route-injection");
        injected_route.input.as_mut().unwrap().route_override = "openai/gpt-5.5".into();
        let mut injected_route = Request::new(injected_route);
        attach_managed_context(
            &mut injected_route,
            managed_execution_context(
                vec!["chisei.execute".into()],
                "sekai:control-plane",
                i64::MAX,
            ),
        );
        assert_eq!(
            service
                .plan_execution(injected_route)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );

        for (request_id, context, expected_code) in [
            (
                "managed-plan-missing-scope",
                managed_execution_context(Vec::new(), "sekai:control-plane", i64::MAX),
                tonic::Code::PermissionDenied,
            ),
            (
                "managed-plan-wrong-resource",
                managed_execution_context(
                    vec!["chisei.execute".into()],
                    "sekai:other-plane",
                    i64::MAX,
                ),
                tonic::Code::Unauthenticated,
            ),
            (
                "managed-plan-expired",
                managed_execution_context(
                    vec!["chisei.execute".into()],
                    "sekai:control-plane",
                    chrono::Utc::now().timestamp() - 1,
                ),
                tonic::Code::Unauthenticated,
            ),
        ] {
            let receipts_before = service
                .db
                .list_operation_receipts_in_window("managed-conformance", 0, i64::MAX, 100)
                .unwrap()
                .len();
            let mut denied = Request::new(managed_plan_request(request_id));
            attach_managed_context(&mut denied, context);
            assert_eq!(
                service.plan_execution(denied).await.unwrap_err().code(),
                expected_code
            );
            assert_eq!(
                service
                    .db
                    .list_operation_receipts_in_window("managed-conformance", 0, i64::MAX, 100,)
                    .unwrap()
                    .len(),
                receipts_before,
                "denied request created a receipt",
            );
        }
    }

    #[tokio::test]
    async fn managed_context_without_enterprise_extension_fails_closed() {
        let service = memory_service();
        let mut request = Request::new(managed_plan_request("managed-context-without-extension"));
        attach_managed_context(
            &mut request,
            managed_execution_context(
                vec!["chisei.execute".into()],
                "sekai:control-plane",
                i64::MAX,
            ),
        );

        assert_eq!(
            service.plan_execution(request).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }

    #[test]
    fn community_machine_context_keeps_legacy_execution_authorization() {
        let principal = crate::enterprise::AuthenticatedPrincipal {
            subject: "agent:community".into(),
            credential_id: "credential:community".into(),
        };
        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTH_SOURCE_HEADER,
            tonic::metadata::MetadataValue::from_static("token"),
        );
        request
            .extensions_mut()
            .insert(crate::enterprise::AuthenticatedContext::machine(principal));

        assert!(
            enterprise_authenticated_context(&request)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn enterprise_execution_marker_without_context_fails_closed() {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTH_SOURCE_HEADER,
            tonic::metadata::MetadataValue::from_static("enterprise"),
        );

        assert_eq!(
            enterprise_authenticated_context(&request)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    async fn synthetic_native_tool_stream() -> AxumResponse {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"read\",\"arguments\":\"{\\\"path\\\":\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"fixture.txt\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\n\n",
            "data: [DONE]\n\n"
        );
        AxumResponse::builder()
            .header("content-type", "text/event-stream")
            .body(Body::from(body))
            .unwrap()
    }

    async fn synthetic_native_chat(Json(request): Json<serde_json::Value>) -> AxumResponse {
        if request["stream"].as_bool() == Some(true) {
            return synthetic_native_tool_stream().await;
        }
        AxumResponse::builder()
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"choices":[{"message":{"content":"","tool_calls":[{"id":"call_1","function":{"name":"read","arguments":"{\"path\":\"fixture.txt\"}"}}]}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#,
            ))
            .unwrap()
    }

    async fn synthetic_ollama_models() -> AxumResponse {
        AxumResponse::builder()
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"models":[{"name":"mistral","details":{"parameter_size":"7B","context_length":32768},"capabilities":["tools"]}]}"#,
            ))
            .unwrap()
    }

    async fn spawn_synthetic_ollama_provider() -> String {
        let app = Router::new()
            .route("/api/tags", get(synthetic_ollama_models))
            .route("/v1/chat/completions", post(synthetic_native_chat));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}")
    }

    fn managed_ollama_execution_service(provider_url: String) -> ChiseiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new_with_enterprise_extension(
                ":memory:",
                Some(Arc::new(ManagedExecutionExtension)),
            )
            .unwrap(),
        )));
        let mut managed_config = config(":memory:");
        managed_config.ollama_url = provider_url;
        let service = ChiseiServiceImpl::new(db, managed_config);
        service.policy.set_namespace_policy(
            "managed-conformance",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["ollama".into()],
                allowed_models: vec!["ollama/mistral".into()],
                default_runtime: "ollama".into(),
                default_model: "ollama/mistral".into(),
                data_class: "unclassified".into(),
            },
        );
        service
    }

    #[tokio::test]
    async fn managed_stream_preserves_tool_calls_usage_and_receipt_without_route_override() {
        let provider_url = spawn_synthetic_ollama_provider().await;
        let service = managed_ollama_execution_service(provider_url);
        let context = managed_execution_context(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
        );
        let mut plan_request = Request::new(managed_plan_request("managed-stream"));
        attach_managed_context(&mut plan_request, context.clone());
        let plan = service
            .plan_execution(plan_request)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert_eq!(plan.resolved_model, "ollama/mistral");
        assert!(plan.input.as_ref().unwrap().route_override.is_empty());
        let plan_id = plan.plan_id.clone();

        let mut denied_execute = Request::new(ExecutePlanRequest {
            plan: Some(plan.clone()),
        });
        attach_managed_context(
            &mut denied_execute,
            managed_execution_context(Vec::new(), "sekai:control-plane", i64::MAX),
        );
        let denied = match service.execute_plan_stream(denied_execute).await {
            Ok(_) => panic!("unauthorized execution unexpectedly started a stream"),
            Err(error) => error,
        };
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let mut execute_request = Request::new(ExecutePlanRequest { plan: Some(plan) });
        attach_managed_context(&mut execute_request, context);
        let mut stream = service
            .execute_plan_stream(execute_request)
            .await
            .unwrap()
            .into_inner();
        let mut terminal = None;
        while let Some(event) = stream.next().await {
            let event = event.unwrap();
            if event.done {
                terminal = event.response;
            }
        }
        let response = terminal.expect("terminal normalized response");
        assert_eq!(response.provider, "ollama");
        assert_eq!(response.input_tokens, 7);
        assert_eq!(response.output_tokens, 3);
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].id, "call_1");
        assert_eq!(response.tool_calls[0].name, "read");
        assert_eq!(
            response.tool_calls[0].args_json,
            r#"{"path":"fixture.txt"}"#
        );

        let receipt = service
            .db
            .get_operation_receipt(&plan_id)
            .unwrap()
            .expect("operation receipt");
        assert!(receipt.completeness().complete);
        let attributes = receipt
            .events
            .iter()
            .flat_map(|event| event.attributes.values())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!attributes.contains("credential:managed-shikigami"));
        assert!(!attributes.contains("synthetic-secret"));
    }

    #[tokio::test]
    async fn managed_cached_plan_is_bound_to_authenticated_tenant() {
        let provider_url = spawn_synthetic_ollama_provider().await;
        let service = managed_ollama_execution_service(provider_url);
        let tenant_a = managed_execution_context_for_tenant(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
            "tenant-managed-a",
        );
        let tenant_b = managed_execution_context_for_tenant(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
            "tenant-managed-b",
        );
        let mut plan_request = Request::new(managed_plan_request("managed-tenant-bound-plan"));
        attach_managed_context(&mut plan_request, tenant_a.clone());
        let plan = service
            .plan_execution(plan_request)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        let mut wrong_tenant = Request::new(ExecutePlanRequest {
            plan: Some(plan.clone()),
        });
        attach_managed_context(&mut wrong_tenant, tenant_b);
        let error = match service.execute_plan_stream(wrong_tenant).await {
            Ok(_) => panic!("another tenant unexpectedly acquired the cached plan"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let mut owning_tenant = Request::new(ExecutePlanRequest { plan: Some(plan) });
        attach_managed_context(&mut owning_tenant, tenant_a);
        let mut stream = service
            .execute_plan_stream(owning_tenant)
            .await
            .unwrap()
            .into_inner();
        while let Some(event) = stream.next().await {
            event.unwrap();
        }
    }

    #[tokio::test]
    async fn managed_unary_execution_accepts_machine_context_and_normalizes_receipt() {
        let provider_url = spawn_synthetic_ollama_provider().await;
        let service = managed_ollama_execution_service(provider_url);
        let context = managed_execution_context(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
        );
        let mut plan_request = Request::new(managed_plan_request("managed-unary"));
        attach_managed_context(&mut plan_request, context.clone());
        let plan = service
            .plan_execution(plan_request)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        let plan_id = plan.plan_id.clone();

        let mut execute_request = Request::new(ExecutePlanRequest { plan: Some(plan) });
        attach_managed_context(&mut execute_request, context);
        let response = service
            .execute_plan(execute_request)
            .await
            .unwrap()
            .into_inner()
            .response
            .expect("normalized unary response");
        assert_eq!(response.provider, "ollama");
        assert_eq!(response.input_tokens, 7);
        assert_eq!(response.output_tokens, 3);
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].id, "call_1");
        assert_eq!(response.tool_calls[0].name, "read");
        assert_eq!(
            response.tool_calls[0].args_json,
            r#"{"path":"fixture.txt"}"#
        );

        let receipt = service
            .db
            .get_operation_receipt(&plan_id)
            .unwrap()
            .expect("completed unary receipt");
        assert!(receipt.completeness().complete);
    }

    async fn synthetic_failed_chat(State(requests): State<Arc<AtomicUsize>>) -> AxumResponse {
        requests.fetch_add(1, Ordering::SeqCst);
        AxumResponse::builder()
            .status(503)
            .body(Body::from("synthetic provider unavailable"))
            .unwrap()
    }

    async fn spawn_synthetic_failing_ollama_provider() -> (String, Arc<AtomicUsize>) {
        let requests = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/api/tags", get(synthetic_ollama_models))
            .route("/v1/chat/completions", post(synthetic_failed_chat))
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), requests)
    }

    async fn synthetic_invalid_tool_stream(
        State(requests): State<Arc<AtomicUsize>>,
    ) -> AxumResponse {
        requests.fetch_add(1, Ordering::SeqCst);
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"read\",\"arguments\":\"{\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n"
        );
        AxumResponse::builder()
            .header("content-type", "text/event-stream")
            .body(Body::from(body))
            .unwrap()
    }

    async fn spawn_synthetic_invalid_stream_ollama_provider() -> (String, Arc<AtomicUsize>) {
        let requests = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/api/tags", get(synthetic_ollama_models))
            .route("/v1/chat/completions", post(synthetic_invalid_tool_stream))
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), requests)
    }

    #[tokio::test]
    async fn managed_provider_failure_records_failed_receipt_without_route_switch() {
        let (provider_url, requests) = spawn_synthetic_failing_ollama_provider().await;
        let service = managed_ollama_execution_service(provider_url);
        let context = managed_execution_context(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
        );
        let mut plan_request = Request::new(managed_plan_request("managed-provider-failure"));
        attach_managed_context(&mut plan_request, context.clone());
        let plan = service
            .plan_execution(plan_request)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        let plan_id = plan.plan_id.clone();
        assert_eq!(plan.resolved_model, "ollama/mistral");

        let mut execute_request = Request::new(ExecutePlanRequest { plan: Some(plan) });
        attach_managed_context(&mut execute_request, context);
        let error = match service.execute_plan_stream(execute_request).await {
            Ok(_) => panic!("synthetic provider failure unexpectedly started a stream"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::Internal);
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        let receipt = service
            .db
            .get_operation_receipt(&plan_id)
            .unwrap()
            .expect("failed operation receipt");
        assert!(receipt.completeness().complete);
        let outcome = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
            .expect("failed outcome");
        assert_eq!(outcome.attributes["status"], "denied");
        assert_eq!(
            outcome.attributes["completion_reason"],
            "model_stream_start_failed"
        );
        let route = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::RouteSelected)
            .expect("recorded route");
        assert_eq!(route.attributes["runtime"], "ollama");
        assert_eq!(route.attributes["model"], "ollama/mistral");
    }

    #[tokio::test]
    async fn managed_stream_read_failure_records_failed_receipt_without_route_switch() {
        let (provider_url, requests) = spawn_synthetic_invalid_stream_ollama_provider().await;
        let service = managed_ollama_execution_service(provider_url);
        let context = managed_execution_context(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
        );
        let mut plan_request = Request::new(managed_plan_request("managed-stream-read-failure"));
        attach_managed_context(&mut plan_request, context.clone());
        let plan = service
            .plan_execution(plan_request)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        let plan_id = plan.plan_id.clone();

        let mut execute_request = Request::new(ExecutePlanRequest { plan: Some(plan) });
        attach_managed_context(&mut execute_request, context);
        let mut stream = service
            .execute_plan_stream(execute_request)
            .await
            .unwrap()
            .into_inner();
        let error = stream
            .next()
            .await
            .expect("stream failure event")
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Internal);
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        let receipt = service
            .db
            .get_operation_receipt(&plan_id)
            .unwrap()
            .expect("failed stream receipt");
        assert!(receipt.completeness().complete);
        let outcome = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
            .expect("failed outcome");
        assert_eq!(outcome.attributes["status"], "denied");
        assert_eq!(
            outcome.attributes["completion_reason"],
            "model_stream_failed"
        );
        let route = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::RouteSelected)
            .expect("recorded route");
        assert_eq!(route.attributes["model"], "ollama/mistral");
    }

    #[tokio::test]
    async fn managed_explicit_retry_creates_distinct_correlated_attempts() {
        let service = managed_execution_service();
        let context = managed_execution_context(
            vec!["chisei.execute".into()],
            "sekai:control-plane",
            i64::MAX,
        );
        let mut plan_ids = Vec::new();

        for attempt_id in ["attempt-1", "attempt-2"] {
            let mut input = managed_plan_request(&format!("managed-retry-{attempt_id}"));
            let execution = input.input.as_mut().unwrap();
            execution.logical_operation_id = "managed-logical-operation".into();
            execution.attempt_id = attempt_id.into();
            let mut request = Request::new(input);
            attach_managed_context(&mut request, context.clone());
            let plan = service
                .plan_execution(request)
                .await
                .unwrap()
                .into_inner()
                .plan
                .unwrap();
            let receipt = service
                .db
                .get_operation_receipt(&plan.plan_id)
                .unwrap()
                .expect("planned retry receipt");
            let intent = receipt
                .events
                .iter()
                .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
                .expect("retry intent");
            assert_eq!(
                intent.attributes["logical_operation_id"],
                "managed-logical-operation"
            );
            assert_eq!(intent.attributes["attempt_id"], attempt_id);
            plan_ids.push(plan.plan_id);
        }

        assert_ne!(plan_ids[0], plan_ids[1]);
    }

    #[derive(Debug)]
    struct SchemaFixtureEvaluator {
        delay_ms: u64,
    }

    impl DeterministicEvaluator for SchemaFixtureEvaluator {
        fn evaluate(
            &self,
            input: &evaluation_execution_domain::DeterministicEvaluatorInput,
        ) -> Result<DeterministicEvaluatorOutput, String> {
            if self.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.delay_ms));
            }
            let strict = input
                .parameters
                .get("strict")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            Ok(DeterministicEvaluatorOutput {
                contract_version: EVALUATOR_RESULT_CONTRACT.into(),
                status: if strict { STATUS_PASS } else { "fail" }.into(),
                reason_code: if strict {
                    "schema_conforms"
                } else {
                    "strict_mode_required"
                }
                .into(),
                result: serde_json::json!({"conforms": strict}),
            })
        }
    }

    fn evaluation_execution_service(delay_ms: u64) -> ChiseiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let registry =
            Arc::new(evaluation_execution_domain::DeterministicEvaluatorRegistry::default());
        registry
            .register(
                &format!("sha256:{}", "a".repeat(64)),
                Arc::new(SchemaFixtureEvaluator { delay_ms }),
            )
            .unwrap();
        ChiseiServiceImpl::new_with_evaluator_registry(db, config(":memory:"), registry)
    }

    fn evaluator_definition_request(namespace: &str) -> PutEvaluatorDefinitionRequest {
        PutEvaluatorDefinitionRequest {
            definition: Some(EvaluatorDefinition {
                contract_version: evaluation_plan_domain::EVALUATOR_DEFINITION_CONTRACT.into(),
                namespace: namespace.into(),
                evaluator_id: "schema-check".into(),
                version: "1.0.0".into(),
                implementation_digest: format!("sha256:{}", "a".repeat(64)),
                execution_class: evaluation_plan_domain::DETERMINISTIC_EXECUTION_CLASS.into(),
                supported_predicate_kinds: vec!["schema_conforms".into()],
                supported_input_schemas: vec!["schema://document/v1".into()],
                supported_result_schemas: vec!["schema://pass-fail/v1".into()],
                parameter_schema_json: r#"{"type":"object","properties":{"strict":{"type":"boolean"}},"required":["strict"],"additionalProperties":false}"#.into(),
                evidence_classifications: vec!["internal".into()],
                resource_limits: Some(EvaluatorResourceLimits {
                    timeout_ms: 1_000,
                    max_input_bytes: 4_096,
                    max_output_bytes: 1_024,
                    max_evidence_items: 8,
                }),
                source_ref: "repo://evaluators/schema-check@1".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn install_invariant(svc: &ChiseiServiceImpl, namespace: &str) -> String {
        install_invariant_with_subject_refs(svc, namespace, "document-schema", vec![])
    }

    fn install_invariant_with_subject_refs(
        svc: &ChiseiServiceImpl,
        namespace: &str,
        fact_id: &str,
        subject_refs: Vec<String>,
    ) -> String {
        install_invariant_with_references(svc, namespace, fact_id, subject_refs, vec![])
    }

    fn install_invariant_with_references(
        svc: &ChiseiServiceImpl,
        namespace: &str,
        fact_id: &str,
        subject_refs: Vec<String>,
        evidence_refs: Vec<String>,
    ) -> String {
        install_invariant_with_contract(
            svc,
            namespace,
            fact_id,
            subject_refs,
            evidence_refs,
            vec![],
            vec![],
        )
    }

    fn install_invariant_with_contract(
        svc: &ChiseiServiceImpl,
        namespace: &str,
        fact_id: &str,
        subject_refs: Vec<String>,
        evidence_refs: Vec<String>,
        evidence_types: Vec<String>,
        requirement_version_ids: Vec<String>,
    ) -> String {
        governed_fact_domain::apply_profile(
            &svc.db,
            namespace,
            governed_fact_domain::PROFILE_CONTRACT_VERSION,
            "root",
            1,
        )
        .unwrap();
        governed_fact_domain::put_fact(
            &svc.db,
            governed_fact_domain::GovernedFactInput {
                contract_version: governed_fact_domain::PROFILE_CONTRACT_VERSION.into(),
                namespace: namespace.into(),
                fact_id: fact_id.into(),
                version: "1.0.0".into(),
                fact_type: GovernedFactType::Invariant,
                status: "active".into(),
                statement: "The document conforms to the declared schema.".into(),
                applicability: governed_fact_domain::FactApplicability {
                    subject_profiles: vec!["document/v1".into()],
                    subject_refs,
                },
                verification: governed_fact_domain::VerificationContract {
                    predicate_kind: "schema_conforms".into(),
                    input_schema: "schema://document/v1".into(),
                    result_schema: "schema://pass-fail/v1".into(),
                    evidence_types,
                },
                requirement_version_ids,
                evidence_refs,
                source_ref: "repo://requirements/document-schema@1".into(),
                effective_from_ms: 1,
                supersedes_object_id: String::new(),
                access_marking: String::new(),
            },
            "root",
            2,
        )
        .unwrap()
        .object_id
    }

    fn install_requirement_with_evidence(
        svc: &ChiseiServiceImpl,
        namespace: &str,
        fact_id: &str,
        evidence_refs: Vec<String>,
    ) -> String {
        governed_fact_domain::apply_profile(
            &svc.db,
            namespace,
            governed_fact_domain::PROFILE_CONTRACT_VERSION,
            "root",
            1,
        )
        .unwrap();
        governed_fact_domain::put_fact(
            &svc.db,
            governed_fact_domain::GovernedFactInput {
                contract_version: governed_fact_domain::PROFILE_CONTRACT_VERSION.into(),
                namespace: namespace.into(),
                fact_id: fact_id.into(),
                version: "1.0.0".into(),
                fact_type: GovernedFactType::Requirement,
                status: "active".into(),
                statement: "The document has attributable schema verification provenance.".into(),
                applicability: governed_fact_domain::FactApplicability {
                    subject_profiles: vec!["document/v1".into()],
                    subject_refs: vec![],
                },
                verification: governed_fact_domain::VerificationContract::default(),
                requirement_version_ids: vec![],
                evidence_refs,
                source_ref: "repo://requirements/schema-provenance@1".into(),
                effective_from_ms: 1,
                supersedes_object_id: String::new(),
                access_marking: String::new(),
            },
            "root",
            2,
        )
        .unwrap()
        .object_id
    }

    fn project_evaluation_evidence(
        svc: &ChiseiServiceImpl,
        target_external_id: &str,
        classification: crate::sekai::evidence::EvidenceClassification,
        expires_at_ms: i64,
        idempotency_key: &str,
    ) -> String {
        use crate::sekai::evidence::{
            EVIDENCE_ENVELOPE_VERSION, EvidenceEnvelope, EvidenceIntent, EvidenceSignal,
            EvidenceTarget, SchemaCompatibility,
        };
        use crate::sekai::evidence_store::{
            EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
        };

        let producer_identity = format!("producer:evaluation:{idempotency_key}");
        let source_instance = format!("evaluation-fixture:{idempotency_key}");
        let target_id = format!("target:{}", target_external_id.replace(':', "-"));
        if svc
            .db
            .find_by_external_id(target_external_id)
            .unwrap()
            .is_none()
        {
            svc.db
                .create_object(&Object {
                    id: target_id,
                    kind: "document".into(),
                    name: target_external_id.into(),
                    namespace: "acme".into(),
                    external_id: target_external_id.into(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                })
                .unwrap();
        }
        svc.db
            .upsert_evidence_producer(
                &EvidenceProducerCapability {
                    producer_identity: producer_identity.clone(),
                    config_version: 1,
                    source_types: vec!["verification_system".into()],
                    source_instances: vec![source_instance.clone()],
                    namespaces: vec!["acme".into()],
                    evidence_types: vec!["schema-check.record".into()],
                    target_kinds: vec!["document".into()],
                    classification_ceiling: classification,
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
                    schema_id: "schema://evidence/schema-check/v1".into(),
                    schema_version: "1.0.0".into(),
                    evidence_type: "schema-check.record".into(),
                    compatible_versions: vec![],
                },
                1,
            )
            .unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let content = serde_json::json!({"result": "passed"});
        let envelope = EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "verification_system".into(),
            source_instance,
            source_record_id: idempotency_key.into(),
            source_version: "1".into(),
            source_sequence: 1,
            target: EvidenceTarget {
                namespace: "acme".into(),
                object_external_id: target_external_id.into(),
                object_kind: "document".into(),
            },
            evidence_type: "schema-check.record".into(),
            signal: EvidenceSignal::Verification,
            schema_id: "schema://evidence/schema-check/v1".into(),
            schema_version: "1.0.0".into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: now - 1,
            collected_at_ms: now,
            expires_at_ms: Some(expires_at_ms),
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: producer_identity.clone(),
            confidence_bps: 10_000,
            classification,
            provenance: BTreeMap::new(),
            idempotency_key: idempotency_key.into(),
            intent: EvidenceIntent::Upsert,
            causality: None,
        };
        let admission = svc
            .db
            .submit_evidence(&envelope, &producer_identity, now)
            .unwrap();
        svc.db
            .project_evidence_submission(&admission.submission.id, now)
            .unwrap()
            .evidence_object_id
            .unwrap()
    }

    fn evaluation_plan_request(
        namespace: &str,
        definition_id: &str,
        invariant_id: &str,
        version: &str,
    ) -> PutEvaluationPlanRequest {
        PutEvaluationPlanRequest {
            plan: Some(EvaluationPlan {
                contract_version: evaluation_plan_domain::EVALUATION_PLAN_CONTRACT.into(),
                namespace: namespace.into(),
                plan_id: "document-review".into(),
                version: version.into(),
                accepted_subject_profiles: vec!["document/v1".into()],
                nodes: vec![EvaluationPlanNode {
                    node_id: "schema".into(),
                    evaluator_definition_id: definition_id.into(),
                    input_bindings: vec![EvaluationInputBinding {
                        name: "document".into(),
                        source_kind: evaluation_plan_domain::INPUT_INVARIANT.into(),
                        schema_id: "schema://document/v1".into(),
                    }],
                    parameters_json: r#"{"strict":true}"#.into(),
                    invariant_version_ids: vec![invariant_id.into()],
                    classification: evaluation_plan_domain::NODE_REQUIRED.into(),
                    ..Default::default()
                }],
                reducer: evaluation_plan_domain::FIXED_REDUCER.into(),
                source_ref: "repo://plans/document-review@1".into(),
                ..Default::default()
            }),
        }
    }

    fn evaluation_resolution_request(
        namespace: &str,
        request_id: &str,
        plan_version_id: &str,
        evaluation_time_ms: i64,
    ) -> ResolveEvaluationPlanRequest {
        ResolveEvaluationPlanRequest {
            resolution: Some(EvaluationResolutionRequest {
                contract_version: evaluation_manifest_domain::RESOLUTION_REQUEST_CONTRACT.into(),
                resolver_version: evaluation_manifest_domain::RESOLVER_VERSION.into(),
                namespace: namespace.into(),
                request_id: request_id.into(),
                plan_version_id: plan_version_id.into(),
                subject_profile: "document/v1".into(),
                subject_identity: "document:42".into(),
                subject_content_digest: format!("sha256:{}", "b".repeat(64)),
                evidence_object_ids: vec![],
                evaluation_time_ms,
            }),
        }
    }

    async fn resolved_execution_fixture(
        svc: &ChiseiServiceImpl,
        request_id: &str,
    ) -> ResolvedEvaluationManifest {
        let invariant_id = install_invariant(svc, "acme");
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let plan = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        svc.resolve_evaluation_plan(Request::new(evaluation_resolution_request(
            "acme",
            request_id,
            &plan.plan_version_id,
            10,
        )))
        .await
        .unwrap()
        .into_inner()
        .manifest
        .unwrap()
    }

    #[tokio::test]
    async fn evaluation_plans_bind_exact_compatible_resources_and_preserve_history() {
        let svc = memory_service();
        let invariant_id = install_invariant(&svc, "acme");
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let stored = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        let replay = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert_eq!(stored.content_digest, replay.content_digest);

        let disabled = svc
            .put_evaluator_definition(Request::new(PutEvaluatorDefinitionRequest {
                definition_id: definition.definition_id.clone(),
                availability_state: evaluation_plan_domain::AVAILABILITY_DISABLED.into(),
                reason: "maintenance".into(),
                request_id: "disable-1".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .availability
            .unwrap();
        assert_eq!(
            disabled.state,
            evaluation_plan_domain::AVAILABILITY_DISABLED
        );
        assert_eq!(disabled.request_id, "disable-1");
        assert_eq!(disabled.reason, "maintenance");
        let historical_replay = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        assert_eq!(historical_replay.plan_version_id, stored.plan_version_id);
        let error = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "2.0.0",
            )))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn evaluation_plan_rejects_evidence_outside_evaluator_classifications() {
        let svc = memory_service();
        let evidence_id = "evidence-confidential";
        svc.db
            .create_object(&Object {
                id: evidence_id.into(),
                kind: crate::domain::KIND_EXTERNAL_EVIDENCE.into(),
                name: "confidential evidence".into(),
                namespace: "acme".into(),
                external_id: "evidence:confidential".into(),
                properties: HashMap::from([("classification".into(), "confidential".into())]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        let invariant_id = install_invariant_with_references(
            &svc,
            "acme",
            "document-schema",
            vec![],
            vec![evidence_id.into()],
        );
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();

        let mut request =
            evaluation_plan_request("acme", &definition.definition_id, &invariant_id, "1.0.0");
        request.plan.as_mut().unwrap().nodes[0]
            .input_bindings
            .push(EvaluationInputBinding {
                name: "evidence".into(),
                source_kind: evaluation_plan_domain::INPUT_EVIDENCE.into(),
                schema_id: "schema://document/v1".into(),
            });
        let error = svc
            .put_evaluation_plan(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            error.message(),
            "evaluator definition does not admit the invariant evidence classification"
        );
    }

    #[tokio::test]
    async fn evaluation_plan_validation_rejects_unknown_reducers_and_bad_parameters() {
        let svc = memory_service();
        let invariant_id = install_invariant(&svc, "acme");
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let mut unknown =
            evaluation_plan_request("acme", &definition.definition_id, &invariant_id, "1.0.0");
        unknown.plan.as_mut().unwrap().reducer = "custom-expression".into();
        assert_eq!(
            svc.put_evaluation_plan(Request::new(unknown))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let mut bad_parameters =
            evaluation_plan_request("acme", &definition.definition_id, &invariant_id, "1.0.0");
        bad_parameters.plan.as_mut().unwrap().nodes[0].parameters_json =
            r#"{"strict":"yes"}"#.into();
        assert_eq!(
            svc.put_evaluation_plan(Request::new(bad_parameters))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let unknown = evaluation_plan_request(
            "acme",
            "evaluator-definition:unknown",
            &invariant_id,
            "1.0.0",
        );
        assert_eq!(
            svc.put_evaluation_plan(Request::new(unknown))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        let subject_specific = install_invariant_with_subject_refs(
            &svc,
            "acme",
            "subject-specific-schema",
            vec!["document:one".into()],
        );
        let subject_specific_plan = evaluation_plan_request(
            "acme",
            &definition.definition_id,
            &subject_specific,
            "1.0.0",
        );
        let error = svc
            .put_evaluation_plan(Request::new(subject_specific_plan))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("subject-specific"));
    }

    #[tokio::test]
    async fn evaluation_resource_reads_are_namespace_and_reference_authorized() {
        let svc = memory_service();
        let invariant_id = install_invariant(&svc, "acme");
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let _plan = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        svc.db
            .create_object(&Object {
                id: "evaluation-namespace-acme".into(),
                kind: "namespace".into(),
                name: "Acme".into(),
                namespace: String::new(),
                external_id: "namespace:acme".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_grant(&Grant {
                id: "alice-evaluation-acme".into(),
                object_id: "evaluation-namespace-acme".into(),
                principal: "alice".into(),
                role: Role::Admin,
                created: 1,
            })
            .unwrap();

        svc.db
            .create_grant(&Grant {
                id: "root-only-invariant".into(),
                object_id: invariant_id,
                principal: "root".into(),
                role: Role::Viewer,
                created: 2,
            })
            .unwrap();
        let mut alice_put = Request::new(evaluator_definition_request("acme"));
        alice_put
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        assert_eq!(
            svc.put_evaluator_definition(alice_put)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn evaluation_resolution_freezes_exact_inputs_and_replays_history() {
        let svc = memory_service();
        let invariant_id = install_invariant(&svc, "acme");
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let plan = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        let request = evaluation_resolution_request("acme", "resolve-1", &plan.plan_version_id, 10);
        let first = svc
            .resolve_evaluation_plan(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            first.status,
            evaluation_manifest_domain::RESOLUTION_RESOLVED
        );
        assert!(first.findings.is_empty());
        let manifest = first.manifest.unwrap();
        assert_eq!(manifest.plan_version_id, plan.plan_version_id);
        assert_eq!(manifest.plan_digest, plan.content_digest);
        assert_eq!(manifest.subject_identity, "document:42");
        assert_eq!(manifest.resolved_by, "local");
        assert_eq!(manifest.nodes.len(), 1);
        assert_eq!(
            manifest.nodes[0]
                .evaluator
                .as_ref()
                .unwrap()
                .implementation_digest,
            definition.implementation_digest
        );
        assert_eq!(
            manifest.nodes[0].invariants[0].invariant_version_id,
            invariant_id
        );

        let replay = svc
            .resolve_evaluation_plan(Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .manifest
            .unwrap();
        assert_eq!(replay.manifest_digest, manifest.manifest_digest);
        assert_eq!(replay.created_at_ms, manifest.created_at_ms);

        svc.put_evaluator_definition(Request::new(PutEvaluatorDefinitionRequest {
            definition_id: definition.definition_id,
            availability_state: evaluation_plan_domain::AVAILABILITY_DISABLED.into(),
            reason: "maintenance".into(),
            request_id: "disable-after-resolution".into(),
            ..Default::default()
        }))
        .await
        .unwrap();

        let historical = svc
            .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
                "acme",
                "resolve-1",
                &plan.plan_version_id,
                10,
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            historical.manifest.unwrap().manifest_digest,
            manifest.manifest_digest
        );
        let unavailable = svc
            .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
                "acme",
                "resolve-2",
                &plan.plan_version_id,
                10,
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            unavailable.status,
            evaluation_manifest_domain::RESOLUTION_UNAVAILABLE
        );
        assert!(unavailable.manifest.is_none());
        assert_eq!(unavailable.findings[0].code, "evaluator_unavailable");
    }

    #[tokio::test]
    async fn deterministic_manifest_execution_is_receipt_authoritative_and_idempotent() {
        let svc = evaluation_execution_service(0);
        let manifest = resolved_execution_fixture(&svc, "execute-resolve").await;
        let definition_id = manifest.nodes[0]
            .evaluator
            .as_ref()
            .unwrap()
            .definition_id
            .clone();
        svc.put_evaluator_definition(Request::new(PutEvaluatorDefinitionRequest {
            definition_id,
            availability_state: evaluation_plan_domain::AVAILABILITY_DISABLED.into(),
            reason: "disabled after manifest resolution".into(),
            request_id: "disable-before-historical-execution".into(),
            ..Default::default()
        }))
        .await
        .unwrap();
        let request = ExecuteEvaluationManifestRequest {
            execution: Some(EvaluationExecutionRequest {
                contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
                executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
                namespace: "acme".into(),
                manifest_digest: manifest.manifest_digest.clone(),
                max_total_duration_ms: 1_000,
            }),
        };
        let first = svc
            .execute_evaluation_manifest(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner()
            .execution
            .unwrap();
        let mut forged_report = Request::new(ReportOperationEventRequest {
            operation_id: first.operation_id.clone(),
            event_id: format!("report:{}:forged-step", first.operation_id),
            parent_event_id: format!("{}:budget", first.operation_id),
            timestamp_ms: 0,
            kind: "verification_recorded".into(),
            attributes: HashMap::from([("evaluation_step_receipt".into(), "{}".into())]),
            references: vec![],
        });
        forged_report
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        forged_report
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "local".parse().unwrap());
        assert_eq!(
            svc.report_operation_event(forged_report)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(first.status, evaluation_execution_domain::VERDICT_ALLOW);
        assert_eq!(first.steps.len(), 1);
        assert_eq!(
            first.steps[0].status,
            evaluation_execution_domain::STATUS_PASS
        );
        assert!(
            first
                .decision
                .as_ref()
                .unwrap()
                .decision_digest
                .starts_with("sha256:")
        );

        let mut replay_request = request;
        replay_request
            .execution
            .as_mut()
            .unwrap()
            .max_total_duration_ms = 2_000;
        let replay = svc
            .execute_evaluation_manifest(Request::new(replay_request))
            .await
            .unwrap()
            .into_inner()
            .execution
            .unwrap();
        assert_eq!(replay, first);
        let tighter = svc
            .execute_evaluation_manifest(Request::new(ExecuteEvaluationManifestRequest {
                execution: Some(EvaluationExecutionRequest {
                    contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT
                        .into(),
                    executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
                    namespace: "acme".into(),
                    manifest_digest: manifest.manifest_digest.clone(),
                    max_total_duration_ms: 500,
                }),
            }))
            .await
            .unwrap_err();
        assert_eq!(tighter.code(), tonic::Code::FailedPrecondition);
        let receipt = svc
            .db
            .get_operation_receipt(&first.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(evaluation_total_budget_ms(&receipt).unwrap(), 1_000);
        assert_eq!(
            evaluation_cancellation_event(&receipt, "different-writer", 42).actor,
            "different-writer"
        );
        assert!(receipt.completeness().complete);
        assert!(receipt.events.iter().any(|event| {
            event.kind == ReceiptEventKind::VerificationRecorded
                && event.attributes.contains_key("evaluation_step_receipt")
        }));
        assert!(receipt.events.iter().any(|event| {
            event.kind == ReceiptEventKind::OutcomeRecorded
                && event.attributes.contains_key("evaluation_gate_decision")
        }));
    }

    #[tokio::test]
    async fn evaluation_execution_authorizes_namespace_before_manifest_lookup() {
        let svc = evaluation_execution_service(0);
        let mut request = Request::new(ExecuteEvaluationManifestRequest {
            execution: Some(EvaluationExecutionRequest {
                contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
                executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
                namespace: "secret".into(),
                manifest_digest: format!("sha256:{}", "9".repeat(64)),
                max_total_duration_ms: 1_000,
            }),
        });
        request
            .metadata_mut()
            .insert("x-principal", "mallory".parse().unwrap());
        let error = svc.execute_evaluation_manifest(request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(!error.message().contains("manifest"));
    }

    #[tokio::test]
    async fn concurrent_cancellation_reconciles_to_the_first_durable_actor() {
        let svc = evaluation_execution_service(0);
        let manifest = resolved_execution_fixture(&svc, "cancel-race-resolve").await;
        let manifest = svc
            .db
            .get_evaluation_manifest(&manifest.manifest_digest)
            .unwrap()
            .unwrap();
        let index = svc
            .ensure_evaluation_execution(&manifest, "starter", 1_000)
            .unwrap();
        let stale_receipt = svc
            .db
            .get_operation_receipt(&index.operation_id)
            .unwrap()
            .unwrap();

        svc.request_evaluation_cancellation(&index, &stale_receipt, "first-writer")
            .unwrap();
        svc.request_evaluation_cancellation(&index, &stale_receipt, "second-writer")
            .unwrap();

        let receipt = svc
            .db
            .get_operation_receipt(&index.operation_id)
            .unwrap()
            .unwrap();
        let cancellation = receipt
            .events
            .iter()
            .find(|event| {
                event
                    .attributes
                    .get("evaluation_cancel_requested")
                    .is_some_and(|value| value == "true")
            })
            .unwrap();
        assert_eq!(cancellation.actor, "first-writer");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn cancellation_is_durable_and_reduces_fail_closed() {
        let svc = Arc::new(evaluation_execution_service(250));
        let cancellation_replica = Arc::new(ChiseiServiceImpl::new_with_evaluator_registry(
            svc.db.clone(),
            svc.config.clone(),
            svc.evaluator_registry.clone(),
        ));
        let manifest = resolved_execution_fixture(&svc, "cancel-resolve").await;
        let execute_request = ExecuteEvaluationManifestRequest {
            execution: Some(EvaluationExecutionRequest {
                contract_version: evaluation_execution_domain::EXECUTION_REQUEST_CONTRACT.into(),
                executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
                namespace: "acme".into(),
                manifest_digest: manifest.manifest_digest.clone(),
                max_total_duration_ms: 2_000,
            }),
        };
        let executor = {
            let svc = svc.clone();
            tokio::spawn(async move {
                svc.execute_evaluation_manifest(Request::new(execute_request))
                    .await
                    .unwrap()
                    .into_inner()
                    .execution
                    .unwrap()
            })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        let cancelled = cancellation_replica
            .cancel_evaluation_execution(Request::new(CancelEvaluationExecutionRequest {
                namespace: "acme".into(),
                manifest_digest: manifest.manifest_digest,
            }))
            .await
            .unwrap()
            .into_inner()
            .execution
            .unwrap();
        let executed = executor.await.unwrap();
        assert_eq!(cancelled, executed);
        assert_eq!(
            cancelled.status,
            evaluation_execution_domain::VERDICT_UNAVAILABLE
        );
        assert_eq!(
            cancelled.decision.as_ref().unwrap().reason_code,
            evaluation_execution_domain::REASON_EXECUTION_CANCELLED
        );
        assert_eq!(
            cancelled.steps[0].reason_code,
            evaluation_execution_domain::REASON_EXECUTION_CANCELLED
        );
        let receipt = svc
            .db
            .get_operation_receipt(&cancelled.operation_id)
            .unwrap()
            .unwrap();
        assert!(evaluation_cancellation_requested(&receipt));
        assert!(receipt.completeness().complete);
    }

    #[tokio::test]
    async fn evaluation_resolution_fails_closed_for_uncovered_invariants() {
        let svc = memory_service();
        let covered_id = install_invariant(&svc, "acme");
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let plan = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &covered_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        let uncovered_id = install_invariant_with_subject_refs(&svc, "acme", "added-later", vec![]);

        let outcome = svc
            .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
                "acme",
                "resolve-uncovered",
                &plan.plan_version_id,
                10,
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            outcome.status,
            evaluation_manifest_domain::RESOLUTION_UNKNOWN
        );
        assert!(outcome.manifest.is_none());
        assert_eq!(outcome.findings[0].code, "invariant_uncovered");
        assert_eq!(outcome.findings[0].invariant_version_id, uncovered_id);

        let waiver = governed_fact_domain::put_waiver(
            &svc.db,
            governed_fact_domain::GovernedWaiverInput {
                contract_version: governed_fact_domain::PROFILE_CONTRACT_VERSION.into(),
                namespace: "acme".into(),
                waiver_id: "added-later-exception".into(),
                version: "1.0.0".into(),
                invariant_version_ids: vec![uncovered_id.clone()],
                applicability: governed_fact_domain::FactApplicability {
                    subject_profiles: vec!["document/v1".into()],
                    subject_refs: vec![],
                },
                reason: "Bounded test exception.".into(),
                evidence_refs: vec![],
                source_ref: "decision:test-waiver".into(),
                valid_from_ms: 3,
                expires_at_ms: 20,
                supersedes_object_id: String::new(),
                access_marking: String::new(),
            },
            "root",
            3,
        )
        .unwrap();
        let resolved = svc
            .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
                "acme",
                "resolve-waived",
                &plan.plan_version_id,
                10,
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            resolved.status,
            evaluation_manifest_domain::RESOLUTION_RESOLVED
        );
        let waiver_binding = resolved
            .manifest
            .unwrap()
            .waivers
            .into_iter()
            .find(|binding| binding.waiver_version_id == waiver.object_id)
            .unwrap();
        assert_eq!(waiver_binding.invariant_version_ids, vec![uncovered_id]);
    }

    #[tokio::test]
    async fn evaluation_resolution_authorizes_before_resource_lookup() {
        let svc = memory_service();
        let mut request = Request::new(evaluation_resolution_request(
            "acme",
            "resolve-denied",
            "evaluation-plan:secret",
            10,
        ));
        request
            .metadata_mut()
            .insert("x-principal", "mallory".parse().unwrap());
        let error = svc.resolve_evaluation_plan(request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(!error.message().contains("plan"));
    }

    #[tokio::test]
    async fn evaluation_resolution_binds_only_fresh_subject_matched_evidence() {
        use crate::sekai::evidence::EvidenceClassification;

        let svc = memory_service();
        let invariant_id = install_invariant_with_contract(
            &svc,
            "acme",
            "document-schema-with-evidence",
            vec![],
            vec![],
            vec!["schema-check.record".into()],
            vec![],
        );
        let mut definition_request = evaluator_definition_request("acme");
        definition_request
            .definition
            .as_mut()
            .unwrap()
            .supported_input_schemas
            .push("schema://evidence/schema-check/v1".into());
        let definition = svc
            .put_evaluator_definition(Request::new(definition_request))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let mut plan_request =
            evaluation_plan_request("acme", &definition.definition_id, &invariant_id, "1.0.0");
        plan_request.plan.as_mut().unwrap().nodes[0]
            .input_bindings
            .push(EvaluationInputBinding {
                name: "verification".into(),
                source_kind: evaluation_plan_domain::INPUT_EVIDENCE.into(),
                schema_id: "schema://evidence/schema-check/v1".into(),
            });
        let plan = svc
            .put_evaluation_plan(Request::new(plan_request))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        let base_time = chrono::Utc::now().timestamp_millis();
        let evidence_id = project_evaluation_evidence(
            &svc,
            "document:42",
            EvidenceClassification::Internal,
            base_time + 60_000,
            "evaluation-evidence-1",
        );
        let evaluation_time = chrono::Utc::now().timestamp_millis();
        let mut request = evaluation_resolution_request(
            "acme",
            "resolve-evidence",
            &plan.plan_version_id,
            evaluation_time,
        );
        request.resolution.as_mut().unwrap().evidence_object_ids = vec![evidence_id.clone()];
        let resolved = svc
            .resolve_evaluation_plan(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            resolved.status,
            evaluation_manifest_domain::RESOLUTION_RESOLVED
        );
        let manifest = resolved.manifest.unwrap();
        assert_eq!(manifest.evidence.len(), 1);
        assert_eq!(manifest.evidence[0].evidence_object_id, evidence_id);
        assert_eq!(manifest.evidence[0].evidence_type, "schema-check.record");
        assert_eq!(
            manifest.nodes[0].evidence_object_ids,
            vec![evidence_id.clone()]
        );

        let stale_base_time = chrono::Utc::now().timestamp_millis();
        let stale_evidence_id = project_evaluation_evidence(
            &svc,
            "document:42",
            EvidenceClassification::Internal,
            stale_base_time + 250,
            "evaluation-evidence-stale",
        );
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let mut stale_request = evaluation_resolution_request(
            "acme",
            "resolve-stale-evidence",
            &plan.plan_version_id,
            chrono::Utc::now().timestamp_millis(),
        );
        stale_request
            .resolution
            .as_mut()
            .unwrap()
            .evidence_object_ids = vec![stale_evidence_id];
        let stale = svc
            .resolve_evaluation_plan(Request::new(stale_request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stale.status, evaluation_manifest_domain::RESOLUTION_UNKNOWN);
        assert_eq!(stale.findings[0].code, "evidence_stale");

        let mismatched_id = project_evaluation_evidence(
            &svc,
            "document:other",
            EvidenceClassification::Internal,
            base_time + 60_000,
            "evaluation-evidence-2",
        );
        let mut mismatched_request = evaluation_resolution_request(
            "acme",
            "resolve-mismatched-evidence",
            &plan.plan_version_id,
            chrono::Utc::now().timestamp_millis(),
        );
        mismatched_request
            .resolution
            .as_mut()
            .unwrap()
            .evidence_object_ids = vec![mismatched_id];
        let mismatched = svc
            .resolve_evaluation_plan(Request::new(mismatched_request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            mismatched.status,
            evaluation_manifest_domain::RESOLUTION_UNKNOWN
        );
        assert_eq!(mismatched.findings[0].code, "evidence_subject_mismatch");
    }

    #[tokio::test]
    async fn evaluation_resolution_rejects_future_evaluation_time() {
        let svc = memory_service();
        let mut request = evaluation_resolution_request(
            "acme",
            "resolve-future",
            "evaluation-plan:future",
            chrono::Utc::now().timestamp_millis() + 60_000,
        );
        request.resolution.as_mut().unwrap().subject_content_digest =
            format!("sha256:{}", "c".repeat(64));
        let error = svc
            .resolve_evaluation_plan(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            error.message(),
            "evaluation_time_ms cannot be in the future"
        );
    }

    #[tokio::test]
    async fn evaluation_resolution_binds_requirement_provenance_evidence() {
        use crate::sekai::evidence::EvidenceClassification;

        let svc = memory_service();
        let base_time = chrono::Utc::now().timestamp_millis();
        let evidence_id = project_evaluation_evidence(
            &svc,
            "document:42",
            EvidenceClassification::Internal,
            base_time + 60_000,
            "requirement-evidence-1",
        );
        let requirement_id = install_requirement_with_evidence(
            &svc,
            "acme",
            "schema-provenance",
            vec![evidence_id.clone()],
        );
        let invariant_id = install_invariant_with_contract(
            &svc,
            "acme",
            "document-schema",
            vec![],
            vec![],
            vec![],
            vec![requirement_id.clone()],
        );
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let plan = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();

        let resolved = svc
            .resolve_evaluation_plan(Request::new(evaluation_resolution_request(
                "acme",
                "resolve-requirement-evidence",
                &plan.plan_version_id,
                chrono::Utc::now().timestamp_millis(),
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            resolved.status,
            evaluation_manifest_domain::RESOLUTION_RESOLVED
        );
        let manifest = resolved.manifest.unwrap();
        assert_eq!(manifest.evidence.len(), 1);
        assert_eq!(manifest.evidence[0].evidence_object_id, evidence_id);
        assert_eq!(manifest.requirements.len(), 1);
        assert_eq!(
            manifest.requirements[0].requirement_version_id,
            requirement_id
        );
        assert_eq!(
            manifest.requirements[0].provenance_evidence_object_ids,
            vec![evidence_id]
        );
    }

    #[tokio::test]
    async fn evaluation_resolution_detects_hidden_applicable_waivers() {
        let svc = memory_service();
        let invariant_id = install_invariant(&svc, "acme");
        let definition = svc
            .put_evaluator_definition(Request::new(evaluator_definition_request("acme")))
            .await
            .unwrap()
            .into_inner()
            .record
            .unwrap()
            .definition
            .unwrap();
        let plan = svc
            .put_evaluation_plan(Request::new(evaluation_plan_request(
                "acme",
                &definition.definition_id,
                &invariant_id,
                "1.0.0",
            )))
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        let waiver = governed_fact_domain::put_waiver(
            &svc.db,
            governed_fact_domain::GovernedWaiverInput {
                contract_version: governed_fact_domain::PROFILE_CONTRACT_VERSION.into(),
                namespace: "acme".into(),
                waiver_id: "root-only-exception".into(),
                version: "1.0.0".into(),
                invariant_version_ids: vec![invariant_id],
                applicability: governed_fact_domain::FactApplicability {
                    subject_profiles: vec!["document/v1".into()],
                    subject_refs: vec![],
                },
                reason: "Visible only to a different principal.".into(),
                evidence_refs: vec![],
                source_ref: "decision:root-only-waiver".into(),
                valid_from_ms: 3,
                expires_at_ms: 20,
                supersedes_object_id: String::new(),
                access_marking: String::new(),
            },
            "root",
            3,
        )
        .unwrap();
        svc.db
            .create_grant(&Grant {
                id: "root-only-manifest-waiver".into(),
                object_id: waiver.object_id,
                principal: "root".into(),
                role: Role::Viewer,
                created: 3,
            })
            .unwrap();
        svc.db
            .create_object(&Object {
                id: "evaluation-resolution-namespace-acme".into(),
                kind: "namespace".into(),
                name: "Acme".into(),
                namespace: String::new(),
                external_id: "namespace:acme".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_grant(&Grant {
                id: "alice-evaluation-resolution-acme".into(),
                object_id: "evaluation-resolution-namespace-acme".into(),
                principal: "alice".into(),
                role: Role::Admin,
                created: 1,
            })
            .unwrap();

        let mut request = Request::new(evaluation_resolution_request(
            "acme",
            "resolve-hidden-waiver",
            &plan.plan_version_id,
            10,
        ));
        request
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        let outcome = svc
            .resolve_evaluation_plan(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            outcome.status,
            evaluation_manifest_domain::RESOLUTION_UNKNOWN
        );
        assert!(outcome.manifest.is_none());
        assert_eq!(outcome.findings[0].code, "invariant_resolution_incomplete");
    }

    fn governed_subject_request(
        request_id: &str,
        subject_profile: &str,
        evaluation_profile: &str,
        observed_at_ms: i64,
    ) -> Request<EvaluateGovernedSubjectRequest> {
        let digest = format!("sha256:{}", "a".repeat(64));
        let kinds = if subject_profile == subject::SOFTWARE_RELEASE_PROFILE {
            ["source_tree", "manifest", "artifact", "build_definition"].as_slice()
        } else {
            ["policy_document", "policy_schema"].as_slice()
        };
        let mut request = Request::new(EvaluateGovernedSubjectRequest {
            subject: Some(GovernedSubjectEnvelope {
                version: subject::ENVELOPE_VERSION.into(),
                namespace: "team-a".into(),
                request_id: request_id.into(),
                subject_profile: subject_profile.into(),
                subject_identity: "subject-1".into(),
                content_digest: digest.clone(),
                references: kinds
                    .iter()
                    .map(|kind| GovernedSubjectReference {
                        kind: (*kind).into(),
                        reference: format!("{kind}-1"),
                        content_digest: digest.clone(),
                        observed_at_ms,
                    })
                    .collect(),
                evaluation_profile: evaluation_profile.into(),
            }),
        });
        request
            .metadata_mut()
            .insert("x-principal", "root".parse().unwrap());
        request
    }

    #[tokio::test]
    async fn governed_subject_profiles_share_receipt_and_idempotency_contract() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        for (index, profile) in [
            subject::SOFTWARE_RELEASE_PROFILE,
            subject::POLICY_BUNDLE_PROFILE,
        ]
        .into_iter()
        .enumerate()
        {
            let request_id = format!("subject-request-{index}");
            let first = svc
                .evaluate_governed_subject(governed_subject_request(
                    &request_id,
                    profile,
                    subject::ALLOW_PROFILE,
                    now,
                ))
                .await
                .unwrap()
                .into_inner()
                .result
                .unwrap();
            let mut replay_request =
                governed_subject_request(&request_id, profile, subject::ALLOW_PROFILE, now - 1);
            replay_request
                .get_mut()
                .subject
                .as_mut()
                .unwrap()
                .references
                .reverse();
            let replay = svc
                .evaluate_governed_subject(replay_request)
                .await
                .unwrap()
                .into_inner()
                .result
                .unwrap();
            assert_eq!(first.decision, "allow");
            assert_eq!(first.operation_id, replay.operation_id);
            assert_eq!(first.receipt_digest, replay.receipt_digest);
            assert!(
                replay
                    .references
                    .iter()
                    .all(|reference| reference.observed_at_ms == now)
            );
            let receipt = svc
                .db
                .get_operation_receipt(&first.operation_id)
                .unwrap()
                .unwrap();
            assert!(receipt.completeness().complete);
            let mut reconcile = Request::new(GetOperationReceiptRequest {
                operation_id: String::new(),
                request_id: request_id.clone(),
                caller_scope: subject::caller_scope("team-a", "root"),
                attempt: 0,
            });
            reconcile
                .metadata_mut()
                .insert("x-principal", "root".parse().unwrap());
            let reconciled = svc
                .get_operation_receipt(reconcile)
                .await
                .unwrap()
                .into_inner();
            assert!(reconciled.complete);
            assert_eq!(
                first.receipt_digest,
                format!(
                    "sha256:{:x}",
                    sha2::Sha256::digest(reconciled.receipt_json.as_bytes())
                )
            );
            let serialized = serde_json::to_string(&receipt).unwrap();
            for forbidden in [
                "subject_payload",
                "repository_path",
                "prompt",
                "credential",
                "raw_tool_output",
            ] {
                assert!(!serialized.contains(forbidden));
            }
        }
    }

    #[tokio::test]
    async fn governed_subject_rejects_changed_bindings_and_unauthorized_callers() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        svc.evaluate_governed_subject(governed_subject_request(
            "binding-conflict",
            subject::POLICY_BUNDLE_PROFILE,
            subject::ALLOW_PROFILE,
            now,
        ))
        .await
        .unwrap();
        let conflict = svc
            .evaluate_governed_subject(governed_subject_request(
                "binding-conflict",
                subject::POLICY_BUNDLE_PROFILE,
                subject::DENY_PROFILE,
                now,
            ))
            .await
            .unwrap_err();
        assert_eq!(conflict.code(), tonic::Code::AlreadyExists);

        let mut unauthorized = governed_subject_request(
            "unauthorized",
            subject::POLICY_BUNDLE_PROFILE,
            subject::ALLOW_PROFILE,
            now,
        );
        unauthorized
            .metadata_mut()
            .insert("x-principal", "intruder".parse().unwrap());
        let denied = svc
            .evaluate_governed_subject(unauthorized)
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn governed_subject_returns_fixed_failures_without_diagnostics() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        for (index, profile, expected_decision, expected_code) in [
            (0, subject::DENY_PROFILE, "deny", ""),
            (
                1,
                subject::UNAVAILABLE_PROFILE,
                "unavailable",
                "evaluation_unavailable",
            ),
            (2, subject::TIMEOUT_PROFILE, "unknown", "evaluation_timeout"),
        ] {
            let result = svc
                .evaluate_governed_subject(governed_subject_request(
                    &format!("fixed-outcome-{index}"),
                    subject::POLICY_BUNDLE_PROFILE,
                    profile,
                    now,
                ))
                .await
                .unwrap()
                .into_inner()
                .result
                .unwrap();
            assert_eq!(result.decision, expected_decision);
            assert_eq!(result.failure_code, expected_code);
            assert!(!result.failure_message.contains('/'));
        }
        let stale = svc
            .evaluate_governed_subject(governed_subject_request(
                "stale-outcome",
                subject::POLICY_BUNDLE_PROFILE,
                subject::ALLOW_PROFILE,
                now - subject::MAX_EVIDENCE_AGE_MS - 1,
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        assert_eq!(stale.decision, "unknown");
        assert_eq!(stale.failure_code, "stale_evidence");
        assert!(!stale.fresh);
    }

    fn governed_subject_provenance_request(
        export_id: &str,
        result: &GovernedSubjectResult,
    ) -> Request<ExportGovernedSubjectProvenanceRequest> {
        let mut request = Request::new(ExportGovernedSubjectProvenanceRequest {
            export_id: export_id.into(),
            operation_id: result.operation_id.clone(),
            expected_subject_identity: "subject-1".into(),
            expected_subject_content_digest: format!("sha256:{}", "a".repeat(64)),
            expected_manifest_digest: format!("sha256:{}", "a".repeat(64)),
            expected_artifact_digest: format!("sha256:{}", "a".repeat(64)),
            expected_receipt_digest: result.receipt_digest.clone(),
        });
        request
            .metadata_mut()
            .insert("x-principal", "root".parse().unwrap());
        request
    }

    #[tokio::test]
    async fn governed_subject_provenance_is_tenkai_compatible_and_replay_safe() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        let result = svc
            .evaluate_governed_subject(governed_subject_request(
                "provenance-release",
                subject::SOFTWARE_RELEASE_PROFILE,
                subject::ALLOW_PROFILE,
                now,
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();

        let first = svc
            .export_governed_subject_provenance(governed_subject_provenance_request(
                "publish-1",
                &result,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(!first.replayed);
        let envelope = first.envelope.clone().unwrap();
        assert_eq!(envelope.profile, subject_provenance::PROFILE);
        assert_eq!(envelope.issuer, subject_provenance::ISSUER);
        assert_eq!(envelope.decision, "allow");
        assert_eq!(envelope.receipt_schema, subject::RECEIPT_SCHEMA_VERSION);
        assert_eq!(envelope.receipt_digest, result.receipt_digest);
        assert_eq!(envelope.governed_references.len(), 1);
        assert_eq!(envelope.governed_references[0].kind, "operation");
        assert_eq!(
            envelope.content_digest,
            subject_provenance::release_content_digest(
                &format!("sha256:{}", "a".repeat(64)),
                &format!("sha256:{}", "a".repeat(64))
            )
            .unwrap()
        );

        let replay = svc
            .export_governed_subject_provenance(governed_subject_provenance_request(
                "publish-1",
                &result,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(replay.replayed);
        assert_eq!(replay.envelope, first.envelope);
        assert_eq!(replay.envelope_digest, first.envelope_digest);

        let root = first.trust_root.unwrap();
        assert_eq!(root.version, subject_provenance::TRUST_ROOT_VERSION);
        assert_eq!(root.identity, subject_provenance::ISSUER);
        assert_eq!(root.key_id, envelope.issuer_key_id);
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(root.public_key)
            .unwrap();
        let domain_envelope = subject_provenance::ProvenanceEnvelope {
            profile: envelope.profile,
            issuer: envelope.issuer,
            issuer_key_id: envelope.issuer_key_id,
            subject: envelope.subject,
            content_digest: envelope.content_digest,
            decision: envelope.decision,
            receipt_schema: envelope.receipt_schema,
            receipt_digest: envelope.receipt_digest,
            governed_references: envelope
                .governed_references
                .into_iter()
                .map(|reference| subject_provenance::GovernedReference {
                    kind: reference.kind,
                    id: reference.id,
                    digest: reference.digest,
                })
                .collect(),
            observed_at_unix_ms: envelope.observed_at_unix_ms,
            expires_at_unix_ms: envelope.expires_at_unix_ms,
            signature: envelope.signature,
        };
        domain_envelope
            .verify(
                public_key.as_slice().try_into().unwrap(),
                chrono::Utc::now().timestamp_millis(),
            )
            .unwrap();

        svc.db
            .ensure_team_namespace("team-a", "alice", Role::Editor, "root")
            .unwrap();
        let mut delegated = governed_subject_provenance_request("publish-delegated", &result);
        delegated
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        assert!(
            svc.export_governed_subject_provenance(delegated)
                .await
                .unwrap()
                .into_inner()
                .envelope
                .is_some()
        );
    }

    #[tokio::test]
    async fn governed_subject_provenance_fails_closed_and_preserves_rotated_roots() {
        let svc = memory_service();
        let now = chrono::Utc::now().timestamp_millis();
        let result = svc
            .evaluate_governed_subject(governed_subject_request(
                "provenance-failures",
                subject::SOFTWARE_RELEASE_PROFILE,
                subject::ALLOW_PROFILE,
                now,
            ))
            .await
            .unwrap()
            .into_inner()
            .result
            .unwrap();
        let first = svc
            .export_governed_subject_provenance(governed_subject_provenance_request(
                "rotation-old",
                &result,
            ))
            .await
            .unwrap()
            .into_inner()
            .envelope
            .unwrap();

        let mut conflict = governed_subject_provenance_request("rotation-old", &result);
        conflict.get_mut().expected_artifact_digest = format!("sha256:{}", "b".repeat(64));
        assert_eq!(
            svc.export_governed_subject_provenance(conflict)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
        for (index, export_id) in [
            "mismatch-subject",
            "mismatch-subject-content",
            "mismatch-receipt",
            "mismatch-content",
        ]
        .into_iter()
        .enumerate()
        {
            let mut request = governed_subject_provenance_request(export_id, &result);
            match index {
                0 => request.get_mut().expected_subject_identity = "other-subject".into(),
                1 => {
                    request.get_mut().expected_subject_content_digest =
                        format!("sha256:{}", "b".repeat(64))
                }
                2 => {
                    request.get_mut().expected_receipt_digest = format!("sha256:{}", "b".repeat(64))
                }
                3 => {
                    request.get_mut().expected_manifest_digest =
                        format!("sha256:{}", "b".repeat(64))
                }
                _ => unreachable!("fixed mismatch cases"),
            }
            assert_eq!(
                svc.export_governed_subject_provenance(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::FailedPrecondition
            );
        }

        let mut rotated_config = config(":memory:");
        rotated_config.governed_subject_provenance_signing_key = Some("0a".repeat(32));
        let rotated = ChiseiServiceImpl::new(svc.db.clone(), rotated_config);
        let second = rotated
            .export_governed_subject_provenance(governed_subject_provenance_request(
                "rotation-new",
                &result,
            ))
            .await
            .unwrap()
            .into_inner()
            .envelope
            .unwrap();
        assert_ne!(first.issuer_key_id, second.issuer_key_id);
        let interrupted_replay = rotated
            .export_governed_subject_provenance(governed_subject_provenance_request(
                "rotation-old",
                &result,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(interrupted_replay.replayed);
        assert_eq!(
            interrupted_replay.envelope.unwrap().issuer_key_id,
            first.issuer_key_id
        );

        let old_root = interrupted_replay.trust_root.unwrap();
        assert_eq!(old_root.key_id, first.issuer_key_id);

        let mut short_lived_config = config(":memory:");
        short_lived_config.governed_subject_provenance_ttl_ms = 1;
        let short_lived = ChiseiServiceImpl::new(svc.db.clone(), short_lived_config);
        short_lived
            .export_governed_subject_provenance(governed_subject_provenance_request(
                "short-lived",
                &result,
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(
            short_lived
                .export_governed_subject_provenance(governed_subject_provenance_request(
                    "short-lived",
                    &result,
                ))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );

        let mut expired_config = config(":memory:");
        expired_config.governed_subject_provenance_key_expires_at_ms = now;
        let expired = ChiseiServiceImpl::new(svc.db.clone(), expired_config);
        assert_eq!(
            expired
                .export_governed_subject_provenance(governed_subject_provenance_request(
                    "expired-key",
                    &result,
                ))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );

        let unauthenticated = Request::new(
            governed_subject_provenance_request("unauthenticated", &result).into_inner(),
        );
        assert_eq!(
            rotated
                .export_governed_subject_provenance(unauthenticated)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    fn external_action_request(
        actor: &str,
        idempotency_key: &str,
    ) -> Request<AuthorizeExternalActionRequest> {
        let mut request = Request::new(AuthorizeExternalActionRequest {
            request: Some(ExternalActionRequest {
                version: external::REQUEST_VERSION.into(),
                operation_id: "op-ext-1".into(),
                parent_operation_id: String::new(),
                attempt_id: "attempt-1".into(),
                request_id: "request-1".into(),
                actor: actor.into(),
                namespace: "team-a".into(),
                requesting_harness: "harness-a".into(),
                intended_executor: "executor-a".into(),
                action_type: "repository.write/v1".into(),
                parameter_schema: "repository.write.params/v1".into(),
                canonical_arguments_digest: "sha256:arguments".into(),
                policy_summary: HashMap::from([("repository".into(), "example/repo".into())]),
                target_selectors: vec!["project:team-a/repo:example/repo".into()],
                immutable_preconditions: HashMap::from([("head".into(), "abc123".into())]),
                risk_class: "write".into(),
                expected_effects: vec!["git.commit".into()],
                requested_invocation_count: 1,
                deadline_ms: 4_102_444_800_000,
                estimated_cost_micros: 0,
                estimated_volume: 1,
                affected_resource_count: 1,
                rollback_capability: "revert_commit".into(),
                required_host_capabilities: vec!["git.ref-precondition/v1".into()],
                idempotency_key: idempotency_key.into(),
                policy_project: "team-a".into(),
            }),
            offline: false,
        });
        request
            .metadata_mut()
            .insert("x-principal", actor.parse().unwrap());
        request
    }

    #[tokio::test]
    async fn external_action_authorization_allows_and_replays_idempotently() {
        let svc = memory_service();
        let first = svc
            .authorize_external_action(external_action_request("local", "idem-allow"))
            .await
            .unwrap()
            .into_inner();
        let replay = svc
            .authorize_external_action(external_action_request("local", "idem-allow"))
            .await
            .unwrap()
            .into_inner();
        let first_decision = first.decision.unwrap();
        let replay_decision = replay.decision.unwrap();
        assert_eq!(first_decision.decision, "permit");
        assert_eq!(
            replay_decision.authorization_id,
            first_decision.authorization_id
        );
        assert_eq!(
            replay.permit.unwrap().permit_id,
            first.permit.unwrap().permit_id
        );
        assert!(first_decision.assurance.unwrap().authorization_only);
    }

    #[tokio::test]
    async fn external_action_authorization_denies_by_policy_and_expiry() {
        let svc = memory_service();
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("agent:local");
        policy.action_overrides.insert(
            "external_action/repository.write/v1".into(),
            ActionDecision::Deny,
        );
        svc.db.upsert_action_policy(&policy).unwrap();
        let denied = svc
            .authorize_external_action(external_action_request("local", "idem-deny"))
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        assert_eq!(denied.decision, "deny");

        svc.db
            .upsert_action_policy(&crate::sekai::action_policy::ActionPolicy::allow_all(
                "agent:local",
            ))
            .unwrap();
        let mut expired = external_action_request("local", "idem-expired");
        expired.get_mut().request.as_mut().unwrap().deadline_ms = 1;
        let expired = svc
            .authorize_external_action(expired)
            .await
            .unwrap()
            .into_inner()
            .decision
            .unwrap();
        assert_eq!(expired.decision, "deny");
        assert!(expired.reason.contains("expired"));
    }

    #[tokio::test]
    async fn external_action_authorization_rejects_namespace_and_idempotency_abuse() {
        let svc = memory_service();
        let unauthorized = svc
            .authorize_external_action(external_action_request("agent-x", "idem-unauthorized"))
            .await
            .unwrap_err();
        assert_eq!(unauthorized.code(), tonic::Code::PermissionDenied);

        svc.authorize_external_action(external_action_request("local", "idem-conflict"))
            .await
            .unwrap();
        let mut conflict = external_action_request("local", "idem-conflict");
        conflict
            .get_mut()
            .request
            .as_mut()
            .unwrap()
            .target_selectors = vec!["project:team-a/repo:other/repo".into()];
        let conflict = svc.authorize_external_action(conflict).await.unwrap_err();
        assert_eq!(conflict.code(), tonic::Code::AlreadyExists);
    }

    fn effective_summary_request(
        namespace: &str,
        principal: &str,
    ) -> Request<GetEffectivePolicySummaryRequest> {
        let mut request = Request::new(GetEffectivePolicySummaryRequest {
            namespace: namespace.into(),
            provider: String::new(),
        });
        request
            .metadata_mut()
            .insert("x-principal", principal.parse().unwrap());
        request
    }

    fn available_models_request(
        namespace: &str,
        provider: &str,
        principal: Option<&str>,
    ) -> Request<GetEffectivePolicySummaryRequest> {
        let mut request = Request::new(GetEffectivePolicySummaryRequest {
            namespace: namespace.into(),
            provider: provider.into(),
        });
        if let Some(principal) = principal {
            request
                .metadata_mut()
                .insert("x-principal", principal.parse().unwrap());
        }
        request
    }

    #[tokio::test]
    async fn available_models_are_authenticated_namespace_scoped_and_filterable() {
        let svc = memory_service();
        svc.db
            .ensure_team_namespace("acme", "alice", Role::Viewer, "local")
            .unwrap();

        let missing_auth = svc
            .get_effective_policy_summary(available_models_request("acme", "", None))
            .await
            .unwrap_err();
        assert_eq!(missing_auth.code(), tonic::Code::Unauthenticated);
        let denied = svc
            .get_effective_policy_summary(available_models_request("acme", "", Some("mallory")))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        let response = svc
            .get_effective_policy_summary(available_models_request("acme", "native", Some("alice")))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.namespace, "acme");
        assert_eq!(response.models.len(), 1);
        assert_eq!(response.models[0].provider, "native");
        assert_eq!(response.models[0].canonical_model, "native/native-default");
        assert!(response.models[0].capabilities.is_some());
        assert!(response.models[0].pricing.is_some());
    }

    #[tokio::test]
    async fn effective_policy_summary_is_authorized_bounded_and_live() {
        use crate::sekai::action::RiskClass;
        use crate::sekai::action_policy::{ActionDecision, ActionPolicy};

        let svc = memory_service();
        svc.db
            .ensure_team_namespace("acme", "alice", Role::Viewer, "local")
            .unwrap();
        svc.policy.set_namespace_policy(
            "acme",
            Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: "internal".into(),
            },
        );
        svc.db
            .budget_set_limit("global", METRIC_REQUESTS, 100, "daily")
            .unwrap();
        svc.db
            .budget_set_limit("project:acme", METRIC_TOKENS, 1_000, "weekly")
            .unwrap();
        svc.db
            .budget_adjust_chain("project:acme", METRIC_TOKENS, 37, 1)
            .unwrap();
        let mut action_policy = ActionPolicy::allow_all("project:acme");
        action_policy
            .action_overrides
            .insert("shell.exec".into(), ActionDecision::RequireApproval);
        action_policy
            .risk_overrides
            .insert(RiskClass::Destructive, ActionDecision::Deny);
        svc.db.upsert_action_policy(&action_policy).unwrap();
        let denied = svc
            .get_effective_policy_summary(effective_summary_request("acme", "mallory"))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let first = svc
            .get_effective_policy_summary(effective_summary_request("acme", "alice"))
            .await
            .unwrap()
            .into_inner();
        let routing = first.routing.unwrap();
        assert_eq!(routing.runtime, "openai");
        assert_eq!(routing.model, "gpt-5.5");
        assert_eq!(routing.policy_scope, "acme");
        assert_eq!(routing.policy_version.len(), 64);
        let budgets = first.budgets.unwrap();
        assert_eq!(budgets.limits.len(), 2);
        assert!(budgets.limits.iter().all(|limit| limit.max_amount != 37));
        let actions = first.actions.unwrap();
        assert_eq!(actions.allow_rule_count, 0);
        assert_eq!(actions.deny_rule_count, 1);
        assert_eq!(actions.require_approval_rule_count, 1);
        assert_eq!(actions.default_decision, "allow");
        svc.policy.set_namespace_policy(
            "acme",
            Policy {
                allowed_runtimes: vec!["anthropic".into()],
                allowed_models: vec!["claude-sonnet-4-20250514".into()],
                default_runtime: "anthropic".into(),
                default_model: "claude-sonnet-4-20250514".into(),
                data_class: "internal".into(),
            },
        );
        svc.db
            .budget_set_limit("project:acme", METRIC_TOKENS, 2_000, "weekly")
            .unwrap();
        let changed = svc
            .get_effective_policy_summary(effective_summary_request("acme", "alice"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            changed
                .budgets
                .unwrap()
                .limits
                .into_iter()
                .find(|limit| limit.metric == METRIC_TOKENS)
                .unwrap()
                .max_amount,
            2_000
        );
        assert_eq!(changed.routing.unwrap().runtime, "anthropic");
    }

    #[tokio::test]
    async fn effective_policy_summary_reports_unconfigured_sections() {
        let svc = memory_service();
        svc.db
            .ensure_team_namespace("empty", "alice", Role::Viewer, "local")
            .unwrap();
        let summary = svc
            .get_effective_policy_summary(effective_summary_request("empty", "alice"))
            .await
            .unwrap()
            .into_inner();
        for (configured, status) in [
            (summary.routing.unwrap().configured, "routing"),
            (summary.budgets.unwrap().configured, "budgets"),
            (summary.actions.unwrap().configured, "actions"),
        ] {
            assert!(!configured, "{status} unexpectedly configured");
        }
    }

    fn file_service(path: &str) -> ChiseiServiceImpl {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path).unwrap())));
        ChiseiServiceImpl::new(db, config(path))
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
            route_override: String::new(),
            capability_requirements_json: Vec::new(),
        }
    }

    fn create_suite(svc: &ChiseiServiceImpl, namespace: &str) {
        svc.eval
            .put_suite(crate::chisei::eval::Suite {
                id: "suite-1".into(),
                name: "suite".into(),
                description: String::new(),
                cases: std::iter::once(crate::chisei::eval::Case {
                    id: "case-1".into(),
                    name: "case".into(),
                    namespace: namespace.into(),
                    spec: "spec".into(),
                    assertions: vec![],
                })
                .chain((1..=MIN_EVIDENCE_CONTEXT_EVAL_CASES).map(|case| {
                    crate::chisei::eval::Case {
                        id: format!("evidence-case-{case}"),
                        name: format!("evidence case {case}"),
                        namespace: namespace.into(),
                        spec: "compare decision quality with and without evidence".into(),
                        assertions: vec![],
                    }
                }))
                .collect(),
            })
            .unwrap();
    }

    fn seed_eval_run(
        svc: &ChiseiServiceImpl,
        run: crate::chisei::eval::Run,
        changed_file: impl AsRef<str>,
        diff_hash: impl AsRef<str>,
    ) {
        let changed_file = changed_file.as_ref();
        let diff_hash = diff_hash.as_ref();
        let suite_id = run.suite_id.clone();
        let run_id = run.id.clone();
        svc.eval
            .put_run(crate::chisei::eval::Run {
                id: run.id,
                suite_id: run.suite_id,
                config_ref: run.config_ref,
                results: run
                    .results
                    .into_iter()
                    .map(|result| crate::chisei::eval::CaseResult {
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
            })
            .unwrap();
        if !changed_file.is_empty() {
            svc.eval
                .track_iteration(&suite_id, &run_id, changed_file, diff_hash)
                .unwrap();
        }
    }

    fn eval_run(id: &str, suite_id: &str, score: i32, timestamp: i64) -> crate::chisei::eval::Run {
        crate::chisei::eval::Run {
            id: id.into(),
            suite_id: suite_id.into(),
            config_ref: "native-default".into(),
            results: vec![crate::chisei::eval::CaseResult {
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
    ) -> crate::chisei::eval::Run {
        crate::chisei::eval::Run {
            id: id.into(),
            suite_id: suite_id.into(),
            config_ref: evidence_context_config_ref(source_type, evidence_type, with_evidence),
            results: (1..=MIN_EVIDENCE_CONTEXT_EVAL_CASES)
                .map(|case| crate::chisei::eval::CaseResult {
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

    fn run_test_gateway_pipeline(
        svc: &ChiseiServiceImpl,
        request_id: &str,
        namespace: &str,
        spec: &str,
        task_class: &str,
    ) -> GatewayPipelineDecision {
        svc.gateway_pipeline_decision(GatewayPipelineInput {
            actor: "local",
            delegated_principal: None,
            request_id,
            namespace,
            spec,
            model: "native-default",
            runtime: "native",
            task_class,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn gunshi_scorecards_require_namespace_membership() {
        let svc = memory_service();
        svc.db
            .ensure_team_namespace(
                "acme",
                "alice",
                crate::sekai::security::Role::Viewer,
                "local",
            )
            .unwrap();
        let mut denied = Request::new(GetGunshiAllocationStatusRequest {
            namespace: "acme".into(),
        });
        denied
            .metadata_mut()
            .insert("x-principal", "bob".parse().unwrap());
        assert_eq!(
            svc.get_gunshi_allocation_status(denied)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );

        let mut allowed = Request::new(GetGunshiAllocationStatusRequest {
            namespace: "acme".into(),
        });
        allowed
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        let scorecard: crate::chisei::gunshi::AdvisoryScorecard = serde_json::from_str(
            &svc.get_gunshi_allocation_status(allowed)
                .await
                .unwrap()
                .into_inner()
                .scorecard_json,
        )
        .unwrap();
        assert_eq!(scorecard.comparisons, 0);
        assert!(require_namespace_write_access(&svc.db, "alice", "acme").is_err());
        svc.db
            .ensure_team_namespace(
                "acme",
                "alice",
                crate::sekai::security::Role::Editor,
                "local",
            )
            .unwrap();
        require_namespace_write_access(&svc.db, "alice", "acme").unwrap();
    }

    #[tokio::test]
    async fn configuration_mutations_require_control_plane_administration() {
        let svc = memory_service();
        let mut budget = Request::new(SetBudgetLimitRequest {
            subject: "project:acme".into(),
            max_tokens: 1_000,
            period_type: "week".into(),
            ..Default::default()
        });
        budget
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        assert_eq!(
            svc.set_budget_limit(budget).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );

        let mut policy = Request::new(SetNamespacePolicyRequest {
            namespace: "acme".into(),
            ..Default::default()
        });
        policy
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        assert_eq!(
            svc.set_namespace_policy(policy).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[test]
    fn team_execution_uses_authenticated_namespace_and_budget_scope() {
        let svc = memory_service();
        svc.db
            .create_object(&Object {
                id: "existing-namespace-acme".into(),
                kind: "namespace".into(),
                name: "Acme".into(),
                namespace: String::new(),
                external_id: "namespace:acme".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_grant(&crate::sekai::security::Grant {
                id: "alice-acme".into(),
                object_id: "existing-namespace-acme".into(),
                principal: "alice".into(),
                role: crate::sekai::security::Role::Viewer,
                created: 1,
            })
            .unwrap();

        require_namespace_access(&svc.db, "alice", "acme").unwrap();
        assert_eq!(
            require_namespace_access(&svc.db, "alice", " acme ")
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            require_namespace_access(&svc.db, "mallory", "acme")
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        require_execution_namespace_access(&svc.db, &svc.config, "chisei-gateway", "unmanaged")
            .unwrap();
        assert_eq!(
            require_execution_namespace_access(&svc.db, &svc.config, "alice", "unmanaged")
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            execution_budget_scope("acme", "alice", "forged"),
            "project:acme/agent:alice"
        );
        assert_eq!(execution_budget_scope("acme", "local", "forged"), "forged");
        assert_eq!(execution_budget_scope("acme", "root", ""), "default");
        assert_eq!(
            strongest_pressure(
                crate::chisei::budget::PressureLevel::None,
                crate::chisei::budget::PressureLevel::Critical,
            ),
            crate::chisei::budget::PressureLevel::Critical
        );
        svc.budget
            .set_limit(
                "project:acme",
                100,
                crate::chisei::budget::PeriodType::Weekly,
            )
            .unwrap();
        svc.budget.record("project:acme/agent:alice", 95);
        assert_eq!(
            svc.budget.scope_pressure("project:acme/agent:alice"),
            crate::chisei::budget::PressureLevel::Critical
        );
    }

    #[tokio::test]
    async fn team_policy_resolution_requires_namespace_membership() {
        let svc = memory_service();
        svc.db
            .ensure_team_namespace(
                "acme",
                "alice",
                crate::sekai::security::Role::Viewer,
                "local",
            )
            .unwrap();
        let mut request = Request::new(ResolvePolicyRequest {
            namespace: "beta".into(),
            ..Default::default()
        });
        request
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        assert_eq!(
            svc.resolve_policy(request).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );

        let mut unmanaged = Request::new(ResolvePolicyRequest {
            namespace: "acme".into(),
            ..Default::default()
        });
        unmanaged
            .metadata_mut()
            .insert("x-principal", "unmanaged-principal".parse().unwrap());
        assert_eq!(
            svc.resolve_policy(unmanaged).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn team_principals_cannot_mutate_usage_accounting() {
        let svc = memory_service();
        let mut request = Request::new(RecordUsageRequest {
            subject: "project:acme".into(),
            tokens_used: -10,
            idempotency_key: "forged-reset".into(),
            ..Default::default()
        });
        request
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        assert_eq!(
            svc.record_usage(request).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );

        let mut sample = Request::new(RecordUsageRequest {
            sample_observation: Some(SampleObservation {
                request_id: "forged".into(),
                namespace: "other-team".into(),
                spec: "forged".into(),
                output_content: "forged".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        sample
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        assert_eq!(
            svc.record_usage(sample).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn cached_plan_execution_rechecks_namespace_membership() {
        let svc = memory_service();
        svc.db
            .create_object(&Object {
                id: "namespace-revocation".into(),
                kind: "namespace".into(),
                name: "Revocation".into(),
                namespace: String::new(),
                external_id: "namespace:revocation".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        svc.db
            .create_grant(&crate::sekai::security::Grant {
                id: "revocation-alice".into(),
                object_id: "namespace-revocation".into(),
                principal: "alice".into(),
                role: crate::sekai::security::Role::Viewer,
                created: 1,
            })
            .unwrap();
        let mut planning = Request::new(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "revoked-plan".into(),
                namespace: "revocation".into(),
                spec: "summarize".into(),
                preferred_model: "native-default".into(),
                preferred_runtime: "kiro".into(),
                user_id: "forged".into(),
                max_tokens: 16,
                ..Default::default()
            }),
            gunshi_allocation: None,
        });
        planning
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        let plan = svc
            .plan_execution(planning)
            .await
            .unwrap()
            .into_inner()
            .plan
            .unwrap();
        svc.db.delete_grant("revocation-alice").unwrap();

        let mut execution = Request::new(ExecutePlanRequest { plan: Some(plan) });
        execution
            .metadata_mut()
            .insert("x-principal", "alice".parse().unwrap());
        assert_eq!(
            svc.execute_plan(execution).await.unwrap_err().code(),
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
    async fn internal_gateway_pipeline_audits_and_applies_the_context_expansion_gate() {
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

        let denied =
            run_test_gateway_pipeline(&svc, "before-eval", "acme", "inspect ticker:AAPL", "");
        assert!(denied.run.prepared_spec.contains("score: 0.82"));
        assert!(
            !denied
                .run
                .prepared_spec
                .contains("validate the filing date")
        );
        assert!(denied.run.evidence_references.is_empty());

        create_suite(&svc, "acme");
        let profile = pipeline_context_expansion_profile_key("acme");
        for (id, score, timestamp) in [("context-base", 90, 1), ("context-pass", 95, 2)] {
            seed_eval_run(
                &svc,
                eval_run(id, "suite-1", score, timestamp),
                &profile,
                format!("hash-{id}"),
            );
        }
        let allowed =
            run_test_gateway_pipeline(&svc, "after-eval", "acme", "inspect ticker:AAPL", "");
        assert!(
            allowed
                .run
                .prepared_spec
                .contains("validate the filing date")
        );
        assert!(allowed.run.evidence_references.is_empty());
        assert!(!allowed.run.prepared_spec.contains("result=passed"));

        let class_profile =
            evidence_context_profile_key("acme", "verification_system", "verification.result");
        for (id, with_evidence, score, timestamp) in [
            ("evidence-base", false, 90, 3),
            ("evidence-pass", true, 95, 4),
        ] {
            seed_eval_run(
                &svc,
                evidence_eval_run(
                    id,
                    "suite-1",
                    "verification_system",
                    "verification.result",
                    with_evidence,
                    score,
                    timestamp,
                ),
                &class_profile,
                format!("hash-{id}"),
            );
        }
        let class_gate =
            svc.evidence_context_gate("acme", "verification_system", "verification.result", true);
        assert!(class_gate.effective_allowed);
        assert_eq!(class_gate.gate.verdict, "pass");
        assert_eq!(class_gate.gate.profile_key, class_profile);

        let invalid_profile = evidence_context_profile_key(
            "acme",
            "verification_system",
            "operations.health_snapshot",
        );
        for (id, score, timestamp) in [("invalid-base", 90, 5), ("invalid-pass", 95, 6)] {
            seed_eval_run(
                &svc,
                eval_run(id, "suite-1", score, timestamp),
                &invalid_profile,
                format!("hash-{id}"),
            );
        }
        let invalid_gate = svc.evidence_context_gate(
            "acme",
            "verification_system",
            "operations.health_snapshot",
            true,
        );
        assert!(!invalid_gate.effective_allowed);
        assert_eq!(invalid_gate.gate.verdict, "invalid_comparison");

        let evidence_allowed = run_test_gateway_pipeline(
            &svc,
            "after-evidence-eval",
            "acme",
            "inspect ticker:AAPL",
            "",
        );
        assert!(evidence_allowed.run.prepared_spec.contains("result=passed"));
        assert_eq!(evidence_allowed.run.evidence_references.len(), 1);
        assert_eq!(
            evidence_allowed.run.evidence_references[0].submission_id,
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
        create_suite(&svc, "acme");
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
            seed_eval_run(&svc, run, &profile, format!("hash-{id}"));
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
        create_suite(&svc, "acme");

        let context_profile = pipeline_context_expansion_profile_key("acme");
        for (id, score, timestamp) in [("context-base", 90, 1), ("context-pass", 95, 2)] {
            seed_eval_run(
                &svc,
                eval_run(id, "suite-1", score, timestamp),
                &context_profile,
                format!("hash-{id}"),
            );
        }

        let verification_profile =
            evidence_context_profile_key("acme", "verification_system", "verification.result");
        for (id, with_evidence, score, timestamp) in [
            ("verification-base", false, 90, 3),
            ("verification-pass", true, 95, 4),
        ] {
            seed_eval_run(
                &svc,
                evidence_eval_run(
                    id,
                    "suite-1",
                    "verification_system",
                    "verification.result",
                    with_evidence,
                    score,
                    timestamp,
                ),
                &verification_profile,
                format!("hash-{id}"),
            );
        }

        let before_native_comparison = run_test_gateway_pipeline(
            &svc,
            "before-native-comparison",
            "acme",
            "inspect ticker:AAPL",
            "analysis",
        );
        assert!(
            before_native_comparison
                .run
                .evidence_references
                .iter()
                .any(|reference| reference.submission_id == verification_id)
        );
        assert!(
            !before_native_comparison
                .run
                .evidence_references
                .iter()
                .any(|reference| reference.submission_id == native_id)
        );
        assert!(before_native_comparison.run.memory_references.is_empty());
        assert!(svc.portfolio.points("acme", "analysis").unwrap().is_empty());

        let native_profile =
            evidence_context_profile_key("acme", "native_harness", "verification.result");
        for (id, with_evidence, score, timestamp) in
            [("native-base", false, 90, 5), ("native-pass", true, 95, 6)]
        {
            seed_eval_run(
                &svc,
                evidence_eval_run(
                    id,
                    "suite-1",
                    "native_harness",
                    "verification.result",
                    with_evidence,
                    score,
                    timestamp,
                ),
                &native_profile,
                format!("hash-{id}"),
            );
        }
        let after_native_comparison = run_test_gateway_pipeline(
            &svc,
            "after-native-comparison",
            "acme",
            "inspect ticker:AAPL",
            "analysis",
        );
        assert!(
            after_native_comparison
                .run
                .evidence_references
                .iter()
                .any(|reference| reference.submission_id == native_id)
        );
        assert!(after_native_comparison.run.memory_references.is_empty());
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
            operation_receipt_json: String::new(),
            sample_observation: None,
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
    async fn trusted_usage_accounting_persists_the_canonical_gateway_receipt() {
        let svc = memory_service();
        let operation_id = "gateway-receipt-1";
        let events = vec![
            receipt_event(
                operation_id,
                "intent",
                None,
                1,
                ReceiptEventKind::IntentRecorded,
                "agent:caller",
                BTreeMap::new(),
            ),
            receipt_event(
                operation_id,
                "policy",
                Some("intent"),
                2,
                ReceiptEventKind::PolicyDecided,
                "chisei-gateway",
                BTreeMap::new(),
            ),
            receipt_event(
                operation_id,
                "route",
                Some("policy"),
                3,
                ReceiptEventKind::RouteSelected,
                "chisei-gateway",
                BTreeMap::new(),
            ),
            receipt_event(
                operation_id,
                "budget",
                Some("route"),
                4,
                ReceiptEventKind::BudgetDecided,
                "chisei-gateway",
                BTreeMap::new(),
            ),
            receipt_event(
                operation_id,
                "outcome",
                Some("budget"),
                5,
                ReceiptEventKind::OutcomeRecorded,
                "chisei-gateway",
                BTreeMap::from([("status".into(), "completed".into())]),
            ),
        ];
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.into(),
            parent_operation_id: None,
            namespace: "acme".into(),
            operation_class: "gateway.request".into(),
            initiating_actor: "agent:caller".into(),
            schema_version: EXECUTION_SCHEMA_VERSION.into(),
            policy_version: "policy-v1".into(),
            started_at_ms: 1,
            completed_at_ms: Some(5),
            events,
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
        };
        assert!(receipt.completeness().complete);
        let usage = RecordUsageRequest {
            user_id: "agent:caller".into(),
            tokens_used: 0,
            project: "acme".into(),
            agent: "gateway".into(),
            work_unit: operation_id.into(),
            idempotency_key: "gateway-receipt-1:accounting".into(),
            operation_receipt_json: serde_json::to_string(&receipt).unwrap(),
            ..Default::default()
        };

        svc.record_usage(Request::new(usage.clone())).await.unwrap();
        assert_eq!(
            svc.db.get_operation_receipt(operation_id).unwrap(),
            Some(receipt)
        );

        let mut untrusted = Request::new(RecordUsageRequest {
            work_unit: "gateway-receipt-2".into(),
            idempotency_key: "gateway-receipt-2:accounting".into(),
            ..usage
        });
        untrusted
            .metadata_mut()
            .insert("x-principal", "agent:intruder".parse().unwrap());
        assert_eq!(
            svc.record_usage(untrusted).await.unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
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
            context_admission_policy_json: String::new(),
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
                context_admission_policy_json: String::new(),
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
                context_admission_policy_json: String::new(),
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
            context_admission_policy_json: String::new(),
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
            context_admission_policy_json: String::new(),
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
            context_admission_policy_json: String::new(),
        }))
        .await
        .unwrap();
        create_suite(&svc, "sekai-chisei");
        seed_eval_run(
            &svc,
            eval_run("run-1", "suite-1", 92, 100),
            "sekai-chisei",
            "hash-a",
        );
        seed_eval_run(
            &svc,
            eval_run("run-2", "suite-1", 60, 200),
            "sekai-chisei",
            "hash-b",
        );

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
            context_admission_policy_json: String::new(),
        }))
        .await
        .unwrap();
        create_suite(&svc, "sekai-chisei");
        // Two runs with a score drop mark the namespace as regressed.
        seed_eval_run(
            &svc,
            eval_run("run-1", "suite-1", 92, 100),
            "sekai-chisei",
            "hash-a",
        );
        seed_eval_run(
            &svc,
            eval_run("run-2", "suite-1", 60, 200),
            "sekai-chisei",
            "hash-b",
        );

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
            context_admission_policy_json: String::new(),
        }))
        .await
        .unwrap();
        for (model, quality, cost) in [("native-cheap", 85.0, 10), ("native-default", 95.0, 30)] {
            svc.portfolio
                .record(&crate::chisei::portfolio::Observation {
                    namespace: "sekai-chisei".into(),
                    task_class: "primary".into(),
                    model: model.into(),
                    prompt_variant: String::new(),
                    quality_score: quality,
                    cost_usd_micros: cost,
                    sample_count: 5,
                    updated_at: 1,
                })
                .unwrap();
        }
        svc.portfolio
            .set_objective(&crate::chisei::portfolio::Objective {
                namespace: "sekai-chisei".into(),
                mode: crate::chisei::portfolio::ObjectiveMode::MinimizeCost,
                budget_usd_micros: 100,
                quality_bar: 80.0,
                min_samples: 3,
                updated_at: 1,
            })
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

        create_suite(&svc, "sekai-chisei");
        for (id, score, timestamp) in [("run-1", 95, 100), ("run-2", 60, 200)] {
            seed_eval_run(
                &svc,
                eval_run(id, "suite-1", score, timestamp),
                "sekai-chisei",
                id,
            );
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
        let context_policy_json = serde_json::json!({
            "contract_version": crate::chisei::policy::CONTEXT_ADMISSION_POLICY_VERSION,
            "default_action": "include",
            "unknown_action": "qualify",
            "rules": []
        })
        .to_string();
        svc.set_namespace_policy(Request::new(SetNamespacePolicyRequest {
            namespace: "sekai-chisei".into(),
            allowed_runtimes: vec!["openai".into()],
            allowed_models: vec!["native-default".into()],
            default_runtime: "openai".into(),
            default_model: "native-default".into(),
            data_class: String::new(),
            context_admission_policy_json: context_policy_json,
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
        let context_policy = reloaded
            .policy
            .context_admission_policy("sekai-chisei")
            .unwrap()
            .unwrap();
        assert_eq!(
            context_policy.unknown_action,
            ContextAdmissionAction::Qualify
        );
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn internal_eval_run_tracking_is_visible_to_gateway_reads() {
        let svc = memory_service();
        create_suite(&svc, "context-a");

        seed_eval_run(
            &svc,
            eval_run("run-1", "suite-1", 90, 100),
            "skills/context-a.md",
            "hash-a",
        );
        seed_eval_run(
            &svc,
            eval_run("run-2", "suite-1", 70, 200),
            "skills/context-a.md",
            "hash-b",
        );

        let latest = svc
            .eval
            .latest_iteration_for_file("skills/context-a.md")
            .unwrap();
        assert_eq!(latest.baseline_run_id, "run-1");
        assert_eq!(latest.candidate_run_id, "run-2");
        assert!(latest.regressed);

        assert_eq!(svc.eval.list_iterations("suite-1").len(), 2);
    }

    #[tokio::test]
    async fn restored_read_contracts_return_bounded_projections() {
        let svc = memory_service();
        svc.db
            .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                request_id: "observation-1".into(),
                namespace: "context-a".into(),
                spec: "private spec".into(),
                resolved_model: "native-default".into(),
                output_content: "private output".into(),
                sample_reason: "threshold".into(),
                input_tokens: 1,
                output_tokens: 2,
                stop_reason: "stop".into(),
                timestamp: 100,
                scored: false,
                task_class: "primary".into(),
                cost_usd_micros: 3,
            })
            .unwrap();

        let mut observation_request = Request::new(GetSampleObservationRequest {
            request_id: "observation-1".into(),
            namespace: "context-a".into(),
        });
        observation_request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let observation = svc
            .get_sample_observation(observation_request)
            .await
            .unwrap()
            .into_inner()
            .observation
            .unwrap();
        assert_eq!(observation.request_id, "observation-1");
        assert_eq!(observation.namespace, "context-a");
        assert_eq!(observation.state, "recorded");
        assert_eq!(observation.observed_at, 100);
        assert!(observation.observation_digest.starts_with("sha256:"));

        svc.eval
            .put_suite(crate::chisei::eval::Suite {
                id: "suite-read".into(),
                name: "suite".into(),
                description: "readback".into(),
                cases: vec![crate::chisei::eval::Case {
                    id: "case-1".into(),
                    name: "case".into(),
                    namespace: "context-a".into(),
                    spec: "spec".into(),
                    assertions: vec![],
                }],
            })
            .unwrap();
        let suite = svc.eval.get_suite("suite-read").unwrap();
        let suite_digest = evaluation_gate_suite_digest(&suite);
        let config_ref = evaluation_gate_config_ref("release", "artifact", &suite_digest);
        svc.eval
            .put_run(crate::chisei::eval::Run {
                id: "run-read".into(),
                suite_id: "suite-read".into(),
                config_ref,
                results: vec![crate::chisei::eval::CaseResult {
                    case_id: "case-1".into(),
                    passed: true,
                    status: "passed".into(),
                    result: "ok".into(),
                    score: 100,
                    reason: String::new(),
                    elapsed: 1,
                }],
                timestamp: 101,
            })
            .unwrap();

        let mut gate_request = Request::new(GetEvaluationGateEvidenceRequest {
            suite_id: "suite-read".into(),
            release_digest: "release".into(),
            artifact_digest: "artifact".into(),
            max_timestamp_ms: 101,
        });
        gate_request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let evidence = svc
            .get_evaluation_gate_evidence(gate_request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(evidence.status, EVALUATION_GATE_STATUS_FOUND);
        let evidence = evidence.evidence.unwrap();
        assert_eq!(evidence.suite_id, "suite-read");
        assert_eq!(evidence.run_id, "run-read");
        assert_eq!(evidence.expected_case_ids, vec!["case-1"]);
        assert_eq!(evidence.results.len(), 1);
        assert!(evidence.results[0].passed);
    }

    #[tokio::test]
    async fn evaluation_gate_evidence_selects_latest_bound_run_and_redacts_details() {
        let svc = memory_service();
        let suite = crate::chisei::eval::Suite {
            id: "gate-suite".into(),
            name: "release gate".into(),
            description: "private suite description".into(),
            cases: vec![
                crate::chisei::eval::Case {
                    id: "case-a".into(),
                    name: "private case".into(),
                    namespace: "private".into(),
                    spec: "private spec".into(),
                    assertions: vec![crate::chisei::eval::Assertion {
                        assert_type: "contains".into(),
                        value: "private assertion".into(),
                    }],
                },
                crate::chisei::eval::Case {
                    id: "case-b".into(),
                    name: "case b".into(),
                    namespace: "private".into(),
                    spec: "private spec b".into(),
                    assertions: vec![],
                },
            ],
        };
        svc.eval.put_suite(suite.clone()).unwrap();
        let suite_digest = evaluation_gate_suite_digest(&suite);
        let config_ref = evaluation_gate_config_ref("release", "artifact", &suite_digest);
        for run in [
            crate::chisei::eval::Run {
                id: "current-old".into(),
                suite_id: suite.id.clone(),
                config_ref: config_ref.clone(),
                results: vec![crate::chisei::eval::CaseResult {
                    case_id: "case-a".into(),
                    passed: true,
                    status: "passed".into(),
                    result: "old raw result".into(),
                    score: 99,
                    reason: "old private reason".into(),
                    elapsed: 10,
                }],
                timestamp: 100,
            },
            crate::chisei::eval::Run {
                id: "current-new".into(),
                suite_id: suite.id.clone(),
                config_ref: config_ref.clone(),
                results: vec![
                    crate::chisei::eval::CaseResult {
                        case_id: "case-a".into(),
                        passed: true,
                        status: "passed".into(),
                        result: "private raw result".into(),
                        score: 100,
                        reason: "private reason".into(),
                        elapsed: 11,
                    },
                    crate::chisei::eval::CaseResult {
                        case_id: "case-b".into(),
                        passed: false,
                        status: "failed".into(),
                        result: "private failure".into(),
                        score: 12,
                        reason: "private failure reason".into(),
                        elapsed: 12,
                    },
                ],
                timestamp: 200,
            },
            crate::chisei::eval::Run {
                id: "wrong-config".into(),
                suite_id: suite.id.clone(),
                config_ref: "tenkai:wrong".into(),
                results: vec![],
                timestamp: 300,
            },
        ] {
            svc.eval.put_run(run).unwrap();
        }

        let mut request = Request::new(GetEvaluationGateEvidenceRequest {
            suite_id: suite.id.clone(),
            release_digest: "release".into(),
            artifact_digest: "artifact".into(),
            max_timestamp_ms: 250,
        });
        request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let response = svc
            .get_evaluation_gate_evidence(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.status, EVALUATION_GATE_STATUS_FOUND);
        let evidence = response.evidence.unwrap();
        assert_eq!(evidence.run_id, "current-new");
        assert_eq!(evidence.run_timestamp, 200);
        assert_eq!(evidence.expected_case_ids, vec!["case-a", "case-b"]);
        assert_eq!(
            evidence
                .results
                .iter()
                .map(|result| (result.case_id.as_str(), result.passed))
                .collect::<Vec<_>>(),
            vec![("case-a", true), ("case-b", false)]
        );
    }

    #[tokio::test]
    async fn lookup_first_promotion_gate_runs_offline_and_records_audit() {
        let svc = memory_service();
        lookup_first::seed_s1_fixture_graph(&svc.db).unwrap();
        svc.db
            .ensure_team_namespace("acme", "alice", Role::Viewer, "local")
            .unwrap();

        let mut missing_source = Request::new(RunLookupFirstPromotionGateRequest {
            contract_version: lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
            namespace: "acme".into(),
            suite_json: include_str!("../../tests/fixtures/lookup_first/promotion-gate-v1.json")
                .into(),
        });
        missing_source
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        assert_eq!(
            svc.run_lookup_first_promotion_gate(missing_source)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );

        let mut request = Request::new(RunLookupFirstPromotionGateRequest {
            contract_version: lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
            namespace: "acme".into(),
            suite_json: include_str!("../../tests/fixtures/lookup_first/promotion-gate-v1.json")
                .into(),
        });
        request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        request
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "local".parse().unwrap());

        let report = svc
            .run_lookup_first_promotion_gate(request)
            .await
            .unwrap()
            .into_inner()
            .report
            .unwrap();
        assert_eq!(report.verdict, "allow");
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 0);
        assert!(!report.audit_decision_id.is_empty());
        let decision = svc
            .db
            .get_decision(&report.audit_decision_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            decision.action,
            lookup_first::LOOKUP_FIRST_GATE_AUDIT_ACTION
        );
        assert_eq!(decision.actor, "local");
        assert!(!decision.evidence.contains_key("answer_json"));

        let unauthorized_suite = serde_json::json!({
            "contract_version": lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION,
            "suite_id": "unauthorized-case-actor",
            "namespace": "acme",
            "cases": [{
                "id": "inaccessible-actor",
                "capability": crate::sekai::semantic::CAPABILITY_RESOLVE_REF,
                "namespace": "acme",
                "actor": "mallory",
                "input": {"object_id": "does-not-exist"},
                "expected_path": "model_path",
                "expected_refusal": "incomplete"
            }]
        });
        let mut unauthorized = Request::new(RunLookupFirstPromotionGateRequest {
            contract_version: lookup_first::LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
            namespace: "acme".into(),
            suite_json: unauthorized_suite.to_string(),
        });
        unauthorized
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        unauthorized
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "local".parse().unwrap());
        assert_eq!(
            svc.run_lookup_first_promotion_gate(unauthorized)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn evaluation_gate_evidence_distinguishes_missing_and_stale_or_mismatched() {
        let svc = memory_service();
        let suite = crate::chisei::eval::Suite {
            id: "gate-status-suite".into(),
            name: "gate".into(),
            description: String::new(),
            cases: vec![crate::chisei::eval::Case {
                id: "case".into(),
                name: "case".into(),
                namespace: "namespace".into(),
                spec: "spec".into(),
                assertions: vec![],
            }],
        };
        svc.eval.put_suite(suite.clone()).unwrap();
        svc.eval
            .put_run(crate::chisei::eval::Run {
                id: "stale".into(),
                suite_id: suite.id.clone(),
                config_ref: "tenkai:not-current".into(),
                results: vec![],
                timestamp: 100,
            })
            .unwrap();

        let request = |suite_id: &str, release_digest: &str| {
            let mut request = Request::new(GetEvaluationGateEvidenceRequest {
                suite_id: suite_id.into(),
                release_digest: release_digest.into(),
                artifact_digest: "artifact".into(),
                max_timestamp_ms: 200,
            });
            request
                .metadata_mut()
                .insert("x-principal", "local".parse().unwrap());
            request
        };
        assert_eq!(
            svc.get_evaluation_gate_evidence(request("missing", "release"))
                .await
                .unwrap()
                .into_inner()
                .status,
            EVALUATION_GATE_STATUS_SUITE_NOT_FOUND
        );
        assert_eq!(
            svc.get_evaluation_gate_evidence(request(&suite.id, "release"))
                .await
                .unwrap()
                .into_inner()
                .status,
            EVALUATION_GATE_STATUS_NO_MATCHING_RUN
        );
    }

    #[tokio::test]
    async fn evaluation_gate_evidence_rejects_malformed_selected_results() {
        let svc = memory_service();
        let suite = crate::chisei::eval::Suite {
            id: "gate-integrity-suite".into(),
            name: "gate".into(),
            description: String::new(),
            cases: vec![crate::chisei::eval::Case {
                id: "expected".into(),
                name: "expected".into(),
                namespace: "namespace".into(),
                spec: "spec".into(),
                assertions: vec![],
            }],
        };
        svc.eval.put_suite(suite.clone()).unwrap();
        let suite_digest = evaluation_gate_suite_digest(&suite);
        let config_ref = evaluation_gate_config_ref("release", "artifact", &suite_digest);
        svc.eval
            .put_run(crate::chisei::eval::Run {
                id: "malformed".into(),
                suite_id: suite.id.clone(),
                config_ref,
                results: vec![
                    crate::chisei::eval::CaseResult {
                        case_id: "expected".into(),
                        passed: true,
                        status: "passed".into(),
                        result: String::new(),
                        score: 1,
                        reason: String::new(),
                        elapsed: 1,
                    },
                    crate::chisei::eval::CaseResult {
                        case_id: "unexpected".into(),
                        passed: true,
                        status: "passed".into(),
                        result: String::new(),
                        score: 1,
                        reason: String::new(),
                        elapsed: 1,
                    },
                ],
                timestamp: 100,
            })
            .unwrap();
        let mut request = Request::new(GetEvaluationGateEvidenceRequest {
            suite_id: suite.id,
            release_digest: "release".into(),
            artifact_digest: "artifact".into(),
            max_timestamp_ms: 200,
        });
        request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let error = svc.get_evaluation_gate_evidence(request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn evaluation_gate_evidence_rejects_unauthorized_readers() {
        let svc = memory_service();
        let mut request = Request::new(GetEvaluationGateEvidenceRequest {
            suite_id: "suite".into(),
            release_digest: "release".into(),
            artifact_digest: "artifact".into(),
            max_timestamp_ms: 1,
        });
        request
            .metadata_mut()
            .insert("x-principal", "untrusted-agent".parse().unwrap());
        let error = svc.get_evaluation_gate_evidence(request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn evaluation_gate_evidence_rejects_timestamps_beyond_clock_skew_bound() {
        let svc = memory_service();
        let mut request = Request::new(GetEvaluationGateEvidenceRequest {
            suite_id: "suite".into(),
            release_digest: "release".into(),
            artifact_digest: "artifact".into(),
            max_timestamp_ms: chrono::Utc::now()
                .timestamp_millis()
                .saturating_add(EVALUATION_GATE_MAX_FUTURE_SKEW_MS + 60_000),
        });
        request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let error = svc.get_evaluation_gate_evidence(request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(error.message(), "max_timestamp_ms is too far in the future");
    }

    #[tokio::test]
    async fn evaluation_gate_evidence_accepts_bound_within_clock_skew_window() {
        let svc = memory_service();
        let mut request = Request::new(GetEvaluationGateEvidenceRequest {
            suite_id: "missing-suite".into(),
            release_digest: "release".into(),
            artifact_digest: "artifact".into(),
            max_timestamp_ms: chrono::Utc::now().timestamp_millis().saturating_add(90_000),
        });
        request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());

        let response = svc
            .get_evaluation_gate_evidence(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.status, EVALUATION_GATE_STATUS_SUITE_NOT_FOUND);
    }

    #[tokio::test]
    async fn sqlite_reload_restores_iterations_and_regression_gate() {
        let path = format!(
            "{}/sekai-chisei-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let svc = file_service(&path);
        create_suite(&svc, "context-a");

        seed_eval_run(
            &svc,
            eval_run("run-1", "suite-1", 92, 100),
            "skills/context-a.md",
            "hash-a",
        );
        seed_eval_run(
            &svc,
            eval_run("run-2", "suite-1", 60, 200),
            "skills/context-a.md",
            "hash-b",
        );

        drop(svc);

        let svc = file_service(&path);
        let latest = svc
            .eval
            .latest_iteration_for_file("skills/context-a.md")
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
                gunshi_allocation: None,
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
    async fn configured_gateway_principal_can_claim_one_dispatch() {
        let mut svc = memory_service();
        svc.config.gateway_receipt_principals = vec!["Gateway-Prod".into()];
        let claim = ClaimGatewayDispatchRequest {
            caller_scope: "gateway:prod".into(),
            request_alias: "attempt-1".into(),
            request_id: "request-1".into(),
            operation_id: "operation-1".into(),
            dispatch_token: "dispatch-1".into(),
        };
        let mut configured = Request::new(claim.clone());
        configured
            .metadata_mut()
            .insert("x-principal", "Gateway-Prod".parse().unwrap());
        configured
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
        assert!(
            svc.claim_gateway_dispatch(configured)
                .await
                .unwrap()
                .into_inner()
                .claimed
        );

        let mut replay = Request::new(ClaimGatewayDispatchRequest {
            dispatch_token: "dispatch-2".into(),
            ..claim.clone()
        });
        replay
            .metadata_mut()
            .insert("x-principal", "Gateway-Prod".parse().unwrap());
        replay
            .metadata_mut()
            .insert(AUTH_SOURCE_HEADER, "token".parse().unwrap());
        assert!(
            !svc.claim_gateway_dispatch(replay)
                .await
                .unwrap()
                .into_inner()
                .claimed
        );

        let mut intruder = Request::new(ClaimGatewayDispatchRequest {
            request_alias: "attempt-2".into(),
            request_id: "request-2".into(),
            ..claim
        });
        intruder
            .metadata_mut()
            .insert("x-principal", "agent:intruder".parse().unwrap());
        assert_eq!(
            svc.claim_gateway_dispatch(intruder)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn internal_gateway_pipeline_honors_delegated_membership() {
        let mut svc = memory_service();
        svc.config.gateway_receipt_principals = vec!["Gateway-Prod".into()];
        svc.db
            .ensure_team_namespace(
                "acme",
                "alice",
                crate::sekai::security::Role::Viewer,
                "local",
            )
            .unwrap();
        svc.db
            .create_object(&Object {
                id: "delegated-context".into(),
                kind: "asset".into(),
                name: "Delegated context".into(),
                namespace: "acme".into(),
                external_id: "asset:DELEGATED".into(),
                properties: HashMap::from([
                    ("verdict".into(), "delegated context value".into()),
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
            .create_grant(&crate::sekai::security::Grant {
                id: "delegated-context-alice".into(),
                object_id: "delegated-context".into(),
                principal: "alice".into(),
                role: crate::sekai::security::Role::Viewer,
                created: 1,
            })
            .unwrap();
        assert_eq!(
            execution_context_actor(&svc.db, &svc.config, "Gateway-Prod", Some("alice"), "acme",)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        let response = svc
            .gateway_pipeline_decision(GatewayPipelineInput {
                actor: "chisei-gateway",
                delegated_principal: Some("alice"),
                request_id: "gateway-observation",
                namespace: "acme",
                spec: "inspect asset:DELEGATED",
                model: "native-default",
                runtime: "native",
                task_class: "",
            })
            .unwrap();
        assert!(
            response
                .run
                .prepared_spec
                .contains("delegated context value")
        );
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
                disclosed_fields: vec![
                    "content.result".into(),
                    "signal".into(),
                    "epistemic_descriptor.contract_version".into(),
                    "epistemic_descriptor.origin_class".into(),
                    "epistemic_descriptor.evidence_status".into(),
                    "epistemic_descriptor.lifecycle_status".into(),
                    "epistemic_descriptor.source_rows_truncated".into(),
                    "epistemic_descriptor.observed_at_ms".into(),
                    "epistemic_descriptor.source_refs".into(),
                    "epistemic_descriptor.source_digests".into(),
                    "epistemic_descriptor.source_row_count".into(),
                ],
                descriptor: Some(EpistemicDescriptor {
                    contract_version: EPISTEMIC_DESCRIPTOR_VERSION.into(),
                    origin_class: "asserted".into(),
                    evidence_status: "unknown".into(),
                    lifecycle_status: "current".into(),
                    producer_confidence_bps: None,
                    confidence_basis: String::new(),
                    observed_at_ms: Some(100),
                    derivation_ref: String::new(),
                    source_refs: vec!["submission-7".into()],
                    source_digests: vec![digest.clone()],
                    source_row_count: Some(1),
                    source_rows_truncated: false,
                    supporting_evidence_count: None,
                    contradicting_evidence_count: None,
                }),
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
                descriptor: None,
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
        let context_event = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::ContextGoverned)
            .expect("context receipt event");
        assert_eq!(
            context_event
                .attributes
                .get("epistemic_descriptor_version")
                .map(String::as_str),
            Some(EPISTEMIC_DESCRIPTOR_VERSION)
        );
        assert_eq!(
            context_event
                .attributes
                .get("epistemic_descriptor_count")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            context_event
                .attributes
                .get("epistemic_descriptor_source_rows")
                .map(String::as_str),
            Some("1")
        );
        let evidence = context_event
            .references
            .iter()
            .find(|reference| reference.kind == "external_evidence")
            .expect("pinned external evidence reference");
        assert_eq!(evidence.reference, "evidence:submission-7@attempt-2");
        assert_eq!(evidence.content_hash.as_deref(), Some(digest.as_str()));
        assert_eq!(
            evidence.disclosed_fields,
            vec![
                "content.result".to_string(),
                "signal".to_string(),
                "epistemic_descriptor.contract_version".to_string(),
                "epistemic_descriptor.origin_class".to_string(),
                "epistemic_descriptor.evidence_status".to_string(),
                "epistemic_descriptor.lifecycle_status".to_string(),
                "epistemic_descriptor.source_rows_truncated".to_string(),
                "epistemic_descriptor.observed_at_ms".to_string(),
                "epistemic_descriptor.source_refs".to_string(),
                "epistemic_descriptor.source_digests".to_string(),
                "epistemic_descriptor.source_row_count".to_string(),
            ]
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
                    descriptor: None,
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
        create_suite(&svc, "context-a");

        seed_eval_run(
            &svc,
            eval_run("run-1", "suite-1", 92, 100),
            "skills/context-a.md",
            "hash-a",
        );
        seed_eval_run(
            &svc,
            eval_run("run-2", "suite-1", 60, 200),
            "skills/context-a.md",
            "hash-b",
        );

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
                gunshi_allocation: None,
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
        create_suite(&svc, "context-a");

        // Two runs whose drop trips the regression signal for context-a.
        seed_eval_run(
            &svc,
            eval_run("run-1", "suite-1", 92, 100),
            "skills/context-a.md",
            "hash-a",
        );
        seed_eval_run(
            &svc,
            eval_run("run-2", "suite-1", 60, 200),
            "skills/context-a.md",
            "hash-b",
        );

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
                gunshi_allocation: None,
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
                gunshi_allocation: None,
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
    fn egress_audit_serializes_epistemic_descriptor_fields() {
        let svc = memory_service();
        svc.record_egress_audit(
            "prepare_context",
            "task-descriptor-egress",
            "native",
            "native-default",
            &[EgressDecision {
                provider: "native".into(),
                external: false,
                included: vec![
                    "object#1.epistemic_descriptor.contract_version".into(),
                    "object#1.epistemic_descriptor.source_digests".into(),
                ],
                redacted: vec![],
                reasons: vec![],
            }],
        );

        let decision = svc
            .db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                actor: Some("chisei.egress".into()),
                action: Some("prepare_context".into()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|decision| decision.target_id == "task-descriptor-egress")
            .expect("descriptor egress audit should be recorded");
        let included: Vec<String> = serde_json::from_str(
            decision
                .evidence
                .get("included_fields")
                .expect("included fields evidence"),
        )
        .expect("included fields should remain JSON-serializable");
        assert_eq!(
            included,
            vec![
                "object#1.epistemic_descriptor.contract_version",
                "object#1.epistemic_descriptor.source_digests",
            ]
        );
    }

    #[test]
    fn namespace_policy_reloads_data_class_from_sekai_object_store() {
        let path = format!(
            "{}/sekai-chisei-policy-{}.db",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        {
            let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(&path).unwrap()));
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
                context_admission_policy_json: String::new(),
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
                gunshi_allocation: None,
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
                route_override: String::new(),
                capability_requirements_json: Vec::new(),
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
                gunshi_allocation: None,
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
                gunshi_allocation: None,
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
                gunshi_allocation: None,
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
    async fn execute_plan_stream_rejects_after_policy_flips_sensitive() {
        let svc = memory_service();
        let plan = svc
            .plan_execution(Request::new(PlanExecutionRequest {
                input: Some(ExecutionInput {
                    request_id: "task-stale-stream-policy".into(),
                    namespace: "alpha".into(),
                    spec: "do ordinary streamed work".into(),
                    preferred_model: "native-default".into(),
                    preferred_runtime: "kiro".into(),
                    user_id: "user-1".into(),
                    max_tokens: 512,
                    ..Default::default()
                }),
                gunshi_allocation: None,
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

        let error = match svc
            .execute_plan_stream(Request::new(ExecutePlanRequest {
                plan: Some(plan.clone()),
            }))
            .await
        {
            Ok(_) => panic!("stale streamed external plan bypassed the privacy gate"),
            Err(error) => error,
        };
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("privacy gate"));

        let receipt = svc
            .db
            .get_operation_receipt(&plan.plan_id)
            .unwrap()
            .expect("rejected streamed execution receipt");
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
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
            ..Default::default()
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
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
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
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
            ..Default::default()
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
        create_suite(&svc, "context-a");

        seed_eval_run(
            &svc,
            eval_run("run-1", "suite-1", 92, 100),
            "skills/context-a.md",
            "hash-a",
        );
        seed_eval_run(
            &svc,
            eval_run("run-2", "suite-1", 60, 200),
            "skills/context-a.md",
            "hash-b",
        );

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
                gunshi_allocation: None,
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
                context_admission_policy_version: String::new(),
                context_admission_descriptor_version: String::new(),
                context_admission_decision: String::new(),
                context_admission_reasons: Vec::new(),
                context_admission_source_digests: Vec::new(),
                context_admission_requires_review: false,
                context_admission_requires_verification: false,
                memory_holdouts: vec![],
                context_bytes: 0,
                context_tokens: 0,
                context_projection_latency_ms: 0,
                context_truncated: false,
                ..Default::default()
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
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
            ..Default::default()
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
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
            ..Default::default()
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
                context_admission_policy_version: String::new(),
                context_admission_descriptor_version: String::new(),
                context_admission_decision: String::new(),
                context_admission_reasons: Vec::new(),
                context_admission_source_digests: Vec::new(),
                context_admission_requires_review: false,
                context_admission_requires_verification: false,
                memory_holdouts: vec![],
                context_bytes: 0,
                context_tokens: 0,
                context_projection_latency_ms: 0,
                context_truncated: false,
                ..Default::default()
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
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
            ..Default::default()
        };
        svc.cache_plan(inserted.clone());

        let plans = svc
            .planned_executions
            .lock()
            .expect("planned executions poisoned");
        assert_eq!(plans.len(), MAX_CACHED_EXECUTION_PLANS);
        assert!(plans.contains_key(&inserted.plan_id));
    }

    #[tokio::test]
    async fn decide_gateway_execution_admits_and_denies_closed() {
        use crate::chisei::gateway_decide::GATEWAY_DECIDE_CONTRACT_VERSION;

        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let mut cfg = config(":memory:");
        cfg.gateway_provided_providers = vec!["openai".into()];
        let svc = ChiseiServiceImpl::new(db, cfg);
        svc.policy.set_namespace_policy(
            "team-a",
            crate::chisei::policy::Policy {
                allowed_runtimes: vec!["openai".into()],
                allowed_models: vec!["gpt-5.5".into(), "gpt-5.5-mini".into()],
                default_runtime: "openai".into(),
                default_model: "gpt-5.5".into(),
                data_class: "internal".into(),
            },
        );

        let mut admit = Request::new(DecideGatewayExecutionRequest {
            contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
            namespace: "team-a".into(),
            requested_model: "gpt-5.5".into(),
            operation_class: "chat".into(),
            estimated_cost_usd_micros: 0,
            correlation_operation_id: "op-decide-1".into(),
            correlation_attempt: 1,
            estimated_tokens: 10,
            task_class: "interactive".into(),
            preferred_runtime: "openai".into(),
            project: "team-a".into(),
            agent: "local".into(),
            key_id: String::new(),
            work_unit: String::new(),
            local_free_available: false,
            user_id: "local".into(),
            route_override: String::new(),
            capability_requirements_json: Vec::new(),
            expected_calls: 1,
            pipeline_spec: "summarize team-a".into(),
        });
        admit
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let admitted = svc
            .decide_gateway_execution(admit)
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted, "{admitted:?}");
        assert_eq!(admitted.resolved_model, "gpt-5.5");
        assert_eq!(admitted.resolved_runtime, "openai");
        assert_eq!(admitted.policy_scope, "team-a");
        assert_eq!(admitted.data_class, "unclassified");
        assert_eq!(
            admitted.fallback_models,
            vec!["openai/gpt-5.5", "openai/gpt-5.5-mini"]
        );
        assert!(!admitted.eval_regressed);
        assert!(admitted.deny_reason.is_empty());
        assert!(!admitted.budget_grant_id.is_empty());
        assert!(admitted.sampling_evaluated);
        assert!(!admitted.prepared_spec.is_empty());

        svc.policy
            .set_context_admission_policy(
                "team-a",
                crate::chisei::policy::ContextAdmissionPolicy {
                    contract_version: crate::chisei::policy::CONTEXT_ADMISSION_POLICY_VERSION
                        .into(),
                    default_action: ContextAdmissionAction::Include,
                    unknown_action: ContextAdmissionAction::HoldOut,
                    rules: vec![crate::chisei::policy::ContextAdmissionRule {
                        action: ContextAdmissionAction::RequireReview,
                        origin_classes: vec![],
                        evidence_statuses: vec![],
                        lifecycle_statuses: vec![],
                        applicability: None,
                        confidence_basis: None,
                        min_confidence_bps: None,
                        max_confidence_bps: None,
                        operation_risk: Some(crate::chisei::policy::OperationRisk::High),
                    }],
                },
            )
            .unwrap();
        let mut context_denied = Request::new(DecideGatewayExecutionRequest {
            contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
            namespace: "team-a".into(),
            requested_model: "gpt-5.5".into(),
            operation_class: "write".into(),
            estimated_cost_usd_micros: 0,
            correlation_operation_id: "op-decide-context-review".into(),
            correlation_attempt: 1,
            estimated_tokens: 10,
            task_class: "interactive".into(),
            preferred_runtime: "openai".into(),
            project: "team-a".into(),
            agent: "local".into(),
            key_id: String::new(),
            work_unit: String::new(),
            local_free_available: false,
            user_id: "local".into(),
            route_override: String::new(),
            capability_requirements_json: Vec::new(),
            expected_calls: 1,
            pipeline_spec: String::new(),
        });
        context_denied
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let context_denied = svc
            .decide_gateway_execution(context_denied)
            .await
            .unwrap()
            .into_inner();
        assert!(!context_denied.admitted);
        assert_eq!(context_denied.context_admission_decision, "require_review");
        assert_eq!(
            context_denied.context_admission_reasons,
            vec!["context_admission:require_review"]
        );
        assert_eq!(
            context_denied.deny_message,
            "context admission policy requires review or verification"
        );
        svc.policy.clear_context_admission_policy("team-a");

        svc.budget
            .set_limit_with_metric(
                "project:team-a",
                crate::db::chisei_budget::METRIC_REQUESTS,
                1,
                crate::chisei::budget::PeriodType::Daily,
            )
            .unwrap();
        let mut request_budget_denied = Request::new(DecideGatewayExecutionRequest {
            contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
            namespace: "team-a".into(),
            requested_model: "gpt-5.5".into(),
            operation_class: "chat".into(),
            estimated_cost_usd_micros: 0,
            correlation_operation_id: "op-decide-request-budget".into(),
            correlation_attempt: 1,
            estimated_tokens: 10,
            task_class: "interactive".into(),
            preferred_runtime: "openai".into(),
            project: "team-a".into(),
            agent: "local".into(),
            key_id: String::new(),
            work_unit: String::new(),
            local_free_available: true,
            user_id: "local".into(),
            route_override: String::new(),
            capability_requirements_json: Vec::new(),
            expected_calls: 2,
            pipeline_spec: String::new(),
        });
        request_budget_denied
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let request_budget_denied = svc
            .decide_gateway_execution(request_budget_denied)
            .await
            .unwrap()
            .into_inner();
        assert!(!request_budget_denied.admitted);
        assert_eq!(request_budget_denied.deny_reason, "budget_denied");
        assert_eq!(request_budget_denied.budget_scope, "project:team-a");

        // Non-bootstrap principal without a grant fails closed (unauthorized).
        let mut denied = Request::new(DecideGatewayExecutionRequest {
            contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
            namespace: "team-a".into(),
            requested_model: "gpt-5.5".into(),
            operation_class: "chat".into(),
            estimated_cost_usd_micros: 0,
            correlation_operation_id: "op-decide-2".into(),
            correlation_attempt: 1,
            estimated_tokens: 10,
            task_class: "interactive".into(),
            preferred_runtime: "openai".into(),
            project: "team-a".into(),
            agent: "mallory".into(),
            key_id: String::new(),
            work_unit: String::new(),
            local_free_available: false,
            user_id: "mallory".into(),
            route_override: String::new(),
            capability_requirements_json: Vec::new(),
            expected_calls: 1,
            pipeline_spec: String::new(),
        });
        denied
            .metadata_mut()
            .insert("x-principal", "mallory".parse().unwrap());
        let denied = svc
            .decide_gateway_execution(denied)
            .await
            .unwrap()
            .into_inner();
        assert!(!denied.admitted, "{denied:?}");
        assert_eq!(denied.deny_reason, "unauthorized");
    }

    #[tokio::test]
    async fn execute_plan_lookup_first_hit_skips_provider_with_zero_tokens() {
        use crate::chisei::lookup_first;
        use crate::sekai::semantic;

        let svc = memory_service();
        lookup_first::seed_s1_fixture_graph(&svc.db).expect("seed lookup fixtures");

        let plan = ExecutionPlan {
            plan_id: "lookup-hit-plan".into(),
            input: Some(ExecutionInput {
                request_id: "lookup-hit-req".into(),
                namespace: "acme".into(),
                spec: r#"{"external_id":"widget:lookup-root"}"#.into(),
                preferred_model: "llama3.2".into(),
                preferred_runtime: "ollama".into(),
                task_type: semantic::CAPABILITY_RESOLVE_REF.into(),
                priority: 0,
                user_id: "alice".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: String::new(),
                max_tokens: 256,
                task_class: String::new(),
                ..Default::default()
            }),
            resolved_runtime: "ollama".into(),
            resolved_model: "llama3.2".into(),
            enriched_spec: r#"{"external_id":"widget:lookup-root"}"#.into(),
            prepared_system: String::new(),
            prepared_messages: vec![ChatMessage {
                role: "user".into(),
                content: r#"{"external_id":"widget:lookup-root"}"#.into(),
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
            max_tokens: 256,
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
            context_admission_policy_version: String::new(),
            context_admission_descriptor_version: String::new(),
            context_admission_decision: String::new(),
            context_admission_reasons: Vec::new(),
            context_admission_source_digests: Vec::new(),
            context_admission_requires_review: false,
            context_admission_requires_verification: false,
            memory_holdouts: vec![],
            context_bytes: 0,
            context_tokens: 0,
            context_projection_latency_ms: 0,
            context_truncated: false,
            ..Default::default()
        };
        svc.record_planned_operation(&plan, "local").unwrap();
        svc.cache_plan(plan.clone());

        let mut request = Request::new(ExecutePlanRequest {
            plan: Some(plan.clone()),
        });
        request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());

        let response = svc
            .execute_plan(request)
            .await
            .expect("lookup hit should execute without provider")
            .into_inner()
            .response
            .expect("response body");
        assert_eq!(response.provider, lookup_first::LOOKUP_PROVIDER);
        assert_eq!(response.stop_reason, lookup_first::LOOKUP_HIT_STOP_REASON);
        assert_eq!(response.input_tokens, 0);
        assert_eq!(response.output_tokens, 0);
        assert_eq!(response.cache_read_input_tokens, 0);
        assert_eq!(response.cache_creation_input_tokens, 0);
        let body: serde_json::Value = serde_json::from_str(&response.content).unwrap();
        assert_eq!(body["resolved"], true);
        assert_eq!(body["object"]["id"], "lookup-root");

        let receipt = svc
            .db
            .get_operation_receipt("lookup-hit-plan")
            .unwrap()
            .unwrap();
        let outcome = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
            .expect("outcome");
        assert_eq!(
            outcome
                .attributes
                .get(lookup_first::ANSWER_PATH_ATTR)
                .map(String::as_str),
            Some(lookup_first::ANSWER_PATH_LOOKUP_HIT)
        );
        assert_eq!(
            outcome
                .attributes
                .get("provider_tokens")
                .map(String::as_str),
            Some("0")
        );
        assert!(
            !receipt
                .events
                .iter()
                .any(|event| event.kind == ReceiptEventKind::ModelCalled),
            "lookup hit must not record a model call"
        );

        create_suite(&svc, "acme");
        seed_eval_run(
            &svc,
            eval_run("lookup-regression-baseline", "suite-1", 95, 100),
            "acme",
            "lookup-regression-baseline",
        );
        seed_eval_run(
            &svc,
            eval_run("lookup-regression-candidate", "suite-1", 50, 200),
            "acme",
            "lookup-regression-candidate",
        );
        assert!(
            svc.eval
                .namespace_regression_signal("acme")
                .expect("regression signal")
                .regressed
        );

        let mut regressed_plan = plan.clone();
        regressed_plan.plan_id = "lookup-regressed-plan".into();
        regressed_plan
            .input
            .as_mut()
            .expect("plan input")
            .request_id = "lookup-regressed-req".into();
        svc.record_planned_operation(&regressed_plan, "local")
            .unwrap();
        svc.cache_plan(regressed_plan.clone());

        let mut regressed_request = Request::new(ExecutePlanRequest {
            plan: Some(regressed_plan),
        });
        regressed_request
            .metadata_mut()
            .insert("x-principal", "local".parse().unwrap());
        let error = svc.execute_plan(regressed_request).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(
            error
                .message()
                .contains("latest eval iteration regressed for namespace acme")
        );
    }

    #[tokio::test]
    async fn execute_plan_lookup_first_incomplete_records_refusal_before_model_path() {
        use crate::chisei::lookup_first;
        use crate::sekai::semantic;

        // Only evaluate the decision path here — full model execute needs a live
        // provider. The fail-closed refusal is unit-tested below via evaluate.
        let db = RuntimeDb::memory();
        lookup_first::seed_s1_fixture_graph(&db).unwrap();
        let input = ExecutionInput {
            request_id: "incomplete".into(),
            namespace: "acme".into(),
            spec: r#"{"object_id":"does-not-exist"}"#.into(),
            task_type: semantic::CAPABILITY_RESOLVE_REF.into(),
            ..Default::default()
        };
        match evaluate_execute_lookup_first(&db, &input, "alice") {
            ExecuteLookupFirst::ModelPath {
                lookup_refusal: Some(reason),
            } => assert_eq!(reason, "incomplete"),
            other => panic!("expected incomplete model path, got {other:?}"),
        }

        let cross = ExecutionInput {
            request_id: "cross".into(),
            namespace: "acme".into(),
            spec: r#"{"object_id":"other-ns-object"}"#.into(),
            task_type: semantic::CAPABILITY_RESOLVE_REF.into(),
            ..Default::default()
        };
        match evaluate_execute_lookup_first(&db, &cross, "alice") {
            ExecuteLookupFirst::ModelPath {
                lookup_refusal: Some(reason),
            } => assert_eq!(reason, "cross_namespace"),
            other => panic!("expected cross_namespace model path, got {other:?}"),
        }
    }

    #[test]
    fn execute_lookup_first_s2_hits_have_zero_provider_fields() {
        use crate::chisei::lookup_first;
        use crate::sekai::semantic;

        let db = RuntimeDb::memory();
        lookup_first::seed_s1_fixture_graph(&db).expect("seed lookup fixtures");
        for (capability, spec) in [
            (
                semantic::CAPABILITY_EXPAND_RELATIONS,
                r#"{"root":{"object_id":"lookup-root"},"direction":"outgoing","max_depth":1}"#,
            ),
            (
                semantic::CAPABILITY_RETRIEVE_CONTEXT,
                r#"{"roots":[{"object_id":"lookup-root"}],"direction":"outgoing","max_depth":1}"#,
            ),
            (
                semantic::CAPABILITY_EXPLAIN_DERIVATION,
                r#"{"from":{"object_id":"lookup-root"},"to":{"object_id":"lookup-child"},"direction":"outgoing","max_depth":1}"#,
            ),
        ] {
            let input = ExecutionInput {
                namespace: "acme".into(),
                spec: spec.into(),
                task_type: capability.into(),
                ..Default::default()
            };
            match evaluate_execute_lookup_first(&db, &input, "alice") {
                ExecuteLookupFirst::Hit { response, .. } => {
                    assert_eq!(response.provider, lookup_first::LOOKUP_PROVIDER);
                    assert_eq!(response.input_tokens, 0);
                    assert_eq!(response.output_tokens, 0);
                    assert_eq!(response.cache_read_input_tokens, 0);
                    assert_eq!(response.cache_creation_input_tokens, 0);
                    assert!(!response.content.is_empty());
                }
                other => panic!("expected {capability} lookup hit, got {other:?}"),
            }
        }
    }
}
