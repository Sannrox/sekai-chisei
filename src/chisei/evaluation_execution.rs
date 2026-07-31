//! Deterministic execution contracts for resolved evaluation manifests.
//!
//! Evaluators are compiled, operator-controlled implementations selected by
//! exact digest. They receive a closed canonical input document and no ambient
//! runtime capability object. This module performs no persistence, network,
//! filesystem, clock, random, model, or action access.

use crate::chisei::evaluation_manifest::{
    ResolvedEvaluationManifest, ResolvedEvaluationNode, ResolvedInvariantBinding,
};
use crate::chisei::evaluation_plan::{EvaluatorResourceLimits, FIXED_REDUCER, NODE_REQUIRED};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

pub const EXECUTION_REQUEST_CONTRACT: &str = "chisei.evaluation-execution-request/v1";
pub const EXECUTOR_VERSION: &str = "chisei.deterministic-evaluation-executor/v1";
pub const EVALUATOR_INPUT_CONTRACT: &str = "chisei.deterministic-evaluator-input/v1";
pub const EVALUATOR_RESULT_CONTRACT: &str = "chisei.deterministic-evaluator-result/v1";
pub const STEP_RECEIPT_CONTRACT: &str = "chisei.evaluation-step-receipt/v1";
pub const GATE_DECISION_CONTRACT: &str = "chisei.evaluation-gate-decision/v1";
pub const EXECUTION_OPERATION_CLASS: &str = "evaluation_manifest_execution";
pub const LEGACY_SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE: &str =
    "subject_content_digest_equals/v1";
pub const LEGACY_SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST: &str =
    "sha256:83df0fa4577447ecf2a7817c49d637ab48a018fb2d72a9fd631ce76d89f6e475";
pub const SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE: &str = "subject_content_digest_equals.v1";
pub const SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST: &str =
    "sha256:fb7617ab821a130efe66c43a22df2923e4648c1cb58ae2d793b958a31e94f155";

pub const STATUS_PASS: &str = "pass";
pub const STATUS_FAIL: &str = "fail";
pub const STATUS_UNKNOWN: &str = "unknown";
pub const STATUS_UNAVAILABLE: &str = "unavailable";
pub const STATUS_ERROR: &str = "error";
pub const STATUS_SKIPPED: &str = "skipped";
pub const STATUS_RUNNING: &str = "running";
pub const STATUS_CANCELLED: &str = "cancelled";

pub const VERDICT_ALLOW: &str = "allow";
pub const VERDICT_DENY: &str = "deny";
pub const VERDICT_UNKNOWN: &str = "unknown";
pub const VERDICT_UNAVAILABLE: &str = "unavailable";

pub const REASON_EVALUATOR_UNAVAILABLE: &str = "evaluator_unavailable";
pub const REASON_EVALUATOR_TIMEOUT: &str = "evaluator_timeout";
pub const REASON_EVALUATOR_PANIC: &str = "evaluator_panic";
pub const REASON_EVALUATOR_CAPACITY: &str = "evaluator_capacity_exhausted";
pub const REASON_INVALID_RESULT: &str = "invalid_result";
pub const REASON_INPUT_LIMIT: &str = "input_limit_exceeded";
pub const REASON_OUTPUT_LIMIT: &str = "output_limit_exceeded";
pub const REASON_EVIDENCE_LIMIT: &str = "evidence_limit_exceeded";
pub const REASON_EVIDENCE_UNAVAILABLE: &str = "evidence_unavailable";
pub const REASON_DEPENDENCY_BLOCKED: &str = "dependency_blocked";
pub const REASON_EXECUTION_CANCELLED: &str = "execution_cancelled";
pub const REASON_TOTAL_BUDGET: &str = "total_budget_exhausted";

pub const DEFAULT_TOTAL_DURATION_MS: u64 = 60_000;
pub const MAX_TOTAL_DURATION_MS: u64 = 300_000;
pub const MAX_RESULT_BYTES: usize = 64 * 1024;
pub const MAX_REASON_CODE_BYTES: usize = 128;
pub const MAX_EXECUTION_DOCUMENT_BYTES: usize = 512 * 1024;
const CANCELLATION_POLL_MS: u64 = 10;
pub const DEFAULT_EVALUATOR_THREAD_CAPACITY: usize = 32;
pub const MAX_EVALUATOR_THREAD_CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationExecutionRequest {
    pub contract_version: String,
    pub executor_version: String,
    pub namespace: String,
    pub manifest_digest: String,
    pub max_total_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationEvidenceInput {
    pub evidence_object_id: String,
    pub submission_id: String,
    pub content_digest: String,
    pub schema_id: String,
    pub schema_version: String,
    pub content: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyResultInput {
    pub node_id: String,
    pub status: String,
    pub result_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeterministicEvaluatorInput {
    pub contract_version: String,
    pub manifest_digest: String,
    pub node_id: String,
    pub subject_profile: String,
    pub subject_identity: String,
    pub subject_content_digest: String,
    pub parameters: Value,
    pub invariants: Vec<ResolvedInvariantBinding>,
    pub evidence: Vec<EvaluationEvidenceInput>,
    pub dependency_results: Vec<DependencyResultInput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeterministicEvaluatorOutput {
    pub contract_version: String,
    pub status: String,
    pub reason_code: String,
    pub result: Value,
}

pub trait DeterministicEvaluator: Send + Sync + 'static {
    fn evaluate(
        &self,
        input: &DeterministicEvaluatorInput,
    ) -> Result<DeterministicEvaluatorOutput, String>;
}

#[derive(Debug)]
pub struct SubjectContentDigestEqualityEvaluator {
    predicate_kind: &'static str,
}

impl DeterministicEvaluator for SubjectContentDigestEqualityEvaluator {
    fn evaluate(
        &self,
        input: &DeterministicEvaluatorInput,
    ) -> Result<DeterministicEvaluatorOutput, String> {
        if input.invariants.is_empty()
            || input
                .invariants
                .iter()
                .any(|invariant| invariant.predicate_kind != self.predicate_kind)
        {
            return Err(
                "subject digest equality evaluator received an unsupported invariant".into(),
            );
        }
        let parameters = input
            .parameters
            .as_object()
            .filter(|parameters| parameters.len() == 1)
            .ok_or_else(|| {
                "subject digest equality parameters require exactly expected_content_digest"
                    .to_string()
            })?;
        let expected = parameters
            .get("expected_content_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| "expected_content_digest must be canonical text".to_string())?;
        validate_digest("expected_content_digest", expected)?;
        let matched = input.subject_content_digest == expected;
        Ok(DeterministicEvaluatorOutput {
            contract_version: EVALUATOR_RESULT_CONTRACT.into(),
            status: if matched { STATUS_PASS } else { STATUS_FAIL }.into(),
            reason_code: if matched {
                "subject_content_digest_matched"
            } else {
                "subject_content_digest_mismatch"
            }
            .into(),
            result: serde_json::json!({"matched": matched}),
        })
    }
}

#[derive(Clone)]
pub struct DeterministicEvaluatorRegistry {
    implementations: Arc<RwLock<BTreeMap<String, RegisteredEvaluator>>>,
    thread_capacity: Arc<EvaluatorThreadCapacity>,
}

#[derive(Clone)]
struct RegisteredEvaluator {
    evaluator: Arc<dyn DeterministicEvaluator>,
    metrics_evaluator: &'static str,
    metrics_version: &'static str,
}

#[derive(Debug)]
struct EvaluatorThreadCapacity {
    limit: usize,
    active: Mutex<usize>,
}

struct EvaluatorThreadPermit {
    capacity: Arc<EvaluatorThreadCapacity>,
}

impl Drop for EvaluatorThreadPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.capacity.active.lock() {
            *active = active.saturating_sub(1);
        }
    }
}

impl Default for DeterministicEvaluatorRegistry {
    fn default() -> Self {
        Self::with_thread_capacity(DEFAULT_EVALUATOR_THREAD_CAPACITY)
            .expect("default evaluator thread capacity is valid")
    }
}

impl std::fmt::Debug for DeterministicEvaluatorRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .implementations
            .read()
            .map(|implementations| implementations.len())
            .unwrap_or_default();
        formatter
            .debug_struct("DeterministicEvaluatorRegistry")
            .field("implementation_count", &count)
            .finish()
    }
}

impl DeterministicEvaluatorRegistry {
    pub fn with_thread_capacity(thread_capacity: usize) -> Result<Self, String> {
        if thread_capacity == 0 || thread_capacity > MAX_EVALUATOR_THREAD_CAPACITY {
            return Err(format!(
                "evaluator thread capacity must be between 1 and {MAX_EVALUATOR_THREAD_CAPACITY}"
            ));
        }
        Ok(Self {
            implementations: Arc::new(RwLock::new(BTreeMap::new())),
            thread_capacity: Arc::new(EvaluatorThreadCapacity {
                limit: thread_capacity,
                active: Mutex::new(0),
            }),
        })
    }

    pub fn register(
        &self,
        implementation_digest: &str,
        evaluator: Arc<dyn DeterministicEvaluator>,
    ) -> Result<(), String> {
        self.register_with_metrics(implementation_digest, "custom_builtin", "v1", evaluator)
    }

    pub fn register_with_metrics(
        &self,
        implementation_digest: &str,
        metrics_evaluator: &'static str,
        metrics_version: &'static str,
        evaluator: Arc<dyn DeterministicEvaluator>,
    ) -> Result<(), String> {
        validate_digest("implementation_digest", implementation_digest)?;
        validate_metrics_label("metrics_evaluator", metrics_evaluator)?;
        validate_metrics_label("metrics_version", metrics_version)?;
        let mut implementations = self
            .implementations
            .write()
            .map_err(|_| "deterministic evaluator registry lock poisoned".to_string())?;
        if implementations.contains_key(implementation_digest) {
            return Err("deterministic evaluator implementation digest already registered".into());
        }
        implementations.insert(
            implementation_digest.to_string(),
            RegisteredEvaluator {
                evaluator,
                metrics_evaluator,
                metrics_version,
            },
        );
        Ok(())
    }

    pub fn contains(&self, implementation_digest: &str) -> bool {
        self.implementations
            .read()
            .is_ok_and(|implementations| implementations.contains_key(implementation_digest))
    }

    pub fn metric_labels(&self, implementation_digest: &str) -> (&'static str, &'static str) {
        self.implementations
            .read()
            .ok()
            .and_then(|implementations| {
                implementations
                    .get(implementation_digest)
                    .map(|entry| (entry.metrics_evaluator, entry.metrics_version))
            })
            .unwrap_or(("unregistered", "unknown"))
    }

    fn get(&self, implementation_digest: &str) -> Option<Arc<dyn DeterministicEvaluator>> {
        self.implementations
            .read()
            .ok()
            .and_then(|implementations| {
                implementations
                    .get(implementation_digest)
                    .map(|entry| entry.evaluator.clone())
            })
    }

    fn try_acquire_thread(&self) -> Option<EvaluatorThreadPermit> {
        let mut active = self.thread_capacity.active.lock().ok()?;
        if *active >= self.thread_capacity.limit {
            return None;
        }
        *active += 1;
        Some(EvaluatorThreadPermit {
            capacity: self.thread_capacity.clone(),
        })
    }
}

pub fn production_evaluator_registry() -> Result<DeterministicEvaluatorRegistry, String> {
    let registry = DeterministicEvaluatorRegistry::default();
    registry.register_with_metrics(
        LEGACY_SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST,
        "subject_digest_equality",
        "legacy_v1",
        Arc::new(SubjectContentDigestEqualityEvaluator {
            predicate_kind: LEGACY_SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE,
        }),
    )?;
    registry.register_with_metrics(
        SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST,
        "subject_digest_equality",
        "v1",
        Arc::new(SubjectContentDigestEqualityEvaluator {
            predicate_kind: SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE,
        }),
    )?;
    Ok(registry)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationStepReceipt {
    pub contract_version: String,
    pub manifest_digest: String,
    pub node_id: String,
    pub classification: String,
    pub status: String,
    pub reason_code: String,
    pub input_digest: String,
    pub parameters_digest: String,
    pub evaluator_definition_digest: String,
    pub implementation_digest: String,
    pub evidence_digests: Vec<String>,
    pub dependency_result_digests: Vec<String>,
    pub result_digest: String,
    pub step_receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantCoverageDecision {
    pub invariant_version_id: String,
    pub covered_by_node_ids: Vec<String>,
    pub waiver_version_ids: Vec<String>,
    pub satisfied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationGateDecision {
    pub contract_version: String,
    pub manifest_digest: String,
    pub reducer: String,
    pub verdict: String,
    pub reason_code: String,
    pub step_receipt_digests: Vec<String>,
    pub invariant_coverage: Vec<InvariantCoverageDecision>,
    pub decision_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationExecutionProjection {
    pub manifest_digest: String,
    pub operation_id: String,
    pub namespace: String,
    pub status: String,
    pub steps: Vec<EvaluationStepReceipt>,
    pub decision: Option<EvaluationGateDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationExecutionIndex {
    pub manifest_digest: String,
    pub operation_id: String,
    pub namespace: String,
    pub executor_version: String,
    pub started_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NodeExecution {
    pub receipt: EvaluationStepReceipt,
    pub elapsed: Duration,
}

pub fn prepare_execution_request(
    mut request: EvaluationExecutionRequest,
) -> Result<EvaluationExecutionRequest, String> {
    if request.contract_version != EXECUTION_REQUEST_CONTRACT {
        return Err("unsupported evaluation execution request contract".into());
    }
    if request.executor_version != EXECUTOR_VERSION {
        return Err("unsupported deterministic evaluation executor version".into());
    }
    if request.namespace.trim().is_empty() || request.namespace.trim() != request.namespace {
        return Err("namespace must be non-empty canonical text".into());
    }
    validate_digest("manifest_digest", &request.manifest_digest)?;
    if request.max_total_duration_ms == 0 {
        request.max_total_duration_ms = DEFAULT_TOTAL_DURATION_MS;
    }
    if request.max_total_duration_ms > MAX_TOTAL_DURATION_MS {
        return Err(format!(
            "max_total_duration_ms exceeds {MAX_TOTAL_DURATION_MS}"
        ));
    }
    Ok(request)
}

pub fn deterministic_topological_order(
    manifest: &ResolvedEvaluationManifest,
) -> Result<Vec<String>, String> {
    let mut inbound = manifest
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node.depends_on_node_ids.len()))
        .collect::<BTreeMap<_, _>>();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in &manifest.nodes {
        for dependency in &node.depends_on_node_ids {
            dependents
                .entry(dependency)
                .or_default()
                .push(&node.node_id);
        }
    }
    for values in dependents.values_mut() {
        values.sort_unstable();
    }
    let mut ready = inbound
        .iter()
        .filter_map(|(node_id, count)| (*count == 0).then_some(*node_id))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(manifest.nodes.len());
    while let Some(node_id) = ready.pop_first() {
        order.push(node_id.to_string());
        for dependent in dependents.get(node_id).into_iter().flatten() {
            let count = inbound
                .get_mut(dependent)
                .ok_or_else(|| "manifest dependency references an unknown node".to_string())?;
            *count -= 1;
            if *count == 0 {
                ready.insert(dependent);
            }
        }
    }
    if order.len() != manifest.nodes.len() {
        return Err("resolved evaluation manifest graph contains a cycle".into());
    }
    Ok(order)
}

pub fn build_evaluator_input(
    manifest: &ResolvedEvaluationManifest,
    node: &ResolvedEvaluationNode,
    mut evidence: Vec<EvaluationEvidenceInput>,
    prior_steps: &BTreeMap<String, EvaluationStepReceipt>,
) -> Result<DeterministicEvaluatorInput, String> {
    let parameters: Value = serde_json::from_str(&node.parameters_json)
        .map_err(|error| format!("canonical node parameters are invalid: {error}"))?;
    evidence.sort_by(|left, right| {
        (
            &left.evidence_object_id,
            &left.submission_id,
            &left.content_digest,
        )
            .cmp(&(
                &right.evidence_object_id,
                &right.submission_id,
                &right.content_digest,
            ))
    });
    let mut dependency_results = node
        .depends_on_node_ids
        .iter()
        .map(|node_id| {
            let step = prior_steps
                .get(node_id)
                .ok_or_else(|| format!("dependency result {node_id:?} is unavailable"))?;
            Ok(DependencyResultInput {
                node_id: node_id.clone(),
                status: step.status.clone(),
                result_digest: step.result_digest.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    dependency_results.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    Ok(DeterministicEvaluatorInput {
        contract_version: EVALUATOR_INPUT_CONTRACT.into(),
        manifest_digest: manifest.manifest_digest.clone(),
        node_id: node.node_id.clone(),
        subject_profile: manifest.subject_profile.clone(),
        subject_identity: manifest.subject_identity.clone(),
        subject_content_digest: manifest.subject_content_digest.clone(),
        parameters,
        invariants: node.invariants.clone(),
        evidence,
        dependency_results,
    })
}

pub fn dependency_blocking_status(
    node: &ResolvedEvaluationNode,
    prior_steps: &BTreeMap<String, EvaluationStepReceipt>,
) -> Option<(&'static str, &'static str)> {
    let statuses = node
        .depends_on_node_ids
        .iter()
        .filter_map(|node_id| prior_steps.get(node_id))
        .map(|step| step.status.as_str())
        .collect::<Vec<_>>();
    statuses
        .iter()
        .any(|status| *status != STATUS_PASS)
        .then_some((STATUS_SKIPPED, REASON_DEPENDENCY_BLOCKED))
}

pub fn execute_registered_node(
    registry: &DeterministicEvaluatorRegistry,
    manifest: &ResolvedEvaluationManifest,
    node: &ResolvedEvaluationNode,
    input: DeterministicEvaluatorInput,
    limits: &EvaluatorResourceLimits,
    remaining_total: Duration,
    cancelled: Arc<AtomicBool>,
) -> Result<NodeExecution, String> {
    let input_validation = validate_input(manifest, node, &input, limits);
    let input_digest = digest_json(&input)?;
    let parameters_digest = digest_json(&input.parameters)?;
    let evidence_digests = input
        .evidence
        .iter()
        .map(|evidence| evidence.content_digest.clone())
        .collect::<Vec<_>>();
    let dependency_result_digests = input
        .dependency_results
        .iter()
        .map(|dependency| dependency.result_digest.clone())
        .collect::<Vec<_>>();
    if let Err(reason) = input_validation {
        if matches!(reason.as_str(), REASON_INPUT_LIMIT | REASON_EVIDENCE_LIMIT) {
            return make_framework_step(
                manifest,
                node,
                STATUS_ERROR,
                &reason,
                input_digest,
                parameters_digest,
                evidence_digests,
                dependency_result_digests,
                Value::Null,
                Duration::ZERO,
            );
        }
        return Err(reason);
    }

    let Some(evaluator) = registry.get(&node.evaluator.implementation_digest) else {
        return make_framework_step(
            manifest,
            node,
            STATUS_UNAVAILABLE,
            REASON_EVALUATOR_UNAVAILABLE,
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            Duration::ZERO,
        );
    };
    let configured_node_budget = Duration::from_millis(limits.timeout_ms.max(1));
    let total_budget_is_limiting = remaining_total < configured_node_budget;
    let node_budget = remaining_total.min(configured_node_budget);
    if node_budget.is_zero() {
        return make_framework_step(
            manifest,
            node,
            STATUS_UNAVAILABLE,
            REASON_TOTAL_BUDGET,
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            Duration::ZERO,
        );
    }
    if cancelled.load(Ordering::Acquire) {
        return make_framework_step(
            manifest,
            node,
            STATUS_SKIPPED,
            REASON_EXECUTION_CANCELLED,
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            Duration::ZERO,
        );
    }
    let Some(thread_permit) = registry.try_acquire_thread() else {
        return make_framework_step(
            manifest,
            node,
            STATUS_UNAVAILABLE,
            REASON_EVALUATOR_CAPACITY,
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            Duration::ZERO,
        );
    };

    let started = Instant::now();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(format!("chisei-evaluator-{}", node.node_id))
        .spawn(move || {
            let _thread_permit = thread_permit;
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| evaluator.evaluate(&input)));
            let _ = sender.send(result);
        })
        .map_err(|error| format!("start deterministic evaluator: {error}"))?;

    let result = loop {
        if cancelled.load(Ordering::Acquire) {
            break None;
        }
        let elapsed = started.elapsed();
        if elapsed >= node_budget {
            break Some(Err(mpsc::RecvTimeoutError::Timeout));
        }
        let wait = (node_budget - elapsed).min(Duration::from_millis(CANCELLATION_POLL_MS));
        match receiver.recv_timeout(wait) {
            Ok(result) => break Some(Ok(result)),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(error) => break Some(Err(error)),
        }
    };
    let elapsed = started.elapsed();
    match result {
        None => make_framework_step(
            manifest,
            node,
            STATUS_SKIPPED,
            REASON_EXECUTION_CANCELLED,
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            elapsed,
        ),
        Some(Err(mpsc::RecvTimeoutError::Timeout)) => make_framework_step(
            manifest,
            node,
            STATUS_UNAVAILABLE,
            if total_budget_is_limiting {
                REASON_TOTAL_BUDGET
            } else {
                REASON_EVALUATOR_TIMEOUT
            },
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            elapsed,
        ),
        Some(Err(mpsc::RecvTimeoutError::Disconnected)) => make_framework_step(
            manifest,
            node,
            STATUS_ERROR,
            REASON_EVALUATOR_PANIC,
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            elapsed,
        ),
        Some(Ok(Err(_panic))) => make_framework_step(
            manifest,
            node,
            STATUS_ERROR,
            REASON_EVALUATOR_PANIC,
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            elapsed,
        ),
        Some(Ok(Ok(Err(_error)))) => make_framework_step(
            manifest,
            node,
            STATUS_ERROR,
            REASON_INVALID_RESULT,
            input_digest,
            parameters_digest,
            evidence_digests,
            dependency_result_digests,
            Value::Null,
            elapsed,
        ),
        Some(Ok(Ok(Ok(output)))) => {
            let output = match validate_output(output, limits) {
                Ok(output) => output,
                Err(reason) => {
                    return make_framework_step(
                        manifest,
                        node,
                        STATUS_ERROR,
                        reason,
                        input_digest,
                        parameters_digest,
                        evidence_digests,
                        dependency_result_digests,
                        Value::Null,
                        elapsed,
                    );
                }
            };
            make_framework_step(
                manifest,
                node,
                &output.status,
                &output.reason_code,
                input_digest,
                parameters_digest,
                evidence_digests,
                dependency_result_digests,
                output.result,
                elapsed,
            )
        }
    }
}

pub fn make_nonexecuted_node(
    manifest: &ResolvedEvaluationManifest,
    node: &ResolvedEvaluationNode,
    input: &DeterministicEvaluatorInput,
    status: &str,
    reason_code: &str,
) -> Result<NodeExecution, String> {
    make_framework_step(
        manifest,
        node,
        status,
        reason_code,
        digest_json(input)?,
        digest_json(&input.parameters)?,
        input
            .evidence
            .iter()
            .map(|evidence| evidence.content_digest.clone())
            .collect(),
        input
            .dependency_results
            .iter()
            .map(|dependency| dependency.result_digest.clone())
            .collect(),
        Value::Null,
        Duration::ZERO,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn make_framework_step(
    manifest: &ResolvedEvaluationManifest,
    node: &ResolvedEvaluationNode,
    status: &str,
    reason_code: &str,
    input_digest: String,
    parameters_digest: String,
    mut evidence_digests: Vec<String>,
    mut dependency_result_digests: Vec<String>,
    result: Value,
    elapsed: Duration,
) -> Result<NodeExecution, String> {
    validate_status(status)?;
    validate_reason_code(reason_code)?;
    evidence_digests.sort();
    dependency_result_digests.sort();
    let result_digest = digest_json(&(EVALUATOR_RESULT_CONTRACT, status, reason_code, &result))?;
    let mut receipt = EvaluationStepReceipt {
        contract_version: STEP_RECEIPT_CONTRACT.into(),
        manifest_digest: manifest.manifest_digest.clone(),
        node_id: node.node_id.clone(),
        classification: node.classification.clone(),
        status: status.into(),
        reason_code: reason_code.into(),
        input_digest,
        parameters_digest,
        evaluator_definition_digest: node.evaluator.definition_digest.clone(),
        implementation_digest: node.evaluator.implementation_digest.clone(),
        evidence_digests,
        dependency_result_digests,
        result_digest,
        step_receipt_digest: String::new(),
    };
    receipt.step_receipt_digest = digest_json(&(
        receipt.contract_version.as_str(),
        receipt.manifest_digest.as_str(),
        receipt.node_id.as_str(),
        receipt.classification.as_str(),
        receipt.status.as_str(),
        receipt.reason_code.as_str(),
        receipt.input_digest.as_str(),
        receipt.parameters_digest.as_str(),
        receipt.evaluator_definition_digest.as_str(),
        receipt.implementation_digest.as_str(),
        receipt.evidence_digests.as_slice(),
        receipt.dependency_result_digests.as_slice(),
        receipt.result_digest.as_str(),
    ))?;
    ensure_document_size(
        &receipt,
        "evaluation step receipt",
        MAX_EXECUTION_DOCUMENT_BYTES,
    )?;
    Ok(NodeExecution { receipt, elapsed })
}

pub fn reduce_gate(
    manifest: &ResolvedEvaluationManifest,
    steps: &[EvaluationStepReceipt],
) -> Result<EvaluationGateDecision, String> {
    let by_node = steps
        .iter()
        .map(|step| (step.node_id.as_str(), step))
        .collect::<BTreeMap<_, _>>();
    if by_node.len() != manifest.nodes.len() {
        return Err("fixed reducer requires exactly one result for every manifest node".into());
    }
    for node in &manifest.nodes {
        let step = by_node
            .get(node.node_id.as_str())
            .ok_or_else(|| format!("missing result for node {:?}", node.node_id))?;
        validate_step_for_node(manifest, node, step)?;
    }

    let required = manifest
        .nodes
        .iter()
        .filter(|node| node.classification == NODE_REQUIRED)
        .filter_map(|node| by_node.get(node.node_id.as_str()).copied())
        .collect::<Vec<_>>();
    let (verdict, reason_code) = if required.iter().any(|step| step.status == STATUS_FAIL) {
        (VERDICT_DENY, "required_node_failed")
    } else if required.iter().any(|step| {
        matches!(
            step.status.as_str(),
            STATUS_UNAVAILABLE | STATUS_ERROR | STATUS_CANCELLED
        )
    }) {
        (VERDICT_UNAVAILABLE, "required_node_unavailable")
    } else if required
        .iter()
        .any(|step| matches!(step.status.as_str(), STATUS_UNKNOWN | STATUS_SKIPPED))
    {
        (VERDICT_UNKNOWN, "required_node_unknown")
    } else if required.iter().all(|step| step.status == STATUS_PASS) {
        (VERDICT_ALLOW, "all_required_nodes_passed")
    } else {
        (VERDICT_UNAVAILABLE, "invalid_required_node_status")
    };

    let waived = manifest
        .waivers
        .iter()
        .flat_map(|waiver| {
            waiver
                .invariant_version_ids
                .iter()
                .map(move |invariant_id| (invariant_id.as_str(), waiver.waiver_version_id.as_str()))
        })
        .fold(
            BTreeMap::<&str, Vec<&str>>::new(),
            |mut map, (id, waiver)| {
                map.entry(id).or_default().push(waiver);
                map
            },
        );
    let mut invariant_nodes = BTreeMap::<&str, Vec<&ResolvedEvaluationNode>>::new();
    for node in &manifest.nodes {
        for invariant in &node.invariants {
            invariant_nodes
                .entry(&invariant.invariant_version_id)
                .or_default()
                .push(node);
        }
    }
    let all_invariant_ids = invariant_nodes
        .keys()
        .copied()
        .chain(waived.keys().copied())
        .collect::<BTreeSet<_>>();
    let mut invariant_coverage = Vec::with_capacity(all_invariant_ids.len());
    for invariant_id in all_invariant_ids {
        let mut covered_by_node_ids = invariant_nodes
            .get(invariant_id)
            .into_iter()
            .flatten()
            .filter(|node| node.classification == NODE_REQUIRED)
            .filter(|node| {
                by_node
                    .get(node.node_id.as_str())
                    .is_some_and(|step| step.status == STATUS_PASS)
            })
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        covered_by_node_ids.sort();
        let mut waiver_version_ids = waived
            .get(invariant_id)
            .into_iter()
            .flatten()
            .map(|waiver| (*waiver).to_string())
            .collect::<Vec<_>>();
        waiver_version_ids.sort();
        invariant_coverage.push(InvariantCoverageDecision {
            invariant_version_id: invariant_id.to_string(),
            satisfied: !covered_by_node_ids.is_empty() || !waiver_version_ids.is_empty(),
            covered_by_node_ids,
            waiver_version_ids,
        });
    }
    let (verdict, reason_code) = if verdict == VERDICT_ALLOW
        && invariant_coverage
            .iter()
            .any(|coverage| !coverage.satisfied)
    {
        (VERDICT_UNKNOWN, "invariant_coverage_incomplete")
    } else {
        (verdict, reason_code)
    };
    let mut step_receipt_digests = steps
        .iter()
        .map(|step| step.step_receipt_digest.clone())
        .collect::<Vec<_>>();
    step_receipt_digests.sort();
    let mut decision = EvaluationGateDecision {
        contract_version: GATE_DECISION_CONTRACT.into(),
        manifest_digest: manifest.manifest_digest.clone(),
        reducer: FIXED_REDUCER.into(),
        verdict: verdict.into(),
        reason_code: reason_code.into(),
        step_receipt_digests,
        invariant_coverage,
        decision_digest: String::new(),
    };
    decision.decision_digest = digest_json(&(
        decision.contract_version.as_str(),
        decision.manifest_digest.as_str(),
        decision.reducer.as_str(),
        decision.verdict.as_str(),
        decision.reason_code.as_str(),
        decision.step_receipt_digests.as_slice(),
        decision.invariant_coverage.as_slice(),
    ))?;
    ensure_document_size(
        &decision,
        "evaluation gate decision",
        MAX_EXECUTION_DOCUMENT_BYTES,
    )?;
    Ok(decision)
}

pub fn reduce_cancelled_gate(
    manifest: &ResolvedEvaluationManifest,
    steps: &[EvaluationStepReceipt],
) -> Result<EvaluationGateDecision, String> {
    let mut decision = reduce_gate(manifest, steps)?;
    decision.verdict = VERDICT_UNAVAILABLE.into();
    decision.reason_code = REASON_EXECUTION_CANCELLED.into();
    decision.decision_digest = digest_json(&(
        decision.contract_version.as_str(),
        decision.manifest_digest.as_str(),
        decision.reducer.as_str(),
        decision.verdict.as_str(),
        decision.reason_code.as_str(),
        decision.step_receipt_digests.as_slice(),
        decision.invariant_coverage.as_slice(),
    ))?;
    ensure_document_size(
        &decision,
        "evaluation gate decision",
        MAX_EXECUTION_DOCUMENT_BYTES,
    )?;
    Ok(decision)
}

pub fn validate_projection(
    manifest: &ResolvedEvaluationManifest,
    projection: &EvaluationExecutionProjection,
) -> Result<(), String> {
    if projection.manifest_digest != manifest.manifest_digest
        || projection.namespace != manifest.namespace
    {
        return Err("evaluation execution projection does not match manifest".into());
    }
    let mut node_ids = BTreeSet::new();
    for step in &projection.steps {
        if !node_ids.insert(step.node_id.as_str()) {
            return Err("evaluation execution projection contains duplicate steps".into());
        }
        let node = manifest
            .nodes
            .iter()
            .find(|node| node.node_id == step.node_id)
            .ok_or_else(|| "projection contains a step outside the manifest".to_string())?;
        validate_step_for_node(manifest, node, step)?;
    }
    match (&projection.decision, projection.status.as_str()) {
        (Some(decision), status)
            if matches!(
                status,
                VERDICT_ALLOW | VERDICT_DENY | VERDICT_UNKNOWN | VERDICT_UNAVAILABLE
            ) =>
        {
            let reduced = if decision.reason_code == REASON_EXECUTION_CANCELLED {
                reduce_cancelled_gate(manifest, &projection.steps)?
            } else {
                reduce_gate(manifest, &projection.steps)?
            };
            if &reduced != decision || status != decision.verdict {
                return Err("projection gate decision is not reproducible".into());
            }
        }
        (None, STATUS_RUNNING | STATUS_CANCELLED) => {}
        _ => return Err("projection status and terminal decision are inconsistent".into()),
    }
    ensure_document_size(
        projection,
        "evaluation execution projection",
        MAX_EXECUTION_DOCUMENT_BYTES,
    )
}

fn validate_input(
    manifest: &ResolvedEvaluationManifest,
    node: &ResolvedEvaluationNode,
    input: &DeterministicEvaluatorInput,
    limits: &EvaluatorResourceLimits,
) -> Result<(), String> {
    if input.contract_version != EVALUATOR_INPUT_CONTRACT
        || input.manifest_digest != manifest.manifest_digest
        || input.node_id != node.node_id
    {
        return Err("deterministic evaluator input binding is invalid".into());
    }
    if input.evidence.len() > limits.max_evidence_items as usize {
        return Err(REASON_EVIDENCE_LIMIT.into());
    }
    let bytes = serde_json::to_vec(input).map_err(|error| error.to_string())?;
    if bytes.len() > limits.max_input_bytes as usize {
        return Err(REASON_INPUT_LIMIT.into());
    }
    Ok(())
}

fn validate_output(
    mut output: DeterministicEvaluatorOutput,
    limits: &EvaluatorResourceLimits,
) -> Result<DeterministicEvaluatorOutput, &'static str> {
    if output.contract_version != EVALUATOR_RESULT_CONTRACT {
        return Err(REASON_INVALID_RESULT);
    }
    if !matches!(
        output.status.as_str(),
        STATUS_PASS | STATUS_FAIL | STATUS_UNKNOWN
    ) {
        return Err(REASON_INVALID_RESULT);
    }
    if validate_reason_code(&output.reason_code).is_err() {
        return Err(REASON_INVALID_RESULT);
    }
    canonicalize_value(&mut output.result);
    let bytes = serde_json::to_vec(&output).map_err(|_| REASON_INVALID_RESULT)?;
    let limit = usize::try_from(limits.max_output_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_RESULT_BYTES);
    if bytes.len() > limit {
        return Err(REASON_OUTPUT_LIMIT);
    }
    Ok(output)
}

fn validate_step_for_node(
    manifest: &ResolvedEvaluationManifest,
    node: &ResolvedEvaluationNode,
    step: &EvaluationStepReceipt,
) -> Result<(), String> {
    if step.contract_version != STEP_RECEIPT_CONTRACT
        || step.manifest_digest != manifest.manifest_digest
        || step.node_id != node.node_id
        || step.classification != node.classification
        || step.evaluator_definition_digest != node.evaluator.definition_digest
        || step.implementation_digest != node.evaluator.implementation_digest
    {
        return Err("evaluation step receipt binding is invalid".into());
    }
    validate_status(&step.status)?;
    validate_reason_code(&step.reason_code)?;
    validate_digest("evaluation step result_digest", &step.result_digest)?;
    let digest = digest_json(&(
        step.contract_version.as_str(),
        step.manifest_digest.as_str(),
        step.node_id.as_str(),
        step.classification.as_str(),
        step.status.as_str(),
        step.reason_code.as_str(),
        step.input_digest.as_str(),
        step.parameters_digest.as_str(),
        step.evaluator_definition_digest.as_str(),
        step.implementation_digest.as_str(),
        step.evidence_digests.as_slice(),
        step.dependency_result_digests.as_slice(),
        step.result_digest.as_str(),
    ))?;
    if digest != step.step_receipt_digest {
        return Err("evaluation step receipt digest is invalid".into());
    }
    Ok(())
}

fn validate_status(status: &str) -> Result<(), String> {
    if matches!(
        status,
        STATUS_PASS
            | STATUS_FAIL
            | STATUS_UNKNOWN
            | STATUS_UNAVAILABLE
            | STATUS_ERROR
            | STATUS_SKIPPED
    ) {
        Ok(())
    } else {
        Err("unknown evaluation step status".into())
    }
}

fn validate_reason_code(reason_code: &str) -> Result<(), String> {
    if reason_code.is_empty()
        || reason_code.len() > MAX_REASON_CODE_BYTES
        || !reason_code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("reason_code must be a bounded lowercase token".into());
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{field} must use sha256:<hex>"));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must contain 64 hexadecimal characters"));
    }
    Ok(())
}

fn validate_metrics_label(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!("{field} must be a bounded lowercase static token"));
    }
    Ok(())
}

fn canonicalize_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let mut ordered = BTreeMap::new();
            for (key, mut value) in std::mem::take(object) {
                canonicalize_value(&mut value);
                ordered.insert(key, value);
            }
            object.extend(ordered);
        }
        Value::Array(values) => {
            for value in values {
                canonicalize_value(value);
            }
        }
        _ => {}
    }
}

fn digest_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn ensure_document_size(value: &impl Serialize, name: &str, limit: usize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        Err(format!("{name} exceeds {limit} bytes"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_manifest::{
        MANIFEST_CONTRACT, RESOLVER_VERSION, ResolvedEvaluatorBinding, ResolvedWaiverBinding,
    };
    use crate::chisei::evaluation_plan::NODE_ADVISORY;
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug)]
    struct FixedEvaluator {
        status: &'static str,
        result: Value,
        calls: Arc<AtomicUsize>,
        delay: Duration,
    }

    impl DeterministicEvaluator for FixedEvaluator {
        fn evaluate(
            &self,
            _input: &DeterministicEvaluatorInput,
        ) -> Result<DeterministicEvaluatorOutput, String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(self.delay);
            Ok(DeterministicEvaluatorOutput {
                contract_version: EVALUATOR_RESULT_CONTRACT.into(),
                status: self.status.into(),
                reason_code: format!("fixture_{}", self.status),
                result: self.result.clone(),
            })
        }
    }

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn node(id: &str, classification: &str, dependencies: &[&str]) -> ResolvedEvaluationNode {
        ResolvedEvaluationNode {
            node_id: id.into(),
            evaluator: ResolvedEvaluatorBinding {
                definition_id: format!("definition:{id}"),
                definition_digest: digest('d'),
                implementation_digest: digest('e'),
            },
            depends_on_node_ids: dependencies.iter().map(|value| value.to_string()).collect(),
            input_bindings: Vec::new(),
            parameters_json: "{}".into(),
            invariants: vec![ResolvedInvariantBinding {
                invariant_version_id: format!("invariant:{id}"),
                content_digest: digest('a'),
                predicate_kind: "fixture_predicate/v1".into(),
                input_schema: "fixture.input/v1".into(),
                result_schema: EVALUATOR_RESULT_CONTRACT.into(),
                evidence_types: Vec::new(),
                provenance_evidence_object_ids: Vec::new(),
                waiver_version_ids: Vec::new(),
            }],
            evidence_object_ids: Vec::new(),
            classification: classification.into(),
        }
    }

    fn manifest(nodes: Vec<ResolvedEvaluationNode>) -> ResolvedEvaluationManifest {
        ResolvedEvaluationManifest {
            contract_version: MANIFEST_CONTRACT.into(),
            resolver_version: RESOLVER_VERSION.into(),
            manifest_id: "manifest:test".into(),
            manifest_digest: digest('f'),
            namespace: "test".into(),
            plan_version_id: "plan:test".into(),
            plan_digest: digest('1'),
            subject_profile: "fixture.subject/v1".into(),
            subject_identity: "subject:test".into(),
            subject_content_digest: digest('2'),
            invariant_set_id: "set:test".into(),
            invariant_set_digest: digest('3'),
            invariant_profile_digest: digest('4'),
            evaluation_time_ms: 1,
            resolved_by: "root".into(),
            requirements: Vec::new(),
            nodes,
            evidence: Vec::new(),
            waivers: Vec::new(),
            created_at_ms: 1,
        }
    }

    fn limits() -> EvaluatorResourceLimits {
        EvaluatorResourceLimits {
            timeout_ms: 1_000,
            max_input_bytes: 64 * 1024,
            max_output_bytes: 16 * 1024,
            max_evidence_items: 16,
        }
    }

    fn input(
        manifest: &ResolvedEvaluationManifest,
        node: &ResolvedEvaluationNode,
    ) -> DeterministicEvaluatorInput {
        build_evaluator_input(manifest, node, Vec::new(), &BTreeMap::new()).unwrap()
    }

    fn fixed_receipt() -> EvaluationStepReceipt {
        let registry = DeterministicEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(FixedEvaluator {
                    status: STATUS_PASS,
                    result: serde_json::json!({"b": 2, "a": 1}),
                    calls: Arc::new(AtomicUsize::new(0)),
                    delay: Duration::ZERO,
                }),
            )
            .unwrap();
        let manifest = manifest(vec![node("check", NODE_REQUIRED, &[])]);
        let node = &manifest.nodes[0];
        execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
        .receipt
    }

    #[test]
    fn topological_order_uses_node_id_as_stable_tie_breaker() {
        let manifest = manifest(vec![
            node("z", NODE_REQUIRED, &[]),
            node("a", NODE_REQUIRED, &[]),
            node("later", NODE_REQUIRED, &["z", "a"]),
        ]);
        assert_eq!(
            deterministic_topological_order(&manifest).unwrap(),
            ["a", "z", "later"]
        );
    }

    #[test]
    fn identical_inputs_produce_identical_semantic_receipts() {
        const CHILD: &str = "SEKAI_EVALUATION_CONFORMANCE_CHILD";
        const MARKER: &str = "EVALUATION_RECEIPT=";
        if std::env::var_os(CHILD).is_some() {
            println!(
                "{MARKER}{}",
                serde_json::to_string(&fixed_receipt()).unwrap()
            );
            return;
        }
        let current_exe = std::env::current_exe().unwrap();
        let test_name = "chisei::evaluation_execution::tests::identical_inputs_produce_identical_semantic_receipts";
        let run = |timezone: &str, locale: &str| {
            let output = std::process::Command::new(&current_exe)
                .args(["--exact", test_name, "--nocapture"])
                .env(CHILD, "1")
                .env("TZ", timezone)
                .env("LC_ALL", locale)
                .env("RUST_HASH_SEED", timezone)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "conformance child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .find_map(|line| {
                    line.find(MARKER)
                        .map(|offset| &line[offset + MARKER.len()..])
                })
                .unwrap()
                .to_string()
        };
        assert_eq!(run("UTC", "C"), run("Pacific/Chatham", "C.UTF-8"));
    }

    #[test]
    fn unknown_implementation_and_status_fail_closed() {
        let manifest = manifest(vec![node("check", NODE_REQUIRED, &[])]);
        let node = &manifest.nodes[0];
        let unavailable = execute_registered_node(
            &DeterministicEvaluatorRegistry::default(),
            &manifest,
            node,
            input(&manifest, node),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(unavailable.receipt.status, STATUS_UNAVAILABLE);
        let registry = DeterministicEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(FixedEvaluator {
                    status: "surprising",
                    result: Value::Null,
                    calls: Arc::new(AtomicUsize::new(0)),
                    delay: Duration::ZERO,
                }),
            )
            .unwrap();
        let invalid = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(invalid.receipt.status, STATUS_ERROR);
        assert_eq!(invalid.receipt.reason_code, REASON_INVALID_RESULT);
    }

    #[test]
    fn production_digest_equality_evaluator_is_narrow_and_callable() {
        let mut digest_node = node("digest", NODE_REQUIRED, &[]);
        digest_node.evaluator.implementation_digest =
            SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST.into();
        digest_node.invariants[0].predicate_kind = SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE.into();
        digest_node.parameters_json =
            serde_json::json!({"expected_content_digest": digest('2')}).to_string();
        let digest_manifest = manifest(vec![digest_node]);
        let registry = production_evaluator_registry().unwrap();
        let passed = execute_registered_node(
            &registry,
            &digest_manifest,
            &digest_manifest.nodes[0],
            input(&digest_manifest, &digest_manifest.nodes[0]),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(passed.receipt.status, STATUS_PASS);

        let mut mismatched_node = digest_manifest.nodes[0].clone();
        mismatched_node.parameters_json =
            serde_json::json!({"expected_content_digest": digest('8')}).to_string();
        let mismatched_manifest = manifest(vec![mismatched_node]);
        let failed = execute_registered_node(
            &registry,
            &mismatched_manifest,
            &mismatched_manifest.nodes[0],
            input(&mismatched_manifest, &mismatched_manifest.nodes[0]),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(failed.receipt.status, STATUS_FAIL);

        let mut legacy_node = digest_manifest.nodes[0].clone();
        legacy_node.evaluator.implementation_digest =
            LEGACY_SUBJECT_CONTENT_DIGEST_EQUALITY_IMPLEMENTATION_DIGEST.into();
        legacy_node.invariants[0].predicate_kind =
            LEGACY_SUBJECT_CONTENT_DIGEST_EQUALITY_PREDICATE.into();
        let legacy_manifest = manifest(vec![legacy_node]);
        let legacy = execute_registered_node(
            &registry,
            &legacy_manifest,
            &legacy_manifest.nodes[0],
            input(&legacy_manifest, &legacy_manifest.nodes[0]),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(legacy.receipt.status, STATUS_PASS);
    }

    #[test]
    fn input_and_evidence_limits_close_as_durable_error_steps() {
        let manifest = manifest(vec![node("check", NODE_REQUIRED, &[])]);
        let node = &manifest.nodes[0];
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = DeterministicEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(FixedEvaluator {
                    status: STATUS_PASS,
                    result: Value::Null,
                    calls: calls.clone(),
                    delay: Duration::ZERO,
                }),
            )
            .unwrap();

        let mut input_limits = limits();
        input_limits.max_input_bytes = 1;
        let input_limited = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &input_limits,
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(input_limited.receipt.status, STATUS_ERROR);
        assert_eq!(input_limited.receipt.reason_code, REASON_INPUT_LIMIT);

        let mut evidence_input = input(&manifest, node);
        evidence_input.evidence.push(EvaluationEvidenceInput {
            evidence_object_id: "evidence:one".into(),
            submission_id: "submission:one".into(),
            content_digest: digest('9'),
            schema_id: "fixture.evidence/v1".into(),
            schema_version: "1".into(),
            content: Value::Null,
        });
        let mut evidence_limits = limits();
        evidence_limits.max_evidence_items = 0;
        let evidence_limited = execute_registered_node(
            &registry,
            &manifest,
            node,
            evidence_input,
            &evidence_limits,
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(evidence_limited.receipt.status, STATUS_ERROR);
        assert_eq!(evidence_limited.receipt.reason_code, REASON_EVIDENCE_LIMIT);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fixed_reducer_has_fail_closed_precedence_and_ignores_advisory_failure() {
        let required = node("required", NODE_REQUIRED, &[]);
        let mut advisory = node("advisory", NODE_ADVISORY, &[]);
        advisory.invariants[0].invariant_version_id =
            required.invariants[0].invariant_version_id.clone();
        let manifest = manifest(vec![required, advisory]);
        let pass = make_framework_step(
            &manifest,
            &manifest.nodes[0],
            STATUS_PASS,
            "fixture_pass",
            digest('1'),
            digest('2'),
            Vec::new(),
            Vec::new(),
            Value::Null,
            Duration::ZERO,
        )
        .unwrap()
        .receipt;
        let advisory_fail = make_framework_step(
            &manifest,
            &manifest.nodes[1],
            STATUS_FAIL,
            "fixture_fail",
            digest('3'),
            digest('4'),
            Vec::new(),
            Vec::new(),
            Value::Null,
            Duration::ZERO,
        )
        .unwrap()
        .receipt;
        assert_eq!(
            reduce_gate(&manifest, &[pass, advisory_fail])
                .unwrap()
                .verdict,
            VERDICT_ALLOW
        );
    }

    #[test]
    fn exact_waiver_satisfies_unexecuted_invariant_coverage() {
        let mut manifest = manifest(vec![node("required", NODE_REQUIRED, &[])]);
        manifest.waivers.push(ResolvedWaiverBinding {
            waiver_version_id: "waiver:one".into(),
            content_digest: digest('7'),
            evidence_object_ids: Vec::new(),
            invariant_version_ids: vec!["invariant:waived".into()],
        });
        let pass = make_framework_step(
            &manifest,
            &manifest.nodes[0],
            STATUS_PASS,
            "fixture_pass",
            digest('1'),
            digest('2'),
            Vec::new(),
            Vec::new(),
            Value::Null,
            Duration::ZERO,
        )
        .unwrap()
        .receipt;
        let decision = reduce_gate(&manifest, &[pass]).unwrap();
        assert_eq!(decision.verdict, VERDICT_ALLOW);
        assert!(
            decision
                .invariant_coverage
                .iter()
                .find(|coverage| coverage.invariant_version_id == "invariant:waived")
                .unwrap()
                .satisfied
        );
    }

    #[test]
    fn cancellation_and_output_bounds_are_closed_states() {
        let registry = DeterministicEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(FixedEvaluator {
                    status: STATUS_PASS,
                    result: Value::String("x".repeat(1_024)),
                    calls: Arc::new(AtomicUsize::new(0)),
                    delay: Duration::ZERO,
                }),
            )
            .unwrap();
        let manifest = manifest(vec![node("check", NODE_REQUIRED, &[])]);
        let node = &manifest.nodes[0];
        let cancelled = Arc::new(AtomicBool::new(true));
        let result = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &limits(),
            Duration::from_secs(1),
            cancelled,
        )
        .unwrap();
        assert_eq!(result.receipt.status, STATUS_SKIPPED);
        assert_eq!(result.receipt.reason_code, REASON_EXECUTION_CANCELLED);

        let mut tiny = limits();
        tiny.max_output_bytes = 16;
        let bounded = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &tiny,
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(bounded.receipt.status, STATUS_ERROR);
        assert_eq!(bounded.receipt.reason_code, REASON_OUTPUT_LIMIT);
    }

    #[test]
    fn timeout_reason_identifies_the_limiting_budget() {
        let registry = DeterministicEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(FixedEvaluator {
                    status: STATUS_PASS,
                    result: Value::Null,
                    calls: Arc::new(AtomicUsize::new(0)),
                    delay: Duration::from_millis(40),
                }),
            )
            .unwrap();
        let manifest = manifest(vec![node("check", NODE_REQUIRED, &[])]);
        let node = &manifest.nodes[0];

        let total_limited = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &limits(),
            Duration::from_millis(5),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(total_limited.receipt.reason_code, REASON_TOTAL_BUDGET);

        let mut node_limits = limits();
        node_limits.timeout_ms = 5;
        let node_limited = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &node_limits,
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(node_limited.receipt.reason_code, REASON_EVALUATOR_TIMEOUT);
    }

    #[test]
    fn timed_out_evaluators_quarantine_bounded_thread_capacity() {
        let registry = DeterministicEvaluatorRegistry::with_thread_capacity(1).unwrap();
        registry
            .register(
                &digest('e'),
                Arc::new(FixedEvaluator {
                    status: STATUS_PASS,
                    result: Value::Null,
                    calls: Arc::new(AtomicUsize::new(0)),
                    delay: Duration::from_millis(80),
                }),
            )
            .unwrap();
        let manifest = manifest(vec![node("check", NODE_REQUIRED, &[])]);
        let node = &manifest.nodes[0];

        let timed_out = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &limits(),
            Duration::from_millis(5),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(timed_out.receipt.reason_code, REASON_TOTAL_BUDGET);

        let quarantined = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(quarantined.receipt.status, STATUS_UNAVAILABLE);
        assert_eq!(quarantined.receipt.reason_code, REASON_EVALUATOR_CAPACITY);

        std::thread::sleep(Duration::from_millis(100));
        let recovered = execute_registered_node(
            &registry,
            &manifest,
            node,
            input(&manifest, node),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(recovered.receipt.status, STATUS_PASS);
    }
}
