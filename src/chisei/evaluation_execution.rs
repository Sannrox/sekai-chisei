//! Bounded execution contracts for resolved evaluation manifests.
//!
//! Deterministic evaluators are compiled or operator-deployed external
//! implementations selected by exact digest. Stochastic evaluators use a
//! separate registry and only receive a frozen policy plus stable trial slot.
//! Provider access remains behind that registered implementation; the execution
//! engine itself receives no ambient provider, persistence, filesystem, or
//! action capability.

use crate::chisei::budget::BudgetTracker;
use crate::chisei::evaluation_manifest::{
    ResolvedEvaluationManifest, ResolvedEvaluationNode, ResolvedInvariantBinding,
};
#[cfg(test)]
use crate::chisei::evaluation_plan::validate_adapter_endpoint;
use crate::chisei::evaluation_plan::{
    EXTERNAL_ADAPTER_EXECUTION_CLASS, EvaluatorDefinition, EvaluatorResourceLimits, FIXED_REDUCER,
    NODE_REQUIRED, STOCHASTIC_EXECUTION_CLASS, StochasticEvaluatorPolicy,
    validate_runtime_adapter_endpoint,
};
use crate::chisei::receipt::OperationReceipt;
use base64::Engine as _;
use futures_util::FutureExt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
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
pub const EXTERNAL_ADAPTER_REQUEST_CONTRACT: &str = "chisei.external-evaluator-request/v1";
pub const EXTERNAL_ADAPTER_SHARED_SECRET_ENV: &str = "CHISEI_EVALUATOR_ADAPTER_SHARED_SECRET";
pub const STOCHASTIC_TRIAL_INPUT_CONTRACT: &str = "chisei.stochastic-trial-input/v1";
pub const STOCHASTIC_TRIAL_RESULT_CONTRACT: &str =
    crate::chisei::evaluation_plan::STOCHASTIC_RESULT_SCHEMA;
pub const STOCHASTIC_STEP_EVIDENCE_CONTRACT: &str = "chisei.stochastic-step-evidence/v1";
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
pub const REASON_STOCHASTIC_PROVIDER_UNAVAILABLE: &str = "stochastic_provider_unavailable";
pub const REASON_STOCHASTIC_REFUSAL: &str = "stochastic_provider_refusal";
pub const REASON_STOCHASTIC_SCHEMA_INVALID: &str = "stochastic_result_schema_invalid";
pub const REASON_STOCHASTIC_POPULATION_INCOMPLETE: &str = "stochastic_population_incomplete";
pub const REASON_STOCHASTIC_ACCEPTED: &str = "stochastic_acceptance_rule_satisfied";
pub const REASON_STOCHASTIC_REJECTED: &str = "stochastic_acceptance_rule_not_satisfied";
pub const REASON_STOCHASTIC_TOKEN_BUDGET: &str = "stochastic_token_budget_exhausted";
pub const REASON_STOCHASTIC_EGRESS_DENIED: &str = "stochastic_egress_denied";

pub const DEFAULT_TOTAL_DURATION_MS: u64 = 60_000;
pub const MAX_TOTAL_DURATION_MS: u64 = 300_000;
pub const MAX_RESULT_BYTES: usize = 64 * 1024;
pub const MAX_REASON_CODE_BYTES: usize = 128;
pub const MAX_EXECUTION_DOCUMENT_BYTES: usize = 512 * 1024;
const CANCELLATION_POLL_MS: u64 = 10;
pub const DEFAULT_EVALUATOR_THREAD_CAPACITY: usize = 32;
pub const MAX_EVALUATOR_THREAD_CAPACITY: usize = 256;
const EXTERNAL_ADAPTER_TIMEOUT_MS: u64 = 300_000;
const EXTERNAL_REGISTRATION_SEPARATOR: char = '\u{1f}';

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
#[serde(deny_unknown_fields)]
pub struct DeterministicEvaluatorOutput {
    pub contract_version: String,
    pub status: String,
    pub reason_code: String,
    pub result: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StochasticTrialInput {
    pub contract_version: String,
    pub base: DeterministicEvaluatorInput,
    pub policy: StochasticEvaluatorPolicy,
    pub trial_index: u32,
    pub seed: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StochasticTrialOutput {
    pub contract_version: String,
    pub passed: bool,
    pub score_micros: u32,
    pub reason_code: String,
    pub result: Value,
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StochasticTrialError {
    Retryable,
    ProviderUnavailable,
    TokenBudgetExceeded,
    Refusal {
        input_tokens: u32,
        output_tokens: u32,
    },
    SchemaInvalid {
        input_tokens: u32,
        output_tokens: u32,
    },
}

#[async_trait::async_trait]
pub trait StochasticEvaluator: Send + Sync + 'static {
    async fn evaluate_trial(
        &self,
        input: &StochasticTrialInput,
    ) -> Result<StochasticTrialOutput, StochasticTrialError>;
}

pub trait DeterministicEvaluator: Send + Sync + 'static {
    fn evaluate(
        &self,
        input: &DeterministicEvaluatorInput,
    ) -> Result<DeterministicEvaluatorOutput, String>;

    fn evaluate_with_timeout(
        &self,
        input: &DeterministicEvaluatorInput,
        _timeout: Duration,
    ) -> Result<DeterministicEvaluatorOutput, String> {
        self.evaluate(input)
    }
}

#[derive(Debug, Serialize)]
struct ExternalAdapterRequest<'a> {
    contract_version: &'static str,
    namespace: &'a str,
    implementation_digest: &'a str,
    input: &'a DeterministicEvaluatorInput,
}

/// Operator-deployed evaluator adapter invoked through a bounded JSON/HTTP
/// contract. The adapter receives no Chisei credentials or ambient capability;
/// it can only return the closed evaluator result contract.
#[derive(Debug)]
pub struct ExternalHttpEvaluator {
    namespace: String,
    implementation_digest: String,
    endpoint: String,
    secret_override: Option<String>,
}

impl ExternalHttpEvaluator {
    pub fn new(
        namespace: &str,
        implementation_digest: &str,
        endpoint: &str,
    ) -> Result<Self, String> {
        validate_runtime_adapter_endpoint(endpoint)?;
        if namespace.trim().is_empty() || implementation_digest.trim().is_empty() {
            return Err("external evaluator registration requires namespace and digest".into());
        }
        Ok(Self {
            namespace: namespace.into(),
            implementation_digest: implementation_digest.into(),
            endpoint: endpoint.into(),
            secret_override: None,
        })
    }

    #[cfg(test)]
    fn new_with_secret(
        namespace: &str,
        implementation_digest: &str,
        endpoint: &str,
        secret: &str,
    ) -> Result<Self, String> {
        validate_adapter_endpoint(endpoint)?;
        if namespace.trim().is_empty() || implementation_digest.trim().is_empty() {
            return Err("external evaluator registration requires namespace and digest".into());
        }
        Ok(Self {
            namespace: namespace.into(),
            implementation_digest: implementation_digest.into(),
            endpoint: endpoint.into(),
            secret_override: Some(secret.to_string()),
        })
    }

    fn shared_secret() -> Option<String> {
        std::env::var(EXTERNAL_ADAPTER_SHARED_SECRET_ENV)
            .ok()
            .map(|secret| secret.trim().to_string())
            .filter(|secret| !secret.is_empty())
    }

    fn request_secret(&self) -> Option<String> {
        self.secret_override.clone().or_else(Self::shared_secret)
    }

    fn signature(secret: &str, request_digest: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC accepts keys of every non-empty length");
        mac.update(request_digest.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    #[cfg(test)]
    fn response_signature(
        secret: &str,
        request_digest: &str,
        response_digest: &str,
        implementation_digest: &str,
    ) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC accepts keys of every non-empty length");
        mac.update(EXTERNAL_ADAPTER_REQUEST_CONTRACT.as_bytes());
        mac.update(b"\n");
        mac.update(request_digest.as_bytes());
        mac.update(b"\n");
        mac.update(response_digest.as_bytes());
        mac.update(b"\n");
        mac.update(implementation_digest.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn response_signature_valid(
        secret: &str,
        request_digest: &str,
        response_digest: &str,
        implementation_digest: &str,
        encoded_signature: &str,
    ) -> bool {
        let Ok(signature) =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded_signature)
        else {
            return false;
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC accepts keys of every non-empty length");
        mac.update(EXTERNAL_ADAPTER_REQUEST_CONTRACT.as_bytes());
        mac.update(b"\n");
        mac.update(request_digest.as_bytes());
        mac.update(b"\n");
        mac.update(response_digest.as_bytes());
        mac.update(b"\n");
        mac.update(implementation_digest.as_bytes());
        mac.verify_slice(&signature).is_ok()
    }
}

pub fn external_adapter_secret_configured() -> bool {
    ExternalHttpEvaluator::shared_secret().is_some()
}

impl DeterministicEvaluator for ExternalHttpEvaluator {
    fn evaluate(
        &self,
        input: &DeterministicEvaluatorInput,
    ) -> Result<DeterministicEvaluatorOutput, String> {
        self.evaluate_with_timeout(input, Duration::from_millis(EXTERNAL_ADAPTER_TIMEOUT_MS))
    }

    fn evaluate_with_timeout(
        &self,
        input: &DeterministicEvaluatorInput,
        timeout: Duration,
    ) -> Result<DeterministicEvaluatorOutput, String> {
        let Some(secret) = self.request_secret() else {
            return Err(REASON_EVALUATOR_UNAVAILABLE.into());
        };
        let request = ExternalAdapterRequest {
            contract_version: EXTERNAL_ADAPTER_REQUEST_CONTRACT,
            namespace: &self.namespace,
            implementation_digest: &self.implementation_digest,
            input,
        };
        let body = crate::shomei::canonical_json_with_finite_numbers(&request)?;
        let request_digest = format!("sha256:{:x}", Sha256::digest(&body));
        let signature = Self::signature(&secret, &request_digest);
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout.max(Duration::from_millis(1)))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| REASON_EVALUATOR_UNAVAILABLE.to_string())?;
        let response = client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header(
                "x-sekai-adapter-contract",
                EXTERNAL_ADAPTER_REQUEST_CONTRACT,
            )
            .header("x-sekai-adapter-request-digest", &request_digest)
            .header("x-sekai-adapter-signature", signature)
            .body(body)
            .send()
            .map_err(|_| REASON_EVALUATOR_UNAVAILABLE.to_string())?;
        if !response.status().is_success() {
            return Err(REASON_EVALUATOR_UNAVAILABLE.into());
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESULT_BYTES as u64)
        {
            return Err(REASON_OUTPUT_LIMIT.into());
        }
        let response_digest_header = response
            .headers()
            .get("x-sekai-adapter-response-digest")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let response_signature_header = response
            .headers()
            .get("x-sekai-adapter-response-signature")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::with_capacity(MAX_RESULT_BYTES.min(8 * 1024));
        let mut limited_response = response.take((MAX_RESULT_BYTES as u64) + 1);
        limited_response
            .read_to_end(&mut bytes)
            .map_err(|_| REASON_EVALUATOR_UNAVAILABLE.to_string())?;
        if bytes.len() > MAX_RESULT_BYTES {
            return Err(REASON_OUTPUT_LIMIT.into());
        }
        let response_digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if response_digest_header.as_deref() != Some(response_digest.as_str())
            || !response_signature_header.is_some_and(|signature| {
                Self::response_signature_valid(
                    &secret,
                    &request_digest,
                    &response_digest,
                    &self.implementation_digest,
                    &signature,
                )
            })
        {
            return Err(REASON_EVALUATOR_UNAVAILABLE.into());
        }
        serde_json::from_slice(&bytes).map_err(|_| REASON_INVALID_RESULT.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StochasticTrialEvidence {
    pub trial_index: u32,
    pub seed: i64,
    pub attempt_count: u32,
    pub status: String,
    pub reason_code: String,
    pub score_micros: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub retry_accounted_tokens: u32,
    pub result_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StochasticStepEvidence {
    pub contract_version: String,
    pub provider: String,
    pub model: String,
    pub prompt_profile: String,
    pub prompt_profile_digest: String,
    pub result_schema: String,
    pub trial_count: u32,
    pub aggregation_rule: String,
    pub minimum_mean_score_micros: u32,
    pub minimum_pass_rate_basis_points: u32,
    pub maximum_score_variance_micros_squared: u64,
    pub gate_eligible: bool,
    pub completed_trial_count: u32,
    pub mean_score_micros: u32,
    pub pass_rate_basis_points: u32,
    pub score_variance_micros_squared: u64,
    pub total_input_tokens: u32,
    pub total_output_tokens: u32,
    pub total_retry_accounted_tokens: u32,
    pub trials: Vec<StochasticTrialEvidence>,
    pub aggregate_digest: String,
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
    external_binding: Option<ExternalAdapterBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExternalAdapterBinding {
    namespace: String,
    definition_digest: String,
    implementation_digest: String,
    endpoint: String,
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
        self.register_key(
            implementation_digest.to_string(),
            metrics_evaluator,
            metrics_version,
            evaluator,
        )
    }

    fn register_key(
        &self,
        key: String,
        metrics_evaluator: &'static str,
        metrics_version: &'static str,
        evaluator: Arc<dyn DeterministicEvaluator>,
    ) -> Result<(), String> {
        let mut implementations = self
            .implementations
            .write()
            .map_err(|_| "deterministic evaluator registry lock poisoned".to_string())?;
        if implementations.contains_key(&key) {
            return Err("deterministic evaluator implementation digest already registered".into());
        }
        implementations.insert(
            key,
            RegisteredEvaluator {
                evaluator,
                metrics_evaluator,
                metrics_version,
                external_binding: None,
            },
        );
        Ok(())
    }

    pub fn register_external_adapter(
        &self,
        namespace: &str,
        definition_digest: &str,
        implementation_digest: &str,
        endpoint: &str,
    ) -> Result<(), String> {
        validate_digest("definition_digest", definition_digest)?;
        validate_digest("implementation_digest", implementation_digest)?;
        let evaluator = Arc::new(ExternalHttpEvaluator::new(
            namespace,
            implementation_digest,
            endpoint,
        )?);
        let binding = ExternalAdapterBinding {
            namespace: namespace.into(),
            definition_digest: definition_digest.into(),
            implementation_digest: implementation_digest.into(),
            endpoint: endpoint.into(),
        };
        let key = external_registration_key(namespace, definition_digest);
        let mut implementations = self
            .implementations
            .write()
            .map_err(|_| "deterministic evaluator registry lock poisoned".to_string())?;
        if let Some(existing) = implementations.get(&key) {
            if existing.external_binding.as_ref() == Some(&binding) {
                return Ok(());
            }
            return Err(
                "external evaluator definition is already bound to a different adapter endpoint"
                    .into(),
            );
        }
        implementations.insert(
            key,
            RegisteredEvaluator {
                evaluator,
                metrics_evaluator: "external_adapter",
                metrics_version: "v1",
                external_binding: Some(binding),
            },
        );
        Ok(())
    }

    pub fn contains(&self, implementation_digest: &str) -> bool {
        self.implementations
            .read()
            .is_ok_and(|implementations| implementations.contains_key(implementation_digest))
    }

    pub fn contains_external_adapter(
        &self,
        namespace: &str,
        definition_digest: &str,
        implementation_digest: &str,
    ) -> bool {
        self.implementations
            .read()
            .ok()
            .is_some_and(|implementations| {
                implementations
                    .get(&external_registration_key(namespace, definition_digest))
                    .is_some_and(|entry| {
                        external_binding_matches(
                            entry,
                            namespace,
                            definition_digest,
                            implementation_digest,
                        )
                    })
            })
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

    pub fn metric_labels_for_namespace(
        &self,
        namespace: &str,
        definition_digest: &str,
        implementation_digest: &str,
    ) -> (&'static str, &'static str) {
        self.implementations
            .read()
            .ok()
            .and_then(|implementations| {
                if let Some(entry) =
                    implementations.get(&external_registration_key(namespace, definition_digest))
                {
                    return external_binding_matches(
                        entry,
                        namespace,
                        definition_digest,
                        implementation_digest,
                    )
                    .then_some((entry.metrics_evaluator, entry.metrics_version));
                }
                implementations
                    .get(implementation_digest)
                    .map(|entry| (entry.metrics_evaluator, entry.metrics_version))
            })
            .unwrap_or(("unregistered", "unknown"))
    }

    fn get_for_namespace(
        &self,
        namespace: &str,
        definition_digest: &str,
        implementation_digest: &str,
    ) -> Option<Arc<dyn DeterministicEvaluator>> {
        self.implementations
            .read()
            .ok()
            .and_then(|implementations| {
                if let Some(entry) =
                    implementations.get(&external_registration_key(namespace, definition_digest))
                {
                    return external_binding_matches(
                        entry,
                        namespace,
                        definition_digest,
                        implementation_digest,
                    )
                    .then(|| entry.evaluator.clone());
                }
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

fn external_registration_key(namespace: &str, definition_digest: &str) -> String {
    format!(
        "external{}{}{}",
        EXTERNAL_REGISTRATION_SEPARATOR, namespace, EXTERNAL_REGISTRATION_SEPARATOR
    ) + definition_digest
}

fn external_binding_matches(
    entry: &RegisteredEvaluator,
    namespace: &str,
    definition_digest: &str,
    implementation_digest: &str,
) -> bool {
    entry.external_binding.as_ref().is_some_and(|binding| {
        binding.namespace == namespace
            && binding.definition_digest == definition_digest
            && binding.implementation_digest == implementation_digest
    })
}

#[derive(Clone)]
pub struct StochasticEvaluatorRegistry {
    implementations: Arc<RwLock<BTreeMap<String, RegisteredStochasticEvaluator>>>,
    thread_capacity: Arc<EvaluatorThreadCapacity>,
}

#[derive(Clone)]
struct RegisteredStochasticEvaluator {
    evaluator: Arc<dyn StochasticEvaluator>,
    metrics_evaluator: &'static str,
    metrics_version: &'static str,
}

impl Default for StochasticEvaluatorRegistry {
    fn default() -> Self {
        Self::with_thread_capacity(DEFAULT_EVALUATOR_THREAD_CAPACITY)
            .expect("default stochastic evaluator thread capacity is valid")
    }
}

impl std::fmt::Debug for StochasticEvaluatorRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .implementations
            .read()
            .map(|implementations| implementations.len())
            .unwrap_or_default();
        formatter
            .debug_struct("StochasticEvaluatorRegistry")
            .field("implementation_count", &count)
            .finish()
    }
}

impl StochasticEvaluatorRegistry {
    pub fn with_thread_capacity(thread_capacity: usize) -> Result<Self, String> {
        if thread_capacity == 0 || thread_capacity > MAX_EVALUATOR_THREAD_CAPACITY {
            return Err(format!(
                "stochastic evaluator thread capacity must be between 1 and {MAX_EVALUATOR_THREAD_CAPACITY}"
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
        evaluator: Arc<dyn StochasticEvaluator>,
    ) -> Result<(), String> {
        self.register_with_metrics(implementation_digest, "custom_stochastic", "v1", evaluator)
    }

    pub fn register_with_metrics(
        &self,
        implementation_digest: &str,
        metrics_evaluator: &'static str,
        metrics_version: &'static str,
        evaluator: Arc<dyn StochasticEvaluator>,
    ) -> Result<(), String> {
        validate_digest("implementation_digest", implementation_digest)?;
        validate_metrics_label("metrics_evaluator", metrics_evaluator)?;
        validate_metrics_label("metrics_version", metrics_version)?;
        let mut implementations = self
            .implementations
            .write()
            .map_err(|_| "stochastic evaluator registry lock poisoned".to_string())?;
        if implementations.contains_key(implementation_digest) {
            return Err("stochastic evaluator implementation digest already registered".into());
        }
        implementations.insert(
            implementation_digest.to_string(),
            RegisteredStochasticEvaluator {
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
            .unwrap_or(("unregistered_stochastic", "unknown"))
    }

    fn get(&self, implementation_digest: &str) -> Option<Arc<dyn StochasticEvaluator>> {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stochastic_evidence: Option<StochasticStepEvidence>,
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

pub fn cancellation_requested(receipt: &OperationReceipt) -> bool {
    receipt.events.iter().any(|event| {
        event
            .attributes
            .get("evaluation_cancel_requested")
            .is_some_and(|value| value == "true")
    })
}

/// Reconstruct one execution exclusively from its canonical receipt and
/// immutable manifest/index bindings.
pub fn projection_from_receipt(
    manifest: &ResolvedEvaluationManifest,
    index: &EvaluationExecutionIndex,
    receipt: &OperationReceipt,
) -> Result<EvaluationExecutionProjection, String> {
    if receipt.operation_id != index.operation_id
        || receipt.namespace != index.namespace
        || receipt.operation_class != EXECUTION_OPERATION_CLASS
    {
        return Err("evaluation execution receipt binding is invalid".into());
    }
    let mut steps = receipt
        .events
        .iter()
        .filter_map(|event| event.attributes.get("evaluation_step_receipt"))
        .map(|json| {
            serde_json::from_str::<EvaluationStepReceipt>(json)
                .map_err(|error| format!("invalid evaluation step receipt: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    steps.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let decision = receipt
        .events
        .iter()
        .find_map(|event| event.attributes.get("evaluation_gate_decision"))
        .map(|json| {
            serde_json::from_str::<EvaluationGateDecision>(json)
                .map_err(|error| format!("invalid evaluation gate decision: {error}"))
        })
        .transpose()?;
    let cancellation_requested = cancellation_requested(receipt);
    if let Some(decision) = &decision
        && (decision.reason_code == REASON_EXECUTION_CANCELLED) != cancellation_requested
    {
        return Err("evaluation cancellation and terminal decision are inconsistent".into());
    }
    let status = decision
        .as_ref()
        .map(|decision| decision.verdict.clone())
        .unwrap_or_else(|| {
            if cancellation_requested {
                STATUS_CANCELLED.into()
            } else {
                STATUS_RUNNING.into()
            }
        });
    let projection = EvaluationExecutionProjection {
        manifest_digest: manifest.manifest_digest.clone(),
        operation_id: index.operation_id.clone(),
        namespace: index.namespace.clone(),
        status,
        steps,
        decision,
    };
    validate_projection(manifest, &projection)?;
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

#[derive(Debug, Clone, PartialEq)]
pub struct NodeExecution {
    pub receipt: EvaluationStepReceipt,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationExecutionError {
    Internal(String),
}

impl std::fmt::Display for EvaluationExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::Internal(message) = self;
        formatter.write_str(message)
    }
}

impl std::error::Error for EvaluationExecutionError {}

/// The deep execution module for one resolved node. It owns evaluator
/// selection, dependency and cancellation semantics, stochastic egress and
/// budget admission, and the exact evaluator invocation. Callers only provide
/// durable inputs and persist the returned receipt.
pub struct EvaluationExecutionEngine<'a> {
    deterministic_registry: &'a DeterministicEvaluatorRegistry,
    stochastic_registry: &'a StochasticEvaluatorRegistry,
    stochastic_egress_reasons: &'a BTreeMap<String, String>,
    budget: &'a BudgetTracker,
}

pub struct EvaluationNodeExecution<'a> {
    pub manifest: &'a ResolvedEvaluationManifest,
    pub node: &'a ResolvedEvaluationNode,
    pub input: DeterministicEvaluatorInput,
    pub evidence_available: bool,
    pub prior_steps: &'a BTreeMap<String, EvaluationStepReceipt>,
    pub definition: Option<&'a EvaluatorDefinition>,
    pub remaining: Duration,
    pub cancelled: Arc<AtomicBool>,
}

impl<'a> EvaluationExecutionEngine<'a> {
    pub fn new(
        deterministic_registry: &'a DeterministicEvaluatorRegistry,
        stochastic_registry: &'a StochasticEvaluatorRegistry,
        stochastic_egress_reasons: &'a BTreeMap<String, String>,
        budget: &'a BudgetTracker,
    ) -> Self {
        Self {
            deterministic_registry,
            stochastic_registry,
            stochastic_egress_reasons,
            budget,
        }
    }

    pub fn metric_labels(
        &self,
        manifest: &ResolvedEvaluationManifest,
        node: &ResolvedEvaluationNode,
    ) -> (&'static str, &'static str) {
        if node.evaluator.stochastic_policy.is_some() {
            self.stochastic_registry
                .metric_labels(&node.evaluator.implementation_digest)
        } else {
            self.deterministic_registry.metric_labels_for_namespace(
                &manifest.namespace,
                &node.evaluator.definition_digest,
                &node.evaluator.implementation_digest,
            )
        }
    }

    pub fn execute_node(
        &self,
        execution: EvaluationNodeExecution<'_>,
    ) -> Result<NodeExecution, EvaluationExecutionError> {
        let EvaluationNodeExecution {
            manifest,
            node,
            input,
            evidence_available,
            prior_steps,
            definition,
            remaining,
            cancelled,
        } = execution;
        if cancelled.load(Ordering::Acquire) {
            return make_nonexecuted_node(
                manifest,
                node,
                &input,
                STATUS_SKIPPED,
                REASON_EXECUTION_CANCELLED,
            )
            .map_err(EvaluationExecutionError::Internal);
        }
        if let Some((status, reason)) = dependency_blocking_status(node, prior_steps) {
            return make_nonexecuted_node(manifest, node, &input, status, reason)
                .map_err(EvaluationExecutionError::Internal);
        }
        if !evidence_available {
            return make_nonexecuted_node(
                manifest,
                node,
                &input,
                STATUS_UNKNOWN,
                REASON_EVIDENCE_UNAVAILABLE,
            )
            .map_err(EvaluationExecutionError::Internal);
        }
        let Some(definition) = definition else {
            return make_nonexecuted_node(
                manifest,
                node,
                &input,
                STATUS_UNAVAILABLE,
                REASON_EVALUATOR_UNAVAILABLE,
            )
            .map_err(EvaluationExecutionError::Internal);
        };
        if definition.execution_class == EXTERNAL_ADAPTER_EXECUTION_CLASS
            && !self.deterministic_registry.contains_external_adapter(
                &definition.namespace,
                &definition.content_digest,
                &definition.implementation_digest,
            )
        {
            return make_nonexecuted_node(
                manifest,
                node,
                &input,
                STATUS_UNAVAILABLE,
                REASON_EVALUATOR_UNAVAILABLE,
            )
            .map_err(EvaluationExecutionError::Internal);
        }
        if definition.execution_class != STOCHASTIC_EXECUTION_CLASS {
            return execute_registered_node(
                self.deterministic_registry,
                manifest,
                node,
                input,
                &definition.resource_limits,
                remaining,
                cancelled,
            )
            .map_err(EvaluationExecutionError::Internal);
        }
        if let Some(reason) = self.stochastic_egress_reasons.get(&node.node_id) {
            return make_nonexecuted_node(manifest, node, &input, STATUS_UNAVAILABLE, reason)
                .map_err(EvaluationExecutionError::Internal);
        }
        if self
            .stochastic_registry
            .contains(&definition.implementation_digest)
        {
            let Some(policy) = node.evaluator.stochastic_policy.as_ref() else {
                return make_nonexecuted_node(
                    manifest,
                    node,
                    &input,
                    STATUS_UNAVAILABLE,
                    REASON_EVALUATOR_UNAVAILABLE,
                )
                .map_err(EvaluationExecutionError::Internal);
            };
            let amount = i32::try_from(policy.max_total_tokens).ok();
            let scope = format!(
                "project:{}/stochastic-evaluation:{}",
                manifest.namespace, node.node_id
            );
            let idempotency_key = format!(
                "stochastic-evaluation-reserve:{}:{}",
                manifest.manifest_digest, node.node_id
            );
            if amount.is_none_or(|amount| {
                self.budget
                    .check_and_reserve_idempotent(&scope, amount, &idempotency_key)
                    .is_err()
            }) {
                return make_nonexecuted_node(
                    manifest,
                    node,
                    &input,
                    STATUS_UNAVAILABLE,
                    REASON_STOCHASTIC_TOKEN_BUDGET,
                )
                .map_err(EvaluationExecutionError::Internal);
            }
        }
        execute_stochastic_node(
            self.stochastic_registry,
            manifest,
            node,
            input,
            &definition.resource_limits,
            remaining,
            cancelled,
        )
        .map_err(EvaluationExecutionError::Internal)
    }
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
    if node.evaluator.stochastic_policy.is_some() {
        return Err("stochastic node cannot execute through the deterministic registry".into());
    }
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

    let Some(evaluator) = registry.get_for_namespace(
        &manifest.namespace,
        &node.evaluator.definition_digest,
        &node.evaluator.implementation_digest,
    ) else {
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
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                evaluator.evaluate_with_timeout(&input, node_budget)
            }));
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
        Some(Ok(Ok(Err(error)))) => make_framework_step(
            manifest,
            node,
            if error == REASON_EVALUATOR_UNAVAILABLE {
                STATUS_UNAVAILABLE
            } else {
                STATUS_ERROR
            },
            if error == REASON_EVALUATOR_UNAVAILABLE {
                REASON_EVALUATOR_UNAVAILABLE
            } else if error == REASON_OUTPUT_LIMIT {
                REASON_OUTPUT_LIMIT
            } else {
                REASON_INVALID_RESULT
            },
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

pub fn execute_stochastic_node(
    registry: &StochasticEvaluatorRegistry,
    manifest: &ResolvedEvaluationManifest,
    node: &ResolvedEvaluationNode,
    input: DeterministicEvaluatorInput,
    limits: &EvaluatorResourceLimits,
    remaining_total: Duration,
    cancelled: Arc<AtomicBool>,
) -> Result<NodeExecution, String> {
    let policy = node
        .evaluator
        .stochastic_policy
        .as_ref()
        .ok_or_else(|| "stochastic node lacks frozen policy".to_string())?;
    crate::chisei::evaluation_plan::validate_stochastic_policy(
        policy,
        std::slice::from_ref(&policy.result_schema),
    )?;
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
    if remaining_total.is_zero() {
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

    let started = Instant::now();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start stochastic evaluator runtime: {error}"))?;
    let mut trials = Vec::with_capacity(policy.trial_count as usize);
    let mut terminal_failure = false;
    let mut total_tokens = 0u64;
    for trial_index in 0..policy.trial_count {
        let seed = stochastic_seed(policy, trial_index)?;
        if terminal_failure {
            trials.push(stochastic_failure_evidence(
                trial_index,
                seed,
                0,
                STATUS_SKIPPED,
                REASON_STOCHASTIC_POPULATION_INCOMPLETE,
                0,
            )?);
            continue;
        }
        if cancelled.load(Ordering::Acquire) {
            terminal_failure = true;
            trials.push(stochastic_failure_evidence(
                trial_index,
                seed,
                0,
                STATUS_SKIPPED,
                REASON_EXECUTION_CANCELLED,
                0,
            )?);
            continue;
        }
        let mut final_trial = None;
        let mut retry_accounted_tokens = 0u32;
        for attempt in 1..=(policy.max_retries_per_trial + 1) {
            let elapsed = started.elapsed();
            let remaining = remaining_total.saturating_sub(elapsed);
            if remaining.is_zero() {
                final_trial = Some(stochastic_failure_evidence(
                    trial_index,
                    seed,
                    attempt,
                    STATUS_UNAVAILABLE,
                    REASON_TOTAL_BUDGET,
                    retry_accounted_tokens,
                )?);
                break;
            }
            let Some(evaluator_permit) = registry.try_acquire_thread() else {
                final_trial = Some(stochastic_failure_evidence(
                    trial_index,
                    seed,
                    attempt,
                    STATUS_UNAVAILABLE,
                    REASON_EVALUATOR_CAPACITY,
                    retry_accounted_tokens,
                )?);
                break;
            };
            let trial_input = StochasticTrialInput {
                contract_version: STOCHASTIC_TRIAL_INPUT_CONTRACT.into(),
                base: input.clone(),
                policy: policy.clone(),
                trial_index,
                seed,
            };
            let evaluator = evaluator.clone();
            let attempt_budget = remaining.min(Duration::from_millis(limits.timeout_ms.max(1)));
            let evaluation =
                AssertUnwindSafe(evaluator.evaluate_trial(&trial_input)).catch_unwind();
            let received = runtime.block_on(async {
                tokio::select! {
                    result = evaluation => Some(Some(result)),
                    _ = tokio::time::sleep(attempt_budget) => Some(None),
                    _ = async {
                        while !cancelled.load(Ordering::Acquire) {
                            tokio::time::sleep(Duration::from_millis(CANCELLATION_POLL_MS)).await;
                        }
                    } => None,
                }
            });
            drop(evaluator_permit);
            match received {
                None => {
                    final_trial = Some(stochastic_failure_evidence(
                        trial_index,
                        seed,
                        attempt,
                        STATUS_SKIPPED,
                        REASON_EXECUTION_CANCELLED,
                        retry_accounted_tokens,
                    )?);
                    break;
                }
                Some(None) => {
                    final_trial = Some(stochastic_failure_evidence(
                        trial_index,
                        seed,
                        attempt,
                        STATUS_UNAVAILABLE,
                        REASON_EVALUATOR_TIMEOUT,
                        retry_accounted_tokens,
                    )?);
                    break;
                }
                Some(Some(Err(_))) => {
                    final_trial = Some(stochastic_failure_evidence(
                        trial_index,
                        seed,
                        attempt,
                        STATUS_ERROR,
                        REASON_EVALUATOR_PANIC,
                        retry_accounted_tokens,
                    )?);
                    break;
                }
                Some(Some(Ok(Err(StochasticTrialError::Retryable)))) => {
                    retry_accounted_tokens =
                        retry_accounted_tokens.saturating_add(policy.max_tokens_per_trial);
                    total_tokens =
                        total_tokens.saturating_add(u64::from(policy.max_tokens_per_trial));
                    if total_tokens > u64::from(policy.max_total_tokens) {
                        final_trial = Some(stochastic_failure_evidence(
                            trial_index,
                            seed,
                            attempt,
                            STATUS_UNAVAILABLE,
                            REASON_STOCHASTIC_TOKEN_BUDGET,
                            retry_accounted_tokens,
                        )?);
                        break;
                    }
                    if attempt <= policy.max_retries_per_trial {
                        continue;
                    }
                    final_trial = Some(stochastic_failure_evidence(
                        trial_index,
                        seed,
                        attempt,
                        STATUS_UNAVAILABLE,
                        REASON_STOCHASTIC_PROVIDER_UNAVAILABLE,
                        retry_accounted_tokens,
                    )?);
                    break;
                }
                Some(Some(Ok(Err(error)))) => {
                    let (status, reason) = stochastic_error_status(&error);
                    let (input_tokens, output_tokens) = stochastic_error_tokens(&error);
                    total_tokens = total_tokens
                        .saturating_add(u64::from(input_tokens))
                        .saturating_add(u64::from(output_tokens));
                    if total_tokens > u64::from(policy.max_total_tokens) {
                        final_trial = Some(stochastic_failure_evidence_with_usage(
                            trial_index,
                            seed,
                            attempt,
                            STATUS_UNAVAILABLE,
                            REASON_STOCHASTIC_TOKEN_BUDGET,
                            input_tokens,
                            output_tokens,
                            retry_accounted_tokens,
                        )?);
                        break;
                    }
                    final_trial = Some(stochastic_failure_evidence_with_usage(
                        trial_index,
                        seed,
                        attempt,
                        status,
                        reason,
                        input_tokens,
                        output_tokens,
                        retry_accounted_tokens,
                    )?);
                    break;
                }
                Some(Some(Ok(Ok(output)))) => {
                    let output_input_tokens = output.input_tokens;
                    let output_output_tokens = output.output_tokens;
                    let output = match validate_stochastic_output(output, policy, limits) {
                        Ok(output) => output,
                        Err(reason) => {
                            total_tokens = total_tokens
                                .saturating_add(u64::from(output_input_tokens))
                                .saturating_add(u64::from(output_output_tokens));
                            let (status, reason) =
                                if total_tokens > u64::from(policy.max_total_tokens) {
                                    (STATUS_UNAVAILABLE, REASON_STOCHASTIC_TOKEN_BUDGET)
                                } else {
                                    (STATUS_ERROR, reason)
                                };
                            final_trial = Some(stochastic_failure_evidence_with_usage(
                                trial_index,
                                seed,
                                attempt,
                                status,
                                reason,
                                output_input_tokens,
                                output_output_tokens,
                                retry_accounted_tokens,
                            )?);
                            break;
                        }
                    };
                    total_tokens = total_tokens
                        .saturating_add(u64::from(output.input_tokens))
                        .saturating_add(u64::from(output.output_tokens));
                    if total_tokens > u64::from(policy.max_total_tokens) {
                        final_trial = Some(stochastic_failure_evidence(
                            trial_index,
                            seed,
                            attempt,
                            STATUS_UNAVAILABLE,
                            REASON_STOCHASTIC_TOKEN_BUDGET,
                            retry_accounted_tokens,
                        )?);
                        break;
                    }
                    final_trial = Some(stochastic_success_evidence(
                        trial_index,
                        seed,
                        attempt,
                        retry_accounted_tokens,
                        output,
                    )?);
                    break;
                }
            }
        }
        let trial = final_trial.ok_or_else(|| "stochastic trial did not terminate".to_string())?;
        if !matches!(trial.status.as_str(), STATUS_PASS | STATUS_FAIL) {
            terminal_failure = true;
        }
        trials.push(trial);
    }

    let aggregate = derive_stochastic_aggregate(policy, &trials);
    let mut stochastic = StochasticStepEvidence {
        contract_version: STOCHASTIC_STEP_EVIDENCE_CONTRACT.into(),
        provider: policy.provider.clone(),
        model: policy.model.clone(),
        prompt_profile: policy.prompt_profile.clone(),
        prompt_profile_digest: policy.prompt_profile_digest.clone(),
        result_schema: policy.result_schema.clone(),
        trial_count: policy.trial_count,
        aggregation_rule: policy.aggregation_rule.clone(),
        minimum_mean_score_micros: policy.minimum_mean_score_micros,
        minimum_pass_rate_basis_points: policy.minimum_pass_rate_basis_points,
        maximum_score_variance_micros_squared: policy.maximum_score_variance_micros_squared,
        gate_eligible: policy.gate_eligible,
        completed_trial_count: aggregate.completed_trial_count,
        mean_score_micros: aggregate.mean_score_micros,
        pass_rate_basis_points: aggregate.pass_rate_basis_points,
        score_variance_micros_squared: aggregate.score_variance_micros_squared,
        total_input_tokens: aggregate.total_input_tokens,
        total_output_tokens: aggregate.total_output_tokens,
        total_retry_accounted_tokens: aggregate.total_retry_accounted_tokens,
        trials,
        aggregate_digest: String::new(),
    };
    stochastic.aggregate_digest = stochastic_aggregate_digest(&stochastic)?;
    let aggregate_result = serde_json::json!({
        "aggregate_digest": stochastic.aggregate_digest,
        "accepted": aggregate.accepted,
        "completed_trial_count": aggregate.completed_trial_count,
        "mean_score_micros": aggregate.mean_score_micros,
        "pass_rate_basis_points": aggregate.pass_rate_basis_points,
        "score_variance_micros_squared": aggregate.score_variance_micros_squared,
    });
    let mut execution = make_framework_step(
        manifest,
        node,
        &aggregate.status,
        &aggregate.reason_code,
        input_digest,
        parameters_digest,
        evidence_digests,
        dependency_result_digests,
        aggregate_result,
        started.elapsed(),
    )?;
    execution.receipt.stochastic_evidence = Some(stochastic);
    execution.receipt.step_receipt_digest = step_receipt_digest(&execution.receipt)?;
    ensure_document_size(
        &execution.receipt,
        "stochastic evaluation step receipt",
        MAX_EXECUTION_DOCUMENT_BYTES,
    )?;
    Ok(execution)
}

fn stochastic_seed(policy: &StochasticEvaluatorPolicy, trial_index: u32) -> Result<i64, String> {
    if policy.seed_supported {
        policy
            .base_seed
            .checked_add(i64::from(trial_index))
            .ok_or_else(|| "stochastic seed range overflowed".to_string())
    } else {
        Ok(0)
    }
}

fn stochastic_error_status(error: &StochasticTrialError) -> (&'static str, &'static str) {
    match error {
        StochasticTrialError::Retryable | StochasticTrialError::ProviderUnavailable => {
            (STATUS_UNAVAILABLE, REASON_STOCHASTIC_PROVIDER_UNAVAILABLE)
        }
        StochasticTrialError::TokenBudgetExceeded => {
            (STATUS_UNAVAILABLE, REASON_STOCHASTIC_TOKEN_BUDGET)
        }
        StochasticTrialError::Refusal { .. } => (STATUS_UNKNOWN, REASON_STOCHASTIC_REFUSAL),
        StochasticTrialError::SchemaInvalid { .. } => {
            (STATUS_ERROR, REASON_STOCHASTIC_SCHEMA_INVALID)
        }
    }
}

fn stochastic_error_tokens(error: &StochasticTrialError) -> (u32, u32) {
    match error {
        StochasticTrialError::Refusal {
            input_tokens,
            output_tokens,
        }
        | StochasticTrialError::SchemaInvalid {
            input_tokens,
            output_tokens,
        } => (*input_tokens, *output_tokens),
        _ => (0, 0),
    }
}

fn stochastic_failure_evidence(
    trial_index: u32,
    seed: i64,
    attempt_count: u32,
    status: &str,
    reason_code: &str,
    retry_accounted_tokens: u32,
) -> Result<StochasticTrialEvidence, String> {
    stochastic_failure_evidence_with_usage(
        trial_index,
        seed,
        attempt_count,
        status,
        reason_code,
        0,
        0,
        retry_accounted_tokens,
    )
}

#[allow(clippy::too_many_arguments)]
fn stochastic_failure_evidence_with_usage(
    trial_index: u32,
    seed: i64,
    attempt_count: u32,
    status: &str,
    reason_code: &str,
    input_tokens: u32,
    output_tokens: u32,
    retry_accounted_tokens: u32,
) -> Result<StochasticTrialEvidence, String> {
    let result_digest = digest_json(&(
        STOCHASTIC_TRIAL_RESULT_CONTRACT,
        trial_index,
        seed,
        attempt_count,
        status,
        reason_code,
        0u32,
        input_tokens,
        output_tokens,
        retry_accounted_tokens,
    ))?;
    Ok(StochasticTrialEvidence {
        trial_index,
        seed,
        attempt_count,
        status: status.into(),
        reason_code: reason_code.into(),
        score_micros: 0,
        input_tokens,
        output_tokens,
        retry_accounted_tokens,
        result_digest,
    })
}

fn stochastic_success_evidence(
    trial_index: u32,
    seed: i64,
    attempt_count: u32,
    retry_accounted_tokens: u32,
    output: StochasticTrialOutput,
) -> Result<StochasticTrialEvidence, String> {
    let status = if output.passed {
        STATUS_PASS
    } else {
        STATUS_FAIL
    };
    let result_digest = digest_json(&(
        STOCHASTIC_TRIAL_RESULT_CONTRACT,
        trial_index,
        seed,
        attempt_count,
        status,
        output.reason_code.as_str(),
        output.score_micros,
        output.input_tokens,
        output.output_tokens,
        retry_accounted_tokens,
        &output.result,
    ))?;
    Ok(StochasticTrialEvidence {
        trial_index,
        seed,
        attempt_count,
        status: status.into(),
        reason_code: output.reason_code,
        score_micros: output.score_micros,
        input_tokens: output.input_tokens,
        output_tokens: output.output_tokens,
        retry_accounted_tokens,
        result_digest,
    })
}

fn validate_stochastic_output(
    mut output: StochasticTrialOutput,
    policy: &StochasticEvaluatorPolicy,
    limits: &EvaluatorResourceLimits,
) -> Result<StochasticTrialOutput, &'static str> {
    if output.contract_version != STOCHASTIC_TRIAL_RESULT_CONTRACT
        || output.score_micros > 1_000_000
        || validate_reason_code(&output.reason_code).is_err()
        || output.input_tokens.saturating_add(output.output_tokens) > policy.max_tokens_per_trial
    {
        return Err(REASON_STOCHASTIC_SCHEMA_INVALID);
    }
    canonicalize_value(&mut output.result);
    let bytes = serde_json::to_vec(&output).map_err(|_| REASON_STOCHASTIC_SCHEMA_INVALID)?;
    let limit = usize::try_from(limits.max_output_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_RESULT_BYTES);
    if bytes.len() > limit {
        return Err(REASON_OUTPUT_LIMIT);
    }
    Ok(output)
}

fn stochastic_aggregate_digest(evidence: &StochasticStepEvidence) -> Result<String, String> {
    let mut canonical = evidence.clone();
    canonical.aggregate_digest.clear();
    digest_json(&canonical)
}

#[derive(Debug, PartialEq, Eq)]
struct DerivedStochasticAggregate {
    completed_trial_count: u32,
    mean_score_micros: u32,
    pass_rate_basis_points: u32,
    score_variance_micros_squared: u64,
    total_input_tokens: u32,
    total_output_tokens: u32,
    total_retry_accounted_tokens: u32,
    accepted: bool,
    status: String,
    reason_code: String,
}

fn derive_stochastic_aggregate(
    policy: &StochasticEvaluatorPolicy,
    trials: &[StochasticTrialEvidence],
) -> DerivedStochasticAggregate {
    let completed = trials
        .iter()
        .filter(|trial| matches!(trial.status.as_str(), STATUS_PASS | STATUS_FAIL))
        .collect::<Vec<_>>();
    let completed_trial_count = completed.len() as u32;
    let score_sum = completed
        .iter()
        .map(|trial| u128::from(trial.score_micros))
        .sum::<u128>();
    let mean_score_micros = if completed.is_empty() {
        0
    } else {
        (score_sum / completed.len() as u128) as u32
    };
    let pass_count = completed
        .iter()
        .filter(|trial| trial.status == STATUS_PASS)
        .count() as u128;
    let pass_rate_basis_points = if completed.is_empty() {
        0
    } else {
        ((pass_count * 10_000) / completed.len() as u128) as u32
    };
    let variance = if completed.is_empty() {
        0
    } else {
        completed
            .iter()
            .map(|trial| {
                let delta = i128::from(trial.score_micros) - i128::from(mean_score_micros);
                (delta * delta) as u128
            })
            .sum::<u128>()
            / completed.len() as u128
    };
    let score_variance_micros_squared = u64::try_from(variance).unwrap_or(u64::MAX);
    let total_input_tokens = trials
        .iter()
        .map(|trial| u64::from(trial.input_tokens))
        .sum::<u64>()
        .min(u64::from(u32::MAX)) as u32;
    let total_output_tokens = trials
        .iter()
        .map(|trial| u64::from(trial.output_tokens))
        .sum::<u64>()
        .min(u64::from(u32::MAX)) as u32;
    let total_retry_accounted_tokens = trials
        .iter()
        .map(|trial| u64::from(trial.retry_accounted_tokens))
        .sum::<u64>()
        .min(u64::from(u32::MAX)) as u32;
    let complete_population = completed_trial_count == policy.trial_count;
    let accepted = complete_population
        && mean_score_micros >= policy.minimum_mean_score_micros
        && pass_rate_basis_points >= policy.minimum_pass_rate_basis_points
        && score_variance_micros_squared <= policy.maximum_score_variance_micros_squared;
    let (status, reason_code) = if complete_population && accepted {
        (STATUS_PASS, REASON_STOCHASTIC_ACCEPTED)
    } else if complete_population {
        (STATUS_FAIL, REASON_STOCHASTIC_REJECTED)
    } else {
        trials
            .iter()
            .find(|trial| !matches!(trial.status.as_str(), STATUS_PASS | STATUS_FAIL))
            .map(|trial| (trial.status.as_str(), trial.reason_code.as_str()))
            .unwrap_or((STATUS_UNAVAILABLE, REASON_STOCHASTIC_POPULATION_INCOMPLETE))
    };
    DerivedStochasticAggregate {
        completed_trial_count,
        mean_score_micros,
        pass_rate_basis_points,
        score_variance_micros_squared,
        total_input_tokens,
        total_output_tokens,
        total_retry_accounted_tokens,
        accepted,
        status: status.into(),
        reason_code: reason_code.into(),
    }
}

fn validate_stochastic_step_evidence(
    node: &ResolvedEvaluationNode,
    evidence: &StochasticStepEvidence,
    step_status: &str,
    step_reason_code: &str,
    step_result_digest: &str,
) -> Result<(), String> {
    let policy = node
        .evaluator
        .stochastic_policy
        .as_ref()
        .ok_or_else(|| "stochastic evidence has no frozen policy".to_string())?;
    if evidence.contract_version != STOCHASTIC_STEP_EVIDENCE_CONTRACT
        || evidence.provider != policy.provider
        || evidence.model != policy.model
        || evidence.prompt_profile != policy.prompt_profile
        || evidence.prompt_profile_digest != policy.prompt_profile_digest
        || evidence.result_schema != policy.result_schema
        || evidence.trial_count != policy.trial_count
        || evidence.aggregation_rule != policy.aggregation_rule
        || evidence.minimum_mean_score_micros != policy.minimum_mean_score_micros
        || evidence.minimum_pass_rate_basis_points != policy.minimum_pass_rate_basis_points
        || evidence.maximum_score_variance_micros_squared
            != policy.maximum_score_variance_micros_squared
        || evidence.gate_eligible != policy.gate_eligible
        || evidence.trials.len() != policy.trial_count as usize
    {
        return Err("stochastic step evidence does not match the frozen policy".into());
    }
    for (expected, trial) in evidence.trials.iter().enumerate() {
        if trial.trial_index != expected as u32
            || trial.seed != stochastic_seed(policy, expected as u32)?
            || trial.attempt_count > policy.max_retries_per_trial + 1
            || !matches!(
                trial.status.as_str(),
                STATUS_PASS
                    | STATUS_FAIL
                    | STATUS_UNKNOWN
                    | STATUS_UNAVAILABLE
                    | STATUS_ERROR
                    | STATUS_SKIPPED
            )
        {
            return Err("stochastic trial evidence is invalid".into());
        }
        let completed = matches!(trial.status.as_str(), STATUS_PASS | STATUS_FAIL);
        if (completed && trial.attempt_count == 0)
            || trial.score_micros > 1_000_000
            || trial.input_tokens.saturating_add(trial.output_tokens) > policy.max_tokens_per_trial
            || trial.retry_accounted_tokens % policy.max_tokens_per_trial != 0
            || trial.retry_accounted_tokens
                > trial
                    .attempt_count
                    .saturating_sub(u32::from(completed))
                    .saturating_mul(policy.max_tokens_per_trial)
            || (!completed && trial.score_micros != 0)
        {
            return Err("stochastic trial evidence values are invalid".into());
        }
        validate_reason_code(&trial.reason_code)?;
        validate_digest("stochastic trial result_digest", &trial.result_digest)?;
    }
    let aggregate = derive_stochastic_aggregate(policy, &evidence.trials);
    if evidence.completed_trial_count != aggregate.completed_trial_count
        || evidence.mean_score_micros != aggregate.mean_score_micros
        || evidence.pass_rate_basis_points != aggregate.pass_rate_basis_points
        || evidence.score_variance_micros_squared != aggregate.score_variance_micros_squared
        || evidence.total_input_tokens != aggregate.total_input_tokens
        || evidence.total_output_tokens != aggregate.total_output_tokens
        || evidence.total_retry_accounted_tokens != aggregate.total_retry_accounted_tokens
        || u64::from(aggregate.total_input_tokens)
            + u64::from(aggregate.total_output_tokens)
            + u64::from(aggregate.total_retry_accounted_tokens)
            > u64::from(policy.max_total_tokens)
        || step_status != aggregate.status
        || step_reason_code != aggregate.reason_code
    {
        return Err("stochastic aggregate evidence is inconsistent with its trials".into());
    }
    if stochastic_aggregate_digest(evidence)? != evidence.aggregate_digest {
        return Err("stochastic aggregate digest is invalid".into());
    }
    let aggregate_result = serde_json::json!({
        "aggregate_digest": evidence.aggregate_digest,
        "accepted": aggregate.accepted,
        "completed_trial_count": aggregate.completed_trial_count,
        "mean_score_micros": aggregate.mean_score_micros,
        "pass_rate_basis_points": aggregate.pass_rate_basis_points,
        "score_variance_micros_squared": aggregate.score_variance_micros_squared,
    });
    let expected_result_digest = digest_json(&(
        EVALUATOR_RESULT_CONTRACT,
        aggregate.status.as_str(),
        aggregate.reason_code.as_str(),
        aggregate_result,
    ))?;
    if step_result_digest != expected_result_digest {
        return Err("stochastic aggregate result digest is invalid".into());
    }
    Ok(())
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
        stochastic_evidence: None,
        step_receipt_digest: String::new(),
    };
    receipt.step_receipt_digest = step_receipt_digest(&receipt)?;
    ensure_document_size(
        &receipt,
        "evaluation step receipt",
        MAX_EXECUTION_DOCUMENT_BYTES,
    )?;
    Ok(NodeExecution { receipt, elapsed })
}

fn step_receipt_digest(receipt: &EvaluationStepReceipt) -> Result<String, String> {
    if let Some(stochastic) = &receipt.stochastic_evidence {
        digest_json(&(
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
            stochastic,
        ))
    } else {
        // Preserve the shipped deterministic v1 digest contract exactly.
        digest_json(&(
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
        ))
    }
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
    if matches!(step.status.as_str(), STATUS_PASS | STATUS_FAIL)
        && node.evaluator.stochastic_policy.is_some()
        && step.stochastic_evidence.is_none()
    {
        return Err("completed stochastic step lacks statistical evidence".into());
    }
    if node.evaluator.stochastic_policy.is_none() && step.stochastic_evidence.is_some() {
        return Err("deterministic step cannot contain stochastic evidence".into());
    }
    if let Some(evidence) = &step.stochastic_evidence {
        validate_stochastic_step_evidence(
            node,
            evidence,
            &step.status,
            &step.reason_code,
            &step.result_digest,
        )?;
    }
    let digest = step_receipt_digest(step)?;
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
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::TcpListener;
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

    struct ScriptedStochasticEvaluator {
        calls: Arc<Mutex<Vec<(u32, i64)>>>,
        results: Mutex<VecDeque<Result<StochasticTrialOutput, StochasticTrialError>>>,
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl StochasticEvaluator for ScriptedStochasticEvaluator {
        async fn evaluate_trial(
            &self,
            input: &StochasticTrialInput,
        ) -> Result<StochasticTrialOutput, StochasticTrialError> {
            tokio::time::sleep(self.delay).await;
            self.calls
                .lock()
                .unwrap()
                .push((input.trial_index, input.seed));
            self.results.lock().unwrap().pop_front().unwrap()
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
                stochastic_policy: None,
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

    fn stochastic_policy() -> StochasticEvaluatorPolicy {
        StochasticEvaluatorPolicy {
            provider: "openai".into(),
            model: "openai/fixture-model".into(),
            prompt_profile: "fixture.rubric/v1".into(),
            prompt_profile_digest: digest('9'),
            result_schema: STOCHASTIC_TRIAL_RESULT_CONTRACT.into(),
            trial_count: 3,
            temperature_millis: 200,
            top_p_millionths: 900_000,
            seed_supported: true,
            base_seed: 40,
            aggregation_rule: crate::chisei::evaluation_plan::STOCHASTIC_AGGREGATION_MEAN_VARIANCE
                .into(),
            minimum_mean_score_micros: 800_000,
            minimum_pass_rate_basis_points: 6_666,
            maximum_score_variance_micros_squared: 7_000_000_000,
            gate_eligible: true,
            max_retries_per_trial: 1,
            max_tokens_per_trial: 100,
            max_total_tokens: 600,
            egress_policy: crate::chisei::evaluation_plan::STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL
                .into(),
            raw_response_retention: crate::chisei::evaluation_plan::STOCHASTIC_RAW_RETENTION_NONE
                .into(),
        }
    }

    fn stochastic_node() -> ResolvedEvaluationNode {
        let mut node = node("model-review", NODE_REQUIRED, &[]);
        node.evaluator.stochastic_policy = Some(stochastic_policy());
        node
    }

    fn stochastic_output(
        passed: bool,
        score_micros: u32,
        raw_marker: &str,
    ) -> StochasticTrialOutput {
        StochasticTrialOutput {
            contract_version: STOCHASTIC_TRIAL_RESULT_CONTRACT.into(),
            passed,
            score_micros,
            reason_code: if passed {
                "fixture_pass"
            } else {
                "fixture_fail"
            }
            .into(),
            result: serde_json::json!({"private_model_text": raw_marker}),
            input_tokens: 10,
            output_tokens: 5,
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

    #[test]
    fn external_adapter_registration_is_namespace_scoped() {
        let registry = DeterministicEvaluatorRegistry::default();
        let definition_digest = digest('d');
        let implementation_digest = digest('e');
        registry
            .register_external_adapter(
                "acme",
                &definition_digest,
                &implementation_digest,
                "https://adapter.example/evaluate",
            )
            .unwrap();
        assert!(registry.contains_external_adapter(
            "acme",
            &definition_digest,
            &implementation_digest
        ));
        assert!(!registry.contains_external_adapter(
            "other",
            &definition_digest,
            &implementation_digest
        ));
        assert!(!registry.contains_external_adapter("acme", &definition_digest, &digest('a')));
    }

    #[test]
    fn external_adapter_registration_binds_the_definition_endpoint() {
        let registry = DeterministicEvaluatorRegistry::default();
        let implementation_digest = digest('e');
        let first_definition = digest('d');
        let second_definition = digest('f');
        registry
            .register_external_adapter(
                "acme",
                &first_definition,
                &implementation_digest,
                "https://adapter-a.example/evaluate",
            )
            .unwrap();
        registry
            .register_external_adapter(
                "acme",
                &second_definition,
                &implementation_digest,
                "https://adapter-b.example/evaluate",
            )
            .unwrap();
        assert!(registry.contains_external_adapter(
            "acme",
            &first_definition,
            &implementation_digest
        ));
        assert!(registry.contains_external_adapter(
            "acme",
            &second_definition,
            &implementation_digest
        ));
        assert_eq!(
            registry.metric_labels_for_namespace("acme", &first_definition, &implementation_digest),
            ("external_adapter", "v1")
        );
        let implementations = registry.implementations.read().unwrap();
        assert_eq!(
            implementations[&external_registration_key("acme", &first_definition)]
                .external_binding
                .as_ref()
                .unwrap()
                .endpoint,
            "https://adapter-a.example/evaluate"
        );
        assert_eq!(
            implementations[&external_registration_key("acme", &second_definition)]
                .external_binding
                .as_ref()
                .unwrap()
                .endpoint,
            "https://adapter-b.example/evaluate"
        );
    }

    #[test]
    fn external_adapter_invocation_uses_signed_bounded_json_contract() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let implementation_digest = digest('e');
        let server_implementation_digest = implementation_digest.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4 * 1024];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .or_else(|| line.strip_prefix("Content-Length:"))
                    })
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap();
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let body = &request[header_end + 4..];
            let header_value = |name: &str| {
                headers.lines().find_map(|line| {
                    line.strip_prefix(name)
                        .or_else(|| line.strip_prefix(&name.to_ascii_uppercase()))
                        .map(str::trim)
                })
            };
            let request_digest = header_value("x-sekai-adapter-request-digest:").unwrap();
            assert_eq!(request_digest, format!("sha256:{:x}", Sha256::digest(body)));
            assert_eq!(
                header_value("x-sekai-adapter-contract:"),
                Some(EXTERNAL_ADAPTER_REQUEST_CONTRACT)
            );
            let expected_signature =
                ExternalHttpEvaluator::signature("fixture-secret", request_digest);
            assert_eq!(
                header_value("x-sekai-adapter-signature:"),
                Some(expected_signature.as_str())
            );
            let request_json: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(request_json["namespace"], "acme");
            assert_eq!(request_json["input"]["parameters"]["threshold"], 1.5);
            let result_body = r#"{"contract_version":"chisei.deterministic-evaluator-result/v1","status":"pass","reason_code":"fixture_pass","result":{"ok":true}}"#;
            let response_digest = format!("sha256:{:x}", Sha256::digest(result_body.as_bytes()));
            let response_signature = ExternalHttpEvaluator::response_signature(
                "fixture-secret",
                request_digest,
                &response_digest,
                &server_implementation_digest,
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-sekai-adapter-response-digest: {}\r\nx-sekai-adapter-response-signature: {}\r\nConnection: close\r\n\r\n{}",
                result_body.len(),
                response_digest,
                response_signature,
                result_body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let evaluator = ExternalHttpEvaluator::new_with_secret(
            "acme",
            &implementation_digest,
            &format!("http://{address}/evaluate"),
            "fixture-secret",
        )
        .unwrap();
        let manifest = manifest(vec![node("check", NODE_REQUIRED, &[])]);
        let node = &manifest.nodes[0];
        let mut evaluator_input = input(&manifest, node);
        evaluator_input.parameters = serde_json::json!({"threshold": 1.5});
        let output = evaluator.evaluate(&evaluator_input).unwrap();
        assert_eq!(output.status, STATUS_PASS);
        assert_eq!(output.reason_code, "fixture_pass");
        server.join().unwrap();
    }

    #[test]
    fn deterministic_evaluator_result_rejects_unknown_fields() {
        let result = serde_json::from_value::<DeterministicEvaluatorOutput>(serde_json::json!({
            "contract_version": EVALUATOR_RESULT_CONTRACT,
            "status": STATUS_PASS,
            "reason_code": "fixture_pass",
            "result": {"ok": true},
            "unexpected": true
        }));
        assert!(result.is_err());
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
    fn stochastic_trials_retry_the_same_slot_and_persist_only_normalized_evidence() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let registry = StochasticEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(ScriptedStochasticEvaluator {
                    calls: calls.clone(),
                    results: Mutex::new(VecDeque::from([
                        Err(StochasticTrialError::Retryable),
                        Ok(stochastic_output(true, 900_000, "raw-secret-one")),
                        Ok(stochastic_output(true, 700_000, "raw-secret-two")),
                        Ok(stochastic_output(false, 800_000, "raw-secret-three")),
                    ])),
                    delay: Duration::ZERO,
                }),
            )
            .unwrap();
        let manifest = manifest(vec![stochastic_node()]);
        let execution = execute_stochastic_node(
            &registry,
            &manifest,
            &manifest.nodes[0],
            input(&manifest, &manifest.nodes[0]),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        assert_eq!(execution.receipt.status, STATUS_PASS);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(0, 40), (0, 40), (1, 41), (2, 42)]
        );
        let evidence = execution.receipt.stochastic_evidence.as_ref().unwrap();
        assert_eq!(evidence.completed_trial_count, 3);
        assert_eq!(evidence.mean_score_micros, 800_000);
        assert_eq!(evidence.pass_rate_basis_points, 6_666);
        assert_eq!(evidence.score_variance_micros_squared, 6_666_666_666);
        assert_eq!(evidence.trials[0].attempt_count, 2);
        assert_eq!(evidence.trials[0].retry_accounted_tokens, 100);
        assert_eq!(evidence.total_input_tokens, 30);
        assert_eq!(evidence.total_output_tokens, 15);
        assert_eq!(evidence.total_retry_accounted_tokens, 100);
        let persisted = serde_json::to_string(&execution.receipt).unwrap();
        assert!(!persisted.contains("raw-secret"));
        assert!(!persisted.contains("private_model_text"));
        validate_step_for_node(&manifest, &manifest.nodes[0], &execution.receipt).unwrap();
    }

    #[test]
    fn stochastic_receipt_validation_recomputes_aggregate_evidence() {
        let registry = StochasticEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(ScriptedStochasticEvaluator {
                    calls: Arc::new(Mutex::new(Vec::new())),
                    results: Mutex::new(VecDeque::from([
                        Ok(stochastic_output(true, 900_000, "one")),
                        Ok(stochastic_output(true, 800_000, "two")),
                        Ok(stochastic_output(true, 700_000, "three")),
                    ])),
                    delay: Duration::ZERO,
                }),
            )
            .unwrap();
        let manifest = manifest(vec![stochastic_node()]);
        let mut receipt = execute_stochastic_node(
            &registry,
            &manifest,
            &manifest.nodes[0],
            input(&manifest, &manifest.nodes[0]),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
        .receipt;
        let evidence = receipt.stochastic_evidence.as_mut().unwrap();
        evidence.completed_trial_count = 0;
        evidence.aggregate_digest = stochastic_aggregate_digest(evidence).unwrap();
        receipt.step_receipt_digest = step_receipt_digest(&receipt).unwrap();

        assert!(
            validate_step_for_node(&manifest, &manifest.nodes[0], &receipt)
                .unwrap_err()
                .contains("inconsistent with its trials")
        );
    }

    #[test]
    fn stochastic_node_cannot_execute_through_deterministic_registry() {
        let registry = DeterministicEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(FixedEvaluator {
                    status: STATUS_PASS,
                    result: Value::Null,
                    calls: Arc::new(AtomicUsize::new(0)),
                    delay: Duration::ZERO,
                }),
            )
            .unwrap();
        let manifest = manifest(vec![stochastic_node()]);
        let error = execute_registered_node(
            &registry,
            &manifest,
            &manifest.nodes[0],
            input(&manifest, &manifest.nodes[0]),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap_err();

        assert!(error.contains("cannot execute through the deterministic registry"));
    }

    #[test]
    fn incomplete_stochastic_population_is_typed_non_pass() {
        let registry = StochasticEvaluatorRegistry::default();
        registry
            .register(
                &digest('e'),
                Arc::new(ScriptedStochasticEvaluator {
                    calls: Arc::new(Mutex::new(Vec::new())),
                    results: Mutex::new(VecDeque::from([Err(
                        StochasticTrialError::ProviderUnavailable,
                    )])),
                    delay: Duration::ZERO,
                }),
            )
            .unwrap();
        let manifest = manifest(vec![stochastic_node()]);
        let execution = execute_stochastic_node(
            &registry,
            &manifest,
            &manifest.nodes[0],
            input(&manifest, &manifest.nodes[0]),
            &limits(),
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        assert_eq!(execution.receipt.status, STATUS_UNAVAILABLE);
        assert_eq!(
            execution.receipt.reason_code,
            REASON_STOCHASTIC_PROVIDER_UNAVAILABLE
        );
        let evidence = execution.receipt.stochastic_evidence.unwrap();
        assert_eq!(evidence.completed_trial_count, 0);
        assert_eq!(evidence.trials.len(), 3);
        assert_eq!(evidence.trials[1].status, STATUS_SKIPPED);
        assert_ne!(execution.receipt.status, STATUS_PASS);
    }

    #[test]
    fn stochastic_refusal_schema_error_and_timeout_remain_typed_non_pass() {
        let cases = [
            (
                Err(StochasticTrialError::Refusal {
                    input_tokens: 11,
                    output_tokens: 7,
                }),
                Duration::ZERO,
                STATUS_UNKNOWN,
                REASON_STOCHASTIC_REFUSAL,
                11,
                7,
            ),
            (
                Err(StochasticTrialError::SchemaInvalid {
                    input_tokens: 12,
                    output_tokens: 8,
                }),
                Duration::ZERO,
                STATUS_ERROR,
                REASON_STOCHASTIC_SCHEMA_INVALID,
                12,
                8,
            ),
            (
                Err(StochasticTrialError::TokenBudgetExceeded),
                Duration::ZERO,
                STATUS_UNAVAILABLE,
                REASON_STOCHASTIC_TOKEN_BUDGET,
                0,
                0,
            ),
            (
                Ok(stochastic_output(true, 900_000, "late-raw-secret")),
                Duration::from_millis(30),
                STATUS_UNAVAILABLE,
                REASON_EVALUATOR_TIMEOUT,
                0,
                0,
            ),
        ];
        for (
            result,
            delay,
            expected_status,
            expected_reason,
            expected_input_tokens,
            expected_output_tokens,
        ) in cases
        {
            let registry = StochasticEvaluatorRegistry::default();
            registry
                .register(
                    &digest('e'),
                    Arc::new(ScriptedStochasticEvaluator {
                        calls: Arc::new(Mutex::new(Vec::new())),
                        results: Mutex::new(VecDeque::from([result])),
                        delay,
                    }),
                )
                .unwrap();
            let manifest = manifest(vec![stochastic_node()]);
            let mut resource_limits = limits();
            if !delay.is_zero() {
                resource_limits.timeout_ms = 5;
            }
            let execution = execute_stochastic_node(
                &registry,
                &manifest,
                &manifest.nodes[0],
                input(&manifest, &manifest.nodes[0]),
                &resource_limits,
                Duration::from_secs(1),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();

            assert_eq!(execution.receipt.status, expected_status);
            assert_eq!(execution.receipt.reason_code, expected_reason);
            let evidence = execution.receipt.stochastic_evidence.as_ref().unwrap();
            assert_eq!(evidence.total_input_tokens, expected_input_tokens);
            assert_eq!(evidence.total_output_tokens, expected_output_tokens);
            assert_ne!(execution.receipt.status, STATUS_PASS);
        }
    }

    #[test]
    fn stochastic_timeout_drops_provider_work_and_releases_capacity() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let registry = StochasticEvaluatorRegistry::with_thread_capacity(1).unwrap();
        registry
            .register(
                &digest('e'),
                Arc::new(ScriptedStochasticEvaluator {
                    calls: calls.clone(),
                    results: Mutex::new(VecDeque::from([Ok(stochastic_output(
                        true,
                        900_000,
                        "late-raw-secret",
                    ))])),
                    delay: Duration::from_millis(100),
                }),
            )
            .unwrap();
        let manifest = manifest(vec![stochastic_node()]);
        let mut resource_limits = limits();
        resource_limits.timeout_ms = 5;

        let execution = execute_stochastic_node(
            &registry,
            &manifest,
            &manifest.nodes[0],
            input(&manifest, &manifest.nodes[0]),
            &resource_limits,
            Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        assert_eq!(execution.receipt.reason_code, REASON_EVALUATOR_TIMEOUT);
        assert!(registry.try_acquire_thread().is_some());
        std::thread::sleep(Duration::from_millis(120));
        assert!(calls.lock().unwrap().is_empty());
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
