//! Immutable evaluator definitions and situation-specific evaluation plans.
//!
//! This is deliberately a closed evaluation vocabulary, not a workflow
//! engine. Plans select exact evaluator versions and situation-specific policy,
//! bind typed inputs, cover exact governed invariant versions, and use one
//! fixed reducer.

use http::Uri;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::chisei::builtin_evaluators::{builtin_parameter_schema, validate_builtin_parameters};
use crate::chisei::evaluation_metrics::{
    self, METRICS_RESULT_SCHEMA, MetricDeclaration, MetricObjective,
};
use sekai_core::sekai::parameter_schema::parse_parameter_schema;
pub use sekai_core::sekai::parameter_schema::{validate_parameter_schema, validate_parameters};

pub const EVALUATOR_DEFINITION_CONTRACT: &str = "chisei.evaluator-definition/v1";
pub const EVALUATION_PLAN_CONTRACT: &str = "chisei.evaluation-plan/v1";
pub const DETERMINISTIC_EXECUTION_CLASS: &str = "deterministic_builtin/v1";
pub const EXTERNAL_ADAPTER_EXECUTION_CLASS: &str = "external_adapter/v1";
pub const STOCHASTIC_EXECUTION_CLASS: &str = "stochastic_model/v1";
pub const STOCHASTIC_AGGREGATION_MEAN_VARIANCE: &str = "mean_score_with_variance/v1";
pub const STOCHASTIC_RESULT_SCHEMA: &str = "chisei.stochastic-trial-result/v1";
pub const STOCHASTIC_EGRESS_LOCAL_ONLY: &str = "local_only/v1";
pub const STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL: &str = "allowlisted_external/v1";
pub const STOCHASTIC_RAW_RETENTION_NONE: &str = "none/v1";
/// Retains only the judge's bounded `rationale` per trial (#2630, ADR 0012),
/// in the dedicated evaluation rationale store, for [`RATIONALE_TTL_MS`].
pub const STOCHASTIC_RETENTION_RATIONALE: &str = "rationale/v1";
/// How long `rationale/v1` keeps a rationale. Fixed by the policy version, so
/// the immutable policy freezes it.
pub const RATIONALE_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
/// Upper bound on one retained rationale, in UTF-8 bytes: 1,024 characters
/// of at most four bytes each.
pub const MAX_RATIONALE_BYTES: usize = 4_096;
pub const FIXED_REDUCER: &str = "required_all_pass_advisory_observed/v1";
pub const AVAILABILITY_ENABLED: &str = "enabled";
pub const AVAILABILITY_DISABLED: &str = "disabled";
pub const AVAILABILITY_SUPERSEDED: &str = "superseded";
pub const NODE_REQUIRED: &str = "required";
pub const NODE_ADVISORY: &str = "advisory";
pub const INPUT_SUBJECT: &str = "subject";
pub const INPUT_INVARIANT: &str = "invariant";
pub const INPUT_EVIDENCE: &str = "evidence";

pub const MAX_PLAN_NODES: usize = 64;
pub const MAX_NODE_DEPENDENCIES: usize = 16;
pub const MAX_NODE_BINDINGS: usize = 16;
pub const MAX_NODE_INVARIANTS: usize = 64;
pub const MAX_PLAN_DEPENDENCIES: usize = 256;
pub const MAX_PLAN_BINDINGS: usize = 256;
pub const MAX_PLAN_INVARIANTS: usize = 256;
const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
const MAX_STRING_BYTES: usize = 1_024;
pub const MIN_STOCHASTIC_TRIALS: u32 = 2;
pub const MAX_STOCHASTIC_TRIALS: u32 = 32;
pub const MAX_STOCHASTIC_RETRIES_PER_TRIAL: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatorResourceLimits {
    pub timeout_ms: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_evidence_items: u32,
}

/// Immutable, situation-specific model evaluation policy.
///
/// Integer units keep canonicalization independent of floating-point
/// implementations. Scores and temperature are millionths and thousandths
/// respectively; pass rate is expressed in basis points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StochasticEvaluatorPolicy {
    pub provider: String,
    pub model: String,
    pub prompt_profile: String,
    pub prompt_profile_digest: String,
    pub result_schema: String,
    pub trial_count: u32,
    pub temperature_millis: u32,
    pub top_p_millionths: u32,
    pub seed_supported: bool,
    pub base_seed: i64,
    pub aggregation_rule: String,
    pub minimum_mean_score_micros: u32,
    pub minimum_pass_rate_basis_points: u32,
    pub maximum_score_variance_micros_squared: u64,
    pub gate_eligible: bool,
    pub max_retries_per_trial: u32,
    pub max_tokens_per_trial: u32,
    pub max_total_tokens: u32,
    pub egress_policy: String,
    pub raw_response_retention: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatorDefinition {
    pub contract_version: String,
    pub definition_id: String,
    pub namespace: String,
    pub evaluator_id: String,
    pub version: String,
    pub implementation_digest: String,
    pub execution_class: String,
    pub supported_predicate_kinds: Vec<String>,
    pub supported_input_schemas: Vec<String>,
    pub supported_result_schemas: Vec<String>,
    pub parameter_schema_json: String,
    pub evidence_classifications: Vec<String>,
    pub resource_limits: EvaluatorResourceLimits,
    /// Operator-deployed adapter endpoint. This is never executable code and is
    /// only valid for `external_adapter/v1` definitions.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub adapter_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stochastic_policy: Option<StochasticEvaluatorPolicy>,
    /// Metrics a `chisei.evaluation-metrics/v1` evaluator reports (ADR 0154).
    /// Empty for single-status evaluators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_metrics: Vec<MetricDeclaration>,
    pub source_ref: String,
    pub content_digest: String,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatorAvailability {
    pub definition_id: String,
    pub state: String,
    pub superseded_by_definition_id: String,
    pub reason: String,
    pub request_id: String,
    pub request_digest: String,
    pub changed_by: String,
    pub changed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationInputBinding {
    pub name: String,
    pub source_kind: String,
    pub schema_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationPlanNode {
    pub node_id: String,
    pub evaluator_definition_id: String,
    pub depends_on_node_ids: Vec<String>,
    pub input_bindings: Vec<EvaluationInputBinding>,
    pub parameters_json: String,
    pub invariant_version_ids: Vec<String>,
    pub classification: String,
    /// Plan-owned objectives over the evaluator's declared metrics (ADR 0154).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metric_objectives: Vec<MetricObjective>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationPlan {
    pub contract_version: String,
    pub plan_version_id: String,
    pub namespace: String,
    pub plan_id: String,
    pub version: String,
    pub accepted_subject_profiles: Vec<String>,
    pub nodes: Vec<EvaluationPlanNode>,
    pub reducer: String,
    pub source_ref: String,
    pub content_digest: String,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Serialize)]
struct CanonicalDefinition<'a> {
    contract_version: &'a str,
    namespace: &'a str,
    evaluator_id: &'a str,
    version: &'a str,
    implementation_digest: &'a str,
    execution_class: &'a str,
    supported_predicate_kinds: &'a [String],
    supported_input_schemas: &'a [String],
    supported_result_schemas: &'a [String],
    parameter_schema: Value,
    evidence_classifications: &'a [String],
    resource_limits: &'a EvaluatorResourceLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    stochastic_policy: Option<&'a StochasticEvaluatorPolicy>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    declared_metrics: &'a [MetricDeclaration],
    source_ref: &'a str,
}

#[derive(Serialize)]
struct CanonicalExternalDefinition<'a> {
    contract_version: &'a str,
    namespace: &'a str,
    evaluator_id: &'a str,
    version: &'a str,
    implementation_digest: &'a str,
    execution_class: &'a str,
    adapter_endpoint: &'a str,
    supported_predicate_kinds: &'a [String],
    supported_input_schemas: &'a [String],
    supported_result_schemas: &'a [String],
    parameter_schema: Value,
    evidence_classifications: &'a [String],
    resource_limits: &'a EvaluatorResourceLimits,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    declared_metrics: &'a [MetricDeclaration],
    source_ref: &'a str,
}

#[derive(Serialize)]
struct CanonicalPlan<'a> {
    contract_version: &'a str,
    namespace: &'a str,
    plan_id: &'a str,
    version: &'a str,
    accepted_subject_profiles: &'a [String],
    nodes: &'a [EvaluationPlanNode],
    reducer: &'a str,
    source_ref: &'a str,
}

pub fn prepare_definition(
    mut definition: EvaluatorDefinition,
    actor: &str,
    now_ms: i64,
) -> Result<EvaluatorDefinition, String> {
    definition.contract_version = canonical_contract(
        &definition.contract_version,
        EVALUATOR_DEFINITION_CONTRACT,
        "evaluator definition",
    )?;
    validate_token("namespace", &definition.namespace)?;
    validate_token("evaluator_id", &definition.evaluator_id)?;
    validate_version(&definition.version)?;
    validate_digest("implementation_digest", &definition.implementation_digest)?;
    match definition.execution_class.as_str() {
        DETERMINISTIC_EXECUTION_CLASS if definition.stochastic_policy.is_none() => {}
        DETERMINISTIC_EXECUTION_CLASS => {
            return Err("deterministic evaluator cannot declare stochastic policy".into());
        }
        EXTERNAL_ADAPTER_EXECUTION_CLASS if definition.stochastic_policy.is_none() => {
            validate_adapter_endpoint(&definition.adapter_endpoint)?;
        }
        EXTERNAL_ADAPTER_EXECUTION_CLASS => {
            return Err("external adapter evaluator cannot declare stochastic policy".into());
        }
        STOCHASTIC_EXECUTION_CLASS => {
            if !definition.adapter_endpoint.is_empty() {
                return Err("stochastic evaluator cannot declare an adapter endpoint".into());
            }
            let policy = definition
                .stochastic_policy
                .as_ref()
                .ok_or_else(|| "stochastic evaluator policy is required".to_string())?;
            validate_stochastic_policy(policy, &definition.supported_result_schemas)?;
        }
        _ => return Err("unknown evaluator execution_class".into()),
    }
    normalize_tokens(
        "supported_predicate_kinds",
        &mut definition.supported_predicate_kinds,
        false,
    )?;
    normalize_tokens(
        "supported_input_schemas",
        &mut definition.supported_input_schemas,
        false,
    )?;
    normalize_tokens(
        "supported_result_schemas",
        &mut definition.supported_result_schemas,
        false,
    )?;
    normalize_classifications(&mut definition.evidence_classifications)?;
    validate_resource_limits(&definition.resource_limits)?;
    validate_declared_metrics(&mut definition)?;
    if definition.execution_class == DETERMINISTIC_EXECUTION_CLASS
        && !definition.adapter_endpoint.is_empty()
    {
        return Err("deterministic evaluator cannot declare an adapter endpoint".into());
    }
    validate_reference("source_ref", &definition.source_ref)?;
    let parameter_schema = parse_parameter_schema(&definition.parameter_schema_json)?;
    if let Some(builtin_schema) = builtin_parameter_schema(&definition.implementation_digest) {
        if definition.execution_class != DETERMINISTIC_EXECUTION_CLASS {
            return Err(
                "a built-in implementation digest requires deterministic_builtin/v1".into(),
            );
        }
        if canonical_schema(parameter_schema.clone())
            != canonical_schema(parse_parameter_schema(builtin_schema)?)
        {
            return Err(
                "parameter_schema_json must equal the built-in evaluator's published schema".into(),
            );
        }
    }
    definition.parameter_schema_json =
        serde_json::to_string(&parameter_schema).map_err(|error| error.to_string())?;
    if actor.trim().is_empty() || now_ms <= 0 {
        return Err("authenticated actor and positive creation time required".into());
    }
    definition.definition_id = resource_id(
        "evaluator-definition",
        &[
            &definition.namespace,
            &definition.evaluator_id,
            &definition.version,
        ],
    );
    definition.content_digest = if definition.execution_class == EXTERNAL_ADAPTER_EXECUTION_CLASS {
        digest_json(&CanonicalExternalDefinition {
            contract_version: &definition.contract_version,
            namespace: &definition.namespace,
            evaluator_id: &definition.evaluator_id,
            version: &definition.version,
            implementation_digest: &definition.implementation_digest,
            execution_class: &definition.execution_class,
            adapter_endpoint: &definition.adapter_endpoint,
            supported_predicate_kinds: &definition.supported_predicate_kinds,
            supported_input_schemas: &definition.supported_input_schemas,
            supported_result_schemas: &definition.supported_result_schemas,
            parameter_schema,
            evidence_classifications: &definition.evidence_classifications,
            resource_limits: &definition.resource_limits,
            declared_metrics: &definition.declared_metrics,
            source_ref: &definition.source_ref,
        })?
    } else {
        // Keep the deterministic and stochastic v1 content digest contract
        // stable for definitions persisted before external adapters existed.
        digest_json(&CanonicalDefinition {
            contract_version: &definition.contract_version,
            namespace: &definition.namespace,
            evaluator_id: &definition.evaluator_id,
            version: &definition.version,
            implementation_digest: &definition.implementation_digest,
            execution_class: &definition.execution_class,
            supported_predicate_kinds: &definition.supported_predicate_kinds,
            supported_input_schemas: &definition.supported_input_schemas,
            supported_result_schemas: &definition.supported_result_schemas,
            parameter_schema,
            evidence_classifications: &definition.evidence_classifications,
            resource_limits: &definition.resource_limits,
            stochastic_policy: definition.stochastic_policy.as_ref(),
            declared_metrics: &definition.declared_metrics,
            source_ref: &definition.source_ref,
        })?
    };
    definition.created_by = actor.into();
    definition.created_at_ms = now_ms;
    ensure_size(&definition, "evaluator definition")?;
    Ok(definition)
}

/// Plan-time parameter check for one node: the definition's declared schema,
/// then a built-in implementation's semantic rules (for example a pattern that
/// must compile), so invalid parameters never reach execution.
pub fn validate_node_parameters(
    definition: &EvaluatorDefinition,
    parameters_json: &str,
) -> Result<(), String> {
    validate_parameters(&definition.parameter_schema_json, parameters_json)?;
    validate_builtin_parameters(&definition.implementation_digest, parameters_json)
}

/// Plan-time check of one node against its exact evaluator definition:
/// parameters, then metric objectives against the declared metrics.
pub fn validate_node_for_definition(
    definition: &EvaluatorDefinition,
    node: &EvaluationPlanNode,
) -> Result<(), String> {
    validate_node_parameters(definition, &node.parameters_json)?;
    evaluation_metrics::check_objectives(&definition.declared_metrics, &node.metric_objectives)
}

/// Metric declarations and the closed metrics result schema come together,
/// and only for deterministic or external evaluators: multi-metric stochastic
/// aggregation is not part of ADR 0154.
fn validate_declared_metrics(definition: &mut EvaluatorDefinition) -> Result<(), String> {
    evaluation_metrics::normalize_declarations(&mut definition.declared_metrics)?;
    let lists_schema = definition
        .supported_result_schemas
        .iter()
        .any(|schema| schema == METRICS_RESULT_SCHEMA);
    if lists_schema != !definition.declared_metrics.is_empty() {
        return Err(format!(
            "declared_metrics and the {METRICS_RESULT_SCHEMA} result schema require each other"
        ));
    }
    if lists_schema && definition.execution_class == STOCHASTIC_EXECUTION_CLASS {
        return Err("stochastic evaluators cannot declare metrics".into());
    }
    Ok(())
}

/// Schema equality ignores the order of `required` names.
fn canonical_schema(mut schema: Value) -> Value {
    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        required.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    }
    schema
}

pub fn validate_stochastic_policy(
    policy: &StochasticEvaluatorPolicy,
    supported_result_schemas: &[String],
) -> Result<(), String> {
    validate_token("stochastic provider", &policy.provider)?;
    validate_reference("stochastic model", &policy.model)?;
    validate_reference("stochastic prompt_profile", &policy.prompt_profile)?;
    validate_digest(
        "stochastic prompt_profile_digest",
        &policy.prompt_profile_digest,
    )?;
    validate_reference("stochastic result_schema", &policy.result_schema)?;
    if policy.result_schema != STOCHASTIC_RESULT_SCHEMA {
        return Err("stochastic v1 requires the normalized trial result schema".into());
    }
    if !supported_result_schemas.contains(&policy.result_schema) {
        return Err("stochastic result_schema must be supported by the evaluator".into());
    }
    let resolved_provider =
        chisei_provider::provider_profile::resolve_provider_id(&policy.model)
            .map_err(|_| "stochastic model must use an explicit supported provider prefix")?;
    if resolved_provider != policy.provider {
        return Err("stochastic provider does not match the exact model route".into());
    }
    if !(MIN_STOCHASTIC_TRIALS..=MAX_STOCHASTIC_TRIALS).contains(&policy.trial_count) {
        return Err(format!(
            "stochastic trial_count must be between {MIN_STOCHASTIC_TRIALS} and {MAX_STOCHASTIC_TRIALS}"
        ));
    }
    if policy.temperature_millis > 2_000
        || policy.top_p_millionths == 0
        || policy.top_p_millionths > 1_000_000
    {
        return Err("stochastic sampling parameters are out of bounds".into());
    }
    if (policy.seed_supported && policy.base_seed <= 0)
        || (!policy.seed_supported && policy.base_seed != 0)
    {
        return Err(
            "stochastic base_seed must be positive only when the provider supports seeds".into(),
        );
    }
    if policy.seed_supported
        && policy
            .base_seed
            .checked_add(i64::from(policy.trial_count.saturating_sub(1)))
            .is_none()
    {
        return Err("stochastic base_seed cannot cover every fixed trial slot".into());
    }
    if policy.seed_supported && policy.provider != "openai" {
        return Err(
            "stochastic v1 permits seeded trials only through the OpenAI seed parameter".into(),
        );
    }
    if policy.aggregation_rule != STOCHASTIC_AGGREGATION_MEAN_VARIANCE {
        return Err("unsupported stochastic aggregation_rule".into());
    }
    if policy.minimum_mean_score_micros > 1_000_000
        || policy.minimum_pass_rate_basis_points > 10_000
        || policy.maximum_score_variance_micros_squared > 1_000_000_000_000
    {
        return Err("stochastic acceptance thresholds are out of bounds".into());
    }
    if policy.max_retries_per_trial > MAX_STOCHASTIC_RETRIES_PER_TRIAL {
        return Err(format!(
            "stochastic max_retries_per_trial exceeds {MAX_STOCHASTIC_RETRIES_PER_TRIAL}"
        ));
    }
    if policy.max_tokens_per_trial == 0 || policy.max_total_tokens == 0 {
        return Err("stochastic token budgets must be positive".into());
    }
    if i32::try_from(policy.max_total_tokens).is_err() {
        return Err("stochastic max_total_tokens exceeds the budget tracker range".into());
    }
    let maximum_attempts = u64::from(policy.trial_count)
        .checked_mul(u64::from(policy.max_retries_per_trial) + 1)
        .and_then(|value| value.checked_mul(u64::from(policy.max_tokens_per_trial)))
        .ok_or_else(|| "stochastic token budget overflows".to_string())?;
    if maximum_attempts > u64::from(policy.max_total_tokens) {
        return Err(
            "stochastic max_total_tokens must cover every fixed trial slot and bounded retry"
                .into(),
        );
    }
    match policy.egress_policy.as_str() {
        STOCHASTIC_EGRESS_LOCAL_ONLY if policy.provider == "ollama" => {}
        STOCHASTIC_EGRESS_LOCAL_ONLY => {
            return Err("local-only stochastic egress requires the ollama provider".into());
        }
        STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL if policy.provider != "ollama" => {}
        STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL => {
            return Err("ollama stochastic evaluation must use local-only egress".into());
        }
        _ => return Err("unsupported stochastic egress_policy".into()),
    }
    if !matches!(
        policy.raw_response_retention.as_str(),
        STOCHASTIC_RAW_RETENTION_NONE | STOCHASTIC_RETENTION_RATIONALE
    ) {
        return Err(
            "stochastic raw_response_retention must be none/v1 or rationale/v1; prompts and responses are never retained"
                .into(),
        );
    }
    Ok(())
}

pub fn prepare_plan(
    mut plan: EvaluationPlan,
    actor: &str,
    now_ms: i64,
) -> Result<EvaluationPlan, String> {
    plan.contract_version = canonical_contract(
        &plan.contract_version,
        EVALUATION_PLAN_CONTRACT,
        "evaluation plan",
    )?;
    validate_token("namespace", &plan.namespace)?;
    validate_token("plan_id", &plan.plan_id)?;
    validate_version(&plan.version)?;
    normalize_tokens(
        "accepted_subject_profiles",
        &mut plan.accepted_subject_profiles,
        false,
    )?;
    validate_reference("source_ref", &plan.source_ref)?;
    if plan.reducer != FIXED_REDUCER {
        return Err("unknown reducer; v1 requires the fixed fail-closed reducer".into());
    }
    if plan.nodes.is_empty() || plan.nodes.len() > MAX_PLAN_NODES {
        return Err(format!(
            "evaluation plan requires 1..={MAX_PLAN_NODES} nodes"
        ));
    }
    normalize_and_validate_nodes(&mut plan.nodes)?;
    let dependency_count = plan
        .nodes
        .iter()
        .map(|node| node.depends_on_node_ids.len())
        .sum::<usize>();
    let binding_count = plan
        .nodes
        .iter()
        .map(|node| node.input_bindings.len())
        .sum::<usize>();
    let invariant_count = plan
        .nodes
        .iter()
        .flat_map(|node| node.invariant_version_ids.iter())
        .collect::<BTreeSet<_>>()
        .len();
    if dependency_count > MAX_PLAN_DEPENDENCIES
        || binding_count > MAX_PLAN_BINDINGS
        || invariant_count > MAX_PLAN_INVARIANTS
    {
        return Err("evaluation plan exceeds aggregate graph limits".into());
    }
    let required_coverage = plan
        .nodes
        .iter()
        .filter(|node| node.classification == NODE_REQUIRED)
        .flat_map(|node| node.invariant_version_ids.iter())
        .collect::<BTreeSet<_>>();
    let all_coverage = plan
        .nodes
        .iter()
        .flat_map(|node| node.invariant_version_ids.iter())
        .collect::<BTreeSet<_>>();
    if !all_coverage.is_subset(&required_coverage) {
        return Err("every covered invariant must be covered by a required node".into());
    }
    validate_acyclic(&plan.nodes)?;
    if actor.trim().is_empty() || now_ms <= 0 {
        return Err("authenticated actor and positive creation time required".into());
    }
    plan.plan_version_id = resource_id(
        "evaluation-plan",
        &[&plan.namespace, &plan.plan_id, &plan.version],
    );
    plan.content_digest = digest_json(&CanonicalPlan {
        contract_version: &plan.contract_version,
        namespace: &plan.namespace,
        plan_id: &plan.plan_id,
        version: &plan.version,
        accepted_subject_profiles: &plan.accepted_subject_profiles,
        nodes: &plan.nodes,
        reducer: &plan.reducer,
        source_ref: &plan.source_ref,
    })?;
    plan.created_by = actor.into();
    plan.created_at_ms = now_ms;
    ensure_size(&plan, "evaluation plan")?;
    Ok(plan)
}

pub fn prepare_availability(
    definition: &EvaluatorDefinition,
    state: &str,
    superseded_by_definition_id: &str,
    reason: &str,
    request_id: &str,
    actor: &str,
    now_ms: i64,
) -> Result<EvaluatorAvailability, String> {
    if !matches!(
        state,
        AVAILABILITY_ENABLED | AVAILABILITY_DISABLED | AVAILABILITY_SUPERSEDED
    ) {
        return Err("availability state must be enabled, disabled, or superseded".into());
    }
    validate_token("request_id", request_id)?;
    validate_reference("reason", reason)?;
    if actor.trim().is_empty() || now_ms <= 0 {
        return Err("authenticated actor and positive transition time required".into());
    }
    if state == AVAILABILITY_SUPERSEDED {
        validate_token("superseded_by_definition_id", superseded_by_definition_id)?;
        if superseded_by_definition_id == definition.definition_id {
            return Err("evaluator definition cannot supersede itself".into());
        }
    } else if !superseded_by_definition_id.is_empty() {
        return Err("superseded_by_definition_id is only valid for superseded state".into());
    }
    let request_digest = digest_json(&(
        definition.definition_id.as_str(),
        definition.implementation_digest.as_str(),
        state,
        superseded_by_definition_id,
        reason,
    ))?;
    Ok(EvaluatorAvailability {
        definition_id: definition.definition_id.clone(),
        state: state.into(),
        superseded_by_definition_id: superseded_by_definition_id.into(),
        reason: reason.into(),
        request_id: request_id.into(),
        request_digest,
        changed_by: actor.into(),
        changed_at_ms: now_ms,
    })
}

fn normalize_and_validate_nodes(nodes: &mut [EvaluationPlanNode]) -> Result<(), String> {
    nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let mut node_ids = BTreeSet::new();
    for node in nodes.iter_mut() {
        validate_token("node_id", &node.node_id)?;
        validate_token("evaluator_definition_id", &node.evaluator_definition_id)?;
        if !node_ids.insert(node.node_id.clone()) {
            return Err(format!("duplicate evaluation node {:?}", node.node_id));
        }
        if !matches!(node.classification.as_str(), NODE_REQUIRED | NODE_ADVISORY) {
            return Err("node classification must be required or advisory".into());
        }
        normalize_tokens("depends_on_node_ids", &mut node.depends_on_node_ids, true)?;
        if node.depends_on_node_ids.len() > MAX_NODE_DEPENDENCIES {
            return Err(format!(
                "node dependency count exceeds {MAX_NODE_DEPENDENCIES}"
            ));
        }
        normalize_tokens(
            "invariant_version_ids",
            &mut node.invariant_version_ids,
            false,
        )?;
        if node.invariant_version_ids.len() > MAX_NODE_INVARIANTS {
            return Err(format!(
                "node invariant coverage exceeds {MAX_NODE_INVARIANTS}"
            ));
        }
        if node.input_bindings.is_empty() || node.input_bindings.len() > MAX_NODE_BINDINGS {
            return Err(format!(
                "evaluation node requires 1..={MAX_NODE_BINDINGS} input bindings"
            ));
        }
        node.input_bindings.sort_by(|left, right| {
            (&left.name, &left.source_kind, &left.schema_id).cmp(&(
                &right.name,
                &right.source_kind,
                &right.schema_id,
            ))
        });
        let mut binding_names = BTreeSet::new();
        for binding in &node.input_bindings {
            validate_token("binding name", &binding.name)?;
            validate_reference("binding schema_id", &binding.schema_id)?;
            if !matches!(
                binding.source_kind.as_str(),
                INPUT_SUBJECT | INPUT_INVARIANT | INPUT_EVIDENCE
            ) {
                return Err(
                    "input binding source_kind must be subject, invariant, or evidence".into(),
                );
            }
            if !binding_names.insert(binding.name.as_str()) {
                return Err(format!("duplicate input binding name {:?}", binding.name));
            }
        }
        let parameters: Value = serde_json::from_str(&node.parameters_json)
            .map_err(|error| format!("parameters_json must be JSON: {error}"))?;
        if !parameters.is_object() {
            return Err("parameters_json must be a JSON object".into());
        }
        node.parameters_json =
            serde_json::to_string(&parameters).map_err(|error| error.to_string())?;
        evaluation_metrics::normalize_objectives(&mut node.metric_objectives)?;
    }
    let all_ids = nodes
        .iter()
        .map(|node| node.node_id.clone())
        .collect::<BTreeSet<_>>();
    for node in nodes.iter() {
        for dependency in &node.depends_on_node_ids {
            if dependency == &node.node_id || !all_ids.contains(dependency) {
                return Err(format!(
                    "node {:?} has unknown or self dependency {dependency:?}",
                    node.node_id
                ));
            }
        }
    }
    Ok(())
}

fn validate_acyclic(nodes: &[EvaluationPlanNode]) -> Result<(), String> {
    let mut inbound = nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node.depends_on_node_ids.len()))
        .collect::<BTreeMap<_, _>>();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        for dependency in &node.depends_on_node_ids {
            dependents
                .entry(dependency)
                .or_default()
                .push(&node.node_id);
        }
    }
    let mut ready = inbound
        .iter()
        .filter_map(|(node_id, count)| (*count == 0).then_some(*node_id))
        .collect::<VecDeque<_>>();
    let mut visited = 0;
    while let Some(node_id) = ready.pop_front() {
        visited += 1;
        for dependent in dependents.get(node_id).into_iter().flatten() {
            let count = inbound.get_mut(dependent).expect("known dependent");
            *count -= 1;
            if *count == 0 {
                ready.push_back(dependent);
            }
        }
    }
    if visited != nodes.len() {
        return Err("evaluation plan graph contains a cycle".into());
    }
    Ok(())
}

fn validate_resource_limits(limits: &EvaluatorResourceLimits) -> Result<(), String> {
    if !(1..=300_000).contains(&limits.timeout_ms)
        || !(1..=16 * 1024 * 1024).contains(&limits.max_input_bytes)
        || !(1..=4 * 1024 * 1024).contains(&limits.max_output_bytes)
        || !(1..=1_024).contains(&limits.max_evidence_items)
    {
        return Err("evaluator resource limits are outside v1 bounds".into());
    }
    Ok(())
}

fn normalize_classifications(values: &mut [String]) -> Result<(), String> {
    normalize_tokens("evidence_classifications", values, false)?;
    if values.iter().any(|value| {
        !matches!(
            value.as_str(),
            "public" | "internal" | "confidential" | "restricted"
        )
    }) {
        return Err("unknown evidence classification".into());
    }
    Ok(())
}

fn normalize_tokens(name: &str, values: &mut [String], allow_empty: bool) -> Result<(), String> {
    for value in values.iter() {
        validate_token(name, value)?;
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(format!("{name} contains duplicates"));
    }
    if !allow_empty && values.is_empty() {
        return Err(format!("{name} required"));
    }
    Ok(())
}

fn validate_token(name: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || value.len() > MAX_STRING_BYTES
        || value.chars().any(char::is_whitespace)
    {
        return Err(format!(
            "{name} must be non-empty, canonical, bounded, and contain no whitespace"
        ));
    }
    Ok(())
}

fn validate_reference(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.trim() != value || value.len() > MAX_STRING_BYTES {
        return Err(format!("{name} must be non-empty, canonical, and bounded"));
    }
    Ok(())
}

pub(crate) fn validate_adapter_endpoint(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 2_048 || value.chars().any(char::is_whitespace) {
        return Err("adapter_endpoint must be bounded absolute URI text".into());
    }
    let uri: Uri = value
        .parse()
        .map_err(|_| "adapter_endpoint must be a valid absolute URI".to_string())?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "adapter_endpoint must include a URI scheme".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "adapter_endpoint must include a URI authority".to_string())?;
    if authority.as_str().contains('@') {
        return Err("adapter_endpoint must not contain userinfo".into());
    }
    if uri.path_and_query().and_then(|path| path.query()).is_some() {
        return Err("adapter_endpoint must not contain a query string".into());
    }
    if scheme != "https" && scheme != "http" {
        return Err("adapter_endpoint must use https or loopback http".into());
    }
    if scheme == "http" {
        let host = authority.host().trim_matches(['[', ']']);
        let loopback = host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if !loopback {
            return Err("non-TLS adapter endpoints must use a loopback host".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_runtime_adapter_endpoint(value: &str) -> Result<(), String> {
    validate_adapter_endpoint(value)?;
    let uri: Uri = value
        .parse()
        .map_err(|_| "adapter_endpoint must be a valid absolute URI".to_string())?;
    let insecure_development = std::env::var("SEKAI_INSECURE")
        .ok()
        .is_some_and(|value| value == "1");
    if uri.scheme_str() == Some("http") && !insecure_development {
        return Err("loopback HTTP adapter endpoints require SEKAI_INSECURE=1".into());
    }
    Ok(())
}

fn validate_digest(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must be a sha256 digest"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must be a sha256 digest"));
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), String> {
    validate_token("version", value)?;
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "latest" | "current" | "default" | "stable" | "head"
    ) {
        return Err("version must be exact; unversioned aliases are not supported".into());
    }
    Ok(())
}

fn canonical_contract(value: &str, expected: &str, name: &str) -> Result<String, String> {
    if value.is_empty() || value == expected {
        Ok(expected.into())
    } else {
        Err(format!("unsupported {name} contract version"))
    }
}

fn ensure_size(value: &impl Serialize, name: &str) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        Err(format!("{name} exceeds {MAX_DOCUMENT_BYTES} bytes"))
    } else {
        Ok(())
    }
}

fn resource_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update([0x1f]);
        hasher.update(part.as_bytes());
    }
    format!("{prefix}:{:x}", hasher.finalize())
}

fn digest_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = sekai_core::shomei::canonical_json(value)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition() -> EvaluatorDefinition {
        EvaluatorDefinition {
            declared_metrics: Vec::new(),
            contract_version: String::new(),
            definition_id: String::new(),
            namespace: "acme".into(),
            evaluator_id: "schema-check".into(),
            version: "1.0.0".into(),
            implementation_digest: format!("sha256:{}", "a".repeat(64)),
            execution_class: DETERMINISTIC_EXECUTION_CLASS.into(),
            supported_predicate_kinds: vec!["schema_conforms".into()],
            supported_input_schemas: vec!["schema://document/v1".into()],
            supported_result_schemas: vec!["schema://pass-fail/v1".into()],
            parameter_schema_json: r#"{"additionalProperties":false,"properties":{"strict":{"type":"boolean"}},"required":["strict"],"type":"object"}"#.into(),
            evidence_classifications: vec!["internal".into(), "public".into()],
            resource_limits: EvaluatorResourceLimits {
                timeout_ms: 1_000,
                max_input_bytes: 4_096,
                max_output_bytes: 1_024,
                max_evidence_items: 8,
            },
            adapter_endpoint: String::new(),
            stochastic_policy: None,
            source_ref: "repo://evaluators/schema-check@1".into(),
            content_digest: String::new(),
            created_by: String::new(),
            created_at_ms: 0,
        }
    }

    fn plan(definition_id: &str) -> EvaluationPlan {
        EvaluationPlan {
            contract_version: String::new(),
            plan_version_id: String::new(),
            namespace: "acme".into(),
            plan_id: "document-review".into(),
            version: "1.0.0".into(),
            accepted_subject_profiles: vec!["document/v1".into()],
            nodes: vec![EvaluationPlanNode {
                metric_objectives: Vec::new(),
                node_id: "schema".into(),
                evaluator_definition_id: definition_id.into(),
                depends_on_node_ids: vec![],
                input_bindings: vec![EvaluationInputBinding {
                    name: "document".into(),
                    source_kind: INPUT_INVARIANT.into(),
                    schema_id: "schema://document/v1".into(),
                }],
                parameters_json: r#"{"strict":true}"#.into(),
                invariant_version_ids: vec!["invariant:1".into()],
                classification: NODE_REQUIRED.into(),
            }],
            reducer: FIXED_REDUCER.into(),
            source_ref: "repo://plans/document-review@1".into(),
            content_digest: String::new(),
            created_by: String::new(),
            created_at_ms: 0,
        }
    }

    fn stochastic_policy() -> StochasticEvaluatorPolicy {
        StochasticEvaluatorPolicy {
            provider: "openai".into(),
            model: "openai/gpt-fixture".into(),
            prompt_profile: "chisei.fixture-rubric/v1".into(),
            prompt_profile_digest: format!("sha256:{}", "b".repeat(64)),
            result_schema: STOCHASTIC_RESULT_SCHEMA.into(),
            trial_count: 3,
            temperature_millis: 200,
            top_p_millionths: 900_000,
            seed_supported: true,
            base_seed: 41,
            aggregation_rule: STOCHASTIC_AGGREGATION_MEAN_VARIANCE.into(),
            minimum_mean_score_micros: 800_000,
            minimum_pass_rate_basis_points: 6_667,
            maximum_score_variance_micros_squared: 10_000_000_000,
            gate_eligible: false,
            max_retries_per_trial: 1,
            max_tokens_per_trial: 100,
            max_total_tokens: 600,
            egress_policy: STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL.into(),
            raw_response_retention: STOCHASTIC_RAW_RETENTION_NONE.into(),
        }
    }

    #[test]
    fn metric_declarations_travel_with_their_result_schema() {
        use crate::chisei::evaluation_metrics::MetricKind;
        let mut metrics = definition();
        metrics.declared_metrics = vec![MetricDeclaration {
            name: "accuracy".into(),
            kind: MetricKind::IntegerMicros,
        }];
        assert!(
            prepare_definition(metrics.clone(), "operator", 10)
                .unwrap_err()
                .contains("require each other")
        );
        let mut schema_only = definition();
        schema_only
            .supported_result_schemas
            .push(METRICS_RESULT_SCHEMA.into());
        assert!(prepare_definition(schema_only, "operator", 10).is_err());
        metrics
            .supported_result_schemas
            .push(METRICS_RESULT_SCHEMA.into());
        let prepared = prepare_definition(metrics, "operator", 10).unwrap();
        assert_ne!(
            prepared.content_digest,
            prepare_definition(definition(), "operator", 10)
                .unwrap()
                .content_digest
        );
    }

    /// Definitions and plans stored before ADR 0154 keep their digests: the
    /// metric fields are absent from canonical JSON when empty.
    #[test]
    fn single_status_digests_predate_metric_fields() {
        let definition = prepare_definition(definition(), "operator", 10).unwrap();
        let plan = prepare_plan(plan(&definition.definition_id), "operator", 10).unwrap();
        assert_eq!(
            (
                definition.content_digest.as_str(),
                plan.content_digest.as_str()
            ),
            (
                "sha256:56b65804c2a28464126259efa081345f20884875a14039706a4d167a697b16fe",
                "sha256:5eeb55b6c066129d093771d84955d288517dac3fefd0d49952c1e2fb3f0adc41"
            )
        );
    }

    #[test]
    fn canonical_definition_and_plan_are_stable() {
        let first = prepare_definition(definition(), "operator", 10).unwrap();
        let mut reordered = definition();
        reordered.evidence_classifications.reverse();
        let second = prepare_definition(reordered, "other", 20).unwrap();
        assert_eq!(first.definition_id, second.definition_id);
        assert_eq!(first.content_digest, second.content_digest);

        let first_plan = prepare_plan(plan(&first.definition_id), "operator", 10).unwrap();
        let second_plan = prepare_plan(plan(&first.definition_id), "other", 20).unwrap();
        assert_eq!(first_plan.plan_version_id, second_plan.plan_version_id);
        assert_eq!(first_plan.content_digest, second_plan.content_digest);
    }

    #[test]
    fn stochastic_definitions_require_an_exact_bounded_situation_policy() {
        let mut stochastic = definition();
        stochastic.execution_class = STOCHASTIC_EXECUTION_CLASS.into();
        stochastic.supported_result_schemas = vec![STOCHASTIC_RESULT_SCHEMA.into()];
        assert!(
            prepare_definition(stochastic.clone(), "operator", 10)
                .unwrap_err()
                .contains("policy is required")
        );

        stochastic.stochastic_policy = Some(stochastic_policy());
        let prepared = prepare_definition(stochastic.clone(), "operator", 10).unwrap();
        assert_eq!(prepared.stochastic_policy.as_ref().unwrap().trial_count, 3);

        stochastic.stochastic_policy.as_mut().unwrap().model = "anthropic/fixture".into();
        assert!(
            prepare_definition(stochastic.clone(), "operator", 10)
                .unwrap_err()
                .contains("does not match")
        );

        stochastic.stochastic_policy = Some(stochastic_policy());
        let policy = stochastic.stochastic_policy.as_mut().unwrap();
        policy.provider = "ollama".into();
        policy.model = "ollama/fixture".into();
        policy.egress_policy = STOCHASTIC_EGRESS_LOCAL_ONLY.into();
        assert!(
            prepare_definition(stochastic.clone(), "operator", 10)
                .unwrap_err()
                .contains("only through the OpenAI seed parameter")
        );

        stochastic.stochastic_policy = Some(stochastic_policy());
        stochastic
            .stochastic_policy
            .as_mut()
            .unwrap()
            .raw_response_retention = "plaintext/v1".into();
        assert!(
            prepare_definition(stochastic.clone(), "operator", 10)
                .unwrap_err()
                .contains("prompts and responses are never retained")
        );
        stochastic
            .stochastic_policy
            .as_mut()
            .unwrap()
            .raw_response_retention = STOCHASTIC_RETENTION_RATIONALE.into();
        prepare_definition(stochastic, "operator", 10).unwrap();

        let mut overflowing_seed = definition();
        overflowing_seed.execution_class = STOCHASTIC_EXECUTION_CLASS.into();
        overflowing_seed.supported_result_schemas = vec![STOCHASTIC_RESULT_SCHEMA.into()];
        overflowing_seed.stochastic_policy = Some(stochastic_policy());
        overflowing_seed
            .stochastic_policy
            .as_mut()
            .unwrap()
            .base_seed = i64::MAX;
        assert!(
            prepare_definition(overflowing_seed, "operator", 10)
                .unwrap_err()
                .contains("every fixed trial slot")
        );

        let mut oversized_budget = definition();
        oversized_budget.execution_class = STOCHASTIC_EXECUTION_CLASS.into();
        oversized_budget.supported_result_schemas = vec![STOCHASTIC_RESULT_SCHEMA.into()];
        oversized_budget.stochastic_policy = Some(stochastic_policy());
        oversized_budget
            .stochastic_policy
            .as_mut()
            .unwrap()
            .max_total_tokens = u32::MAX;
        assert!(
            prepare_definition(oversized_budget, "operator", 10)
                .unwrap_err()
                .contains("budget tracker range")
        );
    }

    #[test]
    fn external_adapter_definitions_require_a_secure_operator_endpoint() {
        let mut external = definition();
        external.execution_class = EXTERNAL_ADAPTER_EXECUTION_CLASS.into();
        assert!(
            prepare_definition(external.clone(), "operator", 10)
                .unwrap_err()
                .contains("adapter_endpoint")
        );

        external.adapter_endpoint = "http://adapter.example/evaluate".into();
        assert!(
            prepare_definition(external.clone(), "operator", 10)
                .unwrap_err()
                .contains("loopback")
        );

        external.adapter_endpoint = "https://adapter.example/evaluate?token=secret".into();
        assert!(
            prepare_definition(external.clone(), "operator", 10)
                .unwrap_err()
                .contains("query")
        );

        external.adapter_endpoint = "https://adapter.example/evaluate".into();
        let prepared = prepare_definition(external, "operator", 10).unwrap();
        assert_eq!(prepared.execution_class, EXTERNAL_ADAPTER_EXECUTION_CLASS);
        assert_eq!(
            prepared.adapter_endpoint,
            "https://adapter.example/evaluate"
        );
    }

    #[test]
    fn loopback_http_requires_explicit_insecure_runtime_opt_in() {
        let result = validate_runtime_adapter_endpoint("http://127.0.0.1:43123/evaluate");
        if std::env::var("SEKAI_INSECURE").ok().as_deref() == Some("1") {
            assert!(result.is_ok());
        } else {
            assert!(result.unwrap_err().contains("SEKAI_INSECURE=1"));
        }
    }

    #[test]
    fn existing_definition_digests_ignore_the_empty_adapter_endpoint() {
        let first = prepare_definition(definition(), "operator", 10).unwrap();
        let mut second = definition();
        second.adapter_endpoint = String::new();
        let second = prepare_definition(second, "operator", 20).unwrap();
        assert_eq!(first.content_digest, second.content_digest);
    }

    #[test]
    fn parameters_are_validated_by_the_definition_schema() {
        let definition = prepare_definition(definition(), "operator", 10).unwrap();
        validate_parameters(&definition.parameter_schema_json, r#"{"strict":true}"#).unwrap();
        assert!(
            validate_parameters(&definition.parameter_schema_json, r#"{"strict":"yes"}"#).is_err()
        );
        assert!(
            validate_parameters(
                &definition.parameter_schema_json,
                r#"{"strict":true,"script":"rm"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn plan_rejects_cycles_and_unknown_reducers() {
        let definition = prepare_definition(definition(), "operator", 10).unwrap();
        let mut cyclic = plan(&definition.definition_id);
        let mut second = cyclic.nodes[0].clone();
        second.node_id = "evidence".into();
        second.depends_on_node_ids = vec!["schema".into()];
        cyclic.nodes[0].depends_on_node_ids = vec!["evidence".into()];
        cyclic.nodes.push(second);
        assert!(prepare_plan(cyclic, "operator", 10).is_err());

        let mut unknown = plan(&definition.definition_id);
        unknown.reducer = "custom-expression".into();
        assert!(prepare_plan(unknown, "operator", 10).is_err());

        let mut aliased = plan(&definition.definition_id);
        aliased.version = "latest".into();
        assert!(prepare_plan(aliased, "operator", 10).is_err());

        let mut advisory_only = plan(&definition.definition_id);
        advisory_only.nodes[0].classification = NODE_ADVISORY.into();
        assert!(prepare_plan(advisory_only, "operator", 10).is_err());
    }

    #[test]
    fn integer_parameter_bounds_are_exact_above_f64_precision() {
        let schema = r#"{"type":"object","properties":{"threshold":{"type":"integer","minimum":9007199254740993}},"required":["threshold"],"additionalProperties":false}"#;
        validate_parameters(schema, r#"{"threshold":9007199254740993}"#).unwrap();
        assert!(
            validate_parameters(schema, r#"{"threshold":9007199254740992}"#)
                .unwrap_err()
                .contains("outside")
        );
    }

    #[test]
    fn number_parameters_reject_float_encoded_large_integers() {
        let schema = r#"{"type":"object","properties":{"ratio":{"type":"number"}},"required":["ratio"],"additionalProperties":false}"#;
        assert!(
            validate_parameters(schema, r#"{"ratio":1e20}"#)
                .unwrap_err()
                .contains("exact v1 numeric range")
        );
        assert!(
            validate_parameters(schema, r#"{"ratio":-1e20}"#)
                .unwrap_err()
                .contains("exact v1 numeric range")
        );
    }

    #[test]
    fn duplicate_parameter_schema_keys_fail_closed() {
        let schema = r#"{"type":"object","properties":{"role":{"type":"string"}},"properties":{"role":{"type":"string","enum":["admin"]}},"required":["role"],"additionalProperties":false}"#;
        assert!(
            validate_parameter_schema(schema)
                .unwrap_err()
                .contains("duplicate object keys")
        );
    }

    #[test]
    fn number_enum_accepts_integer_and_float_encodings() {
        let schema = r#"{"type":"object","properties":{"value":{"type":"number","enum":[1]}},"required":["value"],"additionalProperties":false}"#;
        validate_parameters(schema, r#"{"value":1.0}"#).unwrap();
    }

    #[test]
    fn one_contract_represents_distinct_domain_evaluations() {
        let document_definition = prepare_definition(definition(), "operator", 10).unwrap();
        let document_plan =
            prepare_plan(plan(&document_definition.definition_id), "operator", 10).unwrap();

        let mut release_definition = definition();
        release_definition.evaluator_id = "artifact-signature-check".into();
        release_definition.supported_predicate_kinds = vec!["signature_verified".into()];
        release_definition.supported_input_schemas = vec!["schema://release-artifact/v3".into()];
        release_definition.supported_result_schemas = vec!["schema://trust-result/v2".into()];
        release_definition.parameter_schema_json = r#"{"type":"object","properties":{"minimum_signatures":{"type":"integer","minimum":1,"maximum":8}},"required":["minimum_signatures"],"additionalProperties":false}"#.into();
        let release_definition = prepare_definition(release_definition, "operator", 10).unwrap();
        let mut release_plan = plan(&release_definition.definition_id);
        release_plan.plan_id = "release-trust".into();
        release_plan.accepted_subject_profiles = vec!["software-release/v3".into()];
        release_plan.nodes[0].input_bindings[0].schema_id = "schema://release-artifact/v3".into();
        release_plan.nodes[0].parameters_json = r#"{"minimum_signatures":2}"#.into();
        release_plan.nodes[0].invariant_version_ids = vec!["release-signature-invariant:3".into()];
        let release_plan = prepare_plan(release_plan, "operator", 10).unwrap();

        assert_eq!(
            document_plan.contract_version,
            release_plan.contract_version
        );
        assert_ne!(
            document_plan.accepted_subject_profiles,
            release_plan.accepted_subject_profiles
        );
        assert_ne!(
            document_definition.supported_predicate_kinds,
            release_definition.supported_predicate_kinds
        );
    }
}
