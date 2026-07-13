//! Explainable fleet-allocation decisions for governed operations.
//!
//! Gunshi owns allocation recommendations, not agent runtimes or workflow
//! execution. Callers remain responsible for dispatching an accepted plan.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::db::sekai::SekaiDb;
use crate::domain::{KIND_LEARNING, ListFilter};

pub const ALLOCATION_CONTRACT_VERSION: &str = "gunshi.allocation/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRisk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapacity {
    pub agent_id: String,
    pub runtime: String,
    pub models: BTreeSet<String>,
    pub tools: BTreeSet<String>,
    pub operation_classes: BTreeSet<String>,
    pub available_slots: u32,
    pub healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelProfile {
    pub model: String,
    pub quality: f64,
    pub cost_per_attempt_usd_micros: i64,
    pub latency_ms: i64,
    pub uncertainty: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapacityEnvelope {
    pub captured_at_ms: i64,
    pub policy_version: String,
    pub agents: Vec<AgentCapacity>,
    #[serde(default)]
    pub model_profiles: Vec<ModelProfile>,
    pub budget_remaining_usd_micros: i64,
    pub max_parallel_attempts: u32,
    pub human_attention_minutes: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllocationRequest {
    pub capacity: CapacityEnvelope,
    pub operations: Vec<PendingOperation>,
    pub strategy: Strategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnallocatedOperation {
    pub operation_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineAllocation {
    pub plans: Vec<AllocationPlan>,
    pub unallocated: Vec<UnallocatedOperation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KiokuEvidence {
    pub memory_id: String,
    pub namespace: String,
    pub operation_class: String,
    pub model: String,
    pub score: f64,
    pub passed: bool,
    pub status: String,
    pub observed_at_ms: i64,
    pub receipt_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryPolicy {
    pub max_memory_age_ms: i64,
    pub min_score: f64,
    pub max_evidence_references: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorResponse {
    Accepted,
    Modified,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorChoice {
    pub operation_id: String,
    pub allocation_id: String,
    pub response: OperatorResponse,
    pub selected_resources: Option<ResourceSelection>,
    pub max_attempts: Option<u32>,
    pub budget_ceiling_usd_micros: Option<i64>,
    pub rationale: String,
    pub decided_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedOutcome {
    pub operation_id: String,
    pub receipt_reference: String,
    pub accepted: bool,
    pub quality: f64,
    pub cost_usd_micros: i64,
    pub latency_ms: i64,
    pub attempts: u32,
    pub completed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryComparison {
    pub allocation_id: String,
    pub operation_id: String,
    pub operator_response: OperatorResponse,
    pub resource_selection_matched: bool,
    pub attempt_limit_delta: i64,
    pub budget_ceiling_delta_usd_micros: i64,
    pub outcome_receipt_reference: Option<String>,
    pub outcome_accepted: Option<bool>,
    pub quality_error: Option<f64>,
    pub cost_error_usd_micros: Option<i64>,
    pub latency_error_ms: Option<i64>,
    pub recommendation_evidence: Vec<EvidenceReference>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryScorecard {
    pub comparisons: usize,
    pub accepted: usize,
    pub modified: usize,
    pub rejected: usize,
    pub resource_selection_agreement_rate: f64,
    pub observed_outcomes: usize,
    pub mean_absolute_quality_error: Option<f64>,
    pub mean_absolute_cost_error_usd_micros: Option<f64>,
    pub mean_absolute_latency_error_ms: Option<f64>,
}

impl AdvisoryPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_memory_age_ms < 0 {
            return Err("maximum memory age must be non-negative".into());
        }
        if !self.min_score.is_finite() || !(0.0..=1.0).contains(&self.min_score) {
            return Err("minimum evidence score must be between 0 and 1".into());
        }
        if self.max_evidence_references == 0 {
            return Err("at least one evidence reference must be allowed".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOperation {
    pub operation_id: String,
    pub namespace: String,
    pub operation_class: String,
    pub priority: u16,
    pub risk: OperationRisk,
    pub submitted_at_ms: i64,
    pub required_tools: BTreeSet<String>,
    pub allowed_models: BTreeSet<String>,
    pub max_attempts: u32,
    pub budget_ceiling_usd_micros: i64,
    pub acceptance_criteria: Vec<String>,
    pub approval_required: bool,
    #[serde(default)]
    pub human_attention_minutes_required: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStrategy {
    Conservative,
    PriorityFirst,
    Throughput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Strategy {
    pub strategy_id: String,
    pub version: String,
    pub baseline: BaselineStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSelection {
    pub agent_id: String,
    pub runtime: String,
    pub model: String,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptStrategy {
    pub max_attempts: u32,
    pub parallel_attempts: u32,
    pub speculative: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStrategy {
    pub checks: Vec<String>,
    pub acceptance_criteria: Vec<String>,
    pub human_review_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopConditions {
    pub max_cost_usd_micros: i64,
    pub max_attempts: u32,
    pub deadline_ms: Option<i64>,
    pub stop_on_acceptance: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationRules {
    pub approval_required: bool,
    pub escalate_on_budget_exhaustion: bool,
    pub escalate_after_failed_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub kind: String,
    pub reference: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpectedOutcome {
    pub quality: f64,
    pub cost_usd_micros: i64,
    pub latency_ms: i64,
    pub uncertainty: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllocationPlan {
    pub contract_version: String,
    pub allocation_id: String,
    pub operation_id: String,
    pub namespace: String,
    pub operation_class: String,
    pub priority: u16,
    pub strategy: Strategy,
    pub policy_version: String,
    pub advisory: bool,
    pub selection: ResourceSelection,
    pub attempts: AttemptStrategy,
    pub verification: VerificationStrategy,
    pub budget_ceiling_usd_micros: i64,
    pub stop_conditions: StopConditions,
    pub escalation: EscalationRules,
    pub evidence: Vec<EvidenceReference>,
    pub expected: ExpectedOutcome,
    pub explanation: Vec<String>,
    pub input_fingerprint: String,
}

impl CapacityEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        required("policy_version", &self.policy_version)?;
        if self.budget_remaining_usd_micros < 0 {
            return Err("capacity budget must be non-negative".into());
        }
        if self.max_parallel_attempts == 0 {
            return Err("capacity must allow at least one parallel attempt".into());
        }
        let mut ids = BTreeSet::new();
        for agent in &self.agents {
            required("agent_id", &agent.agent_id)?;
            required("runtime", &agent.runtime)?;
            if !ids.insert(agent.agent_id.as_str()) {
                return Err(format!("duplicate agent capacity {}", agent.agent_id));
            }
            if agent.models.iter().any(|model| model.trim().is_empty()) {
                return Err(format!("agent {} has an empty model", agent.agent_id));
            }
        }
        let mut models = BTreeSet::new();
        for profile in &self.model_profiles {
            required("model profile model", &profile.model)?;
            if !models.insert(profile.model.as_str()) {
                return Err(format!("duplicate model profile {}", profile.model));
            }
            for (name, value) in [
                ("quality", profile.quality),
                ("uncertainty", profile.uncertainty),
            ] {
                if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                    return Err(format!(
                        "model {} {name} must be between 0 and 1",
                        profile.model
                    ));
                }
            }
            if profile.cost_per_attempt_usd_micros < 0 || profile.latency_ms < 0 {
                return Err(format!(
                    "model {} cost and latency must be non-negative",
                    profile.model
                ));
            }
        }
        Ok(())
    }
}

/// Produce an advisory allocation with no learned optimization. The result is
/// deterministic for the serialized request, including ordering and ids.
pub fn recommend_baseline(request: &AllocationRequest) -> Result<BaselineAllocation, String> {
    request.capacity.validate()?;
    request.strategy.validate()?;
    if request.operations.is_empty() {
        return Err("at least one pending operation is required".into());
    }
    let mut operation_ids = BTreeSet::new();
    for operation in &request.operations {
        operation.validate()?;
        if !operation_ids.insert(operation.operation_id.as_str()) {
            return Err(format!(
                "duplicate pending operation {}",
                operation.operation_id
            ));
        }
    }

    let known_classes = request
        .capacity
        .agents
        .iter()
        .flat_map(|agent| agent.operation_classes.iter())
        .filter(|class| class.as_str() != "*")
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut operations = request
        .operations
        .iter()
        .map(|operation| {
            let is_fallback = !known_classes.contains(&operation.operation_class);
            let baseline = if is_fallback {
                BaselineStrategy::Conservative
            } else {
                request.strategy.baseline
            };
            (operation, baseline, is_fallback)
        })
        .collect::<Vec<_>>();
    operations.sort_by(|left, right| {
        left.2
            .cmp(&right.2)
            .then_with(|| operation_order(left.0, right.0, left.1))
    });

    let mut slots = request
        .capacity
        .agents
        .iter()
        .map(|agent| (agent.agent_id.as_str(), agent.available_slots))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut remaining_budget = request.capacity.budget_remaining_usd_micros;
    let mut remaining_human_attention = request.capacity.human_attention_minutes;
    let mut plans = Vec::new();
    let mut unallocated = Vec::new();

    for (operation, effective_baseline, is_fallback) in operations {
        if plans.len() >= request.capacity.max_parallel_attempts as usize {
            unallocated.push(UnallocatedOperation {
                operation_id: operation.operation_id.clone(),
                reason: "fleet parallel-attempt capacity exhausted".into(),
            });
            continue;
        }
        let human_review = operation.approval_required
            || operation.risk >= OperationRisk::Medium
            || operation.human_attention_minutes_required > 0;
        let attention_required = if human_review {
            operation.human_attention_minutes_required.max(1)
        } else {
            0
        };
        if attention_required > remaining_human_attention {
            unallocated.push(UnallocatedOperation {
                operation_id: operation.operation_id.clone(),
                reason: "human-attention capacity exhausted".into(),
            });
            continue;
        }
        let mut choices = eligible_choices(operation, &request.capacity, &slots);
        choices.sort_by(|left, right| choice_order(left, right, effective_baseline));
        let Some((agent, profile)) = choices.into_iter().find(|(_, profile)| {
            profile.cost_per_attempt_usd_micros <= operation.budget_ceiling_usd_micros
                && profile.cost_per_attempt_usd_micros <= remaining_budget
        }) else {
            unallocated.push(UnallocatedOperation {
                operation_id: operation.operation_id.clone(),
                reason: "no healthy eligible capacity within policy and budget limits".into(),
            });
            continue;
        };

        let effective_strategy = Strategy {
            baseline: effective_baseline,
            ..request.strategy.clone()
        };
        let max_attempts = affordable_attempts(operation, profile, remaining_budget);
        let budget_ceiling = profile
            .cost_per_attempt_usd_micros
            .checked_mul(i64::from(max_attempts))
            .ok_or_else(|| format!("attempt budget overflow for {}", operation.operation_id))?;
        let fingerprint = input_fingerprint(&AllocationFingerprint {
            request,
            operation,
            strategy: &effective_strategy,
            agent,
            profile,
            remaining_budget,
            remaining_human_attention,
            max_attempts,
            budget_ceiling,
        })?;
        let fallback_note = is_fallback.then(|| {
            format!(
                "unknown operation class {} uses the conservative baseline",
                operation.operation_class
            )
        });
        let mut explanation = vec![
            format!(
                "selected healthy agent {} with an available slot",
                agent.agent_id
            ),
            format!(
                "selected model {} within the operation and fleet budget ceilings",
                profile.model
            ),
        ];
        if let Some(note) = fallback_note {
            explanation.push(note);
        }
        let plan = AllocationPlan {
            contract_version: ALLOCATION_CONTRACT_VERSION.into(),
            allocation_id: format!("alloc-{}", &fingerprint[..16]),
            operation_id: operation.operation_id.clone(),
            namespace: operation.namespace.clone(),
            operation_class: operation.operation_class.clone(),
            priority: operation.priority,
            strategy: effective_strategy,
            policy_version: request.capacity.policy_version.clone(),
            advisory: true,
            selection: ResourceSelection {
                agent_id: agent.agent_id.clone(),
                runtime: agent.runtime.clone(),
                model: profile.model.clone(),
                tools: operation.required_tools.iter().cloned().collect(),
            },
            attempts: AttemptStrategy {
                max_attempts,
                parallel_attempts: 1,
                speculative: false,
            },
            verification: VerificationStrategy {
                checks: vec!["operation_receipt_complete".into()],
                acceptance_criteria: operation.acceptance_criteria.clone(),
                human_review_required: human_review,
            },
            budget_ceiling_usd_micros: budget_ceiling,
            stop_conditions: StopConditions {
                max_cost_usd_micros: budget_ceiling,
                max_attempts,
                deadline_ms: None,
                stop_on_acceptance: true,
            },
            escalation: EscalationRules {
                approval_required: operation.approval_required,
                escalate_on_budget_exhaustion: true,
                escalate_after_failed_attempts: max_attempts,
            },
            evidence: Vec::new(),
            expected: ExpectedOutcome {
                quality: profile.quality,
                cost_usd_micros: profile.cost_per_attempt_usd_micros,
                latency_ms: profile.latency_ms,
                uncertainty: profile.uncertainty,
            },
            explanation,
            input_fingerprint: fingerprint,
        };
        plan.validate()?;
        *slots
            .get_mut(agent.agent_id.as_str())
            .expect("eligible agent has a slot entry") -= 1;
        remaining_budget -= budget_ceiling;
        remaining_human_attention -= attention_required;
        plans.push(plan);
    }

    Ok(BaselineAllocation { plans, unallocated })
}

/// Refine baseline plans using current, governed Kioku evidence. Evidence may
/// change the selected model, but never expands the resources or budget already
/// admitted by the baseline allocator.
pub fn recommend_advisory(
    request: &AllocationRequest,
    evidence: &[KiokuEvidence],
    policy: &AdvisoryPolicy,
) -> Result<BaselineAllocation, String> {
    policy.validate()?;
    for memory in evidence {
        validate_kioku_evidence(memory)?;
    }
    let mut allocation = recommend_baseline(request)?;
    for plan in &mut allocation.plans {
        let operation = request
            .operations
            .iter()
            .find(|operation| operation.operation_id == plan.operation_id)
            .expect("baseline plan belongs to a validated request operation");
        let agent = request
            .capacity
            .agents
            .iter()
            .find(|agent| agent.agent_id == plan.selection.agent_id)
            .expect("baseline plan selects a validated request agent");
        let current = current_evidence(
            evidence,
            &plan.namespace,
            &plan.operation_class,
            request.capacity.captured_at_ms,
            policy,
        );
        let mut by_model = BTreeMap::<&str, Vec<&KiokuEvidence>>::new();
        for memory in current {
            by_model.entry(&memory.model).or_default().push(memory);
        }
        let mut candidates = request
            .capacity
            .model_profiles
            .iter()
            .filter(|profile| {
                agent.models.contains(&profile.model)
                    && (operation.allowed_models.is_empty()
                        || operation.allowed_models.contains(&profile.model))
                    && profile
                        .cost_per_attempt_usd_micros
                        .checked_mul(i64::from(plan.attempts.max_attempts))
                        .is_some_and(|cost| cost <= plan.budget_ceiling_usd_micros)
                    && by_model.contains_key(profile.model.as_str())
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            evidence_score(&by_model[right.model.as_str()])
                .total_cmp(&evidence_score(&by_model[left.model.as_str()]))
                .then_with(|| left.model.cmp(&right.model))
        });
        let Some(selected) = candidates.first() else {
            plan.explanation
                .push("no current trusted Kioku evidence changed the baseline".into());
            continue;
        };
        let selected_evidence = &by_model[selected.model.as_str()];
        let observed_quality = evidence_score(selected_evidence);
        plan.selection.model = selected.model.clone();
        plan.expected.quality = observed_quality;
        plan.expected.cost_usd_micros = selected.cost_per_attempt_usd_micros;
        plan.expected.latency_ms = selected.latency_ms;
        plan.expected.uncertainty = selected
            .uncertainty
            .min(1.0 / (selected_evidence.len() as f64 + 1.0));
        plan.evidence = evidence_references(selected_evidence, policy.max_evidence_references);
        plan.explanation.push(format!(
            "selected model {} from {} current Kioku observations",
            selected.model,
            selected_evidence.len()
        ));
        refresh_advisory_identity(plan)?;
        plan.validate()?;
    }
    Ok(allocation)
}

/// Load governed learning objects without bypassing their namespace/status
/// metadata. Invalid legacy rows are ignored rather than trusted implicitly.
pub fn load_kioku_evidence(
    db: &SekaiDb,
    namespace: &str,
    operation_class: &str,
) -> Result<Vec<KiokuEvidence>, String> {
    let objects = db.list_all_objects(&ListFilter {
        kind: Some(KIND_LEARNING.into()),
        namespace: Some(namespace.trim().to_string()),
        ..Default::default()
    })?;
    let mut evidence = objects
        .into_iter()
        .filter_map(|object| {
            let memory = KiokuEvidence {
                memory_id: object.id,
                namespace: object.namespace,
                operation_class: object.properties.get("task_class")?.clone(),
                model: object.properties.get("model")?.clone(),
                score: object.properties.get("score")?.parse::<f64>().ok()? / 100.0,
                passed: object.properties.get("passed")?.parse().ok()?,
                status: object.properties.get("status")?.clone(),
                observed_at_ms: object.updated.saturating_mul(1_000),
                receipt_reference: object.properties.get("source_request_id").cloned(),
            };
            (memory.operation_class == operation_class && validate_kioku_evidence(&memory).is_ok())
                .then_some(memory)
        })
        .collect::<Vec<_>>();
    evidence.sort_by(|left, right| {
        right
            .observed_at_ms
            .cmp(&left.observed_at_ms)
            .then_with(|| left.memory_id.cmp(&right.memory_id))
    });
    Ok(evidence)
}

pub fn compare_advisory(
    plan: &AllocationPlan,
    choice: &OperatorChoice,
    outcome: Option<&ObservedOutcome>,
) -> Result<AdvisoryComparison, String> {
    plan.validate()?;
    validate_operator_choice(plan, choice)?;
    if let Some(outcome) = outcome {
        validate_observed_outcome(plan, outcome)?;
    }
    let selected = match choice.response {
        OperatorResponse::Accepted => Some(&plan.selection),
        OperatorResponse::Modified => choice.selected_resources.as_ref().or(Some(&plan.selection)),
        OperatorResponse::Rejected => None,
    };
    let selected_attempts = choice.max_attempts.unwrap_or(plan.attempts.max_attempts);
    let selected_budget = choice
        .budget_ceiling_usd_micros
        .unwrap_or(plan.budget_ceiling_usd_micros);
    Ok(AdvisoryComparison {
        allocation_id: plan.allocation_id.clone(),
        operation_id: plan.operation_id.clone(),
        operator_response: choice.response,
        resource_selection_matched: selected
            .is_some_and(|value| resource_selections_match(value, &plan.selection)),
        attempt_limit_delta: i64::from(selected_attempts) - i64::from(plan.attempts.max_attempts),
        budget_ceiling_delta_usd_micros: selected_budget - plan.budget_ceiling_usd_micros,
        outcome_receipt_reference: outcome.map(|value| value.receipt_reference.clone()),
        outcome_accepted: outcome.map(|value| value.accepted),
        quality_error: outcome.map(|value| value.quality - plan.expected.quality),
        cost_error_usd_micros: outcome
            .map(|value| value.cost_usd_micros - plan.expected.cost_usd_micros),
        latency_error_ms: outcome.map(|value| value.latency_ms - plan.expected.latency_ms),
        recommendation_evidence: plan.evidence.clone(),
    })
}

fn resource_selections_match(left: &ResourceSelection, right: &ResourceSelection) -> bool {
    left.agent_id == right.agent_id
        && left.runtime == right.runtime
        && left.model == right.model
        && left.tools.iter().collect::<BTreeSet<_>>() == right.tools.iter().collect::<BTreeSet<_>>()
}

pub fn score_advisory_comparisons(comparisons: &[AdvisoryComparison]) -> AdvisoryScorecard {
    let accepted = comparisons
        .iter()
        .filter(|value| value.operator_response == OperatorResponse::Accepted)
        .count();
    let modified = comparisons
        .iter()
        .filter(|value| value.operator_response == OperatorResponse::Modified)
        .count();
    let rejected = comparisons
        .iter()
        .filter(|value| value.operator_response == OperatorResponse::Rejected)
        .count();
    let observed = comparisons
        .iter()
        .filter(|value| value.outcome_receipt_reference.is_some())
        .collect::<Vec<_>>();
    AdvisoryScorecard {
        comparisons: comparisons.len(),
        accepted,
        modified,
        rejected,
        resource_selection_agreement_rate: ratio(
            comparisons
                .iter()
                .filter(|value| value.resource_selection_matched)
                .count(),
            comparisons.len(),
        ),
        observed_outcomes: observed.len(),
        mean_absolute_quality_error: mean_absolute(
            observed.iter().filter_map(|value| value.quality_error),
        ),
        mean_absolute_cost_error_usd_micros: mean_absolute(
            observed
                .iter()
                .filter_map(|value| value.cost_error_usd_micros.map(|error| error as f64)),
        ),
        mean_absolute_latency_error_ms: mean_absolute(
            observed
                .iter()
                .filter_map(|value| value.latency_error_ms.map(|error| error as f64)),
        ),
    }
}

fn validate_operator_choice(plan: &AllocationPlan, choice: &OperatorChoice) -> Result<(), String> {
    if choice.operation_id != plan.operation_id || choice.allocation_id != plan.allocation_id {
        return Err("operator choice does not reference the allocation plan".into());
    }
    required("operator rationale", &choice.rationale)?;
    match choice.response {
        OperatorResponse::Accepted
            if choice.selected_resources.is_some()
                || choice.max_attempts.is_some()
                || choice.budget_ceiling_usd_micros.is_some() =>
        {
            return Err("accepted choices cannot carry allocation overrides".into());
        }
        OperatorResponse::Modified
            if choice.selected_resources.is_none()
                && choice.max_attempts.is_none()
                && choice.budget_ceiling_usd_micros.is_none() =>
        {
            return Err("modified choices require at least one allocation override".into());
        }
        OperatorResponse::Rejected
            if choice.selected_resources.is_some()
                || choice.max_attempts.is_some()
                || choice.budget_ceiling_usd_micros.is_some() =>
        {
            return Err("rejected choices cannot carry allocation overrides".into());
        }
        _ => {}
    }
    if choice.max_attempts == Some(0) {
        return Err("operator max attempts must be positive".into());
    }
    if choice
        .budget_ceiling_usd_micros
        .is_some_and(|value| value < 0)
    {
        return Err("operator budget ceiling must be non-negative".into());
    }
    Ok(())
}

fn validate_observed_outcome(
    plan: &AllocationPlan,
    outcome: &ObservedOutcome,
) -> Result<(), String> {
    if outcome.operation_id != plan.operation_id {
        return Err("observed outcome does not belong to the allocation operation".into());
    }
    required("outcome receipt reference", &outcome.receipt_reference)?;
    if !outcome.quality.is_finite() || !(0.0..=1.0).contains(&outcome.quality) {
        return Err("observed outcome quality must be between 0 and 1".into());
    }
    if outcome.cost_usd_micros < 0 || outcome.latency_ms < 0 || outcome.attempts == 0 {
        return Err("observed outcome cost, latency, and attempts must be valid".into());
    }
    Ok(())
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn mean_absolute(values: impl Iterator<Item = f64>) -> Option<f64> {
    let values = values.collect::<Vec<_>>();
    (!values.is_empty())
        .then(|| values.iter().map(|value| value.abs()).sum::<f64>() / values.len() as f64)
}

fn validate_kioku_evidence(memory: &KiokuEvidence) -> Result<(), String> {
    for (name, value) in [
        ("memory_id", memory.memory_id.as_str()),
        ("namespace", memory.namespace.as_str()),
        ("operation_class", memory.operation_class.as_str()),
        ("model", memory.model.as_str()),
        ("status", memory.status.as_str()),
    ] {
        required(name, value)?;
    }
    if !memory.score.is_finite() || !(0.0..=1.0).contains(&memory.score) {
        return Err(format!(
            "Kioku memory {} score must be between 0 and 1",
            memory.memory_id
        ));
    }
    Ok(())
}

fn current_evidence<'a>(
    evidence: &'a [KiokuEvidence],
    namespace: &str,
    operation_class: &str,
    now_ms: i64,
    policy: &AdvisoryPolicy,
) -> Vec<&'a KiokuEvidence> {
    evidence
        .iter()
        .filter(|memory| {
            memory.namespace == namespace
                && memory.operation_class == operation_class
                && memory.status == "active"
                && memory.passed
                && memory.score >= policy.min_score
                && memory.observed_at_ms <= now_ms
                && now_ms.saturating_sub(memory.observed_at_ms) <= policy.max_memory_age_ms
        })
        .collect()
}

fn evidence_score(evidence: &[&KiokuEvidence]) -> f64 {
    evidence.iter().map(|memory| memory.score).sum::<f64>() / evidence.len() as f64
}

fn evidence_references(
    evidence: &[&KiokuEvidence],
    max_references: usize,
) -> Vec<EvidenceReference> {
    let mut ordered = evidence.to_vec();
    ordered.sort_by(|left, right| {
        right
            .observed_at_ms
            .cmp(&left.observed_at_ms)
            .then_with(|| left.memory_id.cmp(&right.memory_id))
    });
    let mut references = Vec::new();
    for memory in ordered.into_iter().take(max_references) {
        if references.len() == max_references {
            break;
        }
        references.push(EvidenceReference {
            kind: "kioku_memory".into(),
            reference: memory.memory_id.clone(),
            reason: format!(
                "observed model {} quality {:.3}",
                memory.model, memory.score
            ),
        });
        if let Some(receipt) = memory
            .receipt_reference
            .as_deref()
            .filter(|reference| !reference.trim().is_empty())
            && references.len() < max_references
        {
            references.push(EvidenceReference {
                kind: "operation_receipt".into(),
                reference: receipt.to_string(),
                reason: format!("source receipt for memory {}", memory.memory_id),
            });
        }
    }
    references
}

fn refresh_advisory_identity(plan: &mut AllocationPlan) -> Result<(), String> {
    let bytes = serde_json::to_vec(&(
        plan.input_fingerprint.as_str(),
        &plan.selection,
        &plan.expected,
        &plan.evidence,
    ))
    .map_err(|error| format!("serialize advisory inputs: {error}"))?;
    let fingerprint = format!("{:x}", Sha256::digest(bytes));
    plan.allocation_id = format!("alloc-{}", &fingerprint[..16]);
    plan.input_fingerprint = fingerprint;
    Ok(())
}

fn affordable_attempts(
    operation: &PendingOperation,
    profile: &ModelProfile,
    remaining_budget: i64,
) -> u32 {
    if profile.cost_per_attempt_usd_micros == 0 {
        return operation.max_attempts;
    }
    let affordable = operation.budget_ceiling_usd_micros.min(remaining_budget)
        / profile.cost_per_attempt_usd_micros;
    i64::from(operation.max_attempts).min(affordable) as u32
}

fn operation_order(
    left: &PendingOperation,
    right: &PendingOperation,
    strategy: BaselineStrategy,
) -> Ordering {
    match strategy {
        BaselineStrategy::Conservative => left
            .risk
            .cmp(&right.risk)
            .then_with(|| right.priority.cmp(&left.priority)),
        BaselineStrategy::PriorityFirst => right.priority.cmp(&left.priority),
        BaselineStrategy::Throughput => left.submitted_at_ms.cmp(&right.submitted_at_ms),
    }
    .then_with(|| left.submitted_at_ms.cmp(&right.submitted_at_ms))
    .then_with(|| left.operation_id.cmp(&right.operation_id))
}

fn eligible_choices<'a>(
    operation: &PendingOperation,
    capacity: &'a CapacityEnvelope,
    slots: &std::collections::BTreeMap<&str, u32>,
) -> Vec<(&'a AgentCapacity, &'a ModelProfile)> {
    capacity
        .agents
        .iter()
        .filter(|agent| {
            agent.healthy
                && slots.get(agent.agent_id.as_str()).copied().unwrap_or(0) > 0
                && (agent.operation_classes.contains(&operation.operation_class)
                    || agent.operation_classes.contains("*"))
                && operation.required_tools.is_subset(&agent.tools)
        })
        .flat_map(|agent| {
            capacity.model_profiles.iter().filter_map(move |profile| {
                (agent.models.contains(&profile.model)
                    && (operation.allowed_models.is_empty()
                        || operation.allowed_models.contains(&profile.model)))
                .then_some((agent, profile))
            })
        })
        .collect()
}

fn choice_order(
    left: &(&AgentCapacity, &ModelProfile),
    right: &(&AgentCapacity, &ModelProfile),
    strategy: BaselineStrategy,
) -> Ordering {
    let profile_order = match strategy {
        BaselineStrategy::Conservative | BaselineStrategy::PriorityFirst => {
            right.1.quality.total_cmp(&left.1.quality).then_with(|| {
                left.1
                    .cost_per_attempt_usd_micros
                    .cmp(&right.1.cost_per_attempt_usd_micros)
            })
        }
        BaselineStrategy::Throughput => left
            .1
            .latency_ms
            .cmp(&right.1.latency_ms)
            .then_with(|| right.1.quality.total_cmp(&left.1.quality)),
    };
    profile_order
        .then_with(|| left.0.agent_id.cmp(&right.0.agent_id))
        .then_with(|| left.1.model.cmp(&right.1.model))
}

#[derive(Serialize)]
struct AllocationFingerprint<'a> {
    request: &'a AllocationRequest,
    operation: &'a PendingOperation,
    strategy: &'a Strategy,
    agent: &'a AgentCapacity,
    profile: &'a ModelProfile,
    remaining_budget: i64,
    remaining_human_attention: u32,
    max_attempts: u32,
    budget_ceiling: i64,
}

fn input_fingerprint(input: &AllocationFingerprint<'_>) -> Result<String, String> {
    let bytes = serde_json::to_vec(input)
        .map_err(|error| format!("serialize allocation inputs: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl PendingOperation {
    pub fn validate(&self) -> Result<(), String> {
        required("operation_id", &self.operation_id)?;
        required("namespace", &self.namespace)?;
        required("operation_class", &self.operation_class)?;
        if self.max_attempts == 0 {
            return Err("operation max_attempts must be positive".into());
        }
        if self.budget_ceiling_usd_micros < 0 {
            return Err("operation budget ceiling must be non-negative".into());
        }
        if self
            .acceptance_criteria
            .iter()
            .any(|criterion| criterion.trim().is_empty())
        {
            return Err("acceptance criteria must not contain empty values".into());
        }
        Ok(())
    }
}

impl Strategy {
    pub fn validate(&self) -> Result<(), String> {
        required("strategy_id", &self.strategy_id)?;
        required("strategy version", &self.version)
    }
}

impl AllocationPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != ALLOCATION_CONTRACT_VERSION {
            return Err(format!(
                "unsupported allocation contract {}",
                self.contract_version
            ));
        }
        for (name, value) in [
            ("allocation_id", self.allocation_id.as_str()),
            ("operation_id", self.operation_id.as_str()),
            ("namespace", self.namespace.as_str()),
            ("operation_class", self.operation_class.as_str()),
            ("policy_version", self.policy_version.as_str()),
            ("agent_id", self.selection.agent_id.as_str()),
            ("runtime", self.selection.runtime.as_str()),
            ("model", self.selection.model.as_str()),
            ("input_fingerprint", self.input_fingerprint.as_str()),
        ] {
            required(name, value)?;
        }
        self.strategy.validate()?;
        if self.attempts.max_attempts == 0 || self.attempts.parallel_attempts == 0 {
            return Err("allocation attempts must be positive".into());
        }
        if self.attempts.parallel_attempts > self.attempts.max_attempts {
            return Err("parallel attempts cannot exceed max attempts".into());
        }
        if self.budget_ceiling_usd_micros < 0 || self.stop_conditions.max_cost_usd_micros < 0 {
            return Err("allocation budget limits must be non-negative".into());
        }
        if self.stop_conditions.max_cost_usd_micros > self.budget_ceiling_usd_micros {
            return Err("stop cost cannot exceed the allocation budget ceiling".into());
        }
        if self.stop_conditions.max_attempts != self.attempts.max_attempts {
            return Err("attempt and stop limits must agree".into());
        }
        for (name, value) in [
            ("quality", self.expected.quality),
            ("uncertainty", self.expected.uncertainty),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(format!("expected {name} must be between 0 and 1"));
            }
        }
        if self.expected.cost_usd_micros < 0 || self.expected.latency_ms < 0 {
            return Err("expected cost and latency must be non-negative".into());
        }
        Ok(())
    }
}

fn required(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{name} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> PendingOperation {
        PendingOperation {
            operation_id: "op-1".into(),
            namespace: "support".into(),
            operation_class: "triage".into(),
            priority: 80,
            risk: OperationRisk::Low,
            submitted_at_ms: 10,
            required_tools: BTreeSet::from(["search".into()]),
            allowed_models: BTreeSet::from(["local-small".into()]),
            max_attempts: 2,
            budget_ceiling_usd_micros: 50_000,
            acceptance_criteria: vec!["all tickets classified".into()],
            approval_required: false,
            human_attention_minutes_required: 0,
        }
    }

    fn capacity() -> CapacityEnvelope {
        CapacityEnvelope {
            captured_at_ms: 10,
            policy_version: "policy-v1".into(),
            agents: vec![AgentCapacity {
                agent_id: "agent-a".into(),
                runtime: "native".into(),
                models: BTreeSet::from(["local-small".into(), "frontier".into()]),
                tools: BTreeSet::from(["search".into()]),
                operation_classes: BTreeSet::from(["triage".into(), "*".into()]),
                available_slots: 2,
                healthy: true,
            }],
            model_profiles: vec![
                ModelProfile {
                    model: "local-small".into(),
                    quality: 0.7,
                    cost_per_attempt_usd_micros: 10_000,
                    latency_ms: 100,
                    uncertainty: 0.2,
                },
                ModelProfile {
                    model: "frontier".into(),
                    quality: 0.9,
                    cost_per_attempt_usd_micros: 40_000,
                    latency_ms: 300,
                    uncertainty: 0.1,
                },
            ],
            budget_remaining_usd_micros: 60_000,
            max_parallel_attempts: 2,
            human_attention_minutes: 30,
        }
    }

    fn request() -> AllocationRequest {
        AllocationRequest {
            capacity: capacity(),
            operations: vec![operation()],
            strategy: Strategy {
                strategy_id: "baseline".into(),
                version: "1".into(),
                baseline: BaselineStrategy::PriorityFirst,
            },
        }
    }

    fn memory(id: &str, model: &str, score: f64, observed_at_ms: i64) -> KiokuEvidence {
        KiokuEvidence {
            memory_id: id.into(),
            namespace: "support".into(),
            operation_class: "triage".into(),
            model: model.into(),
            score,
            passed: true,
            status: "active".into(),
            observed_at_ms,
            receipt_reference: Some(format!("receipt-{id}")),
        }
    }

    fn advisory_policy() -> AdvisoryPolicy {
        AdvisoryPolicy {
            max_memory_age_ms: 1_000,
            min_score: 0.5,
            max_evidence_references: 4,
        }
    }

    #[test]
    fn contracts_round_trip_without_losing_hard_constraints() {
        let original = operation();
        original.validate().unwrap();
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: PendingOperation = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.risk, OperationRisk::Low);
        assert_eq!(decoded.required_tools, BTreeSet::from(["search".into()]));
    }

    #[test]
    fn invalid_capacity_and_operation_limits_are_rejected() {
        let mut invalid = operation();
        invalid.max_attempts = 0;
        assert_eq!(
            invalid.validate().unwrap_err(),
            "operation max_attempts must be positive"
        );

        let capacity = CapacityEnvelope {
            captured_at_ms: 10,
            policy_version: "policy-v1".into(),
            agents: Vec::new(),
            model_profiles: Vec::new(),
            budget_remaining_usd_micros: 0,
            max_parallel_attempts: 0,
            human_attention_minutes: 0,
        };
        assert_eq!(
            capacity.validate().unwrap_err(),
            "capacity must allow at least one parallel attempt"
        );
    }

    #[test]
    fn baseline_is_reproducible_and_respects_eligibility() {
        let first = recommend_baseline(&request()).unwrap();
        let second = recommend_baseline(&request()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.plans.len(), 1);
        let plan = &first.plans[0];
        assert_eq!(plan.selection.agent_id, "agent-a");
        assert_eq!(plan.selection.model, "local-small");
        assert!(plan.advisory);
        assert!(!plan.attempts.speculative);
        assert_eq!(plan.attempts.parallel_attempts, 1);
        assert_eq!(plan.expected.cost_usd_micros, 10_000);
        assert_eq!(plan.input_fingerprint.len(), 64);
    }

    #[test]
    fn priority_and_capacity_determine_which_operation_is_allocated() {
        let mut request = request();
        request.capacity.agents[0].available_slots = 1;
        request.capacity.budget_remaining_usd_micros = 10_000;
        let mut urgent = operation();
        urgent.operation_id = "op-urgent".into();
        urgent.priority = 100;
        request.operations.push(urgent);

        let result = recommend_baseline(&request).unwrap();
        assert_eq!(result.plans[0].operation_id, "op-urgent");
        assert_eq!(result.unallocated[0].operation_id, "op-1");
    }

    #[test]
    fn unknown_classes_use_only_conservative_wildcard_capacity() {
        let mut request = request();
        request.strategy.baseline = BaselineStrategy::Throughput;
        request.operations[0].operation_class = "novel".into();

        let result = recommend_baseline(&request).unwrap();
        assert_eq!(
            result.plans[0].strategy.baseline,
            BaselineStrategy::Conservative
        );
        assert!(result.plans[0].explanation[2].contains("unknown operation class novel"));
    }

    #[test]
    fn fleet_parallel_limit_caps_plans_across_agents() {
        let mut request = request();
        let mut second_agent = request.capacity.agents[0].clone();
        second_agent.agent_id = "agent-b".into();
        request.capacity.agents.push(second_agent);
        request.capacity.max_parallel_attempts = 1;
        let mut second = operation();
        second.operation_id = "op-2".into();
        request.operations.push(second);

        let result = recommend_baseline(&request).unwrap();
        assert_eq!(result.plans.len(), 1);
        assert_eq!(result.unallocated.len(), 1);
        assert_eq!(
            result.unallocated[0].reason,
            "fleet parallel-attempt capacity exhausted"
        );
    }

    #[test]
    fn aggregate_stop_cost_never_exceeds_fleet_budget() {
        let mut request = request();
        let mut second_agent = request.capacity.agents[0].clone();
        second_agent.agent_id = "agent-b".into();
        request.capacity.agents.push(second_agent);
        request.capacity.budget_remaining_usd_micros = 30_000;
        let mut second = operation();
        second.operation_id = "op-2".into();
        request.operations.push(second);

        let result = recommend_baseline(&request).unwrap();
        let exposure: i64 = result
            .plans
            .iter()
            .map(|plan| plan.stop_conditions.max_cost_usd_micros)
            .sum();
        assert_eq!(result.plans.len(), 2);
        assert_eq!(exposure, 30_000);
        assert_eq!(result.plans[0].attempts.max_attempts, 2);
        assert_eq!(result.plans[1].attempts.max_attempts, 1);
    }

    #[test]
    fn wildcard_capacity_remains_available_for_known_classes() {
        let mut request = request();
        request.capacity.agents[0].healthy = false;
        let mut wildcard = request.capacity.agents[0].clone();
        wildcard.agent_id = "agent-wildcard".into();
        wildcard.healthy = true;
        wildcard.operation_classes = BTreeSet::from(["*".into()]);
        request.capacity.agents.push(wildcard);

        let result = recommend_baseline(&request).unwrap();
        assert_eq!(result.plans[0].selection.agent_id, "agent-wildcard");
        assert_eq!(
            result.plans[0].strategy.baseline,
            BaselineStrategy::PriorityFirst
        );
    }

    #[test]
    fn conservative_fallback_is_applied_before_capacity_ordering() {
        let mut request = request();
        request.strategy.baseline = BaselineStrategy::Throughput;
        request.capacity.max_parallel_attempts = 1;
        let mut unknown = operation();
        unknown.operation_id = "op-unknown".into();
        unknown.operation_class = "novel".into();
        unknown.submitted_at_ms = 0;
        request.operations.push(unknown);

        let result = recommend_baseline(&request).unwrap();
        assert_eq!(result.plans[0].operation_id, "op-1");
        assert_eq!(result.unallocated[0].operation_id, "op-unknown");
    }

    #[test]
    fn duplicate_pending_operation_ids_are_rejected() {
        let mut request = request();
        request.operations.push(operation());
        assert_eq!(
            recommend_baseline(&request).unwrap_err(),
            "duplicate pending operation op-1"
        );
    }

    #[test]
    fn review_required_work_reserves_human_attention() {
        let mut request = request();
        request.capacity.human_attention_minutes = 0;
        request.operations[0].risk = OperationRisk::Medium;

        let result = recommend_baseline(&request).unwrap();
        assert!(result.plans.is_empty());
        assert_eq!(
            result.unallocated[0].reason,
            "human-attention capacity exhausted"
        );
    }

    #[test]
    fn allocation_id_changes_with_co_scheduled_capacity_consumption() {
        let mut single = request();
        single.capacity.budget_remaining_usd_micros = 30_000;
        let single_plan = recommend_baseline(&single).unwrap().plans.remove(0);

        let mut scheduled = single;
        let mut earlier = operation();
        earlier.operation_id = "op-earlier".into();
        earlier.priority = 100;
        scheduled.operations.push(earlier);
        let result = recommend_baseline(&scheduled).unwrap();
        let changed = result
            .plans
            .iter()
            .find(|plan| plan.operation_id == "op-1")
            .unwrap();

        assert_eq!(single_plan.attempts.max_attempts, 2);
        assert_eq!(changed.attempts.max_attempts, 1);
        assert_ne!(single_plan.allocation_id, changed.allocation_id);
    }

    #[test]
    fn conservative_strategy_still_defers_unknown_classes() {
        let mut request = request();
        request.strategy.baseline = BaselineStrategy::Conservative;
        request.capacity.max_parallel_attempts = 1;
        let mut unknown = operation();
        unknown.operation_id = "op-unknown".into();
        unknown.operation_class = "novel".into();
        unknown.priority = 100;
        request.operations.push(unknown);

        let result = recommend_baseline(&request).unwrap();
        assert_eq!(result.plans[0].operation_id, "op-1");
        assert_eq!(result.unallocated[0].operation_id, "op-unknown");
    }

    #[test]
    fn advisory_uses_current_kioku_evidence_with_receipt_citations() {
        let mut request = request();
        request.strategy.baseline = BaselineStrategy::Throughput;
        request.operations[0]
            .allowed_models
            .insert("frontier".into());
        request.operations[0].max_attempts = 1;
        request.capacity.model_profiles[1].cost_per_attempt_usd_micros = 10_000;
        let baseline = recommend_baseline(&request).unwrap();
        assert_eq!(baseline.plans[0].selection.model, "local-small");

        let advisory = recommend_advisory(
            &request,
            &[
                memory("frontier-1", "frontier", 0.95, 9),
                memory("local-1", "local-small", 0.6, 9),
            ],
            &advisory_policy(),
        )
        .unwrap();
        let plan = &advisory.plans[0];
        assert_eq!(plan.selection.model, "frontier");
        assert_eq!(plan.expected.quality, 0.95);
        assert_eq!(plan.evidence[0].kind, "kioku_memory");
        assert_eq!(plan.evidence[1].kind, "operation_receipt");
        assert_ne!(plan.allocation_id, baseline.plans[0].allocation_id);
    }

    #[test]
    fn stale_kioku_evidence_cannot_change_the_baseline() {
        let mut request = request();
        request.capacity.captured_at_ms = 10_000;
        request.strategy.baseline = BaselineStrategy::Throughput;
        request.operations[0]
            .allowed_models
            .insert("frontier".into());
        request.operations[0].max_attempts = 1;
        request.capacity.model_profiles[1].cost_per_attempt_usd_micros = 10_000;

        let advisory = recommend_advisory(
            &request,
            &[memory("old", "frontier", 1.0, 1)],
            &advisory_policy(),
        )
        .unwrap();
        assert_eq!(advisory.plans[0].selection.model, "local-small");
        assert!(advisory.plans[0].evidence.is_empty());
    }

    #[test]
    fn governed_learning_objects_load_as_kioku_evidence() {
        use crate::domain::Object;
        use std::collections::HashMap;

        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "learning-1".into(),
            kind: KIND_LEARNING.into(),
            name: "Scored learning".into(),
            namespace: "support".into(),
            external_id: "learning-1".into(),
            properties: HashMap::from([
                ("task_class".into(), "triage".into()),
                ("model".into(), "local-small".into()),
                ("score".into(), "87".into()),
                ("passed".into(), "true".into()),
                ("status".into(), "active".into()),
                ("source_request_id".into(), "receipt-1".into()),
            ]),
            created: 1,
            updated: 2,
        })
        .unwrap();

        let loaded = load_kioku_evidence(&db, "support", "triage").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].score, 0.87);
        assert_eq!(loaded[0].observed_at_ms, 2_000);
        assert_eq!(loaded[0].receipt_reference.as_deref(), Some("receipt-1"));
    }

    #[test]
    fn operator_modifications_are_compared_with_receipted_outcomes() {
        let plan = recommend_baseline(&request()).unwrap().plans.remove(0);
        let choice = OperatorChoice {
            operation_id: plan.operation_id.clone(),
            allocation_id: plan.allocation_id.clone(),
            response: OperatorResponse::Modified,
            selected_resources: Some(ResourceSelection {
                model: "frontier".into(),
                ..plan.selection.clone()
            }),
            max_attempts: Some(1),
            budget_ceiling_usd_micros: Some(15_000),
            rationale: "operator preferred the frontier model".into(),
            decided_at_ms: 20,
        };
        let outcome = ObservedOutcome {
            operation_id: plan.operation_id.clone(),
            receipt_reference: "receipt-op-1".into(),
            accepted: true,
            quality: 0.8,
            cost_usd_micros: 12_000,
            latency_ms: 150,
            attempts: 1,
            completed_at_ms: 30,
        };

        let comparison = compare_advisory(&plan, &choice, Some(&outcome)).unwrap();
        assert!(!comparison.resource_selection_matched);
        assert_eq!(comparison.attempt_limit_delta, -1);
        assert_eq!(comparison.budget_ceiling_delta_usd_micros, -5_000);
        assert!((comparison.quality_error.unwrap() - 0.1).abs() < f64::EPSILON);
        assert_eq!(
            comparison.outcome_receipt_reference.as_deref(),
            Some("receipt-op-1")
        );
    }

    #[test]
    fn scorecard_keeps_decision_and_prediction_measures_separate() {
        let plan = recommend_baseline(&request()).unwrap().plans.remove(0);
        let accepted = compare_advisory(
            &plan,
            &OperatorChoice {
                operation_id: plan.operation_id.clone(),
                allocation_id: plan.allocation_id.clone(),
                response: OperatorResponse::Accepted,
                selected_resources: None,
                max_attempts: None,
                budget_ceiling_usd_micros: None,
                rationale: "accepted as proposed".into(),
                decided_at_ms: 20,
            },
            Some(&ObservedOutcome {
                operation_id: plan.operation_id.clone(),
                receipt_reference: "receipt-op-1".into(),
                accepted: true,
                quality: 0.8,
                cost_usd_micros: 11_000,
                latency_ms: 120,
                attempts: 1,
                completed_at_ms: 30,
            }),
        )
        .unwrap();
        let rejected = compare_advisory(
            &plan,
            &OperatorChoice {
                operation_id: plan.operation_id.clone(),
                allocation_id: plan.allocation_id.clone(),
                response: OperatorResponse::Rejected,
                selected_resources: None,
                max_attempts: None,
                budget_ceiling_usd_micros: None,
                rationale: "operation no longer needed".into(),
                decided_at_ms: 21,
            },
            None,
        )
        .unwrap();

        let scorecard = score_advisory_comparisons(&[accepted, rejected]);
        assert_eq!(scorecard.accepted, 1);
        assert_eq!(scorecard.rejected, 1);
        assert_eq!(scorecard.observed_outcomes, 1);
        assert_eq!(scorecard.resource_selection_agreement_rate, 0.5);
        assert!((scorecard.mean_absolute_quality_error.unwrap() - 0.1).abs() < f64::EPSILON);
        assert_eq!(scorecard.mean_absolute_cost_error_usd_micros, Some(1_000.0));
        assert_eq!(scorecard.mean_absolute_latency_error_ms, Some(20.0));
    }

    #[test]
    fn comparison_rejects_mismatched_receipt_outcomes() {
        let plan = recommend_baseline(&request()).unwrap().plans.remove(0);
        let choice = OperatorChoice {
            operation_id: plan.operation_id.clone(),
            allocation_id: plan.allocation_id.clone(),
            response: OperatorResponse::Accepted,
            selected_resources: None,
            max_attempts: None,
            budget_ceiling_usd_micros: None,
            rationale: "accepted".into(),
            decided_at_ms: 20,
        };
        let outcome = ObservedOutcome {
            operation_id: "other".into(),
            receipt_reference: "receipt-other".into(),
            accepted: false,
            quality: 0.0,
            cost_usd_micros: 0,
            latency_ms: 1,
            attempts: 1,
            completed_at_ms: 30,
        };
        assert_eq!(
            compare_advisory(&plan, &choice, Some(&outcome)).unwrap_err(),
            "observed outcome does not belong to the allocation operation"
        );
    }

    #[test]
    fn accepted_choices_cannot_hide_attempt_or_budget_changes() {
        let plan = recommend_baseline(&request()).unwrap().plans.remove(0);
        let choice = OperatorChoice {
            operation_id: plan.operation_id.clone(),
            allocation_id: plan.allocation_id.clone(),
            response: OperatorResponse::Accepted,
            selected_resources: None,
            max_attempts: Some(1),
            budget_ceiling_usd_micros: None,
            rationale: "accepted with a hidden override".into(),
            decided_at_ms: 20,
        };
        assert_eq!(
            compare_advisory(&plan, &choice, None).unwrap_err(),
            "accepted choices cannot carry allocation overrides"
        );
    }

    #[test]
    fn attempt_only_modifications_keep_the_recommended_resources() {
        let plan = recommend_baseline(&request()).unwrap().plans.remove(0);
        let choice = OperatorChoice {
            operation_id: plan.operation_id.clone(),
            allocation_id: plan.allocation_id.clone(),
            response: OperatorResponse::Modified,
            selected_resources: None,
            max_attempts: Some(1),
            budget_ceiling_usd_micros: None,
            rationale: "one attempt is sufficient".into(),
            decided_at_ms: 20,
        };
        let comparison = compare_advisory(&plan, &choice, None).unwrap();
        assert!(comparison.resource_selection_matched);
        assert_eq!(comparison.attempt_limit_delta, -1);
    }

    #[test]
    fn resource_comparison_treats_tool_order_as_set_semantics() {
        let mut request = request();
        request.operations[0].required_tools.insert("shell".into());
        request.capacity.agents[0].tools.insert("shell".into());
        let plan = recommend_baseline(&request).unwrap().plans.remove(0);
        let mut reordered = plan.selection.clone();
        reordered.tools.reverse();
        let choice = OperatorChoice {
            operation_id: plan.operation_id.clone(),
            allocation_id: plan.allocation_id.clone(),
            response: OperatorResponse::Modified,
            selected_resources: Some(reordered),
            max_attempts: None,
            budget_ceiling_usd_micros: None,
            rationale: "same tools supplied in operator order".into(),
            decided_at_ms: 20,
        };

        let comparison = compare_advisory(&plan, &choice, None).unwrap();
        assert!(comparison.resource_selection_matched);
    }
}
