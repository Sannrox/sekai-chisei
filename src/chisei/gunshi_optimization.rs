//! Deterministic execution-shape optimization for Gunshi allocation plans.
//!
//! The result describes attempts, fallbacks, stopping, and human-review use.
//! It does not dispatch work or mutate runtime capacity.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::chisei::gunshi::{
    AllocationPlan, CapacityEnvelope, ExpectedOutcome, OperationRisk, PendingOperation,
    ResourceSelection,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizationPolicy {
    pub policy_id: String,
    pub version: String,
    pub maximum_best_of_n: u32,
    pub maximum_fallbacks: usize,
    pub early_stop_quality: f64,
    pub speculative_uncertainty_threshold: f64,
    pub human_review_uncertainty_threshold: f64,
    pub maximum_human_attention_minutes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackResource {
    pub selection: ResourceSelection,
    pub activate_after_failed_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EarlyStopStrategy {
    pub stop_on_acceptance: bool,
    pub minimum_quality: f64,
    pub maximum_cost_usd_micros: i64,
    pub maximum_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanAttentionStrategy {
    pub reserved_minutes: u32,
    pub review_before_dispatch: bool,
    pub review_after_failed_attempts: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizedExecutionPlan {
    pub allocation_id: String,
    pub operation_id: String,
    pub optimization_policy_id: String,
    pub optimization_policy_version: String,
    pub primary: ResourceSelection,
    pub best_of_n: u32,
    pub parallel_attempts: u32,
    pub speculative: bool,
    pub fallbacks: Vec<FallbackResource>,
    pub early_stop: EarlyStopStrategy,
    pub human_attention: HumanAttentionStrategy,
    pub expected: ExpectedOutcome,
    pub explanation: Vec<String>,
}

impl OptimizationPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_id.trim().is_empty() || self.version.trim().is_empty() {
            return Err("optimization policy id and version are required".into());
        }
        if self.maximum_best_of_n == 0 {
            return Err("optimization must allow at least one attempt".into());
        }
        for (name, value) in [
            ("early-stop quality", self.early_stop_quality),
            (
                "speculative uncertainty threshold",
                self.speculative_uncertainty_threshold,
            ),
            (
                "human-review uncertainty threshold",
                self.human_review_uncertainty_threshold,
            ),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(format!("{name} must be between 0 and 1"));
            }
        }
        Ok(())
    }
}

pub fn optimize_execution(
    plan: &AllocationPlan,
    operation: &PendingOperation,
    capacity: &CapacityEnvelope,
    policy: &OptimizationPolicy,
) -> Result<OptimizedExecutionPlan, String> {
    plan.validate()?;
    operation.validate()?;
    capacity.validate()?;
    policy.validate()?;
    if plan.operation_id != operation.operation_id
        || plan.namespace != operation.namespace
        || plan.operation_class != operation.operation_class
    {
        return Err("allocation plan does not match the pending operation".into());
    }
    if plan.policy_version != capacity.policy_version {
        return Err("capacity policy version does not match the allocation".into());
    }
    let selected_tools = plan
        .selection
        .tools
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if selected_tools.len() != plan.selection.tools.len()
        || selected_tools != operation.required_tools
        || (!operation.allowed_models.is_empty()
            && !operation.allowed_models.contains(&plan.selection.model))
    {
        return Err("allocation resources exceed the pending operation constraints".into());
    }
    if plan.verification.acceptance_criteria != operation.acceptance_criteria
        || !plan
            .verification
            .checks
            .iter()
            .any(|check| check == "operation_receipt_complete")
    {
        return Err("allocation weakens the pending operation verification requirements".into());
    }

    let primary_agent = capacity
        .agents
        .iter()
        .find(|agent| {
            agent.agent_id == plan.selection.agent_id
                && agent.runtime == plan.selection.runtime
                && agent.healthy
                && agent.available_slots > 0
                && agent.models.contains(&plan.selection.model)
                && selected_tools.is_subset(&agent.tools)
                && (agent.operation_classes.contains(&operation.operation_class)
                    || agent.operation_classes.contains("*"))
        })
        .ok_or_else(|| "selected agent capacity is no longer available".to_string())?;
    let primary_profile = capacity
        .model_profiles
        .iter()
        .find(|profile| profile.model == plan.selection.model)
        .ok_or_else(|| "selected model has no capacity profile".to_string())?;
    let unknown_operation_class = !capacity
        .agents
        .iter()
        .any(|agent| agent.operation_classes.contains(&operation.operation_class));
    let mut hard_attempt_limit = plan
        .attempts
        .max_attempts
        .min(operation.max_attempts)
        .min(plan.stop_conditions.max_attempts)
        .min(policy.maximum_best_of_n);
    if unknown_operation_class {
        hard_attempt_limit = hard_attempt_limit.min(1);
    }
    let hard_budget = plan
        .budget_ceiling_usd_micros
        .min(plan.stop_conditions.max_cost_usd_micros)
        .min(operation.budget_ceiling_usd_micros)
        .min(capacity.budget_remaining_usd_micros);
    let affordable_attempts = if primary_profile.cost_per_attempt_usd_micros == 0 {
        hard_attempt_limit
    } else {
        (hard_budget / primary_profile.cost_per_attempt_usd_micros).clamp(0, u32::MAX as i64) as u32
    };
    let best_of_n = hard_attempt_limit.min(affordable_attempts);
    if best_of_n == 0 {
        return Err("allocation budget cannot fund a primary attempt".into());
    }
    let mut fallback_candidates = Vec::new();
    for agent in &capacity.agents {
        if !agent.healthy
            || agent.available_slots == 0
            || !operation.required_tools.is_subset(&agent.tools)
            || !(agent.operation_classes.contains(&operation.operation_class)
                || agent.operation_classes.contains("*"))
        {
            continue;
        }
        for model in &agent.models {
            if !operation.allowed_models.is_empty() && !operation.allowed_models.contains(model) {
                continue;
            }
            let selection = ResourceSelection {
                agent_id: agent.agent_id.clone(),
                runtime: agent.runtime.clone(),
                model: model.clone(),
                tools: operation.required_tools.iter().cloned().collect(),
            };
            if selection == plan.selection {
                continue;
            }
            let Some(profile) = capacity
                .model_profiles
                .iter()
                .find(|profile| profile.model == *model)
            else {
                continue;
            };
            if profile.cost_per_attempt_usd_micros > hard_budget {
                continue;
            }
            fallback_candidates.push((selection, profile));
        }
    }
    fallback_candidates.sort_by(|(left_selection, left), (right_selection, right)| {
        right
            .quality
            .total_cmp(&left.quality)
            .then_with(|| left.uncertainty.total_cmp(&right.uncertainty))
            .then_with(|| {
                left.cost_per_attempt_usd_micros
                    .cmp(&right.cost_per_attempt_usd_micros)
            })
            .then_with(|| left.latency_ms.cmp(&right.latency_ms))
            .then_with(|| left_selection.agent_id.cmp(&right_selection.agent_id))
            .then_with(|| left_selection.model.cmp(&right_selection.model))
    });
    let maximum_fallbacks = policy
        .maximum_fallbacks
        .min(best_of_n.saturating_sub(1) as usize);
    let mut worst_case_cost = primary_profile
        .cost_per_attempt_usd_micros
        .checked_mul(i64::from(best_of_n))
        .ok_or_else(|| "optimized attempt cost overflowed".to_string())?;
    let mut selected_fallbacks = Vec::new();
    for (selection, profile) in fallback_candidates {
        if selected_fallbacks.len() == maximum_fallbacks {
            break;
        }
        let candidate_cost = worst_case_cost
            .checked_sub(primary_profile.cost_per_attempt_usd_micros)
            .and_then(|cost| cost.checked_add(profile.cost_per_attempt_usd_micros));
        if candidate_cost.is_some_and(|cost| cost <= hard_budget) {
            worst_case_cost = candidate_cost.expect("checked candidate cost");
            selected_fallbacks.push(selection);
        }
    }
    let primary_attempts = best_of_n.saturating_sub(selected_fallbacks.len() as u32);
    let fallbacks = selected_fallbacks
        .into_iter()
        .enumerate()
        .map(|(index, selection)| FallbackResource {
            selection,
            activate_after_failed_attempts: primary_attempts.saturating_add(index as u32),
        })
        .collect::<Vec<_>>();
    let available_parallel_attempts = primary_agent
        .available_slots
        .min(capacity.max_parallel_attempts)
        .min(primary_attempts);
    let speculative = available_parallel_attempts > 1
        && !unknown_operation_class
        && plan.expected.uncertainty >= policy.speculative_uncertainty_threshold;
    let parallel_attempts = if speculative {
        available_parallel_attempts
    } else {
        1
    };

    let review_before_dispatch = operation.approval_required
        || operation.risk >= OperationRisk::Medium
        || plan.verification.human_review_required
        || operation.human_attention_minutes_required > 0;
    let reserved_minutes = if review_before_dispatch {
        operation.human_attention_minutes_required.max(1)
    } else if plan.expected.uncertainty >= policy.human_review_uncertainty_threshold {
        1
    } else {
        0
    };
    if reserved_minutes > capacity.human_attention_minutes
        || reserved_minutes > policy.maximum_human_attention_minutes
    {
        return Err("allocation exceeds the human-attention envelope".into());
    }
    let review_after_failed_attempts =
        (!review_before_dispatch && reserved_minutes > 0).then_some(best_of_n);

    let mut explanation = vec![format!(
        "bounded best-of-N to {best_of_n} attempts by policy, operation, budget, and allocation limits"
    )];
    if speculative {
        explanation.push(format!(
            "runs up to {parallel_attempts} attempts in parallel because expected uncertainty is {:.3}",
            plan.expected.uncertainty
        ));
    } else {
        explanation.push("uses sequential execution because speculation is not justified".into());
    }
    if fallbacks.is_empty() {
        explanation.push("no compatible fallback capacity is available".into());
    } else {
        explanation.push(format!(
            "retains {} deterministic fallback resource selections",
            fallbacks.len()
        ));
    }
    if let Some(after) = review_after_failed_attempts {
        explanation.push(format!(
            "reserves human review only after {after} automated attempts fail"
        ));
    }

    Ok(OptimizedExecutionPlan {
        allocation_id: plan.allocation_id.clone(),
        operation_id: plan.operation_id.clone(),
        optimization_policy_id: policy.policy_id.clone(),
        optimization_policy_version: policy.version.clone(),
        primary: plan.selection.clone(),
        best_of_n,
        parallel_attempts,
        speculative,
        fallbacks,
        early_stop: EarlyStopStrategy {
            stop_on_acceptance: true,
            minimum_quality: policy.early_stop_quality,
            maximum_cost_usd_micros: hard_budget.min(worst_case_cost),
            maximum_attempts: best_of_n,
        },
        human_attention: HumanAttentionStrategy {
            reserved_minutes,
            review_before_dispatch,
            review_after_failed_attempts,
        },
        expected: plan.expected.clone(),
        explanation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use crate::chisei::gunshi::{
        AdvisoryPolicy, AgentCapacity, AllocationRequest, BaselineStrategy, ModelProfile,
        OperationRisk, Strategy, recommend_advisory,
    };

    fn operation() -> PendingOperation {
        PendingOperation {
            operation_id: "op-1".into(),
            namespace: "support".into(),
            operation_class: "triage".into(),
            priority: 80,
            risk: OperationRisk::Low,
            submitted_at_ms: 1,
            required_tools: BTreeSet::from(["search".into()]),
            allowed_models: BTreeSet::from(["primary".into(), "fallback".into()]),
            max_attempts: 3,
            budget_ceiling_usd_micros: 30_000,
            acceptance_criteria: vec!["classified".into()],
            approval_required: false,
            human_attention_minutes_required: 0,
        }
    }

    fn capacity() -> CapacityEnvelope {
        CapacityEnvelope {
            captured_at_ms: 100,
            policy_version: "governance-v1".into(),
            agents: vec![
                AgentCapacity {
                    agent_id: "agent-1".into(),
                    runtime: "native".into(),
                    models: BTreeSet::from(["primary".into()]),
                    tools: BTreeSet::from(["search".into()]),
                    operation_classes: BTreeSet::from(["triage".into()]),
                    available_slots: 2,
                    healthy: true,
                },
                AgentCapacity {
                    agent_id: "agent-2".into(),
                    runtime: "native".into(),
                    models: BTreeSet::from(["fallback".into()]),
                    tools: BTreeSet::from(["search".into()]),
                    operation_classes: BTreeSet::from(["triage".into()]),
                    available_slots: 1,
                    healthy: true,
                },
            ],
            model_profiles: vec![
                ModelProfile {
                    model: "primary".into(),
                    quality: 0.9,
                    cost_per_attempt_usd_micros: 10_000,
                    latency_ms: 100,
                    uncertainty: 0.3,
                },
                ModelProfile {
                    model: "fallback".into(),
                    quality: 0.8,
                    cost_per_attempt_usd_micros: 5_000,
                    latency_ms: 80,
                    uncertainty: 0.2,
                },
            ],
            budget_remaining_usd_micros: 30_000,
            max_parallel_attempts: 2,
            human_attention_minutes: 5,
        }
    }

    fn plan() -> AllocationPlan {
        recommend_advisory(
            &AllocationRequest {
                capacity: capacity(),
                operations: vec![operation()],
                strategy: Strategy {
                    strategy_id: "throughput".into(),
                    version: "1".into(),
                    baseline: BaselineStrategy::Conservative,
                },
            },
            &[],
            &AdvisoryPolicy {
                max_memory_age_ms: 1,
                min_score: 0.5,
                max_evidence_references: 1,
            },
        )
        .unwrap()
        .plans
        .remove(0)
    }

    fn policy() -> OptimizationPolicy {
        OptimizationPolicy {
            policy_id: "balanced".into(),
            version: "1".into(),
            maximum_best_of_n: 3,
            maximum_fallbacks: 1,
            early_stop_quality: 0.85,
            speculative_uncertainty_threshold: 0.2,
            human_review_uncertainty_threshold: 0.25,
            maximum_human_attention_minutes: 5,
        }
    }

    #[test]
    fn chooses_best_of_n_early_stopping_and_deterministic_fallback() {
        let optimized = optimize_execution(&plan(), &operation(), &capacity(), &policy()).unwrap();
        assert_eq!(optimized.best_of_n, 3);
        assert_eq!(optimized.parallel_attempts, 2);
        assert!(optimized.speculative);
        assert_eq!(optimized.fallbacks.len(), 1);
        assert_eq!(optimized.fallbacks[0].selection.agent_id, "agent-2");
        assert_eq!(optimized.fallbacks[0].activate_after_failed_attempts, 2);
        assert_eq!(optimized.early_stop.minimum_quality, 0.85);
        assert_eq!(optimized.early_stop.maximum_attempts, 3);
        assert_eq!(optimized.early_stop.maximum_cost_usd_micros, 25_000);
        assert_eq!(
            optimized.human_attention.review_after_failed_attempts,
            Some(3)
        );
    }

    #[test]
    fn scarce_budget_reduces_best_of_n_without_exceeding_envelope() {
        let mut plan = plan();
        plan.budget_ceiling_usd_micros = 10_000;
        plan.stop_conditions.max_cost_usd_micros = 10_000;
        let optimized = optimize_execution(&plan, &operation(), &capacity(), &policy()).unwrap();
        assert_eq!(optimized.best_of_n, 1);
        assert_eq!(optimized.parallel_attempts, 1);
        assert!(!optimized.speculative);
    }

    #[test]
    fn unavailable_agents_are_not_retained_as_fallbacks() {
        let mut capacity = capacity();
        capacity.agents[1].healthy = false;
        let optimized = optimize_execution(&plan(), &operation(), &capacity, &policy()).unwrap();
        assert!(optimized.fallbacks.is_empty());
    }

    #[test]
    fn expensive_fallbacks_cannot_expand_the_worst_case_budget() {
        let mut capacity = capacity();
        capacity.model_profiles[1].cost_per_attempt_usd_micros = 20_000;
        let optimized = optimize_execution(&plan(), &operation(), &capacity, &policy()).unwrap();
        assert!(optimized.fallbacks.is_empty());
        assert_eq!(optimized.early_stop.maximum_cost_usd_micros, 30_000);
    }

    #[test]
    fn unknown_operation_classes_keep_a_conservative_single_attempt() {
        let mut operation = operation();
        operation.operation_class = "unknown".into();
        let mut capacity = capacity();
        for agent in &mut capacity.agents {
            agent.operation_classes = BTreeSet::from(["*".into()]);
        }
        let plan = recommend_advisory(
            &AllocationRequest {
                capacity: capacity.clone(),
                operations: vec![operation.clone()],
                strategy: Strategy {
                    strategy_id: "throughput".into(),
                    version: "1".into(),
                    baseline: BaselineStrategy::Throughput,
                },
            },
            &[],
            &AdvisoryPolicy {
                max_memory_age_ms: 1,
                min_score: 0.5,
                max_evidence_references: 1,
            },
        )
        .unwrap()
        .plans
        .remove(0);
        let optimized = optimize_execution(&plan, &operation, &capacity, &policy()).unwrap();
        assert_eq!(optimized.best_of_n, 1);
        assert!(!optimized.speculative);
        assert!(optimized.fallbacks.is_empty());
    }

    #[test]
    fn operation_resources_and_verification_remain_hard_limits() {
        let mut extra_tools_plan = plan();
        extra_tools_plan.selection.tools.push("shell".into());
        assert_eq!(
            optimize_execution(&extra_tools_plan, &operation(), &capacity(), &policy())
                .unwrap_err(),
            "allocation resources exceed the pending operation constraints"
        );

        let mut plan = plan();
        plan.verification.acceptance_criteria.clear();
        assert_eq!(
            optimize_execution(&plan, &operation(), &capacity(), &policy()).unwrap_err(),
            "allocation weakens the pending operation verification requirements"
        );
    }

    #[test]
    fn human_attention_is_a_hard_limit() {
        let mut plan = plan();
        plan.verification.human_review_required = true;
        let mut operation = operation();
        operation.human_attention_minutes_required = 6;
        assert_eq!(
            optimize_execution(&plan, &operation, &capacity(), &policy()).unwrap_err(),
            "allocation exceeds the human-attention envelope"
        );
    }

    #[test]
    fn speculation_requires_multiple_live_parallel_slots() {
        let mut capacity = capacity();
        capacity.agents[0].available_slots = 1;
        let optimized = optimize_execution(&plan(), &operation(), &capacity, &policy()).unwrap();
        assert!(!optimized.speculative);
        assert_eq!(optimized.parallel_attempts, 1);
    }

    #[test]
    fn operation_risk_independently_requires_human_review() {
        let plan = plan();
        let mut operation = operation();
        operation.risk = OperationRisk::Medium;
        let optimized = optimize_execution(&plan, &operation, &capacity(), &policy()).unwrap();
        assert!(optimized.human_attention.review_before_dispatch);
        assert_eq!(optimized.human_attention.reserved_minutes, 1);
        assert_eq!(optimized.human_attention.review_after_failed_attempts, None);
    }
}
