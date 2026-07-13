//! Evaluation-gated promotion and rollback for Gunshi allocation policies.
//!
//! Every transition keeps the prior policy snapshot available for reversal.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::chisei::gunshi_dispatch::AutoDispatchPolicy;
use crate::chisei::gunshi_optimization::OptimizationPolicy;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllocationPolicySnapshot {
    pub revision_id: String,
    pub governance_policy_version: String,
    pub dispatch: AutoDispatchPolicy,
    pub optimization: OptimizationPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardLimitChecks {
    pub policy: bool,
    pub security: bool,
    pub privacy: bool,
    pub approval: bool,
    pub budget: bool,
    pub capacity: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub policy_revision_id: String,
    pub suite_id: String,
    pub run_id: String,
    pub samples: u64,
    pub successful_outcomes: u64,
    pub operator_acceptances: u64,
    pub mean_quality: f64,
    pub cost_per_success_usd_micros: f64,
    pub p95_latency_ms: f64,
    pub hard_limits: HardLimitChecks,
    pub evidence_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyEvaluationGate {
    pub gate_id: String,
    pub version: String,
    pub suite_id: String,
    pub minimum_samples: u64,
    pub minimum_success_rate: f64,
    pub minimum_operator_acceptance_rate: f64,
    pub minimum_mean_quality: f64,
    pub maximum_quality_regression: f64,
    pub maximum_cost_per_success_usd_micros: f64,
    pub maximum_cost_increase_usd_micros: f64,
    pub maximum_p95_latency_ms: f64,
    pub maximum_latency_increase_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTransition {
    Retain,
    Promote,
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyTransitionDecision {
    pub gate_id: String,
    pub gate_version: String,
    pub from_revision_id: String,
    pub evaluated_revision_id: String,
    pub transition: PolicyTransition,
    pub reasons: Vec<String>,
    pub evidence_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveAllocationPolicy {
    pub active: AllocationPolicySnapshot,
    pub rollback: Option<AllocationPolicySnapshot>,
    pub rollback_baseline: Option<PolicyEvaluation>,
    pub last_transition: Option<PolicyTransitionDecision>,
    pub changed_at_ms: i64,
}

impl AllocationPolicySnapshot {
    pub fn validate(&self) -> Result<(), String> {
        if self.revision_id.trim().is_empty() || self.governance_policy_version.trim().is_empty() {
            return Err("policy revision id and governance version are required".into());
        }
        self.dispatch.validate()?;
        self.optimization.validate()?;
        if self.dispatch.version != self.revision_id
            || self.optimization.version != self.revision_id
        {
            return Err("embedded policy versions must match the revision id".into());
        }
        if self.dispatch.governance_policy_version != self.governance_policy_version {
            return Err("dispatch and allocation governance versions must match".into());
        }
        Ok(())
    }
}

impl HardLimitChecks {
    fn all_passed(&self) -> bool {
        self.policy
            && self.security
            && self.privacy
            && self.approval
            && self.budget
            && self.capacity
    }
}

impl ActiveAllocationPolicy {
    pub fn validate(&self) -> Result<(), String> {
        self.active.validate()?;
        match (&self.rollback, &self.rollback_baseline) {
            (Some(rollback), Some(baseline)) => {
                rollback.validate()?;
                baseline.validate()?;
                if rollback.governance_policy_version != self.active.governance_policy_version
                    || baseline.policy_revision_id != rollback.revision_id
                {
                    return Err("rollback snapshot and evaluation baseline do not match".into());
                }
            }
            (None, None) => {}
            _ => {
                return Err(
                    "rollback snapshot and evaluation baseline must be stored together".into(),
                );
            }
        }
        Ok(())
    }
}

impl PolicyEvaluation {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("policy revision id", self.policy_revision_id.as_str()),
            ("evaluation suite id", self.suite_id.as_str()),
            ("evaluation run id", self.run_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} is required"));
            }
        }
        if self.successful_outcomes > self.samples || self.operator_acceptances > self.samples {
            return Err("evaluation counts cannot exceed sample count".into());
        }
        for (name, value) in [
            ("mean quality", self.mean_quality),
            (
                "cost per successful outcome",
                self.cost_per_success_usd_micros,
            ),
            ("p95 latency", self.p95_latency_ms),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(format!("{name} must be finite and non-negative"));
            }
        }
        if self.mean_quality > 1.0 {
            return Err("mean quality must not exceed 1".into());
        }
        if self.evidence_references.is_empty()
            || self
                .evidence_references
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err("evaluation requires attributable evidence references".into());
        }
        Ok(())
    }

    fn success_rate(&self) -> f64 {
        ratio(self.successful_outcomes, self.samples)
    }

    fn operator_acceptance_rate(&self) -> f64 {
        ratio(self.operator_acceptances, self.samples)
    }
}

impl PolicyEvaluationGate {
    pub fn validate(&self) -> Result<(), String> {
        if self.gate_id.trim().is_empty()
            || self.version.trim().is_empty()
            || self.suite_id.trim().is_empty()
        {
            return Err("evaluation gate id, version, and suite are required".into());
        }
        if self.minimum_samples == 0 {
            return Err("evaluation gate requires at least one sample".into());
        }
        for (name, value) in [
            ("minimum success rate", self.minimum_success_rate),
            (
                "minimum operator acceptance rate",
                self.minimum_operator_acceptance_rate,
            ),
            ("minimum mean quality", self.minimum_mean_quality),
            (
                "maximum quality regression",
                self.maximum_quality_regression,
            ),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(format!("{name} must be between 0 and 1"));
            }
        }
        for (name, value) in [
            (
                "maximum cost per success",
                self.maximum_cost_per_success_usd_micros,
            ),
            (
                "maximum cost increase",
                self.maximum_cost_increase_usd_micros,
            ),
            ("maximum p95 latency", self.maximum_p95_latency_ms),
            ("maximum latency increase", self.maximum_latency_increase_ms),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(format!("{name} must be finite and non-negative"));
            }
        }
        Ok(())
    }
}

pub fn evaluate_policy_candidate(
    active: &AllocationPolicySnapshot,
    candidate: &AllocationPolicySnapshot,
    baseline: &PolicyEvaluation,
    candidate_evaluation: &PolicyEvaluation,
    gate: &PolicyEvaluationGate,
) -> Result<PolicyTransitionDecision, String> {
    active.validate()?;
    candidate.validate()?;
    baseline.validate()?;
    candidate_evaluation.validate()?;
    gate.validate()?;
    if active.revision_id == candidate.revision_id {
        return Err("candidate policy revision must differ from the active revision".into());
    }
    if baseline.policy_revision_id != active.revision_id
        || candidate_evaluation.policy_revision_id != candidate.revision_id
    {
        return Err("evaluation evidence does not match the policy revisions".into());
    }
    if active.governance_policy_version != candidate.governance_policy_version {
        return Err("candidate cannot change the governing policy version".into());
    }
    let reasons = gate_failures(baseline, candidate_evaluation, gate, true)?;
    Ok(PolicyTransitionDecision {
        gate_id: gate.gate_id.clone(),
        gate_version: gate.version.clone(),
        from_revision_id: active.revision_id.clone(),
        evaluated_revision_id: candidate.revision_id.clone(),
        transition: if reasons.is_empty() {
            PolicyTransition::Promote
        } else {
            PolicyTransition::Retain
        },
        reasons,
        evidence_references: evaluation_evidence(baseline, candidate_evaluation),
    })
}

pub fn apply_promotion(
    current: &ActiveAllocationPolicy,
    candidate: AllocationPolicySnapshot,
    baseline: PolicyEvaluation,
    candidate_evaluation: PolicyEvaluation,
    gate: &PolicyEvaluationGate,
    changed_at_ms: i64,
) -> Result<ActiveAllocationPolicy, String> {
    current.validate()?;
    if changed_at_ms < current.changed_at_ms {
        return Err("policy transition timestamp cannot move backward".into());
    }
    let decision = evaluate_policy_candidate(
        &current.active,
        &candidate,
        &baseline,
        &candidate_evaluation,
        gate,
    )?;
    if decision.transition != PolicyTransition::Promote {
        return Err(format!(
            "policy candidate failed promotion gate: {}",
            decision.reasons.join("; ")
        ));
    }
    Ok(ActiveAllocationPolicy {
        active: candidate,
        rollback: Some(current.active.clone()),
        rollback_baseline: Some(baseline),
        last_transition: Some(decision),
        changed_at_ms,
    })
}

pub fn monitor_and_rollback(
    current: &ActiveAllocationPolicy,
    observed: &PolicyEvaluation,
    gate: &PolicyEvaluationGate,
    changed_at_ms: i64,
) -> Result<ActiveAllocationPolicy, String> {
    current.validate()?;
    observed.validate()?;
    gate.validate()?;
    if changed_at_ms < current.changed_at_ms {
        return Err("policy transition timestamp cannot move backward".into());
    }
    if observed.policy_revision_id != current.active.revision_id {
        return Err("monitoring evidence does not match the active policy revision".into());
    }
    let Some(rollback) = &current.rollback else {
        return Err("active policy has no rollback snapshot".into());
    };
    let Some(baseline) = &current.rollback_baseline else {
        return Err("active policy has no rollback evaluation baseline".into());
    };
    let promotion = current
        .last_transition
        .as_ref()
        .filter(|decision| decision.transition == PolicyTransition::Promote)
        .ok_or_else(|| "active policy was not installed by a promotion decision".to_string())?;
    if promotion.gate_id != gate.gate_id || promotion.gate_version != gate.version {
        return Err("monitoring must use the gate version that authorized promotion".into());
    }
    if baseline.suite_id != gate.suite_id || observed.suite_id != gate.suite_id {
        return Err("policy evaluations must use the gate's evaluation suite".into());
    }
    let reasons = gate_failures(baseline, observed, gate, false)?;
    if reasons.as_slice() == ["evaluation sample count is below the gate minimum"] {
        return Ok(current.clone());
    }
    if reasons.is_empty() {
        return Ok(current.clone());
    }
    let decision = PolicyTransitionDecision {
        gate_id: gate.gate_id.clone(),
        gate_version: gate.version.clone(),
        from_revision_id: current.active.revision_id.clone(),
        evaluated_revision_id: current.active.revision_id.clone(),
        transition: PolicyTransition::Rollback,
        reasons,
        evidence_references: evaluation_evidence(baseline, observed),
    };
    Ok(ActiveAllocationPolicy {
        active: rollback.clone(),
        rollback: Some(current.active.clone()),
        rollback_baseline: Some(observed.clone()),
        last_transition: Some(decision),
        changed_at_ms,
    })
}

fn gate_failures(
    baseline: &PolicyEvaluation,
    evaluated: &PolicyEvaluation,
    gate: &PolicyEvaluationGate,
    require_baseline_gate: bool,
) -> Result<Vec<String>, String> {
    if baseline.suite_id != gate.suite_id || evaluated.suite_id != gate.suite_id {
        return Err("policy evaluations must use the gate's evaluation suite".into());
    }
    let mut reasons = Vec::new();
    if require_baseline_gate && baseline.samples < gate.minimum_samples {
        reasons.push("baseline sample count is below the gate minimum".into());
    }
    if require_baseline_gate
        && (!baseline.hard_limits.all_passed()
            || baseline.success_rate() < gate.minimum_success_rate
            || baseline.operator_acceptance_rate() < gate.minimum_operator_acceptance_rate
            || baseline.mean_quality < gate.minimum_mean_quality
            || baseline.cost_per_success_usd_micros > gate.maximum_cost_per_success_usd_micros
            || baseline.p95_latency_ms > gate.maximum_p95_latency_ms)
    {
        reasons.push("rollback baseline does not satisfy the evaluation gate".into());
    }
    if evaluated.samples < gate.minimum_samples {
        reasons.push("evaluation sample count is below the gate minimum".into());
    }
    if !evaluated.hard_limits.all_passed() {
        reasons.push("one or more policy hard-limit checks failed".into());
    }
    if evaluated.success_rate() < gate.minimum_success_rate {
        reasons.push("successful-outcome rate is below the gate minimum".into());
    }
    if evaluated.operator_acceptance_rate() < gate.minimum_operator_acceptance_rate {
        reasons.push("operator acceptance rate is below the gate minimum".into());
    }
    if evaluated.mean_quality < gate.minimum_mean_quality
        || evaluated.mean_quality + gate.maximum_quality_regression < baseline.mean_quality
    {
        reasons.push("quality failed the absolute or regression limit".into());
    }
    if evaluated.cost_per_success_usd_micros > gate.maximum_cost_per_success_usd_micros
        || evaluated.cost_per_success_usd_micros
            > baseline.cost_per_success_usd_micros + gate.maximum_cost_increase_usd_micros
    {
        reasons.push("cost per successful outcome exceeded the gate limit".into());
    }
    if evaluated.p95_latency_ms > gate.maximum_p95_latency_ms
        || evaluated.p95_latency_ms > baseline.p95_latency_ms + gate.maximum_latency_increase_ms
    {
        reasons.push("p95 latency exceeded the gate limit".into());
    }
    Ok(reasons)
}

fn evaluation_evidence(baseline: &PolicyEvaluation, evaluated: &PolicyEvaluation) -> Vec<String> {
    baseline
        .evidence_references
        .iter()
        .chain(&evaluated.evidence_references)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use crate::chisei::gunshi::OperationRisk;

    fn snapshot(revision: &str) -> AllocationPolicySnapshot {
        AllocationPolicySnapshot {
            revision_id: revision.into(),
            governance_policy_version: "governance-v1".into(),
            dispatch: AutoDispatchPolicy {
                policy_id: "auto-low-risk".into(),
                version: revision.into(),
                governance_policy_version: "governance-v1".into(),
                enabled: true,
                allowed_namespaces: BTreeSet::from(["support".into()]),
                allowed_operation_classes: BTreeSet::from(["triage".into()]),
                maximum_risk: OperationRisk::Low,
                maximum_budget_usd_micros: 10_000,
                maximum_attempts: 2,
                require_governed_evidence: true,
                maximum_evidence_age_ms: 86_400_000,
                minimum_evidence_score: 0.8,
                minimum_advisory_comparisons: 10,
                minimum_observed_outcomes: 10,
                minimum_operator_acceptance_rate: 0.8,
            },
            optimization: OptimizationPolicy {
                policy_id: "balanced".into(),
                version: revision.into(),
                maximum_best_of_n: 2,
                maximum_fallbacks: 1,
                early_stop_quality: 0.8,
                speculative_uncertainty_threshold: 0.2,
                human_review_uncertainty_threshold: 0.4,
                maximum_human_attention_minutes: 5,
            },
        }
    }

    fn evaluation(revision: &str) -> PolicyEvaluation {
        PolicyEvaluation {
            policy_revision_id: revision.into(),
            suite_id: "fleet-eval".into(),
            run_id: format!("run-{revision}"),
            samples: 100,
            successful_outcomes: 95,
            operator_acceptances: 90,
            mean_quality: 0.9,
            cost_per_success_usd_micros: 8_000.0,
            p95_latency_ms: 500.0,
            hard_limits: HardLimitChecks {
                policy: true,
                security: true,
                privacy: true,
                approval: true,
                budget: true,
                capacity: true,
            },
            evidence_references: vec![format!("eval://run-{revision}")],
        }
    }

    fn gate() -> PolicyEvaluationGate {
        PolicyEvaluationGate {
            gate_id: "fleet-promotion".into(),
            version: "1".into(),
            suite_id: "fleet-eval".into(),
            minimum_samples: 50,
            minimum_success_rate: 0.9,
            minimum_operator_acceptance_rate: 0.8,
            minimum_mean_quality: 0.8,
            maximum_quality_regression: 0.02,
            maximum_cost_per_success_usd_micros: 10_000.0,
            maximum_cost_increase_usd_micros: 1_000.0,
            maximum_p95_latency_ms: 750.0,
            maximum_latency_increase_ms: 100.0,
        }
    }

    fn active() -> ActiveAllocationPolicy {
        ActiveAllocationPolicy {
            active: snapshot("v1"),
            rollback: None,
            rollback_baseline: None,
            last_transition: None,
            changed_at_ms: 1,
        }
    }

    #[test]
    fn promotes_only_when_every_evaluation_dimension_passes() {
        let decision = evaluate_policy_candidate(
            &snapshot("v1"),
            &snapshot("v2"),
            &evaluation("v1"),
            &evaluation("v2"),
            &gate(),
        )
        .unwrap();
        assert_eq!(decision.transition, PolicyTransition::Promote);
        assert!(decision.reasons.is_empty());

        let promoted = apply_promotion(
            &active(),
            snapshot("v2"),
            evaluation("v1"),
            evaluation("v2"),
            &gate(),
            2,
        )
        .unwrap();
        assert_eq!(promoted.active.revision_id, "v2");
        assert_eq!(promoted.rollback.unwrap().revision_id, "v1");
    }

    #[test]
    fn hard_limit_failure_blocks_promotion_even_with_strong_outcomes() {
        let mut candidate = evaluation("v2");
        candidate.hard_limits.budget = false;
        let decision = evaluate_policy_candidate(
            &snapshot("v1"),
            &snapshot("v2"),
            &evaluation("v1"),
            &candidate,
            &gate(),
        )
        .unwrap();
        assert_eq!(decision.transition, PolicyTransition::Retain);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("hard-limit"))
        );
        assert!(
            apply_promotion(
                &active(),
                snapshot("v2"),
                evaluation("v1"),
                candidate,
                &gate(),
                2,
            )
            .unwrap_err()
            .contains("failed promotion gate")
        );
    }

    #[test]
    fn monitored_regression_automatically_restores_previous_snapshot() {
        let promoted = apply_promotion(
            &active(),
            snapshot("v2"),
            evaluation("v1"),
            evaluation("v2"),
            &gate(),
            2,
        )
        .unwrap();
        let mut regressed = evaluation("v2");
        regressed.successful_outcomes = 70;
        regressed.mean_quality = 0.7;

        let rolled_back = monitor_and_rollback(&promoted, &regressed, &gate(), 3).unwrap();
        assert_eq!(rolled_back.active.revision_id, "v1");
        assert_eq!(rolled_back.rollback.as_ref().unwrap().revision_id, "v2");
        assert_eq!(
            rolled_back
                .rollback_baseline
                .as_ref()
                .unwrap()
                .policy_revision_id,
            "v2"
        );
        assert_eq!(
            rolled_back.last_transition.unwrap().transition,
            PolicyTransition::Rollback
        );
    }

    #[test]
    fn healthy_monitoring_keeps_the_promoted_policy_active() {
        let promoted = apply_promotion(
            &active(),
            snapshot("v2"),
            evaluation("v1"),
            evaluation("v2"),
            &gate(),
            2,
        )
        .unwrap();
        let monitored = monitor_and_rollback(&promoted, &evaluation("v2"), &gate(), 3).unwrap();
        assert_eq!(monitored, promoted);
    }

    #[test]
    fn incomplete_healthy_monitoring_window_does_not_trigger_rollback() {
        let promoted = apply_promotion(
            &active(),
            snapshot("v2"),
            evaluation("v1"),
            evaluation("v2"),
            &gate(),
            2,
        )
        .unwrap();
        let mut incomplete = evaluation("v2");
        incomplete.samples = 10;
        incomplete.successful_outcomes = 10;
        incomplete.operator_acceptances = 10;
        let monitored = monitor_and_rollback(&promoted, &incomplete, &gate(), 3).unwrap();
        assert_eq!(monitored, promoted);
    }

    #[test]
    fn low_sample_monitoring_still_rolls_back_clear_regressions() {
        let promoted = apply_promotion(
            &active(),
            snapshot("v2"),
            evaluation("v1"),
            evaluation("v2"),
            &gate(),
            2,
        )
        .unwrap();
        let mut failing = evaluation("v2");
        failing.samples = 10;
        failing.successful_outcomes = 0;
        failing.operator_acceptances = 0;
        failing.mean_quality = 0.0;
        failing.p95_latency_ms = 1_000.0;
        let monitored = monitor_and_rollback(&promoted, &failing, &gate(), 3).unwrap();
        assert_eq!(monitored.active.revision_id, "v1");
        assert_eq!(
            monitored.last_transition.unwrap().transition,
            PolicyTransition::Rollback
        );
    }

    #[test]
    fn promotion_requires_a_safe_well_sampled_rollback_baseline() {
        let mut baseline = evaluation("v1");
        baseline.samples = 10;
        baseline.successful_outcomes = 10;
        baseline.operator_acceptances = 10;
        assert!(
            apply_promotion(
                &active(),
                snapshot("v2"),
                baseline,
                evaluation("v2"),
                &gate(),
                2,
            )
            .unwrap_err()
            .contains("failed promotion gate")
        );
    }

    #[test]
    fn monitoring_rejects_wrong_suite_even_before_sample_minimum() {
        let promoted = apply_promotion(
            &active(),
            snapshot("v2"),
            evaluation("v1"),
            evaluation("v2"),
            &gate(),
            2,
        )
        .unwrap();
        let mut observed = evaluation("v2");
        observed.suite_id = "other-suite".into();
        observed.samples = 1;
        observed.successful_outcomes = 1;
        observed.operator_acceptances = 1;
        assert_eq!(
            monitor_and_rollback(&promoted, &observed, &gate(), 3).unwrap_err(),
            "policy evaluations must use the gate's evaluation suite"
        );
    }

    #[test]
    fn persisted_policy_state_must_keep_rollback_artifacts_together() {
        let mut state = active();
        state.rollback = Some(snapshot("v0"));
        assert_eq!(
            state.validate().unwrap_err(),
            "rollback snapshot and evaluation baseline must be stored together"
        );
    }

    #[test]
    fn monitoring_cannot_substitute_a_different_gate_version() {
        let promoted = apply_promotion(
            &active(),
            snapshot("v2"),
            evaluation("v1"),
            evaluation("v2"),
            &gate(),
            2,
        )
        .unwrap();
        let mut changed_gate = gate();
        changed_gate.version = "2".into();
        changed_gate.minimum_mean_quality = 0.95;
        assert_eq!(
            monitor_and_rollback(&promoted, &evaluation("v2"), &changed_gate, 3).unwrap_err(),
            "monitoring must use the gate version that authorized promotion"
        );
    }
}
