//! Bounded automatic-dispatch authorization for Gunshi allocation plans.
//!
//! This module produces an authorization decision. It deliberately does not
//! own or invoke agent runtimes, tools, or workflow execution.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::chisei::gunshi::{
    AdvisoryScorecard, AllocationPlan, CapacityEnvelope, OperationRisk, PendingOperation,
    load_kioku_evidence,
};
use crate::chisei::receipt::ReceiptEventKind;
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoDispatchPolicy {
    pub policy_id: String,
    pub version: String,
    pub governance_policy_version: String,
    pub enabled: bool,
    pub allowed_namespaces: BTreeSet<String>,
    pub allowed_operation_classes: BTreeSet<String>,
    pub maximum_risk: OperationRisk,
    pub maximum_budget_usd_micros: i64,
    pub maximum_attempts: u32,
    pub require_governed_evidence: bool,
    pub maximum_evidence_age_ms: i64,
    pub minimum_evidence_score: f64,
    pub minimum_advisory_comparisons: usize,
    pub minimum_observed_outcomes: usize,
    pub minimum_operator_acceptance_rate: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchMode {
    AdvisoryOnly,
    Automatic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchAuthorization {
    pub allocation_id: String,
    pub operation_id: String,
    pub dispatch_policy_id: String,
    pub dispatch_policy_version: String,
    pub governance_policy_version: String,
    pub mode: DispatchMode,
    pub authorized: bool,
    pub reasons: Vec<String>,
}

impl AutoDispatchPolicy {
    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("dispatch policy id", self.policy_id.as_str()),
            ("dispatch policy version", self.version.as_str()),
            (
                "governance policy version",
                self.governance_policy_version.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} is required"));
            }
        }
        if self.allowed_namespaces.is_empty() || self.allowed_operation_classes.is_empty() {
            return Err(
                "automatic dispatch requires namespace and operation-class allowlists".into(),
            );
        }
        if self
            .allowed_operation_classes
            .iter()
            .any(|class| class.trim().is_empty() || class == "*")
        {
            return Err("automatic dispatch operation classes must be explicit".into());
        }
        if self
            .allowed_namespaces
            .iter()
            .any(|namespace| namespace.trim().is_empty() || namespace == "*")
        {
            return Err("automatic dispatch namespaces must be explicit".into());
        }
        if self.maximum_budget_usd_micros < 0 || self.maximum_attempts == 0 {
            return Err("automatic dispatch budget and attempt limits must be valid".into());
        }
        if self.maximum_risk != OperationRisk::Low {
            return Err("automatic dispatch is limited to low-risk operations".into());
        }
        if self.minimum_advisory_comparisons == 0 || self.minimum_observed_outcomes == 0 {
            return Err("automatic dispatch requires prior advisory calibration".into());
        }
        if self.maximum_evidence_age_ms < 0
            || !self.minimum_evidence_score.is_finite()
            || !(0.0..=1.0).contains(&self.minimum_evidence_score)
        {
            return Err("automatic dispatch evidence limits must be valid".into());
        }
        if !self.minimum_operator_acceptance_rate.is_finite()
            || !(0.0..=1.0).contains(&self.minimum_operator_acceptance_rate)
        {
            return Err("minimum operator acceptance rate must be between 0 and 1".into());
        }
        Ok(())
    }
}

pub fn authorize_dispatch(
    plan: &AllocationPlan,
    operation: &PendingOperation,
    capacity: &CapacityEnvelope,
    policy: &AutoDispatchPolicy,
    calibration: &AdvisoryScorecard,
    db: &RuntimeDb,
) -> Result<DispatchAuthorization, String> {
    plan.validate()?;
    operation.validate()?;
    capacity.validate()?;
    policy.validate()?;
    validate_scorecard(calibration)?;
    if plan.operation_id != operation.operation_id
        || plan.namespace != operation.namespace
        || plan.operation_class != operation.operation_class
    {
        return Err("allocation plan does not match the pending operation".into());
    }

    let mut reasons = Vec::new();
    if !policy.enabled {
        reasons.push("automatic dispatch is disabled".into());
    }
    if policy.governance_policy_version != plan.policy_version
        || capacity.policy_version != plan.policy_version
    {
        reasons.push("governance policy version does not match the allocation".into());
    }
    if !policy.allowed_namespaces.contains(&operation.namespace) {
        reasons.push("namespace is not approved for automatic dispatch".into());
    }
    if !policy
        .allowed_operation_classes
        .contains(&operation.operation_class)
    {
        reasons.push("operation class is not approved for automatic dispatch".into());
    }
    if operation.risk > policy.maximum_risk {
        reasons.push("operation risk exceeds the automatic-dispatch limit".into());
    }
    if operation.approval_required
        || operation.human_attention_minutes_required > 0
        || plan.verification.human_review_required
    {
        reasons.push("operation requires human approval or review".into());
    }
    if plan.verification.acceptance_criteria != operation.acceptance_criteria
        || !plan
            .verification
            .checks
            .iter()
            .any(|check| check == "operation_receipt_complete")
        || plan
            .verification
            .checks
            .iter()
            .any(|check| check.trim().is_empty())
    {
        reasons.push("allocation weakens the pending operation verification requirements".into());
    }
    if plan.budget_ceiling_usd_micros > policy.maximum_budget_usd_micros
        || plan.budget_ceiling_usd_micros > capacity.budget_remaining_usd_micros
        || plan.budget_ceiling_usd_micros > operation.budget_ceiling_usd_micros
    {
        reasons.push("allocation exceeds the automatic-dispatch budget envelope".into());
    }
    if plan.attempts.max_attempts > policy.maximum_attempts
        || plan.attempts.max_attempts > operation.max_attempts
        || plan.attempts.parallel_attempts > capacity.max_parallel_attempts
    {
        reasons.push("allocation exceeds the automatic-dispatch attempt envelope".into());
    }
    let live_total_cost = capacity
        .model_profiles
        .iter()
        .find(|profile| profile.model == plan.selection.model)
        .and_then(|profile| {
            profile
                .cost_per_attempt_usd_micros
                .checked_mul(i64::from(plan.attempts.max_attempts))
        });
    if !live_total_cost.is_some_and(|cost| {
        cost <= plan.budget_ceiling_usd_micros
            && cost <= plan.stop_conditions.max_cost_usd_micros
            && cost <= operation.budget_ceiling_usd_micros
            && cost <= policy.maximum_budget_usd_micros
            && cost <= capacity.budget_remaining_usd_micros
    }) {
        reasons.push("selected model exceeds the live dispatch budget envelope".into());
    }
    if policy.require_governed_evidence {
        let governed = load_kioku_evidence(db, &operation.namespace, &operation.operation_class)?;
        let mut has_governed_evidence = false;
        for reference in plan
            .evidence
            .iter()
            .filter(|reference| reference.kind == "kioku_memory")
        {
            for memory in governed
                .iter()
                .filter(|memory| memory.memory_id == reference.reference)
            {
                if memory.model == plan.selection.model
                    && memory.status == "active"
                    && memory.passed
                    && memory.score >= policy.minimum_evidence_score
                    && memory.observed_at_ms <= capacity.captured_at_ms
                    && capacity
                        .captured_at_ms
                        .saturating_sub(memory.observed_at_ms)
                        <= policy.maximum_evidence_age_ms
                    && dispatch_evidence_matches_receipt(db, memory)?
                {
                    has_governed_evidence = true;
                    break;
                }
            }
            if has_governed_evidence {
                break;
            }
        }
        if !has_governed_evidence {
            reasons.push("allocation lacks current governed recommendation evidence".into());
        }
    }
    let acceptance_rate = if calibration.comparisons == 0 {
        0.0
    } else {
        calibration.accepted as f64 / calibration.comparisons as f64
    };
    if calibration.comparisons < policy.minimum_advisory_comparisons
        || calibration.observed_outcomes < policy.minimum_observed_outcomes
        || acceptance_rate < policy.minimum_operator_acceptance_rate
    {
        reasons.push("advisory performance is not sufficiently calibrated".into());
    }
    let selected_tools = plan
        .selection
        .tools
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if selected_tools.len() != plan.selection.tools.len()
        || selected_tools != operation.required_tools
    {
        reasons.push("selected tools do not exactly match the pending operation".into());
    }
    let agent_available = capacity.agents.iter().any(|agent| {
        agent.agent_id == plan.selection.agent_id
            && agent.runtime == plan.selection.runtime
            && agent.healthy
            && agent.available_slots >= plan.attempts.parallel_attempts
            && agent.models.contains(&plan.selection.model)
            && (operation.allowed_models.is_empty()
                || operation.allowed_models.contains(&plan.selection.model))
            && selected_tools.is_subset(&agent.tools)
            && (agent.operation_classes.contains(&operation.operation_class)
                || agent.operation_classes.contains("*"))
    });
    if !agent_available {
        reasons.push("selected agent capacity is no longer available".into());
    }

    let authorized = reasons.is_empty();
    Ok(DispatchAuthorization {
        allocation_id: plan.allocation_id.clone(),
        operation_id: plan.operation_id.clone(),
        dispatch_policy_id: policy.policy_id.clone(),
        dispatch_policy_version: policy.version.clone(),
        governance_policy_version: plan.policy_version.clone(),
        mode: if authorized {
            DispatchMode::Automatic
        } else {
            DispatchMode::AdvisoryOnly
        },
        authorized,
        reasons,
    })
}

fn dispatch_evidence_matches_receipt(
    db: &RuntimeDb,
    evidence: &crate::chisei::gunshi::KiokuEvidence,
) -> Result<bool, String> {
    let Some(request_id) = evidence.receipt_reference.as_deref() else {
        return Ok(false);
    };
    let Some(receipt) = db.find_operation_receipt_by_request_id(request_id)? else {
        return Ok(false);
    };
    if !receipt.completeness().complete
        || receipt.completed_at_ms.is_none()
        || receipt.namespace != evidence.namespace
        || receipt.operation_class != evidence.operation_class
    {
        return Ok(false);
    }
    let routed_model = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::RouteSelected)
        .and_then(|event| {
            event
                .attributes
                .get("resolved_model")
                .or_else(|| event.attributes.get("model"))
        });
    let outcome = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded);
    let recorded_passed = outcome
        .and_then(|event| event.attributes.get("passed"))
        .and_then(|value| value.parse::<bool>().ok());
    let recorded_score = outcome
        .and_then(|event| event.attributes.get("score"))
        .and_then(|value| value.parse::<f64>().ok())
        .map(|score| score / 100.0);
    Ok(routed_model.is_some_and(|model| model == &evidence.model)
        && recorded_passed == Some(evidence.passed)
        && recorded_score.is_some_and(|score| (score - evidence.score).abs() < f64::EPSILON))
}

fn validate_scorecard(scorecard: &AdvisoryScorecard) -> Result<(), String> {
    let classified = scorecard
        .accepted
        .checked_add(scorecard.modified)
        .and_then(|count| count.checked_add(scorecard.rejected));
    if classified != Some(scorecard.comparisons)
        || scorecard.observed_outcomes > scorecard.comparisons
    {
        return Err("advisory scorecard counts are inconsistent".into());
    }
    if !scorecard.resource_selection_agreement_rate.is_finite()
        || !(0.0..=1.0).contains(&scorecard.resource_selection_agreement_rate)
    {
        return Err("advisory scorecard agreement rate must be between 0 and 1".into());
    }
    let errors = [
        scorecard.mean_absolute_quality_error,
        scorecard.mean_absolute_cost_error_usd_micros,
        scorecard.mean_absolute_latency_error_ms,
    ];
    if errors
        .iter()
        .flatten()
        .any(|value| !value.is_finite() || *value < 0.0)
        || (scorecard.observed_outcomes == 0 && errors.iter().any(Option::is_some))
        || (scorecard.observed_outcomes > 0 && errors.iter().any(Option::is_none))
    {
        return Err("advisory scorecard prediction errors are inconsistent".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::gunshi::{
        AdvisoryPolicy, AgentCapacity, AllocationRequest, BaselineStrategy, EvidenceReference,
        ModelProfile, Strategy, recommend_advisory,
    };
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    };
    use crate::domain::Object;
    use std::collections::{BTreeMap, HashMap};

    fn operation() -> PendingOperation {
        PendingOperation {
            operation_id: "op-1".into(),
            namespace: "support".into(),
            operation_class: "triage".into(),
            priority: 80,
            risk: OperationRisk::Low,
            submitted_at_ms: 1,
            required_tools: BTreeSet::from(["search".into()]),
            allowed_models: BTreeSet::from(["local".into()]),
            max_attempts: 1,
            budget_ceiling_usd_micros: 10_000,
            acceptance_criteria: vec!["classified".into()],
            approval_required: false,
            human_attention_minutes_required: 0,
        }
    }

    fn capacity() -> CapacityEnvelope {
        CapacityEnvelope {
            captured_at_ms: 2_000,
            policy_version: "governance-v1".into(),
            agents: vec![AgentCapacity {
                agent_id: "agent-1".into(),
                runtime: "native".into(),
                models: BTreeSet::from(["local".into()]),
                tools: BTreeSet::from(["search".into()]),
                operation_classes: BTreeSet::from(["triage".into()]),
                available_slots: 1,
                healthy: true,
            }],
            model_profiles: vec![ModelProfile {
                model: "local".into(),
                quality: 0.8,
                cost_per_attempt_usd_micros: 5_000,
                latency_ms: 100,
                uncertainty: 0.1,
            }],
            budget_remaining_usd_micros: 10_000,
            max_parallel_attempts: 1,
            human_attention_minutes: 0,
        }
    }

    fn plan() -> AllocationPlan {
        let request = AllocationRequest {
            capacity: capacity(),
            operations: vec![operation()],
            strategy: Strategy {
                strategy_id: "baseline".into(),
                version: "1".into(),
                baseline: BaselineStrategy::Conservative,
            },
        };
        let mut plan = recommend_advisory(
            &request,
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
        plan.evidence.push(EvidenceReference {
            kind: "kioku_memory".into(),
            reference: "memory-1".into(),
            reason: "calibrated local strategy".into(),
        });
        plan
    }

    fn policy() -> AutoDispatchPolicy {
        AutoDispatchPolicy {
            policy_id: "auto-low-risk".into(),
            version: "1".into(),
            governance_policy_version: "governance-v1".into(),
            enabled: true,
            allowed_namespaces: BTreeSet::from(["support".into()]),
            allowed_operation_classes: BTreeSet::from(["triage".into()]),
            maximum_risk: OperationRisk::Low,
            maximum_budget_usd_micros: 10_000,
            maximum_attempts: 1,
            require_governed_evidence: true,
            maximum_evidence_age_ms: 1_000,
            minimum_evidence_score: 0.8,
            minimum_advisory_comparisons: 10,
            minimum_observed_outcomes: 5,
            minimum_operator_acceptance_rate: 0.8,
        }
    }

    fn db() -> RuntimeDb {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        db.create_object(&Object {
            id: "memory-1".into(),
            kind: crate::domain::KIND_LEARNING.into(),
            name: "Fleet evidence".into(),
            namespace: "support".into(),
            external_id: "memory-1".into(),
            properties: HashMap::from([
                ("task_class".into(), "triage".into()),
                ("model".into(), "local".into()),
                ("score".into(), "90".into()),
                ("passed".into(), "true".into()),
                ("status".into(), "active".into()),
                ("source_request_id".into(), "receipt-1".into()),
            ]),
            created: 1,
            updated: 2,
        })
        .unwrap();
        let event =
            |id: &str,
             parent: Option<&str>,
             kind: ReceiptEventKind,
             attributes: BTreeMap<String, String>| OperationReceiptEvent {
                event_id: id.into(),
                operation_id: "receipt-op-1".into(),
                parent_event_id: parent.map(str::to_string),
                timestamp_ms: 1,
                kind,
                surface: kind.surface(),
                actor: "agent:test".into(),
                references: Vec::new(),
                attributes,
            };
        db.put_operation_receipt(&OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "receipt-op-1".into(),
            parent_operation_id: None,
            namespace: "support".into(),
            operation_class: "triage".into(),
            initiating_actor: "agent:test".into(),
            schema_version: "schema-v1".into(),
            policy_version: "governance-v1".into(),
            started_at_ms: 1,
            completed_at_ms: Some(2),
            events: vec![
                event(
                    "intent",
                    None,
                    ReceiptEventKind::IntentRecorded,
                    BTreeMap::from([("request_id".into(), "receipt-1".into())]),
                ),
                event(
                    "policy",
                    Some("intent"),
                    ReceiptEventKind::PolicyDecided,
                    BTreeMap::new(),
                ),
                event(
                    "route",
                    Some("policy"),
                    ReceiptEventKind::RouteSelected,
                    BTreeMap::from([("resolved_model".into(), "local".into())]),
                ),
                event(
                    "budget",
                    Some("route"),
                    ReceiptEventKind::BudgetDecided,
                    BTreeMap::new(),
                ),
                event(
                    "outcome",
                    Some("budget"),
                    ReceiptEventKind::OutcomeRecorded,
                    BTreeMap::from([
                        ("passed".into(), "true".into()),
                        ("score".into(), "90".into()),
                    ]),
                ),
            ],
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
        })
        .unwrap();
        db
    }

    fn calibrated() -> AdvisoryScorecard {
        AdvisoryScorecard {
            comparisons: 10,
            accepted: 9,
            modified: 1,
            rejected: 0,
            resource_selection_agreement_rate: 0.9,
            observed_outcomes: 10,
            mean_absolute_quality_error: Some(0.05),
            mean_absolute_cost_error_usd_micros: Some(500.0),
            mean_absolute_latency_error_ms: Some(20.0),
        }
    }

    #[test]
    fn calibrated_low_risk_allocation_can_be_authorized() {
        let decision = authorize_dispatch(
            &plan(),
            &operation(),
            &capacity(),
            &policy(),
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(decision.authorized);
        assert_eq!(decision.mode, DispatchMode::Automatic);
        assert!(decision.reasons.is_empty());
    }

    #[test]
    fn human_review_and_high_risk_force_advisory_mode() {
        let plan = plan();
        let mut high_risk_operation = operation();
        high_risk_operation.risk = OperationRisk::High;
        let decision = authorize_dispatch(
            &plan,
            &high_risk_operation,
            &capacity(),
            &policy(),
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("risk"))
        );

        let mut review_plan = plan;
        review_plan.verification.human_review_required = true;
        let decision = authorize_dispatch(
            &review_plan,
            &operation(),
            &capacity(),
            &policy(),
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("human"))
        );
    }

    #[test]
    fn policy_cannot_expand_automatic_dispatch_beyond_low_risk() {
        let mut policy = policy();
        policy.maximum_risk = OperationRisk::Medium;
        assert_eq!(
            policy.validate().unwrap_err(),
            "automatic dispatch is limited to low-risk operations"
        );
    }

    #[test]
    fn missing_calibration_or_evidence_prevents_automatic_dispatch() {
        let mut plan = plan();
        plan.evidence.clear();
        let mut calibration = calibrated();
        calibration.comparisons = 2;
        calibration.accepted = 1;
        calibration.observed_outcomes = 2;
        let decision = authorize_dispatch(
            &plan,
            &operation(),
            &capacity(),
            &policy(),
            &calibration,
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert_eq!(decision.mode, DispatchMode::AdvisoryOnly);
        assert_eq!(decision.reasons.len(), 2);
    }

    #[test]
    fn forgeable_evidence_markers_do_not_unlock_automatic_dispatch() {
        let mut plan = plan();
        plan.evidence[0].reference = "not-a-governed-memory".into();
        let decision = authorize_dispatch(
            &plan,
            &operation(),
            &capacity(),
            &policy(),
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("governed"))
        );
    }

    #[test]
    fn malformed_calibration_is_rejected_before_authorization() {
        let mut calibration = calibrated();
        calibration.accepted = 100;
        assert_eq!(
            authorize_dispatch(
                &plan(),
                &operation(),
                &capacity(),
                &policy(),
                &calibration,
                &db(),
            )
            .unwrap_err(),
            "advisory scorecard counts are inconsistent"
        );
    }

    #[test]
    fn governance_version_and_live_capacity_are_hard_limits() {
        let mut capacity = capacity();
        capacity.policy_version = "governance-v2".into();
        capacity.agents[0].available_slots = 0;
        let decision = authorize_dispatch(
            &plan(),
            &operation(),
            &capacity,
            &policy(),
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("version"))
        );
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("no longer available"))
        );
    }

    #[test]
    fn operation_budget_and_attempt_limits_are_rechecked_at_dispatch() {
        let mut plan = plan();
        plan.attempts.max_attempts = 2;
        plan.stop_conditions.max_attempts = 2;
        plan.budget_ceiling_usd_micros = 20_000;
        plan.stop_conditions.max_cost_usd_micros = 20_000;
        let mut policy = policy();
        policy.maximum_attempts = 2;
        policy.maximum_budget_usd_micros = 20_000;
        let mut capacity = capacity();
        capacity.max_parallel_attempts = 2;
        capacity.budget_remaining_usd_micros = 20_000;

        let decision = authorize_dispatch(
            &plan,
            &operation(),
            &capacity,
            &policy,
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("budget"))
        );
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("attempt"))
        );
    }

    #[test]
    fn selected_tools_must_exactly_match_the_pending_operation() {
        let mut plan = plan();
        plan.selection.tools.push("shell".into());
        let mut capacity = capacity();
        capacity.agents[0].tools.insert("shell".into());

        let decision = authorize_dispatch(
            &plan,
            &operation(),
            &capacity,
            &policy(),
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("tools"))
        );
    }

    #[test]
    fn parallel_attempts_cannot_exceed_selected_agent_slots() {
        let mut plan = plan();
        plan.attempts.max_attempts = 2;
        plan.attempts.parallel_attempts = 2;
        plan.stop_conditions.max_attempts = 2;
        let mut operation = operation();
        operation.max_attempts = 2;
        let mut policy = policy();
        policy.maximum_attempts = 2;
        let mut capacity = capacity();
        capacity.max_parallel_attempts = 2;

        let decision =
            authorize_dispatch(&plan, &operation, &capacity, &policy, &calibrated(), &db())
                .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("no longer available"))
        );
    }

    #[test]
    fn verification_requirements_cannot_be_weakened_at_dispatch() {
        let mut plan = plan();
        plan.verification.acceptance_criteria.clear();
        plan.verification.checks.clear();
        let decision = authorize_dispatch(
            &plan,
            &operation(),
            &capacity(),
            &policy(),
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("verification"))
        );
    }

    #[test]
    fn live_model_cost_is_rechecked_at_dispatch() {
        let mut capacity = capacity();
        capacity.model_profiles[0].cost_per_attempt_usd_micros = 11_000;
        let decision = authorize_dispatch(
            &plan(),
            &operation(),
            &capacity,
            &policy(),
            &calibrated(),
            &db(),
        )
        .unwrap();
        assert!(!decision.authorized);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("live dispatch budget"))
        );
    }
}
