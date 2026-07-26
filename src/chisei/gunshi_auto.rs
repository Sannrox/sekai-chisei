//! Durable eval-gated promotion and bounded Gunshi auto-dispatch control.
//!
//! Builds on pure promotion logic in [`crate::chisei::gunshi_policy`] and
//! authorization in [`crate::chisei::gunshi_dispatch`]. Default posture is
//! advisory-only until a promoted revision is installed **and** the namespace
//! opts in; a kill switch immediately forces advisory mode.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::chisei::gunshi::{AllocationPlan, CapacityEnvelope, PendingOperation};
use crate::chisei::gunshi_dispatch::{
    AutoDispatchPolicy, DispatchAuthorization, DispatchMode, authorize_dispatch,
};
use crate::chisei::gunshi_feedback::advisory_scorecard;
use crate::chisei::gunshi_policy::{
    ActiveAllocationPolicy, AllocationPolicySnapshot, PolicyEvaluation, PolicyEvaluationGate,
    PolicyTransition, PolicyTransitionDecision, apply_promotion, monitor_and_rollback,
};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::Decision;

pub const STATE_CONTRACT_VERSION: &str = "gunshi.allocation-control/v1";
pub const AUDIT_PROMOTE: &str = "gunshi.allocation_policy.promote";
pub const AUDIT_ROLLBACK: &str = "gunshi.allocation_policy.rollback";
pub const AUDIT_INSTALL: &str = "gunshi.allocation_policy.install";
pub const AUDIT_OPT_IN: &str = "gunshi.allocation_policy.auto_opt_in";
pub const AUDIT_KILL: &str = "gunshi.allocation_policy.kill_switch";
/// Minimum wall-clock gap between promotions for a namespace (anti-thrash).
pub const PROMOTE_COOLDOWN_MS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamespaceAllocationState {
    pub contract_version: String,
    pub namespace: String,
    pub policy: ActiveAllocationPolicy,
    pub gate: PolicyEvaluationGate,
    /// Namespace must explicitly opt in after a revision is promoted.
    pub auto_opt_in: bool,
    /// When true, force advisory regardless of revision or opt-in.
    pub kill_switch: bool,
    pub kill_switch_reason: String,
    pub last_gate_result: Option<PolicyTransitionDecision>,
    /// Evaluation that authorized the current active revision (when promoted).
    #[serde(default)]
    pub last_promoted_evaluation: Option<PolicyEvaluation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamespaceAllocationStatus {
    pub namespace: String,
    pub active_revision_id: String,
    pub rollback_revision_id: Option<String>,
    pub auto_opt_in: bool,
    pub kill_switch: bool,
    pub kill_switch_reason: String,
    pub auto_dispatch_live: bool,
    pub last_gate_result: Option<PolicyTransitionDecision>,
    pub changed_at_ms: i64,
    pub gate_id: String,
    pub gate_version: String,
}

impl NamespaceAllocationState {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != STATE_CONTRACT_VERSION {
            return Err(format!(
                "unsupported allocation control contract {}",
                self.contract_version
            ));
        }
        required("namespace", &self.namespace)?;
        self.policy.validate()?;
        self.gate.validate()?;
        if !self
            .policy
            .active
            .dispatch
            .allowed_namespaces
            .contains(&self.namespace)
        {
            return Err("active dispatch policy must allow the owning namespace".into());
        }
        Ok(())
    }

    pub fn auto_dispatch_live(&self) -> bool {
        self.auto_opt_in
            && !self.kill_switch
            && self.policy.active.dispatch.enabled
            && self
                .policy
                .active
                .dispatch
                .allowed_namespaces
                .contains(&self.namespace)
    }

    pub fn status(&self) -> NamespaceAllocationStatus {
        NamespaceAllocationStatus {
            namespace: self.namespace.clone(),
            active_revision_id: self.policy.active.revision_id.clone(),
            rollback_revision_id: self
                .policy
                .rollback
                .as_ref()
                .map(|snapshot| snapshot.revision_id.clone()),
            auto_opt_in: self.auto_opt_in,
            kill_switch: self.kill_switch,
            kill_switch_reason: self.kill_switch_reason.clone(),
            auto_dispatch_live: self.auto_dispatch_live(),
            last_gate_result: self.last_gate_result.clone(),
            changed_at_ms: self.policy.changed_at_ms,
            gate_id: self.gate.gate_id.clone(),
            gate_version: self.gate.version.clone(),
        }
    }

    fn effective_dispatch_policy(&self) -> AutoDispatchPolicy {
        let mut policy = self.policy.active.dispatch.clone();
        policy.enabled = self.auto_dispatch_live();
        policy
    }
}

pub fn load_state(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<Option<NamespaceAllocationState>, String> {
    required("namespace", namespace)?;
    let Some(json) = db.get_gunshi_allocation_state(namespace)? else {
        return Ok(None);
    };
    let state: NamespaceAllocationState =
        serde_json::from_str(&json).map_err(|error| format!("decode allocation state: {error}"))?;
    state.validate()?;
    if state.namespace != namespace {
        return Err("stored allocation state namespace does not match key".into());
    }
    Ok(Some(state))
}

pub fn get_status(
    db: &RuntimeDb,
    namespace: &str,
) -> Result<Option<NamespaceAllocationStatus>, String> {
    Ok(load_state(db, namespace)?.map(|state| state.status()))
}

/// Install the first advisory baseline for a namespace. Auto-dispatch remains off.
pub fn install_baseline(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    mut snapshot: AllocationPolicySnapshot,
    gate: PolicyEvaluationGate,
    now_ms: i64,
) -> Result<NamespaceAllocationStatus, String> {
    required("actor", actor)?;
    required("namespace", namespace)?;
    if now_ms < 0 {
        return Err("timestamp must be non-negative".into());
    }
    // Baseline must not enable auto-dispatch by default.
    snapshot.dispatch.enabled = false;
    snapshot.validate()?;
    gate.validate()?;
    if !snapshot.dispatch.allowed_namespaces.contains(namespace) {
        return Err("baseline dispatch policy must allow the target namespace".into());
    }
    if load_state(db, namespace)?.is_some() {
        return Err("namespace already has an allocation policy revision".into());
    }
    let state = NamespaceAllocationState {
        contract_version: STATE_CONTRACT_VERSION.into(),
        namespace: namespace.into(),
        policy: ActiveAllocationPolicy {
            active: snapshot,
            rollback: None,
            rollback_baseline: None,
            last_transition: None,
            changed_at_ms: now_ms,
        },
        gate,
        auto_opt_in: false,
        kill_switch: false,
        kill_switch_reason: String::new(),
        last_gate_result: None,
        last_promoted_evaluation: None,
    };
    state.validate()?;
    persist(db, &state, None)?;
    audit(
        db,
        actor,
        AUDIT_INSTALL,
        &state,
        "installed advisory baseline allocation policy",
        "installed",
        now_ms,
    )?;
    Ok(state.status())
}

#[derive(Debug, Clone)]
pub struct PromoteRequest {
    pub actor: String,
    pub namespace: String,
    pub candidate: AllocationPolicySnapshot,
    pub baseline: PolicyEvaluation,
    pub candidate_evaluation: PolicyEvaluation,
    pub expected_revision: String,
    pub now_ms: i64,
}

pub fn promote(
    db: &RuntimeDb,
    request: PromoteRequest,
) -> Result<NamespaceAllocationStatus, String> {
    required("actor", &request.actor)?;
    let mut state = load_state(db, &request.namespace)?
        .ok_or_else(|| "namespace has no installed allocation policy baseline".to_string())?;
    if state.policy.active.revision_id != request.expected_revision {
        return Err(format!(
            "allocation policy revision race: expected {}, found {}",
            request.expected_revision, state.policy.active.revision_id
        ));
    }
    if request.now_ms < state.policy.changed_at_ms + PROMOTE_COOLDOWN_MS {
        return Err(format!(
            "promotion cooldown active until {}",
            state.policy.changed_at_ms + PROMOTE_COOLDOWN_MS
        ));
    }
    if !request
        .candidate
        .dispatch
        .allowed_namespaces
        .contains(&state.namespace)
    {
        return Err("candidate dispatch policy must allow the owning namespace".into());
    }
    // Promotion must not silently expand wildcards; validate() already rejects *.
    let promoted = apply_promotion(
        &state.policy,
        request.candidate,
        request.baseline,
        request.candidate_evaluation.clone(),
        &state.gate,
        request.now_ms,
    )?;
    let previous = state.policy.active.revision_id.clone();
    state.policy = promoted;
    state.last_gate_result = state.policy.last_transition.clone();
    state.last_promoted_evaluation = Some(request.candidate_evaluation);
    // Promote does not auto-enable live dispatch; opt-in remains explicit.
    state.validate()?;
    if !persist(db, &state, Some(&previous))? {
        return Err("allocation policy revision race during promote".into());
    }
    audit(
        db,
        &request.actor,
        AUDIT_PROMOTE,
        &state,
        "promoted allocation policy revision under evaluation gate",
        "promoted",
        request.now_ms,
    )?;
    Ok(state.status())
}

pub fn rollback(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    expected_revision: &str,
    reason: &str,
    now_ms: i64,
) -> Result<NamespaceAllocationStatus, String> {
    required("actor", actor)?;
    required("reason", reason)?;
    let mut state = load_state(db, namespace)?
        .ok_or_else(|| "namespace has no installed allocation policy".to_string())?;
    if state.policy.active.revision_id != expected_revision {
        return Err(format!(
            "allocation policy revision race: expected {}, found {}",
            expected_revision, state.policy.active.revision_id
        ));
    }
    if now_ms < state.policy.changed_at_ms {
        return Err("policy transition timestamp cannot move backward".into());
    }
    let Some(rollback_snapshot) = state.policy.rollback.clone() else {
        return Err("active policy has no rollback snapshot".into());
    };
    let Some(demoted_evaluation) =
        state.last_promoted_evaluation.clone().or_else(|| {
            state.policy.rollback_baseline.clone().filter(|evaluation| {
                evaluation.policy_revision_id == state.policy.active.revision_id
            })
        })
    else {
        return Err(
            "manual rollback requires the evaluation that authorized the active revision".into(),
        );
    };
    if demoted_evaluation.policy_revision_id != state.policy.active.revision_id {
        return Err("stored promotion evaluation does not match the active revision".into());
    }
    let from = state.policy.active.revision_id.clone();
    let decision = PolicyTransitionDecision {
        gate_id: state.gate.gate_id.clone(),
        gate_version: state.gate.version.clone(),
        from_revision_id: from.clone(),
        evaluated_revision_id: from.clone(),
        transition: PolicyTransition::Rollback,
        reasons: vec![reason.into()],
        evidence_references: demoted_evaluation.evidence_references.clone(),
    };
    // Demoted revision becomes the rollback target with its evaluation as baseline.
    state.policy = ActiveAllocationPolicy {
        active: rollback_snapshot,
        rollback: Some(state.policy.active.clone()),
        rollback_baseline: Some(demoted_evaluation),
        last_transition: Some(decision.clone()),
        changed_at_ms: now_ms,
    };
    state.last_gate_result = Some(decision);
    state.last_promoted_evaluation = None;
    // Manual rollback disables live auto until re-opt-in.
    state.auto_opt_in = false;
    state.validate()?;
    if !persist(db, &state, Some(&from))? {
        return Err("allocation policy revision race during rollback".into());
    }
    audit(
        db,
        actor,
        AUDIT_ROLLBACK,
        &state,
        reason,
        "rolled_back",
        now_ms,
    )?;
    Ok(state.status())
}

/// Monitor live outcomes and auto-rollback when the promotion gate regresses.
pub fn monitor(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    observed: PolicyEvaluation,
    expected_revision: &str,
    now_ms: i64,
) -> Result<NamespaceAllocationStatus, String> {
    required("actor", actor)?;
    let mut state = load_state(db, namespace)?
        .ok_or_else(|| "namespace has no installed allocation policy".to_string())?;
    if state.policy.active.revision_id != expected_revision {
        return Err(format!(
            "allocation policy revision race: expected {}, found {}",
            expected_revision, state.policy.active.revision_id
        ));
    }
    let previous = state.policy.active.revision_id.clone();
    let previous_changed = state.policy.changed_at_ms;
    let next = monitor_and_rollback(&state.policy, &observed, &state.gate, now_ms)?;
    let rolled = next.active.revision_id != previous;
    let changed = rolled || next.changed_at_ms != previous_changed;
    state.policy = next;
    state.last_gate_result = state.policy.last_transition.clone();
    if rolled {
        state.auto_opt_in = false;
    }
    state.validate()?;
    if changed {
        if !persist(db, &state, Some(&previous))? {
            return Err("allocation policy revision race during monitor".into());
        }
        if rolled {
            audit(
                db,
                actor,
                AUDIT_ROLLBACK,
                &state,
                "automatic rollback after evaluation regression",
                "rolled_back",
                now_ms,
            )?;
        }
    }
    Ok(state.status())
}

pub fn set_auto_opt_in(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    opt_in: bool,
    expected_revision: &str,
    now_ms: i64,
) -> Result<NamespaceAllocationStatus, String> {
    required("actor", actor)?;
    let mut state = load_state(db, namespace)?
        .ok_or_else(|| "namespace has no installed allocation policy".to_string())?;
    if state.policy.active.revision_id != expected_revision {
        return Err(format!(
            "allocation policy revision race: expected {}, found {}",
            expected_revision, state.policy.active.revision_id
        ));
    }
    if opt_in {
        if state.kill_switch {
            return Err("cannot opt into auto-dispatch while the kill switch is active".into());
        }
        if !state.policy.active.dispatch.enabled {
            return Err(
                "active revision does not enable automatic dispatch; promote a revision that sets dispatch.enabled=true first"
                    .into(),
            );
        }
        if state.policy.rollback.is_none() {
            return Err(
                "auto-dispatch opt-in requires a promoted revision with a rollback snapshot".into(),
            );
        }
    }
    let previous = state.policy.active.revision_id.clone();
    state.auto_opt_in = opt_in;
    // Bump changed_at for operator visibility without changing revision id.
    if now_ms > state.policy.changed_at_ms {
        state.policy.changed_at_ms = now_ms;
    }
    state.validate()?;
    if !persist(db, &state, Some(&previous))? {
        return Err("allocation policy revision race during auto opt-in".into());
    }
    audit(
        db,
        actor,
        AUDIT_OPT_IN,
        &state,
        if opt_in {
            "namespace opted into bounded auto-dispatch"
        } else {
            "namespace opted out of auto-dispatch"
        },
        if opt_in { "opted_in" } else { "opted_out" },
        now_ms,
    )?;
    Ok(state.status())
}

pub fn set_kill_switch(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    enabled: bool,
    reason: &str,
    now_ms: i64,
) -> Result<NamespaceAllocationStatus, String> {
    required("actor", actor)?;
    if enabled {
        required("reason", reason)?;
    }
    let mut state = load_state(db, namespace)?
        .ok_or_else(|| "namespace has no installed allocation policy".to_string())?;
    let previous = state.policy.active.revision_id.clone();
    state.kill_switch = enabled;
    state.kill_switch_reason = if enabled {
        reason.into()
    } else {
        String::new()
    };
    if enabled {
        state.auto_opt_in = false;
    }
    if now_ms > state.policy.changed_at_ms {
        state.policy.changed_at_ms = now_ms;
    }
    state.validate()?;
    if !persist(db, &state, Some(&previous))? {
        return Err("allocation policy revision race during kill switch".into());
    }
    audit(
        db,
        actor,
        AUDIT_KILL,
        &state,
        if enabled {
            reason
        } else {
            "kill switch cleared"
        },
        if enabled {
            "kill_switch_on"
        } else {
            "kill_switch_off"
        },
        now_ms,
    )?;
    Ok(state.status())
}

/// Authorize auto-dispatch for a plan under the durable namespace control plane.
pub fn authorize_namespace_auto_dispatch(
    db: &RuntimeDb,
    namespace: &str,
    plan: &AllocationPlan,
    operation: &PendingOperation,
    capacity: &CapacityEnvelope,
) -> Result<(DispatchAuthorization, BTreeMap<String, String>), String> {
    required("namespace", namespace)?;
    if plan.namespace != namespace || operation.namespace != namespace {
        return Err("plan and operation must match the target namespace".into());
    }
    let Some(state) = load_state(db, namespace)? else {
        return Ok((
            DispatchAuthorization {
                allocation_id: plan.allocation_id.clone(),
                operation_id: plan.operation_id.clone(),
                dispatch_policy_id: String::new(),
                dispatch_policy_version: String::new(),
                governance_policy_version: plan.policy_version.clone(),
                mode: DispatchMode::AdvisoryOnly,
                authorized: false,
                reasons: vec!["namespace has no promoted allocation policy".into()],
            },
            receipt_attributes(false, plan, None, None, &[]),
        ));
    };
    let calibration = advisory_scorecard(db, namespace)?;
    let policy = state.effective_dispatch_policy();
    let decision = authorize_dispatch(plan, operation, capacity, &policy, &calibration, db)?;
    let attrs = receipt_attributes(
        decision.authorized,
        plan,
        Some(&state),
        Some(&decision),
        &decision.reasons,
    );
    Ok((decision, attrs))
}

pub fn receipt_attributes(
    auto_authorized: bool,
    plan: &AllocationPlan,
    state: Option<&NamespaceAllocationState>,
    decision: Option<&DispatchAuthorization>,
    reasons: &[String],
) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::from([
        (
            "auto_dispatch".into(),
            if auto_authorized {
                "true".into()
            } else {
                "false".into()
            },
        ),
        ("gunshi_allocation_id".into(), plan.allocation_id.clone()),
        ("operation_id".into(), plan.operation_id.clone()),
    ]);
    if let Some(state) = state {
        attrs.insert(
            "allocation_policy_revision".into(),
            state.policy.active.revision_id.clone(),
        );
        attrs.insert("promotion_gate_id".into(), state.gate.gate_id.clone());
        attrs.insert("gate_version".into(), state.gate.version.clone());
        attrs.insert(
            "auto_opt_in".into(),
            if state.auto_opt_in {
                "true".into()
            } else {
                "false".into()
            },
        );
        attrs.insert(
            "kill_switch".into(),
            if state.kill_switch {
                "true".into()
            } else {
                "false".into()
            },
        );
    }
    if let Some(decision) = decision {
        attrs.insert(
            "dispatch_policy_id".into(),
            decision.dispatch_policy_id.clone(),
        );
        attrs.insert(
            "dispatch_policy_version".into(),
            decision.dispatch_policy_version.clone(),
        );
        attrs.insert(
            "dispatch_mode".into(),
            match decision.mode {
                DispatchMode::Automatic => "automatic".into(),
                DispatchMode::AdvisoryOnly => "advisory_only".into(),
            },
        );
    }
    if !reasons.is_empty() {
        attrs.insert("dispatch_denial_reasons".into(), reasons.join("; "));
    }
    attrs
}

fn persist(
    db: &RuntimeDb,
    state: &NamespaceAllocationState,
    expected_revision: Option<&str>,
) -> Result<bool, String> {
    let json = serde_json::to_string(state)
        .map_err(|error| format!("encode allocation state: {error}"))?;
    db.put_gunshi_allocation_state_cas(
        &state.namespace,
        &state.policy.active.revision_id,
        state.policy.changed_at_ms,
        &json,
        expected_revision,
    )
}

fn audit(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    state: &NamespaceAllocationState,
    reason: &str,
    outcome: &str,
    now_ms: i64,
) -> Result<(), String> {
    let status_json = serde_json::to_string(&state.status())
        .map_err(|error| format!("encode allocation status: {error}"))?;
    let decision = Decision {
        id: format!(
            "gunshi-alloc:{}:{}:{}:{}",
            state.namespace, action, state.policy.active.revision_id, now_ms
        ),
        timestamp: now_ms,
        actor: actor.into(),
        action: action.into(),
        reason: reason.into(),
        evidence: std::collections::HashMap::from([
            ("namespace".into(), state.namespace.clone()),
            ("data_class".into(), "internal".into()),
            (
                "revision_id".into(),
                state.policy.active.revision_id.clone(),
            ),
            ("status_json".into(), status_json),
            (
                "auto_dispatch_live".into(),
                state.auto_dispatch_live().to_string(),
            ),
        ]),
        target_id: state.namespace.clone(),
        outcome: outcome.into(),
    };
    db.record_decision(&decision)
}

fn required(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use crate::chisei::gunshi::OperationRisk;
    use crate::chisei::gunshi_dispatch::AutoDispatchPolicy;
    use crate::chisei::gunshi_optimization::OptimizationPolicy;
    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn snapshot(revision: &str, enabled: bool) -> AllocationPolicySnapshot {
        AllocationPolicySnapshot {
            revision_id: revision.into(),
            governance_policy_version: "governance-v1".into(),
            dispatch: AutoDispatchPolicy {
                policy_id: "auto-low-risk".into(),
                version: revision.into(),
                governance_policy_version: "governance-v1".into(),
                enabled,
                allowed_namespaces: BTreeSet::from(["support".into()]),
                allowed_operation_classes: BTreeSet::from(["triage".into()]),
                maximum_risk: OperationRisk::Low,
                maximum_budget_usd_micros: 10_000,
                maximum_attempts: 2,
                require_governed_evidence: false,
                maximum_evidence_age_ms: 86_400_000,
                minimum_evidence_score: 0.0,
                minimum_advisory_comparisons: 1,
                minimum_observed_outcomes: 1,
                minimum_operator_acceptance_rate: 0.0,
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
            hard_limits: crate::chisei::gunshi_policy::HardLimitChecks {
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

    #[test]
    fn promote_opt_in_kill_switch_and_rollback_flow() {
        let db = db();
        let status = install_baseline(
            &db,
            "admin",
            "support",
            snapshot("v1", false),
            gate(),
            1_000,
        )
        .unwrap();
        assert!(!status.auto_dispatch_live);
        assert_eq!(status.active_revision_id, "v1");

        let mut candidate = snapshot("v2", true);
        candidate.dispatch.maximum_budget_usd_micros = 9_000;
        let promoted = promote(
            &db,
            PromoteRequest {
                actor: "admin".into(),
                namespace: "support".into(),
                candidate,
                baseline: evaluation("v1"),
                candidate_evaluation: evaluation("v2"),
                expected_revision: "v1".into(),
                now_ms: 1_000 + PROMOTE_COOLDOWN_MS + 1,
            },
        )
        .unwrap();
        assert_eq!(promoted.active_revision_id, "v2");
        assert!(!promoted.auto_dispatch_live);

        let opted = set_auto_opt_in(
            &db,
            "admin",
            "support",
            true,
            "v2",
            1_000 + PROMOTE_COOLDOWN_MS + 2,
        )
        .unwrap();
        assert!(opted.auto_dispatch_live);

        let killed = set_kill_switch(
            &db,
            "admin",
            "support",
            true,
            "incident",
            1_000 + PROMOTE_COOLDOWN_MS + 3,
        )
        .unwrap();
        assert!(killed.kill_switch);
        assert!(!killed.auto_opt_in);
        assert!(!killed.auto_dispatch_live);

        let rolled = rollback(
            &db,
            "admin",
            "support",
            "v2",
            "operator rollback",
            1_000 + PROMOTE_COOLDOWN_MS + 4,
        )
        .unwrap();
        assert_eq!(rolled.active_revision_id, "v1");
        assert!(!rolled.auto_dispatch_live);
    }

    #[test]
    fn mismatched_evidence_fails_promotion_and_leaves_baseline() {
        let db = db();
        install_baseline(&db, "admin", "support", snapshot("v1", false), gate(), 1).unwrap();
        let mut bad = evaluation("v2");
        bad.hard_limits.privacy = false;
        assert!(
            promote(
                &db,
                PromoteRequest {
                    actor: "admin".into(),
                    namespace: "support".into(),
                    candidate: snapshot("v2", true),
                    baseline: evaluation("v1"),
                    candidate_evaluation: bad,
                    expected_revision: "v1".into(),
                    now_ms: 1 + PROMOTE_COOLDOWN_MS + 1,
                },
            )
            .unwrap_err()
            .contains("failed promotion gate")
        );
        assert_eq!(
            get_status(&db, "support")
                .unwrap()
                .unwrap()
                .active_revision_id,
            "v1"
        );
    }

    #[test]
    fn cas_rejects_stale_expected_revision() {
        let db = db();
        install_baseline(&db, "admin", "support", snapshot("v1", false), gate(), 1).unwrap();
        promote(
            &db,
            PromoteRequest {
                actor: "admin".into(),
                namespace: "support".into(),
                candidate: snapshot("v2", true),
                baseline: evaluation("v1"),
                candidate_evaluation: evaluation("v2"),
                expected_revision: "v1".into(),
                now_ms: 1 + PROMOTE_COOLDOWN_MS + 1,
            },
        )
        .unwrap();
        assert!(
            promote(
                &db,
                PromoteRequest {
                    actor: "admin".into(),
                    namespace: "support".into(),
                    candidate: snapshot("v3", true),
                    baseline: evaluation("v1"),
                    candidate_evaluation: evaluation("v3"),
                    expected_revision: "v1".into(),
                    now_ms: 1 + 2 * PROMOTE_COOLDOWN_MS + 2,
                },
            )
            .unwrap_err()
            .contains("revision race")
        );
    }

    #[test]
    fn receipt_attributes_mark_auto_path() {
        let plan = AllocationPlan {
            contract_version: crate::chisei::gunshi::ALLOCATION_CONTRACT_VERSION.into(),
            allocation_id: "alloc-1".into(),
            operation_id: "op-1".into(),
            namespace: "support".into(),
            operation_class: "triage".into(),
            priority: 1,
            strategy: crate::chisei::gunshi::Strategy {
                strategy_id: "balanced".into(),
                version: "1".into(),
                baseline: crate::chisei::gunshi::BaselineStrategy::Conservative,
            },
            policy_version: "governance-v1".into(),
            advisory: true,
            selection: crate::chisei::gunshi::ResourceSelection {
                agent_id: "agent".into(),
                runtime: "local".into(),
                model: "local".into(),
                tools: vec!["search".into()],
            },
            attempts: crate::chisei::gunshi::AttemptStrategy {
                max_attempts: 1,
                parallel_attempts: 1,
                speculative: false,
            },
            verification: crate::chisei::gunshi::VerificationStrategy {
                checks: vec!["operation_receipt_complete".into()],
                acceptance_criteria: vec!["classified".into()],
                human_review_required: false,
            },
            budget_ceiling_usd_micros: 1_000,
            stop_conditions: crate::chisei::gunshi::StopConditions {
                max_cost_usd_micros: 1_000,
                max_attempts: 1,
                deadline_ms: None,
                stop_on_acceptance: true,
            },
            escalation: crate::chisei::gunshi::EscalationRules {
                approval_required: false,
                escalate_on_budget_exhaustion: false,
                escalate_after_failed_attempts: 0,
            },
            evidence: vec![],
            expected: crate::chisei::gunshi::ExpectedOutcome {
                quality: 0.9,
                cost_usd_micros: 100,
                latency_ms: 10,
                uncertainty: 0.1,
            },
            explanation: vec![],
            input_fingerprint: "fp".into(),
        };
        let attrs = receipt_attributes(true, &plan, None, None, &[]);
        assert_eq!(attrs.get("auto_dispatch").map(String::as_str), Some("true"));
        assert_eq!(
            attrs.get("gunshi_allocation_id").map(String::as_str),
            Some("alloc-1")
        );
    }
}
