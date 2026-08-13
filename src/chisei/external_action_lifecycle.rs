//! Durable lifecycle orchestration for host-executed action authorization.
//!
//! Transport adapters authenticate and translate protocol values. This module
//! owns policy snapshots, lifecycle transitions, reservation cleanup, and audit
//! projection so callers cannot accidentally reorder those invariants.

use crate::chisei::budget::BudgetTracker;
use crate::chisei::external_action::{
    self, AuthorizationRecord, ExternalActionDecision, ExternalActionRequest,
};
use crate::db::chisei_budget::METRIC_TOKENS;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action::RiskClass;
use crate::sekai::action_policy::{ActionDecision, ActionPolicy};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug)]
pub struct AuthorizationPlan {
    pub record: AuthorizationRecord,
    pub policy_decision: ActionDecision,
    pub max_mutations: Option<u32>,
    pub max_deletes: Option<u32>,
}

impl AuthorizationPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        request: ExternalActionRequest,
        authorization_id: String,
        request_digest: String,
        actor: &str,
        policy: Option<&ActionPolicy>,
        now_ms: i64,
    ) -> Result<Self, String> {
        let risk = RiskClass::parse(request.authoritative_risk_class()?)
            .ok_or_else(|| "invalid risk_class".to_string())?;
        let mut policy_decision = match policy {
            Some(policy) => {
                policy.decide(&format!("external_action/{}", request.action_type), risk)
            }
            None => ActionDecision::Deny,
        };
        let mut reason = match policy {
            Some(_) => "external action satisfies current policy".to_string(),
            None => "external-action action policy is required".to_string(),
        };
        if request.deadline_ms <= now_ms {
            policy_decision = ActionDecision::Deny;
            reason = "external-action request expired".into();
        }
        let approval_id = if policy_decision == ActionDecision::RequireApproval {
            format!("external-approval-{}", uuid::Uuid::new_v4().simple())
        } else {
            String::new()
        };
        let record = AuthorizationRecord {
            request: request.clone(),
            decision: ExternalActionDecision {
                version: external_action::DECISION_VERSION.into(),
                authorization_id,
                request_digest,
                decision: String::new(),
                reason,
                approval_id,
                policy_scope: policy.map(|value| value.scope.clone()).unwrap_or_default(),
                policy_version: policy_version(policy),
                created_at_ms: now_ms,
                expires_at_ms: request.deadline_ms,
                cancelled_at_ms: 0,
                assurance: external_action::AssuranceDeclaration::default(),
            },
            approval_status: if policy_decision == ActionDecision::RequireApproval {
                "pending".into()
            } else {
                String::new()
            },
            budget_reserved: false,
            blast_radius_reserved: false,
            decision_actor: actor.into(),
            decision_updated_at_ms: now_ms,
        };
        let max_mutations = policy.and_then(|value| value.max_mutations_per_work_unit);
        let max_deletes = (risk == RiskClass::Destructive)
            .then(|| policy.and_then(|value| value.max_deletes_per_work_unit))
            .flatten();
        Ok(Self {
            record,
            policy_decision,
            max_mutations,
            max_deletes,
        })
    }

    pub fn finish(mut self) -> AuthorizationRecord {
        self.record.decision.decision = match self.policy_decision {
            ActionDecision::Allow => "permit",
            ActionDecision::Deny => "deny",
            ActionDecision::RequireApproval => "require_approval",
        }
        .into();
        if self.policy_decision == ActionDecision::Deny {
            self.record.decision.approval_id.clear();
            self.record.approval_status.clear();
        }
        self.record
    }
}

pub fn approve_or_deny(
    record: &mut AuthorizationRecord,
    transition: &str,
    reason: &str,
    actor: &str,
    now_ms: i64,
    requester_access_revoked: bool,
    current_policy: Option<&ActionPolicy>,
) -> Result<(), String> {
    if record.approval_status != "pending" || record.decision.decision != "require_approval" {
        return Err("external-action approval is not pending".into());
    }
    if requester_access_revoked {
        record.decision.decision = "deny".into();
        record.decision.reason = "external-action requester no longer has namespace access".into();
        record.approval_status = "revoked".into();
    } else if now_ms >= record.decision.expires_at_ms {
        record.decision.decision = "deny".into();
        record.decision.reason = "external-action approval expired".into();
        record.approval_status = "expired".into();
    } else if policy_version(current_policy) != record.decision.policy_version {
        record.decision.decision = "deny".into();
        record.decision.reason = "external-action approval is stale after policy change".into();
        record.approval_status = "stale".into();
    } else if transition == "approve" {
        record.decision.decision = "permit".into();
        record.decision.reason = "external action approved".into();
        record.approval_status = "approved".into();
    } else {
        record.decision.decision = "deny".into();
        record.decision.reason = if reason.trim().is_empty() {
            "external action denied by approver".into()
        } else {
            reason.into()
        };
        record.approval_status = "denied".into();
    }
    record.decision_actor = actor.into();
    record.decision_updated_at_ms = now_ms;
    Ok(())
}

pub fn cancel(record: &mut AuthorizationRecord, actor: &str, reason: &str, now_ms: i64) -> bool {
    if record.decision.cancelled_at_ms != 0 {
        return false;
    }
    record.decision.cancelled_at_ms = now_ms;
    record.decision.decision = "deny".into();
    record.decision.reason = if reason.trim().is_empty() {
        "external-action authorization cancelled".into()
    } else {
        reason.into()
    };
    record.approval_status = "cancelled".into();
    record.decision_actor = actor.into();
    record.decision_updated_at_ms = now_ms;
    true
}

pub fn budget_scope(request: &ExternalActionRequest) -> String {
    format!(
        "project:{}/agent:{}/external-action:{}",
        request.namespace, request.actor, request.risk_class
    )
}

pub fn ensure_audit(db: &RuntimeDb, record: &AuthorizationRecord) -> Result<(), String> {
    let lifecycle = if record.approval_status.is_empty() {
        record.decision.decision.as_str()
    } else {
        record.approval_status.as_str()
    };
    db.record_decisions_idempotently(&[crate::sekai::audit::Decision {
        id: format!("{}:audit:{lifecycle}", record.decision.authorization_id),
        timestamp: record.decision_updated_at_ms,
        actor: record.decision_actor.clone(),
        action: format!("external_action/{}", record.request.action_type),
        reason: format!("external_action_authorization_{lifecycle}"),
        evidence: HashMap::from([
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
        ]),
        target_id: record.decision.authorization_id.clone(),
        outcome: record.decision.decision.clone(),
    }])
}

pub fn release_reservations(
    db: &RuntimeDb,
    budget: &BudgetTracker,
    record: &mut AuthorizationRecord,
) -> Result<(), String> {
    let units = i32::try_from(record.request.requested_invocation_count).unwrap_or(i32::MAX);
    if record.budget_reserved {
        budget.record_idempotent_with_metric(
            &budget_scope(&record.request),
            -units,
            METRIC_TOKENS,
            &format!(
                "external-action-release:{}",
                record.decision.authorization_id
            ),
        )?;
        record.budget_reserved = false;
    }
    if record.blast_radius_reserved {
        db.release_external_action_blast_radius(
            &record.decision.authorization_id,
            &record.request,
        )?;
        record.blast_radius_reserved = false;
    }
    Ok(())
}

pub fn persist_released_flags(
    db: &RuntimeDb,
    reserved: &AuthorizationRecord,
    released: &AuthorizationRecord,
) -> Result<(), String> {
    if reserved != released {
        let _ = db.compare_and_swap_external_action_authorization(reserved, released)?;
    }
    Ok(())
}

pub fn reclaim_expired(db: &RuntimeDb, budget: &BudgetTracker, now_ms: i64) -> Result<(), String> {
    for expected in db
        .list_external_action_authorizations()?
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
        if db.compare_and_swap_external_action_authorization(&expected, &expired)? {
            let reserved = expired.clone();
            release_reservations(db, budget, &mut expired)?;
            persist_released_flags(db, &reserved, &expired)?;
            ensure_audit(db, &expired)?;
        }
    }
    Ok(())
}

pub fn policy_version(policy: Option<&ActionPolicy>) -> String {
    use sha2::{Digest, Sha256};
    let canonical: BTreeMap<String, String> = policy
        .map(|value| value.to_properties().into_iter().collect())
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&canonical).unwrap_or_default());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ExternalActionRequest {
        ExternalActionRequest {
            version: external_action::REQUEST_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: String::new(),
            attempt_id: "attempt-1".into(),
            request_id: "request-1".into(),
            actor: "agent-1".into(),
            namespace: "team-a".into(),
            requesting_harness: "harness-a".into(),
            intended_executor: "executor-a".into(),
            action_type: "repository.write/v1".into(),
            parameter_schema: "repository.write.params/v1".into(),
            canonical_arguments_digest: "sha256:arguments".into(),
            policy_summary: BTreeMap::new(),
            target_selectors: vec!["project:team-a/repo:example/repo".into()],
            immutable_preconditions: BTreeMap::new(),
            risk_class: "write".into(),
            expected_effects: vec!["git.commit".into()],
            requested_invocation_count: 1,
            deadline_ms: 10_000,
            estimated_cost_micros: 0,
            estimated_volume: 1,
            affected_resource_count: 1,
            rollback_capability: "revert_commit".into(),
            required_host_capabilities: vec![],
            idempotency_key: "idem-1".into(),
            policy_project: "team-a".into(),
        }
    }

    #[test]
    fn interface_resolves_and_approves_one_policy_snapshot() {
        let mut policy = ActionPolicy::allow_all("team-a");
        policy.default_decision = ActionDecision::RequireApproval;
        policy.max_mutations_per_work_unit = Some(5);
        let plan = AuthorizationPlan::resolve(
            request(),
            "auth-1".into(),
            "digest-1".into(),
            "agent-1",
            Some(&policy),
            100,
        )
        .unwrap();
        assert_eq!(plan.policy_decision, ActionDecision::RequireApproval);
        assert_eq!(plan.max_mutations, Some(5));
        let mut record = plan.finish();
        assert_eq!(record.decision.decision, "require_approval");

        approve_or_deny(
            &mut record,
            "approve",
            "",
            "root",
            200,
            false,
            Some(&policy),
        )
        .unwrap();
        assert_eq!(record.decision.decision, "permit");
        assert_eq!(record.approval_status, "approved");
        assert_eq!(record.decision_actor, "root");
    }

    #[test]
    fn interface_fails_closed_when_policy_changes_before_approval() {
        let mut initial = ActionPolicy::allow_all("team-a");
        initial.default_decision = ActionDecision::RequireApproval;
        let mut record = AuthorizationPlan::resolve(
            request(),
            "auth-1".into(),
            "digest-1".into(),
            "agent-1",
            Some(&initial),
            100,
        )
        .unwrap()
        .finish();
        let changed = ActionPolicy::allow_all("team-a");

        approve_or_deny(
            &mut record,
            "approve",
            "",
            "root",
            200,
            false,
            Some(&changed),
        )
        .unwrap();
        assert_eq!(record.decision.decision, "deny");
        assert_eq!(record.approval_status, "stale");
    }

    #[test]
    fn missing_policy_fails_closed() {
        let plan = AuthorizationPlan::resolve(
            request(),
            "auth-1".into(),
            "digest-1".into(),
            "agent-1",
            None,
            100,
        )
        .unwrap();
        assert_eq!(plan.policy_decision, ActionDecision::Deny);
        let record = plan.finish();
        assert_eq!(record.decision.decision, "deny");
        assert!(record.decision.reason.contains("action policy is required"));
        assert!(record.decision.policy_scope.is_empty());
    }

    #[test]
    fn cancellation_is_idempotent_at_the_interface() {
        let mut record = AuthorizationPlan::resolve(
            request(),
            "auth-1".into(),
            "digest-1".into(),
            "agent-1",
            None,
            100,
        )
        .unwrap()
        .finish();
        assert!(cancel(&mut record, "agent-1", "stop", 200));
        assert!(!cancel(&mut record, "agent-1", "different", 300));
        assert_eq!(record.decision.reason, "stop");
        assert_eq!(record.decision.cancelled_at_ms, 200);
    }
}
