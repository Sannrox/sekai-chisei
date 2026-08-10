//! Governed action approval decisions and held-effect resumption.
//!
//! This module owns the ordering that turns a pending approval into a terminal
//! decision. Transport adapters retain caller authentication, protocol mapping,
//! and the concrete effect execution adapter.

use crate::chisei::budget::BudgetTracker;
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action::RiskClass;
use crate::sekai::action_approval::{ActionApproval, ApprovalStatus};
use crate::sekai::action_lifecycle::{
    self, ActionAudit, ActionLimitExceeded, GovernedActionContext,
};
use crate::sekai::action_policy::ActionDecision;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalLifecycleError {
    NotFound,
    Terminal { id: String, status: String },
    PolicyDenied,
    Limit(ActionLimitExceeded),
    InvalidArgument(String),
    FailedPrecondition(String),
    ReferencedNotFound(String),
    PermissionDenied(String),
    Unauthenticated(String),
    AlreadyExists(String),
    ResourceExhausted(String),
    Unavailable(String),
    Storage(String),
}

#[derive(Debug, Clone)]
pub struct ApproveAction<'a> {
    pub approval_id: &'a str,
    pub approver: &'a str,
    pub erased_namespace: &'a str,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct DenyAction<'a> {
    pub approval_id: &'a str,
    pub decided_by: &'a str,
    pub reason: &'a str,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ApprovalOutcome {
    pub approval: ActionApproval,
    pub message: String,
}

pub struct ApprovalActionProfile {
    pub target_ids: Vec<String>,
    pub risk: RiskClass,
    pub op_mutations: u32,
    pub op_deletes: u32,
}

pub struct ActionApprovalLifecycle<'a> {
    db: &'a RuntimeDb,
    budget: Option<&'a BudgetTracker>,
}

impl<'a> ActionApprovalLifecycle<'a> {
    pub fn new(db: &'a RuntimeDb, budget: Option<&'a BudgetTracker>) -> Self {
        Self { db, budget }
    }

    pub fn load(&self, approval_id: &str) -> Result<ActionApproval, ApprovalLifecycleError> {
        self.db
            .get_action_approval(approval_id)
            .map_err(ApprovalLifecycleError::Storage)?
            .ok_or(ApprovalLifecycleError::NotFound)
    }

    pub fn load_pending(
        &self,
        approval_id: &str,
    ) -> Result<ActionApproval, ApprovalLifecycleError> {
        let approval = self.load(approval_id)?;
        if approval.status != ApprovalStatus::Pending {
            return Err(ApprovalLifecycleError::Terminal {
                id: approval.id,
                status: approval.status.as_str().to_string(),
            });
        }
        Ok(approval)
    }

    pub fn approve<Resolve, Prepare, Execute, Clock>(
        &self,
        command: ApproveAction<'_>,
        resolve: Resolve,
        mut prepare: Prepare,
        execute: Execute,
        completed_at: Clock,
    ) -> Result<ApprovalOutcome, ApprovalLifecycleError>
    where
        Resolve: FnOnce(&ActionApproval) -> Result<ApprovalActionProfile, ApprovalLifecycleError>,
        Prepare: FnMut(&ActionApproval, &[String]) -> Result<(), ApprovalLifecycleError>,
        Execute: FnOnce(&ActionApproval, &[String]) -> Result<String, ApprovalLifecycleError>,
        Clock: FnOnce() -> i64,
    {
        let mut approval = self.load_pending(command.approval_id)?;
        let profile = resolve(&approval)?;
        let namespace = action_policy_namespace(self.db, &profile.target_ids, &approval.params);
        let context = GovernedActionContext::resolve(
            self.db,
            &approval.actor,
            &namespace,
            &approval.action,
            profile.risk,
            &approval.work_unit,
            profile.op_mutations,
            profile.op_deletes,
            command.erased_namespace,
        )
        .map_err(ApprovalLifecycleError::Storage)?;
        let audit = || ActionAudit {
            actor: command.approver.to_string(),
            attestation_actor: approval.actor.clone(),
            action: approval.action.clone(),
            target_id: approval.target_id.clone(),
            evidence: HashMap::from([("approval_id".to_string(), approval.id.clone())]),
            timestamp: command.now_ms,
        };
        if context.decision == ActionDecision::Deny {
            context
                .record_outcome(
                    self.db,
                    self.budget,
                    audit(),
                    "action_approval_policy_denied",
                    "policy now denies the held action".into(),
                    false,
                )
                .map_err(ApprovalLifecycleError::Storage)?;
            return Err(ApprovalLifecycleError::PolicyDenied);
        }
        context
            .check_limits_and_record(self.db, self.budget, audit())
            .map_err(ApprovalLifecycleError::Limit)?;

        let proposer = [approval.actor.clone()];
        prepare(&approval, &proposer)?;
        if approval.action == crate::sekai::parked_work::RESOLVE_PARKED_WORK_ACTION {
            let resolution_action_id =
                approval.params.get("resolution_action_id").ok_or_else(|| {
                    ApprovalLifecycleError::InvalidArgument("resolution_action_id required".into())
                })?;
            self.db
                .authorize_parked_resolution_approval(resolution_action_id, &approval.id)
                .map_err(ApprovalLifecycleError::FailedPrecondition)?;
        }
        let message = execute(&approval, &proposer)?;
        let completed_at_ms = completed_at();

        // The effect is committed; metering cannot leave the approval pending.
        let _ = context.record_usage(self.db, self.budget);
        self.deny_competing_parked_resolutions(&approval, command.approver, completed_at_ms)?;
        action_lifecycle::complete_approval(
            self.db,
            &context,
            &mut approval,
            command.approver,
            &message,
            completed_at_ms,
        )
        .map_err(ApprovalLifecycleError::Storage)?;
        Ok(ApprovalOutcome { approval, message })
    }

    pub fn deny(&self, command: DenyAction<'_>) -> Result<ActionApproval, ApprovalLifecycleError> {
        let mut approval = self.load_pending(command.approval_id)?;
        if approval.action == crate::sekai::parked_work::RESOLVE_PARKED_WORK_ACTION {
            self.db
                .reject_parked_resolution(
                    &approval.id,
                    "rejected",
                    command.decided_by,
                    command.now_ms,
                )
                .map_err(ApprovalLifecycleError::Storage)?;
        }
        action_lifecycle::deny_approval(
            self.db,
            &mut approval,
            command.decided_by,
            command.reason,
            command.now_ms,
        )
        .map_err(ApprovalLifecycleError::Storage)?;
        Ok(approval)
    }

    fn deny_competing_parked_resolutions(
        &self,
        approval: &ActionApproval,
        decided_by: &str,
        now_ms: i64,
    ) -> Result<(), ApprovalLifecycleError> {
        if approval.action != crate::sekai::parked_work::RESOLVE_PARKED_WORK_ACTION {
            return Ok(());
        }
        let effect_id = approval
            .params
            .get("effect_id")
            .cloned()
            .unwrap_or_default();
        let generation = approval
            .params
            .get("park_generation")
            .cloned()
            .unwrap_or_default();
        for mut competing in self
            .db
            .list_action_approvals(Some(ApprovalStatus::Pending))
            .map_err(ApprovalLifecycleError::Storage)?
        {
            if competing.action == approval.action
                && competing.id != approval.id
                && competing.params.get("effect_id") == Some(&effect_id)
                && competing.params.get("park_generation") == Some(&generation)
            {
                competing.status = ApprovalStatus::Denied;
                competing.decided_by = decided_by.to_string();
                competing.outcome = format!("stale: superseded by resolution {}", approval.id);
                competing.updated = now_ms;
                self.db
                    .update_action_approval(&competing)
                    .map_err(ApprovalLifecycleError::Storage)?;
            }
        }
        Ok(())
    }
}

fn action_policy_namespace(
    db: &RuntimeDb,
    target_ids: &[String],
    params: &HashMap<String, String>,
) -> String {
    for id in target_ids {
        if let Ok(Some(object)) = db.get_object(id) {
            if object.kind == "namespace" {
                let namespace = object
                    .external_id
                    .strip_prefix("namespace:")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| object.name.trim());
                if !namespace.is_empty() {
                    return namespace.to_string();
                }
            }
            if !object.namespace.trim().is_empty() {
                return object.namespace;
            }
        }
    }
    params
        .get("namespace")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_approval(db: &RuntimeDb) -> ActionApproval {
        let approval = ActionApproval::pending(
            "alice",
            "set_property",
            HashMap::from([
                ("id".into(), "object-1".into()),
                ("key".into(), "state".into()),
                ("value".into(), "ready".into()),
            ]),
            "work-1",
            "agent:alice",
            "write",
            "object-1",
            10,
        );
        db.create_action_approval(&approval).unwrap();
        approval
    }

    #[test]
    fn deny_is_a_terminal_interface_transition() {
        let db = RuntimeDb::memory();
        let approval = pending_approval(&db);
        let lifecycle = ActionApprovalLifecycle::new(&db, None);

        let denied = lifecycle
            .deny(DenyAction {
                approval_id: &approval.id,
                decided_by: "admin",
                reason: "not authorized",
                now_ms: 20,
            })
            .unwrap();

        assert_eq!(denied.status, ApprovalStatus::Denied);
        assert_eq!(denied.decided_by, "admin");
        assert!(matches!(
            lifecycle.load_pending(&approval.id),
            Err(ApprovalLifecycleError::Terminal { .. })
        ));
    }

    #[test]
    fn approve_rechecks_live_policy_before_effect_preparation() {
        let db = RuntimeDb::memory();
        let approval = pending_approval(&db);
        let mut policy = crate::sekai::action_policy::ActionPolicy::allow_all("agent:alice");
        policy.default_decision = ActionDecision::Deny;
        db.upsert_action_policy(&policy).unwrap();
        let lifecycle = ActionApprovalLifecycle::new(&db, None);
        let prepared = std::cell::Cell::new(false);

        let result = lifecycle.approve(
            ApproveAction {
                approval_id: &approval.id,
                approver: "admin",
                erased_namespace: "__erased__",
                now_ms: 20,
            },
            |_| {
                Ok(ApprovalActionProfile {
                    target_ids: Vec::new(),
                    risk: RiskClass::Write,
                    op_mutations: 1,
                    op_deletes: 0,
                })
            },
            |_, _| {
                prepared.set(true);
                Ok(())
            },
            |_, _| Ok("updated".into()),
            || 21,
        );

        assert_eq!(result.unwrap_err(), ApprovalLifecycleError::PolicyDenied);
        assert!(!prepared.get());
        assert_eq!(
            db.get_action_approval(&approval.id)
                .unwrap()
                .unwrap()
                .status,
            ApprovalStatus::Pending
        );
    }

    #[test]
    fn approve_timestamps_terminal_state_after_effect_completion() {
        let db = RuntimeDb::memory();
        let approval = pending_approval(&db);
        let lifecycle = ActionApprovalLifecycle::new(&db, None);

        let outcome = lifecycle
            .approve(
                ApproveAction {
                    approval_id: &approval.id,
                    approver: "admin",
                    erased_namespace: "__erased__",
                    now_ms: 20,
                },
                |_| {
                    Ok(ApprovalActionProfile {
                        target_ids: Vec::new(),
                        risk: RiskClass::Write,
                        op_mutations: 0,
                        op_deletes: 0,
                    })
                },
                |_, _| Ok(()),
                |_, _| Ok("updated".into()),
                || 25,
            )
            .unwrap();

        assert_eq!(outcome.approval.status, ApprovalStatus::Approved);
        assert_eq!(outcome.approval.updated, 25);
    }
}
