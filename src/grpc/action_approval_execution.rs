//! Concrete execution of an approved held action.
//!
//! This module is the deep interface between the gRPC adapter and Sekai's
//! approval lifecycle. It owns live action resolution, resource
//! reauthorization, effect execution, and terminal lifecycle ordering. Caller
//! authentication and protocol mapping remain in the adapter.

use super::{
    ERASED_NAMESPACE, SekaiServiceImpl, approval_adapter_error, check_team_namespace,
    enforce_object_marking_access, now_millis, record_marking_or_purpose_decision,
    resolve_principal_authority,
};
use crate::sekai::action_approval_lifecycle::{
    ActionApprovalLifecycle, ApprovalActionProfile, ApprovalLifecycleError, ApprovalOutcome,
    ApproveAction,
};
use crate::sekai::markings;
use std::collections::HashMap;

pub(super) struct ActionApprovalExecution<'a> {
    service: &'a SekaiServiceImpl,
}

impl<'a> ActionApprovalExecution<'a> {
    pub(super) fn new(service: &'a SekaiServiceImpl) -> Self {
        Self { service }
    }

    pub(super) fn approve(
        &self,
        approval_id: &str,
        approver: &str,
    ) -> Result<ApprovalOutcome, ApprovalLifecycleError> {
        ActionApprovalLifecycle::new(&self.service.db, self.service.budget.as_deref()).approve(
            ApproveAction {
                approval_id,
                approver,
                erased_namespace: ERASED_NAMESPACE,
                now_ms: now_millis(),
            },
            |approval| self.resolve_profile(approval),
            |approval, proposer| self.reauthorize(approval, proposer),
            |approval, proposer| {
                self.service
                    .run_action_effect(
                        &approval.action,
                        &approval.params,
                        &approval.actor,
                        proposer,
                    )
                    .map_err(approval_adapter_error)
            },
            now_millis,
        )
    }

    fn resolve_profile(
        &self,
        approval: &crate::sekai::action_approval::ActionApproval,
    ) -> Result<ApprovalActionProfile, ApprovalLifecycleError> {
        let actions = self
            .service
            .action_definitions
            .fresh_snapshot()
            .map_err(|error| ApprovalLifecycleError::Storage(format!("{error:?}")))?;
        let target_ids = actions
            .target_ids(&self.service.db, &approval.action, &approval.params)
            .unwrap_or_default();
        let (op_mutations, op_deletes) =
            actions.action_op_counts(&approval.action, &approval.params);
        Ok(ApprovalActionProfile {
            target_ids,
            risk: actions.action_risk_class(&approval.action),
            op_mutations,
            op_deletes,
        })
    }

    fn reauthorize(
        &self,
        approval: &crate::sekai::action_approval::ActionApproval,
        proposer: &[String],
    ) -> Result<(), ApprovalLifecycleError> {
        if approval.action == crate::sekai::parked_work::RESOLVE_PARKED_WORK_ACTION {
            self.reauthorize_parked_work(approval, proposer)?;
        }
        let actions = self
            .service
            .action_definitions
            .fresh_snapshot()
            .map_err(|error| ApprovalLifecycleError::Storage(format!("{error:?}")))?;
        let resume_targets = actions
            .target_ids(&self.service.db, &approval.action, &approval.params)
            .map_err(ApprovalLifecycleError::InvalidArgument)?;
        for target_id in &resume_targets {
            if let Some(target) = self
                .service
                .db
                .get_object(target_id)
                .map_err(ApprovalLifecycleError::Storage)?
            {
                enforce_object_marking_access(
                    &self.service.db,
                    &target,
                    proposer,
                    &format!("approve_action:{}:{}", approval.action, target_id),
                )
                .map_err(approval_adapter_error)?;
            }
        }
        let required_purpose = actions
            .get_action_type(&approval.action)
            .map(|action_type| action_type.required_purpose.clone())
            .unwrap_or_default();
        drop(actions);
        self.reauthorize_purpose(approval, proposer, &required_purpose)
    }

    fn reauthorize_parked_work(
        &self,
        approval: &crate::sekai::action_approval::ActionApproval,
        proposer: &[String],
    ) -> Result<(), ApprovalLifecycleError> {
        let effect_id = approval
            .params
            .get("effect_id")
            .ok_or_else(|| ApprovalLifecycleError::InvalidArgument("effect_id required".into()))?;
        let effect = self
            .service
            .db
            .get_action_effect(effect_id)
            .map_err(ApprovalLifecycleError::Storage)?
            .ok_or_else(|| {
                ApprovalLifecycleError::ReferencedNotFound("action effect not found".into())
            })?;
        let submitted_namespace = approval
            .params
            .get("namespace")
            .map(String::as_str)
            .unwrap_or("");
        if submitted_namespace != effect.namespace {
            return Err(ApprovalLifecycleError::FailedPrecondition(
                "parked resolution namespace no longer matches effect".into(),
            ));
        }
        check_team_namespace(&self.service.db, proposer, &effect.namespace, true)
            .map_err(approval_adapter_error)
    }

    fn reauthorize_purpose(
        &self,
        approval: &crate::sekai::action_approval::ActionApproval,
        proposer: &[String],
        required_purpose: &str,
    ) -> Result<(), ApprovalLifecycleError> {
        if required_purpose.trim().is_empty() {
            return Ok(());
        }
        let authority = resolve_principal_authority(&self.service.db, proposer)
            .map_err(approval_adapter_error)?;
        let purpose = markings::evaluate_purpose_access(
            &format!("approve_action:{}", approval.action),
            required_purpose,
            &authority,
        );
        let outcome = match purpose.decision {
            markings::MarkingDecision::Deny => "denied",
            markings::MarkingDecision::Allow => "allowed",
            markings::MarkingDecision::NotApplicable => return Ok(()),
        };
        let evidence = HashMap::from([
            ("required_purpose".into(), purpose.required_purpose.clone()),
            ("detail".into(), purpose.detail.clone()),
            ("outcome".into(), outcome.into()),
        ]);
        let recorded = record_marking_or_purpose_decision(
            &self.service.db,
            &approval.actor,
            "purpose.execute",
            approval.target_id.as_str(),
            &purpose.decision_id,
            outcome,
            evidence,
        )
        .map_err(approval_adapter_error);
        if purpose.decision == markings::MarkingDecision::Deny {
            let _ = recorded;
            return Err(ApprovalLifecycleError::PermissionDenied(
                "purpose not allow-listed".into(),
            ));
        }
        recorded
    }
}
