//! Dual-backend community-store dispatch for actions.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_action_policy(&self, scope: &str) -> Result<Option<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_policy(scope),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_action_policy(scope)),
        }
    }

    pub fn list_action_policies(&self) -> Result<Vec<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_policies(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_action_policies()),
        }
    }

    pub fn put_governed_action_type(
        &self,
        type_def: crate::sekai::governed_action_type::GovernedActionType,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_action_type::GovernedActionType, String> {
        match self {
            Self::Sqlite(db) => db.put_governed_action_type(type_def, actor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_governed_action_type(type_def, actor, now_ms)
            }),
        }
    }

    pub fn get_governed_action_type(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
    ) -> Result<Option<crate::sekai::governed_action_type::GovernedActionType>, String> {
        match self {
            Self::Sqlite(db) => db.get_governed_action_type(namespace, type_id, version),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_governed_action_type(namespace, type_id, version)
            }),
        }
    }

    pub fn list_governed_action_types(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        enabled_only: bool,
    ) -> Result<Vec<crate::sekai::governed_action_type::GovernedActionType>, String> {
        match self {
            Self::Sqlite(db) => db.list_governed_action_types(namespace, type_id, enabled_only),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_governed_action_types(namespace, type_id, enabled_only)
            }),
        }
    }

    pub fn set_governed_action_type_enabled(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
        enabled: bool,
        now_ms: i64,
    ) -> Result<crate::sekai::governed_action_type::GovernedActionType, String> {
        match self {
            Self::Sqlite(db) => {
                db.set_governed_action_type_enabled(namespace, type_id, version, enabled, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_governed_action_type_enabled(namespace, type_id, version, enabled, now_ms)
            }),
        }
    }

    pub fn require_enabled_governed_action_type(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
    ) -> Result<crate::sekai::governed_action_type::GovernedActionType, String> {
        match self {
            Self::Sqlite(db) => {
                db.require_enabled_governed_action_type(namespace, type_id, version)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.require_enabled_governed_action_type(namespace, type_id, version)
            }),
        }
    }

    pub fn put_action_instance(
        &self,
        instance: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<crate::sekai::action_instance::ActionInstance, String> {
        match self {
            Self::Sqlite(db) => db.put_action_instance(instance),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_action_instance(instance))
            }
        }
    }

    pub fn put_decision_memory(
        &self,
        memory: &crate::sekai::decision_memory::DecisionMemory,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_decision_memory(memory),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_decision_memory(memory))
            }
        }
    }

    pub fn list_decision_memory(
        &self,
        namespace: &str,
        type_id: &str,
    ) -> Result<Vec<crate::sekai::decision_memory::DecisionMemory>, String> {
        self.list_decision_memory_page(namespace, type_id, 0, i64::MAX)
    }

    pub fn list_decision_memory_page(
        &self,
        namespace: &str,
        type_id: &str,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<crate::sekai::decision_memory::DecisionMemory>, String> {
        match self {
            Self::Sqlite(db) => db.list_decision_memory_page(namespace, type_id, offset, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_decision_memory_page(namespace, type_id, offset, limit)
            }),
        }
    }

    pub fn get_decision_memory(
        &self,
        memory_id: &str,
    ) -> Result<Option<crate::sekai::decision_memory::DecisionMemory>, String> {
        match self {
            Self::Sqlite(db) => db.get_decision_memory(memory_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_decision_memory(memory_id))
            }
        }
    }

    pub fn mark_decision_memory_superseded(&self, memory_id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.mark_decision_memory_superseded(memory_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.mark_decision_memory_superseded(memory_id))
            }
        }
    }

    pub fn put_action_binding(
        &self,
        binding: &crate::sekai::action_binding::ActionBinding,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::action_binding::ActionBinding, String> {
        match self {
            Self::Sqlite(db) => db.put_action_binding(binding, actor, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_action_binding(binding, actor, now_ms))
            }
        }
    }

    pub fn get_action_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<
        Option<(
            crate::sekai::action_binding::ActionBinding,
            crate::sekai::action_binding::ActionBindingCursor,
        )>,
        String,
    > {
        match self {
            Self::Sqlite(db) => db.get_action_binding(namespace, binding_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_action_binding(namespace, binding_id))
            }
        }
    }

    pub fn advance_action_binding_cursor(
        &self,
        binding: &crate::sekai::action_binding::ActionBinding,
        cursor: &crate::sekai::action_binding::ActionBindingCursor,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.advance_action_binding_cursor(binding, cursor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_action_binding_cursor(binding, cursor, now_ms)
            }),
        }
    }

    pub fn put_fence_binding(
        &self,
        binding: &crate::sekai::fence_binding::FenceBinding,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::fence_binding::FenceBinding, String> {
        match self {
            Self::Sqlite(db) => db.put_fence_binding(binding, actor, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_fence_binding(binding, actor, now_ms))
            }
        }
    }

    pub fn get_fence_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<
        Option<(
            crate::sekai::fence_binding::FenceBinding,
            Option<crate::sekai::fence_binding::FenceEventId>,
        )>,
        String,
    > {
        match self {
            Self::Sqlite(db) => db.get_fence_binding(namespace, binding_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_fence_binding(namespace, binding_id))
            }
        }
    }

    pub fn lease_fence_run(
        &self,
        binding: &crate::sekai::fence_binding::FenceBinding,
        run_id: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.lease_fence_run(binding, run_id, renew, now_ms, until_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.lease_fence_run(binding, run_id, renew, now_ms, until_ms)
            }),
        }
    }

    pub fn release_fence_run(
        &self,
        binding: &crate::sekai::fence_binding::FenceBinding,
        run_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_fence_run(binding, run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.release_fence_run(binding, run_id))
            }
        }
    }

    pub fn advance_fence_binding(
        &self,
        binding: &crate::sekai::fence_binding::FenceBinding,
        run_id: &str,
        through: crate::sekai::fence_binding::FenceEventId,
        receipts: &[crate::sekai::fence_binding::FenceEventReceipt],
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.advance_fence_binding(binding, run_id, through, receipts, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_fence_binding(binding, run_id, through, receipts, now_ms)
            }),
        }
    }

    pub fn list_fence_binding_receipts(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Vec<crate::sekai::fence_binding::FenceEventReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.list_fence_binding_receipts(namespace, binding_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_fence_binding_receipts(namespace, binding_id)
            }),
        }
    }

    pub fn decide_parked_action_instance(
        &self,
        decided: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.decide_parked_action_instance(decided),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.decide_parked_action_instance(decided))
            }
        }
    }

    pub fn update_parked_action_instance(
        &self,
        instance: &crate::sekai::action_instance::ActionInstance,
        expected_assignee: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.transition_action_instance(
                crate::sekai::action_instance::STATUS_PARKED,
                instance,
                expected_assignee,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.transition_action_instance(
                    crate::sekai::action_instance::STATUS_PARKED,
                    instance,
                    expected_assignee,
                )
            }),
        }
    }

    pub fn grant_parked_action_instance(
        &self,
        granted: &crate::sekai::action_instance::ActionInstance,
        target_object_id: &str,
        parked_object_digest: &str,
        write: Option<&crate::sekai::action_instance::ParkedGrantWrite>,
        references: &[crate::sekai::action_instance::PlanReference],
        actor: &str,
        claim: Option<&crate::sekai::action_instance::ExecutionClaim>,
    ) -> Result<crate::sekai::action_instance::ParkedGrantOutcome, String> {
        match self {
            Self::Sqlite(db) => db.grant_parked_action_instance(
                granted,
                target_object_id,
                parked_object_digest,
                write,
                references,
                actor,
                claim,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.grant_parked_action_instance(
                    granted,
                    target_object_id,
                    parked_object_digest,
                    write,
                    references,
                    actor,
                    claim,
                )
            }),
        }
    }

    /// Returns a granted instance to `parked` when its grant could not be
    /// recorded, so the decision can be retried.
    pub fn repark_action_instance(
        &self,
        parked: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.transition_action_instance(
                crate::sekai::action_instance::STATUS_ADMITTED,
                parked,
                &parked.review.assignee,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.transition_action_instance(
                    crate::sekai::action_instance::STATUS_ADMITTED,
                    parked,
                    &parked.review.assignee,
                )
            }),
        }
    }

    /// See [`crate::sekai::action_instance::AdmissionLease`] (#1930).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_admission_object_write(
        &self,
        instance_id: &str,
        lease: &crate::sekai::action_instance::AdmissionLease,
        write: &crate::sekai::action_instance::ParkedGrantWrite,
        expected: Option<&crate::domain::Object>,
        references: &[crate::sekai::action_instance::PlanReference],
        actor: &str,
        attribution: &crate::sekai::audit::ChangeAttribution,
    ) -> Result<
        crate::sekai::action_instance::FencedAdmissionWrite<Option<crate::domain::Object>>,
        String,
    > {
        match self {
            Self::Sqlite(db) => db.apply_admission_object_write(
                instance_id,
                lease,
                write,
                expected,
                references,
                actor,
                attribution,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.apply_admission_object_write(
                    instance_id,
                    lease,
                    write,
                    expected,
                    references,
                    actor,
                    attribution,
                )
            }),
        }
    }

    pub fn put_admission_receipt(
        &self,
        instance_id: &str,
        lease: &crate::sekai::action_instance::AdmissionLease,
        receipt: &OperationReceipt,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.put_admission_receipt(instance_id, lease, receipt),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_admission_receipt(instance_id, lease, receipt)
            }),
        }
    }

    pub fn put_admission_receipt_checked(
        &self,
        instance_id: &str,
        lease: &crate::sekai::action_instance::AdmissionLease,
        receipt: &OperationReceipt,
        check: crate::sekai::action_instance::CommitCheck,
    ) -> Result<crate::sekai::action_instance::FencedAdmissionWrite<()>, String> {
        match self {
            Self::Sqlite(db) => {
                db.put_admission_receipt_checked(instance_id, lease, receipt, check)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.put_admission_receipt_checked(instance_id, lease, receipt, check)
            }),
        }
    }

    pub fn take_over_admission(
        &self,
        instance: &crate::sekai::action_instance::ActionInstance,
        expired: &crate::sekai::action_instance::AdmissionLease,
        next: &crate::sekai::action_instance::AdmissionLease,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.take_over_admission(instance, expired, next),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.take_over_admission(instance, expired, next))
            }
        }
    }

    pub fn mark_decision_follow_ups_recorded(&self, instance_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.mark_decision_follow_ups_recorded(instance_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.mark_decision_follow_ups_recorded(instance_id)
            }),
        }
    }

    pub fn mark_admission_follow_ups_recorded(&self, instance_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.mark_admission_follow_ups_recorded(instance_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.mark_admission_follow_ups_recorded(instance_id)
            }),
        }
    }

    pub fn release_admission(
        &self,
        instance_id: &str,
        lease: &crate::sekai::action_instance::AdmissionLease,
        undo: &crate::sekai::action_instance::AdmissionUndo,
        actor: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.release_admission(instance_id, lease, undo, actor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_admission(instance_id, lease, undo, actor)
            }),
        }
    }

    pub fn delete_action_instance_fenced(
        &self,
        instance_id: &str,
        lease: &crate::sekai::action_instance::AdmissionLease,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_action_instance_fenced(instance_id, lease),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_action_instance_fenced(instance_id, lease)
            }),
        }
    }

    pub fn delete_action_instance(&self, instance_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_action_instance(instance_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.delete_action_instance(instance_id))
            }
        }
    }

    pub fn get_action_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance(instance_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_action_instance(instance_id))
            }
        }
    }

    pub fn get_action_instance_by_operation_id(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance_by_operation_id(operation_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_action_instance_by_operation_id(operation_id)
            }),
        }
    }

    pub fn get_action_instance_by_idempotency(
        &self,
        namespace: &str,
        idempotency_key: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance_by_idempotency(namespace, idempotency_key),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_action_instance_by_idempotency(namespace, idempotency_key)
            }),
        }
    }

    pub fn list_action_instances(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_instance::ActionInstance>, String> {
        self.list_action_instances_page(namespace, type_id, status, limit, 0)
    }

    pub fn list_action_instances_page(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_action_instances_page(namespace, type_id, status, limit, offset)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_action_instances_page(namespace, type_id, status, limit, offset)
            }),
        }
    }

    pub fn put_action_effects(
        &self,
        effects: &[crate::sekai::action_effect::ActionEffect],
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.put_action_effects(effects),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_action_effects(effects))
            }
        }
    }

    /// Inserts the effects not already stored, by effect id, leaving stored
    /// ones as they are (#1943).
    pub fn put_missing_action_effects(
        &self,
        effects: &[crate::sekai::action_effect::ActionEffect],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_missing_action_effects(effects),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_missing_action_effects(effects))
            }
        }
    }

    pub fn get_action_effect(
        &self,
        effect_id: &str,
    ) -> Result<Option<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_effect(effect_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_action_effect(effect_id))
            }
        }
    }

    pub fn list_action_effects_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_effects_for_instance(instance_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_action_effects_for_instance(instance_id)
            }),
        }
    }

    pub fn list_pending_runtime_dispatch_effects(
        &self,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        self.list_pending_runtime_dispatch_effects_page(namespace, limit, None)
    }

    pub fn list_pending_runtime_dispatch_effects_page(
        &self,
        namespace: &str,
        limit: usize,
        cursor: Option<(i64, &str)>,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_pending_runtime_dispatch_effects_page(namespace, limit, cursor)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_pending_runtime_dispatch_effects_page(namespace, limit, cursor)
            }),
        }
    }

    pub fn list_claimable_action_work(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        self.list_claimable_action_work_page(namespace, runtime_id, now_ms, limit, None)
    }

    pub fn list_claimable_action_work_page(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
        cursor: Option<(i64, &str)>,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_claimable_action_work_page(namespace, runtime_id, now_ms, limit, cursor)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_claimable_action_work_page(namespace, runtime_id, now_ms, limit, cursor)
            }),
        }
    }

    /// Claim runtime work for `runtime_id`, recording the authenticated
    /// `principal` that holds the claim.
    pub fn claim_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        request_id: &str,
        principal: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        match self {
            Self::Sqlite(db) => {
                db.claim_action_work(effect_id, runtime_id, request_id, principal, ttl_ms, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_action_work(effect_id, runtime_id, request_id, principal, ttl_ms, now_ms)
            }),
        }
    }

    pub fn heartbeat_action_claim(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        match self {
            Self::Sqlite(db) => db.heartbeat_action_claim(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                ttl_ms,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.heartbeat_action_claim(
                    effect_id,
                    runtime_id,
                    generation,
                    fencing_token,
                    ttl_ms,
                    now_ms,
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ack_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        outcome: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        match self {
            Self::Sqlite(db) => db.ack_action_work(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                outcome,
                reason,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.ack_action_work(
                    effect_id,
                    runtime_id,
                    generation,
                    fencing_token,
                    outcome,
                    reason,
                    now_ms,
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn park_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        reason: &str,
        request_id: &str,
        checkpoint_store_id: &str,
        checkpoint_ref: &str,
        checkpoint_digest: &str,
        parked_by: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::parked_work::ParkResult, String> {
        match self {
            Self::Sqlite(db) => db.park_action_work(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                reason,
                request_id,
                checkpoint_store_id,
                checkpoint_ref,
                checkpoint_digest,
                parked_by,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.park_action_work(
                    effect_id,
                    runtime_id,
                    generation,
                    fencing_token,
                    reason,
                    request_id,
                    checkpoint_store_id,
                    checkpoint_ref,
                    checkpoint_digest,
                    parked_by,
                    now_ms,
                )
            }),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_parked_resolution(
        &self,
        effect_id: &str,
        expected_park_generation: u64,
        input_json: &str,
        reason: &str,
        request_id: &str,
        submitted_by: &str,
        policy_version: &str,
        status: &str,
        approval_id: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::parked_work::ResolutionResult, String> {
        match self {
            Self::Sqlite(db) => db.submit_parked_resolution(
                effect_id,
                expected_park_generation,
                input_json,
                reason,
                request_id,
                submitted_by,
                policy_version,
                status,
                approval_id,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.submit_parked_resolution(
                    effect_id,
                    expected_park_generation,
                    input_json,
                    reason,
                    request_id,
                    submitted_by,
                    policy_version,
                    status,
                    approval_id,
                    now_ms,
                )
            }),
        }
    }

    pub fn invoke_parked_resolution(
        &self,
        resolution_action_id: &str,
        effect_id: &str,
        park_generation: u64,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::parked_work::ActionWorkContinuation, String> {
        match self {
            Self::Sqlite(db) => db.invoke_parked_resolution(
                resolution_action_id,
                effect_id,
                park_generation,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.invoke_parked_resolution(
                    resolution_action_id,
                    effect_id,
                    park_generation,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn mark_parked_resolution_accounted(
        &self,
        resolution_action_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.mark_parked_resolution_accounted(resolution_action_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.mark_parked_resolution_accounted(resolution_action_id)
            }),
        }
    }

    pub fn reserve_parked_resolution_execution(
        &self,
        resolution_action_id: &str,
        effect_id: &str,
        park_generation: u64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.reserve_parked_resolution_execution(
                resolution_action_id,
                effect_id,
                park_generation,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reserve_parked_resolution_execution(
                    resolution_action_id,
                    effect_id,
                    park_generation,
                )
            }),
        }
    }

    pub fn authorize_parked_resolution_approval(
        &self,
        resolution_action_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.authorize_parked_resolution_approval(resolution_action_id, approval_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.authorize_parked_resolution_approval(resolution_action_id, approval_id)
            }),
        }
    }

    pub fn bind_parked_resolution_approval(
        &self,
        resolution_action_id: &str,
        approval_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.bind_parked_resolution_approval(resolution_action_id, approval_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.bind_parked_resolution_approval(resolution_action_id, approval_id)
            }),
        }
    }

    pub fn reject_parked_resolution(
        &self,
        approval_id: &str,
        status: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.reject_parked_resolution(approval_id, status, actor, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.reject_parked_resolution(approval_id, status, actor, now_ms)
            }),
        }
    }

    pub fn get_active_continuation(
        &self,
        effect: &crate::sekai::action_effect::ActionEffect,
    ) -> Result<
        Option<(
            crate::sekai::parked_work::ActionWorkContinuation,
            crate::sekai::parked_work::ActionWorkPark,
        )>,
        String,
    > {
        match self {
            Self::Sqlite(db) => db.get_active_continuation(effect),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_active_continuation(effect))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn report_action_claim_event(
        &self,
        effect_id: &str,
        runtime_id: &str,
        generation: u64,
        fencing_token: &str,
        kind: &str,
        checkpoint_digest: &str,
        reason_code: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.report_action_claim_event(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                kind,
                checkpoint_digest,
                reason_code,
                request_id,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.report_action_claim_event(
                    effect_id,
                    runtime_id,
                    generation,
                    fencing_token,
                    kind,
                    checkpoint_digest,
                    reason_code,
                    request_id,
                    now_ms,
                )
            }),
        }
    }

    pub fn resolve_action_policy(
        &self,
        actor: &str,
        namespace: &str,
        project: &str,
    ) -> Result<Option<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.resolve_action_policy(actor, namespace, project),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.resolve_action_policy(actor, namespace, project)
            }),
        }
    }

    pub fn upsert_action_policy(&self, policy: &ActionPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_action_policy(policy),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.upsert_action_policy(policy))
            }
        }
    }

    pub fn list_decisions_for_action_namespace(
        &self,
        action: &str,
        namespace: &str,
    ) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_decisions_for_action_namespace(action, namespace),
            Self::Postgres(_) => Err("list_decisions_for_action_namespace is unavailable on the PostgreSQL community runtime".into()),
        }
    }
}
