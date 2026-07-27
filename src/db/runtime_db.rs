//! Dual-backend community store used by the public control plane.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use crate::db::postgres::PostgresDb;
use crate::db::sekai::{PrincipalCredential, SekaiDb};
use std::sync::Arc;

use crate::chisei::eval;
use crate::chisei::evolve;
use crate::chisei::external_action::{
    AuthorizationClaim, AuthorizationRecord, ExternalActionRequest,
};
use crate::chisei::external_permit::{
    ExternalPermitPolicy, HostContext, Permit, Redemption, RedemptionTiming,
};
use crate::chisei::kioku::*;
use crate::chisei::portfolio::{FrontierPoint, Objective, Observation, RouteSelection};
use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use crate::chisei::scoring::SampleObservation;
use crate::domain::{Direction, Link, ListFilter, Object, ObjectSet};
use crate::sekai::action::ActionTypeDef;
use crate::sekai::action_approval::{ActionApproval, ApprovalStatus};
use crate::sekai::action_policy::ActionPolicy;
use crate::sekai::attestation::{AttestationVerification, PolicyAttestation};
use crate::sekai::audit::{Decision, DecisionFilter, ObjectChange};
use crate::sekai::capability_package::*;
use crate::sekai::coordination::*;
use crate::sekai::dataset::{Dataset, DatasetRedaction, RowFilter, RowQuery, VirtualTable};
use crate::sekai::deduplication::*;
use crate::sekai::evidence::{EvidenceClassification, EvidenceEnvelope, EvidenceLifecycleState};
use crate::sekai::evidence_projection::EvidenceProjectionOutcome;
use crate::sekai::evidence_store::{
    EvidenceAdmission, EvidenceProducerCapability, EvidenceSchemaDefinition,
    EvidenceSubmissionFilter, EvidenceSubmissionRecord, UsableEvidenceContext,
};
use crate::sekai::execution_evidence::*;
use crate::sekai::function::Function;
use crate::sekai::handoff::*;
use crate::sekai::lease::{Lease, LeaseError};
use crate::sekai::ledger::*;
use crate::sekai::observation::{TaskObservation, TaskObservationBaseline, *};
use crate::sekai::ontology::*;
use crate::sekai::retention::*;
use crate::sekai::schema::*;
use crate::sekai::security::*;
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Instant;

#[derive(Clone)]
pub enum RuntimeDb {
    Sqlite(Arc<SekaiDb>),
    Postgres(Arc<PostgresDb>),
}

impl std::fmt::Debug for RuntimeDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sqlite(_) => "RuntimeDb::Sqlite",
            Self::Postgres(_) => "RuntimeDb::Postgres",
        })
    }
}

impl RuntimeDb {
    /// In-memory SQLite store for tests.
    pub fn memory() -> Self {
        Self::Sqlite(Arc::new(SekaiDb::new(":memory:").expect("memory sqlite")))
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Sqlite(_) => "sqlite",
            Self::Postgres(_) => "postgres",
        }
    }

    pub fn db_lock_poisoned_total(&self) -> u64 {
        match self {
            Self::Sqlite(db) => db.db_lock_poisoned_total(),
            Self::Postgres(_) => 0,
        }
    }

    pub fn enterprise_extension(&self) -> Option<&Arc<dyn crate::enterprise::EnterpriseExtension>> {
        match self {
            Self::Sqlite(db) => db.enterprise_extension(),
            Self::Postgres(_) => None,
        }
    }

    pub fn as_sqlite(&self) -> Option<&SekaiDb> {
        match self {
            Self::Sqlite(db) => Some(db.as_ref()),
            Self::Postgres(_) => None,
        }
    }

    pub fn as_sqlite_arc(&self) -> Option<Arc<SekaiDb>> {
        match self {
            Self::Sqlite(db) => Some(db.clone()),
            Self::Postgres(_) => None,
        }
    }

    pub fn require_sqlite_arc(&self) -> Result<Arc<SekaiDb>, String> {
        self.as_sqlite_arc().ok_or_else(|| {
            "this code path still requires the SQLite community store; PostgreSQL dual-wiring is incomplete for this operation"
                .into()
        })
    }

    pub fn ping(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.ping(),
            Self::Postgres(db) => db.ping(),
        }
    }

    pub fn list_active_credentials(&self) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_active_credentials(),
            Self::Postgres(db) => db.list_active_credentials(),
        }
    }

    pub fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.get_principal_credential(token_hash),
            Self::Postgres(db) => db.get_principal_credential(token_hash),
        }
    }

    pub fn record_decision(&self, decision: &Decision) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decision(decision),
            Self::Postgres(db) => db.record_decision(decision),
        }
    }

    pub fn list_decisions(&self, filter: &DecisionFilter) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_decisions(filter),
            Self::Postgres(db) => db.list_decisions(filter),
        }
    }

    pub fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_object(id),
            Self::Postgres(db) => db.get_object(id),
        }
    }

    pub fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_operation_receipt(receipt),
            Self::Postgres(db) => db.put_operation_receipt(receipt),
        }
    }

    pub fn get_operation_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.get_operation_receipt(operation_id),
            Self::Postgres(db) => db.get_operation_receipt(operation_id),
        }
    }

    /// List operation receipts for a namespace overlapping `[start, end)`.
    pub fn list_operation_receipts_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.list_operation_receipts_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
            Self::Postgres(db) => db.list_operation_receipts_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
        }
    }

    pub fn list_compliance_decisions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_compliance_decisions_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
            Self::Postgres(db) => db.list_compliance_decisions_in_window(
                namespace,
                start_timestamp_ms,
                end_timestamp_ms,
                limit,
            ),
        }
    }

    pub fn abandon_external_action_claim(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.abandon_external_action_claim(request, request_digest),
            Self::Postgres(db) => db.abandon_external_action_claim(request, request_digest),
        }
    }

    pub fn acquire_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        match self {
            Self::Sqlite(db) => db.acquire_lease(
                namespace, key, owner, ttl_ms, request_id, actor, site_id, now_ms,
            ),
            Self::Postgres(db) => db.acquire_lease(
                namespace, key, owner, ttl_ms, request_id, actor, site_id, now_ms,
            ),
        }
    }

    pub fn add_blast_radius(
        &self,
        work_unit: &str,
        mutations: u32,
        deletes: u32,
    ) -> Result<(u32, u32), String> {
        match self {
            Self::Sqlite(db) => db.add_blast_radius(work_unit, mutations, deletes),
            Self::Postgres(db) => db.add_blast_radius(work_unit, mutations, deletes),
        }
    }

    pub fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String> {
        match self {
            Self::Sqlite(db) => db.append_operation_receipt_event(operation_id, event),
            Self::Postgres(db) => db.append_operation_receipt_event(operation_id, event),
        }
    }

    pub fn append_rows(
        &self,
        dataset_id: &str,
        rows: &[HashMap<String, String>],
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.append_rows(dataset_id, rows),
            Self::Postgres(_) => {
                Err("append_rows is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn append_run_event(&self, event: &RunEvent) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.append_run_event(event),
            Self::Postgres(db) => db.append_run_event(event),
        }
    }

    pub fn authorize_operation_reporter(
        &self,
        operation_id: &str,
        principal: &str,
        event_kinds: Vec<ReceiptEventKind>,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.authorize_operation_reporter(operation_id, principal, event_kinds)
            }
            Self::Postgres(db) => {
                db.authorize_operation_reporter(operation_id, principal, event_kinds)
            }
        }
    }

    pub fn budget_adjust_chain(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_adjust_chain(scope_id, metric, delta, now_ms),
            Self::Postgres(db) => db.budget_adjust_chain(scope_id, metric, delta, now_ms),
        }
    }

    pub fn budget_check_and_reserve_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_and_reserve_chain(scope_id, metric, amount, now_ms),
            Self::Postgres(db) => {
                db.budget_check_and_reserve_chain(scope_id, metric, amount, now_ms)
            }
        }
    }

    pub fn budget_check_and_reserve_chain_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_and_reserve_chain_idempotent(
                scope_id,
                metric,
                amount,
                now_ms,
                idempotency_key,
            ),
            Self::Postgres(db) => db.budget_check_and_reserve_chain_idempotent(
                scope_id,
                metric,
                amount,
                now_ms,
                idempotency_key,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_check_and_reserve_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: Option<&str>,
        require_home_pin: bool,
        local_site_id: &str,
        partition_simulated: bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_and_reserve_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                idempotency_key,
                require_home_pin,
                local_site_id,
                partition_simulated,
            ),
            Self::Postgres(db) => db.budget_check_and_reserve_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                idempotency_key,
                require_home_pin,
                local_site_id,
                partition_simulated,
            ),
        }
    }

    pub fn budget_check_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_chain(scope_id, metric, amount, now_ms),
            Self::Postgres(db) => db.budget_check_chain(scope_id, metric, amount, now_ms),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_check_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
        partition_simulated: bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_check_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                require_home_pin,
                local_site_id,
                partition_simulated,
            ),
            Self::Postgres(db) => db.budget_check_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                require_home_pin,
                local_site_id,
                partition_simulated,
            ),
        }
    }

    pub fn budget_assert_home_writable(
        &self,
        scope_id: &str,
        metric: &str,
        local_site_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_assert_home_writable(scope_id, metric, local_site_id),
            Self::Postgres(db) => db.budget_assert_home_writable(scope_id, metric, local_site_id),
        }
    }

    pub fn budget_adjust_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_adjust_chain_for_site(
                scope_id,
                metric,
                delta,
                now_ms,
                require_home_pin,
                local_site_id,
            ),
            Self::Postgres(db) => db.budget_adjust_chain_for_site(
                scope_id,
                metric,
                delta,
                now_ms,
                require_home_pin,
                local_site_id,
            ),
        }
    }

    pub fn budget_set_limit_scoped(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
        home_site_id: &str,
        pool_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_set_limit_scoped(
                scope_id,
                metric,
                max_amount,
                period_type,
                home_site_id,
                pool_id,
            ),
            Self::Postgres(db) => db.budget_set_limit_scoped(
                scope_id,
                metric,
                max_amount,
                period_type,
                home_site_id,
                pool_id,
            ),
        }
    }

    pub fn budget_set_pool_ceiling(
        &self,
        pool_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.budget_set_pool_ceiling(pool_id, metric, max_amount, period_type)
            }
            Self::Postgres(db) => {
                db.budget_set_pool_ceiling(pool_id, metric, max_amount, period_type)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_transfer_capacity(
        &self,
        transfer_id: &str,
        metric: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::db::chisei_budget::BudgetTransferRecord, String> {
        match self {
            Self::Sqlite(db) => db.budget_transfer_capacity(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => db.budget_transfer_capacity(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                now_ms,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_record_transfer_refused(
        &self,
        transfer_id: &str,
        metric: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<crate::db::chisei_budget::BudgetTransferRecord, String> {
        match self {
            Self::Sqlite(db) => db.budget_record_transfer_refused(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                reason,
                now_ms,
            ),
            Self::Postgres(db) => db.budget_record_transfer_refused(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                reason,
                now_ms,
            ),
        }
    }

    pub fn budget_get_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<Option<crate::db::chisei_budget::BudgetTransferRecord>, String> {
        match self {
            Self::Sqlite(db) => db.budget_get_transfer(transfer_id),
            Self::Postgres(db) => db.budget_get_transfer(transfer_id),
        }
    }

    pub fn budget_limits_for_scope(
        &self,
        scope_id: &str,
    ) -> Result<Vec<(String, String, i64, String)>, String> {
        match self {
            Self::Sqlite(db) => db.budget_limits_for_scope(scope_id),
            Self::Postgres(_) => Err(
                "budget_limits_for_scope is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn budget_namespace_pressure(
        &self,
        namespace: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.budget_namespace_pressure(namespace, metric, now_ms),
            Self::Postgres(db) => db.budget_namespace_pressure(namespace, metric, now_ms),
        }
    }

    pub fn budget_record_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.budget_record_idempotent(scope_id, metric, amount, idempotency_key, now_ms)
            }
            Self::Postgres(db) => {
                db.budget_record_idempotent(scope_id, metric, amount, idempotency_key, now_ms)
            }
        }
    }

    pub fn budget_set_limit(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.budget_set_limit(scope_id, metric, max_amount, period_type),
            Self::Postgres(db) => db.budget_set_limit(scope_id, metric, max_amount, period_type),
        }
    }

    pub fn budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String> {
        match self {
            Self::Sqlite(db) => db.budget_usage(scope_id, metric, now_ms),
            Self::Postgres(db) => db.budget_usage(scope_id, metric, now_ms),
        }
    }

    pub fn bump_observation_attempts(&self, request_id: &str) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.bump_observation_attempts(request_id),
            Self::Postgres(db) => db.bump_observation_attempts(request_id),
        }
    }

    pub fn cancel_work_unit(
        &self,
        work_unit_id: &str,
        cancel_reason: &str,
        now_ms: i64,
    ) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.cancel_work_unit(work_unit_id, cancel_reason, now_ms),
            Self::Postgres(db) => db.cancel_work_unit(work_unit_id, cancel_reason, now_ms),
        }
    }

    pub fn claim_external_action_authorization(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
        authorization_id: &str,
        now_ms: i64,
    ) -> Result<AuthorizationClaim, String> {
        match self {
            Self::Sqlite(db) => db.claim_external_action_authorization(
                request,
                request_digest,
                authorization_id,
                now_ms,
            ),
            Self::Postgres(db) => db.claim_external_action_authorization(
                request,
                request_digest,
                authorization_id,
                now_ms,
            ),
        }
    }

    pub fn claim_gateway_request_alias_dispatch(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
        dispatch_token: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.claim_gateway_request_alias_dispatch(
                caller_scope,
                request_alias,
                request_id,
                operation_id,
                dispatch_token,
            ),
            Self::Postgres(db) => db.claim_gateway_request_alias_dispatch(
                caller_scope,
                request_alias,
                request_id,
                operation_id,
                dispatch_token,
            ),
        }
    }

    pub fn compare_and_swap_external_action_authorization(
        &self,
        expected: &AuthorizationRecord,
        next: &AuthorizationRecord,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.compare_and_swap_external_action_authorization(expected, next),
            Self::Postgres(db) => db.compare_and_swap_external_action_authorization(expected, next),
        }
    }

    pub fn complete_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.complete_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => db.complete_work_unit(work_unit_id, now_ms),
        }
    }

    pub fn contention_scope_chain(&self, scope_id: &str) -> Result<Vec<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.contention_scope_chain(scope_id),
            Self::Postgres(db) => db.contention_scope_chain(scope_id),
        }
    }

    pub fn coordination_snapshot(&self, now_ms: i64) -> Result<CoordinationSnapshot, String> {
        match self {
            Self::Sqlite(db) => db.coordination_snapshot(now_ms),
            Self::Postgres(db) => db.coordination_snapshot(now_ms),
        }
    }

    pub fn create_action_approval(&self, approval: &ActionApproval) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_action_approval(approval),
            Self::Postgres(db) => db.create_action_approval(approval),
        }
    }

    pub fn create_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_contention_scope(scope),
            Self::Postgres(db) => db.create_contention_scope(scope),
        }
    }

    pub fn create_dataset(&self, d: &Dataset) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_dataset(d),
            Self::Postgres(db) => db.create_dataset(d),
        }
    }

    pub fn create_function(&self, f: &Function) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_function(f),
            Self::Postgres(db) => db.create_function(f),
        }
    }

    pub fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_grant(grant),
            Self::Postgres(db) => db.create_grant(grant),
        }
    }

    pub fn create_handoff(
        &self,
        manifest: &HandoffManifest,
        request_id: &str,
    ) -> Result<HandoffManifest, String> {
        match self {
            Self::Sqlite(db) => db.create_handoff(manifest, request_id),
            Self::Postgres(db) => db.create_handoff(manifest, request_id),
        }
    }

    pub fn create_link(&self, l: &Link) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_link(l),
            Self::Postgres(db) => db.create_link(l),
        }
    }

    pub fn create_link_once(&self, l: &Link) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.create_link_once(l),
            Self::Postgres(db) => db.create_link_once(l),
        }
    }

    pub fn create_managed_team_credential(
        &self,
        principal: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<PrincipalCredential, String> {
        match self {
            Self::Sqlite(db) => db.create_managed_team_credential(principal, token_hash, now),
            Self::Postgres(_) => Err(
                "create_managed_team_credential is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn create_object(&self, o: &Object) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_object(o),
            Self::Postgres(db) => db.create_object(o),
        }
    }

    pub fn create_object_set(&self, set: &ObjectSet) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_object_set(set),
            Self::Postgres(db) => db.create_object_set(set),
        }
    }

    pub fn create_object_with_audit(&self, object: &Object, actor: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_object_with_audit(object, actor),
            Self::Postgres(db) => db.create_object_with_audit(object, actor),
        }
    }

    pub fn create_virtual_table(&self, vt: &VirtualTable) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_virtual_table(vt),
            Self::Postgres(db) => db.create_virtual_table(vt),
        }
    }

    pub fn create_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_work_unit(work_unit),
            Self::Postgres(db) => db.create_work_unit(work_unit),
        }
    }

    pub fn delete_action_type(&self, name: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_action_type(name),
            Self::Postgres(db) => db.delete_action_type(name),
        }
    }

    pub fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.delete_grant(id),
            Self::Postgres(db) => db.delete_grant(id),
        }
    }

    pub fn delete_interface(&self, name: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_interface(name),
            Self::Postgres(db) => db.delete_interface(name),
        }
    }

    pub fn delete_link(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_link(id),
            Self::Postgres(db) => db.delete_link(id),
        }
    }

    pub fn delete_object_set_for_principals(
        &self,
        id: &str,
        principals: &[&str],
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_set_for_principals(id, principals),
            Self::Postgres(db) => db.delete_object_set_for_principals(id, principals),
        }
    }

    pub fn delete_object_type(&self, kind: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_type(kind),
            Self::Postgres(db) => db.delete_object_type(kind),
        }
    }

    pub fn delete_object_with_audit(
        &self,
        id: &str,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.delete_object_with_audit(id, actor),
            Self::Postgres(db) => db.delete_object_with_audit(id, actor),
        }
    }

    pub fn delete_observation(&self, request_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_observation(request_id),
            Self::Postgres(db) => db.delete_observation(request_id),
        }
    }

    pub fn delete_ontology_class_with_audit(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_ontology_class_with_audit(name, actor),
            Self::Postgres(_) => Err("delete_ontology_class_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn delete_ontology_relation_with_audit(
        &self,
        name: &str,
        actor: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_ontology_relation_with_audit(name, actor),
            Self::Postgres(_) => Err("delete_ontology_relation_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn disable_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        match self {
            Self::Sqlite(db) => {
                db.disable_capability_package(namespace, package_name, actor, request_id, now_ms)
            }
            Self::Postgres(db) => {
                db.disable_capability_package(namespace, package_name, actor, request_id, now_ms)
            }
        }
    }

    pub fn disable_kioku_memory(
        &self,
        id: &str,
        version: u32,
        actor: &str,
        rationale: &str,
        recorded_at_ms: i64,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => {
                db.disable_kioku_memory(id, version, actor, rationale, recorded_at_ms)
            }
            Self::Postgres(db) => {
                db.disable_kioku_memory(id, version, actor, rationale, recorded_at_ms)
            }
        }
    }

    pub fn ensure_team_namespace(
        &self,
        namespace: &str,
        principal: &str,
        member_role: Role,
        actor: &str,
    ) -> Result<(Object, Vec<Grant>), String> {
        match self {
            Self::Sqlite(db) => db.ensure_team_namespace(namespace, principal, member_role, actor),
            Self::Postgres(db) => {
                db.ensure_team_namespace(namespace, principal, member_role, actor)
            }
        }
    }

    pub fn evaluate_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.evaluate_capability_package(namespace, package_name, actor, request_id, now_ms)
            }
            Self::Postgres(db) => {
                db.evaluate_capability_package(namespace, package_name, actor, request_id, now_ms)
            }
        }
    }

    pub fn evaluate_kioku_impact_if_ready(
        &self,
        id: &str,
        version: u32,
        minimum_samples_per_arm: usize,
        regression_threshold: f64,
        actor: &str,
        now_ms: i64,
    ) -> Result<Option<MemoryImpactEvaluation>, String> {
        match self {
            Self::Sqlite(db) => db.evaluate_kioku_impact_if_ready(
                id,
                version,
                minimum_samples_per_arm,
                regression_threshold,
                actor,
                now_ms,
            ),
            Self::Postgres(_) => Err(
                "evaluate_kioku_impact_if_ready is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn evidence_lifecycle_history(
        &self,
        submission_id: &str,
    ) -> Result<Vec<EvidenceLifecycleState>, String> {
        match self {
            Self::Sqlite(db) => db.evidence_lifecycle_history(submission_id),
            Self::Postgres(db) => db.evidence_lifecycle_history(submission_id),
        }
    }

    pub fn fail_work_unit(
        &self,
        work_unit_id: &str,
        failure_reason: &str,
        now_ms: i64,
    ) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.fail_work_unit(work_unit_id, failure_reason, now_ms),
            Self::Postgres(db) => db.fail_work_unit(work_unit_id, failure_reason, now_ms),
        }
    }

    pub fn find_all_by_external_id(&self, external_id: &str) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_all_by_external_id(external_id),
            Self::Postgres(db) => db.find_all_by_external_id(external_id),
        }
    }

    pub fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_by_external_id(external_id),
            Self::Postgres(db) => db.find_by_external_id(external_id),
        }
    }

    pub fn find_by_property(
        &self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_by_property(kind, key, value),
            Self::Postgres(db) => db.find_by_property(kind, key, value),
        }
    }

    pub fn find_gateway_receipt_by_logical_operation_id(
        &self,
        operation_id: &str,
        attempt: Option<u32>,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => {
                db.find_gateway_receipt_by_logical_operation_id(operation_id, attempt)
            }
            Self::Postgres(db) => {
                db.find_gateway_receipt_by_logical_operation_id(operation_id, attempt)
            }
        }
    }

    pub fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.find_namespace_boundary(namespace),
            Self::Postgres(db) => db.find_namespace_boundary(namespace),
        }
    }

    pub fn find_operation_receipt_by_lookup_request_id(
        &self,
        request_id: &str,
        caller_scope: Option<&str>,
        initiating_actor: Option<&str>,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.find_operation_receipt_by_lookup_request_id(
                request_id,
                caller_scope,
                initiating_actor,
            ),
            Self::Postgres(db) => db.find_operation_receipt_by_lookup_request_id(
                request_id,
                caller_scope,
                initiating_actor,
            ),
        }
    }

    pub fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.find_operation_receipt_by_request_id(request_id),
            Self::Postgres(db) => db.find_operation_receipt_by_request_id(request_id),
        }
    }

    pub fn get_action_approval(&self, id: &str) -> Result<Option<ActionApproval>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_approval(id),
            Self::Postgres(db) => db.get_action_approval(id),
        }
    }

    pub fn get_action_policy(&self, scope: &str) -> Result<Option<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_policy(scope),
            Self::Postgres(db) => db.get_action_policy(scope),
        }
    }

    pub fn get_attestation(&self, id: &str) -> Result<Option<PolicyAttestation>, String> {
        match self {
            Self::Sqlite(db) => db.get_attestation(id),
            Self::Postgres(db) => db.get_attestation(id),
        }
    }

    pub fn get_blast_radius(&self, work_unit: &str) -> Result<(u32, u32), String> {
        match self {
            Self::Sqlite(db) => db.get_blast_radius(work_unit),
            Self::Postgres(db) => db.get_blast_radius(work_unit),
        }
    }

    pub fn get_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Option<PackageInstallation>, String> {
        match self {
            Self::Sqlite(db) => db.get_capability_package(namespace, package_name),
            Self::Postgres(db) => db.get_capability_package(namespace, package_name),
        }
    }

    pub fn get_capability_package_manifest(
        &self,
        namespace: &str,
        package_name: &str,
        version: &str,
    ) -> Result<Option<CapabilityPackageManifest>, String> {
        match self {
            Self::Sqlite(db) => {
                db.get_capability_package_manifest(namespace, package_name, version)
            }
            Self::Postgres(db) => {
                db.get_capability_package_manifest(namespace, package_name, version)
            }
        }
    }

    pub fn get_contention_scope(&self, id: &str) -> Result<Option<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.get_contention_scope(id),
            Self::Postgres(db) => db.get_contention_scope(id),
        }
    }

    pub fn get_dataset(&self, id: &str) -> Result<Option<Dataset>, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset(id),
            Self::Postgres(db) => db.get_dataset(id),
        }
    }

    pub fn get_dedup_request(
        &self,
        request_id: &str,
        operation: &str,
    ) -> Result<Option<RequestDedup>, String> {
        match self {
            Self::Sqlite(db) => db.get_dedup_request(request_id, operation),
            Self::Postgres(db) => db.get_dedup_request(request_id, operation),
        }
    }

    pub fn get_evidence_projection_object_id(
        &self,
        submission_id: &str,
    ) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.get_evidence_projection_object_id(submission_id),
            Self::Postgres(_) => Err("get_evidence_projection_object_id is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn get_evidence_submission(
        &self,
        submission_id: &str,
    ) -> Result<Option<EvidenceSubmissionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_evidence_submission(submission_id),
            Self::Postgres(db) => db.get_evidence_submission(submission_id),
        }
    }

    pub fn get_external_action_authorization_by_id(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AuthorizationRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_external_action_authorization_by_id(authorization_id),
            Self::Postgres(db) => db.get_external_action_authorization_by_id(authorization_id),
        }
    }

    pub fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
        match self {
            Self::Sqlite(db) => db.get_external_permit_policy(scope),
            Self::Postgres(db) => db.get_external_permit_policy(scope),
        }
    }

    pub fn get_function(&self, name: &str) -> Result<Option<Function>, String> {
        match self {
            Self::Sqlite(db) => db.get_function(name),
            Self::Postgres(db) => db.get_function(name),
        }
    }

    pub fn get_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.get_grant(id),
            Self::Postgres(db) => db.get_grant(id),
        }
    }

    pub fn get_handoff(&self, id: &str) -> Result<Option<HandoffManifest>, String> {
        match self {
            Self::Sqlite(db) => db.get_handoff(id),
            Self::Postgres(db) => db.get_handoff(id),
        }
    }

    pub fn get_handoff_by_request(
        &self,
        creator_principal: &str,
        request_id: &str,
    ) -> Result<Option<(String, HandoffManifest)>, String> {
        match self {
            Self::Sqlite(db) => db.get_handoff_by_request(creator_principal, request_id),
            Self::Postgres(db) => db.get_handoff_by_request(creator_principal, request_id),
        }
    }

    pub fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.get_kioku_memory(id, version),
            Self::Postgres(db) => db.get_kioku_memory(id, version),
        }
    }

    pub fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>, LeaseError> {
        match self {
            Self::Sqlite(db) => db.get_lease(namespace, key),
            Self::Postgres(db) => db.get_lease(namespace, key),
        }
    }

    pub fn get_link(&self, id: &str) -> Result<Option<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_link(id),
            Self::Postgres(db) => db.get_link(id),
        }
    }

    pub fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
    ) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.get_linked_objects(object_id, relation, dir),
            Self::Postgres(db) => db.get_linked_objects(object_id, relation, dir),
        }
    }

    pub fn get_links(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links(object_id, relation, dir),
            Self::Postgres(db) => db.get_links(object_id, relation, dir),
        }
    }

    pub fn get_object_set(&self, id: &str) -> Result<Option<ObjectSet>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_set(id),
            Self::Postgres(db) => db.get_object_set(id),
        }
    }

    pub fn get_ontology_class(&self, name: &str) -> Result<Option<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_class(name),
            Self::Postgres(db) => db.get_ontology_class(name),
        }
    }

    pub fn get_ontology_relation(&self, name: &str) -> Result<Option<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_relation(name),
            Self::Postgres(db) => db.get_ontology_relation(name),
        }
    }

    pub fn get_work_unit(&self, id: &str) -> Result<Option<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.get_work_unit(id),
            Self::Postgres(db) => db.get_work_unit(id),
        }
    }

    pub fn get_work_unit_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.get_work_unit_by_idempotency_key(idempotency_key),
            Self::Postgres(db) => db.get_work_unit_by_idempotency_key(idempotency_key),
        }
    }

    pub fn guarded_create_object(
        &self,
        object: &Object,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, LeaseError> {
        match self {
            Self::Sqlite(db) => {
                db.guarded_create_object(object, namespace, key, token, request_id, actor, now_ms)
            }
            Self::Postgres(db) => {
                db.guarded_create_object(object, namespace, key, token, request_id, actor, now_ms)
            }
        }
    }

    pub fn guarded_delete_object(
        &self,
        object_id: &str,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_delete_object(
                object_id, expected, namespace, key, token, request_id, actor, now_ms,
            ),
            Self::Postgres(db) => db.guarded_delete_object(
                object_id, expected, namespace, key, token, request_id, actor, now_ms,
            ),
        }
    }

    pub fn guarded_object_replay(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        operation: &str,
        target_id: &str,
        request_object: &Object,
    ) -> Result<Option<Object>, LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_object_replay(
                namespace,
                key,
                token,
                request_id,
                operation,
                target_id,
                request_object,
            ),
            Self::Postgres(db) => db.guarded_object_replay(
                namespace,
                key,
                token,
                request_id,
                operation,
                target_id,
                request_object,
            ),
        }
    }

    pub fn guarded_update_object(
        &self,
        object: &Object,
        request_object: &Object,
        expected: Option<&Object>,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<Object, LeaseError> {
        match self {
            Self::Sqlite(db) => db.guarded_update_object(
                object,
                request_object,
                expected,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => db.guarded_update_object(
                object,
                request_object,
                expected,
                namespace,
                key,
                token,
                request_id,
                actor,
                now_ms,
            ),
        }
    }

    pub fn handoff_is_superseded(&self, id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.handoff_is_superseded(id),
            Self::Postgres(db) => db.handoff_is_superseded(id),
        }
    }

    pub fn heartbeat_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.heartbeat_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => db.heartbeat_work_unit(work_unit_id, now_ms),
        }
    }

    pub fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_operation_receipt(receipt),
            Self::Postgres(db) => db.insert_operation_receipt(receipt),
        }
    }

    pub fn install_capability_package(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        match self {
            Self::Sqlite(db) => {
                db.install_capability_package(namespace, manifest, actor, request_id, now_ms)
            }
            Self::Postgres(db) => {
                // Trust policy enforcement is SQLite-complete; Postgres remains
                // on the grandfather unsigned path until package-trust parity.
                db.install_capability_package(namespace, manifest, actor, request_id, now_ms)
            }
        }
    }

    pub fn set_capability_package_trust_policy(
        &self,
        namespace: &str,
        required_trust_level: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::capability_package::PackageTrustPolicy, String> {
        match self {
            Self::Sqlite(db) => db.set_capability_package_trust_policy(
                namespace,
                required_trust_level,
                actor,
                request_id,
                now_ms,
            ),
            Self::Postgres(_) => Err(
                "capability package trust policy is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn get_capability_package_trust_policy(
        &self,
        namespace: &str,
    ) -> Result<crate::sekai::capability_package::PackageTrustPolicy, String> {
        match self {
            Self::Sqlite(db) => db.get_capability_package_trust_policy(namespace),
            // Fail closed: do not invent a soft default that looks like a
            // configured policy while package-trust tables are unavailable.
            Self::Postgres(_) => Err(
                "capability package trust policy is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_capability_package_signer(
        &self,
        namespace: &str,
        identity: &str,
        key_id: &str,
        public_key_b64: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::capability_package::PackageSigner, String> {
        match self {
            Self::Sqlite(db) => db.put_capability_package_signer(
                namespace,
                identity,
                key_id,
                public_key_b64,
                actor,
                request_id,
                now_ms,
            ),
            Self::Postgres(_) => Err(
                "capability package signers are unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_capability_package_signers(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::capability_package::PackageSigner>, String> {
        match self {
            Self::Sqlite(db) => db.list_capability_package_signers(namespace),
            // Fail closed: an empty list would look like "no signers configured"
            // rather than "trust admin is unavailable on this backend".
            Self::Postgres(_) => Err(
                "capability package signers are unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn is_team_principal(&self, principal: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.is_team_principal(principal),
            Self::Postgres(db) => db.is_team_principal(principal),
        }
    }

    pub fn kioku_authorized_classification_ceiling(
        &self,
        namespace: &str,
        actor: &str,
    ) -> Result<EvidenceClassification, String> {
        match self {
            Self::Sqlite(db) => db.kioku_authorized_classification_ceiling(namespace, actor),
            Self::Postgres(_) => Err("kioku_authorized_classification_ceiling is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_action_approvals(
        &self,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ActionApproval>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_approvals(status),
            Self::Postgres(db) => db.list_action_approvals(status),
        }
    }

    pub fn list_action_policies(&self) -> Result<Vec<ActionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_policies(),
            Self::Postgres(db) => db.list_action_policies(),
        }
    }

    pub fn list_action_types(&self) -> Result<Vec<ActionTypeDef>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_types(),
            Self::Postgres(db) => db.list_action_types(),
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
            Self::Postgres(db) => db.put_governed_action_type(type_def, actor, now_ms),
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
            Self::Postgres(db) => db.get_governed_action_type(namespace, type_id, version),
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
            Self::Postgres(db) => db.list_governed_action_types(namespace, type_id, enabled_only),
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
            Self::Postgres(db) => {
                db.set_governed_action_type_enabled(namespace, type_id, version, enabled, now_ms)
            }
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
            Self::Postgres(db) => {
                db.require_enabled_governed_action_type(namespace, type_id, version)
            }
        }
    }

    pub fn put_action_instance(
        &self,
        instance: &crate::sekai::action_instance::ActionInstance,
    ) -> Result<crate::sekai::action_instance::ActionInstance, String> {
        match self {
            Self::Sqlite(db) => db.put_action_instance(instance),
            Self::Postgres(db) => db.put_action_instance(instance),
        }
    }

    pub fn get_action_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance(instance_id),
            Self::Postgres(db) => db.get_action_instance(instance_id),
        }
    }

    pub fn get_action_instance_by_idempotency(
        &self,
        namespace: &str,
        idempotency_key: &str,
    ) -> Result<Option<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_instance_by_idempotency(namespace, idempotency_key),
            Self::Postgres(db) => db.get_action_instance_by_idempotency(namespace, idempotency_key),
        }
    }

    pub fn list_action_instances(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_instance::ActionInstance>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_instances(namespace, type_id, status, limit),
            Self::Postgres(db) => db.list_action_instances(namespace, type_id, status, limit),
        }
    }

    pub fn put_action_effects(
        &self,
        effects: &[crate::sekai::action_effect::ActionEffect],
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.put_action_effects(effects),
            Self::Postgres(db) => db.put_action_effects(effects),
        }
    }

    pub fn get_action_effect(
        &self,
        effect_id: &str,
    ) -> Result<Option<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.get_action_effect(effect_id),
            Self::Postgres(db) => db.get_action_effect(effect_id),
        }
    }

    pub fn list_action_effects_for_instance(
        &self,
        instance_id: &str,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.list_action_effects_for_instance(instance_id),
            Self::Postgres(db) => db.list_action_effects_for_instance(instance_id),
        }
    }

    pub fn list_pending_runtime_dispatch_effects(
        &self,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.list_pending_runtime_dispatch_effects(namespace, limit),
            Self::Postgres(db) => db.list_pending_runtime_dispatch_effects(namespace, limit),
        }
    }

    pub fn list_claimable_action_work(
        &self,
        namespace: &str,
        runtime_id: Option<&str>,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::sekai::action_effect::ActionEffect>, String> {
        match self {
            Self::Sqlite(db) => db.list_claimable_action_work(namespace, runtime_id, now_ms, limit),
            Self::Postgres(db) => {
                db.list_claimable_action_work(namespace, runtime_id, now_ms, limit)
            }
        }
    }

    pub fn claim_action_work(
        &self,
        effect_id: &str,
        runtime_id: &str,
        request_id: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<crate::sekai::action_effect::ActionEffect, String> {
        match self {
            Self::Sqlite(db) => {
                db.claim_action_work(effect_id, runtime_id, request_id, ttl_ms, now_ms)
            }
            Self::Postgres(db) => {
                db.claim_action_work(effect_id, runtime_id, request_id, ttl_ms, now_ms)
            }
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
            Self::Postgres(db) => db.heartbeat_action_claim(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                ttl_ms,
                now_ms,
            ),
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
            Self::Postgres(db) => db.ack_action_work(
                effect_id,
                runtime_id,
                generation,
                fencing_token,
                outcome,
                reason,
                now_ms,
            ),
        }
    }

    pub fn list_all_grants(&self) -> Result<Vec<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_grants(),
            Self::Postgres(db) => db.list_all_grants(),
        }
    }

    pub fn list_all_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_objects(filter),
            Self::Postgres(_) => {
                Err("list_all_objects is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn list_attestations(
        &self,
        decision_id: Option<&str>,
        policy_scope: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<PolicyAttestation>, String> {
        match self {
            Self::Sqlite(db) => db.list_attestations(decision_id, policy_scope, limit, offset),
            Self::Postgres(db) => db.list_attestations(decision_id, policy_scope, limit, offset),
        }
    }

    pub fn list_capability_package_events(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Vec<PackageLifecycleEvent>, String> {
        match self {
            Self::Sqlite(db) => db.list_capability_package_events(namespace, package_name),
            Self::Postgres(db) => db.list_capability_package_events(namespace, package_name),
        }
    }

    pub fn list_contention_scopes(&self) -> Result<Vec<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.list_contention_scopes(),
            Self::Postgres(db) => db.list_contention_scopes(),
        }
    }

    pub fn list_datasets(&self) -> Result<Vec<Dataset>, String> {
        match self {
            Self::Sqlite(db) => db.list_datasets(),
            Self::Postgres(db) => db.list_datasets(),
        }
    }

    pub fn list_evidence_submissions(
        &self,
        filter: &EvidenceSubmissionFilter,
    ) -> Result<Vec<EvidenceSubmissionRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_evidence_submissions(filter),
            Self::Postgres(db) => db.list_evidence_submissions(filter),
        }
    }

    pub fn list_evolve_enhancements(&self) -> Result<HashMap<String, String>, String> {
        match self {
            Self::Sqlite(db) => db.list_evolve_enhancements(),
            Self::Postgres(db) => db.list_evolve_enhancements(),
        }
    }

    pub fn list_evolve_task_records(&self) -> Result<Vec<evolve::TaskRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_evolve_task_records(),
            Self::Postgres(db) => db.list_evolve_task_records(),
        }
    }

    pub fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String> {
        match self {
            Self::Sqlite(db) => db.list_external_action_authorizations(),
            Self::Postgres(db) => db.list_external_action_authorizations(),
        }
    }

    pub fn list_functions(&self) -> Result<Vec<Function>, String> {
        match self {
            Self::Sqlite(db) => db.list_functions(),
            Self::Postgres(db) => db.list_functions(),
        }
    }

    pub fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.list_grants(object_id),
            Self::Postgres(db) => db.list_grants(object_id),
        }
    }

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String> {
        match self {
            Self::Sqlite(db) => db.list_interfaces(),
            Self::Postgres(db) => db.list_interfaces(),
        }
    }

    pub fn list_kioku_candidates(
        &self,
        namespace: &str,
        operation_class: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KiokuMemory>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_candidates(namespace, operation_class, limit),
            Self::Postgres(db) => db.list_kioku_candidates(namespace, operation_class, limit),
        }
    }

    pub fn list_kioku_evidence(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<KiokuEvidenceLink>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_evidence(id, version),
            Self::Postgres(db) => db.list_kioku_evidence(id, version),
        }
    }

    pub fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_lifecycle_events(id, version),
            Self::Postgres(db) => db.list_kioku_lifecycle_events(id, version),
        }
    }

    pub fn list_kioku_outcome_assignments(
        &self,
        operation_id: &str,
    ) -> Result<Vec<MemoryOutcomeAssignment>, String> {
        match self {
            Self::Sqlite(db) => db.list_kioku_outcome_assignments(operation_id),
            Self::Postgres(_) => Err(
                "list_kioku_outcome_assignments is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_links_by_relation(&self, relation: &str) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.list_links_by_relation(relation),
            Self::Postgres(_) => Err(
                "list_links_by_relation is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_namespace_roles_for_principal(
        &self,
        principal: &str,
    ) -> Result<Vec<(String, Role)>, String> {
        match self {
            Self::Sqlite(db) => db.list_namespace_roles_for_principal(principal),
            Self::Postgres(_) => Err("list_namespace_roles_for_principal is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_object_sets_for_principals(
        &self,
        principals: &[&str],
    ) -> Result<Vec<ObjectSet>, String> {
        match self {
            Self::Sqlite(db) => db.list_object_sets_for_principals(principals),
            Self::Postgres(db) => db.list_object_sets_for_principals(principals),
        }
    }

    pub fn list_object_types_with_errors(
        &self,
    ) -> Result<(Vec<ObjectType>, HashMap<String, String>), String> {
        match self {
            Self::Sqlite(db) => db.list_object_types_with_errors(),
            Self::Postgres(_) => Err(
                "list_object_types_with_errors is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_objects_with_total_for_principals(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
    ) -> Result<(Vec<Object>, i32), String> {
        match self {
            Self::Sqlite(db) => {
                db.list_objects_with_total_for_principals(filter, principals, excluded_kinds)
            }
            Self::Postgres(db) => {
                let _ = excluded_kinds;
                db.list_objects_with_total_for_principals(filter, principals)
            }
        }
    }

    pub fn list_ontology_classes(&self) -> Result<Vec<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_classes(),
            Self::Postgres(db) => db.list_ontology_classes(),
        }
    }

    pub fn list_ontology_relations(&self) -> Result<Vec<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_relations(),
            Self::Postgres(db) => db.list_ontology_relations(),
        }
    }

    pub fn list_readable_ontology_classes(
        &self,
        principals: &[String],
        deadline: Instant,
        limit: u32,
    ) -> Result<Vec<OntologyClass>, String> {
        match self {
            Self::Sqlite(db) => db.list_readable_ontology_classes(principals, deadline, limit),
            Self::Postgres(_) => Err(
                "list_readable_ontology_classes is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_readable_ontology_relations(
        &self,
        principals: &[String],
        deadline: Instant,
        limit: u32,
    ) -> Result<Vec<OntologyRelation>, String> {
        match self {
            Self::Sqlite(db) => db.list_readable_ontology_relations(principals, deadline, limit),
            Self::Postgres(_) => Err("list_readable_ontology_relations is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_reservations(
        &self,
        filter: &ReservationFilter,
    ) -> Result<Vec<Reservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_reservations(filter),
            Self::Postgres(db) => db.list_reservations(filter),
        }
    }

    pub fn list_run_events(
        &self,
        work_unit_id: &str,
        limit: i32,
        after: i64,
        event_types: &[String],
        page_token: Option<&str>,
    ) -> Result<Vec<RunEvent>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_run_events(work_unit_id, limit, after, event_types, page_token)
            }
            Self::Postgres(db) => {
                db.list_run_events(work_unit_id, limit, after, event_types, page_token)
            }
        }
    }

    pub fn list_unbound_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_unbound_credentials(principal, status),
            Self::Postgres(_) => Err(
                "list_unbound_credentials is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_unscored_observations(
        &self,
        limit: i32,
    ) -> Result<Vec<crate::chisei::scoring::SampleObservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_unscored_observations(limit),
            Self::Postgres(db) => db.list_unscored_observations(limit),
        }
    }

    pub fn list_virtual_tables(&self) -> Result<Vec<VirtualTable>, String> {
        match self {
            Self::Sqlite(db) => db.list_virtual_tables(),
            Self::Postgres(db) => db.list_virtual_tables(),
        }
    }

    pub fn list_visible_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        match self {
            Self::Sqlite(db) => db.list_visible_object_changes(object_id, limit, offset),
            Self::Postgres(_) => Err(
                "list_visible_object_changes is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_work_units(&self, filter: &WorkUnitFilter) -> Result<Vec<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.list_work_units(filter),
            Self::Postgres(db) => db.list_work_units(filter),
        }
    }

    pub fn load_ontology_registry(&self) -> Result<OntologyRegistry, String> {
        match self {
            Self::Sqlite(db) => db.load_ontology_registry(),
            Self::Postgres(_) => Err(
                "load_ontology_registry is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn object_change_kind(&self, object_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.object_change_kind(object_id),
            Self::Postgres(_) => {
                Err("object_change_kind is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn object_change_namespace(&self, object_id: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.object_change_namespace(object_id),
            Self::Postgres(_) => Err(
                "object_change_namespace is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn project_evidence_submission(
        &self,
        submission_id: &str,
        now_ms: i64,
    ) -> Result<EvidenceProjectionOutcome, String> {
        match self {
            Self::Sqlite(db) => db.project_evidence_submission(submission_id, now_ms),
            Self::Postgres(db) => db.project_evidence_submission(submission_id, now_ms),
        }
    }

    pub fn prune_eval_iterations_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_eval_iterations_for_suite(suite_id, keep),
            Self::Postgres(db) => db.prune_eval_iterations_for_suite(suite_id, keep),
        }
    }

    pub fn prune_eval_runs_for_suite(&self, suite_id: &str, keep: i64) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_eval_runs_for_suite(suite_id, keep),
            Self::Postgres(db) => db.prune_eval_runs_for_suite(suite_id, keep),
        }
    }

    pub fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String> {
        match self {
            Self::Sqlite(db) => db.put_delegated_permit(permit, issued_by),
            Self::Postgres(_) => Err(
                "put_delegated_permit is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn put_evolve_enhancement(
        &self,
        request_id: &str,
        original_spec: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_evolve_enhancement(request_id, original_spec),
            Self::Postgres(db) => db.put_evolve_enhancement(request_id, original_spec),
        }
    }

    pub fn put_evolve_task(&self, task: &evolve::TaskRecord) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_evolve_task(task),
            Self::Postgres(db) => db.put_evolve_task(task),
        }
    }

    pub fn get_gunshi_allocation_state(&self, namespace: &str) -> Result<Option<String>, String> {
        match self {
            Self::Sqlite(db) => db.get_gunshi_allocation_state(namespace),
            Self::Postgres(_) => Err(
                "get_gunshi_allocation_state is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_gunshi_allocation_state_cas(
        &self,
        namespace: &str,
        revision_id: &str,
        changed_at_ms: i64,
        state_json: &str,
        expected_revision: Option<&str>,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.put_gunshi_allocation_state_cas(
                namespace,
                revision_id,
                changed_at_ms,
                state_json,
                expected_revision,
            ),
            Self::Postgres(_) => Err(
                "put_gunshi_allocation_state_cas is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_external_action_authorization(
        &self,
        record: &AuthorizationRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_external_action_authorization(record),
            Self::Postgres(db) => db.put_external_action_authorization(record),
        }
    }

    pub fn put_operation_receipt_with_kioku_holdouts(
        &self,
        receipt: &OperationReceipt,
        holdouts: &[(String, u32)],
        actor: &str,
        recorded_at_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_operation_receipt_with_kioku_holdouts(receipt, holdouts, actor, recorded_at_ms),
            Self::Postgres(_) => Err("put_operation_receipt_with_kioku_holdouts is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn put_permit(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        issued_by: &str,
    ) -> Result<Permit, String> {
        match self {
            Self::Sqlite(db) => db.put_permit(permit, idempotency_key, issued_by),
            Self::Postgres(db) => db.put_permit(permit, idempotency_key, issued_by),
        }
    }

    pub fn put_sample_observation(
        &self,
        obs: &crate::chisei::scoring::SampleObservation,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_sample_observation(obs),
            Self::Postgres(db) => db.put_sample_observation(obs),
        }
    }

    pub fn query_rows(
        &self,
        dataset_id: &str,
        q: &RowQuery,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        match self {
            Self::Sqlite(db) => db.query_rows(dataset_id, q),
            Self::Postgres(_) => {
                Err("query_rows is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn reconcile_missing_execution_evidence(
        &self,
        now_ms: i64,
    ) -> Result<Vec<ExecutionEvidenceAlert>, String> {
        match self {
            Self::Sqlite(db) => db.reconcile_missing_execution_evidence(now_ms),
            Self::Postgres(_) => Err("reconcile_missing_execution_evidence is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn reconcile_work_units(
        &self,
        now_ms: i64,
        filter: &ReconcileFilter,
    ) -> Result<ReconcileSummary, String> {
        match self {
            Self::Sqlite(db) => db.reconcile_work_units(now_ms, filter),
            Self::Postgres(db) => db.reconcile_work_units(now_ms, filter),
        }
    }

    pub fn record_decision_with_attestation(
        &self,
        decision: &crate::sekai::audit::Decision,
        attestation: Option<&PolicyAttestation>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decision_with_attestation(decision, attestation),
            Self::Postgres(db) => db.record_decision_with_attestation(decision, attestation),
        }
    }

    pub fn record_decisions_idempotently(&self, decisions: &[Decision]) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decisions_idempotently(decisions),
            Self::Postgres(db) => db.record_decisions_idempotently(decisions),
        }
    }

    pub fn record_dedup_request(&self, request: &RequestDedup) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_dedup_request(request),
            Self::Postgres(db) => db.record_dedup_request(request),
        }
    }

    pub fn record_execution_evidence(&self, submission_id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.record_execution_evidence(submission_id),
            Self::Postgres(_) => Err(
                "record_execution_evidence is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_lifecycle_event(event),
            Self::Postgres(db) => db.record_kioku_lifecycle_event(event),
        }
    }

    pub fn record_kioku_outcome(
        &self,
        observation: &MemoryOutcomeObservation,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_outcome(observation),
            Self::Postgres(_) => Err(
                "record_kioku_outcome is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn redeem_or_reconcile_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        timing: RedemptionTiming,
    ) -> Result<Redemption, String> {
        match self {
            Self::Sqlite(db) => db.redeem_or_reconcile_permit(
                permit,
                context,
                trusted_key,
                idempotency_key,
                execution_id,
                host_site_id,
                timing,
            ),
            Self::Postgres(_) => Err(
                "redeem_or_reconcile_permit is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn refresh_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        match self {
            Self::Sqlite(db) => db.refresh_lease(
                namespace, key, token, ttl_ms, request_id, actor, site_id, now_ms,
            ),
            Self::Postgres(db) => db.refresh_lease(
                namespace, key, token, ttl_ms, request_id, actor, site_id, now_ms,
            ),
        }
    }

    pub fn register_evidence_schema(
        &self,
        definition: &EvidenceSchemaDefinition,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.register_evidence_schema(definition, now_ms),
            Self::Postgres(db) => db.register_evidence_schema(definition, now_ms),
        }
    }

    pub fn reject_evidence_submission(
        &self,
        submission_id: &str,
        now_ms: i64,
        code: &str,
        summary: &str,
    ) -> Result<EvidenceAdmission, String> {
        match self {
            Self::Sqlite(db) => db.reject_evidence_submission(submission_id, now_ms, code, summary),
            Self::Postgres(_) => Err(
                "reject_evidence_submission is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn release_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_external_action_blast_radius(authorization_id, request),
            Self::Postgres(db) => {
                db.release_external_action_blast_radius(authorization_id, request)
            }
        }
    }

    pub fn release_lease(
        &self,
        namespace: &str,
        key: &str,
        token: &str,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        match self {
            Self::Sqlite(db) => {
                db.release_lease(namespace, key, token, request_id, actor, site_id, now_ms)
            }
            Self::Postgres(db) => {
                db.release_lease(namespace, key, token, request_id, actor, site_id, now_ms)
            }
        }
    }

    pub fn release_reservations_for_work_unit(
        &self,
        work_unit_id: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.release_reservations_for_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => db.release_reservations_for_work_unit(work_unit_id, now_ms),
        }
    }

    pub fn replay_permit(
        &self,
        authorization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Permit>, String> {
        match self {
            Self::Sqlite(db) => db.replay_permit(authorization_id, idempotency_key),
            Self::Postgres(db) => db.replay_permit(authorization_id, idempotency_key),
        }
    }

    pub fn replay_redemption(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        execution_id: &str,
    ) -> Result<Option<Redemption>, String> {
        match self {
            Self::Sqlite(db) => db.replay_redemption(permit, idempotency_key, execution_id),
            Self::Postgres(_) => {
                Err("replay_redemption is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn reserve_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
        max_mutations: Option<u32>,
        max_deletes: Option<u32>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.reserve_external_action_blast_radius(
                authorization_id,
                request,
                max_mutations,
                max_deletes,
            ),
            Self::Postgres(db) => db.reserve_external_action_blast_radius(
                authorization_id,
                request,
                max_mutations,
                max_deletes,
            ),
        }
    }

    pub fn reserve_gateway_request_alias(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.reserve_gateway_request_alias(
                caller_scope,
                request_alias,
                request_id,
                operation_id,
            ),
            Self::Postgres(db) => db.reserve_gateway_request_alias(
                caller_scope,
                request_alias,
                request_id,
                operation_id,
            ),
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
            Self::Postgres(db) => db.resolve_action_policy(actor, namespace, project),
        }
    }

    pub fn review_kioku_candidate(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => db.review_kioku_candidate(id, version, review),
            Self::Postgres(db) => db.review_kioku_candidate(id, version, review),
        }
    }

    pub fn revoke_handoff(
        &self,
        id: &str,
        actor: &str,
        reason: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<HandoffManifest, String> {
        match self {
            Self::Sqlite(db) => db.revoke_handoff(id, actor, reason, request_id, now_ms),
            Self::Postgres(db) => db.revoke_handoff(id, actor, reason, request_id, now_ms),
        }
    }

    pub fn revoke_permit(&self, handle: &str, reason: &str, now_ms: i64) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.revoke_permit(handle, reason, now_ms),
            Self::Postgres(db) => db.revoke_permit(handle, reason, now_ms),
        }
    }

    pub fn revoke_principal_credential(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.revoke_principal_credential(principal),
            Self::Postgres(db) => db.revoke_principal_credential(principal),
        }
    }

    pub fn rollback_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        match self {
            Self::Sqlite(db) => {
                db.rollback_capability_package(namespace, package_name, actor, request_id, now_ms)
            }
            Self::Postgres(db) => {
                db.rollback_capability_package(namespace, package_name, actor, request_id, now_ms)
            }
        }
    }

    pub fn rotate_managed_team_credential(
        &self,
        principal: &str,
        token_hash: &str,
    ) -> Result<PrincipalCredential, String> {
        match self {
            Self::Sqlite(db) => db.rotate_managed_team_credential(principal, token_hash),
            Self::Postgres(_) => Err(
                "rotate_managed_team_credential is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn rotate_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
    ) -> Result<PrincipalCredential, String> {
        match self {
            Self::Sqlite(db) => db.rotate_principal_credential(principal, token_hash),
            Self::Postgres(db) => db.rotate_principal_credential(principal, token_hash),
        }
    }

    pub fn set_external_permit_policy(
        &self,
        policy: &ExternalPermitPolicy,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_external_permit_policy(policy, now_ms),
            Self::Postgres(db) => db.set_external_permit_policy(policy, now_ms),
        }
    }

    pub fn set_permit_kill_switch(
        &self,
        kind: &str,
        value: &str,
        enabled: bool,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.set_permit_kill_switch(kind, value, enabled, reason, now_ms),
            Self::Postgres(db) => db.set_permit_kill_switch(kind, value, enabled, reason, now_ms),
        }
    }

    pub fn submit_evidence(
        &self,
        envelope: &EvidenceEnvelope,
        authenticated_producer: &str,
        now_ms: i64,
    ) -> Result<EvidenceAdmission, String> {
        match self {
            Self::Sqlite(db) => db.submit_evidence(envelope, authenticated_producer, now_ms),
            Self::Postgres(db) => db.submit_evidence(envelope, authenticated_producer, now_ms),
        }
    }

    pub fn takeover_expired_lease(
        &self,
        namespace: &str,
        key: &str,
        owner: &str,
        expected_token: &str,
        expected_expires_at_ms: i64,
        ttl_ms: i64,
        request_id: &str,
        actor: &str,
        site_id: &str,
        now_ms: i64,
    ) -> Result<Lease, LeaseError> {
        match self {
            Self::Sqlite(db) => db.takeover_expired_lease(
                namespace,
                key,
                owner,
                expected_token,
                expected_expires_at_ms,
                ttl_ms,
                request_id,
                actor,
                site_id,
                now_ms,
            ),
            Self::Postgres(db) => db.takeover_expired_lease(
                namespace,
                key,
                owner,
                expected_token,
                expected_expires_at_ms,
                ttl_ms,
                request_id,
                actor,
                site_id,
                now_ms,
            ),
        }
    }

    pub fn try_admit_work_unit(
        &self,
        work_unit_id: &str,
        lease_owner: &str,
        now_ms: i64,
    ) -> Result<AdmissionResult, String> {
        match self {
            Self::Sqlite(db) => db.try_admit_work_unit(work_unit_id, lease_owner, now_ms),
            Self::Postgres(db) => db.try_admit_work_unit(work_unit_id, lease_owner, now_ms),
        }
    }

    pub fn uninstall_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.uninstall_capability_package(namespace, package_name, actor, request_id, now_ms)
            }
            Self::Postgres(db) => {
                db.uninstall_capability_package(namespace, package_name, actor, request_id, now_ms)
            }
        }
    }

    pub fn update_action_approval(&self, approval: &ActionApproval) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_action_approval(approval),
            Self::Postgres(db) => db.update_action_approval(approval),
        }
    }

    pub fn update_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_contention_scope(scope),
            Self::Postgres(db) => db.update_contention_scope(scope),
        }
    }

    pub fn update_dataset(&self, d: &Dataset) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_dataset(d),
            Self::Postgres(db) => db.update_dataset(d),
        }
    }

    pub fn update_object(&self, o: &Object) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_object(o),
            Self::Postgres(db) => db.update_object(o),
        }
    }

    pub fn update_object_with_audit(
        &self,
        object: &Object,
        actor: &str,
    ) -> Result<Option<Object>, String> {
        match self {
            Self::Sqlite(db) => db.update_object_with_audit(object, actor),
            Self::Postgres(_) => Err(
                "update_object_with_audit is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn upgrade_capability_package(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        match self {
            Self::Sqlite(db) => {
                db.upgrade_capability_package(namespace, manifest, actor, request_id, now_ms)
            }
            Self::Postgres(db) => {
                db.upgrade_capability_package(namespace, manifest, actor, request_id, now_ms)
            }
        }
    }

    pub fn upsert_action_policy(&self, policy: &ActionPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_action_policy(policy),
            Self::Postgres(db) => db.upsert_action_policy(policy),
        }
    }

    pub fn upsert_action_type(&self, action_type: &ActionTypeDef) -> Result<ActionTypeDef, String> {
        match self {
            Self::Sqlite(db) => db.upsert_action_type(action_type),
            Self::Postgres(db) => db.upsert_action_type(action_type),
        }
    }

    pub fn upsert_evidence_producer(
        &self,
        capability: &EvidenceProducerCapability,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_evidence_producer(capability, now_ms),
            Self::Postgres(db) => db.upsert_evidence_producer(capability, now_ms),
        }
    }

    pub fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_interface(interface),
            Self::Postgres(db) => db.upsert_interface(interface),
        }
    }

    pub fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_object_type(object_type),
            Self::Postgres(db) => db.upsert_object_type(object_type),
        }
    }

    pub fn propose_ontology_definitions_from_evidence(
        &self,
        request: &crate::sekai::ontology_proposal::ProposeOntologyDefinitionsRequest,
    ) -> Result<crate::sekai::ontology_proposal::ProposeOntologyDefinitionsResult, String> {
        match self {
            Self::Sqlite(db) => db.propose_ontology_definitions_from_evidence(request),
            Self::Postgres(_) => Err(
                "propose_ontology_definitions_from_evidence is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn get_ontology_definition_proposal(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Option<crate::sekai::ontology_proposal::OntologyDefinitionProposal>, String> {
        match self {
            Self::Sqlite(db) => db.get_ontology_definition_proposal(id, version),
            Self::Postgres(_) => Err(
                "get_ontology_definition_proposal is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_ontology_definition_proposals(
        &self,
        filter: &crate::sekai::ontology_proposal::ProposalFilter,
    ) -> Result<Vec<crate::sekai::ontology_proposal::OntologyDefinitionProposal>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_definition_proposals(filter),
            Self::Postgres(_) => Err(
                "list_ontology_definition_proposals is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn list_ontology_definition_proposal_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<crate::sekai::ontology_proposal::ProposalLifecycleEvent>, String> {
        match self {
            Self::Sqlite(db) => db.list_ontology_definition_proposal_events(id, version),
            Self::Postgres(_) => Err(
                "list_ontology_definition_proposal_events is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn review_ontology_definition_proposal(
        &self,
        id: &str,
        version: u32,
        review: crate::sekai::ontology_proposal::OntologyProposalReview,
    ) -> Result<crate::sekai::ontology_proposal::OntologyDefinitionProposal, String> {
        match self {
            Self::Sqlite(db) => db.review_ontology_definition_proposal(id, version, review),
            Self::Postgres(_) => Err(
                "review_ontology_definition_proposal is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn upsert_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_class_with_audit(class, actor),
            Self::Postgres(_) => Err("upsert_ontology_class_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn upsert_ontology_relation_with_audit(
        &self,
        relation: &OntologyRelation,
        actor: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_relation_with_audit(relation, actor),
            Self::Postgres(_) => Err("upsert_ontology_relation_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn upsert_projected_ontology_class_with_audit(
        &self,
        class: &OntologyClass,
        actor: &str,
        source_grants: &[Grant],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_projected_ontology_class_with_audit(class, actor, source_grants),
            Self::Postgres(_) => Err("upsert_projected_ontology_class_with_audit is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_delegation_chain(permit),
            Self::Postgres(_) => Err(
                "validate_delegation_chain is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn validate_execution_evidence_envelope(
        &self,
        envelope: &crate::sekai::evidence::EvidenceEnvelope,
        authenticated_producer: &str,
    ) -> Result<Option<ExecutionEvidence>, String> {
        match self {
            Self::Sqlite(db) => db.validate_execution_evidence_envelope(envelope, authenticated_producer),
            Self::Postgres(_) => Err("validate_execution_evidence_envelope is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn validate_kioku_candidate(
        &self,
        id: &str,
        version: u32,
    ) -> Result<MemoryValidation, String> {
        match self {
            Self::Sqlite(db) => db.validate_kioku_candidate(id, version),
            Self::Postgres(db) => db.validate_kioku_candidate(id, version),
        }
    }

    pub fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_permit_for_delegation(permit),
            Self::Postgres(_) => Err(
                "validate_permit_for_delegation is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn validate_permit_state(&self, permit: &Permit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.validate_permit_state(permit),
            Self::Postgres(_) => Err(
                "validate_permit_state is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn verify_attestation(&self, id: &str) -> Result<AttestationVerification, String> {
        match self {
            Self::Sqlite(db) => db.verify_attestation(id),
            Self::Postgres(db) => db.verify_attestation(id),
        }
    }

    pub fn verify_ledger(&self) -> Result<LedgerVerification, String> {
        match self {
            Self::Sqlite(db) => db.verify_ledger(),
            Self::Postgres(_) => {
                Err("verify_ledger is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn update_operation_receipt<F>(
        &self,
        operation_id: &str,
        update: F,
    ) -> Result<OperationReceipt, String>
    where
        F: FnOnce(&mut OperationReceipt) -> Result<(), String>,
    {
        match self {
            Self::Sqlite(db) => db.update_operation_receipt(operation_id, update),
            Self::Postgres(_) => {
                // Read-modify-write using dual-backend get/put.
                let mut receipt = self
                    .get_operation_receipt(operation_id)?
                    .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
                update(&mut receipt)?;
                self.put_operation_receipt(&receipt)?;
                Ok(receipt)
            }
        }
    }

    pub fn action_type_target_ids(
        &self,
        action_type: &ActionTypeDef,
        params: &HashMap<String, String>,
    ) -> Result<Vec<String>, String> {
        match self {
            Self::Sqlite(db) => db.action_type_target_ids(action_type, params),
            Self::Postgres(_) => Err(
                "action_type_target_ids is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    /// SQLite-only raw connection access for legacy internals/tests.
    pub fn with_sqlite_conn<R>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> R,
    ) -> Result<R, String> {
        match self {
            Self::Sqlite(db) => {
                let conn = db.conn();
                Ok(f(&conn))
            }
            Self::Postgres(_) => Err("raw SQLite connection is unavailable on PostgreSQL".into()),
        }
    }

    pub fn execute_action_type(
        &self,
        action_type: &ActionTypeDef,
        params: &HashMap<String, String>,
        schema: &SchemaRegistry,
        actor: &str,
    ) -> Result<String, String> {
        match self {
            Self::Sqlite(db) => db.execute_action_type(action_type, params, schema, actor),
            Self::Postgres(_) => {
                Err("execute_action_type is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn get_decision(&self, id: &str) -> Result<Option<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.get_decision(id),
            Self::Postgres(db) => db.get_decision(id),
        }
    }

    pub fn put_peer_trust_root(
        &self,
        root: &crate::sekai::peer_import::PeerTrustRoot,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_peer_trust_root(root),
            Self::Postgres(_) => {
                Err("put_peer_trust_root is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn list_peer_trust_roots(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::peer_import::PeerTrustRoot>, String> {
        match self {
            Self::Sqlite(db) => db.list_peer_trust_roots(namespace),
            Self::Postgres(_) => Err(
                "list_peer_trust_roots is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn put_peer_import(
        &self,
        record: &crate::sekai::peer_import::PeerImportRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_peer_import(record),
            Self::Postgres(_) => {
                Err("put_peer_import is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn get_peer_import(
        &self,
        import_id: &str,
    ) -> Result<Option<crate::sekai::peer_import::PeerImportRecord>, String> {
        match self {
            Self::Sqlite(db) => db.get_peer_import(import_id),
            Self::Postgres(_) => {
                Err("get_peer_import is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn put_federation_local_site(
        &self,
        site: &crate::sekai::federation_profile::LocalSiteIdentity,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_local_site(site),
            Self::Postgres(_) => Err(
                "put_federation_local_site is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn get_federation_local_site(
        &self,
    ) -> Result<Option<crate::sekai::federation_profile::LocalSiteIdentity>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_local_site(),
            Self::Postgres(_) => Err(
                "get_federation_local_site is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn put_federation_peer(
        &self,
        peer: &crate::sekai::federation_profile::FederationPeer,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_federation_peer(peer),
            Self::Postgres(_) => {
                Err("put_federation_peer is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn get_federation_peer(
        &self,
        peer_site_id: &str,
    ) -> Result<Option<crate::sekai::federation_profile::FederationPeer>, String> {
        match self {
            Self::Sqlite(db) => db.get_federation_peer(peer_site_id),
            Self::Postgres(_) => {
                Err("get_federation_peer is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn list_federation_peers(
        &self,
    ) -> Result<Vec<crate::sekai::federation_profile::FederationPeer>, String> {
        match self {
            Self::Sqlite(db) => db.list_federation_peers(),
            Self::Postgres(_) => Err(
                "list_federation_peers is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn get_eval_run_record(&self, id: &str) -> Result<Option<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_run_record(id),
            Self::Postgres(db) => db.get_eval_run_record(id),
        }
    }

    pub fn get_eval_suite_record(&self, id: &str) -> Result<Option<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.get_eval_suite_record(id),
            Self::Postgres(db) => db.get_eval_suite_record(id),
        }
    }

    pub fn get_links_limited(
        &self,
        object_id: &str,
        relation: &str,
        dir: &Direction,
        limit: usize,
    ) -> Result<Vec<Link>, String> {
        match self {
            Self::Sqlite(db) => db.get_links_limited(object_id, relation, dir, limit),
            Self::Postgres(db) => db.get_links_limited(object_id, relation, dir, limit),
        }
    }

    pub fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String> {
        match self {
            Self::Sqlite(db) => db.get_object_type(kind),
            Self::Postgres(db) => db.get_object_type(kind),
        }
    }

    pub fn insert_task_observation(&self, observation: &TaskObservation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_task_observation(observation),
            Self::Postgres(_) => Err(
                "insert_task_observation is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_all_eval_iteration_records(&self) -> Result<Vec<eval::Iteration>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_eval_iteration_records(),
            Self::Postgres(db) => db.list_all_eval_iteration_records(),
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

    pub fn list_eval_iteration_records(
        &self,
        suite_id: &str,
    ) -> Result<Vec<eval::Iteration>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_iteration_records(suite_id),
            Self::Postgres(db) => db.list_eval_iteration_records(suite_id),
        }
    }

    pub fn list_eval_run_records(&self, suite_id: &str) -> Result<Vec<eval::Run>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_run_records(suite_id),
            Self::Postgres(db) => db.list_eval_run_records(suite_id),
        }
    }

    pub fn list_eval_suite_records(&self) -> Result<Vec<eval::Suite>, String> {
        match self {
            Self::Sqlite(db) => db.list_eval_suite_records(),
            Self::Postgres(db) => db.list_eval_suite_records(),
        }
    }

    pub fn list_task_observations_for_component(
        &self,
        component_id: &str,
    ) -> Result<Vec<TaskObservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_task_observations_for_component(component_id),
            Self::Postgres(_) => Err("list_task_observations_for_component is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_usable_evidence_classes_for_targets(
        &self,
        target_object_ids: &[String],
        now_ms: i64,
    ) -> Result<Vec<(String, String)>, String> {
        match self {
            Self::Sqlite(db) => db.list_usable_evidence_classes_for_targets(target_object_ids, now_ms),
            Self::Postgres(_) => Err("list_usable_evidence_classes_for_targets is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_usable_evidence_for_targets(
        &self,
        target_object_ids: &[String],
        allowed_evidence_classes: &[(String, String)],
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<UsableEvidenceContext>, String> {
        match self {
            Self::Sqlite(db) => db.list_usable_evidence_for_targets(target_object_ids, allowed_evidence_classes, now_ms, limit),
            Self::Postgres(_) => Err("list_usable_evidence_for_targets is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn list_work_unit_decisions(
        &self,
        work_unit_id: &str,
        request_ids: &BTreeSet<String>,
    ) -> Result<Vec<Decision>, String> {
        match self {
            Self::Sqlite(db) => db.list_work_unit_decisions(work_unit_id, request_ids),
            Self::Postgres(_) => Err(
                "list_work_unit_decisions is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn portfolio_damped_route(
        &self,
        namespace: &str,
        task_class: &str,
        proposed_model: &str,
        proposed_prompt_variant: &str,
        now_ms: i64,
        force: bool,
    ) -> Result<RouteSelection, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_damped_route(
                namespace,
                task_class,
                proposed_model,
                proposed_prompt_variant,
                now_ms,
                force,
            ),
            Self::Postgres(db) => db.portfolio_damped_route(
                namespace,
                task_class,
                proposed_model,
                proposed_prompt_variant,
                now_ms,
                force,
            ),
        }
    }

    pub fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_objective(namespace),
            Self::Postgres(db) => db.portfolio_objective(namespace),
        }
    }

    pub fn portfolio_points(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String> {
        match self {
            Self::Sqlite(db) => db.portfolio_points(namespace, task_class),
            Self::Postgres(db) => db.portfolio_points(namespace, task_class),
        }
    }

    pub fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.portfolio_record_observation(observation),
            Self::Postgres(db) => db.portfolio_record_observation(observation),
        }
    }

    pub fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.portfolio_set_objective(objective),
            Self::Postgres(db) => db.portfolio_set_objective(objective),
        }
    }

    pub fn principal_credentials_activity_epoch(&self) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.principal_credentials_activity_epoch(),
            Self::Postgres(db) => db.principal_credentials_activity_epoch(),
        }
    }

    pub fn put_eval_iteration(&self, iteration: &eval::Iteration) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_iteration(iteration),
            Self::Postgres(db) => db.put_eval_iteration(iteration),
        }
    }

    pub fn put_eval_run(&self, run: &eval::Run) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_run(run),
            Self::Postgres(db) => db.put_eval_run(run),
        }
    }

    pub fn put_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_eval_suite(suite),
            Self::Postgres(db) => db.put_eval_suite(suite),
        }
    }

    pub fn append_feedback_eval_suite(&self, suite: &eval::Suite) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.append_feedback_eval_suite(suite),
            Self::Postgres(_) => Err(
                "append_feedback_eval_suite is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn record_decisions_idempotently_by(
        &self,
        decisions: &[Decision],
        equivalent: impl Fn(&Decision, &Decision) -> bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_decisions_idempotently_by(decisions, equivalent),
            Self::Postgres(_) => Err("record_decisions_idempotently_by is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn record_object_changes(&self, changes: &[ObjectChange]) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_object_changes(changes),
            Self::Postgres(_) => Err(
                "record_object_changes is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn retrieve_kioku_memories(
        &self,
        request: &MemoryRetrievalRequest,
    ) -> Result<Vec<RetrievedMemory>, String> {
        match self {
            Self::Sqlite(db) => db.retrieve_kioku_memories(request),
            Self::Postgres(_) => Err(
                "retrieve_kioku_memories is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_credentials(principal, status),
            Self::Postgres(db) => db.list_credentials(principal, status),
        }
    }

    pub fn create_principal_credential(
        &self,
        principal: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<PrincipalCredential, String> {
        match self {
            Self::Sqlite(db) => db.create_principal_credential(principal, token_hash, now),
            Self::Postgres(db) => db.create_principal_credential(principal, token_hash, now),
        }
    }

    pub fn get_task_observation_baseline(
        &self,
        component_id: &str,
    ) -> Result<Option<TaskObservationBaseline>, String> {
        match self {
            Self::Sqlite(db) => db.get_task_observation_baseline(component_id),
            Self::Postgres(_) => Err(
                "get_task_observation_baseline is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn insert_task_observation_baseline(
        &self,
        component_id: &str,
        namespace: &str,
        baseline: &TaskObservationBaseline,
        created: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_task_observation_baseline(component_id, namespace, baseline, created),
            Self::Postgres(_) => Err("insert_task_observation_baseline is unavailable on the PostgreSQL community runtime".into()),
        }
    }

    pub fn get_lineage(
        &self,
        object_id: &str,
        max_nodes: usize,
    ) -> Result<crate::sekai::lineage::LineageResult, String> {
        match self {
            Self::Sqlite(db) => crate::sekai::lineage::get_lineage(db, object_id, max_nodes),
            Self::Postgres(db) => db.get_lineage(object_id, max_nodes),
        }
    }

    pub fn set_retention_policy(&self, policy: &RetentionPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_retention_policy(policy),
            Self::Postgres(db) => db.set_retention_policy(policy),
        }
    }

    pub fn list_retention_policies(&self) -> Result<Vec<RetentionPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.list_retention_policies(),
            Self::Postgres(db) => db.list_retention_policies(),
        }
    }

    pub fn erase_subject(
        &self,
        request: &SubjectErasureRequest,
    ) -> Result<SubjectErasureResult, String> {
        match self {
            Self::Sqlite(db) => db.erase_subject(request),
            Self::Postgres(db) => db.erase_subject(request),
        }
    }

    pub fn archive_retained_records(
        &self,
        archive_path: impl AsRef<Path>,
        now: i64,
    ) -> Result<ArchiveRun, String> {
        match self {
            Self::Sqlite(db) => db.archive_retained_records(archive_path, now),
            Self::Postgres(_) => Err(
                "archive_retained_records is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }

    pub fn run_retention(&self, now: i64) -> Result<RetentionRun, String> {
        match self {
            Self::Sqlite(db) => db.run_retention(now),
            Self::Postgres(_) => {
                Err("run_retention is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn purge_old_records(&self, before: i64) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.purge_old_records(before),
            Self::Postgres(_) => {
                Err("purge_old_records is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn record_object_change(&self, c: &ObjectChange) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_object_change(c),
            Self::Postgres(_) => Err(
                "record_object_change is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn list_object_changes(
        &self,
        object_id: &str,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<ObjectChange>, String> {
        match self {
            Self::Sqlite(db) => db.list_object_changes(object_id, limit, offset),
            Self::Postgres(db) => db.list_object_changes(object_id, limit, offset),
        }
    }

    pub fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_kioku_memory(memory, evidence),
            Self::Postgres(db) => db.insert_kioku_memory(memory, evidence),
        }
    }

    pub fn produce_kioku_candidate(
        &self,
        input: CandidateDerivation,
    ) -> Result<KiokuMemory, String> {
        match self {
            Self::Sqlite(db) => db.produce_kioku_candidate(input),
            Self::Postgres(_) => Err(
                "produce_kioku_candidate is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn record_kioku_holdout(
        &self,
        id: &str,
        version: u32,
        operation_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.record_kioku_holdout(id, version, operation_id, actor, now_ms),
            Self::Postgres(_) => Err(
                "record_kioku_holdout is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn sweep_kioku_lifecycle(
        &self,
        actor: &str,
        now_ms: i64,
    ) -> Result<MemoryLifecycleSweep, String> {
        match self {
            Self::Sqlite(db) => db.sweep_kioku_lifecycle(actor, now_ms),
            Self::Postgres(_) => Err(
                "sweep_kioku_lifecycle is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn redeem_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        now_ms: i64,
    ) -> Result<Redemption, String> {
        match self {
            Self::Sqlite(db) => db.redeem_permit(
                permit,
                context,
                trusted_key,
                idempotency_key,
                execution_id,
                host_site_id,
                now_ms,
            ),
            Self::Postgres(_) => {
                Err("redeem_permit is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn insert_attestation(&self, a: &PolicyAttestation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.insert_attestation(a),
            Self::Postgres(_) => {
                Err("insert_attestation is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn upsert_ontology_class(&self, class: &OntologyClass) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_class(class),
            Self::Postgres(db) => db.upsert_ontology_class(class),
        }
    }

    pub fn upsert_ontology_relation(&self, relation: &OntologyRelation) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.upsert_ontology_relation(relation),
            Self::Postgres(db) => db.upsert_ontology_relation(relation),
        }
    }

    pub fn update_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_work_unit(work_unit),
            Self::Postgres(db) => db.update_work_unit(work_unit),
        }
    }

    pub fn lease_audit_count(&self, namespace: &str, key: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.lease_audit_count(namespace, key),
            Self::Postgres(_) => {
                Err("lease_audit_count is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_objects(filter),
            Self::Postgres(db) => db.list_objects(filter),
        }
    }

    pub fn delete_object(&self, id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.delete_object(id),
            Self::Postgres(db) => db.delete_object(id),
        }
    }

    pub fn migrate_all(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_all(),
            Self::Postgres(_) => {
                Err("migrate_all is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    pub fn migrate_schema_types(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_schema_types(),
            Self::Postgres(_) => Err(
                "migrate_schema_types is unavailable on the PostgreSQL community runtime".into(),
            ),
        }
    }

    pub fn conn(&self) -> r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager> {
        match self {
            Self::Sqlite(db) => db.conn(),
            Self::Postgres(_) => panic!("conn() is only available for the SQLite community store"),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn migrate_audit(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.migrate_audit(),
            Self::Postgres(_) => {
                Err("migrate_audit is unavailable on the PostgreSQL community runtime".into())
            }
        }
    }

    /// Test helper used by gateway setup fixtures.
    #[cfg(feature = "gateway-test-support")]
    #[doc(hidden)]
    pub fn gateway_test_budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String> {
        match self {
            Self::Sqlite(db) => db.gateway_test_budget_usage(scope_id, metric, now_ms),
            Self::Postgres(_) => Err(
                "gateway_test_budget_usage is unavailable on the PostgreSQL community runtime"
                    .into(),
            ),
        }
    }
}
