//! Dual-backend community-store dispatch for coordination.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn list_active_credentials(&self) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_active_credentials(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_active_credentials()),
        }
    }

    pub fn get_principal_credential(
        &self,
        token_hash: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.get_principal_credential(token_hash),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_principal_credential(token_hash))
            }
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.acquire_lease(
                    namespace, key, owner, ttl_ms, request_id, actor, site_id, now_ms,
                )
            }),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.add_blast_radius(work_unit, mutations, deletes)
            }),
        }
    }

    pub fn append_run_event(&self, event: &RunEvent) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.append_run_event(event),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.append_run_event(event)),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.cancel_work_unit(work_unit_id, cancel_reason, now_ms)
            }),
        }
    }

    pub fn complete_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.complete_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.complete_work_unit(work_unit_id, now_ms))
            }
        }
    }

    pub fn contention_scope_chain(&self, scope_id: &str) -> Result<Vec<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.contention_scope_chain(scope_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.contention_scope_chain(scope_id))
            }
        }
    }

    pub fn create_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_contention_scope(scope),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_contention_scope(scope))
            }
        }
    }

    pub fn set_write_freeze(
        &self,
        freeze: &crate::sekai::write_freeze::WriteFreeze,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_write_freeze(freeze),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.set_write_freeze(freeze)),
        }
    }

    pub fn set_write_freeze_with_decision(
        &self,
        freeze: &crate::sekai::write_freeze::WriteFreeze,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_write_freeze_with_decision(freeze, decision),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.set_write_freeze_with_decision(freeze, decision)
            }),
        }
    }

    pub fn list_write_freezes(
        &self,
    ) -> Result<Vec<crate::sekai::write_freeze::WriteFreeze>, String> {
        match self {
            Self::Sqlite(db) => db.list_write_freezes(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_write_freezes()),
        }
    }

    pub fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_grant(grant),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.create_grant(grant)),
        }
    }

    pub fn create_grant_with_decision(
        &self,
        grant: &Grant,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_grant_with_decision(grant, decision),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_grant_with_decision(grant, decision))
            }
        }
    }

    pub fn set_namespace_grant_policy(&self, policy: &NamespaceGrantPolicy) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.set_namespace_grant_policy(policy),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.set_namespace_grant_policy(policy))
            }
        }
    }

    /// Stamp namespace grant policy and refresh the in-memory access cache.
    /// Storage updates existing open-ended grants; the cache would otherwise
    /// keep `not_after_ms = 0` until process restart.
    ///
    /// There is no public policy RPC. Call this on a quiet store (tests or
    /// operator setup). CreateGrant and this refresh are not a concurrent
    /// production pair.
    pub fn apply_namespace_grant_policy(
        &self,
        security: &SecurityChecker,
        policy: &NamespaceGrantPolicy,
    ) -> Result<(), String> {
        self.set_namespace_grant_policy(policy)?;
        security.reload(|| self.list_all_grants())?;
        Ok(())
    }

    pub fn namespace_grant_policy(
        &self,
        namespace: &str,
    ) -> Result<Option<NamespaceGrantPolicy>, String> {
        match self {
            Self::Sqlite(db) => db.namespace_grant_policy(namespace),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.namespace_grant_policy(namespace))
            }
        }
    }

    pub fn create_handoff(
        &self,
        manifest: &HandoffManifest,
        request_id: &str,
    ) -> Result<HandoffManifest, String> {
        match self {
            Self::Sqlite(db) => db.create_handoff(manifest, request_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_handoff(manifest, request_id))
            }
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

    pub fn create_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.create_work_unit(work_unit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.create_work_unit(work_unit))
            }
        }
    }

    pub fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.delete_grant(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.delete_grant(id)),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.ensure_team_namespace(namespace, principal, member_role, actor)
            }),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.fail_work_unit(work_unit_id, failure_reason, now_ms)
            }),
        }
    }

    pub fn get_blast_radius(&self, work_unit: &str) -> Result<(u32, u32), String> {
        match self {
            Self::Sqlite(db) => db.get_blast_radius(work_unit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_blast_radius(work_unit))
            }
        }
    }

    pub fn get_contention_scope(&self, id: &str) -> Result<Option<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.get_contention_scope(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_contention_scope(id)),
        }
    }

    pub fn get_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.get_grant(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_grant(id)),
        }
    }

    pub fn get_handoff(&self, id: &str) -> Result<Option<HandoffManifest>, String> {
        match self {
            Self::Sqlite(db) => db.get_handoff(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_handoff(id)),
        }
    }

    pub fn get_handoff_by_request(
        &self,
        creator_principal: &str,
        request_id: &str,
    ) -> Result<Option<(String, HandoffManifest)>, String> {
        match self {
            Self::Sqlite(db) => db.get_handoff_by_request(creator_principal, request_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_handoff_by_request(creator_principal, request_id)
            }),
        }
    }

    pub fn get_lease(&self, namespace: &str, key: &str) -> Result<Option<Lease>, LeaseError> {
        match self {
            Self::Sqlite(db) => db.get_lease(namespace, key),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_lease(namespace, key)),
        }
    }

    pub fn get_work_unit(&self, id: &str) -> Result<Option<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.get_work_unit(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.get_work_unit(id)),
        }
    }

    pub fn get_work_unit_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.get_work_unit_by_idempotency_key(idempotency_key),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_work_unit_by_idempotency_key(idempotency_key)
            }),
        }
    }

    pub fn handoff_is_superseded(&self, id: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.handoff_is_superseded(id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.handoff_is_superseded(id)),
        }
    }

    pub fn heartbeat_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        match self {
            Self::Sqlite(db) => db.heartbeat_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.heartbeat_work_unit(work_unit_id, now_ms))
            }
        }
    }

    pub fn is_team_principal(&self, principal: &str) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.is_team_principal(principal),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.is_team_principal(principal))
            }
        }
    }

    pub fn list_all_grants(&self) -> Result<Vec<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.list_all_grants(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_all_grants()),
        }
    }

    pub fn list_contention_scopes(&self) -> Result<Vec<ContentionScope>, String> {
        match self {
            Self::Sqlite(db) => db.list_contention_scopes(),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_contention_scopes()),
        }
    }

    pub fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        match self {
            Self::Sqlite(db) => db.list_grants(object_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_grants(object_id)),
        }
    }

    pub fn list_namespace_roles_for_principal(
        &self,
        principal: &str,
    ) -> Result<Vec<(String, Role)>, String> {
        match self {
            Self::Sqlite(db) => db.list_namespace_roles_for_principal(principal),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_namespace_roles_for_principal(principal)
            }),
        }
    }

    pub fn list_reservations(
        &self,
        filter: &ReservationFilter,
    ) -> Result<Vec<Reservation>, String> {
        match self {
            Self::Sqlite(db) => db.list_reservations(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_reservations(filter)),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_run_events(work_unit_id, limit, after, event_types, page_token)
            }),
        }
    }

    pub fn list_unbound_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_unbound_credentials(principal, status),
            // Community storage has no tenant binding, so every credential
            // is unbound, the same as SQLite.
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_credentials(principal, status))
            }
        }
    }

    pub fn list_work_units(&self, filter: &WorkUnitFilter) -> Result<Vec<WorkUnit>, String> {
        match self {
            Self::Sqlite(db) => db.list_work_units(filter),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| db.list_work_units(filter)),
        }
    }

    pub fn reconcile_work_units(
        &self,
        now_ms: i64,
        filter: &ReconcileFilter,
    ) -> Result<ReconcileSummary, String> {
        match self {
            Self::Sqlite(db) => db.reconcile_work_units(now_ms, filter),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.reconcile_work_units(now_ms, filter))
            }
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.refresh_lease(
                    namespace, key, token, ttl_ms, request_id, actor, site_id, now_ms,
                )
            }),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_lease(namespace, key, token, request_id, actor, site_id, now_ms)
            }),
        }
    }

    pub fn release_reservations_for_work_unit(
        &self,
        work_unit_id: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        match self {
            Self::Sqlite(db) => db.release_reservations_for_work_unit(work_unit_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_reservations_for_work_unit(work_unit_id, now_ms)
            }),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.revoke_handoff(id, actor, reason, request_id, now_ms)
            }),
        }
    }

    pub fn revoke_principal_credential(
        &self,
        principal: &str,
    ) -> Result<Option<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.revoke_principal_credential(principal),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.revoke_principal_credential(principal))
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.rotate_principal_credential(principal, token_hash)
            }),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.takeover_expired_lease(
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
                )
            }),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.try_admit_work_unit(work_unit_id, lease_owner, now_ms)
            }),
        }
    }

    pub fn update_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_contention_scope(scope),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.update_contention_scope(scope))
            }
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

    pub fn principal_credentials_activity_epoch(&self) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.principal_credentials_activity_epoch(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.principal_credentials_activity_epoch())
            }
        }
    }

    pub fn list_credentials(
        &self,
        principal: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<PrincipalCredential>, String> {
        match self {
            Self::Sqlite(db) => db.list_credentials(principal, status),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_credentials(principal, status))
            }
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.create_principal_credential(principal, token_hash, now)
            }),
        }
    }

    pub fn update_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.update_work_unit(work_unit),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.update_work_unit(work_unit))
            }
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
}
