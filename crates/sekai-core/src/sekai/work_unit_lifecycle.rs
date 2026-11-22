//! Durable Work Unit lifecycle orchestration.
//!
//! The gRPC adapter authenticates and authorizes a request before crossing this
//! seam. This module owns replay identity, transition persistence, and durable
//! request deduplication so every transport observes the same ordering. Each
//! mutation commits in one transaction with its request dedup row, so a retry
//! or a concurrent duplicate replays the first result instead of applying again.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::coordination::{
    AdmissionResult, RESERVATION_STATUS_ACTIVE, ReconcileFilter, ReconcileSummary, RequestDedup,
    RequestOutcome, ReservationFilter, RunEvent, WORK_UNIT_STATUS_PENDING,
    WORK_UNIT_STATUS_RUNNING, WorkUnit,
};

pub struct CreateWorkUnit<'a> {
    pub work_unit: WorkUnit,
    pub request_id: &'a str,
    pub principal: &'a str,
    pub now_ms: i64,
}

pub enum CreateAuthorizationTarget<'a> {
    IdempotencyReplay(&'a WorkUnit),
    New(&'a WorkUnit),
}

pub struct ReconcileWorkUnits<'a> {
    pub work_unit_id: &'a str,
    pub scope_id: &'a str,
    pub principals: &'a [String],
    pub dry_run: bool,
    pub limit: i32,
    pub now_ms: i64,
}

pub struct AdmitWorkUnit<'a> {
    pub work_unit_id: &'a str,
    pub request_id: &'a str,
    pub principal: &'a str,
    pub lease_owner: &'a str,
    pub now_ms: i64,
}

pub struct TransitionWorkUnit<'a> {
    pub work_unit_id: &'a str,
    pub request_id: &'a str,
    pub principal: &'a str,
    pub transition: WorkUnitTransition<'a>,
    pub now_ms: i64,
}

pub enum WorkUnitTransition<'a> {
    Heartbeat,
    Complete,
    Fail(&'a str),
    Cancel(&'a str),
}

impl WorkUnitTransition<'_> {
    fn operation(&self) -> &'static str {
        match self {
            Self::Heartbeat => "heartbeat_work_unit",
            Self::Complete => "complete_work_unit",
            Self::Fail(_) => "fail_work_unit",
            Self::Cancel(_) => "cancel_work_unit",
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum WorkUnitLifecycleError {
    NotFound(String),
    PermissionDenied(String),
    InvalidArgument(String),
    FailedPrecondition(String),
    AlreadyExists(String),
    Storage(String),
}

#[derive(Debug)]
pub enum CreateWorkUnitError<E> {
    Authorization(E),
    Lifecycle(WorkUnitLifecycleError),
}

pub struct WorkUnitLifecycle<'a> {
    db: &'a RuntimeDb,
}

impl<'a> WorkUnitLifecycle<'a> {
    pub fn new(db: &'a RuntimeDb) -> Self {
        Self { db }
    }

    pub fn create<E>(
        &self,
        mut command: CreateWorkUnit<'_>,
        authorize: impl Fn(CreateAuthorizationTarget<'_>) -> Result<(), E>,
    ) -> Result<WorkUnit, CreateWorkUnitError<E>> {
        if let Some(record) = self
            .db
            .get_dedup_request(command.request_id, "create_work_unit")
            .map_err(|error| {
                CreateWorkUnitError::Lifecycle(WorkUnitLifecycleError::Storage(error))
            })?
        {
            return self
                .replay_create(&record, command.principal)
                .map_err(CreateWorkUnitError::Lifecycle);
        }

        if !command.work_unit.idempotency_key.is_empty()
            && let Some(existing) = self
                .db
                .get_work_unit_by_idempotency_key(&command.work_unit.idempotency_key)
                .map_err(|error| {
                    CreateWorkUnitError::Lifecycle(WorkUnitLifecycleError::Storage(error))
                })?
        {
            authorize(CreateAuthorizationTarget::IdempotencyReplay(&existing))
                .map_err(CreateWorkUnitError::Authorization)?;
            return Ok(existing);
        }

        authorize(CreateAuthorizationTarget::New(&command.work_unit))
            .map_err(CreateWorkUnitError::Authorization)?;
        initialize_for_create(&mut command.work_unit, command.principal);
        let work_unit = command.work_unit;
        let created_event = RunEvent {
            id: format!("evt:{}:created:{}", work_unit.id, work_unit.created_at),
            work_unit_id: work_unit.id.clone(),
            event_type: "created".into(),
            message: "work unit created".into(),
            evidence: std::collections::HashMap::from([(
                "scope_id".into(),
                work_unit.scope_id.clone(),
            )]),
            created_at: work_unit.created_at,
        };
        let request = RequestDedup {
            request_id: command.request_id.into(),
            operation: "create_work_unit".into(),
            principal: command.principal.into(),
            created_at: command.now_ms,
            ..Default::default()
        };
        match self
            .db
            .create_work_unit_for_request(&work_unit, &created_event, &request)
            .map_err(|error| {
                CreateWorkUnitError::Lifecycle(WorkUnitLifecycleError::InvalidArgument(error))
            })? {
            RequestOutcome::Applied(()) => Ok(work_unit),
            RequestOutcome::Replayed(record) => self
                .replay_create(&record, command.principal)
                .map_err(CreateWorkUnitError::Lifecycle),
        }
    }

    pub fn admit(
        &self,
        command: AdmitWorkUnit<'_>,
    ) -> Result<AdmissionResult, WorkUnitLifecycleError> {
        let request = RequestDedup {
            request_id: command.request_id.into(),
            operation: "try_admit_work_unit".into(),
            principal: command.principal.into(),
            work_unit_id: command.work_unit_id.into(),
            created_at: command.now_ms,
            lease_owner: command.lease_owner.into(),
            ..Default::default()
        };
        match self
            .db
            .try_admit_work_unit_for_request(
                command.work_unit_id,
                command.lease_owner,
                command.now_ms,
                &request,
            )
            .map_err(WorkUnitLifecycleError::FailedPrecondition)?
        {
            RequestOutcome::Applied(result) => Ok(result),
            RequestOutcome::Replayed(record) => self.replay_admission(&command, record),
        }
    }

    pub fn transition(
        &self,
        command: TransitionWorkUnit<'_>,
    ) -> Result<WorkUnit, WorkUnitLifecycleError> {
        let operation = command.transition.operation();
        let request = RequestDedup {
            request_id: command.request_id.into(),
            operation: operation.into(),
            principal: command.principal.into(),
            work_unit_id: command.work_unit_id.into(),
            created_at: command.now_ms,
            ..Default::default()
        };
        match self
            .db
            .transition_work_unit_for_request(
                command.work_unit_id,
                &command.transition,
                command.now_ms,
                &request,
            )
            .map_err(WorkUnitLifecycleError::FailedPrecondition)?
        {
            RequestOutcome::Applied(work_unit) => Ok(work_unit),
            RequestOutcome::Replayed(record) => {
                if record.work_unit_id != command.work_unit_id
                    || record.principal != command.principal
                {
                    return Err(WorkUnitLifecycleError::AlreadyExists(format!(
                        "request_id already used for {operation} with a different binding"
                    )));
                }
                self.load(command.work_unit_id)
            }
        }
    }

    pub fn reconcile(
        &self,
        command: ReconcileWorkUnits<'_>,
    ) -> Result<ReconcileSummary, WorkUnitLifecycleError> {
        if !command.work_unit_id.is_empty() {
            let work_unit = self.load(command.work_unit_id)?;
            let scope = self.load_scope(&work_unit.scope_id)?;
            require_scope_owner(&scope.owner_principal, command.principals)?;
            if !command.scope_id.is_empty() && command.scope_id != work_unit.scope_id {
                return Ok(ReconcileSummary::default());
            }
            return self.reconcile_filter(
                command.now_ms,
                ReconcileFilter {
                    dry_run: command.dry_run,
                    work_unit_id: Some(command.work_unit_id.into()),
                    scope_id: (!command.scope_id.is_empty()).then(|| command.scope_id.into()),
                    limit: command.limit,
                },
            );
        }

        if !command.scope_id.is_empty() {
            let scope = self.load_scope(command.scope_id)?;
            require_scope_owner(&scope.owner_principal, command.principals)?;
            return self.reconcile_filter(
                command.now_ms,
                ReconcileFilter {
                    dry_run: command.dry_run,
                    work_unit_id: None,
                    scope_id: Some(command.scope_id.into()),
                    limit: command.limit,
                },
            );
        }

        let mut owned_scope_ids: Vec<String> = self
            .db
            .list_contention_scopes()
            .map_err(WorkUnitLifecycleError::Storage)?
            .into_iter()
            .filter(|scope| principal_matches(&scope.owner_principal, command.principals))
            .map(|scope| scope.id)
            .collect();
        owned_scope_ids.sort();
        if owned_scope_ids.is_empty() {
            return Err(WorkUnitLifecycleError::PermissionDenied(
                "reconcile requires scope ownership".into(),
            ));
        }
        let mut summary = ReconcileSummary::default();
        for scope_id in owned_scope_ids {
            if command.limit > 0 && summary.work_units_reconciled >= command.limit {
                break;
            }
            let remaining = if command.limit > 0 {
                command.limit - summary.work_units_reconciled
            } else {
                0
            };
            let next = self.reconcile_filter(
                command.now_ms,
                ReconcileFilter {
                    dry_run: command.dry_run,
                    work_unit_id: None,
                    scope_id: Some(scope_id),
                    limit: remaining,
                },
            )?;
            summary.work_units_reconciled += next.work_units_reconciled;
            summary.reservations_released += next.reservations_released;
            summary.details.extend(next.details);
        }
        Ok(summary)
    }

    fn load(&self, work_unit_id: &str) -> Result<WorkUnit, WorkUnitLifecycleError> {
        self.db
            .get_work_unit(work_unit_id)
            .map_err(WorkUnitLifecycleError::Storage)?
            .ok_or_else(|| WorkUnitLifecycleError::NotFound("work unit not found".into()))
    }

    fn load_scope(
        &self,
        scope_id: &str,
    ) -> Result<crate::sekai::coordination::ContentionScope, WorkUnitLifecycleError> {
        self.db
            .get_contention_scope(scope_id)
            .map_err(WorkUnitLifecycleError::Storage)?
            .ok_or_else(|| WorkUnitLifecycleError::NotFound("scope not found".into()))
    }

    fn reconcile_filter(
        &self,
        now_ms: i64,
        filter: ReconcileFilter,
    ) -> Result<ReconcileSummary, WorkUnitLifecycleError> {
        self.db
            .reconcile_work_units(now_ms, &filter)
            .map_err(WorkUnitLifecycleError::Storage)
    }

    /// Returns the unit an earlier create with this request id made, unless
    /// another principal used the id.
    fn replay_create(
        &self,
        record: &RequestDedup,
        principal: &str,
    ) -> Result<WorkUnit, WorkUnitLifecycleError> {
        if record.principal != principal {
            return Err(WorkUnitLifecycleError::AlreadyExists(
                "request_id already used for create_work_unit by another principal".into(),
            ));
        }
        self.load(&record.work_unit_id)
    }

    /// Returns the admission an earlier request with this id stored. Rows
    /// written before admission outcomes were stored replay from current state.
    fn replay_admission(
        &self,
        command: &AdmitWorkUnit<'_>,
        record: RequestDedup,
    ) -> Result<AdmissionResult, WorkUnitLifecycleError> {
        if record.work_unit_id != command.work_unit_id
            || record.principal != command.principal
            || (record.admitted.is_some() && record.lease_owner != command.lease_owner)
        {
            return Err(WorkUnitLifecycleError::AlreadyExists(
                "request_id already used for try_admit_work_unit with a different binding".into(),
            ));
        }
        let work_unit = self.load(&record.work_unit_id)?;
        let reservations = self
            .db
            .list_reservations(&ReservationFilter {
                work_unit_id: Some(record.work_unit_id),
                status: Some(RESERVATION_STATUS_ACTIVE.into()),
                ..Default::default()
            })
            .map_err(WorkUnitLifecycleError::Storage)?;
        if let Some(admitted) = record.admitted {
            return Ok(AdmissionResult {
                admitted,
                queue_position: record.queue_position.unwrap_or(0),
                reason: record.reason,
                work_unit,
                reservations,
            });
        }
        Ok(AdmissionResult {
            admitted: work_unit.status == WORK_UNIT_STATUS_RUNNING,
            queue_position: 0,
            reason: String::new(),
            work_unit,
            reservations,
        })
    }
}

fn initialize_for_create(work_unit: &mut WorkUnit, principal: &str) {
    if work_unit.owner_principal.is_empty() {
        work_unit.owner_principal = principal.into();
    }
    if work_unit.creator_principal.is_empty() {
        work_unit.creator_principal = principal.into();
    }
    work_unit.status = WORK_UNIT_STATUS_PENDING.into();
    work_unit.admitted_at = 0;
    work_unit.started_at = 0;
    work_unit.finished_at = 0;
    work_unit.last_heartbeat_at = 0;
    work_unit.failure_reason.clear();
    work_unit.cancel_reason.clear();
    work_unit.updated_at = work_unit.created_at;
}

fn principal_matches(owner_principal: &str, principals: &[String]) -> bool {
    !owner_principal.is_empty()
        && principals
            .iter()
            .any(|principal| principal == owner_principal)
}

fn require_scope_owner(
    owner_principal: &str,
    principals: &[String],
) -> Result<(), WorkUnitLifecycleError> {
    if principal_matches(owner_principal, principals) {
        Ok(())
    } else {
        Err(WorkUnitLifecycleError::PermissionDenied(
            "scope access denied".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::coordination::{
        ADMISSION_POLICY_FIFO, ContentionScope, WORK_UNIT_STATUS_CANCELLED,
        WORK_UNIT_STATUS_COMPLETED, WORK_UNIT_STATUS_PENDING,
    };

    fn work_unit() -> WorkUnit {
        WorkUnit {
            id: "work-1".into(),
            kind: "test".into(),
            actor: "alice".into(),
            target_object_id: String::new(),
            status: WORK_UNIT_STATUS_PENDING.into(),
            requested_spec: "{}".into(),
            scope_id: "scope-1".into(),
            priority: 0,
            timeout_seconds: 60,
            heartbeat_ttl_seconds: 30,
            created_at: 1,
            admitted_at: 0,
            started_at: 0,
            finished_at: 0,
            last_heartbeat_at: 0,
            failure_reason: String::new(),
            cancel_reason: String::new(),
            owner_principal: "alice".into(),
            creator_principal: "alice".into(),
            idempotency_key: "key-1".into(),
            updated_at: 1,
        }
    }

    fn empty_database() -> RuntimeDb {
        let db = RuntimeDb::memory();
        db.create_contention_scope(&ContentionScope {
            id: "scope-1".into(),
            name: "scope".into(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 30,
            timeout_seconds: 60,
            owner_principal: "alice".into(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db
    }

    fn database() -> RuntimeDb {
        let db = empty_database();
        db.create_work_unit(&work_unit()).unwrap();
        db
    }

    #[test]
    fn create_interface_owns_normalization_event_ordering_and_replay() {
        let db = empty_database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        let mut candidate = work_unit();
        candidate.status = "completed".into();
        candidate.finished_at = 99;
        candidate.owner_principal.clear();
        candidate.creator_principal.clear();

        let created = lifecycle
            .create(
                CreateWorkUnit {
                    work_unit: candidate.clone(),
                    request_id: "create-1",
                    principal: "alice",
                    now_ms: 10,
                },
                |_| Ok::<_, ()>(()),
            )
            .unwrap();
        let replay = lifecycle
            .create(
                CreateWorkUnit {
                    work_unit: candidate,
                    request_id: "create-1",
                    principal: "alice",
                    now_ms: 20,
                },
                |_| Err("replay must precede authorization"),
            )
            .unwrap();

        assert_eq!(created, replay);
        assert_eq!(created.status, WORK_UNIT_STATUS_PENDING);
        assert_eq!(created.finished_at, 0);
        assert_eq!(created.owner_principal, "alice");
        assert_eq!(created.creator_principal, "alice");
        let events = db.list_run_events("work-1", 10, 0, &[], None).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "created");
        assert_eq!(
            db.get_dedup_request("create-1", "create_work_unit")
                .unwrap()
                .unwrap()
                .created_at,
            10
        );
    }

    #[test]
    fn create_rejects_request_id_reuse_across_principals() {
        let db = empty_database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        let mut alice_unit = work_unit();
        alice_unit.id = "work-alice".into();
        alice_unit.idempotency_key = "key-alice".into();
        lifecycle
            .create(
                CreateWorkUnit {
                    work_unit: alice_unit,
                    request_id: "shared-request",
                    principal: "alice",
                    now_ms: 10,
                },
                |_| Ok::<_, ()>(()),
            )
            .unwrap();

        let mut bob_unit = work_unit();
        bob_unit.id = "work-bob".into();
        bob_unit.idempotency_key = "key-bob".into();
        bob_unit.owner_principal = "bob".into();
        bob_unit.creator_principal = "bob".into();
        let err = lifecycle
            .create(
                CreateWorkUnit {
                    work_unit: bob_unit.clone(),
                    request_id: "shared-request",
                    principal: "bob",
                    now_ms: 20,
                },
                |_| Ok::<_, ()>(()),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            CreateWorkUnitError::Lifecycle(WorkUnitLifecycleError::AlreadyExists(_))
        ));
        assert!(db.get_work_unit("work-bob").unwrap().is_none());

        // Retries must keep failing closed — not mint additional units.
        let retry = lifecycle
            .create(
                CreateWorkUnit {
                    work_unit: bob_unit,
                    request_id: "shared-request",
                    principal: "bob",
                    now_ms: 30,
                },
                |_| Ok::<_, ()>(()),
            )
            .unwrap_err();
        assert!(matches!(
            retry,
            CreateWorkUnitError::Lifecycle(WorkUnitLifecycleError::AlreadyExists(_))
        ));
    }

    #[test]
    fn transition_rejects_request_id_reuse_across_principals() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        lifecycle
            .transition(TransitionWorkUnit {
                work_unit_id: "work-1",
                request_id: "cancel-shared",
                principal: "alice",
                transition: WorkUnitTransition::Cancel("alice-cancel"),
                now_ms: 10,
            })
            .unwrap();
        let err = lifecycle
            .transition(TransitionWorkUnit {
                work_unit_id: "work-1",
                request_id: "cancel-shared",
                principal: "bob",
                transition: WorkUnitTransition::Cancel("bob-cancel"),
                now_ms: 20,
            })
            .unwrap_err();
        assert!(matches!(err, WorkUnitLifecycleError::AlreadyExists(_)));
    }

    #[test]
    fn reconcile_interface_owns_scope_selection_and_authorization() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        let denied = lifecycle.reconcile(ReconcileWorkUnits {
            work_unit_id: "work-1",
            scope_id: "",
            principals: &["bob".into()],
            dry_run: true,
            limit: 0,
            now_ms: 10,
        });
        assert_eq!(
            denied,
            Err(WorkUnitLifecycleError::PermissionDenied(
                "scope access denied".into()
            ))
        );

        let mismatch = lifecycle
            .reconcile(ReconcileWorkUnits {
                work_unit_id: "work-1",
                scope_id: "different-scope",
                principals: &["alice".into()],
                dry_run: true,
                limit: 0,
                now_ms: 10,
            })
            .unwrap();
        assert_eq!(mismatch, ReconcileSummary::default());
    }

    #[test]
    fn transition_interface_owns_mutation_and_replay_deduplication() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);

        let first = lifecycle
            .transition(TransitionWorkUnit {
                work_unit_id: "work-1",
                request_id: "cancel-1",
                principal: "alice",
                transition: WorkUnitTransition::Cancel("superseded"),
                now_ms: 10,
            })
            .unwrap();
        let replay = lifecycle
            .transition(TransitionWorkUnit {
                work_unit_id: "work-1",
                request_id: "cancel-1",
                principal: "alice",
                transition: WorkUnitTransition::Cancel("superseded"),
                now_ms: 20,
            })
            .unwrap();

        assert_eq!(first, replay);
        assert_eq!(replay.status, WORK_UNIT_STATUS_CANCELLED);
        assert_eq!(replay.finished_at, 10);
        assert_eq!(
            db.get_dedup_request("cancel-1", "cancel_work_unit")
                .unwrap()
                .unwrap()
                .principal,
            "alice"
        );
    }

    #[test]
    fn admission_interface_replays_the_durable_result() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);

        let admit = |now_ms| {
            lifecycle.admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "alice",
                now_ms,
            })
        };
        let first = admit(10).unwrap();
        let replay = admit(20).unwrap();

        assert!(first.admitted);
        assert!(replay.admitted);
        assert_eq!(replay.work_unit, first.work_unit);
        assert_eq!(replay.reservations, first.reservations);
    }

    #[test]
    fn queued_admission_replay_returns_the_original_position() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        let mut queued = work_unit();
        queued.id = "work-2".into();
        queued.idempotency_key = "key-2".into();
        queued.created_at = 2;
        queued.updated_at = 2;
        db.create_work_unit(&queued).unwrap();

        let first = lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "alice",
                now_ms: 10,
            })
            .unwrap();
        assert!(first.admitted);

        let blocked = lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-2",
                request_id: "admit-2",
                principal: "alice",
                lease_owner: "alice",
                now_ms: 11,
            })
            .unwrap();
        assert!(!blocked.admitted);
        assert_eq!(blocked.queue_position, 1);
        assert!(!blocked.reason.is_empty());

        let replay = lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-2",
                request_id: "admit-2",
                principal: "alice",
                lease_owner: "alice",
                now_ms: 12,
            })
            .unwrap();
        assert_eq!(replay.admitted, blocked.admitted);
        assert_eq!(replay.queue_position, blocked.queue_position);
        assert_eq!(replay.reason, blocked.reason);
    }

    #[test]
    fn completed_admission_replay_returns_the_original_admit() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        let first = lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "alice",
                now_ms: 10,
            })
            .unwrap();
        assert!(first.admitted);
        db.complete_work_unit("work-1", 20).unwrap();

        let replay = lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "alice",
                now_ms: 30,
            })
            .unwrap();
        assert!(replay.admitted);
        assert_eq!(replay.queue_position, first.queue_position);
        assert_eq!(replay.reason, first.reason);
    }

    #[test]
    fn admission_replay_refuses_a_different_lease_owner() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "alice",
                now_ms: 10,
            })
            .unwrap();
        let err = lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "other",
                now_ms: 20,
            })
            .unwrap_err();
        assert!(matches!(err, WorkUnitLifecycleError::AlreadyExists(_)));
    }

    /// Makes every dedup write that carries a mutation result fail, the way a
    /// storage fault after the mutation would.
    fn fail_dedup_writes(db: &RuntimeDb, fail: bool) {
        let conn = db.as_sqlite().expect("sqlite").conn();
        conn.execute_batch(if fail {
            "CREATE TRIGGER fail_dedup_insert BEFORE INSERT ON sekai_coordination_requests
             WHEN NEW.scope_id <> '' BEGIN SELECT RAISE(ABORT, 'injected'); END;
             CREATE TRIGGER fail_dedup_update BEFORE UPDATE ON sekai_coordination_requests
             WHEN NEW.scope_id <> '' BEGIN SELECT RAISE(ABORT, 'injected'); END;"
        } else {
            "DROP TRIGGER fail_dedup_insert; DROP TRIGGER fail_dedup_update;"
        })
        .unwrap();
    }

    // #2724: the mutation committed before its dedup row, so a retry after a
    // failed dedup write re-ran it: a retried admit reported "not pending".
    #[test]
    fn a_failed_dedup_write_rolls_back_the_mutation_and_the_retry_applies_it() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        let status = || db.get_work_unit("work-1").unwrap().unwrap().status;
        let admit = |now_ms| {
            lifecycle.admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "alice",
                now_ms,
            })
        };
        let complete = |now_ms| {
            lifecycle.transition(TransitionWorkUnit {
                work_unit_id: "work-1",
                request_id: "complete-1",
                principal: "alice",
                transition: WorkUnitTransition::Complete,
                now_ms,
            })
        };

        fail_dedup_writes(&db, true);
        assert!(admit(10).is_err());
        assert_eq!(status(), WORK_UNIT_STATUS_PENDING);
        fail_dedup_writes(&db, false);
        assert!(admit(20).unwrap().admitted);

        fail_dedup_writes(&db, true);
        assert!(complete(30).is_err());
        assert_eq!(status(), WORK_UNIT_STATUS_RUNNING);
        fail_dedup_writes(&db, false);
        let completed = complete(40).unwrap();
        assert_eq!(completed.status, WORK_UNIT_STATUS_COMPLETED);
        assert_eq!(completed.finished_at, 40);
    }

    /// Several threads send the same heartbeat at once; one applies it and
    /// the rest replay it.
    fn concurrent_duplicates_apply_once(db: &RuntimeDb, prefix: &str) {
        let scope_id = format!("{prefix}-scope");
        let work_unit_id = format!("{prefix}-work");
        db.create_contention_scope(&ContentionScope {
            id: scope_id.clone(),
            name: scope_id.clone(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 30,
            timeout_seconds: 60,
            owner_principal: "alice".into(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_work_unit(&WorkUnit {
            id: work_unit_id.clone(),
            scope_id,
            idempotency_key: format!("{prefix}-key"),
            ..work_unit()
        })
        .unwrap();
        assert!(
            db.try_admit_work_unit(&work_unit_id, "alice", 10)
                .unwrap()
                .admitted
        );

        let request_id = format!("{prefix}-heartbeat");
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|threads| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    threads.spawn(|| {
                        barrier.wait();
                        WorkUnitLifecycle::new(db).transition(TransitionWorkUnit {
                            work_unit_id: &work_unit_id,
                            request_id: &request_id,
                            principal: "alice",
                            transition: WorkUnitTransition::Heartbeat,
                            now_ms: 20,
                        })
                    })
                })
                .collect();
            for handle in handles {
                assert_eq!(handle.join().unwrap().unwrap().last_heartbeat_at, 20);
            }
        });
        let heartbeats = db
            .list_run_events(&work_unit_id, 100, 0, &["heartbeat".into()], None)
            .unwrap();
        assert_eq!(heartbeats.len(), 1);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_concurrent_duplicate_requests_apply_once() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                8,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 8),
        };
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        concurrent_duplicates_apply_once(
            &db,
            &format!("dedup-{}-{}", std::process::id(), uuid::Uuid::new_v4()),
        );
    }

    #[test]
    fn pre_migration_dedup_rows_replay_from_current_state() {
        let db = database();
        let lifecycle = WorkUnitLifecycle::new(&db);
        lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "alice",
                now_ms: 10,
            })
            .unwrap();
        db.as_sqlite()
            .expect("sqlite")
            .conn()
            .execute(
                "UPDATE sekai_coordination_requests
                 SET admitted = NULL, queue_position = NULL, reason = '', lease_owner = ''
                 WHERE request_id = ?1 AND operation = ?2",
                ("admit-1", "try_admit_work_unit"),
            )
            .unwrap();
        db.complete_work_unit("work-1", 20).unwrap();

        let replay = lifecycle
            .admit(AdmitWorkUnit {
                work_unit_id: "work-1",
                request_id: "admit-1",
                principal: "alice",
                lease_owner: "other",
                now_ms: 30,
            })
            .unwrap();
        assert!(!replay.admitted);
        assert_eq!(replay.queue_position, 0);
        assert!(replay.reason.is_empty());
    }
}
