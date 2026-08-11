//! Durable Work Unit lifecycle orchestration.
//!
//! The gRPC adapter authenticates and authorizes a request before crossing this
//! seam. This module owns replay identity, transition persistence, and durable
//! request deduplication so every transport observes the same ordering.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::coordination::{
    AdmissionResult, RESERVATION_STATUS_ACTIVE, ReconcileFilter, ReconcileSummary, RequestDedup,
    ReservationFilter, RunEvent, WORK_UNIT_STATUS_PENDING, WORK_UNIT_STATUS_RUNNING, WorkUnit,
};

pub(crate) struct CreateWorkUnit<'a> {
    pub work_unit: WorkUnit,
    pub request_id: &'a str,
    pub principal: &'a str,
    pub now_ms: i64,
}

pub(crate) enum CreateAuthorizationTarget<'a> {
    IdempotencyReplay(&'a WorkUnit),
    New(&'a WorkUnit),
}

pub(crate) struct ReconcileWorkUnits<'a> {
    pub work_unit_id: &'a str,
    pub scope_id: &'a str,
    pub principals: &'a [String],
    pub dry_run: bool,
    pub limit: i32,
    pub now_ms: i64,
}

pub(crate) struct AdmitWorkUnit<'a> {
    pub work_unit_id: &'a str,
    pub request_id: &'a str,
    pub principal: &'a str,
    pub lease_owner: &'a str,
    pub now_ms: i64,
}

pub(crate) struct TransitionWorkUnit<'a> {
    pub work_unit_id: &'a str,
    pub request_id: &'a str,
    pub principal: &'a str,
    pub transition: WorkUnitTransition<'a>,
    pub now_ms: i64,
}

pub(crate) enum WorkUnitTransition<'a> {
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
pub(crate) enum WorkUnitLifecycleError {
    NotFound(String),
    PermissionDenied(String),
    InvalidArgument(String),
    FailedPrecondition(String),
    Storage(String),
}

#[derive(Debug)]
pub(crate) enum CreateWorkUnitError<E> {
    Authorization(E),
    Lifecycle(WorkUnitLifecycleError),
}

pub(crate) struct WorkUnitLifecycle<'a> {
    db: &'a RuntimeDb,
}

impl<'a> WorkUnitLifecycle<'a> {
    pub(crate) fn new(db: &'a RuntimeDb) -> Self {
        Self { db }
    }

    pub(crate) fn create<E>(
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
            .filter(|record| record.principal == command.principal)
        {
            return self
                .load(&record.work_unit_id)
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
        self.db
            .create_work_unit(&command.work_unit)
            .map_err(|error| {
                CreateWorkUnitError::Lifecycle(WorkUnitLifecycleError::InvalidArgument(error))
            })?;
        self.db
            .append_run_event(&RunEvent {
                id: format!(
                    "evt:{}:created:{}",
                    command.work_unit.id, command.work_unit.created_at
                ),
                work_unit_id: command.work_unit.id.clone(),
                event_type: "created".into(),
                message: "work unit created".into(),
                evidence: std::collections::HashMap::from([(
                    "scope_id".into(),
                    command.work_unit.scope_id.clone(),
                )]),
                created_at: command.work_unit.created_at,
            })
            .map_err(|error| {
                CreateWorkUnitError::Lifecycle(WorkUnitLifecycleError::Storage(error))
            })?;
        self.record(
            command.request_id,
            "create_work_unit",
            command.principal,
            &command.work_unit,
            command.now_ms,
        )
        .map_err(CreateWorkUnitError::Lifecycle)?;
        Ok(command.work_unit)
    }

    pub(crate) fn admit(
        &self,
        command: AdmitWorkUnit<'_>,
    ) -> Result<AdmissionResult, WorkUnitLifecycleError> {
        if let Some(record) = self
            .db
            .get_dedup_request(command.request_id, "try_admit_work_unit")
            .map_err(WorkUnitLifecycleError::Storage)?
            .filter(|record| {
                record.work_unit_id == command.work_unit_id && record.principal == command.principal
            })
        {
            let work_unit = self.load(&record.work_unit_id)?;
            let reservations = self
                .db
                .list_reservations(&ReservationFilter {
                    work_unit_id: Some(record.work_unit_id),
                    status: Some(RESERVATION_STATUS_ACTIVE.into()),
                    ..Default::default()
                })
                .map_err(WorkUnitLifecycleError::Storage)?;
            return Ok(AdmissionResult {
                admitted: work_unit.status == WORK_UNIT_STATUS_RUNNING,
                queue_position: 0,
                reason: String::new(),
                work_unit,
                reservations,
            });
        }

        let result = self
            .db
            .try_admit_work_unit(command.work_unit_id, command.lease_owner, command.now_ms)
            .map_err(WorkUnitLifecycleError::FailedPrecondition)?;
        self.record(
            command.request_id,
            "try_admit_work_unit",
            command.principal,
            &result.work_unit,
            command.now_ms,
        )?;
        Ok(result)
    }

    pub(crate) fn transition(
        &self,
        command: TransitionWorkUnit<'_>,
    ) -> Result<WorkUnit, WorkUnitLifecycleError> {
        let operation = command.transition.operation();
        if self
            .db
            .get_dedup_request(command.request_id, operation)
            .map_err(WorkUnitLifecycleError::Storage)?
            .is_some_and(|record| record.work_unit_id == command.work_unit_id)
        {
            return self.load(command.work_unit_id);
        }

        let work_unit = match command.transition {
            WorkUnitTransition::Heartbeat => self
                .db
                .heartbeat_work_unit(command.work_unit_id, command.now_ms),
            WorkUnitTransition::Complete => self
                .db
                .complete_work_unit(command.work_unit_id, command.now_ms),
            WorkUnitTransition::Fail(reason) => {
                self.db
                    .fail_work_unit(command.work_unit_id, reason, command.now_ms)
            }
            WorkUnitTransition::Cancel(reason) => {
                self.db
                    .cancel_work_unit(command.work_unit_id, reason, command.now_ms)
            }
        }
        .map_err(WorkUnitLifecycleError::FailedPrecondition)?;
        self.record(
            command.request_id,
            operation,
            command.principal,
            &work_unit,
            command.now_ms,
        )?;
        Ok(work_unit)
    }

    pub(crate) fn reconcile(
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

    fn record(
        &self,
        request_id: &str,
        operation: &str,
        principal: &str,
        work_unit: &WorkUnit,
        now_ms: i64,
    ) -> Result<(), WorkUnitLifecycleError> {
        self.db
            .record_dedup_request(&RequestDedup {
                request_id: request_id.into(),
                operation: operation.into(),
                principal: principal.into(),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: now_ms,
            })
            .map_err(WorkUnitLifecycleError::Storage)
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
        WORK_UNIT_STATUS_PENDING,
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
}
