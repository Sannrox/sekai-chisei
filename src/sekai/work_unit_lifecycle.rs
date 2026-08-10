//! Durable Work Unit lifecycle orchestration.
//!
//! The gRPC adapter authenticates and authorizes a request before crossing this
//! seam. This module owns replay identity, transition persistence, and durable
//! request deduplication so every transport observes the same ordering.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::coordination::{
    AdmissionResult, RESERVATION_STATUS_ACTIVE, RequestDedup, ReservationFilter,
    WORK_UNIT_STATUS_RUNNING, WorkUnit,
};

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
    FailedPrecondition(String),
    Storage(String),
}

pub(crate) struct WorkUnitLifecycle<'a> {
    db: &'a RuntimeDb,
}

impl<'a> WorkUnitLifecycle<'a> {
    pub(crate) fn new(db: &'a RuntimeDb) -> Self {
        Self { db }
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

    fn load(&self, work_unit_id: &str) -> Result<WorkUnit, WorkUnitLifecycleError> {
        self.db
            .get_work_unit(work_unit_id)
            .map_err(WorkUnitLifecycleError::Storage)?
            .ok_or_else(|| WorkUnitLifecycleError::NotFound("work unit not found".into()))
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

    fn database() -> RuntimeDb {
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
        db.create_work_unit(&work_unit()).unwrap();
        db
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
