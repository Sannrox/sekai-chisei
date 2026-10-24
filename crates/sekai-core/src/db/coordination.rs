//! Backend-neutral reusable coordination persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::coordination::{
    AdmissionResult, ContentionScope, ReconcileFilter, ReconcileSummary, RequestDedup, Reservation,
    ReservationFilter, RunEvent, WorkUnit, WorkUnitFilter,
};

pub trait CoordinationBackend: Send + Sync {
    fn create_contention_scope(&self, scope: &ContentionScope) -> Result<(), String>;
    fn get_contention_scope(&self, id: &str) -> Result<Option<ContentionScope>, String>;
    fn create_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String>;
    fn get_work_unit(&self, id: &str) -> Result<Option<WorkUnit>, String>;
    fn get_work_unit_by_idempotency_key(&self, key: &str) -> Result<Option<WorkUnit>, String>;
    fn list_work_units(&self, filter: &WorkUnitFilter) -> Result<Vec<WorkUnit>, String>;
    fn try_admit_work_unit(
        &self,
        id: &str,
        owner: &str,
        now_ms: i64,
    ) -> Result<AdmissionResult, String>;
    fn heartbeat_work_unit(&self, id: &str, now_ms: i64) -> Result<WorkUnit, String>;
    fn complete_work_unit(&self, id: &str, now_ms: i64) -> Result<WorkUnit, String>;
    fn cancel_work_unit(&self, id: &str, reason: &str, now_ms: i64) -> Result<WorkUnit, String>;
    fn list_reservations(&self, filter: &ReservationFilter) -> Result<Vec<Reservation>, String>;
    fn append_run_event(&self, event: &RunEvent) -> Result<(), String>;
    fn list_run_events(
        &self,
        id: &str,
        limit: i32,
        after: i64,
        types: &[String],
        token: Option<&str>,
    ) -> Result<Vec<RunEvent>, String>;
    fn record_dedup_request(&self, request: &RequestDedup) -> Result<(), String>;
    fn get_dedup_request(
        &self,
        request_id: &str,
        operation: &str,
    ) -> Result<Option<RequestDedup>, String>;
    fn reconcile_work_units(
        &self,
        now_ms: i64,
        filter: &ReconcileFilter,
    ) -> Result<ReconcileSummary, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn create_contention_scope(&self, v: &ContentionScope) -> Result<(), String> {
            <$target>::create_contention_scope(self, v)
        }
        fn get_contention_scope(&self, id: &str) -> Result<Option<ContentionScope>, String> {
            <$target>::get_contention_scope(self, id)
        }
        fn create_work_unit(&self, v: &WorkUnit) -> Result<(), String> {
            <$target>::create_work_unit(self, v)
        }
        fn get_work_unit(&self, id: &str) -> Result<Option<WorkUnit>, String> {
            <$target>::get_work_unit(self, id)
        }
        fn get_work_unit_by_idempotency_key(&self, key: &str) -> Result<Option<WorkUnit>, String> {
            <$target>::get_work_unit_by_idempotency_key(self, key)
        }
        fn list_work_units(&self, v: &WorkUnitFilter) -> Result<Vec<WorkUnit>, String> {
            <$target>::list_work_units(self, v)
        }
        fn try_admit_work_unit(
            &self,
            id: &str,
            owner: &str,
            now: i64,
        ) -> Result<AdmissionResult, String> {
            <$target>::try_admit_work_unit(self, id, owner, now)
        }
        fn heartbeat_work_unit(&self, id: &str, now: i64) -> Result<WorkUnit, String> {
            <$target>::heartbeat_work_unit(self, id, now)
        }
        fn complete_work_unit(&self, id: &str, now: i64) -> Result<WorkUnit, String> {
            <$target>::complete_work_unit(self, id, now)
        }
        fn cancel_work_unit(&self, id: &str, reason: &str, now: i64) -> Result<WorkUnit, String> {
            <$target>::cancel_work_unit(self, id, reason, now)
        }
        fn list_reservations(&self, v: &ReservationFilter) -> Result<Vec<Reservation>, String> {
            <$target>::list_reservations(self, v)
        }
        fn append_run_event(&self, v: &RunEvent) -> Result<(), String> {
            <$target>::append_run_event(self, v)
        }
        fn list_run_events(
            &self,
            id: &str,
            limit: i32,
            after: i64,
            types: &[String],
            token: Option<&str>,
        ) -> Result<Vec<RunEvent>, String> {
            <$target>::list_run_events(self, id, limit, after, types, token)
        }
        fn record_dedup_request(&self, v: &RequestDedup) -> Result<(), String> {
            <$target>::record_dedup_request(self, v)
        }
        fn get_dedup_request(
            &self,
            id: &str,
            operation: &str,
        ) -> Result<Option<RequestDedup>, String> {
            <$target>::get_dedup_request(self, id, operation)
        }
        fn reconcile_work_units(
            &self,
            now: i64,
            v: &ReconcileFilter,
        ) -> Result<ReconcileSummary, String> {
            <$target>::reconcile_work_units(self, now, v)
        }
    };
}

impl CoordinationBackend for SekaiDb {
    forward!(SekaiDb);
}
impl CoordinationBackend for PostgresDb {
    forward!(PostgresDb);
}
