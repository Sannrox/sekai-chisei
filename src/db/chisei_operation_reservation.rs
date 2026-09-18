//! Chisei-owned admission reservations keyed by `(namespace, operation_id)`.

use rusqlite::{OptionalExtension, params};

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;

pub const RESERVATION_PENDING: &str = "pending";
pub const RESERVATION_FINALIZED: &str = "finalized";
pub const RESERVATION_RELEASED: &str = "released";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationReservation {
    pub namespace: String,
    pub operation_id: String,
    pub request_digest: String,
    pub status: String,
    pub actor: String,
    pub budget_subject: String,
    pub incurred_usage: i64,
    pub sekai_instance_id: String,
    pub sekai_status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub expires_at_ms: i64,
}

impl OperationReservation {
    pub fn is_pending(&self) -> bool {
        self.status == RESERVATION_PENDING
    }
}

#[allow(dead_code)]
pub(crate) trait ChiseiOperationReservationBackend {
    fn get_operation_reservation(
        &self,
        namespace: &str,
        operation_id: &str,
    ) -> Result<Option<OperationReservation>, String>;
    fn put_operation_reservation(
        &self,
        reservation: &OperationReservation,
    ) -> Result<OperationReservation, String>;
    fn list_pending_operation_reservations(
        &self,
        limit: usize,
    ) -> Result<Vec<OperationReservation>, String>;
}

macro_rules! forward_reservation {
    ($target:ty) => {
        fn get_operation_reservation(
            &self,
            namespace: &str,
            operation_id: &str,
        ) -> Result<Option<OperationReservation>, String> {
            <$target>::get_operation_reservation(self, namespace, operation_id)
        }
        fn put_operation_reservation(
            &self,
            reservation: &OperationReservation,
        ) -> Result<OperationReservation, String> {
            <$target>::put_operation_reservation(self, reservation)
        }
        fn list_pending_operation_reservations(
            &self,
            limit: usize,
        ) -> Result<Vec<OperationReservation>, String> {
            <$target>::list_pending_operation_reservations(self, limit)
        }
    };
}

impl ChiseiOperationReservationBackend for SekaiDb {
    forward_reservation!(SekaiDb);
}

impl ChiseiOperationReservationBackend for PostgresDb {
    forward_reservation!(PostgresDb);
}

impl SekaiDb {
    pub fn get_operation_reservation(
        &self,
        namespace: &str,
        operation_id: &str,
    ) -> Result<Option<OperationReservation>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT namespace, operation_id, request_digest, status, actor,
                    budget_subject, incurred_usage, sekai_instance_id, sekai_status,
                    created_at_ms, updated_at_ms, expires_at_ms
             FROM chisei_operation_reservations
             WHERE namespace=?1 AND operation_id=?2",
            params![namespace, operation_id],
            row_to_reservation,
        )
        .optional()
        .map_err(|error| error.to_string())
    }

    pub fn put_operation_reservation(
        &self,
        reservation: &OperationReservation,
    ) -> Result<OperationReservation, String> {
        validate_reservation(reservation)?;
        let conn = self.conn();
        conn.execute(
            "INSERT INTO chisei_operation_reservations(
                namespace, operation_id, request_digest, status, actor,
                budget_subject, incurred_usage, sekai_instance_id, sekai_status,
                created_at_ms, updated_at_ms, expires_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(namespace, operation_id) DO UPDATE SET
                request_digest=excluded.request_digest,
                status=excluded.status,
                actor=excluded.actor,
                budget_subject=excluded.budget_subject,
                incurred_usage=excluded.incurred_usage,
                sekai_instance_id=excluded.sekai_instance_id,
                sekai_status=excluded.sekai_status,
                updated_at_ms=excluded.updated_at_ms,
                expires_at_ms=excluded.expires_at_ms",
            params![
                reservation.namespace,
                reservation.operation_id,
                reservation.request_digest,
                reservation.status,
                reservation.actor,
                reservation.budget_subject,
                reservation.incurred_usage,
                reservation.sekai_instance_id,
                reservation.sekai_status,
                reservation.created_at_ms,
                reservation.updated_at_ms,
                reservation.expires_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(reservation.clone())
    }

    pub fn list_pending_operation_reservations(
        &self,
        limit: usize,
    ) -> Result<Vec<OperationReservation>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT namespace, operation_id, request_digest, status, actor,
                        budget_subject, incurred_usage, sekai_instance_id, sekai_status,
                        created_at_ms, updated_at_ms, expires_at_ms
                 FROM chisei_operation_reservations
                 WHERE status=?1
                 ORDER BY created_at_ms ASC
                 LIMIT ?2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![RESERVATION_PENDING, limit.min(1_000) as i64],
                row_to_reservation,
            )
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }
}

fn row_to_reservation(row: &rusqlite::Row<'_>) -> Result<OperationReservation, rusqlite::Error> {
    Ok(OperationReservation {
        namespace: row.get(0)?,
        operation_id: row.get(1)?,
        request_digest: row.get(2)?,
        status: row.get(3)?,
        actor: row.get(4)?,
        budget_subject: row.get(5)?,
        incurred_usage: row.get(6)?,
        sekai_instance_id: row.get(7)?,
        sekai_status: row.get(8)?,
        created_at_ms: row.get(9)?,
        updated_at_ms: row.get(10)?,
        expires_at_ms: row.get(11)?,
    })
}

pub(crate) fn validate_reservation(reservation: &OperationReservation) -> Result<(), String> {
    if reservation.namespace.trim().is_empty() {
        return Err("namespace required".into());
    }
    if reservation.operation_id.trim().is_empty() {
        return Err("operation_id required".into());
    }
    if reservation.request_digest.trim().is_empty() {
        return Err("request_digest required".into());
    }
    match reservation.status.as_str() {
        RESERVATION_PENDING | RESERVATION_FINALIZED | RESERVATION_RELEASED => Ok(()),
        other => Err(format!("unsupported reservation status '{other}'")),
    }
}
