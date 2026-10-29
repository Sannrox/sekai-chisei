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
    /// Budget idempotency key the current charge was reserved under, so a
    /// refund finds the charge's period (#1902). Empty when nothing was
    /// charged or a version before it wrote the row.
    pub charge_key: String,
}

impl OperationReservation {
    pub fn is_pending(&self) -> bool {
        self.status == RESERVATION_PENDING
    }
}

#[allow(dead_code)]
pub trait ChiseiOperationReservationBackend {
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
                    created_at_ms, updated_at_ms, expires_at_ms, charge_key
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
                created_at_ms, updated_at_ms, expires_at_ms, charge_key
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(namespace, operation_id) DO UPDATE SET
                request_digest=excluded.request_digest,
                status=excluded.status,
                actor=excluded.actor,
                budget_subject=excluded.budget_subject,
                incurred_usage=excluded.incurred_usage,
                sekai_instance_id=excluded.sekai_instance_id,
                sekai_status=excluded.sekai_status,
                updated_at_ms=excluded.updated_at_ms,
                expires_at_ms=excluded.expires_at_ms,
                charge_key=excluded.charge_key",
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
                reservation.charge_key,
            ],
        )
        .map_err(|error| error.to_string())?;
        Ok(reservation.clone())
    }

    /// Move a pending reservation to `next`'s status and Sekai commit with no
    /// usage and, when `refund_metric` is given, give its usage back along the
    /// budget chain in the period it was charged in, in one write transaction. Returns the stored row, or `None` when the row is absent
    /// or already left `pending`, so racing callers refund once and a crash
    /// leaves both writes or neither (#1902).
    pub fn settle_pending_reservation(
        &self,
        next: &OperationReservation,
        refund_metric: Option<&str>,
    ) -> Result<Option<OperationReservation>, String> {
        validate_reservation(next)?;
        let (namespace, operation_id) = (next.namespace.as_str(), next.operation_id.as_str());
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT namespace, operation_id, request_digest, status, actor,
                        budget_subject, incurred_usage, sekai_instance_id, sekai_status,
                        created_at_ms, updated_at_ms, expires_at_ms, charge_key
                 FROM chisei_operation_reservations
                 WHERE namespace=?1 AND operation_id=?2",
                params![namespace, operation_id],
                row_to_reservation,
            )
            .optional()
            .map_err(|error| error.to_string())?;
        // Fenced to the caller's acquisition: a stale caller must not settle
        // a later acquisition of the same operation. `next` carries the
        // snapshot's charge key and expiry, which identify it.
        let Some(current) = current.filter(|row| {
            row.is_pending()
                && row.charge_key == next.charge_key
                && row.expires_at_ms == next.expires_at_ms
        }) else {
            return Ok(None);
        };
        tx.execute(
            "UPDATE chisei_operation_reservations
             SET status=?3, incurred_usage=0, sekai_instance_id=?4, sekai_status=?5,
                 updated_at_ms=?6
             WHERE namespace=?1 AND operation_id=?2",
            params![
                namespace,
                operation_id,
                next.status,
                next.sekai_instance_id,
                next.sekai_status,
                next.updated_at_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        if let Some(metric) = refund_metric
            && current.incurred_usage > 0
        {
            // The charge's own idempotency event dates it, so a row written
            // later than its charge still refunds the right period. Without a
            // recorded key, the row's time is the fallback.
            let charged_at: Option<i64> = if current.charge_key.is_empty() {
                None
            } else {
                tx.query_row(
                    "SELECT created_at FROM chisei_budget_usage_events
                     WHERE idempotency_key=?1 AND scope_id=?2 AND metric=?3",
                    params![current.charge_key, current.budget_subject, metric],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
            };
            crate::db::chisei_budget::adjust_chain_tx(
                &tx,
                &current.budget_subject,
                metric,
                -current.incurred_usage,
                charged_at.unwrap_or(current.updated_at_ms),
            )?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(Some(OperationReservation {
            status: next.status.clone(),
            incurred_usage: 0,
            sekai_instance_id: next.sekai_instance_id.clone(),
            sekai_status: next.sekai_status.clone(),
            updated_at_ms: next.updated_at_ms,
            ..current
        }))
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
                        created_at_ms, updated_at_ms, expires_at_ms, charge_key
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
        charge_key: row.get(12)?,
    })
}

pub fn validate_reservation(reservation: &OperationReservation) -> Result<(), String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;

    fn reservation(operation_id: &str, status: &str) -> OperationReservation {
        OperationReservation {
            namespace: "acme".into(),
            operation_id: operation_id.into(),
            request_digest: "digest".into(),
            status: status.into(),
            actor: "alice".into(),
            budget_subject: "action:governed".into(),
            incurred_usage: 1,
            sekai_instance_id: String::new(),
            sekai_status: String::new(),
            created_at_ms: 1,
            updated_at_ms: 1,
            expires_at_ms: 10,
            charge_key: String::new(),
        }
    }

    /// Of two settlements of one pending reservation only the first applies:
    /// the second finds it no longer pending (#1902).
    fn release_applies_once(db: &RuntimeDb, operation_id: &str) {
        db.put_operation_reservation(&reservation(operation_id, RESERVATION_PENDING))
            .unwrap();
        let next = OperationReservation {
            updated_at_ms: 2,
            sekai_instance_id: "gai-1".into(),
            sekai_status: "denied".into(),
            ..reservation(operation_id, RESERVATION_FINALIZED)
        };
        let settled = db
            .settle_pending_reservation(&next, None)
            .unwrap()
            .expect("first settle");
        assert_eq!(settled.status, RESERVATION_FINALIZED);
        assert_eq!(settled.incurred_usage, 0);
        assert_eq!(settled.sekai_instance_id, "gai-1");
        assert!(
            db.settle_pending_reservation(&next, None)
                .unwrap()
                .is_none()
        );
        let stored = db
            .get_operation_reservation("acme", operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored, settled);
    }

    #[test]
    fn sqlite_release_applies_once() {
        release_applies_once(&RuntimeDb::memory_for_chisei_sql_functions(), "op-once");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_release_applies_once() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        release_applies_once(&db, "op-once");
    }
}
