//! PostgreSQL Chisei admission reservations.

use crate::db::chisei_operation_reservation::{
    OperationReservation, RESERVATION_PENDING, validate_reservation,
};
use crate::db::postgres::PostgresDb;

impl PostgresDb {
    pub fn get_operation_reservation(
        &self,
        namespace: &str,
        operation_id: &str,
    ) -> Result<Option<OperationReservation>, String> {
        let row = self
            .connection()?
            .query_opt(
                "SELECT namespace, operation_id, request_digest, status, actor,
                        budget_subject, incurred_usage, sekai_instance_id, sekai_status,
                        created_at_ms, updated_at_ms, expires_at_ms, charge_key
                 FROM chisei_operation_reservations
                 WHERE namespace=$1 AND operation_id=$2",
                &[&namespace, &operation_id],
            )
            .map_err(|error| error.to_string())?;
        row.map(row_to_reservation).transpose()
    }

    /// See `SekaiDb::settle_pending_reservation` (#1902).
    pub fn settle_pending_reservation(
        &self,
        next: &OperationReservation,
        refund_metric: Option<&str>,
    ) -> Result<Option<OperationReservation>, String> {
        validate_reservation(next)?;
        let (namespace, operation_id) = (next.namespace.as_str(), next.operation_id.as_str());
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let current = transaction
            .query_opt(
                "SELECT namespace, operation_id, request_digest, status, actor,
                        budget_subject, incurred_usage, sekai_instance_id, sekai_status,
                        created_at_ms, updated_at_ms, expires_at_ms, charge_key
                 FROM chisei_operation_reservations
                 WHERE namespace=$1 AND operation_id=$2
                 FOR UPDATE",
                &[&namespace, &operation_id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_reservation)
            .transpose()?;
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
        transaction
            .execute(
                "UPDATE chisei_operation_reservations
                 SET status=$3, incurred_usage=0, sekai_instance_id=$4, sekai_status=$5,
                     updated_at_ms=$6
                 WHERE namespace=$1 AND operation_id=$2",
                &[
                    &namespace,
                    &operation_id,
                    &next.status,
                    &next.sekai_instance_id,
                    &next.sekai_status,
                    &next.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        if let Some(metric) = refund_metric
            && current.incurred_usage > 0
        {
            // See `SekaiDb::settle_pending_reservation`: the charge's
            // idempotency event dates it.
            let charged_at: Option<i64> = if current.charge_key.is_empty() {
                None
            } else {
                transaction
                    .query_opt(
                        "SELECT created_at FROM chisei_budget_usage_events
                         WHERE idempotency_key=$1 AND scope_id=$2 AND metric=$3",
                        &[&current.charge_key, &current.budget_subject, &metric],
                    )
                    .map_err(|error| error.to_string())?
                    .map(|row| row.get(0))
            };
            crate::db::postgres_budget::adjust_chain_tx(
                &mut transaction,
                &current.budget_subject,
                metric,
                -current.incurred_usage,
                charged_at.unwrap_or(current.updated_at_ms),
            )?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(Some(OperationReservation {
            status: next.status.clone(),
            incurred_usage: 0,
            sekai_instance_id: next.sekai_instance_id.clone(),
            sekai_status: next.sekai_status.clone(),
            updated_at_ms: next.updated_at_ms,
            ..current
        }))
    }

    pub fn put_operation_reservation(
        &self,
        reservation: &OperationReservation,
    ) -> Result<OperationReservation, String> {
        validate_reservation(reservation)?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_operation_reservations(
                    namespace, operation_id, request_digest, status, actor,
                    budget_subject, incurred_usage, sekai_instance_id, sekai_status,
                    created_at_ms, updated_at_ms, expires_at_ms, charge_key
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                 ON CONFLICT (namespace, operation_id) DO UPDATE SET
                    request_digest=EXCLUDED.request_digest,
                    status=EXCLUDED.status,
                    actor=EXCLUDED.actor,
                    budget_subject=EXCLUDED.budget_subject,
                    incurred_usage=EXCLUDED.incurred_usage,
                    sekai_instance_id=EXCLUDED.sekai_instance_id,
                    sekai_status=EXCLUDED.sekai_status,
                    updated_at_ms=EXCLUDED.updated_at_ms,
                    expires_at_ms=EXCLUDED.expires_at_ms,
                    charge_key=EXCLUDED.charge_key",
                &[
                    &reservation.namespace,
                    &reservation.operation_id,
                    &reservation.request_digest,
                    &reservation.status,
                    &reservation.actor,
                    &reservation.budget_subject,
                    &reservation.incurred_usage,
                    &reservation.sekai_instance_id,
                    &reservation.sekai_status,
                    &reservation.created_at_ms,
                    &reservation.updated_at_ms,
                    &reservation.expires_at_ms,
                    &reservation.charge_key,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(reservation.clone())
    }

    pub fn list_pending_operation_reservations(
        &self,
        limit: usize,
    ) -> Result<Vec<OperationReservation>, String> {
        let limit = i64::try_from(limit.min(1_000)).unwrap_or(1_000);
        let rows = self
            .connection()?
            .query(
                "SELECT namespace, operation_id, request_digest, status, actor,
                        budget_subject, incurred_usage, sekai_instance_id, sekai_status,
                        created_at_ms, updated_at_ms, expires_at_ms, charge_key
                 FROM chisei_operation_reservations
                 WHERE status=$1
                 ORDER BY created_at_ms ASC
                 LIMIT $2",
                &[&RESERVATION_PENDING, &limit],
            )
            .map_err(|error| error.to_string())?;
        rows.into_iter().map(row_to_reservation).collect()
    }
}

fn row_to_reservation(row: postgres::Row) -> Result<OperationReservation, String> {
    Ok(OperationReservation {
        namespace: row.get(0),
        operation_id: row.get(1),
        request_digest: row.get(2),
        status: row.get(3),
        actor: row.get(4),
        budget_subject: row.get(5),
        incurred_usage: row.get(6),
        sekai_instance_id: row.get(7),
        sekai_status: row.get(8),
        created_at_ms: row.get(9),
        updated_at_ms: row.get(10),
        expires_at_ms: row.get(11),
        charge_key: row.get(12),
    })
}
