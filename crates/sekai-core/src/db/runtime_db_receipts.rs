//! Dual-backend community-store dispatch for receipts.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_operation_receipt(receipt),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_operation_receipt(receipt))
            }
        }
    }

    pub fn get_operation_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        match self {
            Self::Sqlite(db) => db.get_operation_receipt(operation_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_operation_receipt(operation_id))
            }
        }
    }

    /// List operation receipts for a namespace overlapping `[start, end)`.
    ///
    /// Open receipts (`completed_at_ms` unset) overlap only while
    /// `started_at_ms` is within
    /// [`OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS`](crate::db::chisei_receipt::OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS)
    /// of `start`. That keeps in-flight harvest visible without letting
    /// abandoned opens accumulate across every later window.
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_operation_receipts_in_window(
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    limit,
                )
            }),
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
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.update_operation_receipt(operation_id, update)
            }),
        }
    }
}
