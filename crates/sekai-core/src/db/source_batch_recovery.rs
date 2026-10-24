//! Recovering a source binding's open batch from its stored body (#1766).
//!
//! `apply_source_batch` persists a batch as an OPEN transaction before it
//! commits it, and a replay of the identical batch resumes it. A caller that
//! no longer holds that batch (a replacement process, a sandboxed connector
//! whose output is gone) recovers through the stored body instead: resuming
//! re-applies it exactly as a replay would, and aborting closes it with a
//! reason and leaves the checkpoint where it was.

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::object_sync::{SourceBatch, SourceBatchResult};

/// A binding's open transaction: its id, producer and stored batch.
pub struct OpenSourceBatch {
    pub transaction_id: String,
    pub producer_identity: String,
    pub batch_json: String,
}

/// The open transaction of a binding, selected by its lookup key.
const OPEN_SQL_SQLITE: &str = "SELECT t.transaction_id, t.producer_identity, t.batch_json
     FROM sekai_source_batch_transactions t
     JOIN sekai_source_bindings b ON b.binding_id = t.binding_id
     WHERE b.namespace = ?1 AND b.source_instance = ?2 AND b.type_digest = ?3
       AND t.status = 'OPEN'";
const OPEN_SQL_POSTGRES: &str = "SELECT t.transaction_id, t.producer_identity, t.batch_json
     FROM sekai_source_batch_transactions t
     JOIN sekai_source_bindings b ON b.binding_id = t.binding_id
     WHERE b.namespace = $1 AND b.source_instance = $2 AND b.type_digest = $3
       AND t.status = 'OPEN'";

impl SekaiDb {
    pub fn open_source_batch(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<OpenSourceBatch>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                OPEN_SQL_SQLITE,
                rusqlite::params![namespace, source_instance, type_digest],
                |row| {
                    Ok(OpenSourceBatch {
                        transaction_id: row.get(0)?,
                        producer_identity: row.get(1)?,
                        batch_json: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn abort_open_source_transaction(
        &self,
        transaction_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                "UPDATE sekai_source_batch_transactions
                 SET status = 'ABORTED', outcome = 'denial', closed_at_ms = ?1, reason = ?2
                 WHERE transaction_id = ?3 AND status = 'OPEN'",
                rusqlite::params![now_ms, reason, transaction_id],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }
}

impl PostgresDb {
    pub fn open_source_batch(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<OpenSourceBatch>, String> {
        Ok(self
            .connection()?
            .query_opt(
                OPEN_SQL_POSTGRES,
                &[&namespace, &source_instance, &type_digest],
            )
            .map_err(|error| error.to_string())?
            .map(|row| OpenSourceBatch {
                transaction_id: row.get(0),
                producer_identity: row.get(1),
                batch_json: row.get(2),
            }))
    }

    pub fn abort_open_source_transaction(
        &self,
        transaction_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.connection()?
            .execute(
                "UPDATE sekai_source_batch_transactions
                 SET status = 'ABORTED', outcome = 'denial', closed_at_ms = $1, reason = $2
                 WHERE transaction_id = $3 AND status = 'OPEN'",
                &[&now_ms, &reason, &transaction_id],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }
}

/// The open transaction belongs to another producer.
pub const PRODUCER_MISMATCH: &str =
    "open_transaction_producer_mismatch: the open batch belongs to another producer";
const MAX_ABORT_REASON: usize = 1024;

impl RuntimeDb {
    fn open_source_batch(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
    ) -> Result<Option<OpenSourceBatch>, String> {
        match self {
            Self::Sqlite(db) => db.open_source_batch(namespace, source_instance, type_digest),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.open_source_batch(namespace, source_instance, type_digest)
            }),
        }
    }

    /// Re-applies the stored body of the binding's open transaction, as
    /// `producer`, exactly as replaying the identical batch would. `None`
    /// when the binding has no open transaction. Concurrent resumes commit
    /// once: the replay path itself makes them idempotent.
    pub fn resume_open_source_batch(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
        producer: &str,
        now_ms: i64,
    ) -> Result<Option<SourceBatchResult>, String> {
        let Some(open) = self.open_source_batch(namespace, source_instance, type_digest)? else {
            return Ok(None);
        };
        if open.producer_identity != producer {
            return Err(PRODUCER_MISMATCH.into());
        }
        let batch: SourceBatch = serde_json::from_str(&open.batch_json)
            .map_err(|error| format!("stored source batch is unreadable: {error}"))?;
        self.apply_source_batch(&batch, producer, now_ms).map(Some)
    }

    /// Aborts the binding's open transaction with `reason`, for a batch that
    /// can no longer become valid; the checkpoint stays where it was. True
    /// when this call aborted it; false when there was nothing open (or a
    /// concurrent call closed it first).
    pub fn abort_open_source_batch(
        &self,
        namespace: &str,
        source_instance: &str,
        type_digest: &str,
        producer: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        let reason = reason.trim();
        if reason.is_empty() || reason.len() > MAX_ABORT_REASON {
            return Err(format!(
                "abort reason must be 1 to {MAX_ABORT_REASON} bytes"
            ));
        }
        let Some(open) = self.open_source_batch(namespace, source_instance, type_digest)? else {
            return Ok(false);
        };
        if open.producer_identity != producer {
            return Err(PRODUCER_MISMATCH.into());
        }
        let reason = format!("aborted_by_producer: {reason}");
        match self {
            Self::Sqlite(db) => {
                db.abort_open_source_transaction(&open.transaction_id, &reason, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.abort_open_source_transaction(&open.transaction_id, &reason, now_ms)
            }),
        }
    }
}
