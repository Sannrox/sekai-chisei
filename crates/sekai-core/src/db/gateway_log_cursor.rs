//! Durable cursors over the gateway egress logs Chisei reads (ADR 0152
//! decision 6, #3096).
//!
//! One row per configured gateway holds the highest log sequence whose
//! records are committed here. [`GatewayLogBatch`] writes a batch's
//! `llm_calls` rows and decision entries in the same transaction that moves
//! the cursor by compare-and-set, so a restart resumes without double writes
//! and of several readers over one gateway only one applies each batch.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::postgres::PostgresDb;
use super::runtime_db::RuntimeDb;
use super::sekai::SekaiDb;
use crate::sekai::audit::{Decision, validate_decision};

/// The dataset gateway usage rows land in.
pub const LLM_CALLS_DATASET: &str = "llm_calls";

/// The Sekai writes of gateway log records `after_seq + 1 ..= through_seq`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayLogBatch {
    pub gateway: String,
    /// The cursor this batch expects; it applies only while the cursor is here.
    pub after_seq: u64,
    pub through_seq: u64,
    pub llm_calls_rows: Vec<HashMap<String, String>>,
    /// Entries whose id is already recorded are skipped.
    pub decisions: Vec<Decision>,
}

impl GatewayLogBatch {
    fn validate(&self) -> Result<(), String> {
        if self.gateway.trim().is_empty() {
            return Err("gateway log batch needs a gateway name".into());
        }
        if self.through_seq <= self.after_seq {
            return Err("gateway log batch must advance the cursor".into());
        }
        self.decisions.iter().try_for_each(validate_decision)
    }
}

fn seq_column(seq: u64) -> Result<i64, String> {
    i64::try_from(seq).map_err(|_| format!("gateway log sequence {seq} out of range"))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl SekaiDb {
    pub(crate) fn migrate_gateway_log_cursors(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_gateway_log_cursors (
                    gateway TEXT PRIMARY KEY,
                    seq INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );",
            )
            .map_err(|error| error.to_string())
    }

    pub fn gateway_log_cursor(&self, gateway: &str) -> Result<u64, String> {
        let seq: Option<i64> = self
            .conn()
            .query_row(
                "SELECT seq FROM sekai_gateway_log_cursors WHERE gateway = ?1",
                params![gateway],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        Ok(seq.unwrap_or(0).max(0) as u64)
    }

    /// See [`RuntimeDb::apply_gateway_log_batch`].
    pub fn apply_gateway_log_batch(&self, batch: &GatewayLogBatch) -> Result<bool, String> {
        batch.validate()?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let through = seq_column(batch.through_seq)?;
        let moved = if batch.after_seq == 0 {
            tx.execute(
                "INSERT INTO sekai_gateway_log_cursors (gateway, seq, updated_at_ms)
                 VALUES (?1, ?2, ?3) ON CONFLICT (gateway) DO NOTHING",
                params![batch.gateway, through, now_ms()],
            )
        } else {
            tx.execute(
                "UPDATE sekai_gateway_log_cursors SET seq = ?2, updated_at_ms = ?3
                 WHERE gateway = ?1 AND seq = ?4",
                params![
                    batch.gateway,
                    through,
                    now_ms(),
                    seq_column(batch.after_seq)?
                ],
            )
        }
        .map_err(|error| error.to_string())?;
        if moved != 1 {
            return Ok(false);
        }
        crate::sekai::dataset::append_rows_tx(&tx, LLM_CALLS_DATASET, &batch.llm_calls_rows)?;
        for decision in &batch.decisions {
            let recorded = tx
                .query_row(
                    "SELECT 1 FROM sekai_decisions WHERE id = ?1",
                    params![decision.id],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .is_some();
            if !recorded {
                crate::sekai::decision_ledger::insert_chained_decision(&tx, decision)?;
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

impl PostgresDb {
    pub fn gateway_log_cursor(&self, gateway: &str) -> Result<u64, String> {
        let seq: Option<i64> = self
            .connection()?
            .query_opt(
                "SELECT seq FROM sekai_gateway_log_cursors WHERE gateway = $1",
                &[&gateway],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        Ok(seq.unwrap_or(0).max(0) as u64)
    }

    /// See [`RuntimeDb::apply_gateway_log_batch`].
    pub fn apply_gateway_log_batch(&self, batch: &GatewayLogBatch) -> Result<bool, String> {
        batch.validate()?;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let through = seq_column(batch.through_seq)?;
        let moved = if batch.after_seq == 0 {
            tx.execute(
                "INSERT INTO sekai_gateway_log_cursors (gateway, seq, updated_at_ms)
                 VALUES ($1, $2, $3) ON CONFLICT (gateway) DO NOTHING",
                &[&batch.gateway, &through, &now_ms()],
            )
        } else {
            tx.execute(
                "UPDATE sekai_gateway_log_cursors SET seq = $2, updated_at_ms = $3
                 WHERE gateway = $1 AND seq = $4",
                &[
                    &batch.gateway,
                    &through,
                    &now_ms(),
                    &seq_column(batch.after_seq)?,
                ],
            )
        }
        .map_err(|error| error.to_string())?;
        if moved != 1 {
            return Ok(false);
        }
        crate::db::postgres_dataset::append_dataset_rows_tx(
            &mut tx,
            LLM_CALLS_DATASET,
            &batch.llm_calls_rows,
        )?;
        for decision in &batch.decisions {
            let recorded = tx
                .query_opt(
                    "SELECT 1 FROM sekai_decisions WHERE id = $1",
                    &[&decision.id],
                )
                .map_err(|error| error.to_string())?
                .is_some();
            if !recorded {
                crate::db::postgres_decision::insert_chained_decision(&mut tx, decision)?;
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

impl RuntimeDb {
    /// The highest sequence of `gateway`'s log committed here; 0 before any.
    pub fn gateway_log_cursor(&self, gateway: &str) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.gateway_log_cursor(gateway),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.gateway_log_cursor(gateway))
            }
        }
    }

    /// Writes `batch` and moves the gateway's cursor from `after_seq` to
    /// `through_seq` in one transaction. Returns `false`, writing nothing,
    /// when the cursor is no longer at `after_seq` (another reader applied
    /// those records first).
    pub fn apply_gateway_log_batch(&self, batch: &GatewayLogBatch) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.apply_gateway_log_batch(batch),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.apply_gateway_log_batch(batch))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(after_seq: u64, through_seq: u64) -> GatewayLogBatch {
        GatewayLogBatch {
            gateway: "edge".into(),
            after_seq,
            through_seq,
            llm_calls_rows: Vec::new(),
            decisions: vec![Decision {
                id: format!("gateway-log:edge:{through_seq}"),
                timestamp: 1,
                actor: "alice".into(),
                action: "gateway.admission".into(),
                reason: "admitted".into(),
                evidence: HashMap::new(),
                target_id: "op".into(),
                outcome: "admitted".into(),
            }],
        }
    }

    #[test]
    fn a_batch_applies_only_from_the_cursor_it_was_read_at() {
        let db = SekaiDb::new(":memory:").unwrap();
        assert_eq!(db.gateway_log_cursor("edge").unwrap(), 0);
        assert!(db.apply_gateway_log_batch(&batch(0, 2)).unwrap());
        // A second reader that read the same cursor writes nothing.
        assert!(!db.apply_gateway_log_batch(&batch(0, 2)).unwrap());
        assert!(!db.apply_gateway_log_batch(&batch(1, 3)).unwrap());
        assert!(db.apply_gateway_log_batch(&batch(2, 3)).unwrap());
        assert_eq!(db.gateway_log_cursor("edge").unwrap(), 3);
        assert_eq!(db.gateway_log_cursor("other").unwrap(), 0);
        assert!(db.apply_gateway_log_batch(&batch(3, 3)).is_err());
    }
}
