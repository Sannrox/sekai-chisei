//! Export grants and open exports (#1627) on both community backends.
//!
//! Grants are an append-only history per (namespace, principal): each
//! change inserts the next sequence number, so two concurrent changes cannot
//! both land, and the history is the durable record of who granted or
//! revoked what and why. Each export's receipt is a row kept for good,
//! holding the receipt, the exporter's lease while open, and its decided
//! outcome. Closing records the outcome under a condition (the exporter's
//! lease still live, or a sweeper's lease expired), so exactly one outcome is
//! decided; finishing writes it into the receipt in one conditional update,
//! so a crash at any step leaves an open row the next sweep finishes.

use crate::db::postgres::PostgresDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::data_export::ExportGrant;

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_export_grants (
    namespace TEXT NOT NULL,
    principal TEXT NOT NULL,
    seq INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    PRIMARY KEY (namespace, principal, seq)
);
CREATE TABLE IF NOT EXISTS sekai_export_receipts (
    operation_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    lease_until_ms INTEGER NOT NULL,
    receipt_json TEXT NOT NULL,
    closing_json TEXT,
    closed INTEGER NOT NULL DEFAULT 0
);
";

/// One dataset version row with its row id.
pub type VersionRow = (i64, std::collections::HashMap<String, String>);

fn decode(json: &str) -> Result<ExportGrant, String> {
    serde_json::from_str(json).map_err(|error| format!("corrupt export grant: {error}"))
}

fn encode(grant: &ExportGrant) -> Result<String, String> {
    serde_json::to_string(grant).map_err(|error| error.to_string())
}

impl SekaiDb {
    pub(crate) fn migrate_export_grants(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    pub fn latest_export_grant(
        &self,
        namespace: &str,
        principal: &str,
    ) -> Result<Option<(i64, ExportGrant)>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT seq, record_json FROM sekai_export_grants
                 WHERE namespace = ?1 AND principal = ?2 ORDER BY seq DESC LIMIT 1",
                rusqlite::params![namespace, principal],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|(seq, json)| decode(&json).map(|grant| (seq, grant)))
            .transpose()
    }

    pub fn export_grant_history(
        &self,
        namespace: &str,
        principal: &str,
    ) -> Result<Vec<(i64, ExportGrant)>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT seq, record_json FROM sekai_export_grants
                 WHERE namespace = ?1 AND principal = ?2 ORDER BY seq",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![namespace, principal], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (seq, json) = row.map_err(|error| error.to_string())?;
            decode(&json).map(|grant| (seq, grant))
        })
        .collect()
    }

    pub fn insert_export_grant(&self, seq: i64, grant: &ExportGrant) -> Result<bool, String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_export_grants (namespace, principal, seq, record_json)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                rusqlite::params![grant.namespace, grant.principal, seq, encode(grant)?],
            )
            .map(|inserted| inserted == 1)
            .map_err(|error| error.to_string())
    }

    pub fn open_export(
        &self,
        operation_id: &str,
        namespace: &str,
        lease_until_ms: i64,
        receipt_json: &str,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_export_receipts
                     (operation_id, namespace, lease_until_ms, receipt_json)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![operation_id, namespace, lease_until_ms, receipt_json],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn renew_export(
        &self,
        operation_id: &str,
        now_ms: i64,
        lease_until_ms: i64,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                "UPDATE sekai_export_receipts SET lease_until_ms = ?3
                 WHERE operation_id = ?1 AND closed = 0 AND closing_json IS NULL AND lease_until_ms >= ?2",
                rusqlite::params![operation_id, now_ms, lease_until_ms],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    pub fn claim_export_close(
        &self,
        operation_id: &str,
        closing_json: &str,
        expired: bool,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                "UPDATE sekai_export_receipts SET closing_json = ?2
                 WHERE operation_id = ?1 AND closed = 0 AND closing_json IS NULL
                   AND ((?3 AND lease_until_ms < ?4) OR (NOT ?3 AND lease_until_ms >= ?4))",
                rusqlite::params![operation_id, closing_json, expired, now_ms],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    pub fn open_export_row(
        &self,
        operation_id: &str,
    ) -> Result<Option<(Option<String>, String)>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT closing_json, receipt_json FROM sekai_export_receipts
                 WHERE operation_id = ?1 AND closed = 0",
                rusqlite::params![operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn finish_export_receipt(
        &self,
        operation_id: &str,
        receipt_json: &str,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE sekai_export_receipts SET receipt_json = ?2, closed = 1
                 WHERE operation_id = ?1 AND closed = 0 AND closing_json IS NOT NULL",
                rusqlite::params![operation_id, receipt_json],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_export_receipt_json(&self, operation_id: &str) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT receipt_json FROM sekai_export_receipts WHERE operation_id = ?1",
                rusqlite::params![operation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    /// Exports to finish: a recorded outcome, or a lease that ran out.
    pub fn recoverable_exports(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<(String, bool)>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT operation_id, closing_json IS NOT NULL FROM sekai_export_receipts
                 WHERE closed = 0 AND (closing_json IS NOT NULL OR lease_until_ms < ?1)
                 ORDER BY lease_until_ms LIMIT ?2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![now_ms, limit as i64], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }
    /// Up to `limit` rows of one dataset version after `after_row_id`, in
    /// row order, with their row ids: a keyset page, so a whole version is
    /// read in one pass with bounded memory.
    pub fn dataset_version_rows_after(
        &self,
        dataset_id: &str,
        version_id: &str,
        after_row_id: i64,
        limit: usize,
    ) -> Result<Vec<VersionRow>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT row_id, data FROM sekai_dataset_version_rows
                 WHERE dataset_id = ?1 AND version_id = ?2 AND row_id > ?3
                 ORDER BY row_id LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![dataset_id, version_id, after_row_id, limit as i64],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let (row_id, data) = row.map_err(|error| error.to_string())?;
            Ok((
                row_id,
                serde_json::from_str(&data).map_err(|error| error.to_string())?,
            ))
        })
        .collect()
    }
}

impl PostgresDb {
    pub fn latest_export_grant(
        &self,
        namespace: &str,
        principal: &str,
    ) -> Result<Option<(i64, ExportGrant)>, String> {
        self.connection()?
            .query_opt(
                "SELECT seq, record_json FROM sekai_export_grants
                 WHERE namespace = $1 AND principal = $2 ORDER BY seq DESC LIMIT 1",
                &[&namespace, &principal],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode(row.get(1)).map(|grant| (row.get::<_, i64>(0), grant)))
            .transpose()
    }

    pub fn export_grant_history(
        &self,
        namespace: &str,
        principal: &str,
    ) -> Result<Vec<(i64, ExportGrant)>, String> {
        self.connection()?
            .query(
                "SELECT seq, record_json FROM sekai_export_grants
                 WHERE namespace = $1 AND principal = $2 ORDER BY seq",
                &[&namespace, &principal],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| decode(row.get(1)).map(|grant| (row.get::<_, i64>(0), grant)))
            .collect()
    }

    pub fn insert_export_grant(&self, seq: i64, grant: &ExportGrant) -> Result<bool, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_export_grants (namespace, principal, seq, record_json)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[&grant.namespace, &grant.principal, &seq, &encode(grant)?],
            )
            .map(|inserted| inserted == 1)
            .map_err(|error| error.to_string())
    }

    pub fn open_export(
        &self,
        operation_id: &str,
        namespace: &str,
        lease_until_ms: i64,
        receipt_json: &str,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_export_receipts
                     (operation_id, namespace, lease_until_ms, receipt_json)
                 VALUES ($1, $2, $3, $4)",
                &[&operation_id, &namespace, &lease_until_ms, &receipt_json],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn renew_export(
        &self,
        operation_id: &str,
        now_ms: i64,
        lease_until_ms: i64,
    ) -> Result<bool, String> {
        self.connection()?
            .execute(
                "UPDATE sekai_export_receipts SET lease_until_ms = $3
                 WHERE operation_id = $1 AND closed = 0 AND closing_json IS NULL AND lease_until_ms >= $2",
                &[&operation_id, &now_ms, &lease_until_ms],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    pub fn claim_export_close(
        &self,
        operation_id: &str,
        closing_json: &str,
        expired: bool,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.connection()?
            .execute(
                "UPDATE sekai_export_receipts SET closing_json = $2
                 WHERE operation_id = $1 AND closed = 0 AND closing_json IS NULL
                   AND (($3 AND lease_until_ms < $4) OR (NOT $3 AND lease_until_ms >= $4))",
                &[&operation_id, &closing_json, &expired, &now_ms],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    pub fn open_export_row(
        &self,
        operation_id: &str,
    ) -> Result<Option<(Option<String>, String)>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT closing_json, receipt_json FROM sekai_export_receipts
                 WHERE operation_id = $1 AND closed = 0",
                &[&operation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| (row.get(0), row.get(1))))
    }

    pub fn finish_export_receipt(
        &self,
        operation_id: &str,
        receipt_json: &str,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "UPDATE sekai_export_receipts SET receipt_json = $2, closed = 1
                 WHERE operation_id = $1 AND closed = 0 AND closing_json IS NOT NULL",
                &[&operation_id, &receipt_json],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_export_receipt_json(&self, operation_id: &str) -> Result<Option<String>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT receipt_json FROM sekai_export_receipts WHERE operation_id = $1",
                &[&operation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0)))
    }

    pub fn recoverable_exports(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<(String, bool)>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT operation_id, closing_json IS NOT NULL FROM sekai_export_receipts
                 WHERE closed = 0 AND (closing_json IS NOT NULL OR lease_until_ms < $1)
                 ORDER BY lease_until_ms LIMIT $2",
                &[&now_ms, &(limit as i64)],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }
    pub fn dataset_version_rows_after(
        &self,
        dataset_id: &str,
        version_id: &str,
        after_row_id: i64,
        limit: usize,
    ) -> Result<Vec<VersionRow>, String> {
        self.connection()?
            .query(
                "SELECT row_id, data FROM sekai_dataset_version_rows
                 WHERE dataset_id = $1 AND version_id = $2 AND row_id > $3
                 ORDER BY row_id LIMIT $4",
                &[&dataset_id, &version_id, &after_row_id, &(limit as i64)],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| {
                let data: String = row.get(1);
                Ok((
                    row.get::<_, i64>(0),
                    serde_json::from_str(&data).map_err(|error| error.to_string())?,
                ))
            })
            .collect()
    }
}

/// Dispatches to the backend the plane runs on; PostgreSQL off the async
/// runtime.
macro_rules! dispatch {
    ($self:ident, $db:ident => $call:expr) => {
        match $self {
            Self::Sqlite($db) => $call,
            Self::Postgres($db) => crate::db::postgres::off_runtime(|| $call),
        }
    };
}

impl crate::db::runtime_db::RuntimeDb {
    pub fn latest_export_grant(
        &self,
        namespace: &str,
        principal: &str,
    ) -> Result<Option<(i64, ExportGrant)>, String> {
        dispatch!(self, db => db.latest_export_grant(namespace, principal))
    }

    /// The current grant of `principal` on `namespace`, if any.
    pub fn get_export_grant(
        &self,
        namespace: &str,
        principal: &str,
    ) -> Result<Option<ExportGrant>, String> {
        Ok(self
            .latest_export_grant(namespace, principal)?
            .map(|(_, grant)| grant))
    }

    pub fn insert_export_grant(&self, seq: i64, grant: &ExportGrant) -> Result<bool, String> {
        dispatch!(self, db => db.insert_export_grant(seq, grant))
    }

    /// Every entry of a grant's history, oldest first.
    pub fn export_grant_history(
        &self,
        namespace: &str,
        principal: &str,
    ) -> Result<Vec<(i64, ExportGrant)>, String> {
        dispatch!(self, db => db.export_grant_history(namespace, principal))
    }

    /// Creates an export's receipt row, open under the exporter's lease.
    pub fn open_export(
        &self,
        operation_id: &str,
        namespace: &str,
        lease_until_ms: i64,
        receipt_json: &str,
    ) -> Result<(), String> {
        dispatch!(self, db => db.open_export(operation_id, namespace, lease_until_ms, receipt_json))
    }

    pub fn renew_export(
        &self,
        operation_id: &str,
        now_ms: i64,
        lease_until_ms: i64,
    ) -> Result<bool, String> {
        dispatch!(self, db => db.renew_export(operation_id, now_ms, lease_until_ms))
    }

    /// Records the outcome of an open export, only while its lease is live
    /// (`expired` false) or has run out (`expired` true) and no outcome is
    /// recorded yet. True when this call decided it.
    pub fn claim_export_close(
        &self,
        operation_id: &str,
        closing_json: &str,
        expired: bool,
        now_ms: i64,
    ) -> Result<bool, String> {
        dispatch!(self, db => db.claim_export_close(operation_id, closing_json, expired, now_ms))
    }

    /// The decided outcome, if any, and the receipt of an export not yet
    /// finished.
    pub fn open_export_row(
        &self,
        operation_id: &str,
    ) -> Result<Option<(Option<String>, String)>, String> {
        dispatch!(self, db => db.open_export_row(operation_id))
    }

    /// Writes the finished receipt of an export whose outcome is decided;
    /// a no-op once finished.
    pub fn finish_export_receipt(
        &self,
        operation_id: &str,
        receipt_json: &str,
    ) -> Result<(), String> {
        dispatch!(self, db => db.finish_export_receipt(operation_id, receipt_json))
    }

    pub fn get_export_receipt_json(&self, operation_id: &str) -> Result<Option<String>, String> {
        dispatch!(self, db => db.get_export_receipt_json(operation_id))
    }

    pub fn recoverable_exports(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<(String, bool)>, String> {
        dispatch!(self, db => db.recoverable_exports(now_ms, limit))
    }
    /// Up to `limit` rows of a dataset version after `after_row_id`.
    pub fn dataset_version_rows_after(
        &self,
        dataset_id: &str,
        version_id: &str,
        after_row_id: i64,
        limit: usize,
    ) -> Result<Vec<VersionRow>, String> {
        dispatch!(self, db => db.dataset_version_rows_after(dataset_id, version_id, after_row_id, limit))
    }
}
