//! Saved export definitions and run artifacts (#1628) on both community
//! backends.
//!
//! A definition is stored once per id with its owner. An artifact is the
//! bytes of one export run, keyed by the run's receipt id: opened when the
//! run begins and filled chunk by chunk. Whether it is complete, and its
//! digest, are the receipt's: an artifact is whole exactly when its receipt
//! completed. Every artifact expires and is unreadable once expired; any
//! instance may sweep expired ones.

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;

/// How long an artifact is kept at most, delivered or not.
pub const ARTIFACT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Expired artifacts removed per sweep.
const SWEEP_BATCH: i64 = 64;

/// An artifact's stored bytes, before it expires or is acknowledged.
pub struct StoredArtifact {
    pub namespace: String,
    pub definition_id: String,
    pub bytes: Vec<u8>,
}

/// An unacked artifact still within its retention bound.
pub struct ArtifactMeta {
    pub receipt_id: String,
    pub namespace: String,
    pub definition_id: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

/// A saved export whose schedule bucket this tick claimed.
pub struct DueExportSchedule {
    pub namespace: String,
    pub definition_id: String,
    pub owner: String,
    pub record_json: String,
}

fn schedule_every_ms(record_json: &str) -> i64 {
    serde_json::from_str::<serde_json::Value>(record_json)
        .ok()
        .and_then(|value| value.get("everyMs")?.as_i64())
        .unwrap_or(0)
}

impl SekaiDb {
    pub fn put_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
        owner: &str,
        record_json: &str,
    ) -> Result<(String, String), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO sekai_export_definitions (namespace, definition_id, owner, record_json)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            rusqlite::params![namespace, definition_id, owner, record_json],
        )
        .map_err(|error| error.to_string())?;
        conn.query_row(
            "SELECT owner, record_json FROM sekai_export_definitions
             WHERE namespace = ?1 AND definition_id = ?2",
            rusqlite::params![namespace, definition_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())
    }

    pub fn get_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
    ) -> Result<Option<(String, String)>, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT owner, record_json FROM sekai_export_definitions
                 WHERE namespace = ?1 AND definition_id = ?2",
                rusqlite::params![namespace, definition_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn delete_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
        record_json: &str,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let deleted = transaction
            .execute(
                "DELETE FROM sekai_export_definitions
                 WHERE namespace = ?1 AND definition_id = ?2 AND record_json = ?3",
                rusqlite::params![namespace, definition_id, record_json],
            )
            .map_err(|error| error.to_string())?;
        if deleted == 1 {
            transaction
                .execute(
                    "DELETE FROM sekai_export_schedule_cursor
                     WHERE namespace = ?1 AND definition_id = ?2",
                    rusqlite::params![namespace, definition_id],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(deleted == 1)
    }

    pub fn open_export_artifact(
        &self,
        receipt_id: &str,
        namespace: &str,
        definition_id: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_export_artifacts
                     (receipt_id, namespace, definition_id, created_at_ms, expires_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    receipt_id,
                    namespace,
                    definition_id,
                    now_ms,
                    now_ms + ARTIFACT_RETENTION_MS
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn put_export_artifact_chunk(
        &self,
        receipt_id: &str,
        seq: i64,
        data: &[u8],
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "INSERT INTO sekai_export_artifact_chunks (receipt_id, seq, data)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![receipt_id, seq, data],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn sweep_export_artifacts(&self, now_ms: i64) -> Result<usize, String> {
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let expired: Vec<String> = {
            let mut statement = transaction
                .prepare(
                    "SELECT receipt_id FROM sekai_export_artifacts
                     WHERE expires_at_ms < ?1 LIMIT ?2",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map(rusqlite::params![now_ms, SWEEP_BATCH], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<_, _>>()
                .map_err(|error| error.to_string())?
        };
        for receipt_id in &expired {
            transaction
                .execute(
                    "DELETE FROM sekai_export_artifact_chunks WHERE receipt_id = ?1",
                    rusqlite::params![receipt_id],
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "DELETE FROM sekai_export_artifacts WHERE receipt_id = ?1",
                    rusqlite::params![receipt_id],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(expired.len())
    }

    pub fn get_export_artifact(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<Option<StoredArtifact>, String> {
        use rusqlite::OptionalExtension;
        let conn = self.conn();
        let Some((namespace, definition_id)) = conn
            .query_row(
                "SELECT namespace, definition_id FROM sekai_export_artifacts
                 WHERE receipt_id = ?1 AND expires_at_ms >= ?2 AND acked_at_ms IS NULL",
                rusqlite::params![receipt_id, now_ms],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let mut statement = conn
            .prepare(
                "SELECT data FROM sekai_export_artifact_chunks
                 WHERE receipt_id = ?1 ORDER BY seq",
            )
            .map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        for chunk in statement
            .query_map(rusqlite::params![receipt_id], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|error| error.to_string())?
        {
            bytes.extend(chunk.map_err(|error| error.to_string())?);
        }
        Ok(Some(StoredArtifact {
            namespace,
            definition_id,
            bytes,
        }))
    }

    pub fn list_unacked_export_artifacts(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<Vec<ArtifactMeta>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT receipt_id, namespace, definition_id, created_at_ms, expires_at_ms
                 FROM sekai_export_artifacts
                 WHERE namespace = ?1 AND acked_at_ms IS NULL AND expires_at_ms >= ?2
                 ORDER BY created_at_ms",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(rusqlite::params![namespace, now_ms], |row| {
                Ok(ArtifactMeta {
                    receipt_id: row.get(0)?,
                    namespace: row.get(1)?,
                    definition_id: row.get(2)?,
                    created_at_ms: row.get(3)?,
                    expires_at_ms: row.get(4)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }

    /// Records delivery: drops the bytes and keeps the ack so a retry is a
    /// no-op. True when this call or an earlier one acknowledged it.
    pub fn acknowledge_export_artifact(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        use rusqlite::OptionalExtension;
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let updated = transaction
            .execute(
                "UPDATE sekai_export_artifacts SET acked_at_ms = ?2
                 WHERE receipt_id = ?1 AND acked_at_ms IS NULL AND expires_at_ms >= ?2",
                rusqlite::params![receipt_id, now_ms],
            )
            .map_err(|error| error.to_string())?;
        if updated == 1 {
            transaction
                .execute(
                    "DELETE FROM sekai_export_artifact_chunks WHERE receipt_id = ?1",
                    rusqlite::params![receipt_id],
                )
                .map_err(|error| error.to_string())?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(true);
        }
        let already = transaction
            .query_row(
                "SELECT 1 FROM sekai_export_artifacts
                 WHERE receipt_id = ?1 AND acked_at_ms IS NOT NULL",
                rusqlite::params![receipt_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .is_some();
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(already)
    }

    /// Claims at most one due bucket. The cursor write is the admission
    /// (ADR 0103): a crash after this commit loses that interval and never
    /// double-runs it; remaining due definitions stay unclaimed.
    pub fn claim_due_export_schedules(
        &self,
        now_ms: i64,
    ) -> Result<Vec<DueExportSchedule>, String> {
        use rusqlite::OptionalExtension;
        use sekai_types::governed_transform::schedule_due_bucket;
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|error| error.to_string())?;
        let definitions: Vec<(String, String, String, String)> = {
            let mut statement = transaction
                .prepare(
                    "SELECT namespace, definition_id, owner, record_json
                     FROM sekai_export_definitions",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<_, _>>()
                .map_err(|error| error.to_string())?
        };
        let mut due = Vec::new();
        for (namespace, definition_id, owner, record_json) in definitions {
            let every_ms = schedule_every_ms(&record_json);
            let last = transaction
                .query_row(
                    "SELECT last_bucket FROM sekai_export_schedule_cursor
                     WHERE namespace = ?1 AND definition_id = ?2",
                    rusqlite::params![namespace, definition_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some(bucket) = schedule_due_bucket(last, every_ms, now_ms) else {
                continue;
            };
            let claimed = transaction
                .execute(
                    "INSERT INTO sekai_export_schedule_cursor
                         (namespace, definition_id, last_bucket)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (namespace, definition_id) DO UPDATE
                     SET last_bucket = excluded.last_bucket
                     WHERE sekai_export_schedule_cursor.last_bucket < excluded.last_bucket",
                    rusqlite::params![namespace, definition_id, bucket],
                )
                .map_err(|error| error.to_string())?;
            if claimed == 1 {
                due.push(DueExportSchedule {
                    namespace,
                    definition_id,
                    owner,
                    record_json,
                });
                break;
            }
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(due)
    }

    pub fn export_artifact_is_deliverable(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT 1 FROM sekai_export_artifacts
                 WHERE receipt_id = ?1 AND expires_at_ms >= ?2 AND acked_at_ms IS NULL",
                rusqlite::params![receipt_id, now_ms],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(|error| error.to_string())
    }

    pub fn export_artifact_chunks_after(
        &self,
        receipt_id: &str,
        after_seq: i64,
        limit: i64,
        now_ms: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT c.seq, c.data FROM sekai_export_artifact_chunks c
                 WHERE c.receipt_id = ?1 AND c.seq > ?2
                   AND EXISTS (
                     SELECT 1 FROM sekai_export_artifacts a
                     WHERE a.receipt_id = c.receipt_id
                       AND a.acked_at_ms IS NULL
                       AND a.expires_at_ms >= ?3
                   )
                 ORDER BY c.seq LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![receipt_id, after_seq, now_ms, limit],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        rows.map(|row| row.map_err(|error| error.to_string()))
            .collect()
    }
}

impl PostgresDb {
    pub fn put_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
        owner: &str,
        record_json: &str,
    ) -> Result<(String, String), String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO sekai_export_definitions (namespace, definition_id, owner, record_json)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                &[&namespace, &definition_id, &owner, &record_json],
            )
            .map_err(|error| error.to_string())?;
        let row = connection
            .query_one(
                "SELECT owner, record_json FROM sekai_export_definitions
                 WHERE namespace = $1 AND definition_id = $2",
                &[&namespace, &definition_id],
            )
            .map_err(|error| error.to_string())?;
        Ok((row.get(0), row.get(1)))
    }

    pub fn get_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
    ) -> Result<Option<(String, String)>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT owner, record_json FROM sekai_export_definitions
                 WHERE namespace = $1 AND definition_id = $2",
                &[&namespace, &definition_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| (row.get(0), row.get(1))))
    }

    pub fn delete_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
        record_json: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let deleted = transaction
            .execute(
                "DELETE FROM sekai_export_definitions
                 WHERE namespace = $1 AND definition_id = $2 AND record_json = $3",
                &[&namespace, &definition_id, &record_json],
            )
            .map_err(|error| error.to_string())?;
        if deleted == 1 {
            transaction
                .execute(
                    "DELETE FROM sekai_export_schedule_cursor
                     WHERE namespace = $1 AND definition_id = $2",
                    &[&namespace, &definition_id],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(deleted == 1)
    }

    pub fn open_export_artifact(
        &self,
        receipt_id: &str,
        namespace: &str,
        definition_id: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_export_artifacts
                     (receipt_id, namespace, definition_id, created_at_ms, expires_at_ms)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &receipt_id,
                    &namespace,
                    &definition_id,
                    &now_ms,
                    &(now_ms + ARTIFACT_RETENTION_MS),
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn put_export_artifact_chunk(
        &self,
        receipt_id: &str,
        seq: i64,
        data: &[u8],
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_export_artifact_chunks (receipt_id, seq, data)
                 VALUES ($1, $2, $3)",
                &[&receipt_id, &seq, &data],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn sweep_export_artifacts(&self, now_ms: i64) -> Result<usize, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let expired: Vec<String> = transaction
            .query(
                "SELECT receipt_id FROM sekai_export_artifacts
                 WHERE expires_at_ms < $1 LIMIT $2 FOR UPDATE SKIP LOCKED",
                &[&now_ms, &SWEEP_BATCH],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| row.get(0))
            .collect();
        for receipt_id in &expired {
            transaction
                .execute(
                    "DELETE FROM sekai_export_artifact_chunks WHERE receipt_id = $1",
                    &[receipt_id],
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "DELETE FROM sekai_export_artifacts WHERE receipt_id = $1",
                    &[receipt_id],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(expired.len())
    }

    pub fn get_export_artifact(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<Option<StoredArtifact>, String> {
        let mut connection = self.connection()?;
        let Some(row) = connection
            .query_opt(
                "SELECT namespace, definition_id FROM sekai_export_artifacts
                 WHERE receipt_id = $1 AND expires_at_ms >= $2 AND acked_at_ms IS NULL",
                &[&receipt_id, &now_ms],
            )
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        for chunk in connection
            .query(
                "SELECT data FROM sekai_export_artifact_chunks
                 WHERE receipt_id = $1 ORDER BY seq",
                &[&receipt_id],
            )
            .map_err(|error| error.to_string())?
        {
            bytes.extend(chunk.get::<_, Vec<u8>>(0));
        }
        Ok(Some(StoredArtifact {
            namespace: row.get(0),
            definition_id: row.get(1),
            bytes,
        }))
    }

    pub fn list_unacked_export_artifacts(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<Vec<ArtifactMeta>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT receipt_id, namespace, definition_id, created_at_ms, expires_at_ms
                 FROM sekai_export_artifacts
                 WHERE namespace = $1 AND acked_at_ms IS NULL AND expires_at_ms >= $2
                 ORDER BY created_at_ms",
                &[&namespace, &now_ms],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| ArtifactMeta {
                receipt_id: row.get(0),
                namespace: row.get(1),
                definition_id: row.get(2),
                created_at_ms: row.get(3),
                expires_at_ms: row.get(4),
            })
            .collect())
    }

    pub fn acknowledge_export_artifact(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let updated = transaction
            .execute(
                "UPDATE sekai_export_artifacts SET acked_at_ms = $2
                 WHERE receipt_id = $1 AND acked_at_ms IS NULL AND expires_at_ms >= $2",
                &[&receipt_id, &now_ms],
            )
            .map_err(|error| error.to_string())?;
        if updated == 1 {
            transaction
                .execute(
                    "DELETE FROM sekai_export_artifact_chunks WHERE receipt_id = $1",
                    &[&receipt_id],
                )
                .map_err(|error| error.to_string())?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(true);
        }
        let already = transaction
            .query_opt(
                "SELECT 1 FROM sekai_export_artifacts
                 WHERE receipt_id = $1 AND acked_at_ms IS NOT NULL",
                &[&receipt_id],
            )
            .map_err(|error| error.to_string())?
            .is_some();
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(already)
    }

    pub fn claim_due_export_schedules(
        &self,
        now_ms: i64,
    ) -> Result<Vec<DueExportSchedule>, String> {
        use sekai_types::governed_transform::schedule_due_bucket;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let definitions: Vec<(String, String, String, String)> = transaction
            .query(
                "SELECT namespace, definition_id, owner, record_json
                 FROM sekai_export_definitions",
                &[],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
            .collect();
        let mut due = Vec::new();
        for (namespace, definition_id, owner, record_json) in definitions {
            let every_ms = schedule_every_ms(&record_json);
            let last = transaction
                .query_opt(
                    "SELECT last_bucket FROM sekai_export_schedule_cursor
                     WHERE namespace = $1 AND definition_id = $2
                     FOR UPDATE",
                    &[&namespace, &definition_id],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, i64>(0));
            let Some(bucket) = schedule_due_bucket(last, every_ms, now_ms) else {
                continue;
            };
            let claimed = transaction
                .execute(
                    "INSERT INTO sekai_export_schedule_cursor
                         (namespace, definition_id, last_bucket)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (namespace, definition_id) DO UPDATE
                     SET last_bucket = EXCLUDED.last_bucket
                     WHERE sekai_export_schedule_cursor.last_bucket < EXCLUDED.last_bucket",
                    &[&namespace, &definition_id, &bucket],
                )
                .map_err(|error| error.to_string())?;
            if claimed == 1 {
                due.push(DueExportSchedule {
                    namespace,
                    definition_id,
                    owner,
                    record_json,
                });
                break;
            }
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(due)
    }

    pub fn export_artifact_is_deliverable(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT 1 FROM sekai_export_artifacts
                 WHERE receipt_id = $1 AND expires_at_ms >= $2 AND acked_at_ms IS NULL",
                &[&receipt_id, &now_ms],
            )
            .map_err(|error| error.to_string())?
            .is_some())
    }

    pub fn export_artifact_chunks_after(
        &self,
        receipt_id: &str,
        after_seq: i64,
        limit: i64,
        now_ms: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT c.seq, c.data FROM sekai_export_artifact_chunks c
                 WHERE c.receipt_id = $1 AND c.seq > $2
                   AND EXISTS (
                     SELECT 1 FROM sekai_export_artifacts a
                     WHERE a.receipt_id = c.receipt_id
                       AND a.acked_at_ms IS NULL
                       AND a.expires_at_ms >= $3
                   )
                 ORDER BY c.seq LIMIT $4",
                &[&receipt_id, &after_seq, &now_ms, &limit],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
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

impl RuntimeDb {
    /// Stores a definition once per id; returns the stored owner and record.
    pub fn put_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
        owner: &str,
        record_json: &str,
    ) -> Result<(String, String), String> {
        dispatch!(self, db => db.put_export_definition(namespace, definition_id, owner, record_json))
    }

    pub fn get_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
    ) -> Result<Option<(String, String)>, String> {
        dispatch!(self, db => db.get_export_definition(namespace, definition_id))
    }

    /// Deletes a definition only while it is still `record_json`, the one
    /// its caller was authorized against.
    pub fn delete_export_definition(
        &self,
        namespace: &str,
        definition_id: &str,
        record_json: &str,
    ) -> Result<bool, String> {
        dispatch!(self, db => db.delete_export_definition(namespace, definition_id, record_json))
    }

    pub fn open_export_artifact(
        &self,
        receipt_id: &str,
        namespace: &str,
        definition_id: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        dispatch!(self, db => db.open_export_artifact(receipt_id, namespace, definition_id, now_ms))
    }

    pub fn put_export_artifact_chunk(
        &self,
        receipt_id: &str,
        seq: i64,
        data: &[u8],
    ) -> Result<(), String> {
        dispatch!(self, db => db.put_export_artifact_chunk(receipt_id, seq, data))
    }

    /// Removes up to a batch of expired artifacts; returns how many.
    pub fn sweep_export_artifacts(&self, now_ms: i64) -> Result<usize, String> {
        dispatch!(self, db => db.sweep_export_artifacts(now_ms))
    }

    /// An artifact's bytes, unless it expired or was acknowledged.
    pub fn get_export_artifact(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<Option<StoredArtifact>, String> {
        dispatch!(self, db => db.get_export_artifact(receipt_id, now_ms))
    }

    pub fn list_unacked_export_artifacts(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<Vec<ArtifactMeta>, String> {
        dispatch!(self, db => db.list_unacked_export_artifacts(namespace, now_ms))
    }

    pub fn acknowledge_export_artifact(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        dispatch!(self, db => db.acknowledge_export_artifact(receipt_id, now_ms))
    }

    pub fn claim_due_export_schedules(
        &self,
        now_ms: i64,
    ) -> Result<Vec<DueExportSchedule>, String> {
        dispatch!(self, db => db.claim_due_export_schedules(now_ms))
    }

    pub fn export_artifact_is_deliverable(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        dispatch!(self, db => db.export_artifact_is_deliverable(receipt_id, now_ms))
    }

    pub fn export_artifact_chunks_after(
        &self,
        receipt_id: &str,
        after_seq: i64,
        limit: i64,
        now_ms: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, String> {
        dispatch!(self, db => db.export_artifact_chunks_after(receipt_id, after_seq, limit, now_ms))
    }
}
