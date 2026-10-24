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

/// An artifact's stored bytes, before it expires.
pub struct StoredArtifact {
    pub namespace: String,
    pub definition_id: String,
    pub bytes: Vec<u8>,
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
        self.conn()
            .execute(
                "DELETE FROM sekai_export_definitions
                 WHERE namespace = ?1 AND definition_id = ?2 AND record_json = ?3",
                rusqlite::params![namespace, definition_id, record_json],
            )
            .map(|deleted| deleted == 1)
            .map_err(|error| error.to_string())
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
                 WHERE receipt_id = ?1 AND expires_at_ms >= ?2",
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
        self.connection()?
            .execute(
                "DELETE FROM sekai_export_definitions
                 WHERE namespace = $1 AND definition_id = $2 AND record_json = $3",
                &[&namespace, &definition_id, &record_json],
            )
            .map(|deleted| deleted == 1)
            .map_err(|error| error.to_string())
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
                 WHERE receipt_id = $1 AND expires_at_ms >= $2",
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

    /// An artifact's bytes, unless it expired.
    pub fn get_export_artifact(
        &self,
        receipt_id: &str,
        now_ms: i64,
    ) -> Result<Option<StoredArtifact>, String> {
        dispatch!(self, db => db.get_export_artifact(receipt_id, now_ms))
    }
}
