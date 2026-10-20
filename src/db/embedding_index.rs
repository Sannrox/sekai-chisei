//! SQLite storage for the embedding index, and the backend dispatch.

use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::embedding_index::{
    EMBEDDING_REVISION_CONFLICT, EmbeddingCheckpoint, EmbeddingChunk, EmbeddingRebuild,
    EmbeddingSource, EmbeddingStore, ObjectEmbeddings, vector_bytes, vector_from_bytes,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sekai_embedding_chunks (
    namespace TEXT NOT NULL,
    spec_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    chunk_digest TEXT NOT NULL,
    vector BLOB NOT NULL,
    source_digest TEXT NOT NULL,
    model TEXT NOT NULL,
    model_version TEXT NOT NULL,
    marking TEXT,
    classifications TEXT NOT NULL,
    embedded_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, spec_id, object_id, chunk_index)
);
CREATE TABLE IF NOT EXISTS sekai_embedding_checkpoints (
    namespace TEXT NOT NULL,
    spec_id TEXT NOT NULL,
    spec_digest TEXT NOT NULL,
    last_change_rowid INTEGER NOT NULL,
    last_generation INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, spec_id)
);
CREATE TABLE IF NOT EXISTS sekai_embedding_rebuilds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    spec_id TEXT NOT NULL,
    from_digest TEXT NOT NULL,
    to_digest TEXT NOT NULL,
    objects INTEGER NOT NULL,
    rebuilt_at_ms INTEGER NOT NULL
);
";

/// Classifications are stored one `property=classification` per line.
pub(crate) fn join_classifications(classifications: &[String]) -> String {
    classifications.join("\n")
}

pub(crate) fn split_classifications(stored: &str) -> Vec<String> {
    stored
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

impl SekaiDb {
    pub(crate) fn migrate_embedding_index(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(SCHEMA)
            .map_err(|error| error.to_string())
    }

    /// Run `write` in an immediate transaction after a compare-and-bump of the
    /// spec revision. Returns the new revision.
    fn fenced_embedding_write(
        &self,
        namespace: &str,
        spec_id: &str,
        revision: i64,
        now_ms: i64,
        write: impl FnOnce(&Transaction<'_>) -> rusqlite::Result<()>,
    ) -> Result<i64, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let bumped = tx
            .execute(
                "UPDATE sekai_embedding_checkpoints
                 SET revision = revision + 1, updated_at_ms = ?4
                 WHERE namespace = ?1 AND spec_id = ?2 AND revision = ?3",
                params![namespace, spec_id, revision, now_ms],
            )
            .map_err(|error| error.to_string())?;
        let created = bumped == 0
            && revision == 0
            && tx
                .execute(
                    "INSERT INTO sekai_embedding_checkpoints
                     (namespace, spec_id, spec_digest, last_change_rowid, last_generation,
                      revision, updated_at_ms)
                     VALUES (?1, ?2, '', 0, 0, 1, ?3)
                     ON CONFLICT(namespace, spec_id) DO NOTHING",
                    params![namespace, spec_id, now_ms],
                )
                .map_err(|error| error.to_string())?
                == 1;
        if bumped != 1 && !created {
            return Err(EMBEDDING_REVISION_CONFLICT.into());
        }
        write(&tx).map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(revision + 1)
    }
}

impl EmbeddingStore for SekaiDb {
    fn embedding_checkpoint(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Option<EmbeddingCheckpoint>, String> {
        self.conn()
            .query_row(
                "SELECT spec_digest, last_change_rowid, last_generation, revision
                 FROM sekai_embedding_checkpoints WHERE namespace = ?1 AND spec_id = ?2",
                params![namespace, spec_id],
                |row| {
                    Ok(EmbeddingCheckpoint {
                        spec_digest: row.get(0)?,
                        last_change_rowid: row.get::<_, i64>(1)?.max(0) as u64,
                        last_generation: row.get::<_, i64>(2)?.max(0) as u64,
                        revision: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn store_embedding_checkpoint(
        &self,
        namespace: &str,
        spec_id: &str,
        checkpoint: &EmbeddingCheckpoint,
        now_ms: i64,
    ) -> Result<i64, String> {
        self.fenced_embedding_write(namespace, spec_id, checkpoint.revision, now_ms, |tx| {
            tx.execute(
                "UPDATE sekai_embedding_checkpoints
                 SET spec_digest = ?3, last_change_rowid = ?4, last_generation = ?5
                 WHERE namespace = ?1 AND spec_id = ?2",
                params![
                    namespace,
                    spec_id,
                    checkpoint.spec_digest,
                    checkpoint.last_change_rowid as i64,
                    checkpoint.last_generation as i64
                ],
            )
            .map(|_| ())
        })
    }

    fn embedding_chunk_digests(
        &self,
        namespace: &str,
        spec_id: &str,
        object_id: &str,
    ) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT chunk_digest FROM sekai_embedding_chunks
                 WHERE namespace = ?1 AND spec_id = ?2 AND object_id = ?3
                 ORDER BY chunk_index",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![namespace, spec_id, object_id], |row| row.get(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|error| error.to_string())
    }

    fn write_embedding_object(
        &self,
        namespace: &str,
        spec_id: &str,
        write: &ObjectEmbeddings<'_>,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        let ObjectEmbeddings {
            object_id,
            source,
            chunks,
            keep,
        } = *write;
        let classifications = join_classifications(&source.classifications);
        self.fenced_embedding_write(namespace, spec_id, revision, now_ms, |tx| {
            for (index, digest, vector) in chunks {
                tx.execute(
                    "INSERT INTO sekai_embedding_chunks
                     (namespace, spec_id, object_id, chunk_index, chunk_digest, vector,
                      source_digest, model, model_version, marking, classifications,
                      embedded_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(namespace, spec_id, object_id, chunk_index) DO UPDATE SET
                        chunk_digest = excluded.chunk_digest,
                        vector = excluded.vector,
                        embedded_at_ms = excluded.embedded_at_ms",
                    params![
                        namespace,
                        spec_id,
                        object_id,
                        *index as i64,
                        digest,
                        vector_bytes(vector),
                        source.source_digest,
                        source.model,
                        source.model_version,
                        source.marking,
                        classifications,
                        now_ms
                    ],
                )?;
            }
            tx.execute(
                "DELETE FROM sekai_embedding_chunks
                 WHERE namespace = ?1 AND spec_id = ?2 AND object_id = ?3 AND chunk_index >= ?4",
                params![namespace, spec_id, object_id, keep as i64],
            )?;
            tx.execute(
                "UPDATE sekai_embedding_chunks
                 SET source_digest = ?4, model = ?5, model_version = ?6, marking = ?7,
                     classifications = ?8
                 WHERE namespace = ?1 AND spec_id = ?2 AND object_id = ?3",
                params![
                    namespace,
                    spec_id,
                    object_id,
                    source.source_digest,
                    source.model,
                    source.model_version,
                    source.marking,
                    classifications
                ],
            )
            .map(|_| ())
        })
    }

    fn delete_embedding_object(
        &self,
        namespace: &str,
        spec_id: &str,
        object_id: &str,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        self.fenced_embedding_write(namespace, spec_id, revision, now_ms, |tx| {
            tx.execute(
                "DELETE FROM sekai_embedding_chunks
                 WHERE namespace = ?1 AND spec_id = ?2 AND object_id = ?3",
                params![namespace, spec_id, object_id],
            )
            .map(|_| ())
        })
    }

    fn reset_embedding_spec(
        &self,
        namespace: &str,
        spec_id: &str,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        self.fenced_embedding_write(namespace, spec_id, revision, now_ms, |tx| {
            tx.execute(
                "UPDATE sekai_embedding_checkpoints SET spec_digest = ''
                 WHERE namespace = ?1 AND spec_id = ?2",
                params![namespace, spec_id],
            )?;
            tx.execute(
                "DELETE FROM sekai_embedding_chunks WHERE namespace = ?1 AND spec_id = ?2",
                params![namespace, spec_id],
            )
            .map(|_| ())
        })
    }

    fn complete_embedding_rebuild(
        &self,
        namespace: &str,
        spec_id: &str,
        rebuild: &EmbeddingRebuild,
        checkpoint: &EmbeddingCheckpoint,
        now_ms: i64,
    ) -> Result<i64, String> {
        self.fenced_embedding_write(namespace, spec_id, checkpoint.revision, now_ms, |tx| {
            tx.execute(
                "INSERT INTO sekai_embedding_rebuilds
                 (namespace, spec_id, from_digest, to_digest, objects, rebuilt_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    namespace,
                    spec_id,
                    rebuild.from_digest,
                    rebuild.to_digest,
                    rebuild.objects,
                    rebuild.rebuilt_at_ms
                ],
            )?;
            tx.execute(
                "UPDATE sekai_embedding_checkpoints
                 SET spec_digest = ?3, last_change_rowid = ?4, last_generation = ?5
                 WHERE namespace = ?1 AND spec_id = ?2",
                params![
                    namespace,
                    spec_id,
                    checkpoint.spec_digest,
                    checkpoint.last_change_rowid as i64,
                    checkpoint.last_generation as i64
                ],
            )
            .map(|_| ())
        })
    }

    fn embedding_source_ids(
        &self,
        namespace: &str,
        kind: &str,
        after_id: &str,
        limit: i64,
    ) -> Result<Vec<String>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id FROM sekai_objects
                 WHERE namespace = ?1 AND kind = ?2 AND id > ?3
                 ORDER BY id LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![namespace, kind, after_id, limit], |row| row.get(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|error| error.to_string())
    }

    fn embedding_chunks(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<EmbeddingChunk>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT object_id, chunk_index, chunk_digest, vector, source_digest, model,
                        model_version, marking, classifications, embedded_at_ms
                 FROM sekai_embedding_chunks WHERE namespace = ?1 AND spec_id = ?2
                 ORDER BY object_id, chunk_index",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![namespace, spec_id], |row| {
            Ok(EmbeddingChunk {
                object_id: row.get(0)?,
                chunk_index: row.get::<_, i64>(1)? as u32,
                chunk_digest: row.get(2)?,
                vector: vector_from_bytes(&row.get::<_, Vec<u8>>(3)?),
                source: EmbeddingSource {
                    source_digest: row.get(4)?,
                    model: row.get(5)?,
                    model_version: row.get(6)?,
                    marking: row.get(7)?,
                    classifications: split_classifications(&row.get::<_, String>(8)?),
                },
                embedded_at_ms: row.get(9)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
    }

    fn embedding_rebuilds(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<EmbeddingRebuild>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT from_digest, to_digest, objects, rebuilt_at_ms
                 FROM sekai_embedding_rebuilds WHERE namespace = ?1 AND spec_id = ?2
                 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![namespace, spec_id], |row| {
            Ok(EmbeddingRebuild {
                from_digest: row.get(0)?,
                to_digest: row.get(1)?,
                objects: row.get(2)?,
                rebuilt_at_ms: row.get(3)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
    }
}

/// Run `$call` on whichever backend holds the runtime.
macro_rules! dispatch {
    ($db:expr, $store:ident => $call:expr) => {
        match $db {
            RuntimeDb::Sqlite($store) => $call,
            RuntimeDb::Postgres($store) => crate::db::postgres::off_runtime(|| $call),
        }
    };
}

impl EmbeddingStore for RuntimeDb {
    fn embedding_checkpoint(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Option<EmbeddingCheckpoint>, String> {
        dispatch!(self, db => db.embedding_checkpoint(namespace, spec_id))
    }

    fn store_embedding_checkpoint(
        &self,
        namespace: &str,
        spec_id: &str,
        checkpoint: &EmbeddingCheckpoint,
        now_ms: i64,
    ) -> Result<i64, String> {
        dispatch!(self, db => db.store_embedding_checkpoint(namespace, spec_id, checkpoint, now_ms))
    }

    fn embedding_chunk_digests(
        &self,
        namespace: &str,
        spec_id: &str,
        object_id: &str,
    ) -> Result<Vec<String>, String> {
        dispatch!(self, db => db.embedding_chunk_digests(namespace, spec_id, object_id))
    }

    fn write_embedding_object(
        &self,
        namespace: &str,
        spec_id: &str,
        write: &ObjectEmbeddings<'_>,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        dispatch!(self, db => db.write_embedding_object(namespace, spec_id, write, revision, now_ms))
    }

    fn delete_embedding_object(
        &self,
        namespace: &str,
        spec_id: &str,
        object_id: &str,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        dispatch!(self, db => db.delete_embedding_object(namespace, spec_id, object_id, revision, now_ms))
    }

    fn reset_embedding_spec(
        &self,
        namespace: &str,
        spec_id: &str,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        dispatch!(self, db => db.reset_embedding_spec(namespace, spec_id, revision, now_ms))
    }

    fn complete_embedding_rebuild(
        &self,
        namespace: &str,
        spec_id: &str,
        rebuild: &EmbeddingRebuild,
        checkpoint: &EmbeddingCheckpoint,
        now_ms: i64,
    ) -> Result<i64, String> {
        dispatch!(self, db => db.complete_embedding_rebuild(
            namespace, spec_id, rebuild, checkpoint, now_ms
        ))
    }

    fn embedding_source_ids(
        &self,
        namespace: &str,
        kind: &str,
        after_id: &str,
        limit: i64,
    ) -> Result<Vec<String>, String> {
        dispatch!(self, db => db.embedding_source_ids(namespace, kind, after_id, limit))
    }

    fn embedding_chunks(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<EmbeddingChunk>, String> {
        dispatch!(self, db => db.embedding_chunks(namespace, spec_id))
    }

    fn embedding_rebuilds(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<EmbeddingRebuild>, String> {
        dispatch!(self, db => db.embedding_rebuilds(namespace, spec_id))
    }
}
