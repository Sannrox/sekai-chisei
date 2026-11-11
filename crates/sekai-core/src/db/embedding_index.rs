//! SQLite storage for the embedding index, and the backend dispatch.

use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::embedding_index::{
    EMBEDDING_REVISION_CONFLICT, EMBEDDING_SPEC_LIMIT, EmbeddingCheckpoint, EmbeddingChunk,
    EmbeddingRebuild, EmbeddingSource, EmbeddingSpec, EmbeddingStore, MAX_SPECS_PER_NAMESPACE,
    ObjectEmbeddings, RebuildCursor, StoredEmbeddingSpec, vector_bytes, vector_from_bytes,
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
CREATE TABLE IF NOT EXISTS sekai_embedding_specs (
    namespace TEXT NOT NULL,
    spec_id TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    properties TEXT NOT NULL,
    chunk_chars INTEGER NOT NULL,
    dimension INTEGER NOT NULL,
    batch_size INTEGER NOT NULL,
    model TEXT NOT NULL,
    updated_by TEXT NOT NULL,
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

/// Rebuild cursor columns (#2244), added to checkpoints created before them.
/// `rebuild_revision` is the revision the cursor is valid at: this plane's
/// fenced writes carry it forward with the revision, so any write that does
/// not (an older plane's, a put, a delete) leaves it behind and voids the
/// cursor. -1 means no cursor.
const REBUILD_CURSOR_COLUMNS: [&str; 7] = [
    "rebuild_from TEXT NOT NULL DEFAULT ''",
    "rebuild_to TEXT NOT NULL DEFAULT ''",
    "rebuild_after TEXT NOT NULL DEFAULT ''",
    "rebuild_watermark INTEGER NOT NULL DEFAULT 0",
    "rebuild_generation INTEGER NOT NULL DEFAULT 0",
    "rebuild_objects INTEGER NOT NULL DEFAULT 0",
    "rebuild_revision INTEGER NOT NULL DEFAULT -1",
];

/// Checkpoint columns as [`checkpoint_from_row`] reads them.
pub const CHECKPOINT_COLUMNS: &str = "spec_digest, last_change_rowid, last_generation, revision,
     updated_at_ms, rebuild_from, rebuild_to, rebuild_after, rebuild_watermark,
     rebuild_generation, rebuild_objects, rebuild_revision";

/// A checkpoint from its [`CHECKPOINT_COLUMNS`] values, with the cursor only
/// while it is valid at the current revision.
#[allow(clippy::too_many_arguments)]
pub fn checkpoint_from_row(
    spec_digest: String,
    last_change_rowid: i64,
    last_generation: i64,
    revision: i64,
    updated_at_ms: i64,
    cursor: RebuildCursor,
    cursor_revision: i64,
) -> EmbeddingCheckpoint {
    let valid = !cursor.to_digest.is_empty() && cursor_revision == revision;
    EmbeddingCheckpoint {
        spec_digest,
        last_change_rowid: last_change_rowid.max(0) as u64,
        last_generation: last_generation.max(0) as u64,
        revision,
        updated_at_ms,
        rebuild: valid.then_some(cursor),
    }
}

/// Put moves the spec's checkpoint revision on (creating the row), so a
/// catch-up that listed the spec earlier is fenced out; see
/// [`StoredEmbeddingSpec::revision`]. It also ends any rebuild lease.
const BUMP_SPEC_CHECKPOINT_SQLITE: &str = "INSERT INTO sekai_embedding_checkpoints
     (namespace, spec_id, spec_digest, last_change_rowid, last_generation, revision,
      updated_at_ms)
     VALUES (?1, ?2, '', 0, 0, 1, 0)
     ON CONFLICT(namespace, spec_id) DO UPDATE SET revision = revision + 1, updated_at_ms = 0";

/// Source properties are stored as a JSON array.
pub fn join_properties(properties: &[String]) -> String {
    serde_json::to_string(properties).unwrap_or_else(|_| "[]".into())
}

pub fn split_properties(stored: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(stored).map_err(|error| error.to_string())
}

/// A spec row: namespace, id, kind, properties, chunk_chars, dimension,
/// batch_size, model, updated_by, updated_at_ms, checkpoint revision.
#[allow(clippy::too_many_arguments)]
pub fn stored_spec(
    namespace: String,
    id: String,
    object_kind: String,
    properties: &str,
    chunk_chars: i64,
    dimension: i64,
    batch_size: i64,
    model: String,
    updated_by: String,
    updated_at_ms: i64,
    revision: i64,
) -> Result<StoredEmbeddingSpec, String> {
    Ok(StoredEmbeddingSpec {
        spec: EmbeddingSpec {
            id,
            namespace,
            object_kind,
            properties: split_properties(properties)?,
            chunk_chars: chunk_chars.max(0) as usize,
            dimension: dimension.max(0) as usize,
            batch_size: batch_size.max(0) as usize,
        },
        model,
        updated_by,
        updated_at_ms,
        revision,
    })
}

/// Classifications are stored one `property=classification` per line.
pub fn join_classifications(classifications: &[String]) -> String {
    classifications.join("\n")
}

pub fn split_classifications(stored: &str) -> Vec<String> {
    stored
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

impl SekaiDb {
    pub fn migrate_embedding_index(&self) -> Result<(), String> {
        let mut conn = self.conn();
        // One immediate transaction, so two planes upgrading one file
        // cannot both see a column missing and both add it.
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        tx.execute_batch(SCHEMA)
            .map_err(|error| error.to_string())?;
        for column in REBUILD_CURSOR_COLUMNS {
            let name = column.split(' ').next().unwrap_or_default();
            let present = tx
                .prepare(
                    "SELECT 1 FROM pragma_table_info('sekai_embedding_checkpoints') WHERE name = ?1",
                )
                .and_then(|mut stmt| stmt.exists(params![name]))
                .map_err(|error| error.to_string())?;
            if !present {
                tx.execute(
                    &format!("ALTER TABLE sekai_embedding_checkpoints ADD COLUMN {column}"),
                    [],
                )
                .map_err(|error| error.to_string())?;
            }
        }
        tx.commit().map_err(|error| error.to_string())
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
                 SET revision = revision + 1, updated_at_ms = ?4,
                     rebuild_revision = CASE WHEN rebuild_revision = revision
                                        THEN revision + 1 ELSE rebuild_revision END
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

/// Save `cursor` valid at `revision`, the one the enclosing fenced write
/// moves the checkpoint to.
fn save_cursor(
    tx: &Transaction<'_>,
    namespace: &str,
    spec_id: &str,
    cursor: &RebuildCursor,
    revision: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE sekai_embedding_checkpoints
         SET rebuild_from = ?3, rebuild_to = ?4, rebuild_after = ?5, rebuild_watermark = ?6,
             rebuild_generation = ?7, rebuild_objects = ?8, rebuild_revision = ?9
         WHERE namespace = ?1 AND spec_id = ?2",
        params![
            namespace,
            spec_id,
            cursor.from_digest,
            cursor.to_digest,
            cursor.after_id,
            cursor.watermark as i64,
            cursor.generation as i64,
            cursor.objects,
            revision
        ],
    )
    .map(|_| ())
}

impl SekaiDb {
    /// At most `page` of a spec's chunks past `(after_id, after_chunk)`,
    /// ordered by object id then chunk index (#2252).
    pub(crate) fn embedding_chunk_page(
        &self,
        namespace: &str,
        spec_id: &str,
        after_id: &str,
        after_chunk: i64,
        page: i64,
    ) -> Result<Vec<EmbeddingChunk>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT object_id, chunk_index, chunk_digest, vector, source_digest, model,
                        model_version, marking, classifications, embedded_at_ms
                 FROM sekai_embedding_chunks
                 WHERE namespace = ?1 AND spec_id = ?2 AND (object_id, chunk_index) > (?3, ?4)
                 ORDER BY object_id, chunk_index
                 LIMIT ?5",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(
            params![namespace, spec_id, after_id, after_chunk, page],
            |row| {
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
            },
        )
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
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
                &format!(
                    "SELECT {CHECKPOINT_COLUMNS} FROM sekai_embedding_checkpoints
                     WHERE namespace = ?1 AND spec_id = ?2"
                ),
                params![namespace, spec_id],
                |row| {
                    Ok(checkpoint_from_row(
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        RebuildCursor {
                            from_digest: row.get(5)?,
                            to_digest: row.get(6)?,
                            after_id: row.get(7)?,
                            watermark: row.get::<_, i64>(8)?.max(0) as u64,
                            generation: row.get::<_, i64>(9)?.max(0) as u64,
                            objects: row.get(10)?,
                        },
                        row.get(11)?,
                    ))
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
        cursor: &RebuildCursor,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        self.fenced_embedding_write(namespace, spec_id, revision, now_ms, |tx| {
            tx.execute(
                "UPDATE sekai_embedding_checkpoints SET spec_digest = ''
                 WHERE namespace = ?1 AND spec_id = ?2",
                params![namespace, spec_id],
            )?;
            save_cursor(tx, namespace, spec_id, cursor, revision + 1)?;
            tx.execute(
                "DELETE FROM sekai_embedding_chunks WHERE namespace = ?1 AND spec_id = ?2",
                params![namespace, spec_id],
            )
            .map(|_| ())
        })
    }

    fn store_embedding_rebuild_cursor(
        &self,
        namespace: &str,
        spec_id: &str,
        cursor: &RebuildCursor,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        self.fenced_embedding_write(namespace, spec_id, revision, now_ms, |tx| {
            save_cursor(tx, namespace, spec_id, cursor, revision + 1)
        })
    }

    fn resume_embedding_rebuild(
        &self,
        namespace: &str,
        spec_id: &str,
        kind: &str,
        cursor: &RebuildCursor,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        self.fenced_embedding_write(namespace, spec_id, revision, now_ms, |tx| {
            tx.execute(
                "DELETE FROM sekai_embedding_chunks
                 WHERE namespace = ?1 AND spec_id = ?2
                   AND NOT EXISTS (SELECT 1 FROM sekai_objects o
                                   WHERE o.id = sekai_embedding_chunks.object_id
                                     AND o.namespace = ?1 AND o.kind = ?3)",
                params![namespace, spec_id, kind],
            )?;
            save_cursor(tx, namespace, spec_id, cursor, revision + 1)
        })
    }

    fn embedding_vector_count(&self, namespace: &str, spec_id: &str) -> Result<i64, String> {
        self.conn()
            .query_row(
                "SELECT count(*) FROM sekai_embedding_chunks WHERE namespace = ?1 AND spec_id = ?2",
                params![namespace, spec_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
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
                 SET spec_digest = ?3, last_change_rowid = ?4, last_generation = ?5,
                     rebuild_to = '', rebuild_revision = -1
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
        self.embedding_chunk_page(namespace, spec_id, "", -1, i64::MAX)
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

    fn put_embedding_spec(&self, stored: &StoredEmbeddingSpec) -> Result<(), String> {
        let spec = &stored.spec;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        // Only a new spec counts toward the limit, so a namespace stored
        // over it before the limit can still replace its specs.
        let (specs, exists): (i64, i64) = tx
            .query_row(
                "SELECT count(*), coalesce(sum(spec_id = ?2), 0)
                 FROM sekai_embedding_specs WHERE namespace = ?1",
                params![spec.namespace, spec.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        if exists == 0 && specs >= MAX_SPECS_PER_NAMESPACE as i64 {
            return Err(EMBEDDING_SPEC_LIMIT.into());
        }
        tx.execute(
            BUMP_SPEC_CHECKPOINT_SQLITE,
            params![spec.namespace, spec.id],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_embedding_specs
             (namespace, spec_id, object_kind, properties, chunk_chars, dimension,
              batch_size, model, updated_by, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(namespace, spec_id) DO UPDATE SET
                object_kind = excluded.object_kind, properties = excluded.properties,
                chunk_chars = excluded.chunk_chars, dimension = excluded.dimension,
                batch_size = excluded.batch_size, model = excluded.model,
                updated_by = excluded.updated_by, updated_at_ms = excluded.updated_at_ms",
            params![
                spec.namespace,
                spec.id,
                spec.object_kind,
                join_properties(&spec.properties),
                spec.chunk_chars as i64,
                spec.dimension as i64,
                spec.batch_size as i64,
                stored.model,
                stored.updated_by,
                stored.updated_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
    }

    fn list_embedding_specs(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<StoredEmbeddingSpec>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT s.namespace, s.spec_id, s.object_kind, s.properties, s.chunk_chars,
                        s.dimension, s.batch_size, s.model, s.updated_by, s.updated_at_ms,
                        coalesce(c.revision, 0)
                 FROM sekai_embedding_specs s
                 LEFT JOIN sekai_embedding_checkpoints c
                   ON c.namespace = s.namespace AND c.spec_id = s.spec_id
                 WHERE ?1 IS NULL OR s.namespace = ?1
                 ORDER BY s.namespace, s.spec_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(
                |(ns, id, kind, properties, chunk, dim, batch, model, by, at, revision)| {
                    stored_spec(
                        ns,
                        id,
                        kind,
                        &properties,
                        chunk,
                        dim,
                        batch,
                        model,
                        by,
                        at,
                        revision,
                    )
                },
            )
            .collect()
    }

    fn delete_embedding_spec(&self, namespace: &str, spec_id: &str) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        // The checkpoint row first (created if a first put has not made it
        // yet), as put and fenced writes take it, so no catch-up can add
        // vectors after the deletes below.
        tx.execute(
            "INSERT INTO sekai_embedding_checkpoints
             (namespace, spec_id, spec_digest, last_change_rowid, last_generation, revision,
              updated_at_ms)
             VALUES (?1, ?2, '', 0, 0, 1, 0)
             ON CONFLICT(namespace, spec_id) DO UPDATE SET
                spec_digest = '', last_change_rowid = 0, last_generation = 0,
                revision = revision + 1, updated_at_ms = 0",
            params![namespace, spec_id],
        )
        .map_err(|error| error.to_string())?;
        let deleted = tx
            .execute(
                "DELETE FROM sekai_embedding_specs WHERE namespace = ?1 AND spec_id = ?2",
                params![namespace, spec_id],
            )
            .map_err(|error| error.to_string())?;
        for table in ["sekai_embedding_chunks", "sekai_embedding_rebuilds"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE namespace = ?1 AND spec_id = ?2"),
                params![namespace, spec_id],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(deleted == 1)
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
        cursor: &RebuildCursor,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        dispatch!(self, db => db.reset_embedding_spec(namespace, spec_id, cursor, revision, now_ms))
    }

    fn store_embedding_rebuild_cursor(
        &self,
        namespace: &str,
        spec_id: &str,
        cursor: &RebuildCursor,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        dispatch!(self, db => db.store_embedding_rebuild_cursor(
            namespace, spec_id, cursor, revision, now_ms
        ))
    }

    fn resume_embedding_rebuild(
        &self,
        namespace: &str,
        spec_id: &str,
        kind: &str,
        cursor: &RebuildCursor,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String> {
        dispatch!(self, db => db.resume_embedding_rebuild(
            namespace, spec_id, kind, cursor, revision, now_ms
        ))
    }

    fn embedding_vector_count(&self, namespace: &str, spec_id: &str) -> Result<i64, String> {
        dispatch!(self, db => db.embedding_vector_count(namespace, spec_id))
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

    fn put_embedding_spec(&self, stored: &StoredEmbeddingSpec) -> Result<(), String> {
        dispatch!(self, db => db.put_embedding_spec(stored))
    }

    fn list_embedding_specs(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<StoredEmbeddingSpec>, String> {
        dispatch!(self, db => db.list_embedding_specs(namespace))
    }

    fn delete_embedding_spec(&self, namespace: &str, spec_id: &str) -> Result<bool, String> {
        dispatch!(self, db => db.delete_embedding_spec(namespace, spec_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor() -> RebuildCursor {
        RebuildCursor {
            to_digest: "v2".into(),
            after_id: "k0499".into(),
            ..Default::default()
        }
    }

    /// #2244: the cursor survives this plane's own writes, and any write
    /// that does not carry it forward (here an older plane's fenced write)
    /// voids it, so a resume never skips objects whose vectors were reset.
    #[test]
    fn rebuild_cursor_is_voided_by_a_write_that_does_not_carry_it() {
        let db = SekaiDb::new(":memory:").unwrap();
        let revision = db.reset_embedding_spec("ns", "s", &cursor(), 0, 1).unwrap();
        let revision = db
            .store_embedding_checkpoint(
                "ns",
                "s",
                &EmbeddingCheckpoint {
                    revision,
                    ..Default::default()
                },
                2,
            )
            .unwrap();
        let read = db.embedding_checkpoint("ns", "s").unwrap().unwrap();
        assert_eq!((read.revision, read.rebuild), (revision, Some(cursor())));

        // What a plane from before the cursor runs for every fenced write.
        db.conn()
            .execute(
                "UPDATE sekai_embedding_checkpoints SET revision = revision + 1
                 WHERE namespace = 'ns' AND spec_id = 's'",
                [],
            )
            .unwrap();
        let read = db.embedding_checkpoint("ns", "s").unwrap().unwrap();
        assert_eq!(read.rebuild, None);
    }

    #[test]
    fn checkpoints_from_before_the_cursor_gain_its_columns() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn()
            .execute_batch(
                "DROP TABLE sekai_embedding_checkpoints;
                 CREATE TABLE sekai_embedding_checkpoints (
                    namespace TEXT NOT NULL, spec_id TEXT NOT NULL, spec_digest TEXT NOT NULL,
                    last_change_rowid INTEGER NOT NULL, last_generation INTEGER NOT NULL,
                    revision INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (namespace, spec_id));
                 INSERT INTO sekai_embedding_checkpoints VALUES ('ns', 's', 'd', 7, 3, 4, 0);",
            )
            .unwrap();
        db.migrate_embedding_index().unwrap();
        db.migrate_embedding_index().unwrap();
        let read = db.embedding_checkpoint("ns", "s").unwrap().unwrap();
        assert_eq!(
            (read.spec_digest.as_str(), read.revision, read.rebuild),
            ("d", 4, None)
        );
    }
}
