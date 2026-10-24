//! PostgreSQL storage for the embedding index (migrations 0086 and 0095).

use crate::db::embedding_index::{
    join_classifications, join_properties, split_classifications, stored_spec,
};
use crate::db::postgres::PostgresDb;
use crate::sekai::embedding_index::{
    EMBEDDING_REVISION_CONFLICT, EmbeddingCheckpoint, EmbeddingChunk, EmbeddingRebuild,
    EmbeddingSource, EmbeddingStore, ObjectEmbeddings, StoredEmbeddingSpec, vector_bytes,
    vector_from_bytes,
};

fn pg_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

impl PostgresDb {
    /// Run `write` in a transaction after a compare-and-bump of the spec
    /// revision (the row lock serializes writers). Returns the new revision.
    fn fenced_embedding_write(
        &self,
        namespace: &str,
        spec_id: &str,
        revision: i64,
        now_ms: i64,
        write: impl FnOnce(&mut postgres::Transaction<'_>) -> Result<(), postgres::Error>,
    ) -> Result<i64, String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(pg_error)?;
        let bumped = tx
            .execute(
                "UPDATE sekai_embedding_checkpoints
                 SET revision = revision + 1, updated_at_ms = $4
                 WHERE namespace = $1 AND spec_id = $2 AND revision = $3",
                &[&namespace, &spec_id, &revision, &now_ms],
            )
            .map_err(pg_error)?;
        let created = bumped == 0
            && revision == 0
            && tx
                .execute(
                    "INSERT INTO sekai_embedding_checkpoints
                     (namespace, spec_id, spec_digest, last_change_rowid, last_generation,
                      revision, updated_at_ms)
                     VALUES ($1, $2, '', 0, 0, 1, $3)
                     ON CONFLICT (namespace, spec_id) DO NOTHING",
                    &[&namespace, &spec_id, &now_ms],
                )
                .map_err(pg_error)?
                == 1;
        if bumped != 1 && !created {
            return Err(EMBEDDING_REVISION_CONFLICT.into());
        }
        write(&mut tx).map_err(pg_error)?;
        tx.commit().map_err(pg_error)?;
        Ok(revision + 1)
    }
}

impl EmbeddingStore for PostgresDb {
    fn embedding_checkpoint(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Option<EmbeddingCheckpoint>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT spec_digest, last_change_rowid, last_generation, revision, updated_at_ms
                 FROM sekai_embedding_checkpoints WHERE namespace = $1 AND spec_id = $2",
                &[&namespace, &spec_id],
            )
            .map_err(pg_error)?
            .map(|row| EmbeddingCheckpoint {
                spec_digest: row.get(0),
                last_change_rowid: row.get::<_, i64>(1).max(0) as u64,
                last_generation: row.get::<_, i64>(2).max(0) as u64,
                revision: row.get(3),
                updated_at_ms: row.get(4),
            }))
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
                 SET spec_digest = $3, last_change_rowid = $4, last_generation = $5
                 WHERE namespace = $1 AND spec_id = $2",
                &[
                    &namespace,
                    &spec_id,
                    &checkpoint.spec_digest,
                    &(checkpoint.last_change_rowid as i64),
                    &(checkpoint.last_generation as i64),
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
        Ok(self
            .connection()?
            .query(
                "SELECT chunk_digest FROM sekai_embedding_chunks
                 WHERE namespace = $1 AND spec_id = $2 AND object_id = $3
                 ORDER BY chunk_index",
                &[&namespace, &spec_id, &object_id],
            )
            .map_err(pg_error)?
            .iter()
            .map(|row| row.get(0))
            .collect())
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
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                     ON CONFLICT (namespace, spec_id, object_id, chunk_index) DO UPDATE SET
                        chunk_digest = EXCLUDED.chunk_digest,
                        vector = EXCLUDED.vector,
                        embedded_at_ms = EXCLUDED.embedded_at_ms",
                    &[
                        &namespace,
                        &spec_id,
                        &object_id,
                        &(*index as i64),
                        digest,
                        &vector_bytes(vector),
                        &source.source_digest,
                        &source.model,
                        &source.model_version,
                        &source.marking,
                        &classifications,
                        &now_ms,
                    ],
                )?;
            }
            tx.execute(
                "DELETE FROM sekai_embedding_chunks
                 WHERE namespace = $1 AND spec_id = $2 AND object_id = $3 AND chunk_index >= $4",
                &[&namespace, &spec_id, &object_id, &(keep as i64)],
            )?;
            tx.execute(
                "UPDATE sekai_embedding_chunks
                 SET source_digest = $4, model = $5, model_version = $6, marking = $7,
                     classifications = $8
                 WHERE namespace = $1 AND spec_id = $2 AND object_id = $3",
                &[
                    &namespace,
                    &spec_id,
                    &object_id,
                    &source.source_digest,
                    &source.model,
                    &source.model_version,
                    &source.marking,
                    &classifications,
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
                 WHERE namespace = $1 AND spec_id = $2 AND object_id = $3",
                &[&namespace, &spec_id, &object_id],
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
                 WHERE namespace = $1 AND spec_id = $2",
                &[&namespace, &spec_id],
            )?;
            tx.execute(
                "DELETE FROM sekai_embedding_chunks WHERE namespace = $1 AND spec_id = $2",
                &[&namespace, &spec_id],
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
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &namespace,
                    &spec_id,
                    &rebuild.from_digest,
                    &rebuild.to_digest,
                    &rebuild.objects,
                    &rebuild.rebuilt_at_ms,
                ],
            )?;
            tx.execute(
                "UPDATE sekai_embedding_checkpoints
                 SET spec_digest = $3, last_change_rowid = $4, last_generation = $5
                 WHERE namespace = $1 AND spec_id = $2",
                &[
                    &namespace,
                    &spec_id,
                    &checkpoint.spec_digest,
                    &(checkpoint.last_change_rowid as i64),
                    &(checkpoint.last_generation as i64),
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
        Ok(self
            .connection()?
            .query(
                "SELECT id FROM sekai_objects
                 WHERE namespace = $1 AND kind = $2 AND id > $3
                 ORDER BY id LIMIT $4",
                &[&namespace, &kind, &after_id, &limit],
            )
            .map_err(pg_error)?
            .iter()
            .map(|row| row.get(0))
            .collect())
    }

    fn embedding_chunks(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<EmbeddingChunk>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT object_id, chunk_index, chunk_digest, vector, source_digest, model,
                        model_version, marking, classifications, embedded_at_ms
                 FROM sekai_embedding_chunks WHERE namespace = $1 AND spec_id = $2
                 ORDER BY object_id, chunk_index",
                &[&namespace, &spec_id],
            )
            .map_err(pg_error)?
            .iter()
            .map(|row| EmbeddingChunk {
                object_id: row.get(0),
                chunk_index: row.get::<_, i64>(1) as u32,
                chunk_digest: row.get(2),
                vector: vector_from_bytes(&row.get::<_, Vec<u8>>(3)),
                source: EmbeddingSource {
                    source_digest: row.get(4),
                    model: row.get(5),
                    model_version: row.get(6),
                    marking: row.get(7),
                    classifications: split_classifications(&row.get::<_, String>(8)),
                },
                embedded_at_ms: row.get(9),
            })
            .collect())
    }

    fn embedding_rebuilds(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<EmbeddingRebuild>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT from_digest, to_digest, objects, rebuilt_at_ms
                 FROM sekai_embedding_rebuilds WHERE namespace = $1 AND spec_id = $2
                 ORDER BY id",
                &[&namespace, &spec_id],
            )
            .map_err(pg_error)?
            .iter()
            .map(|row| EmbeddingRebuild {
                from_digest: row.get(0),
                to_digest: row.get(1),
                objects: row.get(2),
                rebuilt_at_ms: row.get(3),
            })
            .collect())
    }

    fn put_embedding_spec(&self, stored: &StoredEmbeddingSpec) -> Result<(), String> {
        let spec = &stored.spec;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(pg_error)?;
        // Moves the revision on (creating the row), fencing out a catch-up
        // that listed the spec earlier, and ends any rebuild lease. The
        // checkpoint row is locked first, in the order delete and fenced
        // writes take it.
        tx.execute(
            "INSERT INTO sekai_embedding_checkpoints
             (namespace, spec_id, spec_digest, last_change_rowid, last_generation, revision,
              updated_at_ms)
             VALUES ($1, $2, '', 0, 0, 1, 0)
             ON CONFLICT (namespace, spec_id) DO UPDATE SET
                revision = sekai_embedding_checkpoints.revision + 1, updated_at_ms = 0",
            &[&spec.namespace, &spec.id],
        )
        .map_err(pg_error)?;
        tx.execute(
            "INSERT INTO sekai_embedding_specs
             (namespace, spec_id, object_kind, properties, chunk_chars, dimension,
              batch_size, model, updated_by, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (namespace, spec_id) DO UPDATE SET
                object_kind = EXCLUDED.object_kind, properties = EXCLUDED.properties,
                chunk_chars = EXCLUDED.chunk_chars, dimension = EXCLUDED.dimension,
                batch_size = EXCLUDED.batch_size, model = EXCLUDED.model,
                updated_by = EXCLUDED.updated_by, updated_at_ms = EXCLUDED.updated_at_ms",
            &[
                &spec.namespace,
                &spec.id,
                &spec.object_kind,
                &join_properties(&spec.properties),
                &(spec.chunk_chars as i64),
                &(spec.dimension as i64),
                &(spec.batch_size as i64),
                &stored.model,
                &stored.updated_by,
                &stored.updated_at_ms,
            ],
        )
        .map_err(pg_error)?;
        tx.commit().map_err(pg_error)
    }

    fn list_embedding_specs(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<StoredEmbeddingSpec>, String> {
        self.connection()?
            .query(
                "SELECT s.namespace, s.spec_id, s.object_kind, s.properties, s.chunk_chars,
                        s.dimension, s.batch_size, s.model, s.updated_by, s.updated_at_ms,
                        coalesce(c.revision, 0)
                 FROM sekai_embedding_specs s
                 LEFT JOIN sekai_embedding_checkpoints c
                   ON c.namespace = s.namespace AND c.spec_id = s.spec_id
                 WHERE $1::TEXT IS NULL OR s.namespace = $1
                 ORDER BY s.namespace, s.spec_id",
                &[&namespace],
            )
            .map_err(pg_error)?
            .iter()
            .map(|row| {
                stored_spec(
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get::<_, String>(3).as_str(),
                    row.get(4),
                    row.get(5),
                    row.get(6),
                    row.get(7),
                    row.get(8),
                    row.get(9),
                    row.get(10),
                )
            })
            .collect()
    }

    fn delete_embedding_spec(&self, namespace: &str, spec_id: &str) -> Result<bool, String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(pg_error)?;
        // The checkpoint row first (created if a first put has not made it
        // yet), as put and fenced writes take it, so no catch-up can add
        // vectors after the deletes below.
        tx.execute(
            "INSERT INTO sekai_embedding_checkpoints
             (namespace, spec_id, spec_digest, last_change_rowid, last_generation, revision,
              updated_at_ms)
             VALUES ($1, $2, '', 0, 0, 1, 0)
             ON CONFLICT (namespace, spec_id) DO UPDATE SET
                spec_digest = '', last_change_rowid = 0, last_generation = 0,
                revision = sekai_embedding_checkpoints.revision + 1, updated_at_ms = 0",
            &[&namespace, &spec_id],
        )
        .map_err(pg_error)?;
        let deleted = tx
            .execute(
                "DELETE FROM sekai_embedding_specs WHERE namespace = $1 AND spec_id = $2",
                &[&namespace, &spec_id],
            )
            .map_err(pg_error)?;
        for table in ["sekai_embedding_chunks", "sekai_embedding_rebuilds"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE namespace = $1 AND spec_id = $2"),
                &[&namespace, &spec_id],
            )
            .map_err(pg_error)?;
        }
        tx.commit().map_err(pg_error)?;
        Ok(deleted == 1)
    }
}
