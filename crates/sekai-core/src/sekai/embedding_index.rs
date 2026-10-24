//! Governed embedding index for object properties (#1581).
//!
//! An [`EmbeddingSpec`] names the object kind, source properties, chunking
//! rule and vector dimension. The catch-up in
//! `crate::composition::embedding_catch_up` follows the object-change feed and
//! re-embeds only chunks whose text changed. A spec or model version
//! change rebuilds the spec's vectors and records the rebuild. Every stored
//! vector carries its model, model version, source digest, the object's
//! marking and the classification of each source property. Like the search
//! index, the vectors are a derived projection: losing them loses no facts.

use crate::domain::Object;
use sha2::{Digest, Sha256};

/// Chunking rule identity. Changing how text is chunked bumps this and so
/// every spec digest, which forces a rebuild.
pub const CHUNK_RULE: &str = "embed.chars/v1";
/// Object changes one catch-up consumes; the rest wait for the next call.
pub const CHANGE_PAGE: i32 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddingError {
    InvalidArgument(String),
    /// Governance refused the route: review state, or a source property that
    /// may not leave the deployment on an external route.
    Refused(String),
    Model(String),
    Storage(String),
    /// Another catch-up changed the spec's index first; nothing of this one
    /// was kept past the point of conflict. The next call retries.
    Conflict(String),
}

/// Store error text for a stale revision; see [`EmbeddingStore`].
pub const EMBEDDING_REVISION_CONFLICT: &str = "embedding index changed by another catch-up; retry";

impl std::fmt::Display for EmbeddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument(message)
            | Self::Refused(message)
            | Self::Model(message)
            | Self::Storage(message)
            | Self::Conflict(message) => f.write_str(message),
        }
    }
}

impl From<String> for EmbeddingError {
    fn from(message: String) -> Self {
        if message == EMBEDDING_REVISION_CONFLICT {
            Self::Conflict(message)
        } else {
            Self::Storage(message)
        }
    }
}

/// What to embed for one object kind in one namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingSpec {
    pub id: String,
    pub namespace: String,
    pub object_kind: String,
    /// Source properties, embedded in this order as `name: value` lines.
    pub properties: Vec<String>,
    /// Characters per chunk.
    pub chunk_chars: usize,
    pub dimension: usize,
    /// Texts per embedding call.
    pub batch_size: usize,
}

impl EmbeddingSpec {
    pub fn validate(&self) -> Result<(), EmbeddingError> {
        let invalid = |message: &str| Err(EmbeddingError::InvalidArgument(message.into()));
        if self.id.trim().is_empty() || self.namespace.trim().is_empty() {
            return invalid("embedding spec needs an id and a namespace");
        }
        if self.object_kind.trim().is_empty() || self.properties.is_empty() {
            return invalid("embedding spec needs an object kind and source properties");
        }
        if self.chunk_chars == 0 || self.dimension == 0 || self.batch_size == 0 {
            return invalid("chunk_chars, dimension and batch_size must be positive");
        }
        Ok(())
    }

    /// Content address of the spec, chunk rule and model. Stored with the
    /// checkpoint; a different digest means the vectors are stale.
    pub fn digest(&self, model: &str, model_version: &str) -> String {
        sha_hex(
            &[
                CHUNK_RULE,
                &self.object_kind,
                &self.properties.join("\u{1f}"),
                &self.chunk_chars.to_string(),
                &self.dimension.to_string(),
                model,
                model_version,
            ]
            .join("\u{1e}"),
        )
    }
}

/// A spec an operator stored for a namespace (#1609), with the catalog
/// model route that embeds it. Catch-up runs every stored spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEmbeddingSpec {
    pub spec: EmbeddingSpec,
    pub model: String,
    pub updated_by: String,
    pub updated_at_ms: i64,
    /// The spec's checkpoint revision when it was listed. Put and delete
    /// move it on, so a catch-up for this listing is refused once the spec
    /// changed or went away. Ignored on put.
    pub revision: i64,
}

/// Stored progress for one spec in one namespace.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmbeddingCheckpoint {
    pub spec_digest: String,
    pub last_change_rowid: u64,
    pub last_generation: u64,
    /// Bumped by every write to the spec's index. Writers pass the revision
    /// they last saw; a mismatch is [`EMBEDDING_REVISION_CONFLICT`].
    pub revision: i64,
    /// Time of the last fenced write, read back only; 0 after a stored spec
    /// is put or deleted. A rebuild keeps it fresh as its lease.
    pub updated_at_ms: i64,
}

/// Governance tags shared by every chunk of one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingSource {
    pub source_digest: String,
    pub model: String,
    pub model_version: String,
    /// The object's marking, joined over its inputs (#1403).
    pub marking: Option<String>,
    /// `property=classification` for each source property, from the schema.
    pub classifications: Vec<String>,
}

/// The vectors of one object a catch-up writes.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectEmbeddings<'a> {
    pub object_id: &'a str,
    pub source: &'a EmbeddingSource,
    /// Re-embedded chunks: index, chunk digest, vector.
    pub chunks: &'a [(u32, String, Vec<f32>)],
    /// Chunk count of the object now; stored indexes at or past it go.
    pub keep: u32,
}

/// One stored vector.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingChunk {
    pub object_id: String,
    pub chunk_index: u32,
    pub chunk_digest: String,
    pub vector: Vec<f32>,
    pub source: EmbeddingSource,
    pub embedded_at_ms: i64,
}

/// A recorded rebuild: why the vectors of a spec were replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingRebuild {
    pub from_digest: String,
    pub to_digest: String,
    pub objects: i64,
    pub rebuilt_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmbeddingCatchUpReport {
    pub rebuilt: bool,
    pub consumed_changes: i64,
    pub objects: i64,
    pub chunks_embedded: i64,
    /// Age of the oldest consumed change.
    pub lag_ms: i64,
    /// More changes are pending than one call consumes.
    pub more: bool,
}

/// Storage for derived vectors. Implemented by each runtime backend.
///
/// Every write is fenced: it takes the spec revision the caller last saw
/// (0 before the first write), fails with [`EMBEDDING_REVISION_CONFLICT`] when
/// another writer moved it, and returns the new revision. The check and the
/// write share one transaction, so two catch-ups cannot interleave.
pub trait EmbeddingStore {
    fn embedding_checkpoint(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Option<EmbeddingCheckpoint>, String>;
    /// Store progress. `checkpoint.revision` is the expected revision.
    fn store_embedding_checkpoint(
        &self,
        namespace: &str,
        spec_id: &str,
        checkpoint: &EmbeddingCheckpoint,
        now_ms: i64,
    ) -> Result<i64, String>;
    /// Stored chunk digests of one object, by chunk index.
    fn embedding_chunk_digests(
        &self,
        namespace: &str,
        spec_id: &str,
        object_id: &str,
    ) -> Result<Vec<String>, String>;
    /// Upsert the re-embedded chunks, drop indexes at or past `keep`, and
    /// retag every remaining chunk of the object with `source`.
    fn write_embedding_object(
        &self,
        namespace: &str,
        spec_id: &str,
        write: &ObjectEmbeddings<'_>,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String>;
    fn delete_embedding_object(
        &self,
        namespace: &str,
        spec_id: &str,
        object_id: &str,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String>;
    /// Drop every vector of the spec and clear the checkpoint digest, so no
    /// catch-up trusts the half-built index.
    fn reset_embedding_spec(
        &self,
        namespace: &str,
        spec_id: &str,
        revision: i64,
        now_ms: i64,
    ) -> Result<i64, String>;
    /// Record a finished rebuild and publish its checkpoint in one fenced
    /// write; `checkpoint.revision` is the expected revision. An interrupted
    /// or superseded rebuild records nothing.
    fn complete_embedding_rebuild(
        &self,
        namespace: &str,
        spec_id: &str,
        rebuild: &EmbeddingRebuild,
        checkpoint: &EmbeddingCheckpoint,
        now_ms: i64,
    ) -> Result<i64, String>;
    /// Ids of `kind` objects in `namespace` after `after_id`, ascending: a
    /// keyset page that deletions cannot shift.
    fn embedding_source_ids(
        &self,
        namespace: &str,
        kind: &str,
        after_id: &str,
        limit: i64,
    ) -> Result<Vec<String>, String>;
    fn embedding_chunks(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<EmbeddingChunk>, String>;
    fn embedding_rebuilds(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<EmbeddingRebuild>, String>;
    /// Insert or replace a stored spec and move its checkpoint revision on.
    fn put_embedding_spec(&self, stored: &StoredEmbeddingSpec) -> Result<(), String>;
    /// Stored specs of one namespace, or of every namespace, by namespace and id.
    fn list_embedding_specs(
        &self,
        namespace: Option<&str>,
    ) -> Result<Vec<StoredEmbeddingSpec>, String>;
    /// Remove a stored spec with its vectors and rebuild history, and reset
    /// its checkpoint with the revision moved on (never back), in one
    /// transaction. Returns whether the spec existed.
    fn delete_embedding_spec(&self, namespace: &str, spec_id: &str) -> Result<bool, String>;
}

/// The text embedded for an object: `name: value` lines for each present
/// source property, in spec order.
pub fn source_text(spec: &EmbeddingSpec, object: &Object) -> String {
    spec.properties
        .iter()
        .filter_map(|property| {
            object
                .properties
                .get(property)
                .filter(|value| !value.is_empty())
                .map(|value| format!("{property}: {value}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Split on character boundaries into chunks of at most `chunk_chars`.
pub fn chunk_text(text: &str, chunk_chars: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(chunk_chars.max(1))
        .map(|chunk| chunk.iter().collect())
        .collect()
}

pub fn sha_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Little-endian `f32` bytes, the stored vector encoding.
pub fn vector_bytes(vector: &[f32]) -> Vec<u8> {
    vector
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

pub fn vector_from_bytes(bytes: &[u8]) -> Vec<f32> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| f32::from_le_bytes(*chunk))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_split_on_character_boundaries() {
        assert_eq!(chunk_text("äbcdé", 2), vec!["äb", "cd", "é"]);
        assert!(chunk_text("", 4).is_empty());
    }
}
