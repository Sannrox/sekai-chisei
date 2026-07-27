//! Shared hybrid retrieval candidate envelope (#360 / research #152).
//!
//! Cross-representation ranking needs a stable contract so scores are never
//! silently compared across kinds. Late fusion of multiple adapters is #361;
//! this module only defines the envelope and score-kind registry names.

use std::fmt;

/// Graph representation used by `RetrieveContext` (#144).
pub const REPRESENTATION_GRAPH_RETRIEVE_CONTEXT: &str = "graph.retrieve_context";
/// Lexical SQLite FTS5 text representation (#360).
pub const REPRESENTATION_TEXT_FTS5: &str = "text.fts5";

/// Deterministic graph affinity score kind (depth + multi-root corroboration).
pub const SCORE_KIND_GRAPH_CONTEXT_AFFINITY_V1: &str = "graph.context_affinity/v1";
/// SQLite FTS5 BM25 score kind. Score is `-bm25(table)` so higher is better.
pub const SCORE_KIND_TEXT_FTS5_BM25_V1: &str = "text.fts5_bm25/v1";

/// Projection source identity for the SQLite FTS text index.
pub const SOURCE_SQLITE_TEXT_FTS5: &str = "sqlite.text_fts5";

/// Entity kinds that may appear on [`EntityRef`] when a source of truth
/// already asserts the identifier. Similarity never invents these ids.
pub const ENTITY_KIND_OBJECT: &str = "object";
pub const ENTITY_KIND_EVIDENCE_SUBMISSION: &str = "evidence_submission";
pub const ENTITY_KIND_LINK: &str = "link";

/// Stable identifier for a durable fact already present in a source of truth.
///
/// Must only be populated when the underlying store already asserts the id.
/// Text similarity must not mint, merge, or equate durable identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityRef {
    pub kind: String,
    pub id: String,
}

/// Authorization context summary for audit. Not a grant token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthzContextSummary {
    pub namespace: String,
    /// Principal class or authenticated principal label used for the re-check.
    pub principal_class: String,
    /// Classification ceiling applied, if any (empty when none).
    pub classification_ceiling: String,
}

/// Shared hybrid candidate envelope (research #152 phase A / issue #360).
#[derive(Debug, Clone, PartialEq)]
pub struct HybridCandidate {
    pub representation_id: String,
    pub source: String,
    pub source_version: String,
    pub score: f64,
    pub score_kind: String,
    /// Set only when a source of truth already asserts this identifier.
    pub entity_ref: Option<EntityRef>,
    pub authz_context: AuthzContextSummary,
    /// Candidate-level truncation (e.g. snippet capped).
    pub truncated: bool,
    /// True only when the candidate is withheld from disclosure after re-check.
    /// Disclosed responses normally omit denied material entirely; this flag
    /// exists for internal accounting and must not carry secret names.
    pub denied: bool,
}

impl HybridCandidate {
    /// Build a text-FTS candidate. Does not invent entity ids.
    pub fn text_fts(
        source_version: impl Into<String>,
        score: f64,
        entity_ref: Option<EntityRef>,
        authz: AuthzContextSummary,
    ) -> Self {
        Self {
            representation_id: REPRESENTATION_TEXT_FTS5.into(),
            source: SOURCE_SQLITE_TEXT_FTS5.into(),
            source_version: source_version.into(),
            score,
            score_kind: SCORE_KIND_TEXT_FTS5_BM25_V1.into(),
            entity_ref,
            authz_context: authz,
            truncated: false,
            denied: false,
        }
    }
}

/// Registered score kinds for the hybrid envelope (additive only).
pub fn known_score_kinds() -> &'static [&'static str] {
    &[
        SCORE_KIND_GRAPH_CONTEXT_AFFINITY_V1,
        SCORE_KIND_TEXT_FTS5_BM25_V1,
    ]
}

/// Registered representation ids for the hybrid envelope (additive only).
pub fn known_representation_ids() -> &'static [&'static str] {
    &[
        REPRESENTATION_GRAPH_RETRIEVE_CONTEXT,
        REPRESENTATION_TEXT_FTS5,
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridError {
    InvalidArgument(String),
    Storage(String),
}

impl fmt::Display for HybridError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) | Self::Storage(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HybridError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_kinds_are_versioned_and_distinct() {
        assert!(SCORE_KIND_TEXT_FTS5_BM25_V1.ends_with("/v1"));
        assert_ne!(
            SCORE_KIND_GRAPH_CONTEXT_AFFINITY_V1,
            SCORE_KIND_TEXT_FTS5_BM25_V1
        );
        assert!(known_score_kinds().contains(&SCORE_KIND_TEXT_FTS5_BM25_V1));
        assert!(known_representation_ids().contains(&REPRESENTATION_TEXT_FTS5));
    }

    #[test]
    fn text_candidate_never_requires_entity_ref() {
        let candidate = HybridCandidate::text_fts(
            "gen:1",
            1.5,
            None,
            AuthzContextSummary {
                namespace: "ns".into(),
                principal_class: "user:alice".into(),
                classification_ceiling: String::new(),
            },
        );
        assert_eq!(candidate.representation_id, REPRESENTATION_TEXT_FTS5);
        assert_eq!(candidate.score_kind, SCORE_KIND_TEXT_FTS5_BM25_V1);
        assert!(candidate.entity_ref.is_none());
        assert!(!candidate.denied);
    }
}
