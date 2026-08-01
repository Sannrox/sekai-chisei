//! SQLite FTS5 text representation for hybrid retrieval (#360 / research #152).
//!
//! The index is a **rebuildable projection** over sources of truth (evidence
//! submission content and selected object property text). It never becomes a
//! second durable store of identities. Query paths re-check authorization
//! against live sources of truth and omit denied or deleted material
//! (non-disclosure). Similarity scores never mint durable object identities.
//!
//! Public score kind: [`crate::sekai::hybrid::SCORE_KIND_AUTHORIZED_TEXT_BM25_V1`]
//! (`text.authorized_bm25/v1`). Score values are `-bm25(table)` so higher is
//! better. The legacy global projection below is internal-only.

use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::evidence::EvidenceLifecycleState;
use crate::sekai::evidence_store::EvidenceSubmissionRecord;
use crate::sekai::hybrid::{
    AuthzContextSummary, ENTITY_KIND_EVIDENCE_SUBMISSION, ENTITY_KIND_OBJECT, EntityRef,
    HybridCandidate, HybridError, REPRESENTATION_AUTHORIZED_TEXT, REPRESENTATION_TEXT_FTS5,
    SCORE_KIND_AUTHORIZED_TEXT_BM25_V1, SCORE_KIND_TEXT_FTS5_BM25_V1, SOURCE_AUTHORIZED_TEXT,
    SOURCE_SQLITE_TEXT_FTS5,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Index generation meta key (monotonic generation string `gen:<n>`).
pub const META_GENERATION: &str = "generation";
/// Last rebuild wall-clock ms.
pub const META_REBUILT_AT_MS: &str = "rebuilt_at_ms";
/// Corpus selection version for operator notes.
pub const META_CORPUS_PROFILE: &str = "corpus_profile";
pub const CORPUS_PROFILE_V1: &str = "evidence_content+object_props/v1";

pub const SOURCE_KIND_EVIDENCE: &str = "evidence";
pub const SOURCE_KIND_OBJECT_PROPERTY: &str = "object_property";

pub const DEFAULT_MAX_CANDIDATES: u32 = 20;
pub const MAX_CANDIDATES: u32 = 100;
pub const MAX_QUERY_CHARS: usize = 512;
/// Cap property values and evidence string leaves so the index stays bounded.
pub const MAX_INDEXED_TEXT_CHARS: usize = 8_192;
/// Stable source version for the authorization-built per-request corpus.
pub const AUTHORIZED_TEXT_SOURCE_VERSION: &str = "authorized-text/v1";
/// Bound the amount of authorized source material copied into one request's
/// private FTS index. This cap is applied after authorization and therefore
/// cannot be changed by adding hidden rows.
pub const MAX_AUTHORIZED_TEXT_DOCUMENTS: usize = 100_000;
/// Bound the private FTS input even when every authorized row contains a large
/// (but individually capped) text value.
pub const MAX_AUTHORIZED_TEXT_BYTES: usize = 64 * 1024 * 1024;
/// Page the rebuildable index while authorization is rechecked outside the
/// pooled connection.  A page is always rechecked against the index generation
/// before it is added to a result assembled across pooled connections.
#[allow(dead_code)]
const TEXT_FTS_PAGE_SIZE: i64 = 64;
#[allow(dead_code)]
const MAX_TEXT_FTS_GENERATION_RESTARTS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextSourceFilter {
    All,
    Evidence,
    ObjectProperties,
}

impl TextSourceFilter {
    pub fn parse(value: &str) -> Result<Self, HybridError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "all" => Ok(Self::All),
            "evidence" => Ok(Self::Evidence),
            "object_props" | "object_properties" | "object" => Ok(Self::ObjectProperties),
            other => Err(HybridError::InvalidArgument(format!(
                "unknown text source_kinds {other:?}; expected all, evidence, or object_props"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Evidence => "evidence",
            Self::ObjectProperties => "object_props",
        }
    }

    fn matches(self, source_kind: &str) -> bool {
        match self {
            Self::All => true,
            Self::Evidence => source_kind == SOURCE_KIND_EVIDENCE,
            Self::ObjectProperties => source_kind == SOURCE_KIND_OBJECT_PROPERTY,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TextSearchQuery {
    pub query: String,
    pub namespace: String,
    pub source_kinds: TextSourceFilter,
    pub max_candidates: u32,
    /// Shared-plan deadline budget. Public adapters stop at the budget with a
    /// generic `max_time_ms` truncation reason; raw internal FTS callers may
    /// leave enforcement to their enclosing operation.
    pub max_time_ms: u32,
}

#[derive(Debug, Clone, Default)]
pub struct TextSearchResult {
    pub candidates: Vec<HybridCandidate>,
    pub source_version: String,
    pub representation_id: String,
    pub truncated: bool,
    pub truncation_reasons: Vec<String>,
    pub denied_count: u32,
    pub scanned: u32,
}

/// A source-of-truth text row that has already passed the caller's visibility
/// checks. These documents, and only these documents, enter the public text
/// adapter's private FTS index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedTextDocument {
    pub doc_id: String,
    pub source_kind: String,
    pub source_id: String,
    pub source_key: String,
    pub namespace: String,
    pub entity_kind: String,
    pub entity_id: String,
    pub content_hash: String,
    pub text_body: String,
}

impl AuthorizedTextDocument {
    /// Convert one visible object property into an indexed document.
    pub(crate) fn object_property(object: &Object, key: &str, value: &str) -> Option<Self> {
        if key.trim().is_empty()
            || key.starts_with('_')
            || value.trim().is_empty()
            || object.id.trim().is_empty()
        {
            return None;
        }
        let text_body = truncate_chars(value, MAX_INDEXED_TEXT_CHARS);
        if text_body.trim().is_empty() {
            return None;
        }
        Some(Self {
            doc_id: format!("object_prop:{}:{key}", object.id),
            source_kind: SOURCE_KIND_OBJECT_PROPERTY.into(),
            source_id: object.id.clone(),
            source_key: key.into(),
            namespace: object.namespace.clone(),
            entity_kind: ENTITY_KIND_OBJECT.into(),
            entity_id: object.id.clone(),
            content_hash: object_property_content_hash(key, &text_body),
            text_body,
        })
    }

    /// Convert readable admitted evidence into an indexed document.
    pub(crate) fn evidence(submission: &EvidenceSubmissionRecord) -> Option<Self> {
        if !public_evidence_content_readable(submission.lifecycle_state) {
            return None;
        }
        let envelope = submission.envelope.as_ref()?;
        let text_body = truncate_chars(
            &flatten_json_text(&envelope.content),
            MAX_INDEXED_TEXT_CHARS,
        );
        if text_body.trim().is_empty() {
            return None;
        }
        let content_hash = if submission.content_digest.trim().is_empty() {
            sha256_hex(text_body.as_bytes())
        } else {
            submission.content_digest.clone()
        };
        Some(Self {
            doc_id: format!("evidence:{}", submission.id),
            source_kind: SOURCE_KIND_EVIDENCE.into(),
            source_id: submission.id.clone(),
            source_key: String::new(),
            namespace: submission.namespace.clone(),
            entity_kind: ENTITY_KIND_EVIDENCE_SUBMISSION.into(),
            entity_id: submission.id.clone(),
            content_hash,
            text_body,
        })
    }
}

/// Hash the exact bounded property material used by the authorized adapter.
/// The gRPC live re-check uses this helper so a changed property cannot keep a
/// stale ranked hit alive after the corpus was assembled.
pub(crate) fn object_property_content_hash(key: &str, value: &str) -> String {
    let text_body = truncate_chars(value, MAX_INDEXED_TEXT_CHARS);
    sha256_hex(format!("{key}\0{text_body}").as_bytes())
}

#[derive(Debug, Clone)]
struct IndexedHit {
    doc_id: String,
    source_kind: String,
    source_id: String,
    source_key: String,
    namespace: String,
    entity_kind: String,
    entity_id: String,
    content_hash: String,
    bm25_raw: f64,
}

/// Authorization decision for a candidate source row during re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny,
    Gone,
}

/// Callback used to re-check live authorization for an index hit.
///
/// - `source_kind`: `evidence` or `object_property`
/// - `source_id`: submission id or object id
/// - `entity_kind` / `entity_id`: asserted SoT identifiers
/// - `namespace`: source namespace when known
pub type AuthzRecheck<'a> = dyn Fn(&AuthzRecheckInput<'_>) -> AuthzDecision + 'a;

#[derive(Debug, Clone)]
pub struct AuthzRecheckInput<'a> {
    pub source_kind: &'a str,
    pub source_id: &'a str,
    pub source_key: &'a str,
    pub entity_kind: &'a str,
    pub entity_id: &'a str,
    pub namespace: &'a str,
    pub content_hash: &'a str,
}

impl SekaiDb {
    pub(crate) fn migrate_text_fts(&self) -> Result<(), String> {
        let conn = self.conn();
        migrate_text_fts_on(&conn)
    }

    /// Rebuild the FTS projection from sources of truth. Idempotent.
    pub fn rebuild_text_fts(&self, now_ms: i64) -> Result<String, String> {
        let conn = self.conn();
        rebuild_text_fts_on(&conn, now_ms)
    }

    /// Current index generation (`gen:<n>`), empty when never rebuilt.
    pub fn text_fts_generation(&self) -> Result<String, String> {
        let conn = self.conn();
        meta_get(&conn, META_GENERATION).map(|v| v.unwrap_or_default())
    }

    /// Search the FTS projection and re-check authorization per hit.
    #[allow(dead_code)]
    pub(crate) fn search_text_fts(
        &self,
        query: &TextSearchQuery,
        principal_class: &str,
        authz: &AuthzRecheck<'_>,
    ) -> Result<TextSearchResult, HybridError> {
        let (match_expr, mut generation, max_candidates, namespace_filter, source_kinds) = {
            let conn = self.conn();
            prepare_text_fts_query(&conn, query)?
        };
        let mut generation_restarts = 0_u8;

        'search: loop {
            let mut result = empty_text_fts_result(generation.clone());
            let mut offset = 0_i64;
            loop {
                // Release the pooled connection before rechecking authorization:
                // the callback may query the same database for live ACL state.
                let (page_generation, hits) = {
                    let conn = self.conn();
                    fetch_text_fts_hits(
                        &conn,
                        &match_expr,
                        &namespace_filter,
                        source_kinds,
                        offset,
                        TEXT_FTS_PAGE_SIZE,
                    )?
                };
                if page_generation != generation {
                    generation_restarts = generation_restarts.saturating_add(1);
                    if generation_restarts > MAX_TEXT_FTS_GENERATION_RESTARTS {
                        return Err(HybridError::Storage(
                            "text FTS generation changed during search".into(),
                        ));
                    }
                    generation = page_generation;
                    continue 'search;
                }
                if hits.is_empty() {
                    break;
                }
                let page_len = hits.len() as i64;
                append_text_fts_hits(
                    &mut result,
                    &generation,
                    hits,
                    max_candidates,
                    &namespace_filter,
                    source_kinds,
                    principal_class,
                    authz,
                );
                if result.candidates.len() as u32 >= max_candidates || result.truncated {
                    break;
                }

                offset = offset.saturating_add(page_len);
                if page_len < TEXT_FTS_PAGE_SIZE {
                    break;
                }
            }

            // Authorization callbacks run after the page connection is
            // released. Recheck the generation before returning so a rebuild
            // during those callbacks cannot label a mixed result as complete.
            let final_generation = {
                let conn = self.conn();
                meta_get(&conn, META_GENERATION)
                    .map_err(HybridError::Storage)?
                    .unwrap_or_else(|| "gen:0".into())
            };
            if final_generation != generation {
                generation_restarts = generation_restarts.saturating_add(1);
                if generation_restarts > MAX_TEXT_FTS_GENERATION_RESTARTS {
                    return Err(HybridError::Storage(
                        "text FTS generation changed during search".into(),
                    ));
                }
                generation = final_generation;
                continue 'search;
            }
            break Ok(result);
        }
    }
}

/// Validate a text request without touching the durable corpus.
pub fn validate_text_search_query(query: &TextSearchQuery) -> Result<(), HybridError> {
    let q = query.query.trim();
    if q.is_empty() {
        return Err(HybridError::InvalidArgument(
            "query must be non-empty".into(),
        ));
    }
    if q.chars().count() > MAX_QUERY_CHARS {
        return Err(HybridError::InvalidArgument(format!(
            "query exceeds {MAX_QUERY_CHARS} characters"
        )));
    }
    let namespace = query.namespace.trim();
    if !query.namespace.is_empty() && namespace != query.namespace {
        return Err(HybridError::InvalidArgument(
            "canonical namespace required".into(),
        ));
    }
    let _ = fts_match_expression(q)?;
    Ok(())
}

/// Search a corpus that was assembled after authorization and marking checks.
#[allow(dead_code)]
pub(crate) fn search_authorized_text(
    query: &TextSearchQuery,
    principal_class: &str,
    documents: &[AuthorizedTextDocument],
) -> Result<TextSearchResult, HybridError> {
    let allow_all = |_input: &AuthzRecheckInput<'_>| AuthzDecision::Allow;
    search_authorized_text_with_options(query, principal_class, documents, false, None, &allow_all)
}

/// Search an authorization-built corpus with a shared deadline and a final
/// source-of-truth authorization re-check for every candidate that is about to
/// be emitted.
pub(crate) fn search_authorized_text_with_options(
    query: &TextSearchQuery,
    principal_class: &str,
    documents: &[AuthorizedTextDocument],
    corpus_truncated: bool,
    deadline: Option<std::time::Instant>,
    authz: &AuthzRecheck<'_>,
) -> Result<TextSearchResult, HybridError> {
    validate_text_search_query(query)?;
    let q = query.query.trim();
    let namespace = query.namespace.trim();
    let match_expr = fts_match_expression(q)?;
    let max_candidates = normalize_max_candidates(query.max_candidates) as usize;

    let mut result = TextSearchResult {
        candidates: Vec::new(),
        source_version: AUTHORIZED_TEXT_SOURCE_VERSION.into(),
        representation_id: REPRESENTATION_AUTHORIZED_TEXT.into(),
        truncated: corpus_truncated,
        truncation_reasons: if corpus_truncated {
            vec!["authorized_corpus".into()]
        } else {
            Vec::new()
        },
        denied_count: 0,
        scanned: 0,
    };

    let mut deadline_exceeded = false;
    let mark_deadline = |result: &mut TextSearchResult| {
        result.truncated = true;
        push_reason(&mut result.truncation_reasons, "max_time_ms");
    };
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        mark_deadline(&mut result);
        return Ok(result);
    }

    let authorized = documents
        .iter()
        .filter(|document| {
            query.source_kinds.matches(&document.source_kind)
                && (namespace.is_empty() || document.namespace == namespace)
        })
        .take(MAX_AUTHORIZED_TEXT_DOCUMENTS)
        .collect::<Vec<_>>();
    let filtered_document_count = documents
        .iter()
        .filter(|document| {
            query.source_kinds.matches(&document.source_kind)
                && (namespace.is_empty() || document.namespace == namespace)
        })
        .count();
    if filtered_document_count > MAX_AUTHORIZED_TEXT_DOCUMENTS {
        result.truncated = true;
        push_reason(&mut result.truncation_reasons, "authorized_corpus");
    }

    let conn = Connection::open_in_memory().map_err(|error| {
        HybridError::Storage(format!("authorized text adapter database: {error}"))
    })?;
    conn.execute_batch(
        "CREATE VIRTUAL TABLE authorized_text_fts USING fts5(
            doc_id UNINDEXED,
            source_kind UNINDEXED,
            source_id UNINDEXED,
            source_key UNINDEXED,
            namespace UNINDEXED,
            entity_kind UNINDEXED,
            entity_id UNINDEXED,
            content_hash UNINDEXED,
            text_body,
            tokenize='porter unicode61 remove_diacritics 2'
        );",
    )
    .map_err(|error| HybridError::Storage(error.to_string()))?;
    {
        let mut insert = conn
            .prepare(
                "INSERT INTO authorized_text_fts(
                    doc_id, source_kind, source_id, source_key, namespace,
                    entity_kind, entity_id, content_hash, text_body
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            )
            .map_err(|error| HybridError::Storage(error.to_string()))?;
        for document in authorized {
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                deadline_exceeded = true;
                break;
            }
            insert
                .execute(params![
                    document.doc_id,
                    document.source_kind,
                    document.source_id,
                    document.source_key,
                    document.namespace,
                    document.entity_kind,
                    document.entity_id,
                    document.content_hash,
                    document.text_body,
                ])
                .map_err(|error| HybridError::Storage(error.to_string()))?;
        }
    }

    if deadline_exceeded {
        mark_deadline(&mut result);
    }
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        mark_deadline(&mut result);
    }
    if deadline_exceeded || deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        return Ok(result);
    }

    // Fetch the bounded authorized corpus, not just the first candidate window,
    // so a concurrent revocation can be rechecked without dropping a later
    // authorized hit into a false-empty response.
    let query_limit = MAX_AUTHORIZED_TEXT_DOCUMENTS;
    let mut statement = conn
        .prepare(
            "SELECT doc_id, source_kind, source_id, source_key, namespace,
                    entity_kind, entity_id, content_hash,
                    bm25(authorized_text_fts) AS rank
             FROM authorized_text_fts
             WHERE authorized_text_fts MATCH ?1
             ORDER BY rank, rowid
             LIMIT ?2",
        )
        .map_err(|error| HybridError::Storage(error.to_string()))?;
    let mut rows = statement
        .query(params![match_expr, query_limit as i64])
        .map_err(|error| HybridError::Storage(error.to_string()))?;
    let mut hits = Vec::new();
    loop {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            mark_deadline(&mut result);
            return Ok(result);
        }
        let Some(row) = rows
            .next()
            .map_err(|error| HybridError::Storage(error.to_string()))?
        else {
            break;
        };
        hits.push(IndexedHit {
            doc_id: row
                .get(0)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
            source_kind: row
                .get(1)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
            source_id: row
                .get(2)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
            source_key: row
                .get(3)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
            namespace: row
                .get(4)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
            entity_kind: row
                .get(5)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
            entity_id: row
                .get(6)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
            content_hash: row
                .get(7)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
            bm25_raw: row
                .get(8)
                .map_err(|error| HybridError::Storage(error.to_string()))?,
        });
    }
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        mark_deadline(&mut result);
        return Ok(result);
    }
    let mut authorized_match_count = 0_usize;
    let mut completed_hit_scan = true;
    for hit in hits {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            mark_deadline(&mut result);
            completed_hit_scan = false;
            break;
        }
        let decision = authz(&AuthzRecheckInput {
            source_kind: &hit.source_kind,
            source_id: &hit.source_id,
            source_key: &hit.source_key,
            entity_kind: &hit.entity_kind,
            entity_id: &hit.entity_id,
            namespace: &hit.namespace,
            content_hash: &hit.content_hash,
        });
        if decision != AuthzDecision::Allow {
            continue;
        }
        authorized_match_count = authorized_match_count.saturating_add(1);
        if result.candidates.len() >= max_candidates {
            continue;
        }
        let entity_ref =
            (!hit.entity_kind.is_empty() && !hit.entity_id.is_empty()).then_some(EntityRef {
                kind: hit.entity_kind,
                id: hit.entity_id,
            });
        let candidate = HybridCandidate::authorized_text(
            AUTHORIZED_TEXT_SOURCE_VERSION,
            -hit.bm25_raw,
            entity_ref,
            AuthzContextSummary {
                namespace: hit.namespace,
                principal_class: principal_class.into(),
                classification_ceiling: String::new(),
            },
        );
        debug_assert_eq!(candidate.score_kind, SCORE_KIND_AUTHORIZED_TEXT_BM25_V1);
        debug_assert_eq!(candidate.source, SOURCE_AUTHORIZED_TEXT);
        let _ = hit.doc_id;
        let _ = hit.source_kind;
        let _ = hit.source_id;
        let _ = hit.source_key;
        let _ = hit.content_hash;
        result.candidates.push(candidate);
        result.scanned = result.scanned.saturating_add(1);
    }
    if completed_hit_scan && deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        mark_deadline(&mut result);
        completed_hit_scan = false;
    }
    if completed_hit_scan && authorized_match_count > max_candidates {
        result.truncated = true;
        push_reason(&mut result.truncation_reasons, "max_candidates");
    }
    Ok(result)
}

fn migrate_text_fts_on(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sekai_text_fts_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sekai_text_fts_docs (
            rowid INTEGER PRIMARY KEY,
            doc_id TEXT NOT NULL UNIQUE,
            source_kind TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_key TEXT NOT NULL DEFAULT '',
            namespace TEXT NOT NULL DEFAULT '',
            entity_kind TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            text_body TEXT NOT NULL,
            indexed_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_text_fts_docs_source
            ON sekai_text_fts_docs(source_kind, source_id);
        CREATE INDEX IF NOT EXISTS idx_text_fts_docs_namespace
            ON sekai_text_fts_docs(namespace);
        CREATE INDEX IF NOT EXISTS idx_text_fts_docs_entity
            ON sekai_text_fts_docs(entity_kind, entity_id);",
    )
    .map_err(|e| e.to_string())?;

    let fts_exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='sekai_text_fts'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if !fts_exists {
        conn.execute_batch(
            "CREATE VIRTUAL TABLE sekai_text_fts USING fts5(
                text_body,
                content='sekai_text_fts_docs',
                content_rowid='rowid',
                tokenize='porter unicode61 remove_diacritics 2'
            );",
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn rebuild_text_fts_on(conn: &Connection, now_ms: i64) -> Result<String, String> {
    migrate_text_fts_on(conn)?;

    let mut docs: Vec<DocRow> = Vec::new();
    collect_evidence_docs(conn, now_ms, &mut docs)?;
    collect_object_property_docs(conn, now_ms, &mut docs)?;

    let generation = {
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let prev = tx
            .query_row(
                "SELECT value FROM sekai_text_fts_meta WHERE key = ?1",
                params![META_GENERATION],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .and_then(|value| {
                value
                    .strip_prefix("gen:")
                    .and_then(|number| number.parse::<u64>().ok())
            })
            .unwrap_or(0);
        let generation = format!("gen:{}", prev.saturating_add(1));
        // Replace the external-content FTS projection and publish its new
        // generation in one transaction. Readers either see the old complete
        // corpus or the new complete corpus, never an intermediate one.
        tx.execute_batch(
            "INSERT INTO sekai_text_fts(sekai_text_fts) VALUES('delete-all');
             DELETE FROM sekai_text_fts_docs;",
        )
        .map_err(|e| e.to_string())?;
        for doc in &docs {
            tx.execute(
                "INSERT INTO sekai_text_fts_docs (
                    doc_id, source_kind, source_id, source_key, namespace,
                    entity_kind, entity_id, content_hash, text_body, indexed_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    doc.doc_id,
                    doc.source_kind,
                    doc.source_id,
                    doc.source_key,
                    doc.namespace,
                    doc.entity_kind,
                    doc.entity_id,
                    doc.content_hash,
                    doc.text_body,
                    doc.indexed_at_ms,
                ],
            )
            .map_err(|e| e.to_string())?;
        }
        // Sync FTS external content from docs.
        tx.execute_batch(
            "INSERT INTO sekai_text_fts(rowid, text_body)
             SELECT rowid, text_body FROM sekai_text_fts_docs;",
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO sekai_text_fts_meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![META_GENERATION, generation],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO sekai_text_fts_meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![META_REBUILT_AT_MS, now_ms.to_string()],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO sekai_text_fts_meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![META_CORPUS_PROFILE, CORPUS_PROFILE_V1],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        generation
    };
    Ok(generation)
}

struct DocRow {
    doc_id: String,
    source_kind: String,
    source_id: String,
    source_key: String,
    namespace: String,
    entity_kind: String,
    entity_id: String,
    content_hash: String,
    text_body: String,
    indexed_at_ms: i64,
}

fn collect_evidence_docs(
    conn: &Connection,
    now_ms: i64,
    docs: &mut Vec<DocRow>,
) -> Result<(), String> {
    // Index retained content for states that may still disclose content after
    // authz re-check (mirrors get_evidence_submission_content readability).
    let mut stmt = conn
        .prepare(
            "SELECT id, namespace, lifecycle_state, content_digest, envelope_json
             FROM sekai_evidence_submissions
             WHERE envelope_json IS NOT NULL
               AND lifecycle_state IN ('available','superseded','retracted','stale')",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    for row in rows {
        let (id, namespace, _state, content_digest, envelope_json) =
            row.map_err(|e| e.to_string())?;
        let envelope: Value = serde_json::from_str(&envelope_json).map_err(|e| e.to_string())?;
        let content = envelope.get("content").cloned().unwrap_or(Value::Null);
        let text = flatten_json_text(&content);
        if text.trim().is_empty() {
            continue;
        }
        let text = truncate_chars(&text, MAX_INDEXED_TEXT_CHARS);
        let content_hash = if content_digest.trim().is_empty() {
            sha256_hex(text.as_bytes())
        } else {
            content_digest
        };
        docs.push(DocRow {
            doc_id: format!("evidence:{id}"),
            source_kind: SOURCE_KIND_EVIDENCE.into(),
            source_id: id.clone(),
            source_key: String::new(),
            namespace,
            entity_kind: ENTITY_KIND_EVIDENCE_SUBMISSION.into(),
            entity_id: id,
            content_hash,
            text_body: text,
            indexed_at_ms: now_ms,
        });
    }
    Ok(())
}

fn collect_object_property_docs(
    conn: &Connection,
    now_ms: i64,
    docs: &mut Vec<DocRow>,
) -> Result<(), String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, namespace, properties FROM sekai_objects
             WHERE properties IS NOT NULL AND properties != '' AND properties != '{}'",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    for row in rows {
        let (id, namespace, properties_json) = row.map_err(|e| e.to_string())?;
        let properties: std::collections::HashMap<String, String> =
            serde_json::from_str(&properties_json).map_err(|e| e.to_string())?;
        for (key, value) in properties {
            if key.trim().is_empty() || value.trim().is_empty() {
                continue;
            }
            // Skip internal/system property keys that are not human text.
            if key.starts_with('_') {
                continue;
            }
            let text = truncate_chars(&value, MAX_INDEXED_TEXT_CHARS);
            let content_hash = sha256_hex(format!("{key}\0{text}").as_bytes());
            docs.push(DocRow {
                doc_id: format!("object_prop:{id}:{key}"),
                source_kind: SOURCE_KIND_OBJECT_PROPERTY.into(),
                source_id: id.clone(),
                source_key: key,
                namespace: namespace.clone(),
                entity_kind: ENTITY_KIND_OBJECT.into(),
                entity_id: id.clone(),
                content_hash,
                text_body: text,
                indexed_at_ms: now_ms,
            });
        }
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
#[allow(dead_code)]
fn prepare_text_fts_query(
    conn: &Connection,
    query: &TextSearchQuery,
) -> Result<(String, String, u32, String, TextSourceFilter), HybridError> {
    let q = query.query.trim();
    if q.is_empty() {
        return Err(HybridError::InvalidArgument(
            "query must be non-empty".into(),
        ));
    }
    if q.chars().count() > MAX_QUERY_CHARS {
        return Err(HybridError::InvalidArgument(format!(
            "query exceeds {MAX_QUERY_CHARS} characters"
        )));
    }
    let namespace = query.namespace.trim();
    // Empty namespace means no namespace filter; non-empty must be canonical.
    if !query.namespace.is_empty() && namespace != query.namespace {
        return Err(HybridError::InvalidArgument(
            "canonical namespace required".into(),
        ));
    }

    let max_candidates = normalize_max_candidates(query.max_candidates);

    let generation = meta_get(conn, META_GENERATION)
        .map_err(HybridError::Storage)?
        .unwrap_or_else(|| "gen:0".into());

    let match_expr = fts_match_expression(q)?;
    Ok((
        match_expr,
        generation,
        max_candidates,
        namespace.to_string(),
        query.source_kinds,
    ))
}

#[allow(dead_code)]
fn fetch_text_fts_hits(
    conn: &Connection,
    match_expr: &str,
    namespace: &str,
    source_kinds: TextSourceFilter,
    offset: i64,
    limit: i64,
) -> Result<(String, Vec<IndexedHit>), HybridError> {
    let generation = meta_get(conn, META_GENERATION)
        .map_err(HybridError::Storage)?
        .unwrap_or_else(|| "gen:0".into());
    let mut stmt = conn
        .prepare(
            "SELECT d.doc_id, d.source_kind, d.source_id, d.source_key, d.namespace,
                    d.entity_kind, d.entity_id, d.content_hash, bm25(sekai_text_fts) AS rank
             FROM sekai_text_fts
             JOIN sekai_text_fts_docs AS d ON d.rowid = sekai_text_fts.rowid
             WHERE sekai_text_fts MATCH ?1
               AND (?2 = '' OR d.namespace = ?2)
               AND (
                    ?3 = 'all'
                    OR (?3 = 'evidence' AND d.source_kind = 'evidence')
                    OR (?3 = 'object_props' AND d.source_kind = 'object_property')
               )
             ORDER BY rank, d.rowid
             LIMIT ?4 OFFSET ?5",
        )
        .map_err(|e| HybridError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(
            params![match_expr, namespace, source_kinds.as_str(), limit, offset],
            |row| {
                Ok(IndexedHit {
                    doc_id: row.get(0)?,
                    source_kind: row.get(1)?,
                    source_id: row.get(2)?,
                    source_key: row.get(3)?,
                    namespace: row.get(4)?,
                    entity_kind: row.get(5)?,
                    entity_id: row.get(6)?,
                    content_hash: row.get(7)?,
                    bm25_raw: row.get(8)?,
                })
            },
        )
        .map_err(|e| HybridError::Storage(e.to_string()))?;
    let hits = rows
        .map(|row| row.map_err(|e| HybridError::Storage(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let stable_generation = meta_get(conn, META_GENERATION)
        .map_err(HybridError::Storage)?
        .unwrap_or_else(|| "gen:0".into());
    if generation != stable_generation {
        return Ok((stable_generation, Vec::new()));
    }
    Ok((generation, hits))
}

#[allow(dead_code)]
fn empty_text_fts_result(generation: String) -> TextSearchResult {
    TextSearchResult {
        candidates: Vec::new(),
        source_version: generation,
        representation_id: REPRESENTATION_TEXT_FTS5.into(),
        truncated: false,
        truncation_reasons: Vec::new(),
        denied_count: 0,
        scanned: 0,
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn append_text_fts_hits(
    result: &mut TextSearchResult,
    generation: &str,
    hits: Vec<IndexedHit>,
    max_candidates: u32,
    namespace: &str,
    source_kinds: TextSourceFilter,
    principal_class: &str,
    authz: &AuthzRecheck<'_>,
) {
    for hit in hits {
        if !source_kinds.matches(&hit.source_kind) {
            continue;
        }
        if !namespace.is_empty() && hit.namespace != namespace {
            continue;
        }

        let decision = authz(&AuthzRecheckInput {
            source_kind: &hit.source_kind,
            source_id: &hit.source_id,
            source_key: &hit.source_key,
            entity_kind: &hit.entity_kind,
            entity_id: &hit.entity_id,
            namespace: &hit.namespace,
            content_hash: &hit.content_hash,
        });
        match decision {
            AuthzDecision::Deny | AuthzDecision::Gone => {
                // Stale or denied — omit without disclosing names or a
                // denial count that could be used as an existence oracle.
                continue;
            }
            AuthzDecision::Allow => {}
        }

        // `scanned` is deliberately an authorized-work count.  Counting raw
        // index hits would let hidden rows change a public aggregate.
        result.scanned = result.scanned.saturating_add(1);

        // entity_ref only when SoT already asserts the id (re-check path confirmed).
        let entity_ref = if !hit.entity_kind.is_empty() && !hit.entity_id.is_empty() {
            Some(EntityRef {
                kind: hit.entity_kind.clone(),
                id: hit.entity_id.clone(),
            })
        } else {
            None
        };

        // Score: negate bm25 so higher is better; document under score_kind.
        let score = -hit.bm25_raw;
        let candidate = HybridCandidate::text_fts(
            format!("{}#{}", generation, hit.content_hash),
            score,
            entity_ref,
            AuthzContextSummary {
                namespace: hit.namespace.clone(),
                principal_class: principal_class.into(),
                classification_ceiling: String::new(),
            },
        );
        debug_assert_eq!(candidate.score_kind, SCORE_KIND_TEXT_FTS5_BM25_V1);
        debug_assert_eq!(candidate.source, SOURCE_SQLITE_TEXT_FTS5);
        let _ = hit.doc_id;
        result.candidates.push(candidate);

        if result.candidates.len() as u32 >= max_candidates {
            result.truncated = true;
            push_reason(&mut result.truncation_reasons, "max_candidates");
            break;
        }
    }
}

fn normalize_max_candidates(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_MAX_CANDIDATES
    } else {
        value.min(MAX_CANDIDATES)
    }
}

fn push_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|r| r == reason) {
        reasons.push(reason.into());
    }
}

/// Build a FTS5 MATCH expression from free-form user text.
///
/// Tokens are AND-combined; characters special to FTS5 are stripped so callers
/// cannot inject MATCH operators. Empty-after-sanitize is invalid.
fn fts_match_expression(query: &str) -> Result<String, HybridError> {
    let mut tokens = Vec::new();
    for raw in query.split_whitespace() {
        let cleaned: String = raw
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
            .collect();
        if cleaned.is_empty() {
            continue;
        }
        // Quote tokens to treat them as bare terms without column filters.
        tokens.push(cleaned);
    }
    if tokens.is_empty() {
        return Err(HybridError::InvalidArgument(
            "query must contain at least one alphanumeric token".into(),
        ));
    }
    Ok(tokens.join(" "))
}

fn flatten_json_text(value: &Value) -> String {
    let mut parts = Vec::new();
    collect_strings(value, &mut parts);
    parts.join(" ")
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            if !s.trim().is_empty() {
                out.push(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                if !key.starts_with('_') {
                    out.push(key.clone());
                }
                collect_strings(item, out);
            }
        }
        Value::Number(n) => out.push(n.to_string()),
        Value::Bool(b) => out.push(b.to_string()),
        Value::Null => {}
    }
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    text.chars().take(max_chars).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>, String> {
    conn.query_row(
        "SELECT value FROM sekai_text_fts_meta WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// Helper: re-check evidence content readability against live submission state.
pub fn evidence_content_readable(state: EvidenceLifecycleState) -> bool {
    matches!(
        state,
        EvidenceLifecycleState::Available
            | EvidenceLifecycleState::Superseded
            | EvidenceLifecycleState::Retracted
            | EvidenceLifecycleState::Stale
    )
}

/// Lifecycle states admitted to the public authorization-built text corpus.
/// Retraction and staleness remain readable to some internal maintenance paths,
/// but they are never copied into a caller-visible search corpus.
fn public_evidence_content_readable(state: EvidenceLifecycleState) -> bool {
    matches!(
        state,
        EvidenceLifecycleState::Available | EvidenceLifecycleState::Superseded
    )
}

/// Default object property authz using ACL access predicate.
pub fn object_property_present(db: &SekaiDb, object_id: &str) -> Result<Option<Object>, String> {
    db.get_object(object_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::security::{Grant, Role, SecurityChecker};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn test_db() -> SekaiDb {
        let db = SekaiDb::new(":memory:").expect("open");
        db.migrate_all().expect("migrate");
        db
    }

    fn make_object(id: &str, namespace: &str, props: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            kind: "document".into(),
            name: id.into(),
            namespace: namespace.into(),
            external_id: String::new(),
            properties: props
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect::<HashMap<_, _>>(),
            created: 1,
            updated: 1,
        }
    }

    fn allow_all(_input: &AuthzRecheckInput<'_>) -> AuthzDecision {
        AuthzDecision::Allow
    }

    #[test]
    fn migrate_creates_fts_projection_tables() {
        let db = test_db();
        let conn = db.conn();
        let docs: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='sekai_text_fts_docs'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let fts: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='sekai_text_fts'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(docs, 1);
        assert_eq!(fts, 1);
    }

    #[test]
    fn rebuild_indexes_object_properties_and_query_returns_envelope() {
        let db = test_db();
        db.create_object(&make_object(
            "obj-1",
            "ns-a",
            &[("summary", "quantum lattice anomaly report")],
        ))
        .unwrap();
        db.create_object(&make_object(
            "obj-2",
            "ns-a",
            &[("summary", "unrelated weather forecast")],
        ))
        .unwrap();

        let generation = db.rebuild_text_fts(1_000).unwrap();
        assert!(generation.starts_with("gen:"));
        assert_eq!(db.text_fts_generation().unwrap(), generation);

        let result = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "quantum lattice".into(),
                    namespace: "ns-a".into(),
                    source_kinds: TextSourceFilter::ObjectProperties,
                    max_candidates: 10,
                    max_time_ms: 500,
                },
                "user:alice",
                &allow_all,
            )
            .unwrap();

        assert_eq!(result.representation_id, REPRESENTATION_TEXT_FTS5);
        assert_eq!(result.source_version, generation);
        assert!(!result.candidates.is_empty());
        let top = &result.candidates[0];
        assert_eq!(top.representation_id, REPRESENTATION_TEXT_FTS5);
        assert_eq!(top.source, SOURCE_SQLITE_TEXT_FTS5);
        assert_eq!(top.score_kind, SCORE_KIND_TEXT_FTS5_BM25_V1);
        assert_eq!(
            top.entity_ref.as_ref().map(|e| e.kind.as_str()),
            Some(ENTITY_KIND_OBJECT)
        );
        assert_eq!(
            top.entity_ref.as_ref().map(|e| e.id.as_str()),
            Some("obj-1")
        );
        assert_eq!(top.authz_context.namespace, "ns-a");
        assert_eq!(top.authz_context.principal_class, "user:alice");
        assert!(!top.denied);
        // Higher score is better (negated bm25).
        assert!(top.score.is_finite());
    }

    #[test]
    fn reopen_preserves_index_after_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fts.db");
        let generation = {
            let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
            db.migrate_all().unwrap();
            db.create_object(&make_object(
                "persist-1",
                "ns",
                &[("body", "persistent alpha token zeta")],
            ))
            .unwrap();
            db.rebuild_text_fts(42).unwrap()
        };
        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        db.migrate_all().unwrap();
        assert_eq!(db.text_fts_generation().unwrap(), generation);
        let result = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "alpha zeta".into(),
                    namespace: "ns".into(),
                    source_kinds: TextSourceFilter::All,
                    max_candidates: 5,
                    max_time_ms: 500,
                },
                "user:bob",
                &allow_all,
            )
            .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(
            result.candidates[0]
                .entity_ref
                .as_ref()
                .map(|e| e.id.as_str()),
            Some("persist-1")
        );
    }

    #[test]
    fn authz_recheck_denies_without_disclosing() {
        let db = test_db();
        db.create_object(&make_object(
            "secret",
            "ns",
            &[("notes", "classified constellation brief")],
        ))
        .unwrap();
        db.create_object(&make_object(
            "public",
            "ns",
            &[("notes", "public constellation brief")],
        ))
        .unwrap();
        db.rebuild_text_fts(1).unwrap();

        let security = SecurityChecker::new();
        security.add_grant(&Grant {
            id: "g1".into(),
            object_id: "public".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 1,
        });
        // secret has ACL with only "admin" — alice denied (need grant presence).
        security.add_grant(&Grant {
            id: "g2".into(),
            object_id: "secret".into(),
            principal: "admin".into(),
            role: Role::Viewer,
            created: 1,
        });

        let principals = Arc::new(vec!["alice".to_string()]);
        let security = Arc::new(security);
        let authz = move |input: &AuthzRecheckInput<'_>| {
            if input.source_kind != SOURCE_KIND_OBJECT_PROPERTY {
                return AuthzDecision::Gone;
            }
            let refs: Vec<&str> = principals.iter().map(String::as_str).collect();
            if security.can_access(input.entity_id, &refs) {
                AuthzDecision::Allow
            } else {
                AuthzDecision::Deny
            }
        };

        let result = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "constellation".into(),
                    namespace: "ns".into(),
                    source_kinds: TextSourceFilter::ObjectProperties,
                    max_candidates: 10,
                    max_time_ms: 500,
                },
                "user:alice",
                &authz,
            )
            .unwrap();

        assert_eq!(result.candidates.len(), 1);
        assert_eq!(
            result.candidates[0]
                .entity_ref
                .as_ref()
                .map(|e| e.id.as_str()),
            Some("public")
        );
        assert_eq!(result.denied_count, 0);
        // No secret names in truncation reasons.
        for reason in &result.truncation_reasons {
            assert!(!reason.contains("secret"));
        }
    }

    #[test]
    fn paged_authz_recheck_reaches_allowed_hit_beyond_initial_window() {
        let db = test_db();
        // Insert more denied rows than the old 4 * max_candidates window.  A
        // later authorized row must still be returned after page-by-page
        // authorization filtering.
        for i in 0..70 {
            db.create_object(&make_object(
                &format!("hidden-{i}"),
                "ns",
                &[("body", "shared paging token")],
            ))
            .unwrap();
        }
        db.create_object(&make_object(
            "visible-after-hidden",
            "ns",
            &[("body", "shared paging token")],
        ))
        .unwrap();
        db.rebuild_text_fts(1).unwrap();

        let result = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "shared paging".into(),
                    namespace: "ns".into(),
                    source_kinds: TextSourceFilter::ObjectProperties,
                    max_candidates: 1,
                    max_time_ms: 500,
                },
                "user:alice",
                &|input: &AuthzRecheckInput<'_>| {
                    if input.entity_id == "visible-after-hidden" {
                        AuthzDecision::Allow
                    } else {
                        AuthzDecision::Deny
                    }
                },
            )
            .unwrap();

        assert_eq!(result.candidates.len(), 1);
        assert_eq!(
            result.candidates[0]
                .entity_ref
                .as_ref()
                .map(|entity| entity.id.as_str()),
            Some("visible-after-hidden")
        );
        assert_eq!(result.scanned, 1);
        assert_eq!(result.denied_count, 0);
    }

    #[test]
    fn deleted_source_disappears_on_recheck_and_rebuild() {
        let db = test_db();
        db.create_object(&make_object(
            "ephemeral",
            "ns",
            &[("body", "vanishing nebula signal")],
        ))
        .unwrap();
        db.rebuild_text_fts(1).unwrap();

        let allowed = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "nebula".into(),
                    namespace: "ns".into(),
                    source_kinds: TextSourceFilter::All,
                    max_candidates: 5,
                    max_time_ms: 500,
                },
                "user:x",
                &allow_all,
            )
            .unwrap();
        assert_eq!(allowed.candidates.len(), 1);

        // Delete source of truth; re-check reports Gone.
        {
            let conn = db.conn();
            conn.execute(
                "DELETE FROM sekai_objects WHERE id = ?1",
                params!["ephemeral"],
            )
            .unwrap();
        }

        let after_delete = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "nebula".into(),
                    namespace: "ns".into(),
                    source_kinds: TextSourceFilter::All,
                    max_candidates: 5,
                    max_time_ms: 500,
                },
                "user:x",
                &|input: &AuthzRecheckInput<'_>| {
                    if db.get_object(input.entity_id).ok().flatten().is_some() {
                        AuthzDecision::Allow
                    } else {
                        AuthzDecision::Gone
                    }
                },
            )
            .unwrap();
        assert!(after_delete.candidates.is_empty());
        assert_eq!(after_delete.denied_count, 0);

        // Rebuild removes the stale row entirely.
        db.rebuild_text_fts(2).unwrap();
        let after_rebuild = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "nebula".into(),
                    namespace: "ns".into(),
                    source_kinds: TextSourceFilter::All,
                    max_candidates: 5,
                    max_time_ms: 500,
                },
                "user:x",
                &allow_all,
            )
            .unwrap();
        assert!(after_rebuild.candidates.is_empty());
        assert_eq!(after_rebuild.scanned, 0);
    }

    #[test]
    fn empty_and_invalid_query_rejected() {
        let db = test_db();
        db.rebuild_text_fts(1).unwrap();
        let err = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "   ".into(),
                    namespace: String::new(),
                    source_kinds: TextSourceFilter::All,
                    max_candidates: 0,
                    max_time_ms: 0,
                },
                "user:x",
                &allow_all,
            )
            .unwrap_err();
        assert!(matches!(err, HybridError::InvalidArgument(_)));

        let err = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "!!! ???".into(),
                    namespace: String::new(),
                    source_kinds: TextSourceFilter::All,
                    max_candidates: 0,
                    max_time_ms: 0,
                },
                "user:x",
                &allow_all,
            )
            .unwrap_err();
        assert!(matches!(err, HybridError::InvalidArgument(_)));

        let err = TextSourceFilter::parse("vector").unwrap_err();
        assert!(matches!(err, HybridError::InvalidArgument(_)));
    }

    #[test]
    fn similarity_does_not_mint_identity_without_sot() {
        // Candidate entity_ref is only set from asserted entity_id fields, never
        // synthesized from the query string.
        let db = test_db();
        db.create_object(&make_object(
            "known-id",
            "ns",
            &[("body", "mint never happens from query alone")],
        ))
        .unwrap();
        db.rebuild_text_fts(1).unwrap();
        let result = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "mint never".into(),
                    namespace: "ns".into(),
                    source_kinds: TextSourceFilter::All,
                    max_candidates: 5,
                    max_time_ms: 500,
                },
                "user:x",
                &allow_all,
            )
            .unwrap();
        for candidate in result.candidates {
            let entity = candidate.entity_ref.expect("SoT id present");
            assert_eq!(entity.id, "known-id");
            assert_ne!(entity.id, "mint");
            assert_eq!(entity.kind, ENTITY_KIND_OBJECT);
        }
    }

    #[test]
    fn max_candidates_bounds_and_truncates() {
        let db = test_db();
        for i in 0..10 {
            db.create_object(&make_object(
                &format!("o{i}"),
                "ns",
                &[("body", "shared keyword payload")],
            ))
            .unwrap();
        }
        db.rebuild_text_fts(1).unwrap();
        let result = db
            .search_text_fts(
                &TextSearchQuery {
                    query: "shared keyword".into(),
                    namespace: "ns".into(),
                    source_kinds: TextSourceFilter::All,
                    max_candidates: 3,
                    max_time_ms: 500,
                },
                "user:x",
                &allow_all,
            )
            .unwrap();
        assert_eq!(result.candidates.len(), 3);
        assert!(result.truncated);
        assert!(
            result
                .truncation_reasons
                .iter()
                .any(|r| r == "max_candidates")
        );
    }

    #[test]
    fn authorized_adapter_ranks_only_the_prechecked_corpus() {
        let visible = make_object(
            "authorized",
            "ns",
            &[("body", "shared authorization token")],
        );
        let hidden = make_object(
            "hidden",
            "ns",
            &[("body", "shared authorization token"), ("rank", "hidden")],
        );
        let documents = [
            AuthorizedTextDocument::object_property(&visible, "body", "shared authorization token")
                .unwrap(),
            // The caller's source-of-truth authorization layer simply does not
            // pass the hidden row to this adapter.
            AuthorizedTextDocument::object_property(&hidden, "body", "shared authorization token")
                .unwrap(),
        ];
        let result = search_authorized_text(
            &TextSearchQuery {
                query: "shared authorization".into(),
                namespace: "ns".into(),
                source_kinds: TextSourceFilter::ObjectProperties,
                max_candidates: 1,
                max_time_ms: 1,
            },
            "user:alice",
            &documents[..1],
        )
        .unwrap();
        assert_eq!(result.source_version, AUTHORIZED_TEXT_SOURCE_VERSION);
        assert_eq!(result.representation_id, REPRESENTATION_AUTHORIZED_TEXT);
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(
            result.candidates[0]
                .entity_ref
                .as_ref()
                .map(|entity| entity.id.as_str()),
            Some("authorized")
        );
        assert_eq!(result.denied_count, 0);
        assert_eq!(result.scanned, 1);
        assert!(!format!("{result:?}").contains("hidden"));
    }

    #[test]
    fn authorized_adapter_does_not_truncate_on_denied_tail() {
        let first = make_object("first", "ns", &[("body", "shared race token")]);
        let second = make_object("second", "ns", &[("body", "shared race token")]);
        let documents = [
            AuthorizedTextDocument::object_property(&first, "body", "shared race token").unwrap(),
            AuthorizedTextDocument::object_property(&second, "body", "shared race token").unwrap(),
        ];
        let result = search_authorized_text_with_options(
            &TextSearchQuery {
                query: "shared race".into(),
                namespace: "ns".into(),
                source_kinds: TextSourceFilter::ObjectProperties,
                max_candidates: 1,
                max_time_ms: 500,
            },
            "user:alice",
            &documents,
            false,
            None,
            &|input: &AuthzRecheckInput<'_>| {
                if input.source_id == "first" {
                    AuthzDecision::Allow
                } else {
                    AuthzDecision::Deny
                }
            },
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert!(!result.truncated);
        assert!(
            !result
                .truncation_reasons
                .iter()
                .any(|reason| reason == "max_candidates")
        );
    }

    #[test]
    fn evidence_lifecycle_gate_matches_content_read_path() {
        assert!(evidence_content_readable(EvidenceLifecycleState::Available));
        assert!(evidence_content_readable(EvidenceLifecycleState::Stale));
        assert!(!evidence_content_readable(EvidenceLifecycleState::Rejected));
        assert!(!evidence_content_readable(
            EvidenceLifecycleState::Quarantined
        ));
        assert!(!evidence_content_readable(EvidenceLifecycleState::Received));
    }
}
