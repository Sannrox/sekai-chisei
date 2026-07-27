//! Shared hybrid retrieval candidate envelope and late-fusion plan
//! (#360 / #361 / research #152).
//!
//! Cross-representation ranking needs a stable contract so scores are never
//! silently compared across kinds. Callers select representations explicitly
//! and name a versioned fusion profile when more than one adapter runs.
//! Similarity never mints durable identities; partial adapter failure is
//! first-class via per-adapter status.

use std::cmp::Ordering;
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
/// Source identity for graph retrieve-context candidates.
pub const SOURCE_GRAPH_RETRIEVE_CONTEXT: &str = "sekai.retrieve_context";

/// Reciprocal rank fusion (k=60). Scores are not comparable across kinds;
/// only ranks within each adapter list contribute.
pub const FUSION_PROFILE_RRF_V1: &str = "late_fusion.rrf/v1";
/// Graph candidates first (adapter order), then remaining representations.
pub const FUSION_PROFILE_GRAPH_PRIORITY_V1: &str = "late_fusion.graph_priority/v1";
/// Single-representation pass-through (recorded when fusion is not required).
pub const FUSION_PROFILE_IDENTITY_V1: &str = "late_fusion.identity/v1";

/// Classic RRF constant; fixture-pinned so profile changes stay testable.
pub const RRF_K: f64 = 60.0;

pub const DEFAULT_MAX_HYBRID_CANDIDATES: u32 = 40;
pub const MAX_HYBRID_CANDIDATES: u32 = 200;
pub const DEFAULT_MAX_PER_REPRESENTATION: u32 = 20;
pub const MAX_PER_REPRESENTATION: u32 = 100;
pub const DEFAULT_MAX_TIME_MS: u32 = 100;
pub const MAX_TIME_MS: u32 = 1000;

/// Per-adapter status values (wire strings).
pub const ADAPTER_STATUS_OK: &str = "ok";
pub const ADAPTER_STATUS_TRUNCATED: &str = "truncated";
pub const ADAPTER_STATUS_DENIED_EMPTY: &str = "denied_empty";
pub const ADAPTER_STATUS_ERROR: &str = "error";

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

    /// Build a graph retrieve-context candidate from an affinity score.
    pub fn graph_context(
        source_version: impl Into<String>,
        score: f64,
        entity_ref: Option<EntityRef>,
        authz: AuthzContextSummary,
    ) -> Self {
        Self {
            representation_id: REPRESENTATION_GRAPH_RETRIEVE_CONTEXT.into(),
            source: SOURCE_GRAPH_RETRIEVE_CONTEXT.into(),
            source_version: source_version.into(),
            score,
            score_kind: SCORE_KIND_GRAPH_CONTEXT_AFFINITY_V1.into(),
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

/// Registered late-fusion profile ids (additive only; rename requires a new version).
pub fn known_fusion_profiles() -> &'static [&'static str] {
    &[
        FUSION_PROFILE_RRF_V1,
        FUSION_PROFILE_GRAPH_PRIORITY_V1,
        FUSION_PROFILE_IDENTITY_V1,
    ]
}

/// Versioned late-fusion profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusionProfile {
    /// Reciprocal rank fusion across adapter ranks (`late_fusion.rrf/v1`).
    RrfV1,
    /// Graph candidates first, then other representations.
    GraphPriorityV1,
    /// Preserve adapter selection order without cross-adapter reordering.
    IdentityV1,
}

impl FusionProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RrfV1 => FUSION_PROFILE_RRF_V1,
            Self::GraphPriorityV1 => FUSION_PROFILE_GRAPH_PRIORITY_V1,
            Self::IdentityV1 => FUSION_PROFILE_IDENTITY_V1,
        }
    }

    pub fn parse(value: &str) -> Result<Self, HybridError> {
        match value.trim() {
            FUSION_PROFILE_RRF_V1 => Ok(Self::RrfV1),
            FUSION_PROFILE_GRAPH_PRIORITY_V1 => Ok(Self::GraphPriorityV1),
            FUSION_PROFILE_IDENTITY_V1 => Ok(Self::IdentityV1),
            "" => Err(HybridError::InvalidArgument(
                "fusion_profile is required when multiple representations are selected".into(),
            )),
            other => Err(HybridError::InvalidArgument(format!(
                "unknown fusion_profile {other:?}; expected one of {}",
                known_fusion_profiles().join(", ")
            ))),
        }
    }
}

/// Per-adapter outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterStatus {
    Ok,
    Truncated,
    DeniedEmpty,
    Error,
}

impl AdapterStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => ADAPTER_STATUS_OK,
            Self::Truncated => ADAPTER_STATUS_TRUNCATED,
            Self::DeniedEmpty => ADAPTER_STATUS_DENIED_EMPTY,
            Self::Error => ADAPTER_STATUS_ERROR,
        }
    }

    pub fn parse(value: &str) -> Result<Self, HybridError> {
        match value.trim() {
            ADAPTER_STATUS_OK => Ok(Self::Ok),
            ADAPTER_STATUS_TRUNCATED => Ok(Self::Truncated),
            ADAPTER_STATUS_DENIED_EMPTY => Ok(Self::DeniedEmpty),
            ADAPTER_STATUS_ERROR => Ok(Self::Error),
            other => Err(HybridError::InvalidArgument(format!(
                "unknown adapter status {other:?}"
            ))),
        }
    }
}

/// One adapter's contribution to a hybrid plan (before/after fusion).
#[derive(Debug, Clone, PartialEq)]
pub struct AdapterResult {
    pub representation_id: String,
    pub status: AdapterStatus,
    pub candidates: Vec<HybridCandidate>,
    pub truncation_reasons: Vec<String>,
    pub denied_count: u32,
    /// Stable code when status is Error (never includes hidden names).
    pub error_code: String,
    /// Non-sensitive message; never includes hidden object names.
    pub error_message: String,
}

impl AdapterResult {
    pub fn ok(representation_id: impl Into<String>, candidates: Vec<HybridCandidate>) -> Self {
        Self {
            representation_id: representation_id.into(),
            status: AdapterStatus::Ok,
            candidates,
            truncation_reasons: Vec::new(),
            denied_count: 0,
            error_code: String::new(),
            error_message: String::new(),
        }
    }

    pub fn truncated(
        representation_id: impl Into<String>,
        candidates: Vec<HybridCandidate>,
        reasons: Vec<String>,
    ) -> Self {
        Self {
            representation_id: representation_id.into(),
            status: AdapterStatus::Truncated,
            candidates,
            truncation_reasons: reasons,
            denied_count: 0,
            error_code: String::new(),
            error_message: String::new(),
        }
    }

    pub fn denied_empty(representation_id: impl Into<String>, denied_count: u32) -> Self {
        Self {
            representation_id: representation_id.into(),
            status: AdapterStatus::DeniedEmpty,
            candidates: Vec::new(),
            truncation_reasons: Vec::new(),
            denied_count,
            error_code: String::new(),
            error_message: String::new(),
        }
    }

    pub fn error(
        representation_id: impl Into<String>,
        error_code: impl Into<String>,
        error_message: impl Into<String>,
    ) -> Self {
        Self {
            representation_id: representation_id.into(),
            status: AdapterStatus::Error,
            candidates: Vec::new(),
            truncation_reasons: Vec::new(),
            denied_count: 0,
            error_code: error_code.into(),
            error_message: error_message.into(),
        }
    }
}

/// Result of late fusion over adapter results.
#[derive(Debug, Clone, PartialEq)]
pub struct FusedResult {
    pub candidates: Vec<HybridCandidate>,
    pub fusion_profile: String,
    pub truncated: bool,
    pub truncation_reasons: Vec<String>,
}

/// Parse and validate a representation id against the registry.
pub fn parse_representation_id(value: &str) -> Result<&'static str, HybridError> {
    let trimmed = value.trim();
    for known in known_representation_ids() {
        if *known == trimmed {
            return Ok(*known);
        }
    }
    Err(HybridError::InvalidArgument(format!(
        "unknown representation {trimmed:?}; expected one of {}",
        known_representation_ids().join(", ")
    )))
}

/// Validate explicit representation selection for a hybrid plan.
///
/// Empty selection is invalid. Duplicates are rejected. Unknown ids are rejected.
pub fn normalize_representations(values: &[String]) -> Result<Vec<&'static str>, HybridError> {
    if values.is_empty() {
        return Err(HybridError::InvalidArgument(
            "representations must be non-empty; pure graph callers should use RetrieveContext"
                .into(),
        ));
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        let id = parse_representation_id(value)?;
        if out.contains(&id) {
            return Err(HybridError::InvalidArgument(format!(
                "duplicate representation {id:?}"
            )));
        }
        out.push(id);
    }
    Ok(out)
}

/// Resolve the fusion profile for a hybrid request.
///
/// Multi-representation requests require an explicit profile. Single-
/// representation requests default to identity when the field is empty.
pub fn resolve_fusion_profile(
    raw: &str,
    representation_count: usize,
) -> Result<FusionProfile, HybridError> {
    let trimmed = raw.trim();
    if representation_count > 1 {
        return FusionProfile::parse(trimmed);
    }
    if trimmed.is_empty() {
        return Ok(FusionProfile::IdentityV1);
    }
    FusionProfile::parse(trimmed)
}

pub fn normalize_max_candidates(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_MAX_HYBRID_CANDIDATES
    } else {
        value.min(MAX_HYBRID_CANDIDATES)
    }
}

pub fn normalize_max_per_representation(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_MAX_PER_REPRESENTATION
    } else {
        value.min(MAX_PER_REPRESENTATION)
    }
}

pub fn normalize_max_time_ms(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_MAX_TIME_MS
    } else {
        value.min(MAX_TIME_MS)
    }
}

/// Cap candidates contributed by one adapter to `max_per_representation`.
pub fn apply_max_per_representation(
    mut result: AdapterResult,
    max_per_representation: u32,
) -> AdapterResult {
    let cap = normalize_max_per_representation(max_per_representation) as usize;
    if result.candidates.len() > cap {
        result.candidates.truncate(cap);
        push_reason(&mut result.truncation_reasons, "max_per_representation");
        if result.status == AdapterStatus::Ok {
            result.status = AdapterStatus::Truncated;
        }
    }
    result
}

/// Late-fuse adapter results under a versioned profile.
///
/// Candidates keep their representation and score_kind; fusion only defines
/// order. Adapters in `error` or `denied_empty` contribute no candidates but
/// remain visible via `adapter_results` on the wire response. Identity is never
/// reconciled across distinct entity refs.
pub fn late_fuse(
    profile: FusionProfile,
    adapter_results: &[AdapterResult],
    max_candidates: u32,
) -> FusedResult {
    let max_candidates = normalize_max_candidates(max_candidates) as usize;
    let mut fused = match profile {
        FusionProfile::RrfV1 => fuse_rrf(adapter_results),
        FusionProfile::GraphPriorityV1 => fuse_graph_priority(adapter_results),
        FusionProfile::IdentityV1 => fuse_identity(adapter_results),
    };

    let mut truncated = false;
    let mut truncation_reasons = Vec::new();
    if fused.len() > max_candidates {
        fused.truncate(max_candidates);
        truncated = true;
        push_reason(&mut truncation_reasons, "max_candidates");
    }
    // Surface adapter-level truncation on the overall response without dropping
    // healthy adapter candidates.
    for adapter in adapter_results {
        if adapter.status == AdapterStatus::Truncated {
            truncated = true;
            for reason in &adapter.truncation_reasons {
                push_reason(&mut truncation_reasons, reason);
            }
        }
    }

    FusedResult {
        candidates: fused,
        fusion_profile: profile.as_str().into(),
        truncated,
        truncation_reasons,
    }
}

fn fuse_identity(adapter_results: &[AdapterResult]) -> Vec<HybridCandidate> {
    let mut out = Vec::new();
    for adapter in adapter_results {
        if !adapter_contributes(adapter) {
            continue;
        }
        out.extend(adapter.candidates.iter().cloned());
    }
    out
}

fn fuse_graph_priority(adapter_results: &[AdapterResult]) -> Vec<HybridCandidate> {
    let mut graph = Vec::new();
    let mut rest = Vec::new();
    for adapter in adapter_results {
        if !adapter_contributes(adapter) {
            continue;
        }
        if adapter.representation_id == REPRESENTATION_GRAPH_RETRIEVE_CONTEXT {
            graph.extend(adapter.candidates.iter().cloned());
        } else {
            rest.extend(adapter.candidates.iter().cloned());
        }
    }
    graph.extend(rest);
    graph
}

fn fuse_rrf(adapter_results: &[AdapterResult]) -> Vec<HybridCandidate> {
    // Rank is 1-based within each contributing adapter list. Candidates are
    // kept distinct (no identity merge); RRF only assigns an order score.
    #[derive(Clone)]
    struct Ranked {
        candidate: HybridCandidate,
        rrf: f64,
        adapter_order: usize,
        rank: usize,
    }

    let mut ranked = Vec::new();
    for (adapter_order, adapter) in adapter_results.iter().enumerate() {
        if !adapter_contributes(adapter) {
            continue;
        }
        for (idx, candidate) in adapter.candidates.iter().enumerate() {
            let rank = idx + 1;
            let rrf = 1.0 / (RRF_K + rank as f64);
            ranked.push(Ranked {
                candidate: candidate.clone(),
                rrf,
                adapter_order,
                rank,
            });
        }
    }

    ranked.sort_by(|a, b| {
        // Higher RRF first.
        match b.rrf.partial_cmp(&a.rrf).unwrap_or(Ordering::Equal) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
        // Prefer graph representation on pure RRF ties for stability.
        let a_graph =
            (a.candidate.representation_id == REPRESENTATION_GRAPH_RETRIEVE_CONTEXT) as u8;
        let b_graph =
            (b.candidate.representation_id == REPRESENTATION_GRAPH_RETRIEVE_CONTEXT) as u8;
        match b_graph.cmp(&a_graph) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
        match a.adapter_order.cmp(&b.adapter_order) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
        match a.rank.cmp(&b.rank) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
        // Final deterministic tie-breakers.
        match a
            .candidate
            .representation_id
            .cmp(&b.candidate.representation_id)
        {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
        let a_entity = a
            .candidate
            .entity_ref
            .as_ref()
            .map(|e| (e.kind.as_str(), e.id.as_str()))
            .unwrap_or(("", ""));
        let b_entity = b
            .candidate
            .entity_ref
            .as_ref()
            .map(|e| (e.kind.as_str(), e.id.as_str()))
            .unwrap_or(("", ""));
        match a_entity.cmp(&b_entity) {
            Ordering::Equal => a.candidate.source_version.cmp(&b.candidate.source_version),
            non_eq => non_eq,
        }
    });

    ranked.into_iter().map(|r| r.candidate).collect()
}

fn adapter_contributes(adapter: &AdapterResult) -> bool {
    matches!(adapter.status, AdapterStatus::Ok | AdapterStatus::Truncated)
        && !adapter.candidates.is_empty()
}

fn push_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|r| r == reason) {
        reasons.push(reason.into());
    }
}

/// Derive adapter status from candidate/denial/truncation counters.
pub fn status_from_adapter_outcome(
    candidates: usize,
    denied_count: u32,
    truncated: bool,
) -> AdapterStatus {
    if truncated {
        AdapterStatus::Truncated
    } else if candidates == 0 && denied_count > 0 {
        AdapterStatus::DeniedEmpty
    } else {
        AdapterStatus::Ok
    }
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

    fn authz(ns: &str) -> AuthzContextSummary {
        AuthzContextSummary {
            namespace: ns.into(),
            principal_class: "user:alice".into(),
            classification_ceiling: String::new(),
        }
    }

    fn graph_cand(id: &str, score: f64) -> HybridCandidate {
        HybridCandidate::graph_context(
            "rev:1",
            score,
            Some(EntityRef {
                kind: ENTITY_KIND_OBJECT.into(),
                id: id.into(),
            }),
            authz("ns"),
        )
    }

    fn text_cand(id: &str, score: f64) -> HybridCandidate {
        HybridCandidate::text_fts(
            "gen:1",
            score,
            Some(EntityRef {
                kind: ENTITY_KIND_OBJECT.into(),
                id: id.into(),
            }),
            authz("ns"),
        )
    }

    #[test]
    fn score_kinds_are_versioned_and_distinct() {
        assert!(SCORE_KIND_TEXT_FTS5_BM25_V1.ends_with("/v1"));
        assert_ne!(
            SCORE_KIND_GRAPH_CONTEXT_AFFINITY_V1,
            SCORE_KIND_TEXT_FTS5_BM25_V1
        );
        assert!(known_score_kinds().contains(&SCORE_KIND_TEXT_FTS5_BM25_V1));
        assert!(known_representation_ids().contains(&REPRESENTATION_TEXT_FTS5));
        assert!(known_fusion_profiles().contains(&FUSION_PROFILE_RRF_V1));
        assert!(known_fusion_profiles().contains(&FUSION_PROFILE_GRAPH_PRIORITY_V1));
    }

    #[test]
    fn text_candidate_never_requires_entity_ref() {
        let candidate = HybridCandidate::text_fts("gen:1", 1.5, None, authz("ns"));
        assert_eq!(candidate.representation_id, REPRESENTATION_TEXT_FTS5);
        assert_eq!(candidate.score_kind, SCORE_KIND_TEXT_FTS5_BM25_V1);
        assert!(candidate.entity_ref.is_none());
        assert!(!candidate.denied);
    }

    #[test]
    fn empty_representation_selection_is_rejected() {
        let err = normalize_representations(&[]).unwrap_err();
        assert!(matches!(err, HybridError::InvalidArgument(_)));
    }

    #[test]
    fn multi_representation_requires_fusion_profile() {
        let err = resolve_fusion_profile("", 2).unwrap_err();
        assert!(matches!(err, HybridError::InvalidArgument(_)));
        assert_eq!(
            resolve_fusion_profile("", 1).unwrap(),
            FusionProfile::IdentityV1
        );
    }

    #[test]
    fn graph_priority_orders_graph_before_text() {
        let adapters = vec![
            AdapterResult::ok(
                REPRESENTATION_TEXT_FTS5,
                vec![text_cand("t1", 9.0), text_cand("t2", 8.0)],
            ),
            AdapterResult::ok(
                REPRESENTATION_GRAPH_RETRIEVE_CONTEXT,
                vec![graph_cand("g1", 1.0), graph_cand("g2", 0.5)],
            ),
        ];
        let fused = late_fuse(FusionProfile::GraphPriorityV1, &adapters, 10);
        assert_eq!(fused.fusion_profile, FUSION_PROFILE_GRAPH_PRIORITY_V1);
        let ids: Vec<_> = fused
            .candidates
            .iter()
            .map(|c| {
                (
                    c.representation_id.as_str(),
                    c.entity_ref.as_ref().map(|e| e.id.as_str()).unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            ids,
            vec![
                (REPRESENTATION_GRAPH_RETRIEVE_CONTEXT, "g1"),
                (REPRESENTATION_GRAPH_RETRIEVE_CONTEXT, "g2"),
                (REPRESENTATION_TEXT_FTS5, "t1"),
                (REPRESENTATION_TEXT_FTS5, "t2"),
            ]
        );
        // Scores and score_kinds preserved; no silent cross-kind comparison.
        assert_eq!(
            fused.candidates[0].score_kind,
            SCORE_KIND_GRAPH_CONTEXT_AFFINITY_V1
        );
        assert_eq!(fused.candidates[2].score_kind, SCORE_KIND_TEXT_FTS5_BM25_V1);
    }

    #[test]
    fn rrf_profile_pins_order_by_rank_not_raw_score() {
        // Text has higher raw scores, but RRF uses ranks only. First ranks from
        // both lists share the same RRF contribution; graph wins the fixture
        // tie-break, then text first, then second ranks similarly.
        let adapters = vec![
            AdapterResult::ok(
                REPRESENTATION_GRAPH_RETRIEVE_CONTEXT,
                vec![graph_cand("g1", 0.1), graph_cand("g2", 0.05)],
            ),
            AdapterResult::ok(
                REPRESENTATION_TEXT_FTS5,
                vec![text_cand("t1", 100.0), text_cand("t2", 99.0)],
            ),
        ];
        let fused = late_fuse(FusionProfile::RrfV1, &adapters, 10);
        assert_eq!(fused.fusion_profile, FUSION_PROFILE_RRF_V1);
        let ids: Vec<_> = fused
            .candidates
            .iter()
            .map(|c| c.entity_ref.as_ref().map(|e| e.id.as_str()).unwrap_or(""))
            .collect();
        // rank-1 RRF equal for g1 and t1; graph preferred on tie → g1, t1
        // rank-2 equal for g2 and t2 → g2, t2
        assert_eq!(ids, vec!["g1", "t1", "g2", "t2"]);
    }

    #[test]
    fn fusion_profile_versions_are_additive_and_testable() {
        let adapters = vec![
            AdapterResult::ok(REPRESENTATION_TEXT_FTS5, vec![text_cand("t1", 5.0)]),
            AdapterResult::ok(
                REPRESENTATION_GRAPH_RETRIEVE_CONTEXT,
                vec![graph_cand("g1", 1.0)],
            ),
        ];
        let rrf = late_fuse(FusionProfile::RrfV1, &adapters, 10);
        let gp = late_fuse(FusionProfile::GraphPriorityV1, &adapters, 10);
        assert_ne!(rrf.fusion_profile, gp.fusion_profile);
        assert_eq!(
            rrf.candidates[0].entity_ref.as_ref().map(|e| e.id.as_str()),
            Some("g1")
        );
        assert_eq!(
            gp.candidates[0].entity_ref.as_ref().map(|e| e.id.as_str()),
            Some("g1")
        );
        assert_eq!(
            gp.candidates[0].representation_id,
            REPRESENTATION_GRAPH_RETRIEVE_CONTEXT
        );
        // Both profiles keep mixed representations and score kinds.
        assert!(
            rrf.candidates
                .iter()
                .any(|c| c.representation_id == REPRESENTATION_TEXT_FTS5)
        );
        assert!(
            gp.candidates
                .iter()
                .any(|c| c.representation_id == REPRESENTATION_TEXT_FTS5)
        );
    }

    #[test]
    fn partial_adapter_failure_does_not_drop_other_candidates() {
        let adapters = vec![
            AdapterResult::ok(
                REPRESENTATION_GRAPH_RETRIEVE_CONTEXT,
                vec![graph_cand("g1", 1.0)],
            ),
            AdapterResult::error(
                REPRESENTATION_TEXT_FTS5,
                "invalid_argument",
                "query must be non-empty",
            ),
        ];
        let fused = late_fuse(FusionProfile::RrfV1, &adapters, 10);
        assert_eq!(fused.candidates.len(), 1);
        assert_eq!(
            fused.candidates[0]
                .entity_ref
                .as_ref()
                .map(|e| e.id.as_str()),
            Some("g1")
        );
        assert_eq!(adapters[1].status, AdapterStatus::Error);
        assert!(adapters[1].error_message.contains("query"));
        assert!(!adapters[1].error_message.contains("secret"));
    }

    #[test]
    fn max_per_representation_truncates_with_reason() {
        let many: Vec<_> = (0..5).map(|i| graph_cand(&format!("g{i}"), 1.0)).collect();
        let result = apply_max_per_representation(
            AdapterResult::ok(REPRESENTATION_GRAPH_RETRIEVE_CONTEXT, many),
            2,
        );
        assert_eq!(result.candidates.len(), 2);
        assert_eq!(result.status, AdapterStatus::Truncated);
        assert!(
            result
                .truncation_reasons
                .iter()
                .any(|r| r == "max_per_representation")
        );
    }

    #[test]
    fn max_candidates_truncates_fused_list() {
        let adapters = vec![AdapterResult::ok(
            REPRESENTATION_GRAPH_RETRIEVE_CONTEXT,
            vec![
                graph_cand("g1", 1.0),
                graph_cand("g2", 0.9),
                graph_cand("g3", 0.8),
            ],
        )];
        let fused = late_fuse(FusionProfile::IdentityV1, &adapters, 2);
        assert_eq!(fused.candidates.len(), 2);
        assert!(fused.truncated);
        assert!(
            fused
                .truncation_reasons
                .iter()
                .any(|r| r == "max_candidates")
        );
    }

    #[test]
    fn denied_empty_contributes_no_candidates() {
        let adapters = vec![
            AdapterResult::denied_empty(REPRESENTATION_TEXT_FTS5, 3),
            AdapterResult::ok(
                REPRESENTATION_GRAPH_RETRIEVE_CONTEXT,
                vec![graph_cand("g1", 1.0)],
            ),
        ];
        let fused = late_fuse(FusionProfile::GraphPriorityV1, &adapters, 10);
        assert_eq!(fused.candidates.len(), 1);
        assert_eq!(adapters[0].denied_count, 3);
        assert_eq!(adapters[0].status, AdapterStatus::DeniedEmpty);
    }
}
