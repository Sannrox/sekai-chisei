//! Rebuildable permission-aware search index (ADR 0108 / #1537).
//!
//! The index is a derived projection of the object store and dataset catalog.
//! Responses carry `authority: false`. Losing the tables loses no facts.

use crate::domain::Object;
use crate::sekai::classification_lattice::{ClassificationLattice, evaluate_lattice_access};
use crate::sekai::dataset::Dataset;
use crate::sekai::embedding_index::EmbeddingChunk;
use crate::sekai::markings::{
    MarkingDecision, PrincipalAuthority, is_trusted_service_principal, object_marking_token,
    parse_optional_classification, trusted_service_authority,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const ANALYZER_VERSION: &str = "search.text/v1";
/// The one hybrid fusion profile: reciprocal rank fusion with k = 60.
pub const FUSION_PROFILE: &str = "late_fusion.rrf/v1";
pub const RRF_K: f64 = 60.0;
pub const SEARCH_INDEX_UNAVAILABLE: &str = "search index is unavailable on this runtime";

pub const POLICY_ATTRIBUTE_KEYS: &[&str] = &["owner", "acl", "access_marking", "purpose"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchIndexError {
    Unavailable(String),
    InvalidArgument(String),
    Storage(String),
}

impl std::fmt::Display for SearchIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message)
            | Self::InvalidArgument(message)
            | Self::Storage(message) => f.write_str(message),
        }
    }
}

impl From<String> for SearchIndexError {
    fn from(message: String) -> Self {
        Self::Storage(message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchSourceKind {
    Object,
    Dataset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchQueryMode {
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchDocumentKey {
    Object {
        namespace: String,
        object_id: String,
    },
    Dataset {
        namespace: String,
        dataset_id: String,
    },
}

#[derive(Debug, Clone)]
pub enum SearchDocument {
    Object(Object),
    Dataset { namespace: String, dataset: Dataset },
}

#[derive(Debug, Clone, Default)]
pub struct SearchPolicyFilter {
    pub namespace: String,
    pub namespace_authorized: bool,
    pub kinds: Vec<String>,
    pub subjects: Vec<String>,
    pub scopes: Vec<String>,
    pub clearance: Option<String>,
    pub visible_property_names: Option<Vec<String>>,
    pub purpose: Option<String>,
    pub purpose_authorized: bool,
}

#[derive(Debug, Clone)]
pub struct SearchCandidateQuery {
    pub mode: SearchQueryMode,
    pub text: String,
    pub source: Option<SearchSourceKind>,
    pub policy: SearchPolicyFilter,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchCandidate {
    pub source: SearchSourceKind,
    pub id: String,
    pub kind: String,
    pub matched_fields: Vec<String>,
    pub authority: bool,
}

/// Exact nearest-neighbour query over one embedding spec's chunks, under
/// the same compiled read policy as text candidates (ADR 0108).
#[derive(Debug, Clone)]
pub struct VectorCandidateQuery {
    pub spec_id: String,
    pub vector: Vec<f32>,
    pub policy: SearchPolicyFilter,
    pub limit: usize,
}

impl VectorCandidateQuery {
    /// The object-candidate query the backends' per-object policy check takes.
    pub fn policy_query(&self) -> SearchCandidateQuery {
        SearchCandidateQuery {
            mode: SearchQueryMode::Text,
            text: String::new(),
            source: Some(SearchSourceKind::Object),
            policy: self.policy.clone(),
            limit: self.limit,
        }
    }
}

/// An object ranked by the best cosine similarity of any of its chunks.
#[derive(Debug, Clone, PartialEq)]
pub struct VectorCandidate {
    pub object_id: String,
    pub score: f32,
    /// Digest of the source text the vectors were embedded from. A caller
    /// compares it with the live object: a stale vector may carry a value
    /// the caller can no longer read.
    pub source_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchIndexStatus {
    pub namespace: String,
    pub analyzer_version: String,
    pub last_change_rowid: u64,
    pub last_generation: u64,
    pub dataset_catalog_digest: String,
    pub indexed_at_ms: i64,
    pub object_count: i64,
    pub dataset_count: i64,
    pub lag_ms: i64,
    pub pending_changes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchRebuildReport {
    pub namespace: String,
    pub objects: i64,
    pub datasets: i64,
    pub rebuilt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchCatchUpReport {
    pub namespace: String,
    pub objects: i64,
    pub datasets: i64,
    pub rebuilt: bool,
    pub consumed_changes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct SearchIndexDump {
    pub analyzer_version: String,
    pub objects: BTreeMap<String, SearchObjectDump>,
    pub datasets: BTreeMap<String, SearchDatasetDump>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchObjectDump {
    pub kind: String,
    pub access_marking: String,
    pub policy_attributes: BTreeMap<String, String>,
    pub properties: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SearchDatasetDump {
    pub name: String,
    pub bound_object_id: String,
    pub columns: Vec<(String, String)>,
}

pub trait SearchIndex {
    fn index(&self, document: &SearchDocument, now_ms: i64) -> Result<(), SearchIndexError>;
    fn delete(&self, key: &SearchDocumentKey) -> Result<(), SearchIndexError>;
    fn query_candidates(
        &self,
        query: &SearchCandidateQuery,
    ) -> Result<Vec<SearchCandidate>, SearchIndexError>;
    fn rebuild_namespace(
        &self,
        namespace: &str,
        now_ms: i64,
    ) -> Result<SearchRebuildReport, SearchIndexError>;
    fn status(&self, namespace: &str, now_ms: i64) -> Result<SearchIndexStatus, SearchIndexError>;
    /// Objects nearest to the query vector, best first: the first
    /// `query.limit` that pass the index's read policy and then `keep`, the
    /// caller's live check. Exact today; an ANN index may back this later
    /// behind the same contract.
    fn vector_candidates(
        &self,
        query: &VectorCandidateQuery,
        keep: &mut dyn FnMut(&VectorCandidate) -> Result<bool, SearchIndexError>,
    ) -> Result<Vec<VectorCandidate>, SearchIndexError>;
}

/// The marking authority a search policy carries: a trusted service
/// principal's, or the caller's clearance.
fn search_authority(policy: &SearchPolicyFilter) -> PrincipalAuthority {
    let subject = policy
        .subjects
        .iter()
        .find(|subject| is_trusted_service_principal(subject))
        .cloned()
        .or_else(|| policy.subjects.first().cloned())
        .unwrap_or_default();
    if let Some(trusted) = trusted_service_authority(&subject) {
        return trusted;
    }
    PrincipalAuthority {
        principal: subject,
        classification_ceiling: policy
            .clearance
            .as_deref()
            .and_then(|token| parse_optional_classification(token).ok().flatten()),
        classification_token: policy.clearance.clone(),
        allowed_purposes: BTreeSet::new(),
        declassify_markings: BTreeSet::new(),
    }
}

/// Whether the policy's authority may see a document with `marking`.
pub fn policy_marking_allows(
    marking: &str,
    policy: &SearchPolicyFilter,
    lattice: Option<&ClassificationLattice>,
) -> bool {
    let token = (!marking.is_empty()).then_some(marking);
    evaluate_lattice_access("search", token, &search_authority(policy), lattice).decision
        != MarkingDecision::Deny
}

/// Exact search shared by every backend: drop chunks the policy's marking
/// check denies, score the rest by cosine similarity, rank objects by their
/// best chunk (then id), and keep the first `limit` that `allows`, the
/// backend's per-object read policy check. Policy applies before the limit,
/// so recall is exact over what the caller may see.
pub fn exact_vector_candidates(
    chunks: Vec<EmbeddingChunk>,
    query: &VectorCandidateQuery,
    lattice: Option<&ClassificationLattice>,
    mut allows: impl FnMut(&VectorCandidate) -> Result<bool, SearchIndexError>,
) -> Result<Vec<VectorCandidate>, SearchIndexError> {
    let mut best = BTreeMap::<String, (f32, String)>::new();
    // Few distinct markings: decide each once.
    let mut marking_allowed = BTreeMap::<String, bool>::new();
    for chunk in chunks {
        let marking = chunk.source.marking.unwrap_or_default();
        let allowed = match marking_allowed.get(&marking) {
            Some(allowed) => *allowed,
            None => {
                let allowed = policy_marking_allows(&marking, &query.policy, lattice);
                marking_allowed.insert(marking, allowed);
                allowed
            }
        };
        if !allowed {
            continue;
        }
        let Some(score) = cosine(&chunk.vector, &query.vector) else {
            continue;
        };
        let digest = chunk.source.source_digest;
        best.entry(chunk.object_id)
            .and_modify(|current: &mut (f32, String)| current.0 = current.0.max(score))
            .or_insert((score, digest));
    }
    let mut ranked = best
        .into_iter()
        .map(|(object_id, (score, source_digest))| VectorCandidate {
            object_id,
            score,
            source_digest,
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then(a.object_id.cmp(&b.object_id))
    });
    let mut allowed = Vec::new();
    for candidate in ranked {
        if allowed.len() >= query.limit {
            break;
        }
        if allows(&candidate)? {
            allowed.push(candidate);
        }
    }
    Ok(allowed)
}

/// Cosine similarity; none for a dimension mismatch or a zero vector.
fn cosine(a: &[f32], b: &[f32]) -> Option<f32> {
    if a.len() != b.len() {
        return None;
    }
    let (mut dot, mut aa, mut bb) = (0f32, 0f32, 0f32);
    for (x, y) in a.iter().zip(b) {
        dot += x * y;
        aa += x * x;
        bb += y * y;
    }
    (aa > 0.0 && bb > 0.0).then(|| dot / (aa.sqrt() * bb.sqrt()))
}

/// Reciprocal rank fusion of ranked lists under [`FUSION_PROFILE`]: each
/// list adds `weight / (RRF_K + rank)` (rank from 1) to its keys; a list
/// weighted 0 contributes no keys. Ties break by key, so a fixed input
/// fuses to a fixed order.
pub fn rrf_fuse<K: Ord + Clone>(lists: &[(&[K], f64)]) -> Vec<K> {
    let mut scores = BTreeMap::<K, f64>::new();
    for (list, weight) in lists.iter().filter(|(_, weight)| *weight > 0.0) {
        for (rank, key) in list.iter().enumerate() {
            *scores.entry(key.clone()).or_default() += weight / (RRF_K + rank as f64 + 1.0);
        }
    }
    let mut fused = scores.into_iter().collect::<Vec<_>>();
    fused.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    fused.into_iter().map(|(key, _)| key).collect()
}

pub fn policy_attributes(object: &Object) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    for key in POLICY_ATTRIBUTE_KEYS {
        if let Some(value) = object.properties.get(*key)
            && !value.is_empty()
        {
            attributes.insert((*key).to_string(), value.clone());
        }
    }
    attributes
}

pub fn object_text_properties(object: &Object) -> BTreeMap<String, String> {
    let mut properties = BTreeMap::new();
    if !object.name.is_empty() {
        properties.insert("name".into(), object.name.clone());
    }
    for (key, value) in &object.properties {
        if key == "name"
            || key.starts_with('_')
            || POLICY_ATTRIBUTE_KEYS.contains(&key.as_str())
            || value.is_empty()
        {
            continue;
        }
        properties.insert(key.clone(), value.clone());
    }
    properties
}

pub fn object_content_digest(object: &Object) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ANALYZER_VERSION.as_bytes());
    hasher.update(object.kind.as_bytes());
    hasher.update([0u8]);
    hasher.update(object.name.as_bytes());
    hasher.update([0u8]);
    hasher.update(object_marking_token(object).unwrap_or_default().as_bytes());
    hasher.update([0u8]);
    for (key, value) in policy_attributes(object) {
        hasher.update(key.as_bytes());
        hasher.update([0u8]);
        hasher.update(value.as_bytes());
        hasher.update([2u8]);
    }
    for (key, value) in object_text_properties(object) {
        hasher.update(key.as_bytes());
        hasher.update([0u8]);
        hasher.update(value.as_bytes());
        hasher.update([1u8]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub fn dataset_content_digest(dataset: &Dataset) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ANALYZER_VERSION.as_bytes());
    hasher.update(dataset.id.as_bytes());
    hasher.update([0u8]);
    hasher.update(dataset.name.as_bytes());
    hasher.update([0u8]);
    hasher.update(dataset.object_id.as_bytes());
    hasher.update([0u8]);
    for column in &dataset.columns {
        hasher.update(column.name.as_bytes());
        hasher.update([0u8]);
        hasher.update(column.classification.as_bytes());
        hasher.update([1u8]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub fn dataset_catalog_digest<'a>(datasets: impl IntoIterator<Item = &'a Dataset>) -> String {
    let mut entries = datasets
        .into_iter()
        .map(|dataset| {
            (
                dataset.id.clone(),
                dataset.name.clone(),
                dataset.object_id.clone(),
                dataset
                    .columns
                    .iter()
                    .map(|column| (column.name.clone(), column.classification.clone()))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    let encoded = serde_json::to_string(&entries).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(encoded.as_bytes()))
}

fn is_combining_mark(ch: char) -> bool {
    matches!(
        ch as u32,
        0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F
    )
}

fn fold_search_char(ch: char) -> String {
    match ch {
        'À' | 'Á' | 'Â' | 'Ã' | 'Ä' | 'Å' | 'Ā' | 'Ă' | 'Ą' | 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å'
        | 'ā' | 'ă' | 'ą' => "a".into(),
        'È' | 'É' | 'Ê' | 'Ë' | 'Ē' | 'Ĕ' | 'Ė' | 'Ę' | 'Ě' | 'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ'
        | 'ė' | 'ę' | 'ě' => "e".into(),
        'Ì' | 'Í' | 'Î' | 'Ï' | 'Ĩ' | 'Ī' | 'Ĭ' | 'Į' | 'ì' | 'í' | 'î' | 'ï' | 'ĩ' | 'ī' | 'ĭ'
        | 'į' => "i".into(),
        'Ò' | 'Ó' | 'Ô' | 'Õ' | 'Ö' | 'Ō' | 'Ŏ' | 'Ő' | 'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ō' | 'ŏ'
        | 'ő' => "o".into(),
        'Ù' | 'Ú' | 'Û' | 'Ü' | 'Ũ' | 'Ū' | 'Ŭ' | 'Ů' | 'Ű' | 'Ų' | 'ù' | 'ú' | 'û' | 'ü' | 'ũ'
        | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' => "u".into(),
        'Ý' | 'Ÿ' | 'Ŷ' | 'ý' | 'ÿ' | 'ŷ' => "y".into(),
        'Ñ' | 'Ń' | 'Ņ' | 'Ň' | 'ñ' | 'ń' | 'ņ' | 'ň' => "n".into(),
        'Ç' | 'Ć' | 'Ĉ' | 'Ċ' | 'Č' | 'ç' | 'ć' | 'ĉ' | 'ċ' | 'č' => "c".into(),
        'Ď' | 'Đ' | 'ď' | 'đ' => "d".into(),
        'Ĝ' | 'Ğ' | 'Ġ' | 'Ģ' | 'ĝ' | 'ğ' | 'ġ' | 'ģ' => "g".into(),
        'Ĥ' | 'Ħ' | 'ĥ' | 'ħ' => "h".into(),
        'Ĵ' | 'ĵ' => "j".into(),
        'Ķ' | 'ķ' => "k".into(),
        'Ĺ' | 'Ļ' | 'Ľ' | 'Ŀ' | 'Ł' | 'ĺ' | 'ļ' | 'ľ' | 'ŀ' | 'ł' => "l".into(),
        'Ŕ' | 'Ŗ' | 'Ř' | 'ŕ' | 'ŗ' | 'ř' => "r".into(),
        'Ś' | 'Ŝ' | 'Ş' | 'Š' | 'ś' | 'ŝ' | 'ş' | 'š' => "s".into(),
        'Ţ' | 'Ť' | 'Ŧ' | 'ţ' | 'ť' | 'ŧ' => "t".into(),
        'Ŵ' | 'ŵ' => "w".into(),
        'Ź' | 'Ż' | 'Ž' | 'ź' | 'ż' | 'ž' => "z".into(),
        other => other.to_lowercase().collect(),
    }
}

pub fn search_tokens(text: &str) -> Vec<String> {
    let folded: String = text
        .chars()
        .filter(|ch| !is_combining_mark(*ch))
        .flat_map(|ch| fold_search_char(ch).chars().collect::<Vec<_>>())
        .collect();
    folded
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn indexed_search_text(text: &str) -> String {
    search_tokens(text).join(" ")
}

pub fn fts_query(text: &str) -> Result<String, SearchIndexError> {
    let tokens = search_tokens(text)
        .into_iter()
        .map(|token| format!("\"{token}\""))
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return Err(SearchIndexError::InvalidArgument(
            "search text required".into(),
        ));
    }
    Ok(tokens.join(" AND "))
}

pub fn text_matches_query(value: &str, query: &str) -> bool {
    let tokens = search_tokens(query);
    if tokens.is_empty() {
        return false;
    }
    let haystack = search_tokens(value);
    tokens
        .iter()
        .all(|token| haystack.iter().any(|item| item == token))
}

pub fn live_object_match_fields(object: &Object, query: &str) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    if text_matches_query(&object.name, query) {
        fields.insert("name".into());
    }
    for (key, value) in object_text_properties(object) {
        if text_matches_query(&value, query) {
            fields.insert(key);
        }
    }
    fields
}

pub fn acl_allows(attributes: &BTreeMap<String, String>, subjects: &[String]) -> bool {
    if subjects
        .iter()
        .any(|subject| subject == "root" || subject == "local")
    {
        return true;
    }
    if let Some(owner) = attributes.get("owner")
        && subjects.iter().any(|subject| subject == owner)
    {
        return true;
    }
    if let Some(acl) = attributes.get("acl") {
        let granted = acl
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect::<BTreeSet<_>>();
        if granted.is_empty() {
            return true;
        }
        return subjects
            .iter()
            .any(|subject| granted.contains(subject.as_str()));
    }
    attributes.get("owner").is_none()
}

pub fn purpose_allows(
    attributes: &BTreeMap<String, String>,
    purpose: Option<&str>,
    purpose_authorized: bool,
) -> bool {
    match purpose {
        Some(_) if !purpose_authorized => false,
        Some(required) => match attributes.get("purpose") {
            Some(stored) => stored == required,
            None => true,
        },
        None => true,
    }
}

pub fn marking_allows(stored: &str, clearance: Option<&str>) -> bool {
    if stored.is_empty() {
        return true;
    }
    let Some(clearance) = clearance else {
        return false;
    };
    match (
        crate::sekai::markings::parse_classification(stored),
        crate::sekai::markings::parse_classification(clearance),
    ) {
        (Ok(stored), Ok(clearance)) => clearance >= stored,
        _ => false,
    }
}

pub fn dataset_classification_allows(stored: &str, clearance: Option<&str>) -> bool {
    if stored.is_empty() || stored == "public" {
        return true;
    }
    let mapped = match stored {
        "public" => "public",
        "internal" => "internal",
        "sensitive" => "confidential",
        other => other,
    };
    marking_allows(mapped, clearance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::search_index::SearchIndexStore;
    use crate::domain::{ListFilter, Object};
    use crate::sekai::dataset::{ColumnDef, Dataset};

    fn postgres_runtime() -> (crate::db::postgres::ScratchDatabase, RuntimeDb) {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect()));
        (scratch, db)
    }

    fn seed_team_principal(db: &RuntimeDb, principal: &str) {
        if db
            .create_managed_team_credential(principal, "hash", 10)
            .is_ok()
        {
            return;
        }
        let RuntimeDb::Postgres(postgres) = db else {
            panic!("could not seed team principal");
        };
        postgres
            .connection()
            .expect("postgres connection")
            .execute(
                "INSERT INTO sekai_team_principals (principal, created) VALUES ($1, $2)
                 ON CONFLICT (principal) DO NOTHING",
                &[&principal, &10i64],
            )
            .expect("seed team principal");
    }

    fn object(id: &str, namespace: &str, name: &str, properties: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            kind: "note".into(),
            name: name.into(),
            namespace: namespace.into(),
            external_id: String::new(),
            properties: properties
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
            created: 1,
            updated: 1,
        }
    }

    fn dataset(id: &str, name: &str, object_id: &str, columns: &[(&str, &str)]) -> Dataset {
        Dataset {
            id: id.into(),
            name: name.into(),
            columns: columns
                .iter()
                .map(|(name, classification)| ColumnDef {
                    name: (*name).into(),
                    col_type: "string".into(),
                    classification: (*classification).into(),
                })
                .collect(),
            object_id: object_id.into(),
            created: 1,
            partition_keys: Vec::new(),
        }
    }

    #[test]
    fn internal_clearance_does_not_cover_restricted_markings() {
        assert!(marking_allows("public", Some("internal")));
        assert!(marking_allows("internal", Some("internal")));
        assert!(!marking_allows("confidential", Some("internal")));
        assert!(!marking_allows("restricted", Some("internal")));
        assert!(marking_allows("restricted", Some("restricted")));
        assert!(!marking_allows("confidential", None));
        assert!(!marking_allows("secret", Some("internal")));
        assert!(dataset_classification_allows("public", None));
        assert!(dataset_classification_allows("public", Some("internal")));
        assert!(!dataset_classification_allows("internal", None));
    }

    #[test]
    fn fts_query_quotes_tokens_and_splits_hyphens() {
        assert_eq!(
            fts_query("sales-renamed").unwrap(),
            "\"sales\" AND \"renamed\""
        );
        assert_eq!(fts_query("customers").unwrap(), "\"customers\"");
        assert_eq!(fts_query("München").unwrap(), "\"munchen\"");
        assert_eq!(fts_query("foo_bar").unwrap(), "\"foo\" AND \"bar\"");
        assert_eq!(fts_query("Straße").unwrap(), "\"straße\"");
        assert_eq!(fts_query("Český").unwrap(), "\"cesky\"");
        assert!(text_matches_query("office in München", "Munchen"));
        assert!(text_matches_query("Červený", "cerveny"));
        assert!(text_matches_query("Mu\u{0308}nchen", "Munchen"));
    }

    #[test]
    fn dataset_content_digest_encodes_field_boundaries() {
        let left = dataset("ds-1", "sales", "ab", &[("id", "public")]);
        let right = dataset("ds-1", "salesa", "b", &[("id", "public")]);
        assert_ne!(
            dataset_content_digest(&left),
            dataset_content_digest(&right)
        );
    }

    fn exercise_unicode_object_text_is_searchable(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object(
                "note-munich",
                "acme",
                "city",
                &[("body", "office in München")],
            ),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "München".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "note-munich");
        let ascii = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "Munchen".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].id, "note-munich");
    }

    #[test]
    fn unicode_object_text_is_searchable() {
        exercise_unicode_object_text_is_searchable(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_unicode_object_text_is_searchable() {
        let (_scratch, db) = postgres_runtime();
        exercise_unicode_object_text_is_searchable(&db);
    }

    fn exercise_folded_letters_match_the_same_object_text(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object("note-lodz", "acme", "city", &[("body", "office in Łódź")]),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        for query in ["Łódź", "Lodz", "lodz"] {
            let hits = db
                .query_candidates(&SearchCandidateQuery {
                    mode: SearchQueryMode::Text,
                    text: query.into(),
                    source: Some(SearchSourceKind::Object),
                    policy: SearchPolicyFilter {
                        namespace: "acme".into(),
                        namespace_authorized: true,
                        subjects: vec!["editor".into()],
                        ..SearchPolicyFilter::default()
                    },
                    limit: 10,
                })
                .unwrap();
            assert_eq!(hits.len(), 1, "{query}");
            assert_eq!(hits[0].id, "note-lodz");
        }
    }

    #[test]
    fn folded_letters_match_the_same_object_text() {
        exercise_folded_letters_match_the_same_object_text(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_folded_letters_match_the_same_object_text() {
        let (_scratch, db) = postgres_runtime();
        exercise_folded_letters_match_the_same_object_text(&db);
    }

    #[test]
    fn object_name_field_is_not_overwritten_by_a_name_property() {
        let note = object(
            "note-name",
            "acme",
            "visible-title",
            &[("name", "secret-property"), ("body", "other")],
        );
        let properties = object_text_properties(&note);
        assert_eq!(
            properties.get("name").map(String::as_str),
            Some("visible-title")
        );
        assert!(!properties.values().any(|value| value == "secret-property"));
    }

    fn exercise_deny_unmarked_hides_unmarked_search_candidates(db: &RuntimeDb) {
        let mut namespace = object("ns-acme", "acme", "acme", &[("deny_unmarked", "true")]);
        namespace.kind = "namespace".into();
        namespace.external_id = "namespace:acme".into();
        db.create_object_with_audit(&namespace, "root").unwrap();
        db.create_object_with_audit(
            &object("note-bare", "acme", "bare", &[("body", "unmarked token")]),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "unmarked".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());
        let trusted = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "unmarked".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["root".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0].id, "note-bare");
    }

    /// Vector candidates follow the read policy before ranking and before
    /// the limit, the same on every backend (#1582, #1682).
    fn exercise_vector_candidates_follow_the_read_policy(db: &RuntimeDb) {
        use crate::sekai::embedding_index::{
            EmbeddingSource, EmbeddingSpec, EmbeddingStore, ObjectEmbeddings, StoredEmbeddingSpec,
        };
        for (id, properties) in [
            ("near", vec![("body", "near")]),
            ("far", vec![("body", "far")]),
            ("owned", vec![("body", "owned"), ("owner", "alice")]),
            (
                "marked",
                vec![("body", "marked"), ("access_marking", "confidential")],
            ),
        ] {
            db.create_object_with_audit(&object(id, "acme", id, &properties), "root")
                .unwrap();
        }
        db.put_embedding_spec(&StoredEmbeddingSpec {
            spec: EmbeddingSpec {
                id: "notes".into(),
                namespace: "acme".into(),
                object_kind: "note".into(),
                properties: vec!["body".into()],
                chunk_chars: 1_000,
                dimension: 2,
                batch_size: 8,
            },
            model: "m".into(),
            updated_by: "admin".into(),
            updated_at_ms: 1,
            revision: 0,
        })
        .unwrap();
        let mut revision = db
            .embedding_checkpoint("acme", "notes")
            .unwrap()
            .map_or(0, |checkpoint| checkpoint.revision);
        // The owned and marked notes are nearest the query.
        for (id, marking, vector) in [
            ("owned", None, [1.0, 0.0]),
            ("marked", Some("confidential"), [1.0, 0.0]),
            ("near", None, [0.9, 0.1]),
            ("far", None, [0.0, 1.0]),
        ] {
            let source = EmbeddingSource {
                source_digest: format!("digest-{id}"),
                model: "m".into(),
                model_version: "v".into(),
                marking: marking.map(Into::into),
                classifications: Vec::new(),
            };
            revision = db
                .write_embedding_object(
                    "acme",
                    "notes",
                    &ObjectEmbeddings {
                        object_id: id,
                        source: &source,
                        chunks: &[(0, format!("chunk-{id}"), vector.to_vec())],
                        keep: 1,
                    },
                    revision,
                    10,
                )
                .unwrap();
        }
        let ranked = |subject: &str, limit: usize| {
            db.vector_candidates(
                &VectorCandidateQuery {
                    spec_id: "notes".into(),
                    vector: vec![1.0, 0.0],
                    policy: SearchPolicyFilter {
                        namespace: "acme".into(),
                        namespace_authorized: true,
                        subjects: vec![subject.into()],
                        ..SearchPolicyFilter::default()
                    },
                    limit,
                },
                &mut |_| Ok(true),
            )
            .unwrap()
            .into_iter()
            .map(|candidate| candidate.object_id)
            .collect::<Vec<_>>()
        };
        // No vector hit for another owner's note or above the caller's
        // clearance, and neither takes a place within the limit.
        assert_eq!(ranked("editor", 10), vec!["near", "far"]);
        assert_eq!(ranked("editor", 1), vec!["near"]);
        assert_eq!(ranked("alice", 1), vec!["owned"]);
    }

    #[test]
    fn vector_candidates_follow_the_read_policy() {
        exercise_vector_candidates_follow_the_read_policy(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_vector_candidates_follow_the_read_policy() {
        let (_scratch, db) = postgres_runtime();
        exercise_vector_candidates_follow_the_read_policy(&db);
    }

    #[test]
    fn deny_unmarked_hides_unmarked_search_candidates() {
        exercise_deny_unmarked_hides_unmarked_search_candidates(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_deny_unmarked_hides_unmarked_search_candidates() {
        let (_scratch, db) = postgres_runtime();
        exercise_deny_unmarked_hides_unmarked_search_candidates(&db);
    }

    #[test]
    fn namespace_classification_lattice_governs_search_visibility() {
        use crate::sekai::classification_lattice::{
            CLASSIFICATION_LATTICE_VERSION, ClassificationLattice,
        };
        use std::collections::BTreeMap;

        let db = RuntimeDb::memory();
        let inverted = ClassificationLattice {
            contract_version: CLASSIFICATION_LATTICE_VERSION.into(),
            namespace: "acme".into(),
            tokens: vec!["public".into(), "internal".into()],
            parents: BTreeMap::new(),
            incomparable: Vec::new(),
        };
        db.put_classification_lattice(&inverted, "root", 10)
            .unwrap();
        db.create_object_with_audit(
            &object(
                "note-public",
                "acme",
                "public",
                &[("body", "lattice token"), ("access_marking", "public")],
            ),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "lattice".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    clearance: Some("internal".into()),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());

        let custom = ClassificationLattice {
            contract_version: CLASSIFICATION_LATTICE_VERSION.into(),
            namespace: "acme".into(),
            tokens: vec!["public".into(), "compartment-a".into()],
            parents: BTreeMap::from([("public".into(), vec!["compartment-a".into()])]),
            incomparable: Vec::new(),
        };
        db.put_classification_lattice(&custom, "root", 20).unwrap();
        db.create_object_with_audit(
            &object(
                "note-compartment",
                "acme",
                "secret",
                &[
                    ("body", "compartment token"),
                    ("access_marking", "compartment-a"),
                ],
            ),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 30).unwrap();
        let visible = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "compartment".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    clearance: Some("compartment-a".into()),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "note-compartment");
        let denied = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "compartment".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    clearance: Some("restricted".into()),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(denied.is_empty());
    }

    #[test]
    fn catalog_digest_is_stable_under_input_order() {
        let left = dataset(
            "ds-1",
            "sales",
            "obj-1",
            &[("id", "public"), ("secret", "secret")],
        );
        let right = dataset("ds-2", "ops", "obj-2", &[("name", "internal")]);
        assert_eq!(
            dataset_catalog_digest([&left, &right]),
            dataset_catalog_digest([&right, &left])
        );
    }

    fn exercise_object_edit_is_indexed_once_the_cursor_passes_it(db: &RuntimeDb) {
        let note = object(
            "note-1",
            "acme",
            "alpha",
            &[("body", "join customers"), ("owner", "editor")],
        );
        db.create_object_with_audit(&note, "editor").unwrap();
        let before = db.status("acme", 20).unwrap();
        assert_eq!(before.object_count, 0);
        assert!(before.pending_changes > 0);
        db.catch_up_search_namespace("acme", 20).unwrap();
        let status = db.status("acme", 20).unwrap();
        assert_eq!(status.object_count, 1);
        assert_eq!(status.pending_changes, 0);
        assert_eq!(status.lag_ms, 0);
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "customers".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    visible_property_names: Some(vec!["body".into(), "name".into()]),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "note-1");
        assert!(!hits[0].authority);
    }

    #[test]
    fn object_edit_is_indexed_once_the_cursor_passes_it() {
        exercise_object_edit_is_indexed_once_the_cursor_passes_it(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_object_edit_is_indexed_once_the_cursor_passes_it() {
        let (_scratch, db) = postgres_runtime();
        exercise_object_edit_is_indexed_once_the_cursor_passes_it(&db);
    }

    fn exercise_policy_attribute_edit_updates_stored_attributes(db: &RuntimeDb) {
        let mut note = object(
            "note-2",
            "acme",
            "beta",
            &[
                ("body", "visible text"),
                ("owner", "alice"),
                ("access_marking", "internal"),
            ],
        );
        db.create_object_with_audit(&note, "alice").unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        note.properties.insert("owner".into(), "bob".into());
        note.properties
            .insert("access_marking".into(), "secret".into());
        note.updated = 11;
        db.update_object_with_audit(&note, "alice").unwrap();
        db.catch_up_search_namespace("acme", 20).unwrap();
        let dump = db.search_index_dump("acme").unwrap();
        let stored = dump.objects.get("note-2").expect("indexed");
        assert_eq!(
            stored.policy_attributes.get("owner").map(String::as_str),
            Some("bob")
        );
        assert_eq!(stored.access_marking, "secret");
    }

    #[test]
    fn policy_attribute_edit_updates_stored_attributes() {
        exercise_policy_attribute_edit_updates_stored_attributes(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_policy_attribute_edit_updates_stored_attributes() {
        let (_scratch, db) = postgres_runtime();
        exercise_policy_attribute_edit_updates_stored_attributes(&db);
    }

    fn exercise_owner_only_edit_updates_stored_policy_attributes(db: &RuntimeDb) {
        let mut note = object(
            "note-owner",
            "acme",
            "beta",
            &[("body", "visible text"), ("owner", "alice")],
        );
        db.create_object_with_audit(&note, "alice").unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        note.properties.insert("owner".into(), "bob".into());
        note.updated = 11;
        db.update_object_with_audit(&note, "alice").unwrap();
        db.catch_up_search_namespace("acme", 20).unwrap();
        let dump = db.search_index_dump("acme").unwrap();
        let stored = dump.objects.get("note-owner").expect("indexed");
        assert_eq!(
            stored.policy_attributes.get("owner").map(String::as_str),
            Some("bob")
        );
    }

    #[test]
    fn owner_only_edit_updates_stored_policy_attributes() {
        exercise_owner_only_edit_updates_stored_policy_attributes(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_owner_only_edit_updates_stored_policy_attributes() {
        let (_scratch, db) = postgres_runtime();
        exercise_owner_only_edit_updates_stored_policy_attributes(&db);
    }

    fn exercise_generation_gap_rebuilds_and_matches_incremental_contents(db: &RuntimeDb) {
        let first = object("note-3", "acme", "gamma", &[("body", "left join")]);
        db.create_object_with_audit(&first, "editor").unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let second = object("note-4", "acme", "delta", &[("body", "right join")]);
        db.create_object_with_audit(&second, "editor").unwrap();
        let incremental = db.catch_up_search_namespace("acme", 20).unwrap();
        assert!(!incremental.rebuilt);
        let third = object("note-5", "acme", "epsilon", &[("body", "full join")]);
        db.create_object_with_audit(&third, "editor").unwrap();
        db.purge_object_changes_for_test().unwrap();
        let gap = db.catch_up_search_namespace("acme", 30).unwrap();
        assert!(gap.rebuilt);
        let rebuilt = db.search_index_dump("acme").unwrap();
        assert!(rebuilt.objects.contains_key("note-5"));
        db.rebuild_namespace("acme", 40).unwrap();
        let forced = db.search_index_dump("acme").unwrap();
        assert_eq!(rebuilt.objects, forced.objects);
        assert_eq!(rebuilt.datasets, forced.datasets);
        assert_eq!(rebuilt.analyzer_version, ANALYZER_VERSION);
    }

    #[test]
    fn generation_gap_rebuilds_and_matches_incremental_contents() {
        exercise_generation_gap_rebuilds_and_matches_incremental_contents(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_generation_gap_rebuilds_and_matches_incremental_contents() {
        let (_scratch, db) = postgres_runtime();
        exercise_generation_gap_rebuilds_and_matches_incremental_contents(&db);
    }

    fn exercise_generation_gap_rebuilds_even_when_newer_changes_remain(db: &RuntimeDb) {
        let mut first = object("note-stale", "acme", "alpha", &[("body", "old token")]);
        db.create_object_with_audit(&first, "editor").unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        first.properties.insert("body".into(), "fresh token".into());
        first.updated = 11;
        db.update_object_with_audit(&first, "editor").unwrap();
        db.purge_object_changes_for_object_for_test("note-stale")
            .unwrap();
        db.create_object_with_audit(
            &object("note-newer", "acme", "beta", &[("body", "other token")]),
            "editor",
        )
        .unwrap();
        let first = db.catch_up_search_namespace("acme", 20).unwrap();
        let gap = if first.rebuilt {
            first
        } else {
            db.catch_up_search_namespace("acme", 21).unwrap()
        };
        assert!(gap.rebuilt);
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "fresh".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "note-stale");
    }

    #[test]
    fn generation_gap_rebuilds_even_when_newer_changes_remain() {
        exercise_generation_gap_rebuilds_even_when_newer_changes_remain(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_generation_gap_rebuilds_even_when_newer_changes_remain() {
        let (_scratch, db) = postgres_runtime();
        exercise_generation_gap_rebuilds_even_when_newer_changes_remain(&db);
    }

    fn exercise_repeated_edits_to_one_object_stay_incremental(db: &RuntimeDb) {
        let mut note = object("note-repeat", "acme", "alpha", &[("body", "first")]);
        db.create_object_with_audit(&note, "editor").unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        note.properties.insert("body".into(), "second".into());
        note.updated = 11;
        db.update_object_with_audit(&note, "editor").unwrap();
        note.properties.insert("body".into(), "third".into());
        note.updated = 12;
        db.update_object_with_audit(&note, "editor").unwrap();
        let report = db.catch_up_search_namespace("acme", 20).unwrap();
        assert!(!report.rebuilt);
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "third".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "note-repeat");
    }

    #[test]
    fn repeated_edits_to_one_object_stay_incremental() {
        exercise_repeated_edits_to_one_object_stay_incremental(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_repeated_edits_to_one_object_stay_incremental() {
        let (_scratch, db) = postgres_runtime();
        exercise_repeated_edits_to_one_object_stay_incremental(&db);
    }

    fn exercise_property_names_are_not_full_text_matches(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object("note-meta", "acme", "alpha", &[("body", "visible token")]),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "body".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn property_names_are_not_full_text_matches() {
        exercise_property_names_are_not_full_text_matches(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_property_names_are_not_full_text_matches() {
        let (_scratch, db) = postgres_runtime();
        exercise_property_names_are_not_full_text_matches(&db);
    }

    fn exercise_dataset_catalog_change_updates_metadata_entries(db: &RuntimeDb) {
        let bound = object("dataset-owner", "acme", "owner", &[]);
        db.create_object_with_audit(&bound, "editor").unwrap();
        let mut sales = dataset(
            "ds-sales",
            "sales",
            "dataset-owner",
            &[("id", "public"), ("amount", "internal")],
        );
        db.create_dataset(&sales).unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        sales.name = "sales-renamed".into();
        sales.columns.push(ColumnDef {
            name: "region".into(),
            col_type: "string".into(),
            classification: "public".into(),
        });
        db.update_dataset(&sales).unwrap();
        db.catch_up_search_namespace("acme", 20).unwrap();
        let dump = db.search_index_dump("acme").unwrap();
        let stored = dump.datasets.get("ds-sales").expect("dataset indexed");
        assert_eq!(stored.name, "sales-renamed");
        assert!(stored.columns.iter().any(|(name, _)| name == "region"));
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "sales-renamed".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    clearance: Some("internal".into()),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "ds-sales");
    }

    #[test]
    fn dataset_catalog_change_updates_metadata_entries() {
        exercise_dataset_catalog_change_updates_metadata_entries(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_dataset_catalog_change_updates_metadata_entries() {
        let (_scratch, db) = postgres_runtime();
        exercise_dataset_catalog_change_updates_metadata_entries(&db);
    }

    fn exercise_restricted_bound_object_hides_dataset_candidates(db: &RuntimeDb) {
        let bound = object(
            "secret-owner",
            "acme",
            "owner",
            &[("access_marking", "restricted")],
        );
        db.create_object_with_audit(&bound, "editor").unwrap();
        db.create_dataset(&dataset(
            "ds-secret",
            "payroll",
            "secret-owner",
            &[("id", "public")],
        ))
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "payroll".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    clearance: Some("internal".into()),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());
        let visible = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "payroll".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    clearance: Some("restricted".into()),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "ds-secret");
    }

    #[test]
    fn restricted_bound_object_hides_dataset_candidates() {
        exercise_restricted_bound_object_hides_dataset_candidates(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_restricted_bound_object_hides_dataset_candidates() {
        let (_scratch, db) = postgres_runtime();
        exercise_restricted_bound_object_hides_dataset_candidates(&db);
    }

    fn exercise_dataset_purpose_filter_hides_mismatched_bound_objects(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object("finance-owner", "acme", "owner", &[("purpose", "finance")]),
            "editor",
        )
        .unwrap();
        db.create_dataset(&dataset(
            "ds-finance",
            "ledger",
            "finance-owner",
            &[("id", "public")],
        ))
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "ledger".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    purpose: Some("hr".into()),
                    purpose_authorized: true,
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());
        let visible = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "ledger".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    purpose: Some("finance".into()),
                    purpose_authorized: true,
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "ds-finance");
    }

    #[test]
    fn dataset_purpose_filter_hides_mismatched_bound_objects() {
        exercise_dataset_purpose_filter_hides_mismatched_bound_objects(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_dataset_purpose_filter_hides_mismatched_bound_objects() {
        let (_scratch, db) = postgres_runtime();
        exercise_dataset_purpose_filter_hides_mismatched_bound_objects(&db);
    }

    fn exercise_object_grants_filter_search_candidates(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object("note-grant", "acme", "shared", &[("body", "visible token")]),
            "editor",
        )
        .unwrap();
        db.create_grant(&crate::sekai::security::Grant {
            id: "g1".into(),
            object_id: "note-grant".into(),
            principal: "alice".into(),
            role: crate::sekai::security::Role::Viewer,
            created: 1,
            ..Default::default()
        })
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let denied = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "visible".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["bob".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(denied.is_empty());
        let allowed = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "visible".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["alice".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].id, "note-grant");
    }

    #[test]
    fn object_grants_filter_search_candidates() {
        exercise_object_grants_filter_search_candidates(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_object_grants_filter_search_candidates() {
        let (_scratch, db) = postgres_runtime();
        exercise_object_grants_filter_search_candidates(&db);
    }

    fn exercise_compiled_object_security_policy_filters_candidates(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object(
                "note-owned",
                "acme",
                "owned",
                &[("body", "policy token"), ("owner", "alice")],
            ),
            "alice",
        )
        .unwrap();
        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "note".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![
                    crate::sekai::object_security::ObjectSecurityPredicate::SubjectEqualsProperty {
                        property: "owner".into(),
                    },
                ],
            }],
            property_grants: None,
            value_instance_grants: None,
            required_purpose: None,
        };
        let revision = db
            .put_object_security_policy(&policy, "root", "put-search-policy", 1)
            .unwrap();
        db.activate_object_security_policies(
            "acme",
            &std::collections::BTreeMap::from([("note".into(), revision.revision_digest)]),
            "root",
            "activate-search-policy",
            2,
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let denied = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "policy".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["bob".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(denied.is_empty());
        let allowed = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "policy".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["alice".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].id, "note-owned");
    }

    #[test]
    fn compiled_object_security_policy_filters_candidates() {
        exercise_compiled_object_security_policy_filters_candidates(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_compiled_object_security_policy_filters_candidates() {
        let (_scratch, db) = postgres_runtime();
        exercise_compiled_object_security_policy_filters_candidates(&db);
    }

    fn exercise_live_object_permissions_override_stale_index_attributes(db: &RuntimeDb) {
        let mut note = object(
            "note-live",
            "acme",
            "alpha",
            &[("body", "live token"), ("access_marking", "public")],
        );
        db.create_object_with_audit(&note, "editor").unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        note.properties
            .insert("access_marking".into(), "restricted".into());
        note.updated = 11;
        db.update_object_with_audit(&note, "editor").unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "live".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    clearance: Some("internal".into()),
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());
    }

    #[test]
    fn live_object_permissions_override_stale_index_attributes() {
        exercise_live_object_permissions_override_stale_index_attributes(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_live_object_permissions_override_stale_index_attributes() {
        let (_scratch, db) = postgres_runtime();
        exercise_live_object_permissions_override_stale_index_attributes(&db);
    }

    fn exercise_value_instance_grants_hide_denied_search_matches(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object("note-value", "acme", "alpha", &[("body", "secret token")]),
            "editor",
        )
        .unwrap();
        let allowed = crate::sekai::object_security::value_instance_digest("public token").unwrap();
        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "note".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: Some(vec![crate::sekai::object_security::PropertyGrant {
                property: "body".into(),
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            }]),
            value_instance_grants: Some(vec![crate::sekai::object_security::ValueInstanceGrant {
                object_id: "note-value".into(),
                property: "body".into(),
                value_digest: allowed,
                access: crate::sekai::object_security::PropertyGrantAccess::Read,
            }]),
            required_purpose: None,
        };
        let revision = db
            .put_object_security_policy(&policy, "root", "put-value-grant", 1)
            .unwrap();
        db.activate_object_security_policies(
            "acme",
            &std::collections::BTreeMap::from([("note".into(), revision.revision_digest)]),
            "root",
            "activate-value-grant",
            2,
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "secret".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn value_instance_grants_hide_denied_search_matches() {
        exercise_value_instance_grants_hide_denied_search_matches(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_value_instance_grants_hide_denied_search_matches() {
        let (_scratch, db) = postgres_runtime();
        exercise_value_instance_grants_hide_denied_search_matches(&db);
    }

    fn exercise_dataset_candidates_honor_kind_filter(db: &RuntimeDb) {
        db.create_object_with_audit(&object("owner", "acme", "owner", &[]), "editor")
            .unwrap();
        db.create_dataset(&dataset("ds-kind", "ledger", "owner", &[("id", "public")]))
            .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "ledger".into(),
                source: None,
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    kinds: vec!["note".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());
        let datasets = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "ledger".into(),
                source: None,
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    kinds: vec!["dataset".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(datasets.len(), 1);
        assert_eq!(datasets[0].id, "ds-kind");
    }

    #[test]
    fn dataset_candidates_honor_kind_filter() {
        exercise_dataset_candidates_honor_kind_filter(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_dataset_candidates_honor_kind_filter() {
        let (_scratch, db) = postgres_runtime();
        exercise_dataset_candidates_honor_kind_filter(&db);
    }

    fn exercise_unbound_dataset_is_searchable_after_catalog_catch_up(db: &RuntimeDb) {
        db.create_dataset(&dataset(
            "ds-global",
            "shared-catalog",
            "",
            &[("id", "public")],
        ))
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "shared-catalog".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "ds-global");
    }

    #[test]
    fn unbound_dataset_is_searchable_after_catalog_catch_up() {
        exercise_unbound_dataset_is_searchable_after_catalog_catch_up(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_unbound_dataset_is_searchable_after_catalog_catch_up() {
        let (_scratch, db) = postgres_runtime();
        exercise_unbound_dataset_is_searchable_after_catalog_catch_up(&db);
    }

    fn exercise_team_principals_cannot_search_unbound_global_datasets(db: &RuntimeDb) {
        seed_team_principal(db, "team-agent");
        db.create_dataset(&dataset(
            "ds-global",
            "world catalog",
            "",
            &[("id", "public")],
        ))
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "world".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["team-agent".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());
        let visible = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "world".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "ds-global");
    }

    #[test]
    fn team_principals_cannot_search_unbound_global_datasets() {
        exercise_team_principals_cannot_search_unbound_global_datasets(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_team_principals_cannot_search_unbound_global_datasets() {
        let (_scratch, db) = postgres_runtime();
        exercise_team_principals_cannot_search_unbound_global_datasets(&db);
    }

    fn exercise_required_purpose_needs_a_verified_authorization_decision(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object(
                "note-purpose",
                "acme",
                "alpha",
                &[("body", "purpose token")],
            ),
            "editor",
        )
        .unwrap();
        let policy = crate::sekai::object_security::ObjectSecurityPolicy {
            contract_version: crate::sekai::object_security::OBJECT_SECURITY_POLICY_VERSION.into(),
            namespace: "acme".into(),
            kind: "note".into(),
            rules: vec![crate::sekai::object_security::ObjectSecurityRule {
                operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
                predicates: vec![crate::sekai::object_security::ObjectSecurityPredicate::AllowAll],
            }],
            property_grants: None,
            value_instance_grants: None,
            required_purpose: Some("finance".into()),
        };
        let revision = db
            .put_object_security_policy(&policy, "root", "put-purpose-search", 1)
            .unwrap();
        db.activate_object_security_policies(
            "acme",
            &std::collections::BTreeMap::from([("note".into(), revision.revision_digest)]),
            "root",
            "activate-purpose-search",
            2,
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let denied = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "purpose".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    purpose: Some("finance".into()),
                    purpose_authorized: false,
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(denied.is_empty());
        let allowed = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "purpose".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    subjects: vec!["editor".into()],
                    purpose: Some("finance".into()),
                    purpose_authorized: true,
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].id, "note-purpose");
    }

    #[test]
    fn required_purpose_needs_a_verified_authorization_decision() {
        exercise_required_purpose_needs_a_verified_authorization_decision(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_required_purpose_needs_a_verified_authorization_decision() {
        let (_scratch, db) = postgres_runtime();
        exercise_required_purpose_needs_a_verified_authorization_decision(&db);
    }

    fn exercise_live_dataset_binding_overrides_stale_index(db: &RuntimeDb) {
        let mut owner = object(
            "open-owner",
            "acme",
            "open",
            &[("access_marking", "public")],
        );
        db.create_object_with_audit(&owner, "editor").unwrap();
        db.create_dataset(&dataset(
            "ds-rebind",
            "ledger",
            "open-owner",
            &[("id", "public")],
        ))
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        owner
            .properties
            .insert("access_marking".into(), "restricted".into());
        owner.updated = 11;
        db.update_object_with_audit(&owner, "editor").unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "ledger".into(),
                source: Some(SearchSourceKind::Dataset),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    clearance: Some("internal".into()),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());
    }

    #[test]
    fn live_dataset_binding_overrides_stale_index() {
        exercise_live_dataset_binding_overrides_stale_index(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_live_dataset_binding_overrides_stale_index() {
        let (_scratch, db) = postgres_runtime();
        exercise_live_dataset_binding_overrides_stale_index(&db);
    }

    fn exercise_hidden_property_does_not_produce_a_candidate(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object(
                "note-hidden",
                "acme",
                "public name",
                &[("secret", "classified token"), ("body", "visible")],
            ),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let hidden = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "classified".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    visible_property_names: Some(vec!["body".into(), "name".into()]),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(hidden.is_empty());
        let visible = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "visible".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    visible_property_names: Some(vec!["body".into(), "name".into()]),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(visible.len(), 1);
    }

    #[test]
    fn hidden_property_does_not_produce_a_candidate() {
        exercise_hidden_property_does_not_produce_a_candidate(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_hidden_property_does_not_produce_a_candidate() {
        let (_scratch, db) = postgres_runtime();
        exercise_hidden_property_does_not_produce_a_candidate(&db);
    }

    fn exercise_empty_compiled_property_projection_fails_closed(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object(
                "note-proj",
                "acme",
                "title",
                &[("body", "visible token"), ("access_marking", "restricted")],
            ),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        let closed = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "visible".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    visible_property_names: Some(Vec::new()),
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(closed.is_empty());
        let policy_field = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "restricted".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(policy_field.is_empty());
    }

    #[test]
    fn empty_compiled_property_projection_fails_closed() {
        exercise_empty_compiled_property_projection_fails_closed(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_empty_compiled_property_projection_fails_closed() {
        let (_scratch, db) = postgres_runtime();
        exercise_empty_compiled_property_projection_fails_closed(&db);
    }

    fn exercise_lag_gauge_moves_with_unindexed_backlog(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object("note-lag", "acme", "lag", &[("body", "pending")]),
            "editor",
        )
        .unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let early = db.status("acme", now).unwrap();
        db.create_object_with_audit(
            &object("note-lag-2", "acme", "lag-two", &[("body", "more pending")]),
            "editor",
        )
        .unwrap();
        let later = db.status("acme", now + 5_000).unwrap();
        assert!(early.pending_changes > 0);
        assert!(later.lag_ms > early.lag_ms);
        assert!(crate::obs::metrics::search_index_lag_ms() >= later.lag_ms as u64);
        db.catch_up_search_namespace("acme", now + 5_000).unwrap();
        assert_eq!(db.status("acme", now + 5_000).unwrap().lag_ms, 0);
    }

    #[test]
    fn lag_gauge_moves_with_unindexed_backlog() {
        exercise_lag_gauge_moves_with_unindexed_backlog(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_lag_gauge_moves_with_unindexed_backlog() {
        let (_scratch, db) = postgres_runtime();
        exercise_lag_gauge_moves_with_unindexed_backlog(&db);
    }

    fn exercise_list_filter_keeps_namespace_isolation(db: &RuntimeDb) {
        db.create_object_with_audit(
            &object("note-a", "acme", "alpha", &[("body", "shared token")]),
            "editor",
        )
        .unwrap();
        db.create_object_with_audit(
            &object("note-b", "other", "beta", &[("body", "shared token")]),
            "editor",
        )
        .unwrap();
        db.catch_up_search_namespace("acme", 10).unwrap();
        db.catch_up_search_namespace("other", 10).unwrap();
        let hits = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "shared".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: true,
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert_eq!(
            hits.iter().map(|hit| hit.id.as_str()).collect::<Vec<_>>(),
            ["note-a"]
        );
        let denied = db
            .query_candidates(&SearchCandidateQuery {
                mode: SearchQueryMode::Text,
                text: "shared".into(),
                source: Some(SearchSourceKind::Object),
                policy: SearchPolicyFilter {
                    namespace: "acme".into(),
                    namespace_authorized: false,
                    subjects: vec!["editor".into()],
                    ..SearchPolicyFilter::default()
                },
                limit: 10,
            })
            .unwrap();
        assert!(denied.is_empty());
        let listed = db
            .list_objects(&ListFilter {
                namespace: Some("acme".into()),
                limit: 100,
                ..ListFilter::default()
            })
            .unwrap();
        assert!(listed.iter().all(|object| object.namespace == "acme"));
    }

    #[test]
    fn list_filter_keeps_namespace_isolation() {
        exercise_list_filter_keeps_namespace_isolation(&RuntimeDb::memory());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_list_filter_keeps_namespace_isolation() {
        let (_scratch, db) = postgres_runtime();
        exercise_list_filter_keeps_namespace_isolation(&db);
    }

    fn chunk(object_id: &str, marking: Option<&str>, vector: &[f32]) -> EmbeddingChunk {
        EmbeddingChunk {
            object_id: object_id.into(),
            chunk_index: 0,
            chunk_digest: String::new(),
            vector: vector.to_vec(),
            source: crate::sekai::embedding_index::EmbeddingSource {
                source_digest: String::new(),
                model: "m".into(),
                model_version: "v".into(),
                marking: marking.map(Into::into),
                classifications: Vec::new(),
            },
            embedded_at_ms: 0,
        }
    }

    fn vector_query(vector: &[f32], clearance: Option<&str>, limit: usize) -> VectorCandidateQuery {
        VectorCandidateQuery {
            spec_id: "notes".into(),
            vector: vector.to_vec(),
            policy: SearchPolicyFilter {
                namespace: "acme".into(),
                subjects: vec!["tester".into()],
                clearance: clearance.map(Into::into),
                ..Default::default()
            },
            limit,
        }
    }

    #[test]
    fn exact_vector_candidates_rank_best_chunk_and_drop_denied_markings_first() {
        let chunks = vec![
            chunk("near", Some("public"), &[1.0, 0.1]),
            chunk("far", None, &[0.0, 1.0]),
            // The object's best chunk ranks it.
            chunk("split", None, &[0.0, 1.0]),
            chunk("split", None, &[0.9, 0.1]),
            // Above the caller's clearance: never scored, never displaces.
            chunk("secret", Some("restricted"), &[1.0, 0.0]),
            // Another dimension cannot be compared.
            chunk("odd", None, &[1.0, 0.0, 0.0]),
        ];
        let query = vector_query(&[1.0, 0.0], Some("internal"), 10);
        let ranked = exact_vector_candidates(chunks.clone(), &query, None, |_| Ok(true)).unwrap();
        assert_eq!(
            ranked
                .iter()
                .map(|c| c.object_id.as_str())
                .collect::<Vec<_>>(),
            vec!["near", "split", "far"]
        );
        // The per-object policy applies before the limit: a denied object
        // never takes the place of an allowed one.
        let query = vector_query(&[1.0, 0.0], Some("internal"), 1);
        let top = exact_vector_candidates(chunks, &query, None, |candidate| {
            Ok(candidate.object_id != "near")
        })
        .unwrap();
        assert_eq!(
            top.iter().map(|c| c.object_id.as_str()).collect::<Vec<_>>(),
            vec!["split"]
        );
    }

    #[test]
    fn rrf_fuses_deterministically_and_a_zero_weight_list_adds_nothing() {
        let text = ["a", "b", "c"];
        let vector = ["c", "d", "a"];
        let fused = rrf_fuse(&[(&text[..], 1.0), (&vector[..], 1.0)]);
        // a: 1/61 + 1/63, c: 1/63 + 1/61 tie, broken by key; then b and d tie.
        assert_eq!(fused, vec!["a", "c", "b", "d"]);
        assert_eq!(fused, rrf_fuse(&[(&text[..], 1.0), (&vector[..], 1.0)]));
        assert_eq!(
            rrf_fuse(&[(&text[..], 0.0), (&vector[..], 1.0)]),
            vec!["c", "d", "a"]
        );
        assert_eq!(rrf_fuse(&[(&text[..], 1.0), (&vector[..], 3.0)])[0], "c");
    }

    /// The exact path's latency budget at 10^6 vectors (#1582): an ANN index
    /// is added behind `SearchIndex::vector_candidates` only if this fails.
    /// Run with `cargo test --release -- --ignored exact_vector_latency`.
    #[test]
    #[ignore = "latency budget at 10^6 vectors; run in release"]
    fn exact_vector_latency_budget_at_one_million_vectors() {
        const DIMENSION: usize = 64;
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % 2_000) as f32 / 1_000.0 - 1.0
        };
        let chunks = (0..1_000_000)
            .map(|index| {
                let vector = (0..DIMENSION).map(|_| next()).collect::<Vec<_>>();
                chunk(&format!("o{index:07}"), None, &vector)
            })
            .collect::<Vec<_>>();
        let query = (0..DIMENSION).map(|_| next()).collect::<Vec<_>>();
        let started = std::time::Instant::now();
        let ranked =
            exact_vector_candidates(chunks, &vector_query(&query, None, 256), None, |_| Ok(true))
                .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(ranked.len(), 256);
        assert!(elapsed < std::time::Duration::from_secs(2), "{elapsed:?}");
    }
}
