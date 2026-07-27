//! Reference adapter: translate one structured concept-catalog document into
//! admitted external evidence that the core `concept_catalog_v1` extractor can
//! turn into ontology-definition proposals.
//!
//! Collection, authentication, and source-system access stay outside Sekai core.
//! This adapter only maps a bounded JSON document into a `sekai.evidence/v1`
//! draft. It never writes ontology definitions or proposal state.

use crate::sdk::{ConformanceProfile, EvidenceDraft};
use chrono::DateTime;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

pub const EVIDENCE_TYPE: &str = "ontology.concept_catalog";
pub const SCHEMA_ID: &str = "adapter.ontology.concept_catalog";
pub const SCHEMA_VERSION: &str = "1.0.0";
pub const CONFORMANCE_PROFILE: ConformanceProfile = ConformanceProfile {
    source_type: "concept_catalog_document",
    evidence_type: EVIDENCE_TYPE,
    signal: "other",
    schema_id: SCHEMA_ID,
    schema_version: SCHEMA_VERSION,
    delivery: "document",
    requires_expiry: false,
};

#[derive(Debug, Deserialize)]
pub struct ConceptCatalogDocument {
    pub catalog_id: String,
    pub revised_at: String,
    #[serde(default)]
    pub revision: Option<i64>,
    #[serde(default)]
    pub classes: Vec<Value>,
    #[serde(default)]
    pub relations: Vec<Value>,
    #[serde(default)]
    pub source_system: Option<String>,
}

pub fn parse(input: &[u8]) -> Result<ConceptCatalogDocument, String> {
    serde_json::from_slice(input)
        .map_err(|error| format!("invalid concept catalog document: {error}"))
}

pub fn translate(document: ConceptCatalogDocument) -> Result<EvidenceDraft, String> {
    if document.catalog_id.trim().is_empty() {
        return Err("catalog_id is required".into());
    }
    if document.classes.is_empty() && document.relations.is_empty() {
        return Err("concept catalog must declare at least one class or relation".into());
    }
    let observed_at_ms = parse_timestamp(&document.revised_at)?;
    let source_sequence = document.revision.unwrap_or(observed_at_ms);
    let content = json!({
        "classes": document.classes,
        "relations": document.relations,
    });
    Ok(EvidenceDraft {
        source_type: "concept_catalog_document".into(),
        source_record_id: document.catalog_id.clone(),
        source_version: document.revised_at.clone(),
        source_sequence,
        evidence_type: EVIDENCE_TYPE.into(),
        signal: "other".into(),
        schema_id: SCHEMA_ID.into(),
        schema_version: SCHEMA_VERSION.into(),
        observed_at_ms,
        expires_at_ms: None,
        content,
        relationships: vec![],
        confidence_bps: 8_500,
        provenance: HashMap::from([
            ("adapter".into(), "ontology_concept_catalog/v1".into()),
            ("delivery".into(), "document".into()),
            ("catalog_id".into(), document.catalog_id),
            (
                "source_system".into(),
                document.source_system.unwrap_or_else(|| "reference".into()),
            ),
        ]),
        causality: None,
    })
}

fn parse_timestamp(value: &str) -> Result<i64, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp_millis())
        .map_err(|error| format!("invalid revised_at timestamp: {error}"))
}
