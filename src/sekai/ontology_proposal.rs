//! Governed ontology-definition proposals derived from admitted external evidence
//! (issue #147).
//!
//! Proposals suggest classes, class properties, or relations. Dry-run extraction
//! never mutates ontology definitions or the proposal store. Acceptance applies
//! definitions through the normal #141 validation, authorization, audit, and
//! mutation path. Sensitive source content is never copied into proposal rows,
//! lifecycle events, or audit evidence beyond bounded citations.

use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use crate::sekai::evidence::EvidenceLifecycleState;
use crate::sekai::ontology::{
    OntologyClass, OntologyProperty, OntologyRegistry, OntologyRelation, validate_class_definition,
    validate_relation_definition,
};
use crate::sekai::schema::PropertyType;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

pub const ONTOLOGY_PROPOSAL_CONTRACT_VERSION: &str = "sekai.ontology_proposal/v1";
pub const EXTRACTOR_CONCEPT_CATALOG_V1: &str = "concept_catalog_v1";
pub const EVIDENCE_TYPE_CONCEPT_CATALOG: &str = "ontology.concept_catalog";
pub const SCHEMA_ID_CONCEPT_CATALOG: &str = "adapter.ontology.concept_catalog";
pub const SCHEMA_VERSION_CONCEPT_CATALOG: &str = "1.0.0";

/// What kind of ontology definition a proposal would introduce or update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDefinitionKind {
    Class,
    Relation,
    ClassProperty,
}

impl ProposalDefinitionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Relation => "relation",
            Self::ClassProperty => "class_property",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "class" => Self::Class,
            "relation" => Self::Relation,
            "class_property" => Self::ClassProperty,
            _ => return None,
        })
    }
}

/// Lifecycle of a versioned ontology-definition proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalLifecycleState {
    Proposed,
    Accepted,
    Rejected,
    Superseded,
}

impl ProposalLifecycleState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "proposed" => Self::Proposed,
            "accepted" => Self::Accepted,
            "rejected" => Self::Rejected,
            "superseded" => Self::Superseded,
            _ => return None,
        })
    }

    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Proposed)
    }
}

/// Human review action for a proposal awaiting review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalReviewAction {
    Accept,
    Reject,
    Supersede,
}

impl ProposalReviewAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Supersede => "supersede",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "accept" => Self::Accept,
            "reject" => Self::Reject,
            "supersede" => Self::Supersede,
            _ => return None,
        })
    }
}

/// Bounded citation of an admitted evidence submission. Never carries content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCitation {
    pub submission_id: String,
    pub content_digest: String,
    pub evidence_type: String,
    pub source_type: String,
    pub source_instance: String,
    pub source_record_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalVersionRef {
    pub proposal_id: String,
    pub version: u32,
}

/// Payload a proposal would apply through the normal ontology mutation path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposedDefinition {
    Class {
        class: OntologyClass,
    },
    Relation {
        relation: OntologyRelation,
    },
    ClassProperty {
        class_name: String,
        property: OntologyProperty,
    },
}

impl ProposedDefinition {
    pub fn kind(&self) -> ProposalDefinitionKind {
        match self {
            Self::Class { .. } => ProposalDefinitionKind::Class,
            Self::Relation { .. } => ProposalDefinitionKind::Relation,
            Self::ClassProperty { .. } => ProposalDefinitionKind::ClassProperty,
        }
    }

    pub fn definition_name(&self) -> &str {
        match self {
            Self::Class { class } => class.name.as_str(),
            Self::Relation { relation } => relation.name.as_str(),
            Self::ClassProperty { class_name, .. } => class_name.as_str(),
        }
    }
}

/// Versioned ontology-definition proposal retained for human review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OntologyDefinitionProposal {
    pub contract_version: String,
    pub id: String,
    pub version: u32,
    pub state: ProposalLifecycleState,
    pub definition: ProposedDefinition,
    pub sources: Vec<SourceCitation>,
    pub extractor_id: String,
    pub extractor_config: BTreeMap<String, String>,
    pub model_config: BTreeMap<String, String>,
    pub confidence_bps: u16,
    pub authorization_context: String,
    pub proposer: String,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<ProposalVersionRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_definition_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalLifecycleEvent {
    pub proposal_id: String,
    pub proposal_version: u32,
    pub action: String,
    pub from_state: Option<String>,
    pub to_state: String,
    pub actor: String,
    pub reason: String,
    pub recorded_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ExtractorConfig {
    pub extractor_id: String,
    pub config: BTreeMap<String, String>,
    pub model_config: BTreeMap<String, String>,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            extractor_id: EXTRACTOR_CONCEPT_CATALOG_V1.into(),
            config: BTreeMap::new(),
            model_config: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProposeOntologyDefinitionsRequest {
    pub submission_ids: Vec<String>,
    pub extractor: ExtractorConfig,
    pub authorization_context: String,
    pub proposer: String,
    pub dry_run: bool,
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ProposeOntologyDefinitionsResult {
    pub proposals: Vec<OntologyDefinitionProposal>,
    pub dry_run: bool,
    pub persisted: bool,
}

#[derive(Debug, Clone)]
pub struct OntologyProposalReview {
    pub action: ProposalReviewAction,
    pub reviewer: String,
    pub rationale: String,
    pub reviewed_at_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ProposalFilter {
    pub state: Option<ProposalLifecycleState>,
    pub kind: Option<ProposalDefinitionKind>,
    pub limit: i32,
    pub offset: i32,
}

/// Deterministic proposal identity from kind, definition name, extractor, and
/// ordered source submission citations. Content is never part of the identity.
pub fn proposal_identity(
    kind: ProposalDefinitionKind,
    definition_name: &str,
    extractor_id: &str,
    sources: &[SourceCitation],
) -> String {
    let mut digest = Sha256::new();
    for value in [
        ONTOLOGY_PROPOSAL_CONTRACT_VERSION.as_bytes(),
        kind.as_str().as_bytes(),
        definition_name.as_bytes(),
        extractor_id.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    for source in sources {
        for value in [
            source.submission_id.as_bytes(),
            source.content_digest.as_bytes(),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
    }
    format!("odp-{:x}", digest.finalize())
}

/// Extract ontology-definition proposals from one admitted concept-catalog
/// evidence payload. Heuristic and fully deterministic; not a model.
pub fn extract_from_concept_catalog(
    content: &Value,
    sources: &[SourceCitation],
    extractor: &ExtractorConfig,
    authorization_context: &str,
    proposer: &str,
    now_ms: i64,
) -> Result<Vec<OntologyDefinitionProposal>, String> {
    if extractor.extractor_id != EXTRACTOR_CONCEPT_CATALOG_V1 {
        return Err(format!(
            "unsupported extractor '{}'; only {EXTRACTOR_CONCEPT_CATALOG_V1} is available",
            extractor.extractor_id
        ));
    }
    if sources.is_empty() {
        return Err("at least one source citation is required".into());
    }
    let default_confidence = extractor
        .config
        .get("default_confidence_bps")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8_000);

    let mut proposals = Vec::new();
    let classes = content
        .get("classes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in classes {
        let name = required_string(&entry, "name")?;
        let description = optional_string(&entry, "description");
        let superclasses = string_array(&entry, "superclasses");
        let equivalent_classes = string_array(&entry, "equivalent_classes");
        let disjoint_classes = string_array(&entry, "disjoint_classes");
        let mapped_kind = optional_string(&entry, "mapped_kind");
        let properties = parse_properties(entry.get("properties"))?;
        let confidence = entry
            .get("confidence_bps")
            .and_then(Value::as_u64)
            .map(|value| value.min(10_000) as u16)
            .unwrap_or(default_confidence);

        // Standalone property-only entries are encoded as class shells with a
        // single property and `proposal_kind = class_property`.
        let proposal_kind = entry
            .get("proposal_kind")
            .and_then(Value::as_str)
            .unwrap_or("class");
        if proposal_kind == "class_property" {
            if properties.len() != 1 {
                return Err(format!(
                    "class_property proposal for '{name}' must declare exactly one property"
                ));
            }
            let property = properties[0].clone();
            let definition = ProposedDefinition::ClassProperty {
                class_name: name.clone(),
                property,
            };
            proposals.push(build_proposal(
                definition,
                sources,
                extractor,
                confidence,
                authorization_context,
                proposer,
                now_ms,
            ));
            continue;
        }

        let class = OntologyClass {
            name,
            description,
            superclasses,
            equivalent_classes,
            disjoint_classes,
            properties,
            is_builtin: false,
            mapped_kind,
        };
        proposals.push(build_proposal(
            ProposedDefinition::Class { class },
            sources,
            extractor,
            confidence,
            authorization_context,
            proposer,
            now_ms,
        ));
    }

    let relations = content
        .get("relations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in relations {
        let name = required_string(&entry, "name")?;
        let description = optional_string(&entry, "description");
        let domain = required_string(&entry, "domain")?;
        let range = required_string(&entry, "range")?;
        let inverse = optional_string(&entry, "inverse");
        let transitive = entry
            .get("transitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mapped_relation = optional_string(&entry, "mapped_relation");
        let confidence = entry
            .get("confidence_bps")
            .and_then(Value::as_u64)
            .map(|value| value.min(10_000) as u16)
            .unwrap_or(default_confidence);
        let relation = OntologyRelation {
            name,
            description,
            domain,
            range,
            cardinality: Default::default(),
            inverse,
            transitive,
            is_builtin: false,
            mapped_relation,
        };
        proposals.push(build_proposal(
            ProposedDefinition::Relation { relation },
            sources,
            extractor,
            confidence,
            authorization_context,
            proposer,
            now_ms,
        ));
    }

    if proposals.is_empty() {
        return Err("concept catalog produced no class, property, or relation proposals".into());
    }

    // Stable order: classes, class properties, then relations; each by name.
    proposals.sort_by(|left, right| {
        let left_key = (
            left.definition.kind().as_str(),
            left.definition.definition_name(),
        );
        let right_key = (
            right.definition.kind().as_str(),
            right.definition.definition_name(),
        );
        left_key.cmp(&right_key)
    });
    Ok(proposals)
}

fn build_proposal(
    definition: ProposedDefinition,
    sources: &[SourceCitation],
    extractor: &ExtractorConfig,
    confidence_bps: u16,
    authorization_context: &str,
    proposer: &str,
    now_ms: i64,
) -> OntologyDefinitionProposal {
    let id = proposal_identity(
        definition.kind(),
        definition.definition_name(),
        &extractor.extractor_id,
        sources,
    );
    OntologyDefinitionProposal {
        contract_version: ONTOLOGY_PROPOSAL_CONTRACT_VERSION.into(),
        id,
        version: 1,
        state: ProposalLifecycleState::Proposed,
        definition,
        sources: sources.to_vec(),
        extractor_id: extractor.extractor_id.clone(),
        extractor_config: extractor.config.clone(),
        model_config: extractor.model_config.clone(),
        confidence_bps,
        authorization_context: authorization_context.trim().to_string(),
        proposer: proposer.trim().to_string(),
        created_at_ms: now_ms,
        reviewed_at_ms: None,
        reviewer: None,
        rationale: None,
        supersedes: None,
        applied_definition_name: None,
    }
}

fn required_string(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("concept catalog entry missing required string field '{field}'"))
}

fn optional_string(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_properties(value: Option<&Value>) -> Result<Vec<OntologyProperty>, String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut properties = Vec::with_capacity(items.len());
    for item in items {
        let name = required_string(item, "name")?;
        let type_name = item
            .get("type")
            .or_else(|| item.get("prop_type"))
            .and_then(Value::as_str)
            .unwrap_or("string");
        let prop_type = PropertyType::parse(type_name)
            .ok_or_else(|| format!("unsupported property type '{type_name}' on '{name}'"))?;
        properties.push(OntologyProperty {
            name,
            prop_type,
            required: item
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            description: optional_string(item, "description"),
        });
    }
    Ok(properties)
}

impl SekaiDb {
    pub(crate) fn migrate_ontology_proposals(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_ontology_definition_proposals (
                id TEXT NOT NULL,
                version INTEGER NOT NULL,
                state TEXT NOT NULL,
                kind TEXT NOT NULL,
                definition_name TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                reviewed_at_ms INTEGER,
                PRIMARY KEY (id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_ontology_proposals_state
                ON sekai_ontology_definition_proposals(state, created_at_ms);
            CREATE INDEX IF NOT EXISTS idx_ontology_proposals_name
                ON sekai_ontology_definition_proposals(definition_name, kind);
            CREATE TABLE IF NOT EXISTS sekai_ontology_definition_proposal_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_id TEXT NOT NULL,
                proposal_version INTEGER NOT NULL,
                action TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                recorded_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ontology_proposal_events
                ON sekai_ontology_definition_proposal_events(proposal_id, proposal_version, id);",
        )
        .map_err(|error| error.to_string())
    }

    /// Extract proposals from admitted evidence submissions. When `dry_run` is
    /// true, nothing is persisted and ontology definitions are never mutated.
    pub fn propose_ontology_definitions_from_evidence(
        &self,
        request: &ProposeOntologyDefinitionsRequest,
    ) -> Result<ProposeOntologyDefinitionsResult, String> {
        if request.proposer.trim().is_empty() {
            return Err("proposer is required".into());
        }
        if request.authorization_context.trim().is_empty() {
            return Err("authorization_context is required".into());
        }
        if request.submission_ids.is_empty() {
            return Err("at least one admitted evidence submission id is required".into());
        }
        if looks_like_secret(&request.authorization_context)
            || request
                .extractor
                .config
                .values()
                .chain(request.extractor.model_config.values())
                .any(|value| looks_like_secret(value))
        {
            return Err(
                "authorization_context and extractor/model config must not contain secret material"
                    .into(),
            );
        }

        let mut sources = Vec::new();
        let mut contents = Vec::new();
        for submission_id in &request.submission_ids {
            let submission = self
                .get_evidence_submission(submission_id)?
                .ok_or_else(|| format!("evidence submission '{submission_id}' not found"))?;
            if !submission_usable_for_proposals(&submission.lifecycle_state) {
                return Err(format!(
                    "evidence submission '{submission_id}' is not admitted usable (state={})",
                    submission.lifecycle_state.as_str()
                ));
            }
            let envelope = submission
                .envelope
                .as_ref()
                .ok_or_else(|| format!("evidence submission '{submission_id}' has no envelope"))?;
            if envelope.evidence_type != EVIDENCE_TYPE_CONCEPT_CATALOG
                && request.extractor.extractor_id == EXTRACTOR_CONCEPT_CATALOG_V1
            {
                return Err(format!(
                    "evidence submission '{submission_id}' has type '{}'; extractor {} expects {EVIDENCE_TYPE_CONCEPT_CATALOG}",
                    envelope.evidence_type, EXTRACTOR_CONCEPT_CATALOG_V1
                ));
            }
            sources.push(SourceCitation {
                submission_id: submission.id.clone(),
                content_digest: submission.content_digest.clone(),
                evidence_type: submission.evidence_type.clone(),
                source_type: submission.source_type.clone(),
                source_instance: submission.source_instance.clone(),
                source_record_id: submission.source_record_id.clone(),
            });
            contents.push(envelope.content.clone());
        }

        // Merge admitted catalogs in submission order so multi-source proposals
        // remain deterministic without inventing conflict resolution policy.
        let mut merged = serde_json::json!({
            "classes": [],
            "relations": []
        });
        for content in &contents {
            if let Some(classes) = content.get("classes").and_then(Value::as_array) {
                let target = merged
                    .get_mut("classes")
                    .and_then(Value::as_array_mut)
                    .expect("classes array");
                target.extend(classes.iter().cloned());
            }
            if let Some(relations) = content.get("relations").and_then(Value::as_array) {
                let target = merged
                    .get_mut("relations")
                    .and_then(Value::as_array_mut)
                    .expect("relations array");
                target.extend(relations.iter().cloned());
            }
        }

        let proposals = extract_from_concept_catalog(
            &merged,
            &sources,
            &request.extractor,
            &request.authorization_context,
            &request.proposer,
            request.now_ms,
        )?;

        if request.dry_run {
            return Ok(ProposeOntologyDefinitionsResult {
                proposals,
                dry_run: true,
                persisted: false,
            });
        }

        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut stored = Vec::with_capacity(proposals.len());
        for proposal in &proposals {
            stored.push(insert_proposal_row(&tx, proposal)?);
            insert_proposal_event(
                &tx,
                &ProposalLifecycleEvent {
                    proposal_id: proposal.id.clone(),
                    proposal_version: proposal.version,
                    action: "proposed".into(),
                    from_state: None,
                    to_state: ProposalLifecycleState::Proposed.as_str().into(),
                    actor: request.proposer.trim().into(),
                    reason: format!(
                        "extracted by {} from {} source citation(s)",
                        proposal.extractor_id,
                        proposal.sources.len()
                    ),
                    recorded_at_ms: request.now_ms,
                },
            )?;
            insert_proposal_audit(
                &tx,
                request.proposer.trim(),
                "ontology.proposal.create",
                &format!("ontology:proposal:{}:{}", proposal.id, proposal.version),
                proposal,
                "proposed",
                request.now_ms,
            )?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(ProposeOntologyDefinitionsResult {
            proposals: stored,
            dry_run: false,
            persisted: true,
        })
    }

    pub fn get_ontology_definition_proposal(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Option<OntologyDefinitionProposal>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT proposal_json FROM sekai_ontology_definition_proposals
             WHERE id=?1 AND version=?2",
            params![id, version],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
        .transpose()
    }

    pub fn list_ontology_definition_proposals(
        &self,
        filter: &ProposalFilter,
    ) -> Result<Vec<OntologyDefinitionProposal>, String> {
        let conn = self.conn();
        let mut sql =
            "SELECT proposal_json FROM sekai_ontology_definition_proposals WHERE 1=1".to_string();
        let mut binds: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(state) = filter.state {
            sql.push_str(&format!(" AND state=?{}", binds.len() + 1));
            binds.push(Box::new(state.as_str().to_string()));
        }
        if let Some(kind) = filter.kind {
            sql.push_str(&format!(" AND kind=?{}", binds.len() + 1));
            binds.push(Box::new(kind.as_str().to_string()));
        }
        let limit = if filter.limit <= 0 { 100 } else { filter.limit };
        let offset = filter.offset.max(0);
        sql.push_str(&format!(
            " ORDER BY created_at_ms ASC, id ASC, version ASC LIMIT ?{} OFFSET ?{}",
            binds.len() + 1,
            binds.len() + 2
        ));
        binds.push(Box::new(limit));
        binds.push(Box::new(offset));
        let mut statement = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            binds.iter().map(|value| value.as_ref()).collect();
        let rows = statement
            .query_map(params_refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let mut proposals = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            proposals.push(serde_json::from_str(&json).map_err(|error| error.to_string())?);
        }
        Ok(proposals)
    }

    pub fn list_ontology_definition_proposal_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<ProposalLifecycleEvent>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT proposal_id, proposal_version, action, from_state, to_state, actor, reason,
                        recorded_at_ms
                 FROM sekai_ontology_definition_proposal_events
                 WHERE proposal_id=?1 AND proposal_version=?2
                 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![id, version], |row| {
                Ok(ProposalLifecycleEvent {
                    proposal_id: row.get(0)?,
                    proposal_version: row.get(1)?,
                    action: row.get(2)?,
                    from_state: row.get(3)?,
                    to_state: row.get(4)?,
                    actor: row.get(5)?,
                    reason: row.get(6)?,
                    recorded_at_ms: row.get(7)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    /// Accept, reject, or supersede a proposal. Acceptance applies the
    /// definition through the normal ontology validation and audited mutation
    /// path. Rejection and dry-run paths never mutate ontology definitions.
    pub fn review_ontology_definition_proposal(
        &self,
        id: &str,
        version: u32,
        review: OntologyProposalReview,
    ) -> Result<OntologyDefinitionProposal, String> {
        if review.reviewer.trim().is_empty() || review.rationale.trim().is_empty() {
            return Err("reviewer and rationale are required".into());
        }
        if looks_like_secret(&review.rationale) {
            return Err("review rationale must not contain secret material".into());
        }

        let proposal = self
            .get_ontology_definition_proposal(id, version)?
            .ok_or_else(|| format!("proposal {id} version {version} not found"))?;

        // Idempotent replay of a completed review with the same terminal state.
        if proposal.state.is_terminal() {
            return replay_terminal_review(&proposal, &review);
        }
        if proposal.state != ProposalLifecycleState::Proposed {
            return Err(format!(
                "proposal is not awaiting review (state={})",
                proposal.state.as_str()
            ));
        }

        match review.action {
            ProposalReviewAction::Reject => self.apply_reject_proposal(proposal, review),
            ProposalReviewAction::Accept | ProposalReviewAction::Supersede => {
                if review.action == ProposalReviewAction::Supersede && proposal.supersedes.is_none()
                {
                    // Supersede without explicit lineage still accepts this
                    // proposal and retires any other proposed version for the
                    // same definition name/kind that is not this row.
                    // Lineage may also be supplied on the proposal itself.
                }
                self.apply_accept_proposal(proposal, review)
            }
        }
    }

    fn apply_reject_proposal(
        &self,
        mut proposal: OntologyDefinitionProposal,
        review: OntologyProposalReview,
    ) -> Result<OntologyDefinitionProposal, String> {
        let from_state = proposal.state;
        proposal.state = ProposalLifecycleState::Rejected;
        proposal.reviewed_at_ms = Some(review.reviewed_at_ms);
        proposal.reviewer = Some(review.reviewer.trim().into());
        proposal.rationale = Some(review.rationale.trim().into());

        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        update_proposal_row(&tx, &proposal, from_state)?;
        insert_proposal_event(
            &tx,
            &ProposalLifecycleEvent {
                proposal_id: proposal.id.clone(),
                proposal_version: proposal.version,
                action: "rejected".into(),
                from_state: Some(from_state.as_str().into()),
                to_state: ProposalLifecycleState::Rejected.as_str().into(),
                actor: review.reviewer.trim().into(),
                reason: review.rationale.trim().into(),
                recorded_at_ms: review.reviewed_at_ms,
            },
        )?;
        insert_proposal_audit(
            &tx,
            review.reviewer.trim(),
            "ontology.proposal.reject",
            &format!("ontology:proposal:{}:{}", proposal.id, proposal.version),
            &proposal,
            "rejected",
            review.reviewed_at_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(proposal)
    }

    fn apply_accept_proposal(
        &self,
        mut proposal: OntologyDefinitionProposal,
        review: OntologyProposalReview,
    ) -> Result<OntologyDefinitionProposal, String> {
        // Re-validate every cited source remains usable and digest-stable.
        for source in &proposal.sources {
            let submission = self
                .get_evidence_submission(&source.submission_id)?
                .ok_or_else(|| {
                    format!(
                        "stale source: evidence submission '{}' not found",
                        source.submission_id
                    )
                })?;
            if !submission_usable_for_proposals(&submission.lifecycle_state) {
                return Err(format!(
                    "stale source: evidence submission '{}' is {} (no longer usable for acceptance)",
                    source.submission_id,
                    submission.lifecycle_state.as_str()
                ));
            }
            if submission.content_digest != source.content_digest {
                return Err(format!(
                    "stale source: evidence submission '{}' content digest changed",
                    source.submission_id
                ));
            }
        }

        let registry = self.load_ontology_registry()?;
        let applied_name =
            validate_and_materialize_definition(self, &proposal, &registry, &review)?;

        let from_state = proposal.state;
        proposal.state = ProposalLifecycleState::Accepted;
        proposal.reviewed_at_ms = Some(review.reviewed_at_ms);
        proposal.reviewer = Some(review.reviewer.trim().into());
        proposal.rationale = Some(review.rationale.trim().into());
        proposal.applied_definition_name = Some(applied_name);

        // Supersede prior proposed/accepted proposals for the same definition
        // when lineage is declared or the review action is supersede.
        let to_supersede = collect_supersede_targets(self, &proposal, review.action)?;

        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        update_proposal_row(&tx, &proposal, from_state)?;
        for mut prior in to_supersede {
            let prior_from = prior.state;
            prior.state = ProposalLifecycleState::Superseded;
            prior.reviewed_at_ms = Some(review.reviewed_at_ms);
            prior.reviewer = Some(review.reviewer.trim().into());
            prior.rationale = Some(format!(
                "superseded by {}@{}: {}",
                proposal.id,
                proposal.version,
                review.rationale.trim()
            ));
            update_proposal_row(&tx, &prior, prior_from)?;
            insert_proposal_event(
                &tx,
                &ProposalLifecycleEvent {
                    proposal_id: prior.id.clone(),
                    proposal_version: prior.version,
                    action: "superseded".into(),
                    from_state: Some(prior_from.as_str().into()),
                    to_state: ProposalLifecycleState::Superseded.as_str().into(),
                    actor: review.reviewer.trim().into(),
                    reason: format!(
                        "superseded by {}@{}: {}",
                        proposal.id,
                        proposal.version,
                        review.rationale.trim()
                    ),
                    recorded_at_ms: review.reviewed_at_ms,
                },
            )?;
            insert_proposal_audit(
                &tx,
                review.reviewer.trim(),
                "ontology.proposal.supersede",
                &format!("ontology:proposal:{}:{}", prior.id, prior.version),
                &prior,
                "superseded",
                review.reviewed_at_ms,
            )?;
        }
        insert_proposal_event(
            &tx,
            &ProposalLifecycleEvent {
                proposal_id: proposal.id.clone(),
                proposal_version: proposal.version,
                action: if review.action == ProposalReviewAction::Supersede {
                    "supersede_accept".into()
                } else {
                    "accepted".into()
                },
                from_state: Some(from_state.as_str().into()),
                to_state: ProposalLifecycleState::Accepted.as_str().into(),
                actor: review.reviewer.trim().into(),
                reason: review.rationale.trim().into(),
                recorded_at_ms: review.reviewed_at_ms,
            },
        )?;
        insert_proposal_audit(
            &tx,
            review.reviewer.trim(),
            "ontology.proposal.accept",
            &format!("ontology:proposal:{}:{}", proposal.id, proposal.version),
            &proposal,
            "accepted",
            review.reviewed_at_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(proposal)
    }
}

fn submission_usable_for_proposals(state: &EvidenceLifecycleState) -> bool {
    matches!(
        state,
        EvidenceLifecycleState::Authorized
            | EvidenceLifecycleState::Projected
            | EvidenceLifecycleState::Available
    )
}

fn replay_terminal_review(
    proposal: &OntologyDefinitionProposal,
    review: &OntologyProposalReview,
) -> Result<OntologyDefinitionProposal, String> {
    let expected = match review.action {
        ProposalReviewAction::Reject => ProposalLifecycleState::Rejected,
        ProposalReviewAction::Accept | ProposalReviewAction::Supersede => {
            ProposalLifecycleState::Accepted
        }
    };
    if proposal.state != expected {
        return Err(format!(
            "proposal already in terminal state '{}' which conflicts with review action '{}'",
            proposal.state.as_str(),
            review.action.as_str()
        ));
    }
    // Idempotent success: return the stored terminal proposal unchanged.
    Ok(proposal.clone())
}

fn validate_and_materialize_definition(
    db: &SekaiDb,
    proposal: &OntologyDefinitionProposal,
    registry: &OntologyRegistry,
    review: &OntologyProposalReview,
) -> Result<String, String> {
    match &proposal.definition {
        ProposedDefinition::Class { class } => {
            let existing = registry.get_class(&class.name).cloned();
            let mut working = registry.clone();
            working.remove_class(&class.name);
            validate_class_definition(class, existing.as_ref(), &working)?;
            db.upsert_ontology_class_with_audit(class, review.reviewer.trim())?;
            Ok(class.name.clone())
        }
        ProposedDefinition::Relation { relation } => {
            let existing = registry.get_relation(&relation.name).cloned();
            validate_relation_definition(relation, existing.as_ref(), registry)?;
            db.upsert_ontology_relation_with_audit(relation, review.reviewer.trim())?;
            Ok(relation.name.clone())
        }
        ProposedDefinition::ClassProperty {
            class_name,
            property,
        } => {
            let mut class = registry.get_class(class_name).cloned().ok_or_else(|| {
                format!("cannot accept class property: class '{class_name}' does not exist")
            })?;
            if let Some(index) = class
                .properties
                .iter()
                .position(|existing| existing.name == property.name)
            {
                class.properties[index] = property.clone();
            } else {
                class.properties.push(property.clone());
            }
            let existing = registry.get_class(class_name).cloned();
            let mut working = registry.clone();
            working.remove_class(class_name);
            validate_class_definition(&class, existing.as_ref(), &working)?;
            db.upsert_ontology_class_with_audit(&class, review.reviewer.trim())?;
            Ok(class_name.clone())
        }
    }
}

fn collect_supersede_targets(
    db: &SekaiDb,
    proposal: &OntologyDefinitionProposal,
    action: ProposalReviewAction,
) -> Result<Vec<OntologyDefinitionProposal>, String> {
    let mut targets = Vec::new();
    if let Some(reference) = &proposal.supersedes {
        let prior = db
            .get_ontology_definition_proposal(&reference.proposal_id, reference.version)?
            .ok_or_else(|| {
                format!(
                    "superseded proposal {}@{} not found",
                    reference.proposal_id, reference.version
                )
            })?;
        if prior.state != ProposalLifecycleState::Proposed
            && prior.state != ProposalLifecycleState::Accepted
        {
            return Err(format!(
                "cannot supersede proposal in state {}",
                prior.state.as_str()
            ));
        }
        targets.push(prior);
    }
    if action == ProposalReviewAction::Supersede {
        let candidates = db.list_ontology_definition_proposals(&ProposalFilter {
            state: None,
            kind: Some(proposal.definition.kind()),
            limit: 1_000,
            offset: 0,
        })?;
        for candidate in candidates {
            if candidate.id == proposal.id && candidate.version == proposal.version {
                continue;
            }
            if candidate.definition.definition_name() != proposal.definition.definition_name() {
                continue;
            }
            if candidate.state == ProposalLifecycleState::Proposed
                || candidate.state == ProposalLifecycleState::Accepted
            {
                if targets.iter().any(|existing| {
                    existing.id == candidate.id && existing.version == candidate.version
                }) {
                    continue;
                }
                targets.push(candidate);
            }
        }
    }
    Ok(targets)
}

fn insert_proposal_row(
    tx: &Transaction<'_>,
    proposal: &OntologyDefinitionProposal,
) -> Result<OntologyDefinitionProposal, String> {
    let json = serde_json::to_string(proposal).map_err(|error| error.to_string())?;
    // Idempotent insert: identical payload for the same id/version is accepted.
    let existing: Option<String> = tx
        .query_row(
            "SELECT proposal_json FROM sekai_ontology_definition_proposals
             WHERE id=?1 AND version=?2",
            params![proposal.id, proposal.version],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if let Some(existing_json) = existing {
        let existing_proposal: OntologyDefinitionProposal =
            serde_json::from_str(&existing_json).map_err(|error| error.to_string())?;
        if existing_proposal != *proposal {
            return Err(format!(
                "proposal {}@{} already exists with different content",
                proposal.id, proposal.version
            ));
        }
        return Ok(existing_proposal);
    }
    tx.execute(
        "INSERT INTO sekai_ontology_definition_proposals
            (id, version, state, kind, definition_name, proposal_json, created_at_ms, reviewed_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            proposal.id,
            proposal.version,
            proposal.state.as_str(),
            proposal.definition.kind().as_str(),
            proposal.definition.definition_name(),
            json,
            proposal.created_at_ms,
            proposal.reviewed_at_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(proposal.clone())
}

fn update_proposal_row(
    tx: &Transaction<'_>,
    proposal: &OntologyDefinitionProposal,
    expected_from: ProposalLifecycleState,
) -> Result<(), String> {
    let json = serde_json::to_string(proposal).map_err(|error| error.to_string())?;
    let updated = tx
        .execute(
            "UPDATE sekai_ontology_definition_proposals
             SET state=?1, proposal_json=?2, reviewed_at_ms=?3
             WHERE id=?4 AND version=?5 AND state=?6",
            params![
                proposal.state.as_str(),
                json,
                proposal.reviewed_at_ms,
                proposal.id,
                proposal.version,
                expected_from.as_str(),
            ],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("proposal changed during review".into());
    }
    Ok(())
}

fn insert_proposal_event(
    tx: &Transaction<'_>,
    event: &ProposalLifecycleEvent,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_ontology_definition_proposal_events
            (proposal_id, proposal_version, action, from_state, to_state, actor, reason, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            event.proposal_id,
            event.proposal_version,
            event.action,
            event.from_state,
            event.to_state,
            event.actor,
            event.reason,
            event.recorded_at_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

/// Audit records cite proposal identity, extractor, confidence, and source
/// submission ids/digests only — never raw evidence content.
fn insert_proposal_audit(
    tx: &Transaction<'_>,
    actor: &str,
    action: &str,
    target_id: &str,
    proposal: &OntologyDefinitionProposal,
    outcome: &str,
    timestamp: i64,
) -> Result<(), String> {
    let source_ids = proposal
        .sources
        .iter()
        .map(|source| source.submission_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let source_digests = proposal
        .sources
        .iter()
        .map(|source| source.content_digest.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let mut evidence = HashMap::from([
        ("proposal_id".into(), proposal.id.clone()),
        ("proposal_version".into(), proposal.version.to_string()),
        (
            "definition_kind".into(),
            proposal.definition.kind().as_str().into(),
        ),
        (
            "definition_name".into(),
            proposal.definition.definition_name().into(),
        ),
        ("extractor_id".into(), proposal.extractor_id.clone()),
        ("confidence_bps".into(), proposal.confidence_bps.to_string()),
        (
            "authorization_context".into(),
            proposal.authorization_context.clone(),
        ),
        ("source_submission_ids".into(), source_ids),
        ("source_content_digests".into(), source_digests),
        ("data_class".into(), "unclassified".into()),
    ]);
    if !proposal.model_config.is_empty() {
        evidence.insert(
            "model_config_keys".into(),
            proposal
                .model_config
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    crate::sekai::ledger::insert_chained_decision(
        tx,
        &Decision {
            id: format!("ontology-proposal-audit-{}", Uuid::new_v4().simple()),
            timestamp,
            actor: actor.to_string(),
            action: action.to_string(),
            reason: "ontology definition proposal lifecycle".into(),
            evidence,
            target_id: target_id.to_string(),
            outcome: outcome.to_string(),
        },
    )
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "sk-",
        "ghp_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "bearer ",
        "akia",
        "asia",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
        || (lower.starts_with("eyj") && lower.matches('.').count() == 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use crate::sekai::audit::DecisionFilter;
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
        EvidenceSignal, EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_store::{
        EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
    };
    use serde_json::json;
    use std::collections::HashMap;

    fn catalog_content() -> Value {
        json!({
            "classes": [
                {
                    "name": "Service",
                    "description": "Runnable service",
                    "properties": [
                        {"name": "status", "type": "string", "required": true}
                    ]
                },
                {
                    "name": "Service",
                    "proposal_kind": "class_property",
                    "properties": [
                        {"name": "owner", "type": "string", "required": false}
                    ]
                }
            ],
            "relations": [
                {
                    "name": "depends_on",
                    "domain": "Service",
                    "range": "Service",
                    "description": "runtime dependency"
                }
            ]
        })
    }

    fn admit_catalog(db: &SekaiDb, prefix: &str) -> String {
        db.create_object(&Object {
            id: format!("{prefix}:service-object"),
            kind: "service".into(),
            name: "service".into(),
            namespace: format!("{prefix}:namespace"),
            external_id: format!("{prefix}:service"),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        let producer = format!("{prefix}:producer");
        let capability = EvidenceProducerCapability {
            producer_identity: producer.clone(),
            config_version: 1,
            source_types: vec!["concept_catalog_source".into()],
            source_instances: vec![format!("{prefix}:catalog")],
            namespaces: vec![format!("{prefix}:namespace")],
            evidence_types: vec![EVIDENCE_TYPE_CONCEPT_CATALOG.into()],
            target_kinds: vec!["service".into()],
            classification_ceiling: EvidenceClassification::Confidential,
            allowed_intents: vec![EvidenceIntent::Upsert, EvidenceIntent::MarkStale],
            allow_operation_attachment: false,
            replay_window_ms: 60_000,
            max_clock_skew_ms: 5_000,
            max_payload_bytes: 64_000,
            max_relationships: 4,
            rate_limit_per_minute: 100,
            max_retained_submissions: 100,
            revoked: false,
        };
        db.upsert_evidence_producer(&capability, 100).unwrap();
        db.register_evidence_schema(
            &EvidenceSchemaDefinition {
                schema_id: SCHEMA_ID_CONCEPT_CATALOG.into(),
                schema_version: SCHEMA_VERSION_CONCEPT_CATALOG.into(),
                evidence_type: EVIDENCE_TYPE_CONCEPT_CATALOG.into(),
                compatible_versions: vec![],
            },
            100,
        )
        .unwrap();
        let content = catalog_content();
        let envelope = EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "concept_catalog_source".into(),
            source_instance: format!("{prefix}:catalog"),
            source_record_id: format!("{prefix}:catalog-v1"),
            source_version: "1".into(),
            source_sequence: 1,
            target: EvidenceTarget {
                namespace: format!("{prefix}:namespace"),
                object_external_id: format!("{prefix}:service"),
                object_kind: "service".into(),
            },
            evidence_type: EVIDENCE_TYPE_CONCEPT_CATALOG.into(),
            signal: EvidenceSignal::Other,
            schema_id: SCHEMA_ID_CONCEPT_CATALOG.into(),
            schema_version: SCHEMA_VERSION_CONCEPT_CATALOG.into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: 1_000,
            collected_at_ms: 1_010,
            expires_at_ms: None,
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: producer.clone(),
            confidence_bps: 9_000,
            classification: EvidenceClassification::Internal,
            provenance: BTreeMap::new(),
            idempotency_key: format!("{prefix}:delivery"),
            intent: EvidenceIntent::Upsert,
            causality: None,
        };
        let admission = db.submit_evidence(&envelope, &producer, 1_010).unwrap();
        assert!(admission.accepted);
        // Project so the submission becomes available.
        db.project_evidence_submission(&admission.submission.id, 1_020)
            .unwrap();
        admission.submission.id
    }

    #[test]
    fn dry_run_from_admitted_fixture_is_deterministic_and_non_mutating() {
        let db = SekaiDb::new(":memory:").unwrap();
        let submission_id = admit_catalog(&db, "dry");
        let request = ProposeOntologyDefinitionsRequest {
            submission_ids: vec![submission_id.clone()],
            extractor: ExtractorConfig::default(),
            authorization_context: "ontology-review:team-alpha".into(),
            proposer: "extractor-bot".into(),
            dry_run: true,
            now_ms: 2_000,
        };
        let first = db
            .propose_ontology_definitions_from_evidence(&request)
            .unwrap();
        let second = db
            .propose_ontology_definitions_from_evidence(&request)
            .unwrap();
        assert!(first.dry_run && !first.persisted);
        assert_eq!(first.proposals, second.proposals);
        assert_eq!(first.proposals.len(), 3);
        assert!(
            db.list_ontology_definition_proposals(&ProposalFilter::default())
                .unwrap()
                .is_empty()
        );
        assert!(db.list_ontology_classes().unwrap().is_empty());
        assert!(db.list_ontology_relations().unwrap().is_empty());
        // Sources carry digests and ids only.
        for proposal in &first.proposals {
            assert_eq!(proposal.sources.len(), 1);
            assert_eq!(proposal.sources[0].submission_id, submission_id);
            assert!(!proposal.sources[0].content_digest.is_empty());
            assert_eq!(proposal.extractor_id, EXTRACTOR_CONCEPT_CATALOG_V1);
            assert_eq!(proposal.authorization_context, "ontology-review:team-alpha");
        }
    }

    #[test]
    fn accept_applies_definition_through_normal_mutation_path() {
        let db = SekaiDb::new(":memory:").unwrap();
        let submission_id = admit_catalog(&db, "accept");
        let result = db
            .propose_ontology_definitions_from_evidence(&ProposeOntologyDefinitionsRequest {
                submission_ids: vec![submission_id],
                extractor: ExtractorConfig::default(),
                authorization_context: "ontology-review:team-alpha".into(),
                proposer: "extractor-bot".into(),
                dry_run: false,
                now_ms: 2_000,
            })
            .unwrap();
        assert!(result.persisted);
        let class_proposal = result
            .proposals
            .iter()
            .find(|proposal| proposal.definition.kind() == ProposalDefinitionKind::Class)
            .unwrap()
            .clone();
        let accepted = db
            .review_ontology_definition_proposal(
                &class_proposal.id,
                class_proposal.version,
                OntologyProposalReview {
                    action: ProposalReviewAction::Accept,
                    reviewer: "ontology-admin".into(),
                    rationale: "service class is required for domain modeling".into(),
                    reviewed_at_ms: 3_000,
                },
            )
            .unwrap();
        assert_eq!(accepted.state, ProposalLifecycleState::Accepted);
        assert_eq!(
            db.get_ontology_class("Service").unwrap().unwrap().name,
            "Service"
        );
        // Replay is idempotent.
        let replay = db
            .review_ontology_definition_proposal(
                &class_proposal.id,
                class_proposal.version,
                OntologyProposalReview {
                    action: ProposalReviewAction::Accept,
                    reviewer: "ontology-admin".into(),
                    rationale: "service class is required for domain modeling".into(),
                    reviewed_at_ms: 3_100,
                },
            )
            .unwrap();
        assert_eq!(replay.state, ProposalLifecycleState::Accepted);

        // Audit contains bounded refs only.
        let decisions = db
            .list_decisions(&DecisionFilter {
                action: Some("ontology.proposal.accept".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(!decisions.is_empty());
        for decision in decisions {
            assert!(decision.evidence.contains_key("source_submission_ids"));
            assert!(decision.evidence.contains_key("source_content_digests"));
            assert!(
                !decision
                    .evidence
                    .values()
                    .any(|value| value.contains("Runnable"))
            );
        }
    }

    #[test]
    fn rejection_never_mutates_ontology() {
        let db = SekaiDb::new(":memory:").unwrap();
        let submission_id = admit_catalog(&db, "reject");
        let result = db
            .propose_ontology_definitions_from_evidence(&ProposeOntologyDefinitionsRequest {
                submission_ids: vec![submission_id],
                extractor: ExtractorConfig::default(),
                authorization_context: "ontology-review:team-alpha".into(),
                proposer: "extractor-bot".into(),
                dry_run: false,
                now_ms: 2_000,
            })
            .unwrap();
        let relation = result
            .proposals
            .iter()
            .find(|proposal| proposal.definition.kind() == ProposalDefinitionKind::Relation)
            .unwrap();
        let rejected = db
            .review_ontology_definition_proposal(
                &relation.id,
                relation.version,
                OntologyProposalReview {
                    action: ProposalReviewAction::Reject,
                    reviewer: "ontology-admin".into(),
                    rationale: "dependency relation needs domain review".into(),
                    reviewed_at_ms: 3_000,
                },
            )
            .unwrap();
        assert_eq!(rejected.state, ProposalLifecycleState::Rejected);
        assert!(db.list_ontology_relations().unwrap().is_empty());
        assert!(db.get_ontology_class("Service").unwrap().is_none());
    }

    #[test]
    fn supersede_retires_prior_proposed_definition() {
        let db = SekaiDb::new(":memory:").unwrap();
        let submission_id = admit_catalog(&db, "super");
        let first = db
            .propose_ontology_definitions_from_evidence(&ProposeOntologyDefinitionsRequest {
                submission_ids: vec![submission_id.clone()],
                extractor: ExtractorConfig::default(),
                authorization_context: "ontology-review:team-alpha".into(),
                proposer: "extractor-bot".into(),
                dry_run: false,
                now_ms: 2_000,
            })
            .unwrap();
        let class_v1 = first
            .proposals
            .iter()
            .find(|proposal| proposal.definition.kind() == ProposalDefinitionKind::Class)
            .unwrap()
            .clone();

        // Store a second version manually with lineage for the same definition.
        let mut class_v2 = class_v1.clone();
        class_v2.version = 2;
        class_v2.supersedes = Some(ProposalVersionRef {
            proposal_id: class_v1.id.clone(),
            version: class_v1.version,
        });
        if let ProposedDefinition::Class { class } = &mut class_v2.definition {
            class.description = "Runnable service (revised)".into();
        }
        {
            let mut conn = db.conn();
            let tx = conn.transaction().unwrap();
            insert_proposal_row(&tx, &class_v2).unwrap();
            tx.commit().unwrap();
        }

        let accepted = db
            .review_ontology_definition_proposal(
                &class_v2.id,
                class_v2.version,
                OntologyProposalReview {
                    action: ProposalReviewAction::Supersede,
                    reviewer: "ontology-admin".into(),
                    rationale: "revised description is authoritative".into(),
                    reviewed_at_ms: 4_000,
                },
            )
            .unwrap();
        assert_eq!(accepted.state, ProposalLifecycleState::Accepted);
        let prior = db
            .get_ontology_definition_proposal(&class_v1.id, class_v1.version)
            .unwrap()
            .unwrap();
        assert_eq!(prior.state, ProposalLifecycleState::Superseded);
        assert_eq!(
            db.get_ontology_class("Service")
                .unwrap()
                .unwrap()
                .description,
            "Runnable service (revised)"
        );
    }

    #[test]
    fn stale_source_blocks_acceptance() {
        let db = SekaiDb::new(":memory:").unwrap();
        let submission_id = admit_catalog(&db, "stale");
        let result = db
            .propose_ontology_definitions_from_evidence(&ProposeOntologyDefinitionsRequest {
                submission_ids: vec![submission_id.clone()],
                extractor: ExtractorConfig::default(),
                authorization_context: "ontology-review:team-alpha".into(),
                proposer: "extractor-bot".into(),
                dry_run: false,
                now_ms: 2_000,
            })
            .unwrap();
        let class_proposal = result
            .proposals
            .iter()
            .find(|proposal| proposal.definition.kind() == ProposalDefinitionKind::Class)
            .unwrap();
        {
            let conn = db.conn();
            conn.execute(
                "UPDATE sekai_evidence_submissions SET lifecycle_state='stale' WHERE id=?1",
                params![submission_id],
            )
            .unwrap();
        }
        let error = db
            .review_ontology_definition_proposal(
                &class_proposal.id,
                class_proposal.version,
                OntologyProposalReview {
                    action: ProposalReviewAction::Accept,
                    reviewer: "ontology-admin".into(),
                    rationale: "should fail on stale source".into(),
                    reviewed_at_ms: 5_100,
                },
            )
            .unwrap_err();
        assert!(error.contains("stale source"), "{error}");
        assert!(db.get_ontology_class("Service").unwrap().is_none());
    }

    #[test]
    fn invalid_definition_fails_normal_validation_on_accept() {
        let db = SekaiDb::new(":memory:").unwrap();
        let submission_id = admit_catalog(&db, "invalid");
        // Persist only the relation proposal without the domain class.
        let dry = db
            .propose_ontology_definitions_from_evidence(&ProposeOntologyDefinitionsRequest {
                submission_ids: vec![submission_id],
                extractor: ExtractorConfig::default(),
                authorization_context: "ontology-review:team-alpha".into(),
                proposer: "extractor-bot".into(),
                dry_run: true,
                now_ms: 2_000,
            })
            .unwrap();
        let relation = dry
            .proposals
            .into_iter()
            .find(|proposal| proposal.definition.kind() == ProposalDefinitionKind::Relation)
            .unwrap();
        {
            let mut conn = db.conn();
            let tx = conn.transaction().unwrap();
            insert_proposal_row(&tx, &relation).unwrap();
            tx.commit().unwrap();
        }
        let error = db
            .review_ontology_definition_proposal(
                &relation.id,
                relation.version,
                OntologyProposalReview {
                    action: ProposalReviewAction::Accept,
                    reviewer: "ontology-admin".into(),
                    rationale: "should fail validation".into(),
                    reviewed_at_ms: 3_000,
                },
            )
            .unwrap_err();
        assert!(
            error.contains("unknown domain class") || error.contains("unknown range class"),
            "{error}"
        );
        assert!(db.list_ontology_relations().unwrap().is_empty());
    }

    #[test]
    fn empty_reviewer_is_denied() {
        let db = SekaiDb::new(":memory:").unwrap();
        let submission_id = admit_catalog(&db, "deny");
        let result = db
            .propose_ontology_definitions_from_evidence(&ProposeOntologyDefinitionsRequest {
                submission_ids: vec![submission_id],
                extractor: ExtractorConfig::default(),
                authorization_context: "ontology-review:team-alpha".into(),
                proposer: "extractor-bot".into(),
                dry_run: false,
                now_ms: 2_000,
            })
            .unwrap();
        let proposal = &result.proposals[0];
        let error = db
            .review_ontology_definition_proposal(
                &proposal.id,
                proposal.version,
                OntologyProposalReview {
                    action: ProposalReviewAction::Accept,
                    reviewer: "  ".into(),
                    rationale: "missing reviewer".into(),
                    reviewed_at_ms: 3_000,
                },
            )
            .unwrap_err();
        assert!(error.contains("reviewer"), "{error}");
    }

    #[test]
    fn proposal_identity_is_stable() {
        let sources = vec![SourceCitation {
            submission_id: "sub-1".into(),
            content_digest: "abc".into(),
            evidence_type: EVIDENCE_TYPE_CONCEPT_CATALOG.into(),
            source_type: "concept_catalog_source".into(),
            source_instance: "primary".into(),
            source_record_id: "rec-1".into(),
        }];
        let left = proposal_identity(
            ProposalDefinitionKind::Class,
            "Service",
            EXTRACTOR_CONCEPT_CATALOG_V1,
            &sources,
        );
        let right = proposal_identity(
            ProposalDefinitionKind::Class,
            "Service",
            EXTRACTOR_CONCEPT_CATALOG_V1,
            &sources,
        );
        assert_eq!(left, right);
        assert!(left.starts_with("odp-"));
    }
}
