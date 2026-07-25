//! Governed institutional memory derived from verifiable operation outcomes.

use crate::chisei::receipt::{OperationReceipt, ReceiptEventKind};
use crate::db::sekai::SekaiDb;
use crate::sekai::evidence::EvidenceClassification;
use crate::sekai::security::Role;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const KIOKU_MEMORY_VERSION: &str = "kioku.memory/v1";

pub fn memory_claim_digest(memory: &KiokuMemory) -> String {
    let mut digest = Sha256::new();
    for value in [
        memory.contract_version.as_bytes(),
        memory.id.as_bytes(),
        memory.claim.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(memory.version.to_be_bytes());
    format!("{:x}", digest.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    Claim,
    Recommendation,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLifecycleState {
    Candidate,
    Active,
    Superseded,
    Rejected,
}

impl MemoryLifecycleState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryEvidenceStance {
    Supporting,
    Contradicting,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KiokuMemory {
    pub contract_version: String,
    pub id: String,
    pub version: u32,
    pub kind: MemoryKind,
    pub claim: String,
    pub namespace: String,
    pub operation_classes: Vec<String>,
    #[serde(default)]
    pub affinity_object_ids: Vec<String>,
    pub outcome_definition: String,
    pub confidence_bps: u16,
    pub sample_size: u32,
    pub uncertainty: String,
    pub producer_identity: String,
    pub derivation_method: String,
    pub classification: EvidenceClassification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_until_ms: Option<i64>,
    pub state: MemoryLifecycleState,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_confirmed_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<MemoryVersionRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryVersionRef {
    pub memory_id: String,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KiokuEvidenceLink {
    pub memory_id: String,
    pub memory_version: u32,
    pub operation_id: String,
    pub verification_event_id: String,
    pub evidence_reference: String,
    pub evidence_digest: String,
    pub stance: MemoryEvidenceStance,
    pub outcome_metric: String,
    pub outcome_value: f64,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct VerifiedOutcome {
    pub receipt: OperationReceipt,
    pub passed: bool,
    pub outcome_metric: String,
    pub outcome_value: f64,
}

#[derive(Debug, Clone)]
pub struct CandidateDerivation {
    pub id: String,
    pub kind: MemoryKind,
    pub claim: String,
    pub outcome_definition: String,
    pub outcomes: Vec<VerifiedOutcome>,
    pub affinity_object_ids: Vec<String>,
    pub producer_identity: String,
    pub classification: EvidenceClassification,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub retention_until_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    pub supporting_evidence: usize,
    pub contradicting_evidence: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanReviewAction {
    Promote,
    Reject,
}

#[derive(Debug, Clone)]
pub struct HumanMemoryReview {
    pub action: HumanReviewAction,
    pub reviewer: String,
    pub rationale: String,
    pub reviewed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryLifecycleEvent {
    pub memory_id: String,
    pub memory_version: u32,
    pub action: String,
    pub from_state: Option<String>,
    pub to_state: String,
    pub actor: String,
    pub reason: String,
    pub recorded_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct MemoryRetrievalRequest {
    pub namespace: String,
    pub operation_class: String,
    pub context_object_ids: Vec<String>,
    pub classification_ceiling: EvidenceClassification,
    pub min_confidence_bps: u16,
    pub max_results: usize,
    pub actor: String,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RetrievedMemory {
    pub memory: KiokuMemory,
    pub evidence: Vec<KiokuEvidenceLink>,
    pub applicability: String,
    pub graph_affinity: f64,
    pub rank_score: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryOutcomeObservation {
    pub memory_id: String,
    pub memory_version: u32,
    pub operation_id: String,
    pub request_id: String,
    pub memory_applied: bool,
    pub outcome_metric: String,
    pub outcome_value: f64,
    pub passed: bool,
    pub recorded_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MemoryImpactEvaluation {
    pub memory_id: String,
    pub memory_version: u32,
    pub treatment_samples: usize,
    pub control_samples: usize,
    pub treatment_pass_rate: f64,
    pub control_pass_rate: f64,
    pub delta: f64,
    pub retired: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryLifecycleSweep {
    pub expired: usize,
    pub purged: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryOutcomeAssignment {
    pub memory_id: String,
    pub memory_version: u32,
    pub memory_applied: bool,
}

pub fn derive_verified_outcome_candidate(
    input: CandidateDerivation,
) -> Result<(KiokuMemory, Vec<KiokuEvidenceLink>), String> {
    if input.outcomes.is_empty() {
        return Err("candidate derivation requires verified outcomes".into());
    }
    let namespace = input.outcomes[0].receipt.namespace.trim().to_string();
    let operation_class = input.outcomes[0].receipt.operation_class.trim().to_string();
    let outcome_metric = input.outcomes[0].outcome_metric.trim().to_string();
    let mut evidence = Vec::with_capacity(input.outcomes.len());
    let mut supporting = 0_u32;
    let mut last_confirmed_at_ms = None;
    let mut seen_operations = std::collections::HashSet::new();

    for outcome in &input.outcomes {
        if outcome.receipt.namespace.trim() != namespace
            || outcome.receipt.operation_class.trim() != operation_class
        {
            return Err("candidate outcomes must share one namespace and operation class".into());
        }
        if !seen_operations.insert(outcome.receipt.operation_id.as_str()) {
            return Err(format!(
                "duplicate operation receipt {}",
                outcome.receipt.operation_id
            ));
        }
        let completeness = outcome.receipt.completeness();
        if !completeness.complete {
            return Err(format!(
                "operation {} receipt is incomplete: {}",
                outcome.receipt.operation_id,
                completeness.errors.join("; ")
            ));
        }
        if outcome.outcome_metric.trim().is_empty() || !outcome.outcome_value.is_finite() {
            return Err("verified outcome requires a metric and finite value".into());
        }
        if outcome.outcome_metric.trim() != outcome_metric {
            return Err("candidate outcomes must share one outcome metric".into());
        }
        let verification = outcome
            .receipt
            .events
            .iter()
            .filter(|event| event.kind == ReceiptEventKind::VerificationRecorded)
            .find_map(|event| {
                event.references.iter().find_map(|reference| {
                    let digest = reference.content_hash.as_deref()?.trim();
                    if reference.omitted
                        || reference.reference.trim().is_empty()
                        || digest.is_empty()
                    {
                        return None;
                    }
                    let outcome_event = outcome.receipt.events.iter().find(|candidate| {
                        candidate.kind == ReceiptEventKind::OutcomeRecorded
                            && event_descends_from(
                                &outcome.receipt,
                                candidate,
                                event.event_id.as_str(),
                            )
                    })?;
                    Some((event, reference, digest.to_string(), outcome_event))
                })
            })
            .ok_or_else(|| {
                format!(
                    "operation {} lacks a disclosed hashed verification linked to its outcome",
                    outcome.receipt.operation_id
                )
            })?;

        let recorded_metric = verification
            .3
            .attributes
            .get("outcome_metric")
            .map(String::as_str)
            .unwrap_or_default();
        let recorded_value = verification
            .3
            .attributes
            .get("outcome_value")
            .and_then(|value| value.parse::<f64>().ok());
        let recorded_passed = verification
            .3
            .attributes
            .get("passed")
            .and_then(|value| value.parse::<bool>().ok());
        if recorded_metric != outcome.outcome_metric.trim()
            || recorded_value != Some(outcome.outcome_value)
            || recorded_passed != Some(outcome.passed)
        {
            return Err(format!(
                "operation {} outcome labels do not match its receipt evidence",
                outcome.receipt.operation_id
            ));
        }

        let stance = if outcome.passed {
            supporting = supporting.saturating_add(1);
            last_confirmed_at_ms = Some(
                last_confirmed_at_ms
                    .unwrap_or(i64::MIN)
                    .max(verification.0.timestamp_ms),
            );
            MemoryEvidenceStance::Supporting
        } else {
            MemoryEvidenceStance::Contradicting
        };
        evidence.push(KiokuEvidenceLink {
            memory_id: input.id.clone(),
            memory_version: 1,
            operation_id: outcome.receipt.operation_id.clone(),
            verification_event_id: verification.0.event_id.clone(),
            evidence_reference: verification.1.reference.clone(),
            evidence_digest: verification.2,
            stance,
            outcome_metric: outcome.outcome_metric.trim().to_string(),
            outcome_value: outcome.outcome_value,
            observed_at_ms: verification.3.timestamp_ms,
        });
    }
    if supporting == 0 {
        return Err("candidate derivation requires at least one supporting outcome".into());
    }
    let sample_size = u32::try_from(input.outcomes.len())
        .map_err(|_| "candidate sample size exceeds u32".to_string())?;
    let confidence_bps = ((u64::from(supporting) * 10_000) / u64::from(sample_size)) as u16;
    let contradicting = sample_size - supporting;
    let memory = KiokuMemory {
        contract_version: KIOKU_MEMORY_VERSION.into(),
        id: input.id,
        version: 1,
        kind: input.kind,
        claim: input.claim,
        namespace,
        operation_classes: vec![operation_class],
        affinity_object_ids: input.affinity_object_ids,
        outcome_definition: input.outcome_definition,
        confidence_bps,
        sample_size,
        uncertainty: format!(
            "{supporting} supporting and {contradicting} contradicting verified outcomes"
        ),
        producer_identity: input.producer_identity,
        derivation_method: "verified_binary_outcomes/v1".into(),
        classification: input.classification,
        retention_until_ms: input.retention_until_ms,
        state: MemoryLifecycleState::Candidate,
        created_at_ms: input.created_at_ms,
        reviewed_at_ms: None,
        expires_at_ms: input.expires_at_ms,
        last_confirmed_at_ms,
        supersedes: None,
    };
    memory
        .validate_contract()
        .map_err(|errors| errors.join("; "))?;
    Ok((memory, evidence))
}

fn event_descends_from(
    receipt: &OperationReceipt,
    event: &crate::chisei::receipt::OperationReceiptEvent,
    ancestor_id: &str,
) -> bool {
    let mut parent = event.parent_event_id.as_deref();
    let mut visited = std::collections::HashSet::new();
    while let Some(parent_id) = parent {
        if parent_id == ancestor_id {
            return true;
        }
        if !visited.insert(parent_id) {
            return false;
        }
        parent = receipt
            .events
            .iter()
            .find(|candidate| candidate.event_id == parent_id)
            .and_then(|candidate| candidate.parent_event_id.as_deref());
    }
    false
}

impl KiokuMemory {
    pub fn validate_contract(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.contract_version != KIOKU_MEMORY_VERSION {
            errors.push(format!(
                "unsupported memory contract version {}",
                self.contract_version
            ));
        }
        for (field, value) in [
            ("id", self.id.as_str()),
            ("claim", self.claim.as_str()),
            ("namespace", self.namespace.as_str()),
            ("outcome_definition", self.outcome_definition.as_str()),
            ("uncertainty", self.uncertainty.as_str()),
            ("producer_identity", self.producer_identity.as_str()),
            ("derivation_method", self.derivation_method.as_str()),
        ] {
            if value.trim().is_empty() {
                errors.push(format!("{field} is required"));
            }
        }
        if self.version == 0 {
            errors.push("version must be greater than zero".into());
        }
        if self.operation_classes.is_empty()
            || self
                .operation_classes
                .iter()
                .any(|class| class.trim().is_empty())
        {
            errors.push("at least one non-empty operation class is required".into());
        }
        if self.sample_size == 0 {
            errors.push("sample_size must be greater than zero".into());
        }
        if self.confidence_bps > 10_000 {
            errors.push("confidence_bps must not exceed 10000".into());
        }
        if self.claim.chars().count() > 2_048 {
            errors.push("claim exceeds 2048 characters".into());
        }
        if self
            .expires_at_ms
            .is_some_and(|expires| expires <= self.created_at_ms)
        {
            errors.push("expires_at_ms must be after created_at_ms".into());
        }
        if self
            .retention_until_ms
            .zip(self.expires_at_ms)
            .is_some_and(|(retention, expires)| retention < expires)
        {
            errors.push("retention_until_ms must not precede expires_at_ms".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl KiokuEvidenceLink {
    pub(crate) fn validate(&self, memory: &KiokuMemory) -> Result<(), String> {
        if self.memory_id != memory.id || self.memory_version != memory.version {
            return Err("evidence link memory version does not match memory".into());
        }
        for (field, value) in [
            ("operation_id", self.operation_id.as_str()),
            ("verification_event_id", self.verification_event_id.as_str()),
            ("evidence_reference", self.evidence_reference.as_str()),
            ("evidence_digest", self.evidence_digest.as_str()),
            ("outcome_metric", self.outcome_metric.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{field} is required"));
            }
        }
        if !self.outcome_value.is_finite() {
            return Err("outcome_value must be finite".into());
        }
        Ok(())
    }
}

impl SekaiDb {
    pub(crate) fn migrate_kioku(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_kioku_memories (
                id TEXT NOT NULL,
                version INTEGER NOT NULL,
                namespace TEXT NOT NULL,
                state TEXT NOT NULL,
                classification TEXT NOT NULL,
                expires_at_ms INTEGER,
                memory_json TEXT NOT NULL,
                PRIMARY KEY (id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_kioku_memory_retrieval
                ON chisei_kioku_memories(namespace, state, expires_at_ms);
            CREATE TABLE IF NOT EXISTS chisei_kioku_evidence_links (
                memory_id TEXT NOT NULL,
                memory_version INTEGER NOT NULL,
                operation_id TEXT NOT NULL,
                stance TEXT NOT NULL,
                link_json TEXT NOT NULL,
                PRIMARY KEY (memory_id, memory_version, operation_id),
                FOREIGN KEY (memory_id, memory_version)
                    REFERENCES chisei_kioku_memories(id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_kioku_evidence_operation
                ON chisei_kioku_evidence_links(operation_id);
            CREATE TABLE IF NOT EXISTS chisei_kioku_lifecycle_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                memory_id TEXT NOT NULL,
                memory_version INTEGER NOT NULL,
                action TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                recorded_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kioku_lifecycle_memory
                ON chisei_kioku_lifecycle_events(memory_id, memory_version, id);
            CREATE TABLE IF NOT EXISTS chisei_kioku_outcomes (
                memory_id TEXT NOT NULL,
                memory_version INTEGER NOT NULL,
                operation_id TEXT NOT NULL,
                memory_applied INTEGER NOT NULL,
                outcome_metric TEXT NOT NULL,
                outcome_value REAL NOT NULL,
                passed INTEGER NOT NULL,
                recorded_at_ms INTEGER NOT NULL,
                PRIMARY KEY (memory_id, memory_version, operation_id),
                FOREIGN KEY (memory_id, memory_version)
                    REFERENCES chisei_kioku_memories(id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_kioku_outcome_comparison
                ON chisei_kioku_outcomes(memory_id, memory_version, memory_applied);",
        )
        .map_err(|error| error.to_string())
    }

    pub fn insert_kioku_memory(
        &self,
        memory: &KiokuMemory,
        evidence: &[KiokuEvidenceLink],
    ) -> Result<(), String> {
        memory
            .validate_contract()
            .map_err(|errors| errors.join("; "))?;
        if memory.state != MemoryLifecycleState::Candidate || memory.reviewed_at_ms.is_some() {
            return Err("new memories must be unreviewed candidates".into());
        }
        if evidence.is_empty() {
            return Err("at least one evidence link is required".into());
        }
        if !evidence
            .iter()
            .any(|link| link.stance == MemoryEvidenceStance::Supporting)
        {
            return Err("at least one supporting evidence link is required".into());
        }
        for link in evidence {
            link.validate(memory)?;
        }

        let memory_json = serde_json::to_string(memory).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO chisei_kioku_memories
             (id, version, namespace, state, classification, expires_at_ms, memory_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                memory.id,
                memory.version,
                memory.namespace,
                memory.state.as_str(),
                memory.classification.as_str(),
                memory.expires_at_ms,
                memory_json,
            ],
        )
        .map_err(|error| error.to_string())?;
        for link in evidence {
            let link_json = serde_json::to_string(link).map_err(|error| error.to_string())?;
            let stance = match link.stance {
                MemoryEvidenceStance::Supporting => "supporting",
                MemoryEvidenceStance::Contradicting => "contradicting",
            };
            tx.execute(
                "INSERT INTO chisei_kioku_evidence_links
                 (memory_id, memory_version, operation_id, stance, link_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    link.memory_id,
                    link.memory_version,
                    link.operation_id,
                    stance,
                    link_json,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        insert_lifecycle_event(
            &tx,
            &MemoryLifecycleEvent {
                memory_id: memory.id.clone(),
                memory_version: memory.version,
                action: "created".into(),
                from_state: None,
                to_state: memory.state.as_str().into(),
                actor: memory.producer_identity.clone(),
                reason: memory.derivation_method.clone(),
                recorded_at_ms: memory.created_at_ms,
            },
        )?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn produce_kioku_candidate(
        &self,
        input: CandidateDerivation,
    ) -> Result<KiokuMemory, String> {
        let (memory, evidence) = derive_verified_outcome_candidate(input)?;
        self.insert_kioku_memory(&memory, &evidence)?;
        Ok(memory)
    }

    pub fn get_kioku_memory(&self, id: &str, version: u32) -> Result<Option<KiokuMemory>, String> {
        let conn = self.conn();
        let json: Option<String> = conn
            .query_row(
                "SELECT memory_json FROM chisei_kioku_memories WHERE id=?1 AND version=?2",
                params![id, version],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn list_kioku_candidates(
        &self,
        namespace: &str,
        operation_class: Option<&str>,
        limit: usize,
    ) -> Result<Vec<KiokuMemory>, String> {
        if namespace.trim().is_empty() {
            return Err("candidate namespace is required".into());
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT memory_json FROM chisei_kioku_memories
                 WHERE namespace=?1 AND state='candidate'
                 ORDER BY rowid DESC",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([namespace.trim()], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        let operation_class = operation_class
            .map(str::trim)
            .filter(|value| !value.is_empty());
        rows.map(|row| {
            row.map_err(|error| error.to_string())
                .and_then(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
        })
        .filter_map(|memory: Result<KiokuMemory, String>| match memory {
            Ok(memory)
                if operation_class.is_none_or(|class| {
                    memory
                        .operation_classes
                        .iter()
                        .any(|candidate| candidate == class)
                }) =>
            {
                Some(Ok(memory))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .take(limit)
        .collect()
    }

    pub fn list_kioku_evidence(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<KiokuEvidenceLink>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT link_json FROM chisei_kioku_evidence_links
                 WHERE memory_id=?1 AND memory_version=?2 ORDER BY operation_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![id, version], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            row.map_err(|error| error.to_string())
                .and_then(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
        })
        .collect()
    }

    pub fn validate_kioku_candidate(
        &self,
        id: &str,
        version: u32,
    ) -> Result<MemoryValidation, String> {
        let Some(memory) = self.get_kioku_memory(id, version)? else {
            return Err(format!("memory {id} version {version} not found"));
        };
        let evidence = self.list_kioku_evidence(id, version)?;
        let mut errors = memory.validate_contract().err().unwrap_or_default();
        if memory.state != MemoryLifecycleState::Candidate {
            errors.push("only candidate memories can be validated for review".into());
        }
        let supporting_evidence = evidence
            .iter()
            .filter(|link| link.stance == MemoryEvidenceStance::Supporting)
            .count();
        let contradicting_evidence = evidence.len().saturating_sub(supporting_evidence);
        if supporting_evidence == 0 {
            errors.push("candidate requires supporting evidence".into());
        }
        if evidence.len() != memory.sample_size as usize {
            errors.push(format!(
                "sample_size {} does not match {} evidence links",
                memory.sample_size,
                evidence.len()
            ));
        }
        let mut operations = std::collections::HashSet::new();
        let mut metrics = std::collections::HashSet::new();
        for link in &evidence {
            if let Err(error) = link.validate(&memory) {
                errors.push(error);
            }
            if !operations.insert(link.operation_id.as_str()) {
                errors.push(format!(
                    "duplicate evidence operation {}",
                    link.operation_id
                ));
            }
            metrics.insert(link.outcome_metric.trim());
        }
        if metrics.len() != 1 {
            errors.push("candidate evidence must share one outcome metric".into());
        }
        if memory.derivation_method == "verified_binary_outcomes/v1" && !evidence.is_empty() {
            let expected = ((supporting_evidence as u64 * 10_000) / evidence.len() as u64) as u16;
            if memory.confidence_bps != expected {
                errors.push(format!(
                    "confidence_bps {} does not match verified outcome rate {expected}",
                    memory.confidence_bps
                ));
            }
        }
        errors.sort();
        errors.dedup();
        Ok(MemoryValidation {
            valid: errors.is_empty(),
            errors,
            supporting_evidence,
            contradicting_evidence,
        })
    }

    pub fn review_kioku_candidate(
        &self,
        id: &str,
        version: u32,
        review: HumanMemoryReview,
    ) -> Result<KiokuMemory, String> {
        if review.reviewer.trim().is_empty() || review.rationale.trim().is_empty() {
            return Err("reviewer and rationale are required".into());
        }
        let validation = self.validate_kioku_candidate(id, version)?;
        if review.action == HumanReviewAction::Promote && !validation.valid {
            return Err(format!(
                "candidate validation failed: {}",
                validation.errors.join("; ")
            ));
        }
        let mut memory = self
            .get_kioku_memory(id, version)?
            .ok_or_else(|| format!("memory {id} version {version} not found"))?;
        if memory.state != MemoryLifecycleState::Candidate {
            return Err("memory is no longer awaiting review".into());
        }
        let next_state = match review.action {
            HumanReviewAction::Promote => MemoryLifecycleState::Active,
            HumanReviewAction::Reject => MemoryLifecycleState::Rejected,
        };
        let superseded = if review.action == HumanReviewAction::Promote {
            memory
                .supersedes
                .as_ref()
                .map(|reference| {
                    let mut prior = self
                        .get_kioku_memory(&reference.memory_id, reference.version)?
                        .ok_or_else(|| "superseded memory version not found".to_string())?;
                    if prior.state != MemoryLifecycleState::Active {
                        return Err(String::from("superseded memory is not active"));
                    }
                    if prior.namespace != memory.namespace
                        || (prior.id == memory.id && prior.version >= memory.version)
                    {
                        return Err(String::from("invalid memory supersession lineage"));
                    }
                    prior.state = MemoryLifecycleState::Superseded;
                    let json = serde_json::to_string(&prior).map_err(|error| error.to_string())?;
                    Ok((prior, json))
                })
                .transpose()?
        } else {
            None
        };
        memory.state = next_state;
        memory.reviewed_at_ms = Some(review.reviewed_at_ms);
        let memory_json = serde_json::to_string(&memory).map_err(|error| error.to_string())?;

        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let updated = tx
            .execute(
                "UPDATE chisei_kioku_memories
                 SET state=?1, memory_json=?2
                 WHERE id=?3 AND version=?4 AND state='candidate'",
                params![next_state.as_str(), memory_json, id, version],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("memory changed during review".into());
        }
        if let Some((prior, prior_json)) = superseded {
            let updated = tx
                .execute(
                    "UPDATE chisei_kioku_memories
                     SET state='superseded', memory_json=?1
                     WHERE id=?2 AND version=?3 AND state='active'",
                    params![prior_json, prior.id, prior.version],
                )
                .map_err(|error| error.to_string())?;
            if updated != 1 {
                return Err("superseded memory changed during review".into());
            }
            insert_lifecycle_event(
                &tx,
                &MemoryLifecycleEvent {
                    memory_id: prior.id,
                    memory_version: prior.version,
                    action: "superseded".into(),
                    from_state: Some(MemoryLifecycleState::Active.as_str().into()),
                    to_state: MemoryLifecycleState::Superseded.as_str().into(),
                    actor: review.reviewer.trim().into(),
                    reason: format!("superseded by {id}@{version}: {}", review.rationale.trim()),
                    recorded_at_ms: review.reviewed_at_ms,
                },
            )?;
        }
        insert_lifecycle_event(
            &tx,
            &MemoryLifecycleEvent {
                memory_id: id.into(),
                memory_version: version,
                action: match review.action {
                    HumanReviewAction::Promote => "promoted",
                    HumanReviewAction::Reject => "rejected",
                }
                .into(),
                from_state: Some(MemoryLifecycleState::Candidate.as_str().into()),
                to_state: next_state.as_str().into(),
                actor: review.reviewer.trim().into(),
                reason: review.rationale.trim().into(),
                recorded_at_ms: review.reviewed_at_ms,
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(memory)
    }

    pub fn list_kioku_lifecycle_events(
        &self,
        id: &str,
        version: u32,
    ) -> Result<Vec<MemoryLifecycleEvent>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT memory_id, memory_version, action, from_state, to_state, actor, reason,
                        recorded_at_ms
                 FROM chisei_kioku_lifecycle_events
                 WHERE memory_id=?1 AND memory_version=?2 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![id, version], |row| {
                Ok(MemoryLifecycleEvent {
                    memory_id: row.get(0)?,
                    memory_version: row.get(1)?,
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

    pub fn disable_kioku_memory(
        &self,
        id: &str,
        version: u32,
        actor: &str,
        rationale: &str,
        recorded_at_ms: i64,
    ) -> Result<KiokuMemory, String> {
        if actor.trim().is_empty() || rationale.trim().is_empty() {
            return Err("disable actor and rationale are required".into());
        }
        let mut memory = self
            .get_kioku_memory(id, version)?
            .ok_or_else(|| format!("memory {id} version {version} not found"))?;
        if memory.state != MemoryLifecycleState::Active {
            return Err("only active memories can be disabled".into());
        }
        memory.state = MemoryLifecycleState::Rejected;
        let memory_json = serde_json::to_string(&memory).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let updated = tx
            .execute(
                "UPDATE chisei_kioku_memories SET state='rejected', memory_json=?1
                 WHERE id=?2 AND version=?3 AND state='active'",
                params![memory_json, id, version],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("memory changed while it was being disabled".into());
        }
        insert_lifecycle_event(
            &tx,
            &MemoryLifecycleEvent {
                memory_id: id.into(),
                memory_version: version,
                action: "disabled".into(),
                from_state: Some(MemoryLifecycleState::Active.as_str().into()),
                to_state: MemoryLifecycleState::Rejected.as_str().into(),
                actor: actor.trim().into(),
                reason: rationale.trim().into(),
                recorded_at_ms,
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(memory)
    }

    pub fn retrieve_kioku_memories(
        &self,
        request: &MemoryRetrievalRequest,
    ) -> Result<Vec<RetrievedMemory>, String> {
        if request.namespace.trim().is_empty()
            || request.operation_class.trim().is_empty()
            || request.actor.trim().is_empty()
        {
            return Err("retrieval namespace, operation class, and actor are required".into());
        }
        if request.min_confidence_bps > 10_000 {
            return Err("min_confidence_bps must not exceed 10000".into());
        }
        if request.max_results == 0 {
            return Ok(Vec::new());
        }
        self.authorize_kioku_retrieval(request)?;

        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT memory_json FROM chisei_kioku_memories
                 WHERE namespace=?1 AND state='active'
                   AND (expires_at_ms IS NULL OR expires_at_ms>?2)",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![request.namespace.trim(), request.now_ms], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        let memory_json = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(statement);
        drop(conn);

        let context_ids = request
            .context_object_ids
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        let mut retrieved = Vec::new();
        for json in memory_json {
            let memory: KiokuMemory =
                serde_json::from_str(&json).map_err(|error| error.to_string())?;
            if !memory
                .operation_classes
                .iter()
                .any(|class| class == request.operation_class.trim())
                || memory.classification > request.classification_ceiling
                || memory.confidence_bps < request.min_confidence_bps
                || memory
                    .retention_until_ms
                    .is_some_and(|retention| retention <= request.now_ms)
            {
                continue;
            }
            let evidence = self.list_kioku_evidence(&memory.id, memory.version)?;
            validate_resolvable_evidence(&memory, &evidence)?;
            let affinity_hits = memory
                .affinity_object_ids
                .iter()
                .filter(|id| context_ids.contains(id.as_str()))
                .count();
            let graph_affinity = if memory.affinity_object_ids.is_empty() {
                0.0
            } else {
                affinity_hits as f64 / memory.affinity_object_ids.len() as f64
            };
            const FRESHNESS_WINDOW_MS: u64 = 90 * 24 * 60 * 60 * 1_000;
            let confirmed_at = memory.last_confirmed_at_ms.unwrap_or(memory.created_at_ms);
            let age_ms = request.now_ms.saturating_sub(confirmed_at).max(0) as u64;
            let freshness = FRESHNESS_WINDOW_MS
                .saturating_sub(age_ms.min(FRESHNESS_WINDOW_MS))
                .saturating_mul(999_999)
                / FRESHNESS_WINDOW_MS;
            let rank_score = (affinity_hits as u64 * 10_000_000_000)
                .saturating_add(u64::from(memory.confidence_bps) * 1_000_000)
                .saturating_add(freshness.min(999_999));
            retrieved.push(RetrievedMemory {
                applicability: format!(
                    "namespace={} operation_class={} affinity_hits={affinity_hits}",
                    memory.namespace, request.operation_class
                ),
                memory,
                evidence,
                graph_affinity,
                rank_score,
            });
        }
        retrieved.sort_by(|left, right| {
            right
                .rank_score
                .cmp(&left.rank_score)
                .then_with(|| left.memory.id.cmp(&right.memory.id))
        });
        retrieved.truncate(request.max_results.min(100));
        for item in &retrieved {
            self.record_kioku_lifecycle_event(&MemoryLifecycleEvent {
                memory_id: item.memory.id.clone(),
                memory_version: item.memory.version,
                action: "retrieved".into(),
                from_state: Some(MemoryLifecycleState::Active.as_str().into()),
                to_state: MemoryLifecycleState::Active.as_str().into(),
                actor: request.actor.trim().into(),
                reason: item.applicability.clone(),
                recorded_at_ms: request.now_ms,
            })?;
        }
        Ok(retrieved)
    }

    fn authorize_kioku_retrieval(&self, request: &MemoryRetrievalRequest) -> Result<(), String> {
        let actor = request.actor.trim();
        let namespace = request.namespace.trim();
        let authorized_ceiling = self.kioku_authorized_classification_ceiling(namespace, actor)?;
        if request.classification_ceiling > authorized_ceiling {
            return Err("requested memory classification exceeds actor grant".into());
        }
        for object_id in &request.context_object_ids {
            if self.get_object(object_id)?.is_none() {
                return Err(format!("context object {object_id} not found"));
            }
            let grants = self.list_grants(object_id)?;
            if !grants.is_empty() && !grants.iter().any(|grant| grant.principal == actor) {
                return Err(format!(
                    "actor is not authorized for context object {object_id}"
                ));
            }
        }
        Ok(())
    }

    pub fn kioku_authorized_classification_ceiling(
        &self,
        namespace: &str,
        actor: &str,
    ) -> Result<EvidenceClassification, String> {
        let namespace_object = self
            .find_by_external_id(&format!("namespace:{namespace}"))?
            .ok_or_else(|| "memory namespace is not an authorized graph scope".to_string())?;
        let grants = self.list_grants(&namespace_object.id)?;
        let authorized_ceiling = if grants.is_empty() {
            EvidenceClassification::Public
        } else {
            let role = grants
                .iter()
                .find(|grant| grant.principal == actor)
                .map(|grant| &grant.role)
                .ok_or_else(|| "actor is not authorized for memory namespace".to_string())?;
            match role {
                Role::Viewer => EvidenceClassification::Internal,
                Role::Editor => EvidenceClassification::Confidential,
                Role::Admin => EvidenceClassification::Restricted,
            }
        };
        Ok(authorized_ceiling)
    }

    pub fn record_kioku_lifecycle_event(&self, event: &MemoryLifecycleEvent) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        insert_lifecycle_event(&tx, event)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn record_kioku_outcome(
        &self,
        observation: &MemoryOutcomeObservation,
    ) -> Result<bool, String> {
        if observation.operation_id.trim().is_empty()
            || observation.request_id.trim().is_empty()
            || observation.outcome_metric.trim().is_empty()
            || !observation.outcome_value.is_finite()
        {
            return Err("memory outcome requires an operation, metric, and finite value".into());
        }
        let memory = self
            .get_kioku_memory(&observation.memory_id, observation.memory_version)?
            .ok_or_else(|| "memory version not found".to_string())?;
        let receipt = self
            .get_operation_receipt(observation.operation_id.trim())?
            .ok_or_else(|| "operation receipt not found".to_string())?;
        let receipt_request_id = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .and_then(|event| event.attributes.get("request_id"))
            .map(String::as_str)
            .map(str::trim);
        if !receipt.completeness().complete
            || receipt_request_id != Some(observation.request_id.trim())
            || receipt.namespace != memory.namespace
            || !memory
                .operation_classes
                .iter()
                .any(|class| class == &receipt.operation_class)
        {
            return Err("operation receipt does not match memory outcome scope".into());
        }
        let evidence = self.list_kioku_evidence(&memory.id, memory.version)?;
        if !evidence
            .iter()
            .all(|link| link.outcome_metric.trim() == observation.outcome_metric.trim())
        {
            return Err("outcome metric does not match memory evidence".into());
        }
        let recorded_outcome = receipt
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.kind,
                    ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
                ) && event
                    .attributes
                    .get("outcome_metric")
                    .is_some_and(|metric| metric.trim() == observation.outcome_metric.trim())
            })
            .ok_or_else(|| "operation receipt lacks an outcome event".to_string())?;
        let recorded_metric = recorded_outcome
            .attributes
            .get("outcome_metric")
            .map(String::as_str)
            .unwrap_or_default();
        let recorded_value = recorded_outcome
            .attributes
            .get("outcome_value")
            .and_then(|value| value.parse::<f64>().ok());
        let recorded_passed = recorded_outcome
            .attributes
            .get("passed")
            .and_then(|value| value.parse::<bool>().ok());
        if recorded_metric.trim() != observation.outcome_metric.trim()
            || recorded_value != Some(observation.outcome_value)
            || recorded_passed != Some(observation.passed)
        {
            return Err("memory outcome does not match receipt evidence".into());
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let assignment_reason = format!("pipeline operation {}", observation.operation_id.trim());
        let legacy_assignment_reason =
            format!("pipeline request {}", observation.request_id.trim());
        let assignment = {
            let mut statement = tx
                .prepare(
                    "SELECT action FROM chisei_kioku_lifecycle_events
                     WHERE memory_id=?1 AND memory_version=?2
                       AND (reason=?3 OR (reason=?4 AND NOT EXISTS (
                         SELECT 1 FROM chisei_kioku_lifecycle_events
                         WHERE reason=?3 AND memory_id=?1 AND memory_version=?2
                       )))
                       AND action IN
                         ('injected', 'held_out', 'holdout_invalidated', 'assignment_invalidated')
                     ORDER BY id",
                )
                .map_err(|error| error.to_string())?;
            let actions = statement
                .query_map(
                    params![
                        observation.memory_id,
                        observation.memory_version,
                        assignment_reason,
                        legacy_assignment_reason,
                    ],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|error| error.to_string())?;
            let mut assignment = None;
            for action in actions {
                match action.map_err(|error| error.to_string())?.as_str() {
                    "holdout_invalidated" | "assignment_invalidated" => assignment = None,
                    "injected" => assignment = Some(true),
                    "held_out" => assignment = Some(false),
                    _ => unreachable!("assignment query filters lifecycle actions"),
                }
            }
            assignment
        };
        if assignment != Some(observation.memory_applied) {
            return Err(
                "memory outcome treatment assignment does not match injection audit".into(),
            );
        }
        let existing = tx
            .query_row(
                "SELECT memory_applied, outcome_metric, outcome_value, passed
                 FROM chisei_kioku_outcomes
                 WHERE memory_id=?1 AND memory_version=?2 AND operation_id=?3",
                params![
                    observation.memory_id,
                    observation.memory_version,
                    observation.operation_id.trim()
                ],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, f64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(existing) = existing {
            if existing
                == (
                    observation.memory_applied,
                    observation.outcome_metric.trim().to_string(),
                    observation.outcome_value,
                    observation.passed,
                )
            {
                return Ok(false);
            }
            return Err("memory outcome already exists with different evidence".into());
        }
        tx.execute(
            "INSERT INTO chisei_kioku_outcomes
             (memory_id, memory_version, operation_id, memory_applied, outcome_metric,
              outcome_value, passed, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                observation.memory_id,
                observation.memory_version,
                observation.operation_id.trim(),
                observation.memory_applied,
                observation.outcome_metric.trim(),
                observation.outcome_value,
                observation.passed,
                observation.recorded_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn list_kioku_outcome_assignments(
        &self,
        operation_id: &str,
    ) -> Result<Vec<MemoryOutcomeAssignment>, String> {
        if operation_id.trim().is_empty() {
            return Err("assignment operation id is required".into());
        }
        let reason = format!("pipeline operation {}", operation_id.trim());
        let legacy_reason = self
            .get_operation_receipt(operation_id.trim())?
            .and_then(|receipt| {
                receipt
                    .events
                    .into_iter()
                    .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
                    .and_then(|event| event.attributes.get("request_id").cloned())
            })
            .map(|request_id| format!("pipeline request {}", request_id.trim()));
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT lifecycle.memory_id, lifecycle.memory_version, lifecycle.action
                 FROM chisei_kioku_lifecycle_events AS lifecycle
                 WHERE (lifecycle.reason=?1 OR (lifecycle.reason=?2 AND NOT EXISTS (
                     SELECT 1 FROM chisei_kioku_lifecycle_events AS current
                     WHERE current.reason=?1
                       AND current.memory_id=lifecycle.memory_id
                       AND current.memory_version=lifecycle.memory_version
                   ))) AND lifecycle.action IN
                     ('injected', 'held_out', 'holdout_invalidated', 'assignment_invalidated')
                 ORDER BY id",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![reason, legacy_reason], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        let mut assignments = std::collections::BTreeMap::new();
        for row in rows {
            let (memory_id, memory_version, action) = row.map_err(|error| error.to_string())?;
            if matches!(
                action.as_str(),
                "holdout_invalidated" | "assignment_invalidated"
            ) {
                assignments.remove(&(memory_id, memory_version));
                continue;
            }
            let applied = action == "injected";
            if assignments
                .insert((memory_id.clone(), memory_version), applied)
                .is_some_and(|previous| previous != applied)
            {
                return Err(format!(
                    "memory {memory_id}@{memory_version} has conflicting treatment assignments"
                ));
            }
        }
        Ok(assignments
            .into_iter()
            .map(
                |((memory_id, memory_version), memory_applied)| MemoryOutcomeAssignment {
                    memory_id,
                    memory_version,
                    memory_applied,
                },
            )
            .collect())
    }

    pub fn record_kioku_holdout(
        &self,
        id: &str,
        version: u32,
        operation_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        if operation_id.trim().is_empty() || actor.trim().is_empty() {
            return Err("holdout operation and actor are required".into());
        }
        let memory = self
            .get_kioku_memory(id, version)?
            .ok_or_else(|| "memory version not found".to_string())?;
        if memory.state != MemoryLifecycleState::Active {
            return Err("only active memories can be assigned to holdout".into());
        }
        self.record_kioku_lifecycle_event(&MemoryLifecycleEvent {
            memory_id: id.into(),
            memory_version: version,
            action: "held_out".into(),
            from_state: Some(MemoryLifecycleState::Active.as_str().into()),
            to_state: MemoryLifecycleState::Active.as_str().into(),
            actor: actor.trim().into(),
            reason: format!("pipeline operation {}", operation_id.trim()),
            recorded_at_ms: now_ms,
        })
    }

    pub fn evaluate_kioku_impact(
        &self,
        id: &str,
        version: u32,
        minimum_samples_per_arm: usize,
        regression_threshold: f64,
        actor: &str,
        now_ms: i64,
    ) -> Result<MemoryImpactEvaluation, String> {
        if minimum_samples_per_arm == 0
            || !regression_threshold.is_finite()
            || regression_threshold < 0.0
            || actor.trim().is_empty()
        {
            return Err(
                "impact evaluation requires samples, a non-negative threshold, and actor".into(),
            );
        }
        let mut memory = self
            .get_kioku_memory(id, version)?
            .ok_or_else(|| "memory version not found".to_string())?;
        if memory.state != MemoryLifecycleState::Active {
            return Err("only active memories can be evaluated".into());
        }
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT memory_applied, passed FROM chisei_kioku_outcomes
                 WHERE memory_id=?1 AND memory_version=?2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![id, version], |row| {
                Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(statement);
        drop(conn);
        let treatment = rows
            .iter()
            .filter(|(applied, _)| *applied)
            .map(|(_, passed)| *passed)
            .collect::<Vec<_>>();
        let control = rows
            .iter()
            .filter(|(applied, _)| !*applied)
            .map(|(_, passed)| *passed)
            .collect::<Vec<_>>();
        if treatment.len() < minimum_samples_per_arm || control.len() < minimum_samples_per_arm {
            return Err("insufficient treatment or control samples".into());
        }
        let pass_rate = |samples: &[bool]| {
            samples.iter().filter(|passed| **passed).count() as f64 / samples.len() as f64
        };
        let treatment_pass_rate = pass_rate(&treatment);
        let control_pass_rate = pass_rate(&control);
        let delta = treatment_pass_rate - control_pass_rate;
        let retired = delta < -regression_threshold;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if retired {
            memory.state = MemoryLifecycleState::Rejected;
        } else {
            memory.last_confirmed_at_ms = Some(now_ms);
        }
        let memory_json = serde_json::to_string(&memory).map_err(|error| error.to_string())?;
        let updated = tx
            .execute(
                "UPDATE chisei_kioku_memories SET state=?1, memory_json=?2
                 WHERE id=?3 AND version=?4 AND state='active'",
                params![memory.state.as_str(), memory_json, id, version],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("memory changed during impact evaluation".into());
        }
        insert_lifecycle_event(
            &tx,
            &MemoryLifecycleEvent {
                memory_id: id.into(),
                memory_version: version,
                action: if retired { "regressed" } else { "confirmed" }.into(),
                from_state: Some(MemoryLifecycleState::Active.as_str().into()),
                to_state: memory.state.as_str().into(),
                actor: actor.trim().into(),
                reason: format!(
                    "treatment_pass_rate={treatment_pass_rate:.6} control_pass_rate={control_pass_rate:.6} delta={delta:.6}"
                ),
                recorded_at_ms: now_ms,
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(MemoryImpactEvaluation {
            memory_id: id.into(),
            memory_version: version,
            treatment_samples: treatment.len(),
            control_samples: control.len(),
            treatment_pass_rate,
            control_pass_rate,
            delta,
            retired,
        })
    }

    pub fn evaluate_kioku_impact_if_ready(
        &self,
        id: &str,
        version: u32,
        minimum_samples_per_arm: usize,
        regression_threshold: f64,
        actor: &str,
        now_ms: i64,
    ) -> Result<Option<MemoryImpactEvaluation>, String> {
        if minimum_samples_per_arm == 0 {
            return Err("impact evaluation requires samples in both arms".into());
        }
        let conn = self.conn();
        let (treatment, control): (i64, i64) = conn
            .query_row(
                "SELECT
                    COALESCE(SUM(CASE WHEN memory_applied=1 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN memory_applied=0 THEN 1 ELSE 0 END), 0)
                 FROM chisei_kioku_outcomes WHERE memory_id=?1 AND memory_version=?2",
                params![id, version],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| error.to_string())?;
        drop(conn);
        let minimum_samples_per_arm_i64 = i64::try_from(minimum_samples_per_arm)
            .map_err(|_| "minimum sample count exceeds i64".to_string())?;
        if treatment < minimum_samples_per_arm_i64 || control < minimum_samples_per_arm_i64 {
            return Ok(None);
        }
        if self
            .get_kioku_memory(id, version)?
            .is_none_or(|memory| memory.state != MemoryLifecycleState::Active)
        {
            return Ok(None);
        }
        self.evaluate_kioku_impact(
            id,
            version,
            minimum_samples_per_arm,
            regression_threshold,
            actor,
            now_ms,
        )
        .map(Some)
    }

    pub fn sweep_kioku_lifecycle(
        &self,
        actor: &str,
        now_ms: i64,
    ) -> Result<MemoryLifecycleSweep, String> {
        if actor.trim().is_empty() {
            return Err("lifecycle sweep actor is required".into());
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let memory_json = {
            let mut statement = tx
                .prepare("SELECT memory_json FROM chisei_kioku_memories")
                .map_err(|error| error.to_string())?;
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?
        };
        let mut sweep = MemoryLifecycleSweep::default();
        for json in memory_json {
            let mut memory: KiokuMemory =
                serde_json::from_str(&json).map_err(|error| error.to_string())?;
            if memory
                .retention_until_ms
                .is_some_and(|retention| retention <= now_ms)
            {
                tx.execute(
                    "DELETE FROM chisei_kioku_outcomes WHERE memory_id=?1 AND memory_version=?2",
                    params![memory.id, memory.version],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "DELETE FROM chisei_kioku_evidence_links WHERE memory_id=?1 AND memory_version=?2",
                    params![memory.id, memory.version],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "DELETE FROM chisei_kioku_memories WHERE id=?1 AND version=?2",
                    params![memory.id, memory.version],
                )
                .map_err(|error| error.to_string())?;
                insert_lifecycle_event(
                    &tx,
                    &MemoryLifecycleEvent {
                        memory_id: memory.id,
                        memory_version: memory.version,
                        action: "purged".into(),
                        from_state: Some(memory.state.as_str().into()),
                        to_state: "purged".into(),
                        actor: actor.trim().into(),
                        reason: "retention period elapsed".into(),
                        recorded_at_ms: now_ms,
                    },
                )?;
                sweep.purged += 1;
            } else if memory.state == MemoryLifecycleState::Active
                && memory
                    .expires_at_ms
                    .is_some_and(|expires| expires <= now_ms)
            {
                memory.state = MemoryLifecycleState::Rejected;
                let updated_json =
                    serde_json::to_string(&memory).map_err(|error| error.to_string())?;
                tx.execute(
                    "UPDATE chisei_kioku_memories SET state='rejected', memory_json=?1
                     WHERE id=?2 AND version=?3 AND state='active'",
                    params![updated_json, memory.id, memory.version],
                )
                .map_err(|error| error.to_string())?;
                insert_lifecycle_event(
                    &tx,
                    &MemoryLifecycleEvent {
                        memory_id: memory.id,
                        memory_version: memory.version,
                        action: "expired".into(),
                        from_state: Some(MemoryLifecycleState::Active.as_str().into()),
                        to_state: MemoryLifecycleState::Rejected.as_str().into(),
                        actor: actor.trim().into(),
                        reason: "memory expiry elapsed".into(),
                        recorded_at_ms: now_ms,
                    },
                )?;
                sweep.expired += 1;
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(sweep)
    }
}

fn validate_resolvable_evidence(
    memory: &KiokuMemory,
    evidence: &[KiokuEvidenceLink],
) -> Result<(), String> {
    if evidence.len() != memory.sample_size as usize {
        return Err(format!(
            "memory {} version {} has unresolved evidence",
            memory.id, memory.version
        ));
    }
    let mut supporting = false;
    let mut operations = std::collections::HashSet::new();
    for link in evidence {
        link.validate(memory)?;
        supporting |= link.stance == MemoryEvidenceStance::Supporting;
        if !operations.insert(link.operation_id.as_str()) {
            return Err(format!(
                "memory {} version {} repeats operation evidence",
                memory.id, memory.version
            ));
        }
    }
    if !supporting {
        return Err(format!(
            "memory {} version {} lacks supporting evidence",
            memory.id, memory.version
        ));
    }
    Ok(())
}

fn insert_lifecycle_event(
    tx: &rusqlite::Transaction<'_>,
    event: &MemoryLifecycleEvent,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO chisei_kioku_lifecycle_events
         (memory_id, memory_version, action, from_state, to_state, actor, reason, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            event.memory_id,
            event.memory_version,
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

impl SekaiDb {
    pub(crate) fn put_operation_receipt_with_kioku_holdouts(
        &self,
        receipt: &OperationReceipt,
        holdouts: &[(String, u32)],
        actor: &str,
        recorded_at_ms: i64,
    ) -> Result<(), String> {
        if actor.trim().is_empty() {
            return Err("holdout actor is required".into());
        }
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        for (memory_id, memory_version) in holdouts {
            let state = tx
                .query_row(
                    "SELECT state FROM chisei_kioku_memories WHERE id=?1 AND version=?2",
                    params![memory_id, memory_version],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "memory version not found".to_string())?;
            if state != MemoryLifecycleState::Active.as_str() {
                return Err("only active memories can be assigned to holdout".into());
            }
        }
        crate::db::chisei::upsert_operation_receipt(&tx, receipt)?;
        for (memory_id, memory_version) in holdouts {
            insert_lifecycle_event(
                &tx,
                &MemoryLifecycleEvent {
                    memory_id: memory_id.clone(),
                    memory_version: *memory_version,
                    action: "held_out".into(),
                    from_state: Some(MemoryLifecycleState::Active.as_str().into()),
                    to_state: MemoryLifecycleState::Active.as_str().into(),
                    actor: actor.trim().into(),
                    reason: format!("pipeline operation {}", receipt.operation_id),
                    recorded_at_ms,
                },
            )?;
        }
        tx.commit().map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptEventKind,
    };
    use crate::domain::Object;
    use crate::sekai::security::Grant;
    use std::collections::{BTreeMap, HashMap};

    fn candidate() -> KiokuMemory {
        KiokuMemory {
            contract_version: KIOKU_MEMORY_VERSION.into(),
            id: "memory-1".into(),
            version: 1,
            kind: MemoryKind::Warning,
            claim: "Verify generated migrations before deployment".into(),
            namespace: "payments".into(),
            operation_classes: vec!["schema_change".into()],
            affinity_object_ids: vec!["component:migrations".into()],
            outcome_definition: "deployment verification passed".into(),
            confidence_bps: 8_000,
            sample_size: 1,
            uncertainty: "single verified operation".into(),
            producer_identity: "kioku:test".into(),
            derivation_method: "verified_binary_outcomes/v1".into(),
            classification: EvidenceClassification::Internal,
            retention_until_ms: Some(300),
            state: MemoryLifecycleState::Candidate,
            created_at_ms: 100,
            reviewed_at_ms: None,
            expires_at_ms: Some(200),
            last_confirmed_at_ms: Some(100),
            supersedes: None,
        }
    }

    fn candidate_evidence(memory: &KiokuMemory) -> KiokuEvidenceLink {
        KiokuEvidenceLink {
            memory_id: memory.id.clone(),
            memory_version: memory.version,
            operation_id: "operation-1".into(),
            verification_event_id: "verify-1".into(),
            evidence_reference: "artifact://verification".into(),
            evidence_digest: "abc123".into(),
            stance: MemoryEvidenceStance::Supporting,
            outcome_metric: "deployment verification passed".into(),
            outcome_value: 1.0,
            observed_at_ms: 100,
        }
    }

    #[test]
    fn candidate_listing_is_namespace_scoped_and_operation_filtered() {
        let db = SekaiDb::new(":memory:").unwrap();
        let first = candidate();
        db.insert_kioku_memory(&first, &[candidate_evidence(&first)])
            .unwrap();
        let mut second = candidate();
        second.id = "memory-2".into();
        second.namespace = "other".into();
        let mut second_evidence = candidate_evidence(&second);
        second_evidence.operation_id = "operation-2".into();
        db.insert_kioku_memory(&second, &[second_evidence]).unwrap();

        let listed = db
            .list_kioku_candidates("payments", Some("schema_change"), 10)
            .unwrap();
        assert_eq!(listed, vec![first]);
        assert!(
            db.list_kioku_candidates("payments", Some("incident"), 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn disabling_active_memory_is_audited_and_removes_it_from_retrieval() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut memory = candidate();
        memory.confidence_bps = 10_000;
        db.insert_kioku_memory(&memory, &[candidate_evidence(&memory)])
            .unwrap();
        db.review_kioku_candidate(
            &memory.id,
            memory.version,
            HumanMemoryReview {
                action: HumanReviewAction::Promote,
                reviewer: "reviewer".into(),
                rationale: "verified".into(),
                reviewed_at_ms: 120,
            },
        )
        .unwrap();
        let disabled = db
            .disable_kioku_memory(&memory.id, memory.version, "reviewer", "regressed", 130)
            .unwrap();
        assert_eq!(disabled.state, MemoryLifecycleState::Rejected);
        assert!(
            db.list_kioku_lifecycle_events(&memory.id, memory.version)
                .unwrap()
                .iter()
                .any(|event| event.action == "disabled")
        );
    }

    fn verified_outcome(operation_id: &str, passed: bool) -> VerifiedOutcome {
        let event =
            |id: &str,
             parent: Option<&str>,
             kind: ReceiptEventKind,
             references: Vec<GovernedReference>| OperationReceiptEvent {
                event_id: format!("{operation_id}-{id}"),
                operation_id: operation_id.into(),
                parent_event_id: parent.map(|parent| format!("{operation_id}-{parent}")),
                timestamp_ms: 100,
                kind,
                surface: kind.surface(),
                actor: "agent:test".into(),
                references,
                attributes: BTreeMap::new(),
            };
        let mut receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.into(),
            parent_operation_id: None,
            namespace: "payments".into(),
            operation_class: "schema_change".into(),
            initiating_actor: "agent:test".into(),
            schema_version: "schema:v1".into(),
            policy_version: "policy:v1".into(),
            started_at_ms: 90,
            completed_at_ms: Some(110),
            events: vec![
                event("intent", None, ReceiptEventKind::IntentRecorded, vec![]),
                event(
                    "policy",
                    Some("intent"),
                    ReceiptEventKind::PolicyDecided,
                    vec![],
                ),
                event(
                    "route",
                    Some("policy"),
                    ReceiptEventKind::RouteSelected,
                    vec![],
                ),
                event(
                    "budget",
                    Some("route"),
                    ReceiptEventKind::BudgetDecided,
                    vec![],
                ),
                event(
                    "verify",
                    Some("budget"),
                    ReceiptEventKind::VerificationRecorded,
                    vec![GovernedReference {
                        kind: "test_report".into(),
                        reference: format!("evidence:{operation_id}"),
                        content_hash: Some(format!("digest-{operation_id}")),
                        disclosed_fields: vec!["status".into()],
                        omitted: false,
                        omission_reason: None,
                    }],
                ),
                event(
                    "outcome",
                    Some("verify"),
                    ReceiptEventKind::OutcomeRecorded,
                    vec![],
                ),
            ],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
        };
        let outcome = receipt
            .events
            .iter_mut()
            .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
            .unwrap();
        outcome
            .attributes
            .insert("outcome_metric".into(), "verification_pass_rate".into());
        outcome.attributes.insert(
            "outcome_value".into(),
            if passed { "1" } else { "0" }.into(),
        );
        outcome
            .attributes
            .insert("passed".into(), passed.to_string());
        VerifiedOutcome {
            receipt,
            passed,
            outcome_metric: "verification_pass_rate".into(),
            outcome_value: if passed { 1.0 } else { 0.0 },
        }
    }

    fn persist_outcome_receipt(db: &SekaiDb, operation_id: &str, request_id: &str, passed: bool) {
        let mut receipt = verified_outcome(operation_id, passed).receipt;
        receipt
            .events
            .iter_mut()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .unwrap()
            .attributes
            .insert("request_id".into(), request_id.into());
        db.put_operation_receipt(&receipt).unwrap();
    }

    #[test]
    fn receipt_and_holdout_assignments_are_atomic() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut memory = candidate();
        memory.confidence_bps = 10_000;
        db.insert_kioku_memory(&memory, &[candidate_evidence(&memory)])
            .unwrap();
        db.review_kioku_candidate(
            &memory.id,
            memory.version,
            HumanMemoryReview {
                action: HumanReviewAction::Promote,
                reviewer: "reviewer".into(),
                rationale: "verified".into(),
                reviewed_at_ms: 120,
            },
        )
        .unwrap();
        let receipt = verified_outcome("atomic-plan", true).receipt;

        let error = db
            .put_operation_receipt_with_kioku_holdouts(
                &receipt,
                &[(memory.id.clone(), memory.version), ("missing".into(), 1)],
                "agent:test",
                130,
            )
            .unwrap_err();

        assert_eq!(error, "memory version not found");
        assert!(db.get_operation_receipt("atomic-plan").unwrap().is_none());
        assert!(
            db.list_kioku_lifecycle_events(&memory.id, memory.version)
                .unwrap()
                .iter()
                .all(|event| event.action != "held_out")
        );
    }

    fn active_memory(
        db: &SekaiDb,
        id: &str,
        operation_id: &str,
        affinity_object_ids: Vec<String>,
        classification: EvidenceClassification,
    ) {
        db.produce_kioku_candidate(CandidateDerivation {
            id: id.into(),
            kind: MemoryKind::Recommendation,
            claim: format!("Apply guidance from {id}"),
            outcome_definition: "verification pass rate".into(),
            outcomes: vec![verified_outcome(operation_id, true)],
            affinity_object_ids,
            producer_identity: "kioku:deriver".into(),
            classification,
            created_at_ms: 120,
            expires_at_ms: Some(220),
            retention_until_ms: Some(320),
        })
        .unwrap();
        db.review_kioku_candidate(
            id,
            1,
            HumanMemoryReview {
                action: HumanReviewAction::Promote,
                reviewer: "human:operator".into(),
                rationale: "representative evidence".into(),
                reviewed_at_ms: 130,
            },
        )
        .unwrap();
    }

    #[test]
    fn persists_versioned_memory_with_traceable_evidence() {
        let db = SekaiDb::new(":memory:").unwrap();
        let memory = candidate();
        let link = KiokuEvidenceLink {
            memory_id: memory.id.clone(),
            memory_version: memory.version,
            operation_id: "operation-1".into(),
            verification_event_id: "verify-1".into(),
            evidence_reference: "evidence:1".into(),
            evidence_digest: "abc123".into(),
            stance: MemoryEvidenceStance::Supporting,
            outcome_metric: "passed".into(),
            outcome_value: 1.0,
            observed_at_ms: 90,
        };

        db.insert_kioku_memory(&memory, std::slice::from_ref(&link))
            .unwrap();

        assert_eq!(db.get_kioku_memory("memory-1", 1).unwrap(), Some(memory));
        assert_eq!(db.list_kioku_evidence("memory-1", 1).unwrap(), vec![link]);
    }

    #[test]
    fn rejects_untraceable_memory() {
        let db = SekaiDb::new(":memory:").unwrap();
        let error = db.insert_kioku_memory(&candidate(), &[]).unwrap_err();
        assert!(error.contains("evidence link"));
    }

    #[test]
    fn rejects_direct_active_memory_insertion() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut memory = candidate();
        memory.state = MemoryLifecycleState::Active;
        memory.reviewed_at_ms = Some(110);
        let link = KiokuEvidenceLink {
            memory_id: memory.id.clone(),
            memory_version: memory.version,
            operation_id: "operation-1".into(),
            verification_event_id: "verify-1".into(),
            evidence_reference: "evidence:1".into(),
            evidence_digest: "abc123".into(),
            stance: MemoryEvidenceStance::Supporting,
            outcome_metric: "passed".into(),
            outcome_value: 1.0,
            observed_at_ms: 90,
        };
        let error = db.insert_kioku_memory(&memory, &[link]).unwrap_err();
        assert!(error.contains("unreviewed candidates"));
    }

    #[test]
    fn rejects_invalid_confidence_and_contradictions_only() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut memory = candidate();
        memory.confidence_bps = 10_001;
        assert!(
            memory
                .validate_contract()
                .unwrap_err()
                .iter()
                .any(|error| error.contains("confidence_bps"))
        );

        memory.confidence_bps = 8_000;
        let contradiction = KiokuEvidenceLink {
            memory_id: memory.id.clone(),
            memory_version: memory.version,
            operation_id: "operation-1".into(),
            verification_event_id: "verify-1".into(),
            evidence_reference: "evidence:1".into(),
            evidence_digest: "abc123".into(),
            stance: MemoryEvidenceStance::Contradicting,
            outcome_metric: "passed".into(),
            outcome_value: 0.0,
            observed_at_ms: 90,
        };
        let error = db
            .insert_kioku_memory(&memory, &[contradiction])
            .unwrap_err();
        assert!(error.contains("supporting evidence"));
    }

    #[test]
    fn derives_candidate_from_verified_binary_outcomes() {
        let db = SekaiDb::new(":memory:").unwrap();
        let memory = db
            .produce_kioku_candidate(CandidateDerivation {
                id: "derived-1".into(),
                kind: MemoryKind::Recommendation,
                claim: "Run migration verification before deployment".into(),
                outcome_definition: "verification pass rate".into(),
                outcomes: vec![
                    verified_outcome("operation-1", true),
                    verified_outcome("operation-2", false),
                ],
                affinity_object_ids: vec!["component:migrations".into()],
                producer_identity: "kioku:deriver".into(),
                classification: EvidenceClassification::Internal,
                created_at_ms: 120,
                expires_at_ms: Some(220),
                retention_until_ms: Some(320),
            })
            .unwrap();

        assert_eq!(memory.state, MemoryLifecycleState::Candidate);
        assert_eq!(memory.confidence_bps, 5_000);
        assert_eq!(memory.sample_size, 2);
        let links = db.list_kioku_evidence("derived-1", 1).unwrap();
        assert_eq!(links.len(), 2);
        assert!(
            links
                .iter()
                .any(|link| link.stance == MemoryEvidenceStance::Contradicting)
        );
    }

    #[test]
    fn candidate_derivation_rejects_unverified_receipts() {
        let mut outcome = verified_outcome("operation-1", true);
        outcome.receipt.events.retain(|event| {
            event.kind != ReceiptEventKind::VerificationRecorded
                && event.kind != ReceiptEventKind::OutcomeRecorded
        });
        let error = derive_verified_outcome_candidate(CandidateDerivation {
            id: "derived-1".into(),
            kind: MemoryKind::Warning,
            claim: "Verify migrations".into(),
            outcome_definition: "verification pass rate".into(),
            outcomes: vec![outcome],
            affinity_object_ids: vec![],
            producer_identity: "kioku:deriver".into(),
            classification: EvidenceClassification::Internal,
            created_at_ms: 120,
            expires_at_ms: Some(220),
            retention_until_ms: Some(320),
        })
        .unwrap_err();
        assert!(error.contains("incomplete"));
    }

    #[test]
    fn candidate_derivation_requires_comparable_metrics_and_causal_verification() {
        let mut mixed = verified_outcome("operation-2", true);
        mixed.outcome_metric = "latency_ms".into();
        let input = |outcomes| CandidateDerivation {
            id: "derived-1".into(),
            kind: MemoryKind::Warning,
            claim: "Verify migrations".into(),
            outcome_definition: "verification pass rate".into(),
            outcomes,
            affinity_object_ids: vec![],
            producer_identity: "kioku:deriver".into(),
            classification: EvidenceClassification::Internal,
            created_at_ms: 120,
            expires_at_ms: Some(220),
            retention_until_ms: Some(320),
        };
        let error = derive_verified_outcome_candidate(input(vec![
            verified_outcome("operation-1", true),
            mixed,
        ]))
        .unwrap_err();
        assert!(error.contains("one outcome metric"));

        let mut unbound = verified_outcome("operation-3", true);
        let outcome = unbound
            .receipt
            .events
            .iter_mut()
            .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
            .unwrap();
        outcome.parent_event_id = Some("operation-3-budget".into());
        let error = derive_verified_outcome_candidate(input(vec![unbound])).unwrap_err();
        assert!(error.contains("linked to its outcome"));

        let mut multiple = verified_outcome("operation-4", true);
        let mut unrelated = multiple
            .receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::VerificationRecorded)
            .unwrap()
            .clone();
        unrelated.event_id = "operation-4-unrelated-verify".into();
        unrelated.parent_event_id = Some("operation-4-budget".into());
        multiple.receipt.events.insert(4, unrelated);
        let (_, links) = derive_verified_outcome_candidate(input(vec![multiple])).unwrap();
        assert_eq!(links[0].verification_event_id, "operation-4-verify");
    }

    #[test]
    fn validates_and_promotes_candidate_with_human_audit() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.produce_kioku_candidate(CandidateDerivation {
            id: "reviewed-1".into(),
            kind: MemoryKind::Recommendation,
            claim: "Verify migrations".into(),
            outcome_definition: "verification pass rate".into(),
            outcomes: vec![verified_outcome("operation-1", true)],
            affinity_object_ids: vec![],
            producer_identity: "kioku:deriver".into(),
            classification: EvidenceClassification::Internal,
            created_at_ms: 120,
            expires_at_ms: Some(220),
            retention_until_ms: Some(320),
        })
        .unwrap();

        let validation = db.validate_kioku_candidate("reviewed-1", 1).unwrap();
        assert!(validation.valid);
        let promoted = db
            .review_kioku_candidate(
                "reviewed-1",
                1,
                HumanMemoryReview {
                    action: HumanReviewAction::Promote,
                    reviewer: "human:operator".into(),
                    rationale: "evidence is representative".into(),
                    reviewed_at_ms: 130,
                },
            )
            .unwrap();
        assert_eq!(promoted.state, MemoryLifecycleState::Active);
        let duplicate_review = db
            .review_kioku_candidate(
                "reviewed-1",
                1,
                HumanMemoryReview {
                    action: HumanReviewAction::Reject,
                    reviewer: "human:operator".into(),
                    rationale: "late review".into(),
                    reviewed_at_ms: 140,
                },
            )
            .unwrap_err();
        assert!(duplicate_review.contains("no longer awaiting review"));
        let events = db.list_kioku_lifecycle_events("reviewed-1", 1).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].action, "promoted");
        assert_eq!(events[1].actor, "human:operator");
    }

    #[test]
    fn retrieves_active_memories_by_scope_affinity_and_classification() {
        let db = SekaiDb::new(":memory:").unwrap();
        for object in [
            Object {
                id: "namespace-payments".into(),
                kind: "namespace".into(),
                name: "payments".into(),
                namespace: "payments".into(),
                external_id: "namespace:payments".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            },
            Object {
                id: "namespace-other".into(),
                kind: "namespace".into(),
                name: "other".into(),
                namespace: "other".into(),
                external_id: "namespace:other".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            },
            Object {
                id: "component:migrations".into(),
                kind: "component".into(),
                name: "migrations".into(),
                namespace: "payments".into(),
                external_id: "component:migrations".into(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            },
        ] {
            db.create_object(&object).unwrap();
        }
        for grant in [
            Grant {
                id: "grant-payments".into(),
                object_id: "namespace-payments".into(),
                principal: "agent:planner".into(),
                role: Role::Viewer,
                created: 1,
            },
            Grant {
                id: "grant-other".into(),
                object_id: "namespace-other".into(),
                principal: "agent:other".into(),
                role: Role::Viewer,
                created: 1,
            },
            Grant {
                id: "grant-component".into(),
                object_id: "component:migrations".into(),
                principal: "agent:planner".into(),
                role: Role::Viewer,
                created: 1,
            },
        ] {
            db.create_grant(&grant).unwrap();
        }
        active_memory(
            &db,
            "generic",
            "operation-1",
            vec![],
            EvidenceClassification::Internal,
        );
        active_memory(
            &db,
            "affine",
            "operation-2",
            vec!["component:migrations".into()],
            EvidenceClassification::Internal,
        );
        active_memory(
            &db,
            "restricted",
            "operation-3",
            vec!["component:migrations".into()],
            EvidenceClassification::Restricted,
        );
        let request = MemoryRetrievalRequest {
            namespace: "payments".into(),
            operation_class: "schema_change".into(),
            context_object_ids: vec!["component:migrations".into()],
            classification_ceiling: EvidenceClassification::Internal,
            min_confidence_bps: 5_000,
            max_results: 10,
            actor: "agent:planner".into(),
            now_ms: 150,
        };

        let retrieved = db.retrieve_kioku_memories(&request).unwrap();
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved[0].memory.id, "affine");
        assert_eq!(retrieved[0].graph_affinity, 1.0);
        assert!(!retrieved[0].evidence.is_empty());
        let events = db.list_kioku_lifecycle_events("affine", 1).unwrap();
        assert_eq!(events.last().unwrap().action, "retrieved");

        let mut spoofed = request.clone();
        spoofed.actor = "root".into();
        spoofed.classification_ceiling = EvidenceClassification::Restricted;
        assert!(
            db.retrieve_kioku_memories(&spoofed)
                .unwrap_err()
                .contains("not authorized")
        );

        let mut unauthorized = request;
        unauthorized.namespace = "other".into();
        assert!(
            db.retrieve_kioku_memories(&unauthorized)
                .unwrap_err()
                .contains("not authorized")
        );
        unauthorized.namespace = "payments".into();
        unauthorized.classification_ceiling = EvidenceClassification::Restricted;
        assert!(
            db.retrieve_kioku_memories(&unauthorized)
                .unwrap_err()
                .contains("exceeds actor grant")
        );
    }

    #[test]
    fn invalidated_assignment_cannot_record_an_outcome() {
        let db = SekaiDb::new(":memory:").unwrap();
        active_memory(
            &db,
            "invalidated",
            "seed-operation",
            vec![],
            EvidenceClassification::Internal,
        );
        persist_outcome_receipt(&db, "control-invalidated", "request-control", true);
        db.record_kioku_holdout(
            "invalidated",
            1,
            "control-invalidated",
            "kioku:evaluator",
            140,
        )
        .unwrap();
        db.record_kioku_lifecycle_event(&MemoryLifecycleEvent {
            memory_id: "invalidated".into(),
            memory_version: 1,
            action: "holdout_invalidated".into(),
            from_state: Some("active".into()),
            to_state: "active".into(),
            actor: "kioku:evaluator".into(),
            reason: "pipeline operation control-invalidated".into(),
            recorded_at_ms: 145,
        })
        .unwrap();

        let error = db
            .record_kioku_outcome(&MemoryOutcomeObservation {
                memory_id: "invalidated".into(),
                memory_version: 1,
                operation_id: "control-invalidated".into(),
                request_id: "request-control".into(),
                memory_applied: false,
                outcome_metric: "verification_pass_rate".into(),
                outcome_value: 1.0,
                passed: true,
                recorded_at_ms: 150,
            })
            .unwrap_err();
        assert!(error.contains("treatment assignment"));
    }

    #[test]
    fn outcome_metric_matching_ignores_receipt_whitespace() {
        let db = SekaiDb::new(":memory:").unwrap();
        active_memory(
            &db,
            "trimmed-metric",
            "seed-operation",
            vec![],
            EvidenceClassification::Internal,
        );
        let mut receipt = verified_outcome("trimmed-operation", true).receipt;
        receipt
            .events
            .iter_mut()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .unwrap()
            .attributes
            .insert("request_id".into(), "request-trimmed".into());
        receipt
            .events
            .iter_mut()
            .find(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
            .unwrap()
            .attributes
            .insert("outcome_metric".into(), " verification_pass_rate ".into());
        db.put_operation_receipt(&receipt).unwrap();
        db.record_kioku_lifecycle_event(&MemoryLifecycleEvent {
            memory_id: "trimmed-metric".into(),
            memory_version: 1,
            action: "injected".into(),
            from_state: Some("active".into()),
            to_state: "active".into(),
            actor: "agent:planner".into(),
            reason: "pipeline request request-trimmed".into(),
            recorded_at_ms: 140,
        })
        .unwrap();
        assert_eq!(
            db.list_kioku_outcome_assignments("trimmed-operation")
                .unwrap(),
            vec![MemoryOutcomeAssignment {
                memory_id: "trimmed-metric".into(),
                memory_version: 1,
                memory_applied: true,
            }]
        );

        db.record_kioku_outcome(&MemoryOutcomeObservation {
            memory_id: "trimmed-metric".into(),
            memory_version: 1,
            operation_id: "trimmed-operation".into(),
            request_id: "request-trimmed".into(),
            memory_applied: true,
            outcome_metric: "verification_pass_rate".into(),
            outcome_value: 1.0,
            passed: true,
            recorded_at_ms: 150,
        })
        .unwrap();
    }

    #[test]
    fn retires_regressing_memory_from_held_out_outcomes() {
        let db = SekaiDb::new(":memory:").unwrap();
        active_memory(
            &db,
            "regressing",
            "seed-operation",
            vec![],
            EvidenceClassification::Internal,
        );
        for operation_id in ["treatment-1", "treatment-2"] {
            let request_id = format!("request-{operation_id}");
            persist_outcome_receipt(&db, operation_id, &request_id, false);
            db.record_kioku_lifecycle_event(&MemoryLifecycleEvent {
                memory_id: "regressing".into(),
                memory_version: 1,
                action: "injected".into(),
                from_state: Some("active".into()),
                to_state: "active".into(),
                actor: "agent:planner".into(),
                reason: format!("pipeline operation {operation_id}"),
                recorded_at_ms: 140,
            })
            .unwrap();
            let observation = MemoryOutcomeObservation {
                memory_id: "regressing".into(),
                memory_version: 1,
                operation_id: operation_id.into(),
                request_id,
                memory_applied: true,
                outcome_metric: "verification_pass_rate".into(),
                outcome_value: 0.0,
                passed: false,
                recorded_at_ms: 150,
            };
            let mut forged = observation.clone();
            forged.outcome_value = 1.0;
            forged.passed = true;
            assert!(db.record_kioku_outcome(&forged).is_err());
            db.record_kioku_outcome(&observation).unwrap();
            db.record_kioku_outcome(&observation).unwrap();
        }
        for operation_id in ["control-1", "control-2"] {
            let request_id = format!("request-{operation_id}");
            persist_outcome_receipt(&db, operation_id, &request_id, true);
            db.record_kioku_holdout("regressing", 1, operation_id, "kioku:evaluator", 140)
                .unwrap();
            db.record_kioku_outcome(&MemoryOutcomeObservation {
                memory_id: "regressing".into(),
                memory_version: 1,
                operation_id: operation_id.into(),
                request_id,
                memory_applied: false,
                outcome_metric: "verification_pass_rate".into(),
                outcome_value: 1.0,
                passed: true,
                recorded_at_ms: 150,
            })
            .unwrap();
        }

        let evaluation = db
            .evaluate_kioku_impact_if_ready("regressing", 1, 2, 0.05, "kioku:evaluator", 160)
            .unwrap()
            .expect("both evaluation arms are ready");
        assert!(evaluation.retired);
        assert_eq!(evaluation.delta, -1.0);
        assert_eq!(
            db.get_kioku_memory("regressing", 1).unwrap().unwrap().state,
            MemoryLifecycleState::Rejected
        );
        assert_eq!(
            db.list_kioku_lifecycle_events("regressing", 1)
                .unwrap()
                .last()
                .unwrap()
                .action,
            "regressed"
        );
    }

    #[test]
    fn holdout_assignments_are_scoped_to_operation_receipts() {
        let db = SekaiDb::new(":memory:").unwrap();
        active_memory(
            &db,
            "scoped-holdout",
            "seed-operation",
            vec![],
            EvidenceClassification::Internal,
        );
        db.record_kioku_holdout(
            "scoped-holdout",
            1,
            "preview-operation",
            "agent:planner",
            140,
        )
        .unwrap();

        assert_eq!(
            db.list_kioku_outcome_assignments("preview-operation")
                .unwrap(),
            vec![MemoryOutcomeAssignment {
                memory_id: "scoped-holdout".into(),
                memory_version: 1,
                memory_applied: false,
            }]
        );
        assert!(
            db.list_kioku_outcome_assignments("completed-operation")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn supersedes_atomically_and_sweeps_expiry_and_retention() {
        let db = SekaiDb::new(":memory:").unwrap();
        active_memory(
            &db,
            "old",
            "operation-old",
            vec![],
            EvidenceClassification::Internal,
        );
        let mut replacement = candidate();
        replacement.id = "new".into();
        replacement.confidence_bps = 10_000;
        replacement.supersedes = Some(MemoryVersionRef {
            memory_id: "old".into(),
            version: 1,
        });
        let evidence = KiokuEvidenceLink {
            memory_id: "new".into(),
            memory_version: 1,
            operation_id: "operation-new".into(),
            verification_event_id: "verify-new".into(),
            evidence_reference: "evidence:new".into(),
            evidence_digest: "digest-new".into(),
            stance: MemoryEvidenceStance::Supporting,
            outcome_metric: "passed".into(),
            outcome_value: 1.0,
            observed_at_ms: 100,
        };
        db.insert_kioku_memory(&replacement, &[evidence]).unwrap();
        db.review_kioku_candidate(
            "new",
            1,
            HumanMemoryReview {
                action: HumanReviewAction::Promote,
                reviewer: "human:operator".into(),
                rationale: "newer representative evidence".into(),
                reviewed_at_ms: 130,
            },
        )
        .unwrap();
        assert_eq!(
            db.get_kioku_memory("old", 1).unwrap().unwrap().state,
            MemoryLifecycleState::Superseded
        );
        assert_eq!(
            db.list_kioku_lifecycle_events("old", 1)
                .unwrap()
                .last()
                .unwrap()
                .action,
            "superseded"
        );

        let sweep = db.sweep_kioku_lifecycle("kioku:sweeper", 221).unwrap();
        assert_eq!(sweep.expired, 1);
        assert_eq!(
            db.list_kioku_lifecycle_events("new", 1)
                .unwrap()
                .last()
                .unwrap()
                .action,
            "expired"
        );
        let sweep = db.sweep_kioku_lifecycle("kioku:sweeper", 321).unwrap();
        assert_eq!(sweep.purged, 2);
        assert!(db.get_kioku_memory("new", 1).unwrap().is_none());
        assert_eq!(
            db.list_kioku_lifecycle_events("new", 1)
                .unwrap()
                .last()
                .unwrap()
                .action,
            "purged"
        );
    }
}
