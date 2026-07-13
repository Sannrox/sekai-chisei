//! Governed institutional memory derived from verifiable operation outcomes.

use crate::chisei::receipt::{OperationReceipt, ReceiptEventKind};
use crate::db::sekai::SekaiDb;
use crate::sekai::evidence::EvidenceClassification;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

pub const KIOKU_MEMORY_VERSION: &str = "kioku.memory/v1";

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
    fn validate(&self, memory: &KiokuMemory) -> Result<(), String> {
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
                ON chisei_kioku_evidence_links(operation_id);",
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptEventKind,
    };
    use std::collections::BTreeMap;

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
        let receipt = OperationReceipt {
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
        VerifiedOutcome {
            receipt,
            passed,
            outcome_metric: "verification_pass_rate".into(),
            outcome_value: if passed { 1.0 } else { 0.0 },
        }
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

        db.insert_kioku_memory(&memory, &[link.clone()]).unwrap();

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
}
