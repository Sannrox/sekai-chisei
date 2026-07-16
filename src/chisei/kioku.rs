//! Governed institutional memory derived from verifiable operation outcomes.

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
}
