//! Source-neutral contracts for externally produced evidence.
//!
//! The envelope is the authoritative source record. Specialized observation
//! stores are projections and must retain the evidence version they consumed.
//! Producer authentication establishes attribution only: envelope content is
//! untrusted until it passes validation, authorization, and projection.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const EVIDENCE_ENVELOPE_VERSION: &str = "sekai.evidence/v1";
pub const DEFAULT_MAX_EVIDENCE_BYTES: usize = 256 * 1024;
pub const DEFAULT_EVIDENCE_ENVELOPE_HEADROOM_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_RELATIONSHIPS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceIntent {
    Upsert,
    Retract,
    MarkStale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLifecycleState {
    Received,
    Validated,
    Deduplicated,
    Authorized,
    Projected,
    Available,
    Superseded,
    Retracted,
    Stale,
    Rejected,
    Quarantined,
}

impl EvidenceLifecycleState {
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Available)
    }

    pub const fn is_admitted(self) -> bool {
        matches!(self, Self::Authorized | Self::Projected | Self::Available)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Validated => "validated",
            Self::Deduplicated => "deduplicated",
            Self::Authorized => "authorized",
            Self::Projected => "projected",
            Self::Available => "available",
            Self::Superseded => "superseded",
            Self::Retracted => "retracted",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "received" => Self::Received,
            "validated" => Self::Validated,
            "deduplicated" => Self::Deduplicated,
            "authorized" => Self::Authorized,
            "projected" => Self::Projected,
            "available" => Self::Available,
            "superseded" => Self::Superseded,
            "retracted" => Self::Retracted,
            "stale" => Self::Stale,
            "rejected" => Self::Rejected,
            "quarantined" => Self::Quarantined,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl EvidenceClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSignal {
    Acceptance,
    Verification,
    Delivery,
    Regression,
    ResourceUse,
    OperationalHealth,
    Other,
}

impl EvidenceSignal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acceptance => "acceptance",
            Self::Verification => "verification",
            Self::Delivery => "delivery",
            Self::Regression => "regression",
            Self::ResourceUse => "resource_use",
            Self::OperationalHealth => "operational_health",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaCompatibility {
    Exact,
    BackwardCompatible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceTarget {
    pub namespace: String,
    pub object_external_id: String,
    pub object_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRelationship {
    pub relation: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_source_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_source_instance: String,
    pub target_source_record_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCausality {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_call_id: Option<String>,
    #[serde(default)]
    pub subject_references: Vec<String>,
    #[serde(default)]
    pub trace_context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEnvelope {
    pub contract_version: String,
    pub source_type: String,
    pub source_instance: String,
    pub source_record_id: String,
    pub source_version: String,
    /// Monotonic sequence assigned by the source instance. This is the only
    /// ordering signal used for supersession; source version labels are opaque.
    pub source_sequence: i64,
    pub target: EvidenceTarget,
    pub evidence_type: String,
    pub signal: EvidenceSignal,
    pub schema_id: String,
    pub schema_version: String,
    pub schema_compatibility: SchemaCompatibility,
    pub observed_at_ms: i64,
    pub collected_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    pub content: Value,
    #[serde(default)]
    pub relationships: Vec<EvidenceRelationship>,
    pub producer_identity: String,
    /// Producer-supplied confidence in basis points. It is an input to policy,
    /// not a trust decision made by Sekai.
    pub confidence_bps: u16,
    pub classification: EvidenceClassification,
    #[serde(default)]
    pub provenance: BTreeMap<String, String>,
    pub idempotency_key: String,
    /// Lowercase SHA-256 digest of the canonical structured content.
    pub content_digest: String,
    pub intent: EvidenceIntent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causality: Option<EvidenceCausality>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceLimits {
    pub max_content_bytes: usize,
    pub max_envelope_bytes: usize,
    pub max_relationships: usize,
    pub max_subject_references: usize,
}

impl Default for EvidenceLimits {
    fn default() -> Self {
        Self {
            max_content_bytes: DEFAULT_MAX_EVIDENCE_BYTES,
            max_envelope_bytes: DEFAULT_MAX_EVIDENCE_BYTES
                + DEFAULT_EVIDENCE_ENVELOPE_HEADROOM_BYTES,
            max_relationships: DEFAULT_MAX_RELATIONSHIPS,
            max_subject_references: DEFAULT_MAX_RELATIONSHIPS,
        }
    }
}

impl EvidenceEnvelope {
    pub fn validate_contract(&self, limits: EvidenceLimits) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.contract_version != EVIDENCE_ENVELOPE_VERSION {
            errors.push(format!(
                "unsupported evidence contract version {}",
                self.contract_version
            ));
        }
        for (field, value) in [
            ("source_type", self.source_type.as_str()),
            ("source_instance", self.source_instance.as_str()),
            ("source_record_id", self.source_record_id.as_str()),
            ("source_version", self.source_version.as_str()),
            ("namespace", self.target.namespace.as_str()),
            (
                "object_external_id",
                self.target.object_external_id.as_str(),
            ),
            ("object_kind", self.target.object_kind.as_str()),
            ("evidence_type", self.evidence_type.as_str()),
            ("schema_id", self.schema_id.as_str()),
            ("schema_version", self.schema_version.as_str()),
            ("producer_identity", self.producer_identity.as_str()),
            ("idempotency_key", self.idempotency_key.as_str()),
        ] {
            if value.trim().is_empty() {
                errors.push(format!("{field} is required"));
            }
        }
        if self.confidence_bps > 10_000 {
            errors.push("confidence_bps must be at most 10000".to_string());
        }
        if self.source_sequence < 0 {
            errors.push("source_sequence must not be negative".to_string());
        }
        if self
            .expires_at_ms
            .is_some_and(|expires_at| expires_at < self.observed_at_ms)
        {
            errors.push("expires_at_ms cannot precede observed_at_ms".to_string());
        }
        if self.content_digest.len() != 64
            || !self
                .content_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            errors.push("content_digest must be a lowercase SHA-256 digest".to_string());
        }
        let content_bytes = serde_json::to_vec(&self.content)
            .map(|content| content.len())
            .unwrap_or(usize::MAX);
        if content_bytes > limits.max_content_bytes {
            errors.push(format!(
                "content exceeds {} byte limit",
                limits.max_content_bytes
            ));
        }
        let envelope_bytes = serde_json::to_vec(self)
            .map(|envelope| envelope.len())
            .unwrap_or(usize::MAX);
        if envelope_bytes > limits.max_envelope_bytes {
            errors.push(format!(
                "evidence envelope exceeds {} byte limit",
                limits.max_envelope_bytes
            ));
        }
        if self.relationships.len() > limits.max_relationships {
            errors.push(format!(
                "relationships exceed {} item limit",
                limits.max_relationships
            ));
        }
        if self.relationships.iter().any(|relationship| {
            relationship.relation.trim().is_empty()
                || relationship.target_source_record_id.trim().is_empty()
                || (relationship.target_source_type.trim().is_empty()
                    != relationship.target_source_instance.trim().is_empty())
        }) {
            errors.push("relationships require relation and target source record".to_string());
        }
        if let Some(causality) = &self.causality {
            if causality.subject_references.len() > limits.max_subject_references {
                errors.push(format!(
                    "subject references exceed {} item limit",
                    limits.max_subject_references
                ));
            }
            if causality
                .operation_id
                .as_ref()
                .is_some_and(|id| id.trim().is_empty())
            {
                errors.push("operation_id cannot be blank".to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn envelope() -> EvidenceEnvelope {
        EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "change_management".into(),
            source_instance: "engineering-primary".into(),
            source_record_id: "change-42".into(),
            source_version: "3".into(),
            source_sequence: 3,
            target: EvidenceTarget {
                namespace: "acme".into(),
                object_external_id: "service:payments".into(),
                object_kind: "service".into(),
            },
            evidence_type: "change.reviewed".into(),
            signal: EvidenceSignal::Verification,
            schema_id: "change.reviewed".into(),
            schema_version: "1.0.0".into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: 100,
            collected_at_ms: 110,
            expires_at_ms: Some(1_000),
            content: json!({"result": "accepted"}),
            relationships: vec![EvidenceRelationship {
                relation: "verifies".into(),
                target_source_type: "build_system".into(),
                target_source_instance: "builds-primary".into(),
                target_source_record_id: "build-7".into(),
            }],
            producer_identity: "producer:change-adapter".into(),
            confidence_bps: 9_000,
            classification: EvidenceClassification::Internal,
            provenance: BTreeMap::new(),
            idempotency_key: "delivery-42".into(),
            content_digest: "a".repeat(64),
            intent: EvidenceIntent::Upsert,
            causality: Some(EvidenceCausality {
                operation_id: Some("op-1".into()),
                parent_operation_id: None,
                attempt_id: Some("attempt-1".into()),
                model_call_id: None,
                subject_references: vec!["service:payments".into()],
                trace_context: BTreeMap::new(),
            }),
        }
    }

    #[test]
    fn accepts_source_neutral_contract() {
        assert_eq!(
            envelope().validate_contract(EvidenceLimits::default()),
            Ok(())
        );
    }

    #[test]
    fn bounds_untrusted_content_and_relationships() {
        let mut evidence = envelope();
        evidence.content = json!({"payload": "too large"});
        evidence.relationships.push(EvidenceRelationship {
            relation: "conflicts_with".into(),
            target_source_type: "change_management".into(),
            target_source_instance: "engineering-primary".into(),
            target_source_record_id: "record-2".into(),
        });
        let errors = evidence
            .validate_contract(EvidenceLimits {
                max_content_bytes: 4,
                max_envelope_bytes: 1_024,
                max_relationships: 1,
                max_subject_references: 1,
            })
            .unwrap_err();
        assert!(errors.iter().any(|error| error.contains("byte limit")));
        assert!(errors.iter().any(|error| error.contains("relationships")));
    }

    #[test]
    fn lifecycle_only_exposes_available_evidence() {
        assert!(EvidenceLifecycleState::Available.is_usable());
        assert!(!EvidenceLifecycleState::Authorized.is_usable());
        assert!(!EvidenceLifecycleState::Rejected.is_usable());
    }

    #[test]
    fn legacy_relationship_identity_remains_v1_compatible() {
        let mut evidence = envelope();
        evidence.relationships[0].target_source_type.clear();
        evidence.relationships[0].target_source_instance.clear();
        assert_eq!(
            evidence.validate_contract(EvidenceLimits::default()),
            Ok(())
        );
        let serialized = serde_json::to_value(&evidence).unwrap();
        let relationship = &serialized["relationships"][0];
        assert!(relationship.get("target_source_type").is_none());
        assert!(relationship.get("target_source_instance").is_none());
    }
}
