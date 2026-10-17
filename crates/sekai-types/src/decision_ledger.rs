//! Decision ledger record, query filter, and hash-chain content hash.
//!
//! The rusqlite host that inserts chained rows stays in the plane. The row
//! format and `entry_hash` serialization are persisted and must not change.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub id: String,
    pub timestamp: i64,
    pub actor: String,
    pub action: String,
    pub reason: String,
    pub evidence: HashMap<String, String>,
    pub target_id: String,
    pub outcome: String,
}

#[derive(Debug, Clone, Default)]
pub struct DecisionFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target_id: Option<String>,
    pub after: i64,
    pub limit: i32,
    pub offset: i32,
}

pub fn lifecycle_scope_from_evidence(evidence: &HashMap<String, String>) -> (String, String) {
    let namespace = evidence
        .get("namespace")
        .or_else(|| evidence.get("project"))
        .cloned()
        .unwrap_or_default();
    let data_class = evidence
        .get("data_class")
        .cloned()
        .unwrap_or_else(|| "unclassified".into());
    (namespace, data_class)
}

/// Canonical content hash of a chained entry. The evidence is hashed as the
/// exact JSON string stored in the row so the raw bytes are integrity-covered
/// (a parsed representation would let unparseable garbage verify as `{}`).
pub fn entry_hash(seq: i64, prev_hash: &str, d: &Decision, evidence_json: &str) -> String {
    let canonical = serde_json::to_vec(&(
        seq,
        prev_hash,
        &d.id,
        d.timestamp,
        &d.actor,
        &d.action,
        &d.reason,
        evidence_json,
        &d.target_id,
        &d.outcome,
    ))
    .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rows already on disk were hashed with this exact serialization; the
    /// expected value is computed independently of this crate (compact JSON
    /// array of the chained fields, SHA-256, lowercase hex).
    #[test]
    fn entry_hash_format_is_pinned_for_pre_existing_rows() {
        let decision = Decision {
            id: "dec-1".into(),
            timestamp: 1_700_000_000_000,
            actor: "chisei.gate".into(),
            action: "route".into(),
            reason: "pinned format".into(),
            evidence: HashMap::from([("namespace".to_string(), "ns".to_string())]),
            target_id: "target-1".into(),
            outcome: "allow".into(),
        };
        assert_eq!(
            entry_hash(7, "abc", &decision, r#"{"namespace":"ns"}"#),
            "c92dae078281f0ff8cb65677c6541db68b93b67352a32fe0eecc2bcbed1cf9f4"
        );
    }
}
