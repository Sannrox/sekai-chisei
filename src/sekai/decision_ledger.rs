//! Decision ledger: the policy decision record, its query filter, and the
//! hash-chained append (ADR 0082, ADR 0096 rule 5).
//!
//! Decisions are stored in the `sekai_decisions` table as a tamper-evident
//! hash chain; Sekai's `ledger` module verifies and purges that chain and
//! Sekai's `audit` module re-exports the record types for its callers. The
//! row format and `entry_hash` serialization are persisted and must not
//! change, or verification of pre-existing rows fails.

use std::collections::HashMap;

use rusqlite::{Connection, OptionalExtension, params};
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

pub(crate) fn lifecycle_scope_from_evidence(
    evidence: &HashMap<String, String>,
) -> (String, String) {
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
pub(crate) fn entry_hash(seq: i64, prev_hash: &str, d: &Decision, evidence_json: &str) -> String {
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

/// Current chain head: the latest chained decision, falling back to the
/// latest purge anchor, falling back to genesis `(0, "")`.
pub(crate) fn chain_head(conn: &Connection) -> Result<(i64, String), String> {
    let decision_head = conn
        .query_row(
            "SELECT seq, entry_hash FROM sekai_decisions WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some(head) = decision_head {
        return Ok(head);
    }
    let anchor_head = conn
        .query_row(
            "SELECT seq, entry_hash FROM sekai_ledger_anchors ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(anchor_head.unwrap_or((0, String::new())))
}

/// Insert a decision as the next entry of the hash chain. The caller must
/// hold the same pooled connection for the whole call so the head read and
/// insert are not interleaved with another writer on that connection.
pub(crate) fn insert_chained_decision(conn: &Connection, d: &Decision) -> Result<(), String> {
    let (head_seq, head_hash) = chain_head(conn)?;
    let seq = head_seq + 1;
    let evidence = serde_json::to_string(&d.evidence).unwrap_or_default();
    let (namespace, data_class) = lifecycle_scope_from_evidence(&d.evidence);
    let hash = entry_hash(seq, &head_hash, d, &evidence);
    conn.execute(
        "INSERT INTO sekai_decisions (id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash,namespace,data_class) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            d.id,
            d.timestamp,
            d.actor,
            d.action,
            d.reason,
            evidence,
            d.target_id,
            d.outcome,
            seq,
            head_hash,
            hash,
            namespace,
            data_class
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
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
