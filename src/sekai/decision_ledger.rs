//! Decision ledger: the policy decision record, its query filter, and the
//! hash-chained append (ADR 0082, ADR 0096 rule 5).
//!
//! Value types live in `sekai-types`. This module keeps the rusqlite host.

pub use sekai_types::decision_ledger::{
    Decision, DecisionFilter, entry_hash, lifecycle_scope_from_evidence,
};

use rusqlite::{Connection, OptionalExtension, params};

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
