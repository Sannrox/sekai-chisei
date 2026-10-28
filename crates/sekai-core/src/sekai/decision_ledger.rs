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
pub fn chain_head(conn: &Connection) -> Result<(i64, String), String> {
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

/// Insert a decision as the next entry of the hash chain.
///
/// The head read and the insert run under the database write lock (#1722),
/// so concurrent writers on other connections each take the next `seq` and
/// the chain stays intact. Outside a transaction the call opens an
/// immediate one; inside one it takes the write lock before reading the
/// head, so a caller's deferred transaction that read stale state fails
/// rather than inserting a duplicate `seq`.
pub fn insert_chained_decision(conn: &Connection, d: &Decision) -> Result<(), String> {
    if !conn.is_autocommit() {
        take_write_lock(conn)?;
        return insert_at_head(conn, d);
    }
    // Dropping the transaction on any failure, a failed commit included,
    // rolls it back, so the pooled connection never keeps an open write.
    let transaction =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
    insert_at_head(&transaction, d)?;
    transaction.commit().map_err(|e| e.to_string())
}

/// A write statement opens the transaction's write lock even when it
/// changes no row; an immediate transaction already holds it.
fn take_write_lock(conn: &Connection) -> Result<(), String> {
    conn.execute("UPDATE sekai_decisions SET seq = seq WHERE rowid = -1", [])
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn insert_at_head(conn: &Connection, d: &Decision) -> Result<(), String> {
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
