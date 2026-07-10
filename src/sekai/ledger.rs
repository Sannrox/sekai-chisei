//! Tamper-evident hash chain over the audit decision log.
//!
//! Every row in `sekai_decisions` carries a monotonically increasing `seq`,
//! the hash of the previous entry (`prev_hash`), and its own `entry_hash`
//! computed over a canonical serialization of the record.
//!
//! Threat model: the chain is unkeyed and the anchor table lives in the same
//! database, so it detects accidental corruption and tampering that does not
//! rewrite the chain metadata (in-place edits, deletions, reordering,
//! insertions). An attacker with unrestricted write access to the database
//! can recompute the chain from genesis, or truncate a prefix and forge the
//! purge anchor (which leaves `head_hash` unchanged). Detecting those
//! requires recording what [`SekaiDb::verify_ledger`] (or the
//! `VerifyAuditLedger` RPC) reports — `head_seq`/`head_hash` *and*
//! `anchor_seq` — in an external trust root, comparing across runs, and
//! alerting when the anchor advances outside an expected retention purge.
//!
//! Retention purges remain possible without weakening the chain: purging
//! removes only a contiguous prefix and records the last purged entry's
//! `(seq, entry_hash)` as an anchor in `sekai_ledger_anchors`, from which
//! later verification resumes.

use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

/// Verification report for the decision ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerVerification {
    pub ok: bool,
    pub entries_checked: i64,
    /// First sequence number that failed verification (0 when ok).
    pub first_bad_seq: i64,
    pub error: String,
    /// Sequence the check started after (0 = genesis, otherwise a purge anchor).
    pub anchor_seq: i64,
    pub head_seq: i64,
    pub head_hash: String,
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
/// hold the connection for the whole call (the shared `Mutex<Connection>` in
/// `SekaiDb` guarantees head read and insert are not interleaved).
pub(crate) fn insert_chained_decision(conn: &Connection, d: &Decision) -> Result<(), String> {
    let (head_seq, head_hash) = chain_head(conn)?;
    let seq = head_seq + 1;
    let evidence = serde_json::to_string(&d.evidence).unwrap_or_default();
    let hash = entry_hash(seq, &head_hash, d, &evidence);
    conn.execute(
        "INSERT INTO sekai_decisions (id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
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
            hash
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn row_to_decision(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(Decision, String, i64, String, String)> {
    let evidence_str: String = row.get(5)?;
    let decision = Decision {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        actor: row.get(2)?,
        action: row.get(3)?,
        reason: row.get(4)?,
        evidence: serde_json::from_str(&evidence_str).unwrap_or_default(),
        target_id: row.get(6)?,
        outcome: row.get(7)?,
    };
    Ok((
        decision,
        evidence_str,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

impl SekaiDb {
    /// Extend the audit tables with chain columns and chain any rows written
    /// before the ledger existed. Idempotent; runs on every startup.
    pub(crate) fn migrate_ledger(&self) -> Result<(), String> {
        let mut conn = self.conn();
        for column in ["seq INTEGER", "prev_hash TEXT", "entry_hash TEXT"] {
            let result = conn.execute(
                &format!("ALTER TABLE sekai_decisions ADD COLUMN {column}"),
                [],
            );
            if let Err(err) = result {
                let msg = err.to_string();
                if !msg.contains("duplicate column name") {
                    return Err(msg);
                }
            }
        }
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_seq ON sekai_decisions(seq);
             CREATE TABLE IF NOT EXISTS sekai_ledger_anchors (
                seq INTEGER PRIMARY KEY,
                entry_hash TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                created INTEGER NOT NULL
             );",
        )
        .map_err(|e| e.to_string())?;

        // Backfill: chain legacy rows (oldest first) after the current head.
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let legacy = {
            let mut stmt = tx
                .prepare(
                    "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome FROM sekai_decisions \
                     WHERE seq IS NULL ORDER BY timestamp ASC, rowid ASC",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    let evidence_str: String = row.get(5)?;
                    Ok((
                        Decision {
                            id: row.get(0)?,
                            timestamp: row.get(1)?,
                            actor: row.get(2)?,
                            action: row.get(3)?,
                            reason: row.get(4)?,
                            evidence: serde_json::from_str(&evidence_str).unwrap_or_default(),
                            target_id: row.get(6)?,
                            outcome: row.get(7)?,
                        },
                        evidence_str,
                    ))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        };
        if !legacy.is_empty() {
            let (mut seq, mut prev_hash) = chain_head(&tx)?;
            for (decision, evidence_json) in &legacy {
                seq += 1;
                let hash = entry_hash(seq, &prev_hash, decision, evidence_json);
                tx.execute(
                    "UPDATE sekai_decisions SET seq=?1, prev_hash=?2, entry_hash=?3 WHERE id=?4",
                    params![seq, prev_hash, hash, decision.id],
                )
                .map_err(|e| e.to_string())?;
                prev_hash = hash;
            }
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// Walk the chain from the latest purge anchor (or genesis) and verify
    /// sequence contiguity, previous-hash linkage, and every entry hash.
    ///
    /// Rows are read in batches and the shared connection lock is released
    /// between batches, so a long verification does not stall audit writes.
    /// Entries appended mid-scan simply extend the walk.
    pub fn verify_ledger(&self) -> Result<LedgerVerification, String> {
        let (anchor_seq, anchor_hash) = {
            let conn = self.conn();
            let anchor = conn
                .query_row(
                    "SELECT seq, entry_hash FROM sekai_ledger_anchors ORDER BY seq DESC LIMIT 1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or((0, String::new()));
            // Seqs at or below the anchor were purged (or, at genesis, never
            // valid); a row there is a forged "historical" entry that the
            // chain walk below would never visit.
            let forged: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sekai_decisions WHERE seq <= ?1",
                    params![anchor.0],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if forged > 0 {
                return Ok(LedgerVerification {
                    ok: false,
                    entries_checked: 0,
                    first_bad_seq: anchor.0,
                    error: format!(
                        "{forged} entr(ies) at or below purge anchor seq {}: forged historical records",
                        anchor.0
                    ),
                    anchor_seq: anchor.0,
                    head_seq: anchor.0,
                    head_hash: anchor.1,
                });
            }
            anchor
        };
        self.verify_ledger_from(anchor_seq, anchor_hash)
    }

    /// Chain walk starting after `(anchor_seq, anchor_hash)`. Split out so the
    /// mid-scan purge resume path can be exercised with a stale anchor.
    fn verify_ledger_from(
        &self,
        anchor_seq: i64,
        anchor_hash: String,
    ) -> Result<LedgerVerification, String> {
        const BATCH: usize = 1000;
        let mut expected_seq = anchor_seq;
        let mut expected_prev = anchor_hash;
        let mut entries_checked = 0i64;
        let report = |ok: bool,
                      first_bad_seq: i64,
                      error: String,
                      checked: i64,
                      head_seq: i64,
                      head_hash: String| {
            LedgerVerification {
                ok,
                entries_checked: checked,
                first_bad_seq,
                error,
                anchor_seq,
                head_seq,
                head_hash,
            }
        };
        loop {
            // NULL seqs sort first in ASC order, so unchained rows surface in
            // the first batch and fail parsing below.
            let batch: Vec<rusqlite::Result<(Decision, String, i64, String, String)>> = {
                let conn = self.conn();
                let mut stmt = conn
                    .prepare(
                        "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash \
                         FROM sekai_decisions WHERE seq > ?1 OR seq IS NULL ORDER BY seq ASC LIMIT ?2",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![expected_seq, BATCH as i64], |row| {
                        row_to_decision(row)
                    })
                    .map_err(|e| e.to_string())?;
                rows.collect()
            };
            if batch.is_empty() {
                break;
            }
            for parsed in batch {
                let (decision, evidence_json, seq, prev_hash, stored_hash) = match parsed {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        return Ok(report(
                            false,
                            expected_seq + 1,
                            format!("unchained or malformed entry: {err}"),
                            entries_checked,
                            expected_seq,
                            expected_prev,
                        ));
                    }
                };
                if seq != expected_seq + 1 {
                    // A retention purge between batches removes a verified
                    // prefix and records an anchor; a gap that lands exactly
                    // on such an anchor is benign — resume from it.
                    let purge_anchor: Option<String> = {
                        let conn = self.conn();
                        conn.query_row(
                            "SELECT entry_hash FROM sekai_ledger_anchors WHERE seq = ?1",
                            params![seq - 1],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|e| e.to_string())?
                    };
                    match purge_anchor {
                        Some(anchor_hash) if anchor_hash == prev_hash => {
                            expected_seq = seq - 1;
                            expected_prev = anchor_hash;
                        }
                        _ => {
                            return Ok(report(
                                false,
                                seq,
                                format!("sequence gap: expected {}, found {seq}", expected_seq + 1),
                                entries_checked,
                                expected_seq,
                                expected_prev,
                            ));
                        }
                    }
                }
                if prev_hash != expected_prev {
                    return Ok(report(
                        false,
                        seq,
                        "previous-hash link mismatch".into(),
                        entries_checked,
                        expected_seq,
                        expected_prev,
                    ));
                }
                let recomputed = entry_hash(seq, &prev_hash, &decision, &evidence_json);
                if recomputed != stored_hash {
                    return Ok(report(
                        false,
                        seq,
                        "entry hash mismatch: record was altered".into(),
                        entries_checked,
                        expected_seq,
                        expected_prev,
                    ));
                }
                expected_seq = seq;
                expected_prev = stored_hash;
                entries_checked += 1;
            }
        }
        Ok(report(
            true,
            0,
            String::new(),
            entries_checked,
            expected_seq,
            expected_prev,
        ))
    }

    /// Purge chained decisions older than `before` without breaking the
    /// chain: only the longest contiguous prefix whose entries are all older
    /// than the cutoff is removed, and its head is recorded as an anchor.
    /// Returns the number of purged rows.
    pub(crate) fn purge_decisions_with_anchor(&self, before: i64) -> Result<i32, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        // Largest seq such that every entry at or below it is older than the
        // cutoff; entries older than the cutoff but above a newer entry stay.
        let prefix_end: Option<i64> = tx
            .query_row(
                "SELECT COALESCE((SELECT MIN(seq) - 1 FROM sekai_decisions WHERE timestamp >= ?1),
                                 (SELECT MAX(seq) FROM sekai_decisions))",
                params![before],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .flatten();
        let Some(prefix_end) = prefix_end else {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(0);
        };
        let anchor_hash: Option<String> = tx
            .query_row(
                "SELECT entry_hash FROM sekai_decisions WHERE seq = ?1",
                params![prefix_end],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some(anchor_hash) = anchor_hash else {
            // Prefix is empty (oldest surviving entry is the chain start).
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(0);
        };
        let purged = tx
            .execute(
                "DELETE FROM sekai_decisions WHERE seq <= ?1",
                params![prefix_end],
            )
            .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR REPLACE INTO sekai_ledger_anchors (seq, entry_hash, reason, created) VALUES (?1,?2,?3,?4)",
            params![
                prefix_end,
                anchor_hash,
                format!("retention purge before {before}"),
                chrono::Utc::now().timestamp_millis()
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(purged as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn decision(id: &str, timestamp: i64) -> Decision {
        Decision {
            id: id.into(),
            timestamp,
            actor: "tester".into(),
            action: "test_action".into(),
            reason: "because".into(),
            evidence: HashMap::from([("k".into(), "v".into())]),
            target_id: "t1".into(),
            outcome: "ok".into(),
        }
    }

    #[test]
    fn chained_inserts_verify() {
        let db = SekaiDb::new(":memory:").unwrap();
        for i in 0..5 {
            db.record_decision(&decision(&format!("d{i}"), 100 + i))
                .unwrap();
        }
        let report = db.verify_ledger().unwrap();
        assert!(report.ok, "{}", report.error);
        assert_eq!(report.entries_checked, 5);
        assert_eq!(report.head_seq, 5);
        assert!(!report.head_hash.is_empty());
    }

    #[test]
    fn tampering_with_a_row_is_detected() {
        let db = SekaiDb::new(":memory:").unwrap();
        for i in 0..3 {
            db.record_decision(&decision(&format!("d{i}"), 100 + i))
                .unwrap();
        }
        {
            let conn = db.conn();
            conn.execute(
                "UPDATE sekai_decisions SET outcome = 'forged' WHERE id = 'd1'",
                [],
            )
            .unwrap();
        }
        let report = db.verify_ledger().unwrap();
        assert!(!report.ok);
        assert_eq!(report.first_bad_seq, 2);
        assert!(report.error.contains("altered"));
    }

    #[test]
    fn deleting_a_row_is_detected() {
        let db = SekaiDb::new(":memory:").unwrap();
        for i in 0..3 {
            db.record_decision(&decision(&format!("d{i}"), 100 + i))
                .unwrap();
        }
        {
            let conn = db.conn();
            conn.execute("DELETE FROM sekai_decisions WHERE id = 'd1'", [])
                .unwrap();
        }
        let report = db.verify_ledger().unwrap();
        assert!(!report.ok);
        assert!(report.error.contains("sequence gap"));
    }

    #[test]
    fn purge_records_anchor_and_chain_still_verifies() {
        let db = SekaiDb::new(":memory:").unwrap();
        for i in 0..5 {
            db.record_decision(&decision(&format!("d{i}"), 100 + i))
                .unwrap();
        }
        let purged = db.purge_decisions_with_anchor(103).unwrap();
        assert_eq!(purged, 3);
        let report = db.verify_ledger().unwrap();
        assert!(report.ok, "{}", report.error);
        assert_eq!(report.anchor_seq, 3);
        assert_eq!(report.entries_checked, 2);

        // New entries continue the chain after the anchor.
        db.record_decision(&decision("d5", 200)).unwrap();
        let report = db.verify_ledger().unwrap();
        assert!(report.ok, "{}", report.error);
        assert_eq!(report.head_seq, 6);
    }

    #[test]
    fn forged_rows_below_purge_anchor_are_detected() {
        let db = SekaiDb::new(":memory:").unwrap();
        for i in 0..4 {
            db.record_decision(&decision(&format!("d{i}"), 100 + i))
                .unwrap();
        }
        db.purge_decisions_with_anchor(103).unwrap();
        assert!(db.verify_ledger().unwrap().ok);
        {
            let conn = db.conn();
            conn.execute(
                "INSERT INTO sekai_decisions (id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash) \
                 VALUES ('forged',50,'evil','act','','{}','','done',1,'x','y')",
                [],
            )
            .unwrap();
        }
        let report = db.verify_ledger().unwrap();
        assert!(!report.ok);
        assert!(report.error.contains("forged"));
    }

    #[test]
    fn purge_skips_interleaved_newer_entries() {
        let db = SekaiDb::new(":memory:").unwrap();
        // Old timestamp but written after a new one: gateway clients supply
        // their own timestamps, so out-of-order arrival is possible.
        db.record_decision(&decision("new", 500)).unwrap();
        db.record_decision(&decision("old", 100)).unwrap();
        let purged = db.purge_decisions_with_anchor(300).unwrap();
        assert_eq!(purged, 0);
        assert!(db.verify_ledger().unwrap().ok);
    }

    #[test]
    fn purge_all_entries_leaves_verifiable_empty_ledger() {
        let db = SekaiDb::new(":memory:").unwrap();
        for i in 0..3 {
            db.record_decision(&decision(&format!("d{i}"), 100 + i))
                .unwrap();
        }
        let purged = db.purge_decisions_with_anchor(1_000).unwrap();
        assert_eq!(purged, 3);
        let report = db.verify_ledger().unwrap();
        assert!(report.ok);
        assert_eq!(report.entries_checked, 0);
        assert_eq!(report.anchor_seq, 3);
    }

    #[test]
    fn legacy_rows_are_backfilled_into_the_chain() {
        let db = SekaiDb::new(":memory:").unwrap();
        {
            let conn = db.conn();
            for i in 0..3 {
                conn.execute(
                    "INSERT INTO sekai_decisions (id,timestamp,actor,action,reason,evidence,target_id,outcome) \
                     VALUES (?1,?2,'legacy','act','','{}','','done')",
                    params![format!("l{i}"), 100 + i],
                )
                .unwrap();
            }
        }
        db.migrate_ledger().unwrap();
        let report = db.verify_ledger().unwrap();
        assert!(report.ok, "{}", report.error);
        assert_eq!(report.entries_checked, 3);
    }

    #[test]
    fn entry_hash_covers_raw_evidence_bytes() {
        let d = decision("d1", 100);
        assert_ne!(
            entry_hash(1, "", &d, "{\"a\":\"1\"}"),
            entry_hash(1, "", &d, "{\"a\": \"1\"}")
        );
        assert_eq!(
            entry_hash(1, "", &d, "{\"a\":\"1\"}"),
            entry_hash(1, "", &d, "{\"a\":\"1\"}")
        );
    }

    #[test]
    fn rewriting_stored_evidence_bytes_is_detected() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.record_decision(&decision("d0", 100)).unwrap();
        {
            let conn = db.conn();
            conn.execute(
                "UPDATE sekai_decisions SET evidence = 'not json' WHERE id = 'd0'",
                [],
            )
            .unwrap();
        }
        let report = db.verify_ledger().unwrap();
        assert!(!report.ok);
        assert!(report.error.contains("altered"));
    }

    #[test]
    fn purge_between_verify_batches_resumes_from_new_anchor() {
        let db = SekaiDb::new(":memory:").unwrap();
        for i in 0..5 {
            db.record_decision(&decision(&format!("d{i}"), 100 + i))
                .unwrap();
        }
        // Simulate a purge that lands after the verifier read the anchor:
        // walk from the (now stale) genesis anchor while rows 1..=3 are gone.
        db.purge_decisions_with_anchor(103).unwrap();
        let report = db.verify_ledger_from(0, String::new()).unwrap();
        assert!(report.ok, "{}", report.error);
        assert_eq!(report.entries_checked, 2);
        assert_eq!(report.head_seq, 5);
    }
}
