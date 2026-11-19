//! Paged, resumable, verifiable export of one namespace's audit decisions
//! (#2638).
//!
//! The decision ledger is one hash chain across every namespace. A page
//! walks a bounded run of that chain after the caller's cursor, checks each
//! entry's sequence, previous-hash link and entry hash, and keeps the entries
//! whose hashed evidence names the namespace. The cursor carries the last
//! walked `(seq, entry_hash)`, so the next page proves it continues the chain
//! the previous page verified: no gap and no duplicate, even while new
//! decisions are written, because sequence numbers are assigned under the
//! ledger lock in commit order.
//!
//! A cursor below the latest purge anchor resumes from the anchor and the
//! page reports the archived range instead of skipping it silently.

use crate::db::sekai::SekaiDb;
use crate::sekai::decision_ledger::Decision;
use crate::sekai::ledger::{entry_hash, lifecycle_scope_from_evidence};
use rusqlite::{OptionalExtension, params};

/// Records per page when the caller asks for 0.
pub const DEFAULT_PAGE_SIZE: usize = 100;
/// Largest page a caller can ask for.
pub const MAX_PAGE_SIZE: usize = 1000;
/// Chain entries one page walks at most, across all namespaces. A sparse
/// namespace can get an empty page that is not caught up.
pub const SCAN_BUDGET: usize = 2000;

const CURSOR_PREFIX: &str = "a1.";

/// Position in the global chain: the last entry a page walked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCursor {
    pub seq: i64,
    pub entry_hash: String,
}

impl AuditCursor {
    /// Before the first entry ever written.
    pub fn genesis() -> Self {
        Self {
            seq: 0,
            entry_hash: String::new(),
        }
    }

    /// Opaque text form handed to callers.
    pub fn encode(&self) -> String {
        format!("{CURSOR_PREFIX}{}.{}", self.seq, self.entry_hash)
    }

    /// Empty text starts at the oldest retained entry.
    pub fn parse(text: &str) -> Result<Option<Self>, AuditExportError> {
        if text.is_empty() {
            return Ok(None);
        }
        let invalid = || AuditExportError::InvalidCursor;
        let (seq, hash) = text
            .strip_prefix(CURSOR_PREFIX)
            .and_then(|rest| rest.split_once('.'))
            .ok_or_else(invalid)?;
        let seq: i64 = seq.parse().map_err(|_| invalid())?;
        let well_formed = seq >= 0
            && (hash.is_empty() || hash.len() == 64)
            && hash
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
        if !well_formed {
            return Err(invalid());
        }
        Ok(Some(Self {
            seq,
            entry_hash: hash.into(),
        }))
    }
}

/// One chained decision with everything a reader needs to recompute its
/// hash: the evidence is the exact hashed JSON text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEntry {
    pub decision: Decision,
    pub evidence_json: String,
    pub seq: i64,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// What a backend read in one snapshot: the latest purge anchor and up to
/// `limit` chain entries after `max(cursor, anchor)`, in sequence order.
#[derive(Debug, Clone)]
pub struct ChainSnapshot {
    pub anchor: AuditCursor,
    pub entries: Vec<ChainEntry>,
    /// The read limit, so the walker knows whether it reached the head.
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditExportPage {
    pub records: Vec<ChainEntry>,
    /// Pass back to continue after this page.
    pub next_cursor: AuditCursor,
    /// Nonzero when entries through this seq were archived before this page
    /// could read them.
    pub archived_through_seq: i64,
    /// The chain was verified from this position (exclusive) through
    /// `next_cursor` (inclusive), including other namespaces' entries.
    pub verified_from: AuditCursor,
    /// The page reached the ledger head as of its snapshot.
    pub caught_up: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditExportError {
    InvalidCursor,
    /// The chain does not verify at `seq`; nothing past it is returned.
    Chain {
        seq: i64,
        reason: String,
    },
    Store(String),
}

impl std::fmt::Display for AuditExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCursor => f.write_str("invalid audit export cursor"),
            Self::Chain { seq, reason } => {
                write!(f, "audit chain does not verify at seq {seq}: {reason}")
            }
            Self::Store(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for AuditExportError {}

/// The `seq` a backend reads after: the cursor, or the anchor when retention
/// archived past it.
pub fn read_after(cursor: Option<&AuditCursor>, anchor_seq: i64) -> i64 {
    cursor.map_or(0, |cursor| cursor.seq).max(anchor_seq)
}

/// Verify `snapshot` from the caller's position and keep `namespace`'s
/// entries, stopping after `page_size` of them.
pub fn walk(
    cursor: Option<&AuditCursor>,
    snapshot: ChainSnapshot,
    namespace: &str,
    page_size: usize,
) -> Result<AuditExportPage, AuditExportError> {
    let page_size = match page_size {
        0 => DEFAULT_PAGE_SIZE,
        size => size.min(MAX_PAGE_SIZE),
    };
    let (start, archived_through_seq) = match cursor {
        Some(cursor) if cursor.seq >= snapshot.anchor.seq => (cursor.clone(), 0),
        // Below the anchor, or a fresh export of a ledger retention trimmed.
        _ if snapshot.anchor.seq > 0 => (snapshot.anchor.clone(), snapshot.anchor.seq),
        _ => (AuditCursor::genesis(), 0),
    };
    let read = snapshot.entries.len();
    let mut position = start.clone();
    let mut records = Vec::new();
    for entry in snapshot.entries {
        let chain_error = |reason: &str| AuditExportError::Chain {
            seq: entry.seq,
            reason: reason.into(),
        };
        if entry.seq != position.seq + 1 {
            return Err(chain_error("sequence gap"));
        }
        if entry.prev_hash != position.entry_hash {
            return Err(chain_error("previous-hash link mismatch"));
        }
        if entry_hash(
            entry.seq,
            &entry.prev_hash,
            &entry.decision,
            &entry.evidence_json,
        ) != entry.entry_hash
        {
            return Err(chain_error("entry hash mismatch"));
        }
        position = AuditCursor {
            seq: entry.seq,
            entry_hash: entry.entry_hash.clone(),
        };
        if lifecycle_scope_from_evidence(&entry.decision.evidence).0 == namespace {
            records.push(entry);
            if records.len() == page_size {
                break;
            }
        }
    }
    let caught_up = records.len() < page_size && read < snapshot.limit;
    Ok(AuditExportPage {
        records,
        next_cursor: position,
        archived_through_seq,
        verified_from: start,
        caught_up,
    })
}

impl SekaiDb {
    /// One SQLite read snapshot for [`walk`].
    pub fn audit_chain_snapshot(
        &self,
        cursor: Option<&AuditCursor>,
        limit: usize,
    ) -> Result<ChainSnapshot, String> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        let anchor = tx
            .query_row(
                "SELECT seq, entry_hash FROM sekai_ledger_anchors ORDER BY seq DESC LIMIT 1",
                [],
                |row| {
                    Ok(AuditCursor {
                        seq: row.get(0)?,
                        entry_hash: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or_else(AuditCursor::genesis);
        let entries = {
            let mut stmt = tx
                .prepare(
                    "SELECT id,timestamp,actor,action,reason,evidence,target_id,outcome,seq,prev_hash,entry_hash \
                     FROM sekai_decisions WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2",
                )
                .map_err(|e| e.to_string())?;
            stmt.query_map(
                params![read_after(cursor, anchor.seq), limit as i64],
                |row| {
                    let evidence_json: String = row.get(5)?;
                    Ok(ChainEntry {
                        decision: Decision {
                            id: row.get(0)?,
                            timestamp: row.get(1)?,
                            actor: row.get(2)?,
                            action: row.get(3)?,
                            reason: row.get(4)?,
                            evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
                            target_id: row.get(6)?,
                            outcome: row.get(7)?,
                        },
                        evidence_json,
                        seq: row.get(8)?,
                        prev_hash: row.get(9)?,
                        entry_hash: row.get(10)?,
                    })
                },
            )
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };
        tx.commit().map_err(|e| e.to_string())?;
        Ok(ChainSnapshot {
            anchor,
            entries,
            limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn chain(namespaces: &[&str]) -> Vec<ChainEntry> {
        let mut prev = String::new();
        namespaces
            .iter()
            .enumerate()
            .map(|(index, namespace)| {
                let seq = index as i64 + 1;
                let decision = Decision {
                    id: format!("d{seq}"),
                    timestamp: seq,
                    actor: "alice".into(),
                    action: "test".into(),
                    reason: String::new(),
                    evidence: HashMap::from([("namespace".into(), (*namespace).into())]),
                    target_id: String::new(),
                    outcome: "allow".into(),
                };
                let evidence_json = serde_json::to_string(&decision.evidence).unwrap();
                let hash = entry_hash(seq, &prev, &decision, &evidence_json);
                ChainEntry {
                    decision,
                    evidence_json,
                    seq,
                    prev_hash: std::mem::replace(&mut prev, hash.clone()),
                    entry_hash: hash,
                }
            })
            .collect()
    }

    fn snapshot(entries: Vec<ChainEntry>) -> ChainSnapshot {
        ChainSnapshot {
            anchor: AuditCursor::genesis(),
            entries,
            limit: SCAN_BUDGET,
        }
    }

    #[test]
    fn cursor_round_trips_and_rejects_tampering() {
        let cursor = AuditCursor {
            seq: 7,
            entry_hash: "ab".repeat(32),
        };
        assert_eq!(AuditCursor::parse(&cursor.encode()).unwrap(), Some(cursor));
        assert_eq!(AuditCursor::parse("").unwrap(), None);
        for bad in ["7", "a1.x.", "a1.-1.", "a1.3.zz", "a1.3.abc"] {
            assert_eq!(
                AuditCursor::parse(bad),
                Err(AuditExportError::InvalidCursor),
                "{bad}"
            );
        }
    }

    #[test]
    fn pages_resume_without_gap_or_duplicate() {
        let entries = chain(&["a", "b", "a", "a", "b", "a"]);
        let first = walk(None, snapshot(entries.clone()), "a", 2).unwrap();
        assert_eq!(
            first.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            [1, 3]
        );
        assert!(!first.caught_up);
        let rest: Vec<_> = entries
            .iter()
            .filter(|entry| entry.seq > first.next_cursor.seq)
            .cloned()
            .collect();
        let second = walk(Some(&first.next_cursor), snapshot(rest), "a", 10).unwrap();
        assert_eq!(
            second.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            [4, 6]
        );
        assert!(second.caught_up);
        assert_eq!(second.verified_from, first.next_cursor);
    }

    #[test]
    fn tampered_or_disconnected_entries_fail_closed() {
        let mut entries = chain(&["a", "a", "a"]);
        entries[1].decision.actor = "mallory".into();
        assert_eq!(
            walk(None, snapshot(entries), "a", 10),
            Err(AuditExportError::Chain {
                seq: 2,
                reason: "entry hash mismatch".into()
            })
        );
        // A forged cursor hash does not link to the next entry.
        let entries = chain(&["a", "a"]);
        let forged = AuditCursor {
            seq: 1,
            entry_hash: "00".repeat(32),
        };
        assert!(matches!(
            walk(Some(&forged), snapshot(entries[1..].to_vec()), "a", 10),
            Err(AuditExportError::Chain { seq: 2, .. })
        ));
    }

    #[test]
    fn a_cursor_below_the_anchor_reports_the_archived_range() {
        let entries = chain(&["a", "a", "a", "a"]);
        let anchor = AuditCursor {
            seq: 2,
            entry_hash: entries[1].entry_hash.clone(),
        };
        let stale = AuditCursor {
            seq: 1,
            entry_hash: entries[0].entry_hash.clone(),
        };
        let page = walk(
            Some(&stale),
            ChainSnapshot {
                anchor: anchor.clone(),
                entries: entries[2..].to_vec(),
                limit: SCAN_BUDGET,
            },
            "a",
            10,
        )
        .unwrap();
        assert_eq!(page.archived_through_seq, 2);
        assert_eq!(page.verified_from, anchor);
        assert_eq!(
            page.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            [3, 4]
        );
    }
}
