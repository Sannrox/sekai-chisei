//! The capture child's output: one JSON [`Line`] per line on stdout, in
//! stream order. The runtime reads them, applies a transaction's changes
//! only once its `commit` line arrives, and stops at the first `refused`
//! line or at a line over [`MAX_LINE_BYTES`].
//!
//! ```text
//! {"kind":"change","commit_lsn":40,"index":0,"relation":"public.items","op":"insert","key":{"id":"1"},"row":{"id":"1","name":"a"},"unchanged":[]}
//! {"kind":"truncate","commit_lsn":40,"index":1,"relations":["public.items"]}
//! {"kind":"commit","commit_lsn":40,"end_lsn":48}
//! {"kind":"caught_up","wal_end":56}
//! {"kind":"retained_log","bytes":8192,"wal_status":"reserved"}
//! {"kind":"snapshot_at","lsn":32}
//! {"kind":"row","key":{"id":"1"},"row":{"id":"1","name":"a"}}
//! {"kind":"snapshot_end","complete":false}
//! {"kind":"refused","reason":"unknown_relation"}
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::replication::{Change, DecodeError, RowOp, Value};

/// The longest line the child writes or the runtime reads, newline
/// included. JSON escaping can grow one decoded message several times.
pub const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

/// One output line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Line {
    /// A row change; see [`Change::Row`]. `row` and `key` map column to
    /// text, `null` for a null; `unchanged` names the columns the change
    /// did not touch, which `row` omits.
    Change {
        commit_lsn: u64,
        index: u32,
        relation: String,
        op: RowOp,
        key: BTreeMap<String, Option<String>>,
        row: BTreeMap<String, Option<String>>,
        unchanged: Vec<String>,
    },
    Truncate {
        commit_lsn: u64,
        index: u32,
        relations: Vec<String>,
    },
    Commit {
        commit_lsn: u64,
        end_lsn: u64,
    },
    /// `changes` or `snapshot` created the Source's missing, recorded
    /// slot; its stream starts at `consistent_lsn`.
    SlotCreated {
        consistent_lsn: u64,
    },
    /// `snapshot`: a new snapshot found no slot and the plane does not
    /// record it, so the child created none. The runtime records the slot
    /// and runs the page again.
    SlotMissing,
    /// The server keeps `bytes` of log for the slot, from its restart
    /// position to the current position; `wal_status` as the server names
    /// it: reserved, extended, unreserved or lost.
    RetainedLog {
        bytes: i64,
        wal_status: String,
    },
    /// `changes` ends its page: the stream was idle outside a transaction
    /// with the server at `wal_end`.
    CaughtUp {
        wal_end: u64,
    },
    /// `snapshot` reads the table after the slot's position `lsn`: the feed
    /// replays every change committed after it.
    SnapshotAt {
        lsn: u64,
    },
    /// `snapshot`: one row of the table, in key order; `key` maps the
    /// replica-identity columns to their values, `row` every published
    /// column, `null` for a null.
    Row {
        key: BTreeMap<String, Option<String>>,
        row: BTreeMap<String, Option<String>>,
    },
    /// `snapshot`: no row after the page's starting key, and the row at
    /// that key is gone too.
    Gone {
        key: BTreeMap<String, Option<String>>,
    },
    /// `snapshot` ends its page; `complete` when no row follows it.
    SnapshotEnd {
        complete: bool,
    },
    /// `check` found the database ready to capture.
    Checked,
    /// The child stopped: the database or the stream refused, by name.
    Refused {
        reason: String,
    },
}

impl From<Change> for Line {
    fn from(change: Change) -> Self {
        match change {
            Change::Row {
                commit_lsn,
                index,
                relation,
                op,
                key,
                row,
            } => {
                let mut values = BTreeMap::new();
                let mut unchanged = Vec::new();
                for (column, value) in row {
                    match value {
                        Value::Null => {
                            values.insert(column, None);
                        }
                        Value::Text(text) => {
                            values.insert(column, Some(text));
                        }
                        Value::Unchanged => unchanged.push(column),
                    }
                }
                let key = key
                    .into_iter()
                    .filter_map(|(column, value)| match value {
                        Value::Null => Some((column, None)),
                        Value::Text(text) => Some((column, Some(text))),
                        Value::Unchanged => None,
                    })
                    .collect();
                Self::Change {
                    commit_lsn,
                    index,
                    relation,
                    op,
                    key,
                    row: values,
                    unchanged,
                }
            }
            Change::Truncate {
                commit_lsn,
                index,
                relations,
            } => Self::Truncate {
                commit_lsn,
                index,
                relations,
            },
            Change::Commit {
                commit_lsn,
                end_lsn,
            } => Self::Commit {
                commit_lsn,
                end_lsn,
            },
        }
    }
}

impl From<DecodeError> for Line {
    fn from(error: DecodeError) -> Self {
        Self::Refused {
            reason: error.reason().to_owned(),
        }
    }
}

impl Line {
    /// The line as written, newline included; refused when over
    /// [`MAX_LINE_BYTES`].
    pub fn encode(&self) -> Result<String, DecodeError> {
        let mut text = serde_json::to_string(self).map_err(|_| DecodeError::Malformed)?;
        text.push('\n');
        if text.len() > MAX_LINE_BYTES {
            return Err(DecodeError::Oversize);
        }
        Ok(text)
    }

    /// Reads one line, with or without its newline.
    pub fn parse(text: &str) -> Result<Self, DecodeError> {
        if text.len() > MAX_LINE_BYTES {
            return Err(DecodeError::Oversize);
        }
        serde_json::from_str(text.strip_suffix('\n').unwrap_or(text))
            .map_err(|_| DecodeError::Malformed)
    }
}
