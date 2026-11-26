//! Decodes a logical replication stream into ordered [`Change`]s, as pure
//! functions over bytes the connection layer reads (ADR 0170).
//!
//! Two layers, outermost first:
//!
//! - [`Frame::parse`] reads one copy-data message of the replication
//!   stream: a write-ahead log payload, or a keepalive asking for a status
//!   reply;
//! - [`Decoder::decode`] reads one payload of the built-in logical output
//!   plugin (text protocol version 1, no streaming of in-progress
//!   transactions) and returns the change it carries, if any.
//!
//! Ordering: every change carries the log position of its transaction's
//! commit and its index inside that transaction. `(commit_lsn, index)`
//! strictly increases across the stream; a transaction whose commit is not
//! past the last one decoded is refused, never reordered. A change is only
//! final once its [`Change::Commit`] arrives; a reader that stops inside a
//! transaction resumes at that transaction's start.
//!
//! Every input is untrusted: a message over [`MAX_MESSAGE_BYTES`], a
//! truncated or trailing field, an unknown tag, a row for a relation the
//! stream never described, or text that is not UTF-8 is a [`DecodeError`],
//! and the decoder state after an error is not used again.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

/// The largest replication message the decoder reads. A larger one is
/// refused before parsing.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// The most columns one relation may declare.
pub const MAX_COLUMNS: usize = 1600;

/// The most relations one truncate may name.
pub const MAX_TRUNCATE_RELATIONS: usize = 1024;

/// Why a message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Over [`MAX_MESSAGE_BYTES`], [`MAX_COLUMNS`] or
    /// [`MAX_TRUNCATE_RELATIONS`].
    Oversize,
    /// Truncated, trailing bytes, an unknown tag, or a field out of range.
    Malformed,
    /// Text that is not UTF-8.
    NotUtf8,
    /// A row or truncate for a relation the stream has not described.
    UnknownRelation,
    /// A change outside a transaction, a transaction inside another, or a
    /// commit that does not match its begin.
    OutOfTransaction,
    /// A transaction whose commit is not past the last one decoded.
    OutOfOrder,
    /// A message kind this decoder never asks for, such as binary values
    /// or streamed in-progress transactions.
    Unsupported,
}

impl DecodeError {
    /// The reason the child reports.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Oversize => "oversize",
            Self::Malformed => "malformed",
            Self::NotUtf8 => "not_utf8",
            Self::UnknownRelation => "unknown_relation",
            Self::OutOfTransaction => "out_of_transaction",
            Self::OutOfOrder => "out_of_order",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One copy-data message of the replication stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame<'a> {
    /// A write-ahead log payload for [`Decoder::decode`].
    Log {
        wal_start: u64,
        wal_end: u64,
        data: &'a [u8],
    },
    /// The server's position, and whether it wants a status reply now.
    Keepalive { wal_end: u64, reply_requested: bool },
}

impl<'a> Frame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(DecodeError::Oversize);
        }
        let mut reader = Reader(bytes);
        match reader.u8()? {
            b'w' => {
                let wal_start = reader.u64()?;
                let wal_end = reader.u64()?;
                let _server_clock = reader.u64()?;
                Ok(Self::Log {
                    wal_start,
                    wal_end,
                    data: reader.0,
                })
            }
            b'k' => {
                let wal_end = reader.u64()?;
                let _server_clock = reader.u64()?;
                let reply_requested = match reader.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(DecodeError::Malformed),
                };
                reader.end()?;
                Ok(Self::Keepalive {
                    wal_end,
                    reply_requested,
                })
            }
            _ => Err(DecodeError::Malformed),
        }
    }
}

/// One column value of a row. Text values only: the decoder never asks for
/// binary ones.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Value {
    Null,
    Text(String),
    /// A large value the change did not touch; the stream omits it.
    Unchanged,
}

/// A column name and its value, in the relation's column order.
pub type Row = Vec<(String, Value)>;

/// One decoded change, in stream order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// A row change inside the transaction committing at `commit_lsn`.
    Row {
        commit_lsn: u64,
        index: u32,
        relation: String,
        op: RowOp,
        /// The key columns of the row this change replaces or adds: the
        /// old key when the stream sends one (a delete, or an update that
        /// changed the key), otherwise taken from the new row.
        key: BTreeMap<String, Value>,
        /// The full new row; empty for a delete.
        row: Row,
    },
    /// Every row of these relations was removed.
    Truncate {
        commit_lsn: u64,
        index: u32,
        relations: Vec<String>,
    },
    /// The transaction committing at `commit_lsn` is complete; `end_lsn`
    /// is the position to confirm once its changes are applied.
    Commit { commit_lsn: u64, end_lsn: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RowOp {
    Insert,
    Update,
    Delete,
}

struct Relation {
    name: String,
    /// Column name and whether it is part of the replica identity key.
    columns: Vec<(String, bool)>,
}

/// Decoder state across one stream: the relations described so far, the
/// open transaction, and the last commit decoded.
#[derive(Default)]
pub struct Decoder {
    relations: HashMap<u32, Relation>,
    open: Option<Open>,
    last_commit_lsn: Option<u64>,
}

struct Open {
    commit_lsn: u64,
    next_index: u32,
}

impl Decoder {
    /// A decoder for a stream that resumes after `confirmed_lsn`, the end
    /// of the last transaction already read: a transaction committing
    /// before it is refused as out of order. One committing exactly there
    /// is new, since the next commit record can start where the last one
    /// ended.
    pub fn resuming_after(confirmed_lsn: u64) -> Self {
        Self {
            // `begin` refuses a commit at or before the last one decoded.
            last_commit_lsn: confirmed_lsn.checked_sub(1),
            ..Self::default()
        }
    }

    /// Decodes one output plugin message. Relation, type, origin and
    /// logical messages update state or are skipped, returning `None`.
    pub fn decode(&mut self, bytes: &[u8]) -> Result<Option<Change>, DecodeError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(DecodeError::Oversize);
        }
        let mut reader = Reader(bytes);
        let change = match reader.u8()? {
            b'B' => {
                let commit_lsn = reader.u64()?;
                let _timestamp = reader.u64()?;
                let _xid = reader.u32()?;
                self.begin(commit_lsn)?;
                None
            }
            b'C' => {
                let _flags = reader.u8()?;
                let commit_lsn = reader.u64()?;
                let end_lsn = reader.u64()?;
                let _timestamp = reader.u64()?;
                let open = self.open.take().ok_or(DecodeError::OutOfTransaction)?;
                if open.commit_lsn != commit_lsn || end_lsn < commit_lsn {
                    return Err(DecodeError::OutOfTransaction);
                }
                self.last_commit_lsn = Some(commit_lsn);
                Some(Change::Commit {
                    commit_lsn,
                    end_lsn,
                })
            }
            b'R' => {
                self.relation(&mut reader)?;
                None
            }
            tag @ (b'I' | b'U' | b'D') => Some(self.row(tag, &mut reader)?),
            b'T' => {
                let count = reader.u32()? as usize;
                if count > MAX_TRUNCATE_RELATIONS {
                    return Err(DecodeError::Oversize);
                }
                let _options = reader.u8()?;
                let mut relations = Vec::with_capacity(count);
                for _ in 0..count {
                    relations.push(self.known(reader.u32()?)?.name.clone());
                }
                let (commit_lsn, index) = self.next()?;
                Some(Change::Truncate {
                    commit_lsn,
                    index,
                    relations,
                })
            }
            b'Y' => {
                let _oid = reader.u32()?;
                reader.cstr()?;
                reader.cstr()?;
                None
            }
            b'O' => {
                let _lsn = reader.u64()?;
                reader.cstr()?;
                None
            }
            b'M' => {
                let _flags = reader.u8()?;
                let _lsn = reader.u64()?;
                reader.cstr()?;
                let len = reader.u32()? as usize;
                reader.take(len)?;
                None
            }
            b'S' | b'E' | b'c' | b'A' => return Err(DecodeError::Unsupported),
            _ => return Err(DecodeError::Malformed),
        };
        reader.end()?;
        Ok(change)
    }

    fn begin(&mut self, commit_lsn: u64) -> Result<(), DecodeError> {
        if self.open.is_some() {
            return Err(DecodeError::OutOfTransaction);
        }
        if self.last_commit_lsn.is_some_and(|last| commit_lsn <= last) {
            return Err(DecodeError::OutOfOrder);
        }
        self.open = Some(Open {
            commit_lsn,
            next_index: 0,
        });
        Ok(())
    }

    fn relation(&mut self, reader: &mut Reader<'_>) -> Result<(), DecodeError> {
        let oid = reader.u32()?;
        let namespace = reader.cstr()?;
        let name = reader.cstr()?;
        let _replica_identity = reader.u8()?;
        let count = usize::try_from(reader.i16()?).map_err(|_| DecodeError::Malformed)?;
        if count > MAX_COLUMNS {
            return Err(DecodeError::Oversize);
        }
        let mut columns = Vec::with_capacity(count);
        for _ in 0..count {
            let flags = reader.u8()?;
            let column = reader.cstr()?;
            let _type_oid = reader.u32()?;
            let _type_modifier = reader.u32()?;
            columns.push((column, flags & 1 == 1));
        }
        self.relations.insert(
            oid,
            Relation {
                name: format!("{namespace}.{name}"),
                columns,
            },
        );
        Ok(())
    }

    fn known(&self, oid: u32) -> Result<&Relation, DecodeError> {
        self.relations.get(&oid).ok_or(DecodeError::UnknownRelation)
    }

    fn next(&mut self) -> Result<(u64, u32), DecodeError> {
        let open = self.open.as_mut().ok_or(DecodeError::OutOfTransaction)?;
        let index = open.next_index;
        open.next_index = index.checked_add(1).ok_or(DecodeError::Oversize)?;
        Ok((open.commit_lsn, index))
    }

    /// Reads an insert, update or delete after its tag.
    fn row(&mut self, tag: u8, reader: &mut Reader<'_>) -> Result<Change, DecodeError> {
        let relation = self.known(reader.u32()?)?;
        let (op, key, row) = match tag {
            b'I' => {
                reader.tag(b'N')?;
                let row = tuple(reader, relation)?;
                (RowOp::Insert, key_of(relation, &row), row)
            }
            b'U' => {
                let mut next = reader.u8()?;
                let mut old_key = None;
                if matches!(next, b'K' | b'O') {
                    old_key = Some(key_of(relation, &tuple(reader, relation)?));
                    next = reader.u8()?;
                }
                if next != b'N' {
                    return Err(DecodeError::Malformed);
                }
                let row = tuple(reader, relation)?;
                let key = old_key.unwrap_or_else(|| key_of(relation, &row));
                (RowOp::Update, key, row)
            }
            _ => {
                if !matches!(reader.u8()?, b'K' | b'O') {
                    return Err(DecodeError::Malformed);
                }
                let old = tuple(reader, relation)?;
                (RowOp::Delete, key_of(relation, &old), Vec::new())
            }
        };
        let relation = relation.name.clone();
        let (commit_lsn, index) = self.next()?;
        Ok(Change::Row {
            commit_lsn,
            index,
            relation,
            op,
            key,
            row,
        })
    }
}

/// Reads one tuple; its column count must match the relation's.
fn tuple(reader: &mut Reader<'_>, relation: &Relation) -> Result<Row, DecodeError> {
    let count = usize::try_from(reader.i16()?).map_err(|_| DecodeError::Malformed)?;
    if count != relation.columns.len() {
        return Err(DecodeError::Malformed);
    }
    let mut row = Vec::with_capacity(count);
    for (name, _) in &relation.columns {
        let value = match reader.u8()? {
            b'n' => Value::Null,
            b'u' => Value::Unchanged,
            b't' => {
                let len = usize::try_from(reader.i32()?).map_err(|_| DecodeError::Malformed)?;
                let text =
                    std::str::from_utf8(reader.take(len)?).map_err(|_| DecodeError::NotUtf8)?;
                Value::Text(text.to_owned())
            }
            b'b' => return Err(DecodeError::Unsupported),
            _ => return Err(DecodeError::Malformed),
        };
        row.push((name.clone(), value));
    }
    Ok(row)
}

/// The columns of `row` the relation marks as its replica identity key.
fn key_of(relation: &Relation, row: &Row) -> BTreeMap<String, Value> {
    relation
        .columns
        .iter()
        .zip(row)
        .filter(|((_, is_key), _)| *is_key)
        .map(|(_, (name, value))| (name.clone(), value.clone()))
        .collect()
}

/// A bounds-checked big-endian reader over one message.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if len > self.0.len() {
            return Err(DecodeError::Malformed);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?.try_into().map_err(|_| DecodeError::Malformed)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    fn tag(&mut self, expected: u8) -> Result<(), DecodeError> {
        if self.u8()? == expected {
            Ok(())
        } else {
            Err(DecodeError::Malformed)
        }
    }

    fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(i16::from_be_bytes(self.array()?))
    }

    fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn cstr(&mut self) -> Result<String, DecodeError> {
        let end = self
            .0
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(DecodeError::Malformed)?;
        let text = std::str::from_utf8(&self.0[..end]).map_err(|_| DecodeError::NotUtf8)?;
        self.0 = &self.0[end + 1..];
        Ok(text.to_owned())
    }

    fn end(&self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests;
