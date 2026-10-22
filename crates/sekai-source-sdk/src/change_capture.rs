//! Source-neutral change-capture contract for relational sources (ADR 0118).
//!
//! A change-capture connector reports what it read as [`CaptureEvent`]s:
//! a snapshot at a recorded position, then committed changes strictly after
//! it, with optional transaction markers, schema-change events, and a
//! distinct retention-loss event. [`assert_change_capture`] is the offline
//! conformance check every family must pass; [`PositionFamily`] parses and
//! orders each family's native position (LSN, GTID set, SCN).
//!
//! Positions stay adapter-private resume state inside the plane-owned opaque
//! cursor (ADR 0100). They are never the plane offset or `source_sequence`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub const CHANGE_CAPTURE_CONFORMANCE_VERSION: &str = "sekai.change-capture-conformance/v1";

/// How one source family writes and orders its log position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionFamily {
    /// PostgreSQL WAL LSN, `X/Y` in hex.
    PostgresLsn,
    /// MySQL executed GTID set, `uuid:1-5:7,uuid:1-3`.
    MysqlGtidSet,
    /// SQL Server commit LSN, `VLF:block:slot` as 8, 8 and 4 hex digits.
    SqlServerLsn,
    /// Oracle system change number, decimal.
    OracleScn,
}

/// A parsed position. Compare positions only within one family and one
/// source instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourcePosition {
    Lsn(u64),
    /// Source UUID to sorted, merged, inclusive transaction-number ranges.
    GtidSet(BTreeMap<String, Vec<(u64, u64)>>),
    SqlServerLsn(u32, u32, u16),
    Scn(u64),
}

impl PositionFamily {
    pub fn token(self) -> &'static str {
        match self {
            Self::PostgresLsn => "postgres.lsn",
            Self::MysqlGtidSet => "mysql.gtid_set",
            Self::SqlServerLsn => "sqlserver.lsn",
            Self::OracleScn => "oracle.scn",
        }
    }

    /// Whether distinct transactions may commit at the same position. Oracle
    /// can assign one commit SCN to several transactions; a checkpoint at an
    /// SCN then covers every transaction committed at it.
    pub fn commit_positions_can_tie(self) -> bool {
        matches!(self, Self::OracleScn)
    }

    /// Parse a position as the family writes it. Malformed input fails
    /// closed; a position is never guessed or defaulted.
    pub fn parse(self, raw: &str) -> Result<SourcePosition, String> {
        let invalid = || format!("{} position is malformed", self.token());
        match self {
            Self::PostgresLsn => {
                let (high, low) = raw.split_once('/').ok_or_else(invalid)?;
                let high = hex_u32(high).ok_or_else(invalid)?;
                let low = hex_u32(low).ok_or_else(invalid)?;
                Ok(SourcePosition::Lsn(
                    (u64::from(high) << 32) | u64::from(low),
                ))
            }
            Self::MysqlGtidSet => parse_gtid_set(raw).ok_or_else(invalid),
            Self::SqlServerLsn => {
                let parts: Vec<&str> = raw.split(':').collect();
                match parts.as_slice() {
                    [vlf, block, slot] if vlf.len() == 8 && block.len() == 8 && slot.len() == 4 => {
                        Ok(SourcePosition::SqlServerLsn(
                            hex_u32(vlf).ok_or_else(invalid)?,
                            hex_u32(block).ok_or_else(invalid)?,
                            u16::from_str_radix(slot, 16).map_err(|_| invalid())?,
                        ))
                    }
                    _ => Err(invalid()),
                }
            }
            Self::OracleScn => {
                if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid());
                }
                raw.parse().map(SourcePosition::Scn).map_err(|_| invalid())
            }
        }
    }
}

fn hex_u32(raw: &str) -> Option<u32> {
    if raw.is_empty() || raw.len() > 8 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(raw, 16).ok()
}

fn parse_gtid_set(raw: &str) -> Option<SourcePosition> {
    let mut set: BTreeMap<String, Vec<(u64, u64)>> = BTreeMap::new();
    if raw.trim().is_empty() {
        // The empty set: nothing executed yet.
        return Some(SourcePosition::GtidSet(set));
    }
    for member in raw.split(',') {
        let mut parts = member.trim().split(':');
        let uuid = parts.next()?.to_ascii_lowercase();
        if !is_uuid(&uuid) {
            return None;
        }
        let ranges = set.entry(uuid).or_default();
        let mut any = false;
        for interval in parts {
            any = true;
            let (start, end) = match interval.split_once('-') {
                Some((start, end)) => (start.parse().ok()?, end.parse().ok()?),
                None => {
                    let single: u64 = interval.parse().ok()?;
                    (single, single)
                }
            };
            if start == 0 || end < start {
                return None;
            }
            ranges.push((start, end));
        }
        if !any {
            return None;
        }
    }
    for ranges in set.values_mut() {
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for &(start, end) in ranges.iter() {
            match merged.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        *ranges = merged;
    }
    Some(SourcePosition::GtidSet(set))
}

/// The 8-4-4-4-12 hex shape of a source UUID.
fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn gtid_subset(
    left: &BTreeMap<String, Vec<(u64, u64)>>,
    right: &BTreeMap<String, Vec<(u64, u64)>>,
) -> bool {
    left.iter().all(|(uuid, ranges)| {
        let Some(outer) = right.get(uuid) else {
            return ranges.is_empty();
        };
        ranges.iter().all(|&(start, end)| {
            outer
                .iter()
                .any(|&(outer_start, outer_end)| outer_start <= start && end <= outer_end)
        })
    })
}

impl SourcePosition {
    /// Order two positions of one family. GTID sets order by containment;
    /// two sets neither of which contains the other are unordered (`None`),
    /// which the contract treats as a conformance failure.
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Lsn(left), Self::Lsn(right)) | (Self::Scn(left), Self::Scn(right)) => {
                Some(left.cmp(right))
            }
            (Self::SqlServerLsn(a, b, c), Self::SqlServerLsn(x, y, z)) => {
                Some((a, b, c).cmp(&(x, y, z)))
            }
            (Self::GtidSet(left), Self::GtidSet(right)) => {
                match (gtid_subset(left, right), gtid_subset(right, left)) {
                    (true, true) => Some(Ordering::Equal),
                    (true, false) => Some(Ordering::Less),
                    (false, true) => Some(Ordering::Greater),
                    (false, false) => None,
                }
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeOperation {
    Insert,
    Update,
    Delete,
}

/// One committed row change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedChange {
    pub record_kind: String,
    pub operation: ChangeOperation,
    /// Primary-key columns in registered order, as `(column, value)`. Every
    /// component is present; NULL keys never reach this record.
    pub key: Vec<(String, String)>,
    /// Row before the change; absent on insert, optional otherwise.
    pub before: Option<BTreeMap<String, String>>,
    /// Row after the change; required on insert and update, absent on delete.
    pub after: Option<BTreeMap<String, String>>,
    pub transaction_id: String,
    /// Commit position of the change's transaction.
    pub commit_position: String,
    pub commit_time_ms: i64,
}

/// How a source schema change maps onto drift handling (ADR 0100).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaChangeClass {
    /// A new optional column: commits under the current revision on the
    /// next source version.
    Additive,
    /// A mapped-column type change that keeps identity: changes wait as
    /// `unbound_type_revision` until a new revision is registered.
    Compatible,
    /// A primary-key change or a dropped mapped column: a new revision and
    /// object-id space, reached only through a re-snapshot.
    Breaking,
}

/// What the plane does with records after a schema change of each class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftHandling {
    Commit,
    AwaitRevision,
    Resnapshot,
}

impl SchemaChangeClass {
    pub fn handling(self) -> DriftHandling {
        match self {
            Self::Additive => DriftHandling::Commit,
            Self::Compatible => DriftHandling::AwaitRevision,
            Self::Breaking => DriftHandling::Resnapshot,
        }
    }
}

/// What a change-capture connector observed, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureEvent {
    /// A consistent snapshot at `position`. The first snapshot opens
    /// generation 1; each re-snapshot opens the next generation.
    Snapshot {
        generation: u64,
        position: String,
    },
    TransactionBegin {
        transaction_id: String,
    },
    Change(CapturedChange),
    TransactionEnd {
        transaction_id: String,
        commit_position: String,
    },
    SchemaChange {
        record_kind: String,
        class: SchemaChangeClass,
        /// For a breaking change of the primary key, the next revision's key
        /// columns in order; they apply from the re-snapshot that opens it.
        new_key: Option<Vec<String>>,
    },
    /// The source no longer retains its log back to `checkpoint`. Terminal
    /// until an operator decides on a re-snapshot; never a silent restart.
    RetentionLost {
        checkpoint: String,
    },
}

/// Totals of a conforming stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureSummary {
    pub generations: u64,
    pub transactions: usize,
    pub changes: usize,
    pub retention_lost: bool,
}

fn strictly_after(
    family: PositionFamily,
    later: &SourcePosition,
    earlier: &SourcePosition,
    what: &str,
) -> Result<(), String> {
    match later.compare(earlier) {
        Some(Ordering::Greater) => Ok(()),
        Some(_) => Err(format!(
            "{what} is not after the previous {} position",
            family.token()
        )),
        None => Err(format!(
            "{what} is not ordered against the previous {} position",
            family.token()
        )),
    }
}

fn check_change(
    change: &CapturedChange,
    key_columns: &BTreeMap<String, Vec<String>>,
) -> Result<(), String> {
    let Some(registered) = key_columns
        .get(&change.record_kind)
        .filter(|key| !key.is_empty())
    else {
        return Err(format!(
            "{:?} has no registered primary key",
            change.record_kind
        ));
    };
    // The key is the registered primary key, column for column and in order.
    // Values are as the source stores them; an empty string is a valid key
    // value. A NULL component has no representation here: the connector
    // refuses it before reporting the change.
    if !change
        .key
        .iter()
        .map(|(column, _)| column)
        .eq(registered.iter())
    {
        return Err(format!(
            "{} change key is not its complete registered primary key",
            change.record_kind
        ));
    }
    if change.transaction_id.trim().is_empty() {
        return Err(format!(
            "{} change has no transaction id",
            change.record_kind
        ));
    }
    if change.commit_time_ms <= 0 {
        return Err(format!("{} change has no commit time", change.record_kind));
    }
    match (change.operation, &change.before, &change.after) {
        (ChangeOperation::Insert, None, Some(_)) => Ok(()),
        (ChangeOperation::Insert, _, _) => Err(format!(
            "{} insert must carry an after image and no before image",
            change.record_kind
        )),
        (ChangeOperation::Update, _, Some(_)) => Ok(()),
        (ChangeOperation::Update, _, None) => Err(format!(
            "{} update must carry an after image",
            change.record_kind
        )),
        (ChangeOperation::Delete, _, None) => Ok(()),
        (ChangeOperation::Delete, _, Some(_)) => Err(format!(
            "{} delete must not carry an after image",
            change.record_kind
        )),
    }
}

/// Commit order across a stream: the last snapshot, checkpoint, or commit
/// position, and every transaction already started.
struct CommitOrder {
    family: PositionFamily,
    last: Option<SourcePosition>,
    /// Whether `last` is a commit position rather than a snapshot or
    /// checkpoint, which a transaction must always pass strictly.
    last_is_commit: bool,
    started: BTreeSet<String>,
}

impl CommitOrder {
    /// Order the snapshot at `at` after everything so far. A re-snapshot
    /// may sit at the current position when nothing committed since.
    fn snapshot(&mut self, at: SourcePosition) -> Result<(), String> {
        if let Some(previous) = &self.last
            && at.compare(previous) != Some(Ordering::Equal)
        {
            strictly_after(self.family, &at, previous, "snapshot position")?;
        }
        self.last = Some(at);
        self.last_is_commit = false;
        Ok(())
    }

    /// Start transaction `id`, committed at `at`: it is new, and it commits
    /// strictly after what came before, or at the same position as the
    /// previous transaction where the family's commit positions can tie.
    fn begin(&mut self, id: &str, at: &SourcePosition) -> Result<(), String> {
        if !self.started.insert(id.to_string()) {
            return Err(format!(
                "transaction {id:?} resumes after another transaction"
            ));
        }
        let Some(previous) = &self.last else {
            return Err("a transaction precedes any snapshot or checkpoint".into());
        };
        let tie = self.last_is_commit
            && self.family.commit_positions_can_tie()
            && at.compare(previous) == Some(Ordering::Equal);
        if !tie {
            strictly_after(self.family, at, previous, "commit position")?;
        }
        self.last = Some(at.clone());
        self.last_is_commit = true;
        Ok(())
    }
}

/// The offline conformance check for one change-capture stream (ADR 0118).
///
/// `key_columns` maps each record kind to its registered primary-key
/// columns in order; a breaking schema change may declare the next
/// revision's key, which applies from the following re-snapshot. `resume_from` is the committed checkpoint, as `(generation, position)`,
/// when the stream resumes instead of starting with a snapshot. The stream
/// must:
/// - start with a generation-1 snapshot, or resume strictly after
///   `resume_from` in its generation; re-snapshots open the next generation
///   at or after the current position;
/// - deliver only committed changes, each strictly after the snapshot or
///   checkpoint it follows, with commit positions that never go back and
///   that advance between transactions (families whose commit positions can
///   tie may repeat one between consecutive transactions);
/// - keep one transaction id and commit position per transaction; a
///   transaction ends at its end marker, at a schema change, or when another
///   starts, and never resumes; markers are optional, but when present they
///   pair up, do not nest, and enclose only their own transaction;
/// - carry the complete registered key on every change, an after image on insert and
///   update, none on delete, and no before image on insert;
/// - stop a record kind after a breaking schema change until a re-snapshot;
/// - end at retention loss: nothing follows it.
pub fn assert_change_capture(
    family: PositionFamily,
    key_columns: &BTreeMap<String, Vec<String>>,
    resume_from: Option<(u64, &str)>,
    events: &[CaptureEvent],
) -> Result<CaptureSummary, String> {
    let mut summary = CaptureSummary::default();
    let mut order = CommitOrder {
        family,
        last: resume_from.map(|(_, raw)| family.parse(raw)).transpose()?,
        last_is_commit: false,
        started: BTreeSet::new(),
    };
    let mut generation = match resume_from {
        Some((0, _)) => return Err("a checkpoint belongs to generation 1 or later".into()),
        Some((generation, _)) => generation,
        None => 0,
    };
    // The transaction an explicit begin marker opened.
    let mut open: Option<String> = None;
    // The transaction still accepting changes, and its commit position.
    let mut current: Option<(String, SourcePosition)> = None;
    let mut stopped_kinds: BTreeSet<String> = BTreeSet::new();
    // Key registrations in force, and those the next re-snapshot applies.
    let mut registered = key_columns.clone();
    let mut pending_keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if resume_from.is_none() && !matches!(events.first(), Some(CaptureEvent::Snapshot { .. })) {
        return Err("a stream without a checkpoint must start with a snapshot".into());
    }
    for event in events {
        if summary.retention_lost {
            return Err("events follow retention loss; it must stop the stream".into());
        }
        match event {
            CaptureEvent::Snapshot {
                generation: next,
                position: raw,
            } => {
                if open.is_some() {
                    return Err("a snapshot starts inside an open transaction".into());
                }
                if *next != generation + 1 {
                    return Err(format!(
                        "snapshot generation {next} does not follow generation {generation}"
                    ));
                }
                order.snapshot(family.parse(raw)?)?;
                generation = *next;
                summary.generations += 1;
                stopped_kinds.clear();
                registered.append(&mut pending_keys);
                current = None;
            }
            CaptureEvent::TransactionBegin { transaction_id } => {
                if open.is_some() {
                    return Err("transaction markers nest".into());
                }
                if transaction_id.trim().is_empty() {
                    return Err("transaction begin has no id".into());
                }
                if order.started.contains(transaction_id) {
                    return Err(format!(
                        "transaction begin {transaction_id:?} comes after the transaction started"
                    ));
                }
                // A begin marker ends any unmarked transaction before it.
                current = None;
                open = Some(transaction_id.clone());
            }
            CaptureEvent::TransactionEnd {
                transaction_id,
                commit_position,
            } => {
                if open.as_deref() != Some(transaction_id.as_str()) {
                    return Err(format!(
                        "transaction end {transaction_id:?} has no matching begin"
                    ));
                }
                let at = family.parse(commit_position)?;
                match &current {
                    Some((id, change_at)) if id == transaction_id => {
                        if at.compare(change_at) != Some(Ordering::Equal) {
                            return Err(format!(
                                "transaction {transaction_id:?} ends at another position than its changes"
                            ));
                        }
                    }
                    // A transaction without captured rows still commits in order.
                    _ => {
                        order.begin(transaction_id, &at)?;
                        summary.transactions += 1;
                    }
                }
                open = None;
                current = None;
            }
            CaptureEvent::Change(change) => {
                check_change(change, &registered)?;
                if stopped_kinds.contains(&change.record_kind) {
                    return Err(format!(
                        "{} change follows a breaking schema change without a re-snapshot",
                        change.record_kind
                    ));
                }
                if let Some(id) = &open
                    && id != &change.transaction_id
                {
                    return Err(format!(
                        "change of transaction {:?} inside transaction {id:?}",
                        change.transaction_id
                    ));
                }
                let at = family.parse(&change.commit_position)?;
                match &current {
                    Some((id, change_at)) if id == &change.transaction_id => {
                        if at.compare(change_at) != Some(Ordering::Equal) {
                            return Err(format!(
                                "transaction {id:?} changes carry different commit positions"
                            ));
                        }
                    }
                    _ => {
                        order.begin(&change.transaction_id, &at)?;
                        summary.transactions += 1;
                        current = Some((change.transaction_id.clone(), at));
                    }
                }
                summary.changes += 1;
            }
            CaptureEvent::SchemaChange {
                record_kind,
                class,
                new_key,
            } => {
                if open.is_some() {
                    return Err("a schema change is reported inside an open transaction".into());
                }
                // A schema change sits between transactions: none resumes after it.
                current = None;
                if class.handling() == DriftHandling::Resnapshot {
                    stopped_kinds.insert(record_kind.clone());
                }
                if let Some(key) = new_key {
                    if *class != SchemaChangeClass::Breaking || key.is_empty() {
                        return Err(format!(
                            "{record_kind} key changes only through a breaking schema change"
                        ));
                    }
                    pending_keys.insert(record_kind.clone(), key.clone());
                }
            }
            CaptureEvent::RetentionLost { checkpoint } => {
                family.parse(checkpoint)?;
                summary.retention_lost = true;
            }
        }
    }
    if open.is_some() {
        return Err("the stream ends inside an open transaction".into());
    }
    Ok(summary)
}

/// A conforming stream for `family` with its registered key columns:
/// snapshot, a marked transaction, an additive schema change, and an
/// unmarked delete. Connector authors replace it with what their connector
/// read from a containerized source.
pub fn change_capture_fixture(
    family: PositionFamily,
) -> (BTreeMap<String, Vec<String>>, Vec<CaptureEvent>) {
    let positions: [&str; 3] = match family {
        PositionFamily::PostgresLsn => ["0/16B3748", "0/16B3790", "0/16B37D8"],
        PositionFamily::MysqlGtidSet => [
            "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-10",
            "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-11",
            "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-12",
        ],
        PositionFamily::SqlServerLsn => [
            "00000027:00000088:0003",
            "00000027:00000090:0001",
            "00000027:00000098:0002",
        ],
        PositionFamily::OracleScn => ["2122410", "2122455", "2122470"],
    };
    let row = |name: &str| {
        BTreeMap::from([
            ("id".to_string(), "7".to_string()),
            ("name".to_string(), name.to_string()),
        ])
    };
    let change = |operation, before, after, transaction: &str, at: &str, time| {
        CaptureEvent::Change(CapturedChange {
            record_kind: "customer".into(),
            operation,
            key: vec![("id".into(), "7".into())],
            before,
            after,
            transaction_id: transaction.into(),
            commit_position: at.into(),
            commit_time_ms: time,
        })
    };
    let key_columns = BTreeMap::from([("customer".to_string(), vec!["id".to_string()])]);
    let events = vec![
        CaptureEvent::Snapshot {
            generation: 1,
            position: positions[0].into(),
        },
        CaptureEvent::TransactionBegin {
            transaction_id: "tx-1".into(),
        },
        change(
            ChangeOperation::Insert,
            None,
            Some(row("a")),
            "tx-1",
            positions[1],
            1_700_000_000_000,
        ),
        change(
            ChangeOperation::Update,
            Some(row("a")),
            Some(row("b")),
            "tx-1",
            positions[1],
            1_700_000_000_000,
        ),
        CaptureEvent::TransactionEnd {
            transaction_id: "tx-1".into(),
            commit_position: positions[1].into(),
        },
        CaptureEvent::SchemaChange {
            record_kind: "customer".into(),
            class: SchemaChangeClass::Additive,
            new_key: None,
        },
        change(
            ChangeOperation::Delete,
            Some(row("b")),
            None,
            "tx-2",
            positions[2],
            1_700_000_001_000,
        ),
    ];
    (key_columns, events)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAMILIES: [PositionFamily; 4] = [
        PositionFamily::PostgresLsn,
        PositionFamily::MysqlGtidSet,
        PositionFamily::SqlServerLsn,
        PositionFamily::OracleScn,
    ];

    #[test]
    fn every_family_fixture_conforms() {
        for family in FAMILIES {
            let (key_columns, events) = change_capture_fixture(family);
            let summary = assert_change_capture(family, &key_columns, None, &events)
                .unwrap_or_else(|error| panic!("{}: {error}", family.token()));
            assert_eq!(
                (summary.generations, summary.transactions, summary.changes),
                (1, 2, 3)
            );
        }
    }

    #[test]
    fn positions_parse_and_order_per_family() {
        let lsn = PositionFamily::PostgresLsn;
        assert_eq!(
            lsn.parse("1/0")
                .unwrap()
                .compare(&lsn.parse("0/FFFFFFFF").unwrap()),
            Some(Ordering::Greater)
        );
        let scn = PositionFamily::OracleScn;
        assert_eq!(
            scn.parse("10").unwrap().compare(&scn.parse("9").unwrap()),
            Some(Ordering::Greater)
        );
        let sql = PositionFamily::SqlServerLsn;
        assert_eq!(
            sql.parse("00000027:00000088:0003")
                .unwrap()
                .compare(&sql.parse("00000027:00000088:0004").unwrap()),
            Some(Ordering::Less)
        );
        let gtid = PositionFamily::MysqlGtidSet;
        let a = "3e11fa47-71ca-11e1-9e33-c80aa9429562";
        let b = "4e11fa47-71ca-11e1-9e33-c80aa9429562";
        let small = gtid.parse(&format!("{a}:1-5")).unwrap();
        let large = gtid.parse(&format!("{a}:1-3:4-6,{b}:1")).unwrap();
        assert_eq!(small.compare(&large), Some(Ordering::Less));
        assert_eq!(
            gtid.parse(&format!("{a}:1-6,{b}:1"))
                .unwrap()
                .compare(&large),
            Some(Ordering::Equal)
        );
        // Diverged sets are unordered, never guessed.
        let diverged = gtid.parse(&format!("{a}:1-4,{b}:1-2")).unwrap();
        assert_eq!(diverged.compare(&large), None);
        for (family, bad) in [
            (lsn, "16B3748"),
            (scn, "-1"),
            (sql, "27:88:3"),
            (gtid, "not-a-uuid:1"),
            (gtid, "------------------------------------:1"),
            (gtid, &format!("{a}:5-1")),
        ] {
            assert!(
                family.parse(bad).is_err(),
                "{} accepted {bad:?}",
                family.token()
            );
        }
    }

    fn fixture() -> Vec<CaptureEvent> {
        change_capture_fixture(PositionFamily::OracleScn).1
    }

    fn keys() -> BTreeMap<String, Vec<String>> {
        change_capture_fixture(PositionFamily::OracleScn).0
    }

    fn refused(events: &[CaptureEvent]) -> String {
        assert_change_capture(PositionFamily::OracleScn, &keys(), None, events).unwrap_err()
    }

    #[test]
    fn changes_must_follow_the_snapshot_handoff() {
        let mut events = fixture();
        events[0] = CaptureEvent::Snapshot {
            generation: 1,
            position: "2122455".into(),
        };
        assert!(refused(&events).contains("not after"));
        assert!(refused(&events[1..]).contains("must start with a snapshot"));
        // A resumed stream continues strictly after its checkpoint.
        assert!(
            assert_change_capture(
                PositionFamily::OracleScn,
                &keys(),
                Some((1, "2122410")),
                &events[1..]
            )
            .is_ok()
        );
        assert!(
            assert_change_capture(
                PositionFamily::OracleScn,
                &keys(),
                Some((1, "2122455")),
                &events[1..]
            )
            .is_err()
        );
    }

    #[test]
    fn re_snapshots_fence_generations() {
        let mut events = fixture();
        events.push(CaptureEvent::Snapshot {
            generation: 3,
            position: "2122500".into(),
        });
        assert!(refused(&events).contains("does not follow generation"));
        // A resumed generation-2 stream recovers into generation 3, even at
        // the position it resumed from.
        let resumed = [CaptureEvent::Snapshot {
            generation: 3,
            position: "2122470".into(),
        }];
        assert!(
            assert_change_capture(
                PositionFamily::OracleScn,
                &keys(),
                Some((2, "2122470")),
                &resumed
            )
            .is_ok()
        );
        assert!(
            assert_change_capture(
                PositionFamily::OracleScn,
                &keys(),
                Some((2, "2122480")),
                &resumed
            )
            .unwrap_err()
            .contains("not after")
        );
        events.pop();
        events.push(CaptureEvent::Snapshot {
            generation: 2,
            position: "2122500".into(),
        });
        let summary =
            assert_change_capture(PositionFamily::OracleScn, &keys(), None, &events).unwrap();
        assert_eq!(summary.generations, 2);
    }

    #[test]
    fn transactions_keep_one_commit_position_and_pair_their_markers() {
        let mut split = fixture();
        if let CaptureEvent::Change(change) = &mut split[3] {
            change.commit_position = "2122456".into();
        }
        assert!(refused(&split).contains("different commit positions"));

        let mut unclosed = fixture();
        unclosed.remove(4);
        assert!(refused(&unclosed).contains("open transaction"));

        let mut interleaved = fixture();
        if let CaptureEvent::Change(change) = &mut interleaved[3] {
            change.transaction_id = "tx-other".into();
        }
        assert!(refused(&interleaved).contains("inside transaction"));

        let mut resumed = fixture();
        resumed.push(CaptureEvent::Change(CapturedChange {
            record_kind: "customer".into(),
            operation: ChangeOperation::Insert,
            key: vec![("id".into(), "8".into())],
            before: None,
            after: Some(BTreeMap::new()),
            transaction_id: "tx-1".into(),
            commit_position: "2122480".into(),
            commit_time_ms: 1,
        }));
        assert!(refused(&resumed).contains("resumes after another transaction"));
    }

    #[test]
    fn oracle_transactions_may_share_a_commit_scn_but_others_may_not() {
        let tied = |family: PositionFamily| {
            let (key_columns, mut events) = change_capture_fixture(family);
            let first_commit = match &events[4] {
                CaptureEvent::TransactionEnd {
                    commit_position, ..
                } => commit_position.clone(),
                _ => unreachable!(),
            };
            if let CaptureEvent::Change(change) = &mut events[6] {
                change.commit_position = first_commit;
            }
            assert_change_capture(family, &key_columns, None, &events)
        };
        assert!(tied(PositionFamily::OracleScn).is_ok());
        assert!(tied(PositionFamily::PostgresLsn).is_err());
        // A tie never reaches back to the snapshot.
        let mut events = fixture();
        if let CaptureEvent::Change(change) = &mut events[2] {
            change.commit_position = "2122410".into();
        }
        assert!(refused(&events).contains("not after"));
    }

    #[test]
    fn an_empty_marked_transaction_still_commits_in_order() {
        let mut events = fixture();
        events.extend([
            CaptureEvent::TransactionBegin {
                transaction_id: "tx-empty".into(),
            },
            CaptureEvent::TransactionEnd {
                transaction_id: "tx-empty".into(),
                commit_position: "2122465".into(),
            },
        ]);
        assert!(refused(&events).contains("not after"));
        if let CaptureEvent::TransactionEnd {
            commit_position, ..
        } = events.last_mut().unwrap()
        {
            *commit_position = "2122490".into();
        }
        let summary =
            assert_change_capture(PositionFamily::OracleScn, &keys(), None, &events).unwrap();
        assert_eq!(summary.transactions, 3);
        let mut late = events.clone();
        late.push(CaptureEvent::Change(CapturedChange {
            record_kind: "customer".into(),
            operation: ChangeOperation::Delete,
            key: vec![("id".into(), "9".into())],
            before: None,
            after: None,
            transaction_id: "tx-empty".into(),
            commit_position: "2122495".into(),
            commit_time_ms: 1,
        }));
        assert!(refused(&late).contains("resumes after another transaction"));
    }

    #[test]
    fn a_schema_change_closes_an_unmarked_transaction() {
        let mut events = fixture();
        let delete = events[6].clone();
        events.insert(
            7,
            CaptureEvent::SchemaChange {
                record_kind: "customer".into(),
                class: SchemaChangeClass::Additive,
                new_key: None,
            },
        );
        events.push(delete);
        assert!(refused(&events).contains("resumes after another transaction"));
    }

    #[test]
    fn a_begin_marker_cannot_follow_its_own_changes() {
        let mut events = fixture();
        // tx-2's delete, then markers for tx-2.
        events.extend([
            CaptureEvent::TransactionBegin {
                transaction_id: "tx-2".into(),
            },
            CaptureEvent::TransactionEnd {
                transaction_id: "tx-2".into(),
                commit_position: "2122470".into(),
            },
        ]);
        assert!(refused(&events).contains("after the transaction started"));
    }

    #[test]
    fn a_change_after_its_transaction_end_is_refused() {
        let mut events = fixture();
        let late = events[3].clone();
        events.insert(5, late);
        assert!(refused(&events).contains("resumes after another transaction"));
    }

    #[test]
    fn records_carry_keys_and_the_right_images() {
        let mut empty_value = fixture();
        if let CaptureEvent::Change(change) = &mut empty_value[2] {
            change.key = vec![("id".into(), String::new())];
        }
        assert!(
            assert_change_capture(PositionFamily::OracleScn, &keys(), None, &empty_value).is_ok()
        );
        // (event index, edit, expected refusal)
        type Case = (usize, fn(&mut CapturedChange), &'static str);
        let cases: [Case; 7] = [
            (2, |change| change.key.clear(), "registered primary key"),
            (
                2,
                |change| change.key = vec![("tenant".into(), "7".into())],
                "registered primary key",
            ),
            (
                2,
                |change| change.key.push(("id".into(), "7".into())),
                "registered primary key",
            ),
            (
                2,
                |change| change.record_kind = "unregistered".into(),
                "no registered primary key",
            ),
            (
                2,
                |change| change.before = Some(BTreeMap::new()),
                "no before image",
            ),
            (3, |change| change.after = None, "after image"),
            (
                6,
                |change| change.after = Some(BTreeMap::new()),
                "must not carry an after image",
            ),
        ];
        for (index, edit, expected) in cases {
            let mut events = fixture();
            if let CaptureEvent::Change(change) = &mut events[index] {
                edit(change);
            }
            let error = refused(&events);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn a_breaking_schema_change_stops_the_kind_until_a_re_snapshot() {
        let mut events = fixture();
        events[5] = CaptureEvent::SchemaChange {
            record_kind: "customer".into(),
            class: SchemaChangeClass::Breaking,
            new_key: Some(vec!["tenant".into(), "id".into()]),
        };
        assert!(refused(&events).contains("breaking schema change"));
        events.insert(
            6,
            CaptureEvent::Snapshot {
                generation: 2,
                position: "2122460".into(),
            },
        );
        // After the re-snapshot the new revision's key applies.
        assert!(refused(&events).contains("registered primary key"));
        if let CaptureEvent::Change(change) = &mut events[7] {
            change.key = vec![("tenant".into(), "t1".into()), ("id".into(), "7".into())];
        }
        assert!(assert_change_capture(PositionFamily::OracleScn, &keys(), None, &events).is_ok());
        // Only a breaking change may move the key.
        events[5] = CaptureEvent::SchemaChange {
            record_kind: "customer".into(),
            class: SchemaChangeClass::Compatible,
            new_key: Some(vec!["tenant".into(), "id".into()]),
        };
        assert!(refused(&events).contains("only through a breaking schema change"));
        assert_eq!(
            SchemaChangeClass::Compatible.handling(),
            DriftHandling::AwaitRevision
        );
    }

    #[test]
    fn retention_loss_ends_the_stream() {
        let mut events = fixture();
        events.insert(
            5,
            CaptureEvent::RetentionLost {
                checkpoint: "2122455".into(),
            },
        );
        assert!(refused(&events).contains("retention loss"));
        events.truncate(6);
        let summary =
            assert_change_capture(PositionFamily::OracleScn, &keys(), None, &events).unwrap();
        assert!(summary.retention_lost);
    }
}
