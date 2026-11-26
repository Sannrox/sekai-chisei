//! The `postgres_capture` connector type (ADR 0170): `check`, snapshot
//! pages and ordered change pages through the sandboxed change-capture
//! child of [`capture`].
//!
//! Every operation dials the Source's `endpoint` after the egress check
//! ([`capture::connect_admitted`]) and starts one child over that socket,
//! with the Source's `password` once in its start message. The child reads
//! one bounded page from the Source's replication slot and writes JSON
//! lines; this module turns them into records of the Source's
//! `record_kind`, numbered from the plane's committed offset.
//!
//! The snapshot is read after the slot's position `P` (ADR 0170, option B
//! of #3083): the first page makes sure the slot exists and takes its
//! confirmed position, and each page reads the next rows in key order in a
//! fresh child. Its cursor is `pg1s/<P>/<last key>`, the key in the
//! `external_id` encoding below, so it never contains `/`. The last page
//! hands off as `pg1/<P>` at offset 0, and the feed replays every change
//! committed after `P`. Rows read after `P` are keyed upserts the feed
//! brings to the latest value, so the plane ends in the source's state; a
//! row can briefly show an older value again during the hand-off. An empty
//! table is refused as `table_empty` and fails the run `unavailable`, so
//! the next sync tries again.
//!
//! The runtime creates only a slot the plane records (#3083, ADR 0170).
//! A first snapshot, with no committed cursor, runs with the slots the
//! plane recorded: a missing unrecorded slot comes back `slot_missing`,
//! the runtime records it under the sync's claim and runs the page again,
//! and only then does the child create it. A crash in between leaves a
//! recorded slot the next sync creates. An existing slot the plane does
//! not record is refused as `slot_ahead_of_snapshot` and never dropped or
//! re-created. A recovery snapshot has a committed cursor and uses or
//! creates the slot as before. Every page reports the log the slot
//! retains as a `retained_log` note, sent with the sync's acknowledgement.
//!
//! The feed position lives only in the plane's cursor (ADR 0118):
//! `pg1/<lsn>` is the end of the last transaction the plane holds whole,
//! and `pg1/<lsn>/<commit>/<index>` adds that it also holds the changes
//! before `index` of the transaction committing at `commit`, when a
//! transaction did not fit one page. The child streams only committed
//! transactions, so a page may end inside one; the next page streams that
//! transaction again from `lsn` and skips what the plane holds. The child
//! confirms to the server only `lsn`, so a restarted child, or another
//! runtime after a takeover, resumes from the committed cursor without
//! duplicates or gaps.
//!
//! The publication carries one table, whose replica identity is its key.
//! Each change is one record whose `external_id` is the key's values in
//! column-name order, percent-encoded and joined by `~`; properties are
//! the row's non-null text values, without columns whose names suggest a
//! secret. A delete is a tombstone, and an update that changes the key is
//! a tombstone of the old key and the row under the new one. Fail closed,
//! as `invalid`: a truncate, an update that leaves a large value out of
//! the stream (`unchanged`), a row of another table, a key that is
//! missing, null or empty, and any line the child should not write.
//!
//! Supervision: a child that dies, overruns its deadline, or finds the
//! slot still held by the previous child is restarted with backoff, three
//! times at most, before the run fails as `unavailable` (or
//! `unreachable`). A host whose sandbox cannot apply fails `unavailable`
//! at once. Refusals map onto the Source's health by name: a refused
//! password is `auth_failed`, a role without replication permission
//! `permission_missing`, and every other refusal `invalid`, including a
//! certificate that does not verify and a slot gone or ahead of the
//! cursor. [`Capture::offered`] offers the type only where the child's
//! sandbox self-test passes.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, Read};
use std::path::Path;
use std::time::Duration;

use std::sync::Mutex;

use sekai_source_sdk::{
    ChangeFeedPage, ConfigValue, Connector, ConnectorFailure, Destination, EgressAllowlist,
    GenerationSnapshotPage, PlaneView, PlaneViewError, PropertyValue, SourceRecord, SyncNote,
    WalStatus, column_name_suggests_sensitive,
};
use serde::{Deserialize, Serialize};

use crate::capture::{self, CaptureChild, ConnectRefused, EXIT_UNAVAILABLE, Unavailable};
use crate::child::{ChildError, Streamed};
use crate::credentials::Secret;
use crate::relational::{digest_of, percent_decode, percent_encode};
use crate::rest::now_ms;
use crate::sync::Prepared;

/// The PostgreSQL port an endpoint without one connects to.
const DEFAULT_PORT: u16 = 5432;

/// How long one child run may take. The child stops a page once the
/// stream idles, well inside this.
const RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// The waits before each restart of a child that died.
const RESTARTS: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

/// The longest line the child writes, newline included.
const MAX_LINE_BYTES: u64 = 64 * 1024 * 1024;

/// Paths the child reads under its sandbox besides its own executable:
/// the usual system trust roots.
const TRUST_ROOTS: [&str; 3] = ["/etc/ssl", "/usr/lib/ssl", "/etc/pki"];

/// What every capture Source of this runtime shares: the installed child
/// and the operator's CA (PEM), trusted beside the system roots.
#[derive(Debug, Clone)]
pub struct Capture {
    child: CaptureChild,
    ca_pem: Option<String>,
}

impl Capture {
    pub fn new(child: CaptureChild, ca_pem: Option<String>) -> Self {
        Self { child, ca_pem }
    }

    /// The capture this host offers: the child installed beside the
    /// runtime, once its sandbox self-test passes with the paths every run
    /// reads. Linux only; elsewhere, or when the test fails, the reason.
    pub fn offered(ca_pem: Option<String>) -> Result<Self, Unavailable> {
        let child = CaptureChild::beside_runtime()
            .ok_or_else(|| Unavailable("change-capture child not installed".into()))?;
        child.self_test(&read_paths(child.path()))?;
        Ok(Self::new(child, ca_pem))
    }
}

/// The paths the child reads under its sandbox: its own executable and
/// the system trust roots this host has. A path the sandbox cannot open
/// would make it fail closed, so only existing ones are listed.
fn read_paths(child: &Path) -> Vec<&Path> {
    std::iter::once(child)
        .chain(
            TRUST_ROOTS
                .iter()
                .map(Path::new)
                .filter(|path| path.exists()),
        )
        .collect()
}

/// Opens the type for a prepared Source; register it with
/// `Connectors::with(&POSTGRES_CAPTURE_CONNECTOR, move |prepared| postgres_capture::open(prepared, &capture))`.
pub fn open(
    prepared: &Prepared,
    capture: &Capture,
) -> Result<Box<dyn Connector + Send>, ConnectorFailure> {
    let text = |name: &str| match prepared.config.get(name) {
        Some(ConfigValue::Text(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(ConnectorFailure::Invalid),
    };
    let mut endpoint = Destination::parse(&text("endpoint")?).ok_or(ConnectorFailure::Invalid)?;
    endpoint.port = Some(endpoint.port.unwrap_or(DEFAULT_PORT));
    let password = prepared
        .credentials
        .get("password")
        .ok_or(ConnectorFailure::AuthFailed)?
        .clone();
    Ok(Box::new(PostgresCapture {
        child: capture.child.clone(),
        settings: Settings {
            server_name: endpoint.host.clone(),
            user: text("user")?,
            database: text("database")?,
            ca_pem: capture.ca_pem.clone(),
            slot: text("slot")?,
            publication: text("publication")?,
            resume_lsn: 0,
            max_commits: 0,
            snapshot_lsn: 0,
            snapshot_after: None,
            max_rows: 0,
            slot_recorded: false,
        },
        endpoint,
        egress: prepared.egress.clone(),
        password,
        record_kind: text("record_kind")?,
    }))
}

struct PostgresCapture {
    child: CaptureChild,
    endpoint: Destination,
    egress: EgressAllowlist,
    password: Secret,
    settings: Settings,
    record_kind: String,
}

/// The PostgreSQL part of the child's start message.
#[derive(Debug, Clone, Serialize)]
struct Settings {
    server_name: String,
    user: String,
    database: String,
    ca_pem: Option<String>,
    slot: String,
    publication: String,
    resume_lsn: u64,
    max_commits: u32,
    snapshot_lsn: u64,
    snapshot_after: Option<Vec<String>>,
    max_rows: u32,
    slot_recorded: bool,
}

impl Connector for PostgresCapture {
    fn check(&mut self) -> Result<(), ConnectorFailure> {
        self.supervised("check", &self.settings, |out| match next_line(out) {
            Next::Line(Line::Checked) => Outcome::Done(()),
            Next::Line(other) => other.outcome(),
            Next::End => Outcome::Ended(None),
            Next::Invalid => Outcome::Invalid,
        })
    }

    fn read_snapshot_page_with_plane(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
        plane: &mut dyn PlaneView,
    ) -> Result<GenerationSnapshotPage, ConnectorFailure> {
        // Any other cursor, such as a feed position the plane moved to
        // recovery, starts a new snapshot.
        let from = match committed_cursor {
            Some(text) if text.starts_with(SnapshotCursor::PREFIX) => {
                Some(SnapshotCursor::parse(text).ok_or(ConnectorFailure::Invalid)?)
            }
            _ => None,
        };
        if max_records == 0 {
            return Err(ConnectorFailure::Invalid);
        }
        // Only a first snapshot checks the plane's record; a recovery
        // snapshot uses or creates the slot as before.
        let slot = &self.settings.slot;
        let mut settings = Settings {
            snapshot_lsn: from.as_ref().map_or(0, |from| from.lsn),
            snapshot_after: from.as_ref().map(|from| from.after.clone()),
            max_rows: u32::try_from(max_records).unwrap_or(u32::MAX),
            slot_recorded: committed_cursor.is_some()
                || plane
                    .created_slots()
                    .iter()
                    .any(|recorded| recorded == slot),
            ..self.settings.clone()
        };
        let reading = SnapshotReading {
            from: from.as_ref(),
            max_records,
            kind: Kind {
                record_kind: &self.record_kind,
                now_ms: now_ms(),
            },
            retained: Mutex::default(),
        };
        let read = self.supervised("snapshot", &settings, |out| reading.read(out));
        let read = match read {
            Ok(Snapshot::Missing) if !settings.slot_recorded => {
                plane
                    .record_created_slot(slot)
                    .map_err(|error| view_failure(error, &reading.retained, slot, plane))?;
                settings.slot_recorded = true;
                self.supervised("snapshot", &settings, |out| reading.read(out))
            }
            read => read,
        };
        report_retained(&reading.retained, slot, plane);
        let page = match read? {
            Snapshot::Page(page) => page,
            // A recorded slot is created, never reported missing.
            Snapshot::Missing => return Err(ConnectorFailure::Invalid),
        };
        let handoff = Cursor {
            lsn: page.lsn,
            within: None,
        };
        let proposed_next_cursor = match page.records.last() {
            Some(last) if !page.complete => SnapshotCursor::text(page.lsn, &last.external_id),
            _ => handoff.to_string(),
        };
        Ok(GenerationSnapshotPage {
            records: page.records,
            proposed_next_cursor,
            collected_at_ms: reading.kind.now_ms,
            complete: page.complete,
            source_feed_epoch: page
                .complete
                .then(|| format!("{}@{}", self.settings.slot, page.lsn)),
            handoff_offset: page.complete.then_some(0),
        })
    }

    fn read_changes_with_plane(
        &mut self,
        committed_cursor: &str,
        _source_feed_epoch: &str,
        committed_offset: u64,
        max_records: usize,
        plane: &mut dyn PlaneView,
    ) -> Result<ChangeFeedPage, ConnectorFailure> {
        let from = Cursor::parse(committed_cursor).ok_or(ConnectorFailure::Invalid)?;
        if max_records == 0 {
            return Err(ConnectorFailure::Invalid);
        }
        let settings = Settings {
            resume_lsn: from.lsn,
            // Every transaction carries a change of the one table.
            max_commits: u32::try_from(max_records).unwrap_or(u32::MAX),
            ..self.settings.clone()
        };
        let reading = Reading {
            from,
            offset: committed_offset,
            max_records,
            kind: Kind {
                record_kind: &self.record_kind,
                now_ms: now_ms(),
            },
            retained: Mutex::default(),
        };
        let page = self.supervised("changes", &settings, |out| reading.read(out));
        report_retained(&reading.retained, &self.settings.slot, plane);
        let page = page?;
        Ok(ChangeFeedPage {
            offset_start: committed_offset,
            records: page.records,
            proposed_next_cursor: page.next.to_string(),
            collected_at_ms: reading.kind.now_ms,
            caught_up: page.caught_up,
        })
    }
}

impl PostgresCapture {
    /// Runs the child in `mode` until `read` concludes, restarting a child
    /// that died with [`RESTARTS`] backoff.
    fn supervised<T: Send>(
        &self,
        mode: &str,
        settings: &Settings,
        read: impl Fn(&mut dyn BufRead) -> Outcome<T> + Sync,
    ) -> Result<T, ConnectorFailure> {
        let start = serde_json::json!({
            "credential": self.password.expose(),
            "read_paths": self.read_paths(),
            "postgres": settings,
        })
        .to_string()
        .into_bytes();
        let mut waits = RESTARTS.iter();
        loop {
            match self.attempt(mode, &start, &read) {
                Attempt::Done(value) => return Ok(value),
                Attempt::Failed(failure) => return Err(failure),
                Attempt::Died(failure) => match waits.next() {
                    Some(wait) => std::thread::sleep(*wait),
                    None => return Err(failure),
                },
            }
        }
    }

    fn attempt<T: Send>(
        &self,
        mode: &str,
        start: &[u8],
        read: &(impl Fn(&mut dyn BufRead) -> Outcome<T> + Sync),
    ) -> Attempt<T> {
        let socket = match capture::connect_admitted(&self.endpoint, &self.egress) {
            Ok(socket) => socket,
            Err(ConnectRefused::Egress) => return Attempt::Failed(ConnectorFailure::Invalid),
            Err(ConnectRefused::Unreachable) => {
                return Attempt::Died(ConnectorFailure::Unreachable);
            }
        };
        match self.child.stream(mode, &socket, start, RUN_TIMEOUT, read) {
            Ok(Streamed { status, read }) => {
                let code = status.and_then(|status| status.code());
                read.settle(code)
            }
            Err(ChildError::Spawn) => Attempt::Failed(ConnectorFailure::Unavailable),
            Err(ChildError::Overran) => Attempt::Died(ConnectorFailure::Unavailable),
        }
    }

    fn read_paths(&self) -> Vec<&Path> {
        read_paths(self.child.path())
    }
}

/// The log the slot retains, as the child last measured it.
type Retained = Mutex<Option<(i64, String)>>;

/// Reports the last retained log measured to the plane, as a note. A
/// status this runtime does not know is left out.
fn report_retained(retained: &Retained, slot: &str, plane: &mut dyn PlaneView) {
    let measured = retained.lock().map(|mut measured| measured.take());
    if let Ok(Some((bytes, status))) = measured
        && let Some(wal_status) = WalStatus::from_wire_name(&status)
    {
        plane.note(SyncNote::RetainedLog {
            slot: slot.into(),
            bytes,
            wal_status,
        });
    }
}

/// A slot the plane could not record as the run's failure, reporting the
/// log measured so far. A lapsed claim or a plane that cannot answer is
/// `unavailable`, so the next sync records it.
fn view_failure(
    error: PlaneViewError,
    retained: &Retained,
    slot: &str,
    plane: &mut dyn PlaneView,
) -> ConnectorFailure {
    report_retained(retained, slot, plane);
    match error {
        PlaneViewError::Unkeyed => ConnectorFailure::Invalid,
        _ => ConnectorFailure::Unavailable,
    }
}

/// One child run's result.
enum Attempt<T> {
    Done(T),
    /// Final: restarting would not help.
    Failed(ConnectorFailure),
    /// The child died or was turned away for now; restart it, or fail
    /// with this once the restarts are spent.
    Died(ConnectorFailure),
}

/// What a reader made of the child's output.
#[derive(Debug, PartialEq)]
enum Outcome<T> {
    /// The reader has what it needs, whatever the child does next.
    Done(T),
    Refused(String),
    /// The host cannot apply the child's sandbox.
    Unavailable,
    /// The output ended. `Some` is complete if the child exited cleanly.
    Ended(Option<T>),
    Invalid,
}

impl<T> Outcome<T> {
    /// The run's result, given the child's exit code (`None` when it was
    /// stopped or killed by a signal).
    fn settle(self, code: Option<i32>) -> Attempt<T> {
        match self {
            Self::Done(value) => Attempt::Done(value),
            Self::Ended(Some(value)) if code == Some(0) => Attempt::Done(value),
            Self::Unavailable => Attempt::Failed(ConnectorFailure::Unavailable),
            Self::Ended(_) if code == Some(EXIT_UNAVAILABLE) => {
                Attempt::Failed(ConnectorFailure::Unavailable)
            }
            Self::Ended(_) => Attempt::Died(ConnectorFailure::Unavailable),
            Self::Refused(reason) => refused(&reason),
            Self::Invalid => Attempt::Failed(ConnectorFailure::Invalid),
        }
    }
}

/// A refusal the child named, as the Source's health records it.
fn refused<T>(reason: &str) -> Attempt<T> {
    match reason {
        "auth_failed" | "auth_method_unsupported" => Attempt::Failed(ConnectorFailure::AuthFailed),
        "replication_permission_missing" => Attempt::Failed(ConnectorFailure::PermissionMissing),
        "connection_closed" => Attempt::Died(ConnectorFailure::Unreachable),
        // The previous child's session still holds the slot, or another
        // runtime created it a moment ago.
        "slot_in_use" | "slot_conflict" => Attempt::Died(ConnectorFailure::Unavailable),
        // Fails visibly; the next sync tries again once a row exists.
        "table_empty" => Attempt::Failed(ConnectorFailure::Unavailable),
        _ => Attempt::Failed(ConnectorFailure::Invalid),
    }
}

/// One line the child writes, as far as the runtime reads it.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Line {
    Change {
        commit_lsn: u64,
        index: u32,
        relation: String,
        op: Op,
        key: BTreeMap<String, Option<String>>,
        row: BTreeMap<String, Option<String>>,
        unchanged: Vec<String>,
    },
    Truncate {},
    Commit {
        end_lsn: u64,
    },
    SlotCreated {},
    SlotMissing {},
    RetainedLog {
        bytes: i64,
        wal_status: String,
    },
    SnapshotAt {
        lsn: u64,
    },
    Row {
        key: BTreeMap<String, Option<String>>,
        row: BTreeMap<String, Option<String>>,
    },
    Gone {
        key: BTreeMap<String, Option<String>>,
    },
    SnapshotEnd {
        complete: bool,
    },
    CaughtUp {},
    Checked,
    Refused {
        reason: String,
    },
    Unavailable {},
}

impl Line {
    /// The outcome of a line that ends a reader that did not expect it.
    fn outcome<T>(self) -> Outcome<T> {
        match self {
            Self::Refused { reason } => Outcome::Refused(reason),
            Self::Unavailable {} => Outcome::Unavailable,
            _ => Outcome::Invalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    Insert,
    Update,
    Delete,
}

enum Next {
    Line(Line),
    End,
    Invalid,
}

/// The next whole line. A line cut short by the end of the output is the
/// end: the child died writing it.
fn next_line(out: &mut dyn BufRead) -> Next {
    let mut line = Vec::new();
    match (&mut *out)
        .take(MAX_LINE_BYTES)
        .read_until(b'\n', &mut line)
    {
        Ok(0) => Next::End,
        Ok(_) if line.last() == Some(&b'\n') => serde_json::from_slice(&line)
            .map(Next::Line)
            .unwrap_or(Next::Invalid),
        Ok(_) if line.len() as u64 == MAX_LINE_BYTES => Next::Invalid,
        Ok(_) => Next::End,
        Err(_) => Next::End,
    }
}

/// The feed position in the plane's cursor; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cursor {
    /// The end of the last transaction the plane holds whole.
    lsn: u64,
    /// The transaction after it that the plane holds in part: its commit
    /// position and the index of its first change the plane lacks.
    within: Option<(u64, u32)>,
}

impl Cursor {
    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.strip_prefix("pg1/")?.split('/');
        let lsn = parts.next()?.parse().ok().filter(|lsn| *lsn > 0)?;
        let within = match (parts.next(), parts.next(), parts.next()) {
            (None, _, _) => None,
            (Some(commit), Some(index), None) => Some((commit.parse().ok()?, index.parse().ok()?)),
            _ => return None,
        };
        // A transaction the plane holds in part commits after `lsn`.
        within
            .is_none_or(|(commit, _)| commit >= lsn)
            .then_some(Self { lsn, within })
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "pg1/{}", self.lsn)?;
        if let Some((commit, index)) = self.within {
            write!(formatter, "/{commit}/{index}")?;
        }
        Ok(())
    }
}

/// One change page as read.
#[derive(Debug, PartialEq)]
struct Page {
    records: Vec<SourceRecord>,
    next: Cursor,
    caught_up: bool,
}

/// The snapshot position in the plane's cursor: `pg1s/<P>/<last key>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotCursor {
    /// The slot position the snapshot reads after.
    lsn: u64,
    /// The `external_id` of the last row the plane holds.
    key: String,
    /// That key's values, in column-name order.
    after: Vec<String>,
}

impl SnapshotCursor {
    const PREFIX: &str = "pg1s/";

    fn parse(text: &str) -> Option<Self> {
        let (lsn, key) = text.strip_prefix(Self::PREFIX)?.split_once('/')?;
        let lsn = lsn.parse().ok().filter(|lsn| *lsn > 0)?;
        let after = key
            .split('~')
            .map(|part| percent_decode(part).filter(|value| !value.is_empty()))
            .collect::<Option<Vec<_>>>()?;
        // Only the encoding this type writes, so one key has one cursor.
        let canonical = after
            .iter()
            .map(|value| percent_encode(value))
            .collect::<Vec<_>>();
        (canonical.join("~") == key).then(|| Self {
            lsn,
            key: key.to_owned(),
            after,
        })
    }

    /// The cursor after the row whose `external_id` is `key`.
    fn text(lsn: u64, key: &str) -> String {
        format!("{}{lsn}/{key}", Self::PREFIX)
    }
}

/// What one snapshot run read.
#[derive(Debug, PartialEq)]
enum Snapshot {
    /// A first snapshot found no slot the plane records.
    Missing,
    Page(SnapshotPage),
}

/// One snapshot page as read.
#[derive(Debug, PartialEq)]
struct SnapshotPage {
    lsn: u64,
    records: Vec<SourceRecord>,
    complete: bool,
}

/// What one snapshot page reads after the plane's cursor.
struct SnapshotReading<'a> {
    from: Option<&'a SnapshotCursor>,
    max_records: usize,
    kind: Kind<'a>,
    retained: Retained,
}

impl SnapshotReading<'_> {
    /// Reads the child's lines into one page: the position, then rows in
    /// key order, or the starting key gone, then the page's end; or that
    /// the slot is missing and unrecorded.
    fn read(&self, out: &mut dyn BufRead) -> Outcome<Snapshot> {
        let mut page: Option<SnapshotPage> = None;
        loop {
            let line = match next_line(out) {
                Next::Line(line) => line,
                Next::End => return Outcome::Ended(None),
                Next::Invalid => return Outcome::Invalid,
            };
            match (line, page.as_mut()) {
                (Line::SlotCreated {}, None) => {}
                (Line::SlotMissing {}, None) if self.from.is_none() => {
                    return Outcome::Done(Snapshot::Missing);
                }
                (Line::RetainedLog { bytes, wal_status }, None) => {
                    if let Ok(mut retained) = self.retained.lock() {
                        *retained = Some((bytes, wal_status));
                    }
                }
                (Line::SnapshotAt { lsn }, None)
                    if lsn > 0 && self.from.is_none_or(|from| from.lsn == lsn) =>
                {
                    page = Some(SnapshotPage {
                        lsn,
                        records: Vec::new(),
                        complete: false,
                    });
                }
                (Line::Row { key, row }, Some(page)) if page.records.len() < self.max_records => {
                    let version = page.lsn.to_string();
                    let Some(mut records) = self.kind.records(Op::Insert, &key, &row, &version)
                    else {
                        return Outcome::Invalid;
                    };
                    page.records.append(&mut records);
                }
                // Only the key the page started after can be gone, alone.
                (Line::Gone { key }, Some(page)) if page.records.is_empty() => {
                    let id =
                        external_id(key.iter().map(|(column, value)| (column, value.as_deref())));
                    match (id, self.from) {
                        (Some(id), Some(from)) if id == from.key => {
                            let version = page.lsn.to_string();
                            page.records.push(self.kind.record(
                                id,
                                &version,
                                BTreeMap::new(),
                                true,
                            ));
                        }
                        _ => return Outcome::Invalid,
                    }
                }
                (Line::SnapshotEnd { complete }, Some(page)) if !page.records.is_empty() => {
                    page.complete = complete;
                    break;
                }
                (other, _) => return other.outcome(),
            }
        }
        page.map_or(Outcome::Invalid, |page| Outcome::Done(Snapshot::Page(page)))
    }
}

/// How one change becomes records of the Source's kind.
struct Kind<'a> {
    record_kind: &'a str,
    now_ms: i64,
}

/// What one change page reads after the plane's state.
struct Reading<'a> {
    from: Cursor,
    offset: u64,
    max_records: usize,
    kind: Kind<'a>,
    retained: Retained,
}

impl Reading<'_> {
    /// Reads the child's lines into one page: whole transactions while
    /// they fit, then the changes of the next one that fit.
    fn read(&self, out: &mut dyn BufRead) -> Outcome<Page> {
        let mut page = Page {
            records: Vec::new(),
            next: Cursor {
                lsn: self.from.lsn,
                within: None,
            },
            caught_up: false,
        };
        // The one table's name, from its first change.
        let mut table: Option<String> = None;
        // Whether the first transaction read has been checked against the
        // one the cursor holds in part.
        let mut first = true;
        loop {
            let line = match next_line(out) {
                Next::Line(line) => line,
                // The child stops on its own after `max_commits`.
                Next::End => return Outcome::Ended(Some(page)),
                Next::Invalid => return Outcome::Invalid,
            };
            match line {
                Line::Change {
                    commit_lsn,
                    index,
                    relation,
                    op,
                    key,
                    row,
                    unchanged,
                } => {
                    if first {
                        first = false;
                        if self
                            .from
                            .within
                            .is_some_and(|(commit, _)| commit != commit_lsn)
                        {
                            return Outcome::Invalid;
                        }
                    }
                    if self
                        .from
                        .within
                        .is_some_and(|(commit, next)| commit == commit_lsn && index < next)
                    {
                        continue;
                    }
                    if table.get_or_insert_with(|| relation.clone()) != &relation
                        || !unchanged.is_empty()
                    {
                        return Outcome::Invalid;
                    }
                    let version = format!("{commit_lsn}.{index}");
                    let Some(records) = self.kind.records(op, &key, &row, &version) else {
                        return Outcome::Invalid;
                    };
                    if page.records.len() + records.len() > self.max_records {
                        if page.records.is_empty() {
                            return Outcome::Invalid;
                        }
                        page.next.within = Some((commit_lsn, index));
                        return Outcome::Done(page);
                    }
                    for mut record in records {
                        record.source_sequence = Some(self.offset + page.records.len() as u64 + 1);
                        page.records.push(record);
                    }
                }
                Line::Commit { end_lsn } => {
                    first = false;
                    page.next = Cursor {
                        lsn: end_lsn,
                        within: None,
                    };
                    if page.records.len() == self.max_records {
                        return Outcome::Done(page);
                    }
                }
                // The transaction the cursor is inside must come first.
                Line::CaughtUp {} if first && self.from.within.is_some() => {
                    return Outcome::Invalid;
                }
                Line::CaughtUp {} => {
                    page.caught_up = true;
                    return Outcome::Done(page);
                }
                Line::RetainedLog { bytes, wal_status } if first => {
                    if let Ok(mut retained) = self.retained.lock() {
                        *retained = Some((bytes, wal_status));
                    }
                }
                other => return other.outcome(),
            }
        }
    }
}

impl Kind<'_> {
    /// The records one change makes; `None` when it cannot be one.
    fn records(
        &self,
        op: Op,
        key: &BTreeMap<String, Option<String>>,
        row: &BTreeMap<String, Option<String>>,
        version: &str,
    ) -> Option<Vec<SourceRecord>> {
        let old = external_id(key.iter().map(|(column, value)| (column, value.as_deref())))?;
        if op == Op::Delete {
            return Some(vec![self.record(old, version, BTreeMap::new(), true)]);
        }
        let new = external_id(
            key.keys()
                .map(|column| (column, row.get(column).and_then(Option::as_deref))),
        )?;
        let properties = row
            .iter()
            .filter(|(column, _)| !column_name_suggests_sensitive(column))
            .filter_map(|(column, value)| {
                Some((column.clone(), PropertyValue::String(value.clone()?)))
            })
            .collect();
        let upsert = self.record(new.clone(), version, properties, false);
        Some(if new == old {
            vec![upsert]
        } else {
            vec![self.record(old, version, BTreeMap::new(), true), upsert]
        })
    }

    fn record(
        &self,
        external_id: String,
        version: &str,
        properties: BTreeMap<String, PropertyValue>,
        deleted: bool,
    ) -> SourceRecord {
        SourceRecord {
            source: String::new(),
            source_instance: String::new(),
            display_name: external_id.clone(),
            external_id,
            source_version: version.to_owned(),
            type_name: self.record_kind.to_owned(),
            payload_digest: digest_of(&properties),
            properties,
            deleted,
            observed_at_ms: self.now_ms,
            source_sequence: None,
            payload: None,
            object_key: None,
        }
    }
}

/// The key's values in column order, percent-encoded and joined by `~`;
/// `None` when there is no key or a value is null or empty.
fn external_id<'a>(
    key: impl ExactSizeIterator<Item = (&'a String, Option<&'a str>)>,
) -> Option<String> {
    if key.len() == 0 {
        return None;
    }
    key.map(|(_, value)| value.filter(|value| !value.is_empty()).map(percent_encode))
        .collect::<Option<Vec<_>>>()
        .map(|parts| parts.join("~"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const ITEMS: &str = "public.items";

    fn reading(from: &str, offset: u64, max_records: usize) -> Reading<'static> {
        Reading {
            from: Cursor::parse(from).unwrap(),
            offset,
            max_records,
            kind: KIND,
            retained: Mutex::default(),
        }
    }

    const KIND: Kind<'static> = Kind {
        record_kind: "Item",
        now_ms: 1,
    };

    fn change(commit: u64, index: u32, op: &str, id: &str, name: Option<&str>) -> String {
        serde_json::json!({
            "kind": "change", "commit_lsn": commit, "index": index, "relation": ITEMS,
            "op": op, "key": { "id": id },
            "row": if op == "delete" { serde_json::json!({}) } else { serde_json::json!({ "id": id, "name": name }) },
            "unchanged": [],
        })
        .to_string()
    }

    fn commit(commit: u64, end: u64) -> String {
        serde_json::json!({ "kind": "commit", "commit_lsn": commit, "end_lsn": end }).to_string()
    }

    const CAUGHT_UP: &str = r#"{"kind":"caught_up","wal_end":900}"#;

    fn read(reading: &Reading<'_>, lines: &[String]) -> Outcome<Page> {
        let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
        reading.read(&mut text.as_bytes())
    }

    fn ids(page: &Page) -> Vec<(String, Option<u64>, bool)> {
        page.records
            .iter()
            .map(|record| {
                (
                    record.external_id.clone(),
                    record.source_sequence,
                    record.deleted,
                )
            })
            .collect()
    }

    #[test]
    fn cursors_carry_the_last_whole_transaction_and_a_part_of_the_next() {
        for text in ["pg1/208", "pg1/208/300/2"] {
            assert_eq!(Cursor::parse(text).unwrap().to_string(), text);
        }
        for text in [
            "",
            "pg1/0",
            "pg1/x",
            "pg2/1",
            "pg1/208/300",
            "pg1/208/100/1",
            "pg1/1/2/3/4",
        ] {
            assert_eq!(Cursor::parse(text), None, "{text:?}");
        }
    }

    fn snapshot(from: Option<&str>, max_records: usize, lines: &[&str]) -> Outcome<SnapshotPage> {
        match snapshot_run(from, max_records, lines).0 {
            Outcome::Done(Snapshot::Page(page)) => Outcome::Done(page),
            Outcome::Done(Snapshot::Missing) => panic!("the slot is missing"),
            Outcome::Refused(reason) => Outcome::Refused(reason),
            Outcome::Unavailable => Outcome::Unavailable,
            Outcome::Ended(Some(Snapshot::Page(page))) => Outcome::Ended(Some(page)),
            Outcome::Ended(_) => Outcome::Ended(None),
            Outcome::Invalid => Outcome::Invalid,
        }
    }

    /// What one snapshot run reads, and the retained log it measured.
    fn snapshot_run(
        from: Option<&str>,
        max_records: usize,
        lines: &[&str],
    ) -> (Outcome<Snapshot>, Option<(i64, String)>) {
        let from = from.map(|text| SnapshotCursor::parse(text).unwrap());
        let reading = SnapshotReading {
            from: from.as_ref(),
            max_records,
            kind: KIND,
            retained: Mutex::default(),
        };
        let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
        let read = reading.read(&mut text.as_bytes());
        (read, reading.retained.into_inner().unwrap())
    }

    /// Only a new snapshot may find its slot missing; the retained log
    /// comes before the position.
    #[test]
    fn a_new_snapshot_reports_a_missing_slot_and_the_retained_log() {
        let missing = r#"{"kind":"slot_missing"}"#;
        assert_eq!(
            snapshot_run(None, 2, &[missing]).0,
            Outcome::Done(Snapshot::Missing)
        );
        assert_eq!(
            snapshot_run(Some("pg1s/208/a"), 2, &[missing]).0,
            Outcome::Invalid
        );
        let retained = r#"{"kind":"retained_log","bytes":4096,"wal_status":"extended"}"#;
        let at = r#"{"kind":"snapshot_at","lsn":208}"#;
        let done = r#"{"kind":"snapshot_end","complete":true}"#;
        let (read, measured) = snapshot_run(None, 2, &[retained, at, &row("1"), done]);
        assert!(matches!(read, Outcome::Done(Snapshot::Page(_))));
        assert_eq!(measured, Some((4096, "extended".into())));
    }

    fn row(id: &str) -> String {
        serde_json::json!({ "kind": "row", "key": { "id": id }, "row": { "id": id, "name": "a" } })
            .to_string()
    }

    #[test]
    fn snapshot_cursors_carry_the_position_and_the_last_key() {
        let cursor = SnapshotCursor::parse("pg1s/208/eu~a%2Fb").unwrap();
        assert_eq!(cursor.lsn, 208);
        assert_eq!(cursor.after, ["eu", "a/b"]);
        for text in [
            "pg1s/208",
            "pg1s/0/1",
            "pg1s/208/",
            "pg1s/208/a~",
            "pg1s/208/a/b",
            "pg1s/208/%zz",
            // A second spelling of one key.
            "pg1s/208/%61",
        ] {
            assert_eq!(SnapshotCursor::parse(text), None, "{text:?}");
        }
    }

    /// Rows after the cursor's key become upserts at the snapshot's
    /// position; the page ends where the child says, and the starting key
    /// can only come back alone, as itself or gone.
    #[test]
    fn snapshot_pages_read_rows_after_the_position_in_key_order() {
        let at = r#"{"kind":"snapshot_at","lsn":208}"#;
        let more = r#"{"kind":"snapshot_end","complete":false}"#;
        let done = r#"{"kind":"snapshot_end","complete":true}"#;
        let created = r#"{"kind":"slot_created","consistent_lsn":208}"#;
        let Outcome::Done(page) = snapshot(None, 2, &[created, at, &row("1"), &row("a/b"), more])
        else {
            panic!();
        };
        assert_eq!((page.lsn, page.complete), (208, false));
        assert_eq!(
            page.records
                .iter()
                .map(|record| (record.external_id.as_str(), record.source_version.as_str()))
                .collect::<Vec<_>>(),
            [("1", "208"), ("a%2Fb", "208")]
        );
        assert!(
            page.records
                .iter()
                .all(|record| record.source_sequence.is_none())
        );

        let gone = r#"{"kind":"gone","key":{"id":"a/b"}}"#;
        let Outcome::Done(page) = snapshot(Some("pg1s/208/a%2Fb"), 2, &[at, gone, done]) else {
            panic!();
        };
        assert!(page.complete && page.records[0].deleted);

        let (r1, r2, r3, rc) = (row("1"), row("2"), row("3"), row("c"));
        for (from, lines) in [
            // Another position than the cursor's, or none.
            (Some("pg1s/300/1"), vec![at, done]),
            (None, vec![&r1, done]),
            // More rows than the page holds, or none at all.
            (None, vec![at, &r1, &r2, &r3, done]),
            (None, vec![at, done]),
            // Gone is only the starting key, and only alone.
            (None, vec![at, gone, done]),
            (Some("pg1s/208/1"), vec![at, gone, done]),
            (Some("pg1s/208/a%2Fb"), vec![at, &rc, gone, done]),
        ] {
            assert_eq!(
                snapshot(from, 2, &lines),
                Outcome::Invalid,
                "{from:?} {lines:?}"
            );
        }
        // A child that stops before the page's end died.
        assert!(matches!(
            snapshot(None, 2, &[at, &row("1")]),
            Outcome::Ended(None)
        ));
    }

    #[test]
    fn whole_transactions_are_numbered_from_the_offset_until_caught_up() {
        let lines = [
            change(300, 0, "insert", "1", Some("a")),
            change(300, 1, "insert", "a/b", None),
            commit(300, 308),
            change(400, 0, "update", "1", Some("b")),
            change(400, 1, "delete", "a/b", None),
            commit(400, 408),
            CAUGHT_UP.to_owned(),
        ];
        let Outcome::Done(page) = read(&reading("pg1/208", 9, 10), &lines) else {
            panic!();
        };
        assert_eq!(
            ids(&page),
            [
                ("1".into(), Some(10), false),
                ("a%2Fb".into(), Some(11), false),
                ("1".into(), Some(12), false),
                ("a%2Fb".into(), Some(13), true),
            ]
        );
        assert!(page.caught_up);
        assert_eq!(page.next.to_string(), "pg1/408");
        let updated = &page.records[2];
        assert_eq!(updated.source_version, "400.0");
        assert_eq!(updated.type_name, "Item");
        assert_eq!(
            updated.properties.get("name"),
            Some(&PropertyValue::String("b".into()))
        );
        assert!(
            !page.records[1].properties.contains_key("name"),
            "a null is no property"
        );
    }

    /// A transaction larger than a page is delivered in parts: the cursor
    /// keeps the last whole end and where the next page goes on inside it.
    #[test]
    fn a_transaction_over_a_page_resumes_inside_it_without_repeats() {
        let big = [
            change(300, 0, "insert", "1", Some("a")),
            change(300, 1, "insert", "2", Some("a")),
            change(300, 2, "insert", "3", Some("a")),
            commit(300, 308),
            CAUGHT_UP.to_owned(),
        ];
        let Outcome::Done(first) = read(&reading("pg1/208", 0, 2), &big) else {
            panic!();
        };
        assert_eq!(first.records.len(), 2);
        assert!(!first.caught_up);
        assert_eq!(first.next.to_string(), "pg1/208/300/2");

        let Outcome::Done(rest) = read(&reading(&first.next.to_string(), 2, 2), &big) else {
            panic!();
        };
        assert_eq!(ids(&rest), [("3".into(), Some(3), false)]);
        assert_eq!(rest.next.to_string(), "pg1/308");

        // The stream must start with the transaction the cursor is inside.
        let other = [change(500, 0, "insert", "9", None), commit(500, 508)];
        assert_eq!(
            read(&reading("pg1/208/300/2", 2, 2), &other),
            Outcome::Invalid
        );
    }

    #[test]
    fn a_changed_key_is_a_tombstone_and_the_row_under_its_new_key() {
        let moved = serde_json::json!({
            "kind": "change", "commit_lsn": 300, "index": 0, "relation": ITEMS, "op": "update",
            "key": { "id": "1" }, "row": { "id": "2", "name": "a" }, "unchanged": [],
        })
        .to_string();
        let Outcome::Done(page) = read(
            &reading("pg1/208", 0, 10),
            &[moved, commit(300, 308), CAUGHT_UP.into()],
        ) else {
            panic!();
        };
        assert_eq!(
            ids(&page),
            [("1".into(), Some(1), true), ("2".into(), Some(2), false)]
        );
    }

    #[test]
    fn what_cannot_be_a_record_fails_closed() {
        let line = |change: serde_json::Value| vec![change.to_string(), commit(300, 308)];
        let base = serde_json::json!({
            "kind": "change", "commit_lsn": 300, "index": 0, "relation": ITEMS, "op": "update",
            "key": { "id": "1" }, "row": { "id": "1" }, "unchanged": [],
        });
        let with = |field: &str, value: serde_json::Value| {
            let mut change = base.clone();
            change[field] = value;
            line(change)
        };
        for lines in [
            with("unchanged", serde_json::json!(["blob"])),
            with("key", serde_json::json!({})),
            with("key", serde_json::json!({ "id": null })),
            with("key", serde_json::json!({ "id": "" })),
            vec![
                change(300, 0, "insert", "1", None),
                with("relation", serde_json::json!("public.other")).remove(0),
            ],
            vec![r#"{"kind":"truncate","commit_lsn":300,"index":0,"relations":[]}"#.into()],
            vec![r#"{"kind":"slot_created","consistent_lsn":1}"#.into()],
            vec!["not json".into()],
        ] {
            assert_eq!(
                read(&reading("pg1/208", 0, 10), &lines),
                Outcome::Invalid,
                "{lines:?}"
            );
        }
    }

    #[test]
    fn an_output_cut_short_is_complete_only_when_the_child_exits_cleanly() {
        let lines = [change(300, 0, "insert", "1", None), commit(300, 308)];
        let Outcome::Ended(Some(page)) = read(&reading("pg1/208", 0, 10), &lines) else {
            panic!();
        };
        assert_eq!(page.next.to_string(), "pg1/308");
        let ended = || read(&reading("pg1/208", 0, 10), &lines);
        assert!(matches!(ended().settle(Some(0)), Attempt::Done(_)));
        assert!(matches!(
            ended().settle(None),
            Attempt::Died(ConnectorFailure::Unavailable)
        ));
        assert!(matches!(
            ended().settle(Some(EXIT_UNAVAILABLE)),
            Attempt::Failed(ConnectorFailure::Unavailable)
        ));
    }

    #[test]
    fn named_refusals_map_onto_the_sources_health() {
        for (reason, failure, restart) in [
            ("auth_failed", ConnectorFailure::AuthFailed, false),
            (
                "replication_permission_missing",
                ConnectorFailure::PermissionMissing,
                false,
            ),
            ("tls_handshake_failed", ConnectorFailure::Invalid, false),
            ("slot_ahead", ConnectorFailure::Invalid, false),
            ("retention_lost", ConnectorFailure::Invalid, false),
            ("slot_in_use", ConnectorFailure::Unavailable, true),
            ("table_empty", ConnectorFailure::Unavailable, false),
            ("connection_closed", ConnectorFailure::Unreachable, true),
        ] {
            match refused::<()>(reason) {
                Attempt::Failed(found) if !restart => assert_eq!(found, failure, "{reason}"),
                Attempt::Died(found) if restart => assert_eq!(found, failure, "{reason}"),
                _ => panic!("{reason}"),
            }
        }
    }

    /// A stand-in child: it counts its runs in a file beside it, checks it
    /// got the start message, and behaves as `$1` asks.
    const STAND_IN: &str = r#"#!/bin/bash
here="$(dirname "$0")"
start="$(cat)"
case "$start" in *'"resume_lsn":208'*) ;; *) exit 9 ;; esac
case "$start" in *'"max_commits":10'*) ;; *) exit 9 ;; esac
runs=$(( $(cat "$here/runs" 2>/dev/null || echo 0) + 1 ))
echo "$runs" > "$here/runs"
echo '{"kind":"retained_log","bytes":4096,"wal_status":"extended"}'
case "$(cat "$here/mode")" in
  dies-once) [ "$runs" = 1 ] && kill -9 $$ ;;
  dies) kill -9 $$ ;;
  unavailable) echo '{"kind":"unavailable","reason":"landlock"}'; exit 3 ;;
  refused) echo '{"kind":"refused","reason":"auth_failed"}'; exit 4 ;;
esac
echo '{"kind":"change","commit_lsn":300,"index":0,"relation":"public.items","op":"insert","key":{"id":"1"},"row":{"id":"1"},"unchanged":[]}'
echo '{"kind":"commit","commit_lsn":300,"end_lsn":308}'
echo '{"kind":"caught_up","wal_end":308}'
"#;

    /// A stand-in snapshot child: it reports an unrecorded slot missing,
    /// and creates and reads a recorded one.
    const SNAPSHOT_STAND_IN: &str = r#"#!/bin/bash
here="$(dirname "$0")"
start="$(cat)"
runs=$(( $(cat "$here/runs" 2>/dev/null || echo 0) + 1 ))
echo "$runs" > "$here/runs"
case "$start" in
  *'"slot_recorded":false'*) echo '{"kind":"slot_missing"}'; exit 0 ;;
esac
echo '{"kind":"slot_created","consistent_lsn":208}'
echo '{"kind":"snapshot_at","lsn":208}'
echo '{"kind":"row","key":{"id":"1"},"row":{"id":"1"}}'
echo '{"kind":"snapshot_end","complete":true}'
"#;

    /// A plane view with `created_slots`, recording slots into it unless
    /// `refuse` is set, and keeping the notes it is given.
    #[derive(Default)]
    struct Plane {
        created_slots: Vec<String>,
        refuse: Option<PlaneViewError>,
        notes: Vec<SyncNote>,
    }

    impl PlaneView for Plane {
        fn record_versions(
            &mut self,
            _range: sekai_source_sdk::KeyRange<'_>,
            _limit: usize,
        ) -> Result<Vec<sekai_source_sdk::RecordVersion>, PlaneViewError> {
            Ok(Vec::new())
        }

        fn created_slots(&self) -> &[String] {
            &self.created_slots
        }

        fn record_created_slot(&mut self, slot: &str) -> Result<(), PlaneViewError> {
            if let Some(error) = self.refuse {
                return Err(error);
            }
            self.created_slots.push(slot.into());
            Ok(())
        }

        fn note(&mut self, note: SyncNote) {
            self.notes.push(note);
        }
    }

    fn retained_note() -> SyncNote {
        SyncNote::RetainedLog {
            slot: "s".into(),
            bytes: 4096,
            wal_status: WalStatus::Extended,
        }
    }

    /// The stand-in child as a Source's capture, dialing a listener whose
    /// connections queue in its backlog while it lives.
    fn stand_in(directory: &Path, mode: &str) -> (PostgresCapture, std::net::TcpListener) {
        stand_in_running(directory, mode, STAND_IN)
    }

    /// [`stand_in`] running `script` as the child.
    fn stand_in_running(
        directory: &Path,
        mode: &str,
        script: &str,
    ) -> (PostgresCapture, std::net::TcpListener) {
        let path = directory.join(capture::CAPTURE_CHILD_NAME);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(directory.join("mode"), mode).unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let capture = PostgresCapture {
            child: CaptureChild::at(path),
            endpoint: Destination::parse(&format!("127.0.0.1:{port}")).unwrap(),
            egress: EgressAllowlist::parse(&["127.0.0.1"]).unwrap(),
            password: Secret(format!("value-{}", std::process::id())),
            settings: Settings {
                server_name: "127.0.0.1".into(),
                user: "u".into(),
                database: "d".into(),
                ca_pem: None,
                slot: "s".into(),
                publication: "p".into(),
                resume_lsn: 0,
                max_commits: 0,
                snapshot_lsn: 0,
                snapshot_after: None,
                max_rows: 0,
                slot_recorded: false,
            },
            record_kind: "Item".into(),
        };
        (capture, listener)
    }

    fn runs(directory: &Path) -> String {
        std::fs::read_to_string(directory.join("runs"))
            .unwrap_or_default()
            .trim()
            .to_owned()
    }

    #[test]
    fn a_child_that_dies_is_restarted_and_one_that_keeps_dying_is_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let (mut capture, _listener) = stand_in(directory.path(), "dies-once");
        let mut plane = Plane::default();
        let page = capture
            .read_changes_with_plane("pg1/208", "e", 4, 10, &mut plane)
            .unwrap();
        // Each run measured it; the page reports the last once.
        assert_eq!(plane.notes, [retained_note()]);
        assert_eq!(runs(directory.path()), "2");
        assert_eq!(page.offset_start, 4);
        assert_eq!(page.records[0].source_sequence, Some(5));
        assert_eq!(page.proposed_next_cursor, "pg1/308");
        assert!(page.caught_up);

        let directory = tempfile::tempdir().unwrap();
        let (mut capture, _listener) = stand_in(directory.path(), "dies");
        assert_eq!(
            capture.read_changes_with_plane("pg1/208", "e", 4, 10, &mut Plane::default()),
            Err(ConnectorFailure::Unavailable)
        );
        assert_eq!(runs(directory.path()), (RESTARTS.len() + 1).to_string());
    }

    #[test]
    fn a_sandbox_that_cannot_apply_or_a_refusal_is_not_restarted() {
        for (mode, failure) in [
            ("unavailable", ConnectorFailure::Unavailable),
            ("refused", ConnectorFailure::AuthFailed),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let (mut capture, _listener) = stand_in(directory.path(), mode);
            let mut plane = Plane::default();
            assert_eq!(
                capture.read_changes_with_plane("pg1/208", "e", 0, 10, &mut plane),
                Err(failure)
            );
            assert_eq!(runs(directory.path()), "1", "{mode}");
            // A failed page still reports what it measured.
            assert_eq!(plane.notes, [retained_note()], "{mode}");
        }
    }

    /// A first snapshot creates only a slot the plane records: an
    /// unrecorded missing slot is recorded and the page runs again; a slot
    /// the plane cannot record is never created.
    #[test]
    fn a_first_snapshot_records_the_slot_before_the_child_creates_it() {
        let directory = tempfile::tempdir().unwrap();
        let (mut capture, _listener) = stand_in_running(directory.path(), "ok", SNAPSHOT_STAND_IN);
        let mut plane = Plane::default();
        let page = capture
            .read_snapshot_page_with_plane(None, 10, &mut plane)
            .unwrap();
        assert_eq!(plane.created_slots, ["s"]);
        assert_eq!(runs(directory.path()), "2");
        assert!(page.complete);
        assert_eq!(page.proposed_next_cursor, "pg1/208");

        // Already recorded: one run.
        let directory = tempfile::tempdir().unwrap();
        let (mut capture, _listener) = stand_in_running(directory.path(), "ok", SNAPSHOT_STAND_IN);
        capture
            .read_snapshot_page_with_plane(None, 10, &mut plane)
            .unwrap();
        assert_eq!(runs(directory.path()), "1");

        let directory = tempfile::tempdir().unwrap();
        let (mut capture, _listener) = stand_in_running(directory.path(), "ok", SNAPSHOT_STAND_IN);
        let mut lapsed = Plane {
            refuse: Some(PlaneViewError::FenceLost),
            ..Plane::default()
        };
        assert_eq!(
            capture.read_snapshot_page_with_plane(None, 10, &mut lapsed),
            Err(ConnectorFailure::Unavailable)
        );
        assert_eq!(runs(directory.path()), "1");
    }

    #[test]
    fn a_destination_outside_the_allowlist_starts_no_child() {
        let directory = tempfile::tempdir().unwrap();
        let (mut capture, _listener) = stand_in(directory.path(), "ok");
        capture.egress = EgressAllowlist::parse(&["127.0.0.2"]).unwrap();
        assert_eq!(capture.check(), Err(ConnectorFailure::Invalid));
        assert_eq!(runs(directory.path()), "");
    }
}
