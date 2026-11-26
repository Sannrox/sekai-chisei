//! The PostgreSQL capture family (ADR 0170): one replication session over
//! the socket the runtime already dialed.
//!
//! - [`connect`] asks the server for TLS, verifies its certificate against
//!   the system roots plus the operator's CA, and authenticates with
//!   SCRAM-SHA-256 only, so the credential never crosses in the clear or as
//!   a weak hash.
//! - [`check`] names what the database lacks for capture before any data is
//!   read: version 15 or newer (older servers stream empty transactions),
//!   logical write-ahead logging, a role with replication permission, and
//!   the Source's publication of exactly one table.
//! - [`changes`] reads one bounded page: it creates the Source's slot when
//!   it is missing and nothing is committed yet (`resume_lsn` 0), refuses a
//!   slot that is missing later or already confirmed past the committed
//!   position, streams from the position the plane committed, and
//!   writes [`Line`]s until it has `max_commits` transactions or the stream
//!   is idle outside a transaction. It confirms to the server only the
//!   position it started from, so the slot never releases log the plane has
//!   not committed.
//! - [`snapshot`] reads one page of the publication's table in key order,
//!   after the slot's position, which the feed replays from.
//!
//! Every refusal is a [`Refusal`] naming the reason; none carries a server
//! message, a value or the credential.
//!
//! The wire session follows an earlier replication client by the same
//! authors (Apache-2.0), rewritten for blocking I/O, native TLS and the
//! confirm-only-what-was-committed rule.

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;
use native_tls::{Certificate, Protocol, TlsConnector, TlsStream};
use postgres_protocol::authentication::sasl::{self, ChannelBinding, ScramSha256};
use postgres_protocol::message::frontend;
use serde::Deserialize;

use crate::output::Line;
use crate::replication::{Change, Decoder, Frame, MAX_MESSAGE_BYTES};

/// How long a setup step (TLS, authentication, a query) may wait for the
/// server.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the stream may be silent outside a transaction before a page
/// counts as caught up.
pub const IDLE: Duration = Duration::from_secs(2);

/// The oldest server (`server_version_num`) captured from. Older servers
/// stream empty transactions, which would stall a feed whose position
/// moves only with a record.
const MIN_SERVER_VERSION: u32 = 150_000;

/// The longest slot or publication name the server accepts.
const MAX_NAME_BYTES: usize = 63;

/// Microseconds from the Unix epoch to the server's epoch, 2000-01-01.
const POSTGRES_EPOCH_MICROS: u64 = 946_684_800_000_000;

/// The PostgreSQL part of the start message.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The name the server's certificate must carry.
    pub server_name: String,
    pub user: String,
    pub database: String,
    /// The operator's CA (PEM), trusted beside the system roots.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// The Source's replication slot; lowercase letters, digits and `_`.
    pub slot: String,
    /// The Source's publication; lowercase letters, digits and `_`.
    pub publication: String,
    /// `changes`: the commit end the plane last committed; 0 before any.
    #[serde(default)]
    pub resume_lsn: u64,
    /// `changes`: the most transactions one page carries.
    #[serde(default)]
    pub max_commits: u32,
    /// `snapshot`: the slot position the snapshot reads after; 0 starts a
    /// new snapshot at the slot's confirmed position.
    #[serde(default)]
    pub snapshot_lsn: u64,
    /// `snapshot`: the key of the last row the plane holds, its values in
    /// column-name order; `None` on the first page.
    #[serde(default)]
    pub snapshot_after: Option<Vec<String>>,
    /// `snapshot`: the most rows one page carries.
    #[serde(default)]
    pub max_rows: u32,
    /// Whether the plane records the slot as one the runtime may create
    /// (#3083). Only a recorded slot is created; an unrecorded one that
    /// exists when a new snapshot starts is refused.
    #[serde(default)]
    pub slot_recorded: bool,
}

/// Why the session stopped, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal(pub &'static str);

impl From<crate::replication::DecodeError> for Refusal {
    fn from(error: crate::replication::DecodeError) -> Self {
        Self(error.reason())
    }
}

/// One authenticated replication session.
pub struct Session {
    stream: TlsStream<TcpStream>,
    buf: BytesMut,
}

/// A server error, kept to its SQLSTATE.
struct ServerError(String);

/// The rows of a simple query, each column as text or `None` for a null.
type Rows = Vec<Vec<Option<String>>>;

/// What the session read: a message tag and its payload, or silence.
enum Incoming {
    Message(u8, Vec<u8>),
    Idle,
}

/// Opens a session on `socket`, already connected to the Source's
/// database by the runtime.
pub fn connect(socket: TcpStream, settings: &Settings, password: &str) -> Result<Session, Refusal> {
    names_are_plain(settings)?;
    socket
        .set_read_timeout(Some(SETUP_TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(SETUP_TIMEOUT)))
        .map_err(|_| Refusal("connection_closed"))?;
    let mut socket = socket;
    let mut request = BytesMut::new();
    frontend::ssl_request(&mut request);
    socket
        .write_all(&request)
        .map_err(|_| Refusal("connection_closed"))?;
    let mut reply = [0u8; 1];
    socket
        .read_exact(&mut reply)
        .map_err(|_| Refusal("connection_closed"))?;
    if reply[0] != b'S' {
        return Err(Refusal("tls_refused"));
    }
    let mut builder = TlsConnector::builder();
    builder.min_protocol_version(Some(Protocol::Tlsv12));
    if let Some(pem) = &settings.ca_pem {
        let ca = Certificate::from_pem(pem.as_bytes()).map_err(|_| Refusal("invalid_ca"))?;
        builder.add_root_certificate(ca);
    }
    let connector = builder.build().map_err(|_| Refusal("tls_unavailable"))?;
    let stream = connector
        .connect(&settings.server_name, socket)
        .map_err(|_| Refusal("tls_handshake_failed"))?;
    let mut session = Session {
        stream,
        buf: BytesMut::new(),
    };
    session.startup(settings)?;
    session.authenticate(password)?;
    session.ready()?;
    Ok(session)
}

/// Refuses a database that cannot capture, naming what it lacks. A role
/// without REPLICATION never gets here: `connect` is refused at startup.
pub fn check(session: &mut Session, settings: &Settings) -> Result<(), Refusal> {
    let version = session.single("SHOW server_version_num")?;
    if !version
        .and_then(|version| version.parse::<u32>().ok())
        .is_some_and(|version| version >= MIN_SERVER_VERSION)
    {
        return Err(Refusal("server_version_unsupported"));
    }
    let level = session.single("SHOW wal_level")?;
    if level.as_deref() != Some("logical") {
        return Err(Refusal("wal_level_not_logical"));
    }
    let publication = session.query(&format!(
        "SELECT 1 FROM pg_catalog.pg_publication WHERE pubname = '{}'",
        settings.publication
    ))?;
    if publication.is_empty() {
        return Err(Refusal("publication_missing"));
    }
    // A Source is one record kind, so its publication carries one table.
    let tables = session.single(&format!(
        "SELECT count(*) FROM pg_catalog.pg_publication_tables WHERE pubname = '{}'",
        settings.publication
    ))?;
    if tables.as_deref() != Some("1") {
        return Err(Refusal("publication_not_one_table"));
    }
    Ok(())
}

/// Reads one page of changes after `settings.resume_lsn` into `out`.
pub fn changes(
    session: &mut Session,
    settings: &Settings,
    out: &mut impl Write,
) -> Result<(), Refusal> {
    if settings.max_commits == 0 {
        return Err(Refusal("invalid_config"));
    }
    check(session, settings)?;
    let start = settings.resume_lsn;
    match session.slot(settings)? {
        // Nothing committed yet: the stream starts where the new slot does.
        None if start == 0 && settings.slot_recorded => {
            let consistent_lsn = session.create_slot(settings)?;
            emit(out, &Line::SlotCreated { consistent_lsn })?;
        }
        // A slot that vanished, or one confirmed past the committed
        // position, would skip changes the plane never received.
        None => return Err(Refusal("slot_missing")),
        Some(confirmed) if start != 0 && confirmed > start => {
            return Err(Refusal("slot_ahead"));
        }
        Some(_) => {}
    }
    retained_log(session, settings, out)?;
    session.start_replication(settings, start)?;
    session.status(start)?;
    session.stream_timeout(Some(IDLE))?;
    let mut decoder = Decoder::resuming_after(start);
    let mut in_transaction = false;
    let mut commits = 0u32;
    let mut wal_end = start;
    loop {
        let payload = match session.read()? {
            Incoming::Idle if !in_transaction => {
                emit(out, &Line::CaughtUp { wal_end })?;
                return Ok(());
            }
            Incoming::Idle => continue,
            Incoming::Message(b'd', payload) => payload,
            Incoming::Message(b'E', payload) => return Err(stream_error(&payload)),
            Incoming::Message(b'N', _) => continue,
            Incoming::Message(_, _) => return Err(Refusal("stream_failed")),
        };
        match Frame::parse(&payload)? {
            Frame::Keepalive {
                wal_end: server_end,
                reply_requested,
            } => {
                wal_end = wal_end.max(server_end);
                if reply_requested {
                    session.status(start)?;
                }
            }
            Frame::Log {
                wal_end: server_end,
                data,
                ..
            } => {
                wal_end = wal_end.max(server_end);
                if data.first() == Some(&b'B') {
                    in_transaction = true;
                }
                let Some(change) = decoder.decode(data)? else {
                    continue;
                };
                let committed = matches!(change, Change::Commit { .. });
                emit(out, &Line::from(change))?;
                if committed {
                    in_transaction = false;
                    commits += 1;
                    if commits == settings.max_commits {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Reads one snapshot page into `out` (ADR 0170, option B of #3083): the
/// rows after `settings.snapshot_after` in key order, read after the slot's
/// position, which the feed then replays from.
///
/// A new snapshot (`snapshot_lsn` 0) makes sure the slot exists and reads
/// after its confirmed position; a later page refuses a slot that is gone
/// or confirmed past the snapshot's position. A new snapshot creates only
/// a slot the plane records (`slot_recorded`): a missing unrecorded slot
/// ends the page with `slot_missing`, for the runtime to record and run
/// again, and an existing unrecorded one is refused as
/// `slot_ahead_of_snapshot`, since changes before it were never read. Each page is its own
/// read-only transaction, so no session outlives a page. The rows are
/// whatever the table holds when the page reads them, possibly changed
/// after the position: every row is a keyed upsert, and the feed replays
/// every change after the position, so the plane ends in the source's
/// state. An empty table is refused as `table_empty`. When no row follows
/// the starting key, the page carries that key's row again, or `gone` when
/// it was deleted, so no page is empty.
pub fn snapshot(
    session: &mut Session,
    settings: &Settings,
    out: &mut impl Write,
) -> Result<(), Refusal> {
    if settings.max_rows == 0 {
        return Err(Refusal("invalid_config"));
    }
    check(session, settings)?;
    let lsn = match (session.slot(settings)?, settings.snapshot_lsn) {
        (None, 0) if !settings.slot_recorded => return emit(out, &Line::SlotMissing),
        (None, 0) => {
            let consistent_lsn = session.create_slot(settings)?;
            emit(out, &Line::SlotCreated { consistent_lsn })?;
            consistent_lsn
        }
        (Some(_), 0) if !settings.slot_recorded => {
            return Err(Refusal("slot_ahead_of_snapshot"));
        }
        (Some(confirmed), 0) => confirmed,
        (None, _) => return Err(Refusal("slot_missing")),
        (Some(confirmed), at) if confirmed > at => return Err(Refusal("slot_ahead")),
        (Some(_), at) => at,
    };
    retained_log(session, settings, out)?;
    emit(out, &Line::SnapshotAt { lsn })?;
    let table = session.published_table(settings)?;
    let after = settings
        .snapshot_after
        .as_ref()
        .map(|values| table.key_in_index_order(values))
        .transpose()?;
    session.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")?;
    let limit = u64::from(settings.max_rows) + 1;
    let mut rows = session.query(&table.select(after.as_deref(), ">", Some(limit)))?;
    let complete = rows.len() as u64 <= u64::from(settings.max_rows);
    rows.truncate(settings.max_rows as usize);
    let again = match (&after, rows.is_empty()) {
        (None, true) => return Err(Refusal("table_empty")),
        (Some(after), true) => Some(session.query(&table.select(Some(after), "=", None))?),
        _ => None,
    };
    session.query("COMMIT")?;
    match again {
        Some(found) if found.is_empty() => emit(
            out,
            &Line::Gone {
                key: table.key_of(after.as_deref().unwrap_or_default()),
            },
        )?,
        Some(found) => rows = found,
        None => {}
    }
    for values in rows {
        let (key, row) = table.row(values)?;
        emit(out, &Line::Row { key, row })?;
    }
    emit(out, &Line::SnapshotEnd { complete })
}

/// Writes how much log the server keeps for the slot, from its restart
/// position to the current position, with its `wal_status`. The measure
/// is an extra: a server that cannot answer, such as a standby, or a slot
/// that reserves nothing yet, writes no line and reads on.
fn retained_log(
    session: &mut Session,
    settings: &Settings,
    out: &mut impl Write,
) -> Result<(), Refusal> {
    let rows = session.try_query(&format!(
        "SELECT (pg_catalog.pg_current_wal_lsn() - restart_lsn)::bigint, wal_status \
         FROM pg_catalog.pg_replication_slots WHERE slot_name = '{}'",
        settings.slot
    ))?;
    let Ok(rows) = rows else {
        return Ok(());
    };
    match rows.first().map(Vec::as_slice) {
        Some([Some(bytes), Some(wal_status)]) => {
            let bytes = bytes.parse().map_err(|_| Refusal("protocol_violation"))?;
            emit(
                out,
                &Line::RetainedLog {
                    bytes,
                    wal_status: wal_status.clone(),
                },
            )
        }
        _ => Ok(()),
    }
}

/// The one table of the Source's publication, as a snapshot reads it.
#[derive(Debug, PartialEq)]
struct Table {
    /// The relation to read, quoted: `ONLY "schema"."table"`, since an
    /// inheritance child is not published with its parent, or a
    /// partitioned table itself, whose partitions the publication streams
    /// as the root.
    name: String,
    /// The published columns, in table order.
    columns: Vec<String>,
    /// The replica-identity columns, in index order.
    key: Vec<String>,
}

impl Table {
    /// `SELECT` the published columns of the rows whose key compares `op`
    /// to `key` (all rows without one), in key order.
    fn select(&self, key: Option<&[String]>, op: &str, limit: Option<u64>) -> String {
        let list = |names: &[String]| names.iter().map(|n| identifier(n)).collect::<Vec<_>>();
        let mut sql = format!(
            "SELECT {} FROM {}",
            list(&self.columns).join(", "),
            self.name
        );
        if let Some(key) = key {
            let values: Vec<String> = key.iter().map(|value| literal(value)).collect();
            sql += &format!(
                " WHERE ROW({}) {op} ROW({})",
                list(&self.key).join(", "),
                values.join(", ")
            );
        }
        sql += &format!(" ORDER BY {}", list(&self.key).join(", "));
        if let Some(limit) = limit {
            sql += &format!(" LIMIT {limit}");
        }
        sql
    }

    /// Key values given in column-name order, reordered to index order.
    fn key_in_index_order(&self, by_name: &[String]) -> Result<Vec<String>, Refusal> {
        let mut names = self.key.clone();
        names.sort();
        if by_name.len() != names.len() {
            return Err(Refusal("invalid_config"));
        }
        Ok(self
            .key
            .iter()
            .filter_map(|column| {
                names
                    .iter()
                    .position(|name| name == column)
                    .map(|at| by_name[at].clone())
            })
            .collect())
    }

    /// The key columns mapped to `values`, given in index order.
    fn key_of(&self, values: &[String]) -> BTreeMap<String, Option<String>> {
        self.key
            .iter()
            .cloned()
            .zip(values.iter().cloned().map(Some))
            .collect()
    }

    /// One selected row as its key and its published columns.
    fn row(&self, values: Vec<Option<String>>) -> Result<(Key, Key), Refusal> {
        if values.len() != self.columns.len() {
            return Err(Refusal("protocol_violation"));
        }
        let row: Key = self.columns.iter().cloned().zip(values).collect();
        let key = self
            .key
            .iter()
            .map(|column| (column.clone(), row.get(column).cloned().flatten()))
            .collect();
        Ok((key, row))
    }
}

/// Column name to text value, `None` for a null.
type Key = BTreeMap<String, Option<String>>;

/// A name from the server's catalog as a quoted identifier.
fn identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// A value as an escape-string literal, whatever
/// `standard_conforming_strings` says; untyped, so it takes its column's
/// type.
fn literal(value: &str) -> String {
    format!("E'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

impl Session {
    /// The publication's one table, its published columns and its
    /// replica-identity key: the index's key columns, without a covering
    /// index's `INCLUDE` columns, which the feed does not send. A row filter, or a replica identity that is
    /// not a key (`full`, `nothing`), cannot be snapshot as the feed
    /// streams it.
    fn published_table(&mut self, settings: &Settings) -> Result<Table, Refusal> {
        let publication = literal(&settings.publication);
        let found = self.query(&format!(
            "SELECT p.schemaname, p.tablename, p.rowfilter IS NULL, c.relreplident, \
               c.relkind = 'p' \
             FROM pg_catalog.pg_publication_tables p \
             JOIN pg_catalog.pg_namespace n ON n.nspname = p.schemaname \
             JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = p.tablename \
             WHERE p.pubname = {publication}"
        ))?;
        let [row] = found.as_slice() else {
            return Err(Refusal("publication_not_one_table"));
        };
        let (schema, table, partitioned) = match row.as_slice() {
            [
                Some(schema),
                Some(table),
                Some(unfiltered),
                Some(identity),
                Some(partitioned),
            ] if unfiltered == "t" && matches!(identity.as_str(), "d" | "i") => {
                (schema.clone(), table.clone(), partitioned == "t")
            }
            [_, _, Some(unfiltered), _, _] if unfiltered != "t" => {
                return Err(Refusal("publication_row_filter_unsupported"));
            }
            _ => return Err(Refusal("replica_identity_unsupported")),
        };
        let columns = self.names(&format!(
            "SELECT a FROM pg_catalog.pg_publication_tables p, unnest(p.attnames) AS a \
             WHERE p.pubname = {publication}"
        ))?;
        let key = self.names(&format!(
            "SELECT a.attname FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             JOIN pg_catalog.pg_index i ON i.indrelid = c.oid AND CASE c.relreplident \
               WHEN 'd' THEN i.indisprimary WHEN 'i' THEN i.indisreplident ELSE false END \
             JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey) \
             CROSS JOIN LATERAL (SELECT array_position(i.indkey::int2[], a.attnum) \
               - array_lower(i.indkey::int2[], 1) AS position) k \
             WHERE n.nspname = {} AND c.relname = {} AND k.position < i.indnkeyatts \
             ORDER BY k.position",
            literal(&schema),
            literal(&table)
        ))?;
        if key.is_empty() || !key.iter().all(|column| columns.contains(column)) {
            return Err(Refusal("replica_identity_unsupported"));
        }
        Ok(Table {
            name: format!(
                "{}{}.{}",
                if partitioned { "" } else { "ONLY " },
                identifier(&schema),
                identifier(&table)
            ),
            columns,
            key,
        })
    }

    /// The first column of every row `sql` returns.
    fn names(&mut self, sql: &str) -> Result<Vec<String>, Refusal> {
        self.query(sql)?
            .into_iter()
            .map(|row| row.into_iter().next().flatten())
            .collect::<Option<_>>()
            .ok_or(Refusal("protocol_violation"))
    }

    fn startup(&mut self, settings: &Settings) -> Result<(), Refusal> {
        let mut buf = BytesMut::new();
        frontend::startup_message(
            [
                ("user", settings.user.as_str()),
                ("database", settings.database.as_str()),
                ("replication", "database"),
                ("client_encoding", "UTF8"),
                ("application_name", "sekai-change-capture"),
            ],
            &mut buf,
        )
        .map_err(|_| Refusal("invalid_config"))?;
        self.write(&buf)
    }

    /// SCRAM-SHA-256 only, with the server's signature verified; any other
    /// method is refused before the password is sent.
    fn authenticate(&mut self, password: &str) -> Result<(), Refusal> {
        let payload = self.expect(b'R')?;
        match auth_kind(&payload)? {
            0 => return Ok(()),
            10 => {}
            _ => return Err(Refusal("auth_method_unsupported")),
        }
        if !mechanisms(&payload[4..]).any(|name| name == sasl::SCRAM_SHA_256.as_bytes()) {
            return Err(Refusal("auth_method_unsupported"));
        }
        let mut scram = ScramSha256::new(password.as_bytes(), ChannelBinding::unsupported());
        let mut buf = BytesMut::new();
        frontend::sasl_initial_response(sasl::SCRAM_SHA_256, scram.message(), &mut buf)
            .map_err(|_| Refusal("auth_failed"))?;
        self.write(&buf)?;
        let challenge = self.expect_auth(11)?;
        scram
            .update(&challenge)
            .map_err(|_| Refusal("auth_failed"))?;
        buf.clear();
        frontend::sasl_response(scram.message(), &mut buf).map_err(|_| Refusal("auth_failed"))?;
        self.write(&buf)?;
        let outcome = self.expect_auth(12)?;
        scram.finish(&outcome).map_err(|_| Refusal("auth_failed"))?;
        match auth_kind(&self.expect(b'R')?)? {
            0 => Ok(()),
            _ => Err(Refusal("auth_failed")),
        }
    }

    fn expect_auth(&mut self, kind: i32) -> Result<Vec<u8>, Refusal> {
        let payload = self.expect(b'R')?;
        if auth_kind(&payload)? != kind {
            return Err(Refusal("auth_failed"));
        }
        Ok(payload[4..].to_vec())
    }

    /// The next message, which must be `tag`; a server error is mapped to
    /// its refusal.
    fn expect(&mut self, tag: u8) -> Result<Vec<u8>, Refusal> {
        loop {
            match self.read()? {
                Incoming::Message(found, payload) if found == tag => return Ok(payload),
                Incoming::Message(b'N', _) => {}
                Incoming::Message(b'E', payload) => return Err(startup_error(&payload)),
                _ => return Err(Refusal("protocol_violation")),
            }
        }
    }

    fn ready(&mut self) -> Result<(), Refusal> {
        loop {
            match self.read()? {
                Incoming::Message(b'Z', _) => return Ok(()),
                Incoming::Message(b'S' | b'K' | b'N', _) => {}
                Incoming::Message(b'E', payload) => return Err(startup_error(&payload)),
                _ => return Err(Refusal("protocol_violation")),
            }
        }
    }

    /// Runs `sql` as a simple query and returns its rows, positionally.
    fn query(&mut self, sql: &str) -> Result<Rows, Refusal> {
        self.try_query(sql)?
            .map_err(|_: ServerError| Refusal("query_failed"))
    }

    /// The first column of the one row `sql` returns.
    fn single(&mut self, sql: &str) -> Result<Option<String>, Refusal> {
        Ok(self
            .query(sql)?
            .into_iter()
            .next()
            .and_then(|row| row.into_iter().next())
            .flatten())
    }

    /// Like [`Session::query`], keeping a server error for the caller.
    fn try_query(&mut self, sql: &str) -> Result<Result<Rows, ServerError>, Refusal> {
        let mut buf = BytesMut::new();
        frontend::query(sql, &mut buf).map_err(|_| Refusal("invalid_config"))?;
        self.write(&buf)?;
        let mut rows = Vec::new();
        let mut error = None;
        loop {
            match self.read()? {
                Incoming::Message(b'D', payload) => rows.push(data_row(&payload)?),
                Incoming::Message(b'E', payload) => error = Some(ServerError(sqlstate(&payload))),
                Incoming::Message(b'Z', _) => return Ok(error.map_or(Ok(rows), Err)),
                Incoming::Message(b'T' | b'C' | b'I' | b'N' | b'S', _) => {}
                _ => return Err(Refusal("protocol_violation")),
            }
        }
    }

    /// The position the Source's slot has confirmed, or `None` when it is
    /// missing. An existing slot must decode this database with the
    /// built-in plugin.
    fn slot(&mut self, settings: &Settings) -> Result<Option<u64>, Refusal> {
        let existing = self.query(&format!(
            "SELECT plugin, database = current_database(), confirmed_flush_lsn \
             FROM pg_catalog.pg_replication_slots WHERE slot_name = '{}'",
            settings.slot
        ))?;
        let Some(row) = existing.first() else {
            return Ok(None);
        };
        match row.as_slice() {
            [Some(plugin), Some(same), Some(confirmed)] if plugin == "pgoutput" && same == "t" => {
                parse_lsn(confirmed).map(Some)
            }
            _ => Err(Refusal("slot_mismatch")),
        }
    }

    /// Creates the Source's slot and returns the position it starts at.
    fn create_slot(&mut self, settings: &Settings) -> Result<u64, Refusal> {
        let created = self
            .try_query(&format!(
                "CREATE_REPLICATION_SLOT {} LOGICAL pgoutput NOEXPORT_SNAPSHOT",
                settings.slot
            ))?
            .map_err(|ServerError(state)| match state.as_str() {
                // Another runtime created it first; the next run uses it.
                "42710" => Refusal("slot_conflict"),
                _ => Refusal("slot_create_failed"),
            })?;
        let consistent = created
            .first()
            .and_then(|row| row.get(1))
            .cloned()
            .flatten()
            .ok_or(Refusal("protocol_violation"))?;
        parse_lsn(&consistent)
    }

    fn start_replication(&mut self, settings: &Settings, start: u64) -> Result<(), Refusal> {
        let mut buf = BytesMut::new();
        frontend::query(
            &format!(
                "START_REPLICATION SLOT {} LOGICAL {} (proto_version '1', publication_names '{}')",
                settings.slot,
                format_lsn(start),
                settings.publication
            ),
            &mut buf,
        )
        .map_err(|_| Refusal("invalid_config"))?;
        self.write(&buf)?;
        loop {
            match self.read()? {
                Incoming::Message(b'W', _) => return Ok(()),
                Incoming::Message(b'N', _) => {}
                Incoming::Message(b'E', payload) => return Err(stream_error(&payload)),
                _ => return Err(Refusal("protocol_violation")),
            }
        }
    }

    /// Confirms `lsn` as written, flushed and applied.
    fn status(&mut self, lsn: u64) -> Result<(), Refusal> {
        let mut buf = BytesMut::new();
        frontend::CopyData::new(standby_status(lsn, now_micros()).as_slice())
            .map_err(|_| Refusal("stream_failed"))?
            .write(&mut buf);
        self.write(&buf)
    }

    fn stream_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Refusal> {
        self.stream
            .get_ref()
            .set_read_timeout(timeout)
            .map_err(|_| Refusal("connection_closed"))
    }

    /// The next whole message, or [`Incoming::Idle`] when the read timed out.
    /// A partial message stays buffered across an idle read.
    fn read(&mut self) -> Result<Incoming, Refusal> {
        loop {
            if self.buf.len() >= 5 {
                let tag = self.buf[0];
                let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]])
                    as usize;
                // Checked from the header, before the body is buffered.
                if !(4..=MAX_MESSAGE_BYTES + 4).contains(&len) {
                    return Err(Refusal("oversize"));
                }
                if self.buf.len() > len {
                    let message = self.buf.split_to(1 + len);
                    return Ok(Incoming::Message(tag, message[5..].to_vec()));
                }
            }
            let mut chunk = [0u8; 16 * 1024];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(Refusal("connection_closed")),
                Ok(read) => self.buf.extend_from_slice(&chunk[..read]),
                Err(error) if is_timeout(&error) => return Ok(Incoming::Idle),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(_) => return Err(Refusal("connection_closed")),
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        self.stream
            .write_all(bytes)
            .and_then(|()| self.stream.flush())
            .map_err(|_| Refusal("connection_closed"))
    }
}

fn emit(out: &mut impl Write, line: &Line) -> Result<(), Refusal> {
    let text = line.encode()?;
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|_| Refusal("output_closed"))
}

/// Slot and publication names go into replication commands unquoted, so
/// only plain lowercase identifiers are accepted.
fn names_are_plain(settings: &Settings) -> Result<(), Refusal> {
    let plain = |name: &str| {
        !name.is_empty()
            && name.len() <= MAX_NAME_BYTES
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    };
    if plain(&settings.slot) && plain(&settings.publication) {
        Ok(())
    } else {
        Err(Refusal("invalid_config"))
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn auth_kind(payload: &[u8]) -> Result<i32, Refusal> {
    payload
        .get(..4)
        .map(|bytes| i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .ok_or(Refusal("protocol_violation"))
}

/// The mechanism names of a SASL request: NUL-terminated, ending empty.
fn mechanisms(payload: &[u8]) -> impl Iterator<Item = &[u8]> {
    payload
        .split(|byte| *byte == 0)
        .take_while(|name| !name.is_empty())
}

/// The SQLSTATE (`C` field) of an error response; empty when absent.
fn sqlstate(payload: &[u8]) -> String {
    let mut fields = payload.split(|byte| *byte == 0);
    fields
        .find_map(|field| field.strip_prefix(b"C"))
        .and_then(|code| std::str::from_utf8(code).ok())
        .unwrap_or_default()
        .to_owned()
}

/// A refused startup. A role without REPLICATION is refused here (42501),
/// before `check` can ask, since the session asks for a walsender.
fn startup_error(payload: &[u8]) -> Refusal {
    let code = sqlstate(payload);
    if code == "42501" {
        return Refusal("replication_permission_missing");
    }
    match code.get(..2) {
        Some("28") => Refusal("auth_failed"),
        Some("3D") => Refusal("database_missing"),
        _ => Refusal("startup_failed"),
    }
}

/// A refused or ended stream. An invalidated slot (55000) has lost log the
/// position needs: the ADR 0118 retention loss.
fn stream_error(payload: &[u8]) -> Refusal {
    match sqlstate(payload).as_str() {
        "55000" => Refusal("retention_lost"),
        "55006" => Refusal("slot_in_use"),
        "42704" => Refusal("slot_missing"),
        _ => Refusal("stream_failed"),
    }
}

/// The columns of one data row as text, `None` for a null.
fn data_row(payload: &[u8]) -> Result<Vec<Option<String>>, Refusal> {
    let malformed = Refusal("protocol_violation");
    let count = payload.get(..2).ok_or(malformed)?;
    let count = u16::from_be_bytes([count[0], count[1]]);
    let mut rest = &payload[2..];
    let mut row = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let len = rest.get(..4).ok_or(malformed)?;
        let len = i32::from_be_bytes([len[0], len[1], len[2], len[3]]);
        rest = &rest[4..];
        if len < 0 {
            row.push(None);
            continue;
        }
        let len = usize::try_from(len).map_err(|_| malformed)?;
        let value = rest.get(..len).ok_or(malformed)?;
        row.push(Some(
            std::str::from_utf8(value)
                .map_err(|_| Refusal("not_utf8"))?
                .to_owned(),
        ));
        rest = &rest[len..];
    }
    if rest.is_empty() {
        Ok(row)
    } else {
        Err(malformed)
    }
}

/// A standby status update confirming `lsn`, without asking for a reply.
fn standby_status(lsn: u64, clock_micros: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(34);
    message.push(b'r');
    for position in [lsn, lsn, lsn] {
        message.extend_from_slice(&position.to_be_bytes());
    }
    message.extend_from_slice(&clock_micros.to_be_bytes());
    message.push(0);
    message
}

/// The server clock: microseconds since 2000-01-01.
fn now_micros() -> i64 {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros());
    i64::try_from(unix.saturating_sub(u128::from(POSTGRES_EPOCH_MICROS))).unwrap_or(i64::MAX)
}

/// `X/Y`, the server's text form of a log position.
pub fn format_lsn(lsn: u64) -> String {
    format!("{:X}/{:X}", lsn >> 32, lsn & 0xFFFF_FFFF)
}

/// Parses `X/Y`.
pub fn parse_lsn(text: &str) -> Result<u64, Refusal> {
    let malformed = Refusal("protocol_violation");
    let (high, low) = text.split_once('/').ok_or(malformed)?;
    let high = u32::from_str_radix(high, 16).map_err(|_| malformed)?;
    let low = u32::from_str_radix(low, 16).map_err(|_| malformed)?;
    Ok(u64::from(high) << 32 | u64::from(low))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(slot: &str, publication: &str) -> Settings {
        Settings {
            server_name: "localhost".into(),
            user: "u".into(),
            database: "d".into(),
            ca_pem: None,
            slot: slot.into(),
            publication: publication.into(),
            resume_lsn: 0,
            max_commits: 1,
            snapshot_lsn: 0,
            snapshot_after: None,
            max_rows: 0,
            slot_recorded: false,
        }
    }

    fn table() -> Table {
        Table {
            name: r#"ONLY "public"."items""#.into(),
            columns: vec!["region".into(), "id".into(), "name".into()],
            key: vec!["region".into(), "id".into()],
        }
    }

    /// A key read back from the cursor cannot break out of its literal,
    /// whatever `standard_conforming_strings` says.
    #[test]
    fn a_snapshot_page_reads_after_the_key_in_index_order() {
        let table = table();
        let after = table
            .key_in_index_order(&["7".into(), r"eu'\".into()])
            .unwrap();
        assert_eq!(after, [r"eu'\", "7"]);
        assert_eq!(
            table.select(Some(&after), ">", Some(3)),
            r#"SELECT "region", "id", "name" FROM ONLY "public"."items" WHERE ROW("region", "id") > ROW(E'eu''\\', E'7') ORDER BY "region", "id" LIMIT 3"#
        );
        assert_eq!(
            table.select(None, ">", None),
            r#"SELECT "region", "id", "name" FROM ONLY "public"."items" ORDER BY "region", "id""#
        );
        assert_eq!(identifier(r#"a"b"#), r#""a""b""#);
        assert!(table.key_in_index_order(&["7".into()]).is_err());
    }

    #[test]
    fn slot_and_publication_names_must_be_plain_identifiers() {
        assert!(names_are_plain(&settings("orders_slot", "orders_2")).is_ok());
        for (slot, publication) in [
            ("", "p"),
            ("Orders", "p"),
            ("s", "p' (x"),
            ("s;DROP", "p"),
            (&"s".repeat(64), "p"),
        ] {
            assert_eq!(
                names_are_plain(&settings(slot, publication)),
                Err(Refusal("invalid_config")),
                "{slot:?} {publication:?}"
            );
        }
    }

    #[test]
    fn log_positions_round_trip_through_their_text_form() {
        for lsn in [0, 0x16_B374_D848, u64::MAX] {
            assert_eq!(parse_lsn(&format_lsn(lsn)), Ok(lsn));
        }
        assert_eq!(format_lsn(0x1_0000_00FF), "1/FF");
        for text in ["", "1", "1/", "G/0", "1/2/3", "100000000/0"] {
            assert!(parse_lsn(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn a_status_update_confirms_one_position_and_asks_for_no_reply() {
        let message = standby_status(0x0102_0304_0506_0708, 9);
        assert_eq!(message.len(), 34);
        assert_eq!(message[0], b'r');
        for field in message[1..25].chunks(8) {
            assert_eq!(field, 0x0102_0304_0506_0708u64.to_be_bytes());
        }
        assert_eq!(message[25..33], 9i64.to_be_bytes());
        assert_eq!(message[33], 0);
    }

    #[test]
    fn data_rows_are_text_or_null_and_never_trail() {
        let mut row = vec![0, 2];
        row.extend(2i32.to_be_bytes());
        row.extend(b"ok");
        row.extend((-1i32).to_be_bytes());
        assert_eq!(data_row(&row), Ok(vec![Some("ok".into()), None]));
        let mut trailing = row.clone();
        trailing.push(0);
        assert!(data_row(&trailing).is_err());
        assert!(data_row(&row[..row.len() - 1]).is_err());
        let mut not_utf8 = vec![0, 1];
        not_utf8.extend(1i32.to_be_bytes());
        not_utf8.push(0xFF);
        assert_eq!(data_row(&not_utf8), Err(Refusal("not_utf8")));
    }

    #[test]
    fn server_errors_map_to_named_refusals_without_their_message() {
        let error = |code: &str| {
            let mut payload = b"SERROR\0".to_vec();
            payload.extend(format!("C{code}\0").bytes());
            payload.extend(b"Msecret detail\0\0");
            payload
        };
        assert_eq!(startup_error(&error("28P01")), Refusal("auth_failed"));
        assert_eq!(startup_error(&error("3D000")), Refusal("database_missing"));
        assert_eq!(
            startup_error(&error("42501")),
            Refusal("replication_permission_missing")
        );
        assert_eq!(stream_error(&error("55000")), Refusal("retention_lost"));
        assert_eq!(stream_error(&error("55006")), Refusal("slot_in_use"));
        assert_eq!(stream_error(&error("XX000")), Refusal("stream_failed"));
        assert_eq!(sqlstate(b"Mno code\0\0"), "");
    }

    #[test]
    fn only_a_scram_sha_256_offer_is_accepted() {
        let offered = |payload: &[u8]| mechanisms(payload).any(|name| name == b"SCRAM-SHA-256");
        assert!(offered(b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0"));
        assert!(!offered(b"SCRAM-SHA-256-PLUS\0\0"));
        assert!(!offered(b"\0SCRAM-SHA-256\0"));
    }
}
