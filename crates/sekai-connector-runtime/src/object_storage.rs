//! The `object_storage` connector type: the rows of the objects under one
//! bucket prefix of an S3-compatible store, mirrored as snapshot pages
//! under the plane-owned cursor (ADR 0022, ADR 0148, ADR 0167).
//!
//! Each page walks the prefix listing and the Source's live records, read
//! from the plane, together in UTF-8 byte order of object key:
//!
//! - an object whose live records all carry its current ETag as their
//!   version is not fetched again;
//! - any other object is fetched and parsed; its rows that are new or at
//!   another version upsert at the new ETag, and its live records it no
//!   longer has are tombstoned;
//! - a key the plane holds that the listing no longer returns has all its
//!   live records tombstoned, before, between and after listed keys.
//!
//! The cursor is the walk's position: before the first key of a pass,
//! after a key whose records are all applied, or at a key whose records
//! did not fit one page. Resuming at a key needs no position inside it:
//! the records still to apply are exactly those whose live version is not
//! the object's ETag and the live ones it no longer has, and both only
//! shrink. A key resumed at is always fetched, since its applied rows
//! already carry the ETag that would otherwise skip it. A page that would
//! hold no record commits nothing, so the walk
//! goes on through unchanged objects until it finds a change or the
//! listing ends. A walk that started mid-pass and reached the end with
//! nothing to apply wraps into a new pass from the first key and stops at
//! the key it started from, so a change before the cursor is never
//! stranded behind a cursor that cannot move. A pass that reached the end
//! completes the sync; the next sync starts a new pass.
//!
//! Each row's record id is derived from its object key and its
//! `id_column` value ([`external_id`], rule `v1`), since a key may hold
//! characters an id may not; the key itself is the record's object key
//! and its `object_key` property.
//!
//! Parsing is bounded: an object larger than [`MAX_OBJECT_BYTES`] or with
//! more than [`MAX_OBJECT_ROWS`] rows, a row without a usable id, an id
//! twice in one object, or a key the plane cannot hold fails the page as
//! invalid instead of being cut short. Only `json` objects parse here; a
//! Source that asks for another format is refused.

use std::collections::BTreeMap;

use reqwest::Url;
use sekai_source_sdk::{
    ConfigValue, Connector, ConnectorFailure, Destination, KeyRange, MAX_SOURCE_BATCH_RECORDS,
    MAX_SOURCE_IDENTIFIER_BYTES, MAX_SOURCE_OBJECT_KEY_BYTES, MAX_SOURCE_PROPERTY_VALUE_BYTES,
    MAX_SOURCE_RECORD_PROPERTIES, PlaneView, PlaneViewError, PropertyValue, RecordVersion,
    SnapshotPage, SnapshotRead, SourceRecord, contains_secret_like_text,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::rest::{digest_of, display_line, now_ms, property_key, scalar};
use crate::sync::Prepared;

mod store;

pub use store::MAX_LISTING_BYTES;
use store::{Listed, Store};

/// The largest object the type parses.
pub const MAX_OBJECT_BYTES: u64 = 8 * 1024 * 1024;

/// The most rows one object may hold.
pub const MAX_OBJECT_ROWS: usize = 50_000;

/// The property each record carries its object key in.
pub const OBJECT_KEY_PROPERTY: &str = "object_key";

const CURSOR_PREFIX: &str = "object_storage-v1";

/// Keys one listing request asks for.
const LIST_PAGE_KEYS: usize = 1_000;

/// One prefix of one bucket, reached with the Source's bound key pair.
pub struct ObjectStorage {
    store: Store,
    prefix: String,
    record_kind: String,
    id_column: String,
    fields: Vec<String>,
    /// The secret key, only to refuse text that would carry it.
    secret: String,
}

/// Opens the type for a prepared Source; register it with
/// `Connectors::with(&OBJECT_STORAGE_CONNECTOR, object_storage::open)`.
pub fn open(prepared: &Prepared) -> Result<Box<dyn Connector + Send>, ConnectorFailure> {
    Ok(Box::new(open_object_storage(prepared)?))
}

fn open_object_storage(prepared: &Prepared) -> Result<ObjectStorage, ConnectorFailure> {
    let config = &prepared.config;
    let text = |name: &str| match config.get(name) {
        Some(ConfigValue::Text(text)) => Some(text.clone()),
        _ => None,
    };
    let required = |name: &str| text(name).ok_or(ConnectorFailure::Invalid);
    if text("format").is_some_and(|format| format != "json") {
        return Err(ConnectorFailure::Invalid);
    }
    let endpoint = Url::parse(&required("endpoint")?).map_err(|_| ConnectorFailure::Invalid)?;
    let host = endpoint
        .host_str()
        .map(str::to_ascii_lowercase)
        .ok_or(ConnectorFailure::Invalid)?;
    // TLS is required off loopback; the endpoint is an origin, not a path.
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback)
        || !matches!(endpoint.path(), "" | "/")
    {
        return Err(ConnectorFailure::Invalid);
    }
    let bucket = required("bucket")?;
    if bucket.is_empty()
        || !bucket
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
    {
        return Err(ConnectorFailure::Invalid);
    }
    let path_style = matches!(config.get("path_style"), Some(ConfigValue::Boolean(true)));
    let (origin, base_path) = if path_style {
        (endpoint, format!("/{bucket}"))
    } else {
        // The bucket's own host is a destination too.
        let bucket_host = format!("{bucket}.{host}");
        let destination = Destination {
            host: bucket_host.clone(),
            port: endpoint.port_or_known_default(),
        };
        if !prepared.egress.permits(&destination) {
            return Err(ConnectorFailure::Invalid);
        }
        let mut origin = endpoint;
        origin
            .set_host(Some(&bucket_host))
            .map_err(|_| ConnectorFailure::Invalid)?;
        (origin, String::new())
    };
    let id_column = required("id_column")?;
    if !property_key(&id_column.to_ascii_lowercase()) {
        return Err(ConnectorFailure::Invalid);
    }
    let fields: Vec<String> = text("fields")
        .iter()
        .flat_map(|fields| fields.split(','))
        .map(|field| field.trim().to_string())
        .filter(|field| !field.is_empty())
        .collect();
    // One property slot is the object key.
    if fields.len() >= MAX_SOURCE_RECORD_PROPERTIES
        || !fields
            .iter()
            .all(|field| property_key(field) && field != OBJECT_KEY_PROPERTY)
    {
        return Err(ConnectorFailure::Invalid);
    }
    let (access_key_id, secret) = prepared
        .credentials
        .get("access_key")
        .and_then(|pair| pair.expose().split_once(':'))
        .filter(|(id, secret)| !id.is_empty() && !secret.is_empty())
        .map(|(id, secret)| (id.to_string(), secret.to_string()))
        .ok_or(ConnectorFailure::AuthFailed)?;
    Ok(ObjectStorage {
        store: Store::new(
            origin,
            base_path,
            required("region")?,
            access_key_id,
            crate::credentials::Secret(secret.clone()),
        )?,
        prefix: text("prefix").unwrap_or_default(),
        record_kind: required("record_kind")?,
        id_column,
        fields,
        secret,
    })
}

/// The record id of the row with `id` in the object at `key`, rule `v1`:
/// `v1.`, the first 32 hex digits of the key's SHA-256, a dot, and the id with
/// every byte other than ASCII letters, digits, `-`, `_`, `.` and `~`
/// written as `%XX`. Distinct `(key, id)` pairs get distinct ids up to the
/// digest, and every id is a valid registered token.
pub fn external_id(key: &str, id: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let key: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let id: String = id
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    format!("v1.{key}.{id}")
}

/// Where a walk stands in its pass.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Position {
    /// Before the first key.
    Start,
    /// After this key: its records are all applied.
    After(String),
    /// At this key: some of its records are still to apply.
    At(String),
}

/// `object_storage-v1|{page}|start`, `…|after|{key}` or `…|at|{key}`.
/// The page number grows on every page, so each proposed cursor differs
/// from the committed one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cursor {
    page: u64,
    position: Position,
}

impl Cursor {
    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.splitn(4, '|');
        if parts.next()? != CURSOR_PREFIX {
            return None;
        }
        let page = parts.next()?.parse().ok()?;
        let position = match (parts.next()?, parts.next()) {
            ("start", None) => Position::Start,
            ("after", Some(key)) if !key.is_empty() => Position::After(key.into()),
            ("at", Some(key)) if !key.is_empty() => Position::At(key.into()),
            _ => return None,
        };
        Some(Self { page, position })
    }
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let page = self.page;
        match &self.position {
            Position::Start => write!(formatter, "{CURSOR_PREFIX}|{page}|start"),
            Position::After(key) => write!(formatter, "{CURSOR_PREFIX}|{page}|after|{key}"),
            Position::At(key) => write!(formatter, "{CURSOR_PREFIX}|{page}|at|{key}"),
        }
    }
}

/// How one stretch of a walk ended.
enum Walked {
    /// The page filled; the next one starts here.
    Full(Position),
    /// The stretch reached its end.
    End,
}

/// The listing from a position, one request at a time.
struct Listing<'a> {
    storage: &'a ObjectStorage,
    buffered: std::collections::VecDeque<Listed>,
    /// `None` once the listing is done.
    next: Option<Next>,
    last: Option<String>,
}

enum Next {
    StartAfter(Option<String>),
    Token(String),
}

impl<'a> Listing<'a> {
    fn new(storage: &'a ObjectStorage, position: &Position) -> Result<Self, ConnectorFailure> {
        let mut listing = Self {
            storage,
            buffered: Default::default(),
            next: Some(Next::StartAfter(None)),
            last: None,
        };
        match position {
            Position::Start => {}
            Position::After(key) => listing.next = Some(Next::StartAfter(Some(key.clone()))),
            // The key itself, when it is still listed, is the first of the
            // keys it prefixes.
            Position::At(key) => {
                let page = storage.store.list(key, None, None, 1)?;
                listing
                    .buffered
                    .extend(page.objects.into_iter().filter(|object| {
                        &object.key == key && object.key.starts_with(&storage.prefix)
                    }));
                listing.next = Some(Next::StartAfter(Some(key.clone())));
            }
        }
        Ok(listing)
    }

    fn peek(&mut self) -> Result<Option<&Listed>, ConnectorFailure> {
        while self.buffered.is_empty() {
            let page = match self.next.take() {
                None => return Ok(None),
                Some(Next::StartAfter(after)) => self.storage.store.list(
                    &self.storage.prefix,
                    after.as_deref(),
                    None,
                    LIST_PAGE_KEYS,
                )?,
                Some(Next::Token(token)) => self.storage.store.list(
                    &self.storage.prefix,
                    None,
                    Some(&token),
                    LIST_PAGE_KEYS,
                )?,
            };
            self.next = page.next.map(Next::Token);
            self.buffered.extend(page.objects);
        }
        let first = self.buffered.front().map(|object| object.key.clone());
        // The walk relies on byte order; a store that breaks it is refused.
        if first.as_ref().is_some_and(|key| {
            !key.starts_with(&self.storage.prefix)
                || self.last.as_ref().is_some_and(|last| key <= last)
        }) {
            return Err(ConnectorFailure::Invalid);
        }
        Ok(self.buffered.front())
    }

    fn pop(&mut self) -> Option<Listed> {
        let object = self.buffered.pop_front()?;
        self.last = Some(object.key.clone());
        Some(object)
    }
}

/// The Source's live records from a position, one plane read at a time.
struct Live<'v> {
    plane: &'v mut dyn PlaneView,
    buffered: std::collections::VecDeque<RecordVersion>,
    after: (String, Option<String>),
    through: Option<String>,
    done: bool,
}

impl<'v> Live<'v> {
    fn new(plane: &'v mut dyn PlaneView, position: &Position, through: Option<String>) -> Self {
        let after = match position {
            Position::Start => (String::new(), None),
            Position::After(key) => (key.clone(), None),
            // Every id is non-empty, so this starts at the key's first.
            Position::At(key) => (key.clone(), Some(String::new())),
        };
        Self {
            plane,
            buffered: Default::default(),
            after,
            through,
            done: false,
        }
    }

    fn peek_key(&mut self) -> Result<Option<&str>, ConnectorFailure> {
        if self.buffered.is_empty() && !self.done {
            let records = self
                .plane
                .record_versions(
                    KeyRange {
                        after_object_key: &self.after.0,
                        after_external_id: self.after.1.as_deref(),
                        through_object_key: self.through.as_deref(),
                    },
                    MAX_SOURCE_BATCH_RECORDS,
                )
                .map_err(|error| match error {
                    PlaneViewError::Unkeyed => ConnectorFailure::Invalid,
                    _ => ConnectorFailure::Unreachable,
                })?;
            self.done = records.len() < MAX_SOURCE_BATCH_RECORDS;
            if let Some(last) = records.last() {
                self.after = (last.object_key.clone(), Some(last.external_id.clone()));
            }
            self.buffered.extend(records);
        }
        Ok(self
            .buffered
            .front()
            .map(|record| record.object_key.as_str()))
    }

    /// Every live record at `key`, by id, with its version.
    fn take(&mut self, key: &str) -> Result<BTreeMap<String, String>, ConnectorFailure> {
        let mut records = BTreeMap::new();
        while self.peek_key()? == Some(key) {
            let record = self.buffered.pop_front().expect("peeked");
            records.insert(record.external_id, record.source_version);
        }
        Ok(records)
    }
}

impl ObjectStorage {
    /// Walks from `position` through `through` (inclusive; `None` to the
    /// end), adding to `page` the records that bring each key up to date,
    /// until `page` holds `max_records`.
    fn walk(
        &self,
        plane: &mut dyn PlaneView,
        position: &Position,
        through: Option<&str>,
        page: &mut Vec<SourceRecord>,
        max_records: usize,
    ) -> Result<Walked, ConnectorFailure> {
        let mut listing = Listing::new(self, position)?;
        let mut live = Live::new(plane, position, through.map(Into::into));
        let observed_at_ms = now_ms();
        loop {
            let listed = listing.peek()?.map(|object| object.key.clone());
            let held = live.peek_key()?.map(str::to_string);
            let key = match (listed, held) {
                (None, None) => return Ok(Walked::End),
                (Some(listed), None) => listed,
                (None, Some(held)) => held,
                (Some(listed), Some(held)) => listed.min(held),
            };
            if through.is_some_and(|through| key.as_str() > through) {
                return Ok(Walked::End);
            }
            let versions = live.take(&key)?;
            let object = match listing.peek()? {
                Some(object) if object.key == key => listing.pop(),
                _ => None,
            };
            // The key a walk resumes at is partly applied: its applied rows
            // already carry the ETag, so the ETag alone cannot skip it.
            let resumed = matches!(position, Position::At(at) if *at == key);
            let mut records = match object {
                Some(object)
                    if !resumed
                        && !versions.is_empty()
                        && versions.values().all(|version| *version == object.etag) =>
                {
                    continue;
                }
                Some(object) => self.changes(&object, &versions, observed_at_ms)?,
                None => versions
                    .into_iter()
                    .map(|(id, version)| self.tombstone(&key, id, version, observed_at_ms))
                    .collect(),
            };
            let room = max_records - page.len();
            if records.len() > room {
                records.truncate(room);
                page.extend(records);
                return Ok(Walked::Full(Position::At(key)));
            }
            page.extend(records);
            if page.len() == max_records {
                return Ok(Walked::Full(Position::After(key)));
            }
        }
    }

    /// The records that bring a listed object up to date with `versions`,
    /// its live records: its rows not already at its ETag, then tombstones
    /// for the live records it no longer has, each in id order.
    fn changes(
        &self,
        object: &Listed,
        versions: &BTreeMap<String, String>,
        observed_at_ms: i64,
    ) -> Result<Vec<SourceRecord>, ConnectorFailure> {
        let key = &object.key;
        // A dot segment would be normalized away in the request path, so
        // the object could not be read as signed.
        if key.len() > MAX_SOURCE_OBJECT_KEY_BYTES
            || key.chars().any(char::is_control)
            || key
                .split('/')
                .any(|segment| segment == "." || segment == "..")
            || !self.carried(key, MAX_SOURCE_OBJECT_KEY_BYTES)
        {
            return Err(ConnectorFailure::Invalid);
        }
        let (bytes, etag) = self.store.get_object(key, MAX_OBJECT_BYTES)?;
        let mut rows = BTreeMap::new();
        for row in json_rows(&bytes)? {
            let id = scalar(row.get(&self.id_column))
                .filter(|id| self.carried(id, MAX_SOURCE_IDENTIFIER_BYTES))
                .ok_or(ConnectorFailure::Invalid)?;
            let record = self.record(key, &id, &etag, &row, observed_at_ms)?;
            // An id twice in one object has no single identity.
            if rows.insert(record.external_id.clone(), record).is_some() {
                return Err(ConnectorFailure::Invalid);
            }
        }
        let gone: Vec<_> = versions
            .iter()
            .filter(|(id, _)| !rows.contains_key(*id))
            .map(|(id, _)| self.tombstone(key, id.clone(), etag.clone(), observed_at_ms))
            .collect();
        Ok(rows
            .into_values()
            .filter(|record| versions.get(&record.external_id) != Some(&record.source_version))
            .chain(gone)
            .collect())
    }

    fn record(
        &self,
        key: &str,
        id: &str,
        etag: &str,
        row: &serde_json::Map<String, Value>,
        observed_at_ms: i64,
    ) -> Result<SourceRecord, ConnectorFailure> {
        let external_id = external_id(key, id);
        if external_id.len() > MAX_SOURCE_IDENTIFIER_BYTES {
            return Err(ConnectorFailure::Invalid);
        }
        let mut properties: BTreeMap<String, PropertyValue> = self
            .fields
            .iter()
            .filter_map(|field| {
                let value = match row.get(field)? {
                    Value::Bool(flag) => PropertyValue::Bool(*flag),
                    Value::Number(number) => match number.as_i64() {
                        Some(int) => PropertyValue::Int(int),
                        None => PropertyValue::Float(number.as_f64().filter(|f| f.is_finite())?),
                    },
                    Value::String(text) if self.carried(text, MAX_SOURCE_PROPERTY_VALUE_BYTES) => {
                        PropertyValue::String(text.clone())
                    }
                    _ => return None,
                };
                Some((field.clone(), value))
            })
            .collect();
        properties.insert(
            OBJECT_KEY_PROPERTY.into(),
            PropertyValue::String(key.into()),
        );
        Ok(SourceRecord {
            source: String::new(),
            source_instance: String::new(),
            display_name: display_line(id),
            external_id,
            source_version: etag.into(),
            type_name: self.record_kind.clone(),
            payload_digest: digest_of(&properties),
            properties,
            deleted: false,
            observed_at_ms,
            source_sequence: None,
            payload: None,
            object_key: Some(key.into()),
        })
    }

    fn tombstone(
        &self,
        key: &str,
        external_id: String,
        version: String,
        observed_at_ms: i64,
    ) -> SourceRecord {
        let properties = BTreeMap::new();
        SourceRecord {
            source: String::new(),
            source_instance: String::new(),
            display_name: display_line(&external_id),
            external_id,
            source_version: version,
            type_name: self.record_kind.clone(),
            payload_digest: digest_of(&properties),
            properties,
            deleted: true,
            observed_at_ms,
            source_sequence: None,
            payload: None,
            object_key: Some(key.into()),
        }
    }

    /// Whether `text` may go to the plane: bounded, one line, and carrying
    /// neither the secret key nor anything that looks like a credential.
    fn carried(&self, text: &str, max_bytes: usize) -> bool {
        !text.is_empty()
            && text.len() <= max_bytes
            && !text.chars().any(char::is_control)
            && !text.contains(&self.secret)
            && !contains_secret_like_text(text)
    }
}

/// Rows of a JSON object, an array of objects, or one object per line, at
/// most [`MAX_OBJECT_ROWS`] of them.
fn json_rows(bytes: &[u8]) -> Result<Vec<serde_json::Map<String, Value>>, ConnectorFailure> {
    let object = |value: Value| match value {
        Value::Object(object) => Ok(object),
        _ => Err(ConnectorFailure::Invalid),
    };
    let rows = match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Array(values)) if values.len() > MAX_OBJECT_ROWS => {
            return Err(ConnectorFailure::Invalid);
        }
        Ok(Value::Array(values)) => values.into_iter().map(object).collect(),
        Ok(value) => Ok(vec![object(value)?]),
        Err(_) => {
            let text = std::str::from_utf8(bytes).map_err(|_| ConnectorFailure::Invalid)?;
            let lines: Vec<_> = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .collect();
            if lines.len() > MAX_OBJECT_ROWS {
                return Err(ConnectorFailure::Invalid);
            }
            lines
                .into_iter()
                .map(|line| {
                    object(serde_json::from_str(line).map_err(|_| ConnectorFailure::Invalid)?)
                })
                .collect()
        }
    }?;
    Ok(rows)
}

impl Connector for ObjectStorage {
    /// Proves the endpoint answers, the key pair signs, and the prefix can
    /// be listed.
    fn check(&mut self) -> Result<(), ConnectorFailure> {
        self.store.list(&self.prefix, None, None, 1).map(|_| ())
    }

    /// The type needs the plane's live records; without them it reads
    /// nothing rather than a mirror that cannot tombstone.
    fn read_page(
        &mut self,
        _committed_cursor: Option<&str>,
        _max_records: usize,
    ) -> Result<SnapshotRead, ConnectorFailure> {
        Err(ConnectorFailure::Unsupported)
    }

    fn read_page_with_plane(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
        plane: &mut dyn PlaneView,
    ) -> Result<SnapshotRead, ConnectorFailure> {
        if max_records == 0 {
            return Err(ConnectorFailure::Invalid);
        }
        let committed = committed_cursor.and_then(Cursor::parse);
        let page_number = committed.as_ref().map_or(0, |cursor| cursor.page + 1);
        let start = committed.map_or(Position::Start, |cursor| cursor.position);
        let collected_at_ms = now_ms();
        let mut records = Vec::new();
        let page = |records, position, complete| {
            Ok(SnapshotRead::Page(SnapshotPage {
                records,
                proposed_next_cursor: Cursor {
                    page: page_number,
                    position,
                }
                .to_string(),
                collected_at_ms,
                complete,
                notes: Vec::new(),
            }))
        };
        if let Walked::Full(next) = self.walk(plane, &start, None, &mut records, max_records)? {
            return page(records, next, false);
        }
        let through = match &start {
            // The pass reached its end: done, and the next sync starts anew.
            _ if !records.is_empty() => return page(records, Position::Start, true),
            Position::Start => return page(records, Position::Start, true),
            Position::After(key) | Position::At(key) => key.clone(),
        };
        // Nothing changed after the cursor: wrap into a new pass up to it.
        match self.walk(
            plane,
            &Position::Start,
            Some(&through),
            &mut records,
            max_records,
        )? {
            Walked::Full(next) => page(records, next, false),
            Walked::End => page(records, start, true),
        }
    }
}

#[cfg(test)]
mod tests;
