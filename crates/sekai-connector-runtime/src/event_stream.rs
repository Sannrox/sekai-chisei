//! The `event_stream` connector type: JSON records from one topic of an
//! event-stream cluster, read through the [`crate::broker`] client as
//! snapshot pages under the plane-owned cursor (ADR 0022, ADR 0148).
//!
//! The cursor is the next offset of each partition the Source reads. The
//! type commits nothing to the cluster, so a runtime that dies mid-sync
//! loses nothing: the next holder reads the committed cursor and reads the
//! uncommitted page again. Records read again keep their ids and versions,
//! so they change nothing.
//!
//! A first sync starts at each partition's earliest retained offset. When
//! retention has passed a committed offset, the page resumes at the
//! earliest retained one and notes the skipped range as an offset gap
//! (ADR 0163). A record whose value is not a JSON object, or has no usable
//! id at `id_field`, is skipped and noted with its partition and offset, so
//! one bad record never stalls a partition. A null value (a compaction
//! tombstone) is skipped as not JSON; deleting objects from tombstones is
//! out of scope. A page that holds no record commits nothing, so the next
//! sync notes its gaps and skipped records again, until a later record
//! moves the cursor past them.
//!
//! A page reads the partitions in order until it holds `max_records`
//! records or each partition reached the end it had when the page read it,
//! and keeps the latest record per id. A record's version is its partition
//! and offset. Skipped records do not fill a page, but one page reads at
//! most [`MAX_READ_FACTOR`] times `max_records` records. A committed offset
//! past a partition's end (a recreated topic) fails the page as invalid
//! rather than guessing where to resume.
//!
//! Every broker is checked before it is dialed, the bootstrap and each one
//! Metadata advertises, against the Source's egress allowlist, and TLS is
//! required for any broker that is not loopback.

use std::collections::{BTreeMap, BTreeSet};

use native_tls::TlsConnector;
use sekai_source_sdk::{
    ConfigValue, Connector, ConnectorFailure, Destination, EgressAllowlist,
    MAX_SOURCE_IDENTIFIER_BYTES, MAX_SOURCE_PROPERTY_VALUE_BYTES, MAX_SOURCE_RECORD_PROPERTIES,
    PropertyValue, SkipReason, SnapshotPage, SnapshotRead, SourceRecord, SyncNote,
    contains_secret_like_text,
};
use serde_json::Value;

use crate::broker::{BrokerConfig, Cluster, FetchedRecord, Offsets, PlainCredential};
use crate::credentials::Secret;
use crate::rest::{digest_of, display_line, now_ms, property_key, scalar};
use crate::sync::Prepared;

/// The most partitions one Source reads.
pub const MAX_PARTITIONS: usize = 64;

/// How many records one page reads at most, as a multiple of the records
/// it may hold: skipped records do not fill a page, this bounds its time.
pub const MAX_READ_FACTOR: usize = 8;

const CURSOR_PREFIX: &str = "event_stream-v1|";

/// One topic of one cluster, reached with the Source's bound credential.
pub struct EventStream {
    bootstrap: Destination,
    egress: EgressAllowlist,
    tls: Option<TlsConnector>,
    credential: Option<(String, Secret)>,
    topic: String,
    record_kind: String,
    id_field: String,
    fields: Vec<String>,
    /// The configured partitions; `None` reads every partition.
    partitions: Option<BTreeSet<i32>>,
}

/// Opens the type for a prepared Source, reaching brokers that are not
/// loopback through `tls`; register it with
/// `Connectors::with(&EVENT_STREAM_CONNECTOR, move |prepared| event_stream::open(prepared, &tls))`.
pub fn open(
    prepared: &Prepared,
    tls: &TlsConnector,
) -> Result<Box<dyn Connector + Send>, ConnectorFailure> {
    Ok(Box::new(open_event_stream(prepared, tls)?))
}

fn open_event_stream(
    prepared: &Prepared,
    connector: &TlsConnector,
) -> Result<EventStream, ConnectorFailure> {
    let config = &prepared.config;
    let text = |name: &str| match config.get(name) {
        Some(ConfigValue::Text(text)) => Some(text.clone()),
        _ => None,
    };
    let required = |name: &str| text(name).ok_or(ConnectorFailure::Invalid);
    let bootstrap = Destination::parse(&required("bootstrap")?)
        .filter(|destination| destination.port.is_some())
        .ok_or(ConnectorFailure::Invalid)?;
    let id_field = required("id_field")?;
    // Any case, but not a name that suggests a credential.
    if !property_key(&id_field.to_ascii_lowercase()) {
        return Err(ConnectorFailure::Invalid);
    }
    let fields = list(text("fields"));
    if fields.len() > MAX_SOURCE_RECORD_PROPERTIES || !fields.iter().all(|key| property_key(key)) {
        return Err(ConnectorFailure::Invalid);
    }
    let partitions = text("partitions")
        .map(|text| {
            list(Some(text))
                .iter()
                .map(|partition| partition.parse::<i32>().ok().filter(|index| *index >= 0))
                .collect::<Option<BTreeSet<_>>>()
                .filter(|set| !set.is_empty() && set.len() <= MAX_PARTITIONS)
                .ok_or(ConnectorFailure::Invalid)
        })
        .transpose()?;
    let credential = match (text("username"), prepared.credentials.get("password")) {
        (Some(username), Some(password)) => Some((username, password.clone())),
        (None, None) => None,
        (Some(_), None) => return Err(ConnectorFailure::AuthFailed),
        (None, Some(_)) => return Err(ConnectorFailure::Invalid),
    };
    let tls = !matches!(config.get("tls"), Some(ConfigValue::Boolean(false)));
    Ok(EventStream {
        bootstrap,
        egress: prepared.egress.clone(),
        tls: tls.then(|| connector.clone()),
        credential,
        topic: required("topic")?,
        record_kind: required("record_kind")?,
        id_field,
        fields,
        partitions,
    })
}

/// A comma-separated list, trimmed, without empty entries.
fn list(text: Option<String>) -> Vec<String> {
    text.iter()
        .flat_map(|text| text.split(','))
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

impl EventStream {
    fn connect(&self) -> Result<Cluster, ConnectorFailure> {
        Ok(Cluster::connect(BrokerConfig {
            bootstrap: self.bootstrap.clone(),
            egress: self.egress.clone(),
            tls: self.tls.clone(),
            credential: self
                .credential
                .as_ref()
                .map(|(username, password)| PlainCredential {
                    username: username.clone(),
                    password: password.clone(),
                }),
        })?)
    }

    /// The partitions the Source reads: the configured ones, each of which
    /// the topic must have, or all of the topic's, at most [`MAX_PARTITIONS`].
    fn assigned(&self, cluster: &mut Cluster) -> Result<Vec<i32>, ConnectorFailure> {
        let partitions = cluster.partitions(&self.topic)?;
        let assigned = match &self.partitions {
            Some(configured) if configured.iter().all(|index| partitions.contains(index)) => {
                configured.iter().copied().collect()
            }
            Some(_) => return Err(ConnectorFailure::Invalid),
            None => partitions,
        };
        if assigned.len() > MAX_PARTITIONS {
            return Err(ConnectorFailure::Invalid);
        }
        Ok(assigned)
    }

    /// The record a fetched value is, or why it is skipped.
    fn record(
        &self,
        partition: i32,
        fetched: &FetchedRecord,
        observed_at_ms: i64,
    ) -> Result<SourceRecord, SkipReason> {
        let value: Value = fetched
            .value
            .as_deref()
            .and_then(|bytes| serde_json::from_slice(bytes).ok())
            .ok_or(SkipReason::NotJson)?;
        let object = value.as_object().ok_or(SkipReason::NotJson)?;
        // Ids are registered tokens: the plane keys a record as
        // `{record_kind}/{id}`, so an id may not carry `/`, `#` or `:`.
        let external_id = scalar(object.get(&self.id_field))
            .filter(|id| {
                self.carried(id, MAX_SOURCE_IDENTIFIER_BYTES)
                    && id.trim() == id
                    && !id.contains(['/', '#', ':'])
            })
            .ok_or(SkipReason::MissingId)?;
        let properties = self
            .fields
            .iter()
            .filter_map(|key| {
                let value = match object.get(key)? {
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
                Some((key.clone(), value))
            })
            .collect();
        Ok(SourceRecord {
            source: String::new(),
            source_instance: String::new(),
            display_name: display_line(&external_id),
            external_id,
            source_version: format!("{partition}-{}", fetched.offset),
            type_name: self.record_kind.clone(),
            payload_digest: digest_of(&properties),
            properties,
            deleted: false,
            observed_at_ms,
            source_sequence: None,
            payload: None,
            object_key: None,
        })
    }

    /// Whether `text` may go to the plane: bounded, one line, and carrying
    /// neither the password nor anything that looks like a credential.
    fn carried(&self, text: &str, max_bytes: usize) -> bool {
        !text.is_empty()
            && text.len() <= max_bytes
            && !text.chars().any(char::is_control)
            && !self
                .credential
                .as_ref()
                .is_some_and(|(_, password)| text.contains(password.expose()))
            && !contains_secret_like_text(text)
    }
}

impl Connector for EventStream {
    /// Proves the bootstrap answers, the credential authenticates, and the
    /// topic has the configured partitions.
    fn check(&mut self) -> Result<(), ConnectorFailure> {
        self.assigned(&mut self.connect()?).map(|_| ())
    }

    fn read_page(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<SnapshotRead, ConnectorFailure> {
        let mut cluster = self.connect()?;
        let partitions = self.assigned(&mut cluster)?;
        let mut next = committed_cursor.and_then(parse_cursor).unwrap_or_default();
        next.retain(|partition, _| partitions.contains(partition));
        let budget = max_records.saturating_mul(MAX_READ_FACTOR);
        let observed_at_ms = now_ms();
        let (mut records, mut notes) = (BTreeMap::<String, SourceRecord>::new(), Vec::new());
        let (mut read, mut complete) = (0, true);
        'partitions: for &partition in &partitions {
            let Offsets { earliest, latest } = cluster.offsets(&self.topic, partition)?;
            let mut offset = next.get(&partition).copied().unwrap_or(earliest);
            if offset < earliest {
                notes.push(SyncNote::OffsetGap {
                    partition,
                    from_offset: offset,
                    to_offset: earliest,
                });
                offset = earliest;
            }
            if offset > latest {
                return Err(ConnectorFailure::Invalid);
            }
            while offset < latest {
                let fetched = cluster.fetch(&self.topic, partition, offset)?;
                // A leader that answers nothing below its end fails the
                // page visibly instead of reading it forever.
                if fetched.records.is_empty() && fetched.next_offset <= offset {
                    return Err(ConnectorFailure::Unreachable);
                }
                for record in &fetched.records {
                    if records.len() >= max_records || read >= budget {
                        next.insert(partition, offset);
                        complete = false;
                        break 'partitions;
                    }
                    read += 1;
                    match self.record(partition, record, observed_at_ms) {
                        Ok(record) => {
                            records.insert(record.external_id.clone(), record);
                        }
                        Err(reason) => notes.push(SyncNote::SkippedRecord {
                            partition,
                            offset: record.offset,
                            reason,
                        }),
                    }
                    offset = record.offset + 1;
                }
                offset = offset.max(fetched.next_offset);
            }
            next.insert(partition, offset);
        }
        if records.is_empty() && notes.is_empty() && committed_cursor.is_some() {
            return Ok(SnapshotRead::Complete);
        }
        Ok(SnapshotRead::Page(SnapshotPage {
            records: records.into_values().collect(),
            proposed_next_cursor: cursor(&next),
            collected_at_ms: observed_at_ms,
            complete,
            notes,
        }))
    }
}

/// `event_stream-v1|0=12,1=7`: the next offset of each partition read.
fn cursor(next: &BTreeMap<i32, i64>) -> String {
    let offsets: Vec<_> = next
        .iter()
        .map(|(partition, offset)| format!("{partition}={offset}"))
        .collect();
    format!("{CURSOR_PREFIX}{}", offsets.join(","))
}

/// The offsets a cursor of this type holds; `None` for one it did not
/// write, which starts every partition at its earliest offset.
fn parse_cursor(text: &str) -> Option<BTreeMap<i32, i64>> {
    let offsets = text.strip_prefix(CURSOR_PREFIX)?;
    if offsets.is_empty() {
        return Some(BTreeMap::new());
    }
    offsets
        .split(',')
        .map(|entry| {
            let (partition, offset) = entry.split_once('=')?;
            let partition = partition.parse::<i32>().ok().filter(|index| *index >= 0)?;
            let offset = offset.parse::<i64>().ok().filter(|offset| *offset >= 0)?;
            Some((partition, offset))
        })
        .collect()
}

#[cfg(test)]
mod tests;
