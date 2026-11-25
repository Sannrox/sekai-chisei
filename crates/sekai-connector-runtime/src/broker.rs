//! A blocking client for the event-stream broker wire protocol: the few
//! requests a snapshot reader needs (version negotiation, SASL/PLAIN,
//! Metadata, ListOffsets and Fetch), for the event-stream connector type.
//!
//! The wire format comes from `kafka_protocol`; the transport is ours, so
//! every broker is checked before it is dialed. The bootstrap and each
//! broker Metadata advertises must be a destination the Source's egress
//! allowlist permits, and a broker that is not loopback must be reached
//! over TLS. A refused broker is never dialed. An advertised host the
//! allowlist cannot name (an IPv6 literal, for one) is refused too.
//!
//! The client keeps no offsets and commits nothing to the cluster; the
//! caller owns the cursor. Fetches read uncommitted records, so records of
//! aborted transactions are returned like any other (at least once).
//! Control records are skipped. Compressed batches are decoded by
//! [`codec`], which caps how far one batch may expand.

pub mod codec;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use kafka_protocol::messages::api_versions_request::ApiVersionsRequest;
use kafka_protocol::messages::api_versions_response::ApiVersionsResponse;
use kafka_protocol::messages::fetch_request::{FetchPartition, FetchRequest, FetchTopic};
use kafka_protocol::messages::fetch_response::FetchResponse;
use kafka_protocol::messages::list_offsets_request::{
    ListOffsetsPartition, ListOffsetsRequest, ListOffsetsTopic,
};
use kafka_protocol::messages::list_offsets_response::ListOffsetsResponse;
use kafka_protocol::messages::metadata_request::{MetadataRequest, MetadataRequestTopic};
use kafka_protocol::messages::metadata_response::MetadataResponse;
use kafka_protocol::messages::sasl_authenticate_request::SaslAuthenticateRequest;
use kafka_protocol::messages::sasl_authenticate_response::SaslAuthenticateResponse;
use kafka_protocol::messages::sasl_handshake_request::SaslHandshakeRequest;
use kafka_protocol::messages::sasl_handshake_response::SaslHandshakeResponse;
use kafka_protocol::messages::{ApiKey, BrokerId, RequestHeader, ResponseHeader, TopicName};
use kafka_protocol::protocol::{
    Decodable, Encodable, HeaderVersion, Message, StrBytes, VersionRange,
};
use kafka_protocol::records::RecordBatchDecoder;
use native_tls::{TlsConnector, TlsStream};
use sekai_source_sdk::{ConnectorFailure, Destination, EgressAllowlist};

use crate::credentials::Secret;

/// How long one connection, write or read may take.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The largest response frame accepted. A fetch asks for far less; this
/// bounds what a misbehaving broker can make the runtime allocate.
const MAX_FRAME_BYTES: usize = 64 << 20;

/// What one fetch asks for, in total and for its one partition. A broker
/// still returns a first batch larger than this, so a big record never
/// stalls a partition.
const FETCH_MAX_BYTES: i32 = 4 << 20;

/// How long a broker may hold a fetch open waiting for new records.
const FETCH_MAX_WAIT_MS: i32 = 100;

const CLIENT_ID: &str = "sekai-connector-runtime";

/// ListOffsets timestamps that ask for the earliest and the next offset.
const EARLIEST: i64 = -2;
const LATEST: i64 = -1;

/// How the runtime reaches one cluster. `tls` is the connector every
/// broker is reached through; without it only loopback brokers are dialed.
pub struct BrokerConfig {
    pub bootstrap: Destination,
    pub egress: EgressAllowlist,
    pub tls: Option<TlsConnector>,
    pub credential: Option<PlainCredential>,
}

/// A SASL/PLAIN username and password.
pub struct PlainCredential {
    pub username: String,
    pub password: Secret,
}

/// Why a broker call failed. Value-free, like [`ConnectorFailure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerError {
    /// A broker outside the egress allowlist, or one it cannot name. It
    /// was never dialed.
    EgressRefused,
    /// A broker that is not loopback, without TLS. It was never dialed.
    TlsRequired,
    Unreachable,
    AuthFailed,
    PermissionMissing,
    UnknownTopic,
    /// The offset is outside the partition's retained range.
    OffsetOutOfRange,
    /// The partition has no leader, or it moved. Call
    /// [`Cluster::partitions`] again before retrying.
    LeaderMoved,
    /// The broker answered with something this client cannot use.
    Invalid,
}

impl From<BrokerError> for ConnectorFailure {
    fn from(error: BrokerError) -> Self {
        match error {
            BrokerError::Unreachable | BrokerError::LeaderMoved => Self::Unreachable,
            BrokerError::AuthFailed => Self::AuthFailed,
            BrokerError::PermissionMissing => Self::PermissionMissing,
            BrokerError::EgressRefused
            | BrokerError::TlsRequired
            | BrokerError::UnknownTopic
            | BrokerError::OffsetOutOfRange
            | BrokerError::Invalid => Self::Invalid,
        }
    }
}

/// A partition's retained range: `earliest` is the first offset still
/// held, `latest` the offset the next record will get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offsets {
    pub earliest: i64,
    pub latest: i64,
}

/// One record of a fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedRecord {
    pub offset: i64,
    pub key: Option<Bytes>,
    pub value: Option<Bytes>,
}

/// The records of one fetch, in offset order, and where the next fetch
/// starts. `next_offset` passes offsets compaction removed and control
/// records, so it can be greater than the last record's offset plus one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub records: Vec<FetchedRecord>,
    pub next_offset: i64,
    pub high_watermark: i64,
}

/// Connections to one cluster: the bootstrap broker, then each partition
/// leader as it is needed. A connection that fails is dropped and dialed
/// again by the next call.
pub struct Cluster {
    config: BrokerConfig,
    /// Brokers the last Metadata advertised, by node id. `None` is an
    /// address the egress allowlist cannot name.
    brokers: BTreeMap<i32, Option<Destination>>,
    /// Partition leaders from the last Metadata, by topic and partition.
    leaders: BTreeMap<(String, i32), i32>,
    sessions: BTreeMap<Destination, Session>,
}

impl Cluster {
    /// Dials and authenticates with the bootstrap broker. Success proves it
    /// answers and accepts the credential.
    pub fn connect(config: BrokerConfig) -> Result<Self, BrokerError> {
        let bootstrap = config.bootstrap.clone();
        let mut cluster = Self {
            config,
            brokers: BTreeMap::new(),
            leaders: BTreeMap::new(),
            sessions: BTreeMap::new(),
        };
        cluster.session(&bootstrap)?;
        Ok(cluster)
    }

    /// The topic's partitions, sorted, read from the bootstrap broker. It
    /// also refreshes the advertised brokers and partition leaders.
    pub fn partitions(&mut self, topic: &str) -> Result<Vec<i32>, BrokerError> {
        let request = MetadataRequest::default()
            .with_topics(Some(vec![
                MetadataRequestTopic::default().with_name(Some(topic_name(topic))),
            ]))
            .with_allow_auto_topic_creation(false);
        let bootstrap = self.config.bootstrap.clone();
        let response = self.call(&bootstrap, &request)?;
        let entry = response
            .topics
            .iter()
            .find(|entry| {
                entry
                    .name
                    .as_ref()
                    .is_some_and(|name| name.as_str() == topic)
            })
            .ok_or(BrokerError::Invalid)?;
        error_code(entry.error_code)?;
        self.brokers = response
            .brokers
            .iter()
            .map(|broker| {
                (
                    *broker.node_id,
                    advertised(broker.host.as_str(), broker.port),
                )
            })
            .collect();
        self.leaders.retain(|(known, _), _| known != topic);
        let mut partitions = Vec::with_capacity(entry.partitions.len());
        for partition in &entry.partitions {
            partitions.push(partition.partition_index);
            if partition.error_code == 0 && *partition.leader_id >= 0 {
                self.leaders.insert(
                    (topic.to_owned(), partition.partition_index),
                    *partition.leader_id,
                );
            }
        }
        partitions.sort_unstable();
        Ok(partitions)
    }

    /// The partition's retained range, from its leader.
    pub fn offsets(&mut self, topic: &str, partition: i32) -> Result<Offsets, BrokerError> {
        Ok(Offsets {
            earliest: self.list_offset(topic, partition, EARLIEST)?,
            latest: self.list_offset(topic, partition, LATEST)?,
        })
    }

    /// Records of one partition from `offset` on, from its leader. Records
    /// before `offset` in the first batch are dropped.
    pub fn fetch(
        &mut self,
        topic: &str,
        partition: i32,
        offset: i64,
    ) -> Result<Fetched, BrokerError> {
        let request = FetchRequest::default()
            .with_replica_id(BrokerId(-1))
            .with_max_wait_ms(FETCH_MAX_WAIT_MS)
            .with_min_bytes(1)
            .with_max_bytes(FETCH_MAX_BYTES)
            .with_isolation_level(0)
            .with_topics(vec![
                FetchTopic::default()
                    .with_topic(topic_name(topic))
                    .with_partitions(vec![
                        FetchPartition::default()
                            .with_partition(partition)
                            .with_fetch_offset(offset)
                            .with_partition_max_bytes(FETCH_MAX_BYTES),
                    ]),
            ]);
        let leader = self.leader(topic, partition)?;
        let response = self.call(&leader, &request)?;
        error_code(response.error_code)?;
        let data = response
            .responses
            .iter()
            .filter(|entry| entry.topic.as_str() == topic)
            .flat_map(|entry| &entry.partitions)
            .find(|data| data.partition_index == partition)
            .ok_or(BrokerError::Invalid)?;
        error_code(data.error_code)?;
        let (records, next_offset) =
            decode_records(data.records.clone().unwrap_or_default(), offset)?;
        Ok(Fetched {
            records,
            next_offset,
            high_watermark: data.high_watermark,
        })
    }

    fn list_offset(
        &mut self,
        topic: &str,
        partition: i32,
        timestamp: i64,
    ) -> Result<i64, BrokerError> {
        let request = ListOffsetsRequest::default()
            .with_replica_id(BrokerId(-1))
            .with_topics(vec![
                ListOffsetsTopic::default()
                    .with_name(topic_name(topic))
                    .with_partitions(vec![
                        ListOffsetsPartition::default()
                            .with_partition_index(partition)
                            .with_timestamp(timestamp),
                    ]),
            ]);
        let leader = self.leader(topic, partition)?;
        let response = self.call(&leader, &request)?;
        let data = response
            .topics
            .iter()
            .filter(|entry| entry.name.as_str() == topic)
            .flat_map(|entry| &entry.partitions)
            .find(|data| data.partition_index == partition)
            .ok_or(BrokerError::Invalid)?;
        error_code(data.error_code)?;
        (data.offset >= 0)
            .then_some(data.offset)
            .ok_or(BrokerError::Invalid)
    }

    fn leader(&self, topic: &str, partition: i32) -> Result<Destination, BrokerError> {
        let node = self
            .leaders
            .get(&(topic.to_owned(), partition))
            .ok_or(BrokerError::LeaderMoved)?;
        match self.brokers.get(node) {
            Some(Some(destination)) => Ok(destination.clone()),
            Some(None) => Err(BrokerError::EgressRefused),
            None => Err(BrokerError::LeaderMoved),
        }
    }

    fn session(&mut self, destination: &Destination) -> Result<&mut Session, BrokerError> {
        if !self.sessions.contains_key(destination) {
            let session = Session::open(destination, &self.config)?;
            self.sessions.insert(destination.clone(), session);
        }
        self.sessions
            .get_mut(destination)
            .ok_or(BrokerError::Unreachable)
    }

    fn call<R: Call>(
        &mut self,
        destination: &Destination,
        request: &R,
    ) -> Result<R::Response, BrokerError> {
        let result = self.session(destination)?.call(request);
        if matches!(result, Err(BrokerError::Unreachable | BrokerError::Invalid)) {
            self.sessions.remove(destination);
        }
        result
    }
}

/// A request this client sends, the response it expects, and the versions
/// it can speak. The negotiated version is the highest the broker shares.
trait Call: Encodable + HeaderVersion + Message {
    const KEY: ApiKey;
    const SPOKEN: VersionRange;
    type Response: Decodable + HeaderVersion;
}

macro_rules! call {
    ($request:ty, $response:ty, $key:ident, $min:literal ..= $max:literal) => {
        impl Call for $request {
            const KEY: ApiKey = ApiKey::$key;
            const SPOKEN: VersionRange = VersionRange {
                min: $min,
                max: $max,
            };
            type Response = $response;
        }
    };
}

// Versions 0 are answered by every broker; later ones are the oldest that
// recent brokers still serve. Fetch stops at 12: 13 names topics by id.
call!(ApiVersionsRequest, ApiVersionsResponse, ApiVersions, 0..=0);
call!(
    SaslHandshakeRequest,
    SaslHandshakeResponse,
    SaslHandshake,
    1..=1
);
call!(
    SaslAuthenticateRequest,
    SaslAuthenticateResponse,
    SaslAuthenticate,
    0..=2
);
call!(MetadataRequest, MetadataResponse, Metadata, 1..=12);
call!(ListOffsetsRequest, ListOffsetsResponse, ListOffsets, 1..=7);
call!(FetchRequest, FetchResponse, Fetch, 4..=12);

/// One authenticated connection to one broker.
struct Session {
    stream: Stream,
    correlation: i32,
    /// Versions the broker serves, by API key.
    versions: BTreeMap<i16, VersionRange>,
}

impl Session {
    /// Checks the destination, then dials, negotiates versions and
    /// authenticates. Nothing is dialed when the check refuses.
    fn open(destination: &Destination, config: &BrokerConfig) -> Result<Self, BrokerError> {
        let port = destination.port.ok_or(BrokerError::EgressRefused)?;
        if !config.egress.permits(destination) {
            return Err(BrokerError::EgressRefused);
        }
        if config.tls.is_none() && !is_loopback(&destination.host) {
            return Err(BrokerError::TlsRequired);
        }
        let tcp = (destination.host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| BrokerError::Unreachable)?
            .find_map(|address| TcpStream::connect_timeout(&address, TIMEOUT).ok())
            .ok_or(BrokerError::Unreachable)?;
        tcp.set_read_timeout(Some(TIMEOUT))
            .and_then(|()| tcp.set_write_timeout(Some(TIMEOUT)))
            .map_err(|_| BrokerError::Unreachable)?;
        let stream = match &config.tls {
            Some(tls) => Stream::Tls(Box::new(
                tls.connect(&destination.host, tcp)
                    .map_err(|_| BrokerError::Unreachable)?,
            )),
            None => Stream::Plain(tcp),
        };
        let mut session = Self {
            stream,
            correlation: 0,
            versions: BTreeMap::new(),
        };
        let versions = session.call(&ApiVersionsRequest::default())?;
        error_code(versions.error_code)?;
        session.versions = versions
            .api_keys
            .iter()
            .map(|api| {
                let range = VersionRange {
                    min: api.min_version,
                    max: api.max_version,
                };
                (api.api_key, range)
            })
            .collect();
        if let Some(credential) = &config.credential {
            session.authenticate(credential)?;
        }
        Ok(session)
    }

    fn authenticate(&mut self, credential: &PlainCredential) -> Result<(), BrokerError> {
        let handshake = self.call(
            &SaslHandshakeRequest::default().with_mechanism(StrBytes::from_string("PLAIN".into())),
        )?;
        error_code(handshake.error_code).map_err(|_| BrokerError::AuthFailed)?;
        let mut token = BytesMut::new();
        for part in ["", &credential.username, credential.password.expose()] {
            token.extend_from_slice(part.as_bytes());
            token.extend_from_slice(b"\0");
        }
        token.truncate(token.len() - 1);
        let response =
            self.call(&SaslAuthenticateRequest::default().with_auth_bytes(token.freeze()))?;
        error_code(response.error_code).map_err(|_| BrokerError::AuthFailed)
    }

    fn call<R: Call>(&mut self, request: &R) -> Result<R::Response, BrokerError> {
        let version = self.version::<R>()?;
        self.correlation = self.correlation.wrapping_add(1);
        let header = RequestHeader::default()
            .with_request_api_key(R::KEY as i16)
            .with_request_api_version(version)
            .with_correlation_id(self.correlation)
            .with_client_id(Some(StrBytes::from_string(CLIENT_ID.into())));
        let mut frame = BytesMut::new();
        frame.extend_from_slice(&[0; 4]);
        header
            .encode(&mut frame, R::header_version(version))
            .and_then(|()| request.encode(&mut frame, version))
            .map_err(|_| BrokerError::Invalid)?;
        let length = u32::try_from(frame.len() - 4).map_err(|_| BrokerError::Invalid)?;
        frame[..4].copy_from_slice(&length.to_be_bytes());
        self.stream
            .write_all(&frame)
            .map_err(|_| BrokerError::Unreachable)?;

        let mut length = [0; 4];
        self.stream
            .read_exact(&mut length)
            .map_err(|_| BrokerError::Unreachable)?;
        let length =
            usize::try_from(i32::from_be_bytes(length)).map_err(|_| BrokerError::Invalid)?;
        if length > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid);
        }
        let mut payload = vec![0; length];
        self.stream
            .read_exact(&mut payload)
            .map_err(|_| BrokerError::Unreachable)?;
        let mut payload = Bytes::from(payload);
        let header = ResponseHeader::decode(&mut payload, R::Response::header_version(version))
            .map_err(|_| BrokerError::Invalid)?;
        if header.correlation_id != self.correlation {
            return Err(BrokerError::Invalid);
        }
        R::Response::decode(&mut payload, version).map_err(|_| BrokerError::Invalid)
    }

    /// The highest version both sides speak. ApiVersions itself goes out
    /// at version 0, before the broker's versions are known.
    fn version<R: Call>(&self) -> Result<i16, BrokerError> {
        let spoken = R::SPOKEN.intersect(&R::VERSIONS);
        let shared = match R::KEY {
            ApiKey::ApiVersions => spoken,
            key => self
                .versions
                .get(&(key as i16))
                .ok_or(BrokerError::Invalid)?
                .intersect(&spoken),
        };
        (!shared.is_empty())
            .then_some(shared.max)
            .ok_or(BrokerError::Invalid)
    }
}

/// Decodes the record batches of one fetched partition. Returns records
/// at or after `from` and the offset after the last complete batch, or
/// `from` when there is none. A truncated last batch is left for the next
/// fetch, as brokers cut responses at the byte limit.
pub(crate) fn decode_records(
    mut records: Bytes,
    from: i64,
) -> Result<(Vec<FetchedRecord>, i64), BrokerError> {
    // base offset (8), length (4), leader epoch (4), magic (1), crc (4),
    // attributes (2), last offset delta (4): the batch header's prefix.
    const PREFIX: usize = 27;
    let mut fetched = Vec::new();
    let mut next_offset = from;
    while records.len() >= PREFIX {
        let mut header = &records[..PREFIX];
        let base_offset = header.get_i64();
        let length = usize::try_from(header.get_i32()).map_err(|_| BrokerError::Invalid)?;
        if records.len() < 12 + length {
            break;
        }
        header.advance(4);
        if header.get_i8() != 2 {
            return Err(BrokerError::Invalid);
        }
        header.advance(6);
        let last_offset = base_offset + i64::from(header.get_i32());
        let mut batch = records.split_to(12 + length);
        let set = RecordBatchDecoder::decode_with_custom_compression(
            &mut batch,
            Some(|compressed: &mut Bytes, compression| {
                codec::decompress(compressed, compression).map_err(Into::into)
            }),
        )
        .map_err(|_| BrokerError::Invalid)?;
        fetched.extend(
            set.records
                .into_iter()
                .filter(|record| !record.control && record.offset >= from)
                .map(|record| FetchedRecord {
                    offset: record.offset,
                    key: record.key,
                    value: record.value,
                }),
        );
        next_offset = next_offset.max(last_offset + 1);
    }
    Ok((fetched, next_offset))
}

/// Maps a broker error code onto the client's errors.
fn error_code(code: i16) -> Result<(), BrokerError> {
    match code {
        0 => Ok(()),
        1 => Err(BrokerError::OffsetOutOfRange),
        3 => Err(BrokerError::UnknownTopic),
        5 | 6 | 74 | 75 => Err(BrokerError::LeaderMoved),
        29 | 31 => Err(BrokerError::PermissionMissing),
        33 | 34 | 58 => Err(BrokerError::AuthFailed),
        _ => Err(BrokerError::Invalid),
    }
}

/// The destination of an advertised broker: a bare host the allowlist can
/// name and a valid port, or `None`. A host carrying a port, path or
/// scheme of its own is refused rather than reinterpreted.
fn advertised(host: &str, port: i32) -> Option<Destination> {
    let port = u16::try_from(port).ok().filter(|port| *port != 0)?;
    Destination::parse(host)
        .filter(|parsed| parsed.port.is_none() && parsed.host == host.to_ascii_lowercase())
        .map(|parsed| Destination {
            host: parsed.host,
            port: Some(port),
        })
}

/// `localhost`, or a loopback IP literal: the only brokers reached
/// without TLS.
fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn topic_name(topic: &str) -> TopicName {
    TopicName(StrBytes::from_string(topic.to_owned()))
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}
