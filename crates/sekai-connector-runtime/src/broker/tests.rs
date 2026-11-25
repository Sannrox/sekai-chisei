//! The client against an in-process fake broker on `127.0.0.1:0`, and the
//! record decoder against batches written with each codec.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use bytes::{Bytes, BytesMut};
use kafka_protocol::indexmap::IndexMap;
use kafka_protocol::messages::api_versions_response::{ApiVersion, ApiVersionsResponse};
use kafka_protocol::messages::fetch_response::{
    FetchResponse, FetchableTopicResponse, PartitionData,
};
use kafka_protocol::messages::list_offsets_response::{
    ListOffsetsPartitionResponse, ListOffsetsResponse, ListOffsetsTopicResponse,
};
use kafka_protocol::messages::metadata_response::{
    MetadataResponse, MetadataResponseBroker, MetadataResponsePartition, MetadataResponseTopic,
};
use kafka_protocol::messages::sasl_authenticate_response::SaslAuthenticateResponse;
use kafka_protocol::messages::sasl_handshake_response::SaslHandshakeResponse;
use kafka_protocol::messages::*;
use kafka_protocol::protocol::{Decodable, Encodable, StrBytes, decode_request_header_from_buffer};
use kafka_protocol::records::{
    Compression, Record, RecordBatchEncoder, RecordEncodeOptions, TimestampType,
};

use super::*;

const TOPIC: &str = "events";

/// What the fake broker serves. Each accepted connection is counted.
struct Fake {
    /// Advertised brokers: node id, host, port (0 means this broker's own).
    brokers: Vec<(i32, &'static str, i32)>,
    /// Partition index and leader node.
    partitions: Vec<(i32, i32)>,
    offsets: Offsets,
    records: Bytes,
    password: &'static str,
    /// API key and version of every request after ApiVersions.
    seen: Mutex<Vec<(i16, i16)>>,
    accepted: AtomicUsize,
}

impl Fake {
    fn new() -> Self {
        Self {
            brokers: vec![(1, "127.0.0.1", 0)],
            partitions: vec![(1, 1), (0, 1)],
            offsets: Offsets {
                earliest: 3,
                latest: 9,
            },
            records: Bytes::new(),
            password: "secret",
            seen: Mutex::new(Vec::new()),
            accepted: AtomicUsize::new(0),
        }
    }

    /// Serves `self` on an ephemeral loopback port; returns the port.
    fn serve(self: &Arc<Self>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let fake = Arc::clone(self);
        thread::spawn(move || {
            for stream in listener.incoming() {
                fake.accepted.fetch_add(1, Ordering::SeqCst);
                let fake = Arc::clone(&fake);
                thread::spawn(move || fake.connection(stream.unwrap(), port));
            }
        });
        port
    }

    fn connection(&self, mut stream: TcpStream, port: u16) {
        loop {
            let mut length = [0; 4];
            if stream.read_exact(&mut length).is_err() {
                return;
            }
            let mut frame = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut frame).unwrap();
            let mut frame = Bytes::from(frame);
            let header = decode_request_header_from_buffer(&mut frame).unwrap();
            let key = ApiKey::try_from(header.request_api_key).unwrap();
            let version = header.request_api_version;
            if key != ApiKey::ApiVersions {
                self.seen.lock().unwrap().push((key as i16, version));
            }
            let mut body = BytesMut::new();
            match key {
                ApiKey::ApiVersions => {
                    let api = |key: ApiKey, max| {
                        ApiVersion::default()
                            .with_api_key(key as i16)
                            .with_min_version(0)
                            .with_max_version(max)
                    };
                    ApiVersionsResponse::default()
                        .with_api_keys(vec![
                            api(ApiKey::SaslHandshake, 1),
                            api(ApiKey::SaslAuthenticate, 2),
                            api(ApiKey::Metadata, 13),
                            api(ApiKey::ListOffsets, 10),
                            api(ApiKey::Fetch, 17),
                        ])
                        .encode(&mut body, version)
                }
                ApiKey::SaslHandshake => SaslHandshakeResponse::default()
                    .with_mechanisms(vec![StrBytes::from_string("PLAIN".into())])
                    .encode(&mut body, version),
                ApiKey::SaslAuthenticate => {
                    let request = SaslAuthenticateRequest::decode(&mut frame, version).unwrap();
                    let expected = format!("\0user\0{}", self.password);
                    let code = if request.auth_bytes[..] == *expected.as_bytes() {
                        0
                    } else {
                        58
                    };
                    SaslAuthenticateResponse::default()
                        .with_error_code(code)
                        .encode(&mut body, version)
                }
                ApiKey::Metadata => {
                    let brokers = self
                        .brokers
                        .iter()
                        .map(|(node, host, advertised)| {
                            MetadataResponseBroker::default()
                                .with_node_id(BrokerId(*node))
                                .with_host(StrBytes::from_string((*host).into()))
                                .with_port(if *advertised == 0 {
                                    i32::from(port)
                                } else {
                                    *advertised
                                })
                        })
                        .collect();
                    let partitions = self
                        .partitions
                        .iter()
                        .map(|(index, leader)| {
                            MetadataResponsePartition::default()
                                .with_partition_index(*index)
                                .with_leader_id(BrokerId(*leader))
                        })
                        .collect();
                    MetadataResponse::default()
                        .with_brokers(brokers)
                        .with_topics(vec![
                            MetadataResponseTopic::default()
                                .with_name(Some(topic_name(TOPIC)))
                                .with_partitions(partitions),
                        ])
                        .encode(&mut body, version)
                }
                ApiKey::ListOffsets => {
                    let request = ListOffsetsRequest::decode(&mut frame, version).unwrap();
                    let asked = &request.topics[0].partitions[0];
                    let offset = match asked.timestamp {
                        EARLIEST => self.offsets.earliest,
                        _ => self.offsets.latest,
                    };
                    ListOffsetsResponse::default()
                        .with_topics(vec![
                            ListOffsetsTopicResponse::default()
                                .with_name(topic_name(TOPIC))
                                .with_partitions(vec![
                                    ListOffsetsPartitionResponse::default()
                                        .with_partition_index(asked.partition_index)
                                        .with_offset(offset),
                                ]),
                        ])
                        .encode(&mut body, version)
                }
                ApiKey::Fetch => {
                    let request = FetchRequest::decode(&mut frame, version).unwrap();
                    let asked = &request.topics[0].partitions[0];
                    let code = if asked.fetch_offset < self.offsets.earliest {
                        1
                    } else {
                        0
                    };
                    FetchResponse::default()
                        .with_responses(vec![
                            FetchableTopicResponse::default()
                                .with_topic(topic_name(TOPIC))
                                .with_partitions(vec![
                                    PartitionData::default()
                                        .with_partition_index(asked.partition)
                                        .with_error_code(code)
                                        .with_high_watermark(self.offsets.latest)
                                        .with_records(Some(self.records.clone())),
                                ]),
                        ])
                        .encode(&mut body, version)
                }
                other => panic!("unexpected request {other:?}"),
            }
            .unwrap();
            let mut response = BytesMut::new();
            ResponseHeader::default()
                .with_correlation_id(header.correlation_id)
                .encode(&mut response, key.response_header_version(version))
                .unwrap();
            response.extend_from_slice(&body);
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        }
    }
}

fn config(port: u16, egress: &[String], password: &str) -> BrokerConfig {
    BrokerConfig {
        bootstrap: Destination::parse(&format!("127.0.0.1:{port}")).unwrap(),
        egress: EgressAllowlist::parse(egress).unwrap(),
        tls: None,
        credential: Some(PlainCredential {
            username: "user".into(),
            password: Secret(password.into()),
        }),
    }
}

fn record(offset: i64, value: &str, control: bool) -> Record {
    Record {
        transactional: control,
        control,
        delete_horizon: false,
        partition_leader_epoch: 0,
        producer_id: -1,
        producer_epoch: -1,
        timestamp_type: TimestampType::Creation,
        offset,
        sequence: -1,
        timestamp: 0,
        key: Some(Bytes::from(format!("k{offset}"))),
        value: Some(Bytes::from(value.to_owned())),
        headers: IndexMap::default(),
    }
}

/// One v2 batch of `records`, compressed with `compression` by the
/// runtime's own codec crates.
fn batch(records: &[Record], compression: Compression) -> Bytes {
    let mut out = BytesMut::new();
    RecordBatchEncoder::encode_with_custom_compression(
        &mut out,
        records,
        &RecordEncodeOptions {
            version: 2,
            compression,
        },
        Some(|plain: &mut BytesMut, out: &mut BytesMut, compression| {
            out.extend_from_slice(&compress(plain, compression));
            Ok(())
        }),
    )
    .unwrap();
    out.freeze()
}

fn compress(plain: &[u8], compression: Compression) -> Vec<u8> {
    match compression {
        Compression::None => plain.to_vec(),
        Compression::Gzip => {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(plain).unwrap();
            encoder.finish().unwrap()
        }
        Compression::Snappy => {
            // The xerial framing: magic, two versions, then one block.
            let block = snap::raw::Encoder::new().compress_vec(plain).unwrap();
            let mut out = b"\x82SNAPPY\0\0\0\0\x01\0\0\0\x01".to_vec();
            out.extend_from_slice(&(block.len() as u32).to_be_bytes());
            out.extend_from_slice(&block);
            out
        }
        Compression::Lz4 => {
            let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
            encoder.write_all(plain).unwrap();
            encoder.finish().unwrap()
        }
        Compression::Zstd => {
            ruzstd::encoding::compress_to_vec(plain, ruzstd::encoding::CompressionLevel::Fastest)
        }
    }
}

#[test]
fn reads_partitions_offsets_and_records_from_the_advertised_leader() {
    let mut fake = Fake::new();
    let mut records = BytesMut::new();
    records.extend_from_slice(&batch(
        &[record(3, "{\"a\":3}", false), record(4, "{\"a\":4}", false)],
        Compression::None,
    ));
    records.extend_from_slice(&batch(&[record(5, "", true)], Compression::None));
    let last = batch(&[record(6, "{\"a\":6}", false)], Compression::Gzip);
    records.extend_from_slice(&last);
    // A batch cut at the response's byte limit waits for the next fetch.
    records.extend_from_slice(&batch(&[record(7, "{\"a\":7}", false)], Compression::None)[..40]);
    fake.records = records.freeze();
    let fake = Arc::new(fake);
    let port = fake.serve();

    let mut cluster =
        Cluster::connect(config(port, &[format!("127.0.0.1:{port}")], "secret")).unwrap();
    assert_eq!(cluster.partitions(TOPIC).unwrap(), vec![0, 1]);
    assert_eq!(
        cluster.offsets(TOPIC, 0).unwrap(),
        Offsets {
            earliest: 3,
            latest: 9
        }
    );
    let fetched = cluster.fetch(TOPIC, 0, 4).unwrap();
    let offsets: Vec<_> = fetched.records.iter().map(|record| record.offset).collect();
    assert_eq!(
        offsets,
        vec![4, 6],
        "before the asked offset and control records are dropped"
    );
    assert_eq!(fetched.records[1].value.as_deref(), Some(&b"{\"a\":6}"[..]));
    assert_eq!(fetched.next_offset, 7);
    assert_eq!(fetched.high_watermark, 9);
    assert_eq!(
        cluster.fetch(TOPIC, 0, 1),
        Err(BrokerError::OffsetOutOfRange)
    );
    assert_eq!(cluster.partitions("other"), Err(BrokerError::Invalid));

    let seen = fake.seen.lock().unwrap().clone();
    let version = |key: ApiKey| seen.iter().find(|(seen, _)| *seen == key as i16).unwrap().1;
    assert_eq!(version(ApiKey::Metadata), 12);
    assert_eq!(version(ApiKey::ListOffsets), 7);
    assert_eq!(version(ApiKey::Fetch), 12, "fetch stays on topic names");
    assert_eq!(
        fake.accepted.load(Ordering::SeqCst),
        1,
        "the leader is the bootstrap broker, so one connection serves every call"
    );
}

#[test]
fn a_wrong_password_fails_authentication() {
    let fake = Arc::new(Fake::new());
    let port = fake.serve();
    let refused = Cluster::connect(config(port, &[format!("127.0.0.1:{port}")], "wrong"));
    assert_eq!(refused.err(), Some(BrokerError::AuthFailed));
}

#[test]
fn an_advertised_broker_outside_the_allowlist_is_never_dialed() {
    // The leader listens on loopback but is not in the allowlist.
    let leader = Arc::new(Fake::new());
    let leader_port = leader.serve();
    let mut fake = Fake::new();
    fake.brokers = vec![
        (1, "127.0.0.1", 0),
        (2, "localhost", i32::from(leader_port)),
    ];
    fake.partitions = vec![(0, 2)];
    let fake = Arc::new(fake);
    let port = fake.serve();

    let egress = [format!("127.0.0.1:{port}"), "localhost:1".to_owned()];
    let mut cluster = Cluster::connect(config(port, &egress, "secret")).unwrap();
    assert_eq!(cluster.partitions(TOPIC).unwrap(), vec![0]);
    assert_eq!(cluster.fetch(TOPIC, 0, 3), Err(BrokerError::EgressRefused));
    assert_eq!(cluster.offsets(TOPIC, 0), Err(BrokerError::EgressRefused));
    assert_eq!(leader.accepted.load(Ordering::SeqCst), 0);
}

#[test]
fn a_broker_off_loopback_without_tls_is_refused_before_dialing() {
    // A documentation address: allowlisted, so only the TLS rule refuses it.
    let mut config = config(9092, &["192.0.2.10:9092".to_owned()], "secret");
    config.bootstrap = Destination::parse("192.0.2.10:9092").unwrap();
    assert_eq!(
        Cluster::connect(config).err(),
        Some(BrokerError::TlsRequired)
    );
    assert!(is_loopback("localhost") && is_loopback("127.0.0.2") && !is_loopback("192.0.2.10"));
}

#[test]
fn an_advertised_host_must_be_a_bare_name_the_allowlist_can_match() {
    assert_eq!(
        advertised("Broker-1.Internal", 9093),
        Destination::parse("broker-1.internal:9093")
    );
    for host in ["::1", "a:1", "http://a", "a/b", ""] {
        assert_eq!(advertised(host, 9092), None, "{host}");
    }
    assert_eq!(advertised("a", 0), None);
    assert_eq!(advertised("a", 70000), None);
}

#[test]
fn each_codec_decodes_and_an_oversized_batch_is_refused() {
    let records = [
        record(10, "{\"x\":1}", false),
        record(11, "{\"x\":2}", false),
    ];
    for compression in [
        Compression::None,
        Compression::Gzip,
        Compression::Snappy,
        Compression::Lz4,
        Compression::Zstd,
    ] {
        let (fetched, next) = decode_records(batch(&records, compression), 10).unwrap();
        let values: Vec<_> = fetched.iter().map(|record| record.value.clone()).collect();
        assert_eq!(
            values,
            vec![records[0].value.clone(), records[1].value.clone()],
            "{compression:?}"
        );
        assert_eq!(next, 12);
    }

    // Raw snappy without the xerial framing decodes too.
    let raw = snap::raw::Encoder::new().compress_vec(b"plain").unwrap();
    let decoded = codec::decompress(&mut Bytes::from(raw), Compression::Snappy).unwrap();
    assert_eq!(&decoded[..], b"plain");

    let bomb = compress(&vec![0; codec::MAX_BATCH_BYTES + 1], Compression::Gzip);
    assert!(codec::decompress(&mut Bytes::from(bomb), Compression::Gzip).is_err());
}
