//! The type against the in-process fake broker on `127.0.0.1:0`, and,
//! ignored, against a real one (see [`real_broker`]).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::BytesMut;
use kafka_protocol::records::Compression;
use sekai_source_sdk::{EVENT_STREAM_CONNECTOR, SourceConfig};

use super::*;
use crate::broker::tests::{Fake, TOPIC, batch, record, test_password};

fn config(port: u16, extra: &[(&str, ConfigValue)]) -> SourceConfig {
    let text = |value: &str| ConfigValue::Text(value.into());
    let mut config = SourceConfig::from([
        ("bootstrap".into(), text(&format!("127.0.0.1:{port}"))),
        ("tls".into(), ConfigValue::Boolean(false)),
        ("topic".into(), text(TOPIC)),
        ("record_kind".into(), text("Order")),
        ("type_digest".into(), text("sha256:orders")),
        ("id_field".into(), text("id")),
        ("fields".into(), text("n, status")),
        ("username".into(), text("user")),
    ]);
    config.extend(
        extra
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone())),
    );
    config
}

fn prepared(config: SourceConfig, egress: &[String], password: &str) -> Prepared {
    EVENT_STREAM_CONNECTOR.validate_config(&config).unwrap();
    Prepared {
        connector: &EVENT_STREAM_CONNECTOR,
        source_instance: "orders".into(),
        config,
        egress: EgressAllowlist::parse(egress).unwrap(),
        credentials: BTreeMap::from([("password".into(), Secret(password.into()))]),
    }
}

fn connect(port: u16, extra: &[(&str, ConfigValue)], password: &str) -> EventStream {
    let prepared = prepared(
        config(port, extra),
        &[format!("127.0.0.1:{port}")],
        password,
    );
    open_event_stream(&prepared, &TlsConnector::new().unwrap()).unwrap()
}

fn page(read: SnapshotRead) -> SnapshotPage {
    match read {
        SnapshotRead::Page(page) => page,
        SnapshotRead::Complete => panic!("expected a page"),
    }
}

/// `(id, version, n)` of each record of a page.
fn records(page: &SnapshotPage) -> Vec<(String, String, Option<PropertyValue>)> {
    page.records
        .iter()
        .map(|record| {
            (
                record.external_id.clone(),
                record.source_version.clone(),
                record.properties.get("n").cloned(),
            )
        })
        .collect()
}

/// One partition, offsets 3 to 8, each batch in another codec.
fn topic() -> Fake {
    let mut fake = Fake::new();
    fake.partitions = vec![(0, 1)];
    let mut log = BytesMut::new();
    for (offset, value, compression) in [
        (3, r#"{"id":"a","n":1,"secret":"x"}"#, Compression::None),
        (4, r#"{"id":"b","n":2}"#, Compression::Gzip),
        (5, "not json", Compression::Snappy),
        (6, r#"{"n":3}"#, Compression::Lz4),
        (7, r#"{"id":"a","n":4}"#, Compression::Zstd),
        (8, r#"{"id":"c","status":"open"}"#, Compression::None),
    ] {
        log.extend_from_slice(&batch(&[record(offset, value, false)], compression));
    }
    fake.records = log.freeze();
    fake
}

#[test]
fn a_scan_reads_from_the_earliest_offset_and_a_new_holder_resumes_from_the_cursor() {
    let fake = Arc::new(topic());
    let port = fake.serve();
    let mut first = connect(port, &[], &fake.password);

    let one = page(first.read_page(None, 2).unwrap());
    assert_eq!(
        records(&one),
        vec![
            ("a".into(), "0-3".into(), Some(PropertyValue::Int(1))),
            ("b".into(), "0-4".into(), Some(PropertyValue::Int(2))),
        ],
        "only the configured fields become properties"
    );
    assert_eq!(one.proposed_next_cursor, "event_stream-v1|0=5");
    assert!(!one.complete && one.notes.is_empty());

    // The runtime died before committing: the page reads the same again.
    let again = page(first.read_page(None, 2).unwrap());
    assert_eq!(records(&again), records(&one));
    assert_eq!(again.proposed_next_cursor, one.proposed_next_cursor);

    // Another runtime takes over from the committed cursor.
    let mut second = connect(port, &[], &fake.password);
    let two = page(
        second
            .read_page(Some(&one.proposed_next_cursor), 2)
            .unwrap(),
    );
    assert_eq!(
        records(&two),
        vec![
            ("a".into(), "0-7".into(), Some(PropertyValue::Int(4))),
            ("c".into(), "0-8".into(), None),
        ],
        "bad records are skipped and later ones still apply"
    );
    assert_eq!(
        two.notes,
        vec![
            SyncNote::SkippedRecord {
                partition: 0,
                offset: 5,
                reason: SkipReason::NotJson
            },
            SyncNote::SkippedRecord {
                partition: 0,
                offset: 6,
                reason: SkipReason::MissingId
            },
        ]
    );
    assert!(two.complete);
    assert_eq!(two.proposed_next_cursor, "event_stream-v1|0=9");
    assert_eq!(
        second
            .read_page(Some(&two.proposed_next_cursor), 2)
            .unwrap(),
        SnapshotRead::Complete
    );

    // One page keeps the latest record per id.
    let whole = page(second.read_page(None, 10).unwrap());
    assert_eq!(
        records(&whole)
            .into_iter()
            .map(|(id, version, _)| (id, version))
            .collect::<Vec<_>>(),
        vec![
            ("a".into(), "0-7".into()),
            ("b".into(), "0-4".into()),
            ("c".into(), "0-8".into())
        ]
    );
}

/// The pages as the runtime applies them, under the SDK's batch contract.
fn batches(pages: &[SnapshotPage]) -> Vec<sekai_source_sdk::SourceBatch> {
    let adapter = sekai_source_sdk::SourceAdapterConfig {
        namespace: "ops".into(),
        producer_identity: "runtime".into(),
        source_instance: "orders".into(),
        type_digest: format!("sha256:{}", "0".repeat(64)),
    };
    let mut current = String::new();
    pages
        .iter()
        .map(|page| {
            let mut records = page.records.clone();
            for record in &mut records {
                record.source = "orders-stream".into();
                record.source_instance = "orders".into();
            }
            let batch = sekai_source_sdk::build_registered_source_batch(
                &adapter,
                "orders-stream",
                &current,
                &page.proposed_next_cursor,
                page.collected_at_ms,
                records,
            )
            .unwrap();
            current = page.proposed_next_cursor.clone();
            batch
        })
        .collect()
}

#[test]
fn its_pages_pass_the_sdk_conformance_checks() {
    use sekai_source_sdk::conformance::{
        assert_cross_page_identity, assert_deterministic_batch, assert_snapshot_chain,
    };
    let fake = Arc::new(topic());
    let port = fake.serve();
    let mut stream = connect(port, &[], &fake.password);
    let one = page(stream.read_page(None, 2).unwrap());
    let two = page(
        stream
            .read_page(Some(&one.proposed_next_cursor), 2)
            .unwrap(),
    );
    let chain = batches(&[one.clone(), two]);
    assert_snapshot_chain(&chain).unwrap();
    let mut again = page(stream.read_page(None, 2).unwrap());
    again.collected_at_ms = one.collected_at_ms;
    for record in &mut again.records {
        record.observed_at_ms = one.records[0].observed_at_ms;
    }
    assert_deterministic_batch(&chain[0], &batches(&[again])[0]).unwrap();
    let a = &chain[0].records[0];
    assert_cross_page_identity(&chain[0], &chain[1], &a.source_id()).unwrap();
}

#[test]
fn an_offset_retention_passed_resumes_at_the_earliest_and_notes_the_gap() {
    let fake = Arc::new(topic());
    let port = fake.serve();
    let mut stream = connect(port, &[], &fake.password);
    let resumed = page(stream.read_page(Some("event_stream-v1|0=1"), 1).unwrap());
    assert_eq!(resumed.records[0].source_version, "0-3");
    assert_eq!(
        resumed.notes,
        vec![SyncNote::OffsetGap {
            partition: 0,
            from_offset: 1,
            to_offset: 3
        }]
    );
    // An offset past the partition's end is not guessed at.
    assert_eq!(
        stream.read_page(Some("event_stream-v1|0=99"), 1),
        Err(ConnectorFailure::Invalid)
    );
}

#[test]
fn check_reports_a_typed_reason() {
    let fake = Arc::new(topic());
    let port = fake.serve();
    assert_eq!(connect(port, &[], &fake.password).check(), Ok(()));
    let wrong = format!("{}-other", fake.password);
    assert_eq!(
        connect(port, &[], &wrong).check(),
        Err(ConnectorFailure::AuthFailed)
    );
    let other = [("topic", ConfigValue::Text("other".into()))];
    assert_eq!(
        connect(port, &other, &fake.password).check(),
        Err(ConnectorFailure::Invalid)
    );
    let missing = [("partitions", ConfigValue::Text("0,7".into()))];
    assert_eq!(
        connect(port, &missing, &fake.password).check(),
        Err(ConnectorFailure::Invalid)
    );
    // Nothing listens there.
    assert_eq!(
        connect(1, &[], &fake.password).check(),
        Err(ConnectorFailure::Unreachable)
    );
}

#[test]
fn an_advertised_broker_outside_the_allowlist_is_never_dialed() {
    let leader = Arc::new(topic());
    let leader_port = leader.serve();
    let mut fake = topic();
    fake.brokers = vec![
        (1, "127.0.0.1", 0),
        (2, "localhost", i32::from(leader_port)),
    ];
    fake.partitions = vec![(0, 2)];
    let fake = Arc::new(fake);
    let port = fake.serve();
    let mut stream = connect(port, &[], &fake.password);
    assert_eq!(stream.read_page(None, 10), Err(ConnectorFailure::Invalid));
    assert_eq!(leader.accepted.load(Ordering::SeqCst), 0);
}

#[test]
fn a_configuration_that_carries_a_credential_or_names_one_is_refused() {
    let password = test_password();
    // A credential value in any field is refused by the type's schema.
    let mut carried = config(9, &[]);
    carried.insert(
        "topic".into(),
        ConfigValue::Text(format!("{}={password}", "password")),
    );
    assert!(EVENT_STREAM_CONNECTOR.validate_config(&carried).is_err());

    let open = |extra: &[(&str, ConfigValue)]| {
        let prepared = prepared(config(9, extra), &["127.0.0.1:9".into()], &password);
        open_event_stream(&prepared, &TlsConnector::new().unwrap()).err()
    };
    let text = |value: &str| ConfigValue::Text(value.into());
    for (name, value) in [
        ("fields", text("n, password")),
        ("fields", text("Status")),
        ("id_field", text("api_key")),
        ("partitions", text("0,-1")),
        ("partitions", text("x")),
        (
            "partitions",
            text(
                &(0..=64)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ),
        ("bootstrap", text("127.0.0.1")),
    ] {
        assert_eq!(
            open(&[(name, value)]),
            Some(ConnectorFailure::Invalid),
            "{name}"
        );
    }

    // A username needs the password slot, and the slot needs a username.
    let mut no_password = prepared(config(9, &[]), &["127.0.0.1:9".into()], &password);
    no_password.credentials.clear();
    assert_eq!(
        open_event_stream(&no_password, &TlsConnector::new().unwrap()).err(),
        Some(ConnectorFailure::AuthFailed)
    );
    let mut no_username = prepared(config(9, &[]), &["127.0.0.1:9".into()], &password);
    no_username.config.remove("username");
    assert_eq!(
        open_event_stream(&no_username, &TlsConnector::new().unwrap()).err(),
        Some(ConnectorFailure::Invalid)
    );
}

#[test]
fn tls_is_on_unless_turned_off_and_required_off_loopback() {
    let password = test_password();
    let mut config = config(9092, &[]);
    config.remove("tls");
    config.insert(
        "bootstrap".into(),
        ConfigValue::Text("192.0.2.10:9092".into()),
    );
    let mut prepared = prepared(config, &["192.0.2.10:9092".into()], &password);
    let tls = TlsConnector::new().unwrap();
    assert!(open_event_stream(&prepared, &tls).unwrap().tls.is_some());
    prepared
        .config
        .insert("tls".into(), ConfigValue::Boolean(false));
    // Without TLS the documentation address is refused before any dial.
    assert_eq!(
        open_event_stream(&prepared, &tls).unwrap().check(),
        Err(ConnectorFailure::Invalid)
    );
}

#[test]
fn a_cursor_this_type_did_not_write_starts_over() {
    assert_eq!(parse_cursor("rest-v1|0|done"), None);
    assert_eq!(parse_cursor("event_stream-v1|0=x"), None);
    assert_eq!(parse_cursor("event_stream-v1|"), Some(BTreeMap::new()));
    let next = BTreeMap::from([(0, 5), (3, 12)]);
    assert_eq!(parse_cursor(&cursor(&next)), Some(next));
}

/// Against a real broker, ignored by default. Run with a broker listening
/// on loopback without authentication (`SEKAI_TEST_BROKER=127.0.0.1:9092`)
/// that lets clients create topics:
///
/// ```text
/// SEKAI_TEST_BROKER=127.0.0.1:9092 cargo test -p sekai-connector-runtime \
///     -- --ignored real_broker
/// ```
///
/// For the TLS handshake, also set `SEKAI_TEST_BROKER_TLS` to a TLS
/// listener of the same broker (`host:port`, named as its certificate is)
/// and `SEKAI_TEST_BROKER_CA` to the PEM file of the CA that signed it.
/// Each run writes to a topic of its own, so runs may share one broker.
mod real_broker {
    use super::*;
    use crate::broker::Cluster;
    use native_tls::Certificate;

    fn broker() -> String {
        std::env::var("SEKAI_TEST_BROKER").expect("SEKAI_TEST_BROKER")
    }

    fn stream(bootstrap: &str, topic: &str, tls: Option<TlsConnector>) -> EventStream {
        let text = |value: &str| ConfigValue::Text(value.into());
        let config = SourceConfig::from([
            ("bootstrap".into(), text(bootstrap)),
            ("tls".into(), ConfigValue::Boolean(tls.is_some())),
            ("topic".into(), text(topic)),
            ("record_kind".into(), text("Order")),
            ("type_digest".into(), text("sha256:orders")),
            ("id_field".into(), text("id")),
            ("fields".into(), text("n")),
        ]);
        EVENT_STREAM_CONNECTOR.validate_config(&config).unwrap();
        let destination = Destination::parse(bootstrap).unwrap();
        let prepared = Prepared {
            connector: &EVENT_STREAM_CONNECTOR,
            source_instance: "orders".into(),
            config,
            // The broker advertises itself by its own name: permit any port
            // of that host.
            egress: EgressAllowlist::parse(&[destination.host]).unwrap(),
            credentials: BTreeMap::new(),
        };
        open_event_stream(
            &prepared,
            &tls.unwrap_or_else(|| TlsConnector::new().unwrap()),
        )
        .unwrap()
    }

    /// Writes `values` to partition 0, one batch per codec in turn. A
    /// producer's batch starts at offset 0; the broker assigns offsets.
    fn produce(cluster: &mut Cluster, topic: &str, values: &[String]) {
        let codecs = [
            Compression::None,
            Compression::Gzip,
            Compression::Snappy,
            Compression::Lz4,
            Compression::Zstd,
        ];
        for (index, value) in values.iter().enumerate() {
            let compression = codecs[index % codecs.len()];
            cluster
                .produce(topic, 0, batch(&[record(0, value, false)], compression))
                .unwrap();
        }
    }

    /// Reads pages from `cursor` until complete, as the runtime does.
    fn sync(stream: &mut EventStream, mut cursor: Option<String>) -> (Vec<SnapshotPage>, String) {
        let mut pages = Vec::new();
        loop {
            match stream.read_page(cursor.as_deref(), 3).unwrap() {
                SnapshotRead::Complete => break,
                SnapshotRead::Page(page) => {
                    cursor = Some(page.proposed_next_cursor.clone());
                    let complete = page.complete;
                    pages.push(page);
                    if complete {
                        break;
                    }
                }
            }
        }
        (pages, cursor.unwrap())
    }

    #[test]
    #[ignore = "needs a local broker in SEKAI_TEST_BROKER"]
    fn real_broker_syncs_each_codec_resumes_and_skips_bad_records() {
        let bootstrap = broker();
        let topic = format!("sekai-it-{}-{}", std::process::id(), now_ms());
        let mut cluster = Cluster::connect(BrokerConfig {
            bootstrap: Destination::parse(&bootstrap).unwrap(),
            egress: EgressAllowlist::parse(&[Destination::parse(&bootstrap).unwrap().host])
                .unwrap(),
            tls: None,
            credential: None,
        })
        .unwrap();
        cluster.create_topic(&topic, 1).unwrap();
        cluster.partitions(&topic).unwrap();
        let first: Vec<_> = (0..7)
            .map(|n| match n {
                3 => "not json".to_string(),
                _ => format!(r#"{{"id":"o{n}","n":{n}}}"#),
            })
            .collect();
        produce(&mut cluster, &topic, &first);

        let mut stream = stream(&bootstrap, &topic, None);
        assert_eq!(stream.check(), Ok(()));
        let (pages, cursor) = sync(&mut stream, None);
        let mut ids: Vec<_> = pages.iter().flat_map(records).map(|(id, ..)| id).collect();
        ids.sort();
        assert_eq!(ids, ["o0", "o1", "o2", "o4", "o5", "o6"], "each once");
        let notes: Vec<_> = pages.iter().flat_map(|page| page.notes.clone()).collect();
        assert_eq!(
            notes,
            vec![SyncNote::SkippedRecord {
                partition: 0,
                offset: 3,
                reason: SkipReason::NotJson
            }]
        );

        // New records; a runtime killed mid-page leaves the cursor where it
        // was, and the one that takes over reads only what is new.
        let later: Vec<_> = (7..9)
            .map(|n| format!(r#"{{"id":"o{n}","n":{n}}}"#))
            .collect();
        produce(&mut cluster, &topic, &later);
        let uncommitted = page(stream.read_page(Some(&cursor), 3).unwrap());
        let mut takeover = self::stream(&bootstrap, &topic, None);
        let (pages, _) = sync(&mut takeover, Some(cursor));
        assert_eq!(records(&pages[0]), records(&uncommitted));
        let ids: Vec<_> = pages.iter().flat_map(records).map(|(id, ..)| id).collect();
        assert_eq!(ids, ["o7", "o8"]);
    }

    #[test]
    #[ignore = "needs a TLS listener in SEKAI_TEST_BROKER_TLS and its CA"]
    fn real_broker_check_completes_a_tls_handshake() {
        let bootstrap = std::env::var("SEKAI_TEST_BROKER_TLS").expect("SEKAI_TEST_BROKER_TLS");
        let ca =
            std::fs::read(std::env::var("SEKAI_TEST_BROKER_CA").expect("SEKAI_TEST_BROKER_CA"))
                .unwrap();
        let tls = TlsConnector::builder()
            .add_root_certificate(Certificate::from_pem(&ca).unwrap())
            .build()
            .unwrap();
        let topic = format!("sekai-it-tls-{}-{}", std::process::id(), now_ms());
        let mut stream = stream(&bootstrap, &topic, Some(tls));
        // The topic does not exist: a completed handshake reaches Metadata.
        assert_eq!(stream.check(), Err(ConnectorFailure::Invalid));
        stream.tls = Some(TlsConnector::new().unwrap());
        assert_eq!(
            stream.check(),
            Err(ConnectorFailure::Unreachable),
            "an untrusted certificate fails the handshake"
        );
    }
}
