//! The type against an in-process fake store on `127.0.0.1:0` and a fake
//! plane, and, ignored, against a real local store (see [`real_store`]).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use sekai_source_sdk::{
    ConfigError, EgressAllowlist, OBJECT_STORAGE_CONNECTOR, PlaneView, PlaneViewError,
    RecordVersion, SourceConfig,
};

use super::*;
use crate::credentials::Secret;

/// A key pair built at run time, so no credential is a literal.
fn key_pair() -> (String, String) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    (
        format!("id{}x{n}", std::process::id()),
        format!("sk{}x{n}", std::process::id()),
    )
}

/// How the fake store answers.
#[derive(Default)]
struct State {
    objects: BTreeMap<String, (Vec<u8>, String)>,
    fetched: BTreeMap<String, usize>,
    /// Refuses listings, as a key pair without list permission is.
    no_list: bool,
}

/// A path-style store with one bucket, `data`, that checks the access key
/// id of each request and lists at most two keys per page.
struct Fake {
    access_key_id: String,
    state: Mutex<State>,
}

impl Fake {
    fn new(access_key_id: &str) -> Arc<Self> {
        Arc::new(Self {
            access_key_id: access_key_id.into(),
            state: Mutex::default(),
        })
    }

    fn put(&self, key: &str, body: &str) {
        let mut state = self.state.lock().unwrap();
        let etag = format!("{:x}", Sha256::digest(body.as_bytes()))[..12].to_string();
        state
            .objects
            .insert(key.into(), (body.as_bytes().to_vec(), etag));
    }

    fn delete(&self, key: &str) {
        self.state.lock().unwrap().objects.remove(key);
    }

    fn fetched(&self, key: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .fetched
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    fn serve(self: &Arc<Self>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let fake = self.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let fake = fake.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }
                    let mut authorization = String::new();
                    loop {
                        let mut header = String::new();
                        reader.read_line(&mut header).unwrap();
                        if header.trim().is_empty() {
                            break;
                        }
                        if let Some((name, value)) = header.split_once(':')
                            && name.eq_ignore_ascii_case("authorization")
                        {
                            authorization = value.trim().into();
                        }
                    }
                    let target = line.split(' ').nth(1).unwrap_or_default().to_string();
                    let (status, body) = fake.answer(&target, &authorization);
                    let mut stream = stream;
                    let head = format!(
                        "HTTP/1.1 {status}\r\ncontent-length: {}\r\netag: \"{}\"\r\nconnection: close\r\n\r\n",
                        body.0.len(),
                        body.1
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body.0);
                });
            }
        });
        port
    }

    fn answer(&self, target: &str, authorization: &str) -> (&'static str, (Vec<u8>, String)) {
        let error = |status, code: &str| {
            (
                status,
                (
                    format!("<Error><Code>{code}</Code></Error>").into_bytes(),
                    String::new(),
                ),
            )
        };
        if !authorization.starts_with(&format!(
            "AWS4-HMAC-SHA256 Credential={}/",
            self.access_key_id
        )) {
            return error("403 Forbidden", "InvalidAccessKeyId");
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let query: BTreeMap<String, String> = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(name, value)| (decode(name), decode(value)))
            .collect();
        let mut state = self.state.lock().unwrap();
        if path == "/data/" {
            if state.no_list {
                return error("403 Forbidden", "AccessDenied");
            }
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            let after = query
                .get("continuation-token")
                .or(query.get("start-after"))
                .cloned()
                .unwrap_or_default();
            let max: usize = query["max-keys"].parse::<usize>().unwrap().min(2);
            let keys: Vec<_> = state
                .objects
                .iter()
                .filter(|(key, _)| key.starts_with(&prefix) && **key > after)
                .map(|(key, (_, etag))| (key.clone(), etag.clone()))
                .collect();
            let page = &keys[..max.min(keys.len())];
            let mut xml = String::from("<ListBucketResult>");
            for (key, etag) in page {
                xml += &format!(
                    "<Contents><Key>{}</Key><ETag>&quot;{etag}&quot;</ETag></Contents>",
                    key.replace('&', "&amp;")
                );
            }
            if keys.len() > page.len() {
                let last = &page.last().unwrap().0;
                xml += &format!(
                    "<IsTruncated>true</IsTruncated><NextContinuationToken>{}</NextContinuationToken>",
                    last.replace('&', "&amp;")
                );
            }
            xml += "</ListBucketResult>";
            return ("200 OK", (xml.into_bytes(), String::new()));
        }
        let key = decode(path.strip_prefix("/data/").unwrap_or_default());
        match state.objects.get(&key).cloned() {
            Some(object) => {
                *state.fetched.entry(key).or_default() += 1;
                ("200 OK", object)
            }
            None => error("404 Not Found", "NoSuchKey"),
        }
    }
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            out.push(u8::from_str_radix(&text[index + 1..index + 3], 16).unwrap());
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The plane's live records of the Source, kept as committed pages leave them.
#[derive(Default)]
struct Plane {
    /// `(object key, external id)` to version.
    live: BTreeMap<(String, String), String>,
    /// How often each `(external id, version, deleted)` was applied.
    applied: BTreeMap<(String, String, bool), usize>,
}

impl Plane {
    fn commit(&mut self, page: &SnapshotPage) {
        for record in &page.records {
            let key = (
                record.object_key.clone().unwrap(),
                record.external_id.clone(),
            );
            if record.deleted {
                self.live.remove(&key);
            } else {
                self.live.insert(key, record.source_version.clone());
            }
            *self
                .applied
                .entry((
                    record.external_id.clone(),
                    record.source_version.clone(),
                    record.deleted,
                ))
                .or_default() += 1;
        }
    }

    fn keys(&self) -> BTreeSet<String> {
        self.live.keys().map(|(key, _)| key.clone()).collect()
    }
}

impl PlaneView for Plane {
    fn record_versions(
        &mut self,
        range: KeyRange<'_>,
        limit: usize,
    ) -> Result<Vec<RecordVersion>, PlaneViewError> {
        Ok(self
            .live
            .iter()
            .filter(|((key, id), _)| match range.after_external_id {
                Some(after) => (key.as_str(), id.as_str()) > (range.after_object_key, after),
                None => key.as_str() > range.after_object_key,
            })
            .filter(|((key, _), _)| {
                range
                    .through_object_key
                    .is_none_or(|through| key.as_str() <= through)
            })
            .take(limit)
            .map(|((key, id), version)| RecordVersion {
                external_id: id.clone(),
                object_key: key.clone(),
                source_version: version.clone(),
            })
            .collect())
    }
}

fn config(endpoint: &str, extra: &[(&str, ConfigValue)]) -> SourceConfig {
    let text = |value: &str| ConfigValue::Text(value.into());
    let mut config = SourceConfig::from([
        ("endpoint".into(), text(endpoint)),
        ("region".into(), text("local")),
        ("bucket".into(), text("data")),
        ("prefix".into(), text("orders/")),
        ("path_style".into(), ConfigValue::Boolean(true)),
        ("record_kind".into(), text("Order")),
        ("type_digest".into(), text("sha256:orders")),
        ("id_column".into(), text("id")),
        ("fields".into(), text("n, status")),
    ]);
    config.extend(
        extra
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone())),
    );
    config
}

fn prepared(config: SourceConfig, egress: &[&str], pair: &(String, String)) -> Prepared {
    OBJECT_STORAGE_CONNECTOR.validate_config(&config).unwrap();
    Prepared {
        connector: &OBJECT_STORAGE_CONNECTOR,
        source_instance: "orders".into(),
        config,
        egress: EgressAllowlist::parse(egress).unwrap(),
        credentials: BTreeMap::from([(
            "access_key".into(),
            Secret(format!("{}:{}", pair.0, pair.1)),
        )]),
    }
}

fn connect(port: u16, pair: &(String, String)) -> ObjectStorage {
    let endpoint = format!("http://127.0.0.1:{port}");
    open_object_storage(&prepared(config(&endpoint, &[]), &["127.0.0.1"], pair)).unwrap()
}

fn page(read: SnapshotRead) -> SnapshotPage {
    match read {
        SnapshotRead::Page(page) => page,
        SnapshotRead::Complete => panic!("expected a page"),
    }
}

/// Reads and commits pages as the runtime does, until a page completes the
/// sync or would commit nothing; returns the pages committed and the
/// cursor the plane holds.
fn sync(
    storage: &mut ObjectStorage,
    plane: &mut Plane,
    cursor: &mut Option<String>,
    max_records: usize,
) -> Vec<SnapshotPage> {
    let mut pages = Vec::new();
    for _ in 0..50 {
        let read = page(
            storage
                .read_page_with_plane(cursor.as_deref(), max_records, plane)
                .unwrap(),
        );
        assert_ne!(Some(&read.proposed_next_cursor), cursor.as_ref());
        if read.records.is_empty() {
            assert!(read.complete, "only a last page may be empty");
            return pages;
        }
        plane.commit(&read);
        *cursor = Some(read.proposed_next_cursor.clone());
        let complete = read.complete;
        pages.push(read);
        if complete {
            return pages;
        }
    }
    panic!("the sync did not end");
}

/// `(object key, id column value)` of each live record.
fn rows(plane: &Plane, fake: &Fake) -> BTreeSet<(String, String)> {
    let state = fake.state.lock().unwrap();
    plane
        .live
        .keys()
        .map(|(key, external)| {
            let id = external.rsplit('.').next().unwrap().to_string();
            assert!(state.objects.contains_key(key), "{key} is live but gone");
            (key.clone(), id)
        })
        .collect()
}

fn store() -> ((String, String), Arc<Fake>, u16) {
    let pair = key_pair();
    let fake = Fake::new(&pair.0);
    fake.put(
        "orders/a.json",
        r#"[{"id":"1","n":1,"secret":"x"},{"id":"2","n":2}]"#,
    );
    fake.put("orders/b.json", r#"{"id":"1","status":"open"}"#);
    fake.put("orders/c.json", "{\"id\":\"9\"}\n{\"id\":\"8\"}\n");
    fake.put("other/x.json", r#"{"id":"1"}"#);
    let port = fake.serve();
    (pair, fake, port)
}

#[test]
fn a_mirror_syncs_skips_unchanged_objects_rewrites_changed_ones_and_tombstones_deletes() {
    let (pair, fake, port) = store();
    let (mut plane, mut cursor) = (Plane::default(), None);
    let mut storage = connect(port, &pair);

    let first = sync(&mut storage, &mut plane, &mut cursor, 2);
    assert_eq!(first.len(), 3, "five rows in pages of two");
    assert!(first.last().unwrap().complete);
    let a1 = &first[0].records[0];
    assert_eq!(a1.external_id, external_id("orders/a.json", "1"));
    assert_eq!(a1.object_key.as_deref(), Some("orders/a.json"));
    assert_eq!(
        a1.properties.keys().collect::<Vec<_>>(),
        ["n", "object_key"],
        "only the configured fields and the key become properties"
    );
    assert_eq!(plane.live.len(), 5);
    assert!(!plane.keys().contains("other/x.json"));

    // Nothing changed: nothing is fetched again and nothing commits.
    assert!(sync(&mut storage, &mut plane, &mut cursor, 2).is_empty());
    assert_eq!(fake.fetched("orders/a.json"), 1);

    // One object replaced, one deleted mid-range, the last one deleted.
    fake.put("orders/a.json", r#"[{"id":"1","n":5}]"#);
    fake.delete("orders/b.json");
    fake.delete("orders/c.json");
    let changed = sync(&mut storage, &mut plane, &mut cursor, 10);
    let records: Vec<_> = changed[0]
        .records
        .iter()
        .map(|record| (record.object_key.clone().unwrap(), record.deleted))
        .collect();
    assert_eq!(
        records,
        [
            ("orders/a.json".into(), false),
            ("orders/a.json".into(), true),
            ("orders/b.json".into(), true),
            ("orders/c.json".into(), true),
            ("orders/c.json".into(), true),
        ]
    );
    assert_eq!(
        rows(&plane, &fake),
        BTreeSet::from([("orders/a.json".into(), "1".into())])
    );
    assert!(
        plane.applied.values().all(|count| *count == 1),
        "nothing applied twice"
    );
}

#[test]
fn a_resume_mid_pass_with_no_later_change_wraps_and_finds_an_earlier_one() {
    let (pair, fake, port) = store();
    let (mut plane, mut cursor) = (Plane::default(), None);
    let mut storage = connect(port, &pair);
    sync(&mut storage, &mut plane, &mut cursor, 2);
    // The plane holds a cursor in the middle of a pass, after `b`.
    let mid = "object_storage-v1|7|after|orders/b.json";
    fake.put("orders/a.json", r#"[{"id":"1","n":6},{"id":"2","n":2}]"#);

    // A new holder takes over from the committed cursor.
    let mut other = connect(port, &pair);
    let resumed = page(
        other
            .read_page_with_plane(Some(mid), 10, &mut plane)
            .unwrap(),
    );
    assert_eq!(resumed.records.len(), 2, "both rows of a are at a new ETag");
    assert!(
        resumed
            .records
            .iter()
            .all(|record| record.object_key.as_deref() == Some("orders/a.json"))
    );
    assert!(resumed.complete);
    assert_eq!(
        resumed.proposed_next_cursor,
        "object_storage-v1|8|after|orders/b.json"
    );
    plane.commit(&resumed);
    // With nothing changed anywhere, the wrap ends where it started.
    let quiet = page(
        other
            .read_page_with_plane(Some(&resumed.proposed_next_cursor), 10, &mut plane)
            .unwrap(),
    );
    assert!(quiet.records.is_empty() && quiet.complete);
}

#[test]
fn an_object_larger_than_a_page_resumes_inside_it_and_applies_nothing_twice() {
    let pair = key_pair();
    let fake = Fake::new(&pair.0);
    let rows: Vec<_> = (0..5).map(|n| format!(r#"{{"id":"{n}"}}"#)).collect();
    fake.put("orders/big.json", &format!("[{}]", rows.join(",")));
    let port = fake.serve();
    let mut plane = Plane::default();
    let mut storage = connect(port, &pair);

    let one = page(storage.read_page_with_plane(None, 2, &mut plane).unwrap());
    assert_eq!(
        one.proposed_next_cursor,
        "object_storage-v1|0|at|orders/big.json"
    );
    // The runtime died before committing: the page reads the same again.
    let again = page(storage.read_page_with_plane(None, 2, &mut plane).unwrap());
    let ids = |page: &SnapshotPage| {
        page.records
            .iter()
            .map(|record| (record.external_id.clone(), record.source_version.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&again), ids(&one));
    plane.commit(&one);
    let mut cursor = Some(one.proposed_next_cursor.clone());

    let rest = sync(&mut storage, &mut plane, &mut cursor, 2);
    assert_eq!(rest.len(), 2);
    assert_eq!(plane.live.len(), 5);
    assert!(plane.applied.values().all(|count| *count == 1));
    assert_eq!(plane.applied.len(), 5);
}

#[test]
fn its_pages_pass_the_sdk_conformance_checks() {
    use sekai_source_sdk::conformance::{assert_cross_page_identity, assert_snapshot_chain};
    let (pair, fake, port) = store();
    let (mut plane, mut cursor) = (Plane::default(), None);
    let mut storage = connect(port, &pair);
    let mut pages = sync(&mut storage, &mut plane, &mut cursor, 2);
    fake.put("orders/a.json", r#"[{"id":"1","n":7},{"id":"2","n":2}]"#);
    pages.extend(sync(&mut storage, &mut plane, &mut cursor, 2));
    let adapter = sekai_source_sdk::SourceAdapterConfig {
        namespace: "ops".into(),
        producer_identity: "runtime".into(),
        source_instance: "orders".into(),
        type_digest: format!("sha256:{}", "0".repeat(64)),
    };
    let mut current = String::new();
    let chain: Vec<_> = pages
        .iter()
        .map(|page| {
            let mut records = page.records.clone();
            for record in &mut records {
                record.source = "orders-store".into();
                record.source_instance = "orders".into();
            }
            let batch = sekai_source_sdk::build_registered_source_batch(
                &adapter,
                "orders-store",
                &current,
                &page.proposed_next_cursor,
                page.collected_at_ms,
                records,
            )
            .unwrap();
            current = page.proposed_next_cursor.clone();
            batch
        })
        .collect();
    assert_snapshot_chain(&chain).unwrap();
    let a1 = chain[0].records[0].source_id();
    assert_cross_page_identity(&chain[0], chain.last().unwrap(), &a1).unwrap();
}

#[test]
fn objects_past_the_caps_or_with_unusable_rows_fail_the_page() {
    let pair = key_pair();
    let fake = Fake::new(&pair.0);
    let port = fake.serve();
    let mut storage = connect(port, &pair);
    let lines: String = (0..=MAX_OBJECT_ROWS)
        .map(|n| format!("{{\"id\":\"{n}\"}}\n"))
        .collect();
    for body in [
        "x".repeat(MAX_OBJECT_BYTES as usize + 1),
        lines,
        r#"[{"id":"1"},{"id":"1"}]"#.into(),
        r#"[{"n":1}]"#.into(),
        "not json".into(),
    ] {
        fake.put("orders/bad.json", &body);
        assert_eq!(
            storage.read_page_with_plane(None, 10, &mut Plane::default()),
            Err(ConnectorFailure::Invalid)
        );
    }
    fake.delete("orders/bad.json");
    fake.put("orders/../x.json", r#"{"id":"1"}"#);
    assert_eq!(
        storage.read_page_with_plane(None, 10, &mut Plane::default()),
        Err(ConnectorFailure::Invalid)
    );
}

#[test]
fn check_reports_a_typed_reason() {
    let (pair, fake, port) = store();
    assert_eq!(connect(port, &pair).check(), Ok(()));
    let other = key_pair();
    assert_eq!(
        connect(port, &other).check(),
        Err(ConnectorFailure::AuthFailed)
    );
    fake.state.lock().unwrap().no_list = true;
    assert_eq!(
        connect(port, &pair).check(),
        Err(ConnectorFailure::PermissionMissing)
    );
    // Nothing listens there.
    assert_eq!(
        connect(1, &pair).check(),
        Err(ConnectorFailure::Unreachable)
    );
}

#[test]
fn an_endpoint_outside_the_allowlist_or_a_carried_credential_is_refused() {
    let pair = key_pair();
    let endpoint = "https://store.example:9000";
    let egress = EgressAllowlist::parse(&["elsewhere.example"]).unwrap();
    assert_eq!(
        OBJECT_STORAGE_CONNECTOR.require_egress(&config(endpoint, &[]), &egress),
        Err(ConfigError::EgressDenied("endpoint"))
    );
    // A bucket addressed as a subdomain is a destination of its own.
    let virtual_host = config(endpoint, &[("path_style", ConfigValue::Boolean(false))]);
    assert_eq!(
        open_object_storage(&prepared(virtual_host.clone(), &["store.example"], &pair)).err(),
        Some(ConnectorFailure::Invalid)
    );
    assert!(open_object_storage(&prepared(virtual_host, &["data.store.example"], &pair)).is_ok());
    // TLS off loopback, and only the formats the type knows.
    let plain = config("http://store.example:9000", &[]);
    assert_eq!(
        open_object_storage(&prepared(plain, &["store.example"], &pair)).err(),
        Some(ConnectorFailure::Invalid)
    );
    let xml = config(endpoint, &[("format", ConfigValue::Text("xml".into()))]);
    assert_eq!(
        open_object_storage(&prepared(xml, &["store.example"], &pair)).err(),
        Some(ConnectorFailure::Invalid)
    );
    // No worker is installed beside a test binary.
    let csv = config(endpoint, &[("format", ConfigValue::Text("csv".into()))]);
    assert_eq!(
        open_object_storage(&prepared(csv, &["store.example"], &pair)).err(),
        Some(ConnectorFailure::Unsupported)
    );
    // A credential value in a field is refused by the type's schema.
    let carried = config(
        endpoint,
        &[("prefix", ConfigValue::Text(format!("password={}", pair.1)))],
    );
    assert!(matches!(
        OBJECT_STORAGE_CONNECTOR.validate_config(&carried),
        Err(ConfigError::SecretLike("prefix"))
    ));
}

#[test]
fn record_ids_follow_rule_v1() {
    let id = external_id("orders/a b.json", "x/y:z#1");
    assert_eq!(
        id,
        format!(
            "v1.{}.x%2Fy%3Az%231",
            &format!("{:x}", Sha256::digest(b"orders/a b.json"))[..32]
        )
    );
    assert_ne!(external_id("a", "b.c"), external_id("a.b", "c"));
}

/// A worker run as `sh -c script worker <format> <max_rows>`, killed
/// after `timeout`.
#[cfg(unix)]
fn shell_worker(script: &str, timeout: std::time::Duration) -> Worker {
    Worker {
        path: "/bin/sh".into(),
        leading_args: vec!["-c".into(), script.into(), "worker".into()],
        timeout,
    }
}

#[cfg(unix)]
#[test]
fn csv_and_parquet_objects_parse_through_the_worker_under_the_same_mirror() {
    let (pair, fake, port) = store();
    let (mut plane, mut cursor) = (Plane::default(), None);
    let mut storage = connect(port, &pair);
    // A stand-in worker that checks the protocol's arguments and passes
    // rows through; the real one is tested in its own crate.
    let script = r#"[ "$1" = csv ] && [ "$2" = 50000 ] || exit 3; cat"#;
    storage.parser = Some((
        WorkerFormat::Csv,
        shell_worker(script, std::time::Duration::from_secs(10)),
    ));
    let first = sync(&mut storage, &mut plane, &mut cursor, 10);
    assert_eq!(first.len(), 1);
    assert_eq!(plane.live.len(), 5);
    // Unchanged objects are not fetched or parsed again.
    assert!(sync(&mut storage, &mut plane, &mut cursor, 10).is_empty());
    assert_eq!(fake.fetched("orders/a.json"), 1);
    fake.put("orders/b.json", "{\"id\":\"2\"}\n");
    let changed = sync(&mut storage, &mut plane, &mut cursor, 10);
    let records: Vec<_> = changed[0]
        .records
        .iter()
        .map(|record| (record.external_id.clone(), record.deleted))
        .collect();
    assert_eq!(
        records,
        [
            (external_id("orders/b.json", "2"), false),
            (external_id("orders/b.json", "1"), true),
        ]
    );
    // A worker that refuses the object fails the page.
    storage.parser = Some((
        WorkerFormat::Csv,
        shell_worker("exit 2", std::time::Duration::from_secs(10)),
    ));
    fake.put("orders/b.json", "id\n3\n");
    assert_eq!(
        storage
            .read_page_with_plane(cursor.as_deref(), 10, &mut plane)
            .err(),
        Some(ConnectorFailure::Invalid)
    );
}

#[cfg(unix)]
#[test]
fn a_worker_that_hangs_crashes_or_writes_too_much_is_cut_off_as_invalid() {
    use std::time::{Duration, Instant};
    let run = |script: &str| {
        let started = Instant::now();
        let result = shell_worker(script, Duration::from_millis(300)).rows(
            WorkerFormat::Parquet,
            &[0; 4096],
            MAX_OBJECT_ROWS,
        );
        (result.err(), started.elapsed())
    };
    // The trailing command makes every shell fork `sleep` rather than
    // replace itself with it, so the cut-off must reach a grandchild that
    // holds the output pipe.
    let (hung, elapsed) = run("sleep 30; :");
    assert_eq!(hung, Some(ConnectorFailure::Invalid));
    assert!(elapsed < Duration::from_secs(10), "killed at the time cap");
    assert_eq!(run("kill -SEGV $$").0, Some(ConnectorFailure::Invalid));
    let oversize = format!("head -c {} /dev/zero", MAX_WORKER_OUTPUT_BYTES + 1);
    assert_eq!(run(&oversize).0, Some(ConnectorFailure::Invalid));
    // Exactly at the cap is accepted, and leaves the rows to the JSON caps.
    assert_eq!(
        shell_worker(
            "cat >/dev/null; echo '{\"id\":\"1\"}'",
            Duration::from_secs(10)
        )
        .rows(WorkerFormat::Csv, b"id\n1\n", MAX_OBJECT_ROWS)
        .unwrap(),
        b"{\"id\":\"1\"}\n"
    );
    let missing = Worker {
        path: std::env::temp_dir().join(format!("no-worker-{}", std::process::id())),
        leading_args: Vec::new(),
        timeout: Duration::from_secs(1),
    };
    assert_eq!(
        missing.rows(WorkerFormat::Csv, b"", 1).err(),
        Some(ConnectorFailure::Unreachable)
    );
}

/// Against a real store, ignored by default. Run with a local
/// S3-compatible store listening on loopback and a key pair that may
/// create buckets:
///
/// ```sh
/// SEKAI_TEST_OBJECT_STORE=http://127.0.0.1:9000 \
/// SEKAI_TEST_OBJECT_STORE_KEY=<access key id>:<secret key> \
///   cargo test -p sekai-connector-runtime object_storage -- --ignored real_store
/// ```
mod real_store {
    use super::*;

    #[test]
    #[ignore = "needs a local S3-compatible store in SEKAI_TEST_OBJECT_STORE"]
    fn real_store_mirrors_changes_and_resumes_after_a_kill() {
        let endpoint = std::env::var("SEKAI_TEST_OBJECT_STORE").expect("SEKAI_TEST_OBJECT_STORE");
        let key =
            std::env::var("SEKAI_TEST_OBJECT_STORE_KEY").expect("SEKAI_TEST_OBJECT_STORE_KEY");
        let (id, secret) = key.split_once(':').expect("<id>:<secret>");
        let pair = (id.to_string(), secret.to_string());
        let bucket = format!("sekai-test-{}-{}", std::process::id(), now_ms());
        let host = Url::parse(&endpoint)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        let config = config(&endpoint, &[("bucket", ConfigValue::Text(bucket.clone()))]);
        let open = || open_object_storage(&prepared(config.clone(), &[&host], &pair)).unwrap();
        let storage = open();
        storage.store.put("/", Vec::new()).unwrap();
        let put =
            |key: &str, body: &str| storage.store.put(&format!("/{key}"), body.into()).unwrap();
        put(
            "orders/a.json",
            r#"[{"id":"1","n":1},{"id":"2","n":2},{"id":"3","n":3}]"#,
        );
        put("orders/b.json", r#"{"id":"1"}"#);
        put("orders/c.json", r#"{"id":"1"}"#);

        assert_eq!(open().check(), Ok(()));
        let wrong = (pair.0.clone(), format!("{}-other", pair.1));
        let mut refused = open_object_storage(&prepared(config.clone(), &[&host], &wrong)).unwrap();
        assert_eq!(refused.check(), Err(ConnectorFailure::AuthFailed));
        let (mut plane, mut cursor) = (Plane::default(), None);
        // The first holder reads a page and dies before committing it.
        let lost = page(open().read_page_with_plane(None, 2, &mut plane).unwrap());
        assert_eq!(lost.records.len(), 2);
        // A new holder resumes from the committed (empty) cursor.
        sync(&mut open(), &mut plane, &mut cursor, 2);
        assert_eq!(plane.live.len(), 5);

        put("orders/a.json", r#"[{"id":"1","n":9}]"#);
        let unchanged = plane
            .live
            .iter()
            .filter(|((key, _), _)| key == "orders/b.json")
            .count();
        assert_eq!(unchanged, 1);
        storage.store.delete("/orders/c.json").unwrap();
        sync(&mut open(), &mut plane, &mut cursor, 2);
        assert_eq!(
            plane.keys(),
            BTreeSet::from(["orders/a.json".to_string(), "orders/b.json".to_string()])
        );
        assert_eq!(plane.live.len(), 2);
        assert!(plane.applied.values().all(|count| *count == 1));
    }
}
