//! `postgres_capture` through the connector runtime against a real
//! PostgreSQL and a serving plane (ADR 0170): the sandboxed child reads a
//! resumable snapshot after the slot's position, hands off to the feed, and
//! what the runtime read passes the ADR 0118 conformance check.
//!
//! Linux only, ignored: needs `SEKAI_TEST_POSTGRES_URL` for a TLS server with
//! `wal_level=logical`, `SEKAI_TEST_POSTGRES_CA_CERT` for its CA, and
//! `SEKAI_TEST_CAPTURE_CHILD` for the built `sekai-change-capture`;
//! `scripts/postgres-conformance.sh` provides all three. Every test names its
//! own table, publication and slot, so runs against one server do not
//! collide.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres_native_tls::MakeTlsConnector;
use sekai_chisei::sekai::source::SourceSpec;
use sekai_chisei::sekai::source_type_descriptor::{
    ProposedSourceTypeDescriptor, register_source_type_descriptor,
};
use sekai_client::ClientConfig;
use sekai_connector_runtime::capture::CaptureChild;
use sekai_connector_runtime::postgres_capture::{self, Capture};
use sekai_connector_runtime::{
    Connectors, CredentialBindings, Ran, Runtime, RuntimeOptions, SyncFailure,
};
use sekai_source_sdk::change_capture::{
    CaptureEvent, CapturedChange, ChangeOperation, PositionFamily, assert_change_capture,
};
use sekai_source_sdk::{
    ChangeFeedPage, ConfigValue, Connector, ConnectorFailure, GenerationSnapshotPage,
    POSTGRES_CAPTURE_CONNECTOR, SourceConfig, object_id_for,
};

use crate::connector_runtime_effects::{LEASE, NS, PRINCIPAL, Plane, plane_with};

/// The test server, its CA and the built child.
struct Server {
    config: postgres::Config,
    ca_pem: String,
    child: PathBuf,
}

impl Server {
    fn from_env() -> Self {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL").expect("SEKAI_TEST_POSTGRES_URL");
        let ca = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT").expect("SEKAI_TEST_POSTGRES_CA_CERT");
        let child = std::env::var("SEKAI_TEST_CAPTURE_CHILD").expect("SEKAI_TEST_CAPTURE_CHILD");
        Self {
            config: postgres::Config::from_str(&url).unwrap(),
            ca_pem: std::fs::read_to_string(ca).unwrap(),
            child: child.into(),
        }
    }

    /// Runs `work` with an admin connection on its own thread: the client
    /// blocks, and the tests run inside the runtime's executor.
    fn admin<T: Send>(&self, work: impl FnOnce(&mut postgres::Client) -> T + Send) -> T {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let tls = native_tls::TlsConnector::builder()
                        .add_root_certificate(
                            native_tls::Certificate::from_pem(self.ca_pem.as_bytes()).unwrap(),
                        )
                        .build()
                        .unwrap();
                    let mut config = self.config.clone();
                    config.ssl_mode(postgres::config::SslMode::Require);
                    work(&mut config.connect(MakeTlsConnector::new(tls)).unwrap())
                })
                .join()
                .unwrap()
        })
    }

    fn execute(&self, sql: &str) {
        self.admin(|client| client.batch_execute(sql).unwrap());
    }

    /// The table as `id` to `name`.
    fn rows(&self, table: &str) -> BTreeMap<String, String> {
        self.admin(|client| {
            client
                .query(&format!("SELECT id::text, name FROM {table}"), &[])
                .unwrap()
                .iter()
                .map(|row| (row.get(0), row.get(1)))
                .collect()
        })
    }

    fn endpoint(&self) -> String {
        let port = self.config.get_ports().first().copied().unwrap_or(5432);
        format!("localhost:{port}")
    }

    fn drop_slot(&self, slot: &str) {
        for _ in 0..50 {
            let remaining: i64 = self.admin(|client| {
                let _ = client.execute(
                    "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots \
                     WHERE slot_name = $1 AND NOT active",
                    &[&slot],
                );
                client
                    .query_one(
                        "SELECT count(*) FROM pg_replication_slots WHERE slot_name = $1",
                        &[&slot],
                    )
                    .unwrap()
                    .get(0)
            });
            if remaining == 0 {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("slot {slot} was not dropped");
    }
}

fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("{prefix}_{}_{nanos}", std::process::id())
}

fn descriptor() -> ProposedSourceTypeDescriptor {
    ProposedSourceTypeDescriptor::prepare("orders-db", "Order", "orders-v1").unwrap()
}

fn spec(server: &Server, slot: &str, publication: &str) -> SourceSpec {
    let text = |value: &str| ConfigValue::Text(value.into());
    SourceSpec {
        connector_type: "postgres_capture".into(),
        connector_version: "1".into(),
        config: SourceConfig::from([
            ("endpoint".into(), text(&server.endpoint())),
            ("database".into(), text(server.config.get_dbname().unwrap())),
            ("user".into(), text(server.config.get_user().unwrap())),
            ("slot".into(), text(slot)),
            ("publication".into(), text(publication)),
            ("record_kind".into(), text("Order")),
            ("type_digest".into(), text(&descriptor().digest)),
        ]),
        credential_ref: "ops/db".into(),
        egress: vec![server.endpoint()],
        placement: BTreeMap::from([("zone".into(), "eu".into())]),
        every_ms: 60_000,
        owner: "team".into(),
        markings: Vec::new(),
        certification_id: String::new(),
    }
}

/// Every page the runtime read, in order.
#[derive(Debug, Clone)]
enum Read {
    Snapshot(GenerationSnapshotPage),
    Changes(ChangeFeedPage),
}

type Log = Arc<Mutex<Vec<Read>>>;

/// The real connector, recording its pages; with `snapshot_pages` set,
/// it fails like a dying runtime once it has read that many.
struct Recording {
    inner: Box<dyn Connector + Send>,
    log: Log,
    snapshot_pages: Option<usize>,
}

impl Connector for Recording {
    fn read_snapshot_page(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<GenerationSnapshotPage, ConnectorFailure> {
        let read = self
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|read| matches!(read, Read::Snapshot(_)))
            .count();
        if self.snapshot_pages.is_some_and(|limit| read >= limit) {
            return Err(ConnectorFailure::Unavailable);
        }
        let page = self
            .inner
            .read_snapshot_page(committed_cursor, max_records)?;
        self.log.lock().unwrap().push(Read::Snapshot(page.clone()));
        Ok(page)
    }

    fn read_changes_from(
        &mut self,
        committed_cursor: &str,
        source_feed_epoch: &str,
        committed_offset: u64,
        max_records: usize,
    ) -> Result<ChangeFeedPage, ConnectorFailure> {
        let page = self.inner.read_changes_from(
            committed_cursor,
            source_feed_epoch,
            committed_offset,
            max_records,
        )?;
        self.log.lock().unwrap().push(Read::Changes(page.clone()));
        Ok(page)
    }
}

/// A runtime serving the plane with the real child; `snapshot_pages` as in
/// [`Recording`].
async fn runtime(
    server: &Server,
    plane: &Plane,
    id: &str,
    log: &Log,
    snapshot_pages: Option<usize>,
    dir: &std::path::Path,
) -> Runtime {
    let capture = Capture::new(
        CaptureChild::at(server.child.clone()),
        Some(server.ca_pem.clone()),
    );
    let log = log.clone();
    let connectors = Connectors::default().with(&POSTGRES_CAPTURE_CONNECTOR, move |prepared| {
        Ok(Box::new(Recording {
            inner: postgres_capture::open(prepared, &capture)?,
            log: log.clone(),
            snapshot_pages,
        }))
    });
    let password = dir.join(format!("password-{id}"));
    std::fs::write(
        &password,
        server.config.get_password().expect("a password in the URL"),
    )
    .unwrap();
    let bindings: CredentialBindings = serde_json::from_value(serde_json::json!({
        "ops/db": {
            "namespaces": [NS],
            "destinations": [server.endpoint()],
            "slots": { "password": { "file": password } }
        }
    }))
    .unwrap();
    let runtime = Runtime::connect(
        ClientConfig::new(&plane.endpoint, PRINCIPAL).with_default_timeout(Duration::from_secs(30)),
        &[NS.to_string()],
        RuntimeOptions {
            runtime_id: id.into(),
            labels: BTreeMap::from([("zone".into(), "eu".into())]),
            lease: LEASE,
        },
        bindings,
        connectors,
    )
    .await
    .unwrap();
    runtime.register().await.unwrap();
    runtime
}

async fn serving(server: &Server, slot: &str, publication: &str) -> Plane {
    let plane = plane_with(spec(server, slot, publication)).await;
    register_source_type_descriptor(&plane.db, PRINCIPAL, NS, &descriptor(), 1).unwrap();
    plane
}

/// Runs sync `round` of the Source on `runtime`.
async fn sync(plane: &Plane, runtime: &Runtime, round: i64) -> Result<(), SyncFailure> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    plane
        .db
        .tick_source_syncs(NS, now + round * 120_000)
        .unwrap();
    match runtime.pass().await.unwrap().as_slice() {
        [Ran::Finished { outcome, .. }] => *outcome,
        other => panic!("one finished sync expected: {other:?}"),
    }
}

/// The plane's live orders as `id` to `name`, for ids up to `up_to`.
fn plane_rows(plane: &Plane, up_to: u64) -> BTreeMap<String, String> {
    (1..=up_to)
        .filter_map(|id| {
            let object = plane
                .db
                .get_object(&object_id_for(
                    &descriptor().digest,
                    &format!("orders-db:orders#Order/{id}"),
                ))
                .unwrap()?;
            Some((id.to_string(), object.properties.get("name")?.clone()))
        })
        .collect()
}

/// What the runtime read as ADR 0118 capture events: the snapshot at its
/// hand-off position, then each transaction's changes at its commit.
fn events(log: &[Read]) -> Vec<CaptureEvent> {
    let lsn = |value: u64| format!("{:X}/{:X}", value >> 32, value & 0xFFFF_FFFF);
    let mut events = Vec::new();
    let mut open: Option<String> = None;
    for read in log {
        match read {
            Read::Snapshot(page) if page.complete => {
                let position = page.proposed_next_cursor.strip_prefix("pg1/").unwrap();
                events.push(CaptureEvent::Snapshot {
                    generation: 1,
                    position: lsn(position.parse().unwrap()),
                });
            }
            Read::Snapshot(_) => {}
            Read::Changes(page) => {
                for record in &page.records {
                    let (commit, _) = record.source_version.split_once('.').unwrap();
                    let commit = lsn(commit.parse().unwrap());
                    if open.as_ref() != Some(&commit) {
                        if let Some(previous) = open.replace(commit.clone()) {
                            events.push(CaptureEvent::TransactionEnd {
                                transaction_id: previous.clone(),
                                commit_position: previous,
                            });
                        }
                        events.push(CaptureEvent::TransactionBegin {
                            transaction_id: commit.clone(),
                        });
                    }
                    let after = (!record.deleted).then(|| {
                        record
                            .properties
                            .iter()
                            .map(|(column, value)| (column.clone(), format!("{value:?}")))
                            .collect()
                    });
                    events.push(CaptureEvent::Change(CapturedChange {
                        record_kind: record.type_name.clone(),
                        operation: if record.deleted {
                            ChangeOperation::Delete
                        } else {
                            ChangeOperation::Update
                        },
                        key: vec![("id".into(), record.external_id.clone())],
                        before: None,
                        after,
                        transaction_id: commit.clone(),
                        commit_position: commit.clone(),
                        commit_time_ms: record.observed_at_ms,
                    }));
                }
            }
        }
    }
    if let Some(previous) = open {
        events.push(CaptureEvent::TransactionEnd {
            transaction_id: previous.clone(),
            commit_position: previous,
        });
    }
    events
}

/// A snapshot interrupted after its first page resumes in another runtime
/// from the plane's cursor. Rows deleted, changed, inserted and moved to a
/// new key mid-snapshot all end as the source holds them, and the stream
/// the runtimes read passes the conformance check.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL, SEKAI_TEST_POSTGRES_CA_CERT and SEKAI_TEST_CAPTURE_CHILD; run through scripts/postgres-conformance.sh"]
async fn postgres_capture_snapshot_resumes_and_hands_off_to_the_feed() {
    let server = Server::from_env();
    let (table, publication, slot) = (
        unique("cc_rt_items"),
        unique("cc_rt_pub"),
        unique("cc_rt_slot"),
    );
    server.execute(&format!(
        "CREATE TABLE {table} (id int PRIMARY KEY, name text); \
         INSERT INTO {table} SELECT n, 'v1' FROM generate_series(1, 1200) n; \
         CREATE PUBLICATION {publication} FOR TABLE {table}"
    ));
    let plane = serving(&server, &slot, &publication).await;
    let dir = tempfile::tempdir().unwrap();
    let log = Log::default();

    // The first runtime dies after one snapshot page.
    let first = runtime(&server, &plane, "eu-1", &log, Some(1), dir.path()).await;
    assert_eq!(sync(&plane, &first, 1).await, Err(SyncFailure::Unavailable));
    assert_eq!(plane_rows(&plane, 2000).len(), 500);
    drop(first);

    // Five transactions, each its own commit.
    for change in [
        "DELETE FROM {t} WHERE id = 10",
        "UPDATE {t} SET name = 'v2' WHERE id = 700",
        "DELETE FROM {t} WHERE id = 1100",
        "INSERT INTO {t} VALUES (1300, 'v1')",
        "UPDATE {t} SET id = 2000 WHERE id = 5",
    ] {
        server.execute(&change.replace("{t}", &table));
    }

    // Another runtime finishes the snapshot and replays every change.
    let second = runtime(&server, &plane, "eu-2", &log, None, dir.path()).await;
    assert_eq!(sync(&plane, &second, 2).await, Ok(()));
    assert_eq!(plane_rows(&plane, 2000), server.rows(&table));

    let read = log.lock().unwrap().clone();
    let summary = assert_change_capture(
        PositionFamily::PostgresLsn,
        &BTreeMap::from([("Order".into(), vec!["id".into()])]),
        None,
        &events(&read),
    )
    .unwrap();
    assert_eq!((summary.generations, summary.transactions), (1, 5));

    // A later change reaches the plane in the next sync.
    server.execute(&format!("UPDATE {table} SET name = 'v3' WHERE id = 1"));
    assert_eq!(sync(&plane, &second, 3).await, Ok(()));
    assert_eq!(plane_rows(&plane, 2000), server.rows(&table));

    drop(second);
    server.drop_slot(&slot);
    server.execute(&format!(
        "DROP PUBLICATION {publication}; DROP TABLE {table}"
    ));
}

/// An empty table cannot finish a snapshot: the sync fails visibly and
/// the next one succeeds once a row exists.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL, SEKAI_TEST_POSTGRES_CA_CERT and SEKAI_TEST_CAPTURE_CHILD; run through scripts/postgres-conformance.sh"]
async fn postgres_capture_refuses_an_empty_table_until_a_row_exists() {
    let server = Server::from_env();
    assert_eq!(
        CaptureChild::at(server.child.clone()).self_test(&[server.child.as_path()]),
        Ok(()),
        "the sandbox holds on this host"
    );
    let (table, publication, slot) = (
        unique("cc_rt_empty"),
        unique("cc_rt_empty_pub"),
        unique("cc_rt_empty_slot"),
    );
    server.execute(&format!(
        "CREATE TABLE {table} (id int PRIMARY KEY, name text); \
         CREATE PUBLICATION {publication} FOR TABLE {table}"
    ));
    let plane = serving(&server, &slot, &publication).await;
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime(&server, &plane, "eu-1", &Log::default(), None, dir.path()).await;

    assert_eq!(
        sync(&plane, &runtime, 1).await,
        Err(SyncFailure::Unavailable)
    );
    server.execute(&format!("INSERT INTO {table} VALUES (1, 'v1')"));
    assert_eq!(sync(&plane, &runtime, 2).await, Ok(()));
    assert_eq!(plane_rows(&plane, 1), server.rows(&table));

    drop(runtime);
    server.drop_slot(&slot);
    server.execute(&format!(
        "DROP PUBLICATION {publication}; DROP TABLE {table}"
    ));
}
