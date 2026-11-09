//! The connector runtime against a serving plane (ADR 0148): crash
//! mid-claim, takeover after lease expiry, a stale fence refused, two
//! runtime versions side by side, an unresolved credential, and a GitHub
//! repository moved under a Source with its object ids unchanged.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::rpc_maturity::RpcMaturityLayer;
use sekai_chisei::sekai::security::Role;
use sekai_chisei::sekai::source::{self, PutSource, SourceSpec};
use sekai_client::ClientConfig;
use sekai_connector_runtime::{
    Connectors, CredentialBindings, Ran, Runtime, RuntimeOptions, SyncFailure, github,
};
use sekai_source_sdk::{
    ConfigValue, Connector, ConnectorFailure, GITHUB_CONNECTOR, GITHUB_OBJECT_SYNC_TYPE_DIGEST,
    GitHubObjectFixture, RELATIONAL_CONNECTOR, SnapshotPage, SnapshotRead, SourceAdapterConfig,
    SourceConfig, build_source_batch, object_id_for, translate_github_fixture,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::Layer;

const NS: &str = "ops";
const PRINCIPAL: &str = "local";
const LEASE: Duration = Duration::from_millis(300);

struct Plane {
    db: Arc<RuntimeDb>,
    endpoint: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Plane {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn plane() -> Plane {
    let db = Arc::new(RuntimeDb::memory());
    db.ensure_team_namespace(NS, PRINCIPAL, Role::Admin, PRINCIPAL)
        .unwrap();
    let service = RpcMaturityLayer::new(true).layer(SekaiServiceServer::new(
        SekaiServiceImpl::new(SekaiStore::from_shared_runtime(db.clone())),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    Plane {
        db,
        endpoint,
        stop: Some(stop),
    }
}

impl Plane {
    fn put(&self, id: &str, spec: SourceSpec, source: &str, instance: &str) {
        source::put(
            &self.db,
            &PutSource {
                namespace: NS.into(),
                source_id: id.into(),
                source: source.into(),
                source_instance: instance.into(),
                spec,
                expected_revision: 0,
                now_ms: 1,
            },
        )
        .unwrap();
    }

    fn put_github(&self, id: &str, credential_ref: &str) {
        self.put(
            id,
            SourceSpec {
                connector_type: "github".into(),
                connector_version: "1".into(),
                config: SourceConfig::from([(
                    "api_url".into(),
                    ConfigValue::Text("https://api.github.com".into()),
                )]),
                credential_ref: credential_ref.into(),
                egress: vec!["api.github.com".into()],
                placement: BTreeMap::from([("zone".into(), "eu".into())]),
                every_ms: 60_000,
                owner: "team".into(),
                markings: Vec::new(),
                certification_id: String::new(),
            },
            "github",
            &format!("acme/{id}"),
        );
    }

    fn put_relational(&self, id: &str) {
        self.put(
            id,
            SourceSpec {
                connector_type: "relational".into(),
                connector_version: "1".into(),
                config: SourceConfig::from([
                    (
                        "endpoint".into(),
                        ConfigValue::Text("db.internal:5432".into()),
                    ),
                    ("database".into(), ConfigValue::Text("orders".into())),
                    ("user".into(), ConfigValue::Text("reader".into())),
                ]),
                credential_ref: "ops/db".into(),
                egress: vec!["db.internal:5432".into()],
                placement: BTreeMap::from([("zone".into(), "eu".into())]),
                every_ms: 60_000,
                owner: "team".into(),
                markings: Vec::new(),
                certification_id: String::new(),
            },
            "orders-db",
            id,
        );
    }

    fn tick(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        self.db.tick_source_syncs(NS, now).unwrap();
    }

    fn sync_of(&self, id: &str) -> (String, String, i64) {
        let sync = self.db.get_source(NS, id).unwrap().unwrap().sync;
        (sync.last_runtime, sync.last_failure, sync.claim.generation)
    }
}

/// Credential bindings with values in a per-test directory.
fn bindings(dir: &std::path::Path) -> CredentialBindings {
    let token = dir.join("token");
    let password = dir.join("password");
    std::fs::write(&token, "t").unwrap();
    std::fs::write(&password, "p").unwrap();
    serde_json::from_value(serde_json::json!({
        "ops/github-bot": {
            "namespaces": [NS],
            "destinations": ["api.github.com"],
            "slots": { "token": { "file": token } }
        },
        "ops/db": {
            "namespaces": [NS],
            "destinations": ["db.internal:5432"],
            "slots": { "password": { "file": password } }
        }
    }))
    .unwrap()
}

/// A connector that counts its syncs: each reads one complete page with
/// one issue of the Source's repository.
struct Counted(Arc<AtomicUsize>, String);

impl Connector for Counted {
    fn read_page(
        &mut self,
        committed_cursor: Option<&str>,
        _max_records: usize,
    ) -> Result<SnapshotRead, ConnectorFailure> {
        let run = self.0.fetch_add(1, Ordering::SeqCst);
        let issue = translate_github_fixture(
            GitHubObjectFixture {
                repository: self.1.clone(),
                kind: "Issue".into(),
                number: 1,
                revision: format!("r{run}"),
                title: "one".into(),
                state: "open".into(),
                deleted: false,
                observed_at_ms: 1,
                properties: BTreeMap::new(),
            },
            &self.1,
        )
        .unwrap();
        Ok(SnapshotRead::Page(SnapshotPage {
            records: vec![issue],
            proposed_next_cursor: format!("{}-{run}", committed_cursor.unwrap_or("run")),
            collected_at_ms: 1,
            complete: true,
        }))
    }
}

fn counted(types: &[&'static sekai_source_sdk::ConnectorType]) -> (Connectors, Arc<AtomicUsize>) {
    let runs = Arc::new(AtomicUsize::new(0));
    let connectors = types.iter().fold(Connectors::default(), |connectors, ty| {
        let runs = runs.clone();
        connectors.with(ty, move |prepared| {
            Ok(Box::new(Counted(
                runs.clone(),
                prepared.source_instance.clone(),
            )))
        })
    });
    (connectors, runs)
}

async fn runtime(
    plane: &Plane,
    id: &str,
    bindings: CredentialBindings,
    connectors: Connectors,
) -> Runtime {
    let runtime = Runtime::connect(
        ClientConfig::new(&plane.endpoint, PRINCIPAL).with_default_timeout(Duration::from_secs(5)),
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

#[tokio::test(flavor = "multi_thread")]
async fn a_crashed_runtime_is_taken_over_and_its_fence_refused() {
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    plane.put_github("repo", "ops/github-bot");
    plane.tick();
    let (connectors, runs) = counted(&[&GITHUB_CONNECTOR]);
    let a = runtime(
        &plane,
        "runtime-a",
        bindings(dir.path()),
        connectors.clone(),
    )
    .await;
    let b = runtime(&plane, "runtime-b", bindings(dir.path()), connectors).await;

    // A claims and dies before running: B sees nothing while the lease lives.
    let held = a.claim(0).await.unwrap().unwrap();
    assert!(b.claim(0).await.unwrap().is_none());

    // After the lease lapses, B takes over under a new generation and syncs.
    tokio::time::sleep(LEASE * 2).await;
    assert_eq!(
        b.pass().await.unwrap(),
        [Ran::Finished {
            source_id: "repo".into(),
            outcome: Ok(())
        }]
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    let (last_runtime, last_failure, generation) = plane.sync_of("repo");
    assert_eq!(
        (last_runtime.as_str(), last_failure.as_str()),
        ("runtime-b", "")
    );
    assert!(generation > held.claim_generation);

    // A comes back with its stale fence: it is refused before it reads or
    // applies anything, so nothing is recorded twice.
    assert_eq!(
        a.run(0, held).await.unwrap(),
        Ran::Lost {
            source_id: "repo".into()
        }
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1, "A never ran");
    assert_eq!(plane.sync_of("repo").0, "runtime-b");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_runtime_versions_split_the_work_during_a_rolling_deploy() {
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    for id in ["repo-1", "repo-2", "repo-3"] {
        plane.put_github(id, "ops/github-bot");
    }
    plane.put_relational("orders");
    plane.tick();
    // The older runtime implements only GitHub; the newer one both types.
    let (old, old_runs) = counted(&[&GITHUB_CONNECTOR]);
    let (new, new_runs) = counted(&[&GITHUB_CONNECTOR, &RELATIONAL_CONNECTOR]);
    let old = runtime(&plane, "runtime-old", bindings(dir.path()), old).await;
    let new = runtime(&plane, "runtime-new", bindings(dir.path()), new).await;

    let (old_ran, new_ran) = tokio::join!(old.pass(), new.pass());
    let (old_ran, new_ran) = (old_ran.unwrap(), new_ran.unwrap());
    assert_eq!(old_ran.len() + new_ran.len(), 4, "each Source syncs once");
    // Relational Sources do not read pages yet, so only GitHub reads ran.
    assert_eq!(
        old_runs.load(Ordering::SeqCst) + new_runs.load(Ordering::SeqCst),
        3
    );
    let (runtime, failure, _) = plane.sync_of("orders");
    assert_eq!(
        (runtime.as_str(), failure.as_str()),
        ("runtime-new", "unsupported")
    );
    assert!(
        old_ran
            .iter()
            .all(|ran| !matches!(ran, Ran::Finished { source_id, .. } if source_id == "orders"))
    );
    // Nothing is due again until the next interval.
    assert!(old.pass().await.unwrap().is_empty());
    assert!(new.pass().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn due_sources_of_other_types_never_hide_a_runtimes_work() {
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    // More due relational Sources than one list page, all sorting first.
    for n in 0..60 {
        plane.put_relational(&format!("a-db-{n:02}"));
    }
    plane.put_github("z-repo", "ops/github-bot");
    plane.tick();
    let (connectors, runs) = counted(&[&GITHUB_CONNECTOR]);
    let runtime = runtime(&plane, "runtime-old", bindings(dir.path()), connectors).await;

    assert_eq!(
        runtime.pass().await.unwrap(),
        [Ran::Finished {
            source_id: "z-repo".into(),
            outcome: Ok(())
        }]
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unresolved_credential_fails_once_as_unavailable() {
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    plane.put_github("repo", "ops/unbound");
    plane.tick();
    let (connectors, runs) = counted(&[&GITHUB_CONNECTOR]);
    let runtime = runtime(&plane, "runtime-a", bindings(dir.path()), connectors).await;

    assert_eq!(
        runtime.pass().await.unwrap(),
        [Ran::Finished {
            source_id: "repo".into(),
            outcome: Err(SyncFailure::Unavailable)
        }]
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0, "nothing connected");
    assert_eq!(plane.sync_of("repo").1, "unavailable");
    assert!(runtime.pass().await.unwrap().is_empty(), "no retry loop");
}

/// Serves a GitHub REST API stand-in on an ephemeral port that lists
/// `items` for every issues request.
fn fake_github(items: serde_json::Value) -> String {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::from("start");
            while !line.trim().is_empty() {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
            }
            let body = items.to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    url
}

fn issue(number: u64, revision: &str) -> GitHubObjectFixture {
    GitHubObjectFixture {
        repository: "acme/repo".into(),
        kind: "Issue".into(),
        number,
        revision: revision.into(),
        title: format!("issue {number}"),
        state: "open".into(),
        deleted: false,
        observed_at_ms: 1,
        properties: BTreeMap::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_github_repository_moves_under_a_source_with_its_object_ids() {
    const SYNCED: &str = "2026-01-01T00:00:00Z";
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    // Before: a standalone adapter synced issue 1 under its own cursor.
    let legacy = build_source_batch(
        &SourceAdapterConfig {
            namespace: NS.into(),
            producer_identity: PRINCIPAL.into(),
            source_instance: "acme/repo".into(),
            type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        },
        "",
        "adapter-cursor-1",
        1,
        vec![translate_github_fixture(issue(1, SYNCED), "acme/repo").unwrap()],
    )
    .unwrap();
    plane.db.apply_source_batch(&legacy, PRINCIPAL, 1).unwrap();
    let id = |number: u64| {
        object_id_for(
            GITHUB_OBJECT_SYNC_TYPE_DIGEST,
            &format!("github:acme/repo#{number}"),
        )
    };
    let before = plane.db.get_object(&id(1)).unwrap().unwrap();

    // The repository becomes a Source; its runtime reads issue 1 unchanged
    // and issue 2 new.
    let api = fake_github(serde_json::json!([
        { "number": 1, "title": "issue 1", "state": "open", "updated_at": SYNCED },
        { "number": 2, "title": "issue 2", "state": "open", "updated_at": "2026-01-02T00:00:00Z" },
    ]));
    plane.put(
        "repo",
        SourceSpec {
            connector_type: "github".into(),
            connector_version: "1".into(),
            config: SourceConfig::from([("api_url".into(), ConfigValue::Text(api))]),
            credential_ref: "ops/github-local".into(),
            egress: vec!["127.0.0.1".into()],
            placement: BTreeMap::new(),
            every_ms: 60_000,
            owner: "team".into(),
            markings: Vec::new(),
            certification_id: String::new(),
        },
        "github",
        "acme/repo",
    );
    plane.tick();
    let token = dir.path().join("token");
    std::fs::write(&token, "t").unwrap();
    let bindings = serde_json::from_value(serde_json::json!({
        "ops/github-local": {
            "namespaces": [NS],
            "destinations": ["127.0.0.1"],
            "slots": { "token": { "file": token } }
        }
    }))
    .unwrap();
    let runtime = runtime(
        &plane,
        "runtime-a",
        bindings,
        Connectors::default().with(&GITHUB_CONNECTOR, github::open),
    )
    .await;
    assert_eq!(
        runtime.pass().await.unwrap(),
        [Ran::Finished {
            source_id: "repo".into(),
            outcome: Ok(())
        }]
    );

    let after = plane.db.get_object(&id(1)).unwrap().unwrap();
    // Same object, same payload and version; only the observation is newer.
    assert_eq!(
        (&after.name, &after.properties, after.created),
        (&before.name, &before.properties, before.created)
    );
    assert_eq!(
        plane.db.get_object(&id(2)).unwrap().unwrap().external_id,
        "github:acme/repo#2"
    );
    let (last_runtime, last_failure, _) = plane.sync_of("repo");
    assert_eq!(
        (last_runtime.as_str(), last_failure.as_str()),
        ("runtime-a", "")
    );
}
