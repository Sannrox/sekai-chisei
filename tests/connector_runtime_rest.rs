//! The `rest` connector type through the connector runtime, against a
//! serving plane and a local fixture HTTP API (#3082): `check` with an
//! accepted and a rejected credential, a sync whose runtime is killed
//! mid-scan and resumed by another from the committed cursor, an admitted
//! `external_mutate` effect written once with its evidence and a conflict
//! that writes nothing, and destinations refused before any connection.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sekai_chisei::sekai::source::SourceSpec;
use sekai_chisei::sekai::source_type_descriptor::{
    ProposedSourceTypeDescriptor, register_source_type_descriptor,
};
use sekai_client::ClientConfig;
use sekai_connector_runtime::{
    Connectors, CredentialBindings, Effected, Ran, Runtime, RuntimeOptions, SyncFailure, prepare,
    rest,
};
use sekai_source_sdk::{ConfigValue, REST_CONNECTOR, SourceConfig, object_id_for};

use crate::connector_runtime_effects::{LEASE, NS, PRINCIPAL, Plane, plane_with};

const TOKEN: &str = "fixture-credential-7f3a";

/// The registered record type the Source's records are synced as.
fn descriptor() -> ProposedSourceTypeDescriptor {
    ProposedSourceTypeDescriptor::prepare("orders-db", "Order", "orders-v1").unwrap()
}

/// The plane with the `rest` Source over `url` and its live type.
async fn serving(url: &str) -> Plane {
    let plane = plane_with(spec(url)).await;
    register_source_type_descriptor(&plane.db, PRINCIPAL, NS, &descriptor(), 1).unwrap();
    plane
}

/// What the fixture API saw: method, path, and the credential header.
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

/// The fixture's records, by id: version and status.
type Orders = Arc<Mutex<BTreeMap<u64, (String, String)>>>;

/// A paged JSON API of orders on an ephemeral port: two per page, linked
/// by `links.next`; `GET`/`PATCH /orders/{id}` for one. A credential other
/// than [`TOKEN`] is refused with 401. While `stall` is set, the first
/// request for the page after order 102 waits until it is cleared.
struct Fixture {
    url: String,
    seen: Seen,
    orders: Orders,
    stall: Arc<AtomicBool>,
}

fn fixture(ids: &[u64]) -> Fixture {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Seen::default();
    let orders: Orders = Arc::new(Mutex::new(
        ids.iter()
            .map(|id| (*id, ("10".to_string(), "open".to_string())))
            .collect(),
    ));
    let stall = Arc::new(AtomicBool::new(false));
    let (log, data, held) = (seen.clone(), orders.clone(), stall.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let (log, data, held) = (log.clone(), data.clone(), held.clone());
            std::thread::spawn(move || serve(stream, &log, &data, &held));
        }
    });
    Fixture {
        url,
        seen,
        orders,
        stall,
    }
}

fn serve(mut stream: std::net::TcpStream, seen: &Seen, orders: &Orders, stall: &AtomicBool) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let Some((name, value)) = line.trim_end().split_once(": ") else {
            break;
        };
        headers.insert(name.to_ascii_lowercase(), value.to_string());
    }
    let length = headers
        .get("content-length")
        .and_then(|length| length.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let mut parts = request_line.split(' ');
    let (method, path) = (
        parts.next().unwrap_or_default().to_string(),
        parts.next().unwrap_or_default().to_string(),
    );
    let credential = headers.get("x-api-key").cloned().unwrap_or_default();
    let first_of_page_two = path.ends_with("after=102")
        && !seen
            .lock()
            .unwrap()
            .iter()
            .any(|(_, seen_path, _)| *seen_path == path);
    seen.lock()
        .unwrap()
        .push((method.clone(), path.clone(), credential.clone()));
    if first_of_page_two {
        while stall.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let order = |id: u64, (version, status): &(String, String)| serde_json::json!({"id": id, "version": version, "status": status, "label": format!("order {id}")});
    let (status, reply) = if credential != TOKEN {
        (401, r#"{"error":"bad credential"}"#.to_string())
    } else if let Some(id) = path
        .strip_prefix("/orders/")
        .and_then(|id| id.parse::<u64>().ok())
    {
        let mut orders = orders.lock().unwrap();
        match orders.get_mut(&id) {
            None => (404, "{}".into()),
            Some(current) => {
                if method == "PATCH" {
                    let change: BTreeMap<String, String> = serde_json::from_slice(&body).unwrap();
                    current.1 = change["status"].clone();
                    current.0 = (current.0.parse::<u64>().unwrap() + 1).to_string();
                }
                (200, order(id, current).to_string())
            }
        }
    } else {
        let after = path
            .split_once("after=")
            .and_then(|(_, after)| after.parse::<u64>().ok())
            .unwrap_or(0);
        let orders = orders.lock().unwrap();
        let page: Vec<_> = orders
            .iter()
            .filter(|(id, _)| **id > after)
            .take(2)
            .collect();
        let next = page
            .last()
            .filter(|(last, _)| orders.keys().any(|id| id > last))
            .map(|(last, _)| format!("/orders?limit=2&after={last}"));
        let data: Vec<_> = page
            .iter()
            .map(|(id, order_)| order(**id, order_))
            .collect();
        (
            200,
            serde_json::json!({"data": data, "links": {"next": next}}).to_string(),
        )
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
        reply.len()
    );
}

/// The `rest` Source `orders` over `url`.
fn spec(url: &str) -> SourceSpec {
    let text = |value: &str| ConfigValue::Text(value.into());
    SourceSpec {
        connector_type: "rest".into(),
        connector_version: "1".into(),
        config: SourceConfig::from([
            ("base_url".into(), text(url)),
            ("list_path".into(), text("/orders?limit=2")),
            ("check_path".into(), text("/orders?limit=1")),
            ("records_path".into(), text("/data")),
            ("next_link_path".into(), text("/links/next")),
            ("id_path".into(), text("/id")),
            ("version_path".into(), text("/version")),
            ("display_path".into(), text("/label")),
            ("record_kind".into(), text("Order")),
            ("type_digest".into(), text(&descriptor().digest)),
            ("item_path".into(), text("/orders/{id}")),
            ("writable_fields".into(), text("status")),
            ("auth_header".into(), text("x-api-key")),
        ]),
        credential_ref: "ops/orders-api".into(),
        egress: vec!["127.0.0.1".into()],
        placement: BTreeMap::from([("zone".into(), "eu".into())]),
        every_ms: 60_000,
        owner: "team".into(),
        markings: Vec::new(),
        certification_id: String::new(),
    }
}

/// The credential handle, bound to `destinations`, holding `value`.
fn bindings(dir: &std::path::Path, value: &str, destinations: &[&str]) -> CredentialBindings {
    let token = dir.join(format!("{value}-{}", destinations.join("-")));
    std::fs::write(&token, value).unwrap();
    serde_json::from_value(serde_json::json!({
        "ops/orders-api": {
            "namespaces": [NS],
            "destinations": destinations,
            "slots": { "token": { "file": token } }
        }
    }))
    .unwrap()
}

async fn start(plane: &Plane, id: &str, bindings: CredentialBindings) -> Runtime {
    let runtime = Runtime::connect(
        ClientConfig::new(&plane.endpoint, PRINCIPAL).with_default_timeout(Duration::from_secs(5)),
        &[NS.to_string()],
        RuntimeOptions {
            runtime_id: id.into(),
            labels: BTreeMap::from([("zone".into(), "eu".into())]),
            lease: LEASE,
        },
        bindings,
        Connectors::default().with(&REST_CONNECTOR, rest::open),
    )
    .await
    .unwrap();
    runtime.register().await.unwrap();
    runtime
}

fn tick(plane: &Plane) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    plane.db.tick_source_syncs(NS, now).unwrap();
}

fn requests(seen: &Seen) -> Vec<(String, String)> {
    seen.lock()
        .unwrap()
        .iter()
        .map(|(method, path, _)| (method.clone(), path.clone()))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn check_proves_the_api_answers_and_the_credential_is_accepted() {
    let api = fixture(&[101]);
    let plane = serving(&api.url).await;
    let dir = tempfile::tempdir().unwrap();
    tick(&plane);
    let runtime = start(&plane, "eu-1", bindings(dir.path(), TOKEN, &["127.0.0.1"])).await;
    let source = runtime.claim(0).await.unwrap().unwrap().source.unwrap();
    let connectors = Connectors::default().with(&REST_CONNECTOR, rest::open);

    // `check` is blocking, as the runtime runs it.
    let check = |value: &'static str| {
        let prepared = prepare(&source, &bindings(dir.path(), value, &["127.0.0.1"])).unwrap();
        let connectors = connectors.clone();
        tokio::task::spawn_blocking(move || connectors.check(&prepared))
    };
    assert_eq!(check(TOKEN).await.unwrap(), Ok(()));
    let failure = check("wrong").await.unwrap().unwrap_err();
    assert_eq!(failure, SyncFailure::AuthFailed);
    // The typed reason carries neither the response body nor a credential.
    assert_eq!(failure.wire_name(), "auth_failed");
    assert_eq!(
        requests(&api.seen),
        [
            ("GET".to_string(), "/orders?limit=1".to_string()),
            ("GET".to_string(), "/orders?limit=1".to_string()),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_killed_mid_scan_resumes_from_the_committed_cursor() {
    let ids = [101, 102, 103, 104, 105];
    let api = fixture(&ids);
    let plane = serving(&api.url).await;
    let dir = tempfile::tempdir().unwrap();
    tick(&plane);

    // A commits the first page and is killed while reading the second.
    api.stall.store(true, Ordering::SeqCst);
    let doomed = start(&plane, "eu-1", bindings(dir.path(), TOKEN, &["127.0.0.1"])).await;
    let running = tokio::spawn(async move { doomed.pass().await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !requests(&api.seen)
        .iter()
        .any(|(_, path)| path.contains("after=102"))
    {
        assert!(
            tokio::time::Instant::now() < deadline && !running.is_finished(),
            "A never reached the second page: {:?}",
            requests(&api.seen)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    running.abort();
    tokio::time::sleep(LEASE * 2).await;

    // B takes over after the lease and goes on from the committed cursor.
    let takeover = start(&plane, "eu-2", bindings(dir.path(), TOKEN, &["127.0.0.1"])).await;
    let pass = takeover.pass().await.unwrap();
    api.stall.store(false, Ordering::SeqCst);
    let (finished, lost_before) = pass.split_last().expect("B reports an outcome");
    assert_eq!(
        finished,
        &Ran::Finished {
            source_id: "orders".into(),
            outcome: Ok(())
        }
    );
    assert!(
        lost_before
            .iter()
            .all(|ran| matches!(ran, Ran::Lost { .. })),
        "{lost_before:?}"
    );
    let pages: Vec<_> = requests(&api.seen)
        .into_iter()
        .map(|(_, path)| path)
        .collect();
    assert_eq!(
        pages,
        [
            "/orders?limit=2",
            "/orders?limit=2&after=102",
            "/orders?limit=2&after=102",
            "/orders?limit=2&after=104",
        ],
        "the first page is read once, by A"
    );

    // Every record once, under its source identity, with no credential.
    for id in ids {
        let object = plane
            .db
            .get_object(&object_id_for(
                &descriptor().digest,
                &format!("orders-db:orders#Order/{id}"),
            ))
            .unwrap()
            .unwrap_or_else(|| panic!("order {id}"));
        assert_eq!(object.name, format!("order {id}"));
        let stored = serde_json::to_string(&object.properties).unwrap();
        assert!(!stored.contains(TOKEN));
    }
    let state = format!("{:?}", plane.db.get_source(NS, "orders").unwrap().unwrap());
    assert!(!state.contains(TOKEN));
    assert!(
        api.seen
            .lock()
            .unwrap()
            .iter()
            .all(|(_, _, credential)| credential == TOKEN)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_admitted_effect_is_written_once_and_a_moved_record_is_a_conflict() {
    // The effect harness decides order 1's change at version 10.
    let api = fixture(&[1]);
    let plane = serving(&api.url).await;
    let dir = tempfile::tempdir().unwrap();
    let effect_id = plane.admit(1).await;
    let runtime = start(&plane, "eu-1", bindings(dir.path(), TOKEN, &["127.0.0.1"])).await;
    assert_eq!(
        runtime.pass().await.unwrap(),
        [Ran::Effect {
            effect_id: effect_id.clone(),
            outcome: Effected::Completed {
                version: "11".into()
            },
        }]
    );
    assert_eq!(
        api.orders.lock().unwrap()[&1],
        ("11".to_string(), "shipped".to_string())
    );
    assert_eq!(plane.status_of(&effect_id).await, "completed");
    assert!(
        plane
            .db
            .reconcile_missing_execution_evidence(i64::MAX)
            .unwrap()
            .is_empty()
    );
    assert!(runtime.pass().await.unwrap().is_empty());
    let writes = |seen: &Seen| {
        requests(seen)
            .iter()
            .filter(|(method, _)| method == "PATCH")
            .count()
    };
    assert_eq!(writes(&api.seen), 1);

    // The record moved since the decision: nothing is written.
    let moved = fixture(&[1]);
    moved
        .orders
        .lock()
        .unwrap()
        .insert(1, ("12".into(), "open".into()));
    let plane = serving(&moved.url).await;
    let effect_id = plane.admit(1).await;
    let runtime = start(&plane, "eu-1", bindings(dir.path(), TOKEN, &["127.0.0.1"])).await;
    assert_eq!(
        runtime.pass().await.unwrap(),
        [Ran::Effect {
            effect_id: effect_id.clone(),
            outcome: Effected::Failed(SyncFailure::Conflict),
        }]
    );
    assert_eq!(writes(&moved.seen), 0);
    assert_eq!(plane.status_of(&effect_id).await, "failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn destinations_outside_egress_or_the_handle_are_refused_before_connecting() {
    let api = fixture(&[101]);
    let plane = serving(&api.url).await;
    let dir = tempfile::tempdir().unwrap();
    tick(&plane);

    // The handle is not bound to the fixture's address.
    let elsewhere = bindings(dir.path(), TOKEN, &["api.example.com"]);
    let runtime = start(&plane, "eu-1", elsewhere).await;
    let work = runtime.claim(0).await.unwrap().unwrap();
    let mut source = work.source.clone().unwrap();
    assert_eq!(
        runtime.run(0, work).await.unwrap(),
        Ran::Finished {
            source_id: "orders".into(),
            outcome: Err(SyncFailure::Unavailable)
        }
    );

    // The Source's allowlist does not admit the base URL.
    source.spec.as_mut().unwrap().egress = vec!["api.example.com".into()];
    assert_eq!(
        prepare(&source, &bindings(dir.path(), TOKEN, &["127.0.0.1"])).unwrap_err(),
        SyncFailure::Invalid
    );
    assert!(requests(&api.seen).is_empty(), "no connection was made");
}
