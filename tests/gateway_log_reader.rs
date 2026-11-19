//! Chisei reading a gateway egress log into receipts, `llm_calls` rows, and
//! decision entries (#3096), on SQLite and PostgreSQL. A fake gateway on an
//! ephemeral port serves `chisei.gateway-log/v1` pages the way the gateway
//! does: records after `max(after, acked)`, and acknowledgements that drop
//! what they cover.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use sekai_chisei::chisei::receipt::{
    OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
    ReceiptSurface,
};
use sekai_chisei::chisei_store::{ChiseiReceiptStore, ChiseiStore};
use sekai_chisei::composition::gateway_log_reader::{GatewayLogSource, read_once};
use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::dataset::RowQuery;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

const READER_KEY: &str = "reader-key";

#[derive(Default)]
struct FakeLog {
    records: Vec<Value>,
    acked: u64,
    /// Records served per page, so one read covers part of the log.
    page: usize,
    /// Refuse acknowledgements, as if Chisei crashed right after committing.
    refuse_ack: bool,
}

type Shared = Arc<Mutex<FakeLog>>;

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {READER_KEY}"))
}

async fn read_log(
    State(log): State<Shared>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, u64>>,
) -> Result<Json<Value>, StatusCode> {
    if !authorized(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let log = log.lock().unwrap();
    let from = query.get("after").copied().unwrap_or(0).max(log.acked);
    let limit = (query.get("limit").copied().unwrap_or(100) as usize).min(log.page);
    let records: Vec<&Value> = log.records.iter().skip(from as usize).take(limit).collect();
    Ok(Json(json!({
        "format": "chisei.gateway-log/v1",
        "records": records,
        "acked": log.acked,
        "next_seq": log.records.len() + 1,
    })))
}

async fn ack_log(
    State(log): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> StatusCode {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let mut log = log.lock().unwrap();
    let seq = body["seq"].as_u64().unwrap();
    if log.refuse_ack {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    if seq > log.records.len() as u64 {
        return StatusCode::CONFLICT;
    }
    log.acked = log.acked.max(seq);
    StatusCode::OK
}

async fn fake_gateway(log: Shared) -> String {
    let app = Router::new()
        .route("/_chisei/log", get(read_log))
        .route("/_chisei/log/ack", post(ack_log))
        .with_state(log);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

fn receipt(operation_id: &str, request_id: &str) -> OperationReceipt {
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: operation_id.into(),
        parent_operation_id: None,
        namespace: "gateway-log-ns".into(),
        operation_class: "gateway".into(),
        initiating_actor: "alice".into(),
        schema_version: "chisei.gateway/v1".into(),
        policy_version: "policy/v1".into(),
        started_at_ms: 1_000,
        completed_at_ms: Some(1_200),
        events: vec![OperationReceiptEvent {
            event_id: format!("{operation_id}-intent"),
            operation_id: operation_id.into(),
            parent_event_id: None,
            timestamp_ms: 1_000,
            kind: ReceiptEventKind::IntentRecorded,
            surface: ReceiptSurface::Intent,
            actor: "alice".into(),
            references: vec![],
            attributes: BTreeMap::from([("request_id".into(), request_id.into())]),
        }],
        uncovered_surfaces: vec![],
        reporter_grants: vec![],
        ontology_digest: None,
        artifact: None,
    }
}

fn admission(seq: u64, request_id: &str) -> Value {
    json!({
        "seq": seq, "kind": "admission", "request_id": request_id,
        "operation_id": format!("{request_id}-op"), "principal": "alice",
        "provider": "openai", "model": "gpt-5.5", "data_class": "internal",
        "policy_version": "3", "at_ms": 1_000,
    })
}

fn usage(seq: u64, request_id: &str) -> Value {
    json!({
        "seq": seq, "kind": "usage", "request_id": request_id,
        "operation_id": format!("{request_id}-op"), "provider_ordinal": 0,
        "status": 200, "outcome": "success", "input_tokens": 3, "output_tokens": 4,
        "total_tokens": 7, "latency_ms": 20, "at_ms": 1_200,
        "receipt": receipt(&format!("{request_id}-receipt"), request_id),
        "llm_calls_row": {
            "request_id": request_id,
            "receipt_id": format!("{request_id}-receipt"),
            "status": "200",
            "data_class": "internal",
        },
    })
}

/// r1 is forwarded and used, r2 is admitted and never forwarded, r3 is
/// forwarded and used.
fn gateway_log(prefix: &str, page: usize) -> Shared {
    let (r1, r2, r3) = (
        format!("{prefix}-r1"),
        format!("{prefix}-r2"),
        format!("{prefix}-r3"),
    );
    Arc::new(Mutex::new(FakeLog {
        records: vec![
            admission(1, &r1),
            usage(2, &r1),
            admission(3, &r2),
            admission(4, &r3),
            usage(5, &r3),
        ],
        page,
        ..FakeLog::default()
    }))
}

struct Stores {
    sekai: Arc<RuntimeDb>,
    chisei: ChiseiStore,
}

fn stores(sekai: RuntimeDb) -> Stores {
    let sekai = Arc::new(sekai);
    Stores {
        chisei: ChiseiStore::from_shared_runtime(sekai.clone()),
        sekai,
    }
}

/// Closes stores as a stopped process would; a PostgreSQL pool must not be
/// dropped on an async worker.
fn close(stores: Stores) {
    tokio::task::block_in_place(|| drop(stores));
}

async fn drain(client: &reqwest::Client, source: &GatewayLogSource, stores: &Stores) {
    while read_once(client, source, &stores.chisei, &stores.sekai)
        .await
        .unwrap()
        > 0
    {}
}

fn llm_rows(sekai: &RuntimeDb, prefix: &str) -> Vec<String> {
    let query = RowQuery {
        limit: 100_000,
        ..RowQuery::default()
    };
    let mut ids: Vec<String> = sekai
        .query_rows("llm_calls", &query)
        .unwrap()
        .into_iter()
        .filter_map(|row| row.get("request_id").cloned())
        .filter(|id| id.starts_with(prefix))
        .collect();
    ids.sort();
    ids
}

fn assert_applied_once(stores: &Stores, gateway: &str, prefix: &str) {
    assert_eq!(
        llm_rows(&stores.sekai, prefix),
        [format!("{prefix}-r1"), format!("{prefix}-r3")],
        "each used request has exactly one llm_calls row"
    );
    for request in ["r1", "r3"] {
        let id = format!("{prefix}-{request}-receipt");
        assert!(stores.chisei.get_operation_receipt(&id).unwrap().is_some());
    }
    assert_eq!(stores.sekai.gateway_log_cursor(gateway).unwrap(), 5);
    let actions: Vec<String> = (1..=5)
        .map(|seq| {
            let decision = stores
                .sekai
                .get_decision(&format!("gateway-log:{gateway}:{seq}"))
                .unwrap()
                .expect("one decision entry per record");
            decision.action
        })
        .collect();
    assert_eq!(
        actions,
        [
            "gateway.admission",
            "operation.receipt.upsert",
            "gateway.admission",
            "gateway.admission",
            "operation.receipt.upsert",
        ]
    );
}

/// Runs the acceptance scenarios; `open` opens the same durable stores again,
/// as a restarted process would.
async fn exercise(open: impl Fn() -> RuntimeDb, prefix: &str) {
    let client = reqwest::Client::new();

    // A receipt written by a reader that crashed before its Sekai commit,
    // then a reader that commits two records and crashes before acknowledging.
    let gateway = format!("{prefix}-edge");
    let log = gateway_log(prefix, 2);
    log.lock().unwrap().refuse_ack = true;
    let source = GatewayLogSource::new(&gateway, &fake_gateway(log.clone()).await, READER_KEY);
    let first = stores(open());
    first
        .chisei
        .put_operation_receipt(&receipt(
            &format!("{prefix}-r1-receipt"),
            &format!("{prefix}-r1"),
        ))
        .unwrap();
    let crashed = read_once(&client, &source, &first.chisei, &first.sekai).await;
    assert!(crashed.unwrap_err().contains("acknowledge"));
    assert_eq!(first.sekai.gateway_log_cursor(&gateway).unwrap(), 2);
    assert_eq!(log.lock().unwrap().acked, 0);
    close(first);

    // The restarted reader resumes from its cursor and acknowledges.
    log.lock().unwrap().refuse_ack = false;
    let restarted = stores(open());
    drain(&client, &source, &restarted).await;
    assert_eq!(log.lock().unwrap().acked, 5);
    assert_applied_once(&restarted, &gateway, prefix);

    // An admission that was never forwarded leaves its entry and no row.
    let unforwarded = restarted
        .sekai
        .get_decision(&format!("gateway-log:{gateway}:3"))
        .unwrap()
        .unwrap();
    assert_eq!(unforwarded.outcome, "admitted");
    assert_eq!(unforwarded.target_id, format!("{prefix}-r2-op"));
    assert!(!llm_rows(&restarted.sekai, prefix).contains(&format!("{prefix}-r2")));

    // Two readers over one gateway apply each record once.
    let shared_prefix = format!("{prefix}-pair");
    let shared = format!("{shared_prefix}-edge");
    let log = gateway_log(&shared_prefix, 1);
    let source = GatewayLogSource::new(&shared, &fake_gateway(log.clone()).await, READER_KEY);
    let (a, b) = (stores(open()), stores(open()));
    tokio::join!(drain(&client, &source, &a), drain(&client, &source, &b));
    drain(&client, &source, &a).await;
    assert_eq!(log.lock().unwrap().acked, 5);
    assert_applied_once(&a, &shared, &shared_prefix);
    for stores in [restarted, a, b] {
        close(stores);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_gateway_log_reader_applies_each_record_once() {
    let dir = std::env::temp_dir().join(format!(
        "gateway-log-reader-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.db").to_string_lossy().into_owned();
    exercise(
        || {
            RuntimeDb::Sqlite(Arc::new(
                sekai_chisei::chisei_store::open_sekai_with_chisei_schema(&path),
            ))
        },
        "sqlite",
    )
    .await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
async fn postgres_gateway_log_reader_applies_each_record_once() {
    // The synchronous client must not open on an async worker.
    let open = || {
        tokio::task::block_in_place(|| {
            let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
                .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
            let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
                PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap())
                    .unwrap()
            } else {
                PostgresDb::connect(&url, 8).unwrap()
            };
            RuntimeDb::Postgres(Arc::new(
                sekai_chisei::chisei_store::postgres_with_chisei_schema(db),
            ))
        })
    };
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(open, &prefix).await;
}
