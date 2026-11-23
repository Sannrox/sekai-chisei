//! The Action binding RPCs are stable (#3036): a plane with experimental RPCs
//! off serves put, get, list, and run to the typed client on SQLite and
//! PostgreSQL, and a caller who neither runs a binding nor administers its
//! namespace cannot read it.

use std::sync::Arc;
use std::time::Duration;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::rpc_maturity::RpcMaturityLayer;
use sekai_chisei::sekai::governed_action_type::GovernedActionType;
use sekai_chisei::sekai::security::Role;
use sekai_client::{ClientConfig, CoreLoopClient, GrpcTransport};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::Layer;

use crate::postgres_scratch::ScratchDatabase;

const NAMESPACE: &str = "ops";

fn binding(binding_id: &str, run_as: &str) -> String {
    json!({
        "contract_version": "sekai.action-binding/v1",
        "binding_id": binding_id,
        "namespace": NAMESPACE,
        "kind": "component",
        "ops": ["update"],
        "type_id": "component.escalate",
        "version": "1",
        "run_as": run_as,
        "parameters": {"component": {"source": "object_id"}},
        "enabled": true
    })
    .to_string()
}

fn seed(db: &RuntimeDb) {
    for (principal, role) in [
        ("alice", Role::Admin),
        ("svc-a", Role::Editor),
        ("svc-b", Role::Editor),
        ("mallory", Role::Editor),
    ] {
        db.ensure_team_namespace(NAMESPACE, principal, role, "local")
            .unwrap();
    }
    db.put_governed_action_type(
        GovernedActionType {
            namespace: NAMESPACE.into(),
            type_id: "component.escalate".into(),
            version: "1".into(),
            description: "Escalate a component".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"component":{"type":"string"}},"required":["component"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            enabled: true,
            ..Default::default()
        },
        "local",
        1,
    )
    .unwrap();
}

/// Seeds `db` on the test thread, then serves it from a multi-threaded
/// runtime, as the server does, so a handler that blocks a runtime worker on
/// the store fails here too.
fn exercise(db: RuntimeDb) {
    seed(&db);
    let db = Arc::new(db);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(serve_and_call(db.clone()));
    // The last handle drops here, off the runtime: closing a PostgreSQL pool
    // blocks.
    drop(db);
}

async fn serve_and_call(db: Arc<RuntimeDb>) {
    let store = SekaiStore::from_shared_runtime(db);
    // Experimental RPCs off: the gate a default plane applies.
    let service =
        RpcMaturityLayer::new(false).layer(SekaiServiceServer::new(SekaiServiceImpl::new(store)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let client = |principal: &'static str| {
        let endpoint = endpoint.clone();
        async move {
            CoreLoopClient::<GrpcTransport>::connect(
                ClientConfig::new(&endpoint, principal)
                    .with_namespace(NAMESPACE)
                    .with_default_timeout(Duration::from_secs(5)),
            )
            .await
            .unwrap()
        }
    };
    let alice = client("alice").await;
    let admin = alice.action_bindings();

    let installed = admin.put(binding("escalate-a", "svc-a")).await.unwrap();
    assert_eq!(installed.revision, 1);
    admin.put(binding("escalate-b", "svc-b")).await.unwrap();
    let fetched = admin.get(NAMESPACE, "escalate-a").await.unwrap().unwrap();
    assert_eq!(fetched, installed);
    let stored: Value = serde_json::from_str(&fetched.binding_json).unwrap();
    assert_eq!(stored["run_as"], "svc-a");

    // Pages by binding id; the token carries the caller to the next one.
    let first = admin.list(NAMESPACE, 1, "").await.unwrap();
    assert_eq!(first.bindings, std::slice::from_ref(&installed));
    let second = admin
        .list(NAMESPACE, 1, first.next_page_token)
        .await
        .unwrap();
    assert_eq!(second.bindings.len(), 1);
    assert!(second.next_page_token.is_empty());

    // The run_as principal reads and runs its own binding, and nothing else.
    let svc_a = client("svc-a").await;
    let own = svc_a
        .action_bindings()
        .list(NAMESPACE, 0, "")
        .await
        .unwrap();
    assert_eq!(own.bindings, std::slice::from_ref(&installed));
    assert!(
        svc_a
            .action_bindings()
            .get(NAMESPACE, "escalate-b")
            .await
            .unwrap()
            .is_none()
    );
    let run = svc_a
        .action_bindings()
        .run(NAMESPACE, "escalate-a", 16)
        .await
        .unwrap();
    assert_eq!(run.binding_revision, 1);
    assert!(run.submissions.is_empty(), "{run:?}");

    // A namespace editor that runs no binding sees none of them.
    let mallory = client("mallory").await;
    let bindings = mallory.action_bindings();
    assert!(
        bindings
            .get(NAMESPACE, "escalate-a")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        bindings
            .list(NAMESPACE, 0, "")
            .await
            .unwrap()
            .bindings
            .is_empty()
    );
    assert!(
        bindings
            .put(binding("escalate-c", "mallory"))
            .await
            .is_err()
    );

    let _ = stop.send(());
    server.await.unwrap();
}

#[test]
fn sqlite_plane_serves_action_bindings_to_the_typed_client() {
    exercise(RuntimeDb::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_plane_serves_action_bindings_to_the_typed_client() {
    let scratch = ScratchDatabase::create();
    exercise(RuntimeDb::Postgres(Arc::new(scratch.connect(8))));
}
