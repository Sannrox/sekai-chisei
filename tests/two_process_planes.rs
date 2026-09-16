use sekai_chisei::config::Config;
use sekai_chisei::domain::{KIND_COMPONENT, Object};
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::chisei::{GetOperationReceiptRequest, InvokeActionInstanceRequest};
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{GetActionInstanceRequest, GetObjectRequest};
use sekai_chisei::grpc::{ServicePlane, run, run_chisei_plane};
use sekai_chisei::runtime_backend::{RuntimeBackend, RuntimeBackendConfig};
use sekai_chisei::sekai::governed_action_type::EFFECT_KIND_NOTIFY;
use sekai_chisei::sekai::governed_action_type::GovernedActionType;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn test_config(db_path: &str, port: u16) -> Config {
    let mut config = Config::from_env();
    config.grpc_port = port;
    config.sekai_bind = Some("127.0.0.1".into());
    config.sekai_socket = None;
    config.http_port = None;
    config.ops_port = None;
    config.insecure = true;
    config.db_path = db_path.to_string();
    config
}

#[tokio::test]
async fn chisei_plane_invokes_through_sekai_clerk() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("sekai.db");
    let db_path = db_path.to_str().expect("utf8");
    let backend = Arc::new(
        RuntimeBackend::initialize(
            RuntimeBackendConfig::from_env(db_path).expect("backend config"),
        )
        .expect("backend"),
    );
    let db = backend.database();
    db.create_object(&Object {
        id: "obj-plane-1".into(),
        kind: KIND_COMPONENT.into(),
        name: "router".into(),
        namespace: "ops".into(),
        external_id: String::new(),
        properties: Default::default(),
        created: 1,
        updated: 1,
    })
    .expect("seed object");
    db.put_governed_action_type(
        GovernedActionType {
            namespace: "ops".into(),
            type_id: "plane.notify".into(),
            version: "1".into(),
            description: "slice".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"note":{"type":"string"}},"required":["note"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            enabled: true,
            ..Default::default()
        },
        "local",
        1,
    )
    .expect("seed type");
    let sekai_port = free_port();
    let chisei_port = free_port();
    let mut sekai_config = test_config(db_path, sekai_port);
    sekai_config.allow_plaintext = true;
    let mut chisei_config = test_config(db_path, chisei_port);
    chisei_config.allow_plaintext = true;
    let tcp_mode = sekai_config.grpc_tcp_mode(false);

    let sekai = run(
        sekai_config,
        Arc::clone(&backend),
        Vec::new(),
        tcp_mode.clone(),
        ServicePlane::Sekai,
    )
    .expect("sekai plane");
    tokio::spawn(async move {
        let _ = sekai.await;
    });

    unsafe {
        std::env::set_var(
            "CHISEI_SEKAI_ENDPOINT",
            format!("http://127.0.0.1:{sekai_port}"),
        );
    }
    let chisei_tcp = chisei_config.grpc_tcp_mode(false);
    let chisei = run_chisei_plane(chisei_config, chisei_tcp).expect("chisei plane");
    tokio::spawn(async move {
        let _ = chisei.await;
    });

    let sekai_endpoint = format!("http://127.0.0.1:{sekai_port}");
    let chisei_endpoint = format!("http://127.0.0.1:{chisei_port}");
    let mut sekai_client = wait_sekai(&sekai_endpoint).await;
    let mut chisei_client = wait_chisei(&chisei_endpoint).await;

    let fetched = sekai_client
        .get_object(tonic::Request::new(GetObjectRequest {
            id: "obj-plane-1".into(),
        }))
        .await
        .expect("get object");
    assert_eq!(fetched.into_inner().object.unwrap().id, "obj-plane-1");

    let invoked = chisei_client
        .invoke_action_instance(tonic::Request::new(InvokeActionInstanceRequest {
            namespace: "ops".into(),
            type_id: "plane.notify".into(),
            version: "1".into(),
            parameters_json: r#"{"note":"plane"}"#.into(),
            idempotency_key: "plane-key-1".into(),
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: String::new(),
        }))
        .await
        .expect("invoke")
        .into_inner();
    assert!(!invoked.instance_json.is_empty());
    assert!(!invoked.receipt_json.is_empty());
    let instance: serde_json::Value =
        serde_json::from_str(&invoked.instance_json).expect("instance json");
    assert_eq!(instance["status"], "admitted");
    let operation_id = instance["operation_id"].as_str().expect("operation_id");

    let receipt = chisei_client
        .get_operation_receipt(tonic::Request::new(GetOperationReceiptRequest {
            operation_id: operation_id.to_string(),
            request_id: String::new(),
            caller_scope: String::new(),
            attempt: 0,
        }))
        .await
        .expect("receipt")
        .into_inner();
    assert!(receipt.complete);
    assert!(receipt.receipt_json.contains(operation_id));

    let stored = sekai_client
        .get_action_instance(tonic::Request::new(GetActionInstanceRequest {
            instance_id: instance["instance_id"].as_str().unwrap().to_string(),
            namespace: String::new(),
            idempotency_key: String::new(),
        }))
        .await
        .expect("get instance");
    assert_eq!(stored.into_inner().instance.unwrap().status, "admitted");
}

async fn wait_sekai(endpoint: &str) -> SekaiServiceClient<tonic::transport::Channel> {
    for _ in 0..80 {
        if let Ok(client) = SekaiServiceClient::connect(endpoint.to_string()).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("sekai plane did not become ready at {endpoint}");
}

async fn wait_chisei(endpoint: &str) -> ChiseiServiceClient<tonic::transport::Channel> {
    for _ in 0..80 {
        if let Ok(client) = ChiseiServiceClient::connect(endpoint.to_string()).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("chisei plane did not become ready at {endpoint}");
}
