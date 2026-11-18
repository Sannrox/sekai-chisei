//! `sekaictl admin gateway setup` and `key` commands against a running
//! in-process control plane.
//!
//! Only the root crate builds the Sekai and Chisei gRPC services, so these
//! tests live here; the admin client's own unit tests stay in
//! `crates/sekai-admin-client` and no longer rebuild on root edits (#2590).

use std::sync::Arc;

use sekai_admin_client::gateway_setup::{GatewaySetupConfig, run_gateway_key_command, run_setup};
use sekai_chisei::chisei_store::ChiseiRuntimeDb;
use sekai_chisei::config::Config;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_domain::gateway_keys::hash_gateway_key;
use sekai_proto::chisei::chisei_service_server::ChiseiServiceServer;
use sekai_proto::sekai::sekai_service_server::SekaiServiceServer;
use tonic::transport::Server;

fn test_config() -> Config {
    Config {
        grpc_port: 0,
        sekai_bind: None,
        ops_port: None,
        ops_bind: "127.0.0.1".into(),
        http_port: None,
        http_bind: "127.0.0.1".into(),
        sekai_socket: None,
        db_path: ":memory:".into(),
        anthropic_api_key: None,
        openai_api_key: Some("test-openai-key".into()),
        ollama_url: "http://127.0.0.1:11434".into(),
        native_llm_url: None,
        sample_rate: 0.0,
        sample_risk_threshold: 0.7,
        scoring_enabled: false,
        scoring_interval_secs: 60,
        scoring_model: "claude-opus-4-8".into(),
        scoring_batch_size: 16,
        default_data_class: "unclassified".into(),
        safe_egress_providers: vec![],
        gateway_provided_providers: vec![],
        routing_endpoint_allowlist: vec![],
        routing_credential_refs: vec![],
        gateway_receipt_principals: vec![],
        leak_review_model: None,
        tls_cert: None,
        tls_key: None,
        allow_plaintext: false,
        insecure: false,
        permit_signing_key: None,
        permit_issuer: "chisei.local".into(),
        permit_key_id: "permit-key-1".into(),
        governed_subject_provenance_signing_key: None,
        governed_subject_provenance_key_not_before_ms: 0,
        governed_subject_provenance_key_expires_at_ms: i64::MAX,
        governed_subject_provenance_ttl_ms: 24 * 60 * 60 * 1_000,
        site_id: "local".into(),
        budget_topology: Default::default(),
        assertion_issuer: None,
        assertion_audience: None,
        assertion_hmac_key: None,
        sekai_endpoint: None,
        actor_chain_enforcement: false,
        principal_requests_per_minute: 60,
        agent_requests_per_minute: 60,
    }
}

async fn spawn_control_plane() -> (String, Arc<RuntimeDb>) {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));

    let sekai_store = sekai_chisei::db::store::SekaiStore::from_shared_runtime(db.clone());
    let sekai_svc = SekaiServiceImpl::new(sekai_store.clone());
    let chisei_store = sekai_chisei::chisei_store::ChiseiStore::from_shared_runtime(db.clone());
    let _ = sekai_chisei::chisei::model_review::enable_registry_provider_families(&chisei_store);
    let chisei_svc = ChiseiServiceImpl::new(chisei_store, test_config())
        .with_sekai_facts(sekai_chisei::chisei::sekai_facts::SekaiFacts::in_process(
            sekai_store,
        ))
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(SekaiServiceServer::new(sekai_svc))
            .add_service(ChiseiServiceServer::new(chisei_svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    (format!("http://{addr}"), db)
}

#[tokio::test]
async fn setup_seeds_gateway_objects_budget_policy_and_dataset() {
    let (target, db) = spawn_control_plane().await;
    run_setup(GatewaySetupConfig {
        chisei_grpc_target: target.clone(),
        agent: "codex-app".to_string(),
        project: "sekai-chisei".to_string(),
        gateway_key_name: "codex-app".to_string(),
        gateway_key_secret: "sk-chisei-codex-app".to_string(),
        budget_tokens: 42,
        budget_period: "day".to_string(),
        request_budget: Some(7),
        request_budget_period: "day".to_string(),
        allowed_models: vec!["gpt-5.5".to_string()],
        allowed_runtimes: Vec::new(),
        tier: "standard".to_string(),
        default_model: "gpt-5.5".to_string(),
        default_runtime: "openai".to_string(),
        merge_into_existing: false,
        policy_scopes: Vec::new(),
    })
    .await
    .unwrap();

    assert!(
        db.find_by_external_id("project:sekai-chisei")
            .unwrap()
            .is_some()
    );
    assert!(db.find_by_external_id("agent:codex-app").unwrap().is_some());
    assert!(
        db.find_by_external_id("gateway_key:codex-app")
            .unwrap()
            .is_some()
    );
    assert!(
        db.find_by_external_id("budget:codex-app:day")
            .unwrap()
            .is_some()
    );
    let policy = db
        .find_by_external_id("policy:sekai-chisei")
        .unwrap()
        .unwrap();
    assert_eq!(
        policy.properties.get("default_model").map(String::as_str),
        Some("gpt-5.5")
    );
    assert!(
        policy
            .properties
            .get("context_admission_policy_json")
            .is_some_and(|value| value.contains("chisei.context-admission/v1")),
        "gateway setup must seed a context-admission policy"
    );
    assert!(db.get_dataset("llm_calls").unwrap().is_some());
    let key = db
        .find_by_external_id("gateway_key:codex-app")
        .unwrap()
        .unwrap();
    let agent = db.find_by_external_id("agent:codex-app").unwrap().unwrap();
    let project = db
        .find_by_external_id("project:sekai-chisei")
        .unwrap()
        .unwrap();
    let budget_obj = db
        .find_by_external_id("budget:codex-app:day")
        .unwrap()
        .unwrap();
    assert_eq!(
        db.get_links(
            &key.id,
            "identifies",
            &sekai_chisei::domain::Direction::Outgoing
        )
        .unwrap()
        .first()
        .map(|link| link.to_id.as_str()),
        Some(agent.id.as_str())
    );
    assert_eq!(
        db.get_links(
            &agent.id,
            "works_on",
            &sekai_chisei::domain::Direction::Outgoing
        )
        .unwrap()
        .first()
        .map(|link| link.to_id.as_str()),
        Some(project.id.as_str())
    );
    assert_eq!(
        db.get_links(
            &budget_obj.id,
            "limits",
            &sekai_chisei::domain::Direction::Outgoing
        )
        .unwrap()
        .first()
        .map(|link| link.to_id.as_str()),
        Some(agent.id.as_str())
    );
    assert_eq!(
        db.get_links(
            &policy.id,
            "applies_to",
            &sekai_chisei::domain::Direction::Outgoing
        )
        .unwrap()
        .first()
        .map(|link| link.to_id.as_str()),
        Some(project.id.as_str())
    );
    let expected_key_hash = hash_gateway_key("sk-chisei-codex-app");
    assert_eq!(
        key.properties.get("key_hash").map(String::as_str),
        Some(expected_key_hash.as_str())
    );
    assert_eq!(
        key.properties.get("status").map(String::as_str),
        Some("active")
    );

    let request_budget_project = db
        .gateway_test_budget_usage(
            "project:sekai-chisei",
            "requests",
            chrono::Utc::now().timestamp_millis(),
        )
        .unwrap();
    let request_budget_agent = db
        .gateway_test_budget_usage(
            "project:sekai-chisei/agent:codex-app",
            "requests",
            chrono::Utc::now().timestamp_millis(),
        )
        .unwrap();
    assert_eq!(request_budget_project.1, 7);
    assert_eq!(request_budget_agent.1, 7);

    run_gateway_key_command([
        "rotate".to_string(),
        "--target".to_string(),
        target.clone(),
        "--gateway-key-name".to_string(),
        "codex-app".to_string(),
        "--gateway-key".to_string(),
        "sk-chisei-codex-app-rotated".to_string(),
    ])
    .await
    .unwrap();
    let rotated_key = db
        .find_by_external_id("gateway_key:codex-app")
        .unwrap()
        .unwrap();
    assert_eq!(
        rotated_key.properties.get("key_hash").map(String::as_str),
        Some(hash_gateway_key("sk-chisei-codex-app-rotated").as_str())
    );
    assert_eq!(
        rotated_key.properties.get("status").map(String::as_str),
        Some("active")
    );
    assert!(rotated_key.properties.contains_key("rotated_at"));

    run_gateway_key_command([
        "list".to_string(),
        "--target".to_string(),
        target.clone(),
        "--project".to_string(),
        "sekai-chisei".to_string(),
    ])
    .await
    .unwrap();

    run_gateway_key_command([
        "revoke".to_string(),
        "--target".to_string(),
        target,
        "--gateway-key-name".to_string(),
        "codex-app".to_string(),
    ])
    .await
    .unwrap();
    let revoked_key = db
        .find_by_external_id("gateway_key:codex-app")
        .unwrap()
        .unwrap();
    assert_eq!(
        revoked_key.properties.get("status").map(String::as_str),
        Some("revoked")
    );
    assert!(revoked_key.properties.contains_key("revoked_at"));
}

#[tokio::test]
async fn scope_policy_flag_creates_scoped_policy_row() {
    let (target, db) = spawn_control_plane().await;
    run_setup(GatewaySetupConfig {
        chisei_grpc_target: target.clone(),
        agent: "codex-app".to_string(),
        project: "sekai-chisei".to_string(),
        gateway_key_name: "codex-app".to_string(),
        gateway_key_secret: "sk-chisei-codex-app".to_string(),
        budget_tokens: 1000,
        budget_period: "day".to_string(),
        request_budget: None,
        request_budget_period: "day".to_string(),
        allowed_models: vec!["gpt-5.5".to_string()],
        allowed_runtimes: Vec::new(),
        tier: "standard".to_string(),
        default_model: "gpt-5.5".to_string(),
        default_runtime: "openai".to_string(),
        merge_into_existing: false,
        policy_scopes: vec!["agent:codex-app".to_string()],
    })
    .await
    .unwrap();

    let scoped = db
        .find_by_external_id("policy:agent:codex-app")
        .unwrap()
        .unwrap();
    assert_eq!(
        scoped.properties.get("namespace").map(String::as_str),
        Some("agent:codex-app")
    );
    assert_eq!(
        scoped.properties.get("default_model").map(String::as_str),
        Some("gpt-5.5")
    );
}

#[tokio::test]
async fn key_create_seeds_gateway_setup() {
    let (target, db) = spawn_control_plane().await;
    run_gateway_key_command([
        "create".to_string(),
        "worker-one".to_string(),
        "--target".to_string(),
        target,
        "--agent".to_string(),
        "worker-one".to_string(),
        "--project".to_string(),
        "sekai-chisei".to_string(),
        "--gateway-key".to_string(),
        "sk-chisei-worker-one".to_string(),
        "--budget".to_string(),
        "100".to_string(),
        "--allowed-model".to_string(),
        "gpt-5.5".to_string(),
    ])
    .await
    .unwrap();

    let key = db
        .find_by_external_id("gateway_key:worker-one")
        .unwrap()
        .unwrap();
    assert_eq!(key.name, "worker-one");
    assert_eq!(
        key.properties.get("agent").map(String::as_str),
        Some("worker-one")
    );
    assert_eq!(
        key.properties.get("key_hash").map(String::as_str),
        Some(hash_gateway_key("sk-chisei-worker-one").as_str())
    );
    assert!(db.get_dataset("llm_calls").unwrap().is_some());
}

fn setup_config(
    target: &str,
    agent: &str,
    default_model: &str,
    default_runtime: &str,
    allowed: &[&str],
    merge: bool,
) -> GatewaySetupConfig {
    GatewaySetupConfig {
        chisei_grpc_target: target.to_string(),
        agent: agent.to_string(),
        project: "sekai-chisei".to_string(),
        gateway_key_name: agent.to_string(),
        gateway_key_secret: format!("sk-chisei-{agent}"),
        budget_tokens: 1000,
        budget_period: "day".to_string(),
        request_budget: None,
        request_budget_period: "day".to_string(),
        allowed_models: allowed.iter().map(|m| m.to_string()).collect(),
        allowed_runtimes: Vec::new(),
        tier: "standard".to_string(),
        default_model: default_model.to_string(),
        default_runtime: default_runtime.to_string(),
        merge_into_existing: merge,
        policy_scopes: Vec::new(),
    }
}

#[tokio::test]
async fn merge_policy_preserves_existing_default_and_unions_allowed() {
    let (target, db) = spawn_control_plane().await;

    // Codex seeds first with a custom default and its own runtime/models.
    run_setup(setup_config(
        &target,
        "codex-app",
        "gpt-6",
        "openai",
        &["gpt-6", "gpt-5.5"],
        false,
    ))
    .await
    .unwrap();

    // Sanity: codex persisted gpt-6 before the claude launch runs.
    let after_codex = db
        .find_by_external_id("policy:sekai-chisei")
        .unwrap()
        .unwrap();
    assert_eq!(
        after_codex
            .properties
            .get("default_model")
            .map(String::as_str),
        Some("gpt-6")
    );

    // Claude launches later with merge: it must NOT reset the auto default,
    // only add its own runtime/models to the allowed union.
    run_setup(setup_config(
        &target,
        "claude-code",
        "gpt-5.5",
        "anthropic",
        &["claude-sonnet-4-6", "claude-haiku-4-5"],
        true,
    ))
    .await
    .unwrap();

    let policy = db
        .find_by_external_id("policy:sekai-chisei")
        .unwrap()
        .unwrap();
    // Preserved Codex default, not reset to the claude launch's gpt-5.5 arg.
    assert_eq!(
        policy.properties.get("default_model").map(String::as_str),
        Some("gpt-6")
    );
    assert_eq!(
        policy.properties.get("default_runtime").map(String::as_str),
        Some("openai")
    );
    // Allowed models are the union of both launches.
    let allowed = policy
        .properties
        .get("allowed_models")
        .map(String::as_str)
        .unwrap_or_default();
    for model in ["gpt-6", "gpt-5.5", "claude-sonnet-4-6", "claude-haiku-4-5"] {
        assert!(
            allowed.contains(model),
            "allowed {allowed:?} missing {model}"
        );
    }
    // Allowed runtimes union both provider families.
    let runtimes = policy
        .properties
        .get("allowed_runtimes")
        .map(String::as_str)
        .unwrap_or_default();
    assert!(runtimes.contains("openai"), "runtimes {runtimes:?}");
    assert!(runtimes.contains("anthropic"), "runtimes {runtimes:?}");
}

#[tokio::test]
async fn merge_policy_on_fresh_namespace_uses_config_defaults() {
    let (target, db) = spawn_control_plane().await;

    // No existing policy: merge falls back to this config's own defaults.
    run_setup(setup_config(
        &target,
        "claude-code",
        "claude-sonnet-4-6",
        "anthropic",
        &["claude-sonnet-4-6"],
        true,
    ))
    .await
    .unwrap();

    let policy = db
        .find_by_external_id("policy:sekai-chisei")
        .unwrap()
        .unwrap();
    assert_eq!(
        policy.properties.get("default_model").map(String::as_str),
        Some("claude-sonnet-4-6")
    );
    assert_eq!(
        policy.properties.get("default_runtime").map(String::as_str),
        Some("anthropic")
    );
}
