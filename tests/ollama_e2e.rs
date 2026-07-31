use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use sekai_chisei::chisei::evaluation_execution::{
    STATUS_PASS, STOCHASTIC_TRIAL_RESULT_CONTRACT, build_evaluator_input, execute_stochastic_node,
};
use sekai_chisei::chisei::evaluation_manifest::{
    MANIFEST_CONTRACT, RESOLVER_VERSION, ResolvedEvaluationManifest, ResolvedEvaluationNode,
    ResolvedEvaluatorBinding, ResolvedInvariantBinding,
};
use sekai_chisei::chisei::evaluation_plan::{
    EvaluatorResourceLimits, NODE_REQUIRED, STOCHASTIC_AGGREGATION_MEAN_VARIANCE,
    STOCHASTIC_EGRESS_LOCAL_ONLY, STOCHASTIC_RAW_RETENTION_NONE, StochasticEvaluatorPolicy,
};
use sekai_chisei::chisei::stochastic_evaluation::{
    BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST, BOUNDED_RUBRIC_PROFILE, BOUNDED_RUBRIC_PROFILE_DIGEST,
    production_stochastic_evaluator_registry,
};
use sekai_chisei::config::Config;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::Object;
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::chisei::chisei_service_server::ChiseiServiceServer;
use sekai_chisei::grpc::pb::chisei::{
    ExecutePlanRequest, ExecutionInput, PlanExecutionRequest, ResolvePolicyRequest,
};
use tokio::time::sleep;
use tonic::transport::Server;

fn e2e_model() -> String {
    let model = std::env::var("OLLAMA_E2E_MODEL").unwrap_or_else(|_| "llama3.2:latest".into());
    if model.starts_with("ollama/") {
        model
    } else {
        format!("ollama/{model}")
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn ollama_config(db_path: String) -> Config {
    Config {
        grpc_port: 0,
        sekai_bind: None,
        ops_port: None,
        ops_bind: "127.0.0.1".into(),
        sekai_socket: None,
        db_path,
        anthropic_api_key: None,
        openai_api_key: None,
        ollama_url: std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".into()),
        native_llm_url: None,
        auth_token: None,
        sample_rate: 0.05,
        sample_risk_threshold: 0.7,
        scoring_enabled: false,
        scoring_interval_secs: 60,
        scoring_model: "claude-opus-4-8".into(),
        scoring_batch_size: 16,
        default_data_class: "unclassified".into(),
        safe_egress_providers: vec![],
        gateway_provided_providers: vec![],
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
    }
}

fn free_local_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind local test port")
        .local_addr()
        .expect("resolve local test port")
}

async fn connect_with_retry(addr: SocketAddr) -> ChiseiServiceClient<tonic::transport::Channel> {
    let endpoint = format!("http://{addr}");
    let mut last_err = None;

    for _ in 0..20 {
        match ChiseiServiceClient::connect(endpoint.clone()).await {
            Ok(client) => return client,
            Err(err) => {
                last_err = Some(err);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }

    panic!("failed to connect to test server: {last_err:?}");
}

#[test]
#[ignore = "requires a local Ollama server and downloaded model"]
fn bounded_stochastic_evaluator_records_live_variance_evidence() {
    let registry_path = std::env::temp_dir().join(format!(
        "sekai-stochastic-ollama-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let registry = production_stochastic_evaluator_registry(ollama_config(
        registry_path.display().to_string(),
    ))
    .expect("create stochastic registry");
    let model = e2e_model();
    let policy = StochasticEvaluatorPolicy {
        provider: "ollama".into(),
        model,
        prompt_profile: BOUNDED_RUBRIC_PROFILE.into(),
        prompt_profile_digest: BOUNDED_RUBRIC_PROFILE_DIGEST.into(),
        result_schema: STOCHASTIC_TRIAL_RESULT_CONTRACT.into(),
        trial_count: 2,
        temperature_millis: 200,
        top_p_millionths: 900_000,
        seed_supported: false,
        base_seed: 0,
        aggregation_rule: STOCHASTIC_AGGREGATION_MEAN_VARIANCE.into(),
        minimum_mean_score_micros: 0,
        minimum_pass_rate_basis_points: 0,
        maximum_score_variance_micros_squared: 1_000_000_000_000,
        gate_eligible: false,
        max_retries_per_trial: 0,
        max_tokens_per_trial: 16_384,
        max_total_tokens: 32_768,
        egress_policy: STOCHASTIC_EGRESS_LOCAL_ONLY.into(),
        raw_response_retention: STOCHASTIC_RAW_RETENTION_NONE.into(),
    };
    let node = ResolvedEvaluationNode {
        node_id: "live-model-review".into(),
        evaluator: ResolvedEvaluatorBinding {
            definition_id: "evaluator:live-model-review".into(),
            definition_digest: digest('a'),
            implementation_digest: BOUNDED_RUBRIC_IMPLEMENTATION_DIGEST.into(),
            stochastic_policy: Some(policy),
        },
        depends_on_node_ids: vec![],
        input_bindings: vec![],
        parameters_json: "{}".into(),
        invariants: vec![ResolvedInvariantBinding {
            invariant_version_id: "invariant:live-model-review".into(),
            content_digest: digest('b'),
            predicate_kind: "bounded_quality_review/v1".into(),
            input_schema: "fixture.subject/v1".into(),
            result_schema: STOCHASTIC_TRIAL_RESULT_CONTRACT.into(),
            evidence_types: vec![],
            provenance_evidence_object_ids: vec![],
            waiver_version_ids: vec![],
        }],
        evidence_object_ids: vec![],
        classification: NODE_REQUIRED.into(),
    };
    let manifest = ResolvedEvaluationManifest {
        contract_version: MANIFEST_CONTRACT.into(),
        resolver_version: RESOLVER_VERSION.into(),
        manifest_id: "manifest:live-stochastic".into(),
        manifest_digest: digest('c'),
        namespace: "ollama-e2e".into(),
        plan_version_id: "plan:live-stochastic".into(),
        plan_digest: digest('d'),
        subject_profile: "fixture.subject/v1".into(),
        subject_identity: "subject:live-stochastic".into(),
        subject_content_digest: digest('e'),
        invariant_set_id: "set:live-stochastic".into(),
        invariant_set_digest: digest('f'),
        invariant_profile_digest: digest('1'),
        evaluation_time_ms: 1,
        resolved_by: "ollama-e2e".into(),
        requirements: vec![],
        nodes: vec![node],
        evidence: vec![],
        waivers: vec![],
        created_at_ms: 1,
    };
    let input = build_evaluator_input(&manifest, &manifest.nodes[0], vec![], &BTreeMap::new())
        .expect("build stochastic input");
    let execution = execute_stochastic_node(
        &registry,
        &manifest,
        &manifest.nodes[0],
        input,
        &EvaluatorResourceLimits {
            timeout_ms: 60_000,
            max_input_bytes: 64 * 1024,
            max_output_bytes: 16 * 1024,
            max_evidence_items: 8,
        },
        Duration::from_secs(120),
        Arc::new(AtomicBool::new(false)),
    )
    .expect("execute live stochastic trials");

    assert_eq!(execution.receipt.status, STATUS_PASS);
    let evidence = execution
        .receipt
        .stochastic_evidence
        .expect("statistical evidence");
    assert_eq!(evidence.trials.len(), 2);
    assert_eq!(evidence.completed_trial_count, 2);
    assert!(!evidence.aggregate_digest.is_empty());
}

#[tokio::test]
#[ignore = "requires a local Ollama server and downloaded model"]
async fn grpc_chat_round_trip_with_local_ollama() {
    let addr = free_local_addr();
    let config = Config {
        grpc_port: addr.port(),
        sekai_bind: None,
        ops_port: None,
        ops_bind: "127.0.0.1".into(),
        sekai_socket: None,
        db_path: ":memory:".into(),
        anthropic_api_key: None,
        openai_api_key: None,
        ollama_url: std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".into()),
        native_llm_url: None,
        auth_token: None,
        sample_rate: 0.05,
        sample_risk_threshold: 0.7,
        scoring_enabled: false,
        scoring_interval_secs: 60,
        scoring_model: "claude-opus-4-8".into(),
        scoring_batch_size: 16,
        default_data_class: "unclassified".into(),
        safe_egress_providers: vec![],
        gateway_provided_providers: vec![],
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
    };
    let model = e2e_model();
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").expect("create db"),
    )));

    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(ChiseiServiceServer::new(ChiseiServiceImpl::new(db, config)))
            .serve(addr)
            .await
            .expect("serve test gRPC server");
    });

    let mut client = connect_with_retry(addr).await;

    let policy = client
        .resolve_policy(ResolvePolicyRequest {
            namespace: "default".into(),
            preferred_runtime: String::new(),
            preferred_model: model.clone(),
            subject: String::new(),
            project: "default".into(),
            agent: "ollama-e2e".into(),
            key_id: String::new(),
            task_class: String::new(),
            user_id: String::new(),
            expected_calls: 1,
            budget_route_bias: String::new(),
            route_override: String::new(),
            capability_requirements_json: Vec::new(),
        })
        .await
        .expect("resolve policy")
        .into_inner();
    assert!(policy.resolution.unwrap().model.starts_with("ollama/"));

    let plan = client
        .plan_execution(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "ollama-e2e".into(),
                namespace: "default".into(),
                spec: "Say hello in one short sentence.".into(),
                preferred_model: model,
                preferred_runtime: String::new(),
                task_type: String::new(),
                priority: 0,
                user_id: "ollama-e2e".into(),
                estimated_tokens: 0,
                messages: Vec::new(),
                tools: Vec::new(),
                system: "Reply with a short plain-text answer.".into(),
                max_tokens: 32,
                task_class: String::new(),
                ..Default::default()
            }),
        })
        .await
        .expect("plan execution")
        .into_inner();
    let response = client
        .execute_plan(ExecutePlanRequest { plan: plan.plan })
        .await
        .expect("execute plan")
        .into_inner();
    let response = response
        .response
        .expect("plan execution response should include content");

    assert!(
        !response.content.trim().is_empty(),
        "expected non-empty chat response"
    );
    assert!(
        response.input_tokens > 0,
        "expected prompt token accounting"
    );
    assert!(
        response.output_tokens > 0,
        "expected completion token accounting"
    );

    server.abort();
}

#[tokio::test]
#[ignore = "requires local Ollama; frontier template/polish steps also require ANTHROPIC_API_KEY"]
async fn delegation_chain_keeps_private_context_local() {
    let addr = free_local_addr();
    let config = Config {
        grpc_port: addr.port(),
        sekai_bind: None,
        ops_port: None,
        ops_bind: "127.0.0.1".into(),
        sekai_socket: None,
        db_path: ":memory:".into(),
        anthropic_api_key: std::env::var("ANTHROPIC_API_KEY").ok(),
        openai_api_key: None,
        ollama_url: std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".into()),
        native_llm_url: None,
        auth_token: None,
        sample_rate: 0.05,
        sample_risk_threshold: 0.7,
        scoring_enabled: false,
        scoring_interval_secs: 60,
        scoring_model: "claude-opus-4-8".into(),
        scoring_batch_size: 16,
        default_data_class: "unclassified".into(),
        safe_egress_providers: vec![],
        gateway_provided_providers: vec![],
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
    };
    let local_model = e2e_model();
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").expect("create db"),
    )));
    db.create_object(&Object {
        id: "policy-alpha".into(),
        kind: "policy".into(),
        name: "alpha".into(),
        namespace: String::new(),
        external_id: "policy:alpha".into(),
        properties: std::collections::HashMap::from([
            ("default_runtime".into(), "kiro".into()),
            ("default_model".into(), local_model.clone()),
            ("data_class".into(), "sensitive".into()),
        ]),
        created: 0,
        updated: 0,
    })
    .expect("seed policy");

    let server_db = db.clone();
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(ChiseiServiceServer::new(ChiseiServiceImpl::new(
                server_db, config,
            )))
            .serve(addr)
            .await
            .expect("serve test gRPC server");
    });

    let mut client = connect_with_retry(addr).await;
    let local_plan = client
        .plan_execution(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "delegation-local".into(),
                namespace: "alpha".into(),
                spec: "Use private local context to outline the memo.".into(),
                preferred_model: local_model,
                preferred_runtime: String::new(),
                task_type: "analysis".into(),
                priority: 0,
                user_id: "delegation-e2e".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: "Keep private context local.".into(),
                max_tokens: 128,
                task_class: String::new(),
                ..Default::default()
            }),
        })
        .await
        .expect("local private plan")
        .into_inner()
        .plan
        .expect("local plan");
    assert!(local_plan.resolved_model.starts_with("ollama/"));
    let local_response = client
        .execute_plan(ExecutePlanRequest {
            plan: Some(local_plan),
        })
        .await
        .expect("local private execute")
        .into_inner()
        .response
        .expect("local response");
    assert!(!local_response.content.trim().is_empty());

    if std::env::var("ANTHROPIC_API_KEY").is_err() {
        server.abort();
        return;
    }

    let template_plan = client
        .plan_execution(PlanExecutionRequest {
            input: Some(ExecutionInput {
                request_id: "delegation-template".into(),
                namespace: "alpha".into(),
                spec: "Create a generic investment memo checklist with no sectors, tickers, timing, positions, or proprietary signals.".into(),
                preferred_model: "claude-sonnet-4-20250514".into(),
                preferred_runtime: String::new(),
                task_type: "template".into(),
                priority: 0,
                user_id: "delegation-e2e".into(),
                estimated_tokens: 0,
                messages: vec![],
                tools: vec![],
                system: "Return an abstract checklist only.".into(),
                max_tokens: 256,
                task_class: "template_only".into(),
                ..Default::default()
            }),
        })
        .await
        .expect("frontier template plan")
        .into_inner()
        .plan
        .expect("template plan");
    assert_eq!(template_plan.task_class, "template_only");
    assert!(template_plan.executable);

    server.abort();
}
