use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sekai_chisei::config::Config;
use sekai_chisei::db::sekai::SekaiDb;
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

#[tokio::test]
#[ignore = "requires a local Ollama server and downloaded model"]
async fn grpc_chat_round_trip_with_local_ollama() {
    let addr = free_local_addr();
    let config = Config {
        grpc_port: addr.port(),
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
    };
    let model = e2e_model();
    let db = Arc::new(SekaiDb::new(":memory:").expect("create db"));

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
            repo: "".into(),
            preferred_runtime: String::new(),
            preferred_model: model.clone(),
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
                repo: String::new(),
                branch: String::new(),
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
