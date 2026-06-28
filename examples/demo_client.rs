//! End-to-end demo client for the `sekai-chisei` gRPC control plane.
//!
//! It walks through a realistic "AI-assisted delivery" slice against a running
//! server: it builds a small typed-object graph in `sekai`, then drives the
//! `chisei` budget and decision pipeline. Every call is tolerant — a failing
//! step is reported and the demo keeps going, so it doubles as a smoke test.
//!
//! Run the server in one terminal:
//!
//! ```bash
//! SEKAI_INSECURE=1 cargo run
//! ```
//!
//! Then the demo in another:
//!
//! ```bash
//! cargo run --example demo_client
//! ```
//!
//! Honors the same env vars as the server: `GRPC_PORT` (default 50051) and
//! `SEKAI_AUTH_TOKEN` (attaches `authorization: Bearer <token>` when set).

use std::collections::HashMap;

use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Status};

use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::chisei::{
    ChatMessage, CheckBudgetRequest, ExecutePlanRequest, ExecutionInput, PipelineRequest,
    PlanExecutionRequest, RecordUsageRequest, ResolvePolicyRequest, RunPipelineRequest,
    SetBudgetLimitRequest,
};
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    CreateLinkRequest, CreateObjectRequest, GetLinkedObjectsRequest, GraphQuery, Link, ListFilter,
    ListObjectsRequest, Object, TraverseRequest,
};

/// Attaches auth + caller identity metadata to every request.
#[derive(Clone)]
struct DemoAuth {
    token: Option<String>,
    principal: String,
}

impl Interceptor for DemoAuth {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if let Some(token) = &self.token {
            let value: MetadataValue<_> = format!("Bearer {token}")
                .parse()
                .map_err(|_| Status::internal("invalid auth token"))?;
            req.metadata_mut().insert("authorization", value);
        }
        let principal: MetadataValue<_> = self
            .principal
            .parse()
            .map_err(|_| Status::internal("invalid principal"))?;
        req.metadata_mut().insert("x-principal", principal);
        Ok(req)
    }
}

type Sekai = SekaiServiceClient<InterceptedService<Channel, DemoAuth>>;
type Chisei = ChiseiServiceClient<InterceptedService<Channel, DemoAuth>>;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn props(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn section(title: &str) {
    println!("\n\x1b[1;36m== {title} ==\x1b[0m");
}

fn ok(msg: impl AsRef<str>) {
    println!("  \x1b[32m✓\x1b[0m {}", msg.as_ref());
}

fn warn(label: &str, err: &Status) {
    println!(
        "  \x1b[33m✗\x1b[0m {label}: {} ({})",
        err.message(),
        err.code()
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50051".to_string());
    let endpoint = format!("http://127.0.0.1:{port}");
    let auth = DemoAuth {
        token: std::env::var("SEKAI_AUTH_TOKEN").ok(),
        principal: "demo-client".to_string(),
    };

    println!("\x1b[1msekai-chisei demo client\x1b[0m");
    println!("  connecting to {endpoint}");
    println!(
        "  auth: {}",
        if auth.token.is_some() {
            "bearer token"
        } else {
            "insecure (no token)"
        }
    );

    let channel = Channel::from_shared(endpoint.clone())?.connect().await?;
    let mut sekai: Sekai = SekaiServiceClient::with_interceptor(channel.clone(), auth.clone());
    let mut chisei: Chisei = ChiseiServiceClient::with_interceptor(channel, auth);

    // Distinct ids per run so repeated invocations don't collide.
    let run = &uuid::Uuid::new_v4().to_string()[..8];
    let namespace_id = format!("ctx-{run}");
    let service_id = format!("svc-{run}");

    sekai_demo(&mut sekai, &namespace_id, &service_id).await;
    chisei_demo(&mut chisei, &namespace_id).await;
    execute_demo(&mut chisei, &namespace_id).await;

    println!("\n\x1b[1;32mdemo complete.\x1b[0m");
    Ok(())
}

/// Builds a tiny typed-object graph and reads it back.
async fn sekai_demo(sekai: &mut Sekai, namespace_id: &str, service_id: &str) {
    section("sekai · typed object graph");

    let context_obj = Object {
        id: namespace_id.to_string(),
        kind: "component".to_string(),
        name: "sekai-chisei".to_string(),
        namespace: "demo".to_string(),
        external_id: format!("ctx:{namespace_id}"),
        properties: props(&[("language", "rust"), ("visibility", "private")]),
        created: now_ms(),
        updated: now_ms(),
    };
    match sekai
        .create_object(CreateObjectRequest {
            object: Some(context_obj),
        })
        .await
    {
        Ok(_) => ok(format!("created context object  {namespace_id}")),
        Err(e) => warn("create context object", &e),
    }

    let service = Object {
        id: service_id.to_string(),
        kind: "service".to_string(),
        name: "billing-api".to_string(),
        namespace: "demo".to_string(),
        external_id: String::new(),
        properties: props(&[("tier", "prod"), ("runtime", "tokio")]),
        created: now_ms(),
        updated: now_ms(),
    };
    match sekai
        .create_object(CreateObjectRequest {
            object: Some(service),
        })
        .await
    {
        Ok(_) => ok(format!("created service object {service_id}")),
        Err(e) => warn("create service", &e),
    }

    // context --deploys--> service
    match sekai
        .create_link(CreateLinkRequest {
            link: Some(Link {
                id: format!("link-{namespace_id}-{service_id}"),
                from_id: namespace_id.to_string(),
                to_id: service_id.to_string(),
                relation: "deploys".to_string(),
                created: now_ms(),
            }),
        })
        .await
    {
        Ok(_) => ok("linked  context --deploys--> service"),
        Err(e) => warn("create link", &e),
    }

    // Read the relationship back out.
    match sekai
        .get_linked_objects(GetLinkedObjectsRequest {
            object_id: namespace_id.to_string(),
            relation: "deploys".to_string(),
            direction: "out".to_string(),
        })
        .await
    {
        Ok(resp) => {
            let objs = resp.into_inner().objects;
            ok(format!("context deploys {} object(s):", objs.len()));
            for o in objs {
                println!("      - {} ({}) [{}]", o.name, o.kind, o.id);
            }
        }
        Err(e) => warn("get linked objects", &e),
    }

    // Traverse the graph outward from the context object.
    match sekai
        .traverse(TraverseRequest {
            query: Some(GraphQuery {
                start_id: namespace_id.to_string(),
                direction: "out".to_string(),
                max_depth: 3,
                ..Default::default()
            }),
        })
        .await
    {
        Ok(resp) => {
            if let Some(result) = resp.into_inner().result {
                ok(format!(
                    "traverse reached {} object(s), {} link(s)",
                    result.objects.len(),
                    result.links.len()
                ));
            }
        }
        Err(e) => warn("traverse", &e),
    }

    // List by kind.
    match sekai
        .list_objects(ListObjectsRequest {
            filter: Some(ListFilter {
                kind: "service".to_string(),
                ..Default::default()
            }),
        })
        .await
    {
        Ok(resp) => ok(format!(
            "list kind=service returned {} object(s)",
            resp.into_inner().objects.len()
        )),
        Err(e) => warn("list objects", &e),
    }
}

/// Drives the chisei budget + decision pipeline.
async fn chisei_demo(chisei: &mut Chisei, namespace_id: &str) {
    section("chisei · budget & decision pipeline");

    let user = "demo-user";

    match chisei
        .set_budget_limit(SetBudgetLimitRequest {
            user_id: user.to_string(),
            max_tokens: 100_000,
            period_type: "daily".to_string(),
        })
        .await
    {
        Ok(_) => ok("set budget limit: 100000 tokens/day for demo-user"),
        Err(e) => warn("set budget limit", &e),
    }

    match chisei
        .check_budget(CheckBudgetRequest {
            user_id: user.to_string(),
            estimated_tokens: 5_000,
        })
        .await
    {
        Ok(resp) => {
            let r = resp.into_inner();
            let used = r.usage.as_ref().map(|u| u.tokens_used).unwrap_or(0);
            ok(format!(
                "check budget (est 5000): allowed={} used={used}",
                r.allowed
            ));
        }
        Err(e) => warn("check budget", &e),
    }

    match chisei
        .record_usage(RecordUsageRequest {
            user_id: user.to_string(),
            tokens_used: 5_000,
        })
        .await
    {
        Ok(resp) => {
            let used = resp.into_inner().usage.map(|u| u.tokens_used).unwrap_or(0);
            ok(format!("recorded usage: now {used} tokens used"));
        }
        Err(e) => warn("record usage", &e),
    }

    // ResolvePolicy may reach for a live model list; tolerate failure offline.
    match chisei
        .resolve_policy(ResolvePolicyRequest {
            namespace: "demo".to_string(),
            preferred_runtime: String::new(),
            preferred_model: String::new(),
        })
        .await
    {
        Ok(resp) => {
            if let Some(p) = resp.into_inner().resolution {
                ok(format!(
                    "resolved policy: runtime={} model={}",
                    p.runtime, p.model
                ));
            }
        }
        Err(e) => warn("resolve policy (needs a configured model)", &e),
    }

    // The centerpiece: run the decision pipeline over a task spec.
    section("chisei · pipeline decisions");
    let request_id = format!("req-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    match chisei
        .run_pipeline(RunPipelineRequest {
            request: Some(PipelineRequest {
                request_id: request_id.clone(),
                namespace: "demo".to_string(),
                spec: "Add rate limiting to the billing-api login endpoint".to_string(),
                model: String::new(),
                runtime: String::new(),
                task_type: "feature".to_string(),
                priority: 5,
            }),
        })
        .await
    {
        Ok(resp) => {
            if let Some(result) = resp.into_inner().result {
                ok(format!(
                    "pipeline {} produced {} decision step(s):",
                    request_id,
                    result.steps.len()
                ));
                for s in &result.steps {
                    println!(
                        "      [{:<14}] {:<10} (conf {:.2})  {}",
                        s.step, s.action, s.confidence, s.reasoning
                    );
                    if !s.suggestion.is_empty() {
                        println!("                       ↳ suggestion: {}", s.suggestion);
                    }
                }
                if !result.prepared_spec.is_empty() {
                    println!("      prepared spec: {}", result.prepared_spec);
                }
            }
        }
        Err(e) => warn("run pipeline", &e),
    }
}

/// Plans an execution and runs it through a local Ollama model.
///
/// `PlanExecution` resolves policy/budget and caches a server-side plan;
/// `ExecutePlan` then actually calls the model. The model defaults to
/// `ollama/llama3.2:latest` and can be overridden with `DEMO_MODEL`.
async fn execute_demo(chisei: &mut Chisei, namespace_id: &str) {
    section("chisei · execute (live LLM call)");

    let model =
        std::env::var("DEMO_MODEL").unwrap_or_else(|_| "ollama/llama3.2:latest".to_string());
    println!("  model: {model}");

    let request_id = format!("exec-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let input = ExecutionInput {
        request_id: request_id.clone(),
        namespace: namespace_id.to_string(),
        spec: "Explain API rate limiting in one or two sentences.".to_string(),
        preferred_model: model.clone(),
        preferred_runtime: String::new(),
        task_type: "question".to_string(),
        priority: 5,
        user_id: "demo-user".to_string(),
        estimated_tokens: 0,
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: "Explain API rate limiting in one or two sentences.".to_string(),
            tool_call_id: String::new(),
            tool_calls: vec![],
        }],
        tools: vec![],
        system: "You are a terse engineering assistant. Answer in one or two sentences."
            .to_string(),
        max_tokens: 256,
    };

    // Step 1: plan the execution (budget + policy + enrichment, no model call yet).
    let plan = match chisei
        .plan_execution(PlanExecutionRequest { input: Some(input) })
        .await
    {
        Ok(resp) => match resp.into_inner().plan {
            Some(p) => {
                ok(format!(
                    "planned: resolved_model={} executable={} est_tokens={}",
                    p.resolved_model,
                    p.executable,
                    p.input.as_ref().map(|i| i.estimated_tokens).unwrap_or(0)
                ));
                if let Some(b) = &p.budget
                    && !b.allowed
                {
                    println!("      budget blocked: {}", b.reason);
                }
                for w in &p.warnings {
                    println!("      warning: {w}");
                }
                p
            }
            None => {
                warn("plan execution", &Status::internal("empty plan"));
                return;
            }
        },
        Err(e) => {
            warn("plan execution", &e);
            return;
        }
    };

    if !plan.executable {
        println!("  \x1b[33m✗\x1b[0m plan not executable — skipping live call");
        return;
    }

    // Step 2: execute the plan — this is the actual call to Ollama.
    println!("  calling model (this may take a few seconds)...");
    match chisei
        .execute_plan(ExecutePlanRequest { plan: Some(plan) })
        .await
    {
        Ok(resp) => {
            let r = resp.into_inner();
            if let Some(chat) = r.response {
                ok(format!(
                    "response from {} ({} in / {} out tokens, stop: {})",
                    chat.provider, chat.input_tokens, chat.output_tokens, chat.stop_reason
                ));
                println!("\x1b[2m      ┌─────────────────────────────────────────────\x1b[0m");
                for line in chat.content.trim().lines() {
                    println!("      │ {line}");
                }
                println!("\x1b[2m      └─────────────────────────────────────────────\x1b[0m");
            }
        }
        Err(e) => warn("execute plan", &e),
    }
}
