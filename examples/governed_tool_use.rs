//! Governed tool-use bridge demo (Plan 9, Phase D).
//!
//! Shows how a model tool-call becomes a *governed* Sekai action: the client
//! maps the tool-call to an `ExecuteAction` request (the single enforcement
//! point), and the server policy-checks, dry-runs, holds-for-approval,
//! budget-limits, and audits it before any graph mutation.
//!
//! Run the server in one terminal:
//!
//! ```bash
//! SEKAI_INSECURE=1 cargo run
//! ```
//!
//! Then this demo in another:
//!
//! ```bash
//! cargo run --example governed_tool_use
//! ```
//!
//! Honors `GRPC_PORT` (default 50051), `SEKAI_SOCKET` for UDS, and
//! `SEKAI_AUTH_TOKEN`. Uses `SEKAI_PRINCIPAL` for identity (default:
//! `tool-demo`); in `SEKAI_INSECURE=1` mode the `local` principal is an admin.

use std::collections::HashMap;

use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::{Request, Status};

use sekai_chisei::grpc::client::{GatewayClient, connect_sekai};
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    ActionPolicy, ActionRequest, CreateObjectRequest, ExecuteActionRequest,
    ListPendingApprovalsRequest, Object, SetActionPolicyRequest,
};
use sekai_chisei::sekai::tool_bridge::ToolCall;

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

type Sekai = SekaiServiceClient<InterceptedService<GatewayClient, DemoAuth>>;

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

/// Execute a model tool-call as a governed action via ExecuteAction.
async fn run_tool_call(
    sekai: &mut Sekai,
    call: &ToolCall,
    dry_run: bool,
) -> Result<sekai_chisei::grpc::pb::sekai::ActionResult, Status> {
    let params = call.to_action_params().map_err(Status::invalid_argument)?;
    let resp = sekai
        .execute_action(ExecuteActionRequest {
            request: Some(ActionRequest {
                action: call.action_name().to_string(),
                params,
                actor: String::new(),
            }),
            dry_run,
        })
        .await?;
    Ok(resp.into_inner().result.unwrap_or_default())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let principal = std::env::var("SEKAI_PRINCIPAL").unwrap_or_else(|_| "tool-demo".into());
    let endpoint = std::env::var("SEKAI_SOCKET").unwrap_or_else(|_| {
        let port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50051".to_string());
        format!("http://127.0.0.1:{port}")
    });
    let auth = DemoAuth {
        token: std::env::var("SEKAI_AUTH_TOKEN").ok(),
        principal: principal.clone(),
    };

    println!("\x1b[1mgoverned tool-use demo\x1b[0m");
    println!("  connecting to {endpoint} as {principal}");

    let channel = connect_sekai(&endpoint).await?;
    let mut sekai: Sekai = SekaiServiceClient::new(InterceptedService::new(channel, auth));

    let run = &uuid::Uuid::new_v4().to_string()[..8];
    let obj_id = format!("tool-target-{run}");

    section("seed a target object");
    match sekai
        .create_object(CreateObjectRequest {
            object: Some(Object {
                id: obj_id.clone(),
                kind: "namespace".into(),
                name: obj_id.clone(),
                namespace: String::new(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 0,
                updated: 0,
            }),
        })
        .await
    {
        Ok(_) => ok(format!("created {obj_id}")),
        Err(e) => warn("create_object", &e),
    }

    section("set an action policy: allow writes, require approval for destructive");
    let policy = ActionPolicy {
        scope: format!("agent:{principal}"),
        default_decision: "allow".into(),
        action_overrides: HashMap::new(),
        risk_overrides: HashMap::from([(
            "destructive".to_string(),
            "require_approval".to_string(),
        )]),
        max_mutations_per_work_unit: 0,
        max_deletes_per_work_unit: 0,
    };
    match sekai
        .set_action_policy(SetActionPolicyRequest {
            policy: Some(policy),
        })
        .await
    {
        Ok(_) => ok(format!("policy set for agent:{principal}")),
        Err(e) => warn("set_action_policy", &e),
    }

    section("model tool-call → governed write action (dry run first)");
    let write_call = ToolCall::from_json_arguments(
        "set_property",
        &format!(r#"{{"id":"{obj_id}","key":"status","value":"reviewed"}}"#),
    )?;
    match run_tool_call(&mut sekai, &write_call, true).await {
        Ok(result) => ok(format!(
            "dry-run decision={} planned_ops={:?}",
            result.decision, result.planned_ops
        )),
        Err(e) => warn("dry-run set_property", &e),
    }
    match run_tool_call(&mut sekai, &write_call, false).await {
        Ok(result) => ok(format!(
            "executed: {} (decision={})",
            result.message, result.decision
        )),
        Err(e) => warn("set_property", &e),
    }

    section("model tool-call → destructive action (held for approval)");
    // Create a link to delete, then try to delete it via a tool-call.
    let link_call = ToolCall::from_json_arguments(
        "create_link",
        &format!(r#"{{"from_id":"{obj_id}","to_id":"{obj_id}","relation":"self"}}"#),
    )?;
    let _ = run_tool_call(&mut sekai, &link_call, false).await;
    let delete_call =
        ToolCall::from_json_arguments("delete_link", &format!(r#"{{"id":"{obj_id}->{obj_id}"}}"#))?;
    match run_tool_call(&mut sekai, &delete_call, false).await {
        Ok(result) if !result.approval_id.is_empty() => {
            ok(format!("held for approval: {}", result.approval_id))
        }
        Ok(result) => ok(format!("decision={}", result.decision)),
        Err(e) => warn("delete_link", &e),
    }

    section("list pending approvals");
    match sekai
        .list_pending_approvals(ListPendingApprovalsRequest {
            status: String::new(),
        })
        .await
    {
        Ok(resp) => {
            for approval in resp.into_inner().approvals {
                ok(format!(
                    "{}: {} on {} (risk={}) — {}",
                    approval.id,
                    approval.action,
                    approval.target_id,
                    approval.risk_class,
                    approval.status
                ));
            }
        }
        Err(e) => warn("list_pending_approvals", &e),
    }

    println!("\n\x1b[1;32mgoverned tool-use demo complete.\x1b[0m");
    Ok(())
}
