//! Host-neutral reference consumer of the public capability contracts.
//!
//! The host discovers its action at runtime, invokes the canonical Sekai RPC,
//! handles an optional approval, and retrieves the operation receipt. It owns
//! the tool loop and approval presentation; no Chisei action names are compiled
//! into the host.

use std::collections::HashMap;

use sekai_chisei::capability_projection::{ProjectedCapability, ProjectionContext};
use sekai_chisei::grpc::client::{GatewayClient, connect_sekai};
use sekai_chisei::grpc::pb::chisei::GetOperationReceiptRequest;
use sekai_chisei::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::{
    ActionRequest, ApproveActionRequest, DenyActionRequest, DiscoverCapabilitiesRequest,
    ExecuteActionRequest,
};
use sekai_chisei::operation_report::OperationReport;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::{Request, Status};

#[derive(Clone)]
struct HostAuth {
    token: Option<String>,
    principal: String,
}

impl Interceptor for HostAuth {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(token) = &self.token {
            request.metadata_mut().insert(
                "authorization",
                format!("Bearer {token}")
                    .parse()
                    .map_err(|_| Status::internal("invalid authorization metadata"))?,
            );
        }
        request.metadata_mut().insert(
            "x-principal",
            MetadataValue::try_from(self.principal.as_str())
                .map_err(|_| Status::internal("invalid principal metadata"))?,
        );
        Ok(request)
    }
}

type SekaiClient = SekaiServiceClient<InterceptedService<GatewayClient, HostAuth>>;
type ChiseiClient = ChiseiServiceClient<InterceptedService<GatewayClient, HostAuth>>;

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    std::env::var(name).map_err(|_| format!("{name} is required").into())
}

fn action_params(input: &serde_json::Value) -> Result<HashMap<String, String>, String> {
    input
        .as_object()
        .ok_or_else(|| "CAPABILITY_INPUT must be a JSON object".to_string())?
        .iter()
        .map(|(key, value)| {
            let value = match value {
                serde_json::Value::String(value) => value.clone(),
                serde_json::Value::Bool(value) => value.to_string(),
                serde_json::Value::Number(value) => value.to_string(),
                _ => serde_json::to_string(value).map_err(|error| error.to_string())?,
            };
            Ok((key.clone(), value))
        })
        .collect()
}

async fn retrieve_report(
    chisei: &mut ChiseiClient,
    operation_id: &str,
) -> Result<OperationReport, Box<dyn std::error::Error + Send + Sync>> {
    let receipt_json = chisei
        .get_operation_receipt(GetOperationReceiptRequest {
            operation_id: operation_id.into(),
            request_id: String::new(),
            caller_scope: String::new(),
            attempt: 0,
        })
        .await?
        .into_inner()
        .receipt_json;
    Ok(OperationReport::from_authorized_receipt(
        &serde_json::from_str(&receipt_json)?,
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let namespace = required_env("CAPABILITY_NAMESPACE")?;
    let capability_name = required_env("CAPABILITY_NAME")?;
    let input: serde_json::Value = serde_json::from_str(&required_env("CAPABILITY_INPUT")?)?;
    let principal =
        std::env::var("SEKAI_PRINCIPAL").unwrap_or_else(|_| "capability:reference".into());
    let operation_id = std::env::var("CAPABILITY_OPERATION_ID")
        .unwrap_or_else(|_| format!("capability-{}", uuid::Uuid::new_v4().simple()));
    let endpoint = std::env::var("SEKAI_SOCKET").unwrap_or_else(|_| {
        let port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50051".into());
        format!("http://127.0.0.1:{port}")
    });
    let auth = HostAuth {
        token: std::env::var("SEKAI_AUTH_TOKEN").ok(),
        principal: principal.clone(),
    };
    let channel = connect_sekai(&endpoint).await?;
    let mut sekai = SekaiClient::new(InterceptedService::new(channel.clone(), auth.clone()));
    let mut chisei = ChiseiClient::new(InterceptedService::new(channel, auth));

    let catalog = sekai
        .discover_capabilities(DiscoverCapabilitiesRequest {
            namespace: namespace.clone(),
            contract_version: String::new(),
            catalog_version: String::new(),
            page_size: 200,
            page_token: String::new(),
        })
        .await?
        .into_inner();
    let entry = catalog
        .capabilities
        .iter()
        .find(|entry| entry.name == capability_name)
        .ok_or_else(|| format!("capability {capability_name} is not visible"))?;
    if entry.kind != "action" || entry.input_type != "sekai.ExecuteActionRequest" {
        return Err(format!(
            "reference host supports the catalog's governed action contract, not {}",
            entry.input_type
        )
        .into());
    }
    let projection = ProjectedCapability::new(
        entry,
        ProjectionContext {
            namespace,
            principal,
            contract_version: catalog.contract_version,
            catalog_version: catalog.catalog_version,
        },
    )?;
    let action = projection
        .action_schema
        .as_ref()
        .and_then(|schema| schema.get("x-sekai-action"))
        .and_then(serde_json::Value::as_str)
        .ok_or("discovered action schema has no canonical action name")?;
    let invocation = projection.invocation(&operation_id, input.clone())?;
    let request = invocation.bind(ExecuteActionRequest {
        request: Some(ActionRequest {
            action: action.into(),
            params: action_params(&input)?,
            actor: String::new(),
        }),
        dry_run: false,
    })?;

    let mut approval_id = None;
    match sekai.execute_action(request).await {
        Ok(response) => {
            let result = response.into_inner().result.unwrap_or_default();
            if !result.approval_id.is_empty() {
                approval_id = Some(result.approval_id);
            }
        }
        Err(status) => eprintln!("invocation: {} ({})", status.message(), status.code()),
    }
    if let Some(approval_id) = approval_id {
        match std::env::var("CAPABILITY_APPROVAL").as_deref() {
            Ok("approve") => {
                sekai
                    .approve_action(ApproveActionRequest { approval_id })
                    .await?;
            }
            Ok("deny") => {
                sekai
                    .deny_action(DenyActionRequest {
                        approval_id,
                        reason: "denied by reference host operator".into(),
                    })
                    .await?;
            }
            _ => eprintln!("approval pending; set CAPABILITY_APPROVAL=approve or deny"),
        }
    }

    let report = retrieve_report(&mut chisei, &operation_id).await?;
    print!("{}", sekai_chisei::report_cli::render_report(&report));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_params_preserve_scalar_and_structured_values() {
        let params = action_params(&serde_json::json!({
            "id": "object-1",
            "force": true,
            "labels": ["a", "b"]
        }))
        .unwrap();
        assert_eq!(params["id"], "object-1");
        assert_eq!(params["force"], "true");
        assert_eq!(params["labels"], r#"["a","b"]"#);
    }
}
