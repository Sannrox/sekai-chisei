use serde_json::{Value, json};

use crate::capability_projection::{ProjectedCapability, ProjectedError, ProjectionContext};
use crate::grpc::pb::sekai::CapabilityEntry;
use crate::sekai::capability::CONTRACT_VERSION;

use super::surface::{AdapterError, NativeRpc, NativeSurface};

pub const PROTOCOL_VERSION: &str = "2024-11-05";
pub const GET_OBJECT_TOOL: &str = "sekai.objects.get";
pub const EVALUATE_SET_TOOL: &str = "sekai.objects.evaluate_set";
pub const DESCRIBE_ACTION_TOOL: &str = "sekai.actions.describe";
pub const PREVIEW_ACTION_TOOL: &str = "sekai.actions.preview";
pub const SUBMIT_ACTION_TOOL: &str = "sekai.actions.submit";
pub const GET_RECEIPT_TOOL: &str = "chisei.receipt.read";
/// Link read and create (#1093). Both back onto stable RPCs.
pub const GET_LINKS_TOOL: &str = "sekai.links.get";
pub const CREATE_LINK_TOOL: &str = "sekai.links.create";
/// Evaluation resolve and execute (#1093), listed since both RPCs are stable
/// (#1090). Compare is a CLI projection with no wire RPC, so it has no tool.
pub const RESOLVE_EVALUATION_TOOL: &str = "chisei.evaluation.resolve";
pub const EXECUTE_EVALUATION_TOOL: &str = "chisei.evaluation.execute";

const RESERVED_ARGUMENT_KEYS: &[&str] = &[
    "authorization",
    "x-principal",
    "x-sekai-namespace",
    "x-sekai-capability",
    "x-sekai-operation-id",
    "x-chisei-work-unit",
    "x-sekai-catalog-version",
    "x-chisei-request-id",
    "principal",
];

pub fn well_known_tools() -> [&'static str; 10] {
    [
        GET_OBJECT_TOOL,
        EVALUATE_SET_TOOL,
        DESCRIBE_ACTION_TOOL,
        PREVIEW_ACTION_TOOL,
        SUBMIT_ACTION_TOOL,
        GET_RECEIPT_TOOL,
        GET_LINKS_TOOL,
        CREATE_LINK_TOOL,
        RESOLVE_EVALUATION_TOOL,
        EXECUTE_EVALUATION_TOOL,
    ]
}

pub fn rpc_for_tool(name: &str) -> Option<NativeRpc> {
    match name {
        GET_OBJECT_TOOL => Some(NativeRpc::GetObject),
        EVALUATE_SET_TOOL => Some(NativeRpc::EvaluateObjectSet),
        DESCRIBE_ACTION_TOOL => Some(NativeRpc::DescribeObjectAction),
        PREVIEW_ACTION_TOOL => Some(NativeRpc::PreviewObjectAction),
        SUBMIT_ACTION_TOOL => Some(NativeRpc::SubmitActionInstance),
        GET_RECEIPT_TOOL => Some(NativeRpc::GetOperationReceipt),
        GET_LINKS_TOOL => Some(NativeRpc::GetLinks),
        CREATE_LINK_TOOL => Some(NativeRpc::CreateLink),
        RESOLVE_EVALUATION_TOOL => Some(NativeRpc::ResolveEvaluationPlan),
        EXECUTE_EVALUATION_TOOL => Some(NativeRpc::ExecuteEvaluationManifest),
        _ => None,
    }
}

pub async fn handle_message<S>(surface: &S, message: Value) -> Option<Value>
where
    S: NativeSurface,
{
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(rpc_error(
            message.get("id").cloned(),
            -32600,
            "invalid JSON-RPC",
        ));
    }
    let id = message.get("id").cloned()?;
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => initialize(params),
        "ping" => Ok(json!({})),
        "tools/list" => list_tools(surface).await,
        "tools/call" => call_tool(surface, params).await,
        _ => Err(json!({"code":-32601,"message":"method not found"})),
    };
    Some(match result {
        Ok(value) => json!({"jsonrpc":"2.0","id":id,"result":value}),
        Err(error) => {
            if error.get("jsonrpc").is_some() {
                error
            } else {
                json!({"jsonrpc":"2.0","id":id,"error":error})
            }
        }
    })
}

fn initialize(params: Value) -> Result<Value, Value> {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    let protocol_version = if requested == PROTOCOL_VERSION || requested == "2025-03-26" {
        requested
    } else {
        PROTOCOL_VERSION
    };
    Ok(json!({
        "protocolVersion": protocol_version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name":"sekai-mcp","version": env!("CARGO_PKG_VERSION")},
        "instructions": "Projection host over GetObject, EvaluateObjectSet, DescribeObjectAction, PreviewObjectAction, SubmitActionInstance, GetOperationReceipt, GetLinks, CreateLink, ResolveEvaluationPlan, and ExecuteEvaluationManifest. Discovery is not a grant."
    }))
}

async fn list_tools<S>(surface: &S) -> Result<Value, Value>
where
    S: NativeSurface,
{
    let snapshot = surface.refresh_catalog().await.map_err(adapter_error)?;
    let tools = well_known_entries()
        .into_iter()
        .map(|entry| {
            ProjectedCapability::new(&entry, snapshot.context.clone())
                .map(|projected| serde_json::to_value(projected.mcp_tool()).expect("tool"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| json!({"code":-32000,"message": error.to_string()}))?;
    Ok(json!({"tools": tools}))
}

async fn call_tool<S>(surface: &S, params: Value) -> Result<Value, Value>
where
    S: NativeSurface,
{
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| json!({"code":-32602,"message":"tool name is required"}))?;
    let empty_arguments = json!({});
    let arguments = params.get("arguments").unwrap_or(&empty_arguments);
    if contains_reserved_metadata(arguments) {
        return Ok(tool_error(
            "invalid_argument",
            "forged reserved metadata is rejected",
            name,
            "",
        ));
    }
    let Some(rpc) = rpc_for_tool(name) else {
        return Ok(tool_error(
            "unimplemented",
            "unsupported RPC mapping",
            name,
            "",
        ));
    };
    let operation_id = arguments
        .get("operation_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| json!({"code":-32602,"message":"operation_id is required"}))?;
    let snapshot = surface.discover().await.map_err(adapter_error)?;
    let mut input = arguments.get("input").cloned().unwrap_or_else(|| json!({}));
    if !input.is_object() {
        return Ok(tool_error(
            "invalid_argument",
            "input must be an object",
            name,
            operation_id,
        ));
    }
    if contains_reserved_metadata(&input) {
        return Ok(tool_error(
            "invalid_argument",
            "forged reserved metadata is rejected",
            name,
            operation_id,
        ));
    }
    input = bind_session_input(rpc, input, &snapshot.context, operation_id)?;
    let entry = well_known_entries()
        .into_iter()
        .find(|entry| entry.name == name)
        .expect("allowlisted tool has a catalog entry");
    let projected = ProjectedCapability::new(&entry, snapshot.context.clone())
        .map_err(|error| json!({"code":-32000,"message": error.to_string()}))?;
    let invocation = projected
        .invocation(operation_id, input)
        .map_err(|error| json!({"code":-32602,"message": error.to_string()}))?;
    match surface.dispatch(rpc, invocation).await {
        Ok(output) => Ok(tool_success(operation_id, &projected.output_type, output)),
        Err(error) => Ok(tool_error_from_adapter(error, name, operation_id)),
    }
}

fn bind_session_input(
    rpc: NativeRpc,
    mut input: Value,
    context: &ProjectionContext,
    operation_id: &str,
) -> Result<Value, Value> {
    let object = input
        .as_object_mut()
        .ok_or_else(|| json!({"code":-32602,"message":"input must be an object"}))?;
    match rpc {
        NativeRpc::GetObject => {
            let id = object
                .get("id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| json!({"code":-32602,"message":"GetObject requires input.id"}))?;
            *object = serde_json::Map::from_iter([("id".into(), json!(id))]);
        }
        NativeRpc::SubmitActionInstance => {
            if let Some(namespace) = object.get("namespace").and_then(Value::as_str)
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"Action namespace must match the authenticated adapter session"
                }));
            }
            if let Some(request_id) = object.get("request_id").and_then(Value::as_str)
                && !request_id.is_empty()
                && request_id != operation_id
            {
                return Err(json!({
                    "code":-32602,
                    "message":"SubmitActionInstance request_id must equal operation_id"
                }));
            }
            object.insert("namespace".into(), json!(context.namespace));
            object.insert("request_id".into(), json!(operation_id));
        }
        NativeRpc::GetOperationReceipt => {
            let has_operation = ["operation_id", "operationId"].iter().any(|key| {
                object
                    .get(*key)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .is_some_and(|value| !value.is_empty())
            });
            let has_request = ["request_id", "requestId"].iter().any(|key| {
                object
                    .get(*key)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .is_some_and(|value| !value.is_empty())
            });
            if !has_operation && !has_request {
                object.insert("operation_id".into(), json!(operation_id));
            }
        }
        NativeRpc::EvaluateObjectSet => {
            if let Some(descriptor) = object.get("descriptor").and_then(Value::as_object)
                && let Some(namespace) = descriptor.get("namespace").and_then(Value::as_str)
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"object-set namespace must match the authenticated adapter session"
                }));
            }
        }
        NativeRpc::GetLinks => {
            let object_id = session_string(object, "object_id")?.ok_or_else(
                || json!({"code":-32602,"message":"GetLinks requires input.object_id"}),
            )?;
            let mut bound = serde_json::Map::from_iter([("object_id".into(), json!(object_id))]);
            for key in ["relation", "direction"] {
                if let Some(value) = session_string(object, key)? {
                    bound.insert(key.into(), json!(value));
                }
            }
            *object = bound;
        }
        NativeRpc::CreateLink => {
            // Only the endpoints and the relation cross the adapter; the
            // server assigns the link id and timestamp.
            let mut bound = serde_json::Map::new();
            for key in ["from_id", "to_id", "relation"] {
                let value = session_string(object, key)?.ok_or_else(
                    || json!({"code":-32602,"message": format!("CreateLink requires input.{key}")}),
                )?;
                bound.insert(key.into(), json!(value));
            }
            *object = bound;
        }
        NativeRpc::ResolveEvaluationPlan => {
            bind_nested_namespace(object, "resolution", context)?;
        }
        NativeRpc::ExecuteEvaluationManifest => {
            bind_nested_namespace(object, "execution", context)?;
        }
        NativeRpc::DescribeObjectAction | NativeRpc::PreviewObjectAction => {
            if let Some(namespace) = object.get("namespace").and_then(Value::as_str)
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"Action namespace must match the authenticated adapter session"
                }));
            }
            object.insert("namespace".into(), json!(context.namespace));
        }
    }
    Ok(input)
}

/// Binds `input.<field>.namespace` to the session namespace, refusing a
/// different one.
fn bind_nested_namespace(
    object: &mut serde_json::Map<String, Value>,
    field: &str,
    context: &ProjectionContext,
) -> Result<(), Value> {
    let nested = object
        .get_mut(field)
        .and_then(Value::as_object_mut)
        .ok_or_else(
            || json!({"code":-32602,"message": format!("input.{field} must be an object")}),
        )?;
    if let Some(namespace) = nested.get("namespace").and_then(Value::as_str)
        && !namespace.is_empty()
        && namespace != context.namespace
    {
        return Err(json!({
            "code":-32602,
            "message":"evaluation namespace must match the authenticated adapter session"
        }));
    }
    nested.insert("namespace".into(), json!(context.namespace));
    Ok(())
}

/// A trimmed, non-empty string field, `None` when absent, and an error when
/// present with any other type.
fn session_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, Value> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty()))
        }
        Some(_) => Err(json!({"code":-32602,"message": format!("input.{key} must be a string")})),
    }
}

fn contains_reserved_metadata(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.keys().any(|key| {
        RESERVED_ARGUMENT_KEYS
            .iter()
            .any(|reserved| key.eq_ignore_ascii_case(reserved))
    })
}

fn well_known_entries() -> Vec<CapabilityEntry> {
    vec![
        capability_entry(
            GET_OBJECT_TOOL,
            "Read one authorized typed object.",
            "query",
            "sekai.GetObjectRequest",
            "sekai.GetObjectResponse",
            "read",
        ),
        capability_entry(
            EVALUATE_SET_TOOL,
            "Evaluate one authorized object set.",
            "query",
            "sekai.EvaluateObjectSetRequest",
            "sekai.EvaluateObjectSetResponse",
            "read",
        ),
        capability_entry(
            DESCRIBE_ACTION_TOOL,
            "Describe one object-bound Action type.",
            "query",
            "sekai.DescribeObjectActionRequest",
            "sekai.DescribeObjectActionResponse",
            "read",
        ),
        capability_entry(
            PREVIEW_ACTION_TOOL,
            "Preview one object-bound Action without submitting it.",
            "query",
            "sekai.PreviewObjectActionRequest",
            "sekai.PreviewObjectActionResponse",
            "read",
        ),
        capability_entry(
            SUBMIT_ACTION_TOOL,
            "Submit one governed Action instance.",
            "action",
            "sekai.SubmitActionInstanceRequest",
            "sekai.SubmitActionInstanceResponse",
            "write",
        ),
        capability_entry(
            GET_RECEIPT_TOOL,
            "Inspect the canonical operation receipt.",
            "query",
            "chisei.GetOperationReceiptRequest",
            "chisei.GetOperationReceiptResponse",
            "read",
        ),
        capability_entry(
            GET_LINKS_TOOL,
            "Read the authorized links of one object.",
            "query",
            "sekai.GetLinksRequest",
            "sekai.GetLinksResponse",
            "read",
        ),
        capability_entry(
            CREATE_LINK_TOOL,
            "Create one link between two authorized objects.",
            "action",
            "sekai.CreateLinkRequest",
            "sekai.CreateLinkResponse",
            "write",
        ),
        capability_entry(
            RESOLVE_EVALUATION_TOOL,
            "Resolve one evaluation plan into a pinned manifest.",
            "query",
            "chisei.ResolveEvaluationPlanRequest",
            "chisei.ResolveEvaluationPlanResponse",
            "read",
        ),
        capability_entry(
            EXECUTE_EVALUATION_TOOL,
            "Execute one resolved evaluation manifest.",
            "action",
            "chisei.ExecuteEvaluationManifestRequest",
            "chisei.ExecuteEvaluationManifestResponse",
            "write",
        ),
    ]
}

fn capability_entry(
    name: &str,
    description: &str,
    kind: &str,
    input_type: &str,
    output_type: &str,
    risk_class: &str,
) -> CapabilityEntry {
    CapabilityEntry {
        name: name.into(),
        description: description.into(),
        kind: kind.into(),
        lifecycle_state: "active".into(),
        contract_version: CONTRACT_VERSION.into(),
        minimum_compatible_version: CONTRACT_VERSION.into(),
        maximum_compatible_version: CONTRACT_VERSION.into(),
        replacement_capability: String::new(),
        input_type: input_type.into(),
        output_type: output_type.into(),
        required_scopes: vec!["namespace:read".into()],
        policy_decision_points: vec!["namespace_access".into()],
        risk_class: risk_class.into(),
        approval_behavior: "none".into(),
        limits: vec![],
        object_type: None,
        evidence_requirements: vec![],
        product_tier: "advanced".into(),
    }
}

fn tool_success(operation_id: &str, output_type: &str, output: Value) -> Value {
    let body = json!({
        "operation_id": operation_id,
        "output_type": output_type,
        "output": output,
    });
    json!({
        "content": [{"type":"text","text": body.to_string()}],
        "structuredContent": body,
        "isError": false
    })
}

fn tool_error(code: &str, message: &str, capability: &str, operation_id: &str) -> Value {
    let error = ProjectedError {
        code: code.into(),
        message: message.into(),
        capability: capability.into(),
        operation_id: operation_id.into(),
        retryable: matches!(code, "aborted" | "unavailable" | "deadline_exceeded"),
    };
    let body = serde_json::to_value(error).expect("projected error");
    json!({
        "content": [{"type":"text","text": body.to_string()}],
        "structuredContent": body,
        "isError": true
    })
}

fn tool_error_from_adapter(error: AdapterError, capability: &str, operation_id: &str) -> Value {
    match error {
        AdapterError::Projected(mut projected) => {
            if projected.capability.is_empty() {
                projected.capability = capability.into();
            }
            if projected.operation_id.is_empty() {
                projected.operation_id = operation_id.into();
            }
            let body = serde_json::to_value(projected).expect("projected error");
            json!({
                "content": [{"type":"text","text": body.to_string()}],
                "structuredContent": body,
                "isError": true
            })
        }
        AdapterError::Protocol(message) => {
            tool_error("invalid_argument", &message, capability, operation_id)
        }
        AdapterError::Deadline => tool_error(
            "deadline_exceeded",
            "reconcile through GetOperationReceipt",
            capability,
            operation_id,
        ),
        AdapterError::Cancelled => {
            tool_error("cancelled", "call cancelled", capability, operation_id)
        }
    }
}

fn adapter_error(error: AdapterError) -> Value {
    json!({"code":-32000,"message": error.to_string()})
}

fn rpc_error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_adapter::FixtureSurface;
    use crate::mcp_adapter::surface::FixtureObject;

    fn surface() -> FixtureSurface {
        let mut fixture = FixtureSurface::new("tester", "acme");
        fixture.insert_object(FixtureObject {
            id: "widget-1".into(),
            kind: "widget".into(),
            name: "spinner".into(),
            namespace: "acme".into(),
            properties: [("color".into(), "blue".into())].into(),
        });
        fixture
    }

    #[tokio::test]
    async fn initialize_returns_a_supported_protocol_version() {
        let newer = handle_message(
            &surface(),
            json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"initialize",
                "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"host","version":"1"}}
            }),
        )
        .await
        .unwrap();
        assert_eq!(newer["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(newer.get("error").is_none());
    }

    #[tokio::test]
    async fn lists_only_the_allowlisted_tools() {
        let listed = handle_message(
            &surface(),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await
        .unwrap();
        let names = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                GET_OBJECT_TOOL,
                EVALUATE_SET_TOOL,
                DESCRIBE_ACTION_TOOL,
                PREVIEW_ACTION_TOOL,
                SUBMIT_ACTION_TOOL,
                GET_RECEIPT_TOOL,
                GET_LINKS_TOOL,
                CREATE_LINK_TOOL,
                RESOLVE_EVALUATION_TOOL,
                EXECUTE_EVALUATION_TOOL,
            ]
        );
        assert_eq!(
            listed["result"]["tools"][0]["inputSchema"]["additionalProperties"],
            false
        );
        let got = handle_message(
            &surface(),
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{"name":GET_OBJECT_TOOL,"arguments":{"operation_id":"op-1","input":{"id":"widget-1"}}}
            }),
        )
        .await
        .unwrap();
        let output = got["result"]["structuredContent"].as_object().unwrap();
        let mut keys = output.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["operation_id", "output", "output_type"]);
    }

    #[tokio::test]
    async fn unknown_mapping_and_reserved_metadata_fail_closed() {
        let unsupported = handle_message(
            &surface(),
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{"name":"sekai.relations.traverse","arguments":{"operation_id":"op-1","input":{}}}
            }),
        )
        .await
        .unwrap();
        assert_eq!(unsupported["result"]["isError"], true);
        assert_eq!(
            unsupported["result"]["structuredContent"]["code"],
            "unimplemented"
        );

        let forged = handle_message(
            &surface(),
            json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{
                    "name": GET_OBJECT_TOOL,
                    "arguments":{
                        "operation_id":"op-1",
                        "x-principal":"other",
                        "input":{"id":"widget-1"}
                    }
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            forged["result"]["structuredContent"]["code"],
            "invalid_argument"
        );
    }

    #[tokio::test]
    async fn missing_operation_id_does_not_discover_and_warm_calls_reuse_catalog() {
        let fixture = surface();
        let missing = handle_message(
            &fixture,
            json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/call",
                "params":{"name":GET_OBJECT_TOOL,"arguments":{"input":{"id":"widget-1"}}}
            }),
        )
        .await
        .unwrap();
        assert_eq!(missing["error"]["message"], "operation_id is required");
        assert_eq!(
            fixture
                .discover_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        let first = handle_message(
            &fixture,
            json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{"name":GET_OBJECT_TOOL,"arguments":{"operation_id":"op-1","input":{"id":"widget-1"}}}
            }),
        )
        .await
        .unwrap();
        assert!(first.get("error").is_none());
        assert_eq!(
            fixture
                .discover_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        let second = handle_message(
            &fixture,
            json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{"name":GET_OBJECT_TOOL,"arguments":{"operation_id":"op-2","input":{"id":"widget-1"}}}
            }),
        )
        .await
        .unwrap();
        assert!(second.get("error").is_none());
        assert_eq!(
            fixture
                .discover_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }
}
