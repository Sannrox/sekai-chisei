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
/// Store an immutable evaluation plan (#3174) so a definition proposal can
/// name its digest in `eval_plan_digests`. The backing RPC is stable.
pub const PUT_EVALUATION_PLAN_TOOL: &str = "chisei.evaluation.plan.put";
/// Definition-branch tools (#1311). Backing RPCs are stable (#2095).
pub const CREATE_DEFINITION_BRANCH_TOOL: &str = "sekai.definitions.branch.create";
pub const EDIT_DEFINITION_BRANCH_TOOL: &str = "sekai.definitions.branch.edit";
pub const DIFF_DEFINITIONS_TOOL: &str = "sekai.definitions.diff";
pub const IMPACT_DEFINITIONS_TOOL: &str = "sekai.definitions.impact";
pub const CREATE_DEFINITION_PROPOSAL_TOOL: &str = "sekai.definitions.proposal.create";
/// Hybrid search (#1683): object references under the Search RPC's read
/// policy and fusion profile, never vectors. The backing RPC is stable (#2243).
pub const SEARCH_TOOL: &str = "sekai.search.query";
/// Ontology discovery (#2430): read-only tools under the caller's own
/// authorization. Lineage backs onto a stable RPC; the class and neighborhood
/// RPCs are still experimental, so those tools are listed only when
/// experimental RPCs are enabled. The neighborhood tool reuses the catalog
/// capability name, and the server binds it and lineage to the session
/// namespace.
pub const LIST_CLASSES_TOOL: &str = "sekai.ontology.classes.list";
pub const GET_CLASS_TOOL: &str = "sekai.ontology.classes.get";
pub const NEIGHBORHOOD_TOOL: &str = "sekai.relations.neighborhood";
pub const GET_LINEAGE_TOOL: &str = "sekai.lineage.get";
/// Upper bound on `max_nodes` for the lineage tool. The RPC clamps larger
/// values to the same cap; the tool refuses them instead of truncating.
pub const MAX_LINEAGE_NODES: i64 = 500;
/// Working memory read (#2436): the calling instance pages through its own
/// live working memory, redacted as over gRPC. Experimental.
pub const LIST_WORKING_MEMORY_TOOL: &str = "sekai.agents.memory.list";
/// Upper bound on `limit` for the working memory tool. The RPC clamps larger
/// values to the same cap; the tool refuses them instead of truncating.
pub const MAX_WORKING_MEMORY_PAGE: i64 = crate::domain::MAX_LIST_LIMIT as i64;
/// Rehearsal tools (#2432): each runs the no-effect form of its RPC and
/// submits nothing; ADR 0109 holds, a trace is never certification. All four
/// RPCs are experimental, so the tools are listed only when experimental RPCs
/// are enabled. A plan simulation is keyed by the call's `operation_id`, so
/// calling again with it returns the stored simulation; a transform preview
/// that runs isolated returns a `previewId` to read back the same way.
pub const DRY_RUN_AGENT_TOOL: &str = "sekai.agents.dry_run";
pub const SIMULATE_PLAN_TOOL: &str = "sekai.plans.simulate";
pub const PREVIEW_TRANSFORM_TOOL: &str = "sekai.transforms.preview";
pub const DRY_RUN_CHANGE_BUNDLE_TOOL: &str = "sekai.definitions.change_bundle.dry_run";
/// Dataset branch tools (#2433): develop a transform on an isolated copy of
/// a dataset and propose its merge. Merge stays a human decision over gRPC.
/// The server confines each call to datasets bound in the session namespace.
/// All four RPCs are experimental.
pub const CREATE_DATASET_BRANCH_TOOL: &str = "sekai.datasets.branch.create";
pub const RUN_TRANSFORM_ON_BRANCH_TOOL: &str = "sekai.transforms.run_on_branch";
pub const COMPARE_DATASET_BRANCH_TOOL: &str = "sekai.datasets.branch.compare";
pub const PROPOSE_DATASET_MERGE_TOOL: &str = "sekai.datasets.branch.propose_merge";
/// Experimental (#2119). Listed only when experimental RPCs are enabled.
pub const RUN_TRANSFORM_CHAIN_TOOL: &str = "sekai.transforms.chain.run";
pub const GET_TRANSFORM_CHAIN_RUN_TOOL: &str = "sekai.transforms.chain.status";

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

pub fn well_known_tools() -> [&'static str; 20] {
    [
        GET_OBJECT_TOOL,
        EVALUATE_SET_TOOL,
        DESCRIBE_ACTION_TOOL,
        PREVIEW_ACTION_TOOL,
        SUBMIT_ACTION_TOOL,
        GET_RECEIPT_TOOL,
        GET_LINKS_TOOL,
        CREATE_LINK_TOOL,
        PUT_EVALUATION_PLAN_TOOL,
        RESOLVE_EVALUATION_TOOL,
        EXECUTE_EVALUATION_TOOL,
        CREATE_DEFINITION_BRANCH_TOOL,
        EDIT_DEFINITION_BRANCH_TOOL,
        DIFF_DEFINITIONS_TOOL,
        IMPACT_DEFINITIONS_TOOL,
        CREATE_DEFINITION_PROPOSAL_TOOL,
        SEARCH_TOOL,
        GET_LINEAGE_TOOL,
        GET_CLASS_TOOL,
        NEIGHBORHOOD_TOOL,
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
        PUT_EVALUATION_PLAN_TOOL => Some(NativeRpc::PutEvaluationPlan),
        RESOLVE_EVALUATION_TOOL => Some(NativeRpc::ResolveEvaluationPlan),
        EXECUTE_EVALUATION_TOOL => Some(NativeRpc::ExecuteEvaluationManifest),
        CREATE_DEFINITION_BRANCH_TOOL => Some(NativeRpc::CreateDefinitionBranch),
        EDIT_DEFINITION_BRANCH_TOOL => Some(NativeRpc::ApplyDefinitionBranchEdit),
        DIFF_DEFINITIONS_TOOL => Some(NativeRpc::CompareDefinitionRevisions),
        IMPACT_DEFINITIONS_TOOL => Some(NativeRpc::ReportDefinitionConsumerImpact),
        CREATE_DEFINITION_PROPOSAL_TOOL => Some(NativeRpc::CreateDefinitionProposal),
        SEARCH_TOOL => Some(NativeRpc::Search),
        LIST_CLASSES_TOOL => Some(NativeRpc::ListOntologyClasses),
        GET_CLASS_TOOL => Some(NativeRpc::GetOntologyClass),
        NEIGHBORHOOD_TOOL => Some(NativeRpc::ExpandNeighborhood),
        GET_LINEAGE_TOOL => Some(NativeRpc::GetLineage),
        LIST_WORKING_MEMORY_TOOL => Some(NativeRpc::ListSiteAgentWorkingMemory),
        CREATE_DATASET_BRANCH_TOOL => Some(NativeRpc::CreateDatasetBranch),
        RUN_TRANSFORM_ON_BRANCH_TOOL => Some(NativeRpc::RunGovernedTransformOnBranch),
        COMPARE_DATASET_BRANCH_TOOL => Some(NativeRpc::CompareDatasetBranch),
        PROPOSE_DATASET_MERGE_TOOL => Some(NativeRpc::ProposeDatasetBranchMerge),
        DRY_RUN_AGENT_TOOL => Some(NativeRpc::DryRunAgent),
        SIMULATE_PLAN_TOOL => Some(NativeRpc::SimulatePlan),
        PREVIEW_TRANSFORM_TOOL => Some(NativeRpc::PreviewGovernedTransform),
        DRY_RUN_CHANGE_BUNDLE_TOOL => Some(NativeRpc::DryRunDefinitionChangeBundle),
        RUN_TRANSFORM_CHAIN_TOOL => Some(NativeRpc::RunTransformChain),
        GET_TRANSFORM_CHAIN_RUN_TOOL => Some(NativeRpc::GetTransformChainRun),
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
        "instructions": "Projection host over GetObject, EvaluateObjectSet, DescribeObjectAction, PreviewObjectAction, SubmitActionInstance, GetOperationReceipt, GetLinks, CreateLink, PutEvaluationPlan, ResolveEvaluationPlan, ExecuteEvaluationManifest, Search, GetLineage, ontology discovery, rehearsal (dry-run, simulate, preview), working-memory, dataset-branch, and definition-branch tools. Discovery is not a grant. Approve and merge stay off this surface."
    }))
}

async fn list_tools<S>(surface: &S) -> Result<Value, Value>
where
    S: NativeSurface,
{
    let snapshot = surface.refresh_catalog().await.map_err(adapter_error)?;
    let mut entries = well_known_entries();
    if surface.experimental_tools() {
        entries.extend(experimental_entries());
    }
    let tools = entries
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
        .chain(experimental_entries())
        .find(|entry| entry.name == name)
        .ok_or_else(|| json!({"code":-32602,"message":"unsupported RPC mapping"}))?;
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
        NativeRpc::GetTransformChainRun => {}
        NativeRpc::ListOntologyClasses => {
            if !object.is_empty() {
                return Err(json!({"code":-32602,"message":"listing classes takes no input"}));
            }
        }
        NativeRpc::GetOntologyClass => {
            let name = session_string(object, "name")?.ok_or_else(
                || json!({"code":-32602,"message":"reading a class requires input.name"}),
            )?;
            *object = serde_json::Map::from_iter([("name".into(), json!(name))]);
        }
        NativeRpc::ExpandNeighborhood => {
            // Every request field, defaulted; the RPC enforces the bounds
            // and refuses an over-limit request rather than truncating.
            let seeds = session_strings(object, "seed_ids", "seedIds")?;
            if seeds.is_empty() {
                return Err(
                    json!({"code":-32602,"message":"neighborhood requires input.seed_ids"}),
                );
            }
            *object = serde_json::Map::from_iter([
                ("seedIds".into(), json!(seeds)),
                (
                    "relations".into(),
                    json!(session_strings(object, "relations", "relations")?),
                ),
                (
                    "objectKinds".into(),
                    json!(session_strings(object, "object_kinds", "objectKinds")?),
                ),
                (
                    "depth".into(),
                    json!(session_int(object, "depth", "depth")?),
                ),
                (
                    "fanOutCap".into(),
                    json!(session_int(object, "fan_out_cap", "fanOutCap")?),
                ),
                (
                    "limit".into(),
                    json!(session_int(object, "limit", "limit")?),
                ),
            ]);
        }
        NativeRpc::ListSiteAgentWorkingMemory => {
            if let Some(namespace) = session_string(object, "namespace")?
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"memory namespace must match the authenticated adapter session"
                }));
            }
            let instance_id = session_string(object, "instance_id")?
                .or(session_string(object, "instanceId")?)
                .ok_or_else(
                    || json!({"code":-32602,"message":"memory read requires input.instance_id"}),
                )?;
            let turn_id = session_string(object, "turn_id")?.or(session_string(object, "turnId")?);
            let page_token =
                session_string(object, "page_token")?.or(session_string(object, "pageToken")?);
            // 0 takes the server default page; a larger page is refused, so
            // every read is bounded and pages on with next_page_token.
            let limit = session_int(object, "limit", "limit")?;
            if !(0..=MAX_WORKING_MEMORY_PAGE).contains(&limit) {
                return Err(json!({
                    "code":-32602,
                    "message": format!("input.limit must be 0 to {MAX_WORKING_MEMORY_PAGE}")
                }));
            }
            *object = serde_json::Map::from_iter([
                ("namespace".into(), json!(context.namespace)),
                ("instanceId".into(), json!(instance_id)),
                ("turnId".into(), json!(turn_id.unwrap_or_default())),
                ("limit".into(), json!(limit)),
                ("pageToken".into(), json!(page_token.unwrap_or_default())),
            ]);
        }
        NativeRpc::GetLineage => {
            let object_id = session_string(object, "object_id")?.ok_or_else(
                || json!({"code":-32602,"message":"lineage requires input.object_id"}),
            )?;
            let max_nodes = session_int(object, "max_nodes", "maxNodes")?;
            if !(0..=MAX_LINEAGE_NODES).contains(&max_nodes) {
                return Err(json!({
                    "code":-32602,
                    "message": format!("input.max_nodes must be 0 to {MAX_LINEAGE_NODES}")
                }));
            }
            *object = serde_json::Map::from_iter([
                ("objectId".into(), json!(object_id)),
                ("maxNodes".into(), json!(max_nodes)),
            ]);
        }
        NativeRpc::Search => {
            // Only these fields cross the adapter. The session fixes the
            // namespace; the tool always searches objects, hybrid by default.
            if let Some(namespace) = session_string(object, "namespace")?
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"search namespace must match the authenticated adapter session"
                }));
            }
            let text = session_string(object, "text")?
                .ok_or_else(|| json!({"code":-32602,"message":"search requires input.text"}))?;
            let mode = session_string(object, "mode")?.unwrap_or_else(|| "hybrid".into());
            if !matches!(mode.as_str(), "hybrid" | "text") {
                return Err(json!({"code":-32602,"message":"input.mode must be hybrid or text"}));
            }
            // Every SearchRequest field (its JSON names are camelCase),
            // defaulted, then the allowed ones in either spelling.
            let mut bound = serde_json::Map::from_iter([
                ("namespace".into(), json!(context.namespace)),
                ("source".into(), json!("object")),
                ("mode".into(), json!(mode)),
                ("text".into(), json!(text)),
                ("kinds".into(), json!([])),
                ("propertyFilters".into(), json!([])),
                ("facets".into(), json!([])),
                ("pageToken".into(), json!("")),
                ("pageSize".into(), json!(0)),
                ("textWeight".into(), json!(0.0)),
                ("vectorWeight".into(), json!(0.0)),
            ]);
            for (snake, camel) in [
                ("kinds", "kinds"),
                ("page_size", "pageSize"),
                ("page_token", "pageToken"),
                ("text_weight", "textWeight"),
                ("vector_weight", "vectorWeight"),
            ] {
                if let Some(value) = object.get(snake).or_else(|| object.get(camel)) {
                    bound.insert(camel.into(), value.clone());
                }
            }
            *object = bound;
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
        NativeRpc::PutEvaluationPlan => {
            bind_nested_namespace(object, "plan", context)?;
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
        NativeRpc::CreateDefinitionBranch
        | NativeRpc::ApplyDefinitionBranchEdit
        | NativeRpc::CompareDefinitionRevisions
        | NativeRpc::ReportDefinitionConsumerImpact
        | NativeRpc::CreateDefinitionProposal
        | NativeRpc::DryRunDefinitionChangeBundle
        | NativeRpc::DryRunAgent => {
            // Proto JSON wants every scalar; the optional ones default empty.
            let optional = match rpc {
                NativeRpc::DryRunDefinitionChangeBundle => Some("bundleDigest"),
                NativeRpc::DryRunAgent => Some("input"),
                _ => None,
            };
            if let Some(field) = optional {
                object.entry(field).or_insert_with(|| json!(""));
            }
            if let Some(namespace) = object.get("namespace").and_then(Value::as_str)
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"definition namespace must match the authenticated adapter session"
                }));
            }
            object.insert("namespace".into(), json!(context.namespace));
        }
        NativeRpc::CreateDatasetBranch
        | NativeRpc::CompareDatasetBranch
        | NativeRpc::ProposeDatasetBranchMerge => {
            // A dataset request names no namespace; the server checks the
            // dataset's binding against the session instead.
            if object.contains_key("namespace") {
                return Err(json!({
                    "code":-32602,
                    "message":"dataset branch tools take no input.namespace; the session namespace applies"
                }));
            }
            if rpc == NativeRpc::CreateDatasetBranch && !object.contains_key("from_version_id") {
                object.entry("fromVersionId").or_insert_with(|| json!(""));
            }
        }
        NativeRpc::RunGovernedTransformOnBranch => {
            if let Some(namespace) = object.get("namespace").and_then(Value::as_str)
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"transform namespace must match the authenticated adapter session"
                }));
            }
            object.insert("namespace".into(), json!(context.namespace));
        }
        NativeRpc::SimulatePlan => {
            if let Some(namespace) = object.get("namespace").and_then(Value::as_str)
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"plan namespace must match the authenticated adapter session"
                }));
            }
            // The simulation is keyed by the call, so the same operation_id
            // reads the stored simulation back instead of running it again.
            let supplied = session_string(object, "simulation_id")?
                .or(session_string(object, "simulationId")?);
            if let Some(id) = supplied
                && id != operation_id
            {
                return Err(json!({
                    "code":-32602,
                    "message":"SimulatePlan simulation_id must equal operation_id"
                }));
            }
            object.remove("simulation_id");
            object.insert("namespace".into(), json!(context.namespace));
            object.insert("simulationId".into(), json!(operation_id));
        }
        NativeRpc::PreviewGovernedTransform => {
            // A stored preview is read back by id alone; a new one runs the
            // given transform inside the session namespace.
            let preview_id =
                session_string(object, "preview_id")?.or(session_string(object, "previewId")?);
            if object.contains_key("transform") {
                if preview_id.is_some() {
                    return Err(json!({
                        "code":-32602,
                        "message":"pass input.transform or input.preview_id, not both"
                    }));
                }
                bind_nested_namespace(object, "transform", context)?;
            } else if preview_id.is_none() {
                return Err(json!({
                    "code":-32602,
                    "message":"preview requires input.transform or input.preview_id"
                }));
            }
            object.remove("preview_id");
            object.insert("previewId".into(), json!(preview_id.unwrap_or_default()));
            object.entry("rowCap").or_insert_with(|| json!(0));
        }
        NativeRpc::RunTransformChain => {
            if let Some(namespace) = object.get("namespace").and_then(Value::as_str)
                && namespace != context.namespace
            {
                return Err(json!({
                    "code":-32602,
                    "message":"chain namespace must match the authenticated adapter session"
                }));
            }
            let supplied = object
                .get("idempotency_key")
                .or_else(|| object.get("idempotencyKey"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if let Some(key) = supplied
                && key != operation_id
            {
                return Err(json!({
                    "code":-32602,
                    "message":"RunTransformChain idempotency_key must equal operation_id"
                }));
            }
            object.insert("namespace".into(), json!(context.namespace));
            object.insert("idempotencyKey".into(), json!(operation_id));
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
            "message": format!("input.{field}.namespace must match the authenticated adapter session")
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

/// A string array under either spelling, empty when absent; any other type
/// is an error.
fn session_strings(
    object: &serde_json::Map<String, Value>,
    snake: &str,
    camel: &str,
) -> Result<Vec<String>, Value> {
    let invalid =
        || json!({"code":-32602,"message": format!("input.{snake} must be an array of strings")});
    match object.get(snake).or_else(|| object.get(camel)) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string).ok_or_else(invalid))
            .collect(),
        Some(_) => Err(invalid()),
    }
}

/// An integer under either spelling, 0 when absent; any other type is an error.
fn session_int(
    object: &serde_json::Map<String, Value>,
    snake: &str,
    camel: &str,
) -> Result<i64, Value> {
    match object.get(snake).or_else(|| object.get(camel)) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => value
            .as_i64()
            .filter(|value| i32::try_from(*value).is_ok())
            .ok_or_else(
                || json!({"code":-32602,"message": format!("input.{snake} must be an integer")}),
            ),
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
            PUT_EVALUATION_PLAN_TOOL,
            "Store one immutable evaluation plan and return its content digest.",
            "action",
            "chisei.PutEvaluationPlanRequest",
            "chisei.PutEvaluationPlanResponse",
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
        capability_entry(
            CREATE_DEFINITION_BRANCH_TOOL,
            "Create one definition branch from a published parent.",
            "action",
            "sekai.CreateDefinitionBranchRequest",
            "sekai.CreateDefinitionBranchResponse",
            "write",
        ),
        capability_entry(
            EDIT_DEFINITION_BRANCH_TOOL,
            "Apply one definition-branch edit.",
            "action",
            "sekai.ApplyDefinitionBranchEditRequest",
            "sekai.ApplyDefinitionBranchEditResponse",
            "write",
        ),
        capability_entry(
            DIFF_DEFINITIONS_TOOL,
            "Compare two definition revisions.",
            "query",
            "sekai.CompareDefinitionRevisionsRequest",
            "sekai.CompareDefinitionRevisionsResponse",
            "read",
        ),
        capability_entry(
            IMPACT_DEFINITIONS_TOOL,
            "Report visible consumers of a definition revision pair.",
            "query",
            "sekai.ReportDefinitionConsumerImpactRequest",
            "sekai.ReportDefinitionConsumerImpactResponse",
            "read",
        ),
        capability_entry(
            CREATE_DEFINITION_PROPOSAL_TOOL,
            "Open one definition proposal from a branch head.",
            "action",
            "sekai.CreateDefinitionProposalRequest",
            "sekai.CreateDefinitionProposalResponse",
            "write",
        ),
        capability_entry(
            SEARCH_TOOL,
            "Search objects by text and meaning; returns references the caller may read, never vectors.",
            "query",
            "sekai.SearchRequest",
            "sekai.SearchResponse",
            "read",
        ),
        capability_entry(
            GET_LINEAGE_TOOL,
            "Read where one authorized object came from: its sources, transforms, and upstream objects.",
            "query",
            "sekai.GetLineageRequest",
            "sekai.GetLineageResponse",
            "read",
        ),
        capability_entry(
            GET_CLASS_TOOL,
            "Read one ontology class with its properties.",
            "query",
            "sekai.GetOntologyClassRequest",
            "sekai.GetOntologyClassResponse",
            "read",
        ),
        capability_entry(
            NEIGHBORHOOD_TOOL,
            "Expand the authorized neighborhood of objects, bounded in depth, fan-out, and size.",
            "query",
            "sekai.ExpandNeighborhoodRequest",
            "sekai.ExpandNeighborhoodResponse",
            "read",
        ),
    ]
}

fn experimental_entries() -> Vec<CapabilityEntry> {
    vec![
        capability_entry(
            LIST_WORKING_MEMORY_TOOL,
            "Page through the calling agent instance's live working memory, redacted as over gRPC.",
            "query",
            "sekai.ListSiteAgentWorkingMemoryRequest",
            "sekai.ListSiteAgentWorkingMemoryResponse",
            "read",
        ),
        capability_entry(
            CREATE_DATASET_BRANCH_TOOL,
            "Create a named branch of a dataset, forked from its latest or a given version; the live dataset is untouched.",
            "action",
            "sekai.CreateDatasetBranchRequest",
            "sekai.CreateDatasetBranchResponse",
            "write",
        ),
        capability_entry(
            RUN_TRANSFORM_ON_BRANCH_TOOL,
            "Run a governed transform with its output written to a dataset branch instead of the live dataset.",
            "action",
            "sekai.RunGovernedTransformOnBranchRequest",
            "sekai.RunGovernedTransformOnBranchResponse",
            "write",
        ),
        capability_entry(
            COMPARE_DATASET_BRANCH_TOOL,
            "Compare a dataset branch with its base: columns added or removed, row counts, and digests.",
            "query",
            "sekai.CompareDatasetBranchRequest",
            "sekai.CompareDatasetBranchResponse",
            "read",
        ),
        capability_entry(
            PROPOSE_DATASET_MERGE_TOOL,
            "Propose merging a dataset branch; another principal merges it over gRPC.",
            "action",
            "sekai.ProposeDatasetBranchMergeRequest",
            "sekai.ProposeDatasetBranchMergeResponse",
            "write",
        ),
        capability_entry(
            DRY_RUN_AGENT_TOOL,
            "Dry-run an agent definition revision: its model steps, tool calls, and the Actions it would propose, none submitted.",
            "query",
            "sekai.DryRunAgentRequest",
            "sekai.DryRunAgentResponse",
            "read",
        ),
        capability_entry(
            SIMULATE_PLAN_TOOL,
            "Simulate a proposed plan step by step without submitting it; the same operation_id reads the stored simulation.",
            "query",
            "sekai.SimulatePlanRequest",
            "sekai.SimulatePlanResponse",
            "read",
        ),
        capability_entry(
            PREVIEW_TRANSFORM_TOOL,
            "Preview a governed transform's output rows without running or storing it, or read back a preview by preview_id.",
            "query",
            "sekai.PreviewGovernedTransformRequest",
            "sekai.PreviewGovernedTransformResponse",
            "read",
        ),
        capability_entry(
            DRY_RUN_CHANGE_BUNDLE_TOOL,
            "Dry-run the backfills a definition change would need between two revisions and report the rows they would change.",
            "query",
            "sekai.DryRunDefinitionChangeBundleRequest",
            "sekai.DryRunDefinitionChangeBundleResponse",
            "read",
        ),
        capability_entry(
            LIST_CLASSES_TOOL,
            "List the ontology classes the caller may read.",
            "query",
            "sekai.ListOntologyClassesRequest",
            "sekai.ListOntologyClassesResponse",
            "read",
        ),
        capability_entry(
            RUN_TRANSFORM_CHAIN_TOOL,
            "Run one registered transform chain as a governed, receipted operation.",
            "action",
            "sekai.RunTransformChainRequest",
            "sekai.RunTransformChainResponse",
            "write",
        ),
        capability_entry(
            GET_TRANSFORM_CHAIN_RUN_TOOL,
            "Read the status and receipt of one transform chain run.",
            "query",
            "sekai.GetTransformChainRunRequest",
            "sekai.GetTransformChainRunResponse",
            "read",
        ),
    ]
}

/// One adapter tool as a catalog entry. A read tool states the namespace read
/// scope and no approval. A writing tool leaves scopes, decision points, and
/// approval behavior empty, so `_meta` omits them: the generic tool has no
/// native catalog entry, and whether a write needs a further scope or parks
/// for approval depends on the Action type and namespace policy that the
/// server enforces on the call.
fn capability_entry(
    name: &str,
    description: &str,
    kind: &str,
    input_type: &str,
    output_type: &str,
    risk_class: &str,
) -> CapabilityEntry {
    let read_only = risk_class == "read";
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
        required_scopes: if read_only {
            vec!["namespace:read".into()]
        } else {
            vec![]
        },
        policy_decision_points: if read_only {
            vec!["namespace_access".into()]
        } else {
            vec![]
        },
        risk_class: risk_class.into(),
        approval_behavior: if read_only { "none" } else { "" }.into(),
        limits: vec![],
        object_type: None,
        evidence_requirements: vec![],
        product_tier: "advanced".into(),
        parameter_schema_json: String::new(),
        markings: vec![],
        action_version: String::new(),
        tool_effect: String::new(),
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

    /// A writing tool must not report a read scope or "never needs approval"
    /// (#2431); a read tool keeps stating both.
    #[tokio::test]
    async fn writing_tools_do_not_report_a_read_scope_or_no_approval() {
        let listed = handle_message(
            &surface(),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await
        .unwrap();
        let tools = listed["result"]["tools"].as_array().unwrap();
        let meta_of = |name: &str| {
            tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("{name} is listed"))["_meta"]
                .clone()
        };
        for tool in tools {
            let meta = &tool["_meta"];
            if tool["annotations"]["readOnlyHint"] == false {
                assert_eq!(meta["risk_class"], "write", "{}", tool["name"]);
                for field in [
                    "required_scopes",
                    "policy_decision_points",
                    "approval_behavior",
                ] {
                    assert!(
                        meta.get(field).is_none(),
                        "{} reports {field}",
                        tool["name"]
                    );
                }
            }
        }
        let read = meta_of(GET_OBJECT_TOOL);
        assert_eq!(read["required_scopes"], json!(["namespace:read"]));
        assert_eq!(read["approval_behavior"], "none");
        assert!(
            meta_of(SUBMIT_ACTION_TOOL)
                .get("approval_behavior")
                .is_none()
        );
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
                PUT_EVALUATION_PLAN_TOOL,
                RESOLVE_EVALUATION_TOOL,
                EXECUTE_EVALUATION_TOOL,
                CREATE_DEFINITION_BRANCH_TOOL,
                EDIT_DEFINITION_BRANCH_TOOL,
                DIFF_DEFINITIONS_TOOL,
                IMPACT_DEFINITIONS_TOOL,
                CREATE_DEFINITION_PROPOSAL_TOOL,
                SEARCH_TOOL,
                GET_LINEAGE_TOOL,
                GET_CLASS_TOOL,
                NEIGHBORHOOD_TOOL,
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

    #[tokio::test]
    async fn run_transform_chain_binds_operation_id_as_idempotency_key() {
        let fixture = surface();
        let call = |id: i64, input: Value| {
            json!({
                "jsonrpc":"2.0",
                "id":id,
                "method":"tools/call",
                "params":{
                    "name": RUN_TRANSFORM_CHAIN_TOOL,
                    "arguments":{"operation_id":"op-chain-1","input":input}
                }
            })
        };
        let conflict = handle_message(
            &fixture,
            call(1, json!({"chainId":"c1","idempotencyKey":"other"})),
        )
        .await
        .unwrap();
        assert_eq!(conflict["error"]["code"], -32602, "{conflict}");
        assert!(
            conflict["error"]["message"]
                .as_str()
                .unwrap()
                .contains("idempotency_key"),
            "{conflict}"
        );

        let snake_conflict = handle_message(
            &fixture,
            call(2, json!({"chain_id":"c1","idempotency_key":"other"})),
        )
        .await
        .unwrap();
        assert_eq!(snake_conflict["error"]["code"], -32602, "{snake_conflict}");

        let foreign = handle_message(
            &fixture,
            call(3, json!({"namespace":"other","chainId":"c1"})),
        )
        .await
        .unwrap();
        assert_eq!(foreign["error"]["code"], -32602, "{foreign}");

        let denied = handle_message(&fixture, call(4, json!({"chainId":"c1"})))
            .await
            .unwrap();
        assert_eq!(denied["result"]["isError"], true, "{denied}");
        assert_eq!(
            denied["result"]["structuredContent"]["code"],
            "permission_denied"
        );

        let matching = handle_message(
            &fixture,
            call(5, json!({"chainId":"c1","idempotencyKey":"op-chain-1"})),
        )
        .await
        .unwrap();
        assert_eq!(
            matching["result"]["structuredContent"]["code"], "permission_denied",
            "{matching}"
        );
    }
}
