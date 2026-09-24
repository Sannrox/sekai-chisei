use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tonic::Request;
use tonic::metadata::MetadataValue;

use crate::capability_projection::{ProjectionContext, SdkInvocation};
use crate::chisei::budget::BudgetTracker;
use crate::config::Config;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::grpc::chisei_service::ChiseiServiceImpl;
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::pb::sekai::{
    CreateObjectRequest, CreateSchemaTypeRequest, DiscoverCapabilitiesRequest, GovernedActionType,
    Object, ObjectType, PropertyDef, PutGovernedActionTypeRequest,
};
use crate::grpc::sekai_service::SekaiServiceImpl;
use crate::sekai::action_policy::ActionPolicy;
use crate::sekai::capability::CONTRACT_VERSION;
use crate::sekai::security::{Grant, Role};

use super::surface::{AdapterError, CatalogSnapshot, NativeRpc, NativeSurface, status_error};

const PRINCIPAL: &str = "tester";
const NAMESPACE: &str = "acme";
const OBJECT_ID: &str = "widget-1";
const ACTION_TYPE: &str = "review.intake";
const ACTION_VERSION: &str = "1.0.0";

/// Isolated SQLite plane used by the synthetic example and conformance test.
pub struct InProcessSurface {
    pub principal: String,
    pub namespace: String,
    pub object_id: String,
    pub action_type: String,
    pub action_version: String,
    sekai: SekaiServiceImpl,
    chisei: ChiseiServiceImpl,
}

impl InProcessSurface {
    pub async fn synthetic() -> Result<Self, String> {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").map_err(|error| error.to_string())?,
        )));
        db.ensure_team_namespace(NAMESPACE, PRINCIPAL, Role::Admin, "local")
            .map_err(|error| error.to_string())?;
        db.upsert_action_policy(&ActionPolicy::allow_all(PRINCIPAL))
            .map_err(|error| error.to_string())?;
        for (id, object_id) in [
            ("schema-admin-mcp", "schema"),
            ("action-admin-mcp", "action"),
        ] {
            db.create_grant(&Grant {
                id: id.into(),
                object_id: object_id.into(),
                principal: PRINCIPAL.into(),
                role: Role::Admin,
                created: 0,
            })
            .map_err(|error| error.to_string())?;
        }
        let sekai_store = crate::db::store::SekaiStore::from_shared_runtime(db.clone());
        let chisei_store = crate::db::store::ChiseiStore::from_shared_runtime(db);
        let budget = Arc::new(BudgetTracker::new(chisei_store.clone()));
        let clerk = crate::chisei::cross_store_admission::CrossStoreAdmission::new(
            chisei_store.clone(),
            sekai_store.clone(),
            Some(budget),
        );
        let sekai = SekaiServiceImpl::new(sekai_store).with_cross_store_admission(Arc::new(clerk));
        let chisei = ChiseiServiceImpl::new(chisei_store, fixture_config());

        let surface = Self {
            principal: PRINCIPAL.into(),
            namespace: NAMESPACE.into(),
            object_id: OBJECT_ID.into(),
            action_type: ACTION_TYPE.into(),
            action_version: ACTION_VERSION.into(),
            sekai,
            chisei,
        };
        surface.seed().await?;
        Ok(surface)
    }

    async fn seed(&self) -> Result<(), String> {
        self.sekai
            .create_schema_type(with_identity(
                CreateSchemaTypeRequest {
                    r#type: Some(ObjectType {
                        kind: "widget".into(),
                        description: "Synthetic widget".into(),
                        is_builtin: false,
                        implements: vec![],
                        properties: vec![property("name", true), property("color", true)],
                    }),
                },
                &self.principal,
                &self.namespace,
            ))
            .await
            .map_err(|error| error.message().to_string())?;
        self.sekai
            .create_object(with_identity(
                CreateObjectRequest {
                    object: Some(Object {
                        id: self.object_id.clone(),
                        kind: "widget".into(),
                        name: "spinner".into(),
                        namespace: self.namespace.clone(),
                        external_id: String::new(),
                        properties: HashMap::from([
                            ("name".into(), "spinner".into()),
                            ("color".into(), "blue".into()),
                        ]),
                        created: 0,
                        updated: 0,
                    }),
                    lease_precondition: None,
                },
                &self.principal,
                &self.namespace,
            ))
            .await
            .map_err(|error| error.message().to_string())?;
        self.sekai
            .put_governed_action_type(with_identity(
                PutGovernedActionTypeRequest {
                    r#type: Some(GovernedActionType {
                        namespace: self.namespace.clone(),
                        type_id: self.action_type.clone(),
                        version: self.action_version.clone(),
                        description: "Admit review".into(),
                        parameter_schema_json: r#"{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}"#.into(),
                        allowed_effect_kinds: vec!["runtime_dispatch".into()],
                        approvers: Vec::new(),
                        policy_scope: String::new(),
                        budget_scope: String::new(),
                        enabled: true,
                        created_by: String::new(),
                        created_at_ms: 0,
                        updated_at_ms: 0,
                        disabled_at_ms: 0,
                        object_kind: String::new(),
                        object_mutation: String::new(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
                        system_one_json: String::new(),
                    }),
                    request_id: "put-mcp-action".into(),
                },
                &self.principal,
                &self.namespace,
            ))
            .await
            .map_err(|error| error.message().to_string())?;
        Ok(())
    }
}

#[async_trait]
impl NativeSurface for InProcessSurface {
    async fn discover(&self) -> Result<CatalogSnapshot, AdapterError> {
        let response = self
            .sekai
            .discover_capabilities(with_identity(
                DiscoverCapabilitiesRequest {
                    namespace: self.namespace.clone(),
                    product_tier_filter: "all".into(),
                    page_size: 200,
                    ..Default::default()
                },
                &self.principal,
                &self.namespace,
            ))
            .await
            .map_err(status_error)?
            .into_inner();
        Ok(CatalogSnapshot {
            context: ProjectionContext {
                namespace: self.namespace.clone(),
                principal: self.principal.clone(),
                contract_version: if response.contract_version.is_empty() {
                    CONTRACT_VERSION.into()
                } else {
                    response.contract_version
                },
                catalog_version: response.catalog_version,
            },
        })
    }

    async fn dispatch(
        &self,
        rpc: NativeRpc,
        invocation: SdkInvocation,
    ) -> Result<Value, AdapterError> {
        super::surface::dispatch_native(&self.sekai, &self.chisei, rpc, invocation).await
    }
}

fn property(name: &str, required: bool) -> PropertyDef {
    PropertyDef {
        name: name.into(),
        r#type: "string".into(),
        required,
        description: String::new(),
        enum_values: vec![],
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: String::new(),
        struct_fields: vec![],
    }
}

fn with_identity<T>(payload: T, principal: &str, namespace: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).expect("principal"),
    );
    request.metadata_mut().insert(
        "x-sekai-namespace",
        MetadataValue::try_from(namespace).expect("namespace"),
    );
    request
}

fn fixture_config() -> Config {
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
        openai_api_key: None,
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
        insecure: true,
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
    }
}

#[derive(Debug, serde::Serialize)]
pub struct SyntheticHostReport {
    pub contract: &'static str,
    pub tools: Vec<String>,
    pub object_id: String,
    pub object_color: String,
    pub action_status: String,
    pub action_operation_id: String,
    pub receipt_present: bool,
    pub receipt_complete: bool,
}

/// Independent MCP client against the synthetic in-process plane.
pub async fn run_synthetic_host() -> Result<SyntheticHostReport, String> {
    use super::{handle_message, read_frame, serve_io, write_frame};
    use std::sync::Arc;
    use tokio::io::BufReader;

    let surface = Arc::new(InProcessSurface::synthetic().await?);
    let (client_out, server_in) = tokio::io::duplex(64 * 1024);
    let (server_out, client_in) = tokio::io::duplex(64 * 1024);
    let served = surface.clone();
    let server =
        tokio::spawn(async move { serve_io(served, BufReader::new(server_in), server_out).await });

    let mut writer = client_out;
    let mut reader = BufReader::new(client_in);
    write_frame(
        &mut writer,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sekai-mcp-example","version":"1"}}}),
    )
    .await?;
    let initialized = read_frame(&mut reader).await?;
    if initialized["result"]["serverInfo"]["name"] != "sekai-mcp" {
        return Err("initialize did not return sekai-mcp".into());
    }
    let _ = handle_message(
        surface.as_ref(),
        json!({"jsonrpc":"2.0","id":99,"method":"ping"}),
    )
    .await;

    write_frame(
        &mut writer,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await?;
    let listed = read_frame(&mut reader).await?;
    let tools = listed["result"]["tools"]
        .as_array()
        .ok_or("tools/list missing tools")?
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();

    write_frame(
        &mut writer,
        &json!({
            "jsonrpc":"2.0",
            "id":3,
            "method":"tools/call",
            "params":{
                "name":"sekai.objects.get",
                "arguments":{"operation_id":"op-get-1","input":{"id": surface.object_id}}
            }
        }),
    )
    .await?;
    let object = call_output(read_frame(&mut reader).await?)?;

    write_frame(
        &mut writer,
        &json!({
            "jsonrpc":"2.0",
            "id":4,
            "method":"tools/call",
            "params":{
                "name":"sekai.actions.submit",
                "arguments":{
                    "operation_id":"op-act-1",
                    "input":{
                        "type_id": surface.action_type,
                        "version": surface.action_version,
                        "parameters_json": {"summary":"ship it"},
                        "idempotency_key":"idem-mcp-1"
                    }
                }
            }
        }),
    )
    .await?;
    let action = call_output(read_frame(&mut reader).await?)?;

    write_frame(
        &mut writer,
        &json!({
            "jsonrpc":"2.0",
            "id":5,
            "method":"tools/call",
            "params":{
                "name":"chisei.receipt.read",
                "arguments":{"operation_id":"op-act-1","input":{"operation_id":"op-act-1"}}
            }
        }),
    )
    .await?;
    let receipt = call_output(read_frame(&mut reader).await?)?;
    drop(writer);
    server.await.map_err(|error| error.to_string())?.ok();

    Ok(SyntheticHostReport {
        contract: "sekai.mcp-adapter/v1",
        tools,
        object_id: object["output"]["object"]["id"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        object_color: object["output"]["object"]["properties"]["color"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        action_status: action["output"]["instance"]["status"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        action_operation_id: action["output"]["instance"]["operation_id"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        receipt_present: receipt["output"]
            .get("receipt_json")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("op-act-1")),
        receipt_complete: receipt["output"]["complete"].as_bool().unwrap_or(false),
    })
}

fn call_output(message: Value) -> Result<Value, String> {
    if message["result"]["isError"] == true {
        return Err(message["result"]["structuredContent"].to_string());
    }
    Ok(message["result"]["structuredContent"].clone())
}
