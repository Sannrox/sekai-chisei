use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};
use tonic::Request;
use tonic::metadata::MetadataValue;

use crate::capability_projection::{ProjectionContext, SdkInvocation};
use crate::chisei::budget::BudgetTracker;
use crate::config::Config;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::{self, ListFilter};
use crate::grpc::chisei_service::ChiseiServiceImpl;
use crate::grpc::pb::sekai::sekai_service_server::SekaiService;
use crate::grpc::pb::sekai::{
    CreateSchemaTypeRequest, DiscoverCapabilitiesRequest, GovernedActionType, ObjectType,
    PropertyDef, PutGovernedActionTypeRequest,
};
use crate::grpc::sekai_service::SekaiServiceImpl;
use crate::sekai::action_policy::ActionPolicy;
use crate::sekai::capability::CONTRACT_VERSION;
use crate::sekai::definition_branch::{
    DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
};
use crate::sekai::object_security::{
    OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
    ObjectSecurityPredicate, ObjectSecurityRule,
};
use crate::sekai::object_set::CONTRACT_VERSION as OBJECT_SET_CONTRACT;
use crate::sekai::security::{Grant, Role};

use super::surface::{AdapterError, CatalogSnapshot, NativeRpc, NativeSurface, status_error};

const PRINCIPAL: &str = "tester";
const NAMESPACE: &str = "acme";
const OBJECT_ID: &str = "widget-1";
/// A second synthetic object, so link tools have two endpoints (#1093).
const PEER_OBJECT_ID: &str = "widget-2";
/// Objects in another namespace the principal can still ACL, for #1203.
const FOREIGN_NAMESPACE: &str = "other";
const FOREIGN_OBJECT_ID: &str = "other-widget-1";
const FOREIGN_PEER_OBJECT_ID: &str = "other-widget-2";
const ACTION_TYPE: &str = "review.intake";
const ACTION_VERSION: &str = "1.0.0";
const SECRET_KIND: &str = "secret";
const SECRET_OBJECT_ID: &str = "secret-1";
const SECRET_PAYLOAD: &str = "classified-token-xyz";

/// Isolated SQLite plane used by the synthetic example and conformance test.
pub struct InProcessSurface {
    pub principal: String,
    pub namespace: String,
    pub object_id: String,
    pub peer_object_id: String,
    pub foreign_object_id: String,
    pub foreign_peer_object_id: String,
    pub action_type: String,
    pub action_version: String,
    pub definition_digest: String,
    pub secret_object_id: String,
    pub sekai: SekaiServiceImpl,
    chisei: ChiseiServiceImpl,
    catalog: Mutex<Option<CatalogSnapshot>>,
    /// Whether experimental tools may run. The synthetic plane enables them;
    /// a deployed host passes the operator setting.
    pub experimental_rpcs: bool,
    /// The plane's store, for fixture methods that seed it directly.
    db: Arc<RuntimeDb>,
}

impl InProcessSurface {
    pub async fn synthetic() -> Result<Self, String> {
        Self::synthetic_with(None).await
    }

    /// The synthetic plane, with an embedding route for hybrid search when
    /// given (as combined mode wires one).
    pub async fn synthetic_with(
        embedding_route: Option<crate::composition::embedding_catch_up::EmbeddingRoute>,
    ) -> Result<Self, String> {
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").map_err(|error| error.to_string())?,
        )));
        db.ensure_team_namespace(NAMESPACE, PRINCIPAL, Role::Admin, "local")
            .map_err(|error| error.to_string())?;
        db.ensure_team_namespace(FOREIGN_NAMESPACE, PRINCIPAL, Role::Admin, "local")
            .map_err(|error| error.to_string())?;
        db.upsert_action_policy(&ActionPolicy::allow_all(PRINCIPAL))
            .map_err(|error| error.to_string())?;
        for (id, object_id) in [
            ("schema-admin-mcp", "schema"),
            ("action-admin-mcp", "action"),
            ("foreign-object-acl-1", FOREIGN_OBJECT_ID),
            ("foreign-object-acl-2", FOREIGN_PEER_OBJECT_ID),
        ] {
            db.create_grant(&Grant {
                id: id.into(),
                object_id: object_id.into(),
                principal: PRINCIPAL.into(),
                role: Role::Admin,
                created: 0,
                ..Default::default()
            })
            .map_err(|error| error.to_string())?;
        }
        let sekai_store = crate::db::store::SekaiStore::from_shared_runtime(db.clone());
        let chisei_store = crate::chisei_store::ChiseiStore::from_shared_runtime(db.clone());
        let budget = Arc::new(BudgetTracker::new(chisei_store.clone()));
        let clerk = crate::composition::cross_store_admission::CrossStoreAdmission::new(
            chisei_store.clone(),
            sekai_store.clone(),
            Some(budget),
        );
        let mut sekai =
            SekaiServiceImpl::new(sekai_store.clone()).with_cross_store_admission(Arc::new(clerk));
        if let Some(route) = embedding_route {
            sekai = sekai.with_embedding_route(route);
        }
        let chisei = ChiseiServiceImpl::new(chisei_store, fixture_config())
            .with_sekai_facts(crate::chisei::sekai_facts::SekaiFacts::in_process(
                sekai_store.clone(),
            ))
            .unwrap();

        let mut surface = Self {
            principal: PRINCIPAL.into(),
            namespace: NAMESPACE.into(),
            object_id: OBJECT_ID.into(),
            peer_object_id: PEER_OBJECT_ID.into(),
            foreign_object_id: FOREIGN_OBJECT_ID.into(),
            foreign_peer_object_id: FOREIGN_PEER_OBJECT_ID.into(),
            action_type: ACTION_TYPE.into(),
            action_version: ACTION_VERSION.into(),
            definition_digest: String::new(),
            secret_object_id: SECRET_OBJECT_ID.into(),
            sekai,
            chisei,
            catalog: Mutex::new(None),
            experimental_rpcs: true,
            db,
        };
        surface.seed().await?;
        Ok(surface)
    }

    async fn seed(&mut self) -> Result<(), String> {
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
            .create_schema_type(with_identity(
                CreateSchemaTypeRequest {
                    r#type: Some(ObjectType {
                        kind: SECRET_KIND.into(),
                        description: "Synthetic secret".into(),
                        is_builtin: false,
                        implements: vec![],
                        properties: vec![property("name", true), property("payload", true)],
                    }),
                },
                &self.principal,
                &self.namespace,
            ))
            .await
            .map_err(|error| error.message().to_string())?;
        for (id, name, color, namespace) in [
            (&self.object_id, "spinner", "blue", self.namespace.as_str()),
            (&self.peer_object_id, "gear", "red", self.namespace.as_str()),
            (
                &self.foreign_object_id,
                "foreign-spinner",
                "green",
                FOREIGN_NAMESPACE,
            ),
            (
                &self.foreign_peer_object_id,
                "foreign-gear",
                "yellow",
                FOREIGN_NAMESPACE,
            ),
        ] {
            self.db
                .create_object_with_audit(
                    &domain::Object {
                        id: id.clone(),
                        kind: "widget".into(),
                        name: name.into(),
                        namespace: namespace.into(),
                        external_id: String::new(),
                        properties: HashMap::from([
                            ("name".into(), name.into()),
                            ("color".into(), color.into()),
                        ]),
                        created: 1,
                        updated: 1,
                    },
                    &self.principal,
                )
                .map_err(|error| error.to_string())?;
        }
        // Persist a cross-namespace link on the store path. MCP get must not
        // disclose the foreign id.
        self.db
            .create_link(&domain::Link {
                id: "mcp-leak".into(),
                from_id: self.object_id.clone(),
                to_id: self.foreign_object_id.clone(),
                relation: "leaks_to".into(),
                created: 1,
            })
            .map_err(|error| error.to_string())?;
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
                        review_queue_id: String::new(),
                        review_sla_ms: 0,
                        review_escalate: String::new(),
                        review_escalate_to: String::new(),
                        review_threshold_param: String::new(),
                        review_threshold: 0,
                        review_pool: vec![],
                        review_agent_reviewers: vec![],
                        last_writer_wins_properties: Vec::new(), offline_conflict: String::new(), impact_class: String::new(),
            budget_work_unit_parameter: String::new(),
            budget_amount_parameter: String::new(),
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

    /// Bind evaluate_set to a published revision of the synthetic kinds.
    pub fn seed_object_set_definition(&mut self) -> Result<(), String> {
        self.definition_digest = seed_published_definition(self.db.as_ref())?;
        Ok(())
    }

    /// Activate object-security for every instantiated kind except `kind`.
    /// An EvaluateObjectSet of that kind is then type-denied.
    pub fn deny_object_type(&self, kind: &str) -> Result<(), String> {
        let instantiated = self
            .db
            .list_objects(&ListFilter {
                namespace: Some(self.namespace.clone()),
                limit: 1000,
                ..Default::default()
            })
            .map_err(|error| error.to_string())?;
        let mut activation = BTreeMap::new();
        for (index, instantiated_kind) in instantiated
            .iter()
            .map(|object| object.kind.as_str())
            .filter(|instantiated_kind| *instantiated_kind != kind)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
        {
            let policy = ObjectSecurityPolicy {
                contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
                namespace: self.namespace.clone(),
                kind: instantiated_kind.into(),
                rules: vec![ObjectSecurityRule {
                    operation: ObjectSecurityOperation::Read,
                    predicates: vec![ObjectSecurityPredicate::AllowAll],
                }],
                property_grants: None,
                value_instance_grants: None,
                required_purpose: None,
            };
            let revision = self
                .db
                .put_object_security_policy(
                    &policy,
                    "root",
                    &format!("put-mcp-{instantiated_kind}"),
                    10 + index as i64,
                )
                .map_err(|error| error.to_string())?;
            activation.insert(instantiated_kind.to_string(), revision.revision_digest);
        }
        self.db
            .activate_object_security_policies(
                &self.namespace,
                &activation,
                "root",
                "activate-mcp",
                40,
            )
            .map_err(|error| error.to_string())?;
        // Rows of the denied kind exist after activation so a leak would be
        // visible; the kind has no policy, so EvaluateObjectSet must deny.
        if kind == SECRET_KIND {
            self.db
                .create_object(&domain::Object {
                    id: self.secret_object_id.clone(),
                    kind: SECRET_KIND.into(),
                    name: "vault".into(),
                    namespace: self.namespace.clone(),
                    external_id: String::new(),
                    properties: HashMap::from([
                        ("name".into(), "vault".into()),
                        ("payload".into(), SECRET_PAYLOAD.into()),
                    ]),
                    created: 1,
                    updated: 1,
                })
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    /// Store one evaluator definition and one evaluation plan in `namespace`
    /// directly, as an operator would, and return the plan's content digest.
    /// The plan cites one unmarked invariant, so every caller with namespace
    /// access can see it.
    pub fn seed_evaluation_plan(&self, namespace: &str) -> Result<String, String> {
        use crate::chisei::evaluation_plan::*;
        use crate::ext::*;
        use crate::sekai::governed_facts as facts;
        // A plan node must cite a governed invariant; install one first.
        facts::apply_profile(
            &self.db,
            namespace,
            facts::PROFILE_CONTRACT_VERSION,
            "root",
            1,
        )?;
        let invariant = facts::put_fact(
            &self.db,
            facts::GovernedFactInput {
                contract_version: facts::PROFILE_CONTRACT_VERSION.into(),
                namespace: namespace.into(),
                fact_id: "document-schema".into(),
                version: "1.0.0".into(),
                fact_type: facts::GovernedFactType::Invariant,
                status: "active".into(),
                statement: "The document conforms to the declared schema.".into(),
                applicability: facts::FactApplicability {
                    subject_profiles: vec!["document/v1".into()],
                    subject_refs: Vec::new(),
                },
                verification: facts::VerificationContract {
                    predicate_kind: "schema_conforms".into(),
                    input_schema: "schema://document/v1".into(),
                    result_schema: "schema://pass-fail/v1".into(),
                    evidence_types: Vec::new(),
                },
                requirement_version_ids: Vec::new(),
                evidence_refs: Vec::new(),
                source_ref: "repo://requirements/document-schema@1".into(),
                effective_from_ms: 1,
                supersedes_object_id: String::new(),
                access_marking: String::new(),
            },
            "root",
            2,
        )?;
        let definition = self.db.put_evaluator_definition(
            EvaluatorDefinition {
                declared_metrics: Vec::new(),
                contract_version: EVALUATOR_DEFINITION_CONTRACT.into(),
                definition_id: String::new(),
                namespace: namespace.into(),
                evaluator_id: "schema-check".into(),
                version: "1.0.0".into(),
                implementation_digest: format!("sha256:{}", "a".repeat(64)),
                execution_class: DETERMINISTIC_EXECUTION_CLASS.into(),
                supported_predicate_kinds: vec!["schema_conforms".into()],
                supported_input_schemas: vec!["schema://document/v1".into()],
                supported_result_schemas: vec!["schema://pass-fail/v1".into()],
                parameter_schema_json: r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#.into(),
                evidence_classifications: vec!["internal".into()],
                resource_limits: EvaluatorResourceLimits {
                    timeout_ms: 1_000,
                    max_input_bytes: 4_096,
                    max_output_bytes: 1_024,
                    max_evidence_items: 8,
                },
                adapter_endpoint: String::new(),
                stochastic_policy: None,
                source_ref: "repo://evaluators/schema-check@1".into(),
                content_digest: String::new(),
                created_by: String::new(),
                created_at_ms: 0,
            },
            "root",
            10,
        )?;
        let plan = self.db.put_evaluation_plan(
            EvaluationPlan {
                contract_version: EVALUATION_PLAN_CONTRACT.into(),
                plan_version_id: String::new(),
                namespace: namespace.into(),
                plan_id: "document-review".into(),
                version: "1.0.0".into(),
                accepted_subject_profiles: vec!["document/v1".into()],
                nodes: vec![EvaluationPlanNode {
                    metric_objectives: Vec::new(),
                    node_id: "schema".into(),
                    evaluator_definition_id: definition.definition_id,
                    depends_on_node_ids: Vec::new(),
                    input_bindings: vec![EvaluationInputBinding {
                        name: "document".into(),
                        source_kind: INPUT_INVARIANT.into(),
                        schema_id: "schema://document/v1".into(),
                    }],
                    parameters_json: "{}".into(),
                    invariant_version_ids: vec![invariant.object_id],
                    classification: NODE_REQUIRED.into(),
                }],
                reducer: FIXED_REDUCER.into(),
                source_ref: "repo://plans/document-review@1".into(),
                content_digest: String::new(),
                created_by: String::new(),
                created_at_ms: 0,
            },
            "root",
            20,
        )?;
        Ok(plan.content_digest)
    }

    /// Change one object's color after a query so receipt replay can be checked.
    pub fn mutate_object_color(&self, id: &str, color: &str) -> Result<(), String> {
        let mut object = self
            .db
            .get_object(id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "object missing".to_string())?;
        object.properties.insert("color".into(), color.into());
        self.db
            .update_object_with_audit(&object, &self.principal)
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn object_set_descriptor(&self, kind: &str) -> serde_json::Value {
        json!({
            "contractVersion": OBJECT_SET_CONTRACT,
            "namespace": self.namespace,
            "kind": kind,
            "definitionDigest": self.definition_digest,
            "limit": 10
        })
    }
}

fn seed_published_definition(db: &RuntimeDb) -> Result<String, String> {
    let members = ["widget", SECRET_KIND]
        .into_iter()
        .map(|kind| {
            DefinitionMemberInput {
                member_kind: "object_type".into(),
                member_id: kind.into(),
                definition_json: format!(
                    r#"{{"name":"{kind}","properties":{{"name":{{"type":"string"}}}}}}"#
                ),
                member_digest: String::new(),
            }
            .prepare(NAMESPACE)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let revision = prepare_revision(
        NAMESPACE,
        "",
        members.iter().map(|item| DefinitionRevisionMember {
            member_kind: item.member_kind.clone(),
            member_id: item.member_id.clone(),
            member_digest: item.member_digest.clone(),
        }),
        true,
        "root",
        1,
    )?;
    db.seed_published_definition_revision(&revision, &members)?;
    Ok(revision.revision_digest)
}

#[async_trait]
impl NativeSurface for InProcessSurface {
    async fn discover(&self) -> Result<CatalogSnapshot, AdapterError> {
        if let Some(cached) = self.catalog.lock().expect("catalog cache").clone() {
            return Ok(cached);
        }
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
        let snapshot = CatalogSnapshot {
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
        };
        *self.catalog.lock().expect("catalog cache") = Some(snapshot.clone());
        Ok(snapshot)
    }

    async fn refresh_catalog(&self) -> Result<CatalogSnapshot, AdapterError> {
        *self.catalog.lock().expect("catalog cache") = None;
        self.discover().await
    }

    async fn dispatch(
        &self,
        rpc: NativeRpc,
        invocation: SdkInvocation,
    ) -> Result<Value, AdapterError> {
        super::surface::dispatch_native(
            &self.sekai,
            &self.chisei,
            rpc,
            invocation,
            self.experimental_rpcs,
        )
        .await
    }

    fn experimental_tools(&self) -> bool {
        self.experimental_rpcs
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
        gateway_key: None,
        gateway_url: crate::config::DEFAULT_GATEWAY_URL.into(),
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
        actor_chain_enforcement: false,
        principal_requests_per_minute: 60,
        agent_requests_per_minute: 60,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::pb::sekai::SearchRequest;
    use crate::mcp_adapter::handle_message;
    use crate::sekai::embedding_index::{EmbeddingSpec, EmbeddingStore, StoredEmbeddingSpec};
    use chisei_provider::embedding::Embedder;

    /// One axis for cats, one for dogs: "kitten" is near "cat" without
    /// sharing a word with it.
    struct Topic;

    #[async_trait]
    impl Embedder for Topic {
        fn model(&self) -> &str {
            "topic"
        }
        fn model_version(&self) -> &str {
            "v1"
        }
        fn external(&self) -> bool {
            false
        }
        async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
            let axis = |text: &str, words: &[&str]| {
                f32::from(u8::from(words.iter().any(|word| text.contains(word))))
            };
            Ok(texts
                .iter()
                .map(|text| vec![axis(text, &["cat", "kitten"]), axis(text, &["dog"]), 0.01])
                .collect())
        }
    }

    fn topic_route() -> crate::composition::embedding_catch_up::EmbeddingRoute {
        Arc::new(|_| Box::pin(async { Ok(Box::new(Topic) as Box<dyn Embedder>) }))
    }

    /// Notes the session principal may read, plus one another owner holds.
    async fn indexed_surface() -> InProcessSurface {
        let surface = InProcessSurface::synthetic_with(Some(topic_route()))
            .await
            .unwrap();
        for (id, body, owner) in [
            ("note-cat", "cat sleeps", ""),
            ("note-kitten", "kitten naps", ""),
            ("note-hidden", "kitten secret", "someone-else"),
        ] {
            let mut properties = HashMap::from([("body".to_string(), body.to_string())]);
            if !owner.is_empty() {
                properties.insert("owner".into(), owner.into());
            }
            surface
                .db
                .create_object_with_audit(
                    &crate::domain::Object {
                        id: id.into(),
                        kind: "note".into(),
                        name: "note".into(),
                        namespace: NAMESPACE.into(),
                        external_id: String::new(),
                        properties,
                        created: 1,
                        updated: 1,
                    },
                    if owner.is_empty() { PRINCIPAL } else { owner },
                )
                .unwrap();
        }
        surface
            .db
            .put_embedding_spec(&StoredEmbeddingSpec {
                spec: EmbeddingSpec {
                    id: "notes".into(),
                    namespace: NAMESPACE.into(),
                    object_kind: "note".into(),
                    properties: vec!["body".into()],
                    chunk_chars: 1_000,
                    dimension: 3,
                    batch_size: 8,
                },
                model: "topic".into(),
                updated_by: "admin".into(),
                updated_at_ms: 1,
                revision: 0,
            })
            .unwrap();
        let route = topic_route();
        crate::composition::embedding_catch_up::catch_up_stored_specs(
            &surface.db,
            |stored| route(stored),
            &|| 1_000,
        )
        .await
        .unwrap();
        // Text candidates come from the search index the worker keeps.
        for (_, outcome) in
            crate::db::search_index::catch_up_search_pass(&surface.db, "", usize::MAX, &|| 1_000)
                .unwrap()
        {
            outcome.unwrap();
        }
        surface
    }

    /// Fails when any object key names a vector or embedding, or any array
    /// is all numbers.
    fn assert_no_vectors(value: &Value) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map {
                    assert!(
                        !matches!(
                            key.as_str(),
                            "vector" | "vectors" | "embedding" | "embeddings"
                        ),
                        "{key} in {value}"
                    );
                    assert_no_vectors(inner);
                }
            }
            Value::Array(items) => {
                assert!(
                    items.is_empty() || !items.iter().all(Value::is_number),
                    "numeric array in {value}"
                );
                items.iter().for_each(assert_no_vectors);
            }
            _ => {}
        }
    }

    #[tokio::test]
    async fn search_tool_returns_the_rpc_hits_as_references_without_vectors() {
        let surface = indexed_surface().await;
        let called = handle_message(
            &surface,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": crate::mcp_adapter::protocol::SEARCH_TOOL,
                    "arguments": {"operation_id": "op-search-1", "input": {"text": "cat"}}
                }
            }),
        )
        .await
        .unwrap();
        let output = call_output(called).unwrap()["output"].clone();
        let rpc = surface
            .sekai
            .search(with_identity(
                SearchRequest {
                    namespace: NAMESPACE.into(),
                    text: "cat".into(),
                    source: "object".into(),
                    mode: "hybrid".into(),
                    ..Default::default()
                },
                PRINCIPAL,
                NAMESPACE,
            ))
            .await
            .unwrap()
            .into_inner();

        let references = output["references"].as_array().unwrap();
        let ids = references
            .iter()
            .map(|reference| reference["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        // The same hits in the same order as the RPC for this principal; the
        // note another owner holds is absent though its vector is as near.
        assert_eq!(
            ids,
            rpc.hits
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(ids, vec!["note-cat", "note-kitten"]);
        assert_eq!(references[0]["type"], "note");
        assert!(references[0]["score"].as_f64().unwrap() > 0.0);
        assert_eq!(output["fusion_profile"], "late_fusion.rrf/v1");
        assert_no_vectors(&output);
    }

    #[tokio::test]
    async fn search_tool_runs_while_experimental_rpcs_are_disabled() {
        let mut surface = indexed_surface().await;
        surface.experimental_rpcs = false;
        let called = handle_message(
            &surface,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": crate::mcp_adapter::protocol::SEARCH_TOOL,
                    "arguments": {"operation_id": "op-search-3", "input": {"text": "cat"}}
                }
            }),
        )
        .await
        .unwrap();
        // Search is stable (#2243): the experimental gate no longer applies.
        let output = call_output(called).unwrap()["output"].clone();
        assert!(!output["references"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn search_tool_keeps_the_session_namespace() {
        let surface = indexed_surface().await;
        let called = handle_message(
            &surface,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": crate::mcp_adapter::protocol::SEARCH_TOOL,
                    "arguments": {
                        "operation_id": "op-search-2",
                        "input": {"text": "cat", "namespace": FOREIGN_NAMESPACE}
                    }
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(called["error"]["code"], -32602, "{called}");
    }

    async fn call(surface: &InProcessSurface, tool: &str, input: Value) -> Value {
        handle_message(
            surface,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": {"operation_id": format!("op-{tool}"), "input": input}
                }
            }),
        )
        .await
        .unwrap()
    }

    /// The synthetic plane plus a `Visible` class the session may read, a
    /// `Hidden` class only another reader may, and a widget-1 -> widget-2 link.
    async fn discovery_surface() -> InProcessSurface {
        use crate::grpc::pb::sekai::{
            CreateGrantRequest, CreateOntologyClassRequest, OntologyClass,
        };
        let surface = InProcessSurface::synthetic().await.unwrap();
        for (name, reader) in [("Visible", PRINCIPAL), ("Hidden", "other-reader")] {
            surface
                .sekai
                .create_ontology_class(with_identity(
                    CreateOntologyClassRequest {
                        class: Some(OntologyClass {
                            name: name.into(),
                            description: format!("{name} class"),
                            mapped_kind: "widget".into(),
                            ..Default::default()
                        }),
                    },
                    "local",
                    NAMESPACE,
                ))
                .await
                .unwrap();
            surface
                .sekai
                .create_grant(with_identity(
                    CreateGrantRequest {
                        grant: Some(crate::grpc::pb::sekai::Grant {
                            id: format!("class-reader-{name}"),
                            object_id: format!("ontology:class:{name}"),
                            principal: reader.into(),
                            role: "viewer".into(),
                            ..Default::default()
                        }),
                    },
                    "local",
                    NAMESPACE,
                ))
                .await
                .unwrap();
        }
        surface
            .db
            .create_link(&domain::Link {
                id: "widget-pair".into(),
                from_id: OBJECT_ID.into(),
                to_id: PEER_OBJECT_ID.into(),
                relation: "pairs_with".into(),
                created: 1,
            })
            .unwrap();
        surface
    }

    #[tokio::test]
    async fn an_agent_discovers_a_class_and_walks_from_an_object_to_its_neighbors() {
        use crate::mcp_adapter::protocol::{GET_CLASS_TOOL, LIST_CLASSES_TOOL, NEIGHBORHOOD_TOOL};
        let surface = discovery_surface().await;

        let listed = call_output(call(&surface, LIST_CLASSES_TOOL, json!({})).await).unwrap();
        let names = listed["output"]["classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|class| class["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["Visible"], "{listed}");

        let class =
            call_output(call(&surface, GET_CLASS_TOOL, json!({"name": "Visible"})).await).unwrap();
        assert_eq!(class["output"]["class"]["mappedKind"], "widget", "{class}");

        let walked = call_output(
            call(
                &surface,
                NEIGHBORHOOD_TOOL,
                json!({"seed_ids": [OBJECT_ID], "depth": 1}),
            )
            .await,
        )
        .unwrap();
        let ids = walked["output"]["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|object| object["id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        // The foreign object the store also links is outside the session,
        // though the principal may read it over direct gRPC.
        assert_eq!(ids, BTreeSet::from([OBJECT_ID, PEER_OBJECT_ID]), "{walked}");
        assert!(!walked.to_string().contains(FOREIGN_OBJECT_ID), "{walked}");
    }

    #[tokio::test]
    async fn graph_tools_refuse_a_start_object_outside_the_session_namespace() {
        use crate::mcp_adapter::protocol::{GET_LINEAGE_TOOL, NEIGHBORHOOD_TOOL};
        let surface = discovery_surface().await;
        for (tool, input) in [
            (NEIGHBORHOOD_TOOL, json!({"seed_ids": [FOREIGN_OBJECT_ID]})),
            (GET_LINEAGE_TOOL, json!({"object_id": FOREIGN_OBJECT_ID})),
        ] {
            let called = call(&surface, tool, input).await;
            let refused = call_output(called.clone()).unwrap_err();
            assert!(refused.contains("not_found"), "{tool}: {called}");
        }
    }

    #[tokio::test]
    async fn a_hidden_class_is_refused_as_the_rpc_refuses_it() {
        use crate::grpc::pb::sekai::GetOntologyClassRequest;
        let surface = discovery_surface().await;
        let rpc = surface
            .sekai
            .get_ontology_class(with_identity(
                GetOntologyClassRequest {
                    name: "Hidden".into(),
                },
                PRINCIPAL,
                NAMESPACE,
            ))
            .await
            .unwrap_err();
        let called = call(
            &surface,
            crate::mcp_adapter::protocol::GET_CLASS_TOOL,
            json!({"name": "Hidden"}),
        )
        .await;
        let refused = call_output(called.clone()).unwrap_err();
        assert!(!refused.contains("Hidden class"), "{called}");
        let AdapterError::Projected(expected) = status_error(rpc) else {
            unreachable!()
        };
        assert!(
            refused.contains(&format!("\"{}\"", expected.code)),
            "{called}"
        );
    }

    #[tokio::test]
    async fn graph_bounds_beyond_the_rpc_limits_are_refused() {
        use crate::mcp_adapter::protocol::{GET_LINEAGE_TOOL, NEIGHBORHOOD_TOOL};
        let surface = discovery_surface().await;
        let deep = call(
            &surface,
            NEIGHBORHOOD_TOOL,
            json!({"seed_ids": [OBJECT_ID], "depth": 5}),
        )
        .await;
        assert!(call_output(deep.clone()).is_err(), "{deep}");
        let wide = call(
            &surface,
            GET_LINEAGE_TOOL,
            json!({"object_id": OBJECT_ID, "max_nodes": 501}),
        )
        .await;
        assert_eq!(wide["error"]["code"], -32602, "{wide}");
    }

    #[tokio::test]
    async fn stable_discovery_runs_while_experimental_rpcs_are_disabled_and_class_listing_does_not()
    {
        use crate::mcp_adapter::protocol::{
            GET_CLASS_TOOL, GET_LINEAGE_TOOL, LIST_CLASSES_TOOL, NEIGHBORHOOD_TOOL,
        };
        let mut surface = discovery_surface().await;
        surface.experimental_rpcs = false;
        let lineage = call(&surface, GET_LINEAGE_TOOL, json!({"id": OBJECT_ID})).await;
        assert!(call_output(lineage.clone()).is_ok(), "{lineage}");
        // Promoted to stable (#2666); listing waits for paging.
        let class = call(&surface, GET_CLASS_TOOL, json!({"name": "Visible"})).await;
        assert!(call_output(class.clone()).is_ok(), "{class}");
        let neighborhood = call(
            &surface,
            NEIGHBORHOOD_TOOL,
            json!({"seed_ids": [OBJECT_ID]}),
        )
        .await;
        assert!(call_output(neighborhood.clone()).is_ok(), "{neighborhood}");
        let listed = call(&surface, LIST_CLASSES_TOOL, json!({})).await;
        assert!(
            listed.get("error").is_some() || call_output(listed.clone()).is_err(),
            "{listed}"
        );
    }

    /// Opens branch `feature` on the namespace head and stores one edit,
    /// over MCP, returning the parent and the edited head digests.
    async fn edit_branch(surface: &InProcessSurface, member: Value) -> (String, String) {
        use crate::mcp_adapter::protocol::{
            CREATE_DEFINITION_BRANCH_TOOL as BRANCH_CREATE_TOOL,
            EDIT_DEFINITION_BRANCH_TOOL as BRANCH_EDIT_TOOL,
        };
        let created = call(
            surface,
            BRANCH_CREATE_TOOL,
            json!({
                "branchId": "feature",
                "parentRevisionDigest": "",
                "idempotencyKey": "create-feature"
            }),
        )
        .await;
        let parent =
            call_output(created.clone()).unwrap()["output"]["branch"]["headRevisionDigest"]
                .as_str()
                .unwrap_or_else(|| panic!("{created}"))
                .to_string();
        let edited = call(
            surface,
            BRANCH_EDIT_TOOL,
            json!({
                "branchId": "feature",
                "expectedHeadDigest": parent,
                "upserts": [member],
                "removals": [],
                "idempotencyKey": "edit-feature"
            }),
        )
        .await;
        let head = call_output(edited.clone()).unwrap()["output"]["revision"]["revisionDigest"]
            .as_str()
            .unwrap_or_else(|| panic!("{edited}"))
            .to_string();
        (parent, head)
    }

    #[tokio::test]
    async fn rehearsal_tools_are_listed_read_only() {
        use crate::mcp_adapter::protocol::{
            DRY_RUN_AGENT_TOOL, DRY_RUN_CHANGE_BUNDLE_TOOL, PREVIEW_TRANSFORM_TOOL,
            SIMULATE_PLAN_TOOL,
        };
        let surface = InProcessSurface::synthetic().await.unwrap();
        let listed = handle_message(
            &surface,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await
        .unwrap();
        let tools = listed["result"]["tools"].as_array().expect("tools");
        for name in [
            DRY_RUN_AGENT_TOOL,
            SIMULATE_PLAN_TOOL,
            PREVIEW_TRANSFORM_TOOL,
            DRY_RUN_CHANGE_BUNDLE_TOOL,
        ] {
            let tool = tools
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("{name} not listed"));
            assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
        }
    }

    #[tokio::test]
    async fn an_agent_edits_a_branch_and_dry_runs_its_change_bundle_without_writing_facts() {
        use crate::mcp_adapter::protocol::{DRY_RUN_CHANGE_BUNDLE_TOOL, GET_OBJECT_TOOL};
        let surface = InProcessSurface::synthetic().await.unwrap();
        let before = call(&surface, GET_OBJECT_TOOL, json!({"id": OBJECT_ID})).await;
        let before = call_output(before).unwrap()["output"].clone();
        let (parent, head) = edit_branch(
            &surface,
            json!({
                "memberKind": "object_type",
                "memberId": "Ticket",
                "definitionJson": "{\"name\":\"Ticket\",\"properties\":[\"title\"]}",
                "memberDigest": ""
            }),
        )
        .await;
        let report = call(
            &surface,
            DRY_RUN_CHANGE_BUNDLE_TOOL,
            json!({"fromRevisionDigest": parent, "toRevisionDigest": head}),
        )
        .await;
        let report = call_output(report.clone()).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            report["output"]["bundleDigest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:")),
            "{report}"
        );
        let after = call(&surface, GET_OBJECT_TOOL, json!({"id": OBJECT_ID})).await;
        assert_eq!(call_output(after).unwrap()["output"], before);
    }

    #[tokio::test]
    async fn an_agent_dry_run_returns_a_trace_and_submits_no_action() {
        use crate::grpc::pb::sekai::ListActionInstancesRequest;
        use crate::mcp_adapter::protocol::DRY_RUN_AGENT_TOOL;
        use crate::sekai::agent_dry_run::{ProposedAction, ScriptedHost};
        let mut surface = InProcessSurface::synthetic().await.unwrap();
        surface.sekai =
            surface
                .sekai
                .clone()
                .with_dry_run_host(Some(Arc::new(ScriptedHost::proposing(vec![
                    ProposedAction {
                        action_type: ACTION_TYPE.into(),
                        parameters_json: "{}".into(),
                    },
                ]))));
        let definition = json!({
            "contract_version": "sekai.agent-definition/v1",
            "name": "Triage",
            "task_class": "lookup",
            "instructions": "Inspect records.",
            "allowed_action_types": [ACTION_TYPE]
        });
        let (_, head) = edit_branch(
            &surface,
            json!({
                "memberKind": "agent",
                "memberId": "triage",
                "definitionJson": definition.to_string(),
                "memberDigest": ""
            }),
        )
        .await;
        let traced = call(
            &surface,
            DRY_RUN_AGENT_TOOL,
            json!({"revisionDigest": head, "memberId": "triage", "input": "inspect"}),
        )
        .await;
        let trace = call_output(traced.clone()).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(trace["output"]["modelSteps"][0]["route"], "native/scripted");
        assert_eq!(trace["output"]["actions"][0]["actionType"], ACTION_TYPE);
        let instances = surface
            .sekai
            .list_action_instances(with_identity(
                ListActionInstancesRequest {
                    namespace: NAMESPACE.into(),
                    ..Default::default()
                },
                "local",
                NAMESPACE,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(instances.instances.is_empty(), "{instances:?}");
    }

    #[tokio::test]
    async fn a_simulation_the_rpc_refuses_is_refused_the_same_way() {
        use crate::grpc::pb::sekai::SimulatePlanRequest;
        use crate::mcp_adapter::protocol::SIMULATE_PLAN_TOOL;
        let surface = InProcessSurface::synthetic().await.unwrap();
        let rpc = surface
            .sekai
            .simulate_plan(with_identity(
                SimulatePlanRequest {
                    namespace: NAMESPACE.into(),
                    plan_id: "missing".into(),
                    simulation_id: format!("op-{SIMULATE_PLAN_TOOL}"),
                },
                PRINCIPAL,
                NAMESPACE,
            ))
            .await
            .unwrap_err();
        let called = call(&surface, SIMULATE_PLAN_TOOL, json!({"planId": "missing"})).await;
        let refused = call_output(called.clone()).unwrap_err();
        let AdapterError::Projected(expected) = status_error(rpc) else {
            unreachable!()
        };
        assert!(
            refused.contains(&format!("\"{}\"", expected.code)),
            "{called}"
        );
        // The simulation id is the poll handle, so it cannot drift from the call.
        let drifted = call(
            &surface,
            SIMULATE_PLAN_TOOL,
            json!({"planId": "missing", "simulationId": "other"}),
        )
        .await;
        assert_eq!(drifted["error"]["code"], -32602, "{drifted}");
    }

    /// The synthetic plane as `principal`, with datasets `in` and `out`
    /// bound to widget-1 in the session namespace, `foreign` bound to an
    /// object in another one, and transform `t1` filtering `in` into `out`.
    async fn dataset_branch_surface(principal: &str) -> InProcessSurface {
        use crate::sekai::dataset::{ColumnDef, Dataset};
        use crate::sekai::governed_transform::{GovernedTransform, TransformStep};
        let mut surface = InProcessSurface::synthetic().await.unwrap();
        surface.principal = principal.into();
        for (id, object_id) in [
            ("in", OBJECT_ID),
            ("out", OBJECT_ID),
            ("foreign", FOREIGN_OBJECT_ID),
        ] {
            surface
                .db
                .create_dataset(&Dataset {
                    id: id.into(),
                    name: id.into(),
                    columns: ["id", "keep"]
                        .map(|name| ColumnDef {
                            name: name.into(),
                            col_type: "string".into(),
                            classification: "public".into(),
                        })
                        .to_vec(),
                    object_id: object_id.into(),
                    created: 1,
                    partition_keys: Vec::new(),
                })
                .unwrap();
        }
        let row = |id: &str, keep: &str| {
            HashMap::from([
                ("id".to_string(), id.to_string()),
                ("keep".into(), keep.into()),
            ])
        };
        surface
            .db
            .append_rows("in", &[row("1", "yes"), row("2", "no"), row("3", "yes")])
            .unwrap();
        let transform = GovernedTransform {
            contract_version: crate::sekai::governed_transform::CONTRACT_VERSION.into(),
            namespace: NAMESPACE.into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: "yes".into(),
                columns: Vec::new(),
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        surface.db.put_governed_transform(&transform, 1).unwrap();
        surface
    }

    #[tokio::test]
    async fn an_agent_develops_a_transform_on_a_branch_and_proposes_its_merge() {
        use crate::grpc::pb::sekai::MergeDatasetBranchRequest;
        use crate::mcp_adapter::protocol::{
            COMPARE_DATASET_BRANCH_TOOL, CREATE_DATASET_BRANCH_TOOL, PROPOSE_DATASET_MERGE_TOOL,
            RUN_TRANSFORM_ON_BRANCH_TOOL,
        };
        let surface = dataset_branch_surface("local").await;
        let branch = json!({"datasetId": "out", "name": "dev"});
        let created = call(&surface, CREATE_DATASET_BRANCH_TOOL, branch.clone()).await;
        call_output(created).unwrap_or_else(|error| panic!("{error}"));
        let ran = call(
            &surface,
            RUN_TRANSFORM_ON_BRANCH_TOOL,
            json!({"transformId": "t1", "branch": "dev"}),
        )
        .await;
        let ran = call_output(ran).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ran["output"]["rowsWritten"], 2, "{ran}");
        let compared = call(&surface, COMPARE_DATASET_BRANCH_TOOL, branch.clone()).await;
        let compared = call_output(compared).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(compared["output"]["branchRows"], 2, "{compared}");
        let proposed = call(&surface, PROPOSE_DATASET_MERGE_TOOL, branch).await;
        let proposed = call_output(proposed).unwrap_or_else(|error| panic!("{error}"));
        let proposal_id = proposed["output"]["proposal"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{proposed}"))
            .to_string();
        let live = surface
            .db
            .query_rows("out", &crate::sekai::dataset::RowQuery::default())
            .unwrap();
        assert!(live.is_empty(), "live dataset changed before a merge");
        // The proposer cannot merge its own proposal.
        let own = surface
            .sekai
            .merge_dataset_branch(with_identity(
                MergeDatasetBranchRequest {
                    dataset_id: "out".into(),
                    proposal_id,
                    reason: String::new(),
                },
                "local",
                NAMESPACE,
            ))
            .await
            .unwrap_err();
        assert_eq!(own.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn dataset_branch_tools_reach_only_the_session_namespace() {
        use crate::grpc::pb::sekai::CompareDatasetBranchRequest;
        use crate::grpc::pb::sekai::CreateGrantRequest;
        use crate::mcp_adapter::protocol::{
            COMPARE_DATASET_BRANCH_TOOL, CREATE_DATASET_BRANCH_TOOL,
        };
        let surface = dataset_branch_surface("local").await;
        // The principal may write the foreign dataset, so only the session
        // namespace stands between the tool and it.
        surface
            .sekai
            .create_grant(with_identity(
                CreateGrantRequest {
                    grant: Some(crate::grpc::pb::sekai::Grant {
                        id: "foreign-writer".into(),
                        object_id: FOREIGN_OBJECT_ID.into(),
                        principal: "local".into(),
                        role: "editor".into(),
                        ..Default::default()
                    }),
                },
                "local",
                FOREIGN_NAMESPACE,
            ))
            .await
            .unwrap();
        let foreign = json!({"datasetId": "foreign", "name": "dev"});
        let created = call(&surface, CREATE_DATASET_BRANCH_TOOL, foreign.clone()).await;
        let refused = call_output(created.clone()).unwrap_err();
        assert!(refused.contains("\"not_found\""), "{created}");
        // Direct gRPC still reaches it, so the refusal is the session's.
        surface
            .db
            .create_dataset_branch(&crate::sekai::dataset_branch::CreateDatasetBranch {
                dataset_id: "foreign".into(),
                name: "dev".into(),
                actor: "local".into(),
                ..Default::default()
            })
            .unwrap();
        surface
            .sekai
            .compare_dataset_branch(with_identity(
                CompareDatasetBranchRequest {
                    dataset_id: "foreign".into(),
                    name: "dev".into(),
                },
                "local",
                NAMESPACE,
            ))
            .await
            .unwrap();
        let compared = call(&surface, COMPARE_DATASET_BRANCH_TOOL, foreign).await;
        assert!(call_output(compared.clone()).is_err(), "{compared}");
    }

    #[tokio::test]
    async fn a_branch_run_the_rpc_refuses_is_refused_the_same_way() {
        use crate::grpc::pb::sekai::RunGovernedTransformOnBranchRequest;
        use crate::mcp_adapter::protocol::RUN_TRANSFORM_ON_BRANCH_TOOL;
        let surface = dataset_branch_surface(PRINCIPAL).await;
        let rpc = surface
            .sekai
            .run_governed_transform_on_branch(with_identity(
                RunGovernedTransformOnBranchRequest {
                    namespace: NAMESPACE.into(),
                    transform_id: "t1".into(),
                    branch: "dev".into(),
                },
                PRINCIPAL,
                NAMESPACE,
            ))
            .await
            .unwrap_err();
        let called = call(
            &surface,
            RUN_TRANSFORM_ON_BRANCH_TOOL,
            json!({"transformId": "t1", "branch": "dev"}),
        )
        .await;
        let refused = call_output(called.clone()).unwrap_err();
        let AdapterError::Projected(expected) = status_error(rpc) else {
            unreachable!()
        };
        assert!(
            refused.contains(&format!("\"{}\"", expected.code)),
            "{called}"
        );
    }

    /// The synthetic plane with memory installed and instances `line-7`
    /// (the session principal's) and `line-8` (another principal's) in the
    /// session namespace.
    async fn memory_surface() -> InProcessSurface {
        use crate::sekai::site_agent_memory as memory;
        let surface = InProcessSurface::synthetic().await.unwrap();
        memory::install(&surface.db, NAMESPACE, "root", 1).unwrap();
        for (id, principal) in [("line-7", PRINCIPAL), ("line-8", "svc-line-8")] {
            surface
                .db
                .create_object(&domain::Object {
                    id: id.into(),
                    kind: crate::sekai::site_agent_instance::KIND.into(),
                    name: id.into(),
                    namespace: NAMESPACE.into(),
                    external_id: String::new(),
                    properties: HashMap::from([("principal_id".into(), principal.into())]),
                    created: 1,
                    updated: 1,
                })
                .unwrap();
        }
        surface
    }

    #[tokio::test]
    async fn an_instance_writes_memory_through_the_action_and_reads_it_back() {
        use crate::grpc::pb::sekai::ListSiteAgentWorkingMemoryRequest;
        use crate::mcp_adapter::protocol::LIST_WORKING_MEMORY_TOOL;
        use crate::sekai::site_agent_memory as memory;
        let surface = memory_surface().await;
        let submitted = call(
            &surface,
            "sekai.actions.submit",
            json!({
                "type_id": memory::ACTION_CREATE,
                "version": memory::ACTION_VERSION,
                "parameters_json": {
                    "object_id": "note-1",
                    "instance_id": "line-7",
                    "content": "the press on line 7 runs hot"
                },
                "idempotency_key": "memory-1"
            }),
        )
        .await;
        assert!(submitted.get("error").is_none(), "{submitted}");
        call_output(submitted).unwrap_or_else(|error| panic!("{error}"));
        let read = call(
            &surface,
            LIST_WORKING_MEMORY_TOOL,
            json!({"instance_id": "line-7", "limit": 10}),
        )
        .await;
        assert!(read.get("error").is_none(), "{read}");
        let read = call_output(read).unwrap_or_else(|error| panic!("{error}"));
        let items = read["output"]["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{read}"));
        assert_eq!(items.len(), 1, "{read}");
        assert_eq!(items[0]["id"], "note-1");
        // The tool returns exactly what the RPC returns to the same caller,
        // so redaction cannot differ.
        let rpc = surface
            .sekai
            .list_site_agent_working_memory(with_identity(
                ListSiteAgentWorkingMemoryRequest {
                    namespace: NAMESPACE.into(),
                    instance_id: "line-7".into(),
                    turn_id: String::new(),
                    limit: 10,
                    page_token: String::new(),
                },
                PRINCIPAL,
                NAMESPACE,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(read["output"], serde_json::to_value(rpc).unwrap());
    }

    #[tokio::test]
    async fn an_instance_cannot_read_another_instances_memory_or_an_unbounded_page() {
        use crate::mcp_adapter::protocol::{LIST_WORKING_MEMORY_TOOL, MAX_WORKING_MEMORY_PAGE};
        let surface = memory_surface().await;
        let other = call(
            &surface,
            LIST_WORKING_MEMORY_TOOL,
            json!({"instance_id": "line-8"}),
        )
        .await;
        assert!(other.get("error").is_none(), "{other}");
        let refused = call_output(other.clone()).unwrap_err();
        assert!(refused.contains("\"not_found\""), "{other}");
        let unbounded = call(
            &surface,
            LIST_WORKING_MEMORY_TOOL,
            json!({"instance_id": "line-7", "limit": MAX_WORKING_MEMORY_PAGE + 1}),
        )
        .await;
        assert_eq!(unbounded["error"]["code"], -32602, "{unbounded}");
    }

    /// The synthetic plane plus `account-1`, whose `ssn` is `sensitive`, read
    /// by an object admin so only egress decides what reaches it, and one
    /// configured gateway `edge` whose policy the test loads.
    async fn account_surface() -> (
        InProcessSurface,
        Arc<crate::composition::gateway_egress_policy::EgressPolicies>,
    ) {
        let mut surface = InProcessSurface::synthetic().await.unwrap();
        let mut ssn = property("ssn", false);
        ssn.classification = "sensitive".into();
        surface
            .sekai
            .create_schema_type(with_identity(
                CreateSchemaTypeRequest {
                    r#type: Some(ObjectType {
                        kind: "account".into(),
                        description: String::new(),
                        is_builtin: false,
                        implements: vec![],
                        properties: vec![property("region", false), ssn],
                    }),
                },
                PRINCIPAL,
                NAMESPACE,
            ))
            .await
            .unwrap();
        surface
            .db
            .create_object_with_audit(
                &domain::Object {
                    id: "account-1".into(),
                    kind: "account".into(),
                    name: "account-1".into(),
                    namespace: NAMESPACE.into(),
                    external_id: String::new(),
                    properties: HashMap::from([
                        ("region".into(), "eu".into()),
                        ("ssn".into(), "123-45-6789".into()),
                    ]),
                    created: 1,
                    updated: 1,
                },
                PRINCIPAL,
            )
            .unwrap();
        surface
            .sekai
            .create_grant(with_identity(
                crate::grpc::pb::sekai::CreateGrantRequest {
                    grant: Some(crate::grpc::pb::sekai::Grant {
                        id: "account-admin".into(),
                        object_id: "account-1".into(),
                        principal: PRINCIPAL.into(),
                        role: "admin".into(),
                        ..Default::default()
                    }),
                },
                "local",
                NAMESPACE,
            ))
            .await
            .unwrap();
        let policies =
            crate::composition::gateway_egress_policy::EgressPolicies::new(["edge".to_string()]);
        surface.sekai.set_egress_policies(policies.clone());
        (surface, policies)
    }

    /// `edge`'s published policy with these gateway principals, each
    /// `(name, provider)`: `openai` takes only public data, `ollama` all, and
    /// `anthropic` has no egress rule, so it takes nothing.
    fn load_edge_policy(
        policies: &crate::composition::gateway_egress_policy::EgressPolicies,
        principals: &[(&str, &str)],
    ) {
        let principals = principals
            .iter()
            .map(|(name, provider)| {
                json!({"name": name, "routes": [{"provider": provider, "models": ["*"]}]})
            })
            .collect::<Vec<_>>();
        let published = json!({
            "format": "chisei.gateway-policy/v1",
            "generation": 1,
            "principals": principals,
            "egress": [
                {"provider": "openai", "data_classes": ["public"]},
                {"provider": "ollama", "data_classes": ["public", "internal", "sensitive"]},
            ],
        });
        policies
            .load("edge", published.to_string().as_bytes())
            .unwrap();
    }

    /// #2699: over MCP, a `sensitive` property is withheld from a reader
    /// whose egress reaches a hosted provider that may not receive it, and
    /// from a reader no gateway principal maps to, and returned to a reader
    /// whose only route is local.
    #[tokio::test]
    async fn a_sensitive_property_reaches_only_a_reader_whose_egress_may_receive_it() {
        use crate::mcp_adapter::protocol::GET_OBJECT_TOOL;
        let (surface, policies) = account_surface().await;

        for (principals, reason) in [
            (&[(PRINCIPAL, "openai")][..], "egress_not_allowed"),
            (
                &[("other", "ollama"), ("another", "openai")][..],
                "egress_unknown",
            ),
        ] {
            load_edge_policy(&policies, principals);
            let read =
                call_output(call(&surface, GET_OBJECT_TOOL, json!({"id": "account-1"})).await)
                    .unwrap();
            let output = &read["output"];
            assert_eq!(output["object"]["properties"]["region"], "eu", "{read}");
            assert!(!read.to_string().contains("123-45-6789"), "{read}");
            assert_eq!(
                output["withheld_properties"],
                json!([{"kind": "account", "property": "ssn", "reason": reason}]),
                "{read}"
            );
        }

        load_edge_policy(&policies, &[(PRINCIPAL, "ollama")]);
        let read =
            call_output(call(&surface, GET_OBJECT_TOOL, json!({"id": "account-1"})).await).unwrap();
        assert_eq!(
            read["output"]["object"]["properties"]["ssn"], "123-45-6789",
            "{read}"
        );
        assert_eq!(read["output"]["withheld_properties"], json!([]), "{read}");
    }

    /// #2699: a withheld value takes no part in a query. A filter on it is
    /// refused, and Search does not match it.
    #[tokio::test]
    async fn a_withheld_property_is_not_filtered_on_or_searched() {
        use crate::grpc::pb::sekai::{ListFilter, ListObjectsRequest, PropertyFilter};
        let (surface, policies) = account_surface().await;
        for (_, outcome) in
            crate::db::search_index::catch_up_search_pass(&surface.db, "", usize::MAX, &|| 1_000)
                .unwrap()
        {
            outcome.unwrap();
        }

        // A public property, so only egress can refuse the filter.
        load_edge_policy(&policies, &[(PRINCIPAL, "anthropic")]);
        let filtered = surface
            .sekai
            .list_objects(with_identity(
                ListObjectsRequest {
                    filter: Some(ListFilter {
                        kind: "account".into(),
                        namespace: NAMESPACE.into(),
                        property_filters: vec![PropertyFilter {
                            key: "region".into(),
                            op: "eq".into(),
                            value: "eu".into(),
                        }],
                        ..Default::default()
                    }),
                    page_token: String::new(),
                },
                PRINCIPAL,
                NAMESPACE,
            ))
            .await
            .unwrap_err();
        assert_eq!(filtered.code(), tonic::Code::PermissionDenied, "{filtered}");

        let search = || async {
            surface
                .sekai
                .search(with_identity(
                    SearchRequest {
                        namespace: NAMESPACE.into(),
                        text: "123-45-6789".into(),
                        source: "object".into(),
                        ..Default::default()
                    },
                    PRINCIPAL,
                    NAMESPACE,
                ))
                .await
                .unwrap()
                .into_inner()
        };
        load_edge_policy(&policies, &[(PRINCIPAL, "ollama")]);
        assert_eq!(
            search().await.hits.len(),
            1,
            "a local reader finds the value"
        );
        load_edge_policy(&policies, &[(PRINCIPAL, "openai")]);
        let searched = search().await;
        assert!(searched.hits.is_empty(), "{searched:?}");
    }
}
