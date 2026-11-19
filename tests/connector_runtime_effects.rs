//! External effects through the connector runtime (ADR 0148), against a
//! serving plane with Chisei: an admitted Action's permit-bound change is
//! claimed by the runtime its Source places, redeemed once, applied and
//! acknowledged. A runtime killed after the write leaves the effect to a
//! takeover that cannot redeem again and records `outcome_unknown`; the
//! kill switch stops a claimed effect before anything is applied; a
//! runtime the Source does not place never sees the work.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sekai_chisei::config::Config;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::domain::Object;
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::pb::chisei::chisei_service_server::{ChiseiService, ChiseiServiceServer};
use sekai_chisei::grpc::pb::chisei::{
    AuthorizeExternalActionRequest, ExternalActionRequest, SetExternalActionPolicyRequest,
};
use sekai_chisei::grpc::pb::sekai::sekai_service_server::{SekaiService, SekaiServiceServer};
use sekai_chisei::grpc::pb::sekai::{
    EvidenceSchemaDefinition, GetActionEffectRequest, GovernedActionType, ListActionEffectsRequest,
    PutGovernedActionTypeRequest, RegisterEvidenceSchemaRequest, SubmitActionInstanceRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::action_policy::ActionPolicy;
use sekai_chisei::sekai::evidence::{EvidenceClassification, EvidenceIntent};
use sekai_chisei::sekai::evidence_store::EvidenceProducerCapability;
use sekai_chisei::sekai::execution_evidence::{EXECUTION_EVIDENCE_SCHEMA, EXECUTION_EVIDENCE_TYPE};
use sekai_chisei::sekai::security::Role;
use sekai_chisei::sekai::source::{self, PutSource, SourceSpec};
use sekai_client::ClientConfig;
use sekai_connector_runtime::effect::HOST_CAPABILITY;
use sekai_connector_runtime::{
    Connectors, CredentialBindings, Effected, Ran, Runtime, RuntimeOptions, SyncFailure,
};
use sekai_source_sdk::{
    ConfigValue, Connector, ConnectorFailure, RELATIONAL_CONNECTOR, RecordChange, SourceConfig,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Request;
use tonic::metadata::MetadataValue;

const NS: &str = "ops";
/// The operator, and the principal the runtime authenticates as: the
/// permits' bound executor.
const PRINCIPAL: &str = "local";
const LEASE: Duration = Duration::from_millis(300);
const RESOURCE: &str = "orders-db:orders#1";
const ACTION_TYPE: &str = "orders.row.write";
/// The kind the Source projects order rows as.
const KIND: &str = "Order";

fn config() -> Config {
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
        scoring_model: "unused".into(),
        scoring_batch_size: 16,
        default_data_class: "unclassified".into(),
        safe_egress_providers: vec![],
        gateway_provided_providers: vec![],
        gateway_key: None,
        gateway_url: sekai_chisei::config::DEFAULT_GATEWAY_URL.into(),
        routing_endpoint_allowlist: vec![],
        routing_credential_refs: vec![],
        gateway_receipt_principals: vec![],
        leak_review_model: None,
        tls_cert: None,
        tls_key: None,
        allow_plaintext: false,
        insecure: true,
        permit_signing_key: Some("07".repeat(32)),
        permit_issuer: "issuer:test".into(),
        permit_key_id: "key-1".into(),
        governed_subject_provenance_signing_key: Some("09".repeat(32)),
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
        principal_requests_per_minute: 600,
        agent_requests_per_minute: 600,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn with_principal<T>(payload: T) -> Request<T> {
    let mut request = Request::new(payload);
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static(PRINCIPAL));
    request
}

/// Sekai and Chisei on one ephemeral port, with a relational Source
/// `orders` placed in `zone=eu`.
struct Plane {
    db: Arc<RuntimeDb>,
    sekai: SekaiServiceImpl,
    chisei: Arc<ChiseiServiceImpl>,
    endpoint: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Plane {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn plane() -> Plane {
    let db = Arc::new(RuntimeDb::memory());
    db.ensure_team_namespace(NS, PRINCIPAL, Role::Admin, PRINCIPAL)
        .unwrap();
    db.upsert_action_policy(&ActionPolicy::allow_all("agent:local"))
        .unwrap();
    db.upsert_evidence_producer(
        &EvidenceProducerCapability {
            producer_identity: PRINCIPAL.into(),
            config_version: 1,
            source_types: vec!["host_executor".into()],
            source_instances: vec![format!("{PRINCIPAL}:external-effect")],
            namespaces: vec![NS.into()],
            evidence_types: vec![EXECUTION_EVIDENCE_TYPE.into()],
            target_kinds: vec![KIND.into()],
            classification_ceiling: EvidenceClassification::Internal,
            allowed_intents: vec![EvidenceIntent::Upsert],
            allow_operation_attachment: true,
            replay_window_ms: 60_000,
            max_clock_skew_ms: 60_000,
            max_payload_bytes: 64 * 1024,
            max_relationships: 8,
            rate_limit_per_minute: 100,
            max_retained_submissions: 100,
            revoked: false,
        },
        now_ms(),
    )
    .unwrap();
    // The row as the Source projected it; execution evidence attaches here.
    db.create_object(&Object {
        id: "order-1".into(),
        kind: KIND.into(),
        name: "order 1".into(),
        namespace: NS.into(),
        external_id: RESOURCE.into(),
        properties: Default::default(),
        created: 1,
        updated: 1,
    })
    .unwrap();
    source::put(
        &db,
        &PutSource {
            namespace: NS.into(),
            source_id: "orders".into(),
            source: "orders-db".into(),
            source_instance: "orders".into(),
            spec: SourceSpec {
                connector_type: "relational".into(),
                connector_version: "1".into(),
                config: SourceConfig::from([
                    (
                        "endpoint".into(),
                        ConfigValue::Text("db.internal:5432".into()),
                    ),
                    ("database".into(), ConfigValue::Text("orders".into())),
                    ("user".into(), ConfigValue::Text("writer".into())),
                ]),
                credential_ref: "ops/db".into(),
                egress: vec!["db.internal:5432".into()],
                placement: BTreeMap::from([("zone".into(), "eu".into())]),
                every_ms: 60_000,
                owner: "team".into(),
                markings: Vec::new(),
                certification_id: String::new(),
            },
            expected_revision: 0,
            now_ms: 1,
        },
    )
    .unwrap();
    let store = SekaiStore::from_shared_runtime(db.clone());
    let sekai = SekaiServiceImpl::new(store.clone());
    let chisei = ChiseiServiceImpl::new(
        sekai_chisei::chisei_store::ChiseiStore::from_shared_runtime(db.clone()),
        config(),
    )
    .with_sekai_facts(sekai_chisei::chisei::sekai_facts::SekaiFacts::in_process(
        store,
    ))
    .map(Arc::new)
    .unwrap();
    sekai
        .register_evidence_schema(with_principal(RegisterEvidenceSchemaRequest {
            definition: Some(EvidenceSchemaDefinition {
                schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
                schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
                evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
                compatible_versions: vec![],
            }),
        }))
        .await
        .unwrap();
    sekai
        .put_governed_action_type(with_principal(PutGovernedActionTypeRequest {
            r#type: Some(GovernedActionType {
                namespace: NS.into(),
                type_id: ACTION_TYPE.into(),
                version: "1".into(),
                description: "Permit-backed row write".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"permit_id":{"type":"string"},"source_id":{"type":"string"},"record_kind":{"type":"string"},"change":{"type":"string"},"permit":{"type":"string"}},"required":["permit_id","source_id","record_kind","change","permit"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec!["external_mutate".into()],
                created_by: PRINCIPAL.into(),
                enabled: true,
                ..Default::default()
            }),
            request_id: "put-type".into(),
        }))
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let services = (
        SekaiServiceServer::new(sekai.clone()),
        ChiseiServiceServer::from_arc(chisei.clone()),
    );
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(services.0)
            .add_service(services.1)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    Plane {
        db,
        sekai,
        chisei,
        endpoint,
        stop: Some(stop),
    }
}

impl Plane {
    /// Authorizes setting order 1's status, decided at version `10`, for
    /// `invocations` invocations, and admits the Action that carries the
    /// permit. Returns the effect id.
    async fn admit(&self, invocations: u32) -> String {
        let change = RecordChange {
            idempotency_key: String::new(),
            key: "1".into(),
            expected_version: "10".into(),
            change: BTreeMap::from([("status".into(), "shipped".into())]),
        };
        let permit = self
            .chisei
            .authorize_external_action(with_principal(AuthorizeExternalActionRequest {
                request: Some(ExternalActionRequest {
                    version: "external-action.request/v1".into(),
                    operation_id: "op-ship-1".into(),
                    attempt_id: "op-ship-1-attempt".into(),
                    request_id: "op-ship-1-request".into(),
                    actor: PRINCIPAL.into(),
                    namespace: NS.into(),
                    requesting_harness: "harness:orders".into(),
                    intended_executor: PRINCIPAL.into(),
                    action_type: "orders.row.write/v1".into(),
                    parameter_schema: "orders.row.write.params/v1".into(),
                    canonical_arguments_digest: change.arguments_digest(RESOURCE),
                    target_selectors: vec![format!("project:{NS}/{RESOURCE}")],
                    immutable_preconditions: [("record_version".to_string(), "10".to_string())]
                        .into(),
                    risk_class: "write".into(),
                    expected_effects: vec!["record_updated".into()],
                    requested_invocation_count: invocations,
                    deadline_ms: now_ms() + 3_600_000,
                    estimated_volume: 1,
                    affected_resource_count: 1,
                    rollback_capability: "restore_record_version".into(),
                    required_host_capabilities: vec![HOST_CAPABILITY.into()],
                    idempotency_key: "ship-1".into(),
                    policy_project: NS.into(),
                    ..Default::default()
                }),
                offline: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .permit
            .expect("the change is authorized");
        let instance = self
            .sekai
            .submit_action_instance(with_principal(SubmitActionInstanceRequest {
                namespace: NS.into(),
                type_id: ACTION_TYPE.into(),
                version: "1".into(),
                parameters_json: serde_json::json!({
                    "permit_id": permit.permit_id,
                    "source_id": RESOURCE,
                    "record_kind": KIND,
                    "change": serde_json::to_string(&change.change).unwrap(),
                    "permit": serde_json::to_string(&permit).unwrap(),
                })
                .to_string(),
                idempotency_key: "ship-1".into(),
                request_id: permit.operation_id.clone(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .instance
            .unwrap();
        assert_eq!(instance.status, "admitted");
        let effects = self
            .sekai
            .list_action_effects(with_principal(ListActionEffectsRequest {
                instance_id: instance.instance_id,
                kind: "external_mutate".into(),
                limit: 8,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner()
            .effects;
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].status, "pending");
        effects[0].effect_id.clone()
    }

    async fn status_of(&self, effect_id: &str) -> String {
        self.sekai
            .get_action_effect(with_principal(GetActionEffectRequest {
                effect_id: effect_id.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .effect
            .unwrap()
            .status
    }

    /// Stops redemption of every permit for the action type.
    async fn kill(&self) {
        self.chisei
            .set_external_action_policy(with_principal(SetExternalActionPolicyRequest {
                operation: "kill_switch".into(),
                scope_kind: "action_type".into(),
                scope_value: "orders.row.write/v1".into(),
                enabled: true,
                reason: "incident".into(),
                ..Default::default()
            }))
            .await
            .unwrap();
    }
}

/// The database password, bound for the Source's credential handle.
fn bindings(dir: &std::path::Path) -> CredentialBindings {
    let password = dir.join("password");
    std::fs::write(&password, "p").unwrap();
    serde_json::from_value(serde_json::json!({
        "ops/db": {
            "namespaces": [NS],
            "destinations": ["db.internal:5432"],
            "slots": { "password": { "file": password } }
        }
    }))
    .unwrap()
}

/// A relational connector that counts the changes it writes. With
/// `hang`, a write is followed by a hang, as a process killed between the
/// write and the acknowledge.
struct Rows {
    writes: Arc<AtomicUsize>,
    hang: bool,
}

impl Connector for Rows {
    fn apply(&mut self, change: &RecordChange) -> Result<String, ConnectorFailure> {
        assert_eq!(
            (change.key.as_str(), change.expected_version.as_str()),
            ("1", "10")
        );
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.hang {
            // Long past the lease; short enough to let the test end.
            std::thread::sleep(LEASE * 10);
        }
        Ok("11".into())
    }
}

async fn runtime(
    plane: &Plane,
    id: &str,
    zone: &str,
    writes: &Arc<AtomicUsize>,
    hang: bool,
    dir: &std::path::Path,
) -> Runtime {
    let writes = writes.clone();
    let connectors = Connectors::default().with(&RELATIONAL_CONNECTOR, move |_| {
        Ok(Box::new(Rows {
            writes: writes.clone(),
            hang,
        }))
    });
    let runtime = Runtime::connect(
        ClientConfig::new(&plane.endpoint, PRINCIPAL).with_default_timeout(Duration::from_secs(5)),
        &[NS.to_string()],
        RuntimeOptions {
            runtime_id: id.into(),
            labels: BTreeMap::from([("zone".into(), zone.into())]),
            lease: LEASE,
        },
        bindings(dir),
        connectors,
    )
    .await
    .unwrap();
    runtime.register().await.unwrap();
    runtime
}

#[tokio::test(flavor = "multi_thread")]
async fn an_effect_is_redeemed_applied_and_acknowledged_once() {
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    let writes = Arc::new(AtomicUsize::new(0));
    let effect_id = plane.admit(1).await;

    // A runtime the Source does not place never sees the work.
    let elsewhere = runtime(&plane, "us-1", "us", &writes, false, dir.path()).await;
    assert!(elsewhere.claim_effect(0).await.unwrap().is_none());

    let eu = runtime(&plane, "eu-1", "eu", &writes, false, dir.path()).await;
    let ran = eu.pass().await.unwrap();
    assert_eq!(
        ran,
        [Ran::Effect {
            effect_id: effect_id.clone(),
            outcome: Effected::Completed {
                version: "11".into()
            },
        }]
    );
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    assert_eq!(plane.status_of(&effect_id).await, "completed");
    // The terminal execution evidence was admitted: no redemption is left
    // without it, however late the check.
    assert!(
        plane
            .db
            .reconcile_missing_execution_evidence(i64::MAX)
            .unwrap()
            .is_empty()
    );
    // Acknowledged work is not handed out again.
    assert!(eu.pass().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runtime_killed_after_the_write_leaves_outcome_unknown_and_no_second_write() {
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    let writes = Arc::new(AtomicUsize::new(0));
    let effect_id = plane.admit(1).await;

    let doomed = runtime(&plane, "eu-1", "eu", &writes, true, dir.path()).await;
    let work = doomed.claim_effect(0).await.unwrap().unwrap();
    let running = tokio::spawn(async move { doomed.apply(0, work).await });
    while writes.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Killed after the write: no heartbeat, no acknowledge.
    running.abort();
    tokio::time::sleep(LEASE * 2).await;

    let takeover = runtime(&plane, "eu-2", "eu", &writes, false, dir.path()).await;
    let ran = takeover.pass().await.unwrap();
    assert_eq!(
        ran,
        [Ran::Effect {
            effect_id: effect_id.clone(),
            outcome: Effected::OutcomeUnknown,
        }]
    );
    assert_eq!(writes.load(Ordering::SeqCst), 1, "written once");
    assert_eq!(plane.status_of(&effect_id).await, "outcome_unknown");
    // Never retried.
    tokio::time::sleep(LEASE * 2).await;
    assert!(takeover.pass().await.unwrap().is_empty());
    assert_eq!(writes.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_kill_switch_stops_a_claimed_effect_before_it_is_applied() {
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    let writes = Arc::new(AtomicUsize::new(0));
    let effect_id = plane.admit(1).await;

    let eu = runtime(&plane, "eu-1", "eu", &writes, false, dir.path()).await;
    let work = eu.claim_effect(0).await.unwrap().unwrap();
    plane.kill().await;
    assert_eq!(
        eu.apply(0, work).await.unwrap(),
        Ran::Effect {
            effect_id: effect_id.clone(),
            outcome: Effected::Failed(SyncFailure::Refused),
        }
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(plane.status_of(&effect_id).await, "failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_permit_that_allows_a_second_invocation_is_never_redeemed() {
    let plane = plane().await;
    let dir = tempfile::tempdir().unwrap();
    let writes = Arc::new(AtomicUsize::new(0));
    // A takeover could redeem such a permit again and write twice.
    let effect_id = plane.admit(2).await;

    let eu = runtime(&plane, "eu-1", "eu", &writes, false, dir.path()).await;
    assert_eq!(
        eu.pass().await.unwrap(),
        [Ran::Effect {
            effect_id: effect_id.clone(),
            outcome: Effected::Failed(SyncFailure::Invalid),
        }]
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(plane.status_of(&effect_id).await, "failed");
}
