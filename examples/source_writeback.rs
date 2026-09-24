//! Deterministic source → object → governed Action → write-back → receipt fixture.
//!
//! The runner starts an isolated SQLite control plane and a loopback GitHub
//! Issue/executor fixture. The fixture keeps its record version and applied-effect
//! counter outside the control-plane database. It uses the admitted GitHub Issue
//! profile; the Issue title describes a service incident without adding an
//! Incident source type.
//!
//! ```bash
//! cargo run --locked --example source_writeback
//! cargo test --locked --test source_writeback_example
//! ```

#[allow(dead_code)]
#[path = "../adapters/github_object_sync.rs"]
mod github_object_sync;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use ed25519_dalek::VerifyingKey;

use sekai_chisei::chisei::external_permit::{HostContext, Permit, signing_key_from_hex};
use sekai_chisei::chisei::receipt::OPERATION_RECEIPT_VERSION;
use sekai_chisei::config::Config;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::pb::chisei::chisei_service_server::ChiseiService;
use sekai_chisei::grpc::pb::chisei::{
    AuthorizeExternalActionRequest, ExternalActionPermit, ExternalActionRequest,
    GetOperationReceiptRequest, RedeemExternalActionPermitRequest, TransitionExternalActionRequest,
};
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    ApplySourceBatchRequest, EvidenceCausality, EvidenceEnvelope, EvidenceSchemaDefinition,
    GetActionInstanceRequest, GetObjectRequest, GetSourceSyncStateRequest, GovernedActionType,
    ListActionEffectsRequest, PutGovernedActionTypeRequest, RegisterEvidenceSchemaRequest,
    SourceBatch, SourceRecord, SubmitActionInstanceRequest, SubmitEvidenceRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::action_policy::ActionPolicy;
use sekai_chisei::sekai::evidence::{
    EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceIntent, EvidenceSignal,
};
use sekai_chisei::sekai::evidence_store::{EvidenceProducerCapability, canonical_content_digest};
use sekai_chisei::sekai::execution_evidence::{
    EXECUTION_EVIDENCE_SCHEMA, EXECUTION_EVIDENCE_TYPE, ExecutionEvidence, ExecutionLifecycleState,
    verify_for_executor,
};
use sekai_chisei::sekai::governed_action_type::EFFECT_KIND_EXTERNAL_MUTATE;
use sekai_chisei::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_VERSION, SOURCE_GITHUB,
    SourceBatch as DomainBatch, object_id_for, source_id as compose_source_id,
};
use sekai_chisei::sekai::security::Role;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tonic::Request;
use tonic::metadata::MetadataValue;

pub const CONTRACT_VERSION: &str = "example.source-writeback/v1";
pub const GITHUB_TYPE_DIGEST: &str = GITHUB_OBJECT_SYNC_TYPE_DIGEST;
const NAMESPACE: &str = "ops";
const OPERATOR: &str = "local";
const CONNECTOR: &str = "connector/ops";
const EXECUTOR: &str = "executor:http";
const HARNESS: &str = "harness:loopback";
const SOURCE_INSTANCE: &str = "acme/ops";
const ISSUE_NUMBER: u64 = 42;
const ACTION_TYPE_ID: &str = "source.writeback";
const ACTION_TYPE_VERSION: &str = "1";
const EXTERNAL_ACTION_TYPE: &str = "source.writeback.write/v1";
const ACTION_PARAMETER_SCHEMA: &str = "source.writeback.params/v1";
const HOST_CAPABILITY: &str = "conditional_request";
const EXECUTION_ID: &str = "exec-writeback-success";
const PERMIT_SEED: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const PERMIT_ISSUER: &str = "issuer:test";
const PERMIT_KEY_ID: &str = "key-1";
const SEED_ISSUE: &str = include_str!("source-writeback/incident-issue.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
struct FixtureRecord {
    repository: String,
    kind: String,
    number: u64,
    revision: String,
    title: String,
    state: String,
    deleted: bool,
    observed_at_ms: i64,
    properties: BTreeMap<String, String>,
    #[serde(default)]
    applied_effect_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub contract_version: String,
    pub source_identity: String,
    pub object_id: String,
    pub type_digest: String,
    pub action_instance_id: String,
    pub permit_id: String,
    pub execution_id: String,
    pub receipt_operation_id: String,
    pub execution_evidence_id: String,
    pub readback_source_version: String,
    pub applied_effect_count: u64,
    pub stale_precondition_blocked: bool,
    pub denied_authorization_blocked: bool,
    pub identical_intent_replayed: bool,
    pub changed_intent_rejected: bool,
    pub response_loss_outcome: String,
    pub recovered_without_repeat: bool,
    pub restart_preserved_identity: bool,
    pub fixture_effect_count_after_restart: u64,
}

#[derive(Clone)]
struct FixtureHandle {
    path: PathBuf,
    state: Arc<Mutex<FixtureRecord>>,
}

impl FixtureHandle {
    fn create(root: &Path) -> Result<Self, String> {
        let path = root.join("source-fixture").join("issue.json");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut record: FixtureRecord = serde_json::from_str(SEED_ISSUE)
            .map_err(|error| format!("invalid incident issue fixture: {error}"))?;
        record.applied_effect_count = 0;
        fs::write(
            &path,
            serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(record)),
        })
    }

    fn load(path: PathBuf) -> Result<Self, String> {
        let record: FixtureRecord =
            serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
                .map_err(|error| format!("fixture store is unreadable: {error}"))?;
        Ok(Self {
            path,
            state: Arc::new(Mutex::new(record)),
        })
    }

    fn snapshot(&self) -> Result<FixtureRecord, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "fixture lock poisoned".to_string())?
            .clone())
    }

    fn persist_locked(path: &Path, record: &FixtureRecord) -> Result<(), String> {
        let temporary = path.with_extension("json.tmp");
        fs::write(
            &temporary,
            serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        fs::rename(temporary, path).map_err(|error| error.to_string())
    }

    fn persist(&self, record: &FixtureRecord) -> Result<(), String> {
        Self::persist_locked(&self.path, record)
    }

    fn bump_revision(
        &self,
        revision: &str,
        title: &str,
        observed_at_ms: i64,
    ) -> Result<(), String> {
        let mut record = self
            .state
            .lock()
            .map_err(|_| "fixture lock poisoned".to_string())?;
        record.revision = revision.into();
        record.title = title.into();
        record.observed_at_ms = observed_at_ms;
        self.persist(&record)
    }

    fn conditional_update(
        &self,
        if_match: &str,
        title: &str,
        observed_at_ms: i64,
        lose_response: bool,
    ) -> Result<Option<String>, String> {
        let mut record = self
            .state
            .lock()
            .map_err(|_| "fixture lock poisoned".to_string())?;
        if record.revision != if_match {
            return Err("precondition_failed".into());
        }
        let next = next_revision(&record.revision);
        record.revision = next.clone();
        record.title = title.into();
        record.observed_at_ms = observed_at_ms;
        record.applied_effect_count = record
            .applied_effect_count
            .checked_add(1)
            .ok_or_else(|| "fixture effect counter overflow".to_string())?;
        Self::persist_locked(&self.path, &record)?;
        if lose_response {
            return Ok(None);
        }
        Ok(Some(next))
    }
}

#[derive(Clone)]
struct HttpState {
    fixture: FixtureHandle,
}

#[derive(Deserialize)]
struct PatchIssue {
    title: String,
}

fn next_revision(current: &str) -> String {
    if let Some(rest) = current.strip_prefix("issue-42-v")
        && let Ok(version) = rest.parse::<u64>()
    {
        return format!("issue-42-v{}", version + 1);
    }
    format!("{current}-next")
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn isolated_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "sekai-source-writeback-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ))
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
        permit_signing_key: Some(PERMIT_SEED.into()),
        permit_issuer: PERMIT_ISSUER.into(),
        permit_key_id: PERMIT_KEY_ID.into(),
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
    }
}

fn with_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).expect("principal is a valid metadata value"),
    );
    request
}

fn source_identity() -> String {
    compose_source_id("github", SOURCE_INSTANCE, &ISSUE_NUMBER.to_string())
}

fn build_batch(
    current_cursor: &str,
    proposed_next_cursor: &str,
    collected_at_ms: i64,
    record: sekai_chisei::sekai::object_sync::SourceRecord,
) -> Result<DomainBatch, String> {
    let mut batch = DomainBatch {
        contract_version: SOURCE_BATCH_VERSION.into(),
        namespace: NAMESPACE.into(),
        producer_identity: CONNECTOR.into(),
        source: SOURCE_GITHUB.into(),
        source_instance: SOURCE_INSTANCE.into(),
        family: FAMILY_OBJECT_SYNC.into(),
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        type_digest: GITHUB_TYPE_DIGEST.into(),
        current_cursor: current_cursor.into(),
        proposed_next_cursor: proposed_next_cursor.into(),
        idempotency_key: format!("sync-{collected_at_ms}-{proposed_next_cursor}"),
        batch_digest: String::new(),
        collected_at_ms,
        records: vec![record],
        delivery: None,
    };
    batch.batch_digest = batch.canonical_digest().map_err(|error| error.code)?;
    batch.validate().map_err(|error| error.code)?;
    Ok(batch)
}

fn to_proto_batch(batch: DomainBatch) -> SourceBatch {
    SourceBatch {
        contract_version: batch.contract_version,
        namespace: batch.namespace,
        producer_identity: batch.producer_identity,
        source: batch.source,
        source_instance: batch.source_instance,
        family: batch.family,
        adapter_id: batch.adapter_id,
        adapter_version: batch.adapter_version,
        type_digest: batch.type_digest,
        current_cursor: batch.current_cursor,
        proposed_next_cursor: batch.proposed_next_cursor,
        idempotency_key: batch.idempotency_key,
        batch_digest: batch.batch_digest,
        collected_at_ms: batch.collected_at_ms,
        records: batch
            .records
            .into_iter()
            .map(|record| SourceRecord {
                source: record.source,
                source_instance: record.source_instance,
                external_id: record.external_id,
                source_version: record.source_version,
                type_name: record.type_name,
                display_name: record.display_name,
                payload_digest: record.payload_digest,
                properties: record.properties.into_iter().collect(),
                deleted: record.deleted,
                observed_at_ms: record.observed_at_ms,
                source_sequence: record.source_sequence,
            })
            .collect(),
        delivery: None,
    }
}

fn github_record(
    record: &FixtureRecord,
) -> Result<sekai_chisei::sekai::object_sync::SourceRecord, String> {
    github_object_sync::translate(
        github_object_sync::GitHubObjectFixture {
            repository: record.repository.clone(),
            kind: record.kind.clone(),
            number: record.number,
            revision: record.revision.clone(),
            title: record.title.clone(),
            state: record.state.clone(),
            deleted: record.deleted,
            observed_at_ms: record.observed_at_ms,
            properties: record.properties.clone(),
        },
        SOURCE_INSTANCE,
    )
}

fn permit_from_proto(value: ExternalActionPermit) -> Permit {
    Permit {
        version: value.version,
        permit_id: value.permit_id,
        authorization_id: value.authorization_id,
        request_digest: value.request_digest,
        issuer: value.issuer,
        subject_actor: value.subject_actor,
        namespace: value.namespace,
        operation_id: value.operation_id,
        requesting_harness: value.requesting_harness,
        executor: value.executor,
        action_type: value.action_type,
        parameter_schema: value.parameter_schema,
        canonical_arguments_digest: value.canonical_arguments_digest,
        target_selectors: value.target_selectors,
        immutable_preconditions: value.immutable_preconditions.into_iter().collect(),
        allowed_effects: value.allowed_effects,
        required_host_capabilities: value.required_host_capabilities,
        parent_chain: value.parent_chain,
        initiating_actor: value.initiating_actor,
        offline_revocation_unavailable: value.offline_revocation_unavailable,
        policy_scope: value.policy_scope,
        constraints: value.constraints,
        risk_class: value.risk_class,
        budget_micros: value.budget_micros,
        volume_limit: value.volume_limit,
        blast_radius_limit: value.blast_radius_limit,
        max_invocations: value.max_invocations,
        not_before_ms: value.not_before_ms,
        expires_at_ms: value.expires_at_ms,
        redemption_mode: value.redemption_mode,
        approval_identities: value.approval_identities,
        policy_version: value.policy_version,
        schema_version: value.schema_version,
        capability_version: value.capability_version,
        pricing_version: value.pricing_version,
        nonce: value.nonce,
        delegation_depth: value.delegation_depth,
        parent_permit_id: value.parent_permit_id,
        revocation_handle: value.revocation_handle,
        signature_algorithm: value.signature_algorithm,
        key_id: value.key_id,
        public_key: value.public_key,
        issued_at_ms: value.issued_at_ms,
        revocation_latency_ms: value.revocation_latency_ms,
        site_id: if value.site_id.trim().is_empty() {
            "local".into()
        } else {
            value.site_id
        },
        signed_digest: value.signed_digest,
        signature: value.signature,
    }
}

fn arguments_digest(title: &str, source_version: &str) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sha256:{:x}",
        Sha256::digest(format!("{title}\n{source_version}\n").as_bytes())
    )
}

struct ControlPlane {
    db_path: PathBuf,
    sekai: SekaiServiceImpl,
    chisei: ChiseiServiceImpl,
}

impl ControlPlane {
    fn start(root: &Path) -> Result<Self, String> {
        let db_dir = root.join("control-plane");
        fs::create_dir_all(&db_dir).map_err(|error| error.to_string())?;
        let db_path = db_dir.join("sekai.db");
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(SekaiDb::new(
            db_path
                .to_str()
                .ok_or_else(|| "control-plane database path is not utf-8".to_string())?,
        )?)));
        db.ensure_team_namespace(NAMESPACE, OPERATOR, Role::Admin, OPERATOR)?;
        db.ensure_team_namespace(NAMESPACE, CONNECTOR, Role::Editor, OPERATOR)?;
        db.upsert_action_policy(&ActionPolicy::allow_all("agent:local"))?;
        db.upsert_evidence_producer(
            &EvidenceProducerCapability {
                producer_identity: EXECUTOR.into(),
                config_version: 1,
                source_types: vec!["host_executor".into()],
                source_instances: vec![format!("{EXECUTOR}:loopback")],
                namespaces: vec![NAMESPACE.into()],
                evidence_types: vec![EXECUTION_EVIDENCE_TYPE.into()],
                target_kinds: vec!["Issue".into(), "action".into()],
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
        )?;
        let mut config = fixture_config();
        config.db_path = db_path.display().to_string();
        Ok(Self {
            db_path,
            sekai: SekaiServiceImpl::new(sekai_chisei::db::store::SekaiStore::from_shared_runtime(
                db.clone(),
            )),
            chisei: ChiseiServiceImpl::new(
                sekai_chisei::db::store::ChiseiStore::from_shared_runtime(db),
                config,
            ),
        })
    }

    fn reopen(self) -> Result<Self, String> {
        let db_path = self.db_path.clone();
        drop(self);
        let db = Arc::new(RuntimeDb::Sqlite(Arc::new(SekaiDb::new(
            db_path
                .to_str()
                .ok_or_else(|| "control-plane database path is not utf-8".to_string())?,
        )?)));
        let mut config = fixture_config();
        config.db_path = db_path.display().to_string();
        Ok(Self {
            db_path,
            sekai: SekaiServiceImpl::new(sekai_chisei::db::store::SekaiStore::from_shared_runtime(
                db.clone(),
            )),
            chisei: ChiseiServiceImpl::new(
                sekai_chisei::db::store::ChiseiStore::from_shared_runtime(db),
                config,
            ),
        })
    }
}

async fn get_issue(State(state): State<HttpState>) -> Json<FixtureRecord> {
    Json(state.fixture.snapshot().expect("fixture snapshot"))
}

async fn patch_issue(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(patch): Json<PatchIssue>,
) -> Result<Json<FixtureRecord>, StatusCode> {
    let if_match = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::PRECONDITION_REQUIRED)?;
    match state
        .fixture
        .conditional_update(if_match, &patch.title, now_ms(), false)
    {
        Ok(_) => Ok(Json(
            state
                .fixture
                .snapshot()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        )),
        Err(error) if error == "precondition_failed" => Err(StatusCode::PRECONDITION_FAILED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn start_loopback_http(
    fixture: FixtureHandle,
) -> Result<(String, oneshot::Sender<()>), String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let app = Router::new()
        .route("/issue", get(get_issue).patch(patch_issue))
        .with_state(HttpState { fixture });
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .ok();
    });
    Ok((format!("http://{address}"), shutdown_tx))
}

async fn apply_current_batch(
    sekai: &SekaiServiceImpl,
    fixture: &FixtureHandle,
    current_cursor: &str,
    next_cursor: &str,
    collected_at_ms: i64,
) -> Result<sekai_chisei::grpc::pb::sekai::SourceBatchResult, String> {
    let record = github_record(&fixture.snapshot()?)?;
    let batch = build_batch(current_cursor, next_cursor, collected_at_ms, record)?;
    let response = sekai
        .apply_source_batch(with_principal(
            ApplySourceBatchRequest {
                batch: Some(to_proto_batch(batch)),
            },
            CONNECTOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner()
        .result
        .ok_or_else(|| "ApplySourceBatch returned no result".to_string())?;
    Ok(response)
}

async fn current_cursor(sekai: &SekaiServiceImpl) -> Result<String, String> {
    let state = sekai
        .get_source_sync_state(with_principal(
            GetSourceSyncStateRequest {
                namespace: NAMESPACE.into(),
                source_instance: SOURCE_INSTANCE.into(),
                type_digest: GITHUB_TYPE_DIGEST.into(),
            },
            CONNECTOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner();
    Ok(state
        .state
        .and_then(|state| state.checkpoint)
        .map(|checkpoint| checkpoint.cursor)
        .unwrap_or_default())
}

async fn bootstrap_types(sekai: &SekaiServiceImpl) -> Result<(), String> {
    sekai
        .register_evidence_schema(with_principal(
            RegisterEvidenceSchemaRequest {
                definition: Some(EvidenceSchemaDefinition {
                    schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
                    schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
                    evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
                    compatible_versions: vec![],
                }),
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?;
    sekai
        .put_governed_action_type(with_principal(
            PutGovernedActionTypeRequest {
                r#type: Some(GovernedActionType {
                    approvers: Vec::new(),
                    namespace: NAMESPACE.into(),
                    type_id: ACTION_TYPE_ID.into(),
                    version: ACTION_TYPE_VERSION.into(),
                    description: "Permit-backed GitHub Issue write-back".into(),
                    parameter_schema_json: r#"{"type":"object","properties":{"permit_id":{"type":"string"},"source_id":{"type":"string"},"title":{"type":"string"}},"required":["permit_id","source_id","title"],"additionalProperties":false}"#.into(),
                    allowed_effect_kinds: vec![EFFECT_KIND_EXTERNAL_MUTATE.into()],
                    policy_scope: String::new(),
                    budget_scope: String::new(),
                    enabled: true,
                    created_by: OPERATOR.into(),
                    created_at_ms: 0,
                    updated_at_ms: 0,
                    disabled_at_ms: 0,
                    object_kind: String::new(),
                    object_mutation: String::new(),
            submission_criteria: vec![],
            declared_effect_kinds: vec![],
                    system_one_json: String::new(),
                }),
                request_id: "put-writeback-type".into(),
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?;
    Ok(())
}

fn write_request(
    idempotency_key: &str,
    source_version: &str,
    title: &str,
    operation_id: &str,
) -> AuthorizeExternalActionRequest {
    let digest = arguments_digest(title, source_version);
    AuthorizeExternalActionRequest {
        request: Some(ExternalActionRequest {
            version: "external-action.request/v1".into(),
            operation_id: operation_id.into(),
            parent_operation_id: String::new(),
            attempt_id: format!("{operation_id}-attempt"),
            request_id: format!("{operation_id}-request"),
            actor: OPERATOR.into(),
            namespace: NAMESPACE.into(),
            requesting_harness: HARNESS.into(),
            intended_executor: EXECUTOR.into(),
            action_type: EXTERNAL_ACTION_TYPE.into(),
            parameter_schema: ACTION_PARAMETER_SCHEMA.into(),
            canonical_arguments_digest: digest,
            policy_summary: HashMap::from([("repository".into(), SOURCE_INSTANCE.into())]),
            target_selectors: vec![format!("project:{NAMESPACE}/{}", source_identity())],
            immutable_preconditions: HashMap::from([("etag".into(), source_version.into())]),
            risk_class: "write".into(),
            expected_effects: vec!["issue_updated".into()],
            requested_invocation_count: 1,
            deadline_ms: now_ms() + 3_600_000,
            estimated_cost_micros: 0,
            estimated_volume: 1,
            affected_resource_count: 1,
            rollback_capability: "restore_issue_revision".into(),
            required_host_capabilities: vec![HOST_CAPABILITY.into()],
            idempotency_key: idempotency_key.into(),
            policy_project: NAMESPACE.into(),
        }),
        offline: false,
    }
}

fn verifying_key() -> Result<VerifyingKey, String> {
    Ok(signing_key_from_hex(PERMIT_SEED)?.verifying_key())
}

async fn submit_execution_evidence(
    sekai: &SekaiServiceImpl,
    permit: &Permit,
    redemption_id: &str,
    execution_id: &str,
    state: ExecutionLifecycleState,
    sequence: i64,
    observed_at_ms: i64,
) -> Result<String, String> {
    let report = ExecutionEvidence {
        version: EXECUTION_EVIDENCE_SCHEMA.into(),
        permit_id: permit.permit_id.clone(),
        redemption_id: redemption_id.into(),
        execution_id: execution_id.into(),
        host_identity: EXECUTOR.into(),
        lifecycle_state: state,
        observed_at_ms,
        started_at_ms: (!matches!(state, ExecutionLifecycleState::Accepted))
            .then_some(observed_at_ms),
        finished_at_ms: state.is_terminal().then_some(observed_at_ms),
        enforced_preconditions: permit.immutable_preconditions.clone(),
        normalized_effects: vec!["issue_updated".into()],
        affected_resource_references: vec![source_identity()],
        cost_micros: 0,
        resource_use: BTreeMap::new(),
        artifact_hashes: vec![],
        exit_classification: String::new(),
        error_classification: String::new(),
        compensation_evidence_hashes: vec![],
        host_schema_version: "host-evidence/v1".into(),
        host_software_version: "loopback-executor/1.0".into(),
    };
    let content = serde_json::to_value(&report).map_err(|error| error.to_string())?;
    let envelope = EvidenceEnvelope {
        contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: "host_executor".into(),
        source_instance: format!("{EXECUTOR}:loopback"),
        source_record_id: redemption_id.into(),
        source_version: format!("state-{sequence}"),
        source_sequence: sequence,
        namespace: NAMESPACE.into(),
        target_external_id: source_identity(),
        target_kind: "Issue".into(),
        evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
        signal: EvidenceSignal::Delivery.as_str().into(),
        schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
        schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
        schema_compatibility: "exact".into(),
        observed_at_ms,
        collected_at_ms: observed_at_ms,
        expires_at_ms: None,
        content_json: serde_json::to_vec(&content).map_err(|error| error.to_string())?,
        relationships: vec![],
        producer_identity: EXECUTOR.into(),
        confidence_bps: 8_000,
        classification: EvidenceClassification::Internal.as_str().into(),
        provenance: HashMap::new(),
        idempotency_key: format!("{redemption_id}-{sequence}"),
        content_digest: canonical_content_digest(&content)?,
        intent: "upsert".into(),
        causality: Some(EvidenceCausality {
            operation_id: permit.operation_id.clone(),
            parent_operation_id: String::new(),
            attempt_id: String::new(),
            model_call_id: String::new(),
            subject_references: vec![source_identity()],
            trace_context: HashMap::new(),
        }),
    };
    let result = sekai
        .submit_evidence(with_principal(
            SubmitEvidenceRequest {
                envelope: Some(envelope),
            },
            EXECUTOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner()
        .result
        .ok_or_else(|| "SubmitEvidence returned no result".to_string())?;
    if !result.admitted {
        return Err(format!(
            "execution evidence was not admitted: {}",
            result
                .submission
                .as_ref()
                .map(|submission| submission.rejection_summary.clone())
                .unwrap_or_default()
        ));
    }
    Ok(result
        .submission
        .map(|submission| submission.id)
        .unwrap_or_default())
}

pub fn run() -> Result<Report, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(run_async())
}

async fn run_async() -> Result<Report, String> {
    let root = isolated_root();
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let fixture = FixtureHandle::create(&root)?;
    let (loopback_url, shutdown) = start_loopback_http(fixture.clone()).await?;
    let plane = ControlPlane::start(&root)?;
    bootstrap_types(&plane.sekai).await?;

    let initial = apply_current_batch(&plane.sekai, &fixture, "", "cursor:1", 20).await?;
    let object = initial
        .records
        .first()
        .and_then(|record| record.object.as_ref())
        .ok_or_else(|| "initial sync did not project an object".to_string())?;
    if object.source_id != source_identity() {
        return Err("initial sync lost the GitHub source identity".into());
    }
    let object_id = object.object_id.clone();
    if object_id != object_id_for(GITHUB_TYPE_DIGEST, &source_identity()) {
        return Err("projected object id is not the type-digest binding".into());
    }

    fixture.bump_revision(
        "issue-42-v2",
        "Service checkout latency incident — investigating",
        1_700_000_200_000,
    )?;
    let cursor = current_cursor(&plane.sekai).await?;
    let refresh = apply_current_batch(&plane.sekai, &fixture, &cursor, "cursor:2", 30).await?;
    if refresh.records[0]
        .object
        .as_ref()
        .map(|object| object.object_id.as_str())
        != Some(object_id.as_str())
    {
        return Err("refresh minted a new object identity".into());
    }

    fixture.bump_revision(
        "issue-42-v3",
        "Service checkout latency incident — source moved",
        1_700_000_300_000,
    )?;
    let stale_blocked = fixture
        .conditional_update("issue-42-v2", "stale write", 1_700_000_310_000, false)
        .is_err();
    if fixture.snapshot()?.applied_effect_count != 0 {
        return Err("stale write mutated the loopback source".into());
    }
    let cursor = current_cursor(&plane.sekai).await?;
    apply_current_batch(&plane.sekai, &fixture, &cursor, "cursor:3", 40).await?;

    let denied = plane
        .chisei
        .authorize_external_action(with_principal(
            write_request(
                "writeback-denied",
                "issue-42-v3",
                "denied title",
                "op-writeback-denied",
            ),
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner();
    let denied_permit = denied
        .permit
        .ok_or_else(|| "denied path did not issue a permit to revoke".to_string())?;
    plane
        .chisei
        .transition_external_action(with_principal(
            TransitionExternalActionRequest {
                transition: "revoke".into(),
                authorization_id: denied
                    .decision
                    .as_ref()
                    .map(|decision| decision.authorization_id.clone())
                    .unwrap_or_default(),
                reason: "operator revoked write-back".into(),
                revocation_handle: denied_permit.revocation_handle.clone(),
                parent: None,
                subject_actor: String::new(),
                target_selectors: vec![],
                allowed_effects: vec![],
                budget_micros: 0,
                volume_limit: 0,
                blast_radius_limit: 0,
                max_invocations: 0,
                expires_at_ms: 0,
                risk_class: String::new(),
                offline: false,
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?;
    let revoked = plane
        .chisei
        .redeem_external_action_permit(with_principal(
            RedeemExternalActionPermitRequest {
                permit: Some(denied_permit.clone()),
                executor: EXECUTOR.into(),
                requesting_harness: HARNESS.into(),
                canonical_arguments_digest: denied_permit.canonical_arguments_digest.clone(),
                target_selectors: denied_permit.target_selectors.clone(),
                observed_preconditions: denied_permit.immutable_preconditions.clone(),
                host_capabilities: vec![HOST_CAPABILITY.into()],
                idempotency_key: "redeem-denied".into(),
                execution_id: "exec-writeback-denied".into(),
                invoked_at_ms: 0,
            },
            EXECUTOR,
        ))
        .await;
    let denied_authorization_blocked =
        revoked.is_err() && fixture.snapshot()?.applied_effect_count == 0;

    let title = "Service checkout latency incident — mitigated";
    let authorize = write_request(
        "writeback-success",
        "issue-42-v3",
        title,
        "op-writeback-success",
    );
    let first = plane
        .chisei
        .authorize_external_action(with_principal(authorize.clone(), OPERATOR))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner();
    let replay = plane
        .chisei
        .authorize_external_action(with_principal(authorize, OPERATOR))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner();
    let permit_proto = first
        .permit
        .ok_or_else(|| "authorized write-back did not return a permit".to_string())?;
    let identical_intent_replayed = replay
        .permit
        .as_ref()
        .is_some_and(|permit| permit.permit_id == permit_proto.permit_id);

    let mut changed = write_request(
        "writeback-success",
        "issue-42-v3",
        title,
        "op-writeback-success",
    );
    if let Some(request) = changed.request.as_mut() {
        request.target_selectors = vec![format!("project:{NAMESPACE}/github:acme/ops#99")];
    }
    let changed_intent_rejected = plane
        .chisei
        .authorize_external_action(with_principal(changed, OPERATOR))
        .await
        .is_err();

    let permit = permit_from_proto(permit_proto.clone());
    let trusted = verifying_key()?;
    let host = HostContext {
        executor: EXECUTOR.into(),
        requesting_harness: HARNESS.into(),
        canonical_arguments_digest: permit.canonical_arguments_digest.clone(),
        target_selectors: permit.target_selectors.clone(),
        observed_preconditions: permit.immutable_preconditions.clone(),
        host_capabilities: vec![HOST_CAPABILITY.into()],
    };
    verify_for_executor(
        &permit,
        &trusted,
        PERMIT_ISSUER,
        PERMIT_KEY_ID,
        &host,
        now_ms(),
    )?;

    let admitted = plane
        .sekai
        .submit_action_instance(with_principal(
            SubmitActionInstanceRequest {
                namespace: NAMESPACE.into(),
                type_id: ACTION_TYPE_ID.into(),
                version: ACTION_TYPE_VERSION.into(),
                parameters_json: serde_json::json!({
                    "permit_id": permit.permit_id,
                    "source_id": source_identity(),
                    "title": title,
                })
                .to_string(),
                idempotency_key: "action-writeback-success".into(),
                evidence_submission_ids: vec![],
                request_id: permit.operation_id.clone(),
                ontology_digest: String::new(),
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner();
    let instance = admitted
        .instance
        .ok_or_else(|| "SubmitActionInstance returned no instance".to_string())?;
    if instance.status != "admitted" {
        return Err(format!("write-back Action was {}", instance.status));
    }
    let replayed_instance = plane
        .sekai
        .submit_action_instance(with_principal(
            SubmitActionInstanceRequest {
                namespace: NAMESPACE.into(),
                type_id: ACTION_TYPE_ID.into(),
                version: ACTION_TYPE_VERSION.into(),
                parameters_json: serde_json::json!({
                    "permit_id": permit.permit_id,
                    "source_id": source_identity(),
                    "title": title,
                })
                .to_string(),
                idempotency_key: "action-writeback-success".into(),
                evidence_submission_ids: vec![],
                request_id: "op-writeback-success-other".into(),
                ontology_digest: String::new(),
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner();
    if !replayed_instance.replay
        || replayed_instance
            .instance
            .as_ref()
            .map(|value| value.instance_id.as_str())
            != Some(instance.instance_id.as_str())
    {
        return Err("identical Action intent did not replay the original identity".into());
    }
    let changed_action = plane
        .sekai
        .submit_action_instance(with_principal(
            SubmitActionInstanceRequest {
                namespace: NAMESPACE.into(),
                type_id: ACTION_TYPE_ID.into(),
                version: ACTION_TYPE_VERSION.into(),
                parameters_json: serde_json::json!({
                    "permit_id": permit.permit_id,
                    "source_id": "github:acme/ops#99",
                    "title": title,
                })
                .to_string(),
                idempotency_key: "action-writeback-success".into(),
                evidence_submission_ids: vec![],
                request_id: "op-writeback-changed".into(),
                ontology_digest: String::new(),
            },
            OPERATOR,
        ))
        .await;
    let changed_intent_rejected = changed_intent_rejected && changed_action.is_err();

    let effects = plane
        .sekai
        .list_action_effects(with_principal(
            ListActionEffectsRequest {
                instance_id: instance.instance_id.clone(),
                namespace: String::new(),
                kind: String::new(),
                status: String::new(),
                limit: 8,
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner()
        .effects;
    if !effects
        .iter()
        .any(|effect| effect.kind == EFFECT_KIND_EXTERNAL_MUTATE && effect.status == "pending")
    {
        return Err(
            "admitted write-back did not materialize a pending external_mutate effect".into(),
        );
    }

    let redemption = plane
        .chisei
        .redeem_external_action_permit(with_principal(
            RedeemExternalActionPermitRequest {
                permit: Some(permit_proto),
                executor: EXECUTOR.into(),
                requesting_harness: HARNESS.into(),
                canonical_arguments_digest: permit.canonical_arguments_digest.clone(),
                target_selectors: permit.target_selectors.clone(),
                observed_preconditions: permit
                    .immutable_preconditions
                    .clone()
                    .into_iter()
                    .collect(),
                host_capabilities: vec![HOST_CAPABILITY.into()],
                idempotency_key: "redeem-writeback-success".into(),
                execution_id: EXECUTION_ID.into(),
                invoked_at_ms: 0,
            },
            EXECUTOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner()
        .redemption
        .ok_or_else(|| "permit redemption returned no record".to_string())?;

    let client = reqwest::Client::new();
    let http_probe = client
        .get(format!("{loopback_url}/issue"))
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?;
    let _ = http_probe;
    let lost = fixture.conditional_update("issue-42-v3", title, now_ms(), true)?;
    if lost.is_some() {
        return Err("response-loss path returned a fabricated success".into());
    }
    if fixture.snapshot()?.applied_effect_count != 1 {
        return Err("response-loss path did not commit exactly one source mutation".into());
    }
    let retry = fixture.conditional_update("issue-42-v3", title, now_ms(), false);
    if retry.is_ok() {
        return Err("recovery retried the lost write-back against a new source version".into());
    }
    let observed_at = now_ms().max(redemption.redeemed_at_ms);
    let execution_evidence_id = submit_execution_evidence(
        &plane.sekai,
        &permit,
        &redemption.redemption_id,
        EXECUTION_ID,
        ExecutionLifecycleState::OutcomeUnknown,
        1,
        observed_at,
    )
    .await?;
    let cursor = current_cursor(&plane.sekai).await?;
    let readback = apply_current_batch(&plane.sekai, &fixture, &cursor, "cursor:4", 50).await?;
    let readback_object = readback
        .records
        .first()
        .and_then(|record| record.object.as_ref())
        .ok_or_else(|| "readback did not return the source object".to_string())?;
    if readback_object.object_id != object_id || readback_object.source_version != "issue-42-v4" {
        return Err("readback did not preserve identity after the lost response".into());
    }

    let receipt = plane
        .chisei
        .get_operation_receipt(with_principal(
            GetOperationReceiptRequest {
                operation_id: instance.operation_id.clone(),
                request_id: String::new(),
                caller_scope: String::new(),
                attempt: 0,
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner();
    if receipt.receipt_json.is_empty() {
        return Err("operation receipt was not inspectable".into());
    }
    let receipt_value: serde_json::Value = serde_json::from_str(&receipt.receipt_json)
        .map_err(|error| format!("operation receipt is not JSON: {error}"))?;
    let receipt_operation_id = receipt_value
        .get("operation_id")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    if receipt_operation_id.is_empty() {
        return Err("receipt is missing the bound operation identity".into());
    }
    let receipt_version = receipt_value
        .get("version")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if !receipt_version.is_empty() && receipt_version != OPERATION_RECEIPT_VERSION {
        return Err("receipt is missing the operation receipt contract".into());
    }

    let restored_plane = plane.reopen()?;
    let restored_object = restored_plane
        .sekai
        .get_object(with_principal(
            GetObjectRequest {
                id: object_id.clone(),
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner()
        .object
        .ok_or_else(|| "restart lost the projected source object".to_string())?;
    let restored_instance = restored_plane
        .sekai
        .get_action_instance(with_principal(
            GetActionInstanceRequest {
                instance_id: instance.instance_id.clone(),
                namespace: String::new(),
                idempotency_key: String::new(),
                operation_id: String::new(),
            },
            OPERATOR,
        ))
        .await
        .map_err(|error| error.message().to_string())?
        .into_inner()
        .instance
        .ok_or_else(|| "restart lost the Action identity".to_string())?;
    let restored_fixture = FixtureHandle::load(root.join("source-fixture").join("issue.json"))?;
    let restart_preserved_identity = restored_object.id == object_id
        && restored_instance.instance_id == instance.instance_id
        && restored_fixture.snapshot()?.revision == "issue-42-v4";
    let fixture_effect_count_after_restart = restored_fixture.snapshot()?.applied_effect_count;
    let _ = shutdown.send(());
    let _ = restored_plane;

    Ok(Report {
        contract_version: CONTRACT_VERSION.into(),
        source_identity: source_identity(),
        object_id,
        type_digest: GITHUB_TYPE_DIGEST.into(),
        action_instance_id: instance.instance_id,
        permit_id: permit.permit_id,
        execution_id: EXECUTION_ID.into(),
        receipt_operation_id,
        execution_evidence_id,
        readback_source_version: "issue-42-v4".into(),
        applied_effect_count: fixture_effect_count_after_restart,
        stale_precondition_blocked: stale_blocked,
        denied_authorization_blocked,
        identical_intent_replayed,
        changed_intent_rejected,
        response_loss_outcome: "unknown".into(),
        recovered_without_repeat: retry.is_err(),
        restart_preserved_identity,
        fixture_effect_count_after_restart,
    })
}

#[allow(dead_code)]
pub fn main() {
    match run() {
        Ok(report) => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report is serializable")
        ),
        Err(error) => {
            eprintln!("source write-back fixture failed: {error}");
            std::process::exit(1);
        }
    }
}
