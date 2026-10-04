//! Warehouse writeback end to end (#1085): source → object → governed Action
//! → source write → next snapshot → object, with a receipt. The executor holds
//! the table; the plane only sees the permit, the Action, the evidence, and
//! the next ingested batch.

#[allow(dead_code)]
#[path = "../adapters/warehouse_table_ingest.rs"]
mod warehouse_table_ingest;

#[allow(dead_code)]
#[path = "../adapters/source_writeback.rs"]
mod source_writeback;

use std::collections::BTreeMap;
use std::sync::Arc;

use sekai_chisei::chisei::external_permit::signing_key_from_hex;
use sekai_chisei::config::Config;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::chisei_service::ChiseiServiceImpl;
use sekai_chisei::grpc::pb::chisei::GetOperationReceiptRequest;
use sekai_chisei::grpc::pb::chisei::chisei_service_server::ChiseiService;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    ApplySourceBatchRequest, GetObjectRequest, RegisterSourceTypeDescriptorRequest, SourceBatch,
    SourceRecord,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::action_policy::ActionPolicy;
use sekai_chisei::sekai::evidence::{EvidenceClassification, EvidenceIntent};
use sekai_chisei::sekai::evidence_store::EvidenceProducerCapability;
use sekai_chisei::sekai::execution_evidence::EXECUTION_EVIDENCE_TYPE;
use sekai_chisei::sekai::security::Role;
use source_writeback::{PermitTrust, SourceSystem, WritebackIntent, WritebackProfile};
use tonic::Request;
use tonic::metadata::MetadataValue;
use warehouse_table_ingest::TableStore;

const NAMESPACE: &str = "sales";
const OPERATOR: &str = "local";
const CONNECTOR: &str = "connector/warehouse";
const EXECUTOR: &str = "executor:warehouse";
const PERMIT_SEED: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const PERMIT_ISSUER: &str = "issuer:test";
const PERMIT_KEY_ID: &str = "key-1";

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

impl SourceSystem for TableStore {
    fn resource(&self, key: &str) -> Result<String, String> {
        TableStore::resource(self, key)
    }

    fn version(&self, key: &str) -> Result<String, String> {
        self.row_version(key)
    }

    fn apply(
        &self,
        key: &str,
        expected_version: &str,
        change: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        TableStore::apply(self, key, expected_version, change)
    }
}

fn with_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    request
}

fn snapshot(name: &str) -> warehouse_table_ingest::TableSnapshot {
    let path = format!(
        "{}/tests/fixtures/warehouse_ingest/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    warehouse_table_ingest::parse(&std::fs::read(path).unwrap()).unwrap()
}

fn to_proto(batch: sekai_chisei::sekai::object_sync::SourceBatch) -> SourceBatch {
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

async fn ingest(sekai: &SekaiServiceImpl, store: &TableStore, current_cursor: &str) -> String {
    let batch =
        warehouse_table_ingest::batch(store.snapshot(), NAMESPACE, CONNECTOR, current_cursor)
            .unwrap();
    let next = batch.proposed_next_cursor.clone();
    let result = sekai
        .apply_source_batch(with_principal(
            ApplySourceBatchRequest {
                batch: Some(to_proto(batch)),
            },
            CONNECTOR,
        ))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(
        result
            .transaction
            .as_ref()
            .map(|transaction| transaction.status.as_str()),
        Some("COMMITTED"),
        "{result:?}"
    );
    next
}

async fn status_of(sekai: &SekaiServiceImpl, object_id: &str) -> String {
    sekai
        .get_object(with_principal(
            GetObjectRequest {
                id: object_id.into(),
            },
            OPERATOR,
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap()
        .properties
        .get("status")
        .cloned()
        .unwrap_or_default()
}

#[tokio::test]
async fn a_governed_action_writes_back_to_the_warehouse_and_the_next_snapshot_shows_it() {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    db.ensure_team_namespace(NAMESPACE, OPERATOR, Role::Admin, OPERATOR)
        .unwrap();
    db.ensure_team_namespace(NAMESPACE, CONNECTOR, Role::Editor, OPERATOR)
        .unwrap();
    db.upsert_action_policy(&ActionPolicy::allow_all("agent:local"))
        .unwrap();
    db.upsert_evidence_producer(
        &EvidenceProducerCapability {
            producer_identity: EXECUTOR.into(),
            config_version: 1,
            source_types: vec!["host_executor".into()],
            source_instances: vec![format!("{EXECUTOR}:writeback")],
            namespaces: vec![NAMESPACE.into()],
            evidence_types: vec![EXECUTION_EVIDENCE_TYPE.into()],
            target_kinds: vec!["Order".into(), "action".into()],
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
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    let sekai = SekaiServiceImpl::new(sekai_chisei::db::store::SekaiStore::from_shared_runtime(
        db.clone(),
    ));
    let chisei = ChiseiServiceImpl::new(
        sekai_chisei::db::store::ChiseiStore::from_shared_runtime(db),
        fixture_config(),
    );

    // The executor's table, seeded with the first committed snapshot.
    let store = TableStore::new(snapshot("orders-snapshot-1.json")).unwrap();
    let first = store.snapshot();
    let descriptor = warehouse_table_ingest::descriptor(&first).unwrap();
    sekai
        .register_source_type_descriptor(with_principal(
            RegisterSourceTypeDescriptorRequest {
                namespace: NAMESPACE.into(),
                source: warehouse_table_ingest::SOURCE.into(),
                record_kind: first.record_kind.clone(),
                schema_revision: first.schema_revision.clone(),
            },
            OPERATOR,
        ))
        .await
        .unwrap();
    let cursor = ingest(&sekai, &store, "").await;
    let order = warehouse_table_ingest::object_id(&descriptor, &first.table, "1001").unwrap();
    assert_eq!(status_of(&sekai, &order).await, "open");

    let profile = WritebackProfile {
        namespace: NAMESPACE.into(),
        action_type_id: "warehouse.order.update".into(),
        action_type_version: "1".into(),
        external_action_type: "warehouse.row.write/v1".into(),
        parameter_schema: "warehouse.row.write.params/v1".into(),
        executor: EXECUTOR.into(),
        harness: "harness:writeback".into(),
        host_capability: "conditional_request".into(),
        target_kind: first.record_kind.clone(),
    };
    profile.bootstrap(&sekai, OPERATOR).await.unwrap();
    let key = signing_key_from_hex(PERMIT_SEED).unwrap().verifying_key();
    let trust = PermitTrust {
        key: &key,
        issuer: PERMIT_ISSUER,
        key_id: PERMIT_KEY_ID,
    };
    let decided_at = store.row_version("1001").unwrap();
    let intent = WritebackIntent {
        key: "1001".into(),
        expected_version: decided_at.clone(),
        change: BTreeMap::from([("status".into(), "cancelled".into())]),
        operation_id: "op-cancel-1001".into(),
        idempotency_key: "cancel-1001".into(),
    };

    let outcome = profile
        .run(&sekai, &chisei, &store, OPERATOR, &trust, &intent)
        .await
        .unwrap();
    assert_eq!(outcome.effect.kind, "external_mutate");
    assert_eq!(outcome.new_version, "2");
    assert!(
        outcome.evidence.as_ref().is_ok_and(|id| !id.is_empty()),
        "{:?}",
        outcome.evidence
    );
    // The source of record changed; the plane learns it from the next batch.
    assert_eq!(status_of(&sekai, &order).await, "open");
    let cursor = ingest(&sekai, &store, &cursor).await;
    assert_eq!(cursor, "snapshot:4082");
    assert_eq!(status_of(&sekai, &order).await, "cancelled");

    // The operation receipt carries the Action's identity.
    let receipt = chisei
        .get_operation_receipt(with_principal(
            GetOperationReceiptRequest {
                operation_id: outcome.operation_id.clone(),
                request_id: String::new(),
                caller_scope: String::new(),
                attempt: 0,
            },
            OPERATOR,
        ))
        .await
        .unwrap()
        .into_inner();
    let receipt: serde_json::Value = serde_json::from_str(&receipt.receipt_json).unwrap();
    assert_eq!(
        receipt
            .get("operation_id")
            .and_then(serde_json::Value::as_str),
        Some(outcome.operation_id.as_str())
    );

    // A change decided against a stale row version never overwrites the
    // newer row.
    let stale = WritebackIntent {
        key: "1001".into(),
        expected_version: decided_at,
        change: BTreeMap::from([("status".into(), "open".into())]),
        operation_id: "op-reopen-1001".into(),
        idempotency_key: "reopen-1001".into(),
    };
    let refused = profile
        .run(&sekai, &chisei, &store, OPERATOR, &trust, &stale)
        .await
        .unwrap_err();
    assert!(refused.contains("record version changed"), "{refused}");
    assert_eq!(store.row_version("1001").unwrap(), "2");
    assert_eq!(status_of(&sekai, &order).await, "cancelled");

    // The source write itself is conditional, for a change that raced the
    // version check.
    assert!(
        store
            .apply(
                "1002",
                "0",
                &BTreeMap::from([("status".into(), "shipped".into())])
            )
            .is_err()
    );
    assert_eq!(store.row_version("1002").unwrap(), "1");

    // Identity and restricted columns cannot be written through the adapter.
    let forbidden = store.apply(
        "1002",
        "1",
        &BTreeMap::from([("customer_email".into(), "x@example.com".into())]),
    );
    assert!(forbidden.is_err());
}
