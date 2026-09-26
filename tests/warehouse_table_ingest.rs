//! Warehouse table ingest profile end to end (#1085): a connector outside the
//! plane turns committed table snapshots into registered-source batches; the
//! plane admits them into typed objects, checkpoints on the snapshot id,
//! quarantines schema drift without touching the last consistent objects, and
//! never sees restricted columns.

#[allow(dead_code)]
#[path = "../adapters/warehouse_table_ingest.rs"]
mod warehouse_table_ingest;

use std::collections::BTreeMap;
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    ApplyDefinitionBranchEditRequest, ApplySourceBatchRequest, ApproveDefinitionProposalRequest,
    CreateDefinitionBranchRequest, CreateDefinitionProposalRequest, DefinitionMemberInput,
    EvaluateObjectSetRequest, GetObjectRequest, GetSourceSyncStateRequest,
    MergeDefinitionProposalRequest, ObjectSetDescriptor, PropertyFilter,
    RegisterSourceTypeDescriptorRequest, SourceBatch, SourceRecord,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::security::Role;
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

const NAMESPACE: &str = "sales";
const OPERATOR: &str = "operator";
const CONNECTOR: &str = "connector/warehouse";
const OUTSIDER: &str = "connector/outsider";
/// Definitions are published by the control-plane schema administrator.
const SCHEMA_ADMIN: &str = "root";

fn snapshot(name: &str) -> warehouse_table_ingest::TableSnapshot {
    let path = format!(
        "{}/tests/fixtures/warehouse_ingest/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    warehouse_table_ingest::parse(&std::fs::read(path).unwrap()).unwrap()
}

fn with_principal<T>(payload: T, principal: &str) -> Request<T> {
    let mut request = Request::new(payload);
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::try_from(principal).unwrap());
    request
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

async fn apply(
    service: &SekaiServiceImpl,
    snapshot: warehouse_table_ingest::TableSnapshot,
    namespace: &str,
    producer: &str,
    current_cursor: &str,
) -> Result<sekai_chisei::grpc::pb::sekai::SourceBatchResult, tonic::Status> {
    let batch = warehouse_table_ingest::batch(snapshot, namespace, producer, current_cursor)
        .map_err(tonic::Status::invalid_argument)?;
    service
        .apply_source_batch(with_principal(
            ApplySourceBatchRequest {
                batch: Some(to_proto(batch)),
            },
            producer,
        ))
        .await
        .map(|response| response.into_inner().result.expect("batch result"))
}

fn status(result: &sekai_chisei::grpc::pb::sekai::SourceBatchResult) -> &str {
    result
        .transaction
        .as_ref()
        .map(|transaction| transaction.status.as_str())
        .unwrap_or_default()
}

async fn object_properties(
    service: &SekaiServiceImpl,
    id: &str,
) -> Option<BTreeMap<String, String>> {
    service
        .get_object(with_principal(GetObjectRequest { id: id.into() }, OPERATOR))
        .await
        .ok()
        .and_then(|response| response.into_inner().object)
        .map(|object| object.properties.into_iter().collect())
}

/// Publishes an object-type definition for `kind` through the reviewed
/// proposal flow and returns the published revision digest.
async fn publish_object_type(
    service: &SekaiServiceImpl,
    kind: &str,
    definition_json: String,
) -> String {
    let branch = service
        .create_definition_branch(with_principal(
            CreateDefinitionBranchRequest {
                namespace: NAMESPACE.into(),
                branch_id: "orders".into(),
                parent_revision_digest: String::new(),
                idempotency_key: "orders-branch".into(),
            },
            SCHEMA_ADMIN,
        ))
        .await
        .unwrap()
        .into_inner()
        .branch
        .unwrap();
    let genesis = branch.head_revision_digest;
    let candidate = service
        .apply_definition_branch_edit(with_principal(
            ApplyDefinitionBranchEditRequest {
                namespace: NAMESPACE.into(),
                branch_id: "orders".into(),
                expected_head_digest: genesis.clone(),
                upserts: vec![DefinitionMemberInput {
                    member_kind: "object_type".into(),
                    member_id: kind.into(),
                    definition_json,
                    member_digest: String::new(),
                }],
                removals: Vec::new(),
                idempotency_key: "orders-edit".into(),
            },
            SCHEMA_ADMIN,
        ))
        .await
        .unwrap()
        .into_inner()
        .revision
        .unwrap()
        .revision_digest;
    service
        .create_definition_proposal(with_principal(
            CreateDefinitionProposalRequest {
                namespace: NAMESPACE.into(),
                branch_id: "orders".into(),
                proposal_id: "orders-proposal".into(),
                base_digest: genesis.clone(),
                candidate_digest: candidate.clone(),
                eval_plan_digests: Vec::new(),
                named_foreign_digests: Vec::new(),
                idempotency_key: "orders-propose".into(),
            },
            SCHEMA_ADMIN,
        ))
        .await
        .unwrap();
    service
        .approve_definition_proposal(with_principal(
            ApproveDefinitionProposalRequest {
                namespace: NAMESPACE.into(),
                proposal_id: "orders-proposal".into(),
                idempotency_key: "orders-approve".into(),
            },
            SCHEMA_ADMIN,
        ))
        .await
        .unwrap();
    service
        .merge_definition_proposal(with_principal(
            MergeDefinitionProposalRequest {
                namespace: NAMESPACE.into(),
                proposal_id: "orders-proposal".into(),
                idempotency_key: "orders-merge".into(),
                expected_published_digest: genesis,
            },
            SCHEMA_ADMIN,
        ))
        .await
        .unwrap()
        .into_inner()
        .published_revision
        .unwrap()
        .revision_digest
}

async fn checkpoint(service: &SekaiServiceImpl, type_digest: &str) -> String {
    service
        .get_source_sync_state(with_principal(
            GetSourceSyncStateRequest {
                namespace: NAMESPACE.into(),
                source_instance: "lake.sales.orders".into(),
                type_digest: type_digest.into(),
            },
            CONNECTOR,
        ))
        .await
        .unwrap()
        .into_inner()
        .state
        .and_then(|state| state.checkpoint)
        .map(|checkpoint| checkpoint.cursor)
        .unwrap_or_default()
}

#[tokio::test]
async fn warehouse_snapshots_hydrate_typed_objects_with_checkpoints_and_quarantine() {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    db.ensure_team_namespace(NAMESPACE, OPERATOR, Role::Admin, OPERATOR)
        .unwrap();
    db.ensure_team_namespace(NAMESPACE, CONNECTOR, Role::Editor, OPERATOR)
        .unwrap();
    let service =
        SekaiServiceImpl::new(sekai_chisei::db::store::SekaiStore::from_shared_runtime(db));

    let first = snapshot("orders-snapshot-1.json");
    let descriptor = warehouse_table_ingest::descriptor(&first).unwrap();
    let registered = service
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
        .unwrap()
        .into_inner()
        .descriptor
        .unwrap();
    assert_eq!(registered.digest, descriptor.digest);
    let object =
        |key: &str| warehouse_table_ingest::object_id(&descriptor, &first.table, key).unwrap();

    // Snapshot 1 admits three typed objects; the restricted column never
    // reaches the plane.
    let admitted = apply(&service, first.clone(), NAMESPACE, CONNECTOR, "")
        .await
        .unwrap();
    assert_eq!(status(&admitted), "COMMITTED", "{admitted:?}");
    assert_eq!(
        checkpoint(&service, &descriptor.digest).await,
        "snapshot:4081"
    );
    for key in ["1001", "1002", "1003"] {
        let properties = object_properties(&service, &object(key)).await.unwrap();
        assert_eq!(properties.get("order_id").map(String::as_str), Some(key));
        assert!(!properties.contains_key("customer_email"), "{properties:?}");
        assert!(
            !properties
                .values()
                .any(|value| value.contains("@example.com")),
            "{properties:?}"
        );
    }
    let admitted_json = format!("{admitted:?}");
    assert!(!admitted_json.contains("@example.com"));

    // The admitted rows are typed objects the product loop can query.
    let kind = service
        .get_object(with_principal(
            GetObjectRequest { id: object("1001") },
            OPERATOR,
        ))
        .await
        .unwrap()
        .into_inner()
        .object
        .unwrap()
        .kind;
    assert_eq!(kind, first.record_kind);
    let definition = warehouse_table_ingest::object_type_definition(&first);
    assert!(!definition.contains("customer_email"), "{definition}");
    let published = publish_object_type(&service, &kind, definition).await;
    let open_in_eu = service
        .evaluate_object_set(with_principal(
            EvaluateObjectSetRequest {
                descriptor: Some(ObjectSetDescriptor {
                    contract_version: sekai_chisei::sekai::object_set::CONTRACT_VERSION.into(),
                    namespace: NAMESPACE.into(),
                    kind: kind.clone(),
                    definition_digest: published,
                    property_filters: vec![PropertyFilter {
                        key: "region".into(),
                        op: "eq".into(),
                        value: "eu".into(),
                    }],
                    limit: 10,
                    ..Default::default()
                }),
                page_token: String::new(),
                required_freshness_ms: 0,
            },
            OPERATOR,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(open_in_eu.total, 2, "{open_in_eu:?}");

    // Snapshot 2 advances the checkpoint: one row changed, one tombstoned.
    let second = snapshot("orders-snapshot-2.json");
    let advanced = apply(
        &service,
        second.clone(),
        NAMESPACE,
        CONNECTOR,
        "snapshot:4081",
    )
    .await
    .unwrap();
    assert_eq!(status(&advanced), "COMMITTED", "{advanced:?}");
    assert_eq!(
        checkpoint(&service, &descriptor.digest).await,
        "snapshot:4082"
    );
    assert_eq!(
        object_properties(&service, &object("1001"))
            .await
            .unwrap()
            .get("status")
            .map(String::as_str),
        Some("shipped")
    );
    let decisions = advanced
        .records
        .iter()
        .map(|record| record.decision.as_str())
        .collect::<Vec<_>>();
    assert!(decisions.contains(&"tombstone"), "{decisions:?}");

    // Declared drift: snapshot 3 moved to schema revision v2, which nobody
    // registered. The plane refuses it before any write.
    let drift = snapshot("orders-snapshot-3-drift.json");
    let declared = apply(
        &service,
        drift.clone(),
        NAMESPACE,
        CONNECTOR,
        "snapshot:4082",
    )
    .await
    .unwrap_err();
    assert_eq!(declared.code(), Code::FailedPrecondition, "{declared:?}");
    assert_eq!(
        checkpoint(&service, &descriptor.digest).await,
        "snapshot:4082"
    );

    // Undeclared drift: snapshot 4 rewrote row 1001 under the same schema
    // revision and row version. The plane quarantines the batch, sync state
    // shows it, and the last consistent object and checkpoint stay.
    let rewrite = snapshot("orders-snapshot-4-rewrite.json");
    let quarantined = apply(
        &service,
        rewrite.clone(),
        NAMESPACE,
        CONNECTOR,
        "snapshot:4082",
    )
    .await
    .unwrap();
    assert_eq!(status(&quarantined), "QUARANTINED", "{quarantined:?}");
    let state = service
        .get_source_sync_state(with_principal(
            GetSourceSyncStateRequest {
                namespace: NAMESPACE.into(),
                source_instance: "lake.sales.orders".into(),
                type_digest: descriptor.digest.clone(),
            },
            CONNECTOR,
        ))
        .await
        .unwrap()
        .into_inner()
        .state
        .unwrap();
    assert_eq!(
        state
            .latest_transaction
            .as_ref()
            .map(|transaction| transaction.status.as_str()),
        Some("QUARANTINED")
    );
    assert_eq!(state.checkpoint.unwrap().cursor, "snapshot:4082");
    let kept = object_properties(&service, &object("1001")).await.unwrap();
    assert_eq!(kept.get("status").map(String::as_str), Some("shipped"));
    assert_eq!(kept.get("region").map(String::as_str), Some("eu"));

    // A producer without access to the namespace cannot admit a batch.
    let outsider = apply(
        &service,
        second.clone(),
        NAMESPACE,
        OUTSIDER,
        "snapshot:4082",
    )
    .await;
    match outsider {
        Err(status) => assert!(
            matches!(
                status.code(),
                Code::PermissionDenied | Code::Unauthenticated
            ),
            "{status:?}"
        ),
        Ok(result) => assert_ne!(status(&result), "COMMITTED", "{result:?}"),
    }
    assert_eq!(
        checkpoint(&service, &descriptor.digest).await,
        "snapshot:4082"
    );
}

#[test]
fn the_adapter_refuses_malformed_snapshots() {
    let mut malformed = snapshot("orders-snapshot-1.json");
    malformed.rows[0].insert("undeclared".into(), "x".into());
    assert!(warehouse_table_ingest::validate(&malformed).is_err());
    let mut hidden_key = snapshot("orders-snapshot-1.json");
    hidden_key.columns[0].hidden = true;
    assert!(warehouse_table_ingest::validate(&hidden_key).is_err());
    let mut undisplayed = snapshot("orders-snapshot-1.json");
    undisplayed.rows[0].remove("summary");
    assert!(warehouse_table_ingest::validate(&undisplayed).is_err());
    let mut blank_display = snapshot("orders-snapshot-1.json");
    blank_display.rows[0].insert("summary".into(), String::new());
    assert!(warehouse_table_ingest::validate(&blank_display).is_err());
    let mut unversioned = snapshot("orders-snapshot-1.json");
    unversioned.rows[0].remove("row_version");
    assert!(warehouse_table_ingest::validate(&unversioned).is_err());
    let mut duplicated = snapshot("orders-snapshot-1.json");
    let row = duplicated.rows[0].clone();
    duplicated.rows.push(row);
    assert!(warehouse_table_ingest::validate(&duplicated).is_err());
    // An unchanged row keeps its source version across snapshots.
    let first = warehouse_table_ingest::records(snapshot("orders-snapshot-1.json")).unwrap();
    let second = warehouse_table_ingest::records(snapshot("orders-snapshot-2.json")).unwrap();
    assert!(warehouse_table_ingest::records(undisplayed).is_err());
    assert!(warehouse_table_ingest::batch(unversioned, NAMESPACE, CONNECTOR, "").is_err());
    let version = |records: &[sekai_chisei::sekai::object_sync::SourceRecord], key: &str| {
        records
            .iter()
            .find(|record| record.external_id == key)
            .map(|record| record.source_version.clone())
    };
    assert_eq!(version(&first, "1002"), version(&second, "1002"));
    assert!(
        first
            .iter()
            .all(|record| !record.properties.contains_key("customer_email")),
        "hidden columns must be dropped from moved row maps (#1209)"
    );
    assert_ne!(version(&first, "1001"), version(&second, "1001"));
}
