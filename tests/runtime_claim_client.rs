//! Runtime-claim client against SQLite and PostgreSQL planes (#1389).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::gateway_keys::hash_gateway_key;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::rpc_maturity::RpcMaturityLayer;
use sekai_chisei::sekai::action_effect::plan_effects_for_admit;
use sekai_chisei::sekai::action_instance::{ActionInstance, STATUS_ADMITTED};
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset};
use sekai_chisei::sekai::governed_transform::{
    CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, rows_digest,
};
use sekai_chisei::sekai::security::Role;
use sekai_client::claim::{
    ActionAck, ActionFence, ClaimAttempt, DELEGATOR_DISABLED, RuntimeClaimError, TransformFence,
    TransformWrite,
};
use sekai_client::protocol::sekai::TransformRunInputRow;
use sekai_client::{ClientConfig, CoreLoopClient};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tower::Layer;

use crate::postgres_scratch::ScratchDatabase;

const NAMESPACE: &str = "ops";
const PRINCIPAL: &str = "local";
const DELEGATOR: &str = "origin-user";

struct ServingPlane {
    endpoint: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ServingPlane {
    async fn start(db: RuntimeDb) -> Self {
        let store = SekaiStore::from_shared_runtime(Arc::new(db));
        let service = RpcMaturityLayer::new(true)
            .layer(SekaiServiceServer::new(SekaiServiceImpl::new(store)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            endpoint,
            stop: Some(stop),
            join: Some(join),
        }
    }

    async fn client(&self) -> CoreLoopClient<sekai_client::GrpcTransport> {
        CoreLoopClient::connect(
            ClientConfig::new(&self.endpoint, PRINCIPAL)
                .with_namespace(NAMESPACE)
                .with_default_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("connect runtime-claim client")
    }

    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for ServingPlane {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

fn seed_action(db: &RuntimeDb, prefix: &str) {
    seed_action_with_act(db, prefix, None);
}

fn seed_action_with_act(db: &RuntimeDb, prefix: &str, delegating_actor: Option<&str>) {
    db.ensure_team_namespace(NAMESPACE, PRINCIPAL, Role::Admin, PRINCIPAL)
        .unwrap();
    let mut effect = plan_effects_for_admit(
        &format!("{prefix}-instance"),
        NAMESPACE,
        &format!("{prefix}-operation"),
        &["runtime_dispatch".into()],
        r#"{"runtime":"runner-a"}"#,
        10,
        false,
    )
    .unwrap()
    .remove(0);
    effect.effect_id = format!("{prefix}-effect");
    db.put_action_instance(&ActionInstance {
        instance_id: effect.instance_id.clone(),
        namespace: effect.namespace.clone(),
        type_id: "dispatch".into(),
        version: "1".into(),
        principal: PRINCIPAL.into(),
        delegating_actor: delegating_actor.map(str::to_string),
        parameters_json: r#"{"runtime":"runner-a"}"#.into(),
        request_digest: "digest-1".into(),
        idempotency_key: format!("idem-{}", effect.effect_id),
        operation_id: effect.operation_id.clone(),
        status: STATUS_ADMITTED.into(),
        deny_reason: String::new(),
        evidence_submission_ids: Vec::new(),
        policy_decision: "allow".into(),
        budget_decision: "allow".into(),
        created_at_ms: 10,
        decided_at_ms: 10,
        system_one_fill_json: String::new(),
        parked_object_digest: String::new(),
        decided_by: String::new(),
        approval_decision: String::new(),
        autonomous_envelope_id: String::new(),
    })
    .unwrap();
    db.put_action_effects(&[effect]).unwrap();
}

fn seed_delegated_action(db: &RuntimeDb, prefix: &str) {
    db.create_principal_credential(DELEGATOR, &hash_gateway_key("delegator-secret"), 1)
        .unwrap();
    db.ensure_team_namespace(NAMESPACE, DELEGATOR, Role::Editor, PRINCIPAL)
        .unwrap();
    seed_action_with_act(db, prefix, Some(DELEGATOR));
}

/// Community `RuntimeDb::append_rows` stays SQLite-only; PostgreSQL snapshots
/// come from each backend's native dataset-row API.
fn seed_dataset_rows(db: &RuntimeDb, dataset_id: &str, rows: &[HashMap<String, String>]) {
    match db {
        RuntimeDb::Sqlite(_) => {
            db.append_rows(dataset_id, rows).unwrap();
        }
        RuntimeDb::Postgres(pg) => {
            tokio::task::block_in_place(|| {
                pg.append_dataset_rows(dataset_id, rows).unwrap();
            });
        }
    }
}

fn seed_transform(db: &RuntimeDb, prefix: &str) {
    db.ensure_team_namespace(NAMESPACE, PRINCIPAL, Role::Admin, PRINCIPAL)
        .unwrap();
    let dataset = |id: &str| Dataset {
        id: format!("{prefix}-{id}"),
        name: id.into(),
        columns: vec![ColumnDef {
            name: "id".into(),
            col_type: "string".into(),
            classification: "public".into(),
        }],
        object_id: String::new(),
        created: 1,
    };
    db.create_dataset(&dataset("in")).unwrap();
    db.create_dataset(&dataset("out")).unwrap();
    seed_dataset_rows(
        db,
        &format!("{prefix}-in"),
        &[HashMap::from([("id".into(), "1".into())])],
    );
    let transform = GovernedTransform {
        contract_version: CONTRACT_VERSION.into(),
        namespace: NAMESPACE.into(),
        transform_id: format!("{prefix}-iso"),
        input_dataset_id: format!("{prefix}-in"),
        output_dataset_id: format!("{prefix}-out"),
        steps: Vec::new(),
        quality_rule: String::new(),
        definition_digest: String::new(),
        analytical: None,
        isolated_process: Some(IsolatedProcessSpec {
            engine: "python".into(),
            runtime_image: "runner:1".into(),
            inputs: Vec::new(),
        }),
        schedule: None,
        trigger: None,
    }
    .prepare()
    .unwrap();
    db.put_governed_transform(&transform, 10).unwrap();
    db.run_governed_transform(NAMESPACE, &transform.transform_id, false, 20)
        .unwrap();
}

async fn exercise_action(db: RuntimeDb, prefix: &str) {
    seed_action(&db, prefix);
    let plane = ServingPlane::start(db.clone()).await;
    let client = plane.client().await;
    let claim = client.runtime_claim();

    assert!(
        matches!(
            claim
                .claim_next_action("runner-idle", Duration::from_secs(30))
                .await
                .unwrap(),
            ClaimAttempt::Idle
        ),
        "no work for a different runtime is idle"
    );

    let first = match claim
        .claim_next_action("runner-a", Duration::from_secs(30))
        .await
        .unwrap()
    {
        ClaimAttempt::Claimed(claimed) => claimed,
        other => panic!("expected claimed action, got {other:?}"),
    };
    let effect = first.effect.expect("claimed effect");
    let fence = ActionFence::from_effect(&effect, "runner-a");

    let second = claim
        .claim_action_work(&fence.effect_id, "runner-b", Duration::from_secs(30), None)
        .await
        .unwrap();
    assert!(
        matches!(second, ClaimAttempt::Contended),
        "double-claim is contention, not idle: {second:?}"
    );

    claim
        .heartbeat_action(&fence, Duration::from_secs(30))
        .await
        .expect("live fence heartbeat");
    claim
        .ack_action(
            &fence,
            ActionAck::Completed {
                reason: "done".into(),
                artifact_json: String::new(),
            },
        )
        .await
        .expect("ack completed");

    seed_action(&db, &format!("{prefix}-lease"));
    let leased = match claim
        .claim_next_action("runner-a", Duration::from_millis(80))
        .await
        .unwrap()
    {
        ClaimAttempt::Claimed(claimed) => claimed,
        other => panic!("expected short-lease claim, got {other:?}"),
    };
    let lease_fence = ActionFence::from_effect(leased.effect.as_ref().unwrap(), "runner-a");
    tokio::time::sleep(Duration::from_millis(120)).await;
    let lost = claim
        .heartbeat_action(&lease_fence, Duration::from_secs(1))
        .await
        .expect_err("expired lease");
    assert!(
        matches!(lost, RuntimeClaimError::FenceLost),
        "lease expiry is fence loss, not idle: {lost}"
    );
    plane.shutdown().await;
}

async fn exercise_delegator_claim_refusal(db: RuntimeDb, prefix: &str) {
    seed_delegated_action(&db, prefix);
    db.revoke_principal_credential(DELEGATOR).unwrap();
    let plane = ServingPlane::start(db).await;
    let client = plane.client().await;
    let claim = client.runtime_claim();
    let effect_id = format!("{prefix}-effect");

    let targeted = claim
        .claim_action_work(&effect_id, "runner-a", Duration::from_secs(30), None)
        .await
        .expect_err("disabled delegator must not claim");
    assert!(
        matches!(
            targeted,
            RuntimeClaimError::DelegatorRefused(DELEGATOR_DISABLED)
        ),
        "claim client must surface delegator_disabled, got {targeted}"
    );

    let scheduled = claim
        .claim_next_action("runner-a", Duration::from_secs(30))
        .await
        .expect("drained refusal must not keep blocking the queue");
    assert!(
        matches!(scheduled, ClaimAttempt::Idle),
        "scheduled claim must not run after the refused item is drained, got {scheduled:?}"
    );
    plane.shutdown().await;
}

async fn exercise_transform(db: RuntimeDb, prefix: &str) {
    seed_transform(&db, prefix);
    let plane = ServingPlane::start(db.clone()).await;
    let client = plane.client().await;
    let claim = client.runtime_claim();

    let listed = claim.list_transform_work("runner-a", 10).await.unwrap();
    assert_eq!(listed.len(), 1);
    let claimed = match claim
        .claim_transform_work("runner-a", &listed[0].run_id, Duration::from_secs(30))
        .await
        .unwrap()
    {
        ClaimAttempt::Claimed(claimed) => claimed,
        other => panic!("expected claimed transform, got {other:?}"),
    };
    let work = claimed.work.expect("claimed work");
    let fence = TransformFence::from_work(&work, "runner-a");

    let mut stream = claim
        .read_transform_inputs(&fence, "", "", 0, 100)
        .await
        .unwrap();
    let mut rows = Vec::new();
    while let Some(item) = stream.next().await {
        rows.push(item.expect("input row").row.expect("row"));
    }
    assert_eq!(rows.len(), 1);

    let stale = TransformFence {
        fencing_token: "stale-token".into(),
        ..fence.clone()
    };
    let output = vec![HashMap::from([("id".into(), "1".into())])];
    let write = TransformWrite {
        rows: vec![TransformRunInputRow {
            alias: String::new(),
            dataset_id: format!("{prefix}-out"),
            row_id: 0,
            values: output[0].clone(),
        }],
        output_digest: rows_digest(&output),
        quarantined: false,
        quality_rule: String::new(),
    };
    let refused = claim
        .write_transform_result(&stale, write.clone())
        .await
        .expect_err("stale fence");
    assert!(
        matches!(refused, RuntimeClaimError::FenceLost),
        "stale write-back is fence loss: {refused}"
    );

    let written = claim
        .write_transform_result(&fence, write)
        .await
        .unwrap()
        .run
        .expect("completed run");
    assert_eq!(written.dispatch_status, "completed");
    plane.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_runtime_claim_action_conformance() {
    exercise_action(RuntimeDb::memory(), "sqlite-action").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_runtime_claim_refuses_disabled_delegator() {
    exercise_delegator_claim_refusal(RuntimeDb::memory(), "sqlite-delegator").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_runtime_claim_transform_conformance() {
    exercise_transform(RuntimeDb::memory(), "sqlite-transform").await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_runtime_claim_action_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(4)));
    let prefix = format!("pg-a-{}", uuid::Uuid::new_v4().simple());
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(exercise_action(db.clone(), &prefix));
    drop(db);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_runtime_claim_transform_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(4)));
    let prefix = format!("pg-t-{}", uuid::Uuid::new_v4().simple());
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(exercise_transform(db.clone(), &prefix));
    drop(db);
}
