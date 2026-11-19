//! Retained judge rationale reads (#2630): only a principal cleared for every
//! source evidence object reads it, and it goes away at its TTL or with its
//! source.

use super::*;
use crate::chisei::evaluation_rationale::{
    EvaluationRationale, EvaluationRationaleStore, sweep_evaluation_rationales,
};
use crate::sekai::markings;
use crate::sekai::security::{Grant, Role};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A service whose namespace `acme` admits `alice` (cleared for
/// confidential) and `bob` (not cleared), holding one confidential evidence
/// object `ev-1`.
fn service() -> ChiseiServiceImpl {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let chisei = crate::chisei_store::ChiseiStore::from_shared_runtime(db.clone());
    let svc = ChiseiServiceImpl::new(chisei, super::tests::config(":memory:"))
        .with_sekai_facts(crate::chisei::sekai_facts::SekaiFacts::in_process(
            crate::db::store::SekaiStore::from_shared_runtime(db.clone()),
        ))
        .unwrap();
    for member in ["alice", "bob"] {
        db.ensure_team_namespace("acme", member, Role::Viewer, "local")
            .unwrap();
    }
    db.create_object(&Object {
        id: "principal-alice".into(),
        kind: markings::PRINCIPAL_PROFILE_KIND.into(),
        name: "alice".into(),
        namespace: "acme".into(),
        external_id: markings::principal_profile_external_id("alice"),
        properties: HashMap::from([
            (
                markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                "confidential".into(),
            ),
            (
                markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.into(),
                "true".into(),
            ),
        ]),
        created: 0,
        updated: 0,
    })
    .unwrap();
    db.create_grant(&Grant {
        id: "profile-admin".into(),
        object_id: "principal-alice".into(),
        principal: "root".into(),
        role: Role::Admin,
        created: 1,
        ..Default::default()
    })
    .unwrap();
    db.create_object(&evidence("available")).unwrap();
    svc
}

fn evidence(lifecycle_state: &str) -> Object {
    Object {
        id: "ev-1".into(),
        kind: "evidence".into(),
        name: "ev-1".into(),
        namespace: "acme".into(),
        external_id: String::new(),
        properties: HashMap::from([
            (
                markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                "confidential".into(),
            ),
            ("lifecycle_state".into(), lifecycle_state.into()),
        ]),
        created: 0,
        updated: 0,
    }
}

fn retain(svc: &ChiseiServiceImpl, trial_index: u32, expires_at_ms: i64) {
    svc.db
        .runtime()
        .put_evaluation_rationales(&[EvaluationRationale {
            operation_id: evaluation_execution_domain::execution_operation_id(DIGEST),
            node_id: "judge".into(),
            trial_index,
            namespace: "acme".into(),
            rationale: "cites the refund clause".into(),
            rationale_digest: "sha256:rationale".into(),
            evidence_object_ids: vec!["ev-1".into()],
            classification: "confidential".into(),
            created_at_ms: 0,
            expires_at_ms,
        }])
        .unwrap();
}

fn stored(svc: &ChiseiServiceImpl, trial_index: u32) -> bool {
    svc.db
        .runtime()
        .get_evaluation_rationale(
            &evaluation_execution_domain::execution_operation_id(DIGEST),
            "judge",
            trial_index,
        )
        .unwrap()
        .is_some()
}

async fn read(
    svc: &ChiseiServiceImpl,
    principal: &str,
    trial_index: u32,
) -> Result<GetEvaluationRationaleResponse, Status> {
    let mut request = Request::new(GetEvaluationRationaleRequest {
        namespace: "acme".into(),
        manifest_digest: DIGEST.into(),
        node_id: "judge".into(),
        trial_index,
    });
    request
        .metadata_mut()
        .insert("x-principal", principal.parse().unwrap());
    svc.get_evaluation_rationale(request)
        .await
        .map(Response::into_inner)
}

fn far_future() -> i64 {
    chrono::Utc::now().timestamp_millis() + 60_000
}

#[tokio::test]
async fn only_a_principal_cleared_for_the_evidence_reads_the_rationale() {
    let svc = service();
    retain(&svc, 0, far_future());

    let shown = read(&svc, "alice", 0).await.unwrap();
    assert_eq!(shown.rationale, "cites the refund clause");
    assert_eq!(shown.classification, "confidential");
    let audited = svc
        .db
        .runtime()
        .list_decisions(&crate::sekai::audit::DecisionFilter {
            action: Some("evaluation_rationale/read".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].actor, "alice");

    // Denied clearance reads as missing; no namespace grant is refused.
    assert_eq!(
        read(&svc, "bob", 0).await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    assert_eq!(
        read(&svc, "mallory", 0).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert!(stored(&svc, 0), "a refused read keeps the rationale");
}

#[tokio::test]
async fn an_expired_rationale_is_gone_on_read_and_by_sweep() {
    let svc = service();
    retain(&svc, 0, 1);
    retain(&svc, 1, 1);
    assert_eq!(
        read(&svc, "alice", 0).await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    assert!(!stored(&svc, 0));
    let removed = sweep_evaluation_rationales(
        svc.db.runtime(),
        svc.sekai_facts.reader(),
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    assert_eq!(removed, 1);
    assert!(!stored(&svc, 1));
}

#[tokio::test]
async fn a_rationale_goes_away_with_its_source_evidence() {
    let svc = service();
    retain(&svc, 0, far_future());
    retain(&svc, 1, far_future());
    let now = chrono::Utc::now().timestamp_millis();
    assert_eq!(
        sweep_evaluation_rationales(svc.db.runtime(), svc.sekai_facts.reader(), now).unwrap(),
        0
    );

    // A retracted source withdraws the rationale on read.
    svc.db
        .runtime()
        .update_object(&evidence("retracted"))
        .unwrap();
    assert_eq!(
        read(&svc, "alice", 0).await.unwrap_err().code(),
        tonic::Code::NotFound
    );
    assert!(!stored(&svc, 0));

    // A deleted source withdraws it in the sweep.
    svc.db.runtime().delete_object("ev-1").unwrap();
    assert_eq!(
        sweep_evaluation_rationales(svc.db.runtime(), svc.sekai_facts.reader(), now).unwrap(),
        1
    );
    assert!(!stored(&svc, 1));
}
