//! `SimulateObjectPolicyChange` reports the Action types a grant change lets
//! a principal propose or decide (#2708), and a real submit after the change
//! is really made gives the same answer, on SQLite and PostgreSQL.

use super::*;

const NS: &str = "acme";
const READER: &str = "j.novak";

fn service_on(db: RuntimeDb) -> SekaiServiceImpl {
    SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(Arc::new(
        db,
    )))
}

async fn put_type(svc: &SekaiServiceImpl, type_id: &str, approvers: &[&str], enabled: bool) {
    let mut definition = intake_action_type("");
    definition.type_id = type_id.into();
    definition.approvers = approvers
        .iter()
        .map(|approver| (*approver).into())
        .collect();
    svc.put_governed_action_type(with_named_principal(
        PutGovernedActionTypeRequest {
            r#type: Some(definition),
            request_id: format!("put-{type_id}"),
        },
        "local",
    ))
    .await
    .unwrap();
    if !enabled {
        svc.set_governed_action_type_enabled(with_named_principal(
            SetGovernedActionTypeEnabledRequest {
                namespace: NS.into(),
                type_id: type_id.into(),
                version: "1.0.0".into(),
                enabled: false,
                ..Default::default()
            },
            "local",
        ))
        .await
        .unwrap();
    }
}

async fn simulate(
    svc: &SekaiServiceImpl,
    add_grants: Vec<CandidateGrant>,
    remove_grant_ids: Vec<String>,
) -> PolicySimulationActionSummary {
    let mut summaries = svc
        .simulate_object_policy_change(with_named_principal(
            SimulateObjectPolicyChangeRequest {
                namespace: NS.into(),
                principals: vec![READER.into()],
                add_grants,
                remove_grant_ids,
                ..Default::default()
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .action_summaries;
    assert_eq!(summaries.len(), 1);
    summaries.remove(0)
}

fn on_boundary(boundary: &str, role: &str) -> CandidateGrant {
    CandidateGrant {
        object_id: boundary.into(),
        principal: READER.into(),
        role: role.into(),
        not_after_ms: 0,
    }
}

async fn real_submit(svc: &SekaiServiceImpl, key: &str) -> Result<(), tonic::Code> {
    svc.submit_action_instance(with_named_principal(
        SubmitActionInstanceRequest {
            namespace: NS.into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            parameters_json: r#"{"summary":"ship it"}"#.into(),
            idempotency_key: key.into(),
            evidence_submission_ids: vec![],
            request_id: format!("req-{key}"),
            ontology_digest: String::new(),
            offline: None,
        },
        READER,
    ))
    .await
    .map(|_| ())
    .map_err(|status| status.code())
}

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

async fn exercise_action_simulation(db: RuntimeDb) {
    let svc = service_on(db);
    // A team-managed namespace, and a reader who is a team principal of
    // another one, so the namespace membership gate applies to it.
    grant_source_namespace(&svc, NS, "alice", security::Role::Admin);
    grant_source_namespace(&svc, "novak-home", READER, security::Role::Admin);
    svc.db
        .runtime()
        .upsert_action_policy(&action_policy::ActionPolicy::allow_all(format!(
            "project:{NS}"
        )))
        .unwrap();
    put_type(&svc, "review.intake", &[], true).await;
    put_type(&svc, "review.escalate", &[], true).await;
    // Named approvers decide without any grant; a disabled type is never
    // proposable or decidable.
    put_type(&svc, "review.audit", &[READER], true).await;
    put_type(&svc, "review.retired", &[], false).await;
    let boundary = svc
        .db
        .runtime()
        .find_namespace_boundary(NS)
        .unwrap()
        .unwrap()
        .id;
    assert_eq!(
        real_submit(&svc, "before").await,
        Err(tonic::Code::PermissionDenied)
    );

    let editor = simulate(&svc, vec![on_boundary(&boundary, "editor")], vec![]).await;
    assert!(editor.current_proposable_type_ids.is_empty());
    let all = ids(&["review.audit", "review.escalate", "review.intake"]);
    assert_eq!(editor.candidate_proposable_type_ids, all);
    assert_eq!(editor.current_runnable_type_ids, ids(&["review.audit"]));
    assert_eq!(editor.candidate_runnable_type_ids, ids(&["review.audit"]));

    let admin = simulate(&svc, vec![on_boundary(&boundary, "admin")], vec![]).await;
    assert_eq!(admin.candidate_proposable_type_ids, all);
    assert_eq!(admin.candidate_runnable_type_ids, all);

    // Made for real, the simulated grant lets the reader propose.
    grant_source_namespace(&svc, NS, READER, security::Role::Editor);
    assert_eq!(real_submit(&svc, "granted").await, Ok(()));
    let grant_id = svc
        .db
        .runtime()
        .list_grants(&boundary)
        .unwrap()
        .into_iter()
        .find(|grant| grant.principal == READER)
        .unwrap()
        .id;

    let removal = simulate(&svc, vec![], vec![grant_id.clone()]).await;
    assert_eq!(removal.current_proposable_type_ids, all);
    assert!(removal.candidate_proposable_type_ids.is_empty());
    assert_eq!(removal.candidate_runnable_type_ids, ids(&["review.audit"]));

    // Removed for real, the reader may no longer propose.
    svc.delete_grant(with_named_principal(
        DeleteGrantRequest { id: grant_id },
        "local",
    ))
    .await
    .unwrap();
    assert_eq!(
        real_submit(&svc, "revoked").await,
        Err(tonic::Code::PermissionDenied)
    );
}

#[tokio::test]
async fn simulated_grant_changes_match_real_action_proposals() {
    exercise_action_simulation(RuntimeDb::memory()).await;
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_simulated_grant_changes_match_real_action_proposals() {
    let scratch = crate::db::ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(exercise_action_simulation(db.clone()));
    drop(db);
}
