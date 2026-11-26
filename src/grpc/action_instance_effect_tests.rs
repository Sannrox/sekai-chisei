//! `PreviewActionInstanceEffect` and the effect-bound grant (#3085): an
//! approver reads what a parked instance would write, and a grant bound to
//! that read refuses once the write would differ.

use super::*;

/// Parks `plan.a` (retitle `cust-plan` to `vip`) for alice or bob; returns
/// the instance id.
async fn parked_retitle(svc: &SekaiServiceImpl) -> String {
    let steps = plan_review_fixture(svc);
    let mut require_approval = action_policy::ActionPolicy::allow_all("agent:tester");
    require_approval.action_overrides.insert(
        crate::sekai::action_instance::SUBMIT_POLICY_ACTION.into(),
        action_policy::ActionDecision::RequireApproval,
    );
    svc.db
        .runtime()
        .upsert_action_policy(&require_approval)
        .unwrap();
    let instance = svc
        .submit_action_instance(with_principal(SubmitActionInstanceRequest {
            namespace: "acme".into(),
            type_id: steps[0].type_id.clone(),
            version: steps[0].version.clone(),
            parameters_json: steps[0].parameters_json.clone(),
            idempotency_key: "effect-1".into(),
            request_id: "req-effect-1".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .instance
        .unwrap();
    assert_eq!(
        instance.status,
        crate::sekai::action_instance::STATUS_PARKED
    );
    instance.instance_id
}

async fn preview(
    svc: &SekaiServiceImpl,
    instance_id: &str,
    principal: &str,
) -> Result<PreviewActionInstanceEffectResponse, Status> {
    svc.preview_action_instance_effect(as_decider(
        PreviewActionInstanceEffectRequest {
            instance_id: instance_id.into(),
        },
        principal,
    ))
    .await
    .map(Response::into_inner)
}

async fn grant(
    svc: &SekaiServiceImpl,
    instance_id: &str,
    expected_effect_digest: &str,
) -> Result<ActionInstance, Status> {
    svc.decide_action_instance(as_decider(
        DecideActionInstanceRequest {
            instance_id: instance_id.into(),
            decision: "grant".into(),
            reason: String::new(),
            expected_effect_digest: expected_effect_digest.into(),
        },
        "alice",
    ))
    .await
    .map(|response| response.into_inner().instance.unwrap())
}

/// Changes `cust-plan` behind the approver's back.
fn retitle_elsewhere(svc: &SekaiServiceImpl) {
    let db = svc.db.runtime();
    let mut object = db.get_object("cust-plan").unwrap().unwrap();
    object.properties.insert("title".into(), "churned".into());
    object.updated += 1;
    db.update_object(&object).unwrap();
}

#[tokio::test]
async fn an_approver_reads_the_write_a_parked_instance_would_make() {
    let svc = service();
    let instance_id = parked_retitle(&svc).await;

    let read = preview(&svc, &instance_id, "alice").await.unwrap();
    assert_eq!(read.object_id, "cust-plan");
    let effect = read.effect.clone().unwrap();
    assert_eq!(effect.mutation, "update");
    assert_eq!(effect.changed_properties, ["title"]);
    assert_eq!(read.withheld_properties, 0);
    assert!(read.effect_digest.starts_with("sha256:"));
    // The read applies nothing.
    let object = svc.db.runtime().get_object("cust-plan").unwrap().unwrap();
    assert_eq!(object.properties["title"], "account");
    assert_eq!(
        preview(&svc, &instance_id, "alice")
            .await
            .unwrap()
            .effect_digest,
        read.effect_digest
    );

    // Someone who may not decide or read the instance learns nothing.
    let outsider = preview(&svc, &instance_id, "carol").await.unwrap_err();
    assert_eq!(outsider.code(), tonic::Code::PermissionDenied);

    // A property the approver may not read is counted, not named, and the
    // digest still covers it.
    svc.create_schema_type(with_named_principal(
        CreateSchemaTypeRequest {
            r#type: Some(ObjectType {
                kind: "customer_record".into(),
                description: "fixture".into(),
                properties: vec![PropertyDef {
                    name: "title".into(),
                    r#type: "string".into(),
                    classification: "sensitive".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        },
        "root",
    ))
    .await
    .unwrap();
    let redacted = preview(&svc, &instance_id, "alice").await.unwrap();
    assert!(redacted.effect.unwrap().changed_properties.is_empty());
    assert_eq!(redacted.withheld_properties, 1);
    assert_eq!(redacted.effect_digest, read.effect_digest);
}

#[tokio::test]
async fn a_grant_bound_to_the_read_effect_admits_and_records_it() {
    let svc = service();
    let instance_id = parked_retitle(&svc).await;
    let digest = preview(&svc, &instance_id, "alice")
        .await
        .unwrap()
        .effect_digest;

    let granted = grant(&svc, &instance_id, &digest).await.unwrap();
    assert_eq!(
        granted.status,
        crate::sekai::action_instance::STATUS_ADMITTED
    );
    let receipt = svc
        .db
        .runtime()
        .get_operation_receipt(&granted.operation_id)
        .unwrap()
        .expect("decision receipt");
    let approval = receipt
        .events
        .iter()
        .find(|event| event.kind == sekai_domain::receipt::ReceiptEventKind::ApprovalDecided)
        .unwrap();
    assert_eq!(approval.attributes["effect_digest"], digest);

    // A decided instance has no pending effect to read.
    let decided = preview(&svc, &instance_id, "alice").await.unwrap_err();
    assert_eq!(decided.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn a_grant_bound_to_a_stale_effect_is_refused_and_changes_nothing() {
    let svc = service();
    let instance_id = parked_retitle(&svc).await;
    let digest = preview(&svc, &instance_id, "alice")
        .await
        .unwrap()
        .effect_digest;
    retitle_elsewhere(&svc);

    let refused = grant(&svc, &instance_id, &digest).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert!(
        refused.message().starts_with("action_effect_changed"),
        "{}",
        refused.message()
    );
    let stored = svc
        .db
        .runtime()
        .get_action_instance(&instance_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, crate::sekai::action_instance::STATUS_PARKED);

    // Reading again gives the approver the current effect to bind to.
    let fresh = preview(&svc, &instance_id, "alice")
        .await
        .unwrap()
        .effect_digest;
    assert_ne!(fresh, digest);
}

#[tokio::test]
async fn a_decision_without_a_digest_decides_as_before() {
    let svc = service();
    let instance_id = parked_retitle(&svc).await;

    let granted = grant(&svc, &instance_id, "").await.unwrap();
    assert_eq!(
        granted.status,
        crate::sekai::action_instance::STATUS_ADMITTED
    );
    let receipt = svc
        .db
        .runtime()
        .get_operation_receipt(&granted.operation_id)
        .unwrap()
        .unwrap();
    assert!(receipt.events.iter().all(|event| {
        event.kind != sekai_domain::receipt::ReceiptEventKind::ApprovalDecided
            || !event.attributes.contains_key("effect_digest")
    }));
}
