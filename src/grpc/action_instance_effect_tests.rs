//! `PreviewActionInstanceEffect` and the effect-bound grant (#3085, creates
//! in #3528): an
//! approver reads what a parked instance would write, and a grant bound to
//! that read refuses once the write would differ.

use super::*;

/// Parks `type_id` version 1 with `parameters_json`, submitted by `tester`
/// under a policy that sends every submit to approval; returns its id.
async fn park(svc: &SekaiServiceImpl, type_id: &str, parameters_json: &str) -> String {
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
            type_id: type_id.into(),
            version: "1".into(),
            parameters_json: parameters_json.into(),
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

/// Parks `plan.a` (retitle `cust-plan` to `vip`) for alice or bob; returns
/// the instance id.
async fn parked_retitle(svc: &SekaiServiceImpl) -> String {
    let steps = plan_review_fixture(svc);
    park(svc, &steps[0].type_id, &steps[0].parameters_json).await
}

/// Parks `plan.create`, which adds `cust-new` titled `vip`, for alice;
/// returns the instance id.
async fn parked_create(svc: &SekaiServiceImpl) -> String {
    plan_review_fixture(svc);
    svc.db
        .runtime()
        .put_governed_action_type(
            crate::sekai::governed_action_type::GovernedActionType {
                namespace: "acme".into(),
                type_id: "plan.create".into(),
                version: "1".into(),
                description: "Add one customer".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"title":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec!["notify".into()],
                object_kind: "customer_record".into(),
                object_mutation: crate::sekai::governed_action_type::OBJECT_MUTATION_CREATE
                    .into(),
                enabled: true,
                approvers: vec!["alice".into()],
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
    park(
        svc,
        "plan.create",
        r#"{"object_id":"cust-new","title":"vip"}"#,
    )
    .await
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

#[tokio::test]
async fn an_approver_reads_the_object_a_parked_create_would_add() {
    let svc = service();
    let instance_id = parked_create(&svc).await;

    let read = preview(&svc, &instance_id, "alice").await.unwrap();
    assert_eq!(read.outcome, "valid");
    assert_eq!(read.object_id, "cust-new");
    let effect = read.effect.clone().unwrap();
    assert_eq!(effect.mutation, "create");
    assert_eq!(effect.object_kind, "customer_record");
    assert_eq!(effect.changed_properties, ["_name", "title"]);
    assert_eq!(read.withheld_properties, 0);
    assert!(svc.db.runtime().get_object("cust-new").unwrap().is_none());

    // Nobody holds grants on an object that does not exist yet, so a
    // restricted property it would set is counted for the approver.
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
    assert_eq!(redacted.effect.unwrap().changed_properties, ["_name"]);
    assert_eq!(redacted.withheld_properties, 1);
    assert_eq!(redacted.effect_digest, read.effect_digest);

    let granted = grant(&svc, &instance_id, &read.effect_digest)
        .await
        .unwrap();
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
    let approval = receipt
        .events
        .iter()
        .find(|event| event.kind == sekai_domain::receipt::ReceiptEventKind::ApprovalDecided)
        .unwrap();
    assert_eq!(approval.attributes["effect_digest"], read.effect_digest);
}

#[tokio::test]
async fn a_create_grant_is_refused_once_its_object_id_is_taken() {
    let svc = service();
    let instance_id = parked_create(&svc).await;
    let digest = preview(&svc, &instance_id, "alice")
        .await
        .unwrap()
        .effect_digest;
    let mut taken = svc.db.runtime().get_object("cust-plan").unwrap().unwrap();
    taken.id = "cust-new".into();
    svc.db.runtime().create_object(&taken).unwrap();

    let read = preview(&svc, &instance_id, "alice").await.unwrap();
    assert_eq!(read.outcome, "invalid");
    assert!(read.effect.is_none());
    assert_ne!(read.effect_digest, digest);
    let refused = grant(&svc, &instance_id, &digest).await.unwrap_err();
    assert!(
        refused.message().starts_with("action_effect_changed"),
        "{}",
        refused.message()
    );
}
