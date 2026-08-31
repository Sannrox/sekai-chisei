#[path = "../adapters/model_messages.rs"]
mod model_messages;
#[path = "../adapters/model_responses.rs"]
mod model_responses;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::model_platform::{
    MODEL_UNAVAILABLE, PROFILE_MESSAGES, PROFILE_RESPONSES, STATUS_REVOKED, certify_model_platform,
    revoke_model_platform, verify_model_platform,
};

fn adapter_lifecycle(adapter_id: &str) {
    let db = RuntimeDb::memory();
    let certification = if adapter_id == PROFILE_RESPONSES {
        model_responses::translate_certification(
            &model_responses::parse(include_bytes!("../adapters/fixtures/model_responses.json"))
                .unwrap(),
        )
        .unwrap()
    } else {
        model_messages::translate_certification(
            &model_messages::parse(include_bytes!("../adapters/fixtures/model_messages.json"))
                .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(certification.adapter_id, adapter_id);
    let certified = certify_model_platform(&db, "integrator", &certification, 1_000).unwrap();
    assert!(!certified.evidence_digest.is_empty());
    assert_eq!(
        certify_model_platform(&db, "integrator", &certified, 1_100)
            .unwrap()
            .evidence_digest,
        certified.evidence_digest
    );
    verify_model_platform(
        &db,
        "integrator",
        "ops",
        &certified.certification_id,
        &certified,
    )
    .unwrap();
    let mut missing_support = certification.clone();
    missing_support.certification_id = format!("{}-missing", certification.certification_id);
    missing_support.evidence_id = format!("ev:{}", missing_support.certification_id);
    missing_support.protocol.capability.supported = vec!["streaming".into()];
    assert_eq!(
        certify_model_platform(&db, "integrator", &missing_support, 1_900).unwrap_err(),
        MODEL_UNAVAILABLE
    );
    let mut unsupported = certification.clone();
    unsupported.certification_id = format!("{}-cap", certification.certification_id);
    unsupported.evidence_id = format!("ev:{}", unsupported.certification_id);
    unsupported.protocol.capability.requested = vec!["batch".into()];
    assert_eq!(
        certify_model_platform(&db, "integrator", &unsupported, 2_000).unwrap_err(),
        MODEL_UNAVAILABLE
    );
    let mut ambiguous = certification.clone();
    ambiguous.certification_id = format!("{}-usage", certification.certification_id);
    ambiguous.evidence_id = format!("ev:{}", ambiguous.certification_id);
    ambiguous.protocol.usage.ambiguous = true;
    assert_eq!(
        certify_model_platform(&db, "integrator", &ambiguous, 2_100).unwrap_err(),
        MODEL_UNAVAILABLE
    );
    let revoked =
        revoke_model_platform(&db, "integrator", "ops", &certified.certification_id, 3_000)
            .unwrap();
    assert_eq!(revoked.status, STATUS_REVOKED);
    assert_eq!(
        verify_model_platform(
            &db,
            "integrator",
            "ops",
            &certified.certification_id,
            &certified
        )
        .unwrap_err(),
        MODEL_UNAVAILABLE
    );
}

#[test]
fn two_adapters_pass_deterministic_protocol_fixtures() {
    adapter_lifecycle(PROFILE_RESPONSES);
    adapter_lifecycle(PROFILE_MESSAGES);
}

#[test]
fn hidden_fields_fail_closed() {
    let mut responses: serde_json::Value =
        serde_json::from_slice(include_bytes!("../adapters/fixtures/model_responses.json"))
            .unwrap();
    responses
        .as_object_mut()
        .unwrap()
        .insert("token".into(), serde_json::json!("sk-live"));
    assert!(model_responses::parse(&serde_json::to_vec(&responses).unwrap()).is_err());
    assert_eq!(model_responses::ADAPTER_ID, PROFILE_RESPONSES);
    assert_eq!(model_messages::ADAPTER_ID, PROFILE_MESSAGES);
}
