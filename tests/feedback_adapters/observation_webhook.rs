//! Signed Tenkai feedback webhook deliveries recorded through the reference
//! receiver against an in-process plane (#2176).

use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

use crate::feedback_observation_webhook::{
    Delivery, EVENT, Observation, ObservationPlane, Operation, Reason, ReceiveError, Receiver,
    Refusal, SOURCE_TYPE, TENKAI_SCHEMA_JSON, TENKAI_SCHEMA_SHA256,
};
use crate::sdk;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::pb::sekai::{
    SubmitActionInstanceRequest, SubmitActionInstanceResponse, SubmitEvidenceRequest,
    SubmitEvidenceResponse,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::evidence::{EvidenceClassification, EvidenceIntent};
use sekai_chisei::sekai::evidence_store::{EvidenceProducerCapability, EvidenceSubmissionFilter};
use sekai_chisei::sekai::feedback_package::{EVIDENCE_TYPE, KIND_OBSERVATION, install};
use sekai_chisei::sekai::security::Role;
use sekai_domain::domain::ListFilter;

const NAMESPACE: &str = "ops";
const OPERATOR: &str = "local";
const RECEIVER: &str = "producer:tenkai-webhook";
const SOURCE_INSTANCE: &str = "tenkai:prod";
const SECRET: &[u8] = b"webhook-secret";
const KEY: &str = "outbox-7f3a";

struct Plane {
    db: Arc<RuntimeDb>,
    sekai: SekaiServiceImpl,
}

fn plane() -> Plane {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").unwrap(),
    )));
    let now = now_ms();
    for (principal, role) in [(OPERATOR, Role::Admin), (RECEIVER, Role::Editor)] {
        db.ensure_team_namespace(NAMESPACE, principal, role, OPERATOR)
            .unwrap();
    }
    install(&db, NAMESPACE, OPERATOR, now).unwrap();
    db.upsert_evidence_producer(&producer(), now).unwrap();
    let store = sekai_chisei::db::store::SekaiStore::from_shared_runtime(db.clone());
    Plane {
        db,
        sekai: SekaiServiceImpl::new(store),
    }
}

fn producer() -> EvidenceProducerCapability {
    EvidenceProducerCapability {
        producer_identity: RECEIVER.into(),
        config_version: 1,
        source_types: vec![SOURCE_TYPE.into()],
        source_instances: vec![SOURCE_INSTANCE.into()],
        namespaces: vec![NAMESPACE.into()],
        evidence_types: vec![EVIDENCE_TYPE.into()],
        target_kinds: vec![KIND_OBSERVATION.into()],
        classification_ceiling: EvidenceClassification::Confidential,
        allowed_intents: vec![EvidenceIntent::Upsert],
        allow_operation_attachment: true,
        replay_window_ms: 600_000,
        max_clock_skew_ms: 600_000,
        max_payload_bytes: 4_096,
        max_relationships: 4,
        rate_limit_per_minute: 1_000,
        max_retained_submissions: 1_000,
        revoked: false,
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn receiver(outbox: &tempfile::TempDir) -> Receiver {
    Receiver {
        secret: SECRET.to_vec(),
        producer: RECEIVER.into(),
        source_instance: SOURCE_INSTANCE.into(),
        namespace: NAMESPACE.into(),
        outbox: outbox.path().join("outbox"),
    }
}

/// A failed apply attempt, shaped as Tenkai posts it.
fn observation_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "tenkai.feedback_observation.v1",
        "id": "attempt-41",
        "operation": "apply_step",
        "environment": "prod",
        "product": "api",
        "plan_id": "plan-9",
        "step_id": "step-2",
        "action": "apply",
        "release_id": "rel-5",
        "status": "failed",
        "reason": "tenkai_failed",
        "duration_ms": 1200,
        "controller_version": "1.9.0",
        "lease_generation": 3,
        "observed_at_ms": now_ms(),
        "context": {"takeover": true}
    }))
    .unwrap()
}

fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(body);
    format!("sha256={:x}", mac.finalize().into_bytes())
}

fn delivery(body: Vec<u8>) -> Delivery {
    let signature = sign(SECRET, &body);
    Delivery::from_headers(
        body,
        [
            ("X-Tenkai-Signature", signature.as_str()),
            ("X-Tenkai-Signature-Alg", "hmac-sha256"),
            ("X-Tenkai-Event", EVENT),
            ("X-Tenkai-Idempotency-Key", KEY),
        ],
    )
}

fn submissions(db: &RuntimeDb) -> usize {
    db.list_evidence_submissions(&EvidenceSubmissionFilter {
        producer_identity: Some(RECEIVER.into()),
        limit: 100,
        ..Default::default()
    })
    .unwrap()
    .len()
}

fn observations(db: &RuntimeDb) -> Vec<sekai_domain::domain::Object> {
    db.list_objects(&ListFilter {
        kind: Some(KIND_OBSERVATION.into()),
        namespace: Some(NAMESPACE.into()),
        limit: 100,
        ..Default::default()
    })
    .unwrap()
}

/// Delegates to the real plane, counting calls and optionally failing the
/// Action call the way a crash between the two RPCs would.
struct Faulty<'a> {
    plane: &'a SekaiServiceImpl,
    fail_evidence: bool,
    fail_action: bool,
    calls: Cell<usize>,
}

impl<'a> Faulty<'a> {
    fn new(plane: &'a SekaiServiceImpl, fail_action: bool) -> Self {
        Self {
            plane,
            fail_evidence: false,
            fail_action,
            calls: Cell::new(0),
        }
    }

    fn evidence_outage(plane: &'a SekaiServiceImpl) -> Self {
        Self {
            fail_evidence: true,
            ..Self::new(plane, false)
        }
    }
}

impl ObservationPlane for Faulty<'_> {
    async fn submit_evidence(
        &self,
        request: Request<SubmitEvidenceRequest>,
    ) -> Result<Response<SubmitEvidenceResponse>, Status> {
        self.calls.set(self.calls.get() + 1);
        if self.fail_evidence {
            return Err(Status::unavailable("plane down"));
        }
        ObservationPlane::submit_evidence(self.plane, request).await
    }

    async fn submit_action_instance(
        &self,
        request: Request<SubmitActionInstanceRequest>,
    ) -> Result<Response<SubmitActionInstanceResponse>, Status> {
        self.calls.set(self.calls.get() + 1);
        if self.fail_action {
            return Err(Status::unavailable("receiver crashed"));
        }
        ObservationPlane::submit_action_instance(self.plane, request).await
    }
}

#[tokio::test]
async fn a_signed_delivery_records_evidence_and_one_observation() {
    let plane = plane();
    let outbox = tempfile::tempdir().unwrap();
    let recorded = receiver(&outbox)
        .receive(&plane.sekai, &delivery(observation_body()), now_ms())
        .await
        .unwrap();
    assert!(!recorded.replay);

    let observations = observations(&plane.db);
    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert_eq!(observation.id, "attempt-41");
    let property = |name: &str| observation.properties.get(name).cloned();
    assert_eq!(
        property("problem_signature"),
        Some("api:tenkai_failed".into())
    );
    assert_eq!(property("operation_id"), Some("plan-9".into()));
    assert_eq!(property("scope"), Some("prod".into()));
    assert_eq!(property("classification"), Some("defect".into()));
    let stored = serde_json::to_string(&observation.properties).unwrap();
    assert!(
        !stored.contains("webhook-secret") && !stored.contains(RECEIVER),
        "receiver credentials never reach object properties: {stored}"
    );
}

#[tokio::test]
async fn a_tampered_body_or_wrong_secret_is_refused_before_any_plane_call() {
    let plane = plane();
    let outbox = tempfile::tempdir().unwrap();
    let receiver = receiver(&outbox);
    let counting = Faulty::new(&plane.sekai, false);

    let mut tampered = delivery(observation_body());
    tampered.body = String::from_utf8(tampered.body)
        .unwrap()
        .replace("tenkai_failed", "none")
        .into_bytes();
    let mut wrong_secret = delivery(observation_body());
    wrong_secret.signature = Some(sign(b"other-secret", &wrong_secret.body));
    let mut unsigned = delivery(observation_body());
    unsigned.signature = None;

    for (refused, expected) in [
        (tampered, Refusal::BadSignature),
        (wrong_secret, Refusal::BadSignature),
        (unsigned, Refusal::MissingSignature),
    ] {
        match receiver.receive(&counting, &refused, now_ms()).await {
            Err(ReceiveError::Refused(refusal)) => assert_eq!(refusal, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }
    assert_eq!(counting.calls.get(), 0);
    assert_eq!(submissions(&plane.db), 0);
}

#[tokio::test]
async fn a_body_that_fails_the_schema_is_refused_with_a_typed_reason_and_no_writes() {
    let plane = plane();
    let outbox = tempfile::tempdir().unwrap();
    let receiver = receiver(&outbox);
    let counting = Faulty::new(&plane.sekai, false);
    let mut body: Value = serde_json::from_slice(&observation_body()).unwrap();
    let cases = [
        ("reason", json!("exploded")),
        ("schema", json!("tenkai.feedback_observation.v2")),
        ("unexpected_field", json!(1)),
        ("environment", json!("x".repeat(257))),
        ("environment", json!("")),
        ("observed_at_ms", json!(-1)),
        ("duration_ms", Value::Null),
        ("context", Value::Null),
        ("context", json!({"takeover": null})),
    ];
    for (field, value) in cases {
        let mut invalid = body.clone();
        invalid[field] = value;
        let refused = delivery(serde_json::to_vec(&invalid).unwrap());
        match receiver.receive(&counting, &refused, now_ms()).await {
            Err(ReceiveError::Refused(refusal)) => {
                assert_eq!(refusal.code(), "observation_invalid", "{field}");
            }
            other => panic!("{field}: expected a schema refusal, got {other:?}"),
        }
    }
    body.as_object_mut().unwrap().remove("lease_generation");
    let missing = delivery(serde_json::to_vec(&body).unwrap());
    assert!(matches!(
        receiver.receive(&counting, &missing, now_ms()).await,
        Err(ReceiveError::Refused(Refusal::InvalidObservation(_)))
    ));
    assert_eq!(counting.calls.get(), 0);
    assert_eq!(submissions(&plane.db), 0);
    assert!(observations(&plane.db).is_empty());
}

#[tokio::test]
async fn a_redelivered_event_creates_one_submission_and_one_observation() {
    let plane = plane();
    let outbox = tempfile::tempdir().unwrap();
    let receiver = receiver(&outbox);
    let event = delivery(observation_body());

    let first = receiver
        .receive(&plane.sekai, &event, now_ms())
        .await
        .unwrap();
    // Tenkai retries with the same bytes and key after the receiver already
    // completed the first delivery, more often than the plane allows
    // delivery aliases for one submission.
    for retry in 1..=20 {
        let again = receiver
            .receive(&plane.sekai, &event, now_ms() + retry * 1_000)
            .await
            .unwrap();
        assert!(again.replay);
        assert_eq!(first.evidence_submission_id, again.evidence_submission_id);
        assert_eq!(first.action_instance_id, again.action_instance_id);
    }
    assert_eq!(submissions(&plane.db), 1);
    assert_eq!(observations(&plane.db).len(), 1);
}

#[tokio::test]
async fn a_crash_between_evidence_and_action_replays_into_the_same_observation() {
    let plane = plane();
    let outbox = tempfile::tempdir().unwrap();
    let receiver = receiver(&outbox);
    let event = delivery(observation_body());

    let crashed = Faulty::new(&plane.sekai, true);
    assert!(matches!(
        receiver.receive(&crashed, &event, now_ms()).await,
        Err(ReceiveError::Plane(_))
    ));
    assert_eq!(submissions(&plane.db), 1);
    assert!(observations(&plane.db).is_empty());

    // The restarted receiver finishes the pending delivery from its outbox.
    let replayed = receiver
        .replay_pending(&plane.sekai, now_ms())
        .await
        .unwrap();
    assert_eq!(replayed.len(), 1);
    let replayed = replayed.into_iter().next().unwrap().unwrap();
    assert!(
        receiver
            .replay_pending(&plane.sekai, now_ms())
            .await
            .unwrap()
            .is_empty()
    );

    // Tenkai's retry of the same delivery lands on the same records.
    let retried = receiver
        .receive(&plane.sekai, &event, now_ms())
        .await
        .unwrap();
    assert_eq!(retried.action_instance_id, replayed.action_instance_id);
    assert_eq!(submissions(&plane.db), 1);
    assert_eq!(observations(&plane.db).len(), 1);
}

#[tokio::test]
async fn a_corrupt_pending_entry_does_not_block_the_others() {
    let plane = plane();
    let outbox = tempfile::tempdir().unwrap();
    let receiver = receiver(&outbox);
    let event = delivery(observation_body());

    let crashed = Faulty::new(&plane.sekai, true);
    assert!(receiver.receive(&crashed, &event, now_ms()).await.is_err());
    // Sorts before the healthy entry.
    std::fs::write(receiver.outbox.join("0-corrupt.bin"), b"not an envelope").unwrap();

    let results = receiver
        .replay_pending(&plane.sekai, now_ms())
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(matches!(results[0], Err(ReceiveError::Outbox(_))));
    assert!(results[1].is_ok());
    assert_eq!(observations(&plane.db).len(), 1);
}

#[tokio::test]
async fn two_workers_completing_one_entry_both_succeed() {
    let plane = plane();
    let outbox = tempfile::tempdir().unwrap();
    let receiver = receiver(&outbox);
    let crashed = Faulty::new(&plane.sekai, true);
    assert!(
        receiver
            .receive(&crashed, &delivery(observation_body()), now_ms())
            .await
            .is_err()
    );

    // A redelivery and a replay pick up the same pending entry.
    let mut first = sdk::pending_deliveries(&receiver.outbox).unwrap();
    let mut second = sdk::pending_deliveries(&receiver.outbox).unwrap();
    let (_, first) = first.remove(0).unwrap();
    let (_, second) = second.remove(0).unwrap();
    first.complete().unwrap();
    second.complete().unwrap();
    assert!(
        sdk::pending_deliveries(&receiver.outbox)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_delivery_held_past_the_replay_window_is_recorded_after_the_outage() {
    let plane = plane();
    let outbox = tempfile::tempdir().unwrap();
    let receiver = receiver(&outbox);
    let event = delivery(observation_body());
    let window = producer().replay_window_ms;

    // The plane is down when the delivery arrives; the receiver keeps it.
    let down = Faulty::evidence_outage(&plane.sekai);
    let received_at = now_ms() - 2 * window;
    assert!(matches!(
        receiver.receive(&down, &event, received_at).await,
        Err(ReceiveError::Plane(_))
    ));

    let (stale, stale_receipt) = sdk::pending_deliveries(&receiver.outbox)
        .unwrap()
        .remove(0)
        .unwrap();

    // Back after more than a replay window: the stale entry is collected
    // again instead of being rejected forever.
    let results = receiver
        .replay_pending(&plane.sekai, now_ms())
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    let recorded = results.into_iter().next().unwrap().unwrap();
    assert_eq!(observations(&plane.db).len(), 1);

    // A slower worker that loaded the same stale entry gets the admitted
    // envelope back instead of minting another key.
    let late = sdk::restamp_delivery(
        &stale_receipt,
        &stale.idempotency_key,
        &sdk::AdapterConfig {
            target: String::new(),
            producer_identity: RECEIVER.into(),
            source_instance: SOURCE_INSTANCE.into(),
            namespace: NAMESPACE.into(),
            target_external_id: String::new(),
            target_kind: String::new(),
            classification: "internal".into(),
        },
        sdk::EvidenceDraft {
            source_type: String::new(),
            source_record_id: String::new(),
            source_version: String::new(),
            source_sequence: 0,
            evidence_type: String::new(),
            signal: String::new(),
            schema_id: String::new(),
            schema_version: String::new(),
            observed_at_ms: 0,
            expires_at_ms: None,
            content: Value::Null,
            relationships: Vec::new(),
            confidence_bps: 0,
            provenance: HashMap::new(),
            causality: None,
        },
        now_ms(),
    )
    .unwrap();
    assert_ne!(late.idempotency_key, stale.idempotency_key);
    assert!(
        sdk::pending_deliveries(&receiver.outbox)
            .unwrap()
            .is_empty()
    );

    // Tenkai's later retry replays the restamped, admitted envelope.
    let retried = receiver
        .receive(&plane.sekai, &event, now_ms())
        .await
        .unwrap();
    assert_eq!(
        retried.evidence_submission_id,
        recorded.evidence_submission_id
    );
    assert_eq!(retried.action_instance_id, recorded.action_instance_id);
    assert_eq!(observations(&plane.db).len(), 1);
}

#[test]
fn the_vendored_schema_is_pinned_and_matches_the_receiver_model() {
    assert_eq!(
        format!("{:x}", Sha256::digest(TENKAI_SCHEMA_JSON.as_bytes())),
        TENKAI_SCHEMA_SHA256
    );
    let schema: Value = serde_json::from_str(TENKAI_SCHEMA_JSON).unwrap();
    let strings = |value: &Value| -> BTreeSet<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect()
    };
    let consts = |name: &str| -> BTreeSet<String> {
        schema["$defs"][name]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|variant| variant["const"].as_str().unwrap().to_owned())
            .collect()
    };
    let serialized = |values: Vec<Value>| -> BTreeSet<String> {
        values
            .into_iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    };

    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        strings(&schema["required"]),
        Observation::REQUIRED.map(String::from).into()
    );
    let properties: BTreeSet<String> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let modeled: BTreeSet<String> = Observation::REQUIRED
        .iter()
        .chain(Observation::OPTIONAL.iter())
        .map(|field| field.to_string())
        .collect();
    assert_eq!(properties, modeled);
    assert_eq!(
        consts("Operation"),
        serialized(
            Operation::ALL
                .map(|v| serde_json::to_value(v).unwrap())
                .into()
        )
    );
    assert_eq!(
        consts("Reason"),
        serialized(Reason::ALL.map(|v| serde_json::to_value(v).unwrap()).into())
    );
    let bounded: HashMap<&str, u64> = schema["properties"]
        .as_object()
        .unwrap()
        .iter()
        .filter_map(|(name, property)| {
            property["maxLength"]
                .as_u64()
                .map(|max| (name.as_str(), max))
        })
        .collect();
    assert!(bounded.values().all(|max| *max == 256), "{bounded:?}");
}
