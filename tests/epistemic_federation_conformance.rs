//! Conformance evidence for issue #500.
//!
//! The fixture deliberately composes the existing signed receipt, provenance,
//! compliance-import, handoff, and federation-policy contracts. It carries
//! only profile/evidence/assessment identities and digests; no epistemic
//! payload is promoted into a federation-specific authority surface.

use ed25519_dalek::SigningKey;
use sekai_chisei::chisei::governed_subject_provenance::ProvenanceEnvelope;
use sekai_chisei::chisei::policy::PolicyResolver;
use sekai_chisei::chisei::receipt::{
    GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    ReceiptEventKind,
};
use sekai_chisei::chisei::residency::ResidencyPolicy;
use sekai_chisei::compliance_export::{
    ComplianceExportRequest, RedactionMode, build_compliance_export, compliance_bundle_bytes,
    sign_compliance_export, verify_compliance_export,
};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::action::RiskClass;
use sekai_chisei::sekai::action_policy::{ActionDecision, ActionPolicy};
use sekai_chisei::sekai::attestation::{
    ActionAttestationInput, EVIDENCE_ATTESTATION_HASH, EVIDENCE_ATTESTATION_ID,
    attestation_content_hash, build_action_attestation,
};
use sekai_chisei::sekai::audit::Decision;
use sekai_chisei::sekai::federation_profile::{RemoteControlOp, evaluate_remote_control};
use sekai_chisei::sekai::handoff::{HANDOFF_VERSION, HandoffManifest, HandoffReference};
use sekai_chisei::sekai::peer_import::{
    PeerTrustRoot, import_compliance_bundle, peer_import_grants_permit_authority, put_trust_root,
};
use sekai_chisei::shomei::{
    AttestationBundle, KeyMetadata, KeyState, TrustedKeyring, receipt_digest, verify_bundle_at,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const PROFILE_PACKAGE: &str = include_str!("../examples/epistemic-replication/profile-v1.json");
const NAMESPACE: &str = "replication";
const OPERATION_ID: &str = "epistemic-federation:op-1";
const SIGNER_IDENTITY: &str = "site-a";
const SIGNER_KEY_ID: &str = "key-1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EpistemicProfileEnvelope {
    profile: String,
    version: String,
    profile_digest: String,
    claim_digest: String,
    evidence_digests: BTreeMap<String, String>,
    assessment_digest: String,
    evidence_status: String,
    lifecycle_status: String,
}

fn digest(value: impl AsRef<[u8]>) -> String {
    format!("sha256:{:x}", Sha256::digest(value.as_ref()))
}

fn public_key_hex(key: &SigningKey) -> String {
    key.verifying_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn profile_fixture() -> EpistemicProfileEnvelope {
    EpistemicProfileEnvelope {
        profile: "example.epistemic-replication".into(),
        version: "v1".into(),
        profile_digest: digest(PROFILE_PACKAGE),
        claim_digest: digest("claim:replication-001"),
        evidence_digests: BTreeMap::from([
            ("supporting".into(), digest("evidence:supporting:v1")),
            ("contradicting".into(), digest("evidence:contradicting:v1")),
        ]),
        assessment_digest: digest("assessment:replication-001:v1"),
        evidence_status: "contested".into(),
        lifecycle_status: "retracted".into(),
    }
}

fn event(
    suffix: &str,
    parent_suffix: Option<&str>,
    kind: ReceiptEventKind,
    actor: &str,
    references: Vec<GovernedReference>,
    attributes: BTreeMap<String, String>,
    timestamp_ms: i64,
) -> OperationReceiptEvent {
    OperationReceiptEvent {
        event_id: format!("{OPERATION_ID}:{suffix}"),
        operation_id: OPERATION_ID.into(),
        parent_event_id: parent_suffix.map(|parent| format!("{OPERATION_ID}:{parent}")),
        timestamp_ms,
        kind,
        surface: kind.surface(),
        actor: actor.into(),
        references,
        attributes,
    }
}

fn receipt(
    profile: &EpistemicProfileEnvelope,
    attestation_id: &str,
    attestation_hash: &str,
) -> OperationReceipt {
    let context_references = vec![
        GovernedReference {
            kind: "epistemic.profile".into(),
            reference: format!("profile:{}:{}", profile.profile, profile.version),
            content_hash: Some(profile.profile_digest.clone()),
            disclosed_fields: vec!["profile".into(), "version".into(), "digest".into()],
            omitted: true,
            omission_reason: Some("policy".into()),
        },
        GovernedReference {
            kind: "epistemic.claim".into(),
            reference: "claim:replication-001".into(),
            content_hash: Some(profile.claim_digest.clone()),
            disclosed_fields: vec!["identity".into(), "digest".into()],
            omitted: true,
            omission_reason: Some("policy".into()),
        },
        GovernedReference {
            kind: "epistemic.evidence".into(),
            reference: "evidence:supporting".into(),
            content_hash: Some(profile.evidence_digests["supporting"].clone()),
            disclosed_fields: vec!["stance".into(), "digest".into()],
            omitted: true,
            omission_reason: Some("policy".into()),
        },
        GovernedReference {
            kind: "epistemic.evidence".into(),
            reference: "evidence:contradicting".into(),
            content_hash: Some(profile.evidence_digests["contradicting"].clone()),
            disclosed_fields: vec!["stance".into(), "digest".into()],
            omitted: true,
            omission_reason: Some("policy".into()),
        },
        GovernedReference {
            kind: "epistemic.assessment".into(),
            reference: "assessment:replication-001".into(),
            content_hash: Some(profile.assessment_digest.clone()),
            disclosed_fields: vec!["status".into(), "lifecycle".into(), "digest".into()],
            omitted: true,
            omission_reason: Some("policy".into()),
        },
    ];

    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: OPERATION_ID.into(),
        parent_operation_id: None,
        namespace: NAMESPACE.into(),
        operation_class: "epistemic_profile_evaluation".into(),
        initiating_actor: "plane-a.operator".into(),
        schema_version: "example.epistemic-replication/v1".into(),
        policy_version: "policy:replication:v1".into(),
        started_at_ms: 1_000,
        completed_at_ms: Some(2_000),
        events: vec![
            event(
                "intent",
                None,
                ReceiptEventKind::IntentRecorded,
                "plane-a.operator",
                vec![],
                BTreeMap::from([("purpose".into(), "bounded epistemic assessment".into())]),
                1_000,
            ),
            event(
                "context",
                Some("intent"),
                ReceiptEventKind::ContextGoverned,
                "chisei.context",
                context_references,
                BTreeMap::from([
                    ("profile_version".into(), profile.version.clone()),
                    ("profile_digest".into(), profile.profile_digest.clone()),
                    ("evidence_status".into(), profile.evidence_status.clone()),
                    ("lifecycle_status".into(), profile.lifecycle_status.clone()),
                ]),
                1_100,
            ),
            event(
                "policy",
                Some("context"),
                ReceiptEventKind::PolicyDecided,
                "chisei.policy",
                vec![GovernedReference {
                    kind: "policy_attestation".into(),
                    reference: attestation_id.into(),
                    content_hash: Some(attestation_hash.into()),
                    disclosed_fields: vec!["policy_version".into(), "decision".into()],
                    omitted: false,
                    omission_reason: None,
                }],
                BTreeMap::from([
                    ("decision".into(), "allow".into()),
                    (EVIDENCE_ATTESTATION_ID.into(), attestation_id.into()),
                    (EVIDENCE_ATTESTATION_HASH.into(), attestation_hash.into()),
                ]),
                1_200,
            ),
            event(
                "route",
                Some("policy"),
                ReceiptEventKind::RouteSelected,
                "chisei.routing",
                vec![],
                BTreeMap::from([
                    ("provider".into(), "openai".into()),
                    ("model".into(), "gpt-4o-mini".into()),
                    ("provider_region".into(), "us".into()),
                ]),
                1_300,
            ),
            event(
                "budget",
                Some("route"),
                ReceiptEventKind::BudgetDecided,
                "chisei.budget",
                vec![],
                BTreeMap::from([("decision".into(), "allow".into())]),
                1_400,
            ),
            event(
                "outcome",
                Some("budget"),
                ReceiptEventKind::OutcomeRecorded,
                "chisei.evaluation",
                vec![],
                BTreeMap::from([
                    ("decision".into(), "hold_out".into()),
                    ("evidence_status".into(), profile.evidence_status.clone()),
                    ("lifecycle_status".into(), profile.lifecycle_status.clone()),
                ]),
                2_000,
            ),
        ],
        uncovered_surfaces: vec![],
        reporter_grants: vec![],
    }
}

#[test]
fn existing_federation_contracts_preserve_epistemic_profiles_without_new_authority() {
    let profile = profile_fixture();
    let signing_key = SigningKey::from_bytes(&[42; 32]);

    let policy = ActionPolicy::allow_all(NAMESPACE);
    let decision_id = format!("{OPERATION_ID}:policy-decision");
    let mut attestation = build_action_attestation(ActionAttestationInput {
        decision_id: &decision_id,
        policy: &policy,
        action: "evaluate_epistemic_profile",
        actor: "plane-a.operator",
        risk: RiskClass::Read,
        namespace: NAMESPACE,
        decision: ActionDecision::Allow,
        created: 1_200,
    });
    // The builder's UUID is useful for production records; this conformance
    // fixture pins it so all bundle and import identities are reproducible.
    attestation.id = format!("{OPERATION_ID}:policy-attestation");
    attestation.content_hash = attestation_content_hash(&attestation);

    let receipt = receipt(&profile, &attestation.id, &attestation.content_hash);
    let completeness = receipt.completeness();
    assert!(
        completeness.complete,
        "receipt incomplete: {completeness:?}"
    );

    let decision = Decision {
        id: decision_id,
        timestamp: 1_200,
        actor: "plane-a.operator".into(),
        action: "evaluate_epistemic_profile".into(),
        reason: "profile is carried as bounded evidence references".into(),
        evidence: HashMap::from([
            ("namespace".into(), NAMESPACE.into()),
            (EVIDENCE_ATTESTATION_ID.into(), attestation.id.clone()),
            (
                EVIDENCE_ATTESTATION_HASH.into(),
                attestation.content_hash.clone(),
            ),
            ("profile_digest".into(), profile.profile_digest.clone()),
        ]),
        target_id: OPERATION_ID.into(),
        outcome: "allow".into(),
    };

    let plane_a = RuntimeDb::memory();
    plane_a
        .record_decision_with_attestation(&decision, Some(&attestation))
        .expect("source plane should persist the signed policy evidence");
    assert!(
        plane_a
            .verify_attestation(&attestation.id)
            .expect("attestation should be readable")
            .ok
    );

    let mut shomei = AttestationBundle::unsigned(receipt.clone()).expect("receipt is encodable");
    shomei.extensions.insert(
        "epistemic.profile".into(),
        serde_json::to_value(&profile).expect("profile envelope is serializable"),
    );
    shomei
        .attach_policy_attestation(attestation.clone())
        .expect("receipt link should accept the policy attestation");
    shomei
        .sign(&signing_key, SIGNER_IDENTITY, SIGNER_KEY_ID, 3_000)
        .expect("source plane should sign the portable bundle");

    let mut trusted = TrustedKeyring::at_time(3_000);
    trusted
        .trust(SIGNER_IDENTITY, SIGNER_KEY_ID, signing_key.verifying_key())
        .expect("source key should be trusted");
    let verified = verify_bundle_at(&shomei, &trusted, 3_000);
    assert!(
        verified.integrity.valid,
        "Shomei verification failed: {verified:?}"
    );
    assert!(
        verified.policy.compliant,
        "Shomei policy verification failed: {verified:?}"
    );
    let shomei_json = serde_json::to_string(&shomei).expect("bundle is JSON serializable");
    assert!(shomei_json.contains(&profile.profile_digest));
    assert!(
        !shomei_json.contains("ResearchQuestion"),
        "raw profile schema leaked into bundle"
    );

    let mut revoked = TrustedKeyring::at_time(3_000);
    revoked
        .trust_with_metadata(
            SIGNER_IDENTITY,
            SIGNER_KEY_ID,
            signing_key.verifying_key(),
            KeyMetadata {
                state: KeyState::Revoked,
                valid_from_ms: Some(0),
                valid_until_ms: None,
                revoked_at_ms: Some(2_500),
                successor_key_id: Some("key-2".into()),
            },
        )
        .expect("revoked key metadata should be accepted");
    let revoked_report = verify_bundle_at(&shomei, &revoked, 3_000);
    assert!(!revoked_report.policy.key.acceptable_at_verification);
    assert!(!revoked_report.policy.compliant);

    let request = ComplianceExportRequest {
        namespace: NAMESPACE.into(),
        start_timestamp_ms: 0,
        end_timestamp_ms: 10_000,
        redaction: RedactionMode::Full,
        actor: "plane-a.auditor".into(),
        request_id: "epistemic-export-1".into(),
    };
    let mut export = build_compliance_export(&request, vec![receipt], vec![decision], 3_100)
        .expect("existing compliance export should carry the receipt");
    sign_compliance_export(
        &mut export,
        &signing_key,
        SIGNER_IDENTITY,
        SIGNER_KEY_ID,
        3_100,
    )
    .expect("source plane should sign the compliance export");
    let export_bytes = compliance_bundle_bytes(&export).expect("export should have bounded bytes");
    assert!(
        export_bytes.len() < 256 * 1024,
        "portable evidence bundle grew unexpectedly"
    );
    let export_json = String::from_utf8(export_bytes.clone()).expect("export is UTF-8 JSON");
    assert!(export_json.contains(&profile.claim_digest));

    let plane_b = RuntimeDb::memory();
    put_trust_root(
        &plane_b,
        &PeerTrustRoot {
            namespace: NAMESPACE.into(),
            site_identity: SIGNER_IDENTITY.into(),
            key_id: SIGNER_KEY_ID.into(),
            public_key_hex: public_key_hex(&signing_key),
            enabled: true,
            created_by: "plane-b.admin".into(),
            created_at_ms: 3_000,
        },
    )
    .expect("destination plane should pin the source trust root");

    let imported =
        import_compliance_bundle(&plane_b, "plane-b.importer", NAMESPACE, &export, 3_200)
            .expect("destination plane should verify and import evidence");
    assert!(imported.record.verified);
    assert!(!peer_import_grants_permit_authority(&imported.record));
    let duplicate =
        import_compliance_bundle(&plane_b, "plane-b.importer", NAMESPACE, &export, 3_201)
            .expect("same evidence import should be idempotent");
    assert_eq!(duplicate.record.import_id, imported.record.import_id);

    let mut tampered = export.clone();
    tampered.manifest.export_request_id = "tampered-request".into();
    let tampered_report = verify_compliance_export(&tampered, Some(&public_key_hex(&signing_key)));
    assert!(!tampered_report.ok);
    assert!(
        import_compliance_bundle(&plane_b, "plane-b.importer", NAMESPACE, &tampered, 3_202)
            .is_err()
    );

    put_trust_root(
        &plane_b,
        &PeerTrustRoot {
            namespace: NAMESPACE.into(),
            site_identity: SIGNER_IDENTITY.into(),
            key_id: SIGNER_KEY_ID.into(),
            public_key_hex: public_key_hex(&signing_key),
            enabled: false,
            created_by: "plane-b.admin".into(),
            created_at_ms: 3_300,
        },
    )
    .expect("destination plane should be able to disable the trust root");
    assert!(
        import_compliance_bundle(&plane_b, "plane-b.importer", NAMESPACE, &export, 3_301).is_err()
    );

    // The existing gRPC handoff conformance tests own principal, expiry,
    // supersession, availability, and revocation re-checks. This fixture
    // proves that the bounded epistemic references remain portable through
    // the local coordination manifest without turning it into a trust
    // envelope.
    let mut handoff = HandoffManifest {
        schema_version: HANDOFF_VERSION.into(),
        id: "handoff:epistemic-1".into(),
        namespace: NAMESPACE.into(),
        parent_operation_id: OPERATION_ID.into(),
        parent_attempt_id: "attempt-1".into(),
        parent_work_unit_id: "work-1".into(),
        references: vec![
            HandoffReference {
                kind: "epistemic.profile".into(),
                id: "profile:example.epistemic-replication:v1".into(),
                version: "v1".into(),
                omitted: false,
                omission_reason: String::new(),
            },
            HandoffReference {
                kind: "epistemic.evidence".into(),
                id: "evidence:raw-payload".into(),
                version: String::new(),
                omitted: true,
                omission_reason: "policy".into(),
            },
        ],
        creator_principal: "plane-a.operator".into(),
        intended_principal: "plane-a.reviewer".into(),
        intended_scope: "epistemic-review".into(),
        purpose: "review bounded assessment references".into(),
        created_at_ms: 3_000,
        expires_at_ms: 4_000,
        digest: String::new(),
        supersedes_manifest_id: String::new(),
        revoked: false,
    };
    handoff.validate().expect("handoff should validate locally");
    handoff.digest = handoff
        .canonical_digest()
        .expect("handoff digest should be reproducible");
    let handoff_roundtrip: HandoffManifest =
        serde_json::from_str(&serde_json::to_string(&handoff).expect("handoff is serializable"))
            .expect("handoff should round-trip");
    handoff_roundtrip
        .validate()
        .expect("handoff round-trip should retain local validation");
    assert_eq!(handoff_roundtrip.digest, handoff.digest);

    let receipt_digest = format!(
        "sha256:{}",
        receipt_digest(&shomei.receipt).expect("receipt digest should be reproducible")
    );
    let provenance = ProvenanceEnvelope::issue(
        &signing_key,
        "claim:replication-001".into(),
        profile.claim_digest.clone(),
        receipt_digest,
        OPERATION_ID.into(),
        3_000,
        4_000,
    )
    .expect("existing provenance envelope should carry the profile evidence");
    assert_eq!(provenance.content_digest, profile.claim_digest);
    provenance
        .verify(&signing_key.verifying_key().to_bytes(), 3_500)
        .expect("fresh provenance should verify");
    assert!(
        provenance
            .verify(&signing_key.verifying_key().to_bytes(), 4_000)
            .is_err()
    );

    let resolver = PolicyResolver::new();
    resolver
        .set_residency_policy(
            NAMESPACE,
            ResidencyPolicy {
                policy_id: "residency:eu-only".into(),
                version: "v1".into(),
                allowed_regions: BTreeSet::from(["eu".into()]),
                provider_regions: BTreeMap::from([(String::from("openai"), String::from("us"))]),
                model_regions: BTreeMap::new(),
                allowed_data_classes: BTreeSet::from(["research".into()]),
            },
        )
        .expect("local residency policy should validate");
    assert!(
        resolver
            .enforce_residency(NAMESPACE, "openai", "gpt-4o-mini", "research")
            .is_err()
    );
    // The imported evidence does not alter the local route policy or provide
    // a promotion/permit path, so the same deny remains after import.
    assert!(
        resolver
            .enforce_residency(NAMESPACE, "openai", "gpt-4o-mini", "research")
            .is_err()
    );

    for op in [
        RemoteControlOp::Verify,
        RemoteControlOp::Import,
        RemoteControlOp::Deny,
    ] {
        assert!(evaluate_remote_control(op).is_ok());
    }
    for op in [
        RemoteControlOp::Promote,
        RemoteControlOp::Kill,
        RemoteControlOp::BudgetDebit,
    ] {
        assert!(evaluate_remote_control(op).is_err());
    }
}
