//! Shared SQLite/PostgreSQL conformance for model-release evidence (#1396).

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sekai_chisei::chisei::eval::{Case, CaseResult, EvalStore, Run, Suite};
use sekai_chisei::chisei::model_release_evidence::{
    self, EVALUATION_TRUST_VERSION, EvaluationOutcome, EvaluationTrustRoots, ModelReleaseFeedback,
    ModelReleaseIdentity, RuntimeCanary, RuntimeEvidenceDraft, RuntimeHealth, TrustedSigner,
    sign_runtime_evidence,
};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::ChiseiStore;
use sha2::Digest as _;

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const RELEASE_DIGEST: &str =
    "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const NOW_MS: i64 = 1_700_000_100_000;

fn identity() -> ModelReleaseIdentity {
    ModelReleaseIdentity {
        provider: "huggingface".into(),
        model: "qwen-coder".into(),
        profile_version: "v1".into(),
        artifact_digest: DIGEST.into(),
        endpoint: "served://qwen-coder".into(),
    }
}

fn pair() -> (SigningKey, EvaluationTrustRoots) {
    let key = SigningKey::from_bytes(&[17u8; 32]);
    let public = key.verifying_key().to_bytes();
    let key_id = format!("sha256:{:x}", sha2::Sha256::digest(public));
    (
        key,
        EvaluationTrustRoots {
            version: EVALUATION_TRUST_VERSION,
            signers: vec![TrustedSigner {
                key_id,
                public_key: base64::engine::general_purpose::STANDARD.encode(public),
            }],
        },
    )
}

fn exercise(store: &ChiseiStore) {
    let (key, roots) = pair();
    model_release_evidence::install_trust_roots(store, roots, NOW_MS).unwrap();
    let evidence = sign_runtime_evidence(
        RuntimeEvidenceDraft {
            identity: identity(),
            release_id: "qwen-coder@0.1.0".into(),
            release_digest: RELEASE_DIGEST.into(),
            health: RuntimeHealth::Healthy,
            canary: RuntimeCanary::Passed,
            observed_at: 1_700_000_000_000,
            expires_at: 1_700_003_600_000,
        },
        &key,
    )
    .unwrap();
    model_release_evidence::ingest_runtime_evidence(store, evidence, NOW_MS).unwrap();
    assert!(
        model_release_evidence::load_runtime_evidence_json(store, &identity())
            .unwrap()
            .is_some()
    );

    let eval = EvalStore::with_db(store.clone());
    eval.put_suite(Suite {
        id: "quality".into(),
        name: "quality".into(),
        description: "pinned".into(),
        cases: vec![Case {
            id: "c1".into(),
            name: "c1".into(),
            namespace: "sales".into(),
            spec: "ok".into(),
            assertions: Vec::new(),
        }],
    })
    .unwrap();
    eval.put_run(Run {
        id: "base".into(),
        suite_id: "quality".into(),
        config_ref: DIGEST.into(),
        results: vec![CaseResult {
            case_id: "c1".into(),
            passed: true,
            status: "ok".into(),
            result: "ok".into(),
            score: 1,
            reason: "ok".into(),
            elapsed: 1,
        }],
        timestamp: 1,
    })
    .unwrap();
    eval.put_run(Run {
        id: "cand".into(),
        suite_id: "quality".into(),
        config_ref: DIGEST.into(),
        results: vec![CaseResult {
            case_id: "c1".into(),
            passed: true,
            status: "ok".into(),
            result: "ok".into(),
            score: 1,
            reason: "ok".into(),
            elapsed: 1,
        }],
        timestamp: 2,
    })
    .unwrap();
    let exported = model_release_evidence::export_evaluation_from_compare(
        store,
        identity(),
        "quality",
        "base",
        "cand",
        "cand",
        &key,
        NOW_MS,
        "root",
    )
    .unwrap();
    assert_eq!(exported.outcome, EvaluationOutcome::Passed);

    model_release_evidence::record_model_release_feedback(
        store,
        ModelReleaseFeedback {
            id: "fb-1".into(),
            namespace: "sales".into(),
            identity: identity(),
            actor: "root".into(),
            note: "latency within bound".into(),
            recorded_at_ms: NOW_MS,
        },
    )
    .unwrap();
    assert_eq!(
        model_release_evidence::list_model_release_feedback(store, "sales")
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn sqlite_model_release_evidence_conformance() {
    exercise(&ChiseiStore::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_model_release_evidence_backend_conformance() {
    use sekai_chisei::db::postgres::PostgresDb;
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let postgres = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 4).unwrap()
    };
    let store = ChiseiStore::from_shared_runtime(std::sync::Arc::new(RuntimeDb::Postgres(
        std::sync::Arc::new(postgres),
    )));
    exercise(&store);
}
