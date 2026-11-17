//! Tests of `chisei::model_review` that break the decision-ledger write
//! through the store's connection.

use super::*;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};

/// #2473: when the refusal audit cannot be written the route is still
/// refused, and the lost audit is counted instead of dropped.
#[test]
fn a_refusal_whose_audit_fails_is_still_refused_and_counted() {
    let db = ChiseiStore::memory();
    db.runtime()
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_decision_write BEFORE INSERT ON sekai_decisions
             BEGIN SELECT RAISE(ABORT, 'injected decision write failure'); END;",
        )
        .unwrap();
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let error = metrics::with_local_recorder(&recorder, || {
        admit_enabled_route(
            &db,
            "sales",
            &ModelIdentity {
                provider: "openai".into(),
                model: "gpt-4".into(),
                upstream_model: "gpt-4".into(),
                profile_version: "v1".into(),
                artifact_digest: None,
                endpoint: "https://example.invalid".into(),
            },
            "",
            "alice",
        )
        .unwrap_err()
    });
    assert_eq!(error.reason, REFUSAL_NOT_ENABLED);
    let failures: Vec<_> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, ..)| key.key().name() == ADMISSION_AUDIT_FAILED_METRIC)
        .map(|(.., value)| value)
        .collect();
    assert_eq!(failures, [DebugValue::Counter(1)]);
}
