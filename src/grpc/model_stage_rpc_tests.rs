//! Model stage promotion (#3023): a gated stage moves only with a passing run
//! of its suite against the version, and every attempt records a receipt.

use super::*;

fn store_version(svc: &SekaiServiceImpl, digest: &str) -> String {
    super::model_version_rpc_tests::store_version(svc, digest, "")
}

fn seed_eval_run(svc: &SekaiServiceImpl, id: &str, version_id: &str, passed: bool) {
    svc.db
        .runtime()
        .put_eval_run(&crate::chisei::eval::Run {
            id: id.into(),
            suite_id: "churn-suite".into(),
            config_ref: version_id.into(),
            results: vec![crate::chisei::eval::CaseResult {
                case_id: "case-1".into(),
                passed,
                status: if passed { "done" } else { "failed" }.into(),
                result: "result".into(),
                score: if passed { 100 } else { 0 },
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 1,
        })
        .unwrap();
}

async fn promote(
    svc: &SekaiServiceImpl,
    version_id: &str,
    evaluation_run_id: &str,
) -> PromoteModelVersionResponse {
    svc.promote_model_version(with_principal(PromoteModelVersionRequest {
        namespace: "ml".into(),
        model_name: "churn".into(),
        stage: "production".into(),
        version_id: version_id.into(),
        evaluation_run_id: evaluation_run_id.into(),
    }))
    .await
    .unwrap()
    .into_inner()
}

fn receipt_decision(svc: &SekaiServiceImpl, operation_id: &str) -> (String, usize) {
    let receipt = svc
        .db
        .runtime()
        .get_operation_receipt(operation_id)
        .unwrap()
        .expect("promotion receipt");
    assert_eq!(
        receipt.operation_class,
        crate::sekai::model_stage::PROMOTION_OPERATION_CLASS
    );
    (
        receipt.events[0].attributes["decision"].clone(),
        receipt.events.len(),
    )
}

#[tokio::test]
async fn promotion_needs_a_passing_suite_and_records_a_receipt() {
    let svc = service();
    svc.put_model_stage(with_principal(PutModelStageRequest {
        namespace: "ml".into(),
        model_name: "churn".into(),
        stage: "production".into(),
        evaluation_suite_id: "churn-suite".into(),
    }))
    .await
    .unwrap();
    let first = store_version(&svc, "sha256:a");
    let second = store_version(&svc, "sha256:b");
    seed_eval_run(&svc, "eval-pass", &first, true);
    seed_eval_run(&svc, "eval-fail", &second, false);

    let admitted = promote(&svc, &first, "eval-pass").await;
    assert!(admitted.promoted);
    assert_eq!(admitted.stage.unwrap().version_id, first);
    assert_eq!(
        receipt_decision(&svc, &admitted.operation_id),
        ("admitted".to_string(), 2)
    );

    let failed = promote(&svc, &second, "eval-fail").await;
    assert!(!failed.promoted);
    assert_eq!(
        failed.refusal,
        crate::sekai::model_stage::REFUSAL_SUITE_FAILED
    );
    assert_eq!(failed.stage.unwrap().version_id, first);
    assert_eq!(
        receipt_decision(&svc, &failed.operation_id),
        ("refused".to_string(), 1)
    );

    // A passing run of another version is not evidence for this one.
    let mismatched = promote(&svc, &second, "eval-pass").await;
    assert_eq!(
        mismatched.refusal,
        crate::sekai::model_stage::REFUSAL_VERSION_MISMATCH
    );
    let missing = promote(&svc, &second, "").await;
    assert_eq!(
        missing.refusal,
        crate::sekai::model_stage::REFUSAL_SUITE_MISSING
    );
}

#[tokio::test]
async fn promotion_to_a_missing_stage_is_not_found() {
    let svc = service();
    let version = store_version(&svc, "sha256:a");
    let status = svc
        .promote_model_version(with_principal(PromoteModelVersionRequest {
            namespace: "ml".into(),
            model_name: "churn".into(),
            stage: "production".into(),
            version_id: version,
            evaluation_run_id: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}
