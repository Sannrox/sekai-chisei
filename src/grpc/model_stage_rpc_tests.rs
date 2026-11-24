//! Model stage promotion (#3023): a gated stage moves only with an approved
//! review (#3159) and a passing run of its suite against the version, and
//! every attempt records a receipt.

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

async fn submit_review(svc: &SekaiServiceImpl, version_id: &str, by: &str) -> String {
    svc.submit_model_stage_review(with_named_principal(
        SubmitModelStageReviewRequest {
            namespace: "ml".into(),
            model_name: "churn".into(),
            stage: "production".into(),
            version_id: version_id.into(),
        },
        by,
    ))
    .await
    .unwrap()
    .into_inner()
    .operation_id
}

async fn decide_review(
    svc: &SekaiServiceImpl,
    version_id: &str,
    by: &str,
    decision: &str,
) -> Result<DecideModelStageReviewResponse, Status> {
    svc.decide_model_stage_review(with_named_principal(
        DecideModelStageReviewRequest {
            namespace: "ml".into(),
            model_name: "churn".into(),
            stage: "production".into(),
            version_id: version_id.into(),
            decision: decision.into(),
            reason: String::new(),
        },
        by,
    ))
    .await
    .map(Response::into_inner)
}

/// Submits `version_id` as `tester` and approves it as `reviewer`.
async fn approve(svc: &SekaiServiceImpl, version_id: &str) {
    submit_review(svc, version_id, "tester").await;
    decide_review(svc, version_id, "reviewer", "approve")
        .await
        .unwrap();
}

async fn put_gated_stage(svc: &SekaiServiceImpl) {
    svc.put_model_stage(with_principal(PutModelStageRequest {
        namespace: "ml".into(),
        model_name: "churn".into(),
        stage: "production".into(),
        evaluation_suite_id: "churn-suite".into(),
    }))
    .await
    .unwrap();
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
    put_gated_stage(&svc).await;
    let first = store_version(&svc, "sha256:a");
    let second = store_version(&svc, "sha256:b");
    approve(&svc, &first).await;
    approve(&svc, &second).await;
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

/// Only an approved review admits a gated promotion, and the review gate is
/// checked before the evaluation gate.
#[tokio::test]
async fn promotion_needs_an_approved_review_from_another_principal() {
    let svc = service();
    put_gated_stage(&svc).await;
    let version = store_version(&svc, "sha256:a");
    let rejected = store_version(&svc, "sha256:b");
    seed_eval_run(&svc, "eval-pass", &version, true);
    seed_eval_run(&svc, "eval-pass-b", &rejected, true);
    let not_approved = crate::sekai::model_stage::REFUSAL_REVIEW_NOT_APPROVED;
    let refused = |response: &PromoteModelVersionResponse| {
        assert!(!response.promoted);
        assert_eq!(response.refusal, not_approved);
        assert_eq!(response.stage.as_ref().unwrap().version_id, "");
    };

    // Missing: no review, and no suite run either; the review gate names it.
    let missing = promote(&svc, &version, "").await;
    refused(&missing);
    assert_eq!(
        receipt_decision(&svc, &missing.operation_id),
        ("refused".to_string(), 1)
    );

    // Pending, and the submitter's own approval leaves it pending.
    let submitted = submit_review(&svc, &version, "tester").await;
    let receipt = svc
        .db
        .runtime()
        .get_operation_receipt(&submitted)
        .unwrap()
        .expect("submission receipt");
    assert_eq!(
        receipt.operation_class,
        crate::sekai::model_stage::REVIEW_OPERATION_CLASS
    );
    let own = decide_review(&svc, &version, "tester", "approve")
        .await
        .unwrap_err();
    assert_eq!(own.code(), tonic::Code::PermissionDenied);
    refused(&promote(&svc, &version, "eval-pass").await);

    // Rejected stays refused, and a rejection is final.
    submit_review(&svc, &rejected, "tester").await;
    decide_review(&svc, &rejected, "reviewer", "reject")
        .await
        .unwrap();
    refused(&promote(&svc, &rejected, "eval-pass-b").await);
    let reversed = decide_review(&svc, &rejected, "reviewer", "approve")
        .await
        .unwrap_err();
    assert_eq!(reversed.code(), tonic::Code::FailedPrecondition);

    // A second principal's approval admits the same promotion.
    let approved = decide_review(&svc, &version, "reviewer", "approve")
        .await
        .unwrap();
    assert_eq!(approved.review.as_ref().unwrap().state, "approved");
    assert!(
        svc.db
            .runtime()
            .get_operation_receipt(&approved.operation_id)
            .unwrap()
            .is_some()
    );
    let replay = decide_review(&svc, &version, "reviewer", "approve")
        .await
        .unwrap();
    assert!(replay.replay);
    let admitted = promote(&svc, &version, "eval-pass").await;
    assert!(admitted.promoted, "{}", admitted.refusal);
    assert_eq!(admitted.stage.unwrap().version_id, version);
}

/// A gateless stage follows each registered version with no review.
#[tokio::test]
async fn gateless_stage_follows_a_new_version_without_review() {
    let svc = service();
    svc.put_model_stage(with_principal(PutModelStageRequest {
        namespace: "ml".into(),
        model_name: "churn".into(),
        stage: "latest".into(),
        evaluation_suite_id: String::new(),
    }))
    .await
    .unwrap();
    let version = store_version(&svc, "sha256:a");
    let stage = svc
        .db
        .runtime()
        .get_model_stage("ml", "churn", "latest")
        .unwrap()
        .unwrap();
    assert_eq!(stage.version_id, version);
}
