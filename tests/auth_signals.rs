//! Authentication rejection signals, isolated in their own test binary.
//!
//! The Prometheus recorder is process-global, so a sibling test emitting
//! `sekai_rejected_work_total` directly would satisfy these assertions even with
//! the production instrumentation deleted. Each `tests/*.rs` gets its own
//! process, so nothing here emits a signal except the code under test.

use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::TokenAuthInterceptor;
use sekai_chisei::obs::signals;
use sekai_chisei::sekai::credentials::PrincipalCredentialStore;
use tonic::Request;
use tonic::service::Interceptor;

fn interceptor() -> TokenAuthInterceptor {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").expect("open in-memory database"),
    )));
    let store = Arc::new(PrincipalCredentialStore::new());
    TokenAuthInterceptor::new(
        store,
        sekai_chisei::db::store::SekaiStore::from_shared_runtime(db),
    )
}

/// Every rendered `REJECTED_WORK_TOTAL` sample in the gRPC subsystem.
fn grpc_rejection_lines(rendered: &str) -> Vec<&str> {
    rendered
        .lines()
        .filter(|line| {
            line.strip_prefix(signals::REJECTED_WORK_TOTAL)
                .is_some_and(|rest| rest.starts_with('{'))
                && line.contains(r#"subsystem="grpc""#)
        })
        .collect()
}

// Both assertions live in one test on purpose. Tests in a binary share the
// process-global recorder and run concurrently, so a second test emitting the
// same series makes an exact-count assertion flap. An earlier split version
// read 3 where it expected 2.
#[test]
fn authentication_refusals_record_one_indistinct_rejection_each() {
    sekai_chisei::obs::metrics::handle();

    let before = sekai_chisei::obs::metrics::handle().render();
    assert!(
        grpc_rejection_lines(&before).is_empty(),
        "rejection series existed before any request:\n{before}"
    );

    let mut auth = interceptor();

    // No authorization metadata at all.
    let missing = auth.call(Request::new(()));
    assert!(missing.is_err(), "request without credentials was accepted");

    // Present but unresolvable token.
    let mut request = Request::new(());
    request
        .metadata_mut()
        .insert("authorization", "Bearer not-a-real-token".parse().unwrap());
    let invalid = auth.call(request);
    assert!(invalid.is_err(), "request with bad token was accepted");

    let after = sekai_chisei::obs::metrics::handle().render();
    // Separating "missing header" from "invalid token" would let a reader of
    // the metrics endpoint probe which tokens exist. Every authentication
    // refusal must collapse to one series, counted once per refused request.
    let [series] = grpc_rejection_lines(&after)[..] else {
        panic!("expected exactly one gRPC rejection series:\n{after}");
    };
    assert!(
        series.contains(r#"reason="unauthorized""#),
        "rejection series is not the indistinct unauthorized reason: {series}"
    );
    assert_eq!(
        series
            .rsplit(' ')
            .next()
            .and_then(|value| value.parse::<u64>().ok()),
        Some(2),
        "expected exactly one rejection per refused request: {series}"
    );
}
