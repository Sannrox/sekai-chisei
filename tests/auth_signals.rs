//! Authentication rejection signals, isolated in their own test binary.
//!
//! The Prometheus recorder is process-global, so a sibling test emitting
//! `sekai_rejected_work_total` directly would satisfy these assertions even with
//! the production instrumentation deleted. Each `tests/*.rs` gets its own
//! process, so nothing here emits a signal except the code under test.

use std::sync::Arc;

use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::grpc::TokenAuthInterceptor;
use sekai_chisei::obs::signals;
use sekai_chisei::sekai::credentials::PrincipalCredentialStore;
use tonic::Request;
use tonic::service::Interceptor;

fn interceptor() -> TokenAuthInterceptor {
    let db = Arc::new(SekaiDb::new(":memory:").expect("open in-memory database"));
    let store = Arc::new(PrincipalCredentialStore::new());
    TokenAuthInterceptor::new(store, db, None)
}

fn rejected_unauthorized_count(rendered: &str) -> Option<u64> {
    rendered
        .lines()
        .find(|line| {
            line.starts_with(signals::REJECTED_WORK_TOTAL)
                && line.contains(r#"subsystem="grpc""#)
                && line.contains(r#"reason="unauthorized""#)
        })
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
}

// Both assertions live in one test on purpose. Tests in a binary share the
// process-global recorder and run concurrently, so a second test emitting the
// same series makes an exact-count assertion flap. An earlier split version
// read 3 where it expected 2.
#[test]
fn authentication_refusals_record_one_indistinct_rejection_each() {
    sekai_chisei::obs::metrics::handle();

    let before = sekai_chisei::obs::metrics::handle().render();
    assert_eq!(
        rejected_unauthorized_count(&before),
        None,
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
    let count = rejected_unauthorized_count(&after)
        .unwrap_or_else(|| panic!("no unauthorized rejection series:\n{after}"));
    assert_eq!(
        count, 2,
        "expected exactly one rejection per refused request:\n{after}"
    );

    // Separating "missing header" from "invalid token" would let a reader of
    // the metrics endpoint probe which tokens exist. Every authentication
    // refusal must collapse to the same series.
    for forbidden in ["missing", "invalid_token", "bad_token", "token"] {
        assert!(
            !after.contains(&format!(r#"reason="{forbidden}""#)),
            "rejection reason leaked credential detail {forbidden:?}:\n{after}"
        );
    }
}
