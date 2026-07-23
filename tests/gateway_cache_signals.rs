//! Gateway cache signals, isolated in their own test binary.
//!
//! The Prometheus recorder is process-global, so a sibling test emitting
//! `sekai_cache_events_total` directly would satisfy these assertions with the
//! production instrumentation deleted. Each `tests/*.rs` runs in its own
//! process, so nothing here emits a cache event except the code under test.

use sekai_chisei::obs::signals;

fn cache_series(rendered: &str, cache: &str, outcome: &str) -> Option<u64> {
    rendered
        .lines()
        .find(|line| {
            line.starts_with(signals::CACHE_EVENTS)
                && line.contains(&format!(r#"cache="{cache}""#))
                && line.contains(&format!(r#"outcome="{outcome}""#))
        })
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
}

/// A miss on an empty cache must be recorded, not silently skipped.
///
/// `cached_gateway_key_identity` is private, so this drives it through the
/// public gateway router the same way a request would.
#[tokio::test]
async fn key_cache_miss_is_recorded_on_an_unknown_key() {
    sekai_chisei::obs::metrics::handle();

    let before = sekai_chisei::obs::metrics::handle().render();
    assert_eq!(
        cache_series(&before, "gateway_key", "miss"),
        None,
        "cache series existed before any lookup:\n{before}"
    );

    // from_env requires some provider key. This binary holds a single test, so
    // mutating the process environment here cannot race another test.
    unsafe {
        std::env::set_var("ANTHROPIC_API_KEY", "test-only-not-a-real-key");
        // Without a governance target the key store is never consulted and the
        // cache lookup is skipped entirely. Point at a closed port: the miss is
        // recorded before the connection is attempted.
        std::env::set_var("CHISEI_GRPC_URL", "http://127.0.0.1:1");
    }
    let config = chisei_gateway::gateway::GatewayConfig::from_env().expect("gateway config");
    let app = chisei_gateway::gateway::app(config);

    // An authenticated route with a key that was never cached forces exactly
    // one lookup against an empty cache.
    let request = http::Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("authorization", "Bearer sk-not-a-real-key")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            r#"{"model":"claude-3","messages":[]}"#,
        ))
        .expect("build request");

    let _ = tower::ServiceExt::oneshot(app, request).await;

    let after = sekai_chisei::obs::metrics::handle().render();
    let misses = cache_series(&after, "gateway_key", "miss");
    assert!(
        misses.is_some_and(|count| count > 0),
        "key cache lookup recorded no miss:\n{after}"
    );
}
