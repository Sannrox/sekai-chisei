use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes, to_bytes};
use futures_util::future::poll_fn;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body::{Body as HttpBody, Frame};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::obs::grpc_layer::MetricsLayer;
use tokio::time::sleep;
use tonic::transport::{Channel, Server};
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_client::HealthClient;
use tower::{Service, ServiceBuilder, ServiceExt, service_fn};

fn free_local_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind local test port")
        .local_addr()
        .expect("resolve local test port")
}

struct TestBody {
    frames: VecDeque<Result<Frame<Bytes>, &'static str>>,
}

impl TestBody {
    fn trailers(status: &'static str) -> Self {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", status.parse().expect("valid grpc status"));
        Self {
            frames: VecDeque::from([Ok(Frame::trailers(trailers))]),
        }
    }

    fn error() -> Self {
        Self {
            frames: VecDeque::from([Err("body failed")]),
        }
    }

    fn empty() -> Self {
        Self {
            frames: VecDeque::new(),
        }
    }
}

impl HttpBody for TestBody {
    type Data = Bytes;
    type Error = &'static str;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }
}

#[tokio::test]
async fn ops_routes_report_health_readiness_and_metrics() {
    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").expect("create db"),
    )));
    let directory =
        std::env::temp_dir().join(format!("sekai-ops-registry-{}", uuid::Uuid::new_v4()));
    let registry_path = directory.join("provider-registry.json");
    let app = sekai_chisei::obs::ops::router(
        db,
        registry_path.clone(),
        std::sync::Arc::new(sekai_chisei::sekai::credentials::PrincipalCredentialStore::new()),
    );

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("health route");
    assert_eq!(health.status(), StatusCode::OK);

    let ready = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("ready route");
    assert_eq!(ready.status(), StatusCode::OK);

    std::fs::remove_file(&registry_path).expect("remove registry state");
    let unavailable = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("unavailable readiness route");
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);

    let metrics = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("metrics route");
    assert_eq!(metrics.status(), StatusCode::OK);
    let body = to_bytes(metrics.into_body(), usize::MAX)
        .await
        .expect("metrics body");
    let body = String::from_utf8(body.to_vec()).expect("utf8 metrics");
    assert!(body.contains("sekai_build_info"));
    std::fs::remove_dir_all(directory).expect("remove registry fixture");
}

#[tokio::test]
async fn grpc_health_service_reports_serving() {
    let addr = free_local_addr();
    let (reporter, health_service) = tonic_health::server::health_reporter();
    reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;

    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(health_service)
            .serve(addr)
            .await
            .expect("serve health server");
    });

    let endpoint = format!("http://{addr}");
    let mut last_err = None;
    let mut client = None;
    for _ in 0..20 {
        match Channel::from_shared(endpoint.clone())
            .expect("valid health endpoint")
            .connect()
            .await
        {
            Ok(channel) => {
                client = Some(HealthClient::new(channel));
                break;
            }
            Err(err) => {
                last_err = Some(err);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    let mut client = client.unwrap_or_else(|| panic!("failed to connect: {last_err:?}"));
    let response = client
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .expect("health check")
        .into_inner();
    assert_eq!(response.status, tonic_health::ServingStatus::Serving as i32);

    server.abort();
}

#[tokio::test]
async fn metrics_layer_records_successful_rpc() {
    sekai_chisei::obs::metrics::handle();
    let service = service_fn(|_req: Request<Body>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .header("grpc-status", "0")
                .body(Body::empty())
                .unwrap(),
        )
    });
    let mut service = ServiceBuilder::new().layer(MetricsLayer).service(service);

    let response = service
        .ready()
        .await
        .expect("service ready")
        .call(
            Request::builder()
                .uri("/sekai.SekaiService/ListObjects")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("service response");
    drop(response);

    let metrics = sekai_chisei::obs::metrics::handle().render();
    assert!(metrics.contains("grpc_server_handled_total"));
    assert!(metrics.contains("grpc_service=\"sekai.SekaiService\""));
    assert!(metrics.contains("grpc_method=\"ListObjects\""));
    assert!(metrics.contains("grpc_code=\"ok\""));
}

#[tokio::test]
async fn metrics_layer_records_trailer_status() {
    sekai_chisei::obs::metrics::handle();
    let service = service_fn(|_req: Request<Body>| async move {
        Ok::<_, Infallible>(Response::new(TestBody::trailers("16")))
    });
    let mut service = ServiceBuilder::new().layer(MetricsLayer).service(service);

    let response = service
        .ready()
        .await
        .expect("service ready")
        .call(
            Request::builder()
                .uri("/sekai.SekaiService/GetObject")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("service response");
    let mut body = response.into_body();
    let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
        .await
        .expect("trailers frame")
        .expect("trailers ok");
    assert!(frame.is_trailers());

    let metrics = sekai_chisei::obs::metrics::handle().render();
    assert!(metrics.contains("grpc_method=\"GetObject\""));
    assert!(metrics.contains("grpc_code=\"unauthenticated\""));
}

#[tokio::test]
async fn metrics_layer_records_body_error_as_unknown() {
    sekai_chisei::obs::metrics::handle();
    let service = service_fn(|_req: Request<Body>| async move {
        Ok::<_, Infallible>(Response::new(TestBody::error()))
    });
    let mut service = ServiceBuilder::new().layer(MetricsLayer).service(service);

    let response = service
        .ready()
        .await
        .expect("service ready")
        .call(
            Request::builder()
                .uri("/sekai.SekaiService/UpdateObject")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("service response");
    let mut body = response.into_body();
    let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
        .await
        .expect("error frame");
    assert!(frame.is_err());

    let metrics = sekai_chisei::obs::metrics::handle().render();
    assert!(metrics.contains("grpc_method=\"UpdateObject\""));
    assert!(metrics.contains("grpc_code=\"unknown\""));
}

#[tokio::test]
async fn metrics_layer_records_cancelled_when_body_is_dropped() {
    sekai_chisei::obs::metrics::handle();
    let service = service_fn(|_req: Request<Body>| async move {
        Ok::<_, Infallible>(Response::new(TestBody::empty()))
    });
    let mut service = ServiceBuilder::new().layer(MetricsLayer).service(service);

    let response = service
        .ready()
        .await
        .expect("service ready")
        .call(
            Request::builder()
                .uri("/sekai.SekaiService/DeleteObject")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("service response");
    drop(response);

    let metrics = sekai_chisei::obs::metrics::handle().render();
    assert!(metrics.contains("grpc_method=\"DeleteObject\""));
    assert!(metrics.contains("grpc_code=\"cancelled\""));
}

// --- Operability signal surface (Issue #98) ---

use sekai_chisei::obs::labels::{
    Cache, CacheOutcome, FallbackTrigger, LagSurface, Outcome, RejectionReason, Subsystem, WaitKind,
};
use sekai_chisei::obs::signals;

#[test]
fn every_signal_family_renders_with_bounded_labels() {
    sekai_chisei::obs::metrics::handle();

    signals::record_control_plane_overhead(
        Subsystem::Chisei,
        Outcome::Ok,
        Duration::from_millis(12),
    );
    signals::record_db_wait(
        WaitKind::ConnectionAcquire,
        Outcome::Ok,
        Duration::from_millis(3),
    );
    signals::set_queue_depth(Subsystem::Sekai, 7);
    signals::record_cache_event(Cache::GatewayKey, CacheOutcome::Hit);
    signals::record_durability_lag(LagSurface::Receipt, Duration::from_millis(40));
    signals::record_fallback(Subsystem::Llm, FallbackTrigger::BudgetDegraded);
    signals::record_rejected_work(Subsystem::Gateway, RejectionReason::Overloaded);

    let rendered = sekai_chisei::obs::metrics::handle().render();

    for family in [
        signals::CONTROL_PLANE_OVERHEAD,
        signals::DB_WAIT,
        signals::QUEUE_DEPTH,
        signals::CACHE_EVENTS,
        signals::DURABILITY_LAG,
        signals::FALLBACK_TOTAL,
        signals::REJECTED_WORK_TOTAL,
    ] {
        assert!(rendered.contains(family), "missing signal family {family}");
    }

    assert!(rendered.contains(r#"subsystem="chisei""#));
    assert!(rendered.contains(r#"wait_kind="connection_acquire""#));
    assert!(rendered.contains(r#"cache="gateway_key""#));
    assert!(rendered.contains(r#"reason="overloaded""#));
    assert!(rendered.contains(r#"trigger="budget_degraded""#));
}

#[test]
fn saturation_ratio_is_clamped_in_rendered_output() {
    sekai_chisei::obs::metrics::handle();

    // A miscounted denominator must not render a ratio above 1.0.
    signals::set_saturation(Subsystem::Persistence, 4.2);
    let rendered = sekai_chisei::obs::metrics::handle().render();
    let line = rendered
        .lines()
        .find(|line| line.starts_with(signals::SATURATION_RATIO) && line.contains("persistence"))
        .expect("saturation series for persistence");
    let value: f64 = line
        .rsplit(' ')
        .next()
        .expect("value field")
        .parse()
        .expect("numeric gauge value");
    assert_eq!(value, 1.0, "saturation rendered above unit range: {line}");

    signals::set_saturation(Subsystem::Persistence, f64::NAN);
    let rendered = sekai_chisei::obs::metrics::handle().render();
    let line = rendered
        .lines()
        .find(|line| line.starts_with(signals::SATURATION_RATIO) && line.contains("persistence"))
        .expect("saturation series for persistence");
    assert!(
        !line.contains("NaN"),
        "non-finite saturation leaked into output: {line}"
    );
}

#[test]
fn signal_labels_never_carry_identifiers_or_digests() {
    sekai_chisei::obs::metrics::handle();

    signals::record_rejected_work(Subsystem::Sekai, RejectionReason::PolicyBlocked);
    signals::record_cache_event(Cache::GatewayKey, CacheOutcome::Miss);

    let rendered = sekai_chisei::obs::metrics::handle().render();

    // Issue #98 forbids content-derived, high-cardinality, or sensitive labels.
    // Assert on the label *keys* our families emit rather than scanning values,
    // since the closed enums already bound the values.
    let permitted_keys = [
        "subsystem",
        "outcome",
        "wait_kind",
        "cache",
        "surface",
        "trigger",
        "reason",
    ];
    for line in rendered.lines() {
        let is_ours = [
            signals::CONTROL_PLANE_OVERHEAD,
            signals::SATURATION_RATIO,
            signals::DB_WAIT,
            signals::QUEUE_DEPTH,
            signals::CACHE_EVENTS,
            signals::DURABILITY_LAG,
            signals::FALLBACK_TOTAL,
            signals::REJECTED_WORK_TOTAL,
        ]
        .iter()
        .any(|family| line.starts_with(*family));
        if !is_ours {
            continue;
        }
        let Some(start) = line.find('{') else {
            continue;
        };
        let Some(end) = line.find('}') else { continue };
        for pair in line[start + 1..end].split(',') {
            let Some((key, _)) = pair.split_once('=') else {
                continue;
            };
            let key = key.trim();
            // `le` is the Prometheus histogram bucket boundary, not our label.
            if key == "le" {
                continue;
            }
            assert!(
                permitted_keys.contains(&key),
                "unexpected label key {key:?} in operability signal: {line}"
            );
        }
    }
}

#[test]
fn signal_families_are_emitted_only_through_the_typed_surface() {
    // A runtime scrape cannot guard this: a call site that emits a signal
    // family directly only shows up if that code path runs in this test binary.
    // `capacity::record_snapshot` does not, and an earlier runtime-based guard
    // passed while the collision was live. Scan the source instead.
    //
    // Two emissions of one family with different label sets render as one
    // family with inconsistent dimensions, which is invalid Prometheus
    // exposition: a scraper aggregating it sums across meanings that are not
    // comparable.
    const OWNER: &str = "src/obs/signals.rs";
    let families = [
        signals::CONTROL_PLANE_OVERHEAD,
        signals::SATURATION_RATIO,
        signals::DB_WAIT,
        signals::QUEUE_DEPTH,
        signals::CACHE_EVENTS,
        signals::DURABILITY_LAG,
        signals::FALLBACK_TOTAL,
        signals::REJECTED_WORK_TOTAL,
    ];

    let mut offenders = Vec::new();
    for path in rust_sources("src") {
        let normalized = path.replace('\\', "/");
        if normalized.ends_with(OWNER) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read source file");
        for family in families {
            let needle = format!("\"{family}\"");
            if !source.contains(&needle) {
                continue;
            }
            for macro_name in ["gauge!", "counter!", "histogram!"] {
                let direct = format!("{macro_name}({needle}");
                if source.contains(&direct) {
                    offenders.push(format!("{path}: {macro_name} emits {family} directly"));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "operability signal families must be emitted through obs::signals, not raw macros:\n{}",
        offenders.join("\n")
    );
}

fn rust_sources(root: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_string()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path.to_string_lossy().into_owned());
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path.to_string_lossy().into_owned());
            }
        }
    }
    found
}
