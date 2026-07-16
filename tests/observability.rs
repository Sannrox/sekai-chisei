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
    let db = Arc::new(SekaiDb::new(":memory:").expect("create db"));
    let directory =
        std::env::temp_dir().join(format!("sekai-ops-registry-{}", uuid::Uuid::new_v4()));
    let registry_path = directory.join("provider-registry.json");
    let app = sekai_chisei::obs::ops::router(db, registry_path.clone());

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
