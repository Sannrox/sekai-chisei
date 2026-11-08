use crate::db::chisei_rpc_inventory::{CHISEI_SERVICE_PROTO, parse_service_rpcs};
use crate::db::sekai_rpc_inventory::{SEKAI_SERVICE_PROTO, parse_sekai_service_rpcs};
use futures_util::future::BoxFuture;
use http::{HeaderMap, Request, Response};
use http_body::{Body, Frame};
use metrics::{counter, histogram};
use pin_project_lite::pin_project;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower::{Layer, Service};
use tracing::{Instrument, debug, info_span, warn};

/// gRPC service name as it appears on the wire (`package.Service`).
const SEKAI_GRPC_SERVICE: &str = "sekai.SekaiService";
const CHISEI_GRPC_SERVICE: &str = "chisei.ChiseiService";
const HEALTH_GRPC_SERVICE: &str = "grpc.health.v1.Health";

#[derive(Clone, Default)]
pub struct MetricsLayer;

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService { inner }
    }
}

#[derive(Clone)]
pub struct MetricsService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for MetricsService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<MetricsBody<ResBody>>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let (grpc_service, grpc_method) = parse_grpc_path(req.uri().path());
        let started = Instant::now();
        // Every RPC opens a correlated operation. The id is generated, never
        // derived from the request, so correlating two spans cannot reveal
        // that they touched the same namespace or content.
        let correlation = crate::obs::correlation::Correlation::new_operation();
        let caller_operation = crate::obs::correlation::caller_operation_id(req.headers())
            .ok()
            .flatten()
            .unwrap_or_default();
        let span = info_span!(
            "grpc",
            grpc_service = %grpc_service,
            grpc_method = %grpc_method,
            stage = crate::obs::correlation::Stage::Operation.as_str(),
            operation = %correlation.operation,
            attempt = correlation.attempt,
            sekai.operation_id = caller_operation.as_str(),
            otel.kind = "server",
        );

        crate::obs::otel::set_parent_from_headers(&span, req.headers());
        let future = self.inner.call(req);
        Box::pin(
            async move {
                let response = future.await?;
                if let Some(code) = grpc_code(response.headers()) {
                    record_rpc(&grpc_service, &grpc_method, &code, started.elapsed());
                    Ok(response.map(|body| MetricsBody::already_recorded(body)))
                } else {
                    Ok(response
                        .map(|body| MetricsBody::new(body, grpc_service, grpc_method, started)))
                }
            }
            .instrument(span),
        )
    }
}

pin_project! {
    pub struct MetricsBody<B> {
        #[pin]
        inner: B,
        grpc_service: String,
        grpc_method: String,
        started: Instant,
        recorded: bool,
    }

    impl<B> PinnedDrop for MetricsBody<B> {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            if !*this.recorded {
                record_rpc(
                    this.grpc_service,
                    this.grpc_method,
                    "cancelled",
                    this.started.elapsed(),
                );
                *this.recorded = true;
            }
        }
    }
}

impl<B> MetricsBody<B> {
    fn new(inner: B, grpc_service: String, grpc_method: String, started: Instant) -> Self {
        Self {
            inner,
            grpc_service,
            grpc_method,
            started,
            recorded: false,
        }
    }

    fn already_recorded(inner: B) -> Self {
        Self {
            inner,
            grpc_service: String::new(),
            grpc_method: String::new(),
            started: Instant::now(),
            recorded: true,
        }
    }
}

impl<B> Body for MetricsBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.is_trailers()
                    && let Some(trailers) = frame.trailers_ref()
                {
                    let code = grpc_code(trailers).unwrap_or_else(|| "ok".into());
                    record_rpc(
                        this.grpc_service,
                        this.grpc_method,
                        &code,
                        this.started.elapsed(),
                    );
                    *this.recorded = true;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                if !*this.recorded {
                    record_rpc(
                        this.grpc_service,
                        this.grpc_method,
                        "unknown",
                        this.started.elapsed(),
                    );
                    *this.recorded = true;
                }
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                if !*this.recorded {
                    record_rpc(
                        this.grpc_service,
                        this.grpc_method,
                        "ok",
                        this.started.elapsed(),
                    );
                    *this.recorded = true;
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

fn parse_grpc_path(path: &str) -> (String, String) {
    let trimmed = path.trim_start_matches('/');
    let mut parts = trimmed.splitn(2, '/');
    let service = parts
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    let method = parts
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    if known_rpc(service, method) {
        (service.to_string(), method.to_string())
    } else {
        ("unknown".to_string(), "unknown".to_string())
    }
}

/// Methods the combined plane actually serves, keyed by wire service name.
///
/// Sekai and Chisei come from the checked-in proto inventories so adding an
/// RPC does not require a second edit here. Health is the well-known tonic
/// service registered next to them. Unknown paths stay unlabelled.
fn served_rpc_index() -> &'static HashMap<&'static str, HashSet<&'static str>> {
    static INDEX: OnceLock<HashMap<&'static str, HashSet<&'static str>>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index = HashMap::new();
        index.insert(
            SEKAI_GRPC_SERVICE,
            parse_sekai_service_rpcs(SEKAI_SERVICE_PROTO)
                .expect("SekaiService proto inventory")
                .into_iter()
                .collect(),
        );
        index.insert(
            CHISEI_GRPC_SERVICE,
            parse_service_rpcs(CHISEI_SERVICE_PROTO, "ChiseiService")
                .expect("ChiseiService proto inventory")
                .into_iter()
                .collect(),
        );
        index.insert(HEALTH_GRPC_SERVICE, HashSet::from(["Check", "Watch"]));
        index
    })
}

fn known_rpc(service: &str, method: &str) -> bool {
    served_rpc_index()
        .get(service)
        .is_some_and(|methods| methods.contains(method))
}

fn grpc_code(headers: &HeaderMap) -> Option<String> {
    headers
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .map(grpc_status_name)
}

fn grpc_status_name(code: &str) -> String {
    match code {
        "0" => "ok",
        "1" => "cancelled",
        "2" => "unknown",
        "3" => "invalid_argument",
        "4" => "deadline_exceeded",
        "5" => "not_found",
        "6" => "already_exists",
        "7" => "permission_denied",
        "8" => "resource_exhausted",
        "9" => "failed_precondition",
        "10" => "aborted",
        "11" => "out_of_range",
        "12" => "unimplemented",
        "13" => "internal",
        "14" => "unavailable",
        "15" => "data_loss",
        "16" => "unauthenticated",
        other => other,
    }
    .to_string()
}

/// Map a gRPC status code onto the bounded outcome vocabulary.
///
/// The per-method `grpc_*` series below keep method granularity. This
/// collapses to `subsystem` and `outcome` so control-plane overhead stays a
/// flat-cardinality series that can be aggregated across every method.
fn outcome_for_code(grpc_code: &str) -> crate::obs::labels::Outcome {
    use crate::obs::labels::Outcome;
    match grpc_code {
        "ok" => Outcome::Ok,
        "deadline_exceeded" => Outcome::Timeout,
        // Refusals the server chose, as opposed to failures it suffered.
        "unauthenticated"
        | "permission_denied"
        | "invalid_argument"
        | "failed_precondition"
        | "resource_exhausted"
        | "out_of_range"
        | "already_exists"
        | "not_found" => Outcome::Rejected,
        _ => Outcome::Failed,
    }
}

fn record_rpc(grpc_service: &str, grpc_method: &str, grpc_code: &str, elapsed: Duration) {
    crate::obs::signals::record_control_plane_overhead(
        crate::obs::labels::Subsystem::Grpc,
        outcome_for_code(grpc_code),
        elapsed,
    );
    counter!(
        "grpc_server_handled_total",
        "grpc_service" => grpc_service.to_string(),
        "grpc_method" => grpc_method.to_string(),
        "grpc_code" => grpc_code.to_string()
    )
    .increment(1);
    histogram!(
        "grpc_server_handling_seconds",
        "grpc_service" => grpc_service.to_string(),
        "grpc_method" => grpc_method.to_string()
    )
    .record(elapsed.as_secs_f64());

    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    // Successful unaries are already in metrics. Logging each one at INFO
    // floods operators when clients poll claim/heartbeat/receipt RPCs.
    if grpc_code == "ok" {
        debug!(
            grpc_service,
            grpc_method, grpc_code, elapsed_ms, "gRPC request completed"
        );
    } else {
        warn!(
            grpc_service,
            grpc_method, grpc_code, elapsed_ms, "gRPC request completed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::parse_grpc_path;

    #[test]
    fn recognizes_operation_receipt_rpc_paths() {
        for method in [
            "ReportOperationEvent",
            "GetOperationReceipt",
            "ClaimGatewayDispatch",
        ] {
            assert_eq!(
                parse_grpc_path(&format!("/chisei.ChiseiService/{method}")),
                ("chisei.ChiseiService".into(), method.into())
            );
        }
    }

    #[test]
    fn recognizes_governed_fact_rpc_paths() {
        for method in ["GetGovernedFactVersion", "ResolveInvariantSet"] {
            assert_eq!(
                parse_grpc_path(&format!("/sekai.SekaiService/{method}")),
                ("sekai.SekaiService".into(), method.into())
            );
        }
    }

    #[test]
    fn every_served_method_is_labelled() {
        let mut saw_federated_aggregate = false;
        let mut saw_apply_source_batch = false;
        for (service, methods) in super::served_rpc_index() {
            for method in methods {
                assert_eq!(
                    parse_grpc_path(&format!("/{service}/{method}")),
                    ((*service).to_string(), (*method).to_string()),
                    "{service}/{method} must not collapse to unknown"
                );
                if *service == super::SEKAI_GRPC_SERVICE && *method == "FederatedAggregate" {
                    saw_federated_aggregate = true;
                }
                if *service == super::SEKAI_GRPC_SERVICE && *method == "ApplySourceBatch" {
                    saw_apply_source_batch = true;
                }
            }
        }
        assert!(
            saw_federated_aggregate,
            "index must include FederatedAggregate (missing from the old hand list)"
        );
        assert!(
            saw_apply_source_batch,
            "index must include ApplySourceBatch (missing from the old hand list)"
        );
    }

    #[test]
    fn unknown_path_stays_unknown() {
        assert_eq!(
            parse_grpc_path("/sekai.SekaiService/NotARealRpc"),
            ("unknown".into(), "unknown".into())
        );
        assert_eq!(
            parse_grpc_path("/example.NotServed/ListObjects"),
            ("unknown".into(), "unknown".into())
        );
        assert_eq!(
            parse_grpc_path("/sekai.SekaiService/"),
            ("unknown".into(), "unknown".into())
        );
    }

    #[test]
    fn successful_completion_is_silent_at_info() {
        let logs = capture_completion_logs(tracing::Level::INFO, "ok");
        assert!(
            !logs.contains("gRPC request completed"),
            "ok completions must stay off the default info stream: {logs}"
        );
    }

    #[test]
    fn successful_completion_is_visible_at_debug() {
        let logs = capture_completion_logs(tracing::Level::DEBUG, "ok");
        assert!(
            logs.contains("gRPC request completed"),
            "ok completions remain available at debug: {logs}"
        );
    }

    #[test]
    fn non_ok_completion_is_warned_at_info() {
        let logs = capture_completion_logs(tracing::Level::INFO, "unknown");
        assert!(
            logs.contains("gRPC request completed"),
            "non-ok completions must remain visible at info: {logs}"
        );
        assert!(
            logs.contains("WARN"),
            "non-ok completions must remain WARN: {logs}"
        );
    }

    fn capture_completion_logs(max_level: tracing::Level, grpc_code: &str) -> String {
        use std::io::{self, Write};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                self.0.lock().expect("log buffer").write(data)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let _serialized = crate::obs::tracing_capture_lock();
        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(max_level)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            // As in the other capture: interest cached before this
            // subscriber existed would hide its events.
            tracing::callsite::rebuild_interest_cache();
            super::record_rpc("unknown", "unknown", grpc_code, Duration::from_millis(1));
        });
        String::from_utf8(buf.0.lock().expect("log buffer").clone()).expect("utf8 logs")
    }
}

#[cfg(test)]
mod outcome_mapping_tests {
    use super::outcome_for_code;
    use crate::obs::labels::Outcome;

    #[test]
    fn success_maps_to_ok() {
        assert_eq!(outcome_for_code("ok"), Outcome::Ok);
    }

    #[test]
    fn deadline_is_a_timeout_not_a_failure() {
        assert_eq!(outcome_for_code("deadline_exceeded"), Outcome::Timeout);
    }

    #[test]
    fn server_refusals_are_rejections_not_failures() {
        // A refused request is a policy outcome, not a broken server. Folding
        // these into Failed would make an authentication storm look like an
        // outage.
        for code in [
            "unauthenticated",
            "permission_denied",
            "invalid_argument",
            "failed_precondition",
            "resource_exhausted",
        ] {
            assert_eq!(outcome_for_code(code), Outcome::Rejected, "code {code}");
        }
    }

    #[test]
    fn unknown_and_internal_are_failures() {
        for code in ["internal", "unknown", "unavailable", "data_loss"] {
            assert_eq!(outcome_for_code(code), Outcome::Failed, "code {code}");
        }
    }
}
