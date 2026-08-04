use futures_util::future::BoxFuture;
use http::{HeaderMap, Request, Response};
use http_body::{Body, Frame};
use metrics::{counter, histogram};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower::{Layer, Service};
use tracing::{Instrument, info, info_span, warn};

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
        let span = info_span!(
            "grpc",
            grpc_service = %grpc_service,
            grpc_method = %grpc_method,
            stage = crate::obs::correlation::Stage::Operation.as_str(),
            operation = %correlation.operation,
            attempt = correlation.attempt,
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

fn known_rpc(service: &str, method: &str) -> bool {
    match service {
        "sekai.SekaiService" => matches!(
            method,
            "AcquireLease"
                | "GetLease"
                | "RefreshLease"
                | "ReleaseLease"
                | "TakeoverExpiredLease"
                | "CreateObject"
                | "GetObject"
                | "UpdateObject"
                | "DeleteObject"
                | "ListObjects"
                | "FindByExternalId"
                | "FindByProperty"
                | "CreateLink"
                | "DeleteLink"
                | "GetLinks"
                | "GetLinkedObjects"
                | "Traverse"
                | "GetGovernedFactVersion"
                | "ResolveInvariantSet"
                | "ListSchemaTypes"
                | "CreateFunction"
                | "ListFunctions"
                | "CreateDataset"
                | "UpdateDataset"
                | "ListDatasets"
                | "AppendRows"
                | "QueryRows"
                | "CreateVirtualTable"
                | "ListVirtualTables"
                | "CreateGrant"
                | "DeleteGrant"
                | "ListGrants"
                | "CheckAccess"
                | "RecordDecision"
                | "ListDecisions"
                | "ListObjectChanges"
                | "ExecuteAction"
                | "GetLineage"
                | "CreateContentionScope"
                | "UpdateContentionScope"
                | "GetContentionScope"
                | "ListContentionScopes"
                | "CreateWorkUnit"
                | "GetWorkUnit"
                | "ListWorkUnits"
                | "TryAdmitWorkUnit"
                | "HeartbeatWorkUnit"
                | "CompleteWorkUnit"
                | "FailWorkUnit"
                | "CancelWorkUnit"
                | "ListReservations"
                | "ListRunEvents"
                | "ReconcileWorkUnits"
        ),
        "chisei.ChiseiService" => matches!(
            method,
            "RecordUsage"
                | "SetBudgetLimit"
                | "SetNamespacePolicy"
                | "PlanExecution"
                | "ExecutePlanStream"
                | "ReportOperationEvent"
                | "GetOperationReceipt"
                | "GetSampleObservation"
                | "ClaimGatewayDispatch"
                | "PutEvaluatorDefinition"
                | "PutEvaluationPlan"
                | "ResolveEvaluationPlan"
                | "GetEvaluationGateEvidence"
                | "ExecuteEvaluationManifest"
                | "CancelEvaluationExecution"
        ),
        "grpc.health.v1.Health" => matches!(method, "Check" | "Watch"),
        _ => false,
    }
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
    if grpc_code == "ok" {
        info!(
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
