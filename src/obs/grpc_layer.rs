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
        let span = info_span!(
            "grpc",
            grpc_service = %grpc_service,
            grpc_method = %grpc_method
        );

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
            "CreateObject"
                | "GetObject"
                | "UpdateObject"
                | "DeleteObject"
                | "ListObjects"
                | "CreateObjectSet"
                | "ListObjectSets"
                | "DeleteObjectSet"
                | "ResolveObjectSet"
                | "FindByExternalId"
                | "FindByProperty"
                | "CreateLink"
                | "DeleteLink"
                | "GetLinks"
                | "GetLinkedObjects"
                | "Traverse"
                | "ListSchemaTypes"
                | "CreateFunction"
                | "ListFunctions"
                | "ExecuteFunction"
                | "CreateDataset"
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
                | "ReleaseReservation"
                | "ListReservations"
                | "ListRunEvents"
                | "ReconcileWorkUnits"
                | "GetCoordinationSnapshot"
        ),
        "chisei.ChiseiService" => matches!(
            method,
            "CheckBudget"
                | "RecordUsage"
                | "SetBudgetLimit"
                | "SetNamespacePolicy"
                | "ResolvePolicy"
                | "CheckEgress"
                | "RunPipeline"
                | "ListPipelineRuns"
                | "RecordSampleObservation"
                | "RecordGatewayAudit"
                | "PlanExecution"
                | "ExecutePlan"
                | "ExecutePlanStream"
                | "GetAffinity"
                | "CreateEvalSuite"
                | "ListEvalSuites"
                | "GetEvalSuite"
                | "CreateEvalRun"
                | "GetEvalRun"
                | "ListEvalRuns"
                | "TrackEvalIteration"
                | "GetLatestEvalIteration"
                | "ListEvalIterations"
                | "CompareRuns"
                | "EvalVariance"
                | "EvalModelCompare"
                | "EvolveSuggest"
                | "EvolveEnhance"
                | "EvolveRecommend"
                | "EvolveReport"
                | "EvolvePatterns"
                | "EvolveVariance"
                | "EvolveAbResults"
                | "EvolveTemplates"
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

fn record_rpc(grpc_service: &str, grpc_method: &str, grpc_code: &str, elapsed: Duration) {
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
