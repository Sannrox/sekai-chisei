use std::time::Duration;

use http::HeaderMap;
use opentelemetry::Context;
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry::trace::TraceContextExt;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_opentelemetry::OpenTelemetrySpanExt;

const DEFAULT_SERVICE_NAME: &str = "sekai-chisei";

/// Owns the exporter until the process has stopped accepting work.
///
/// Dropping the provider flushes pending spans, but an explicit shutdown makes
/// the lifecycle visible at the same boundary as the server shutdown.
pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl TelemetryGuard {
    pub(crate) fn new(provider: Option<SdkTracerProvider>) -> Self {
        Self { provider }
    }

    pub fn shutdown(&mut self) {
        let Some(provider) = self.provider.take() else {
            return;
        };
        if provider
            .shutdown_with_timeout(Duration::from_secs(5))
            .is_err()
        {
            eprintln!("OpenTelemetry trace exporter shutdown failed");
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(crate) fn build_provider() -> Option<SdkTracerProvider> {
    if !telemetry_enabled() {
        return None;
    }

    let exporter = match SpanExporter::builder().build() {
        Ok(exporter) => exporter,
        Err(_) => {
            eprintln!("OpenTelemetry trace export disabled: invalid OTLP exporter configuration");
            return None;
        }
    };
    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name)
        .build();

    Some(
        SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build(),
    )
}

fn telemetry_enabled() -> bool {
    if env_truthy("OTEL_SDK_DISABLED") {
        return false;
    }
    if std::env::var("OTEL_TRACES_EXPORTER")
        .ok()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("none"))
    {
        return false;
    }
    non_empty_env("OTEL_EXPORTER_OTLP_ENDPOINT")
        || non_empty_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
}

fn non_empty_env(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

pub(crate) fn extract_parent(headers: &HeaderMap) -> Context {
    TraceContextPropagator::new().extract(&HeaderExtractor(headers))
}

pub(crate) fn set_parent_from_headers(span: &tracing::Span, headers: &HeaderMap) {
    let parent = extract_parent(headers);
    if parent.span().span_context().is_valid() {
        let _ = span.set_parent(parent);
    }
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|key| key.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_valid_w3c_trace_context() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );

        let context = extract_parent(&headers);
        assert_eq!(
            context.span().span_context().trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert!(context.span().span_context().is_remote());
    }
}
