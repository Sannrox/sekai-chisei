use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

use super::otel::{TelemetryGuard, build_provider};

pub fn init() -> TelemetryGuard {
    let provider = build_provider();

    if std::env::var("LOG_FORMAT")
        .map(|value| value.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
    {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let format_layer = tracing_subscriber::fmt::layer().json().with_filter(filter);
        init_with_format(format_layer, provider.as_ref());
    } else {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let format_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_filter(filter);
        init_with_format(format_layer, provider.as_ref());
    }

    TelemetryGuard::new(provider)
}

fn init_with_format<L>(format_layer: L, provider: Option<&SdkTracerProvider>)
where
    L: Layer<tracing_subscriber::Registry> + Send + Sync + 'static,
{
    let subscriber = tracing_subscriber::registry().with(format_layer);
    if let Some(provider) = provider {
        let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
        // Export only spans whose fields are deliberately bounded below. In
        // particular, do not turn arbitrary tracing events into OTel events:
        // existing event sites may carry provider diagnostics or content.
        let otel_filter = filter_fn(|metadata| {
            metadata.is_span() && matches!(metadata.name(), "grpc" | "gateway.http" | "stage")
        });
        let otel_layer = tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(otel_filter);
        let _ = subscriber.with(otel_layer).try_init();
    } else {
        let _ = subscriber.try_init();
    }
}
