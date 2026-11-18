//! Background pass spans through an in-memory exporter (#2643). Its own test
//! binary because it owns the process-global tracer provider.

use opentelemetry::trace::{SpanId, Status};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use sekai_obs::jobs::{JobKind, JobOutcome, JobPass};

fn attribute(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.to_string())
}

#[test]
fn passes_export_one_root_span_unless_idle() {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    opentelemetry::global::set_tracer_provider(provider);

    JobPass::start(JobKind::Retention).finish(JobOutcome::Ok, 0);
    assert!(
        exporter.get_finished_spans().unwrap().is_empty(),
        "an idle pass exports nothing"
    );

    JobPass::start(JobKind::Retention).finish(JobOutcome::Ok, 3);
    JobPass::start(JobKind::Retention).finish(JobOutcome::Held, 0);
    let mut drain = JobPass::start(JobKind::ObjectLogIngest);
    drain.on_behalf_of("op-admit-1");
    drain.on_behalf_of("");
    drain.finish(JobOutcome::Ok, 1);

    let spans = exporter.get_finished_spans().unwrap();
    let roots: Vec<_> = spans
        .iter()
        .filter(|span| span.parent_span_id == SpanId::INVALID)
        .collect();
    let summary: Vec<_> = roots
        .iter()
        .map(|span| {
            (
                span.name.to_string(),
                attribute(span, "job.outcome").unwrap(),
                attribute(span, "job.items").unwrap(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("retention".into(), "ok".into(), "3".into()),
            ("retention".into(), "held".into(), "0".into()),
            ("object_log_ingest".into(), "ok".into(), "1".into()),
        ]
    );
    assert!(matches!(roots[1].status, Status::Error { .. }));

    let drain = roots[2];
    let linked: Vec<_> = spans
        .iter()
        .filter(|span| span.parent_span_id == drain.span_context.span_id())
        .map(|span| {
            assert_eq!(span.span_context.trace_id(), drain.span_context.trace_id());
            attribute(span, "sekai.operation_id").unwrap()
        })
        .collect();
    assert_eq!(linked, ["op-admit-1"]);
}
