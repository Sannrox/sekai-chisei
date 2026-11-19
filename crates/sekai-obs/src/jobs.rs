//! Root spans for background passes (#2643).
//!
//! Each pass of a background loop that did work, failed, or found its work
//! held by another instance exports one root span named by a closed
//! [`JobKind`]. An idle pass (`ok` with no items) exports nothing, so a quiet
//! plane does not flood the collector. The span is built after the pass with
//! its real start and end times, which is what lets an idle pass skip it.
//!
//! Work done for a recorded operation adds one child span per operation
//! carrying `sekai.operation_id` (ADR 0069), the join key to that
//! operation's request trace. Receipts keep the operation id, not a trace
//! context, so the join is by attribute rather than by span link.

use std::time::SystemTime;

use opentelemetry::trace::{Span as _, SpanKind, Status, TraceContextExt, Tracer as _};
use opentelemetry::{Context, KeyValue, global};

/// Background loop a pass belongs to. Closed so span names stay bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum JobKind {
    EmbeddingCatchUp,
    SearchCatchUp,
    AdmissionReconcile,
    Retention,
    ExportSweep,
    ConsumerViolationSweep,
    CriticalityOutbox,
    ObjectLogIngest,
    SecurityReopen,
    CatalogReconcile,
    ScheduleTick,
}

impl JobKind {
    pub const ALL: &'static [JobKind] = &[
        JobKind::EmbeddingCatchUp,
        JobKind::SearchCatchUp,
        JobKind::AdmissionReconcile,
        JobKind::Retention,
        JobKind::ExportSweep,
        JobKind::ConsumerViolationSweep,
        JobKind::CriticalityOutbox,
        JobKind::ObjectLogIngest,
        JobKind::SecurityReopen,
        JobKind::CatalogReconcile,
        JobKind::ScheduleTick,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            JobKind::EmbeddingCatchUp => "embedding_catch_up",
            JobKind::SearchCatchUp => "search_catch_up",
            JobKind::AdmissionReconcile => "admission_reconcile",
            JobKind::Retention => "retention",
            JobKind::ExportSweep => "export_sweep",
            JobKind::ConsumerViolationSweep => "consumer_violation_sweep",
            JobKind::CriticalityOutbox => "criticality_outbox",
            JobKind::ObjectLogIngest => "object_log_ingest",
            JobKind::SecurityReopen => "security_reopen",
            JobKind::CatalogReconcile => "catalog_reconcile",
            JobKind::ScheduleTick => "schedule_tick",
        }
    }
}

/// How a pass ended. Closed, like [`JobKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JobOutcome {
    Ok,
    /// Another instance held the lease for this pass's work.
    Held,
    Failed,
}

impl JobOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            JobOutcome::Ok => "ok",
            JobOutcome::Held => "held",
            JobOutcome::Failed => "failed",
        }
    }
}

/// Operations one pass names at most; the rest are counted in `job.items`.
pub const MAX_OPERATIONS_PER_PASS: usize = 32;

/// One background pass. Start it before the work and [`JobPass::finish`] it
/// after; dropping it unfinished exports nothing.
pub struct JobPass {
    kind: JobKind,
    started: SystemTime,
    operations: Vec<String>,
}

impl JobPass {
    pub fn start(kind: JobKind) -> Self {
        Self {
            kind,
            started: SystemTime::now(),
            operations: Vec::new(),
        }
    }

    /// Record that this pass worked for `operation_id`. Empty ids and ids
    /// past [`MAX_OPERATIONS_PER_PASS`] are dropped.
    pub fn on_behalf_of(&mut self, operation_id: impl Into<String>) {
        let operation_id = operation_id.into();
        if !operation_id.is_empty() && self.operations.len() < MAX_OPERATIONS_PER_PASS {
            self.operations.push(operation_id);
        }
    }

    /// Export the pass as one root span unless it was idle: `ok` with no
    /// items and no operations.
    pub fn finish(self, outcome: JobOutcome, items: u64) {
        if outcome == JobOutcome::Ok && items == 0 && self.operations.is_empty() {
            return;
        }
        let ended = SystemTime::now();
        let tracer = global::tracer("sekai.jobs");
        let mut span = tracer.build_with_context(
            tracer
                .span_builder(self.kind.as_str())
                .with_kind(SpanKind::Internal)
                .with_start_time(self.started)
                .with_attributes([
                    KeyValue::new("job.kind", self.kind.as_str()),
                    KeyValue::new("job.outcome", outcome.as_str()),
                    KeyValue::new("job.items", items.min(i64::MAX as u64) as i64),
                ]),
            // A fresh context: a pass is a root, never a child of whatever
            // span happened to be current on this thread.
            &Context::new(),
        );
        if outcome != JobOutcome::Ok {
            span.set_status(Status::error(outcome.as_str()));
        }
        let pass = Context::new().with_span(span);
        for operation_id in self.operations {
            tracer
                .span_builder("operation")
                .with_kind(SpanKind::Internal)
                .with_start_time(self.started)
                .with_attributes([KeyValue::new("sekai.operation_id", operation_id)])
                .start_with_context(&tracer, &pass)
                .end_with_timestamp(ended);
        }
        pass.span().end_with_timestamp(ended);
    }
}

#[cfg(test)]
mod tests {
    use super::JobKind;
    use std::collections::BTreeSet;

    #[test]
    fn job_vocabulary_is_closed_and_snake_case() {
        let distinct: BTreeSet<&str> = JobKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(distinct.len(), JobKind::ALL.len(), "duplicate job kind");
        for kind in JobKind::ALL {
            let name = kind.as_str();
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "job kind {name} is not snake_case"
            );
        }
    }
}
