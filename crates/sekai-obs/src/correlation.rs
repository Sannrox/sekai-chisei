//! Closed correlation-stage vocabulary for tracing control-plane work.
//!
//! The *stage* set must stay finite so span names stay bounded. Identifier
//! generation stays in the root crate because it reads HTTP headers and
//! normalizes caller operation ids through Sekai.
//!
//! A request's main stages run inside [`in_stage`] / [`in_stage_async`], or
//! hold a [`StageGuard`] when one stage spans several steps. Each opens one
//! child span of the current span named after the stage, with an `outcome` of
//! `ok`, `refused`, or `failed`. Stage spans carry no other fields: no object
//! ids, namespaces, content, or digests (#98).

use std::future::Future;

use tracing::Instrument;
use tracing::field::Empty;

/// Stage of work a span describes. Closed so span names stay bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Stage {
    Operation,
    Attempt,
    ProviderRequest,
    /// One store transaction or connection checkout.
    Persistence,
    EvidenceProjection,
    Authorization,
    PolicyDecision,
    Budget,
    Routing,
    EvaluationStep,
    StochasticTrial,
    /// A call to a service outside the plane other than a model provider.
    OutboundCall,
}

impl Stage {
    pub const ALL: &'static [Stage] = &[
        Stage::Operation,
        Stage::Attempt,
        Stage::ProviderRequest,
        Stage::Persistence,
        Stage::EvidenceProjection,
        Stage::Authorization,
        Stage::PolicyDecision,
        Stage::Budget,
        Stage::Routing,
        Stage::EvaluationStep,
        Stage::StochasticTrial,
        Stage::OutboundCall,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Operation => "operation",
            Stage::Attempt => "attempt",
            Stage::ProviderRequest => "provider_request",
            Stage::Persistence => "persistence",
            Stage::EvidenceProjection => "evidence_projection",
            Stage::Authorization => "authorization",
            Stage::PolicyDecision => "policy_decision",
            Stage::Budget => "budget",
            Stage::Routing => "routing",
            Stage::EvaluationStep => "evaluation_step",
            Stage::StochasticTrial => "stochastic_trial",
            Stage::OutboundCall => "outbound_call",
        }
    }

    /// Whether an error from this stage is a decision to refuse the request
    /// rather than a failure to do the work.
    const fn refuses(self) -> bool {
        matches!(
            self,
            Stage::Authorization | Stage::PolicyDecision | Stage::Budget
        )
    }
}

/// How a stage ended. Closed, like [`Stage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StageOutcome {
    Ok,
    Refused,
    Failed,
}

impl StageOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            StageOutcome::Ok => "ok",
            StageOutcome::Refused => "refused",
            StageOutcome::Failed => "failed",
        }
    }
}

/// One stage span under the current span. Its lifetime is the stage's
/// duration. Dropping it records `ok` unless [`StageGuard::check`] or
/// [`StageGuard::refuse`] recorded an earlier outcome.
pub struct StageGuard {
    span: tracing::Span,
    stage: Stage,
    recorded: bool,
}

impl StageGuard {
    pub fn open(stage: Stage) -> Self {
        let span = tracing::info_span!(
            "stage",
            otel.name = stage.as_str(),
            stage = stage.as_str(),
            outcome = Empty,
            otel.status_code = Empty,
        );
        Self {
            span,
            stage,
            recorded: false,
        }
    }

    /// [`StageGuard::open`] only under a current span. Store checkouts use
    /// it so background work outside any request does not export one orphan
    /// trace per checkout.
    pub fn open_nested(stage: Stage) -> Option<Self> {
        if tracing::Span::current().is_none() {
            None
        } else {
            Some(Self::open(stage))
        }
    }

    pub fn span(&self) -> &tracing::Span {
        &self.span
    }

    pub fn in_scope<T>(&self, work: impl FnOnce() -> T) -> T {
        self.span.in_scope(work)
    }

    /// Record an `Err` as this stage's outcome: `refused` for authorization,
    /// policy, and budget stages, `failed` for any other.
    pub fn check<T, E>(&mut self, result: Result<T, E>) -> Result<T, E> {
        if result.is_err() {
            self.record(if self.stage.refuses() {
                StageOutcome::Refused
            } else {
                StageOutcome::Failed
            });
        }
        result
    }

    /// Record a refusal decided without an `Err`, such as a persisted denial.
    pub fn refuse(&mut self) {
        self.record(StageOutcome::Refused);
    }

    /// Record a failure reported without an `Err`.
    pub fn fail(&mut self) {
        self.record(StageOutcome::Failed);
    }

    fn record(&mut self, outcome: StageOutcome) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        self.span.record("outcome", outcome.as_str());
        if outcome != StageOutcome::Ok {
            self.span.record("otel.status_code", "ERROR");
        }
    }
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        self.record(StageOutcome::Ok);
    }
}

/// Run a synchronous stage; see [`StageGuard::check`] for the outcome.
pub fn in_stage<T, E>(stage: Stage, work: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let mut guard = StageGuard::open(stage);
    let result = guard.in_scope(work);
    guard.check(result)
}

/// [`in_stage`] for a future.
pub async fn in_stage_async<T, E>(
    stage: Stage,
    work: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut guard = StageGuard::open(stage);
    let result = work.instrument(guard.span.clone()).await;
    guard.check(result)
}

#[cfg(test)]
mod tests {
    use super::{Stage, StageGuard, StageOutcome, in_stage};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    #[test]
    fn stage_vocabulary_is_closed_and_snake_case() {
        assert_eq!(Stage::ALL.len(), 12);
        let distinct: BTreeSet<&str> = Stage::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(distinct.len(), Stage::ALL.len(), "duplicate stage name");
        for stage in Stage::ALL {
            let name = stage.as_str();
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "stage {name} is not snake_case"
            );
        }
    }

    /// Outcome recorded on each stage span, in span creation order.
    #[derive(Clone, Default)]
    struct Outcomes(Arc<Mutex<Vec<String>>>);

    impl tracing::field::Visit for Outcomes {
        fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "outcome" {
                self.0.lock().unwrap().push(value.into());
            }
        }
    }

    impl tracing::Subscriber for Outcomes {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
            values.record(&mut self.clone());
        }
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, _: &tracing::Event<'_>) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[test]
    fn errors_refuse_in_deciding_stages_and_fail_elsewhere() {
        let outcomes = Outcomes::default();
        tracing::subscriber::with_default(outcomes.clone(), || {
            let _ = in_stage(Stage::Authorization, || Ok::<_, ()>(()));
            let _ = in_stage(Stage::Authorization, || Err::<(), _>(()));
            let _ = in_stage(Stage::Budget, || Err::<(), _>(()));
            let _ = in_stage(Stage::Persistence, || Err::<(), _>(()));
            StageGuard::open(Stage::PolicyDecision).refuse();
        });
        assert_eq!(
            *outcomes.0.lock().unwrap(),
            [
                StageOutcome::Ok.as_str(),
                "refused",
                "refused",
                StageOutcome::Failed.as_str(),
                "refused"
            ]
        );
    }
}
