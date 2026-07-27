//! Closed label vocabulary for control-plane metrics.
//!
//! Issue #98 requires that metrics expose operational behavior "without leaking
//! sensitive labels or payloads", using "bounded-cardinality identifiers", and
//! that cross-namespace or cross-classification content equality is not
//! observable through metrics.
//!
//! Free-form `&str` labels cannot satisfy that: any call site may pass an
//! object id, a namespace name, or a content digest, and the leak is invisible
//! at review time. Every label in this module is therefore a closed enum with a
//! `'static` rendering, so the emitted label set is finite and auditable, and a
//! caller cannot smuggle caller-controlled data into a label position.
//!
//! Adding a variant is a deliberate, reviewable act. Adding a *value* is not
//! possible.

/// Subsystem a signal originates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subsystem {
    Sekai,
    Chisei,
    Gateway,
    Grpc,
    Llm,
    Persistence,
    Evidence,
}

impl Subsystem {
    pub const ALL: &'static [Subsystem] = &[
        Subsystem::Sekai,
        Subsystem::Chisei,
        Subsystem::Gateway,
        Subsystem::Grpc,
        Subsystem::Llm,
        Subsystem::Persistence,
        Subsystem::Evidence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Subsystem::Sekai => "sekai",
            Subsystem::Chisei => "chisei",
            Subsystem::Gateway => "gateway",
            Subsystem::Grpc => "grpc",
            Subsystem::Llm => "llm",
            Subsystem::Persistence => "persistence",
            Subsystem::Evidence => "evidence",
        }
    }
}

/// Terminal disposition of a unit of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Ok,
    Rejected,
    Failed,
    Timeout,
}

impl Outcome {
    pub const ALL: &'static [Outcome] = &[
        Outcome::Ok,
        Outcome::Rejected,
        Outcome::Failed,
        Outcome::Timeout,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Rejected => "rejected",
            Outcome::Failed => "failed",
            Outcome::Timeout => "timeout",
        }
    }
}

/// Why work was refused before or during execution.
///
/// Deliberately coarse. A finer reason risks distinguishing *which* policy or
/// *which* namespace refused the work, which is the cross-classification
/// inference Issue #98 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RejectionReason {
    Unauthorized,
    PolicyBlocked,
    BudgetExhausted,
    Overloaded,
    Malformed,
    ShuttingDown,
}

impl RejectionReason {
    pub const ALL: &'static [RejectionReason] = &[
        RejectionReason::Unauthorized,
        RejectionReason::PolicyBlocked,
        RejectionReason::BudgetExhausted,
        RejectionReason::Overloaded,
        RejectionReason::Malformed,
        RejectionReason::ShuttingDown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            RejectionReason::Unauthorized => "unauthorized",
            RejectionReason::PolicyBlocked => "policy_blocked",
            RejectionReason::BudgetExhausted => "budget_exhausted",
            RejectionReason::Overloaded => "overloaded",
            RejectionReason::Malformed => "malformed",
            RejectionReason::ShuttingDown => "shutting_down",
        }
    }
}

/// Kind of wait a caller observed before making progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WaitKind {
    ConnectionAcquire,
    Query,
    Transaction,
    Migration,
    QueueAdmission,
}

impl WaitKind {
    pub const ALL: &'static [WaitKind] = &[
        WaitKind::ConnectionAcquire,
        WaitKind::Query,
        WaitKind::Transaction,
        WaitKind::Migration,
        WaitKind::QueueAdmission,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            WaitKind::ConnectionAcquire => "connection_acquire",
            WaitKind::Query => "query",
            WaitKind::Transaction => "transaction",
            WaitKind::Migration => "migration",
            WaitKind::QueueAdmission => "queue_admission",
        }
    }
}

/// Named cache within the control plane.
///
/// These are the caches that actually exist, both in the gateway runtime. An
/// earlier revision named four caches taken from the issue text rather than
/// from the code — `PolicyResolution`, `ProviderProfile`, `EvidenceSchema`,
/// and `Memory` — none of which were real. `PolicyResolver` is an
/// authoritative in-memory store where a lookup failure means no policy is
/// set, not that a fetch is needed, and the provider-profile `cache_*` fields
/// describe provider-side prompt-token accounting rather than a local cache.
///
/// A closed vocabulary is only auditable if its entries correspond to
/// something; variants that name nothing make the surface look more instrumented
/// than it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cache {
    /// Gateway identity key cache, TTL from `CHISEI_GATEWAY_KEY_CACHE_TTL_SECS`.
    GatewayKey,
    /// Gateway governance cache holding budget, policy, and egress decisions.
    GatewayGovernance,
}

impl Cache {
    pub const ALL: &'static [Cache] = &[Cache::GatewayKey, Cache::GatewayGovernance];

    pub const fn as_str(self) -> &'static str {
        match self {
            Cache::GatewayKey => "gateway_key",
            Cache::GatewayGovernance => "gateway_governance",
        }
    }
}

/// Outcome of a cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CacheOutcome {
    Hit,
    Miss,
    Evicted,
}

impl CacheOutcome {
    pub const ALL: &'static [CacheOutcome] =
        &[CacheOutcome::Hit, CacheOutcome::Miss, CacheOutcome::Evicted];

    pub const fn as_str(self) -> &'static str {
        match self {
            CacheOutcome::Hit => "hit",
            CacheOutcome::Miss => "miss",
            CacheOutcome::Evicted => "evicted",
        }
    }
}

/// Lag surface being observed between production and durable visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LagSurface {
    Receipt,
    Audit,
    EvidenceProjection,
}

impl LagSurface {
    pub const ALL: &'static [LagSurface] = &[
        LagSurface::Receipt,
        LagSurface::Audit,
        LagSurface::EvidenceProjection,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            LagSurface::Receipt => "receipt",
            LagSurface::Audit => "audit",
            LagSurface::EvidenceProjection => "evidence_projection",
        }
    }
}

/// A deduplication or idempotency decision.
///
/// Only outcomes that a call site actually produces are listed. Issue #98 names
/// a longer set — duplicate evidence deliveries, projection suppressions,
/// shared bytes, garbage-collection backlog, merge and split decisions — but
/// those describe machinery this codebase does not currently reach, and naming
/// them here would make the surface look more instrumented than it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeduplicationEvent {
    /// Same idempotency key and same payload: the retry was suppressed.
    IdempotentReplay,
    /// Same idempotency key, different payload: the caller reused a key.
    IdempotencyConflict,
}

impl DeduplicationEvent {
    pub const ALL: &'static [DeduplicationEvent] = &[
        DeduplicationEvent::IdempotentReplay,
        DeduplicationEvent::IdempotencyConflict,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            DeduplicationEvent::IdempotentReplay => "idempotent_replay",
            DeduplicationEvent::IdempotencyConflict => "idempotency_conflict",
        }
    }
}

/// Why a request fell back from its preferred execution path.
///
/// These name the fallbacks the gateway actually performs. An earlier revision
/// listed `ProviderUnavailable`, `ProviderError`, `Timeout`, and `BudgetGuard`,
/// taken from the issue text; none had a production emitter, and the retry
/// decision they implied (`harness::retry_disposition`) has no production
/// caller either — only its own tests and a benchmark.
///
/// The fallbacks that do run are both about the control plane: serving a
/// last-known budget while it is unreachable, and accepting a degraded route
/// when it responds with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FallbackTrigger {
    /// Control plane unreachable; a cached last-known budget was used.
    GovernanceUnavailable,
    /// Control plane responded but degraded the route.
    BudgetDegraded,
}

impl FallbackTrigger {
    pub const ALL: &'static [FallbackTrigger] = &[
        FallbackTrigger::GovernanceUnavailable,
        FallbackTrigger::BudgetDegraded,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            FallbackTrigger::GovernanceUnavailable => "governance_unavailable",
            FallbackTrigger::BudgetDegraded => "budget_degraded",
        }
    }
}

/// Answer path taken by the S1 lookup-first short-circuit (#281).
///
/// Closed vocabulary: either a full structured lookup hit or the model path
/// (including fail-closed refusals). Never records free-form content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LookupFirstPath {
    LookupHit,
    ModelPath,
}

impl LookupFirstPath {
    pub const ALL: &'static [LookupFirstPath] =
        &[LookupFirstPath::LookupHit, LookupFirstPath::ModelPath];

    pub const fn as_str(self) -> &'static str {
        match self {
            LookupFirstPath::LookupHit => "lookup_hit",
            LookupFirstPath::ModelPath => "model_path",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Upper bound on distinct label values across the whole vocabulary. A
    /// change here is a deliberate cardinality decision, not an accident.
    const MAX_TOTAL_LABEL_VALUES: usize = 42;

    fn rendered<T: Copy>(all: &[T], render: fn(T) -> &'static str) -> Vec<&'static str> {
        all.iter().copied().map(render).collect()
    }

    #[test]
    fn every_label_value_is_lowercase_snake_case_and_bounded() {
        let groups: Vec<Vec<&'static str>> = vec![
            rendered(Subsystem::ALL, Subsystem::as_str),
            rendered(Outcome::ALL, Outcome::as_str),
            rendered(RejectionReason::ALL, RejectionReason::as_str),
            rendered(WaitKind::ALL, WaitKind::as_str),
            rendered(Cache::ALL, Cache::as_str),
            rendered(CacheOutcome::ALL, CacheOutcome::as_str),
            rendered(LagSurface::ALL, LagSurface::as_str),
            rendered(FallbackTrigger::ALL, FallbackTrigger::as_str),
            rendered(DeduplicationEvent::ALL, DeduplicationEvent::as_str),
            rendered(LookupFirstPath::ALL, LookupFirstPath::as_str),
        ];

        let mut total = 0;
        for group in &groups {
            // Values within a group must be distinct, or two states collapse
            // into one time series and become unreadable.
            let distinct: BTreeSet<_> = group.iter().collect();
            assert_eq!(distinct.len(), group.len(), "duplicate label value");
            total += group.len();

            for value in group {
                assert!(!value.is_empty(), "empty label value");
                assert!(
                    value
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                    "label {value} is not lowercase snake_case"
                );
            }
        }

        assert!(
            total <= MAX_TOTAL_LABEL_VALUES,
            "label vocabulary grew to {total}, above the {MAX_TOTAL_LABEL_VALUES} bound"
        );
    }

    #[test]
    fn all_slices_cover_every_variant() {
        // A variant missing from ALL would silently escape the cardinality
        // bound and the casing check above.
        assert_eq!(Subsystem::ALL.len(), 7);
        assert_eq!(Outcome::ALL.len(), 4);
        assert_eq!(RejectionReason::ALL.len(), 6);
        assert_eq!(WaitKind::ALL.len(), 5);
        assert_eq!(Cache::ALL.len(), 2);
        assert_eq!(CacheOutcome::ALL.len(), 3);
        assert_eq!(LagSurface::ALL.len(), 3);
        assert_eq!(FallbackTrigger::ALL.len(), 2);
        assert_eq!(DeduplicationEvent::ALL.len(), 2);
        assert_eq!(LookupFirstPath::ALL.len(), 2);
    }
}
