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
/// These are the caches that actually exist, both in `src/gateway.rs`. An
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

/// Why a request fell back from its preferred execution path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FallbackTrigger {
    ProviderUnavailable,
    ProviderError,
    Timeout,
    BudgetGuard,
}

impl FallbackTrigger {
    pub const ALL: &'static [FallbackTrigger] = &[
        FallbackTrigger::ProviderUnavailable,
        FallbackTrigger::ProviderError,
        FallbackTrigger::Timeout,
        FallbackTrigger::BudgetGuard,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            FallbackTrigger::ProviderUnavailable => "provider_unavailable",
            FallbackTrigger::ProviderError => "provider_error",
            FallbackTrigger::Timeout => "timeout",
            FallbackTrigger::BudgetGuard => "budget_guard",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Upper bound on distinct label values across the whole vocabulary. A
    /// change here is a deliberate cardinality decision, not an accident.
    const MAX_TOTAL_LABEL_VALUES: usize = 40;

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
        assert_eq!(FallbackTrigger::ALL.len(), 4);
    }
}
