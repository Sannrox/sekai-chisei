//! Correlation identifiers for tracing control-plane work.
//!
//! Issue #98 asks that traces correlate operation, attempt, provider request,
//! persistence work, and evidence projection "using bounded-cardinality
//! identifiers". Two separate constraints hide in that phrase:
//!
//! - the *stage* vocabulary must be closed, so span names stay a finite set;
//! - the *identifier* must be opaque, so correlating two spans never reveals
//!   which namespace, principal, or content they touched.
//!
//! A correlation id is therefore generated, not derived. Deriving it from a
//! request — hashing a namespace, reusing an object id — would make equal ids
//! prove equal inputs, which is exactly the cross-namespace content equality
//! Issue #98 forbids being observable.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Stage of work a span describes. Closed so span names stay bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Operation,
    Attempt,
    ProviderRequest,
    Persistence,
    EvidenceProjection,
}

impl Stage {
    pub const ALL: &'static [Stage] = &[
        Stage::Operation,
        Stage::Attempt,
        Stage::ProviderRequest,
        Stage::Persistence,
        Stage::EvidenceProjection,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Operation => "operation",
            Stage::Attempt => "attempt",
            Stage::ProviderRequest => "provider_request",
            Stage::Persistence => "persistence",
            Stage::EvidenceProjection => "evidence_projection",
        }
    }
}

/// An opaque correlation id.
///
/// Generated from a process-local counter mixed with the process start, not
/// from any request content. Two operations on identical inputs get different
/// ids, and an id reveals nothing about what it correlates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CorrelationId(u64);

static NEXT_CORRELATION: AtomicU64 = AtomicU64::new(1);

impl CorrelationId {
    /// Issue a fresh id. Never derived from caller-supplied data.
    pub fn new() -> Self {
        Self(NEXT_CORRELATION.fetch_add(1, Ordering::Relaxed))
    }

    /// Rendered form used in span fields: fixed-width hex, no content.
    pub fn as_hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

/// Correlation carried across the stages of one operation.
#[derive(Debug, Clone, Copy)]
pub struct Correlation {
    pub operation: CorrelationId,
    /// Attempt number within the operation, starting at 1.
    pub attempt: u32,
}

impl Correlation {
    pub fn new_operation() -> Self {
        Self {
            operation: CorrelationId::new(),
            attempt: 1,
        }
    }

    /// Next attempt of the same operation, keeping the operation id stable so
    /// retries stay correlated with their original.
    pub fn next_attempt(self) -> Self {
        Self {
            operation: self.operation,
            attempt: self.attempt.saturating_add(1),
        }
    }
}

/// Open a span for one stage of a correlated operation.
///
/// Only the stage, the opaque operation id, and the attempt number are
/// recorded. Nothing derived from request content enters a span field.
#[macro_export]
macro_rules! stage_span {
    ($stage:expr, $correlation:expr) => {
        tracing::info_span!(
            "stage",
            stage = $stage.as_str(),
            operation = %$correlation.operation,
            attempt = $correlation.attempt,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn ids_are_unique_across_calls() {
        let ids: BTreeSet<String> = (0..1000).map(|_| CorrelationId::new().as_hex()).collect();
        assert_eq!(ids.len(), 1000, "correlation ids collided");
    }

    #[test]
    fn identical_inputs_do_not_produce_identical_ids() {
        // The property that keeps correlation from becoming an equality oracle:
        // an id must not be derivable from what it correlates.
        let first = CorrelationId::new();
        let second = CorrelationId::new();
        assert_ne!(first, second);
    }

    #[test]
    fn rendered_id_is_fixed_width_hex() {
        let rendered = CorrelationId::new().as_hex();
        assert_eq!(rendered.len(), 16, "unexpected id width: {rendered}");
        assert!(
            rendered.chars().all(|c| c.is_ascii_hexdigit()),
            "id is not hex: {rendered}"
        );
    }

    #[test]
    fn retries_keep_the_operation_id_and_advance_the_attempt() {
        let first = Correlation::new_operation();
        let second = first.next_attempt();
        assert_eq!(
            first.operation, second.operation,
            "retry lost its correlation to the original operation"
        );
        assert_eq!(first.attempt, 1);
        assert_eq!(second.attempt, 2);
    }

    #[test]
    fn attempt_counter_saturates_rather_than_wrapping() {
        // Wrapping would make attempt 0 follow u32::MAX and silently reorder a
        // trace; saturating keeps the last value truthful.
        let mut correlation = Correlation::new_operation();
        correlation.attempt = u32::MAX;
        assert_eq!(correlation.next_attempt().attempt, u32::MAX);
    }

    #[test]
    fn stage_vocabulary_is_closed_and_snake_case() {
        assert_eq!(Stage::ALL.len(), 5);
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
}
