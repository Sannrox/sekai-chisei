//! Provider-neutral prompt-cache eligibility and fallback policy.
//!
//! This module deliberately accepts only bounded metadata. Prompt text, cache
//! keys, and content-derived identifiers must never enter a decision or report.

pub const POLICY_VERSION: &str = "chisei.prompt-cache-policy/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheDecisionKind {
    Enabled,
    Bypassed,
    Unavailable,
    Invalid,
}

impl CacheDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Bypassed => "bypassed",
            Self::Unavailable => "unavailable",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheDecisionReason {
    Eligible,
    NotRequested,
    UnsupportedProvider,
    UnsupportedModel,
    ProviderDisabled,
    PrefixTooSmall,
    NoStablePrefix,
    DataClassIneligible,
    InvalidControls,
    AccountingUnavailable,
    BudgetRequiresCache,
    BelowBreakEven,
}

impl CacheDecisionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::NotRequested => "not_requested",
            Self::UnsupportedProvider => "unsupported_provider",
            Self::UnsupportedModel => "unsupported_model",
            Self::ProviderDisabled => "provider_disabled",
            Self::PrefixTooSmall => "prefix_too_small",
            Self::NoStablePrefix => "no_stable_prefix",
            Self::DataClassIneligible => "data_class_ineligible",
            Self::InvalidControls => "invalid_controls",
            Self::AccountingUnavailable => "accounting_unavailable",
            Self::BudgetRequiresCache => "budget_requires_cache",
            Self::BelowBreakEven => "below_break_even",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CachePolicyInput {
    pub requested: bool,
    pub provider_supported: bool,
    pub model_supported: bool,
    pub provider_enabled: bool,
    pub stable_prefix_tokens: u64,
    pub minimum_cacheable_tokens: Option<u64>,
    pub data_class_allowed: bool,
    pub controls_valid: bool,
    pub accounting_available: bool,
    pub uncached_fallback_allowed: bool,
    /// Expected executions sharing this exact stable prefix before expiry.
    pub expected_requests: u64,
    /// Price ratios in millionths of the ordinary input-token price.
    pub write_price_ratio_millionths: Option<u64>,
    pub read_price_ratio_millionths: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicyDecision {
    pub kind: CacheDecisionKind,
    pub reason: CacheDecisionReason,
    pub break_even_requests: Option<u64>,
}

impl CachePolicyDecision {
    fn new(kind: CacheDecisionKind, reason: CacheDecisionReason) -> Self {
        Self {
            kind,
            reason,
            break_even_requests: None,
        }
    }

    pub fn enabled(self) -> bool {
        self.kind == CacheDecisionKind::Enabled
    }
}

pub fn evaluate(input: CachePolicyInput) -> CachePolicyDecision {
    if !input.requested {
        return CachePolicyDecision::new(
            CacheDecisionKind::Bypassed,
            CacheDecisionReason::NotRequested,
        );
    }
    if !input.controls_valid {
        return CachePolicyDecision::new(
            CacheDecisionKind::Invalid,
            CacheDecisionReason::InvalidControls,
        );
    }
    if !input.data_class_allowed {
        return CachePolicyDecision::new(
            CacheDecisionKind::Bypassed,
            CacheDecisionReason::DataClassIneligible,
        );
    }
    if !input.provider_supported {
        return fallback(input, CacheDecisionReason::UnsupportedProvider);
    }
    if !input.model_supported {
        return fallback(input, CacheDecisionReason::UnsupportedModel);
    }
    if !input.provider_enabled {
        return fallback(input, CacheDecisionReason::ProviderDisabled);
    }
    if input.stable_prefix_tokens == 0 {
        return CachePolicyDecision::new(
            CacheDecisionKind::Bypassed,
            CacheDecisionReason::NoStablePrefix,
        );
    }
    if input
        .minimum_cacheable_tokens
        .is_some_and(|minimum| input.stable_prefix_tokens < minimum)
    {
        return CachePolicyDecision::new(
            CacheDecisionKind::Bypassed,
            CacheDecisionReason::PrefixTooSmall,
        );
    }
    if !input.accounting_available {
        return fallback(input, CacheDecisionReason::AccountingUnavailable);
    }

    if input
        .read_price_ratio_millionths
        .is_some_and(|read| read >= 1_000_000)
    {
        return CachePolicyDecision::new(
            CacheDecisionKind::Bypassed,
            CacheDecisionReason::BelowBreakEven,
        );
    }

    let break_even_requests = break_even_requests(
        input.write_price_ratio_millionths,
        input.read_price_ratio_millionths,
    );
    if break_even_requests.is_some_and(|count| input.expected_requests < count) {
        return CachePolicyDecision {
            kind: CacheDecisionKind::Bypassed,
            reason: CacheDecisionReason::BelowBreakEven,
            break_even_requests,
        };
    }
    CachePolicyDecision {
        kind: CacheDecisionKind::Enabled,
        reason: CacheDecisionReason::Eligible,
        break_even_requests,
    }
}

fn fallback(
    input: CachePolicyInput,
    unavailable_reason: CacheDecisionReason,
) -> CachePolicyDecision {
    if input.uncached_fallback_allowed {
        CachePolicyDecision::new(CacheDecisionKind::Unavailable, unavailable_reason)
    } else {
        CachePolicyDecision::new(
            CacheDecisionKind::Invalid,
            CacheDecisionReason::BudgetRequiresCache,
        )
    }
}

pub fn break_even_requests(write_ratio: Option<u64>, read_ratio: Option<u64>) -> Option<u64> {
    let (write, read) = (write_ratio?, read_ratio?);
    if read >= 1_000_000 {
        return None;
    }
    let savings = 1_000_000 - read;
    let premium = write.saturating_sub(1_000_000);
    Some(1 + premium.div_ceil(savings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eligible() -> CachePolicyInput {
        CachePolicyInput {
            requested: true,
            provider_supported: true,
            model_supported: true,
            provider_enabled: true,
            stable_prefix_tokens: 2_048,
            minimum_cacheable_tokens: Some(1_024),
            data_class_allowed: true,
            controls_valid: true,
            accounting_available: true,
            uncached_fallback_allowed: true,
            expected_requests: 2,
            write_price_ratio_millionths: Some(1_250_000),
            read_price_ratio_millionths: Some(100_000),
        }
    }

    #[test]
    fn enables_only_at_break_even() {
        let decision = evaluate(eligible());
        assert!(decision.enabled());
        assert_eq!(decision.break_even_requests, Some(2));

        let decision = evaluate(CachePolicyInput {
            expected_requests: 1,
            ..eligible()
        });
        assert_eq!(decision.reason, CacheDecisionReason::BelowBreakEven);
    }

    #[test]
    fn known_non_discounted_reads_never_break_even() {
        let decision = evaluate(CachePolicyInput {
            read_price_ratio_millionths: Some(1_000_000),
            expected_requests: u64::MAX,
            ..eligible()
        });
        assert_eq!(decision.kind, CacheDecisionKind::Bypassed);
        assert_eq!(decision.reason, CacheDecisionReason::BelowBreakEven);
    }

    #[test]
    fn privacy_rejection_precedes_provider_fallback() {
        let decision = evaluate(CachePolicyInput {
            data_class_allowed: false,
            provider_supported: false,
            ..eligible()
        });
        assert_eq!(decision.kind, CacheDecisionKind::Bypassed);
        assert_eq!(decision.reason, CacheDecisionReason::DataClassIneligible);
    }

    #[test]
    fn unavailable_cache_fails_when_budget_forbids_uncached_fallback() {
        let decision = evaluate(CachePolicyInput {
            provider_enabled: false,
            uncached_fallback_allowed: false,
            ..eligible()
        });
        assert_eq!(decision.kind, CacheDecisionKind::Invalid);
        assert_eq!(decision.reason, CacheDecisionReason::BudgetRequiresCache);
    }

    #[test]
    fn invalid_controls_fail_explicitly() {
        let decision = evaluate(CachePolicyInput {
            controls_valid: false,
            ..eligible()
        });
        assert_eq!(decision.kind, CacheDecisionKind::Invalid);
        assert_eq!(decision.reason, CacheDecisionReason::InvalidControls);
    }

    #[test]
    fn decision_metadata_is_bounded() {
        let decision = evaluate(eligible());
        let summary = format!(
            "{}:{}:{}",
            POLICY_VERSION,
            decision.kind.as_str(),
            decision.reason.as_str()
        );
        assert_eq!(summary, "chisei.prompt-cache-policy/v1:enabled:eligible");
        assert!(!summary.contains("cache_key"));
        assert!(!summary.contains("secret"));
    }

    #[test]
    fn sanitized_benchmark_covers_cold_warm_and_fallback_paths() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../benchmarks/prompt-cache-policy-v1.json"))
                .unwrap();
        assert_eq!(fixture["version"], "prompt-cache-policy-benchmark/v1");
        assert!(
            fixture["results"]
                .as_array()
                .is_some_and(|rows| rows.len() >= 4)
        );
    }
}
