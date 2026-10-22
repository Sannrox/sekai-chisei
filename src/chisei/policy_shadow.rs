//! Live shadow evaluation of a candidate namespace policy (#1630).
//!
//! A shadowed candidate route policy is evaluated beside the active policy on
//! every live policy resolution for its namespace. Only the active decision
//! takes effect; the candidate outcome is counted and, when it differs,
//! sampled into a bounded report. Activating the shadowed candidate through
//! `SetNamespacePolicy` requires a passing report. Like the historical
//! dry-run (#282), the comparison covers the namespace route policy only.

use crate::chisei::policy::Policy;
use serde::{Deserialize, Serialize};

pub const POLICY_SHADOW_CONTRACT: &str = "chisei.policy-shadow/v1";
/// Maximum retained samples per differing delta class.
pub const MAX_SHADOW_SAMPLES: i64 = crate::chisei::policy_dry_run::MAX_DRY_RUN_SAMPLES as i64;
pub const MAX_MATCH_RATE_BPS: u32 = 10_000;
pub const REFUSAL_NOT_PASSING: &str = "policy_shadow_report_not_passing";
/// How long an admitted activation holds its run against replacement.
pub const ACTIVATION_CLAIM_MS: i64 = 60_000;
pub const ACTIVATION_IN_PROGRESS: &str =
    "policy shadow activation is in progress; retry after it completes";

/// How the candidate decision compares with the active one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowDelta {
    /// Same allow/deny and, when allowed, the same runtime and model.
    Unchanged,
    /// Both allow, with a different runtime or model.
    ReRouted,
    /// The active policy allows and the candidate would deny.
    WouldDeny,
    /// The active policy denies and the candidate would allow.
    WouldAllow,
}

impl ShadowDelta {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::ReRouted => "re_routed",
            Self::WouldDeny => "would_deny",
            Self::WouldAllow => "would_allow",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "unchanged" => Ok(Self::Unchanged),
            "re_routed" => Ok(Self::ReRouted),
            "would_deny" => Ok(Self::WouldDeny),
            "would_allow" => Ok(Self::WouldAllow),
            other => Err(format!("unknown policy shadow delta {other:?}")),
        }
    }
}

/// A route decision: the selected `(runtime, model)` or the denial reason.
pub type RouteOutcome = Result<(String, String), String>;

pub fn classify(active: &RouteOutcome, candidate: &RouteOutcome) -> ShadowDelta {
    match (active, candidate) {
        (Ok(active), Ok(candidate)) if active == candidate => ShadowDelta::Unchanged,
        (Ok(_), Ok(_)) => ShadowDelta::ReRouted,
        (Ok(_), Err(_)) => ShadowDelta::WouldDeny,
        (Err(_), Ok(_)) => ShadowDelta::WouldAllow,
        (Err(_), Err(_)) => ShadowDelta::Unchanged,
    }
}

/// A started shadow. `shadow_id` identifies one run: a restart gets a new id
/// even for the same candidate. `active_version` pins the namespace's own
/// policy at start; an empty value means the namespace had none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyShadow {
    pub shadow_id: String,
    pub namespace: String,
    pub candidate: Policy,
    pub candidate_version: String,
    pub active_version: String,
    pub min_evaluations: u32,
    pub min_match_rate_bps: u32,
    pub started_by: String,
    pub started_at_ms: i64,
}

impl PolicyShadow {
    pub fn validate(&self) -> Result<(), String> {
        if self.namespace.trim().is_empty() || self.namespace != self.namespace.trim() {
            return Err("namespace is required and must be trimmed".into());
        }
        if self.shadow_id.is_empty() {
            return Err("shadow_id is required".into());
        }
        if self.min_evaluations == 0 {
            return Err("min_evaluations must be at least 1".into());
        }
        if self.min_match_rate_bps > MAX_MATCH_RATE_BPS {
            return Err(format!(
                "min_match_rate_bps must be at most {MAX_MATCH_RATE_BPS}"
            ));
        }
        if self.candidate_version != self.candidate.version() {
            return Err("candidate_version does not match the candidate policy".into());
        }
        Ok(())
    }
}

/// One live decision the candidate decided differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowSample {
    pub delta: ShadowDelta,
    pub preferred_runtime: String,
    pub preferred_model: String,
    pub active: String,
    pub candidate: String,
    pub observed_at_ms: i64,
}

impl ShadowSample {
    pub fn new(
        delta: ShadowDelta,
        preferred_runtime: &str,
        preferred_model: &str,
        active: &RouteOutcome,
        candidate: &RouteOutcome,
        observed_at_ms: i64,
    ) -> Self {
        Self {
            delta,
            preferred_runtime: preferred_runtime.into(),
            preferred_model: preferred_model.into(),
            active: describe(active),
            candidate: describe(candidate),
            observed_at_ms,
        }
    }
}

fn describe(outcome: &RouteOutcome) -> String {
    match outcome {
        Ok((runtime, model)) => format!("allow {runtime}/{model}"),
        Err(reason) => format!("deny: {reason}"),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShadowCounts {
    pub evaluated: i64,
    pub unchanged: i64,
    pub re_routed: i64,
    pub would_deny: i64,
    pub would_allow: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyShadowReport {
    pub shadow: PolicyShadow,
    pub counts: ShadowCounts,
    pub samples: Vec<ShadowSample>,
}

impl PolicyShadowReport {
    /// Passing needs at least `min_evaluations` live decisions and an
    /// unchanged share of at least `min_match_rate_bps`. `Err` names why not.
    pub fn verdict(&self) -> Result<(), String> {
        let counts = &self.counts;
        let min_evaluations = i64::from(self.shadow.min_evaluations);
        if counts.evaluated < min_evaluations {
            return Err(format!(
                "{REFUSAL_NOT_PASSING}: {} of {min_evaluations} required live decisions evaluated",
                counts.evaluated
            ));
        }
        let required = i64::from(self.shadow.min_match_rate_bps) * counts.evaluated;
        if counts.unchanged * i64::from(MAX_MATCH_RATE_BPS) < required {
            return Err(format!(
                "{REFUSAL_NOT_PASSING}: match rate {} bps is below {} bps",
                self.match_rate_bps(),
                self.shadow.min_match_rate_bps
            ));
        }
        Ok(())
    }

    pub fn match_rate_bps(&self) -> u32 {
        if self.counts.evaluated == 0 {
            return 0;
        }
        (self.counts.unchanged * i64::from(MAX_MATCH_RATE_BPS) / self.counts.evaluated) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(runtime: &str, model: &str) -> RouteOutcome {
        Ok((runtime.into(), model.into()))
    }

    fn report(
        evaluated: i64,
        unchanged: i64,
        min_evaluations: u32,
        bps: u32,
    ) -> PolicyShadowReport {
        let candidate = Policy {
            allowed_runtimes: vec![],
            allowed_models: vec![],
            default_runtime: String::new(),
            default_model: String::new(),
            data_class: String::new(),
        };
        PolicyShadowReport {
            shadow: PolicyShadow {
                shadow_id: "run-1".into(),
                namespace: "ns".into(),
                candidate_version: candidate.version(),
                candidate,
                active_version: String::new(),
                min_evaluations,
                min_match_rate_bps: bps,
                started_by: "root".into(),
                started_at_ms: 1,
            },
            counts: ShadowCounts {
                evaluated,
                unchanged,
                re_routed: evaluated - unchanged,
                ..ShadowCounts::default()
            },
            samples: vec![],
        }
    }

    #[test]
    fn classify_compares_allow_deny_and_route() {
        let a = allow("openai", "gpt-5.5");
        let b = allow("anthropic", "claude-sonnet-4-20250514");
        let deny: RouteOutcome = Err("model not allowed".into());
        assert_eq!(classify(&a, &a), ShadowDelta::Unchanged);
        assert_eq!(classify(&a, &b), ShadowDelta::ReRouted);
        assert_eq!(classify(&a, &deny), ShadowDelta::WouldDeny);
        assert_eq!(classify(&deny, &a), ShadowDelta::WouldAllow);
        assert_eq!(classify(&deny, &deny), ShadowDelta::Unchanged);
    }

    #[test]
    fn verdict_requires_enough_decisions_and_match_rate() {
        assert!(report(2, 2, 3, 0).verdict().is_err());
        assert!(report(3, 0, 3, 0).verdict().is_ok());
        assert!(report(4, 3, 1, 7_500).verdict().is_ok());
        let refused = report(4, 2, 1, 7_500).verdict().unwrap_err();
        assert!(refused.starts_with(REFUSAL_NOT_PASSING), "{refused}");
        assert_eq!(report(4, 3, 1, 0).match_rate_bps(), 7_500);
    }
}
