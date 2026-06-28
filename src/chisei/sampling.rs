//! Control-plane-aware sampling.
//!
//! For each plan request, chisei decides whether the request is *sampled* —
//! selected for deeper evaluation/observation. Rather than a flat coin flip,
//! the decision keys on request metadata:
//!
//! 1. **Base random rate** — sampled with probability `base_rate` (unbiased floor).
//! 2. **Triggered oversampling** — always sample when risk is elevated: `risk_score`
//!    at/above `risk_threshold`, `Critical` budget pressure, or a capable/expensive
//!    model. This catches the rare-but-risky requests a flat rate would mostly miss.
//! 3. **Deterministic draw** — the random draw is seeded from `request_id`, so a given
//!    request is reproducibly sampled-or-not (replayable, testable).
//!
//! The eval-driven adaptive trigger (oversample when the namespace eval signal is
//! regressed) lives in the service layer, which holds the eval store; see
//! `plan_from_input` in `grpc/chisei_service.rs`.

use super::budget::PressureLevel;
use super::pipeline::{PipelineRequest, Step, StepDecision, complexity_class};
use crate::db::sekai::SekaiDb;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq)]
pub struct SamplingDecision {
    pub sampled: bool,
    pub effective_rate: f64,
    pub reason: String,
}

pub struct SamplingStep {
    base_rate: f64,
    risk_threshold: f64,
}

impl SamplingStep {
    pub fn new(base_rate: f64, risk_threshold: f64) -> Self {
        Self {
            base_rate: base_rate.clamp(0.0, 1.0),
            risk_threshold,
        }
    }

    /// Pure sampling decision over request metadata (no DB / eval signal).
    pub fn decide(&self, req: &PipelineRequest) -> SamplingDecision {
        // Triggers force-sample regardless of the random draw.
        if req.risk_score >= self.risk_threshold {
            return SamplingDecision {
                sampled: true,
                effective_rate: 1.0,
                reason: "high_risk".into(),
            };
        }
        if req.budget_pressure == PressureLevel::Critical {
            return SamplingDecision {
                sampled: true,
                effective_rate: 1.0,
                reason: "budget_critical".into(),
            };
        }
        if complexity_class(req) == Some("capable") {
            return SamplingDecision {
                sampled: true,
                effective_rate: 1.0,
                reason: "capable_model".into(),
            };
        }
        // Base random rate, seeded deterministically from request_id.
        let sampled = deterministic_draw(&req.request_id) < self.base_rate;
        SamplingDecision {
            sampled,
            effective_rate: self.base_rate,
            reason: if sampled { "base" } else { "not_sampled" }.into(),
        }
    }
}

impl Step for SamplingStep {
    fn name(&self) -> &str {
        "sampling"
    }

    fn run(&self, req: &mut PipelineRequest, _db: &SekaiDb) -> StepDecision {
        let decision = self.decide(req);
        let value = serde_json::json!({
            "sampled": decision.sampled,
            "effective_rate": decision.effective_rate,
            "reason": decision.reason,
        })
        .to_string();
        StepDecision {
            step: String::new(),
            action: if decision.sampled { "sample" } else { "skip" }.into(),
            reasoning: "sampling decision from request metadata".into(),
            confidence: 1.0,
            suggestion: String::new(),
            value,
        }
    }
}

/// Maps a request id to a stable pseudo-random value in `[0, 1)`.
fn deterministic_draw(request_id: &str) -> f64 {
    let mut hasher = DefaultHasher::new();
    request_id.hash(&mut hasher);
    // Top 53 bits give an evenly distributed f64 in [0, 1).
    (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64
}

/// Decodes the `SamplingStep` decision out of the collected pipeline steps.
pub fn decode_sampling(steps: &[StepDecision]) -> Option<SamplingDecision> {
    let step = steps
        .iter()
        .find(|s| s.step == "sampling" && !s.value.is_empty())?;
    let value: serde_json::Value = serde_json::from_str(&step.value).ok()?;
    Some(SamplingDecision {
        sampled: value.get("sampled")?.as_bool()?,
        effective_rate: value.get("effective_rate")?.as_f64()?,
        reason: value
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: &str) -> PipelineRequest {
        PipelineRequest {
            request_id: id.into(),
            namespace: "ns".into(),
            spec: "a standard task that is not trivially short but otherwise plain work here"
                .into(),
            model: "claude-sonnet-4-20250514".into(),
            runtime: "native".into(),
            task_type: "feature".into(),
            priority: 0,
            risk_score: 0.0,
            budget_pressure: PressureLevel::None,
            review_model: String::new(),
        }
    }

    #[test]
    fn draw_is_deterministic_for_a_fixed_request_id() {
        assert_eq!(deterministic_draw("req-1"), deterministic_draw("req-1"));
    }

    #[test]
    fn rate_one_always_samples_and_rate_zero_never() {
        let always = SamplingStep::new(1.0, 0.7);
        let never = SamplingStep::new(0.0, 0.7);
        for id in ["a", "b", "c", "d", "e"] {
            assert!(always.decide(&req(id)).sampled, "rate 1.0 must sample {id}");
            assert!(!never.decide(&req(id)).sampled, "rate 0.0 must skip {id}");
        }
    }

    #[test]
    fn high_risk_forces_sampling_even_at_zero_rate() {
        let step = SamplingStep::new(0.0, 0.7);
        let mut r = req("x");
        r.risk_score = 0.9;
        let d = step.decide(&r);
        assert!(d.sampled);
        assert_eq!(d.reason, "high_risk");
    }

    #[test]
    fn critical_budget_pressure_forces_sampling() {
        let step = SamplingStep::new(0.0, 0.7);
        let mut r = req("y");
        r.budget_pressure = PressureLevel::Critical;
        let d = step.decide(&r);
        assert!(d.sampled);
        assert_eq!(d.reason, "budget_critical");
    }

    #[test]
    fn capable_task_forces_sampling() {
        let step = SamplingStep::new(0.0, 0.7);
        let mut r = req("z");
        r.spec = "perform a large architecture migration across the entire platform, \
            touching every service and rewriting the data access layer and the public \
            api contracts as part of this substantial multi week effort"
            .into();
        let d = step.decide(&r);
        assert!(d.sampled);
        assert_eq!(d.reason, "capable_model");
    }

    #[test]
    fn decode_round_trips_the_step_value() {
        let step = SamplingStep::new(1.0, 0.7);
        let mut decision = step.run(&mut req("w"), &SekaiDb::new(":memory:").unwrap());
        decision.step = "sampling".into();
        let decoded = decode_sampling(std::slice::from_ref(&decision)).unwrap();
        assert!(decoded.sampled);
        assert_eq!(decoded.reason, "base");
    }
}
