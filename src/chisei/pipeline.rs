use crate::chisei::budget::PressureLevel;
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, KIND_LEARNING, REL_CONTAINS, REL_TOUCHES};
use crate::sekai::capacity;

#[derive(Debug, Clone)]
pub struct PipelineRequest {
    pub request_id: String,
    pub namespace: String,
    pub spec: String,
    pub repo: String,
    pub branch: String,
    pub model: String,
    pub runtime: String,
    pub task_type: String,
    pub priority: i32,
    pub risk_score: f64,
    pub budget_pressure: PressureLevel,
    pub review_model: String,
}

#[derive(Debug, Clone)]
pub struct StepDecision {
    pub step: String,
    pub action: String,
    pub reasoning: String,
    pub confidence: f64,
    pub suggestion: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct ReviewPolicy {
    pub confidence_threshold: f64,
    pub max_cycles: i32,
    pub model: String,
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub request_id: String,
    pub steps: Vec<StepDecision>,
    pub timestamp: i64,
    pub prepared_spec: String,
    pub risk_score: f64,
    pub review_policy: Option<ReviewPolicy>,
}

impl RunResult {
    pub fn recommended_model(&self) -> Option<(&str, f64)> {
        self.steps
            .iter()
            .find(|s| s.step == "model_select" && s.action == "recommend" && !s.value.is_empty())
            .map(|s| (s.value.as_str(), s.confidence))
    }

    pub fn warnings(&self) -> Vec<String> {
        self.steps
            .iter()
            .filter(|s| s.action == "warn" && !s.suggestion.is_empty())
            .map(|s| s.suggestion.clone())
            .collect()
    }
}

pub trait Step: Send + Sync {
    fn name(&self) -> &str;
    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision;
}

pub struct Pipeline {
    steps: Vec<Box<dyn Step>>,
}

impl Pipeline {
    pub fn new(steps: Vec<Box<dyn Step>>) -> Self {
        Self { steps }
    }

    pub fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> RunResult {
        let decisions: Vec<StepDecision> = self
            .steps
            .iter()
            .map(|s| {
                let mut d = s.run(req, db);
                d.step = s.name().into();
                d
            })
            .collect();
        let review_policy = decode_review_policy(&decisions);
        RunResult {
            request_id: req.request_id.clone(),
            steps: decisions,
            timestamp: chrono::Utc::now().timestamp(),
            prepared_spec: req.spec.clone(),
            risk_score: req.risk_score,
            review_policy,
        }
    }
}

pub struct LearningsEnrichStep;
impl Step for LearningsEnrichStep {
    fn name(&self) -> &str {
        "learnings_enrich"
    }

    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision {
        let repo_obj = match db
            .find_by_external_id(&format!("repo:{}", req.repo))
            .ok()
            .flatten()
        {
            Some(o) => o,
            None => {
                return StepDecision {
                    step: String::new(),
                    action: "none".into(),
                    reasoning: "repo not found in sekai".into(),
                    confidence: 1.0,
                    suggestion: String::new(),
                    value: String::new(),
                };
            }
        };
        let learnings = db
            .get_linked_objects(&repo_obj.id, REL_TOUCHES, &Direction::Incoming)
            .unwrap_or_default();
        let mut pitfalls = Vec::new();
        for obj in learnings {
            if obj.kind != KIND_LEARNING {
                continue;
            }
            let Some(title) = obj.properties.get("title") else {
                continue;
            };
            let Some(prevention) = obj.properties.get("prevention") else {
                continue;
            };
            pitfalls.push(format!("{title} - {prevention}"));
            if pitfalls.len() >= 3 {
                break;
            }
        }
        if pitfalls.is_empty() {
            return StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "no relevant learnings found".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: String::new(),
            };
        }
        req.spec.push_str(&format!(
            "\n\n[Known pitfalls]\n- {}",
            pitfalls.join("\n- ")
        ));
        StepDecision {
            step: String::new(),
            action: "enrich".into(),
            reasoning: format!("injected {} learning(s) from Sekai", pitfalls.len()),
            confidence: 1.0,
            suggestion: format!("spec enriched with {} prior pitfall(s)", pitfalls.len()),
            value: pitfalls.len().to_string(),
        }
    }
}

pub struct SpecEnrichStep;
impl Step for SpecEnrichStep {
    fn name(&self) -> &str {
        "spec_enrich"
    }

    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision {
        let repo_obj = match db
            .find_by_external_id(&format!("repo:{}", req.repo))
            .ok()
            .flatten()
        {
            Some(o) => o,
            None => {
                return StepDecision {
                    step: String::new(),
                    action: "none".into(),
                    reasoning: "repo not found in sekai".into(),
                    confidence: 1.0,
                    suggestion: String::new(),
                    value: String::new(),
                };
            }
        };
        let components = db
            .get_linked_objects(&repo_obj.id, REL_CONTAINS, &Direction::Outgoing)
            .unwrap_or_default();
        let mut hints = Vec::new();
        for comp in components {
            if comp.kind != KIND_COMPONENT {
                continue;
            }
            let total = comp
                .properties
                .get("task_total")
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0);
            let rate = comp
                .properties
                .get("success_rate")
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(100);
            if total >= 3 && rate < 50 {
                hints.push(format!(
                    "component {} is degraded ({}% success)",
                    comp.name, rate
                ));
            }
        }
        if hints.is_empty() {
            return StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "no component constraints to inject".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: String::new(),
            };
        }
        req.spec
            .push_str(&format!("\n\n[Sekai context] {}.", hints.join("; ")));
        StepDecision {
            step: String::new(),
            action: "enrich".into(),
            reasoning: format!("injected {} component constraint(s)", hints.len()),
            confidence: 1.0,
            suggestion: format!("spec enriched with {} sekai constraint(s)", hints.len()),
            value: hints.len().to_string(),
        }
    }
}

pub struct RiskStep;
impl Step for RiskStep {
    fn name(&self) -> &str {
        "risk_gate"
    }

    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision {
        let mut signals = Vec::new();
        let mut risk = 0.0f64;
        let snapshots = capacity::latest_snapshots(db, 24).unwrap_or_default();
        if snapshots.len() >= 3 {
            let latest = &snapshots[0];
            if latest.agent_count > 0 && latest.queue_depth > latest.agent_count * 2 {
                signals.push(format!(
                    "capacity queue depth {} exceeds 2x agent count",
                    latest.queue_depth
                ));
                risk = risk.max(0.5);
            }
            if latest.avg_wait_seconds >= 1800 {
                signals.push("capacity wait time exceeds 30 minutes".into());
                risk = risk.max(0.6);
            }
        }
        if let Some(repo_obj) = db
            .find_by_external_id(&format!("repo:{}", req.repo))
            .ok()
            .flatten()
        {
            let components = db
                .get_linked_objects(&repo_obj.id, REL_CONTAINS, &Direction::Outgoing)
                .unwrap_or_default();
            let degraded = components
                .iter()
                .filter(|c| {
                    c.kind == KIND_COMPONENT
                        && c.properties
                            .get("success_rate")
                            .and_then(|v| v.parse::<i32>().ok())
                            .unwrap_or(100)
                            < 30
                        && c.properties
                            .get("task_total")
                            .and_then(|v| v.parse::<i32>().ok())
                            .unwrap_or(0)
                            >= 3
                })
                .count();
            if degraded > 0 {
                signals.push(format!("{degraded} degraded component(s) detected"));
                risk = risk.max(0.7);
            }
        }
        req.risk_score = risk;
        if signals.is_empty() {
            return StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "no risk signals".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: "0.00".into(),
            };
        }
        StepDecision {
            step: String::new(),
            action: "warn".into(),
            reasoning: format!("{} risk signal(s) detected", signals.len()),
            confidence: 0.7,
            suggestion: format!("risk warning: {}", signals[0]),
            value: format!("{risk:.2}"),
        }
    }
}

/// Classifies a request's complexity from its task type and spec.
/// Returns `Some("cheap")` for trivial work, `Some("capable")` for complex
/// work, or `None` when the task is standard. Shared by `ComplexityRouteStep`
/// (model bias) and `SamplingStep` (capable-model oversampling trigger).
pub(crate) fn complexity_class(req: &PipelineRequest) -> Option<&'static str> {
    if req.task_type == "lint"
        || req.task_type == "typo"
        || req.spec.split_whitespace().count() < 20
    {
        return Some("cheap");
    }
    let lower = req.spec.to_lowercase();
    if [
        "architecture",
        "migration",
        "breaking change",
        "cross-cutting",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
    {
        return Some("capable");
    }
    None
}

pub struct ComplexityRouteStep;
impl Step for ComplexityRouteStep {
    fn name(&self) -> &str {
        "complexity_route"
    }

    fn run(&self, req: &mut PipelineRequest, _db: &SekaiDb) -> StepDecision {
        let action = match complexity_class(req) {
            Some("cheap") => Some((
                "cheap",
                "task classified as trivial; prefer cheapest allowed model",
            )),
            Some("capable") => Some((
                "capable",
                "task classified as complex; prefer most capable allowed model",
            )),
            _ => None,
        };
        match action {
            Some((value, reasoning)) => StepDecision {
                step: String::new(),
                action: "recommend".into(),
                reasoning: reasoning.into(),
                confidence: 0.8,
                suggestion: format!("complexity bias: {value}"),
                value: value.into(),
            },
            None => StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "task classified as standard; no model bias applied".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: String::new(),
            },
        }
    }
}

pub struct ModelSelectStep;
impl Step for ModelSelectStep {
    fn name(&self) -> &str {
        "model_select"
    }

    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision {
        if !req.model.is_empty() {
            return StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "user specified model".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: req.model.clone(),
            };
        }
        let recommended = crate::chisei::affinity::get_affinity(db, &req.repo).best_model;
        let model = if !recommended.is_empty() {
            recommended
        } else {
            "claude-sonnet-4-20250514".into()
        };
        req.model = model.clone();
        StepDecision {
            step: String::new(),
            action: "recommend".into(),
            reasoning: "pipeline selected the best available model".into(),
            confidence: 0.7,
            suggestion: format!("model recommendation: {model}"),
            value: model,
        }
    }
}

pub struct ReviewPolicyStep;
impl Step for ReviewPolicyStep {
    fn name(&self) -> &str {
        "review_policy"
    }

    fn run(&self, req: &mut PipelineRequest, _db: &SekaiDb) -> StepDecision {
        let mut max_cycles = if req.risk_score >= 0.5 { 4 } else { 2 };
        max_cycles += if req.spec.split_whitespace().count() > 80 {
            1
        } else {
            0
        };
        match req.budget_pressure {
            PressureLevel::Critical => max_cycles = 1,
            PressureLevel::Moderate => max_cycles = max_cycles.min(2),
            PressureLevel::None => {}
        }
        let threshold = 0.7 + (req.risk_score * 0.2);
        let model = if req.review_model.is_empty() {
            req.model.clone()
        } else {
            req.review_model.clone()
        };
        let value = serde_json::json!({
            "confidence_threshold": threshold,
            "max_cycles": max_cycles,
            "model": model,
        })
        .to_string();
        StepDecision {
            step: String::new(),
            action: "configure".into(),
            reasoning: "review policy computed from risk and budget pressure".into(),
            confidence: 1.0,
            suggestion: String::new(),
            value,
        }
    }
}

pub fn default_pipeline() -> Pipeline {
    default_pipeline_with(0.05, 0.7)
}

/// Builds the pipeline with sampler parameters threaded from config:
/// `base_rate` is the unconditional sampling probability and `risk_threshold`
/// is the `risk_score` at or above which a request is force-sampled.
pub fn default_pipeline_with(base_rate: f64, risk_threshold: f64) -> Pipeline {
    Pipeline::new(vec![
        Box::new(LearningsEnrichStep),
        Box::new(SpecEnrichStep),
        Box::new(RiskStep),
        Box::new(ComplexityRouteStep),
        Box::new(ModelSelectStep),
        Box::new(ReviewPolicyStep),
        Box::new(super::sampling::SamplingStep::new(
            base_rate,
            risk_threshold,
        )),
    ])
}

fn decode_review_policy(steps: &[StepDecision]) -> Option<ReviewPolicy> {
    let step = steps
        .iter()
        .find(|s| s.step == "review_policy" && !s.value.is_empty())?;
    let value: serde_json::Value = serde_json::from_str(&step.value).ok()?;
    Some(ReviewPolicy {
        confidence_threshold: value.get("confidence_threshold")?.as_f64()?,
        max_cycles: value.get("max_cycles")?.as_i64()? as i32,
        model: value
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use std::collections::HashMap;

    fn make_req() -> PipelineRequest {
        PipelineRequest {
            request_id: "t1".into(),
            namespace: "ns".into(),
            spec: "fix the broken test".into(),
            repo: "repo".into(),
            branch: String::new(),
            model: String::new(),
            runtime: String::new(),
            task_type: String::new(),
            priority: 0,
            risk_score: 0.0,
            budget_pressure: PressureLevel::None,
            review_model: String::new(),
        }
    }

    #[test]
    fn test_pipeline_runs_all_steps() {
        let db = SekaiDb::new(":memory:").unwrap();
        let p = default_pipeline();
        let mut req = make_req();
        let result = p.run(&mut req, &db);
        assert_eq!(result.steps.len(), 7);
        assert_eq!(result.steps[0].step, "learnings_enrich");
        assert_eq!(result.steps[5].step, "review_policy");
        assert_eq!(result.steps[6].step, "sampling");
    }

    #[test]
    fn test_enrich_with_learnings() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "r1".into(),
            kind: "repo".into(),
            name: "repo".into(),
            namespace: "".into(),
            external_id: "repo:repo".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        crate::sekai::learning::produce_learning(&db, "repo", "always test", "add tests");
        let p = default_pipeline();
        let mut req = make_req();
        let result = p.run(&mut req, &db);
        assert_eq!(result.steps[0].action, "enrich");
        assert!(result.prepared_spec.contains("Known pitfalls"));
    }

    #[test]
    fn test_review_policy_extracted() {
        let db = SekaiDb::new(":memory:").unwrap();
        let p = default_pipeline();
        let mut req = make_req();
        req.risk_score = 0.6;
        let result = p.run(&mut req, &db);
        let policy = result.review_policy.expect("review policy");
        assert!(policy.confidence_threshold >= 0.7);
        assert!(policy.max_cycles >= 2);
    }
}
