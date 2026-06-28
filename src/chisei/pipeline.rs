use crate::chisei::budget::PressureLevel;
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, KIND_LEARNING, REL_CONTAINS, REL_TOUCHES};
use crate::sekai::capacity;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct PipelineRequest {
    pub request_id: String,
    pub namespace: String,
    pub spec: String,
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

const VERDICT_KEYS: [&str; 3] = ["verdict", "prior_verdict", "last_verdict"];
const CONVICTION_KEYS: [&str; 4] = [
    "conviction",
    "conviction_score",
    "confidence",
    "confidence_score",
];

fn extract_object_context_refs(namespace: &str, spec: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();

    for token in namespace.split_whitespace().chain(spec.split_whitespace()) {
        if let Some((kind, value)) = parse_object_reference(token) {
            refs.push((kind, value));
        }
    }
    if let Some((kind, value)) = parse_object_reference(namespace) {
        refs.push((kind, value));
    }
    refs
}

fn parse_object_reference(text: &str) -> Option<(String, String)> {
    let token = text
        .trim()
        .trim_matches(|c| matches!(c, '"' | '\'' | '`' | ',' | '.' | ';' | ':' | ')'));
    let (raw_kind, raw_value) = token.split_once(':')?;
    if raw_value.is_empty() || raw_kind.is_empty() {
        return None;
    }

    let kind = normalize_identifier(raw_kind)?;
    let mut value =
        raw_value.trim_matches(|c| matches!(c, '"' | '\'' | '`' | ',' | '.' | ';' | ':' | ')'));
    if value.starts_with('{') && value.ends_with('}') && value.len() > 2 {
        value = &value[1..value.len() - 1];
    }
    if value.is_empty() {
        return None;
    }
    let value = normalize_identifier(value)?;
    Some((kind, value))
}

fn normalize_identifier(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches(|c| c == '_' || c == '-');
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn property_value_for_keys<'a>(
    obj: &'a crate::domain::Object,
    keys: &'a [&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| obj.properties.get(*key).map(String::as_str))
}

fn resolve_context_objects(req: &PipelineRequest, db: &SekaiDb) -> Vec<crate::domain::Object> {
    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    for (kind, value) in extract_object_context_refs(&req.namespace, &req.spec) {
        let external_id = format!("{}:{}", kind, value);
        if !seen.insert(external_id.clone()) {
            continue;
        }
        let obj = db.find_by_external_id(&external_id).ok().flatten();
        if let Some(obj) = obj {
            objects.push(obj);
        }
    }
    objects
}

fn collect_verdicts(obj: &crate::domain::Object, db: &SekaiDb) -> Vec<String> {
    let linked = db
        .get_linked_objects(&obj.id, REL_TOUCHES, &Direction::Incoming)
        .unwrap_or_default()
        .into_iter()
        .collect::<Vec<_>>();

    let mut verdicts = Vec::new();
    for candidate in linked {
        if let Some(v) = property_value_for_keys(&candidate, &VERDICT_KEYS) {
            verdicts.push(format!("{} ({})", v, candidate.name));
        }
        if verdicts.len() >= 3 {
            break;
        }
    }
    for candidate in &db
        .get_linked_objects(&obj.id, REL_TOUCHES, &Direction::Outgoing)
        .unwrap_or_default()
    {
        if let Some(v) = property_value_for_keys(candidate, &VERDICT_KEYS) {
            verdicts.push(format!("{} ({})", v, candidate.name));
        }
        if verdicts.len() >= 3 {
            break;
        }
    }
    verdicts
}

pub struct ObjectContextEnrichStep;
impl Step for ObjectContextEnrichStep {
    fn name(&self) -> &str {
        "object_context_enrich"
    }

    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision {
        let mut lines = Vec::new();
        let context_objects = resolve_context_objects(req, db);
        if context_objects.is_empty() {
            return StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "no matching object context found".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: String::new(),
            };
        }
        for obj in context_objects {
            let mut has_content = false;
            let mut details = Vec::new();
            if let Some(verdict) = property_value_for_keys(&obj, &VERDICT_KEYS) {
                details.push(format!("prior_verdict: {}", verdict));
                has_content = true;
            }
            if let Some(conviction) = property_value_for_keys(&obj, &CONVICTION_KEYS) {
                details.push(format!("conviction: {}", conviction));
                has_content = true;
            }
            if let Some(score) = obj.properties.get("score").filter(|s| !s.is_empty())
                && !details.iter().any(|d| d.contains("conviction"))
            {
                details.push(format!("score: {}", score));
                has_content = true;
            }
            if let Some(rate) = property_value_for_keys(&obj, &["success_rate"]) {
                details.push(format!("success_rate: {}", rate));
                has_content = true;
            }

            let learnings = db
                .get_linked_objects(&obj.id, REL_TOUCHES, &Direction::Incoming)
                .unwrap_or_default();
            let mut pitfalls = Vec::new();
            let mut related_verdicts = Vec::new();
            for candidate in learnings {
                if candidate.kind == KIND_LEARNING {
                    let Some(title) = candidate.properties.get("title") else {
                        continue;
                    };
                    let Some(prevention) = candidate.properties.get("prevention") else {
                        continue;
                    };
                    pitfalls.push(format!("{title} - {prevention}"));
                } else if let Some(v) = property_value_for_keys(&candidate, &VERDICT_KEYS) {
                    related_verdicts.push(format!("{} - {}", candidate.name, v));
                }
                if pitfalls.len() >= 3 && related_verdicts.len() >= 3 {
                    break;
                }
            }
            if !pitfalls.is_empty() {
                details.push(format!("recent_learning: {}", pitfalls.join(", ")));
                has_content = true;
            }
            for verdict in collect_verdicts(&obj, db).into_iter().take(3) {
                details.push(format!("related_verdict: {}", verdict));
                has_content = true;
            }

            if has_content {
                lines.push(format!(
                    "object {} ({}) [{}] {}",
                    obj.kind,
                    obj.name,
                    obj.external_id,
                    details.join(", ")
                ));
            }
        }

        if lines.is_empty() {
            return StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "no matching object context found".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: String::new(),
            };
        }
        req.spec
            .push_str(&format!("\n\n[Object context]\n{}", lines.join("\n")));
        StepDecision {
            step: String::new(),
            action: "enrich".into(),
            reasoning: format!("injected {} object context block(s)", lines.len()),
            confidence: 1.0,
            suggestion: format!(
                "enriched spec with generic object context from {}",
                lines.len()
            ),
            value: lines.len().to_string(),
        }
    }
}

#[cfg(test)]
mod object_context_tests {
    use super::*;

    #[test]
    fn test_parse_object_reference() {
        assert_eq!(
            parse_object_reference("ticker:AAPL"),
            Some(("ticker".into(), "AAPL".into()))
        );
        assert_eq!(
            parse_object_reference("ticker:{AAPL}"),
            Some(("ticker".into(), "AAPL".into()))
        );
        assert_eq!(parse_object_reference("ignore http://example"), None);
        assert_eq!(parse_object_reference("namespace"), None);
    }

    #[test]
    fn test_extract_object_context_refs() {
        let refs = extract_object_context_refs("ticker:AAPL", "analyze ticker:{MSFT}");
        assert!(refs.contains(&("ticker".to_string(), "AAPL".to_string())));
        assert!(refs.contains(&("ticker".to_string(), "MSFT".to_string())));
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
        let mut pitfalls = Vec::new();
        let mut found_context = false;
        for context in resolve_context_objects(req, db) {
            found_context = true;
            let mut sources = vec![context.id.clone()];
            if let Some(ns_obj) = db
                .find_by_external_id(&format!("namespace:{}", context.kind))
                .ok()
                .flatten()
            {
                sources.push(ns_obj.id);
            }
            for source_id in sources {
                let learnings = db
                    .get_linked_objects(&source_id, REL_TOUCHES, &Direction::Incoming)
                    .unwrap_or_default();
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
                if pitfalls.len() >= 3 {
                    break;
                }
            }
        }
        if !found_context {
            return StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "no object context found".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: String::new(),
            };
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
        let mut hints = Vec::new();
        let mut found_context = false;
        for context in resolve_context_objects(req, db) {
            found_context = true;
            let components = db
                .get_linked_objects(&context.id, REL_CONTAINS, &Direction::Outgoing)
                .unwrap_or_default();
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
        }
        if !found_context {
            return StepDecision {
                step: String::new(),
                action: "none".into(),
                reasoning: "no object context found".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: String::new(),
            };
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
        for context in resolve_context_objects(req, db) {
            let components = db
                .get_linked_objects(&context.id, REL_CONTAINS, &Direction::Outgoing)
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
        let namespace = req.namespace.trim().to_string();
        let recommended = if namespace.is_empty() {
            String::new()
        } else {
            crate::chisei::affinity::get_affinity(db, &namespace).best_model
        };
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
        Box::new(ObjectContextEnrichStep),
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
    use crate::domain::{Link, Object};
    use std::collections::HashMap;

    fn make_req() -> PipelineRequest {
        PipelineRequest {
            request_id: "t1".into(),
            namespace: "ns".into(),
            spec: "fix the broken test".into(),
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
        assert_eq!(result.steps.len(), 8);
        assert_eq!(result.steps[0].step, "object_context_enrich");
        assert_eq!(result.steps[7].step, "sampling");
    }

    #[test]
    fn test_enrich_with_learnings() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "r1".into(),
            kind: "component".into(),
            name: "service".into(),
            namespace: "".into(),
            external_id: "component:service".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "ns-component".into(),
            kind: "namespace".into(),
            name: "component".into(),
            namespace: "".into(),
            external_id: "namespace:component".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        crate::sekai::learning::produce_learning(&db, "component", "always test", "add tests");
        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "component:service".into();
        let result = p.run(&mut req, &db);
        assert_eq!(result.steps[1].step, "learnings_enrich");
        assert_eq!(result.steps[1].action, "enrich");
        assert!(result.prepared_spec.contains("Known pitfalls"));
    }

    #[test]
    fn test_object_context_enrichment_from_ticker_reference() {
        let db = SekaiDb::new(":memory:").unwrap();
        let created = chrono::Utc::now().timestamp_millis();
        db.create_object(&Object {
            id: "ticker-aapl".into(),
            kind: "ticker".into(),
            name: "AAPL".into(),
            namespace: "".into(),
            external_id: "ticker:AAPL".into(),
            properties: HashMap::from([
                ("verdict".into(), "bullish".into()),
                ("conviction".into(), "0.87".into()),
            ]),
            created,
            updated: created,
        })
        .unwrap();
        db.create_object(&Object {
            id: "learning-aapl".into(),
            kind: KIND_LEARNING.into(),
            name: "AAPL learning".into(),
            namespace: "".into(),
            external_id: "learning:conviction-signal".into(),
            properties: HashMap::from([
                ("title".into(), "avoid overstated upside".into()),
                ("prevention".into(), "require earnings confirmation".into()),
            ]),
            created,
            updated: created,
        })
        .unwrap();
        db.create_link(&Link {
            id: "touches-learning".into(),
            from_id: "learning-aapl".into(),
            to_id: "ticker-aapl".into(),
            relation: REL_TOUCHES.into(),
            created,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = PipelineRequest {
            request_id: "ticker".into(),
            namespace: "ticker:AAPL".into(),
            spec: "portfolio analysis: use ticker:{AAPL} fundamentals".into(),
            model: String::new(),
            runtime: String::new(),
            task_type: String::new(),
            priority: 0,
            risk_score: 0.0,
            budget_pressure: PressureLevel::None,
            review_model: String::new(),
        };
        let result = p.run(&mut req, &db);
        assert_eq!(result.steps[0].action, "enrich");
        assert!(result.prepared_spec.contains("Object context"));
        assert!(result.prepared_spec.contains("prior_verdict: bullish"));
        assert!(result.prepared_spec.contains("conviction: 0.87"));
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
