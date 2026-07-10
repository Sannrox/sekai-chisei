use crate::chisei::budget::PressureLevel;
use crate::chisei::egress;
use crate::db::sekai::SekaiDb;
use crate::domain::{Direction, KIND_COMPONENT, KIND_LEARNING, Object, REL_CONTAINS, REL_TOUCHES};
use crate::sekai::capacity;
use crate::sekai::schema::ObjectType;
use std::collections::{HashMap, HashSet};

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
    pub egress_records: Vec<egress::ContextEgressRecord>,
    pub external_egress: bool,
    pub template_only: bool,
    pub expanded_context_items: usize,
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
    pub egress_records: Vec<egress::ContextEgressRecord>,
    pub expanded_context_items: usize,
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
const INTERFACE_EVALUABLE: &str = "Evaluable";
const INTERFACE_RISK_SCORED: &str = "RiskScored";

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

fn object_implements(db: &SekaiDb, obj: &Object, interface_name: &str) -> bool {
    db.get_object_type(&obj.kind)
        .ok()
        .flatten()
        .is_some_and(|object_type| {
            object_type
                .implements
                .iter()
                .any(|implemented| implemented == interface_name)
        })
}

fn is_evaluable_context(db: &SekaiDb, obj: &Object) -> bool {
    obj.kind == KIND_COMPONENT
        || object_implements(db, obj, INTERFACE_EVALUABLE)
        || object_implements(db, obj, INTERFACE_RISK_SCORED)
}

fn is_degraded_evaluable(db: &SekaiDb, obj: &Object, max_success_rate: i32) -> bool {
    is_evaluable_context(db, obj)
        && obj
            .properties
            .get("success_rate")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(100)
            < max_success_rate
        && obj
            .properties
            .get("task_total")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(0)
            >= 3
}

fn risk_score_value(obj: &Object) -> Option<f64> {
    obj.properties
        .get("risk_score")
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
}

fn filter_context_property(
    db: &SekaiDb,
    type_cache: &mut HashMap<String, Option<ObjectType>>,
    obj: &Object,
    field: &str,
    record: &mut egress::ContextEgressRecord,
    external: bool,
) -> Option<String> {
    let object_type = type_cache
        .entry(obj.kind.clone())
        .or_insert_with(|| db.get_object_type(&obj.kind).ok().flatten());
    egress::filter_property_with_schema(obj, field, object_type.as_ref(), record, external)
}

fn collect_related_verdict_context(
    obj: &Object,
    db: &SekaiDb,
    external_egress: bool,
) -> (Vec<String>, Vec<egress::ContextEgressRecord>) {
    let mut lines = Vec::new();
    let mut records = Vec::new();
    let mut type_cache = HashMap::new();
    let mut candidates = db
        .get_linked_objects(&obj.id, REL_TOUCHES, &Direction::Incoming)
        .unwrap_or_default();
    candidates.extend(
        db.get_linked_objects(&obj.id, REL_TOUCHES, &Direction::Outgoing)
            .unwrap_or_default(),
    );

    for candidate in candidates {
        if candidate.kind == KIND_LEARNING {
            continue;
        }
        let Some(verdict_key) = VERDICT_KEYS.iter().find(|key| {
            candidate
                .properties
                .get(**key)
                .is_some_and(|value| !value.is_empty())
        }) else {
            continue;
        };
        let mut record = egress::new_record(&candidate);
        let Some(verdict) = filter_context_property(
            db,
            &mut type_cache,
            &candidate,
            verdict_key,
            &mut record,
            external_egress,
        ) else {
            records.push(record);
            continue;
        };
        if !external_egress || egress::include_identity(&candidate) {
            record.included_fields.push("identity".into());
            lines.push(format!("related_verdict: {} - {}", candidate.name, verdict));
        } else {
            record.redacted_fields.push("identity".into());
            record
                .reasons
                .push("identity denied by default egress policy".into());
            lines.push(format!("related_verdict: {}", verdict));
        }
        records.push(record);
        if lines.len() >= 3 {
            break;
        }
    }
    (lines, records)
}

pub struct ObjectContextEnrichStep;
impl Step for ObjectContextEnrichStep {
    fn name(&self) -> &str {
        "object_context_enrich"
    }

    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision {
        run_object_context_enrich(req, db, false)
    }

    fn run_with_context_expansion(
        &self,
        req: &mut PipelineRequest,
        db: &SekaiDb,
        context_expansion_allowed: bool,
    ) -> StepDecision {
        run_object_context_enrich(req, db, context_expansion_allowed)
    }
}

fn run_object_context_enrich(
    req: &mut PipelineRequest,
    db: &SekaiDb,
    context_expansion_allowed: bool,
) -> StepDecision {
    if req.template_only {
        return StepDecision {
            step: String::new(),
            action: "skipped".into(),
            reasoning: "template_only sanitization contract".into(),
            confidence: 1.0,
            suggestion: String::new(),
            value: String::new(),
        };
    }
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
    let mut type_cache = HashMap::new();
    for obj in context_objects {
        let mut egress_record = egress::new_record(&obj);
        let mut has_content = false;
        let mut details = Vec::new();
        if let Some(verdict_key) = VERDICT_KEYS.iter().find(|key| {
            obj.properties
                .get(**key)
                .is_some_and(|value| !value.is_empty())
        }) && let Some(verdict) = filter_context_property(
            db,
            &mut type_cache,
            &obj,
            verdict_key,
            &mut egress_record,
            req.external_egress,
        ) {
            details.push(format!("prior_verdict: {}", verdict));
            has_content = true;
        }
        if let Some(conviction_key) = CONVICTION_KEYS.iter().find(|key| {
            obj.properties
                .get(**key)
                .is_some_and(|value| !value.is_empty())
        }) && let Some(conviction) = filter_context_property(
            db,
            &mut type_cache,
            &obj,
            conviction_key,
            &mut egress_record,
            req.external_egress,
        ) {
            details.push(format!("conviction: {}", conviction));
            has_content = true;
        }
        if obj.properties.get("score").is_some_and(|s| !s.is_empty())
            && !details.iter().any(|d| d.contains("conviction"))
            && let Some(score) = filter_context_property(
                db,
                &mut type_cache,
                &obj,
                "score",
                &mut egress_record,
                req.external_egress,
            )
        {
            details.push(format!("score: {}", score));
            has_content = true;
        }
        if obj
            .properties
            .get("success_rate")
            .is_some_and(|value| !value.is_empty())
            && let Some(rate) = filter_context_property(
                db,
                &mut type_cache,
                &obj,
                "success_rate",
                &mut egress_record,
                req.external_egress,
            )
        {
            details.push(format!("success_rate: {}", rate));
            has_content = true;
        }
        if object_implements(db, &obj, INTERFACE_RISK_SCORED)
            && obj
                .properties
                .get("risk_score")
                .is_some_and(|value| !value.is_empty())
            && let Some(score) = filter_context_property(
                db,
                &mut type_cache,
                &obj,
                "risk_score",
                &mut egress_record,
                req.external_egress,
            )
        {
            details.push(format!("risk_score: {}", score));
            has_content = true;
        }
        if object_implements(db, &obj, INTERFACE_RISK_SCORED)
            && obj
                .properties
                .get("risk_reason")
                .is_some_and(|value| !value.is_empty())
            && let Some(reason) = filter_context_property(
                db,
                &mut type_cache,
                &obj,
                "risk_reason",
                &mut egress_record,
                req.external_egress,
            )
        {
            details.push(format!("risk_reason: {}", reason));
            has_content = true;
        }

        if context_expansion_allowed {
            let learnings = db
                .get_linked_objects(&obj.id, REL_TOUCHES, &Direction::Incoming)
                .unwrap_or_default();
            let mut pitfalls = Vec::new();
            for candidate in learnings {
                if candidate.kind == KIND_LEARNING {
                    let mut learning_record = egress::new_record(&candidate);
                    let title = filter_context_property(
                        db,
                        &mut type_cache,
                        &candidate,
                        "title",
                        &mut learning_record,
                        req.external_egress,
                    );
                    let prevention = filter_context_property(
                        db,
                        &mut type_cache,
                        &candidate,
                        "prevention",
                        &mut learning_record,
                        req.external_egress,
                    );
                    if let (Some(title), Some(prevention)) = (title, prevention) {
                        pitfalls.push(format!("{title} - {prevention}"));
                    }
                    req.egress_records.push(learning_record);
                }
                if pitfalls.len() >= 3 {
                    break;
                }
            }
            if !pitfalls.is_empty() {
                req.expanded_context_items =
                    req.expanded_context_items.saturating_add(pitfalls.len());
                details.push(format!("recent_learning: {}", pitfalls.join(", ")));
                has_content = true;
            }
            let (related_verdicts, mut related_records) =
                collect_related_verdict_context(&obj, db, req.external_egress);
            if !related_verdicts.is_empty() {
                req.expanded_context_items = req
                    .expanded_context_items
                    .saturating_add(related_verdicts.len());
                details.extend(related_verdicts);
                has_content = true;
            }
            req.egress_records.append(&mut related_records);
        }
        if has_content {
            if !req.external_egress || egress::include_identity(&obj) {
                egress_record.included_fields.push("identity".into());
                lines.push(format!(
                    "object {} ({}) [{}] {}",
                    obj.kind,
                    obj.name,
                    obj.external_id,
                    details.join(", ")
                ));
            } else {
                egress_record.redacted_fields.push("identity".into());
                egress_record
                    .reasons
                    .push("identity denied by default egress policy".into());
                lines.push(format!("object context {}", details.join(", ")));
            }
        }
        if !egress_record.included_fields.is_empty() || !egress_record.redacted_fields.is_empty() {
            req.egress_records.push(egress_record);
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

    fn run_with_context_expansion(
        &self,
        req: &mut PipelineRequest,
        db: &SekaiDb,
        _context_expansion_allowed: bool,
    ) -> StepDecision {
        self.run(req, db)
    }
}

pub struct Pipeline {
    steps: Vec<Box<dyn Step>>,
}

impl Pipeline {
    pub fn new(steps: Vec<Box<dyn Step>>) -> Self {
        Self { steps }
    }

    pub fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> RunResult {
        self.run_with_context_expansion(req, db, false)
    }

    /// Run the pipeline with the server-owned result of the context-expansion eval gate.
    /// Existing callers use [`Pipeline::run`], which denies expansion by default.
    pub fn run_with_context_expansion(
        &self,
        req: &mut PipelineRequest,
        db: &SekaiDb,
        context_expansion_allowed: bool,
    ) -> RunResult {
        req.expanded_context_items = 0;
        let decisions: Vec<StepDecision> = self
            .steps
            .iter()
            .map(|s| {
                let mut d = s.run_with_context_expansion(req, db, context_expansion_allowed);
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
            egress_records: req.egress_records.clone(),
            expanded_context_items: req.expanded_context_items,
        }
    }
}

pub struct LearningsEnrichStep;
impl Step for LearningsEnrichStep {
    fn name(&self) -> &str {
        "learnings_enrich"
    }

    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision {
        run_learnings_enrich(req, db, false)
    }

    fn run_with_context_expansion(
        &self,
        req: &mut PipelineRequest,
        db: &SekaiDb,
        context_expansion_allowed: bool,
    ) -> StepDecision {
        run_learnings_enrich(req, db, context_expansion_allowed)
    }
}

fn run_learnings_enrich(
    req: &mut PipelineRequest,
    db: &SekaiDb,
    context_expansion_allowed: bool,
) -> StepDecision {
    if req.template_only {
        return StepDecision {
            step: String::new(),
            action: "skipped".into(),
            reasoning: "template_only sanitization contract".into(),
            confidence: 1.0,
            suggestion: String::new(),
            value: String::new(),
        };
    }
    if !context_expansion_allowed {
        return StepDecision {
            step: String::new(),
            action: "skipped".into(),
            reasoning: "context expansion has not passed the eval gate".into(),
            confidence: 1.0,
            suggestion: String::new(),
            value: String::new(),
        };
    }
    let mut pitfalls = Vec::new();
    let mut found_context = false;
    let mut type_cache = HashMap::new();
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
                let mut learning_record = egress::new_record(&obj);
                let title = filter_context_property(
                    db,
                    &mut type_cache,
                    &obj,
                    "title",
                    &mut learning_record,
                    req.external_egress,
                );
                let prevention = filter_context_property(
                    db,
                    &mut type_cache,
                    &obj,
                    "prevention",
                    &mut learning_record,
                    req.external_egress,
                );
                if let (Some(title), Some(prevention)) = (title, prevention) {
                    pitfalls.push(format!("{title} - {prevention}"));
                    req.expanded_context_items = req.expanded_context_items.saturating_add(1);
                }
                req.egress_records.push(learning_record);
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

pub struct SpecEnrichStep;
impl Step for SpecEnrichStep {
    fn name(&self) -> &str {
        "spec_enrich"
    }

    fn run(&self, req: &mut PipelineRequest, db: &SekaiDb) -> StepDecision {
        if req.template_only {
            return StepDecision {
                step: String::new(),
                action: "skipped".into(),
                reasoning: "template_only sanitization contract".into(),
                confidence: 1.0,
                suggestion: String::new(),
                value: String::new(),
            };
        }
        let mut hints = Vec::new();
        let mut found_context = false;
        let mut type_cache = HashMap::new();
        for context in resolve_context_objects(req, db) {
            found_context = true;
            let components = db
                .get_linked_objects(&context.id, REL_CONTAINS, &Direction::Outgoing)
                .unwrap_or_default();
            for comp in components {
                if !is_evaluable_context(db, &comp) {
                    continue;
                }
                let mut comp_record = egress::new_record(&comp);
                let Some(safe_total) = filter_context_property(
                    db,
                    &mut type_cache,
                    &comp,
                    "task_total",
                    &mut comp_record,
                    req.external_egress,
                ) else {
                    if !comp_record.redacted_fields.is_empty() {
                        req.egress_records.push(comp_record);
                    }
                    continue;
                };
                let Some(safe_rate) = filter_context_property(
                    db,
                    &mut type_cache,
                    &comp,
                    "success_rate",
                    &mut comp_record,
                    req.external_egress,
                ) else {
                    if !comp_record.redacted_fields.is_empty() {
                        req.egress_records.push(comp_record);
                    }
                    continue;
                };
                let total = safe_total.parse::<i32>().unwrap_or(0);
                let rate = safe_rate.parse::<i32>().unwrap_or(100);
                if total >= 3 && rate < 50 {
                    if !req.external_egress || egress::include_identity(&comp) {
                        comp_record.included_fields.push("identity".into());
                        hints.push(format!(
                            "{} {} is degraded ({}% success)",
                            comp.kind, comp.name, safe_rate
                        ));
                    } else {
                        comp_record.redacted_fields.push("identity".into());
                        comp_record
                            .reasons
                            .push("identity denied by default egress policy".into());
                        hints.push(format!(
                            "evaluable object is degraded ({}% success)",
                            safe_rate
                        ));
                    }
                    req.egress_records.push(comp_record);
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
        let mut type_cache = HashMap::new();
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
                .filter(|c| is_degraded_evaluable(db, c, 30))
                .count();
            if degraded > 0 {
                signals.push(format!("{degraded} degraded evaluable object(s) detected"));
                risk = risk.max(0.7);
            }
            let mut exposed_high_risk = 0usize;
            let mut redacted_high_risk = 0usize;
            for candidate in std::iter::once(&context)
                .chain(components.iter())
                .filter(|c| object_implements(db, c, INTERFACE_RISK_SCORED))
            {
                let mut record = egress::new_record(candidate);
                let exposed_score = filter_context_property(
                    db,
                    &mut type_cache,
                    candidate,
                    "risk_score",
                    &mut record,
                    req.external_egress,
                );
                let score_was_redacted = record
                    .redacted_fields
                    .iter()
                    .any(|field| field == "risk_score");
                if !record.included_fields.is_empty() || !record.redacted_fields.is_empty() {
                    req.egress_records.push(record);
                }
                if risk_score_value(candidate).is_some_and(|score| score >= 0.7) {
                    if exposed_score.is_none() && score_was_redacted {
                        redacted_high_risk += 1;
                    } else {
                        exposed_high_risk += 1;
                    }
                }
            }
            if exposed_high_risk > 0 || redacted_high_risk > 0 {
                if exposed_high_risk > 0 && redacted_high_risk > 0 {
                    signals.push(format!(
                        "{exposed_high_risk} high-risk object(s) detected; internal risk signal detected"
                    ));
                } else if exposed_high_risk > 0 {
                    signals.push(format!("{exposed_high_risk} high-risk object(s) detected"));
                } else {
                    signals.push("internal risk signal detected".into());
                }
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
    use crate::sekai::schema::{ObjectType, PropertyDef, PropertyType};
    use std::collections::HashMap;

    fn prop(name: &str, prop_type: PropertyType) -> PropertyDef {
        PropertyDef {
            name: name.into(),
            prop_type,
            required: false,
            description: String::new(),
            enum_values: vec![],
            link_kind: String::new(),
            compute_expr: String::new(),
            classification: crate::sekai::schema::default_property_classification(),
            struct_fields: vec![],
        }
    }

    fn prop_with_classification(
        name: &str,
        prop_type: PropertyType,
        classification: &str,
    ) -> PropertyDef {
        let mut property = prop(name, prop_type);
        property.classification = classification.into();
        property
    }

    fn register_object_type(
        db: &SekaiDb,
        kind: &str,
        implements: Vec<&str>,
        properties: Vec<PropertyDef>,
    ) {
        db.upsert_object_type(&ObjectType {
            kind: kind.into(),
            description: format!("{kind} type"),
            properties,
            is_builtin: false,
            implements: implements.into_iter().map(str::to_string).collect(),
        })
        .unwrap();
    }

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
            egress_records: vec![],
            external_egress: true,
            template_only: false,
            expanded_context_items: 0,
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
    fn test_context_expansion_allows_linked_learnings() {
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
        db.create_object(&Object {
            id: "learning-service".into(),
            kind: KIND_LEARNING.into(),
            name: "service learning".into(),
            namespace: "".into(),
            external_id: "learning:service".into(),
            properties: HashMap::from([
                ("title".into(), "always test".into()),
                ("prevention".into(), "add tests".into()),
                (
                    egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "title,prevention".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "touches-service-learning".into(),
            from_id: "learning-service".into(),
            to_id: "r1".into(),
            relation: REL_TOUCHES.into(),
            created: 0,
        })
        .unwrap();
        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "component:service".into();
        let result = p.run_with_context_expansion(&mut req, &db, true);
        assert_eq!(result.steps[1].step, "learnings_enrich");
        assert_eq!(result.steps[1].action, "enrich");
        assert!(result.prepared_spec.contains("Known pitfalls"));
        assert!(result.expanded_context_items > 0);
    }

    #[test]
    fn test_direct_context_survives_default_denied_expansion() {
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
                (
                    egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "verdict,conviction".into(),
                ),
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
                (
                    egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "title,prevention".into(),
                ),
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
        db.create_object(&Object {
            id: "analysis-aapl".into(),
            kind: "analysis".into(),
            name: "AAPL analysis".into(),
            namespace: "".into(),
            external_id: "analysis:AAPL".into(),
            properties: HashMap::from([
                ("verdict".into(), "related-only verdict".into()),
                (egress::EXTERNAL_PROPERTIES_KEY.into(), "verdict".into()),
            ]),
            created,
            updated: created,
        })
        .unwrap();
        db.create_link(&Link {
            id: "touches-analysis".into(),
            from_id: "analysis-aapl".into(),
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
            egress_records: vec![],
            external_egress: true,
            template_only: false,
            expanded_context_items: 0,
        };
        let result = p.run(&mut req, &db);
        assert_eq!(result.steps[0].action, "enrich");
        assert!(result.prepared_spec.contains("Object context"));
        assert!(result.prepared_spec.contains("prior_verdict: bullish"));
        assert!(result.prepared_spec.contains("conviction: 0.87"));
        assert!(!result.prepared_spec.contains("recent_learning"));
        assert!(!result.prepared_spec.contains("avoid overstated upside"));
        assert!(!result.prepared_spec.contains("related_verdict"));
        assert!(!result.prepared_spec.contains("related-only verdict"));
        assert_eq!(result.steps[1].action, "skipped");
        assert!(result.steps[1].reasoning.contains("eval gate"));
        assert_eq!(result.expanded_context_items, 0);
        assert!(!result.prepared_spec.contains("object ticker (AAPL)"));
        assert!(
            result
                .egress_records
                .iter()
                .any(|record| record.redacted_fields.contains(&"identity".to_string()))
        );
    }

    #[test]
    fn test_object_context_uses_risk_scored_interface() {
        let db = SekaiDb::new(":memory:").unwrap();
        register_object_type(
            &db,
            "service",
            vec![INTERFACE_RISK_SCORED],
            vec![
                prop("risk_score", PropertyType::Float),
                prop("risk_reason", PropertyType::String),
            ],
        );
        db.create_object(&Object {
            id: "service-checkout".into(),
            kind: "service".into(),
            name: "checkout".into(),
            namespace: "".into(),
            external_id: "service:checkout".into(),
            properties: HashMap::from([
                ("risk_score".into(), "0.83".into()),
                ("risk_reason".into(), "payment error spike".into()),
                (
                    egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "risk_score,risk_reason".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "service:checkout".into();
        let result = p.run(&mut req, &db);

        assert_eq!(result.steps[0].action, "enrich");
        assert!(result.prepared_spec.contains("risk_score: 0.83"));
        assert!(
            result
                .prepared_spec
                .contains("risk_reason: payment error spike")
        );
    }

    #[test]
    fn test_object_context_prefers_schema_classification_over_legacy_allowlist() {
        let db = SekaiDb::new(":memory:").unwrap();
        register_object_type(
            &db,
            "service",
            vec![INTERFACE_RISK_SCORED],
            vec![
                prop_with_classification("risk_score", PropertyType::Float, "sensitive"),
                prop("risk_reason", PropertyType::String),
            ],
        );
        db.create_object(&Object {
            id: "service-checkout".into(),
            kind: "service".into(),
            name: "checkout".into(),
            namespace: "".into(),
            external_id: "service:checkout".into(),
            properties: HashMap::from([
                ("risk_score".into(), "0.83".into()),
                ("risk_reason".into(), "payment error spike".into()),
                (
                    egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "risk_score,risk_reason".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "service:checkout".into();
        let result = p.run(&mut req, &db);

        assert!(!result.prepared_spec.contains("risk_score: 0.83"));
        assert!(
            result
                .prepared_spec
                .contains("risk_reason: payment error spike")
        );
        assert!(result.egress_records.iter().any(|record| {
            record.object_ref == "service:checkout"
                && record.redacted_fields.contains(&"risk_score".to_string())
        }));
    }

    #[test]
    fn test_object_context_denies_unlabelled_properties() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "asset-secret".into(),
            kind: "asset".into(),
            name: "SecretCo".into(),
            namespace: "".into(),
            external_id: "asset:SECRET".into(),
            properties: HashMap::from([
                ("verdict".into(), "do not disclose".into()),
                ("score".into(), "99".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "asset:SECRET".into();
        let result = p.run(&mut req, &db);
        assert_eq!(result.steps[0].action, "none");
        assert!(!result.prepared_spec.contains("do not disclose"));
        assert!(
            result
                .egress_records
                .iter()
                .any(|record| record.redacted_fields.contains(&"verdict".to_string()))
        );
    }

    #[test]
    fn test_local_object_context_allows_unlabelled_properties() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "asset-local".into(),
            kind: "asset".into(),
            name: "LocalCo".into(),
            namespace: "".into(),
            external_id: "asset:LOCAL".into(),
            properties: HashMap::from([
                ("verdict".into(), "local insight".into()),
                ("score".into(), "99".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "asset:LOCAL".into();
        req.external_egress = false;
        let result = p.run(&mut req, &db);
        assert_eq!(result.steps[0].action, "enrich");
        assert!(result.prepared_spec.contains("local insight"));
        assert!(result.prepared_spec.contains("LocalCo"));
        assert!(
            result
                .egress_records
                .iter()
                .any(|record| record.included_fields.contains(&"identity".to_string()))
        );
    }

    #[test]
    fn test_object_context_includes_identity_only_when_allowed() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "asset-secret".into(),
            kind: "asset".into(),
            name: "SecretCo".into(),
            namespace: "".into(),
            external_id: "asset:SECRET".into(),
            properties: HashMap::from([
                ("verdict".into(), "approved".into()),
                (egress::EXTERNAL_PROPERTIES_KEY.into(), "verdict".into()),
                (egress::INCLUDE_IDENTITY_KEY.into(), "true".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "asset:SECRET".into();
        let result = p.run(&mut req, &db);
        assert!(result.prepared_spec.contains("object asset (SecretCo)"));
        assert!(result.prepared_spec.contains("[asset:SECRET]"));
    }

    #[test]
    fn test_learning_context_requires_explicit_allowed_fields() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "component-service".into(),
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
            id: "learning-secret".into(),
            kind: KIND_LEARNING.into(),
            name: "secret learning".into(),
            namespace: "".into(),
            external_id: "learning:secret".into(),
            properties: HashMap::from([
                ("title".into(), "sensitive title".into()),
                ("prevention".into(), "sensitive prevention".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "touches-secret".into(),
            from_id: "learning-secret".into(),
            to_id: "component-service".into(),
            relation: REL_TOUCHES.into(),
            created: 0,
        })
        .unwrap();
        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "component:service".into();
        let result = p.run(&mut req, &db);
        assert!(!result.prepared_spec.contains("Known pitfalls"));
        assert!(!result.prepared_spec.contains("sensitive title"));
    }

    #[test]
    fn test_degraded_component_hint_requires_allowed_task_total() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "namespace-alpha".into(),
            kind: "namespace".into(),
            name: "alpha".into(),
            namespace: "".into(),
            external_id: "namespace:alpha".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "component-secret".into(),
            kind: KIND_COMPONENT.into(),
            name: "secret service".into(),
            namespace: "".into(),
            external_id: "component:secret-service".into(),
            properties: HashMap::from([
                ("task_total".into(), "5".into()),
                ("success_rate".into(), "20".into()),
                (
                    egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "success_rate".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "contains-secret".into(),
            from_id: "namespace-alpha".into(),
            to_id: "component-secret".into(),
            relation: REL_CONTAINS.into(),
            created: 0,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "namespace:alpha".into();
        let result = p.run(&mut req, &db);

        assert!(!result.prepared_spec.contains("component is degraded"));
        assert!(!result.prepared_spec.contains("20% success"));
        assert!(result.egress_records.iter().any(|record| {
            record.object_ref == "component:secret-service"
                && record.redacted_fields.contains(&"task_total".to_string())
        }));
    }

    #[test]
    fn test_interface_backed_object_participates_in_degraded_routing() {
        let db = SekaiDb::new(":memory:").unwrap();
        register_object_type(
            &db,
            "service",
            vec![INTERFACE_EVALUABLE],
            vec![
                prop("task_total", PropertyType::Int),
                prop("success_rate", PropertyType::Int),
            ],
        );
        db.create_object(&Object {
            id: "namespace-alpha".into(),
            kind: "namespace".into(),
            name: "alpha".into(),
            namespace: "".into(),
            external_id: "namespace:alpha".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "service-checkout".into(),
            kind: "service".into(),
            name: "checkout".into(),
            namespace: "".into(),
            external_id: "service:checkout".into(),
            properties: HashMap::from([
                ("task_total".into(), "5".into()),
                ("success_rate".into(), "20".into()),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "contains-checkout".into(),
            from_id: "namespace-alpha".into(),
            to_id: "service-checkout".into(),
            relation: REL_CONTAINS.into(),
            created: 0,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "namespace:alpha".into();
        req.external_egress = false;
        let result = p.run(&mut req, &db);

        assert!(
            result
                .prepared_spec
                .contains("service checkout is degraded")
        );
        assert_eq!(result.risk_score, 0.7);
        assert!(result.warnings()[0].contains("degraded evaluable object"));
    }

    #[test]
    fn test_redacted_interface_degradation_hint_uses_generic_label() {
        let db = SekaiDb::new(":memory:").unwrap();
        register_object_type(
            &db,
            "service",
            vec![INTERFACE_EVALUABLE],
            vec![
                prop("task_total", PropertyType::Int),
                prop("success_rate", PropertyType::Int),
            ],
        );
        db.create_object(&Object {
            id: "namespace-alpha".into(),
            kind: "namespace".into(),
            name: "alpha".into(),
            namespace: "".into(),
            external_id: "namespace:alpha".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "service-secret".into(),
            kind: "service".into(),
            name: "secret".into(),
            namespace: "".into(),
            external_id: "service:secret".into(),
            properties: HashMap::from([
                ("task_total".into(), "5".into()),
                ("success_rate".into(), "20".into()),
                (
                    egress::EXTERNAL_PROPERTIES_KEY.into(),
                    "task_total,success_rate".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "contains-secret-service".into(),
            from_id: "namespace-alpha".into(),
            to_id: "service-secret".into(),
            relation: REL_CONTAINS.into(),
            created: 0,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "namespace:alpha".into();
        let result = p.run(&mut req, &db);

        assert!(
            result
                .prepared_spec
                .contains("evaluable object is degraded (20% success)")
        );
        assert!(!result.prepared_spec.contains("component is degraded"));
        assert!(result.egress_records.iter().any(|record| {
            record.object_ref == "service:secret"
                && record.redacted_fields.contains(&"identity".to_string())
        }));
    }

    #[test]
    fn test_risk_scored_routing_respects_egress_policy() {
        let db = SekaiDb::new(":memory:").unwrap();
        register_object_type(
            &db,
            "service",
            vec![INTERFACE_RISK_SCORED],
            vec![prop_with_classification(
                "risk_score",
                PropertyType::Float,
                "sensitive",
            )],
        );
        db.create_object(&Object {
            id: "namespace-alpha".into(),
            kind: "namespace".into(),
            name: "alpha".into(),
            namespace: "".into(),
            external_id: "namespace:alpha".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "service-checkout".into(),
            kind: "service".into(),
            name: "checkout".into(),
            namespace: "".into(),
            external_id: "service:checkout".into(),
            properties: HashMap::from([("risk_score".into(), "0.91".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "service-billing".into(),
            kind: "service".into(),
            name: "billing".into(),
            namespace: "".into(),
            external_id: "service:billing".into(),
            properties: HashMap::from([
                ("risk_score".into(), "0.95".into()),
                (
                    "chisei.egress.external_properties".into(),
                    "risk_score".into(),
                ),
            ]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "contains-risk".into(),
            from_id: "namespace-alpha".into(),
            to_id: "service-checkout".into(),
            relation: REL_CONTAINS.into(),
            created: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "contains-visible-risk".into(),
            from_id: "namespace-alpha".into(),
            to_id: "service-billing".into(),
            relation: REL_CONTAINS.into(),
            created: 0,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "namespace:alpha".into();
        let result = p.run(&mut req, &db);

        assert_eq!(result.risk_score, 0.7);
        assert!(result.warnings()[0].contains("internal risk signal"));
        assert!(!result.warnings()[0].contains("high-risk object"));
        assert!(result.egress_records.iter().any(|record| {
            record.object_ref == "service:checkout"
                && record.redacted_fields.contains(&"risk_score".to_string())
        }));
    }

    #[test]
    fn test_direct_risk_scored_context_raises_pipeline_risk() {
        let db = SekaiDb::new(":memory:").unwrap();
        register_object_type(
            &db,
            "service",
            vec![INTERFACE_RISK_SCORED],
            vec![prop_with_classification(
                "risk_score",
                PropertyType::Float,
                "sensitive",
            )],
        );
        db.create_object(&Object {
            id: "service-checkout".into(),
            kind: "service".into(),
            name: "checkout".into(),
            namespace: "".into(),
            external_id: "service:checkout".into(),
            properties: HashMap::from([("risk_score".into(), "0.91".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "service:checkout".into();
        let result = p.run(&mut req, &db);

        assert_eq!(result.risk_score, 0.7);
        assert!(result.warnings()[0].contains("internal risk signal"));
        assert!(result.egress_records.iter().any(|record| {
            record.object_ref == "service:checkout"
                && record.redacted_fields.contains(&"risk_score".to_string())
        }));
    }

    #[test]
    fn test_context_expansion_allows_related_verdict_context() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "asset-local".into(),
            kind: "asset".into(),
            name: "LocalCo".into(),
            namespace: "".into(),
            external_id: "asset:LOCAL".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_object(&Object {
            id: "analysis-local".into(),
            kind: "analysis".into(),
            name: "Local analysis".into(),
            namespace: "".into(),
            external_id: "analysis:LOCAL".into(),
            properties: HashMap::from([("verdict".into(), "watch margin risk".into())]),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.create_link(&Link {
            id: "touches-analysis".into(),
            from_id: "analysis-local".into(),
            to_id: "asset-local".into(),
            relation: REL_TOUCHES.into(),
            created: 0,
        })
        .unwrap();

        let p = default_pipeline();
        let mut req = make_req();
        req.namespace = "asset:LOCAL".into();
        req.external_egress = false;
        let result = p.run_with_context_expansion(&mut req, &db, true);
        assert_eq!(result.steps[0].action, "enrich");
        assert!(result.prepared_spec.contains("related_verdict"));
        assert!(result.prepared_spec.contains("watch margin risk"));
        assert!(result.expanded_context_items > 0);
        assert!(result.prepared_spec.contains("Local analysis"));
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
