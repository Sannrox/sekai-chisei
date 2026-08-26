//! Lookup-first governed answers for allow-listed structured capabilities (#281 / S2).
//!
//! When a PlanExecution/ExecutePlanStream request targets an allow-listed #151 semantic
//! capability with a fixed structured contract, Chisei attempts an authorized
//! ontology/graph lookup **after** namespace authz and **before** provider
//! routing. A complete hit returns a normal response with **zero provider
//! tokens**. Incomplete graph state or ACL misses fail closed to the model path
//! and record `lookup_refusal` on the operation receipt.
//!
//! Scope (maintainer decision S2):
//! - Narrow allow-listed structured capabilities only (no free-form NL).
//! - Fixture suite + dual-run/shadow structural equality where practical.
//! - No fleet-wide spend-% claim.

use crate::chisei::epistemic_descriptor::{
    EPISTEMIC_DESCRIPTOR_VERSION, EpistemicDescriptor as DomainEpistemicDescriptor,
};
use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::action_policy::{ACTION_POLICY_KIND, BLAST_RADIUS_KIND};
use crate::sekai::compute;
use crate::sekai::governed_facts::{FACT_KIND, PROFILE_KIND, WAIVER_KIND};
use crate::sekai::markings;
use crate::sekai::ontology::OntologyRegistry;
use crate::sekai::retrieval::{
    self, ReasoningMode, RetrievalDirection, RetrievalQuery, RetrievalRoot,
};
use crate::sekai::schema::{self, SchemaRegistry};
use crate::sekai::security::Role;
use crate::sekai::semantic;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Receipt / report path when structured lookup fully answers the request.
pub const ANSWER_PATH_LOOKUP_HIT: &str = "lookup_hit";
/// Receipt / report path when the model provider is used (including after refusal).
pub const ANSWER_PATH_MODEL: &str = "model_path";
/// Receipt attribute for fail-closed fallback reasons.
pub const LOOKUP_REFUSAL_ATTR: &str = "lookup_refusal";
/// Receipt attribute always set for allow-listed capability attempts.
pub const ANSWER_PATH_ATTR: &str = "answer_path";
/// Synthetic provider identity recorded on full lookup hits (never a billable adapter).
pub const LOOKUP_PROVIDER: &str = "lookup";
/// Stop reason on PlannedChatResponse for a full lookup hit.
pub const LOOKUP_HIT_STOP_REASON: &str = "lookup_hit";
/// Closed v1 contract for the operator-controlled lookup-vs-golden promotion gate.
pub const LOOKUP_FIRST_GATE_CONTRACT_VERSION: &str = "chisei.lookup-first-promotion-gate/v1";
/// Audit action recorded after every valid gate execution.
pub const LOOKUP_FIRST_GATE_AUDIT_ACTION: &str = "lookup_first.gate";
/// The gate is intentionally bounded independently from generic evaluation suites.
pub const LOOKUP_FIRST_GATE_MAX_CASES: usize = 256;
pub const LOOKUP_FIRST_GATE_MAX_SUITE_BYTES: usize = 1024 * 1024;
const LOOKUP_FIRST_GATE_MAX_DETAIL_BYTES: usize = 512;

/// S2 allow-list: fixed #151 semantic capability contracts only.
pub const LOOKUP_FIRST_ALLOWLIST: &[&str] = &[
    semantic::CAPABILITY_RESOLVE_REF,
    semantic::CAPABILITY_EXPAND_RELATIONS,
    semantic::CAPABILITY_RETRIEVE_CONTEXT,
    semantic::CAPABILITY_EXPLAIN_DERIVATION,
];

/// Process-local fixture / runtime counters (not a fleet spend claim).
static LOOKUP_HIT_TOTAL: AtomicU64 = AtomicU64::new(0);
static MODEL_PATH_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOOKUP_REFUSAL_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Whether `capability_id` is eligible for lookup-first short-circuit.
pub fn is_lookup_first_capability(capability_id: &str) -> bool {
    let name = capability_id.trim();
    LOOKUP_FIRST_ALLOWLIST.contains(&name)
}

/// Structured input for `sekai.semantic.resolve_ref` (fixed contract, no NL).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolveRefInput {
    #[serde(default)]
    pub object_id: String,
    #[serde(default)]
    pub external_id: String,
    #[serde(default)]
    pub ontology_class: String,
    #[serde(default)]
    pub ontology_relation: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
struct LookupContextRoot {
    object_id: String,
    external_id: String,
    link_id: String,
}

impl LookupContextRoot {
    fn into_retrieval_root(self) -> Result<RetrievalRoot, ()> {
        let configured = [
            !self.object_id.is_empty(),
            !self.external_id.is_empty(),
            !self.link_id.is_empty(),
        ]
        .into_iter()
        .filter(|configured| *configured)
        .count();
        if configured != 1 {
            return Err(());
        }
        if !self.object_id.is_empty() {
            Ok(RetrievalRoot::Object(self.object_id))
        } else if !self.external_id.is_empty() {
            Ok(RetrievalRoot::External(self.external_id))
        } else {
            Ok(RetrievalRoot::Link(self.link_id))
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
struct LookupRetrievalInput {
    /// Accepted for the native Expand/Explain request shape. ExecutePlanStream
    /// already supplies the authoritative namespace outside the spec.
    namespace: String,
    roots: Vec<LookupContextRoot>,
    root: Option<LookupContextRoot>,
    from: Option<LookupContextRoot>,
    to: Option<LookupContextRoot>,
    relations: Vec<String>,
    direction: String,
    reasoning_mode: String,
    max_depth: u32,
    max_objects: u32,
    max_links: u32,
    kind_filter: Vec<String>,
    max_source_rows: u32,
    max_derived_rows: u32,
    max_derivation_steps: u32,
    max_time_ms: u32,
    max_explanation_bytes: u64,
}

/// Outcome of a lookup-first attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupDecision {
    /// Fully satisfied structured answer; no provider call.
    Hit {
        capability: String,
        answer_json: String,
        provenance: BTreeMap<String, String>,
    },
    /// Incomplete graph, ACL miss, schema miss, or unsupported capability shape.
    /// Caller must take the model path and record `lookup_refusal`.
    Refusal { capability: String, reason: String },
    /// Request is not an allow-listed structured capability attempt.
    NotEligible,
}

/// Fixture case for the checked-in S1 suite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LookupFixtureCase {
    pub id: String,
    pub capability: String,
    pub namespace: String,
    pub actor: String,
    /// Structured capability input JSON (not free-form NL).
    pub input: Value,
    /// Expected answer path: `lookup_hit` or `model_path`.
    pub expected_path: String,
    /// When expected_path is model_path after an attempt, expected refusal token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_refusal: Option<String>,
    /// Golden structured answer for dual-run structural equality (lookup_hit cases).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_answer: Option<Value>,
    /// Optional dual-run shadow: second structured answer that must match lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_model_answer: Option<Value>,
}

/// Per-case fixture result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LookupFixtureCaseResult {
    pub id: String,
    pub answer_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_refusal: Option<String>,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Aggregate report for the fixture suite (hit vs model) — S1 metrics surface.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LookupFixtureSuiteReport {
    pub suite: String,
    pub lookup_hits: u64,
    pub model_path: u64,
    pub lookup_refusals: u64,
    pub passed: u64,
    pub failed: u64,
    pub cases: Vec<LookupFixtureCaseResult>,
}

/// One strict, versioned lookup-vs-golden gate case.
///
/// This is deliberately separate from [`LookupFixtureCase`]. The latter also
/// supports the older S1/S2 test helper's optional shadow field; the promotion
/// gate accepts only the v1 lookup-vs-golden shape selected by research #527.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LookupPromotionGateCase {
    pub id: String,
    pub capability: String,
    pub namespace: String,
    pub actor: String,
    /// Structured JSON input only. Free-form natural-language strings are rejected.
    pub input: Value,
    pub expected_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_refusal: Option<String>,
    /// Required for every lookup hit; equality is JSON value equality after parsing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_answer: Option<Value>,
}

/// Published v1 gate document. The exact canonical content is digest-bound in
/// the audit decision; raw cases and answers are never written to that audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LookupPromotionGateSuite {
    pub contract_version: String,
    pub suite_id: String,
    pub namespace: String,
    pub cases: Vec<LookupPromotionGateCase>,
}

/// Bounded, secret-free result of a lookup-vs-golden gate execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LookupPromotionGateReport {
    pub contract_version: String,
    pub suite_id: String,
    pub namespace: String,
    pub suite_digest: String,
    #[serde(default)]
    pub audit_decision_id: String,
    /// `allow` means every case passed; `deny` leaves policy unchanged.
    pub verdict: String,
    pub lookup_hits: u64,
    pub model_path: u64,
    pub lookup_refusals: u64,
    pub passed: u64,
    pub failed: u64,
    pub cases: Vec<LookupFixtureCaseResult>,
}

/// Snapshot of process-local runtime counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupFirstCounters {
    pub lookup_hits: u64,
    pub model_path: u64,
    pub lookup_refusals: u64,
}

pub fn counters_snapshot() -> LookupFirstCounters {
    LookupFirstCounters {
        lookup_hits: LOOKUP_HIT_TOTAL.load(Ordering::Relaxed),
        model_path: MODEL_PATH_TOTAL.load(Ordering::Relaxed),
        lookup_refusals: LOOKUP_REFUSAL_TOTAL.load(Ordering::Relaxed),
    }
}

pub fn record_lookup_hit() {
    LOOKUP_HIT_TOTAL.fetch_add(1, Ordering::Relaxed);
    crate::obs::signals::record_lookup_first(crate::obs::labels::LookupFirstPath::LookupHit);
}

pub fn record_model_path(refused: bool) {
    MODEL_PATH_TOTAL.fetch_add(1, Ordering::Relaxed);
    if refused {
        LOOKUP_REFUSAL_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    crate::obs::signals::record_lookup_first(crate::obs::labels::LookupFirstPath::ModelPath);
}

/// Parse and validate a published lookup-vs-golden suite.
pub fn parse_lookup_promotion_gate_suite(raw: &str) -> Result<LookupPromotionGateSuite, String> {
    if raw.len() > LOOKUP_FIRST_GATE_MAX_SUITE_BYTES {
        return Err(format!(
            "lookup promotion suite exceeds {LOOKUP_FIRST_GATE_MAX_SUITE_BYTES} bytes"
        ));
    }
    let suite = serde_json::from_str::<LookupPromotionGateSuite>(raw)
        .map_err(|error| format!("malformed lookup promotion suite: {error}"))?;
    validate_lookup_promotion_gate_suite(&suite)?;
    Ok(suite)
}

pub fn validate_lookup_promotion_gate_suite(
    suite: &LookupPromotionGateSuite,
) -> Result<(), String> {
    if suite.contract_version != LOOKUP_FIRST_GATE_CONTRACT_VERSION {
        return Err(format!(
            "lookup promotion suite contract must be {LOOKUP_FIRST_GATE_CONTRACT_VERSION}"
        ));
    }
    validate_gate_identifier("suite_id", &suite.suite_id, 128)?;
    validate_gate_namespace(&suite.namespace)?;
    if suite.cases.is_empty() || suite.cases.len() > LOOKUP_FIRST_GATE_MAX_CASES {
        return Err(format!(
            "lookup promotion suite requires 1..={LOOKUP_FIRST_GATE_MAX_CASES} cases"
        ));
    }

    let mut ids = std::collections::BTreeSet::new();
    for case in &suite.cases {
        validate_gate_identifier("case id", &case.id, 128)?;
        if !ids.insert(case.id.as_str()) {
            return Err(format!("duplicate lookup promotion case id {:?}", case.id));
        }
        if case.namespace != suite.namespace {
            return Err(format!(
                "case {:?} namespace must match suite namespace",
                case.id
            ));
        }
        if case.actor.trim().is_empty() || case.actor != case.actor.trim() {
            return Err(format!(
                "case {:?} actor must be non-empty and trimmed",
                case.id
            ));
        }
        if !case.input.is_object() {
            return Err(format!(
                "case {:?} input must be a structured JSON object",
                case.id
            ));
        }
        if !is_lookup_first_capability(&case.capability) {
            return Err(format!(
                "case {:?} capability is not an allow-listed structured capability",
                case.id
            ));
        }
        if let Some(expected_answer) = &case.expected_answer
            && !expected_answer.is_object()
        {
            return Err(format!(
                "case {:?} expected_answer must be a structured JSON object",
                case.id
            ));
        }
        if let Some(expected_refusal) = &case.expected_refusal {
            validate_gate_identifier("expected_refusal", expected_refusal, 128)
                .map_err(|error| format!("case {:?} {error}", case.id))?;
        }
        match case.expected_path.as_str() {
            ANSWER_PATH_LOOKUP_HIT => {
                if case.expected_answer.is_none() || case.expected_refusal.is_some() {
                    return Err(format!(
                        "lookup-hit case {:?} requires expected_answer and forbids expected_refusal",
                        case.id
                    ));
                }
            }
            ANSWER_PATH_MODEL => {
                if case.expected_refusal.is_none() || case.expected_answer.is_some() {
                    return Err(format!(
                        "model-path case {:?} requires expected_refusal and forbids expected_answer",
                        case.id
                    ));
                }
            }
            other => {
                return Err(format!(
                    "case {:?} has unsupported expected_path {:?}",
                    case.id, other
                ));
            }
        }
    }
    Ok(())
}

fn validate_gate_identifier(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(format!("{field} must be non-empty and trimmed"));
    }
    if value.len() > max_bytes {
        return Err(format!("{field} exceeds {max_bytes} bytes"));
    }
    Ok(())
}

fn validate_gate_namespace(namespace: &str) -> Result<(), String> {
    validate_gate_identifier("namespace", namespace, 256)
}

/// Execute the v1 gate without contacting a provider or mutating policy.
pub fn run_lookup_promotion_gate(
    suite: &LookupPromotionGateSuite,
    db: &RuntimeDb,
) -> Result<LookupPromotionGateReport, String> {
    validate_lookup_promotion_gate_suite(suite)?;
    let cases = suite
        .cases
        .iter()
        .map(|case| LookupFixtureCase {
            id: case.id.clone(),
            capability: case.capability.clone(),
            namespace: case.namespace.clone(),
            actor: case.actor.clone(),
            input: case.input.clone(),
            expected_path: case.expected_path.clone(),
            expected_refusal: case.expected_refusal.clone(),
            expected_answer: case.expected_answer.clone(),
            shadow_model_answer: None,
        })
        .collect::<Vec<_>>();
    let result = run_fixture_suite(&suite.suite_id, &cases, db);
    let suite_digest = lookup_promotion_suite_digest(suite)?;
    Ok(LookupPromotionGateReport {
        contract_version: suite.contract_version.clone(),
        suite_id: suite.suite_id.clone(),
        namespace: suite.namespace.clone(),
        suite_digest,
        audit_decision_id: String::new(),
        verdict: if result.failed == 0 { "allow" } else { "deny" }.into(),
        lookup_hits: result.lookup_hits,
        model_path: result.model_path,
        lookup_refusals: result.lookup_refusals,
        passed: result.passed,
        failed: result.failed,
        cases: result
            .cases
            .into_iter()
            .map(bound_gate_case_result)
            .collect(),
    })
}

pub fn lookup_promotion_suite_digest(suite: &LookupPromotionGateSuite) -> Result<String, String> {
    let bytes = crate::shomei::canonical_json_with_finite_numbers(suite)?;
    Ok(format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
}

/// Persist only bounded, secret-free gate evidence. The suite and golden answers
/// remain operator-owned artifacts; the audit stores their digest and case-result digest.
pub fn record_lookup_promotion_gate(
    db: &RuntimeDb,
    actor: &str,
    report: &LookupPromotionGateReport,
) -> Result<String, String> {
    if actor.trim().is_empty() || actor != actor.trim() {
        return Err("gate audit actor must be non-empty and trimmed".into());
    }
    let case_results_digest = {
        let bytes = crate::shomei::canonical_json_with_finite_numbers(&report.cases)?;
        format!("sha256:{:x}", sha2::Sha256::digest(bytes))
    };
    let decision_id = uuid::Uuid::new_v4().to_string();
    let mut evidence = BTreeMap::new();
    evidence.insert("contract_version".into(), report.contract_version.clone());
    evidence.insert("suite_id".into(), report.suite_id.clone());
    evidence.insert("namespace".into(), report.namespace.clone());
    evidence.insert("suite_digest".into(), report.suite_digest.clone());
    evidence.insert("case_results_digest".into(), case_results_digest);
    evidence.insert("lookup_hits".into(), report.lookup_hits.to_string());
    evidence.insert("model_path".into(), report.model_path.to_string());
    evidence.insert("lookup_refusals".into(), report.lookup_refusals.to_string());
    evidence.insert("passed".into(), report.passed.to_string());
    evidence.insert("failed".into(), report.failed.to_string());
    let verdict = report.verdict.as_str();
    db.record_decision(&crate::sekai::audit::Decision {
        id: decision_id.clone(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: actor.into(),
        action: LOOKUP_FIRST_GATE_AUDIT_ACTION.into(),
        reason: if verdict == "allow" {
            "lookup-vs-golden promotion gate passed".into()
        } else {
            "lookup-vs-golden promotion gate failed; prior route policy remains unchanged".into()
        },
        evidence: evidence.into_iter().collect(),
        target_id: format!("lookup-first:{}:{}", report.namespace, report.suite_id),
        outcome: verdict.into(),
    })?;
    Ok(decision_id)
}

fn bound_gate_case_result(mut result: LookupFixtureCaseResult) -> LookupFixtureCaseResult {
    if result
        .detail
        .as_ref()
        .is_some_and(|detail| detail.len() > LOOKUP_FIRST_GATE_MAX_DETAIL_BYTES)
        && let Some(detail) = result.detail.as_mut()
    {
        let mut boundary = LOOKUP_FIRST_GATE_MAX_DETAIL_BYTES;
        while !detail.is_char_boundary(boundary) {
            boundary -= 1;
        }
        detail.truncate(boundary);
    }
    result
}

/// Attempt lookup-first for an allow-listed capability with structured input JSON.
pub fn try_lookup_first(
    capability: &str,
    namespace: &str,
    actor: &str,
    structured_input_json: &str,
    db: &RuntimeDb,
) -> Result<LookupDecision, String> {
    let capability = capability.trim();
    if !is_lookup_first_capability(capability) {
        return Ok(LookupDecision::NotEligible);
    }
    let namespace = namespace.trim();
    if namespace.is_empty() {
        return Ok(LookupDecision::Refusal {
            capability: capability.into(),
            reason: "invalid_namespace".into(),
        });
    }

    match capability {
        semantic::CAPABILITY_RESOLVE_REF => {
            try_resolve_ref(namespace, actor, structured_input_json, db)
        }
        semantic::CAPABILITY_EXPAND_RELATIONS => {
            try_expand_relations(namespace, actor, structured_input_json, db)
        }
        semantic::CAPABILITY_RETRIEVE_CONTEXT => {
            try_retrieve_context(namespace, actor, structured_input_json, db)
        }
        semantic::CAPABILITY_EXPLAIN_DERIVATION => {
            try_explain_derivation(namespace, actor, structured_input_json, db)
        }
        _ => Ok(LookupDecision::NotEligible),
    }
}

#[derive(Debug)]
enum RetrievalLookupError {
    Refusal(&'static str),
    Storage(String),
}

fn refusal(capability: &str, reason: &'static str) -> LookupDecision {
    LookupDecision::Refusal {
        capability: capability.into(),
        reason: reason.into(),
    }
}

fn parse_retrieval_input(
    capability: &str,
    namespace: &str,
    structured_input_json: &str,
) -> Result<LookupRetrievalInput, LookupDecision> {
    let raw = serde_json::from_str::<Value>(structured_input_json)
        .map_err(|_| refusal(capability, "schema_miss"))?;
    validate_retrieval_fields(capability, &raw)?;
    let input = serde_json::from_value::<LookupRetrievalInput>(raw)
        .map_err(|_| refusal(capability, "schema_miss"))?;
    if !input.namespace.is_empty() && input.namespace != namespace {
        return Err(refusal(capability, "cross_namespace"));
    }
    Ok(input)
}

fn validate_retrieval_fields(capability: &str, raw: &Value) -> Result<(), LookupDecision> {
    let Some(fields) = raw.as_object() else {
        return Err(refusal(capability, "schema_miss"));
    };
    let allowed = match capability {
        semantic::CAPABILITY_EXPAND_RELATIONS => &[
            "namespace",
            "root",
            "relations",
            "direction",
            "reasoning_mode",
            "max_depth",
            "max_objects",
            "max_links",
            "kind_filter",
            "max_source_rows",
            "max_derived_rows",
            "max_derivation_steps",
            "max_time_ms",
            "max_explanation_bytes",
        ][..],
        semantic::CAPABILITY_RETRIEVE_CONTEXT => &[
            "roots",
            "relations",
            "direction",
            "max_depth",
            "max_objects",
            "max_links",
            "kind_filter",
            "reasoning_mode",
            "max_source_rows",
            "max_derived_rows",
            "max_derivation_steps",
            "max_time_ms",
            "max_explanation_bytes",
        ][..],
        semantic::CAPABILITY_EXPLAIN_DERIVATION => &[
            "namespace",
            "from",
            "to",
            "relations",
            "direction",
            "reasoning_mode",
            "max_depth",
            "max_objects",
            "max_links",
            "max_source_rows",
            "max_derived_rows",
            "max_derivation_steps",
            "max_time_ms",
            "max_explanation_bytes",
        ][..],
        _ => return Err(refusal(capability, "schema_miss")),
    };
    if fields
        .keys()
        .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err(refusal(capability, "schema_miss"));
    }
    Ok(())
}

fn build_retrieval_query(
    input: &LookupRetrievalInput,
    roots: Vec<RetrievalRoot>,
    default_max_depth: Option<u32>,
) -> Result<RetrievalQuery, LookupDecision> {
    let direction = RetrievalDirection::parse(&input.direction)
        .map_err(|_| refusal("lookup", "schema_miss"))?;
    let reasoning_mode = ReasoningMode::parse(&input.reasoning_mode)
        .map_err(|_| refusal("lookup", "schema_miss"))?;
    Ok(RetrievalQuery {
        roots,
        relations: input.relations.clone(),
        direction,
        max_depth: if input.max_depth == 0 {
            default_max_depth.unwrap_or(0)
        } else {
            input.max_depth
        },
        max_objects: input.max_objects,
        max_links: input.max_links,
        kind_filter: input.kind_filter.clone(),
        reasoning_mode,
        max_source_rows: input.max_source_rows,
        max_derived_rows: input.max_derived_rows,
        max_derivation_steps: input.max_derivation_steps,
        max_time_ms: input.max_time_ms,
        max_explanation_bytes: input.max_explanation_bytes,
        initial_source_rows: 0,
        source_rows_truncated: false,
    })
}

fn try_expand_relations(
    namespace: &str,
    actor: &str,
    structured_input_json: &str,
    db: &RuntimeDb,
) -> Result<LookupDecision, String> {
    let capability = semantic::CAPABILITY_EXPAND_RELATIONS;
    let input = match parse_retrieval_input(capability, namespace, structured_input_json) {
        Ok(input) => input,
        Err(decision) => return Ok(decision),
    };
    let Some(root) = input.root.clone() else {
        return Ok(refusal(capability, "schema_miss"));
    };
    let root = match root.into_retrieval_root() {
        Ok(root) => root,
        Err(()) => return Ok(refusal(capability, "schema_miss")),
    };
    let query = match build_retrieval_query(&input, vec![root], None) {
        Ok(query) => query,
        Err(decision) => return Ok(with_capability(decision, capability)),
    };
    let reasoning_mode = query.reasoning_mode;
    let result = match run_lookup_retrieval(namespace, actor, db, query) {
        Ok(result) => result,
        Err(RetrievalLookupError::Refusal(reason)) => return Ok(refusal(capability, reason)),
        Err(RetrievalLookupError::Storage(error)) => return Err(error),
    };
    if let Some(reason) = result_refusal_reason(&result) {
        return Ok(refusal(capability, reason));
    }
    let answer = retrieval_answer_json(capability, &result, reasoning_mode, None)?;
    let provenance = retrieval_provenance(&result);
    Ok(LookupDecision::Hit {
        capability: capability.into(),
        answer_json: answer,
        provenance,
    })
}

fn try_retrieve_context(
    namespace: &str,
    actor: &str,
    structured_input_json: &str,
    db: &RuntimeDb,
) -> Result<LookupDecision, String> {
    let capability = semantic::CAPABILITY_RETRIEVE_CONTEXT;
    let input = match parse_retrieval_input(capability, namespace, structured_input_json) {
        Ok(input) => input,
        Err(decision) => return Ok(decision),
    };
    if input.roots.is_empty() {
        return Ok(refusal(capability, "schema_miss"));
    }
    let roots = match input
        .roots
        .clone()
        .into_iter()
        .map(LookupContextRoot::into_retrieval_root)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(roots) => roots,
        Err(()) => return Ok(refusal(capability, "schema_miss")),
    };
    let query = match build_retrieval_query(&input, roots, None) {
        Ok(query) => query,
        Err(decision) => return Ok(with_capability(decision, capability)),
    };
    let reasoning_mode = query.reasoning_mode;
    let result = match run_lookup_retrieval(namespace, actor, db, query) {
        Ok(result) => result,
        Err(RetrievalLookupError::Refusal(reason)) => return Ok(refusal(capability, reason)),
        Err(RetrievalLookupError::Storage(error)) => return Err(error),
    };
    if let Some(reason) = result_refusal_reason(&result) {
        return Ok(refusal(capability, reason));
    }
    let answer = retrieval_answer_json(capability, &result, reasoning_mode, None)?;
    let provenance = retrieval_provenance(&result);
    Ok(LookupDecision::Hit {
        capability: capability.into(),
        answer_json: answer,
        provenance,
    })
}

fn try_explain_derivation(
    namespace: &str,
    actor: &str,
    structured_input_json: &str,
    db: &RuntimeDb,
) -> Result<LookupDecision, String> {
    let capability = semantic::CAPABILITY_EXPLAIN_DERIVATION;
    let input = match parse_retrieval_input(capability, namespace, structured_input_json) {
        Ok(input) => input,
        Err(decision) => return Ok(decision),
    };
    let (Some(from), Some(to)) = (input.from.clone(), input.to.clone()) else {
        return Ok(refusal(capability, "schema_miss"));
    };
    let from = match from.into_retrieval_root() {
        Ok(root) => root,
        Err(()) => return Ok(refusal(capability, "schema_miss")),
    };
    let to = match to.into_retrieval_root() {
        Ok(root) => root,
        Err(()) => return Ok(refusal(capability, "schema_miss")),
    };
    let principals = effective_lookup_principals(actor);
    if !explain_target_is_authorized(&to, namespace, &principals, db)? {
        // Missing and unauthorized targets intentionally share one outcome.
        // A distinct refusal for an existing but hidden target would create
        // an existence oracle through the lookup/model path boundary.
        return Ok(refusal(capability, "incomplete"));
    }
    let query = match build_retrieval_query(&input, vec![from], Some(retrieval::MAX_DEPTH)) {
        Ok(query) => query,
        Err(decision) => return Ok(with_capability(decision, capability)),
    };
    let reasoning_mode = query.reasoning_mode;
    let result = match run_lookup_retrieval(namespace, actor, db, query) {
        Ok(result) => result,
        Err(RetrievalLookupError::Refusal(reason)) => return Ok(refusal(capability, reason)),
        Err(RetrievalLookupError::Storage(error)) => return Err(error),
    };
    if let Some(reason) = result_refusal_reason(&result) {
        return Ok(refusal(capability, reason));
    }
    let answer = retrieval_answer_json(capability, &result, reasoning_mode, Some(&to))?;
    let provenance = retrieval_provenance(&result);
    Ok(LookupDecision::Hit {
        capability: capability.into(),
        answer_json: answer,
        provenance,
    })
}

fn with_capability(decision: LookupDecision, capability: &str) -> LookupDecision {
    match decision {
        LookupDecision::Refusal { reason, .. } => LookupDecision::Refusal {
            capability: capability.into(),
            reason,
        },
        other => other,
    }
}

const RESERVED_GOVERNANCE_KINDS: &[&str] = &[
    ACTION_POLICY_KIND,
    BLAST_RADIUS_KIND,
    "action_approval",
    crate::domain::KIND_CAPABILITY,
    crate::domain::KIND_EXTERNAL_EVIDENCE,
    PROFILE_KIND,
    FACT_KIND,
    WAIVER_KIND,
    markings::PRINCIPAL_PROFILE_KIND,
];

fn is_reserved_governance_kind(kind: &str) -> bool {
    RESERVED_GOVERNANCE_KINDS.contains(&kind)
}

fn run_lookup_retrieval(
    namespace: &str,
    actor: &str,
    db: &RuntimeDb,
    mut query: RetrievalQuery,
) -> Result<retrieval::RetrievalResult, RetrievalLookupError> {
    let started = Instant::now();
    let principals = effective_lookup_principals(actor);
    let roots = query.roots.clone();
    if let Some(reason) = preflight_root_access(&roots, namespace, &principals, db)
        .map_err(RetrievalLookupError::Storage)?
    {
        return Err(RetrievalLookupError::Refusal(reason));
    }
    let (ontology, source_rows, source_rows_truncated) =
        lookup_ontology_snapshot(db, &principals, &query, started)?;
    query.initial_source_rows = source_rows;
    query.source_rows_truncated = source_rows_truncated;
    let namespace = namespace.to_string();
    let mut result = retrieval::retrieve_with_ontology_started(
        db,
        &query,
        ontology.as_ref(),
        started,
        |object| {
            (object.namespace.is_empty() || object.namespace == namespace)
                && lookup_object_readable(object, &principals, db).unwrap_or(false)
        },
        |object| is_reserved_governance_kind(&object.kind),
    )
    .map_err(|error| match error {
        retrieval::RetrievalError::InvalidArgument(_) => {
            RetrievalLookupError::Refusal("schema_miss")
        }
        retrieval::RetrievalError::Storage(error) => RetrievalLookupError::Storage(error),
    })?;
    if query.reasoning_mode == ReasoningMode::Entailment
        && started.elapsed() >= lookup_reasoning_timeout(query.max_time_ms)
        && !result
            .truncation_reasons
            .iter()
            .any(|reason| reason == "time")
    {
        result.truncation_reasons.push("time".into());
        result.truncated = true;
    }
    for candidate in &mut result.candidates {
        candidate.object = redact_lookup_object(&candidate.object, &principals, &namespace, db)
            .map_err(RetrievalLookupError::Storage)?;
    }
    Ok(result)
}

fn effective_lookup_principals(actor: &str) -> Vec<String> {
    // ExecutePlanStream receives one canonical authenticated subject. Keep it
    // opaque; an independently authenticated principal list would need to be
    // passed as a separate request-context value, never encoded in the name.
    vec![actor.to_string()]
}

fn lookup_reasoning_timeout(max_time_ms: u32) -> Duration {
    Duration::from_millis(u64::from(if max_time_ms == 0 {
        retrieval::DEFAULT_MAX_TIME_MS
    } else {
        max_time_ms.min(retrieval::MAX_TIME_MS)
    }))
}

fn preflight_root_access(
    roots: &[RetrievalRoot],
    namespace: &str,
    principals: &[String],
    db: &RuntimeDb,
) -> Result<Option<&'static str>, String> {
    for root in roots {
        let objects = match root {
            RetrievalRoot::Object(id) => db.get_object(id)?.into_iter().collect::<Vec<_>>(),
            RetrievalRoot::External(external_id) => db
                .find_by_external_id(external_id)?
                .into_iter()
                .collect::<Vec<_>>(),
            RetrievalRoot::Link(id) => {
                let Some(link) = db.get_link(id)? else {
                    continue;
                };
                [db.get_object(&link.from_id)?, db.get_object(&link.to_id)?]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
            }
        };
        for object in objects {
            if !object.namespace.is_empty() && object.namespace != namespace {
                return Ok(Some("cross_namespace"));
            }
            if is_reserved_governance_kind(&object.kind)
                || !lookup_object_readable(&object, principals, db)?
            {
                return Ok(Some("acl_denied"));
            }
        }
    }
    Ok(None)
}

fn explain_target_is_authorized(
    target: &RetrievalRoot,
    namespace: &str,
    principals: &[String],
    db: &RuntimeDb,
) -> Result<bool, String> {
    let objects = match target {
        RetrievalRoot::Object(id) => db.get_object(id)?.into_iter().collect::<Vec<_>>(),
        RetrievalRoot::External(external_id) => db
            .find_by_external_id(external_id)?
            .into_iter()
            .collect::<Vec<_>>(),
        RetrievalRoot::Link(id) => {
            let Some(link) = db.get_link(id)? else {
                return Ok(false);
            };
            [db.get_object(&link.from_id)?, db.get_object(&link.to_id)?]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
        }
    };
    if objects.is_empty() {
        return Ok(false);
    }
    Ok(objects.iter().all(|object| {
        (object.namespace.is_empty() || object.namespace == namespace)
            && !is_reserved_governance_kind(&object.kind)
            && lookup_object_readable(object, principals, db).unwrap_or(false)
    }))
}

fn lookup_ontology_snapshot(
    db: &RuntimeDb,
    principals: &[String],
    query: &RetrievalQuery,
    started: Instant,
) -> Result<(Option<OntologyRegistry>, u32, bool), RetrievalLookupError> {
    if query.reasoning_mode != ReasoningMode::Entailment {
        return Ok((None, 0, false));
    }
    if db.backend_name() == "postgres" {
        return Err(RetrievalLookupError::Refusal("backend_unsupported"));
    }
    let deadline = started + lookup_reasoning_timeout(query.max_time_ms);
    let source_limit = if query.max_source_rows == 0 {
        retrieval::DEFAULT_MAX_SOURCE_ROWS
    } else {
        query.max_source_rows.min(retrieval::MAX_SOURCE_ROWS)
    };
    let mut source_rows = 0u32;
    let mut source_rows_truncated = false;
    let mut classes = match db.list_readable_ontology_classes(
        principals,
        deadline,
        source_limit.saturating_add(1),
    ) {
        Ok(classes) => classes,
        Err(_) if started.elapsed() >= lookup_reasoning_timeout(query.max_time_ms) => Vec::new(),
        Err(error) => return Err(RetrievalLookupError::Storage(error)),
    };
    if classes.len() > source_limit as usize {
        classes.truncate(source_limit as usize);
        source_rows_truncated = true;
    }
    source_rows = source_rows.saturating_add(classes.len() as u32);
    classes.retain(|_| started.elapsed() < lookup_reasoning_timeout(query.max_time_ms));
    let visible_class_names = classes
        .iter()
        .map(|class| class.name.clone())
        .collect::<std::collections::HashSet<_>>();
    for class in &mut classes {
        class
            .superclasses
            .retain(|name| visible_class_names.contains(name));
        class
            .equivalent_classes
            .retain(|name| visible_class_names.contains(name));
        class
            .disjoint_classes
            .retain(|name| visible_class_names.contains(name));
    }
    let remaining_rows = source_limit.saturating_sub(source_rows);
    let mut relations = if !source_rows_truncated && started < deadline {
        match db.list_readable_ontology_relations(
            principals,
            deadline,
            remaining_rows.saturating_add(1),
        ) {
            Ok(relations) => relations,
            Err(_) if started.elapsed() >= lookup_reasoning_timeout(query.max_time_ms) => {
                Vec::new()
            }
            Err(error) => return Err(RetrievalLookupError::Storage(error)),
        }
    } else {
        Vec::new()
    };
    if relations.len() > remaining_rows as usize {
        relations.truncate(remaining_rows as usize);
        source_rows_truncated = true;
    }
    source_rows = source_rows.saturating_add(relations.len() as u32);
    relations.retain(|_| started.elapsed() < lookup_reasoning_timeout(query.max_time_ms));
    let visible_relation_names = relations
        .iter()
        .map(|relation| relation.name.clone())
        .collect::<std::collections::HashSet<_>>();
    relations.retain(|relation| {
        visible_class_names.contains(&relation.domain)
            && visible_class_names.contains(&relation.range)
    });
    for relation in &mut relations {
        if !relation.inverse.is_empty() && !visible_relation_names.contains(&relation.inverse) {
            relation.inverse.clear();
        }
    }
    Ok((
        Some(OntologyRegistry::from_parts(classes, relations)),
        source_rows,
        source_rows_truncated,
    ))
}

fn result_refusal_reason(result: &retrieval::RetrievalResult) -> Option<&'static str> {
    if result.denied_roots > 0 || result.denied_objects > 0 {
        return Some("acl_denied");
    }
    if result.unresolved_roots > 0 {
        return Some("incomplete");
    }
    if result.truncated {
        return Some("truncated");
    }
    None
}

fn retrieval_answer_json(
    capability: &str,
    result: &retrieval::RetrievalResult,
    reasoning_mode: ReasoningMode,
    explain_to: Option<&RetrievalRoot>,
) -> Result<String, String> {
    if capability == semantic::CAPABILITY_EXPLAIN_DERIVATION {
        let found_explanation = result.candidates.iter().find_map(|candidate| {
            explain_to
                .is_some_and(|root| retrieval_root_matches_object(root, &candidate.object, result))
                .then(|| candidate.explanation.clone())
        });
        let mut evidence_refs = found_explanation
            .as_ref()
            .map(|explanation| explanation.source_fact_ids.clone())
            .unwrap_or_default();
        if let Some(explanation) = found_explanation.as_ref() {
            for step in &explanation.steps {
                evidence_refs.extend(step.source_fact_ids.iter().cloned());
            }
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        let descriptor = found_explanation
            .as_ref()
            .map(|explanation| descriptor_json(explanation, false));
        return serde_json::to_string(&json!({
            "explanation": found_explanation.as_ref().map(explanation_json),
            "found": found_explanation.is_some(),
            "truncated": result.truncated,
            "truncation_reasons": result.truncation_reasons,
            "ontology_revision": result.ontology_revision,
            "reasoning_mode": semantic::reasoning_mode_label(reasoning_mode),
            "evidence_refs": evidence_refs,
            "descriptor": descriptor,
        }))
        .map_err(|error| error.to_string());
    }

    let candidates = result
        .candidates
        .iter()
        .map(candidate_json)
        .collect::<Vec<_>>();
    let links = result
        .links
        .iter()
        .map(|link| serde_json::to_value(link).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut response = json!({
        "candidates": candidates,
        "links": links,
        "truncated": result.truncated,
        "unresolved_roots": result.unresolved_roots,
        "denied_objects": 0,
        "truncated_objects": result.truncated_objects,
        "truncated_links": result.truncated_links,
        "truncation_reasons": result.truncation_reasons,
        "source_rows": result.source_rows,
        "derived_rows": result.derived_rows,
        "ontology_revision": result.ontology_revision,
    });
    if capability == semantic::CAPABILITY_EXPAND_RELATIONS {
        response["reasoning_mode"] = json!(semantic::reasoning_mode_label(reasoning_mode));
        response["epistemic_descriptor_version"] = json!(EPISTEMIC_DESCRIPTOR_VERSION);
    } else {
        response["epistemic_descriptor_version"] = json!(EPISTEMIC_DESCRIPTOR_VERSION);
    }
    serde_json::to_string(&response).map_err(|error| error.to_string())
}

fn retrieval_root_matches_object(
    root: &RetrievalRoot,
    object: &Object,
    result: &retrieval::RetrievalResult,
) -> bool {
    match root {
        RetrievalRoot::Object(id) => object.id == *id,
        RetrievalRoot::External(external_id) => object.external_id == *external_id,
        RetrievalRoot::Link(link_id) => result.links.iter().any(|link| {
            link.id == *link_id && (link.from_id == object.id || link.to_id == object.id)
        }),
    }
}

fn candidate_json(candidate: &retrieval::RetrievalCandidate) -> Value {
    json!({
        "object": candidate.object,
        "depth": candidate.depth,
        "via_relation": candidate.via_relation,
        "affinity": candidate.affinity,
        "explanation": explanation_json(&candidate.explanation),
        "descriptor": descriptor_json(&candidate.explanation, false),
    })
}

fn explanation_json(explanation: &retrieval::Explanation) -> Value {
    json!({
        "steps": explanation
            .steps
            .iter()
            .map(|step| json!({
                "kind": step.kind,
                "relation": step.relation,
                "from_id": step.from_id,
                "to_id": step.to_id,
                "source_fact_ids": step.source_fact_ids,
                "ontology_revision": step.ontology_revision,
                "rule": step.rule,
            }))
            .collect::<Vec<_>>(),
        "source_fact_ids": explanation.source_fact_ids,
        "ontology_revision": explanation.ontology_revision,
        "derived": explanation.derived,
    })
}

fn descriptor_json(explanation: &retrieval::Explanation, source_rows_truncated: bool) -> Value {
    serde_json::to_value(DomainEpistemicDescriptor::from_graph_explanation(
        explanation,
        source_rows_truncated,
    ))
    .expect("epistemic descriptor is serializable")
}

fn retrieval_provenance(result: &retrieval::RetrievalResult) -> BTreeMap<String, String> {
    let mut object_ids = result
        .candidates
        .iter()
        .map(|candidate| candidate.object.id.clone())
        .collect::<Vec<_>>();
    object_ids.sort();
    object_ids.dedup();
    object_ids.truncate(8);
    let mut link_ids = result
        .links
        .iter()
        .map(|link| link.id.clone())
        .collect::<Vec<_>>();
    link_ids.sort();
    link_ids.dedup();
    link_ids.truncate(8);
    let mut provenance = BTreeMap::new();
    if !object_ids.is_empty() {
        provenance.insert("source_object_ids".into(), object_ids.join(","));
    }
    if !link_ids.is_empty() {
        provenance.insert("source_link_ids".into(), link_ids.join(","));
    }
    if !result.ontology_revision.is_empty() {
        provenance.insert("ontology_revision".into(), result.ontology_revision.clone());
    }
    provenance
}

fn try_resolve_ref(
    namespace: &str,
    actor: &str,
    structured_input_json: &str,
    db: &RuntimeDb,
) -> Result<LookupDecision, String> {
    let input: ResolveRefInput = match serde_json::from_str(structured_input_json) {
        Ok(value) => value,
        Err(_) => {
            return Ok(LookupDecision::Refusal {
                capability: semantic::CAPABILITY_RESOLVE_REF.into(),
                reason: "schema_miss".into(),
            });
        }
    };

    let field_count = semantic::resolve_ref_field_count(
        &input.object_id,
        &input.external_id,
        &input.ontology_class,
        &input.ontology_relation,
    );
    if field_count != 1 {
        return Ok(LookupDecision::Refusal {
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            reason: "schema_miss".into(),
        });
    }

    if !input.object_id.trim().is_empty() || !input.external_id.trim().is_empty() {
        return resolve_object_ref(namespace, actor, &input, db);
    }
    if !input.ontology_class.trim().is_empty() {
        return resolve_ontology_class(namespace, actor, input.ontology_class.trim(), db);
    }
    resolve_ontology_relation(namespace, actor, input.ontology_relation.trim(), db)
}

fn resolve_object_ref(
    namespace: &str,
    actor: &str,
    input: &ResolveRefInput,
    db: &RuntimeDb,
) -> Result<LookupDecision, String> {
    let object = if !input.object_id.trim().is_empty() {
        db.get_object(input.object_id.trim())?
    } else {
        db.find_by_external_id(input.external_id.trim())?
    };

    let Some(object) = object else {
        return Ok(LookupDecision::Refusal {
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            reason: "incomplete".into(),
        });
    };

    if object.namespace != namespace {
        // Fail closed: never leak cross-namespace facts into a model-bound answer path.
        return Ok(LookupDecision::Refusal {
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            reason: "cross_namespace".into(),
        });
    }

    if !object_readable(&object, actor, db)? {
        return Ok(LookupDecision::Refusal {
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            reason: "acl_denied".into(),
        });
    }
    let object = db.project_object_property_grants(object)?;

    let answer = json!({
        "capability": semantic::CAPABILITY_RESOLVE_REF,
        "ref_kind": semantic::REF_KIND_OBJECT,
        "resolved": true,
        "namespace": namespace,
        "object": {
            "id": object.id,
            "kind": object.kind,
            "name": object.name,
            "namespace": object.namespace,
            "external_id": object.external_id,
            "properties": object.properties,
        }
    });
    let mut provenance = BTreeMap::new();
    provenance.insert("source_object_id".into(), object.id.clone());
    provenance.insert("ref_kind".into(), semantic::REF_KIND_OBJECT.into());
    Ok(LookupDecision::Hit {
        capability: semantic::CAPABILITY_RESOLVE_REF.into(),
        answer_json: answer.to_string(),
        provenance,
    })
}

fn resolve_ontology_class(
    namespace: &str,
    actor: &str,
    class_name: &str,
    db: &RuntimeDb,
) -> Result<LookupDecision, String> {
    let Some(class) = db.get_ontology_class(class_name)? else {
        return Ok(LookupDecision::Refusal {
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            reason: "incomplete".into(),
        });
    };
    // Ontology class bodies are global; still re-check any projected ACL object
    // when grants exist (fail closed). No grant → readable.
    let class_object_id = format!("ontology.class:{class_name}");
    if !id_readable(&class_object_id, actor, db)? {
        return Ok(LookupDecision::Refusal {
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            reason: "acl_denied".into(),
        });
    }
    let answer = json!({
        "capability": semantic::CAPABILITY_RESOLVE_REF,
        "ref_kind": semantic::REF_KIND_ONTOLOGY_CLASS,
        "resolved": true,
        "namespace": namespace,
        "ontology_class": {
            "name": class.name,
            "description": class.description,
            "mapped_kind": class.mapped_kind,
        }
    });
    let mut provenance = BTreeMap::new();
    provenance.insert("ontology_class".into(), class.name);
    provenance.insert("ref_kind".into(), semantic::REF_KIND_ONTOLOGY_CLASS.into());
    Ok(LookupDecision::Hit {
        capability: semantic::CAPABILITY_RESOLVE_REF.into(),
        answer_json: answer.to_string(),
        provenance,
    })
}

fn resolve_ontology_relation(
    namespace: &str,
    actor: &str,
    relation_name: &str,
    db: &RuntimeDb,
) -> Result<LookupDecision, String> {
    let Some(relation) = db.get_ontology_relation(relation_name)? else {
        return Ok(LookupDecision::Refusal {
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            reason: "incomplete".into(),
        });
    };
    let relation_object_id = format!("ontology.relation:{relation_name}");
    if !id_readable(&relation_object_id, actor, db)? {
        return Ok(LookupDecision::Refusal {
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            reason: "acl_denied".into(),
        });
    }
    let answer = json!({
        "capability": semantic::CAPABILITY_RESOLVE_REF,
        "ref_kind": semantic::REF_KIND_ONTOLOGY_RELATION,
        "resolved": true,
        "namespace": namespace,
        "ontology_relation": {
            "name": relation.name,
            "description": relation.description,
            "domain": relation.domain,
            "range": relation.range,
        }
    });
    let mut provenance = BTreeMap::new();
    provenance.insert("ontology_relation".into(), relation.name);
    provenance.insert(
        "ref_kind".into(),
        semantic::REF_KIND_ONTOLOGY_RELATION.into(),
    );
    Ok(LookupDecision::Hit {
        capability: semantic::CAPABILITY_RESOLVE_REF.into(),
        answer_json: answer.to_string(),
        provenance,
    })
}

/// Object is readable when unrestricted (no grants) or the actor holds a grant.
/// Privileged local/root actors always pass, matching control-plane conventions.
fn object_readable(object: &Object, actor: &str, db: &RuntimeDb) -> Result<bool, String> {
    if matches!(actor, "root" | "local") {
        return Ok(true);
    }
    id_readable(&object.id, actor, db)
}

fn id_readable(object_id: &str, actor: &str, db: &RuntimeDb) -> Result<bool, String> {
    if matches!(actor, "root" | "local") {
        return Ok(true);
    }
    let grants = db.list_grants(object_id)?;
    if grants.is_empty() {
        return Ok(true);
    }
    Ok(grants.iter().any(|grant| grant.principal == actor))
}

fn id_readable_for_principals(
    object_id: &str,
    principals: &[String],
    db: &RuntimeDb,
) -> Result<bool, String> {
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return Ok(true);
    }
    let grants = db.list_grants(object_id)?;
    if grants.is_empty() {
        return Ok(true);
    }
    Ok(grants
        .iter()
        .any(|grant| principals.contains(&grant.principal)))
}

fn lookup_object_readable(
    object: &Object,
    principals: &[String],
    db: &RuntimeDb,
) -> Result<bool, String> {
    if !id_readable_for_principals(&object.id, principals, db)?
        || is_reserved_governance_kind(&object.kind)
    {
        return Ok(false);
    }
    if markings::object_marking_token(object).is_none() {
        return Ok(true);
    }
    let primary = principals.first().map(String::as_str).unwrap_or_default();
    let authority = lookup_principal_authority(primary, db)?;
    let lattice = db.get_classification_lattice(&object.namespace)?;
    Ok(
        crate::sekai::classification_lattice::evaluate_lattice_access(
            "lookup-first",
            markings::object_marking_token(object),
            &authority,
            lattice.as_ref(),
        )
        .decision
            != markings::MarkingDecision::Deny,
    )
}

fn lookup_principal_authority(
    actor: &str,
    db: &RuntimeDb,
) -> Result<markings::PrincipalAuthority, String> {
    if let Some(trusted) = markings::trusted_service_authority(actor) {
        return Ok(trusted);
    }
    let candidates = db.find_all_by_external_id(&markings::principal_profile_external_id(actor))?;
    let mut trusted_profiles = Vec::new();
    for object in &candidates {
        if object.kind != markings::PRINCIPAL_PROFILE_KIND
            || object
                .properties
                .get(markings::PRINCIPAL_PROFILE_SEALED_PROPERTY)
                .is_none_or(|value| value != "true")
        {
            continue;
        }
        let grants = db.list_grants(&object.id)?;
        if grants.iter().any(|grant| matches!(grant.role, Role::Admin)) {
            trusted_profiles.push(object);
        }
    }
    if trusted_profiles.len() > 1 {
        return Err("multiple trusted principal profiles found".into());
    }
    markings::principal_authority_from_profile(actor, trusted_profiles.first().copied())
}

fn redact_lookup_object(
    object: &Object,
    principals: &[String],
    namespace: &str,
    db: &RuntimeDb,
) -> Result<Object, String> {
    let mut schema_registry = SchemaRegistry::new();
    if let Some(object_type) = db.get_object_type(&object.kind)? {
        schema_registry.register(object_type);
    }
    let mut projected = object.clone();
    compute::resolve_schema_computed_with_filter(
        &mut projected,
        db,
        &schema_registry,
        |candidate| {
            (candidate.namespace.is_empty() || candidate.namespace == namespace)
                && lookup_object_readable(candidate, principals, db).unwrap_or(false)
        },
    )?;
    if principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"))
    {
        return db.project_object_property_grants(projected);
    }
    let is_admin = db
        .list_grants(&projected.id)?
        .iter()
        .any(|grant| principals.contains(&grant.principal) && matches!(grant.role, Role::Admin));
    if is_admin {
        return db.project_object_property_grants(projected);
    }
    let Some(object_type) = schema_registry.get(&projected.kind) else {
        return db.project_object_property_grants(projected);
    };
    let mut redacted = projected;
    for property in &object_type.properties {
        if schema::is_restricted_property_classification(&property.classification)
            && redacted.properties.contains_key(&property.name)
        {
            redacted
                .properties
                .insert(property.name.clone(), "[redacted]".into());
        }
    }
    db.project_object_property_grants(redacted)
}

/// Run the lookup-first fixture suite against a prepared database.
///
/// Dual-run/shadow: when a case supplies `shadow_model_answer`, the lookup
/// answer must be structurally equal (JSON value equality after parse).
pub fn run_fixture_suite(
    suite_name: &str,
    cases: &[LookupFixtureCase],
    db: &RuntimeDb,
) -> LookupFixtureSuiteReport {
    let mut report = LookupFixtureSuiteReport {
        suite: suite_name.into(),
        ..Default::default()
    };

    for case in cases {
        let decision = try_lookup_first(
            &case.capability,
            &case.namespace,
            &case.actor,
            &case.input.to_string(),
            db,
        );
        let result = match decision {
            Ok(LookupDecision::Hit { answer_json, .. }) => {
                report.lookup_hits += 1;
                let mut passed = case.expected_path == ANSWER_PATH_LOOKUP_HIT;
                let mut detail = None;
                if let Some(expected) = &case.expected_answer {
                    match serde_json::from_str::<Value>(&answer_json) {
                        Ok(actual) if values_structurally_equal(&actual, expected) => {}
                        Ok(_) => {
                            passed = false;
                            detail = Some("lookup answer diverged from golden".into());
                        }
                        Err(error) => {
                            passed = false;
                            detail = Some(format!("lookup answer not JSON: {error}"));
                        }
                    }
                }
                if let Some(shadow) = &case.shadow_model_answer {
                    match serde_json::from_str::<Value>(&answer_json) {
                        Ok(actual) if values_structurally_equal(&actual, shadow) => {}
                        Ok(_) => {
                            passed = false;
                            detail = Some("dual-run shadow structural mismatch".into());
                        }
                        Err(error) => {
                            passed = false;
                            detail = Some(format!("lookup answer not JSON for shadow: {error}"));
                        }
                    }
                }
                LookupFixtureCaseResult {
                    id: case.id.clone(),
                    answer_path: ANSWER_PATH_LOOKUP_HIT.into(),
                    lookup_refusal: None,
                    passed,
                    detail,
                }
            }
            Ok(LookupDecision::Refusal { reason, .. }) => {
                report.model_path += 1;
                report.lookup_refusals += 1;
                let mut passed = case.expected_path == ANSWER_PATH_MODEL;
                if let Some(expected_refusal) = &case.expected_refusal
                    && expected_refusal != &reason
                {
                    passed = false;
                }
                LookupFixtureCaseResult {
                    id: case.id.clone(),
                    answer_path: ANSWER_PATH_MODEL.into(),
                    lookup_refusal: Some(reason),
                    passed,
                    detail: None,
                }
            }
            Ok(LookupDecision::NotEligible) => {
                report.model_path += 1;
                let passed = case.expected_path == ANSWER_PATH_MODEL;
                LookupFixtureCaseResult {
                    id: case.id.clone(),
                    answer_path: ANSWER_PATH_MODEL.into(),
                    lookup_refusal: Some("not_eligible".into()),
                    passed,
                    detail: Some("capability not allow-listed".into()),
                }
            }
            Err(error) => {
                report.model_path += 1;
                LookupFixtureCaseResult {
                    id: case.id.clone(),
                    answer_path: ANSWER_PATH_MODEL.into(),
                    lookup_refusal: Some("storage_error".into()),
                    passed: false,
                    detail: Some(error),
                }
            }
        };
        if result.passed {
            report.passed += 1;
        } else {
            report.failed += 1;
        }
        report.cases.push(result);
    }
    report
}

fn values_structurally_equal(left: &Value, right: &Value) -> bool {
    left == right
}

/// Built-in S1 fixture definitions (hit, incomplete→fallback, cross-namespace deny).
pub fn s1_fixture_cases() -> Vec<LookupFixtureCase> {
    vec![
        LookupFixtureCase {
            id: "resolve_ref_hit".into(),
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({"external_id": "widget:lookup-root"}),
            expected_path: ANSWER_PATH_LOOKUP_HIT.into(),
            expected_refusal: None,
            expected_answer: Some(json!({
                "capability": semantic::CAPABILITY_RESOLVE_REF,
                "ref_kind": semantic::REF_KIND_OBJECT,
                "resolved": true,
                "namespace": "acme",
                "object": {
                    "id": "lookup-root",
                    "kind": "widget",
                    "name": "lookup-root",
                    "namespace": "acme",
                    "external_id": "widget:lookup-root",
                    "properties": {"name": "lookup-root", "color": "red"}
                }
            })),
            shadow_model_answer: Some(json!({
                "capability": semantic::CAPABILITY_RESOLVE_REF,
                "ref_kind": semantic::REF_KIND_OBJECT,
                "resolved": true,
                "namespace": "acme",
                "object": {
                    "id": "lookup-root",
                    "kind": "widget",
                    "name": "lookup-root",
                    "namespace": "acme",
                    "external_id": "widget:lookup-root",
                    "properties": {"name": "lookup-root", "color": "red"}
                }
            })),
        },
        LookupFixtureCase {
            id: "resolve_ref_incomplete_fallback".into(),
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({"object_id": "does-not-exist"}),
            expected_path: ANSWER_PATH_MODEL.into(),
            expected_refusal: Some("incomplete".into()),
            expected_answer: None,
            shadow_model_answer: None,
        },
        LookupFixtureCase {
            id: "resolve_ref_cross_namespace_deny".into(),
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({"object_id": "other-ns-object"}),
            expected_path: ANSWER_PATH_MODEL.into(),
            expected_refusal: Some("cross_namespace".into()),
            expected_answer: None,
            shadow_model_answer: None,
        },
        LookupFixtureCase {
            id: "resolve_ref_acl_denied_fallback".into(),
            capability: semantic::CAPABILITY_RESOLVE_REF.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({"object_id": "acl-denied"}),
            expected_path: ANSWER_PATH_MODEL.into(),
            expected_refusal: Some("acl_denied".into()),
            expected_answer: None,
            shadow_model_answer: None,
        },
    ]
}

/// Built-in S2 fixture definitions for complete retrieval-shaped answers.
///
/// Every newly short-circuitable capability has at least one complete hit and
/// one fail-closed model-path case. The negative explain case is intentional:
/// a complete, authorized `found=false` result is still a structured hit.
pub fn s2_fixture_cases() -> Vec<LookupFixtureCase> {
    let expand_golden = s2_expand_golden_answer();
    let retrieve_golden = s2_retrieve_golden_answer();
    let explain_golden = s2_explain_golden_answer();
    let explain_negative_golden = s2_explain_negative_golden_answer();
    vec![
        LookupFixtureCase {
            id: "expand_relations_hit".into(),
            capability: semantic::CAPABILITY_EXPAND_RELATIONS.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "root": {"object_id": "lookup-root"},
                "direction": "outgoing",
                "max_depth": 1
            }),
            expected_path: ANSWER_PATH_LOOKUP_HIT.into(),
            expected_refusal: None,
            expected_answer: Some(expand_golden.clone()),
            shadow_model_answer: Some(expand_golden),
        },
        LookupFixtureCase {
            id: "expand_relations_truncated_fallback".into(),
            capability: semantic::CAPABILITY_EXPAND_RELATIONS.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "root": {"object_id": "lookup-root"},
                "direction": "outgoing",
                "max_depth": 1,
                "max_objects": 1
            }),
            expected_path: ANSWER_PATH_MODEL.into(),
            expected_refusal: Some("truncated".into()),
            expected_answer: None,
            shadow_model_answer: None,
        },
        LookupFixtureCase {
            id: "retrieve_context_hit".into(),
            capability: semantic::CAPABILITY_RETRIEVE_CONTEXT.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "roots": [{"object_id": "lookup-root"}],
                "direction": "outgoing",
                "max_depth": 1
            }),
            expected_path: ANSWER_PATH_LOOKUP_HIT.into(),
            expected_refusal: None,
            expected_answer: Some(retrieve_golden.clone()),
            shadow_model_answer: Some(retrieve_golden),
        },
        LookupFixtureCase {
            id: "retrieve_context_acl_fallback".into(),
            capability: semantic::CAPABILITY_RETRIEVE_CONTEXT.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "roots": [{"object_id": "acl-denied"}],
                "max_depth": 0
            }),
            expected_path: ANSWER_PATH_MODEL.into(),
            expected_refusal: Some("acl_denied".into()),
            expected_answer: None,
            shadow_model_answer: None,
        },
        LookupFixtureCase {
            id: "explain_derivation_hit".into(),
            capability: semantic::CAPABILITY_EXPLAIN_DERIVATION.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "from": {"object_id": "lookup-root"},
                "to": {"object_id": "lookup-child"},
                "direction": "outgoing",
                "max_depth": 1
            }),
            expected_path: ANSWER_PATH_LOOKUP_HIT.into(),
            expected_refusal: None,
            expected_answer: Some(explain_golden.clone()),
            shadow_model_answer: Some(explain_golden),
        },
        LookupFixtureCase {
            id: "explain_derivation_missing_root_fallback".into(),
            capability: semantic::CAPABILITY_EXPLAIN_DERIVATION.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "from": {"object_id": "does-not-exist"},
                "to": {"object_id": "lookup-child"}
            }),
            expected_path: ANSWER_PATH_MODEL.into(),
            expected_refusal: Some("incomplete".into()),
            expected_answer: None,
            shadow_model_answer: None,
        },
        LookupFixtureCase {
            id: "explain_derivation_acl_target_fallback".into(),
            capability: semantic::CAPABILITY_EXPLAIN_DERIVATION.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "from": {"object_id": "lookup-root"},
                "to": {"object_id": "acl-denied"}
            }),
            expected_path: ANSWER_PATH_MODEL.into(),
            expected_refusal: Some("incomplete".into()),
            expected_answer: None,
            shadow_model_answer: None,
        },
        LookupFixtureCase {
            id: "explain_derivation_complete_negative_hit".into(),
            capability: semantic::CAPABILITY_EXPLAIN_DERIVATION.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "from": {"object_id": "lookup-root"},
                "to": {"object_id": "lookup-unrelated"}
            }),
            expected_path: ANSWER_PATH_LOOKUP_HIT.into(),
            expected_refusal: None,
            expected_answer: Some(explain_negative_golden.clone()),
            shadow_model_answer: Some(explain_negative_golden),
        },
        LookupFixtureCase {
            id: "explain_derivation_missing_target_fallback".into(),
            capability: semantic::CAPABILITY_EXPLAIN_DERIVATION.into(),
            namespace: "acme".into(),
            actor: "alice".into(),
            input: json!({
                "from": {"object_id": "lookup-root"},
                "to": {"object_id": "does-not-exist"}
            }),
            expected_path: ANSWER_PATH_MODEL.into(),
            expected_refusal: Some("incomplete".into()),
            expected_answer: None,
            shadow_model_answer: None,
        },
    ]
}

fn s2_descriptor(source_refs: &[&str]) -> Value {
    json!({
        "confidence_basis": null,
        "contract_version": EPISTEMIC_DESCRIPTOR_VERSION,
        "contradicting_evidence_count": null,
        "derivation_ref": null,
        "evidence_status": "unknown",
        "lifecycle_status": "current",
        "observed_at_ms": null,
        "origin_class": "asserted",
        "producer_confidence_bps": null,
        "source_digests": [],
        "source_refs": source_refs,
        "source_row_count": source_refs.len(),
        "source_rows_truncated": false,
        "supporting_evidence_count": null
    })
}

fn s2_candidate(
    object_id: &str,
    depth: u32,
    affinity: f64,
    via_relation: &str,
    source_refs: &[&str],
    steps: Value,
) -> Value {
    let color = if object_id == "lookup-root" {
        "red"
    } else {
        "blue"
    };
    let external_id = format!("widget:{object_id}");
    json!({
        "affinity": affinity,
        "depth": depth,
        "descriptor": s2_descriptor(source_refs),
        "explanation": {
            "derived": false,
            "ontology_revision": "",
            "source_fact_ids": source_refs,
            "steps": steps
        },
        "object": {
            "created": 1_700_000_000_000i64,
            "external_id": external_id,
            "id": object_id,
            "kind": "widget",
            "name": object_id,
            "namespace": "acme",
            "properties": {"color": color, "name": object_id},
            "updated": 1_700_000_000_000i64
        },
        "via_relation": via_relation
    })
}

fn s2_root_candidate() -> Value {
    s2_candidate(
        "lookup-root",
        0,
        1.0,
        "",
        &["lookup-root"],
        json!([{
            "from_id": "lookup-root",
            "kind": "asserted",
            "ontology_revision": "",
            "relation": "",
            "rule": "root",
            "source_fact_ids": ["lookup-root"],
            "to_id": "lookup-root"
        }]),
    )
}

fn s2_child_candidate() -> Value {
    s2_candidate(
        "lookup-child",
        1,
        0.5,
        "contains",
        &["lookup-link-contains"],
        json!([{
            "from_id": "lookup-root",
            "kind": "asserted",
            "ontology_revision": "",
            "relation": "contains",
            "rule": "graph_link",
            "source_fact_ids": ["lookup-link-contains"],
            "to_id": "lookup-child"
        }]),
    )
}

fn s2_links() -> Value {
    json!([{
        "created": 1_700_000_000_000i64,
        "from_id": "lookup-root",
        "id": "lookup-link-contains",
        "relation": "contains",
        "to_id": "lookup-child"
    }])
}

fn s2_expand_golden_answer() -> Value {
    json!({
        "candidates": [s2_root_candidate(), s2_child_candidate()],
        "denied_objects": 0,
        "derived_rows": 0,
        "epistemic_descriptor_version": EPISTEMIC_DESCRIPTOR_VERSION,
        "links": s2_links(),
        "ontology_revision": "",
        "reasoning_mode": "asserted_only",
        "source_rows": 1,
        "truncated": false,
        "truncated_links": 0,
        "truncated_objects": 0,
        "truncation_reasons": [],
        "unresolved_roots": 0
    })
}

fn s2_retrieve_golden_answer() -> Value {
    json!({
        "candidates": [s2_root_candidate(), s2_child_candidate()],
        "denied_objects": 0,
        "derived_rows": 0,
        "epistemic_descriptor_version": EPISTEMIC_DESCRIPTOR_VERSION,
        "links": s2_links(),
        "ontology_revision": "",
        "source_rows": 1,
        "truncated": false,
        "truncated_links": 0,
        "truncated_objects": 0,
        "truncation_reasons": [],
        "unresolved_roots": 0
    })
}

fn s2_explain_golden_answer() -> Value {
    json!({
        "descriptor": s2_descriptor(&["lookup-link-contains"]),
        "evidence_refs": ["lookup-link-contains"],
        "explanation": {
            "derived": false,
            "ontology_revision": "",
            "source_fact_ids": ["lookup-link-contains"],
            "steps": [{
                "from_id": "lookup-root",
                "kind": "asserted",
                "ontology_revision": "",
                "relation": "contains",
                "rule": "graph_link",
                "source_fact_ids": ["lookup-link-contains"],
                "to_id": "lookup-child"
            }]
        },
        "found": true,
        "ontology_revision": "",
        "reasoning_mode": "asserted_only",
        "truncated": false,
        "truncation_reasons": []
    })
}

fn s2_explain_negative_golden_answer() -> Value {
    json!({
        "descriptor": null,
        "evidence_refs": [],
        "explanation": null,
        "found": false,
        "ontology_revision": "",
        "reasoning_mode": "asserted_only",
        "truncated": false,
        "truncation_reasons": []
    })
}

/// Seed the graph state required by [`s1_fixture_cases`].
pub fn seed_s1_fixture_graph(db: &RuntimeDb) -> Result<(), String> {
    use crate::domain::{Link, Object};
    use crate::sekai::security::{Grant, Role};
    use std::collections::HashMap;

    let now = 1_700_000_000_000i64;
    for (id, external_id, namespace, props) in [
        (
            "lookup-root",
            "widget:lookup-root",
            "acme",
            HashMap::from([
                ("name".into(), "lookup-root".into()),
                ("color".into(), "red".into()),
            ]),
        ),
        (
            "lookup-child",
            "widget:lookup-child",
            "acme",
            HashMap::from([
                ("name".into(), "lookup-child".into()),
                ("color".into(), "blue".into()),
            ]),
        ),
        (
            "lookup-unrelated",
            "widget:lookup-unrelated",
            "acme",
            HashMap::from([("name".into(), "lookup-unrelated".into())]),
        ),
        (
            "other-ns-object",
            "widget:other",
            "other",
            HashMap::from([("name".into(), "other".into())]),
        ),
        (
            "acl-denied",
            "widget:acl-denied",
            "acme",
            HashMap::from([("name".into(), "acl-denied".into())]),
        ),
    ] {
        let object = Object {
            id: id.into(),
            kind: "widget".into(),
            name: id.into(),
            namespace: namespace.into(),
            external_id: external_id.into(),
            properties: props,
            created: now,
            updated: now,
        };
        db.create_object(&object)?;
    }
    // Restrict acl-denied so only bob can read it.
    db.create_grant(&Grant {
        id: "grant-acl-denied-bob".into(),
        object_id: "acl-denied".into(),
        principal: "bob".into(),
        role: Role::Viewer,
        created: now,
    })?;
    db.create_link(&Link {
        id: "lookup-link-contains".into(),
        from_id: "lookup-root".into(),
        to_id: "lookup-child".into(),
        relation: "contains".into(),
        created: now,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;

    #[test]
    fn allowlist_matches_151_surfaces_only() {
        assert!(is_lookup_first_capability(semantic::CAPABILITY_RESOLVE_REF));
        assert!(is_lookup_first_capability(
            semantic::CAPABILITY_EXPAND_RELATIONS
        ));
        assert!(is_lookup_first_capability(
            semantic::CAPABILITY_RETRIEVE_CONTEXT
        ));
        assert!(is_lookup_first_capability(
            semantic::CAPABILITY_EXPLAIN_DERIVATION
        ));
        assert!(!is_lookup_first_capability("free.form.nl.question"));
        assert!(!is_lookup_first_capability(""));
    }

    #[test]
    fn s1_fixture_suite_hit_incomplete_and_cross_namespace() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        let report = run_fixture_suite("s1-lookup-first", &s1_fixture_cases(), &db);
        assert_eq!(report.failed, 0, "{report:?}");
        assert_eq!(report.lookup_hits, 1);
        assert_eq!(report.model_path, 3);
        assert_eq!(report.lookup_refusals, 3);
        assert_eq!(report.passed, 4);
        let by_id: BTreeMap<_, _> = report
            .cases
            .iter()
            .map(|case| (case.id.as_str(), case))
            .collect();
        assert_eq!(by_id["resolve_ref_hit"].answer_path, ANSWER_PATH_LOOKUP_HIT);
        assert_eq!(
            by_id["resolve_ref_incomplete_fallback"]
                .lookup_refusal
                .as_deref(),
            Some("incomplete")
        );
        assert_eq!(
            by_id["resolve_ref_cross_namespace_deny"]
                .lookup_refusal
                .as_deref(),
            Some("cross_namespace")
        );
        assert_eq!(
            by_id["resolve_ref_acl_denied_fallback"]
                .lookup_refusal
                .as_deref(),
            Some("acl_denied")
        );
    }

    #[test]
    fn s2_fixture_suite_covers_hits_and_fail_closed_paths() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        let report = run_fixture_suite("s2-lookup-first", &s2_fixture_cases(), &db);
        assert_eq!(report.failed, 0, "{report:?}");
        assert_eq!(report.lookup_hits, 4);
        assert_eq!(report.model_path, 5);
        assert_eq!(report.lookup_refusals, 5);
        assert_eq!(report.passed, 9);
    }

    #[test]
    fn s2_answers_match_native_retrieval_shapes_and_zero_provider_fields() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");

        let expand = try_lookup_first(
            semantic::CAPABILITY_EXPAND_RELATIONS,
            "acme",
            "alice",
            r#"{"root":{"object_id":"lookup-root"},"direction":"outgoing","max_depth":1}"#,
            &db,
        )
        .expect("expand lookup");
        let retrieve = try_lookup_first(
            semantic::CAPABILITY_RETRIEVE_CONTEXT,
            "acme",
            "alice",
            r#"{"roots":[{"object_id":"lookup-root"}],"direction":"outgoing","max_depth":1}"#,
            &db,
        )
        .expect("retrieve lookup");
        let explain = try_lookup_first(
            semantic::CAPABILITY_EXPLAIN_DERIVATION,
            "acme",
            "alice",
            r#"{"from":{"object_id":"lookup-root"},"to":{"object_id":"lookup-child"},"direction":"outgoing","max_depth":1}"#,
            &db,
        )
        .expect("explain lookup");

        let answer = |decision: LookupDecision| match decision {
            LookupDecision::Hit {
                answer_json,
                provenance,
                ..
            } => {
                let value: Value = serde_json::from_str(&answer_json).expect("structured JSON");
                assert!(value.get("input_tokens").is_none());
                assert!(value.get("output_tokens").is_none());
                assert!(!provenance.is_empty());
                value
            }
            other => panic!("expected lookup hit, got {other:?}"),
        };

        let expand = answer(expand);
        assert_eq!(expand["reasoning_mode"], "asserted_only");
        assert_eq!(
            expand["epistemic_descriptor_version"],
            EPISTEMIC_DESCRIPTOR_VERSION
        );
        assert_eq!(expand["candidates"][0]["object"]["id"], "lookup-root");
        assert_eq!(expand["links"][0]["id"], "lookup-link-contains");

        let retrieve = answer(retrieve);
        assert_eq!(
            retrieve["epistemic_descriptor_version"],
            EPISTEMIC_DESCRIPTOR_VERSION
        );
        assert_eq!(retrieve["candidates"][1]["object"]["id"], "lookup-child");

        let explain = answer(explain);
        assert_eq!(explain["found"], true);
        assert_eq!(explain["explanation"]["steps"][0]["relation"], "contains");
        assert_eq!(explain["reasoning_mode"], "asserted_only");
    }

    #[test]
    fn explain_complete_negative_is_a_structured_lookup_hit() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        let decision = try_lookup_first(
            semantic::CAPABILITY_EXPLAIN_DERIVATION,
            "acme",
            "alice",
            r#"{"from":{"object_id":"lookup-root"},"to":{"object_id":"lookup-unrelated"}}"#,
            &db,
        )
        .expect("explain lookup");
        match decision {
            LookupDecision::Hit { answer_json, .. } => {
                let value: Value = serde_json::from_str(&answer_json).unwrap();
                assert_eq!(value["found"], false);
                assert!(value["explanation"].is_null());
            }
            other => panic!("expected complete negative hit, got {other:?}"),
        }
    }

    #[test]
    fn s2_rejects_unknown_and_capability_crossed_fields() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        for (capability, spec) in [
            (
                semantic::CAPABILITY_EXPAND_RELATIONS,
                r#"{"root":{"object_id":"lookup-root"},"unexpected":"ignored?"}"#,
            ),
            (
                semantic::CAPABILITY_RETRIEVE_CONTEXT,
                r#"{"roots":[{"object_id":"lookup-root"}],"root":{"object_id":"lookup-root"}}"#,
            ),
            (
                semantic::CAPABILITY_EXPLAIN_DERIVATION,
                r#"{"from":{"object_id":"lookup-root"},"to":{"object_id":"lookup-child"},"kind_filter":["widget"]}"#,
            ),
        ] {
            match try_lookup_first(capability, "acme", "alice", spec, &db).unwrap() {
                LookupDecision::Refusal { reason, .. } => assert_eq!(reason, "schema_miss"),
                other => panic!("expected schema refusal for {capability}, got {other:?}"),
            }
        }
    }

    #[test]
    fn full_hit_has_zero_provider_token_fields_in_answer_envelope() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        let decision = try_lookup_first(
            semantic::CAPABILITY_RESOLVE_REF,
            "acme",
            "alice",
            r#"{"external_id":"widget:lookup-root"}"#,
            &db,
        )
        .unwrap();
        match decision {
            LookupDecision::Hit { answer_json, .. } => {
                let value: Value = serde_json::from_str(&answer_json).unwrap();
                assert_eq!(value["resolved"], true);
                assert!(value.get("input_tokens").is_none());
                assert!(value.get("output_tokens").is_none());
            }
            other => panic!("expected hit, got {other:?}"),
        }
    }

    #[test]
    fn dual_run_shadow_flags_structural_mismatch() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        let mut cases = s1_fixture_cases();
        cases[0].shadow_model_answer = Some(json!({"resolved": false, "wrong": true}));
        let report = run_fixture_suite("shadow-mismatch", &cases[..1], &db);
        assert_eq!(report.failed, 1);
        assert!(
            report.cases[0]
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("dual-run")
        );
    }

    fn promotion_suite_from_fixture_cases(
        cases: Vec<LookupFixtureCase>,
    ) -> LookupPromotionGateSuite {
        LookupPromotionGateSuite {
            contract_version: LOOKUP_FIRST_GATE_CONTRACT_VERSION.into(),
            suite_id: "lookup-first-v1".into(),
            namespace: "acme".into(),
            cases: cases
                .into_iter()
                .map(|case| LookupPromotionGateCase {
                    id: case.id,
                    capability: case.capability,
                    namespace: case.namespace,
                    actor: case.actor,
                    input: case.input,
                    expected_path: case.expected_path,
                    expected_refusal: case.expected_refusal,
                    expected_answer: case.expected_answer,
                })
                .collect(),
        }
    }

    #[test]
    fn lookup_promotion_suite_rejects_free_form_and_shadow_fields() {
        let free_form = serde_json::json!({
            "contract_version": LOOKUP_FIRST_GATE_CONTRACT_VERSION,
            "suite_id": "suite",
            "namespace": "acme",
            "cases": [{
                "id": "free-form",
                "capability": semantic::CAPABILITY_RESOLVE_REF,
                "namespace": "acme",
                "actor": "alice",
                "input": "resolve this",
                "expected_path": ANSWER_PATH_LOOKUP_HIT,
                "expected_answer": {}
            }]
        });
        let error = parse_lookup_promotion_gate_suite(&free_form.to_string()).unwrap_err();
        assert!(error.contains("structured JSON object"), "{error}");

        let shadow = serde_json::json!({
            "contract_version": LOOKUP_FIRST_GATE_CONTRACT_VERSION,
            "suite_id": "suite",
            "namespace": "acme",
            "cases": [{
                "id": "shadow",
                "capability": semantic::CAPABILITY_RESOLVE_REF,
                "namespace": "acme",
                "actor": "alice",
                "input": {"object_id": "lookup-root"},
                "expected_path": ANSWER_PATH_LOOKUP_HIT,
                "expected_answer": {},
                "shadow_model_answer": {}
            }]
        });
        let error = parse_lookup_promotion_gate_suite(&shadow.to_string()).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn lookup_promotion_gate_passes_and_records_bounded_audit() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        let suite = promotion_suite_from_fixture_cases(s1_fixture_cases());
        let report = run_lookup_promotion_gate(&suite, &db).expect("gate");
        assert_eq!(report.verdict, "allow");
        assert_eq!(report.failed, 0);
        assert!(report.suite_digest.starts_with("sha256:"));

        let decision_id = record_lookup_promotion_gate(&db, "alice", &report).expect("audit");
        let decision = db.get_decision(&decision_id).expect("read audit").unwrap();
        assert_eq!(decision.action, LOOKUP_FIRST_GATE_AUDIT_ACTION);
        assert_eq!(decision.outcome, "allow");
        assert_eq!(decision.evidence["failed"], "0");
        assert!(!decision.evidence.contains_key("answer_json"));
    }

    #[test]
    fn checked_in_lookup_promotion_suite_executes_offline() {
        let raw = include_str!("../../tests/fixtures/lookup_first/promotion-gate-v1.json");
        let suite = parse_lookup_promotion_gate_suite(raw).expect("promotion gate fixture");
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        let report = run_lookup_promotion_gate(&suite, &db).expect("offline gate");
        assert_eq!(report.verdict, "allow", "{report:?}");
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 0);
    }

    #[test]
    fn lookup_promotion_gate_denies_on_golden_mismatch_without_policy_effect() {
        let db = RuntimeDb::memory();
        seed_s1_fixture_graph(&db).expect("seed");
        let mut cases = s1_fixture_cases();
        cases[0].expected_answer = Some(json!({"resolved": false}));
        let suite = promotion_suite_from_fixture_cases(cases);
        let report = run_lookup_promotion_gate(&suite, &db).expect("gate");
        assert_eq!(report.verdict, "deny");
        assert_eq!(report.failed, 1);
        assert_eq!(report.cases[0].answer_path, ANSWER_PATH_LOOKUP_HIT);
        assert!(!report.cases[0].passed);
        let decision_id = record_lookup_promotion_gate(&db, "alice", &report).expect("audit");
        let decision = db.get_decision(&decision_id).expect("read audit").unwrap();
        assert_eq!(decision.outcome, "deny");
        assert!(
            decision
                .reason
                .contains("prior route policy remains unchanged")
        );
    }
}
