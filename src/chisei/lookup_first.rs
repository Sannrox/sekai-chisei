//! Lookup-first governed answers for allow-listed structured capabilities (#281 / S1).
//!
//! When a PlanExecution/ExecutePlan request targets an allow-listed #151 semantic
//! capability with a fixed structured contract, Chisei attempts an authorized
//! ontology/graph lookup **after** namespace authz and **before** provider
//! routing. A complete hit returns a normal response with **zero provider
//! tokens**. Incomplete graph state or ACL misses fail closed to the model path
//! and record `lookup_refusal` on the operation receipt.
//!
//! Scope (maintainer decision S1):
//! - Narrow allow-listed structured capabilities only (no free-form NL).
//! - Fixture suite + dual-run/shadow structural equality where practical.
//! - No fleet-wide spend-% claim.

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::semantic;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// S1 allow-list: fixed #151 semantic capability contracts only.
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
        // Expand / retrieve / explain are allow-listed for identification and
        // fixture documentation. S1 short-circuits only resolve_ref fully;
        // other shapes refuse closed so callers take the model path with an
        // explicit reason rather than inventing free-form answers.
        semantic::CAPABILITY_EXPAND_RELATIONS
        | semantic::CAPABILITY_RETRIEVE_CONTEXT
        | semantic::CAPABILITY_EXPLAIN_DERIVATION => Ok(LookupDecision::Refusal {
            capability: capability.into(),
            reason: "capability_not_short_circuitable_in_s1".into(),
        }),
        _ => Ok(LookupDecision::NotEligible),
    }
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

/// Run the S1 fixture suite against a prepared database.
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

/// Seed the graph state required by [`s1_fixture_cases`].
pub fn seed_s1_fixture_graph(db: &RuntimeDb) -> Result<(), String> {
    use crate::domain::Object;
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
        assert!(!is_lookup_first_capability(
            semantic::CAPABILITY_EVALUATE_SCENARIO
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
}
