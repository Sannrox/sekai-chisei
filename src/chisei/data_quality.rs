//! Content-bound data-quality rules and results (#681).

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::audit::Decision;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const RULE_CONTRACT: &str = "chisei.data-quality-rule/v1";
pub const RESULT_CONTRACT: &str = "chisei.data-quality-result/v1";
pub const POSTGRES_UNAVAILABLE: &str =
    "data quality rules are unavailable on the PostgreSQL community runtime";
pub const UNAVAILABLE: &str = "data quality identity is unavailable";

pub const EVALUATOR_DIGEST_PIN: &str = "digest_pin";
pub const EVALUATOR_COMPLETENESS: &str = "completeness";
pub const EVALUATOR_ROW_COUNT: &str = "row_count_bound";

pub const STATUS_PASS: &str = "pass";
pub const STATUS_FAIL: &str = "fail";
pub const STATUS_MISSING: &str = "missing";
pub const STATUS_INVALID: &str = "invalid";
pub const STATUS_UNAVAILABLE: &str = "unavailable";
pub const STATUS_UNKNOWN: &str = "unknown";
pub const STATUS_RUNNING: &str = "running";
pub const STATUS_CANCELLED: &str = "cancelled";

pub const POPULATION_COMPLETE: &str = "complete";
pub const POPULATION_MISSING: &str = "missing";
pub const POPULATION_PARTIAL: &str = "partial";

const KIND_DATASET: &str = "dataset";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataQualityRule {
    pub contract_version: String,
    pub rule_id: String,
    pub namespace: String,
    pub dataset_id: String,
    pub evaluator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_digest: Option<String>,
    pub rule_digest: String,
    pub write_authority: bool,
    pub permit_authority: bool,
    pub published_by: String,
    pub published_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataQualityResult {
    pub contract_version: String,
    pub result_id: String,
    pub namespace: String,
    pub rule_id: String,
    pub rule_digest: String,
    pub evaluator: String,
    pub evaluator_digest: String,
    pub dataset_id: String,
    pub dataset_revision_digest: String,
    pub evidence_receipt_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_receipt_digest: Option<String>,
    pub population: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_digest: Option<String>,
    pub status: String,
    pub write_authority: bool,
    pub permit_authority: bool,
    pub evaluated_by: String,
    pub evaluated_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct PublishDataQualityRule {
    pub namespace: String,
    pub rule_id: String,
    pub dataset_id: String,
    pub evaluator: String,
    pub expected_digest: Option<String>,
    pub required_fields: Vec<String>,
    pub min_rows: Option<i64>,
    pub max_rows: Option<i64>,
    pub baseline_digest: Option<String>,
}

pub fn publish_rule(
    db: &RuntimeDb,
    actor: &str,
    request: &PublishDataQualityRule,
    now_ms: i64,
) -> Result<DataQualityRule, String> {
    required("actor", actor)?;
    required("namespace", &request.namespace)?;
    required("rule id", &request.rule_id)?;
    required("dataset id", &request.dataset_id)?;
    if now_ms < 0 {
        return Err("publish timestamp must be non-negative".into());
    }
    let evaluator = parse_evaluator(&request.evaluator)?;
    match evaluator {
        EVALUATOR_DIGEST_PIN => {
            let digest = request
                .expected_digest
                .as_deref()
                .ok_or_else(|| "digest_pin requires expected_digest".to_string())?;
            validate_digest("expected_digest", digest)?;
        }
        EVALUATOR_COMPLETENESS => {
            if request.required_fields.is_empty() {
                return Err("completeness requires required_fields".into());
            }
            for field in &request.required_fields {
                required("required field", field)?;
            }
        }
        EVALUATOR_ROW_COUNT => {
            if request.min_rows.is_none() && request.max_rows.is_none() {
                return Err("row_count_bound requires min_rows or max_rows".into());
            }
            if let (Some(min), Some(max)) = (request.min_rows, request.max_rows)
                && min > max
            {
                return Err("row_count_bound min_rows must not exceed max_rows".into());
            }
        }
        _ => return Err(STATUS_UNKNOWN.into()),
    }
    if let Some(baseline) = request.baseline_digest.as_deref() {
        validate_digest("baseline_digest", baseline)?;
    }
    let mut rule = DataQualityRule {
        contract_version: RULE_CONTRACT.into(),
        rule_id: request.rule_id.clone(),
        namespace: request.namespace.clone(),
        dataset_id: request.dataset_id.clone(),
        evaluator: evaluator.into(),
        expected_digest: request.expected_digest.clone(),
        required_fields: request.required_fields.clone(),
        min_rows: request.min_rows,
        max_rows: request.max_rows,
        baseline_digest: request.baseline_digest.clone(),
        rule_digest: String::new(),
        write_authority: false,
        permit_authority: false,
        published_by: actor.into(),
        published_at_ms: now_ms,
    };
    rule.rule_digest = rule_digest(&rule)?;
    if let Some(existing) = db.get_data_quality_rule(&request.namespace, &request.rule_id)?
        && existing.rule_digest == rule.rule_digest
    {
        return Ok(existing);
    }
    db.put_data_quality_rule(&rule)?;
    audit(
        db,
        actor,
        "data_quality.rule_publish",
        "published",
        &rule.namespace,
        &rule.rule_id,
        &rule.rule_digest,
        now_ms,
    )?;
    Ok(rule)
}

pub fn start_evaluation(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    rule_id: &str,
    pinned_rule_digest: Option<&str>,
    now_ms: i64,
) -> Result<DataQualityResult, String> {
    let (rule, dataset, revision) =
        prepare_evaluation(db, actor, namespace, rule_id, pinned_rule_digest)?;
    let result_id = result_id_for(namespace, &rule.rule_digest, &revision);
    if let Some(existing) = db.get_data_quality_result(&result_id)? {
        return Ok(existing);
    }
    let running = DataQualityResult {
        contract_version: RESULT_CONTRACT.into(),
        result_id,
        namespace: namespace.into(),
        rule_id: rule.rule_id.clone(),
        rule_digest: rule.rule_digest.clone(),
        evaluator: rule.evaluator.clone(),
        evaluator_digest: evaluator_digest(&rule.evaluator),
        dataset_id: rule.dataset_id.clone(),
        dataset_revision_digest: revision,
        evidence_receipt_digest: String::new(),
        prior_receipt_digest: None,
        population: if dataset.is_some() {
            POPULATION_COMPLETE
        } else {
            POPULATION_MISSING
        }
        .into(),
        baseline_digest: rule.baseline_digest.clone(),
        status: STATUS_RUNNING.into(),
        write_authority: false,
        permit_authority: false,
        evaluated_by: actor.into(),
        evaluated_at_ms: now_ms,
    };
    db.put_data_quality_result(&running)?;
    Ok(running)
}

pub fn evaluate_rule(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    rule_id: &str,
    pinned_rule_digest: Option<&str>,
    now_ms: i64,
) -> Result<DataQualityResult, String> {
    let started = start_evaluation(db, actor, namespace, rule_id, pinned_rule_digest, now_ms)?;
    if is_closed(&started.status) {
        return Ok(started);
    }
    finish_evaluation(db, actor, &started.result_id, now_ms)
}

pub fn cancel_evaluation(
    db: &RuntimeDb,
    actor: &str,
    result_id: &str,
    now_ms: i64,
) -> Result<DataQualityResult, String> {
    required("actor", actor)?;
    required("result id", result_id)?;
    let mut record = db
        .get_data_quality_result(result_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    if is_closed(&record.status) {
        return Err("closed data quality receipt is immutable".into());
    }
    record.status = STATUS_CANCELLED.into();
    record.evaluated_by = actor.into();
    record.evaluated_at_ms = now_ms;
    record.evidence_receipt_digest = receipt_digest(&record)?;
    db.put_data_quality_result(&record)?;
    audit(
        db,
        actor,
        "data_quality.result_cancel",
        STATUS_CANCELLED,
        &record.namespace,
        &record.rule_id,
        &record.result_id,
        now_ms,
    )?;
    Ok(record)
}

pub fn restart_evaluation(
    db: &RuntimeDb,
    actor: &str,
    result_id: &str,
    now_ms: i64,
) -> Result<DataQualityResult, String> {
    required("actor", actor)?;
    required("result id", result_id)?;
    let existing = db
        .get_data_quality_result(result_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    if is_closed(&existing.status) {
        return Err("closed data quality receipt is immutable".into());
    }
    finish_evaluation(db, actor, result_id, now_ms)
}

pub fn show_rule(
    db: &RuntimeDb,
    namespace: &str,
    rule_id: &str,
) -> Result<DataQualityRule, String> {
    required("namespace", namespace)?;
    required("rule id", rule_id)?;
    db.get_data_quality_rule(namespace, rule_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())
}

pub fn list_rules(db: &RuntimeDb, namespace: Option<&str>) -> Result<Vec<DataQualityRule>, String> {
    db.list_data_quality_rules(namespace)
}

pub fn show_result(db: &RuntimeDb, result_id: &str) -> Result<DataQualityResult, String> {
    required("result id", result_id)?;
    db.get_data_quality_result(result_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())
}

pub fn list_results(
    db: &RuntimeDb,
    namespace: Option<&str>,
) -> Result<Vec<DataQualityResult>, String> {
    db.list_data_quality_results(namespace)
}

fn finish_evaluation(
    db: &RuntimeDb,
    actor: &str,
    result_id: &str,
    now_ms: i64,
) -> Result<DataQualityResult, String> {
    let mut record = db
        .get_data_quality_result(result_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    if is_closed(&record.status) {
        return Ok(record);
    }
    let prior = if record.status == STATUS_CANCELLED {
        Some(record.evidence_receipt_digest.clone()).filter(|value| !value.is_empty())
    } else {
        None
    };
    let rule = db
        .get_data_quality_rule(&record.namespace, &record.rule_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    if rule.rule_digest != record.rule_digest {
        record.status = STATUS_UNKNOWN.into();
        record.population = POPULATION_MISSING.into();
    } else {
        let dataset = authorized_dataset(db, actor, &rule.namespace, &rule.dataset_id)?;
        apply_evaluator(&rule, dataset.as_ref(), &mut record);
    }
    record.prior_receipt_digest = prior;
    record.evaluated_by = actor.into();
    record.evaluated_at_ms = now_ms;
    record.evidence_receipt_digest = receipt_digest(&record)?;
    db.put_data_quality_result(&record)?;
    audit(
        db,
        actor,
        "data_quality.result_evaluate",
        &record.status,
        &record.namespace,
        &record.rule_id,
        &record.result_id,
        now_ms,
    )?;
    Ok(record)
}

fn prepare_evaluation(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    rule_id: &str,
    pinned_rule_digest: Option<&str>,
) -> Result<(DataQualityRule, Option<Object>, String), String> {
    required("actor", actor)?;
    required("namespace", namespace)?;
    required("rule id", rule_id)?;
    let rule = db
        .get_data_quality_rule(namespace, rule_id)?
        .ok_or_else(|| UNAVAILABLE.to_string())?;
    if let Some(pinned) = pinned_rule_digest.filter(|value| !value.is_empty()) {
        validate_digest("rule_digest", pinned)?;
        if pinned != rule.rule_digest {
            return Err(STATUS_UNKNOWN.into());
        }
    }
    let dataset = authorized_dataset(db, actor, namespace, &rule.dataset_id)?;
    let revision = match &dataset {
        Some(object) => dataset_revision_digest(object)?,
        None => missing_revision_digest(namespace, &rule.dataset_id),
    };
    Ok((rule, dataset, revision))
}

fn apply_evaluator(
    rule: &DataQualityRule,
    dataset: Option<&Object>,
    record: &mut DataQualityResult,
) {
    match rule.evaluator.as_str() {
        EVALUATOR_DIGEST_PIN => match dataset {
            None => {
                record.status = STATUS_MISSING.into();
                record.population = POPULATION_MISSING.into();
            }
            Some(object) => {
                let actual = dataset_revision_digest(object).unwrap_or_default();
                let expected = rule.expected_digest.clone().unwrap_or_default();
                record.population = POPULATION_COMPLETE.into();
                record.status = if actual == expected {
                    STATUS_PASS
                } else {
                    STATUS_FAIL
                }
                .into();
            }
        },
        EVALUATOR_COMPLETENESS => match dataset {
            None => {
                record.status = STATUS_MISSING.into();
                record.population = POPULATION_MISSING.into();
            }
            Some(object) => {
                let present = rule
                    .required_fields
                    .iter()
                    .filter(|field| {
                        object
                            .properties
                            .get(*field)
                            .is_some_and(|value| !value.trim().is_empty())
                    })
                    .count();
                if present == 0 {
                    record.population = POPULATION_MISSING.into();
                    record.status = STATUS_FAIL.into();
                } else if present < rule.required_fields.len() {
                    record.population = POPULATION_PARTIAL.into();
                    record.status = STATUS_FAIL.into();
                } else {
                    record.population = POPULATION_COMPLETE.into();
                    record.status = STATUS_PASS.into();
                }
            }
        },
        EVALUATOR_ROW_COUNT => match dataset {
            None => {
                record.status = STATUS_MISSING.into();
                record.population = POPULATION_MISSING.into();
            }
            Some(object) => match object.properties.get("row_count") {
                None => {
                    record.population = POPULATION_MISSING.into();
                    record.status = STATUS_INVALID.into();
                }
                Some(raw) => match raw.parse::<i64>() {
                    Ok(count) => {
                        let min_ok = rule.min_rows.is_none_or(|min| count >= min);
                        let max_ok = rule.max_rows.is_none_or(|max| count <= max);
                        record.population = POPULATION_COMPLETE.into();
                        record.status = if min_ok && max_ok {
                            STATUS_PASS
                        } else {
                            STATUS_FAIL
                        }
                        .into();
                    }
                    Err(_) => {
                        record.population = POPULATION_PARTIAL.into();
                        record.status = STATUS_INVALID.into();
                    }
                },
            },
        },
        _ => {
            record.status = STATUS_UNKNOWN.into();
            record.population = POPULATION_MISSING.into();
        }
    }
}

fn authorized_dataset(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    dataset_id: &str,
) -> Result<Option<Object>, String> {
    let object_id = dataset_object_id(namespace, dataset_id);
    match db.get_object(&object_id)? {
        Some(object)
            if object.namespace == namespace
                && object.kind == KIND_DATASET
                && object.name == dataset_id =>
        {
            let _ = actor;
            Ok(Some(object))
        }
        Some(_) => Ok(None),
        None => Ok(None),
    }
}

pub fn dataset_object_id(namespace: &str, dataset_id: &str) -> String {
    format!("{namespace}:dataset:{dataset_id}")
}

fn dataset_revision_digest(object: &Object) -> Result<String, String> {
    let properties = object.properties.iter().collect::<BTreeMap<_, _>>();
    canonical_digest("dataset-revision", &properties)
}

fn missing_revision_digest(namespace: &str, dataset_id: &str) -> String {
    canonical_digest("dataset-missing", &(namespace, dataset_id)).expect("canonical missing digest")
}

fn rule_digest(rule: &DataQualityRule) -> Result<String, String> {
    canonical_digest(
        RULE_CONTRACT,
        &(
            &rule.namespace,
            &rule.rule_id,
            &rule.dataset_id,
            &rule.evaluator,
            &rule.expected_digest,
            &rule.required_fields,
            &rule.min_rows,
            &rule.max_rows,
            &rule.baseline_digest,
        ),
    )
}

fn evaluator_digest(evaluator: &str) -> String {
    canonical_digest("data-quality-evaluator", evaluator).expect("canonical evaluator digest")
}

fn result_id_for(namespace: &str, rule_digest: &str, dataset_revision: &str) -> String {
    canonical_digest(RESULT_CONTRACT, &(namespace, rule_digest, dataset_revision))
        .expect("canonical result id")
}

fn receipt_digest(result: &DataQualityResult) -> Result<String, String> {
    canonical_digest(
        RESULT_CONTRACT,
        &(
            &result.result_id,
            &result.rule_digest,
            &result.dataset_revision_digest,
            &result.status,
            &result.population,
        ),
    )
}

fn canonical_digest(label: &str, value: &(impl Serialize + ?Sized)) -> Result<String, String> {
    let json = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(b"\n");
    hasher.update(&json);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn parse_evaluator(value: &str) -> Result<&'static str, String> {
    match value {
        EVALUATOR_DIGEST_PIN => Ok(EVALUATOR_DIGEST_PIN),
        EVALUATOR_COMPLETENESS => Ok(EVALUATOR_COMPLETENESS),
        EVALUATOR_ROW_COUNT => Ok(EVALUATOR_ROW_COUNT),
        _ => Err(STATUS_UNKNOWN.into()),
    }
}

fn is_closed(status: &str) -> bool {
    matches!(
        status,
        STATUS_PASS
            | STATUS_FAIL
            | STATUS_MISSING
            | STATUS_INVALID
            | STATUS_UNAVAILABLE
            | STATUS_UNKNOWN
    )
}

fn validate_digest(name: &str, value: &str) -> Result<(), String> {
    if let Some(hex) = value.strip_prefix("sha256:")
        && hex.len() == 64
        && hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Ok(());
    }
    Err(format!("{name} must be a sha256 digest"))
}

fn required(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn audit(
    db: &RuntimeDb,
    actor: &str,
    action: &str,
    outcome: &str,
    namespace: &str,
    rule_id: &str,
    target_id: &str,
    now_ms: i64,
) -> Result<(), String> {
    db.record_decision(&Decision {
        id: format!("{action}:{target_id}:{now_ms}"),
        timestamp: now_ms,
        actor: actor.into(),
        action: action.into(),
        reason: format!("recorded {RESULT_CONTRACT} {outcome}"),
        evidence: HashMap::from([
            ("contract_version".into(), RESULT_CONTRACT.into()),
            ("namespace".into(), namespace.into()),
            ("rule_id".into(), rule_id.into()),
            ("write_authority".into(), "false".into()),
            ("permit_authority".into(), "false".into()),
        ]),
        target_id: target_id.into(),
        outcome: outcome.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn expected() -> String {
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()
    }

    fn put_dataset(db: &RuntimeDb, rows: &str, extra: &[(&str, &str)]) {
        let mut properties = HashMap::from([("row_count".into(), rows.into())]);
        for (key, value) in extra {
            properties.insert((*key).into(), (*value).into());
        }
        db.create_object(&Object {
            id: dataset_object_id("quality", "orders"),
            kind: KIND_DATASET.into(),
            name: "orders".into(),
            namespace: "quality".into(),
            external_id: String::new(),
            properties,
            created: 1,
            updated: 1,
        })
        .unwrap();
    }

    fn publish_pin(db: &RuntimeDb) -> DataQualityRule {
        let dataset = db
            .get_object(&dataset_object_id("quality", "orders"))
            .unwrap()
            .unwrap();
        publish_rule(
            db,
            "analyst",
            &PublishDataQualityRule {
                namespace: "quality".into(),
                rule_id: "orders-pin".into(),
                dataset_id: "orders".into(),
                evaluator: EVALUATOR_DIGEST_PIN.into(),
                expected_digest: Some(dataset_revision_digest(&dataset).unwrap()),
                required_fields: Vec::new(),
                min_rows: None,
                max_rows: None,
                baseline_digest: Some(expected()),
            },
            10,
        )
        .unwrap()
    }

    #[test]
    fn authorized_pass_fail_missing_and_invalid_stay_distinct() {
        let db = db();
        put_dataset(&db, "4", &[("owner", "alice")]);
        let rule = publish_pin(&db);
        let passed = evaluate_rule(&db, "analyst", "quality", "orders-pin", None, 20).unwrap();
        assert_eq!(passed.status, STATUS_PASS);
        assert_eq!(passed.population, POPULATION_COMPLETE);
        assert!(!passed.evidence_receipt_digest.is_empty());
        let replay = evaluate_rule(&db, "analyst", "quality", "orders-pin", None, 21).unwrap();
        assert_eq!(replay.result_id, passed.result_id);
        assert_eq!(
            replay.evidence_receipt_digest,
            passed.evidence_receipt_digest
        );
        assert_eq!(replay.evaluated_at_ms, passed.evaluated_at_ms);

        publish_rule(
            &db,
            "analyst",
            &PublishDataQualityRule {
                namespace: "quality".into(),
                rule_id: "orders-count".into(),
                dataset_id: "orders".into(),
                evaluator: EVALUATOR_ROW_COUNT.into(),
                expected_digest: None,
                required_fields: Vec::new(),
                min_rows: Some(10),
                max_rows: Some(20),
                baseline_digest: None,
            },
            22,
        )
        .unwrap();
        let failed = evaluate_rule(&db, "analyst", "quality", "orders-count", None, 23).unwrap();
        assert_eq!(failed.status, STATUS_FAIL);

        publish_rule(
            &db,
            "analyst",
            &PublishDataQualityRule {
                namespace: "quality".into(),
                rule_id: "ghost-pin".into(),
                dataset_id: "ghost".into(),
                evaluator: EVALUATOR_DIGEST_PIN.into(),
                expected_digest: Some(expected()),
                required_fields: Vec::new(),
                min_rows: None,
                max_rows: None,
                baseline_digest: None,
            },
            24,
        )
        .unwrap();
        let missing = evaluate_rule(&db, "analyst", "quality", "ghost-pin", None, 25).unwrap();
        assert_eq!(missing.status, STATUS_MISSING);
        assert_eq!(missing.population, POPULATION_MISSING);

        db.create_object(&Object {
            id: dataset_object_id("quality", "broken"),
            kind: KIND_DATASET.into(),
            name: "broken".into(),
            namespace: "quality".into(),
            external_id: String::new(),
            properties: HashMap::from([("row_count".into(), "n/a".into())]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        publish_rule(
            &db,
            "analyst",
            &PublishDataQualityRule {
                namespace: "quality".into(),
                rule_id: "broken-count".into(),
                dataset_id: "broken".into(),
                evaluator: EVALUATOR_ROW_COUNT.into(),
                expected_digest: None,
                required_fields: Vec::new(),
                min_rows: Some(1),
                max_rows: None,
                baseline_digest: None,
            },
            26,
        )
        .unwrap();
        let invalid = evaluate_rule(&db, "analyst", "quality", "broken-count", None, 27).unwrap();
        assert_eq!(invalid.status, STATUS_INVALID);
        assert_ne!(invalid.status, STATUS_PASS);
        assert_eq!(rule.evaluator, EVALUATOR_DIGEST_PIN);
    }

    #[test]
    fn unknown_versions_and_hidden_identities_never_become_pass() {
        let db = db();
        put_dataset(&db, "2", &[]);
        publish_pin(&db);
        let unknown_rule = show_rule(&db, "quality", "missing-rule").unwrap_err();
        let unknown_ns = show_rule(&db, "hidden", "orders-pin").unwrap_err();
        assert_eq!(unknown_rule, unknown_ns);
        assert_eq!(unknown_rule, UNAVAILABLE);
        let stale = evaluate_rule(
            &db,
            "analyst",
            "quality",
            "orders-pin",
            Some(&expected()),
            30,
        )
        .unwrap_err();
        assert_eq!(stale, STATUS_UNKNOWN);
        assert_eq!(
            publish_rule(
                &db,
                "analyst",
                &PublishDataQualityRule {
                    namespace: "quality".into(),
                    rule_id: "bad-eval".into(),
                    dataset_id: "orders".into(),
                    evaluator: "caller_reducer".into(),
                    expected_digest: None,
                    required_fields: Vec::new(),
                    min_rows: None,
                    max_rows: None,
                    baseline_digest: None,
                },
                31,
            )
            .unwrap_err(),
            STATUS_UNKNOWN
        );
    }

    #[test]
    fn cancel_is_durable_and_restart_does_not_rewrite_a_closed_receipt() {
        let db = db();
        put_dataset(&db, "3", &[("region", "eu")]);
        publish_rule(
            &db,
            "analyst",
            &PublishDataQualityRule {
                namespace: "quality".into(),
                rule_id: "orders-complete".into(),
                dataset_id: "orders".into(),
                evaluator: EVALUATOR_COMPLETENESS.into(),
                expected_digest: None,
                required_fields: vec!["region".into()],
                min_rows: None,
                max_rows: None,
                baseline_digest: None,
            },
            40,
        )
        .unwrap();
        let running =
            start_evaluation(&db, "analyst", "quality", "orders-complete", None, 41).unwrap();
        assert_eq!(running.status, STATUS_RUNNING);
        let cancelled = cancel_evaluation(&db, "analyst", &running.result_id, 42).unwrap();
        assert_eq!(cancelled.status, STATUS_CANCELLED);
        assert!(!cancelled.evidence_receipt_digest.is_empty());
        let replay = show_result(&db, &running.result_id).unwrap();
        assert_eq!(replay.status, STATUS_CANCELLED);
        assert_eq!(
            replay.evidence_receipt_digest,
            cancelled.evidence_receipt_digest
        );
        let restarted = restart_evaluation(&db, "analyst", &running.result_id, 43).unwrap();
        assert_eq!(restarted.status, STATUS_PASS);
        assert_eq!(
            restarted.prior_receipt_digest.as_deref(),
            Some(cancelled.evidence_receipt_digest.as_str())
        );
        assert_ne!(
            restarted.evidence_receipt_digest,
            cancelled.evidence_receipt_digest
        );
        assert_eq!(
            restart_evaluation(&db, "analyst", &running.result_id, 44).unwrap_err(),
            "closed data quality receipt is immutable"
        );
        assert!(POSTGRES_UNAVAILABLE.contains("PostgreSQL"));
    }
}
