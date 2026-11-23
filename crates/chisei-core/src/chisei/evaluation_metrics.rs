//! Multi-metric evaluator results judged by plan-owned objectives (ADR 0154).
//!
//! An evaluator definition declares the metrics it measures. A plan node binds
//! an objective to any of them. The evaluator reports values in the closed
//! [`METRICS_RESULT_SCHEMA`] result; the executor, not the evaluator, derives
//! the step status from the bound objectives and records one
//! [`MetricVerdict`] per reported metric in the step receipt.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Closed result schema for multi-metric evaluator output. A definition that
/// declares metrics lists it in `supported_result_schemas`.
pub const METRICS_RESULT_SCHEMA: &str = "chisei.evaluation-metrics/v1";
pub const MAX_METRICS: usize = 32;
const MAX_METRIC_NAME_BYTES: usize = 64;

pub const REASON_OBJECTIVES_MET: &str = "metric_objectives_met";
pub const REASON_OBJECTIVE_UNMET: &str = "metric_objective_unmet";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Bool,
    /// An integer in millionths of the metric's unit, so judging never
    /// depends on floating-point behavior.
    IntegerMicros,
}

impl MetricKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::IntegerMicros => "integer_micros",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "bool" => Ok(Self::Bool),
            "integer_micros" => Ok(Self::IntegerMicros),
            _ => Err("metric kind must be bool or integer_micros".into()),
        }
    }
}

/// One metric an evaluator definition promises to report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricDeclaration {
    pub name: String,
    pub kind: MetricKind,
}

/// What a plan requires of one metric. Thresholds are inclusive; a direction
/// without a threshold judges nothing and keeps the metric advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "objective", rename_all = "snake_case")]
pub enum Objective {
    Equals {
        expected: bool,
    },
    Maximize {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        threshold_micros: Option<i64>,
    },
    Minimize {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        threshold_micros: Option<i64>,
    },
}

impl Objective {
    fn kind(self) -> MetricKind {
        match self {
            Self::Equals { .. } => MetricKind::Bool,
            Self::Maximize { .. } | Self::Minimize { .. } => MetricKind::IntegerMicros,
        }
    }

    /// `None` when the objective sets no pass condition.
    fn judge(self, value: MetricValue) -> Option<bool> {
        match (self, value) {
            (Self::Equals { expected }, MetricValue::Bool(actual)) => Some(actual == expected),
            (Self::Maximize { threshold_micros }, MetricValue::IntegerMicros(actual)) => {
                threshold_micros.map(|threshold| actual >= threshold)
            }
            (Self::Minimize { threshold_micros }, MetricValue::IntegerMicros(actual)) => {
                threshold_micros.map(|threshold| actual <= threshold)
            }
            _ => None,
        }
    }
}

impl Objective {
    /// Build from the flat wire fields. `expected` only means something for
    /// `equals`, `threshold_micros` only for a direction.
    pub fn from_parts(
        objective: &str,
        expected: bool,
        threshold_micros: Option<i64>,
    ) -> Result<Self, String> {
        match objective {
            "equals" if threshold_micros.is_none() => Ok(Self::Equals { expected }),
            "maximize" if !expected => Ok(Self::Maximize { threshold_micros }),
            "minimize" if !expected => Ok(Self::Minimize { threshold_micros }),
            "equals" | "maximize" | "minimize" => Err(
                "equals takes only expected; maximize and minimize take only a threshold".into(),
            ),
            _ => Err("metric objective must be equals, maximize, or minimize".into()),
        }
    }

    /// The flat wire fields: objective name, expected, threshold.
    pub fn parts(self) -> (&'static str, bool, Option<i64>) {
        match self {
            Self::Equals { expected } => ("equals", expected, None),
            Self::Maximize { threshold_micros } => ("maximize", false, threshold_micros),
            Self::Minimize { threshold_micros } => ("minimize", false, threshold_micros),
        }
    }
}

impl MetricValue {
    /// Build from the flat wire fields, keeping only the field `kind` names.
    pub fn from_parts(kind: MetricKind, bool_value: bool, integer_micros_value: i64) -> Self {
        match kind {
            MetricKind::Bool => Self::Bool(bool_value),
            MetricKind::IntegerMicros => Self::IntegerMicros(integer_micros_value),
        }
    }

    /// The flat wire fields: bool value, integer value.
    pub fn parts(self) -> (bool, i64) {
        match self {
            Self::Bool(value) => (value, 0),
            Self::IntegerMicros(value) => (false, value),
        }
    }
}

/// A plan node's objective for one declared metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricObjective {
    pub metric: String,
    #[serde(flatten)]
    pub objective: Objective,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetricValue {
    Bool(bool),
    IntegerMicros(i64),
}

impl MetricValue {
    pub fn kind(self) -> MetricKind {
        match self {
            Self::Bool(_) => MetricKind::Bool,
            Self::IntegerMicros(_) => MetricKind::IntegerMicros,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Met,
    Unmet,
    /// Reported, but no objective with a pass condition is bound to it.
    Advisory,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Met => "met",
            Self::Unmet => "unmet",
            Self::Advisory => "advisory",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "met" => Ok(Self::Met),
            "unmet" => Ok(Self::Unmet),
            "advisory" => Ok(Self::Advisory),
            _ => Err("metric verdict must be met, unmet, or advisory".into()),
        }
    }
}

/// One reported metric, its frozen objective, and the executor's verdict, as
/// recorded in the step receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricVerdict {
    pub name: String,
    pub kind: MetricKind,
    pub value: MetricValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective: Option<Objective>,
    pub verdict: Verdict,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricsResult {
    contract_version: String,
    metrics: Vec<ReportedMetric>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportedMetric {
    name: String,
    kind: MetricKind,
    value: MetricValue,
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > MAX_METRIC_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
    {
        return Err(format!(
            "metric name must be 1..={MAX_METRIC_NAME_BYTES} lowercase token bytes"
        ));
    }
    Ok(())
}

/// Sort and check a definition's declarations: bounded, unique, valid names.
pub fn normalize_declarations(declarations: &mut [MetricDeclaration]) -> Result<(), String> {
    if declarations.len() > MAX_METRICS {
        return Err(format!(
            "an evaluator declares at most {MAX_METRICS} metrics"
        ));
    }
    declarations.sort_by(|left, right| left.name.cmp(&right.name));
    for declaration in declarations.iter() {
        validate_name(&declaration.name)?;
    }
    if declarations
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
    {
        return Err("duplicate metric declaration".into());
    }
    Ok(())
}

/// Sort and check a node's objectives on their own: bounded, one per metric.
pub fn normalize_objectives(objectives: &mut [MetricObjective]) -> Result<(), String> {
    if objectives.len() > MAX_METRICS {
        return Err(format!(
            "a node binds at most {MAX_METRICS} metric objectives"
        ));
    }
    objectives.sort_by(|left, right| left.metric.cmp(&right.metric));
    for objective in objectives.iter() {
        validate_name(&objective.metric)?;
    }
    if objectives
        .windows(2)
        .any(|pair| pair[0].metric == pair[1].metric)
    {
        return Err("duplicate metric objective".into());
    }
    Ok(())
}

/// Plan-time check that every objective names a declared metric of the kind
/// the objective judges.
pub fn check_objectives(
    declarations: &[MetricDeclaration],
    objectives: &[MetricObjective],
) -> Result<(), String> {
    let declared = declaration_kinds(declarations);
    for objective in objectives {
        match declared.get(objective.metric.as_str()) {
            None => {
                return Err(format!(
                    "metric objective {:?} names a metric the evaluator does not declare",
                    objective.metric
                ));
            }
            Some(kind) if *kind != objective.objective.kind() => {
                return Err(format!(
                    "metric objective {:?} does not fit a {} metric",
                    objective.metric,
                    kind.as_str()
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn declaration_kinds(declarations: &[MetricDeclaration]) -> BTreeMap<&str, MetricKind> {
    declarations
        .iter()
        .map(|declaration| (declaration.name.as_str(), declaration.kind))
        .collect()
}

/// Judge an evaluator's `result` against the frozen declarations and
/// objectives. The result must be the closed metrics schema, report only
/// declared metrics with their declared kind, and report every metric an
/// objective is bound to. Verdicts come back sorted by name.
pub fn judge(
    declarations: &[MetricDeclaration],
    objectives: &[MetricObjective],
    result: &Value,
) -> Result<Vec<MetricVerdict>, String> {
    let result = MetricsResult::deserialize(result)
        .map_err(|error| format!("metrics result is invalid: {error}"))?;
    if result.contract_version != METRICS_RESULT_SCHEMA {
        return Err("metrics result contract_version is unsupported".into());
    }
    if result.metrics.is_empty() || result.metrics.len() > MAX_METRICS {
        return Err(format!("metrics result requires 1..={MAX_METRICS} metrics"));
    }
    let declared = declaration_kinds(declarations);
    let bound = objectives
        .iter()
        .map(|objective| (objective.metric.as_str(), objective.objective))
        .collect::<BTreeMap<_, _>>();
    let mut verdicts = BTreeMap::new();
    for metric in result.metrics {
        if declared.get(metric.name.as_str()) != Some(&metric.kind)
            || metric.value.kind() != metric.kind
        {
            return Err(format!(
                "metric {:?} is undeclared or has the wrong kind",
                metric.name
            ));
        }
        let objective = bound.get(metric.name.as_str()).copied();
        let verdict = verdict_for(objective, metric.value);
        let entry = MetricVerdict {
            name: metric.name.clone(),
            kind: metric.kind,
            value: metric.value,
            objective,
            verdict,
        };
        if verdicts.insert(metric.name, entry).is_some() {
            return Err("metrics result repeats a metric".into());
        }
    }
    if let Some(missing) = bound.keys().find(|name| !verdicts.contains_key(**name)) {
        return Err(format!("metrics result omits bound metric {missing:?}"));
    }
    Ok(verdicts.into_values().collect())
}

fn verdict_for(objective: Option<Objective>, value: MetricValue) -> Verdict {
    match objective.and_then(|objective| objective.judge(value)) {
        Some(true) => Verdict::Met,
        Some(false) => Verdict::Unmet,
        None => Verdict::Advisory,
    }
}

/// The step status and reason code the verdicts decide: fail when any bound
/// objective is unmet, otherwise pass.
pub fn derived_status(verdicts: &[MetricVerdict]) -> (&'static str, &'static str) {
    if verdicts
        .iter()
        .any(|verdict| verdict.verdict == Verdict::Unmet)
    {
        ("fail", REASON_OBJECTIVE_UNMET)
    } else {
        ("pass", REASON_OBJECTIVES_MET)
    }
}

/// Receipt-side check that recorded verdicts are exactly what the frozen
/// node policy decides for the recorded values, and that the step status
/// follows from them.
pub fn verify_verdicts(
    declarations: &[MetricDeclaration],
    objectives: &[MetricObjective],
    verdicts: &[MetricVerdict],
    status: &str,
    reason_code: &str,
) -> Result<(), String> {
    let reported = Value::Object(serde_json::Map::from_iter([
        ("contract_version".into(), METRICS_RESULT_SCHEMA.into()),
        (
            "metrics".into(),
            Value::Array(
                verdicts
                    .iter()
                    .map(|verdict| {
                        serde_json::json!({
                            "name": verdict.name,
                            "kind": verdict.kind,
                            "value": verdict.value,
                        })
                    })
                    .collect(),
            ),
        ),
    ]));
    let expected = judge(declarations, objectives, &reported)?;
    if expected != verdicts || derived_status(verdicts) != (status, reason_code) {
        return Err("evaluation step metric verdicts are inconsistent".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn declarations() -> Vec<MetricDeclaration> {
        vec![
            MetricDeclaration {
                name: "accuracy".into(),
                kind: MetricKind::IntegerMicros,
            },
            MetricDeclaration {
                name: "latency_ms".into(),
                kind: MetricKind::IntegerMicros,
            },
            MetricDeclaration {
                name: "safe".into(),
                kind: MetricKind::Bool,
            },
        ]
    }

    fn objective(metric: &str, objective: Objective) -> MetricObjective {
        MetricObjective {
            metric: metric.into(),
            objective,
        }
    }

    fn result(metrics: Value) -> Value {
        json!({"contract_version": METRICS_RESULT_SCHEMA, "metrics": metrics})
    }

    #[test]
    fn a_value_at_the_threshold_meets_both_directions() {
        let objectives = [
            objective(
                "accuracy",
                Objective::Maximize {
                    threshold_micros: Some(900_000),
                },
            ),
            objective(
                "latency_ms",
                Objective::Minimize {
                    threshold_micros: Some(250_000_000),
                },
            ),
        ];
        let verdicts = judge(
            &declarations(),
            &objectives,
            &result(json!([
                {"name": "accuracy", "kind": "integer_micros", "value": 900_000},
                {"name": "latency_ms", "kind": "integer_micros", "value": 250_000_000},
            ])),
        )
        .unwrap();
        assert!(
            verdicts
                .iter()
                .all(|verdict| verdict.verdict == Verdict::Met)
        );
        assert_eq!(derived_status(&verdicts), ("pass", REASON_OBJECTIVES_MET));
    }

    #[test]
    fn one_unmet_objective_fails_and_unbound_metrics_stay_advisory() {
        let objectives = [
            objective("safe", Objective::Equals { expected: true }),
            objective(
                "latency_ms",
                Objective::Minimize {
                    threshold_micros: None,
                },
            ),
        ];
        let verdicts = judge(
            &declarations(),
            &objectives,
            &result(json!([
                {"name": "safe", "kind": "bool", "value": false},
                {"name": "latency_ms", "kind": "integer_micros", "value": 7},
                {"name": "accuracy", "kind": "integer_micros", "value": 1},
            ])),
        )
        .unwrap();
        let by_name = verdicts
            .iter()
            .map(|verdict| (verdict.name.as_str(), verdict.verdict))
            .collect::<Vec<_>>();
        assert_eq!(
            by_name,
            [
                ("accuracy", Verdict::Advisory),
                ("latency_ms", Verdict::Advisory),
                ("safe", Verdict::Unmet),
            ]
        );
        assert_eq!(derived_status(&verdicts), ("fail", REASON_OBJECTIVE_UNMET));
        verify_verdicts(
            &declarations(),
            &objectives,
            &verdicts,
            "fail",
            REASON_OBJECTIVE_UNMET,
        )
        .unwrap();
        assert!(
            verify_verdicts(
                &declarations(),
                &objectives,
                &verdicts,
                "pass",
                REASON_OBJECTIVES_MET
            )
            .is_err()
        );
    }

    #[test]
    fn results_outside_the_declaration_fail_closed() {
        let bound = [objective("safe", Objective::Equals { expected: true })];
        for metrics in [
            json!([{"name": "safe", "kind": "bool", "value": true}, {"name": "cost", "kind": "bool", "value": true}]),
            json!([{"name": "safe", "kind": "integer_micros", "value": 1}]),
            json!([{"name": "safe", "kind": "bool", "value": 1}]),
            json!([{"name": "safe", "kind": "bool", "value": true}, {"name": "safe", "kind": "bool", "value": true}]),
            json!([{"name": "accuracy", "kind": "integer_micros", "value": 1.5}]),
            json!([]),
        ] {
            assert!(
                judge(&declarations(), &bound, &result(metrics.clone())).is_err(),
                "{metrics}"
            );
        }
        assert!(judge(&declarations(), &[], &json!({"metrics": []})).is_err());
    }

    #[test]
    fn plan_objectives_must_name_a_declared_metric_of_their_kind() {
        let declared = declarations();
        assert!(
            check_objectives(
                &declared,
                &[objective("cost", Objective::Equals { expected: true })]
            )
            .unwrap_err()
            .contains("does not declare")
        );
        assert!(
            check_objectives(
                &declared,
                &[objective(
                    "safe",
                    Objective::Maximize {
                        threshold_micros: Some(1)
                    }
                )]
            )
            .is_err()
        );
        let mut duplicate = vec![
            objective("safe", Objective::Equals { expected: true }),
            objective("safe", Objective::Equals { expected: false }),
        ];
        assert!(normalize_objectives(&mut duplicate).is_err());
    }

    #[test]
    fn objectives_keep_a_flat_canonical_json_shape() {
        let value = objective(
            "accuracy",
            Objective::Maximize {
                threshold_micros: Some(5),
            },
        );
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            json!({"metric": "accuracy", "objective": "maximize", "threshold_micros": 5})
        );
        let open: MetricObjective =
            serde_json::from_value(json!({"metric": "accuracy", "objective": "minimize"})).unwrap();
        assert_eq!(
            open.objective,
            Objective::Minimize {
                threshold_micros: None
            }
        );
    }
}
