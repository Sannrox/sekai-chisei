//! Authorized, receipt-backed quality trend projections.
//!
//! Canonical operation receipts remain the authority. This module reconstructs
//! evaluation executions, keeps closed non-pass states distinct, and derives
//! like-for-like baselines without persisting a second analytics truth.

use crate::chisei::evaluation_execution::{
    self, EXECUTION_OPERATION_CLASS, EvaluationExecutionProjection, EvaluationStepReceipt,
    REASON_EXECUTION_CANCELLED, STATUS_CANCELLED, STATUS_ERROR, STATUS_FAIL, STATUS_PASS,
    STATUS_RUNNING, STATUS_SKIPPED, STATUS_UNAVAILABLE, STATUS_UNKNOWN, VERDICT_ALLOW,
    VERDICT_DENY, VERDICT_UNAVAILABLE, VERDICT_UNKNOWN,
};
use crate::chisei::evaluation_manifest::{ResolvedEvaluationManifest, ResolvedEvaluationNode};
use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, OperationReceipt, ReceiptEventKind};
use crate::db::runtime_db::RuntimeDb;
use crate::obs::console::{is_safe_namespace, principal_can_access_namespace};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

pub const QUALITY_TREND_VERSION: &str = "chisei.evaluation-quality-trend/v1";
pub const MAX_QUALITY_TREND_WINDOW_MS: i64 = 366 * 24 * 60 * 60 * 1000;
pub const MAX_QUALITY_TREND_RECEIPTS: usize = 4_096;

const AUTHORITY: &str = "canonical_operation_receipt";
const DIMENSION_HIDDEN: &str = "hidden";
const DIMENSION_NOT_APPLICABLE: &str = "not_applicable";
const POPULATION_COMPLETE: &str = "complete";
const POPULATION_LOW_SAMPLE: &str = "low_sample";
const POPULATION_MISSING: &str = "missing";
const BASELINE_COMPARED: &str = "compared";
const BASELINE_MISSING: &str = "missing";
const BASELINE_INCOMPARABLE: &str = "incomparable";
const BASELINE_UNAVAILABLE: &str = "unavailable";
const REGRESSION_REGRESSED: &str = "regressed";
const REGRESSION_IMPROVED: &str = "improved";
const REGRESSION_UNCHANGED: &str = "unchanged";
const REGRESSION_UNAVAILABLE: &str = "unavailable";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct QualityTrendTotals {
    pub receipts_scanned: u64,
    pub ignored_non_evaluation_receipts: u64,
    pub evaluation_receipts: u64,
    pub baseline_history_receipts: u64,
    pub baseline_history_valid_executions: u64,
    pub baseline_history_missing_dependencies: u64,
    pub baseline_history_invalid_executions: u64,
    pub valid_executions: u64,
    pub missing_dependencies: u64,
    pub invalid_executions: u64,
    pub allow: u64,
    pub deny: u64,
    pub unknown: u64,
    pub unavailable: u64,
    pub cancelled: u64,
    pub running: u64,
    pub partial_executions: u64,
    pub trend_points: u64,
    pub step_pass: u64,
    pub step_fail: u64,
    pub step_unknown: u64,
    pub step_unavailable: u64,
    pub step_error: u64,
    pub step_skipped: u64,
    pub stochastic_complete_populations: u64,
    pub stochastic_low_sample_populations: u64,
    pub baseline_compared: u64,
    pub baseline_missing: u64,
    pub baseline_incomparable: u64,
    pub baseline_unavailable: u64,
    pub regressed: u64,
    pub improved: u64,
    pub unchanged: u64,
    pub regression_unavailable: u64,
    pub hidden_dimensions: u64,
    pub missing_dimensions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct QualityTrendSeriesKey {
    pub plan_digest: String,
    pub node_id: String,
    pub evaluator_definition_digest: String,
    pub implementation_digest: String,
    pub provider: String,
    pub model: String,
    pub agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QualityTrendPoint {
    pub operation_id: String,
    pub manifest_digest: String,
    pub started_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub evaluation_time_ms: i64,
    pub evaluator_input_digest: String,
    pub subject_content_digest: String,
    pub subject_identity_state: String,
    pub evidence_set_digest: String,
    pub evidence_digest_count: u32,
    pub evidence_identity_state: String,
    pub dependency_result_set_digest: String,
    pub dependency_result_digest_count: u32,
    pub dependency_result_identity_state: String,
    pub execution_status: String,
    pub gate_verdict: String,
    pub gate_reason_code: String,
    pub step_status: String,
    pub step_reason_code: String,
    pub classification: String,
    pub population_state: String,
    pub trial_count: Option<u32>,
    pub completed_trial_count: Option<u32>,
    pub mean_score_micros: Option<u32>,
    pub pass_rate_basis_points: Option<u32>,
    pub score_variance_micros_squared: Option<u64>,
    pub aggregation_rule: Option<String>,
    pub baseline_state: String,
    pub baseline_operation_id: Option<String>,
    pub mean_score_delta_micros: Option<i64>,
    pub pass_rate_delta_basis_points: Option<i64>,
    pub variance_delta_micros_squared: Option<i128>,
    pub regression: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QualityTrendSeries {
    pub key: QualityTrendSeriesKey,
    pub points: Vec<QualityTrendPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QualityTrendReport {
    pub version: String,
    pub source_receipt_version: String,
    pub authority: String,
    pub namespace: String,
    pub since_ms: i64,
    pub until_ms: i64,
    pub totals: QualityTrendTotals,
    pub series: Vec<QualityTrendSeries>,
    pub semantic_digest: String,
}

enum EvaluatedReceipt {
    Valid {
        receipt: Box<OperationReceipt>,
        manifest: Box<ResolvedEvaluationManifest>,
        projection: Box<EvaluationExecutionProjection>,
    },
    Missing,
    Invalid,
}

pub fn query_quality_trends(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    since_ms: i64,
    until_ms: i64,
) -> Result<QualityTrendReport, String> {
    let namespace = namespace.trim();
    if !is_safe_namespace(namespace) {
        return Err("invalid namespace".into());
    }
    if !principal_can_access_namespace(db, principal.trim(), namespace).unwrap_or(false) {
        return Err("namespace access denied".into());
    }
    if until_ms <= since_ms {
        return Err("until_ms must be greater than since_ms".into());
    }
    if until_ms.saturating_sub(since_ms) > MAX_QUALITY_TREND_WINDOW_MS {
        return Err("quality trend window exceeds one year".into());
    }

    let receipts = db.list_operation_receipts_in_window(
        namespace,
        since_ms,
        until_ms,
        MAX_QUALITY_TREND_RECEIPTS.saturating_add(1),
    )?;
    if receipts.len() > MAX_QUALITY_TREND_RECEIPTS {
        return Err(format!(
            "quality trend receipt limit exceeded ({MAX_QUALITY_TREND_RECEIPTS})"
        ));
    }
    let receipts_scanned = receipts.len() as u64;
    let selected_operation_ids = receipts
        .iter()
        .map(|receipt| receipt.operation_id.as_str())
        .collect::<HashSet<_>>();
    let baseline_receipts = db.list_operation_receipts_in_window(
        namespace,
        since_ms.saturating_sub(MAX_QUALITY_TREND_WINDOW_MS),
        since_ms,
        MAX_QUALITY_TREND_RECEIPTS.saturating_add(1),
    )?;
    if baseline_receipts.len() > MAX_QUALITY_TREND_RECEIPTS {
        return Err(format!(
            "quality trend baseline receipt limit exceeded ({MAX_QUALITY_TREND_RECEIPTS})"
        ));
    }
    let historical = baseline_receipts
        .into_iter()
        .filter(|receipt| !selected_operation_ids.contains(receipt.operation_id.as_str()))
        .filter(|receipt| receipt.operation_class == EXECUTION_OPERATION_CLASS)
        .map(|receipt| load_evaluated_receipt(db, receipt))
        .collect::<Result<Vec<_>, _>>()?;
    let evaluated = receipts
        .into_iter()
        .filter(|receipt| receipt.operation_class == EXECUTION_OPERATION_CLASS)
        .map(|receipt| load_evaluated_receipt(db, receipt))
        .collect::<Result<Vec<_>, _>>()?;
    build_report(
        namespace,
        since_ms,
        until_ms,
        receipts_scanned,
        evaluated,
        historical,
    )
}

fn load_evaluated_receipt(
    db: &RuntimeDb,
    receipt: OperationReceipt,
) -> Result<EvaluatedReceipt, String> {
    let Some(manifest_digest) = manifest_digest_from_receipt(&receipt) else {
        return Ok(EvaluatedReceipt::Missing);
    };
    let manifest = match db.get_evaluation_manifest(&manifest_digest) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => return Ok(EvaluatedReceipt::Missing),
        Err(error) => return Err(error),
    };
    let index = match db.get_evaluation_execution_index(&manifest_digest) {
        Ok(Some(index)) => index,
        Ok(None) => return Ok(EvaluatedReceipt::Missing),
        Err(error) => return Err(error),
    };
    Ok(
        match evaluation_execution::projection_from_receipt(&manifest, &index, &receipt) {
            Ok(projection) => EvaluatedReceipt::Valid {
                receipt: Box::new(receipt),
                manifest: Box::new(manifest),
                projection: Box::new(projection),
            },
            Err(_) => EvaluatedReceipt::Invalid,
        },
    )
}

fn manifest_digest_from_receipt(receipt: &OperationReceipt) -> Option<String> {
    let mut digests = receipt
        .events
        .iter()
        .filter(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .filter_map(|event| event.attributes.get("manifest_digest"))
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let digest = digests.next()?.to_string();
    if digests.any(|candidate| candidate != digest) {
        None
    } else {
        Some(digest)
    }
}

fn build_report(
    namespace: &str,
    since_ms: i64,
    until_ms: i64,
    receipts_scanned: u64,
    evaluated: Vec<EvaluatedReceipt>,
    historical: Vec<EvaluatedReceipt>,
) -> Result<QualityTrendReport, String> {
    let mut totals = QualityTrendTotals {
        receipts_scanned,
        evaluation_receipts: evaluated.len() as u64,
        ignored_non_evaluation_receipts: receipts_scanned.saturating_sub(evaluated.len() as u64),
        ..QualityTrendTotals::default()
    };
    let mut grouped: BTreeMap<QualityTrendSeriesKey, Vec<QualityTrendPoint>> = BTreeMap::new();
    let mut historical_grouped: BTreeMap<QualityTrendSeriesKey, Vec<QualityTrendPoint>> =
        BTreeMap::new();
    let mut baseline_history_complete = true;

    totals.baseline_history_receipts = historical.len() as u64;
    for source in historical {
        let EvaluatedReceipt::Valid {
            receipt,
            manifest,
            projection,
        } = source
        else {
            baseline_history_complete = false;
            match source {
                EvaluatedReceipt::Missing => {
                    totals.baseline_history_missing_dependencies = totals
                        .baseline_history_missing_dependencies
                        .saturating_add(1)
                }
                EvaluatedReceipt::Invalid => {
                    totals.baseline_history_invalid_executions =
                        totals.baseline_history_invalid_executions.saturating_add(1)
                }
                EvaluatedReceipt::Valid { .. } => unreachable!(),
            }
            continue;
        };
        totals.baseline_history_valid_executions =
            totals.baseline_history_valid_executions.saturating_add(1);
        for step in &projection.steps {
            let Some(node) = manifest
                .nodes
                .iter()
                .find(|node| node.node_id == step.node_id)
            else {
                baseline_history_complete = false;
                totals.baseline_history_invalid_executions =
                    totals.baseline_history_invalid_executions.saturating_add(1);
                continue;
            };
            let (provider, model, population_state) = population_dimensions(step, node);
            let key = series_key(&manifest, node, &receipt, provider, model);
            let point = trend_point(&receipt, &manifest, &projection, step, population_state)?;
            historical_grouped.entry(key).or_default().push(point);
        }
    }

    for source in evaluated {
        let EvaluatedReceipt::Valid {
            receipt,
            manifest,
            projection,
        } = source
        else {
            match source {
                EvaluatedReceipt::Missing => {
                    totals.missing_dependencies = totals.missing_dependencies.saturating_add(1)
                }
                EvaluatedReceipt::Invalid => {
                    totals.invalid_executions = totals.invalid_executions.saturating_add(1)
                }
                EvaluatedReceipt::Valid { .. } => unreachable!(),
            }
            continue;
        };

        totals.valid_executions = totals.valid_executions.saturating_add(1);
        let execution_status = report_execution_status(&projection);
        increment_execution_status(&mut totals, execution_status);
        let hidden_references = receipt
            .events
            .iter()
            .flat_map(|event| &event.references)
            .filter(|reference| reference.omitted)
            .count() as u64;
        totals.hidden_dimensions = totals.hidden_dimensions.saturating_add(hidden_references);
        let mut partial = matches!(execution_status, STATUS_RUNNING | STATUS_CANCELLED);

        for step in &projection.steps {
            increment_step_status(&mut totals, &step.status);
            let Some(node) = manifest
                .nodes
                .iter()
                .find(|node| node.node_id == step.node_id)
            else {
                totals.invalid_executions = totals.invalid_executions.saturating_add(1);
                continue;
            };
            let (provider, model, population_state) = population_dimensions(step, node);
            if population_state == POPULATION_MISSING {
                totals.missing_dimensions = totals.missing_dimensions.saturating_add(1);
            }
            match population_state {
                POPULATION_COMPLETE => {
                    totals.stochastic_complete_populations =
                        totals.stochastic_complete_populations.saturating_add(1)
                }
                POPULATION_LOW_SAMPLE => {
                    totals.stochastic_low_sample_populations =
                        totals.stochastic_low_sample_populations.saturating_add(1);
                    partial = true;
                }
                _ => {}
            }
            let key = series_key(&manifest, node, &receipt, provider, model);
            let point = trend_point(&receipt, &manifest, &projection, step, population_state)?;
            totals.trend_points = totals.trend_points.saturating_add(1);
            // Subject identity is deliberately absent. Evidence identities are
            // likewise replaced by the exact digest set used by the evaluator.
            totals.hidden_dimensions = totals.hidden_dimensions.saturating_add(
                1 + u64::from(point.evidence_digest_count > 0)
                    + u64::from(point.dependency_result_digest_count > 0),
            );
            grouped.entry(key).or_default().push(point);
        }
        if partial {
            totals.partial_executions = totals.partial_executions.saturating_add(1);
        }
    }

    let mut series = Vec::with_capacity(grouped.len());
    for (key, mut points) in grouped {
        points.sort_by(|left, right| {
            left.evaluation_time_ms
                .cmp(&right.evaluation_time_ms)
                .then_with(|| left.operation_id.cmp(&right.operation_id))
        });
        let mut historical_points = historical_grouped.remove(&key).unwrap_or_default();
        historical_points.sort_by(|left, right| {
            left.evaluation_time_ms
                .cmp(&right.evaluation_time_ms)
                .then_with(|| left.operation_id.cmp(&right.operation_id))
        });
        attach_baselines(
            &mut points,
            &historical_points,
            baseline_history_complete,
            &mut totals,
        );
        series.push(QualityTrendSeries { key, points });
    }

    let accounted = totals
        .valid_executions
        .saturating_add(totals.missing_dependencies)
        .saturating_add(totals.invalid_executions);
    if accounted != totals.evaluation_receipts {
        return Err("quality trend execution totals do not reconcile".into());
    }
    let closed = totals
        .allow
        .saturating_add(totals.deny)
        .saturating_add(totals.unknown)
        .saturating_add(totals.unavailable)
        .saturating_add(totals.cancelled)
        .saturating_add(totals.running);
    if closed != totals.valid_executions {
        return Err("quality trend status totals do not reconcile".into());
    }

    let mut report = QualityTrendReport {
        version: QUALITY_TREND_VERSION.into(),
        source_receipt_version: OPERATION_RECEIPT_VERSION.into(),
        authority: AUTHORITY.into(),
        namespace: namespace.into(),
        since_ms,
        until_ms,
        totals,
        series,
        semantic_digest: String::new(),
    };
    report.semantic_digest = semantic_digest(&report)?;
    Ok(report)
}

fn increment_execution_status(totals: &mut QualityTrendTotals, status: &str) {
    let counter = match status {
        VERDICT_ALLOW => &mut totals.allow,
        VERDICT_DENY => &mut totals.deny,
        VERDICT_UNKNOWN => &mut totals.unknown,
        VERDICT_UNAVAILABLE => &mut totals.unavailable,
        STATUS_CANCELLED => &mut totals.cancelled,
        STATUS_RUNNING => &mut totals.running,
        _ => &mut totals.invalid_executions,
    };
    *counter = counter.saturating_add(1);
}

fn report_execution_status(projection: &EvaluationExecutionProjection) -> &str {
    if projection
        .decision
        .as_ref()
        .is_some_and(|decision| decision.reason_code == REASON_EXECUTION_CANCELLED)
    {
        STATUS_CANCELLED
    } else {
        &projection.status
    }
}

fn increment_step_status(totals: &mut QualityTrendTotals, status: &str) {
    let counter = match status {
        STATUS_PASS => &mut totals.step_pass,
        STATUS_FAIL => &mut totals.step_fail,
        STATUS_UNKNOWN => &mut totals.step_unknown,
        STATUS_UNAVAILABLE => &mut totals.step_unavailable,
        STATUS_ERROR => &mut totals.step_error,
        STATUS_SKIPPED => &mut totals.step_skipped,
        _ => return,
    };
    *counter = counter.saturating_add(1);
}

fn population_dimensions<'a>(
    step: &'a EvaluationStepReceipt,
    node: &'a ResolvedEvaluationNode,
) -> (&'a str, &'a str, &'static str) {
    let Some(population) = &step.stochastic_evidence else {
        if let Some(policy) = &node.evaluator.stochastic_policy {
            return (
                policy.provider.trim(),
                policy.model.trim(),
                POPULATION_MISSING,
            );
        }
        return (
            DIMENSION_NOT_APPLICABLE,
            DIMENSION_NOT_APPLICABLE,
            DIMENSION_NOT_APPLICABLE,
        );
    };
    let state = if population.completed_trial_count == population.trial_count {
        POPULATION_COMPLETE
    } else {
        POPULATION_LOW_SAMPLE
    };
    (population.provider.trim(), population.model.trim(), state)
}

fn series_key(
    manifest: &ResolvedEvaluationManifest,
    node: &ResolvedEvaluationNode,
    receipt: &OperationReceipt,
    provider: &str,
    model: &str,
) -> QualityTrendSeriesKey {
    QualityTrendSeriesKey {
        plan_digest: manifest.plan_digest.clone(),
        node_id: node.node_id.clone(),
        evaluator_definition_digest: node.evaluator.definition_digest.clone(),
        implementation_digest: node.evaluator.implementation_digest.clone(),
        provider: provider.into(),
        model: model.into(),
        agent: receipt.initiating_actor.clone(),
    }
}

fn trend_point(
    receipt: &OperationReceipt,
    manifest: &ResolvedEvaluationManifest,
    projection: &EvaluationExecutionProjection,
    step: &EvaluationStepReceipt,
    population_state: &str,
) -> Result<QualityTrendPoint, String> {
    let population = step.stochastic_evidence.as_ref();
    let decision = projection.decision.as_ref();
    Ok(QualityTrendPoint {
        operation_id: receipt.operation_id.clone(),
        manifest_digest: manifest.manifest_digest.clone(),
        started_at_ms: receipt.started_at_ms,
        completed_at_ms: receipt.completed_at_ms,
        evaluation_time_ms: manifest.evaluation_time_ms,
        evaluator_input_digest: step.input_digest.clone(),
        subject_content_digest: manifest.subject_content_digest.clone(),
        subject_identity_state: DIMENSION_HIDDEN.into(),
        evidence_set_digest: digest_values(&step.evidence_digests)?,
        evidence_digest_count: u32::try_from(step.evidence_digests.len()).unwrap_or(u32::MAX),
        evidence_identity_state: if step.evidence_digests.is_empty() {
            DIMENSION_NOT_APPLICABLE.into()
        } else {
            DIMENSION_HIDDEN.into()
        },
        dependency_result_set_digest: digest_values(&step.dependency_result_digests)?,
        dependency_result_digest_count: u32::try_from(step.dependency_result_digests.len())
            .unwrap_or(u32::MAX),
        dependency_result_identity_state: if step.dependency_result_digests.is_empty() {
            DIMENSION_NOT_APPLICABLE.into()
        } else {
            DIMENSION_HIDDEN.into()
        },
        execution_status: report_execution_status(projection).into(),
        gate_verdict: decision
            .map(|value| value.verdict.clone())
            .unwrap_or_default(),
        gate_reason_code: decision
            .map(|value| value.reason_code.clone())
            .unwrap_or_default(),
        step_status: step.status.clone(),
        step_reason_code: step.reason_code.clone(),
        classification: step.classification.clone(),
        population_state: population_state.into(),
        trial_count: population.map(|value| value.trial_count),
        completed_trial_count: population.map(|value| value.completed_trial_count),
        mean_score_micros: population.map(|value| value.mean_score_micros),
        pass_rate_basis_points: population.map(|value| value.pass_rate_basis_points),
        score_variance_micros_squared: population.map(|value| value.score_variance_micros_squared),
        aggregation_rule: population.map(|value| value.aggregation_rule.clone()),
        baseline_state: BASELINE_UNAVAILABLE.into(),
        baseline_operation_id: None,
        mean_score_delta_micros: None,
        pass_rate_delta_basis_points: None,
        variance_delta_micros_squared: None,
        regression: REGRESSION_UNAVAILABLE.into(),
    })
}

fn attach_baselines(
    points: &mut [QualityTrendPoint],
    historical_points: &[QualityTrendPoint],
    baseline_history_complete: bool,
    totals: &mut QualityTrendTotals,
) {
    for current_index in 0..points.len() {
        if !baseline_eligible(&points[current_index]) {
            totals.baseline_unavailable = totals.baseline_unavailable.saturating_add(1);
            totals.regression_unavailable = totals.regression_unavailable.saturating_add(1);
            continue;
        }
        let mut prior_eligible = historical_points
            .iter()
            .filter(|point| {
                baseline_eligible(point)
                    && (point.evaluation_time_ms, point.operation_id.as_str())
                        < (
                            points[current_index].evaluation_time_ms,
                            points[current_index].operation_id.as_str(),
                        )
            })
            .cloned()
            .collect::<Vec<_>>();
        prior_eligible.extend(
            points[..current_index]
                .iter()
                .filter(|point| baseline_eligible(point))
                .cloned(),
        );
        prior_eligible.sort_by(|left, right| {
            left.evaluation_time_ms
                .cmp(&right.evaluation_time_ms)
                .then_with(|| left.operation_id.cmp(&right.operation_id))
        });
        let baseline = prior_eligible
            .iter()
            .rev()
            .find(|candidate| comparable(candidate, &points[current_index]))
            .cloned();
        let Some(baseline) = baseline else {
            if !baseline_history_complete {
                points[current_index].baseline_state = BASELINE_UNAVAILABLE.into();
                totals.baseline_unavailable = totals.baseline_unavailable.saturating_add(1);
            } else if prior_eligible.is_empty() {
                points[current_index].baseline_state = BASELINE_MISSING.into();
                totals.baseline_missing = totals.baseline_missing.saturating_add(1);
            } else {
                points[current_index].baseline_state = BASELINE_INCOMPARABLE.into();
                totals.baseline_incomparable = totals.baseline_incomparable.saturating_add(1);
            }
            totals.regression_unavailable = totals.regression_unavailable.saturating_add(1);
            continue;
        };

        let current = &mut points[current_index];
        current.baseline_state = BASELINE_COMPARED.into();
        current.baseline_operation_id = Some(baseline.operation_id.clone());
        current.mean_score_delta_micros =
            signed_delta(current.mean_score_micros, baseline.mean_score_micros);
        current.pass_rate_delta_basis_points = signed_delta(
            current.pass_rate_basis_points,
            baseline.pass_rate_basis_points,
        );
        current.variance_delta_micros_squared = signed_delta_i128(
            current.score_variance_micros_squared,
            baseline.score_variance_micros_squared,
        );
        current.regression = classify_regression(&baseline, current).into();
        totals.baseline_compared = totals.baseline_compared.saturating_add(1);
        match current.regression.as_str() {
            REGRESSION_REGRESSED => totals.regressed = totals.regressed.saturating_add(1),
            REGRESSION_IMPROVED => totals.improved = totals.improved.saturating_add(1),
            REGRESSION_UNCHANGED => totals.unchanged = totals.unchanged.saturating_add(1),
            _ => totals.regression_unavailable = totals.regression_unavailable.saturating_add(1),
        }
    }
}

fn baseline_eligible(point: &QualityTrendPoint) -> bool {
    matches!(
        point.execution_status.as_str(),
        VERDICT_ALLOW | VERDICT_DENY | VERDICT_UNKNOWN | VERDICT_UNAVAILABLE
    ) && point.gate_reason_code != REASON_EXECUTION_CANCELLED
        && point.population_state != POPULATION_LOW_SAMPLE
        && point.population_state != POPULATION_MISSING
}

fn comparable(baseline: &QualityTrendPoint, current: &QualityTrendPoint) -> bool {
    if baseline.evaluator_input_digest != current.evaluator_input_digest
        || baseline.subject_content_digest != current.subject_content_digest
        || baseline.evidence_set_digest != current.evidence_set_digest
        || baseline.dependency_result_set_digest != current.dependency_result_set_digest
    {
        return false;
    }
    match (baseline.trial_count, current.trial_count) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left == right && baseline.aggregation_rule == current.aggregation_rule
        }
        _ => false,
    }
}

fn classify_regression(baseline: &QualityTrendPoint, current: &QualityTrendPoint) -> &'static str {
    let mut worse = (baseline.step_status == STATUS_PASS && current.step_status != STATUS_PASS)
        || (baseline.gate_verdict == VERDICT_ALLOW && current.gate_verdict != VERDICT_ALLOW);
    let mut better = (baseline.step_status != STATUS_PASS && current.step_status == STATUS_PASS)
        || (baseline.gate_verdict != VERDICT_ALLOW && current.gate_verdict == VERDICT_ALLOW);

    if let (Some(left), Some(right)) = (baseline.mean_score_micros, current.mean_score_micros) {
        worse |= right < left;
        better |= right > left;
    }
    if let (Some(left), Some(right)) = (
        baseline.pass_rate_basis_points,
        current.pass_rate_basis_points,
    ) {
        worse |= right < left;
        better |= right > left;
    }
    if let (Some(left), Some(right)) = (
        baseline.score_variance_micros_squared,
        current.score_variance_micros_squared,
    ) {
        worse |= right > left;
        better |= right < left;
    }

    match (worse, better) {
        (true, false) => REGRESSION_REGRESSED,
        (false, true) => REGRESSION_IMPROVED,
        (false, false)
            if baseline.step_status == current.step_status
                && baseline.gate_verdict == current.gate_verdict =>
        {
            REGRESSION_UNCHANGED
        }
        _ => REGRESSION_UNAVAILABLE,
    }
}

fn signed_delta<T>(current: Option<T>, baseline: Option<T>) -> Option<i64>
where
    T: Into<i64> + Copy,
{
    Some(current?.into().saturating_sub(baseline?.into()))
}

fn signed_delta_i128(current: Option<u64>, baseline: Option<u64>) -> Option<i128> {
    Some(i128::from(current?).saturating_sub(i128::from(baseline?)))
}

fn digest_values(values: &[String]) -> Result<String, String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    let bytes = serde_json::to_vec(&values).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn semantic_digest(report: &QualityTrendReport) -> Result<String, String> {
    let bytes = serde_json::to_vec(&(
        report.version.as_str(),
        report.source_receipt_version.as_str(),
        report.authority.as_str(),
        report.namespace.as_str(),
        report.since_ms,
        report.until_ms,
        &report.totals,
        &report.series,
    ))
    .map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_execution::{
        EvaluationGateDecision, StochasticStepEvidence, StochasticTrialEvidence,
    };
    use crate::chisei::evaluation_manifest::{
        ResolvedEvaluationManifest, ResolvedEvaluationNode, ResolvedEvaluatorBinding,
    };
    use crate::domain::Object;
    use crate::sekai::security::{Grant, Role};
    use std::collections::HashMap;

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn manifest(manifest_digest: &str, evaluation_time_ms: i64) -> ResolvedEvaluationManifest {
        ResolvedEvaluationManifest {
            contract_version: "chisei.resolved-evaluation-manifest/v1".into(),
            resolver_version: "chisei.evaluation-resolver/v1".into(),
            manifest_id: format!("manifest-{evaluation_time_ms}"),
            manifest_digest: manifest_digest.into(),
            namespace: "acme".into(),
            plan_version_id: "plan-v1".into(),
            plan_digest: digest('p'),
            subject_profile: "example.dataset/v1".into(),
            subject_identity: "secret-subject".into(),
            subject_content_digest: digest('s'),
            invariant_set_id: "invariants-v1".into(),
            invariant_set_digest: digest('i'),
            invariant_profile_digest: digest('j'),
            evaluation_time_ms,
            resolved_by: "resolver".into(),
            requirements: vec![],
            nodes: vec![ResolvedEvaluationNode {
                node_id: "quality".into(),
                evaluator: ResolvedEvaluatorBinding {
                    definition_id: "definition-v1".into(),
                    definition_digest: digest('d'),
                    implementation_digest: digest('m'),
                    stochastic_policy: None,
                },
                depends_on_node_ids: vec![],
                input_bindings: vec![],
                parameters_json: "{}".into(),
                invariants: vec![],
                evidence_object_ids: vec![],
                classification: "required".into(),
            }],
            evidence: vec![],
            waivers: vec![],
            created_at_ms: evaluation_time_ms,
        }
    }

    fn step(manifest_digest: &str, status: &str) -> EvaluationStepReceipt {
        EvaluationStepReceipt {
            contract_version: "chisei.evaluation-step-receipt/v1".into(),
            manifest_digest: manifest_digest.into(),
            node_id: "quality".into(),
            classification: "required".into(),
            status: status.into(),
            reason_code: format!("quality_{status}"),
            input_digest: digest('n'),
            parameters_digest: digest('o'),
            evaluator_definition_digest: digest('d'),
            implementation_digest: digest('m'),
            evidence_digests: vec![digest('e')],
            dependency_result_digests: vec![],
            result_digest: digest('r'),
            stochastic_evidence: None,
            step_receipt_digest: digest('t'),
        }
    }

    fn source(operation: &str, timestamp: i64, status: &str) -> EvaluatedReceipt {
        let manifest_digest = digest(if status == STATUS_PASS { 'a' } else { 'b' });
        let manifest = manifest(&manifest_digest, timestamp);
        let verdict = if status == STATUS_PASS {
            VERDICT_ALLOW
        } else {
            VERDICT_DENY
        };
        let projection = EvaluationExecutionProjection {
            manifest_digest: manifest_digest.clone(),
            operation_id: operation.into(),
            namespace: "acme".into(),
            status: verdict.into(),
            steps: vec![step(&manifest_digest, status)],
            decision: Some(EvaluationGateDecision {
                contract_version: "chisei.evaluation-gate-decision/v1".into(),
                manifest_digest: manifest_digest.clone(),
                reducer: "required_all_pass_advisory_observed/v1".into(),
                verdict: verdict.into(),
                reason_code: format!("gate_{verdict}"),
                step_receipt_digests: vec![digest('t')],
                invariant_coverage: vec![],
                decision_digest: digest('g'),
            }),
        };
        EvaluatedReceipt::Valid {
            receipt: Box::new(OperationReceipt {
                version: OPERATION_RECEIPT_VERSION.into(),
                operation_id: operation.into(),
                parent_operation_id: None,
                namespace: "acme".into(),
                operation_class: EXECUTION_OPERATION_CLASS.into(),
                initiating_actor: "agent-a".into(),
                schema_version: "test/v1".into(),
                policy_version: "test/v1".into(),
                started_at_ms: timestamp,
                completed_at_ms: Some(timestamp + 1),
                events: vec![],
                uncovered_surfaces: vec![],
                reporter_grants: vec![],
                ontology_digest: None,
                artifact: None,
            }),
            manifest: Box::new(manifest),
            projection: Box::new(projection),
        }
    }

    #[test]
    fn trends_reconcile_and_regression_uses_exact_prior_receipt() {
        let report = build_report(
            "acme",
            0,
            1_000,
            3,
            vec![
                source("allow", 100, STATUS_PASS),
                source("deny", 200, STATUS_FAIL),
            ],
            vec![],
        )
        .unwrap();

        assert_eq!(report.totals.receipts_scanned, 3);
        assert_eq!(report.totals.ignored_non_evaluation_receipts, 1);
        assert_eq!(report.totals.evaluation_receipts, 2);
        assert_eq!(report.totals.allow, 1);
        assert_eq!(report.totals.deny, 1);
        assert_eq!(report.totals.baseline_missing, 1);
        assert_eq!(report.totals.baseline_compared, 1);
        assert_eq!(report.totals.regressed, 1);
        assert_eq!(report.series[0].points[1].regression, REGRESSION_REGRESSED);
        assert_eq!(
            report.series[0].points[1].baseline_operation_id.as_deref(),
            Some("allow")
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("secret-subject"));
        assert!(json.contains(DIMENSION_HIDDEN));
    }

    #[test]
    fn baseline_history_is_compared_without_entering_window_totals() {
        let report = build_report(
            "acme",
            100,
            1_000,
            1,
            vec![source("current", 200, STATUS_FAIL)],
            vec![source("historical-baseline", 90, STATUS_PASS)],
        )
        .unwrap();

        assert_eq!(report.totals.receipts_scanned, 1);
        assert_eq!(report.totals.evaluation_receipts, 1);
        assert_eq!(report.totals.deny, 1);
        assert_eq!(report.totals.allow, 0);
        assert_eq!(report.totals.baseline_history_receipts, 1);
        assert_eq!(report.totals.baseline_history_valid_executions, 1);
        assert_eq!(report.totals.baseline_compared, 1);
        assert_eq!(report.totals.baseline_missing, 0);
        assert_eq!(
            report.series[0].points[0].baseline_operation_id.as_deref(),
            Some("historical-baseline")
        );
        assert_eq!(report.series[0].points[0].regression, REGRESSION_REGRESSED);
    }

    #[test]
    fn incomplete_baseline_history_stays_unavailable_not_missing() {
        let report = build_report(
            "acme",
            100,
            1_000,
            1,
            vec![source("current", 200, STATUS_PASS)],
            vec![EvaluatedReceipt::Missing],
        )
        .unwrap();
        assert_eq!(report.totals.baseline_history_missing_dependencies, 1);
        assert_eq!(report.totals.baseline_unavailable, 1);
        assert_eq!(report.totals.baseline_missing, 0);
        assert_eq!(
            report.series[0].points[0].baseline_state,
            BASELINE_UNAVAILABLE
        );
        assert_eq!(
            report.series[0].points[0].regression,
            REGRESSION_UNAVAILABLE
        );
    }

    #[test]
    fn baselines_follow_manifest_evaluation_time_not_execution_start() {
        let mut earlier_evaluation = source("earlier-evaluation", 200, STATUS_PASS);
        let EvaluatedReceipt::Valid { manifest, .. } = &mut earlier_evaluation else {
            unreachable!()
        };
        manifest.evaluation_time_ms = 100;
        let mut later_evaluation = source("later-evaluation", 100, STATUS_FAIL);
        let EvaluatedReceipt::Valid { manifest, .. } = &mut later_evaluation else {
            unreachable!()
        };
        manifest.evaluation_time_ms = 200;

        let report = build_report(
            "acme",
            0,
            1_000,
            2,
            vec![later_evaluation, earlier_evaluation],
            vec![],
        )
        .unwrap();
        let points = &report.series[0].points;
        assert_eq!(points[0].operation_id, "earlier-evaluation");
        assert_eq!(points[1].operation_id, "later-evaluation");
        assert_eq!(
            points[1].baseline_operation_id.as_deref(),
            Some("earlier-evaluation")
        );
        assert_eq!(points[1].regression, REGRESSION_REGRESSED);
    }

    #[test]
    fn dependency_result_changes_make_baselines_incomparable() {
        let earlier = source("earlier", 100, STATUS_PASS);
        let mut later = source("later", 200, STATUS_FAIL);
        let EvaluatedReceipt::Valid { projection, .. } = &mut later else {
            unreachable!()
        };
        projection.steps[0].input_digest = digest('v');
        projection.steps[0].dependency_result_digests = vec![digest('u')];

        let report = build_report("acme", 0, 1_000, 2, vec![earlier, later], vec![]).unwrap();

        assert_eq!(report.totals.baseline_missing, 1);
        assert_eq!(report.totals.baseline_incomparable, 1);
        assert_eq!(report.totals.baseline_compared, 0);
        assert_eq!(
            report.series[0].points[1].baseline_state,
            BASELINE_INCOMPARABLE
        );
        assert_eq!(
            report.series[0].points[1].regression,
            REGRESSION_UNAVAILABLE
        );
    }

    #[test]
    fn missing_invalid_and_low_sample_never_become_pass() {
        let mut low_sample = source("partial", 100, STATUS_FAIL);
        let EvaluatedReceipt::Valid {
            projection,
            manifest,
            ..
        } = &mut low_sample
        else {
            unreachable!()
        };
        projection.status = VERDICT_UNAVAILABLE.into();
        projection.decision.as_mut().unwrap().verdict = VERDICT_UNAVAILABLE.into();
        projection.steps[0].status = STATUS_UNAVAILABLE.into();
        projection.steps[0].stochastic_evidence = Some(StochasticStepEvidence {
            contract_version: "chisei.stochastic-step-evidence/v1".into(),
            provider: "test-provider".into(),
            model: "test-model".into(),
            prompt_profile: "profile".into(),
            prompt_profile_digest: digest('q'),
            result_schema: "schema".into(),
            trial_count: 4,
            aggregation_rule: "mean_score_with_variance/v1".into(),
            minimum_mean_score_micros: 500_000,
            minimum_pass_rate_basis_points: 7_500,
            maximum_score_variance_micros_squared: 1_000,
            gate_eligible: true,
            completed_trial_count: 2,
            mean_score_micros: 700_000,
            pass_rate_basis_points: 10_000,
            score_variance_micros_squared: 25,
            total_input_tokens: 10,
            total_output_tokens: 4,
            total_retry_accounted_tokens: 0,
            trials: vec![StochasticTrialEvidence {
                trial_index: 0,
                seed: 0,
                attempt_count: 1,
                status: STATUS_PASS.into(),
                reason_code: "criteria_met".into(),
                score_micros: 700_000,
                input_tokens: 5,
                output_tokens: 2,
                retry_accounted_tokens: 0,
                result_digest: digest('x'),
            }],
            aggregate_digest: digest('z'),
        });
        manifest.nodes[0].evaluator.stochastic_policy = None;

        let report = build_report(
            "acme",
            0,
            1_000,
            3,
            vec![
                low_sample,
                EvaluatedReceipt::Missing,
                EvaluatedReceipt::Invalid,
            ],
            vec![],
        )
        .unwrap();
        assert_eq!(report.totals.allow, 0);
        assert_eq!(report.totals.unavailable, 1);
        assert_eq!(report.totals.missing_dependencies, 1);
        assert_eq!(report.totals.invalid_executions, 1);
        assert_eq!(report.totals.stochastic_low_sample_populations, 1);
        assert_eq!(report.totals.partial_executions, 1);
        assert_eq!(report.totals.baseline_unavailable, 1);
        assert_eq!(report.totals.regression_unavailable, 1);
    }

    #[test]
    fn terminal_cancellation_stays_cancelled_and_partial() {
        let mut cancelled = source("cancelled", 100, STATUS_PASS);
        let EvaluatedReceipt::Valid { projection, .. } = &mut cancelled else {
            unreachable!()
        };
        projection.status = VERDICT_UNAVAILABLE.into();
        let decision = projection.decision.as_mut().unwrap();
        decision.verdict = VERDICT_UNAVAILABLE.into();
        decision.reason_code = REASON_EXECUTION_CANCELLED.into();
        projection.steps[0].status = STATUS_SKIPPED.into();
        projection.steps[0].reason_code = REASON_EXECUTION_CANCELLED.into();

        let report = build_report("acme", 0, 1_000, 1, vec![cancelled], vec![]).unwrap();

        assert_eq!(report.totals.cancelled, 1);
        assert_eq!(report.totals.unavailable, 0);
        assert_eq!(report.totals.partial_executions, 1);
        assert_eq!(
            report.series[0].points[0].execution_status,
            STATUS_CANCELLED
        );
        assert_eq!(report.series[0].points[0].gate_verdict, VERDICT_UNAVAILABLE);
        assert_eq!(
            report.series[0].points[0].gate_reason_code,
            REASON_EXECUTION_CANCELLED
        );
    }

    #[test]
    fn namespace_access_is_checked_before_receipt_listing() {
        let db = RuntimeDb::memory();
        db.create_object(&Object {
            id: "namespace-acme".into(),
            kind: "namespace".into(),
            name: "acme".into(),
            namespace: String::new(),
            external_id: "namespace:acme".into(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_grant(&Grant {
            id: "grant-acme-alice".into(),
            object_id: "namespace-acme".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 1,
        })
        .unwrap();

        assert_eq!(
            query_quality_trends(&db, "mallory", "acme", 0, 100).unwrap_err(),
            "namespace access denied"
        );
        let report = query_quality_trends(&db, "alice", "acme", 0, 100).unwrap();
        assert_eq!(report.totals.receipts_scanned, 0);
        assert_eq!(report.totals.evaluation_receipts, 0);
    }

    #[test]
    fn semantic_digest_is_stable_for_the_same_authorized_receipts() {
        let first = build_report(
            "acme",
            0,
            1_000,
            1,
            vec![source("allow", 100, STATUS_PASS)],
            vec![],
        )
        .unwrap();
        let second = build_report(
            "acme",
            0,
            1_000,
            1,
            vec![source("allow", 100, STATUS_PASS)],
            vec![],
        )
        .unwrap();
        assert_eq!(first.semantic_digest, second.semantic_digest);
    }

    #[test]
    fn manifest_digest_requires_one_consistent_intent_binding() {
        let mut receipt = match source("allow", 100, STATUS_PASS) {
            EvaluatedReceipt::Valid { receipt, .. } => receipt,
            _ => unreachable!(),
        };
        receipt
            .events
            .push(crate::chisei::receipt::OperationReceiptEvent {
                event_id: "intent".into(),
                operation_id: receipt.operation_id.clone(),
                parent_event_id: None,
                timestamp_ms: 100,
                kind: ReceiptEventKind::IntentRecorded,
                surface: ReceiptEventKind::IntentRecorded.surface(),
                actor: "agent-a".into(),
                references: vec![],
                attributes: BTreeMap::from([("manifest_digest".into(), digest('a'))]),
            });
        assert_eq!(manifest_digest_from_receipt(&receipt), Some(digest('a')));
        receipt
            .events
            .push(crate::chisei::receipt::OperationReceiptEvent {
                event_id: "intent-conflict".into(),
                operation_id: receipt.operation_id.clone(),
                parent_event_id: None,
                timestamp_ms: 101,
                kind: ReceiptEventKind::IntentRecorded,
                surface: ReceiptEventKind::IntentRecorded.surface(),
                actor: "agent-a".into(),
                references: vec![],
                attributes: BTreeMap::from([("manifest_digest".into(), digest('b'))]),
            });
        assert_eq!(manifest_digest_from_receipt(&receipt), None);
    }
}
