//! Eval dataset run views for the operator console (#2639).
//!
//! `/evals` shows a pass-rate trend per dataset with its most recent runs;
//! `/evals/{run_id}` leads with the run against its baseline (regressions
//! grouped by recorded reason code) and folds the full case table below.
//! Both read the namespace's recorded runs through the same store reads the
//! trend and compare calls use; nothing here starts, gates, or changes a run.

use std::collections::{BTreeMap, HashMap};

use crate::chisei::eval_compare::{
    CaseDifference, ComparedRun, ComparisonGate, RunComparison, RunTrendPoint, case_differences,
    compare_runs, trend_point,
};
use crate::chisei::eval_dataset::{DatasetSources, EvalDataset, datasets_directory};
use crate::chisei::eval_run::{EvalCaseResult, EvalRunSpec, EvalRunStore};
use crate::db::runtime_db::RuntimeDb;
use crate::ext::EvalRunRuntimeDbExt;
use crate::obs::console::{escape_html, is_safe_namespace, principal_can_access_namespace};

/// Most recent runs the list page reads per namespace.
pub const RUN_LIST_LIMIT: usize = 50;
/// Points in each dataset's trend line.
const TREND_POINTS: usize = 20;
/// Earlier runs the run page reads, newest first, to find a complete baseline.
const BASELINE_CANDIDATES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvalViewError {
    InvalidNamespace,
    NamespaceDenied,
    /// This process has no Chisei store to read runs from.
    Unavailable,
    NotFound,
    Internal,
}

impl EvalViewError {
    pub fn status(self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::InvalidNamespace => StatusCode::BAD_REQUEST,
            Self::NamespaceDenied => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidNamespace => "Invalid namespace identifier.",
            Self::NamespaceDenied => "Namespace access denied.",
            Self::Unavailable => "Eval results are not available on this console.",
            Self::NotFound => "Eval run not found.",
            Self::Internal => "Failed to load eval runs.",
        }
    }
}

/// One run as the list shows it.
pub struct RunRow {
    pub point: RunTrendPoint,
    pub spend_micros: i64,
    /// Cases in the run's dataset version; `None` when it no longer resolves.
    pub cases_total: Option<u64>,
}

/// A dataset's runs, newest first.
pub struct DatasetRuns {
    pub dataset: String,
    pub runs: Vec<RunRow>,
}

pub struct EvalHome {
    pub namespace: String,
    pub datasets: Vec<DatasetRuns>,
}

/// The baseline run and how the viewed run compares with it.
pub struct Compared {
    pub spec: EvalRunSpec,
    pub results: Vec<EvalCaseResult>,
    pub comparison: RunComparison,
    pub differences: Vec<CaseDifference>,
}

/// The run against its baseline, or why there is no comparison.
#[non_exhaustive]
pub enum Baseline {
    Compared(Box<Compared>),
    Missing(&'static str),
}

pub struct EvalRunView {
    pub namespace: String,
    pub spec: EvalRunSpec,
    pub results: Vec<EvalCaseResult>,
    pub cases_total: Option<u64>,
    pub baseline: Baseline,
}

/// Namespace access is granted on the Sekai store; runs live in Chisei's.
fn authorize<'a>(
    db: &RuntimeDb,
    chisei_db: Option<&'a RuntimeDb>,
    principal: &str,
    namespace: &str,
) -> Result<&'a RuntimeDb, EvalViewError> {
    if !is_safe_namespace(namespace) {
        return Err(EvalViewError::InvalidNamespace);
    }
    let allowed = principal_can_access_namespace(db, principal, namespace)
        .map_err(|_| EvalViewError::Internal)?;
    if !allowed {
        return Err(EvalViewError::NamespaceDenied);
    }
    chisei_db.ok_or(EvalViewError::Unavailable)
}

/// Resolves each `(dataset, version)` once per page load.
struct Datasets<'a> {
    store: &'a RuntimeDb,
    namespace: &'a str,
    resolved: HashMap<(String, String), Option<EvalDataset>>,
}

impl<'a> Datasets<'a> {
    fn new(store: &'a RuntimeDb, namespace: &'a str) -> Self {
        Self {
            store,
            namespace,
            resolved: HashMap::new(),
        }
    }

    fn get(&mut self, spec: &EvalRunSpec) -> Option<&EvalDataset> {
        let (store, namespace) = (self.store, self.namespace);
        self.resolved
            .entry((spec.dataset.clone(), spec.dataset_version.clone()))
            .or_insert_with(|| {
                let directory = datasets_directory();
                DatasetSources {
                    directory: directory.as_deref(),
                    store,
                    namespace,
                }
                .resolve(&spec.dataset, &spec.dataset_version)
                .ok()
            })
            .as_ref()
    }
}

fn spend(results: &[EvalCaseResult]) -> i64 {
    results
        .iter()
        .map(|result| result.outcome.cost_micros)
        .sum()
}

pub fn load_home(
    db: &RuntimeDb,
    chisei_db: Option<&RuntimeDb>,
    principal: &str,
    namespace: &str,
) -> Result<EvalHome, EvalViewError> {
    let store = authorize(db, chisei_db, principal, namespace)?;
    let mut runs = store
        .list_dataset_runs(namespace)
        .map_err(|_| EvalViewError::Internal)?;
    runs.sort_by(|(a, at), (b, bt)| bt.cmp(at).then_with(|| b.run_id.cmp(&a.run_id)));
    runs.truncate(RUN_LIST_LIMIT);
    let mut datasets = Datasets::new(store, namespace);
    let mut by_dataset: BTreeMap<String, Vec<RunRow>> = BTreeMap::new();
    for (spec, started_at_ms) in runs {
        let results = store
            .list_dataset_run_cases(namespace, &spec.run_id)
            .map_err(|_| EvalViewError::Internal)?;
        let cases_total = datasets
            .get(&spec)
            .map(|dataset| dataset.cases.len() as u64);
        by_dataset
            .entry(spec.dataset.clone())
            .or_default()
            .push(RunRow {
                point: trend_point(&spec, started_at_ms, &results),
                spend_micros: spend(&results),
                cases_total,
            });
    }
    Ok(EvalHome {
        namespace: namespace.into(),
        datasets: by_dataset
            .into_iter()
            .map(|(dataset, runs)| DatasetRuns { dataset, runs })
            .collect(),
    })
}

/// `baseline_run_id` picks the baseline; without it, the latest earlier run of
/// the same dataset version under the same evaluator.
pub fn load_run(
    db: &RuntimeDb,
    chisei_db: Option<&RuntimeDb>,
    principal: &str,
    namespace: &str,
    run_id: &str,
    baseline_run_id: Option<&str>,
) -> Result<EvalRunView, EvalViewError> {
    let store = authorize(db, chisei_db, principal, namespace)?;
    let runs = store
        .list_dataset_runs(namespace)
        .map_err(|_| EvalViewError::Internal)?;
    let (spec, started_at_ms) = runs
        .iter()
        .find(|(spec, _)| spec.run_id == run_id)
        .cloned()
        .ok_or(EvalViewError::NotFound)?;
    let cases = |spec: &EvalRunSpec| {
        store
            .list_dataset_run_cases(namespace, &spec.run_id)
            .map_err(|_| EvalViewError::Internal)
    };
    let results = cases(&spec)?;
    let mut datasets = Datasets::new(store, namespace);
    let dataset = datasets.get(&spec).cloned();

    let comparable = |other: &EvalRunSpec| {
        other.dataset == spec.dataset
            && other.dataset_version == spec.dataset_version
            && other.evaluator_definition_id == spec.evaluator_definition_id
            && other.evaluator_digest == spec.evaluator_digest
    };
    let covers = |results: &[EvalCaseResult]| {
        dataset.as_ref().is_some_and(|dataset| {
            let recorded: std::collections::HashSet<&str> =
                results.iter().map(|r| r.case_id.as_str()).collect();
            dataset
                .cases
                .iter()
                .all(|case| recorded.contains(case.case_id.as_str()))
        })
    };
    let picked: Result<(EvalRunSpec, Vec<EvalCaseResult>), &'static str> = match baseline_run_id
        .filter(|id| !id.is_empty())
    {
        Some(id) if id == spec.run_id => Err("A run cannot be its own baseline."),
        Some(id) => match runs.iter().find(|(other, _)| other.run_id == id) {
            Some((other, _)) => Ok((other.clone(), cases(other)?)),
            None => Err("Baseline run not found."),
        },
        // The latest earlier complete run: an aborted or still-recording
        // predecessor cannot be compared and is skipped.
        None => {
            let mut earlier: Vec<_> = runs
                .iter()
                .filter(|(other, at)| {
                    other.run_id != spec.run_id
                        && comparable(other)
                        && (*at, other.run_id.as_str()) < (started_at_ms, spec.run_id.as_str())
                })
                .collect();
            earlier.sort_by(|(a, at), (b, bt)| bt.cmp(at).then_with(|| b.run_id.cmp(&a.run_id)));
            let mut found = None;
            for (other, _) in earlier.into_iter().take(BASELINE_CANDIDATES) {
                let before = cases(other)?;
                if covers(&before) {
                    found = Some((other.clone(), before));
                    break;
                }
            }
            found.ok_or("No earlier complete run of this dataset version under the same evaluator.")
        }
    };
    let baseline = match (picked, &dataset) {
        (Err(why), _) => Baseline::Missing(why),
        (Ok(_), None) => Baseline::Missing("This dataset version no longer resolves."),
        (Ok((baseline, before)), Some(dataset)) => {
            let (base_run, run) = (
                ComparedRun {
                    spec: &baseline,
                    results: &before,
                },
                ComparedRun {
                    spec: &spec,
                    results: &results,
                },
            );
            // Only read when `compare_runs` accepts the pair.
            let differences = case_differences(dataset, &base_run, &run);
            match compare_runs(dataset, base_run, run, ComparisonGate::default()) {
                Ok(comparison) => Baseline::Compared(Box::new(Compared {
                    spec: baseline,
                    results: before,
                    comparison,
                    differences,
                })),
                Err(_) => Baseline::Missing(
                    "Not comparable: both runs need a result for every case of the same dataset version under the same evaluator.",
                ),
            }
        }
    };
    Ok(EvalRunView {
        namespace: namespace.into(),
        cases_total: dataset.map(|dataset| dataset.cases.len() as u64),
        spec,
        results,
        baseline,
    })
}

/// A path segment: run ids are caller-chosen strings.
fn encode_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn usd(micros: i64) -> String {
    let sign = if micros < 0 { "-" } else { "" };
    let cents = micros.unsigned_abs().div_ceil(10_000);
    format!("{sign}${}.{:02}", cents / 100, cents % 100)
}

fn percent(passed: u64, of: u64) -> String {
    if of == 0 {
        return "n/a".into();
    }
    format!("{:.1}%", passed as f64 * 100.0 / of as f64)
}

/// `marking_leak` reads as "marking leak".
fn kind_label(kind: &str) -> String {
    kind.replace('_', " ")
}

fn status(recorded: u64, total: Option<u64>) -> (&'static str, &'static str) {
    match total {
        Some(total) if recorded >= total => ("Complete", ""),
        Some(_) => ("Incomplete", "warn"),
        None => ("Unknown", "warn"),
    }
}

/// A static pass-rate line over the latest complete runs, oldest left; a run
/// still recording would plot a pass rate over a few cases.
fn trend_svg(runs: &[RunRow]) -> String {
    let mut points: Vec<(&str, f64)> = runs
        .iter()
        .filter(|row| {
            row.point.cases_recorded > 0
                && row
                    .cases_total
                    .is_some_and(|total| row.point.cases_recorded >= total)
        })
        .take(TREND_POINTS)
        .map(|row| {
            (
                row.point.run_id.as_str(),
                row.point.cases_passed as f64 * 100.0 / row.point.cases_recorded as f64,
            )
        })
        .collect();
    if points.len() < 2 {
        return String::new();
    }
    points.reverse();
    let (low, high) = points
        .iter()
        .fold((100.0_f64, 0.0_f64), |(lo, hi), (_, rate)| {
            (lo.min(*rate), hi.max(*rate))
        });
    let (low, high) = ((low - 1.0).max(0.0).floor(), (high + 1.0).min(100.0).ceil());
    let span = (high - low).max(1.0);
    let (width, top, bottom) = (320.0, 8.0, 52.0);
    let step = (width - 60.0) / (points.len() - 1) as f64;
    let xy: Vec<(f64, f64)> = points
        .iter()
        .enumerate()
        .map(|(i, (_, rate))| {
            (
                30.0 + i as f64 * step,
                bottom - (rate - low) / span * (bottom - top),
            )
        })
        .collect();
    let polyline = xy
        .iter()
        .map(|(x, y)| format!("{x:.1},{y:.1}"))
        .collect::<Vec<_>>()
        .join(" ");
    let (last_x, last_y) = xy[xy.len() - 1];
    let (first, last) = (points[0], points[points.len() - 1]);
    format!(
        r##"<p class="meta">Pass rate, last {n} complete runs</p><svg class="eval-trend" viewBox="0 0 {width} 60" role="img" aria-label="Pass rate over {n} runs, {first:.1}% at {first_id} to {last:.1}% at {last_id}">
<line x1="0" y1="{bottom}" x2="{width}" y2="{bottom}" stroke="currentColor" stroke-opacity="0.25"/>
<polyline fill="none" stroke="currentColor" stroke-width="1.5" points="{polyline}"/>
<circle cx="{last_x:.1}" cy="{last_y:.1}" r="3"/>
<text x="0" y="12" font-size="9">{high:.0}%</text>
<text x="0" y="58" font-size="9">{low:.0}%</text>
</svg>"##,
        n = points.len(),
        first = first.1,
        first_id = escape_html(first.0),
        last = last.1,
        last_id = escape_html(last.0),
    )
}

pub fn render_home(home: &EvalHome) -> String {
    let ns = escape_html(&home.namespace);
    let mut body = String::new();
    if home.datasets.is_empty() {
        body.push_str(
            "<p>No eval runs in this namespace. Start one with <code>sekaictl eval dataset run</code>.</p>",
        );
    }
    for dataset in &home.datasets {
        body.push_str(&format!(
            r#"<h2>{name}</h2>{trend}<div class="table-wrap"><table class="ops-table"><thead><tr><th>Run</th><th>Agent</th><th>Model</th><th>Version</th><th>Status</th><th class="num">Pass</th><th class="num">Policy</th><th class="num">Spend</th></tr></thead><tbody>"#,
            name = escape_html(&dataset.dataset),
            trend = trend_svg(&dataset.runs),
        ));
        for row in &dataset.runs {
            let point = &row.point;
            let (status, status_class) = status(point.cases_recorded, row.cases_total);
            let violations: u64 = point.policy.values().sum();
            body.push_str(&format!(
                r#"<tr><td><a href="/console/n/{ns}/evals/{href}">{id}</a></td><td>{agent}</td><td>{model}</td><td><code>{version}</code></td><td class="{status_class}">{status}</td><td class="num">{pass} <span class="meta">{passed}/{recorded}</span></td><td class="num{policy_class}">{violations}</td><td class="num">{spend}</td></tr>"#,
                href = encode_segment(&point.run_id),
                id = escape_html(&point.run_id),
                agent = escape_html(&point.agent),
                model = escape_html(&point.model),
                version = escape_html(&point.dataset_version),
                pass = percent(point.cases_passed, point.cases_recorded),
                passed = point.cases_passed,
                recorded = point.cases_recorded,
                policy_class = if violations > 0 { " bad" } else { "" },
                spend = usd(row.spend_micros),
            ));
        }
        body.push_str("</tbody></table></div>");
    }
    format!(
        r#"
<section aria-labelledby="evals-heading">
  <h1 id="evals-heading">Evals</h1>
  <p class="meta">Recorded dataset runs in <strong>{ns}</strong>, newest first, up to {limit}. Pass rate is over recorded cases.</p>
  {body}
</section>"#,
        limit = RUN_LIST_LIMIT,
    )
}

fn violations_text(kinds: impl IntoIterator<Item = String>) -> String {
    kinds
        .into_iter()
        .map(|kind| kind_label(&kind))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_comparison(view: &EvalRunView, results: &HashMap<&str, &EvalCaseResult>) -> String {
    let ns = escape_html(&view.namespace);
    let (baseline, before, comparison, differences) = match &view.baseline {
        Baseline::Compared(compared) => (
            &compared.spec,
            &compared.results,
            &compared.comparison,
            &compared.differences,
        ),
        Baseline::Missing(why) => {
            return format!(r#"<p class="meta">No baseline comparison. {why}</p>"#);
        }
    };
    let pass = comparison.verdict == crate::chisei::eval_compare::VERDICT_PASS;
    let baseline_id = escape_html(&baseline.run_id);
    let mut out = format!(
        r#"<p class="verdict {class}">Gate: {verdict} vs <a href="/console/n/{ns}/evals/{href}">{baseline_id}</a></p>"#,
        class = if pass { "ok" } else { "bad" },
        verdict = if pass { "pass" } else { "fail" },
        href = encode_segment(&baseline.run_id),
    );
    for reason in &comparison.reasons {
        out.push_str(&format!(r#"<p class="bad">{}</p>"#, escape_html(reason)));
    }
    let policy: Vec<String> = comparison
        .policy
        .iter()
        .filter(|delta| delta.candidate != delta.baseline)
        .map(|delta| {
            format!(
                r#"<span class="{class}">{kind} {baseline} to {candidate}</span>"#,
                class = if delta.candidate > delta.baseline {
                    "bad"
                } else {
                    "ok"
                },
                kind = escape_html(&kind_label(&delta.kind)),
                baseline = delta.baseline,
                candidate = delta.candidate,
            )
        })
        .collect();
    let baseline_passed = before.iter().filter(|r| r.outcome.passed).count();
    let passed = view.results.iter().filter(|r| r.outcome.passed).count();
    out.push_str(&format!(
        r#"<dl class="kv"><div><dt>Regressions</dt><dd>{regressions}</dd></div><div><dt>Improvements</dt><dd>{improvements}</dd></div><div><dt>Failed in both</dt><dd>{both_failed}</dd></div><div><dt>p</dt><dd>{p:.4} <span class="meta">alpha {alpha}</span></dd></div><div><dt>Pass</dt><dd>{passed}/{cases} <span class="meta">baseline {baseline_passed}</span></dd></div><div><dt>Spend</dt><dd>{spend} <span class="meta">baseline {baseline_spend}</span></dd></div><div><dt>Policy</dt><dd>{policy}</dd></div></dl>"#,
        regressions = comparison.regressions,
        improvements = comparison.improvements,
        both_failed = comparison.both_failed,
        p = comparison.p_value,
        alpha = comparison.alpha,
        cases = comparison.cases,
        spend = usd(spend(&view.results)),
        baseline_spend = usd(spend(before)),
        policy = if policy.is_empty() {
            "unchanged".into()
        } else {
            policy.join(", ")
        },
    ));

    // Regressions grouped by the candidate's recorded reason code; no cause
    // is inferred beyond that (#2631).
    let mut groups: BTreeMap<&str, Vec<&CaseDifference>> = BTreeMap::new();
    for difference in differences
        .iter()
        .filter(|d| d.baseline_passed && !d.candidate_passed)
    {
        let reason = results
            .get(difference.case_id.as_str())
            .map(|result| result.outcome.reason.as_str())
            .filter(|reason| !reason.is_empty())
            .unwrap_or("no reason recorded");
        groups.entry(reason).or_default().push(difference);
    }
    if groups.is_empty() {
        out.push_str("<p>No case regressed against the baseline.</p>");
        return out;
    }
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_by(|(a, x), (b, y)| y.len().cmp(&x.len()).then_with(|| a.cmp(b)));
    let widest = groups[0].1.len();
    out.push_str(r#"<h2>Regressions by reason</h2><div class="table-wrap"><table class="ops-table"><thead><tr><th>Reason</th><th class="num">Cases</th><th></th></tr></thead><tbody>"#);
    for (reason, cases) in &groups {
        out.push_str(&format!(
            r#"<tr><td><code>{reason}</code></td><td class="num">{n}</td><td><span class="eval-bar" style="width:{w}px"></span></td></tr>"#,
            reason = escape_html(reason),
            n = cases.len(),
            w = (cases.len() * 120).div_ceil(widest),
        ));
    }
    out.push_str("</tbody></table></div>");
    for (reason, cases) in &groups {
        let ids = cases
            .iter()
            .map(|difference| {
                let violations = violations_text(
                    difference
                        .candidate_violations
                        .iter()
                        .map(|kind| kind.as_str().to_string()),
                );
                if violations.is_empty() {
                    format!("<code>{}</code>", escape_html(&difference.case_id))
                } else {
                    format!(
                        r#"<code>{}</code> <span class="bad">{}</span>"#,
                        escape_html(&difference.case_id),
                        escape_html(&violations)
                    )
                }
            })
            .collect::<Vec<_>>()
            .join(" · ");
        out.push_str(&format!(
            r#"<h3><code>{reason}</code> · {n}</h3><p class="case-ids">{ids}</p>"#,
            reason = escape_html(reason),
            n = cases.len(),
        ));
    }
    out
}

pub fn render_run(view: &EvalRunView) -> String {
    let ns = escape_html(&view.namespace);
    let spec = &view.spec;
    let results: HashMap<&str, &EvalCaseResult> = view
        .results
        .iter()
        .map(|result| (result.case_id.as_str(), result))
        .collect();
    let comparison = render_comparison(view, &results);
    let recorded = view.results.len() as u64;
    let (status, status_class) = status(recorded, view.cases_total);
    let mut cases = String::new();
    for result in &view.results {
        let outcome = &result.outcome;
        let violations = violations_text(
            outcome
                .policy
                .iter()
                .flat_map(|policy| policy.violations.iter())
                .map(|violation| violation.kind.as_str().to_string()),
        );
        // A case with an operation receipt (#2694) opens its workspace, which
        // applies the receipt ACL; older results render without a link.
        let id = match &result.operation_id {
            Some(operation_id) => format!(
                r#"<a href="/console/n/{ns}/ops/{op}"><code>{id}</code></a>"#,
                op = escape_html(operation_id),
                id = escape_html(&result.case_id),
            ),
            None => format!("<code>{}</code>", escape_html(&result.case_id)),
        };
        cases.push_str(&format!(
            r#"<tr><td>{id}</td><td class="{class}">{verdict}</td><td><code>{reason}</code></td><td class="bad">{violations}</td><td class="num">{tokens}</td><td class="num">{cost}</td></tr>"#,
            class = if outcome.passed { "ok" } else { "bad" },
            verdict = if outcome.passed { "pass" } else { "fail" },
            reason = escape_html(&outcome.reason),
            violations = escape_html(&violations),
            tokens = outcome.input_tokens + outcome.output_tokens,
            cost = usd(outcome.cost_micros),
        ));
    }
    format!(
        r#"
<section aria-labelledby="eval-run-heading">
  <h1 id="eval-run-heading">Eval run <code>{run_id}</code></h1>
  <p><a href="/console/n/{ns}/evals">All eval runs</a></p>
  {comparison}
  <h2>Run</h2>
  <dl class="kv">
    <div><dt>Dataset</dt><dd>{dataset} <code>{version}</code></dd></div>
    <div><dt>Status</dt><dd class="{status_class}">{status} <span class="meta">{recorded}/{total} cases</span></dd></div>
    <div><dt>Agent</dt><dd>{agent}</dd></div>
    <div><dt>Model</dt><dd>{model}</dd></div>
    <div><dt>Tools</dt><dd>{tools}</dd></div>
    <div><dt>Evaluator</dt><dd>{evaluator}</dd></div>
    <div><dt>Budget</dt><dd>{spend} of {budget}</dd></div>
  </dl>
  <details>
    <summary>All {recorded} recorded cases</summary>
    <div class="table-wrap"><table class="ops-table"><thead><tr><th>Case</th><th>Verdict</th><th>Reason</th><th>Policy</th><th class="num">Tokens</th><th class="num">Cost</th></tr></thead><tbody>{cases}</tbody></table></div>
  </details>
</section>"#,
        run_id = escape_html(&spec.run_id),
        dataset = escape_html(&spec.dataset),
        version = escape_html(&spec.dataset_version),
        total = view
            .cases_total
            .map_or_else(|| "?".to_string(), |total| total.to_string()),
        agent = escape_html(&spec.agent),
        model = escape_html(&spec.model),
        tools = escape_html(&spec.tool_version),
        evaluator = escape_html(&spec.evaluator_definition_id),
        spend = usd(spend(&view.results)),
        budget = usd(spec.budget_micros),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::eval_dataset::{EvalDatasetDefinitionStore, StoredEvalDatasetDefinition};
    use crate::chisei::eval_policy::{
        CasePolicyOutcome, POLICY_SCORER_VERSION, Violation, ViolationKind,
    };
    use crate::chisei::eval_run::{CaseOutcome, EVAL_RUN_CONTRACT};
    use crate::db::sekai::SekaiDb;
    use crate::domain::Object;
    use crate::sekai::security::{Grant, Role};
    use std::sync::Arc;

    const DEFINITION: &str = r#"{
        "contract_version": "chisei.eval-dataset-definition/v1",
        "name": "triage",
        "generator": "supply_chain",
        "namespace": "eval-demo",
        "seed": 7,
        "preset": "demo",
        "templates": [{
            "id": "shipment-status",
            "kind": "synthetic_shipment",
            "input_properties": ["tracking"],
            "expected_property": "status"
        }]
    }"#;

    /// Split stores as in production: grants on Sekai's, with `alice` reading
    /// `alpha`; runs on Chisei's, with the `triage` dataset put under `alpha`.
    fn store() -> (Arc<RuntimeDb>, Arc<RuntimeDb>, EvalDataset) {
        let sekai = Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").expect("memory db"),
        )));
        let db = &sekai;
        db.create_object(&Object {
            id: "ns-alpha".into(),
            kind: "namespace".into(),
            name: "alpha".into(),
            namespace: String::new(),
            external_id: "namespace:alpha".into(),
            properties: Default::default(),
            created: 1,
            updated: 1,
        })
        .unwrap();
        db.create_grant(&Grant {
            id: "grant-alpha-alice".into(),
            object_id: "ns-alpha".into(),
            principal: "alice".into(),
            role: Role::Viewer,
            created: 1,
            ..Default::default()
        })
        .unwrap();
        let db = crate::chisei_store::ChiseiStore::memory().runtime_arc();
        let stored = StoredEvalDatasetDefinition::new("alpha", DEFINITION, "test", 1).unwrap();
        db.put_eval_dataset_definition(&stored).unwrap();
        let dataset = DatasetSources {
            directory: None,
            store: db.as_ref(),
            namespace: "alpha",
        }
        .resolve("triage", &stored.version)
        .unwrap();
        (sekai, db, dataset)
    }

    /// Records `run_id` started at `at` with one result per dataset case
    /// `outcome` returns.
    fn record(
        db: &RuntimeDb,
        dataset: &EvalDataset,
        run_id: &str,
        at: i64,
        outcome: impl Fn(usize) -> Option<(bool, &'static str, bool)>,
    ) {
        let spec = EvalRunSpec {
            contract_version: EVAL_RUN_CONTRACT.into(),
            namespace: "alpha".into(),
            run_id: run_id.into(),
            dataset: dataset.name.clone(),
            dataset_version: dataset.version.clone(),
            agent: "triage@1".into(),
            model: "local/m-large".into(),
            tool_version: "tools@1".into(),
            evaluator_definition_id: "status-match".into(),
            evaluator_digest: "digest".into(),
            concurrency: 1,
            budget_micros: 1_000_000,
            max_case_cost_micros: 10_000,
        };
        EvalRunStore::put_dataset_run(db, &spec, at).unwrap();
        assert!(
            EvalRunStore::lease_dataset_run(db, "alpha", run_id, "t", false, at, at + 60_000)
                .unwrap()
        );
        for (index, case) in dataset.cases.iter().enumerate() {
            let Some((passed, reason, leak)) = outcome(index) else {
                continue;
            };
            let result = EvalCaseResult {
                case_id: case.case_id.clone(),
                outcome: CaseOutcome {
                    passed,
                    reason: reason.into(),
                    trial_code: None,
                    unmet_metrics: Vec::new(),
                    input_tokens: 10,
                    output_tokens: 5,
                    cost_micros: 4_000,
                    receipts: None,
                    policy: Some(CasePolicyOutcome {
                        scorer_version: POLICY_SCORER_VERSION.into(),
                        violations: leak
                            .then(|| Violation {
                                kind: ViolationKind::MarkingLeak,
                                case_id: case.case_id.clone(),
                                receipt_id: format!("{}/answer", case.case_id),
                            })
                            .into_iter()
                            .collect(),
                    }),
                },
                recorded_at_ms: at,
                // The first case carries a receipt; the rest read as results
                // recorded before case receipts (#2694).
                operation_id: (index == 0).then(|| format!("eval-case:{run_id}-0")),
            };
            EvalRunStore::record_dataset_run_case(db, "alpha", run_id, "t", &result, 0, at)
                .unwrap()
                .unwrap();
        }
    }

    /// Design rules for operator-visible HTML: no raw errors or internal type
    /// names, and every table scrolls inside its own wrapper on a phone.
    fn assert_operator_html(html: &str) {
        for internal in [
            "RuntimeDb",
            "EvalRunSpec",
            "Status {",
            "Err(",
            "Some(",
            "None",
            "sqlite",
            "corrupt",
            "not found\"",
            "panicked",
            "{",
            "}",
        ] {
            assert!(!html.contains(internal), "{internal:?} in visible HTML");
        }
        assert_eq!(
            html.matches("<table").count(),
            html.matches(r#"<div class="table-wrap"><table"#).count(),
            "every table is wrapped"
        );
    }

    #[test]
    fn a_regressed_run_leads_with_its_baseline_diff_grouped_by_reason() {
        let (sekai, db, dataset) = store();
        assert!(dataset.cases.len() > 6, "demo preset has enough cases");
        record(&db, &dataset, "r41", 100, |_| Some((true, "match", false)));
        // Six regressions: four mismatches (one leaking a marking), two
        // below threshold.
        record(&db, &dataset, "r42", 200, |index| {
            Some(match index {
                0 => (false, "expected_mismatch", true),
                1..=3 => (false, "expected_mismatch", false),
                4 | 5 => (false, "score_below_threshold", false),
                _ => (true, "match", false),
            })
        });
        // Still running: three cases recorded.
        record(&db, &dataset, "r43", 300, |index| {
            (index < 3).then_some((true, "match", false))
        });

        let home = load_home(&sekai, Some(&db), "alice", "alpha").unwrap();
        assert_eq!(home.datasets.len(), 1);
        let runs: Vec<_> = home.datasets[0]
            .runs
            .iter()
            .map(|row| row.point.run_id.as_str())
            .collect();
        assert_eq!(runs, ["r43", "r42", "r41"]);
        let html = render_home(&home);
        assert_operator_html(&html);
        assert!(html.contains("<svg class=\"eval-trend\""));
        assert!(html.contains(">Incomplete<"), "{html}");
        assert!(html.contains(r#"href="/console/n/alpha/evals/r42""#));

        let view = load_run(&sekai, Some(&db), "alice", "alpha", "r42", None).unwrap();
        let Baseline::Compared(ref compared) = view.baseline else {
            panic!("r42 compares with r41");
        };
        let (spec, comparison) = (&compared.spec, &compared.comparison);
        assert_eq!(spec.run_id, "r41");
        assert_eq!(comparison.regressions, 6);
        let html = render_run(&view);
        assert_operator_html(&html);
        assert!(html.contains("Gate: fail vs"), "{html}");
        // Only the case with a receipt links to its operation workspace.
        let first = &dataset.cases[0].case_id;
        assert!(html.contains(&format!(
            r#"<a href="/console/n/alpha/ops/eval-case:r42-0"><code>{first}</code></a>"#
        )));
        assert_eq!(html.matches(r#"href="/console/n/alpha/ops/"#).count(), 1);
        assert!(html.contains("marking leak 0 to 1"));
        let mismatch = html.find("<code>expected_mismatch</code> · 4").unwrap();
        let threshold = html.find("<code>score_below_threshold</code> · 2").unwrap();
        assert!(mismatch < threshold, "largest group first");
        // The diff comes before the folded case table.
        assert!(html.find("Regressions by reason").unwrap() < html.find("<details>").unwrap());

        // An explicit baseline that cannot be compared says why.
        let view = load_run(&sekai, Some(&db), "alice", "alpha", "r42", Some("r43")).unwrap();
        assert!(matches!(view.baseline, Baseline::Missing(_)));
        let html = render_run(&view);
        assert_operator_html(&html);
        assert!(html.contains("Not comparable"));
        let view = load_run(&sekai, Some(&db), "alice", "alpha", "r42", Some("r42")).unwrap();
        assert!(render_run(&view).contains("cannot be its own baseline"));
        // A later run skips the incomplete r43 and compares with r42.
        record(&db, &dataset, "r44", 400, |_| Some((true, "match", false)));
        let view = load_run(&sekai, Some(&db), "alice", "alpha", "r44", None).unwrap();
        let Baseline::Compared(ref compared) = view.baseline else {
            panic!("r44 compares with the latest complete run");
        };
        assert_eq!(compared.spec.run_id, "r42");
        // The first run has nothing earlier to compare with.
        let view = load_run(&sekai, Some(&db), "alice", "alpha", "r41", None).unwrap();
        assert!(render_run(&view).contains("No earlier complete run"));
    }

    #[test]
    fn runs_are_read_only_for_a_principal_with_namespace_access() {
        let (sekai, db, dataset) = store();
        record(&db, &dataset, "r1", 100, |_| Some((true, "match", false)));

        let denied = [
            load_home(&sekai, Some(&db), "bob", "alpha").err(),
            load_run(&sekai, Some(&db), "bob", "alpha", "r1", None).err(),
        ];
        assert_eq!(denied, [Some(EvalViewError::NamespaceDenied); 2]);
        assert_eq!(
            load_home(&sekai, None, "alice", "alpha").err(),
            Some(EvalViewError::Unavailable)
        );
        assert_eq!(
            load_home(&sekai, Some(&db), "alice", "../alpha").err(),
            Some(EvalViewError::InvalidNamespace)
        );
        // A run id from another namespace is not found under this one.
        assert_eq!(
            load_run(&sekai, Some(&db), "root", "beta", "r1", None).err(),
            Some(EvalViewError::NotFound)
        );

        let empty = load_home(&sekai, Some(&db), "root", "beta").unwrap();
        let html = render_home(&empty);
        assert_operator_html(&html);
        assert!(html.contains("No eval runs in this namespace"));
    }

    #[test]
    fn spend_rounds_up_to_the_cent() {
        assert_eq!(usd(0), "$0.00");
        assert_eq!(usd(18_400_000), "$18.40");
        assert_eq!(usd(1), "$0.01");
    }
}
