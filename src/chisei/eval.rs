use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarianceCaseResult {
    pub case_id: String,
    pub run_count: i32,
    pub pass_rate: f64,
    pub mean_score: f64,
    pub min_score: f64,
    pub max_score: f64,
    pub std_dev: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarianceRun {
    pub suite_id: String,
    pub config_ref: String,
    pub run_count: i32,
    pub mean_score: f64,
    pub std_dev: f64,
    pub min_score: f64,
    pub max_score: f64,
    pub cases: Vec<VarianceCaseResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVarianceResult {
    pub model_id: String,
    pub variance: VarianceRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelComparison {
    pub suite_id: String,
    pub models: Vec<ModelVarianceResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    pub assert_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub name: String,
    pub repo: String,
    pub spec: String,
    pub assertions: Vec<Assertion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suite {
    pub id: String,
    pub name: String,
    pub description: String,
    pub cases: Vec<Case>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub case_id: String,
    pub passed: bool,
    pub status: String,
    pub result: String,
    pub score: i32,
    pub reason: String,
    pub elapsed: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: String,
    pub suite_id: String,
    pub config_ref: String,
    pub results: Vec<CaseResult>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Iteration {
    pub id: String,
    pub run_id: String,
    pub suite_id: String,
    pub repo: String,
    pub changed_file: String,
    pub diff_hash: String,
    pub parent_iteration_id: String,
    pub baseline_run_id: String,
    pub candidate_run_id: String,
    pub delta: f64,
    pub regressed: bool,
    pub created: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDecision {
    pub verdict: String,
    pub reason: String,
    pub baseline_score: f64,
    pub candidate_score: f64,
}

pub struct EvalStore {
    suites: Mutex<HashMap<String, Suite>>,
    runs: Mutex<HashMap<String, Run>>,
    iterations: Mutex<HashMap<String, Iteration>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RepoRegressionSignal {
    pub regressed: bool,
    pub reason: String,
    pub iteration: Option<Iteration>,
}

impl Default for EvalStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EvalStore {
    pub fn new() -> Self {
        Self {
            suites: Mutex::new(HashMap::new()),
            runs: Mutex::new(HashMap::new()),
            iterations: Mutex::new(HashMap::new()),
        }
    }

    pub fn create_suite(&self, s: Suite) {
        self.suites.lock().unwrap().insert(s.id.clone(), s);
    }
    pub fn get_suite(&self, id: &str) -> Option<Suite> {
        self.suites.lock().unwrap().get(id).cloned()
    }
    pub fn list_suites(&self) -> Vec<Suite> {
        self.suites.lock().unwrap().values().cloned().collect()
    }

    pub fn create_run(&self, r: Run) {
        self.runs.lock().unwrap().insert(r.id.clone(), r);
    }
    pub fn get_run(&self, id: &str) -> Option<Run> {
        self.runs.lock().unwrap().get(id).cloned()
    }
    pub fn list_runs(&self, suite_id: &str) -> Vec<Run> {
        self.runs
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.suite_id == suite_id)
            .cloned()
            .collect()
    }

    pub fn create_iteration(&self, iteration: Iteration) {
        self.iterations
            .lock()
            .unwrap()
            .insert(iteration.id.clone(), iteration);
    }

    /// Drop all but the newest `keep` runs for a suite from memory (newest by timestamp). Used to
    /// bound the runs a continuous producer (the scoring job) accumulates for its synthetic suites.
    pub fn retain_recent_runs(&self, suite_id: &str, keep: usize) {
        let mut runs = self.runs.lock().unwrap();
        let mut ordered: Vec<(String, i64)> = runs
            .values()
            .filter(|r| r.suite_id == suite_id)
            .map(|r| (r.id.clone(), r.timestamp))
            .collect();
        if ordered.len() <= keep {
            return;
        }
        ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        for (id, _) in ordered.into_iter().skip(keep) {
            runs.remove(&id);
        }
    }

    /// Drop all but the newest `keep` iterations for a suite from memory (newest by `created`).
    pub fn retain_recent_iterations(&self, suite_id: &str, keep: usize) {
        let mut iterations = self.iterations.lock().unwrap();
        let mut ordered: Vec<(String, i64)> = iterations
            .values()
            .filter(|i| i.suite_id == suite_id)
            .map(|i| (i.id.clone(), i.created))
            .collect();
        if ordered.len() <= keep {
            return;
        }
        ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        for (id, _) in ordered.into_iter().skip(keep) {
            iterations.remove(&id);
        }
    }

    pub fn list_iterations(&self, suite_id: &str) -> Vec<Iteration> {
        let mut iterations: Vec<_> = self
            .iterations
            .lock()
            .unwrap()
            .values()
            .filter(|iteration| suite_id.is_empty() || iteration.suite_id == suite_id)
            .cloned()
            .collect();
        iterations.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
        iterations
    }

    pub fn list_iterations_for_file(&self, changed_file: &str) -> Vec<Iteration> {
        let mut iterations: Vec<_> = self
            .iterations
            .lock()
            .unwrap()
            .values()
            .filter(|iteration| iteration.changed_file == changed_file)
            .cloned()
            .collect();
        iterations.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
        iterations
    }

    pub fn latest_iteration_for_file(&self, changed_file: &str) -> Option<Iteration> {
        self.list_iterations_for_file(changed_file)
            .into_iter()
            .next_back()
    }

    pub fn latest_iteration_for_suite_file(
        &self,
        suite_id: &str,
        changed_file: &str,
    ) -> Option<Iteration> {
        self.list_iterations_for_file(changed_file)
            .into_iter()
            .rfind(|iteration| iteration.suite_id == suite_id)
    }

    pub fn track_iteration(
        &self,
        suite_id: &str,
        run_id: &str,
        changed_file: &str,
        diff_hash: &str,
    ) -> Result<Iteration, String> {
        let run = self
            .get_run(run_id)
            .ok_or_else(|| format!("eval run not found: {run_id}"))?;
        if run.suite_id != suite_id {
            return Err(format!(
                "eval run {} belongs to suite {}, not {}",
                run.id, run.suite_id, suite_id
            ));
        }
        let repo = self.infer_iteration_repo(suite_id, &run, changed_file)?;
        let previous = self.latest_iteration_for_suite_file(suite_id, changed_file);
        let mut iteration = Iteration {
            id: format!("iter-{}-{}", run.id, chrono::Utc::now().timestamp_millis()),
            run_id: run.id.clone(),
            suite_id: suite_id.to_string(),
            repo,
            changed_file: changed_file.to_string(),
            diff_hash: diff_hash.to_string(),
            parent_iteration_id: String::new(),
            baseline_run_id: run.id.clone(),
            candidate_run_id: run.id.clone(),
            delta: 0.0,
            regressed: false,
            created: chrono::Utc::now().timestamp_millis(),
        };
        if let Some(previous) = previous {
            let baseline = self
                .get_run(&previous.candidate_run_id)
                .ok_or_else(|| format!("eval run not found: {}", previous.candidate_run_id))?;
            let baseline_score = aggregate_run_score(&baseline);
            let candidate_score = aggregate_run_score(&run);
            iteration.parent_iteration_id = previous.id;
            iteration.baseline_run_id = baseline.id;
            iteration.delta = candidate_score - baseline_score;
            iteration.regressed = iteration.delta < -DEFAULT_REGRESSION_THRESHOLD;
        }
        self.create_iteration(iteration.clone());
        Ok(iteration)
    }

    pub fn repo_regression_signal(&self, repo: &str) -> Option<RepoRegressionSignal> {
        if repo.is_empty() {
            return None;
        }
        let iterations: Vec<_> = self.iterations.lock().unwrap().values().cloned().collect();
        let latest = self
            .iterations_for_repo(&iterations, repo)
            .into_iter()
            .max_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)))?;
        let reason = if latest.regressed {
            format!(
                "latest eval iteration regressed for repo {} on {} (delta {:.1})",
                repo, latest.changed_file, latest.delta
            )
        } else {
            format!(
                "latest eval iteration is stable for repo {} on {} (delta {:.1})",
                repo, latest.changed_file, latest.delta
            )
        };
        Some(RepoRegressionSignal {
            regressed: latest.regressed,
            reason,
            iteration: Some(latest),
        })
    }

    fn iterations_for_repo(&self, iterations: &[Iteration], repo: &str) -> Vec<Iteration> {
        iterations
            .iter()
            .filter(|iteration| self.iteration_matches_repo(iteration, repo))
            .cloned()
            .collect()
    }

    fn iteration_matches_repo(&self, iteration: &Iteration, repo: &str) -> bool {
        if iteration.repo == repo {
            return true;
        }
        if !iteration.repo.is_empty() {
            return false;
        }
        let run = match self.get_run(&iteration.run_id) {
            Some(run) => run,
            None => return false,
        };
        self.infer_iteration_repo(&iteration.suite_id, &run, &iteration.changed_file)
            .map(|inferred_repo| inferred_repo == repo)
            .unwrap_or(false)
    }

    fn infer_iteration_repo(
        &self,
        suite_id: &str,
        run: &Run,
        changed_file: &str,
    ) -> Result<String, String> {
        let suites = self.suites.lock().unwrap();
        let suite = suites
            .get(suite_id)
            .ok_or_else(|| format!("eval suite not found: {suite_id}"))?;
        let mut repos: Vec<String> = run
            .results
            .iter()
            .filter_map(|result| {
                suite
                    .cases
                    .iter()
                    .find(|case| case.id == result.case_id)
                    .map(|case| case.repo.clone())
            })
            .collect();
        repos.sort();
        repos.dedup();
        if repos.len() == 1 {
            return Ok(repos[0].clone());
        }
        let matching: Vec<String> = repos
            .into_iter()
            .filter(|repo| changed_file.contains(repo))
            .collect();
        if matching.len() == 1 {
            Ok(matching[0].clone())
        } else {
            Err(format!(
                "unable to infer repo for iteration in suite {} from file {}",
                suite_id, changed_file
            ))
        }
    }

    pub fn compare_runs(&self, baseline_id: &str, candidate_id: &str) -> Option<GateDecision> {
        let runs = self.runs.lock().unwrap();
        let baseline = runs.get(baseline_id)?;
        let candidate = runs.get(candidate_id)?;
        let b_score = pass_rate(baseline);
        let c_score = pass_rate(candidate);
        let verdict = if c_score >= b_score { "pass" } else { "fail" };
        Some(GateDecision {
            verdict: verdict.into(),
            reason: format!(
                "candidate {:.0}% vs baseline {:.0}%",
                c_score * 100.0,
                b_score * 100.0
            ),
            baseline_score: b_score,
            candidate_score: c_score,
        })
    }

    pub fn variance(&self, suite_id: &str, config_ref: &str) -> VarianceRun {
        let runs = self.list_runs(suite_id);
        analyze_variance(suite_id, config_ref, &runs)
    }

    pub fn model_compare(&self, suite_id: &str) -> ModelComparison {
        let runs = self.list_runs(suite_id);
        compare_models(suite_id, &runs)
    }
}

const DEFAULT_REGRESSION_THRESHOLD: f64 = 10.0;

fn pass_rate(r: &Run) -> f64 {
    if r.results.is_empty() {
        return 0.0;
    }
    let passed = r.results.iter().filter(|c| c.passed).count() as f64;
    passed / r.results.len() as f64
}

fn aggregate_run_score(r: &Run) -> f64 {
    if r.results.is_empty() {
        return 0.0;
    }
    r.results
        .iter()
        .map(|result| result.score as f64)
        .sum::<f64>()
        / r.results.len() as f64
}

pub fn analyze_variance(suite_id: &str, config_ref: &str, runs: &[Run]) -> VarianceRun {
    let filtered: Vec<&Run> = runs
        .iter()
        .filter(|run| config_ref.is_empty() || run.config_ref == config_ref)
        .collect();
    if filtered.is_empty() {
        return VarianceRun {
            suite_id: suite_id.into(),
            config_ref: config_ref.into(),
            run_count: 0,
            mean_score: 0.0,
            std_dev: 0.0,
            min_score: 0.0,
            max_score: 0.0,
            cases: vec![],
        };
    }

    let mut total_score = 0.0;
    let mut min_score = aggregate_run_score(filtered[0]);
    let mut max_score = min_score;
    let mut case_scores: HashMap<String, Vec<f64>> = HashMap::new();
    let mut case_passes: HashMap<String, i32> = HashMap::new();

    for run in &filtered {
        let run_score = aggregate_run_score(run);
        total_score += run_score;
        min_score = min_score.min(run_score);
        max_score = max_score.max(run_score);
        for result in &run.results {
            case_scores
                .entry(result.case_id.clone())
                .or_default()
                .push(result.score as f64);
            if result.passed {
                *case_passes.entry(result.case_id.clone()).or_default() += 1;
            }
        }
    }

    let run_count = filtered.len() as i32;
    let mean_score = total_score / filtered.len() as f64;
    let std_dev = stddev(
        filtered
            .iter()
            .map(|run| aggregate_run_score(run))
            .collect(),
    );

    let mut cases: Vec<VarianceCaseResult> = case_scores
        .into_iter()
        .map(|(case_id, scores)| {
            let run_count = scores.len() as i32;
            let mean_score = scores.iter().sum::<f64>() / scores.len() as f64;
            let min_score = scores.iter().copied().fold(f64::INFINITY, f64::min);
            let max_score = scores.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            VarianceCaseResult {
                case_id: case_id.clone(),
                run_count,
                pass_rate: case_passes.get(&case_id).copied().unwrap_or_default() as f64
                    / scores.len() as f64,
                mean_score,
                min_score,
                max_score,
                std_dev: stddev(scores),
            }
        })
        .collect();
    cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));

    VarianceRun {
        suite_id: suite_id.into(),
        config_ref: config_ref.into(),
        run_count,
        mean_score,
        std_dev,
        min_score,
        max_score,
        cases,
    }
}

pub fn compare_models(suite_id: &str, runs: &[Run]) -> ModelComparison {
    let mut by_model: HashMap<&str, Vec<Run>> = HashMap::new();
    for run in runs {
        by_model
            .entry(&run.config_ref)
            .or_default()
            .push(run.clone());
    }
    let mut models: Vec<ModelVarianceResult> = by_model
        .into_iter()
        .map(|(model_id, model_runs)| ModelVarianceResult {
            model_id: model_id.to_string(),
            variance: analyze_variance(suite_id, model_id, &model_runs),
        })
        .collect();
    models.sort_by(|a, b| a.model_id.cmp(&b.model_id));
    ModelComparison {
        suite_id: suite_id.into(),
        models,
    }
}

fn stddev(values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| {
            let diff = *value - mean;
            diff * diff
        })
        .sum::<f64>()
        / values.len() as f64;
    variance.sqrt()
}

pub fn check_assertions(
    assertions: &[Assertion],
    status: &str,
    result: &str,
    score: i32,
) -> (bool, String) {
    for a in assertions {
        let ok = match a.assert_type.as_str() {
            "status" => status == a.value,
            "contains" => result.contains(&a.value),
            "not_contains" => !result.contains(&a.value),
            "min_score" => score >= a.value.parse().unwrap_or(0),
            _ => true,
        };
        if !ok {
            return (
                false,
                format!("assertion {} failed: expected {:?}", a.assert_type, a.value),
            );
        }
    }
    (true, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_lifecycle() {
        let store = EvalStore::new();
        store.create_suite(Suite {
            id: "s1".into(),
            name: "test".into(),
            description: "".into(),
            cases: vec![Case {
                id: "c1".into(),
                name: "case1".into(),
                repo: "r".into(),
                spec: "s".into(),
                assertions: vec![],
            }],
        });
        assert_eq!(store.list_suites().len(), 1);

        store.create_run(Run {
            id: "r1".into(),
            suite_id: "s1".into(),
            config_ref: "v1".into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 80,
                reason: "".into(),
                elapsed: 100,
            }],
            timestamp: 100,
        });
        store.create_run(Run {
            id: "r2".into(),
            suite_id: "s1".into(),
            config_ref: "v2".into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: false,
                status: "failed".into(),
                result: "err".into(),
                score: 30,
                reason: "broke".into(),
                elapsed: 50,
            }],
            timestamp: 200,
        });

        let gate = store.compare_runs("r1", "r2").unwrap();
        assert_eq!(gate.verdict, "fail");
    }

    #[test]
    fn test_assertions() {
        let (ok, _) = check_assertions(
            &[Assertion {
                assert_type: "status".into(),
                value: "done".into(),
            }],
            "done",
            "",
            0,
        );
        assert!(ok);
        let (ok, _) = check_assertions(
            &[Assertion {
                assert_type: "contains".into(),
                value: "success".into(),
            }],
            "",
            "task success",
            0,
        );
        assert!(ok);
        let (ok, _) = check_assertions(
            &[Assertion {
                assert_type: "min_score".into(),
                value: "80".into(),
            }],
            "",
            "",
            50,
        );
        assert!(!ok);
    }

    #[test]
    fn test_variance() {
        let store = EvalStore::new();
        store.create_run(Run {
            id: "r1".into(),
            suite_id: "s1".into(),
            config_ref: "m1".into(),
            results: vec![
                CaseResult {
                    case_id: "c1".into(),
                    passed: true,
                    status: "done".into(),
                    result: "ok".into(),
                    score: 100,
                    reason: "".into(),
                    elapsed: 10,
                },
                CaseResult {
                    case_id: "c2".into(),
                    passed: false,
                    status: "failed".into(),
                    result: "bad".into(),
                    score: 0,
                    reason: "err".into(),
                    elapsed: 10,
                },
            ],
            timestamp: 100,
        });
        store.create_run(Run {
            id: "r2".into(),
            suite_id: "s1".into(),
            config_ref: "m1".into(),
            results: vec![
                CaseResult {
                    case_id: "c1".into(),
                    passed: true,
                    status: "done".into(),
                    result: "ok".into(),
                    score: 80,
                    reason: "".into(),
                    elapsed: 10,
                },
                CaseResult {
                    case_id: "c2".into(),
                    passed: true,
                    status: "done".into(),
                    result: "ok".into(),
                    score: 60,
                    reason: "".into(),
                    elapsed: 10,
                },
            ],
            timestamp: 200,
        });

        let variance = store.variance("s1", "m1");
        assert_eq!(variance.run_count, 2);
        assert_eq!(variance.cases.len(), 2);
        assert!((variance.mean_score - 60.0).abs() < 0.0001);
        assert!((variance.std_dev - 10.0).abs() < 0.0001);
    }

    #[test]
    fn test_model_compare() {
        let store = EvalStore::new();
        for (id, model, passed) in [("r1", "m1", true), ("r2", "m2", false)] {
            store.create_run(Run {
                id: id.into(),
                suite_id: "s1".into(),
                config_ref: model.into(),
                results: vec![CaseResult {
                    case_id: "c1".into(),
                    passed,
                    status: if passed {
                        "done".into()
                    } else {
                        "failed".into()
                    },
                    result: String::new(),
                    score: if passed { 100 } else { 0 },
                    reason: String::new(),
                    elapsed: 10,
                }],
                timestamp: 100,
            });
        }
        let comparison = store.model_compare("s1");
        assert_eq!(comparison.models.len(), 2);
        assert_eq!(comparison.models[0].model_id, "m1");
        assert_eq!(comparison.models[1].model_id, "m2");
    }

    #[test]
    fn test_track_iteration_links_history_and_delta() {
        let store = EvalStore::new();
        store.create_suite(Suite {
            id: "s1".into(),
            name: "suite".into(),
            description: String::new(),
            cases: vec![Case {
                id: "c1".into(),
                name: "case".into(),
                repo: "repo-a".into(),
                spec: "spec".into(),
                assertions: vec![],
            }],
        });
        store.create_run(Run {
            id: "r1".into(),
            suite_id: "s1".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 80,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 100,
        });
        store.create_run(Run {
            id: "r2".into(),
            suite_id: "s1".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 95,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 200,
        });

        let first = store
            .track_iteration("s1", "r1", "skills/foo.md", "hash-a")
            .expect("track first iteration");
        assert_eq!(first.baseline_run_id, "r1");
        assert_eq!(first.candidate_run_id, "r1");
        assert_eq!(first.delta, 0.0);
        assert!(!first.regressed);

        let second = store
            .track_iteration("s1", "r2", "skills/foo.md", "hash-b")
            .expect("track second iteration");
        assert_eq!(second.parent_iteration_id, first.id);
        assert_eq!(second.baseline_run_id, "r1");
        assert_eq!(second.candidate_run_id, "r2");
        assert_eq!(second.delta, 15.0);
        assert!(!second.regressed);

        let latest = store
            .latest_iteration_for_file("skills/foo.md")
            .expect("latest iteration");
        assert_eq!(latest.id, second.id);
        assert_eq!(store.list_iterations("s1").len(), 2);
    }

    #[test]
    fn test_track_iteration_marks_regression() {
        let store = EvalStore::new();
        store.create_suite(Suite {
            id: "s1".into(),
            name: "suite".into(),
            description: String::new(),
            cases: vec![Case {
                id: "c1".into(),
                name: "case".into(),
                repo: "repo-a".into(),
                spec: "spec".into(),
                assertions: vec![],
            }],
        });
        store.create_run(Run {
            id: "r1".into(),
            suite_id: "s1".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 90,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 100,
        });
        store.create_run(Run {
            id: "r2".into(),
            suite_id: "s1".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 75,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 200,
        });

        store
            .track_iteration("s1", "r1", "skills/bar.md", "hash-a")
            .expect("track baseline");
        let second = store
            .track_iteration("s1", "r2", "skills/bar.md", "hash-b")
            .expect("track candidate");
        assert_eq!(second.delta, -15.0);
        assert!(second.regressed);
    }

    #[test]
    fn test_track_iteration_keeps_file_history_within_suite() {
        let store = EvalStore::new();
        for (suite_id, repo) in [("suite-a", "repo-a"), ("suite-b", "repo-b")] {
            store.create_suite(Suite {
                id: suite_id.into(),
                name: format!("suite {suite_id}"),
                description: String::new(),
                cases: vec![Case {
                    id: "c1".into(),
                    name: "case".into(),
                    repo: repo.into(),
                    spec: "spec".into(),
                    assertions: vec![],
                }],
            });
        }
        for (id, suite_id, score, timestamp) in [
            ("suite-a-run-1", "suite-a", 80, 100),
            ("suite-b-run-1", "suite-b", 60, 200),
            ("suite-b-run-2", "suite-b", 90, 300),
        ] {
            store.create_run(Run {
                id: id.into(),
                suite_id: suite_id.into(),
                config_ref: "m1".into(),
                results: vec![CaseResult {
                    case_id: "c1".into(),
                    passed: true,
                    status: "done".into(),
                    result: "ok".into(),
                    score,
                    reason: String::new(),
                    elapsed: 10,
                }],
                timestamp,
            });
        }

        store
            .track_iteration("suite-a", "suite-a-run-1", "skills/shared.md", "hash-a")
            .expect("track suite a");
        let first_suite_b = store
            .track_iteration("suite-b", "suite-b-run-1", "skills/shared.md", "hash-b")
            .expect("track suite b baseline");
        let second_suite_b = store
            .track_iteration("suite-b", "suite-b-run-2", "skills/shared.md", "hash-c")
            .expect("track suite b candidate");

        assert_eq!(first_suite_b.baseline_run_id, "suite-b-run-1");
        assert_eq!(second_suite_b.parent_iteration_id, first_suite_b.id);
        assert_eq!(second_suite_b.baseline_run_id, "suite-b-run-1");
        assert_eq!(second_suite_b.delta, 30.0);
    }

    #[test]
    fn test_repo_regression_signal_uses_latest_repo_suite_iteration() {
        let store = EvalStore::new();
        store.create_suite(Suite {
            id: "suite-a".into(),
            name: "repo suite".into(),
            description: String::new(),
            cases: vec![Case {
                id: "c1".into(),
                name: "case".into(),
                repo: "repo-a".into(),
                spec: "spec".into(),
                assertions: vec![],
            }],
        });
        for (id, score, timestamp) in [("r1", 90, 100), ("r2", 70, 200)] {
            store.create_run(Run {
                id: id.into(),
                suite_id: "suite-a".into(),
                config_ref: "m1".into(),
                results: vec![CaseResult {
                    case_id: "c1".into(),
                    passed: true,
                    status: "done".into(),
                    result: "ok".into(),
                    score,
                    reason: String::new(),
                    elapsed: 10,
                }],
                timestamp,
            });
        }
        store
            .track_iteration("suite-a", "r1", "skills/repo-a.md", "hash-a")
            .expect("baseline");
        store
            .track_iteration("suite-a", "r2", "skills/repo-a.md", "hash-b")
            .expect("candidate");

        let signal = store.repo_regression_signal("repo-a").expect("repo signal");
        assert!(signal.regressed);
        assert!(signal.reason.contains("regressed"));
        assert!(signal.reason.contains("repo-a"));
    }

    #[test]
    fn test_repo_regression_signal_ignores_other_repo_iterations_in_shared_suite() {
        let store = EvalStore::new();
        store.create_suite(Suite {
            id: "shared-suite".into(),
            name: "shared".into(),
            description: String::new(),
            cases: vec![
                Case {
                    id: "case-a".into(),
                    name: "repo a".into(),
                    repo: "repo-a".into(),
                    spec: "spec-a".into(),
                    assertions: vec![],
                },
                Case {
                    id: "case-b".into(),
                    name: "repo b".into(),
                    repo: "repo-b".into(),
                    spec: "spec-b".into(),
                    assertions: vec![],
                },
            ],
        });
        store.create_run(Run {
            id: "run-a1".into(),
            suite_id: "shared-suite".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "case-a".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 90,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 100,
        });
        store.create_run(Run {
            id: "run-a2".into(),
            suite_id: "shared-suite".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "case-a".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 85,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 200,
        });
        store.create_run(Run {
            id: "run-b1".into(),
            suite_id: "shared-suite".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "case-b".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 95,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 300,
        });
        store.create_run(Run {
            id: "run-b2".into(),
            suite_id: "shared-suite".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "case-b".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 60,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 400,
        });

        store
            .track_iteration("shared-suite", "run-a1", "skills/repo-a.md", "hash-a1")
            .expect("repo a baseline");
        store
            .track_iteration("shared-suite", "run-a2", "skills/repo-a.md", "hash-a2")
            .expect("repo a candidate");
        store
            .track_iteration("shared-suite", "run-b1", "skills/repo-b.md", "hash-b1")
            .expect("repo b baseline");
        store
            .track_iteration("shared-suite", "run-b2", "skills/repo-b.md", "hash-b2")
            .expect("repo b candidate");

        let signal = store
            .repo_regression_signal("repo-a")
            .expect("repo a signal");
        assert!(!signal.regressed);
        assert!(signal.reason.contains("stable"));
        assert!(
            signal
                .iteration
                .as_ref()
                .expect("iteration")
                .changed_file
                .contains("repo-a")
        );
    }

    #[test]
    fn test_repo_regression_signal_falls_back_for_legacy_iterations_without_repo() {
        let store = EvalStore::new();
        store.create_suite(Suite {
            id: "suite-a".into(),
            name: "suite".into(),
            description: String::new(),
            cases: vec![Case {
                id: "case-a".into(),
                name: "repo a".into(),
                repo: "repo-a".into(),
                spec: "spec-a".into(),
                assertions: vec![],
            }],
        });
        store.create_run(Run {
            id: "run-a1".into(),
            suite_id: "suite-a".into(),
            config_ref: "m1".into(),
            results: vec![CaseResult {
                case_id: "case-a".into(),
                passed: true,
                status: "done".into(),
                result: "ok".into(),
                score: 90,
                reason: String::new(),
                elapsed: 10,
            }],
            timestamp: 100,
        });
        store.create_iteration(Iteration {
            id: "legacy-1".into(),
            run_id: "run-a1".into(),
            suite_id: "suite-a".into(),
            repo: String::new(),
            changed_file: "skills/repo-a.md".into(),
            diff_hash: "hash-a".into(),
            parent_iteration_id: String::new(),
            baseline_run_id: "run-a1".into(),
            candidate_run_id: "run-a1".into(),
            delta: -15.0,
            regressed: true,
            created: 100,
        });

        let signal = store
            .repo_regression_signal("repo-a")
            .expect("repo a signal");
        assert!(signal.regressed);
        assert!(signal.reason.contains("regressed"));
    }
}
