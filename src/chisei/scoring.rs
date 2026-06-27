//! Scoring job: turn the durable sampled-observation dataset into real eval `Run`s.
//!
//! Control-plane-aware sampling selects a fraction of executions for deeper observation and
//! records a judge-able payload (spec + model output) in `chisei_sample_observations`. This
//! background job consumes that dataset, scores each observation with a hybrid of
//! state-of-the-art LLM-as-judge grading and the existing deterministic [`eval::check_assertions`]
//! gate, and emits one [`eval::Run`] per repo via the same persistence path the `CreateEvalRun`
//! RPC uses. The resulting iterations feed [`EvalStore::repo_regression_signal`], which already
//! drives adaptive sampling (`reason = "eval_regressed"`) — closing the learning loop.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::chisei::budget::BudgetTracker;
use crate::chisei::eval::{self, EvalStore};
use crate::config::Config;
use crate::db::sekai::SekaiDb;
use crate::llm;

/// A sampled execution captured at execute time, carrying enough context to be scored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleObservation {
    pub request_id: String,
    pub repo: String,
    pub spec: String,
    pub resolved_model: String,
    pub output_content: String,
    pub sample_reason: String,
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub stop_reason: String,
    pub timestamp: i64,
    pub scored: bool,
}

/// Structured verdict the judge produces for a single observation.
#[derive(Debug, Clone)]
pub struct JudgeVerdict {
    pub score: i32, // 0..=100
    pub passed: bool,
    pub reasoning: String,
}

/// Pluggable scorer so the job's orchestration is testable without a live provider.
#[async_trait::async_trait]
pub trait Judge: Send + Sync {
    async fn judge(
        &self,
        model: &str,
        rubric: &str,
        spec: &str,
        output: &str,
    ) -> Result<JudgeVerdict, String>;
}

/// Synthetic suite id namespace for sampled observations of a repo.
const SUITE_PREFIX: &str = "sampling-";
/// LLM-judge score (0..=100) at or above which an observation passes on the judge axis.
const PASS_THRESHOLD: i32 = 60;
/// Bound on the stored output snippet so run JSON stays compact.
const SNIPPET_LEN: usize = 2000;
/// Judge output cap.
const JUDGE_MAX_TOKENS: i32 = 1024;

const JUDGE_SYSTEM_PREAMBLE: &str = "You are a rigorous, impartial evaluator of an AI coding \
assistant's output. Score the output against the rubric and call the `record_score` tool exactly \
once with your verdict. Score 0-100 (100 = fully meets the rubric). Be specific in your reasoning \
and ground every claim in the actual output — do not reward plausible-looking but unsupported work.";

const DEFAULT_RUBRIC: &str = "Evaluate the output as a response to the task specification on:\n\
- Correctness: does it actually do what the task asked, without bugs or hand-waving?\n\
- Completeness: are all parts of the task addressed?\n\
- Safety & soundness: no destructive, insecure, or clearly wrong actions.\n\
- Clarity: is the result understandable and self-consistent?\n\
A truncated or refused output should score low.";

/// The background scoring job. Holds shared handles to the same DB and in-memory [`EvalStore`]
/// the gRPC service uses, so emitted runs are visible to live regression checks immediately.
pub struct ScoringJob {
    db: Arc<SekaiDb>,
    eval: Arc<EvalStore>,
    judge: Arc<dyn Judge>,
    interval: Duration,
    batch_size: i32,
    model: String,
}

impl ScoringJob {
    pub fn new(
        db: Arc<SekaiDb>,
        eval: Arc<EvalStore>,
        config: Config,
        budget: Arc<BudgetTracker>,
    ) -> Self {
        let judge = Arc::new(LlmJudge {
            config: config.clone(),
            budget,
        });
        Self {
            db,
            eval,
            judge,
            interval: Duration::from_secs(config.scoring_interval_secs.max(1)),
            batch_size: config.scoring_batch_size,
            model: config.scoring_model,
        }
    }

    /// Test/alternate constructor with an injected judge.
    pub fn with_judge(
        db: Arc<SekaiDb>,
        eval: Arc<EvalStore>,
        judge: Arc<dyn Judge>,
        batch_size: i32,
        model: impl Into<String>,
    ) -> Self {
        Self {
            db,
            eval,
            judge,
            interval: Duration::from_secs(60),
            batch_size,
            model: model.into(),
        }
    }

    pub async fn run_loop(self) {
        loop {
            match self.run_once().await {
                Ok(n) if n > 0 => println!("scoring job: scored {n} sampled observation(s)"),
                Ok(_) => {}
                Err(e) => eprintln!("scoring job error: {e}"),
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    /// Consume one batch of unscored observations, score them, and emit one eval run per repo.
    /// Returns the number of observations scored.
    pub async fn run_once(&self) -> Result<usize, String> {
        let observations = self.db.list_unscored_observations(self.batch_size)?;
        if observations.is_empty() {
            return Ok(0);
        }

        let mut by_repo: BTreeMap<String, Vec<SampleObservation>> = BTreeMap::new();
        for obs in observations {
            by_repo.entry(obs.repo.clone()).or_default().push(obs);
        }

        let mut total_scored = 0usize;
        for (repo, group) in by_repo {
            let reference_assertions = self.reference_assertions(&repo);
            let rubric = self.build_rubric(&repo);

            let mut results = Vec::with_capacity(group.len());
            for obs in &group {
                let verdict = self
                    .judge
                    .judge(&self.model, &rubric, &obs.spec, &obs.output_content)
                    .await?;
                let status = status_from_stop_reason(&obs.stop_reason);
                // Deterministic gate: only applied when authored assertions exist for the repo.
                let (gate_ok, gate_reason) = if reference_assertions.is_empty() {
                    (true, String::new())
                } else {
                    eval::check_assertions(
                        &reference_assertions,
                        &status,
                        &obs.output_content,
                        verdict.score,
                    )
                };
                let passed = verdict.passed && gate_ok;
                let reason = if gate_ok {
                    verdict.reasoning.clone()
                } else {
                    format!("{} | gate: {}", verdict.reasoning, gate_reason)
                };
                results.push(eval::CaseResult {
                    case_id: obs.request_id.clone(),
                    passed,
                    status,
                    result: snippet(&obs.output_content),
                    score: verdict.score,
                    reason,
                    elapsed: 0,
                });
            }

            self.emit_run(&repo, &group, results)?;

            for obs in &group {
                self.db.mark_observation_scored(&obs.request_id)?;
                total_scored += 1;
            }
        }
        Ok(total_scored)
    }

    /// Build a synthetic per-repo suite (one case per observation, mirroring the run's case ids so
    /// the eval store can infer the repo), persist the run + a tracked iteration, and record an
    /// audit decision. Bounded: the suite only ever holds the current batch's cases.
    fn emit_run(
        &self,
        repo: &str,
        group: &[SampleObservation],
        results: Vec<eval::CaseResult>,
    ) -> Result<(), String> {
        let suite_id = format!("{SUITE_PREFIX}{repo}");
        let changed_file = format!("sampling/{repo}");
        let now = chrono::Utc::now().timestamp_millis();

        let suite = eval::Suite {
            id: suite_id.clone(),
            name: format!("Sampled observations: {repo}"),
            description: "Auto-generated suite of control-plane sampled executions.".to_string(),
            cases: group
                .iter()
                .map(|obs| eval::Case {
                    id: obs.request_id.clone(),
                    name: obs.request_id.clone(),
                    repo: repo.to_string(),
                    spec: obs.spec.clone(),
                    assertions: vec![],
                })
                .collect(),
        };
        self.db.put_eval_suite(&suite)?;
        self.eval.create_suite(suite);

        let run = eval::Run {
            id: format!("sampling-run-{repo}-{now}"),
            suite_id: suite_id.clone(),
            config_ref: self.model.clone(),
            results,
            timestamp: now,
        };
        let pass_count = run.results.iter().filter(|r| r.passed).count();
        let total = run.results.len();
        self.db.put_eval_run(&run)?;
        self.eval.create_run(run.clone());

        // Track an iteration so regression detection (and adaptive sampling) picks this up.
        // `diff_hash` is the run id — a stable, unique marker for this batch.
        match self
            .eval
            .track_iteration(&suite_id, &run.id, &changed_file, &run.id)
        {
            Ok(iteration) => {
                self.db.put_eval_iteration(&iteration)?;
                let mut evidence = std::collections::HashMap::new();
                evidence.insert("repo".to_string(), repo.to_string());
                evidence.insert("run_id".to_string(), run.id.clone());
                evidence.insert("model".to_string(), self.model.clone());
                evidence.insert(
                    "pass_rate".to_string(),
                    format!("{pass_count}/{total}"),
                );
                evidence.insert("delta".to_string(), format!("{:.1}", iteration.delta));
                evidence.insert("regressed".to_string(), iteration.regressed.to_string());
                let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: now,
                    actor: "chisei.scoring".into(),
                    action: "scored".into(),
                    reason: format!("scored {total} sampled observation(s) for repo {repo}"),
                    evidence,
                    target_id: repo.to_string(),
                    outcome: if iteration.regressed {
                        "regressed".into()
                    } else {
                        "stable".into()
                    },
                });
            }
            // An empty repo (or otherwise un-inferable) run still persists; it simply has no
            // regression signal. Don't fail the whole batch over it.
            Err(e) => eprintln!("scoring job: skipped iteration for repo {repo:?}: {e}"),
        }
        Ok(())
    }

    /// Union of assertions from any authored (non-sampling) suite whose cases target this repo.
    fn reference_assertions(&self, repo: &str) -> Vec<eval::Assertion> {
        if repo.is_empty() {
            return vec![];
        }
        let mut assertions = Vec::new();
        for suite in self.eval.list_suites() {
            if suite.id.starts_with(SUITE_PREFIX) {
                continue;
            }
            for case in suite.cases.iter().filter(|c| c.repo == repo) {
                assertions.extend(case.assertions.iter().cloned());
            }
        }
        assertions
    }

    /// Rubric for the judge: the default quality rubric, plus criteria distilled from any authored
    /// suite cases for this repo (their names/specs describe what "good" looks like).
    fn build_rubric(&self, repo: &str) -> String {
        let mut rubric = DEFAULT_RUBRIC.to_string();
        if repo.is_empty() {
            return rubric;
        }
        let mut criteria = Vec::new();
        for suite in self.eval.list_suites() {
            if suite.id.starts_with(SUITE_PREFIX) {
                continue;
            }
            for case in suite.cases.iter().filter(|c| c.repo == repo) {
                let spec = case.spec.trim();
                if spec.is_empty() {
                    criteria.push(format!("- {}", case.name));
                } else {
                    criteria.push(format!("- {}: {}", case.name, truncate(spec, 200)));
                }
            }
        }
        if !criteria.is_empty() {
            rubric.push_str("\n\nRepo-specific reference criteria:\n");
            rubric.push_str(&criteria.join("\n"));
        }
        rubric
    }
}

/// Default judge: calls the configured model through the native provider layer, using a
/// `record_score` tool call for reliable structured output (the `llm` interface has no
/// `output_config`, so tool-calling is the provider-agnostic path to structure).
struct LlmJudge {
    config: Config,
    budget: Arc<BudgetTracker>,
}

#[async_trait::async_trait]
impl Judge for LlmJudge {
    async fn judge(
        &self,
        model: &str,
        rubric: &str,
        spec: &str,
        output: &str,
    ) -> Result<JudgeVerdict, String> {
        let provider = llm::resolve(
            model,
            self.config.anthropic_api_key.as_deref(),
            self.config.openai_api_key.as_deref(),
            &self.config.ollama_url,
            self.config.native_llm_url.as_deref(),
        )?;

        let system = format!("{JUDGE_SYSTEM_PREAMBLE}\n\n{rubric}");
        let user = format!(
            "## Task specification\n{spec}\n\n## Model output\n{output}\n\nScore the model output against the rubric by calling record_score."
        );
        let tool = llm::ToolDef {
            name: "record_score".to_string(),
            description: "Record the evaluation verdict for the model output.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "score": {"type": "integer", "minimum": 0, "maximum": 100,
                        "description": "Overall quality score, 0-100."},
                    "passed": {"type": "boolean",
                        "description": "Whether the output acceptably satisfies the task."},
                    "reasoning": {"type": "string",
                        "description": "Concise justification grounded in the output."}
                },
                "required": ["score", "passed", "reasoning"]
            }),
        };
        let req = llm::ChatRequest {
            model: model.to_string(),
            system,
            messages: vec![llm::Message {
                role: "user".to_string(),
                content: user,
                tool_call_id: String::new(),
                tool_calls: vec![],
            }],
            tools: vec![tool],
            max_tokens: JUDGE_MAX_TOKENS,
        };

        // Reserve against a dedicated scoring budget bucket, then reconcile to actual usage.
        let user_id = "chisei.scoring";
        let estimated = (system_estimate(&req)).max(1);
        self.budget.check_and_reserve(user_id, estimated)?;
        let resp = match provider.chat(&req).await {
            Ok(r) => r,
            Err(e) => {
                self.budget.adjust(user_id, estimated, 0);
                return Err(e);
            }
        };
        self.budget
            .adjust(user_id, estimated, resp.input_tokens + resp.output_tokens);

        parse_verdict(&resp)
    }
}

fn system_estimate(req: &llm::ChatRequest) -> i32 {
    let body: usize = req.system.len() + req.messages.iter().map(|m| m.content.len()).sum::<usize>();
    (body as i32) / 4 + req.max_tokens
}

/// Extract the verdict from a `record_score` tool call, falling back to JSON in the text content.
fn parse_verdict(resp: &llm::ChatResponse) -> Result<JudgeVerdict, String> {
    let args = resp
        .tool_calls
        .iter()
        .find(|tc| tc.name == "record_score")
        .map(|tc| tc.args.clone())
        .or_else(|| serde_json::from_str::<serde_json::Value>(resp.content.trim()).ok());
    let Some(args) = args else {
        return Err("judge returned no record_score tool call and no JSON content".to_string());
    };
    let score = args
        .get("score")
        .and_then(|v| v.as_i64())
        .map(|v| v.clamp(0, 100) as i32)
        .ok_or("judge verdict missing integer `score`")?;
    let passed = args
        .get("passed")
        .and_then(|v| v.as_bool())
        .unwrap_or(score >= PASS_THRESHOLD);
    let reasoning = args
        .get("reasoning")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(JudgeVerdict {
        score,
        passed,
        reasoning,
    })
}

fn status_from_stop_reason(stop_reason: &str) -> String {
    match stop_reason {
        "end_turn" | "stop" | "" => "ok".to_string(),
        "max_tokens" => "truncated".to_string(),
        other => other.to_string(),
    }
}

fn snippet(s: &str) -> String {
    truncate(s, SNIPPET_LEN)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubJudge {
        score: i32,
        passed: bool,
    }

    #[async_trait::async_trait]
    impl Judge for StubJudge {
        async fn judge(
            &self,
            _model: &str,
            _rubric: &str,
            _spec: &str,
            _output: &str,
        ) -> Result<JudgeVerdict, String> {
            Ok(JudgeVerdict {
                score: self.score,
                passed: self.passed,
                reasoning: "stub".to_string(),
            })
        }
    }

    fn setup() -> (Arc<SekaiDb>, Arc<EvalStore>) {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        db.migrate_chisei().unwrap();
        db.migrate_audit();
        (db, Arc::new(EvalStore::new()))
    }

    fn observe(db: &SekaiDb, request_id: &str, repo: &str, ts: i64) {
        db.put_sample_observation(&SampleObservation {
            request_id: request_id.into(),
            repo: repo.into(),
            spec: "do the thing".into(),
            resolved_model: "claude-opus-4-8".into(),
            output_content: "here is the thing".into(),
            sample_reason: "base".into(),
            input_tokens: 10,
            output_tokens: 20,
            stop_reason: "end_turn".into(),
            timestamp: ts,
            scored: false,
        })
        .unwrap();
    }

    #[tokio::test]
    async fn scores_observations_into_a_run_and_iteration() {
        let (db, eval) = setup();
        observe(&db, "req-1", "acme", 100);
        observe(&db, "req-2", "acme", 101);

        let job = ScoringJob::with_judge(
            db.clone(),
            eval.clone(),
            Arc::new(StubJudge {
                score: 90,
                passed: true,
            }),
            16,
            "claude-opus-4-8",
        );

        let scored = job.run_once().await.unwrap();
        assert_eq!(scored, 2);

        // A run with both case results is persisted under the synthetic repo suite.
        let runs = db.list_eval_run_records("sampling-acme").unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].results.len(), 2);
        assert!(runs[0].results.iter().all(|r| r.passed && r.score == 90));

        // Observations are consumed.
        assert!(db.list_unscored_observations(16).unwrap().is_empty());

        // An iteration exists and the repo now has a (stable) regression signal.
        let signal = eval.repo_regression_signal("acme").unwrap();
        assert!(!signal.regressed);
    }

    #[tokio::test]
    async fn second_batch_with_low_scores_marks_regression() {
        let (db, eval) = setup();
        observe(&db, "req-1", "acme", 100);
        let good = ScoringJob::with_judge(
            db.clone(),
            eval.clone(),
            Arc::new(StubJudge {
                score: 95,
                passed: true,
            }),
            16,
            "claude-opus-4-8",
        );
        assert_eq!(good.run_once().await.unwrap(), 1);
        assert!(!eval.repo_regression_signal("acme").unwrap().regressed);

        observe(&db, "req-2", "acme", 200);
        let bad = ScoringJob::with_judge(
            db.clone(),
            eval.clone(),
            Arc::new(StubJudge {
                score: 10,
                passed: false,
            }),
            16,
            "claude-opus-4-8",
        );
        assert_eq!(bad.run_once().await.unwrap(), 1);

        // 10 vs 95 is a >10 point drop → regression flagged, which is what adaptive sampling reads.
        assert!(eval.repo_regression_signal("acme").unwrap().regressed);
    }

    #[tokio::test]
    async fn empty_batch_is_a_noop() {
        let (db, eval) = setup();
        let job = ScoringJob::with_judge(
            db.clone(),
            eval,
            Arc::new(StubJudge {
                score: 50,
                passed: true,
            }),
            16,
            "claude-opus-4-8",
        );
        assert_eq!(job.run_once().await.unwrap(), 0);
    }
}
