//! Closed-loop self-improvement, Phase B (Propose): turn observed outcomes (`eval.rs`,
//! `scoring.rs`) and mined patterns (`evolve.rs`) into candidate changes. A [`Candidate`] is never
//! live on its own — it only becomes a routing/template change once Phase C gates it and Phase D
//! promotes it. This module only proposes; nothing here mutates live routing or policy.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::chisei::eval::EvalStore;
use crate::chisei::evolve::{self, TaskRecord};
use crate::chisei::scoring::normalize_task_class;
use crate::db::sekai::SekaiDb;
use crate::sekai::audit::DecisionFilter;

/// What a candidate would change if promoted.
pub const KIND_ROUTING_BIAS: &str = "routing_bias";
pub const KIND_TEMPLATE: &str = "template";

/// Lifecycle status of a proposed candidate. Set by this module (`Proposed`) and advanced by
/// Phase C (`GatePassed`/`GateFailed`) and Phase D (`Promoted`/`RolledBack`).
pub const STATUS_PROPOSED: &str = "proposed";
pub const STATUS_GATE_PASSED: &str = "gate_passed";
pub const STATUS_GATE_FAILED: &str = "gate_failed";
pub const STATUS_PROMOTED: &str = "promoted";
pub const STATUS_ROLLED_BACK: &str = "rolled_back";
/// A `proposed` candidate that a newer proposal for the same (kind, namespace, task_class)
/// contradicts (e.g. a pending "cheap" bias when the namespace has since regressed and a "capable"
/// revert is now proposed). Never gated/promoted — a consumer scanning `STATUS_PROPOSED` will not
/// see it.
pub const STATUS_SUPERSEDED: &str = "superseded";

/// Minimum number of scored cycles a (namespace, task_class) pair needs represented in the audit
/// history before its history is trusted enough to propose a routing-bias change. Mirrors
/// `scoring::MIN_OBS_FOR_REGRESSION`'s rationale: a handful of cycles is dominated by task-mix
/// noise, not signal.
const MIN_CYCLES_FOR_ROUTING_PROPOSAL: usize = 3;
/// How many of the most recent `chisei.scoring` "scored" audit decisions for this namespace to
/// inspect when looking for this task_class's cycles. Scoped server-side by `target_id`, so this
/// bounds one namespace's history, not the whole audit log.
const DECISION_SCAN_LIMIT: i32 = 20;
/// How far back to look for scored decisions. Bounds the proposal to *recent* evidence — without
/// this, a quiet namespace's `DECISION_SCAN_LIMIT` window could span arbitrarily old history and
/// ground a "propose routing to the cheap tier" rationale in stale data presented as recent.
const DECISION_LOOKBACK_MS: i64 = 24 * 60 * 60 * 1000;
/// Pass rate (fraction of case results marked `passed`) at/above which a task-class's observed
/// history is healthy enough to propose routing it to the cheaper tier.
const CHEAP_BIAS_PASS_RATE: f64 = 0.9;

/// Whether `cheap_route_bias` (grpc/chisei_service.rs) would ever route this (already-normalized)
/// task class to the cheaper tier. Mirrored here rather than imported to avoid a
/// `chisei::promotion` -> `grpc` dependency; keep in sync if that routing vocabulary changes.
fn is_cheap_eligible(normalized_class: &str) -> bool {
    matches!(
        normalized_class,
        "background" | "bulk" | "batch" | "small_fast" | "small-fast"
    )
}

/// Mirrors `scoring::ClassCount`'s JSON shape (`{"pass": N, "total": N}`) stored in the
/// `task_class_breakdown` audit evidence field.
#[derive(Deserialize)]
struct ClassCount {
    pass: u64,
    total: u64,
}

/// A proposed change, not yet live. See module docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    /// One of `KIND_ROUTING_BIAS` / `KIND_TEMPLATE`.
    pub kind: String,
    pub namespace: String,
    /// Routing/cost-tier task class this candidate applies to. Empty for candidates that are not
    /// task-class-scoped (e.g. a namespace-wide template).
    pub task_class: String,
    /// Kind-specific payload, JSON-encoded: `{"bias": "cheap"}` for routing bias,
    /// the serialized `evolve::Template` for templates.
    pub payload: String,
    /// Human-readable justification, grounded in the observation that produced the proposal.
    pub rationale: String,
    pub status: String,
    /// The eval suite (or other) id the proposal was derived from, for traceability.
    pub source_ref: String,
    pub created: i64,
}

/// In-memory store for proposed candidates, mirroring `EvalStore`'s shape (see that module for the
/// persistence pattern this follows: a durable SQLite mirror is added alongside, hydrated at
/// startup by the owning service).
pub struct CandidateStore {
    candidates: Mutex<HashMap<String, Candidate>>,
}

impl Default for CandidateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CandidateStore {
    pub fn new() -> Self {
        Self {
            candidates: Mutex::new(HashMap::new()),
        }
    }

    pub fn upsert(&self, candidate: Candidate) {
        self.candidates
            .lock()
            .expect("candidate store poisoned")
            .insert(candidate.id.clone(), candidate);
    }

    pub fn get(&self, id: &str) -> Option<Candidate> {
        self.candidates
            .lock()
            .expect("candidate store poisoned")
            .get(id)
            .cloned()
    }

    /// Atomically set `id`'s status to `new_status` iff its *current* status is
    /// `expected_status`, under a single lock acquisition. Returns the updated candidate on
    /// success, or `None` if the candidate doesn't exist or a concurrent writer already changed
    /// its status away from `expected_status` (e.g. a proposer superseding it) — in that case the
    /// write is skipped entirely, so a check-then-act caller (read status, decide, write) can't
    /// clobber a status change that happened in between.
    pub fn transition(
        &self,
        id: &str,
        expected_status: &str,
        new_status: &str,
    ) -> Option<Candidate> {
        let mut candidates = self.candidates.lock().expect("candidate store poisoned");
        let current = candidates.get(id)?;
        if current.status != expected_status {
            return None;
        }
        let mut updated = current.clone();
        updated.status = new_status.to_string();
        candidates.insert(id.to_string(), updated.clone());
        Some(updated)
    }

    pub fn list(&self) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = self
            .candidates
            .lock()
            .expect("candidate store poisoned")
            .values()
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn list_by_status(&self, status: &str) -> Vec<Candidate> {
        self.list()
            .into_iter()
            .filter(|c| c.status == status)
            .collect()
    }
}

/// Serializable payload for a `KIND_ROUTING_BIAS` candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingBiasPayload {
    /// The bias to apply if promoted: `"cheap"` (route to the cheaper tier) or `"capable"`
    /// (force back to the default/capable model — used to propose reverting an unhealthy bias).
    pub bias: String,
}

/// Inspect the audit history of scored batches for a (namespace, task_class) pair and propose a
/// routing-bias candidate if the evidence is strong enough. Reads the `task_class_breakdown`
/// evidence `scoring::ScoringJob::emit_run` records on every `chisei.scoring` "scored" decision —
/// deliberately *not* a separate eval suite/iteration per class (see the grouping note in
/// `scoring::run_once`): the regression-driving artifact stays one-per-namespace-per-cycle, and
/// this function only reads the durable, already-recorded rollup of it.
///
/// Returns `None` when there isn't yet enough history for this class, or when the current signal
/// doesn't warrant a change (stable, but not overwhelmingly healthy).
///
/// This only proposes — it never touches live routing. Promotion (Phase D) is a separate step
/// gated by Phase C.
pub fn propose_routing_bias_candidate(
    store: &CandidateStore,
    db: &SekaiDb,
    eval: &EvalStore,
    namespace: &str,
    task_class: &str,
) -> Option<Candidate> {
    let normalized_class = normalize_task_class(task_class);
    // Only classes `cheap_route_bias` (grpc/chisei_service.rs) actually routes to the cheaper
    // tier are worth a routing-bias proposal in either direction: a "cheap" proposal for e.g.
    // "primary" would never take effect if promoted, and a "capable" revert is meaningless for a
    // class that was never biased cheap to begin with.
    if namespace.is_empty() || normalized_class.is_empty() || !is_cheap_eligible(&normalized_class)
    {
        return None;
    }

    let decisions = db
        .list_decisions(&DecisionFilter {
            actor: Some("chisei.scoring".to_string()),
            action: Some("scored".to_string()),
            target_id: Some(namespace.to_string()),
            after: chrono::Utc::now().timestamp_millis() - DECISION_LOOKBACK_MS,
            limit: DECISION_SCAN_LIMIT,
            ..Default::default()
        })
        .ok()?;

    let mut total = 0u64;
    let mut passed = 0u64;
    let mut cycles = 0usize;
    for decision in &decisions {
        let Some(breakdown_json) = decision.evidence.get("task_class_breakdown") else {
            continue;
        };
        let Ok(breakdown) = serde_json::from_str::<HashMap<String, ClassCount>>(breakdown_json)
        else {
            continue;
        };
        let Some(counts) = breakdown.get(&normalized_class) else {
            continue;
        };
        total += counts.total;
        passed += counts.pass;
        cycles += 1;
    }
    if cycles < MIN_CYCLES_FOR_ROUTING_PROPOSAL || total == 0 {
        return None;
    }
    let pass_rate = passed as f64 / total as f64;

    let regressed = eval
        .namespace_regression_signal(namespace)
        .map(|signal| signal.regressed)
        .unwrap_or(false);

    let (bias, rationale) = if regressed {
        (
            "capable",
            format!(
                "namespace {namespace} shows an active eval regression; propose reverting \
                 task_class {normalized_class} off the cheap tier until it recovers"
            ),
        )
    } else if pass_rate >= CHEAP_BIAS_PASS_RATE {
        (
            "cheap",
            format!(
                "task_class {normalized_class} in namespace {namespace} passed {passed}/{total} \
                 ({:.0}%) sampled observations over {cycles} cycles with no active regression; \
                 propose routing to the cheaper tier",
                pass_rate * 100.0,
            ),
        )
    } else {
        return None;
    };

    // Pending proposals for this same (kind, namespace, task_class) key, regardless of bias.
    let pending_same_key: Vec<Candidate> = store
        .list_by_status(STATUS_PROPOSED)
        .into_iter()
        .filter(|c| {
            c.kind == KIND_ROUTING_BIAS
                && c.namespace == namespace
                && c.task_class == normalized_class
        })
        .collect();

    // Skip if an equivalent proposal (same bias) is already pending — otherwise a periodic caller
    // (Phase D) would accrue one new candidate per tick for the same unchanged signal.
    let already_proposed = pending_same_key.iter().any(|c| {
        serde_json::from_str::<RoutingBiasPayload>(&c.payload)
            .map(|p| p.bias == bias)
            .unwrap_or(false)
    });
    if already_proposed {
        return None;
    }

    // Any pending proposal for this key with a *different* bias is now stale (the signal moved):
    // supersede it so a consumer scanning `STATUS_PROPOSED` never finds two contradictory pending
    // proposals (e.g. a "cheap" bias still pending after the namespace regressed and this call
    // proposes reverting to "capable").
    for stale in pending_same_key {
        let mut superseded = stale;
        superseded.status = STATUS_SUPERSEDED.to_string();
        store.upsert(superseded);
    }

    let now = chrono::Utc::now().timestamp_millis();
    let seq = eval.next_sequence();
    let candidate = Candidate {
        id: format!("candidate-routing-{namespace}-{normalized_class}-{now}-{seq}"),
        kind: KIND_ROUTING_BIAS.to_string(),
        namespace: namespace.to_string(),
        task_class: normalized_class,
        payload: serde_json::to_string(&RoutingBiasPayload {
            bias: bias.to_string(),
        })
        .unwrap_or_default(),
        rationale,
        status: STATUS_PROPOSED.to_string(),
        source_ref: format!("chisei.scoring:{namespace}"),
        created: now,
    };
    // Persist the replacement in the same call that superseded the stale one, so the two writes
    // can't be split by a caller that drops the return value (error path, filtering, crash).
    store.upsert(candidate.clone());
    Some(candidate)
}

/// Turn `evolve::generate_templates`'s output into candidates. Namespace-scoped, not
/// task-class-scoped (spec templates apply to a namespace regardless of routing tier). Skips a
/// template whose exact content is already sitting in `proposed` status for that namespace, so a
/// periodic caller (Phase D) doesn't accrue duplicate proposals for an unchanged mined template;
/// a template whose content *did* change is still proposed anew.
pub fn propose_template_candidates(
    store: &CandidateStore,
    eval: &EvalStore,
    tasks: &[TaskRecord],
) -> Vec<Candidate> {
    let now = chrono::Utc::now().timestamp_millis();
    let already_proposed = store.list_by_status(STATUS_PROPOSED);
    evolve::generate_templates(tasks)
        .into_iter()
        .filter_map(|template| {
            let payload = serde_json::to_string(&template).unwrap_or_default();
            let duplicate = already_proposed.iter().any(|c| {
                c.kind == KIND_TEMPLATE && c.namespace == template.namespace && c.payload == payload
            });
            if duplicate {
                return None;
            }
            let seq = eval.next_sequence();
            let candidate = Candidate {
                id: format!("candidate-template-{}-{now}-{seq}", template.namespace),
                kind: KIND_TEMPLATE.to_string(),
                namespace: template.namespace.clone(),
                task_class: String::new(),
                rationale: format!(
                    "mined from {} terminal task(s) in namespace {}",
                    tasks
                        .iter()
                        .filter(|t| t.namespace == template.namespace && t.status == "done")
                        .count(),
                    template.namespace
                ),
                payload,
                status: STATUS_PROPOSED.to_string(),
                source_ref: format!("evolve-templates-{}", template.namespace),
                created: now,
            };
            // Self-persisting, mirroring `propose_routing_bias_candidate`: a caller that forgets to
            // upsert would otherwise also bypass the dedup guard above (which reads the store) on
            // the next call, silently accruing duplicates.
            store.upsert(candidate.clone());
            Some(candidate)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::scoring::{Judge, JudgeError, JudgeVerdict, SampleObservation, ScoringJob};
    use std::sync::Arc;

    /// Batch size used for regression-signal tests: must be >= `scoring::MIN_OBS_FOR_REGRESSION`
    /// (5, private to that module) for a cycle to track an iteration.
    const REGRESSION_BATCH: usize = 5;

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
        ) -> Result<JudgeVerdict, JudgeError> {
            Ok(JudgeVerdict {
                score: self.score,
                passed: self.passed,
                reasoning: "stub".to_string(),
            })
        }
    }

    fn setup() -> (Arc<SekaiDb>, Arc<EvalStore>, CandidateStore) {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        (db, Arc::new(EvalStore::new()), CandidateStore::new())
    }

    fn observe(db: &SekaiDb, request_id: &str, namespace: &str, task_class: &str, ts: i64) {
        db.put_sample_observation(&SampleObservation {
            request_id: request_id.into(),
            namespace: namespace.into(),
            spec: "do the thing".into(),
            resolved_model: "claude-opus-4-8".into(),
            output_content: "here is the thing".into(),
            sample_reason: "base".into(),
            input_tokens: 10,
            output_tokens: 20,
            stop_reason: "end_turn".into(),
            timestamp: ts,
            scored: false,
            task_class: task_class.into(),
            cost_usd_micros: 0,
        })
        .unwrap();
    }

    fn observe_batch(
        db: &SekaiDb,
        namespace: &str,
        task_class: &str,
        base: &str,
        count: usize,
        ts_base: i64,
    ) {
        for i in 0..count {
            observe(
                db,
                &format!("{base}-{i}"),
                namespace,
                task_class,
                ts_base + i as i64,
            );
        }
    }

    async fn run_cycle(db: &Arc<SekaiDb>, eval: &Arc<EvalStore>, score: i32, passed: bool) {
        let job = ScoringJob::with_judge(
            db.clone(),
            eval.clone(),
            Arc::new(StubJudge { score, passed }),
            32,
            "claude-opus-4-8",
        );
        job.run_once().await.unwrap();
    }

    #[tokio::test]
    async fn no_proposal_below_min_cycles() {
        let (db, eval, store) = setup();
        // Only two scored cycles for this (namespace, task_class) — below the 3-cycle floor.
        observe_batch(&db, "acme", "background", "c0", 2, 100);
        run_cycle(&db, &eval, 90, true).await;
        observe_batch(&db, "acme", "background", "c1", 2, 200);
        run_cycle(&db, &eval, 90, true).await;

        assert!(propose_routing_bias_candidate(&store, &db, &eval, "acme", "background").is_none());
    }

    #[tokio::test]
    async fn whitespace_only_task_class_is_rejected() {
        let (db, eval, store) = setup();
        // Seed a healthy *unclassified* (empty task_class) history: without the early
        // `normalized_class.is_empty()` guard, "   " would normalize to "" and this bucket would
        // satisfy the min-cycles/pass-rate check, wrongly yielding a candidate.
        for cycle in 0..3 {
            observe_batch(&db, "acme", "", &format!("c{cycle}"), 2, 100 + cycle * 10);
            run_cycle(&db, &eval, 90, true).await;
        }
        assert!(propose_routing_bias_candidate(&store, &db, &eval, "acme", "   ").is_none());
    }

    #[tokio::test]
    async fn no_proposal_for_a_class_cheap_route_bias_never_routes_cheap() {
        let (db, eval, store) = setup();
        // Healthy history for "primary" - cheap_route_bias never routes this class to the cheaper
        // tier, so a "cheap" (or later "capable") proposal for it would be a semantic no-op.
        for cycle in 0..3 {
            observe_batch(
                &db,
                "acme",
                "primary",
                &format!("c{cycle}"),
                2,
                100 + cycle * 10,
            );
            run_cycle(&db, &eval, 90, true).await;
        }
        assert!(propose_routing_bias_candidate(&store, &db, &eval, "acme", "primary").is_none());
    }

    #[tokio::test]
    async fn does_not_duplicate_a_pending_proposal() {
        let (db, eval, store) = setup();
        for cycle in 0..3 {
            observe_batch(
                &db,
                "acme",
                "background",
                &format!("c{cycle}"),
                2,
                100 + cycle * 10,
            );
            run_cycle(&db, &eval, 90, true).await;
        }
        // The function persists its own proposal, so no explicit upsert is needed here.
        propose_routing_bias_candidate(&store, &db, &eval, "acme", "background")
            .expect("first proposal");

        // Same unchanged signal, called again (as a periodic caller would) - must not duplicate.
        assert!(propose_routing_bias_candidate(&store, &db, &eval, "acme", "background").is_none());
    }

    #[tokio::test]
    async fn flipped_signal_supersedes_the_stale_opposite_bias_proposal() {
        let (db, eval, store) = setup();
        // Three healthy cycles (>= scoring::MIN_OBS_FOR_REGRESSION each, meeting the min-cycle
        // floor and tracking an iteration/baseline every cycle), proposing "cheap"; leave pending.
        for (i, cycle) in ["c0", "c1", "c2"].iter().enumerate() {
            observe_batch(
                &db,
                "acme",
                "background",
                cycle,
                REGRESSION_BATCH,
                100 + i as i64 * 100,
            );
            run_cycle(&db, &eval, 90, true).await;
        }
        // The function persists its own proposal, so no explicit upsert is needed here.
        let cheap = propose_routing_bias_candidate(&store, &db, &eval, "acme", "background")
            .expect("healthy history should propose cheap");

        // A fourth, much worse cycle drives the namespace regression signal negative.
        observe_batch(&db, "acme", "background", "c3", REGRESSION_BATCH, 400);
        run_cycle(&db, &eval, 10, false).await;
        assert!(eval.namespace_regression_signal("acme").unwrap().regressed);

        let capable = propose_routing_bias_candidate(&store, &db, &eval, "acme", "background")
            .expect("regression should propose reverting to capable");
        assert_eq!(
            serde_json::from_str::<RoutingBiasPayload>(&capable.payload)
                .unwrap()
                .bias,
            "capable"
        );
        let capable_id = capable.id.clone();

        // The stale "cheap" proposal must no longer be pending — a consumer scanning
        // STATUS_PROPOSED must not find two contradictory candidates for the same key.
        assert_eq!(store.get(&cheap.id).unwrap().status, STATUS_SUPERSEDED);
        let pending = store.list_by_status(STATUS_PROPOSED);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, capable_id);
    }

    #[tokio::test]
    async fn proposes_cheap_bias_on_healthy_history() {
        let (db, eval, store) = setup();
        for cycle in 0..3 {
            observe_batch(
                &db,
                "acme",
                "background",
                &format!("c{cycle}"),
                2,
                100 + cycle * 10,
            );
            run_cycle(&db, &eval, 90, true).await;
        }

        let candidate = propose_routing_bias_candidate(&store, &db, &eval, "acme", "background")
            .expect("healthy history should propose");
        assert_eq!(candidate.kind, KIND_ROUTING_BIAS);
        assert_eq!(candidate.status, STATUS_PROPOSED);
        let payload: RoutingBiasPayload = serde_json::from_str(&candidate.payload).unwrap();
        assert_eq!(payload.bias, "cheap");
    }

    #[tokio::test]
    async fn no_proposal_on_mediocre_but_non_regressed_history() {
        let (db, eval, store) = setup();
        for cycle in 0..3 {
            observe_batch(
                &db,
                "acme",
                "background",
                &format!("c{cycle}"),
                2,
                100 + cycle * 10,
            );
            // Alternate pass/fail across cycles so the aggregate pass rate lands at 50%.
            run_cycle(&db, &eval, 50, cycle % 2 == 0).await;
        }
        assert!(propose_routing_bias_candidate(&store, &db, &eval, "acme", "background").is_none());
    }

    #[tokio::test]
    async fn proposes_reverting_to_capable_when_namespace_regressed() {
        let (db, eval, store) = setup();
        // Two healthy cycles, then a third that drives the namespace regression signal negative.
        // Batches are >= scoring::MIN_OBS_FOR_REGRESSION so each cycle tracks an iteration.
        observe_batch(&db, "acme", "background", "c0", REGRESSION_BATCH, 100);
        run_cycle(&db, &eval, 90, true).await;
        observe_batch(&db, "acme", "background", "c1", REGRESSION_BATCH, 200);
        run_cycle(&db, &eval, 90, true).await;
        observe_batch(&db, "acme", "background", "c2", REGRESSION_BATCH, 300);
        run_cycle(&db, &eval, 10, false).await;

        assert!(eval.namespace_regression_signal("acme").unwrap().regressed);

        let candidate = propose_routing_bias_candidate(&store, &db, &eval, "acme", "background")
            .expect("regression should still propose (a revert)");
        let payload: RoutingBiasPayload = serde_json::from_str(&candidate.payload).unwrap();
        assert_eq!(payload.bias, "capable");
    }

    #[tokio::test]
    async fn task_class_is_normalized_and_case_insensitive() {
        let (db, eval, store) = setup();
        for cycle in 0..3 {
            observe_batch(
                &db,
                "acme",
                "Background",
                &format!("c{cycle}"),
                2,
                100 + cycle * 10,
            );
            run_cycle(&db, &eval, 90, true).await;
        }
        // Querying with a different case must still find the (normalized) history.
        let candidate = propose_routing_bias_candidate(&store, &db, &eval, "acme", "BACKGROUND")
            .expect("normalization should match the stored class");
        assert_eq!(candidate.task_class, "background");
    }

    #[test]
    fn template_candidates_wrap_generate_templates() {
        let eval = EvalStore::new();
        let tasks = vec![
            TaskRecord {
                id: "t1".into(),
                spec: "implement the retry loop for the widget service".into(),
                status: "done".into(),
                namespace: "acme".into(),
                tokens_used: 100,
                original_spec: None,
                created: 1,
            },
            TaskRecord {
                id: "t2".into(),
                spec: "implement the retry loop for the gadget service".into(),
                status: "done".into(),
                namespace: "acme".into(),
                tokens_used: 100,
                original_spec: None,
                created: 2,
            },
        ];
        let store = CandidateStore::new();
        let candidates = propose_template_candidates(&store, &eval, &tasks);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, KIND_TEMPLATE);
        assert_eq!(candidates[0].namespace, "acme");
        assert_eq!(candidates[0].status, STATUS_PROPOSED);
    }

    #[test]
    fn does_not_duplicate_a_pending_template_proposal() {
        let eval = EvalStore::new();
        let tasks = vec![
            TaskRecord {
                id: "t1".into(),
                spec: "implement the retry loop for the widget service".into(),
                status: "done".into(),
                namespace: "acme".into(),
                tokens_used: 100,
                original_spec: None,
                created: 1,
            },
            TaskRecord {
                id: "t2".into(),
                spec: "implement the retry loop for the gadget service".into(),
                status: "done".into(),
                namespace: "acme".into(),
                tokens_used: 100,
                original_spec: None,
                created: 2,
            },
        ];
        let store = CandidateStore::new();
        // The function persists its own proposals, so no explicit upsert is needed here.
        assert_eq!(propose_template_candidates(&store, &eval, &tasks).len(), 1);
        // Same unchanged task history, called again - must not duplicate.
        assert!(propose_template_candidates(&store, &eval, &tasks).is_empty());
    }
}
