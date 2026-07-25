//! Closed-loop self-improvement, gate stage: before any candidate change
//! (`chisei::promotion::Candidate`) can be promoted, it must pass an eval gate against held
//! evidence — the cheapest check that still passes. Passing candidates move to
//! `STATUS_GATE_PASSED`; failing candidates move to `STATUS_GATE_FAILED` and are recorded, never
//! promoted. Nothing here mutates live routing, policy, or templates — gating only decides whether
//! a proposal is *eligible* to be promoted later.

use std::collections::HashMap;

use crate::chisei::eval::{EvalStore, GateDecision};
use crate::chisei::evolve::{self, TaskRecord};
use crate::chisei::promotion::{
    Candidate, CandidateStore, KIND_ROUTING_BIAS, KIND_TEMPLATE, RoutingBiasPayload,
    STATUS_GATE_FAILED, STATUS_GATE_PASSED, STATUS_PROPOSED,
};
use crate::chisei::scoring::sampling_suite_id;
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;

/// Minimum aggregate success rate a template candidate's namespace task history must show to pass
/// the gate.
const TEMPLATE_GATE_PASS_RATE: f64 = 0.6;
/// Minimum terminal (done + failed) tasks needed before a template candidate can be gated at all.
/// Chosen to match `evolve::generate_templates`'s own >=2-*done*-task-per-namespace floor in the
/// common case, but is a strictly weaker floor: it's satisfied by terminal tasks generally, not
/// specifically done ones, so an all-failed namespace slice can clear it (and correctly fail the
/// gate on that evidence) even though it wouldn't have mined a template.
const TEMPLATE_GATE_MIN_TASKS: i32 = 2;

/// Gate one `proposed` candidate against held evidence and advance its status accordingly, and
/// record the outcome as an audit decision. Returns the `GateDecision`, or `None` if the candidate
/// doesn't exist, isn't in `proposed` status, there isn't yet enough held evidence to gate it (left
/// `proposed`, retried later), or a concurrent writer (e.g. a proposer superseding this exact
/// candidate) changed its status between the read and the write below — in every `None` case
/// nothing is written and no audit decision is recorded.
///
/// Reads the candidate from `store` by id, and writes the new status via
/// `CandidateStore::transition`, which is conditioned on the status *still* being `proposed` at
/// write time (not just at the initial read) under a single lock acquisition — the gating work in
/// between (suite lookups, `EvalStore` reads) is not itself locked, so re-checking only at read
/// time would leave a window for a concurrent supersede to be silently overwritten.
pub fn gate_candidate(
    store: &CandidateStore,
    db: &RuntimeDb,
    eval: &EvalStore,
    candidate_id: &str,
    tasks: &[TaskRecord],
) -> Option<GateDecision> {
    let candidate = store.get(candidate_id)?;
    if candidate.status != STATUS_PROPOSED {
        return None;
    }
    let decision = match candidate.kind.as_str() {
        KIND_ROUTING_BIAS => gate_routing_bias(db, eval, &candidate)?,
        KIND_TEMPLATE => gate_template(&candidate, tasks)?,
        _ => return None,
    };

    let passed = decision.verdict == "pass";
    let new_status = if passed {
        STATUS_GATE_PASSED
    } else {
        STATUS_GATE_FAILED
    };
    // Skip the write (and the audit record below) if the candidate's status moved on since the
    // read above — nothing to report, since this gate never actually took effect.
    store.transition(candidate_id, STATUS_PROPOSED, new_status)?;

    let mut evidence = HashMap::new();
    evidence.insert("kind".to_string(), candidate.kind.clone());
    evidence.insert("namespace".to_string(), candidate.namespace.clone());
    evidence.insert("task_class".to_string(), candidate.task_class.clone());
    evidence.insert("verdict".to_string(), decision.verdict.clone());
    evidence.insert(
        "baseline_score".to_string(),
        format!("{:.2}", decision.baseline_score),
    );
    evidence.insert(
        "candidate_score".to_string(),
        format!("{:.2}", decision.candidate_score),
    );
    let _ = db.record_decision(&crate::sekai::audit::Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: "chisei.gate".into(),
        action: "gated".into(),
        reason: decision.reason.clone(),
        evidence,
        target_id: candidate.id.clone(),
        outcome: if passed { "pass".into() } else { "fail".into() },
    });

    Some(decision)
}

/// Gate a routing-bias candidate. The two directions need opposite checks against the same
/// evidence, so this dispatches on the candidate's proposed `bias`:
///
/// - `"cheap"`: proposed because recent evidence was healthy. Gated by comparing the namespace's
///   sampling suite's oldest tracked run (baseline) against its most recent run (candidate
///   evidence) via `EvalStore::compare_runs` — the same `GateDecision` machinery `CompareRuns`
///   exposes over gRPC — requiring the newest run to be at least as good as the oldest.
/// - `"capable"`: proposed *because* `namespace_regression_signal` was active, i.e. recent
///   evidence is expected to be worse than older evidence. Applying the same "newest >= oldest"
///   check here would fail the revert precisely while the regression it corrects is still active,
///   and only let it pass once the regression has already resolved (when reverting is moot).
///   Gated directly against the live regression signal instead: pass while the regression is
///   still active (the revert is warranted), fail once it has resolved (the revert is stale).
///
/// Returns `None` only when there isn't yet enough held evidence to gate (for `"cheap"`, fewer
/// than two suite runs; for `"capable"`, no regression signal exists for the namespace at all) —
/// the candidate is left `proposed` to retry. A payload that fails to parse, or parses to a `bias`
/// other than `"cheap"`/`"capable"`, is terminally gate-failed with an explanatory reason instead
/// of returning `None`: unlike missing evidence, a corrupt/unrecognized payload will never resolve
/// itself on a later retry, so treating it as "not enough evidence yet" would leave the candidate
/// stuck in `proposed` forever, silently re-gated on every tick with no audit trail.
fn gate_routing_bias(
    db: &RuntimeDb,
    eval: &EvalStore,
    candidate: &Candidate,
) -> Option<GateDecision> {
    let payload: RoutingBiasPayload = match serde_json::from_str(&candidate.payload) {
        Ok(p) => p,
        Err(e) => {
            return Some(GateDecision {
                verdict: "fail".to_string(),
                reason: format!("unparseable routing-bias payload: {e}"),
                baseline_score: 0.0,
                candidate_score: 0.0,
            });
        }
    };

    match payload.bias.as_str() {
        "capable" => {
            // `None` means no held evidence exists for this namespace at all (distinct from
            // `Some(signal)` with `regressed: false`, which means the regression genuinely
            // resolved). A capable candidate can only be proposed while a regression signal
            // exists, so `None` here means the evidence vanished between propose and gate (e.g.
            // restart before hydration) — treat it the same as "not enough evidence yet", not as
            // a resolved regression, so the candidate is left `proposed` to retry.
            let class_signal = crate::chisei::scoring::task_class_regression_signal(
                db,
                &candidate.namespace,
                &candidate.task_class,
            );
            let namespace_signal = eval.namespace_regression_signal(&candidate.namespace);
            if class_signal.is_none() && namespace_signal.is_none() {
                return None;
            }
            let regressed = crate::chisei::scoring::task_class_or_namespace_regressed(
                db,
                eval,
                &candidate.namespace,
                &candidate.task_class,
            );
            Some(GateDecision {
                verdict: if regressed {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                },
                reason: if regressed {
                    format!(
                        "namespace {} still shows an active eval regression; reverting to capable is warranted",
                        candidate.namespace
                    )
                } else {
                    format!(
                        "namespace {} regression has resolved; the capable revert is no longer warranted",
                        candidate.namespace
                    )
                },
                baseline_score: 0.0,
                candidate_score: if regressed { 1.0 } else { 0.0 },
            })
        }
        "cheap" => {
            let suite_id = sampling_suite_id(&candidate.namespace);
            let mut runs = eval.list_runs(&suite_id);
            if runs.len() < 2 {
                return None;
            }
            // `list_runs` iterates a HashMap, so input order is arbitrary; tie-break on id (as
            // `retain_recent_runs` does) since runs minted within the same millisecond are
            // common.
            runs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));
            let baseline_id = runs.first()?.id.clone();
            let candidate_id = runs.last()?.id.clone();
            eval.compare_runs(&baseline_id, &candidate_id)
        }
        other => Some(GateDecision {
            verdict: "fail".to_string(),
            reason: format!("unrecognized routing bias {other:?}"),
            baseline_score: 0.0,
            candidate_score: 0.0,
        }),
    }
}

/// Gate a template candidate against the terminal task history of the namespace it was mined
/// from — the same held evidence `evolve::generate_templates` used to produce it. Returns `None`
/// when that namespace doesn't have enough terminal tasks to gate on (mirroring the floor
/// `generate_templates` itself requires).
fn gate_template(candidate: &Candidate, tasks: &[TaskRecord]) -> Option<GateDecision> {
    let scoped: Vec<TaskRecord> = tasks
        .iter()
        .filter(|t| t.namespace == candidate.namespace)
        .cloned()
        .collect();
    let report = evolve::report(&scoped);
    if report.total_tasks < TEMPLATE_GATE_MIN_TASKS {
        return None;
    }
    let passed = report.success_rate >= TEMPLATE_GATE_PASS_RATE;
    Some(GateDecision {
        verdict: if passed {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        reason: format!(
            "namespace {} task history: {}/{} succeeded ({:.0}%), gate requires >= {:.0}%",
            candidate.namespace,
            report.succeeded,
            report.total_tasks,
            report.success_rate * 100.0,
            TEMPLATE_GATE_PASS_RATE * 100.0,
        ),
        baseline_score: TEMPLATE_GATE_PASS_RATE,
        candidate_score: report.success_rate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::promotion::{
        STATUS_SUPERSEDED, propose_routing_bias_candidate, propose_template_candidates,
    };
    use crate::chisei::scoring::{Judge, JudgeError, JudgeVerdict, SampleObservation, ScoringJob};
    use std::sync::Arc;

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

    fn setup() -> (Arc<RuntimeDb>, Arc<EvalStore>, CandidateStore) {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        (db, Arc::new(EvalStore::new()), CandidateStore::new())
    }

    fn observe_batch(
        db: &RuntimeDb,
        namespace: &str,
        task_class: &str,
        base: &str,
        count: usize,
        ts_base: i64,
    ) {
        for i in 0..count {
            db.put_sample_observation(&SampleObservation {
                request_id: format!("{base}-{i}"),
                namespace: namespace.into(),
                spec: "do the thing".into(),
                resolved_model: "claude-opus-4-8".into(),
                output_content: "here is the thing".into(),
                sample_reason: "base".into(),
                input_tokens: 10,
                output_tokens: 20,
                stop_reason: "end_turn".into(),
                timestamp: ts_base + i as i64,
                scored: false,
                task_class: task_class.into(),
                cost_usd_micros: 0,
            })
            .unwrap();
        }
    }

    async fn run_cycle(db: &Arc<RuntimeDb>, eval: &Arc<EvalStore>, score: i32, passed: bool) {
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
    async fn routing_bias_candidate_gates_on_suite_history() {
        let (db, eval, store) = setup();
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
        let candidate = propose_routing_bias_candidate(&store, &db, &eval, "acme", "background")
            .expect("healthy history should propose");

        let decision = gate_candidate(&store, &db, &eval, &candidate.id, &[])
            .expect("suite has >= 2 runs, should gate");
        assert_eq!(decision.verdict, "pass");
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_GATE_PASSED);
    }

    #[tokio::test]
    async fn capable_revert_candidate_gates_pass_while_regression_is_still_active() {
        let (db, eval, store) = setup();
        // Establish a healthy baseline, then drive an active regression (mirrors
        // promotion.rs's own regression test): the newest suite run is *worse* than the oldest,
        // which is exactly what a "capable" revert candidate is proposed to fix - the direction a
        // naive "newest >= oldest" gate would get backwards.
        for (i, cycle) in ["c0", "c1"].iter().enumerate() {
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
        observe_batch(&db, "acme", "background", "c2", REGRESSION_BATCH, 300);
        run_cycle(&db, &eval, 10, false).await;
        assert!(eval.namespace_regression_signal("acme").unwrap().regressed);

        let candidate = propose_routing_bias_candidate(&store, &db, &eval, "acme", "background")
            .expect("regression should propose reverting to capable");
        assert_eq!(
            serde_json::from_str::<crate::chisei::promotion::RoutingBiasPayload>(
                &candidate.payload
            )
            .unwrap()
            .bias,
            "capable"
        );

        // The gate must pass the revert *because* the regression is still active, not despite it.
        let decision = gate_candidate(&store, &db, &eval, &candidate.id, &[])
            .expect("regression signal makes this gateable");
        assert_eq!(decision.verdict, "pass");
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_GATE_PASSED);
    }

    #[tokio::test]
    async fn routing_bias_candidate_not_gated_without_enough_suite_history() {
        let (db, eval, store) = setup();
        // Only one run exists for the suite (a single small, sub-regression-threshold cycle) — not
        // enough to compare baseline vs candidate.
        observe_batch(&db, "acme", "background", "c0", 2, 100);
        run_cycle(&db, &eval, 90, true).await;

        // Hand-build a candidate directly (the small batch alone wouldn't clear the propose floor).
        let candidate = Candidate {
            id: "candidate-routing-acme-background-1-1".into(),
            kind: KIND_ROUTING_BIAS.to_string(),
            namespace: "acme".into(),
            task_class: "background".into(),
            payload: "{\"bias\":\"cheap\"}".into(),
            rationale: "test".into(),
            status: STATUS_PROPOSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        store.upsert(candidate.clone());

        assert!(gate_candidate(&store, &db, &eval, &candidate.id, &[]).is_none());
        // Left untouched (still proposed) so it can be retried later.
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_PROPOSED);
    }

    #[test]
    fn template_candidate_gates_on_namespace_task_history() {
        let eval = EvalStore::new();
        let store = CandidateStore::new();
        let tasks: Vec<TaskRecord> = (0..4)
            .map(|i| TaskRecord {
                id: format!("t{i}"),
                spec: format!("implement the retry loop for service {i}"),
                status: "done".to_string(),
                namespace: "acme".to_string(),
                tokens_used: 100,
                original_spec: None,
                created: i,
            })
            .collect();
        let candidates = propose_template_candidates(&store, &eval, &tasks);
        assert_eq!(candidates.len(), 1);

        let decision = gate_candidate(
            &store,
            &Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
                SekaiDb::new(":memory:").unwrap(),
            ))),
            &eval,
            &candidates[0].id,
            &tasks,
        )
        .expect("4/4 done tasks should gate");
        assert_eq!(decision.verdict, "pass");
        assert_eq!(
            store.get(&candidates[0].id).unwrap().status,
            STATUS_GATE_PASSED
        );
    }

    #[test]
    fn template_candidate_fails_gate_on_poor_namespace_history() {
        let eval = EvalStore::new();
        let store = CandidateStore::new();
        // 2 done (mines the template) + several failed, dragging success_rate below the gate.
        let mut tasks: Vec<TaskRecord> = (0..2)
            .map(|i| TaskRecord {
                id: format!("done{i}"),
                spec: "implement the retry loop for the widget service".to_string(),
                status: "done".to_string(),
                namespace: "acme".to_string(),
                tokens_used: 100,
                original_spec: None,
                created: i,
            })
            .collect();
        tasks.extend((0..8).map(|i| TaskRecord {
            id: format!("failed{i}"),
            spec: "implement something else entirely".to_string(),
            status: "failed".to_string(),
            namespace: "acme".to_string(),
            tokens_used: 100,
            original_spec: None,
            created: 100 + i,
        }));
        let candidates = propose_template_candidates(&store, &eval, &tasks);
        assert_eq!(candidates.len(), 1);

        let decision = gate_candidate(
            &store,
            &Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
                SekaiDb::new(":memory:").unwrap(),
            ))),
            &eval,
            &candidates[0].id,
            &tasks,
        )
        .expect("enough terminal tasks to gate");
        assert_eq!(decision.verdict, "fail");
        assert_eq!(
            store.get(&candidates[0].id).unwrap().status,
            STATUS_GATE_FAILED
        );
    }

    #[test]
    fn already_gated_candidate_is_not_re_gated() {
        let eval = EvalStore::new();
        let store = CandidateStore::new();
        let mut candidate = Candidate {
            id: "candidate-1".into(),
            kind: KIND_TEMPLATE.to_string(),
            namespace: "acme".into(),
            task_class: String::new(),
            payload: "{}".into(),
            rationale: "test".into(),
            status: STATUS_GATE_PASSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        store.upsert(candidate.clone());
        candidate.status = STATUS_GATE_PASSED.to_string();

        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        assert!(gate_candidate(&store, &db, &eval, &candidate.id, &[]).is_none());
    }

    #[test]
    fn a_candidate_superseded_after_the_read_is_not_overwritten() {
        let eval = EvalStore::new();
        let store = CandidateStore::new();
        let candidate = Candidate {
            id: "candidate-1".into(),
            kind: KIND_TEMPLATE.to_string(),
            namespace: "acme".into(),
            task_class: String::new(),
            payload: "{}".into(),
            rationale: "test".into(),
            status: STATUS_PROPOSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        store.upsert(candidate.clone());

        // Simulate a concurrent proposer superseding this candidate between `gate_candidate`'s
        // initial read and its write - the CAS write inside `gate_candidate` must not resurrect it
        // as gate_passed/gate_failed.
        store.transition(&candidate.id, STATUS_PROPOSED, STATUS_SUPERSEDED);

        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        assert!(
            gate_candidate(
                &store,
                &db,
                &eval,
                &candidate.id,
                &[
                    TaskRecord {
                        id: "t1".into(),
                        spec: "x".into(),
                        status: "done".into(),
                        namespace: "acme".into(),
                        tokens_used: 0,
                        original_spec: None,
                        created: 1,
                    },
                    TaskRecord {
                        id: "t2".into(),
                        spec: "x".into(),
                        status: "done".into(),
                        namespace: "acme".into(),
                        tokens_used: 0,
                        original_spec: None,
                        created: 2,
                    },
                ]
            )
            .is_none()
        );
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_SUPERSEDED);
    }

    #[test]
    fn capable_candidate_left_proposed_when_no_regression_evidence_exists() {
        // A "capable" candidate with no tracked iterations for its namespace at all (distinct from
        // a resolved regression) must be left `proposed` to retry, not terminally gate_failed.
        let eval = EvalStore::new();
        let store = CandidateStore::new();
        let candidate = Candidate {
            id: "candidate-1".into(),
            kind: KIND_ROUTING_BIAS.to_string(),
            namespace: "ghost-namespace".into(),
            task_class: "background".into(),
            payload: "{\"bias\":\"capable\"}".into(),
            rationale: "test".into(),
            status: STATUS_PROPOSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        store.upsert(candidate.clone());

        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        assert!(gate_candidate(&store, &db, &eval, &candidate.id, &[]).is_none());
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_PROPOSED);
    }

    #[test]
    fn corrupt_routing_bias_payload_is_terminally_gate_failed_not_stuck_forever() {
        let eval = EvalStore::new();
        let store = CandidateStore::new();
        let candidate = Candidate {
            id: "candidate-1".into(),
            kind: KIND_ROUTING_BIAS.to_string(),
            namespace: "acme".into(),
            task_class: "background".into(),
            payload: String::new(), // e.g. from a serialization failure upstream
            rationale: "test".into(),
            status: STATUS_PROPOSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        store.upsert(candidate.clone());

        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let decision = gate_candidate(&store, &db, &eval, &candidate.id, &[])
            .expect("a corrupt payload must be decided, not left indefinitely proposed");
        assert_eq!(decision.verdict, "fail");
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_GATE_FAILED);
    }

    #[test]
    fn unrecognized_bias_value_is_terminally_gate_failed() {
        let eval = EvalStore::new();
        let store = CandidateStore::new();
        let candidate = Candidate {
            id: "candidate-1".into(),
            kind: KIND_ROUTING_BIAS.to_string(),
            namespace: "acme".into(),
            task_class: "background".into(),
            payload: "{\"bias\":\"ludicrous\"}".into(),
            rationale: "test".into(),
            status: STATUS_PROPOSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        store.upsert(candidate.clone());

        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let decision = gate_candidate(&store, &db, &eval, &candidate.id, &[])
            .expect("an unrecognized bias must be rejected, not silently treated as cheap");
        assert_eq!(decision.verdict, "fail");
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_GATE_FAILED);
    }
}
