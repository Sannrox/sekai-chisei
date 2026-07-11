//! Closed-loop self-improvement, promote/rollback stage: turn a `gate_passed` candidate into a
//! live, governed override of the default routing heuristic, and auto-revert it if the namespace
//! it applies to later regresses. This generalizes the previously audit-only `eval_regressed`
//! observation (`gateway.rs`'s `gateway.eval_regression` hook, which only logs) into an active
//! decision: promotion and rollback are both first-class, audited actions here, and a promoted
//! candidate has a real effect on live routing (see `ActivePromotions`).
//!
//! Every promotion and rollback is recorded as a `chisei.promotion` audit decision — the same
//! durable, queryable log every other stage of this loop writes to.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::chisei::eval::EvalStore;
use crate::chisei::promotion::{
    Candidate, CandidateStore, KIND_ROUTING_BIAS, RoutingBiasPayload, STATUS_GATE_PASSED,
    STATUS_PROMOTED, STATUS_ROLLED_BACK,
};
use crate::db::sekai::SekaiDb;

/// Live, governed routing-bias overrides keyed by (namespace, task_class), consulted by
/// `resolve_policy` (`grpc/chisei_service.rs`) alongside the static `cheap_route_bias` heuristic.
///
/// Only a `"capable"` override has an active effect today: it forces capable-tier routing for its
/// (namespace, task_class) even when the class would otherwise default to cheap, closing a gap the
/// live per-request regression check alone can't cover (e.g. a namespace whose regressed iteration
/// was since pruned, or a scope-matching mismatch between the raw namespace and the resolved
/// policy scope). A `"cheap"` override doesn't change behavior beyond what `cheap_route_bias`
/// already grants eligible classes by default — it exists so the promoted state is visible and
/// auditable — but is tracked the same way so a future stricter default (only route cheap when
/// explicitly promoted) is a policy change here, not a schema change.
#[derive(Default)]
pub struct ActivePromotions {
    overrides: Mutex<HashMap<(String, String), String>>,
}

impl ActivePromotions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a `"capable"` override is currently active for (namespace, task_class).
    pub fn capable_override_active(&self, namespace: &str, task_class: &str) -> bool {
        self.overrides
            .lock()
            .expect("active promotions poisoned")
            .get(&(namespace.to_string(), task_class.to_string()))
            .map(|bias| bias == "capable")
            .unwrap_or(false)
    }

    /// The currently active bias for (namespace, task_class), if any.
    pub fn active_bias(&self, namespace: &str, task_class: &str) -> Option<String> {
        self.overrides
            .lock()
            .expect("active promotions poisoned")
            .get(&(namespace.to_string(), task_class.to_string()))
            .cloned()
    }

    fn set(&self, namespace: &str, task_class: &str, bias: &str) {
        self.overrides
            .lock()
            .expect("active promotions poisoned")
            .insert(
                (namespace.to_string(), task_class.to_string()),
                bias.to_string(),
            );
    }

    /// Remove the (namespace, task_class) override, but only if its current value is still
    /// `expected_bias` — a compare-and-remove. `promote_candidate` maintains the invariant that
    /// only one candidate is ever `promoted` per key (superseding any other on promotion), so this
    /// should never actually find a mismatch in practice; it exists as a second line of defense so
    /// a rollback can never clobber a different, still-live candidate's override for the same key
    /// (e.g. a promoted "capable" revert for a namespace whose earlier "cheap" promotion's
    /// rollback fires after the revert already took over the same key).
    fn clear_if(&self, namespace: &str, task_class: &str, expected_bias: &str) {
        let mut overrides = self.overrides.lock().expect("active promotions poisoned");
        if let std::collections::hash_map::Entry::Occupied(entry) =
            overrides.entry((namespace.to_string(), task_class.to_string()))
            && entry.get() == expected_bias
        {
            entry.remove();
        }
    }
}

/// Promote one `gate_passed` candidate: atomically (via `CandidateStore::transition`) advance its
/// status to `promoted`, activate its routing-bias override if it's a `KIND_ROUTING_BIAS`
/// candidate, and record a `chisei.promotion` audit decision. Returns `None` if the candidate
/// doesn't exist, isn't `gate_passed`, a concurrent writer already moved it, or (for a routing-bias
/// candidate) its payload doesn't parse — in every `None` case except the parse failure, nothing
/// is written; a parse failure is recorded as an immediate rollback instead of being left silently
/// `promoted` with no override installed (which would make the audit log claim a live effect that
/// doesn't exist).
///
/// `ActivePromotions` holds exactly one override per (namespace, task_class): promoting a
/// candidate for a key that already has a different `promoted` candidate rolls that other one back
/// first, keeping candidate status consistent with the registry's single-active-value reality
/// (otherwise an older promoted candidate would silently lose its live effect while its status
/// still read `promoted`).
pub fn promote_candidate(
    store: &CandidateStore,
    active: &ActivePromotions,
    db: &SekaiDb,
    candidate_id: &str,
) -> Option<()> {
    let promoted = store.transition(candidate_id, STATUS_GATE_PASSED, STATUS_PROMOTED)?;

    if promoted.kind == KIND_ROUTING_BIAS {
        let Ok(payload) = serde_json::from_str::<RoutingBiasPayload>(&promoted.payload) else {
            store.transition(&promoted.id, STATUS_PROMOTED, STATUS_ROLLED_BACK);
            record(
                db,
                "rolled_back",
                &promoted,
                "unparseable routing-bias payload; promotion reverted",
            );
            return None;
        };

        for other in store.list_by_status(STATUS_PROMOTED) {
            if other.id != promoted.id
                && other.kind == KIND_ROUTING_BIAS
                && other.namespace == promoted.namespace
                && other.task_class == promoted.task_class
                && let Some(superseded) =
                    store.transition(&other.id, STATUS_PROMOTED, STATUS_ROLLED_BACK)
            {
                record(
                    db,
                    "rolled_back",
                    &superseded,
                    "superseded by a newer promotion for the same (namespace, task_class)",
                );
            }
        }
        active.set(&promoted.namespace, &promoted.task_class, &payload.bias);
    }

    record(db, "promoted", &promoted, "promoted candidate to live");
    Some(())
}

/// Scan `promoted` routing-bias candidates and auto-roll-back any whose namespace shows an active
/// eval regression right now. A promoted `"cheap"` bias is rolled back (regression means the
/// evidence that justified routing cheap no longer holds); a promoted `"capable"` revert is left
/// alone — it already *is* the safe state a regression calls for, so there's nothing to revert.
/// Returns the number of candidates rolled back.
pub fn check_rollbacks(
    store: &CandidateStore,
    active: &ActivePromotions,
    eval: &EvalStore,
    db: &SekaiDb,
) -> usize {
    let mut rolled_back = 0;
    for candidate in store.list_by_status(STATUS_PROMOTED) {
        if candidate.kind != KIND_ROUTING_BIAS {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<RoutingBiasPayload>(&candidate.payload) else {
            continue;
        };
        if payload.bias != "cheap" {
            continue;
        }
        let regressed = crate::chisei::scoring::task_class_or_namespace_regressed(
            db,
            eval,
            &candidate.namespace,
            &candidate.task_class,
        );
        if !regressed {
            continue;
        }
        let Some(rolled) = store.transition(&candidate.id, STATUS_PROMOTED, STATUS_ROLLED_BACK)
        else {
            continue;
        };
        active.clear_if(&rolled.namespace, &rolled.task_class, "cheap");
        record(
            db,
            "rolled_back",
            &rolled,
            "auto-rolled back: task-class quality regression detected while promoted",
        );
        rolled_back += 1;
    }
    rolled_back
}

fn record(db: &SekaiDb, outcome: &str, candidate: &Candidate, reason: &str) {
    let mut evidence = HashMap::new();
    evidence.insert("kind".to_string(), candidate.kind.clone());
    evidence.insert("namespace".to_string(), candidate.namespace.clone());
    evidence.insert("task_class".to_string(), candidate.task_class.clone());
    evidence.insert("payload".to_string(), candidate.payload.clone());
    let _ = db.record_decision(&crate::sekai::audit::Decision {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: "chisei.promotion".into(),
        action: outcome.into(),
        reason: reason.to_string(),
        evidence,
        target_id: candidate.id.clone(),
        outcome: outcome.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::eval::{CaseResult, Run};
    use std::sync::Arc;

    fn setup() -> (Arc<SekaiDb>, EvalStore, CandidateStore, ActivePromotions) {
        (
            Arc::new(SekaiDb::new(":memory:").unwrap()),
            EvalStore::new(),
            CandidateStore::new(),
            ActivePromotions::new(),
        )
    }

    fn gate_passed_routing_candidate(namespace: &str, task_class: &str, bias: &str) -> Candidate {
        Candidate {
            id: format!("candidate-{namespace}-{task_class}-{bias}"),
            kind: KIND_ROUTING_BIAS.to_string(),
            namespace: namespace.to_string(),
            task_class: task_class.to_string(),
            payload: serde_json::to_string(&RoutingBiasPayload {
                bias: bias.to_string(),
            })
            .unwrap(),
            rationale: "test".to_string(),
            status: STATUS_GATE_PASSED.to_string(),
            source_ref: "test".to_string(),
            created: 1,
        }
    }

    #[test]
    fn promoting_a_cheap_candidate_activates_the_override() {
        let (db, _eval, store, active) = setup();
        let candidate = gate_passed_routing_candidate("acme", "background", "cheap");
        store.upsert(candidate.clone());

        assert!(promote_candidate(&store, &active, &db, &candidate.id).is_some());
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_PROMOTED);
        assert_eq!(
            active.active_bias("acme", "background"),
            Some("cheap".to_string())
        );
    }

    #[test]
    fn only_gate_passed_candidates_can_be_promoted() {
        let (db, _eval, store, active) = setup();
        let mut candidate = gate_passed_routing_candidate("acme", "background", "cheap");
        candidate.status = crate::chisei::promotion::STATUS_PROPOSED.to_string();
        store.upsert(candidate.clone());

        assert!(promote_candidate(&store, &active, &db, &candidate.id).is_none());
        assert!(active.active_bias("acme", "background").is_none());
    }

    #[test]
    fn regressed_namespace_rolls_back_a_promoted_cheap_bias() {
        let (db, eval, store, active) = setup();
        let candidate = gate_passed_routing_candidate("acme", "background", "cheap");
        store.upsert(candidate.clone());
        promote_candidate(&store, &active, &db, &candidate.id).unwrap();
        assert!(!active.capable_override_active("acme", "background"));
        assert!(active.active_bias("acme", "background").is_some());

        // Drive a regression signal for the namespace directly against EvalStore.
        let suite_id = "sampling-acme".to_string();
        eval.create_suite(crate::chisei::eval::Suite {
            id: suite_id.clone(),
            name: "test".into(),
            description: "test".into(),
            cases: vec![crate::chisei::eval::Case {
                id: "c1".into(),
                name: "c1".into(),
                namespace: "acme".into(),
                spec: "x".into(),
                assertions: vec![],
            }],
        });
        let good = Run {
            id: "run-1-good".into(),
            suite_id: suite_id.clone(),
            config_ref: "m".into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: true,
                status: "ok".into(),
                result: String::new(),
                score: 90,
                reason: String::new(),
                elapsed: 0,
            }],
            timestamp: 100,
        };
        eval.create_run(good.clone());
        eval.track_iteration(&suite_id, &good.id, "sampling/acme", "d1")
            .unwrap();
        let bad = Run {
            id: "run-2-bad".into(),
            suite_id: suite_id.clone(),
            config_ref: "m".into(),
            results: vec![CaseResult {
                case_id: "c1".into(),
                passed: false,
                status: "ok".into(),
                result: String::new(),
                score: 10,
                reason: String::new(),
                elapsed: 0,
            }],
            timestamp: 200,
        };
        eval.create_run(bad.clone());
        eval.track_iteration(&suite_id, &bad.id, "sampling/acme", "d2")
            .unwrap();
        assert!(eval.namespace_regression_signal("acme").unwrap().regressed);

        let rolled_back = check_rollbacks(&store, &active, &eval, &db);
        assert_eq!(rolled_back, 1);
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_ROLLED_BACK);
        assert!(active.active_bias("acme", "background").is_none());
    }

    #[test]
    fn a_promoted_capable_revert_is_never_rolled_back() {
        let (db, eval, store, active) = setup();
        let candidate = gate_passed_routing_candidate("acme", "background", "capable");
        store.upsert(candidate.clone());
        promote_candidate(&store, &active, &db, &candidate.id).unwrap();
        assert!(active.capable_override_active("acme", "background"));

        // No regression tracked at all - nothing to roll back regardless.
        assert_eq!(check_rollbacks(&store, &active, &eval, &db), 0);
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_PROMOTED);
        assert!(active.capable_override_active("acme", "background"));
    }

    #[test]
    fn stable_namespace_does_not_roll_back_a_promoted_cheap_bias() {
        let (db, eval, store, active) = setup();
        let candidate = gate_passed_routing_candidate("acme", "background", "cheap");
        store.upsert(candidate.clone());
        promote_candidate(&store, &active, &db, &candidate.id).unwrap();

        assert_eq!(check_rollbacks(&store, &active, &eval, &db), 0);
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_PROMOTED);
        assert_eq!(
            active.active_bias("acme", "background"),
            Some("cheap".to_string())
        );
    }

    #[test]
    fn promoting_a_new_candidate_supersedes_an_older_promoted_one_for_the_same_key() {
        let (db, _eval, store, active) = setup();
        let cheap = gate_passed_routing_candidate("acme", "background", "cheap");
        store.upsert(cheap.clone());
        promote_candidate(&store, &active, &db, &cheap.id).unwrap();
        assert_eq!(store.get(&cheap.id).unwrap().status, STATUS_PROMOTED);

        // A second, later candidate for the *same* (namespace, task_class) is promoted (e.g. a
        // "capable" revert proposed and gated while the older "cheap" one was still promoted).
        let capable = gate_passed_routing_candidate("acme", "background", "capable");
        store.upsert(capable.clone());
        promote_candidate(&store, &active, &db, &capable.id).unwrap();

        // The older candidate is rolled back (not left `promoted` with a phantom live effect),
        // and the registry reflects only the newer candidate's bias.
        assert_eq!(store.get(&cheap.id).unwrap().status, STATUS_ROLLED_BACK);
        assert_eq!(store.get(&capable.id).unwrap().status, STATUS_PROMOTED);
        assert_eq!(
            active.active_bias("acme", "background"),
            Some("capable".to_string())
        );
    }

    #[test]
    fn rolling_back_a_superseded_candidate_does_not_clobber_the_newer_overrides_entry() {
        let (db, eval, store, active) = setup();
        // Promote "cheap", then supersede it with "capable" (as above) - the "cheap" candidate is
        // now STATUS_ROLLED_BACK, but if `check_rollbacks` were ever called on it again (e.g. a
        // stale reference, or a race), it must not be able to clear the *newer* candidate's
        // now-active "capable" override via the (namespace, task_class) key they share.
        let cheap = gate_passed_routing_candidate("acme", "background", "cheap");
        store.upsert(cheap.clone());
        promote_candidate(&store, &active, &db, &cheap.id).unwrap();
        let capable = gate_passed_routing_candidate("acme", "background", "capable");
        store.upsert(capable.clone());
        promote_candidate(&store, &active, &db, &capable.id).unwrap();
        assert_eq!(
            active.active_bias("acme", "background"),
            Some("capable".to_string())
        );

        // Directly exercise the compare-and-remove: clearing under the *old* candidate's bias
        // must not remove the entry, since it no longer matches.
        active.clear_if("acme", "background", "cheap");
        assert_eq!(
            active.active_bias("acme", "background"),
            Some("capable".to_string())
        );
        // check_rollbacks also has nothing to do here (cheap is already rolled_back).
        assert_eq!(check_rollbacks(&store, &active, &eval, &db), 0);
        assert_eq!(
            active.active_bias("acme", "background"),
            Some("capable".to_string())
        );
    }

    #[test]
    fn unparseable_payload_is_rolled_back_instead_of_silently_promoted() {
        let (db, _eval, store, active) = setup();
        let candidate = Candidate {
            id: "candidate-1".into(),
            kind: KIND_ROUTING_BIAS.to_string(),
            namespace: "acme".into(),
            task_class: "background".into(),
            payload: String::new(),
            rationale: "test".into(),
            status: STATUS_GATE_PASSED.to_string(),
            source_ref: "test".into(),
            created: 1,
        };
        store.upsert(candidate.clone());

        assert!(promote_candidate(&store, &active, &db, &candidate.id).is_none());
        assert_eq!(store.get(&candidate.id).unwrap().status, STATUS_ROLLED_BACK);
        assert!(active.active_bias("acme", "background").is_none());
    }
}
