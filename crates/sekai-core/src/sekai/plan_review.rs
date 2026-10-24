//! One review-queue bundle over a simulated plan (#1678, layer 2 of #1460).
//!
//! A simulated plan is submitted for review once, bound to one stored
//! simulation and its digest. The review names the queues its steps route
//! to, as their Action types would place a parked instance. One decision,
//! grant or deny, covers the whole plan and is bound to the plan id and the
//! simulation digest. The decider must be able to decide every step as a
//! single parked Action; a step they could not decide refuses the decision,
//! named by its position, and nothing is recorded. There is no partial
//! approval, and a denied plan can never execute. Authority is rechecked per
//! step at execution.

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_instance::{DECISION_DENY, DECISION_GRANT};
use crate::sekai::action_plan::{PlanError, PlanStep, ProposedPlan};

pub const REVIEW_DIGEST_MISMATCH: &str = "plan_review_digest_mismatch";
pub const REVIEW_ALREADY_DECIDED: &str = "plan_review_already_decided";
pub const REVIEW_STEP_NOT_DECIDABLE: &str = "plan_review_step_not_decidable";
const MAX_REASON: usize = 2048;

/// The bundle item for one plan. `decision` is empty while it is pending.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanReview {
    pub namespace: String,
    pub plan_id: String,
    pub simulation_id: String,
    pub simulation_digest: String,
    /// The queue each step routes to, by position; empty when none. Routing
    /// can depend on parameters, so a reader sees only the queues of steps
    /// whose objects they may read ([`PlanReview::queue_ids`]).
    pub step_queues: Vec<String>,
    pub submitted_by: String,
    pub submitted_at_ms: i64,
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub decided_by: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub decided_at_ms: i64,
    /// Whether the decider granted under a space-scoped credential, whose
    /// approval role cannot be revalidated without it (#1679).
    #[serde(default)]
    pub decided_in_space: bool,
}

impl PlanReview {
    /// Distinct, sorted queues of the steps not `hidden` (by position).
    pub fn queue_ids(&self, hidden: impl Fn(usize) -> bool) -> Vec<String> {
        let mut queues: Vec<String> = self
            .step_queues
            .iter()
            .enumerate()
            .filter(|(index, queue)| !queue.is_empty() && !hidden(*index))
            .map(|(_, queue)| queue.clone())
            .collect();
        queues.sort();
        queues.dedup();
        queues
    }
}

#[derive(Debug)]
pub enum ReviewError {
    Plan(PlanError),
    /// The caller may not decide this review, disclosing nothing.
    AccessDenied,
    /// The step at this position (0-based) is beyond the decider's authority.
    StepNotDecidable {
        index: usize,
        type_id: String,
    },
    DigestMismatch,
    AlreadyDecided,
}

impl From<String> for ReviewError {
    fn from(error: String) -> Self {
        Self::Plan(PlanError::Store(error))
    }
}

impl From<PlanError> for ReviewError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

/// The queue each step routes to, as its Action type would place a parked
/// instance of it; empty when none.
fn step_queues(db: &RuntimeDb, plan: &ProposedPlan) -> Result<Vec<String>, String> {
    plan.steps
        .iter()
        .map(|step| {
            Ok(db
                .get_governed_action_type(&plan.namespace, &step.type_id, &step.version)?
                .filter(|type_def| {
                    crate::sekai::review_queue::routes_to_queue(
                        &type_def.review_queue,
                        &step.parameters_json,
                    )
                })
                .map(|type_def| type_def.review_queue.queue_id)
                .unwrap_or_default())
        })
        .collect()
}

/// Submits a simulated plan for review. Only its planner submits it, so the
/// planner is the one subject every step's queue placement and the decision
/// exclude. A retry returns the stored review; a plan already submitted with
/// another simulation is a conflict, since a decision binds one simulation.
pub fn submit_review(
    db: &RuntimeDb,
    namespace: &str,
    plan_id: &str,
    simulation_id: &str,
    submitter: &str,
    now_ms: i64,
) -> Result<PlanReview, ReviewError> {
    let plan = db
        .get_plan(namespace, plan_id)?
        .ok_or(PlanError::NotFound)?;
    if submitter != plan.planner {
        return Err(ReviewError::AccessDenied);
    }
    let simulation = db
        .get_plan_simulation(namespace, plan_id, simulation_id)?
        .ok_or(PlanError::NotFound)?;
    let stored = db.put_plan_review(&PlanReview {
        namespace: namespace.into(),
        plan_id: plan_id.into(),
        simulation_id: simulation.simulation_id,
        simulation_digest: simulation.digest,
        step_queues: step_queues(db, &plan)?,
        submitted_by: submitter.into(),
        submitted_at_ms: now_ms,
        ..PlanReview::default()
    })?;
    if stored.simulation_id != simulation_id {
        return Err(PlanError::Conflict.into());
    }
    Ok(stored)
}

pub struct ReviewDecision<'a> {
    pub simulation_digest: &'a str,
    pub decision: &'a str,
    pub reason: &'a str,
    /// The decider presented a space-scoped credential.
    pub in_space: bool,
}

/// Decides a submitted review for the whole plan. The planner, who
/// submitted it, never decides it. `may_decide` answers whether the decider could
/// decide the step as a single parked Action; the first step it refuses is
/// named and nothing is written. The same decision again replays (`true`);
/// another fails.
pub fn decide_review(
    db: &RuntimeDb,
    namespace: &str,
    plan_id: &str,
    request: &ReviewDecision<'_>,
    decider: &str,
    may_decide: &dyn Fn(&ProposedPlan, &PlanStep) -> bool,
    now_ms: i64,
) -> Result<(PlanReview, bool), ReviewError> {
    if request.decision != DECISION_GRANT && request.decision != DECISION_DENY {
        return Err(PlanError::Invalid("decision must be grant or deny".into()).into());
    }
    if request.reason.len() > MAX_REASON {
        return Err(PlanError::Invalid(format!("reason exceeds {MAX_REASON} bytes")).into());
    }
    let review = db
        .get_plan_review(namespace, plan_id)?
        .ok_or(ReviewError::AccessDenied)?;
    let plan = db
        .get_plan(namespace, plan_id)?
        .ok_or(ReviewError::AccessDenied)?;
    if decider == plan.planner {
        return Err(ReviewError::AccessDenied);
    }
    if let Some((index, step)) = plan
        .steps
        .iter()
        .enumerate()
        .find(|(_, step)| !may_decide(&plan, step))
    {
        return Err(ReviewError::StepNotDecidable {
            index,
            type_id: step.type_id.clone(),
        });
    }
    if request.simulation_digest != review.simulation_digest {
        return Err(ReviewError::DigestMismatch);
    }
    let decided = |review: PlanReview| {
        if review.decision == request.decision {
            Ok((review, true))
        } else {
            Err(ReviewError::AlreadyDecided)
        }
    };
    if !review.decision.is_empty() {
        return decided(review);
    }
    let next = PlanReview {
        decision: request.decision.into(),
        decided_by: decider.into(),
        reason: request.reason.into(),
        decided_at_ms: now_ms,
        decided_in_space: request.in_space,
        ..review
    };
    if db.decide_plan_review(&next)? {
        return Ok((next, false));
    }
    // Another decision landed first.
    decided(
        db.get_plan_review(namespace, plan_id)?
            .ok_or(ReviewError::AccessDenied)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A review is stored once and decided once on either backend.
    fn store_contract(db: &RuntimeDb, ns: &str) {
        let review = PlanReview {
            namespace: ns.into(),
            plan_id: "plan-1".into(),
            simulation_id: "sim-1".into(),
            simulation_digest: "sha256:one".into(),
            submitted_by: "planner".into(),
            submitted_at_ms: 1,
            ..PlanReview::default()
        };
        assert_eq!(db.put_plan_review(&review).unwrap(), review);
        let other = PlanReview {
            simulation_id: "sim-2".into(),
            ..review.clone()
        };
        assert_eq!(db.put_plan_review(&other).unwrap(), review);
        let granted = PlanReview {
            decision: DECISION_GRANT.into(),
            decided_by: "alice".into(),
            decided_at_ms: 2,
            ..review.clone()
        };
        assert!(db.decide_plan_review(&granted).unwrap());
        let denied = PlanReview {
            decision: DECISION_DENY.into(),
            decided_by: "bob".into(),
            ..review
        };
        assert!(!db.decide_plan_review(&denied).unwrap());
        assert_eq!(db.get_plan_review(ns, "plan-1").unwrap(), Some(granted));
        assert_eq!(db.get_plan_review(ns, "plan-2").unwrap(), None);
    }

    #[test]
    fn a_hidden_step_does_not_name_its_queue() {
        let review = PlanReview {
            step_queues: vec!["risk".into(), String::new(), "audit".into(), "risk".into()],
            ..PlanReview::default()
        };
        assert_eq!(review.queue_ids(|_| false), ["audit", "risk"]);
        // Only the hidden step routes to audit.
        assert_eq!(review.queue_ids(|index| index == 2), ["risk"]);
    }

    #[test]
    fn sqlite_reviews_are_stored_and_decided_once() {
        store_contract(&RuntimeDb::memory(), "acme");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_reviews_are_stored_and_decided_once() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(Arc::new(db.unwrap()));
        // A namespace of its own, so concurrent or repeated runs never share
        // a record.
        let ns = format!("reviews-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        store_contract(&db, &ns);
    }
}
