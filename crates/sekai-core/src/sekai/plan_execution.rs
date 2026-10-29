//! Executing an approved plan (#1679, layer 3 of #1460).
//!
//! The steps of a granted plan run in order through the normal Action
//! submit path. Each is submitted as the planner with idempotency key
//! `plan:{plan_id}:step:{index}`; a step its policy parks is then decided
//! by the plan's approver. Before every step:
//! - the approver's authority over it is rechecked;
//! - the step is simulated again through the preview path. The plan stops if
//!   its prediction differs from the approved simulation, or its object's
//!   revision is not the approved one (or, for an object an earlier step of
//!   this plan wrote, the revision that write produced).
//!
//! A refused or failed step stops the plan as well. A stopped plan records
//! why and where, and later steps never run.
//!
//! The revision a step was checked against travels into admission, which
//! refuses the write unless the object it writes still has it, in the same
//! read the write applies against. The revision recorded for a later step
//! on the same object is the one the write itself produced.
//!
//! Progress is durable and fenced by a revision. A restarted executor
//! resumes at the next step. A step already submitted before a crash is
//! found by its idempotency key, must match the planned submission, and is
//! completed through admission's replay, never applied again. Its produced
//! revision is then unknown, so a later step on the same object stops
//! rather than trust a read. Two executors racing on one plan cannot both
//! advance it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::action_instance::{
    ActionInstance, DECISION_GRANT, STATUS_ADMITTED, STATUS_DENIED, STATUS_PARKED,
};
use crate::sekai::action_plan::{
    PlanError, PlanStep, ProposedPlan, SimulationContext, StepSimulation, simulate_step,
};

pub const EXECUTION_RUNNING: &str = "running";
pub const EXECUTION_COMPLETED: &str = "completed";
pub const EXECUTION_STOPPED: &str = "stopped";

pub const STOP_NOT_APPROVED: &str = "plan_not_approved";
pub const STOP_AUTHORITY_REVOKED: &str = "approver_authority_revoked";
pub const STOP_SIMULATION_CHANGED: &str = "simulation_changed";
pub const STOP_STEP_REFUSED: &str = "step_refused";
/// The instance under a step's key is not the planned submission.
pub const STOP_STEP_MISMATCH: &str = "step_instance_mismatch";

/// What one step's execution produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepExecution {
    pub index: u32,
    pub instance_id: String,
    pub operation_id: String,
    pub status: String,
    /// The revision the step's write produced, for later steps on the same
    /// object; empty when unknown (recovered after a crash).
    pub object_revision_after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanExecution {
    pub namespace: String,
    pub plan_id: String,
    pub simulation_id: String,
    pub simulation_digest: String,
    pub status: String,
    pub next_step: u32,
    pub steps: Vec<StepExecution>,
    /// Why a stopped plan stopped, and before which step.
    pub stop_reason: String,
    pub stopped_at_step: Option<u32>,
    pub started_by: String,
    pub updated_at_ms: i64,
    /// Fences concurrent executors: a write must name the revision it read.
    pub revision: u64,
    /// The run that owns the execution until `claim_until_ms`; empty when
    /// none does.
    #[serde(default)]
    pub claim_holder: String,
    #[serde(default)]
    pub claim_until_ms: i64,
}

/// An admitted instance and the revision of the object its write produced;
/// none on a replay or when nothing was written.
pub type Admitted = (ActionInstance, Option<String>);

/// Why a submit or decision did not admit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    /// Refused for good; the plan stops.
    Refused(String),
    /// The same key's admission is still in flight; a later call retries,
    /// unless it has been in flight past the lease (abandoned by a crash).
    InProgress,
    /// The store or a dependency failed; the plan stays running and a later
    /// call retries, however old the instance.
    Unavailable,
}

/// How long one execution owns a plan before another may take it over.
pub const EXECUTION_LEASE_MS: i64 = 120_000;

/// What execution needs from the transport, which authenticates the caller
/// and owns the submit and decision admission paths.
pub struct ExecutionPorts<'a> {
    /// Submits a step as the planner under its idempotency key, refused
    /// unless the object still has the expected revision (empty: unchecked).
    /// The same key replays the stored instance without applying it again.
    pub submit: &'a dyn Fn(&PlanStep, &str, &str) -> Result<Admitted, PortError>,
    /// Grants a parked instance as the plan's approver, only while the run
    /// holding the named execution claim still owns the plan.
    pub decide: &'a dyn Fn(&ActionInstance, &str) -> Result<Admitted, PortError>,
    /// Whether the planner may still submit `step` in the namespace.
    pub planner_may_submit: &'a dyn Fn(&PlanStep) -> Result<bool, String>,
    /// The current time, read afresh for every lease decision.
    pub clock: &'a dyn Fn() -> i64,
    /// Whether the plan's approver may still decide `step` as a parked Action.
    pub approver_may_decide: &'a dyn Fn(&ProposedPlan, &PlanStep) -> Result<bool, String>,
    /// The preview context steps are simulated in again.
    pub simulation: SimulationContext<'a>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExecutionError {
    Plan(PlanError),
    /// Another executor advanced the plan; the stored execution is current.
    Superseded(Box<PlanExecution>),
}

impl From<String> for ExecutionError {
    fn from(error: String) -> Self {
        Self::Plan(PlanError::Store(error))
    }
}

impl From<PlanError> for ExecutionError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

/// The idempotency key of step `index` of `plan_id`; scoped by namespace.
pub fn step_idempotency_key(plan_id: &str, index: usize) -> String {
    format!("plan:{plan_id}:step:{index}")
}

/// The simulation context at the time a step is checked: a run spans many
/// steps.
fn step_context<'a>(ports: &ExecutionPorts<'a>) -> SimulationContext<'a> {
    SimulationContext {
        now_ms: (ports.clock)(),
        ..ports.simulation
    }
}

/// Both parties' authority over `step` now: the approver may decide it and
/// the planner may submit it (and, for a parked step, read its object).
/// `Err` when a dependency failed and it could not be determined.
fn authorized(
    ports: &ExecutionPorts<'_>,
    plan: &ProposedPlan,
    step: &PlanStep,
    planner_must_read: bool,
) -> Result<bool, String> {
    Ok((ports.approver_may_decide)(plan, step)?
        && (ports.planner_may_submit)(step)?
        && (!planner_must_read || (ports.simulation.visible_object)(&step.object_id)?.is_some()))
}

/// Whether `instance` is the planned submission of `step`: the planner's,
/// with the step's type, version and parameters and no evidence, as the
/// executor submits it (so a replay of it matches).
fn is_planned(instance: &ActionInstance, plan: &ProposedPlan, step: &PlanStep) -> bool {
    instance.principal == plan.planner
        && instance.type_id == step.type_id
        && instance.version == step.version
        && instance.parameters_json == step.parameters_json
        && instance.evidence_submission_ids.is_empty()
}

/// Whether a re-simulated step predicts what was approved. Revisions are
/// compared against `expected_revision` instead.
fn same_prediction(current: &StepSimulation, approved: &StepSimulation) -> bool {
    current.outcome == approved.outcome
        && current.reason_code == approved.reason_code
        && current.policy_decision == approved.policy_decision
        && current.approval_state == approved.approval_state
        && current.budget_decision == approved.budget_decision
}

/// Runs a granted plan from where its execution stands. A completed or
/// stopped execution is returned as it is.
pub fn execute_plan(
    db: &RuntimeDb,
    ports: &ExecutionPorts<'_>,
    namespace: &str,
    plan_id: &str,
    started_by: &str,
) -> Result<PlanExecution, ExecutionError> {
    let now_ms = ports.simulation.now_ms;
    let plan = db
        .get_plan(namespace, plan_id)?
        .ok_or(PlanError::NotFound)?;
    let review = db
        .get_plan_review(namespace, plan_id)?
        .ok_or(PlanError::NotFound)?;
    let approved = db
        .get_plan_simulation(namespace, plan_id, &review.simulation_id)?
        .filter(|simulation| simulation.digest == review.simulation_digest)
        .ok_or(PlanError::NotFound)?;
    let mut execution = match db.get_plan_execution(namespace, plan_id)? {
        Some(execution) if execution.status != EXECUTION_RUNNING => return Ok(execution),
        Some(execution) => execution,
        None => {
            let fresh = PlanExecution {
                namespace: namespace.into(),
                plan_id: plan_id.into(),
                simulation_id: approved.simulation_id.clone(),
                simulation_digest: approved.digest.clone(),
                status: EXECUTION_RUNNING.into(),
                next_step: 0,
                steps: Vec::new(),
                stop_reason: String::new(),
                stopped_at_step: None,
                started_by: started_by.into(),
                updated_at_ms: now_ms,
                revision: 0,
                claim_holder: String::new(),
                claim_until_ms: 0,
            };
            // A concurrent first call may have created, and even stopped, it.
            let stored = db.put_plan_execution(&fresh)?;
            if stored.status != EXECUTION_RUNNING {
                return Ok(stored);
            }
            stored
        }
    };
    // Own the execution before any side effect. A live claim of another run
    // leaves it to that run; an expired one (a crashed run) is taken over.
    if !execution.claim_holder.is_empty() && execution.claim_until_ms > now_ms {
        return Ok(execution);
    }
    let holder = uuid::Uuid::new_v4().to_string();
    execution.claim_holder = holder.clone();
    execution.claim_until_ms = now_ms + EXECUTION_LEASE_MS;
    execution = save(db, execution)?;
    if review.decision != DECISION_GRANT {
        return save(db, stop(execution, STOP_NOT_APPROVED, 0, now_ms));
    }
    // Revisions this plan's own steps produced, by object.
    let mut produced: BTreeMap<String, String> = BTreeMap::new();
    for (step, done) in plan.steps.iter().zip(&execution.steps) {
        produced.insert(step.object_id.clone(), done.object_revision_after.clone());
    }
    for index in execution.next_step as usize..plan.steps.len() {
        let step = &plan.steps[index];
        let key = step_idempotency_key(plan_id, index);
        // Everything is checked against the step's object; a write aimed at
        // another one is never adopted or granted.
        if crate::sekai::action_plan::parameter_target(&step.parameters_json).as_deref()
            != Some(step.object_id.as_str())
        {
            return halt(
                db,
                execution,
                &plan,
                step,
                &key,
                STOP_STEP_MISMATCH,
                index,
                now_ms,
            );
        }
        let (instance, revision_after) = match db
            .get_action_instance_by_idempotency(namespace, &key)?
        {
            // Submitted before a crash. It must be the planned submission;
            // admission's replay completes it without applying it again.
            Some(stored) => {
                if !is_planned(&stored, &plan, step) {
                    return halt(
                        db,
                        execution,
                        &plan,
                        step,
                        &key,
                        STOP_STEP_MISMATCH,
                        index,
                        now_ms,
                    );
                }
                execution = renew(db, execution, (ports.clock)())?;
                match (ports.submit)(step, &key, "") {
                    Ok((instance, _)) => (instance, None),
                    // However old, an admission in flight may still
                    // complete: its age proves no crash, so the plan
                    // waits for it rather than stopping beside it.
                    Err(PortError::InProgress | PortError::Unavailable) => {
                        return release(db, execution);
                    }
                    Err(PortError::Refused(_)) => {
                        return halt(
                            db,
                            execution,
                            &plan,
                            step,
                            &key,
                            STOP_STEP_REFUSED,
                            index,
                            now_ms,
                        );
                    }
                }
            }
            None => {
                match authorized(ports, &plan, step, false) {
                    Ok(true) => {}
                    Ok(false) => {
                        return halt(
                            db,
                            execution,
                            &plan,
                            step,
                            &key,
                            STOP_AUTHORITY_REVOKED,
                            index,
                            now_ms,
                        );
                    }
                    // A dependency failed: not a revocation. Retry later.
                    Err(_) => return release(db, execution),
                }
                let current =
                    match simulate_step(db, &step_context(ports), index as u32, namespace, step) {
                        Ok(current) => current,
                        // The store failed: not a changed world. Retry later.
                        Err(PlanError::Store(_)) => return release(db, execution),
                        Err(error) => return Err(error.into()),
                    };
                let approved_step = approved.steps.get(index).ok_or(PlanError::NotFound)?;
                // An earlier step wrote this object: expect what it produced
                // (unknown after a crash, which stops the plan).
                let expected_revision = match produced.get(&step.object_id) {
                    Some(revision) => revision.clone(),
                    None => approved_step.object_revision.clone(),
                };
                if expected_revision.is_empty()
                    || current.object_revision != expected_revision
                    || !same_prediction(&current, approved_step)
                {
                    return halt(
                        db,
                        execution,
                        &plan,
                        step,
                        &key,
                        STOP_SIMULATION_CHANGED,
                        index,
                        now_ms,
                    );
                }
                execution = renew(db, execution, (ports.clock)())?;
                match (ports.submit)(step, &key, &expected_revision) {
                    Ok(admitted) => admitted,
                    Err(PortError::InProgress | PortError::Unavailable) => {
                        return release(db, execution);
                    }
                    Err(PortError::Refused(_)) => {
                        return halt(
                            db,
                            execution,
                            &plan,
                            step,
                            &key,
                            STOP_STEP_REFUSED,
                            index,
                            now_ms,
                        );
                    }
                }
            }
        };
        // Whatever submit returned (a replay may hand back an instance
        // another principal put under this key) must be the planned one.
        if !is_planned(&instance, &plan, step) {
            return halt(
                db,
                execution,
                &plan,
                step,
                &key,
                STOP_STEP_MISMATCH,
                index,
                now_ms,
            );
        }
        let (instance, revision_after) = if instance.status == STATUS_PARKED {
            // Both parties, now: the planner may still submit and read it,
            // the approver may still decide it. A recovered parked instance
            // skipped the fresh-step checks, so they run here.
            match authorized(ports, &plan, step, true) {
                Ok(true) => {}
                Ok(false) => {
                    return halt(
                        db,
                        execution,
                        &plan,
                        step,
                        &key,
                        STOP_AUTHORITY_REVOKED,
                        index,
                        now_ms,
                    );
                }
                Err(_) => return release(db, execution),
            }
            // A recovered parked step skipped the fresh-step simulation: the
            // world must still predict what was approved before the grant.
            let current =
                match simulate_step(db, &step_context(ports), index as u32, namespace, step) {
                    Ok(current) => current,
                    Err(PlanError::Store(_)) => return release(db, execution),
                    Err(error) => return Err(error.into()),
                };
            // Its budget unit was reserved when it parked, so only policy
            // and approval are compared, not budget headroom.
            let predicted = approved.steps.get(index).is_some_and(|approved_step| {
                current.policy_decision == approved_step.policy_decision
                    && current.approval_state == approved_step.approval_state
            });
            if !predicted {
                return halt(
                    db,
                    execution,
                    &plan,
                    step,
                    &key,
                    STOP_SIMULATION_CHANGED,
                    index,
                    now_ms,
                );
            }
            // The grant writes over the state the instance parked on, and
            // refuses if the object changed since. So the object must be at
            // the revision the plan expects now: then that state is the
            // approved one, also for an instance recovered after a crash.
            let expected_revision = match produced.get(&step.object_id) {
                Some(revision) => revision.clone(),
                None => approved
                    .steps
                    .get(index)
                    .map(|approved_step| approved_step.object_revision.clone())
                    .unwrap_or_default(),
            };
            let current_revision = db
                .get_object(&step.object_id)?
                .map(|object| crate::sekai::action_describe_preview::object_revision(&object));
            if expected_revision.is_empty() || current_revision.as_ref() != Some(&expected_revision)
            {
                return halt(
                    db,
                    execution,
                    &plan,
                    step,
                    &key,
                    STOP_SIMULATION_CHANGED,
                    index,
                    now_ms,
                );
            }
            execution = renew(db, execution, (ports.clock)())?;
            match (ports.decide)(&instance, &execution.claim_holder) {
                Ok(admitted) => admitted,
                Err(PortError::InProgress | PortError::Unavailable) => {
                    return release(db, execution);
                }
                Err(PortError::Refused(_)) => {
                    return halt(
                        db,
                        execution,
                        &plan,
                        step,
                        &key,
                        STOP_STEP_REFUSED,
                        index,
                        now_ms,
                    );
                }
            }
        } else {
            (instance, revision_after)
        };
        if instance.status != STATUS_ADMITTED {
            return halt(
                db,
                execution,
                &plan,
                step,
                &key,
                STOP_STEP_REFUSED,
                index,
                now_ms,
            );
        }
        let revision_after = revision_after.unwrap_or_default();
        produced.insert(step.object_id.clone(), revision_after.clone());
        execution.steps.push(StepExecution {
            index: index as u32,
            instance_id: instance.instance_id,
            operation_id: instance.operation_id,
            status: instance.status,
            object_revision_after: revision_after,
        });
        execution.next_step = index as u32 + 1;
        execution.updated_at_ms = now_ms;
        execution = save(db, execution)?;
    }
    execution.status = EXECUTION_COMPLETED.into();
    execution.updated_at_ms = now_ms;
    release(db, execution)
}

/// Renews this run's claim right before a side effect. A run that lost its
/// claim (it paused past the lease and another took over) fails here and
/// submits nothing; see [`save`].
fn renew(
    db: &RuntimeDb,
    mut execution: PlanExecution,
    now_ms: i64,
) -> Result<PlanExecution, ExecutionError> {
    execution.claim_until_ms = now_ms + EXECUTION_LEASE_MS;
    save(db, execution)
}

/// Saves `execution` and gives up its claim, for a later run to continue.
fn release(db: &RuntimeDb, mut execution: PlanExecution) -> Result<PlanExecution, ExecutionError> {
    execution.claim_holder.clear();
    execution.claim_until_ms = 0;
    save(db, execution)
}

/// Stops the plan at step `index`, first closing an unused step key with a
/// denied record so a run that lost its claim cannot still submit the step.
/// The close is atomic in the store and applies only while this run still
/// owns the execution, so a superseded run never closes the step of the run
/// that took over. A parked step needs no close: the plan's grant holds only
/// under a live claim, and the step stays an ordinary parked Action. When
/// the step was admitted meanwhile, or the claim is gone, the plan is
/// released (a lost claim's save would fail anyway).
#[allow(clippy::too_many_arguments)]
fn halt(
    db: &RuntimeDb,
    execution: PlanExecution,
    plan: &ProposedPlan,
    step: &PlanStep,
    key: &str,
    reason: &str,
    index: usize,
    now_ms: i64,
) -> Result<PlanExecution, ExecutionError> {
    let closed = match db.get_action_instance_by_idempotency(&plan.namespace, key)? {
        None => {
            let closing = closing_record(plan, step, key, reason, now_ms);
            // False when another run reserved the key first or this run no
            // longer owns the execution.
            db.close_plan_step_key(&closing, &plan.plan_id, &execution.claim_holder)?
        }
        Some(admitted) => {
            !(admitted.status == STATUS_ADMITTED && is_planned(&admitted, plan, step))
        }
    };
    if closed {
        save(db, stop(execution, reason, index, now_ms))
    } else {
        release(db, execution)
    }
}

/// The denied record that takes a stopped step's unused key.
fn closing_record(
    plan: &ProposedPlan,
    step: &PlanStep,
    key: &str,
    reason: &str,
    now_ms: i64,
) -> ActionInstance {
    let id = uuid::Uuid::new_v4().to_string();
    ActionInstance {
        agent_turn: None,
        instance_id: id.clone(),
        namespace: plan.namespace.clone(),
        type_id: step.type_id.clone(),
        version: step.version.clone(),
        principal: plan.planner.clone(),
        delegating_actor: None,
        // Never the step's parameters: the step did not run, and its
        // object's contents stay behind the object's own checks.
        parameters_json: "{}".into(),
        request_digest: format!("plan_execution_stopped:{reason}"),
        idempotency_key: key.into(),
        operation_id: format!("plan-stop:{id}"),
        status: STATUS_DENIED.into(),
        deny_reason: reason.into(),
        evidence_submission_ids: Vec::new(),
        policy_decision: String::new(),
        budget_decision: String::new(),
        created_at_ms: now_ms,
        decided_at_ms: now_ms,
        system_one_fill_json: String::new(),
        parked_object_digest: String::new(),
        decided_by: String::new(),
        approval_decision: String::new(),
        autonomous_envelope_id: String::new(),
        review: Default::default(),
        agent_action: false,
        admission_tenant: String::new(),
        resource_tenant: String::new(),
        marking: String::new(),
        offline: None,
        conflict: None,
        approval: None,
        admission_lease: None,
        admission_ontology_digest: None,
        admission_budget_already_reserved: false,
    }
}

fn stop(mut execution: PlanExecution, reason: &str, index: usize, now_ms: i64) -> PlanExecution {
    execution.claim_holder.clear();
    execution.claim_until_ms = 0;
    execution.status = EXECUTION_STOPPED.into();
    execution.stop_reason = reason.into();
    execution.stopped_at_step = Some(index as u32);
    execution.updated_at_ms = now_ms;
    execution
}

/// Writes `execution` over the revision it was read at.
fn save(db: &RuntimeDb, execution: PlanExecution) -> Result<PlanExecution, ExecutionError> {
    let next = PlanExecution {
        revision: execution.revision + 1,
        ..execution.clone()
    };
    if db.advance_plan_execution(&next, execution.revision)? {
        return Ok(next);
    }
    let current = db
        .get_plan_execution(&execution.namespace, &execution.plan_id)?
        .ok_or(PlanError::NotFound)?;
    Err(ExecutionError::Superseded(Box::new(current)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::domain::Object;
    use crate::sekai::action_instance_admission::{
        ActionInstanceAdmission, ActionInstanceAdmissionRequest,
    };
    use crate::sekai::action_plan::{PlanIntent, create_intent, propose_plan, simulate_plan};
    use crate::sekai::governed_action_type::{GovernedActionType, OBJECT_MUTATION_UPDATE};
    use crate::sekai::plan_review::{ReviewDecision, decide_review, submit_review};

    const NS: &str = "acme";
    const PLANNER: &str = "planner";
    const APPROVER: &str = "approver";

    fn object(id: &str, title: &str) -> Object {
        Object {
            id: id.into(),
            kind: "customer_record".into(),
            name: format!("Customer {id}"),
            namespace: NS.into(),
            external_id: String::new(),
            properties: HashMap::from([("title".into(), title.into())]),
            created: 10,
            updated: 20,
        }
    }

    fn step(id: &str, title: &str) -> PlanStep {
        PlanStep {
            type_id: "customer.retitle".into(),
            version: "1".into(),
            object_id: id.into(),
            parameters_json: format!(r#"{{"object_id":"{id}","title":"{title}"}}"#),
        }
    }

    fn visible(db: &RuntimeDb) -> impl Fn(&str) -> Result<Option<Object>, String> + '_ {
        |id| db.get_object(id)
    }

    fn context<'a>(
        visible: &'a dyn Fn(&str) -> Result<Option<Object>, String>,
        now_ms: i64,
    ) -> SimulationContext<'a> {
        SimulationContext {
            actor: PLANNER,
            budget: None,
            proposal: None,
            policy_context: None,
            visible_object: visible,
            now_ms,
            acting_tenant: "",
        }
    }

    /// A granted three-step plan retitling three customers.
    fn approved_plan(db: &RuntimeDb) {
        db.upsert_object_type(&crate::sekai::schema::ObjectType {
            kind: "customer_record".into(),
            description: "fixture".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
        for id in ["c1", "c2", "c3"] {
            db.create_object(&object(id, "account")).unwrap();
        }
        db.put_governed_action_type(
            GovernedActionType {
                namespace: NS.into(),
                type_id: "customer.retitle".into(),
                version: "1".into(),
                description: "Retitle one customer".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"title":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec!["notify".into()],
                object_kind: "customer_record".into(),
                object_mutation: OBJECT_MUTATION_UPDATE.into(),
                enabled: true,
                ..Default::default()
            },
            "operator",
            1,
        )
        .unwrap();
        create_intent(
            db,
            PlanIntent {
                namespace: NS.into(),
                intent_id: "intent-1".into(),
                goal: "Retitle".into(),
                constraints: vec![],
                planner: PLANNER.into(),
                created_at_ms: 1,
            },
        )
        .unwrap();
        propose_plan(
            db,
            ProposedPlan {
                namespace: NS.into(),
                plan_id: "plan-1".into(),
                intent_id: "intent-1".into(),
                planner: PLANNER.into(),
                steps: vec![step("c1", "vip"), step("c2", "vip"), step("c3", "vip")],
                created_at_ms: 2,
            },
        )
        .unwrap();
        let visible = visible(db);
        let simulation = simulate_plan(db, &context(&visible, 3), NS, "plan-1", "sim-1").unwrap();
        submit_review(db, NS, "plan-1", "sim-1", PLANNER, 4).unwrap();
        decide_review(
            db,
            NS,
            "plan-1",
            &ReviewDecision {
                simulation_digest: &simulation.digest,
                decision: DECISION_GRANT,
                reason: "ok",
                in_space: false,
            },
            APPROVER,
            &|_, _| true,
            5,
        )
        .unwrap();
    }

    /// Submits as the planner through admission, counting submits by key.
    fn submitter<'a>(
        db: &'a RuntimeDb,
        submits: &'a RefCell<Vec<String>>,
    ) -> impl Fn(&PlanStep, &str, &str) -> Result<Admitted, PortError> + 'a {
        move |step, key, expected_revision| {
            submits.borrow_mut().push(key.to_owned());
            ActionInstanceAdmission::new(db, None)
                .admit(
                    ActionInstanceAdmissionRequest {
                        agent_turn: None,
                        namespace: NS.into(),
                        type_id: step.type_id.clone(),
                        version: step.version.clone(),
                        parameters_json: step.parameters_json.clone(),
                        idempotency_key: key.into(),
                        evidence_submission_ids: Vec::new(),
                        request_id: format!("{NS}:{key}"),
                        ontology_digest: String::new(),
                        autonomous_envelope_id: String::new(),
                        policy_context: Default::default(),
                        delegating_actor: None,
                        budget_already_reserved: false,
                        resource_tenant: String::new(),
                        binding_markings: Vec::new(),
                        source_object_id: String::new(),
                        marking_gate: Default::default(),
                        expected_object_revision: expected_revision.into(),
                        offline: None,
                    },
                    PLANNER,
                    100,
                )
                .map(|outcome| (outcome.instance, outcome.object_revision))
                .map_err(|error| PortError::Refused(format!("{error:?}")))
        }
    }

    fn run(
        db: &RuntimeDb,
        submits: &RefCell<Vec<String>>,
        may_decide: &dyn Fn(&ProposedPlan, &PlanStep) -> Result<bool, String>,
    ) -> PlanExecution {
        let submit = submitter(db, submits);
        let decide = |_: &ActionInstance, _: &str| {
            Err::<Admitted, _>(PortError::Refused("no parked steps".into()))
        };
        let visible = visible(db);
        execute_plan(
            db,
            &ExecutionPorts {
                submit: &submit,
                decide: &decide,
                approver_may_decide: may_decide,
                planner_may_submit: &|_| Ok(true),
                clock: &|| 100,
                simulation: context(&visible, 100),
            },
            NS,
            "plan-1",
            APPROVER,
        )
        .unwrap()
    }

    fn title(db: &RuntimeDb, id: &str) -> String {
        db.get_object(id).unwrap().unwrap().properties["title"].clone()
    }

    #[test]
    fn an_approved_plan_runs_every_step_in_order_with_its_instance_linked() {
        let db = RuntimeDb::memory();
        approved_plan(&db);
        let submits = RefCell::new(Vec::new());
        let execution = run(&db, &submits, &|_, _| Ok(true));
        assert_eq!(execution.status, EXECUTION_COMPLETED, "{execution:?}");
        let keys: Vec<String> = (0..3).map(|i| step_idempotency_key("plan-1", i)).collect();
        assert_eq!(*submits.borrow(), keys);
        assert_eq!(execution.steps.len(), 3);
        for (index, done) in execution.steps.iter().enumerate() {
            let instance = db.get_action_instance(&done.instance_id).unwrap().unwrap();
            assert_eq!(instance.idempotency_key, keys[index]);
            assert_eq!(instance.principal, PLANNER);
        }
        assert_eq!(title(&db, "c3"), "vip");
        // Run again: the stored execution, nothing resubmitted.
        assert_eq!(run(&db, &submits, &|_, _| Ok(true)), execution);
        assert_eq!(submits.borrow().len(), 3);
    }

    #[test]
    fn a_changed_precondition_stops_the_plan_before_the_affected_step() {
        let db = RuntimeDb::memory();
        approved_plan(&db);
        db.update_object(&Object {
            updated: 30,
            ..object("c2", "churned")
        })
        .unwrap();
        let submits = RefCell::new(Vec::new());
        let execution = run(&db, &submits, &|_, _| Ok(true));
        assert_eq!(execution.status, EXECUTION_STOPPED);
        assert_eq!(execution.stop_reason, STOP_SIMULATION_CHANGED);
        assert_eq!(execution.stopped_at_step, Some(1));
        assert_eq!(execution.steps.len(), 1);
        assert_eq!(title(&db, "c2"), "churned");
        assert_eq!(title(&db, "c3"), "account");
    }

    #[test]
    fn an_authority_check_that_cannot_complete_retries_instead_of_stopping() {
        let db = RuntimeDb::memory();
        approved_plan(&db);
        let submits = RefCell::new(Vec::new());
        let unavailable = |_: &ProposedPlan, step: &PlanStep| {
            if step.object_id == "c2" {
                Err("store unavailable".to_owned())
            } else {
                Ok(true)
            }
        };
        let paused = run(&db, &submits, &unavailable);
        assert_eq!(paused.status, EXECUTION_RUNNING, "{paused:?}");
        assert_eq!(paused.steps.len(), 1);
        assert!(paused.claim_holder.is_empty());
        let resumed = run(&db, &submits, &|_, _| Ok(true));
        assert_eq!(resumed.status, EXECUTION_COMPLETED, "{resumed:?}");
    }

    #[test]
    fn removing_the_approvers_authority_stops_the_plan_before_that_step() {
        let db = RuntimeDb::memory();
        approved_plan(&db);
        let submits = RefCell::new(Vec::new());
        let execution = run(&db, &submits, &|_, step| Ok(step.object_id != "c2"));
        assert_eq!(execution.stop_reason, STOP_AUTHORITY_REVOKED);
        assert_eq!(execution.stopped_at_step, Some(1));
        assert_eq!(submits.borrow().len(), 1);
        // A run that lost its claim before this stop cannot still apply the
        // step: its key is closed.
        let plan = db.get_plan(NS, "plan-1").unwrap().unwrap();
        let revision = crate::sekai::action_describe_preview::object_revision(
            &db.get_object("c2").unwrap().unwrap(),
        );
        let stale = submitter(&db, &submits);
        assert!(
            stale(
                &plan.steps[1],
                &step_idempotency_key("plan-1", 1),
                &revision
            )
            .is_err()
        );
        assert_eq!(title(&db, "c2"), "account");
    }

    /// The executor died after step 2 was submitted and before its progress
    /// was recorded. The restart finds step 2 by its key, completes it
    /// through replay and runs step 3 once; steps 1 and 2 are not applied
    /// again.
    #[test]
    fn a_restart_after_step_two_runs_step_three_once() {
        let db = RuntimeDb::memory();
        approved_plan(&db);
        let submits = RefCell::new(Vec::new());
        // Paused before step 3 (a check that could not complete), so its
        // key stays open.
        let first = run(&db, &submits, &|_, step| {
            if step.object_id == "c3" {
                Err("unavailable".to_owned())
            } else {
                Ok(true)
            }
        });
        assert_eq!(first.steps.len(), 2);
        // Roll the record back to "step 1 done" with the instance of step 2
        // already admitted, as a crash before the save would leave it.
        let mut crashed = first.clone();
        crashed.steps.truncate(1);
        crashed.next_step = 1;
        crashed.revision = first.revision + 1;
        assert!(db.advance_plan_execution(&crashed, first.revision).unwrap());
        submits.borrow_mut().clear();
        let resumed = run(&db, &submits, &|_, _| Ok(true));
        assert_eq!(resumed.status, EXECUTION_COMPLETED, "{resumed:?}");
        // Step 2 completes through admission's replay (same key, nothing
        // applied); step 3 is submitted once.
        assert_eq!(
            *submits.borrow(),
            [
                step_idempotency_key("plan-1", 1),
                step_idempotency_key("plan-1", 2)
            ]
        );
        assert_eq!(resumed.steps[1].instance_id, first.steps[1].instance_id);
        let instances = db.list_action_instances(NS, None, None, 10).unwrap();
        assert_eq!(instances.len(), 3);
    }

    /// Another submitter put a different Action under step 2's key; the
    /// plan stops rather than adopt or grant it.
    #[test]
    fn an_instance_under_a_step_key_that_is_not_the_planned_one_stops_the_plan() {
        let db = RuntimeDb::memory();
        approved_plan(&db);
        let submits = RefCell::new(Vec::new());
        let foreign = submitter(&db, &submits);
        foreign(
            &step("c2", "hijacked"),
            &step_idempotency_key("plan-1", 1),
            "",
        )
        .unwrap();
        submits.borrow_mut().clear();
        let execution = run(&db, &submits, &|_, _| Ok(true));
        assert_eq!(execution.stop_reason, STOP_STEP_MISMATCH);
        assert_eq!(execution.stopped_at_step, Some(1));
    }

    /// The object changed after the executor checked it and before
    /// admission wrote: admission refuses the write.
    #[test]
    fn admission_refuses_a_write_over_a_revision_other_than_the_checked_one() {
        let db = RuntimeDb::memory();
        approved_plan(&db);
        let submits = RefCell::new(Vec::new());
        let submit = submitter(&db, &submits);
        let error = submit(&step("c1", "vip"), "check-1", "sha256:not-the-revision").unwrap_err();
        assert!(
            matches!(&error, PortError::Refused(message) if message.contains("object changed")),
            "{error:?}"
        );
        assert_eq!(title(&db, "c1"), "account");
        assert!(
            db.get_action_instance_by_idempotency(NS, "check-1")
                .unwrap()
                .is_none()
        );
    }

    /// Steps park for approval. A parked instance submitted under step 1's
    /// key over a changed object is found on recovery and not granted.
    #[test]
    fn a_recovered_parked_step_on_a_changed_object_is_not_granted() {
        use sekai_types::action_policy::{ActionDecision, ActionPolicy};
        let db = RuntimeDb::memory();
        db.upsert_action_policy(&ActionPolicy {
            scope: NS.into(),
            default_decision: ActionDecision::RequireApproval,
            action_overrides: HashMap::new(),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        })
        .unwrap();
        approved_plan(&db);
        db.update_object(&Object {
            updated: 30,
            ..object("c1", "changed")
        })
        .unwrap();
        let submits = RefCell::new(Vec::new());
        let submit = submitter(&db, &submits);
        let parked = submit(&step("c1", "vip"), &step_idempotency_key("plan-1", 0), "")
            .unwrap()
            .0;
        assert_eq!(parked.status, STATUS_PARKED);
        let grants = RefCell::new(0);
        let decide = |instance: &ActionInstance, _: &str| {
            *grants.borrow_mut() += 1;
            Ok((instance.clone(), None))
        };
        let visible = visible(&db);
        let execution = execute_plan(
            &db,
            &ExecutionPorts {
                submit: &submit,
                decide: &decide,
                approver_may_decide: &|_, _| Ok(true),
                planner_may_submit: &|_| Ok(true),
                clock: &|| 100,
                simulation: context(&visible, 100),
            },
            NS,
            "plan-1",
            APPROVER,
        )
        .unwrap();
        assert_eq!(execution.stop_reason, STOP_SIMULATION_CHANGED);
        assert_eq!(execution.stopped_at_step, Some(0));
        assert_eq!(*grants.borrow(), 0);
    }

    /// A run that holds a live claim is left alone; once its lease lapses
    /// (it crashed) the next run takes over.
    #[test]
    fn a_live_claim_keeps_other_runs_out_until_it_lapses() {
        let db = RuntimeDb::memory();
        approved_plan(&db);
        let claimed = PlanExecution {
            namespace: NS.into(),
            plan_id: "plan-1".into(),
            simulation_id: "sim-1".into(),
            simulation_digest: db
                .get_plan_review(NS, "plan-1")
                .unwrap()
                .unwrap()
                .simulation_digest,
            status: EXECUTION_RUNNING.into(),
            next_step: 0,
            steps: Vec::new(),
            stop_reason: String::new(),
            stopped_at_step: None,
            started_by: APPROVER.into(),
            updated_at_ms: 50,
            revision: 0,
            claim_holder: "other-run".into(),
            claim_until_ms: 100 + 1,
        };
        db.put_plan_execution(&claimed).unwrap();
        let submits = RefCell::new(Vec::new());
        let untouched = run(&db, &submits, &|_, _| Ok(true));
        assert_eq!(untouched, claimed);
        assert!(submits.borrow().is_empty());
        let lapsed = PlanExecution {
            claim_until_ms: 100,
            revision: 1,
            ..claimed.clone()
        };
        assert!(db.advance_plan_execution(&lapsed, 0).unwrap());
        let taken = run(&db, &submits, &|_, _| Ok(true));
        assert_eq!(taken.status, EXECUTION_COMPLETED);
        assert!(taken.claim_holder.is_empty());
    }

    #[test]
    fn a_plan_without_a_grant_never_executes() {
        let db = RuntimeDb::memory();
        approved_plan_pending(&db);
        let submits = RefCell::new(Vec::new());
        let submit = submitter(&db, &submits);
        let decide =
            |_: &ActionInstance, _: &str| Err::<Admitted, _>(PortError::Refused("unused".into()));
        let visible = visible(&db);
        let execution = execute_plan(
            &db,
            &ExecutionPorts {
                submit: &submit,
                decide: &decide,
                approver_may_decide: &|_, _| Ok(true),
                planner_may_submit: &|_| Ok(true),
                clock: &|| 100,
                simulation: context(&visible, 100),
            },
            NS,
            "plan-2",
            APPROVER,
        )
        .unwrap();
        assert_eq!(execution.stop_reason, STOP_NOT_APPROVED);
        assert!(submits.borrow().is_empty());
    }

    /// An execution is stored once and advances only over the revision a
    /// writer read, on either backend.
    fn store_contract(db: &RuntimeDb, ns: &str) {
        let execution = PlanExecution {
            namespace: ns.into(),
            plan_id: "plan-1".into(),
            simulation_id: "sim-1".into(),
            simulation_digest: "sha256:one".into(),
            status: EXECUTION_RUNNING.into(),
            next_step: 0,
            steps: Vec::new(),
            stop_reason: String::new(),
            stopped_at_step: None,
            started_by: APPROVER.into(),
            updated_at_ms: 1,
            revision: 0,
            claim_holder: String::new(),
            claim_until_ms: 0,
        };
        assert_eq!(db.put_plan_execution(&execution).unwrap(), execution);
        let other = PlanExecution {
            started_by: "someone".into(),
            ..execution.clone()
        };
        assert_eq!(db.put_plan_execution(&other).unwrap(), execution);
        let advanced = PlanExecution {
            next_step: 1,
            revision: 1,
            ..execution.clone()
        };
        assert!(db.advance_plan_execution(&advanced, 0).unwrap());
        // A writer that read revision 0 is fenced.
        assert!(!db.advance_plan_execution(&advanced, 0).unwrap());
        assert_eq!(
            db.get_plan_execution(ns, "plan-1").unwrap(),
            Some(advanced.clone())
        );
        // Closing a step's key holds only for the run owning the claim.
        let claimed = PlanExecution {
            claim_holder: "run-a".into(),
            revision: 2,
            ..advanced
        };
        assert!(db.advance_plan_execution(&claimed, 1).unwrap());
        let step = PlanStep {
            type_id: "t".into(),
            version: "1".into(),
            object_id: "c1".into(),
            parameters_json: "{}".into(),
        };
        let plan = ProposedPlan {
            namespace: ns.into(),
            plan_id: "plan-1".into(),
            intent_id: "intent-1".into(),
            planner: PLANNER.into(),
            steps: vec![step.clone()],
            created_at_ms: 1,
        };
        let closing = |key: &str| closing_record(&plan, &step, key, STOP_STEP_REFUSED, 3);
        assert!(
            !db.close_plan_step_key(&closing("k1"), "plan-1", "run-b")
                .unwrap()
        );
        assert_eq!(
            db.get_action_instance_by_idempotency(ns, "k1").unwrap(),
            None
        );
        assert!(
            db.close_plan_step_key(&closing("k1"), "plan-1", "run-a")
                .unwrap()
        );
        // A taken key stays taken.
        assert!(
            !db.close_plan_step_key(&closing("k1"), "plan-1", "run-a")
                .unwrap()
        );
        // So does a grant of a parked plan step.
        let parked = db
            .put_action_instance(&ActionInstance {
                status: STATUS_PARKED.into(),
                deny_reason: String::new(),
                ..closing("k2")
            })
            .unwrap();
        let granted = ActionInstance {
            status: STATUS_ADMITTED.into(),
            ..parked
        };
        let grant = |holder: &str| {
            db.grant_parked_action_instance(
                &granted,
                "",
                "",
                None,
                &[],
                PLANNER,
                Some(&crate::sekai::action_instance::ExecutionClaim {
                    plan_id: "plan-1".into(),
                    holder: holder.into(),
                }),
            )
            .unwrap()
        };
        assert!(matches!(
            grant("run-b"),
            crate::sekai::action_instance::ParkedGrantOutcome::ClaimLost
        ));
        assert!(matches!(
            grant("run-a"),
            crate::sekai::action_instance::ParkedGrantOutcome::Granted { .. }
        ));
    }

    #[test]
    fn sqlite_executions_are_fenced_by_revision() {
        store_contract(&RuntimeDb::memory(), NS);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_executions_are_fenced_by_revision() {
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
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        let ns = format!("executions-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        store_contract(&db, &ns);
    }

    /// [`approved_plan`] plus `plan-2`, a copy whose review is undecided.
    fn approved_plan_pending(db: &RuntimeDb) {
        approved_plan(db);
        let review = db.get_plan_review(NS, "plan-1").unwrap().unwrap();
        let pending = crate::sekai::plan_review::PlanReview {
            plan_id: "plan-2".into(),
            decision: String::new(),
            decided_by: String::new(),
            ..review
        };
        db.put_plan_review(&pending).unwrap();
        let plan = db.get_plan(NS, "plan-1").unwrap().unwrap();
        db.put_plan(&ProposedPlan {
            plan_id: "plan-2".into(),
            ..plan
        })
        .unwrap();
        let simulation = db
            .get_plan_simulation(NS, "plan-1", "sim-1")
            .unwrap()
            .unwrap();
        db.put_plan_simulation(&crate::sekai::action_plan::PlanSimulation {
            plan_id: "plan-2".into(),
            ..simulation
        })
        .unwrap();
    }
}
