//! Intents, proposed plans and their simulations (#1675, layer 1 of #1460).
//! Sekai owns them: steps are Sekai Actions on Sekai objects, simulated by
//! the Action preview path under the object read policy.
//!
//! An intent is a goal with constraints. A proposed plan is an ordered list
//! of steps, each one Action type with parameters against one object; it is
//! not a DAG. Simulating a plan runs every step through the Action preview
//! path, which applies nothing, and stores the result with the plan: per
//! step the preview outcome, the policy and approval decisions, and the
//! object effect the Action would write. A digest over the canonical plan
//! and that result is stored with it, so an unchanged world simulates to
//! the same digest and a changed precondition does not. Every simulation is
//! kept.
//!
//! Creates are idempotent by caller-supplied id: a retry returns the stored
//! record, and a different body under a stored id is a conflict.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::action_describe_preview::{
    self, ObjectActionPreviewRequest, ObjectActionProjectionError, PREVIEW_INVALID, PREVIEW_STALE,
    PREVIEW_UNAVAILABLE, PREVIEW_VALID,
};
use crate::sekai::action_object_mutation::{self, PlannedObjectMutation};
use crate::sekai::action_ports::{ActionBudgetPort, ActionProposalPort};

pub const MAX_PLAN_STEPS: usize = 32;
pub const MAX_CONSTRAINTS: usize = 32;
const MAX_ID: usize = 128;
const MAX_GOAL: usize = 4096;
const MAX_CONSTRAINT: usize = 512;
const MAX_PARAMETERS: usize = 64 * 1024;
/// Simulations a plan read returns, newest first.
pub const MAX_LISTED_SIMULATIONS: usize = 100;

/// A step a reader may not see: its object is outside the read policy.
pub const STEP_REDACTED: &str = "redacted";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanIntent {
    pub namespace: String,
    pub intent_id: String,
    pub goal: String,
    pub constraints: Vec<String>,
    pub planner: String,
    pub created_at_ms: i64,
}

/// One step: an Action type and version, applied to one existing object.
/// The preview path is object-bound, so steps are updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub type_id: String,
    pub version: String,
    pub object_id: String,
    pub parameters_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedPlan {
    pub namespace: String,
    pub plan_id: String,
    pub intent_id: String,
    pub planner: String,
    pub steps: Vec<PlanStep>,
    pub created_at_ms: i64,
}

/// The object write a step's Action would make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepEffect {
    pub object_id: String,
    pub object_kind: String,
    /// `update`: steps act on existing objects.
    pub mutation: String,
    /// Properties the write sets or changes, sorted. `_name` for the name.
    pub changed_properties: Vec<String>,
}

/// What the preview path predicted for one step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepSimulation {
    pub index: u32,
    pub object_id: String,
    /// The object revision the step was simulated against.
    pub object_revision: String,
    pub outcome: String,
    pub reason_code: String,
    pub policy_decision: String,
    /// The approval the step needs before it may run.
    pub approval_state: String,
    pub budget_decision: String,
    pub failing_criterion: String,
    pub effect: Option<StepEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSimulation {
    pub namespace: String,
    pub plan_id: String,
    pub simulation_id: String,
    pub digest: String,
    pub simulated_by: String,
    pub simulated_at_ms: i64,
    pub steps: Vec<StepSimulation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Invalid(String),
    NotFound,
    /// A different body is stored under the same id.
    Conflict,
    Store(String),
}

impl From<String> for PlanError {
    fn from(error: String) -> Self {
        Self::Store(error)
    }
}

fn check_id(field: &str, value: &str) -> Result<(), PlanError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_ID
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'));
    if valid {
        Ok(())
    } else {
        Err(PlanError::Invalid(format!(
            "{field} must be 1 to {MAX_ID} letters, digits, '.', '_', '-' or ':'"
        )))
    }
}

fn check_text(field: &str, value: &str, max: usize) -> Result<(), PlanError> {
    if value.trim().is_empty() || value.len() > max {
        return Err(PlanError::Invalid(format!(
            "{field} must be non-empty and at most {max} bytes"
        )));
    }
    Ok(())
}

/// Records `intent`, or returns the one already stored under its id.
pub fn create_intent(db: &RuntimeDb, intent: PlanIntent) -> Result<PlanIntent, PlanError> {
    check_id("intent_id", &intent.intent_id)?;
    check_text("goal", &intent.goal, MAX_GOAL)?;
    if intent.constraints.len() > MAX_CONSTRAINTS {
        return Err(PlanError::Invalid(format!(
            "at most {MAX_CONSTRAINTS} constraints"
        )));
    }
    for constraint in &intent.constraints {
        check_text("constraint", constraint, MAX_CONSTRAINT)?;
    }
    let stored = db.put_plan_intent(&intent)?;
    let same = PlanIntent {
        created_at_ms: stored.created_at_ms,
        ..intent
    };
    if stored == same {
        Ok(stored)
    } else {
        Err(PlanError::Conflict)
    }
}

/// Records `plan` for a stored intent, or returns the one already stored
/// under its id.
pub fn propose_plan(db: &RuntimeDb, plan: ProposedPlan) -> Result<ProposedPlan, PlanError> {
    check_id("plan_id", &plan.plan_id)?;
    check_id("intent_id", &plan.intent_id)?;
    if plan.steps.is_empty() || plan.steps.len() > MAX_PLAN_STEPS {
        return Err(PlanError::Invalid(format!(
            "a plan has 1 to {MAX_PLAN_STEPS} steps"
        )));
    }
    for step in &plan.steps {
        check_text("type_id", &step.type_id, MAX_ID)?;
        check_text("version", &step.version, MAX_ID)?;
        check_text("object_id", &step.object_id, MAX_ID)?;
        if step.parameters_json.len() > MAX_PARAMETERS
            || serde_json::from_str::<serde_json::Value>(&step.parameters_json).is_err()
        {
            return Err(PlanError::Invalid(format!(
                "parameters_json must be JSON of at most {MAX_PARAMETERS} bytes"
            )));
        }
        // Authority and revisions are checked against the step's object, so
        // the parameters must target that object.
        if parameter_target(&step.parameters_json).as_deref() != Some(step.object_id.as_str()) {
            return Err(PlanError::Invalid(
                "parameters_json.object_id must be the step's object_id".into(),
            ));
        }
    }
    if db
        .get_plan_intent(&plan.namespace, &plan.intent_id)?
        .is_none()
    {
        return Err(PlanError::NotFound);
    }
    let stored = db.put_plan(&plan)?;
    let same = ProposedPlan {
        created_at_ms: stored.created_at_ms,
        ..plan
    };
    if stored == same {
        Ok(stored)
    } else {
        Err(PlanError::Conflict)
    }
}

/// The object a step's parameters target (`object_id`).
pub fn parameter_target(parameters_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(parameters_json)
        .ok()?
        .get("object_id")?
        .as_str()
        .map(str::to_owned)
}

/// What a simulation needs from the caller's session.
pub struct SimulationContext<'a> {
    pub actor: &'a str,
    pub budget: Option<&'a dyn ActionBudgetPort>,
    pub proposal: Option<&'a dyn ActionProposalPort>,
    pub policy_context: Option<&'a crate::sekai::object_security::PrincipalPolicyContext>,
    /// The object with `id` when the caller may read it.
    /// `Ok(None)` when the caller may not read it; `Err` when that could
    /// not be determined (the store failed).
    pub visible_object: &'a dyn Fn(&str) -> Result<Option<Object>, String>,
    pub now_ms: i64,
    /// The tenant steps are submitted under, for cross-tenant sharing
    /// criteria (#1860). Empty where the caller has none.
    pub acting_tenant: &'a str,
}

fn changed_properties(planned: &PlannedObjectMutation) -> StepEffect {
    let (object, before) = match planned {
        PlannedObjectMutation::Create(object) => (object, None),
        PlannedObjectMutation::Update(object, before) => (object, Some(before.as_ref())),
    };
    let mut changed: Vec<String> = object
        .properties
        .iter()
        .filter(|(key, value)| {
            before.is_none_or(|before| before.properties.get(*key) != Some(*value))
        })
        .map(|(key, _)| key.clone())
        .collect();
    if let Some(before) = before {
        changed.extend(
            before
                .properties
                .keys()
                .filter(|key| !object.properties.contains_key(*key))
                .cloned(),
        );
    }
    if before.is_none_or(|before| before.name != object.name) {
        changed.push("_name".into());
    }
    changed.sort();
    changed.dedup();
    StepEffect {
        object_id: object.id.clone(),
        object_kind: object.kind.clone(),
        mutation: match planned {
            PlannedObjectMutation::Create(_) => "create",
            PlannedObjectMutation::Update(..) => "update",
        }
        .into(),
        changed_properties: changed,
    }
}

fn unavailable_step(index: u32, step: &PlanStep) -> StepSimulation {
    StepSimulation {
        index,
        object_id: step.object_id.clone(),
        object_revision: String::new(),
        outcome: PREVIEW_UNAVAILABLE.into(),
        reason_code: "unavailable".into(),
        policy_decision: String::new(),
        approval_state: String::new(),
        budget_decision: String::new(),
        failing_criterion: String::new(),
        effect: None,
    }
}

/// What planning the step's write found.
enum Predicted {
    Effect(StepEffect),
    /// Nothing to predict: parameters outside the schema or another target.
    None,
    /// The object changed or went away after its revision was recorded.
    Stale,
    /// The write would be refused, with why.
    Invalid(String),
}

/// The object write a step's Action would make, when its parameters pass
/// the type's schema, planned against `revision`. Plans only; applies
/// nothing.
fn predicted_effect(
    db: &RuntimeDb,
    context: &SimulationContext<'_>,
    namespace: &str,
    object: &Object,
    revision: &str,
    step: &PlanStep,
) -> Result<Predicted, PlanError> {
    // The parameters must target the step's object, the one whose read
    // policy was checked: mutation planning loads its target by itself.
    let target = serde_json::from_str::<serde_json::Value>(&step.parameters_json)
        .ok()
        .and_then(|parameters| parameters.get("object_id")?.as_str().map(str::to_owned));
    if target.as_deref() != Some(object.id.as_str()) {
        return Ok(Predicted::None);
    }
    let type_def =
        action_describe_preview::load_object_bound_type(db, object, &step.type_id, &step.version)
            .map_err(|_| PlanError::Store("action type vanished during simulation".into()))?;
    if crate::sekai::parameter_schema::validate_parameters(
        &type_def.parameter_schema_json,
        &step.parameters_json,
    )
    .is_err()
    {
        return Ok(Predicted::None);
    }
    let planned = match action_object_mutation::plan(
        db,
        &type_def,
        namespace,
        &step.parameters_json,
        Some(context.actor),
        None,
        context.now_ms,
    ) {
        Ok(planned) => planned,
        Err(action_object_mutation::ActionObjectMutationError::Internal(error)) => {
            return Err(PlanError::Store(error));
        }
        // A refusal is stale only if the object changed or went away since
        // its revision was recorded; otherwise the write itself is invalid.
        Err(
            action_object_mutation::ActionObjectMutationError::FailedPrecondition(error)
            | action_object_mutation::ActionObjectMutationError::InvalidArgument(error),
        ) => {
            let current = db.get_object(&object.id)?;
            let changed = current.is_none_or(|current| {
                action_describe_preview::object_revision(&current) != revision
            });
            return Ok(if changed {
                Predicted::Stale
            } else {
                Predicted::Invalid(error)
            });
        }
    };
    Ok(match planned {
        // The planner reads the object again; its before-image must be the
        // revision the step records, or the effect would not match it.
        Some(PlannedObjectMutation::Update(_, ref before))
            if action_describe_preview::object_revision(before) != revision =>
        {
            Predicted::Stale
        }
        Some(planned) => Predicted::Effect(changed_properties(&planned)),
        None => Predicted::None,
    })
}

/// Runs one step through the Action preview path. Applies nothing.
pub fn simulate_step(
    db: &RuntimeDb,
    context: &SimulationContext<'_>,
    index: u32,
    namespace: &str,
    step: &PlanStep,
) -> Result<StepSimulation, PlanError> {
    let Some(object) = (context.visible_object)(&step.object_id)? else {
        return Ok(unavailable_step(index, step));
    };
    if object.namespace != namespace {
        return Ok(unavailable_step(index, step));
    }
    let revision = action_describe_preview::object_revision(&object);
    let preview = match action_describe_preview::preview_object_action(
        db,
        context.budget,
        context.proposal,
        ObjectActionPreviewRequest {
            actor: context.actor,
            object: &object,
            type_id: &step.type_id,
            version: &step.version,
            parameters_json: &step.parameters_json,
            expected_object_updated_ms: object.updated,
            expected_object_revision: &revision,
            evidence_submission_ids: &[],
            policy_context: context.policy_context,
            acting_tenant: context.acting_tenant,
        },
    ) {
        Ok(preview) => preview,
        Err(ObjectActionProjectionError::Unavailable) => return Ok(unavailable_step(index, step)),
        Err(ObjectActionProjectionError::InvalidArgument(error)) => {
            return Err(PlanError::Invalid(error));
        }
        Err(ObjectActionProjectionError::Store(error)) => return Err(PlanError::Store(error)),
    };
    // A step that needs approval still shows what it would write, so the
    // approver sees it.
    let predicted =
        if preview.outcome == PREVIEW_VALID || preview.policy_decision == "require_approval" {
            predicted_effect(db, context, namespace, &object, &revision, step)?
        } else {
            Predicted::None
        };
    let mut failing_criterion = preview.failing_criterion;
    let (outcome, reason_code, effect) = match predicted {
        Predicted::Effect(effect) => (preview.outcome, preview.reason_code, Some(effect)),
        Predicted::None => (preview.outcome, preview.reason_code, None),
        Predicted::Stale => (
            PREVIEW_STALE.to_string(),
            "object_changed_during_simulation".to_string(),
            None,
        ),
        Predicted::Invalid(error) => {
            failing_criterion = error;
            (
                PREVIEW_INVALID.to_string(),
                "invalid_write".to_string(),
                None,
            )
        }
    };
    Ok(StepSimulation {
        index,
        object_id: object.id,
        object_revision: revision,
        outcome,
        reason_code,
        policy_decision: preview.policy_decision,
        approval_state: preview.approval_state,
        budget_decision: preview.budget_decision,
        failing_criterion,
        effect,
    })
}

/// The digest of a simulation: the canonical plan and what each step was
/// predicted to do, against which object revision. Ids of the simulation
/// and times are left out, so an unchanged world digests the same.
pub fn simulation_digest(plan: &ProposedPlan, steps: &[StepSimulation]) -> String {
    #[derive(Serialize)]
    struct Canonical<'a> {
        namespace: &'a str,
        plan_id: &'a str,
        intent_id: &'a str,
        steps: &'a [PlanStep],
        simulated: &'a [StepSimulation],
    }
    let canonical = serde_json::to_vec(&Canonical {
        namespace: &plan.namespace,
        plan_id: &plan.plan_id,
        intent_id: &plan.intent_id,
        steps: &plan.steps,
        simulated: steps,
    })
    .expect("plan simulation serializes");
    format!("sha256:{:x}", Sha256::digest(canonical))
}

/// Simulates a stored plan and keeps the result as `simulation_id`. A retry
/// with a stored id returns that simulation. Either way, steps whose object
/// the caller may not see are redacted.
pub fn simulate_plan(
    db: &RuntimeDb,
    context: &SimulationContext<'_>,
    namespace: &str,
    plan_id: &str,
    simulation_id: &str,
) -> Result<PlanSimulation, PlanError> {
    check_id("simulation_id", simulation_id)?;
    let plan = db
        .get_plan(namespace, plan_id)?
        .ok_or(PlanError::NotFound)?;
    // Whatever is returned, a fresh, retried or concurrently stored
    // simulation, is shown under this caller's read policy.
    let hidden: Vec<bool> = plan
        .steps
        .iter()
        .map(|step| (context.visible_object)(&step.object_id).map(|object| object.is_none()))
        .collect::<Result<_, _>>()?;
    let shown = |mut simulation: PlanSimulation| {
        redact_simulation(&mut simulation, &hidden);
        simulation
    };
    if let Some(stored) = db.get_plan_simulation(namespace, plan_id, simulation_id)? {
        return Ok(shown(stored));
    }
    let steps = plan
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| simulate_step(db, context, index as u32, namespace, step))
        .collect::<Result<Vec<_>, _>>()?;
    let simulation = PlanSimulation {
        namespace: namespace.into(),
        plan_id: plan_id.into(),
        simulation_id: simulation_id.into(),
        digest: simulation_digest(&plan, &steps),
        simulated_by: context.actor.into(),
        simulated_at_ms: context.now_ms,
        steps,
    };
    Ok(shown(db.put_plan_simulation(&simulation)?))
}

/// Clears every step of `simulation` the reader may not see (`hidden` by
/// step index; a step with no entry counts as hidden).
fn redact_simulation(simulation: &mut PlanSimulation, hidden: &[bool]) {
    for step in &mut simulation.steps {
        if hidden.get(step.index as usize).copied().unwrap_or(true) {
            *step = StepSimulation {
                index: step.index,
                object_id: String::new(),
                object_revision: String::new(),
                outcome: STEP_REDACTED.into(),
                reason_code: STEP_REDACTED.into(),
                policy_decision: String::new(),
                approval_state: String::new(),
                budget_decision: String::new(),
                failing_criterion: String::new(),
                effect: None,
            };
        }
    }
}

/// A stored plan as one reader sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanView {
    pub intent: PlanIntent,
    pub plan: ProposedPlan,
    pub simulations: Vec<PlanSimulation>,
}

/// Reads a plan with its intent and simulations, newest first. A step whose
/// object the reader may not see keeps its position and Action type but
/// loses its object, parameters and every prediction, in the plan and in
/// every simulation.
pub fn read_plan(
    db: &RuntimeDb,
    namespace: &str,
    plan_id: &str,
    may_read: &dyn Fn(&str) -> bool,
) -> Result<PlanView, PlanError> {
    let mut plan = db
        .get_plan(namespace, plan_id)?
        .ok_or(PlanError::NotFound)?;
    let intent = db
        .get_plan_intent(namespace, &plan.intent_id)?
        .ok_or(PlanError::NotFound)?;
    let mut simulations = db.list_plan_simulations(namespace, plan_id, MAX_LISTED_SIMULATIONS)?;
    let hidden: Vec<bool> = plan
        .steps
        .iter()
        .map(|step| !may_read(&step.object_id))
        .collect();
    for (step, hidden) in plan.steps.iter_mut().zip(&hidden) {
        if *hidden {
            step.object_id.clear();
            step.parameters_json.clear();
        }
    }
    for simulation in &mut simulations {
        redact_simulation(simulation, &hidden);
    }
    Ok(PlanView {
        intent,
        plan,
        simulations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::sekai::governed_action_type::GovernedActionType;
    use crate::sekai::governed_action_type::OBJECT_MUTATION_UPDATE;
    use sekai_types::action_policy::{ActionDecision, ActionPolicy};

    fn object(ns: &str, id: &str, title: &str) -> Object {
        Object {
            id: id.into(),
            kind: "customer_record".into(),
            name: format!("Customer {id}"),
            namespace: ns.into(),
            external_id: String::new(),
            properties: HashMap::from([("title".into(), title.into())]),
            created: 10,
            updated: 20,
        }
    }

    fn update_type(ns: &str, type_id: &str, policy_scope: &str) -> GovernedActionType {
        GovernedActionType {
            namespace: ns.into(),
            type_id: type_id.into(),
            version: "1".into(),
            description: "Update one customer".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"title":{"type":"string"}},"required":["object_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            policy_scope: policy_scope.into(),
            object_kind: "customer_record".into(),
            object_mutation: OBJECT_MUTATION_UPDATE.into(),
            enabled: true,
            ..Default::default()
        }
    }

    /// Three customers; `retitle` is allowed, `escalate` needs approval.
    fn world(db: &RuntimeDb, ns: &str) {
        db.upsert_object_type(&crate::sekai::schema::ObjectType {
            kind: "customer_record".into(),
            description: "fixture".into(),
            properties: vec![],
            is_builtin: false,
            implements: vec![],
        })
        .unwrap();
        for id in ["c1", "c2", "c3"] {
            db.create_object(&object(ns, &format!("{ns}-{id}"), "account"))
                .unwrap();
        }
        db.put_governed_action_type(update_type(ns, "customer.retitle", ""), "operator", 1)
            .unwrap();
        db.put_governed_action_type(
            update_type(ns, "customer.escalate", "approvals"),
            "operator",
            1,
        )
        .unwrap();
        db.upsert_action_policy(&ActionPolicy {
            scope: "project:approvals".into(),
            default_decision: ActionDecision::RequireApproval,
            action_overrides: HashMap::new(),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        })
        .unwrap();
    }

    fn step(ns: &str, type_id: &str, id: &str, title: &str) -> PlanStep {
        let object_id = format!("{ns}-{id}");
        PlanStep {
            type_id: type_id.into(),
            version: "1".into(),
            parameters_json: format!(r#"{{"object_id":"{object_id}","title":"{title}"}}"#),
            object_id,
        }
    }

    fn intent(ns: &str) -> PlanIntent {
        PlanIntent {
            namespace: ns.into(),
            intent_id: "intent-1".into(),
            goal: "Retitle three customers".into(),
            constraints: vec!["no deletes".into()],
            planner: "planner".into(),
            created_at_ms: 100,
        }
    }

    fn plan(ns: &str) -> ProposedPlan {
        ProposedPlan {
            namespace: ns.into(),
            plan_id: "plan-1".into(),
            intent_id: "intent-1".into(),
            planner: "planner".into(),
            steps: vec![
                step(ns, "customer.retitle", "c1", "vip"),
                step(ns, "customer.escalate", "c2", "escalated"),
                step(ns, "customer.retitle", "c3", "account"),
            ],
            created_at_ms: 200,
        }
    }

    fn simulate(db: &RuntimeDb, ns: &str, simulation_id: &str, now_ms: i64) -> PlanSimulation {
        let visible = |id: &str| db.get_object(id);
        let context = SimulationContext {
            actor: "planner",
            budget: None,
            proposal: None,
            policy_context: None,
            visible_object: &visible,
            now_ms,
            acting_tenant: "",
        };
        simulate_plan(db, &context, ns, "plan-1", simulation_id).unwrap()
    }

    fn contract(db: &RuntimeDb, ns: &str) {
        world(db, ns);
        let stored = create_intent(db, intent(ns)).unwrap();
        // A retry returns the stored record; another body is a conflict.
        assert_eq!(create_intent(db, intent(ns)).unwrap(), stored);
        let other = PlanIntent {
            goal: "something else".into(),
            ..intent(ns)
        };
        assert_eq!(create_intent(db, other), Err(PlanError::Conflict));
        let proposed = propose_plan(db, plan(ns)).unwrap();
        assert_eq!(propose_plan(db, plan(ns)).unwrap(), proposed);
        let orphan = ProposedPlan {
            plan_id: "plan-2".into(),
            intent_id: "missing".into(),
            ..plan(ns)
        };
        assert_eq!(propose_plan(db, orphan), Err(PlanError::NotFound));

        let first = simulate(db, ns, "sim-1", 1_000);
        let outcomes: Vec<(&str, &str)> = first
            .steps
            .iter()
            .map(|step| (step.outcome.as_str(), step.approval_state.as_str()))
            .collect();
        assert_eq!(
            outcomes,
            [("valid", "none"), ("denied", "required"), ("valid", "none")]
        );
        let effects: Vec<Vec<String>> = first
            .steps
            .iter()
            .map(|step| step.effect.as_ref().unwrap().changed_properties.clone())
            .collect();
        // c3 keeps its title: an update that changes nothing.
        assert_eq!(
            effects,
            [
                vec!["title".to_string()],
                vec!["title".to_string()],
                Vec::new()
            ]
        );
        assert_eq!(first.steps[1].effect.as_ref().unwrap().mutation, "update");

        // Simulation writes nothing: no Action instance, no object change.
        assert!(
            db.list_action_instances(ns, None, None, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.get_object(&format!("{ns}-c1"))
                .unwrap()
                .unwrap()
                .properties["title"],
            "account"
        );

        // A retried simulation id returns the stored one; a new id against
        // an unchanged world digests the same; both are kept.
        assert_eq!(simulate(db, ns, "sim-1", 9_000), first);
        let again = simulate(db, ns, "sim-2", 2_000);
        assert_eq!(again.digest, first.digest);
        // A changed precondition changes the digest.
        db.update_object(&Object {
            updated: 30,
            ..object(ns, &format!("{ns}-c3"), "churned")
        })
        .unwrap();
        let changed = simulate(db, ns, "sim-3", 3_000);
        assert_ne!(changed.digest, first.digest);
        assert_eq!(
            changed.steps[2].effect.as_ref().unwrap().changed_properties,
            ["title"]
        );

        let view = read_plan(db, ns, "plan-1", &|_| true).unwrap();
        assert_eq!(view.intent, stored);
        let ids: Vec<&str> = view
            .simulations
            .iter()
            .map(|simulation| simulation.simulation_id.as_str())
            .collect();
        assert_eq!(ids, ["sim-3", "sim-2", "sim-1"]);
    }

    #[test]
    fn sqlite_plans_simulate_through_the_preview_path() {
        contract(&RuntimeDb::memory(), "acme");
    }

    #[test]
    fn a_reader_without_access_to_a_step_object_sees_only_its_position() {
        let ns = "acme";
        let db = RuntimeDb::memory();
        world(&db, ns);
        create_intent(&db, intent(ns)).unwrap();
        propose_plan(&db, plan(ns)).unwrap();
        simulate(&db, ns, "sim-1", 1_000);
        let hidden = format!("{ns}-c2");
        let view = read_plan(&db, ns, "plan-1", &|id| id != hidden).unwrap();
        let step = &view.plan.steps[1];
        assert_eq!(step.type_id, "customer.escalate");
        assert!(step.object_id.is_empty() && step.parameters_json.is_empty());
        let simulated = &view.simulations[0].steps[1];
        assert_eq!(simulated.outcome, STEP_REDACTED);
        assert!(simulated.effect.is_none() && simulated.approval_state.is_empty());
        assert!(view.simulations[0].steps[0].effect.is_some());
    }

    #[test]
    fn a_step_object_the_simulator_cannot_see_is_unavailable() {
        let ns = "acme";
        let db = RuntimeDb::memory();
        world(&db, ns);
        create_intent(&db, intent(ns)).unwrap();
        propose_plan(&db, plan(ns)).unwrap();
        let hidden = format!("{ns}-c1");
        let visible = |id: &str| {
            if id == hidden {
                Ok(None)
            } else {
                db.get_object(id)
            }
        };
        let context = SimulationContext {
            actor: "planner",
            budget: None,
            proposal: None,
            policy_context: None,
            visible_object: &visible,
            now_ms: 1_000,
            acting_tenant: "",
        };
        let simulation = simulate_plan(&db, &context, ns, "plan-1", "sim-1").unwrap();
        // Stored as unavailable; shown to this caller as redacted.
        assert_eq!(simulation.steps[0].outcome, STEP_REDACTED);
        let stored = db
            .get_plan_simulation(ns, "plan-1", "sim-1")
            .unwrap()
            .unwrap();
        assert_eq!(stored.steps[0].outcome, PREVIEW_UNAVAILABLE);
        assert!(stored.steps[0].effect.is_none());
    }

    #[test]
    fn a_retried_simulation_is_shown_under_the_retrying_callers_policy() {
        let ns = "acme";
        let db = RuntimeDb::memory();
        world(&db, ns);
        create_intent(&db, intent(ns)).unwrap();
        propose_plan(&db, plan(ns)).unwrap();
        simulate(&db, ns, "sim-1", 1_000);
        let hidden = format!("{ns}-c1");
        let visible = |id: &str| {
            if id == hidden {
                Ok(None)
            } else {
                db.get_object(id)
            }
        };
        let context = SimulationContext {
            actor: "other",
            budget: None,
            proposal: None,
            policy_context: None,
            visible_object: &visible,
            now_ms: 2_000,
            acting_tenant: "",
        };
        let retried = simulate_plan(&db, &context, ns, "plan-1", "sim-1").unwrap();
        assert_eq!(retried.steps[0].outcome, STEP_REDACTED);
        assert!(retried.steps[0].effect.is_none() && retried.steps[0].object_revision.is_empty());
        assert!(retried.steps[1].effect.is_some());
    }

    #[test]
    fn a_step_whose_parameters_aim_at_another_object_is_refused() {
        let ns = "acme";
        let db = RuntimeDb::memory();
        world(&db, ns);
        create_intent(&db, intent(ns)).unwrap();
        // Step object c2 is the one checked; the parameters aim at c3.
        let mut aimed = step(ns, "customer.escalate", "c2", "probe");
        aimed.parameters_json = format!(r#"{{"object_id":"{ns}-c3","title":"probe"}}"#);
        let refused = propose_plan(
            &db,
            ProposedPlan {
                steps: vec![aimed],
                ..plan(ns)
            },
        );
        assert!(matches!(refused, Err(PlanError::Invalid(_))), "{refused:?}");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_plans_simulate_through_the_preview_path() {
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
        // A namespace of its own, so concurrent or repeated runs on one
        // database never share a record.
        let ns = format!("plans-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        contract(&db, &ns);
    }
}
