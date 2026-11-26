//! The predicted effect of a parked Action instance (#3085): what a grant
//! would write, against which object revision, under a digest the approver
//! hands back to `DecideActionInstance`.

use super::*;
use sha2::{Digest, Sha256};

/// How a predicted effect names a change to the object name.
const NAME_PROPERTY: &str = "_name";

/// The effect a grant of `instance` would make now, for an approver who read
/// it as `principals`. Reuses the plan simulation of one step, so the
/// prediction is the `PreviewObjectAction` path with nothing applied; a
/// create is planned from its parameters (`simulate_create_step`).
pub(super) fn current_instance_effect(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    policy_context: &crate::sekai::object_security::PrincipalPolicyContext,
    instance: &crate::sekai::action_instance::ActionInstance,
) -> Result<PreviewActionInstanceEffectResponse, Status> {
    use crate::sekai::action_plan::{
        PlanStep, SimulationContext, parameter_target, simulate_create_step, simulate_step,
    };

    if instance.status != crate::sekai::action_instance::STATUS_PARKED {
        return Err(Status::failed_precondition(
            "action instance is not awaiting a decision",
        ));
    }
    let clerk = service.cross_store.as_ref();
    let fallback_proposal = crate::chisei::system_one_action::SystemOneProposal;
    let proposal: &dyn crate::sekai::action_ports::ActionProposalPort = match clerk {
        Some(clerk) => clerk.proposal_port(),
        None => &fallback_proposal,
    };
    // The approver's read policy gates the object; the prediction runs on
    // the stored object, so its revision is the one a grant checks.
    let visible = |object_id: &str| match visible_action_object(
        service,
        principals,
        tenant_context,
        policy_context,
        &instance.namespace,
        object_id,
        crate::enterprise::NamespaceAction::Read,
    ) {
        Ok(_) => service.db.runtime().get_object(object_id),
        Err(status) if status.code() == tonic::Code::Internal => Err(status.message().to_owned()),
        Err(_) => Ok(None),
    };
    let step = PlanStep {
        type_id: instance.type_id.clone(),
        version: instance.version.clone(),
        object_id: parameter_target(&instance.parameters_json).unwrap_or_default(),
        parameters_json: instance.parameters_json.clone(),
    };
    // A create has no existing object to preview against (#3528): it is
    // planned from its parameters instead.
    let creates = service
        .db
        .runtime()
        .get_governed_action_type(&instance.namespace, &instance.type_id, &instance.version)
        .map_err(Status::internal)?
        .is_some_and(|definition| {
            definition.object_mutation == crate::sekai::governed_action_type::OBJECT_MUTATION_CREATE
        });
    let simulate = if creates {
        simulate_create_step
    } else {
        simulate_step
    };
    let simulated = simulate(
        service.db.runtime(),
        &SimulationContext {
            actor: &instance.principal,
            budget: clerk.and_then(|clerk| clerk.budget_port()),
            proposal: Some(proposal),
            policy_context: Some(policy_context),
            visible_object: &visible,
            now_ms: now_millis(),
            acting_tenant: acting_tenant(tenant_context),
        },
        0,
        &instance.namespace,
        &step,
    )
    .map_err(|error| match error {
        crate::sekai::action_plan::PlanError::Store(_) => {
            Status::internal("action effect unavailable")
        }
        _ => Status::failed_precondition("action effect unavailable"),
    })?;
    let effect_digest = effect_digest(&instance.instance_id, &simulated);
    let (effect, withheld_properties) = match simulated.effect {
        Some(effect) => {
            let hidden = withheld_properties(
                service,
                principals,
                tenant_context,
                &effect,
                &instance.namespace,
            )?;
            let (shown, withheld): (Vec<_>, Vec<_>) = effect
                .changed_properties
                .into_iter()
                .partition(|property| !hidden.contains(property));
            (
                Some(PlanStepEffect {
                    object_id: effect.object_id,
                    object_kind: effect.object_kind,
                    mutation: effect.mutation,
                    changed_properties: shown,
                }),
                u32::try_from(withheld.len()).unwrap_or(u32::MAX),
            )
        }
        None => (None, 0),
    };
    Ok(PreviewActionInstanceEffectResponse {
        instance_id: instance.instance_id.clone(),
        object_id: simulated.object_id,
        object_revision: simulated.object_revision,
        outcome: simulated.outcome,
        reason_code: simulated.reason_code,
        failing_criterion: simulated.failing_criterion,
        effect,
        withheld_properties,
        effect_digest,
    })
}

/// The digest of what a grant would write: the instance, the object
/// revision it was predicted against, and the full effect, withheld
/// properties included. Policy, budget, and time are left out, so it
/// changes only when the write would.
fn effect_digest(
    instance_id: &str,
    simulated: &crate::sekai::action_plan::StepSimulation,
) -> String {
    #[derive(serde::Serialize)]
    struct Canonical<'a> {
        instance_id: &'a str,
        object_id: &'a str,
        object_revision: &'a str,
        effect: &'a Option<crate::sekai::action_plan::StepEffect>,
    }
    let canonical = serde_json::to_vec(&Canonical {
        instance_id,
        object_id: &simulated.object_id,
        object_revision: &simulated.object_revision,
        effect: &simulated.effect,
    })
    .expect("action effect serializes");
    format!("sha256:{:x}", Sha256::digest(canonical))
}

/// The changed properties of `effect` the approver may not read. Each is
/// probed on the stored object, or on the object a create would add, and is
/// withheld when the response projection removes or rewrites it. A create
/// has no object grants yet, so a restricted property it sets is withheld
/// from everyone short of the operator.
fn withheld_properties(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    effect: &crate::sekai::action_plan::StepEffect,
    namespace: &str,
) -> Result<std::collections::BTreeSet<String>, Status> {
    let changed = &effect.changed_properties;
    let mut probe = service
        .db
        .runtime()
        .get_object(&effect.object_id)
        .map_err(Status::internal)?
        .unwrap_or_else(|| crate::domain::Object {
            id: effect.object_id.clone(),
            kind: effect.object_kind.clone(),
            name: String::new(),
            namespace: namespace.to_owned(),
            external_id: String::new(),
            properties: Default::default(),
            created: 0,
            updated: 0,
        });
    for property in changed.iter().filter(|property| *property != NAME_PROPERTY) {
        probe
            .properties
            .entry(property.clone())
            .or_insert_with(|| "probe".into());
    }
    let schema = service
        .schema_definitions
        .snapshot()
        .map_err(map_schema_definition_lifecycle_error)?;
    let shown = service.project_for_response(probe.clone(), &schema, principals, tenant_context)?;
    Ok(changed
        .iter()
        // `_name` stands for the object name, which every reader sees.
        .filter(|property| {
            *property != NAME_PROPERTY
                && probe.properties.get(*property) != shown.properties.get(*property)
        })
        .cloned()
        .collect())
}

/// Reads the predicted effect of a parked instance for a caller who may
/// read the instance and, for an update, its target object.
pub(super) async fn preview_action_instance_effect(
    service: &SekaiServiceImpl,
    req: Request<PreviewActionInstanceEffectRequest>,
) -> Result<Response<PreviewActionInstanceEffectResponse>, Status> {
    let principals = caller_principals(&req);
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let policy_context = principal_policy_context(&req);
    let inner = req.into_inner();
    let instance = service
        .db
        .runtime()
        .get_action_instance(inner.instance_id.trim())
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("action instance not found"))?;
    authorize_action_instance_read(
        service,
        &principals,
        &instance.namespace,
        tenant_context.as_ref(),
    )?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        &instance.namespace,
        false,
    )?;
    super::rpc_actions::authorize_action_instance_visibility(
        service,
        &principals,
        tenant_context.as_ref(),
        &policy_context,
        &instance,
    )?;
    current_instance_effect(
        service,
        &principals,
        tenant_context.as_ref(),
        &policy_context,
        &instance,
    )
    .map(Response::new)
}
