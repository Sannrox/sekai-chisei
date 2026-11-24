//! `SimulateObjectPolicyChange`: what named principals would read of one
//! namespace under candidate object policies and candidate grant changes.
//!
//! Both sides decide through [`effective_object_read`]: the current side over
//! the stored grants and active policies, the candidate side over a
//! [`GrantOverlay`] and the candidate policies. Nothing is changed; each call
//! is recorded as a decision naming the candidate grants and principals.

use super::rpc_objects::snapshot_from_activation;
use super::*;
use crate::sekai::object_security::{ObjectSecurityOperation, ObjectSecurityPolicy};
use crate::sekai::policy_decision::{PolicyOutcome, PolicySnapshot};
use crate::sekai::security::{Grant, Role};
use std::collections::BTreeSet;

/// Most objects one simulation evaluates. Summary counts are exact, so a
/// larger namespace is refused rather than sampled.
const MAX_SIMULATED_OBJECTS: usize = 10_000;
/// Most `differences` rows returned, and the default.
const MAX_DIFFERENCE_ROWS: usize = 10_000;
/// Most principals, added grants, and removed grants in one request.
const MAX_SIMULATION_INPUTS: usize = 100;

pub(super) async fn simulate_object_policy_change(
    service: &SekaiServiceImpl,
    req: Request<SimulateObjectPolicyChangeRequest>,
) -> Result<Response<SimulateObjectPolicyChangeResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    let svc = service.clone();
    service
        .spawn_db(move || {
            simulate_blocking(&svc, &principals, tenant_context.as_ref(), input).map(Response::new)
        })
        .await
}

fn simulate_blocking(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    input: SimulateObjectPolicyChangeRequest,
) -> Result<SimulateObjectPolicyChangeResponse, Status> {
    let db = service.db.runtime();
    let namespace = input.namespace.as_str();
    enforce_namespace_tenant_context(db, tenant_context, namespace, false)?;
    check_team_namespace(db, principals, namespace, false)?;
    let operation = if input.operation.trim().is_empty() {
        ObjectSecurityOperation::Read
    } else {
        ObjectSecurityOperation::parse(&input.operation).map_err(Status::invalid_argument)?
    };
    let named = if input.principals.is_empty() {
        principals.to_vec()
    } else {
        input.principals.clone()
    };
    if named.len() > MAX_SIMULATION_INPUTS
        || input.add_grants.len() > MAX_SIMULATION_INPUTS
        || input.remove_grant_ids.len() > MAX_SIMULATION_INPUTS
    {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_SIMULATION_INPUTS} principals, added grants and removed grants each"
        )));
    }
    let current_activation = db
        .get_object_security_activation(namespace)
        .map_err(map_object_security_error)?;
    let current = snapshot_from_activation(db, namespace, current_activation.as_ref())?;
    let candidate_policies = candidate_policies(db, namespace, &input.candidate_policies)?;
    let candidate = PolicySnapshot {
        namespace: namespace.into(),
        activation_digest: "candidate".into(),
        policies: candidate_policies
            .clone()
            .unwrap_or_else(|| current.policies.clone()),
        lattice: current.lattice.clone(),
    };
    let candidate_digest =
        crate::sekai::policy_decision::snapshot_digest(&candidate).map_err(Status::internal)?;
    let (added, removed) = candidate_grants(
        db,
        &CallerScope {
            security: service.security.as_ref(),
            principals,
            tenant_context,
            namespace,
            named: &named,
        },
        &input,
    )?;
    let grant_change = !added.is_empty() || !removed.is_empty();
    let overlay = GrantOverlay::new(db, added.clone(), removed.clone())?;
    let candidate_grants = if grant_change {
        ReadGrants::Overlay(&overlay)
    } else {
        ReadGrants::Stored
    };

    let objects = db
        .list_objects(&crate::domain::ListFilter {
            namespace: Some(namespace.into()),
            limit: i32::try_from(MAX_SIMULATED_OBJECTS + 1).unwrap_or(i32::MAX),
            ..crate::domain::ListFilter::default()
        })
        .map_err(Status::internal)?;
    if objects.len() > MAX_SIMULATED_OBJECTS {
        return Err(Status::failed_precondition(format!(
            "namespace holds more than {MAX_SIMULATED_OBJECTS} objects; simulation counts would not be exact"
        )));
    }

    let security = service.security.as_ref();
    let mut summaries = BTreeMap::<(String, String), PolicySimulationKindSummary>::new();
    let mut differences = Vec::new();
    for object in &objects {
        if is_reserved_governance_kind(&object.kind) {
            continue;
        }
        // The caller learns nothing, through counts or ids, about objects
        // it may not read itself.
        if !caller_reads(db, security, principals, tenant_context, object)? {
            continue;
        }
        let candidate_policy = match &candidate_policies {
            Some(policies) => PolicyCache::Resolved(policies.get(&object.kind)),
            None => PolicyCache::Fetch,
        };
        for principal in &named {
            let subject = std::slice::from_ref(principal);
            let read = |grants, policy| {
                effective_object_read(
                    db,
                    security,
                    grants,
                    object,
                    &ReadRequest {
                        principals: subject,
                        tenant_context: None,
                        operation,
                        purpose: None,
                        operation_id: "policy-simulation",
                        policy,
                    },
                )
            };
            let now = Visible::of(object, read(ReadGrants::Stored, PolicyCache::Fetch)?);
            let then = Visible::of(object, read(candidate_grants, candidate_policy)?);
            let summary = summaries
                .entry((principal.clone(), object.kind.clone()))
                .or_insert_with(|| PolicySimulationKindSummary {
                    principal: principal.clone(),
                    object_kind: object.kind.clone(),
                    ..Default::default()
                });
            summary.current_readable += u64::from(now.properties.is_some());
            match &then.properties {
                Some(visible) => {
                    summary.candidate_readable += 1;
                    for hidden in object
                        .properties
                        .keys()
                        .filter(|key| !visible.contains(*key))
                    {
                        *summary
                            .candidate_hidden_properties
                            .entry(hidden.clone())
                            .or_default() += 1;
                    }
                }
                None => {
                    *summary
                        .candidate_denied_by
                        .entry(then.denied_by.as_str().into())
                        .or_default() += 1;
                }
            }
            push_differences(&mut differences, principal, object, &now, &then);
        }
    }
    let action_summaries =
        action_summaries(service, principals, namespace, &named, candidate_grants)?;
    differences.sort_by(|left: &PolicySimulationDifference, right| {
        (&left.principal, &left.object_id, &left.property).cmp(&(
            &right.principal,
            &right.object_id,
            &right.property,
        ))
    });
    let limit = usize::try_from(input.limit)
        .ok()
        .filter(|limit| *limit > 0)
        .map_or(MAX_DIFFERENCE_ROWS, |limit| limit.min(MAX_DIFFERENCE_ROWS));
    let differences_truncated = differences.len() > limit;
    differences.truncate(limit);

    let applied_add_grants = added
        .iter()
        .map(|grant| CandidateGrant {
            object_id: grant.object_id.clone(),
            principal: grant.principal.clone(),
            role: grant.role.as_str().into(),
            not_after_ms: grant.not_after_ms,
        })
        .collect::<Vec<_>>();
    let applied_remove_grant_ids = removed
        .iter()
        .map(|grant| grant.id.clone())
        .collect::<Vec<_>>();
    db.record_decision(&audit::Decision {
        id: format!("policy-simulation:{}", uuid::Uuid::new_v4().as_simple()),
        timestamp: now_millis(),
        actor: principals.first().cloned().unwrap_or_default(),
        action: "simulate_object_policy_change".into(),
        reason: "simulated object policy and grant change; nothing changed".into(),
        evidence: HashMap::from([
            ("operation".into(), operation.as_str().into()),
            ("principals".into(), named.join(",")),
            (
                "add_grants".into(),
                applied_add_grants
                    .iter()
                    .map(|grant| {
                        format!(
                            "{}|{}|{}|{}",
                            grant.object_id, grant.principal, grant.role, grant.not_after_ms
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "remove_grant_ids".into(),
                applied_remove_grant_ids.join(","),
            ),
            ("candidate_digest".into(), candidate_digest.clone()),
        ]),
        target_id: namespace.into(),
        outcome: "allow".into(),
    })
    .map_err(Status::internal)?;

    Ok(SimulateObjectPolicyChangeResponse {
        namespace: namespace.into(),
        current_activation_digest: current.activation_digest,
        candidate_digest,
        differences,
        kind_summaries: summaries.into_values().collect(),
        applied_add_grants,
        applied_remove_grant_ids,
        differences_truncated,
        action_summaries,
    })
}

/// Per named principal, the enabled Action types its grants let it propose
/// and decide, over the stored grants and over `candidate`. The same gates
/// real submission and decision call decide each answer. Nothing is
/// reported when the caller may not list the namespace's Action types.
fn action_summaries(
    service: &SekaiServiceImpl,
    caller: &[String],
    namespace: &str,
    named: &[String],
    candidate: ReadGrants<'_>,
) -> Result<Vec<PolicySimulationActionSummary>, Status> {
    let db = service.db.runtime();
    // As `ListGovernedActionTypes` authorizes its caller.
    let caller_lists_types = check_team_namespace(db, caller, namespace, true).is_ok()
        && check_action_admin(
            &service.security,
            &format!("governed_action:{namespace}"),
            caller,
        )
        .is_ok();
    if !caller_lists_types {
        return Ok(Vec::new());
    }
    let types = db
        .list_governed_action_types(namespace, None, true)
        .map_err(Status::internal)?;
    let allowed = |grants: ReadGrants<'_>, principal: &String| -> Result<_, Status> {
        let subject = std::slice::from_ref(principal);
        let proposes = granted(authorize_action_instance_submit_in(
            service, grants, subject, namespace,
        ))?;
        let admin = granted(authorize_source_type_namespace_admin_in(
            service, grants, subject, namespace,
        ))?;
        let mut proposable = BTreeSet::new();
        let mut runnable = BTreeSet::new();
        for type_def in &types {
            if proposes {
                proposable.insert(type_def.type_id.clone());
            }
            if crate::sekai::action_instance_admission::entitled_to_decide(
                type_def,
                std::iter::once(principal.as_str()),
                admin,
            ) {
                runnable.insert(type_def.type_id.clone());
            }
        }
        Ok((
            proposable.into_iter().collect::<Vec<_>>(),
            runnable.into_iter().collect::<Vec<_>>(),
        ))
    };
    named
        .iter()
        .map(|principal| {
            let (current_proposable_type_ids, current_runnable_type_ids) =
                allowed(ReadGrants::Stored, principal)?;
            let (candidate_proposable_type_ids, candidate_runnable_type_ids) =
                allowed(candidate, principal)?;
            Ok(PolicySimulationActionSummary {
                principal: principal.clone(),
                current_proposable_type_ids,
                candidate_proposable_type_ids,
                current_runnable_type_ids,
                candidate_runnable_type_ids,
            })
        })
        .collect()
}

/// A refusal is `false`; a check that could not complete fails the
/// simulation instead of reporting a guess.
fn granted<T>(decision: Result<T, Status>) -> Result<bool, Status> {
    match decision {
        Ok(_) => Ok(true),
        Err(status)
            if matches!(
                status.code(),
                tonic::Code::PermissionDenied | tonic::Code::Unauthenticated
            ) =>
        {
            Ok(false)
        }
        Err(status) => Err(status),
    }
}

/// One side of a simulated read: the visible property names when readable.
struct Visible {
    properties: Option<BTreeSet<String>>,
    denied_by: ReadLayer,
}

impl Visible {
    fn of(object: &domain::Object, decision: ReadDecision) -> Self {
        match decision {
            ReadDecision::Allowed { access, .. } => Self {
                properties: Some(match access {
                    Some(access) => access.visible_property_names(object),
                    None => object.properties.keys().cloned().collect(),
                }),
                denied_by: ReadLayer::Hidden,
            },
            ReadDecision::Denied { layer, .. } => Self {
                properties: None,
                denied_by: layer,
            },
        }
    }
}

/// Object rows where readability changes, then property rows where a
/// property's visibility changes, as the policy-only simulation reported.
fn push_differences(
    differences: &mut Vec<PolicySimulationDifference>,
    principal: &str,
    object: &domain::Object,
    now: &Visible,
    then: &Visible,
) {
    let outcome = |readable: bool| {
        if readable {
            PolicyOutcome::Allow
        } else {
            PolicyOutcome::Deny
        }
        .as_str()
        .to_string()
    };
    let row = |property: &str, current: bool, candidate: bool| PolicySimulationDifference {
        principal: principal.into(),
        object_id: object.id.clone(),
        object_kind: object.kind.clone(),
        property: property.into(),
        current_outcome: outcome(current),
        candidate_outcome: outcome(candidate),
    };
    if now.properties.is_some() != then.properties.is_some() {
        differences.push(row("", now.properties.is_some(), then.properties.is_some()));
    }
    let empty = BTreeSet::new();
    let current = now.properties.as_ref().unwrap_or(&empty);
    let candidate = then.properties.as_ref().unwrap_or(&empty);
    for property in current.symmetric_difference(candidate) {
        differences.push(row(
            property,
            current.contains(property),
            candidate.contains(property),
        ));
    }
}

/// The stored candidate policy revisions, by kind; `None` when none are given.
fn candidate_policies(
    db: &RuntimeDb,
    namespace: &str,
    bindings: &[ObjectSecurityPolicyBinding],
) -> Result<Option<BTreeMap<String, ObjectSecurityPolicy>>, Status> {
    if bindings.is_empty() {
        return Ok(None);
    }
    let mut policies = BTreeMap::new();
    for binding in bindings {
        if binding.kind.trim().is_empty() || binding.revision_digest.trim().is_empty() {
            return Err(Status::invalid_argument(
                "each candidate policy kind and revision is required",
            ));
        }
        let revision = db
            .get_object_security_policy(namespace, &binding.revision_digest)
            .map_err(map_object_security_error)?
            .ok_or_else(|| Status::not_found("candidate policy revision not found"))?;
        let policy = ObjectSecurityPolicy::from_canonical_input(&revision.canonical_policy_json)
            .map_err(Status::invalid_argument)?;
        if policy.kind != binding.kind {
            return Err(Status::invalid_argument(
                "candidate policy kind does not match stored revision",
            ));
        }
        if policies.insert(binding.kind.clone(), policy).is_some() {
            return Err(Status::invalid_argument(
                "each candidate policy kind must appear exactly once",
            ));
        }
    }
    Ok(Some(policies))
}

/// Validated grant changes: added grants (not stored) and the stored grants
/// to remove. Each is on an object of `namespace`, its namespace boundary, or
/// the principal profile of a simulated principal, so a simulation cannot
/// probe grants elsewhere.
fn candidate_grants(
    db: &RuntimeDb,
    scope: &CallerScope<'_>,
    input: &SimulateObjectPolicyChangeRequest,
) -> Result<(Vec<Grant>, Vec<Grant>), Status> {
    // Missing, out of scope, and unreadable by the caller answer alike, so
    // validation is no oracle for objects or grants the caller cannot see.
    let in_scope = |object_id: &str| -> Result<bool, Status> {
        let Some(object) = db.get_object(object_id).map_err(Status::internal)? else {
            return Ok(false);
        };
        let namespace = scope.namespace;
        let boundary =
            object.kind == "namespace" && object.external_id == format!("namespace:{namespace}");
        let profile = object.kind == markings::PRINCIPAL_PROFILE_KIND
            && scope.named.iter().any(|principal| {
                object.external_id == markings::principal_profile_external_id(principal)
            });
        // A simulated principal's sealed profile is credential-admin state,
        // which the caller administers whether or not its ACL names it.
        if profile {
            return Ok(true);
        }
        Ok((object.namespace == namespace || boundary)
            && caller_reads(
                db,
                scope.security,
                scope.principals,
                scope.tenant_context,
                &object,
            )?)
    };
    let now = now_millis();
    let mut added = Vec::new();
    for (index, candidate) in input.add_grants.iter().enumerate() {
        let principal = candidate.principal.trim();
        if candidate.object_id.trim().is_empty() || principal.is_empty() {
            return Err(Status::invalid_argument(
                "each added grant needs an object_id and a principal",
            ));
        }
        let role = Role::parse(&candidate.role).ok_or_else(|| {
            Status::invalid_argument("added grant role must be viewer, editor or admin")
        })?;
        if candidate.not_after_ms < 0 {
            return Err(Status::invalid_argument(
                "added grant not_after_ms must not be negative",
            ));
        }
        if added.iter().any(|grant: &Grant| {
            grant.object_id == candidate.object_id && grant.principal == principal
        }) {
            return Err(Status::invalid_argument(
                "each added grant object and principal must appear once",
            ));
        }
        if !in_scope(&candidate.object_id)? {
            return Err(Status::not_found(
                "candidate grant object not found in the simulated namespace",
            ));
        }
        added.push(Grant {
            id: format!("candidate-grant-{index}"),
            object_id: candidate.object_id.clone(),
            principal: principal.into(),
            role,
            created: now,
            purpose: String::new(),
            not_after_ms: candidate.not_after_ms,
            exception_reason: String::new(),
        });
    }
    let mut removed = Vec::new();
    for id in &input.remove_grant_ids {
        if removed.iter().any(|grant: &Grant| &grant.id == id) {
            return Err(Status::invalid_argument(
                "each removed grant id must appear once",
            ));
        }
        let grant = match db.get_grant(id).map_err(Status::internal)? {
            Some(grant) if in_scope(&grant.object_id)? => grant,
            _ => return Err(Status::not_found("removed grant not found")),
        };
        removed.push(grant);
    }
    Ok((added, removed))
}

/// The caller and namespace a simulation's candidate grants must stay within.
struct CallerScope<'a> {
    security: &'a SecurityChecker,
    principals: &'a [String],
    tenant_context: Option<&'a RequestEnterpriseContext>,
    namespace: &'a str,
    named: &'a [String],
}

/// True when the caller's own request could read `object`.
fn caller_reads(
    db: &RuntimeDb,
    security: &SecurityChecker,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    object: &domain::Object,
) -> Result<bool, Status> {
    let request = ReadRequest {
        principals,
        tenant_context,
        operation: ObjectSecurityOperation::Read,
        purpose: None,
        operation_id: "policy-simulation",
        policy: PolicyCache::Fetch,
    };
    Ok(matches!(
        effective_object_read(db, security, ReadGrants::Stored, object, &request)?,
        ReadDecision::Allowed { .. }
    ))
}
