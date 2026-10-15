use super::*;

pub(super) fn require_credential_admin(principals: &[String]) -> Result<(), Status> {
    if principals
        .iter()
        .any(|principal| principal == "root" || principal == "local")
    {
        return Ok(());
    }
    Err(Status::permission_denied("credential admin required"))
}
pub(super) fn map_object_security_error(error: String) -> Status {
    if error.starts_with("object_security_idempotency_conflict")
        || error.starts_with("object_security_activation_incomplete")
        || error.starts_with("object_security_policy_not_found")
        || error.starts_with("object_security_policy_invalid")
    {
        Status::failed_precondition(error)
    } else if error.starts_with("invalid ") {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}
pub(super) fn map_source_type_descriptor_error(error: String) -> Status {
    if error.contains("unavailable") {
        Status::unavailable("source-type descriptor is unavailable")
    } else if error.contains("unsupported")
        || error.contains("must remain")
        || error.contains("stays the code-owned")
        || error.contains("canonical registered token")
        || error.contains("required")
        || error.contains("cannot be inferred")
        || error.contains("timestamp")
    {
        Status::invalid_argument(error)
    } else {
        Status::unavailable("source-type descriptor is unavailable")
    }
}
pub(super) fn to_proto_source_type_descriptor(
    descriptor: &crate::sekai::source_type_descriptor::SourceTypeDescriptorIdentity,
) -> SourceTypeDescriptor {
    SourceTypeDescriptor {
        contract_version: descriptor.contract_version.clone(),
        namespace: descriptor.namespace.clone(),
        family: descriptor.family.clone(),
        source: descriptor.source.clone(),
        record_kind: descriptor.record_kind.clone(),
        schema_revision: descriptor.schema_revision.clone(),
        digest: descriptor.digest.clone(),
        status: descriptor.status.clone(),
    }
}
pub(super) fn map_purpose_authorization_error(error: String) -> Status {
    if error.contains("unavailable") {
        Status::unavailable("purpose authorization unavailable")
    } else if error.contains("unsupported")
        || error.contains("invalid")
        || error.contains("missing")
        || error.contains("already revoked")
    {
        Status::failed_precondition(error)
    } else {
        Status::internal(error)
    }
}
pub(super) fn from_proto_purpose_authorization(
    authorization: PurposeAuthorization,
) -> crate::sekai::purpose_authorization::PurposeAuthorization {
    crate::sekai::purpose_authorization::PurposeAuthorization {
        contract_version: authorization.contract_version,
        authorization_id: authorization.authorization_id,
        actor: authorization.actor,
        purpose: authorization.purpose,
        namespace: authorization.namespace,
        kind: authorization.kind,
        not_before_ms: authorization.not_before_ms,
        not_after_ms: authorization.not_after_ms,
        policy_activation_digest: authorization.policy_activation_digest,
        created_by: authorization.created_by,
        created_at_ms: authorization.created_at_ms,
        revoked_at_ms: authorization.revoked_at_ms,
    }
}
pub(super) fn map_classification_lattice_error(error: String) -> Status {
    if error.contains("unavailable") || error.contains("stale") || error.contains("mismatch") {
        Status::unavailable("classification lattice unavailable")
    } else if error.contains("unsupported")
        || error.contains("invalid")
        || error.contains("unknown")
        || error.contains("acyclic")
        || error.contains("duplicate")
    {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}
pub(super) fn from_proto_classification_lattice(
    lattice: ClassificationLattice,
) -> crate::sekai::classification_lattice::ClassificationLattice {
    let mut parents = BTreeMap::new();
    for edge in lattice.parents {
        parents
            .entry(edge.child)
            .or_insert_with(Vec::new)
            .push(edge.parent);
    }
    crate::sekai::classification_lattice::ClassificationLattice {
        contract_version: lattice.contract_version,
        namespace: lattice.namespace,
        tokens: lattice.tokens,
        parents,
        incomparable: lattice
            .incomparable
            .into_iter()
            .map(|pair| (pair.left, pair.right))
            .collect(),
    }
}
pub(super) fn to_proto_classification_lattice(
    lattice: &crate::sekai::classification_lattice::ClassificationLattice,
) -> Result<ClassificationLattice, Status> {
    Ok(ClassificationLattice {
        contract_version: lattice.contract_version.clone(),
        namespace: lattice.namespace.clone(),
        tokens: lattice.tokens.clone(),
        parents: lattice
            .parents
            .iter()
            .flat_map(|(child, parents)| {
                parents.iter().map(|parent| ClassificationParentEdge {
                    child: child.clone(),
                    parent: parent.clone(),
                })
            })
            .collect(),
        incomparable: lattice
            .incomparable
            .iter()
            .map(|(left, right)| ClassificationIncomparablePair {
                left: left.clone(),
                right: right.clone(),
            })
            .collect(),
        digest: lattice.digest().map_err(Status::internal)?,
    })
}
pub(super) fn to_proto_purpose_authorization(
    authorization: &crate::sekai::purpose_authorization::PurposeAuthorization,
) -> PurposeAuthorization {
    PurposeAuthorization {
        contract_version: authorization.contract_version.clone(),
        authorization_id: authorization.authorization_id.clone(),
        actor: authorization.actor.clone(),
        purpose: authorization.purpose.clone(),
        namespace: authorization.namespace.clone(),
        kind: authorization.kind.clone(),
        not_before_ms: authorization.not_before_ms,
        not_after_ms: authorization.not_after_ms,
        policy_activation_digest: authorization.policy_activation_digest.clone(),
        created_by: authorization.created_by.clone(),
        created_at_ms: authorization.created_at_ms,
        revoked_at_ms: authorization.revoked_at_ms,
    }
}
pub(super) fn to_proto_object_security_revision(
    revision: &crate::sekai::object_security::ObjectSecurityPolicyRevision,
) -> ObjectSecurityPolicyRevision {
    ObjectSecurityPolicyRevision {
        namespace: revision.namespace.clone(),
        kind: revision.kind.clone(),
        revision_digest: revision.revision_digest.clone(),
        canonical_policy_json: revision.canonical_policy_json.clone(),
        created_by: revision.created_by.clone(),
        created_at_ms: revision.created_at_ms,
    }
}
pub(super) fn to_proto_object_security_activation(
    activation: &crate::sekai::object_security::ObjectSecurityActivation,
) -> ObjectSecurityActivation {
    ObjectSecurityActivation {
        namespace: activation.namespace.clone(),
        activation_id: activation.activation_id.clone(),
        policies: activation
            .policies
            .iter()
            .map(|(kind, revision_digest)| ObjectSecurityPolicyBinding {
                kind: kind.clone(),
                revision_digest: revision_digest.clone(),
            })
            .collect(),
        activated_by: activation.activated_by.clone(),
        activated_at_ms: activation.activated_at_ms,
    }
}
pub(super) fn credential_admin_actor(
    db: &RuntimeDb,
    req: &Request<impl std::any::Any>,
    requested_tenant: &str,
) -> Result<(String, bool), Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let actor = principals
        .into_iter()
        .next()
        .ok_or_else(|| Status::unauthenticated("authenticated principal required"))?;
    let _ = (db, requested_tenant);
    require_credential_admin(std::slice::from_ref(&actor))?;
    Ok((actor, true))
}
pub(super) fn principal_policy_context_from(
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
) -> crate::sekai::object_security::PrincipalPolicyContext {
    if let Some(context) = tenant_context {
        return crate::sekai::object_security::PrincipalPolicyContext {
            subjects: vec![context.principal.subject.clone()],
            scopes: context.scopes.clone(),
            delegated_subject: context.act.clone(),
        }
        .normalized();
    }
    crate::sekai::object_security::PrincipalPolicyContext {
        subjects: principals.to_vec(),
        scopes: Vec::new(),
        delegated_subject: None,
    }
    .normalized()
}
pub(super) fn principal_policy_context(
    req: &Request<impl std::any::Any>,
) -> crate::sekai::object_security::PrincipalPolicyContext {
    if let Some(context) = req
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        return principal_policy_context_from(&[], Some(context));
    }
    // The community/insecure fallback remains explicit and carries no scopes.
    principal_policy_context_from(&caller_principals(req), None)
}
pub(super) fn ontology_revision_pin(req: &Request<impl std::any::Any>) -> Option<String> {
    req.metadata()
        .get("x-sekai-definition-revision")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}
pub(super) fn enforce_optional_ontology_revision_pin(
    db: &RuntimeDb,
    pin: Option<&str>,
    namespace: &str,
) -> Result<(), Status> {
    let Some(pin) = pin.filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    if !crate::ontology_codegen::is_metadata_safe(pin) || namespace.is_empty() {
        return Err(Status::failed_precondition(
            "ontology client revision pin is stale",
        ));
    }
    let live = db
        .get_published_definition_revision(namespace)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    match live {
        Some(revision) if revision.published && revision.revision_digest == pin => Ok(()),
        _ => Err(Status::failed_precondition(
            "ontology client revision pin is stale",
        )),
    }
}
pub(super) fn request_purpose_presentation(
    req: &Request<impl std::any::Any>,
    principals: &[String],
) -> Option<crate::sekai::purpose_authorization::PurposePresentation> {
    let actor = principals.first()?.clone();
    let purpose = req
        .metadata()
        .get("x-sekai-purpose")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string();
    Some(crate::sekai::purpose_authorization::PurposePresentation { actor, purpose })
}
pub(super) fn require_purpose_for_kind(
    db: &RuntimeDb,
    namespace: &str,
    kind: &str,
    presentation: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    operation_id: &str,
) -> Result<(), Status> {
    let decision = purpose_decision_for_kind(db, namespace, kind, presentation, operation_id)?;
    if decision.decision == markings::MarkingDecision::Deny {
        return Err(Status::not_found("not found"));
    }
    record_purpose_allow(db, presentation, operation_id, &decision)?;
    Ok(())
}
pub(super) fn purpose_allows_kind(
    db: &RuntimeDb,
    namespace: &str,
    kind: &str,
    presentation: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    recorded: &mut HashSet<(String, String)>,
) -> Result<bool, Status> {
    let decision = purpose_decision_for_kind(db, namespace, kind, presentation, "purpose-filter")?;
    if decision.decision == markings::MarkingDecision::Deny {
        return Ok(false);
    }
    if decision.decision == markings::MarkingDecision::Allow
        && recorded.insert((namespace.to_string(), kind.to_string()))
    {
        record_purpose_allow(
            db,
            presentation,
            &format!("purpose-filter:{namespace}:{kind}"),
            &decision,
        )?;
    }
    Ok(true)
}
pub(super) fn purpose_kind_permitted(
    db: &RuntimeDb,
    namespace: &str,
    kind: &str,
    presentation: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
) -> Result<bool, Status> {
    let decision = purpose_decision_for_kind(db, namespace, kind, presentation, "purpose-source")?;
    Ok(decision.decision != markings::MarkingDecision::Deny)
}
pub(super) fn purpose_decision_for_kind(
    db: &RuntimeDb,
    namespace: &str,
    kind: &str,
    presentation: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    operation_id: &str,
) -> Result<crate::sekai::purpose_authorization::PurposeDecision, Status> {
    let policy = match db.active_object_policy(namespace, kind) {
        Ok(policy) => policy,
        Err(error) if error.starts_with("object_security_denied") => {
            return Ok(crate::sekai::purpose_authorization::PurposeDecision {
                decision: markings::MarkingDecision::Deny,
                decision_id: format!("purpose:{operation_id}:denied"),
                required_purpose: String::new(),
                detail: "object authorization denied".into(),
            });
        }
        Err(_) => return Err(Status::unavailable("object authorization unavailable")),
    };
    let Some(policy) = policy else {
        return Ok(crate::sekai::purpose_authorization::PurposeDecision {
            decision: markings::MarkingDecision::NotApplicable,
            decision_id: format!("purpose:{operation_id}:n/a"),
            required_purpose: String::new(),
            detail: "kind does not require a purpose".into(),
        });
    };
    let Some(required) = policy.required_purpose.as_deref() else {
        return Ok(crate::sekai::purpose_authorization::PurposeDecision {
            decision: markings::MarkingDecision::NotApplicable,
            decision_id: format!("purpose:{operation_id}:n/a"),
            required_purpose: String::new(),
            detail: "kind does not require a purpose".into(),
        });
    };
    let activation = db
        .get_object_security_activation(namespace)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::unavailable("object authorization unavailable"))?;
    let activation_digest =
        crate::sekai::object_security::object_security_activation_digest(&activation)
            .map_err(Status::internal)?;
    let authorization = match presentation {
        Some(presented)
            if !markings::is_trusted_service_principal(&presented.actor)
                && !presented.purpose.is_empty() =>
        {
            db.find_purpose_authorization(
                &presented.actor,
                &presented.purpose,
                namespace,
                kind,
                &activation_digest,
                now_millis(),
            )
            .map_err(|error| {
                if error.contains("unavailable") {
                    Status::unavailable("purpose authorization unavailable")
                } else {
                    Status::internal(error)
                }
            })?
        }
        _ => None,
    };
    Ok(
        crate::sekai::purpose_authorization::evaluate_required_purpose(
            crate::sekai::purpose_authorization::PurposeEvaluation {
                operation_id,
                required_purpose: Some(required),
                presentation,
                authorization: authorization.as_ref(),
                namespace,
                kind,
                activation_digest: &activation_digest,
                now_ms: now_millis(),
            },
        ),
    )
}
pub(super) fn record_purpose_allow(
    db: &RuntimeDb,
    presentation: Option<&crate::sekai::purpose_authorization::PurposePresentation>,
    operation_id: &str,
    decision: &crate::sekai::purpose_authorization::PurposeDecision,
) -> Result<(), Status> {
    if decision.decision != markings::MarkingDecision::Allow {
        return Ok(());
    }
    let actor = presentation
        .map(|presented| presented.actor.as_str())
        .unwrap_or_default();
    let mut evidence = HashMap::new();
    evidence.insert("required_purpose".into(), decision.required_purpose.clone());
    evidence.insert("detail".into(), decision.detail.clone());
    record_marking_or_purpose_decision(
        db,
        actor,
        "purpose.read",
        operation_id,
        &decision.decision_id,
        "allowed",
        evidence,
    )
}
pub(super) fn request_tenant_context(
    db: &RuntimeDb,
    req: &Request<impl std::any::Any>,
) -> Result<Option<RequestEnterpriseContext>, Status> {
    if let Some(context) = req
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        if db.enterprise_extension().is_some() && context.tenant.is_none() {
            return Err(Status::unauthenticated(
                "enterprise tenant context required",
            ));
        }
        return Ok(Some(context.clone()));
    }
    if db.enterprise_extension().is_some() {
        return Err(Status::unauthenticated(
            "enterprise authenticated context required",
        ));
    }
    Ok(None)
}
pub(super) fn enforce_namespace_tenant_context(
    db: &RuntimeDb,
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    write: bool,
) -> Result<(), Status> {
    enforce_namespace_tenant_context_for(
        db,
        tenant_context,
        namespace,
        if write {
            crate::enterprise::NamespaceAction::Write
        } else {
            crate::enterprise::NamespaceAction::Read
        },
    )
}

/// Live scope registration of a service-principal caller (#1511), or `None`
/// for any other caller. A service-principal context whose registration is
/// gone or belongs to another tenant is refused, so enforcement fails closed.
pub(super) fn service_principal_scope(
    db: &RuntimeDb,
    tenant_context: Option<&RequestEnterpriseContext>,
) -> Result<Option<crate::sekai::service_principal::ServicePrincipalRegistration>, Status> {
    let Some(context) = tenant_context
        .filter(|context| crate::service_token::is_service_principal_context(context))
    else {
        return Ok(None);
    };
    let tenant_id = context
        .tenant
        .as_ref()
        .map(|tenant| tenant.tenant_id.as_str());
    db.get_service_principal(&context.principal.subject)
        .map_err(Status::internal)?
        .filter(|registration| Some(registration.tenant_id.as_str()) == tenant_id)
        .map(Some)
        .ok_or_else(|| Status::permission_denied("service principal registration unavailable"))
}

/// Refuse a service-principal caller outside its registered Action types.
pub(super) fn enforce_service_principal_action_type(
    db: &RuntimeDb,
    tenant_context: Option<&RequestEnterpriseContext>,
    type_id: &str,
) -> Result<(), Status> {
    match service_principal_scope(db, tenant_context)? {
        Some(scope) if !scope.action_types.iter().any(|allowed| allowed == type_id) => Err(
            Status::permission_denied("action type outside the service principal scope"),
        ),
        _ => Ok(()),
    }
}

pub(super) fn enforce_namespace_tenant_context_for(
    db: &RuntimeDb,
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    action: crate::enterprise::NamespaceAction,
) -> Result<(), Status> {
    let write = action == crate::enterprise::NamespaceAction::Write;
    let mut guest_grant_ok = None;
    let result = (|| {
        if service_principal_scope(db, tenant_context)?
            .is_some_and(|scope| !scope.namespaces.iter().any(|allowed| allowed == namespace))
        {
            return Err(Status::permission_denied(
                "namespace outside the service principal scope",
            ));
        }
        if let Some(context) = tenant_context {
            context.authorize_space(action).map_err(extension_status)?;
            context
                .authorize_credential_scope(action)
                .map_err(extension_status)?;
        }
        if let Some(context) = tenant_context
            && let Some(actor) = &context.act
        {
            check_team_namespace(
                db,
                std::slice::from_ref(&context.principal.subject),
                namespace,
                write,
            )?;
            check_team_namespace(db, std::slice::from_ref(actor), namespace, write)?;
        }
        if let Some(context) = tenant_context
            && context.guest_home_tenant().is_some()
        {
            let guest = authorize_guest(db, context, namespace, action);
            guest_grant_ok = Some(guest.is_ok());
            return match guest {
                Ok(()) => {
                    if action == crate::enterprise::NamespaceAction::Discover {
                        record_namespace_discovery(db, context, namespace, true)?;
                    }
                    Ok(())
                }
                Err(status)
                    if status.code() == tonic::Code::PermissionDenied
                        && action == crate::enterprise::NamespaceAction::Discover =>
                {
                    authorize_discovery_namespace(db, context, namespace)
                }
                Err(status) => Err(status),
            };
        }
        let Some(extension) = db.enterprise_extension() else {
            return Ok(());
        };
        let Some(context) = tenant_context else {
            return Err(Status::unauthenticated(
                "enterprise authenticated context required",
            ));
        };
        extension
            .authorize_authenticated_context(context, namespace, action)
            .map_err(extension_status)
    })();
    // Guest-grant audit stays independent of a later discovery admit (#1435).
    if let Some(context) = tenant_context
        && context.guest_home_tenant().is_some()
    {
        crate::grpc::record_guest_access(
            db,
            context,
            namespace,
            &format!("{action:?}").to_lowercase(),
            guest_grant_ok.unwrap_or(result.is_ok()),
        )
        .map_err(Status::internal)?;
    }
    if result.is_err() {
        record_delegated_policy_decision(
            db,
            &principal_policy_context_from(&[], tenant_context),
            namespace,
            if write {
                crate::sekai::object_security::ObjectSecurityOperation::Update
            } else {
                crate::sekai::object_security::ObjectSecurityOperation::Read
            },
            crate::sekai::policy_decision::PolicyOutcome::Deny,
        )?;
    }
    result
}
/// Cross-tenant (guest) namespace decision (#1432): only a host grant from
/// the installed extension whose role permits `action` admits it.
fn authorize_guest(
    db: &RuntimeDb,
    context: &RequestEnterpriseContext,
    namespace: &str,
    action: crate::enterprise::NamespaceAction,
) -> Result<(), Status> {
    guest_grant(db, context, namespace, action).map(|_| ())
}

fn acting_owner_tenant(context: &RequestEnterpriseContext) -> &str {
    context
        .tenant
        .as_ref()
        .map(|tenant| tenant.tenant_id.as_str())
        .filter(|tenant| !tenant.trim().is_empty())
        .unwrap_or_default()
}

fn record_namespace_discovery(
    db: &RuntimeDb,
    context: &RequestEnterpriseContext,
    namespace: &str,
    allowed: bool,
) -> Result<(), Status> {
    crate::grpc::record_discovery(
        db,
        context,
        acting_owner_tenant(context),
        namespace,
        "namespace",
        allowed,
    )
    .map_err(Status::internal)
}

fn discovery_rule(
    db: &RuntimeDb,
    context: &RequestEnterpriseContext,
) -> Result<Option<crate::enterprise::DiscoveryRule>, Status> {
    let owner = acting_owner_tenant(context);
    if owner.is_empty() {
        return Err(Status::permission_denied("enterprise authorization denied"));
    }
    let Some(extension) = db.enterprise_extension() else {
        return Ok(None);
    };
    extension
        .authorize_discovery(context, owner)
        .map_err(extension_status)
}

fn authorize_discovery_namespace(
    db: &RuntimeDb,
    context: &RequestEnterpriseContext,
    namespace: &str,
) -> Result<(), Status> {
    let denied = || Status::permission_denied("enterprise authorization denied");
    let rule = match discovery_rule(db, context) {
        Ok(rule) => rule,
        Err(status) if status.code() == tonic::Code::PermissionDenied => {
            record_namespace_discovery(db, context, namespace, false)?;
            return Err(status);
        }
        Err(status) => return Err(status),
    };
    let allowed = rule
        .as_ref()
        .is_some_and(|rule| rule.exposes_namespace(namespace));
    record_namespace_discovery(db, context, namespace, allowed)?;
    allowed.then_some(()).ok_or_else(denied)
}

fn guest_grant(
    db: &RuntimeDb,
    context: &RequestEnterpriseContext,
    namespace: &str,
    action: crate::enterprise::NamespaceAction,
) -> Result<crate::enterprise::GuestGrant, Status> {
    let denied = || Status::permission_denied("enterprise authorization denied");
    let grant = db
        .enterprise_extension()
        .ok_or_else(denied)?
        .authorize_guest_namespace(context, namespace, action)
        .map_err(extension_status)?;
    grant.permits(action).then_some(grant).ok_or_else(denied)
}

/// Whether a guest may see (`Read`) or write (`Write`) this object: the host
/// grant's marking ceiling must cover its `access_marking` (#1433). An
/// activated lattice uses dominance; otherwise the evidence ordinal.
/// Unparsable or unknown tokens fail closed. Non-guests always pass here.
pub(super) fn guest_object_permitted(
    db: &RuntimeDb,
    tenant_context: Option<&RequestEnterpriseContext>,
    object: &domain::Object,
    action: crate::enterprise::NamespaceAction,
) -> Result<bool, Status> {
    let Some(context) = tenant_context.filter(|context| context.guest_home_tenant().is_some())
    else {
        return Ok(true);
    };
    let grant = match guest_grant(db, context, &object.namespace, action) {
        Ok(grant) => grant,
        Err(status) if status.code() == tonic::Code::PermissionDenied => return Ok(false),
        Err(status) => return Err(status),
    };
    let permitted = guest_ceiling_covers(db, object, &grant.marking_ceiling)?;
    if !permitted {
        crate::grpc::record_guest_access(db, context, &object.id, "ceiling", false)
            .map_err(Status::internal)?;
    }
    Ok(permitted)
}

fn guest_ceiling_covers(
    db: &RuntimeDb,
    object: &domain::Object,
    ceiling: &str,
) -> Result<bool, Status> {
    let Some(marking) = markings::object_marking_token(object) else {
        return Ok(true);
    };
    match load_classification_lattice(db, &object.namespace)? {
        Some(lattice) => Ok(lattice.dominates(ceiling, marking).unwrap_or(false)),
        None => {
            let (Ok(ceiling), Ok(marking)) = (
                markings::parse_classification(ceiling),
                markings::parse_classification(marking),
            ) else {
                return Ok(false);
            };
            Ok(marking <= ceiling)
        }
    }
}

pub(super) fn extension_status(error: crate::enterprise::ExtensionError) -> Status {
    match error {
        crate::enterprise::ExtensionError::CredentialNotFound => {
            Status::unauthenticated("enterprise credential not found")
        }
        crate::enterprise::ExtensionError::Unauthenticated => {
            Status::unauthenticated("enterprise authentication failed")
        }
        crate::enterprise::ExtensionError::PermissionDenied => {
            Status::permission_denied("enterprise authorization denied")
        }
        crate::enterprise::ExtensionError::UnsupportedVersion => {
            Status::failed_precondition("unsupported enterprise identity contract version")
        }
        crate::enterprise::ExtensionError::Expired
        | crate::enterprise::ExtensionError::Revoked
        | crate::enterprise::ExtensionError::Replayed
        | crate::enterprise::ExtensionError::MembershipRevoked
        | crate::enterprise::ExtensionError::TenantSuspended
        | crate::enterprise::ExtensionError::InvalidState
        | crate::enterprise::ExtensionError::InvalidNonce
        | crate::enterprise::ExtensionError::InvalidRedirectUri
        | crate::enterprise::ExtensionError::InvalidPkce
        | crate::enterprise::ExtensionError::IssuerMismatch
        | crate::enterprise::ExtensionError::ResourceMismatch => {
            Status::permission_denied("enterprise credential validation failed")
        }
        crate::enterprise::ExtensionError::Unavailable(message) => Status::unavailable(message),
    }
}
pub(super) fn validate_credential_principal(principal: &str) -> Result<String, Status> {
    let principal = principal.trim();
    if principal.is_empty()
        || !principal
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
    {
        return Err(Status::invalid_argument(
            "principal must match [a-zA-Z0-9._-]+",
        ));
    }
    Ok(principal.to_string())
}
pub(super) fn validate_new_credential_principal(principal: &str) -> Result<String, Status> {
    let principal = validate_credential_principal(principal)?;
    if matches!(principal.as_str(), "root" | "local" | "anonymous") {
        return Err(Status::invalid_argument(format!(
            "principal {principal:?} is reserved for control-plane authentication"
        )));
    }
    Ok(principal)
}
pub(super) fn validate_team_principal(principal: &str) -> Result<String, Status> {
    let principal = validate_new_credential_principal(principal)?;
    if principal == "chisei-gateway" {
        return Err(Status::invalid_argument(
            "principal \"chisei-gateway\" is reserved for gateway authentication",
        ));
    }
    Ok(principal)
}
pub(super) fn new_credential_token() -> String {
    format!(
        "sekai_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}
pub(super) fn to_proto_credential(
    credential: crate::db::sekai::PrincipalCredential,
) -> CredentialRecord {
    CredentialRecord {
        id: credential.id,
        principal: credential.principal,
        status: credential.status,
        created: credential.created,
        rotated_at: credential.rotated_at,
        revoked_at: credential.revoked_at,
        tenant_id: String::new(),
    }
}
