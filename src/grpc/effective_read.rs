//! One read decision over a grant source (#2304).
//!
//! [`effective_object_read`] decides whether principals may read one object:
//! tenant collaboration, the team namespace membership gate, the object's
//! grants, the object policy and marking clearance, in that order. Single
//! object reads ([`require_visible_object_contents`]) call it with the stored
//! grants. `SimulateObjectPolicyChange` calls it with a [`GrantOverlay`], the
//! stored grants with candidate additions and removals, so a simulated grant
//! change answers what a real read gives once the change is made.

use super::*;
use crate::sekai::policy_decision::{CompiledObjectAccess, PolicyLayer, PolicyOutcome};
use crate::sekai::security::{Grant, Role, grant_live};

/// Where a read decision takes grants from.
#[derive(Clone, Copy)]
pub(super) enum ReadGrants<'a> {
    /// The stored grants (the service's grant cache for object ACLs).
    Stored,
    /// The stored grants with a candidate change applied.
    Overlay(&'a GrantOverlay),
}

impl ReadGrants<'_> {
    /// Grants on one object, expired ones included, as `list_grants` lists them.
    pub(super) fn on_object(self, db: &RuntimeDb, object_id: &str) -> Result<Vec<Grant>, Status> {
        let stored = db.list_grants(object_id).map_err(Status::internal)?;
        Ok(match self {
            Self::Stored => stored,
            Self::Overlay(overlay) => overlay.on_object(stored, object_id),
        })
    }

    /// Live namespace roles of one principal, as
    /// `list_namespace_roles_for_principal` lists them.
    pub(super) fn namespace_roles(
        self,
        db: &RuntimeDb,
        principal: &str,
    ) -> Result<Vec<(String, Role)>, Status> {
        let stored = db
            .list_namespace_roles_for_principal(principal)
            .map_err(Status::internal)?;
        Ok(match self {
            Self::Stored => stored,
            Self::Overlay(overlay) => overlay.namespace_roles(stored, principal),
        })
    }
}

/// Stored grants plus `added`, minus `dropped`. Nothing is written.
pub(super) struct GrantOverlay {
    added: Vec<Grant>,
    /// Stored grants the change takes away: the removals, and any stored
    /// grant an addition replaces on the same object and principal (grants
    /// are unique per object and principal).
    dropped: Vec<Grant>,
    /// Namespace name of each namespace boundary a changed grant is on.
    boundaries: HashMap<String, String>,
}

impl GrantOverlay {
    /// `added` grants carry their object, principal, role and expiry;
    /// `removed` are stored grants. Callers validate scope first.
    pub(super) fn new(
        db: &RuntimeDb,
        added: Vec<Grant>,
        removed: Vec<Grant>,
    ) -> Result<Self, Status> {
        let mut dropped = removed;
        for grant in &added {
            for stored in db.list_grants(&grant.object_id).map_err(Status::internal)? {
                if stored.principal == grant.principal
                    && !dropped.iter().any(|known| known.id == stored.id)
                {
                    dropped.push(stored);
                }
            }
        }
        let mut boundaries = HashMap::new();
        for grant in added.iter().chain(&dropped) {
            if boundaries.contains_key(&grant.object_id) {
                continue;
            }
            if let Some(object) = db.get_object(&grant.object_id).map_err(Status::internal)?
                && object.kind == "namespace"
            {
                // The name `list_namespace_roles_for_principal` reports.
                let name = object
                    .external_id
                    .strip_prefix("namespace:")
                    .unwrap_or(&object.external_id)
                    .to_string();
                boundaries.insert(grant.object_id.clone(), name);
            }
        }
        Ok(Self {
            added,
            dropped,
            boundaries,
        })
    }

    fn on_object(&self, mut stored: Vec<Grant>, object_id: &str) -> Vec<Grant> {
        stored.retain(|grant| !self.dropped.iter().any(|gone| gone.id == grant.id));
        stored.extend(
            self.added
                .iter()
                .filter(|grant| grant.object_id == object_id)
                .cloned(),
        );
        stored
    }

    fn namespace_roles(
        &self,
        mut stored: Vec<(String, Role)>,
        principal: &str,
    ) -> Vec<(String, Role)> {
        let on_boundary =
            |grant: &&Grant| grant.principal == principal && grant_live(grant.not_after_ms);
        for gone in self.dropped.iter().filter(on_boundary) {
            let Some(name) = self.boundaries.get(&gone.object_id) else {
                continue;
            };
            // Each stored row is one grant, so drop exactly one match.
            if let Some(index) = stored
                .iter()
                .position(|(namespace, role)| namespace == name && *role == gone.role)
            {
                stored.remove(index);
            }
        }
        for grant in self.added.iter().filter(on_boundary) {
            if let Some(name) = self.boundaries.get(&grant.object_id) {
                stored.push((name.clone(), grant.role.clone()));
            }
        }
        stored
    }
}

/// The check that refused a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ReadLayer {
    /// Reserved governance kind or tenant collaboration: reads as missing.
    Hidden,
    /// Team namespace membership.
    NamespaceMembership,
    /// The object's own grants.
    ObjectGrant,
    /// A layer of the object policy decision.
    Policy(PolicyLayer),
    /// Classification marking clearance.
    Marking,
}

impl ReadLayer {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::NamespaceMembership => "namespace_membership",
            Self::ObjectGrant => "object_grant",
            Self::Policy(layer) => layer.as_str(),
            Self::Marking => "marking",
        }
    }
}

/// Outcome of [`effective_object_read`].
pub(super) enum ReadDecision {
    Allowed {
        marking: markings::MarkingCheckResult,
        /// Projects the properties the reader sees; `None` only when the
        /// policy decision was never compiled.
        access: Option<Box<CompiledObjectAccess>>,
    },
    /// `status` is what a single-object read returns for this denial.
    Denied { layer: ReadLayer, status: Status },
}

/// Who reads, how, and under which policies.
pub(super) struct ReadRequest<'a> {
    pub(super) principals: &'a [String],
    pub(super) tenant_context: Option<&'a RequestEnterpriseContext>,
    pub(super) operation: crate::sekai::object_security::ObjectSecurityOperation,
    pub(super) purpose: Option<&'a crate::sekai::purpose_authorization::PurposePresentation>,
    pub(super) operation_id: &'a str,
    /// The active policy (`Fetch`) or a candidate one.
    pub(super) policy: PolicyCache<'a>,
}

/// Decide one read of `object` over `grants`. Denials come back as
/// [`ReadDecision::Denied`]; `Err` is an outage (store or policy unavailable).
/// A refused ACL check is audited for a delegated subject, as before.
pub(super) fn effective_object_read(
    db: &RuntimeDb,
    security: &SecurityChecker,
    grants: ReadGrants<'_>,
    object: &domain::Object,
    request: &ReadRequest<'_>,
) -> Result<ReadDecision, Status> {
    let denied = |layer, status| Ok(ReadDecision::Denied { layer, status });
    if is_reserved_governance_kind(&object.kind)
        || !collaboration_object_permitted(
            db,
            request.tenant_context,
            object,
            crate::enterprise::NamespaceAction::Read,
        )?
    {
        return denied(ReadLayer::Hidden, Status::not_found("not found"));
    }
    let write = !operation_reads(request.operation);
    if let Err(status) =
        check_team_namespace_in(db, grants, request.principals, &object.namespace, write)
    {
        return refusal(ReadLayer::NamespaceMembership, status);
    }
    if let Err(status) = check_object_acl_with_audit_in(
        db,
        security,
        grants,
        &object.id,
        request.principals,
        request.tenant_context,
        request.operation,
    ) {
        return refusal(ReadLayer::ObjectGrant, status);
    }
    let (decision, access) = decide_object_access_in(
        db,
        grants,
        object,
        request.principals,
        request.tenant_context,
        request.operation,
        request.purpose,
        request.policy,
    )
    .map_err(hide_read_root_as_missing)?;
    match (decision.outcome, decision.denied_by) {
        (PolicyOutcome::Allow, _) => {}
        // Marking denials stay on the marking check below so they remain
        // PermissionDenied rather than NotFound.
        (_, Some(PolicyLayer::Marking))
            if request
                .tenant_context
                .is_none_or(|context| context.act.is_none()) => {}
        (_, layer) => {
            return denied(
                ReadLayer::Policy(layer.unwrap_or(PolicyLayer::ObjectRow)),
                Status::not_found("not found"),
            );
        }
    }
    let marking =
        evaluate_object_marking_in(db, grants, object, request.principals, request.operation_id)?;
    if marking.decision == markings::MarkingDecision::Deny {
        // Generic denial: do not leak marking details to unauthorized callers.
        return denied(
            ReadLayer::Marking,
            Status::permission_denied("access denied"),
        );
    }
    Ok(ReadDecision::Allowed {
        marking,
        access: access.map(Box::new),
    })
}

/// A permission refusal is a denial; anything else is an outage.
fn refusal(layer: ReadLayer, status: Status) -> Result<ReadDecision, Status> {
    if status.code() == tonic::Code::PermissionDenied {
        Ok(ReadDecision::Denied { layer, status })
    } else {
        Err(status)
    }
}
