//! `GetAgentAutonomy` and `SetAgentAutonomy` (#3086): read and change whether
//! an agent's submits of one Action type are proposed for review or applied.
//! Both run the same core calls as `sekaictl admin autonomy`
//! (`agent_autonomy::offer`, `grant_auto_apply`, `revoke_auto_apply`), so the
//! eligibility threshold and the Decision receipts stay the only authority.
//! The CLI's store-level trust is not carried over: reading needs namespace
//! read and changing needs namespace admin. A caller who cannot read the
//! namespace gets `NOT_FOUND`, so the RPC does not reveal it.

use super::*;
use crate::sekai::agent_autonomy::{
    self, AutonomyOffer, AutonomyThreshold, GrantAutoApplyRequest, REASON_ADMIN, STATUS_LIVE_GRANT,
};

const MODE_PROPOSE: &str = "propose";
const MODE_APPLY: &str = "apply";

impl SekaiServiceImpl {
    pub(super) async fn get_agent_autonomy_rpc(
        &self,
        req: Request<GetAgentAutonomyRequest>,
    ) -> Result<Response<GetAgentAutonomyResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let request = req.into_inner();
        let db = self.db.runtime();
        require_subject(&request.namespace, &request.principal, &request.type_id)?;
        require_namespace_read(db, tenant_context.as_ref(), &principals, &request.namespace)?;
        let autonomy = read(db, &request.namespace, &request.principal, &request.type_id)?;
        Ok(Response::new(GetAgentAutonomyResponse {
            autonomy: Some(autonomy),
        }))
    }

    pub(super) async fn set_agent_autonomy_rpc(
        &self,
        req: Request<SetAgentAutonomyRequest>,
    ) -> Result<Response<SetAgentAutonomyResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let request = req.into_inner();
        let db = self.db.runtime();
        require_subject(&request.namespace, &request.principal, &request.type_id)?;
        require_namespace_read(db, tenant_context.as_ref(), &principals, &request.namespace)?;
        enforce_namespace_tenant_context(db, tenant_context.as_ref(), &request.namespace, true)?;
        let actor = require_namespace_admin(db, &principals, &request.namespace)?;
        let now_ms = now_millis();
        match request.mode.as_str() {
            MODE_APPLY => {
                if request.envelope_id.trim().is_empty() {
                    return Err(Status::invalid_argument("envelope_id required for apply"));
                }
                // Refuse an unearned grant with the numbers it was measured on.
                let current = read(db, &request.namespace, &request.principal, &request.type_id)?;
                if current.mode != MODE_APPLY && !current.eligible {
                    return Err(Status::failed_precondition(format!(
                        "agent has not earned auto-apply for this Action type: \
                         {} reviews, {} approved unchanged, {} incidents",
                        current.reviews, current.approved_unchanged, current.incidents
                    )));
                }
                agent_autonomy::grant_auto_apply(
                    db,
                    GrantAutoApplyRequest {
                        actor: &actor,
                        namespace: &request.namespace,
                        principal: &request.principal,
                        type_id: &request.type_id,
                        envelope_id: &request.envelope_id,
                        now_ms,
                        threshold: AutonomyThreshold::production(),
                    },
                )
                .map_err(grant_status)?;
            }
            MODE_PROPOSE => {
                let reason = if request.reason.trim().is_empty() {
                    REASON_ADMIN
                } else {
                    request.reason.as_str()
                };
                agent_autonomy::revoke_auto_apply(
                    db,
                    &actor,
                    &request.namespace,
                    &request.principal,
                    &request.type_id,
                    reason,
                    now_ms,
                )
                .map_err(map_runtime_store_error)?;
            }
            _ => return Err(Status::invalid_argument("mode must be propose or apply")),
        }
        let autonomy = read(db, &request.namespace, &request.principal, &request.type_id)?;
        Ok(Response::new(SetAgentAutonomyResponse {
            autonomy: Some(autonomy),
        }))
    }
}

fn require_subject(namespace: &str, principal: &str, type_id: &str) -> Result<(), Status> {
    for (field, value) in [
        ("namespace", namespace),
        ("principal", principal),
        ("type_id", type_id),
    ] {
        if value.trim().is_empty() || value.trim() != value {
            return Err(Status::invalid_argument(format!(
                "{field} must be a canonical non-empty identifier"
            )));
        }
    }
    Ok(())
}

/// Any refusal to read the namespace answers `NOT_FOUND`.
fn require_namespace_read(
    db: &RuntimeDb,
    tenant_context: Option<&RequestEnterpriseContext>,
    principals: &[String],
    namespace: &str,
) -> Result<(), Status> {
    require_authenticated(principals)?;
    enforce_namespace_tenant_context(db, tenant_context, namespace, false)
        .and_then(|()| check_team_namespace(db, principals, namespace, false))
        .map_err(|status| match status.code() {
            tonic::Code::PermissionDenied => Status::not_found("agent autonomy not found"),
            _ => status,
        })
}

/// Root and the local operator pass; anyone else needs the admin role on
/// `namespace`. Returns the acting principal recorded on the receipt.
fn require_namespace_admin(
    db: &RuntimeDb,
    principals: &[String],
    namespace: &str,
) -> Result<String, Status> {
    let privileged = principals
        .iter()
        .any(|principal| matches!(principal.as_str(), "root" | "local"));
    let admin = privileged
        || team_namespace_memberships(db, principals)?
            .iter()
            .any(|(member_namespace, role)| {
                member_namespace == namespace && matches!(role, security::Role::Admin)
            });
    if !admin {
        return Err(Status::permission_denied("namespace admin required"));
    }
    principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))
}

fn read(
    db: &RuntimeDb,
    namespace: &str,
    principal: &str,
    type_id: &str,
) -> Result<AgentAutonomy, Status> {
    let offer = agent_autonomy::offer(
        db,
        namespace,
        principal,
        type_id,
        AutonomyThreshold::production(),
    )
    .map_err(map_runtime_store_error)?;
    let envelope_id = if offer.granted {
        db.get_agent_autonomy(namespace, principal, type_id)
            .map_err(map_runtime_store_error)?
            .filter(|grant| grant.status == STATUS_LIVE_GRANT)
            .map(|grant| grant.envelope_id)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let AutonomyOffer {
        namespace,
        principal,
        type_id,
        reviews,
        approved_unchanged,
        incidents,
        eligible,
        granted,
    } = offer;
    Ok(AgentAutonomy {
        namespace,
        principal,
        type_id,
        mode: if granted { MODE_APPLY } else { MODE_PROPOSE }.into(),
        envelope_id,
        reviews,
        approved_unchanged,
        incidents,
        eligible,
    })
}

/// A grant the core refuses is a precondition the caller can change (an
/// envelope that is not live, a principal that is not an agent, another live
/// grant); PostgreSQL reports grants unavailable.
fn grant_status(error: String) -> Status {
    match map_runtime_store_error(error) {
        status if status.code() == tonic::Code::Unavailable => status,
        status => Status::failed_precondition(status.message()),
    }
}
