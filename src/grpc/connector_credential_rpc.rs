//! Platform-admin issue and revoke of plane-held connector credential
//! handles sealed to a runtime fleet key (ADR 0175).

use super::*;
use crate::sekai::connector_credential::{self, CredentialHandle, SealedSlot};
use crate::sekai::source::Source;

fn status(error: String) -> Status {
    if error.contains("not found") {
        Status::not_found(error)
    } else if error.contains("already") || error.contains("different") {
        Status::failed_precondition(error)
    } else if error.starts_with("invalid")
        || error.contains("must")
        || error.contains("required")
        || error.contains("duplicate")
        || error.contains("at most")
        || error.contains("share one")
    {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}

fn to_proto_key(record: connector_credential::FleetKeyRecord) -> RuntimeFleetKey {
    RuntimeFleetKey {
        key_id: record.key_id,
        public_key: record.public_key,
    }
}

fn to_proto_material(handle: CredentialHandle) -> CredentialHandleMaterial {
    CredentialHandleMaterial {
        name: handle.name,
        namespaces: handle.namespaces,
        destinations: handle.destinations,
        slots: handle
            .slots
            .into_iter()
            .map(|slot| SealedCredentialSlot {
                name: slot.name,
                fleet_key_id: slot.fleet_key_id,
                ciphertext: slot.ciphertext,
            })
            .collect(),
        revoked: handle.revoked,
    }
}

fn from_proto_slots(slots: Vec<SealedCredentialSlot>) -> Vec<SealedSlot> {
    slots
        .into_iter()
        .map(|slot| SealedSlot {
            name: slot.name,
            fleet_key_id: slot.fleet_key_id,
            ciphertext: slot.ciphertext,
        })
        .collect()
}

/// Plane material for a Source's credential_ref, including a tombstone.
pub(super) fn material_for_handle(
    db: &RuntimeDb,
    handle: &str,
) -> Result<Option<CredentialHandleMaterial>, Status> {
    if handle.trim().is_empty() {
        return Ok(None);
    }
    connector_credential::get_handle(db, handle)
        .map(|handle| handle.map(to_proto_material))
        .map_err(|_| Status::internal("credential handle store unavailable"))
}

pub(super) fn material_for_source(
    db: &RuntimeDb,
    source: &Source,
) -> Result<Option<CredentialHandleMaterial>, Status> {
    material_for_handle(db, &source.spec.credential_ref)
}

pub(super) fn material_for_source_id(
    db: &RuntimeDb,
    namespace: &str,
    source_id: &str,
) -> Result<Option<CredentialHandleMaterial>, Status> {
    let Some(source) = db
        .get_source(namespace, source_id)
        .map_err(|_| Status::internal("source store unavailable"))?
    else {
        return Ok(None);
    };
    material_for_source(db, &source)
}

impl SekaiServiceImpl {
    pub(super) async fn register_runtime_fleet_key_rpc(
        &self,
        req: Request<RegisterRuntimeFleetKeyRequest>,
    ) -> Result<Response<RegisterRuntimeFleetKeyResponse>, Status> {
        let principals = caller_principals(&req);
        require_credential_admin(&principals)?;
        let actor = principals
            .first()
            .cloned()
            .ok_or_else(|| Status::permission_denied("credential admin required"))?;
        let inner = req.into_inner();
        let record = connector_credential::register_fleet_key(
            self.db.runtime(),
            &inner.key_id,
            &inner.public_key,
            &actor,
            now_millis(),
        )
        .map_err(status)?;
        Ok(Response::new(RegisterRuntimeFleetKeyResponse {
            key: Some(to_proto_key(record)),
        }))
    }

    pub(super) async fn get_runtime_fleet_key_rpc(
        &self,
        req: Request<GetRuntimeFleetKeyRequest>,
    ) -> Result<Response<GetRuntimeFleetKeyResponse>, Status> {
        require_credential_admin(&caller_principals(&req))?;
        let inner = req.into_inner();
        let record = connector_credential::get_fleet_key(self.db.runtime(), &inner.key_id)
            .map_err(status)?
            .ok_or_else(|| Status::not_found("fleet key not found"))?;
        Ok(Response::new(GetRuntimeFleetKeyResponse {
            key: Some(to_proto_key(record)),
        }))
    }

    pub(super) async fn issue_credential_handle_rpc(
        &self,
        req: Request<IssueCredentialHandleRequest>,
    ) -> Result<Response<IssueCredentialHandleResponse>, Status> {
        let principals = caller_principals(&req);
        require_credential_admin(&principals)?;
        let actor = principals
            .first()
            .cloned()
            .ok_or_else(|| Status::permission_denied("credential admin required"))?;
        let inner = req.into_inner();
        let handle = connector_credential::issue_handle(
            self.db.runtime(),
            &inner.name,
            &inner.namespaces,
            &inner.destinations,
            &from_proto_slots(inner.slots),
            &actor,
            now_millis(),
        )
        .map_err(status)?;
        Ok(Response::new(IssueCredentialHandleResponse {
            name: handle.name,
            content_digest: handle.content_digest,
        }))
    }

    pub(super) async fn revoke_credential_handle_rpc(
        &self,
        req: Request<RevokeCredentialHandleRequest>,
    ) -> Result<Response<RevokeCredentialHandleResponse>, Status> {
        let principals = caller_principals(&req);
        require_credential_admin(&principals)?;
        let actor = principals
            .first()
            .cloned()
            .ok_or_else(|| Status::permission_denied("credential admin required"))?;
        let inner = req.into_inner();
        connector_credential::revoke_handle(self.db.runtime(), &inner.name, &actor, now_millis())
            .map_err(status)?;
        Ok(Response::new(RevokeCredentialHandleResponse {}))
    }
}
