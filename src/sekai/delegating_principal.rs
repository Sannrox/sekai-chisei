//! Apply-time re-validation of the delegating principal (`act`).
//!
//! Claim-time re-validation waits on the runtime-claim client. This module
//! loads live credential, membership, and grant facts and applies the identity
//! contract rule.

use crate::db::runtime_db::RuntimeDb;
use crate::enterprise::{
    DelegatingPrincipalState, DelegatorApplyRefusal, ExtensionError, NamespaceAction,
    revalidate_delegating_principal,
};
use crate::sekai::namespace_access::{
    principal_can_access_namespace, principal_can_write_namespace,
};
use sekai_provider::receipt::ReceiptEventKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DelegatorApplyError {
    Refused(DelegatorApplyRefusal),
    Internal(String),
}

pub(crate) fn current_delegating_principal_state(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    needed: NamespaceAction,
) -> Result<DelegatingPrincipalState, String> {
    if let Some(extension) = db.enterprise_extension() {
        return match extension.authorize_delegating_principal(principal, namespace, needed) {
            Ok(()) => Ok(DelegatingPrincipalState {
                enabled: true,
                tenant_member: true,
                holds_needed_grant: true,
            }),
            Err(ExtensionError::Revoked) | Err(ExtensionError::TenantSuspended) => {
                Ok(DelegatingPrincipalState {
                    enabled: false,
                    tenant_member: false,
                    holds_needed_grant: false,
                })
            }
            Err(ExtensionError::MembershipRevoked) => Ok(DelegatingPrincipalState {
                enabled: true,
                tenant_member: false,
                holds_needed_grant: false,
            }),
            Err(ExtensionError::PermissionDenied) => Ok(DelegatingPrincipalState {
                enabled: true,
                tenant_member: true,
                holds_needed_grant: false,
            }),
            Err(error) => Err(format!("{error:?}")),
        };
    }
    // Community apply uses the same live facts as namespace access: principal
    // credential status, namespace membership, and write grants.
    let credentials = db.list_credentials(Some(principal), None)?;
    let enabled = credentials.is_empty()
        || credentials
            .iter()
            .any(|credential| credential.status == "active");
    let tenant_member = principal_can_access_namespace(db, principal, namespace)?;
    let holds_needed_grant = match needed {
        NamespaceAction::Read => tenant_member,
        NamespaceAction::Write => principal_can_write_namespace(db, principal, namespace)?,
    };
    Ok(DelegatingPrincipalState {
        enabled,
        tenant_member,
        holds_needed_grant,
    })
}

pub(crate) fn revalidate_delegator_at_apply(
    db: &RuntimeDb,
    act: Option<&str>,
    namespace: &str,
) -> Result<(), DelegatorApplyError> {
    let Some(principal) = act.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let state =
        current_delegating_principal_state(db, principal, namespace, NamespaceAction::Write)
            .map_err(DelegatorApplyError::Internal)?;
    revalidate_delegating_principal(Some(principal), state).map_err(DelegatorApplyError::Refused)
}

/// Load the delegating actor retained on the planning receipt.
pub(crate) fn planning_act_from_receipt(
    db: &RuntimeDb,
    operation_id: &str,
) -> Result<Option<String>, String> {
    let Some(receipt) = db.get_operation_receipt(operation_id)? else {
        return Ok(None);
    };
    Ok(receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .and_then(|event| event.attributes.get("act"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string))
}

pub(crate) fn revalidate_planning_delegator_at_apply(
    db: &RuntimeDb,
    plan_id: &str,
    namespace: &str,
) -> Result<(), DelegatorApplyError> {
    let act = planning_act_from_receipt(db, plan_id).map_err(DelegatorApplyError::Internal)?;
    revalidate_delegator_at_apply(db, act.as_deref(), namespace)
}
