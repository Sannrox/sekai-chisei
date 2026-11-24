//! Experimental dataset rollback proposal RPCs (#3186): ProposeDatasetRollback,
//! DecideDatasetRollback, GetDatasetRollbackProposal and
//! ListDatasetRollbackProposals.
//!
//! Proposing and deciding need the access `RollbackDataset` needs: write
//! access to the dataset and readable columns. Reading needs read access. A
//! proposal is decided by another principal of the same tenant, as a branch
//! merge proposal is (ADR 0119), and `ListPendingDecisions` lists open ones
//! through [`may_decide_dataset_rollback`]. `RollbackDataset` is unchanged.

use super::rpc_data::{authorize_dataset_rollback, context_tenant};
use super::*;
use crate::db::OlderThan;
use crate::sekai::dataset_rollback::{
    self as rollback, DecideDatasetRollback, ProposeDatasetRollback,
};

const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 500;

/// The caller of a rollback proposal RPC on one dataset, after its access
/// check.
struct RollbackCaller {
    actor: String,
    tenant: String,
}

fn rollback_caller<T: 'static>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    dataset_id: &str,
    write: bool,
) -> Result<RollbackCaller, Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let context = request_tenant_context(service.db.runtime(), req)?;
    let dataset = service
        .db
        .runtime()
        .get_dataset(dataset_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("dataset not found"))?;
    authorize_dataset_rollback(service, &principals, context.as_ref(), &dataset, write)?;
    let actor = principals
        .first()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("principal required"))?;
    Ok(RollbackCaller {
        actor,
        tenant: context_tenant(context.as_ref()),
    })
}

fn rollback_status(error: String) -> Status {
    match error.as_str() {
        rollback::PROPOSAL_NOT_FOUND => Status::not_found(error),
        rollback::PROPOSAL_SELF_DECIDE => Status::permission_denied(error),
        rollback::PROPOSAL_DECIDED
        | rollback::PROPOSAL_STALE_BASE
        | rollback::PROPOSAL_SOURCE_PURGED => Status::failed_precondition(error),
        _ => map_dataset_version_error(error),
    }
}

async fn propose_dataset_rollback(
    service: &SekaiServiceImpl,
    req: Request<ProposeDatasetRollbackRequest>,
) -> Result<Response<ProposeDatasetRollbackResponse>, Status> {
    let caller = rollback_caller(service, &req, &req.get_ref().dataset_id, true)?;
    let inner = req.into_inner();
    let proposal = service
        .db
        .runtime()
        .propose_dataset_rollback(&ProposeDatasetRollback {
            dataset_id: inner.dataset_id,
            restore_from_version_id: inner.restore_from_version_id,
            reason: inner.reason,
            actor: caller.actor,
            tenant: caller.tenant,
        })
        .map_err(rollback_status)?;
    Ok(Response::new(ProposeDatasetRollbackResponse {
        proposal: Some(to_proto(proposal)),
    }))
}

async fn decide_dataset_rollback(
    service: &SekaiServiceImpl,
    req: Request<DecideDatasetRollbackRequest>,
) -> Result<Response<DecideDatasetRollbackResponse>, Status> {
    let caller = rollback_caller(service, &req, &req.get_ref().dataset_id, true)?;
    let inner = req.into_inner();
    let proposal = service
        .db
        .runtime()
        .decide_dataset_rollback(&DecideDatasetRollback {
            dataset_id: inner.dataset_id,
            proposal_id: inner.proposal_id,
            approve: inner.approve,
            reason: inner.reason,
            actor: caller.actor,
            tenant: caller.tenant,
        })
        .map_err(rollback_status)?;
    Ok(Response::new(DecideDatasetRollbackResponse {
        proposal: Some(to_proto(proposal)),
    }))
}

async fn get_dataset_rollback_proposal(
    service: &SekaiServiceImpl,
    req: Request<GetDatasetRollbackProposalRequest>,
) -> Result<Response<GetDatasetRollbackProposalResponse>, Status> {
    let caller = rollback_caller(service, &req, &req.get_ref().dataset_id, false)?;
    let inner = req.into_inner();
    let proposal = service
        .db
        .runtime()
        .get_dataset_rollback_proposal(&inner.dataset_id, &inner.proposal_id)
        .map_err(rollback_status)?;
    // Another tenant's proposal reads as missing.
    if proposal.tenant != caller.tenant {
        return Err(Status::not_found(rollback::PROPOSAL_NOT_FOUND));
    }
    Ok(Response::new(GetDatasetRollbackProposalResponse {
        proposal: Some(to_proto(proposal)),
    }))
}

async fn list_dataset_rollback_proposals(
    service: &SekaiServiceImpl,
    req: Request<ListDatasetRollbackProposalsRequest>,
) -> Result<Response<ListDatasetRollbackProposalsResponse>, Status> {
    let caller = rollback_caller(service, &req, &req.get_ref().dataset_id, false)?;
    let inner = req.into_inner();
    let limit = match inner.limit {
        0 => DEFAULT_PAGE,
        limit => (limit as usize).min(MAX_PAGE),
    };
    let after = page_position(&inner.page_token)?;
    let before = after
        .as_ref()
        .map_or(OlderThan::START, |(at_ms, id)| OlderThan {
            at_ms: *at_ms,
            id,
        });
    let mut proposals = service
        .db
        .runtime()
        .list_dataset_rollback_proposals(&inner.dataset_id, &caller.tenant, limit + 1, before)
        .map_err(rollback_status)?;
    let next_page_token = if proposals.len() > limit {
        proposals.truncate(limit);
        proposals
            .last()
            .map(|last| format!("{}:{}", last.created_at_ms, last.id))
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(Response::new(ListDatasetRollbackProposalsResponse {
        proposals: proposals.into_iter().map(to_proto).collect(),
        next_page_token,
    }))
}

/// The `(created_at_ms, id)` a page token resumes after.
fn page_position(token: &str) -> Result<Option<(i64, String)>, Status> {
    if token.is_empty() {
        return Ok(None);
    }
    let invalid = || Status::invalid_argument("invalid page_token");
    let (at_ms, id) = token.split_once(':').ok_or_else(invalid)?;
    Ok(Some((
        at_ms.parse().map_err(|_| invalid())?,
        id.to_string(),
    )))
}

/// Whether `principals` may decide the open `proposal` of a dataset bound in
/// `namespace` through `DecideDatasetRollback`, by its checks before
/// freshness: the proposal is open, of the caller's tenant and not their
/// own, and the caller has the write access and readable columns the decide
/// needs. A refusal is `false`; a store failure is an error. Used by the
/// pending-decision listing.
pub(super) fn may_decide_dataset_rollback(
    service: &SekaiServiceImpl,
    principals: &[String],
    context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    proposal: &rollback::DatasetRollbackProposal,
) -> Result<bool, Status> {
    let Some(actor) = principals.first() else {
        return Ok(false);
    };
    let request = DecideDatasetRollback {
        dataset_id: proposal.dataset_id.clone(),
        proposal_id: proposal.id.clone(),
        approve: true,
        reason: String::new(),
        actor: actor.clone(),
        tenant: context_tenant(context),
    };
    if rollback::check_decidable(proposal, &request) != Ok(false) {
        return Ok(false);
    }
    let Some(dataset) = service
        .db
        .runtime()
        .get_dataset(&proposal.dataset_id)
        .map_err(Status::internal)?
    else {
        return Ok(false);
    };
    match authorize_dataset_rollback(service, principals, context, &dataset, true) {
        Ok(bound) => Ok(bound.as_deref() == Some(namespace)),
        Err(status)
            if matches!(
                status.code(),
                tonic::Code::Internal | tonic::Code::Unavailable
            ) =>
        {
            Err(status)
        }
        Err(_) => Ok(false),
    }
}

fn to_proto(proposal: rollback::DatasetRollbackProposal) -> DatasetRollbackProposal {
    DatasetRollbackProposal {
        id: proposal.id,
        dataset_id: proposal.dataset_id,
        restore_from_version_id: proposal.restore_from_version_id,
        base_version_id: proposal.base_version_id,
        proposer: proposal.proposer,
        reason: proposal.reason,
        status: proposal.status,
        decided_by: proposal.decided_by,
        restored_version_id: proposal.restored_version_id,
        receipt_id: proposal.receipt_id,
        created_at_ms: proposal.created_at_ms,
        decided_at_ms: proposal.decided_at_ms,
        decision_reason: proposal.decision_reason,
    }
}

/// Trait routes for the facade's `delegate_rpcs!` list.
impl SekaiServiceImpl {
    pub(super) async fn propose_dataset_rollback_rpc(
        &self,
        req: Request<ProposeDatasetRollbackRequest>,
    ) -> Result<Response<ProposeDatasetRollbackResponse>, Status> {
        propose_dataset_rollback(self, req).await
    }
    pub(super) async fn decide_dataset_rollback_rpc(
        &self,
        req: Request<DecideDatasetRollbackRequest>,
    ) -> Result<Response<DecideDatasetRollbackResponse>, Status> {
        decide_dataset_rollback(self, req).await
    }
    pub(super) async fn get_dataset_rollback_proposal_rpc(
        &self,
        req: Request<GetDatasetRollbackProposalRequest>,
    ) -> Result<Response<GetDatasetRollbackProposalResponse>, Status> {
        get_dataset_rollback_proposal(self, req).await
    }
    pub(super) async fn list_dataset_rollback_proposals_rpc(
        &self,
        req: Request<ListDatasetRollbackProposalsRequest>,
    ) -> Result<Response<ListDatasetRollbackProposalsResponse>, Status> {
        list_dataset_rollback_proposals(self, req).await
    }
}
