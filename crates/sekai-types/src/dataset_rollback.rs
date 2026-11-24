//! Dataset rollback proposals (#3186).
//!
//! A rollback of a dataset to an earlier version can be proposed and then
//! decided by a different principal of the same tenant, in the shape of a
//! branch merge proposal (ADR 0119). The proposal pins the dataset's current
//! version as its base. An approval writes exactly one restored version and
//! the decision in one transaction; a denial writes the decision only. A
//! decision is final, and deciding it the same way again replays it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROPOSAL_NOT_FOUND: &str = "dataset rollback proposal not found";
pub const PROPOSAL_DECIDED: &str = "dataset rollback proposal is already decided the other way";
pub const PROPOSAL_SELF_DECIDE: &str =
    "a dataset rollback proposal is decided by another principal";
pub const PROPOSAL_STALE_BASE: &str =
    "the dataset has a newer version than the proposal's base version; propose again";
pub const PROPOSAL_SOURCE_PURGED: &str = "the proposal's restore source version is past retention";

pub const STATUS_OPEN: &str = "open";
pub const STATUS_APPROVED: &str = "approved";
pub const STATUS_DENIED: &str = "denied";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetRollbackProposal {
    pub id: String,
    pub dataset_id: String,
    pub restore_from_version_id: String,
    /// The dataset's newest version when proposed; an approval needs it to
    /// still be newest.
    pub base_version_id: String,
    pub proposer: String,
    pub tenant: String,
    pub reason: String,
    pub status: String,
    /// Empty while open.
    pub decided_by: String,
    pub decision_reason: String,
    /// The version an approval wrote; empty otherwise.
    pub restored_version_id: String,
    pub receipt_id: String,
    pub created_at_ms: i64,
    pub decided_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct ProposeDatasetRollback {
    pub dataset_id: String,
    pub restore_from_version_id: String,
    pub reason: String,
    pub actor: String,
    pub tenant: String,
}

#[derive(Debug, Clone)]
pub struct DecideDatasetRollback {
    pub dataset_id: String,
    pub proposal_id: String,
    pub approve: bool,
    pub reason: String,
    pub actor: String,
    pub tenant: String,
}

/// What a decision does to `proposal`: `Ok(true)` replays a decision already
/// made the same way, `Ok(false)` decides an open proposal. Another tenant's
/// proposal reads as missing, replay included; the proposer never decides.
pub fn check_decidable(
    proposal: &DatasetRollbackProposal,
    request: &DecideDatasetRollback,
) -> Result<bool, &'static str> {
    if proposal.tenant != request.tenant {
        return Err(PROPOSAL_NOT_FOUND);
    }
    if proposal.status != STATUS_OPEN {
        let same = proposal.status == decided_status(request.approve);
        return if same {
            Ok(true)
        } else {
            Err(PROPOSAL_DECIDED)
        };
    }
    if proposal.proposer == request.actor {
        return Err(PROPOSAL_SELF_DECIDE);
    }
    Ok(false)
}

pub fn decided_status(approve: bool) -> &'static str {
    if approve {
        STATUS_APPROVED
    } else {
        STATUS_DENIED
    }
}

/// The reason the restored version records: the proposal's, else a pointer
/// to the proposal.
pub fn restored_version_reason(proposal: &DatasetRollbackProposal) -> String {
    if proposal.reason.trim().is_empty() {
        format!("rollback-proposal:{}", proposal.id)
    } else {
        proposal.reason.clone()
    }
}

/// The receipt id of an approved proposal, over what it pinned and wrote.
pub fn receipt_id(proposal: &DatasetRollbackProposal, restored_version_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.dataset-rollback\n");
    for part in [
        proposal.dataset_id.as_str(),
        &proposal.id,
        &proposal.restore_from_version_id,
        &proposal.base_version_id,
        restored_version_id,
    ] {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(status: &str) -> DatasetRollbackProposal {
        DatasetRollbackProposal {
            id: "p".into(),
            dataset_id: "d".into(),
            restore_from_version_id: "v1".into(),
            base_version_id: "v2".into(),
            proposer: "alice".into(),
            tenant: "t".into(),
            reason: String::new(),
            status: status.into(),
            decided_by: String::new(),
            decision_reason: String::new(),
            restored_version_id: String::new(),
            receipt_id: String::new(),
            created_at_ms: 1,
            decided_at_ms: 0,
        }
    }

    fn request(actor: &str, tenant: &str, approve: bool) -> DecideDatasetRollback {
        DecideDatasetRollback {
            dataset_id: "d".into(),
            proposal_id: "p".into(),
            approve,
            reason: String::new(),
            actor: actor.into(),
            tenant: tenant.into(),
        }
    }

    #[test]
    fn another_principal_of_the_tenant_decides_once() {
        let open = proposal(STATUS_OPEN);
        assert_eq!(
            check_decidable(&open, &request("bob", "t", true)),
            Ok(false)
        );
        assert_eq!(
            check_decidable(&open, &request("alice", "t", true)),
            Err(PROPOSAL_SELF_DECIDE)
        );
        assert_eq!(
            check_decidable(&open, &request("bob", "other", true)),
            Err(PROPOSAL_NOT_FOUND)
        );
        let approved = proposal(STATUS_APPROVED);
        assert_eq!(
            check_decidable(&approved, &request("bob", "t", true)),
            Ok(true)
        );
        assert_eq!(
            check_decidable(&approved, &request("bob", "t", false)),
            Err(PROPOSAL_DECIDED)
        );
        assert_eq!(
            check_decidable(&proposal(STATUS_DENIED), &request("carol", "t", false)),
            Ok(true)
        );
    }
}
