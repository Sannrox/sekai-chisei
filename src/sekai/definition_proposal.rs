//! Governed branch proposals as the atomic change-set publication contract.
//!
//! A proposal pins one published base digest and one branch-head candidate.
//! Approval is set-level and digest-bound. Merge rechecks live grants and
//! compare-and-swaps the namespace published head in the same transaction.
//! Named foreign digests and frozen evaluation-plan references confer no grant.

use serde::{Deserialize, Serialize};

use crate::sekai::definition_branch::{
    DefinitionRevision, DefinitionRevisionMember, MAX_DEFINITION_ID_BYTES, canonical_digest,
    validate_digest, validate_identifier, validate_namespace,
};

pub const PROPOSAL_CONTRACT_VERSION: &str = "sekai.definition-proposal/v1";
pub const PROPOSAL_STATUS_OPEN: &str = "open";
pub const PROPOSAL_STATUS_APPROVED: &str = "approved";
pub const PROPOSAL_STATUS_REJECTED: &str = "rejected";
pub const PROPOSAL_STATUS_MERGED: &str = "merged";
pub const MAX_PROPOSAL_REFS: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenEvalPlanRef {
    pub plan_id: String,
    pub plan_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalApproval {
    pub approved_by: String,
    pub approved_at_ms: i64,
    pub proposal_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalRejection {
    pub rejected_by: String,
    pub rejected_at_ms: i64,
    pub proposal_digest: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionProposal {
    pub contract_version: String,
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub base_digest: String,
    pub candidate_digest: String,
    pub proposal_digest: String,
    pub frozen_eval_plans: Vec<FrozenEvalPlanRef>,
    pub named_foreign_digests: Vec<String>,
    pub status: String,
    pub created_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub approval: Option<ProposalApproval>,
    pub rejection: Option<ProposalRejection>,
    pub merge_receipt_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateDefinitionProposal {
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub base_digest: String,
    pub candidate_digest: String,
    pub frozen_eval_plans: Vec<FrozenEvalPlanRef>,
    pub named_foreign_digests: Vec<String>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveDefinitionProposal {
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub expected_proposal_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectDefinitionProposal {
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub expected_proposal_digest: String,
    pub reason_code: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeDefinitionProposal {
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub expected_proposal_digest: String,
    pub expected_published_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionMergeResult {
    pub proposal: DefinitionProposal,
    pub previous_published_digest: String,
    pub published_digest: String,
    pub revision: DefinitionRevision,
    pub receipt_id: String,
}

impl FrozenEvalPlanRef {
    pub fn validate(&self) -> Result<(), String> {
        validate_identifier("plan_id", &self.plan_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("plan_digest", &self.plan_digest)
    }
}

impl CreateDefinitionProposal {
    pub fn validate(&self) -> Result<(), String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("branch_id", &self.branch_id, MAX_DEFINITION_ID_BYTES)?;
        validate_identifier("proposal_id", &self.proposal_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("base_digest", &self.base_digest)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        if self.base_digest == self.candidate_digest {
            return Err("definition_proposal_no_change: candidate must differ from base".into());
        }
        prepare_proposal_refs(&self.frozen_eval_plans, &self.named_foreign_digests)?;
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, String> {
        let (frozen_eval_plans, named_foreign_digests) =
            prepare_proposal_refs(&self.frozen_eval_plans, &self.named_foreign_digests)?;
        canonical_digest(
            "create_definition_proposal",
            &CreateProposalDigestInput {
                namespace: &self.namespace,
                branch_id: &self.branch_id,
                proposal_id: &self.proposal_id,
                base_digest: &self.base_digest,
                candidate_digest: &self.candidate_digest,
                frozen_eval_plans: &frozen_eval_plans,
                named_foreign_digests: &named_foreign_digests,
            },
        )
    }
}

impl ApproveDefinitionProposal {
    pub fn validate(&self) -> Result<(), String> {
        validate_lifecycle_request(
            &self.namespace,
            &self.branch_id,
            &self.proposal_id,
            &self.expected_proposal_digest,
            &self.idempotency_key,
        )
    }

    pub fn request_digest(&self) -> Result<String, String> {
        self.validate()?;
        canonical_digest("approve_definition_proposal", self)
    }
}

impl RejectDefinitionProposal {
    pub fn validate(&self) -> Result<(), String> {
        validate_lifecycle_request(
            &self.namespace,
            &self.branch_id,
            &self.proposal_id,
            &self.expected_proposal_digest,
            &self.idempotency_key,
        )?;
        validate_identifier("reason_code", &self.reason_code, MAX_DEFINITION_ID_BYTES)
    }

    pub fn request_digest(&self) -> Result<String, String> {
        self.validate()?;
        canonical_digest("reject_definition_proposal", self)
    }
}

impl MergeDefinitionProposal {
    pub fn validate(&self) -> Result<(), String> {
        validate_lifecycle_request(
            &self.namespace,
            &self.branch_id,
            &self.proposal_id,
            &self.expected_proposal_digest,
            &self.idempotency_key,
        )?;
        validate_digest("expected_published_digest", &self.expected_published_digest)
    }

    pub fn request_digest(&self) -> Result<String, String> {
        self.validate()?;
        canonical_digest("merge_definition_proposal", self)
    }
}

impl DefinitionProposal {
    pub fn verify(&self) -> Result<(), String> {
        if self.contract_version != PROPOSAL_CONTRACT_VERSION {
            return Err("definition proposal contract version is unsupported".into());
        }
        validate_namespace(&self.namespace)?;
        validate_identifier("branch_id", &self.branch_id, MAX_DEFINITION_ID_BYTES)?;
        validate_identifier("proposal_id", &self.proposal_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("base_digest", &self.base_digest)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("proposal_digest", &self.proposal_digest)?;
        validate_identifier("created_by", &self.created_by, MAX_DEFINITION_ID_BYTES)?;
        if self.created_at_ms <= 0 || self.updated_at_ms < self.created_at_ms {
            return Err("proposal timestamps must be positive and non-decreasing".into());
        }
        match self.status.as_str() {
            PROPOSAL_STATUS_OPEN
            | PROPOSAL_STATUS_APPROVED
            | PROPOSAL_STATUS_REJECTED
            | PROPOSAL_STATUS_MERGED => {}
            _ => return Err("definition proposal status is unsupported".into()),
        }
        let (frozen_eval_plans, named_foreign_digests) =
            prepare_proposal_refs(&self.frozen_eval_plans, &self.named_foreign_digests)?;
        if frozen_eval_plans != self.frozen_eval_plans
            || named_foreign_digests != self.named_foreign_digests
        {
            return Err("definition proposal references are not canonical".into());
        }
        let digest = proposal_content_digest(
            &self.namespace,
            &self.branch_id,
            &self.proposal_id,
            &self.base_digest,
            &self.candidate_digest,
            &frozen_eval_plans,
            &named_foreign_digests,
        )?;
        if digest != self.proposal_digest {
            return Err("definition proposal digest does not match canonical identity".into());
        }
        if self.base_digest == self.candidate_digest {
            return Err("definition_proposal_no_change: candidate must differ from base".into());
        }
        match (&self.status.as_str(), &self.approval, &self.rejection) {
            (s, None, None) if *s == PROPOSAL_STATUS_OPEN => {}
            (s, Some(approval), None)
                if *s == PROPOSAL_STATUS_APPROVED || *s == PROPOSAL_STATUS_MERGED =>
            {
                if approval.proposal_digest != self.proposal_digest {
                    return Err("proposal approval digest does not match proposal".into());
                }
                validate_identifier(
                    "approved_by",
                    &approval.approved_by,
                    MAX_DEFINITION_ID_BYTES,
                )?;
                if approval.approved_at_ms < self.created_at_ms {
                    return Err("proposal approval timestamp is invalid".into());
                }
            }
            (s, None, Some(rejection)) if *s == PROPOSAL_STATUS_REJECTED => {
                if rejection.proposal_digest != self.proposal_digest {
                    return Err("proposal rejection digest does not match proposal".into());
                }
                validate_identifier(
                    "rejected_by",
                    &rejection.rejected_by,
                    MAX_DEFINITION_ID_BYTES,
                )?;
                validate_identifier(
                    "reason_code",
                    &rejection.reason_code,
                    MAX_DEFINITION_ID_BYTES,
                )?;
                if rejection.rejected_at_ms < self.created_at_ms {
                    return Err("proposal rejection timestamp is invalid".into());
                }
            }
            _ => return Err("definition proposal lifecycle binding is invalid".into()),
        }
        if self.status == PROPOSAL_STATUS_MERGED {
            if self.merge_receipt_id.trim().is_empty() {
                return Err("merged proposal requires a receipt identity".into());
            }
        } else if !self.merge_receipt_id.is_empty() {
            return Err("unmerged proposal must not carry a merge receipt".into());
        }
        Ok(())
    }
}

pub fn prepare_proposal(
    request: &CreateDefinitionProposal,
    actor: &str,
    now_ms: i64,
) -> Result<DefinitionProposal, String> {
    request.validate()?;
    validate_identifier("created_by", actor, MAX_DEFINITION_ID_BYTES)?;
    if now_ms <= 0 {
        return Err("now_ms must be positive".into());
    }
    let (frozen_eval_plans, named_foreign_digests) =
        prepare_proposal_refs(&request.frozen_eval_plans, &request.named_foreign_digests)?;
    let proposal_digest = proposal_content_digest(
        &request.namespace,
        &request.branch_id,
        &request.proposal_id,
        &request.base_digest,
        &request.candidate_digest,
        &frozen_eval_plans,
        &named_foreign_digests,
    )?;
    let proposal = DefinitionProposal {
        contract_version: PROPOSAL_CONTRACT_VERSION.into(),
        namespace: request.namespace.clone(),
        branch_id: request.branch_id.clone(),
        proposal_id: request.proposal_id.clone(),
        base_digest: request.base_digest.clone(),
        candidate_digest: request.candidate_digest.clone(),
        proposal_digest,
        frozen_eval_plans,
        named_foreign_digests,
        status: PROPOSAL_STATUS_OPEN.into(),
        created_by: actor.into(),
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
        approval: None,
        rejection: None,
        merge_receipt_id: String::new(),
    };
    proposal.verify()?;
    Ok(proposal)
}

pub fn apply_proposal_approval(
    proposal: &DefinitionProposal,
    actor: &str,
    expected_proposal_digest: &str,
    now_ms: i64,
) -> Result<DefinitionProposal, String> {
    proposal.verify()?;
    require_expected_digest(proposal, expected_proposal_digest)?;
    if proposal.status == PROPOSAL_STATUS_REJECTED {
        return Err("definition_proposal_rejected: rejected proposals cannot be approved".into());
    }
    if proposal.status == PROPOSAL_STATUS_MERGED {
        return Err("definition_proposal_not_open: merged proposals cannot be approved".into());
    }
    validate_identifier("approved_by", actor, MAX_DEFINITION_ID_BYTES)?;
    if now_ms < proposal.created_at_ms {
        return Err("proposal approval timestamp is invalid".into());
    }
    if proposal.status == PROPOSAL_STATUS_APPROVED {
        let approval = proposal
            .approval
            .as_ref()
            .ok_or_else(|| "definition proposal lifecycle binding is invalid".to_string())?;
        if approval.approved_by == actor && approval.proposal_digest == proposal.proposal_digest {
            return Ok(proposal.clone());
        }
        return Err("definition_proposal_not_open: proposal is already approved".into());
    }
    let mut approved = proposal.clone();
    approved.status = PROPOSAL_STATUS_APPROVED.into();
    approved.updated_at_ms = now_ms;
    approved.approval = Some(ProposalApproval {
        approved_by: actor.into(),
        approved_at_ms: now_ms,
        proposal_digest: proposal.proposal_digest.clone(),
    });
    approved.verify()?;
    Ok(approved)
}

pub fn apply_proposal_rejection(
    proposal: &DefinitionProposal,
    actor: &str,
    expected_proposal_digest: &str,
    reason_code: &str,
    now_ms: i64,
) -> Result<DefinitionProposal, String> {
    proposal.verify()?;
    require_expected_digest(proposal, expected_proposal_digest)?;
    if proposal.status == PROPOSAL_STATUS_MERGED {
        return Err("definition_proposal_not_open: merged proposals cannot be rejected".into());
    }
    validate_identifier("rejected_by", actor, MAX_DEFINITION_ID_BYTES)?;
    validate_identifier("reason_code", reason_code, MAX_DEFINITION_ID_BYTES)?;
    if now_ms < proposal.created_at_ms {
        return Err("proposal rejection timestamp is invalid".into());
    }
    if proposal.status == PROPOSAL_STATUS_REJECTED {
        let rejection = proposal
            .rejection
            .as_ref()
            .ok_or_else(|| "definition proposal lifecycle binding is invalid".to_string())?;
        if rejection.rejected_by == actor
            && rejection.reason_code == reason_code
            && rejection.proposal_digest == proposal.proposal_digest
        {
            return Ok(proposal.clone());
        }
        return Err("definition_proposal_rejected: proposal is already rejected".into());
    }
    let mut rejected = proposal.clone();
    rejected.status = PROPOSAL_STATUS_REJECTED.into();
    rejected.updated_at_ms = now_ms;
    rejected.approval = None;
    rejected.rejection = Some(ProposalRejection {
        rejected_by: actor.into(),
        rejected_at_ms: now_ms,
        proposal_digest: proposal.proposal_digest.clone(),
        reason_code: reason_code.into(),
    });
    rejected.verify()?;
    Ok(rejected)
}

pub fn require_mergeable_proposal(
    proposal: &DefinitionProposal,
    expected_proposal_digest: &str,
) -> Result<(), String> {
    proposal.verify()?;
    require_expected_digest(proposal, expected_proposal_digest)?;
    if proposal.status == PROPOSAL_STATUS_REJECTED {
        return Err("definition_proposal_rejected: rejected proposals cannot merge".into());
    }
    if proposal.status == PROPOSAL_STATUS_MERGED {
        return Err("definition_proposal_not_open: proposal is already merged".into());
    }
    if proposal.status != PROPOSAL_STATUS_APPROVED || proposal.approval.is_none() {
        return Err(
            "definition_proposal_missing_approval: set-level approval is required before merge"
                .into(),
        );
    }
    Ok(())
}

pub fn mark_proposal_merged(
    proposal: &DefinitionProposal,
    receipt_id: &str,
    now_ms: i64,
) -> Result<DefinitionProposal, String> {
    require_mergeable_proposal(proposal, &proposal.proposal_digest)?;
    if receipt_id.trim().is_empty() || receipt_id.trim() != receipt_id {
        return Err("canonical merge receipt identity required".into());
    }
    let mut merged = proposal.clone();
    merged.status = PROPOSAL_STATUS_MERGED.into();
    merged.updated_at_ms = now_ms;
    merged.merge_receipt_id = receipt_id.into();
    merged.verify()?;
    Ok(merged)
}

pub fn changed_members<'a>(
    base: &'a DefinitionRevision,
    candidate: &'a DefinitionRevision,
) -> Vec<&'a DefinitionRevisionMember> {
    let base_members = base
        .members
        .iter()
        .map(|member| {
            (
                (member.member_kind.as_str(), member.member_id.as_str()),
                member,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut changed = Vec::new();
    for member in &candidate.members {
        match base_members.get(&(member.member_kind.as_str(), member.member_id.as_str())) {
            Some(parent) if parent.member_digest == member.member_digest => {}
            _ => changed.push(member),
        }
    }
    for (key, member) in base_members {
        if !candidate
            .members
            .iter()
            .any(|item| item.member_kind == key.0 && item.member_id == key.1)
        {
            changed.push(member);
        }
    }
    changed
}

pub fn candidate_descends_from_base(
    candidate: &DefinitionRevision,
    base_digest: &str,
    mut load_parent: impl FnMut(&str) -> Result<Option<DefinitionRevision>, String>,
) -> Result<(), String> {
    if candidate.revision_digest == base_digest {
        return Err("definition_proposal_no_change: candidate must differ from base".into());
    }
    let mut cursor = candidate.parent_revision_digest.clone();
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(candidate.revision_digest.clone());
    while !cursor.is_empty() {
        if !seen.insert(cursor.clone()) {
            return Err(
                "definition_proposal_incompatible_candidate: revision parent chain is cyclic"
                    .into(),
            );
        }
        if cursor == base_digest {
            return Ok(());
        }
        let parent = load_parent(&cursor)?.ok_or_else(|| {
            "definition_revision_not_found: candidate parent chain is unavailable".to_string()
        })?;
        cursor = parent.parent_revision_digest;
        if seen.len() > MAX_PROPOSAL_REFS {
            return Err(
                "definition_proposal_incompatible_candidate: candidate parent chain is too deep"
                    .into(),
            );
        }
    }
    Err(
        "definition_proposal_incompatible_candidate: candidate does not descend from the published base"
            .into(),
    )
}

pub fn named_foreign_digests_confer_no_grant(
    proposal: &DefinitionProposal,
    candidate: &DefinitionRevision,
) -> Result<(), String> {
    let member_digests = candidate
        .members
        .iter()
        .map(|member| member.member_digest.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for digest in &proposal.named_foreign_digests {
        if member_digests.contains(digest.as_str()) {
            return Err(
                "definition_proposal_foreign_authority: named foreign digest is not a member grant"
                    .into(),
            );
        }
    }
    for plan in &proposal.frozen_eval_plans {
        if member_digests.contains(plan.plan_digest.as_str()) {
            return Err(
                "definition_proposal_foreign_authority: frozen evaluation digest is not a member grant"
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_lifecycle_request(
    namespace: &str,
    branch_id: &str,
    proposal_id: &str,
    expected_proposal_digest: &str,
    idempotency_key: &str,
) -> Result<(), String> {
    validate_namespace(namespace)?;
    validate_identifier("branch_id", branch_id, MAX_DEFINITION_ID_BYTES)?;
    validate_identifier("proposal_id", proposal_id, MAX_DEFINITION_ID_BYTES)?;
    validate_digest("expected_proposal_digest", expected_proposal_digest)?;
    validate_identifier("idempotency_key", idempotency_key, MAX_DEFINITION_ID_BYTES)
}

fn require_expected_digest(
    proposal: &DefinitionProposal,
    expected_proposal_digest: &str,
) -> Result<(), String> {
    if proposal.proposal_digest != expected_proposal_digest {
        return Err(
            "definition_proposal_changed_digest: expected proposal digest is no longer current"
                .into(),
        );
    }
    Ok(())
}

fn prepare_proposal_refs(
    frozen_eval_plans: &[FrozenEvalPlanRef],
    named_foreign_digests: &[String],
) -> Result<(Vec<FrozenEvalPlanRef>, Vec<String>), String> {
    if frozen_eval_plans.len() + named_foreign_digests.len() > MAX_PROPOSAL_REFS {
        return Err("definition proposal exceeds the supported reference count".into());
    }
    let mut plans = frozen_eval_plans.to_vec();
    let mut seen_plans = std::collections::BTreeSet::new();
    for plan in &plans {
        plan.validate()?;
        if !seen_plans.insert((plan.plan_id.clone(), plan.plan_digest.clone())) {
            return Err("definition proposal contains a duplicate frozen evaluation plan".into());
        }
    }
    plans.sort_by(|left, right| {
        (&left.plan_id, &left.plan_digest).cmp(&(&right.plan_id, &right.plan_digest))
    });
    let mut foreign = named_foreign_digests.to_vec();
    let mut seen_foreign = std::collections::BTreeSet::new();
    for digest in &foreign {
        validate_digest("named_foreign_digest", digest)?;
        if !seen_foreign.insert(digest.clone()) {
            return Err("definition proposal contains a duplicate named foreign digest".into());
        }
    }
    foreign.sort();
    Ok((plans, foreign))
}

fn proposal_content_digest(
    namespace: &str,
    branch_id: &str,
    proposal_id: &str,
    base_digest: &str,
    candidate_digest: &str,
    frozen_eval_plans: &[FrozenEvalPlanRef],
    named_foreign_digests: &[String],
) -> Result<String, String> {
    canonical_digest(
        "definition_proposal",
        &CreateProposalDigestInput {
            namespace,
            branch_id,
            proposal_id,
            base_digest,
            candidate_digest,
            frozen_eval_plans,
            named_foreign_digests,
        },
    )
}

#[derive(Serialize)]
struct CreateProposalDigestInput<'a> {
    namespace: &'a str,
    branch_id: &'a str,
    proposal_id: &'a str,
    base_digest: &'a str,
    candidate_digest: &'a str,
    frozen_eval_plans: &'a [FrozenEvalPlanRef],
    named_foreign_digests: &'a [String],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::{DefinitionRevisionMember, prepare_revision};

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn request() -> CreateDefinitionProposal {
        CreateDefinitionProposal {
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            proposal_id: "cs-1".into(),
            base_digest: digest('a'),
            candidate_digest: digest('b'),
            frozen_eval_plans: vec![FrozenEvalPlanRef {
                plan_id: "gate".into(),
                plan_digest: digest('e'),
            }],
            named_foreign_digests: vec![digest('f')],
            idempotency_key: "propose-1".into(),
        }
    }

    #[test]
    fn proposal_digest_is_order_independent() {
        let first = prepare_proposal(&request(), "author", 1).unwrap();
        let mut reordered = request();
        reordered.frozen_eval_plans.reverse();
        assert_eq!(
            prepare_proposal(&reordered, "author", 2)
                .unwrap()
                .proposal_digest,
            first.proposal_digest
        );
        let mut extra = request();
        extra.named_foreign_digests = vec![digest('f'), digest('c')];
        assert_ne!(
            prepare_proposal(&extra, "author", 3)
                .unwrap()
                .proposal_digest,
            first.proposal_digest
        );
    }

    #[test]
    fn merge_requires_matching_approval() {
        let proposal = prepare_proposal(&request(), "author", 1).unwrap();
        assert!(
            require_mergeable_proposal(&proposal, &proposal.proposal_digest)
                .unwrap_err()
                .contains("missing_approval")
        );
        let approved =
            apply_proposal_approval(&proposal, "reviewer", &proposal.proposal_digest, 2).unwrap();
        require_mergeable_proposal(&approved, &approved.proposal_digest).unwrap();
        let rejected =
            apply_proposal_rejection(&proposal, "reviewer", &proposal.proposal_digest, "deny", 2)
                .unwrap();
        assert!(
            require_mergeable_proposal(&rejected, &rejected.proposal_digest)
                .unwrap_err()
                .contains("rejected")
        );
    }

    #[test]
    fn named_foreign_digest_is_not_a_member_grant() {
        let proposal = prepare_proposal(&request(), "author", 1).unwrap();
        let member = DefinitionRevisionMember {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            member_digest: digest('f'),
        };
        let revision =
            prepare_revision("team-a", &digest('a'), [member], false, "author", 2).unwrap();
        assert!(
            named_foreign_digests_confer_no_grant(&proposal, &revision)
                .unwrap_err()
                .contains("foreign_authority")
        );
    }
}
