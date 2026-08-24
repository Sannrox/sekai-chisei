//! Governed definition proposals that publish or reject one exact revision.
//!
//! A proposal pins a published base digest and a branch-head candidate. Merge
//! compare-and-swaps the namespace published head against an expected digest
//! and stores a receipt in the same transaction. Branch edits after the pin,
//! missing approvals, non-descendant candidates, and foreign digests never
//! become a grant. Close records a canonical reason without moving the head.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::sekai::definition_branch::{
    DefinitionRevision, MAX_DEFINITION_ID_BYTES, validate_digest, validate_identifier,
    validate_namespace,
};

pub const PROPOSAL_CONTRACT_VERSION: &str = "sekai.definition-proposal/v1";
pub const MAX_PROPOSAL_DIGEST_REFS: usize = 32;

pub const STATUS_OPEN: &str = "open";
pub const STATUS_MERGED: &str = "merged";
pub const STATUS_CLOSED: &str = "closed";

pub const CLOSE_REASON_OPERATOR_ABORT: &str = "operator_abort";
pub const CLOSE_REASON_SUPERSEDED: &str = "superseded";
pub const CLOSE_REASON_POLICY_DENIED: &str = "policy_denied";
const MAX_ANCESTRY_WALK: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionProposalApproval {
    pub actor: String,
    pub approved_at_ms: i64,
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
    pub eval_plan_digests: Vec<String>,
    pub named_foreign_digests: Vec<String>,
    pub approvals: Vec<DefinitionProposalApproval>,
    pub status: String,
    pub created_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub receipt_id: String,
    #[serde(default)]
    pub close_reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateDefinitionProposal {
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub base_digest: String,
    pub candidate_digest: String,
    pub eval_plan_digests: Vec<String>,
    pub named_foreign_digests: Vec<String>,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveDefinitionProposal {
    pub namespace: String,
    pub proposal_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeDefinitionProposal {
    pub namespace: String,
    pub proposal_id: String,
    pub expected_published_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseDefinitionProposal {
    pub namespace: String,
    pub proposal_id: String,
    pub reason_code: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionProposalMergeResult {
    pub proposal: DefinitionProposal,
    pub previous_published_digest: String,
    pub published_revision: DefinitionRevision,
    pub receipt_id: String,
}

impl CreateDefinitionProposal {
    pub fn prepare(&self) -> Result<(Vec<String>, Vec<String>, String, String), String> {
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
        let eval_plan_digests = normalize_digest_refs("eval_plan_digest", &self.eval_plan_digests)?;
        let named_foreign_digests =
            normalize_digest_refs("named_foreign_digest", &self.named_foreign_digests)?;
        if eval_plan_digests
            .iter()
            .any(|digest| named_foreign_digests.binary_search(digest).is_ok())
        {
            return Err(
                "definition_proposal_conflict: eval and foreign digest lists overlap".into(),
            );
        }
        let proposal_digest = proposal_content_digest(
            &self.namespace,
            &self.branch_id,
            &self.proposal_id,
            &self.base_digest,
            &self.candidate_digest,
            &eval_plan_digests,
            &named_foreign_digests,
        )?;
        let request_digest = canonical_digest(
            "create_definition_proposal",
            &PreparedProposalDigestInput {
                namespace: &self.namespace,
                branch_id: &self.branch_id,
                proposal_id: &self.proposal_id,
                base_digest: &self.base_digest,
                candidate_digest: &self.candidate_digest,
                eval_plan_digests: &eval_plan_digests,
                named_foreign_digests: &named_foreign_digests,
            },
        )?;
        Ok((
            eval_plan_digests,
            named_foreign_digests,
            proposal_digest,
            request_digest,
        ))
    }
}

impl ApproveDefinitionProposal {
    pub fn request_digest(&self) -> Result<String, String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("proposal_id", &self.proposal_id, MAX_DEFINITION_ID_BYTES)?;
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        canonical_digest("approve_definition_proposal", self)
    }
}

impl MergeDefinitionProposal {
    pub fn request_digest(&self) -> Result<String, String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("proposal_id", &self.proposal_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("expected_published_digest", &self.expected_published_digest)?;
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        canonical_digest("merge_definition_proposal", self)
    }
}

impl CloseDefinitionProposal {
    pub fn request_digest(&self) -> Result<String, String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("proposal_id", &self.proposal_id, MAX_DEFINITION_ID_BYTES)?;
        validate_close_reason_code(&self.reason_code)?;
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        canonical_digest("close_definition_proposal", self)
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
        let eval_plan_digests = normalize_digest_refs("eval_plan_digest", &self.eval_plan_digests)?;
        let named_foreign_digests =
            normalize_digest_refs("named_foreign_digest", &self.named_foreign_digests)?;
        if eval_plan_digests != self.eval_plan_digests
            || named_foreign_digests != self.named_foreign_digests
        {
            return Err("definition proposal digest lists are not canonical".into());
        }
        let expected = proposal_content_digest(
            &self.namespace,
            &self.branch_id,
            &self.proposal_id,
            &self.base_digest,
            &self.candidate_digest,
            &self.eval_plan_digests,
            &self.named_foreign_digests,
        )?;
        if expected != self.proposal_digest {
            return Err("definition proposal content binding is invalid".into());
        }
        match self.status.as_str() {
            STATUS_OPEN => {
                if !self.receipt_id.is_empty() || !self.close_reason_code.is_empty() {
                    return Err(
                        "definition proposal open state cannot carry a receipt or close reason"
                            .into(),
                    );
                }
            }
            STATUS_MERGED => {
                if !self.receipt_id.is_empty() {
                    validate_digest("receipt_id", &self.receipt_id)?;
                }
                if !self.close_reason_code.is_empty() {
                    return Err("merged definition proposal cannot carry a close reason".into());
                }
            }
            STATUS_CLOSED => {
                if !self.receipt_id.is_empty() {
                    return Err("closed definition proposal cannot carry a merge receipt".into());
                }
                if !self.close_reason_code.is_empty() {
                    validate_close_reason_code(&self.close_reason_code)?;
                }
            }
            _ => return Err("definition proposal status is unsupported".into()),
        }
        validate_identifier("created_by", &self.created_by, MAX_DEFINITION_ID_BYTES)?;
        if self.created_at_ms <= 0 || self.updated_at_ms < self.created_at_ms {
            return Err("definition proposal timestamps are invalid".into());
        }
        let mut seen = BTreeSet::new();
        for approval in &self.approvals {
            validate_identifier("approval_actor", &approval.actor, MAX_DEFINITION_ID_BYTES)?;
            if approval.approved_at_ms <= 0 {
                return Err("approval timestamp must be positive".into());
            }
            if !seen.insert(approval.actor.as_str()) {
                return Err("definition proposal contains duplicate approvals".into());
            }
        }
        Ok(())
    }

    pub fn require_open(&self) -> Result<(), String> {
        if self.status != STATUS_OPEN {
            return Err("definition_proposal_not_open: proposal cannot accept this write".into());
        }
        Ok(())
    }
}

pub fn changed_member_refs(
    base: &DefinitionRevision,
    candidate: &DefinitionRevision,
) -> Vec<(String, String)> {
    let base_members = base
        .members
        .iter()
        .map(|member| {
            (
                (member.member_kind.clone(), member.member_id.clone()),
                member.member_digest.clone(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let candidate_members = candidate
        .members
        .iter()
        .map(|member| {
            (
                (member.member_kind.clone(), member.member_id.clone()),
                member.member_digest.clone(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut changed = BTreeSet::new();
    for (identity, digest) in &candidate_members {
        if base_members.get(identity) != Some(digest) {
            changed.insert(identity.clone());
        }
    }
    for identity in base_members.keys() {
        if !candidate_members.contains_key(identity) {
            changed.insert(identity.clone());
        }
    }
    changed.into_iter().collect()
}

pub fn validate_close_reason_code(reason_code: &str) -> Result<(), String> {
    match reason_code {
        CLOSE_REASON_OPERATOR_ABORT | CLOSE_REASON_SUPERSEDED | CLOSE_REASON_POLICY_DENIED => {
            Ok(())
        }
        _ => Err("definition_proposal_invalid_close_reason: reason_code is not canonical".into()),
    }
}

pub fn merge_receipt_id(
    namespace: &str,
    proposal_id: &str,
    proposal_digest: &str,
    base_digest: &str,
    candidate_digest: &str,
    previous_published_digest: &str,
) -> Result<String, String> {
    canonical_digest(
        "definition_proposal_merge_receipt",
        &MergeReceiptDigestInput {
            namespace,
            proposal_id,
            proposal_digest,
            base_digest,
            candidate_digest,
            previous_published_digest,
        },
    )
}

pub fn require_descendant_candidate(
    candidate: &DefinitionRevision,
    base_digest: &str,
    mut load_parent: impl FnMut(&str) -> Result<Option<DefinitionRevision>, String>,
) -> Result<(), String> {
    if candidate.revision_digest == base_digest {
        return Err("definition_proposal_no_change: candidate must differ from base".into());
    }
    let mut current = candidate.parent_revision_digest.clone();
    let mut seen = BTreeSet::from([candidate.revision_digest.clone()]);
    for _ in 0..MAX_ANCESTRY_WALK {
        if current.is_empty() {
            return Err(
                "incompatible_definition_proposal_candidate: candidate is not a descendant of the pinned base"
                    .into(),
            );
        }
        if current == base_digest {
            return Ok(());
        }
        if !seen.insert(current.clone()) {
            return Err(
                "incompatible_definition_proposal_candidate: revision parent chain contains a cycle"
                    .into(),
            );
        }
        let Some(parent) = load_parent(&current)? else {
            return Err(
                "incompatible_definition_proposal_candidate: candidate is not a descendant of the pinned base"
                    .into(),
            );
        };
        current = parent.parent_revision_digest;
    }
    Err(
        "incompatible_definition_proposal_candidate: revision parent chain exceeds the supported depth"
            .into(),
    )
}

pub fn reject_foreign_member_grants(
    revision: &DefinitionRevision,
    named_foreign_digests: &[String],
) -> Result<(), String> {
    let foreign = named_foreign_digests.iter().collect::<BTreeSet<_>>();
    if revision
        .members
        .iter()
        .any(|member| foreign.contains(&member.member_digest))
    {
        return Err(
            "foreign_authority_is_not_a_grant: named foreign digest cannot enter published members"
                .into(),
        );
    }
    Ok(())
}

fn normalize_digest_refs(field: &str, values: &[String]) -> Result<Vec<String>, String> {
    if values.len() > MAX_PROPOSAL_DIGEST_REFS {
        return Err(format!("{field} list exceeds the supported size"));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_digest(field, value)?;
        if !unique.insert(value.clone()) {
            return Err(format!("{field} list contains duplicates"));
        }
    }
    Ok(unique.into_iter().collect())
}

fn proposal_content_digest(
    namespace: &str,
    branch_id: &str,
    proposal_id: &str,
    base_digest: &str,
    candidate_digest: &str,
    eval_plan_digests: &[String],
    named_foreign_digests: &[String],
) -> Result<String, String> {
    canonical_digest(
        "definition_proposal",
        &PreparedProposalDigestInput {
            namespace,
            branch_id,
            proposal_id,
            base_digest,
            candidate_digest,
            eval_plan_digests,
            named_foreign_digests,
        },
    )
}

#[derive(Serialize)]
struct MergeReceiptDigestInput<'a> {
    namespace: &'a str,
    proposal_id: &'a str,
    proposal_digest: &'a str,
    base_digest: &'a str,
    candidate_digest: &'a str,
    previous_published_digest: &'a str,
}

#[derive(Serialize)]
struct PreparedProposalDigestInput<'a> {
    namespace: &'a str,
    branch_id: &'a str,
    proposal_id: &'a str,
    base_digest: &'a str,
    candidate_digest: &'a str,
    eval_plan_digests: &'a [String],
    named_foreign_digests: &'a [String],
}

fn canonical_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, String> {
    let canonical = crate::shomei::canonical_json_with_finite_numbers(value)?;
    let mut hasher = Sha256::new();
    hasher.update(PROPOSAL_CONTRACT_VERSION.as_bytes());
    hasher.update(b"\n");
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn create_request() -> CreateDefinitionProposal {
        CreateDefinitionProposal {
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            proposal_id: "cs-1".into(),
            base_digest: digest('a'),
            candidate_digest: digest('b'),
            eval_plan_digests: vec![digest('e')],
            named_foreign_digests: vec![digest('f')],
            idempotency_key: "propose-1".into(),
        }
    }

    #[test]
    fn proposal_digest_ignores_ref_order() {
        let mut reversed = create_request();
        reversed.eval_plan_digests = vec![digest('e'), digest('c')];
        let mut ordered = reversed.clone();
        ordered.eval_plan_digests = vec![digest('c'), digest('e')];
        let first = reversed.prepare().unwrap();
        let second = ordered.prepare().unwrap();
        assert_eq!(first.2, second.2);
        assert_eq!(first.0, vec![digest('c'), digest('e')]);
    }

    #[test]
    fn identical_base_and_candidate_are_rejected() {
        let mut request = create_request();
        request.candidate_digest = request.base_digest.clone();
        assert!(
            request
                .prepare()
                .unwrap_err()
                .contains("definition_proposal_no_change")
        );
    }

    #[test]
    fn foreign_member_digest_is_not_a_grant() {
        let member = DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket"}"#.into(),
            member_digest: String::new(),
        }
        .prepare("team-a")
        .unwrap();
        let revision = prepare_revision(
            "team-a",
            "",
            [DefinitionRevisionMember {
                member_kind: member.member_kind,
                member_id: member.member_id,
                member_digest: member.member_digest.clone(),
            }],
            false,
            "author",
            1,
        )
        .unwrap();
        assert!(
            reject_foreign_member_grants(&revision, &[member.member_digest])
                .unwrap_err()
                .contains("foreign_authority_is_not_a_grant")
        );
    }

    #[test]
    fn historical_merged_and_closed_proposals_load_without_new_columns() {
        let mut proposal = DefinitionProposal {
            contract_version: PROPOSAL_CONTRACT_VERSION.into(),
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            proposal_id: "cs-1".into(),
            base_digest: digest('a'),
            candidate_digest: digest('b'),
            proposal_digest: String::new(),
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            approvals: Vec::new(),
            status: STATUS_MERGED.into(),
            created_by: "author".into(),
            created_at_ms: 1,
            updated_at_ms: 2,
            receipt_id: String::new(),
            close_reason_code: String::new(),
        };
        proposal.proposal_digest = proposal_content_digest(
            &proposal.namespace,
            &proposal.branch_id,
            &proposal.proposal_id,
            &proposal.base_digest,
            &proposal.candidate_digest,
            &proposal.eval_plan_digests,
            &proposal.named_foreign_digests,
        )
        .unwrap();
        proposal.verify().unwrap();
        proposal.status = STATUS_CLOSED.into();
        proposal.verify().unwrap();
    }

    #[test]
    fn merge_requires_expected_published_digest() {
        let request = MergeDefinitionProposal {
            namespace: "team-a".into(),
            proposal_id: "cs-1".into(),
            expected_published_digest: String::new(),
            idempotency_key: "merge-1".into(),
        };
        assert!(
            request
                .request_digest()
                .unwrap_err()
                .contains("expected_published_digest")
        );
    }

    #[test]
    fn close_rejects_unknown_reason_codes() {
        let request = CloseDefinitionProposal {
            namespace: "team-a".into(),
            proposal_id: "cs-1".into(),
            reason_code: "retry_later".into(),
            idempotency_key: "close-1".into(),
        };
        assert!(
            request
                .request_digest()
                .unwrap_err()
                .contains("definition_proposal_invalid_close_reason")
        );
    }

    #[test]
    fn descendant_candidate_is_accepted_and_sibling_is_denied() {
        let base = digest('a');
        let candidate = DefinitionRevision {
            contract_version: crate::sekai::definition_branch::REVISION_CONTRACT_VERSION.into(),
            namespace: "team-a".into(),
            revision_digest: digest('c'),
            parent_revision_digest: digest('b'),
            members: Vec::new(),
            published: false,
            created_by: "author".into(),
            created_at_ms: 1,
        };
        let mid = DefinitionRevision {
            parent_revision_digest: base.clone(),
            revision_digest: digest('b'),
            ..candidate.clone()
        };
        require_descendant_candidate(&candidate, &base, |digest| {
            if digest == mid.revision_digest {
                Ok(Some(mid.clone()))
            } else {
                Ok(None)
            }
        })
        .unwrap();
        let sibling = DefinitionRevision {
            parent_revision_digest: digest('z'),
            ..candidate
        };
        let error = require_descendant_candidate(&sibling, &base, |_| Ok(None)).unwrap_err();
        assert!(error.contains("incompatible_definition_proposal_candidate"));
        assert!(!error.contains("AlreadyExists"));
    }
}
