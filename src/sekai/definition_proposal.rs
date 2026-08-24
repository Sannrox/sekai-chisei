//! Governed definition proposals that publish or reject one exact revision.
//!
//! A proposal pins a published base digest and a branch-head candidate. Merge
//! compare-and-swaps the namespace published head in one transaction. Branch
//! edits after the pin, missing approvals, and foreign digests never become a
//! grant.

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
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseDefinitionProposal {
    pub namespace: String,
    pub proposal_id: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionProposalMergeResult {
    pub proposal: DefinitionProposal,
    pub previous_published_digest: String,
    pub published_revision: DefinitionRevision,
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
            STATUS_OPEN | STATUS_MERGED | STATUS_CLOSED => {}
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
}
