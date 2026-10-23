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
    DefinitionMember, DefinitionMemberRef, DefinitionRevision, MAX_DEFINITION_ID_BYTES,
    validate_digest, validate_identifier, validate_namespace,
};
use crate::sekai::definition_diff::DefinitionRevisionDiff;

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
    #[serde(default)]
    pub restored_from_digest: String,
    #[serde(default)]
    pub migration_plan_digest: String,
    /// Approved as a new major revision: it may break blocking consumer
    /// bindings (ADR 0067, amended).
    #[serde(default)]
    pub major_revision: bool,
    /// Package digest of the signed definition package this proposal
    /// imports (#1700). Empty for proposals not created by import.
    #[serde(default)]
    pub source_package_digest: String,
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
    #[serde(default)]
    pub major_revision: bool,
    /// Digest of the change bundle this proposal migrates by (#1693); part of
    /// the approved proposal digest, so apply runs only that bundle.
    #[serde(default)]
    pub migration_plan_digest: String,
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
    /// Datasets a change bundle migrated, with the version each must still be
    /// at when the proposal publishes (#1693). Checked in the publish
    /// transaction; outside the request digest, so a retry still replays.
    #[serde(default, skip_serializing)]
    pub expected_dataset_versions: Vec<(String, String)>,
    /// Object types a change bundle migrated, with the datasource fingerprint
    /// (`object_type_index::datasource_fingerprint`) each must still have when
    /// the proposal publishes. Checked like `expected_dataset_versions`.
    #[serde(default, skip_serializing)]
    pub expected_datasources: Vec<(String, String)>,
}

/// Merge refusal: a datasource a change bundle migrated was reconfigured.
pub const MERGE_DATASOURCE_CHANGED: &str = "definition_bundle_apply_datasource_changed";

/// Merge refusal: a dataset a change bundle migrated was written since.
pub const MERGE_DATASET_MOVED: &str = "definition_bundle_apply_data_moved";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseDefinitionProposal {
    pub namespace: String,
    pub proposal_id: String,
    pub reason_code: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposeDefinitionRollback {
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub restore_from_digest: String,
    // Captured for compare-and-swap only; omitted from the request digest so
    // an identical client retry still replays after the published head moves.
    #[serde(default, skip_serializing)]
    pub expected_published_digest: String,
    #[serde(default)]
    pub migration_plan_digest: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionProposalMergeResult {
    pub proposal: DefinitionProposal,
    pub previous_published_digest: String,
    pub published_revision: DefinitionRevision,
    pub receipt_id: String,
}

/// One published merge in a namespace's revision history (#1354).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedDefinitionRevisionHistoryEntry {
    pub revision_digest: String,
    pub previous_published_digest: String,
    pub proposal_id: String,
    pub receipt_id: String,
    pub actor: String,
    pub published_at_ms: i64,
}

pub const HISTORY_DEFAULT_PAGE_SIZE: usize = 50;
pub const HISTORY_MAX_PAGE_SIZE: usize = 200;

pub fn validate_history_member_filter(member_kind: &str, member_id: &str) -> Result<(), String> {
    match (member_kind.trim().is_empty(), member_id.trim().is_empty()) {
        (true, true) | (false, false) => Ok(()),
        _ => Err(
            "definition_history_invalid_member_filter: member_kind and member_id must both be set or both empty"
                .into(),
        ),
    }
}

pub fn clamp_history_page_size(requested: i32) -> usize {
    if requested <= 0 {
        HISTORY_DEFAULT_PAGE_SIZE
    } else {
        (requested as usize).min(HISTORY_MAX_PAGE_SIZE)
    }
}

pub fn decode_history_page_token(token: &str) -> Result<Option<(i64, String)>, String> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    let Some((ms, proposal_id)) = token.split_once('|') else {
        return Err(
            "invalid_definition_history_page_token: expected published_at_ms|proposal_id".into(),
        );
    };
    if proposal_id.is_empty() {
        return Err("invalid_definition_history_page_token: proposal_id is empty".into());
    }
    let ms = ms.parse::<i64>().map_err(|_| {
        "invalid_definition_history_page_token: published_at_ms is not an integer".to_string()
    })?;
    Ok(Some((ms, proposal_id.to_string())))
}

pub fn encode_history_page_token(published_at_ms: i64, proposal_id: &str) -> String {
    format!("{published_at_ms}|{proposal_id}")
}

pub fn paginate_history_entries(
    mut entries: Vec<PublishedDefinitionRevisionHistoryEntry>,
    page_size: usize,
) -> (Vec<PublishedDefinitionRevisionHistoryEntry>, String) {
    let next_page_token = if entries.len() > page_size {
        let last = &entries[page_size - 1];
        encode_history_page_token(last.published_at_ms, &last.proposal_id)
    } else {
        String::new()
    };
    entries.truncate(page_size);
    (entries, next_page_token)
}

/// True when `member_kind`/`member_id` was added, removed, or digest-changed
/// between the previous published revision and `current`.
pub fn history_member_changed(
    current: &DefinitionRevision,
    previous: Option<&DefinitionRevision>,
    member_kind: &str,
    member_id: &str,
) -> bool {
    fn digest_of<'a>(
        revision: &'a DefinitionRevision,
        member_kind: &str,
        member_id: &str,
    ) -> Option<&'a str> {
        revision.members.iter().find_map(|member| {
            (member.member_kind == member_kind && member.member_id == member_id)
                .then_some(member.member_digest.as_str())
        })
    }
    digest_of(current, member_kind, member_id)
        != previous.and_then(|revision| digest_of(revision, member_kind, member_id))
}

pub trait PublishedDefinitionHistoryStore {
    fn fetch_merged_history(
        &mut self,
        namespace: &str,
        cursor: Option<(i64, String)>,
        limit: usize,
    ) -> Result<Vec<PublishedDefinitionRevisionHistoryEntry>, String>;

    fn load_history_revision(
        &mut self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<DefinitionRevision>, String>;
}

pub fn history_entry_from_merged_proposal(
    body_json: &str,
    receipt_id: String,
    updated_at_ms: i64,
    proposal_id: String,
    actor: String,
) -> Result<PublishedDefinitionRevisionHistoryEntry, String> {
    let proposal: DefinitionProposal = serde_json::from_str(body_json)
        .map_err(|error| format!("corrupt definition proposal: {error}"))?;
    if proposal.proposal_id != proposal_id {
        return Err("corrupt definition proposal: lookup identity mismatch".into());
    }
    Ok(PublishedDefinitionRevisionHistoryEntry {
        revision_digest: proposal.candidate_digest,
        previous_published_digest: proposal.base_digest,
        proposal_id,
        receipt_id,
        actor,
        published_at_ms: updated_at_ms,
    })
}

pub fn validate_list_published_history_request(
    namespace: &str,
    member_kind: &str,
    member_id: &str,
    page_token: &str,
) -> Result<(), String> {
    validate_namespace(namespace)?;
    validate_history_member_filter(member_kind, member_id)?;
    if !member_kind.trim().is_empty() {
        validate_identifier("member_kind", member_kind, MAX_DEFINITION_ID_BYTES)?;
        validate_identifier("member_id", member_id, MAX_DEFINITION_ID_BYTES)?;
    }
    decode_history_page_token(page_token).map(|_| ())
}

pub fn list_published_definition_history(
    store: &mut dyn PublishedDefinitionHistoryStore,
    namespace: &str,
    member_kind: &str,
    member_id: &str,
    page_token: &str,
    page_size: i32,
) -> Result<(Vec<PublishedDefinitionRevisionHistoryEntry>, String), String> {
    validate_list_published_history_request(namespace, member_kind, member_id, page_token)?;
    let kind = member_kind.trim();
    let id = member_id.trim();
    let page_size = clamp_history_page_size(page_size);
    let mut cursor = decode_history_page_token(page_token)?;
    let filter = !kind.is_empty();
    let mut matched = Vec::new();
    loop {
        let fetch = if filter {
            (page_size + 1).max(32)
        } else {
            page_size + 1
        };
        let batch = store.fetch_merged_history(namespace, cursor.clone(), fetch)?;
        let exhausted = batch.len() < fetch;
        for row in batch {
            cursor = Some((row.published_at_ms, row.proposal_id.clone()));
            if filter {
                let current = store
                    .load_history_revision(namespace, &row.revision_digest)?
                    .ok_or_else(|| {
                        "definition_history_revision_missing: merged candidate is absent"
                            .to_string()
                    })?;
                let previous = if row.previous_published_digest.is_empty() {
                    None
                } else {
                    store.load_history_revision(namespace, &row.previous_published_digest)?
                };
                if !history_member_changed(&current, previous.as_ref(), kind, id) {
                    continue;
                }
            }
            matched.push(row);
            if matched.len() == page_size + 1 {
                break;
            }
        }
        if matched.len() == page_size + 1 || exhausted {
            break;
        }
    }
    Ok(paginate_history_entries(matched, page_size))
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
        if !self.migration_plan_digest.is_empty() {
            validate_digest("migration_plan_digest", &self.migration_plan_digest)?;
        }
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
        let proposal_digest = proposal_content_digest(&PreparedProposalDigestInput {
            namespace: &self.namespace,
            branch_id: &self.branch_id,
            proposal_id: &self.proposal_id,
            base_digest: &self.base_digest,
            candidate_digest: &self.candidate_digest,
            eval_plan_digests: &eval_plan_digests,
            named_foreign_digests: &named_foreign_digests,
            restored_from_digest: "",
            migration_plan_digest: &self.migration_plan_digest,
            major_revision: self.major_revision,
            source_package_digest: "",
        })?;
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
                restored_from_digest: "",
                migration_plan_digest: &self.migration_plan_digest,
                major_revision: self.major_revision,
                source_package_digest: "",
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

/// Opens a proposal whose candidate holds exactly a verified package's
/// members (#1700). `members` are already prepared for `namespace`; the
/// package digest binds them, so they stay out of the request digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposeDefinitionImport {
    pub namespace: String,
    pub branch_id: String,
    pub proposal_id: String,
    pub source_package_digest: String,
    #[serde(default, skip_serializing)]
    pub members: Vec<DefinitionMember>,
    // Captured for compare-and-swap only, like rollback.
    #[serde(default, skip_serializing)]
    pub expected_published_digest: String,
    pub idempotency_key: String,
}

impl ProposeDefinitionImport {
    pub fn prepare(&self) -> Result<String, String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("branch_id", &self.branch_id, MAX_DEFINITION_ID_BYTES)?;
        validate_identifier("proposal_id", &self.proposal_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("source_package_digest", &self.source_package_digest)?;
        validate_digest("expected_published_digest", &self.expected_published_digest).map_err(
            |_| {
                "stale_published_definition_head: expected published digest is required".to_string()
            },
        )?;
        if self
            .members
            .iter()
            .any(|member| member.namespace != self.namespace)
        {
            return Err("import members must be prepared for the target namespace".into());
        }
        if self.members.len() > crate::sekai::definition_branch::MAX_DEFINITION_MEMBERS {
            return Err(format!(
                "{}: package exceeds the supported member count",
                crate::sekai::definition_package::REFUSAL_INCOMPATIBLE
            ));
        }
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        canonical_digest("propose_definition_import", self)
    }
}

impl ProposeDefinitionRollback {
    pub fn prepare(&self) -> Result<String, String> {
        validate_namespace(&self.namespace)?;
        validate_identifier("branch_id", &self.branch_id, MAX_DEFINITION_ID_BYTES)?;
        validate_identifier("proposal_id", &self.proposal_id, MAX_DEFINITION_ID_BYTES)?;
        validate_digest("restore_from_digest", &self.restore_from_digest)?;
        if self.expected_published_digest.is_empty() {
            return Err(
                "stale_published_definition_head: expected published digest is required".into(),
            );
        }
        validate_digest("expected_published_digest", &self.expected_published_digest)?;
        if self.restore_from_digest == self.expected_published_digest {
            return Err(
                "definition_proposal_no_change: restore digest must differ from published head"
                    .into(),
            );
        }
        if !self.migration_plan_digest.is_empty() {
            validate_digest("migration_plan_digest", &self.migration_plan_digest)?;
        }
        validate_identifier(
            "idempotency_key",
            &self.idempotency_key,
            MAX_DEFINITION_ID_BYTES,
        )?;
        canonical_digest("propose_definition_rollback", self)
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
        if !self.restored_from_digest.is_empty() {
            validate_digest("restored_from_digest", &self.restored_from_digest)?;
        }
        if !self.migration_plan_digest.is_empty() {
            validate_digest("migration_plan_digest", &self.migration_plan_digest)?;
        }
        if !self.source_package_digest.is_empty() {
            validate_digest("source_package_digest", &self.source_package_digest)?;
        }
        let expected = proposal_content_digest(&PreparedProposalDigestInput {
            namespace: &self.namespace,
            branch_id: &self.branch_id,
            proposal_id: &self.proposal_id,
            base_digest: &self.base_digest,
            candidate_digest: &self.candidate_digest,
            eval_plan_digests: &self.eval_plan_digests,
            named_foreign_digests: &self.named_foreign_digests,
            restored_from_digest: &self.restored_from_digest,
            migration_plan_digest: &self.migration_plan_digest,
            major_revision: self.major_revision,
            source_package_digest: &self.source_package_digest,
        })?;
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
    restored_from_digest: &str,
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
            restored_from_digest,
        },
    )
}

/// A proposal whose candidate holds exactly `members` on top of the
/// published head: a rollback (`restored_from_digest`) or a package import
/// (`source_package_digest`). Members absent from `members` become removals.
pub(crate) struct ReplacementProposal<'a> {
    pub namespace: &'a str,
    pub branch_id: &'a str,
    pub proposal_id: &'a str,
    pub members: Vec<DefinitionMember>,
    pub restored_from_digest: &'a str,
    pub migration_plan_digest: &'a str,
    pub source_package_digest: &'a str,
}

/// Upserts every member of a prior published revision and removes members that
/// exist only on the live published head, so the candidate matches the restore
/// set while remaining a descendant of that head.
pub fn rollback_member_edits(
    published: &DefinitionRevision,
    restore_members: &[DefinitionMember],
) -> Result<(Vec<DefinitionMember>, Vec<DefinitionMemberRef>), String> {
    let restore_keys = restore_members
        .iter()
        .map(|member| (member.member_kind.clone(), member.member_id.clone()))
        .collect::<BTreeSet<_>>();
    let removals = published
        .members
        .iter()
        .filter(|member| {
            !restore_keys.contains(&(member.member_kind.clone(), member.member_id.clone()))
        })
        .map(|member| DefinitionMemberRef {
            member_kind: member.member_kind.clone(),
            member_id: member.member_id.clone(),
        })
        .collect();
    Ok((restore_members.to_vec(), removals))
}

pub fn object_property_keys(properties_json: &str) -> BTreeSet<String> {
    serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(properties_json)
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default()
}

pub fn dataset_column_names(columns_json: &str) -> BTreeSet<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(columns_json) else {
        return BTreeSet::new();
    };
    let mut names = BTreeSet::new();
    let Some(items) = value.as_array() else {
        return names;
    };
    for item in items {
        match item {
            serde_json::Value::String(name) => {
                names.insert(name.clone());
            }
            serde_json::Value::Array(tuple) => {
                if let Some(serde_json::Value::String(name)) = tuple.first() {
                    names.insert(name.clone());
                }
            }
            serde_json::Value::Object(object) => {
                if let Some(serde_json::Value::String(name)) = object.get("name") {
                    names.insert(name.clone());
                }
            }
            _ => {}
        }
    }
    names
}

pub fn rollback_may_drop_live_object_type_properties(
    proposal: &DefinitionProposal,
    diff: &DefinitionRevisionDiff,
) -> bool {
    if proposal.restored_from_digest.is_empty() || !proposal.migration_plan_digest.is_empty() {
        return false;
    }
    diff.changed
        .iter()
        .chain(diff.removed.iter())
        .any(|change| change.member_kind == "object_type" && !change.removed_properties.is_empty())
}

pub fn require_rollback_migration_plan(
    proposal: &DefinitionProposal,
    diff: &DefinitionRevisionDiff,
    live_kind_properties: &[(String, BTreeSet<String>)],
) -> Result<(), String> {
    if proposal.restored_from_digest.is_empty() {
        return Ok(());
    }
    if !proposal.migration_plan_digest.is_empty() {
        return validate_digest("migration_plan_digest", &proposal.migration_plan_digest);
    }
    let dropping = diff
        .changed
        .iter()
        .chain(diff.removed.iter())
        .any(|change| {
            change.member_kind == "object_type"
                && change.removed_properties.iter().any(|property| {
                    live_kind_properties
                        .iter()
                        .any(|(kind, keys)| kind == &change.member_id && keys.contains(property))
                })
        });
    if dropping {
        return Err(
            "definition_rollback_requires_migration_plan: rollback would drop live object or dataset properties"
                .into(),
        );
    }
    Ok(())
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

pub(crate) fn proposal_content_digest(
    input: &PreparedProposalDigestInput<'_>,
) -> Result<String, String> {
    canonical_digest("definition_proposal", input)
}

#[derive(Serialize)]
struct MergeReceiptDigestInput<'a> {
    namespace: &'a str,
    proposal_id: &'a str,
    proposal_digest: &'a str,
    base_digest: &'a str,
    candidate_digest: &'a str,
    previous_published_digest: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    restored_from_digest: &'a str,
}

#[derive(Serialize)]
pub(crate) struct PreparedProposalDigestInput<'a> {
    pub(crate) namespace: &'a str,
    pub(crate) branch_id: &'a str,
    pub(crate) proposal_id: &'a str,
    pub(crate) base_digest: &'a str,
    pub(crate) candidate_digest: &'a str,
    pub(crate) eval_plan_digests: &'a [String],
    pub(crate) named_foreign_digests: &'a [String],
    #[serde(skip_serializing_if = "str::is_empty")]
    pub(crate) restored_from_digest: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub(crate) migration_plan_digest: &'a str,
    /// Omitted when false, so digests of earlier proposals are unchanged.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) major_revision: bool,
    /// Omitted when empty, so digests of earlier proposals are unchanged.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub(crate) source_package_digest: &'a str,
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
            major_revision: false,
            migration_plan_digest: String::new(),
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
            restored_from_digest: String::new(),
            migration_plan_digest: String::new(),
            major_revision: false,
            source_package_digest: String::new(),
        };
        proposal.proposal_digest = proposal_content_digest(&PreparedProposalDigestInput {
            namespace: &proposal.namespace,
            branch_id: &proposal.branch_id,
            proposal_id: &proposal.proposal_id,
            base_digest: &proposal.base_digest,
            candidate_digest: &proposal.candidate_digest,
            eval_plan_digests: &proposal.eval_plan_digests,
            named_foreign_digests: &proposal.named_foreign_digests,
            restored_from_digest: "",
            migration_plan_digest: "",
            major_revision: false,
            source_package_digest: "",
        })
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
            expected_dataset_versions: Vec::new(),
            expected_datasources: Vec::new(),
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

    #[test]
    fn history_page_token_round_trips_and_rejects_junk() {
        let token = encode_history_page_token(42, "cs-1");
        assert_eq!(
            decode_history_page_token(&token).unwrap(),
            Some((42, "cs-1".into()))
        );
        assert_eq!(decode_history_page_token("").unwrap(), None);
        assert!(
            decode_history_page_token("not-a-token")
                .unwrap_err()
                .contains("invalid_definition_history_page_token")
        );
        assert!(
            decode_history_page_token("x|cs-1")
                .unwrap_err()
                .contains("published_at_ms")
        );
        assert!(
            validate_history_member_filter("object_type", "")
                .unwrap_err()
                .contains("definition_history_invalid_member_filter")
        );
        validate_history_member_filter("", "").unwrap();
        validate_history_member_filter("object_type", "Ticket").unwrap();
        assert!(
            validate_list_published_history_request("team-a", " object_type", "Ticket", "")
                .unwrap_err()
                .contains("canonical member_kind required")
        );
        validate_list_published_history_request("team-a", "object_type", "Ticket", "").unwrap();
    }

    #[test]
    fn history_member_changed_detects_add_remove_and_digest() {
        let ticket = |digest: &str| DefinitionRevisionMember {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            member_digest: digest.into(),
        };
        let current = DefinitionRevision {
            contract_version: crate::sekai::definition_branch::REVISION_CONTRACT_VERSION.into(),
            namespace: "team-a".into(),
            revision_digest: digest('c'),
            parent_revision_digest: digest('b'),
            members: vec![ticket("sha256:new")],
            published: true,
            created_by: "author".into(),
            created_at_ms: 2,
        };
        let previous = DefinitionRevision {
            members: vec![ticket("sha256:old")],
            revision_digest: digest('b'),
            ..current.clone()
        };
        assert!(history_member_changed(
            &current,
            Some(&previous),
            "object_type",
            "Ticket"
        ));
        assert!(!history_member_changed(
            &current,
            Some(&current),
            "object_type",
            "Ticket"
        ));
        assert!(history_member_changed(
            &current,
            None,
            "object_type",
            "Ticket"
        ));
        assert!(!history_member_changed(
            &current,
            Some(&previous),
            "ontology_class",
            "TicketClass"
        ));
    }

    #[test]
    fn rollback_request_digest_ignores_expected_published_head() {
        let mut request = ProposeDefinitionRollback {
            namespace: "team-a".into(),
            branch_id: "restore".into(),
            proposal_id: "cs-1".into(),
            restore_from_digest: digest('a'),
            expected_published_digest: digest('b'),
            migration_plan_digest: String::new(),
            idempotency_key: "rb-1".into(),
        };
        let first = request.prepare().unwrap();
        request.expected_published_digest = digest('c');
        assert_eq!(first, request.prepare().unwrap());
    }
}
