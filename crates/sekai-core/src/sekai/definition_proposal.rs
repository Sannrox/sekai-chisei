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
/// The contract of a proposal with attached dataset branch proposals
/// (#2199). An instance that knows only v1 refuses it on load, so it never
/// publishes the definition without its data. Digests keep the v1 prefix.
pub const PROPOSAL_CONTRACT_VERSION_V2: &str = "sekai.definition-proposal/v2";
pub const MAX_PROPOSAL_DIGEST_REFS: usize = 32;
pub const MAX_DATASET_PROPOSALS: usize = 16;

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

/// A dataset branch merge proposal a caller asks to attach (#2199).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DatasetProposalRef {
    pub dataset_id: String,
    pub proposal_id: String,
}

/// An attached dataset branch proposal as pinned when the definition proposal
/// was created. The pins are part of the proposal digest, so an approval
/// covers the data; the merge lands it only while every pin still holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetProposalAttachment {
    pub dataset_id: String,
    pub proposal_id: String,
    pub parent_version_id: String,
    pub branch_digest: String,
    /// The dataset proposal's tenant, which the merge must still match.
    pub tenant: String,
}

impl DatasetProposalAttachment {
    /// Pins `proposal` for a caller in `tenant`. Another tenant's proposal
    /// reads as missing; only an open, non-bundle proposal attaches.
    pub fn pin(
        proposal: &crate::sekai::dataset_branch::DatasetBranchProposal,
        tenant: &str,
    ) -> Result<Self, String> {
        use crate::sekai::dataset_branch as branch;
        if proposal.tenant != tenant {
            return Err(format!(
                "{DATASET_PROPOSAL_NOT_FOUND}: dataset branch proposal is unavailable"
            ));
        }
        if proposal.status != branch::STATUS_OPEN {
            return Err(format!(
                "{DATASET_PROPOSAL_REFUSED}: dataset branch proposal is not open"
            ));
        }
        if proposal.branch.starts_with(branch::BUNDLE_BRANCH_PREFIX) {
            return Err(format!(
                "{DATASET_PROPOSAL_REFUSED}: change bundle branches merge only through ApplyDefinitionChangeBundle"
            ));
        }
        Ok(Self {
            dataset_id: proposal.dataset_id.clone(),
            proposal_id: proposal.id.clone(),
            parent_version_id: proposal.parent_version_id.clone(),
            branch_digest: proposal.branch_digest.clone(),
            tenant: tenant.into(),
        })
    }

    /// Rechecks the pin against `proposal` as read in the merge transaction.
    /// A merged, closed (its branch was deleted), or re-pinned proposal is
    /// stale. The dataset rule that another principal merges still holds for
    /// `actor`, the principal merging the definition proposal.
    pub fn recheck(
        &self,
        proposal: &crate::sekai::dataset_branch::DatasetBranchProposal,
        actor: &str,
    ) -> Result<(), String> {
        use crate::sekai::dataset_branch as branch;
        if proposal.status != branch::STATUS_OPEN
            || proposal.tenant != self.tenant
            || proposal.parent_version_id != self.parent_version_id
            || proposal.branch_digest != self.branch_digest
        {
            return Err(self.stale());
        }
        if proposal.proposer == actor {
            return Err(format!(
                "{DATASET_PROPOSAL_REFUSED}: {}",
                branch::PROPOSAL_SELF_MERGE
            ));
        }
        Ok(())
    }

    /// `error` from loading or merging the pinned dataset proposal, read as
    /// staleness when it says the proposal or its dataset moved on.
    pub fn stale_or(&self, error: String) -> String {
        use crate::sekai::dataset_branch as branch;
        match error.as_str() {
            branch::PROPOSAL_NOT_FOUND
            | branch::PROPOSAL_NOT_OPEN
            | branch::PROPOSAL_STALE_PARENT
            | branch::PROPOSAL_STALE_BRANCH => self.stale(),
            _ => error,
        }
    }

    /// The refusal for a dataset that moved since the pin.
    pub fn stale(&self) -> String {
        format!(
            "{MERGE_DATASET_PROPOSAL_STALE}: dataset {} changed since the proposal pinned it",
            self.dataset_id
        )
    }
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
    /// Commit of the definition file tree this proposal imports (#1618).
    /// Empty for proposals not created by a tree import.
    #[serde(default)]
    pub source_commit: String,
    /// Dataset branch proposals merged with this one, in dataset-id order
    /// (#2199). Omitted when empty, so v1 proposals stay byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dataset_proposals: Vec<DatasetProposalAttachment>,
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
    /// Dataset branch proposals to merge with this one (#2199).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dataset_proposals: Vec<DatasetProposalRef>,
    /// The caller's tenant, which each attached dataset proposal must belong
    /// to. Set by the server; outside the request digest.
    #[serde(default, skip_serializing)]
    pub tenant: String,
}

/// A validated `CreateDefinitionProposal`: canonical digest lists and
/// dataset refs, and the digest that identifies the request for replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCreateDefinitionProposal {
    pub eval_plan_digests: Vec<String>,
    pub named_foreign_digests: Vec<String>,
    pub dataset_proposals: Vec<DatasetProposalRef>,
    pub request_digest: String,
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

/// Merge refusal: a change-bundle proposal publishes only through
/// `ApplyDefinitionChangeBundle`, which migrates its data first.
pub const MERGE_REQUIRES_BUNDLE_APPLY: &str = "definition_proposal_requires_bundle_apply";

/// Merge refusal: an attached dataset branch proposal was merged, closed, or
/// its dataset or branch moved since the proposal pinned it (#2199).
pub const MERGE_DATASET_PROPOSAL_STALE: &str = "definition_proposal_dataset_stale";

/// An attached dataset branch proposal is absent or in another tenant.
pub const DATASET_PROPOSAL_NOT_FOUND: &str = "definition_proposal_dataset_not_found";

/// A dataset branch proposal cannot be attached or merged by this caller.
pub const DATASET_PROPOSAL_REFUSED: &str = "definition_proposal_dataset_refused";

/// Who asks a store to merge a definition proposal. Internal to the server:
/// no request field selects it, so a client can only merge `Direct`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionMergePath {
    /// `MergeDefinitionProposal` and every other caller.
    Direct,
    /// The publish step of `ApplyDefinitionChangeBundle`.
    BundleApply,
}

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
    pub fn prepare(&self) -> Result<PreparedCreateDefinitionProposal, String> {
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
        let dataset_proposals = normalize_dataset_refs(&self.dataset_proposals)?;
        if !dataset_proposals.is_empty() && !self.migration_plan_digest.is_empty() {
            return Err(format!(
                "{DATASET_PROPOSAL_REFUSED}: a change bundle proposal cannot attach dataset branch proposals"
            ));
        }
        let input = PreparedProposalDigestInput {
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
            source_commit: "",
            dataset_proposals: &[],
        };
        // Without attachments the request digest is the v1 one.
        let request_digest = if dataset_proposals.is_empty() {
            canonical_digest("create_definition_proposal", &input)?
        } else {
            canonical_digest("create_definition_proposal", &(input, &dataset_proposals))?
        };
        Ok(PreparedCreateDefinitionProposal {
            eval_plan_digests,
            named_foreign_digests,
            dataset_proposals,
            request_digest,
        })
    }
}

/// Sorted by dataset id, at most one proposal per dataset: a second one on
/// the same dataset could never merge after the first.
fn normalize_dataset_refs(refs: &[DatasetProposalRef]) -> Result<Vec<DatasetProposalRef>, String> {
    if refs.len() > MAX_DATASET_PROPOSALS {
        return Err("dataset_proposals list exceeds the supported size".into());
    }
    let mut sorted = refs.to_vec();
    sorted.sort();
    for reference in &sorted {
        validate_identifier("dataset_id", &reference.dataset_id, MAX_DEFINITION_ID_BYTES)?;
        validate_identifier(
            "dataset proposal_id",
            &reference.proposal_id,
            MAX_DEFINITION_ID_BYTES,
        )?;
    }
    if sorted
        .windows(2)
        .any(|pair| pair[0].dataset_id == pair[1].dataset_id)
    {
        return Err("dataset_proposals list names a dataset twice".into());
    }
    Ok(sorted)
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
    /// A signed package import names its package; a file tree import names
    /// its commit instead. Exactly one is set.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_package_digest: String,
    /// Omitted when empty, so request digests of package imports are unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_commit: String,
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
        match (
            self.source_package_digest.is_empty(),
            self.source_commit.is_empty(),
        ) {
            (false, true) => validate_digest("source_package_digest", &self.source_package_digest)?,
            (true, false) => validate_source_commit(&self.source_commit)?,
            _ => {
                return Err(
                    "an import names exactly one of source_package_digest and source_commit".into(),
                );
            }
        }
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
        if self.source_commit.is_empty() {
            // A package's digest already binds its members.
            return canonical_digest("propose_definition_import", self);
        }
        // A commit is only a caller's label, so a tree import binds its
        // members here: the same key with other contents is a conflict, not a
        // replay of the first proposal.
        let mut members: Vec<(&str, &str, &str)> = self
            .members
            .iter()
            .map(|member| {
                (
                    member.member_kind.as_str(),
                    member.member_id.as_str(),
                    member.member_digest.as_str(),
                )
            })
            .collect();
        members.sort_unstable();
        canonical_digest("propose_definition_tree_import", &(self, members))
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
    /// The contract version a proposal with these attachments carries.
    pub fn contract_version_for(dataset_proposals: &[DatasetProposalAttachment]) -> &'static str {
        if dataset_proposals.is_empty() {
            PROPOSAL_CONTRACT_VERSION
        } else {
            PROPOSAL_CONTRACT_VERSION_V2
        }
    }

    /// The digest an approval covers: everything the proposal pins.
    pub fn content_digest(&self) -> Result<String, String> {
        proposal_content_digest(&PreparedProposalDigestInput {
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
            source_commit: &self.source_commit,
            dataset_proposals: &self.dataset_proposals,
        })
    }

    /// The `merged_by` an attached dataset branch merge records.
    pub fn dataset_merge_actor(&self) -> String {
        format!("definition-proposal:{}", self.proposal_id)
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.contract_version != Self::contract_version_for(&self.dataset_proposals) {
            return Err("definition proposal contract version is unsupported".into());
        }
        if !self.dataset_proposals.is_empty() {
            if !self.migration_plan_digest.is_empty() {
                return Err(
                    "definition proposal cannot attach datasets to a migration plan".into(),
                );
            }
            let refs = self
                .dataset_proposals
                .iter()
                .map(|attachment| DatasetProposalRef {
                    dataset_id: attachment.dataset_id.clone(),
                    proposal_id: attachment.proposal_id.clone(),
                })
                .collect::<Vec<_>>();
            if normalize_dataset_refs(&refs)? != refs {
                return Err("definition proposal dataset attachments are not canonical".into());
            }
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
        if !self.source_commit.is_empty() {
            validate_source_commit(&self.source_commit)?;
        }
        if self.content_digest()? != self.proposal_digest {
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

    /// Refuses a direct merge of a proposal created for a change bundle
    /// (#1693): only bundle apply migrates its data before the publish. A
    /// rollback's `migration_plan_digest` pins a plan, not a bundle, and
    /// merges directly; so does a proposal without one.
    pub fn require_merge_path(&self, path: DefinitionMergePath) -> Result<(), String> {
        let bundle = self.restored_from_digest.is_empty() && !self.migration_plan_digest.is_empty();
        if bundle && path != DefinitionMergePath::BundleApply {
            return Err(format!(
                "{MERGE_REQUIRES_BUNDLE_APPLY}: publish this proposal with ApplyDefinitionChangeBundle"
            ));
        }
        Ok(())
    }
}

/// Whether any stored proposal body in `bodies` attaches the dataset
/// proposal. An unreadable body fails closed.
pub fn any_attaches(
    bodies: &[String],
    dataset_id: &str,
    proposal_id: &str,
) -> Result<bool, String> {
    for body in bodies {
        let proposal: DefinitionProposal = serde_json::from_str(body)
            .map_err(|error| format!("corrupt definition proposal: {error}"))?;
        if proposal.dataset_proposals.iter().any(|attachment| {
            attachment.dataset_id == dataset_id && attachment.proposal_id == proposal_id
        }) {
            return Ok(true);
        }
    }
    Ok(false)
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

/// The receipt of merging `proposal` over `previous_published_digest`. It
/// covers the receipts of the dataset branch merges it landed, if any.
pub fn merge_receipt_id(
    proposal: &DefinitionProposal,
    previous_published_digest: &str,
    dataset_receipt_ids: &[String],
) -> Result<String, String> {
    canonical_digest(
        "definition_proposal_merge_receipt",
        &MergeReceiptDigestInput {
            namespace: &proposal.namespace,
            proposal_id: &proposal.proposal_id,
            proposal_digest: &proposal.proposal_digest,
            base_digest: &proposal.base_digest,
            candidate_digest: &proposal.candidate_digest,
            previous_published_digest,
            restored_from_digest: &proposal.restored_from_digest,
            dataset_receipt_ids,
        },
    )
}

/// A proposal whose candidate holds exactly `members` on top of the
/// published head: a rollback (`restored_from_digest`) or a package import
/// (`source_package_digest`). Members absent from `members` become removals.
pub struct ReplacementProposal<'a> {
    pub namespace: &'a str,
    pub branch_id: &'a str,
    pub proposal_id: &'a str,
    pub members: Vec<DefinitionMember>,
    pub restored_from_digest: &'a str,
    pub migration_plan_digest: &'a str,
    pub source_package_digest: &'a str,
    pub source_commit: &'a str,
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

pub fn proposal_content_digest(input: &PreparedProposalDigestInput<'_>) -> Result<String, String> {
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
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    dataset_receipt_ids: &'a [String],
}

#[derive(Serialize)]
pub struct PreparedProposalDigestInput<'a> {
    pub namespace: &'a str,
    pub branch_id: &'a str,
    pub proposal_id: &'a str,
    pub base_digest: &'a str,
    pub candidate_digest: &'a str,
    pub eval_plan_digests: &'a [String],
    pub named_foreign_digests: &'a [String],
    #[serde(skip_serializing_if = "str::is_empty")]
    pub restored_from_digest: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub migration_plan_digest: &'a str,
    /// Omitted when false, so digests of earlier proposals are unchanged.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub major_revision: bool,
    /// Omitted when empty, so digests of earlier proposals are unchanged.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub source_package_digest: &'a str,
    /// Omitted when empty, so digests of earlier proposals are unchanged.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub source_commit: &'a str,
    /// Omitted when empty, so v1 proposal digests are unchanged.
    #[serde(skip_serializing_if = "<[DatasetProposalAttachment]>::is_empty")]
    pub dataset_proposals: &'a [DatasetProposalAttachment],
}

/// A Git object id: 7 to 64 lowercase hex digits (abbreviated, SHA-1 or SHA-256).
pub fn validate_source_commit(commit: &str) -> Result<(), String> {
    if (7..=64).contains(&commit.len())
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("source_commit must be 7 to 64 lowercase hex digits".into())
    }
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
            dataset_proposals: Vec::new(),
            tenant: String::new(),
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
        assert_eq!(first.request_digest, second.request_digest);
        assert_eq!(first.eval_plan_digests, vec![digest('c'), digest('e')]);
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
            source_commit: String::new(),
            dataset_proposals: Vec::new(),
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
            source_commit: "",
            dataset_proposals: &[],
        })
        .unwrap();
        proposal.verify().unwrap();
        proposal.status = STATUS_CLOSED.into();
        proposal.verify().unwrap();
    }

    /// Attachments bump the contract to v2; without them the stored v1 body
    /// and request digest are what older binaries already wrote.
    #[test]
    fn attachments_select_contract_v2_and_v1_stays_unchanged() {
        // Pinned: the request digest a v1 binary computes for this request.
        assert_eq!(
            create_request().prepare().unwrap().request_digest,
            "sha256:34902c5f002342da3fceb691b76d9800ecd991510e56efb8143f05435c148550"
        );
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
            status: STATUS_OPEN.into(),
            created_by: "author".into(),
            created_at_ms: 1,
            updated_at_ms: 1,
            receipt_id: String::new(),
            close_reason_code: String::new(),
            restored_from_digest: String::new(),
            migration_plan_digest: String::new(),
            major_revision: false,
            source_package_digest: String::new(),
            source_commit: String::new(),
            dataset_proposals: Vec::new(),
        };
        proposal.proposal_digest = proposal.content_digest().unwrap();
        proposal.verify().unwrap();
        assert!(
            !serde_json::to_string(&proposal)
                .unwrap()
                .contains("dataset_proposals")
        );

        let v1 = proposal.clone();
        proposal.dataset_proposals = vec![DatasetProposalAttachment {
            dataset_id: "orders".into(),
            proposal_id: digest('d'),
            parent_version_id: "v1".into(),
            branch_digest: digest('c'),
            tenant: String::new(),
        }];
        proposal.proposal_digest = proposal.content_digest().unwrap();
        assert_ne!(proposal.proposal_digest, v1.proposal_digest);
        assert!(
            proposal.verify().is_err(),
            "attachments under v1 must not verify"
        );
        proposal.contract_version =
            DefinitionProposal::contract_version_for(&proposal.dataset_proposals).into();
        assert_eq!(proposal.contract_version, PROPOSAL_CONTRACT_VERSION_V2);
        proposal.verify().unwrap();

        let mut empty_v2 = v1;
        empty_v2.contract_version = PROPOSAL_CONTRACT_VERSION_V2.into();
        assert!(
            empty_v2.verify().is_err(),
            "v2 without attachments must not verify"
        );
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
