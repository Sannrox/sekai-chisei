//! Dataset branches and their governed merge (#1444, ADR 0119).
//!
//! A branch is one working copy of a dataset, forked from a version. Until
//! its first write it reads that base version, so creating a branch copies
//! nothing. A merge goes through a proposal that pins the branch digest and
//! the parent head; a different principal merges it, and the merge writes
//! exactly one new parent version with a receipt.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const BRANCH_NOT_FOUND: &str = "dataset branch not found";
pub const BRANCH_EXISTS: &str = "dataset branch already exists";
pub const BRANCH_NAME_INVALID: &str =
    "dataset branch name must be 1-64 characters of [A-Za-z0-9._-]";
pub const PROPOSAL_NOT_FOUND: &str = "dataset branch proposal not found";
pub const PROPOSAL_NOT_OPEN: &str = "dataset branch proposal is not open";
pub const PROPOSAL_SELF_MERGE: &str = "a dataset branch proposal is merged by another principal";
pub const PROPOSAL_STALE_PARENT: &str =
    "the parent dataset changed since the proposal; propose again";
pub const PROPOSAL_STALE_BRANCH: &str = "the branch changed since the proposal; propose again";

pub const BRANCH_RUN_ISOLATED: &str =
    "an isolated-process transform cannot run on a dataset branch";
pub const BRANCH_RUN_RAISES_MARKING: &str =
    "this branch run would raise the output marking; run it on the parent first";

pub const STATUS_OPEN: &str = "open";
pub const STATUS_MERGED: &str = "merged";
pub const STATUS_CLOSED: &str = "closed";

/// One open branch of a dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DatasetBranch {
    pub dataset_id: String,
    pub name: String,
    /// Version the branch forked from; empty for a dataset with no version.
    pub base_version_id: String,
    /// False until the first write, while the branch still reads its base.
    pub written: bool,
    /// Unique per creation, so a deleted and recreated branch of the same
    /// name gets fresh proposals.
    pub incarnation: String,
    pub created_by: String,
    pub tenant: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreateDatasetBranch {
    pub dataset_id: String,
    pub name: String,
    /// Fork point; empty means the dataset's latest version.
    pub from_version_id: String,
    pub actor: String,
    pub tenant: String,
}

/// A request to merge a branch, pinned to what the proposer reviewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DatasetBranchProposal {
    pub id: String,
    pub dataset_id: String,
    pub branch: String,
    /// Parent head the merge must still find; empty when it had no version.
    pub parent_version_id: String,
    pub branch_digest: String,
    pub proposer: String,
    pub tenant: String,
    pub status: String,
    pub merged_by: String,
    pub merged_version_id: String,
    pub receipt_id: String,
    pub created_at_ms: i64,
    pub merged_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProposeDatasetBranch {
    pub dataset_id: String,
    pub branch: String,
    pub actor: String,
    pub tenant: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MergeDatasetBranch {
    pub dataset_id: String,
    pub proposal_id: String,
    pub actor: String,
    pub tenant: String,
    pub reason: String,
}

/// What a transform run on a branch read and wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DatasetBranchRun {
    pub transform_id: String,
    pub branch: String,
    pub output_dataset_id: String,
    pub rows_written: i64,
    /// Input datasets read from the branch; the others read the parent.
    pub branch_inputs: Vec<String>,
    pub markings_out: String,
}

/// Branch head against the parent's live rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DatasetBranchDiff {
    pub columns_added: Vec<String>,
    pub columns_removed: Vec<String>,
    pub parent_rows: i64,
    pub branch_rows: i64,
    pub parent_digest: String,
    pub branch_digest: String,
}

impl DatasetBranchDiff {
    pub fn identical(&self) -> bool {
        self.parent_digest == self.branch_digest
    }
}

pub fn validate_branch_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(BRANCH_NAME_INVALID.into())
    }
}

/// Order-independent digest of a row multiset. Keys are sorted, so the same
/// rows always give the same digest whatever map order produced them.
pub fn rows_digest(rows: &[HashMap<String, String>]) -> String {
    let mut encoded: Vec<String> = rows
        .iter()
        .map(|row| {
            let sorted: BTreeMap<&String, &String> = row.iter().collect();
            serde_json::to_string(&sorted).unwrap_or_default()
        })
        .collect();
    encoded.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.dataset-rows\n");
    for row in &encoded {
        hasher.update(row.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Compare branch rows with the parent's rows by column set, count and digest.
pub fn diff_rows(
    parent: &[HashMap<String, String>],
    branch: &[HashMap<String, String>],
) -> DatasetBranchDiff {
    let columns = |rows: &[HashMap<String, String>]| -> BTreeSet<String> {
        rows.iter().flat_map(|row| row.keys().cloned()).collect()
    };
    let (parent_columns, branch_columns) = (columns(parent), columns(branch));
    DatasetBranchDiff {
        columns_added: branch_columns
            .difference(&parent_columns)
            .cloned()
            .collect(),
        columns_removed: parent_columns
            .difference(&branch_columns)
            .cloned()
            .collect(),
        parent_rows: parent.len() as i64,
        branch_rows: branch.len() as i64,
        parent_digest: rows_digest(parent),
        branch_digest: rows_digest(branch),
    }
}

/// What a redaction or erasure does to one branch working-copy row; `None`
/// stands for a row that no longer decodes.
pub enum BranchRowEdit {
    Keep,
    Replace(HashMap<String, String>),
    Delete,
}

/// Stable proposal id: one per pinned (branch digest, parent head) pair of
/// one branch incarnation.
pub fn proposal_id(
    dataset_id: &str,
    branch: &DatasetBranch,
    parent_version_id: &str,
    branch_digest: &str,
) -> String {
    digest(
        b"sekai.dataset-branch-proposal\n",
        &[
            dataset_id,
            &branch.name,
            &branch.incarnation,
            parent_version_id,
            branch_digest,
        ],
    )
}

/// Receipt id of a merge, binding what was merged to the version it made.
pub fn merge_receipt_id(proposal: &DatasetBranchProposal, merged_version_id: &str) -> String {
    digest(
        b"sekai.dataset-branch-merge\n",
        &[
            &proposal.dataset_id,
            &proposal.id,
            &proposal.parent_version_id,
            &proposal.branch_digest,
            merged_version_id,
        ],
    )
}

fn digest(domain: &[u8], parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
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

    fn row(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn digest_ignores_row_order_and_diff_names_column_changes() {
        let a = vec![
            row(&[("id", "1"), ("v", "x")]),
            row(&[("id", "2"), ("v", "y")]),
        ];
        let reordered = vec![a[1].clone(), a[0].clone()];
        assert_eq!(rows_digest(&a), rows_digest(&reordered));
        let b = vec![row(&[("id", "1"), ("w", "x")])];
        let diff = diff_rows(&a, &b);
        assert_eq!(diff.columns_added, vec!["w".to_string()]);
        assert_eq!(diff.columns_removed, vec!["v".to_string()]);
        assert_eq!((diff.parent_rows, diff.branch_rows), (2, 1));
        assert!(!diff.identical());
        assert!(diff_rows(&a, &reordered).identical());
    }

    #[test]
    fn branch_names_are_bounded_identifiers() {
        assert!(validate_branch_name("fix-totals.v2_a").is_ok());
        for bad in ["", "a b", "a/b", &"x".repeat(65)] {
            assert!(validate_branch_name(bad).is_err(), "{bad}");
        }
    }
}
