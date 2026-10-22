//! SQLite storage for dataset branches and their governed merge (ADR 0119).
//!
//! A branch row exists only while the branch is open. Its working copy lives
//! in `sekai_dataset_branch_rows` after the first write; before that, reads
//! fall back to the base version. Merge and delete drop the working copy, and
//! the proposal keeps the record.

use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::{
    mark_consuming_transform_outputs_stale_tx, parse_partition_keys, query_dataset_version_rows_tx,
    reindex_dataset_partition_keys, snapshot_dataset_version_tx,
};
use crate::sekai::dataset_branch::{
    self, BranchRowEdit, CreateDatasetBranch, DatasetBranch, DatasetBranchDiff,
    DatasetBranchProposal, MergeDatasetBranch, ProposeDatasetBranch,
};
use crate::sekai::dataset_version::{self, encode_row_map};
use rusqlite::{OptionalExtension, Transaction, params};
use std::collections::HashMap;

pub(crate) fn migrate_dataset_branches(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sekai_dataset_branches (
            dataset_id TEXT NOT NULL,
            name TEXT NOT NULL,
            base_version_id TEXT NOT NULL DEFAULT '',
            written INTEGER NOT NULL DEFAULT 0,
            incarnation TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            tenant TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (dataset_id, name)
        );
        CREATE TABLE IF NOT EXISTS sekai_dataset_branch_rows (
            dataset_id TEXT NOT NULL,
            name TEXT NOT NULL,
            row_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (dataset_id, name, row_id)
        );
        CREATE TABLE IF NOT EXISTS sekai_dataset_branch_proposals (
            id TEXT PRIMARY KEY,
            dataset_id TEXT NOT NULL,
            branch TEXT NOT NULL,
            parent_version_id TEXT NOT NULL DEFAULT '',
            branch_digest TEXT NOT NULL,
            proposer TEXT NOT NULL,
            tenant TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            merged_by TEXT NOT NULL DEFAULT '',
            merged_version_id TEXT NOT NULL DEFAULT '',
            receipt_id TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL,
            merged_at_ms INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sekai_dataset_branch_proposals_branch
            ON sekai_dataset_branch_proposals(dataset_id, branch, status);",
    )
    .map_err(|error| error.to_string())
}

impl SekaiDb {
    pub fn create_dataset_branch(
        &self,
        request: &CreateDatasetBranch,
    ) -> Result<DatasetBranch, String> {
        dataset_branch::validate_branch_name(&request.name)?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        dataset_exists(&tx, &request.dataset_id)?;
        let base_version_id = if request.from_version_id.is_empty() {
            latest_version_id(&tx, &request.dataset_id)?
        } else {
            let purged: Option<bool> = tx
                .query_row(
                    "SELECT purged FROM sekai_dataset_versions
                     WHERE dataset_id = ?1 AND version_id = ?2",
                    params![request.dataset_id, request.from_version_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            match purged {
                None => return Err(dataset_version::DATASET_VERSION_NOT_FOUND.into()),
                Some(true) => return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into()),
                Some(false) => request.from_version_id.clone(),
            }
        };
        let branch = DatasetBranch {
            dataset_id: request.dataset_id.clone(),
            name: request.name.clone(),
            base_version_id,
            written: false,
            incarnation: uuid::Uuid::new_v4().to_string(),
            created_by: request.actor.clone(),
            tenant: request.tenant.clone(),
            created_at_ms: dataset_version::now_ms(),
        };
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO sekai_dataset_branches
                 (dataset_id, name, base_version_id, written, incarnation, created_by, tenant,
                  created_at_ms)
                 VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7)",
                params![
                    branch.dataset_id,
                    branch.name,
                    branch.base_version_id,
                    branch.incarnation,
                    branch.created_by,
                    branch.tenant,
                    branch.created_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        if inserted == 0 {
            return Err(dataset_branch::BRANCH_EXISTS.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(branch)
    }

    pub fn list_dataset_branches(&self, dataset_id: &str) -> Result<Vec<DatasetBranch>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT dataset_id, name, base_version_id, written, incarnation, created_by, tenant,
                        created_at_ms
                 FROM sekai_dataset_branches WHERE dataset_id = ?1 ORDER BY name",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![dataset_id], map_branch)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    /// The branch head: its working copy, or its base version before a write.
    pub fn dataset_branch_rows(
        &self,
        dataset_id: &str,
        name: &str,
    ) -> Result<Vec<HashMap<String, String>>, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let branch = load_branch(&tx, dataset_id, name)?;
        branch_rows_tx(&tx, &branch)
    }

    /// Write rows to the branch only. `replace` drops the head first; an
    /// append onto an unwritten branch first copies its base version.
    pub fn write_dataset_branch_rows(
        &self,
        dataset_id: &str,
        name: &str,
        rows: &[HashMap<String, String>],
        replace: bool,
    ) -> Result<i64, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let branch = load_branch(&tx, dataset_id, name)?;
        let mut head = if replace {
            Vec::new()
        } else {
            branch_rows_tx(&tx, &branch)?
        };
        head.extend(rows.iter().cloned());
        tx.execute(
            "DELETE FROM sekai_dataset_branch_rows WHERE dataset_id = ?1 AND name = ?2",
            params![dataset_id, name],
        )
        .map_err(|error| error.to_string())?;
        for (row_id, row) in head.iter().enumerate() {
            tx.execute(
                "INSERT INTO sekai_dataset_branch_rows (dataset_id, name, row_id, data)
                 VALUES (?1, ?2, ?3, ?4)",
                params![dataset_id, name, row_id as i64, encode_row_map(row)?],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute(
            "UPDATE sekai_dataset_branches SET written = 1 WHERE dataset_id = ?1 AND name = ?2",
            params![dataset_id, name],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(head.len() as i64)
    }

    pub fn compare_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
    ) -> Result<DatasetBranchDiff, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let branch = load_branch(&tx, dataset_id, name)?;
        let head = branch_rows_tx(&tx, &branch)?;
        Ok(dataset_branch::diff_rows(
            &live_rows(&tx, dataset_id)?,
            &head,
        ))
    }

    /// Delete a branch and its working copy, closing its open proposals.
    pub fn delete_dataset_branch(&self, dataset_id: &str, name: &str) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        load_branch(&tx, dataset_id, name)?;
        drop_branch(&tx, dataset_id, name)?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// Pin the branch head and the parent head for review. Proposing the same
    /// pair again returns the existing proposal.
    pub fn propose_dataset_branch(
        &self,
        request: &ProposeDatasetBranch,
    ) -> Result<DatasetBranchProposal, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let branch = load_branch(&tx, &request.dataset_id, &request.branch)?;
        // A branch is proposed only within the tenant that created it.
        if branch.tenant != request.tenant {
            return Err(dataset_branch::BRANCH_NOT_FOUND.into());
        }
        let branch_digest = dataset_branch::rows_digest(&branch_rows_tx(&tx, &branch)?);
        let parent_version_id = latest_version_id(&tx, &request.dataset_id)?;
        let id = dataset_branch::proposal_id(
            &request.dataset_id,
            &branch,
            &parent_version_id,
            &branch_digest,
        );
        tx.execute(
            "INSERT OR IGNORE INTO sekai_dataset_branch_proposals
             (id, dataset_id, branch, parent_version_id, branch_digest, proposer, tenant,
              status, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                request.dataset_id,
                request.branch,
                parent_version_id,
                branch_digest,
                request.actor,
                request.tenant,
                dataset_branch::STATUS_OPEN,
                dataset_version::now_ms()
            ],
        )
        .map_err(|error| error.to_string())?;
        let proposal = load_proposal(&tx, &request.dataset_id, &id)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(proposal)
    }

    pub fn get_dataset_branch_proposal(
        &self,
        dataset_id: &str,
        id: &str,
    ) -> Result<DatasetBranchProposal, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        load_proposal(&tx, dataset_id, id)
    }

    /// Merge a proposal as exactly one new parent version with a receipt. A
    /// replay of a merged proposal returns it unchanged.
    pub fn merge_dataset_branch(
        &self,
        request: &MergeDatasetBranch,
    ) -> Result<DatasetBranchProposal, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut proposal = load_proposal(&tx, &request.dataset_id, &request.proposal_id)?;
        if proposal.status == dataset_branch::STATUS_MERGED {
            return Ok(proposal);
        }
        check_mergeable(&proposal, request)?;
        if latest_version_id(&tx, &request.dataset_id)? != proposal.parent_version_id {
            return Err(dataset_branch::PROPOSAL_STALE_PARENT.into());
        }
        let branch = load_branch(&tx, &request.dataset_id, &proposal.branch)
            .map_err(|_| dataset_branch::PROPOSAL_STALE_BRANCH.to_string())?;
        let head = branch_rows_tx(&tx, &branch)?;
        if dataset_branch::rows_digest(&head) != proposal.branch_digest {
            return Err(dataset_branch::PROPOSAL_STALE_BRANCH.into());
        }
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE dataset_id = ?1",
            params![request.dataset_id],
        )
        .map_err(|error| error.to_string())?;
        for row in &head {
            tx.execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data) VALUES (?1, ?2)",
                params![request.dataset_id, encode_row_map(row)?],
            )
            .map_err(|error| error.to_string())?;
        }
        let keys_json: String = tx
            .query_row(
                "SELECT partition_keys FROM sekai_datasets WHERE id = ?1",
                params![request.dataset_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        reindex_dataset_partition_keys(
            &tx,
            &request.dataset_id,
            &parse_partition_keys(&keys_json)?,
        )?;
        let now = dataset_version::now_ms();
        mark_consuming_transform_outputs_stale_tx(&tx, &request.dataset_id, &proposal.id, now)?;
        let version = snapshot_dataset_version_tx(
            &tx,
            &request.dataset_id,
            &request.actor,
            &request.tenant,
            &merge_reason(request, &proposal),
            "",
            now,
        )?;
        proposal.status = dataset_branch::STATUS_MERGED.into();
        proposal.merged_by = request.actor.clone();
        proposal.merged_version_id = version.version_id.clone();
        proposal.receipt_id = dataset_branch::merge_receipt_id(&proposal, &version.version_id);
        proposal.merged_at_ms = now;
        tx.execute(
            "UPDATE sekai_dataset_branch_proposals
             SET status = ?1, merged_by = ?2, merged_version_id = ?3, receipt_id = ?4,
                 merged_at_ms = ?5
             WHERE id = ?6",
            params![
                proposal.status,
                proposal.merged_by,
                proposal.merged_version_id,
                proposal.receipt_id,
                proposal.merged_at_ms,
                proposal.id
            ],
        )
        .map_err(|error| error.to_string())?;
        drop_branch(&tx, &request.dataset_id, &proposal.branch)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(proposal)
    }
}

/// Checks that need no storage: open, another principal, the same tenant.
pub(crate) fn check_mergeable(
    proposal: &DatasetBranchProposal,
    request: &MergeDatasetBranch,
) -> Result<(), String> {
    if proposal.status != dataset_branch::STATUS_OPEN {
        return Err(dataset_branch::PROPOSAL_NOT_OPEN.into());
    }
    if proposal.proposer == request.actor {
        return Err(dataset_branch::PROPOSAL_SELF_MERGE.into());
    }
    if proposal.tenant != request.tenant {
        return Err(dataset_branch::PROPOSAL_NOT_FOUND.into());
    }
    Ok(())
}

pub(crate) fn merge_reason(
    request: &MergeDatasetBranch,
    proposal: &DatasetBranchProposal,
) -> String {
    if request.reason.trim().is_empty() {
        format!("branch-merge:{}", proposal.branch)
    } else {
        request.reason.clone()
    }
}

fn dataset_exists(tx: &Transaction<'_>, dataset_id: &str) -> Result<(), String> {
    tx.query_row(
        "SELECT 1 FROM sekai_datasets WHERE id = ?1",
        params![dataset_id],
        |_| Ok(()),
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| dataset_version::DATASET_NOT_FOUND.to_string())
}

fn latest_version_id(tx: &Transaction<'_>, dataset_id: &str) -> Result<String, String> {
    tx.query_row(
        "SELECT version_id FROM sekai_dataset_versions
         WHERE dataset_id = ?1 ORDER BY seq DESC LIMIT 1",
        params![dataset_id],
        |row| row.get(0),
    )
    .optional()
    .map(Option::unwrap_or_default)
    .map_err(|error| error.to_string())
}

fn map_branch(row: &rusqlite::Row<'_>) -> rusqlite::Result<DatasetBranch> {
    Ok(DatasetBranch {
        dataset_id: row.get(0)?,
        name: row.get(1)?,
        base_version_id: row.get(2)?,
        written: row.get::<_, i64>(3)? != 0,
        incarnation: row.get(4)?,
        created_by: row.get(5)?,
        tenant: row.get(6)?,
        created_at_ms: row.get(7)?,
    })
}

fn load_branch(
    tx: &Transaction<'_>,
    dataset_id: &str,
    name: &str,
) -> Result<DatasetBranch, String> {
    tx.query_row(
        "SELECT dataset_id, name, base_version_id, written, incarnation, created_by, tenant, created_at_ms
         FROM sekai_dataset_branches WHERE dataset_id = ?1 AND name = ?2",
        params![dataset_id, name],
        map_branch,
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| dataset_branch::BRANCH_NOT_FOUND.to_string())
}

fn branch_rows_tx(
    tx: &Transaction<'_>,
    branch: &DatasetBranch,
) -> Result<Vec<HashMap<String, String>>, String> {
    if !branch.written {
        if branch.base_version_id.is_empty() {
            return Ok(Vec::new());
        }
        return query_dataset_version_rows_tx(tx, &branch.dataset_id, &branch.base_version_id);
    }
    let mut stmt = tx
        .prepare(
            "SELECT data FROM sekai_dataset_branch_rows
             WHERE dataset_id = ?1 AND name = ?2 ORDER BY row_id",
        )
        .map_err(|error| error.to_string())?;
    decode_rows(&mut stmt, params![branch.dataset_id, branch.name])
}

fn live_rows(
    tx: &Transaction<'_>,
    dataset_id: &str,
) -> Result<Vec<HashMap<String, String>>, String> {
    let mut stmt = tx
        .prepare("SELECT data FROM sekai_dataset_rows WHERE dataset_id = ?1 ORDER BY id")
        .map_err(|error| error.to_string())?;
    decode_rows(&mut stmt, params![dataset_id])
}

fn decode_rows(
    stmt: &mut rusqlite::Statement<'_>,
    args: impl rusqlite::Params,
) -> Result<Vec<HashMap<String, String>>, String> {
    let encoded = stmt
        .query_map(args, |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    encoded
        .iter()
        .map(|data| serde_json::from_str(data).map_err(|error| error.to_string()))
        .collect()
}

fn drop_branch(tx: &Transaction<'_>, dataset_id: &str, name: &str) -> Result<(), String> {
    for sql in [
        "DELETE FROM sekai_dataset_branch_rows WHERE dataset_id = ?1 AND name = ?2",
        "DELETE FROM sekai_dataset_branches WHERE dataset_id = ?1 AND name = ?2",
    ] {
        tx.execute(sql, params![dataset_id, name])
            .map_err(|error| error.to_string())?;
    }
    tx.execute(
        "UPDATE sekai_dataset_branch_proposals SET status = ?3
         WHERE dataset_id = ?1 AND branch = ?2 AND status = ?4",
        params![
            dataset_id,
            name,
            dataset_branch::STATUS_CLOSED,
            dataset_branch::STATUS_OPEN
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn load_proposal(
    tx: &Transaction<'_>,
    dataset_id: &str,
    id: &str,
) -> Result<DatasetBranchProposal, String> {
    tx.query_row(
        "SELECT id, dataset_id, branch, parent_version_id, branch_digest, proposer, tenant,
                status, merged_by, merged_version_id, receipt_id, created_at_ms, merged_at_ms
         FROM sekai_dataset_branch_proposals WHERE id = ?1 AND dataset_id = ?2",
        params![id, dataset_id],
        |row| {
            Ok(DatasetBranchProposal {
                id: row.get(0)?,
                dataset_id: row.get(1)?,
                branch: row.get(2)?,
                parent_version_id: row.get(3)?,
                branch_digest: row.get(4)?,
                proposer: row.get(5)?,
                tenant: row.get(6)?,
                status: row.get(7)?,
                merged_by: row.get(8)?,
                merged_version_id: row.get(9)?,
                receipt_id: row.get(10)?,
                created_at_ms: row.get(11)?,
                merged_at_ms: row.get(12)?,
            })
        },
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| dataset_branch::PROPOSAL_NOT_FOUND.to_string())
}

/// Apply `edit` to every branch working-copy row of a dataset. Redaction and
/// subject erasure call this so a branch never keeps a value they removed.
pub(crate) fn edit_branch_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    edit: &dyn Fn(Option<HashMap<String, String>>) -> BranchRowEdit,
) -> Result<(), String> {
    let exists: Option<String> = tx
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table'
             AND name = 'sekai_dataset_branch_rows'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if exists.is_none() {
        return Ok(());
    }
    let rows: Vec<(String, i64, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT name, row_id, data FROM sekai_dataset_branch_rows WHERE dataset_id = ?1",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![dataset_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())?
    };
    for (name, row_id, data) in rows {
        match edit(serde_json::from_str(&data).ok()) {
            BranchRowEdit::Keep => {}
            BranchRowEdit::Replace(values) => {
                tx.execute(
                    "UPDATE sekai_dataset_branch_rows SET data = ?1
                     WHERE dataset_id = ?2 AND name = ?3 AND row_id = ?4",
                    params![encode_row_map(&values)?, dataset_id, name, row_id],
                )
                .map_err(|error| error.to_string())?;
            }
            BranchRowEdit::Delete => {
                tx.execute(
                    "DELETE FROM sekai_dataset_branch_rows
                     WHERE dataset_id = ?1 AND name = ?2 AND row_id = ?3",
                    params![dataset_id, name, row_id],
                )
                .map_err(|error| error.to_string())?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::db::dataset::DatasetBackend;
    use crate::sekai::dataset::{ColumnDef, Dataset, RowQuery};
    use crate::sekai::dataset_branch::{
        self, CreateDatasetBranch, MergeDatasetBranch, ProposeDatasetBranch,
    };
    use std::collections::HashMap;

    fn row(id: &str, value: &str) -> HashMap<String, String> {
        HashMap::from([("id".into(), id.into()), ("value".into(), value.into())])
    }

    fn live(db: &dyn DatasetBackend, id: &str) -> Vec<HashMap<String, String>> {
        db.query_rows(id, &RowQuery::default()).unwrap()
    }

    /// The #1444 acceptance on one backend: a branch never changes the parent,
    /// a merge makes exactly one version with a receipt, deleting a branch
    /// frees its working copy, and retention keeps an open branch's base.
    fn exercise(db: &dyn DatasetBackend) {
        let id = format!("ds-{}", uuid::Uuid::new_v4().as_simple());
        db.create_dataset(&Dataset {
            id: id.clone(),
            name: id.clone(),
            columns: ["id", "value"]
                .map(|name| ColumnDef {
                    name: name.into(),
                    col_type: "string".into(),
                    classification: "internal".into(),
                })
                .to_vec(),
            object_id: String::new(),
            created: 0,
            partition_keys: Vec::new(),
        })
        .unwrap();
        db.append_rows(&id, &[row("1", "a"), row("2", "b")])
            .unwrap();
        let versions = db.list_dataset_versions(&id).unwrap();
        let base = versions.last().unwrap().version_id.clone();

        let create = |name: &str| CreateDatasetBranch {
            dataset_id: id.clone(),
            name: name.into(),
            actor: "dev".into(),
            tenant: "t1".into(),
            ..Default::default()
        };
        let branch = db.create_dataset_branch(&create("fix")).unwrap();
        assert_eq!(branch.base_version_id, base);
        assert!(!branch.written);
        assert_eq!(
            db.create_dataset_branch(&create("fix")).unwrap_err(),
            dataset_branch::BRANCH_EXISTS
        );
        // Unwritten, the branch reads its base version.
        assert_eq!(db.dataset_branch_rows(&id, "fix").unwrap().len(), 2);
        db.write_dataset_branch_rows(&id, "fix", &[row("3", "c")], false)
            .unwrap();
        assert_eq!(db.dataset_branch_rows(&id, "fix").unwrap().len(), 3);
        let diff = db.compare_dataset_branch(&id, "fix").unwrap();
        assert_eq!((diff.parent_rows, diff.branch_rows), (2, 3));
        assert!(!diff.identical());
        // The parent is untouched by branch work.
        assert_eq!(live(db, &id).len(), 2);
        assert_eq!(db.list_dataset_versions(&id).unwrap(), versions);

        let propose = ProposeDatasetBranch {
            dataset_id: id.clone(),
            branch: "fix".into(),
            actor: "dev".into(),
            tenant: "t1".into(),
        };
        assert_eq!(
            db.propose_dataset_branch(&ProposeDatasetBranch {
                tenant: "t2".into(),
                ..propose.clone()
            })
            .unwrap_err(),
            dataset_branch::BRANCH_NOT_FOUND
        );
        let proposal = db.propose_dataset_branch(&propose).unwrap();
        assert_eq!(db.propose_dataset_branch(&propose).unwrap(), proposal);
        let merge = |actor: &str| MergeDatasetBranch {
            dataset_id: id.clone(),
            proposal_id: proposal.id.clone(),
            actor: actor.into(),
            tenant: "t1".into(),
            reason: String::new(),
        };
        assert_eq!(
            db.merge_dataset_branch(&merge("dev")).unwrap_err(),
            dataset_branch::PROPOSAL_SELF_MERGE
        );
        let merged = db.merge_dataset_branch(&merge("reviewer")).unwrap();
        assert_eq!(merged.status, dataset_branch::STATUS_MERGED);
        assert!(merged.receipt_id.starts_with("sha256:"));
        let after = db.list_dataset_versions(&id).unwrap();
        assert_eq!(after.len(), versions.len() + 1);
        assert_eq!(after.last().unwrap().version_id, merged.merged_version_id);
        assert_eq!(live(db, &id).len(), 3);
        // A replay returns the merge and makes no second version.
        assert_eq!(db.merge_dataset_branch(&merge("reviewer")).unwrap(), merged);
        assert_eq!(db.list_dataset_versions(&id).unwrap().len(), after.len());
        assert!(db.list_dataset_branches(&id).unwrap().is_empty());

        // A proposal goes stale when the parent moves on.
        db.create_dataset_branch(&create("late")).unwrap();
        db.write_dataset_branch_rows(&id, "late", &[row("9", "z")], true)
            .unwrap();
        let late = db
            .propose_dataset_branch(&ProposeDatasetBranch {
                branch: "late".into(),
                ..propose.clone()
            })
            .unwrap();
        db.append_rows(&id, &[row("4", "d")]).unwrap();
        assert_eq!(
            db.merge_dataset_branch(&MergeDatasetBranch {
                proposal_id: late.id.clone(),
                ..merge("reviewer")
            })
            .unwrap_err(),
            dataset_branch::PROPOSAL_STALE_PARENT
        );

        // Retention keeps an open branch's base; deleting the branch frees
        // its working copy and closes its proposal.
        let kept = db.create_dataset_branch(&create("kept")).unwrap();
        db.set_dataset_version_retention(&id, 1).unwrap();
        db.append_rows(&id, &[row("5", "e")]).unwrap();
        assert_eq!(db.dataset_branch_rows(&id, "kept").unwrap().len(), 4);
        assert!(
            !db.get_dataset_version(&id, &kept.base_version_id, 0)
                .unwrap()
                .purged
        );
        db.delete_dataset_branch(&id, "late").unwrap();
        assert_eq!(
            db.dataset_branch_rows(&id, "late").unwrap_err(),
            dataset_branch::BRANCH_NOT_FOUND
        );
        assert_eq!(
            db.get_dataset_branch_proposal(&id, &late.id)
                .unwrap()
                .status,
            dataset_branch::STATUS_CLOSED
        );

        // A recreated branch with the same rows gets a fresh proposal, and
        // redaction reaches its working copy.
        db.create_dataset_branch(&create("late")).unwrap();
        db.write_dataset_branch_rows(&id, "late", &[row("9", "z")], true)
            .unwrap();
        let again = db
            .propose_dataset_branch(&ProposeDatasetBranch {
                branch: "late".into(),
                ..propose.clone()
            })
            .unwrap();
        assert_ne!(again.id, late.id);
        assert_eq!(again.status, dataset_branch::STATUS_OPEN);
        db.redact_dataset_fields(&id, "internal", &[]).unwrap();
        assert!(
            db.dataset_branch_rows(&id, "late")
                .unwrap()
                .iter()
                .all(|row| row.values().all(|value| value == "[redacted]"))
        );
    }

    #[test]
    fn sqlite_branches_isolate_merge_once_and_free_on_delete() {
        exercise(&crate::db::sekai::SekaiDb::new(":memory:").unwrap());
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_branches_isolate_merge_once_and_free_on_delete() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        exercise(&db.unwrap());
    }
}
