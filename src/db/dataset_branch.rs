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
    DatasetBranchProposal, DatasetBranchRun, MergeDatasetBranch, ProposeDatasetBranch,
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
            ON sekai_dataset_branch_proposals(dataset_id, branch, status);
        CREATE TABLE IF NOT EXISTS sekai_transform_replays (
            id TEXT PRIMARY KEY,
            namespace TEXT NOT NULL,
            transform_id TEXT NOT NULL,
            output_dataset_id TEXT NOT NULL,
            tenant TEXT NOT NULL DEFAULT '',
            record_json TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sekai_transform_replays_transform
            ON sekai_transform_replays(namespace, transform_id, created_at_ms);",
    )
    .map_err(|error| error.to_string())
}

impl SekaiDb {
    pub fn create_dataset_branch(
        &self,
        request: &CreateDatasetBranch,
    ) -> Result<DatasetBranch, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let branch = create_branch_tx(&tx, request)?;
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
        let written = write_branch_rows_tx(&tx, dataset_id, name, rows, replace)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(written)
    }

    /// Fill branch `name` from its base version with `compute` if it has not
    /// been written, only while it is still `incarnation`: the check, the
    /// base read and the write share one immediate transaction, so a
    /// recreated branch is never overwritten. A written branch is returned
    /// as it stands. Returns the base rows and the branch rows.
    pub fn fill_dataset_branch_from_base(
        &self,
        dataset_id: &str,
        name: &str,
        incarnation: &str,
        compute: &crate::sekai::dataset_branch::BranchCompute<'_>,
    ) -> Result<
        (
            crate::sekai::dataset_branch::BranchRows,
            crate::sekai::dataset_branch::BranchRows,
        ),
        String,
    > {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let branch = load_branch(&tx, dataset_id, name)
            .map_err(|_| dataset_branch::BRANCH_CHANGED.to_string())?;
        if branch.incarnation != incarnation {
            return Err(dataset_branch::BRANCH_CHANGED.into());
        }
        let base = if branch.base_version_id.is_empty() {
            Vec::new()
        } else {
            query_dataset_version_rows_tx(&tx, dataset_id, &branch.base_version_id)?
        };
        // Written once: a written branch is the result, so a redaction
        // applied to it since is never undone by recomputing.
        let expected = if branch.written {
            branch_rows_tx(&tx, &branch)?
        } else {
            let columns: String = tx
                .query_row(
                    "SELECT columns FROM sekai_datasets WHERE id = ?1",
                    params![dataset_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            let expected = compute(&crate::sekai::dataset::parse_columns(&columns)?, &base)?;
            write_branch_rows_tx(&tx, dataset_id, name, &expected, true)?;
            expected
        };
        tx.commit().map_err(|error| error.to_string())?;
        Ok((base, expected))
    }

    /// Run a transform on `branch`: each input reads its branch head when
    /// that dataset has the branch, else the parent's live rows; the output
    /// is written to the output dataset's branch only, created on demand.
    /// Nothing on the parent changes: no rows, checkpoint, trigger or
    /// marking stamp. A run whose derived marking would raise the output's
    /// marking is refused, since the branch cannot carry a stricter stamp.
    pub fn run_governed_transform_on_branch(
        &self,
        namespace: &str,
        transform_id: &str,
        branch: &str,
        actor: &str,
        tenant: &str,
        now_ms: i64,
    ) -> Result<DatasetBranchRun, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let transform =
            crate::db::governed_transform::load_transform(&tx, namespace, transform_id)?
                .ok_or("governed transform not found")?;
        let (run, _) = branch_run_tx(
            &tx, namespace, &transform, branch, None, actor, tenant, now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(run)
    }

    /// Run `transform` (as stored or a candidate) over pinned input
    /// versions (dataset id to version id; empty reads an empty input) into
    /// a fresh `branch` of its output, and keep the record `describe` makes
    /// of the run and its rows, in one transaction (#1585): a replay branch
    /// never exists without its record.
    #[allow(clippy::too_many_arguments)]
    pub fn replay_transform_into_branch(
        &self,
        namespace: &str,
        transform: &crate::sekai::governed_transform::GovernedTransform,
        branch: &str,
        pins: &std::collections::BTreeMap<String, String>,
        actor: &str,
        tenant: &str,
        now_ms: i64,
        baseline_version_id: &str,
        definition_digest: &str,
        describe: &crate::sekai::transform_replay::Describe<'_>,
    ) -> Result<crate::sekai::transform_replay::TransformReplay, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current: Option<String> = tx
            .query_row(
                "SELECT definition_digest FROM sekai_governed_transform
                 WHERE namespace = ?1 AND transform_id = ?2",
                params![transform.namespace, transform.transform_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if current.as_deref() != Some(definition_digest) {
            return Err(crate::sekai::transform_replay::REPLAY_TRANSFORM_CHANGED.into());
        }
        let (run, rows) = branch_run_tx(
            &tx,
            namespace,
            transform,
            branch,
            Some(pins),
            actor,
            tenant,
            now_ms,
        )?;
        if !baseline_version_id.is_empty() {
            require_live_version(&tx, &run.output_dataset_id, baseline_version_id)?;
        }
        // The baseline is read in the same transaction as the inputs, so the
        // diff sees one state, and is charged to the transform's memory and
        // time budget (the preview default when it has none).
        let mut budget = crate::sekai::governed_transform::InputLoadBudget::for_preview(transform);
        let baseline = branch_records_budgeted(
            &tx,
            &DatasetBranch {
                dataset_id: run.output_dataset_id.clone(),
                base_version_id: baseline_version_id.into(),
                ..DatasetBranch::default()
            },
            Some(&mut budget),
        )?;
        budget.expire_if_past();
        if let Some(reason) = budget.exceeded {
            return Err(format!("branch run refused: {reason}"));
        }
        let baseline: Vec<HashMap<String, String>> =
            baseline.into_iter().map(|(_, row)| row).collect();
        let replay = describe(&run, &rows, &baseline)?;
        let json =
            serde_json::to_string(&replay.without_rows()).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_transform_replays
             (id, namespace, transform_id, output_dataset_id, tenant, record_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                replay.id,
                replay.namespace,
                replay.transform_id,
                replay.output_dataset_id,
                replay.tenant,
                json,
                replay.created_at_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(replay)
    }

    pub fn get_transform_replay(
        &self,
        id: &str,
    ) -> Result<Option<crate::sekai::transform_replay::TransformReplay>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_transform_replays WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    /// The object types of `namespace` backed by a dataset, with their keys.
    pub fn list_object_type_datasources(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeDatasource>, String> {
        let conn = self.conn();
        let exists: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                 AND name = 'sekai_object_type_datasource'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if exists.is_none() {
            return Ok(Vec::new());
        }
        let mut stmt = conn
            .prepare(
                "SELECT kind, dataset_id, key_column FROM sekai_object_type_datasource
                 WHERE namespace = ?1 ORDER BY kind",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![namespace], |row| {
            Ok(datasource(namespace, row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
    }

    /// Every object type binding of `dataset_id`, in any namespace, as
    /// (namespace, kind).
    pub fn dataset_bindings(&self, dataset_id: &str) -> Result<Vec<(String, String)>, String> {
        let conn = self.conn();
        let exists: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                 AND name = 'sekai_object_type_datasource'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if exists.is_none() {
            return Ok(Vec::new());
        }
        let mut stmt = conn
            .prepare(
                "SELECT namespace, kind FROM sekai_object_type_datasource
                 WHERE dataset_id = ?1 ORDER BY namespace, kind",
            )
            .map_err(|error| error.to_string())?;
        stmt.query_map(params![dataset_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    /// Compare the caller's branch; another tenant's reads as missing.
    pub fn compare_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
        tenant: &str,
    ) -> Result<DatasetBranchDiff, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let branch = load_owned_branch(&tx, dataset_id, name, tenant)?;
        let head = branch_rows_tx(&tx, &branch)?;
        Ok(dataset_branch::diff_rows(
            &live_rows(&tx, dataset_id)?,
            &head,
        ))
    }

    /// Delete a branch and its working copy, closing its open proposals.
    pub fn delete_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
        tenant: &str,
    ) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        load_owned_branch(&tx, dataset_id, name, tenant)?;
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
        if request
            .expected_incarnation
            .as_ref()
            .is_some_and(|expected| *expected != branch.incarnation)
        {
            return Err(dataset_branch::BRANCH_NOT_FOUND.into());
        }
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
        self.merge_dataset_branch_checked(request, &|_| Ok(()))
    }

    /// [`Self::merge_dataset_branch`], refused unless `check` accepts the
    /// dataset's column definitions as read in the merge's transaction.
    pub fn merge_dataset_branch_checked(
        &self,
        request: &MergeDatasetBranch,
        check: &dyn Fn(&[crate::sekai::dataset::ColumnDef]) -> Result<(), String>,
    ) -> Result<DatasetBranchProposal, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut proposal = load_proposal(&tx, &request.dataset_id, &request.proposal_id)?;
        // Another tenant's proposal reads as missing, replay included.
        if proposal.tenant != request.tenant {
            return Err(dataset_branch::PROPOSAL_NOT_FOUND.into());
        }
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
        let columns: String = tx
            .query_row(
                "SELECT columns FROM sekai_datasets WHERE id = ?1",
                params![request.dataset_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        check(&crate::sekai::dataset::parse_columns(&columns)?)?;
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

pub(crate) fn create_branch_tx(
    tx: &Transaction<'_>,
    request: &CreateDatasetBranch,
) -> Result<DatasetBranch, String> {
    dataset_branch::validate_branch_name(&request.name)?;
    dataset_exists(tx, &request.dataset_id)?;
    let base_version_id = if request.from_version_id.is_empty() {
        latest_version_id(tx, &request.dataset_id)?
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
    Ok(branch)
}

pub(crate) fn write_branch_rows_tx(
    tx: &Transaction<'_>,
    dataset_id: &str,
    name: &str,
    rows: &[HashMap<String, String>],
    replace: bool,
) -> Result<i64, String> {
    let branch = load_branch(tx, dataset_id, name)?;
    let mut head = if replace {
        Vec::new()
    } else {
        branch_rows_tx(tx, &branch)?
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
    Ok(head.len() as i64)
}

/// One branch run inside `tx`, and the rows it wrote; see
/// [`SekaiDb::run_governed_transform_on_branch`]. With `pins`, each input
/// reads its pinned version instead, and the output branch must be new.
#[allow(clippy::too_many_arguments)]
fn branch_run_tx(
    tx: &Transaction<'_>,
    namespace: &str,
    transform: &crate::sekai::governed_transform::GovernedTransform,
    branch: &str,
    pins: Option<&std::collections::BTreeMap<String, String>>,
    actor: &str,
    tenant: &str,
    now_ms: i64,
) -> Result<(DatasetBranchRun, Vec<HashMap<String, String>>), String> {
    use crate::db::governed_transform::{
        dataset_exists, list_row_records_after, load_dataset_column_names, load_dataset_object_id,
        load_lattice, load_object_marking_token,
    };
    use crate::sekai::governed_transform::{
        InputLoadBudget, TransformInputRows, compute_run_tables_until, derive_transform_markings,
        require_bound_output_for_markings,
    };
    dataset_branch::validate_branch_name(branch)?;
    if transform.is_isolated_process() {
        return Err(dataset_branch::BRANCH_RUN_ISOLATED.into());
    }
    // The same load budget as a run on the parent, shared by every input.
    let mut budget = InputLoadBudget::for_transform(transform);
    let mut loaded = Vec::new();
    let mut tokens = Vec::new();
    let mut branch_inputs = Vec::new();
    let mut read = Vec::new();
    for (alias, dataset_id) in transform.input_bindings() {
        if !dataset_exists(tx, &dataset_id)? {
            return Err(dataset_version::DATASET_NOT_FOUND.into());
        }
        let records = if let Some(pins) = pins {
            // A replay reads the pinned version, or nothing when the
            // dataset had no version.
            let version_id = pins.get(&dataset_id).cloned().unwrap_or_default();
            let pinned = DatasetBranch {
                dataset_id: dataset_id.clone(),
                base_version_id: version_id.clone(),
                ..DatasetBranch::default()
            };
            if !version_id.is_empty() {
                require_live_version(tx, &dataset_id, &version_id)?;
            }
            let records = branch_records_budgeted(tx, &pinned, budget.as_mut())?;
            let rows: Vec<HashMap<String, String>> =
                records.iter().map(|(_, row)| row.clone()).collect();
            read.push(crate::sekai::transform_replay::ReplayInput {
                alias: alias.clone(),
                dataset_id: dataset_id.clone(),
                version_id,
                rows: rows.len() as i64,
                digest: dataset_branch::rows_digest(&rows),
                columns: Vec::new(),
            });
            records
        } else {
            match load_branch(tx, &dataset_id, branch) {
                Ok(head) if head.tenant != tenant => {
                    return Err(dataset_branch::BRANCH_NOT_FOUND.into());
                }
                Ok(head) => {
                    branch_inputs.push(dataset_id.clone());
                    branch_records_budgeted(tx, &head, budget.as_mut())?
                }
                Err(_) => list_row_records_after(tx, &dataset_id, 0, budget.as_mut())?,
            }
        };
        if let Some(reason) = budget.as_ref().and_then(|budget| budget.exceeded) {
            return Err(format!("branch run refused: {reason}"));
        }
        let columns = load_dataset_column_names(tx, &dataset_id)?;
        if let (Some(_), Some(input)) = (pins, read.last_mut()) {
            input.columns = columns.clone();
        }
        loaded.push((alias, columns, records));
        tokens.push(load_object_marking_token(
            tx,
            &load_dataset_object_id(tx, &dataset_id)?,
        )?);
    }
    let output = &transform.output_dataset_id;
    if !dataset_exists(tx, output)? {
        return Err(dataset_version::DATASET_NOT_FOUND.into());
    }
    let output_object_id = load_dataset_object_id(tx, output)?;
    let prior = load_object_marking_token(tx, &output_object_id)?;
    let (_, markings_out) = derive_transform_markings(
        load_lattice(tx, namespace)?.as_ref(),
        tokens.iter().map(|token| token.as_deref()),
        prior.as_deref(),
        loaded
            .iter()
            .flat_map(|(_, _, records)| records.iter().map(|(_, row)| row)),
    )?;
    require_bound_output_for_markings(&output_object_id, &markings_out)?;
    if markings_out.trim() != prior.as_deref().unwrap_or("").trim() {
        return Err(dataset_branch::BRANCH_RUN_RAISES_MARKING.into());
    }
    if let Some(budget) = budget.as_mut() {
        budget.expire_if_past();
        if let Some(reason) = budget.exceeded {
            return Err(format!("branch run refused: {reason}"));
        }
    }
    let tables: Vec<TransformInputRows<'_>> = loaded
        .iter()
        .map(|(alias, columns, records)| TransformInputRows {
            alias,
            records,
            columns,
        })
        .collect();
    let (run, rows) = compute_run_tables_until(
        transform,
        None,
        &tables,
        false,
        now_ms,
        uuid::Uuid::new_v4().to_string(),
        budget.as_ref().map(|budget| budget.deadline()),
    );
    if run.quarantined {
        return Err(format!("branch run quarantined by {}", run.quality_rule));
    }
    match load_branch(tx, output, branch) {
        // A replay's branch is its own, never an existing one.
        Ok(_) if pins.is_some() => return Err(dataset_branch::BRANCH_EXISTS.into()),
        Ok(head) if head.tenant != tenant => {
            return Err(dataset_branch::BRANCH_NOT_FOUND.into());
        }
        Ok(_) => {}
        Err(_) => {
            create_branch_tx(
                tx,
                &CreateDatasetBranch {
                    dataset_id: output.clone(),
                    name: branch.into(),
                    from_version_id: String::new(),
                    actor: actor.into(),
                    tenant: tenant.into(),
                },
            )?;
        }
    }
    let rows_written = write_branch_rows_tx(tx, output, branch, &rows, true)?;
    Ok((
        DatasetBranchRun {
            transform_id: transform.transform_id.clone(),
            branch: branch.into(),
            output_dataset_id: output.clone(),
            rows_written,
            branch_inputs,
            markings_out,
            inputs: read,
        },
        rows,
    ))
}

/// A datasource binding carrying what replay diffs and impact need.
pub(crate) fn datasource(
    namespace: &str,
    kind: String,
    dataset_id: String,
    key_column: String,
) -> crate::sekai::object_type_index::ObjectTypeDatasource {
    crate::sekai::object_type_index::ObjectTypeDatasource {
        contract_version: String::new(),
        namespace: namespace.into(),
        kind,
        definition_digest: String::new(),
        dataset_id,
        key_column,
        property_mapping: Default::default(),
        hidden_column: String::new(),
        edits_only: false,
    }
}

/// A pinned version must exist and still hold its rows.
fn require_live_version(
    tx: &Transaction<'_>,
    dataset_id: &str,
    version_id: &str,
) -> Result<(), String> {
    let purged: Option<i64> = tx
        .query_row(
            "SELECT purged FROM sekai_dataset_versions WHERE dataset_id = ?1 AND version_id = ?2",
            params![dataset_id, version_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    match purged {
        None => Err(dataset_version::DATASET_VERSION_NOT_FOUND.into()),
        Some(0) => Ok(()),
        Some(_) => Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into()),
    }
}

/// Branch head rows as run input, charged to `budget` while decoding the way
/// parent reads are; stops at the first row past the budget.
fn branch_records_budgeted(
    tx: &Transaction<'_>,
    branch: &DatasetBranch,
    mut budget: Option<&mut crate::sekai::governed_transform::InputLoadBudget>,
) -> Result<Vec<crate::sekai::dataset::DatasetRowRecord>, String> {
    let (sql, key) = if branch.written {
        (
            "SELECT data FROM sekai_dataset_branch_rows
             WHERE dataset_id = ?1 AND name = ?2 ORDER BY row_id",
            branch.name.as_str(),
        )
    } else if branch.base_version_id.is_empty() {
        return Ok(Vec::new());
    } else {
        (
            "SELECT data FROM sekai_dataset_version_rows
             WHERE dataset_id = ?1 AND version_id = ?2 ORDER BY row_id",
            branch.base_version_id.as_str(),
        )
    };
    let mut stmt = tx.prepare(sql).map_err(|error| error.to_string())?;
    let mut rows = stmt
        .query(params![branch.dataset_id, key])
        .map_err(|error| error.to_string())?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let data: String = row.get(0).map_err(|error| error.to_string())?;
        if let Some(budget) = budget.as_mut()
            && !budget.allow_encoded(data.len() as u64)
        {
            break;
        }
        let values: HashMap<String, String> =
            serde_json::from_str(&data).map_err(|error| error.to_string())?;
        if let Some(budget) = budget.as_mut()
            && !budget.charge(&values)
        {
            break;
        }
        records.push((records.len() as i64 + 1, values));
    }
    Ok(records)
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

/// The branch if it belongs to `tenant`, checked in the caller's transaction.
fn load_owned_branch(
    tx: &Transaction<'_>,
    dataset_id: &str,
    name: &str,
    tenant: &str,
) -> Result<DatasetBranch, String> {
    load_branch(tx, dataset_id, name)
        .ok()
        .filter(|branch| branch.tenant == tenant)
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
    // Change bundle dry-run branches are previews whose copies carry no
    // classification: redaction and erasure drop them whole, and a rerun
    // refills from the edited base (#1692).
    // Case-sensitive, as the reservation is: SQLite's LIKE is not.
    let prefix = dataset_branch::BUNDLE_BRANCH_PREFIX;
    for table in ["sekai_dataset_branch_rows", "sekai_dataset_branches"] {
        tx.execute(
            &format!(
                "DELETE FROM {table} WHERE dataset_id = ?1 AND substr(name, 1, length(?2)) = ?2"
            ),
            params![dataset_id, prefix],
        )
        .map_err(|error| error.to_string())?;
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

    /// A checked merge (#1693) writes nothing when its check refuses the
    /// dataset's column definitions, and the proposal stays open.
    #[test]
    fn a_checked_merge_refuses_what_its_check_refuses() {
        let db = crate::db::runtime_db::RuntimeDb::memory();
        let id = format!("ds-{}", uuid::Uuid::new_v4().as_simple());
        db.create_dataset(&Dataset {
            id: id.clone(),
            name: id.clone(),
            columns: ["id", "value"]
                .map(|name| ColumnDef {
                    name: name.into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                })
                .to_vec(),
            object_id: String::new(),
            created: 0,
            partition_keys: Vec::new(),
        })
        .unwrap();
        db.append_rows(&id, &[row("1", "a")]).unwrap();
        db.create_dataset_branch(&CreateDatasetBranch {
            dataset_id: id.clone(),
            name: "b".into(),
            actor: "author".into(),
            tenant: "t1".into(),
            ..Default::default()
        })
        .unwrap();
        db.write_dataset_branch_rows(&id, "b", &[row("1", "changed")], true)
            .unwrap();
        // A proposal fenced on another incarnation finds no branch.
        let mut propose = ProposeDatasetBranch {
            dataset_id: id.clone(),
            branch: "b".into(),
            actor: "author".into(),
            tenant: "t1".into(),
            expected_incarnation: Some("an-earlier-branch".into()),
        };
        assert_eq!(
            db.propose_dataset_branch(&propose).unwrap_err(),
            dataset_branch::BRANCH_NOT_FOUND
        );
        propose.expected_incarnation = None;
        let proposal = db.propose_dataset_branch(&propose).unwrap();
        let merge = MergeDatasetBranch {
            dataset_id: id.clone(),
            proposal_id: proposal.id.clone(),
            actor: "merger".into(),
            tenant: "t1".into(),
            reason: String::new(),
        };
        let refused = db
            .merge_dataset_branch_checked(&merge, &|columns| {
                assert_eq!(columns.len(), 2);
                Err("column check refused".into())
            })
            .unwrap_err();
        assert_eq!(refused, "column check refused");
        let rows = db.query_rows(&id, &RowQuery::default()).unwrap();
        assert_eq!(rows[0]["value"], "a");
        let merged = db
            .merge_dataset_branch_checked(&merge, &|_| Ok(()))
            .unwrap();
        assert_eq!(merged.status, dataset_branch::STATUS_MERGED);
    }

    /// Redaction deletes change bundle dry-run branches whole (#1692) and
    /// leaves other branches to the field redaction.
    fn exercise_bundle_branches_drop_on_redaction(db: &dyn DatasetBackend) {
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
        db.append_rows(&id, &[row("1", "a")]).unwrap();
        for name in ["bundle-preview", "Bundle-keep", "keep"] {
            db.create_dataset_branch(&CreateDatasetBranch {
                dataset_id: id.clone(),
                name: name.into(),
                actor: "dev".into(),
                tenant: "t1".into(),
                ..Default::default()
            })
            .unwrap();
            db.write_dataset_branch_rows(&id, name, &[row("1", "copy")], true)
                .unwrap();
        }
        db.redact_dataset_fields(&id, "internal", &[]).unwrap();
        let names = db
            .list_dataset_branches(&id)
            .unwrap()
            .into_iter()
            .map(|branch| branch.name)
            .collect::<Vec<_>>();
        assert_eq!(names, ["Bundle-keep", "keep"]);
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
        // A write fenced on another incarnation is refused and writes nothing.
        assert_eq!(
            db.fill_dataset_branch_from_base(&id, "fix", "stale", &|_, _| Ok(vec![row("9", "z")]))
                .unwrap_err(),
            dataset_branch::BRANCH_CHANGED
        );
        assert_eq!(
            db.create_dataset_branch(&create("fix")).unwrap_err(),
            dataset_branch::BRANCH_EXISTS
        );
        // Unwritten, the branch reads its base version.
        assert_eq!(db.dataset_branch_rows(&id, "fix").unwrap().len(), 2);
        db.write_dataset_branch_rows(&id, "fix", &[row("3", "c")], false)
            .unwrap();
        assert_eq!(db.dataset_branch_rows(&id, "fix").unwrap().len(), 3);
        let diff = db.compare_dataset_branch(&id, "fix", "t1").unwrap();
        assert_eq!((diff.parent_rows, diff.branch_rows), (2, 3));
        assert!(!diff.identical());
        // The parent is untouched by branch work.
        assert_eq!(live(db, &id).len(), 2);
        assert_eq!(db.list_dataset_versions(&id).unwrap(), versions);

        let propose = ProposeDatasetBranch {
            expected_incarnation: None,
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
        db.delete_dataset_branch(&id, "late", "t1").unwrap();
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

    /// A transform run on a branch reads input branches where they exist and
    /// writes only the output's branch. `put` stores the transform.
    fn exercise_branch_run(
        db: &dyn DatasetBackend,
        put: &dyn Fn(&crate::sekai::governed_transform::GovernedTransform),
    ) {
        use crate::sekai::governed_transform::{
            CONTRACT_VERSION, GovernedTransform, TransformStep,
        };
        let suffix = uuid::Uuid::new_v4().as_simple().to_string();
        let (input, output, namespace) = (
            format!("in-{suffix}"),
            format!("out-{suffix}"),
            format!("ops-{suffix}"),
        );
        for id in [&input, &output] {
            db.create_dataset(&Dataset {
                id: id.clone(),
                name: id.clone(),
                columns: ["id", "keep"]
                    .map(|name| ColumnDef {
                        name: name.into(),
                        col_type: "string".into(),
                        classification: "public".into(),
                    })
                    .to_vec(),
                object_id: String::new(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        }
        let keep = |id: &str, keep: &str| {
            HashMap::from([
                ("id".to_string(), id.to_string()),
                ("keep".into(), keep.into()),
            ])
        };
        db.append_rows(
            &input,
            &[
                keep("1", "yes"),
                keep("2", "no"),
                keep("3", "yes"),
                keep("4", "no"),
            ],
        )
        .unwrap();
        let transform = GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: namespace.clone(),
            transform_id: "t1".into(),
            input_dataset_id: input.clone(),
            output_dataset_id: output.clone(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: "yes".into(),
                columns: Vec::new(),
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap();
        put(&transform);
        let out_versions = db.list_dataset_versions(&output).unwrap();

        // Without an input branch the run reads the parent's rows.
        let run = db
            .run_governed_transform_on_branch(&namespace, "t1", "dev", "dev", "t1", 20)
            .unwrap();
        assert!(run.branch_inputs.is_empty());
        assert_eq!(run.rows_written, 2);
        // With an input branch it reads the branch.
        db.create_dataset_branch(&CreateDatasetBranch {
            dataset_id: input.clone(),
            name: "dev".into(),
            actor: "dev".into(),
            tenant: "t1".into(),
            ..Default::default()
        })
        .unwrap();
        db.write_dataset_branch_rows(&input, "dev", &[keep("5", "yes")], false)
            .unwrap();
        let run = db
            .run_governed_transform_on_branch(&namespace, "t1", "dev", "dev", "t1", 30)
            .unwrap();
        assert_eq!(run.branch_inputs, vec![input.clone()]);
        assert_eq!(run.rows_written, 3);
        assert_eq!(db.dataset_branch_rows(&output, "dev").unwrap().len(), 3);
        // The parent output is untouched.
        assert!(live(db, &output).is_empty());
        assert_eq!(db.list_dataset_versions(&output).unwrap(), out_versions);
        // Another tenant cannot run into this tenant's branches.
        assert_eq!(
            db.run_governed_transform_on_branch(&namespace, "t1", "dev", "x", "t2", 40)
                .unwrap_err(),
            dataset_branch::BRANCH_NOT_FOUND
        );
    }

    #[test]
    fn sqlite_transform_run_on_a_branch_writes_only_its_output_branch() {
        let db = crate::db::sekai::SekaiDb::new(":memory:").unwrap();
        exercise_branch_run(&db, &|transform| {
            db.put_governed_transform(transform, 10).unwrap();
        });
    }

    #[test]
    fn sqlite_branches_isolate_merge_once_and_free_on_delete() {
        let db = crate::db::sekai::SekaiDb::new(":memory:").unwrap();
        exercise(&db);
        exercise_bundle_branches_drop_on_redaction(&db);
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
        let db = db.unwrap();
        exercise(&db);
        exercise_bundle_branches_drop_on_redaction(&db);
        exercise_branch_run(&db, &|transform| {
            db.put_governed_transform(transform, 10).unwrap();
        });
    }
}
