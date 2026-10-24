//! PostgreSQL storage for dataset branches (ADR 0119). Same tables and
//! semantics as SQLite (`src/db/dataset_branch.rs`). Every branch mutation
//! first takes the dataset rows lock that appends, rollback and redaction
//! use, so they serialize with one another and with retention.

use crate::db::dataset_branch::{check_mergeable, merge_reason};
use crate::db::postgres::{PostgresDb, lock_dataset_rows};
use crate::db::postgres_dataset::{
    mark_consuming_transform_outputs_stale_pg, snapshot_dataset_version_pg,
};
use crate::sekai::dataset_branch::{
    self, BranchRowEdit, CreateDatasetBranch, DatasetBranch, DatasetBranchDiff,
    DatasetBranchProposal, DatasetBranchRun, MergeDatasetBranch, ProposeDatasetBranch,
};
use crate::sekai::dataset_version::{self, encode_row_map};
use postgres::Transaction;
use std::collections::HashMap;

type Rows = Vec<HashMap<String, String>>;

/// One read-only snapshot, so branch metadata, its rows and the parent are
/// read as of the same moment.
fn read_snapshot(connection: &mut postgres::Client) -> Result<Transaction<'_>, String> {
    connection
        .build_transaction()
        .isolation_level(postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .map_err(|error| error.to_string())
}

impl PostgresDb {
    pub fn create_dataset_branch(
        &self,
        request: &CreateDatasetBranch,
    ) -> Result<DatasetBranch, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let branch = create_branch_pg(&mut tx, request)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(branch)
    }

    pub fn list_dataset_branches(&self, dataset_id: &str) -> Result<Vec<DatasetBranch>, String> {
        let mut connection = self.connection()?;
        Ok(connection
            .query(
                "SELECT dataset_id, name, base_version_id, written, incarnation, created_by, tenant,
                        created_at_ms
                 FROM sekai_dataset_branches WHERE dataset_id = $1 ORDER BY name",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(map_branch)
            .collect())
    }

    pub fn dataset_branch_rows(&self, dataset_id: &str, name: &str) -> Result<Rows, String> {
        let mut connection = self.connection()?;
        let mut tx = read_snapshot(&mut connection)?;
        let branch = load_branch(&mut tx, dataset_id, name, false)?;
        branch_rows(&mut tx, &branch)
    }

    pub fn write_dataset_branch_rows(
        &self,
        dataset_id: &str,
        name: &str,
        rows: &[HashMap<String, String>],
        replace: bool,
    ) -> Result<i64, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let written = write_branch_rows_pg(&mut tx, dataset_id, name, rows, replace)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(written)
    }

    /// PostgreSQL twin of the SQLite fill: under the dataset rows lock that
    /// redaction and every branch mutation take, check the incarnation, read
    /// the base version, and compute and write only an unwritten branch.
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_dataset_rows(&mut tx, dataset_id)?;
        let branch = load_branch(&mut tx, dataset_id, name, true)
            .map_err(|_| dataset_branch::BRANCH_CHANGED.to_string())?;
        if branch.incarnation != incarnation {
            return Err(dataset_branch::BRANCH_CHANGED.into());
        }
        let base = branch_rows(
            &mut tx,
            &DatasetBranch {
                written: false,
                ..branch.clone()
            },
        )?;
        // Written once: a written branch is the result, so a redaction
        // applied to it since is never undone by recomputing.
        let expected = if branch.written {
            branch_rows(&mut tx, &branch)?
        } else {
            // Column metadata changes take the same dataset rows lock.
            let columns: String = tx
                .query_one(
                    "SELECT columns FROM sekai_datasets WHERE id = $1",
                    &[&dataset_id],
                )
                .map_err(|error| error.to_string())?
                .get(0);
            let expected = compute(&crate::sekai::dataset::parse_columns(&columns)?, &base)?;
            write_branch_rows_pg(&mut tx, dataset_id, name, &expected, true)?;
            expected
        };
        tx.commit().map_err(|error| error.to_string())?;
        Ok((base, expected))
    }

    /// PostgreSQL twin of the SQLite branch run (`src/db/dataset_branch.rs`).
    pub fn run_governed_transform_on_branch(
        &self,
        namespace: &str,
        transform_id: &str,
        branch: &str,
        actor: &str,
        tenant: &str,
        now_ms: i64,
    ) -> Result<DatasetBranchRun, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let transform = crate::db::postgres_governed_transform::load_transform(
            &mut tx,
            namespace,
            transform_id,
        )?
        .ok_or_else(|| "governed transform not found".to_string())?;
        let (run, _) = branch_run_pg(&mut tx, &transform, branch, None, actor, tenant, now_ms)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(run)
    }

    /// PostgreSQL twin of the SQLite replay run: the branch and its record
    /// commit together.
    #[allow(clippy::too_many_arguments)]
    pub fn replay_transform_into_branch(
        &self,
        _namespace: &str,
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // FOR SHARE holds off a redefinition or delete until commit.
        let current: Option<String> = tx
            .query_opt(
                "SELECT definition_digest FROM sekai_governed_transform
                 WHERE namespace = $1 AND transform_id = $2 FOR SHARE",
                &[&transform.namespace, &transform.transform_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if current.as_deref() != Some(definition_digest) {
            return Err(crate::sekai::transform_replay::REPLAY_TRANSFORM_CHANGED.into());
        }
        let (run, rows) = branch_run_pg(
            &mut tx,
            transform,
            branch,
            Some(pins),
            actor,
            tenant,
            now_ms,
        )?;
        if !baseline_version_id.is_empty() {
            require_live_version_pg(&mut tx, &run.output_dataset_id, baseline_version_id)?;
        }
        // The baseline is read in the same transaction as the inputs, so the
        // diff sees one state, and is charged to the transform's memory and
        // time budget (the preview default when it has none).
        let mut budget = crate::sekai::governed_transform::InputLoadBudget::for_preview(transform);
        let baseline = branch_records_budgeted(
            &mut tx,
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
        let baseline: Rows = baseline.into_iter().map(|(_, row)| row).collect();
        let replay = describe(&run, &rows, &baseline)?;
        let json =
            serde_json::to_string(&replay.without_rows()).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_transform_replays
             (id, namespace, transform_id, output_dataset_id, tenant, record_json, created_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &replay.id,
                &replay.namespace,
                &replay.transform_id,
                &replay.output_dataset_id,
                &replay.tenant,
                &json,
                &replay.created_at_ms,
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
        let row = self
            .connection()?
            .query_opt(
                "SELECT record_json FROM sekai_transform_replays WHERE id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?;
        row.map(|row| {
            serde_json::from_str(&row.get::<_, String>(0)).map_err(|error| error.to_string())
        })
        .transpose()
    }

    /// Every object type binding of `dataset_id`, in any namespace.
    pub fn dataset_bindings(&self, dataset_id: &str) -> Result<Vec<(String, String)>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT namespace, kind FROM sekai_object_type_datasource
                 WHERE dataset_id = $1 ORDER BY namespace, kind",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }

    pub fn list_object_type_datasources(
        &self,
        namespace: &str,
    ) -> Result<Vec<crate::sekai::object_type_index::ObjectTypeDatasource>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT kind, dataset_id, key_column FROM sekai_object_type_datasource
                 WHERE namespace = $1 ORDER BY kind",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?;
        Ok(rows
            .iter()
            .map(|row| {
                crate::db::dataset_branch::datasource(namespace, row.get(0), row.get(1), row.get(2))
            })
            .collect())
    }

    pub fn compare_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
        tenant: &str,
    ) -> Result<DatasetBranchDiff, String> {
        let mut connection = self.connection()?;
        let mut tx = read_snapshot(&mut connection)?;
        let branch = load_branch(&mut tx, dataset_id, name, false)?;
        if branch.tenant != tenant {
            return Err(dataset_branch::BRANCH_NOT_FOUND.into());
        }
        let head = branch_rows(&mut tx, &branch)?;
        let parent = decode(
            &tx.query(
                "SELECT data FROM sekai_dataset_rows WHERE dataset_id = $1 ORDER BY id",
                &[&dataset_id],
            )
            .map_err(|error| error.to_string())?,
        )?;
        Ok(dataset_branch::diff_rows(&parent, &head))
    }

    pub fn delete_dataset_branch(
        &self,
        dataset_id: &str,
        name: &str,
        tenant: &str,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_dataset_rows(&mut tx, dataset_id)?;
        if load_branch(&mut tx, dataset_id, name, true)?.tenant != tenant {
            return Err(dataset_branch::BRANCH_NOT_FOUND.into());
        }
        drop_branch(&mut tx, dataset_id, name)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn propose_dataset_branch(
        &self,
        request: &ProposeDatasetBranch,
    ) -> Result<DatasetBranchProposal, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_dataset_rows(&mut tx, &request.dataset_id)?;
        let branch = load_branch(&mut tx, &request.dataset_id, &request.branch, true)?;
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
        let branch_digest = dataset_branch::rows_digest(&branch_rows(&mut tx, &branch)?);
        let parent_version_id = latest_version_id(&mut tx, &request.dataset_id)?;
        let id = dataset_branch::proposal_id(
            &request.dataset_id,
            &branch,
            &parent_version_id,
            &branch_digest,
        );
        tx.execute(
            "INSERT INTO sekai_dataset_branch_proposals
             (id, dataset_id, branch, parent_version_id, branch_digest, proposer, tenant,
              status, created_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO NOTHING",
            &[
                &id,
                &request.dataset_id,
                &request.branch,
                &parent_version_id,
                &branch_digest,
                &request.actor,
                &request.tenant,
                &dataset_branch::STATUS_OPEN,
                &dataset_version::now_ms(),
            ],
        )
        .map_err(|error| error.to_string())?;
        let proposal = load_proposal(&mut tx, &request.dataset_id, &id, false)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(proposal)
    }

    pub fn get_dataset_branch_proposal(
        &self,
        dataset_id: &str,
        id: &str,
    ) -> Result<DatasetBranchProposal, String> {
        let mut connection = self.connection()?;
        let mut tx = read_snapshot(&mut connection)?;
        load_proposal(&mut tx, dataset_id, id, false)
    }

    pub fn merge_dataset_branch(
        &self,
        request: &MergeDatasetBranch,
    ) -> Result<DatasetBranchProposal, String> {
        self.merge_dataset_branch_checked(request, &|_| Ok(()))
    }

    /// [`Self::merge_dataset_branch`], refused unless `check` accepts the
    /// dataset's column definitions as read under the merge's dataset lock.
    pub fn merge_dataset_branch_checked(
        &self,
        request: &MergeDatasetBranch,
        check: &dyn Fn(&[crate::sekai::dataset::ColumnDef]) -> Result<(), String>,
    ) -> Result<DatasetBranchProposal, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_dataset_rows(&mut tx, &request.dataset_id)?;
        let mut proposal = load_proposal(&mut tx, &request.dataset_id, &request.proposal_id, true)?;
        // Another tenant's proposal reads as missing, replay included.
        if proposal.tenant != request.tenant {
            return Err(dataset_branch::PROPOSAL_NOT_FOUND.into());
        }
        if proposal.status == dataset_branch::STATUS_MERGED {
            return Ok(proposal);
        }
        check_mergeable(&proposal, request)?;
        if latest_version_id(&mut tx, &request.dataset_id)? != proposal.parent_version_id {
            return Err(dataset_branch::PROPOSAL_STALE_PARENT.into());
        }
        let branch = load_branch(&mut tx, &request.dataset_id, &proposal.branch, true)
            .map_err(|_| dataset_branch::PROPOSAL_STALE_BRANCH.to_string())?;
        let head = branch_rows(&mut tx, &branch)?;
        if dataset_branch::rows_digest(&head) != proposal.branch_digest {
            return Err(dataset_branch::PROPOSAL_STALE_BRANCH.into());
        }
        // Column metadata changes take the same dataset rows lock.
        let columns: String = tx
            .query_one(
                "SELECT columns FROM sekai_datasets WHERE id = $1",
                &[&request.dataset_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        check(&crate::sekai::dataset::parse_columns(&columns)?)?;
        tx.execute(
            "DELETE FROM sekai_dataset_rows WHERE dataset_id = $1",
            &[&request.dataset_id],
        )
        .map_err(|error| error.to_string())?;
        let keys_json: String = tx
            .query_one(
                "SELECT partition_keys FROM sekai_datasets WHERE id = $1",
                &[&request.dataset_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        let keys = crate::sekai::dataset::parse_partition_keys(&keys_json)?;
        for row in &head {
            let data = encode_row_map(row)?;
            let partition_key = crate::sekai::dataset::partition_key_for_row_json(&keys, &data)?;
            tx.execute(
                "INSERT INTO sekai_dataset_rows (dataset_id, data, partition_key)
                 VALUES ($1, $2, $3)",
                &[&request.dataset_id, &data, &partition_key],
            )
            .map_err(|error| error.to_string())?;
        }
        let now = dataset_version::now_ms();
        mark_consuming_transform_outputs_stale_pg(&mut tx, &request.dataset_id, &proposal.id, now)?;
        let version = snapshot_dataset_version_pg(
            &mut tx,
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
             SET status = $1, merged_by = $2, merged_version_id = $3, receipt_id = $4,
                 merged_at_ms = $5
             WHERE id = $6",
            &[
                &proposal.status,
                &proposal.merged_by,
                &proposal.merged_version_id,
                &proposal.receipt_id,
                &proposal.merged_at_ms,
                &proposal.id,
            ],
        )
        .map_err(|error| error.to_string())?;
        drop_branch(&mut tx, &request.dataset_id, &proposal.branch)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(proposal)
    }
}

pub fn create_branch_pg(
    tx: &mut Transaction<'_>,
    request: &CreateDatasetBranch,
) -> Result<DatasetBranch, String> {
    dataset_branch::validate_branch_name(&request.name)?;
    // Appends prune under this lock; holding it keeps the base version
    // from being purged before the branch that spares it commits.
    lock_dataset_rows(tx, &request.dataset_id)?;
    tx.query_opt(
        "SELECT 1 FROM sekai_datasets WHERE id = $1",
        &[&request.dataset_id],
    )
    .map_err(|error| error.to_string())?
    .ok_or_else(|| dataset_version::DATASET_NOT_FOUND.to_string())?;
    let base_version_id = if request.from_version_id.is_empty() {
        latest_version_id(tx, &request.dataset_id)?
    } else {
        let purged: Option<i32> = tx
            .query_opt(
                "SELECT purged FROM sekai_dataset_versions
                     WHERE dataset_id = $1 AND version_id = $2",
                &[&request.dataset_id, &request.from_version_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        match purged {
            None => return Err(dataset_version::DATASET_VERSION_NOT_FOUND.into()),
            Some(purged) if purged != 0 => {
                return Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into());
            }
            Some(_) => request.from_version_id.clone(),
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
            "INSERT INTO sekai_dataset_branches
                 (dataset_id, name, base_version_id, written, incarnation, created_by, tenant,
                  created_at_ms)
                 VALUES ($1, $2, $3, 0, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
            &[
                &branch.dataset_id,
                &branch.name,
                &branch.base_version_id,
                &branch.incarnation,
                &branch.created_by,
                &branch.tenant,
                &branch.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    if inserted == 0 {
        return Err(dataset_branch::BRANCH_EXISTS.into());
    }
    Ok(branch)
}

pub fn write_branch_rows_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    name: &str,
    rows: &[HashMap<String, String>],
    replace: bool,
) -> Result<i64, String> {
    lock_dataset_rows(tx, dataset_id)?;
    let branch = load_branch(tx, dataset_id, name, true)?;
    let mut head = if replace {
        Vec::new()
    } else {
        branch_rows(tx, &branch)?
    };
    head.extend(rows.iter().cloned());
    tx.execute(
        "DELETE FROM sekai_dataset_branch_rows WHERE dataset_id = $1 AND name = $2",
        &[&dataset_id, &name],
    )
    .map_err(|error| error.to_string())?;
    for (row_id, row) in head.iter().enumerate() {
        tx.execute(
            "INSERT INTO sekai_dataset_branch_rows (dataset_id, name, row_id, data)
                 VALUES ($1, $2, $3, $4)",
            &[&dataset_id, &name, &(row_id as i64), &encode_row_map(row)?],
        )
        .map_err(|error| error.to_string())?;
    }
    tx.execute(
        "UPDATE sekai_dataset_branches SET written = 1 WHERE dataset_id = $1 AND name = $2",
        &[&dataset_id, &name],
    )
    .map_err(|error| error.to_string())?;
    Ok(head.len() as i64)
}

/// One branch run inside `tx`; see [`PostgresDb::run_governed_transform_on_branch`].
/// With `pins`, each input reads its pinned version instead, and the output
/// branch must be new.
fn branch_run_pg(
    tx: &mut Transaction<'_>,
    transform: &crate::sekai::governed_transform::GovernedTransform,
    branch: &str,
    pins: Option<&std::collections::BTreeMap<String, String>>,
    actor: &str,
    tenant: &str,
    now_ms: i64,
) -> Result<(DatasetBranchRun, Rows), String> {
    use crate::db::postgres_audit::lock_object_lifecycle;
    use crate::db::postgres_governed_transform::{
        load_dataset_column_names, load_dataset_object_id, load_object_marking_token,
        load_row_records, lock_transform_datasets,
    };
    use crate::sekai::governed_transform::{
        InputLoadBudget, TransformInputRows, compute_run_tables_until, derive_transform_markings,
        require_bound_output_for_markings,
    };
    dataset_branch::validate_branch_name(branch)?;
    if transform.is_isolated_process() {
        return Err(dataset_branch::BRANCH_RUN_ISOLATED.into());
    }
    let bindings = transform.input_bindings();
    let output = transform.output_dataset_id.clone();
    let mut lock_ids: Vec<&str> = bindings.iter().map(|(_, id)| id.as_str()).collect();
    lock_ids.push(&output);
    lock_transform_datasets(tx, &lock_ids)?;
    let mut budget = InputLoadBudget::for_transform(transform);
    let mut loaded = Vec::new();
    let mut tokens = Vec::new();
    let mut branch_inputs = Vec::new();
    let mut read = Vec::new();
    for (alias, dataset_id) in &bindings {
        let records = if let Some(pins) = pins {
            // A replay reads the pinned version, or nothing when the
            // dataset had no version.
            let version_id = pins.get(dataset_id).cloned().unwrap_or_default();
            let pinned = DatasetBranch {
                dataset_id: dataset_id.clone(),
                base_version_id: version_id.clone(),
                ..DatasetBranch::default()
            };
            if !version_id.is_empty() {
                require_live_version_pg(tx, dataset_id, &version_id)?;
            }
            let records = branch_records_budgeted(tx, &pinned, budget.as_mut())?;
            let rows: Rows = records.iter().map(|(_, row)| row.clone()).collect();
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
            match load_branch(tx, dataset_id, branch, true) {
                Ok(head) if head.tenant != tenant => {
                    return Err(dataset_branch::BRANCH_NOT_FOUND.into());
                }
                Ok(head) => {
                    branch_inputs.push(dataset_id.clone());
                    branch_records_budgeted(tx, &head, budget.as_mut())?
                }
                Err(_) => load_row_records(tx, dataset_id, 0, budget.as_mut())?,
            }
        };
        if let Some(reason) = budget.as_ref().and_then(|budget| budget.exceeded) {
            return Err(format!("branch run refused: {reason}"));
        }
        let columns = load_dataset_column_names(tx, dataset_id)?;
        if let (Some(_), Some(input)) = (pins, read.last_mut()) {
            input.columns = columns.clone();
        }
        loaded.push((alias.clone(), columns, records));
        let object_id = load_dataset_object_id(tx, dataset_id)?;
        tokens.push(load_object_marking_token(tx, &object_id)?);
    }
    let output_object_id = load_dataset_object_id(tx, &output)?;
    // Held to commit, so the marking checked here is the one the branch
    // rows land under, as on a parent run.
    if !output_object_id.trim().is_empty() {
        lock_object_lifecycle(tx, &output_object_id)?;
    }
    let prior = load_object_marking_token(tx, &output_object_id)?;
    let (_, markings_out) = derive_transform_markings(
        crate::db::postgres_object_security_terms::load_classification_lattice(
            tx,
            &transform.namespace,
        )?
        .as_ref(),
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
    match load_branch(tx, &output, branch, true) {
        // A replay's branch is its own, never an existing one.
        Ok(_) if pins.is_some() => return Err(dataset_branch::BRANCH_EXISTS.into()),
        Ok(head) if head.tenant != tenant => {
            return Err(dataset_branch::BRANCH_NOT_FOUND.into());
        }
        Ok(_) => {}
        Err(_) => {
            create_branch_pg(
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
    let rows_written = write_branch_rows_pg(tx, &output, branch, &rows, true)?;
    Ok((
        DatasetBranchRun {
            transform_id: transform.transform_id.clone(),
            branch: branch.into(),
            output_dataset_id: output,
            rows_written,
            branch_inputs,
            markings_out,
            inputs: read,
        },
        rows,
    ))
}

/// A pinned version must exist and still hold its rows.
fn require_live_version_pg(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    version_id: &str,
) -> Result<(), String> {
    let row = tx
        .query_opt(
            "SELECT purged FROM sekai_dataset_versions WHERE dataset_id = $1 AND version_id = $2",
            &[&dataset_id, &version_id],
        )
        .map_err(|error| error.to_string())?;
    match row.map(|row| row.get::<_, i32>(0)) {
        None => Err(dataset_version::DATASET_VERSION_NOT_FOUND.into()),
        Some(0) => Ok(()),
        Some(_) => Err(dataset_version::DATASET_VERSION_PAST_RETENTION.into()),
    }
}

/// Branch head rows as run input, streamed and charged to `budget` while
/// decoding, as parent reads are; stops at the first row past the budget.
fn branch_records_budgeted(
    tx: &mut Transaction<'_>,
    branch: &DatasetBranch,
    mut budget: Option<&mut crate::sekai::governed_transform::InputLoadBudget>,
) -> Result<Vec<crate::sekai::dataset::DatasetRowRecord>, String> {
    use postgres::fallible_iterator::FallibleIterator;
    use postgres::types::ToSql;
    let (sql, key) = if branch.written {
        (
            "SELECT data FROM sekai_dataset_branch_rows
             WHERE dataset_id = $1 AND name = $2 ORDER BY row_id",
            branch.name.as_str(),
        )
    } else if branch.base_version_id.is_empty() {
        return Ok(Vec::new());
    } else {
        (
            "SELECT data FROM sekai_dataset_version_rows
             WHERE dataset_id = $1 AND version_id = $2 ORDER BY row_id",
            branch.base_version_id.as_str(),
        )
    };
    let params: [&(dyn ToSql + Sync); 2] = [&branch.dataset_id, &key];
    let mut rows = tx
        .query_raw(sql, params)
        .map_err(|error| error.to_string())?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(|error| error.to_string())? {
        let data: &str = row.get(0);
        if let Some(budget) = budget.as_mut()
            && !budget.allow_encoded(data.len() as u64)
        {
            break;
        }
        let values: HashMap<String, String> =
            serde_json::from_str(data).map_err(|error| error.to_string())?;
        if let Some(budget) = budget.as_mut()
            && !budget.charge(&values)
        {
            break;
        }
        records.push((records.len() as i64 + 1, values));
    }
    Ok(records)
}

fn latest_version_id(tx: &mut Transaction<'_>, dataset_id: &str) -> Result<String, String> {
    Ok(tx
        .query_opt(
            "SELECT version_id FROM sekai_dataset_versions
             WHERE dataset_id = $1 ORDER BY seq DESC LIMIT 1",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0))
        .unwrap_or_default())
}

fn map_branch(row: &postgres::Row) -> DatasetBranch {
    DatasetBranch {
        dataset_id: row.get(0),
        name: row.get(1),
        base_version_id: row.get(2),
        written: row.get::<_, i32>(3) != 0,
        incarnation: row.get(4),
        created_by: row.get(5),
        tenant: row.get(6),
        created_at_ms: row.get(7),
    }
}

fn load_branch(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    name: &str,
    for_update: bool,
) -> Result<DatasetBranch, String> {
    let sql = if for_update {
        "SELECT dataset_id, name, base_version_id, written, incarnation, created_by, tenant, created_at_ms
         FROM sekai_dataset_branches WHERE dataset_id = $1 AND name = $2 FOR UPDATE"
    } else {
        "SELECT dataset_id, name, base_version_id, written, incarnation, created_by, tenant, created_at_ms
         FROM sekai_dataset_branches WHERE dataset_id = $1 AND name = $2"
    };
    tx.query_opt(sql, &[&dataset_id, &name])
        .map_err(|error| error.to_string())?
        .as_ref()
        .map(map_branch)
        .ok_or_else(|| dataset_branch::BRANCH_NOT_FOUND.to_string())
}

fn branch_rows(tx: &mut Transaction<'_>, branch: &DatasetBranch) -> Result<Rows, String> {
    let rows = if !branch.written {
        if branch.base_version_id.is_empty() {
            return Ok(Vec::new());
        }
        tx.query(
            "SELECT data FROM sekai_dataset_version_rows
             WHERE dataset_id = $1 AND version_id = $2 ORDER BY row_id",
            &[&branch.dataset_id, &branch.base_version_id],
        )
    } else {
        tx.query(
            "SELECT data FROM sekai_dataset_branch_rows
             WHERE dataset_id = $1 AND name = $2 ORDER BY row_id",
            &[&branch.dataset_id, &branch.name],
        )
    }
    .map_err(|error| error.to_string())?;
    decode(&rows)
}

fn decode(rows: &[postgres::Row]) -> Result<Rows, String> {
    rows.iter()
        .map(|row| {
            let data: String = row.get(0);
            serde_json::from_str(&data).map_err(|error| error.to_string())
        })
        .collect()
}

fn drop_branch(tx: &mut Transaction<'_>, dataset_id: &str, name: &str) -> Result<(), String> {
    for sql in [
        "DELETE FROM sekai_dataset_branch_rows WHERE dataset_id = $1 AND name = $2",
        "DELETE FROM sekai_dataset_branches WHERE dataset_id = $1 AND name = $2",
    ] {
        tx.execute(sql, &[&dataset_id, &name])
            .map_err(|error| error.to_string())?;
    }
    tx.execute(
        "UPDATE sekai_dataset_branch_proposals SET status = $3
         WHERE dataset_id = $1 AND branch = $2 AND status = $4",
        &[
            &dataset_id,
            &name,
            &dataset_branch::STATUS_CLOSED,
            &dataset_branch::STATUS_OPEN,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn load_proposal(
    tx: &mut Transaction<'_>,
    dataset_id: &str,
    id: &str,
    for_update: bool,
) -> Result<DatasetBranchProposal, String> {
    let base = "SELECT id, dataset_id, branch, parent_version_id, branch_digest, proposer, tenant,
                status, merged_by, merged_version_id, receipt_id, created_at_ms, merged_at_ms
         FROM sekai_dataset_branch_proposals WHERE id = $1 AND dataset_id = $2";
    let sql = if for_update {
        format!("{base} FOR UPDATE")
    } else {
        base.to_string()
    };
    let row = tx
        .query_opt(&sql, &[&id, &dataset_id])
        .map_err(|error| error.to_string())?
        .ok_or_else(|| dataset_branch::PROPOSAL_NOT_FOUND.to_string())?;
    Ok(DatasetBranchProposal {
        id: row.get(0),
        dataset_id: row.get(1),
        branch: row.get(2),
        parent_version_id: row.get(3),
        branch_digest: row.get(4),
        proposer: row.get(5),
        tenant: row.get(6),
        status: row.get(7),
        merged_by: row.get(8),
        merged_version_id: row.get(9),
        receipt_id: row.get(10),
        created_at_ms: row.get(11),
        merged_at_ms: row.get(12),
    })
}

/// PostgreSQL twin of `edit_branch_rows_tx` for redaction and erasure.
pub fn edit_branch_rows_pg(
    client: &mut impl postgres::GenericClient,
    dataset_id: &str,
    edit: &dyn Fn(Option<HashMap<String, String>>) -> BranchRowEdit,
) -> Result<(), String> {
    // The dataset rows lock every branch mutation takes: a branch write that
    // read an unredacted base waits here instead of landing afterwards.
    client
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&crate::db::postgres::advisory_lock_key(&[
                "dataset_rows",
                dataset_id,
            ])],
        )
        .map_err(|error| error.to_string())?;
    // Change bundle dry-run branches are previews whose copies carry no
    // classification: redaction and erasure drop them whole, and a rerun
    // refills from the edited base (#1692).
    let bundle_names = format!("{}%", dataset_branch::BUNDLE_BRANCH_PREFIX);
    for table in ["sekai_dataset_branch_rows", "sekai_dataset_branches"] {
        client
            .execute(
                &format!("DELETE FROM {table} WHERE dataset_id = $1 AND name LIKE $2"),
                &[&dataset_id, &bundle_names],
            )
            .map_err(|error| error.to_string())?;
    }
    let rows = client
        .query(
            "SELECT name, row_id, data FROM sekai_dataset_branch_rows
             WHERE dataset_id = $1 FOR UPDATE",
            &[&dataset_id],
        )
        .map_err(|error| error.to_string())?;
    for row in rows {
        let (name, row_id, data): (String, i64, String) = (row.get(0), row.get(1), row.get(2));
        match edit(serde_json::from_str(&data).ok()) {
            BranchRowEdit::Keep => {}
            BranchRowEdit::Replace(values) => {
                client
                    .execute(
                        "UPDATE sekai_dataset_branch_rows SET data = $1
                         WHERE dataset_id = $2 AND name = $3 AND row_id = $4",
                        &[&encode_row_map(&values)?, &dataset_id, &name, &row_id],
                    )
                    .map_err(|error| error.to_string())?;
            }
            BranchRowEdit::Delete => {
                client
                    .execute(
                        "DELETE FROM sekai_dataset_branch_rows
                         WHERE dataset_id = $1 AND name = $2 AND row_id = $3",
                        &[&dataset_id, &name, &row_id],
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
    }
    Ok(())
}
