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
        use crate::db::postgres_audit::lock_object_lifecycle;
        use crate::db::postgres_governed_transform::{
            load_dataset_column_names, load_dataset_object_id, load_object_marking_token,
            load_row_records, load_transform, lock_transform_datasets,
        };
        use crate::sekai::governed_transform::{
            InputLoadBudget, TransformInputRows, compute_run_tables_until,
            derive_transform_markings, require_bound_output_for_markings,
        };
        dataset_branch::validate_branch_name(branch)?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let transform = load_transform(&mut tx, namespace, transform_id)?
            .ok_or_else(|| "governed transform not found".to_string())?;
        if transform.is_isolated_process() {
            return Err(dataset_branch::BRANCH_RUN_ISOLATED.into());
        }
        let bindings = transform.input_bindings();
        let output = transform.output_dataset_id.clone();
        let mut lock_ids: Vec<&str> = bindings.iter().map(|(_, id)| id.as_str()).collect();
        lock_ids.push(&output);
        lock_transform_datasets(&mut tx, &lock_ids)?;
        let mut budget = InputLoadBudget::for_transform(&transform);
        let mut loaded = Vec::new();
        let mut tokens = Vec::new();
        let mut branch_inputs = Vec::new();
        for (alias, dataset_id) in &bindings {
            let records = match load_branch(&mut tx, dataset_id, branch, true) {
                Ok(head) if head.tenant != tenant => {
                    return Err(dataset_branch::BRANCH_NOT_FOUND.into());
                }
                Ok(head) => {
                    branch_inputs.push(dataset_id.clone());
                    branch_records_budgeted(&mut tx, &head, budget.as_mut())?
                }
                Err(_) => load_row_records(&mut tx, dataset_id, 0, budget.as_mut())?,
            };
            if let Some(reason) = budget.as_ref().and_then(|budget| budget.exceeded) {
                return Err(format!("branch run refused: {reason}"));
            }
            loaded.push((
                alias.clone(),
                load_dataset_column_names(&mut tx, dataset_id)?,
                records,
            ));
            let object_id = load_dataset_object_id(&mut tx, dataset_id)?;
            tokens.push(load_object_marking_token(&mut tx, &object_id)?);
        }
        let output_object_id = load_dataset_object_id(&mut tx, &output)?;
        // Held to commit, so the marking checked here is the one the branch
        // rows land under, as on a parent run.
        if !output_object_id.trim().is_empty() {
            lock_object_lifecycle(&mut tx, &output_object_id)?;
        }
        let prior = load_object_marking_token(&mut tx, &output_object_id)?;
        let (_, markings_out) = derive_transform_markings(
            None,
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
            &transform,
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
        match load_branch(&mut tx, &output, branch, true) {
            Ok(head) if head.tenant != tenant => {
                return Err(dataset_branch::BRANCH_NOT_FOUND.into());
            }
            Ok(_) => {}
            Err(_) => {
                create_branch_pg(
                    &mut tx,
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
        let rows_written = write_branch_rows_pg(&mut tx, &output, branch, &rows, true)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(DatasetBranchRun {
            transform_id: transform_id.into(),
            branch: branch.into(),
            output_dataset_id: output,
            rows_written,
            branch_inputs,
            markings_out,
        })
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

pub(crate) fn create_branch_pg(
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

pub(crate) fn write_branch_rows_pg(
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
pub(crate) fn edit_branch_rows_pg(
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
