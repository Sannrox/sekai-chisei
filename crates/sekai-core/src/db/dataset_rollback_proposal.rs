//! SQLite and PostgreSQL storage for dataset rollback proposals (#3186).
//!
//! A proposal pins the dataset's newest version as its base. At most one
//! proposal per tenant, restore source and base is open at a time, so
//! proposing the same rollback again returns it. An approval restores the
//! source version, writing exactly one new dataset version, and records the
//! decision in the same transaction, so a crash leaves neither half. A
//! repeated decision replays without writing.

use rusqlite::{OptionalExtension, Transaction, params};

use super::OlderThan;
use super::postgres::PostgresDb;
use super::runtime_db::RuntimeDb;
use super::sekai::SekaiDb;
use crate::sekai::dataset_rollback::{
    self as rollback, DatasetRollbackProposal, DecideDatasetRollback, ProposeDatasetRollback,
};
use crate::sekai::dataset_version::{self, DatasetRollback};

pub(crate) const SQLITE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS sekai_dataset_rollback_proposals (
    id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL,
    restore_from_version_id TEXT NOT NULL,
    base_version_id TEXT NOT NULL,
    proposer TEXT NOT NULL,
    tenant TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    decided_by TEXT NOT NULL DEFAULT '',
    decision_reason TEXT NOT NULL DEFAULT '',
    restored_version_id TEXT NOT NULL DEFAULT '',
    receipt_id TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    decided_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sekai_dataset_rollback_proposals_one_open
    ON sekai_dataset_rollback_proposals(dataset_id, tenant, restore_from_version_id, base_version_id)
    WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_sekai_dataset_rollback_proposals_dataset
    ON sekai_dataset_rollback_proposals(dataset_id, tenant, created_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_sekai_dataset_rollback_proposals_pending
    ON sekai_dataset_rollback_proposals(tenant, status, created_at_ms DESC, id DESC);";

const COLUMNS: &str = "id, dataset_id, restore_from_version_id, base_version_id, proposer, \
     tenant, reason, status, decided_by, decision_reason, restored_version_id, receipt_id, \
     created_at_ms, decided_at_ms";

/// The same columns qualified by the `p` alias the pending listing joins on.
const P_COLUMNS: &str = "p.id, p.dataset_id, p.restore_from_version_id, p.base_version_id, \
     p.proposer, p.tenant, p.reason, p.status, p.decided_by, p.decision_reason, \
     p.restored_version_id, p.receipt_id, p.created_at_ms, p.decided_at_ms";

fn from_sqlite(row: &rusqlite::Row<'_>) -> rusqlite::Result<DatasetRollbackProposal> {
    Ok(DatasetRollbackProposal {
        id: row.get(0)?,
        dataset_id: row.get(1)?,
        restore_from_version_id: row.get(2)?,
        base_version_id: row.get(3)?,
        proposer: row.get(4)?,
        tenant: row.get(5)?,
        reason: row.get(6)?,
        status: row.get(7)?,
        decided_by: row.get(8)?,
        decision_reason: row.get(9)?,
        restored_version_id: row.get(10)?,
        receipt_id: row.get(11)?,
        created_at_ms: row.get(12)?,
        decided_at_ms: row.get(13)?,
    })
}

fn from_pg(row: &postgres::Row) -> DatasetRollbackProposal {
    DatasetRollbackProposal {
        id: row.get(0),
        dataset_id: row.get(1),
        restore_from_version_id: row.get(2),
        base_version_id: row.get(3),
        proposer: row.get(4),
        tenant: row.get(5),
        reason: row.get(6),
        status: row.get(7),
        decided_by: row.get(8),
        decision_reason: row.get(9),
        restored_version_id: row.get(10),
        receipt_id: row.get(11),
        created_at_ms: row.get(12),
        decided_at_ms: row.get(13),
    }
}

/// The proposal row a new proposal inserts, before the store fills its base.
fn new_proposal(
    request: &ProposeDatasetRollback,
    base_version_id: String,
) -> DatasetRollbackProposal {
    DatasetRollbackProposal {
        id: format!("drp_{}", uuid::Uuid::new_v4().simple()),
        dataset_id: request.dataset_id.clone(),
        restore_from_version_id: request.restore_from_version_id.clone(),
        base_version_id,
        proposer: request.actor.clone(),
        tenant: request.tenant.clone(),
        reason: request.reason.clone(),
        status: rollback::STATUS_OPEN.into(),
        decided_by: String::new(),
        decision_reason: String::new(),
        restored_version_id: String::new(),
        receipt_id: String::new(),
        created_at_ms: dataset_version::now_ms(),
        decided_at_ms: 0,
    }
}

/// `proposal` after `request` decided it; an approval names the version it
/// restored.
fn decided(
    mut proposal: DatasetRollbackProposal,
    request: &DecideDatasetRollback,
    restored_version_id: Option<String>,
) -> DatasetRollbackProposal {
    proposal.status = rollback::decided_status(request.approve).into();
    proposal.decided_by = request.actor.clone();
    proposal.decision_reason = request.reason.clone();
    proposal.decided_at_ms = dataset_version::now_ms();
    if let Some(version_id) = restored_version_id {
        proposal.receipt_id = rollback::receipt_id(&proposal, &version_id);
        proposal.restored_version_id = version_id;
    }
    proposal
}

/// The restore source must still be readable: a purged version refuses
/// with the proposal's own reason.
fn source_purged(purged: bool) -> Result<(), String> {
    if purged {
        Err(rollback::PROPOSAL_SOURCE_PURGED.into())
    } else {
        Ok(())
    }
}

fn restore_request(
    proposal: &DatasetRollbackProposal,
    request: &DecideDatasetRollback,
) -> DatasetRollback {
    DatasetRollback {
        dataset_id: proposal.dataset_id.clone(),
        restore_from_version_id: proposal.restore_from_version_id.clone(),
        reason: rollback::restored_version_reason(proposal),
        actor: request.actor.clone(),
        tenant: request.tenant.clone(),
    }
}

fn load_sqlite(
    tx: &Transaction<'_>,
    dataset_id: &str,
    id: &str,
) -> Result<DatasetRollbackProposal, String> {
    tx.query_row(
        &format!(
            "SELECT {COLUMNS} FROM sekai_dataset_rollback_proposals
             WHERE id = ?1 AND dataset_id = ?2"
        ),
        params![id, dataset_id],
        from_sqlite,
    )
    .optional()
    .map_err(|error| error.to_string())?
    .ok_or_else(|| rollback::PROPOSAL_NOT_FOUND.to_string())
}

impl SekaiDb {
    /// Opens a proposal to restore `restore_from_version_id`, based on the
    /// dataset's newest version. The same open rollback returns as is.
    pub fn propose_dataset_rollback(
        &self,
        request: &ProposeDatasetRollback,
    ) -> Result<DatasetRollbackProposal, String> {
        if request.restore_from_version_id.trim().is_empty() {
            return Err(dataset_version::DATASET_ROLLBACK_REQUIRES_RESTORE.into());
        }
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let source = crate::sekai::dataset::get_dataset_version_tx(
            &tx,
            &request.dataset_id,
            &request.restore_from_version_id,
            0,
        )?;
        source_purged(source.purged)?;
        let base = super::dataset_branch::latest_version_id(&tx, &request.dataset_id)?;
        let proposal = new_proposal(request, base);
        tx.execute(
            &format!(
                "INSERT OR IGNORE INTO sekai_dataset_rollback_proposals ({COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '', '', '', '', ?9, 0)"
            ),
            params![
                proposal.id,
                proposal.dataset_id,
                proposal.restore_from_version_id,
                proposal.base_version_id,
                proposal.proposer,
                proposal.tenant,
                proposal.reason,
                proposal.status,
                proposal.created_at_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        let open = tx
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_dataset_rollback_proposals
                     WHERE dataset_id = ?1 AND tenant = ?2 AND restore_from_version_id = ?3
                       AND base_version_id = ?4 AND status = ?5"
                ),
                params![
                    proposal.dataset_id,
                    proposal.tenant,
                    proposal.restore_from_version_id,
                    proposal.base_version_id,
                    rollback::STATUS_OPEN
                ],
                from_sqlite,
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(open)
    }

    pub fn get_dataset_rollback_proposal(
        &self,
        dataset_id: &str,
        id: &str,
    ) -> Result<DatasetRollbackProposal, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        load_sqlite(&tx, dataset_id, id)
    }

    /// Proposals of `tenant` on one dataset older than `before`, newest first.
    pub fn list_dataset_rollback_proposals(
        &self,
        dataset_id: &str,
        tenant: &str,
        limit: usize,
        before: OlderThan<'_>,
    ) -> Result<Vec<DatasetRollbackProposal>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM sekai_dataset_rollback_proposals
                 WHERE dataset_id = ?1 AND tenant = ?2 AND (created_at_ms, id) < (?3, ?4)
                 ORDER BY created_at_ms DESC, id DESC LIMIT ?5"
            ))
            .map_err(|error| error.to_string())?;
        stmt.query_map(
            params![dataset_id, tenant, before.at_ms, before.id, limit as i64],
            from_sqlite,
        )
        .map_err(|error| error.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())
    }

    /// Open proposals of `tenant` on datasets bound in `namespace`, older
    /// than `before`, newest first. A dataset is bound in the namespace of
    /// its binding object.
    pub fn list_open_dataset_rollback_proposals(
        &self,
        tenant: &str,
        namespace: &str,
        limit: usize,
        before: OlderThan<'_>,
    ) -> Result<Vec<DatasetRollbackProposal>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {P_COLUMNS} FROM sekai_dataset_rollback_proposals p
                 JOIN sekai_datasets d ON d.id = p.dataset_id
                 JOIN sekai_objects o ON o.id = d.object_id
                 WHERE p.tenant = ?1 AND p.status = ?2 AND o.namespace = ?3
                   AND (p.created_at_ms, p.id) < (?4, ?5)
                 ORDER BY p.created_at_ms DESC, p.id DESC LIMIT ?6"
            ))
            .map_err(|error| error.to_string())?;
        stmt.query_map(
            params![
                tenant,
                rollback::STATUS_OPEN,
                namespace,
                before.at_ms,
                before.id,
                limit as i64
            ],
            from_sqlite,
        )
        .map_err(|error| error.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|error| error.to_string())
    }

    /// Decides an open proposal. An approval needs the base still newest and
    /// the source still retained, and writes the restored version with the
    /// decision; a denial writes the decision only. A decision made the same
    /// way before replays unchanged.
    pub fn decide_dataset_rollback(
        &self,
        request: &DecideDatasetRollback,
    ) -> Result<DatasetRollbackProposal, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let proposal = load_sqlite(&tx, &request.dataset_id, &request.proposal_id)?;
        if rollback::check_decidable(&proposal, request)? {
            return Ok(proposal);
        }
        let restored = if request.approve {
            if super::dataset_branch::latest_version_id(&tx, &proposal.dataset_id)?
                != proposal.base_version_id
            {
                return Err(rollback::PROPOSAL_STALE_BASE.into());
            }
            source_purged(
                crate::sekai::dataset::get_dataset_version_tx(
                    &tx,
                    &proposal.dataset_id,
                    &proposal.restore_from_version_id,
                    0,
                )?
                .purged,
            )?;
            let version = crate::sekai::dataset::rollback_dataset_tx(
                &tx,
                &restore_request(&proposal, request),
            )?;
            Some(version.version_id)
        } else {
            None
        };
        let proposal = decided(proposal, request, restored);
        tx.execute(
            "UPDATE sekai_dataset_rollback_proposals
             SET status = ?1, decided_by = ?2, decision_reason = ?3, restored_version_id = ?4,
                 receipt_id = ?5, decided_at_ms = ?6
             WHERE id = ?7 AND status = ?8",
            params![
                proposal.status,
                proposal.decided_by,
                proposal.decision_reason,
                proposal.restored_version_id,
                proposal.receipt_id,
                proposal.decided_at_ms,
                proposal.id,
                rollback::STATUS_OPEN
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(proposal)
    }
}

fn load_pg(
    tx: &mut postgres::Transaction<'_>,
    dataset_id: &str,
    id: &str,
    for_update: bool,
) -> Result<DatasetRollbackProposal, String> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    tx.query_opt(
        &format!(
            "SELECT {COLUMNS} FROM sekai_dataset_rollback_proposals
             WHERE id = $1 AND dataset_id = $2{lock}"
        ),
        &[&id, &dataset_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| from_pg(&row))
    .ok_or_else(|| rollback::PROPOSAL_NOT_FOUND.to_string())
}

impl PostgresDb {
    /// See [`SekaiDb::propose_dataset_rollback`].
    pub fn propose_dataset_rollback(
        &self,
        request: &ProposeDatasetRollback,
    ) -> Result<DatasetRollbackProposal, String> {
        if request.restore_from_version_id.trim().is_empty() {
            return Err(dataset_version::DATASET_ROLLBACK_REQUIRES_RESTORE.into());
        }
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        super::postgres::lock_dataset_rows(&mut tx, &request.dataset_id)?;
        let source = super::postgres_dataset::get_dataset_version_pg(
            &mut tx,
            &request.dataset_id,
            &request.restore_from_version_id,
            0,
        )?;
        source_purged(source.purged)?;
        let base = super::postgres_dataset_branch::latest_version_id(&mut tx, &request.dataset_id)?;
        let proposal = new_proposal(request, base);
        tx.execute(
            &format!(
                "INSERT INTO sekai_dataset_rollback_proposals ({COLUMNS})
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '', '', '', '', $9, 0)
                 ON CONFLICT DO NOTHING"
            ),
            &[
                &proposal.id,
                &proposal.dataset_id,
                &proposal.restore_from_version_id,
                &proposal.base_version_id,
                &proposal.proposer,
                &proposal.tenant,
                &proposal.reason,
                &proposal.status,
                &proposal.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        let open = tx
            .query_one(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_dataset_rollback_proposals
                     WHERE dataset_id = $1 AND tenant = $2 AND restore_from_version_id = $3
                       AND base_version_id = $4 AND status = $5"
                ),
                &[
                    &proposal.dataset_id,
                    &proposal.tenant,
                    &proposal.restore_from_version_id,
                    &proposal.base_version_id,
                    &rollback::STATUS_OPEN,
                ],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(from_pg(&open))
    }

    /// See [`SekaiDb::get_dataset_rollback_proposal`].
    pub fn get_dataset_rollback_proposal(
        &self,
        dataset_id: &str,
        id: &str,
    ) -> Result<DatasetRollbackProposal, String> {
        let mut connection = self.connection()?;
        let mut tx = super::postgres_dataset_branch::read_snapshot(&mut connection)?;
        load_pg(&mut tx, dataset_id, id, false)
    }

    /// See [`SekaiDb::list_dataset_rollback_proposals`].
    pub fn list_dataset_rollback_proposals(
        &self,
        dataset_id: &str,
        tenant: &str,
        limit: usize,
        before: OlderThan<'_>,
    ) -> Result<Vec<DatasetRollbackProposal>, String> {
        Ok(self
            .connection()?
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_dataset_rollback_proposals
                     WHERE dataset_id = $1 AND tenant = $2 AND (created_at_ms, id) < ($3, $4)
                     ORDER BY created_at_ms DESC, id DESC LIMIT $5"
                ),
                &[
                    &dataset_id,
                    &tenant,
                    &before.at_ms,
                    &before.id,
                    &(limit as i64),
                ],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(from_pg)
            .collect())
    }

    /// See [`SekaiDb::list_open_dataset_rollback_proposals`].
    pub fn list_open_dataset_rollback_proposals(
        &self,
        tenant: &str,
        namespace: &str,
        limit: usize,
        before: OlderThan<'_>,
    ) -> Result<Vec<DatasetRollbackProposal>, String> {
        Ok(self
            .connection()?
            .query(
                &format!(
                    "SELECT {P_COLUMNS} FROM sekai_dataset_rollback_proposals p
                     JOIN sekai_datasets d ON d.id = p.dataset_id
                     JOIN sekai_objects o ON o.id = d.object_id
                     WHERE p.tenant = $1 AND p.status = $2 AND o.namespace = $3
                       AND (p.created_at_ms, p.id) < ($4, $5)
                     ORDER BY p.created_at_ms DESC, p.id DESC LIMIT $6"
                ),
                &[
                    &tenant,
                    &rollback::STATUS_OPEN,
                    &namespace,
                    &before.at_ms,
                    &before.id,
                    &(limit as i64),
                ],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(from_pg)
            .collect())
    }

    /// See [`SekaiDb::decide_dataset_rollback`].
    pub fn decide_dataset_rollback(
        &self,
        request: &DecideDatasetRollback,
    ) -> Result<DatasetRollbackProposal, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        super::postgres::lock_dataset_rows(&mut tx, &request.dataset_id)?;
        let proposal = load_pg(&mut tx, &request.dataset_id, &request.proposal_id, true)?;
        if rollback::check_decidable(&proposal, request)? {
            return Ok(proposal);
        }
        let restored = if request.approve {
            if super::postgres_dataset_branch::latest_version_id(&mut tx, &proposal.dataset_id)?
                != proposal.base_version_id
            {
                return Err(rollback::PROPOSAL_STALE_BASE.into());
            }
            source_purged(
                super::postgres_dataset::get_dataset_version_pg(
                    &mut tx,
                    &proposal.dataset_id,
                    &proposal.restore_from_version_id,
                    0,
                )?
                .purged,
            )?;
            let version = super::postgres_dataset::rollback_dataset_pg(
                &mut tx,
                &restore_request(&proposal, request),
            )?;
            Some(version.version_id)
        } else {
            None
        };
        let proposal = decided(proposal, request, restored);
        tx.execute(
            "UPDATE sekai_dataset_rollback_proposals
             SET status = $1, decided_by = $2, decision_reason = $3, restored_version_id = $4,
                 receipt_id = $5, decided_at_ms = $6
             WHERE id = $7 AND status = $8",
            &[
                &proposal.status,
                &proposal.decided_by,
                &proposal.decision_reason,
                &proposal.restored_version_id,
                &proposal.receipt_id,
                &proposal.decided_at_ms,
                &proposal.id,
                &rollback::STATUS_OPEN,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(proposal)
    }
}

/// Dual-backend dispatch for dataset rollback proposals.
impl RuntimeDb {
    pub fn propose_dataset_rollback(
        &self,
        request: &ProposeDatasetRollback,
    ) -> Result<DatasetRollbackProposal, String> {
        match self {
            Self::Sqlite(db) => db.propose_dataset_rollback(request),
            Self::Postgres(db) => {
                super::postgres::off_runtime(|| db.propose_dataset_rollback(request))
            }
        }
    }

    pub fn get_dataset_rollback_proposal(
        &self,
        dataset_id: &str,
        id: &str,
    ) -> Result<DatasetRollbackProposal, String> {
        match self {
            Self::Sqlite(db) => db.get_dataset_rollback_proposal(dataset_id, id),
            Self::Postgres(db) => {
                super::postgres::off_runtime(|| db.get_dataset_rollback_proposal(dataset_id, id))
            }
        }
    }

    pub fn list_dataset_rollback_proposals(
        &self,
        dataset_id: &str,
        tenant: &str,
        limit: usize,
        before: OlderThan<'_>,
    ) -> Result<Vec<DatasetRollbackProposal>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_dataset_rollback_proposals(dataset_id, tenant, limit, before)
            }
            Self::Postgres(db) => super::postgres::off_runtime(|| {
                db.list_dataset_rollback_proposals(dataset_id, tenant, limit, before)
            }),
        }
    }

    pub fn list_open_dataset_rollback_proposals(
        &self,
        tenant: &str,
        namespace: &str,
        limit: usize,
        before: OlderThan<'_>,
    ) -> Result<Vec<DatasetRollbackProposal>, String> {
        match self {
            Self::Sqlite(db) => {
                db.list_open_dataset_rollback_proposals(tenant, namespace, limit, before)
            }
            Self::Postgres(db) => super::postgres::off_runtime(|| {
                db.list_open_dataset_rollback_proposals(tenant, namespace, limit, before)
            }),
        }
    }

    pub fn decide_dataset_rollback(
        &self,
        request: &DecideDatasetRollback,
    ) -> Result<DatasetRollbackProposal, String> {
        match self {
            Self::Sqlite(db) => db.decide_dataset_rollback(request),
            Self::Postgres(db) => {
                super::postgres::off_runtime(|| db.decide_dataset_rollback(request))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::db::OlderThan;
    use crate::db::runtime_db::RuntimeDb;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::dataset_rollback::{
        self as rollback, DecideDatasetRollback, ProposeDatasetRollback,
    };

    fn row(value: &str) -> HashMap<String, String> {
        HashMap::from([("value".to_string(), value.to_string())])
    }

    /// A dataset with one version per row batch, oldest first.
    fn dataset(db: &RuntimeDb, batches: &[&str]) -> (String, Vec<String>) {
        let id = format!("ds-{}", uuid::Uuid::new_v4().simple());
        db.create_dataset(&Dataset {
            id: id.clone(),
            name: id.clone(),
            columns: vec![ColumnDef {
                name: "value".into(),
                col_type: "string".into(),
                classification: "internal".into(),
            }],
            object_id: String::new(),
            created: 0,
            partition_keys: Vec::new(),
        })
        .unwrap();
        for value in batches {
            db.append_rows(&id, &[row(value)]).unwrap();
        }
        let versions = versions(db, &id);
        (id, versions)
    }

    fn versions(db: &RuntimeDb, id: &str) -> Vec<String> {
        db.list_dataset_versions(id)
            .unwrap()
            .into_iter()
            .map(|version| version.version_id)
            .collect()
    }

    fn propose(db: &RuntimeDb, id: &str, source: &str) -> rollback::DatasetRollbackProposal {
        db.propose_dataset_rollback(&ProposeDatasetRollback {
            dataset_id: id.into(),
            restore_from_version_id: source.into(),
            reason: "bad load".into(),
            actor: "alice".into(),
            tenant: "t1".into(),
        })
        .unwrap()
    }

    fn decide(
        db: &RuntimeDb,
        id: &str,
        proposal_id: &str,
        actor: &str,
        approve: bool,
    ) -> Result<rollback::DatasetRollbackProposal, String> {
        db.decide_dataset_rollback(&DecideDatasetRollback {
            dataset_id: id.into(),
            proposal_id: proposal_id.into(),
            approve,
            reason: String::new(),
            actor: actor.into(),
            tenant: "t1".into(),
        })
    }

    /// The #3186 acceptance on one store: only another principal applies a
    /// proposal, exactly once; a denial changes nothing; a moved base or a
    /// purged source refuses by name.
    fn exercise(db: &RuntimeDb) {
        let (id, before) = dataset(db, &["a", "b"]);
        let proposal = propose(db, &id, &before[0]);
        assert_eq!(proposal.base_version_id, before[1]);
        assert_eq!(propose(db, &id, &before[0]).id, proposal.id);

        assert_eq!(
            decide(db, &id, &proposal.id, "alice", true).unwrap_err(),
            rollback::PROPOSAL_SELF_DECIDE
        );
        let approved = decide(db, &id, &proposal.id, "bob", true).unwrap();
        assert_eq!(approved.status, rollback::STATUS_APPROVED);
        assert!(!approved.receipt_id.is_empty());
        let after = versions(db, &id);
        assert_eq!(after.len(), 3);
        assert_eq!(after[2], approved.restored_version_id);
        let restored = db.list_dataset_versions(&id).unwrap().pop().unwrap();
        assert_eq!(restored.restored_from_version_id, before[0]);
        // A replay returns the decision and writes no second version.
        assert_eq!(
            decide(db, &id, &proposal.id, "carol", true).unwrap(),
            approved
        );
        assert_eq!(versions(db, &id).len(), 3);
        assert_eq!(
            decide(db, &id, &proposal.id, "carol", false).unwrap_err(),
            rollback::PROPOSAL_DECIDED
        );

        // Denied: the dataset is unchanged and nothing is pending.
        let denied = propose(db, &id, &before[1]);
        let decision = decide(db, &id, &denied.id, "bob", false).unwrap();
        assert_eq!(decision.status, rollback::STATUS_DENIED);
        assert_eq!(versions(db, &id).len(), 3);

        // A newer version than the base refuses the approval.
        let stale = propose(db, &id, &before[0]);
        db.append_rows(&id, &[row("c")]).unwrap();
        assert_eq!(
            decide(db, &id, &stale.id, "bob", true).unwrap_err(),
            rollback::PROPOSAL_STALE_BASE
        );

        let listed = db
            .list_dataset_rollback_proposals(&id, "t1", 10, OlderThan::START)
            .unwrap();
        assert_eq!(listed.len(), 3);
        assert!(
            db.list_dataset_rollback_proposals(&id, "t2", 10, OlderThan::START)
                .unwrap()
                .is_empty()
        );

        // Retention purges the source after the proposal pinned it.
        let (id, before) = dataset(db, &["a", "b", "c"]);
        let purged = propose(db, &id, &before[0]);
        // Pruning keeps the newest version, so the base has not moved.
        db.set_dataset_version_retention(&id, 1).unwrap();
        assert_eq!(
            decide(db, &id, &purged.id, "bob", true).unwrap_err(),
            rollback::PROPOSAL_SOURCE_PURGED
        );
    }

    #[test]
    fn sqlite_rollback_proposals_apply_once_by_another_principal() {
        exercise(&RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
    }

    /// A decision is durable: after a restart the same approval replays the
    /// stored decision and writes no second version.
    #[test]
    fn sqlite_approval_replays_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "rollback-restart-{}-{}.db",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let path_str = path.to_str().unwrap();
        let open = || RuntimeDb::Sqlite(Arc::new(SekaiDb::new(path_str).unwrap()));
        let (id, approved) = {
            let db = open();
            let (id, before) = dataset(&db, &["a", "b"]);
            let proposal = propose(&db, &id, &before[0]);
            (
                id.clone(),
                decide(&db, &id, &proposal.id, "bob", true).unwrap(),
            )
        };
        let db = open();
        assert_eq!(
            decide(&db, &id, &approved.id, "bob", true).unwrap(),
            approved
        );
        assert_eq!(versions(&db, &id).len(), 3);
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path_str}{suffix}"));
        }
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_rollback_proposals_apply_once_by_another_principal() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        exercise(&RuntimeDb::Postgres(Arc::new(scratch.connect())));
    }
}
