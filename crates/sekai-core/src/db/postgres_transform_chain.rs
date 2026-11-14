//! PostgreSQL persistence for governed transform chains (#2119).

use std::collections::HashMap;

use postgres::Row;

use crate::db::postgres::PostgresDb;
use crate::db::transform_chain::{
    CHAIN_STEP_CLAIM_LEASE_MS, ChainStore, get_transform_chain_run, peek_transform_chain_run,
    put_transform_chain, run_transform_chain,
};
use crate::sekai::dataset::RowQuery;
use crate::sekai::governed_transform::TransformRun;
use crate::sekai::transform_chain::{ChainStepRun, TransformChain, TransformChainRun};

impl ChainStore for PostgresDb {
    fn persist_chain(&self, chain: &TransformChain, created_at_ms: i64) -> Result<(), String> {
        let json = serde_json::to_string(chain).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_transform_chain
                 (namespace, chain_id, definition_json, definition_digest, created_at_ms)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (namespace, chain_id) DO UPDATE SET
                    definition_json = EXCLUDED.definition_json,
                    definition_digest = EXCLUDED.definition_digest,
                    created_at_ms = EXCLUDED.created_at_ms",
                &[
                    &chain.namespace,
                    &chain.chain_id,
                    &json,
                    &chain.definition_digest,
                    &created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn load_chain(
        &self,
        namespace: &str,
        chain_id: &str,
    ) -> Result<Option<TransformChain>, String> {
        self.connection()?
            .query_opt(
                "SELECT definition_json FROM sekai_transform_chain
                 WHERE namespace = $1 AND chain_id = $2",
                &[&namespace, &chain_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .transpose()
    }

    fn persist_run(&self, run: &TransformChainRun) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // Terminal status is monotonic here; retry uses begin_retry.
        tx.execute(
            "INSERT INTO sekai_transform_chain_run
             (run_id, namespace, chain_id, definition_digest, definition_json, tenant_id, identity, status, failed_step, error, created_at_ms, completed_at_ms, input_digest, output_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT (run_id) DO UPDATE SET
                status = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.status
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND EXCLUDED.status = 'running' THEN sekai_transform_chain_run.status
                    ELSE EXCLUDED.status
                END,
                failed_step = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.failed_step
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND EXCLUDED.status = 'running' THEN sekai_transform_chain_run.failed_step
                    ELSE EXCLUDED.failed_step
                END,
                error = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.error
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND EXCLUDED.status = 'running' THEN sekai_transform_chain_run.error
                    ELSE EXCLUDED.error
                END,
                completed_at_ms = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.completed_at_ms
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND EXCLUDED.status = 'running' THEN sekai_transform_chain_run.completed_at_ms
                    ELSE EXCLUDED.completed_at_ms
                END,
                input_digest = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.input_digest
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND EXCLUDED.status = 'running' THEN sekai_transform_chain_run.input_digest
                    ELSE EXCLUDED.input_digest
                END,
                output_digest = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.output_digest
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND EXCLUDED.status = 'running' THEN sekai_transform_chain_run.output_digest
                    ELSE EXCLUDED.output_digest
                END",
            &[
                &run.run_id,
                &run.namespace,
                &run.chain_id,
                &run.definition_digest,
                &run.definition_json,
                &run.tenant_id,
                &run.identity,
                &run.status,
                &run.failed_step,
                &run.error,
                &run.created_at_ms,
                &run.completed_at_ms,
                &run.input_digest,
                &run.output_digest,
            ],
        )
        .map_err(|error| error.to_string())?;
        for step in &run.steps {
            tx.execute(
                "INSERT INTO sekai_transform_chain_step_run
                 (chain_run_id, step_name, transform_run_id, status)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (chain_run_id, step_name) DO UPDATE SET
                    transform_run_id = CASE WHEN sekai_transform_chain_step_run.transform_run_id = '' THEN EXCLUDED.transform_run_id ELSE sekai_transform_chain_step_run.transform_run_id END,
                    status = CASE WHEN sekai_transform_chain_step_run.status IN ('completed', 'failed', 'cancelled') THEN sekai_transform_chain_step_run.status ELSE EXCLUDED.status END",
                &[
                    &run.run_id,
                    &step.step,
                    &step.transform_run_id,
                    &step.status,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn try_insert_run(&self, run: &TransformChainRun) -> Result<bool, String> {
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO sekai_transform_chain_run
                 (run_id, namespace, chain_id, definition_digest, definition_json, tenant_id, identity, status, failed_step, error, created_at_ms, completed_at_ms, input_digest, output_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                 ON CONFLICT (namespace, chain_id, identity) DO NOTHING",
                &[
                    &run.run_id,
                    &run.namespace,
                    &run.chain_id,
                    &run.definition_digest,
                    &run.definition_json,
                    &run.tenant_id,
                    &run.identity,
                    &run.status,
                    &run.failed_step,
                    &run.error,
                    &run.created_at_ms,
                    &run.completed_at_ms,
                    &run.input_digest,
                    &run.output_digest,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    fn load_run(&self, run_id: &str) -> Result<Option<TransformChainRun>, String> {
        load_run_pg(&mut *self.connection()?, "run_id = $1", &[&run_id])
    }

    fn load_run_by_identity(
        &self,
        namespace: &str,
        chain_id: &str,
        identity: &str,
    ) -> Result<Option<TransformChainRun>, String> {
        load_run_pg(
            &mut *self.connection()?,
            "namespace = $1 AND chain_id = $2 AND identity = $3",
            &[&namespace, &chain_id, &identity],
        )
    }

    fn load_run_id_for_step(&self, transform_run_id: &str) -> Result<Option<String>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT chain_run_id FROM sekai_transform_chain_step_run
                 WHERE transform_run_id = $1",
                &[&transform_run_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0)))
    }

    fn try_claim_step(&self, run_id: &str, step: &str, now_ms: i64) -> Result<bool, String> {
        let changed = self
            .connection()?
            .execute(
                "INSERT INTO sekai_transform_chain_step_run
                 (chain_run_id, step_name, transform_run_id, status, claimed_at_ms)
                 VALUES ($1, $2, '', 'running', $3)
                 ON CONFLICT (chain_run_id, step_name) DO NOTHING",
                &[&run_id, &step, &now_ms],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    fn bind_step_run(
        &self,
        run_id: &str,
        step: &str,
        transform_run_id: &str,
    ) -> Result<bool, String> {
        let changed = self
            .connection()?
            .execute(
                "UPDATE sekai_transform_chain_step_run
                 SET transform_run_id = $3
                 WHERE chain_run_id = $1 AND step_name = $2 AND transform_run_id = ''",
                &[&run_id, &step, &transform_run_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    fn reclaim_stale_step(&self, run_id: &str, step: &str, now_ms: i64) -> Result<bool, String> {
        let deadline = now_ms.saturating_sub(CHAIN_STEP_CLAIM_LEASE_MS);
        let changed = self
            .connection()?
            .execute(
                "UPDATE sekai_transform_chain_step_run
                 SET claimed_at_ms = $3
                 WHERE chain_run_id = $1 AND step_name = $2
                   AND transform_run_id = '' AND claimed_at_ms <= $4",
                &[&run_id, &step, &now_ms, &deadline],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    fn begin_retry(&self, run_id: &str) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let changed = tx
            .execute(
                "UPDATE sekai_transform_chain_run
                 SET status = 'running', failed_step = '', error = '', completed_at_ms = 0
                 WHERE run_id = $1 AND status IN ('failed', 'cancelled')",
                &[&run_id],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute(
            "DELETE FROM sekai_transform_chain_step_run
             WHERE chain_run_id = $1 AND status != 'completed'",
            &[&run_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    fn dataset_partition_keys(&self, dataset_id: &str) -> Result<Vec<String>, String> {
        Ok(self
            .get_dataset(dataset_id)?
            .map(|dataset| dataset.partition_keys)
            .unwrap_or_default())
    }

    fn get_transform(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::GovernedTransform>, String> {
        self.get_governed_transform(namespace, transform_id)
    }

    fn run_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        tenant_id: &str,
        expected_definition_digest: &str,
        now_ms: i64,
    ) -> Result<TransformRun, String> {
        self.run_governed_transform_owned(
            namespace,
            transform_id,
            false,
            now_ms,
            tenant_id,
            expected_definition_digest,
        )
    }

    fn get_transform_run(&self, run_id: &str) -> Result<Option<TransformRun>, String> {
        self.get_governed_transform_run(run_id)
    }

    fn query_output_rows(&self, dataset_id: &str) -> Result<Vec<HashMap<String, String>>, String> {
        self.query_dataset_rows(dataset_id, &RowQuery::default())
    }

    fn append_chain_receipt(&self, receipt: &TransformRun) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        crate::db::postgres_receipt_chain::append_transform_run_chain(&mut tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn load_run_pg(
    client: &mut impl postgres::GenericClient,
    where_sql: &str,
    params: &[&(dyn postgres::types::ToSql + Sync)],
) -> Result<Option<TransformChainRun>, String> {
    let sql = format!(
        "SELECT run_id, namespace, chain_id, definition_digest, definition_json, tenant_id, identity, status, failed_step, error, created_at_ms, completed_at_ms, input_digest, output_digest
         FROM sekai_transform_chain_run WHERE {where_sql}"
    );
    let Some(row) = client
        .query_opt(&sql, params)
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let mut run = map_run(&row);
    let steps = client
        .query(
            "SELECT step_name, transform_run_id, status FROM sekai_transform_chain_step_run
             WHERE chain_run_id = $1 ORDER BY step_name",
            &[&run.run_id],
        )
        .map_err(|error| error.to_string())?;
    run.steps = steps
        .iter()
        .map(|row| ChainStepRun {
            step: row.get(0),
            transform_run_id: row.get(1),
            status: row.get(2),
        })
        .collect();
    Ok(Some(run))
}

fn map_run(row: &Row) -> TransformChainRun {
    TransformChainRun {
        run_id: row.get(0),
        namespace: row.get(1),
        chain_id: row.get(2),
        definition_digest: row.get(3),
        definition_json: row.get(4),
        tenant_id: row.get(5),
        identity: row.get(6),
        status: row.get(7),
        failed_step: row.get(8),
        error: row.get(9),
        steps: Vec::new(),
        created_at_ms: row.get(10),
        completed_at_ms: row.get(11),
        input_digest: row.get(12),
        output_digest: row.get(13),
    }
}

impl PostgresDb {
    pub fn put_transform_chain(
        &self,
        chain: &TransformChain,
        created_at_ms: i64,
    ) -> Result<TransformChain, String> {
        put_transform_chain(self, chain.clone(), created_at_ms)
    }

    pub fn run_transform_chain(
        &self,
        namespace: &str,
        chain_id: &str,
        idempotency_key: &str,
        tenant_id: &str,
        now_ms: i64,
    ) -> Result<(TransformChainRun, bool), String> {
        run_transform_chain(
            self,
            namespace,
            chain_id,
            idempotency_key,
            tenant_id,
            now_ms,
        )
    }

    pub fn peek_transform_chain_run(
        &self,
        run_id: &str,
    ) -> Result<Option<TransformChainRun>, String> {
        peek_transform_chain_run(self, run_id)
    }

    pub fn peek_transform_chain_run_by_identity(
        &self,
        namespace: &str,
        chain_id: &str,
        identity: &str,
    ) -> Result<Option<TransformChainRun>, String> {
        self.load_run_by_identity(namespace, chain_id, identity)
    }

    pub fn get_transform_chain_run(
        &self,
        run_id: &str,
        now_ms: i64,
    ) -> Result<Option<TransformChainRun>, String> {
        get_transform_chain_run(self, run_id, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::postgres::ScratchDatabase;
    use crate::db::receipt_chain::install_test_signer;
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, TransformStep,
        WriteTransformRunCommand, rows_digest,
    };
    use crate::sekai::transform_chain::{
        CHAIN_ASSERT_NOT_NULL, CHAIN_CONTRACT, CHAIN_PROFILE, CHAIN_WORK_CANCELLED,
        CHAIN_WORK_COMPLETED, CHAIN_WORK_RUNNING, ChainAssertion, ChainEdge, ChainStep,
    };
    use sekai_types::receipt_chain::{SigningKeySet, verify_bundle};
    use std::collections::HashMap;

    // Family DDL lives in chisei persist. Shared scratch applies the empty
    // sekai-core receipt_chain migration, so tests that export a bundle create
    // the tables the dest pair would apply on Chisei open.
    const RECEIPT_CHAIN_DDL: &str = "
CREATE TABLE IF NOT EXISTS chisei_receipt_chain (
    namespace TEXT NOT NULL,
    seq BIGINT NOT NULL,
    kind TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, seq)
);
CREATE INDEX IF NOT EXISTS idx_chisei_receipt_chain_receipt
    ON chisei_receipt_chain(namespace, receipt_id);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain_checkpoints (
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    head_seq BIGINT NOT NULL,
    head_hash TEXT NOT NULL,
    entry_count BIGINT NOT NULL,
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (namespace, kind, head_seq)
);
CREATE TABLE IF NOT EXISTS chisei_receipt_chain_keys (
    key_id TEXT PRIMARY KEY,
    public_key_hex TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    retired_at_ms BIGINT
);
";

    fn connect_with_receipts(scratch: &ScratchDatabase) -> PostgresDb {
        let db = scratch.connect();
        {
            let mut conn = db.connection().expect("scratch connection");
            conn.batch_execute(RECEIPT_CHAIN_DDL)
                .expect("receipt chain tables");
        }
        db
    }

    fn dataset(id: &str) -> Dataset {
        Dataset {
            id: id.into(),
            name: id.into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "keep".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }
    }

    fn projection(id: &str, input: &str, output: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: id.into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
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
        .unwrap()
    }

    fn isolated(id: &str, input: &str, output: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: id.into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                inputs: Vec::new(),
                requires: Default::default(),
                code: String::new(),
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    fn three_step_chain() -> TransformChain {
        TransformChain {
            contract_version: CHAIN_CONTRACT.into(),
            namespace: "ops".into(),
            chain_id: "pipe".into(),
            steps: vec![
                ChainStep {
                    name: "a".into(),
                    transform_id: "t1".into(),
                    transform_digest: String::new(),
                    assertions: vec![ChainAssertion {
                        kind: CHAIN_ASSERT_NOT_NULL.into(),
                        column: "id".into(),
                        value: String::new(),
                    }],
                },
                ChainStep {
                    name: "b".into(),
                    transform_id: "t2".into(),
                    transform_digest: String::new(),
                    assertions: Vec::new(),
                },
                ChainStep {
                    name: "c".into(),
                    transform_id: "t3".into(),
                    transform_digest: String::new(),
                    assertions: Vec::new(),
                },
            ],
            edges: vec![
                ChainEdge {
                    from_step: "a".into(),
                    output: "mid1".into(),
                    to_step: "b".into(),
                    input: "mid1".into(),
                },
                ChainEdge {
                    from_step: "b".into(),
                    output: "output".into(),
                    to_step: "c".into(),
                    input: "mid2".into(),
                },
            ],
            definition_digest: String::new(),
        }
    }

    fn seed_projection(db: &PostgresDb) {
        for id in ["in", "mid1", "mid2", "out"] {
            db.create_dataset(&dataset(id)).unwrap();
        }
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&projection("t1", "in", "mid1"), 10)
            .unwrap();
        db.put_governed_transform(&projection("t2", "mid1", "mid2"), 11)
            .unwrap();
        db.put_governed_transform(&projection("t3", "mid2", "out"), 12)
            .unwrap();
    }

    fn seed_isolated(db: &PostgresDb) {
        for id in ["in", "mid1", "mid2", "out"] {
            db.create_dataset(&dataset(id)).unwrap();
        }
        db.append_dataset_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated("t1", "in", "mid1"), 10)
            .unwrap();
        db.put_governed_transform(&isolated("t2", "mid1", "mid2"), 11)
            .unwrap();
        db.put_governed_transform(&isolated("t3", "mid2", "out"), 12)
            .unwrap();
    }

    fn write_claimed(db: &PostgresDb, now_ms: i64) -> TransformRun {
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, now_ms)
            .unwrap()
            .expect("claimable work");
        let output = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("keep".into(), "yes".into()),
        ])];
        db.write_transform_run(
            WriteTransformRunCommand {
                run_id: work.run_id.clone(),
                runtime_id: work.claim_owner.clone(),
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token.clone(),
                rows: output.clone(),
                output_digest: rows_digest(&output),
                quarantined: false,
                quality_rule: String::new(),
                ..WriteTransformRunCommand::default()
            },
            now_ms + 10,
        )
        .unwrap()
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_three_step_chain_completes_and_receipts_verify() {
        let scratch = ScratchDatabase::create();
        let db = connect_with_receipts(&scratch);
        let keys = SigningKeySet::from_seed_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
            1,
        )
        .unwrap();
        let _guard = install_test_signer(keys.clone());
        seed_projection(&db);
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (run, replayed) = db.run_transform_chain("ops", "pipe", "k1", "", 30).unwrap();
        assert!(!replayed);
        assert_eq!(run.status, CHAIN_WORK_COMPLETED);
        assert_eq!(run.steps.len(), 3);
        let (again, replayed) = db.run_transform_chain("ops", "pipe", "k1", "", 40).unwrap();
        assert!(replayed);
        assert_eq!(again.run_id, run.run_id);
        let bundle = crate::db::postgres_receipt_chain::export_receipt_chain(&db, "ops").unwrap();
        verify_bundle(&bundle, &[keys.current_public_key_hex().as_str()]).unwrap();
        let chain_entry = bundle
            .entries
            .iter()
            .find(|entry| entry.receipt_id == run.run_id)
            .expect("chain receipt");
        let receipt: TransformRun = serde_json::from_str(&chain_entry.receipt_json).unwrap();
        assert_eq!(receipt.profile, CHAIN_PROFILE);
        assert!(receipt.trigger_ref.contains(&run.steps[0].transform_run_id));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_kill_isolated_mid_chain_skips_downstream_and_rerun_skips_completed() {
        let scratch = ScratchDatabase::create();
        let db = scratch.connect();
        seed_isolated(&db);
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (run, _) = db
            .run_transform_chain("ops", "pipe", "k-kill", "", 30)
            .unwrap();
        assert_eq!(run.status, CHAIN_WORK_RUNNING);
        write_claimed(&db, 40);
        let after_a = db
            .get_transform_chain_run(&run.run_id, 50)
            .unwrap()
            .unwrap();
        assert_eq!(after_a.step_status("a"), Some(CHAIN_WORK_COMPLETED));
        let b_run_id = after_a.step_run_id("b").unwrap().to_string();
        db.cancel_governed_transform_run(&b_run_id, 60).unwrap();
        let failed = db
            .get_transform_chain_run(&run.run_id, 70)
            .unwrap()
            .unwrap();
        assert_eq!(failed.status, CHAIN_WORK_CANCELLED);
        assert!(failed.step_status("c").is_none());
        let a_run = failed.step_run_id("a").unwrap().to_string();
        let (rerun, _) = db
            .run_transform_chain("ops", "pipe", "k-kill", "", 80)
            .unwrap();
        assert_eq!(rerun.step_run_id("a"), Some(a_run.as_str()));
        write_claimed(&db, 90);
        write_claimed(&db, 110);
        let done = db
            .get_transform_chain_run(&run.run_id, 130)
            .unwrap()
            .unwrap();
        assert_eq!(done.status, CHAIN_WORK_COMPLETED);
        assert_eq!(
            db.query_dataset_rows("out", &RowQuery::default())
                .unwrap()
                .len(),
            1
        );
    }
}
