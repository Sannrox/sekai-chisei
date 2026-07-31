//! SQLite execution index for receipt-authoritative evaluation runs.

use crate::chisei::evaluation_execution::{EXECUTOR_VERSION, EvaluationExecutionIndex};
use crate::chisei::receipt::OperationReceipt;
use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl SekaiDb {
    pub(crate) fn migrate_evaluation_executions(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_evaluation_executions (
                    manifest_digest TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    namespace TEXT NOT NULL,
                    executor_version TEXT NOT NULL,
                    started_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    FOREIGN KEY(manifest_digest)
                        REFERENCES chisei_evaluation_manifests(manifest_digest),
                    FOREIGN KEY(operation_id)
                        REFERENCES chisei_operation_receipts(operation_id)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_executions_namespace
                    ON chisei_evaluation_executions(namespace, created_at_ms, operation_id);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn get_evaluation_execution_index(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<EvaluationExecutionIndex>, String> {
        self.conn()
            .query_row(
                "SELECT manifest_digest, operation_id, namespace, executor_version,
                        started_by, created_at_ms
                 FROM chisei_evaluation_executions
                 WHERE manifest_digest=?1",
                params![manifest_digest],
                index_from_row,
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn create_evaluation_execution(
        &self,
        index: &EvaluationExecutionIndex,
        receipt: &OperationReceipt,
    ) -> Result<EvaluationExecutionIndex, String> {
        validate_index_receipt(index, receipt)?;
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT manifest_digest, operation_id, namespace, executor_version,
                        started_by, created_at_ms
                 FROM chisei_evaluation_executions
                 WHERE manifest_digest=?1",
                params![index.manifest_digest],
                index_from_row,
            )
            .optional()
            .map_err(|error| error.to_string())?
        {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(existing);
        }
        let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO chisei_operation_receipts(
                    operation_id, request_id, lookup_request_id, initiating_actor,
                    caller_scope, namespace, receipt_json, updated_at
                 ) VALUES (?1,NULL,NULL,?2,NULL,?3,?4,?5)",
                params![
                    receipt.operation_id,
                    receipt.initiating_actor,
                    receipt.namespace,
                    receipt_json,
                    index.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO chisei_evaluation_executions(
                    manifest_digest, operation_id, namespace, executor_version,
                    started_by, created_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    index.manifest_digest,
                    index.operation_id,
                    index.namespace,
                    index.executor_version,
                    index.started_by,
                    index.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(index.clone())
    }
}

fn index_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EvaluationExecutionIndex> {
    Ok(EvaluationExecutionIndex {
        manifest_digest: row.get(0)?,
        operation_id: row.get(1)?,
        namespace: row.get(2)?,
        executor_version: row.get(3)?,
        started_by: row.get(4)?,
        created_at_ms: row.get(5)?,
    })
}

fn validate_index_receipt(
    index: &EvaluationExecutionIndex,
    receipt: &OperationReceipt,
) -> Result<(), String> {
    if index.executor_version != EXECUTOR_VERSION
        || index.manifest_digest.trim().is_empty()
        || index.operation_id != receipt.operation_id
        || index.namespace != receipt.namespace
        || index.started_by != receipt.initiating_actor
        || index.created_at_ms != receipt.started_at_ms
    {
        return Err("evaluation execution index and receipt binding is invalid".into());
    }
    Ok(())
}
