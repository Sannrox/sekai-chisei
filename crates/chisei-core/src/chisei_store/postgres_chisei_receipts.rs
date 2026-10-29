//! PostgreSQL operation receipt and gateway request-alias persistence.

use crate::chisei_store::ext::ReceiptChainPostgresDbExt;
use sekai_core::db::postgres::PostgresDb;
use sekai_domain::receipt::{OperationReceipt, ReceiptEventKind};

pub trait PostgresChiseiReceiptsPostgresDbExt {
    fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String>;

    fn upsert_operation_receipt_on<C: postgres::GenericClient>(
        &self,
        client: &mut C,
        receipt: &OperationReceipt,
    ) -> Result<(), String>;

    fn count_active_kioku_promotions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
    ) -> Result<i64, String>;

    fn list_kioku_lifecycle_events_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::chisei::kioku::MemoryLifecycleEvent>, String>;

    fn list_kioku_outcomes_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::chisei::kioku::MemoryOutcomeObservation>, String>;
}

impl PostgresChiseiReceiptsPostgresDbExt for PostgresDb {
    fn insert_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        let request_id = intent_attr(receipt, "request_id");
        let lookup_request_id = intent_attr(receipt, "lookup_request_id");
        let caller_scope = intent_attr(receipt, "caller_scope");
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO chisei_operation_receipts(
                    operation_id, request_id, lookup_request_id, initiating_actor,
                    caller_scope, namespace, receipt_json, updated_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &receipt.operation_id,
                &request_id,
                &lookup_request_id,
                &receipt.initiating_actor,
                &caller_scope,
                &receipt.namespace,
                &receipt_json,
                &chrono::Utc::now().timestamp_millis(),
            ],
        )
        .map_err(|error| error.to_string())?;
        self.append_operation_receipt_chain(&mut tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())
    }

    fn upsert_operation_receipt_on<C: postgres::GenericClient>(
        &self,
        client: &mut C,
        receipt: &OperationReceipt,
    ) -> Result<(), String> {
        let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        let request_id = intent_attr(receipt, "request_id");
        let lookup_request_id = intent_attr(receipt, "lookup_request_id");
        let caller_scope = intent_attr(receipt, "caller_scope");
        client
            .execute(
                "INSERT INTO chisei_operation_receipts(
                    operation_id, request_id, lookup_request_id, initiating_actor,
                    caller_scope, namespace, receipt_json, updated_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (operation_id) DO UPDATE SET
                    request_id = EXCLUDED.request_id,
                    lookup_request_id = CASE
                      WHEN chisei_operation_receipts.alias_retired = 1 THEN NULL
                      ELSE EXCLUDED.lookup_request_id
                    END,
                    initiating_actor = EXCLUDED.initiating_actor,
                    caller_scope = COALESCE(
                        EXCLUDED.caller_scope, chisei_operation_receipts.caller_scope
                    ),
                    namespace = EXCLUDED.namespace,
                    receipt_json = EXCLUDED.receipt_json,
                    updated_at = EXCLUDED.updated_at",
                &[
                    &receipt.operation_id,
                    &request_id,
                    &lookup_request_id,
                    &receipt.initiating_actor,
                    &caller_scope,
                    &receipt.namespace,
                    &receipt_json,
                    &chrono::Utc::now().timestamp_millis(),
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn count_active_kioku_promotions_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
    ) -> Result<i64, String> {
        self.connection()?
            .query_one(
                "SELECT COUNT(*)
                 FROM chisei_kioku_lifecycle_events AS lifecycle
                 JOIN chisei_kioku_memories AS memory
                   ON memory.id=lifecycle.memory_id AND memory.version=lifecycle.memory_version
                 WHERE memory.namespace=$1 AND memory.state='active'
                   AND lifecycle.action='promoted'
                   AND lifecycle.recorded_at_ms >= $2
                   AND lifecycle.recorded_at_ms < $3",
                &[&namespace, &start_timestamp_ms, &end_timestamp_ms],
            )
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }

    fn list_kioku_lifecycle_events_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::chisei::kioku::MemoryLifecycleEvent>, String> {
        let limit = i64::try_from(limit.min(5_001)).unwrap_or(5_001);
        let rows = self
            .connection()?
            .query(
                "SELECT lifecycle.memory_id, lifecycle.memory_version, lifecycle.action,
                        lifecycle.from_state, lifecycle.to_state, lifecycle.actor,
                        lifecycle.reason, lifecycle.recorded_at_ms
                 FROM chisei_kioku_lifecycle_events AS lifecycle
                 JOIN chisei_kioku_memories AS memory
                   ON memory.id=lifecycle.memory_id AND memory.version=lifecycle.memory_version
                 WHERE memory.namespace=$1
                   AND lifecycle.recorded_at_ms >= $2
                   AND lifecycle.recorded_at_ms < $3
                 ORDER BY lifecycle.recorded_at_ms, lifecycle.id
                 LIMIT $4",
                &[&namespace, &start_timestamp_ms, &end_timestamp_ms, &limit],
            )
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| {
                Ok(crate::chisei::kioku::MemoryLifecycleEvent {
                    memory_id: row.get(0),
                    memory_version: row.get::<_, i64>(1) as u32,
                    action: row.get(2),
                    from_state: row.get(3),
                    to_state: row.get(4),
                    actor: row.get(5),
                    reason: row.get(6),
                    recorded_at_ms: row.get(7),
                })
            })
            .collect()
    }

    fn list_kioku_outcomes_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::chisei::kioku::MemoryOutcomeObservation>, String> {
        let limit = i64::try_from(limit.min(5_001)).unwrap_or(5_001);
        let rows = self
            .connection()?
            .query(
                "SELECT outcome.memory_id, outcome.memory_version, outcome.operation_id,
                        outcome.memory_applied, outcome.outcome_metric, outcome.outcome_value,
                        outcome.passed, outcome.recorded_at_ms
                 FROM chisei_kioku_outcomes AS outcome
                 JOIN chisei_kioku_memories AS memory
                   ON memory.id=outcome.memory_id AND memory.version=outcome.memory_version
                 WHERE memory.namespace=$1
                   AND outcome.recorded_at_ms >= $2
                   AND outcome.recorded_at_ms < $3
                 ORDER BY outcome.recorded_at_ms, outcome.operation_id
                 LIMIT $4",
                &[&namespace, &start_timestamp_ms, &end_timestamp_ms, &limit],
            )
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| {
                Ok(crate::chisei::kioku::MemoryOutcomeObservation {
                    memory_id: row.get(0),
                    memory_version: row.get::<_, i64>(1) as u32,
                    operation_id: row.get(2),
                    request_id: String::new(),
                    memory_applied: row.get::<_, i64>(3) != 0,
                    outcome_metric: row.get(4),
                    outcome_value: row.get(5),
                    passed: row.get::<_, i64>(6) != 0,
                    recorded_at_ms: row.get(7),
                })
            })
            .collect()
    }
}

fn intent_attr(receipt: &OperationReceipt, key: &str) -> Option<String> {
    receipt.events.iter().find_map(|event| {
        (event.kind == ReceiptEventKind::IntentRecorded)
            .then(|| event.attributes.get(key))
            .flatten()
            .filter(|value| !value.is_empty())
            .cloned()
    })
}
