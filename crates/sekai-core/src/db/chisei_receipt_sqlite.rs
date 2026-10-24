//! Receipt persistence moved with `RuntimeDb` so Sekai admission can record events.

use crate::db::chisei_receipt::{
    open_receipt_min_started_at_ms, validate_evaluation_receipt_event_order,
};
use crate::db::sekai::SekaiDb;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sekai_domain::receipt::{
    OperationReceipt, OperationReceiptEvent, OperationReporterGrant, ReceiptEventKind,
};

impl SekaiDb {
    pub fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        let _span = tracing::info_span!(
            "stage",
            stage = crate::obs::correlation::Stage::Persistence.as_str(),
        )
        .entered();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        upsert_operation_receipt(&tx, receipt)?;
        self.append_operation_receipt_chain(&tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn get_operation_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        let conn = self.conn();
        let receipt_json = conn
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id=?1",
                params![operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        receipt_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn list_operation_receipts_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<OperationReceipt>, String> {
        // Callers may pass max+1 to detect overflow; allow that sentinel.
        let limit = limit.min(5_001) as i64;
        // Open receipts stay harvestable until ack (#645). Windowed lists still
        // drop abandoned opens whose start is older than the overlap TTL so
        // narrowing a window actually shrinks the result set.
        let open_min_started_at_ms = open_receipt_min_started_at_ms(start_timestamp_ms);
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE namespace=?1
                   AND CAST(json_extract(receipt_json, '$.started_at_ms') AS INTEGER) < ?3
                   AND (
                     (
                       json_extract(receipt_json, '$.completed_at_ms') IS NOT NULL
                       AND CAST(json_extract(receipt_json, '$.completed_at_ms') AS INTEGER) >= ?2
                     )
                     OR (
                       json_extract(receipt_json, '$.completed_at_ms') IS NULL
                       AND CAST(json_extract(receipt_json, '$.started_at_ms') AS INTEGER) >= ?5
                     )
                   )
                 ORDER BY CAST(json_extract(receipt_json, '$.started_at_ms') AS INTEGER), operation_id
                 LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                params![
                    namespace,
                    start_timestamp_ms,
                    end_timestamp_ms,
                    limit,
                    open_min_started_at_ms
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?;
        let mut receipts = Vec::new();
        for row in rows {
            let json = row.map_err(|error| error.to_string())?;
            receipts.push(serde_json::from_str(&json).map_err(|error| error.to_string())?);
        }
        Ok(receipts)
    }

    pub fn update_operation_receipt<F>(
        &self,
        operation_id: &str,
        update: F,
    ) -> Result<OperationReceipt, String>
    where
        F: FnOnce(&mut OperationReceipt) -> Result<(), String>,
    {
        // Hold the same sole connection guard used by reporter appends across
        // this entire read-modify-write operation so completion cannot erase
        // evidence reported concurrently.
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let receipt_json = tx
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id=?1",
                params![operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        let original = receipt.clone();
        update(&mut receipt)?;
        if receipt == original {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(receipt);
        }
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE chisei_operation_receipts SET receipt_json=?1, updated_at=?2 WHERE operation_id=?3",
            params![updated_json, chrono::Utc::now().timestamp_millis(), operation_id],
        )
        .map_err(|error| error.to_string())?;
        self.append_operation_receipt_chain(&tx, &receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(receipt)
    }

    pub fn reserve_gateway_request_alias(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let receipt_exists = transaction
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM chisei_operation_receipts
                   WHERE caller_scope=?1 AND lookup_request_id=?2
                 )",
                params![caller_scope, request_alias],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| error.to_string())?;
        if receipt_exists {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let existing_reservation = transaction
            .query_row(
                "SELECT request_id, operation_id, dispatch_started
                 FROM chisei_gateway_request_aliases
                 WHERE caller_scope=?1 AND request_alias=?2",
                params![caller_scope, request_alias],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some((existing_request_id, existing_operation_id, dispatch_started)) =
            existing_reservation
        {
            let resumable = existing_request_id == request_id
                && existing_operation_id == operation_id
                && !dispatch_started;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(resumable);
        }
        let reserved = transaction.execute(
            "INSERT OR IGNORE INTO chisei_gateway_request_aliases(caller_scope, request_alias, request_id, operation_id, reserved_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                caller_scope,
                request_alias,
                request_id,
                operation_id,
                chrono::Utc::now().timestamp_millis()
            ],
        )
        .map_err(|error| error.to_string())? == 1;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(reserved)
    }

    pub fn claim_gateway_request_alias_dispatch(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
        dispatch_token: &str,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let claimed = transaction
            .execute(
                "UPDATE chisei_gateway_request_aliases
                 SET dispatch_started=1, dispatch_token=?1
                 WHERE caller_scope=?2 AND request_alias=?3 AND request_id=?4
                   AND operation_id=?5 AND dispatch_started=0",
                params![
                    dispatch_token,
                    caller_scope,
                    request_alias,
                    request_id,
                    operation_id,
                ],
            )
            .map_err(|error| error.to_string())?
            == 1;
        let same_claim = if claimed {
            true
        } else {
            transaction
                .query_row(
                    "SELECT dispatch_token=?1
                     FROM chisei_gateway_request_aliases
                     WHERE caller_scope=?2 AND request_alias=?3 AND request_id=?4
                       AND operation_id=?5 AND dispatch_started=1",
                    params![
                        dispatch_token,
                        caller_scope,
                        request_alias,
                        request_id,
                        operation_id,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .unwrap_or(false)
        };
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(same_claim)
    }

    pub fn find_gateway_receipt_by_logical_operation_id(
        &self,
        operation_id: &str,
        attempt: Option<u32>,
    ) -> Result<Option<OperationReceipt>, String> {
        let conn = self.conn();
        let attempt = attempt.map(|attempt| attempt.to_string());
        let mut statement = conn
            .prepare(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE instr(operation_id, ?1 || ':__attempt__:')=1
                   AND (?2 IS NULL OR operation_id LIKE '%:' || ?2)
                 ORDER BY updated_at DESC, operation_id DESC LIMIT 2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![operation_id, attempt], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if rows.len() > 1 {
            return Err("logical operation id matches multiple receipt attempts".into());
        }
        rows.into_iter()
            .next()
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        let conn = self.conn();
        let receipt_json = conn
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE request_id=?1",
                params![request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        receipt_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn find_operation_receipt_by_lookup_request_id(
        &self,
        request_id: &str,
        caller_scope: Option<&str>,
        initiating_actor: Option<&str>,
    ) -> Result<Option<OperationReceipt>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE lookup_request_id=?1
                   AND (?2 IS NULL OR caller_scope=?2)
                   AND (?3 IS NULL OR initiating_actor=?3)
                 ORDER BY operation_id LIMIT 2",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![request_id, caller_scope, initiating_actor], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if rows.len() > 1 {
            return Err("request id matches multiple operation receipts".into());
        }
        rows.into_iter()
            .next()
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String> {
        if event.operation_id != operation_id {
            return Err("event operation id does not match receipt".into());
        }
        // `conn()` returns the database's sole `MutexGuard<Connection>` and
        // this guard remains live through the read, mutation, and update below.
        // Concurrent reporters therefore serialize across this whole JSON
        // read-modify-write sequence rather than overwriting one another.
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let receipt_json = tx
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id=?1",
                params![operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        if let Some(existing) = receipt
            .events
            .iter()
            .find(|existing| existing.event_id == event.event_id)
        {
            let mut replay = event.clone();
            replay.timestamp_ms = existing.timestamp_ms;
            if existing == &replay {
                tx.commit().map_err(|error| error.to_string())?;
                return Ok((receipt, false));
            }
            return Err(format!(
                "event {} already exists with different evidence",
                event.event_id
            ));
        }
        validate_evaluation_receipt_event_order(&receipt, &event)?;
        if let Some((metric, value, passed)) = crate::db::chisei_receipt::outcome_evidence(&event)?
        {
            for existing in &receipt.events {
                let Some((existing_metric, existing_value, existing_passed)) =
                    crate::db::chisei_receipt::outcome_evidence(existing)?
                else {
                    continue;
                };
                if existing_metric == metric
                    && (existing_value != value || existing_passed != passed)
                {
                    return Err(format!(
                        "outcome metric {metric} already exists with different evidence"
                    ));
                }
            }
        }
        let parent_id = event
            .parent_event_id
            .as_deref()
            .ok_or_else(|| "reported event requires a causal parent".to_string())?;
        if !receipt
            .events
            .iter()
            .any(|existing| existing.event_id == parent_id)
        {
            return Err(format!("causal parent {parent_id} not found"));
        }
        receipt
            .uncovered_surfaces
            .retain(|entry| entry.surface != event.surface);
        if event.kind == ReceiptEventKind::OutcomeRecorded {
            if receipt.completed_at_ms.is_some() {
                return Err("operation receipt already has a terminal outcome".into());
            }
            receipt.completed_at_ms = Some(event.timestamp_ms);
        }
        let produced_at_ms = event.timestamp_ms;
        receipt.events.push(event);
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        let durable_at_ms = chrono::Utc::now().timestamp_millis();
        tx.execute(
            "UPDATE chisei_operation_receipts SET receipt_json=?1, updated_at=?2 WHERE operation_id=?3",
            params![updated_json, durable_at_ms, operation_id],
        )
        .map_err(|error| error.to_string())?;
        self.append_operation_receipt_chain(&tx, &receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        crate::db::chisei_receipt::record_receipt_durability_lag(produced_at_ms, durable_at_ms);
        Ok((receipt, true))
    }

    pub fn authorize_operation_reporter(
        &self,
        operation_id: &str,
        principal: &str,
        event_kinds: Vec<ReceiptEventKind>,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let receipt_json = tx
            .query_row(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id=?1",
                params![operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        let mut normalized = event_kinds;
        normalized.sort_by_key(|kind| kind.as_str());
        normalized.dedup();
        if let Some(grant) = receipt
            .reporter_grants
            .iter_mut()
            .find(|grant| grant.principal == principal)
        {
            let mut existing = grant.event_kinds.clone();
            existing.sort_by_key(|kind| kind.as_str());
            existing.dedup();
            if existing == normalized {
                tx.commit().map_err(|error| error.to_string())?;
                return Ok(false);
            }
            grant.event_kinds = normalized;
        } else {
            receipt.reporter_grants.push(OperationReporterGrant {
                principal: principal.to_string(),
                event_kinds: normalized,
            });
        }
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE chisei_operation_receipts SET receipt_json=?1, updated_at=?2 WHERE operation_id=?3",
            params![updated_json, chrono::Utc::now().timestamp_millis(), operation_id],
        )
        .map_err(|error| error.to_string())?;
        self.append_operation_receipt_chain(&tx, &receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

pub fn upsert_operation_receipt(
    conn: &Connection,
    receipt: &OperationReceipt,
) -> Result<(), String> {
    let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
    let request_id = receipt_intent_attr(receipt, "request_id");
    let lookup_request_id = receipt_intent_attr(receipt, "lookup_request_id");
    let caller_scope = receipt_intent_attr(receipt, "caller_scope");
    conn.execute(
            "INSERT INTO chisei_operation_receipts(operation_id, request_id, lookup_request_id, initiating_actor, caller_scope, namespace, receipt_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(operation_id) DO UPDATE SET
                request_id=excluded.request_id,
                lookup_request_id=CASE
                  WHEN chisei_operation_receipts.alias_retired=1 THEN NULL
                  ELSE excluded.lookup_request_id
                END,
                initiating_actor=excluded.initiating_actor,
                caller_scope=COALESCE(excluded.caller_scope, chisei_operation_receipts.caller_scope),
                namespace=excluded.namespace,
                receipt_json=excluded.receipt_json,
                updated_at=excluded.updated_at",
            params![
                receipt.operation_id,
                request_id,
                lookup_request_id,
                receipt.initiating_actor,
                caller_scope,
                receipt.namespace,
                receipt_json,
                chrono::Utc::now().timestamp_millis()
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn receipt_intent_attr<'a>(receipt: &'a OperationReceipt, name: &str) -> Option<&'a String> {
    receipt.events.iter().find_map(|event| {
        (event.kind == ReceiptEventKind::IntentRecorded)
            .then(|| event.attributes.get(name))
            .flatten()
            .filter(|value| !value.is_empty())
    })
}
