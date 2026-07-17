//! Bounded, read-only aggregation over canonical operation and Kioku facts.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use crate::db::sekai::SekaiDb;

const RECEIPT_PAGE_SIZE: i64 = 128;
pub const MAX_STATISTICS_WINDOW_MS: i64 = 366 * 24 * 60 * 60 * 1000;
const MAX_STATISTICS_RECEIPTS: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatisticsTotals {
    pub logical_operations: i64,
    pub receipts: i64,
    pub model_calls: i64,
    pub priced_model_calls: i64,
    pub unpriced_model_calls: i64,
    pub model_calls_without_model: i64,
    pub total_cost_usd_micros: i64,
    pub waiting_operations: i64,
    pub waiting_time_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutcomeCounts {
    pub verified: i64,
    pub failed: i64,
    pub parked: i64,
    pub rejected: i64,
    pub unverified: i64,
    pub unknown: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LearningCounts {
    pub learnings_admitted: i64,
    pub enrichments_served: i64,
    pub escalations_answered: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationStatistics {
    pub totals: StatisticsTotals,
    pub daily_spend: BTreeMap<String, i64>,
    pub namespace_model_spend: BTreeMap<(String, String), i64>,
    pub outcomes: OutcomeCounts,
    pub learning: LearningCounts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomeClass {
    Verified,
    Failed,
    Parked,
    Rejected,
    Unverified,
    Unknown,
}

pub fn query_operation_statistics(
    db: &SekaiDb,
    namespaces: &[String],
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
) -> Result<OperationStatistics, String> {
    if end_timestamp_ms.saturating_sub(start_timestamp_ms) > MAX_STATISTICS_WINDOW_MS {
        return Err("statistics window exceeds one year".into());
    }
    let receipts = list_receipts_in_window(db, namespaces, start_timestamp_ms, end_timestamp_ms)?;
    let waiting_window_end_ms = end_timestamp_ms.min(chrono::Utc::now().timestamp_millis());
    let mut statistics = OperationStatistics::default();
    statistics.totals.receipts = receipts.len() as i64;
    let mut logical_outcomes: HashMap<(String, String), (i64, String, OutcomeClass)> =
        HashMap::new();
    let mut logical_waiting: HashMap<(String, String), (i64, String, bool, i64)> = HashMap::new();
    let mut logical_operations = HashSet::new();

    for receipt in &receipts {
        let logical_id = logical_operation_id(receipt);
        let logical_key = (receipt.namespace.clone(), logical_id);
        logical_operations.insert(logical_key.clone());
        let route_model = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::RouteSelected)
            .and_then(event_model);
        for event in &receipt.events {
            let event_in_window =
                event.timestamp_ms >= start_timestamp_ms && event.timestamp_ms < end_timestamp_ms;
            if event.kind == ReceiptEventKind::ModelCalled {
                if !event_in_window {
                    continue;
                }
                statistics.totals.model_calls += 1;
                let model = event_model(event).or_else(|| route_model.clone());
                if model.is_none() {
                    statistics.totals.model_calls_without_model += 1;
                }
                match event
                    .attributes
                    .get("cost_usd_micros")
                    .and_then(|value| value.parse::<i64>().ok())
                    .filter(|value| *value >= 0)
                {
                    Some(cost) => {
                        statistics.totals.priced_model_calls += 1;
                        statistics.totals.total_cost_usd_micros =
                            statistics.totals.total_cost_usd_micros.saturating_add(cost);
                        if let Some(day) = utc_day(event.timestamp_ms) {
                            let total = statistics.daily_spend.entry(day).or_default();
                            *total = total.saturating_add(cost);
                        }
                        if let Some(model) = model {
                            let total = statistics
                                .namespace_model_spend
                                .entry((receipt.namespace.clone(), model))
                                .or_default();
                            *total = total.saturating_add(cost);
                        }
                    }
                    None => statistics.totals.unpriced_model_calls += 1,
                }
            }
            if event_in_window && event.kind == ReceiptEventKind::ContextGoverned {
                statistics.learning.enrichments_served += event
                    .references
                    .iter()
                    .filter(|reference| reference.kind == "kioku_memory" && !reference.omitted)
                    .count() as i64;
            }
            if event_in_window && is_answered_escalation(event) {
                statistics.learning.escalations_answered += 1;
            }
        }
        let (waiting, waiting_ms) =
            receipt_waiting_time(receipt, start_timestamp_ms, waiting_window_end_ms);
        let outcome_timestamp = receipt.completed_at_ms.unwrap_or(receipt.started_at_ms);
        let candidate = (
            outcome_timestamp,
            receipt.operation_id.clone(),
            classify_receipt(receipt, end_timestamp_ms),
        );
        let replace = logical_outcomes
            .get(&logical_key)
            .is_none_or(|current| (candidate.0, &candidate.1) > (current.0, &current.1));
        if replace {
            logical_outcomes.insert(logical_key.clone(), candidate);
        }
        let waiting_candidate = (
            outcome_timestamp,
            receipt.operation_id.clone(),
            waiting,
            waiting_ms,
        );
        let replace_waiting = logical_waiting.get(&logical_key).is_none_or(|current| {
            (waiting_candidate.0, &waiting_candidate.1) > (current.0, &current.1)
        });
        if replace_waiting {
            logical_waiting.insert(logical_key, waiting_candidate);
        }
    }
    statistics.totals.logical_operations = logical_operations.len() as i64;
    for (_, _, outcome) in logical_outcomes.into_values() {
        match outcome {
            OutcomeClass::Verified => statistics.outcomes.verified += 1,
            OutcomeClass::Failed => statistics.outcomes.failed += 1,
            OutcomeClass::Parked => statistics.outcomes.parked += 1,
            OutcomeClass::Rejected => statistics.outcomes.rejected += 1,
            OutcomeClass::Unverified => statistics.outcomes.unverified += 1,
            OutcomeClass::Unknown => statistics.outcomes.unknown += 1,
        }
    }
    for (_, _, waiting, waiting_ms) in logical_waiting.into_values() {
        if waiting {
            statistics.totals.waiting_operations += 1;
            statistics.totals.waiting_time_ms =
                statistics.totals.waiting_time_ms.saturating_add(waiting_ms);
        }
    }
    statistics.learning.learnings_admitted =
        active_admissions_in_window(db, namespaces, start_timestamp_ms, end_timestamp_ms)?;
    Ok(statistics)
}

fn list_receipts_in_window(
    db: &SekaiDb,
    namespaces: &[String],
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
) -> Result<Vec<OperationReceipt>, String> {
    let conn = db.conn();
    let namespace_placeholders = (0..namespaces.len())
        .map(|index| format!("?{}", index + 1))
        .collect::<Vec<_>>()
        .join(",");
    let start_index = namespaces.len() + 1;
    let end_index = namespaces.len() + 2;
    let limit_index = namespaces.len() + 3;
    let offset_index = namespaces.len() + 4;
    let sql = format!(
        "SELECT receipt_json FROM chisei_operation_receipts
         WHERE namespace IN ({namespace_placeholders})
           AND CAST(json_extract(receipt_json, '$.started_at_ms') AS INTEGER) < ?{end_index}
           AND (json_extract(receipt_json, '$.completed_at_ms') IS NULL
                OR CAST(json_extract(receipt_json, '$.completed_at_ms') AS INTEGER) >= ?{start_index})
         ORDER BY CAST(json_extract(receipt_json, '$.started_at_ms') AS INTEGER), operation_id
         LIMIT ?{limit_index} OFFSET ?{offset_index}"
    );
    let mut offset = 0_i64;
    let mut receipts = Vec::new();
    loop {
        let mut values = namespaces
            .iter()
            .cloned()
            .map(rusqlite::types::Value::Text)
            .collect::<Vec<_>>();
        values.extend([
            rusqlite::types::Value::Integer(start_timestamp_ms),
            rusqlite::types::Value::Integer(end_timestamp_ms),
            rusqlite::types::Value::Integer(RECEIPT_PAGE_SIZE),
            rusqlite::types::Value::Integer(offset),
        ]);
        let mut statement = conn.prepare(&sql).map_err(|error| error.to_string())?;
        let page = statement
            .query_map(rusqlite::params_from_iter(values), |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        let page_len = page.len() as i64;
        if receipts.len().saturating_add(page.len()) > MAX_STATISTICS_RECEIPTS {
            return Err(format!(
                "statistics receipt limit exceeded ({MAX_STATISTICS_RECEIPTS})"
            ));
        }
        for json in page {
            receipts.push(serde_json::from_str(&json).map_err(|error| error.to_string())?);
        }
        if page_len < RECEIPT_PAGE_SIZE {
            break;
        }
        offset = offset.saturating_add(page_len);
    }
    Ok(receipts)
}

fn active_admissions_in_window(
    db: &SekaiDb,
    namespaces: &[String],
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
) -> Result<i64, String> {
    let conn = db.conn();
    let placeholders = (0..namespaces.len())
        .map(|index| format!("?{}", index + 1))
        .collect::<Vec<_>>()
        .join(",");
    let start_index = namespaces.len() + 1;
    let end_index = namespaces.len() + 2;
    let sql = format!(
        "SELECT COUNT(*)
         FROM chisei_kioku_lifecycle_events AS lifecycle
         JOIN chisei_kioku_memories AS memory
           ON memory.id=lifecycle.memory_id AND memory.version=lifecycle.memory_version
         WHERE memory.namespace IN ({placeholders})
           -- Kioku lifecycle is authoritative at query time: admissions that
           -- are now rejected or superseded are intentionally excluded.
           AND memory.state='active'
           AND lifecycle.action='promoted'
           AND lifecycle.recorded_at_ms >= ?{start_index}
           AND lifecycle.recorded_at_ms < ?{end_index}"
    );
    let mut values = namespaces
        .iter()
        .cloned()
        .map(rusqlite::types::Value::Text)
        .collect::<Vec<_>>();
    values.extend([
        rusqlite::types::Value::Integer(start_timestamp_ms),
        rusqlite::types::Value::Integer(end_timestamp_ms),
    ]);
    conn.query_row(&sql, rusqlite::params_from_iter(values), |row| row.get(0))
        .map_err(|error| error.to_string())
}

fn logical_operation_id(receipt: &OperationReceipt) -> String {
    receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
        .and_then(|event| event.attributes.get("logical_operation_id"))
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&receipt.operation_id)
        .to_string()
}

fn event_model(event: &OperationReceiptEvent) -> Option<String> {
    ["model", "resolved_model"]
        .into_iter()
        .find_map(|key| event.attributes.get(key))
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn utc_day(timestamp_ms: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(timestamp_ms)
        .map(|timestamp| timestamp.format("%Y-%m-%d").to_string())
}

fn normalized_status(event: &OperationReceiptEvent) -> &str {
    event
        .attributes
        .get("status")
        .or_else(|| event.attributes.get("verdict"))
        .map(String::as_str)
        .unwrap_or_default()
}

fn classify_receipt(receipt: &OperationReceipt, window_end_ms: i64) -> OutcomeClass {
    let verification_passed = receipt.events.iter().any(|event| {
        event.timestamp_ms < window_end_ms
            && event.kind == ReceiptEventKind::VerificationRecorded
            && (matches!(
                normalized_status(event),
                "pass" | "passed" | "verified" | "succeeded"
            ) || event.attributes.get("passed").map(String::as_str) == Some("true"))
    });
    let rejected = receipt.events.iter().any(|event| {
        event.timestamp_ms < window_end_ms
            && matches!(
                event.kind,
                ReceiptEventKind::PolicyDecided
                    | ReceiptEventKind::BudgetDecided
                    | ReceiptEventKind::ApprovalDecided
                    | ReceiptEventKind::EgressDecided
            )
            && matches!(normalized_status(event), "denied" | "rejected")
    });
    let outcome = receipt
        .events
        .iter()
        .filter(|event| {
            event.kind == ReceiptEventKind::OutcomeRecorded && event.timestamp_ms < window_end_ms
        })
        .max_by_key(|event| (event.timestamp_ms, event.event_id.as_str()));
    let outcome_status = outcome.map(normalized_status).unwrap_or_default();
    let pending = receipt.events.iter().any(|event| {
        event.timestamp_ms < window_end_ms
            && matches!(
                event.kind,
                ReceiptEventKind::ApprovalDecided | ReceiptEventKind::HumanIntervened
            )
            && matches!(normalized_status(event), "pending" | "parked" | "waiting")
    });
    if rejected {
        OutcomeClass::Rejected
    } else if matches!(outcome_status, "parked" | "waiting") || (outcome.is_none() && pending) {
        OutcomeClass::Parked
    } else if matches!(
        outcome_status,
        "failed" | "cancelled" | "interrupted" | "incomplete" | "error" | "denied"
    ) {
        OutcomeClass::Failed
    } else if verification_passed
        && matches!(
            outcome_status,
            "completed" | "succeeded" | "success" | "passed"
        )
    {
        OutcomeClass::Verified
    } else if outcome.is_some() {
        OutcomeClass::Unverified
    } else {
        OutcomeClass::Unknown
    }
}

fn receipt_waiting_time(
    receipt: &OperationReceipt,
    window_start_ms: i64,
    window_end_ms: i64,
) -> (bool, i64) {
    let mut decisions = receipt
        .events
        .iter()
        .filter(|event| {
            event.timestamp_ms < window_end_ms
                && matches!(
                    event.kind,
                    ReceiptEventKind::ApprovalDecided | ReceiptEventKind::HumanIntervened
                )
        })
        .collect::<Vec<_>>();
    decisions.sort_by_key(|event| (event.timestamp_ms, event.event_id.as_str()));
    let mut pending_at = None;
    let mut waiting_time_ms = 0_i64;
    for event in decisions {
        let status = normalized_status(event);
        if matches!(status, "pending" | "parked" | "waiting") {
            pending_at.get_or_insert(event.timestamp_ms);
        } else if matches!(
            status,
            "answered" | "approved" | "rejected" | "denied" | "resolved"
        ) && let Some(started_at) = pending_at.take()
        {
            let counted_start = started_at.max(window_start_ms);
            let counted_end = event.timestamp_ms.min(window_end_ms);
            if counted_end > counted_start {
                waiting_time_ms =
                    waiting_time_ms.saturating_add(counted_end.saturating_sub(counted_start));
            }
        }
    }
    if let Some(started_at) = pending_at {
        let counted_start = started_at.max(window_start_ms);
        if window_end_ms > counted_start {
            waiting_time_ms =
                waiting_time_ms.saturating_add(window_end_ms.saturating_sub(counted_start));
        }
    }
    (waiting_time_ms > 0, waiting_time_ms)
}

fn is_answered_escalation(event: &OperationReceiptEvent) -> bool {
    matches!(
        event.kind,
        ReceiptEventKind::ApprovalDecided | ReceiptEventKind::HumanIntervened
    ) && matches!(
        normalized_status(event),
        "answered" | "approved" | "rejected" | "denied" | "resolved"
    )
}
