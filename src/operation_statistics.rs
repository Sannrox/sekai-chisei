//! Bounded, read-only aggregation over canonical operation and Kioku facts.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
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
pub struct OutcomeAttributedSpend {
    /// Priced model spend attributed to each logical-operation outcome class.
    pub by_outcome: BTreeMap<String, i64>,
    /// Priced model spend attributed to (capability, outcome) pairs.
    /// Capability is the receipt `operation_class` when present, else `"unknown"`.
    pub by_capability_outcome: BTreeMap<(String, String), i64>,
    /// Mean priced spend for verified logical operations (0 when none verified).
    pub cost_per_verified_usd_micros: i64,
    /// Mean priced spend for failed logical operations (0 when none failed).
    pub cost_per_failed_usd_micros: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationStatistics {
    pub totals: StatisticsTotals,
    pub daily_spend: BTreeMap<String, i64>,
    pub namespace_model_spend: BTreeMap<(String, String), i64>,
    pub outcomes: OutcomeCounts,
    pub learning: LearningCounts,
    pub outcome_spend: OutcomeAttributedSpend,
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

impl OutcomeClass {
    fn as_str(self) -> &'static str {
        match self {
            OutcomeClass::Verified => "verified",
            OutcomeClass::Failed => "failed",
            OutcomeClass::Parked => "parked",
            OutcomeClass::Rejected => "rejected",
            OutcomeClass::Unverified => "unverified",
            OutcomeClass::Unknown => "unknown",
        }
    }
}

pub fn query_operation_statistics(
    db: &RuntimeDb,
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
    // Sum priced model spend per logical operation (all attempts in-window), then
    // attribute that total to the winning outcome class for the logical op.
    // Capability spend is tracked per (logical, capability) so multi-attempt
    // receipts with different operation_class values are not collapsed to the
    // first receipt's capability.
    let mut logical_priced_spend: HashMap<(String, String), i64> = HashMap::new();
    let mut logical_capability_spend: HashMap<(String, String, String), i64> = HashMap::new();

    for receipt in &receipts {
        let logical_id = logical_operation_id(receipt);
        let logical_key = (receipt.namespace.clone(), logical_id);
        logical_operations.insert(logical_key.clone());
        let capability = receipt_capability(receipt);
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
                        let spend = logical_priced_spend.entry(logical_key.clone()).or_default();
                        *spend = spend.saturating_add(cost);
                        let cap_key = (
                            logical_key.0.clone(),
                            logical_key.1.clone(),
                            capability.clone(),
                        );
                        let cap_spend = logical_capability_spend.entry(cap_key).or_default();
                        *cap_spend = cap_spend.saturating_add(cost);
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
    let mut verified_spend = 0_i64;
    let mut failed_spend = 0_i64;
    let mut resolved_logical_keys = HashSet::new();
    for (logical_key, (_, _, outcome)) in &logical_outcomes {
        resolved_logical_keys.insert(logical_key.clone());
        match outcome {
            OutcomeClass::Verified => statistics.outcomes.verified += 1,
            OutcomeClass::Failed => statistics.outcomes.failed += 1,
            OutcomeClass::Parked => statistics.outcomes.parked += 1,
            OutcomeClass::Rejected => statistics.outcomes.rejected += 1,
            OutcomeClass::Unverified => statistics.outcomes.unverified += 1,
            OutcomeClass::Unknown => statistics.outcomes.unknown += 1,
        }
        let spend = logical_priced_spend.get(logical_key).copied().unwrap_or(0);
        let outcome_label = outcome.as_str();
        let bucket = statistics
            .outcome_spend
            .by_outcome
            .entry(outcome_label.into())
            .or_default();
        *bucket = bucket.saturating_add(spend);
        match outcome {
            OutcomeClass::Verified => verified_spend = verified_spend.saturating_add(spend),
            OutcomeClass::Failed => failed_spend = failed_spend.saturating_add(spend),
            _ => {}
        }
    }
    for ((namespace, logical_id, capability), spend) in logical_capability_spend {
        let logical_key = (namespace, logical_id);
        let outcome_label = logical_outcomes
            .get(&logical_key)
            .map(|(_, _, outcome)| outcome.as_str())
            .unwrap_or(OutcomeClass::Unknown.as_str());
        let cap_bucket = statistics
            .outcome_spend
            .by_capability_outcome
            .entry((capability, outcome_label.into()))
            .or_default();
        *cap_bucket = cap_bucket.saturating_add(spend);
    }
    // Logical ops with priced spend but no outcome classification still must not
    // vanish — attribute the total to the explicit `unknown` bucket once.
    for (logical_key, spend) in logical_priced_spend {
        if resolved_logical_keys.contains(&logical_key) {
            continue;
        }
        let bucket = statistics
            .outcome_spend
            .by_outcome
            .entry(OutcomeClass::Unknown.as_str().into())
            .or_default();
        *bucket = bucket.saturating_add(spend);
    }
    if statistics.outcomes.verified > 0 {
        statistics.outcome_spend.cost_per_verified_usd_micros =
            verified_spend / statistics.outcomes.verified;
    }
    if statistics.outcomes.failed > 0 {
        statistics.outcome_spend.cost_per_failed_usd_micros =
            failed_spend / statistics.outcomes.failed;
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

fn receipt_capability(receipt: &OperationReceipt) -> String {
    let class = receipt.operation_class.trim();
    if class.is_empty() {
        "unknown".into()
    } else {
        class.to_string()
    }
}

fn list_receipts_in_window(
    db: &RuntimeDb,
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
    db: &RuntimeDb,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        GovernedReference, OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent,
    };

    fn event(
        operation_id: &str,
        sequence: usize,
        timestamp_ms: i64,
        kind: ReceiptEventKind,
        attributes: &[(&str, &str)],
    ) -> OperationReceiptEvent {
        OperationReceiptEvent {
            event_id: format!("{operation_id}-{sequence}"),
            operation_id: operation_id.into(),
            parent_event_id: None,
            timestamp_ms,
            kind,
            surface: kind.surface(),
            actor: "test".into(),
            references: Vec::new(),
            attributes: attributes
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
        }
    }

    fn receipt(
        operation_id: &str,
        namespace: &str,
        started_at_ms: i64,
        completed_at_ms: Option<i64>,
        events: Vec<OperationReceiptEvent>,
    ) -> OperationReceipt {
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: operation_id.into(),
            parent_operation_id: None,
            namespace: namespace.into(),
            operation_class: "test".into(),
            initiating_actor: "test".into(),
            schema_version: "test/v1".into(),
            policy_version: "test/v1".into(),
            started_at_ms,
            completed_at_ms,
            events,
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
        }
    }

    #[test]
    fn reconciles_attempts_cost_outcomes_and_learning_without_content() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let first_id = "attempt-1";
        let mut first_context = event(first_id, 3, 130, ReceiptEventKind::ContextGoverned, &[]);
        first_context.references = vec![GovernedReference {
            kind: "kioku_memory".into(),
            reference: "secret-memory-body-must-not-leak".into(),
            content_hash: None,
            disclosed_fields: Vec::new(),
            omitted: false,
            omission_reason: None,
        }];
        db.put_operation_receipt(&receipt(
            first_id,
            "alpha",
            100,
            Some(150),
            vec![
                event(
                    first_id,
                    0,
                    100,
                    ReceiptEventKind::IntentRecorded,
                    &[("logical_operation_id", "logical-1")],
                ),
                event(
                    first_id,
                    1,
                    110,
                    ReceiptEventKind::RouteSelected,
                    &[("resolved_model", "model-a")],
                ),
                event(
                    first_id,
                    2,
                    120,
                    ReceiptEventKind::ModelCalled,
                    &[("cost_usd_micros", "100")],
                ),
                first_context,
                event(
                    first_id,
                    4,
                    150,
                    ReceiptEventKind::OutcomeRecorded,
                    &[("status", "failed")],
                ),
            ],
        ))
        .unwrap();

        let second_id = "attempt-2";
        db.put_operation_receipt(&receipt(
            second_id,
            "alpha",
            200,
            Some(260),
            vec![
                event(
                    second_id,
                    0,
                    200,
                    ReceiptEventKind::IntentRecorded,
                    &[("logical_operation_id", "logical-1")],
                ),
                event(
                    second_id,
                    1,
                    220,
                    ReceiptEventKind::ModelCalled,
                    &[("model", "model-a"), ("cost_usd_micros", "250")],
                ),
                event(
                    second_id,
                    2,
                    240,
                    ReceiptEventKind::HumanIntervened,
                    &[("status", "answered")],
                ),
                event(
                    second_id,
                    3,
                    250,
                    ReceiptEventKind::VerificationRecorded,
                    &[("verdict", "passed")],
                ),
                event(
                    second_id,
                    4,
                    260,
                    ReceiptEventKind::OutcomeRecorded,
                    &[("status", "completed")],
                ),
            ],
        ))
        .unwrap();

        let unpriced_id = "unpriced";
        db.put_operation_receipt(&receipt(
            unpriced_id,
            "beta",
            300,
            Some(340),
            vec![
                event(unpriced_id, 0, 300, ReceiptEventKind::IntentRecorded, &[]),
                event(unpriced_id, 1, 320, ReceiptEventKind::ModelCalled, &[]),
                event(
                    unpriced_id,
                    2,
                    330,
                    ReceiptEventKind::PolicyDecided,
                    &[("status", "denied")],
                ),
                event(
                    unpriced_id,
                    3,
                    340,
                    ReceiptEventKind::OutcomeRecorded,
                    &[("status", "failed")],
                ),
            ],
        ))
        .unwrap();

        let statistics =
            query_operation_statistics(&db, &["alpha".into(), "beta".into()], 0, 1_000).unwrap();
        assert_eq!(statistics.totals.logical_operations, 2);
        assert_eq!(statistics.totals.receipts, 3);
        assert_eq!(statistics.totals.model_calls, 3);
        assert_eq!(statistics.totals.priced_model_calls, 2);
        assert_eq!(statistics.totals.unpriced_model_calls, 1);
        assert_eq!(statistics.totals.model_calls_without_model, 1);
        assert_eq!(statistics.totals.total_cost_usd_micros, 350);
        assert_eq!(
            statistics
                .namespace_model_spend
                .get(&("alpha".into(), "model-a".into())),
            Some(&350)
        );
        assert_eq!(statistics.outcomes.verified, 1);
        assert_eq!(statistics.outcomes.rejected, 1);
        assert_eq!(statistics.outcomes.failed, 0);
        assert_eq!(statistics.learning.enrichments_served, 1);
        assert_eq!(statistics.learning.escalations_answered, 1);
        // logical-1 attempts cost 100+250=350 and the winning outcome is verified.
        assert_eq!(
            statistics.outcome_spend.by_outcome.get("verified"),
            Some(&350)
        );
        // Rejected beta call was unpriced, so no spend under rejected.
        assert_eq!(
            statistics
                .outcome_spend
                .by_outcome
                .get("rejected")
                .copied()
                .unwrap_or(0),
            0
        );
        assert_eq!(statistics.outcome_spend.cost_per_verified_usd_micros, 350);
        assert_eq!(statistics.outcome_spend.cost_per_failed_usd_micros, 0);
        assert_eq!(
            statistics
                .outcome_spend
                .by_capability_outcome
                .get(&("test".into(), "verified".into())),
            Some(&350)
        );
        assert!(!format!("{statistics:?}").contains("secret-memory-body"));
    }

    #[test]
    fn attributes_priced_spend_to_outcome_classes_and_capabilities() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let mut success = receipt(
            "success-1",
            "alpha",
            100,
            Some(150),
            vec![
                event(
                    "success-1",
                    0,
                    100,
                    ReceiptEventKind::IntentRecorded,
                    &[("logical_operation_id", "op-success")],
                ),
                event(
                    "success-1",
                    1,
                    120,
                    ReceiptEventKind::ModelCalled,
                    &[("model", "m1"), ("cost_usd_micros", "200")],
                ),
                event(
                    "success-1",
                    2,
                    140,
                    ReceiptEventKind::VerificationRecorded,
                    &[("verdict", "passed")],
                ),
                event(
                    "success-1",
                    3,
                    150,
                    ReceiptEventKind::OutcomeRecorded,
                    &[("status", "completed")],
                ),
            ],
        );
        success.operation_class = "capability.write".into();
        db.put_operation_receipt(&success).unwrap();

        let mut failed = receipt(
            "failed-1",
            "alpha",
            200,
            Some(240),
            vec![
                event(
                    "failed-1",
                    0,
                    200,
                    ReceiptEventKind::IntentRecorded,
                    &[("logical_operation_id", "op-failed")],
                ),
                event(
                    "failed-1",
                    1,
                    210,
                    ReceiptEventKind::ModelCalled,
                    &[("model", "m1"), ("cost_usd_micros", "50")],
                ),
                event(
                    "failed-1",
                    2,
                    220,
                    ReceiptEventKind::ModelCalled,
                    &[("model", "m1"), ("cost_usd_micros", "50")],
                ),
                event(
                    "failed-1",
                    3,
                    240,
                    ReceiptEventKind::OutcomeRecorded,
                    &[("status", "failed")],
                ),
            ],
        );
        failed.operation_class = "capability.write".into();
        db.put_operation_receipt(&failed).unwrap();

        // Incomplete receipt with cost but no outcome → explicit unknown bucket.
        let mut dangling = receipt(
            "dangling-1",
            "alpha",
            300,
            None,
            vec![event(
                "dangling-1",
                0,
                310,
                ReceiptEventKind::ModelCalled,
                &[("model", "m2"), ("cost_usd_micros", "75")],
            )],
        );
        dangling.operation_class = "capability.read".into();
        db.put_operation_receipt(&dangling).unwrap();

        let statistics = query_operation_statistics(&db, &["alpha".into()], 0, 1_000).unwrap();
        assert_eq!(statistics.outcomes.verified, 1);
        assert_eq!(statistics.outcomes.failed, 1);
        assert_eq!(statistics.outcomes.unknown, 1);
        assert_eq!(
            statistics.outcome_spend.by_outcome.get("verified"),
            Some(&200)
        );
        assert_eq!(
            statistics.outcome_spend.by_outcome.get("failed"),
            Some(&100)
        );
        assert_eq!(
            statistics.outcome_spend.by_outcome.get("unknown"),
            Some(&75)
        );
        assert_eq!(statistics.outcome_spend.cost_per_verified_usd_micros, 200);
        assert_eq!(statistics.outcome_spend.cost_per_failed_usd_micros, 100);
        assert_eq!(
            statistics
                .outcome_spend
                .by_capability_outcome
                .get(&("capability.write".into(), "verified".into())),
            Some(&200)
        );
        assert_eq!(
            statistics
                .outcome_spend
                .by_capability_outcome
                .get(&("capability.write".into(), "failed".into())),
            Some(&100)
        );
        assert_eq!(
            statistics
                .outcome_spend
                .by_capability_outcome
                .get(&("capability.read".into(), "unknown".into())),
            Some(&75)
        );
    }

    #[test]
    fn paginates_receipts_and_applies_inclusive_exclusive_event_bounds() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for index in 0..129 {
            let operation_id = format!("op-{index:03}");
            let timestamp = 1_000 + index;
            db.put_operation_receipt(&receipt(
                &operation_id,
                "alpha",
                timestamp,
                Some(timestamp),
                vec![event(
                    &operation_id,
                    0,
                    timestamp,
                    ReceiptEventKind::ModelCalled,
                    &[("model", "model-a"), ("cost_usd_micros", "1")],
                )],
            ))
            .unwrap();
        }
        db.put_operation_receipt(&receipt(
            "end-boundary",
            "alpha",
            1_999,
            Some(2_000),
            vec![event(
                "end-boundary",
                0,
                2_000,
                ReceiptEventKind::ModelCalled,
                &[("model", "model-a"), ("cost_usd_micros", "99")],
            )],
        ))
        .unwrap();

        let statistics = query_operation_statistics(&db, &["alpha".into()], 1_000, 2_000).unwrap();
        assert_eq!(statistics.totals.receipts, 130);
        assert_eq!(statistics.totals.model_calls, 129);
        assert_eq!(statistics.totals.total_cost_usd_micros, 129);
    }

    #[test]
    fn waiting_time_sums_repeated_cycles_and_excludes_resolved_pre_window_waits() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let operation_id = "waiting";
        db.put_operation_receipt(&receipt(
            operation_id,
            "alpha",
            50,
            Some(350),
            vec![
                event(
                    operation_id,
                    0,
                    60,
                    ReceiptEventKind::ApprovalDecided,
                    &[("status", "pending")],
                ),
                event(
                    operation_id,
                    1,
                    90,
                    ReceiptEventKind::ApprovalDecided,
                    &[("status", "approved")],
                ),
                event(
                    operation_id,
                    2,
                    150,
                    ReceiptEventKind::HumanIntervened,
                    &[("status", "pending")],
                ),
                event(
                    operation_id,
                    3,
                    200,
                    ReceiptEventKind::HumanIntervened,
                    &[("status", "answered")],
                ),
                event(
                    operation_id,
                    4,
                    250,
                    ReceiptEventKind::ApprovalDecided,
                    &[("status", "pending")],
                ),
                event(
                    operation_id,
                    5,
                    300,
                    ReceiptEventKind::ApprovalDecided,
                    &[("status", "rejected")],
                ),
            ],
        ))
        .unwrap();

        let statistics = query_operation_statistics(&db, &["alpha".into()], 100, 400).unwrap();
        assert_eq!(statistics.totals.waiting_operations, 1);
        assert_eq!(statistics.totals.waiting_time_ms, 100);
    }

    #[test]
    fn classifies_terminal_parked_unverified_and_unknown_operations() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for (operation_id, kind, status) in [
            (
                "dispatch-failure",
                ReceiptEventKind::OutcomeRecorded,
                "failed",
            ),
            ("cancelled", ReceiptEventKind::OutcomeRecorded, "cancelled"),
            ("parked", ReceiptEventKind::ApprovalDecided, "pending"),
            (
                "admitted-no-verdict",
                ReceiptEventKind::OutcomeRecorded,
                "completed",
            ),
        ] {
            db.put_operation_receipt(&receipt(
                operation_id,
                "alpha",
                100,
                Some(150),
                vec![event(operation_id, 0, 150, kind, &[("status", status)])],
            ))
            .unwrap();
        }
        db.put_operation_receipt(&receipt(
            "external-evidence-only",
            "alpha",
            100,
            None,
            vec![{
                let mut event = event(
                    "external-evidence-only",
                    0,
                    120,
                    ReceiptEventKind::ContextGoverned,
                    &[],
                );
                event.references.push(GovernedReference {
                    kind: "external_evidence".into(),
                    reference: "evidence:admitted".into(),
                    content_hash: None,
                    disclosed_fields: Vec::new(),
                    omitted: false,
                    omission_reason: None,
                });
                event
            }],
        ))
        .unwrap();

        let statistics = query_operation_statistics(&db, &["alpha".into()], 0, 1_000).unwrap();
        assert_eq!(statistics.outcomes.failed, 2);
        assert_eq!(statistics.outcomes.parked, 1);
        assert_eq!(statistics.outcomes.unverified, 1);
        assert_eq!(statistics.outcomes.unknown, 1);
        assert_eq!(statistics.outcomes.verified, 0);
    }

    #[test]
    fn learning_admissions_include_only_current_active_memories_in_window() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        for (id, state, promoted_at) in [
            ("active", "active", 100),
            ("rejected", "rejected", 110),
            ("superseded", "superseded", 120),
            ("before", "active", 99),
            ("end", "active", 200),
        ] {
            db.conn()
                .execute(
                    "INSERT INTO chisei_kioku_memories
                     (id, version, namespace, state, classification, expires_at_ms, memory_json)
                     VALUES (?1, 1, 'alpha', ?2, 'internal', NULL, '{}')",
                    rusqlite::params![id, state],
                )
                .unwrap();
            db.conn()
                .execute(
                    "INSERT INTO chisei_kioku_lifecycle_events
                     (memory_id, memory_version, action, from_state, to_state, actor, reason, recorded_at_ms)
                     VALUES (?1, 1, 'promoted', 'candidate', ?2, 'test', 'test', ?3)",
                    rusqlite::params![id, state, promoted_at],
                )
                .unwrap();
        }

        let statistics = query_operation_statistics(&db, &["alpha".into()], 100, 200).unwrap();
        assert_eq!(statistics.learning.learnings_admitted, 1);
    }
}
