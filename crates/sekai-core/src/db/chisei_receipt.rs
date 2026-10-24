//! Backend-neutral operation receipt and gateway alias persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_domain::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};

/// How long an open (`completed_at_ms = None`) receipt continues to overlap
/// windowed lists. Matches max action-work claim TTL so in-flight harvest
/// stays visible in current windows while abandoned Workshop generate
/// receipts cannot accumulate across every later stats/export/console list.
///
/// GET and `AckActionWork` still see the open receipt until a real ack.
/// This bound is list-only; it does not invent a harvest timeout outcome.
pub const OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS: i64 = 24 * 60 * 60 * 1_000;

pub fn open_receipt_min_started_at_ms(window_start_ms: i64) -> i64 {
    window_start_ms.saturating_sub(OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS)
}

/// Overlap for `[window_start_ms, window_end_ms)` used by both receipt stores.
/// Completed receipts overlap when they close on or after the start.
/// Open receipts overlap only while `started_at_ms` is still within the TTL
/// lookback of the window start.
pub fn operation_receipt_overlaps_window(
    started_at_ms: i64,
    completed_at_ms: Option<i64>,
    window_start_ms: i64,
    window_end_ms: i64,
) -> bool {
    if started_at_ms >= window_end_ms {
        return false;
    }
    match completed_at_ms {
        Some(completed_at_ms) => completed_at_ms >= window_start_ms,
        None => started_at_ms >= open_receipt_min_started_at_ms(window_start_ms),
    }
}

pub fn validate_evaluation_receipt_event_order(
    receipt: &OperationReceipt,
    event: &OperationReceiptEvent,
) -> Result<(), String> {
    if receipt.operation_class != "evaluation_manifest_execution" {
        return Ok(());
    }
    let is_cancellation = event
        .attributes
        .get("evaluation_cancel_requested")
        .is_some_and(|value| value == "true");
    if is_cancellation && receipt.completed_at_ms.is_some() {
        return Err("evaluation execution already has a terminal outcome".into());
    }
    let cancellation_preempts = receipt.events.iter().any(|existing| {
        existing
            .attributes
            .get("evaluation_cancel_requested")
            .is_some_and(|value| value == "true")
    });
    if event.attributes.contains_key("evaluation_step_receipt")
        && cancellation_preempts
        && event.attributes.get("reason_code").map(String::as_str) != Some("execution_cancelled")
    {
        return Err("evaluation execution cancellation preempts step result".into());
    }
    if event.attributes.contains_key("evaluation_gate_decision")
        && cancellation_preempts
        && event.attributes.get("reason_code").map(String::as_str) != Some("execution_cancelled")
    {
        return Err("evaluation execution cancellation preempts terminal outcome".into());
    }
    Ok(())
}

pub fn outcome_evidence(
    event: &OperationReceiptEvent,
) -> Result<Option<(&str, f64, bool)>, String> {
    if !matches!(
        event.kind,
        ReceiptEventKind::OutcomeRecorded | ReceiptEventKind::MemoryOutcomeRecorded
    ) {
        return Ok(None);
    }
    let Some(metric) = event.attributes.get("outcome_metric") else {
        return Ok(None);
    };
    let Some(value) = event.attributes.get("outcome_value") else {
        return Ok(None);
    };
    let Some(passed) = event.attributes.get("passed") else {
        return Ok(None);
    };
    let metric = metric.trim();
    let value = value
        .parse::<f64>()
        .map_err(|_| "outcome evidence value must be finite".to_string())?;
    if metric.is_empty() || !value.is_finite() {
        return Err("outcome evidence metric and finite value are required".into());
    }
    let passed = passed
        .parse::<bool>()
        .map_err(|_| "outcome evidence passed flag must be boolean".to_string())?;
    Ok(Some((metric, value, passed)))
}

/// Time between a record being produced and becoming durable.
///
/// Both timestamps are wall-clock milliseconds sampled at different points, so
/// a clock adjustment can make the difference negative. A negative lag is not
/// meaningful: `None` drops it rather than clamping to zero, because clamping
/// would report a real clock problem as a run of implausibly fast writes.
///
/// Kept pure so it can be tested without the process-global metrics recorder.
fn durability_lag(produced_at_ms: i64, durable_at_ms: i64) -> Option<std::time::Duration> {
    let lag_ms = durable_at_ms.checked_sub(produced_at_ms)?;
    if lag_ms < 0 {
        return None;
    }
    Some(std::time::Duration::from_millis(lag_ms as u64))
}

pub fn record_receipt_durability_lag(produced_at_ms: i64, durable_at_ms: i64) {
    if let Some(lag) = durability_lag(produced_at_ms, durable_at_ms) {
        crate::obs::signals::record_durability_lag(crate::obs::labels::LagSurface::Receipt, lag);
    }
}

pub trait ChiseiReceiptBackend: Send + Sync {
    fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String>;
    fn get_operation_receipt(&self, operation_id: &str)
    -> Result<Option<OperationReceipt>, String>;
    fn reserve_gateway_request_alias(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
    ) -> Result<bool, String>;
    fn claim_gateway_request_alias_dispatch(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
        dispatch_token: &str,
    ) -> Result<bool, String>;
    fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String>;
    fn find_operation_receipt_by_lookup_request_id(
        &self,
        request_id: &str,
        caller_scope: Option<&str>,
        initiating_actor: Option<&str>,
    ) -> Result<Option<OperationReceipt>, String>;
    fn find_gateway_receipt_by_logical_operation_id(
        &self,
        operation_id: &str,
        attempt: Option<u32>,
    ) -> Result<Option<OperationReceipt>, String>;
    fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String>;
    fn authorize_operation_reporter(
        &self,
        operation_id: &str,
        principal: &str,
        event_kinds: Vec<ReceiptEventKind>,
    ) -> Result<bool, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
            <$target>::put_operation_receipt(self, receipt)
        }
        fn get_operation_receipt(
            &self,
            operation_id: &str,
        ) -> Result<Option<OperationReceipt>, String> {
            <$target>::get_operation_receipt(self, operation_id)
        }
        fn reserve_gateway_request_alias(
            &self,
            caller_scope: &str,
            request_alias: &str,
            request_id: &str,
            operation_id: &str,
        ) -> Result<bool, String> {
            <$target>::reserve_gateway_request_alias(
                self,
                caller_scope,
                request_alias,
                request_id,
                operation_id,
            )
        }
        fn claim_gateway_request_alias_dispatch(
            &self,
            caller_scope: &str,
            request_alias: &str,
            request_id: &str,
            operation_id: &str,
            dispatch_token: &str,
        ) -> Result<bool, String> {
            <$target>::claim_gateway_request_alias_dispatch(
                self,
                caller_scope,
                request_alias,
                request_id,
                operation_id,
                dispatch_token,
            )
        }
        fn find_operation_receipt_by_request_id(
            &self,
            request_id: &str,
        ) -> Result<Option<OperationReceipt>, String> {
            <$target>::find_operation_receipt_by_request_id(self, request_id)
        }
        fn find_operation_receipt_by_lookup_request_id(
            &self,
            request_id: &str,
            caller_scope: Option<&str>,
            initiating_actor: Option<&str>,
        ) -> Result<Option<OperationReceipt>, String> {
            <$target>::find_operation_receipt_by_lookup_request_id(
                self,
                request_id,
                caller_scope,
                initiating_actor,
            )
        }
        fn find_gateway_receipt_by_logical_operation_id(
            &self,
            operation_id: &str,
            attempt: Option<u32>,
        ) -> Result<Option<OperationReceipt>, String> {
            <$target>::find_gateway_receipt_by_logical_operation_id(self, operation_id, attempt)
        }
        fn append_operation_receipt_event(
            &self,
            operation_id: &str,
            event: OperationReceiptEvent,
        ) -> Result<(OperationReceipt, bool), String> {
            <$target>::append_operation_receipt_event(self, operation_id, event)
        }
        fn authorize_operation_reporter(
            &self,
            operation_id: &str,
            principal: &str,
            event_kinds: Vec<ReceiptEventKind>,
        ) -> Result<bool, String> {
            <$target>::authorize_operation_reporter(self, operation_id, principal, event_kinds)
        }
    };
}

impl ChiseiReceiptBackend for SekaiDb {
    forward!(SekaiDb);
}
impl ChiseiReceiptBackend for PostgresDb {
    forward!(PostgresDb);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_domain::receipt::{OPERATION_RECEIPT_VERSION, ReceiptEventKind, ReceiptSurface};
    use std::collections::BTreeMap;

    fn receipt() -> OperationReceipt {
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "evaluation-execution:test".into(),
            parent_operation_id: None,
            namespace: "test".into(),
            operation_class: "evaluation_manifest_execution".into(),
            initiating_actor: "starter".into(),
            schema_version: "executor/v1".into(),
            policy_version: "reducer/v1".into(),
            started_at_ms: 1,
            completed_at_ms: None,
            events: vec![],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
            ontology_digest: None,
            artifact: None,
        }
    }

    fn event(attributes: BTreeMap<String, String>) -> OperationReceiptEvent {
        OperationReceiptEvent {
            event_id: "event".into(),
            operation_id: "evaluation-execution:test".into(),
            parent_event_id: Some("parent".into()),
            timestamp_ms: 2,
            kind: ReceiptEventKind::OutcomeRecorded,
            surface: ReceiptSurface::Outcome,
            actor: "executor".into(),
            references: vec![],
            attributes,
        }
    }

    #[test]
    fn serialized_receipt_order_makes_cancellation_and_terminal_outcome_exclusive() {
        let cancellation = event(BTreeMap::from([(
            "evaluation_cancel_requested".into(),
            "true".into(),
        )]));
        let mut cancelled_receipt = receipt();
        cancelled_receipt.events.push(cancellation);
        let allow_gate = event(BTreeMap::from([
            ("evaluation_gate_decision".into(), "{}".into()),
            ("reason_code".into(), "all_required_nodes_passed".into()),
        ]));
        assert!(validate_evaluation_receipt_event_order(&cancelled_receipt, &allow_gate).is_err());
        let stale_step = event(BTreeMap::from([
            ("evaluation_step_receipt".into(), "{}".into()),
            ("reason_code".into(), "fixture_pass".into()),
        ]));
        assert!(validate_evaluation_receipt_event_order(&cancelled_receipt, &stale_step).is_err());
        let cancelled_step = event(BTreeMap::from([
            ("evaluation_step_receipt".into(), "{}".into()),
            ("reason_code".into(), "execution_cancelled".into()),
        ]));
        assert!(
            validate_evaluation_receipt_event_order(&cancelled_receipt, &cancelled_step).is_ok()
        );
        let cancelled_gate = event(BTreeMap::from([
            ("evaluation_gate_decision".into(), "{}".into()),
            ("reason_code".into(), "execution_cancelled".into()),
        ]));
        assert!(
            validate_evaluation_receipt_event_order(&cancelled_receipt, &cancelled_gate).is_ok()
        );

        let mut completed_receipt = receipt();
        completed_receipt.completed_at_ms = Some(2);
        let late_cancellation = event(BTreeMap::from([(
            "evaluation_cancel_requested".into(),
            "true".into(),
        )]));
        assert!(
            validate_evaluation_receipt_event_order(&completed_receipt, &late_cancellation)
                .is_err()
        );
        completed_receipt.operation_class = "unrelated_operation".into();
        assert!(
            validate_evaluation_receipt_event_order(&completed_receipt, &late_cancellation).is_ok()
        );
    }

    #[test]
    fn open_receipts_overlap_recent_windows_and_age_out_of_later_ones() {
        let started = 1_000;
        assert!(operation_receipt_overlaps_window(
            started,
            None,
            started,
            started + 10
        ));
        assert!(operation_receipt_overlaps_window(
            started,
            None,
            started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS,
            started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS + 10
        ));
        assert!(!operation_receipt_overlaps_window(
            started,
            None,
            started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS + 1,
            started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS + 11
        ));
        assert!(!operation_receipt_overlaps_window(
            started,
            Some(started + 5),
            started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS + 1,
            started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS + 11
        ));
        assert!(operation_receipt_overlaps_window(
            started,
            Some(started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS + 2),
            started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS + 1,
            started + OPEN_OPERATION_RECEIPT_WINDOW_TTL_MS + 11
        ));
    }

    #[test]
    fn negative_lag_from_clock_skew_is_dropped_not_clamped() {
        // Produced at t=1000, "durable" at t=900 means the clock moved, not
        // that the write was instant. Reporting zero would hide a real clock
        // problem behind a run of implausibly fast writes.
        assert_eq!(durability_lag(1000, 900), None);
    }

    #[test]
    fn ordinary_lag_is_measured_in_milliseconds() {
        assert_eq!(
            durability_lag(1000, 1250),
            Some(std::time::Duration::from_millis(250))
        );
    }

    #[test]
    fn zero_lag_is_recorded_not_dropped() {
        assert_eq!(durability_lag(1000, 1000), Some(std::time::Duration::ZERO));
    }

    #[test]
    fn overflowing_timestamps_do_not_panic() {
        assert_eq!(durability_lag(i64::MIN, i64::MAX), None);
    }
}
