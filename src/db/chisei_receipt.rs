//! Backend-neutral operation receipt and gateway alias persistence.

use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use crate::db::{postgres::PostgresDb, sekai::SekaiDb};

pub(crate) fn validate_evaluation_receipt_event_order(
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
    use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, ReceiptEventKind, ReceiptSurface};
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
}
