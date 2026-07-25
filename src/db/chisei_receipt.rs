//! Backend-neutral operation receipt and gateway alias persistence.

use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use crate::db::{postgres::PostgresDb, sekai::SekaiDb};

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
