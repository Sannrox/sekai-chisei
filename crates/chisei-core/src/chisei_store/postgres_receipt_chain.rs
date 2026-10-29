//! PostgreSQL receipt-chain export and in-tx append on Chisei persist.
//!
//! The signed-chain SQL stays a dest-pair leftover in
//! `sekai_core::db::postgres_receipt_chain` because shared operation receipts
//! and governed transforms append in the same transaction (ADR 0096). Family
//! DDL lives in this crate's persist migrations.

use postgres::GenericClient;
use sekai_core::db::postgres::PostgresDb;
use sekai_domain::receipt::OperationReceipt;
use sekai_types::receipt_chain::ReceiptChainBundle;

pub trait ReceiptChainPostgresDbExt {
    fn export_receipt_chain(&self, namespace: &str) -> Result<ReceiptChainBundle, String>;

    fn append_operation_receipt_chain<C: GenericClient>(
        &self,
        client: &mut C,
        receipt: &OperationReceipt,
    ) -> Result<(), String>;
}

impl ReceiptChainPostgresDbExt for PostgresDb {
    fn export_receipt_chain(&self, namespace: &str) -> Result<ReceiptChainBundle, String> {
        sekai_core::db::postgres_receipt_chain::export_receipt_chain(self, namespace)
    }

    fn append_operation_receipt_chain<C: GenericClient>(
        &self,
        client: &mut C,
        receipt: &OperationReceipt,
    ) -> Result<(), String> {
        sekai_core::db::postgres_receipt_chain::append_operation_receipt_chain(client, receipt)
    }
}
