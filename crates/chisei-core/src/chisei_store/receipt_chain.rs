//! SQLite receipt-chain export and in-tx append on Chisei persist.
//!
//! The signed-chain SQL stays a dest-pair leftover in `sekai_core::db::receipt_chain`
//! because shared operation receipts and governed transforms append in the same
//! transaction (ADR 0096). Family DDL lives in this crate's persist migrations.

use rusqlite::Connection;
use sekai_core::db::sekai::SekaiDb;
use sekai_domain::receipt::OperationReceipt;
use sekai_types::receipt_chain::ReceiptChainBundle;

pub trait ReceiptChainSekaiDbExt {
    fn export_receipt_chain(&self, namespace: &str) -> Result<ReceiptChainBundle, String>;

    fn append_operation_receipt_chain(
        &self,
        conn: &Connection,
        receipt: &OperationReceipt,
    ) -> Result<(), String>;
}

impl ReceiptChainSekaiDbExt for SekaiDb {
    fn export_receipt_chain(&self, namespace: &str) -> Result<ReceiptChainBundle, String> {
        sekai_core::db::receipt_chain::export_receipt_chain(self, namespace)
    }

    fn append_operation_receipt_chain(
        &self,
        conn: &Connection,
        receipt: &OperationReceipt,
    ) -> Result<(), String> {
        sekai_core::db::receipt_chain::append_operation_receipt_chain(conn, receipt)
    }
}
