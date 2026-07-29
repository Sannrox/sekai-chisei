//! Compatibility re-exports plus the root-only offline persistence adapter.

pub use sekai_admin_client::gateway_report::*;
use sekai_proto::sekai::Row;

use crate::db::runtime_db::RuntimeDb;

pub fn egress_rows(db: &RuntimeDb, after: i64, limit: i32) -> Result<Vec<Row>, String> {
    let rows = db.query_rows(
        "llm_calls",
        &crate::sekai::dataset::RowQuery {
            filters: vec![crate::sekai::dataset::RowFilter {
                column: "timestamp_ms".to_string(),
                op: "gte".to_string(),
                value: after.to_string(),
            }],
            columns: vec![],
            limit,
            offset: 0,
        },
    )?;
    Ok(rows.into_iter().map(|values| Row { values }).collect())
}
