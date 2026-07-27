//! Tenant usage event ledger (#122).
//!
//! Immutable, tenant-scoped usage events projected from governed operation
//! receipts. No pricing, invoicing, or billing-provider authority.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chisei::receipt::OperationReceipt;
use crate::db::sekai::SekaiDb;

pub const USAGE_EVENT_VERSION: &str = "chisei.usage-event/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageUnit {
    Tokens,
    Requests,
}

impl UsageUnit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tokens => "tokens",
            Self::Requests => "requests",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tokens" => Some(Self::Tokens),
            "requests" => Some(Self::Requests),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    /// Measured by Sekai Chisei from the receipt.
    Measured,
    /// Upstream provider reported quantity.
    ProviderReported,
    /// Estimate used for reservation/admission only.
    Estimated,
    /// Explicit append-only correction of a prior event.
    Correction,
}

impl UsageSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::ProviderReported => "provider_reported",
            Self::Estimated => "estimated",
            Self::Correction => "correction",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "measured" => Some(Self::Measured),
            "provider_reported" => Some(Self::ProviderReported),
            "estimated" => Some(Self::Estimated),
            "correction" => Some(Self::Correction),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEvent {
    pub version: String,
    pub event_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub unit: UsageUnit,
    /// Signed quantity; corrections may be negative.
    pub quantity: i64,
    pub source: UsageSource,
    pub receipt_operation_id: String,
    pub dedupe_key: String,
    pub event_time_ms: i64,
    pub corrects_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UsageAggregate {
    pub tenant_id: String,
    pub unit: String,
    pub measured: i64,
    pub provider_reported: i64,
    pub estimated: i64,
    pub corrections: i64,
    pub net: i64,
}

impl SekaiDb {
    pub(crate) fn migrate_usage_ledger(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_usage_events (
                    event_id TEXT PRIMARY KEY,
                    version TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    unit TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    receipt_operation_id TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL UNIQUE,
                    event_time_ms INTEGER NOT NULL,
                    corrects_event_id TEXT,
                    CHECK (unit IN ('tokens', 'requests')),
                    CHECK (source IN ('measured', 'provider_reported', 'estimated', 'correction'))
                );
                CREATE INDEX IF NOT EXISTS idx_usage_events_tenant_time
                    ON chisei_usage_events(tenant_id, event_time_ms, event_id);
                CREATE INDEX IF NOT EXISTS idx_usage_events_receipt
                    ON chisei_usage_events(receipt_operation_id);",
            )
            .map_err(|e| e.to_string())
    }

    /// Append a usage event. Identical `dedupe_key` is a no-op success (replay-safe).
    pub fn append_usage_event(&self, event: &UsageEvent) -> Result<bool, String> {
        validate_event(event)?;
        let conn = self.conn();
        let inserted = conn
            .execute(
                "INSERT OR IGNORE INTO chisei_usage_events
                 (event_id, version, tenant_id, namespace, unit, quantity, source,
                  receipt_operation_id, dedupe_key, event_time_ms, corrects_event_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    event.event_id,
                    event.version,
                    event.tenant_id,
                    event.namespace,
                    event.unit.as_str(),
                    event.quantity,
                    event.source.as_str(),
                    event.receipt_operation_id,
                    event.dedupe_key,
                    event.event_time_ms,
                    event.corrects_event_id,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(inserted == 1)
    }

    pub fn get_usage_event(&self, event_id: &str) -> Result<Option<UsageEvent>, String> {
        self.conn()
            .query_row(
                "SELECT event_id, version, tenant_id, namespace, unit, quantity, source,
                        receipt_operation_id, dedupe_key, event_time_ms, corrects_event_id
                 FROM chisei_usage_events WHERE event_id = ?1",
                params![event_id],
                row_to_event,
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    pub fn list_usage_events_for_tenant(
        &self,
        tenant_id: &str,
        start_ms: i64,
        end_ms: i64,
        limit: i64,
    ) -> Result<Vec<UsageEvent>, String> {
        if tenant_id.is_empty() {
            return Err("tenant_id required".into());
        }
        let limit = if limit <= 0 { 100 } else { limit.min(5_000) };
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT event_id, version, tenant_id, namespace, unit, quantity, source,
                        receipt_operation_id, dedupe_key, event_time_ms, corrects_event_id
                 FROM chisei_usage_events
                 WHERE tenant_id = ?1 AND event_time_ms >= ?2 AND event_time_ms < ?3
                 ORDER BY event_time_ms ASC, event_id ASC
                 LIMIT ?4",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![tenant_id, start_ms, end_ms, limit], row_to_event)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn aggregate_usage_for_tenant(
        &self,
        tenant_id: &str,
        unit: UsageUnit,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<UsageAggregate, String> {
        let events = self.list_usage_events_for_tenant(tenant_id, start_ms, end_ms, 5_000)?;
        let mut agg = UsageAggregate {
            tenant_id: tenant_id.into(),
            unit: unit.as_str().into(),
            ..Default::default()
        };
        for event in events.into_iter().filter(|e| e.unit == unit) {
            match event.source {
                UsageSource::Measured => agg.measured += event.quantity,
                UsageSource::ProviderReported => agg.provider_reported += event.quantity,
                UsageSource::Estimated => agg.estimated += event.quantity,
                UsageSource::Correction => agg.corrections += event.quantity,
            }
            agg.net += event.quantity;
        }
        Ok(agg)
    }

    /// Project measured usage from a completed receipt into the ledger.
    /// `tenant_id` must come from verified enterprise context, not the receipt alone.
    pub fn project_usage_from_receipt(
        &self,
        tenant_id: &str,
        receipt: &OperationReceipt,
    ) -> Result<Vec<UsageEvent>, String> {
        if tenant_id.trim().is_empty() {
            return Err("tenant_id required from authenticated context".into());
        }
        let tokens = measured_tokens_from_receipt(receipt);
        let event_time = receipt.completed_at_ms.unwrap_or(receipt.started_at_ms);
        let mut out = Vec::new();

        // One request unit per completed operation.
        let request_event = UsageEvent {
            version: USAGE_EVENT_VERSION.into(),
            event_id: stable_event_id(tenant_id, &receipt.operation_id, "requests", "measured"),
            tenant_id: tenant_id.into(),
            namespace: receipt.namespace.clone(),
            unit: UsageUnit::Requests,
            quantity: 1,
            source: UsageSource::Measured,
            receipt_operation_id: receipt.operation_id.clone(),
            dedupe_key: format!(
                "usage:v1:{tenant_id}:{}:requests:measured",
                receipt.operation_id
            ),
            event_time_ms: event_time,
            corrects_event_id: None,
        };
        self.append_usage_event(&request_event)?;
        out.push(request_event);

        if tokens != 0 {
            let token_event = UsageEvent {
                version: USAGE_EVENT_VERSION.into(),
                event_id: stable_event_id(tenant_id, &receipt.operation_id, "tokens", "measured"),
                tenant_id: tenant_id.into(),
                namespace: receipt.namespace.clone(),
                unit: UsageUnit::Tokens,
                quantity: tokens,
                source: UsageSource::Measured,
                receipt_operation_id: receipt.operation_id.clone(),
                dedupe_key: format!(
                    "usage:v1:{tenant_id}:{}:tokens:measured",
                    receipt.operation_id
                ),
                event_time_ms: event_time,
                corrects_event_id: None,
            };
            self.append_usage_event(&token_event)?;
            out.push(token_event);
        }
        Ok(out)
    }

    /// Append-only correction (never mutates prior rows).
    pub fn correct_usage_event(
        &self,
        prior_event_id: &str,
        delta: i64,
        actor_note: &str,
    ) -> Result<UsageEvent, String> {
        let prior = self
            .get_usage_event(prior_event_id)?
            .ok_or_else(|| "prior usage event not found".to_string())?;
        let _ = actor_note; // attribution reserved for enterprise audit coupling
        let event = UsageEvent {
            version: USAGE_EVENT_VERSION.into(),
            event_id: format!("corr:{}:{delta}", prior.event_id),
            tenant_id: prior.tenant_id.clone(),
            namespace: prior.namespace.clone(),
            unit: prior.unit,
            quantity: delta,
            source: UsageSource::Correction,
            receipt_operation_id: prior.receipt_operation_id.clone(),
            dedupe_key: format!("usage:v1:corr:{}:{delta}", prior.event_id),
            event_time_ms: chrono::Utc::now().timestamp_millis(),
            corrects_event_id: Some(prior.event_id),
        };
        self.append_usage_event(&event)?;
        Ok(event)
    }

    /// Export events for a closed period as versioned JSON lines payload.
    pub fn export_usage_period(
        &self,
        tenant_id: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<String, String> {
        let events = self.list_usage_events_for_tenant(tenant_id, start_ms, end_ms, 5_000)?;
        let mut lines = Vec::new();
        for event in events {
            lines.push(serde_json::to_string(&event).map_err(|e| e.to_string())?);
        }
        Ok(lines.join("\n"))
    }
}

fn validate_event(event: &UsageEvent) -> Result<(), String> {
    if event.version != USAGE_EVENT_VERSION {
        return Err(format!("unsupported usage event version {}", event.version));
    }
    for (label, value) in [
        ("event_id", event.event_id.as_str()),
        ("tenant_id", event.tenant_id.as_str()),
        ("namespace", event.namespace.as_str()),
        ("receipt_operation_id", event.receipt_operation_id.as_str()),
        ("dedupe_key", event.dedupe_key.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{label} required"));
        }
    }
    if event.quantity == 0 && event.source != UsageSource::Correction {
        return Err("quantity must be non-zero for non-correction events".into());
    }
    Ok(())
}

fn measured_tokens_from_receipt(receipt: &OperationReceipt) -> i64 {
    let mut total = 0i64;
    for event in &receipt.events {
        for key in [
            "total_tokens",
            "tokens",
            "input_tokens",
            "output_tokens",
            "prompt_tokens",
            "completion_tokens",
        ] {
            if let Some(value) = event.attributes.get(key)
                && let Ok(n) = value.parse::<i64>()
            {
                // Prefer explicit total when present once.
                if key == "total_tokens" || key == "tokens" {
                    return n;
                }
                total = total.saturating_add(n);
            }
        }
    }
    total
}

fn stable_event_id(tenant_id: &str, operation_id: &str, unit: &str, source: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(operation_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(unit.as_bytes());
    hasher.update(b"\0");
    hasher.update(source.as_bytes());
    format!("ue:{}", hex_encode(hasher.finalize()))
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<UsageEvent> {
    let unit_raw: String = row.get(4)?;
    let source_raw: String = row.get(6)?;
    Ok(UsageEvent {
        event_id: row.get(0)?,
        version: row.get(1)?,
        tenant_id: row.get(2)?,
        namespace: row.get(3)?,
        unit: UsageUnit::parse(&unit_raw).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                format!("unknown unit {unit_raw}").into(),
            )
        })?,
        quantity: row.get(5)?,
        source: UsageSource::parse(&source_raw).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                format!("unknown source {source_raw}").into(),
            )
        })?,
        receipt_operation_id: row.get(7)?,
        dedupe_key: row.get(8)?,
        event_time_ms: row.get(9)?,
        corrects_event_id: row.get(10)?,
    })
}

// Keep hex without adding a dependency if hex crate missing - check
// use simple format instead
fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

// Fix stable_event_id if hex crate unavailable - use local encoder
// Patch after compile if needed

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptEventKind, ReceiptSurface,
    };
    use std::collections::BTreeMap;

    fn sample_receipt(op: &str, tokens: i64) -> OperationReceipt {
        let mut attributes = BTreeMap::new();
        attributes.insert("total_tokens".into(), tokens.to_string());
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: op.into(),
            parent_operation_id: None,
            namespace: "ns".into(),
            operation_class: "chat".into(),
            initiating_actor: "alice".into(),
            schema_version: "1".into(),
            policy_version: "1".into(),
            started_at_ms: 1_000,
            completed_at_ms: Some(2_000),
            events: vec![OperationReceiptEvent {
                event_id: format!("{op}-ev1"),
                operation_id: op.into(),
                parent_event_id: None,
                timestamp_ms: 1_500,
                kind: ReceiptEventKind::ModelCalled,
                surface: ReceiptSurface::ModelCall,
                actor: "alice".into(),
                references: vec![],
                attributes,
            }],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
        }
    }

    #[test]
    fn replay_does_not_double_count() {
        let db = SekaiDb::new(":memory:").unwrap();
        let receipt = sample_receipt("op-1", 42);
        let first = db.project_usage_from_receipt("tenant-a", &receipt).unwrap();
        assert_eq!(first.len(), 2);
        let second = db.project_usage_from_receipt("tenant-a", &receipt).unwrap();
        assert_eq!(second.len(), 2);
        let agg = db
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Tokens, 0, 10_000)
            .unwrap();
        assert_eq!(agg.measured, 42);
        assert_eq!(agg.net, 42);
        let req = db
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, 10_000)
            .unwrap();
        assert_eq!(req.measured, 1);
    }

    #[test]
    fn tenants_are_isolated() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.project_usage_from_receipt("tenant-a", &sample_receipt("op-a", 10))
            .unwrap();
        db.project_usage_from_receipt("tenant-b", &sample_receipt("op-b", 99))
            .unwrap();
        let a = db
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Tokens, 0, 10_000)
            .unwrap();
        let b = db
            .aggregate_usage_for_tenant("tenant-b", UsageUnit::Tokens, 0, 10_000)
            .unwrap();
        assert_eq!(a.measured, 10);
        assert_eq!(b.measured, 99);
    }

    #[test]
    fn corrections_are_append_only() {
        let db = SekaiDb::new(":memory:").unwrap();
        let events = db
            .project_usage_from_receipt("tenant-a", &sample_receipt("op-c", 50))
            .unwrap();
        let token_event = events.iter().find(|e| e.unit == UsageUnit::Tokens).unwrap();
        let correction = db
            .correct_usage_event(&token_event.event_id, -10, "dispute")
            .unwrap();
        assert_eq!(correction.source, UsageSource::Correction);
        assert_eq!(
            correction.corrects_event_id.as_deref(),
            Some(token_event.event_id.as_str())
        );
        // Prior row unchanged.
        let prior = db.get_usage_event(&token_event.event_id).unwrap().unwrap();
        assert_eq!(prior.quantity, 50);
        let agg = db
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Tokens, 0, i64::MAX)
            .unwrap();
        assert_eq!(agg.measured, 50);
        assert_eq!(agg.corrections, -10);
        assert_eq!(agg.net, 40);
    }

    #[test]
    fn export_is_json_lines() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.project_usage_from_receipt("tenant-a", &sample_receipt("op-x", 3))
            .unwrap();
        let export = db.export_usage_period("tenant-a", 0, 10_000).unwrap();
        assert!(export.contains("\"unit\":\"requests\""));
        assert!(export.contains("\"unit\":\"tokens\""));
        assert!(export.lines().count() >= 2);
    }
}
