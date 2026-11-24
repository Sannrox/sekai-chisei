//! Tenant usage event ledger (#122).
//!
//! Immutable, tenant-scoped usage events projected from governed operation
//! receipts. No pricing, invoicing, or billing-provider authority.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::chisei::receipt::OperationReceipt;
use sekai_core::db::sekai::SekaiDb;

pub const USAGE_EVENT_VERSION: &str = "chisei.usage-event/v1";

/// What a usage event counts. Readers skip stored units they do not know, so a
/// later release can add a unit without breaking this release's list or export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UsageUnit {
    /// Model tokens in total; the sum of input and output unless a receipt
    /// reports an explicit total.
    Tokens,
    Requests,
    InputTokens,
    OutputTokens,
    /// Wall-clock seconds of an isolated job, reported by the service that ran it.
    ComputeSeconds,
    /// Retained bytes, reported by the service that stores them.
    StorageBytes,
}

impl UsageUnit {
    pub const ALL: [Self; 6] = [
        Self::Tokens,
        Self::Requests,
        Self::InputTokens,
        Self::OutputTokens,
        Self::ComputeSeconds,
        Self::StorageBytes,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tokens => "tokens",
            Self::Requests => "requests",
            Self::InputTokens => "input_tokens",
            Self::OutputTokens => "output_tokens",
            Self::ComputeSeconds => "compute_seconds",
            Self::StorageBytes => "storage_bytes",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|unit| unit.as_str() == value)
    }
}

/// SQL list of the units this release reads, e.g. `'tokens','requests'`. Readers
/// filter on it so a row written by a newer release is skipped, not an error.
/// Built only from `UsageUnit::ALL`, never from input.
pub(crate) fn known_units_sql() -> String {
    UsageUnit::ALL
        .map(|unit| format!("'{}'", unit.as_str()))
        .join(",")
}

/// The resource that consumed the usage, for example a transform or a dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageResource {
    pub kind: String,
    pub id: String,
}

/// Narrows an aggregate below the tenant. `None` means every value.
#[derive(Debug, Clone, Copy, Default)]
pub struct UsageScope<'a> {
    pub namespace: Option<&'a str>,
    pub principal_id: Option<&'a str>,
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
    /// The principal that caused the work, from verified context only: the
    /// receipt's initiating actor, or the tenant assertion's subject on append.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<UsageResource>,
    /// The service that reported `provider_reported` usage on the principal's
    /// behalf (the delegating caller of the append call).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_by: Option<String>,
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

impl UsageAggregate {
    /// Fold one `(source, quantity)` sum into the aggregate.
    pub(crate) fn add(&mut self, source_raw: &str, quantity: i64) {
        match UsageSource::parse(source_raw) {
            Some(UsageSource::Measured) => self.measured += quantity,
            Some(UsageSource::ProviderReported) => self.provider_reported += quantity,
            Some(UsageSource::Estimated) => self.estimated += quantity,
            Some(UsageSource::Correction) => self.corrections += quantity,
            None => {}
        }
        self.net += quantity;
    }
}

/// Units a service may report through the append call. Tokens and requests are
/// measured by the plane itself from receipts.
pub const REPORTABLE_UNITS: [UsageUnit; 2] = [UsageUnit::ComputeSeconds, UsageUnit::StorageBytes];

const MAX_DEDUPE_KEY_LEN: usize = 256;

/// Usage a service measured outside the plane. `tenant_id` and `principal_id`
/// come from the verified tenant assertion, never from the request body.
#[derive(Debug, Clone)]
pub struct ReportedUsage<'a> {
    pub tenant_id: &'a str,
    pub principal_id: &'a str,
    /// The authenticated caller that reports on the principal's behalf.
    pub reported_by: &'a str,
    pub namespace: &'a str,
    pub unit: UsageUnit,
    pub quantity: i64,
    /// Caller key, unique per tenant; a replay with the same key is a no-op.
    pub dedupe_key: &'a str,
    /// The job or operation that consumed the usage; defaults to the dedupe key.
    pub operation_id: Option<&'a str>,
    pub resource: Option<UsageResource>,
    pub event_time_ms: i64,
}

/// Build the `provider_reported` ledger event for reported usage, or say why it
/// is not accepted.
pub fn reported_usage_event(report: ReportedUsage<'_>) -> Result<UsageEvent, String> {
    if !REPORTABLE_UNITS.contains(&report.unit) {
        return Err(format!(
            "unit {} is measured by the plane and cannot be reported",
            report.unit.as_str()
        ));
    }
    if report.quantity <= 0 {
        return Err("quantity must be positive".into());
    }
    let key = report.dedupe_key.trim();
    if key.is_empty() || key.len() > MAX_DEDUPE_KEY_LEN {
        return Err(format!(
            "dedupe_key required, at most {MAX_DEDUPE_KEY_LEN} bytes"
        ));
    }
    if report.principal_id.trim().is_empty() {
        return Err("principal required from authenticated context".into());
    }
    if let Some(resource) = &report.resource
        && (resource.kind.trim().is_empty() || resource.id.trim().is_empty())
    {
        return Err("resource needs both kind and id".into());
    }
    let tenant_id = report.tenant_id;
    let operation_id = report
        .operation_id
        .filter(|id| !id.trim().is_empty())
        .unwrap_or(key);
    Ok(UsageEvent {
        version: USAGE_EVENT_VERSION.into(),
        event_id: stable_event_id(tenant_id, key, "reported", "provider_reported"),
        tenant_id: tenant_id.into(),
        namespace: report.namespace.into(),
        unit: report.unit,
        quantity: report.quantity,
        source: UsageSource::ProviderReported,
        receipt_operation_id: operation_id.into(),
        dedupe_key: format!("usage:v1:{tenant_id}:reported:{key}"),
        event_time_ms: report.event_time_ms,
        corrects_event_id: None,
        principal_id: Some(report.principal_id.into()),
        resource: report.resource,
        reported_by: Some(report.reported_by.into()),
    })
}

const EVENT_COLUMNS: &str = "event_id, version, tenant_id, namespace, unit, quantity, source,
    receipt_operation_id, dedupe_key, event_time_ms, corrects_event_id,
    principal_id, resource_kind, resource_id, reported_by";

pub trait UsageLedgerSekaiDbExt {
    /// Append a usage event. Identical `dedupe_key` is a no-op success (replay-safe).
    fn append_usage_event(&self, event: &UsageEvent) -> Result<bool, String>;

    /// One event by id; `None` when absent or in a unit this release does not know.
    fn get_usage_event(&self, event_id: &str) -> Result<Option<UsageEvent>, String>;

    /// Events of a period in known units, oldest first.
    fn list_usage_events_for_tenant(
        &self,
        tenant_id: &str,
        start_ms: i64,
        end_ms: i64,
        limit: i64,
    ) -> Result<Vec<UsageEvent>, String>;

    /// Sum one unit for a tenant and period, optionally per namespace or principal.
    fn aggregate_usage(
        &self,
        tenant_id: &str,
        unit: UsageUnit,
        scope: UsageScope<'_>,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<UsageAggregate, String>;

    fn aggregate_usage_for_tenant(
        &self,
        tenant_id: &str,
        unit: UsageUnit,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<UsageAggregate, String> {
        self.aggregate_usage(tenant_id, unit, UsageScope::default(), start_ms, end_ms)
    }

    /// Project measured usage from a completed receipt into the ledger.
    /// `tenant_id` must come from verified enterprise context, not the receipt alone.
    fn project_usage_from_receipt(
        &self,
        tenant_id: &str,
        receipt: &OperationReceipt,
    ) -> Result<Vec<UsageEvent>, String>;

    /// Append-only correction (never mutates prior rows).
    fn correct_usage_event(
        &self,
        prior_event_id: &str,
        delta: i64,
        actor_note: &str,
    ) -> Result<UsageEvent, String>;

    /// Export known-unit events for a closed period as versioned JSON lines.
    fn export_usage_period(
        &self,
        tenant_id: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<String, String>;
}

impl UsageLedgerSekaiDbExt for SekaiDb {
    fn append_usage_event(&self, event: &UsageEvent) -> Result<bool, String> {
        validate_event(event)?;
        let (resource_kind, resource_id) = event
            .resource
            .as_ref()
            .map(|resource| (resource.kind.as_str(), resource.id.as_str()))
            .unzip();
        let inserted = self
            .conn()
            .execute(
                &format!(
                    "INSERT OR IGNORE INTO chisei_usage_events ({EVENT_COLUMNS})
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"
                ),
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
                    event.principal_id,
                    resource_kind,
                    resource_id,
                    event.reported_by,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(inserted == 1)
    }

    fn get_usage_event(&self, event_id: &str) -> Result<Option<UsageEvent>, String> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {EVENT_COLUMNS} FROM chisei_usage_events
                     WHERE event_id = ?1 AND unit IN ({})",
                    known_units_sql()
                ),
                params![event_id],
                row_to_event,
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    fn list_usage_events_for_tenant(
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
            .prepare(&format!(
                "SELECT {EVENT_COLUMNS} FROM chisei_usage_events
                 WHERE tenant_id = ?1 AND event_time_ms >= ?2 AND event_time_ms < ?3
                   AND unit IN ({})
                 ORDER BY event_time_ms ASC, event_id ASC
                 LIMIT ?4",
                known_units_sql()
            ))
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![tenant_id, start_ms, end_ms, limit], row_to_event)
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    fn aggregate_usage(
        &self,
        tenant_id: &str,
        unit: UsageUnit,
        scope: UsageScope<'_>,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<UsageAggregate, String> {
        if tenant_id.is_empty() {
            return Err("tenant_id required".into());
        }
        let mut agg = UsageAggregate {
            tenant_id: tenant_id.into(),
            unit: unit.as_str().into(),
            ..Default::default()
        };
        // Summed in SQL so the result never depends on how many events the period holds.
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT source, SUM(quantity) FROM chisei_usage_events
                 WHERE tenant_id = ?1 AND unit = ?2 AND event_time_ms >= ?3 AND event_time_ms < ?4
                   AND (?5 IS NULL OR namespace = ?5)
                   AND (?6 IS NULL OR principal_id = ?6)
                 GROUP BY source",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(
                params![
                    tenant_id,
                    unit.as_str(),
                    start_ms,
                    end_ms,
                    scope.namespace,
                    scope.principal_id
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (source_raw, quantity) = row.map_err(|e| e.to_string())?;
            agg.add(&source_raw, quantity);
        }
        Ok(agg)
    }

    fn project_usage_from_receipt(
        &self,
        tenant_id: &str,
        receipt: &OperationReceipt,
    ) -> Result<Vec<UsageEvent>, String> {
        let events = measured_usage_events(tenant_id, receipt)?;
        for event in &events {
            self.append_usage_event(event)?;
        }
        Ok(events)
    }

    fn correct_usage_event(
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
            principal_id: prior.principal_id,
            resource: prior.resource,
            reported_by: None,
        };
        self.append_usage_event(&event)?;
        Ok(event)
    }

    fn export_usage_period(
        &self,
        tenant_id: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<String, String> {
        // Page through the whole period in (event_time_ms, event_id) order so a large
        // tenant is never truncated at the per-call cap.
        const PAGE: i64 = 5_000;
        let sql = format!(
            "SELECT {EVENT_COLUMNS} FROM chisei_usage_events
             WHERE tenant_id = ?1 AND event_time_ms >= ?2 AND event_time_ms < ?3
               AND (event_time_ms, event_id) > (?4, ?5)
               AND unit IN ({})
             ORDER BY event_time_ms ASC, event_id ASC
             LIMIT ?6",
            known_units_sql()
        );
        let mut lines = Vec::new();
        let mut cursor = (i64::MIN, String::new());
        loop {
            let page = {
                let conn = self.conn();
                let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(
                        params![tenant_id, start_ms, end_ms, cursor.0, cursor.1, PAGE],
                        row_to_event,
                    )
                    .map_err(|e| e.to_string())?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?
            };
            for event in &page {
                lines.push(serde_json::to_string(event).map_err(|e| e.to_string())?);
            }
            match page.last() {
                Some(last) if page.len() as i64 == PAGE => {
                    cursor = (last.event_time_ms, last.event_id.clone());
                }
                _ => break,
            }
        }
        Ok(lines.join("\n"))
    }
}

/// Measured events for a receipt: one request, and the token total plus its
/// input and output parts when nonzero. Each carries the receipt's initiating
/// actor as principal.
pub(crate) fn measured_usage_events(
    tenant_id: &str,
    receipt: &OperationReceipt,
) -> Result<Vec<UsageEvent>, String> {
    if tenant_id.trim().is_empty() {
        return Err("tenant_id required from authenticated context".into());
    }
    let tokens = measured_tokens_from_receipt(receipt);
    let principal_id = Some(receipt.initiating_actor.trim())
        .filter(|actor| !actor.is_empty())
        .map(str::to_owned);
    let event_time = receipt.completed_at_ms.unwrap_or(receipt.started_at_ms);
    let measured = |unit: UsageUnit, quantity: i64| UsageEvent {
        version: USAGE_EVENT_VERSION.into(),
        event_id: stable_event_id(tenant_id, &receipt.operation_id, unit.as_str(), "measured"),
        tenant_id: tenant_id.into(),
        namespace: receipt.namespace.clone(),
        unit,
        quantity,
        source: UsageSource::Measured,
        receipt_operation_id: receipt.operation_id.clone(),
        dedupe_key: format!(
            "usage:v1:{tenant_id}:{}:{}:measured",
            receipt.operation_id,
            unit.as_str()
        ),
        event_time_ms: event_time,
        corrects_event_id: None,
        principal_id: principal_id.clone(),
        resource: None,
        reported_by: None,
    };
    Ok([
        (UsageUnit::Requests, 1),
        (UsageUnit::Tokens, tokens.total),
        (UsageUnit::InputTokens, tokens.input),
        (UsageUnit::OutputTokens, tokens.output),
    ]
    .into_iter()
    .filter(|(_, quantity)| *quantity != 0)
    .map(|(unit, quantity)| measured(unit, quantity))
    .collect())
}

pub(crate) fn validate_event(event: &UsageEvent) -> Result<(), String> {
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

#[derive(Debug, Default, PartialEq, Eq)]
struct MeasuredTokens {
    total: i64,
    input: i64,
    output: i64,
}

fn measured_tokens_from_receipt(receipt: &OperationReceipt) -> MeasuredTokens {
    // Per event: an explicit total wins over its parts. Across events: totals add up,
    // so a receipt with several model calls is not under-counted.
    receipt
        .events
        .iter()
        .fold(MeasuredTokens::default(), |sum, event| {
            let attr = |key: &str| {
                event
                    .attributes
                    .get(key)
                    .and_then(|value| value.parse::<i64>().ok())
            };
            let parts = |keys: [&str; 2]| {
                keys.into_iter()
                    .filter_map(attr)
                    .fold(0i64, i64::saturating_add)
            };
            let input = parts(["input_tokens", "prompt_tokens"]);
            let output = parts(["output_tokens", "completion_tokens"]);
            let total = ["total_tokens", "tokens"]
                .into_iter()
                .find_map(attr)
                .unwrap_or(input.saturating_add(output));
            MeasuredTokens {
                total: sum.total.saturating_add(total),
                input: sum.input.saturating_add(input),
                output: sum.output.saturating_add(output),
            }
        })
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
    let resource_kind: Option<String> = row.get(12)?;
    let resource_id: Option<String> = row.get(13)?;
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
        principal_id: row.get(11)?,
        resource: resource_kind
            .zip(resource_id)
            .map(|(kind, id)| UsageResource { kind, id }),
        reported_by: row.get(14)?,
    })
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

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
            ontology_digest: None,
            artifact: None,
        }
    }

    #[test]
    fn replay_does_not_double_count() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
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
    fn measured_tokens_sum_across_events_and_prefer_event_total() {
        let mut receipt = sample_receipt("op-multi", 100);
        let mut second = receipt.events[0].clone();
        second.event_id = "op-multi-ev2".into();
        second.attributes.clear();
        second.attributes.insert("input_tokens".into(), "30".into());
        second
            .attributes
            .insert("output_tokens".into(), "20".into());
        let mut third = receipt.events[0].clone();
        third.event_id = "op-multi-ev3".into();
        third.attributes.insert("input_tokens".into(), "7".into());
        receipt.events.extend([second, third]);
        // 100 (total wins over parts) + 50 (30 + 20) + 100 (total wins over input).
        assert_eq!(
            measured_tokens_from_receipt(&receipt),
            MeasuredTokens {
                total: 250,
                input: 37,
                output: 20
            }
        );
    }

    #[test]
    fn aggregate_and_export_cover_more_than_one_page_of_events() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
        let total = 5_003i64;
        for i in 0..total {
            let event = UsageEvent {
                version: USAGE_EVENT_VERSION.into(),
                event_id: format!("ev-{i:05}"),
                tenant_id: "tenant-a".into(),
                namespace: "ns".into(),
                unit: UsageUnit::Requests,
                quantity: 1,
                source: UsageSource::Measured,
                receipt_operation_id: format!("op-{i}"),
                dedupe_key: format!("dk-{i}"),
                // Shared timestamps exercise the event_id tiebreak in paging.
                event_time_ms: 1_000 + i / 3,
                corrects_event_id: None,
                principal_id: None,
                resource: None,
                reported_by: None,
            };
            assert!(db.append_usage_event(&event).unwrap());
        }
        let agg = db
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap();
        assert_eq!(agg.measured, total);
        assert_eq!(agg.net, total);
        let exported = db.export_usage_period("tenant-a", 0, i64::MAX).unwrap();
        assert_eq!(exported.lines().count() as i64, total);
    }

    #[test]
    fn tenants_are_isolated() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
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
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
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
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
        db.project_usage_from_receipt("tenant-a", &sample_receipt("op-x", 3))
            .unwrap();
        let export = db.export_usage_period("tenant-a", 0, 10_000).unwrap();
        assert!(export.contains("\"unit\":\"requests\""));
        assert!(export.contains("\"unit\":\"tokens\""));
        assert!(export.lines().count() >= 2);
    }

    fn split_receipt(op: &str, actor: &str, input: i64, output: i64) -> OperationReceipt {
        let mut receipt = sample_receipt(op, 0);
        receipt.initiating_actor = actor.into();
        let attributes = &mut receipt.events[0].attributes;
        attributes.clear();
        attributes.insert("input_tokens".into(), input.to_string());
        attributes.insert("output_tokens".into(), output.to_string());
        receipt
    }

    fn total(db: &SekaiDb, unit: UsageUnit, scope: UsageScope<'_>) -> i64 {
        db.aggregate_usage("tenant-a", unit, scope, 0, i64::MAX)
            .unwrap()
            .net
    }

    fn reported(key: &str, principal: &str, namespace: &str, quantity: i64) -> UsageEvent {
        reported_usage_event(ReportedUsage {
            tenant_id: "tenant-a",
            principal_id: principal,
            reported_by: "svc-jobs",
            namespace,
            unit: UsageUnit::ComputeSeconds,
            quantity,
            dedupe_key: key,
            operation_id: Some("job-1"),
            resource: Some(UsageResource {
                kind: "transform".into(),
                id: "t-1".into(),
            }),
            event_time_ms: 3_000,
        })
        .unwrap()
    }

    #[test]
    fn receipt_projects_split_tokens_with_the_initiating_principal() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
        let events = db
            .project_usage_from_receipt("tenant-a", &split_receipt("op-s", "alice", 30, 20))
            .unwrap();
        let quantity = |unit| events.iter().find(|e| e.unit == unit).map(|e| e.quantity);
        assert_eq!(quantity(UsageUnit::Tokens), Some(50));
        assert_eq!(quantity(UsageUnit::InputTokens), Some(30));
        assert_eq!(quantity(UsageUnit::OutputTokens), Some(20));
        assert!(
            events
                .iter()
                .all(|e| e.principal_id.as_deref() == Some("alice"))
        );
        db.project_usage_from_receipt("tenant-a", &split_receipt("op-t", "bob", 5, 1))
            .unwrap();
        let alice = UsageScope {
            principal_id: Some("alice"),
            ..Default::default()
        };
        assert_eq!(total(&db, UsageUnit::InputTokens, alice), 30);
        assert_eq!(total(&db, UsageUnit::OutputTokens, alice), 20);
        assert_eq!(total(&db, UsageUnit::Tokens, UsageScope::default()), 56);
    }

    #[test]
    fn reported_usage_aggregates_per_namespace_and_principal_and_replays_once() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
        assert!(
            db.append_usage_event(&reported("k1", "alice", "ns", 40))
                .unwrap()
        );
        // Same key, different body: a no-op, never a second charge.
        assert!(
            !db.append_usage_event(&reported("k1", "alice", "ns", 99))
                .unwrap()
        );
        assert!(
            db.append_usage_event(&reported("k2", "bob", "other", 7))
                .unwrap()
        );
        let ns = UsageScope {
            namespace: Some("ns"),
            ..Default::default()
        };
        let bob = UsageScope {
            principal_id: Some("bob"),
            ..Default::default()
        };
        assert_eq!(total(&db, UsageUnit::ComputeSeconds, ns), 40);
        assert_eq!(total(&db, UsageUnit::ComputeSeconds, bob), 7);
        let all = db
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::ComputeSeconds, 0, i64::MAX)
            .unwrap();
        assert_eq!((all.provider_reported, all.net), (47, 47));
        let listed = db
            .list_usage_events_for_tenant("tenant-a", 0, i64::MAX, 10)
            .unwrap();
        assert_eq!(
            listed[0].resource.as_ref().map(|r| r.id.as_str()),
            Some("t-1")
        );
    }

    #[test]
    fn reported_usage_rejects_measured_units_and_empty_keys() {
        let base = ReportedUsage {
            tenant_id: "tenant-a",
            principal_id: "alice",
            reported_by: "svc-jobs",
            namespace: "ns",
            unit: UsageUnit::Tokens,
            quantity: 1,
            dedupe_key: "k",
            operation_id: None,
            resource: None,
            event_time_ms: 1,
        };
        assert!(reported_usage_event(base.clone()).is_err());
        assert!(
            reported_usage_event(ReportedUsage {
                unit: UsageUnit::StorageBytes,
                dedupe_key: " ",
                ..base.clone()
            })
            .is_err()
        );
        assert!(
            reported_usage_event(ReportedUsage {
                unit: UsageUnit::StorageBytes,
                quantity: 0,
                ..base
            })
            .is_err()
        );
    }

    #[test]
    fn readers_skip_units_written_by_a_newer_release() {
        let db = crate::chisei_store::memory_sekai_with_chisei_schema();
        db.project_usage_from_receipt("tenant-a", &sample_receipt("op-k", 12))
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO chisei_usage_events
                    (event_id, version, tenant_id, namespace, unit, quantity, source,
                     receipt_operation_id, dedupe_key, event_time_ms)
                 VALUES ('future', ?1, 'tenant-a', 'ns', 'gpu_hours', 5, 'measured',
                         'op-f', 'future-key', 1500)",
                params![USAGE_EVENT_VERSION],
            )
            .unwrap();
        let listed = db
            .list_usage_events_for_tenant("tenant-a", 0, i64::MAX, 100)
            .unwrap();
        assert_eq!(listed.len(), 2);
        let exported = db.export_usage_period("tenant-a", 0, i64::MAX).unwrap();
        assert_eq!(exported.lines().count(), 2);
        assert!(!exported.contains("gpu_hours"));
        assert!(db.get_usage_event("future").unwrap().is_none());
        assert_eq!(total(&db, UsageUnit::Tokens, UsageScope::default()), 12);
        assert_eq!(total(&db, UsageUnit::Requests, UsageScope::default()), 1);
    }

    #[test]
    fn upgraded_table_keeps_events_and_accepts_new_units() {
        use crate::chisei_store::ChiseiSqliteSchema;
        let db = SekaiDb::new(":memory:").unwrap();
        db.conn()
            .execute_batch(
                "CREATE TABLE chisei_usage_events (
                    event_id TEXT PRIMARY KEY, version TEXT NOT NULL,
                    tenant_id TEXT NOT NULL, namespace TEXT NOT NULL, unit TEXT NOT NULL,
                    quantity INTEGER NOT NULL, source TEXT NOT NULL,
                    receipt_operation_id TEXT NOT NULL, dedupe_key TEXT NOT NULL UNIQUE,
                    event_time_ms INTEGER NOT NULL, corrects_event_id TEXT,
                    CHECK (unit IN ('tokens', 'requests')),
                    CHECK (source IN ('measured', 'provider_reported', 'estimated', 'correction'))
                );
                INSERT INTO chisei_usage_events VALUES
                    ('old', 'chisei.usage-event/v1', 'tenant-a', 'ns', 'tokens', 9,
                     'measured', 'op-old', 'old-key', 1000, NULL);",
            )
            .unwrap();
        db.migrate_usage_ledger().unwrap();
        db.migrate_usage_ledger().unwrap();
        let old = db.get_usage_event("old").unwrap().unwrap();
        assert_eq!(
            (old.unit, old.quantity, old.principal_id),
            (UsageUnit::Tokens, 9, None)
        );
        assert!(
            db.append_usage_event(&reported("k1", "alice", "ns", 3))
                .unwrap()
        );
        assert_eq!(
            total(&db, UsageUnit::ComputeSeconds, UsageScope::default()),
            3
        );
    }
}
