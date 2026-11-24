//! PostgreSQL persistence for the tenant usage ledger (#122).

use crate::chisei::usage_ledger::{
    UsageAggregate, UsageEvent, UsageScope, UsageUnit, measured_usage_events, validate_event,
};
use sekai_core::db::postgres::PostgresDb;
use sekai_domain::receipt::OperationReceipt;

pub trait PostgresUsageLedgerPostgresDbExt {
    fn append_usage_event(&self, event: &UsageEvent) -> Result<bool, String>;

    fn project_usage_from_receipt(
        &self,
        tenant_id: &str,
        receipt: &OperationReceipt,
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
}

impl PostgresUsageLedgerPostgresDbExt for PostgresDb {
    fn append_usage_event(&self, event: &UsageEvent) -> Result<bool, String> {
        validate_event(event)?;
        let unit = event.unit.as_str();
        let source = event.source.as_str();
        let (resource_kind, resource_id) = event
            .resource
            .as_ref()
            .map(|resource| (resource.kind.as_str(), resource.id.as_str()))
            .unzip();
        let inserted = self
            .connection()?
            .execute(
                "INSERT INTO chisei_usage_events
                    (event_id, version, tenant_id, namespace, unit, quantity, source,
                     receipt_operation_id, dedupe_key, event_time_ms, corrects_event_id,
                     principal_id, resource_kind, resource_id, reported_by)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                 ON CONFLICT DO NOTHING",
                &[
                    &event.event_id,
                    &event.version,
                    &event.tenant_id,
                    &event.namespace,
                    &unit,
                    &event.quantity,
                    &source,
                    &event.receipt_operation_id,
                    &event.dedupe_key,
                    &event.event_time_ms,
                    &event.corrects_event_id,
                    &event.principal_id,
                    &resource_kind,
                    &resource_id,
                    &event.reported_by,
                ],
            )
            .map_err(|error| {
                sekai_core::db::postgres::missing_relation_or(error, "chisei_usage_events")
            })?;
        Ok(inserted == 1)
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
        let rows = self
            .connection()?
            .query(
                "SELECT source, SUM(quantity)::BIGINT FROM chisei_usage_events
                 WHERE tenant_id = $1 AND unit = $2
                   AND event_time_ms >= $3 AND event_time_ms < $4
                   AND ($5::TEXT IS NULL OR namespace = $5)
                   AND ($6::TEXT IS NULL OR principal_id = $6)
                 GROUP BY source",
                &[
                    &tenant_id,
                    &unit.as_str(),
                    &start_ms,
                    &end_ms,
                    &scope.namespace,
                    &scope.principal_id,
                ],
            )
            .map_err(|error| {
                sekai_core::db::postgres::missing_relation_or(error, "chisei_usage_events")
            })?;
        let mut agg = UsageAggregate {
            tenant_id: tenant_id.into(),
            unit: unit.as_str().into(),
            ..Default::default()
        };
        for row in rows {
            agg.add(row.get::<_, &str>(0), row.get(1));
        }
        Ok(agg)
    }
}

/// Append one event to whichever backend holds the Chisei plane.
pub fn append_usage_event_in(
    db: &sekai_core::db::runtime_db::RuntimeDb,
    event: &UsageEvent,
) -> Result<bool, String> {
    use crate::chisei::usage_ledger::UsageLedgerSekaiDbExt;
    match db {
        sekai_core::db::runtime_db::RuntimeDb::Sqlite(sqlite) => sqlite.append_usage_event(event),
        sekai_core::db::runtime_db::RuntimeDb::Postgres(postgres) => {
            sekai_core::db::postgres::off_runtime(|| postgres.append_usage_event(event))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_core::db::postgres::ScratchDatabase;
    use sekai_domain::receipt::OPERATION_RECEIPT_VERSION;

    fn sample_receipt(op: &str) -> OperationReceipt {
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: op.into(),
            parent_operation_id: None,
            namespace: "ops".into(),
            operation_class: "transform".into(),
            initiating_actor: "local".into(),
            schema_version: "1".into(),
            policy_version: "1".into(),
            started_at_ms: 20,
            completed_at_ms: Some(20),
            events: Vec::new(),
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
            artifact: None,
        }
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_project_usage_from_receipt_records_once() {
        let scratch = ScratchDatabase::create();
        let db = crate::chisei_store::postgres_with_chisei_schema(scratch.connect());
        let receipt = sample_receipt("run-1");
        db.project_usage_from_receipt("tenant-a", &receipt).unwrap();
        db.project_usage_from_receipt("tenant-a", &receipt).unwrap();
        let usage = db
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap();
        assert_eq!(usage.measured, 1);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated PostgreSQL database"]
    fn postgres_ledger_accepts_new_units_and_aggregates_per_principal() {
        use crate::chisei::usage_ledger::{ReportedUsage, UsageResource, reported_usage_event};
        let scratch = ScratchDatabase::create();
        let db = crate::chisei_store::postgres_with_chisei_schema(scratch.connect());
        let mut receipt = sample_receipt("run-2");
        receipt.initiating_actor = "alice".into();
        receipt.events = vec![sekai_domain::receipt::OperationReceiptEvent {
            event_id: "ev".into(),
            operation_id: "run-2".into(),
            parent_event_id: None,
            timestamp_ms: 20,
            kind: sekai_domain::receipt::ReceiptEventKind::ModelCalled,
            surface: sekai_domain::receipt::ReceiptSurface::ModelCall,
            actor: "alice".into(),
            references: vec![],
            attributes: [("input_tokens", "30"), ("output_tokens", "20")]
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .into(),
        }];
        db.project_usage_from_receipt("tenant-a", &receipt).unwrap();
        let report = |key: &str, principal: &str| {
            reported_usage_event(ReportedUsage {
                tenant_id: "tenant-a",
                principal_id: principal,
                reported_by: "svc-jobs",
                namespace: "ops",
                unit: UsageUnit::ComputeSeconds,
                quantity: 11,
                dedupe_key: key,
                operation_id: None,
                resource: Some(UsageResource {
                    kind: "transform".into(),
                    id: "t-1".into(),
                }),
                event_time_ms: 30,
            })
            .unwrap()
        };
        assert!(db.append_usage_event(&report("k1", "bob")).unwrap());
        assert!(!db.append_usage_event(&report("k1", "bob")).unwrap());
        let scoped = |unit, principal_id| {
            db.aggregate_usage(
                "tenant-a",
                unit,
                UsageScope {
                    principal_id,
                    namespace: Some("ops"),
                },
                0,
                i64::MAX,
            )
            .unwrap()
            .net
        };
        assert_eq!(scoped(UsageUnit::InputTokens, Some("alice")), 30);
        assert_eq!(scoped(UsageUnit::OutputTokens, Some("alice")), 20);
        assert_eq!(scoped(UsageUnit::Tokens, None), 50);
        assert_eq!(scoped(UsageUnit::ComputeSeconds, Some("bob")), 11);
        assert_eq!(scoped(UsageUnit::ComputeSeconds, Some("alice")), 0);
    }
}
