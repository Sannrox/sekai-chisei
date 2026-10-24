//! PostgreSQL persistence for the tenant usage ledger (#122).

use crate::chisei::usage_ledger::{
    UsageAggregate, UsageEvent, UsageSource, UsageUnit, measured_usage_events, validate_event,
};
use crate::db::postgres::PostgresDb;
use sekai_domain::receipt::OperationReceipt;

pub trait PostgresUsageLedgerPostgresDbExt {
    fn append_usage_event(&self, event: &UsageEvent) -> Result<bool, String>;

    fn project_usage_from_receipt(
        &self,
        tenant_id: &str,
        receipt: &OperationReceipt,
    ) -> Result<Vec<UsageEvent>, String>;

    fn aggregate_usage_for_tenant(
        &self,
        tenant_id: &str,
        unit: UsageUnit,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<UsageAggregate, String>;
}

impl PostgresUsageLedgerPostgresDbExt for PostgresDb {
    fn append_usage_event(&self, event: &UsageEvent) -> Result<bool, String> {
        validate_event(event)?;
        let unit = event.unit.as_str();
        let source = event.source.as_str();
        let inserted = self
            .connection()?
            .execute(
                "INSERT INTO chisei_usage_events
                    (event_id, version, tenant_id, namespace, unit, quantity, source,
                     receipt_operation_id, dedupe_key, event_time_ms, corrects_event_id)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
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
                ],
            )
            .map_err(|error| {
                crate::db::postgres::missing_relation_or(error, "chisei_usage_events")
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

    fn aggregate_usage_for_tenant(
        &self,
        tenant_id: &str,
        unit: UsageUnit,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<UsageAggregate, String> {
        if tenant_id.is_empty() {
            return Err("tenant_id required".into());
        }
        let rows = self
            .connection()?
            .query(
                "SELECT source, quantity FROM chisei_usage_events
                 WHERE tenant_id = $1 AND unit = $2
                   AND event_time_ms >= $3 AND event_time_ms < $4",
                &[&tenant_id, &unit.as_str(), &start_ms, &end_ms],
            )
            .map_err(|error| {
                crate::db::postgres::missing_relation_or(error, "chisei_usage_events")
            })?;
        let mut agg = UsageAggregate {
            tenant_id: tenant_id.into(),
            unit: unit.as_str().into(),
            ..Default::default()
        };
        for row in rows {
            let source_raw: String = row.get(0);
            let quantity: i64 = row.get(1);
            match UsageSource::parse(&source_raw) {
                Some(UsageSource::Measured) => agg.measured += quantity,
                Some(UsageSource::ProviderReported) => agg.provider_reported += quantity,
                Some(UsageSource::Estimated) => agg.estimated += quantity,
                Some(UsageSource::Correction) => agg.corrections += quantity,
                None => {}
            }
            agg.net += quantity;
        }
        Ok(agg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::postgres::ScratchDatabase;
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
        let db = scratch.connect();
        let receipt = sample_receipt("run-1");
        db.project_usage_from_receipt("tenant-a", &receipt).unwrap();
        db.project_usage_from_receipt("tenant-a", &receipt).unwrap();
        let usage = db
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, i64::MAX)
            .unwrap();
        assert_eq!(usage.measured, 1);
    }
}
