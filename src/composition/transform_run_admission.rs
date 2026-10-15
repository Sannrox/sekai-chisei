//! Apply tenant quota and the usage ledger when a governed transform runs.
//!
//! Authority is the authenticated tenant. Policy is [`TenantQuotaGate`]. Usage
//! is a measured request event keyed by the transform run id.

use crate::chisei::budget::PeriodType;
use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, OperationReceipt};
use crate::chisei::tenant_quota::{
    METRIC_CONCURRENCY, METRIC_STORAGE_BYTES, TenantQuotaAdmission, TenantQuotaError,
    TenantQuotaGate, TenantQuotaLimits, tenant_scope_id,
};
use crate::chisei::usage_ledger::UsageEvent;
use crate::db::chisei_budget::{METRIC_REQUESTS, METRIC_TOKENS};
use crate::db::runtime_db::RuntimeDb;
use crate::db::store::ChiseiStore;
use crate::enterprise::AuthenticatedContext;
use crate::sekai::governed_transform::{TRANSFORM_CLASS, TransformRun};

pub fn receipt_from_transform_run(
    run: &TransformRun,
    actor: &str,
    completed_at_ms: i64,
) -> OperationReceipt {
    OperationReceipt {
        version: OPERATION_RECEIPT_VERSION.into(),
        operation_id: run.run_id.clone(),
        parent_operation_id: None,
        namespace: run.namespace.clone(),
        operation_class: TRANSFORM_CLASS.into(),
        initiating_actor: actor.into(),
        schema_version: "1".into(),
        policy_version: "1".into(),
        started_at_ms: run.created_at_ms,
        completed_at_ms: Some(completed_at_ms),
        events: Vec::new(),
        uncovered_surfaces: Vec::new(),
        reporter_grants: Vec::new(),
        ontology_digest: None,
        artifact: None,
    }
}

pub fn record_transform_usage(
    db: &RuntimeDb,
    tenant_id: &str,
    run: &TransformRun,
    actor: &str,
    completed_at_ms: i64,
) -> Result<Vec<UsageEvent>, String> {
    let receipt = receipt_from_transform_run(run, actor, completed_at_ms);
    let result = match db {
        RuntimeDb::Sqlite(sqlite) => sqlite.project_usage_from_receipt(tenant_id, &receipt),
        RuntimeDb::Postgres(db) => {
            crate::db::postgres::off_runtime(|| db.project_usage_from_receipt(tenant_id, &receipt))
        }
    };
    match result {
        Err(error) if relation_missing(&error, "chisei_usage_events") => Ok(Vec::new()),
        other => other,
    }
}

fn relation_missing(error: &str, table: &str) -> bool {
    let error = error.to_ascii_lowercase();
    let table = table.to_ascii_lowercase();
    error.contains(&table) && (error.contains("no such table") || error.contains("does not exist"))
}

pub fn quota_gate(db: std::sync::Arc<RuntimeDb>) -> TenantQuotaGate {
    TenantQuotaGate::new(ChiseiStore::from_shared_runtime(db))
}

pub fn configured_limits(
    db: &RuntimeDb,
    tenant_id: &str,
) -> Result<Option<TenantQuotaLimits>, String> {
    let rows = match db.budget_limits_for_scope(&tenant_scope_id(tenant_id)) {
        Ok(rows) => rows,
        Err(error)
            if error.contains("unavailable")
                || relation_missing(&error, "chisei_budget_limits") =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut limits = TenantQuotaLimits::unlimited(1);
    let mut any = false;
    let mut request_period = None;
    let mut token_period = None;
    for (_scope, metric, max_amount, period) in rows {
        any = true;
        match metric.as_str() {
            METRIC_REQUESTS => {
                limits.max_requests_per_period =
                    Some(i32::try_from(max_amount).unwrap_or(i32::MAX));
                request_period = Some(PeriodType::parse(&period));
            }
            METRIC_TOKENS => {
                limits.max_tokens_per_period = Some(i32::try_from(max_amount).unwrap_or(i32::MAX));
                token_period = Some(PeriodType::parse(&period));
            }
            METRIC_CONCURRENCY => {
                // In-flight units stay on a long tracker period; they are not
                // the request/token accounting window.
                limits.max_concurrency = Some(i32::try_from(max_amount).unwrap_or(i32::MAX));
            }
            METRIC_STORAGE_BYTES => limits.max_storage_bytes = Some(max_amount),
            _ => {}
        }
    }
    if let Some(period) = request_period.or(token_period) {
        limits.period = period;
    }
    Ok(any.then_some(limits))
}

pub fn admit_transform_run(
    gate: &TenantQuotaGate,
    context: &AuthenticatedContext,
    limits: &TenantQuotaLimits,
    run_key: &str,
    reclaim: bool,
) -> Result<TenantQuotaAdmission, TenantQuotaError> {
    let mut limits = limits.clone();
    if reclaim {
        limits.max_requests_per_period = None;
    }
    gate.admit(context, &limits, 1, 0, run_key)
}

pub fn complete_transform_run(
    gate: &TenantQuotaGate,
    admission: &TenantQuotaAdmission,
) -> Result<(), TenantQuotaError> {
    gate.complete(admission, 0).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::db::sekai::SekaiDb;
    use crate::provider_credentials::tenant_context;

    fn run(id: &str) -> TransformRun {
        TransformRun {
            run_id: id.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            definition_digest: "sha256:def".into(),
            input_digest: "sha256:in".into(),
            output_digest: "sha256:out".into(),
            last_input_row_id: 1,
            incremental: false,
            quarantined: false,
            quality_rule: String::new(),
            rows_in: 1,
            rows_out: 1,
            lineage_parent: String::new(),
            created_at_ms: 20,
            markings_in: String::new(),
            markings_out: String::new(),
            profile: String::new(),
            engine: String::new(),
            runtime_image: String::new(),
            dispatch_status: String::new(),
            trigger_cause: String::new(),
            trigger_ref: String::new(),
            input_partitions: Vec::new(),
            output_partitions: Vec::new(),
        }
    }

    #[test]
    fn receipt_identity_is_the_run_id() {
        let receipt = receipt_from_transform_run(&run("run-1"), "local", 20);
        assert_eq!(receipt.completed_at_ms, Some(20));
        assert_eq!(receipt.operation_id, "run-1");
        assert_eq!(receipt.namespace, "ops");
        assert_eq!(receipt.operation_class, TRANSFORM_CLASS);
        assert_eq!(receipt.initiating_actor, "local");
    }

    #[test]
    fn measured_request_is_recorded_once() {
        let sqlite = SekaiDb::new(":memory:").unwrap();
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(sqlite));
        let first = record_transform_usage(&db, "tenant-a", &run("run-1"), "local", 20).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].unit, UsageUnit::Requests);
        assert_eq!(first[0].quantity, 1);
        record_transform_usage(&db, "tenant-a", &run("run-1"), "local", 20).unwrap();
        let RuntimeDb::Sqlite(sqlite) = &db else {
            panic!("sqlite");
        };
        let agg = sqlite
            .aggregate_usage_for_tenant("tenant-a", UsageUnit::Requests, 0, 10_000)
            .unwrap();
        assert_eq!(agg.measured, 1);
    }

    #[test]
    fn configured_limits_reads_assigned_requests() {
        let db = std::sync::Arc::new(RuntimeDb::memory());
        let gate = quota_gate(db.clone());
        gate.configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(2),
                max_tokens_per_period: None,
                max_concurrency: None,
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
        let limits = configured_limits(&db, "tenant-a")
            .unwrap()
            .expect("configured limits");
        assert_eq!(limits.max_requests_per_period, Some(2));
        assert_eq!(limits.period, PeriodType::Daily);
    }

    #[test]
    fn configured_limits_keeps_request_period_when_concurrency_is_monthly() {
        let db = std::sync::Arc::new(RuntimeDb::memory());
        let gate = quota_gate(db.clone());
        gate.configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(2),
                max_tokens_per_period: None,
                max_concurrency: Some(4),
                max_storage_bytes: None,
                period: PeriodType::Daily,
            },
        )
        .unwrap();
        let limits = configured_limits(&db, "tenant-a")
            .unwrap()
            .expect("configured limits");
        assert_eq!(limits.max_requests_per_period, Some(2));
        assert_eq!(limits.max_concurrency, Some(4));
        assert_eq!(limits.period, PeriodType::Daily);
    }

    #[test]
    fn configured_request_quota_refuses_the_third_run() {
        let db = std::sync::Arc::new(RuntimeDb::memory());
        let gate = quota_gate(db);
        let limits = TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(2),
            max_tokens_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        };
        gate.configure("tenant-a", &limits).unwrap();
        let ctx = tenant_context("tenant-a", "alice");
        let a1 = admit_transform_run(&gate, &ctx, &limits, "run-1", false).unwrap();
        complete_transform_run(&gate, &a1).unwrap();
        let a2 = admit_transform_run(&gate, &ctx, &limits, "run-2", false).unwrap();
        complete_transform_run(&gate, &a2).unwrap();
        let err = admit_transform_run(&gate, &ctx, &limits, "run-3", false).unwrap_err();
        assert!(matches!(
            err,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_REQUESTS
        ));
    }

    #[test]
    fn reclaim_does_not_consume_another_request() {
        let db = std::sync::Arc::new(RuntimeDb::memory());
        let gate = quota_gate(db);
        let limits = TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(1),
            max_tokens_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        };
        gate.configure("tenant-a", &limits).unwrap();
        let ctx = tenant_context("tenant-a", "alice");
        let first = admit_transform_run(&gate, &ctx, &limits, "run-1", false).unwrap();
        complete_transform_run(&gate, &first).unwrap();
        admit_transform_run(&gate, &ctx, &limits, "run-1", true).unwrap();
        let err = admit_transform_run(&gate, &ctx, &limits, "run-2", false).unwrap_err();
        assert!(matches!(
            err,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_REQUESTS
        ));
    }

    #[test]
    fn configured_limits_skip_a_sekai_plane_without_budget_tables() {
        let sqlite =
            SekaiDb::new_for_plane(":memory:", crate::db::schema_plane::SchemaPlane::Sekai)
                .unwrap();
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(sqlite));
        assert_eq!(configured_limits(&db, "tenant-a").unwrap(), None);
    }

    #[test]
    fn record_usage_on_a_sekai_plane_without_ledger_is_a_noop() {
        let sqlite =
            SekaiDb::new_for_plane(":memory:", crate::db::schema_plane::SchemaPlane::Sekai)
                .unwrap();
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(sqlite));
        let events = record_transform_usage(&db, "tenant-a", &run("run-1"), "local", 20).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn postgres_db_error_is_not_a_missing_budget_table() {
        assert!(!relation_missing("db error", "chisei_budget_limits"));
        assert!(relation_missing(
            "chisei_budget_limits does not exist",
            "chisei_budget_limits"
        ));
    }
}
