//! Apply tenant quota and the usage ledger when a governed transform runs.
//!
//! Authority is the authenticated tenant. Policy is [`TenantQuotaGate`]. Usage
//! is a measured request event keyed by the transform run id.

use crate::chisei::budget::PeriodType;
use crate::chisei::receipt::{OPERATION_RECEIPT_VERSION, OperationReceipt};
use crate::chisei::tenant_quota::{
    METRIC_COMPUTE_SECONDS, METRIC_CONCURRENCY, METRIC_STORAGE_BYTES, NamespaceQuotaScope,
    TenantQuotaAdmission, TenantQuotaError, TenantQuotaGate, TenantQuotaLimits, tenant_scope_id,
};
use crate::chisei::usage_ledger::UsageEvent;
use crate::chisei_store::ChiseiStore;
use crate::ext::*;
use sekai_core::db::chisei_budget::{METRIC_REQUESTS, METRIC_TOKENS};
use sekai_core::db::runtime_db::RuntimeDb;
use sekai_core::enterprise::{AuthenticatedContext, IsolatedProcessRefusal};
use sekai_core::sekai::governed_transform::{TRANSFORM_CLASS, TransformRun};

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
        RuntimeDb::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
            db.project_usage_from_receipt(tenant_id, &receipt)
        }),
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

pub fn quota_gate(db: std::sync::Arc<RuntimeDb>) -> Result<TenantQuotaGate, String> {
    Ok(TenantQuotaGate::new(ChiseiStore::try_from_shared_runtime(
        db,
    )?))
}

type BudgetLimitRows = Vec<(String, String, i64, String)>;

/// A plane without budget tables has no tenant quota (`Ok(None)`). Every other
/// store error propagates so admission refuses instead of running unmetered.
fn budget_rows(result: Result<BudgetLimitRows, String>) -> Result<Option<BudgetLimitRows>, String> {
    match result {
        Ok(rows) => Ok(Some(rows)),
        Err(error) if relation_missing(&error, "chisei_budget_limits") => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn configured_limits(
    db: &RuntimeDb,
    tenant_id: &str,
) -> Result<Option<TenantQuotaLimits>, String> {
    let Some(rows) = budget_rows(db.budget_limits_for_scope(&tenant_scope_id(tenant_id)))? else {
        return Ok(None);
    };
    Ok(limits_from_rows(rows))
}

/// The namespace's own assignment (#3044, ADR 0168): only the rows stored
/// under its scope, not the tenant's it would inherit on the budget chain.
/// `None` when the namespace has none, or the plane has no budget tables.
pub fn configured_namespace_limits(
    db: &RuntimeDb,
    scope: &NamespaceQuotaScope,
) -> Result<Option<TenantQuotaLimits>, String> {
    let Some(rows) = budget_rows(db.budget_limits_for_scope(scope.scope_id()))? else {
        return Ok(None);
    };
    Ok(limits_from_rows(
        rows.into_iter()
            .filter(|(row_scope, ..)| row_scope == scope.scope_id())
            .collect(),
    ))
}

/// The tenant and namespace assignments a transform run in `namespace` is
/// admitted against. The namespace part is `None` when it has no assignment
/// or is a name no assignment can be stored under.
pub fn configured_run_limits(
    db: &RuntimeDb,
    tenant_id: &str,
    namespace: &str,
) -> Result<RunQuotaLimits, String> {
    let tenant = configured_limits(db, tenant_id)?;
    let namespace = match NamespaceQuotaScope::new(tenant_id, namespace) {
        Ok(scope) => configured_namespace_limits(db, &scope)?.map(|limits| (scope, limits)),
        Err(_) => None,
    };
    Ok(RunQuotaLimits { tenant, namespace })
}

/// A transform run's tenant assignment and its namespace's, either absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunQuotaLimits {
    pub tenant: Option<TenantQuotaLimits>,
    pub namespace: Option<(NamespaceQuotaScope, TenantQuotaLimits)>,
}

impl RunQuotaLimits {
    /// True when neither the tenant nor the namespace has an assignment.
    pub fn is_unlimited(&self) -> bool {
        self.tenant.is_none() && self.namespace.is_none()
    }

    /// The refusal of a run estimated at `compute_seconds` that is larger
    /// than either whole budget.
    pub fn refusal_larger_than_budget(
        &self,
        compute_seconds: i32,
    ) -> Option<IsolatedProcessRefusal> {
        self.tenant
            .iter()
            .chain(self.namespace.as_ref().map(|(_, limits)| limits))
            .find_map(|limits| refusal_larger_than_budget(limits, compute_seconds))
    }
}

fn limits_from_rows(rows: BudgetLimitRows) -> Option<TenantQuotaLimits> {
    let mut limits = TenantQuotaLimits::unlimited(1);
    let mut any = false;
    let mut request_period = None;
    let mut token_period = None;
    let mut compute_period = None;
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
            METRIC_COMPUTE_SECONDS => {
                limits.max_compute_seconds_per_period =
                    Some(i32::try_from(max_amount).unwrap_or(i32::MAX));
                compute_period = Some(PeriodType::parse(&period));
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
    if let Some(period) = request_period.or(token_period).or(compute_period) {
        limits.period = period;
    }
    any.then_some(limits)
}

/// Refusal code for a run that asks more of one metric than its scope's
/// whole budget, so it could never be admitted (#3044, ADR 0168).
pub const REFUSAL_LARGER_THAN_BUDGET: &str = "quota_larger_than_budget";

/// The terminal refusal of a transform run whose own reservation exceeds a
/// whole configured budget. Each run reserves one request, one concurrency
/// unit and its `compute_seconds` estimate, so a limit below any of them can
/// never admit it; a run left waiting on such a limit would wait forever.
/// Usage, which frees with time, never refuses here.
pub fn refusal_larger_than_budget(
    limits: &TenantQuotaLimits,
    compute_seconds: i32,
) -> Option<IsolatedProcessRefusal> {
    const RUN_REQUESTS: i64 = 1;
    const RUN_CONCURRENCY: i64 = 1;
    [
        (
            METRIC_REQUESTS,
            limits.max_requests_per_period.map(i64::from),
            RUN_REQUESTS,
        ),
        (
            METRIC_COMPUTE_SECONDS,
            limits.max_compute_seconds_per_period.map(i64::from),
            i64::from(compute_seconds),
        ),
        (
            METRIC_CONCURRENCY,
            limits.max_concurrency.map(i64::from),
            RUN_CONCURRENCY,
        ),
    ]
    .into_iter()
    .find_map(|(metric, limit, requested)| {
        let limit = limit.filter(|limit| *limit < requested)?;
        Some(IsolatedProcessRefusal {
            code: REFUSAL_LARGER_THAN_BUDGET.into(),
            details: [
                ("metric", metric.to_string()),
                ("limit", limit.to_string()),
                ("requested", requested.to_string()),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
        })
    })
}

/// Refusal code for a run whose tenant or namespace budget is spent (#3044,
/// ADR 0168): budgets refuse, only concurrency waits.
pub const REFUSAL_BUDGET_EXHAUSTED: &str = "quota_budget_exhausted";

/// The terminal refusal an admission error stands for, with the spent
/// `metric`. `None` for a full concurrency limit, which frees as runs
/// finish, and for every error that is not exhaustion.
pub fn refusal_budget_exhausted(error: &TenantQuotaError) -> Option<IsolatedProcessRefusal> {
    match error {
        TenantQuotaError::Exhausted { metric, .. } if metric != METRIC_CONCURRENCY => {
            Some(IsolatedProcessRefusal {
                code: REFUSAL_BUDGET_EXHAUSTED.into(),
                details: [("metric".to_string(), metric.clone())].into(),
            })
        }
        _ => None,
    }
}

/// Admit a transform run against its tenant and namespace assignments,
/// reserving `compute_seconds` of its compute budget. A reclaimed run
/// already holds its request on both scopes, so it reserves none again; its
/// compute is reserved anew because the lost claim's was refunded.
pub fn admit_transform_run(
    gate: &TenantQuotaGate,
    context: &AuthenticatedContext,
    limits: &RunQuotaLimits,
    run_key: &str,
    compute_seconds: i32,
    reclaim: bool,
) -> Result<TenantQuotaAdmission, TenantQuotaError> {
    let without_request = |limits: &TenantQuotaLimits| {
        let mut limits = limits.clone();
        if reclaim {
            limits.max_requests_per_period = None;
        }
        limits
    };
    let tenant = without_request(
        limits
            .tenant
            .as_ref()
            .unwrap_or(&TenantQuotaLimits::unlimited(1)),
    );
    let namespace = limits
        .namespace
        .as_ref()
        .map(|(scope, limits)| (scope, without_request(limits)));
    gate.admit_in_namespace(
        context,
        &tenant,
        namespace.as_ref().map(|(scope, limits)| (*scope, limits)),
        1,
        0,
        compute_seconds,
        run_key,
    )
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
    use crate::chisei::tenant_quota::NamespaceQuotaScope;
    use crate::chisei::usage_ledger::UsageUnit;
    use crate::tenant_context;
    use sekai_core::db::sekai::SekaiDb;

    fn run(id: &str) -> TransformRun {
        TransformRun {
            input_versions: Default::default(),
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
        crate::chisei_store::apply_chisei_schema(&db);
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
        let gate = quota_gate(db.clone()).unwrap();
        gate.configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(2),
                max_tokens_per_period: None,
                max_compute_seconds_per_period: None,
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
        let gate = quota_gate(db.clone()).unwrap();
        gate.configure(
            "tenant-a",
            &TenantQuotaLimits {
                version: 1,
                max_requests_per_period: Some(2),
                max_tokens_per_period: None,
                max_compute_seconds_per_period: None,
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

    /// Run limits with only a tenant assignment, as before namespaces.
    fn tenant_only(limits: &TenantQuotaLimits) -> RunQuotaLimits {
        RunQuotaLimits {
            tenant: Some(limits.clone()),
            namespace: None,
        }
    }

    fn requests_and_concurrency(requests: i32, concurrency: i32) -> TenantQuotaLimits {
        TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(requests),
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: Some(concurrency),
            max_storage_bytes: None,
            period: PeriodType::Daily,
        }
    }

    #[test]
    fn a_namespace_assignment_leaves_the_tenant_assignment_as_it_was() {
        let db = std::sync::Arc::new(RuntimeDb::memory());
        let gate = quota_gate(db.clone()).unwrap();
        let tenant = requests_and_concurrency(2, 4);
        gate.configure("tenant-a", &tenant).unwrap();
        let before = configured_limits(&db, "tenant-a").unwrap();
        let ops = NamespaceQuotaScope::new("tenant-a", "ops").unwrap();
        gate.configure_namespace(&ops, &requests_and_concurrency(0, 0))
            .unwrap();

        assert_eq!(configured_limits(&db, "tenant-a").unwrap(), before);
        let own: Vec<_> = db
            .budget_limits_for_scope(ops.scope_id())
            .unwrap()
            .into_iter()
            .filter(|(scope, ..)| scope == ops.scope_id())
            .map(|(_, metric, max, _)| (metric, max))
            .collect();
        assert_eq!(
            own.len(),
            2,
            "the namespace rows are stored under their own scope: {own:?}"
        );
        // The tenant still admits two runs and refuses the third by usage,
        // and is never larger than its budget, although the namespace
        // assignment would refuse every run once enforced.
        let limits = before.expect("tenant limits");
        assert_eq!(refusal_larger_than_budget(&limits, 0), None);
        let ctx = tenant_context("tenant-a", "alice");
        for key in ["run-1", "run-2"] {
            let held =
                admit_transform_run(&gate, &ctx, &tenant_only(&limits), key, 0, false).unwrap();
            complete_transform_run(&gate, &held).unwrap();
        }
        assert!(matches!(
            admit_transform_run(&gate, &ctx, &tenant_only(&limits), "run-3", 0, false),
            Err(TenantQuotaError::Exhausted { metric, .. }) if metric == METRIC_REQUESTS
        ));
    }

    fn requests_only(requests: i32) -> TenantQuotaLimits {
        TenantQuotaLimits {
            max_concurrency: None,
            ..requests_and_concurrency(requests, 0)
        }
    }

    fn exhausted_on(result: Result<TenantQuotaAdmission, TenantQuotaError>, expected: &str) {
        assert!(
            matches!(&result, Err(TenantQuotaError::Exhausted { metric, .. }) if metric == expected),
            "expected {expected} exhausted, got {result:?}"
        );
    }

    /// A gate on a fresh store with `tenant-a` and its `ops` namespace
    /// assigned as given.
    fn namespace_gate(
        tenant: Option<TenantQuotaLimits>,
        ops: TenantQuotaLimits,
    ) -> (std::sync::Arc<RuntimeDb>, TenantQuotaGate) {
        let db = std::sync::Arc::new(RuntimeDb::memory());
        let gate = quota_gate(db.clone()).unwrap();
        if let Some(tenant) = tenant {
            gate.configure("tenant-a", &tenant).unwrap();
        }
        let ops_scope = NamespaceQuotaScope::new("tenant-a", "ops").unwrap();
        gate.configure_namespace(&ops_scope, &ops).unwrap();
        (db, gate)
    }

    fn admit_in(
        db: &RuntimeDb,
        gate: &TenantQuotaGate,
        namespace: &str,
        key: &str,
    ) -> Result<TenantQuotaAdmission, TenantQuotaError> {
        let limits = configured_run_limits(db, "tenant-a", namespace).unwrap();
        admit_transform_run(
            gate,
            &tenant_context("tenant-a", "alice"),
            &limits,
            key,
            0,
            false,
        )
    }

    #[test]
    fn a_run_reserves_on_its_tenant_and_namespace_and_the_stricter_wins() {
        let (db, gate) = namespace_gate(Some(requests_only(3)), requests_only(1));
        complete_transform_run(&gate, &admit_in(&db, &gate, "ops", "run-1").unwrap()).unwrap();
        // The namespace's one request is spent although the tenant has two.
        exhausted_on(admit_in(&db, &gate, "ops", "run-2"), METRIC_REQUESTS);
        // A namespace without an assignment shares what is left of the tenant:
        // the ops run counted there too.
        for key in ["run-3", "run-4"] {
            complete_transform_run(&gate, &admit_in(&db, &gate, "dev", key).unwrap()).unwrap();
        }
        exhausted_on(admit_in(&db, &gate, "dev", "run-5"), METRIC_REQUESTS);
    }

    #[test]
    fn a_namespace_refusal_leaves_nothing_reserved_on_the_tenant() {
        let (db, gate) = namespace_gate(
            Some(requests_and_concurrency(2, 5)),
            requests_and_concurrency(10, 1),
        );
        let held = admit_in(&db, &gate, "ops", "run-1").unwrap();
        // The tenant request and concurrency taken for run-2 are rolled back
        // when the namespace's concurrency refuses it.
        exhausted_on(admit_in(&db, &gate, "ops", "run-2"), METRIC_CONCURRENCY);
        complete_transform_run(&gate, &admit_in(&db, &gate, "dev", "run-3").unwrap()).unwrap();
        exhausted_on(admit_in(&db, &gate, "dev", "run-4"), METRIC_REQUESTS);
        // Completing run-1 frees the namespace hold again.
        complete_transform_run(&gate, &held).unwrap();
        let limits = configured_run_limits(&db, "tenant-a", "ops").unwrap();
        let reclaim = admit_transform_run(
            &gate,
            &tenant_context("tenant-a", "alice"),
            &limits,
            "run-1",
            0,
            true,
        );
        assert!(reclaim.is_ok(), "{reclaim:?}");
    }

    #[test]
    fn a_namespace_assignment_without_a_tenant_assignment_is_enforced() {
        let (db, gate) = namespace_gate(None, requests_only(1));
        let limits = configured_run_limits(&db, "tenant-a", "ops").unwrap();
        assert_eq!(limits.tenant, None);
        assert!(!limits.is_unlimited());
        assert!(
            configured_run_limits(&db, "tenant-a", "dev")
                .unwrap()
                .is_unlimited()
        );
        complete_transform_run(&gate, &admit_in(&db, &gate, "ops", "run-1").unwrap()).unwrap();
        exhausted_on(admit_in(&db, &gate, "ops", "run-2"), METRIC_REQUESTS);
    }

    #[test]
    fn a_run_larger_than_its_namespace_budget_is_refused() {
        let (db, _gate) = namespace_gate(
            Some(requests_and_concurrency(5, 5)),
            requests_and_concurrency(5, 0),
        );
        let refusal = configured_run_limits(&db, "tenant-a", "ops")
            .unwrap()
            .refusal_larger_than_budget(0)
            .expect("the namespace can never hold a concurrency unit");
        assert_eq!(refusal.details["metric"], METRIC_CONCURRENCY);
        assert_eq!(refusal.details["limit"], "0");
        let dev = configured_run_limits(&db, "tenant-a", "dev").unwrap();
        assert_eq!(dev.refusal_larger_than_budget(0), None);
    }

    /// What a successor refunds for a crashed claim from its stored hold.
    fn stored_hold_refund(tenant_scope: &str, run_key: &str) -> TenantQuotaAdmission {
        TenantQuotaAdmission {
            reserved_request: true,
            reserved_concurrency: true,
            ..TenantQuotaAdmission::from_hold("tenant-a", tenant_scope, run_key)
        }
    }

    #[test]
    fn a_stored_hold_refunds_the_tenant_and_the_namespace_it_names() {
        let (db, gate) = namespace_gate(
            Some(requests_and_concurrency(1, 1)),
            requests_and_concurrency(1, 1),
        );
        let crashed = admit_in(&db, &gate, "ops", "run-1").unwrap();
        exhausted_on(admit_in(&db, &gate, "ops", "run-2"), METRIC_REQUESTS);
        gate.abandon(&stored_hold_refund(&crashed.scope_id, "run-1"))
            .unwrap();
        // Both scopes got their request and concurrency back.
        let next = admit_in(&db, &gate, "ops", "run-2").unwrap();
        assert!(next.reserved_request && next.reserved_concurrency);
    }

    #[test]
    fn an_older_hold_without_a_scope_refunds_only_the_tenant() {
        let (db, gate) = namespace_gate(Some(requests_only(2)), requests_only(1));
        admit_in(&db, &gate, "ops", "run-1").unwrap();
        // A hold written before namespaces carries no scope. Its refund
        // reaches the tenant without error and leaves the namespace counted,
        // which refuses rather than over-admits.
        let older = stored_hold_refund("", "run-1");
        assert_eq!(older.scope_id, tenant_scope_id("tenant-a"));
        gate.abandon(&older).unwrap();
        exhausted_on(admit_in(&db, &gate, "ops", "run-2"), METRIC_REQUESTS);
        for key in ["run-3", "run-4"] {
            complete_transform_run(&gate, &admit_in(&db, &gate, "dev", key).unwrap()).unwrap();
        }
        exhausted_on(admit_in(&db, &gate, "dev", "run-5"), METRIC_REQUESTS);
    }

    #[test]
    fn a_zero_budget_refuses_a_run_that_could_never_fit() {
        let refusal = refusal_larger_than_budget(&requests_and_concurrency(5, 0), 0)
            .expect("no concurrency unit can ever be held");
        assert_eq!(refusal.code, REFUSAL_LARGER_THAN_BUDGET);
        assert_eq!(refusal.details["metric"], METRIC_CONCURRENCY);
        assert_eq!(refusal.details["limit"], "0");
        assert_eq!(refusal.details["requested"], "1");
        refusal.validate().unwrap();
        let refusal = refusal_larger_than_budget(&requests_and_concurrency(0, 1), 0).unwrap();
        assert_eq!(refusal.details["metric"], METRIC_REQUESTS);
        assert_eq!(
            refusal_larger_than_budget(&requests_and_concurrency(1, 1), 0),
            None
        );
        assert_eq!(
            refusal_larger_than_budget(&TenantQuotaLimits::unlimited(1), 0),
            None
        );
    }

    #[test]
    fn configured_request_quota_refuses_the_third_run() {
        let db = std::sync::Arc::new(RuntimeDb::memory());
        let gate = quota_gate(db).unwrap();
        let limits = TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(2),
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        };
        gate.configure("tenant-a", &limits).unwrap();
        let ctx = tenant_context("tenant-a", "alice");
        let a1 =
            admit_transform_run(&gate, &ctx, &tenant_only(&limits), "run-1", 0, false).unwrap();
        complete_transform_run(&gate, &a1).unwrap();
        let a2 =
            admit_transform_run(&gate, &ctx, &tenant_only(&limits), "run-2", 0, false).unwrap();
        complete_transform_run(&gate, &a2).unwrap();
        let err =
            admit_transform_run(&gate, &ctx, &tenant_only(&limits), "run-3", 0, false).unwrap_err();
        assert!(matches!(
            err,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_REQUESTS
        ));
    }

    #[test]
    fn reclaim_does_not_consume_another_request() {
        let db = std::sync::Arc::new(RuntimeDb::memory());
        let gate = quota_gate(db).unwrap();
        let limits = TenantQuotaLimits {
            version: 1,
            max_requests_per_period: Some(1),
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        };
        gate.configure("tenant-a", &limits).unwrap();
        let ctx = tenant_context("tenant-a", "alice");
        let first =
            admit_transform_run(&gate, &ctx, &tenant_only(&limits), "run-1", 0, false).unwrap();
        complete_transform_run(&gate, &first).unwrap();
        admit_transform_run(&gate, &ctx, &tenant_only(&limits), "run-1", 0, true).unwrap();
        let err =
            admit_transform_run(&gate, &ctx, &tenant_only(&limits), "run-2", 0, false).unwrap_err();
        assert!(matches!(
            err,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_REQUESTS
        ));
    }

    #[test]
    fn configured_limits_skip_a_sekai_plane_without_budget_tables() {
        let sqlite =
            SekaiDb::new_for_plane(":memory:", sekai_core::db::schema_plane::SchemaPlane::Sekai)
                .unwrap();
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(sqlite));
        assert_eq!(configured_limits(&db, "tenant-a").unwrap(), None);
    }

    #[test]
    fn record_usage_on_a_sekai_plane_without_ledger_is_a_noop() {
        let sqlite =
            SekaiDb::new_for_plane(":memory:", sekai_core::db::schema_plane::SchemaPlane::Sekai)
                .unwrap();
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(sqlite));
        let events = record_transform_usage(&db, "tenant-a", &run("run-1"), "local", 20).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn a_budget_store_outage_refuses_instead_of_dropping_the_quota() {
        // #2607: an error that merely mentions "unavailable" used to read as
        // "no quota configured", so a database fault ran transforms unmetered.
        let error = "connection pool unavailable: timed out".to_string();
        assert_eq!(budget_rows(Err(error.clone())), Err(error));
        let missing = "no such table: chisei_budget_limits".to_string();
        assert_eq!(budget_rows(Err(missing)), Ok(None));
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
