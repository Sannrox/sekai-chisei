//! Tenant resource quotas (#119).
//!
//! Enforces request rate, token, concurrency, and storage bounds per tenant
//! using the existing replica-safe budget tables under `tenant:{id}` scopes.
//! Commercial plans stay outside the control plane: operators (or enterprise
//! context) assign versioned limits; missing/stale assignments fail closed when
//! required.
//!
//! Quotas never override stricter project/namespace budgets (those remain on
//! the hierarchical chain). Tenant admission is an additional gate.
//!
//! A namespace assignment (#3044, ADR 0168) is stored under
//! `tenant:{id}/namespace:{ns}`, a child of the tenant scope on the budget
//! chain. [`TenantQuotaGate::admit_in_namespace`] reserves on that scope, so
//! the chain reserves on the tenant and the namespace or on neither, and the
//! stricter limit wins. A namespace concurrency limit is a second hold beside
//! the tenant's.
//!
//! A tenant's [`QuotaMode`] (ADR 0168 part 1c) is the `mode` column of its
//! budget limit rows. In `report_only` the gate still evaluates every metric,
//! reserves what fits, and returns each refusal or queue it would have made
//! as a [`QuotaBreach`] instead of refusing.

use serde::{Deserialize, Serialize};

use crate::chisei::budget::{BudgetTracker, PeriodType};
use crate::chisei_store::{ChiseiBudgetStore, ChiseiStore};
use sekai_core::db::chisei_budget::{METRIC_REQUESTS, METRIC_TOKENS};

/// Seconds of isolated-process compute per period (#3044, ADR 0168 part 2b).
/// A claim reserves the run's estimate; the finished run settles it to the
/// measured seconds.
pub const METRIC_COMPUTE_SECONDS: &str = "compute_seconds";
use sekai_core::enterprise::AuthenticatedContext;

/// In-flight concurrency units reserved while a tenant operation is active.
pub const METRIC_CONCURRENCY: &str = "concurrency";
/// How long an unreclaimed concurrency hold counts against the tenant.
pub(crate) const CONCURRENCY_HOLD_MS: i64 = 120_000;
/// Retained storage units (bytes) attributed to a tenant.
pub const METRIC_STORAGE_BYTES: &str = "storage_bytes";

/// Versioned, operator-configured tenant limits (not a commercial plan catalog).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantQuotaLimits {
    /// Monotonic assignment version from enterprise/operator control.
    pub version: u64,
    pub max_requests_per_period: Option<i32>,
    pub max_tokens_per_period: Option<i32>,
    /// Absent in an assignment an older plane serialized.
    #[serde(default)]
    pub max_compute_seconds_per_period: Option<i32>,
    pub max_concurrency: Option<i32>,
    pub max_storage_bytes: Option<i64>,
    pub period: PeriodType,
}

impl TenantQuotaLimits {
    /// Refuses a negative limit. Zero is a valid limit that admits nothing.
    pub fn validate(&self) -> Result<(), String> {
        let negative = [
            (METRIC_REQUESTS, self.max_requests_per_period.map(i64::from)),
            (METRIC_TOKENS, self.max_tokens_per_period.map(i64::from)),
            (
                METRIC_COMPUTE_SECONDS,
                self.max_compute_seconds_per_period.map(i64::from),
            ),
            (METRIC_CONCURRENCY, self.max_concurrency.map(i64::from)),
            (METRIC_STORAGE_BYTES, self.max_storage_bytes),
        ]
        .into_iter()
        .find(|(_, limit)| limit.is_some_and(|limit| limit < 0));
        match negative {
            Some((metric, _)) => Err(format!("quota limit for {metric} must not be negative")),
            None => Ok(()),
        }
    }

    pub fn unlimited(version: u64) -> Self {
        Self {
            version,
            max_requests_per_period: None,
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        }
    }
}

/// Whether a tenant's assignment refuses and queues work or only reports what
/// it would have done (#3044, ADR 0168 part 1c). It applies to the tenant and
/// all its namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum QuotaMode {
    #[default]
    Enforce,
    ReportOnly,
}

impl QuotaMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::ReportOnly => "report_only",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "enforce" => Ok(Self::Enforce),
            "report_only" => Ok(Self::ReportOnly),
            other => Err(format!(
                "quota mode must be enforce or report_only, not {other:?}"
            )),
        }
    }

    /// The mode the `mode` values of a scope's own limit rows assign. Only
    /// rows that all say `report_only` report; a row an older plane wrote
    /// (default `enforce`), an unknown value or no row at all enforces.
    pub fn from_stored(modes: &[String]) -> Self {
        let report_only =
            !modes.is_empty() && modes.iter().all(|mode| mode == Self::ReportOnly.as_str());
        if report_only {
            Self::ReportOnly
        } else {
            Self::Enforce
        }
    }
}

/// What enforcing would have done to work a report-only tenant admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuotaWould {
    Refuse,
    Queue,
}

impl QuotaWould {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::Queue => "queue",
        }
    }
}

/// One refusal or queue a report-only admission did not apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaBreach {
    /// `tenant:{id}` or `tenant:{id}/namespace:{ns}`.
    pub scope_id: String,
    pub metric: String,
    pub would: QuotaWould,
    /// The refusal code enforcing would store, or `concurrency` for a queue.
    pub reason: String,
}

/// Audit action of a report-only breach decision.
pub const QUOTA_REPORT_ONLY_ACTION: &str = "tenant_quota_report_only";

/// Stable exhaustion / retry outcomes for tenant quotas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantQuotaError {
    /// Authenticated tenant is required when quota enforcement is mandatory.
    TenantRequired,
    /// Assignment version is missing or older than the required floor.
    StaleAssignment {
        have: u64,
        need: u64,
    },
    Exhausted {
        metric: String,
        retry_after_hint: String,
        /// Budget scope whose limit refused: `tenant:{id}` or
        /// `tenant:{id}/namespace:{ns}`. A full concurrency limit queues the
        /// run in this scope (#3044, ADR 0168 part 3).
        scope_id: String,
    },
    Storage(String),
}

impl std::fmt::Display for TenantQuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TenantRequired => write!(f, "tenant quota requires authenticated tenant context"),
            Self::StaleAssignment { have, need } => {
                write!(
                    f,
                    "tenant quota assignment stale (have {have}, need {need})"
                )
            }
            Self::Exhausted {
                metric,
                retry_after_hint,
                ..
            } => write!(
                f,
                "tenant quota exhausted for {metric}; retry_after={retry_after_hint}"
            ),
            Self::Storage(msg) => write!(f, "tenant quota storage error: {msg}"),
        }
    }
}

/// Storage failure while abandoning an unused admission, plus the metrics
/// that still need refunding so a retry does not double-apply a committed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaAbandonError {
    pub error: TenantQuotaError,
    pub remaining: TenantQuotaAdmission,
}

impl std::error::Error for TenantQuotaError {}

/// Canonical budget scope id for a tenant.
pub fn tenant_scope_id(tenant_id: &str) -> String {
    format!("tenant:{tenant_id}")
}

/// A tenant plus one of its namespaces, as the budget scope
/// `tenant:{id}/namespace:{ns}`.
///
/// The budget chain splits scopes on `/`, so neither part may contain one:
/// a namespace `a/b` would otherwise inherit the limits assigned to `a`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceQuotaScope {
    scope_id: String,
}

/// Longest tenant id or namespace a namespace quota scope accepts.
pub const MAX_QUOTA_SCOPE_PART_BYTES: usize = 256;

impl NamespaceQuotaScope {
    pub fn new(tenant_id: &str, namespace: &str) -> Result<Self, String> {
        for (field, value) in [("tenant id", tenant_id), ("namespace", namespace)] {
            if value.is_empty()
                || value.len() > MAX_QUOTA_SCOPE_PART_BYTES
                || value.trim() != value
                || value.contains('/')
                || value.chars().any(char::is_control)
            {
                return Err(format!(
                    "quota {field} must be 1 to {MAX_QUOTA_SCOPE_PART_BYTES} bytes without \
                     '/', surrounding spaces or control characters"
                ));
            }
        }
        Ok(Self {
            scope_id: format!("{}/namespace:{namespace}", tenant_scope_id(tenant_id)),
        })
    }

    /// Budget scope id the assignment's limit rows are stored under.
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
}

/// The budget scope a stored hold refunds: `quota_scope` when it is a scope
/// under the tenant's, otherwise the tenant scope. A hold an older plane
/// wrote has no scope and refunds the tenant only.
pub fn hold_refund_scope(tenant_id: &str, quota_scope: &str) -> String {
    let tenant = tenant_scope_id(tenant_id);
    match quota_scope.strip_prefix(tenant.as_str()) {
        Some(rest) if rest.starts_with('/') => quota_scope.to_string(),
        _ => tenant,
    }
}

/// Fields safe to place on an operation receipt (no other-tenant usage).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TenantQuotaReceiptNote {
    pub tenant_id: String,
    pub assignment_version: u64,
    pub admitted_metrics: Vec<String>,
    pub exhausted_metric: Option<String>,
}

/// Tenant quota gate backed by shared budget state.
pub struct TenantQuotaGate {
    tracker: BudgetTracker,
    store: ChiseiStore,
}

impl TenantQuotaGate {
    pub fn new(db: impl Into<ChiseiStore>) -> Self {
        let store = db.into();
        Self {
            tracker: BudgetTracker::new(store.clone()),
            store,
        }
    }

    /// Persist operator-configured limits for one tenant.
    pub fn configure(
        &self,
        tenant_id: &str,
        limits: &TenantQuotaLimits,
    ) -> Result<(), TenantQuotaError> {
        self.configure_scope(&tenant_scope_id(tenant_id), limits)
    }

    /// Persist limits for one namespace of a tenant, enforced by
    /// [`Self::admit_in_namespace`].
    pub fn configure_namespace(
        &self,
        scope: &NamespaceQuotaScope,
        limits: &TenantQuotaLimits,
    ) -> Result<(), TenantQuotaError> {
        self.configure_scope(scope.scope_id(), limits)
    }

    fn configure_scope(
        &self,
        scope: &str,
        limits: &TenantQuotaLimits,
    ) -> Result<(), TenantQuotaError> {
        if let Some(max) = limits.max_tokens_per_period {
            self.tracker
                .set_limit_with_metric(scope, METRIC_TOKENS, max, limits.period)
                .map_err(TenantQuotaError::Storage)?;
        }
        if let Some(max) = limits.max_requests_per_period {
            self.tracker
                .set_limit_with_metric(scope, METRIC_REQUESTS, max, limits.period)
                .map_err(TenantQuotaError::Storage)?;
        }
        if let Some(max) = limits.max_compute_seconds_per_period {
            self.tracker
                .set_limit_with_metric(scope, METRIC_COMPUTE_SECONDS, max, limits.period)
                .map_err(TenantQuotaError::Storage)?;
        }
        if let Some(max) = limits.max_concurrency {
            // The monthly row is only the configured cap `configured_limits`
            // reads. Live units are holder-keyed holds, not budget consume.
            self.tracker
                .set_limit_with_metric(scope, METRIC_CONCURRENCY, max, PeriodType::Monthly)
                .map_err(TenantQuotaError::Storage)?;
        }
        if let Some(max) = limits.max_storage_bytes {
            let capped = i32::try_from(max.min(i64::from(i32::MAX))).unwrap_or(i32::MAX);
            self.tracker
                .set_limit_with_metric(scope, METRIC_STORAGE_BYTES, capped, PeriodType::Monthly)
                .map_err(TenantQuotaError::Storage)?;
        }
        Ok(())
    }

    /// Sets the mode of a tenant's stored assignment. False, and nothing
    /// stored, when the tenant has no limit rows: a mode needs an assignment
    /// to apply to. A limit row written later starts as `enforce`, which
    /// enforces the whole tenant, so set the mode again after adding a metric.
    pub fn configure_mode(
        &self,
        tenant_id: &str,
        mode: QuotaMode,
    ) -> Result<bool, TenantQuotaError> {
        self.store
            .budget_set_scope_mode(&tenant_scope_id(tenant_id), mode.as_str())
            .map(|updated| updated > 0)
            .map_err(TenantQuotaError::Storage)
    }

    /// The mode of a tenant's stored assignment.
    pub fn mode(&self, tenant_id: &str) -> Result<QuotaMode, TenantQuotaError> {
        self.store
            .budget_scope_modes(&tenant_scope_id(tenant_id))
            .map(|modes| QuotaMode::from_stored(&modes))
            .map_err(TenantQuotaError::Storage)
    }

    /// Records each breach a report-only admission of `run_key` did not
    /// apply as one audit decision. The id is the run key, scope, metric and
    /// reason, so a retried or reclaimed admission records each once.
    pub fn report_breaches(
        &self,
        tenant_id: &str,
        run_key: &str,
        breaches: &[QuotaBreach],
    ) -> Result<(), TenantQuotaError> {
        use crate::chisei_store::ChiseiDecisionStore;
        let now = wall_ms();
        let decisions: Vec<_> = breaches
            .iter()
            .map(|breach| sekai_core::sekai::audit::Decision {
                id: format!(
                    "{QUOTA_REPORT_ONLY_ACTION}:{run_key}:{}:{}:{}",
                    breach.scope_id, breach.metric, breach.reason
                ),
                timestamp: now,
                actor: "chisei-tenant-quota".into(),
                action: QUOTA_REPORT_ONLY_ACTION.into(),
                reason: format!(
                    "report-only quota would {} on {} in {}",
                    breach.would.as_str(),
                    breach.metric,
                    breach.scope_id
                ),
                evidence: [
                    ("tenant_id", tenant_id),
                    ("scope_id", breach.scope_id.as_str()),
                    ("metric", breach.metric.as_str()),
                    ("would", breach.would.as_str()),
                    ("reason", breach.reason.as_str()),
                    ("mode", QuotaMode::ReportOnly.as_str()),
                ]
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
                target_id: run_key.into(),
                outcome: "admitted".into(),
            })
            .collect();
        self.store
            .record_decisions_idempotently_by(&decisions, |existing, requested| {
                existing.id == requested.id
            })
            .map_err(TenantQuotaError::Storage)
    }

    /// Atomic multi-dimension admission for one tenant operation.
    ///
    /// Reserves request (1), estimated tokens, and one concurrency unit when
    /// those limits are configured. On any failure after partial reserve, rolls
    /// back reserved units for this attempt.
    pub fn admit(
        &self,
        context: &AuthenticatedContext,
        limits: &TenantQuotaLimits,
        min_assignment_version: u64,
        estimated_tokens: i32,
        idempotency_key: &str,
    ) -> Result<TenantQuotaAdmission, TenantQuotaError> {
        self.admit_in_namespace(
            context,
            limits,
            None,
            min_assignment_version,
            estimated_tokens,
            0,
            idempotency_key,
        )
    }

    /// [`Self::admit`] against the tenant and, when given, one of its
    /// namespaces (#3044, ADR 0168). Request and token budgets reserve on the
    /// namespace scope, so the budget chain reserves on both scopes or on
    /// neither. A namespace concurrency limit takes a second hold under the
    /// namespace scope, given back when the tenant's or its own is refused.
    /// `estimated_compute_seconds` reserves like the request does, without an
    /// idempotency key: each claim of a run is its own reservation.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_in_namespace(
        &self,
        context: &AuthenticatedContext,
        limits: &TenantQuotaLimits,
        namespace: Option<(&NamespaceQuotaScope, &TenantQuotaLimits)>,
        min_assignment_version: u64,
        estimated_tokens: i32,
        estimated_compute_seconds: i32,
        idempotency_key: &str,
    ) -> Result<TenantQuotaAdmission, TenantQuotaError> {
        let now = wall_ms();
        self.admit_at(
            context,
            limits,
            namespace,
            min_assignment_version,
            estimated_tokens,
            estimated_compute_seconds,
            idempotency_key,
            now..=now.saturating_add(CONCURRENCY_HOLD_MS),
        )
    }

    /// [`Self::admit_in_namespace`] for a report-only tenant: each metric
    /// that fits is reserved as enforcing would, and each that would refuse
    /// or queue reserves nothing and is returned as a breach. Only a missing
    /// tenant, a stale assignment or a storage error still fails.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_in_namespace_reporting(
        &self,
        context: &AuthenticatedContext,
        limits: &TenantQuotaLimits,
        namespace: Option<(&NamespaceQuotaScope, &TenantQuotaLimits)>,
        min_assignment_version: u64,
        estimated_tokens: i32,
        estimated_compute_seconds: i32,
        idempotency_key: &str,
    ) -> Result<(TenantQuotaAdmission, Vec<QuotaBreach>), TenantQuotaError> {
        let now = wall_ms();
        let mut breaches = Vec::new();
        self.admit_evaluating(
            context,
            limits,
            namespace,
            min_assignment_version,
            estimated_tokens,
            estimated_compute_seconds,
            idempotency_key,
            now..=now.saturating_add(CONCURRENCY_HOLD_MS),
            Some(&mut breaches),
        )
        .map(|admission| (admission, breaches))
    }

    /// Admit with an explicit hold window `[now, until]` so expiry is testable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_at(
        &self,
        context: &AuthenticatedContext,
        limits: &TenantQuotaLimits,
        namespace: Option<(&NamespaceQuotaScope, &TenantQuotaLimits)>,
        min_assignment_version: u64,
        estimated_tokens: i32,
        estimated_compute_seconds: i32,
        idempotency_key: &str,
        hold: std::ops::RangeInclusive<i64>,
    ) -> Result<TenantQuotaAdmission, TenantQuotaError> {
        self.admit_evaluating(
            context,
            limits,
            namespace,
            min_assignment_version,
            estimated_tokens,
            estimated_compute_seconds,
            idempotency_key,
            hold,
            None,
        )
    }

    /// Shared admission. With `report` set, a metric that does not fit is
    /// pushed there and skipped; without it, it rolls back and refuses.
    #[allow(clippy::too_many_arguments)]
    fn admit_evaluating(
        &self,
        context: &AuthenticatedContext,
        limits: &TenantQuotaLimits,
        namespace: Option<(&NamespaceQuotaScope, &TenantQuotaLimits)>,
        min_assignment_version: u64,
        estimated_tokens: i32,
        estimated_compute_seconds: i32,
        idempotency_key: &str,
        hold: std::ops::RangeInclusive<i64>,
        mut report: Option<&mut Vec<QuotaBreach>>,
    ) -> Result<TenantQuotaAdmission, TenantQuotaError> {
        let now_ms = *hold.start();
        let until_ms = *hold.end();
        let tenant = context
            .tenant
            .as_ref()
            .ok_or(TenantQuotaError::TenantRequired)?;
        if limits.version < min_assignment_version {
            return Err(TenantQuotaError::StaleAssignment {
                have: limits.version,
                need: min_assignment_version,
            });
        }
        let scope = match namespace {
            Some((namespace, _)) => namespace.scope_id().to_string(),
            None => tenant_scope_id(&tenant.tenant_id),
        };
        let own = namespace.map(|(_, limits)| limits);
        let either = |pick: fn(&TenantQuotaLimits) -> bool| pick(limits) || own.is_some_and(pick);
        let mut reserved = TenantQuotaAdmission {
            tenant_id: tenant.tenant_id.clone(),
            scope_id: scope.clone(),
            assignment_version: limits.version,
            reserved_tokens: 0,
            reserved_request: false,
            reserved_compute_seconds: 0,
            reserved_concurrency: false,
            idempotency_key: idempotency_key.to_string(),
            concurrency_holder: String::new(),
        };

        if either(|limits| limits.max_requests_per_period.is_some()) {
            match self
                .tracker
                .check_and_reserve_with_metric(&scope, 1, METRIC_REQUESTS)
            {
                Ok(()) => reserved.reserved_request = true,
                Err(error) => self.refuse_or_report(
                    &reserved,
                    &error,
                    exhausted(METRIC_REQUESTS, &scope),
                    report.as_deref_mut(),
                )?,
            }
        }
        if either(|limits| limits.max_tokens_per_period.is_some()) && estimated_tokens > 0 {
            match self.tracker.check_and_reserve_idempotent(
                &scope,
                estimated_tokens,
                idempotency_key,
            ) {
                Ok(()) => reserved.reserved_tokens = estimated_tokens,
                Err(error) => self.refuse_or_report(
                    &reserved,
                    &error,
                    exhausted(METRIC_TOKENS, &scope),
                    report.as_deref_mut(),
                )?,
            }
        }
        if either(|limits| limits.max_compute_seconds_per_period.is_some())
            && estimated_compute_seconds > 0
        {
            match self.tracker.check_and_reserve_with_metric(
                &scope,
                estimated_compute_seconds,
                METRIC_COMPUTE_SECONDS,
            ) {
                Ok(()) => reserved.reserved_compute_seconds = estimated_compute_seconds,
                Err(error) => self.refuse_or_report(
                    &reserved,
                    &error,
                    exhausted(METRIC_COMPUTE_SECONDS, &scope),
                    report.as_deref_mut(),
                )?,
            }
        }
        // The tenant's hold first, then the namespace's, under one holder.
        let tenant_scope = tenant_scope_id(&tenant.tenant_id);
        let holds = [
            (
                tenant.tenant_id.as_str(),
                tenant_scope.as_str(),
                limits.max_concurrency,
            ),
            (
                reserved.scope_id.as_str(),
                reserved.scope_id.as_str(),
                own.and_then(|limits| limits.max_concurrency),
            ),
        ];
        let holder = uuid::Uuid::new_v4().to_string();
        for (key, queue_scope, max) in holds {
            let Some(max) = max else { continue };
            let taken = self.store.take_tenant_concurrency_hold(
                key,
                idempotency_key,
                &holder,
                max,
                now_ms,
                until_ms,
            );
            if matches!(taken, Ok(false))
                && let Some(report) = report.as_deref_mut()
            {
                report.push(QuotaBreach {
                    scope_id: queue_scope.to_string(),
                    metric: METRIC_CONCURRENCY.into(),
                    would: QuotaWould::Queue,
                    reason: METRIC_CONCURRENCY.into(),
                });
                continue;
            }
            if !matches!(taken, Ok(true)) {
                if reserved.reserved_concurrency {
                    let _ = self.release_concurrency(&reserved);
                }
                let _ = self.rollback_partial(&reserved);
                return Err(match taken {
                    Err(err) => TenantQuotaError::Storage(err),
                    _ => exhausted(METRIC_CONCURRENCY, queue_scope),
                });
            }
            reserved.reserved_concurrency = true;
            reserved.concurrency_holder = holder.clone();
        }
        Ok(reserved)
    }

    /// Handles a reservation that failed with `store_error`. Without
    /// `report`, rolls back what `reserved` holds and refuses with
    /// `exhausted`, as enforcing always has. With it, a spent budget is
    /// recorded as a would-be refusal in the scope the store names, which on
    /// a namespace's chain may be its tenant, and admission goes on; a
    /// storage failure still rolls back and fails, so nothing runs
    /// unaccounted.
    fn refuse_or_report(
        &self,
        reserved: &TenantQuotaAdmission,
        store_error: &str,
        exhausted: TenantQuotaError,
        report: Option<&mut Vec<QuotaBreach>>,
    ) -> Result<(), TenantQuotaError> {
        let error = match (report, exhausted) {
            (Some(report), TenantQuotaError::Exhausted { metric, .. })
                if let Some(scope_id) =
                    crate::chisei::budget::budget_exceeded_scope(store_error) =>
            {
                report.push(QuotaBreach {
                    scope_id: scope_id.to_string(),
                    metric,
                    would: QuotaWould::Refuse,
                    reason: REFUSAL_BUDGET_EXHAUSTED.into(),
                });
                return Ok(());
            }
            (Some(_), _) => TenantQuotaError::Storage(store_error.to_string()),
            (None, exhausted) => exhausted,
        };
        let _ = self.rollback_partial(reserved);
        Err(error)
    }

    /// Gives back the tenant's concurrency hold and, for a namespace
    /// admission, the namespace's. A hold that is not there is a no-op.
    fn release_concurrency(&self, admission: &TenantQuotaAdmission) -> Result<(), String> {
        for key in admission.concurrency_hold_keys() {
            self.store.release_tenant_concurrency_hold(
                key,
                &admission.idempotency_key,
                &admission.concurrency_holder,
            )?;
        }
        Ok(())
    }

    /// Extends a live concurrency hold. False when another holder has it or
    /// it has already expired.
    pub fn renew_concurrency(
        &self,
        admission: &TenantQuotaAdmission,
        now_ms: i64,
    ) -> Result<bool, TenantQuotaError> {
        if !admission.reserved_concurrency {
            return Ok(true);
        }
        // True while this holder still has at least one of its holds; a
        // namespace admission without a tenant limit holds only the second.
        let mut renewed = false;
        for key in admission.concurrency_hold_keys() {
            renewed |= self
                .store
                .renew_tenant_concurrency_hold(
                    key,
                    &admission.idempotency_key,
                    &admission.concurrency_holder,
                    now_ms,
                    now_ms.saturating_add(CONCURRENCY_HOLD_MS),
                )
                .map_err(TenantQuotaError::Storage)?;
        }
        Ok(renewed)
    }

    /// Drop a reservation when the admitted work did not run.
    ///
    /// Refunds request, tokens, compute seconds, then concurrency. On a storage error the
    /// returned admission still includes the metric that failed and any that
    /// were not attempted, so a retry does not refund a metric twice.
    pub fn abandon(&self, admission: &TenantQuotaAdmission) -> Result<(), Box<QuotaAbandonError>> {
        let mut remaining = admission.clone();
        if remaining.reserved_request {
            if let Err(error) =
                self.tracker
                    .try_adjust_with_metric(&remaining.scope_id, 1, 0, METRIC_REQUESTS)
            {
                return Err(Box::new(QuotaAbandonError {
                    error: TenantQuotaError::Storage(error),
                    remaining,
                }));
            }
            remaining.reserved_request = false;
        }
        if remaining.reserved_tokens > 0 {
            if let Err(error) = self.tracker.try_adjust_with_metric(
                &remaining.scope_id,
                remaining.reserved_tokens,
                0,
                METRIC_TOKENS,
            ) {
                return Err(Box::new(QuotaAbandonError {
                    error: TenantQuotaError::Storage(error),
                    remaining,
                }));
            }
            remaining.reserved_tokens = 0;
        }
        if remaining.reserved_compute_seconds > 0 {
            if let Err(error) = self.settle_compute(&remaining, 0) {
                return Err(Box::new(QuotaAbandonError { error, remaining }));
            }
            remaining.reserved_compute_seconds = 0;
        }
        if remaining.reserved_concurrency {
            if let Err(error) = self.release_concurrency(&remaining) {
                return Err(Box::new(QuotaAbandonError {
                    error: TenantQuotaError::Storage(error),
                    remaining,
                }));
            }
            remaining.reserved_concurrency = false;
        }
        Ok(())
    }

    /// Release concurrency and reconcile token reservation to actual usage.
    pub fn complete(
        &self,
        admission: &TenantQuotaAdmission,
        actual_tokens: i32,
    ) -> Result<TenantQuotaReceiptNote, TenantQuotaError> {
        if admission.reserved_tokens > 0 {
            self.tracker
                .try_adjust_with_metric(
                    &admission.scope_id,
                    admission.reserved_tokens,
                    actual_tokens.max(0),
                    METRIC_TOKENS,
                )
                .map_err(TenantQuotaError::Storage)?;
        }
        if admission.reserved_concurrency {
            // Holder-matched release. A missing row is a no-op so a second
            // complete cannot free another unit. Storage errors surface; the
            // row stays until expiry.
            self.release_concurrency(admission)
                .map_err(TenantQuotaError::Storage)?;
        }
        Ok(TenantQuotaReceiptNote {
            tenant_id: admission.tenant_id.clone(),
            assignment_version: admission.assignment_version,
            admitted_metrics: admission.admitted_metric_names(),
            exhausted_metric: None,
        })
    }

    /// Reconciles the compute seconds an admission reserved to `actual`, and
    /// refunds them when `actual` is zero. The caller clears
    /// `reserved_compute_seconds` once this returns, so a retry cannot
    /// adjust twice.
    pub fn settle_compute(
        &self,
        admission: &TenantQuotaAdmission,
        actual: i32,
    ) -> Result<(), TenantQuotaError> {
        if admission.reserved_compute_seconds <= 0 {
            return Ok(());
        }
        self.tracker
            .try_adjust_with_metric(
                &admission.scope_id,
                admission.reserved_compute_seconds,
                actual.max(0),
                METRIC_COMPUTE_SECONDS,
            )
            .map_err(TenantQuotaError::Storage)
    }

    /// Charge storage growth against the tenant storage quota.
    pub fn charge_storage(
        &self,
        tenant_id: &str,
        limits: &TenantQuotaLimits,
        bytes: i32,
    ) -> Result<(), TenantQuotaError> {
        if limits.max_storage_bytes.is_none() || bytes <= 0 {
            return Ok(());
        }
        let scope = tenant_scope_id(tenant_id);
        self.tracker
            .check_and_reserve_with_metric(&scope, bytes, METRIC_STORAGE_BYTES)
            .map_err(|_| exhausted(METRIC_STORAGE_BYTES, &scope))
    }

    fn rollback_partial(&self, admission: &TenantQuotaAdmission) -> Result<(), TenantQuotaError> {
        if admission.reserved_request {
            self.tracker
                .try_adjust_with_metric(&admission.scope_id, 1, 0, METRIC_REQUESTS)
                .map_err(TenantQuotaError::Storage)?;
        }
        if admission.reserved_tokens > 0 {
            self.tracker
                .try_adjust_with_metric(
                    &admission.scope_id,
                    admission.reserved_tokens,
                    0,
                    METRIC_TOKENS,
                )
                .map_err(TenantQuotaError::Storage)?;
        }
        self.settle_compute(admission, 0)
    }
}

/// Held reservation from a successful [`TenantQuotaGate::admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantQuotaAdmission {
    pub tenant_id: String,
    pub scope_id: String,
    pub assignment_version: u64,
    pub reserved_tokens: i32,
    pub reserved_request: bool,
    /// Compute seconds reserved and not yet settled.
    pub reserved_compute_seconds: i32,
    pub reserved_concurrency: bool,
    pub idempotency_key: String,
    /// Process that took the concurrency hold. Empty on reconstructed
    /// admissions so a successor can delete the key after a crash.
    pub concurrency_holder: String,
}

impl TenantQuotaAdmission {
    /// The admission a stored hold stands for after its process is gone: it
    /// reserves nothing until the caller marks what the hold still owns, and
    /// its empty holder lets a successor drop the concurrency holds by key.
    pub fn from_hold(tenant_id: &str, quota_scope: &str, idempotency_key: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            scope_id: hold_refund_scope(tenant_id, quota_scope),
            assignment_version: 1,
            reserved_tokens: 0,
            reserved_request: false,
            reserved_compute_seconds: 0,
            reserved_concurrency: false,
            idempotency_key: idempotency_key.to_string(),
            concurrency_holder: String::new(),
        }
    }

    /// Keys of the concurrency holds this admission may own: the tenant, then
    /// the namespace scope when it reserved on one.
    fn concurrency_hold_keys(&self) -> impl Iterator<Item = &str> {
        let namespace =
            (self.scope_id != tenant_scope_id(&self.tenant_id)).then_some(self.scope_id.as_str());
        std::iter::once(self.tenant_id.as_str()).chain(namespace)
    }

    fn admitted_metric_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if self.reserved_request {
            names.push(METRIC_REQUESTS.into());
        }
        if self.reserved_tokens > 0 {
            names.push(METRIC_TOKENS.into());
        }
        if self.reserved_compute_seconds > 0 {
            names.push(METRIC_COMPUTE_SECONDS.into());
        }
        if self.reserved_concurrency {
            names.push(METRIC_CONCURRENCY.into());
        }
        names
    }

    pub fn receipt_note(&self) -> TenantQuotaReceiptNote {
        TenantQuotaReceiptNote {
            tenant_id: self.tenant_id.clone(),
            assignment_version: self.assignment_version,
            admitted_metrics: self.admitted_metric_names(),
            exhausted_metric: None,
        }
    }
}

/// Refusal code for a run whose tenant or namespace budget is spent (#3044,
/// ADR 0168): budgets refuse, only concurrency waits.
pub const REFUSAL_BUDGET_EXHAUSTED: &str = "quota_budget_exhausted";

fn exhausted(metric: &str, scope_id: &str) -> TenantQuotaError {
    TenantQuotaError::Exhausted {
        metric: metric.into(),
        scope_id: scope_id.into(),
        // Period budgets reset at period boundary; concurrency may free sooner.
        retry_after_hint: if metric == METRIC_CONCURRENCY {
            "when in-flight work completes or its hold expires".into()
        } else {
            "next period boundary".into()
        },
    }
}

fn wall_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant_context;
    use sekai_core::enterprise::{AuthenticatedPrincipal, TenantContext};

    fn gate() -> TenantQuotaGate {
        TenantQuotaGate::new(ChiseiStore::memory())
    }

    fn limits(version: u64) -> TenantQuotaLimits {
        TenantQuotaLimits {
            version,
            max_requests_per_period: Some(2),
            max_tokens_per_period: Some(100),
            max_compute_seconds_per_period: None,
            max_concurrency: Some(1),
            max_storage_bytes: Some(1_000),
            period: PeriodType::Daily,
        }
    }

    #[test]
    fn a_hold_refunds_the_scope_it_names_only_under_its_own_tenant() {
        let ops = "tenant:tenant-a/namespace:ops";
        assert_eq!(hold_refund_scope("tenant-a", ops), ops);
        for other in [
            "",
            "tenant:tenant-b/namespace:ops",
            "tenant:tenant-ab/namespace:ops",
            "tenant:tenant-a",
            "garbage",
        ] {
            assert_eq!(
                hold_refund_scope("tenant-a", other),
                "tenant:tenant-a",
                "{other}"
            );
        }
    }

    #[test]
    fn a_namespace_scope_is_a_child_of_its_tenant_on_the_budget_chain() {
        let scope = NamespaceQuotaScope::new("tenant-a", "ops").unwrap();
        assert_eq!(scope.scope_id(), "tenant:tenant-a/namespace:ops");
        assert!(
            sekai_core::db::chisei_budget::scope_chain(scope.scope_id())
                .contains(&tenant_scope_id("tenant-a"))
        );
        for (tenant, namespace) in [
            ("tenant-a", "ops/prod"),
            ("tenant/a", "ops"),
            ("tenant-a", ""),
            ("tenant-a", " ops"),
            ("tenant-a", "op\ns"),
        ] {
            assert!(
                NamespaceQuotaScope::new(tenant, namespace).is_err(),
                "{tenant:?} {namespace:?} must be refused"
            );
        }
        let long = "n".repeat(MAX_QUOTA_SCOPE_PART_BYTES + 1);
        assert!(NamespaceQuotaScope::new("tenant-a", &long).is_err());
    }

    #[test]
    fn a_negative_limit_is_invalid_and_zero_is_not() {
        let negative = TenantQuotaLimits {
            max_concurrency: Some(-1),
            ..limits(1)
        };
        assert!(
            negative
                .validate()
                .unwrap_err()
                .contains(METRIC_CONCURRENCY)
        );
        let zero = TenantQuotaLimits {
            max_requests_per_period: Some(0),
            ..limits(1)
        };
        zero.validate().unwrap();
    }

    #[test]
    fn tenants_are_isolated_on_exhaustion() {
        let gate = gate();
        let lim = TenantQuotaLimits {
            max_concurrency: Some(8), // focus this case on request isolation
            ..limits(1)
        };
        gate.configure("tenant-a", &lim).unwrap();
        gate.configure("tenant-b", &lim).unwrap();

        let a = tenant_context("tenant-a", "alice");
        let b = tenant_context("tenant-b", "bob");
        let a1 = gate.admit(&a, &lim, 1, 10, "a-1").unwrap();
        gate.complete(&a1, 10).unwrap();
        let a2 = gate.admit(&a, &lim, 1, 10, "a-2").unwrap();
        gate.complete(&a2, 10).unwrap();
        let err = gate.admit(&a, &lim, 1, 10, "a-3").unwrap_err();
        assert!(matches!(
            err,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_REQUESTS
        ));
        // Tenant B remains healthy.
        assert!(gate.admit(&b, &lim, 1, 10, "b-1").is_ok());
    }

    #[test]
    fn concurrency_releases_capacity() {
        let gate = gate();
        let lim = limits(1);
        gate.configure("tenant-a", &lim).unwrap();
        let a = tenant_context("tenant-a", "alice");
        let adm = gate.admit(&a, &lim, 1, 5, "c-1").unwrap();
        assert!(
            gate.admit(&a, &lim, 1, 5, "c-2").is_err(),
            "second concurrent admit must fail"
        );
        gate.complete(&adm, 5).unwrap();
        assert!(
            gate.admit(&a, &lim, 1, 5, "c-3").is_ok(),
            "after release concurrency must free"
        );
    }

    #[test]
    fn abandon_refunds_a_request_that_did_not_run() {
        let gate = gate();
        let lim = TenantQuotaLimits {
            max_requests_per_period: Some(1),
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            ..limits(1)
        };
        gate.configure("tenant-a", &lim).unwrap();
        let a = tenant_context("tenant-a", "alice");
        let held = gate.admit(&a, &lim, 1, 0, "tick-1").unwrap();
        gate.abandon(&held).unwrap();
        assert!(
            gate.admit(&a, &lim, 1, 0, "tick-2").is_ok(),
            "abandoned request reservation must free the period slot"
        );
    }

    #[test]
    fn stale_assignment_fails_closed() {
        let gate = gate();
        let lim = limits(1);
        gate.configure("tenant-a", &lim).unwrap();
        let a = tenant_context("tenant-a", "alice");
        let err = gate.admit(&a, &lim, 5, 1, "s-1").unwrap_err();
        assert!(matches!(
            err,
            TenantQuotaError::StaleAssignment { have: 1, need: 5 }
        ));
    }

    #[test]
    fn unscoped_context_requires_tenant() {
        let gate = gate();
        let lim = limits(1);
        let ctx = sekai_core::enterprise::AuthenticatedContext::machine(AuthenticatedPrincipal {
            subject: "machine".into(),
            credential_id: "m1".into(),
        });
        assert!(matches!(
            gate.admit(&ctx, &lim, 1, 1, "u-1"),
            Err(TenantQuotaError::TenantRequired)
        ));
        // Ensure TenantContext field shape stays used.
        let _ = TenantContext {
            tenant_id: "x".into(),
            subject: "y".into(),
        };
    }

    #[test]
    fn storage_charge_exhausts_independently() {
        let gate = gate();
        let lim = limits(1);
        gate.configure("tenant-a", &lim).unwrap();
        gate.charge_storage("tenant-a", &lim, 600).unwrap();
        let err = gate.charge_storage("tenant-a", &lim, 500).unwrap_err();
        assert!(matches!(
            err,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_STORAGE_BYTES
        ));
    }

    fn gate_on_file(path: &str) -> TenantQuotaGate {
        TenantQuotaGate::new(ChiseiStore::open_sqlite(path))
    }

    fn drop_budget_usage(path: &str) {
        rusqlite::Connection::open(path)
            .unwrap()
            .execute_batch("DROP TABLE chisei_budget_usage")
            .unwrap();
    }

    fn drop_concurrency_holds(path: &str) {
        rusqlite::Connection::open(path)
            .unwrap()
            .execute_batch("DROP TABLE chisei_tenant_concurrency_holds")
            .unwrap();
    }

    #[test]
    fn complete_reports_storage_when_concurrency_release_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quota.db");
        let path = path.to_str().unwrap();
        let gate = gate_on_file(path);
        let lim = TenantQuotaLimits {
            max_requests_per_period: None,
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: Some(1),
            max_storage_bytes: None,
            ..limits(1)
        };
        gate.configure("tenant-a", &lim).unwrap();
        let admission = gate
            .admit(&tenant_context("tenant-a", "alice"), &lim, 1, 0, "run-1")
            .unwrap();
        drop_concurrency_holds(path);
        let err = gate.complete(&admission, 0).unwrap_err();
        assert!(
            matches!(err, TenantQuotaError::Storage(ref message) if message.contains("chisei_tenant_concurrency_holds")),
            "{err}"
        );
    }

    #[test]
    fn abandon_reports_storage_when_concurrency_release_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quota.db");
        let path = path.to_str().unwrap();
        let gate = gate_on_file(path);
        let lim = TenantQuotaLimits {
            max_requests_per_period: None,
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: Some(1),
            max_storage_bytes: None,
            ..limits(1)
        };
        gate.configure("tenant-a", &lim).unwrap();
        let admission = gate
            .admit(&tenant_context("tenant-a", "alice"), &lim, 1, 0, "run-1")
            .unwrap();
        drop_concurrency_holds(path);
        let err = gate.abandon(&admission).unwrap_err();
        assert!(
            matches!(err.error, TenantQuotaError::Storage(ref message) if message.contains("chisei_tenant_concurrency_holds")),
            "{}",
            err.error
        );
        assert!(err.remaining.reserved_concurrency);
        assert!(!err.remaining.reserved_request);
    }

    #[test]
    fn abandon_reports_storage_when_request_refund_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quota.db");
        let path = path.to_str().unwrap();
        let gate = gate_on_file(path);
        let lim = TenantQuotaLimits {
            max_requests_per_period: Some(1),
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            ..limits(1)
        };
        gate.configure("tenant-a", &lim).unwrap();
        let admission = gate
            .admit(&tenant_context("tenant-a", "alice"), &lim, 1, 0, "run-1")
            .unwrap();
        drop_budget_usage(path);
        let err = gate.abandon(&admission).unwrap_err();
        assert!(
            matches!(err.error, TenantQuotaError::Storage(ref message) if message.contains("chisei_budget_usage")),
            "{}",
            err.error
        );
        assert!(err.remaining.reserved_request);
        assert!(!err.remaining.reserved_concurrency);
    }

    #[test]
    fn receipt_note_exposes_only_own_tenant() {
        let gate = gate();
        let lim = limits(3);
        gate.configure("tenant-a", &lim).unwrap();
        let a = tenant_context("tenant-a", "alice");
        let adm = gate.admit(&a, &lim, 1, 10, "r-1").unwrap();
        let note = adm.receipt_note();
        assert_eq!(note.tenant_id, "tenant-a");
        assert_eq!(note.assignment_version, 3);
        assert!(note.exhausted_metric.is_none());
        assert!(note.admitted_metrics.contains(&METRIC_REQUESTS.into()));
    }

    #[test]
    fn compute_seconds_reserve_settle_to_actual_and_refund_on_abandon() {
        let gate = gate();
        let lim = TenantQuotaLimits {
            max_compute_seconds_per_period: Some(60),
            ..TenantQuotaLimits::unlimited(1)
        };
        gate.configure("tenant-a", &lim).unwrap();
        let ctx = tenant_context("tenant-a", "alice");
        let admit = |key: &str| gate.admit_in_namespace(&ctx, &lim, None, 1, 0, 30, key);
        let first = admit("run-1").unwrap();
        assert_eq!(first.reserved_compute_seconds, 30);
        let second = admit("run-2").unwrap();
        assert!(matches!(
            admit("run-3").unwrap_err(),
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_COMPUTE_SECONDS
        ));
        // Settling to 5 measured seconds frees 25, not enough for a third 30.
        gate.settle_compute(&first, 5).unwrap();
        assert!(admit("run-3").is_err());
        // Abandoning the second run refunds all 30 of its seconds.
        gate.abandon(&second).unwrap();
        admit("run-3").unwrap();
    }

    #[test]
    fn token_exhaustion_rolls_back_request_reservation() {
        let gate = gate();
        let lim = TenantQuotaLimits {
            max_requests_per_period: Some(1),
            max_tokens_per_period: Some(5),
            max_compute_seconds_per_period: None,
            max_concurrency: None,
            ..limits(1)
        };
        gate.configure("tenant-a", &lim).unwrap();
        let a = tenant_context("tenant-a", "alice");

        let err = gate.admit(&a, &lim, 1, 10, "tok-over").unwrap_err();
        assert!(matches!(
            err,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_TOKENS
        ));

        // Without rollback, the failed admit would consume the only request unit
        // and this subsequent in-budget admit would fail as METRIC_REQUESTS.
        let admitted = gate.admit(&a, &lim, 1, 5, "tok-ok").unwrap();
        gate.complete(&admitted, 5).unwrap();
    }

    fn concurrency_only() -> TenantQuotaLimits {
        TenantQuotaLimits {
            max_requests_per_period: None,
            max_tokens_per_period: None,
            max_compute_seconds_per_period: None,
            max_concurrency: Some(1),
            max_storage_bytes: None,
            ..limits(1)
        }
    }

    #[test]
    fn expired_concurrency_hold_stops_counting_without_complete() {
        let gate = gate();
        let lim = concurrency_only();
        gate.configure("tenant-a", &lim).unwrap();
        let a = tenant_context("tenant-a", "alice");
        gate.admit_at(&a, &lim, None, 1, 0, 0, "run-1", 0..=10)
            .unwrap();
        let blocked = gate
            .admit_at(&a, &lim, None, 1, 0, 0, "run-2", 5..=15)
            .unwrap_err();
        assert!(matches!(
            blocked,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_CONCURRENCY
        ));
        gate.admit_at(&a, &lim, None, 1, 0, 0, "run-3", 11..=21)
            .expect("expired hold must free the slot");
    }

    #[test]
    fn renewed_concurrency_hold_still_blocks_a_second_admit() {
        let gate = gate();
        let lim = concurrency_only();
        gate.configure("tenant-a", &lim).unwrap();
        let a = tenant_context("tenant-a", "alice");
        let held = gate
            .admit_at(&a, &lim, None, 1, 0, 0, "run-1", 0..=10)
            .unwrap();
        assert!(
            gate.renew_concurrency(&held, 9).unwrap(),
            "live holder must extend the hold"
        );
        let blocked = gate
            .admit_at(&a, &lim, None, 1, 0, 0, "run-2", 11..=21)
            .unwrap_err();
        assert!(matches!(
            blocked,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_CONCURRENCY
        ));
    }

    #[test]
    fn restarted_process_reclaims_an_expired_hold_and_double_release_is_one_unit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("quota.db");
        let path = path.to_str().unwrap();
        let lim = concurrency_only();
        let a = tenant_context("tenant-a", "alice");
        {
            let first = gate_on_file(path);
            first.configure("tenant-a", &lim).unwrap();
            first
                .admit_at(&a, &lim, None, 1, 0, 0, "run-crashed", 0..=10)
                .unwrap();
        }
        let second = gate_on_file(path);
        second
            .admit_at(&a, &lim, None, 1, 0, 0, "run-next", 11..=21)
            .expect("a new process must reclaim the expired hold");
        let still_blocked = second
            .admit_at(&a, &lim, None, 1, 0, 0, "run-extra", 12..=22)
            .unwrap_err();
        assert!(matches!(
            still_blocked,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_CONCURRENCY
        ));

        let held = TenantQuotaAdmission {
            tenant_id: "tenant-a".into(),
            scope_id: tenant_scope_id("tenant-a"),
            assignment_version: 1,
            reserved_tokens: 0,
            reserved_request: false,
            reserved_compute_seconds: 0,
            reserved_concurrency: true,
            idempotency_key: "run-next".into(),
            concurrency_holder: String::new(),
        };
        second.complete(&held, 0).unwrap();
        second.complete(&held, 0).unwrap();
        second
            .admit_at(&a, &lim, None, 1, 0, 0, "run-after-double", 13..=23)
            .expect("one complete frees one unit");
        let over = second
            .admit_at(&a, &lim, None, 1, 0, 0, "run-over", 14..=24)
            .unwrap_err();
        assert!(
            matches!(
                over,
                TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_CONCURRENCY
            ),
            "double complete must not free a second unit"
        );
    }

    #[test]
    fn stale_holder_complete_does_not_free_a_reclaimed_key() {
        let gate = gate();
        let lim = concurrency_only();
        gate.configure("tenant-a", &lim).unwrap();
        let a = tenant_context("tenant-a", "alice");
        let stale = gate
            .admit_at(&a, &lim, None, 1, 0, 0, "run-1", 0..=10)
            .unwrap();
        let live = gate
            .admit_at(&a, &lim, None, 1, 0, 0, "run-1", 11..=21)
            .expect("expired same key is reclaimable");
        gate.complete(&stale, 0).unwrap();
        let blocked = gate
            .admit_at(&a, &lim, None, 1, 0, 0, "run-2", 12..=22)
            .unwrap_err();
        assert!(matches!(
            blocked,
            TenantQuotaError::Exhausted { metric, .. } if metric == METRIC_CONCURRENCY
        ));
        gate.complete(&live, 0).unwrap();
        gate.admit_at(&a, &lim, None, 1, 0, 0, "run-2", 13..=23)
            .expect("the live holder still owned the slot");
    }
}
