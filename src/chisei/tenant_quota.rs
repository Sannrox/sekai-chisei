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

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::chisei::budget::{BudgetTracker, PeriodType};
use crate::db::chisei_budget::{METRIC_REQUESTS, METRIC_TOKENS};
use crate::db::runtime_db::RuntimeDb;
use crate::enterprise::AuthenticatedContext;

/// In-flight concurrency units reserved while a tenant operation is active.
pub const METRIC_CONCURRENCY: &str = "concurrency";
/// Retained storage units (bytes) attributed to a tenant.
pub const METRIC_STORAGE_BYTES: &str = "storage_bytes";

/// Versioned, operator-configured tenant limits (not a commercial plan catalog).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantQuotaLimits {
    /// Monotonic assignment version from enterprise/operator control.
    pub version: u64,
    pub max_requests_per_period: Option<i32>,
    pub max_tokens_per_period: Option<i32>,
    pub max_concurrency: Option<i32>,
    pub max_storage_bytes: Option<i64>,
    pub period: PeriodType,
}

impl TenantQuotaLimits {
    pub fn unlimited(version: u64) -> Self {
        Self {
            version,
            max_requests_per_period: None,
            max_tokens_per_period: None,
            max_concurrency: None,
            max_storage_bytes: None,
            period: PeriodType::Daily,
        }
    }
}

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
            } => write!(
                f,
                "tenant quota exhausted for {metric}; retry_after={retry_after_hint}"
            ),
            Self::Storage(msg) => write!(f, "tenant quota storage error: {msg}"),
        }
    }
}

impl std::error::Error for TenantQuotaError {}

/// Canonical budget scope id for a tenant.
pub fn tenant_scope_id(tenant_id: &str) -> String {
    format!("tenant:{tenant_id}")
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
}

impl TenantQuotaGate {
    pub fn new(db: Arc<RuntimeDb>) -> Self {
        Self {
            tracker: BudgetTracker::new(db),
        }
    }

    /// Persist operator-configured limits for one tenant.
    pub fn configure(
        &self,
        tenant_id: &str,
        limits: &TenantQuotaLimits,
    ) -> Result<(), TenantQuotaError> {
        let scope = tenant_scope_id(tenant_id);
        if let Some(max) = limits.max_tokens_per_period {
            self.tracker
                .set_limit_with_metric(&scope, METRIC_TOKENS, max, limits.period)
                .map_err(TenantQuotaError::Storage)?;
        }
        if let Some(max) = limits.max_requests_per_period {
            self.tracker
                .set_limit_with_metric(&scope, METRIC_REQUESTS, max, limits.period)
                .map_err(TenantQuotaError::Storage)?;
        }
        if let Some(max) = limits.max_concurrency {
            // Concurrency uses a long period so units represent in-flight work;
            // release returns capacity immediately via adjust.
            self.tracker
                .set_limit_with_metric(&scope, METRIC_CONCURRENCY, max, PeriodType::Monthly)
                .map_err(TenantQuotaError::Storage)?;
        }
        if let Some(max) = limits.max_storage_bytes {
            let capped = i32::try_from(max.min(i64::from(i32::MAX))).unwrap_or(i32::MAX);
            self.tracker
                .set_limit_with_metric(&scope, METRIC_STORAGE_BYTES, capped, PeriodType::Monthly)
                .map_err(TenantQuotaError::Storage)?;
        }
        Ok(())
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
        let scope = tenant_scope_id(&tenant.tenant_id);
        let mut reserved = TenantQuotaAdmission {
            tenant_id: tenant.tenant_id.clone(),
            scope_id: scope.clone(),
            assignment_version: limits.version,
            reserved_tokens: 0,
            reserved_request: false,
            reserved_concurrency: false,
            idempotency_key: idempotency_key.to_string(),
        };

        if limits.max_requests_per_period.is_some() {
            self.tracker
                .check_and_reserve_with_metric(&scope, 1, METRIC_REQUESTS)
                .map_err(|_| exhausted(METRIC_REQUESTS))?;
            reserved.reserved_request = true;
        }
        if limits.max_tokens_per_period.is_some() && estimated_tokens > 0 {
            if let Err(err) =
                self.tracker
                    .check_and_reserve_idempotent(&scope, estimated_tokens, idempotency_key)
            {
                self.rollback_partial(&reserved);
                let _ = err;
                return Err(exhausted(METRIC_TOKENS));
            }
            reserved.reserved_tokens = estimated_tokens;
        }
        if limits.max_concurrency.is_some() {
            if let Err(err) =
                self.tracker
                    .check_and_reserve_with_metric(&scope, 1, METRIC_CONCURRENCY)
            {
                self.rollback_partial(&reserved);
                let _ = err;
                return Err(exhausted(METRIC_CONCURRENCY));
            }
            reserved.reserved_concurrency = true;
        }
        Ok(reserved)
    }

    /// Release concurrency and reconcile token reservation to actual usage.
    pub fn complete(
        &self,
        admission: &TenantQuotaAdmission,
        actual_tokens: i32,
    ) -> Result<TenantQuotaReceiptNote, TenantQuotaError> {
        if admission.reserved_tokens > 0 {
            self.tracker.adjust(
                &admission.scope_id,
                admission.reserved_tokens,
                actual_tokens.max(0),
            );
        }
        if admission.reserved_concurrency {
            // Return the in-flight unit.
            self.tracker
                .adjust_with_metric(&admission.scope_id, 1, 0, METRIC_CONCURRENCY);
        }
        Ok(TenantQuotaReceiptNote {
            tenant_id: admission.tenant_id.clone(),
            assignment_version: admission.assignment_version,
            admitted_metrics: admission.admitted_metric_names(),
            exhausted_metric: None,
        })
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
            .map_err(|_| exhausted(METRIC_STORAGE_BYTES))
    }

    fn rollback_partial(&self, admission: &TenantQuotaAdmission) {
        if admission.reserved_request {
            self.tracker
                .adjust_with_metric(&admission.scope_id, 1, 0, METRIC_REQUESTS);
        }
        if admission.reserved_tokens > 0 {
            self.tracker
                .adjust(&admission.scope_id, admission.reserved_tokens, 0);
        }
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
    pub reserved_concurrency: bool,
    pub idempotency_key: String,
}

impl TenantQuotaAdmission {
    fn admitted_metric_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if self.reserved_request {
            names.push(METRIC_REQUESTS.into());
        }
        if self.reserved_tokens > 0 {
            names.push(METRIC_TOKENS.into());
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

fn exhausted(metric: &str) -> TenantQuotaError {
    TenantQuotaError::Exhausted {
        metric: metric.into(),
        // Period budgets reset at period boundary; concurrency may free sooner.
        retry_after_hint: if metric == METRIC_CONCURRENCY {
            "when in-flight work completes".into()
        } else {
            "next period boundary".into()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enterprise::{AuthenticatedPrincipal, TenantContext};
    use crate::provider_credentials::tenant_context;

    fn gate() -> TenantQuotaGate {
        TenantQuotaGate::new(Arc::new(RuntimeDb::memory()))
    }

    fn limits(version: u64) -> TenantQuotaLimits {
        TenantQuotaLimits {
            version,
            max_requests_per_period: Some(2),
            max_tokens_per_period: Some(100),
            max_concurrency: Some(1),
            max_storage_bytes: Some(1_000),
            period: PeriodType::Daily,
        }
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
        let ctx = crate::enterprise::AuthenticatedContext::machine(AuthenticatedPrincipal {
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
    fn token_exhaustion_rolls_back_request_reservation() {
        let gate = gate();
        let lim = TenantQuotaLimits {
            max_requests_per_period: Some(1),
            max_tokens_per_period: Some(5),
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
}
