//! Tenant entitlement enforcement contract (#123).
//!
//! Versioned entitlement sets from the enterprise authority. Entitlements may
//! only narrow access/limits; they never widen governance, grants, egress,
//! approvals, budgets, or quotas beyond an explicit assignment.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::chisei::tenant_quota::TenantQuotaLimits;
use crate::enterprise::AuthenticatedContext;

pub const ENTITLEMENT_SET_VERSION: &str = "chisei.entitlement-set/v1";

/// Named product capability flags (not commercial SKUs).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntitlementFeature(pub String);

/// Versioned entitlement set supplied by the enterprise authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementSet {
    pub version: u64,
    pub set_id: String,
    pub features: BTreeSet<String>,
    /// Optional ceilings that narrow (never widen) tenant quotas.
    pub quota_ceiling: Option<TenantQuotaLimits>,
    pub expires_at_ms: Option<i64>,
}

/// Active assignment of a set to a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantEntitlementAssignment {
    pub tenant_id: String,
    pub set: EntitlementSet,
    pub assigned_at_ms: i64,
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementError {
    TenantRequired,
    MissingAssignment,
    Expired,
    FeatureDenied {
        feature: String,
    },
    /// Distinct from quota/budget/governance denial.
    EntitlementDenied {
        reason: String,
    },
    StaleVersion {
        have: u64,
        need: u64,
    },
}

impl std::fmt::Display for EntitlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TenantRequired => write!(f, "entitlement check requires tenant context"),
            Self::MissingAssignment => write!(f, "no entitlement assignment for tenant"),
            Self::Expired => write!(f, "entitlement assignment expired"),
            Self::FeatureDenied { feature } => {
                write!(f, "entitlement does not include feature {feature}")
            }
            Self::EntitlementDenied { reason } => write!(f, "entitlement denied: {reason}"),
            Self::StaleVersion { have, need } => {
                write!(f, "entitlement version stale (have {have}, need {need})")
            }
        }
    }
}

impl std::error::Error for EntitlementError {}

/// Effective resolution recorded on a decision/receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveEntitlement {
    pub tenant_id: String,
    pub set_id: String,
    pub version: u64,
    pub features: BTreeSet<String>,
}

/// In-memory assignment store (enterprise may replace with durable authority).
#[derive(Default)]
pub struct EntitlementRegistry {
    by_tenant: RwLock<BTreeMap<String, TenantEntitlementAssignment>>,
}

impl EntitlementRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn assign(&self, assignment: TenantEntitlementAssignment) {
        self.by_tenant
            .write()
            .unwrap()
            .insert(assignment.tenant_id.clone(), assignment);
    }

    pub fn remove(&self, tenant_id: &str, now_ms: i64) {
        let mut map = self.by_tenant.write().unwrap();
        if let Some(existing) = map.get_mut(tenant_id) {
            existing.removed = true;
            existing.assigned_at_ms = now_ms;
        }
    }

    pub fn resolve(
        &self,
        context: &AuthenticatedContext,
        now_ms: i64,
    ) -> Result<EffectiveEntitlement, EntitlementError> {
        let tenant = context
            .tenant
            .as_ref()
            .ok_or(EntitlementError::TenantRequired)?;
        let map = self.by_tenant.read().unwrap();
        let assignment = map
            .get(&tenant.tenant_id)
            .ok_or(EntitlementError::MissingAssignment)?;
        if assignment.removed {
            return Err(EntitlementError::MissingAssignment);
        }
        if assignment
            .set
            .expires_at_ms
            .is_some_and(|exp| exp <= now_ms)
        {
            return Err(EntitlementError::Expired);
        }
        Ok(EffectiveEntitlement {
            tenant_id: tenant.tenant_id.clone(),
            set_id: assignment.set.set_id.clone(),
            version: assignment.set.version,
            features: assignment.set.features.clone(),
        })
    }

    pub fn require_feature(
        &self,
        context: &AuthenticatedContext,
        feature: &str,
        now_ms: i64,
    ) -> Result<EffectiveEntitlement, EntitlementError> {
        let effective = self.resolve(context, now_ms)?;
        if !effective.features.contains(feature) {
            return Err(EntitlementError::FeatureDenied {
                feature: feature.into(),
            });
        }
        Ok(effective)
    }

    /// Narrow quota limits to the entitlement ceiling (min of each configured max).
    pub fn narrow_quota_limits(
        &self,
        context: &AuthenticatedContext,
        requested: &TenantQuotaLimits,
        now_ms: i64,
    ) -> Result<TenantQuotaLimits, EntitlementError> {
        let tenant = context
            .tenant
            .as_ref()
            .ok_or(EntitlementError::TenantRequired)?;
        let map = self.by_tenant.read().unwrap();
        let assignment = map
            .get(&tenant.tenant_id)
            .ok_or(EntitlementError::MissingAssignment)?;
        if assignment.removed {
            return Err(EntitlementError::MissingAssignment);
        }
        if assignment
            .set
            .expires_at_ms
            .is_some_and(|exp| exp <= now_ms)
        {
            return Err(EntitlementError::Expired);
        }
        let Some(ceiling) = &assignment.set.quota_ceiling else {
            return Ok(requested.clone());
        };
        Ok(TenantQuotaLimits {
            version: requested.version.max(ceiling.version),
            max_requests_per_period: min_opt(
                requested.max_requests_per_period,
                ceiling.max_requests_per_period,
            ),
            max_tokens_per_period: min_opt(
                requested.max_tokens_per_period,
                ceiling.max_tokens_per_period,
            ),
            max_concurrency: min_opt(requested.max_concurrency, ceiling.max_concurrency),
            max_storage_bytes: min_opt_i64(requested.max_storage_bytes, ceiling.max_storage_bytes),
            period: requested.period,
        })
    }
}

fn min_opt(a: Option<i32>, b: Option<i32>) -> Option<i32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

fn min_opt_i64(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// Migration default: explicit restricted set, never unlimited implicit grant.
pub fn migration_entitlement_set(version: u64) -> EntitlementSet {
    EntitlementSet {
        version,
        set_id: "migration-default".into(),
        features: BTreeSet::from(["core.chat".into()]),
        quota_ceiling: Some(TenantQuotaLimits {
            version,
            max_requests_per_period: Some(1_000),
            max_tokens_per_period: Some(1_000_000),
            max_concurrency: Some(10),
            max_storage_bytes: Some(10_000_000_000),
            period: crate::chisei::budget::PeriodType::Daily,
        }),
        expires_at_ms: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_credentials::tenant_context;

    fn set_with_feature(feature: &str, version: u64) -> EntitlementSet {
        EntitlementSet {
            version,
            set_id: "plan-a".into(),
            features: BTreeSet::from([feature.into()]),
            quota_ceiling: Some(TenantQuotaLimits {
                version,
                max_requests_per_period: Some(5),
                max_tokens_per_period: Some(100),
                max_concurrency: Some(2),
                max_storage_bytes: Some(1_000),
                period: crate::chisei::budget::PeriodType::Daily,
            }),
            expires_at_ms: None,
        }
    }

    #[test]
    fn feature_check_and_denial_are_distinct() {
        let reg = EntitlementRegistry::new();
        reg.assign(TenantEntitlementAssignment {
            tenant_id: "tenant-a".into(),
            set: set_with_feature("core.chat", 1),
            assigned_at_ms: 1,
            removed: false,
        });
        let ctx = tenant_context("tenant-a", "alice");
        assert!(reg.require_feature(&ctx, "core.chat", 10).is_ok());
        let err = reg.require_feature(&ctx, "premium.search", 10).unwrap_err();
        assert!(matches!(err, EntitlementError::FeatureDenied { .. }));
        // Missing assignment is a different error class.
        let other = tenant_context("tenant-b", "bob");
        assert!(matches!(
            reg.require_feature(&other, "core.chat", 10),
            Err(EntitlementError::MissingAssignment)
        ));
    }

    #[test]
    fn expiry_and_removal_fail_closed() {
        let reg = EntitlementRegistry::new();
        let mut set = set_with_feature("core.chat", 2);
        set.expires_at_ms = Some(100);
        reg.assign(TenantEntitlementAssignment {
            tenant_id: "tenant-a".into(),
            set,
            assigned_at_ms: 1,
            removed: false,
        });
        let ctx = tenant_context("tenant-a", "alice");
        assert!(matches!(
            reg.resolve(&ctx, 100),
            Err(EntitlementError::Expired)
        ));
        reg.assign(TenantEntitlementAssignment {
            tenant_id: "tenant-a".into(),
            set: set_with_feature("core.chat", 3),
            assigned_at_ms: 101,
            removed: false,
        });
        assert!(reg.resolve(&ctx, 101).is_ok());
        reg.remove("tenant-a", 200);
        assert!(matches!(
            reg.resolve(&ctx, 201),
            Err(EntitlementError::MissingAssignment)
        ));
    }

    #[test]
    fn quota_ceiling_only_narrows() {
        let reg = EntitlementRegistry::new();
        reg.assign(TenantEntitlementAssignment {
            tenant_id: "tenant-a".into(),
            set: set_with_feature("core.chat", 1),
            assigned_at_ms: 1,
            removed: false,
        });
        let ctx = tenant_context("tenant-a", "alice");
        let requested = TenantQuotaLimits {
            version: 9,
            max_requests_per_period: Some(100),
            max_tokens_per_period: Some(50),
            max_concurrency: Some(10),
            max_storage_bytes: Some(500),
            period: crate::chisei::budget::PeriodType::Daily,
        };
        let narrowed = reg.narrow_quota_limits(&ctx, &requested, 10).unwrap();
        assert_eq!(narrowed.max_requests_per_period, Some(5)); // ceiling 5
        assert_eq!(narrowed.max_tokens_per_period, Some(50)); // requested tighter
        assert_eq!(narrowed.max_concurrency, Some(2));
        assert_eq!(narrowed.max_storage_bytes, Some(500));
    }

    #[test]
    fn migration_default_is_restricted_not_unlimited() {
        let set = migration_entitlement_set(1);
        assert!(set.features.contains("core.chat"));
        assert!(set.quota_ceiling.is_some());
        assert!(
            set.quota_ceiling
                .as_ref()
                .unwrap()
                .max_tokens_per_period
                .is_some()
        );
    }

    #[test]
    fn resolve_is_deterministic() {
        let reg = EntitlementRegistry::new();
        reg.assign(TenantEntitlementAssignment {
            tenant_id: "tenant-a".into(),
            set: set_with_feature("core.chat", 7),
            assigned_at_ms: 1,
            removed: false,
        });
        let ctx = tenant_context("tenant-a", "alice");
        let a = reg.resolve(&ctx, 10).unwrap();
        let b = reg.resolve(&ctx, 10).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.version, 7);
    }
}
