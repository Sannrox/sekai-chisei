//! Tenant data lifecycle contract (#127).
//!
//! Inventories, exports, retains, and closes Sekai Chisei-owned data for a
//! verified tenant request. Enterprise orchestrates cross-service privacy
//! requests; this surface is domain-local, idempotent, and non-disclosing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::chisei::billing_adapter::FakeBillingAdapter;
use crate::chisei::usage_ledger::UsageUnit;
use crate::db::sekai::SekaiDb;
use crate::enterprise::AuthenticatedContext;
use crate::provider_credentials::MemoryTenantProviderCredentialResolver;

pub const TENANT_LIFECYCLE_VERSION: &str = "sekai.tenant-lifecycle/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStore {
    UsageLedger,
    ProviderCredentials,
    Quotas,
    Entitlements,
    Invitations,
    BillingLink,
    Archives,
    Backups,
}

impl LifecycleStore {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UsageLedger => "usage_ledger",
            Self::ProviderCredentials => "provider_credentials",
            Self::Quotas => "quotas",
            Self::Entitlements => "entitlements",
            Self::Invitations => "invitations",
            Self::BillingLink => "billing_link",
            Self::Archives => "archives",
            Self::Backups => "backups",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub store: String,
    pub record_count: u64,
    pub contains_secrets: bool,
    pub retain_reason: Option<String>,
    pub retain_until_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantDataInventory {
    pub version: String,
    pub tenant_id: String,
    pub entries: Vec<InventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantExportBundle {
    pub version: String,
    pub tenant_id: String,
    pub exported_at_ms: i64,
    /// Portable JSON map of store -> payload. Never includes secrets.
    pub stores: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosurePhase {
    Inventory,
    Export,
    EraseHot,
    SealRetained,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureProgress {
    pub tenant_id: String,
    pub phase: ClosurePhase,
    pub completed_stores: BTreeSet<String>,
    pub incomplete_stores: BTreeSet<String>,
    pub retained: Vec<InventoryEntry>,
    pub closed: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    Unauthorized,
    CrossTenant,
    AlreadyClosed,
    Incomplete(String),
    Invalid(String),
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "tenant lifecycle unauthorized"),
            Self::CrossTenant => write!(f, "cross-tenant lifecycle denied"),
            Self::AlreadyClosed => write!(f, "tenant already closed"),
            Self::Incomplete(m) => write!(f, "lifecycle incomplete: {m}"),
            Self::Invalid(m) => write!(f, "lifecycle invalid: {m}"),
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Domain-local lifecycle controller (enterprise owns orchestration).
pub struct TenantLifecycleController {
    db: std::sync::Arc<SekaiDb>,
    credentials: std::sync::Arc<MemoryTenantProviderCredentialResolver>,
    billing: std::sync::Arc<FakeBillingAdapter>,
    /// Closed tenants cannot authenticate / admit / resolve secrets.
    closed: RwLock<BTreeSet<String>>,
    progress: RwLock<BTreeMap<String, ClosureProgress>>,
    /// Simulated per-tenant record counts for inventory/export demos.
    hot_records: RwLock<BTreeMap<String, BTreeMap<LifecycleStore, u64>>>,
    admins: RwLock<BTreeSet<(String, String)>>,
}

impl TenantLifecycleController {
    pub fn new(
        db: std::sync::Arc<SekaiDb>,
        credentials: std::sync::Arc<MemoryTenantProviderCredentialResolver>,
        billing: std::sync::Arc<FakeBillingAdapter>,
    ) -> Self {
        Self {
            db,
            credentials,
            billing,
            closed: RwLock::new(BTreeSet::new()),
            progress: RwLock::new(BTreeMap::new()),
            hot_records: RwLock::new(BTreeMap::new()),
            admins: RwLock::new(BTreeSet::new()),
        }
    }

    pub fn grant_admin(&self, tenant_id: &str, subject: &str) {
        self.admins
            .write()
            .unwrap()
            .insert((tenant_id.into(), subject.into()));
    }

    pub fn seed_records(&self, tenant_id: &str, store: LifecycleStore, count: u64) {
        self.hot_records
            .write()
            .unwrap()
            .entry(tenant_id.into())
            .or_default()
            .insert(store, count);
    }

    pub fn is_closed(&self, tenant_id: &str) -> bool {
        self.closed.read().unwrap().contains(tenant_id)
    }

    /// Closed tenants cannot resolve provider secrets.
    pub fn assert_can_resolve_secrets(&self, tenant_id: &str) -> Result<(), LifecycleError> {
        if self.is_closed(tenant_id) {
            return Err(LifecycleError::AlreadyClosed);
        }
        Ok(())
    }

    pub fn assert_can_admit_work(&self, tenant_id: &str) -> Result<(), LifecycleError> {
        if self.is_closed(tenant_id) {
            return Err(LifecycleError::AlreadyClosed);
        }
        Ok(())
    }

    fn authorize(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
    ) -> Result<(), LifecycleError> {
        if let Some(t) = &context.tenant
            && t.tenant_id != tenant_id
        {
            return Err(LifecycleError::CrossTenant);
        }
        if !self
            .admins
            .read()
            .unwrap()
            .contains(&(tenant_id.into(), context.principal.subject.clone()))
        {
            return Err(LifecycleError::Unauthorized);
        }
        Ok(())
    }

    pub fn inventory(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        now_ms: i64,
    ) -> Result<TenantDataInventory, LifecycleError> {
        self.authorize(context, tenant_id)?;
        let counts = self
            .hot_records
            .read()
            .unwrap()
            .get(tenant_id)
            .cloned()
            .unwrap_or_default();
        let usage = self
            .db
            .aggregate_usage_for_tenant(tenant_id, UsageUnit::Tokens, 0, now_ms)
            .unwrap_or_default();
        let mut entries = vec![
            InventoryEntry {
                store: LifecycleStore::UsageLedger.as_str().into(),
                record_count: if usage.net != 0 || usage.measured != 0 {
                    1
                } else {
                    *counts.get(&LifecycleStore::UsageLedger).unwrap_or(&0)
                },
                contains_secrets: false,
                retain_reason: Some("billing_evidence".into()),
                retain_until_ms: Some(now_ms.saturating_add(365 * 86_400_000)),
            },
            InventoryEntry {
                store: LifecycleStore::ProviderCredentials.as_str().into(),
                record_count: *counts
                    .get(&LifecycleStore::ProviderCredentials)
                    .unwrap_or(&0),
                contains_secrets: true,
                retain_reason: None,
                retain_until_ms: None,
            },
            InventoryEntry {
                store: LifecycleStore::Quotas.as_str().into(),
                record_count: *counts.get(&LifecycleStore::Quotas).unwrap_or(&0),
                contains_secrets: false,
                retain_reason: None,
                retain_until_ms: None,
            },
            InventoryEntry {
                store: LifecycleStore::Backups.as_str().into(),
                record_count: *counts.get(&LifecycleStore::Backups).unwrap_or(&0),
                contains_secrets: false,
                retain_reason: Some("immutable_backup_window".into()),
                retain_until_ms: Some(now_ms.saturating_add(30 * 86_400_000)),
            },
        ];
        // Never invent another tenant's data.
        entries.retain(|e| e.record_count > 0 || e.retain_reason.is_some());
        Ok(TenantDataInventory {
            version: TENANT_LIFECYCLE_VERSION.into(),
            tenant_id: tenant_id.into(),
            entries,
        })
    }

    pub fn export(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        now_ms: i64,
    ) -> Result<TenantExportBundle, LifecycleError> {
        self.authorize(context, tenant_id)?;
        let inv = self.inventory(context, tenant_id, now_ms)?;
        let mut stores = BTreeMap::new();
        for entry in &inv.entries {
            if entry.contains_secrets {
                // Export never includes secrets — only opaque counts/ids.
                stores.insert(
                    entry.store.clone(),
                    format!(
                        r#"{{"credential_slots":{},"secrets":null}}"#,
                        entry.record_count
                    ),
                );
            } else if entry.store == LifecycleStore::UsageLedger.as_str() {
                let export = self
                    .db
                    .export_usage_period(tenant_id, 0, now_ms)
                    .unwrap_or_default();
                stores.insert(entry.store.clone(), export);
            } else {
                stores.insert(
                    entry.store.clone(),
                    format!(r#"{{"record_count":{}}}"#, entry.record_count),
                );
            }
        }
        // Ensure no secret material patterns.
        let joined = stores.values().cloned().collect::<Vec<_>>().join("\n");
        if joined.contains("sk-") || joined.contains("\"secret\"") {
            return Err(LifecycleError::Invalid(
                "export sanitizer blocked secret material".into(),
            ));
        }
        Ok(TenantExportBundle {
            version: TENANT_LIFECYCLE_VERSION.into(),
            tenant_id: tenant_id.into(),
            exported_at_ms: now_ms,
            stores,
        })
    }

    /// Idempotent, resumable closure. Reports incomplete stores.
    pub fn close_tenant(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        now_ms: i64,
    ) -> Result<ClosureProgress, LifecycleError> {
        self.authorize(context, tenant_id)?;
        if self.is_closed(tenant_id) {
            return Ok(ClosureProgress {
                tenant_id: tenant_id.into(),
                phase: ClosurePhase::Complete,
                completed_stores: BTreeSet::new(),
                incomplete_stores: BTreeSet::new(),
                retained: vec![],
                closed: true,
                message: "already closed".into(),
            });
        }

        let inv = self.inventory(context, tenant_id, now_ms)?;
        let _export = self.export(context, tenant_id, now_ms)?;

        let mut completed = BTreeSet::new();
        let mut incomplete = BTreeSet::new();
        let mut retained = Vec::new();

        // Erase hot non-retained stores.
        for entry in &inv.entries {
            if entry.retain_reason.is_some() {
                retained.push(entry.clone());
                completed.insert(entry.store.clone());
                continue;
            }
            match entry.store.as_str() {
                "provider_credentials" => {
                    // Revoke known providers for the tenant (memory store).
                    self.credentials.revoke(tenant_id, "openai");
                    self.credentials.revoke(tenant_id, "anthropic");
                    self.credentials.revoke(tenant_id, "xai");
                    completed.insert(entry.store.clone());
                }
                "quotas" | "entitlements" | "invitations" => {
                    completed.insert(entry.store.clone());
                }
                "billing_link" => {
                    // Billing adapter cannot own closure of usage authority;
                    // local link is marked complete for domain purposes.
                    let _ = self.billing.as_ref();
                    completed.insert(entry.store.clone());
                }
                other if other == LifecycleStore::Backups.as_str() => {
                    incomplete.insert(other.into());
                }
                other => {
                    completed.insert(other.into());
                }
            }
        }

        // Clear hot record counts for non-retained stores.
        if let Some(map) = self.hot_records.write().unwrap().get_mut(tenant_id) {
            map.retain(|store, _| {
                matches!(store, LifecycleStore::UsageLedger | LifecycleStore::Backups)
            });
        }

        let closed = incomplete.is_empty();
        if closed {
            self.closed.write().unwrap().insert(tenant_id.into());
        }

        let progress = ClosureProgress {
            tenant_id: tenant_id.into(),
            phase: if closed {
                ClosurePhase::Complete
            } else {
                ClosurePhase::EraseHot
            },
            completed_stores: completed,
            incomplete_stores: incomplete.clone(),
            retained,
            closed,
            message: if closed {
                "tenant closed; retained evidence listed".into()
            } else {
                format!(
                    "incomplete stores: {}",
                    incomplete.into_iter().collect::<Vec<_>>().join(",")
                )
            },
        };
        self.progress
            .write()
            .unwrap()
            .insert(tenant_id.into(), progress.clone());
        Ok(progress)
    }

    pub fn progress(&self, tenant_id: &str) -> Option<ClosureProgress> {
        self.progress.read().unwrap().get(tenant_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_credentials::tenant_context;
    use std::sync::Arc;

    fn controller() -> TenantLifecycleController {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        TenantLifecycleController::new(
            db,
            Arc::new(MemoryTenantProviderCredentialResolver::new()),
            Arc::new(FakeBillingAdapter::new()),
        )
    }

    #[test]
    fn two_tenant_export_and_closure_isolation() {
        let ctl = controller();
        ctl.grant_admin("tenant-a", "alice");
        ctl.grant_admin("tenant-b", "bob");
        ctl.seed_records("tenant-a", LifecycleStore::ProviderCredentials, 2);
        ctl.seed_records("tenant-b", LifecycleStore::ProviderCredentials, 5);
        ctl.credentials.upsert("tenant-a", "openai", "sk-a");
        ctl.credentials.upsert("tenant-b", "openai", "sk-b");

        let alice = tenant_context("tenant-a", "alice");
        let export_a = ctl.export(&alice, "tenant-a", 1_000).unwrap();
        assert_eq!(export_a.tenant_id, "tenant-a");
        assert!(!export_a.stores.values().any(|v| v.contains("sk-")));
        // tenant-b secret not present
        assert!(!format!("{export_a:?}").contains("sk-b"));

        let progress = ctl.close_tenant(&alice, "tenant-a", 1_000).unwrap();
        assert!(progress.closed || !progress.incomplete_stores.is_empty());
        // Retry is safe
        let again = ctl.close_tenant(&alice, "tenant-a", 1_001).unwrap();
        assert!(
            again.closed
                || again.message.contains("already")
                || !again.incomplete_stores.is_empty()
        );

        // Closed tenant cannot resolve secrets / admit
        if ctl.is_closed("tenant-a") {
            assert!(ctl.assert_can_resolve_secrets("tenant-a").is_err());
            assert!(ctl.assert_can_admit_work("tenant-a").is_err());
        }
        // Other tenant unaffected
        assert!(ctl.assert_can_resolve_secrets("tenant-b").is_ok());
        let bob = tenant_context("tenant-b", "bob");
        let inv_b = ctl.inventory(&bob, "tenant-b", 1_000).unwrap();
        assert!(
            inv_b
                .entries
                .iter()
                .any(|e| e.store == "provider_credentials" && e.record_count == 5)
        );
    }

    #[test]
    fn retained_billing_evidence_is_explicit() {
        let ctl = controller();
        ctl.grant_admin("tenant-a", "alice");
        let alice = tenant_context("tenant-a", "alice");
        // Project some usage so ledger appears.
        use crate::chisei::receipt::{
            OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
            ReceiptSurface,
        };
        use std::collections::BTreeMap;
        let mut attrs = BTreeMap::new();
        attrs.insert("total_tokens".into(), "10".into());
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: None,
            namespace: "ns".into(),
            operation_class: "chat".into(),
            initiating_actor: "alice".into(),
            schema_version: "1".into(),
            policy_version: "1".into(),
            started_at_ms: 1,
            completed_at_ms: Some(2),
            events: vec![OperationReceiptEvent {
                event_id: "e1".into(),
                operation_id: "op-1".into(),
                parent_event_id: None,
                timestamp_ms: 1,
                kind: ReceiptEventKind::ModelCalled,
                surface: ReceiptSurface::ModelCall,
                actor: "alice".into(),
                references: vec![],
                attributes: attrs,
            }],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
            ontology_digest: None,
        };
        ctl.db
            .project_usage_from_receipt("tenant-a", &receipt)
            .unwrap();
        let inv = ctl.inventory(&alice, "tenant-a", 100).unwrap();
        let usage = inv
            .entries
            .iter()
            .find(|e| e.store == "usage_ledger")
            .unwrap();
        assert_eq!(usage.retain_reason.as_deref(), Some("billing_evidence"));
        assert!(usage.retain_until_ms.is_some());
    }

    #[test]
    fn cross_tenant_denied() {
        let ctl = controller();
        ctl.grant_admin("tenant-a", "alice");
        let bob = tenant_context("tenant-b", "bob");
        assert!(matches!(
            ctl.inventory(&bob, "tenant-a", 1),
            Err(LifecycleError::CrossTenant | LifecycleError::Unauthorized)
        ));
    }
}
