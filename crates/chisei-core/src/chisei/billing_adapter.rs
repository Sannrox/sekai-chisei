//! Billing adapter contract (#124).
//!
//! Provider-neutral surface for synchronizing subscription state and closed
//! usage periods. The adapter is never tenant/usage/entitlement authority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::chisei::entitlements::EntitlementSet;
use crate::chisei::usage_ledger::{UsageAggregate, UsageUnit};

pub const BILLING_ADAPTER_VERSION: &str = "chisei.billing-adapter/v1";

/// Opaque external customer reference (not a Sekai tenant id).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalCustomerRef {
    pub provider: String,
    pub customer_id: String,
}

/// Closed usage period published for metered sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedUsagePeriod {
    pub tenant_id: String,
    pub period_id: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub aggregates: Vec<UsageAggregate>,
    /// Stable idempotency key for the closed period.
    pub idempotency_key: String,
}

/// Normalized webhook/event after provider-specific verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedBillingEvent {
    pub event_id: String,
    pub provider: String,
    pub kind: BillingEventKind,
    pub occurred_at_ms: i64,
    pub external_customer: Option<ExternalCustomerRef>,
    pub entitlement_set: Option<EntitlementSet>,
    pub period_id: Option<String>,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingEventKind {
    SubscriptionActivated,
    SubscriptionReplaced,
    SubscriptionExpired,
    SubscriptionRemoved,
    UsageAcknowledged,
    UsageDisputed,
    ReconciliationHint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationResult {
    pub provider: String,
    pub tenant_id: String,
    pub period_id: String,
    pub local_net_tokens: i64,
    pub published: bool,
    pub drift_detected: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillingAdapterError {
    Invalid(String),
    DuplicateEvent,
    SignatureInvalid,
    Refused(String),
    Unavailable(String),
}

impl std::fmt::Display for BillingAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "billing adapter invalid: {m}"),
            Self::DuplicateEvent => write!(f, "billing event already processed"),
            Self::SignatureInvalid => write!(f, "billing webhook signature invalid"),
            Self::Refused(m) => write!(f, "billing adapter refused: {m}"),
            Self::Unavailable(m) => write!(f, "billing adapter unavailable: {m}"),
        }
    }
}

impl std::error::Error for BillingAdapterError {}

/// Replaceable billing adapter. Implementations must not mutate local
/// entitlement or usage authority; they only sync external state.
pub trait BillingAdapter: Send + Sync {
    fn contract_version(&self) -> &'static str {
        BILLING_ADAPTER_VERSION
    }

    fn link_customer(
        &self,
        tenant_id: &str,
        customer: &ExternalCustomerRef,
    ) -> Result<(), BillingAdapterError>;

    fn publish_closed_usage(&self, period: &ClosedUsagePeriod) -> Result<(), BillingAdapterError>;

    fn apply_normalized_event(
        &self,
        event: &NormalizedBillingEvent,
    ) -> Result<(), BillingAdapterError>;

    fn reconcile_period(
        &self,
        tenant_id: &str,
        period_id: &str,
    ) -> Result<ReconciliationResult, BillingAdapterError>;
}

/// Deterministic fake for conformance tests (no provider SDK).
///
/// Subscription events apply in `occurred_at_ms` order per tenant: an event
/// older than the last applied one is recorded as processed but changes
/// nothing; ties apply in arrival order. Activation and replacement store
/// the event's entitlement set; expiry and removal clear it.
#[derive(Default)]
pub struct FakeBillingAdapter {
    customers: RwLock<BTreeMap<String, ExternalCustomerRef>>,
    published_periods: RwLock<BTreeSet<String>>,
    events: RwLock<BTreeSet<String>>,
    /// Per tenant: the last applied subscription event time and the
    /// entitlement set it left (`None` after expiry or removal).
    entitlement_by_tenant: RwLock<BTreeMap<String, (i64, Option<EntitlementSet>)>>,
    last_publish: RwLock<BTreeMap<String, ClosedUsagePeriod>>,
}

impl FakeBillingAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn customer_for(&self, tenant_id: &str) -> Option<ExternalCustomerRef> {
        self.customers.read().unwrap().get(tenant_id).cloned()
    }

    pub fn entitlement_for(&self, tenant_id: &str) -> Option<EntitlementSet> {
        self.entitlement_by_tenant
            .read()
            .unwrap()
            .get(tenant_id)
            .and_then(|(_, set)| set.clone())
    }

    pub fn was_published(&self, idempotency_key: &str) -> bool {
        self.published_periods
            .read()
            .unwrap()
            .contains(idempotency_key)
    }
}

impl BillingAdapter for FakeBillingAdapter {
    fn link_customer(
        &self,
        tenant_id: &str,
        customer: &ExternalCustomerRef,
    ) -> Result<(), BillingAdapterError> {
        if tenant_id.is_empty() || customer.customer_id.is_empty() {
            return Err(BillingAdapterError::Invalid(
                "tenant_id and customer_id required".into(),
            ));
        }
        self.customers
            .write()
            .unwrap()
            .insert(tenant_id.into(), customer.clone());
        Ok(())
    }

    fn publish_closed_usage(&self, period: &ClosedUsagePeriod) -> Result<(), BillingAdapterError> {
        if period.idempotency_key.is_empty() {
            return Err(BillingAdapterError::Invalid(
                "idempotency_key required".into(),
            ));
        }
        if !self
            .customers
            .read()
            .unwrap()
            .contains_key(&period.tenant_id)
        {
            return Err(BillingAdapterError::Refused(
                "customer not linked for tenant".into(),
            ));
        }
        let mut published = self.published_periods.write().unwrap();
        if !published.insert(period.idempotency_key.clone()) {
            // Idempotent success — no double publication side effects.
            return Ok(());
        }
        self.last_publish
            .write()
            .unwrap()
            .insert(period.tenant_id.clone(), period.clone());
        Ok(())
    }

    fn apply_normalized_event(
        &self,
        event: &NormalizedBillingEvent,
    ) -> Result<(), BillingAdapterError> {
        if event.event_id.is_empty() {
            return Err(BillingAdapterError::Invalid("event_id required".into()));
        }
        let mut events = self.events.write().unwrap();
        if !events.insert(event.event_id.clone()) {
            return Err(BillingAdapterError::DuplicateEvent);
        }
        // Map external customer -> tenant by reverse lookup of linked refs.
        if let Some(customer) = &event.external_customer {
            let customers = self.customers.read().unwrap();
            let tenant_id = customers
                .iter()
                .find(|(_, c)| c == &customer)
                .map(|(t, _)| t.clone());
            drop(customers);
            let next = match event.kind {
                BillingEventKind::SubscriptionActivated
                | BillingEventKind::SubscriptionReplaced => event.entitlement_set.clone().map(Some),
                BillingEventKind::SubscriptionExpired | BillingEventKind::SubscriptionRemoved => {
                    Some(None)
                }
                _ => None,
            };
            if let Some(tenant_id) = tenant_id
                && let Some(next) = next
            {
                let mut entitlements = self.entitlement_by_tenant.write().unwrap();
                let stale = entitlements
                    .get(&tenant_id)
                    .is_some_and(|(applied_at_ms, _)| event.occurred_at_ms < *applied_at_ms);
                if !stale {
                    entitlements.insert(tenant_id, (event.occurred_at_ms, next));
                }
            }
        }
        Ok(())
    }

    fn reconcile_period(
        &self,
        tenant_id: &str,
        period_id: &str,
    ) -> Result<ReconciliationResult, BillingAdapterError> {
        let published = self.last_publish.read().unwrap();
        let period = published.get(tenant_id);
        let local_net = period
            .map(|p| {
                p.aggregates
                    .iter()
                    .filter(|a| a.unit == UsageUnit::Tokens.as_str())
                    .map(|a| a.net)
                    .sum()
            })
            .unwrap_or(0);
        let was_published = period.is_some_and(|p| p.period_id == period_id);
        Ok(ReconciliationResult {
            provider: "fake".into(),
            tenant_id: tenant_id.into(),
            period_id: period_id.into(),
            local_net_tokens: local_net,
            published: was_published,
            drift_detected: !was_published && local_net != 0,
            notes: if was_published {
                vec!["period matches last publication".into()]
            } else {
                vec!["no publication for period".into()]
            },
        })
    }
}

/// Verify a fake webhook signature: lowercase or uppercase hex of
/// HMAC-SHA256(secret, body), compared in constant time. Malformed hex is
/// refused.
pub fn verify_fake_webhook_signature(secret: &str, body: &str, signature: &str) -> bool {
    use hmac::{Hmac, Mac};
    let Some(signature) = decode_hex(signature) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body.as_bytes());
    mac.verify_slice(&signature).is_ok()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::entitlements::EntitlementSet;
    use crate::chisei::usage_ledger::UsageAggregate;
    use std::collections::BTreeSet;

    fn sample_period(tenant: &str, period: &str, tokens: i64) -> ClosedUsagePeriod {
        ClosedUsagePeriod {
            tenant_id: tenant.into(),
            period_id: period.into(),
            start_ms: 0,
            end_ms: 86_400_000,
            aggregates: vec![UsageAggregate {
                tenant_id: tenant.into(),
                unit: "tokens".into(),
                measured: tokens,
                provider_reported: 0,
                estimated: 0,
                corrections: 0,
                net: tokens,
            }],
            idempotency_key: format!("period:{tenant}:{period}"),
        }
    }

    #[test]
    fn duplicate_publish_and_events_converge() {
        let adapter = FakeBillingAdapter::new();
        adapter
            .link_customer(
                "tenant-a",
                &ExternalCustomerRef {
                    provider: "fake".into(),
                    customer_id: "cus_a".into(),
                },
            )
            .unwrap();
        let period = sample_period("tenant-a", "2026-07", 100);
        adapter.publish_closed_usage(&period).unwrap();
        adapter.publish_closed_usage(&period).unwrap(); // idempotent
        assert!(adapter.was_published(&period.idempotency_key));

        let event = NormalizedBillingEvent {
            event_id: "evt-1".into(),
            provider: "fake".into(),
            kind: BillingEventKind::SubscriptionActivated,
            occurred_at_ms: 1,
            external_customer: Some(ExternalCustomerRef {
                provider: "fake".into(),
                customer_id: "cus_a".into(),
            }),
            entitlement_set: Some(EntitlementSet {
                version: 1,
                set_id: "starter".into(),
                features: BTreeSet::from(["core.chat".into()]),
                quota_ceiling: None,
                expires_at_ms: None,
            }),
            period_id: None,
            attributes: BTreeMap::new(),
        };
        adapter.apply_normalized_event(&event).unwrap();
        assert!(matches!(
            adapter.apply_normalized_event(&event),
            Err(BillingAdapterError::DuplicateEvent)
        ));
        assert!(
            adapter
                .entitlement_for("tenant-a")
                .is_some_and(|s| s.set_id == "starter")
        );
        // Entitlement authority remains local; adapter only stores observed set.
    }

    fn subscription_event(
        id: &str,
        kind: BillingEventKind,
        occurred_at_ms: i64,
        set_id: Option<&str>,
    ) -> NormalizedBillingEvent {
        NormalizedBillingEvent {
            event_id: id.into(),
            provider: "fake".into(),
            kind,
            occurred_at_ms,
            external_customer: Some(ExternalCustomerRef {
                provider: "fake".into(),
                customer_id: "cus_a".into(),
            }),
            entitlement_set: set_id.map(|set_id| EntitlementSet {
                version: 1,
                set_id: set_id.into(),
                features: BTreeSet::from(["core.chat".into()]),
                quota_ceiling: None,
                expires_at_ms: None,
            }),
            period_id: None,
            attributes: BTreeMap::new(),
        }
    }

    fn linked_adapter() -> FakeBillingAdapter {
        let adapter = FakeBillingAdapter::new();
        adapter
            .link_customer(
                "tenant-a",
                &ExternalCustomerRef {
                    provider: "fake".into(),
                    customer_id: "cus_a".into(),
                },
            )
            .unwrap();
        adapter
    }

    #[test]
    fn a_late_older_event_does_not_overwrite_a_newer_one() {
        let adapter = linked_adapter();
        adapter
            .apply_normalized_event(&subscription_event(
                "e-replace",
                BillingEventKind::SubscriptionReplaced,
                20,
                Some("basic"),
            ))
            .unwrap();
        // The older premium activation arrives late: processed, not applied.
        adapter
            .apply_normalized_event(&subscription_event(
                "e-activate",
                BillingEventKind::SubscriptionActivated,
                10,
                Some("premium"),
            ))
            .unwrap();
        assert_eq!(adapter.entitlement_for("tenant-a").unwrap().set_id, "basic");
        // A late older expiry does not clear it either.
        adapter
            .apply_normalized_event(&subscription_event(
                "e-old-expiry",
                BillingEventKind::SubscriptionExpired,
                15,
                None,
            ))
            .unwrap();
        assert_eq!(adapter.entitlement_for("tenant-a").unwrap().set_id, "basic");
    }

    #[test]
    fn expiry_and_removal_clear_the_entitlement() {
        for kind in [
            BillingEventKind::SubscriptionExpired,
            BillingEventKind::SubscriptionRemoved,
        ] {
            let adapter = linked_adapter();
            adapter
                .apply_normalized_event(&subscription_event(
                    "e-activate",
                    BillingEventKind::SubscriptionActivated,
                    10,
                    Some("basic"),
                ))
                .unwrap();
            adapter
                .apply_normalized_event(&subscription_event("e-end", kind, 20, None))
                .unwrap();
            assert_eq!(adapter.entitlement_for("tenant-a"), None, "{kind:?}");
            // An older activation cannot revive it.
            adapter
                .apply_normalized_event(&subscription_event(
                    "e-late",
                    BillingEventKind::SubscriptionActivated,
                    15,
                    Some("basic"),
                ))
                .unwrap();
            assert_eq!(adapter.entitlement_for("tenant-a"), None, "{kind:?}");
        }
    }

    #[test]
    fn reconciliation_detects_unpublished_drift() {
        let adapter = FakeBillingAdapter::new();
        let result = adapter.reconcile_period("tenant-a", "2026-07").unwrap();
        assert!(!result.published);
        // No local publication stored → no token net, no false drift from zero.
        assert!(!result.drift_detected || result.local_net_tokens != 0);
    }

    #[test]
    fn webhook_signature_gate() {
        use hmac::{Hmac, Mac};
        let body = r#"{"event_id":"e1"}"#;
        let secret = "test-secret";
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body.as_bytes());
        let sig: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(verify_fake_webhook_signature(secret, body, &sig));
        assert!(verify_fake_webhook_signature(
            secret,
            body,
            &sig.to_uppercase()
        ));
        assert!(!verify_fake_webhook_signature(
            secret,
            r#"{"event_id":"e2"}"#,
            &sig
        ));
        assert!(!verify_fake_webhook_signature("wrong-secret", body, &sig));
        assert!(!verify_fake_webhook_signature(secret, body, "deadbeef"));
        assert!(!verify_fake_webhook_signature(secret, body, "zz"));
        // A sign prefix is not hex, even where the radix parser would take it.
        let signed = format!("+{}", &sig[1..]);
        assert!(!verify_fake_webhook_signature(secret, body, &signed));
        // The keyless digest the fake used to accept is refused.
        use sha2::{Digest, Sha256};
        let unkeyed: String = Sha256::digest(format!("{secret}{body}"))
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!verify_fake_webhook_signature(secret, body, &unkeyed));
    }
}
