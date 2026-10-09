//! Shared observability: closed metric labels, Prometheus export, logging, and OTLP.
//!
//! Console, ops, and gRPC-auth layers stay in the root crate. This crate holds
//! the vocabulary and exporters the gateway previously copied.

pub mod build_info;
pub mod labels;
pub mod logging;
pub mod metrics;
pub mod otel;
pub mod signals;

#[cfg(test)]
mod tests {
    use crate::labels::{FallbackTrigger, LookupFirstPath, PoolPlane};
    use crate::signals;

    #[test]
    fn shared_vocabulary_keeps_control_plane_and_gateway_emitters() {
        assert_eq!(FallbackTrigger::BudgetDegraded.as_str(), "budget_degraded");
        assert_eq!(
            FallbackTrigger::ProviderUnhealthy.as_str(),
            "provider_unhealthy"
        );
        assert_eq!(PoolPlane::Sekai.as_str(), "sekai");
        assert_eq!(LookupFirstPath::LookupHit.as_str(), "lookup_hit");
        assert_eq!(
            signals::PROVIDER_CIRCUIT_OPEN,
            "sekai_provider_circuit_open"
        );
        assert_eq!(signals::POOL_CHECKOUT, "sekai_db_pool_checkout_seconds");
        assert_eq!(signals::LOOKUP_FIRST_TOTAL, "sekai_lookup_first_total");
    }

    #[test]
    fn build_info_metric_uses_caller_package_version() {
        let rendered = crate::metrics::handle("9.9.9-test").render();
        assert!(
            rendered.contains("version=\"9.9.9-test\""),
            "caller version must win over sekai-obs CARGO_PKG_VERSION: {rendered}"
        );
    }
}
