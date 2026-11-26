pub mod gateway;
pub use sekai_domain::domain;
pub use sekai_domain::enterprise;
mod gateway_support;
#[allow(dead_code)]
mod harness;
pub use sekai_domain::secrets;
pub use sekai_obs as obs;

pub use chisei_provider::{
    cost_estimate, gateway_keys, llm, model_availability, pricing, provider_profile,
    provider_resolution,
};

#[cfg(test)]
mod shared_crate_cut {
    #[test]
    fn gateway_src_has_no_copied_domain_or_obs_modules() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for rel in [
            "domain.rs",
            "enterprise.rs",
            "secrets.rs",
            "obs/mod.rs",
            "obs/labels.rs",
            "obs/logging.rs",
            "obs/metrics.rs",
            "obs/otel.rs",
            "obs/signals.rs",
        ] {
            assert!(
                !src.join(rel).exists(),
                "gateway must not keep a cfg(not(test)) copy of {rel}"
            );
        }
        assert!(
            src.join("harness.rs").exists(),
            "harness.rs stays in the gateway crate"
        );
    }
}
