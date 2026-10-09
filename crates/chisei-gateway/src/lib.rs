pub mod gateway;
pub mod gateway_report;
pub mod gateway_setup;

#[allow(dead_code)]
mod client;
#[cfg(test)]
pub use sekai_chisei::config;
pub use sekai_domain::domain;
mod egress;
pub use sekai_domain::enterprise;
mod gateway_support;
#[allow(dead_code)]
mod harness;
pub use sekai_domain::secrets;
pub use sekai_obs as obs;

pub use sekai_provider::{
    cost_estimate, gateway_keys, llm, model_availability, pricing, provider_profile,
    provider_resolution,
};

#[cfg(test)]
mod test_support {
    pub use sekai_chisei::db::{runtime_db, sekai as sekai_db};
    pub use sekai_chisei::grpc::{chisei_service, sekai_service};
    pub use sekai_chisei::sekai::{audit, dataset, security};
}

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
