pub mod gateway;
pub mod gateway_report;
pub mod gateway_setup;

#[allow(dead_code)]
mod client;
#[cfg(test)]
pub use sekai_chisei::config;
#[allow(dead_code)]
mod domain;
mod egress;
mod enterprise;
mod gateway_support;
#[allow(dead_code)]
mod harness;
pub mod obs;
mod secrets;

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
