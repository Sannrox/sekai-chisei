pub mod gateway;
pub mod gateway_report;
pub mod gateway_setup;

#[allow(dead_code)]
mod client;
#[cfg(test)]
pub use sekai_chisei::config;
#[allow(dead_code)]
mod domain;
mod enterprise;
#[allow(dead_code)]
mod harness;
pub mod obs;
mod secrets;

pub use sekai_provider::{
    cost_estimate, gateway_keys, llm, model_availability, pricing, provider_profile,
    provider_resolution,
};

mod chisei {
    pub mod egress;

    pub mod model_availability {
        pub use sekai_provider::model_availability::*;
    }

    pub mod model_routing {
        pub fn is_cheap_eligible_task_class(task_class: &str) -> bool {
            matches!(
                task_class.trim().to_ascii_lowercase().as_str(),
                "background" | "bulk" | "batch" | "small_fast" | "small-fast"
            )
        }
    }

    pub mod receipt {
        pub use sekai_provider::receipt::*;
    }
}

mod db {
    pub mod chisei_budget {
        pub const METRIC_REQUESTS: &str = "requests";
    }

    #[cfg(test)]
    pub use sekai_chisei::db::sekai;
}

mod grpc {
    pub mod client {
        pub use crate::client::*;
    }

    pub mod pb {
        pub use sekai_proto::{chisei, sekai};
    }

    #[cfg(test)]
    pub use sekai_chisei::grpc::{chisei_service, sekai_service};
}

mod sekai {
    pub mod dataset {
        #[cfg(test)]
        pub use sekai_chisei::sekai::dataset::RowQuery;

        pub fn llm_call_column_classification(name: &str) -> &'static str {
            if matches!(
                name,
                "request_id" | "agent" | "user_id" | "key_id" | "work_unit_id" | "refusal_reason"
            ) {
                "sensitive"
            } else if matches!(
                name,
                "project" | "route_bias" | "policy_scope" | "policy_version"
            ) {
                "internal"
            } else {
                "public"
            }
        }
    }

    pub mod schema {
        pub fn is_restricted_property_classification(value: &str) -> bool {
            matches!(value.trim(), "internal" | "sensitive")
        }
    }

    #[cfg(test)]
    pub use sekai_chisei::sekai::{audit, security};
}
