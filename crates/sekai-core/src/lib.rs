//! Durable Sekai graph, audit, lineage, security, coordination, and persistence.
//!
//! This crate sits below composition, gRPC, and Chisei. The root crate
//! re-exports `db` and `sekai` until a follow-up removes those aliases.

pub use sekai_domain::{domain, enterprise};

pub mod compliance_export;
pub mod db;
pub mod runtime_backend;
pub mod sekai;
pub mod shomei;
pub mod source_adapter_catalog;

/// Store and Sekai observability: closed labels, signals, and metrics.
pub mod obs {
    pub use sekai_obs::{labels, signals};

    pub mod correlation {
        pub use sekai_obs::correlation::Stage;
    }

    /// Metrics wrapper so `sekai_build_info.version` is this crate when tests
    /// install the recorder before the root binary does.
    pub mod metrics {
        pub use sekai_obs::metrics::{
            db_lock_poisoned_total, record_db_lock_poisoned, search_index_lag_ms,
            set_embedding_index_lag_ms, set_search_index_lag_ms,
        };

        pub fn handle() -> &'static sekai_obs::metrics::PrometheusHandle {
            sekai_obs::metrics::handle(env!("CARGO_PKG_VERSION"))
        }
    }
}
