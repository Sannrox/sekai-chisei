//! Composition code that holds both planes (ADR 0092 rule 4).
//!
//! Chisei never names Sekai and Sekai never opens the Chisei store. Code that
//! needs both store handles, in-process implementations of Chisei-owned ports,
//! and Chisei features that answer directly from the Sekai graph live here,
//! next to the gRPC wiring that assembles the planes.

pub mod action_policy_dry_run;
pub mod capability;
pub mod cross_store_admission;
pub mod embedding_catch_up;
pub mod function_revision_gate;
pub mod gateway_egress_policy;
pub mod gateway_log_reader;
pub mod invoice_extraction_eval;
pub use chisei_core::lookup_first;
pub mod sekai_facts;
pub mod sekai_principal;
pub use chisei_core::transform_run_admission;

#[cfg(test)]
mod system_one_fill_tests;
