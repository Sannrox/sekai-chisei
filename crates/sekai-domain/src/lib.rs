//! Shared domain types, identity-extension contracts, and secret resolution.
//!
//! This crate has no OpenTelemetry, gRPC, or storage dependencies. The root
//! control plane and `chisei-gateway` both depend on it so those copies cannot
//! drift.

pub mod domain;
pub mod enterprise;
pub mod secrets;
