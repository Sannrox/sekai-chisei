//! Shared domain types, identity-extension contracts, and secret resolution.
//!
//! This crate has no OpenTelemetry, gRPC, or storage dependencies. The root
//! control plane and `chisei-gateway` both depend on it so those copies cannot
//! drift. Operation receipts and gateway key hashing live here so Sekai can use
//! them without depending on the Chisei provider crate.

pub mod domain;
pub mod enterprise;
pub mod gateway_keys;
pub mod receipt;
pub mod secrets;
