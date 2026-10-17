//! Stable Sekai values shared by the control plane and the future store crate.
//!
//! This crate has no gRPC, storage, or OpenTelemetry dependencies. `chisei-gateway`
//! does not depend on it: these types are plane and store vocabulary, not the
//! gateway-shared slice in `sekai-domain`.

pub mod classification_lattice;
pub mod dataset_version;
pub mod evidence;
pub mod evidence_vocabulary;
pub mod json;
pub mod markings;
pub mod object_security;
pub mod policy_decision;
pub mod purpose_authorization;
pub mod service_principal;
