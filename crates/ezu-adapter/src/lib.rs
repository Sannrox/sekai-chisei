//! Host process for the Ezu adapter (#3563).
//!
//! The runners live in `adapters/ezu.rs` (#2182). This crate is the
//! deployment that runs them: Tenkai's dependency document decides whether
//! an Ezu engine is present, a sealed Secret supplies the Ezu URL and
//! bearer, and two replicas fence each feed or binding with plane leases.

#[path = "../../../adapters/ezu.rs"]
pub mod ezu;

pub mod host;
pub mod http;
