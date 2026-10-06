//! Composition code that holds both planes (ADR 0092 rule 4).
//!
//! Chisei never names Sekai and Sekai never opens the Chisei store. Code that
//! needs both store handles, in-process implementations of Chisei-owned ports,
//! and Chisei features that answer directly from the Sekai graph live here,
//! next to the gRPC wiring that assembles the planes.

pub mod cross_store_admission;
pub mod lookup_first;
pub mod remote_sekai;
pub mod sekai_facts;
