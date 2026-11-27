//! Benchmark, soak, and conformance drivers for the control plane.
//!
//! These sit above `sekai-chisei` so editing a driver rebuilds only this
//! crate. The `game-soak`, `perf-gate`, `replica-conformance`, and
//! `relational-snapshot-rehearsal` binaries and the `control_plane` bench
//! are their entry points.

pub mod game_soak;
pub mod harness;
pub mod perf_object_path;
pub mod perf_regression;
pub mod perf_signals;
pub mod relational_snapshot;
