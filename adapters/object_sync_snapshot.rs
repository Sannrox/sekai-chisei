//! Bounded checkpoint-driven snapshot transport for source-sync adapters.
//!
//! Implementation lives in `sekai-source-sdk`.
#![allow(unused_imports)]

pub use sekai_source_sdk::{
    DEFAULT_MAX_SNAPSHOT_PAGES_PER_RUN, GenerationSnapshotPage, GenerationSnapshotRead,
    GenerationSnapshotSource, SnapshotPage, SnapshotPageSource, SnapshotRead, SnapshotRunError,
    SnapshotRunLimits, SnapshotRunOutcome, SnapshotSourceFailure, run_generation_snapshot_v2,
    run_snapshot,
};
