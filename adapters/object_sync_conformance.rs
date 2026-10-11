//! Reusable offline conformance checks for source-sync transports and outboxes.
//!
//! Implementation lives in `sekai-source-sdk`.
#![allow(unused_imports)]

pub use sekai_source_sdk::{
    LifecycleConformanceReport, LifecycleFixture, LifecycleObservation, LifecycleProjection,
    LifecycleStage, OBJECT_SYNC_LIFECYCLE_CONFORMANCE_VERSION, assert_cross_page_identity,
    assert_deterministic_batch, assert_files_omit, assert_lifecycle_report, assert_snapshot_chain,
    github_issue_lifecycle_fixture, run_lifecycle_fixture, run_restart_and_commit,
};
