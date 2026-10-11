//! Dependency-light helper for out-of-process source-sync adapters.
//!
//! Implementation lives in `sekai-source-sdk`.
#![allow(unused_imports)]

pub use sekai_source_sdk::{
    ApplySourceBatchReply, DEFAULT_MAX_ENTRY_BYTES, DEFAULT_MAX_PENDING_FILES, FlushDisposition,
    FlushEntry, FlushReport, GetSourceSyncStateInput, MAX_QUARANTINE_REASON_BYTES,
    OUTBOX_FORMAT_VERSION, OutboxLimits, SourceAdapterConfig, SourceGenerationStatus, SourceOutbox,
    SourceRunDisposition, SourceRunReport, SourceSyncStateView, SourceSyncTransport,
    TransportFailure, build_source_batch, build_source_batch_v2, serialize_source_batch,
};
