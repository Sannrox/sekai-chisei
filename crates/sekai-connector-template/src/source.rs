//! The real source. Replace each stub with calls to the source system.

use sekai_source_sdk::{
    ChangeFeedPage, ChangeFeedSource, ChangeFeedSourceFailure, ConnectionFailure,
    SnapshotPageSource, SnapshotRead, SnapshotSourceFailure, SourceDiscovery, SourceInspector,
};

pub struct Source {
    /// Source credential, read from the configured environment variable.
    /// Keep it in memory only: never log it or put it in records.
    #[allow(dead_code)]
    credential: Option<String>,
}

impl Source {
    pub fn new(credential: Option<String>) -> Self {
        Self { credential }
    }
}

impl SourceInspector for Source {
    /// Connect and authenticate without reading records.
    fn check(&mut self) -> Result<(), ConnectionFailure> {
        Err(ConnectionFailure::Unreachable)
    }

    /// List record kinds, columns, and key candidates. See `fake.rs`.
    fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure> {
        Err(ConnectionFailure::Unreachable)
    }
}

impl SnapshotPageSource for Source {
    /// `read_batch`: return the page after `committed_cursor`, at most
    /// `max_records` normalized records, and an opaque next cursor.
    fn read_page(
        &mut self,
        _committed_cursor: Option<&str>,
        _max_records: usize,
    ) -> Result<SnapshotRead, SnapshotSourceFailure> {
        Err(SnapshotSourceFailure::Unavailable)
    }
}

impl ChangeFeedSource for Source {
    /// Optional `read_changes`. Keep `UnsupportedOrdering` unless the source
    /// has a stable epoch and a contiguous, monotonic sequence.
    fn read_change_feed(
        &mut self,
        _source_feed_epoch: &str,
        _committed_offset: u64,
        _max_records: usize,
    ) -> Result<ChangeFeedPage, ChangeFeedSourceFailure> {
        Err(ChangeFeedSourceFailure::UnsupportedOrdering)
    }
}
