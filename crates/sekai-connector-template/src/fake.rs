//! Fixed in-memory source for local development and the conformance tests.
//! Two pages of `Item` records, then completion.

use sekai_source_sdk::{
    ConnectionFailure, DiscoveredColumn, DiscoveredRecordKind, SOURCE_DISCOVERY_VERSION,
    SnapshotPage, SnapshotPageSource, SnapshotRead, SnapshotSourceFailure, SourceDiscovery,
    SourceInspector, SourceRecord,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const RECORD_KIND: &str = "Item";
pub const SCHEMA_REVISION: &str = "v1";
const PAGES: [&[(&str, &str)]; 2] = [
    &[("item-1", "First item"), ("item-2", "Second item")],
    &[("item-3", "Third item")],
];

pub struct FakeSource {
    source: String,
    source_instance: String,
    records_read: u64,
}

impl FakeSource {
    pub fn new(source: impl Into<String>, source_instance: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            source_instance: source_instance.into(),
            records_read: 0,
        }
    }

    pub fn records_read(&self) -> u64 {
        self.records_read
    }

    fn record(&self, id: &str, name: &str) -> SourceRecord {
        let properties = BTreeMap::from([("id".into(), id.into()), ("name".into(), name.into())]);
        let canonical = serde_json::to_vec(&properties).expect("string map serializes");
        SourceRecord {
            source: self.source.clone(),
            source_instance: self.source_instance.clone(),
            external_id: id.into(),
            source_version: "1".into(),
            type_name: RECORD_KIND.into(),
            display_name: name.into(),
            payload_digest: format!("sha256:{:x}", Sha256::digest(canonical)),
            properties,
            deleted: false,
            observed_at_ms: 1_000,
            source_sequence: None,
        }
    }
}

impl SourceInspector for FakeSource {
    fn check(&mut self) -> Result<(), ConnectionFailure> {
        Ok(())
    }

    fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure> {
        let column = |name: &str| DiscoveredColumn {
            name: name.into(),
            data_type: "string".into(),
            nullable: false,
            profile: None,
        };
        Ok(SourceDiscovery {
            contract_version: SOURCE_DISCOVERY_VERSION.into(),
            source: self.source.clone(),
            record_kinds: vec![DiscoveredRecordKind {
                record_kind: RECORD_KIND.into(),
                schema_revision: SCHEMA_REVISION.into(),
                columns: vec![column("id"), column("name")],
                key_candidates: vec![vec!["id".into()]],
            }],
        })
    }
}

impl SnapshotPageSource for FakeSource {
    fn read_page(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<SnapshotRead, SnapshotSourceFailure> {
        let next = match committed_cursor {
            None => 0,
            Some(cursor) => cursor
                .strip_prefix("page-")
                .and_then(|page| page.parse::<usize>().ok())
                .ok_or(SnapshotSourceFailure::Invalid)?,
        };
        let Some(rows) = PAGES.get(next) else {
            return Ok(SnapshotRead::Complete);
        };
        if rows.len() > max_records {
            return Err(SnapshotSourceFailure::Invalid);
        }
        self.records_read += rows.len() as u64;
        Ok(SnapshotRead::Page(SnapshotPage {
            records: rows
                .iter()
                .map(|(id, name)| self.record(id, name))
                .collect(),
            proposed_next_cursor: format!("page-{}", next + 1),
            collected_at_ms: 1_000 + next as i64,
            complete: next + 1 == PAGES.len(),
        }))
    }
}
