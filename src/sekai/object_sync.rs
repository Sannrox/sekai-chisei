//! Bounded inbound object sync from one system of record.
//!
//! This is not a pipeline product. It maps one external record onto one
//! Sekai object identity with refresh, tombstone, and conflict rules.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SOURCE_GITHUB: &str = "github";
pub const FAMILY_OBJECT_SYNC: &str = "source_control.object_sync";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub source: String,
    pub source_instance: String,
    pub external_id: String,
    pub type_name: String,
    pub display_name: String,
    pub payload_digest: String,
    pub deleted: bool,
    pub observed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncedObject {
    pub object_id: String,
    pub type_name: String,
    pub source_id: String,
    pub payload_digest: String,
    pub tombstoned: bool,
    pub type_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncDecision {
    Upsert(SyncedObject),
    Tombstone(SyncedObject),
    Conflict { source_id: String, reason: String },
    Reject { reason: String },
}

pub fn source_id(source: &str, instance: &str, external_id: &str) -> String {
    format!("{source}:{instance}#{external_id}")
}

pub fn object_id_for(type_digest: &str, source_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(type_digest.as_bytes());
    hasher.update(b"\n");
    hasher.update(source_id.as_bytes());
    format!("sync-{:x}", hasher.finalize())
}

/// Map one GitHub issue or pull-request observation onto a sync decision.
pub fn sync_github_record(record: SourceRecord, type_digest: &str) -> SyncDecision {
    if record.source != SOURCE_GITHUB {
        return SyncDecision::Reject {
            reason: "source is not the GitHub dogfood system of record".into(),
        };
    }
    if type_digest.trim().is_empty() {
        return SyncDecision::Reject {
            reason: "type_digest is required".into(),
        };
    }
    if record.external_id.trim().is_empty() || record.source_instance.trim().is_empty() {
        return SyncDecision::Reject {
            reason: "source instance and external id are required".into(),
        };
    }
    if record.type_name != "Issue" && record.type_name != "PullRequest" {
        return SyncDecision::Reject {
            reason: "GitHub sync admits Issue and PullRequest only".into(),
        };
    }
    let source = source_id(&record.source, &record.source_instance, &record.external_id);
    let object = SyncedObject {
        object_id: object_id_for(type_digest, &source),
        type_name: record.type_name,
        source_id: source,
        payload_digest: record.payload_digest,
        tombstoned: record.deleted,
        type_digest: type_digest.to_string(),
    };
    if record.deleted {
        SyncDecision::Tombstone(object)
    } else {
        SyncDecision::Upsert(object)
    }
}

/// Detect a conflicting refresh when the same source identity would change
/// object id for a type revision.
pub fn detect_identity_conflict(
    existing: &SyncedObject,
    incoming: &SyncedObject,
) -> Option<String> {
    if existing.source_id != incoming.source_id {
        return None;
    }
    if existing.type_digest != incoming.type_digest {
        return Some("source identity moved across type revisions".into());
    }
    if existing.object_id != incoming.object_id {
        return Some("source identity mapped to a different object id".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue() -> SourceRecord {
        SourceRecord {
            source: SOURCE_GITHUB.into(),
            source_instance: "acme/ops".into(),
            external_id: "12".into(),
            type_name: "Issue".into(),
            display_name: "Broken deploy".into(),
            payload_digest: "sha256:1".into(),
            deleted: false,
            observed_at_ms: 10,
        }
    }

    #[test]
    fn github_issue_upserts_stable_object_id() {
        let first = match sync_github_record(issue(), "sha256:types") {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        let second = match sync_github_record(issue(), "sha256:types") {
            SyncDecision::Upsert(object) => object,
            other => panic!("expected upsert, got {other:?}"),
        };
        assert_eq!(first.object_id, second.object_id);
        assert_eq!(first.source_id, "github:acme/ops#12");
        assert!(!first.tombstoned);
    }

    #[test]
    fn deleted_github_record_tombstones() {
        let mut record = issue();
        record.deleted = true;
        match sync_github_record(record, "sha256:types") {
            SyncDecision::Tombstone(object) => assert!(object.tombstoned),
            other => panic!("expected tombstone, got {other:?}"),
        }
    }

    #[test]
    fn foreign_source_is_rejected() {
        let mut record = issue();
        record.source = "jira".into();
        match sync_github_record(record, "sha256:types") {
            SyncDecision::Reject { reason } => assert!(reason.contains("GitHub")),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn type_revision_change_is_a_conflict() {
        let upserted = match sync_github_record(issue(), "sha256:a") {
            SyncDecision::Upsert(object) => object,
            other => panic!("{other:?}"),
        };
        let moved = match sync_github_record(issue(), "sha256:b") {
            SyncDecision::Upsert(object) => object,
            other => panic!("{other:?}"),
        };
        assert!(detect_identity_conflict(&upserted, &moved).is_some());
    }
}
