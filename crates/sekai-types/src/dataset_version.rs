//! Dataset version snapshots and append-only rollback (#1412).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DATASET_VERSION_PAST_RETENTION: &str = "dataset version is past retention";
pub const DATASET_VERSION_NOT_FOUND: &str = "dataset version not found";
pub const DATASET_NOT_FOUND: &str = "dataset not found";
pub const DATASET_ROLLBACK_REQUIRES_RESTORE: &str = "restore_from_version_id is required";
/// Prefix of the refusal for rolling back a dataset that an object type index
/// derives objects from (#2415): the index would keep the rolled-back rows.
pub const DATASET_ROLLBACK_BACKS_INDEX: &str = "dataset backs an object type index";

/// The refusal naming the object type index a rollback would leave behind.
pub fn rollback_backs_index_error(namespace: &str, kind: &str) -> String {
    format!(
        "{DATASET_ROLLBACK_BACKS_INDEX} ({namespace}/{kind}); rollback would leave its \
         derived objects on the rolled-back rows"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DatasetVersion {
    pub dataset_id: String,
    pub version_id: String,
    pub seq: i64,
    pub created_at_ms: i64,
    pub actor: String,
    pub tenant: String,
    pub reason: String,
    pub restored_from_version_id: String,
    pub row_count: i32,
    pub purged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DatasetRollback {
    pub dataset_id: String,
    pub restore_from_version_id: String,
    pub reason: String,
    pub actor: String,
    pub tenant: String,
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub fn version_id(dataset_id: &str, seq: i64, created_at_ms: i64, row_jsons: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.dataset-version\n");
    hasher.update(dataset_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(seq.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(created_at_ms.to_string().as_bytes());
    hasher.update(b"\n");
    for row in row_jsons {
        hasher.update(row.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// The id of a `span` version (ADR 0172 decision 6). It chains to the
/// previous version id (empty for the first version) and hashes only the rows
/// this version changed, so its cost follows the change, not the dataset:
/// `changed` lists every row of a `snapshot`, or the closed row ids and the
/// added rows of an `append` or `update`, in the order they were applied.
pub fn span_version_id(
    dataset_id: &str,
    seq: i64,
    created_at_ms: i64,
    kind: &str,
    previous_version_id: &str,
    changed: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.dataset-version.span\n");
    for field in [
        dataset_id,
        &seq.to_string(),
        &created_at_ms.to_string(),
        kind,
        previous_version_id,
    ] {
        hasher.update(field.as_bytes());
        hasher.update(b"\n");
    }
    for row in changed {
        hasher.update(row.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub fn encode_row_map(row: &HashMap<String, String>) -> Result<String, String> {
    serde_json::to_string(row).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_id_is_stable_for_the_same_snapshot() {
        let rows = ["{\"a\":\"1\"}".into(), "{\"a\":\"2\"}".into()];
        assert_eq!(
            version_id("ds", 1, 10, &rows),
            version_id("ds", 1, 10, &rows)
        );
        assert_ne!(
            version_id("ds", 1, 10, &rows),
            version_id("ds", 2, 10, &rows)
        );
    }
}
