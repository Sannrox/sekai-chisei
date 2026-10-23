//! Reference offline replica for sync scopes (`sekai.sync/v1`, #1632, #1633).
//!
//! It shows how a client applies snapshot pages and deltas, and the rules it
//! must keep:
//!
//! - an upsert replaces the whole object;
//! - a removal drops it;
//! - a purge deletes what the caller may no longer read, whether a whole
//!   object or only the listed properties;
//! - after `offline_until_ms` the data is not shown until the client syncs
//!   again; a delta renews that time only when it leaves nothing pending;
//! - nothing is shown until a snapshot is complete, and a resnapshot
//!   discards the data.

use sekai_proto::sekai::{Object, ReadSyncDeltasResponse, ReadSyncSnapshotResponse};
use std::collections::BTreeMap;

/// Why a replica refused to show its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicaError {
    /// The scope's maximum offline age passed at this time: sync again.
    MustResync { offline_until_ms: i64 },
    /// The server ended the cursor: take a new snapshot.
    ResnapshotRequired,
    /// A snapshot is still being read.
    SnapshotIncomplete,
}

/// The objects of one scope as the client holds them, and its cursor.
#[derive(Debug, Clone, Default)]
pub struct SyncReplica {
    objects: BTreeMap<String, Object>,
    cursor: String,
    offline_until_ms: i64,
    resnapshot: bool,
    complete: bool,
}

impl SyncReplica {
    /// Apply one snapshot page. The first page of a new snapshot starts the
    /// replica over.
    pub fn apply_snapshot_page(&mut self, page: &ReadSyncSnapshotResponse, first: bool) {
        if first {
            *self = Self::default();
        }
        for object in &page.objects {
            self.objects.insert(object.id.clone(), object.clone());
        }
        if !page.cursor.is_empty() {
            self.cursor = page.cursor.clone();
            self.offline_until_ms = page.offline_until_ms;
            self.complete = true;
        }
    }

    /// Apply one delta read.
    pub fn apply_deltas(&mut self, deltas: &ReadSyncDeltasResponse) {
        if deltas.resnapshot_required {
            // The data may include what the caller can no longer read.
            *self = Self {
                resnapshot: true,
                ..Self::default()
            };
            return;
        }
        for object in &deltas.upserts {
            self.objects.insert(object.id.clone(), object.clone());
        }
        for id in &deltas.removed_object_ids {
            self.objects.remove(id);
        }
        for purge in &deltas.purges {
            if purge.properties.is_empty() {
                self.objects.remove(&purge.object_id);
            } else if let Some(object) = self.objects.get_mut(&purge.object_id) {
                for property in &purge.properties {
                    object.properties.remove(property);
                }
            }
        }
        self.cursor = deltas.cursor.clone();
        if deltas.offline_until_ms != 0 {
            self.offline_until_ms = deltas.offline_until_ms;
        }
    }

    /// The cursor to read the next deltas from.
    pub fn cursor(&self) -> &str {
        &self.cursor
    }

    /// The data to show at `now_ms`, unless the replica must sync first.
    pub fn view(&self, now_ms: i64) -> Result<&BTreeMap<String, Object>, ReplicaError> {
        if self.resnapshot {
            return Err(ReplicaError::ResnapshotRequired);
        }
        if !self.complete {
            return Err(ReplicaError::SnapshotIncomplete);
        }
        if self.offline_until_ms != 0 && now_ms > self.offline_until_ms {
            return Err(ReplicaError::MustResync {
                offline_until_ms: self.offline_until_ms,
            });
        }
        Ok(&self.objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_proto::sekai::SyncPurge;

    fn object(id: &str, properties: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            properties: properties
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn purges_delete_and_the_offline_age_is_enforced() {
        let mut replica = SyncReplica::default();
        // A first page without a cursor shows nothing yet.
        replica.apply_snapshot_page(
            &ReadSyncSnapshotResponse {
                objects: vec![object("wo-0", &[])],
                next_page_token: "page-2".into(),
                ..Default::default()
            },
            true,
        );
        assert_eq!(
            replica.view(0).unwrap_err(),
            ReplicaError::SnapshotIncomplete
        );
        replica.apply_snapshot_page(
            &ReadSyncSnapshotResponse {
                objects: vec![
                    object("wo-1", &[("site", "north"), ("notes", "gate")]),
                    object("wo-2", &[("site", "north")]),
                ],
                cursor: "pos-1".into(),
                offline_until_ms: 1_000,
                ..Default::default()
            },
            true,
        );
        assert_eq!(replica.view(500).unwrap().len(), 2);
        // Past the maximum offline age the data is not shown.
        assert_eq!(
            replica.view(1_001).unwrap_err(),
            ReplicaError::MustResync {
                offline_until_ms: 1_000
            }
        );
        replica.apply_deltas(&ReadSyncDeltasResponse {
            removed_object_ids: vec!["wo-2".into()],
            purges: vec![
                SyncPurge {
                    object_id: "wo-1".into(),
                    properties: vec!["notes".into()],
                },
                SyncPurge {
                    object_id: "wo-2".into(),
                    properties: Vec::new(),
                },
            ],
            cursor: "pos-2".into(),
            offline_until_ms: 5_000,
            ..Default::default()
        });
        let view = replica.view(2_000).unwrap();
        assert_eq!(view.keys().collect::<Vec<_>>(), ["wo-1"]);
        assert!(!view["wo-1"].properties.contains_key("notes"));
        // A read with changes still pending keeps the deadline.
        replica.apply_deltas(&ReadSyncDeltasResponse {
            cursor: "pos-3".into(),
            more: true,
            ..Default::default()
        });
        assert!(replica.view(5_001).is_err());
        assert_eq!(replica.cursor(), "pos-3");
        replica.apply_deltas(&ReadSyncDeltasResponse {
            resnapshot_required: true,
            ..Default::default()
        });
        assert_eq!(
            replica.view(2_000).unwrap_err(),
            ReplicaError::ResnapshotRequired
        );
        // The data was discarded with the cursor.
        replica.apply_snapshot_page(
            &ReadSyncSnapshotResponse {
                cursor: "pos-9".into(),
                ..Default::default()
            },
            true,
        );
        assert!(replica.view(0).unwrap().is_empty());
    }
}
