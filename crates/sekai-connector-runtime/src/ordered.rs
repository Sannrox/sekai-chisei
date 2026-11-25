//! One ordered sync (ADR 0023): a type that declares
//! [`Operation::ReadChanges`] syncs a generation snapshot, then change
//! pages after the plane-owned offset.
//!
//! Every page starts from the plane's state, so a runtime that dies
//! mid-sync loses nothing: the next holder reads the same generation,
//! cursor and offset and goes on. The Source's own position (such as a log
//! position) lives only in the opaque cursor (ADR 0118); the offset the
//! plane fences on is the contiguous `source_sequence`, numbered by the
//! connector from the committed offset. A gap or a lost feed moves the
//! generation to recovery-required, and the next page starts the next
//! generation's snapshot; nothing else resets the offset.

use sekai_client::protocol::sekai::{
    self as pb, ApplySourceBatchRequest, ApplySourceBatchResponse, ConnectorSource,
    GetSourceSyncStateRequest, GetSourceSyncStateResponse, SourceSyncGenerationStatus,
};
use sekai_client::{CallOptions, CoreLoopClient, GrpcTransport};
use sekai_source_sdk::{
    ChangeFeedPage, ConfigValue, GenerationSnapshotPage, MAX_SOURCE_BATCH_RECORDS,
    SourceAdapterConfig, SourceDeliveryMode, SourceDeliveryWindow, SourceRecord,
    build_registered_source_batch_v2,
};
use std::sync::Arc;

use crate::pages::{MAX_PAGES, plane_failure, to_proto};
use crate::runtime::Runtime;
use crate::sync::{Prepared, SyncFailure, blocking};

/// Where the Source's current generation stands, as the next page needs it.
#[derive(Debug, PartialEq, Eq)]
enum Phase {
    /// Read the snapshot of `generation` after `cursor`.
    Snapshot {
        generation: u64,
        cursor: Option<String>,
    },
    /// Read changes after `offset` in `epoch`, from `cursor`.
    Feed {
        generation: u64,
        epoch: String,
        offset: u64,
        cursor: String,
    },
}

impl Phase {
    /// The phase the plane's state asks for. A Source with no generation
    /// starts at one; recovery starts the next generation's snapshot from
    /// the committed cursor, which the connector does not resume from.
    fn of(state: &pb::SourceSyncState) -> Result<Self, SyncFailure> {
        let cursor = state
            .checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.cursor.clone())
            .filter(|cursor| !cursor.is_empty());
        let Some(generation) = state.current_generation.as_ref() else {
            // A v1 cursor without a generation is not an ordered Source.
            return match cursor {
                None => Ok(Self::Snapshot {
                    generation: 1,
                    cursor,
                }),
                Some(_) => Err(SyncFailure::Invalid),
            };
        };
        match (generation.status(), generation.delivery_mode()) {
            (SourceSyncGenerationStatus::Snapshotting, pb::SourceDeliveryMode::Snapshot) => {
                Ok(Self::Snapshot {
                    generation: generation.sync_generation,
                    cursor,
                })
            }
            (SourceSyncGenerationStatus::Active, pb::SourceDeliveryMode::ChangeFeed) => {
                match (
                    generation.source_feed_epoch.clone(),
                    generation.committed_offset,
                    cursor,
                ) {
                    (Some(epoch), Some(offset), Some(cursor)) if !epoch.is_empty() => {
                        Ok(Self::Feed {
                            generation: generation.sync_generation,
                            epoch,
                            offset,
                            cursor,
                        })
                    }
                    _ => Err(SyncFailure::Invalid),
                }
            }
            (SourceSyncGenerationStatus::RecoveryRequired, _) => Ok(Self::Snapshot {
                generation: generation
                    .sync_generation
                    .checked_add(1)
                    .ok_or(SyncFailure::Invalid)?,
                cursor,
            }),
            _ => Err(SyncFailure::Invalid),
        }
    }
}

/// One page as a batch to apply, or the sync's end.
enum Step {
    Apply {
        cursor: Option<String>,
        proposed_next_cursor: String,
        collected_at_ms: i64,
        records: Vec<SourceRecord>,
        delivery: SourceDeliveryWindow,
        /// The page ends this sync once it commits.
        last: bool,
    },
    Done,
}

/// A snapshot page as a batch. The terminal page carries the feed epoch
/// and the barrier offset; no other page may.
fn snapshot_step(
    generation: u64,
    cursor: Option<String>,
    page: GenerationSnapshotPage,
) -> Result<Step, SyncFailure> {
    let terminal = match (&page.source_feed_epoch, page.handoff_offset) {
        (Some(epoch), Some(_)) if page.complete && !epoch.is_empty() => true,
        (None, None) if !page.complete => false,
        _ => return Err(SyncFailure::Invalid),
    };
    if page.records.is_empty()
        || page.proposed_next_cursor.is_empty()
        || cursor.as_ref() == Some(&page.proposed_next_cursor)
    {
        return Err(SyncFailure::Invalid);
    }
    Ok(Step::Apply {
        cursor,
        proposed_next_cursor: page.proposed_next_cursor,
        collected_at_ms: page.collected_at_ms,
        records: page.records,
        delivery: SourceDeliveryWindow {
            mode: SourceDeliveryMode::Snapshot,
            sync_generation: generation,
            source_feed_epoch: page.source_feed_epoch,
            offset_start: None,
            offset_end: page.handoff_offset,
            snapshot_complete: terminal,
        },
        // The feed continues in the same sync.
        last: false,
    })
}

/// A change page as a batch. Its records carry the contiguous sequences
/// after the committed offset; an empty page is valid only as caught up
/// and commits nothing.
fn feed_step(
    generation: u64,
    epoch: String,
    offset: u64,
    cursor: String,
    page: ChangeFeedPage,
) -> Result<Step, SyncFailure> {
    if page.offset_start != offset {
        return Err(SyncFailure::Invalid);
    }
    if page.records.is_empty() {
        return if page.caught_up {
            Ok(Step::Done)
        } else {
            Err(SyncFailure::Invalid)
        };
    }
    let mut expected = offset;
    for record in &page.records {
        expected = expected.checked_add(1).ok_or(SyncFailure::Invalid)?;
        if record.source_sequence != Some(expected) {
            return Err(SyncFailure::Invalid);
        }
    }
    if page.proposed_next_cursor.is_empty() || page.proposed_next_cursor == cursor {
        return Err(SyncFailure::Invalid);
    }
    Ok(Step::Apply {
        cursor: Some(cursor),
        proposed_next_cursor: page.proposed_next_cursor,
        collected_at_ms: page.collected_at_ms,
        records: page.records,
        delivery: SourceDeliveryWindow {
            mode: SourceDeliveryMode::ChangeFeed,
            sync_generation: generation,
            source_feed_epoch: Some(epoch),
            offset_start: Some(offset),
            offset_end: Some(expected),
            snapshot_complete: false,
        },
        last: page.caught_up,
    })
}

impl Runtime {
    /// Applies the Source's snapshot pages, then its change pages, from
    /// the plane's state until the feed is caught up or [`MAX_PAGES`] have
    /// applied. A refused batch fails the sync as invalid unless the plane
    /// moved the generation to recovery, which the next page starts.
    pub(crate) async fn sync_ordered(
        &self,
        index: usize,
        source: &ConnectorSource,
        prepared: Prepared,
    ) -> Result<(), SyncFailure> {
        let type_digest = match prepared.config.get("type_digest") {
            Some(ConfigValue::Text(digest)) if !digest.is_empty() => digest.clone(),
            _ => return Err(SyncFailure::Invalid),
        };
        let client = &self.clients[index];
        let adapter = SourceAdapterConfig {
            namespace: source.namespace.clone(),
            producer_identity: client.config().principal.clone(),
            source_instance: source.source_instance.clone(),
            type_digest,
        };
        let prepared = Arc::new(prepared);
        for _ in 0..MAX_PAGES {
            let state = sync_state(client, &adapter).await?;
            // A batch another producer left open settles first.
            if state.open_transaction.is_some() {
                return Err(SyncFailure::Unavailable);
            }
            let (connectors, reading) = (self.connectors.clone(), prepared.clone());
            let step = match Phase::of(&state)? {
                Phase::Snapshot { generation, cursor } => {
                    let after = cursor.clone();
                    let page = blocking(move || {
                        connectors.read_snapshot_page(
                            &reading,
                            after.as_deref(),
                            MAX_SOURCE_BATCH_RECORDS,
                        )
                    })
                    .await?;
                    snapshot_step(generation, cursor, page)?
                }
                Phase::Feed {
                    generation,
                    epoch,
                    offset,
                    cursor,
                } => {
                    let reading_epoch = epoch.clone();
                    let page = blocking(move || {
                        connectors.read_changes(
                            &reading,
                            &reading_epoch,
                            offset,
                            MAX_SOURCE_BATCH_RECORDS,
                        )
                    })
                    .await?;
                    feed_step(generation, epoch, offset, cursor, page)?
                }
            };
            let Step::Apply {
                cursor,
                proposed_next_cursor,
                collected_at_ms,
                mut records,
                delivery,
                last,
            } = step
            else {
                return Ok(());
            };
            for record in &mut records {
                record.source = source.source.clone();
                record.source_instance = source.source_instance.clone();
            }
            let batch = build_registered_source_batch_v2(
                &adapter,
                &source.source,
                cursor.as_deref().unwrap_or_default(),
                &proposed_next_cursor,
                collected_at_ms,
                records,
                delivery,
            )
            .map_err(|_| SyncFailure::Invalid)?;
            let applied: ApplySourceBatchResponse = client
                .raw()
                .unary(
                    "/sekai.SekaiService/ApplySourceBatch",
                    ApplySourceBatchRequest {
                        batch: Some(to_proto(batch, &source.source_id)),
                    },
                    CallOptions::new(),
                )
                .await
                .map_err(plane_failure)?;
            let committed = applied
                .result
                .and_then(|result| result.transaction)
                .is_some_and(|transaction| transaction.status == "COMMITTED");
            if !committed {
                // A gap the plane caught leaves the generation in
                // recovery; the next page starts the next snapshot. Any
                // other refusal holds the cursor for an operator.
                let after = sync_state(client, &adapter).await?;
                let recovering = after.current_generation.is_some_and(|generation| {
                    generation.status() == SourceSyncGenerationStatus::RecoveryRequired
                });
                if !recovering {
                    return Err(SyncFailure::Invalid);
                }
                continue;
            }
            if last {
                return Ok(());
            }
        }
        Ok(())
    }
}

async fn sync_state(
    client: &CoreLoopClient<GrpcTransport>,
    adapter: &SourceAdapterConfig,
) -> Result<pb::SourceSyncState, SyncFailure> {
    let state: GetSourceSyncStateResponse = client
        .raw()
        .unary(
            "/sekai.SekaiService/GetSourceSyncState",
            GetSourceSyncStateRequest {
                namespace: adapter.namespace.clone(),
                source_instance: adapter.source_instance.clone(),
                type_digest: adapter.type_digest.clone(),
            },
            CallOptions::new(),
        )
        .await
        .map_err(plane_failure)?;
    Ok(state.state.filter(|_| state.found).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(
        status: SourceSyncGenerationStatus,
        mode: pb::SourceDeliveryMode,
        cursor: &str,
    ) -> pb::SourceSyncState {
        pb::SourceSyncState {
            checkpoint: Some(pb::SourceCheckpoint {
                cursor: cursor.into(),
                ..Default::default()
            }),
            current_generation: Some(pb::SourceSyncGeneration {
                sync_generation: 4,
                status: status as i32,
                delivery_mode: mode as i32,
                source_feed_epoch: Some("e".into()),
                committed_offset: Some(9),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Only a next-generation snapshot leaves recovery; a cursor with no
    /// generation behind it is not an ordered Source.
    #[test]
    fn recovery_starts_the_next_generation_and_a_bare_cursor_is_refused() {
        assert_eq!(
            Phase::of(&state(
                SourceSyncGenerationStatus::RecoveryRequired,
                pb::SourceDeliveryMode::ChangeFeed,
                "log/9",
            )),
            Ok(Phase::Snapshot {
                generation: 5,
                cursor: Some("log/9".into()),
            })
        );
        assert_eq!(
            Phase::of(&state(
                SourceSyncGenerationStatus::Superseded,
                pb::SourceDeliveryMode::ChangeFeed,
                "log/9",
            )),
            Err(SyncFailure::Invalid)
        );
        let mut bare = state(
            SourceSyncGenerationStatus::Active,
            pb::SourceDeliveryMode::ChangeFeed,
            "v1",
        );
        bare.current_generation = None;
        assert_eq!(Phase::of(&bare), Err(SyncFailure::Invalid));
    }
}
