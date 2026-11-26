//! An ordered connector type through the connector runtime, against a
//! serving plane (ADR 0023, ADR 0170): a generation snapshot hands off to
//! change pages, each later sync resumes from the plane-owned offset with
//! a fresh connector, and a change page that skips a sequence commits
//! nothing. The connector is a stand-in for the capture child: a shared
//! table and change log, with the log position kept in the cursor.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sekai_chisei::sekai::source::SourceSpec;
use sekai_chisei::sekai::source_type_descriptor::{
    ProposedSourceTypeDescriptor, register_source_type_descriptor,
};
use sekai_client::ClientConfig;
use sekai_connector_runtime::{
    Connectors, CredentialBindings, Ran, Runtime, RuntimeOptions, SyncFailure,
};
use sekai_source_sdk::{
    ChangeFeedPage, ConfigValue, Connector, ConnectorFailure, GenerationSnapshotPage,
    POSTGRES_CAPTURE_CONNECTOR, SourceConfig, SourceRecord, SourceSyncGenerationStatus,
    object_id_for,
};

use crate::connector_runtime_effects::{LEASE, NS, PRINCIPAL, Plane, plane_with};

const EPOCH: &str = "slot-orders-1";

fn descriptor() -> ProposedSourceTypeDescriptor {
    ProposedSourceTypeDescriptor::prepare("orders-db", "Order", "orders-v1").unwrap()
}

fn spec() -> SourceSpec {
    let text = |value: &str| ConfigValue::Text(value.into());
    SourceSpec {
        connector_type: "postgres_capture".into(),
        connector_version: "1".into(),
        config: SourceConfig::from([
            ("endpoint".into(), text("db.internal:5432")),
            ("database".into(), text("orders")),
            ("user".into(), text("capture")),
            ("slot".into(), text("sekai_orders")),
            ("publication".into(), text("sekai_orders")),
            ("record_kind".into(), text("Order")),
            ("type_digest".into(), text(&descriptor().digest)),
        ]),
        credential_ref: "ops/db".into(),
        egress: vec!["db.internal:5432".into()],
        placement: BTreeMap::from([("zone".into(), "eu".into())]),
        every_ms: 60_000,
        owner: "team".into(),
        markings: Vec::new(),
        certification_id: String::new(),
    }
}

fn bindings(dir: &std::path::Path) -> CredentialBindings {
    let password = dir.join("password");
    std::fs::write(&password, format!("pw-{}", std::process::id())).unwrap();
    serde_json::from_value(serde_json::json!({
        "ops/db": {
            "namespaces": [NS],
            "destinations": ["db.internal:5432"],
            "slots": { "password": { "file": password } }
        }
    }))
    .unwrap()
}

/// One row event: the order id, its version, and whether it was deleted.
type Event = (u64, u64, bool);

/// The stand-in's source: the table the snapshot reads and the change log
/// after the snapshot's barrier. `skip` makes the next change page number
/// its first record one past the committed offset plus one.
#[derive(Default)]
struct Database {
    table: BTreeMap<u64, u64>,
    log: Vec<Event>,
    skip: bool,
    opened: usize,
}

type Shared = Arc<Mutex<Database>>;

fn record((id, version, deleted): Event) -> SourceRecord {
    SourceRecord {
        source: String::new(),
        source_instance: String::new(),
        external_id: id.to_string(),
        source_version: version.to_string(),
        type_name: "Order".into(),
        display_name: format!("order {id}"),
        payload_digest: format!("sha256:{:064x}", id * 1_000 + version),
        properties: BTreeMap::new(),
        deleted,
        observed_at_ms: 1,
        source_sequence: None,
        payload: None,
        object_key: None,
    }
}

/// Snapshot pages of two rows, cursor `snapshot/<last id>`; the terminal
/// page hands off at offset 0. Change pages of two events, cursor
/// `log/<position>`, numbered from the committed offset.
struct Capture(Shared);

impl Connector for Capture {
    fn read_snapshot_page(
        &mut self,
        committed_cursor: Option<&str>,
        _max_records: usize,
    ) -> Result<GenerationSnapshotPage, ConnectorFailure> {
        let database = self.0.lock().unwrap();
        let after = committed_cursor
            .and_then(|cursor| cursor.strip_prefix("snapshot/"))
            .map_or(0, |id| id.parse().unwrap());
        let rows: Vec<_> = database.table.range(after + 1..).take(2).collect();
        let last = *rows.last().ok_or(ConnectorFailure::Unreachable)?.0;
        let complete = database.table.range(last + 1..).next().is_none();
        Ok(GenerationSnapshotPage {
            records: rows
                .into_iter()
                .map(|(id, version)| record((*id, *version, false)))
                .collect(),
            proposed_next_cursor: format!("snapshot/{last}"),
            collected_at_ms: 1,
            complete,
            source_feed_epoch: complete.then(|| EPOCH.to_string()),
            handoff_offset: complete.then_some(0),
        })
    }

    fn read_changes(
        &mut self,
        source_feed_epoch: &str,
        committed_offset: u64,
        max_records: usize,
    ) -> Result<ChangeFeedPage, ConnectorFailure> {
        assert_eq!(source_feed_epoch, EPOCH);
        let database = self.0.lock().unwrap();
        let start = usize::try_from(committed_offset).unwrap();
        let events: Vec<_> = database
            .log
            .iter()
            .skip(start)
            .take(2.min(max_records))
            .collect();
        let first = committed_offset + 1 + u64::from(database.skip);
        let end = start + events.len();
        Ok(ChangeFeedPage {
            offset_start: committed_offset,
            records: events
                .iter()
                .zip(first..)
                .map(|(event, sequence)| SourceRecord {
                    source_sequence: Some(sequence),
                    ..record(**event)
                })
                .collect(),
            proposed_next_cursor: if events.is_empty() {
                String::new()
            } else {
                format!("log/{end}")
            },
            collected_at_ms: 1,
            caught_up: end == database.log.len(),
        })
    }
}

async fn serving(database: &Shared) -> (Plane, Runtime, tempfile::TempDir) {
    let plane = plane_with(spec()).await;
    register_source_type_descriptor(&plane.db, PRINCIPAL, NS, &descriptor(), 1).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let shared = database.clone();
    let connectors = Connectors::default().with(&POSTGRES_CAPTURE_CONNECTOR, move |_| {
        shared.lock().unwrap().opened += 1;
        Ok(Box::new(Capture(shared.clone())))
    });
    let runtime = Runtime::connect(
        ClientConfig::new(&plane.endpoint, PRINCIPAL).with_default_timeout(Duration::from_secs(5)),
        &[NS.to_string()],
        RuntimeOptions {
            runtime_id: "eu-1".into(),
            labels: BTreeMap::from([("zone".into(), "eu".into())]),
            lease: LEASE,
        },
        bindings(dir.path()),
        connectors,
    )
    .await
    .unwrap();
    runtime.register().await.unwrap();
    (plane, runtime, dir)
}

/// Runs sync `round` of the Source: the tick runs `round` intervals ahead,
/// so the Source is due again after the previous sync moved its schedule.
async fn sync(plane: &Plane, runtime: &Runtime, round: i64) -> Result<(), SyncFailure> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    plane
        .db
        .tick_source_syncs(NS, now + round * 120_000)
        .unwrap();
    match runtime.pass().await.unwrap().as_slice() {
        [Ran::Finished { outcome, .. }] => *outcome,
        other => panic!("one finished sync expected: {other:?}"),
    }
}

/// The stored version of order `id`, or `None` when it is absent or
/// deleted.
fn version_of(plane: &Plane, id: u64) -> Option<String> {
    let object = plane
        .db
        .get_object(&object_id_for(
            &descriptor().digest,
            &format!("orders-db:orders#Order/{id}"),
        ))
        .unwrap()?;
    Some(object.name)
}

/// (status, cursor, committed offset) of the Source's current generation.
fn feed(plane: &Plane) -> (SourceSyncGenerationStatus, String, Option<u64>) {
    let state = plane
        .db
        .get_source_sync_state(NS, "orders", &descriptor().digest)
        .unwrap()
        .unwrap();
    let generation = state.current_generation.unwrap();
    (
        generation.status,
        state.checkpoint.unwrap().cursor,
        generation.committed_offset,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_snapshot_hands_off_to_changes_resumed_from_the_plane_offset() {
    let database = Shared::default();
    {
        let mut database = database.lock().unwrap();
        database.table = BTreeMap::from([(1, 1), (2, 1), (3, 1)]);
        database.log = vec![(2, 2, false), (3, 2, true), (4, 1, false)];
    }
    let (plane, runtime, _dir) = serving(&database).await;

    // One sync: two snapshot pages, then two change pages to caught up.
    assert_eq!(sync(&plane, &runtime, 1).await, Ok(()));
    assert_eq!(
        feed(&plane),
        (SourceSyncGenerationStatus::Active, "log/3".into(), Some(3))
    );
    for id in [1, 2, 4] {
        assert!(version_of(&plane, id).is_some(), "order {id}");
    }

    // Nothing new: the sync reads one empty page and moves nothing.
    assert_eq!(sync(&plane, &runtime, 2).await, Ok(()));
    assert_eq!(feed(&plane).2, Some(3));

    // A new change, read by a freshly opened connector from offset 3.
    database.lock().unwrap().log.push((1, 2, false));
    let opened = database.lock().unwrap().opened;
    assert_eq!(sync(&plane, &runtime, 3).await, Ok(()));
    assert!(database.lock().unwrap().opened > opened);
    assert_eq!(
        feed(&plane),
        (SourceSyncGenerationStatus::Active, "log/4".into(), Some(4))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_page_that_skips_a_sequence_commits_nothing() {
    let database = Shared::default();
    {
        let mut database = database.lock().unwrap();
        database.table = BTreeMap::from([(1, 1)]);
        database.log = vec![(1, 2, false)];
    }
    let (plane, runtime, _dir) = serving(&database).await;
    database.lock().unwrap().skip = true;

    assert_eq!(sync(&plane, &runtime, 1).await, Err(SyncFailure::Invalid));
    // The snapshot committed; the gapped page did not move the offset.
    assert_eq!(
        feed(&plane),
        (
            SourceSyncGenerationStatus::Active,
            "snapshot/1".into(),
            Some(0)
        )
    );
}
