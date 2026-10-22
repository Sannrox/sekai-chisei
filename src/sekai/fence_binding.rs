//! Plane-owned bindings from Ezu geofence events to governed Actions
//! (#1564, ADR 0121).
//!
//! A binding maps the fence events of one Ezu namespace (enter, exit,
//! inside, dwell) for one collection onto one pinned `GovernedActionType`
//! through a closed parameter mapping, run as an explicit service principal.
//! Ezu ids `(lsn, index)` only grow and reading a page commits nothing, so
//! a run reads after its cursor, submits each event under an id-derived
//! idempotency key, and only then moves the cursor with the page's receipts.
//! A crash before that rereads the page and its submits replay.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::action_binding::SKIP_SOURCE_UNAVAILABLE;

pub const FENCE_BINDING_CONTRACT: &str = "sekai.fence-binding/v1";
pub const MAX_FENCE_BINDING_PARAMETERS: usize = 16;
pub const MAX_BOUND_FENCES: usize = 64;
/// Events one run reads when the binding names no cap, and the most it may.
pub const DEFAULT_EVENTS_PER_RUN: u32 = 100;
pub const MAX_EVENTS_PER_RUN: u32 = 1_000;
/// How long a run holds its binding without renewing. A run renews before
/// every submit; a crashed run's lease lapses and the next run takes over.
pub const FENCE_RUN_LEASE_MS: i64 = 60_000;
/// Ezu event kinds by their wire number.
pub const EVENT_KINDS: [(i32, &str); 4] = [(1, "enter"), (2, "exit"), (3, "inside"), (4, "dwell")];
/// An Ezu event id `(lsn, index)`: the write that raised it and its place
/// among that write's events. Ids only grow.
pub type FenceEventId = (u64, u32);

pub const SKIP_COLLECTION_NOT_BOUND: &str = "collection_not_bound";
pub const SKIP_KIND_NOT_BOUND: &str = "event_kind_not_bound";
/// The entity names no object the service principal can read.
pub const SKIP_OBJECT_UNAVAILABLE: &str = "object_unavailable";

/// Where one Action parameter comes from. Closed: no expressions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", content = "value", rename_all = "snake_case")]
pub enum FenceParameterSource {
    /// The bound object's id: the event's entity id.
    ObjectId,
    /// The fence id.
    Fence,
    /// `enter`, `exit`, `inside`, or `dwell`.
    EventKind,
    /// The entity's observation time, Unix milliseconds.
    EventTime,
    /// A property of the bound object, read as the service principal.
    Property(String),
    Constant(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FenceBinding {
    pub contract_version: String,
    pub binding_id: String,
    pub namespace: String,
    /// Fences whose events fire; every fence when empty.
    #[serde(default)]
    pub fences: Vec<String>,
    /// Event kinds that fire: a subset of enter, exit, inside, dwell.
    pub kinds: Vec<String>,
    /// Ezu collection whose entity ids are object ids.
    pub collection: String,
    /// Object kind those ids name.
    pub kind: String,
    pub type_id: String,
    /// Pinned `GovernedActionType` version.
    pub version: String,
    /// Service principal the binding submits as.
    pub run_as: String,
    pub parameters: BTreeMap<String, FenceParameterSource>,
    /// Most events one run reads; [`DEFAULT_EVENTS_PER_RUN`] when 0.
    #[serde(default)]
    pub max_events_per_run: u32,
    pub enabled: bool,
    /// Increments on every install; part of the idempotency key.
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub updated_at_ms: i64,
}

/// One Ezu fence event as `GET /v1/events` returns it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FenceEvent {
    pub lsn: u64,
    pub index: u32,
    pub fence: String,
    pub collection: String,
    pub entity: String,
    pub kind: i32,
    pub ts_ms: i64,
}

impl FenceEvent {
    pub fn id(&self) -> FenceEventId {
        (self.lsn, self.index)
    }

    pub fn kind_name(&self) -> Option<&'static str> {
        EVENT_KINDS
            .iter()
            .find(|(number, _)| *number == self.kind)
            .map(|(_, name)| *name)
    }
}

/// One page of events and the id it was read through, past events a fence
/// filter skipped: the next read's resume point.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct FenceEventPage {
    pub events: Vec<FenceEvent>,
    pub through_lsn: Option<u64>,
    pub through_index: u32,
}

impl FenceEventPage {
    pub fn through(&self) -> Option<FenceEventId> {
        self.through_lsn.map(|lsn| (lsn, self.through_index))
    }
}

/// What one event became; kept per event id as its receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FenceEventReceipt {
    pub lsn: u64,
    pub index: u32,
    pub fence: String,
    pub entity: String,
    pub kind: String,
    /// Empty when the event did not submit.
    pub instance_id: String,
    pub status: String,
    /// The submit was an idempotent replay of an earlier one.
    pub replay: bool,
    pub skipped_reason: String,
}

impl FenceBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != FENCE_BINDING_CONTRACT {
            return Err(format!("contract_version must be {FENCE_BINDING_CONTRACT}"));
        }
        for (field, value) in [
            ("binding_id", &self.binding_id),
            ("namespace", &self.namespace),
            ("collection", &self.collection),
            ("kind", &self.kind),
            ("type_id", &self.type_id),
            ("version", &self.version),
            ("run_as", &self.run_as),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
                return Err(format!("{field} must be non-empty without whitespace"));
            }
        }
        if self.fences.len() > MAX_BOUND_FENCES {
            return Err(format!("at most {MAX_BOUND_FENCES} fences are allowed"));
        }
        if self
            .fences
            .iter()
            .any(|fence| fence.trim().is_empty() || fence.chars().any(char::is_whitespace))
        {
            return Err("fence ids must be non-empty without whitespace".into());
        }
        if self.kinds.is_empty() {
            return Err("kinds must name at least one of enter, exit, inside, dwell".into());
        }
        if let Some(kind) = self
            .kinds
            .iter()
            .find(|kind| !EVENT_KINDS.iter().any(|(_, name)| name == kind))
        {
            return Err(format!("unsupported event kind {kind:?}"));
        }
        if self.max_events_per_run > MAX_EVENTS_PER_RUN {
            return Err(format!(
                "max_events_per_run must be at most {MAX_EVENTS_PER_RUN}"
            ));
        }
        if self.parameters.len() > MAX_FENCE_BINDING_PARAMETERS {
            return Err(format!(
                "at most {MAX_FENCE_BINDING_PARAMETERS} mapped parameters are allowed"
            ));
        }
        for (name, source) in &self.parameters {
            if name.trim().is_empty() || name.chars().any(char::is_whitespace) {
                return Err("parameter names must be non-empty without whitespace".into());
            }
            if let FenceParameterSource::Property(property) = source
                && !crate::domain::is_valid_property_key(property)
            {
                return Err(format!("invalid property source {property:?}"));
            }
        }
        Ok(())
    }

    pub fn events_per_run(&self) -> u32 {
        match self.max_events_per_run {
            0 => DEFAULT_EVENTS_PER_RUN,
            cap => cap,
        }
    }

    /// Stable per binding and Ezu event id, across revisions: a reread
    /// page, or a run that raced a reinstall, never admits a second instance
    /// for the same event. The namespace keeps same-named bindings apart,
    /// since the key also names the operation.
    pub fn idempotency_key(&self, event: &FenceEvent) -> Result<String, String> {
        Ok(format!(
            "fence-{}",
            crate::shomei::digest_serializable(&(
                &self.namespace,
                &self.binding_id,
                event.lsn,
                event.index,
            ))?
        ))
    }

    /// Why `event` does not fire, if it does not. Fences are also filtered
    /// at read, so this is the last word, not the only one.
    pub fn unbound_reason(&self, event: &FenceEvent) -> Option<&'static str> {
        if event.collection != self.collection {
            return Some(SKIP_COLLECTION_NOT_BOUND);
        }
        let Some(kind) = event.kind_name() else {
            return Some(SKIP_KIND_NOT_BOUND);
        };
        let fence_bound = self.fences.is_empty() || self.fences.contains(&event.fence);
        if !fence_bound || !self.kinds.iter().any(|bound| bound == kind) {
            return Some(SKIP_KIND_NOT_BOUND);
        }
        None
    }

    /// Builds parameters for one event. `object` is the bound object as the
    /// service principal sees it: hidden properties are already absent, so a
    /// mapping that needs one skips the event instead of submitting.
    pub fn parameters_for(
        &self,
        event: &FenceEvent,
        object: &Object,
    ) -> Result<String, &'static str> {
        let mut parameters = serde_json::Map::new();
        for (name, source) in &self.parameters {
            let value = match source {
                FenceParameterSource::ObjectId => object.id.clone(),
                FenceParameterSource::Fence => event.fence.clone(),
                FenceParameterSource::EventKind => {
                    event.kind_name().ok_or(SKIP_KIND_NOT_BOUND)?.to_string()
                }
                FenceParameterSource::EventTime => event.ts_ms.to_string(),
                FenceParameterSource::Constant(value) => value.clone(),
                FenceParameterSource::Property(property) => object
                    .properties
                    .get(property)
                    .cloned()
                    .ok_or(SKIP_SOURCE_UNAVAILABLE)?,
            };
            parameters.insert(name.clone(), serde_json::Value::String(value));
        }
        Ok(serde_json::Value::Object(parameters).to_string())
    }
}

/// Event-time lag of a run: how old the oldest event it read was, or 0 when
/// it found nothing new. A paused binding's next run shows the backlog age.
pub fn event_lag_ms(page: &FenceEventPage, now_ms: i64) -> i64 {
    page.events
        .first()
        .map_or(0, |event| now_ms.saturating_sub(event.ts_ms).max(0))
}

impl SekaiDb {
    fn migrate_fence_bindings(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_fence_bindings (
                    namespace TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    body_json TEXT NOT NULL,
                    after_lsn INTEGER,
                    after_index INTEGER NOT NULL DEFAULT 0,
                    run_id TEXT NOT NULL DEFAULT '',
                    run_lease_until_ms INTEGER NOT NULL DEFAULT 0,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (namespace, binding_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_fence_binding_receipts (
                    namespace TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    lsn INTEGER NOT NULL,
                    event_index INTEGER NOT NULL,
                    receipt_json TEXT NOT NULL,
                    recorded_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (namespace, binding_id, revision, lsn, event_index)
                );",
            )
            .map_err(|error| error.to_string())
    }

    /// Installs or replaces a binding. A new revision keeps the cursor, so a
    /// reinstall neither replays nor skips events, and idempotency keys do
    /// not change with it, so an event an old revision admitted stays
    /// admitted once.
    pub fn put_fence_binding(
        &self,
        binding: &FenceBinding,
        actor: &str,
        now_ms: i64,
    ) -> Result<FenceBinding, String> {
        binding.validate()?;
        self.migrate_fence_bindings()?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let previous: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM sekai_fence_bindings WHERE namespace = ?1 AND binding_id = ?2",
                params![binding.namespace, binding.binding_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let mut stored = binding.clone();
        stored.revision = previous.map_or(1, |revision| revision as u64 + 1);
        stored.created_by = actor.to_string();
        stored.updated_at_ms = now_ms;
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_fence_bindings
                    (namespace, binding_id, revision, body_json, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(namespace, binding_id) DO UPDATE SET
                    revision = excluded.revision,
                    body_json = excluded.body_json,
                    run_id = '',
                    run_lease_until_ms = 0,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    stored.namespace,
                    stored.binding_id,
                    stored.revision as i64,
                    body,
                    now_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    /// The binding and the id its events were read through, if any.
    pub fn get_fence_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<(FenceBinding, Option<FenceEventId>)>, String> {
        self.migrate_fence_bindings()?;
        self.conn()
            .query_row(
                "SELECT body_json, after_lsn, after_index
                 FROM sekai_fence_bindings WHERE namespace = ?1 AND binding_id = ?2",
                params![namespace, binding_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|(body, lsn, index)| {
                let binding: FenceBinding = serde_json::from_str(&body)
                    .map_err(|error| format!("corrupt fence binding: {error}"))?;
                Ok((binding, lsn.map(|lsn| (lsn as u64, index as u32))))
            })
            .transpose()
    }

    /// Takes or renews the run lease of `binding`'s revision for `run_id`
    /// until `until_ms`. Taking needs a free or lapsed lease; renewing needs
    /// the lease still held. False when another run holds it, the lease
    /// lapsed, or the binding was reinstalled.
    pub fn lease_fence_run(
        &self,
        binding: &FenceBinding,
        run_id: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        self.migrate_fence_bindings()?;
        let held = if renew {
            "run_id = ?4 AND run_lease_until_ms >= ?5"
        } else {
            "(run_id = '' OR run_lease_until_ms < ?5)"
        };
        self.conn()
            .execute(
                &format!(
                    "UPDATE sekai_fence_bindings SET run_id = ?4, run_lease_until_ms = ?6
                     WHERE namespace = ?1 AND binding_id = ?2 AND revision = ?3 AND {held}"
                ),
                params![
                    binding.namespace,
                    binding.binding_id,
                    binding.revision as i64,
                    run_id,
                    now_ms,
                    until_ms
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    /// Frees the run lease if `run_id` holds it.
    pub fn release_fence_run(&self, binding: &FenceBinding, run_id: &str) -> Result<(), String> {
        self.migrate_fence_bindings()?;
        self.conn()
            .execute(
                "UPDATE sekai_fence_bindings SET run_id = '', run_lease_until_ms = 0
                 WHERE namespace = ?1 AND binding_id = ?2 AND run_id = ?3",
                params![binding.namespace, binding.binding_id, run_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Records a page's receipts and moves the cursor to `through` in one
    /// write, only while `run_id` holds the run lease of the revision that
    /// read the page and only forward, so a concurrent or stale run can
    /// neither rewind, skip, nor record over another run's outcomes.
    pub fn advance_fence_binding(
        &self,
        binding: &FenceBinding,
        run_id: &str,
        through: FenceEventId,
        receipts: &[FenceEventReceipt],
        now_ms: i64,
    ) -> Result<bool, String> {
        self.migrate_fence_bindings()?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let moved = transaction
            .execute(
                "UPDATE sekai_fence_bindings
                 SET after_lsn = ?4, after_index = ?5, updated_at_ms = ?6
                 WHERE namespace = ?1 AND binding_id = ?2 AND revision = ?3
                   AND run_id = ?7 AND run_lease_until_ms >= ?6
                   AND (after_lsn IS NULL OR after_lsn < ?4
                        OR (after_lsn = ?4 AND after_index < ?5))",
                params![
                    binding.namespace,
                    binding.binding_id,
                    binding.revision as i64,
                    through.0 as i64,
                    through.1 as i64,
                    now_ms,
                    run_id
                ],
            )
            .map_err(|error| error.to_string())?
            == 1;
        if moved {
            for receipt in receipts {
                transaction
                    .execute(
                        "INSERT INTO sekai_fence_binding_receipts
                            (namespace, binding_id, revision, lsn, event_index, receipt_json,
                             recorded_at_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                         ON CONFLICT DO NOTHING",
                        params![
                            binding.namespace,
                            binding.binding_id,
                            binding.revision as i64,
                            receipt.lsn as i64,
                            receipt.index as i64,
                            serde_json::to_string(receipt).map_err(|error| error.to_string())?,
                            now_ms
                        ],
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(moved)
    }

    /// Receipts of a binding's events, oldest first.
    pub fn list_fence_binding_receipts(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Vec<FenceEventReceipt>, String> {
        self.migrate_fence_bindings()?;
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT receipt_json FROM sekai_fence_binding_receipts
                 WHERE namespace = ?1 AND binding_id = ?2
                 ORDER BY lsn, event_index, revision",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![namespace, binding_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let json = row.map_err(|error| error.to_string())?;
            serde_json::from_str(&json).map_err(|error| format!("corrupt fence receipt: {error}"))
        })
        .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn binding() -> FenceBinding {
        FenceBinding {
            contract_version: FENCE_BINDING_CONTRACT.into(),
            binding_id: "depot-arrivals".into(),
            namespace: "fleet".into(),
            fences: vec!["depot".into()],
            kinds: vec!["enter".into(), "dwell".into(), "exit".into()],
            collection: "trucks".into(),
            kind: "truck".into(),
            type_id: "truck.arrive".into(),
            version: "1".into(),
            run_as: "svc-dispatch".into(),
            parameters: BTreeMap::from([
                ("truck".into(), FenceParameterSource::ObjectId),
                ("event".into(), FenceParameterSource::EventKind),
                (
                    "plate".into(),
                    FenceParameterSource::Property("plate".into()),
                ),
            ]),
            max_events_per_run: 0,
            enabled: true,
            revision: 1,
            created_by: String::new(),
            updated_at_ms: 0,
        }
    }

    fn event(lsn: u64, kind: i32) -> FenceEvent {
        FenceEvent {
            lsn,
            index: 0,
            fence: "depot".into(),
            collection: "trucks".into(),
            entity: "truck-1".into(),
            kind,
            ts_ms: 1_000,
        }
    }

    #[test]
    fn a_binding_rejects_open_ended_kinds_and_caps() {
        assert!(binding().validate().is_ok());
        let mut unknown = binding();
        unknown.kinds = vec!["teleport".into()];
        assert!(unknown.validate().unwrap_err().contains("teleport"));
        let mut empty = binding();
        empty.kinds.clear();
        assert!(empty.validate().is_err());
        let mut greedy = binding();
        greedy.max_events_per_run = MAX_EVENTS_PER_RUN + 1;
        assert!(greedy.validate().is_err());
        assert_eq!(binding().events_per_run(), DEFAULT_EVENTS_PER_RUN);
    }

    #[test]
    fn only_bound_fences_kinds_and_collections_fire() {
        let binding = binding();
        assert_eq!(binding.unbound_reason(&event(1, 1)), None);
        for unbound in [3, 0, 9] {
            assert_eq!(
                binding.unbound_reason(&event(1, unbound)),
                Some(SKIP_KIND_NOT_BOUND)
            );
        }
        let mut other_fence = event(1, 1);
        other_fence.fence = "yard".into();
        assert_eq!(
            binding.unbound_reason(&other_fence),
            Some(SKIP_KIND_NOT_BOUND)
        );
        let mut other_collection = event(1, 1);
        other_collection.collection = "drones".into();
        assert_eq!(
            binding.unbound_reason(&other_collection),
            Some(SKIP_COLLECTION_NOT_BOUND)
        );
    }

    #[test]
    fn parameters_come_from_the_event_and_visible_properties() {
        let mut truck = Object {
            id: "truck-1".into(),
            kind: "truck".into(),
            name: "truck-1".into(),
            namespace: "fleet".into(),
            external_id: String::new(),
            properties: std::collections::HashMap::from([("plate".into(), "K-1".into())]),
            created: 1,
            updated: 1,
        };
        let parameters: serde_json::Value =
            serde_json::from_str(&binding().parameters_for(&event(1, 4), &truck).unwrap()).unwrap();
        assert_eq!(
            parameters,
            serde_json::json!({"truck": "truck-1", "event": "dwell", "plate": "K-1"})
        );
        truck.properties.clear();
        assert_eq!(
            binding().parameters_for(&event(1, 4), &truck),
            Err(SKIP_SOURCE_UNAVAILABLE)
        );
    }

    #[test]
    fn the_idempotency_key_follows_the_event_id_across_revisions() {
        let first = binding().idempotency_key(&event(7, 1)).unwrap();
        assert_eq!(first, binding().idempotency_key(&event(7, 2)).unwrap());
        assert_ne!(first, binding().idempotency_key(&event(8, 1)).unwrap());
        let mut reinstalled = binding();
        reinstalled.revision = 2;
        assert_eq!(first, reinstalled.idempotency_key(&event(7, 1)).unwrap());
        let mut other = binding();
        other.binding_id = "yard-arrivals".into();
        assert_ne!(first, other.idempotency_key(&event(7, 1)).unwrap());
        let mut elsewhere = binding();
        elsewhere.namespace = "harbor".into();
        assert_ne!(first, elsewhere.idempotency_key(&event(7, 1)).unwrap());
    }

    #[test]
    fn the_cursor_only_moves_forward_for_the_revision_that_read() {
        cursor_contract(&crate::db::runtime_db::RuntimeDb::memory(), "fleet");
    }

    /// The lease, cursor and receipt rules every backend keeps, in
    /// `namespace`.
    pub(crate) fn cursor_contract(db: &crate::db::runtime_db::RuntimeDb, namespace: &str) {
        let binding = FenceBinding {
            namespace: namespace.into(),
            ..binding()
        };
        let first = db.put_fence_binding(&binding, "admin", 1).unwrap();
        assert_eq!(
            db.get_fence_binding(namespace, "depot-arrivals")
                .unwrap()
                .unwrap()
                .1,
            None
        );
        // One run at a time: a second run cannot take a held lease, and only
        // the holder renews it.
        assert!(db.lease_fence_run(&first, "run-a", false, 10, 100).unwrap());
        assert!(!db.lease_fence_run(&first, "run-b", false, 20, 200).unwrap());
        assert!(!db.lease_fence_run(&first, "run-b", true, 20, 200).unwrap());
        assert!(db.lease_fence_run(&first, "run-a", true, 20, 200).unwrap());
        let receipt = FenceEventReceipt {
            lsn: 5,
            kind: "enter".into(),
            instance_id: "ai-1".into(),
            ..Default::default()
        };
        // Only the holder moves the cursor.
        assert!(
            !db.advance_fence_binding(&first, "run-b", (5, 0), std::slice::from_ref(&receipt), 30)
                .unwrap()
        );
        assert!(
            db.advance_fence_binding(&first, "run-a", (5, 0), std::slice::from_ref(&receipt), 30)
                .unwrap()
        );
        // A rerun of the same page cannot rewind or record twice.
        assert!(
            !db.advance_fence_binding(&first, "run-a", (5, 0), std::slice::from_ref(&receipt), 31)
                .unwrap()
        );
        assert!(
            !db.advance_fence_binding(&first, "run-a", (4, 9), &[], 31)
                .unwrap()
        );
        assert_eq!(
            db.list_fence_binding_receipts(namespace, "depot-arrivals")
                .unwrap(),
            [receipt]
        );
        db.release_fence_run(&first, "run-a").unwrap();
        // A lapsed lease is taken over; the lapsed holder can neither renew
        // nor move the cursor.
        assert!(db.lease_fence_run(&first, "run-c", false, 40, 50).unwrap());
        assert!(db.lease_fence_run(&first, "run-d", false, 51, 500).unwrap());
        assert!(!db.lease_fence_run(&first, "run-c", true, 52, 600).unwrap());
        assert!(
            !db.advance_fence_binding(&first, "run-c", (6, 0), &[], 52)
                .unwrap()
        );
        // A reinstall keeps the cursor and clears the lease; the old
        // revision's run can no longer renew or move it.
        let second = db.put_fence_binding(&binding, "admin", 60).unwrap();
        assert_eq!(second.revision, 2);
        assert!(!db.lease_fence_run(&first, "run-d", true, 61, 700).unwrap());
        assert!(
            !db.advance_fence_binding(&first, "run-d", (9, 0), &[], 61)
                .unwrap()
        );
        let (_, cursor) = db
            .get_fence_binding(namespace, "depot-arrivals")
            .unwrap()
            .unwrap();
        assert_eq!(cursor, Some((5, 0)));
        assert!(
            db.lease_fence_run(&second, "run-e", false, 62, 700)
                .unwrap()
        );
        assert!(
            db.advance_fence_binding(&second, "run-e", (9, 0), &[], 63)
                .unwrap()
        );
    }

    #[test]
    fn lag_is_the_age_of_the_oldest_unread_event() {
        let page = FenceEventPage {
            events: vec![event(1, 1), event(2, 2)],
            through_lsn: Some(2),
            through_index: 0,
        };
        assert_eq!(event_lag_ms(&page, 61_000), 60_000);
        assert_eq!(event_lag_ms(&FenceEventPage::default(), 61_000), 0);
    }

    #[test]
    fn ezu_event_pages_decode_from_the_http_shape() {
        let page: FenceEventPage = serde_json::from_str(
            r#"{"events":[{"lsn":3,"index":1,"fence":"depot","collection":"trucks",
                "entity":"truck-1","kind":4,"ts_ms":9,"position":{"lon":1.0,"lat":2.0},
                "entity_labels":[],"fence_labels":[]}],"through_lsn":3,"through_index":1}"#,
        )
        .unwrap();
        assert_eq!(page.through(), Some((3, 1)));
        assert_eq!(page.events[0].kind_name(), Some("dwell"));
    }
}
