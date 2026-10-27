//! Fenced incremental feed of object geo changes into Ezu (#1797) and
//! GeoArrow backfill (#1798).
//!
//! A feed is namespace-scoped and names the object kind, geo property, Ezu
//! collection, optional filter fields, and the service principal whose Ezu
//! token authenticates writes. A run reads the committed object-change stream
//! after a durable cursor, upserts or expires one Ezu entity per object, and
//! only then moves the cursor while it holds the run lease. Each write carries
//! `write_fence` plus the object's last mutation seq in the page as `ts_ms`;
//! Ezu ignores a stale write. A reinstall raises the fence above the
//! namespace watermark so a delayed write from the old feed cannot overwrite
//! the replacement, while seq order inside a revision is kept. Two runs
//! cannot interleave: a second instance cannot take a held lease or advance
//! the cursor. Marked properties are never copied as filter fields.
//!
//! Backfill captures that namespace watermark first, bulk-upserts live
//! objects of the bound kind, then hands the incremental cursor to the
//! watermark so a change between capture and complete is not skipped.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::sekai::{SekaiDb, row_to_object};
use crate::domain::Object;
use crate::sekai::geospatial::{GeospatialGeometry, stored_geospatial_value};
use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
use crate::sekai::object_change_subscription::CommittedObjectMutation;
use crate::sekai::object_schema::{ObjectType, is_restricted_property_classification};

pub const EZU_GEO_FEED_CONTRACT: &str = "sekai.ezu-geo-feed/v1";
/// Changes one run consumes when the feed names no cap, and the most it may.
pub const DEFAULT_CHANGES_PER_RUN: u32 = 100;
pub const MAX_CHANGES_PER_RUN: u32 = 1_000;
/// Live objects one backfill page consumes when the feed names no cap.
pub const DEFAULT_BACKFILL_PER_RUN: u32 = 1_000;
/// How long a run holds its feed without renewing. A crashed run's lease
/// lapses and the next run takes over.
pub const FEED_RUN_LEASE_MS: i64 = 60_000;
/// Ezu accepts at most this many filter fields on one entity.
pub const MAX_FILTER_FIELDS: usize = 8;
const MAX_NAME_BYTES: usize = 64;
const MAX_TEXT_BYTES: usize = 64;

/// One installed feed: which objects, which geo property, which Ezu collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EzuGeoFeed {
    pub contract_version: String,
    pub feed_id: String,
    pub namespace: String,
    /// Object kind whose geo property is projected.
    pub object_kind: String,
    /// Property holding a `sekai.geospatial-value/v1` value.
    pub geo_property: String,
    /// Ezu collection; the object id is the entity id.
    pub collection: String,
    /// Small properties copied as Ezu filter fields. Marked properties are
    /// dropped even when listed.
    #[serde(default)]
    pub filter_fields: Vec<String>,
    /// Service principal whose Ezu credential authenticates the writes.
    pub run_as: String,
    /// Most change rows one run consumes; [`DEFAULT_CHANGES_PER_RUN`] when 0.
    #[serde(default)]
    pub max_changes_per_run: u32,
    pub enabled: bool,
    /// Increments on every install; a reinstall keeps the cursor.
    #[serde(default)]
    pub revision: u64,
    /// Added to the mutation seq to form Ezu `ts_ms`. A reinstall raises it
    /// above the namespace watermark so a delayed write from the old revision
    /// is stale, while seq order inside the revision is kept.
    #[serde(default)]
    pub write_fence: i64,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub updated_at_ms: i64,
}

impl EzuGeoFeed {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != EZU_GEO_FEED_CONTRACT {
            return Err(format!("contract_version must be {EZU_GEO_FEED_CONTRACT}"));
        }
        for (field, value) in [
            ("feed_id", &self.feed_id),
            ("namespace", &self.namespace),
            ("object_kind", &self.object_kind),
            ("geo_property", &self.geo_property),
            ("collection", &self.collection),
            ("run_as", &self.run_as),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
                return Err(format!("{field} must be non-empty without whitespace"));
            }
        }
        if !valid_ezu_name(&self.collection) {
            return Err("collection must be 1-64 bytes without control characters".into());
        }
        if self.filter_fields.len() > MAX_FILTER_FIELDS {
            return Err(format!(
                "at most {MAX_FILTER_FIELDS} filter fields are allowed"
            ));
        }
        if self
            .filter_fields
            .iter()
            .any(|field| field.trim().is_empty() || field.chars().any(char::is_whitespace))
        {
            return Err("filter field names must be non-empty without whitespace".into());
        }
        if self.max_changes_per_run > MAX_CHANGES_PER_RUN {
            return Err(format!(
                "max_changes_per_run must be at most {MAX_CHANGES_PER_RUN}"
            ));
        }
        Ok(())
    }

    pub fn changes_per_run(&self) -> u32 {
        if self.max_changes_per_run == 0 {
            DEFAULT_CHANGES_PER_RUN
        } else {
            self.max_changes_per_run
        }
    }

    /// Objects one backfill page consumes. A named cap is the incremental
    /// page size so tests can bound both; the default is larger because a
    /// rebuild walks live objects, not the change stream.
    pub fn backfill_per_run(&self) -> u32 {
        if self.max_changes_per_run == 0 {
            DEFAULT_BACKFILL_PER_RUN
        } else {
            self.changes_per_run()
        }
    }
}

/// Durable cursor plus in-flight backfill page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EzuGeoFeedProgress {
    pub after_seq: u64,
    pub backfill_watermark: u64,
    pub backfill_after_id: String,
    pub backfill_active: bool,
}

/// Geometry Ezu indexes: a point or a single closed ring.
#[derive(Debug, Clone, PartialEq)]
pub enum EzuGeometry {
    Point { lon: f64, lat: f64 },
    Polygon { ring: Vec<(f64, f64)> },
}

/// A typed Ezu filter field. Text is capped at 64 bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum EzuField {
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
}

/// One entity the feed would write.
#[derive(Debug, Clone, PartialEq)]
pub struct EzuEntity {
    pub collection: String,
    pub id: String,
    pub geometry: EzuGeometry,
    /// `write_fence` plus mutation seq. Ezu ignores an older write.
    pub ts_ms: i64,
    /// When set, Ezu hides the entity from reads after `ts_ms + ttl_ms`.
    /// Used to expire an entity at a revision so a delayed remove cannot
    /// wipe a newer live write.
    pub ttl_ms: Option<i64>,
    pub fields: BTreeMap<String, EzuField>,
}

/// Why an object did not become an upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedSkip {
    /// No geo property, or it was cleared: delete the Ezu entity.
    MissingGeo,
    /// The stored value is not an admitted geometry.
    RejectedGeometry,
    /// Collection or object id is not a valid Ezu name.
    InvalidName,
}

/// Age of the oldest mutation a run read, or 0 when there was nothing new.
pub fn feed_lag_ms(pending: &[CommittedObjectMutation], now_ms: i64) -> i64 {
    pending
        .iter()
        .map(|mutation| now_ms.saturating_sub(mutation.change.timestamp).max(0))
        .max()
        .unwrap_or(0)
}

/// Kind for feed selection: live row, else `_created`/`_deleted` metadata.
pub fn mutation_kind_for_feed(mutation: &CommittedObjectMutation) -> &str {
    if !mutation.object_kind.is_empty() {
        return &mutation.object_kind;
    }
    let value = match mutation.change.field.as_str() {
        "_created" => mutation.change.new_value.as_str(),
        "_deleted" => mutation.change.old_value.as_str(),
        _ => return "",
    };
    value.split('/').next().unwrap_or("")
}

/// Drop a trailing split mutation so a page never counts one write twice.
pub fn keep_whole_mutations(pending: &mut Vec<CommittedObjectMutation>, page_full: bool) -> bool {
    if !page_full {
        return false;
    }
    let Some(last) = pending.last().map(mutation_key) else {
        return false;
    };
    let keep = pending.len()
        - pending
            .iter()
            .rev()
            .take_while(|mutation| mutation_key(mutation) == last)
            .count();
    if keep > 0 {
        pending.truncate(keep);
        false
    } else {
        true
    }
}

fn mutation_key(mutation: &CommittedObjectMutation) -> (String, i64) {
    (mutation.change.object_id.clone(), mutation.change.timestamp)
}

/// Project a live object into an Ezu upsert, or say why not.
pub fn entity_for(
    feed: &EzuGeoFeed,
    object: &Object,
    schema: Option<&ObjectType>,
    revision: i64,
) -> Result<EzuEntity, FeedSkip> {
    if !valid_ezu_name(&feed.collection) || !valid_ezu_name(&object.id) {
        return Err(FeedSkip::InvalidName);
    }
    let raw = object
        .properties
        .get(&feed.geo_property)
        .filter(|value| !value.trim().is_empty())
        .ok_or(FeedSkip::MissingGeo)?;
    let geometry = geometry_from_stored(raw).ok_or(FeedSkip::RejectedGeometry)?;
    Ok(EzuEntity {
        collection: feed.collection.clone(),
        id: object.id.clone(),
        geometry,
        ts_ms: entity_ts_ms(feed, revision),
        ttl_ms: None,
        fields: filter_fields_for(feed, object, schema),
    })
}

/// Above every timestamp the old revision could have issued (`fence + seq`
/// with seq at most the watermark), so a delayed write cannot beat the
/// replacement even after repeated reinstalls or a smaller page cap.
pub fn next_write_fence(previous_fence: i64, watermark: u64) -> i64 {
    let watermark = i64::try_from(watermark).unwrap_or(i64::MAX);
    previous_fence.saturating_add(watermark).saturating_add(1)
}

/// Ezu `ts_ms` for a write of this feed at `mutation_seq`.
///
/// `write_fence + seq` keeps seq order inside a revision and puts every
/// write of a replaced feed below the next revision, even when the new page
/// used a smaller seq. Equal-seq last-writer-wins is Ezu's rule.
pub fn entity_ts_ms(feed: &EzuGeoFeed, mutation_seq: i64) -> i64 {
    feed.write_fence.saturating_add(mutation_seq.max(1))
}

/// Expire the Ezu entity at `revision`. Ezu requires geometry on an upsert;
/// the dummy point is hidden from reads at once because `ttl_ms = 1`.
/// Ezu has no durable tombstone: after sweep the revision is gone, so a
/// delayed upsert can insert again. That is an Ezu limitation, not closed
/// here. Live replacements are fenced with the run lease and [`entity_ts_ms`].
pub fn expire_entity(
    feed: &EzuGeoFeed,
    object_id: &str,
    revision: i64,
) -> Result<EzuEntity, FeedSkip> {
    if !valid_ezu_name(&feed.collection) || !valid_ezu_name(object_id) {
        return Err(FeedSkip::InvalidName);
    }
    Ok(EzuEntity {
        collection: feed.collection.clone(),
        id: object_id.to_string(),
        geometry: EzuGeometry::Point { lon: 0.0, lat: 0.0 },
        ts_ms: entity_ts_ms(feed, revision),
        ttl_ms: Some(1),
        fields: BTreeMap::new(),
    })
}

/// Selected small properties, never including a marked property.
pub fn filter_fields_for(
    feed: &EzuGeoFeed,
    object: &Object,
    schema: Option<&ObjectType>,
) -> BTreeMap<String, EzuField> {
    let mut fields = BTreeMap::new();
    for name in &feed.filter_fields {
        if fields.len() >= MAX_FILTER_FIELDS {
            break;
        }
        if property_is_marked(name, schema) {
            continue;
        }
        if !valid_ezu_name(name) {
            continue;
        }
        let Some(raw) = object
            .properties
            .get(name)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if let Some(value) = field_value(raw) {
            fields.insert(name.clone(), value);
        }
    }
    fields
}

fn property_is_marked(name: &str, schema: Option<&ObjectType>) -> bool {
    if name == OBJECT_CLASSIFICATION_PROPERTY || name.starts_with('_') {
        return true;
    }
    schema
        .and_then(|object_type| {
            object_type
                .properties
                .iter()
                .find(|property| property.name == name)
        })
        .is_some_and(|property| is_restricted_property_classification(&property.classification))
}

fn field_value(raw: &str) -> Option<EzuField> {
    if raw.eq_ignore_ascii_case("true") {
        return Some(EzuField::Bool(true));
    }
    if raw.eq_ignore_ascii_case("false") {
        return Some(EzuField::Bool(false));
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Some(EzuField::Int(value));
    }
    if let Ok(value) = raw.parse::<f64>()
        && value.is_finite()
    {
        return Some(EzuField::Float(value));
    }
    if raw.len() <= MAX_TEXT_BYTES {
        Some(EzuField::Text(raw.to_string()))
    } else {
        None
    }
}

fn geometry_from_stored(raw: &str) -> Option<EzuGeometry> {
    match stored_geospatial_value(raw)?.geometry {
        GeospatialGeometry::Point(point) => Some(EzuGeometry::Point {
            lon: point.lon,
            lat: point.lat,
        }),
        GeospatialGeometry::Polygon(ring) => Some(EzuGeometry::Polygon {
            ring: ring
                .into_iter()
                .map(|point| (point.lon, point.lat))
                .collect(),
        }),
    }
}

/// Collection and entity ids Ezu accepts, and that cannot change a URL path.
pub fn valid_ezu_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | '?' | '#' | '%'))
}

fn namespace_change_watermark(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
) -> Result<u64, String> {
    tx.query_row(
        "SELECT COALESCE(MAX(c.rowid), 0)
         FROM sekai_object_changes c
         LEFT JOIN sekai_objects o ON o.id = c.object_id
         WHERE o.namespace = ?1
            OR EXISTS (
                SELECT 1 FROM sekai_object_changes n
                WHERE n.object_id = c.object_id
                  AND n.field = '_namespace'
                  AND n.old_value = ?1
            )",
        params![namespace],
        |row| row.get::<_, i64>(0),
    )
    .map(|watermark| watermark.max(0) as u64)
    .map_err(|error| error.to_string())
}

impl SekaiDb {
    fn migrate_ezu_geo_feeds(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_ezu_geo_feeds (
                    namespace TEXT NOT NULL,
                    feed_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    body_json TEXT NOT NULL,
                    after_seq INTEGER NOT NULL DEFAULT 0,
                    run_id TEXT NOT NULL DEFAULT '',
                    run_lease_until_ms INTEGER NOT NULL DEFAULT 0,
                    updated_at_ms INTEGER NOT NULL,
                    backfill_watermark INTEGER NOT NULL DEFAULT 0,
                    backfill_after_id TEXT NOT NULL DEFAULT '',
                    backfill_active INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (namespace, feed_id)
                );",
            )
            .map_err(|error| error.to_string())?;
        for statement in [
            "ALTER TABLE sekai_ezu_geo_feeds ADD COLUMN backfill_watermark INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE sekai_ezu_geo_feeds ADD COLUMN backfill_after_id TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE sekai_ezu_geo_feeds ADD COLUMN backfill_active INTEGER NOT NULL DEFAULT 0",
        ] {
            match self.conn().execute(statement, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                    if message.contains("duplicate column name") => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }

    /// Installs or replaces a feed. A new revision keeps the cursor, so a
    /// reinstall neither replays nor skips changes, clears the run lease, and
    /// fences outstanding Ezu writes from the old revision.
    pub fn put_ezu_geo_feed(
        &self,
        feed: &EzuGeoFeed,
        actor: &str,
        now_ms: i64,
    ) -> Result<EzuGeoFeed, String> {
        feed.validate()?;
        self.migrate_ezu_geo_feeds()?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let previous: Option<(i64, String)> = transaction
            .query_row(
                "SELECT revision, body_json FROM sekai_ezu_geo_feeds
                 WHERE namespace = ?1 AND feed_id = ?2",
                params![feed.namespace, feed.feed_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let previous_fence = previous
            .as_ref()
            .and_then(|(_, body)| serde_json::from_str::<EzuGeoFeed>(body).ok())
            .map(|previous| previous.write_fence)
            .unwrap_or(0);
        let watermark = namespace_change_watermark(&transaction, &feed.namespace)?;
        let mut stored = feed.clone();
        let reinstall = previous.is_some();
        stored.revision = previous.map_or(1, |(revision, _)| revision as u64 + 1);
        stored.write_fence = if reinstall {
            next_write_fence(previous_fence, watermark)
        } else {
            0
        };
        stored.created_by = actor.to_string();
        stored.updated_at_ms = now_ms;
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_ezu_geo_feeds
                    (namespace, feed_id, revision, body_json, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(namespace, feed_id) DO UPDATE SET
                    revision = excluded.revision,
                    body_json = excluded.body_json,
                    run_id = '',
                    run_lease_until_ms = 0,
                    backfill_watermark = 0,
                    backfill_after_id = '',
                    backfill_active = 0,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    stored.namespace,
                    stored.feed_id,
                    stored.revision as i64,
                    body,
                    now_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    /// The feed and the change seq it has read through.
    pub fn get_ezu_geo_feed(
        &self,
        namespace: &str,
        feed_id: &str,
    ) -> Result<Option<(EzuGeoFeed, u64)>, String> {
        self.migrate_ezu_geo_feeds()?;
        self.conn()
            .query_row(
                "SELECT body_json, after_seq
                 FROM sekai_ezu_geo_feeds WHERE namespace = ?1 AND feed_id = ?2",
                params![namespace, feed_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|(body, seq)| {
                let feed: EzuGeoFeed = serde_json::from_str(&body)
                    .map_err(|error| format!("corrupt ezu geo feed: {error}"))?;
                Ok((feed, seq.max(0) as u64))
            })
            .transpose()
    }

    /// Takes or renews the run lease of `feed`'s revision for `run_id` until
    /// `until_ms`. Taking needs a free or lapsed lease; renewing needs the
    /// lease still held. A takeover of a lapsed holder raises `write_fence`
    /// with [`next_write_fence`] so that holder's in-flight write is older.
    /// False when another run holds it or the feed changed.
    pub fn lease_ezu_geo_feed_run(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        self.migrate_ezu_geo_feeds()?;
        if renew {
            return self
                .conn()
                .execute(
                    "UPDATE sekai_ezu_geo_feeds SET run_id = ?4, run_lease_until_ms = ?6
                     WHERE namespace = ?1 AND feed_id = ?2 AND revision = ?3
                       AND run_id = ?4 AND run_lease_until_ms >= ?5",
                    params![
                        feed.namespace,
                        feed.feed_id,
                        feed.revision as i64,
                        run_id,
                        now_ms,
                        until_ms
                    ],
                )
                .map(|updated| updated == 1)
                .map_err(|error| error.to_string());
        }
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let row: Option<(String, i64, String, i64)> = transaction
            .query_row(
                "SELECT run_id, run_lease_until_ms, body_json, revision
                 FROM sekai_ezu_geo_feeds WHERE namespace = ?1 AND feed_id = ?2",
                params![feed.namespace, feed.feed_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((held_run, lease_until, body, revision)) = row else {
            return Ok(false);
        };
        if revision != feed.revision as i64 || !(held_run.is_empty() || lease_until < now_ms) {
            return Ok(false);
        }
        let mut stored: EzuGeoFeed = serde_json::from_str(&body)
            .map_err(|error| format!("corrupt ezu geo feed: {error}"))?;
        if !held_run.is_empty() {
            let watermark = namespace_change_watermark(&transaction, &feed.namespace)?;
            stored.write_fence = next_write_fence(stored.write_fence, watermark);
        }
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        let updated = transaction
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET run_id = ?3, run_lease_until_ms = ?4, body_json = ?5
                 WHERE namespace = ?1 AND feed_id = ?2 AND revision = ?6",
                params![
                    feed.namespace,
                    feed.feed_id,
                    run_id,
                    until_ms,
                    body,
                    feed.revision as i64
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(updated == 1)
    }

    /// Raises `write_fence` above the namespace watermark while `run_id`
    /// holds the lease, so a delayed Ezu write from this run is older than
    /// the next run's retry.
    pub fn raise_ezu_geo_feed_write_fence(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
    ) -> Result<bool, String> {
        self.migrate_ezu_geo_feeds()?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let row: Option<(String, String, i64)> = transaction
            .query_row(
                "SELECT run_id, body_json, revision
                 FROM sekai_ezu_geo_feeds WHERE namespace = ?1 AND feed_id = ?2",
                params![feed.namespace, feed.feed_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((held_run, body, revision)) = row else {
            return Ok(false);
        };
        if held_run != run_id || revision != feed.revision as i64 {
            return Ok(false);
        }
        let mut stored: EzuGeoFeed = serde_json::from_str(&body)
            .map_err(|error| format!("corrupt ezu geo feed: {error}"))?;
        let watermark = namespace_change_watermark(&transaction, &feed.namespace)?;
        stored.write_fence = next_write_fence(stored.write_fence, watermark);
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        let updated = transaction
            .execute(
                "UPDATE sekai_ezu_geo_feeds SET body_json = ?3
                 WHERE namespace = ?1 AND feed_id = ?2 AND run_id = ?4 AND revision = ?5",
                params![
                    feed.namespace,
                    feed.feed_id,
                    body,
                    run_id,
                    feed.revision as i64
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(updated == 1)
    }

    /// Frees the run lease if `run_id` holds it.
    pub fn release_ezu_geo_feed_run(&self, feed: &EzuGeoFeed, run_id: &str) -> Result<(), String> {
        self.migrate_ezu_geo_feeds()?;
        self.conn()
            .execute(
                "UPDATE sekai_ezu_geo_feeds SET run_id = '', run_lease_until_ms = 0
                 WHERE namespace = ?1 AND feed_id = ?2 AND run_id = ?3",
                params![feed.namespace, feed.feed_id, run_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Moves the cursor to `through` in one write, only while `run_id` holds
    /// the run lease of the revision that read and only forward, so a
    /// concurrent or stale run can neither rewind nor skip.
    pub fn advance_ezu_geo_feed(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        through: u64,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.migrate_ezu_geo_feeds()?;
        self.conn()
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET after_seq = ?4, updated_at_ms = ?5
                 WHERE namespace = ?1 AND feed_id = ?2 AND revision = ?3
                   AND run_id = ?6 AND run_lease_until_ms >= ?5
                   AND after_seq < ?4",
                params![
                    feed.namespace,
                    feed.feed_id,
                    feed.revision as i64,
                    through as i64,
                    now_ms,
                    run_id
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    /// Cursor and in-flight backfill page.
    pub fn get_ezu_geo_feed_progress(
        &self,
        namespace: &str,
        feed_id: &str,
    ) -> Result<Option<EzuGeoFeedProgress>, String> {
        self.migrate_ezu_geo_feeds()?;
        self.conn()
            .query_row(
                "SELECT after_seq, backfill_watermark, backfill_after_id, backfill_active
                 FROM sekai_ezu_geo_feeds WHERE namespace = ?1 AND feed_id = ?2",
                params![namespace, feed_id],
                |row| {
                    Ok(EzuGeoFeedProgress {
                        after_seq: row.get::<_, i64>(0)?.max(0) as u64,
                        backfill_watermark: row.get::<_, i64>(1)?.max(0) as u64,
                        backfill_after_id: row.get(2)?,
                        backfill_active: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    /// Starts a backfill page: captures the namespace watermark once, then
    /// keeps it for later pages of the same rebuild. None when `run_id` does
    /// not hold the lease of this revision.
    pub fn begin_ezu_geo_feed_backfill(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        now_ms: i64,
    ) -> Result<Option<EzuGeoFeedProgress>, String> {
        self.migrate_ezu_geo_feeds()?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let row: Option<(i64, String, i64, i64, String, i64)> = transaction
            .query_row(
                "SELECT after_seq, backfill_after_id, backfill_watermark, backfill_active,
                        run_id, revision
                 FROM sekai_ezu_geo_feeds WHERE namespace = ?1 AND feed_id = ?2",
                params![feed.namespace, feed.feed_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((after_seq, after_id, stored_watermark, active, held_run, revision)) = row else {
            return Ok(None);
        };
        if held_run != run_id || revision != feed.revision as i64 {
            return Ok(None);
        }
        if active != 0 {
            return Ok(Some(EzuGeoFeedProgress {
                after_seq: after_seq.max(0) as u64,
                backfill_watermark: stored_watermark.max(0) as u64,
                backfill_after_id: after_id,
                backfill_active: true,
            }));
        }
        let watermark = namespace_change_watermark(&transaction, &feed.namespace)?;
        transaction
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET backfill_watermark = ?3, backfill_after_id = '', backfill_active = 1,
                     updated_at_ms = ?4
                 WHERE namespace = ?1 AND feed_id = ?2 AND run_id = ?5 AND revision = ?6",
                params![
                    feed.namespace,
                    feed.feed_id,
                    watermark as i64,
                    now_ms,
                    run_id,
                    feed.revision as i64
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(Some(EzuGeoFeedProgress {
            after_seq: after_seq.max(0) as u64,
            backfill_watermark: watermark,
            backfill_after_id: String::new(),
            backfill_active: true,
        }))
    }

    /// Live objects of `kind` in `namespace` after `after_id`, ordered by id.
    pub fn list_ezu_geo_feed_objects(
        &self,
        namespace: &str,
        kind: &str,
        after_id: &str,
        limit: u32,
    ) -> Result<Vec<Object>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects
                 WHERE namespace = ?1 AND kind = ?2 AND id > ?3
                 ORDER BY id ASC
                 LIMIT ?4",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(
                params![namespace, kind, after_id, limit as i64],
                row_to_object,
            )
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }

    /// Records the last id this backfill page put, only while `run_id` holds
    /// an active backfill.
    pub fn advance_ezu_geo_feed_backfill(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        after_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.migrate_ezu_geo_feeds()?;
        self.conn()
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET backfill_after_id = ?4, updated_at_ms = ?5
                 WHERE namespace = ?1 AND feed_id = ?2 AND revision = ?3
                   AND run_id = ?6 AND run_lease_until_ms >= ?5
                   AND backfill_active = 1",
                params![
                    feed.namespace,
                    feed.feed_id,
                    feed.revision as i64,
                    after_id,
                    now_ms,
                    run_id
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    /// Hands the incremental cursor to the captured watermark and clears the
    /// backfill page. Forward only: a cursor already past the watermark stays.
    /// The snapshot is live objects with geo; pre-watermark removals are not
    /// expired here. A new or rebuilt Ezu has none. Incremental applies
    /// changes after the watermark.
    pub fn complete_ezu_geo_feed_backfill(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.migrate_ezu_geo_feeds()?;
        self.conn()
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET after_seq = CASE
                        WHEN after_seq < backfill_watermark THEN backfill_watermark
                        ELSE after_seq
                     END,
                     backfill_active = 0,
                     backfill_after_id = '',
                     updated_at_ms = ?4
                 WHERE namespace = ?1 AND feed_id = ?2 AND revision = ?3
                   AND run_id = ?5 AND run_lease_until_ms >= ?4
                   AND backfill_active = 1",
                params![
                    feed.namespace,
                    feed.feed_id,
                    feed.revision as i64,
                    now_ms,
                    run_id
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::object_schema::{PropertyDef, PropertyType};
    use std::collections::HashMap;

    const BERLIN: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[13.405,52.52]}"#;
    const PARIS: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[2.3522,48.8566]}"#;

    fn feed() -> EzuGeoFeed {
        EzuGeoFeed {
            contract_version: EZU_GEO_FEED_CONTRACT.into(),
            feed_id: "trucks".into(),
            namespace: "fleet".into(),
            object_kind: "truck".into(),
            geo_property: "location".into(),
            collection: "trucks".into(),
            filter_fields: vec!["status".into(), "access_marking".into(), "badge".into()],
            run_as: "svc-geo".into(),
            max_changes_per_run: 10,
            enabled: true,
            revision: 0,
            write_fence: 0,
            created_by: String::new(),
            updated_at_ms: 0,
        }
    }

    fn truck(id: &str, geo: &str, status: &str, marking: &str) -> Object {
        Object {
            id: id.into(),
            kind: "truck".into(),
            name: id.into(),
            namespace: "fleet".into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("location".into(), geo.into()),
                ("status".into(), status.into()),
                (OBJECT_CLASSIFICATION_PROPERTY.into(), marking.into()),
                ("badge".into(), "restricted".into()),
            ]),
            created: 1,
            updated: 1,
        }
    }

    fn property(name: &str, classification: &str) -> PropertyDef {
        PropertyDef {
            name: name.into(),
            prop_type: PropertyType::String,
            required: false,
            description: String::new(),
            enum_values: Vec::new(),
            link_kind: String::new(),
            compute_expr: String::new(),
            classification: classification.into(),
            struct_fields: Vec::new(),
        }
    }

    #[test]
    fn a_create_projects_geometry_and_drops_marked_filter_fields() {
        let schema = ObjectType {
            kind: "truck".into(),
            description: String::new(),
            properties: vec![
                property("location", "public"),
                property("status", "public"),
                property("badge", "sensitive"),
            ],
            is_builtin: false,
            implements: Vec::new(),
        };
        let entity = entity_for(
            &feed(),
            &truck("t1", BERLIN, "moving", "confidential"),
            Some(&schema),
            7,
        )
        .unwrap();
        assert_eq!(entity.collection, "trucks");
        assert_eq!(entity.id, "t1");
        assert_eq!(
            entity.geometry,
            EzuGeometry::Point {
                lon: 13.405,
                lat: 52.52
            }
        );
        assert_eq!(entity.ts_ms, 7);
        assert_eq!(
            entity.fields,
            BTreeMap::from([("status".into(), EzuField::Text("moving".into()))])
        );
        assert!(!entity.fields.contains_key(OBJECT_CLASSIFICATION_PROPERTY));
        assert!(!entity.fields.contains_key("badge"));
    }

    #[test]
    fn an_expire_is_fenced_by_revision() {
        let expired = expire_entity(&feed(), "t1", 10).unwrap();
        assert_eq!(expired.ts_ms, 10);
        assert_eq!(expired.ttl_ms, Some(1));
        assert!(valid_ezu_name(&expired.id));
    }

    #[test]
    fn a_reinstall_write_beats_a_delayed_write_from_the_old_revision() {
        let mut old = feed();
        old.revision = 1;
        let mut new = feed();
        new.revision = 2;
        new.write_fence = next_write_fence(old.write_fence, 100);
        let delayed = entity_for(&old, &truck("t1", BERLIN, "idle", "public"), None, 100).unwrap();
        let replacement =
            entity_for(&new, &truck("t1", PARIS, "moving", "public"), None, 10).unwrap();
        assert_eq!(delayed.ts_ms, 100);
        assert_eq!(replacement.ts_ms, 111);
        assert!(replacement.ts_ms > delayed.ts_ms);
        assert!(entity_ts_ms(&new, 90) > entity_ts_ms(&new, 10));
        let mut again = feed();
        again.write_fence = next_write_fence(new.write_fence, 100);
        assert!(entity_ts_ms(&again, 10) > entity_ts_ms(&new, 100));
        let mut takeover = feed();
        takeover.write_fence = next_write_fence(old.write_fence, 50);
        assert!(entity_ts_ms(&takeover, 10) > entity_ts_ms(&old, 50));
        assert!(
            expire_entity(&new, "t1", 10).unwrap().ts_ms
                > expire_entity(&old, "t1", 100).unwrap().ts_ms
        );
    }

    #[test]
    fn a_cleared_or_invalid_geo_does_not_upsert() {
        let mut object = truck("t1", "", "idle", "public");
        assert_eq!(
            entity_for(&feed(), &object, None, 1),
            Err(FeedSkip::MissingGeo)
        );
        object
            .properties
            .insert("location".into(), "not-geo".into());
        assert_eq!(
            entity_for(&feed(), &object, None, 1),
            Err(FeedSkip::RejectedGeometry)
        );
    }

    #[test]
    fn the_cursor_only_moves_forward_for_the_revision_that_read() {
        cursor_contract(&RuntimeDb::memory(), "fleet");
    }

    /// The lease and cursor rules every backend keeps, in `namespace`.
    pub(crate) fn cursor_contract(db: &RuntimeDb, namespace: &str) {
        let feed = EzuGeoFeed {
            namespace: namespace.into(),
            ..feed()
        };
        let first = db.put_ezu_geo_feed(&feed, "admin", 1).unwrap();
        assert_eq!(
            db.get_ezu_geo_feed(namespace, "trucks").unwrap().unwrap().1,
            0
        );
        assert!(
            db.lease_ezu_geo_feed_run(&first, "run-a", false, 10, 100)
                .unwrap()
        );
        assert!(
            !db.lease_ezu_geo_feed_run(&first, "run-b", false, 20, 200)
                .unwrap()
        );
        assert!(
            !db.lease_ezu_geo_feed_run(&first, "run-b", true, 20, 200)
                .unwrap()
        );
        assert!(
            db.lease_ezu_geo_feed_run(&first, "run-a", true, 20, 200)
                .unwrap()
        );
        assert!(!db.advance_ezu_geo_feed(&first, "run-b", 5, 30).unwrap());
        assert!(db.advance_ezu_geo_feed(&first, "run-a", 5, 30).unwrap());
        assert!(!db.advance_ezu_geo_feed(&first, "run-a", 5, 31).unwrap());
        assert!(!db.advance_ezu_geo_feed(&first, "run-a", 4, 31).unwrap());
        db.release_ezu_geo_feed_run(&first, "run-a").unwrap();
        assert!(
            db.lease_ezu_geo_feed_run(&first, "run-c", false, 40, 50)
                .unwrap()
        );
        assert!(
            db.lease_ezu_geo_feed_run(&first, "run-d", false, 51, 500)
                .unwrap()
        );
        let (taken, _) = db.get_ezu_geo_feed(namespace, "trucks").unwrap().unwrap();
        assert!(taken.write_fence > first.write_fence);
        assert!(
            !db.lease_ezu_geo_feed_run(&first, "run-c", true, 52, 600)
                .unwrap()
        );
        assert!(!db.advance_ezu_geo_feed(&first, "run-c", 6, 52).unwrap());
        let second = db.put_ezu_geo_feed(&feed, "admin", 60).unwrap();
        assert_eq!(second.revision, 2);
        assert!(second.write_fence > first.write_fence);
        assert!(
            !db.lease_ezu_geo_feed_run(&first, "run-d", true, 61, 700)
                .unwrap()
        );
        assert!(!db.advance_ezu_geo_feed(&first, "run-d", 9, 61).unwrap());
        let (_, cursor) = db.get_ezu_geo_feed(namespace, "trucks").unwrap().unwrap();
        assert_eq!(cursor, 5);
        assert!(
            db.lease_ezu_geo_feed_run(&second, "run-e", false, 62, 700)
                .unwrap()
        );
        assert!(db.advance_ezu_geo_feed(&second, "run-e", 9, 63).unwrap());
        assert!(db.raise_ezu_geo_feed_write_fence(&second, "run-e").unwrap());
        let (fenced, _) = db.get_ezu_geo_feed(namespace, "trucks").unwrap().unwrap();
        assert!(fenced.write_fence > second.write_fence);
        db.release_ezu_geo_feed_run(&second, "run-e").unwrap();
        assert!(
            db.lease_ezu_geo_feed_run(&second, "run-g", false, 64, 800)
                .unwrap()
        );
        let (retry, _) = db.get_ezu_geo_feed(namespace, "trucks").unwrap().unwrap();
        assert_eq!(retry.write_fence, fenced.write_fence);
    }

    #[test]
    fn a_path_segment_is_not_a_valid_ezu_name() {
        assert!(!valid_ezu_name(".."));
        assert!(!valid_ezu_name("."));
        assert!(!valid_ezu_name("../other"));
        assert!(!valid_ezu_name("a/b"));
        assert!(valid_ezu_name("t1"));
    }

    #[test]
    fn a_deleted_object_kind_comes_from_the_deleted_record() {
        use crate::sekai::audit::ObjectChange;
        let mutation = CommittedObjectMutation {
            change: ObjectChange {
                field: "_deleted".into(),
                old_value: "truck/t1".into(),
                ..Default::default()
            },
            seq: 9,
            object_kind: String::new(),
            object_namespace: String::new(),
        };
        assert_eq!(mutation_kind_for_feed(&mutation), "truck");
        let other = CommittedObjectMutation {
            change: ObjectChange {
                field: "_deleted".into(),
                old_value: "van/v1".into(),
                ..Default::default()
            },
            seq: 10,
            object_kind: String::new(),
            object_namespace: String::new(),
        };
        assert_eq!(mutation_kind_for_feed(&other), "van");
    }

    #[test]
    fn a_full_page_does_not_split_one_write() {
        use crate::sekai::audit::ObjectChange;
        let mutation = |object_id: &str, timestamp: i64, seq: u64| CommittedObjectMutation {
            change: ObjectChange {
                object_id: object_id.into(),
                timestamp,
                ..Default::default()
            },
            seq,
            object_kind: "truck".into(),
            object_namespace: "fleet".into(),
        };
        let mut pending = vec![
            mutation("t1", 1, 1),
            mutation("t2", 2, 2),
            mutation("t2", 2, 3),
        ];
        assert!(!keep_whole_mutations(&mut pending, true));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].change.object_id, "t1");
        let mut whole = vec![mutation("t1", 1, 1), mutation("t1", 1, 2)];
        assert!(keep_whole_mutations(&mut whole, true));
        assert_eq!(whole.len(), 2);
        let mut short = vec![mutation("t1", 1, 1), mutation("t1", 1, 2)];
        assert!(!keep_whole_mutations(&mut short, false));
        assert_eq!(short.len(), 2);
    }

    #[test]
    fn paris_is_a_distinct_revision_from_berlin() {
        let moved = {
            let mut object = truck("t1", PARIS, "moving", "public");
            object.updated = 2;
            object
        };
        let entity = entity_for(&feed(), &moved, None, moved.updated).unwrap();
        assert_eq!(
            entity.geometry,
            EzuGeometry::Point {
                lon: 2.3522,
                lat: 48.8566
            }
        );
        assert_eq!(entity.ts_ms, 2);
    }

    #[test]
    fn backfill_captures_a_watermark_pages_by_id_and_hands_off_the_cursor() {
        backfill_contract(&RuntimeDb::memory(), "fleet");
    }

    /// Watermark capture, keyset paging, and cursor handoff every backend keeps.
    pub(crate) fn backfill_contract(db: &RuntimeDb, namespace: &str) {
        let feed = EzuGeoFeed {
            namespace: namespace.into(),
            max_changes_per_run: 1,
            ..feed()
        };
        let stored = db.put_ezu_geo_feed(&feed, "admin", 1).unwrap();
        let id1 = format!("{namespace}-t1");
        let id2 = format!("{namespace}-t2");
        let id3 = format!("{namespace}-t3");
        let truck_in = |id: &str, geo: &str, status: &str| {
            let mut object = truck(id, geo, status, "public");
            object.namespace = namespace.into();
            object
        };
        db.create_object_with_audit(&truck_in(&id1, BERLIN, "idle"), "local")
            .unwrap();
        db.create_object_with_audit(&truck_in(&id2, PARIS, "moving"), "local")
            .unwrap();
        assert!(
            db.lease_ezu_geo_feed_run(&stored, "run-a", false, 10, 100)
                .unwrap()
        );
        let first = db
            .begin_ezu_geo_feed_backfill(&stored, "run-a", 11)
            .unwrap()
            .expect("lease holds");
        assert!(first.backfill_active);
        assert!(first.backfill_watermark > 0);
        assert!(first.backfill_after_id.is_empty());
        let page = db
            .list_ezu_geo_feed_objects(namespace, "truck", &first.backfill_after_id, 1)
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, id1);
        assert!(
            db.advance_ezu_geo_feed_backfill(&stored, "run-a", &id1, 12)
                .unwrap()
        );
        let again = db
            .begin_ezu_geo_feed_backfill(&stored, "run-a", 13)
            .unwrap()
            .expect("same rebuild");
        assert_eq!(again.backfill_watermark, first.backfill_watermark);
        assert_eq!(again.backfill_after_id, id1);
        let rest = db
            .list_ezu_geo_feed_objects(namespace, "truck", &id1, 1)
            .unwrap();
        assert_eq!(rest[0].id, id2);
        db.create_object_with_audit(&truck_in(&id3, BERLIN, "idle"), "local")
            .unwrap();
        assert!(
            db.complete_ezu_geo_feed_backfill(&stored, "run-a", 14)
                .unwrap()
        );
        let progress = db
            .get_ezu_geo_feed_progress(namespace, "trucks")
            .unwrap()
            .unwrap();
        assert!(!progress.backfill_active);
        assert_eq!(progress.after_seq, first.backfill_watermark);
        let mutations = db
            .list_committed_object_mutations_after(namespace, progress.after_seq, 100)
            .unwrap();
        assert!(
            mutations
                .iter()
                .any(|mutation| mutation.change.object_id == id3),
            "a change after the captured watermark must be visible to incremental"
        );
        assert!(
            !db.complete_ezu_geo_feed_backfill(&stored, "run-a", 15)
                .unwrap()
        );
        db.release_ezu_geo_feed_run(&stored, "run-a").unwrap();
        assert!(
            db.lease_ezu_geo_feed_run(&stored, "run-b", false, 16, 200)
                .unwrap()
        );
        assert!(
            db.begin_ezu_geo_feed_backfill(&stored, "run-b", 17)
                .unwrap()
                .unwrap()
                .backfill_active
        );
        let rebuilt = db.put_ezu_geo_feed(&feed, "admin", 18).unwrap();
        let cleared = db
            .get_ezu_geo_feed_progress(namespace, "trucks")
            .unwrap()
            .unwrap();
        assert!(!cleared.backfill_active);
        assert!(cleared.backfill_after_id.is_empty());
        assert_eq!(cleared.after_seq, first.backfill_watermark);
        assert!(
            !db.begin_ezu_geo_feed_backfill(&stored, "run-b", 19)
                .unwrap()
                .is_some()
        );
        let _ = rebuilt;
    }
}
