//! Plane-owned object-change delivery over event-subscription cursors (#838).
//!
//! The producer is committed create/update/delete history. A caller-supplied
//! page is never object authority. Snapshot, then stream; a gap or expiry
//! requires resnapshot.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::{Object, PropertyFilter, is_valid_property_key};
use crate::sekai::audit::ObjectChange;
use crate::sekai::event_stream::{
    self, EVENT_STREAM_CONTRACT, EventStreamBinding, EventStreamCheckpoint, EventStreamColumn,
    SCHEMA_REVISION_V1,
};
use crate::sekai::event_subscription::{
    self, EVENT_SUBSCRIPTION_CONTRACT, EventSubscription, EventSubscriptionCursor, STATUS_ACTIVE,
    SUBSCRIBE_UNAVAILABLE,
};
use crate::shomei;

pub const OBJECT_CHANGE_SOURCE: &str = "sekai.object-store";
pub const OUTCOME_PAGE: &str = "page";
pub const OUTCOME_REPLAYED: &str = "replayed";
pub const OUTCOME_RESNAPSHOT: &str = "resnapshot_required";
pub const OUTCOME_REVOKED: &str = "revoked";
pub const OUTCOME_DISCONNECTED: &str = "disconnected";
pub const DISCONNECT_SLOW_CONSUMER: &str = "slow_consumer";
pub const OP_CREATE: &str = "create";
pub const OP_UPDATE: &str = "update";
pub const OP_DELETE: &str = "delete";
pub const OP_INVALIDATE: &str = "invalidate";
pub const MAX_PROPERTY_FILTERS: usize = 4;
pub const MAX_PAGE: u32 = 64;
pub const MAX_BACKLOG: u32 = 256;
pub const DEFAULT_RETENTION_MS: i64 = 86_400_000;
pub const MAX_RETENTION_MS: i64 = 604_800_000;
pub const DEFAULT_PAGE_LIMIT: i32 = 32;

const ALLOWED_OPERATORS: &[&str] = &["eq", "gt", "gte", "lt", "lte"];
const SKIPPED_FIELDS: &[&str] = &[
    "_namespace",
    "_security_snapshot",
    "_security_kind",
    "namespace",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectChangeScope {
    pub namespace: String,
    pub kind: String,
    pub object_ids: Vec<String>,
    pub property_filters: Vec<PropertyFilter>,
}

#[derive(Debug, Clone)]
pub struct ObjectChangeReadRequest {
    pub subscription_id: String,
    pub scope: ObjectChangeScope,
    pub snapshot_revision: String,
    pub limit: i32,
    pub retention_ms: i64,
    pub last_page_digest: String,
    pub revoke: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectChangeEvent {
    pub offset: u64,
    pub event_id: String,
    pub object_id: String,
    pub kind: String,
    pub op: String,
    pub field: String,
    pub committed_at_ms: i64,
    pub operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectChangePage {
    pub contract_version: String,
    pub subscription_id: String,
    pub stream_id: String,
    pub outcome: String,
    pub snapshot_revision: String,
    pub generation: u64,
    pub feed_epoch: String,
    pub committed_offset: u64,
    pub page_digest: String,
    pub events: Vec<ObjectChangeEvent>,
    pub authority: bool,
    pub disconnect_reason: String,
}

#[derive(Debug, Clone)]
pub struct CommittedObjectMutation {
    pub change: ObjectChange,
    pub seq: u64,
    pub object_kind: String,
    pub object_namespace: String,
}

/// What a strict reader may learn of beyond the visible objects it was
/// resolved: see [`read_object_change_subscription_for_reader`].
#[derive(Debug, Clone, Default)]
pub struct ReaderVisibility {
    /// Live ids the reader may read now, in or out of the scope's filters.
    pub readable_ids: BTreeSet<String>,
    /// Deleted ids whose history the reader may read.
    pub readable_deletes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectChangeStreamState {
    kind: String,
    object_ids: Vec<String>,
    property_filters: Vec<PropertyFilter>,
    authorization_pin: String,
}

#[derive(Serialize)]
struct ScopePin<'a> {
    namespace: &'a str,
    kind: &'a str,
    object_ids: &'a [String],
    property_filters: &'a [PropertyFilter],
}

#[derive(Serialize)]
struct PagePin<'a> {
    subscription_id: &'a str,
    stream_id: &'a str,
    generation: u64,
    feed_epoch: &'a str,
    offset_start: u64,
    offset_end: u64,
    events: &'a [ObjectChangeEvent],
}

pub fn scope_digest(scope: &ObjectChangeScope) -> Result<String, String> {
    let mut object_ids = scope.object_ids.clone();
    object_ids.sort();
    object_ids.dedup();
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&ScopePin {
            namespace: &scope.namespace,
            kind: &scope.kind,
            object_ids: &object_ids,
            property_filters: &scope.property_filters,
        })?
    ))
}

pub fn snapshot_revision(scope: &ObjectChangeScope, watermark_seq: u64) -> Result<String, String> {
    Ok(format!("v1:{watermark_seq}:{}", scope_digest(scope)?))
}

pub fn authorization_pin(activation_id: &str, principals: &[String]) -> Result<String, String> {
    let mut principals = principals.to_vec();
    principals.sort();
    principals.dedup();
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&(activation_id, principals))?
    ))
}

pub fn read_object_change_subscription(
    db: &RuntimeDb,
    actor: &str,
    request: &ObjectChangeReadRequest,
    now_ms: i64,
    visible: &[Object],
    authorization_pin: &str,
) -> Result<ObjectChangePage, String> {
    let mut resolved_visible = Vec::new();
    read_object_change_subscription_with_resolved_objects(
        db,
        actor,
        request,
        now_ms,
        &mut resolved_visible,
        |object_ids| {
            let object_ids = object_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            Ok(visible
                .iter()
                .filter(|object| object_ids.contains(object.id.as_str()))
                .cloned()
                .collect())
        },
        authorization_pin,
    )
}

pub fn read_object_change_subscription_with_resolved_objects<F>(
    db: &RuntimeDb,
    actor: &str,
    request: &ObjectChangeReadRequest,
    now_ms: i64,
    resolved_visible: &mut Vec<Object>,
    resolve_visible: F,
    authorization_pin: &str,
) -> Result<ObjectChangePage, String>
where
    F: FnOnce(&[String]) -> Result<Vec<Object>, String>,
{
    read_object_changes(
        db,
        actor,
        request,
        now_ms,
        resolved_visible,
        |object_ids, _| Ok((resolve_visible(object_ids)?, None)),
        authorization_pin,
    )
}

/// Reads a page for a reader that may learn of no object it cannot read.
/// `resolve` gets the live and the deleted ids a page would name and returns
/// the visible objects plus what else the reader may read. A change to any
/// other object restarts the subscription: the page is `resnapshot_required`,
/// names no object, and the next read with the new revision continues it.
pub fn read_object_change_subscription_for_reader<F>(
    db: &RuntimeDb,
    actor: &str,
    request: &ObjectChangeReadRequest,
    now_ms: i64,
    resolved_visible: &mut Vec<Object>,
    resolve: F,
    authorization_pin: &str,
) -> Result<ObjectChangePage, String>
where
    F: FnOnce(&[String], &[String]) -> Result<(Vec<Object>, ReaderVisibility), String>,
{
    read_object_changes(
        db,
        actor,
        request,
        now_ms,
        resolved_visible,
        |object_ids, deleted_ids| {
            let (visible, reader) = resolve(object_ids, deleted_ids)?;
            Ok((visible, Some(reader)))
        },
        authorization_pin,
    )
}

/// `resolve` returns the visible objects and, for a strict reader, what else
/// it may read; `None` keeps the lenient projection.
fn read_object_changes<F>(
    db: &RuntimeDb,
    actor: &str,
    request: &ObjectChangeReadRequest,
    now_ms: i64,
    resolved_visible: &mut Vec<Object>,
    resolve: F,
    authorization_pin: &str,
) -> Result<ObjectChangePage, String>
where
    F: FnOnce(&[String], &[String]) -> Result<(Vec<Object>, Option<ReaderVisibility>), String>,
{
    resolved_visible.clear();
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("read timestamp must be non-negative".into());
    }
    let scope = validate_scope(&request.scope)?;
    required("subscription id", &request.subscription_id)?;
    let retention_ms = normalize_retention(request.retention_ms)?;
    let live_watermark = db.object_change_watermark(&scope.namespace)?;
    let live_revision = snapshot_revision(&scope, live_watermark)?;

    if request.revoke {
        return revoke_page(db, actor, &scope, &request.subscription_id, now_ms);
    }
    if request.snapshot_revision.trim().is_empty() {
        return Ok(resnapshot_page(
            &request.subscription_id,
            &stream_id(&scope.namespace, &request.subscription_id),
            live_revision,
        ));
    }
    let admitted_watermark = parse_snapshot_revision(&scope, &request.snapshot_revision)?;
    let oldest = db.object_change_oldest_seq(&scope.namespace)?;
    if admitted_watermark > 0 && oldest > 0 && admitted_watermark < oldest.saturating_sub(1) {
        return Ok(resnapshot_page(
            &request.subscription_id,
            &stream_id(&scope.namespace, &request.subscription_id),
            live_revision,
        ));
    }

    let stream = ensure_object_change_stream(
        db,
        actor,
        &scope,
        &request.subscription_id,
        authorization_pin,
        now_ms,
    )?;
    ensure_object_change_checkpoint(
        db,
        &stream,
        &request.snapshot_revision,
        live_watermark.max(admitted_watermark),
    )?;
    if let Ok(existing) = event_subscription::inspect_event_subscription(
        db,
        actor,
        &scope.namespace,
        &request.subscription_id,
    ) && existing.status == STATUS_ACTIVE
        && idle_past_retention(&existing, now_ms)
    {
        return restart_for_resnapshot(db, &existing, now_ms, live_revision);
    }
    let subscription = ensure_subscription(db, actor, request, &stream, retention_ms, now_ms)?;
    if subscription.status != STATUS_ACTIVE {
        return Ok(revoked_page(&subscription, &request.snapshot_revision));
    }
    if idle_past_retention(&subscription, now_ms) {
        return restart_for_resnapshot(db, &subscription, now_ms, live_revision);
    }
    let state = parse_stream_state(&stream)?;
    if !stream_state_matches(&state, &scope, authorization_pin) {
        bind_object_change_stream_state(db, &stream, &scope, authorization_pin)?;
        return restart_for_resnapshot(db, &subscription, now_ms, live_revision);
    }
    if !request.last_page_digest.is_empty()
        && request.last_page_digest == subscription.cursor.last_page_digest
    {
        return Ok(replayed_page(&subscription, &request.snapshot_revision));
    }

    let after_seq = if subscription.cursor.committed_offset > 0 {
        subscription.cursor.committed_offset
    } else {
        admitted_watermark
    };
    let raw = db.list_committed_object_mutations_after(
        &scope.namespace,
        after_seq,
        i32::try_from(MAX_BACKLOG.saturating_add(1)).map_err(|error| error.to_string())?,
    )?;
    let operation_ids = crate::sekai::operation_correlation::operation_ids_for_objects(
        db,
        &raw.iter()
            .map(|mutation| mutation.change.object_id.clone())
            .collect(),
    )?;
    let object_ids = object_ids_for_projection(&scope, &raw);
    let deleted_ids = deleted_ids_for_projection(&scope, &raw);
    let (visible, reader) = resolve(&object_ids, &deleted_ids)?;
    *resolved_visible = visible;
    let Some(events) = project(
        &scope,
        resolved_visible,
        reader.as_ref(),
        &raw,
        subscription.cursor.committed_offset,
        &operation_ids,
    )?
    else {
        return restart_for_resnapshot(db, &subscription, now_ms, live_revision);
    };
    let limit = page_limit(request.limit);
    let page_events = events.into_iter().take(limit).collect::<Vec<_>>();
    if page_events.is_empty() {
        // Skip the scanned prefix so a busy out-of-scope kind cannot look like
        // a slow consumer. CAS keeps a crash/retry from jumping past an
        // in-scope event that was not in this empty projection.
        let next = EventSubscription {
            cursor: EventSubscriptionCursor {
                committed_offset: raw
                    .last()
                    .map(|mutation| mutation.seq)
                    .unwrap_or(subscription.cursor.committed_offset),
                admitted_at_ms: now_ms,
                ..subscription.cursor.clone()
            },
            ..subscription.clone()
        };
        db.advance_event_subscription_cursor(&next, &subscription)?;
        return Ok(empty_page(&next, &request.snapshot_revision));
    }
    if raw.len() > MAX_BACKLOG as usize {
        return disconnect_slow(&subscription, &request.snapshot_revision);
    }
    let digest = page_digest(
        &subscription.subscription_id,
        &subscription.stream_id,
        subscription.cursor.generation.max(1),
        &request.snapshot_revision,
        page_events.first().map(|event| event.offset).unwrap_or(1),
        page_events.last().map(|event| event.offset).unwrap_or(1),
        &page_events,
    )?;
    let last_seq = page_events
        .last()
        .and_then(|event| {
            raw.iter()
                .find(|mutation| mutation.change.id == event.event_id)
                .map(|mutation| mutation.seq)
        })
        .unwrap_or(after_seq);
    let next = EventSubscription {
        cursor: EventSubscriptionCursor {
            generation: subscription.cursor.generation.max(1),
            feed_epoch: request.snapshot_revision.clone(),
            committed_offset: last_seq,
            last_page_digest: digest.clone(),
            admitted_at_ms: now_ms,
        },
        ..subscription.clone()
    };
    db.advance_event_subscription_cursor(&next, &subscription)?;
    Ok(ObjectChangePage {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        subscription_id: next.subscription_id.clone(),
        stream_id: next.stream_id.clone(),
        outcome: OUTCOME_PAGE.into(),
        snapshot_revision: request.snapshot_revision.clone(),
        generation: next.cursor.generation,
        feed_epoch: next.cursor.feed_epoch.clone(),
        committed_offset: next.cursor.committed_offset,
        page_digest: digest,
        events: page_events,
        authority: false,
        disconnect_reason: String::new(),
    })
}

fn validate_scope(scope: &ObjectChangeScope) -> Result<ObjectChangeScope, String> {
    required("namespace", &scope.namespace)?;
    required("kind", &scope.kind)?;
    if !is_valid_kind(&scope.kind) {
        return Err("object-change kind is invalid".into());
    }
    if scope.property_filters.len() > MAX_PROPERTY_FILTERS {
        return Err("object-change subscription supports at most 4 property filters".into());
    }
    let mut filters = Vec::with_capacity(scope.property_filters.len());
    for filter in &scope.property_filters {
        if !is_valid_property_key(&filter.key) {
            return Err("object-change property filter key is invalid".into());
        }
        if !ALLOWED_OPERATORS.contains(&filter.op.as_str()) {
            return Err("object-change property filter operator is unsupported".into());
        }
        filters.push(filter.clone());
    }
    let mut object_ids = Vec::new();
    for object_id in &scope.object_ids {
        required("object id", object_id)?;
        object_ids.push(object_id.clone());
    }
    object_ids.sort();
    object_ids.dedup();
    Ok(ObjectChangeScope {
        namespace: scope.namespace.clone(),
        kind: scope.kind.clone(),
        object_ids,
        property_filters: filters,
    })
}

fn normalize_retention(retention_ms: i64) -> Result<i64, String> {
    let retention = if retention_ms <= 0 {
        DEFAULT_RETENTION_MS
    } else {
        retention_ms
    };
    if retention > MAX_RETENTION_MS {
        return Err("object-change retention exceeds the allowed bound".into());
    }
    Ok(retention)
}

fn parse_snapshot_revision(scope: &ObjectChangeScope, revision: &str) -> Result<u64, String> {
    let expected = scope_digest(scope)?;
    let mut parts = revision.splitn(3, ':');
    if parts.next() != Some("v1") {
        return Err("object-change snapshot revision is stale".into());
    }
    let watermark = parts
        .next()
        .ok_or("object-change snapshot revision is stale")?
        .parse::<u64>()
        .map_err(|_| "object-change snapshot revision is stale".to_string())?;
    let digest = parts
        .next()
        .ok_or("object-change snapshot revision is stale")?;
    if digest != expected {
        return Err("object-change snapshot revision is stale".into());
    }
    Ok(watermark)
}

fn ensure_object_change_stream(
    db: &RuntimeDb,
    actor: &str,
    scope: &ObjectChangeScope,
    subscription_id: &str,
    authorization_pin: &str,
    now_ms: i64,
) -> Result<EventStreamBinding, String> {
    let stream_id = stream_id(&scope.namespace, subscription_id);
    if let Some(existing) = db.get_event_stream_binding(&stream_id)? {
        if existing.owner != actor || existing.namespace != scope.namespace {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
        if existing.source != OBJECT_CHANGE_SOURCE {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
        return Ok(existing);
    }
    let state = ObjectChangeStreamState {
        kind: scope.kind.clone(),
        object_ids: normalized_object_ids(scope),
        property_filters: scope.property_filters.clone(),
        authorization_pin: authorization_pin.into(),
    };
    let binding = EventStreamBinding {
        contract_version: EVENT_STREAM_CONTRACT.into(),
        stream_id,
        namespace: scope.namespace.clone(),
        owner: actor.into(),
        source: OBJECT_CHANGE_SOURCE.into(),
        source_instance: serde_json::to_string(&state).map_err(|error| error.to_string())?,
        schema_revision: SCHEMA_REVISION_V1.into(),
        type_digest: scope_digest(scope)?,
        definition_digest: String::new(),
        columns: object_change_columns(),
        registered_by: actor.into(),
        registered_at_ms: now_ms,
    };
    event_stream::register_event_stream(db, actor, &binding, now_ms)
}

fn ensure_subscription(
    db: &RuntimeDb,
    actor: &str,
    request: &ObjectChangeReadRequest,
    stream: &EventStreamBinding,
    retention_ms: i64,
    now_ms: i64,
) -> Result<EventSubscription, String> {
    let existing = event_subscription::inspect_event_subscription(
        db,
        actor,
        &request.scope.namespace,
        &request.subscription_id,
    );
    match existing {
        Ok(subscription)
            if subscription.status == STATUS_ACTIVE
                && subscription.stream_id == stream.stream_id
                && subscription.definition_digest == stream.definition_digest
                && !idle_past_retention(&subscription, now_ms) =>
        {
            if subscription.cursor.feed_epoch.is_empty() {
                // Restarted for a resnapshot: the first read pins its revision.
                let admitted = EventSubscription {
                    cursor: EventSubscriptionCursor {
                        feed_epoch: request.snapshot_revision.clone(),
                        admitted_at_ms: now_ms,
                        ..subscription.cursor.clone()
                    },
                    ..subscription
                };
                db.put_event_subscription(&admitted)?;
                return Ok(admitted);
            }
            if subscription.cursor.feed_epoch != request.snapshot_revision {
                return Err("object-change snapshot revision is stale".into());
            }
            Ok(subscription)
        }
        Ok(_) | Err(_) => {
            let registered = event_subscription::register_event_subscription(
                db,
                actor,
                &EventSubscription {
                    contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
                    subscription_id: request.subscription_id.clone(),
                    namespace: request.scope.namespace.clone(),
                    owner: actor.into(),
                    stream_id: stream.stream_id.clone(),
                    schema_revision: SCHEMA_REVISION_V1.into(),
                    type_digest: stream.type_digest.clone(),
                    definition_digest: stream.definition_digest.clone(),
                    columns: Vec::new(),
                    retention_ms,
                    status: STATUS_ACTIVE.into(),
                    cursor: EventSubscriptionCursor {
                        generation: 1,
                        feed_epoch: request.snapshot_revision.clone(),
                        committed_offset: 0,
                        last_page_digest: String::new(),
                        admitted_at_ms: now_ms,
                    },
                    registered_by: actor.into(),
                    registered_at_ms: now_ms,
                },
                now_ms,
            )?;
            let admitted = EventSubscription {
                cursor: EventSubscriptionCursor {
                    generation: 1,
                    feed_epoch: request.snapshot_revision.clone(),
                    committed_offset: 0,
                    last_page_digest: String::new(),
                    admitted_at_ms: now_ms,
                },
                ..registered
            };
            db.put_event_subscription(&admitted)?;
            Ok(admitted)
        }
    }
}

fn ensure_object_change_checkpoint(
    db: &RuntimeDb,
    stream: &EventStreamBinding,
    snapshot_revision: &str,
    watermark_seq: u64,
) -> Result<(), String> {
    let current = db
        .get_event_stream_checkpoint(&stream.stream_id)?
        .unwrap_or(EventStreamCheckpoint {
            stream_id: stream.stream_id.clone(),
            generation: 1,
            feed_epoch: snapshot_revision.into(),
            committed_offset: 0,
            last_batch_digest: String::new(),
        });
    let next_offset = watermark_seq.max(current.committed_offset);
    if current.generation == 1
        && current.feed_epoch == snapshot_revision
        && current.committed_offset >= next_offset
    {
        return Ok(());
    }
    let next = EventStreamCheckpoint {
        stream_id: stream.stream_id.clone(),
        generation: 1,
        feed_epoch: snapshot_revision.into(),
        committed_offset: next_offset,
        last_batch_digest: String::new(),
    };
    db.advance_event_stream_checkpoint(&next, &current, &stream.definition_digest, None)
}

/// Projects committed mutations onto `scope` as seen through `visible`: the
/// subscription rules that agent change wakes (#1952) share.
pub fn project_events(
    scope: &ObjectChangeScope,
    visible: &[Object],
    mutations: &[CommittedObjectMutation],
    prior_offset: u64,
    operation_ids: &HashMap<String, String>,
) -> Result<Vec<ObjectChangeEvent>, String> {
    Ok(project(scope, visible, None, mutations, prior_offset, operation_ids)?.unwrap_or_default())
}

/// [`project_events`]; with `reader`, a change to an object the reader may not
/// read (or, deleted, whose history it may not read) yields `None`: the page
/// must restart instead of naming that object.
fn project(
    scope: &ObjectChangeScope,
    visible: &[Object],
    reader: Option<&ReaderVisibility>,
    mutations: &[CommittedObjectMutation],
    prior_offset: u64,
    operation_ids: &HashMap<String, String>,
) -> Result<Option<Vec<ObjectChangeEvent>>, String> {
    let mut events = Vec::new();
    let mut offset = prior_offset;
    let pinned: BTreeSet<&str> = scope.object_ids.iter().map(String::as_str).collect();
    let visible_ids: BTreeSet<&str> = visible.iter().map(|object| object.id.as_str()).collect();
    let deleted_ids: BTreeSet<&str> = mutations
        .iter()
        .filter(|mutation| mutation.change.field == "_deleted")
        .map(|mutation| mutation.change.object_id.as_str())
        .collect();
    for mutation in mutations {
        if !pinned.is_empty() && !pinned.contains(mutation.change.object_id.as_str()) {
            continue;
        }
        if SKIPPED_FIELDS
            .iter()
            .any(|field| mutation.change.field == *field)
            || mutation.change.field.starts_with("_security_property.")
        {
            continue;
        }
        let kind = mutation_kind(mutation);
        if kind != scope.kind {
            continue;
        }
        let live = visible
            .iter()
            .find(|object| object.id == mutation.change.object_id);
        if let Some(object) = live
            && !object_matches_filters(scope, object)
            && mutation.change.field != "_deleted"
        {
            continue;
        }
        // A live object the caller cannot see was never theirs to learn of.
        let object_id = mutation.change.object_id.as_str();
        if mutation.change.field == "_created"
            && !visible_ids.contains(object_id)
            && !deleted_ids.contains(object_id)
        {
            continue;
        }
        if let Some(reader) = reader {
            let attributable = if deleted_ids.contains(object_id) {
                reader.readable_deletes.contains(object_id)
            } else {
                visible_ids.contains(object_id) || reader.readable_ids.contains(object_id)
            };
            if !attributable {
                return Ok(None);
            }
        }
        let op = if mutation.change.field == "_created" {
            OP_CREATE
        } else if mutation.change.field == "_deleted" {
            OP_DELETE
        } else if visible_ids.contains(mutation.change.object_id.as_str()) {
            OP_UPDATE
        } else {
            OP_INVALIDATE
        };
        offset = offset.saturating_add(1);
        events.push(ObjectChangeEvent {
            offset,
            event_id: mutation.change.id.clone(),
            object_id: mutation.change.object_id.clone(),
            kind,
            op: op.into(),
            field: if op == OP_UPDATE {
                mutation.change.field.clone()
            } else {
                String::new()
            },
            committed_at_ms: mutation.change.timestamp,
            operation_id: operation_ids
                .get(&mutation.change.object_id)
                .cloned()
                .unwrap_or_default(),
        });
    }
    Ok(Some(events))
}

fn object_ids_for_projection(
    scope: &ObjectChangeScope,
    mutations: &[CommittedObjectMutation],
) -> Vec<String> {
    let pinned: BTreeSet<&str> = scope.object_ids.iter().map(String::as_str).collect();
    let mut object_ids = mutations
        .iter()
        .filter(|mutation| {
            mutation_kind(mutation) == scope.kind
                && mutation.change.field != "_deleted"
                && !SKIPPED_FIELDS
                    .iter()
                    .any(|field| mutation.change.field == *field)
                && !mutation.change.field.starts_with("_security_property.")
                && (pinned.is_empty() || pinned.contains(mutation.change.object_id.as_str()))
        })
        .map(|mutation| mutation.change.object_id.clone())
        .collect::<Vec<_>>();
    object_ids.sort_unstable();
    object_ids.dedup();
    object_ids
}

/// Ids of the scope's objects that `mutations` delete.
fn deleted_ids_for_projection(
    scope: &ObjectChangeScope,
    mutations: &[CommittedObjectMutation],
) -> Vec<String> {
    let pinned: BTreeSet<&str> = scope.object_ids.iter().map(String::as_str).collect();
    let mut object_ids = mutations
        .iter()
        .filter(|mutation| {
            mutation.change.field == "_deleted"
                && mutation_kind(mutation) == scope.kind
                && (pinned.is_empty() || pinned.contains(mutation.change.object_id.as_str()))
        })
        .map(|mutation| mutation.change.object_id.clone())
        .collect::<Vec<_>>();
    object_ids.sort_unstable();
    object_ids.dedup();
    object_ids
}

/// Clears the subscription's revision and cursor so the next read pins the
/// revision the client resnapshots at; a retry of this read restarts again.
fn restart_for_resnapshot(
    db: &RuntimeDb,
    subscription: &EventSubscription,
    now_ms: i64,
    live_revision: String,
) -> Result<ObjectChangePage, String> {
    let restarted = EventSubscription {
        cursor: EventSubscriptionCursor {
            generation: 1,
            feed_epoch: String::new(),
            committed_offset: 0,
            last_page_digest: String::new(),
            admitted_at_ms: now_ms,
        },
        ..subscription.clone()
    };
    db.put_event_subscription(&restarted)?;
    Ok(resnapshot_page(
        &restarted.subscription_id,
        &restarted.stream_id,
        live_revision,
    ))
}

fn stream_state_matches(
    state: &ObjectChangeStreamState,
    scope: &ObjectChangeScope,
    authorization_pin: &str,
) -> bool {
    state.authorization_pin == authorization_pin
        && state.kind == scope.kind
        && state.object_ids == normalized_object_ids(scope)
        && same_filters(&state.property_filters, &scope.property_filters)
}

fn bind_object_change_stream_state(
    db: &RuntimeDb,
    stream: &EventStreamBinding,
    scope: &ObjectChangeScope,
    authorization_pin: &str,
) -> Result<(), String> {
    let state = ObjectChangeStreamState {
        kind: scope.kind.clone(),
        object_ids: normalized_object_ids(scope),
        property_filters: scope.property_filters.clone(),
        authorization_pin: authorization_pin.into(),
    };
    let binding = EventStreamBinding {
        source_instance: serde_json::to_string(&state).map_err(|error| error.to_string())?,
        type_digest: scope_digest(scope)?,
        ..stream.clone()
    };
    db.put_event_stream_binding(&binding)
}

fn mutation_kind(mutation: &CommittedObjectMutation) -> String {
    if !mutation.object_kind.is_empty() {
        return mutation.object_kind.clone();
    }
    match mutation.change.field.as_str() {
        "_created" => mutation
            .change
            .new_value
            .split('/')
            .next()
            .unwrap_or_default()
            .into(),
        "_deleted" => mutation
            .change
            .old_value
            .split('/')
            .next()
            .unwrap_or_default()
            .into(),
        _ => String::new(),
    }
}

/// Whether `object` satisfies every property filter of `scope`.
pub fn object_matches_filters(scope: &ObjectChangeScope, object: &Object) -> bool {
    if scope.property_filters.is_empty() {
        return true;
    }
    scope.property_filters.iter().all(|filter| {
        let actual = object.properties.get(&filter.key).map(String::as_str);
        match (filter.op.as_str(), actual) {
            ("eq", Some(actual)) => actual == filter.value,
            ("gt", Some(actual)) => compare_filter_value(actual, &filter.value).is_gt(),
            ("gte", Some(actual)) => compare_filter_value(actual, &filter.value).is_ge(),
            ("lt", Some(actual)) => compare_filter_value(actual, &filter.value).is_lt(),
            ("lte", Some(actual)) => compare_filter_value(actual, &filter.value).is_le(),
            _ => false,
        }
    })
}

fn compare_filter_value(actual: &str, expected: &str) -> std::cmp::Ordering {
    match (actual.parse::<f64>(), expected.parse::<f64>()) {
        (Ok(left), Ok(right)) => left
            .partial_cmp(&right)
            .unwrap_or(std::cmp::Ordering::Equal),
        _ => actual.cmp(expected),
    }
}

fn object_change_columns() -> Vec<EventStreamColumn> {
    [
        "object_id",
        "kind",
        "op",
        "field",
        "change_id",
        "committed_at_ms",
    ]
    .into_iter()
    .map(|name| EventStreamColumn {
        name: name.into(),
        col_type: if name == "committed_at_ms" {
            "int".into()
        } else {
            "string".into()
        },
        classification: "public".into(),
    })
    .collect()
}

fn stream_id(namespace: &str, subscription_id: &str) -> String {
    format!("object-change:{namespace}/{subscription_id}")
}

fn same_filters(left: &[PropertyFilter], right: &[PropertyFilter]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.key == b.key && a.op == b.op && a.value == b.value)
}

fn normalized_object_ids(scope: &ObjectChangeScope) -> Vec<String> {
    let mut object_ids = scope.object_ids.clone();
    object_ids.sort();
    object_ids.dedup();
    object_ids
}

fn parse_stream_state(stream: &EventStreamBinding) -> Result<ObjectChangeStreamState, String> {
    if stream.source != OBJECT_CHANGE_SOURCE {
        return Err(SUBSCRIBE_UNAVAILABLE.into());
    }
    serde_json::from_str(&stream.source_instance).map_err(|_| SUBSCRIBE_UNAVAILABLE.to_string())
}

fn idle_past_retention(subscription: &EventSubscription, now_ms: i64) -> bool {
    let origin = if subscription.cursor.admitted_at_ms > 0 {
        subscription.cursor.admitted_at_ms
    } else {
        subscription.registered_at_ms
    };
    now_ms.saturating_sub(origin) > subscription.retention_ms
}

/// A requested page size, defaulted when unset and clamped to the maximum.
pub fn page_limit(limit: i32) -> usize {
    let requested = if limit <= 0 {
        DEFAULT_PAGE_LIMIT
    } else {
        limit
    };
    requested.clamp(1, MAX_PAGE as i32) as usize
}

fn page_digest(
    subscription_id: &str,
    stream_id: &str,
    generation: u64,
    feed_epoch: &str,
    offset_start: u64,
    offset_end: u64,
    events: &[ObjectChangeEvent],
) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&PagePin {
            subscription_id,
            stream_id,
            generation,
            feed_epoch,
            offset_start,
            offset_end,
            events,
        })?
    ))
}

fn resnapshot_page(
    subscription_id: &str,
    stream_id: &str,
    snapshot_revision: String,
) -> ObjectChangePage {
    ObjectChangePage {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        subscription_id: subscription_id.into(),
        stream_id: stream_id.into(),
        outcome: OUTCOME_RESNAPSHOT.into(),
        snapshot_revision,
        generation: 0,
        feed_epoch: String::new(),
        committed_offset: 0,
        page_digest: String::new(),
        events: Vec::new(),
        authority: false,
        disconnect_reason: String::new(),
    }
}

fn revoked_page(subscription: &EventSubscription, snapshot_revision: &str) -> ObjectChangePage {
    ObjectChangePage {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        subscription_id: subscription.subscription_id.clone(),
        stream_id: subscription.stream_id.clone(),
        outcome: OUTCOME_REVOKED.into(),
        snapshot_revision: snapshot_revision.into(),
        generation: subscription.cursor.generation,
        feed_epoch: subscription.cursor.feed_epoch.clone(),
        committed_offset: subscription.cursor.committed_offset,
        page_digest: subscription.cursor.last_page_digest.clone(),
        events: Vec::new(),
        authority: false,
        disconnect_reason: String::new(),
    }
}

fn replayed_page(subscription: &EventSubscription, snapshot_revision: &str) -> ObjectChangePage {
    ObjectChangePage {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        subscription_id: subscription.subscription_id.clone(),
        stream_id: subscription.stream_id.clone(),
        outcome: OUTCOME_REPLAYED.into(),
        snapshot_revision: snapshot_revision.into(),
        generation: subscription.cursor.generation,
        feed_epoch: subscription.cursor.feed_epoch.clone(),
        committed_offset: subscription.cursor.committed_offset,
        page_digest: subscription.cursor.last_page_digest.clone(),
        events: Vec::new(),
        authority: false,
        disconnect_reason: String::new(),
    }
}

fn empty_page(subscription: &EventSubscription, snapshot_revision: &str) -> ObjectChangePage {
    ObjectChangePage {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        subscription_id: subscription.subscription_id.clone(),
        stream_id: subscription.stream_id.clone(),
        outcome: OUTCOME_PAGE.into(),
        snapshot_revision: snapshot_revision.into(),
        generation: subscription.cursor.generation.max(1),
        feed_epoch: subscription.cursor.feed_epoch.clone(),
        committed_offset: subscription.cursor.committed_offset,
        page_digest: subscription.cursor.last_page_digest.clone(),
        events: Vec::new(),
        authority: false,
        disconnect_reason: String::new(),
    }
}

fn disconnect_slow(
    subscription: &EventSubscription,
    snapshot_revision: &str,
) -> Result<ObjectChangePage, String> {
    Ok(ObjectChangePage {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        subscription_id: subscription.subscription_id.clone(),
        stream_id: subscription.stream_id.clone(),
        outcome: OUTCOME_DISCONNECTED.into(),
        snapshot_revision: snapshot_revision.into(),
        generation: subscription.cursor.generation,
        feed_epoch: subscription.cursor.feed_epoch.clone(),
        committed_offset: subscription.cursor.committed_offset,
        page_digest: subscription.cursor.last_page_digest.clone(),
        events: Vec::new(),
        authority: false,
        disconnect_reason: DISCONNECT_SLOW_CONSUMER.into(),
    })
}

fn revoke_page(
    db: &RuntimeDb,
    actor: &str,
    scope: &ObjectChangeScope,
    subscription_id: &str,
    now_ms: i64,
) -> Result<ObjectChangePage, String> {
    let revoked = event_subscription::revoke_event_subscription(
        db,
        actor,
        &scope.namespace,
        subscription_id,
        now_ms,
    )?;
    Ok(revoked_page(&revoked, ""))
}

fn is_valid_kind(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Object;
    use std::collections::HashMap;

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn scope() -> ObjectChangeScope {
        ObjectChangeScope {
            namespace: "sales".into(),
            kind: "Customer".into(),
            object_ids: Vec::new(),
            property_filters: Vec::new(),
        }
    }

    fn customer(id: &str, name: &str, region: &str, ts: i64) -> Object {
        Object {
            id: id.into(),
            kind: "Customer".into(),
            name: name.into(),
            namespace: "sales".into(),
            external_id: format!("sales:{id}"),
            properties: HashMap::from([("region".into(), region.into())]),
            created: ts,
            updated: ts,
        }
    }

    fn visible_customers(ids: &[&str]) -> Vec<Object> {
        ids.iter().map(|id| customer(id, id, "eu", 1)).collect()
    }

    fn read(
        runtime: &RuntimeDb,
        snapshot: &str,
        visible: &[&str],
        now: i64,
        revoke: bool,
        last_digest: &str,
    ) -> ObjectChangePage {
        let objects = visible_customers(visible);
        read_object_change_subscription(
            runtime,
            "alice",
            &ObjectChangeReadRequest {
                subscription_id: "sales-customers".into(),
                scope: scope(),
                snapshot_revision: snapshot.into(),
                limit: 32,
                retention_ms: DEFAULT_RETENTION_MS,
                last_page_digest: last_digest.into(),
                revoke,
            },
            now,
            &objects,
            "sha256:auth",
        )
        .unwrap()
    }

    fn read_with_pin(
        runtime: &RuntimeDb,
        snapshot: &str,
        visible: &[&str],
        now: i64,
        pin: &str,
    ) -> ObjectChangePage {
        read_object_change_subscription(
            runtime,
            "alice",
            &ObjectChangeReadRequest {
                subscription_id: "sales-customers".into(),
                scope: scope(),
                snapshot_revision: snapshot.into(),
                limit: 32,
                retention_ms: DEFAULT_RETENTION_MS,
                last_page_digest: String::new(),
                revoke: false,
            },
            now,
            &visible_customers(visible),
            pin,
        )
        .unwrap()
    }

    #[test]
    fn snapshot_then_insert_update_delete_converges() {
        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let watermark = runtime.object_change_watermark("sales").unwrap();
        let revision = snapshot_revision(&scope(), watermark).unwrap();
        let first = read(&runtime, "", &["c-eu"], 20, false, "");
        assert_eq!(first.outcome, OUTCOME_RESNAPSHOT);
        assert_eq!(first.snapshot_revision, revision);
        assert!(!first.authority);

        let empty = read(&runtime, &revision, &["c-eu"], 21, false, "");
        assert_eq!(empty.outcome, OUTCOME_PAGE);
        assert!(empty.events.is_empty());

        runtime
            .create_object_with_audit(&customer("c-us", "West", "us", 22), "alice")
            .unwrap();
        let mut updated = customer("c-eu", "North", "eu", 10);
        updated.properties.insert("region".into(), "apac".into());
        updated.updated = 23;
        runtime.update_object_with_audit(&updated, "alice").unwrap();
        runtime.delete_object_with_audit("c-us", "alice").unwrap();

        let page = read(&runtime, &revision, &["c-eu"], 24, false, "");
        assert_eq!(page.outcome, OUTCOME_PAGE);
        let ops: Vec<_> = page
            .events
            .iter()
            .map(|event| (event.object_id.as_str(), event.op.as_str()))
            .collect();
        assert!(ops.contains(&("c-us", OP_CREATE)));
        assert!(ops.iter().any(|(id, op)| *id == "c-eu" && *op == OP_UPDATE));
        assert!(ops.contains(&("c-us", OP_DELETE)));
        assert!(
            page.events
                .iter()
                .all(|event| event.op != OP_UPDATE || !event.field.is_empty())
        );
        let replay = read(&runtime, &revision, &["c-eu"], 25, false, &page.page_digest);
        assert_eq!(replay.outcome, OUTCOME_REPLAYED);
        assert_eq!(replay.committed_offset, page.committed_offset);
        assert_eq!(replay.page_digest, page.page_digest);

        let revoked = read(&runtime, &revision, &["c-eu"], 26, true, "");
        assert_eq!(revoked.outcome, OUTCOME_REVOKED);
        let again = read_object_change_subscription(
            &runtime,
            "alice",
            &ObjectChangeReadRequest {
                subscription_id: "sales-customers".into(),
                scope: scope(),
                snapshot_revision: revision,
                limit: 32,
                retention_ms: DEFAULT_RETENTION_MS,
                last_page_digest: String::new(),
                revoke: false,
            },
            27,
            &visible_customers(&["c-eu"]),
            "sha256:auth",
        );
        assert!(again.is_err());
    }

    #[test]
    fn restoring_a_recorded_subscription_redelivers_the_same_page() {
        // #1092: an action binding records the subscription before reading and
        // restores it when a crash lost the page between read and persist.
        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let revision = read(&runtime, "", &["c-eu"], 20, false, "").snapshot_revision;
        read(&runtime, &revision, &["c-eu"], 21, false, "");
        let mut updated = customer("c-eu", "North", "eu", 10);
        updated.properties.insert("region".into(), "apac".into());
        updated.updated = 22;
        runtime.update_object_with_audit(&updated, "alice").unwrap();

        let before = crate::sekai::event_subscription::inspect_event_subscription(
            &runtime,
            "alice",
            "sales",
            "sales-customers",
        )
        .unwrap();
        let lost = read(&runtime, &revision, &["c-eu"], 23, false, "");
        assert!(!lost.events.is_empty());
        let after = crate::sekai::event_subscription::inspect_event_subscription(
            &runtime,
            "alice",
            "sales",
            "sales-customers",
        )
        .unwrap();
        runtime
            .advance_event_subscription_cursor(&before, &after)
            .unwrap();

        let redelivered = read(&runtime, &revision, &["c-eu"], 24, false, "");
        assert_eq!(redelivered.events, lost.events);
    }

    #[test]
    fn expired_retention_and_authorization_change_require_resnapshot() {
        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        let page = read(&runtime, &revision, &["c-eu"], 20, false, "");
        assert_eq!(page.outcome, OUTCOME_PAGE);
        let expired = read(
            &runtime,
            &revision,
            &["c-eu"],
            20 + DEFAULT_RETENTION_MS + 1,
            false,
            "",
        );
        assert_eq!(expired.outcome, OUTCOME_RESNAPSHOT);
        let idle_recovered = read(
            &runtime,
            &expired.snapshot_revision,
            &["c-eu"],
            20 + DEFAULT_RETENTION_MS + 2,
            false,
            "",
        );
        assert_eq!(idle_recovered.outcome, OUTCOME_PAGE);

        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        read(&runtime, &revision, &["c-eu"], 20, false, "");
        let changed = read_with_pin(&runtime, &revision, &[], 21, "sha256:other-auth");
        assert_eq!(changed.outcome, OUTCOME_RESNAPSHOT);
        assert!(changed.events.is_empty());
        let pin_recovered = read_with_pin(
            &runtime,
            &changed.snapshot_revision,
            &["c-eu"],
            22,
            "sha256:other-auth",
        );
        assert_eq!(pin_recovered.outcome, OUTCOME_PAGE);

        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        read_with_pin(&runtime, &revision, &["c-eu"], 20, "sha256:auth");
        runtime
            .create_object_with_audit(&customer("c-us", "West", "us", 21), "alice")
            .unwrap();
        let changed = read_with_pin(
            &runtime,
            &revision,
            &["c-eu", "c-us"],
            22,
            "sha256:other-auth",
        );
        assert_eq!(changed.outcome, OUTCOME_RESNAPSHOT);
        assert!(changed.events.is_empty());
        let recovered = read_with_pin(
            &runtime,
            &changed.snapshot_revision,
            &["c-eu", "c-us"],
            23,
            "sha256:other-auth",
        );
        assert_eq!(recovered.outcome, OUTCOME_PAGE);
        assert!(
            recovered
                .events
                .iter()
                .all(|event| event.object_id != "c-us")
        );
        let retried = read_with_pin(
            &runtime,
            &changed.snapshot_revision,
            &["c-eu", "c-us"],
            24,
            "sha256:auth",
        );
        assert_eq!(retried.outcome, OUTCOME_RESNAPSHOT);
        assert!(retried.events.is_empty());
    }

    #[test]
    fn hidden_updates_invalidate_without_field_names() {
        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        runtime
            .create_object_with_audit(&customer("c-us", "West", "us", 11), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        read(&runtime, &revision, &["c-eu", "c-us"], 20, false, "");
        let mut hidden = customer("c-us", "West", "us", 11);
        hidden.properties.insert("region".into(), "hidden".into());
        hidden.updated = 21;
        runtime.update_object_with_audit(&hidden, "alice").unwrap();
        let page = read(&runtime, &revision, &["c-eu"], 22, false, "");
        let hidden_event = page
            .events
            .iter()
            .find(|event| event.object_id == "c-us")
            .unwrap();
        assert_eq!(hidden_event.op, OP_INVALIDATE);
        assert!(hidden_event.field.is_empty());
    }

    #[test]
    fn creates_of_live_hidden_objects_are_not_delivered() {
        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        read(&runtime, &revision, &["c-eu"], 20, false, "");
        runtime
            .create_object_with_audit(&customer("c-hidden", "Hidden", "eu", 21), "alice")
            .unwrap();
        runtime
            .create_object_with_audit(&customer("c-seen", "Seen", "eu", 22), "alice")
            .unwrap();
        let page = read(&runtime, &revision, &["c-eu", "c-seen"], 23, false, "");
        let ids: Vec<_> = page
            .events
            .iter()
            .map(|event| (event.object_id.as_str(), event.op.as_str()))
            .collect();
        assert_eq!(ids, [("c-seen", OP_CREATE)]);
    }

    fn read_strict(
        runtime: &RuntimeDb,
        snapshot: &str,
        visible: &[&str],
        readable: &[&str],
        readable_deletes: &[&str],
        now: i64,
    ) -> ObjectChangePage {
        let objects = visible_customers(visible);
        let set = |ids: &[&str]| ids.iter().map(|id| id.to_string()).collect();
        read_object_change_subscription_for_reader(
            runtime,
            "alice",
            &ObjectChangeReadRequest {
                subscription_id: "sales-customers".into(),
                scope: scope(),
                snapshot_revision: snapshot.into(),
                limit: 32,
                retention_ms: DEFAULT_RETENTION_MS,
                last_page_digest: String::new(),
                revoke: false,
            },
            now,
            &mut Vec::new(),
            |object_ids, _| {
                let object_ids = object_ids
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                Ok((
                    objects
                        .iter()
                        .filter(|object| object_ids.contains(object.id.as_str()))
                        .cloned()
                        .collect(),
                    ReaderVisibility {
                        readable_ids: set(readable),
                        readable_deletes: set(readable_deletes),
                    },
                ))
            },
            "sha256:auth",
        )
        .unwrap()
    }

    #[test]
    fn strict_readers_learn_only_of_objects_they_may_read() {
        let runtime = db();
        for (id, ts) in [
            ("c-eu", 10),
            ("c-hidden", 11),
            ("c-gone", 12),
            ("c-out", 13),
        ] {
            runtime
                .create_object_with_audit(&customer(id, id, "eu", ts), "alice")
                .unwrap();
        }
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        read_strict(&runtime, &revision, &["c-eu"], &[], &[], 20);

        // A delete whose history the reader may read, and a readable object
        // outside the scope, are named as before.
        runtime.delete_object_with_audit("c-gone", "alice").unwrap();
        let mut out = customer("c-out", "c-out", "us", 13);
        out.updated = 21;
        runtime.update_object_with_audit(&out, "alice").unwrap();
        let page = read_strict(&runtime, &revision, &["c-eu"], &["c-out"], &["c-gone"], 22);
        let ops: Vec<_> = page
            .events
            .iter()
            .map(|event| (event.object_id.as_str(), event.op.as_str()))
            .collect();
        assert_eq!(ops, [("c-gone", OP_DELETE), ("c-out", OP_INVALIDATE)]);

        // A change to an object the reader may not read names nothing and
        // restarts the subscription; a retry restarts again.
        let mut hidden = customer("c-hidden", "c-hidden", "us", 11);
        hidden.updated = 23;
        runtime.update_object_with_audit(&hidden, "alice").unwrap();
        for now in [24, 25] {
            let restarted = read_strict(&runtime, &revision, &["c-eu"], &[], &[], now);
            assert_eq!(restarted.outcome, OUTCOME_RESNAPSHOT);
            assert!(restarted.events.is_empty());
        }

        // The next read at the new revision continues the same subscription.
        let fresh =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        let resumed = read_strict(&runtime, &fresh, &["c-eu"], &[], &[], 26);
        assert_eq!(resumed.outcome, OUTCOME_PAGE);
        assert!(resumed.events.is_empty());
        let mut seen = customer("c-eu", "c-eu", "apac", 10);
        seen.updated = 27;
        runtime.update_object_with_audit(&seen, "alice").unwrap();
        let next = read_strict(&runtime, &fresh, &["c-eu"], &[], &[], 28);
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0].op, OP_UPDATE);

        // A delete whose history the reader may not read names nothing either.
        runtime
            .delete_object_with_audit("c-hidden", "alice")
            .unwrap();
        let refused = read_strict(&runtime, &fresh, &["c-eu"], &[], &[], 29);
        assert_eq!(refused.outcome, OUTCOME_RESNAPSHOT);
        assert!(refused.events.is_empty());
    }

    #[test]
    fn slow_consumer_is_disconnected_explicitly() {
        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        read(&runtime, &revision, &["c-eu"], 20, false, "");
        for index in 0..=MAX_BACKLOG {
            let mut updated = customer("c-eu", "North", "eu", 10);
            updated
                .properties
                .insert("region".into(), format!("r{index}"));
            updated.updated = 21 + i64::from(index);
            runtime.update_object_with_audit(&updated, "alice").unwrap();
        }
        let page = read(&runtime, &revision, &["c-eu"], 10_000, false, "");
        assert_eq!(page.outcome, OUTCOME_DISCONNECTED);
        assert_eq!(page.disconnect_reason, DISCONNECT_SLOW_CONSUMER);
        assert!(page.events.is_empty());
    }

    fn order(id: &str, ts: i64) -> Object {
        Object {
            id: id.into(),
            kind: "Order".into(),
            name: id.into(),
            namespace: "sales".into(),
            external_id: format!("sales:{id}"),
            properties: HashMap::from([("status".into(), "open".into())]),
            created: ts,
            updated: ts,
        }
    }

    fn inspect_customers(runtime: &RuntimeDb) -> EventSubscription {
        crate::sekai::event_subscription::inspect_event_subscription(
            runtime,
            "alice",
            "sales",
            "sales-customers",
        )
        .unwrap()
    }

    #[test]
    fn out_of_scope_mutations_are_skipped_without_disconnecting() {
        // #2740: a subscriber caught up on its own kind must skip a busy
        // sibling kind instead of looking like a slow consumer.
        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        read(&runtime, &revision, &["c-eu"], 20, false, "");

        runtime
            .create_object_with_audit(&order("o-1", 21), "alice")
            .unwrap();
        for index in 0..300 {
            let mut updated = order("o-1", 21);
            updated
                .properties
                .insert("status".into(), format!("s{index}"));
            updated.updated = 22 + i64::from(index);
            runtime.update_object_with_audit(&updated, "alice").unwrap();
        }

        let mut now = 400i64;
        let mut last_offset = inspect_customers(&runtime).cursor.committed_offset;
        loop {
            now += 1;
            assert!(now < 420, "out-of-scope backlog should skip in a few pages");
            let page = read(&runtime, &revision, &["c-eu"], now, false, "");
            assert_eq!(page.outcome, OUTCOME_PAGE);
            assert!(page.events.is_empty());
            assert_eq!(page.disconnect_reason, "");
            if page.committed_offset == last_offset {
                break;
            }
            last_offset = page.committed_offset;
        }

        let mut seen = customer("c-eu", "North", "eu", 10);
        seen.properties.insert("region".into(), "apac".into());
        seen.updated = now + 1;
        runtime.update_object_with_audit(&seen, "alice").unwrap();
        let page = read(&runtime, &revision, &["c-eu"], now + 2, false, "");
        assert_eq!(page.outcome, OUTCOME_PAGE);
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].object_id, "c-eu");
        assert_eq!(page.events[0].op, OP_UPDATE);
    }

    #[test]
    fn empty_page_cursor_advance_retry_does_not_skip_in_scope_event() {
        // #2740: CAS-advancing past an empty projection, then losing that
        // persist and retrying, must still deliver a later in-scope event.
        let runtime = db();
        runtime
            .create_object_with_audit(&customer("c-eu", "North", "eu", 10), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        read(&runtime, &revision, &["c-eu"], 20, false, "");
        runtime
            .create_object_with_audit(&order("o-1", 21), "alice")
            .unwrap();

        let before = inspect_customers(&runtime);
        let skipped = read(&runtime, &revision, &["c-eu"], 40, false, "");
        assert_eq!(skipped.outcome, OUTCOME_PAGE);
        assert!(skipped.events.is_empty());
        assert!(skipped.committed_offset > before.cursor.committed_offset);
        let after = inspect_customers(&runtime);
        runtime
            .advance_event_subscription_cursor(&before, &after)
            .unwrap();

        let mut seen = customer("c-eu", "North", "eu", 10);
        seen.properties.insert("region".into(), "apac".into());
        seen.updated = 41;
        runtime.update_object_with_audit(&seen, "alice").unwrap();
        let page = read(&runtime, &revision, &["c-eu"], 42, false, "");
        assert_eq!(page.outcome, OUTCOME_PAGE);
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].object_id, "c-eu");
        assert_eq!(page.events[0].op, OP_UPDATE);
    }

    fn postgres_runtime() -> RuntimeDb {
        let database_url = std::env::var("SEKAI_TEST_POSTGRES_URL").unwrap_or_else(|_| {
            panic!("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database")
        });
        let db = if let Ok(ca_certificate_path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            let ca_certificate = std::fs::read(&ca_certificate_path).unwrap_or_else(|error| {
                panic!("read PostgreSQL test CA certificate {ca_certificate_path}: {error}")
            });
            crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &database_url,
                4,
                &ca_certificate,
            )
            .unwrap()
        } else {
            crate::db::postgres::PostgresDb::connect(&database_url, 4).unwrap()
        };
        RuntimeDb::Postgres(std::sync::Arc::new(db))
    }

    fn assert_postgres_committed_matrix(runtime: &RuntimeDb) {
        let suffix = uuid::Uuid::new_v4().as_simple().to_string();
        let id = format!("c-eu-{suffix}");
        runtime
            .create_object_with_audit(&customer(&id, "North", "eu", 10), "alice")
            .unwrap();
        let revision =
            snapshot_revision(&scope(), runtime.object_change_watermark("sales").unwrap()).unwrap();
        let objects = [customer(&id, "North", "eu", 10)];
        let first = read_object_change_subscription(
            runtime,
            "alice",
            &ObjectChangeReadRequest {
                subscription_id: format!("sales-customers-{suffix}"),
                scope: scope(),
                snapshot_revision: String::new(),
                limit: 32,
                retention_ms: DEFAULT_RETENTION_MS,
                last_page_digest: String::new(),
                revoke: false,
            },
            20,
            &objects,
            "sha256:auth",
        )
        .unwrap();
        assert_eq!(first.outcome, OUTCOME_RESNAPSHOT);
        assert_eq!(first.snapshot_revision, revision);
        let page = read_object_change_subscription(
            runtime,
            "alice",
            &ObjectChangeReadRequest {
                subscription_id: format!("sales-customers-{suffix}"),
                scope: scope(),
                snapshot_revision: revision.clone(),
                limit: 32,
                retention_ms: DEFAULT_RETENTION_MS,
                last_page_digest: String::new(),
                revoke: false,
            },
            21,
            &objects,
            "sha256:auth",
        )
        .unwrap();
        assert_eq!(page.outcome, OUTCOME_PAGE);
        assert!(!page.authority);
        let changed = read_object_change_subscription(
            runtime,
            "alice",
            &ObjectChangeReadRequest {
                subscription_id: format!("sales-customers-{suffix}"),
                scope: scope(),
                snapshot_revision: revision.clone(),
                limit: 32,
                retention_ms: DEFAULT_RETENTION_MS,
                last_page_digest: String::new(),
                revoke: false,
            },
            22,
            &objects,
            "sha256:other-auth",
        )
        .unwrap();
        assert_eq!(changed.outcome, OUTCOME_RESNAPSHOT);
        let recovered = read_object_change_subscription(
            runtime,
            "alice",
            &ObjectChangeReadRequest {
                subscription_id: format!("sales-customers-{suffix}"),
                scope: scope(),
                snapshot_revision: changed.snapshot_revision,
                limit: 32,
                retention_ms: DEFAULT_RETENTION_MS,
                last_page_digest: String::new(),
                revoke: false,
            },
            23,
            &objects,
            "sha256:other-auth",
        )
        .unwrap();
        assert_eq!(recovered.outcome, OUTCOME_PAGE);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_object_change_subscription_matrix() {
        assert_postgres_committed_matrix(&postgres_runtime());
    }
}
