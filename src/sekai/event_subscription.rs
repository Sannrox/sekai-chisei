//! Governed event subscriptions (#691).
//!
//! A subscription is a consumer cursor over an admitted
//! `sekai.event-stream-projection/v1` stream. It is not a broker client.

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::event_stream::{
    self, EventStreamBatch, EventStreamBinding, ProjectedStreamEvent, StreamEvent,
};
use crate::shomei;

pub const EVENT_SUBSCRIPTION_CONTRACT: &str = "sekai.event-subscription/v1";
pub const SCHEMA_REVISION_V1: &str = "v1";
pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_REVOKED: &str = "revoked";
pub const SUBSCRIBE_UNAVAILABLE: &str = "event subscription is not admitted";
pub const PAGE_MALFORMED: &str = "event subscription page is malformed";
pub const PAGE_GAP: &str = "event subscription page has a gap";
pub const PAGE_LATE: &str = "event subscription page is late";
pub const REVISION_UNSUPPORTED: &str = "event subscription revision is unsupported";
pub const RETENTION_GAP: &str = "event subscription retention window elapsed";
pub const CURSOR_CONFLICT: &str = "event subscription cursor conflict";
pub const POSTGRES_UNAVAILABLE: &str =
    "event subscriptions are unavailable on the PostgreSQL community runtime";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSubscriptionCursor {
    pub generation: u64,
    pub feed_epoch: String,
    pub committed_offset: u64,
    pub last_page_digest: String,
    pub admitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSubscription {
    pub contract_version: String,
    pub subscription_id: String,
    pub namespace: String,
    pub owner: String,
    pub stream_id: String,
    pub schema_revision: String,
    pub type_digest: String,
    pub definition_digest: String,
    pub columns: Vec<String>,
    pub retention_ms: i64,
    pub status: String,
    pub cursor: EventSubscriptionCursor,
    pub registered_by: String,
    pub registered_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSubscriptionPage {
    pub subscription_id: String,
    pub namespace: String,
    pub stream_id: String,
    pub generation: u64,
    pub feed_epoch: String,
    pub offset_start: u64,
    pub offset_end: u64,
    pub events: Vec<StreamEvent>,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSubscriptionDelivery {
    pub contract_version: String,
    pub namespace: String,
    pub subscription_id: String,
    pub stream_id: String,
    pub generation: u64,
    pub feed_epoch: String,
    pub definition_digest: String,
    pub outcome: String,
    pub columns: Vec<String>,
    pub event_count: u32,
    pub page_digest: String,
    pub cursor: EventSubscriptionCursor,
    pub events: Vec<ProjectedStreamEvent>,
}

#[derive(Serialize)]
struct PagePin<'a> {
    subscription_id: &'a str,
    namespace: &'a str,
    stream_id: &'a str,
    generation: u64,
    feed_epoch: &'a str,
    offset_start: u64,
    offset_end: u64,
    events: &'a [StreamEvent],
}

pub fn page_digest_for(page: &EventSubscriptionPage) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&PagePin {
            subscription_id: &page.subscription_id,
            namespace: &page.namespace,
            stream_id: &page.stream_id,
            generation: page.generation,
            feed_epoch: &page.feed_epoch,
            offset_start: page.offset_start,
            offset_end: page.offset_end,
            events: &page.events,
        })?
    ))
}

pub fn register_event_subscription(
    db: &RuntimeDb,
    actor: &str,
    subscription: &EventSubscription,
    now_ms: i64,
) -> Result<EventSubscription, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("register timestamp must be non-negative".into());
    }
    let stream = admitted_stream(db, actor, subscription)?;
    let validated = finalize_register_columns(
        db,
        actor,
        validate_subscription(subscription, &stream, actor, now_ms)?,
        &stream,
    )?;
    if let Some(existing) =
        db.get_event_subscription(&validated.namespace, &validated.subscription_id)?
    {
        if existing.owner != actor || existing.status == STATUS_REVOKED {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
        if same_pins(&existing, &validated) && !idle_past_retention(&existing, now_ms) {
            return Ok(existing);
        }
    }
    db.put_event_subscription(&validated)?;
    Ok(validated)
}

pub fn inspect_event_subscription(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    subscription_id: &str,
) -> Result<EventSubscription, String> {
    required("actor", actor)?;
    owned_subscription(db, actor, namespace, subscription_id)
}

pub fn revoke_event_subscription(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    subscription_id: &str,
    now_ms: i64,
) -> Result<EventSubscription, String> {
    required("actor", actor)?;
    if now_ms < 0 {
        return Err("revoke timestamp must be non-negative".into());
    }
    owned_subscription(db, actor, namespace, subscription_id)?;
    db.revoke_event_subscription_record(namespace, subscription_id, actor)
}

pub fn deliver_subscription_page(
    db: &RuntimeDb,
    actor: &str,
    page: &EventSubscriptionPage,
    now_ms: i64,
) -> Result<EventSubscriptionDelivery, String> {
    required("actor", actor)?;
    required("subscription id", &page.subscription_id)?;
    required("namespace", &page.namespace)?;
    if now_ms < 0 {
        return Err("deliver timestamp must be non-negative".into());
    }
    let subscription = owned_subscription(db, actor, &page.namespace, &page.subscription_id)?;
    if subscription.status != STATUS_ACTIVE {
        return Err(SUBSCRIBE_UNAVAILABLE.into());
    }
    let stream = db
        .get_event_stream_binding(&subscription.stream_id)?
        .ok_or(SUBSCRIBE_UNAVAILABLE)?;
    if stream.owner != actor
        || stream.namespace != subscription.namespace
        || stream.stream_id != page.stream_id
        || page.stream_id != subscription.stream_id
    {
        return Err(SUBSCRIBE_UNAVAILABLE.into());
    }
    if stream.schema_revision != subscription.schema_revision
        || stream.type_digest != subscription.type_digest
        || stream.definition_digest != subscription.definition_digest
        || subscription.schema_revision != SCHEMA_REVISION_V1
    {
        return Err(REVISION_UNSUPPORTED.into());
    }

    let checkpoint = db
        .get_event_stream_checkpoint(&subscription.stream_id)?
        .ok_or(PAGE_GAP)?;
    if checkpoint.generation != page.generation || checkpoint.feed_epoch != page.feed_epoch {
        return Err(PAGE_GAP.into());
    }
    if checkpoint.committed_offset < page.offset_end {
        return Err(PAGE_GAP.into());
    }

    let digest = page_digest_for(page)?;
    if digest != page.content_digest {
        return Err(PAGE_MALFORMED.into());
    }
    if idle_past_retention(&subscription, now_ms) {
        return Err(RETENTION_GAP.into());
    }

    let authority = event_stream::stream_authority(db, actor)?;
    let visible = event_stream::authorized_columns(&stream, &authority);
    let authorized = resolve_authorized_columns(&subscription, &visible)?;
    let batch = page_as_batch(page);
    event_stream::validate_batch(&stream, &batch).map_err(map_batch_error)?;
    db.verify_event_stream_admitted_events(
        &page.stream_id,
        page.generation,
        &page.feed_epoch,
        &page.events,
    )
    .map_err(map_batch_error)?;

    if let Some(delivery) = decided_without_advance(&subscription, page, &authorized, &digest)? {
        return Ok(delivery);
    }

    let events = event_stream::project_events(&batch, &authorized).map_err(map_batch_error)?;
    let next = EventSubscription {
        cursor: EventSubscriptionCursor {
            generation: page.generation,
            feed_epoch: page.feed_epoch.clone(),
            committed_offset: page.offset_end,
            last_page_digest: digest.clone(),
            admitted_at_ms: now_ms,
        },
        ..subscription.clone()
    };
    match db.advance_event_subscription_cursor(&next, &subscription) {
        Ok(()) => delivery_result(&next, page, &authorized, events, "accepted"),
        Err(error) if error == CURSOR_CONFLICT => {
            let latest = owned_subscription(db, actor, &page.namespace, &page.subscription_id)?;
            decided_without_advance(&latest, page, &authorized, &digest)?
                .ok_or_else(|| PAGE_GAP.to_string())
        }
        Err(error) => Err(error),
    }
}

fn admitted_stream(
    db: &RuntimeDb,
    actor: &str,
    subscription: &EventSubscription,
) -> Result<EventStreamBinding, String> {
    required("stream id", &subscription.stream_id)?;
    required("namespace", &subscription.namespace)?;
    let stream = db
        .get_event_stream_binding(&subscription.stream_id)?
        .ok_or(SUBSCRIBE_UNAVAILABLE)?;
    if stream.owner != actor || stream.namespace != subscription.namespace {
        return Err(SUBSCRIBE_UNAVAILABLE.into());
    }
    if stream.schema_revision != SCHEMA_REVISION_V1
        || subscription.schema_revision != SCHEMA_REVISION_V1
        || subscription.contract_version != EVENT_SUBSCRIPTION_CONTRACT
    {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if !subscription.type_digest.is_empty() && subscription.type_digest != stream.type_digest {
        return Err(REVISION_UNSUPPORTED.into());
    }
    if !subscription.definition_digest.is_empty()
        && subscription.definition_digest != stream.definition_digest
    {
        return Err(REVISION_UNSUPPORTED.into());
    }
    Ok(stream)
}

fn validate_subscription(
    subscription: &EventSubscription,
    stream: &EventStreamBinding,
    actor: &str,
    now_ms: i64,
) -> Result<EventSubscription, String> {
    required("subscription id", &subscription.subscription_id)?;
    required("owner", &subscription.owner)?;
    if subscription.owner != actor {
        return Err(SUBSCRIBE_UNAVAILABLE.into());
    }
    if subscription.retention_ms <= 0 {
        return Err(PAGE_MALFORMED.into());
    }
    if !matches!(
        subscription.status.as_str(),
        "" | STATUS_ACTIVE | STATUS_REVOKED
    ) {
        return Err(PAGE_MALFORMED.into());
    }
    let known: Vec<&str> = stream
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect();
    for name in &subscription.columns {
        required("column name", name)?;
        if !known.contains(&name.as_str()) {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
    }
    Ok(EventSubscription {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        subscription_id: subscription.subscription_id.clone(),
        namespace: stream.namespace.clone(),
        owner: actor.into(),
        stream_id: stream.stream_id.clone(),
        schema_revision: stream.schema_revision.clone(),
        type_digest: stream.type_digest.clone(),
        definition_digest: stream.definition_digest.clone(),
        columns: subscription.columns.clone(),
        retention_ms: subscription.retention_ms,
        status: STATUS_ACTIVE.into(),
        cursor: EventSubscriptionCursor {
            generation: 0,
            feed_epoch: String::new(),
            committed_offset: 0,
            last_page_digest: String::new(),
            admitted_at_ms: 0,
        },
        registered_by: actor.into(),
        registered_at_ms: now_ms,
    })
}

fn finalize_register_columns(
    db: &RuntimeDb,
    actor: &str,
    mut subscription: EventSubscription,
    stream: &EventStreamBinding,
) -> Result<EventSubscription, String> {
    let authority = event_stream::stream_authority(db, actor)?;
    let visible = event_stream::authorized_columns(stream, &authority);
    resolve_authorized_columns(&subscription, &visible)?;
    if subscription.columns.is_empty() {
        subscription.columns = visible;
    }
    Ok(subscription)
}

fn resolve_authorized_columns(
    subscription: &EventSubscription,
    visible: &[String],
) -> Result<Vec<String>, String> {
    if subscription.columns.is_empty() {
        if visible.is_empty() {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
        return Ok(visible.to_vec());
    }
    for name in &subscription.columns {
        if !visible.iter().any(|column| column == name) {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
    }
    Ok(subscription.columns.clone())
}

fn owned_subscription(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    subscription_id: &str,
) -> Result<EventSubscription, String> {
    required("namespace", namespace)?;
    required("subscription id", subscription_id)?;
    let subscription = db
        .get_event_subscription(namespace, subscription_id)?
        .ok_or(SUBSCRIBE_UNAVAILABLE)?;
    if subscription.owner != actor || subscription.namespace != namespace {
        return Err(SUBSCRIBE_UNAVAILABLE.into());
    }
    Ok(subscription)
}

fn same_pins(existing: &EventSubscription, next: &EventSubscription) -> bool {
    existing.stream_id == next.stream_id
        && existing.schema_revision == next.schema_revision
        && existing.type_digest == next.type_digest
        && existing.definition_digest == next.definition_digest
        && existing.columns == next.columns
        && existing.retention_ms == next.retention_ms
        && existing.status == STATUS_ACTIVE
}

fn idle_past_retention(subscription: &EventSubscription, now_ms: i64) -> bool {
    let origin = if subscription.cursor.admitted_at_ms > 0 {
        subscription.cursor.admitted_at_ms
    } else {
        subscription.registered_at_ms
    };
    now_ms.saturating_sub(origin) > subscription.retention_ms
}

fn page_as_batch(page: &EventSubscriptionPage) -> EventStreamBatch {
    EventStreamBatch {
        stream_id: page.stream_id.clone(),
        generation: page.generation,
        feed_epoch: page.feed_epoch.clone(),
        offset_start: page.offset_start,
        offset_end: page.offset_end,
        events: page.events.clone(),
        content_digest: String::new(),
    }
}

fn decided_without_advance(
    subscription: &EventSubscription,
    page: &EventSubscriptionPage,
    authorized: &[String],
    digest: &str,
) -> Result<Option<EventSubscriptionDelivery>, String> {
    if subscription.cursor.committed_offset == 0 {
        if page.offset_start != 1 {
            return Err(PAGE_GAP.into());
        }
        return Ok(None);
    }
    if subscription.cursor.generation != page.generation
        || subscription.cursor.feed_epoch != page.feed_epoch
    {
        return Err(PAGE_GAP.into());
    }
    if page.offset_end <= subscription.cursor.committed_offset {
        if digest == subscription.cursor.last_page_digest
            && page.offset_start <= subscription.cursor.committed_offset
        {
            let events = event_stream::project_events(&page_as_batch(page), authorized)
                .map_err(map_batch_error)?;
            return Ok(Some(delivery_result(
                subscription,
                page,
                authorized,
                events,
                "replayed",
            )?));
        }
        return Err(PAGE_LATE.into());
    }
    if page.offset_start != subscription.cursor.committed_offset.saturating_add(1) {
        return Err(PAGE_GAP.into());
    }
    Ok(None)
}

fn delivery_result(
    subscription: &EventSubscription,
    page: &EventSubscriptionPage,
    authorized: &[String],
    events: Vec<ProjectedStreamEvent>,
    outcome: &str,
) -> Result<EventSubscriptionDelivery, String> {
    Ok(EventSubscriptionDelivery {
        contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
        namespace: subscription.namespace.clone(),
        subscription_id: subscription.subscription_id.clone(),
        stream_id: subscription.stream_id.clone(),
        generation: page.generation,
        feed_epoch: page.feed_epoch.clone(),
        definition_digest: subscription.definition_digest.clone(),
        outcome: outcome.into(),
        columns: authorized.to_vec(),
        event_count: u32::try_from(events.len()).map_err(|error| error.to_string())?,
        page_digest: page.content_digest.clone(),
        cursor: subscription.cursor.clone(),
        events,
    })
}

fn map_batch_error(error: String) -> String {
    if error == event_stream::BATCH_MALFORMED {
        PAGE_MALFORMED.into()
    } else if error == event_stream::BATCH_GAP {
        PAGE_GAP.into()
    } else if error == event_stream::BATCH_LATE {
        PAGE_LATE.into()
    } else if error == event_stream::REVISION_UNSUPPORTED {
        REVISION_UNSUPPORTED.into()
    } else if error == event_stream::PROJECT_UNAVAILABLE {
        SUBSCRIBE_UNAVAILABLE.into()
    } else {
        error
    }
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
    use crate::sekai::event_stream::{
        EventStreamColumn, SCHEMA_REVISION_V1 as STREAM_REVISION, batch_digest_for,
        project_event_batch, register_event_stream,
    };
    use crate::sekai::markings::{
        PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY, PRINCIPAL_PROFILE_KIND,
        PRINCIPAL_PROFILE_SEALED_PROPERTY, principal_profile_external_id,
    };
    use crate::sekai::security::{Grant, Role};
    use std::collections::{BTreeMap, HashMap};

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn pin_ceiling(runtime: &RuntimeDb, principal: &str, ceiling: &str) {
        let profile_id = format!("profile:{principal}");
        runtime
            .create_object(&Object {
                id: profile_id.clone(),
                kind: PRINCIPAL_PROFILE_KIND.into(),
                name: principal.into(),
                namespace: "ops".into(),
                external_id: principal_profile_external_id(principal),
                properties: HashMap::from([
                    (
                        PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.into(),
                        ceiling.into(),
                    ),
                    (PRINCIPAL_PROFILE_SEALED_PROPERTY.into(), "true".into()),
                ]),
                created: 1,
                updated: 1,
            })
            .unwrap();
        runtime
            .create_grant(&Grant {
                id: format!("grant:{principal}"),
                object_id: profile_id,
                principal: "root".into(),
                role: Role::Admin,
                created: 1,
            })
            .unwrap();
    }

    fn stream_binding() -> EventStreamBinding {
        EventStreamBinding {
            contract_version: event_stream::EVENT_STREAM_CONTRACT.into(),
            stream_id: "github:ops".into(),
            namespace: "ops".into(),
            owner: "analyst".into(),
            source: "github".into(),
            source_instance: "sekai/chisei".into(),
            schema_revision: STREAM_REVISION.into(),
            type_digest: "sha256:typedef".into(),
            definition_digest: String::new(),
            columns: vec![
                EventStreamColumn {
                    name: "id".into(),
                    col_type: "int".into(),
                    classification: "public".into(),
                },
                EventStreamColumn {
                    name: "kind".into(),
                    col_type: "string".into(),
                    classification: "internal".into(),
                },
                EventStreamColumn {
                    name: "secret".into(),
                    col_type: "string".into(),
                    classification: "restricted".into(),
                },
            ],
            registered_by: String::new(),
            registered_at_ms: 0,
        }
    }

    fn event(offset: u64) -> StreamEvent {
        StreamEvent {
            offset,
            event_id: format!("e{offset}"),
            properties: BTreeMap::from([
                ("id".into(), offset.to_string()),
                ("kind".into(), "issue".into()),
                ("secret".into(), "hidden".into()),
            ]),
        }
    }

    fn projected_batch(start: u64, end: u64) -> EventStreamBatch {
        let events: Vec<_> = (start..=end).map(event).collect();
        let mut batch = EventStreamBatch {
            stream_id: "github:ops".into(),
            generation: 1,
            feed_epoch: "epoch-1".into(),
            offset_start: start,
            offset_end: end,
            events,
            content_digest: String::new(),
        };
        batch.content_digest = batch_digest_for(&batch).unwrap();
        batch
    }

    fn page(start: u64, end: u64) -> EventSubscriptionPage {
        let events: Vec<_> = (start..=end).map(event).collect();
        let mut page = EventSubscriptionPage {
            subscription_id: "ops-alerts".into(),
            namespace: "ops".into(),
            stream_id: "github:ops".into(),
            generation: 1,
            feed_epoch: "epoch-1".into(),
            offset_start: start,
            offset_end: end,
            events,
            content_digest: String::new(),
        };
        page.content_digest = page_digest_for(&page).unwrap();
        page
    }

    fn subscription() -> EventSubscription {
        EventSubscription {
            contract_version: EVENT_SUBSCRIPTION_CONTRACT.into(),
            subscription_id: "ops-alerts".into(),
            namespace: "ops".into(),
            owner: "analyst".into(),
            stream_id: "github:ops".into(),
            schema_revision: SCHEMA_REVISION_V1.into(),
            type_digest: String::new(),
            definition_digest: String::new(),
            columns: vec!["id".into(), "kind".into()],
            retention_ms: 10_000,
            status: String::new(),
            cursor: EventSubscriptionCursor {
                generation: 0,
                feed_epoch: String::new(),
                committed_offset: 0,
                last_page_digest: String::new(),
                admitted_at_ms: 0,
            },
            registered_by: String::new(),
            registered_at_ms: 0,
        }
    }

    fn setup() -> RuntimeDb {
        let runtime = db();
        pin_ceiling(&runtime, "analyst", "internal");
        register_event_stream(&runtime, "analyst", &stream_binding(), 1_000).unwrap();
        project_event_batch(&runtime, "analyst", &projected_batch(1, 2), 2_000).unwrap();
        register_event_subscription(&runtime, "analyst", &subscription(), 3_000).unwrap();
        runtime
    }

    #[test]
    fn accepted_page_replays_and_survives_reregister() {
        let runtime = setup();
        let first = deliver_subscription_page(&runtime, "analyst", &page(1, 1), 4_000).unwrap();
        assert_eq!(first.outcome, "accepted");
        assert_eq!(first.cursor.committed_offset, 1);
        assert_eq!(first.event_count, 1);
        assert!(
            first
                .events
                .iter()
                .all(|event| !event.properties.contains_key("secret"))
        );

        let replay = deliver_subscription_page(&runtime, "analyst", &page(1, 1), 4_100).unwrap();
        assert_eq!(replay.outcome, "replayed");
        assert_eq!(replay.cursor.committed_offset, 1);
        assert_eq!(replay.page_digest, first.page_digest);

        let restarted =
            register_event_subscription(&runtime, "analyst", &subscription(), 4_200).unwrap();
        assert_eq!(restarted.cursor.committed_offset, 1);
        let next = deliver_subscription_page(&runtime, "analyst", &page(2, 2), 4_300).unwrap();
        assert_eq!(next.outcome, "accepted");
        assert_eq!(next.cursor.committed_offset, 2);
    }

    #[test]
    fn gap_late_malformed_and_unadmitted_offsets_fail_closed() {
        let runtime = setup();
        deliver_subscription_page(&runtime, "analyst", &page(1, 2), 4_000).unwrap();
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &page(3, 3), 4_100).unwrap_err(),
            PAGE_GAP
        );
        let mut fabricated = page(1, 2);
        fabricated.events[0].event_id = "other".into();
        fabricated.content_digest = page_digest_for(&fabricated).unwrap();
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &fabricated, 4_200).unwrap_err(),
            PAGE_MALFORMED
        );
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &page(1, 1), 4_250).unwrap_err(),
            PAGE_LATE
        );
        let mut malformed = page(2, 2);
        malformed.events[0].offset = 9;
        malformed.content_digest = page_digest_for(&malformed).unwrap();
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &malformed, 4_300).unwrap_err(),
            PAGE_MALFORMED
        );
        assert_eq!(
            inspect_event_subscription(&runtime, "analyst", "ops", "ops-alerts")
                .unwrap()
                .cursor
                .committed_offset,
            2
        );
    }

    #[test]
    fn retention_revocation_cross_namespace_and_hidden_identity_fail_before_disclosure() {
        let runtime = setup();
        deliver_subscription_page(&runtime, "analyst", &page(1, 1), 4_000).unwrap();
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &page(1, 1), 20_000).unwrap_err(),
            RETENTION_GAP
        );
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &page(2, 2), 20_100).unwrap_err(),
            RETENTION_GAP
        );
        let recovered =
            register_event_subscription(&runtime, "analyst", &subscription(), 20_200).unwrap();
        assert_eq!(recovered.cursor.committed_offset, 0);
        let restarted =
            deliver_subscription_page(&runtime, "analyst", &page(1, 1), 20_300).unwrap();
        assert_eq!(restarted.outcome, "accepted");

        let revoked =
            revoke_event_subscription(&runtime, "analyst", "ops", "ops-alerts", 21_000).unwrap();
        assert_eq!(revoked.status, STATUS_REVOKED);
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &page(1, 1), 21_100).unwrap_err(),
            SUBSCRIBE_UNAVAILABLE
        );
        assert_eq!(
            register_event_subscription(&runtime, "analyst", &subscription(), 21_200).unwrap_err(),
            SUBSCRIBE_UNAVAILABLE
        );
        assert_eq!(
            inspect_event_subscription(&runtime, "intruder", "ops", "ops-alerts").unwrap_err(),
            SUBSCRIBE_UNAVAILABLE
        );
        assert_eq!(
            inspect_event_subscription(&runtime, "analyst", "ops", "missing").unwrap_err(),
            SUBSCRIBE_UNAVAILABLE
        );
        assert_eq!(
            inspect_event_subscription(&runtime, "analyst", "other", "ops-alerts").unwrap_err(),
            SUBSCRIBE_UNAVAILABLE
        );

        let mut foreign = subscription();
        foreign.subscription_id = "other-alerts".into();
        foreign.namespace = "other".into();
        assert_eq!(
            register_event_subscription(&runtime, "analyst", &foreign, 22_000).unwrap_err(),
            SUBSCRIBE_UNAVAILABLE
        );
        assert_eq!(
            register_event_subscription(&runtime, "intruder", &subscription(), 22_100).unwrap_err(),
            SUBSCRIBE_UNAVAILABLE
        );

        let mut hidden = subscription();
        hidden.subscription_id = "hidden-secret".into();
        hidden.columns = vec!["secret".into()];
        assert_eq!(
            register_event_subscription(&runtime, "analyst", &hidden, 22_200).unwrap_err(),
            SUBSCRIBE_UNAVAILABLE
        );
    }

    #[test]
    fn stale_definition_and_idle_register_expire() {
        let runtime = setup();
        let mut next_stream = stream_binding();
        next_stream.type_digest = "sha256:other".into();
        register_event_stream(&runtime, "analyst", &next_stream, 5_000).unwrap();
        project_event_batch(&runtime, "analyst", &projected_batch(1, 1), 5_100).unwrap();
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &page(1, 1), 5_200).unwrap_err(),
            REVISION_UNSUPPORTED
        );

        let mut stale = subscription();
        stale.subscription_id = "idle".into();
        register_event_subscription(&runtime, "analyst", &stale, 6_000).unwrap();
        let mut idle_page = page(1, 1);
        idle_page.subscription_id = "idle".into();
        idle_page.content_digest = page_digest_for(&idle_page).unwrap();
        assert_eq!(
            deliver_subscription_page(&runtime, "analyst", &idle_page, 20_000).unwrap_err(),
            RETENTION_GAP
        );
    }
}
