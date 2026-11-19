//! Ezu adapter (#2182): keeps Ezu, the external spatial store, in step with
//! governed objects, turns its fence events into governed Actions, and
//! filters every user-facing Ezu read through the plane. It runs outside the
//! plane as a service principal on stable RPCs only (ADR 0147, ADR 0148); see
//! `docs/ezu-adapter.md`.
//!
//! - [`GeoFeedRunner`]: a snapshot, then the object-change subscription, into
//!   one Ezu collection. Fences are plane objects fed the same way.
//! - [`FenceRunner`]: Ezu fence events into `SubmitActionInstance`, keyed
//!   `ezu:{lsn}:{index}`.
//! - [`nearby`], [`positions`], [`tracks`]: Ezu reads that return only the
//!   objects the reader may read in the plane, checked at read time with the
//!   reader's own credential.
//!
//! Each runner holds a lease (`AcquireLease`, `TakeoverExpiredLease`). Its
//! cursor is a plane object written only under that lease, so another
//! instance takes over where the last durable write left off, and a runner
//! that lost its lease cannot move the cursor. Nothing on the adapter's disk
//! is authoritative.
//!
//! The Ezu URL and bearer belong to the [`Ezu`] implementation the deployment
//! provides; they never enter the plane. Hosting the runners and the read
//! endpoint is a deployment decision outside this module.

use std::collections::{BTreeMap, BTreeSet};

use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{
    AcquireLeaseRequest, CreateObjectRequest, EvaluateObjectSetRequest, GetLeaseRequest,
    GetObjectRequest, GetPublishedDefinitionRevisionRequest, LeasePrecondition, ListFilter,
    ListObjectsRequest, Object, ObjectChangeEvent, ObjectChangeSubscriptionScope,
    ObjectSetDescriptor, PropertyFilter, ReadObjectChangeSubscriptionRequest,
    ReadObjectChangeSubscriptionResponse, RefreshLeaseRequest, SubmitActionInstanceRequest,
    TakeoverExpiredLeaseRequest, UpdateObjectRequest,
};
use serde::{Deserialize, Serialize};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

/// Kind of the plane objects that hold a runner's cursor.
pub const STATE_KIND: &str = "ezu_adapter_state";
/// Property of a fence object that names the Action type its events submit.
pub const FENCE_ACTION_TYPE_PROPERTY: &str = "action_type";
/// Most ids one user-facing read returns or filters.
pub const MAX_READ_IDS: usize = 200;

const SUBSCRIPTION_PAGE: i32 = 64;
const LIST_PAGE: i32 = 1_000;
const EVENT_PAGE: u32 = 64;
const OUTCOME_PAGE: &str = "page";
const OUTCOME_RESNAPSHOT: &str = "resnapshot_required";
const OUTCOME_REPLAYED: &str = "replayed";
const OUTCOME_DISCONNECTED: &str = "disconnected";
const OP_DELETE: &str = "delete";
const OP_INVALIDATE: &str = "invalidate";
const OBJECT_SET_CONTRACT: &str = "sekai.object-set/v1";
/// Never copied into Ezu: the marking property and plane-internal properties.
const ACCESS_MARKING_PROPERTY: &str = "access_marking";

#[derive(Debug)]
pub enum Error {
    /// The plane refused or failed a call. Nothing after it was acknowledged.
    Plane(Status),
    /// Ezu failed. Nothing after it was acknowledged.
    Ezu(String),
    /// Another runner holds or took over the lease. Drop this runner.
    LeaseLost,
    /// The stored cursor or a configuration value is unusable.
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plane(status) => write!(f, "plane: {}: {}", status.code(), status.message()),
            Self::Ezu(message) => write!(f, "Ezu: {message}"),
            Self::LeaseLost => f.write_str("lease lost to another runner"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<Status> for Error {
    fn from(status: Status) -> Self {
        Self::Plane(status)
    }
}

/// The plane as one principal: every call carries its bearer.
#[derive(Clone)]
pub struct Sekai {
    client: SekaiServiceClient<Channel>,
    bearer: String,
}

impl Sekai {
    /// The adapter's service principal, or, for one user-facing read, the
    /// reader. The bearer is held only as long as this value.
    pub fn new(client: SekaiServiceClient<Channel>, bearer: impl Into<String>) -> Self {
        Self {
            client,
            bearer: bearer.into(),
        }
    }

    fn request<T>(&self, message: T) -> Result<Request<T>, Error> {
        let mut request = Request::new(message);
        let value = MetadataValue::try_from(format!("Bearer {}", self.bearer))
            .map_err(|_| Error::Invalid("credential is not a valid header value".into()))?;
        request.metadata_mut().insert("authorization", value);
        Ok(request)
    }

    /// `None` when the object is absent or hidden from this principal.
    async fn get_object(&self, id: &str) -> Result<Option<Object>, Error> {
        let request = self.request(GetObjectRequest { id: id.into() })?;
        match self.client.clone().get_object(request).await {
            Ok(response) => Ok(response.into_inner().object),
            Err(status) if matches!(status.code(), Code::NotFound | Code::PermissionDenied) => {
                Ok(None)
            }
            Err(status) => Err(status.into()),
        }
    }
}

/// One object kind fed into one Ezu collection. The collection names the
/// feed: its lease, cursor, and subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoFeed {
    pub namespace: String,
    pub kind: String,
    /// Holds a `sekai.geospatial-value/v1`, passed to Ezu unchanged.
    pub geometry_property: String,
    pub collection: String,
    /// Properties copied as Ezu fields when present.
    #[serde(default)]
    pub filter_fields: Vec<String>,
}

/// Fence events of fences of `fence_kind` that name `type_id`, submitted as
/// that Action type at `version`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceBinding {
    pub binding_id: String,
    pub namespace: String,
    pub fence_kind: String,
    pub type_id: String,
    pub version: String,
    /// Action parameter name to the event field it is mapped from.
    pub parameters: BTreeMap<String, EventField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventField {
    Fence,
    Entity,
    Collection,
    Kind,
    TsMs,
}

/// The `EZU_ADAPTER_CONFIG` document.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterConfig {
    #[serde(default)]
    pub feeds: Vec<GeoFeed>,
    #[serde(default)]
    pub bindings: Vec<FenceBinding>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entity {
    pub collection: String,
    pub id: String,
    pub geometry: String,
    pub ts_ms: i64,
    pub fields: BTreeMap<String, String>,
}

/// One position of one entity: a live position or a point of a track.
#[derive(Debug, Clone, PartialEq)]
pub struct Position {
    pub id: String,
    pub geometry: String,
    pub ts_ms: i64,
}

/// `(lsn, index)`: Ezu's total order of fence events.
pub type EventId = (u64, u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceEvent {
    pub lsn: u64,
    pub index: u32,
    pub fence: String,
    pub collection: String,
    pub entity: String,
    pub kind: String,
    pub ts_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct EventPage {
    pub events: Vec<FenceEvent>,
    /// Resume point, past any events Ezu skipped. `None`: the last event.
    pub through: Option<EventId>,
}

/// Ezu as the adapter uses it. Writes are ordered by `ts_ms` per entity: an
/// upsert or an expire applies unless Ezu holds something strictly newer for
/// the id (entity or tombstone), and an expire leaves a tombstone, so a late
/// write of an older state loses. On a tie the later write wins: one lease
/// holder writes a collection at a time, always with current state.
#[allow(async_fn_in_trait)]
pub trait Ezu {
    async fn upsert(&self, entity: &Entity) -> Result<(), String>;
    async fn expire(&self, collection: &str, id: &str, ts_ms: i64) -> Result<(), String>;
    /// Every live entity id in `collection`.
    async fn entity_ids(&self, collection: &str) -> Result<Vec<String>, String>;
    async fn events_after(&self, after: Option<EventId>, limit: u32) -> Result<EventPage, String>;
    async fn nearby(
        &self,
        collection: &str,
        center: [f64; 2],
        radius_m: f64,
        limit: usize,
    ) -> Result<Vec<Position>, String>;
    async fn positions(&self, collection: &str, ids: &[String]) -> Result<Vec<Position>, String>;
    async fn tracks(
        &self,
        collection: &str,
        ids: &[String],
        since_ms: i64,
    ) -> Result<Vec<Position>, String>;
}

/// The lease one runner holds on `key`.
struct Lease {
    namespace: String,
    key: String,
    fencing_token: String,
    ttl_ms: i64,
}

impl Lease {
    /// Acquires `key`, or takes it over once its holder let it expire.
    /// `None` while another runner holds it.
    async fn hold(
        sekai: &Sekai,
        namespace: &str,
        key: &str,
        owner: &str,
        ttl_ms: i64,
    ) -> Result<Option<Self>, Error> {
        let acquire = sekai.request(AcquireLeaseRequest {
            namespace: namespace.into(),
            key: key.into(),
            owner: owner.into(),
            ttl_ms,
            request_id: request_id(),
        })?;
        let lease = match sekai.client.clone().acquire_lease(acquire).await {
            Ok(response) => response.into_inner().lease,
            Err(status) if status.code() == Code::AlreadyExists => {
                let get = sekai.request(GetLeaseRequest {
                    namespace: namespace.into(),
                    key: key.into(),
                })?;
                let held = sekai
                    .client
                    .clone()
                    .get_lease(get)
                    .await?
                    .into_inner()
                    .lease
                    .ok_or_else(|| Error::Invalid("lease answer without a lease".into()))?;
                let takeover = sekai.request(TakeoverExpiredLeaseRequest {
                    namespace: namespace.into(),
                    key: key.into(),
                    owner: owner.into(),
                    expected_fencing_token: held.fencing_token,
                    expected_expires_at_ms: held.expires_at_ms,
                    ttl_ms,
                    request_id: request_id(),
                })?;
                match sekai.client.clone().takeover_expired_lease(takeover).await {
                    Ok(response) => response.into_inner().lease,
                    // Not expired, or another contender took it first.
                    Err(status) if status.code() == Code::FailedPrecondition => return Ok(None),
                    Err(status) => return Err(status.into()),
                }
            }
            Err(status) => return Err(status.into()),
        };
        let lease = lease.ok_or_else(|| Error::Invalid("lease answer without a lease".into()))?;
        Ok(Some(Self {
            namespace: namespace.into(),
            key: key.into(),
            fencing_token: lease.fencing_token,
            ttl_ms,
        }))
    }

    /// Returns the plane time of the refresh.
    async fn refresh(&self, sekai: &Sekai) -> Result<i64, Error> {
        let request = sekai.request(RefreshLeaseRequest {
            namespace: self.namespace.clone(),
            key: self.key.clone(),
            fencing_token: self.fencing_token.clone(),
            ttl_ms: self.ttl_ms,
            request_id: request_id(),
        })?;
        match sekai.client.clone().refresh_lease(request).await {
            Ok(response) => response
                .into_inner()
                .lease
                .map(|lease| lease.refreshed_at_ms)
                .ok_or_else(|| Error::Invalid("lease answer without a lease".into())),
            Err(status) if status.code() == Code::FailedPrecondition => Err(Error::LeaseLost),
            Err(status) => Err(status.into()),
        }
    }

    fn precondition(&self) -> Option<LeasePrecondition> {
        Some(LeasePrecondition {
            namespace: self.namespace.clone(),
            key: self.key.clone(),
            fencing_token: self.fencing_token.clone(),
            request_id: request_id(),
        })
    }
}

/// A runner's cursor object: read once, then written only under the lease.
struct Cursor {
    object: Object,
    stored: bool,
}

impl Cursor {
    async fn load(sekai: &Sekai, namespace: &str, id: &str) -> Result<Self, Error> {
        Ok(match sekai.get_object(id).await? {
            Some(object) => Self {
                object,
                stored: true,
            },
            None => Self {
                object: Object {
                    id: id.into(),
                    kind: STATE_KIND.into(),
                    name: id.into(),
                    namespace: namespace.into(),
                    ..Default::default()
                },
                stored: false,
            },
        })
    }

    fn get(&self, key: &str) -> &str {
        self.object.properties.get(key).map_or("", String::as_str)
    }

    fn set(&mut self, key: &str, value: String) {
        self.object.properties.insert(key.into(), value);
    }

    /// A failed precondition means the lease moved on: stop this runner.
    async fn save(&mut self, sekai: &Sekai, lease: &Lease) -> Result<(), Error> {
        let object = Some(self.object.clone());
        let lease_precondition = lease.precondition();
        let written = if self.stored {
            let request = sekai.request(UpdateObjectRequest {
                object,
                lease_precondition,
            })?;
            sekai
                .client
                .clone()
                .update_object(request)
                .await
                .map(|response| response.into_inner().object)
        } else {
            let request = sekai.request(CreateObjectRequest {
                object,
                lease_precondition,
            })?;
            sekai
                .client
                .clone()
                .create_object(request)
                .await
                .map(|response| response.into_inner().object)
        };
        match written {
            Ok(object) => {
                if let Some(object) = object {
                    self.object = object;
                }
                self.stored = true;
                Ok(())
            }
            Err(status) if status.code() == Code::FailedPrecondition => Err(Error::LeaseLost),
            Err(status) => Err(status.into()),
        }
    }
}

/// Whether a step did work. After `Worked`, step again without waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Worked,
    Idle,
}

const FEED: &str = "feed";
const SUBSCRIPTION: &str = "subscription_id";
const SNAPSHOT_REVISION: &str = "snapshot_revision";
const PAGE_DIGEST: &str = "page_digest";
const PENDING_EVENTS: &str = "pending_events";

/// Feeds one object kind into one Ezu collection: snapshot, then stream.
///
/// A read commits the subscription cursor on delivery, so each page is made
/// durable in the adapter's cursor, with its `page_digest`, before it is
/// applied: a crash while applying replays it, and Ezu's ordering makes the
/// replayed writes no-ops. A runner that loads the cursor first asks the
/// plane to replay the stored digest. `replayed` proves no page was
/// delivered after it; any other answer, or no stored page since the
/// snapshot, means a page may be lost, and the runner takes a new snapshot.
/// So does a cursor written for different feed settings. An idle step writes
/// nothing to the plane.
///
/// Ezu orders the feed's writes by plane time: the step's lease refresh, or
/// an event's `committed_at_ms` when that is later. Every write carries the
/// state the plane holds after that time, so a write from a runner that lost
/// its lease, which refreshed before the takeover, loses; and a visibility
/// tombstone or an entity written under older feed settings loses to the
/// next observation. Object `updated` times are set by writers, so they are
/// not used.
pub struct GeoFeedRunner {
    sekai: Sekai,
    feed: GeoFeed,
    lease: Lease,
    cursor: Option<Cursor>,
}

#[derive(Serialize, Deserialize)]
struct PendingEvent {
    object_id: String,
    op: String,
    committed_at_ms: i64,
}

impl GeoFeedRunner {
    /// Holds the feed's lease as `owner`. `None` while another runner holds
    /// it and it has not expired.
    pub async fn start(
        sekai: Sekai,
        feed: GeoFeed,
        owner: &str,
        ttl_ms: i64,
    ) -> Result<Option<Self>, Error> {
        let key = format!("ezu-geo-feed/{}", feed.collection);
        let Some(lease) = Lease::hold(&sekai, &feed.namespace, &key, owner, ttl_ms).await? else {
            return Ok(None);
        };
        Ok(Some(Self {
            sekai,
            feed,
            lease,
            cursor: None,
        }))
    }

    /// One snapshot, or one page: apply the pending page, then read the next.
    pub async fn step<E: Ezu>(&mut self, ezu: &E) -> Result<Step, Error> {
        let step = self.try_step(ezu).await;
        if step.is_err() {
            // Reload and recheck the durable cursor; this one may be ahead.
            self.cursor = None;
        }
        step
    }

    async fn try_step<E: Ezu>(&mut self, ezu: &E) -> Result<Step, Error> {
        let now_ms = self.lease.refresh(&self.sekai).await?;
        let mut cursor = match self.cursor.take() {
            Some(cursor) => cursor,
            None => {
                let id = format!("ezu-adapter.geo-feed.{}", self.feed.collection);
                let mut cursor = Cursor::load(&self.sekai, &self.feed.namespace, &id).await?;
                if cursor.get(FEED) != self.settings()? || !self.in_step(&cursor).await? {
                    cursor.set(SNAPSHOT_REVISION, String::new());
                }
                cursor
            }
        };
        let pending: Vec<PendingEvent> = match cursor.get(PENDING_EVENTS) {
            "" => Vec::new(),
            json => serde_json::from_str(json)
                .map_err(|_| Error::Invalid("stored pending page is unreadable".into()))?,
        };
        self.apply(ezu, &pending, now_ms).await?;
        cursor.set(PENDING_EVENTS, String::new());

        if cursor.get(SNAPSHOT_REVISION).is_empty() {
            // A subscription keeps the revision it was first read at, so a
            // new snapshot needs a new subscription. End the old one, and
            // store the new id before reading it, so a crash mid-snapshot
            // leaves no subscription the next runner cannot revoke.
            if !cursor.get(SUBSCRIPTION).is_empty() {
                self.revoke(cursor.get(SUBSCRIPTION)).await?;
            }
            let subscription = format!(
                "ezu-geo-feed.{}.{}",
                self.feed.collection,
                uuid::Uuid::new_v4().simple()
            );
            cursor.set(SUBSCRIPTION, subscription);
            cursor.set(FEED, self.settings()?);
            cursor.set(PAGE_DIGEST, String::new());
            cursor.save(&self.sekai, &self.lease).await?;
            let revision = self.snapshot(ezu, cursor.get(SUBSCRIPTION), now_ms).await?;
            cursor.set(SNAPSHOT_REVISION, revision);
            cursor.save(&self.sekai, &self.lease).await?;
            self.cursor = Some(cursor);
            return Ok(Step::Worked);
        }

        let page = self
            .read(cursor.get(SUBSCRIPTION), cursor.get(SNAPSHOT_REVISION), "")
            .await?;
        let step = match page.outcome.as_str() {
            OUTCOME_PAGE if page.events.is_empty() => {
                self.cursor = Some(cursor);
                return Ok(Step::Idle);
            }
            OUTCOME_PAGE => {
                let events = page
                    .events
                    .iter()
                    .map(PendingEvent::from)
                    .collect::<Vec<_>>();
                let json = serde_json::to_string(&events)
                    .map_err(|_| Error::Invalid("page is not serializable".into()))?;
                cursor.set(PENDING_EVENTS, json);
                cursor.set(PAGE_DIGEST, page.page_digest);
                Step::Worked
            }
            OUTCOME_RESNAPSHOT | OUTCOME_DISCONNECTED => {
                cursor.set(SNAPSHOT_REVISION, String::new());
                Step::Worked
            }
            outcome => return Err(Error::Invalid(format!("subscription is {outcome}"))),
        };
        cursor.save(&self.sekai, &self.lease).await?;
        self.cursor = Some(cursor);
        Ok(step)
    }

    /// The feed settings the cursor was written for.
    fn settings(&self) -> Result<String, Error> {
        serde_json::to_string(&self.feed)
            .map_err(|_| Error::Invalid("feed is not serializable".into()))
    }

    /// Whether the plane delivered nothing after the stored cursor's last
    /// page: an exact replay of its digest answers `replayed`.
    async fn in_step(&self, cursor: &Cursor) -> Result<bool, Error> {
        let (revision, digest) = (cursor.get(SNAPSHOT_REVISION), cursor.get(PAGE_DIGEST));
        if revision.is_empty() || digest.is_empty() {
            return Ok(false);
        }
        let replay = self
            .read(cursor.get(SUBSCRIPTION), revision, digest)
            .await?;
        Ok(replay.outcome == OUTCOME_REPLAYED)
    }

    async fn read(
        &self,
        subscription_id: &str,
        snapshot_revision: &str,
        last_page_digest: &str,
    ) -> Result<ReadObjectChangeSubscriptionResponse, Error> {
        self.call_subscription(ReadObjectChangeSubscriptionRequest {
            subscription_id: subscription_id.into(),
            snapshot_revision: snapshot_revision.into(),
            limit: SUBSCRIPTION_PAGE,
            last_page_digest: last_page_digest.into(),
            ..Default::default()
        })
        .await
    }

    /// Ends `subscription_id`. One that is already gone needs nothing.
    async fn revoke(&self, subscription_id: &str) -> Result<(), Error> {
        let revoked = self
            .call_subscription(ReadObjectChangeSubscriptionRequest {
                subscription_id: subscription_id.into(),
                revoke: true,
                ..Default::default()
            })
            .await;
        match revoked {
            Err(Error::Plane(status))
                if matches!(status.code(), Code::NotFound | Code::FailedPrecondition) =>
            {
                Ok(())
            }
            other => other.map(drop),
        }
    }

    async fn call_subscription(
        &self,
        mut request: ReadObjectChangeSubscriptionRequest,
    ) -> Result<ReadObjectChangeSubscriptionResponse, Error> {
        request.scope = Some(ObjectChangeSubscriptionScope {
            namespace: self.feed.namespace.clone(),
            kind: self.feed.kind.clone(),
            ..Default::default()
        });
        let request = self.sekai.request(request)?;
        Ok(self
            .sekai
            .client
            .clone()
            .read_object_change_subscription(request)
            .await?
            .into_inner())
    }

    /// Pins a revision, writes every visible object, and expires every Ezu
    /// entity the listing did not name, at `started_ms`, a plane time before
    /// the pin. Returns the pinned revision.
    async fn snapshot<E: Ezu>(
        &self,
        ezu: &E,
        subscription_id: &str,
        started_ms: i64,
    ) -> Result<String, Error> {
        let pin = self.read(subscription_id, "", "").await?;
        if pin.outcome != OUTCOME_RESNAPSHOT || pin.snapshot_revision.is_empty() {
            return Err(Error::Invalid(format!(
                "subscription pin answered {}",
                pin.outcome
            )));
        }
        let mut listed = BTreeSet::new();
        let mut page_token = String::new();
        loop {
            let request = self.sekai.request(ListObjectsRequest {
                filter: Some(ListFilter {
                    kind: self.feed.kind.clone(),
                    namespace: self.feed.namespace.clone(),
                    limit: LIST_PAGE,
                    ..Default::default()
                }),
                page_token,
            })?;
            let page = self
                .sekai
                .client
                .clone()
                .list_objects(request)
                .await?
                .into_inner();
            for object in &page.objects {
                listed.insert(object.id.clone());
                self.write(ezu, object, started_ms).await?;
            }
            if page.next_page_token.is_empty() {
                break;
            }
            page_token = page.next_page_token;
        }
        for id in ezu
            .entity_ids(&self.feed.collection)
            .await
            .map_err(Error::Ezu)?
        {
            if !listed.contains(&id) {
                ezu.expire(&self.feed.collection, &id, started_ms)
                    .await
                    .map_err(Error::Ezu)?;
            }
        }
        Ok(pin.snapshot_revision)
    }

    /// Writes each named object's current state once, as the adapter sees it,
    /// at `now_ms` or the event's commit time when that is later.
    async fn apply<E: Ezu>(
        &self,
        ezu: &E,
        events: &[PendingEvent],
        now_ms: i64,
    ) -> Result<(), Error> {
        let mut last = BTreeMap::new();
        for event in events {
            last.insert(event.object_id.as_str(), event);
        }
        for (id, event) in last {
            let ts_ms = now_ms.max(event.committed_at_ms);
            let gone = event.op == OP_DELETE || event.op == OP_INVALIDATE;
            match if gone {
                None
            } else {
                self.sekai.get_object(id).await?
            } {
                Some(object) => self.write(ezu, &object, ts_ms).await?,
                None => ezu
                    .expire(&self.feed.collection, id, ts_ms)
                    .await
                    .map_err(Error::Ezu)?,
            }
        }
        Ok(())
    }

    /// Upserts `object` at `ts_ms`, or expires it without geometry.
    async fn write<E: Ezu>(&self, ezu: &E, object: &Object, ts_ms: i64) -> Result<(), Error> {
        let collection = &self.feed.collection;
        let written = match object
            .properties
            .get(&self.feed.geometry_property)
            .filter(|geometry| !geometry.is_empty())
        {
            Some(geometry) => {
                let fields = self
                    .feed
                    .filter_fields
                    .iter()
                    .filter(|field| copyable(field))
                    .filter_map(|field| {
                        Some((field.clone(), object.properties.get(field)?.clone()))
                    })
                    .collect();
                ezu.upsert(&Entity {
                    collection: collection.clone(),
                    id: object.id.clone(),
                    geometry: geometry.clone(),
                    ts_ms,
                    fields,
                })
                .await
            }
            None => ezu.expire(collection, &object.id, ts_ms).await,
        };
        written.map_err(Error::Ezu)
    }
}

impl From<&ObjectChangeEvent> for PendingEvent {
    fn from(event: &ObjectChangeEvent) -> Self {
        Self {
            object_id: event.object_id.clone(),
            op: event.op.clone(),
            committed_at_ms: event.committed_at_ms,
        }
    }
}

fn copyable(field: &str) -> bool {
    field != ACCESS_MARKING_PROPERTY && !field.starts_with('_')
}

const AFTER_LSN: &str = "after_lsn";
const AFTER_INDEX: &str = "after_index";

/// Turns Ezu fence events into governed Actions for one binding.
///
/// Only a fence that is a plane object of the bound kind, visible to the
/// adapter and naming the bound Action type, submits; a fence created in Ezu
/// directly submits nothing. The cursor moves after the page, so a crash
/// replays it and the idempotency key turns each replayed submit into the
/// original instance.
pub struct FenceRunner {
    sekai: Sekai,
    binding: FenceBinding,
    lease: Lease,
    cursor: Option<Cursor>,
}

impl FenceRunner {
    /// Holds the binding's lease as `owner`. `None` while another runner
    /// holds it and it has not expired.
    pub async fn start(
        sekai: Sekai,
        binding: FenceBinding,
        owner: &str,
        ttl_ms: i64,
    ) -> Result<Option<Self>, Error> {
        let key = format!("ezu-fence/{}", binding.binding_id);
        let Some(lease) = Lease::hold(&sekai, &binding.namespace, &key, owner, ttl_ms).await?
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            sekai,
            binding,
            lease,
            cursor: None,
        }))
    }

    /// Reads one page of Ezu events after the cursor and submits the bound ones.
    pub async fn step<E: Ezu>(&mut self, ezu: &E) -> Result<Step, Error> {
        let step = self.try_step(ezu).await;
        if step.is_err() {
            self.cursor = None;
        }
        step
    }

    async fn try_step<E: Ezu>(&mut self, ezu: &E) -> Result<Step, Error> {
        self.lease.refresh(&self.sekai).await?;
        let mut cursor = match self.cursor.take() {
            Some(cursor) => cursor,
            None => {
                let id = format!("ezu-adapter.fence.{}", self.binding.binding_id);
                Cursor::load(&self.sekai, &self.binding.namespace, &id).await?
            }
        };
        let after = match (cursor.get(AFTER_LSN), cursor.get(AFTER_INDEX)) {
            ("", _) => None,
            (lsn, index) => Some((
                lsn.parse()
                    .map_err(|_| Error::Invalid("stored cursor is unreadable".into()))?,
                index
                    .parse()
                    .map_err(|_| Error::Invalid("stored cursor is unreadable".into()))?,
            )),
        };
        let page = ezu
            .events_after(after, EVENT_PAGE)
            .await
            .map_err(Error::Ezu)?;
        let through = page
            .through
            .or_else(|| page.events.last().map(|event| (event.lsn, event.index)));
        let Some((lsn, index)) = through.filter(|through| Some(*through) != after) else {
            self.cursor = Some(cursor);
            return Ok(Step::Idle);
        };
        for event in &page.events {
            self.submit(event).await?;
        }
        cursor.set(AFTER_LSN, lsn.to_string());
        cursor.set(AFTER_INDEX, index.to_string());
        cursor.save(&self.sekai, &self.lease).await?;
        self.cursor = Some(cursor);
        Ok(Step::Worked)
    }

    async fn submit(&self, event: &FenceEvent) -> Result<(), Error> {
        let binding = &self.binding;
        let Some(fence) = self.sekai.get_object(&event.fence).await? else {
            return Ok(());
        };
        let bound = fence.kind == binding.fence_kind
            && fence.namespace == binding.namespace
            && fence.properties.get(FENCE_ACTION_TYPE_PROPERTY) == Some(&binding.type_id);
        if !bound {
            return Ok(());
        }
        let parameters = binding
            .parameters
            .iter()
            .map(|(name, field)| {
                let value = match field {
                    EventField::Fence => event.fence.clone().into(),
                    EventField::Entity => event.entity.clone().into(),
                    EventField::Collection => event.collection.clone().into(),
                    EventField::Kind => event.kind.clone().into(),
                    EventField::TsMs => event.ts_ms.into(),
                };
                (name.clone(), value)
            })
            .collect::<serde_json::Map<_, serde_json::Value>>();
        let request = self.sekai.request(SubmitActionInstanceRequest {
            namespace: binding.namespace.clone(),
            type_id: binding.type_id.clone(),
            version: binding.version.clone(),
            parameters_json: serde_json::Value::Object(parameters).to_string(),
            idempotency_key: format!("ezu:{}:{}", event.lsn, event.index),
            ..Default::default()
        })?;
        self.sekai
            .client
            .clone()
            .submit_action_instance(request)
            .await?;
        Ok(())
    }
}

/// Positions within `radius_m` of `center` (`[lon, lat]`) that `reader` may
/// see. Ezu answers at most [`MAX_READ_IDS`]; the plane drops the rest.
pub async fn nearby<E: Ezu>(
    reader: &Sekai,
    ezu: &E,
    feed: &GeoFeed,
    center: [f64; 2],
    radius_m: f64,
) -> Result<Vec<Position>, Error> {
    let mut found = ezu
        .nearby(&feed.collection, center, radius_m, MAX_READ_IDS)
        .await
        .map_err(Error::Ezu)?;
    found.truncate(MAX_READ_IDS);
    let ids = found
        .iter()
        .map(|position| position.id.clone())
        .collect::<BTreeSet<_>>();
    let visible = visible_ids(reader, feed, ids).await?;
    found.retain(|position| visible.contains(&position.id));
    Ok(found)
}

/// Live positions of the `ids` that `reader` may see. Plane first: Ezu is
/// asked only for visible ids.
pub async fn positions<E: Ezu>(
    reader: &Sekai,
    ezu: &E,
    feed: &GeoFeed,
    ids: &[String],
) -> Result<Vec<Position>, Error> {
    let visible = visible_list(reader, feed, ids).await?;
    if visible.is_empty() {
        return Ok(Vec::new());
    }
    let mut found = ezu
        .positions(&feed.collection, &visible)
        .await
        .map_err(Error::Ezu)?;
    found.retain(|position| visible.contains(&position.id));
    Ok(found)
}

/// Track points since `since_ms` of the `ids` that `reader` may see.
pub async fn tracks<E: Ezu>(
    reader: &Sekai,
    ezu: &E,
    feed: &GeoFeed,
    ids: &[String],
    since_ms: i64,
) -> Result<Vec<Position>, Error> {
    let visible = visible_list(reader, feed, ids).await?;
    if visible.is_empty() {
        return Ok(Vec::new());
    }
    let mut found = ezu
        .tracks(&feed.collection, &visible, since_ms)
        .await
        .map_err(Error::Ezu)?;
    found.retain(|point| visible.contains(&point.id));
    Ok(found)
}

async fn visible_list(
    reader: &Sekai,
    feed: &GeoFeed,
    ids: &[String],
) -> Result<Vec<String>, Error> {
    if ids.len() > MAX_READ_IDS {
        return Err(Error::Invalid(format!(
            "a read names at most {MAX_READ_IDS} ids"
        )));
    }
    let ids = ids.iter().cloned().collect::<BTreeSet<_>>();
    Ok(visible_ids(reader, feed, ids).await?.into_iter().collect())
}

/// The subset of `ids` that `reader` may read now: one `EvaluateObjectSet`
/// with an id `in` filter, as the reader, so namespace, grant, and marking
/// checks are the plane's normal read path. Any refusal fails the read.
async fn visible_ids(
    reader: &Sekai,
    feed: &GeoFeed,
    ids: BTreeSet<String>,
) -> Result<BTreeSet<String>, Error> {
    if ids.is_empty() {
        return Ok(ids);
    }
    let request = reader.request(GetPublishedDefinitionRevisionRequest {
        namespace: feed.namespace.clone(),
    })?;
    let definition_digest = reader
        .client
        .clone()
        .get_published_definition_revision(request)
        .await?
        .into_inner()
        .revision
        .map(|revision| revision.revision_digest)
        .unwrap_or_default();
    let filter = PropertyFilter {
        key: "id".into(),
        op: "in".into(),
        value: serde_json::to_string(&ids)
            .map_err(|_| Error::Invalid("ids are not serializable".into()))?,
    };
    let mut visible = BTreeSet::new();
    let mut page_token = String::new();
    loop {
        let request = reader.request(EvaluateObjectSetRequest {
            descriptor: Some(ObjectSetDescriptor {
                contract_version: OBJECT_SET_CONTRACT.into(),
                namespace: feed.namespace.clone(),
                kind: feed.kind.clone(),
                definition_digest: definition_digest.clone(),
                property_filters: vec![filter.clone()],
                limit: MAX_READ_IDS as i32,
                ..Default::default()
            }),
            page_token,
            ..Default::default()
        })?;
        let page = reader
            .client
            .clone()
            .evaluate_object_set(request)
            .await?
            .into_inner();
        visible.extend(
            page.members
                .into_iter()
                .map(|member| member.id)
                .filter(|id| ids.contains(id)),
        );
        if page.next_page_token.is_empty() {
            return Ok(visible);
        }
        page_token = page.next_page_token;
    }
}

fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
