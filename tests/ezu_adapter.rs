//! The Ezu adapter (#2182) against an in-process plane over gRPC and a fake
//! Ezu. The plane, leases, subscriptions, grants, markings, and Action
//! admission are real; bearer tokens name principals directly, standing in
//! for the plane's authentication layer.

#[allow(dead_code)]
#[path = "../adapters/ezu.rs"]
mod ezu;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ezu::{
    Entity, Error, EventField, EventId, EventPage, Ezu, FenceBinding, FenceEvent, FenceRunner,
    GeoFeed, GeoFeedRunner, Position, Sekai, Step,
};
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::SekaiStore;
use sekai_chisei::domain::Object;
use sekai_chisei::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use sekai_chisei::grpc::pb::sekai::sekai_service_server::{SekaiService, SekaiServiceServer};
use sekai_chisei::grpc::pb::sekai::{
    CreateGrantRequest, GovernedActionType, Grant, PutGovernedActionTypeRequest,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::action_policy::ActionPolicy;
use sekai_chisei::sekai::definition_branch::{
    DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
};
use sekai_chisei::sekai::security::Role;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

const NS: &str = "fleet";
const ADMIN: &str = "local";
const ADAPTER: &str = "svc-ezu";
const VEHICLE: &str = "vehicle";
const FENCE: &str = "geofence";
const ACTION: &str = "fleet.fence.alert";
/// A lease that outlives any test. Steps refresh it, so a slow machine only
/// delays a test; it never loses the lease.
const HELD_TTL_MS: i64 = 60_000;
/// A lease a test lets expire. Each step refreshes it, so it only has to
/// outlast the pause between two steps.
const EXPIRING_TTL_MS: i64 = 2_000;

/// Plane RPCs the transport fails once, standing in for a crash.
#[derive(Clone, Default)]
struct Faults {
    /// The next subscription read commits in the plane, then its answer is lost.
    lose_read: Arc<AtomicBool>,
    /// The next cursor write is refused before it reaches the plane.
    refuse_cursor_write: Arc<AtomicBool>,
}

struct Plane {
    db: Arc<RuntimeDb>,
    svc: SekaiServiceImpl,
    client: SekaiServiceClient<Channel>,
    faults: Faults,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Plane {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

impl Plane {
    fn as_principal(&self, principal: &str) -> Sekai {
        Sekai::new(self.client.clone(), principal)
    }

    /// Kinds with a published type are not written through `CreateObject`;
    /// the test writes them as committed, audited facts.
    async fn put(&self, mut object: Object) {
        object.created = now_ms();
        object.updated = object.created;
        self.db.create_object_with_audit(&object, ADMIN).unwrap();
    }

    async fn update(&self, id: &str, key: &str, value: &str) {
        let mut object = self.object(id);
        object.properties.insert(key.into(), value.into());
        object.updated = now_ms().max(object.updated + 1);
        self.db.update_object_with_audit(&object, ADMIN).unwrap();
    }

    async fn delete(&self, id: &str) {
        self.db
            .delete_object_with_audit(id, ADMIN)
            .unwrap()
            .unwrap();
    }

    fn object(&self, id: &str) -> Object {
        self.db.get_object(id).unwrap().unwrap()
    }

    async fn grant(&self, object_id: &str, principal: &str, role: &str) {
        self.svc
            .create_grant(admin(CreateGrantRequest {
                grant: Some(Grant {
                    id: format!("grant-{object_id}-{principal}"),
                    object_id: object_id.into(),
                    principal: principal.into(),
                    role: role.into(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap();
    }

    fn admitted(&self) -> Vec<String> {
        self.db
            .list_action_instances(NS, Some(ACTION), None, 100)
            .unwrap()
            .into_iter()
            .map(|instance| instance.idempotency_key)
            .collect()
    }
}

fn admin<T>(message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request
        .metadata_mut()
        .insert("x-principal", MetadataValue::from_static(ADMIN));
    request
}

async fn plane() -> Plane {
    let db = Arc::new(RuntimeDb::memory());
    for (principal, role) in [
        (ADMIN, Role::Admin),
        (ADAPTER, Role::Editor),
        ("alice", Role::Viewer),
        ("bob", Role::Viewer),
    ] {
        db.ensure_team_namespace(NS, principal, role, ADMIN)
            .unwrap();
    }
    db.upsert_action_policy(&ActionPolicy::allow_all(NS))
        .unwrap();
    let members = [
        (VEHICLE, r#"{"name":"vehicle","properties":{"location":{"type":"string"},"status":{"type":"string"}}}"#),
        (FENCE, r#"{"name":"geofence","properties":{"area":{"type":"string"},"rule":{"type":"string"},"action_type":{"type":"string"}}}"#),
    ]
    .map(|(id, json)| {
        DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare(NS)
        .unwrap()
    });
    let revision = prepare_revision(
        NS,
        "",
        members.iter().map(|member| DefinitionRevisionMember {
            member_kind: member.member_kind.clone(),
            member_id: member.member_id.clone(),
            member_digest: member.member_digest.clone(),
        }),
        true,
        ADMIN,
        1,
    )
    .unwrap();
    db.seed_published_definition_revision(&revision, &members)
        .unwrap();
    let svc = SekaiServiceImpl::new(SekaiStore::from_shared_runtime(db.clone()));
    svc.put_governed_action_type(admin(PutGovernedActionTypeRequest {
        r#type: Some(GovernedActionType {
            namespace: NS.into(),
            type_id: ACTION.into(),
            version: "1".into(),
            description: "A vehicle crossed a fence".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"fence_id":{"type":"string"},"vehicle_id":{"type":"string"},"event":{"type":"string"},"at_ms":{"type":"integer"}},"required":["fence_id","vehicle_id","event","at_ms"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec!["notify".into()],
            created_by: ADMIN.into(),
            enabled: true,
            ..Default::default()
        }),
        request_id: "put-type".into(),
    }))
    .await
    .unwrap();

    let faults = Faults::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let service = SekaiServiceServer::with_interceptor(svc.clone(), bearer_names_principal);
    let layer = faults.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .layer(tower::layer::layer_fn(move |inner| Faulty {
                inner,
                faults: layer.clone(),
            }))
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let client = SekaiServiceClient::connect(endpoint).await.unwrap();
    Plane {
        db,
        svc,
        client,
        faults,
        stop: Some(stop),
    }
}

/// The test's authentication layer: the bearer token is the principal name.
fn bearer_names_principal(
    mut request: tonic::Request<()>,
) -> Result<tonic::Request<()>, tonic::Status> {
    let principal = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| tonic::Status::unauthenticated("bearer required"))?
        .to_string();
    request
        .metadata_mut()
        .insert("x-principal", principal.parse().unwrap());
    Ok(request)
}

#[derive(Clone)]
struct Faulty<S> {
    inner: S,
    faults: Faults,
}

impl<S, B> tower::Service<http::Request<B>> for Faulty<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<tonic::body::Body>>
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let path = request.uri().path().to_string();
        let cursor_write = path.ends_with("/CreateObject") || path.ends_with("/UpdateObject");
        if cursor_write
            && self
                .faults
                .refuse_cursor_write
                .swap(false, Ordering::SeqCst)
        {
            return Box::pin(async { Ok(tonic::Status::unavailable("crashed").into_http()) });
        }
        let lose = path.ends_with("/ReadObjectChangeSubscription")
            && self.faults.lose_read.swap(false, Ordering::SeqCst);
        let response = self.inner.call(request);
        Box::pin(async move {
            let response = response.await?;
            if lose {
                return Ok(tonic::Status::unavailable("answer lost").into_http());
            }
            Ok(response)
        })
    }
}

/// Ezu in memory, with the ordering the adapter relies on: an upsert applies
/// only when newer, an expire unless something newer is held.
#[derive(Default)]
struct FakeEzu {
    inner: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    /// `(collection, id)` to `(ts_ms, geometry)`; `None` is a tombstone.
    entities: BTreeMap<(String, String), (i64, Option<String>)>,
    /// Fields of the last applied upsert per `(collection, id)`.
    fields: BTreeMap<(String, String), BTreeMap<String, String>>,
    tracks: Vec<(String, Position)>,
    events: Vec<FenceEvent>,
    /// Writes accepted before the next one fails.
    writes_left: Option<usize>,
}

impl FakeState {
    fn spend_write(&mut self) -> Result<(), String> {
        match &mut self.writes_left {
            Some(0) => {
                self.writes_left = None;
                Err("Ezu unavailable".into())
            }
            Some(left) => {
                *left -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl FakeEzu {
    fn live(&self, collection: &str) -> BTreeMap<String, String> {
        self.inner
            .lock()
            .unwrap()
            .entities
            .iter()
            .filter(|((c, _), _)| c == collection)
            .filter_map(|((_, id), (_, geometry))| Some((id.clone(), geometry.clone()?)))
            .collect()
    }

    fn fail_after(&self, writes: usize) {
        self.inner.lock().unwrap().writes_left = Some(writes);
    }

    /// A high-rate producer writing positions to Ezu directly.
    fn stream(&self, collection: &str, id: &str, geometry: &str, ts_ms: i64) {
        let mut state = self.inner.lock().unwrap();
        state.entities.insert(
            (collection.into(), id.into()),
            (ts_ms, Some(geometry.into())),
        );
        state.tracks.push((
            collection.into(),
            Position {
                id: id.into(),
                geometry: geometry.into(),
                ts_ms,
            },
        ));
    }

    fn emit(&self, fence: &str, entity: &str) {
        let mut state = self.inner.lock().unwrap();
        let lsn = state.events.len() as u64 + 1;
        state.events.push(FenceEvent {
            lsn,
            index: 0,
            fence: fence.into(),
            collection: "vehicles".into(),
            entity: entity.into(),
            kind: "enter".into(),
            ts_ms: 1_000 + lsn as i64,
        });
    }
}

impl Ezu for FakeEzu {
    async fn upsert(&self, entity: &Entity) -> Result<(), String> {
        let mut state = self.inner.lock().unwrap();
        state.spend_write()?;
        let key = (entity.collection.clone(), entity.id.clone());
        if state
            .entities
            .get(&key)
            .is_some_and(|(ts, _)| *ts > entity.ts_ms)
        {
            return Ok(());
        }
        state
            .entities
            .insert(key.clone(), (entity.ts_ms, Some(entity.geometry.clone())));
        state.fields.insert(key, entity.fields.clone());
        Ok(())
    }

    async fn expire(&self, collection: &str, id: &str, ts_ms: i64) -> Result<(), String> {
        let mut state = self.inner.lock().unwrap();
        state.spend_write()?;
        let key = (collection.to_string(), id.to_string());
        if state.entities.get(&key).is_none_or(|(ts, _)| *ts <= ts_ms) {
            state.entities.insert(key, (ts_ms, None));
        }
        Ok(())
    }

    async fn entity_ids(&self, collection: &str) -> Result<Vec<String>, String> {
        Ok(self.live(collection).into_keys().collect())
    }

    async fn events_after(&self, after: Option<EventId>, limit: u32) -> Result<EventPage, String> {
        let state = self.inner.lock().unwrap();
        let events = state
            .events
            .iter()
            .filter(|event| after.is_none_or(|after| (event.lsn, event.index) > after))
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(EventPage {
            events,
            through: None,
        })
    }

    async fn nearby(
        &self,
        collection: &str,
        _center: [f64; 2],
        _radius_m: f64,
        limit: usize,
    ) -> Result<Vec<Position>, String> {
        let state = self.inner.lock().unwrap();
        Ok(state
            .entities
            .iter()
            .filter(|((c, _), _)| c == collection)
            .filter_map(|((_, id), (ts_ms, geometry))| {
                Some(Position {
                    id: id.clone(),
                    geometry: geometry.clone()?,
                    ts_ms: *ts_ms,
                })
            })
            .take(limit)
            .collect())
    }

    async fn positions(&self, collection: &str, ids: &[String]) -> Result<Vec<Position>, String> {
        let mut found = self.nearby(collection, [0.0, 0.0], 0.0, usize::MAX).await?;
        found.retain(|position| ids.contains(&position.id));
        Ok(found)
    }

    async fn tracks(
        &self,
        collection: &str,
        ids: &[String],
        since_ms: i64,
    ) -> Result<Vec<Position>, String> {
        let state = self.inner.lock().unwrap();
        Ok(state
            .tracks
            .iter()
            .filter(|(c, point)| {
                c == collection && ids.contains(&point.id) && point.ts_ms >= since_ms
            })
            .map(|(_, point)| point.clone())
            .collect())
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn point(lon: f64, lat: f64) -> String {
    format!(
        r#"{{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[{lon},{lat}]}}"#
    )
}

fn vehicle(id: &str, location: &str) -> Object {
    Object {
        id: id.into(),
        kind: VEHICLE.into(),
        name: id.into(),
        namespace: NS.into(),
        external_id: format!("{NS}:{id}"),
        properties: [("location".to_string(), location.to_string())].into(),
        created: 0,
        updated: 0,
    }
}

fn fence(id: &str, action_type: &str) -> Object {
    Object {
        id: id.into(),
        kind: FENCE.into(),
        name: id.into(),
        namespace: NS.into(),
        properties: [
            ("area".to_string(), point(13.4, 52.5)),
            ("rule".to_string(), "enter".to_string()),
            ("action_type".to_string(), action_type.to_string()),
        ]
        .into(),
        external_id: format!("{NS}:{id}"),
        created: 0,
        updated: 0,
    }
}

fn vehicles() -> GeoFeed {
    GeoFeed {
        namespace: NS.into(),
        kind: VEHICLE.into(),
        geometry_property: "location".into(),
        collection: "vehicles".into(),
        filter_fields: vec!["status".into()],
    }
}

fn fences() -> GeoFeed {
    GeoFeed {
        namespace: NS.into(),
        kind: FENCE.into(),
        geometry_property: "area".into(),
        collection: "fences".into(),
        filter_fields: vec!["rule".into()],
    }
}

fn alerts() -> FenceBinding {
    FenceBinding {
        binding_id: "alerts".into(),
        namespace: NS.into(),
        fence_kind: FENCE.into(),
        type_id: ACTION.into(),
        version: "1".into(),
        parameters: BTreeMap::from([
            ("fence_id".into(), EventField::Fence),
            ("vehicle_id".into(), EventField::Entity),
            ("event".into(), EventField::Kind),
            ("at_ms".into(), EventField::TsMs),
        ]),
    }
}

async fn geo_runner(plane: &Plane, feed: GeoFeed, owner: &str) -> Option<GeoFeedRunner> {
    expiring_geo_runner(plane, feed, owner, HELD_TTL_MS).await
}

async fn expiring_geo_runner(
    plane: &Plane,
    feed: GeoFeed,
    owner: &str,
    ttl_ms: i64,
) -> Option<GeoFeedRunner> {
    GeoFeedRunner::start(plane.as_principal(ADAPTER), feed, owner, ttl_ms)
        .await
        .unwrap()
}

async fn drain_geo(runner: &mut GeoFeedRunner, ezu: &FakeEzu) {
    for _ in 0..16 {
        if runner.step(ezu).await.unwrap() == Step::Idle {
            return;
        }
    }
    panic!("the geo feed never went idle");
}

async fn drain_fences(runner: &mut FenceRunner, ezu: &FakeEzu) {
    for _ in 0..16 {
        if runner.step(ezu).await.unwrap() == Step::Idle {
            return;
        }
    }
    panic!("the fence runner never went idle");
}

async fn wait_for_lease_expiry() {
    tokio::time::sleep(Duration::from_millis(EXPIRING_TTL_MS as u64 + 100)).await;
}

/// What Ezu must hold for the feed: every live vehicle the adapter can see.
fn expected(plane: &Plane, ids: &[&str]) -> BTreeMap<String, String> {
    ids.iter()
        .map(|id| {
            (
                id.to_string(),
                plane.object(id).properties["location"].clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_crash_mid_page_and_a_takeover_converge_and_the_old_runner_writes_nothing() {
    let plane = plane().await;
    let ezu = FakeEzu::default();
    for id in ["v1", "v2", "v3"] {
        plane.put(vehicle(id, &point(13.0, 52.0))).await;
    }
    let mut first = expiring_geo_runner(&plane, vehicles(), "a", EXPIRING_TTL_MS)
        .await
        .unwrap();
    drain_geo(&mut first, &ezu).await;
    assert_eq!(ezu.live("vehicles"), expected(&plane, &["v1", "v2", "v3"]));

    plane.update("v1", "location", &point(13.1, 52.1)).await;
    plane.put(vehicle("v4", &point(13.4, 52.4))).await;
    plane.delete("v3").await;
    // The page becomes durable, then Ezu fails after one write: a crash.
    assert_eq!(first.step(&ezu).await.unwrap(), Step::Worked);
    ezu.fail_after(1);
    assert!(matches!(first.step(&ezu).await, Err(Error::Ezu(_))));

    assert!(
        geo_runner(&plane, vehicles(), "b").await.is_none(),
        "the lease is still held"
    );
    wait_for_lease_expiry().await;
    let mut second = geo_runner(&plane, vehicles(), "b").await.unwrap();
    drain_geo(&mut second, &ezu).await;
    assert_eq!(ezu.live("vehicles"), expected(&plane, &["v1", "v2", "v4"]));

    // The crashed runner wakes up fenced out and writes nothing.
    plane.update("v2", "location", &point(13.2, 52.2)).await;
    let before = ezu.live("vehicles");
    assert!(matches!(first.step(&ezu).await, Err(Error::LeaseLost)));
    assert_eq!(ezu.live("vehicles"), before);
    drain_geo(&mut second, &ezu).await;
    assert_eq!(ezu.live("vehicles"), expected(&plane, &["v1", "v2", "v4"]));
}

#[tokio::test]
async fn a_read_whose_answer_is_lost_takes_a_new_snapshot() {
    let plane = plane().await;
    let ezu = FakeEzu::default();
    plane.put(vehicle("v1", &point(13.0, 52.0))).await;
    let mut runner = geo_runner(&plane, vehicles(), "a").await.unwrap();
    drain_geo(&mut runner, &ezu).await;

    plane.update("v1", "location", &point(13.5, 52.5)).await;
    plane.put(vehicle("v2", &point(13.6, 52.6))).await;
    plane.faults.lose_read.store(true, Ordering::SeqCst);
    assert!(matches!(runner.step(&ezu).await, Err(Error::Plane(_))));

    drain_geo(&mut runner, &ezu).await;
    assert_eq!(ezu.live("vehicles"), expected(&plane, &["v1", "v2"]));
}

#[tokio::test]
async fn a_new_snapshot_restores_an_entity_behind_a_newer_tombstone() {
    let plane = plane().await;
    let ezu = FakeEzu::default();
    plane.put(vehicle("v1", &point(13.0, 52.0))).await;
    let mut runner = geo_runner(&plane, vehicles(), "a").await.unwrap();
    drain_geo(&mut runner, &ezu).await;

    // Visibility was lost after the last change and is back unchanged.
    ezu.expire("vehicles", "v1", now_ms()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    plane.faults.lose_read.store(true, Ordering::SeqCst);
    assert!(runner.step(&ezu).await.is_err());

    drain_geo(&mut runner, &ezu).await;
    assert_eq!(ezu.live("vehicles"), expected(&plane, &["v1"]));
}

#[tokio::test]
async fn changed_feed_settings_rewrite_unchanged_objects() {
    let plane = plane().await;
    let ezu = FakeEzu::default();
    let mut v1 = vehicle("v1", &point(13.0, 52.0));
    v1.properties.insert("status".into(), "moving".into());
    plane.put(v1).await;
    let mut runner = expiring_geo_runner(&plane, vehicles(), "a", EXPIRING_TTL_MS)
        .await
        .unwrap();
    drain_geo(&mut runner, &ezu).await;
    plane.update("v1", "location", &point(13.1, 52.1)).await;
    drain_geo(&mut runner, &ezu).await;
    drop(runner);
    wait_for_lease_expiry().await;

    let key = ("vehicles".to_string(), "v1".to_string());
    assert_eq!(ezu.inner.lock().unwrap().fields[&key]["status"], "moving");
    let without_status = GeoFeed {
        filter_fields: Vec::new(),
        ..vehicles()
    };
    let mut runner = geo_runner(&plane, without_status, "b").await.unwrap();
    drain_geo(&mut runner, &ezu).await;
    assert!(ezu.inner.lock().unwrap().fields[&key].is_empty());
}

#[tokio::test]
async fn fence_events_submit_once_and_only_for_bound_plane_fences() {
    let plane = plane().await;
    let ezu = FakeEzu::default();
    plane.put(fence("f-plane", ACTION)).await;
    plane.put(fence("f-other-type", "fleet.other")).await;
    plane.put(vehicle("v1", &point(13.0, 52.0))).await;
    let mut feed = geo_runner(&plane, fences(), "a").await.unwrap();
    drain_geo(&mut feed, &ezu).await;
    ezu.stream("fences", "f-ezu-only", &point(13.4, 52.5), 1);

    ezu.emit("f-plane", "v1");
    ezu.emit("f-ezu-only", "v1");
    ezu.emit("f-other-type", "v1");
    ezu.emit("f-plane", "v1");
    let mut first = FenceRunner::start(plane.as_principal(ADAPTER), alerts(), "a", EXPIRING_TTL_MS)
        .await
        .unwrap()
        .unwrap();
    // Every submit lands, then the cursor write is lost: a crash.
    plane
        .faults
        .refuse_cursor_write
        .store(true, Ordering::SeqCst);
    assert!(first.step(&ezu).await.is_err());
    assert_eq!(plane.admitted().len(), 2);

    wait_for_lease_expiry().await;
    let mut second = FenceRunner::start(plane.as_principal(ADAPTER), alerts(), "b", HELD_TTL_MS)
        .await
        .unwrap()
        .unwrap();
    drain_fences(&mut second, &ezu).await;
    let mut admitted = plane.admitted();
    admitted.sort();
    assert_eq!(admitted, ["ezu:1:0", "ezu:4:0"]);
}

#[tokio::test]
async fn deleting_a_fence_object_removes_the_fence_in_ezu() {
    let plane = plane().await;
    let ezu = FakeEzu::default();
    plane.put(fence("f-1", ACTION)).await;
    let mut feed = geo_runner(&plane, fences(), "a").await.unwrap();
    drain_geo(&mut feed, &ezu).await;
    assert!(ezu.live("fences").contains_key("f-1"));

    plane.delete("f-1").await;
    drain_geo(&mut feed, &ezu).await;
    assert!(ezu.live("fences").is_empty());
}

/// risk:security. The read filter is the boundary between Ezu, which holds
/// everything the adapter sees, and each reader's rights.
#[tokio::test]
async fn reads_return_only_objects_the_reader_may_read() {
    let plane = plane().await;
    let ezu = FakeEzu::default();
    plane.put(vehicle("open", &point(13.0, 52.0))).await;
    plane.put(vehicle("granted", &point(13.1, 52.1))).await;
    plane.grant("granted", ADAPTER, "editor").await;
    plane.grant("granted", "alice", "viewer").await;
    let mut marked = vehicle("marked", &point(13.2, 52.2));
    marked
        .properties
        .insert("access_marking".into(), "restricted".into());
    plane.put(marked).await;
    plane
        .put(Object {
            id: "profile-alice".into(),
            kind: "principal_profile".into(),
            name: "alice".into(),
            namespace: String::new(),
            external_id: sekai_chisei::sekai::markings::principal_profile_external_id("alice"),
            properties: [
                ("classification_ceiling".to_string(), "internal".to_string()),
                ("sealed_by_credential_admin".to_string(), "true".to_string()),
            ]
            .into(),
            created: 0,
            updated: 0,
        })
        .await;
    let mut feed = geo_runner(&plane, vehicles(), "a").await.unwrap();
    drain_geo(&mut feed, &ezu).await;
    for id in ["open", "granted", "marked"] {
        ezu.stream("vehicles", id, &point(14.0, 53.0), i64::MAX - 1);
    }
    assert_eq!(
        ezu.live("vehicles").len(),
        3,
        "Ezu holds every object, so only the plane can filter"
    );

    let all = ["open", "granted", "marked"].map(String::from);
    for (reader, visible) in [("alice", vec!["granted", "open"]), ("bob", vec!["open"])] {
        let reader = plane.as_principal(reader);
        let mut near = ezu::nearby(&reader, &ezu, &vehicles(), [13.0, 52.0], 1_000.0)
            .await
            .unwrap()
            .into_iter()
            .map(|position| position.id)
            .collect::<Vec<_>>();
        near.sort();
        assert_eq!(near, visible);
        let mut live = ezu::positions(&reader, &ezu, &vehicles(), &all)
            .await
            .unwrap()
            .into_iter()
            .map(|position| position.id)
            .collect::<Vec<_>>();
        live.sort();
        assert_eq!(live, visible);
        let mut track = ezu::tracks(&reader, &ezu, &vehicles(), &all, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|point| point.id)
            .collect::<Vec<_>>();
        track.sort();
        assert_eq!(track, visible);
    }
    let outsider = plane.as_principal("mallory");
    let refused = ezu::tracks(&outsider, &ezu, &vehicles(), &all, 0).await;
    assert!(refused.is_err() || refused.unwrap().is_empty());
}

#[tokio::test]
async fn a_direct_position_stream_writes_nothing_to_the_plane() {
    let plane = plane().await;
    let ezu = FakeEzu::default();
    plane.put(vehicle("v1", &point(13.0, 52.0))).await;
    let mut feed = geo_runner(&plane, vehicles(), "a").await.unwrap();
    drain_geo(&mut feed, &ezu).await;

    let watermark = plane.db.object_change_watermark(NS).unwrap();
    let fresh = point(13.9, 52.9);
    for step in 0..100 {
        ezu.stream("vehicles", "v1", &fresh, now_ms() + 1 + step);
    }
    drain_geo(&mut feed, &ezu).await;
    assert_eq!(plane.db.object_change_watermark(NS).unwrap(), watermark);
    assert_eq!(
        ezu.live("vehicles")["v1"],
        fresh,
        "an older plane position never wins"
    );
}
