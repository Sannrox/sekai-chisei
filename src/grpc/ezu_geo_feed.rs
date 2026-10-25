//! Install and run a fenced incremental Ezu geo feed (#1797).

use super::action_binding::load_bound_objects;
use super::fence_binding::EZU_URL_ENV;
use super::*;
use crate::sekai::ezu_geo_feed::{
    EzuEntity, EzuField, EzuGeoFeed, EzuGeometry, FEED_RUN_LEASE_MS, FeedSkip, entity_for,
    expire_entity, feed_lag_ms, keep_whole_mutations, mutation_kind_for_feed, valid_ezu_name,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;

const FEED_UNAVAILABLE: &str = "ezu geo feed unavailable";
const EZU_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Where a run writes entities: the Ezu namespace `token` maps to.
pub(crate) trait EzuEntitySink {
    fn upsert(
        &self,
        token: &str,
        entity: EzuEntity,
    ) -> impl Future<Output = Result<EzuWriteOutcome, Status>> + Send;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EzuWriteOutcome {
    Inserted,
    Updated,
    Stale,
    Refused,
}

/// Ezu's `POST /v1/entities`.
pub(crate) struct EzuHttp {
    base_url: String,
    client: reqwest::Client,
}

impl EzuHttp {
    pub(crate) fn from_env() -> Result<Self, Status> {
        let base_url = std::env::var(EZU_URL_ENV)
            .ok()
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| Status::failed_precondition("Ezu is not configured"))?;
        let client = reqwest::Client::builder()
            .timeout(EZU_WRITE_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| Status::internal("Ezu client unavailable"))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }
}

impl EzuEntitySink for EzuHttp {
    fn upsert(
        &self,
        token: &str,
        entity: EzuEntity,
    ) -> impl Future<Output = Result<EzuWriteOutcome, Status>> + Send {
        let request = self
            .client
            .post(format!("{}/v1/entities", self.base_url))
            .bearer_auth(token)
            .json(&upsert_body(&entity));
        async move {
            let response = request
                .send()
                .await
                .map_err(|_| Status::unavailable("Ezu unavailable"))?;
            let status = response.status();
            if status.is_server_error() {
                return Err(Status::unavailable("Ezu unavailable"));
            }
            if !status.is_success() {
                return Err(Status::failed_precondition(format!(
                    "Ezu refused the entity write ({})",
                    status.as_u16()
                )));
            }
            let body: serde_json::Value = response
                .json()
                .await
                .map_err(|_| Status::unavailable("Ezu answered an unreadable upsert"))?;
            outcome_from_json(&body)
        }
    }
}

#[cfg(test)]
fn entity_url(base_url: &str, collection: &str, id: &str) -> Result<reqwest::Url, Status> {
    let mut url = reqwest::Url::parse(&format!("{base_url}/v1/entities"))
        .map_err(|_| Status::internal("Ezu client unavailable"))?;
    url.path_segments_mut()
        .map_err(|_| Status::internal("Ezu client unavailable"))?
        .push(collection)
        .push(id);
    Ok(url)
}

fn upsert_body(entity: &EzuEntity) -> serde_json::Value {
    let geometry = match &entity.geometry {
        EzuGeometry::Point { lon, lat } => {
            serde_json::json!({"shape": {"point": {"lon": lon, "lat": lat}}})
        }
        EzuGeometry::Polygon { ring } => {
            let positions: Vec<_> = ring
                .iter()
                .map(|(lon, lat)| serde_json::json!({"lon": lon, "lat": lat}))
                .collect();
            serde_json::json!({"shape": {"polygon": {"rings": [{"positions": positions}]}}})
        }
    };
    let fields: serde_json::Map<String, serde_json::Value> = entity
        .fields
        .iter()
        .map(|(name, value)| {
            let encoded = match value {
                EzuField::Bool(v) => serde_json::json!({"value": {"bool_value": v}}),
                EzuField::Int(v) => serde_json::json!({"value": {"int_value": v}}),
                EzuField::Float(v) => serde_json::json!({"value": {"float_value": v}}),
                EzuField::Text(v) => serde_json::json!({"value": {"text_value": v}}),
            };
            (name.clone(), encoded)
        })
        .collect();
    let mut body = serde_json::json!({
        "entities": [{
            "collection": entity.collection,
            "id": entity.id,
            "geometry": geometry,
            "ts_ms": entity.ts_ms,
            "fields": fields,
        }]
    });
    if let Some(ttl_ms) = entity.ttl_ms {
        body["entities"][0]["ttl_ms"] = serde_json::json!(ttl_ms);
    }
    body
}

fn outcome_from_json(body: &serde_json::Value) -> Result<EzuWriteOutcome, Status> {
    let outcome = body
        .get("results")
        .and_then(serde_json::Value::as_array)
        .and_then(|results| results.first())
        .and_then(|result| result.get("outcome"));
    let parsed = match outcome {
        Some(serde_json::Value::String(name)) => match name.to_ascii_lowercase().as_str() {
            "outcome_inserted" | "inserted" => Some(EzuWriteOutcome::Inserted),
            "outcome_updated" | "updated" => Some(EzuWriteOutcome::Updated),
            "outcome_stale" | "stale" => Some(EzuWriteOutcome::Stale),
            "outcome_refused" | "refused" => Some(EzuWriteOutcome::Refused),
            _ => None,
        },
        Some(serde_json::Value::Number(n)) => match n.as_i64() {
            Some(1) => Some(EzuWriteOutcome::Inserted),
            Some(2) => Some(EzuWriteOutcome::Updated),
            Some(3) => Some(EzuWriteOutcome::Stale),
            Some(4) => Some(EzuWriteOutcome::Refused),
            _ => None,
        },
        _ => None,
    };
    parsed.ok_or_else(|| Status::unavailable("Ezu answered an unreadable upsert"))
}

impl SekaiServiceImpl {
    pub(super) async fn put_ezu_geo_feed_definition(
        &self,
        req: Request<PutEzuGeoFeedRequest>,
    ) -> Result<Response<PutEzuGeoFeedResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let feed: EzuGeoFeed = serde_json::from_str(&req.into_inner().feed_json)
            .map_err(|error| Status::invalid_argument(format!("feed_json: {error}")))?;
        feed.validate().map_err(Status::invalid_argument)?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &feed.namespace,
            true,
        )?;
        let actor = authorize_source_type_namespace_admin(self, &principals, &feed.namespace)?;
        check_team_namespace(
            self.db.runtime(),
            std::slice::from_ref(&feed.run_as),
            &feed.namespace,
            true,
        )
        .map_err(|_| Status::failed_precondition("run_as lacks namespace write"))?;
        let stored = self
            .db
            .runtime()
            .put_ezu_geo_feed(&feed, &actor, now_millis())
            .map_err(map_feed_store_error)?;
        Ok(Response::new(PutEzuGeoFeedResponse {
            feed_json: serde_json::to_string(&stored)
                .map_err(|error| Status::internal(error.to_string()))?,
            revision: stored.revision,
        }))
    }

    pub(super) async fn run_ezu_geo_feed_once(
        &self,
        req: Request<RunEzuGeoFeedRequest>,
    ) -> Result<Response<RunEzuGeoFeedResponse>, Status> {
        self.run_ezu_geo_feed_with(req, &EzuHttp::from_env()?).await
    }

    /// Reads one bounded page of committed object changes after the feed's
    /// cursor and upserts or expires the matching Ezu entities. The cursor
    /// moves only after the writes, and only while this run holds the lease.
    pub(super) async fn run_ezu_geo_feed_with(
        &self,
        req: Request<RunEzuGeoFeedRequest>,
        sink: &impl EzuEntitySink,
    ) -> Result<Response<RunEzuGeoFeedResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let input = req.into_inner();
        let (feed, _) = self
            .db
            .runtime()
            .get_ezu_geo_feed(input.namespace.trim(), input.feed_id.trim())
            .map_err(map_feed_store_error)?
            .ok_or_else(|| Status::not_found(FEED_UNAVAILABLE))?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &feed.namespace,
            true,
        )?;
        let caller_runs_feed = principals.iter().any(|principal| principal == &feed.run_as);
        if !caller_runs_feed
            && authorize_source_type_namespace_admin(self, &principals, &feed.namespace).is_err()
        {
            return Err(Status::permission_denied(FEED_UNAVAILABLE));
        }
        if !feed.enabled {
            return Err(Status::failed_precondition("ezu geo feed is disabled"));
        }
        let tenant = crate::sekai::write_freeze::acting_or_registered_tenant(
            self.db.runtime(),
            "",
            &feed.run_as,
        )
        .map_err(Status::internal)?
        .into_owned();
        recheck_feed_run_as(self, &feed, &tenant)?;
        let run_id = uuid::Uuid::new_v4().to_string();
        let now = now_millis();
        if !self
            .db
            .runtime()
            .lease_ezu_geo_feed_run(&feed, &run_id, false, now, now + FEED_RUN_LEASE_MS)
            .map_err(map_feed_store_error)?
        {
            return Err(Status::aborted(
                "another run of this ezu geo feed is in progress",
            ));
        }
        // Reload so a lapsed-lease takeover writes with the raised write_fence.
        let (feed, cursor) = match self
            .db
            .runtime()
            .get_ezu_geo_feed(&feed.namespace, &feed.feed_id)
            .map_err(map_feed_store_error)?
        {
            Some((current, cursor)) if current.revision == feed.revision => (current, cursor),
            _ => {
                let _ = self.db.runtime().release_ezu_geo_feed_run(&feed, &run_id);
                return Err(Status::aborted(
                    "ezu geo feed changed during the run; run again",
                ));
            }
        };
        let result: Result<Response<RunEzuGeoFeedResponse>, Status> = async {
            let token = self.ezu_token(&tenant, &feed.run_as)?;
            let limit = feed.changes_per_run();
            let mut pending = self
                .db
                .runtime()
                .list_committed_object_mutations_after(&feed.namespace, cursor, limit as i32)
                .map_err(map_feed_store_error)?;
            let more = pending.len() as u32 >= limit;
            keep_whole_mutations(&mut pending, more);
            let lag_ms = feed_lag_ms(&pending, now_millis());
            metrics::gauge!(
                "sekai_ezu_geo_feed_lag_ms",
                "namespace" => feed.namespace.clone(),
                "feed" => feed.feed_id.clone()
            )
            .set(lag_ms as f64);

            let mut writes = 0u32;
            let mut deletes = 0u32;
            let mut rejected_geometries = 0u32;
            let mut errors = 0u32;
            let mut seen = BTreeSet::new();
            let mut through = cursor;
            let schema = self
                .db
                .runtime()
                .get_object_type(&feed.object_kind)
                .map_err(map_feed_store_error)?;
            let mut object_ids = Vec::new();
            let mut revisions = HashMap::new();
            for mutation in &pending {
                through = through.max(mutation.seq);
                // Current kind is joined from the live row. Deleted objects
                // have none; `_deleted` carries `kind/name`. A `kind` change
                // that left this feed still has to reach expire, or the old
                // entity stays in Ezu.
                let kind = mutation_kind_for_feed(mutation);
                if kind != feed.object_kind
                    && (mutation.change.field != "kind"
                        || mutation.change.old_value != feed.object_kind)
                {
                    continue;
                }
                if seen.insert(mutation.change.object_id.clone()) {
                    object_ids.push(mutation.change.object_id.clone());
                }
            }
            for mutation in &pending {
                if seen.contains(&mutation.change.object_id) {
                    let seq = revisions
                        .entry(mutation.change.object_id.clone())
                        .or_insert(0);
                    *seq = (*seq).max(mutation.seq);
                }
            }
            let mut property_keys: HashSet<String> = feed.filter_fields.iter().cloned().collect();
            property_keys.insert(feed.geo_property.clone());
            for object_id in &object_ids {
                let now = now_millis();
                if !self
                    .db
                    .runtime()
                    .lease_ezu_geo_feed_run(&feed, &run_id, true, now, now + FEED_RUN_LEASE_MS)
                    .map_err(map_feed_store_error)?
                {
                    return Err(Status::aborted(
                        "ezu geo feed changed during the run; run again",
                    ));
                }
                recheck_feed_run_as(self, &feed, &tenant)?;
                let visible = load_bound_objects(
                    self,
                    &feed.namespace,
                    &feed.object_kind,
                    std::slice::from_ref(object_id),
                    std::slice::from_ref(&feed.run_as),
                    &property_keys,
                )?;
                match apply_object(
                    self,
                    sink,
                    &feed,
                    &token,
                    &schema,
                    ApplyTarget {
                        object_id,
                        visible: visible.first(),
                        revision: revisions.get(object_id).copied().unwrap_or(through).max(1)
                            as i64,
                    },
                )
                .await
                {
                    Ok(Apply::Upserted) => writes += 1,
                    Ok(Apply::Deleted) => deletes += 1,
                    Ok(Apply::RejectedGeometry) => {
                        rejected_geometries += 1;
                        metrics::counter!(
                            "sekai_ezu_geo_feed_rejected_geometries",
                            "namespace" => feed.namespace.clone(),
                            "feed" => feed.feed_id.clone()
                        )
                        .increment(1);
                    }
                    Ok(Apply::InvalidName) => {
                        errors += 1;
                        metrics::counter!(
                            "sekai_ezu_geo_feed_errors",
                            "namespace" => feed.namespace.clone(),
                            "feed" => feed.feed_id.clone()
                        )
                        .increment(1);
                    }
                    Err(status) => {
                        metrics::counter!(
                            "sekai_ezu_geo_feed_errors",
                            "namespace" => feed.namespace.clone(),
                            "feed" => feed.feed_id.clone()
                        )
                        .increment(1);
                        return Err(status);
                    }
                }
            }
            if through > cursor
                && !self
                    .db
                    .runtime()
                    .advance_ezu_geo_feed(&feed, &run_id, through, now_millis())
                    .map_err(map_feed_store_error)?
            {
                return Err(Status::aborted(
                    "ezu geo feed changed during the run; run again",
                ));
            }
            Ok(Response::new(RunEzuGeoFeedResponse {
                feed_revision: feed.revision,
                through_seq: through,
                writes,
                deletes,
                rejected_geometries,
                errors,
                lag_ms,
                more,
            }))
        }
        .await;
        // A timed-out HTTP write may still land. Raise the fence before
        // release so the retry's ts_ms beats that delayed apply. If the
        // fence cannot be stored, keep the lease so a later takeover raises
        // it instead of retrying at the same ts_ms.
        let mut release = true;
        if result.is_err() {
            match self
                .db
                .runtime()
                .raise_ezu_geo_feed_write_fence(&feed, &run_id)
            {
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "ezu geo feed write fence not raised after a failed run"
                    );
                    release = false;
                }
            }
        }
        if release {
            if let Err(error) = self.db.runtime().release_ezu_geo_feed_run(&feed, &run_id) {
                tracing::warn!(error = %error, "ezu geo feed run lease not released");
            }
        }
        result
    }
}

enum Apply {
    Upserted,
    Deleted,
    RejectedGeometry,
    InvalidName,
}

struct ApplyTarget<'a> {
    object_id: &'a str,
    visible: Option<&'a domain::Object>,
    revision: i64,
}

async fn apply_object(
    service: &SekaiServiceImpl,
    sink: &impl EzuEntitySink,
    feed: &EzuGeoFeed,
    token: &str,
    schema: &Option<crate::sekai::object_schema::ObjectType>,
    target: ApplyTarget<'_>,
) -> Result<Apply, Status> {
    if !valid_ezu_name(&feed.collection) || !valid_ezu_name(target.object_id) {
        return Ok(Apply::InvalidName);
    }
    let live = match service.db.runtime().get_object(target.object_id) {
        Ok(object) => object,
        Err(error) => return Err(map_feed_store_error(error)),
    };
    let in_scope = live.as_ref().is_some_and(|object| {
        object.namespace == feed.namespace && object.kind == feed.object_kind
    });
    if in_scope {
        let Some(visible) = target.visible else {
            return expire(sink, feed, token, target.object_id, target.revision).await;
        };
        match entity_for(feed, visible, schema.as_ref(), target.revision) {
            Ok(entity) => match sink.upsert(token, entity).await? {
                EzuWriteOutcome::Refused => {
                    Err(Status::unavailable("Ezu refused the entity write"))
                }
                EzuWriteOutcome::Inserted | EzuWriteOutcome::Updated | EzuWriteOutcome::Stale => {
                    Ok(Apply::Upserted)
                }
            },
            Err(FeedSkip::MissingGeo) => {
                expire(sink, feed, token, target.object_id, target.revision).await
            }
            Err(FeedSkip::InvalidName) => Ok(Apply::InvalidName),
            Err(FeedSkip::RejectedGeometry) => Ok(Apply::RejectedGeometry),
        }
    } else {
        expire(sink, feed, token, target.object_id, target.revision).await
    }
}

async fn expire(
    sink: &impl EzuEntitySink,
    feed: &EzuGeoFeed,
    token: &str,
    object_id: &str,
    revision: i64,
) -> Result<Apply, Status> {
    match expire_entity(feed, object_id, revision) {
        Ok(entity) => match sink.upsert(token, entity).await? {
            EzuWriteOutcome::Refused => Err(Status::unavailable("Ezu refused the entity write")),
            EzuWriteOutcome::Inserted | EzuWriteOutcome::Updated | EzuWriteOutcome::Stale => {
                Ok(Apply::Deleted)
            }
        },
        Err(FeedSkip::InvalidName) => Ok(Apply::InvalidName),
        Err(_) => Ok(Apply::RejectedGeometry),
    }
}

fn map_feed_store_error(error: String) -> Status {
    if error.contains("must") || error.contains("unsupported") || error.contains("invalid") {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}

/// Recheck `run_as` namespace write and write freeze. A page of HTTP writes
/// can outlive the snapshot taken at run start; a revoked principal must
/// not keep writing to Ezu. This is a namespace-write projection, not a
/// governed export.
fn recheck_feed_run_as(
    service: &SekaiServiceImpl,
    feed: &EzuGeoFeed,
    tenant: &str,
) -> Result<(), Status> {
    check_team_namespace(
        service.db.runtime(),
        std::slice::from_ref(&feed.run_as),
        &feed.namespace,
        true,
    )
    .map_err(|_| Status::failed_precondition("run_as lacks namespace write"))?;
    crate::sekai::write_freeze::refuse_if_frozen_any(
        service.db.runtime(),
        &crate::sekai::write_freeze::write_checks_for_actors(
            &feed.namespace,
            tenant,
            &feed.run_as,
            None,
            "",
            true,
        ),
    )
    .map_err(crate::grpc::write_freeze_status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::ezu_geo_feed::EZU_GEO_FEED_CONTRACT;
    use crate::sekai::object_schema::{ObjectType, PropertyDef, PropertyType};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tonic::metadata::MetadataValue;

    const BERLIN: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[13.405,52.52]}"#;
    const PARIS: &str = r#"{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[2.3522,48.8566]}"#;

    #[derive(Clone, Debug)]
    struct Stored {
        token: String,
        entity: EzuEntity,
    }

    struct FakeEzu {
        token: String,
        writes: Mutex<Vec<Stored>>,
    }

    impl EzuEntitySink for FakeEzu {
        fn upsert(
            &self,
            token: &str,
            entity: EzuEntity,
        ) -> impl Future<Output = Result<EzuWriteOutcome, Status>> + Send {
            assert_eq!(
                token, self.token,
                "feed must not write with another tenant token"
            );
            let mut writes = self.writes.lock().unwrap();
            let outcome = writes
                .iter()
                .rev()
                .find(|stored| {
                    stored.token == token
                        && stored.entity.collection == entity.collection
                        && stored.entity.id == entity.id
                })
                .map(|stored| {
                    if stored.entity.ts_ms > entity.ts_ms {
                        EzuWriteOutcome::Stale
                    } else {
                        EzuWriteOutcome::Updated
                    }
                })
                .unwrap_or(EzuWriteOutcome::Inserted);
            if outcome != EzuWriteOutcome::Stale {
                writes.push(Stored {
                    token: token.into(),
                    entity,
                });
            }
            std::future::ready(Ok(outcome))
        }
    }

    fn run_request() -> Request<RunEzuGeoFeedRequest> {
        let mut request = Request::new(RunEzuGeoFeedRequest {
            namespace: "fleet".into(),
            feed_id: "trucks".into(),
        });
        request
            .metadata_mut()
            .insert("x-principal", MetadataValue::from_static("local"));
        request
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

    fn setup() -> (Arc<RuntimeDb>, SekaiServiceImpl) {
        let db = Arc::new(RuntimeDb::memory());
        let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
            db.clone(),
        ));
        let (_, grants) = db
            .ensure_team_namespace("fleet", "svc-geo", security::Role::Editor, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
        db.upsert_object_type(&ObjectType {
            kind: "truck".into(),
            description: String::new(),
            properties: vec![
                property("location", "public"),
                property("status", "public"),
                property("badge", "sensitive"),
            ],
            is_builtin: false,
            implements: Vec::new(),
        })
        .unwrap();
        db.put_ezu_geo_feed(
            &EzuGeoFeed {
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
            },
            "local",
            2,
        )
        .unwrap();
        (db, svc)
    }

    fn truck(id: &str, geo: &str, status: &str, marking: &str, updated: i64) -> domain::Object {
        let mut properties = std::collections::HashMap::from([
            ("location".into(), geo.into()),
            ("status".into(), status.into()),
            ("badge".into(), "restricted".into()),
        ]);
        if !marking.is_empty() {
            properties.insert(
                crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                marking.into(),
            );
        }
        domain::Object {
            id: id.into(),
            kind: "truck".into(),
            name: id.into(),
            namespace: "fleet".into(),
            external_id: String::new(),
            properties,
            created: 1,
            updated,
        }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn last_entity(ezu: &FakeEzu, id: &str) -> EzuEntity {
        ezu.writes
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|stored| stored.entity.id == id)
            .map(|stored| stored.entity.clone())
            .expect("entity written")
    }

    #[test]
    fn create_move_and_delete_show_up_and_marked_fields_stay_out() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "", 10), "local")
                .unwrap();
            let ezu = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::default(),
            };
            let created = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(created.writes, 1);
            assert_eq!(created.deletes, 0);
            let created_obj = db.get_object("t1").unwrap().unwrap();
            let entity = last_entity(&ezu, "t1");
            assert_eq!(
                entity.geometry,
                EzuGeometry::Point {
                    lon: 13.405,
                    lat: 52.52
                }
            );
            assert_eq!(entity.ts_ms, created.through_seq as i64);
            assert_eq!(
                entity.fields,
                BTreeMap::from([("status".into(), EzuField::Text("idle".into()))])
            );

            let mut moved = created_obj;
            moved.properties.insert("location".into(), PARIS.into());
            moved.properties.insert("status".into(), "moving".into());
            moved.updated += 10;
            db.update_object_with_audit(&moved, "local").unwrap();
            let moved_run = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(moved_run.writes, 1);
            let moved_obj = db.get_object("t1").unwrap().unwrap();
            let entity = last_entity(&ezu, "t1");
            assert_eq!(
                entity.geometry,
                EzuGeometry::Point {
                    lon: 2.3522,
                    lat: 48.8566
                }
            );
            assert_eq!(entity.ts_ms, moved_run.through_seq as i64);

            let mut cleared = moved_obj;
            cleared.properties.insert("location".into(), String::new());
            cleared.updated += 10;
            db.update_object_with_audit(&cleared, "local").unwrap();
            let cleared_run = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(cleared_run.deletes, 1);
            assert_eq!(cleared_run.writes, 0);
            let expired = last_entity(&ezu, "t1");
            assert_eq!(expired.ttl_ms, Some(1));
            assert_eq!(expired.ts_ms, cleared_run.through_seq as i64);

            db.delete_object_with_audit("t1", "local").unwrap();
            let deleted = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(deleted.deletes, 1);
            let gone = last_entity(&ezu, "t1");
            assert_eq!(gone.ttl_ms, Some(1));
            assert_eq!(gone.ts_ms, deleted.through_seq as i64);
        });
    }

    #[test]
    fn a_deleted_object_of_another_kind_is_not_expired() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            let mut van = truck("v1", BERLIN, "idle", "", 10);
            van.kind = "van".into();
            db.create_object_with_audit(&van, "local").unwrap();
            db.delete_object_with_audit("v1", "local").unwrap();
            let ezu = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::default(),
            };
            let run = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(run.writes, 0);
            assert_eq!(run.deletes, 0);
            assert!(run.through_seq > 0);
            assert!(ezu.writes.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn a_stale_revision_is_ignored_and_a_second_run_cannot_take_the_lease() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "", 10), "local")
                .unwrap();
            let ezu = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::default(),
            };
            let first = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            let through = first.through_seq;
            let mut moved = db.get_object("t1").unwrap().unwrap();
            moved.properties.insert("location".into(), PARIS.into());
            moved.updated = 20;
            db.update_object_with_audit(&moved, "local").unwrap();
            let ezu = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::new(vec![Stored {
                    token: "ezu-fleet-token".into(),
                    entity: EzuEntity {
                        collection: "trucks".into(),
                        id: "t1".into(),
                        geometry: EzuGeometry::Point {
                            lon: 2.3522,
                            lat: 48.8566,
                        },
                        ts_ms: 20,
                        ttl_ms: None,
                        fields: BTreeMap::new(),
                    },
                }]),
            };
            let (feed, _) = db.get_ezu_geo_feed("fleet", "trucks").unwrap().unwrap();
            assert!(
                db.lease_ezu_geo_feed_run(&feed, "held", false, 1, i64::MAX)
                    .unwrap()
            );
            let refused = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu)).unwrap_err();
            assert_eq!(refused.code(), tonic::Code::Aborted);
            assert_eq!(
                db.get_ezu_geo_feed("fleet", "trucks").unwrap().unwrap().1,
                through
            );
            db.release_ezu_geo_feed_run(&feed, "held").unwrap();

            let replay = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::new(vec![Stored {
                    token: "ezu-fleet-token".into(),
                    entity: EzuEntity {
                        collection: "trucks".into(),
                        id: "t1".into(),
                        geometry: EzuGeometry::Point {
                            lon: 2.3522,
                            lat: 48.8566,
                        },
                        ts_ms: 20,
                        ttl_ms: None,
                        fields: BTreeMap::new(),
                    },
                }]),
            };
            let berlin = EzuEntity {
                collection: "trucks".into(),
                id: "t1".into(),
                geometry: EzuGeometry::Point {
                    lon: 13.405,
                    lat: 52.52,
                },
                ts_ms: 10,
                ttl_ms: None,
                fields: BTreeMap::new(),
            };
            let outcome = block_on(replay.upsert("ezu-fleet-token", berlin)).unwrap();
            assert_eq!(outcome, EzuWriteOutcome::Stale);
            assert_eq!(last_entity(&replay, "t1").ts_ms, 20);
        });
    }

    #[test]
    fn tenant_tokens_never_write_each_others_objects() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "", 10), "local")
                .unwrap();
            let fleet = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::default(),
            };
            block_on(svc.run_ezu_geo_feed_with(run_request(), &fleet)).unwrap();
            assert!(
                fleet
                    .writes
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|stored| stored.token == "ezu-fleet-token")
            );
            let other = FakeEzu {
                token: "ezu-other-token".into(),
                writes: Mutex::default(),
            };
            assert!(other.writes.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn rejected_geometry_advances_the_cursor() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", "not-geo", "idle", "", 10), "local")
                .unwrap();
            let ezu = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::default(),
            };
            let run = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(run.rejected_geometries, 1);
            assert_eq!(run.writes, 0);
            assert_eq!(run.deletes, 0);
            assert!(run.through_seq > 0);
            assert!(ezu.writes.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn a_timed_out_write_is_stale_on_retry() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "", 10), "local")
                .unwrap();
            struct TimeoutAfterRecord {
                inner: FakeEzu,
            }
            impl EzuEntitySink for TimeoutAfterRecord {
                fn upsert(
                    &self,
                    token: &str,
                    entity: EzuEntity,
                ) -> impl Future<Output = Result<EzuWriteOutcome, Status>> + Send {
                    let outcome = self.inner.upsert(token, entity);
                    async move {
                        let _ = outcome.await;
                        Err(Status::unavailable("ezu timed out"))
                    }
                }
            }
            let ezu = TimeoutAfterRecord {
                inner: FakeEzu {
                    token: "ezu-fleet-token".into(),
                    writes: Mutex::default(),
                },
            };
            let err = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu)).unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unavailable);
            let delayed = last_entity(&ezu.inner, "t1");
            let retried = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu.inner))
                .unwrap()
                .into_inner();
            assert_eq!(retried.writes, 1);
            let replacement = last_entity(&ezu.inner, "t1");
            assert!(replacement.ts_ms > delayed.ts_ms);
            assert_eq!(
                block_on(ezu.inner.upsert("ezu-fleet-token", delayed)).unwrap(),
                EzuWriteOutcome::Stale
            );
            assert_eq!(last_entity(&ezu.inner, "t1").ts_ms, replacement.ts_ms);
        });
    }

    #[test]
    fn an_ezu_refusal_does_not_advance_the_cursor() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "", 10), "local")
                .unwrap();
            struct Refuse;
            impl EzuEntitySink for Refuse {
                fn upsert(
                    &self,
                    _token: &str,
                    _entity: EzuEntity,
                ) -> impl Future<Output = Result<EzuWriteOutcome, Status>> + Send {
                    std::future::ready(Ok(EzuWriteOutcome::Refused))
                }
            }
            let err = block_on(svc.run_ezu_geo_feed_with(run_request(), &Refuse)).unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unavailable);
            assert_eq!(
                db.get_ezu_geo_feed("fleet", "trucks").unwrap().unwrap().1,
                0
            );
        });
    }

    #[test]
    fn a_marked_object_run_as_cannot_read_is_not_exported() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "public", 10), "local")
                .unwrap();
            let ezu = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::default(),
            };
            let run = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(run.writes, 0);
            assert_eq!(run.deletes, 1);
            assert!(run.through_seq > 0);
            assert_eq!(last_entity(&ezu, "t1").ttl_ms, Some(1));
        });
    }

    #[test]
    fn a_revoked_run_as_cannot_run_the_feed() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            let boundary = db.find_namespace_boundary("fleet").unwrap().unwrap();
            for grant in db.list_grants(&boundary.id).unwrap() {
                if grant.principal == "svc-geo" {
                    db.delete_grant(&grant.id).unwrap();
                }
            }
            let ezu = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::default(),
            };
            let err = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu)).unwrap_err();
            assert_eq!(err.code(), tonic::Code::FailedPrecondition);
            assert!(ezu.writes.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn an_unreadable_upsert_outcome_does_not_count_as_success() {
        assert!(outcome_from_json(&serde_json::json!({})).is_err());
        assert!(outcome_from_json(&serde_json::json!({"results": []})).is_err());
        assert!(outcome_from_json(&serde_json::json!({"results": [{"outcome": 0}]})).is_err());
        assert!(outcome_from_json(&serde_json::json!({"results": [{"outcome": "nope"}]})).is_err());
        assert_eq!(
            outcome_from_json(&serde_json::json!({"results": [{"outcome": 1}]})).unwrap(),
            EzuWriteOutcome::Inserted
        );
        assert_eq!(
            outcome_from_json(&serde_json::json!({"results": [{"outcome": "outcome_updated"}]}))
                .unwrap(),
            EzuWriteOutcome::Updated
        );
        assert_eq!(
            outcome_from_json(&serde_json::json!({"results": [{"outcome": "stale"}]})).unwrap(),
            EzuWriteOutcome::Stale
        );
    }

    #[test]
    fn upsert_body_never_names_a_namespace() {
        let body = upsert_body(&EzuEntity {
            collection: "trucks".into(),
            id: "t1".into(),
            geometry: EzuGeometry::Point {
                lon: 13.405,
                lat: 52.52,
            },
            ts_ms: 10,
            ttl_ms: None,
            fields: BTreeMap::from([("status".into(), EzuField::Text("idle".into()))]),
        });
        let json = body.to_string();
        assert!(!json.contains("namespace"));
        assert_eq!(body["entities"][0]["collection"], "trucks");
        assert_eq!(body["entities"][0]["id"], "t1");
        assert_eq!(body["entities"][0]["ts_ms"], 10);
        assert_eq!(
            body["entities"][0]["geometry"]["shape"]["point"]["lon"],
            13.405
        );
        assert_eq!(
            body["entities"][0]["fields"]["status"]["value"]["text_value"],
            "idle"
        );
        assert!(body["entities"][0].get("ttl_ms").is_none());
    }

    #[test]
    fn delete_url_keeps_each_id_as_one_path_segment() {
        let url = entity_url("http://127.0.0.1:8080", "trucks", "../other/victim").unwrap();
        assert_eq!(url.path(), "/v1/entities/trucks/..%2Fother%2Fvictim");
        assert_eq!(
            url.path_segments().map(|segments| segments.count()),
            Some(4)
        );
    }

    #[test]
    fn a_reinstall_stops_the_in_flight_run_before_more_writes() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "", 10), "local")
                .unwrap();
            db.create_object_with_audit(&truck("t2", PARIS, "idle", "", 11), "local")
                .unwrap();
            struct PoisonOnFirst {
                inner: FakeEzu,
                db: Arc<RuntimeDb>,
            }
            impl EzuEntitySink for PoisonOnFirst {
                fn upsert(
                    &self,
                    token: &str,
                    entity: EzuEntity,
                ) -> impl Future<Output = Result<EzuWriteOutcome, Status>> + Send {
                    let outcome = self.inner.upsert(token, entity);
                    if let Some((feed, _)) = self.db.get_ezu_geo_feed("fleet", "trucks").unwrap() {
                        let _ = self.db.put_ezu_geo_feed(&feed, "local", 99);
                    }
                    outcome
                }
            }
            let ezu = PoisonOnFirst {
                inner: FakeEzu {
                    token: "ezu-fleet-token".into(),
                    writes: Mutex::default(),
                },
                db: db.clone(),
            };
            let err = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu)).unwrap_err();
            assert_eq!(err.code(), tonic::Code::Aborted);
            assert_eq!(ezu.inner.writes.lock().unwrap().len(), 1);
            assert_eq!(
                db.get_ezu_geo_feed("fleet", "trucks").unwrap().unwrap().1,
                0
            );
            let delayed = last_entity(&ezu.inner, "t1");
            let replaced = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu.inner))
                .unwrap()
                .into_inner();
            assert!(replaced.writes >= 1);
            let replacement = last_entity(&ezu.inner, "t1");
            assert!(replacement.ts_ms > delayed.ts_ms);
            assert_eq!(
                block_on(ezu.inner.upsert("ezu-fleet-token", delayed)).unwrap(),
                EzuWriteOutcome::Stale
            );
            assert_eq!(last_entity(&ezu.inner, "t1").ts_ms, replacement.ts_ms);
        });
    }

    #[test]
    fn a_kind_change_expires_the_entity() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "", 10), "local")
                .unwrap();
            let ezu = FakeEzu {
                token: "ezu-fleet-token".into(),
                writes: Mutex::default(),
            };
            let created = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(created.writes, 1);
            let mut van = db.get_object("t1").unwrap().unwrap();
            van.kind = "van".into();
            van.updated += 10;
            db.update_object_with_audit(&van, "local").unwrap();
            let left = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(left.deletes, 1);
            assert_eq!(left.writes, 0);
            assert_eq!(last_entity(&ezu, "t1").ttl_ms, Some(1));
        });
    }

    #[test]
    fn a_later_object_is_reauthorized_before_write() {
        crate::provider_credentials::with_test_env("EZU_TOKEN", "ezu-fleet-token", || {
            let (db, svc) = setup();
            db.create_object_with_audit(&truck("t1", BERLIN, "idle", "", 10), "local")
                .unwrap();
            db.create_object_with_audit(&truck("t2", PARIS, "idle", "", 11), "local")
                .unwrap();
            struct RestrictSecondOnFirst {
                inner: FakeEzu,
                db: Arc<RuntimeDb>,
            }
            impl EzuEntitySink for RestrictSecondOnFirst {
                fn upsert(
                    &self,
                    token: &str,
                    entity: EzuEntity,
                ) -> impl Future<Output = Result<EzuWriteOutcome, Status>> + Send {
                    let outcome = self.inner.upsert(token, entity);
                    if let Some(mut later) = self.db.get_object("t2").unwrap() {
                        later.properties.insert(
                            crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                            "public".into(),
                        );
                        later.updated += 1;
                        let _ = self.db.update_object_with_audit(&later, "local");
                    }
                    outcome
                }
            }
            let ezu = RestrictSecondOnFirst {
                inner: FakeEzu {
                    token: "ezu-fleet-token".into(),
                    writes: Mutex::default(),
                },
                db: db.clone(),
            };
            let run = block_on(svc.run_ezu_geo_feed_with(run_request(), &ezu))
                .unwrap()
                .into_inner();
            assert_eq!(run.writes, 1);
            assert_eq!(run.deletes, 1);
            assert_eq!(last_entity(&ezu.inner, "t1").ttl_ms, None);
            assert_eq!(last_entity(&ezu.inner, "t2").ttl_ms, Some(1));
        });
    }
}
