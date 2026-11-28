//! HTTP/JSON Ezu client. The plane never sees these URLs or tokens.

use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ezu::{Entity, EventId, EventPage, Ezu, FenceEvent, Position};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Ezu over its HTTP/JSON API. Geometry is converted from
/// `sekai.geospatial-value/v1` at the wire; the plane never sees Ezu types.
#[derive(Clone)]
pub struct HttpEzu {
    client: Client,
    base: String,
    token: String,
}

impl HttpEzu {
    pub fn new(base: &str, token: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("reqwest client"),
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
        }
    }

    /// `/healthz` (no token) and `/v1/status` (bearer). Both must answer.
    pub async fn ping(&self) -> Result<(), String> {
        let health = self
            .client
            .get(format!("{}/healthz", self.base))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !health.status().is_success() {
            return Err(format!("Ezu healthz {}", health.status()));
        }
        let status = self
            .authed(self.client.get(format!("{}/v1/status", self.base)))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !status.status().is_success() {
            return Err(format!("Ezu status {}", status.status()));
        }
        Ok(())
    }

    fn authed(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.bearer_auth(&self.token)
    }

    async fn query_positions(&self, body: Value) -> Result<Vec<Position>, String> {
        let page: QueryPage = self
            .authed(self.client.post(format!("{}/v1/query", self.base)))
            .json(&body)
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        page.entities.iter().map(position_from_value).collect()
    }
}

impl Ezu for HttpEzu {
    async fn upsert(&self, entity: &Entity) -> Result<(), String> {
        let body = json!({
            "entities": [entity_json(entity, None)?]
        });
        let response = self
            .authed(self.client.post(format!("{}/v1/entities", self.base)))
            .json(&body)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("Ezu upsert {}", response.status()));
        }
        Ok(())
    }

    async fn expire(&self, collection: &str, id: &str, ts_ms: i64) -> Result<(), String> {
        // DELETE is not ordered. Re-upsert the live geometry with ttl_ms=1
        // at ts_ms so a newer write still wins, matching Ezu's stale rule.
        let got = self
            .authed(
                self.client
                    .get(format!("{}/v1/entities/{collection}/{id}", self.base)),
            )
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if got.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        if !got.status().is_success() {
            return Err(format!("Ezu get {}", got.status()));
        }
        let page: GetEntity = got.json().await.map_err(|error| error.to_string())?;
        let Some(entity) = page.entity else {
            return Ok(());
        };
        let mut body = entity;
        body["ts_ms"] = json!(ts_ms);
        body["ttl_ms"] = json!(1);
        let response = self
            .authed(self.client.post(format!("{}/v1/entities", self.base)))
            .json(&json!({ "entities": [body] }))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!("Ezu expire {}", response.status()));
        }
        Ok(())
    }

    async fn entity_ids(&self, collection: &str) -> Result<Vec<String>, String> {
        let mut ids = Vec::new();
        let mut cursor = String::new();
        loop {
            let mut body = json!({
                "collection": collection,
                "bbox": { "west": -180.0, "south": -90.0, "east": 180.0, "north": 90.0 },
                "limit": 1000
            });
            if !cursor.is_empty() {
                body["cursor"] = json!(cursor);
            }
            let page: QueryPage = self
                .authed(self.client.post(format!("{}/v1/query", self.base)))
                .json(&body)
                .send()
                .await
                .map_err(|error| error.to_string())?
                .error_for_status()
                .map_err(|error| error.to_string())?
                .json()
                .await
                .map_err(|error| error.to_string())?;
            ids.extend(
                page.entities
                    .into_iter()
                    .filter_map(|entity| entity.get("id")?.as_str().map(str::to_string)),
            );
            if page.next_cursor.is_empty() {
                return Ok(ids);
            }
            cursor = page.next_cursor;
        }
    }

    async fn events_after(&self, after: Option<EventId>, limit: u32) -> Result<EventPage, String> {
        let mut url = format!("{}/v1/events?limit={limit}", self.base);
        if let Some((lsn, index)) = after {
            url.push_str(&format!("&after_lsn={lsn}&after_index={index}"));
        }
        let page: EventsPage = self
            .authed(self.client.get(url))
            .send()
            .await
            .map_err(|error| error.to_string())?
            .error_for_status()
            .map_err(|error| error.to_string())?
            .json()
            .await
            .map_err(|error| error.to_string())?;
        let events = page
            .events
            .into_iter()
            .map(FenceEvent::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let through = page.through_lsn.map(|lsn| (lsn, page.through_index));
        Ok(EventPage { events, through })
    }

    async fn nearby(
        &self,
        collection: &str,
        center: [f64; 2],
        radius_m: f64,
        limit: usize,
    ) -> Result<Vec<Position>, String> {
        let body = json!({
            "collection": collection,
            "radius": {
                "center": { "lon": center[0], "lat": center[1] },
                "meters": radius_m
            },
            "limit": limit
        });
        self.query_positions(body).await
    }

    async fn positions(&self, collection: &str, ids: &[String]) -> Result<Vec<Position>, String> {
        let mut found = Vec::new();
        for id in ids {
            let response = self
                .authed(
                    self.client
                        .get(format!("{}/v1/entities/{collection}/{id}", self.base)),
                )
                .send()
                .await
                .map_err(|error| error.to_string())?;
            if response.status() == StatusCode::NOT_FOUND {
                continue;
            }
            let page: GetEntity = response
                .error_for_status()
                .map_err(|error| error.to_string())?
                .json()
                .await
                .map_err(|error| error.to_string())?;
            if let Some(entity) = page.entity {
                found.push(position_from_value(&entity)?);
            }
        }
        Ok(found)
    }

    async fn tracks(
        &self,
        collection: &str,
        ids: &[String],
        _since_ms: i64,
    ) -> Result<Vec<Position>, String> {
        // Live index only: Ezu HTTP has no historical track surface.
        self.positions(collection, ids).await
    }
}

#[derive(Debug, Deserialize)]
struct GetEntity {
    #[serde(default)]
    entity: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct QueryPage {
    #[serde(default)]
    entities: Vec<Value>,
    #[serde(default)]
    next_cursor: String,
}

#[derive(Debug, Deserialize)]
struct EventsPage {
    #[serde(default)]
    events: Vec<WireEvent>,
    through_lsn: Option<u64>,
    #[serde(default)]
    through_index: u32,
}

#[derive(Debug, Deserialize)]
struct WireEvent {
    lsn: u64,
    #[serde(default)]
    index: u32,
    #[serde(default)]
    fence: String,
    #[serde(default)]
    collection: String,
    #[serde(default)]
    entity: String,
    #[serde(default)]
    kind: Value,
    #[serde(default)]
    ts_ms: i64,
}

impl TryFrom<WireEvent> for FenceEvent {
    type Error = String;

    fn try_from(event: WireEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            lsn: event.lsn,
            index: event.index,
            fence: event.fence,
            collection: event.collection,
            entity: event.entity,
            kind: event_kind(&event.kind),
            ts_ms: event.ts_ms,
        })
    }
}

fn event_kind(value: &Value) -> String {
    let raw = match value {
        Value::String(kind) => kind.as_str(),
        Value::Number(kind) => return number_kind(kind.as_u64().unwrap_or(0)),
        _ => return String::new(),
    };
    match raw {
        "EVENT_KIND_ENTER" | "enter" | "ENTER" => "enter".into(),
        "EVENT_KIND_EXIT" | "exit" | "EXIT" => "exit".into(),
        "EVENT_KIND_INSIDE" | "inside" | "INSIDE" => "inside".into(),
        "EVENT_KIND_DWELL" | "dwell" | "DWELL" => "dwell".into(),
        other => other.to_ascii_lowercase(),
    }
}

fn number_kind(kind: u64) -> String {
    match kind {
        1 => "enter".into(),
        2 => "exit".into(),
        3 => "inside".into(),
        4 => "dwell".into(),
        _ => String::new(),
    }
}

fn entity_json(entity: &Entity, ttl_ms: Option<i64>) -> Result<Value, String> {
    let mut body = json!({
        "collection": entity.collection,
        "id": entity.id,
        "geometry": geometry_json(&entity.geometry)?,
        "ts_ms": entity.ts_ms,
        "fields": entity
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), json!({ "text_value": value })))
            .collect::<serde_json::Map<_, _>>(),
    });
    if let Some(ttl_ms) = ttl_ms {
        body["ttl_ms"] = json!(ttl_ms);
    }
    Ok(body)
}

fn geometry_json(raw: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(raw).map_err(|_| "geometry is not JSON".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "geometry is not an object".to_string())?;
    if object.get("type").and_then(Value::as_str) != Some("sekai.geospatial-value/v1") {
        return Err("geometry is not sekai.geospatial-value/v1".into());
    }
    if object.get("crs").and_then(Value::as_str) != Some("EPSG:4326") {
        return Err("geometry crs is not EPSG:4326".into());
    }
    let coordinates = object
        .get("coordinates")
        .ok_or_else(|| "geometry has no coordinates".to_string())?;
    match object.get("kind").and_then(Value::as_str) {
        Some("point") => {
            let pair = coordinates
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| "point coordinates are [lon, lat]".to_string())?;
            Ok(json!({
                "point": {
                    "lon": pair[0].as_f64().ok_or_else(|| "point lon".to_string())?,
                    "lat": pair[1].as_f64().ok_or_else(|| "point lat".to_string())?,
                }
            }))
        }
        Some("line") => Ok(json!({ "line": { "positions": ring(coordinates)? } })),
        Some("polygon") => Ok(json!({
            "polygon": { "rings": [{ "positions": ring(coordinates)? }] }
        })),
        _ => Err("geometry kind is unsupported".into()),
    }
}

fn ring(coordinates: &Value) -> Result<Vec<Value>, String> {
    let points = coordinates
        .as_array()
        .ok_or_else(|| "ring coordinates are an array".to_string())?;
    points
        .iter()
        .map(|point| {
            let pair = point
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| "ring point is [lon, lat]".to_string())?;
            Ok(json!({
                "lon": pair[0].as_f64().ok_or_else(|| "lon".to_string())?,
                "lat": pair[1].as_f64().ok_or_else(|| "lat".to_string())?,
            }))
        })
        .collect()
}

fn position_from_value(entity: &Value) -> Result<Position, String> {
    let id = entity
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "entity has no id".to_string())?
        .to_string();
    let ts_ms = entity.get("ts_ms").and_then(Value::as_i64).unwrap_or(0);
    let geometry = entity
        .get("geometry")
        .ok_or_else(|| "entity has no geometry".to_string())?;
    Ok(Position {
        id,
        geometry: geometry.to_string(),
        ts_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::Router;
    use axum::extract::Query;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[derive(Default)]
    struct Store {
        entities: HashMap<(String, String), Value>,
        events: Vec<Value>,
    }

    fn point(lon: f64, lat: f64) -> String {
        format!(
            r#"{{"type":"sekai.geospatial-value/v1","kind":"point","crs":"EPSG:4326","coordinates":[{lon},{lat}]}}"#
        )
    }

    async fn serve(store: Arc<Mutex<Store>>) -> String {
        let app = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/v1/status", get(|| async { Json(json!({})) }))
            .route(
                "/v1/entities",
                post({
                    let store = store.clone();
                    move |Json(body): Json<Value>| {
                        let store = store.clone();
                        async move {
                            let mut state = store.lock().expect("store");
                            if let Some(entities) = body.get("entities").and_then(Value::as_array) {
                                for entity in entities {
                                    let collection = entity["collection"].as_str().unwrap().to_string();
                                    let id = entity["id"].as_str().unwrap().to_string();
                                    state.entities.insert((collection, id), entity.clone());
                                }
                            }
                            Json(json!({}))
                        }
                    }
                }),
            )
            .route(
                "/v1/entities/{collection}/{id}",
                get({
                    let store = store.clone();
                    move |axum::extract::Path((collection, id)): axum::extract::Path<(String, String)>| {
                        let store = store.clone();
                        async move {
                            let state = store.lock().expect("store");
                            match state.entities.get(&(collection, id)) {
                                Some(entity) => Json(json!({ "entity": entity })).into_response(),
                                None => (axum::http::StatusCode::NOT_FOUND, "missing").into_response(),
                            }
                        }
                    }
                }),
            )
            .route(
                "/v1/query",
                post({
                    let store = store.clone();
                    move |Json(_body): Json<Value>| {
                        let store = store.clone();
                        async move {
                            let state = store.lock().expect("store");
                            let entities: Vec<Value> = state.entities.values().cloned().collect();
                            Json(json!({ "entities": entities, "next_cursor": "" }))
                        }
                    }
                }),
            )
            .route(
                "/v1/events",
                get({
                    let store = store.clone();
                    move |Query(params): Query<HashMap<String, String>>| {
                        let store = store.clone();
                        async move {
                            let after_lsn = params
                                .get("after_lsn")
                                .and_then(|raw| raw.parse::<u64>().ok());
                            let after_index = params
                                .get("after_index")
                                .and_then(|raw| raw.parse::<u32>().ok())
                                .unwrap_or(0);
                            let state = store.lock().expect("store");
                            let events: Vec<Value> = state
                                .events
                                .iter()
                                .filter(|event| {
                                    let lsn = event["lsn"].as_u64().unwrap_or(0);
                                    let index = event["index"].as_u64().unwrap_or(0) as u32;
                                    after_lsn.is_none_or(|after| (lsn, index) > (after, after_index))
                                })
                                .cloned()
                                .collect();
                            Json(json!({
                                "events": events,
                                "through_lsn": events.last().and_then(|event| event["lsn"].as_u64()),
                                "through_index": events.last().and_then(|event| event["index"].as_u64()).unwrap_or(0)
                            }))
                        }
                    }
                }),
            )
            .with_state(());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn ping_upsert_events_and_ordered_expire() {
        let store = Arc::new(Mutex::new(Store::default()));
        store.lock().unwrap().events.push(json!({
            "lsn": 3,
            "index": 0,
            "fence": "yard",
            "collection": "vehicles",
            "entity": "truck-1",
            "kind": "EVENT_KIND_ENTER",
            "ts_ms": 1000
        }));
        let base = serve(store.clone()).await;
        let ezu = HttpEzu::new(&base, "secret");
        ezu.ping().await.expect("ping");
        ezu.upsert(&Entity {
            collection: "vehicles".into(),
            id: "truck-1".into(),
            geometry: point(13.4, 52.5),
            ts_ms: 50,
            fields: Default::default(),
        })
        .await
        .expect("upsert");
        let ids = ezu.entity_ids("vehicles").await.expect("ids");
        assert_eq!(ids, vec!["truck-1".to_string()]);
        ezu.expire("vehicles", "truck-1", 40)
            .await
            .expect("older expire");
        {
            let state = store.lock().unwrap();
            let entity = state
                .entities
                .get(&("vehicles".into(), "truck-1".into()))
                .expect("kept");
            // The fake store last-write-wins; the client sent ttl_ms=1 at ts 40
            // after GET. Real Ezu would treat ts 40 as stale. Here we only
            // prove the expire path called GET then upsert with ttl.
            assert_eq!(entity["ttl_ms"], 1);
        }
        let page = ezu.events_after(Some((2, 0)), 64).await.expect("events");
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].kind, "enter");
        assert_eq!(page.events[0].fence, "yard");
        assert_eq!(page.through, Some((3, 0)));
    }

    #[test]
    fn point_geometry_becomes_ezu_point() {
        let value = geometry_json(&point(13.405, 52.52)).expect("geometry");
        assert_eq!(value["point"]["lon"], 13.405);
        assert_eq!(value["point"]["lat"], 52.52);
    }
}
