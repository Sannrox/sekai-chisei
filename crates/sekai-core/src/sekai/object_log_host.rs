//! Clerk client for the mikura object-log hosts (ADR 0088, #1196, #2292).
//!
//! ADR 0088 makes one object-log host at a time the writer of object
//! identity and every clerk process its client. `SEKAI_OBJECT_LOG_HOST`
//! names that host, or a comma-separated list of a writer and its standbys;
//! the clerk then appends admitted objects and reads their generations
//! through them instead of opening a log in-process (`SEKAI_OBJECT_LOG`).
//! The two are mutually exclusive.
//!
//! With several hosts the client learns the writer from each host's `health`
//! role. A write a host refuses because it is a standby or was fenced by a
//! newer writer is sent again to the rediscovered writer. A write keyed by
//! an Action id whose reply was lost is sent again too: the host treats a
//! repeat of a committed id as a no-op, so the log answers the unknown
//! outcome. After a write the client keeps the snapshot it produced and
//! passes it as `min_version` on later reads, so a read after a write
//! includes it whichever host answers. A reply that does not carry a
//! snapshot at or past that version (a host that has not caught up, or an
//! older host without versions) is not used.
//!
//! The wire is the pinned mikura tag's `mikura-host` contract: one JSON line
//! per connection, envelope `{ v: 1, token?, min_version?, op, … }`, one
//! JSON line back. Every failure (unreachable hosts, rejected request,
//! malformed or oversized reply, wrong wire version) fails closed. The
//! client never falls back to a local log, and the bearer never appears in
//! errors or `Debug` output.

use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mikura::{
    EvaluateRequest, EvaluateResponse, Group, ObjectRecord, OverlayPatch, Predicate, Sort,
};
use serde::Deserialize;
use serde_json::{Value, json};

pub const HOST_ENV: &str = "SEKAI_OBJECT_LOG_HOST";
/// Bearer the hosts require (ADR 0007 on the mikura side). Required for any
/// non-loopback host.
pub const HOST_BEARER_ENV: &str = "SEKAI_OBJECT_LOG_HOST_BEARER";

const WIRE_V: u64 = 1;
const MAX_REPLY_BYTES: usize = 4 << 20;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Client for one writer host and its standbys. Clones share the learned
/// writer and the read-your-writes version.
#[derive(Clone)]
pub struct ObjectLogHost {
    hosts: Arc<[SocketAddr]>,
    bearer: Option<String>,
    state: Arc<Mutex<ClientState>>,
}

#[derive(Default)]
struct ClientState {
    /// Index into `hosts` of the last host that reported the writer role.
    writer: Option<usize>,
    /// Highest snapshot this client's own writes produced.
    written_version: Option<u64>,
}

impl fmt::Debug for ObjectLogHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectLogHost")
            .field("hosts", &self.hosts)
            .field("bearer", &self.bearer.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Deserialize)]
struct Reply {
    v: u64,
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    load: Option<ObjectRecord>,
    #[serde(default)]
    evaluate: Option<EvaluateWire>,
    #[serde(default)]
    health: Option<Health>,
    /// Snapshot the reply was answered at; absent on older hosts.
    #[serde(default)]
    manifest_version: Option<u64>,
    /// How far that snapshot trails the writer's.
    #[serde(default)]
    behind: Option<u64>,
}

#[derive(Deserialize)]
struct Health {
    #[serde(default)]
    role: String,
}

#[derive(Deserialize)]
struct EvaluateWire {
    two_hop_count: usize,
    sum_amount: i64,
    #[serde(default)]
    objects: Vec<ObjectRecord>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    groups: Vec<EvaluateGroupWire>,
}

#[derive(Deserialize)]
struct EvaluateGroupWire {
    key: Vec<Option<String>>,
    count: usize,
    sum: i64,
    n: u64,
    min: Option<i64>,
    max: Option<i64>,
    avg: (i64, u64),
    #[serde(default)]
    distinct: Option<usize>,
}

impl EvaluateWire {
    fn into_response(self) -> EvaluateResponse {
        EvaluateResponse {
            two_hop_count: self.two_hop_count,
            sum_amount: self.sum_amount,
            objects: self.objects,
            cursor: self.cursor,
            groups: self
                .groups
                .into_iter()
                .map(|group| Group {
                    key: group.key,
                    count: group.count,
                    sum: group.sum,
                    n: group.n,
                    min: group.min,
                    max: group.max,
                    avg: group.avg,
                    distinct: group.distinct,
                })
                .collect(),
        }
    }
}

/// Why a host answered without serving the request.
enum Refusal {
    /// A standby, or a writer fenced by a newer one. Try the writer.
    NotWriter,
    /// The host has not reached the requested `min_version`.
    Behind,
    Other,
}

fn refusal(reply: &Reply) -> Refusal {
    let error = reply.error.as_deref().unwrap_or("");
    if error.starts_with(mikura::LOG_FENCED) || error == "standby refuses writes" {
        Refusal::NotWriter
    } else if error.starts_with("minimum manifest version") {
        Refusal::Behind
    } else {
        Refusal::Other
    }
}

/// Whether a lost reply may be resolved by sending the write again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Repeat {
    /// Keyed by an Action id: the host applies a repeat at most once.
    Idempotent,
    /// Not keyed: the caller resolves a lost reply by reading the log.
    Once,
}

impl ObjectLogHost {
    /// A client for `host:port`, or for a comma-separated list of a writer
    /// and its standbys. A host that is not on loopback must be given a
    /// bearer, since it serves object identity to anyone who can reach it.
    pub fn new(addresses: &str, bearer: Option<String>) -> Result<Self, String> {
        let bearer = bearer.filter(|bearer| !bearer.trim().is_empty());
        let hosts = addresses
            .split(',')
            .map(|address| {
                let addr = address
                    .trim()
                    .to_socket_addrs()
                    .map_err(|_| format!("{HOST_ENV} must be host:port[,host:port…]"))?
                    .next()
                    .ok_or_else(|| format!("{HOST_ENV} did not resolve"))?;
                if !addr.ip().is_loopback() && bearer.is_none() {
                    return Err(format!(
                        "{HOST_ENV} on a non-loopback address requires {HOST_BEARER_ENV}"
                    ));
                }
                Ok(addr)
            })
            .collect::<Result<Arc<[_]>, String>>()?;
        Ok(Self {
            hosts,
            bearer,
            state: Arc::default(),
        })
    }

    /// Resolves the process host client once. Later admits reuse this
    /// client instead of re-reading env and re-resolving DNS (#1207).
    pub fn from_env() -> Result<Option<Self>, String> {
        let cache = CACHED_FROM_ENV.get_or_init(|| Mutex::new(None));
        let mut cached = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        take_cached(&mut cached, Self::from_env_uncached)
    }

    fn from_env_uncached() -> Result<Option<Self>, String> {
        let Some(address) = std::env::var(HOST_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };
        Self::new(&address, std::env::var(HOST_BEARER_ENV).ok()).map(Some)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ClientState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// One request to one host. Transport errors mean the outcome is unknown.
    fn call_at(&self, index: usize, mut request: Value) -> Result<Reply, String> {
        let addr = self.hosts[index];
        request["v"] = json!(WIRE_V);
        if let Some(bearer) = &self.bearer {
            request["token"] = json!(bearer);
        }
        let mut line = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
        line.push(b'\n');
        let unreachable = |_| "object-log host is unreachable".to_string();
        #[cfg(test)]
        CONNECT_COUNT.with(|count| count.set(count.get() + 1));
        let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(unreachable)?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .map_err(unreachable)?;
        stream
            .set_write_timeout(Some(TIMEOUT))
            .map_err(unreachable)?;
        stream.write_all(&line).map_err(unreachable)?;
        let mut reply = Vec::new();
        stream
            .take(MAX_REPLY_BYTES as u64 + 1)
            .read_to_end(&mut reply)
            .map_err(|_| "object-log host did not reply".to_string())?;
        if reply.len() > MAX_REPLY_BYTES {
            return Err("object-log host reply exceeds its bound".into());
        }
        let end = reply
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or("object-log host reply is not one JSON line")?;
        let reply: Reply = serde_json::from_slice(&reply[..end])
            .map_err(|_| "object-log host reply is malformed".to_string())?;
        if reply.v != WIRE_V {
            return Err(format!("unsupported object-log host wire v {}", reply.v));
        }
        if let Some(behind) = reply.behind {
            crate::obs::metrics::set_object_log_host_behind(&addr.to_string(), behind);
        }
        Ok(reply)
    }

    /// The writer's index. One configured host is the writer without a
    /// `health` round trip, so a single older host keeps working. With
    /// several, the first host whose `health` role is `writer` wins; a host
    /// fenced by a newer writer reports `fenced` and is never chosen again.
    fn writer(&self) -> Result<usize, String> {
        if let Some(index) = self.state().writer {
            return Ok(index);
        }
        let found = if self.hosts.len() == 1 {
            Some(0)
        } else {
            (0..self.hosts.len()).find(|&index| {
                self.call_at(index, json!({ "op": "health" }))
                    .ok()
                    .and_then(|reply| reply.health)
                    .is_some_and(|health| health.role == "writer")
            })
        };
        let index = found.ok_or("no object-log host reports the writer role")?;
        self.state().writer = Some(index);
        for (other, addr) in self.hosts.iter().enumerate() {
            crate::obs::metrics::set_object_log_host_writer(&addr.to_string(), other == index);
        }
        Ok(index)
    }

    fn forget_writer(&self, index: usize) {
        let mut state = self.state();
        if state.writer == Some(index) {
            state.writer = None;
        }
    }

    /// Sends a write to the writer. A standby or fenced refusal is sent
    /// again to the rediscovered writer; a lost reply is sent again only
    /// when `repeat` allows it. Attempts are bounded by the host count.
    fn write(&self, request: Value, repeat: Repeat) -> Result<Reply, String> {
        let mut last_error = String::from("no object-log host reports the writer role");
        for attempt in 0..=self.hosts.len() {
            if attempt > 0 {
                crate::obs::metrics::record_object_log_host_retry();
            }
            let Ok(index) = self.writer() else { continue };
            match self.call_at(index, request.clone()) {
                Ok(reply) if reply.ok => {
                    if let Some(version) = reply.manifest_version {
                        let mut state = self.state();
                        state.written_version = state.written_version.max(Some(version));
                    }
                    return Ok(reply);
                }
                Ok(reply) if matches!(refusal(&reply), Refusal::NotWriter) => {
                    self.forget_writer(index);
                    last_error = reply.error.unwrap_or_default();
                }
                Ok(reply) => return Ok(reply),
                Err(error) => {
                    self.forget_writer(index);
                    if repeat == Repeat::Once {
                        return Err(error);
                    }
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }

    /// Sends a read with this client's written version as `min_version`,
    /// writer first. A host that is behind that version, unreachable, or
    /// answers without a version is skipped for the next host.
    fn read(&self, mut request: Value) -> Result<Reply, String> {
        let min_version = self.state().written_version.filter(|version| *version > 0);
        if let Some(version) = min_version {
            request["min_version"] = json!(version);
        }
        let first = self.writer().ok();
        let order = first
            .into_iter()
            .chain((0..self.hosts.len()).filter(|index| Some(*index) != first));
        let mut last_error = String::from("object-log host is unreachable");
        for (attempt, index) in order.enumerate() {
            if attempt > 0 {
                crate::obs::metrics::record_object_log_host_retry();
            }
            match self.call_at(index, request.clone()) {
                Ok(reply) if matches!(refusal(&reply), Refusal::Behind) => {
                    last_error = reply.error.unwrap_or_default();
                }
                Ok(reply)
                    if min_version
                        .is_some_and(|min| reply.manifest_version.is_none_or(|at| at < min)) =>
                {
                    last_error = "object-log host did not report the requested version".into();
                }
                Ok(reply) => return Ok(reply),
                Err(error) => {
                    self.forget_writer(index);
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }

    fn require_ok(reply: Reply) -> Result<Reply, String> {
        if reply.ok {
            Ok(reply)
        } else {
            Err(format!(
                "object-log host rejected the request: {}",
                reply.error.unwrap_or_default()
            ))
        }
    }

    /// Commits `records` as one batch on the host.
    pub fn ingest_batch(&self, records: &[ObjectRecord]) -> Result<(), String> {
        Self::require_ok(self.write(
            json!({ "op": "ingest_batch", "records": records }),
            Repeat::Once,
        )?)
        .map(|_| ())
    }

    /// The identity's current record, or `None` when the host has never
    /// committed it.
    pub fn load(
        &self,
        namespace: &str,
        kind: &str,
        key: &str,
    ) -> Result<Option<ObjectRecord>, String> {
        let reply = self.read(json!({
            "op": "load",
            "namespace": namespace,
            "kind": kind,
            "key": key
        }))?;
        // The pinned host reports a never-committed identity only as error
        // text; it has no structured not-found. A namespace the host has
        // never ingested is the same absence: first admit must ingest rather
        // than fail closed. The real-host tests pin both strings, so a pin
        // bump that rewords them fails there instead of turning every first
        // admit into an error. Any other failure stays an error.
        if !reply.ok {
            let error = reply.error.as_deref().unwrap_or("");
            if error == format!("unknown identity {namespace}/{kind}/{key}")
                || error == format!("unknown namespace {namespace}")
            {
                return Ok(None);
            }
        }
        let record = Self::require_ok(reply)?
            .load
            .ok_or("object-log host load returned no record")?;
        if record.namespace != namespace || record.kind != kind || record.key != key {
            return Err("object-log host returned a different identity".into());
        }
        Ok(Some(record))
    }

    /// Admits one object: an identity already at these properties keeps its
    /// generation; otherwise the record is appended and its committed
    /// generation read back. A committed record that does not carry the
    /// admitted properties (another writer won the race) fails closed.
    pub fn admit(&self, record: ObjectRecord) -> Result<u64, String> {
        if let Some(existing) = self.load(&record.namespace, &record.kind, &record.key)?
            && !existing.hidden
            && existing.props == record.props
        {
            return Ok(existing.r#gen);
        }
        self.ingest_batch(std::slice::from_ref(&record))?;
        let committed = self
            .load(&record.namespace, &record.kind, &record.key)?
            .ok_or("object-log host did not commit the admitted identity")?;
        if committed.hidden || committed.props != record.props {
            return Err("object-log host generation does not carry the admitted properties".into());
        }
        Ok(committed.r#gen)
    }

    /// Appends `record`'s properties under Action `action_id` while the
    /// identity is still at `expected_gen` (0: absent). A repeat of a
    /// committed id is a no-op. Errors carry the host's text, so a stale
    /// generation reads as `stale generation` and an unopened namespace as
    /// `unknown namespace`.
    pub fn apply_action(
        &self,
        action_id: &str,
        record: &ObjectRecord,
        expected_gen: u64,
    ) -> Result<(), String> {
        Self::require_ok(self.write(
            json!({
                "op": "apply_action",
                "id": action_id,
                "namespace": record.namespace,
                "kind": record.kind,
                "key": record.key,
                "props": record.props,
                "expected_gen": expected_gen,
            }),
            Repeat::Idempotent,
        )?)
        .map(|_| ())
    }

    /// Source ingest of `record` (overlay merge and conflict audit) while
    /// its identity is still at `expected_gen` (0: absent). `record.action_id`
    /// is required; a repeat of a committed id is a no-op. A stale
    /// generation reads as `stale generation`.
    pub fn ingest_fenced(&self, record: &ObjectRecord, expected_gen: u64) -> Result<(), String> {
        Self::require_ok(self.write(
            json!({
                "op": "ingest_fenced",
                "record": record,
                "expected_gen": expected_gen,
            }),
            Repeat::Idempotent,
        )?)
        .map(|_| ())
    }

    /// Admits a property overlay on the host (ADR 0009).
    pub fn apply_overlay(
        &self,
        patch: &OverlayPatch,
        action_id: &str,
        expected_gen: Option<u64>,
    ) -> Result<(), String> {
        let mut request = json!({
            "op": "apply_overlay",
            "id": action_id,
            "namespace": patch.namespace,
            "kind": patch.kind,
            "key": patch.key,
            "props": patch.props,
            "cleared": patch.cleared,
        });
        if let Some(at) = &patch.at {
            request["at"] = json!(at);
        }
        if let Some(generation) = expected_gen {
            request["expected_gen"] = json!(generation);
        }
        Self::require_ok(self.write(request, Repeat::Idempotent)?).map(|_| ())
    }

    /// Namespace-scoped evaluate from the host (#2290, #3510).
    /// `deny` is the host's property-deny shorthand for the log restriction.
    pub fn evaluate(
        &self,
        request: &EvaluateRequest,
        deny: &[(String, String)],
    ) -> Result<EvaluateResponse, String> {
        let reply = Self::require_ok(self.read(evaluate_wire(request, deny))?)?;
        reply
            .evaluate
            .map(EvaluateWire::into_response)
            .ok_or_else(|| "object-log host evaluate returned no payload".into())
    }
}

fn evaluate_wire(request: &EvaluateRequest, deny: &[(String, String)]) -> Value {
    let mut body = json!({
        "namespace": request.namespace,
        "root_kind": request.root_kind,
        "hops": request.hops.iter().map(|hop| json!({
            "far_kind": hop.far_kind,
            "join_property": hop.join_property,
            "incoming": hop.incoming,
        })).collect::<Vec<_>>(),
        "sum_kind": request.sum_kind,
        "sum_property": request.sum_property,
        "deny": deny.iter().map(|(kind, property)| json!({
            "kind": kind,
            "property": property,
        })).collect::<Vec<_>>(),
    });
    if let Some(predicate) = &request.predicate {
        body["predicate"] = predicate_wire(predicate);
    }
    if let Some(breakdown) = &request.breakdown {
        body["breakdown"] = json!({
            "group_by": breakdown.group_by,
            "max_groups": breakdown.max_groups,
            "distinct": breakdown.distinct,
        });
    }
    if request.object_bound > 0 {
        body["object_bound"] = json!(request.object_bound);
    }
    if let Some(sort) = &request.sort {
        body["sort"] = sort_wire(sort);
    }
    if !request.then_by.is_empty() {
        body["then_by"] = json!(request.then_by.iter().map(sort_wire).collect::<Vec<_>>());
    }
    if request.page_size > 0 {
        body["page_size"] = json!(request.page_size);
    }
    if let Some(cursor) = &request.cursor {
        body["cursor"] = json!(cursor);
    }
    json!({ "op": "evaluate", "request": body })
}

fn sort_wire(sort: &Sort) -> Value {
    let mut body = json!({
        "property": sort.property,
        "descending": sort.descending,
    });
    if let Some(nearest) = &sort.nearest {
        body["nearest"] = json!(nearest);
    }
    body
}

fn predicate_wire(predicate: &Predicate) -> Value {
    match predicate {
        Predicate::Eq { property, value } => {
            json!({ "op": "eq", "property": property, "value": value })
        }
        Predicate::And(args) => json!({
            "op": "and",
            "args": args.iter().map(predicate_wire).collect::<Vec<_>>(),
        }),
        Predicate::Neq { property, value } => {
            json!({ "op": "neq", "property": property, "value": value })
        }
        Predicate::Or(args) => json!({
            "op": "or",
            "args": args.iter().map(predicate_wire).collect::<Vec<_>>(),
        }),
        Predicate::Not(arg) => json!({ "op": "not", "arg": predicate_wire(arg) }),
        Predicate::Missing { property } => json!({ "op": "missing", "property": property }),
        Predicate::Range { property, min, max } => json!({
            "op": "range",
            "property": property,
            "min": min,
            "max": max,
        }),
        Predicate::Bbox {
            property,
            min_lat,
            min_lon,
            max_lat,
            max_lon,
        } => json!({
            "op": "bbox",
            "property": property,
            "min_lat": min_lat,
            "min_lon": min_lon,
            "max_lat": max_lat,
            "max_lon": max_lon,
        }),
    }
}

type CachedFromEnv = Option<Result<Option<ObjectLogHost>, String>>;

fn take_cached(
    cache: &mut CachedFromEnv,
    resolve: impl FnOnce() -> Result<Option<ObjectLogHost>, String>,
) -> Result<Option<ObjectLogHost>, String> {
    if let Some(resolved) = cache.as_ref() {
        return resolved.clone();
    }
    let resolved = resolve();
    if resolved.is_ok() {
        *cache = Some(resolved.clone());
    }
    resolved
}

static CACHED_FROM_ENV: OnceLock<Mutex<CachedFromEnv>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static CONNECT_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_connect_count() {
    CONNECT_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn connect_count() -> usize {
    CONNECT_COUNT.with(|count| count.get())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::Arc;

    fn record(key: &str, region: &str) -> ObjectRecord {
        ObjectRecord {
            r#gen: 0,
            namespace: "sales".into(),
            kind: "Customer".into(),
            key: key.into(),
            hidden: false,
            action_id: None,
            props: HashMap::from([("region".into(), region.into())]),
            schema_version: 1,
            source_version: 0,
        }
    }

    /// One real object-log host on loopback, serving until the test ends.
    fn spawn_host(bearer: Option<&str>) -> (SocketAddr, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let host = mikura_host::Host::open(&dir.path().join("objects.mikura"), 64).unwrap();
        if let Some(bearer) = bearer {
            host.require_bearer(bearer).unwrap();
        }
        let listener = mikura_host::Host::bind("127.0.0.1:0".parse().unwrap(), bearer).unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let _ = host.serve(listener);
        });
        (addr, dir)
    }

    #[test]
    fn two_clerk_clients_share_generations_through_one_host() {
        // ADR 0088 validation: write once through one clerk client, read the
        // same generation from a second.
        let (addr, _dir) = spawn_host(Some("clerk-bearer"));
        let first = ObjectLogHost::new(&addr.to_string(), Some("clerk-bearer".into())).unwrap();
        let second = ObjectLogHost::new(&addr.to_string(), Some("clerk-bearer".into())).unwrap();

        let generation = first.admit(record("c-1", "eu")).unwrap();
        let seen = second.load("sales", "Customer", "c-1").unwrap().unwrap();
        assert_eq!(seen.r#gen, generation);
        assert_eq!(seen.props["region"], "eu");
        // An identical admit from the other client keeps the generation.
        assert_eq!(second.admit(record("c-1", "eu")).unwrap(), generation);
        // A changed admit appends, and both clients see the new generation.
        let updated = second.admit(record("c-1", "us")).unwrap();
        assert!(updated > generation);
        assert_eq!(
            first
                .load("sales", "Customer", "c-1")
                .unwrap()
                .unwrap()
                .r#gen,
            updated
        );
        assert_eq!(first.load("sales", "Customer", "missing").unwrap(), None);
    }

    #[test]
    fn evaluate_counts_admitted_roots_and_fails_closed_when_unreachable() {
        let (addr, _dir) = spawn_host(None);
        let host = ObjectLogHost::new(&addr.to_string(), None).unwrap();
        host.admit(record("c-1", "eu")).unwrap();
        host.admit(record("c-2", "us")).unwrap();
        let request = EvaluateRequest {
            namespace: "sales".into(),
            root_kind: "Customer".into(),
            hops: Vec::new(),
            sum_kind: "Customer".into(),
            sum_property: String::new(),
            ..EvaluateRequest::default()
        };
        let page = host.evaluate(&request, &[]).unwrap();
        assert_eq!(page.two_hop_count, 2);
        assert!(page.groups.is_empty());
        assert!(page.objects.is_empty());

        let mut members = request.clone();
        members.object_bound = 8;
        members.sort = Some(Sort::by("region"));
        members.page_size = 1;
        let first = host.evaluate(&members, &[]).unwrap();
        assert_eq!(first.objects.len(), 1);
        assert_eq!(first.two_hop_count, 2);
        let token = first.cursor.expect("next page");
        members.cursor = Some(token);
        let second = host.evaluate(&members, &[]).unwrap();
        assert_eq!(second.objects.len(), 1);
        assert_ne!(first.objects[0].key, second.objects[0].key);
        assert!(second.cursor.is_none());

        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let gone = closed.local_addr().unwrap();
        drop(closed);
        let unreachable = ObjectLogHost::new(&gone.to_string(), None).unwrap();
        let error = unreachable.evaluate(&request, &[]).unwrap_err();
        assert!(error.contains("unreachable"), "{error}");
    }

    #[test]
    fn two_namespaces_keep_separate_generations_through_the_host() {
        let (addr, _dir) = spawn_host(None);
        let host = ObjectLogHost::new(&addr.to_string(), None).unwrap();
        let sales = record("shared", "eu");
        let mut ops = record("shared", "us");
        ops.namespace = "ops".into();
        let sales_gen = host.admit(sales).unwrap();
        let ops_gen = host.admit(ops).unwrap();
        assert_eq!(sales_gen, 1);
        assert_eq!(ops_gen, 1);
        assert_eq!(
            host.load("sales", "Customer", "shared")
                .unwrap()
                .unwrap()
                .props["region"],
            "eu"
        );
        assert_eq!(
            host.load("ops", "Customer", "shared")
                .unwrap()
                .unwrap()
                .props["region"],
            "us"
        );
    }

    #[test]
    fn a_wrong_bearer_or_unreachable_host_fails_closed() {
        let (addr, _dir) = spawn_host(Some("clerk-bearer"));
        let honest = ObjectLogHost::new(&addr.to_string(), Some("clerk-bearer".into())).unwrap();
        let generation = honest.admit(record("c-1", "eu")).unwrap();
        let forged = ObjectLogHost::new(&addr.to_string(), Some("guess".into())).unwrap();
        let refused = forged.admit(record("c-1", "us")).unwrap_err();
        assert!(!refused.contains("guess"), "the bearer leaked: {refused}");
        assert_eq!(
            honest
                .load("sales", "Customer", "c-1")
                .unwrap()
                .unwrap()
                .r#gen,
            generation
        );

        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let gone = closed.local_addr().unwrap();
        drop(closed);
        let unreachable = ObjectLogHost::new(&gone.to_string(), None).unwrap();
        assert!(unreachable.admit(record("c-1", "eu")).is_err());

        assert!(ObjectLogHost::new("203.0.113.9:4000", None).is_err());
        assert!(
            !format!(
                "{:?}",
                ObjectLogHost::new("127.0.0.1:1", Some("secret".into())).unwrap()
            )
            .contains("secret")
        );
    }

    /// A host double that answers every connection with `reply(op)`.
    fn spawn_scripted(reply: impl Fn(&str) -> String + Send + 'static) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut line = String::new();
                let mut byte = [0u8; 1];
                while stream.read(&mut byte).is_ok_and(|read| read == 1) && byte[0] != b'\n' {
                    line.push(byte[0] as char);
                }
                let op = serde_json::from_str::<Value>(&line).unwrap()["op"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let _ = stream.write_all(reply(&op).as_bytes());
            }
        });
        addr
    }

    #[test]
    fn a_host_that_commits_different_properties_or_breaks_the_wire_fails_closed() {
        // Another writer won the race: the committed record differs.
        let raced = spawn_scripted(|op| {
            match op {
            "load" => r#"{"v":1,"ok":true,"load":{"gen":7,"namespace":"sales","kind":"Customer","key":"c-1","hidden":false,"props":{"region":"other"}}}"#.to_string() + "\n",
            _ => "{\"v\":1,\"ok\":true}\n".into(),
        }
        });
        let error = ObjectLogHost::new(&raced.to_string(), None)
            .unwrap()
            .admit(record("c-1", "eu"))
            .unwrap_err();
        assert!(
            error.contains("does not carry the admitted properties"),
            "{error}"
        );

        for reply in [
            "{\"v\":2,\"ok\":true}\n",
            "not json\n",
            "{\"v\":1,\"ok\":true,\"load\":{\"gen\":1,\"namespace\":\"sales\",\"kind\":\"Other\",\"key\":\"c-1\",\"hidden\":false,\"props\":{}}}\n",
            "{\"v\":1,\"ok\":false,\"error\":\"store is poisoned\"}\n",
        ] {
            let host = spawn_scripted(move |_| reply.to_string());
            assert!(
                ObjectLogHost::new(&host.to_string(), None)
                    .unwrap()
                    .load("sales", "Customer", "c-1")
                    .is_err(),
                "{reply}"
            );
        }
    }

    #[test]
    fn a_local_log_and_a_host_are_mutually_exclusive() {
        let (addr, dir) = spawn_host(None);
        let host = ObjectLogHost::new(&addr.to_string(), None).unwrap();
        let object = crate::domain::Object {
            id: "c-1".into(),
            kind: "Customer".into(),
            name: "c-1".into(),
            namespace: "sales".into(),
            external_id: String::new(),
            properties: HashMap::from([("region".into(), "eu".into())]),
            created: 1,
            updated: 1,
        };
        let via_host = crate::sekai::object_log::with_test_log_host(host.clone(), || {
            crate::sekai::object_log::ensure_admitted_object_in_configured_log(&object)
        })
        .unwrap();
        assert_eq!(
            via_host,
            host.load("sales", "Customer", "c-1")
                .unwrap()
                .map(|record| record.r#gen)
        );
        let both =
            crate::sekai::object_log::with_test_log_path(&dir.path().join("local.mikura"), || {
                crate::sekai::object_log::with_test_log_host(host, || {
                    crate::sekai::object_log::ensure_admitted_object_in_configured_log(&object)
                })
            });
        assert!(both.unwrap_err().contains("mutually exclusive"));
        assert!(!dir.path().join("local.mikura").exists());
    }

    #[test]
    fn take_cached_resolves_the_host_client_once() {
        let mut cache = None;
        let calls = std::cell::Cell::new(0);
        let host = ObjectLogHost::new("127.0.0.1:1", None).unwrap();
        let resolve = || {
            calls.set(calls.get() + 1);
            Ok(Some(host.clone()))
        };
        assert!(take_cached(&mut cache, resolve).unwrap().is_some());
        assert!(take_cached(&mut cache, resolve).unwrap().is_some());
        assert_eq!(calls.get(), 1);

        let mut errors = None;
        let error_calls = std::cell::Cell::new(0);
        assert!(
            take_cached(&mut errors, || {
                error_calls.set(error_calls.get() + 1);
                Err("dns lookup failed".into())
            })
            .is_err()
        );
        assert!(
            take_cached(&mut errors, || {
                error_calls.set(error_calls.get() + 1);
                Err("dns lookup failed".into())
            })
            .is_err()
        );
        assert_eq!(error_calls.get(), 2);
    }

    #[test]
    fn identical_admits_do_not_pay_three_rtts_each() {
        let (addr, _dir) = spawn_host(None);
        let host = ObjectLogHost::new(&addr.to_string(), None).unwrap();
        reset_connect_count();
        let generation = host.admit(record("c-cache", "eu")).unwrap();
        assert_eq!(host.admit(record("c-cache", "eu")).unwrap(), generation);
        assert_eq!(host.admit(record("c-cache", "eu")).unwrap(), generation);
        assert_eq!(
            connect_count(),
            5,
            "first admit is load+ingest+load; later identical admits are one load each"
        );
    }

    /// A writer and a standby host on one log, each on its own loopback
    /// port. The writer can be stopped; both stay reachable as in-process
    /// handles for promotion and health.
    struct Pair {
        _dir: tempfile::TempDir,
        writer: mikura_host::Host,
        writer_addr: SocketAddr,
        standby: mikura_host::Host,
        standby_addr: SocketAddr,
        stop_writer: Arc<std::sync::atomic::AtomicBool>,
        writer_thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Pair {
        fn open() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("objects.mikura");
            let writer = mikura_host::Host::open(&log, 64).unwrap();
            // `apply_action` needs an opened namespace.
            let seeded = writer.handle(mikura_host::HostRequest::IngestBatch {
                records: vec![record("seed", "eu")],
            });
            assert!(seeded.ok, "{:?}", seeded.error);
            let standby = mikura_host::Host::open_standby(&log, 64).unwrap();
            let stop_writer = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let listener = mikura_host::Host::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
            let writer_addr = listener.local_addr().unwrap();
            let served = writer.clone();
            let stop = stop_writer.clone();
            let writer_thread = std::thread::spawn(move || {
                let _ = served
                    .serve_while(listener, || !stop.load(std::sync::atomic::Ordering::SeqCst));
            });
            let listener = mikura_host::Host::bind("127.0.0.1:0".parse().unwrap(), None).unwrap();
            let standby_addr = listener.local_addr().unwrap();
            let served = standby.clone();
            std::thread::spawn(move || {
                let _ = served.serve(listener);
            });
            Self {
                _dir: dir,
                writer,
                writer_addr,
                standby,
                standby_addr,
                stop_writer,
                writer_thread: Some(writer_thread),
            }
        }

        fn client(&self) -> ObjectLogHost {
            ObjectLogHost::new(&format!("{},{}", self.writer_addr, self.standby_addr), None)
                .unwrap()
        }

        fn promote_standby(&self) {
            let promoted = self.standby.handle(mikura_host::HostRequest::Promote);
            assert!(promoted.ok, "{:?}", promoted.error);
        }

        /// Closes the writer's port; later connects are refused.
        fn stop_writer(&mut self) {
            self.stop_writer
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = TcpStream::connect(self.writer_addr);
            self.writer_thread.take().unwrap().join().unwrap();
        }

        fn rejected(host: &mikura_host::Host) -> u64 {
            host.handle(mikura_host::HostRequest::Health)
                .health
                .unwrap()
                .rejected
        }
    }

    fn apply_until_admitted(client: &ObjectLogHost, id: &str, record: &ObjectRecord) {
        // A refused or unreachable write returns an error; the durable
        // ingest intent (#2289) sends it again. Stand in for that retry.
        for _ in 0..200 {
            if client.apply_action(id, record, 0).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("{id} was never admitted");
    }

    #[test]
    fn the_client_learns_the_writer_from_health_whichever_host_is_listed_first() {
        let pair = Pair::open();
        let client =
            ObjectLogHost::new(&format!("{},{}", pair.standby_addr, pair.writer_addr), None)
                .unwrap();
        let standby_rejected = Pair::rejected(&pair.standby);
        let generation = client.admit(record("c-1", "eu")).unwrap();
        assert_eq!(generation, 1);
        assert_eq!(client.state().writer, Some(1));
        assert_eq!(Pair::rejected(&pair.standby), standby_rejected);
    }

    #[test]
    fn replacing_the_writer_under_load_loses_and_doubles_no_action() {
        let pair = Pair::open();
        // Two clerk replicas: independent clients, no shared state.
        let replicas = [pair.client(), pair.client()];
        let writes = 40;
        let halfway = std::sync::Barrier::new(replicas.len() + 1);
        let before = Pair::rejected(&pair.writer);
        std::thread::scope(|scope| {
            for (replica, client) in replicas.iter().enumerate() {
                let halfway = &halfway;
                scope.spawn(move || {
                    for index in 0..writes {
                        if index == writes / 2 {
                            halfway.wait();
                        }
                        let key = format!("r{replica}-{index}");
                        let id = format!("act-{key}");
                        apply_until_admitted(client, &id, &record(&key, "eu"));
                    }
                });
            }
            // Both replicas have written to the first writer and still hold
            // it as their writer when the standby takes over.
            halfway.wait();
            pair.promote_standby();
        });

        // Each replica's next write after the promotion was refused by the
        // fenced host, then sent to the new writer.
        let fenced_rejected = Pair::rejected(&pair.writer);
        assert!(fenced_rejected >= before + replicas.len() as u64);
        for client in &replicas {
            assert_eq!(client.state().writer, Some(1));
            client.admit(record("after", "eu")).unwrap();
        }
        // A fenced host is never written to again once it refused.
        assert_eq!(Pair::rejected(&pair.writer), fenced_rejected);

        let reader = pair.client();
        for replica in 0..replicas.len() {
            for index in 0..writes {
                let key = format!("r{replica}-{index}");
                let committed = reader.load("sales", "Customer", &key).unwrap().unwrap();
                assert_eq!(committed.r#gen, 1, "{key} applied more than once");
                assert_eq!(committed.action_id.as_deref(), Some(&*format!("act-{key}")));
            }
        }
    }

    #[test]
    fn a_read_after_a_write_includes_it_when_only_a_standby_answers() {
        let mut pair = Pair::open();
        let client = pair.client();
        client
            .apply_action("act-c-1", &record("c-1", "eu"), 0)
            .unwrap();
        let written = client.state().written_version.unwrap();
        assert!(written > 0);
        pair.stop_writer();

        let seen = client.load("sales", "Customer", "c-1").unwrap().unwrap();
        assert_eq!(seen.props["region"], "eu");
        // With the writer gone, a write fails closed instead of reaching the
        // standby.
        assert!(
            client
                .apply_action("act-c-2", &record("c-2", "eu"), 0)
                .is_err()
        );
        assert_eq!(client.load("sales", "Customer", "c-2").unwrap(), None);
    }

    #[test]
    fn a_reply_without_the_written_version_is_not_used_for_the_read() {
        // An older host answers without a snapshot version; a host that is
        // behind refuses. Neither may answer a read after this client's write.
        let older = spawn_scripted(|_| {
            "{\"v\":1,\"ok\":true,\"load\":{\"gen\":1,\"namespace\":\"sales\",\"kind\":\"Customer\",\"key\":\"c-1\",\"hidden\":false,\"props\":{}}}\n".into()
        });
        let behind = spawn_scripted(|_| {
            "{\"v\":1,\"ok\":false,\"error\":\"minimum manifest version 9 not reached (serving 3)\",\"manifest_version\":3}\n".into()
        });
        let client = ObjectLogHost::new(&format!("{older},{behind}"), None).unwrap();
        client.state().writer = Some(0);
        client.state().written_version = Some(9);
        let error = client.load("sales", "Customer", "c-1").unwrap_err();
        assert!(error.contains("minimum manifest version"), "{error}");
        // Without a written version, the older host's answer stands.
        client.state().written_version = None;
        assert!(client.load("sales", "Customer", "c-1").unwrap().is_some());
    }

    #[test]
    fn a_list_rejects_any_unresolvable_or_unauthenticated_entry() {
        assert_eq!(
            ObjectLogHost::new("127.0.0.1:1, 127.0.0.1:2", None)
                .unwrap()
                .hosts
                .len(),
            2
        );
        assert!(ObjectLogHost::new("127.0.0.1:1,not-an-address", None).is_err());
        assert!(ObjectLogHost::new("127.0.0.1:1,203.0.113.9:4000", None).is_err());
    }
}
