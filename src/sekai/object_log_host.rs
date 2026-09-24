//! Clerk client for the mikura object-log host (ADR 0088, #1196).
//!
//! ADR 0088 makes one object-log host the owner of object identity and every
//! clerk process its client. `SEKAI_OBJECT_LOG_HOST` names that host; the
//! clerk then appends admitted objects and reads their generations through
//! it instead of opening a log in-process (`SEKAI_OBJECT_LOG`). The two are
//! mutually exclusive.
//!
//! The wire is the pinned mikura tag's `mikura-host` contract: one JSON line
//! per connection, envelope `{ v: 1, token?, op, … }`, one JSON line back.
//! Every failure (unreachable host, rejected request, malformed or oversized
//! reply, wrong wire version) fails closed. The client never falls back to a
//! local log, and the bearer never appears in errors or `Debug` output.

use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use mikura::ObjectRecord;
use serde::Deserialize;
use serde_json::{Value, json};

pub const HOST_ENV: &str = "SEKAI_OBJECT_LOG_HOST";
/// Bearer the host requires (ADR 0007 on the mikura side). Required for any
/// non-loopback host.
pub const HOST_BEARER_ENV: &str = "SEKAI_OBJECT_LOG_HOST_BEARER";

const WIRE_V: u64 = 1;
const MAX_REPLY_BYTES: usize = 4 << 20;
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct ObjectLogHost {
    addr: SocketAddr,
    bearer: Option<String>,
}

impl fmt::Debug for ObjectLogHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectLogHost")
            .field("addr", &self.addr)
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
}

impl ObjectLogHost {
    /// A client for `host:port`. A host that is not on loopback must be
    /// given a bearer, since it serves object identity to anyone who can
    /// reach it.
    pub fn new(address: &str, bearer: Option<String>) -> Result<Self, String> {
        let addr = address
            .trim()
            .to_socket_addrs()
            .map_err(|_| format!("{HOST_ENV} must be host:port"))?
            .next()
            .ok_or_else(|| format!("{HOST_ENV} did not resolve"))?;
        let bearer = bearer.filter(|bearer| !bearer.trim().is_empty());
        if !addr.ip().is_loopback() && bearer.is_none() {
            return Err(format!(
                "{HOST_ENV} on a non-loopback address requires {HOST_BEARER_ENV}"
            ));
        }
        Ok(Self { addr, bearer })
    }

    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(address) = std::env::var(HOST_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };
        Self::new(&address, std::env::var(HOST_BEARER_ENV).ok()).map(Some)
    }

    fn call(&self, mut request: Value) -> Result<Reply, String> {
        request["v"] = json!(WIRE_V);
        if let Some(bearer) = &self.bearer {
            request["token"] = json!(bearer);
        }
        let mut line = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
        line.push(b'\n');
        let unreachable = |_| "object-log host is unreachable".to_string();
        let mut stream = TcpStream::connect_timeout(&self.addr, TIMEOUT).map_err(unreachable)?;
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
        Ok(reply)
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
        Self::require_ok(self.call(json!({ "op": "ingest_batch", "records": records }))?)
            .map(|_| ())
    }

    /// The identity's current record, or `None` when the host has never
    /// committed it.
    pub fn load(&self, kind: &str, key: &str) -> Result<Option<ObjectRecord>, String> {
        let reply = self.call(json!({ "op": "load", "kind": kind, "key": key }))?;
        // The pinned host tag reports a never-committed identity only as this
        // error text; it has no structured not-found. The real-host test
        // (`two_clerk_clients_share_generations_through_one_host`) pins it,
        // so a tag bump that rewords it fails there instead of turning every
        // first admit into an error. Any other failure stays an error.
        if !reply.ok
            && reply.error.as_deref() == Some(format!("unknown identity {kind}/{key}").as_str())
        {
            return Ok(None);
        }
        let record = Self::require_ok(reply)?
            .load
            .ok_or("object-log host load returned no record")?;
        if record.kind != kind || record.key != key {
            return Err("object-log host returned a different identity".into());
        }
        Ok(Some(record))
    }

    /// Admits one object: an identity already at these properties keeps its
    /// generation; otherwise the record is appended and its committed
    /// generation read back. A committed record that does not carry the
    /// admitted properties (another writer won the race) fails closed.
    pub fn admit(&self, record: ObjectRecord) -> Result<u64, String> {
        if let Some(existing) = self.load(&record.kind, &record.key)?
            && !existing.hidden
            && existing.props == record.props
        {
            return Ok(existing.r#gen);
        }
        self.ingest_batch(std::slice::from_ref(&record))?;
        let committed = self
            .load(&record.kind, &record.key)?
            .ok_or("object-log host did not commit the admitted identity")?;
        if committed.hidden || committed.props != record.props {
            return Err("object-log host generation does not carry the admitted properties".into());
        }
        Ok(committed.r#gen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;

    fn record(key: &str, region: &str) -> ObjectRecord {
        ObjectRecord {
            r#gen: 0,
            kind: "Customer".into(),
            key: key.into(),
            hidden: false,
            action_id: None,
            props: HashMap::from([("region".into(), region.into())]),
        }
    }

    /// One real object-log host on loopback, serving until the test ends.
    fn spawn_host(bearer: Option<&str>) -> (SocketAddr, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut host = mikura_host::Host::open(&dir.path().join("objects.mikura"), 64).unwrap();
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
        let seen = second.load("Customer", "c-1").unwrap().unwrap();
        assert_eq!(seen.r#gen, generation);
        assert_eq!(seen.props["region"], "eu");
        // An identical admit from the other client keeps the generation.
        assert_eq!(second.admit(record("c-1", "eu")).unwrap(), generation);
        // A changed admit appends, and both clients see the new generation.
        let updated = second.admit(record("c-1", "us")).unwrap();
        assert!(updated > generation);
        assert_eq!(
            first.load("Customer", "c-1").unwrap().unwrap().r#gen,
            updated
        );
        assert_eq!(first.load("Customer", "missing").unwrap(), None);
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
            honest.load("Customer", "c-1").unwrap().unwrap().r#gen,
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
            "load" => r#"{"v":1,"ok":true,"load":{"gen":7,"kind":"Customer","key":"c-1","hidden":false,"props":{"region":"other"}}}"#.to_string() + "\n",
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
            "{\"v\":1,\"ok\":true,\"load\":{\"gen\":1,\"kind\":\"Other\",\"key\":\"c-1\",\"hidden\":false,\"props\":{}}}\n",
            "{\"v\":1,\"ok\":false,\"error\":\"store is poisoned\"}\n",
        ] {
            let host = spawn_scripted(move |_| reply.to_string());
            assert!(
                ObjectLogHost::new(&host.to_string(), None)
                    .unwrap()
                    .load("Customer", "c-1")
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
            host.load("Customer", "c-1")
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
}
