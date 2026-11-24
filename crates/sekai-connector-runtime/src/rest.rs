//! The `rest` connector type: one record kind from an HTTP API that
//! returns paged JSON, read as snapshot pages under the plane-owned cursor
//! and written back by admitted `external_mutate` effects.
//!
//! A page is one response. Its records are the array at `records_path`
//! (the body itself when unset); each record's id, version and display
//! name are read at `id_path`, `version_path` and `display_path`, and its
//! other top-level scalar fields become properties. The response names
//! the next page by a link or by a token, which the cursor carries. A
//! response without one ends the scan; the next sync starts a new pass
//! from the first page, and re-read records keep their ids and versions,
//! so they change nothing. The cursor numbers its pass, so a pass that
//! ends on its first page still moves the cursor.
//!
//! The parser reads untrusted bodies: a response larger than
//! [`MAX_RESPONSE_BYTES`], or a page with more records than a batch holds,
//! fails the page as invalid instead of being cut short. A next link must
//! stay on the origin of `base_url`, which the egress allowlist admitted,
//! and the client follows no redirect and no proxy, so the type connects
//! nowhere else.
//!
//! An applied change sets `writable_fields` of the record at `item_path`,
//! addressed by the record's id (the key the plane holds is
//! `{record_kind}/{id}`).
//! With `conditional_write` the write carries the decided version as
//! `If-Match` and the API refuses it once the record moved; otherwise the
//! version check is a read just before the write, as the `github` type
//! does. After a write the version has moved, so a replay finds a conflict
//! rather than writing twice.
//!
//! The credential is sent only as the configured header. No failure
//! carries a response body, and a page whose cursor would carry the
//! credential fails rather than handing it to the plane.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use reqwest::Url;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{ACCEPT, HeaderName, HeaderValue, IF_MATCH};
use reqwest::redirect::Policy;
use sekai_source_sdk::{
    ConfigValue, Connector, ConnectorFailure, MAX_SOURCE_CURSOR_BYTES,
    MAX_SOURCE_DISPLAY_NAME_BYTES, MAX_SOURCE_IDENTIFIER_BYTES, MAX_SOURCE_PROPERTY_KEY_BYTES,
    MAX_SOURCE_PROPERTY_VALUE_BYTES, MAX_SOURCE_RECORD_PROPERTIES, PropertyValue, RecordChange,
    SnapshotPage, SnapshotRead, SourceRecord, column_name_suggests_sensitive,
    contains_secret_like_text,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::sync::Prepared;

/// The largest response body the type parses.
pub const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// Headers the credential may not be sent as: they steer the request.
const RESERVED_HEADERS: [&str; 7] = [
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "if-match",
    "idempotency-key",
];

/// One record kind of one API, reached with the Source's bound credential.
pub struct Rest {
    http: Client,
    base: Url,
    base_url: String,
    list_path: String,
    check_path: String,
    records_path: Option<String>,
    paging: Paging,
    id_path: String,
    version_path: String,
    display_path: Option<String>,
    record_kind: String,
    item_path: Option<String>,
    writable: Vec<String>,
    conditional_write: bool,
    auth_header: HeaderName,
    auth_value: HeaderValue,
    /// The bare credential, only to refuse a cursor that would carry it.
    secret: String,
}

/// How a response names the next page.
enum Paging {
    /// A JSON Pointer to a link, absolute or relative to the request.
    Link(String),
    /// A JSON Pointer to a token, sent as this query parameter.
    Token { path: String, param: String },
}

/// Opens the `rest` type for a prepared Source; register it with
/// `Connectors::with(&REST_CONNECTOR, rest::open)`.
pub fn open(prepared: &Prepared) -> Result<Box<dyn Connector + Send>, ConnectorFailure> {
    Ok(Box::new(open_rest(prepared)?))
}

fn open_rest(prepared: &Prepared) -> Result<Rest, ConnectorFailure> {
    let text = |name: &str| match prepared.config.get(name) {
        Some(ConfigValue::Text(text)) => Some(text.clone()),
        _ => None,
    };
    let required = |name: &str| text(name).ok_or(ConnectorFailure::Invalid);
    let base_url = required("base_url")?;
    let base = Url::parse(&base_url).map_err(|_| ConnectorFailure::Invalid)?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err(ConnectorFailure::Invalid);
    }
    let request_path = |name: &str| {
        text(name)
            .map(|path| {
                if path.starts_with('/') {
                    Ok(path)
                } else {
                    Err(ConnectorFailure::Invalid)
                }
            })
            .transpose()
    };
    let pointer = request_path;
    let list_path = request_path("list_path")?.ok_or(ConnectorFailure::Invalid)?;
    let paging = match (
        pointer("next_link_path")?,
        pointer("next_cursor_path")?,
        text("next_cursor_param"),
    ) {
        (Some(path), None, None) => Paging::Link(path),
        (None, Some(path), Some(param)) => Paging::Token { path, param },
        _ => return Err(ConnectorFailure::Invalid),
    };
    let item_path = request_path("item_path")?;
    if item_path
        .as_ref()
        .is_some_and(|path| !path.contains("{id}"))
    {
        return Err(ConnectorFailure::Invalid);
    }
    let writable = text("writable_fields")
        .map(|fields| {
            fields
                .split(',')
                .map(|field| field.trim().to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if writable.iter().any(String::is_empty) {
        return Err(ConnectorFailure::Invalid);
    }
    let auth_header = HeaderName::from_bytes(
        text("auth_header")
            .unwrap_or_else(|| "authorization".into())
            .as_bytes(),
    )
    .map_err(|_| ConnectorFailure::Invalid)?;
    if RESERVED_HEADERS.contains(&auth_header.as_str()) {
        return Err(ConnectorFailure::Invalid);
    }
    let secret = prepared
        .credentials
        .get("token")
        .ok_or(ConnectorFailure::AuthFailed)?
        .expose()
        .to_string();
    let value = match text("auth_scheme") {
        Some(scheme) => format!("{scheme} {secret}"),
        None => secret.clone(),
    };
    let mut auth_value = HeaderValue::from_str(&value).map_err(|_| ConnectorFailure::AuthFailed)?;
    auth_value.set_sensitive(true);
    let http = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .user_agent("sekai-connector-runtime")
        .build()
        .map_err(|_| ConnectorFailure::Invalid)?;
    Ok(Rest {
        http,
        base,
        base_url: base_url.trim_end_matches('/').to_string(),
        check_path: request_path("check_path")?.unwrap_or_else(|| list_path.clone()),
        list_path,
        records_path: pointer("records_path")?,
        paging,
        id_path: pointer("id_path")?.ok_or(ConnectorFailure::Invalid)?,
        version_path: pointer("version_path")?.ok_or(ConnectorFailure::Invalid)?,
        display_path: pointer("display_path")?,
        record_kind: required("record_kind")?,
        item_path,
        writable,
        conditional_write: matches!(
            prepared.config.get("conditional_write"),
            Some(ConfigValue::Boolean(true))
        ),
        auth_header,
        auth_value,
        secret,
    })
}

impl Rest {
    fn url(&self, path: &str) -> Result<Url, ConnectorFailure> {
        self.same_origin(
            Url::parse(&format!("{}{path}", self.base_url))
                .map_err(|_| ConnectorFailure::Invalid)?,
        )
    }

    /// `url` when it is on the origin of `base_url`, which egress admitted.
    fn same_origin(&self, url: Url) -> Result<Url, ConnectorFailure> {
        let same = url.scheme() == self.base.scheme()
            && url.host_str() == self.base.host_str()
            && url.port_or_known_default() == self.base.port_or_known_default()
            && url.username().is_empty()
            && url.password().is_none();
        if same {
            Ok(url)
        } else {
            Err(ConnectorFailure::Invalid)
        }
    }

    fn send(&self, request: RequestBuilder) -> Result<Response, ConnectorFailure> {
        let response = request
            .header(self.auth_header.clone(), self.auth_value.clone())
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| ConnectorFailure::Unreachable)?;
        match response.status().as_u16() {
            200..=299 => Ok(response),
            401 => Err(ConnectorFailure::AuthFailed),
            403 | 404 => Err(ConnectorFailure::PermissionMissing),
            409 | 412 => Err(ConnectorFailure::Conflict),
            408 | 429 | 500..=599 => Err(ConnectorFailure::Unreachable),
            _ => Err(ConnectorFailure::Invalid),
        }
    }

    fn get_json(&self, url: Url) -> Result<Value, ConnectorFailure> {
        json_body(self.send(self.http.get(url))?).ok_or(ConnectorFailure::Invalid)
    }

    /// The URL of the page `next` names, from the first page when `None`.
    fn page_url(&self, next: Option<&Next>) -> Result<Url, ConnectorFailure> {
        let first = self.url(&self.list_path)?;
        match next {
            None => Ok(first),
            Some(Next::Link(link)) => {
                self.same_origin(first.join(link).map_err(|_| ConnectorFailure::Invalid)?)
            }
            Some(Next::Token(token)) => {
                let Paging::Token { param, .. } = &self.paging else {
                    return Err(ConnectorFailure::Invalid);
                };
                let mut url = first;
                url.query_pairs_mut().append_pair(param, token);
                Ok(url)
            }
        }
    }

    /// What the page `body` names as the next one, if anything.
    fn next_of(&self, body: &Value) -> Result<Option<Next>, ConnectorFailure> {
        let (path, link) = match &self.paging {
            Paging::Link(path) => (path, true),
            Paging::Token { path, .. } => (path, false),
        };
        let value = match body.pointer(path) {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::String(text)) if text.is_empty() => return Ok(None),
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) if !link => number.to_string(),
            Some(_) => return Err(ConnectorFailure::Invalid),
        };
        Ok(Some(if link {
            Next::Link(value)
        } else {
            Next::Token(value)
        }))
    }

    fn record(&self, item: &Value, observed_at_ms: i64) -> Result<SourceRecord, ConnectorFailure> {
        let object = item.as_object().ok_or(ConnectorFailure::Invalid)?;
        let external_id = scalar(item.pointer(&self.id_path)).ok_or(ConnectorFailure::Invalid)?;
        let version = scalar(item.pointer(&self.version_path)).ok_or(ConnectorFailure::Invalid)?;
        // Ids are registered tokens: the plane keys a record as
        // `{record_kind}/{id}`, so an id may not carry `/`, `#` or `:`.
        if !self.carried(&external_id, MAX_SOURCE_IDENTIFIER_BYTES)
            || external_id.trim() != external_id
            || external_id.contains(['/', '#', ':'])
            || !self.carried(&version, MAX_SOURCE_IDENTIFIER_BYTES)
        {
            return Err(ConnectorFailure::Invalid);
        }
        let mut properties = BTreeMap::new();
        for (key, value) in object {
            if properties.len() == MAX_SOURCE_RECORD_PROPERTIES {
                break;
            }
            if !property_key(key) {
                continue;
            }
            let value = match value {
                Value::Bool(flag) => PropertyValue::Bool(*flag),
                Value::Number(number) => match number.as_i64() {
                    Some(int) => PropertyValue::Int(int),
                    None => match number.as_f64().filter(|float| float.is_finite()) {
                        Some(float) => PropertyValue::Float(float),
                        None => continue,
                    },
                },
                Value::String(text) if self.carried(text, MAX_SOURCE_PROPERTY_VALUE_BYTES) => {
                    PropertyValue::String(text.clone())
                }
                _ => continue,
            };
            properties.insert(key.clone(), value);
        }
        let display_name = self
            .display_path
            .as_deref()
            .and_then(|path| scalar(item.pointer(path)))
            .map(|name| display_line(&name))
            .filter(|name| !name.is_empty() && self.carried(name, MAX_SOURCE_DISPLAY_NAME_BYTES))
            .unwrap_or_else(|| display_line(&external_id));
        Ok(SourceRecord {
            source: String::new(),
            source_instance: String::new(),
            external_id,
            source_version: version,
            type_name: self.record_kind.clone(),
            display_name,
            payload_digest: digest_of(&properties),
            properties,
            deleted: false,
            observed_at_ms,
            source_sequence: None,
            payload: None,
        })
    }

    /// Whether `text` may go to the plane: bounded, one line, and carrying
    /// neither the credential nor anything that looks like one.
    fn carried(&self, text: &str, max_bytes: usize) -> bool {
        !text.is_empty()
            && text.len() <= max_bytes
            && !text.chars().any(char::is_control)
            && !text.contains(self.secret.as_str())
            && !contains_secret_like_text(text)
    }

    fn item_url(&self, key: &str) -> Result<Url, ConnectorFailure> {
        let path = self
            .item_path
            .as_ref()
            .ok_or(ConnectorFailure::Unsupported)?;
        self.url(&path.replace("{id}", &percent_encode(key)))
    }

    fn version_of(&self, body: &Value) -> Option<String> {
        scalar(body.pointer(&self.version_path)).filter(|version| !version.is_empty())
    }
}

impl Connector for Rest {
    fn check(&mut self) -> Result<(), ConnectorFailure> {
        let url = self.url(&self.check_path)?;
        self.send(self.http.get(url)).map(|_| ())
    }

    fn read_page(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<SnapshotRead, ConnectorFailure> {
        // A finished pass, or a cursor this type did not write, starts a
        // new pass from the first page.
        let cursor = match committed_cursor.and_then(Cursor::parse) {
            Some(Cursor {
                pass,
                next: Some(next),
            }) => Cursor {
                pass,
                next: Some(next),
            },
            Some(Cursor { pass, next: None }) => Cursor {
                pass: pass.wrapping_add(1),
                next: None,
            },
            None => Cursor::default(),
        };
        let body = self.get_json(self.page_url(cursor.next.as_ref())?)?;
        let items = match &self.records_path {
            Some(path) => body.pointer(path),
            None => Some(&body),
        }
        .and_then(Value::as_array)
        .ok_or(ConnectorFailure::Invalid)?;
        if items.len() > max_records {
            return Err(ConnectorFailure::Invalid);
        }
        let next = self.next_of(&body)?;
        let complete = next.is_none();
        let proposed = Cursor {
            pass: cursor.pass,
            next,
        }
        .to_string();
        if proposed.len() > MAX_SOURCE_CURSOR_BYTES || !self.carried(&proposed, usize::MAX) {
            return Err(ConnectorFailure::Invalid);
        }
        let observed_at_ms = now_ms();
        let records = items
            .iter()
            .map(|item| self.record(item, observed_at_ms))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SnapshotRead::Page(SnapshotPage {
            records,
            proposed_next_cursor: proposed,
            collected_at_ms: observed_at_ms,
            complete,
        }))
    }

    fn apply(&mut self, change: &RecordChange) -> Result<String, ConnectorFailure> {
        // The record's key as the plane holds it is `{record_kind}/{id}`.
        let key = change
            .key
            .strip_prefix(&format!("{}/", self.record_kind))
            .unwrap_or(&change.key);
        if key.is_empty()
            || change.change.is_empty()
            || change
                .change
                .keys()
                .any(|field| !self.writable.contains(field))
        {
            return Err(ConnectorFailure::Invalid);
        }
        let url = self.item_url(key)?;
        let mut write = self
            .http
            .patch(url.clone())
            .header("idempotency-key", &change.idempotency_key)
            .json(&change.change);
        if self.conditional_write {
            let version = HeaderValue::from_str(&change.expected_version)
                .map_err(|_| ConnectorFailure::Invalid)?;
            write = write.header(IF_MATCH, version);
        } else {
            let current = self.get_json(url)?;
            if self.version_of(&current).as_deref() != Some(change.expected_version.as_str()) {
                return Err(ConnectorFailure::Conflict);
            }
        }
        json_body(self.send(write)?)
            .and_then(|body| self.version_of(&body))
            // The write was accepted; only its reply is lost.
            .ok_or(ConnectorFailure::Unreachable)
    }
}

/// The body of `response` as JSON, if it is JSON within the bound.
fn json_body(response: Response) -> Option<Value> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return None;
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// A string or number as text; anything else is not an id or version.
fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// A field name the plane holds as a property: normalized, and not one
/// that suggests a credential or personal data.
fn property_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_SOURCE_PROPERTY_KEY_BYTES
        && key.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-' | '.')
        })
        && !column_name_suggests_sensitive(key)
        && !["credential", "authorization", "api_key", "private_key"]
            .iter()
            .any(|hint| key.replace('-', "_").contains(hint))
}

/// `text` on one line within the display limit.
fn display_line(text: &str) -> String {
    let mut line: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    while line.len() > MAX_SOURCE_DISPLAY_NAME_BYTES {
        line.pop();
    }
    line.trim().to_string()
}

fn digest_of(properties: &BTreeMap<String, PropertyValue>) -> String {
    let cells: BTreeMap<&str, String> = properties
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_cell()))
        .collect();
    let canonical = serde_json::to_vec(&cells).unwrap_or_else(|_| b"{}".to_vec());
    format!("sha256:{:x}", Sha256::digest(canonical))
}

/// `key` as one path segment: unreserved bytes as they are, others escaped.
fn percent_encode(key: &str) -> String {
    key.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// The page a response named as next.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Next {
    Link(String),
    Token(String),
}

/// Where a scan stands: its pass, and the page it reads next (`None` once
/// the pass has read its last page).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Cursor {
    pass: u64,
    next: Option<Next>,
}

impl Cursor {
    const PREFIX: &str = "rest-v1";

    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.splitn(4, '|');
        if parts.next()? != Self::PREFIX {
            return None;
        }
        let pass = parts.next()?.parse().ok()?;
        let next = match (parts.next()?, parts.next()) {
            ("done", None) => None,
            ("link", Some(link)) if !link.is_empty() => Some(Next::Link(link.into())),
            ("token", Some(token)) if !token.is_empty() => Some(Next::Token(token.into())),
            _ => return None,
        };
        Some(Self { pass, next })
    }
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = Self::PREFIX;
        match &self.next {
            None => write!(formatter, "{prefix}|{}|done", self.pass),
            Some(Next::Link(link)) => write!(formatter, "{prefix}|{}|link|{link}", self.pass),
            Some(Next::Token(token)) => write!(formatter, "{prefix}|{}|token|{token}", self.pass),
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Secret;
    use sekai_source_sdk::{REST_CONNECTOR, SourceConfig};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// One request a fake API saw.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: String,
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    /// Serves `respond(request) -> (status, body)` on an ephemeral port.
    fn fake_api(respond: impl Fn(&Seen) -> (u16, String) + Send + 'static) -> (String, Log) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log = Log::default();
        let seen = log.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut headers = BTreeMap::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let Some((name, value)) = line.trim_end().split_once(": ") else {
                        break;
                    };
                    headers.insert(name.to_ascii_lowercase(), value.to_string());
                }
                let length = headers
                    .get("content-length")
                    .and_then(|length| length.parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let mut parts = request_line.split(' ');
                let request = Seen {
                    method: parts.next().unwrap_or_default().into(),
                    path: parts.next().unwrap_or_default().into(),
                    headers,
                    body: String::from_utf8(body).unwrap(),
                };
                let (status, body) = respond(&request);
                seen.lock().unwrap().push(request);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (url, log)
    }

    fn config(base_url: &str, extra: &[(&str, ConfigValue)]) -> SourceConfig {
        let mut config = SourceConfig::from([
            ("base_url".into(), ConfigValue::Text(base_url.into())),
            (
                "list_path".into(),
                ConfigValue::Text("/tickets?limit=2".into()),
            ),
            ("records_path".into(), ConfigValue::Text("/data".into())),
            (
                "next_link_path".into(),
                ConfigValue::Text("/links/next".into()),
            ),
            ("id_path".into(), ConfigValue::Text("/id".into())),
            ("version_path".into(), ConfigValue::Text("/rev".into())),
            ("display_path".into(), ConfigValue::Text("/title".into())),
            ("record_kind".into(), ConfigValue::Text("Ticket".into())),
            (
                "type_digest".into(),
                ConfigValue::Text("sha256:tickets".into()),
            ),
            (
                "item_path".into(),
                ConfigValue::Text("/tickets/{id}".into()),
            ),
            (
                "writable_fields".into(),
                ConfigValue::Text("status,title".into()),
            ),
            ("auth_scheme".into(), ConfigValue::Text("Bearer".into())),
        ]);
        for (name, value) in extra {
            config.insert((*name).into(), value.clone());
        }
        config
    }

    fn connect(config: SourceConfig) -> Result<Rest, ConnectorFailure> {
        REST_CONNECTOR.validate_config(&config).unwrap();
        open_rest(&Prepared {
            connector: &REST_CONNECTOR,
            source_instance: "tickets".into(),
            config,
            credentials: BTreeMap::from([("token".into(), Secret("s3cr3t-value".into()))]),
        })
    }

    fn ticket(id: u64, rev: &str) -> Value {
        serde_json::json!({"id": id, "rev": rev, "title": format!("ticket {id}"), "status": "open"})
    }

    fn page(read: SnapshotRead) -> SnapshotPage {
        match read {
            SnapshotRead::Page(page) => page,
            SnapshotRead::Complete => panic!("a page"),
        }
    }

    /// Three tickets, two per page, linked by relative next links.
    fn linked(request: &Seen) -> (u16, String) {
        let body = if request.path.contains("after=2") {
            serde_json::json!({"data": [ticket(3, "c")], "links": {"next": null}})
        } else {
            serde_json::json!({
                "data": [ticket(1, "a"), ticket(2, "b")],
                "links": {"next": "/tickets?limit=2&after=2"},
            })
        };
        (200, body.to_string())
    }

    #[test]
    fn a_scan_follows_next_links_to_the_end_and_resumes_from_the_cursor() {
        let (url, log) = fake_api(linked);
        let mut rest = connect(config(&url, &[])).unwrap();
        let first = page(rest.read_page(None, 500).unwrap());
        assert_eq!(
            first
                .records
                .iter()
                .map(|record| (record.external_id.as_str(), record.source_version.as_str()))
                .collect::<Vec<_>>(),
            [("1", "a"), ("2", "b")]
        );
        assert_eq!(first.records[0].display_name, "ticket 1");
        assert_eq!(first.records[0].type_name, "Ticket");
        assert!(!first.complete);

        // Another runtime resumes from the committed cursor.
        let mut other = connect(config(&url, &[])).unwrap();
        let last = page(
            other
                .read_page(Some(&first.proposed_next_cursor), 500)
                .unwrap(),
        );
        assert_eq!(last.records[0].external_id, "3");
        assert!(last.complete);
        assert_eq!(log.lock().unwrap()[1].path, "/tickets?limit=2&after=2");

        // The next sync starts a new pass, under a cursor of its own.
        let again = page(
            other
                .read_page(Some(&last.proposed_next_cursor), 500)
                .unwrap(),
        );
        assert_eq!(again.records.len(), 2);
        assert_ne!(again.proposed_next_cursor, first.proposed_next_cursor);
        assert_eq!(log.lock().unwrap()[2].path, "/tickets?limit=2");

        // The credential goes only in the configured header.
        let seen = log.lock().unwrap();
        assert!(seen.iter().all(|request| {
            request.headers.get("authorization").map(String::as_str) == Some("Bearer s3cr3t-value")
        }));
    }

    #[test]
    fn a_scan_pages_by_token_in_a_query_parameter() {
        let (url, log) = fake_api(|request| {
            let body = if request.path.contains("page_token=t%2B2") {
                serde_json::json!([ticket(3, "c")])
            } else {
                serde_json::json!([ticket(1, "a")])
            };
            (200, body.to_string())
        });
        let mut config = config(
            &url,
            &[
                ("next_cursor_path", ConfigValue::Text("/next".into())),
                ("next_cursor_param", ConfigValue::Text("page_token".into())),
            ],
        );
        config.remove("next_link_path");
        config.remove("records_path");
        let mut rest = connect(config).unwrap();
        // A body that is the array has no next token: one page ends the pass.
        let only = page(rest.read_page(None, 500).unwrap());
        assert!(only.complete);
        let cursor = Cursor {
            pass: 4,
            next: Some(Next::Token("t+2".into())),
        }
        .to_string();
        let next = page(rest.read_page(Some(&cursor), 500).unwrap());
        assert_eq!(next.records[0].external_id, "3");
        assert_eq!(
            log.lock().unwrap()[1].path,
            "/tickets?limit=2&page_token=t%2B2"
        );
    }

    #[test]
    fn a_next_link_off_the_admitted_origin_is_refused() {
        for next in [
            "http://elsewhere.example/tickets",
            "//elsewhere.example/tickets",
            "http://user@127.0.0.1/tickets",
        ] {
            let body = serde_json::json!({"data": [ticket(1, "a")], "links": {"next": next}});
            let (url, _) = fake_api(move |_| (200, body.to_string()));
            let mut rest = connect(config(&url, &[])).unwrap();
            let read = page(rest.read_page(None, 500).unwrap());
            assert_eq!(
                rest.read_page(Some(&read.proposed_next_cursor), 500),
                Err(ConnectorFailure::Invalid),
                "{next}"
            );
        }
    }

    #[test]
    fn untrusted_bodies_are_bounded() {
        // More records than a batch holds.
        let (url, _) = fake_api(|_| {
            let body =
                serde_json::json!({"data": [ticket(1, "a"), ticket(2, "b"), ticket(3, "c")]});
            (200, body.to_string())
        });
        assert_eq!(
            connect(config(&url, &[])).unwrap().read_page(None, 2),
            Err(ConnectorFailure::Invalid)
        );
        // A body over the size bound.
        let (url, _) = fake_api(|_| {
            let filler = "x".repeat(usize::try_from(MAX_RESPONSE_BYTES).unwrap());
            (200, format!(r#"{{"data":[],"pad":"{filler}"}}"#))
        });
        assert_eq!(
            connect(config(&url, &[])).unwrap().read_page(None, 500),
            Err(ConnectorFailure::Invalid)
        );
        // Not JSON, a record without an id, and an id the plane cannot key.
        for body in [
            "<html>",
            r#"{"data":[{"rev":"a"}]}"#,
            r#"{"data":[{"id":"a/b","rev":"a"}]}"#,
        ] {
            let (url, _) = fake_api(move |_| (200, body.into()));
            assert_eq!(
                connect(config(&url, &[])).unwrap().read_page(None, 500),
                Err(ConnectorFailure::Invalid)
            );
        }
    }

    #[test]
    fn nothing_credential_like_reaches_the_plane() {
        let (url, _) = fake_api(|_| {
            let body = serde_json::json!({
                "data": [{
                    "id": 1, "rev": "a", "title": "ok", "status": "open",
                    "api_token": "x", "email": "a@example.com", "note": "s3cr3t-value",
                    "Mixed": "case", "nested": {"a": 1}, "count": 3,
                }],
                "links": {"next": "/tickets?access_token=s3cr3t-value"},
            });
            (200, body.to_string())
        });
        assert_eq!(
            connect(config(&url, &[])).unwrap().read_page(None, 500),
            Err(ConnectorFailure::Invalid)
        );
        let (url, _) = fake_api(|_| {
            let body = serde_json::json!({
                "data": [{
                    "id": 1, "rev": "a", "title": "password=hunter2", "status": "open",
                    "api_token": "x", "email": "a@example.com", "note": "s3cr3t-value",
                    "Mixed": "case", "nested": {"a": 1}, "count": 3,
                }],
            });
            (200, body.to_string())
        });
        let read = page(
            connect(config(&url, &[]))
                .unwrap()
                .read_page(None, 500)
                .unwrap(),
        );
        let record = &read.records[0];
        // Secret-named, personal, unnormalized, nested, secret-like and
        // credential-carrying fields are left out.
        assert_eq!(
            record
                .properties
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["count", "id", "rev", "status"]
        );
        assert_eq!(record.display_name, "1");
    }

    #[test]
    fn check_proves_the_url_answers_and_the_credential_is_accepted() {
        let (url, log) = fake_api(|_| (200, "{}".into()));
        let mut keyed = config(
            &url,
            &[
                ("check_path", ConfigValue::Text("/me".into())),
                ("auth_header", ConfigValue::Text("x-api-key".into())),
            ],
        );
        keyed.remove("auth_scheme");
        let mut ping = connect(keyed).unwrap();
        assert_eq!(ping.check(), Ok(()));
        let seen = log.lock().unwrap()[0].clone();
        assert_eq!(seen.path, "/me");
        assert_eq!(seen.headers["x-api-key"], "s3cr3t-value");
        for (status, failure) in [
            (401, ConnectorFailure::AuthFailed),
            (403, ConnectorFailure::PermissionMissing),
            (503, ConnectorFailure::Unreachable),
            (302, ConnectorFailure::Invalid),
        ] {
            let (url, _) = fake_api(move |_| (status, "{\"error\":\"s3cr3t-value\"}".into()));
            let failure_text = connect(config(&url, &[])).unwrap().check().unwrap_err();
            assert_eq!(failure_text, failure, "{status}");
            assert!(!failure_text.to_string().contains("s3cr3t"));
        }
    }

    #[test]
    fn a_configuration_that_would_misroute_the_credential_is_refused() {
        for extra in [
            ("auth_header", ConfigValue::Text("host".into())),
            ("list_path", ConfigValue::Text("tickets".into())),
            ("item_path", ConfigValue::Text("/tickets".into())),
            ("next_cursor_path", ConfigValue::Text("/next".into())),
        ] {
            let name = extra.0;
            assert_eq!(
                connect(config("http://127.0.0.1:9", &[extra])).err(),
                Some(ConnectorFailure::Invalid),
                "{name}"
            );
        }
    }

    fn change(version: &str) -> RecordChange {
        RecordChange {
            idempotency_key: "effect-1".into(),
            key: "Ticket/a 7".into(),
            expected_version: version.into(),
            change: BTreeMap::from([("status".to_string(), "closed".to_string())]),
        }
    }

    #[test]
    fn a_change_is_written_only_while_the_record_has_the_decided_version() {
        let (url, log) = fake_api(|request| {
            let rev = if request.method == "PATCH" { "b" } else { "a" };
            (200, ticket(7, rev).to_string())
        });
        let mut rest_type = connect(config(&url, &[])).unwrap();
        assert_eq!(rest_type.apply(&change("a")), Ok("b".into()));
        {
            let seen = log.lock().unwrap();
            assert_eq!(
                seen.iter()
                    .map(|request| (request.method.as_str(), request.path.as_str()))
                    .collect::<Vec<_>>(),
                [("GET", "/tickets/a%207"), ("PATCH", "/tickets/a%207")]
            );
            assert_eq!(seen[1].body, r#"{"status":"closed"}"#);
            assert_eq!(seen[1].headers["idempotency-key"], "effect-1");
        }

        // A moved record is a conflict, and nothing is written.
        let (url, log) = fake_api(|_| (200, ticket(7, "z").to_string()));
        let mut moved = connect(config(&url, &[])).unwrap();
        assert_eq!(moved.apply(&change("a")), Err(ConnectorFailure::Conflict));
        // Only writable fields.
        let mut other = change("z");
        other.change = BTreeMap::from([("owner".to_string(), "x".to_string())]);
        assert_eq!(moved.apply(&other), Err(ConnectorFailure::Invalid));
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .all(|request| request.method == "GET")
        );
    }

    #[test]
    fn a_conditional_write_carries_the_decided_version() {
        let (url, log) = fake_api(|request| match request.headers.get("if-match") {
            Some(version) if version == "a" => (200, ticket(7, "b").to_string()),
            _ => (412, "{}".into()),
        });
        let mut rest = connect(config(
            &url,
            &[("conditional_write", ConfigValue::Boolean(true))],
        ))
        .unwrap();
        assert_eq!(rest.apply(&change("a")), Ok("b".into()));
        assert_eq!(rest.apply(&change("z")), Err(ConnectorFailure::Conflict));
        let seen = log.lock().unwrap();
        assert!(seen.iter().all(|request| request.method == "PATCH"));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn cursors_round_trip_and_foreign_ones_restart() {
        for cursor in [
            Cursor::default(),
            Cursor {
                pass: 3,
                next: Some(Next::Link("/x?a=1|2".into())),
            },
            Cursor {
                pass: 9,
                next: Some(Next::Token("t".into())),
            },
        ] {
            assert_eq!(Cursor::parse(&cursor.to_string()), Some(cursor));
        }
        for foreign in ["github-v1||1|open|0", "rest-v1|x|done", "rest-v1|1|link|"] {
            assert_eq!(Cursor::parse(foreign), None, "{foreign}");
        }
    }
}
