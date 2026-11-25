//! A blocking client for the part of the S3-compatible API the
//! `object_storage` type reads: a prefix listing in key order and a
//! size-capped object download, each signed with Signature Version 4.
//!
//! The client follows no redirect and no proxy, so it reaches only the
//! origin the egress allowlist admitted. Response bodies are read up to a
//! cap and never surface in a failure.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use hmac::{Hmac, Mac};
use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use sekai_source_sdk::ConnectorFailure;
use sha2::{Digest, Sha256};

use crate::credentials::Secret;
use crate::rest::now_ms;

/// The largest listing response the client parses.
pub const MAX_LISTING_BYTES: u64 = 8 * 1024 * 1024;

/// One object a listing returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub key: String,
    /// The ETag without its quotes.
    pub etag: String,
}

/// One page of a prefix listing, in UTF-8 byte order of key.
#[derive(Debug, Default)]
pub struct ListPage {
    pub objects: Vec<Listed>,
    /// The token for the next page; `None` when the listing is done.
    pub next: Option<String>,
}

/// One bucket of one store, reached with an access key pair.
pub struct Store {
    http: Client,
    /// The origin requests go to, with the bucket as a subdomain unless
    /// the store is addressed path-style.
    origin: Url,
    /// The path every request starts with: `/{bucket}` path-style, else empty.
    base_path: String,
    region: String,
    access_key_id: String,
    secret_key: Secret,
}

impl Store {
    pub fn new(
        origin: Url,
        base_path: String,
        region: String,
        access_key_id: String,
        secret_key: Secret,
    ) -> Result<Self, ConnectorFailure> {
        let http = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(60))
            .user_agent("sekai-connector-runtime")
            .build()
            .map_err(|_| ConnectorFailure::Invalid)?;
        Ok(Self {
            http,
            origin,
            base_path,
            region,
            access_key_id,
            secret_key,
        })
    }

    /// One listing page of the keys under `prefix`, after `start_after`
    /// or at `token`, at most `max_keys` of them.
    pub fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        token: Option<&str>,
        max_keys: usize,
    ) -> Result<ListPage, ConnectorFailure> {
        let max_keys = max_keys.to_string();
        let mut query = vec![
            ("list-type", "2"),
            ("max-keys", max_keys.as_str()),
            ("prefix", prefix),
        ];
        if let Some(token) = token {
            query.push(("continuation-token", token));
        } else if let Some(after) = start_after {
            query.push(("start-after", after));
        }
        let path = format!("{}/", self.base_path);
        let response = self.get(&path, &query)?;
        let body = read_capped(response, MAX_LISTING_BYTES)?;
        let xml = std::str::from_utf8(&body).map_err(|_| ConnectorFailure::Invalid)?;
        parse_listing(xml)
    }

    /// The bytes of the object at `key`, at most `cap` of them, and the
    /// ETag the store served them at.
    pub fn get_object(&self, key: &str, cap: u64) -> Result<(Vec<u8>, String), ConnectorFailure> {
        let response = self.get(&format!("{}/{key}", self.base_path), &[])?;
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(unquote)
            .ok_or(ConnectorFailure::Invalid)?;
        Ok((read_capped(response, cap)?, etag))
    }

    /// A signed GET; a refusal is mapped to its typed reason.
    fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<Response, ConnectorFailure> {
        self.send(reqwest::Method::GET, path, query, Vec::new())
    }

    /// A signed PUT of `body` at `path` (`/` alone for the bucket), for
    /// tests that prepare a real store.
    #[cfg(test)]
    pub(super) fn put(&self, path: &str, body: Vec<u8>) -> Result<(), ConnectorFailure> {
        self.send(
            reqwest::Method::PUT,
            &format!("{}{path}", self.base_path),
            &[],
            body,
        )
        .map(|_| ())
    }

    /// A signed DELETE of the object at `path`, for tests that prepare a
    /// real store.
    #[cfg(test)]
    pub(super) fn delete(&self, path: &str) -> Result<(), ConnectorFailure> {
        self.send(
            reqwest::Method::DELETE,
            &format!("{}{path}", self.base_path),
            &[],
            Vec::new(),
        )
        .map(|_| ())
    }

    fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<Response, ConnectorFailure> {
        let mut url = self.origin.clone();
        url.set_path(&uri_encode(path, true));
        let canonical = canonical_query(query);
        url.set_query((!canonical.is_empty()).then_some(canonical.as_str()));
        let host = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        let amz_date = amz_date(now_ms());
        let payload_sha256 = format!("{:x}", Sha256::digest(&body));
        let authorization = sign(&Signing {
            method: method.as_str(),
            path,
            query,
            host: &host,
            payload_sha256: &payload_sha256,
            amz_date: &amz_date,
            region: &self.region,
            access_key_id: &self.access_key_id,
            secret_key: self.secret_key.expose(),
        });
        let response = self
            .http
            .request(method, url)
            .header("authorization", authorization)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", payload_sha256)
            .body(body)
            .send()
            .map_err(|_| ConnectorFailure::Unreachable)?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        if status.is_server_error() {
            return Err(ConnectorFailure::Unreachable);
        }
        // The error code names the reason; the body is never passed on.
        let code = read_capped(response, 64 * 1024)
            .ok()
            .and_then(|body| {
                let xml = String::from_utf8(body).ok()?;
                elements(&xml, "Code").next().map(unescape)
            })
            .unwrap_or_default();
        Err(refusal(status.as_u16(), &code))
    }
}

/// The typed reason a store refused a request for.
fn refusal(status: u16, code: &str) -> ConnectorFailure {
    match code {
        "InvalidAccessKeyId"
        | "SignatureDoesNotMatch"
        | "AuthorizationHeaderMalformed"
        | "ExpiredToken"
        | "InvalidToken" => ConnectorFailure::AuthFailed,
        "AccessDenied" | "AllAccessDisabled" => ConnectorFailure::PermissionMissing,
        _ if status == 401 => ConnectorFailure::AuthFailed,
        _ if status == 403 => ConnectorFailure::PermissionMissing,
        _ => ConnectorFailure::Invalid,
    }
}

/// The body of `response`, refused when it is larger than `cap`.
fn read_capped(response: Response, cap: u64) -> Result<Vec<u8>, ConnectorFailure> {
    if response.content_length().is_some_and(|length| length > cap) {
        return Err(ConnectorFailure::Invalid);
    }
    let mut bytes = Vec::new();
    response
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConnectorFailure::Unreachable)?;
    if bytes.len() as u64 > cap {
        return Err(ConnectorFailure::Invalid);
    }
    Ok(bytes)
}

fn unquote(etag: &str) -> String {
    etag.trim().trim_matches('"').to_string()
}

/// The objects of a `ListObjectsV2` response. A truncated page without a
/// continuation token is refused rather than read as the end.
fn parse_listing(xml: &str) -> Result<ListPage, ConnectorFailure> {
    let objects = elements(xml, "Contents")
        .map(|block| {
            let field = |name: &str| elements(block, name).next().map(unescape);
            Ok(Listed {
                key: field("Key")
                    .filter(|key| !key.is_empty())
                    .ok_or(ConnectorFailure::Invalid)?,
                etag: field("ETag")
                    .map(|etag| unquote(&etag))
                    .filter(|etag| !etag.is_empty())
                    .ok_or(ConnectorFailure::Invalid)?,
            })
        })
        .collect::<Result<Vec<_>, ConnectorFailure>>()?;
    let truncated = elements(xml, "IsTruncated").next() == Some("true");
    let next = elements(xml, "NextContinuationToken")
        .next()
        .map(unescape)
        .filter(|token| !token.is_empty());
    if truncated && next.is_none() {
        return Err(ConnectorFailure::Invalid);
    }
    Ok(ListPage {
        objects,
        next: next.filter(|_| truncated),
    })
}

/// The contents of each `<tag>…</tag>` in `xml`, in document order.
fn elements<'a>(xml: &'a str, tag: &str) -> impl Iterator<Item = &'a str> + use<'a> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut rest = xml;
    std::iter::from_fn(move || {
        let start = rest.find(&open)? + open.len();
        let end = rest[start..].find(&close)? + start;
        let inner = &rest[start..end];
        rest = &rest[end + close.len()..];
        Some(inner)
    })
}

/// XML text with its entities resolved: the five named ones and numeric
/// character references. An unknown entity stays literal.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let resolved = rest.find(';').and_then(|end| {
            let entity = &rest[1..end];
            let character = match entity {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "amp" => Some('&'),
                _ => entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .map(|hex| u32::from_str_radix(hex, 16))
                    .or_else(|| entity.strip_prefix('#').map(str::parse::<u32>))
                    .and_then(Result::ok)
                    .and_then(char::from_u32),
            };
            character.map(|character| (character, end))
        });
        match resolved {
            Some((character, end)) => {
                out.push(character);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// What one request signature covers.
struct Signing<'a> {
    method: &'a str,
    /// The path as sent, before encoding.
    path: &'a str,
    query: &'a [(&'a str, &'a str)],
    host: &'a str,
    /// The hex SHA-256 of the body.
    payload_sha256: &'a str,
    amz_date: &'a str,
    region: &'a str,
    access_key_id: &'a str,
    secret_key: &'a str,
}

/// The `Authorization` header of a Signature Version 4 request for the
/// `s3` service.
fn sign(request: &Signing<'_>) -> String {
    let headers = BTreeMap::from([
        ("host", request.host),
        ("x-amz-content-sha256", request.payload_sha256),
        ("x-amz-date", request.amz_date),
    ]);
    let canonical_headers: String = headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let signed_headers = headers.keys().copied().collect::<Vec<_>>().join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
        request.method,
        uri_encode(request.path, true),
        canonical_query(request.query),
        request.payload_sha256,
    );
    let date = &request.amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", request.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{:x}",
        request.amz_date,
        Sha256::digest(canonical_request.as_bytes())
    );
    let hmac = |key: &[u8], data: &str| {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
        mac.update(data.as_bytes());
        mac.finalize().into_bytes().to_vec()
    };
    let signing_key = [request.region, "s3", "aws4_request"].iter().fold(
        hmac(format!("AWS4{}", request.secret_key).as_bytes(), date),
        |key, part| hmac(&key, part),
    );
    let signature: String = hmac(&signing_key, &string_to_sign)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        request.access_key_id
    )
}

/// Signature Version 4 URI encoding: unreserved bytes as they are, `/`
/// kept in paths, everything else `%XX`.
fn uri_encode(value: &str, keep_slash: bool) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'~')
                || keep_slash && byte == b'/'
            {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// The query as the signature canonicalizes it, and as it is sent:
/// encoded pairs sorted by name, then value.
fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<_> = query
        .iter()
        .map(|(name, value)| (uri_encode(name, false), uri_encode(value, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `YYYYMMDDTHHMMSSZ` (UTC) for `now_ms`.
fn amz_date(now_ms: i64) -> String {
    let seconds = now_ms.div_euclid(1_000);
    let (days, time) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Days since 1970-01-01 to a proleptic Gregorian date.
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        time / 3_600,
        time % 3_600 / 60,
        time % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_reads_keys_etags_and_the_continuation() {
        let xml = r#"<ListBucketResult><IsTruncated>true</IsTruncated>
            <Contents><Key>a/x&amp;y.json</Key><ETag>&quot;e1&quot;</ETag></Contents>
            <Contents><Key>a/z.json</Key><ETag>"e2"</ETag></Contents>
            <NextContinuationToken>t&amp;1</NextContinuationToken></ListBucketResult>"#;
        let page = parse_listing(xml).unwrap();
        assert_eq!(
            page.objects,
            vec![
                Listed {
                    key: "a/x&y.json".into(),
                    etag: "e1".into()
                },
                Listed {
                    key: "a/z.json".into(),
                    etag: "e2".into()
                },
            ]
        );
        assert_eq!(page.next.as_deref(), Some("t&1"));
        let cut = "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>";
        assert_eq!(parse_listing(cut).err(), Some(ConnectorFailure::Invalid));
    }

    #[test]
    fn refusals_map_to_typed_reasons() {
        assert_eq!(
            refusal(403, "SignatureDoesNotMatch"),
            ConnectorFailure::AuthFailed
        );
        assert_eq!(
            refusal(403, "AccessDenied"),
            ConnectorFailure::PermissionMissing
        );
        assert_eq!(refusal(404, "NoSuchBucket"), ConnectorFailure::Invalid);
    }

    #[test]
    fn the_signing_date_is_utc_calendar_time() {
        // 2013-05-24T00:00:00Z.
        assert_eq!(amz_date(1_369_353_600_000), "20130524T000000Z");
        assert_eq!(amz_date(951_782_400_000), "20000229T000000Z");
    }
}
