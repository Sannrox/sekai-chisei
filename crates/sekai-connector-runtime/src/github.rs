//! The `github` connector type: the issues and pull requests of one
//! repository, read as snapshot pages over the REST API and normalized by
//! the SDK's GitHub profile, so object ids are the profile's
//! `github:{owner}/{repo}#{number}` and do not change when a repository
//! moves under a Source.
//!
//! Pages are keyed by update time, oldest first: each page starts at the
//! newest update the previous one saw, and re-reads the items updated at
//! that instant. An item updated mid-scan moves past the key and is read
//! again later, so nothing slips between pages. Only a page full of items
//! updated in the same second pages on by offset; the run is then read
//! again from its start until two passes count it alike, so an item of the
//! run updated meanwhile cannot shift another past the offset. A key
//! settles only five minutes after it has passed, since an item can still
//! be updated in its second; until then each sync reads its items again.
//! Once a page reads nothing newer than a settled key, the scan is
//! complete; later syncs read only what changed since. A cursor this type did not write, such as one a
//! standalone adapter committed before the repository became a Source,
//! restarts the scan: re-read records keep their ids and versions, so they
//! change nothing.
//!
//! The client follows no redirect and no proxy, so it connects only to the
//! `api_url` the egress allowlist admitted.

use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::ACCEPT;
use reqwest::redirect::Policy;
use sekai_source_sdk::{
    ConfigValue, Connector, ConnectorFailure, GitHubObjectFixture, MAX_SOURCE_DISPLAY_NAME_BYTES,
    SnapshotPage, SnapshotRead, SourceRecord, translate_github_fixture,
};
use serde::Deserialize;

use crate::sync::Prepared;

/// GitHub's largest page.
const MAX_PER_PAGE: usize = 100;

/// How long after an update time no further item can be updated at it, as
/// this host's clock sees GitHub's: one-second timestamps plus clock skew.
const SETTLE_AFTER_SECS: i64 = 300;

/// One repository, reached with the Source's bound token.
pub struct GitHub {
    http: Client,
    api_url: String,
    repository: String,
    token: String,
    settle_after_secs: i64,
}

/// Opens the GitHub type for a prepared Source; register it with
/// `Connectors::with(&GITHUB_CONNECTOR, github::open)`.
pub fn open(prepared: &Prepared) -> Result<Box<dyn Connector + Send>, ConnectorFailure> {
    Ok(Box::new(open_github(prepared)?))
}

fn open_github(prepared: &Prepared) -> Result<GitHub, ConnectorFailure> {
    let Some(ConfigValue::Text(api_url)) = prepared.config.get("api_url") else {
        return Err(ConnectorFailure::Invalid);
    };
    let token = prepared
        .credentials
        .get("token")
        .ok_or(ConnectorFailure::AuthFailed)?
        .expose()
        .to_string();
    let http = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .user_agent("sekai-connector-runtime")
        .build()
        .map_err(|_| ConnectorFailure::Invalid)?;
    Ok(GitHub {
        http,
        api_url: api_url.trim_end_matches('/').to_string(),
        repository: prepared.source_instance.clone(),
        token,
        settle_after_secs: SETTLE_AFTER_SECS,
    })
}

impl GitHub {
    fn get(&self, path: &str) -> Result<Response, ConnectorFailure> {
        let response = self
            .http
            .get(format!("{}{path}", self.api_url))
            .bearer_auth(&self.token)
            .header(ACCEPT, "application/vnd.github+json")
            .send()
            .map_err(|_| ConnectorFailure::Unreachable)?;
        // A rate limit answers 403 too; it passes, a refusal does not.
        let limited = response.headers().contains_key("retry-after")
            || response
                .headers()
                .get("x-ratelimit-remaining")
                .is_some_and(|remaining| remaining == "0");
        match response.status().as_u16() {
            200..=299 => Ok(response),
            401 => Err(ConnectorFailure::AuthFailed),
            403 if limited => Err(ConnectorFailure::Unreachable),
            403 | 404 => Err(ConnectorFailure::PermissionMissing),
            429 | 500..=599 => Err(ConnectorFailure::Unreachable),
            _ => Err(ConnectorFailure::Invalid),
        }
    }
}

impl GitHub {
    /// One page of the items updated at or after `since`, oldest update
    /// first.
    fn list(&self, since: &str, page: u32, per_page: usize) -> Result<Vec<Item>, ConnectorFailure> {
        let mut path = format!(
            "/repos/{}/issues?state=all&sort=updated&direction=asc&per_page={per_page}&page={page}",
            self.repository
        );
        if !since.is_empty() {
            path.push_str("&since=");
            path.push_str(since);
        }
        let items: Vec<Item> = self
            .get(&path)?
            .json()
            .map_err(|_| ConnectorFailure::Invalid)?;
        if items.iter().any(|item| !timestamp(&item.updated_at)) {
            return Err(ConnectorFailure::Invalid);
        }
        Ok(items)
    }
}

impl Connector for GitHub {
    fn check(&mut self) -> Result<(), ConnectorFailure> {
        self.get(&format!("/repos/{}", self.repository)).map(|_| ())
    }

    fn read_page(
        &mut self,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<SnapshotRead, ConnectorFailure> {
        let cursor = committed_cursor.and_then(Cursor::parse).unwrap_or_default();
        let per_page = max_records.clamp(1, MAX_PER_PAGE);
        let (mut page, mut items) = (
            cursor.page,
            self.list(&cursor.since, cursor.page, per_page)?,
        );
        // Past the end of a run of whole pages: the run ends at the page
        // before, which also holds any of its items updated since.
        let mut fell_back = items.is_empty() && page > 1;
        if fell_back {
            page -= 1;
            items = self.list(&cursor.since, page, per_page)?;
            // Items of the run were deleted or moved away: no committed
            // page can be reached from here, so the run is read from its
            // start.
            if items.is_empty() && page > 1 {
                (page, fell_back) = (1, false);
                items = self.list(&cursor.since, page, per_page)?;
            }
        }
        let newest = items
            .iter()
            .map(|item| item.updated_at.as_str())
            .max()
            .unwrap_or_default();
        let ends = fell_back || items.len() < per_page;
        // An update time is settled only once no item can still be updated
        // at it; until then its items are read again on a later sync.
        let cutoff = utc_timestamp(now_ms() / 1000 - self.settle_after_secs);
        let past = |key: &str| key < cutoff.as_str();
        // Paged by offset, a run of items updated in one second shifts when
        // one of them is updated meanwhile, which could skip another. The
        // run is read again from its start until two passes count it alike.
        let counted = (page as usize - 1) * per_page
            + items
                .iter()
                .filter(|item| item.updated_at == cursor.since)
                .count();
        let next = if page > 1 && (ends || newest > cursor.since.as_str()) && counted != cursor.run
        {
            Cursor {
                page: 1,
                settled: false,
                run: counted,
                ..cursor
            }
        } else if newest > cursor.since.as_str() {
            // A last page saw every item up to its newest update.
            Cursor {
                since: newest.to_string(),
                page: 1,
                settled: ends && past(newest),
                run: 0,
            }
        } else if ends {
            // Nothing newer than the key, and every item at it was read.
            // A key too recent to settle is read again by a later sync.
            if cursor.settled || !past(&cursor.since) {
                return Ok(SnapshotRead::Complete);
            }
            Cursor {
                settled: true,
                ..cursor
            }
        } else {
            // A full page updated in one second: on by offset.
            Cursor {
                page: page + 1,
                ..cursor
            }
        };
        let complete = next.settled;
        let next = next.to_string();
        let observed_at_ms = now_ms();
        // An item the profile cannot hold even under `#number` fails the
        // page visibly rather than being left out.
        let records = items
            .into_iter()
            .map(|item| record(item, &self.repository, observed_at_ms))
            .collect::<Option<Vec<_>>>()
            .ok_or(ConnectorFailure::Invalid)?;
        Ok(SnapshotRead::Page(SnapshotPage {
            records,
            proposed_next_cursor: next,
            collected_at_ms: observed_at_ms,
            complete,
        }))
    }
}

/// One issue or pull request as the REST API lists it.
#[derive(Deserialize)]
struct Item {
    number: u64,
    title: String,
    state: String,
    updated_at: String,
    #[serde(default)]
    pull_request: Option<serde_json::Value>,
}

/// The profile's record for `item`. A title the profile refuses, such as
/// one that looks like a secret, is replaced by `#number`, so a title never
/// stops the repository's sync.
fn record(item: Item, repository: &str, observed_at_ms: i64) -> Option<SourceRecord> {
    let kind = if item.pull_request.is_some() {
        "PullRequest"
    } else {
        "Issue"
    };
    let fixture = GitHubObjectFixture {
        repository: repository.into(),
        kind: kind.into(),
        number: item.number,
        revision: item.updated_at,
        title: display_title(&item.title, item.number),
        state: item.state,
        deleted: false,
        observed_at_ms,
        properties: BTreeMap::new(),
    };
    translate_github_fixture(fixture.clone(), repository)
        .or_else(|_| {
            translate_github_fixture(
                GitHubObjectFixture {
                    title: format!("#{}", item.number),
                    ..fixture
                },
                repository,
            )
        })
        .ok()
}

/// The title on one line within the profile's limit; `#number` when empty.
fn display_title(title: &str, number: u64) -> String {
    let mut line: String = title
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
    let line = line.trim();
    if line.is_empty() {
        format!("#{number}")
    } else {
        line.to_string()
    }
}

/// An ISO 8601 UTC timestamp as GitHub writes them; these order as text.
fn timestamp(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b':' | b'T' | b'Z'))
}

/// Where a scan stands: the update time its next page starts at (empty
/// for the beginning), the page at that time, whether every item updated
/// at that time has been read, and how many such items the last pass
/// through a run of whole pages counted (0 for none).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cursor {
    since: String,
    page: u32,
    settled: bool,
    run: usize,
}

impl Default for Cursor {
    fn default() -> Self {
        Self {
            since: String::new(),
            page: 1,
            settled: false,
            run: 0,
        }
    }
}

impl Cursor {
    const PREFIX: &str = "github-v1";

    fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('|');
        if parts.next()? != Self::PREFIX {
            return None;
        }
        let (since, page, settled, run) =
            (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || !(since.is_empty() || timestamp(since)) {
            return None;
        }
        Some(Self {
            since: since.into(),
            page: page.parse().ok().filter(|page| *page > 0)?,
            settled: match settled {
                "settled" => true,
                "open" => false,
                _ => return None,
            },
            run: run.parse().ok()?,
        })
    }
}

impl std::fmt::Display for Cursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let settled = if self.settled { "settled" } else { "open" };
        write!(
            formatter,
            "{}|{}|{}|{settled}|{}",
            Self::PREFIX,
            self.since,
            self.page,
            self.run
        )
    }
}

/// `secs` since the epoch in the form GitHub writes update times.
fn utc_timestamp(secs: i64) -> String {
    let (days, secs) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01, proleptic Gregorian.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
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
    use sekai_source_sdk::{GITHUB_CONNECTOR, SourceConfig};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Requests a fake API saw: request line and authorization header.
    type Seen = Arc<Mutex<Vec<(String, String)>>>;

    /// Serves `respond(path) -> (status, body)` on an ephemeral port.
    fn fake_api<S: std::fmt::Display>(
        respond: impl Fn(&str) -> (S, String) + Send + 'static,
    ) -> (String, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Seen::default();
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut authorization = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some(value) = line.strip_prefix("authorization: ") {
                        authorization = value.trim().into();
                    }
                }
                let path = request_line
                    .split(' ')
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                log.lock().unwrap().push((path.clone(), authorization));
                let (status, body) = respond(&path);
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (url, seen)
    }

    fn github(api_url: &str) -> GitHub {
        settling(api_url, SETTLE_AFTER_SECS)
    }

    /// The type with update times settling `settle_after_secs` after they
    /// pass; a century or more keeps every test time recent.
    fn settling(api_url: &str, settle_after_secs: i64) -> GitHub {
        let mut github = open_github(&Prepared {
            connector: &GITHUB_CONNECTOR,
            source_instance: "acme/repo".into(),
            config: SourceConfig::from([("api_url".into(), ConfigValue::Text(api_url.into()))]),
            credentials: BTreeMap::from([("token".into(), Secret("t0k".into()))]),
        })
        .unwrap();
        github.settle_after_secs = settle_after_secs;
        github
    }

    fn item(number: u64, updated_at: &str, pull_request: bool) -> serde_json::Value {
        let mut item = serde_json::json!({
            "number": number,
            "title": format!("item {number}"),
            "state": "open",
            "updated_at": updated_at,
        });
        if pull_request {
            item["pull_request"] = serde_json::json!({});
        }
        item
    }

    fn page(read: SnapshotRead) -> SnapshotPage {
        match read {
            SnapshotRead::Page(page) => page,
            SnapshotRead::Complete => panic!("a page"),
        }
    }

    /// The repository's items: number, update time, pull request.
    type Items = Arc<Mutex<Vec<(u64, &'static str, bool)>>>;

    /// Lists `items` as the issues endpoint does: updated at or after
    /// `since`, oldest update first, one page of `per_page`.
    fn issues(items: &Items, path: &str) -> String {
        let query = |name: &str| {
            path.split(['?', '&'])
                .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
                .map(str::to_string)
        };
        let since = query("since").unwrap_or_default();
        let page: usize = query("page").unwrap().parse().unwrap();
        let per_page: usize = query("per_page").unwrap().parse().unwrap();
        let mut listed: Vec<_> = items
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, updated_at, _)| *updated_at >= since.as_str())
            .copied()
            .collect();
        listed.sort_by_key(|(number, updated_at, _)| (*updated_at, *number));
        let listed: Vec<_> = listed
            .into_iter()
            .skip((page - 1) * per_page)
            .take(per_page)
            .map(|(number, updated_at, pull_request)| item(number, updated_at, pull_request))
            .collect();
        serde_json::Value::from(listed).to_string()
    }

    /// Reads pages as the runtime does, committing each cursor, until the
    /// scan is complete; returns the numbers read per page.
    fn scan(github: &mut dyn Connector, cursor: &mut Option<String>) -> Vec<Vec<String>> {
        let mut pages = Vec::new();
        while let SnapshotRead::Page(page) = github.read_page(cursor.as_deref(), 2).unwrap() {
            assert_ne!(Some(&page.proposed_next_cursor), cursor.as_ref());
            pages.push(
                page.records
                    .iter()
                    .map(|record| record.external_id.clone())
                    .collect(),
            );
            *cursor = Some(page.proposed_next_cursor);
            assert!(pages.len() < 10, "the scan ends");
        }
        pages
    }

    #[test]
    fn a_scan_pages_by_update_time_then_reads_only_what_changed() {
        let items = Items::new(Mutex::new(vec![
            (1, "2026-01-01T00:00:00Z", false),
            (2, "2026-01-02T00:00:00Z", true),
            (3, "2026-01-03T00:00:00Z", false),
        ]));
        let listed = items.clone();
        let (url, seen) = fake_api(move |path| (200, issues(&listed, path)));
        let mut github = github(&url);
        let mut cursor = None;

        let first = page(github.read_page(None, 2).unwrap());
        let kinds: Vec<_> = first
            .records
            .iter()
            .map(|record| (record.source_id(), record.type_name.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("github:acme/repo#1".to_string(), "Issue"),
                ("github:acme/repo#2".to_string(), "PullRequest"),
            ]
        );
        assert_eq!(
            scan(&mut github, &mut cursor),
            [vec!["1", "2"], vec!["2", "3"], vec!["3"]]
        );
        assert!(scan(&mut github, &mut cursor).is_empty(), "nothing changed");

        // Issue 1 is updated: only it, and the item at the key, are read.
        items.lock().unwrap()[0].1 = "2026-01-04T00:00:00Z";
        assert_eq!(scan(&mut github, &mut cursor), [vec!["3", "1"], vec!["1"]]);
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .all(|(_, auth)| auth == "Bearer t0k")
        );
    }

    #[test]
    fn a_page_updated_in_one_second_pages_on_by_offset() {
        const SAME: &str = "2026-01-01T00:00:00Z";
        let items = Items::new(Mutex::new(
            (1..=5).map(|number| (number, SAME, false)).collect(),
        ));
        let listed = items.clone();
        let (url, _) = fake_api(move |path| (200, issues(&listed, path)));
        let mut github = github(&url);
        let mut cursor = None;
        let read: Vec<String> = scan(&mut github, &mut cursor).concat();
        for number in 1..=5 {
            assert!(read.contains(&number.to_string()), "{number} read");
        }
        assert!(scan(&mut github, &mut cursor).is_empty());
        // A later update lands after the run and is read.
        items
            .lock()
            .unwrap()
            .push((6, "2026-01-02T00:00:00Z", false));
        assert!(
            scan(&mut github, &mut cursor)
                .concat()
                .contains(&"6".to_string())
        );
    }

    #[test]
    fn an_update_inside_a_run_of_whole_pages_is_read() {
        const SAME: &str = "2026-01-01T00:00:00Z";
        // Four items in one second fill two pages exactly.
        let items = Items::new(Mutex::new(
            (1..=4).map(|number| (number, SAME, false)).collect(),
        ));
        let listed = items.clone();
        let (url, _) = fake_api(move |path| (200, issues(&listed, path)));
        let mut github = github(&url);
        let mut cursor = None;
        scan(&mut github, &mut cursor);
        assert!(scan(&mut github, &mut cursor).is_empty());
        items.lock().unwrap()[0].1 = "2026-01-02T00:00:00Z";
        assert!(
            scan(&mut github, &mut cursor)
                .concat()
                .contains(&"1".to_string())
        );
    }

    #[test]
    fn an_item_of_a_run_updated_mid_pass_skips_no_other() {
        const SAME: &str = "2026-01-01T00:00:00Z";
        let items = Items::new(Mutex::new(
            (1..=4).map(|number| (number, SAME, false)).collect(),
        ));
        let listed = items.clone();
        let (url, _) = fake_api(move |path| (200, issues(&listed, path)));
        let mut github = github(&url);
        // Into the run: page 1 of `since=SAME` is read and committed.
        let mut cursor = None;
        while !cursor
            .as_deref()
            .is_some_and(|cursor: &str| cursor.contains(SAME))
        {
            cursor =
                Some(page(github.read_page(cursor.as_deref(), 2).unwrap()).proposed_next_cursor);
        }
        let first = page(github.read_page(cursor.as_deref(), 2).unwrap());
        assert_eq!(first.records.len(), 2);
        cursor = Some(first.proposed_next_cursor);
        // Issue 1 is updated before page 2: the run shifts under the offset.
        items.lock().unwrap()[0].1 = "2026-01-02T00:00:00Z";
        let read: Vec<String> = scan(&mut github, &mut cursor).concat();
        assert!(read.contains(&"3".to_string()), "3 is read: {read:?}");
    }

    #[test]
    fn a_recent_update_time_settles_only_once_it_has_passed() {
        const AT: &str = "2026-01-01T00:00:00Z";
        let items = Items::new(Mutex::new(vec![(1, AT, false)]));
        let listed = items.clone();
        let (url, _) = fake_api(move |path| (200, issues(&listed, path)));
        let mut github = settling(&url, i64::from(u32::MAX));
        // One page holds every item, so no read pages on by offset.
        let read = |github: &mut GitHub, cursor: &mut Option<String>| match github
            .read_page(cursor.as_deref(), 10)
            .unwrap()
        {
            SnapshotRead::Complete => None,
            SnapshotRead::Page(page) => {
                *cursor = Some(page.proposed_next_cursor);
                Some(
                    page.records
                        .into_iter()
                        .map(|record| record.external_id)
                        .collect::<Vec<_>>(),
                )
            }
        };
        let mut cursor = None;
        assert_eq!(read(&mut github, &mut cursor), Some(vec!["1".to_string()]));
        assert_eq!(read(&mut github, &mut cursor), None, "too recent to settle");
        // Issue 2 is updated in the same second, after that read.
        items.lock().unwrap().push((2, AT, false));
        assert_eq!(read(&mut github, &mut cursor), None, "still recent");
        github.settle_after_secs = SETTLE_AFTER_SECS;
        assert_eq!(
            read(&mut github, &mut cursor),
            Some(vec!["1".to_string(), "2".to_string()])
        );
        assert_eq!(read(&mut github, &mut cursor), None, "settled");
    }

    #[test]
    fn update_times_are_written_as_github_writes_them() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_timestamp(1_798_761_599), "2026-12-31T23:59:59Z");
    }

    #[test]
    fn a_run_whose_items_were_deleted_is_read_from_its_start() {
        const SAME: &str = "2026-01-01T00:00:00Z";
        let items = Items::new(Mutex::new(vec![
            (1, SAME, false),
            (2, "2026-01-02T00:00:00Z", false),
        ]));
        let listed = items.clone();
        let (url, _) = fake_api(move |path| (200, issues(&listed, path)));
        let mut github = github(&url);
        // The scan stood at page 3 of a run that has since shrunk to one item.
        let mut cursor = Some(
            Cursor {
                since: SAME.into(),
                page: 3,
                settled: false,
                run: 0,
            }
            .to_string(),
        );
        assert_eq!(scan(&mut github, &mut cursor), [vec!["1", "2"], vec!["2"]]);
    }

    #[test]
    fn a_cursor_another_adapter_wrote_restarts_the_scan() {
        let (url, seen) = fake_api(|_| (200, "[]".into()));
        let read = page(github(&url).read_page(Some("legacy-7"), 10).unwrap());
        assert!(read.complete && read.records.is_empty());
        assert_ne!(read.proposed_next_cursor, "legacy-7");
        let request = &seen.lock().unwrap()[0].0;
        assert!(request.contains("&page=1") && !request.contains("since="));
    }

    #[test]
    fn api_refusals_map_to_failure_classes() {
        for (status, failure) in [
            (401, ConnectorFailure::AuthFailed),
            (404, ConnectorFailure::PermissionMissing),
            (503, ConnectorFailure::Unreachable),
            (302, ConnectorFailure::Invalid),
        ] {
            let (url, _) = fake_api(move |_| (status, "{}".into()));
            assert_eq!(github(&url).check(), Err(failure), "{status}");
        }
        // A rate limit is a 403 that names when to retry; the status line
        // carries the header into the fake's response.
        let (url, _) = fake_api(|_| ("403 Limited\r\nretry-after: 60", "{}".into()));
        assert_eq!(github(&url).check(), Err(ConnectorFailure::Unreachable));
        let (url, _) = fake_api(|_| (403, "{}".into()));
        assert_eq!(
            github(&url).check(),
            Err(ConnectorFailure::PermissionMissing)
        );
        let (url, _) = fake_api(|_| (200, r#"[{"number":1}]"#.into()));
        assert_eq!(
            github(&url).read_page(None, 10),
            Err(ConnectorFailure::Invalid)
        );
    }

    #[test]
    fn titles_fit_the_profile() {
        let refused = Item {
            number: 7,
            title: "rotate password=hunter2".into(),
            state: "open".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            pull_request: None,
        };
        assert_eq!(record(refused, "acme/repo", 1).unwrap().display_name, "#7");
        assert_eq!(display_title("  ", 4), "#4");
        assert_eq!(display_title("a\nb", 4), "a b");
        assert!(display_title(&"é".repeat(400), 4).len() <= MAX_SOURCE_DISPLAY_NAME_BYTES);
    }
}
