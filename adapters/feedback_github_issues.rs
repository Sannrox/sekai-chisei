//! Qualifying feedback findings as GitHub issues (#1232, out of the plane).
//!
//! Publication is a source writeback (`source_writeback.rs`): the issue tracker
//! is the [`SourceSystem`], and every create or update goes through the permit,
//! Action, and execution-evidence path there.
//!
//! - Each (namespace, problem signature) owns one issue, found by a public
//!   marker in its body. The marker is the writeback key, so a marker written
//!   for another namespace never matches.
//! - Only issues the executor's own account opened are managed or counted
//!   toward the daily cap. Markers are public; a pasted copy is ignored.
//! - The record version is `absent` or the issue's number and `updated_at`. A
//!   create whose response was lost shows up as present on the next decision,
//!   which becomes an update or nothing, never a second create.
//! - [`IssuePublisher::decide`] returns [`Publish::Unchanged`] when the issue
//!   already carries the composed title and managed section: no permit, no write.
//! - GitHub has no conditional write. `apply` re-reads the issue right before
//!   writing, so the check-then-act window is one list round trip. Run one
//!   executor per repository so the window does not widen.
//!
//! The executor holds the token in its [`GitHubIssues`] implementation, which
//! must not block the async runtime that drives the writeback. It never
//! enters the plane, the permit, the Action, or the evidence. Public text is
//! sanitized before it leaves: secrets, emails, addresses, private paths and
//! hosts, and references to other repositories become `[redacted]`.

use std::collections::{BTreeMap, BTreeSet};

use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    GetObjectRequest, ListFilter, ListObjectsRequest, Object, PropertyFilter,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::feedback_package::{
    INVESTIGATION_RUNTIME, KIND_INVESTIGATION_RESULT, KIND_OBSERVATION, PROPERTY_RECORDED_BY,
};
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

use crate::feedback_investigation::{
    InvestigationAnalysis, observation_view, publication_permitted,
};
use crate::source_writeback::{SourceSystem, WritebackIntent};

pub const DEFAULT_DAILY_CAP: u32 = 5;
pub const MARKER_PREFIX: &str = "sekai-feedback:";
/// Version of a marker no issue carries yet.
pub const ABSENT: &str = "absent";
const MANAGED_END: &str = "<!-- /sekai-feedback -->";
const DAY_MS: i64 = 86_400_000;
const LIST_PAGE: i32 = 256;
const TITLE_MAX_CHARS: usize = 72;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubIssue {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub created_ms: i64,
    pub updated_ms: i64,
    /// Login of the account that opened the issue.
    pub author: String,
}

/// The executor's view of one repository. The implementation holds the token.
pub trait GitHubIssues {
    /// The account the token acts as. Only issues it opened are managed.
    fn login(&self) -> &str;
    /// Every issue in the repository, open and closed.
    fn list(&self) -> Result<Vec<GitHubIssue>, String>;
    fn create(&self, title: &str, body: &str) -> Result<GitHubIssue, String>;
    fn update(&self, number: u64, title: &str, body: &str) -> Result<GitHubIssue, String>;
}

/// One repository as a writeback target. Keys are public markers; a change
/// carries `title` and `managed_body` (the marked section only).
pub struct IssueTracker<G> {
    pub github: G,
    /// `owner/repo`.
    pub repository: String,
    /// New issues per UTC day across all markers; 0 means [`DEFAULT_DAILY_CAP`].
    pub daily_cap: u32,
}

impl<G: GitHubIssues> IssueTracker<G> {
    /// Issues the executor opened. Markers are public, so anyone can paste
    /// one into an issue; those are never adopted and never use up the cap.
    fn own_issues(&self) -> Result<Vec<GitHubIssue>, String> {
        let login = self.github.login();
        let mut issues = self.github.list()?;
        issues.retain(|issue| issue.author == login);
        Ok(issues)
    }

    fn find(&self, marker: &str) -> Result<Option<GitHubIssue>, String> {
        let needle = marker_comment(marker);
        Ok(self
            .own_issues()?
            .into_iter()
            .find(|issue| issue.body.contains(&needle)))
    }

    fn daily_cap(&self) -> u32 {
        if self.daily_cap == 0 {
            DEFAULT_DAILY_CAP
        } else {
            self.daily_cap
        }
    }
}

fn issue_version(issue: Option<&GitHubIssue>) -> String {
    issue.map_or_else(
        || ABSENT.to_string(),
        |issue| format!("{}@{}", issue.number, issue.updated_ms),
    )
}

impl<G: GitHubIssues> SourceSystem for IssueTracker<G> {
    fn resource(&self, key: &str) -> Result<String, String> {
        if !key.starts_with(MARKER_PREFIX) {
            return Err(format!("{key} is not a feedback marker"));
        }
        Ok(format!("github:{}#{key}", self.repository))
    }

    fn version(&self, key: &str) -> Result<String, String> {
        Ok(issue_version(self.find(key)?.as_ref()))
    }

    fn apply(
        &self,
        key: &str,
        expected_version: &str,
        change: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        let field = |name: &str| {
            change
                .get(name)
                .ok_or_else(|| format!("change is missing {name}"))
        };
        let (title, managed) = (field("title")?, field("managed_body")?);
        let current = self.find(key)?;
        if issue_version(current.as_ref()) != expected_version {
            return Err("issue changed since the writeback was decided".into());
        }
        let written = match current {
            None => {
                let issues = self.own_issues()?;
                if new_issues_today(&issues, now_ms()) >= self.daily_cap() {
                    return Err("daily new-issue cap reached".into());
                }
                self.github.create(title, managed)?
            }
            Some(issue) => self.github.update(
                issue.number,
                title,
                &merge_maintainer_body(&issue.body, managed),
            )?,
        };
        Ok(issue_version(Some(&written)))
    }
}

/// The next step for one finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publish {
    /// The issue already shows this content; nothing to authorize.
    Unchanged,
    /// No issue exists and today's cap is spent; retry tomorrow.
    DailyCapReached,
    Write(WritebackIntent),
}

/// Reads findings and their cluster as `principal`, and turns a qualifying
/// finding into a writeback intent against an [`IssueTracker`].
pub struct IssuePublisher {
    pub namespace: String,
    pub principal: String,
}

impl IssuePublisher {
    pub async fn decide<G: GitHubIssues>(
        &self,
        sekai: &SekaiServiceImpl,
        tracker: &IssueTracker<G>,
        finding_id: &str,
    ) -> Result<Publish, String> {
        let finding = self
            .get(sekai, finding_id)
            .await?
            .filter(|finding| finding.namespace == self.namespace && publication_permitted(finding))
            .ok_or_else(|| format!("{finding_id} is not a publishable finding"))?;
        let anchor = finding
            .properties
            .get("observation_id")
            .cloned()
            .unwrap_or_default();
        let signature = self
            .get(sekai, &anchor)
            .await?
            .filter(|observation| observation.namespace == self.namespace)
            .as_ref()
            .and_then(observation_view)
            .map(|view| view.problem_signature)
            .ok_or("the finding's observation is not visible")?;
        let investigation = self
            .list(sekai, KIND_INVESTIGATION_RESULT, "observation_id", &anchor)
            .await?
            .into_iter()
            .find(|investigation| {
                investigation
                    .properties
                    .get(PROPERTY_RECORDED_BY)
                    .map(String::as_str)
                    == Some(INVESTIGATION_RUNTIME)
            });
        let property = |key: &str| {
            investigation
                .as_ref()
                .and_then(|investigation| investigation.properties.get(key))
        };
        let analysis = property("outcome")
            .and_then(|outcome| serde_json::from_str::<InvestigationAnalysis>(outcome).ok());
        // The plane-recorded flag, never the model's own claim.
        let measured = property("measured").map(String::as_str) == Some("true");
        let observations = self
            .list(sekai, KIND_OBSERVATION, "problem_signature", &signature)
            .await?;
        let draft = draft(
            &self.namespace,
            &signature,
            analysis.as_ref(),
            measured,
            &observations,
            &tracker.repository,
        );

        let marker = public_marker(&self.namespace, &signature);
        let issues = tracker.own_issues()?;
        let current = issues
            .iter()
            .find(|issue| issue.body.contains(&marker_comment(&marker)));
        if let Some(issue) = current
            && issue.title == draft.title
            && issue.body.starts_with(&draft.managed_body)
        {
            return Ok(Publish::Unchanged);
        }
        if current.is_none() && new_issues_today(&issues, now_ms()) >= tracker.daily_cap() {
            return Ok(Publish::DailyCapReached);
        }
        let expected_version = issue_version(current);
        let change = BTreeMap::from([
            ("title".to_string(), draft.title),
            ("managed_body".to_string(), draft.managed_body),
        ]);
        // Same marker, version, and content replays one Action.
        let digest = format!(
            "{:x}",
            Sha256::digest(
                format!(
                    "{marker}\0{expected_version}\0{}",
                    serde_json::to_string(&change).map_err(|error| error.to_string())?
                )
                .as_bytes()
            )
        );
        let operation_id = format!("feedback-publish-{}", &digest[..24]);
        Ok(Publish::Write(WritebackIntent {
            key: marker,
            expected_version,
            change,
            idempotency_key: operation_id.clone(),
            operation_id,
        }))
    }

    async fn get(&self, sekai: &SekaiServiceImpl, id: &str) -> Result<Option<Object>, String> {
        match sekai
            .get_object(with_principal(
                GetObjectRequest { id: id.into() },
                &self.principal,
            )?)
            .await
        {
            Ok(response) => Ok(response.into_inner().object),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(status.message().into()),
        }
    }

    async fn list(
        &self,
        sekai: &SekaiServiceImpl,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>, String> {
        let mut objects = Vec::new();
        let mut page_token = String::new();
        loop {
            let page = sekai
                .list_objects(with_principal(
                    ListObjectsRequest {
                        filter: Some(ListFilter {
                            kind: kind.into(),
                            namespace: self.namespace.clone(),
                            property_filters: vec![PropertyFilter {
                                key: key.into(),
                                op: "eq".into(),
                                value: value.into(),
                            }],
                            limit: LIST_PAGE,
                            ..Default::default()
                        }),
                        page_token,
                    },
                    &self.principal,
                )?)
                .await
                .map_err(|status| status.message().to_string())?
                .into_inner();
            objects.extend(page.objects);
            if page.next_page_token.is_empty() {
                return Ok(objects);
            }
            page_token = page.next_page_token;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueDraft {
    pub title: String,
    /// Marker comment, public sections, end marker.
    pub managed_body: String,
}

/// Public title and managed section for one signature. Everything derived
/// from observations or the model passes through [`sanitize_public_text`].
pub fn draft(
    namespace: &str,
    signature: &str,
    analysis: Option<&InvestigationAnalysis>,
    measured: bool,
    observations: &[Object],
    repository: &str,
) -> IssueDraft {
    let public = |text: &str| public_token(&sanitize_public_text(&words(text), repository));
    let (operation, reason) = signature.rsplit_once(':').unwrap_or((signature, ""));
    let (operation, reason) = (public(operation), public(reason));
    let attribution = analysis
        .and_then(|analysis| serde_json::to_value(analysis.attribution).ok())
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unspecified".into());
    let views: Vec<_> = observations
        .iter()
        .filter_map(observation_view)
        .filter(|view| view.problem_signature == signature)
        .collect();
    let operations: BTreeSet<_> = views
        .iter()
        .flat_map(|view| view.occurrence_ids.iter())
        .collect();
    let version = observations
        .iter()
        .filter_map(|object| object.properties.get("tenkai_version"))
        .find_map(|raw| public_version(raw))
        .map_or_else(|| "unspecified".to_string(), public);
    let reproduction = if measured {
        "Measured."
    } else {
        "Not independently measured."
    };
    let sections = format!(
        "## Operation\n\n{operation}\n\n## Reason\n\n{reason}\n\n## Attribution\n\n{attribution}\n\n## Recurrence\n\n{} observations across {} operations.\n\n## Controller version\n\n{version}\n\n## Reproduction\n\n{reproduction}\n\n## Acceptance\n\nA measured verification of the investigation result confirms the documented reproduction no longer fails.",
        views.len(),
        operations.len(),
    );
    IssueDraft {
        title: public_title(&operation, &reason),
        managed_body: format!(
            "{}\n{sections}\n{MANAGED_END}",
            marker_comment(&public_marker(namespace, signature))
        ),
    }
}

/// Opaque per (namespace, signature): reveals neither.
pub fn public_marker(namespace: &str, signature: &str) -> String {
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{namespace}\0{signature}").as_bytes())
    );
    format!("{MARKER_PREFIX}{}", &digest[..16])
}

fn marker_comment(marker: &str) -> String {
    format!("<!-- {marker} -->")
}

/// The managed section followed by whatever maintainers wrote below it.
pub fn merge_maintainer_body(existing: &str, managed: &str) -> String {
    let maintainer = maintainer_text(existing);
    if maintainer.is_empty() {
        managed.to_string()
    } else {
        format!("{managed}\n\n{maintainer}")
    }
}

pub fn maintainer_text(body: &str) -> String {
    match body.find(MANAGED_END) {
        Some(index) => body[index + MANAGED_END.len()..].trim().to_string(),
        None if body.contains(&format!("<!-- {MARKER_PREFIX}")) => String::new(),
        None => body.trim().to_string(),
    }
}

/// Issues this adapter created today (UTC), across all markers.
pub fn new_issues_today(issues: &[GitHubIssue], now_ms: i64) -> u32 {
    let day = now_ms.div_euclid(DAY_MS);
    let prefix = format!("<!-- {MARKER_PREFIX}");
    issues
        .iter()
        .filter(|issue| issue.created_ms.div_euclid(DAY_MS) == day && issue.body.contains(&prefix))
        .count() as u32
}

/// Producer text split into the words the redactors inspect. A private value
/// glued to other text (`file=/home/x`, `connect(db01.example)`) becomes its
/// own word, so it is redacted before [`public_token`] joins the words again.
fn words(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '@' | '#' | '~') {
                c
            } else {
                ' '
            }
        })
        .collect()
}

/// One signature part as plain identifier text. Anything else (markup,
/// comment delimiters, `@` mentions) becomes `_`, so producer text cannot
/// format the issue, end the managed section, or notify anyone.
fn public_token(text: &str) -> String {
    match text.trim() {
        "" | "[redacted]" => "unspecified".into(),
        trimmed => trimmed
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '/') {
                    c
                } else {
                    '_'
                }
            })
            .collect(),
    }
}

fn public_version(raw: &str) -> Option<&str> {
    let version = raw.trim();
    (!version.is_empty()
        && version.len() <= 32
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+')))
    .then_some(version)
}

fn public_title(operation: &str, reason: &str) -> String {
    let mut title = format!("feedback: {operation}");
    if !reason.is_empty() && reason != "unspecified" {
        title.push(' ');
        title.push_str(reason);
    }
    title.chars().take(TITLE_MAX_CHARS).collect()
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn with_principal<T>(payload: T, principal: &str) -> Result<Request<T>, String> {
    let mut request = Request::new(payload);
    request.metadata_mut().insert(
        "x-principal",
        MetadataValue::try_from(principal).map_err(|error| error.to_string())?,
    );
    Ok(request)
}

/// Replace private identifiers with `[redacted]`. References to `repository`
/// and to github.com stay.
pub fn sanitize_public_text(text: &str, repository: &str) -> String {
    let mut out = redact_secrets(text);
    out = redact_emails(&out);
    out = redact_ipv4(&out);
    out = redact_ipv6(&out);
    out = redact_paths(&out);
    out = redact_foreign_refs(&out, repository);
    redact_hostnames(&out)
}

const TOKEN_TRIM: &str = ",.;:()[]{}<>\"'`*";

fn trim_token(token: &str) -> &str {
    token.trim_matches(|c: char| TOKEN_TRIM.contains(c))
}

fn match_at(haystack: &[char], start: usize, needle: &str) -> bool {
    let needle: Vec<char> = needle.chars().collect();
    if start + needle.len() > haystack.len() {
        return false;
    }
    haystack[start..start + needle.len()] == needle
}

fn redact_secrets(text: &str) -> String {
    let orig: Vec<char> = text.chars().collect();
    let lower: Vec<char> = text.to_ascii_lowercase().chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < orig.len() {
        if match_at(&lower, i, "authorization:") {
            out.push_str("[redacted]");
            i += "authorization:".len();
            while i < orig.len() && orig[i].is_whitespace() {
                i += 1;
            }
            if match_at(&lower, i, "bearer") {
                i += "bearer".len();
                while i < orig.len() && orig[i].is_whitespace() {
                    i += 1;
                }
            }
            while i < orig.len() && !orig[i].is_whitespace() {
                i += 1;
            }
            continue;
        }
        let bearer_boundary = i == 0 || !lower[i - 1].is_ascii_alphanumeric();
        if bearer_boundary && match_at(&lower, i, "bearer") {
            let after = i + "bearer".len();
            if after < orig.len() && orig[after].is_whitespace() {
                out.push_str("[redacted]");
                i = after;
                while i < orig.len() && orig[i].is_whitespace() {
                    i += 1;
                }
                while i < orig.len() && !orig[i].is_whitespace() {
                    i += 1;
                }
                continue;
            }
        }
        out.push(orig[i]);
        i += 1;
    }
    out
}

fn redact_emails(text: &str) -> String {
    let mut out = String::new();
    for token in split_keep(text) {
        if is_email(trim_token(&token)) {
            out.push_str("[redacted]");
        } else {
            out.push_str(&token);
        }
    }
    out
}

fn is_email(token: &str) -> bool {
    let Some((local, domain)) = token.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

fn redact_ipv4(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if let Some(len) = ipv4_char_len(&chars, i) {
            out.push_str("[redacted]");
            i += len;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn redact_ipv6(text: &str) -> String {
    let mut out = String::new();
    for token in split_keep(text) {
        if is_ipv6(trim_token(&token)) {
            out.push_str("[redacted]");
        } else {
            out.push_str(&token);
        }
    }
    out
}

fn is_ipv6(token: &str) -> bool {
    let host = token
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(token);
    let host = host.split('%').next().unwrap_or(host);
    let colons = host.chars().filter(|c| *c == ':').count();
    colons >= 2
        && host.contains(':')
        && host
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
}

fn ipv4_char_len(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    let mut parts = 0;
    while parts < 4 {
        let mut digits = 0;
        let part_start = i;
        while i < chars.len() && chars[i].is_ascii_digit() && digits < 3 {
            digits += 1;
            i += 1;
        }
        if digits == 0 {
            return None;
        }
        let value: u32 = chars[part_start..i]
            .iter()
            .collect::<String>()
            .parse()
            .ok()?;
        if value > 255 {
            return None;
        }
        parts += 1;
        if parts == 4 {
            return Some(i - start);
        }
        if i >= chars.len() || chars[i] != '.' {
            return None;
        }
        i += 1;
    }
    None
}

fn redact_paths(text: &str) -> String {
    let mut out = String::new();
    for token in split_keep(text) {
        if is_private_path(&token) {
            out.push_str("[redacted]");
        } else {
            out.push_str(&token);
        }
    }
    out
}

fn is_private_path(token: &str) -> bool {
    let trimmed = trim_token(token);
    if trimmed.len() > 1 && trimmed.starts_with('/') {
        return true;
    }
    trimmed.len() > 3
        && trimmed.as_bytes()[0].is_ascii_alphabetic()
        && trimmed.as_bytes().get(1) == Some(&b':')
        && trimmed.as_bytes().get(2) == Some(&b'\\')
}

fn redact_foreign_refs(text: &str, allowed: &str) -> String {
    let mut out = String::new();
    for token in split_keep(text) {
        let trimmed = trim_token(&token);
        if is_foreign_issue_ref(trimmed, allowed) {
            out.push_str("[redacted]");
        } else {
            out.push_str(&token);
        }
    }
    out
}

fn is_foreign_issue_ref(token: &str, allowed: &str) -> bool {
    let token = token.strip_prefix("https://github.com/").unwrap_or(token);
    let token = token.strip_prefix("github.com/").unwrap_or(token);
    let Some((repo, rest)) = token.split_once('#') else {
        if let Some((owner, repo)) = token.split_once('/')
            && !owner.is_empty()
            && !repo.is_empty()
            && !repo.contains('/')
            && owner
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && repo
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            && format!("{owner}/{repo}") != allowed
            && owner != "http"
            && owner != "https"
        {
            return token.starts_with("github.com/") || token.contains("/issues/");
        }
        return token.contains("/issues/") && !token.contains(allowed);
    };
    let repo = repo.trim_end_matches("/issues");
    rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() && repo != allowed
}

fn redact_hostnames(text: &str) -> String {
    let mut out = String::new();
    for token in split_keep(text) {
        let trimmed = trim_token(&token);
        if is_private_host(trimmed) {
            out.push_str("[redacted]");
        } else {
            out.push_str(&token);
        }
    }
    out
}

fn is_private_host(token: &str) -> bool {
    let token = token.strip_prefix("http://").unwrap_or(token);
    let token = token.strip_prefix("https://").unwrap_or(token);
    let host = token.split('/').next().unwrap_or(token);
    let host = host.split(':').next().unwrap_or(host);
    if host.eq_ignore_ascii_case("github.com") {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && labels
            .last()
            .is_some_and(|label| label.len() >= 2 && label.chars().all(|c| c.is_ascii_alphabetic()))
}

fn split_keep(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            tokens.push(ch.to_string());
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}
