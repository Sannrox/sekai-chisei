//! Qualifying feedback findings as GitHub issues (#1232, out of the plane).
//!
//! Publication is a source writeback (`source_writeback.rs`): the issue tracker
//! is the [`SourceSystem`], and every create or update goes through the permit,
//! Action, and execution-evidence path there.
//!
//! - Each (namespace, problem signature) owns one issue, found by a public
//!   marker in its body. The marker is the writeback key, so a marker written
//!   for another namespace never matches. Only the body's first line counts,
//!   so a marker quoted in maintainer text never matches.
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
//! an allowlist, not a redaction: a signature part is published only when it
//! is plain identifier text and the version only when it is semver. Anything
//! else, hosts, paths, addresses, and markup included, becomes `unspecified`.
//! Model text is never published.

use std::collections::{BTreeMap, BTreeSet};

use sekai_chisei::grpc::pb::sekai::sekai_service_server::SekaiService;
use sekai_chisei::grpc::pb::sekai::{
    GetObjectRequest, ListFilter, ListObjectsRequest, Object, PropertyFilter,
};
use sekai_chisei::grpc::sekai_service::SekaiServiceImpl;
use sekai_chisei::sekai::feedback_package::{KIND_INVESTIGATION_RESULT, KIND_OBSERVATION};
use sha2::{Digest, Sha256};
use tonic::metadata::MetadataValue;
use tonic::{Code, Request};

use crate::feedback_investigation::{
    InvestigationAnalysis, observation_view, publication_permitted, runtime_investigation,
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
const UNSPECIFIED: &str = "unspecified";

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
            .find(|issue| issue.body.starts_with(&needle)))
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
                &merge_maintainer_body(&issue.body, managed)?,
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
        // A measured reproduction can share the observation; only the bucket
        // analysis parses as one.
        let analysis = self
            .list(sekai, KIND_INVESTIGATION_RESULT, "observation_id", &anchor)
            .await?
            .iter()
            .filter(|investigation| runtime_investigation(investigation))
            .find_map(|investigation| {
                serde_json::from_str::<InvestigationAnalysis>(
                    investigation.properties.get("outcome")?,
                )
                .ok()
            });
        // The same plane-recorded check filing used, never the model's own claim.
        let measured = self.measured_reproduction(sekai, &signature).await?;
        let observations = self
            .list(sekai, KIND_OBSERVATION, "problem_signature", &signature)
            .await?;
        let draft = draft(
            &self.namespace,
            &signature,
            analysis.as_ref(),
            measured,
            &observations,
        );

        let marker = public_marker(&self.namespace, &signature);
        let issues = tracker.own_issues()?;
        let current = issues
            .iter()
            .find(|issue| issue.body.starts_with(&marker_comment(&marker)));
        if let Some(issue) = current
            && maintainer_text(&issue.body).is_none()
        {
            return Err(format!(
                "issue #{} lost its managed end marker; restore it to resume updates",
                issue.number
            ));
        }
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

    /// A runtime-recorded measured reproduction of any observation with this
    /// signature, matching the investigator's filing check.
    async fn measured_reproduction(
        &self,
        sekai: &SekaiServiceImpl,
        signature: &str,
    ) -> Result<bool, String> {
        let measured = self
            .list(sekai, KIND_INVESTIGATION_RESULT, "measured", "true")
            .await?;
        for result in measured
            .iter()
            .filter(|result| runtime_investigation(result))
        {
            let Some(observation_id) = result.properties.get("observation_id") else {
                continue;
            };
            if self
                .get(sekai, observation_id)
                .await?
                .filter(|observation| observation.namespace == self.namespace)
                .as_ref()
                .and_then(observation_view)
                .is_some_and(|view| view.problem_signature == signature)
            {
                return Ok(true);
            }
        }
        Ok(false)
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

/// Public title and managed section for one signature. Producer text enters
/// only through [`public_token`] and [`public_version`].
pub fn draft(
    namespace: &str,
    signature: &str,
    analysis: Option<&InvestigationAnalysis>,
    measured: bool,
    observations: &[Object],
) -> IssueDraft {
    // The reason is the last segment, as filing reads it.
    let (operation, reason) = signature.rsplit_once(':').unwrap_or((signature, ""));
    let (operation, reason) = (public_token(operation), public_token(reason));
    let attribution = analysis
        .and_then(|analysis| serde_json::to_value(analysis.attribution).ok())
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| UNSPECIFIED.into());
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
        .unwrap_or(UNSPECIFIED);
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
        title: public_title(operation, reason),
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
/// Refuses when the end marker is gone: there is no telling where
/// maintainer text starts, and guessing would drop or duplicate it.
pub fn merge_maintainer_body(existing: &str, managed: &str) -> Result<String, String> {
    let maintainer = maintainer_text(existing).ok_or("managed end marker missing")?;
    Ok(if maintainer.is_empty() {
        managed.to_string()
    } else {
        format!("{managed}\n\n{maintainer}")
    })
}

/// Text below the managed section, or `None` without its end marker.
pub fn maintainer_text(body: &str) -> Option<String> {
    body.find(MANAGED_END)
        .map(|index| body[index + MANAGED_END.len()..].trim().to_string())
}

/// Issues this adapter created today (UTC), across all markers.
pub fn new_issues_today(issues: &[GitHubIssue], now_ms: i64) -> u32 {
    let day = now_ms.div_euclid(DAY_MS);
    let prefix = format!("<!-- {MARKER_PREFIX}");
    issues
        .iter()
        .filter(|issue| {
            issue.created_ms.div_euclid(DAY_MS) == day && issue.body.starts_with(&prefix)
        })
        .count() as u32
}

/// One signature part, published only as plain identifier text: an ASCII
/// letter, then letters, digits, `_` and `-`, at most 64 characters. Anything
/// else could carry a host, path, address part, mention, or markup, so it is
/// not published.
fn public_token(text: &str) -> &str {
    let text = text.trim();
    let plain = text.starts_with(|c: char| c.is_ascii_alphabetic())
        && text.len() <= 64
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
    if plain { text } else { UNSPECIFIED }
}

/// `MAJOR.MINOR.PATCH`, optionally `-alpha`, `-beta` or `-rc` with a number.
/// Free-form pre-release and build suffixes can carry hosts or names.
fn public_version(raw: &str) -> Option<&str> {
    let version = raw.trim();
    let (core, pre) = version.split_once('-').unwrap_or((version, ""));
    let numeric = |part: &str| {
        !part.is_empty() && part.len() <= 9 && part.chars().all(|c| c.is_ascii_digit())
    };
    let core_ok = core.split('.').count() == 3 && core.split('.').all(numeric);
    let pre_ok = pre.is_empty() || {
        let (label, number) = pre.split_once('.').unwrap_or((pre, "1"));
        matches!(label, "alpha" | "beta" | "rc") && numeric(number)
    };
    (core_ok && pre_ok).then_some(version)
}

fn public_title(operation: &str, reason: &str) -> String {
    let mut title = format!("feedback: {operation}");
    if reason != UNSPECIFIED {
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
