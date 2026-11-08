//! Publish qualifying feedback findings to one configured GitHub repository (#1232).
//!
//! The plane actor authorizes an external action, redeems the permit, mutates
//! only the configured repository at the bound API origin, and records
//! execution evidence plus a durable `feedback_external_issue` mapping. A lost
//! create or update is pending reconciliation: the next pass lists issues for
//! the public marker and never retries the mutation blindly.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::Object;
use crate::sekai::action_describe_preview::object_revision;
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
};
use crate::sekai::evidence::{
    EVIDENCE_ENVELOPE_VERSION, EvidenceClassification, EvidenceEnvelope, EvidenceIntent,
    EvidenceSignal, EvidenceTarget, SchemaCompatibility,
};
use crate::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle;
use crate::sekai::evidence_store::{
    EvidenceProducerCapability, EvidenceSchemaDefinition, canonical_content_digest,
};
use crate::sekai::execution_evidence::{
    EXECUTION_EVIDENCE_SCHEMA, EXECUTION_EVIDENCE_TYPE, ExecutionEvidence, ExecutionLifecycleState,
};
use crate::sekai::feedback_investigation::{
    eq_property, github_dispatch_permitted, list_feedback_objects, observation_view,
    parse_occurrence_ids, runtime_recorded,
};
use crate::sekai::feedback_package::{
    ACTION_EXTERNAL_ISSUE, KIND_EXTERNAL_ISSUE, KIND_FINDING, KIND_INVESTIGATION_RESULT,
    KIND_OBSERVATION, PACKAGE_VERSION,
};
use crate::sekai::governed_action_type::{
    EFFECT_KIND_NOTIFY, GovernedActionType, OBJECT_MUTATION_UPDATE,
};
use crate::sekai::object_security::PrincipalPolicyContext;

pub const RUNTIME_ID: &str = "feedback-github";
pub const POLL_INTERVAL_SECS: u64 = 15;
pub const DEFAULT_DAILY_CAP: u32 = 5;
pub const TRACKER: &str = "github";
pub const ACTION_BIND: &str = "feedback.external_issue.bind";
pub const EXECUTOR: &str = "executor:github-issues";
pub const HARNESS: &str = "harness:feedback-github";
pub const HOST_CAPABILITY: &str = "github.issues.write/v1";
pub const EXTERNAL_ACTION_TYPE: &str = "github.issues.mutate/v1";
pub const PARAMETER_SCHEMA: &str = "github.issues.mutate.params/v1";

const _: () = assert!(POLL_INTERVAL_SECS * 8 <= 120);
const _: () = assert!(DEFAULT_DAILY_CAP == 5);

const REMOTE_PENDING_QUEUED: &str = "pending:queued";
const REMOTE_PENDING_RECONCILE: &str = "pending:reconcile";
const REMOTE_PENDING_INFLIGHT: &str = "pending:inflight:";
const MANAGED_END: &str = "<!-- /sekai-feedback -->";
const DAY_MS: i64 = 86_400_000;
const INFLIGHT_TTL_MS: i64 = 60_000;
const PERMIT_TTL_MS: i64 = 3_600_000;

/// Configured public Tenkai repository the executor may write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubTarget {
    pub owner: String,
    pub repo: String,
    pub daily_cap: u32,
}

impl GitHubTarget {
    pub fn parse(owner: &str, repo: &str, daily_cap: u32) -> Option<Self> {
        let owner = owner.trim();
        let repo = repo.trim();
        if owner.is_empty() || repo.is_empty() || owner.contains('/') || repo.contains('/') {
            return None;
        }
        Some(Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            daily_cap: if daily_cap == 0 {
                DEFAULT_DAILY_CAP
            } else {
                daily_cap
            },
        })
    }

    pub fn repository(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    pub fn remote_id(&self, number: u64) -> String {
        format!("github:{}#{}", self.repository(), number)
    }

    pub fn matches_remote(&self, remote_id: &str) -> bool {
        remote_id
            .strip_prefix("github:")
            .and_then(|rest| rest.split_once('#'))
            .is_some_and(|(repo, _)| repo == self.repository())
    }
}

/// Scheme and host (optional port) of the GitHub API URL. Path and query are
/// dropped. Userinfo, percent-encoding, whitespace, and control characters are
/// refused so the permit cannot bind a credential or a host that HTTP parsing
/// would rewrite.
pub fn github_api_origin(api_url: &str) -> Option<String> {
    let raw = api_url.trim();
    let (scheme, rest) = raw
        .strip_prefix("https://")
        .map(|rest| ("https", rest))
        .or_else(|| raw.strip_prefix("http://").map(|rest| ("http", rest)))?;
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    if hostport.is_empty()
        || hostport.contains(['@', '\\', '%'])
        || hostport
            .chars()
            .any(|ch| ch.is_ascii_whitespace() || ch.is_ascii_control())
    {
        return None;
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty()
                && !host.contains(':')
                && !port.is_empty()
                && port.chars().all(|ch| ch.is_ascii_digit()) =>
        {
            (host, Some(port))
        }
        _ if hostport.contains(':') => return None,
        _ => (hostport, None),
    };
    if host.is_empty() {
        return None;
    }
    match port {
        Some(port) => Some(format!("{scheme}://{host}:{port}")),
        None => Some(format!("{scheme}://{host}")),
    }
}

/// Plane actor that authorizes and redeems. Empty defaults to [`RUNTIME_ID`].
/// Privileged bootstrap principals are refused.
pub fn publisher_principal(run_as: &str) -> Option<String> {
    let value = run_as.trim();
    if value.is_empty() {
        return Some(RUNTIME_ID.into());
    }
    if matches!(value, "root" | "local") {
        return None;
    }
    Some(value.into())
}

pub fn permit_target_selectors(
    namespace: &str,
    target: &GitHubTarget,
    api_origin: &str,
) -> Vec<String> {
    // v1 permits refuse `://` in selectors; scheme stays in api_origin preconditions.
    let hostport = api_origin
        .strip_prefix("https://")
        .or_else(|| api_origin.strip_prefix("http://"))
        .unwrap_or(api_origin);
    vec![
        format!("project:{}/github:{}", namespace, target.repository()),
        format!("project:{namespace}/github-api:{hostport}"),
    ]
}

pub fn permit_preconditions(target: &GitHubTarget, api_origin: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("repository".into(), target.repository()),
        ("api_origin".into(), api_origin.into()),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubIssue {
    pub number: u64,
    pub title: String,
    pub body: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueDraft {
    pub title: String,
    pub managed_body: String,
    pub marker: String,
    pub signature: String,
    pub finding_id: String,
    pub namespace: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishIntent {
    pub operation: PublishOperation,
    pub draft: IssueDraft,
    pub arguments_digest: String,
    pub mapping_id: String,
    /// Inflight fence token for a create attempt. Distinct tokens get distinct
    /// permit keys so a failed create can authorize again after revert.
    pub attempt_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOperation {
    Create,
    Update { number: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitProof {
    pub permit_id: String,
    pub redemption_id: String,
    pub execution_id: String,
    pub operation_id: String,
    pub enforced_preconditions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReport {
    pub finding_id: String,
    pub mapping_id: String,
    pub remote_id: String,
    pub issue_number: u64,
    pub created: bool,
    pub proof: PermitProof,
}

#[derive(Debug)]
pub enum GitHubError {
    MissingCredentials,
    IssuesDisabled,
    RateLimited,
    Lost,
    Other(String),
}

#[derive(Debug)]
pub enum PermitError {
    Denied(String),
    Expired,
    Revoked,
    Mismatched,
    Missing,
}

#[derive(Debug)]
pub enum PublishError {
    NotQualifying,
    DailyCap,
    Retryable(String),
    Permit(PermitError),
    GitHub(GitHubError),
    Internal(String),
}

pub trait GitHubIssues {
    fn list(&self) -> Result<Vec<GitHubIssue>, GitHubError>;
    fn get(&self, number: u64) -> Result<GitHubIssue, GitHubError>;
    fn create(&self, title: &str, body: &str) -> Result<GitHubIssue, GitHubError>;
    fn update(&self, number: u64, title: &str, body: &str) -> Result<GitHubIssue, GitHubError>;
}

pub trait PermitGate {
    fn authorize_and_redeem(&self, intent: &PublishIntent) -> Result<PermitProof, PermitError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingState {
    Queued,
    Inflight,
    Reconcile,
    Published,
}

pub fn mapping_key(namespace: &str, signature: &str) -> String {
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{namespace}\0{signature}").as_bytes())
    );
    digest[..16].to_string()
}

pub fn mapping_object_id(namespace: &str, signature: &str) -> String {
    format!("fb-ext-{}", mapping_key(namespace, signature))
}

pub fn public_marker(namespace: &str, signature: &str) -> String {
    format!("sekai-feedback:{}", mapping_key(namespace, signature))
}

pub fn marker_comment(marker: &str) -> String {
    format!("<!-- {marker} -->")
}

pub fn arguments_digest(operation: PublishOperation, body: &str) -> String {
    let op = match operation {
        PublishOperation::Create => "create",
        PublishOperation::Update { number } => {
            return format!(
                "sha256:{:x}",
                Sha256::digest(format!("update\n{number}\n{body}\n").as_bytes())
            );
        }
    };
    format!(
        "sha256:{:x}",
        Sha256::digest(format!("{op}\n{body}\n").as_bytes())
    )
}

/// Permit operation id for one GitHub mutate intent.
///
/// Distinct arguments, update issue numbers, and create-attempt tokens get
/// distinct keys so a later contentful update or a failed create retry is not
/// refused as a digest conflict on an earlier row.
pub fn permit_operation_id(intent: &PublishIntent) -> String {
    let digest = digest_suffix(&intent.arguments_digest);
    match intent.operation {
        PublishOperation::Create => {
            let attempt = create_attempt_suffix(&intent.attempt_token);
            format!(
                "feedback-gh-{}-create-{digest}-{attempt}",
                intent.mapping_id
            )
        }
        PublishOperation::Update { number } => {
            format!("feedback-gh-{}-update-{number}-{digest}", intent.mapping_id)
        }
    }
}

/// Deadline encoded in the permit request for `intent`.
///
/// Create attempts use the inflight claim time so the digest is stable for that
/// fence. Updates bucket wall-clock time into `PERMIT_TTL_MS` windows so a
/// same-body refresh inside the window replays instead of conflicting.
pub fn permit_deadline_ms(intent: &PublishIntent, now_ms: i64) -> i64 {
    if let Some(started) = inflight_started_ms(&intent.attempt_token) {
        return started.saturating_add(PERMIT_TTL_MS);
    }
    let bucket = now_ms.div_euclid(PERMIT_TTL_MS).saturating_add(2);
    bucket.saturating_mul(PERMIT_TTL_MS)
}

fn digest_suffix(digest: &str) -> &str {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let end = hex.len().min(16);
    &hex[..end]
}

fn create_attempt_suffix(token: &str) -> &str {
    token
        .strip_prefix(REMOTE_PENDING_INFLIGHT)
        .and_then(|value| value.rsplit_once(':'))
        .map(|(_, attempt)| attempt)
        .filter(|attempt| !attempt.is_empty())
        .unwrap_or("missing")
}

pub fn utc_day(now_ms: i64) -> i64 {
    now_ms.div_euclid(DAY_MS)
}

pub fn mapping_state(remote_id: &str) -> MappingState {
    if remote_id == REMOTE_PENDING_RECONCILE {
        MappingState::Reconcile
    } else if remote_id.starts_with(REMOTE_PENDING_INFLIGHT) {
        MappingState::Inflight
    } else if remote_id.starts_with("github:") {
        MappingState::Published
    } else {
        MappingState::Queued
    }
}

pub fn published_number(remote_id: &str, target: &GitHubTarget) -> Option<u64> {
    if !target.matches_remote(remote_id) {
        return None;
    }
    remote_id
        .rsplit_once('#')
        .and_then(|(_, number)| number.parse().ok())
}

/// Register the update Action that binds a GitHub issue onto an external-issue object.
pub fn ensure_adapter_types(
    db: &RuntimeDb,
    namespace: &str,
    actor: &str,
    now_ms: i64,
) -> Result<(), String> {
    db.put_governed_action_type(
        GovernedActionType {
            namespace: namespace.into(),
            type_id: ACTION_BIND.into(),
            version: PACKAGE_VERSION.into(),
            description: "Bind a GitHub issue identifier onto an external-issue reference".into(),
            parameter_schema_json: r#"{"type":"object","properties":{"object_id":{"type":"string"},"name":{"type":"string"},"finding_id":{"type":"string"},"tracker":{"type":"string"},"remote_id":{"type":"string"}},"required":["object_id","finding_id","tracker","remote_id"],"additionalProperties":false}"#.into(),
            allowed_effect_kinds: vec![EFFECT_KIND_NOTIFY.into()],
            object_kind: KIND_EXTERNAL_ISSUE.into(),
            object_mutation: OBJECT_MUTATION_UPDATE.into(),
            enabled: true,
            created_by: actor.into(),
            ..Default::default()
        },
        actor,
        now_ms,
    )?;
    db.register_evidence_schema(
        &EvidenceSchemaDefinition {
            schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
            evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
            compatible_versions: vec![],
        },
        now_ms,
    )?;
    match db.upsert_evidence_producer(
        &EvidenceProducerCapability {
            producer_identity: EXECUTOR.into(),
            config_version: 1,
            source_types: vec!["host_executor".into()],
            source_instances: vec![format!("{EXECUTOR}:github")],
            namespaces: vec![namespace.into()],
            evidence_types: vec![EXECUTION_EVIDENCE_TYPE.into()],
            target_kinds: vec![KIND_FINDING.into(), KIND_EXTERNAL_ISSUE.into()],
            classification_ceiling: EvidenceClassification::Internal,
            allowed_intents: vec![EvidenceIntent::Upsert],
            allow_operation_attachment: true,
            replay_window_ms: 60_000,
            max_clock_skew_ms: 60_000,
            max_payload_bytes: 64 * 1024,
            max_relationships: 8,
            rate_limit_per_minute: 100,
            max_retained_submissions: 100,
            revoked: false,
        },
        now_ms,
    ) {
        Ok(()) => Ok(()),
        Err(error) if error.contains("must increase") => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn sanitize_public_text(text: &str, target: &GitHubTarget) -> String {
    let mut out = redact_secrets(text);
    out = redact_emails(&out);
    out = redact_ipv4(&out);
    out = redact_ipv6(&out);
    out = redact_paths(&out);
    out = redact_foreign_refs(&out, target);
    redact_hostnames(&out, target)
}

pub fn compose_managed_body(draft: &IssueDraft) -> String {
    format!(
        "{}\n{}\n{}",
        marker_comment(&draft.marker),
        draft.managed_body.trim(),
        MANAGED_END
    )
}

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
        None => {
            if body.contains("<!-- sekai-feedback:") {
                String::new()
            } else {
                body.trim().to_string()
            }
        }
    }
}

pub fn issue_has_marker(issue: &GitHubIssue, marker: &str) -> bool {
    issue.body.contains(&marker_comment(marker))
}

pub fn new_issues_today(issues: &[GitHubIssue], marker_prefix: &str, now_ms: i64) -> u32 {
    let day = utc_day(now_ms);
    issues
        .iter()
        .filter(|issue| {
            utc_day(issue.created_ms) == day
                && issue.body.contains(&format!("<!-- {marker_prefix}"))
        })
        .count() as u32
}

/// Findings that may still need a create or an update, newest first per signature.
pub fn qualifying_findings(db: &RuntimeDb, namespace: &str) -> Result<Vec<Object>, PublishError> {
    let listed = list_feedback_objects(db, namespace, KIND_FINDING, Vec::new())
        .map_err(PublishError::Internal)?;
    let mut by_signature: BTreeMap<String, Object> = BTreeMap::new();
    for finding in listed {
        if !github_dispatch_permitted(&finding) {
            continue;
        }
        let Some(signature) = finding_signature(db, &finding)? else {
            continue;
        };
        let entry = by_signature
            .entry(signature)
            .or_insert_with(|| finding.clone());
        if finding.created > entry.created
            || (finding.created == entry.created && finding.id > entry.id)
        {
            *entry = finding;
        }
    }
    let mut findings: Vec<Object> = by_signature.into_values().collect();
    findings.sort_by(|left, right| {
        left.created
            .cmp(&right.created)
            .then(left.id.cmp(&right.id))
    });
    Ok(findings)
}

pub fn draft_from_finding(
    db: &RuntimeDb,
    finding: &Object,
    target: &GitHubTarget,
) -> Result<IssueDraft, PublishError> {
    if !github_dispatch_permitted(finding) {
        return Err(PublishError::NotQualifying);
    }
    let signature = finding_signature(db, finding)?
        .ok_or_else(|| PublishError::Internal("finding observation is missing".into()))?;
    let observation_id = finding
        .properties
        .get("observation_id")
        .cloned()
        .unwrap_or_default();
    let investigation = related_object(
        db,
        &finding.namespace,
        KIND_INVESTIGATION_RESULT,
        &observation_id,
    )?;
    let outcome = investigation
        .as_ref()
        .and_then(|object| object.properties.get("outcome"))
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
    let (operation, reason) = signature_parts(&signature);
    let operation = public_token(&sanitize_public_text(&operation, target));
    let reason = public_token(&sanitize_public_text(&reason, target));
    let attribution = public_attribution(outcome.as_ref());
    let (observation_count, operation_count, version) =
        recurrence_fields(db, &finding.namespace, &signature, target)?;
    let measured = investigation
        .as_ref()
        .and_then(|object| object.properties.get("measured"))
        .map(String::as_str)
        == Some("true");
    let title = public_title(&operation, &reason);
    let reproduction = if measured {
        "Measured."
    } else {
        "Not independently measured."
    };
    let managed = format!(
        "## Operation\n\n{operation}\n\n## Reason\n\n{reason}\n\n## Attribution\n\n{attribution}\n\n## Recurrence\n\n{observation_count} observations across {operation_count} operations.\n\n## Controller version\n\n{version}\n\n## Reproduction\n\n{reproduction}\n\n## Acceptance\n\nA measured verification of the investigation result confirms the documented reproduction no longer fails."
    );
    Ok(IssueDraft {
        title,
        managed_body: managed,
        marker: public_marker(&finding.namespace, &signature),
        signature,
        finding_id: finding.id.clone(),
        namespace: finding.namespace.clone(),
    })
}

/// One finding: fence a mapping, reconcile through GitHub listing, then create or update.
pub fn publish_finding(
    db: &RuntimeDb,
    github: &dyn GitHubIssues,
    permits: &dyn PermitGate,
    target: &GitHubTarget,
    finding: &Object,
    actor: &str,
    now_ms: i64,
) -> Result<PublishReport, PublishError> {
    let draft = draft_from_finding(db, finding, target)?;
    ensure_adapter_types(db, &draft.namespace, actor, now_ms).map_err(PublishError::Internal)?;
    let mapping_id = mapping_object_id(&draft.namespace, &draft.signature);
    let mapping = fence_mapping(db, actor, &draft, &mapping_id, now_ms)?;
    let listed = match github.list() {
        Ok(issues) => issues,
        Err(GitHubError::MissingCredentials) => {
            return Err(PublishError::GitHub(GitHubError::MissingCredentials));
        }
        Err(GitHubError::RateLimited) => {
            return Err(PublishError::GitHub(GitHubError::RateLimited));
        }
        Err(error) => return Err(PublishError::GitHub(error)),
    };
    let matched = listed
        .iter()
        .find(|issue| issue_has_marker(issue, &draft.marker))
        .cloned();
    let remote = mapping
        .properties
        .get("remote_id")
        .map(String::as_str)
        .unwrap_or(REMOTE_PENDING_QUEUED);
    let state = mapping_state(remote);
    let managed = compose_managed_body(&draft);

    if let Some(issue) = matched {
        return update_existing(
            db,
            github,
            permits,
            target,
            &draft,
            &mapping_id,
            actor,
            now_ms,
            issue,
            &managed,
            false,
        );
    }
    if let Some(number) = published_number(remote, target) {
        let issue = github.get(number).map_err(PublishError::GitHub)?;
        return update_existing(
            db,
            github,
            permits,
            target,
            &draft,
            &mapping_id,
            actor,
            now_ms,
            issue,
            &managed,
            false,
        );
    }
    if state == MappingState::Reconcile {
        return Err(PublishError::Retryable(
            "create response is pending reconciliation".into(),
        ));
    }
    if state == MappingState::Inflight {
        let age = inflight_age_ms(remote, now_ms).unwrap_or(0);
        if age < INFLIGHT_TTL_MS {
            return Err(PublishError::Retryable(
                "another publisher holds the create fence".into(),
            ));
        }
    }
    let created_today = new_issues_today(&listed, "sekai-feedback:", now_ms);
    if created_today >= target.daily_cap {
        return Err(PublishError::DailyCap);
    }
    let attempt_token = claim_inflight(db, actor, &draft, &mapping, now_ms)?;
    let intent = PublishIntent {
        operation: PublishOperation::Create,
        arguments_digest: arguments_digest(PublishOperation::Create, &managed),
        mapping_id: mapping_id.clone(),
        attempt_token,
        draft: draft.clone(),
    };
    let proof = match permits.authorize_and_redeem(&intent) {
        Ok(proof) => proof,
        Err(error) => {
            revert_mapping(
                db,
                actor,
                &draft,
                &mapping_id,
                REMOTE_PENDING_QUEUED,
                now_ms,
            );
            return Err(PublishError::Permit(error));
        }
    };
    match github.create(&draft.title, &managed) {
        Ok(issue) => finish_published(
            db,
            target,
            &draft,
            &mapping_id,
            actor,
            now_ms,
            issue,
            proof,
            true,
        ),
        Err(GitHubError::Lost) => {
            bind_mapping(
                db,
                actor,
                &draft,
                &mapping_id,
                REMOTE_PENDING_RECONCILE,
                "",
                now_ms,
            )?;
            let _ = record_publish_evidence(
                db,
                actor,
                target,
                &draft,
                &proof,
                evidence_lifecycle_for(Some(&GitHubError::Lost)),
                now_ms,
            );
            Err(PublishError::GitHub(GitHubError::Lost))
        }
        Err(error) => {
            revert_mapping(
                db,
                actor,
                &draft,
                &mapping_id,
                REMOTE_PENDING_QUEUED,
                now_ms,
            );
            let _ = record_publish_evidence(
                db,
                actor,
                target,
                &draft,
                &proof,
                evidence_lifecycle_for(Some(&error)),
                now_ms,
            );
            Err(PublishError::GitHub(error))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn update_existing(
    db: &RuntimeDb,
    github: &dyn GitHubIssues,
    permits: &dyn PermitGate,
    target: &GitHubTarget,
    draft: &IssueDraft,
    mapping_id: &str,
    actor: &str,
    now_ms: i64,
    issue: GitHubIssue,
    managed: &str,
    created: bool,
) -> Result<PublishReport, PublishError> {
    let body = merge_maintainer_body(&issue.body, managed);
    let intent = PublishIntent {
        operation: PublishOperation::Update {
            number: issue.number,
        },
        arguments_digest: arguments_digest(
            PublishOperation::Update {
                number: issue.number,
            },
            &body,
        ),
        mapping_id: mapping_id.to_string(),
        attempt_token: String::new(),
        draft: draft.clone(),
    };
    let proof = permits
        .authorize_and_redeem(&intent)
        .map_err(PublishError::Permit)?;
    match github.update(issue.number, &draft.title, &body) {
        Ok(updated) => finish_published(
            db, target, draft, mapping_id, actor, now_ms, updated, proof, created,
        ),
        Err(GitHubError::Lost) => {
            bind_mapping(
                db,
                actor,
                draft,
                mapping_id,
                &target.remote_id(issue.number),
                "",
                now_ms,
            )?;
            let _ = record_publish_evidence(
                db,
                actor,
                target,
                draft,
                &proof,
                evidence_lifecycle_for(Some(&GitHubError::Lost)),
                now_ms,
            );
            Err(PublishError::GitHub(GitHubError::Lost))
        }
        Err(error) => {
            let _ = record_publish_evidence(
                db,
                actor,
                target,
                draft,
                &proof,
                evidence_lifecycle_for(Some(&error)),
                now_ms,
            );
            Err(PublishError::GitHub(error))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_published(
    db: &RuntimeDb,
    target: &GitHubTarget,
    draft: &IssueDraft,
    mapping_id: &str,
    actor: &str,
    now_ms: i64,
    issue: GitHubIssue,
    proof: PermitProof,
    created: bool,
) -> Result<PublishReport, PublishError> {
    let remote_id = target.remote_id(issue.number);
    bind_mapping(db, actor, draft, mapping_id, &remote_id, "", now_ms)?;
    let _ = record_publish_evidence(
        db,
        actor,
        target,
        draft,
        &proof,
        evidence_lifecycle_for(None),
        now_ms,
    );
    Ok(PublishReport {
        finding_id: draft.finding_id.clone(),
        mapping_id: mapping_id.to_string(),
        remote_id,
        issue_number: issue.number,
        created,
        proof,
    })
}

fn mapping_belongs(object: &Object, namespace: &str) -> bool {
    object.namespace == namespace && object.kind == KIND_EXTERNAL_ISSUE
}

fn occupied_mapping_error() -> PublishError {
    PublishError::Retryable("mapping id occupied by a foreign or mismatched object".into())
}

/// Mapping used for GitHub publish, or `None` when the id is missing or not owned.
fn owned_mapping(
    db: &RuntimeDb,
    namespace: &str,
    mapping_id: &str,
) -> Result<Option<Object>, PublishError> {
    let Some(object) = db.get_object(mapping_id).map_err(PublishError::Internal)? else {
        return Ok(None);
    };
    if mapping_belongs(&object, namespace) {
        Ok(Some(object))
    } else {
        Ok(None)
    }
}

/// Admit this namespace's mapping, or fail closed if the id belongs elsewhere.
fn fence_mapping(
    db: &RuntimeDb,
    actor: &str,
    draft: &IssueDraft,
    mapping_id: &str,
    now_ms: i64,
) -> Result<Object, PublishError> {
    if let Some(object) = owned_mapping(db, &draft.namespace, mapping_id)? {
        return Ok(object);
    }
    if db
        .get_object(mapping_id)
        .map_err(PublishError::Internal)?
        .is_some()
    {
        return Err(occupied_mapping_error());
    }
    match admit(
        db,
        actor,
        &draft.namespace,
        ACTION_EXTERNAL_ISSUE,
        serde_json::json!({
            "object_id": mapping_id,
            "name": draft.marker,
            "finding_id": draft.finding_id,
            "tracker": TRACKER,
            "remote_id": REMOTE_PENDING_QUEUED,
        }),
        &format!(
            "feedback:ext:{}",
            mapping_key(&draft.namespace, &draft.signature)
        ),
        "",
        now_ms,
    ) {
        Ok(()) => {}
        Err(PublishError::Internal(error))
            if error.contains("already exists") || error.contains("AlreadyExists") => {}
        Err(error) => return Err(error),
    }
    match owned_mapping(db, &draft.namespace, mapping_id)? {
        Some(object) => Ok(object),
        None if db
            .get_object(mapping_id)
            .map_err(PublishError::Internal)?
            .is_some() =>
        {
            Err(occupied_mapping_error())
        }
        None => Err(PublishError::Internal("mapping fence disappeared".into())),
    }
}

fn claim_inflight(
    db: &RuntimeDb,
    actor: &str,
    draft: &IssueDraft,
    mapping: &Object,
    now_ms: i64,
) -> Result<String, PublishError> {
    let token = format!(
        "{REMOTE_PENDING_INFLIGHT}{now_ms}:{}",
        uuid::Uuid::new_v4().simple()
    );
    bind_mapping(
        db,
        actor,
        draft,
        &mapping.id,
        &token,
        &object_revision(mapping),
        now_ms,
    )?;
    let stored =
        owned_mapping(db, &draft.namespace, &mapping.id)?.ok_or_else(occupied_mapping_error)?;
    if stored.properties.get("remote_id").map(String::as_str) == Some(token.as_str()) {
        Ok(token)
    } else {
        Err(PublishError::Retryable(
            "another publisher holds the create fence".into(),
        ))
    }
}

fn inflight_started_ms(remote_id: &str) -> Option<i64> {
    remote_id
        .strip_prefix(REMOTE_PENDING_INFLIGHT)
        .and_then(|value| value.split(':').next())
        .and_then(|value| value.parse().ok())
}

fn inflight_age_ms(remote_id: &str, now_ms: i64) -> Option<i64> {
    inflight_started_ms(remote_id).map(|started| now_ms.saturating_sub(started))
}

fn revert_mapping(
    db: &RuntimeDb,
    actor: &str,
    draft: &IssueDraft,
    mapping_id: &str,
    remote_id: &str,
    now_ms: i64,
) {
    let Some(object) = owned_mapping(db, &draft.namespace, mapping_id)
        .ok()
        .flatten()
    else {
        return;
    };
    let _ = bind_mapping(
        db,
        actor,
        draft,
        mapping_id,
        remote_id,
        &object_revision(&object),
        now_ms,
    );
}

fn bind_mapping(
    db: &RuntimeDb,
    actor: &str,
    draft: &IssueDraft,
    mapping_id: &str,
    remote_id: &str,
    expected_revision: &str,
    now_ms: i64,
) -> Result<(), PublishError> {
    admit(
        db,
        actor,
        &draft.namespace,
        ACTION_BIND,
        serde_json::json!({
            "object_id": mapping_id,
            "name": draft.marker,
            "finding_id": draft.finding_id,
            "tracker": TRACKER,
            "remote_id": remote_id,
        }),
        &format!(
            "feedback:extbind:{}:{}:{}",
            mapping_key(&draft.namespace, &draft.signature),
            remote_id.replace(['/', '#'], ":"),
            uuid::Uuid::new_v4().simple()
        ),
        expected_revision,
        now_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn admit(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    type_id: &str,
    parameters: serde_json::Value,
    idempotency_key: &str,
    expected_object_revision: &str,
    now_ms: i64,
) -> Result<(), PublishError> {
    match ActionInstanceAdmission::new(db, None).admit(
        ActionInstanceAdmissionRequest {
            agent_turn: None,
            namespace: namespace.into(),
            type_id: type_id.into(),
            version: PACKAGE_VERSION.into(),
            parameters_json: parameters.to_string(),
            idempotency_key: idempotency_key.into(),
            evidence_submission_ids: Vec::new(),
            request_id: String::new(),
            ontology_digest: String::new(),
            autonomous_envelope_id: String::new(),
            policy_context: PrincipalPolicyContext::default(),
            delegating_actor: None,
            budget_already_reserved: false,
            resource_tenant: String::new(),
            binding_markings: Vec::new(),
            source_object_id: String::new(),
            marking_gate: Default::default(),
            expected_object_revision: expected_object_revision.into(),
            offline: None,
        },
        actor,
        now_ms,
    ) {
        Ok(_) => Ok(()),
        Err(ActionInstanceAdmissionError::AlreadyExists(_)) => Ok(()),
        Err(ActionInstanceAdmissionError::FailedPrecondition(error))
            if error.contains("revision") || error.contains("already exists") =>
        {
            Err(PublishError::Retryable(error))
        }
        Err(error) => Err(PublishError::Internal(format!("{error:?}"))),
    }
}

fn record_publish_evidence(
    db: &RuntimeDb,
    actor: &str,
    target: &GitHubTarget,
    draft: &IssueDraft,
    proof: &PermitProof,
    state: ExecutionLifecycleState,
    now_ms: i64,
) -> Result<(), String> {
    db.register_evidence_schema(
        &EvidenceSchemaDefinition {
            schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
            evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
            compatible_versions: Vec::new(),
        },
        now_ms,
    )?;
    db.upsert_evidence_producer(
        &EvidenceProducerCapability {
            producer_identity: actor.into(),
            config_version: 1,
            source_types: vec!["host_executor".into()],
            source_instances: vec![format!("{actor}:github")],
            namespaces: vec![draft.namespace.clone()],
            evidence_types: vec![EXECUTION_EVIDENCE_TYPE.into()],
            target_kinds: vec![KIND_FINDING.into()],
            classification_ceiling: EvidenceClassification::Internal,
            allowed_intents: vec![EvidenceIntent::Upsert],
            allow_operation_attachment: true,
            replay_window_ms: 60_000,
            max_clock_skew_ms: 60_000,
            max_payload_bytes: 16_384,
            max_relationships: 8,
            rate_limit_per_minute: 60,
            max_retained_submissions: 1_000,
            revoked: false,
        },
        now_ms,
    )?;
    let report = ExecutionEvidence {
        version: EXECUTION_EVIDENCE_SCHEMA.into(),
        permit_id: proof.permit_id.clone(),
        redemption_id: proof.redemption_id.clone(),
        execution_id: proof.execution_id.clone(),
        host_identity: actor.into(),
        lifecycle_state: state,
        observed_at_ms: now_ms,
        started_at_ms: Some(now_ms),
        finished_at_ms: state.is_terminal().then_some(now_ms),
        enforced_preconditions: proof.enforced_preconditions.clone(),
        normalized_effects: vec!["issue_upserted".into()],
        affected_resource_references: vec![format!("github:{}", target.repository())],
        cost_micros: 0,
        resource_use: BTreeMap::new(),
        artifact_hashes: Vec::new(),
        exit_classification: String::new(),
        error_classification: String::new(),
        compensation_evidence_hashes: Vec::new(),
        host_schema_version: "host-evidence/v1".into(),
        host_software_version: "feedback-github/1".into(),
    };
    let content = serde_json::to_value(&report).map_err(|error| error.to_string())?;
    let envelope = EvidenceEnvelope {
        contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
        source_type: "host_executor".into(),
        source_instance: format!("{actor}:github"),
        source_record_id: proof.redemption_id.clone(),
        source_version: format!("state-{}", state.as_str()),
        source_sequence: 1,
        target: EvidenceTarget {
            namespace: draft.namespace.clone(),
            object_external_id: draft.finding_id.clone(),
            object_kind: KIND_FINDING.into(),
        },
        evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
        signal: EvidenceSignal::Delivery,
        schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
        schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
        schema_compatibility: SchemaCompatibility::Exact,
        observed_at_ms: now_ms,
        collected_at_ms: now_ms,
        expires_at_ms: None,
        content_digest: canonical_content_digest(&content)?,
        content,
        relationships: Vec::new(),
        producer_identity: actor.into(),
        confidence_bps: 8_000,
        classification: EvidenceClassification::Internal,
        provenance: BTreeMap::new(),
        idempotency_key: format!("{}-{}", proof.redemption_id, state.as_str()),
        intent: EvidenceIntent::Upsert,
        causality: None,
    };
    EvidenceAdmissionLifecycle::new(db)
        .admit(&envelope, actor, now_ms)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"))
}

fn finding_signature(db: &RuntimeDb, finding: &Object) -> Result<Option<String>, PublishError> {
    let Some(observation_id) = finding.properties.get("observation_id") else {
        return Ok(None);
    };
    let Some(observation) = db
        .get_object(observation_id)
        .map_err(PublishError::Internal)?
    else {
        return Ok(None);
    };
    if observation.kind != KIND_OBSERVATION {
        return Ok(None);
    }
    Ok(observation
        .properties
        .get("problem_signature")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string))
}

fn related_object(
    db: &RuntimeDb,
    namespace: &str,
    kind: &str,
    observation_id: &str,
) -> Result<Option<Object>, PublishError> {
    let listed = list_feedback_objects(
        db,
        namespace,
        kind,
        vec![eq_property("observation_id", observation_id)],
    )
    .map_err(PublishError::Internal)?;
    let mut fallback = None;
    for object in listed {
        if object.properties.get("observation_id").map(String::as_str) != Some(observation_id) {
            continue;
        }
        if kind == KIND_INVESTIGATION_RESULT && !runtime_recorded(&object) {
            continue;
        }
        let parses_analysis = object
            .properties
            .get("outcome")
            .is_some_and(|raw| serde_json::from_str::<serde_json::Value>(raw).is_ok());
        if parses_analysis {
            return Ok(Some(object));
        }
        if fallback.is_none() {
            fallback = Some(object);
        }
    }
    Ok(fallback)
}

fn signature_parts(signature: &str) -> (String, String) {
    match signature.rsplit_once(':') {
        Some((operation, reason)) => (operation.to_string(), reason.to_string()),
        None => (signature.to_string(), String::new()),
    }
}

fn public_token(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "[redacted]" {
        "unspecified".into()
    } else {
        trimmed.to_string()
    }
}

fn public_attribution(outcome: Option<&serde_json::Value>) -> &'static str {
    match outcome
        .and_then(|value| value.get("attribution"))
        .and_then(serde_json::Value::as_str)
    {
        Some("tenkai") => "tenkai",
        Some("application") => "application",
        Some("expected_wait") => "expected_wait",
        Some("cancellation") => "cancellation",
        Some("inconclusive") => "inconclusive",
        Some("malformed") => "malformed",
        _ => "unspecified",
    }
}

fn public_version(raw: &str) -> Option<&str> {
    let version = raw.trim();
    if version.is_empty() || version.len() > 32 {
        return None;
    }
    version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
        .then_some(version)
}

fn recurrence_fields(
    db: &RuntimeDb,
    namespace: &str,
    signature: &str,
    target: &GitHubTarget,
) -> Result<(usize, usize, String), PublishError> {
    let listed = list_feedback_objects(
        db,
        namespace,
        KIND_OBSERVATION,
        vec![eq_property("problem_signature", signature)],
    )
    .map_err(PublishError::Internal)?;
    let mut operations = BTreeSet::new();
    let mut version = String::new();
    let mut observations = 0;
    for object in listed {
        let Some(view) = observation_view(&object) else {
            continue;
        };
        if view.problem_signature != signature {
            continue;
        }
        observations += 1;
        for occurrence in parse_occurrence_ids(
            object
                .properties
                .get("occurrence_ids")
                .map(String::as_str)
                .unwrap_or(""),
        ) {
            operations.insert(occurrence);
        }
        if version.is_empty()
            && let Some(found) = object
                .properties
                .get("tenkai_version")
                .map(String::as_str)
                .and_then(public_version)
        {
            version = found.to_string();
        }
    }
    let version = public_token(&sanitize_public_text(
        if version.is_empty() {
            "unspecified"
        } else {
            &version
        },
        target,
    ));
    Ok((observations, operations.len(), version))
}

fn public_title(operation: &str, reason: &str) -> String {
    let mut title = format!("feedback: {operation}");
    if !reason.is_empty() && reason != "unspecified" {
        title.push(' ');
        title.push_str(reason);
    }
    if title.len() > 72 {
        title.truncate(72);
    }
    title
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

fn redact_foreign_refs(text: &str, target: &GitHubTarget) -> String {
    let allowed = target.repository();
    let mut out = String::new();
    for token in split_keep(text) {
        let trimmed = trim_token(&token);
        if is_foreign_issue_ref(trimmed, &allowed) {
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

fn redact_hostnames(text: &str, target: &GitHubTarget) -> String {
    let mut out = String::new();
    for token in split_keep(text) {
        let trimmed = trim_token(&token);
        if is_private_host(trimmed, target) {
            out.push_str("[redacted]");
        } else {
            out.push_str(&token);
        }
    }
    out
}

fn is_private_host(token: &str, _target: &GitHubTarget) -> bool {
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

pub fn evidence_lifecycle_for(error: Option<&GitHubError>) -> ExecutionLifecycleState {
    match error {
        None => ExecutionLifecycleState::Completed,
        Some(GitHubError::Lost) => ExecutionLifecycleState::OutcomeUnknown,
        Some(_) => ExecutionLifecycleState::Failed,
    }
}

/// Allow-all permit gate for deterministic tests.
pub struct AllowPermit;

impl PermitGate for AllowPermit {
    fn authorize_and_redeem(&self, intent: &PublishIntent) -> Result<PermitProof, PermitError> {
        Ok(PermitProof {
            permit_id: format!("permit-{}", intent.mapping_id),
            redemption_id: format!("redeem-{}", intent.mapping_id),
            execution_id: format!("exec-{}", intent.arguments_digest),
            operation_id: format!("feedback-gh-{}", intent.mapping_id),
            enforced_preconditions: BTreeMap::new(),
        })
    }
}

pub struct DenyPermit(pub PermitError);

impl PermitGate for DenyPermit {
    fn authorize_and_redeem(&self, _: &PublishIntent) -> Result<PermitProof, PermitError> {
        match &self.0 {
            PermitError::Denied(reason) => Err(PermitError::Denied(reason.clone())),
            PermitError::Expired => Err(PermitError::Expired),
            PermitError::Revoked => Err(PermitError::Revoked),
            PermitError::Mismatched => Err(PermitError::Mismatched),
            PermitError::Missing => Err(PermitError::Missing),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::evidence::{
        EVIDENCE_ENVELOPE_VERSION, EvidenceEnvelope, EvidenceIntent, EvidenceSignal,
        EvidenceTarget, SchemaCompatibility,
    };
    use crate::sekai::evidence_admission_lifecycle::EvidenceAdmissionLifecycle;
    use crate::sekai::evidence_store::{EvidenceProducerCapability, canonical_content_digest};
    use crate::sekai::feedback_investigation::{
        Attribution, CLASSIFICATION_QUALIFYING, InvestigationAnalysis, github_dispatch_permitted,
        record_investigation,
    };
    use crate::sekai::feedback_package::{
        EVIDENCE_SCHEMA_VERSION, EVIDENCE_TYPE, KIND_EXTERNAL_ISSUE, KIND_FINDING, install,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const NAMESPACE: &str = "ops";
    const ACTOR: &str = "reviewer";

    struct MemoryGitHub {
        issues: Mutex<Vec<GitHubIssue>>,
        creates: Mutex<u32>,
        updates: Mutex<u32>,
        next_number: Mutex<u64>,
        create_error: Mutex<Option<GitHubErrorKind>>,
        update_error: Mutex<Option<GitHubErrorKind>>,
        list_error: Mutex<Option<GitHubErrorKind>>,
        retain_on_lost: bool,
    }

    #[derive(Clone, Copy)]
    enum GitHubErrorKind {
        MissingCredentials,
        IssuesDisabled,
        RateLimited,
        Lost,
    }

    impl GitHubErrorKind {
        fn to_error(self) -> GitHubError {
            match self {
                Self::MissingCredentials => GitHubError::MissingCredentials,
                Self::IssuesDisabled => GitHubError::IssuesDisabled,
                Self::RateLimited => GitHubError::RateLimited,
                Self::Lost => GitHubError::Lost,
            }
        }
    }

    impl MemoryGitHub {
        fn new() -> Self {
            Self {
                issues: Mutex::new(Vec::new()),
                creates: Mutex::new(0),
                updates: Mutex::new(0),
                next_number: Mutex::new(1),
                create_error: Mutex::new(None),
                update_error: Mutex::new(None),
                list_error: Mutex::new(None),
                retain_on_lost: true,
            }
        }

        fn fail_create(&self, kind: GitHubErrorKind) {
            *self.create_error.lock().unwrap() = Some(kind);
        }

        fn created(&self) -> u32 {
            *self.creates.lock().unwrap()
        }

        fn updated(&self) -> u32 {
            *self.updates.lock().unwrap()
        }

        fn issues(&self) -> Vec<GitHubIssue> {
            self.issues.lock().unwrap().clone()
        }
    }

    impl GitHubIssues for MemoryGitHub {
        fn list(&self) -> Result<Vec<GitHubIssue>, GitHubError> {
            if let Some(kind) = *self.list_error.lock().unwrap() {
                return Err(kind.to_error());
            }
            Ok(self.issues.lock().unwrap().clone())
        }

        fn get(&self, number: u64) -> Result<GitHubIssue, GitHubError> {
            self.issues
                .lock()
                .unwrap()
                .iter()
                .find(|issue| issue.number == number)
                .cloned()
                .ok_or_else(|| GitHubError::Other("missing issue".into()))
        }

        fn create(&self, title: &str, body: &str) -> Result<GitHubIssue, GitHubError> {
            *self.creates.lock().unwrap() += 1;
            let number = {
                let mut next = self.next_number.lock().unwrap();
                let number = *next;
                *next += 1;
                number
            };
            let issue = GitHubIssue {
                number,
                title: title.into(),
                body: body.into(),
                created_ms: 1_700_000_000_000,
            };
            let error = *self.create_error.lock().unwrap();
            if let Some(kind) = error {
                if matches!(kind, GitHubErrorKind::Lost) && self.retain_on_lost {
                    self.issues.lock().unwrap().push(issue);
                }
                return Err(kind.to_error());
            }
            self.issues.lock().unwrap().push(issue.clone());
            Ok(issue)
        }

        fn update(&self, number: u64, title: &str, body: &str) -> Result<GitHubIssue, GitHubError> {
            if let Some(kind) = *self.update_error.lock().unwrap() {
                return Err(kind.to_error());
            }
            *self.updates.lock().unwrap() += 1;
            let mut issues = self.issues.lock().unwrap();
            let issue = issues
                .iter_mut()
                .find(|issue| issue.number == number)
                .ok_or_else(|| GitHubError::Other("missing issue".into()))?;
            issue.title = title.into();
            issue.body = body.into();
            Ok(issue.clone())
        }
    }

    fn target() -> GitHubTarget {
        GitHubTarget::parse("tenkai-org", "tenkai", DEFAULT_DAILY_CAP).unwrap()
    }

    fn db() -> RuntimeDb {
        let runtime = RuntimeDb::memory();
        install(&runtime, NAMESPACE, ACTOR, 1_000).unwrap();
        runtime
            .upsert_evidence_producer(&producer(), 1_000)
            .unwrap();
        runtime
    }

    fn producer() -> EvidenceProducerCapability {
        EvidenceProducerCapability {
            producer_identity: "producer:feedback".into(),
            config_version: 1,
            source_types: vec!["feedback_source".into()],
            source_instances: vec!["feedback:checks".into()],
            namespaces: vec![NAMESPACE.into()],
            evidence_types: vec![EVIDENCE_TYPE.into()],
            target_kinds: vec![KIND_OBSERVATION.into()],
            classification_ceiling: crate::sekai::evidence::EvidenceClassification::Confidential,
            allowed_intents: vec![EvidenceIntent::Upsert],
            allow_operation_attachment: true,
            replay_window_ms: 10_000,
            max_clock_skew_ms: 1_000,
            max_payload_bytes: 4_096,
            max_relationships: 4,
            rate_limit_per_minute: 20,
            max_retained_submissions: 100,
            revoked: false,
        }
    }

    fn envelope(
        external_id: &str,
        signature: &str,
        occurrence: &str,
        classification: &str,
        payload: serde_json::Value,
    ) -> EvidenceEnvelope {
        let content = json!({
            "problem_signature": signature,
            "occurrence_ids": occurrence,
            "classification": classification,
            "disposition": "open",
            "note": payload,
        });
        EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "feedback_source".into(),
            source_instance: "feedback:checks".into(),
            source_record_id: external_id.into(),
            source_version: "attempt-1".into(),
            source_sequence: 1,
            target: EvidenceTarget {
                namespace: NAMESPACE.into(),
                object_external_id: external_id.into(),
                object_kind: KIND_OBSERVATION.into(),
            },
            evidence_type: EVIDENCE_TYPE.into(),
            signal: EvidenceSignal::OperationalHealth,
            schema_id: EVIDENCE_TYPE.into(),
            schema_version: EVIDENCE_SCHEMA_VERSION.into(),
            schema_compatibility: SchemaCompatibility::Exact,
            observed_at_ms: 1_000,
            collected_at_ms: 1_010,
            expires_at_ms: Some(60_000_000),
            content_digest: canonical_content_digest(&content).unwrap(),
            content,
            relationships: vec![],
            producer_identity: "producer:feedback".into(),
            confidence_bps: 9_000,
            classification: crate::sekai::evidence::EvidenceClassification::Internal,
            provenance: Default::default(),
            idempotency_key: format!("delivery-{external_id}"),
            intent: EvidenceIntent::Upsert,
            causality: None,
        }
    }

    fn record_observation(
        runtime: &RuntimeDb,
        id: &str,
        signature: &str,
        occurrence: &str,
        classification: &str,
        created_ms: i64,
        note: serde_json::Value,
    ) {
        let admission = EvidenceAdmissionLifecycle::new(runtime)
            .admit(
                &envelope(id, signature, occurrence, classification, note),
                "producer:feedback",
                created_ms,
            )
            .unwrap();
        let evidence_id = admission.submission.id.clone();
        crate::sekai::action_instance_admission::ActionInstanceAdmission::new(runtime, None)
            .admit(
                ActionInstanceAdmissionRequest {
                    agent_turn: None,
                    namespace: NAMESPACE.into(),
                    type_id: crate::sekai::feedback_package::ACTION_OBSERVATION.into(),
                    version: PACKAGE_VERSION.into(),
                    parameters_json: json!({
                        "object_id": id,
                        "name": signature,
                        "source_evidence": evidence_id,
                        "problem_signature": signature,
                        "occurrence_ids": occurrence,
                        "classification": classification,
                        "disposition": "open"
                    })
                    .to_string(),
                    idempotency_key: format!("obs-{id}"),
                    evidence_submission_ids: vec![evidence_id],
                    request_id: String::new(),
                    ontology_digest: String::new(),
                    autonomous_envelope_id: String::new(),
                    policy_context: PrincipalPolicyContext::default(),
                    delegating_actor: None,
                    budget_already_reserved: false,
                    resource_tenant: String::new(),
                    binding_markings: Vec::new(),
                    source_object_id: String::new(),
                    marking_gate: Default::default(),
                    expected_object_revision: String::new(),
                    offline: None,
                },
                ACTOR,
                created_ms,
            )
            .unwrap();
        let mut stored = runtime.get_object(id).unwrap().unwrap();
        stored.created = created_ms;
        stored.updated = created_ms;
        runtime.update_object(&stored).unwrap();
    }

    fn qualifying_cluster(
        runtime: &RuntimeDb,
        prefix: &str,
        signature: &str,
        impact: &str,
        extra: &str,
    ) -> Object {
        for index in 1..=3 {
            record_observation(
                runtime,
                &format!("{prefix}-{index}"),
                signature,
                &format!("{prefix}-op-{index}"),
                "defect",
                1_000 * i64::from(index),
                json!(extra),
            );
        }
        let analysis = InvestigationAnalysis {
            observed_facts: vec!["controller retry exhausted".into()],
            hypotheses: vec!["lease fencing dropped".into()],
            impact: impact.into(),
            attribution: Attribution::Tenkai,
            proposed_reproduction: "replay the same plan".into(),
            missing_evidence: Vec::new(),
            independently_verified_reproduction: true,
        };
        let cluster = crate::sekai::feedback_investigation::cluster_from_observations(
            NAMESPACE,
            &format!("{prefix}-3"),
            signature,
            10_000,
            (1..=3)
                .map(
                    |index| crate::sekai::feedback_investigation::ObservationView {
                        object_id: format!("{prefix}-{index}"),
                        created_ms: 1_000 * i64::from(index),
                        problem_signature: signature.into(),
                        occurrence_ids: vec![format!("{prefix}-op-{index}")],
                        classification: "defect".into(),
                        disposition: "open".into(),
                        source_evidence: String::new(),
                    },
                )
                .collect(),
            true,
        );
        let report = record_investigation(runtime, &cluster, &analysis, ACTOR, 10_000).unwrap();
        runtime.get_object(&report.finding_id).unwrap().unwrap()
    }

    fn publish(
        runtime: &RuntimeDb,
        github: &MemoryGitHub,
        permits: &dyn PermitGate,
        finding: &Object,
    ) -> Result<PublishReport, PublishError> {
        publish_finding(
            runtime,
            github,
            permits,
            &target(),
            finding,
            ACTOR,
            1_700_000_000_000,
        )
    }

    #[derive(Default)]
    struct RecordingPermit {
        ids: Mutex<Vec<String>>,
    }

    impl RecordingPermit {
        fn ids(&self) -> Vec<String> {
            self.ids.lock().unwrap().clone()
        }
    }

    impl PermitGate for RecordingPermit {
        fn authorize_and_redeem(&self, intent: &PublishIntent) -> Result<PermitProof, PermitError> {
            self.ids.lock().unwrap().push(permit_operation_id(intent));
            AllowPermit.authorize_and_redeem(intent)
        }
    }

    fn sample_intent(
        operation: PublishOperation,
        body: &str,
        attempt_token: &str,
    ) -> PublishIntent {
        PublishIntent {
            arguments_digest: arguments_digest(operation, body),
            mapping_id: "fb-ext-deadbeefdeadbeef".into(),
            attempt_token: attempt_token.into(),
            operation,
            draft: IssueDraft {
                title: "title".into(),
                managed_body: body.into(),
                marker: "marker".into(),
                signature: "signature".into(),
                finding_id: "finding".into(),
                namespace: NAMESPACE.into(),
            },
        }
    }

    #[test]
    fn github_target_parse_rejects_empty_and_slashes() {
        assert!(GitHubTarget::parse("", "tenkai", 5).is_none());
        assert!(GitHubTarget::parse("tenkai-org", "tenkai/app", 5).is_none());
        let target = GitHubTarget::parse("tenkai-org", "tenkai", 0).unwrap();
        assert_eq!(target.daily_cap, DEFAULT_DAILY_CAP);
        assert_eq!(target.repository(), "tenkai-org/tenkai");
    }

    #[test]
    fn github_api_origin_binds_scheme_and_host() {
        assert_eq!(
            github_api_origin("https://api.github.com"),
            Some("https://api.github.com".into())
        );
        assert_eq!(
            github_api_origin(" https://api.github.com/api/v3 "),
            Some("https://api.github.com".into())
        );
        assert_eq!(
            github_api_origin("http://127.0.0.1:8443/repos"),
            Some("http://127.0.0.1:8443".into())
        );
        assert!(github_api_origin("https://user:token@api.github.com").is_none());
        assert!(github_api_origin("https://api.github.com%2eevil.com").is_none());
        assert!(github_api_origin("https://api.github.com\tevil.com").is_none());
        assert!(github_api_origin("ftp://api.github.com").is_none());
        assert!(github_api_origin("not-a-url").is_none());
    }

    #[test]
    fn publisher_principal_rejects_privileged_actors() {
        assert_eq!(publisher_principal(""), Some(RUNTIME_ID.into()));
        assert_eq!(publisher_principal("ops-bot"), Some("ops-bot".into()));
        assert!(publisher_principal("root").is_none());
        assert!(publisher_principal("local").is_none());
        assert!(publisher_principal(" root ").is_none());
    }

    #[test]
    fn permit_binds_repository_and_api_origin() {
        let target = GitHubTarget::parse("tenkai-org", "tenkai", 5).unwrap();
        let origin = "https://api.github.com";
        let selectors = permit_target_selectors(NAMESPACE, &target, origin);
        assert_eq!(
            selectors,
            [
                "project:ops/github:tenkai-org/tenkai",
                "project:ops/github-api:api.github.com"
            ]
        );
        let project_root = format!("project:{NAMESPACE}/");
        assert!(
            selectors
                .iter()
                .all(|selector| selector.starts_with(&project_root) && !selector.contains("://"))
        );
        let preconditions = permit_preconditions(&target, origin);
        assert_eq!(
            preconditions.get("repository").map(String::as_str),
            Some("tenkai-org/tenkai")
        );
        assert_eq!(
            preconditions.get("api_origin").map(String::as_str),
            Some(origin)
        );
    }

    #[test]
    fn permit_operation_id_changes_with_create_attempt_and_update_digest() {
        let first = sample_intent(
            PublishOperation::Create,
            "body",
            "pending:inflight:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let retry = sample_intent(
            PublishOperation::Create,
            "body",
            "pending:inflight:2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        assert_ne!(permit_operation_id(&first), permit_operation_id(&retry));
        let update = sample_intent(PublishOperation::Update { number: 7 }, "body", "");
        let changed = sample_intent(PublishOperation::Update { number: 7 }, "body-2", "");
        let other_issue = sample_intent(PublishOperation::Update { number: 8 }, "body", "");
        assert_ne!(permit_operation_id(&update), permit_operation_id(&changed));
        assert_ne!(
            permit_operation_id(&update),
            permit_operation_id(&other_issue)
        );
        assert_eq!(permit_operation_id(&update), permit_operation_id(&update));
    }

    #[test]
    fn permit_deadline_is_stable_within_the_ttl_window() {
        let update = sample_intent(PublishOperation::Update { number: 1 }, "body", "");
        let now = 1_700_000_000_000;
        assert_eq!(
            permit_deadline_ms(&update, now),
            permit_deadline_ms(&update, now + 30_000)
        );
        let create = sample_intent(
            PublishOperation::Create,
            "body",
            "pending:inflight:1700000000000:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_eq!(
            permit_deadline_ms(&create, now),
            1_700_000_000_000 + PERMIT_TTL_MS
        );
        assert_eq!(
            permit_deadline_ms(&create, now + 30_000),
            1_700_000_000_000 + PERMIT_TTL_MS
        );
    }

    #[test]
    fn qualifying_finding_creates_one_issue() {
        let runtime = db();
        let finding = qualifying_cluster(
            &runtime,
            "a",
            "api:tenkai_failed",
            "apply cannot finish",
            "",
        );
        let github = MemoryGitHub::new();
        let report = publish(&runtime, &github, &AllowPermit, &finding).unwrap();
        assert!(report.created);
        assert_eq!(github.created(), 1);
        let issue = &github.issues()[0];
        assert_eq!(issue.title, "feedback: api tenkai_failed");
        assert!(issue.body.contains("## Operation"));
        assert!(issue.body.contains("api"));
        assert!(issue.body.contains("tenkai_failed"));
        assert!(issue.body.contains("tenkai"));
        assert!(issue.body.contains("3 observations across 3 operations."));
        assert!(issue.body.contains("## Acceptance"));
        assert!(!issue.body.contains("apply cannot finish"));
        let mapping = runtime.get_object(&report.mapping_id).unwrap().unwrap();
        assert_eq!(
            mapping.properties.get("remote_id").map(String::as_str),
            Some("github:tenkai-org/tenkai#1")
        );
    }

    #[test]
    fn draft_uses_analysis_when_a_newer_quality_stub_exists() {
        let runtime = db();
        let finding = qualifying_cluster(&runtime, "q", "api:timeout", "apply cannot finish", "");
        let observation_id = finding.properties.get("observation_id").cloned().unwrap();
        runtime
            .create_object(&Object {
                id: "fb-inv-quality-stub".into(),
                kind: KIND_INVESTIGATION_RESULT.into(),
                name: "quality".into(),
                namespace: NAMESPACE.into(),
                external_id: "fb-inv-quality-stub".into(),
                properties: std::collections::HashMap::from([
                    ("observation_id".into(), observation_id),
                    ("outcome".into(), "quality-evaluation".into()),
                    ("measured".into(), "true".into()),
                ]),
                created: 99_000,
                updated: 99_000,
            })
            .unwrap();
        let draft = draft_from_finding(&runtime, &finding, &target()).unwrap();
        assert!(draft.managed_body.contains("timeout"));
        assert!(draft.managed_body.contains("tenkai"));
        assert!(!draft.managed_body.contains("apply cannot finish"));
        assert!(!draft.managed_body.contains("replay the same plan"));
        assert!(!draft.managed_body.contains("quality-evaluation"));
    }

    #[test]
    fn later_occurrence_updates_managed_content_and_keeps_maintainer_text() {
        let runtime = db();
        let finding = qualifying_cluster(
            &runtime,
            "a",
            "api:tenkai_failed",
            "apply cannot finish",
            "",
        );
        let github = MemoryGitHub::new();
        publish(&runtime, &github, &AllowPermit, &finding).unwrap();
        {
            let mut issues = github.issues.lock().unwrap();
            issues[0]
                .body
                .push_str("\n\nMaintainer: parked until the next cut.");
        }
        let later = qualifying_cluster(
            &runtime,
            "b",
            "api:tenkai_failed",
            "apply still cannot finish after retry",
            "",
        );
        let report = publish(&runtime, &github, &AllowPermit, &later).unwrap();
        assert!(!report.created);
        assert_eq!(github.created(), 1);
        let body = &github.issues()[0].body;
        assert!(body.contains("6 observations across 6 operations."));
        assert!(body.contains("Maintainer: parked until the next cut."));
        assert!(!body.contains("apply still cannot finish after retry"));
    }

    #[test]
    fn independent_findings_stay_distinct() {
        let runtime = db();
        let first = qualifying_cluster(&runtime, "a", "api:tenkai_failed", "first", "");
        let second = qualifying_cluster(&runtime, "c", "api:budget_exhausted", "second", "");
        let github = MemoryGitHub::new();
        publish(&runtime, &github, &AllowPermit, &first).unwrap();
        publish(&runtime, &github, &AllowPermit, &second).unwrap();
        assert_eq!(github.created(), 2);
        assert_eq!(github.issues()[0].number, 1);
        assert_eq!(github.issues()[1].number, 2);
    }

    #[test]
    fn concurrent_publishers_do_not_duplicate() {
        let runtime = Arc::new(db());
        let finding = qualifying_cluster(
            runtime.as_ref(),
            "a",
            "api:tenkai_failed",
            "apply cannot finish",
            "",
        );
        let github = Arc::new(MemoryGitHub::new());
        let finding = Arc::new(finding);
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let runtime = runtime.clone();
                let github = github.clone();
                let finding = finding.clone();
                std::thread::spawn(move || {
                    publish(runtime.as_ref(), github.as_ref(), &AllowPermit, &finding)
                })
            })
            .collect();
        let mut ok = 0;
        for worker in workers {
            if worker.join().unwrap().is_ok() {
                ok += 1;
            }
        }
        assert!(ok >= 1);
        assert_eq!(github.created(), 1);
        assert_eq!(github.issues().len(), 1);
    }

    #[test]
    fn lost_create_reconciles_without_a_second_create() {
        let runtime = db();
        let finding = qualifying_cluster(
            &runtime,
            "a",
            "api:tenkai_failed",
            "apply cannot finish",
            "",
        );
        let github = MemoryGitHub::new();
        github.fail_create(GitHubErrorKind::Lost);
        let error = publish(&runtime, &github, &AllowPermit, &finding).unwrap_err();
        assert!(matches!(error, PublishError::GitHub(GitHubError::Lost)));
        *github.create_error.lock().unwrap() = None;
        let report = publish(&runtime, &github, &AllowPermit, &finding).unwrap();
        assert_eq!(github.created(), 1);
        assert_eq!(report.issue_number, 1);
        assert!(!report.created);
    }

    #[test]
    fn denied_permits_do_not_mutate_github() {
        let runtime = db();
        let finding = qualifying_cluster(&runtime, "a", "api:tenkai_failed", "impact", "");
        let github = MemoryGitHub::new();
        for permit in [
            PermitError::Denied("policy".into()),
            PermitError::Expired,
            PermitError::Revoked,
            PermitError::Mismatched,
            PermitError::Missing,
        ] {
            let error = publish(&runtime, &github, &DenyPermit(permit), &finding).unwrap_err();
            assert!(matches!(error, PublishError::Permit(_)));
        }
        assert_eq!(github.created(), 0);
    }

    #[test]
    fn rate_limited_create_retries_with_a_new_permit_operation_id() {
        let runtime = db();
        let finding = qualifying_cluster(&runtime, "a", "api:tenkai_failed", "impact", "");
        let github = MemoryGitHub::new();
        let permits = RecordingPermit::default();
        github.fail_create(GitHubErrorKind::RateLimited);
        assert!(matches!(
            publish(&runtime, &github, &permits, &finding).unwrap_err(),
            PublishError::GitHub(GitHubError::RateLimited)
        ));
        *github.create_error.lock().unwrap() = None;
        publish(&runtime, &github, &permits, &finding).unwrap();
        let ids = permits.ids();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert!(ids[0].contains("-create-"), "{}", ids[0]);
        assert!(ids[1].contains("-create-"), "{}", ids[1]);
    }

    #[test]
    fn later_contentful_update_uses_a_distinct_permit_operation_id() {
        let runtime = db();
        let finding = qualifying_cluster(
            &runtime,
            "a",
            "api:tenkai_failed",
            "apply cannot finish",
            "",
        );
        let github = MemoryGitHub::new();
        let permits = RecordingPermit::default();
        publish(&runtime, &github, &permits, &finding).unwrap();
        let later = qualifying_cluster(
            &runtime,
            "b",
            "api:tenkai_failed",
            "apply still cannot finish after retry",
            "",
        );
        publish(&runtime, &github, &permits, &later).unwrap();
        let third = qualifying_cluster(
            &runtime,
            "c",
            "api:tenkai_failed",
            "apply failed a third time",
            "",
        );
        publish(&runtime, &github, &permits, &third).unwrap();
        let ids = permits.ids();
        assert_eq!(ids.len(), 3);
        assert!(ids[0].contains("-create-"), "{}", ids[0]);
        assert!(ids[1].contains("-update-"), "{}", ids[1]);
        assert!(ids[2].contains("-update-"), "{}", ids[2]);
        assert_ne!(ids[1], ids[2]);
    }

    #[test]
    fn missing_credentials_rate_limits_and_disabled_issues_stay_retryable() {
        let runtime = db();
        let finding = qualifying_cluster(&runtime, "a", "api:tenkai_failed", "impact", "");
        let github = MemoryGitHub::new();
        github.fail_create(GitHubErrorKind::MissingCredentials);
        assert!(matches!(
            publish(&runtime, &github, &AllowPermit, &finding).unwrap_err(),
            PublishError::GitHub(GitHubError::MissingCredentials)
        ));
        github.fail_create(GitHubErrorKind::RateLimited);
        assert!(matches!(
            publish(&runtime, &github, &AllowPermit, &finding).unwrap_err(),
            PublishError::GitHub(GitHubError::RateLimited)
        ));
        github.fail_create(GitHubErrorKind::IssuesDisabled);
        assert!(matches!(
            publish(&runtime, &github, &AllowPermit, &finding).unwrap_err(),
            PublishError::GitHub(GitHubError::IssuesDisabled)
        ));
        assert!(github.issues().is_empty());
    }

    #[test]
    fn public_draft_omits_model_text_and_uses_template_fields() {
        let runtime = db();
        let poison = "apply failed at 10.1.2.3 from /Users/ops/secret";
        let finding = qualifying_cluster(&runtime, "a", "api:tenkai_failed", poison, poison);
        let draft = draft_from_finding(&runtime, &finding, &target()).unwrap();
        assert_eq!(draft.title, "feedback: api tenkai_failed");
        assert!(draft.managed_body.contains("## Operation\n\napi"));
        assert!(draft.managed_body.contains("## Reason\n\ntenkai_failed"));
        assert!(draft.managed_body.contains("## Attribution\n\ntenkai"));
        assert!(
            draft
                .managed_body
                .contains("3 observations across 3 operations.")
        );
        assert!(draft.managed_body.contains("Not independently measured."));
        assert!(!draft.title.contains(poison), "{}", draft.title);
        assert!(
            !draft.managed_body.contains(poison),
            "{}",
            draft.managed_body
        );
        assert!(
            !draft.managed_body.contains("10.1.2.3"),
            "{}",
            draft.managed_body
        );
        assert!(
            !draft.managed_body.contains("/Users/ops/secret"),
            "{}",
            draft.managed_body
        );
    }

    #[test]
    fn sanitize_public_text_redacts_private_identifiers() {
        let target = target();
        let samples = [
            "reached 10.1.2.3 from /Users/ops/secret and acme/private-ops#9 on ops.internal.example",
            "path `/home/ops/.ssh/id_rsa` leaked",
            "store /srv/tenant/data/export.json",
            "host `<db01.tenant.example>` and `ops.internal.example`",
            "owner-shaped tenkai-org.internal.example",
            "contact ops@tenant.example",
            "addr fd00::1 and [2001:db8::1]",
            "Authorization: Bearer ghp_exampletoken",
        ];
        for sample in samples {
            let sanitized = sanitize_public_text(sample, &target);
            assert!(
                sanitized.contains("[redacted]"),
                "expected redaction in {sample:?} -> {sanitized:?}"
            );
            for needle in [
                "10.1.2.3",
                "/Users/ops/secret",
                "/home/ops/.ssh/id_rsa",
                "/srv/tenant/data/export.json",
                "db01.tenant.example",
                "ops.internal.example",
                "tenkai-org.internal.example",
                "ops@tenant.example",
                "fd00::1",
                "2001:db8::1",
                "ghp_exampletoken",
                "acme/private-ops#9",
            ] {
                assert!(
                    !sanitized.contains(needle),
                    "leaked {needle:?} from {sample:?} -> {sanitized:?}"
                );
            }
        }
        let github = sanitize_public_text("see github.com/tenkai-org/tenkai#1", &target);
        assert!(
            github.contains("github.com/tenkai-org/tenkai#1"),
            "{github}"
        );
    }

    #[test]
    fn publication_strips_private_identifiers_from_adversarial_input() {
        let runtime = db();
        let poison = "reached 10.1.2.3 from /Users/ops/secret and acme/private-ops#9 on ops.internal.example `/home/ops/.ssh/id_rsa` /srv/tenant/data `<db01.tenant.example>` tenkai-org.internal.example ops@tenant.example fd00::1 Authorization: Bearer ghp_exampletoken";
        let finding = qualifying_cluster(
            &runtime,
            "a",
            "api:tenkai_failed",
            &format!("apply failed at {poison}"),
            poison,
        );
        let github = MemoryGitHub::new();
        publish(&runtime, &github, &AllowPermit, &finding).unwrap();
        let body = &github.issues()[0].body;
        let title = &github.issues()[0].title;
        for needle in [
            "10.1.2.3",
            "/Users/ops/secret",
            "acme/private-ops#9",
            "ops.internal.example",
            "/home/ops/.ssh/id_rsa",
            "/srv/tenant/data",
            "db01.tenant.example",
            "tenkai-org.internal.example",
            "ops@tenant.example",
            "fd00::1",
            "ghp_exampletoken",
            "apply failed at",
        ] {
            assert!(!body.contains(needle), "{needle} in {body}");
            assert!(!title.contains(needle), "{needle} in {title}");
        }
    }

    #[test]
    fn daily_cap_keeps_excess_findings_queued() {
        let runtime = db();
        let github = MemoryGitHub::new();
        let mut findings = Vec::new();
        for index in 0..6 {
            findings.push(qualifying_cluster(
                &runtime,
                &format!("n{index}"),
                &format!("api:fail-{index}"),
                &format!("impact {index}"),
                "",
            ));
        }
        let mut created = 0;
        let mut capped = 0;
        for finding in &findings {
            match publish(&runtime, &github, &AllowPermit, finding) {
                Ok(_) => created += 1,
                Err(PublishError::DailyCap) => capped += 1,
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(created, 5);
        assert_eq!(capped, 1);
        assert_eq!(github.created(), 5);
    }

    #[test]
    fn internal_findings_are_not_published() {
        let runtime = db();
        record_observation(
            &runtime,
            "o-1",
            "api:cancelled",
            "op-1",
            "cancelled",
            1_000,
            json!({}),
        );
        let cluster = crate::sekai::feedback_investigation::cluster_from_observations(
            NAMESPACE,
            "o-1",
            "api:cancelled",
            2_000,
            vec![crate::sekai::feedback_investigation::ObservationView {
                object_id: "o-1".into(),
                created_ms: 1_000,
                problem_signature: "api:cancelled".into(),
                occurrence_ids: vec!["op-1".into()],
                classification: "cancelled".into(),
                disposition: "open".into(),
                source_evidence: String::new(),
            }],
            false,
        );
        let analysis = InvestigationAnalysis {
            observed_facts: vec![],
            hypotheses: vec![],
            impact: "cancelled".into(),
            attribution: Attribution::Cancellation,
            proposed_reproduction: String::new(),
            missing_evidence: Vec::new(),
            independently_verified_reproduction: false,
        };
        let report = record_investigation(&runtime, &cluster, &analysis, ACTOR, 2_000).unwrap();
        let finding = runtime.get_object(&report.finding_id).unwrap().unwrap();
        let github = MemoryGitHub::new();
        let error = publish(&runtime, &github, &AllowPermit, &finding).unwrap_err();
        assert!(matches!(error, PublishError::NotQualifying));
        assert_eq!(github.created(), 0);
    }

    #[test]
    fn foreign_namespace_mapping_does_not_redirect_publish() {
        let runtime = db();
        let finding = qualifying_cluster(
            &runtime,
            "a",
            "api:tenkai_failed",
            "apply cannot finish",
            "",
        );
        let mapping_id = mapping_object_id(NAMESPACE, "api:tenkai_failed");
        runtime
            .create_object(&Object {
                id: mapping_id,
                kind: KIND_EXTERNAL_ISSUE.into(),
                name: "forged".into(),
                namespace: "attacker".into(),
                external_id: String::new(),
                properties: HashMap::from([
                    ("finding_id".into(), "forged-finding".into()),
                    ("tracker".into(), TRACKER.into()),
                    ("remote_id".into(), "github:tenkai-org/tenkai#1".into()),
                ]),
                created: 1_000,
                updated: 1_000,
            })
            .unwrap();
        let github = MemoryGitHub::new();
        github.issues.lock().unwrap().push(GitHubIssue {
            number: 1,
            title: "unrelated".into(),
            body: "keep me".into(),
            created_ms: 1_700_000_000_000,
        });
        *github.next_number.lock().unwrap() = 2;
        let error = publish(&runtime, &github, &AllowPermit, &finding).unwrap_err();
        assert!(
            matches!(error, PublishError::Retryable(ref reason) if reason.contains("occupied")),
            "{error:?}"
        );
        assert_eq!(github.created(), 0);
        assert_eq!(github.updated(), 0);
        let issue = &github.issues()[0];
        assert_eq!(issue.number, 1);
        assert_eq!(issue.title, "unrelated");
        assert_eq!(issue.body, "keep me");

        let later = qualifying_cluster(&runtime, "c", "api:budget_exhausted", "second", "");
        let report = publish(&runtime, &github, &AllowPermit, &later).unwrap();
        assert!(report.created);
        assert_eq!(github.created(), 1);
        assert_eq!(github.updated(), 0);
        assert_eq!(github.issues()[0].title, "unrelated");
        assert_eq!(github.issues()[1].title, "feedback: api budget_exhausted");
    }

    #[test]
    fn mismatched_kind_mapping_does_not_redirect_publish() {
        let runtime = db();
        let finding = qualifying_cluster(
            &runtime,
            "k",
            "api:tenkai_failed",
            "apply cannot finish",
            "",
        );
        let mapping_id = mapping_object_id(NAMESPACE, "api:tenkai_failed");
        runtime
            .create_object(&Object {
                id: mapping_id,
                kind: KIND_FINDING.into(),
                name: "forged".into(),
                namespace: NAMESPACE.into(),
                external_id: String::new(),
                properties: HashMap::from([
                    ("finding_id".into(), "forged-finding".into()),
                    ("tracker".into(), TRACKER.into()),
                    ("remote_id".into(), "github:tenkai-org/tenkai#1".into()),
                ]),
                created: 1_000,
                updated: 1_000,
            })
            .unwrap();
        let github = MemoryGitHub::new();
        github.issues.lock().unwrap().push(GitHubIssue {
            number: 1,
            title: "unrelated".into(),
            body: "keep me".into(),
            created_ms: 1_700_000_000_000,
        });
        let error = publish(&runtime, &github, &AllowPermit, &finding).unwrap_err();
        assert!(
            matches!(error, PublishError::Retryable(ref reason) if reason.contains("occupied")),
            "{error:?}"
        );
        assert_eq!(github.created(), 0);
        assert_eq!(github.updated(), 0);
        assert_eq!(github.issues()[0].title, "unrelated");
        assert_eq!(github.issues()[0].body, "keep me");
    }

    #[test]
    fn writer_created_qualifying_finding_is_not_published() {
        let runtime = db();
        let finding = Object {
            id: "writer-find".into(),
            kind: KIND_FINDING.into(),
            name: "forged".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("classification".into(), CLASSIFICATION_QUALIFYING.into()),
                ("observation_id".into(), "o-1".into()),
                ("statement".into(), "forged impact".into()),
            ]),
            created: 1_000,
            updated: 1_000,
        };
        runtime.create_object(&finding).unwrap();
        assert!(!github_dispatch_permitted(&finding));
        let github = MemoryGitHub::new();
        let error = publish(&runtime, &github, &AllowPermit, &finding).unwrap_err();
        assert!(matches!(error, PublishError::NotQualifying));
        assert_eq!(github.created(), 0);
    }
}
