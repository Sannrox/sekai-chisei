//! Combined-mode worker that publishes qualifying findings to GitHub (#1232).
//!
//! Reads the configured Tenkai repository each pass. Missing credentials, a
//! disabled issue tracker, and rate limits stay visible and retryable and do
//! not stop investigation or other plane recovery.

use super::chisei_service::{
    ChiseiServiceImpl, external_permit_from_proto, external_permit_to_proto, permit_signing_key,
};
use super::pb::chisei::{
    AuthorizeExternalActionRequest, ExternalActionRequest, RedeemExternalActionPermitRequest,
};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::execution_evidence::verify_for_executor;
use crate::sekai::external_permit::HostContext;
use crate::sekai::feedback_github::{
    DEFAULT_DAILY_CAP, EXTERNAL_ACTION_TYPE, GitHubError, GitHubIssue, GitHubIssues, GitHubTarget,
    HARNESS, HOST_CAPABILITY, PARAMETER_SCHEMA, POLL_INTERVAL_SECS, PermitError, PermitGate,
    PermitProof, PublishError, PublishIntent, PublishOperation, RUNTIME_ID, publish_finding,
    qualifying_findings,
};
use crate::sekai::feedback_package::PACKAGE_ID;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const OWNER_ENV: &str = "SEKAI_FEEDBACK_GITHUB_OWNER";
const REPO_ENV: &str = "SEKAI_FEEDBACK_GITHUB_REPO";
const TOKEN_ENV: &str = "SEKAI_FEEDBACK_GITHUB_TOKEN";
const RUN_AS_ENV: &str = "SEKAI_FEEDBACK_GITHUB_RUN_AS";
const CAP_ENV: &str = "SEKAI_FEEDBACK_GITHUB_DAILY_CAP";
const API_ENV: &str = "SEKAI_FEEDBACK_GITHUB_API";
const DEFAULT_API: &str = "https://api.github.com";

pub(super) fn spawn_feedback_github(db: Arc<RuntimeDb>, chisei: Arc<ChiseiServiceImpl>) {
    tracing::info!(
        interval_secs = POLL_INTERVAL_SECS,
        runtime = RUNTIME_ID,
        "feedback GitHub publisher enabled"
    );
    tokio::spawn(async move {
        let publishing = Mutex::new(());
        let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let Ok(_guard) = publishing.try_lock() else {
                continue;
            };
            let db = db.clone();
            let chisei = chisei.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || publish_pass(&db, &chisei))
                .await
                .unwrap_or_else(|error| Err(error.to_string()))
            {
                tracing::error!(%error, "feedback GitHub publisher pass failed");
            }
        }
    });
}

fn publish_pass(db: &RuntimeDb, chisei: &ChiseiServiceImpl) -> Result<(), String> {
    let Some(target) = configured_target() else {
        return Ok(());
    };
    let run_as = configured_run_as();
    let github = GitHubHttp::from_env(&target)?;
    let permits = LivePermitGate {
        chisei,
        target: target.clone(),
        run_as: run_as.clone(),
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    for namespace in db.list_live_package_namespaces(PACKAGE_ID)? {
        let findings = qualifying_findings(db, &namespace).map_err(|error| format!("{error:?}"))?;
        for finding in findings {
            match publish_finding(db, &github, &permits, &target, &finding, &run_as, now_ms) {
                Ok(report) => tracing::info!(
                    namespace = %namespace,
                    finding = %report.finding_id,
                    issue = report.issue_number,
                    created = report.created,
                    "feedback finding published"
                ),
                Err(PublishError::NotQualifying) => {}
                Err(PublishError::DailyCap) => {
                    tracing::info!(
                        namespace = %namespace,
                        cap = target.daily_cap,
                        "feedback GitHub daily cap retained remaining findings"
                    );
                    break;
                }
                Err(PublishError::Retryable(reason)) => {
                    tracing::info!(namespace = %namespace, %reason, "feedback GitHub publish deferred")
                }
                Err(PublishError::Permit(error)) => tracing::warn!(
                    namespace = %namespace,
                    error = %permit_label(&error),
                    "feedback GitHub permit refused; no external mutation"
                ),
                Err(PublishError::GitHub(GitHubError::MissingCredentials)) => {
                    tracing::warn!(
                        namespace = %namespace,
                        "feedback GitHub credentials missing; publication retryable"
                    );
                    return Ok(());
                }
                Err(PublishError::GitHub(GitHubError::RateLimited)) => {
                    tracing::warn!(
                        namespace = %namespace,
                        "feedback GitHub rate limited; publication retryable"
                    );
                    return Ok(());
                }
                Err(PublishError::GitHub(GitHubError::IssuesDisabled)) => {
                    tracing::warn!(
                        namespace = %namespace,
                        "feedback GitHub issues disabled; publication retryable"
                    );
                    return Ok(());
                }
                Err(PublishError::GitHub(GitHubError::Lost)) => tracing::warn!(
                    namespace = %namespace,
                    "feedback GitHub response lost; pending reconciliation"
                ),
                Err(PublishError::GitHub(GitHubError::Other(error))) => {
                    tracing::warn!(namespace = %namespace, %error, "feedback GitHub publish failed")
                }
                Err(PublishError::Internal(error)) => {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}

fn configured_target() -> Option<GitHubTarget> {
    GitHubTarget::parse(
        &std::env::var(OWNER_ENV).unwrap_or_default(),
        &std::env::var(REPO_ENV).unwrap_or_default(),
        std::env::var(CAP_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_DAILY_CAP),
    )
}

fn configured_run_as() -> String {
    std::env::var(RUN_AS_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| RUNTIME_ID.to_string())
}

fn permit_label(error: &PermitError) -> &'static str {
    match error {
        PermitError::Denied(_) => "denied",
        PermitError::Expired => "expired",
        PermitError::Revoked => "revoked",
        PermitError::Mismatched => "mismatched",
        PermitError::Missing => "missing",
    }
}

struct LivePermitGate<'a> {
    chisei: &'a ChiseiServiceImpl,
    target: GitHubTarget,
    run_as: String,
}

impl PermitGate for LivePermitGate<'_> {
    fn authorize_and_redeem(&self, intent: &PublishIntent) -> Result<PermitProof, PermitError> {
        let resource = format!("github:{}", self.target.repository());
        let op = match intent.operation {
            PublishOperation::Create => "create",
            PublishOperation::Update { number } => {
                let _ = number;
                "update"
            }
        };
        let operation_id = format!("feedback-gh-{}-{op}", intent.mapping_id);
        let authorized = self
            .chisei
            .authorize_from_authenticated(
                self.run_as.clone(),
                AuthorizeExternalActionRequest {
                    request: Some(ExternalActionRequest {
                        version: "external-action.request/v1".into(),
                        operation_id: operation_id.clone(),
                        parent_operation_id: String::new(),
                        attempt_id: format!("{operation_id}-attempt"),
                        request_id: format!("{operation_id}-request"),
                        actor: self.run_as.clone(),
                        namespace: intent.draft.namespace.clone(),
                        requesting_harness: HARNESS.into(),
                        intended_executor: self.run_as.clone(),
                        action_type: EXTERNAL_ACTION_TYPE.into(),
                        parameter_schema: PARAMETER_SCHEMA.into(),
                        canonical_arguments_digest: intent.arguments_digest.clone(),
                        policy_summary: std::collections::HashMap::from([(
                            "repository".into(),
                            self.target.repository(),
                        )]),
                        target_selectors: vec![format!(
                            "project:{}/{}",
                            intent.draft.namespace, resource
                        )],
                        immutable_preconditions: std::collections::HashMap::from([(
                            "repository".into(),
                            self.target.repository(),
                        )]),
                        risk_class: "write".into(),
                        expected_effects: vec![format!("issue_{op}")],
                        requested_invocation_count: 1,
                        deadline_ms: chrono::Utc::now().timestamp_millis() + 3_600_000,
                        estimated_cost_micros: 0,
                        estimated_volume: 1,
                        affected_resource_count: 1,
                        rollback_capability: "none".into(),
                        required_host_capabilities: vec![HOST_CAPABILITY.into()],
                        idempotency_key: format!("{operation_id}-auth"),
                        policy_project: intent.draft.namespace.clone(),
                    }),
                    offline: false,
                },
            )
            .map_err(status_to_permit)?;
        let decision = authorized.decision.ok_or(PermitError::Missing)?;
        if decision.decision != "permit" {
            return Err(classify_decision(&decision.reason));
        }
        let permit_proto = authorized.permit.ok_or(PermitError::Missing)?;
        let permit = external_permit_from_proto(permit_proto.clone());
        let host = HostContext {
            executor: self.run_as.clone(),
            requesting_harness: HARNESS.into(),
            canonical_arguments_digest: intent.arguments_digest.clone(),
            target_selectors: vec![format!("project:{}/{}", intent.draft.namespace, resource)],
            observed_preconditions: BTreeMap::from([(
                "repository".into(),
                self.target.repository(),
            )]),
            host_capabilities: vec![HOST_CAPABILITY.into()],
        };
        let key = permit_signing_key(&self.chisei.config)
            .map_err(|_| PermitError::Missing)?
            .verifying_key();
        verify_for_executor(
            &permit,
            &key,
            &self.chisei.config.permit_issuer,
            &self.chisei.config.permit_key_id,
            &host,
            chrono::Utc::now().timestamp_millis(),
        )
        .map_err(|error| classify_decision(&error))?;
        let execution_id = format!("{operation_id}-exec");
        let redeemed = self
            .chisei
            .redeem_from_authenticated(
                self.run_as.clone(),
                RedeemExternalActionPermitRequest {
                    permit: Some(external_permit_to_proto(&permit)),
                    executor: self.run_as.clone(),
                    requesting_harness: HARNESS.into(),
                    canonical_arguments_digest: host.canonical_arguments_digest,
                    target_selectors: host.target_selectors,
                    observed_preconditions: host.observed_preconditions.into_iter().collect(),
                    host_capabilities: host.host_capabilities,
                    idempotency_key: format!("{operation_id}-redeem"),
                    execution_id: execution_id.clone(),
                    invoked_at_ms: 0,
                },
            )
            .map_err(status_to_permit)?;
        let redemption = redeemed.redemption.ok_or(PermitError::Missing)?;
        Ok(PermitProof {
            permit_id: permit.permit_id,
            redemption_id: redemption.redemption_id,
            execution_id,
            operation_id,
            enforced_preconditions: permit.immutable_preconditions,
        })
    }
}

fn classify_decision(reason: &str) -> PermitError {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("expir") {
        PermitError::Expired
    } else if reason.contains("revok") {
        PermitError::Revoked
    } else if reason.contains("mismatch") || reason.contains("target") {
        PermitError::Mismatched
    } else if reason.contains("missing") || reason.contains("not configured") {
        PermitError::Missing
    } else {
        PermitError::Denied(reason)
    }
}

fn status_to_permit(status: tonic::Status) -> PermitError {
    classify_decision(status.message())
}

struct GitHubHttp {
    client: reqwest::blocking::Client,
    api: String,
    owner: String,
    repo: String,
    token: String,
}

impl GitHubHttp {
    fn from_env(target: &GitHubTarget) -> Result<Self, String> {
        let token = std::env::var(TOKEN_ENV).unwrap_or_default();
        let api = std::env::var(API_ENV)
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_API.to_string());
        let client = reqwest::blocking::Client::builder()
            .user_agent("sekai-chisei-feedback-github")
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            api,
            owner: target.owner.clone(),
            repo: target.repo.clone(),
            token,
        })
    }

    fn issues_url(&self) -> String {
        format!("{}/repos/{}/{}/issues", self.api, self.owner, self.repo)
    }

    fn headers(&self) -> Result<reqwest::header::HeaderMap, GitHubError> {
        if self.token.trim().is_empty() {
            return Err(GitHubError::MissingCredentials);
        }
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            "application/vnd.github+json"
                .parse()
                .map_err(|error| GitHubError::Other(format!("{error}")))?,
        );
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", self.token.trim())
                .parse()
                .map_err(|error| GitHubError::Other(format!("{error}")))?,
        );
        Ok(headers)
    }

    fn map_status(status: reqwest::StatusCode, body: &str) -> GitHubError {
        match status.as_u16() {
            401 => GitHubError::MissingCredentials,
            403 | 429 => GitHubError::RateLimited,
            410 => GitHubError::IssuesDisabled,
            _ => GitHubError::Other(format!("{status}: {body}")),
        }
    }

    fn map_send(error: reqwest::Error) -> GitHubError {
        if error.is_timeout() {
            GitHubError::Lost
        } else if error.is_connect() {
            GitHubError::Other(error.to_string())
        } else {
            GitHubError::Lost
        }
    }

    fn parse_issue(value: &Value) -> Result<GitHubIssue, GitHubError> {
        let number = value
            .get("number")
            .and_then(Value::as_u64)
            .ok_or_else(|| GitHubError::Other("issue number missing".into()))?;
        let title = value
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let body = value
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let created_ms = value
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
            .map(|when| when.timestamp_millis())
            .unwrap_or(0);
        Ok(GitHubIssue {
            number,
            title,
            body,
            created_ms,
        })
    }
}

impl GitHubIssues for GitHubHttp {
    fn list(&self) -> Result<Vec<GitHubIssue>, GitHubError> {
        let response = self
            .client
            .get(self.issues_url())
            .headers(self.headers()?)
            .query(&[("state", "all"), ("per_page", "100")])
            .send()
            .map_err(Self::map_send)?;
        let status = response.status();
        let text = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(Self::map_status(status, &text));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|error| GitHubError::Other(error.to_string()))?;
        let items = value
            .as_array()
            .ok_or_else(|| GitHubError::Other("issues list is not an array".into()))?;
        items.iter().map(Self::parse_issue).collect()
    }

    fn get(&self, number: u64) -> Result<GitHubIssue, GitHubError> {
        let response = self
            .client
            .get(format!("{}/{}", self.issues_url(), number))
            .headers(self.headers()?)
            .send()
            .map_err(Self::map_send)?;
        let status = response.status();
        let text = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(Self::map_status(status, &text));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|error| GitHubError::Other(error.to_string()))?;
        Self::parse_issue(&value)
    }

    fn create(&self, title: &str, body: &str) -> Result<GitHubIssue, GitHubError> {
        let response = self
            .client
            .post(self.issues_url())
            .headers(self.headers()?)
            .json(&serde_json::json!({ "title": title, "body": body }))
            .send()
            .map_err(Self::map_send)?;
        let status = response.status();
        let text = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(Self::map_status(status, &text));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|error| GitHubError::Other(error.to_string()))?;
        Self::parse_issue(&value)
    }

    fn update(&self, number: u64, title: &str, body: &str) -> Result<GitHubIssue, GitHubError> {
        let response = self
            .client
            .patch(format!("{}/{}", self.issues_url(), number))
            .headers(self.headers()?)
            .json(&serde_json::json!({ "title": title, "body": body }))
            .send()
            .map_err(Self::map_send)?;
        let status = response.status();
        let text = response.text().unwrap_or_default();
        if !status.is_success() {
            return Err(Self::map_status(status, &text));
        }
        let value: Value =
            serde_json::from_str(&text).map_err(|error| GitHubError::Other(error.to_string()))?;
        Self::parse_issue(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_status_maps_retryable_failures() {
        assert!(matches!(
            GitHubHttp::map_status(reqwest::StatusCode::UNAUTHORIZED, ""),
            GitHubError::MissingCredentials
        ));
        assert!(matches!(
            GitHubHttp::map_status(reqwest::StatusCode::FORBIDDEN, ""),
            GitHubError::RateLimited
        ));
        assert!(matches!(
            GitHubHttp::map_status(reqwest::StatusCode::TOO_MANY_REQUESTS, ""),
            GitHubError::RateLimited
        ));
        assert!(matches!(
            GitHubHttp::map_status(reqwest::StatusCode::GONE, ""),
            GitHubError::IssuesDisabled
        ));
    }
}
