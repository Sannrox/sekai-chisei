//! Reference GitHub Issue/PullRequest normalizer.
//!
//! Input fixtures are already collected and normalized. This adapter performs
//! no network calls and has no credential fields.

use sekai_chisei::sekai::object_sync::{
    MAX_SOURCE_DISPLAY_NAME_BYTES, MAX_SOURCE_IDENTIFIER_BYTES, MAX_SOURCE_PROPERTY_KEY_BYTES,
    MAX_SOURCE_PROPERTY_VALUE_BYTES, MAX_SOURCE_RECORD_PROPERTIES, SOURCE_GITHUB, SourceRecord,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_GITHUB_FIXTURE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectFeedCapability {
    UnsupportedOrdering,
}

/// Public GitHub collection does not provide the contiguous ordered feed that
/// v2 requires. Fixture normalization remains snapshot-only.
pub fn direct_feed_capability() -> DirectFeedCapability {
    DirectFeedCapability::UnsupportedOrdering
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubObjectFixture {
    pub repository: String,
    pub kind: String,
    pub number: u64,
    pub revision: String,
    pub title: String,
    pub state: String,
    #[serde(default)]
    pub deleted: bool,
    pub observed_at_ms: i64,
    #[serde(default)]
    pub properties: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct NormalizedPayload<'a> {
    repository: &'a str,
    kind: &'a str,
    number: u64,
    revision: &'a str,
    title: &'a str,
    state: &'a str,
    deleted: bool,
    properties: &'a BTreeMap<String, String>,
}

pub fn parse(input: &[u8]) -> Result<GitHubObjectFixture, String> {
    if input.len() > MAX_GITHUB_FIXTURE_BYTES {
        return Err("GitHub object fixture exceeds the byte limit".into());
    }
    serde_json::from_slice(input).map_err(|_| "invalid normalized GitHub object fixture".into())
}

pub fn translate(
    fixture: GitHubObjectFixture,
    expected_repository: &str,
) -> Result<SourceRecord, String> {
    validate_repository(expected_repository)?;
    validate_repository(&fixture.repository)?;
    if fixture.repository != expected_repository {
        return Err("GitHub object repository does not match the source instance".into());
    }
    if !matches!(fixture.kind.as_str(), "Issue" | "PullRequest") {
        return Err("GitHub object kind must be Issue or PullRequest".into());
    }
    if fixture.number == 0 {
        return Err("GitHub object number must be positive".into());
    }
    validate_identifier("revision", &fixture.revision)?;
    validate_text(
        "title",
        &fixture.title,
        MAX_SOURCE_DISPLAY_NAME_BYTES,
        false,
    )?;
    validate_text(
        "state",
        &fixture.state,
        MAX_SOURCE_PROPERTY_VALUE_BYTES,
        false,
    )?;
    if fixture.observed_at_ms <= 0 {
        return Err("GitHub object observed_at_ms must be positive".into());
    }
    if fixture.properties.len() >= MAX_SOURCE_RECORD_PROPERTIES {
        return Err("GitHub object properties exceed the entry limit".into());
    }

    let mut properties = fixture.properties;
    if properties.contains_key("state") {
        return Err("GitHub object properties cannot replace reserved fields".into());
    }
    for (key, value) in &properties {
        validate_property(key, value)?;
    }
    properties.insert("state".into(), fixture.state.clone());

    let normalized = NormalizedPayload {
        repository: &fixture.repository,
        kind: &fixture.kind,
        number: fixture.number,
        revision: &fixture.revision,
        title: &fixture.title,
        state: &fixture.state,
        deleted: fixture.deleted,
        properties: &properties,
    };
    let payload = serde_json::to_vec(&normalized)
        .map_err(|_| "GitHub object cannot be canonicalized".to_string())?;
    let record = SourceRecord {
        source: SOURCE_GITHUB.into(),
        source_instance: fixture.repository,
        // Issues and pull requests share GitHub's repository number identity.
        external_id: fixture.number.to_string(),
        source_version: fixture.revision,
        type_name: fixture.kind,
        display_name: fixture.title,
        payload_digest: format!("sha256:{:x}", Sha256::digest(payload)),
        properties,
        deleted: fixture.deleted,
        observed_at_ms: fixture.observed_at_ms,
        source_sequence: None,
    };
    Ok(record)
}

fn validate_repository(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err("GitHub repository identity is invalid".into());
    }
    let mut parts = value.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    if parts.next().is_some() || !valid_repository_part(owner) || !valid_repository_part(repository)
    {
        return Err("GitHub repository must be canonical owner/repository".into());
    }
    Ok(())
}

fn valid_repository_part(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn validate_identifier(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || contains_secret_like_text(value)
    {
        Err(format!("GitHub object {label} is invalid"))
    } else {
        Ok(())
    }
}

fn validate_property(key: &str, value: &str) -> Result<(), String> {
    if key.is_empty()
        || key.len() > MAX_SOURCE_PROPERTY_KEY_BYTES
        || key.trim() != key
        || key.chars().any(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-' | '.'))
        })
    {
        return Err("GitHub object property key is not normalized".into());
    }
    if is_secret_key(key) || contains_secret_like_text(value) {
        return Err("GitHub object properties contain secret-like data".into());
    }
    validate_text(
        "property value",
        value,
        MAX_SOURCE_PROPERTY_VALUE_BYTES,
        true,
    )
}

fn validate_text(label: &str, value: &str, max: usize, allow_empty: bool) -> Result<(), String> {
    if (!allow_empty && value.trim().is_empty())
        || value.len() > max
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        || contains_secret_like_text(value)
    {
        Err(format!("GitHub object {label} is invalid"))
    } else {
        Ok(())
    }
}

fn is_secret_key(key: &str) -> bool {
    let normalized = key.replace('-', "_");
    normalized
        .split(['.', '_'])
        .any(|part| matches!(part, "secret" | "password" | "token" | "credential"))
        || normalized.contains("api_key")
        || normalized.contains("private_key")
        || normalized.contains("authorization")
}

fn contains_secret_like_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("-----begin private key-----")
        || lower.contains("authorization: bearer ")
        || lower.contains("x-api-key:")
        || lower.contains("api_key=")
        || lower.contains("api-key=")
        || lower.contains("access_token=")
        || lower.contains("client_secret=")
        || lower.contains("password=")
        || lower.contains("private_key=")
        || lower.contains("github_pat_")
        || lower.contains("ghp_")
        || lower.contains("gho_")
        || lower.contains("ghs_")
        || lower.contains("ghu_")
}
