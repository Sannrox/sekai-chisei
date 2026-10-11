//! Connection check and schema discovery for source adapters (#1408).
//!
//! `check` proves connectivity and credentials without reading records.
//! `discover` lists what a source offers: record kinds, typed columns, key
//! candidates, and optional per-column profile hints. A discovery only drafts
//! source-type descriptors (ADR 0060) and onboarding input; admission and
//! sensitivity marking stay reviewable control-plane acts.

use crate::contract::{MAX_SOURCE_IDENTIFIER_BYTES, contains_secret_like_text};
use std::collections::BTreeSet;

pub const SOURCE_DISCOVERY_VERSION: &str = "sekai.source-discovery/v1";
pub const MAX_DISCOVERED_RECORD_KINDS: usize = 1024;
pub const MAX_DISCOVERED_COLUMNS: usize = 1024;
/// Profile ratios are basis points so discoveries stay exact and comparable.
pub const PROFILE_RATIO_SCALE: u16 = 10_000;

/// Why a source could not be checked or discovered. Value-free by design:
/// diagnostics never carry credentials, hosts, or remote response bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionFailure {
    Unreachable,
    AuthFailed,
    PermissionMissing,
}

impl std::fmt::Display for ConnectionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unreachable => "source is unreachable",
            Self::AuthFailed => "source rejected the credentials",
            Self::PermissionMissing => "source credentials lack a required permission",
        })
    }
}

impl std::error::Error for ConnectionFailure {}

/// Source-owned check and discovery, next to the snapshot and change-feed
/// readers. Implementations hold their own credentials.
pub trait SourceInspector {
    /// Validate connectivity and credentials. Must not read records.
    fn check(&mut self) -> Result<(), ConnectionFailure>;
    /// List record kinds in ascending `record_kind` order. Must be
    /// deterministic for an unchanged source.
    fn discover(&mut self) -> Result<SourceDiscovery, ConnectionFailure>;
}

/// Optional per-column hints computed by the connector, never by the plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColumnProfileHint {
    pub distinct_ratio_bp: u16,
    pub null_ratio_bp: u16,
    pub possibly_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredColumn {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub profile: Option<ColumnProfileHint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRecordKind {
    pub record_kind: String,
    /// The source's own schema revision; a change is declared drift.
    pub schema_revision: String,
    /// Columns in source order.
    pub columns: Vec<DiscoveredColumn>,
    /// Each candidate is an ordered column list; composite keys have several.
    /// Empty when the record kind has no usable key.
    pub key_candidates: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDiscovery {
    pub contract_version: String,
    pub source: String,
    pub record_kinds: Vec<DiscoveredRecordKind>,
}

/// Reviewable input for `RegisterSourceTypeDescriptor`: one record kind at one
/// schema revision. The plane computes the digest when it admits the draft, and
/// still rejects code-owned GitHub Issue/PullRequest names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorDraft {
    pub source: String,
    pub record_kind: String,
    pub schema_revision: String,
}

impl SourceDiscovery {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != SOURCE_DISCOVERY_VERSION {
            return Err("unsupported source discovery contract".into());
        }
        require_token("source", &self.source)?;
        if self.record_kinds.len() > MAX_DISCOVERED_RECORD_KINDS {
            return Err("discovery lists too many record kinds".into());
        }
        for pair in self.record_kinds.windows(2) {
            if pair[0].record_kind >= pair[1].record_kind {
                return Err("record kinds must be unique and in ascending order".into());
            }
        }
        self.record_kinds.iter().try_for_each(validate_record_kind)
    }

    /// One draft per record kind, in discovery order. Mechanical conversion
    /// only; the catalog still refuses code-owned GitHub kinds.
    pub fn descriptor_drafts(&self) -> Result<Vec<DescriptorDraft>, String> {
        self.validate()?;
        Ok(self
            .record_kinds
            .iter()
            .map(|kind| DescriptorDraft {
                source: self.source.clone(),
                record_kind: kind.record_kind.clone(),
                schema_revision: kind.schema_revision.clone(),
            })
            .collect())
    }
}

/// Name-only sensitivity hint for connectors that have no catalog marking.
/// A hint feeds review; it never assigns a marking.
pub fn column_name_suggests_sensitive(name: &str) -> bool {
    const HINTS: [&str; 10] = [
        "email", "phone", "ssn", "password", "secret", "token", "birth", "address", "iban", "tax",
    ];
    let lower = name.to_ascii_lowercase();
    HINTS.iter().any(|hint| lower.contains(hint))
}

fn validate_record_kind(kind: &DiscoveredRecordKind) -> Result<(), String> {
    require_token("record_kind", &kind.record_kind)?;
    require_token("schema_revision", &kind.schema_revision)?;
    if kind.columns.is_empty() || kind.columns.len() > MAX_DISCOVERED_COLUMNS {
        return Err("record kind must list between one and the maximum columns".into());
    }
    let mut names = BTreeSet::new();
    for column in &kind.columns {
        require_text("column name", &column.name)?;
        require_text("column type", &column.data_type)?;
        if !names.insert(column.name.as_str()) {
            return Err("column names must be unique within a record kind".into());
        }
        if let Some(profile) = column.profile
            && (profile.distinct_ratio_bp > PROFILE_RATIO_SCALE
                || profile.null_ratio_bp > PROFILE_RATIO_SCALE)
        {
            return Err("profile ratios must be within 0..=10000 basis points".into());
        }
    }
    let mut candidates = BTreeSet::new();
    for candidate in &kind.key_candidates {
        let mut seen = BTreeSet::new();
        if candidate.is_empty()
            || !candidate
                .iter()
                .all(|column| names.contains(column.as_str()) && seen.insert(column.as_str()))
        {
            return Err("key candidates must name distinct declared columns".into());
        }
        if !candidates.insert(candidate) {
            return Err("key candidates must be unique".into());
        }
    }
    Ok(())
}

/// Registered-token shape (ADR 0060): no separators the identity format uses.
fn require_token(label: &str, value: &str) -> Result<(), String> {
    require_text(label, value)?;
    if value.contains([':', '#', '/']) {
        return Err(format!("{label} is not a canonical registered token"));
    }
    Ok(())
}

fn require_text(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || contains_secret_like_text(value)
    {
        return Err(format!("{label} is not bounded, trimmed, value-free text"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(name: &str) -> DiscoveredColumn {
        DiscoveredColumn {
            name: name.into(),
            data_type: "string".into(),
            nullable: false,
            profile: None,
        }
    }

    fn discovery(kinds: &[&str]) -> SourceDiscovery {
        SourceDiscovery {
            contract_version: SOURCE_DISCOVERY_VERSION.into(),
            source: "fake.crm".into(),
            record_kinds: kinds
                .iter()
                .map(|kind| DiscoveredRecordKind {
                    record_kind: (*kind).into(),
                    schema_revision: "v1".into(),
                    columns: vec![column("id"), column("region")],
                    key_candidates: vec![vec!["id".into()], vec!["region".into(), "id".into()]],
                })
                .collect(),
        }
    }

    #[test]
    fn drafts_follow_record_kinds() {
        let drafts = discovery(&["Account", "Contact"])
            .descriptor_drafts()
            .unwrap();
        assert_eq!(
            drafts
                .iter()
                .map(|draft| draft.record_kind.as_str())
                .collect::<Vec<_>>(),
            ["Account", "Contact"]
        );
        assert!(drafts.iter().all(|draft| draft.source == "fake.crm"));
    }

    #[test]
    fn rejects_unordered_kinds_unknown_keys_and_bad_ratios() {
        assert!(discovery(&["Contact", "Account"]).validate().is_err());
        assert!(discovery(&["Account", "Account"]).validate().is_err());

        let mut unknown_key = discovery(&["Account"]);
        unknown_key.record_kinds[0].key_candidates = vec![vec!["missing".into()]];
        assert!(unknown_key.validate().is_err());

        let mut repeated_key = discovery(&["Account"]);
        repeated_key.record_kinds[0].key_candidates = vec![vec!["id".into(), "id".into()]];
        assert!(repeated_key.validate().is_err());

        let mut ratio = discovery(&["Account"]);
        ratio.record_kinds[0].columns[0].profile = Some(ColumnProfileHint {
            distinct_ratio_bp: PROFILE_RATIO_SCALE + 1,
            null_ratio_bp: 0,
            possibly_sensitive: false,
        });
        assert!(ratio.validate().is_err());
    }

    #[test]
    fn rejects_identity_separators_and_secret_like_names() {
        let mut kind = discovery(&["Account"]);
        kind.record_kinds[0].record_kind = "crm:Account".into();
        assert!(kind.validate().is_err());

        let mut secret = discovery(&["Account"]);
        secret.record_kinds[0].columns[1].name = "github_pat_abc".into();
        assert!(secret.validate().is_err());
    }

    #[test]
    fn keyless_record_kind_is_valid() {
        let mut keyless = discovery(&["Event"]);
        keyless.record_kinds[0].key_candidates.clear();
        keyless.validate().unwrap();
    }
}
