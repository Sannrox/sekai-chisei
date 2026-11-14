//! Connector type contract (ADR 0148).
//!
//! A connector type is what the one connector runtime runs for a Source. It
//! declares the operations it supports, the configuration a Source of that
//! type carries, and the credential slots the runtime fills from an
//! operator-issued credential handle. The plane validates a Source's
//! configuration against the declared schema; it never sees a credential.
//!
//! Configuration is flat, bounded and value-free: credentials live only in
//! slots, so a configuration that looks like it carries one is refused.
//! Every outbound address is a [`ConfigFieldKind::Destination`] field, which
//! the runtime checks against the Source's [`EgressAllowlist`] before it
//! connects, failing closed.

use crate::contract::{
    SOURCE_GITHUB, contains_secret_like_text, require_bounded_identifier,
    require_registered_record_token, validate_github_repository,
};
use crate::discover::{DiscoverySample, SourceDiscovery};
use crate::feed::ChangeFeedPage;
use crate::snapshot::SnapshotRead;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_CONFIG_FIELDS: usize = 64;
pub const MAX_CONFIG_VALUE_BYTES: usize = 1024;
pub const MAX_EGRESS_RULES: usize = 64;

/// One operation a connector type may support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Operation {
    /// Prove connectivity and credentials without reading records.
    Check,
    /// List what the source offers, as discovery drafts.
    Discover,
    /// Read one snapshot page after the plane-owned cursor.
    ReadPage,
    /// Read one ordered change-feed page after the plane-owned offset.
    ReadChanges,
    /// Deliver a saved-export artifact out of the plane.
    Deliver,
    /// Apply an `external_mutate` writeback effect.
    Apply,
}

impl Operation {
    pub const ALL: [Operation; 6] = [
        Operation::Check,
        Operation::Discover,
        Operation::ReadPage,
        Operation::ReadChanges,
        Operation::Deliver,
        Operation::Apply,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Operation::Check => "check",
            Operation::Discover => "discover",
            Operation::ReadPage => "read_page",
            Operation::ReadChanges => "read_changes",
            Operation::Deliver => "deliver",
            Operation::Apply => "apply",
        }
    }

    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.wire_name() == name)
    }
}

/// The value shape of one configuration field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigFieldKind {
    Text,
    Integer,
    Boolean,
    /// An address the connector connects to: `host`, `host:port`, or a URL
    /// without user information. The egress allowlist must permit it.
    Destination,
}

/// One field of a connector type's configuration schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigField {
    pub name: &'static str,
    pub kind: ConfigFieldKind,
    pub required: bool,
}

/// A named credential the runtime fills from the Source's credential handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialSlot {
    pub name: &'static str,
    pub required: bool,
}

/// One connector type at one version. Types are data: the plane validates
/// Sources against them and the runtime matches its implementations to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorType {
    pub name: &'static str,
    pub version: &'static str,
    /// The `source` token every Source of this type uses, when the type
    /// fixes one (GitHub). `None` lets the Source name its registered token.
    pub fixed_source: Option<&'static str>,
    pub operations: &'static [Operation],
    pub config: &'static [ConfigField],
    pub credential_slots: &'static [CredentialSlot],
}

/// GitHub object sync and writeback. The Source's instance is
/// `owner/repository`, so object ids match the existing profile.
pub const GITHUB_CONNECTOR: ConnectorType = ConnectorType {
    name: "github",
    version: "1",
    fixed_source: Some(SOURCE_GITHUB),
    operations: &[Operation::Check, Operation::ReadPage, Operation::Apply],
    config: &[ConfigField {
        name: "api_url",
        kind: ConfigFieldKind::Destination,
        required: true,
    }],
    credential_slots: &[CredentialSlot {
        name: "token",
        required: true,
    }],
};

/// The reference relational source (ADR 0100): snapshot pages from one
/// table, and saved-export delivery into a delivery table.
pub const RELATIONAL_CONNECTOR: ConnectorType = ConnectorType {
    name: "relational",
    version: "1",
    fixed_source: None,
    operations: &[
        Operation::Check,
        Operation::Discover,
        Operation::ReadPage,
        Operation::Deliver,
    ],
    config: &[
        ConfigField {
            name: "endpoint",
            kind: ConfigFieldKind::Destination,
            required: true,
        },
        ConfigField {
            name: "database",
            kind: ConfigFieldKind::Text,
            required: true,
        },
        ConfigField {
            name: "user",
            kind: ConfigFieldKind::Text,
            required: true,
        },
        ConfigField {
            name: "table",
            kind: ConfigFieldKind::Text,
            required: false,
        },
        ConfigField {
            name: "delivery_table",
            kind: ConfigFieldKind::Text,
            required: false,
        },
        ConfigField {
            name: "type_digest",
            kind: ConfigFieldKind::Text,
            required: false,
        },
        ConfigField {
            name: "record_kind",
            kind: ConfigFieldKind::Text,
            required: false,
        },
        ConfigField {
            name: "pk_columns",
            kind: ConfigFieldKind::Text,
            required: false,
        },
        ConfigField {
            name: "monotonic_column",
            kind: ConfigFieldKind::Text,
            required: false,
        },
        ConfigField {
            name: "display_column",
            kind: ConfigFieldKind::Text,
            required: false,
        },
        ConfigField {
            name: "version_column",
            kind: ConfigFieldKind::Text,
            required: false,
        },
    ],
    credential_slots: &[CredentialSlot {
        name: "password",
        required: true,
    }],
};

/// Every connector type this SDK version defines.
pub const CONNECTOR_TYPES: &[ConnectorType] = &[GITHUB_CONNECTOR, RELATIONAL_CONNECTOR];

/// The connector type with this name and version, if this SDK defines it.
pub fn connector_type(name: &str, version: &str) -> Option<&'static ConnectorType> {
    CONNECTOR_TYPES
        .iter()
        .find(|ty| ty.name == name && ty.version == version)
}

/// One configuration value. Nested values are not configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ConfigValue {
    Boolean(bool),
    Integer(i64),
    Text(String),
}

/// A Source's configuration, keyed by field name.
pub type SourceConfig = BTreeMap<String, ConfigValue>;

/// Why a configuration, destination or allowlist was refused. Value-free:
/// it names schema fields, never the values a caller sent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    TooManyFields,
    UnknownField,
    MissingField(&'static str),
    WrongKind(&'static str),
    /// Empty, untrimmed, too long, or carrying control characters.
    InvalidValue(&'static str),
    /// A value looks like it carries a credential. Credentials go in slots.
    SecretLike(&'static str),
    InvalidDestination(&'static str),
    InvalidEgressRule,
    TooManyEgressRules,
    /// A destination the allowlist does not permit.
    EgressDenied(&'static str),
    /// `source` or `source_instance` is not a token this type may use.
    InvalidSourceTokens,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyFields => formatter.write_str("configuration has too many fields"),
            Self::UnknownField => formatter.write_str("configuration names an unknown field"),
            Self::MissingField(field) => {
                write!(formatter, "configuration field {field} is required")
            }
            Self::WrongKind(field) => {
                write!(formatter, "configuration field {field} has the wrong kind")
            }
            Self::InvalidValue(field) => write!(
                formatter,
                "configuration field {field} must be nonempty, trimmed text of at most {MAX_CONFIG_VALUE_BYTES} bytes"
            ),
            Self::SecretLike(field) => write!(
                formatter,
                "configuration field {field} looks like a credential; name a credential handle instead"
            ),
            Self::InvalidDestination(field) => {
                write!(
                    formatter,
                    "configuration field {field} is not a valid destination"
                )
            }
            Self::InvalidEgressRule => formatter.write_str("egress rule is not host or host:port"),
            Self::TooManyEgressRules => formatter.write_str("egress allowlist has too many rules"),
            Self::InvalidSourceTokens => formatter
                .write_str("source or source_instance is not valid for this connector type"),
            Self::EgressDenied(field) => {
                write!(
                    formatter,
                    "egress allowlist does not permit configuration field {field}"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl ConnectorType {
    pub fn supports(&self, operation: Operation) -> bool {
        self.operations.contains(&operation)
    }

    /// Validate the `source` and `source_instance` tokens a Source of this
    /// type holds. They feed `source_id(source, source_instance,
    /// external_id)`, so they follow the batch contract: canonical
    /// `owner/repository` for GitHub, registered tokens (ADR 0060) otherwise.
    pub fn validate_tokens(&self, source: &str, source_instance: &str) -> Result<(), ConfigError> {
        let valid = match self.fixed_source {
            Some(fixed) if source != fixed => false,
            Some(SOURCE_GITHUB) => {
                require_bounded_identifier("source_instance", source_instance).is_ok()
                    && validate_github_repository(source_instance).is_ok()
            }
            Some(_) => {
                require_registered_record_token("source_instance", source_instance, true).is_ok()
            }
            None => {
                source != SOURCE_GITHUB
                    && require_registered_record_token("source", source, false).is_ok()
                    && require_registered_record_token("source_instance", source_instance, true)
                        .is_ok()
            }
        };
        if valid && !contains_secret_like_text(source_instance) {
            Ok(())
        } else {
            Err(ConfigError::InvalidSourceTokens)
        }
    }

    /// Validate a Source configuration against this type's schema: no
    /// unknown fields, every required field present with its kind, bounded
    /// values, valid destinations and nothing that looks like a credential.
    pub fn validate_config(&self, config: &SourceConfig) -> Result<(), ConfigError> {
        if config.len() > MAX_CONFIG_FIELDS {
            return Err(ConfigError::TooManyFields);
        }
        if config
            .keys()
            .any(|name| !self.config.iter().any(|field| field.name == name))
        {
            return Err(ConfigError::UnknownField);
        }
        for field in self.config {
            let Some(value) = config.get(field.name) else {
                if field.required {
                    return Err(ConfigError::MissingField(field.name));
                }
                continue;
            };
            match (field.kind, value) {
                (ConfigFieldKind::Integer, ConfigValue::Integer(_))
                | (ConfigFieldKind::Boolean, ConfigValue::Boolean(_)) => {}
                (ConfigFieldKind::Text, ConfigValue::Text(text)) => check_text(field.name, text)?,
                (ConfigFieldKind::Destination, ConfigValue::Text(text)) => {
                    check_text(field.name, text)?;
                    Destination::parse(text).ok_or(ConfigError::InvalidDestination(field.name))?;
                }
                _ => return Err(ConfigError::WrongKind(field.name)),
            }
        }
        Ok(())
    }

    /// The destinations a valid configuration names, with their field.
    pub fn destinations(&self, config: &SourceConfig) -> Vec<(&'static str, Destination)> {
        self.config
            .iter()
            .filter(|field| field.kind == ConfigFieldKind::Destination)
            .filter_map(|field| match config.get(field.name) {
                Some(ConfigValue::Text(text)) => {
                    Destination::parse(text).map(|destination| (field.name, destination))
                }
                _ => None,
            })
            .collect()
    }

    /// Every destination of a valid configuration is permitted by `egress`.
    /// The runtime calls this before it opens a connector; a refusal fails
    /// the run instead of connecting.
    pub fn require_egress(
        &self,
        config: &SourceConfig,
        egress: &EgressAllowlist,
    ) -> Result<(), ConfigError> {
        self.validate_config(config)?;
        match self
            .destinations(config)
            .into_iter()
            .find(|(_, destination)| !egress.permits(destination))
        {
            Some((field, _)) => Err(ConfigError::EgressDenied(field)),
            None => Ok(()),
        }
    }
}

fn check_text(field: &'static str, text: &str) -> Result<(), ConfigError> {
    if text.is_empty()
        || text.trim() != text
        || text.len() > MAX_CONFIG_VALUE_BYTES
        || text.chars().any(char::is_control)
    {
        return Err(ConfigError::InvalidValue(field));
    }
    if contains_secret_like_text(text) {
        return Err(ConfigError::SecretLike(field));
    }
    Ok(())
}

/// A host and optional port a connector connects to. IPv6 literals are
/// refused (fail closed); name such a host by DNS.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Destination {
    /// Lowercase DNS name or IPv4 address.
    pub host: String,
    pub port: Option<u16>,
}

impl Destination {
    /// Parse `host`, `host:port`, or `scheme://host[:port][/path]`. User
    /// information (`user:password@host`) is refused: credentials go in
    /// slots, never in a destination. A query or fragment is refused too:
    /// connection strings read hosts and ports from query keys, which the
    /// egress check would not see. A URL with a well-known scheme and no
    /// port gets the scheme's default port, so a `host:port` egress rule
    /// matches it.
    pub fn parse(text: &str) -> Option<Self> {
        let (scheme, rest) = match text.split_once("://") {
            Some((scheme, rest)) if is_scheme(scheme) => (Some(scheme), rest),
            Some(_) => return None,
            None => (None, text),
        };
        if rest.contains(['?', '#']) {
            return None;
        }
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.contains('@') {
            return None;
        }
        let mut destination = Self::parse_authority(authority)?;
        if destination.port.is_none() {
            destination.port = scheme.and_then(default_port);
        }
        Some(destination)
    }

    fn parse_authority(authority: &str) -> Option<Self> {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse::<u16>().ok().filter(|p| *p != 0)?)),
            None => (authority, None),
        };
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && !host.starts_with(['.', '-'])
            && !host.ends_with(['.', '-'])
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
        valid_host.then(|| Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme.to_ascii_lowercase().as_str() {
        "https" => Some(443),
        "http" => Some(80),
        "postgres" | "postgresql" => Some(5432),
        _ => None,
    }
}

fn is_scheme(scheme: &str) -> bool {
    scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The hosts a Source may reach. A rule is `host` (any port) or
/// `host:port`; matching is exact on the lowercase host. An empty allowlist
/// permits nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressAllowlist {
    rules: Vec<Destination>,
}

impl EgressAllowlist {
    pub fn parse<S: AsRef<str>>(rules: &[S]) -> Result<Self, ConfigError> {
        if rules.len() > MAX_EGRESS_RULES {
            return Err(ConfigError::TooManyEgressRules);
        }
        let mut parsed = rules
            .iter()
            .map(|rule| Destination::parse_authority(rule.as_ref()))
            .collect::<Option<Vec<_>>>()
            .ok_or(ConfigError::InvalidEgressRule)?;
        parsed.sort();
        parsed.dedup();
        Ok(Self { rules: parsed })
    }

    pub fn permits(&self, destination: &Destination) -> bool {
        self.rules.iter().any(|rule| {
            rule.host == destination.host && (rule.port.is_none() || rule.port == destination.port)
        })
    }

    /// Canonical rule text, sorted and deduplicated, as the plane stores it.
    pub fn rules(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|rule| match rule.port {
                Some(port) => format!("{}:{port}", rule.host),
                None => rule.host.clone(),
            })
            .collect()
    }
}

/// Why an operation failed. Value-free: no credentials, hosts or remote
/// response bodies. The runtime maps it onto the Source's health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectorFailure {
    /// The type does not implement the operation.
    Unsupported,
    Unreachable,
    AuthFailed,
    PermissionMissing,
    /// The remote record changed since the version the effect was decided
    /// against, or a replay could not be proven. Nothing was written.
    Conflict,
    /// The remote system returned something the type cannot use.
    Invalid,
}

impl std::fmt::Display for ConnectorFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "connector type does not support the operation",
            Self::Unreachable => "source is unreachable",
            Self::AuthFailed => "source rejected the credentials",
            Self::PermissionMissing => "source credentials lack a required permission",
            Self::Conflict => "source record changed; nothing was written",
            Self::Invalid => "source returned an unusable response",
        })
    }
}

impl std::error::Error for ConnectorFailure {}

/// A claimed saved-export artifact, with the bytes the runtime fetched and
/// verified against `content_digest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportArtifact<'a> {
    pub receipt_id: &'a str,
    pub namespace: &'a str,
    pub definition_id: &'a str,
    pub content_digest: &'a str,
    pub bytes: &'a [u8],
}

/// One `external_mutate` change to one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordChange {
    /// The effect's idempotency key; a retry presents the same key.
    pub idempotency_key: String,
    pub key: String,
    /// The record version the change was decided against.
    pub expected_version: String,
    pub change: BTreeMap<String, String>,
}

/// One connected Source of some connector type. The runtime opens it with
/// the Source's configuration and resolved credentials, after the egress
/// check, and calls only the operations the type declares; the rest keep
/// their `Unsupported` default.
///
/// `deliver` and `apply` run under a claim that may be retried after a
/// crash, so both are keyed: delivering the same `receipt_id` again must
/// not duplicate the artifact, and `apply` must either recognise a repeated
/// `idempotency_key` or return [`ConnectorFailure::Conflict`] rather than
/// write twice.
pub trait Connector {
    fn check(&mut self) -> Result<(), ConnectorFailure> {
        Err(ConnectorFailure::Unsupported)
    }

    fn discover(&mut self) -> Result<SourceDiscovery, ConnectorFailure> {
        Err(ConnectorFailure::Unsupported)
    }

    /// Bounded peek at values for one discovered record kind. The size cap
    /// is plane-owned. Types that do not sample keep this default.
    fn sample_rows(&mut self, _record_kind: &str) -> Result<DiscoverySample, ConnectorFailure> {
        Err(ConnectorFailure::Unsupported)
    }

    fn read_page(
        &mut self,
        _committed_cursor: Option<&str>,
        _max_records: usize,
    ) -> Result<SnapshotRead, ConnectorFailure> {
        Err(ConnectorFailure::Unsupported)
    }

    fn read_changes(
        &mut self,
        _source_feed_epoch: &str,
        _committed_offset: u64,
        _max_records: usize,
    ) -> Result<ChangeFeedPage, ConnectorFailure> {
        Err(ConnectorFailure::Unsupported)
    }

    fn deliver(&mut self, _artifact: &ExportArtifact<'_>) -> Result<(), ConnectorFailure> {
        Err(ConnectorFailure::Unsupported)
    }

    /// Returns the record's new version.
    fn apply(&mut self, _change: &RecordChange) -> Result<String, ConnectorFailure> {
        Err(ConnectorFailure::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> ConfigValue {
        ConfigValue::Text(value.into())
    }

    fn relational() -> SourceConfig {
        SourceConfig::from([
            ("endpoint".into(), text("db.internal:5432")),
            ("database".into(), text("orders")),
            ("user".into(), text("reader")),
        ])
    }

    #[test]
    fn operation_wire_names_round_trip() {
        for op in Operation::ALL {
            assert_eq!(Operation::from_wire_name(op.wire_name()), Some(op));
        }
        assert_eq!(Operation::from_wire_name("sync"), None);
    }

    #[test]
    fn defined_types_are_unique_and_declare_no_credential_in_configuration() {
        for (index, ty) in CONNECTOR_TYPES.iter().enumerate() {
            assert_eq!(connector_type(ty.name, ty.version), Some(ty));
            assert!(
                CONNECTOR_TYPES[index + 1..]
                    .iter()
                    .all(|other| (other.name, other.version) != (ty.name, ty.version))
            );
            assert!(!ty.operations.is_empty());
            for field in ty.config {
                let name = field.name;
                assert!(
                    !["password", "secret", "token", "credential", "key"]
                        .iter()
                        .any(|word| name.contains(word)),
                    "{}: {name} belongs in a credential slot",
                    ty.name
                );
            }
        }
        assert_eq!(connector_type("github", "2"), None);
    }

    #[test]
    fn configuration_is_validated_against_the_schema() {
        RELATIONAL_CONNECTOR.validate_config(&relational()).unwrap();

        let mut missing = relational();
        missing.remove("database");
        assert_eq!(
            RELATIONAL_CONNECTOR.validate_config(&missing),
            Err(ConfigError::MissingField("database"))
        );

        let mut unknown = relational();
        unknown.insert("schema".into(), text("public"));
        assert_eq!(
            RELATIONAL_CONNECTOR.validate_config(&unknown),
            Err(ConfigError::UnknownField)
        );

        let mut wrong = relational();
        wrong.insert("table".into(), ConfigValue::Integer(3));
        assert_eq!(
            RELATIONAL_CONNECTOR.validate_config(&wrong),
            Err(ConfigError::WrongKind("table"))
        );

        let mut pages = relational();
        pages.insert(
            "type_digest".into(),
            text("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        pages.insert("record_kind".into(), text("Order"));
        pages.insert("pk_columns".into(), text("id"));
        pages.insert("monotonic_column".into(), text("updated_at"));
        pages.insert("display_column".into(), text("name"));
        pages.insert("version_column".into(), text("updated_at"));
        pages.insert("table".into(), text("orders"));
        RELATIONAL_CONNECTOR.validate_config(&pages).unwrap();

        for value in [
            "",
            "  ",
            " orders",
            "a\nb",
            &"x".repeat(MAX_CONFIG_VALUE_BYTES + 1),
        ] {
            let mut bad = relational();
            bad.insert("database".into(), text(value));
            assert_eq!(
                RELATIONAL_CONNECTOR.validate_config(&bad),
                Err(ConfigError::InvalidValue("database")),
                "{value:?}"
            );
        }
    }

    #[test]
    fn secret_like_configuration_is_refused() {
        let mut token = relational();
        token.insert("table".into(), text("ghp_0123456789abcdef"));
        assert_eq!(
            RELATIONAL_CONNECTOR.validate_config(&token),
            Err(ConfigError::SecretLike("table"))
        );

        let mut password = relational();
        password.insert("user".into(), text("reader password=hunter2"));
        assert_eq!(
            RELATIONAL_CONNECTOR.validate_config(&password),
            Err(ConfigError::SecretLike("user"))
        );

        let mut userinfo = relational();
        userinfo.insert(
            "endpoint".into(),
            text("postgres://reader:hunter2@db.internal:5432/orders"),
        );
        assert_eq!(
            RELATIONAL_CONNECTOR.validate_config(&userinfo),
            Err(ConfigError::InvalidDestination("endpoint"))
        );

        let named = SourceConfig::from([("token".into(), text("abc"))]);
        assert_eq!(
            GITHUB_CONNECTOR.validate_config(&named),
            Err(ConfigError::UnknownField)
        );
    }

    #[test]
    fn source_tokens_follow_the_batch_contract() {
        GITHUB_CONNECTOR
            .validate_tokens("github", "acme/repo")
            .unwrap();
        RELATIONAL_CONNECTOR
            .validate_tokens("postgres.table", "sys/db/public/orders")
            .unwrap();
        let long = format!("acme/{}", "r".repeat(600));
        for (ty, source, instance) in [
            (GITHUB_CONNECTOR, "github", long.as_str()),
            (GITHUB_CONNECTOR, "gitlab", "acme/repo"),
            (GITHUB_CONNECTOR, "github", "Acme/Repo"),
            (GITHUB_CONNECTOR, "github", "acme"),
            (RELATIONAL_CONNECTOR, "github", "acme/repo"),
            (RELATIONAL_CONNECTOR, "postgres:table", "x"),
            (RELATIONAL_CONNECTOR, "postgres.table", "a#b"),
            (RELATIONAL_CONNECTOR, "postgres.table", "ghp_abcdef"),
        ] {
            assert_eq!(
                ty.validate_tokens(source, instance),
                Err(ConfigError::InvalidSourceTokens),
                "{source} {instance}"
            );
        }
    }

    #[test]
    fn configuration_values_are_flat_json() {
        let config: SourceConfig =
            serde_json::from_str(r#"{"api_url":"https://api.github.com","n":3,"b":true}"#).unwrap();
        assert_eq!(config["n"], ConfigValue::Integer(3));
        assert_eq!(config["b"], ConfigValue::Boolean(true));
        assert!(serde_json::from_str::<SourceConfig>(r#"{"api_url":{"host":"x"}}"#).is_err());
    }

    #[test]
    fn destinations_parse_host_port_and_url() {
        assert_eq!(
            Destination::parse("https://API.github.com/v3"),
            Some(Destination {
                host: "api.github.com".into(),
                port: Some(443)
            })
        );
        assert_eq!(
            Destination::parse("api.github.com"),
            Some(Destination {
                host: "api.github.com".into(),
                port: None
            })
        );
        assert_eq!(
            Destination::parse("custom://db.internal").map(|d| d.port),
            Some(None)
        );
        let allow = EgressAllowlist::parse(&["api.github.com:443"]).unwrap();
        assert!(allow.permits(&Destination::parse("https://api.github.com").unwrap()));
        assert!(!allow.permits(&Destination::parse("http://api.github.com").unwrap()));
        assert_eq!(
            Destination::parse("db.internal:5432"),
            Some(Destination {
                host: "db.internal".into(),
                port: Some(5432)
            })
        );
        for bad in [
            "",
            "https://",
            "db:0",
            "db:99999",
            "user@db",
            "-db",
            "[::1]:5432",
            "a b",
            "1https://db",
            "https://api.github.com/v3?x=1",
            "postgres://db.internal:5432/orders?host=10.0.0.1",
            "db.internal#x",
        ] {
            assert_eq!(Destination::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn egress_allowlist_fails_closed() {
        let config = relational();
        assert_eq!(
            RELATIONAL_CONNECTOR.require_egress(&config, &EgressAllowlist::default()),
            Err(ConfigError::EgressDenied("endpoint"))
        );
        let other_port = EgressAllowlist::parse(&["db.internal:5433"]).unwrap();
        assert_eq!(
            RELATIONAL_CONNECTOR.require_egress(&config, &other_port),
            Err(ConfigError::EgressDenied("endpoint"))
        );
        for rules in [["db.internal"], ["DB.internal:5432"]] {
            let allow = EgressAllowlist::parse(&rules).unwrap();
            RELATIONAL_CONNECTOR
                .require_egress(&config, &allow)
                .unwrap();
        }
        assert_eq!(
            EgressAllowlist::parse(&["https://db.internal"]),
            Err(ConfigError::InvalidEgressRule)
        );
        assert_eq!(
            EgressAllowlist::parse(&["b:1", "a", "b:1"])
                .unwrap()
                .rules(),
            ["a", "b:1"]
        );
    }

    #[test]
    fn undeclared_operations_are_unsupported() {
        struct ReadOnly;
        impl Connector for ReadOnly {
            fn check(&mut self) -> Result<(), ConnectorFailure> {
                Ok(())
            }
        }
        let mut connector = ReadOnly;
        assert_eq!(connector.check(), Ok(()));
        assert_eq!(
            connector.apply(&RecordChange {
                idempotency_key: "k".into(),
                key: "1".into(),
                expected_version: "v1".into(),
                change: BTreeMap::new(),
            }),
            Err(ConnectorFailure::Unsupported)
        );
        assert_eq!(
            connector.sample_rows("Order"),
            Err(ConnectorFailure::Unsupported)
        );
        assert!(GITHUB_CONNECTOR.supports(Operation::Apply));
        assert!(!GITHUB_CONNECTOR.supports(Operation::Deliver));
    }
}
