//! One Source sync, from a claimed Source to its outcome, without the plane.
//!
//! [`prepare`] checks everything that fails closed before a connection:
//! the connector type, the configuration against its schema, every
//! destination against the Source's egress allowlist, and the credential
//! handle against the runtime's binding. [`Connectors`] then opens the
//! type's implementation and runs one operation.

use std::collections::BTreeMap;
use std::sync::Arc;

use sekai_client::protocol::sekai::{ConnectorSource, source_config_value};
use sekai_source_sdk::{
    ConfigValue, Connector, ConnectorFailure, ConnectorType, EgressAllowlist, ExportArtifact,
    Operation, SnapshotRead, SourceConfig, connector_type,
};

use crate::credentials::{CredentialBindings, Credentials};

/// Why a sync failed, as the plane records it (`AckWork` reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncFailure {
    /// The credential handle did not resolve for this Source.
    Unavailable,
    Unreachable,
    AuthFailed,
    PermissionMissing,
    /// The Source or the remote system is not usable as it stands,
    /// including a destination outside the egress allowlist.
    Invalid,
    /// This runtime has no implementation of the type or operation.
    Unsupported,
}

impl SyncFailure {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Unreachable => "unreachable",
            Self::AuthFailed => "auth_failed",
            Self::PermissionMissing => "permission_missing",
            Self::Invalid => "invalid",
            Self::Unsupported => "unsupported",
        }
    }
}

impl From<ConnectorFailure> for SyncFailure {
    fn from(failure: ConnectorFailure) -> Self {
        match failure {
            ConnectorFailure::Unsupported => Self::Unsupported,
            ConnectorFailure::Unreachable => Self::Unreachable,
            ConnectorFailure::AuthFailed => Self::AuthFailed,
            ConnectorFailure::PermissionMissing => Self::PermissionMissing,
            _ => Self::Invalid,
        }
    }
}

/// A Source cleared to connect: its type, checked configuration and
/// resolved credentials.
#[derive(Debug)]
pub struct Prepared {
    pub connector: &'static ConnectorType,
    /// The Source's registered `source` token (`github`, `postgres.table`).
    pub source: String,
    /// The Source's instance token, such as a GitHub `owner/repository`.
    pub source_instance: String,
    pub config: SourceConfig,
    pub credentials: Credentials,
}

/// Checks the claimed Source before any connection. Fails closed.
pub fn prepare(
    source: &ConnectorSource,
    bindings: &CredentialBindings,
) -> Result<Prepared, SyncFailure> {
    let spec = source.spec.as_ref().ok_or(SyncFailure::Invalid)?;
    let connector = connector_type(&spec.connector_type, &spec.connector_version)
        .ok_or(SyncFailure::Unsupported)?;
    let config = spec
        .config
        .iter()
        .map(|(name, value)| {
            let value = match value.value.as_ref().ok_or(SyncFailure::Invalid)? {
                source_config_value::Value::Text(text) => ConfigValue::Text(text.clone()),
                source_config_value::Value::Integer(integer) => ConfigValue::Integer(*integer),
                source_config_value::Value::Boolean(boolean) => ConfigValue::Boolean(*boolean),
            };
            Ok((name.clone(), value))
        })
        .collect::<Result<SourceConfig, SyncFailure>>()?;
    let egress = EgressAllowlist::parse(&spec.egress).map_err(|_| SyncFailure::Invalid)?;
    connector
        .require_egress(&config, &egress)
        .map_err(|_| SyncFailure::Invalid)?;
    let destinations = connector
        .destinations(&config)
        .into_iter()
        .map(|(_, destination)| destination)
        .collect::<Vec<_>>();
    let credentials = bindings
        .resolve(
            &spec.credential_ref,
            &source.namespace,
            connector,
            &destinations,
        )
        .map_err(|_| SyncFailure::Unavailable)?;
    Ok(Prepared {
        connector,
        source: source.source.clone(),
        source_instance: source.source_instance.clone(),
        config,
        credentials,
    })
}

/// Runs `job` on the blocking pool; a job that panics is `Invalid`.
pub(crate) async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, SyncFailure> + Send + 'static,
) -> Result<T, SyncFailure> {
    tokio::task::spawn_blocking(job)
        .await
        .unwrap_or(Err(SyncFailure::Invalid))
}

/// Opens one type's implementation for a prepared Source.
pub type Open =
    Arc<dyn Fn(&Prepared) -> Result<Box<dyn Connector + Send>, ConnectorFailure> + Send + Sync>;

/// The connector types this runtime implements, by name and version. The
/// runtime claims only Sources of these types, so a runtime of an older
/// version leaves a newer type's work to a runtime that has it.
#[derive(Clone, Default)]
pub struct Connectors(BTreeMap<(&'static str, &'static str), Open>);

impl Connectors {
    pub fn with(
        mut self,
        connector: &'static ConnectorType,
        open: impl Fn(&Prepared) -> Result<Box<dyn Connector + Send>, ConnectorFailure>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.0
            .insert((connector.name, connector.version), Arc::new(open));
        self
    }

    /// The `(name, version)` of every type this runtime implements.
    pub fn types(&self) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        self.0.keys().copied()
    }

    /// The registered types that deliver saved exports.
    pub fn delivery_types(&self) -> Vec<(&'static str, &'static str)> {
        self.types()
            .filter(|(name, version)| {
                connector_type(name, version)
                    .is_some_and(|connector| connector.supports(Operation::Deliver))
            })
            .collect()
    }

    /// Whether this runtime runs Sources of the type the spec names.
    pub fn implements(&self, source: &ConnectorSource) -> bool {
        source.spec.as_ref().is_some_and(|spec| {
            self.0.keys().any(|(name, version)| {
                (*name, *version) == (&*spec.connector_type, &*spec.connector_version)
            })
        })
    }

    /// Whether this runtime delivers saved exports through Sources of the
    /// type the spec names.
    pub fn delivers(&self, source: &ConnectorSource) -> bool {
        self.implements(source)
            && source.spec.as_ref().is_some_and(|spec| {
                connector_type(&spec.connector_type, &spec.connector_version)
                    .is_some_and(|connector| connector.supports(Operation::Deliver))
            })
    }

    fn open(&self, prepared: &Prepared) -> Result<Box<dyn Connector + Send>, SyncFailure> {
        let open = self
            .0
            .get(&(prepared.connector.name, prepared.connector.version))
            .ok_or(SyncFailure::Unsupported)?;
        Ok(open(prepared)?)
    }

    /// Checks a prepared Source can be reached. Blocking.
    pub fn check(&self, prepared: &Prepared) -> Result<(), SyncFailure> {
        self.open(prepared)?.check()?;
        Ok(())
    }

    /// Reads one snapshot page of a prepared Source after
    /// `committed_cursor`. Blocking.
    pub fn read_page(
        &self,
        prepared: &Prepared,
        committed_cursor: Option<&str>,
        max_records: usize,
    ) -> Result<SnapshotRead, SyncFailure> {
        if !prepared.connector.supports(Operation::ReadPage) {
            return Err(SyncFailure::Unsupported);
        }
        Ok(self
            .open(prepared)?
            .read_page(committed_cursor, max_records)?)
    }

    /// Delivers one verified saved-export artifact through a prepared
    /// Source. Blocking.
    pub fn deliver(
        &self,
        prepared: &Prepared,
        artifact: &ExportArtifact<'_>,
    ) -> Result<(), SyncFailure> {
        if !prepared.connector.supports(Operation::Deliver) {
            return Err(SyncFailure::Unsupported);
        }
        self.open(prepared)?.deliver(artifact)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_client::protocol::sekai::{ConnectorSourceSpec, SourceConfigValue};
    use sekai_source_sdk::GITHUB_CONNECTOR;

    fn source(egress: &[&str], credential_ref: &str) -> ConnectorSource {
        ConnectorSource {
            namespace: "ops".into(),
            source_id: "repo".into(),
            spec: Some(ConnectorSourceSpec {
                connector_type: "github".into(),
                connector_version: "1".into(),
                config: [(
                    "api_url".to_string(),
                    SourceConfigValue {
                        value: Some(source_config_value::Value::Text(
                            "https://api.github.com".into(),
                        )),
                    },
                )]
                .into(),
                credential_ref: credential_ref.into(),
                egress: egress.iter().map(|rule| rule.to_string()).collect(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn bindings(dir: &std::path::Path) -> CredentialBindings {
        let token = dir.join("token");
        std::fs::write(&token, "value").unwrap();
        serde_json::from_value(serde_json::json!({
            "bot": {
                "namespaces": ["ops"],
                "destinations": ["api.github.com"],
                "slots": { "token": { "file": token } }
            }
        }))
        .unwrap()
    }

    #[test]
    fn prepare_fails_closed_before_any_connection() {
        let dir = tempfile::tempdir().unwrap();
        let bindings = bindings(dir.path());
        let prepared = prepare(&source(&["api.github.com"], "bot"), &bindings).unwrap();
        assert_eq!(prepared.connector, &GITHUB_CONNECTOR);
        assert_eq!(prepared.credentials["token"].expose(), "value");

        let mut unknown = source(&["api.github.com"], "bot");
        unknown.spec.as_mut().unwrap().connector_version = "9".into();
        for (source, failure) in [
            (source(&[], "bot"), SyncFailure::Invalid),
            (source(&["example.com"], "bot"), SyncFailure::Invalid),
            (
                source(&["api.github.com"], "other"),
                SyncFailure::Unavailable,
            ),
            (source(&["api.github.com"], ""), SyncFailure::Unavailable),
            (unknown, SyncFailure::Unsupported),
            (ConnectorSource::default(), SyncFailure::Invalid),
        ] {
            assert_eq!(prepare(&source, &bindings).unwrap_err(), failure);
        }
    }

    struct Checked(Result<(), ConnectorFailure>);

    impl Connector for Checked {
        fn check(&mut self) -> Result<(), ConnectorFailure> {
            self.0
        }
    }

    #[test]
    fn a_sync_runs_only_an_implemented_type() {
        let dir = tempfile::tempdir().unwrap();
        let bindings = bindings(dir.path());
        let github = source(&["api.github.com"], "bot");
        let prepared = prepare(&github, &bindings).unwrap();
        assert!(!Connectors::default().implements(&github));
        assert_eq!(
            Connectors::default().check(&prepared),
            Err(SyncFailure::Unsupported)
        );
        let connectors = Connectors::default().with(&GITHUB_CONNECTOR, |_| {
            Ok(Box::new(Checked(Err(ConnectorFailure::AuthFailed))))
        });
        assert!(connectors.implements(&github));
        assert_eq!(connectors.check(&prepared), Err(SyncFailure::AuthFailed));
    }
}
