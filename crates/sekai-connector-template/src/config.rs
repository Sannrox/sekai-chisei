//! Connector configuration. Credentials are referenced by environment
//! variable name and read at run time; the file never holds a secret.

use sekai_source_sdk::{SourceAdapterConfig, contains_secret_like_text};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    /// Control-plane gRPC endpoint.
    pub target: String,
    /// Environment variable holding the control-plane bearer credential.
    pub credential_env: String,
    pub namespace: String,
    pub producer_identity: String,
    /// Registered source name (ADR 0060).
    pub source: String,
    pub source_instance: String,
    /// Digest of the admitted source-type descriptor.
    pub type_digest: String,
    pub outbox_dir: PathBuf,
    /// Environment variable holding the source system credential.
    pub source_credential_env: String,
}

impl ConnectorConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if contains_secret_like_text(&text) {
            return Err("connector config must reference credentials, not contain them".into());
        }
        let config: Self = serde_json::from_str(&text)
            .map_err(|error| format!("connector config is invalid: {error}"))?;
        for name in [&config.credential_env, &config.source_credential_env] {
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                return Err(format!("{name:?} is not an environment variable name"));
            }
        }
        Ok(config)
    }

    /// The control-plane bearer credential, when the plane requires one.
    pub fn credential(&self) -> Option<String> {
        std::env::var(&self.credential_env).ok()
    }

    pub fn source_credential(&self) -> Option<String> {
        std::env::var(&self.source_credential_env).ok()
    }

    pub fn adapter(&self) -> SourceAdapterConfig {
        SourceAdapterConfig {
            namespace: self.namespace.clone(),
            producer_identity: self.producer_identity.clone(),
            source_instance: self.source_instance.clone(),
            type_digest: self.type_digest.clone(),
        }
    }
}
