use std::env;
use tracing::warn;

use crate::chisei::budget::BudgetTopologyConfig;

#[derive(Clone)]
pub struct Config {
    pub grpc_port: u16,
    pub sekai_bind: Option<String>,
    pub ops_port: Option<u16>,
    pub ops_bind: String,
    /// HTTP/JSON projection of stable gRPC. Empty `SEKAI_HTTP_PORT` disables it.
    pub http_port: Option<u16>,
    pub http_bind: String,
    pub sekai_socket: Option<String>,
    pub db_path: String,
    pub anthropic_api_key: Option<String>,
    pub openai_api_key: Option<String>,
    pub ollama_url: String,
    pub native_llm_url: Option<String>,
    pub sample_rate: f64,
    pub sample_risk_threshold: f64,
    pub scoring_enabled: bool,
    pub scoring_interval_secs: u64,
    pub scoring_model: String,
    pub scoring_batch_size: i32,
    pub default_data_class: String,
    pub safe_egress_providers: Vec<String>,
    /// Providers whose upstream auth is supplied by the gateway rather than this
    /// control-plane server (e.g. Codex ChatGPT-plan passthrough). Model routing
    /// treats them as available even when the server holds no API key for them.
    pub gateway_provided_providers: Vec<String>,
    /// Operator-owned origins customer-hosted routing profiles may use
    /// (`SEKAI_ROUTING_ENDPOINT_ALLOWLIST`, #1171), as canonical origins.
    pub routing_endpoint_allowlist: Vec<String>,
    /// Community credential references that resolve: the `<REF>` of every
    /// non-empty `SEKAI_ROUTING_CREDENTIAL_<REF>` variable. Names only; the
    /// secret values are never held here.
    pub routing_credential_refs: Vec<String>,
    /// Authenticated service principals allowed to persist gateway operation receipts.
    pub gateway_receipt_principals: Vec<String>,
    pub leak_review_model: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Client CA PEM path. When set with server TLS, the gRPC listener requires
    /// a client certificate signed by this CA. Unset keeps server-TLS-only.
    pub tls_client_ca: Option<String>,
    pub allow_plaintext: bool,
    pub insecure: bool,
    /// Hex-encoded Ed25519 seed used only to sign short-lived external-action permits.
    pub permit_signing_key: Option<String>,
    pub permit_issuer: String,
    pub permit_key_id: String,
    /// Hex-encoded Ed25519 seed used only for Tenkai-compatible governed-subject
    /// provenance. The key is never projected through an API.
    pub governed_subject_provenance_signing_key: Option<String>,
    pub governed_subject_provenance_key_not_before_ms: i64,
    pub governed_subject_provenance_key_expires_at_ms: i64,
    pub governed_subject_provenance_ttl_ms: i64,
    /// Stable region/site pin for leases and online permit redemption (#293).
    /// Default `"local"` keeps single-region deployments unchanged.
    pub site_id: String,
    /// Multi-region budget topology (#294). Default `single_region`.
    pub budget_topology: BudgetTopologyConfig,
    /// Optional audience-bound assertion authority (#888). All three of issuer,
    /// audience, and HMAC key must be set together; partial config is refused.
    pub assertion_issuer: Option<String>,
    pub assertion_audience: Option<String>,
    pub assertion_hmac_key: Option<String>,
    /// Authenticated hop target for a Chisei process (`http://127.0.0.1:50051`).
    /// Required to boot `chisei-plane` (ADR 0096 rule 4). Combined mode ignores it.
    pub sekai_endpoint: Option<String>,
    /// Per-principal and per-agent rate limits plus the agent grant ceiling (#1563).
    /// Off until callers send actor chains.
    pub actor_chain_enforcement: bool,
    pub principal_requests_per_minute: u32,
    pub agent_requests_per_minute: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrpcTcpMode {
    pub bind_addr: String,
    pub token_auth_mode: bool,
    pub auth_configured: bool,
    pub bind_inferred_from_active_credentials: bool,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            grpc_port: env("GRPC_PORT", "50051").parse().unwrap_or(50051),
            sekai_bind: optional_env("SEKAI_BIND"),
            ops_port: optional_port("OPS_PORT", "9464"),
            ops_bind: env("OPS_BIND", "127.0.0.1"),
            http_port: optional_port("SEKAI_HTTP_PORT", "50080"),
            http_bind: env("SEKAI_HTTP_BIND", "127.0.0.1"),
            sekai_socket: socket_path("SEKAI_SOCKET", "./data/sekai.sock"),
            db_path: default_sekai_sqlite_path(),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok(),
            openai_api_key: env::var("OPENAI_API_KEY").ok(),
            ollama_url: env("OLLAMA_URL", "http://localhost:11434"),
            native_llm_url: env::var("NATIVE_LLM_URL").ok(),
            sample_rate: env("SAMPLE_RATE", "0.05").parse().unwrap_or(0.05),
            sample_risk_threshold: env("SAMPLE_RISK_THRESHOLD", "0.7").parse().unwrap_or(0.7),
            scoring_enabled: env("SCORING_ENABLED", "false").parse().unwrap_or(false),
            scoring_interval_secs: env("SCORING_INTERVAL_SECS", "60").parse().unwrap_or(60),
            scoring_model: env("SCORING_MODEL", "claude-opus-4-8"),
            scoring_batch_size: env("SCORING_BATCH_SIZE", "16").parse().unwrap_or(16),
            default_data_class: env("CHISEI_DEFAULT_DATA_CLASS", "unclassified"),
            safe_egress_providers: csv_env("CHISEI_SAFE_EGRESS_PROVIDERS"),
            gateway_provided_providers: csv_env("CHISEI_GATEWAY_PROVIDED_PROVIDERS"),
            routing_endpoint_allowlist: crate::chisei::routing_profiles::endpoint_allowlist(),
            routing_credential_refs: crate::chisei::routing_profiles::resolvable_credential_refs(),
            gateway_receipt_principals: identity_csv_env("CHISEI_GATEWAY_RECEIPT_PRINCIPALS"),
            leak_review_model: env::var("LEAK_REVIEW_MODEL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            tls_cert: env::var("SEKAI_TLS_CERT")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            tls_key: env::var("SEKAI_TLS_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            tls_client_ca: env::var("SEKAI_TLS_CLIENT_CA")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            allow_plaintext: env::var("SEKAI_ALLOW_PLAINTEXT").unwrap_or_default() == "1",
            insecure: env::var("SEKAI_INSECURE").unwrap_or_default() == "1",
            permit_signing_key: optional_env("CHISEI_PERMIT_SIGNING_KEY"),
            permit_issuer: env("CHISEI_PERMIT_ISSUER", "chisei.local"),
            permit_key_id: env("CHISEI_PERMIT_KEY_ID", "permit-key-1"),
            governed_subject_provenance_signing_key: optional_env(
                "CHISEI_GOVERNED_SUBJECT_PROVENANCE_SIGNING_KEY",
            ),
            governed_subject_provenance_key_not_before_ms: security_i64_env(
                "CHISEI_GOVERNED_SUBJECT_PROVENANCE_KEY_NOT_BEFORE_MS",
                0,
                i64::MAX,
            ),
            governed_subject_provenance_key_expires_at_ms: security_i64_env(
                "CHISEI_GOVERNED_SUBJECT_PROVENANCE_KEY_EXPIRES_AT_MS",
                i64::MAX,
                i64::MIN,
            ),
            governed_subject_provenance_ttl_ms: security_i64_env(
                "CHISEI_GOVERNED_SUBJECT_PROVENANCE_TTL_MS",
                24 * 60 * 60 * 1_000,
                0,
            ),
            site_id: site_id_env("SEKAI_SITE_ID", "local"),
            budget_topology: BudgetTopologyConfig::from_env().unwrap_or_else(|err| {
                warn!(error = %err, "invalid budget topology config; using single_region");
                BudgetTopologyConfig::single_region()
            }),
            assertion_issuer: optional_env("SEKAI_ASSERTION_ISSUER"),
            assertion_audience: optional_env("SEKAI_ASSERTION_AUDIENCE"),
            assertion_hmac_key: optional_env("SEKAI_ASSERTION_HMAC_KEY"),
            sekai_endpoint: optional_env("SEKAI_ENDPOINT"),
            actor_chain_enforcement: env::var("SEKAI_ACTOR_CHAIN_ENFORCEMENT").unwrap_or_default()
                == "1",
            principal_requests_per_minute: env("SEKAI_PRINCIPAL_REQUESTS_PER_MINUTE", "60")
                .parse()
                .unwrap_or(60),
            agent_requests_per_minute: env("SEKAI_AGENT_REQUESTS_PER_MINUTE", "60")
                .parse()
                .unwrap_or(60),
        }
    }

    /// The identity-assertion verifier, or `None` when none is configured.
    /// Reads `SEKAI_ASSERTION_ED25519_KEYS` and `SEKAI_ASSERTION_ACCEPT_HMAC`
    /// beside the fields on this config.
    pub fn assertion_authority(
        &self,
    ) -> Result<Option<crate::identity_assertion::AssertionAuthority>, String> {
        self.assertion_authority_with(
            optional_env("SEKAI_ASSERTION_ED25519_KEYS").as_deref(),
            optional_env("SEKAI_ASSERTION_ACCEPT_HMAC").as_deref(),
        )
    }

    /// [`Self::assertion_authority`] with the Ed25519 public keys and the
    /// HMAC acceptance switch given instead of read from the environment.
    /// Issuer and audience are required with either key; HMAC acceptance
    /// defaults on and may be off only when Ed25519 keys are configured.
    pub fn assertion_authority_with(
        &self,
        ed25519_keys: Option<&str>,
        accept_hmac: Option<&str>,
    ) -> Result<Option<crate::identity_assertion::AssertionAuthority>, String> {
        use crate::identity_assertion::{AssertionAuthority, AssertionVerifyingKeys};
        let nonempty = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
        let (issuer, audience, hmac_key) = (
            nonempty(&self.assertion_issuer),
            nonempty(&self.assertion_audience),
            nonempty(&self.assertion_hmac_key),
        );
        if [
            &self.assertion_issuer,
            &self.assertion_audience,
            &self.assertion_hmac_key,
        ]
        .iter()
        .all(|value| value.is_none())
            && ed25519_keys.is_none()
            && accept_hmac.is_none()
        {
            return Ok(None);
        }
        let accept_hmac = match accept_hmac {
            None | Some("1") => true,
            Some("0") => false,
            Some(_) => return Err("SEKAI_ASSERTION_ACCEPT_HMAC must be 0 or 1".into()),
        };
        let ed25519_keys = ed25519_keys
            .map(AssertionVerifyingKeys::parse)
            .transpose()?;
        let authority = match (issuer, audience, hmac_key, ed25519_keys) {
            (Some(issuer), Some(audience), Some(key), keys) => {
                let authority = AssertionAuthority::new(issuer, audience, key.into_bytes());
                match keys {
                    Some(keys) => authority.with_ed25519_keys(keys),
                    None if !accept_hmac => {
                        return Err(
                            "SEKAI_ASSERTION_ACCEPT_HMAC=0 requires SEKAI_ASSERTION_ED25519_KEYS"
                                .into(),
                        );
                    }
                    None => authority,
                }
            }
            (Some(issuer), Some(audience), None, Some(keys)) => {
                AssertionAuthority::ed25519_only(issuer, audience, keys)
            }
            _ => {
                return Err(
                    "assertion authority requires SEKAI_ASSERTION_ISSUER, SEKAI_ASSERTION_AUDIENCE, and SEKAI_ASSERTION_HMAC_KEY or SEKAI_ASSERTION_ED25519_KEYS together"
                        .into(),
                );
            }
        };
        Ok(Some(if accept_hmac {
            authority
        } else {
            authority.without_hmac_assertions()
        }))
    }

    pub fn grpc_tcp_mode(&self, active_credentials: bool) -> GrpcTcpMode {
        let auth_configured = active_credentials;
        let token_auth_mode = auth_configured && !self.insecure;
        let inferred_bind_addr = if token_auth_mode {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let bind_addr = self
            .sekai_bind
            .clone()
            .unwrap_or_else(|| inferred_bind_addr.to_string());
        let bind_inferred_from_active_credentials =
            self.sekai_bind.is_none() && token_auth_mode && active_credentials;

        GrpcTcpMode {
            bind_addr,
            token_auth_mode,
            auth_configured,
            bind_inferred_from_active_credentials,
        }
    }
}

fn security_i64_env(name: &str, default: i64, invalid: i64) -> i64 {
    match std::env::var(name) {
        Ok(value) => match value.parse() {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    variable = name,
                    error = %error,
                    "invalid security-sensitive configuration; dependent issuance is disabled"
                );
                invalid
            }
        },
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => {
            warn!(
                variable = name,
                error = %error,
                "unreadable security-sensitive configuration; dependent issuance is disabled"
            );
            invalid
        }
    }
}

fn env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn optional_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Resolve and validate `SEKAI_SITE_ID` (non-empty, no wildcards).
fn site_id_env(key: &str, default: &str) -> String {
    let raw = env::var(key).unwrap_or_else(|_| default.to_string());
    match validate_site_id(&raw) {
        Ok(value) => value,
        Err(error) => {
            warn!(key, value = %raw, error = %error, "invalid site id; using default");
            default.to_string()
        }
    }
}

/// Validate a region/site pin used for lease and permit pinning.
pub fn validate_site_id(value: &str) -> Result<String, String> {
    sekai_core::sekai::lease::validate_site_id(value)
}

fn default_sekai_sqlite_path() -> String {
    match env::var("SEKAI_DB_PATH") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            let dir = match env::var("SEKAI_DATA_DIR") {
                Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
                _ => "./data".into(),
            };
            std::path::Path::new(&dir)
                .join("sekai.db")
                .to_string_lossy()
                .into_owned()
        }
    }
}

fn socket_path(key: &str, default: &str) -> Option<String> {
    match env::var(key) {
        Ok(value) if value.trim().is_empty() => None,
        Ok(value) => Some(value),
        Err(_) => Some(default.to_string()),
    }
}

fn optional_port(key: &str, default: &str) -> Option<u16> {
    match env::var(key) {
        Ok(value) if value.trim().is_empty() => None,
        Ok(value) => match value.trim().parse() {
            Ok(port) => Some(port),
            Err(err) => {
                warn!(
                    key,
                    value = %value,
                    default,
                    error = %err,
                    "invalid port environment value; using default"
                );
                default.parse().ok()
            }
        },
        Err(_) => default.parse().ok(),
    }
}

fn csv_env(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn identity_csv_env(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        let mut config = Config::from_env();
        config.sekai_bind = None;
        config.insecure = false;
        config.assertion_issuer = None;
        config.assertion_audience = None;
        config.assertion_hmac_key = None;
        config
    }

    #[test]
    fn grpc_tcp_mode_infers_public_bind_from_active_credentials() {
        let config = test_config();

        let mode = config.grpc_tcp_mode(true);

        assert_eq!(mode.bind_addr, "0.0.0.0");
        assert!(mode.token_auth_mode);
        assert!(mode.auth_configured);
        assert!(mode.bind_inferred_from_active_credentials);
    }

    #[test]
    fn grpc_tcp_mode_explicit_bind_wins_without_changing_auth_mode() {
        let mut config = test_config();
        config.sekai_bind = Some("127.0.0.1".to_string());

        let mode = config.grpc_tcp_mode(true);

        assert_eq!(mode.bind_addr, "127.0.0.1");
        assert!(mode.token_auth_mode);
        assert!(mode.auth_configured);
        assert!(!mode.bind_inferred_from_active_credentials);
    }

    #[test]
    fn grpc_tcp_mode_insecure_disables_token_auth_and_keeps_local_bind() {
        let mut config = test_config();
        config.insecure = true;

        let mode = config.grpc_tcp_mode(true);

        assert_eq!(mode.bind_addr, "127.0.0.1");
        assert!(!mode.token_auth_mode);
        assert!(mode.auth_configured);
        assert!(!mode.bind_inferred_from_active_credentials);
    }

    #[test]
    fn site_id_defaults_to_local_and_rejects_wildcards() {
        assert_eq!(validate_site_id("local").unwrap(), "local");
        assert_eq!(validate_site_id(" us-east-1 ").unwrap(), "us-east-1");
        assert!(validate_site_id("").is_err());
        assert!(validate_site_id("   ").is_err());
        assert!(validate_site_id("region*").is_err());
        assert!(validate_site_id("region?").is_err());
    }

    #[test]
    fn assertion_authority_requires_all_three_or_none() {
        let mut config = test_config();
        assert!(
            config
                .assertion_authority_with(None, None)
                .unwrap()
                .is_none()
        );
        config.assertion_issuer = Some("https://issuer.test".into());
        assert!(config.assertion_authority_with(None, None).is_err());
        config.assertion_audience = Some("https://sekai.test".into());
        assert!(config.assertion_authority_with(None, None).is_err());
        config.assertion_hmac_key = Some("test-hmac-key".into());
        let authority = config
            .assertion_authority_with(None, None)
            .unwrap()
            .expect("installed");
        assert_eq!(authority.issuer, "https://issuer.test");
        assert_eq!(authority.audience, "https://sekai.test");
    }

    #[test]
    fn assertion_authority_takes_ed25519_public_keys_and_an_hmac_switch() {
        use crate::identity_assertion::{AssertionReject, Ed25519AssertionSigner};
        let signer = Ed25519AssertionSigner::new("k1", &[1; 32]).unwrap();
        let keys = format!("k1={}", signer.public_key());
        let mut config = test_config();
        // The switch or keys alone are partial configuration.
        assert!(config.assertion_authority_with(None, Some("0")).is_err());
        assert!(config.assertion_authority_with(Some(&keys), None).is_err());
        config.assertion_issuer = Some("https://issuer.test".into());
        config.assertion_audience = Some("https://sekai.test".into());
        // Issuer and audience need a key.
        assert!(config.assertion_authority_with(None, None).is_err());
        let ed25519_only = config
            .assertion_authority_with(Some(&keys), None)
            .unwrap()
            .expect("installed");
        assert!(ed25519_only.seal("srt1.", b"{}").is_err());

        config.assertion_hmac_key = Some("test-hmac-key".into());
        assert!(config.assertion_authority_with(None, Some("0")).is_err());
        assert!(
            config
                .assertion_authority_with(Some(&keys), Some("off"))
                .is_err()
        );
        assert!(
            config
                .assertion_authority_with(Some("k1=bad"), None)
                .is_err()
        );
        let hmac_token = |authority: &crate::identity_assertion::AssertionAuthority| {
            authority
                .sign(&crate::identity_assertion::IdentityAssertion {
                    contract_version: crate::identity_assertion::IDENTITY_ASSERTION_VERSION.into(),
                    issuer: "https://issuer.test".into(),
                    audience: "https://sekai.test".into(),
                    subject: "subject-a".into(),
                    credential_id: "credential-a".into(),
                    credential_kind: "machine".into(),
                    tenant_id: None,
                    space: None,
                    space_role: None,
                    act: None,
                    scopes: vec!["sekai.read".into()],
                    expires_at: 100,
                    nonce: "n".into(),
                    device: None,
                })
                .unwrap()
        };
        for accept in [None, Some("1")] {
            let both = config
                .assertion_authority_with(Some(&keys), accept)
                .unwrap()
                .expect("installed");
            assert!(both.verify(&hmac_token(&both), 50, None).is_ok());
        }
        let ed25519_and_sealing = config
            .assertion_authority_with(Some(&keys), Some("0"))
            .unwrap()
            .expect("installed");
        assert_eq!(
            ed25519_and_sealing
                .verify(&hmac_token(&ed25519_and_sealing), 50, None)
                .unwrap_err(),
            AssertionReject::Signature
        );
        assert!(ed25519_and_sealing.seal("srt1.", b"{}").is_ok());
    }
}
