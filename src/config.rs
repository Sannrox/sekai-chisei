use std::env;
use tracing::warn;

#[derive(Clone)]
pub struct Config {
    pub grpc_port: u16,
    pub sekai_bind: Option<String>,
    pub ops_port: Option<u16>,
    pub ops_bind: String,
    pub sekai_socket: Option<String>,
    pub db_path: String,
    pub anthropic_api_key: Option<String>,
    pub openai_api_key: Option<String>,
    pub ollama_url: String,
    pub native_llm_url: Option<String>,
    pub auth_token: Option<String>,
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
    /// Authenticated service principals allowed to persist gateway operation receipts.
    pub gateway_receipt_principals: Vec<String>,
    pub leak_review_model: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub allow_plaintext: bool,
    pub insecure: bool,
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
            sekai_socket: socket_path("SEKAI_SOCKET", "./data/sekai.sock"),
            db_path: env("DB_PATH", "./data/sekai.db"),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok(),
            openai_api_key: env::var("OPENAI_API_KEY").ok(),
            ollama_url: env("OLLAMA_URL", "http://localhost:11434"),
            native_llm_url: env::var("NATIVE_LLM_URL").ok(),
            auth_token: env::var("SEKAI_AUTH_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            sample_rate: env("SAMPLE_RATE", "0.05").parse().unwrap_or(0.05),
            sample_risk_threshold: env("SAMPLE_RISK_THRESHOLD", "0.7").parse().unwrap_or(0.7),
            scoring_enabled: env("SCORING_ENABLED", "false").parse().unwrap_or(false),
            scoring_interval_secs: env("SCORING_INTERVAL_SECS", "60").parse().unwrap_or(60),
            scoring_model: env("SCORING_MODEL", "claude-opus-4-8"),
            scoring_batch_size: env("SCORING_BATCH_SIZE", "16").parse().unwrap_or(16),
            default_data_class: env("CHISEI_DEFAULT_DATA_CLASS", "unclassified"),
            safe_egress_providers: csv_env("CHISEI_SAFE_EGRESS_PROVIDERS"),
            gateway_provided_providers: csv_env("CHISEI_GATEWAY_PROVIDED_PROVIDERS"),
            gateway_receipt_principals: csv_env("CHISEI_GATEWAY_RECEIPT_PRINCIPALS"),
            leak_review_model: env::var("LEAK_REVIEW_MODEL")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            tls_cert: env::var("SEKAI_TLS_CERT")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            tls_key: env::var("SEKAI_TLS_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            allow_plaintext: env::var("SEKAI_ALLOW_PLAINTEXT").unwrap_or_default() == "1",
            insecure: env::var("SEKAI_INSECURE").unwrap_or_default() == "1",
        }
    }

    pub fn grpc_tcp_mode(&self, active_credentials: bool) -> GrpcTcpMode {
        let auth_configured = self.auth_token.is_some() || active_credentials;
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

fn env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn optional_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        let mut config = Config::from_env();
        config.sekai_bind = None;
        config.auth_token = None;
        config.insecure = false;
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
        config.auth_token = Some("legacy-token".to_string());
        config.insecure = true;

        let mode = config.grpc_tcp_mode(true);

        assert_eq!(mode.bind_addr, "127.0.0.1");
        assert!(!mode.token_auth_mode);
        assert!(mode.auth_configured);
        assert!(!mode.bind_inferred_from_active_credentials);
    }
}
