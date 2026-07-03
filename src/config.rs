use std::env;
use tracing::warn;

#[derive(Clone)]
pub struct Config {
    pub grpc_port: u16,
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
    pub leak_review_model: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub allow_plaintext: bool,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            grpc_port: env("GRPC_PORT", "50051").parse().unwrap_or(50051),
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
        }
    }
}

fn env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
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
