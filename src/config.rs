use std::env;

#[derive(Clone)]
pub struct Config {
    pub grpc_port: u16,
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
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            grpc_port: env("GRPC_PORT", "50051").parse().unwrap_or(50051),
            db_path: env("DB_PATH", "./data/sekai.db"),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok(),
            openai_api_key: env::var("OPENAI_API_KEY").ok(),
            ollama_url: env("OLLAMA_URL", "http://localhost:11434"),
            native_llm_url: env::var("NATIVE_LLM_URL").ok(),
            auth_token: env::var("SEKAI_AUTH_TOKEN").ok(),
            sample_rate: env("SAMPLE_RATE", "0.05").parse().unwrap_or(0.05),
            sample_risk_threshold: env("SAMPLE_RISK_THRESHOLD", "0.7").parse().unwrap_or(0.7),
            scoring_enabled: env("SCORING_ENABLED", "false").parse().unwrap_or(false),
            scoring_interval_secs: env("SCORING_INTERVAL_SECS", "60").parse().unwrap_or(60),
            scoring_model: env("SCORING_MODEL", "claude-opus-4-8"),
            scoring_batch_size: env("SCORING_BATCH_SIZE", "16").parse().unwrap_or(16),
        }
    }
}

fn env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}
