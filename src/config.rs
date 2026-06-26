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
        }
    }
}

fn env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}
