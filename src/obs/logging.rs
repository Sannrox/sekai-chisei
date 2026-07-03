use tracing_subscriber::EnvFilter;

pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let result = if std::env::var("LOG_FORMAT")
        .map(|value| value.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
    {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .try_init()
    };

    let _ = result;
}
