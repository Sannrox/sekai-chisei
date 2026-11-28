use ezu_adapter::host::{Settings, run};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt().with_ansi(false).init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {}
        [help] if help == "--help" || help == "-h" => {
            println!("{USAGE}");
            return Ok(());
        }
        [version] if version == "--version" || version == "-V" => {
            println!("ezu-adapter {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {
            eprintln!("ezu-adapter: unexpected arguments {args:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
    let settings = Settings::from_env().map_err(std::io::Error::other)?;
    run(settings).await.map_err(std::io::Error::other)?;
    Ok(())
}

const USAGE: &str = "ezu-adapter — geo feeds and fence Actions for an Ezu engine\n\n\
Environment:\n\
  TENKAI_DEPENDENCIES_FILE  dependency document (default /etc/tenkai/dependencies.json)\n\
  SEKAI_ENDPOINT            plane URI (default https://sekai-chisei:50051)\n\
  SEKAI_CREDENTIAL          adapter service-principal bearer\n\
  SEKAI_TLS_CA              PEM file when the plane uses TLS\n\
  EZU_URL, EZU_TOKEN        Ezu base URL and bearer (sealed secret)\n\
  EZU_ADAPTER_CONFIG_FILE   JSON feeds and bindings\n\
  OPS_BIND, OPS_PORT        /healthz and /readyz (default 127.0.0.1:9464)\n\
  EZU_ADAPTER_OWNER         lease owner (default HOSTNAME)\n\n\
Without ezu.query and ezu.events in the dependency document the process\n\
idles and /readyz is idle. URL and bearer never come from a ConfigMap.";
