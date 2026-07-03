use sekai_chisei::config::Config;
use sekai_chisei::db::sekai::SekaiDb;
use std::sync::Arc;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env();
    println!("sekai-chisei v0.1.0");

    let insecure =
        config.allow_plaintext || std::env::var("SEKAI_INSECURE").unwrap_or_default() == "1";
    if config.auth_token.is_some() {
        eprintln!(
            "warning: SEKAI_AUTH_TOKEN is deprecated and maps to fixed principal `root`; use sekaictl credential create instead"
        );
    }

    let db = Arc::new(SekaiDb::new(&config.db_path).expect("failed to open database"));
    db.migrate_datasets();
    db.migrate_functions();
    db.migrate_grants();
    db.migrate_audit();
    let _ = db.migrate_chisei();
    db.migrate_principal_credentials().map_err(std::io::Error::other)?;
    let token_auth_mode = config.auth_token.is_some() || !db.list_active_credentials()?.is_empty();

    if token_auth_mode {
        println!(
            "  grpc: {}:{}",
            "0.0.0.0",
            config.grpc_port
        );
    } else if insecure {
        println!(
            "  grpc: {}:{}",
            "127.0.0.1",
            config.grpc_port
        );
    } else {
        println!("  grpc: tcp disabled");
    }

    if let Some(socket_path) = &config.sekai_socket {
        println!("  uds:  {}", socket_path);
    }
    println!("  db:   {}", config.db_path);
    println!(
        "  llm:  anthropic={} openai={} ollama={}",
        if config.anthropic_api_key.is_some() {
            "yes"
        } else {
            "no"
        },
        if config.openai_api_key.is_some() {
            "yes"
        } else {
            "no"
        },
        config.ollama_url
    );

    let server = sekai_chisei::grpc::run(config.grpc_port, db);
    let shutdown = async {
        signal::ctrl_c().await.ok();
        println!("\nshutting down...");
    };

    tokio::select! {
        result = server => {
            result?;
        }
        _ = shutdown => {}
    }
    Ok(())
}
