use sekai_chisei::config::Config;
use sekai_chisei::db::sekai::SekaiDb;
use std::sync::Arc;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env();
    println!("sekai-chisei v0.1.0");
    if config.auth_token.is_some() || std::env::var("SEKAI_INSECURE").unwrap_or_default() == "1" {
        println!(
            "  grpc: {}:{}",
            if config.auth_token.is_some() {
                "0.0.0.0"
            } else {
                "127.0.0.1"
            },
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

    let db = Arc::new(SekaiDb::new(&config.db_path).expect("failed to open database"));
    db.migrate_datasets();
    db.migrate_functions();
    db.migrate_grants();
    db.migrate_audit();
    let _ = db.migrate_chisei();

    let server = sekai_chisei::grpc::run(config.grpc_port, db);
    let shutdown = async {
        signal::ctrl_c().await.ok();
        println!("\nshutting down...");
    };

    tokio::select! {
        result = server => { result?; }
        _ = shutdown => {}
    }
    Ok(())
}
