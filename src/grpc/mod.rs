pub mod chisei_service;
pub mod client;
mod llm_service;
pub mod sekai_service;

pub mod pb {
    pub mod sekai {
        tonic::include_proto!("sekai");
    }
    pub mod chisei {
        tonic::include_proto!("chisei");
    }
    pub(super) mod llm {
        tonic::include_proto!("llm");
    }
}

use crate::chisei::budget::BudgetTracker;
use crate::config::Config;
use crate::db::sekai::SekaiDb;
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Server;
use tonic::{Request, Status};

#[derive(Clone)]
pub struct AuthInterceptor {
    token: Option<String>,
}

impl AuthInterceptor {
    pub fn new(token: Option<String>) -> Self {
        Self { token }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        let Some(expected) = &self.token else {
            return Ok(req);
        };
        match req.metadata().get("authorization") {
            Some(val) => {
                let val = val
                    .to_str()
                    .map_err(|_| Status::unauthenticated("invalid auth header"))?;
                let token = val.strip_prefix("Bearer ").unwrap_or(val);
                if token.as_bytes().ct_eq(expected.as_bytes()).into() {
                    Ok(req)
                } else {
                    Err(Status::unauthenticated("invalid token"))
                }
            }
            None => Err(Status::unauthenticated("missing authorization")),
        }
    }
}

pub async fn run(port: u16, db: Arc<SekaiDb>) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env();
    let insecure = std::env::var("SEKAI_INSECURE").unwrap_or_default() == "1";
    let serve_tcp = config.auth_token.is_some() || insecure;
    let Some(socket_path) = config.sekai_socket.clone() else {
        if config.auth_token.is_none() && !insecure {
            return Err(
                "SEKAI_AUTH_TOKEN must be set, or set SEKAI_INSECURE=1 for local dev".into(),
            );
        }
        return run_tcp(port, db, config).await;
    };

    if !serve_tcp {
        println!("gRPC TCP listener disabled; serving local UDS only");
    }

    let interceptor = AuthInterceptor::new(config.auth_token.clone());
    let budget = Arc::new(BudgetTracker::new());
    let sekai_svc = Arc::new(sekai_service::SekaiServiceImpl::new(db.clone()));
    let chisei_svc = Arc::new(chisei_service::ChiseiServiceImpl::with_budget(
        db,
        config.clone(),
        budget,
    ));
    if config.scoring_enabled {
        println!(
            "scoring job enabled (model={}, interval={}s, batch={})",
            config.scoring_model, config.scoring_interval_secs, config.scoring_batch_size
        );
        tokio::spawn(chisei_svc.scoring_job().run_loop());
    }

    let uds_server = serve_uds(
        socket_path,
        sekai_svc.clone(),
        chisei_svc.clone(),
        interceptor.clone(),
    );
    if serve_tcp {
        let tcp_server = serve_tcp_listener(port, config, sekai_svc, chisei_svc, interceptor);
        tokio::select! {
            result = tcp_server => result,
            result = uds_server => result,
        }
    } else {
        uds_server.await
    }
}

async fn run_tcp(
    port: u16,
    db: Arc<SekaiDb>,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let insecure = std::env::var("SEKAI_INSECURE").unwrap_or_default() == "1";
    if config.auth_token.is_none() && !insecure {
        return Err("SEKAI_AUTH_TOKEN must be set, or set SEKAI_INSECURE=1 for local dev".into());
    }
    let interceptor = AuthInterceptor::new(config.auth_token.clone());
    let budget = Arc::new(BudgetTracker::new());
    let sekai_svc = Arc::new(sekai_service::SekaiServiceImpl::new(db.clone()));
    let chisei_svc = Arc::new(chisei_service::ChiseiServiceImpl::with_budget(
        db,
        config.clone(),
        budget,
    ));
    if config.scoring_enabled {
        println!(
            "scoring job enabled (model={}, interval={}s, batch={})",
            config.scoring_model, config.scoring_interval_secs, config.scoring_batch_size
        );
        tokio::spawn(chisei_svc.scoring_job().run_loop());
    }
    serve_tcp_listener(port, config, sekai_svc, chisei_svc, interceptor).await
}

async fn serve_tcp_listener(
    port: u16,
    config: Config,
    sekai_svc: Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: Arc<chisei_service::ChiseiServiceImpl>,
    interceptor: AuthInterceptor,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = if config.auth_token.is_some() {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let addr = format!("{}:{}", bind_addr, port).parse()?;
    println!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(InterceptedService::new(
            pb::sekai::sekai_service_server::SekaiServiceServer::from_arc(sekai_svc),
            interceptor.clone(),
        ))
        .add_service(InterceptedService::new(
            pb::chisei::chisei_service_server::ChiseiServiceServer::from_arc(chisei_svc),
            interceptor.clone(),
        ))
        .serve(addr)
        .await?;

    Ok(())
}

async fn serve_uds(
    socket_path: String,
    sekai_svc: Arc<sekai_service::SekaiServiceImpl>,
    chisei_svc: Arc<chisei_service::ChiseiServiceImpl>,
    interceptor: AuthInterceptor,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(&socket_path);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("gRPC server listening on unix://{}", socket_path);

    Server::builder()
        .add_service(InterceptedService::new(
            pb::sekai::sekai_service_server::SekaiServiceServer::from_arc(sekai_svc),
            interceptor.clone(),
        ))
        .add_service(InterceptedService::new(
            pb::chisei::chisei_service_server::ChiseiServiceServer::from_arc(chisei_svc),
            interceptor.clone(),
        ))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?;

    Ok(())
}
