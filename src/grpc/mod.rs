pub mod chisei_service;
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
use std::sync::Arc;
use subtle::ConstantTimeEq;
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
    if config.auth_token.is_none() && !insecure {
        return Err("SEKAI_AUTH_TOKEN must be set, or set SEKAI_INSECURE=1 for local dev".into());
    }
    let bind_addr = if config.auth_token.is_some() {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let addr = format!("{}:{}", bind_addr, port).parse()?;
    let interceptor = AuthInterceptor::new(config.auth_token.clone());
    let budget = Arc::new(BudgetTracker::new());

    let sekai_svc = sekai_service::SekaiServiceImpl::new(db.clone());
    let chisei_svc =
        chisei_service::ChiseiServiceImpl::with_budget(db, config.clone(), budget.clone());
    if config.scoring_enabled {
        println!(
            "scoring job enabled (model={}, interval={}s, batch={})",
            config.scoring_model, config.scoring_interval_secs, config.scoring_batch_size
        );
        tokio::spawn(chisei_svc.scoring_job().run_loop());
    }
    println!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(InterceptedService::new(
            pb::sekai::sekai_service_server::SekaiServiceServer::new(sekai_svc),
            interceptor.clone(),
        ))
        .add_service(InterceptedService::new(
            pb::chisei::chisei_service_server::ChiseiServiceServer::new(chisei_svc),
            interceptor.clone(),
        ))
        .serve(addr)
        .await?;

    Ok(())
}
