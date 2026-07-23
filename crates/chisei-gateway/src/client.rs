use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::Status;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Uri};
use tower::service_fn;

#[derive(Clone)]
pub struct GatewayAuthInterceptor {
    auth_token: Option<String>,
}

pub type GatewayClient = InterceptedService<Channel, GatewayAuthInterceptor>;

impl tonic::service::Interceptor for GatewayAuthInterceptor {
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        let Some(token) = self.auth_token.as_ref() else {
            return Ok(request);
        };
        let header = format!("Bearer {token}");
        let header = tonic::metadata::MetadataValue::from_str(&header)
            .map_err(|_| Status::internal("invalid SEKAI_AUTH_TOKEN metadata"))?;
        request.metadata_mut().insert("authorization", header);
        Ok(request)
    }
}

pub async fn connect_sekai(
    target: &str,
) -> Result<GatewayClient, Box<dyn std::error::Error + Send + Sync>> {
    connect_sekai_with_timeout(target, None).await
}

pub async fn connect_sekai_with_timeout(
    target: &str,
    timeout: Option<Duration>,
) -> Result<GatewayClient, Box<dyn std::error::Error + Send + Sync>> {
    let auth_token = if target.starts_with("http://") || target.starts_with("https://") {
        std::env::var("SEKAI_AUTH_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty())
    } else {
        None
    };
    connect_sekai_with_token(target, auth_token, timeout).await
}

pub async fn connect_sekai_as_gateway(
    target: &str,
) -> Result<GatewayClient, Box<dyn std::error::Error + Send + Sync>> {
    connect_sekai_as_gateway_with_timeout(target, None).await
}

pub async fn connect_sekai_as_gateway_with_timeout(
    target: &str,
    timeout: Option<Duration>,
) -> Result<GatewayClient, Box<dyn std::error::Error + Send + Sync>> {
    let environment_token = || {
        std::env::var("SEKAI_AUTH_TOKEN")
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
    };
    let auth_token = if target.starts_with("http://") || target.starts_with("https://") {
        environment_token()
    } else {
        let socket_target = target.strip_prefix("unix://").unwrap_or(target);
        std::fs::read_to_string(format!("{socket_target}.gateway-token"))
            .ok()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
            .or_else(environment_token)
    };
    connect_sekai_with_token(target, auth_token, timeout).await
}

async fn connect_sekai_with_token(
    target: &str,
    auth_token: Option<String>,
    timeout: Option<Duration>,
) -> Result<GatewayClient, Box<dyn std::error::Error + Send + Sync>> {
    let interceptor = GatewayAuthInterceptor { auth_token };

    if target.starts_with("http://") || target.starts_with("https://") {
        let tls_ca = std::env::var("SEKAI_TLS_CA").ok();
        let tls = if target.starts_with("https://") {
            let mut cfg = ClientTlsConfig::new().with_native_roots();
            if let Some(path) = tls_ca.filter(|value| !value.trim().is_empty()) {
                let cert = std::fs::read(path)?;
                cfg = cfg.ca_certificate(Certificate::from_pem(cert));
            }
            Some(cfg)
        } else {
            None
        };
        let mut channel = Channel::from_shared(target.to_string())?;
        if let Some(timeout) = timeout {
            channel = channel.connect_timeout(timeout).timeout(timeout);
        }
        if let Some(tls) = tls {
            channel = channel.tls_config(tls)?;
        }
        let channel = channel.connect().await?;
        return Ok(InterceptedService::new(channel, interceptor));
    }

    let socket_target = target.strip_prefix("unix://").unwrap_or(target);
    let socket_path = PathBuf::from(socket_target);
    let mut endpoint = Endpoint::try_from("http://[::]:50051")?;
    if let Some(timeout) = timeout {
        endpoint = endpoint.connect_timeout(timeout).timeout(timeout);
    }
    let channel =
        endpoint
            .connect_with_connector(service_fn(move |_: Uri| {
                let socket_path = socket_path.clone();
                async move {
                    Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(socket_path).await?))
                }
            }))
            .await?;

    Ok(InterceptedService::new(channel, interceptor))
}
