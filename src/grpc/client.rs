use std::path::PathBuf;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub async fn connect_sekai(
    target: &str,
) -> Result<Channel, Box<dyn std::error::Error + Send + Sync>> {
    if target.starts_with("http://") || target.starts_with("https://") {
        return Ok(Channel::from_shared(target.to_string())?.connect().await?);
    }

    let socket_target = target.strip_prefix("unix://").unwrap_or(target);
    let socket_path = PathBuf::from(socket_target);
    let channel =
        Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(service_fn(move |_: Uri| {
                let socket_path = socket_path.clone();
                async move {
                    Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(socket_path).await?))
                }
            }))
            .await?;

    Ok(channel)
}
