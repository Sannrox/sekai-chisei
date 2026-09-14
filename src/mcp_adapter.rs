//! Bounded MCP stdio adapter over native object, Action, and receipt RPCs.
//!
//! The process is a projection host. Discovery annotations never grant
//! authority. Every tool call is rebound to an allowlisted native RPC with
//! session identity; the adapter does not copy proto definitions or host a
//! policy engine.

mod framing;
mod in_process;
mod protocol;
mod surface;

pub use framing::{MAX_FRAME_BYTES, read_frame, write_frame};
pub use in_process::{InProcessSurface, SyntheticHostReport, run_synthetic_host};
pub use protocol::{PROTOCOL_VERSION, handle_message, well_known_tools};
pub use surface::{
    AdapterError, CatalogSnapshot, FixtureObject, FixtureSurface, NativeRpc, NativeSurface,
    SdkSurface, dispatch_native, status_error,
};

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, BufReader, stdin, stdout};

/// Host configuration for `sekai-mcp`. Credentials stay in the process
/// environment and are never projected into tool schemas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterConfig {
    pub target: String,
    pub principal: String,
    pub namespace: String,
    pub credential: Option<String>,
    pub timeout: Duration,
}

impl AdapterConfig {
    pub fn from_env() -> Result<Self, String> {
        let principal = required_env("SEKAI_MCP_PRINCIPAL")?;
        let namespace = required_env("SEKAI_MCP_NAMESPACE")?;
        let target = std::env::var("SEKAI_MCP_TARGET")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                std::env::var("SEKAI_SOCKET")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            })
            .unwrap_or_else(|| "http://127.0.0.1:50051".into());
        let credential = std::env::var("SEKAI_CREDENTIAL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Ok(Self {
            target,
            principal,
            namespace,
            credential,
            timeout: Duration::from_secs(30),
        })
    }
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

/// Serve MCP on process stdio until EOF.
pub async fn run_stdio(config: AdapterConfig) -> Result<(), String> {
    let surface = SdkSurface::connect(config)
        .await
        .map_err(|error| error.to_string())?;
    serve_io(Arc::new(surface), BufReader::new(stdin()), stdout()).await
}

pub async fn serve_io<S, R, W>(
    surface: Arc<S>,
    mut reader: BufReader<R>,
    mut writer: W,
) -> Result<(), String>
where
    S: NativeSurface + 'static,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let message = match read_frame(&mut reader).await {
            Ok(message) => message,
            Err(error) if error == "eof" => break,
            Err(error) => return Err(error),
        };
        if let Some(response) = handle_message(surface.as_ref(), message).await {
            write_frame(&mut writer, &response).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_env_rejects_blank_values() {
        unsafe {
            std::env::remove_var("SEKAI_MCP_PRINCIPAL_TEST");
            std::env::set_var("SEKAI_MCP_PRINCIPAL_TEST", "   ");
        }
        assert!(required_env("SEKAI_MCP_PRINCIPAL_TEST").is_err());
        unsafe {
            std::env::remove_var("SEKAI_MCP_PRINCIPAL_TEST");
        }
    }
}
