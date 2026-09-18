//! Authenticated hop from a Chisei process to a Sekai process.
//!
//! The hop carries a caller credential. Sekai rechecks current authorization
//! on the commit lookup; a Chisei decision is not a substitute.

use std::time::Duration;

use crate::chisei::cross_store_admission::{SekaiCommitLookup, SekaiCommitRef};
use crate::grpc::pb::sekai::GetActionInstanceRequest;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;

/// Live Sekai commit lookup over an authenticated gRPC hop.
pub struct RemoteSekaiCommitLookup {
    endpoint: String,
    credential: Option<String>,
}

impl RemoteSekaiCommitLookup {
    pub fn new(endpoint: String, credential: Option<String>) -> Self {
        Self {
            endpoint,
            credential: credential.filter(|value| !value.trim().is_empty()),
        }
    }

    pub fn from_env(endpoint: String) -> Self {
        Self::new(endpoint, std::env::var("SEKAI_CREDENTIAL").ok())
    }

    fn lookup_blocking(&self, operation_id: &str) -> Result<Option<SekaiCommitRef>, String> {
        let endpoint = self.endpoint.clone();
        let credential = self.credential.clone();
        let operation_id = operation_id.to_string();
        std::thread::Builder::new()
            .name("sekai-commit-hop".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| error.to_string())?;
                runtime.block_on(lookup_commit_async(
                    &endpoint,
                    credential.as_deref(),
                    &operation_id,
                ))
            })
            .map_err(|error| error.to_string())?
            .join()
            .map_err(|_| "sekai commit hop thread panicked".to_string())?
    }
}

impl SekaiCommitLookup for RemoteSekaiCommitLookup {
    fn lookup_commit(&self, operation_id: &str) -> Result<Option<SekaiCommitRef>, String> {
        self.lookup_blocking(operation_id)
    }
}

async fn lookup_commit_async(
    endpoint: &str,
    credential: Option<&str>,
    operation_id: &str,
) -> Result<Option<SekaiCommitRef>, String> {
    let channel = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .map_err(|error| format!("SEKAI_ENDPOINT: {error}"))?
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .map_err(|error| format!("sekai hop connect: {error}"))?;
    let mut client = SekaiServiceClient::new(channel);
    let mut request = tonic::Request::new(GetActionInstanceRequest {
        instance_id: String::new(),
        namespace: String::new(),
        idempotency_key: String::new(),
        operation_id: operation_id.to_string(),
    });
    if let Some(token) = credential {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {token}")
                .parse()
                .map_err(|error| format!("SEKAI_CREDENTIAL: {error}"))?,
        );
    }
    match client.get_action_instance(request).await {
        Ok(response) => Ok(response
            .into_inner()
            .instance
            .map(|instance| SekaiCommitRef {
                namespace: instance.namespace,
                instance_id: instance.instance_id,
                status: instance.status,
            })),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(format!("sekai hop lookup: {status}")),
    }
}
