//! Authenticated hop from a Chisei process to a Sekai process.
//!
//! The hop carries a caller credential. Sekai rechecks current authorization
//! on the commit lookup; a Chisei decision is not a substitute.

use std::future::Future;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::runtime::{Handle, Runtime};
use tonic::transport::Channel;

use crate::chisei::cross_store_admission::{SekaiCommitLookup, SekaiCommitRef};
use crate::grpc::pb::sekai::GetActionInstanceRequest;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;

/// Live Sekai commit lookup over an authenticated gRPC hop.
pub struct RemoteSekaiCommitLookup {
    endpoint: String,
    credential: Option<String>,
    channel: OnceLock<Channel>,
    fallback_runtime: OnceLock<Runtime>,
}

impl RemoteSekaiCommitLookup {
    pub fn new(endpoint: String, credential: Option<String>) -> Self {
        Self {
            endpoint,
            credential: credential.filter(|value| !value.trim().is_empty()),
            channel: OnceLock::new(),
            fallback_runtime: OnceLock::new(),
        }
    }

    pub fn from_env(endpoint: String) -> Self {
        Self::new(endpoint, std::env::var("SEKAI_CREDENTIAL").ok())
    }

    fn run<T>(&self, future: impl Future<Output = Result<T, String>>) -> Result<T, String> {
        if let Ok(handle) = Handle::try_current() {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
        self.fallback_runtime()?.block_on(future)
    }

    fn fallback_runtime(&self) -> Result<&Runtime, String> {
        if let Some(runtime) = self.fallback_runtime.get() {
            return Ok(runtime);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        Ok(self.fallback_runtime.get_or_init(|| runtime))
    }

    fn channel(&self) -> Result<Channel, String> {
        if let Some(channel) = self.channel.get() {
            return Ok(channel.clone());
        }
        let channel = self.run(connect_channel(&self.endpoint))?;
        Ok(self.channel.get_or_init(|| channel.clone()).clone())
    }
}

impl SekaiCommitLookup for RemoteSekaiCommitLookup {
    fn lookup_commit(&self, operation_id: &str) -> Result<Option<SekaiCommitRef>, String> {
        let channel = self.channel()?;
        let credential = self.credential.clone();
        let operation_id = operation_id.to_string();
        self.run(lookup_on_channel(channel, credential, operation_id))
    }
}

async fn connect_channel(endpoint: &str) -> Result<Channel, String> {
    tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .map_err(|error| format!("SEKAI_ENDPOINT: {error}"))?
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .map_err(|error| format!("sekai hop connect: {error}"))
}

async fn lookup_on_channel(
    channel: Channel,
    credential: Option<String>,
    operation_id: String,
) -> Result<Option<SekaiCommitRef>, String> {
    let mut client = SekaiServiceClient::new(channel);
    let mut request = tonic::Request::new(GetActionInstanceRequest {
        instance_id: String::new(),
        namespace: String::new(),
        idempotency_key: String::new(),
        operation_id,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_outside_runtime_reports_connect_error() {
        let hop = RemoteSekaiCommitLookup::new("http://127.0.0.1:1".into(), None);
        let error = hop.lookup_commit("op-1").unwrap_err();
        assert!(error.contains("sekai hop connect"), "{error}");
        let again = hop.lookup_commit("op-2").unwrap_err();
        assert!(again.contains("sekai hop connect"), "{again}");
        assert!(hop.channel.get().is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lookup_inside_runtime_does_not_need_a_nested_runtime() {
        let hop = RemoteSekaiCommitLookup::new("http://127.0.0.1:1".into(), None);
        let error = hop.lookup_commit("op-1").unwrap_err();
        assert!(error.contains("sekai hop connect"), "{error}");
        assert!(hop.fallback_runtime.get().is_none());
    }
}
