//! Blocking `SourceSyncTransport` over the Sekai gRPC API. `https://`
//! targets use TLS with the platform's root certificates; plaintext targets
//! carry a credential only on loopback.

use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{self as pb, ApplySourceBatchRequest, GetSourceSyncStateRequest};
use sekai_source_sdk::{
    ApplySourceBatchReply, GetSourceSyncStateInput, SourceBatch, SourceSyncStateView,
    SourceSyncTransport, TransportFailure,
};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

pub struct GrpcTransport {
    runtime: tokio::runtime::Runtime,
    client: SekaiServiceClient<Channel>,
    credential: Option<String>,
}

impl GrpcTransport {
    pub fn connect(target: &str, credential: Option<String>) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("cannot start runtime: {error}"))?;
        let mut endpoint = Endpoint::from_shared(target.to_string())
            .map_err(|_| "control plane target is not a URI".to_string())?;
        let loopback = matches!(
            endpoint.uri().host(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        );
        if credential.is_some() && !target.starts_with("https://") && !loopback {
            return Err("a credential is only sent over https or to a loopback target".into());
        }
        if target.starts_with("https://") {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .map_err(|_| "control plane TLS is unavailable".to_string())?;
        }
        let channel = runtime
            .block_on(endpoint.connect())
            .map_err(|_| "control plane is unreachable".to_string())?;
        let client = SekaiServiceClient::new(channel);
        Ok(Self {
            runtime,
            client,
            credential,
        })
    }

    fn state_response(
        &mut self,
        message: GetSourceSyncStateRequest,
    ) -> Result<pb::GetSourceSyncStateResponse, TransportFailure> {
        let request = self.request(message)?;
        self.runtime
            .block_on(self.client.get_source_sync_state(request))
            .map(tonic::Response::into_inner)
            .map_err(|status| failure(&status))
    }

    /// The plane's sync state for `batch`'s binding, if it has one.
    fn raw_state(
        &mut self,
        batch: &SourceBatch,
    ) -> Result<Option<pb::SourceSyncState>, TransportFailure> {
        let response = self.state_response(GetSourceSyncStateRequest {
            namespace: batch.namespace.clone(),
            source_instance: batch.source_instance.clone(),
            type_digest: batch.type_digest.clone(),
        })?;
        Ok(response.state.filter(|_| response.found))
    }

    fn request<T>(&self, message: T) -> Result<tonic::Request<T>, TransportFailure> {
        let mut request = tonic::Request::new(message);
        if let Some(credential) = &self.credential {
            let value = MetadataValue::try_from(format!("Bearer {credential}"))
                .map_err(|_| TransportFailure::Unavailable)?;
            request.metadata_mut().insert("authorization", value);
        }
        Ok(request)
    }
}

/// Whether the plane recorded this exact batch as aborted.
fn aborted(state: &pb::SourceSyncState, batch: &SourceBatch) -> bool {
    [
        state.latest_transaction.as_ref(),
        state
            .last_result
            .as_ref()
            .and_then(|result| result.transaction.as_ref()),
    ]
    .into_iter()
    .flatten()
    .any(|transaction| {
        transaction.status == "ABORTED"
            && transaction.idempotency_key == batch.idempotency_key
            && transaction.batch_digest == batch.batch_digest
    })
}

fn failure(status: &tonic::Status) -> TransportFailure {
    match status.code() {
        tonic::Code::Unavailable => TransportFailure::Unavailable,
        _ => TransportFailure::Ambiguous,
    }
}

/// Permanent refusals of the batch itself: an invalid batch, a producer the
/// namespace does not admit, an unsupported contract, or an unknown or retired
/// descriptor. State conflicts and objects changed since authorization are
/// also `FailedPrecondition` but may succeed on retry, so they stay pending.
fn denial(status: &tonic::Status) -> Option<ApplySourceBatchReply> {
    let reason_code = match (status.code(), status.message()) {
        (tonic::Code::InvalidArgument, _) => "invalid_argument",
        (tonic::Code::PermissionDenied, _) => "permission_denied",
        (tonic::Code::FailedPrecondition, "source sync contract version is unsupported") => {
            "unsupported_contract"
        }
        (tonic::Code::FailedPrecondition, "source type revision is not bound") => {
            "unbound_type_revision"
        }
        _ => return None,
    };
    Some(ApplySourceBatchReply::Rejected {
        reason_code: reason_code.into(),
    })
}

impl SourceSyncTransport for GrpcTransport {
    fn apply_source_batch(
        &mut self,
        batch: &SourceBatch,
    ) -> Result<ApplySourceBatchReply, TransportFailure> {
        let request = self.request(ApplySourceBatchRequest {
            batch: Some(to_proto(batch)),
        })?;
        let response = match self
            .runtime
            .block_on(self.client.apply_source_batch(request))
        {
            Ok(response) => response,
            Err(status) if status.message() == "source sync state conflict" => {
                // A replay of a durably aborted batch lands here too; only the
                // plane's transaction record tells it apart from a live conflict.
                return match self.raw_state(batch)? {
                    Some(state) if aborted(&state, batch) => Ok(ApplySourceBatchReply::Rejected {
                        reason_code: "batch_aborted".into(),
                    }),
                    _ => Err(TransportFailure::Ambiguous),
                };
            }
            Err(status) => return denial(&status).ok_or_else(|| failure(&status)),
        };
        let result = response
            .into_inner()
            .result
            .and_then(|result| result.transaction)
            .ok_or(TransportFailure::Ambiguous)?;
        match result.status.as_str() {
            "COMMITTED" => Ok(ApplySourceBatchReply::Committed {
                idempotency_key: result.idempotency_key,
                batch_digest: result.batch_digest,
                committed_cursor: result.proposed_next_cursor,
            }),
            "ABORTED" | "QUARANTINED" => Ok(ApplySourceBatchReply::Rejected {
                reason_code: result.outcome,
            }),
            _ => Err(TransportFailure::Ambiguous),
        }
    }

    fn get_source_sync_state(
        &mut self,
        input: &GetSourceSyncStateInput,
    ) -> Result<SourceSyncStateView, TransportFailure> {
        let response = self.state_response(GetSourceSyncStateRequest {
            namespace: input.namespace.clone(),
            source_instance: input.source_instance.clone(),
            type_digest: input.type_digest.clone(),
        })?;
        let state = response.state.unwrap_or_default();
        let checkpoint = state
            .checkpoint
            .filter(|checkpoint| !checkpoint.cursor.is_empty());
        Ok(SourceSyncStateView {
            found: response.found,
            current_cursor: checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.cursor.clone()),
            open_transaction: state.open_transaction.is_some(),
            last_committed_batch_digest: checkpoint
                .map(|checkpoint| checkpoint.committed_batch_digest),
            ..SourceSyncStateView::default()
        })
    }
}

fn to_proto(batch: &SourceBatch) -> pb::SourceBatch {
    pb::SourceBatch {
        contract_version: batch.contract_version.clone(),
        namespace: batch.namespace.clone(),
        producer_identity: batch.producer_identity.clone(),
        source: batch.source.clone(),
        source_instance: batch.source_instance.clone(),
        family: batch.family.clone(),
        adapter_id: batch.adapter_id.clone(),
        adapter_version: batch.adapter_version.clone(),
        type_digest: batch.type_digest.clone(),
        current_cursor: batch.current_cursor.clone(),
        proposed_next_cursor: batch.proposed_next_cursor.clone(),
        idempotency_key: batch.idempotency_key.clone(),
        batch_digest: batch.batch_digest.clone(),
        collected_at_ms: batch.collected_at_ms,
        records: batch
            .records
            .iter()
            .map(|record| pb::SourceRecord {
                source: record.source.clone(),
                source_instance: record.source_instance.clone(),
                external_id: record.external_id.clone(),
                source_version: record.source_version.clone(),
                type_name: record.type_name.clone(),
                display_name: record.display_name.clone(),
                payload_digest: record.payload_digest.clone(),
                properties: record.properties.clone().into_iter().collect(),
                deleted: record.deleted,
                observed_at_ms: record.observed_at_ms,
                source_sequence: record.source_sequence,
            })
            .collect(),
        delivery: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_source_sdk::SourceBatch;

    fn batch() -> SourceBatch {
        serde_json::from_value(serde_json::json!({
            "contract_version": "sekai.source-batch/v1",
            "namespace": "ns",
            "producer_identity": "p",
            "source": "s",
            "source_instance": "i",
            "family": "source_control.object_sync",
            "adapter_id": "a",
            "adapter_version": "1",
            "type_digest": "t",
            "current_cursor": "",
            "proposed_next_cursor": "c",
            "idempotency_key": "key",
            "batch_digest": "digest",
            "collected_at_ms": 1,
            "records": [],
        }))
        .unwrap()
    }

    fn transaction(status: &str, key: &str) -> pb::SourceBatchTransaction {
        pb::SourceBatchTransaction {
            status: status.into(),
            idempotency_key: key.into(),
            batch_digest: "digest".into(),
            ..Default::default()
        }
    }

    #[test]
    fn only_this_batch_recorded_as_aborted_counts() {
        let batch = batch();
        let state = |latest| pb::SourceSyncState {
            latest_transaction: Some(latest),
            ..Default::default()
        };
        assert!(aborted(&state(transaction("ABORTED", "key")), &batch));
        assert!(!aborted(&state(transaction("ABORTED", "other")), &batch));
        assert!(!aborted(&state(transaction("OPEN", "key")), &batch));
        assert!(!aborted(&pb::SourceSyncState::default(), &batch));
    }
}
