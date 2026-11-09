//! Saved-export delivery through a Source (ADR 0148): the plane hands an
//! artifact whose definition names a delivery Source only to a runtime
//! that Source's placement admits. The runtime claims it, fetches the bytes
//! under the claim's fence, checks the digest, delivers through the
//! Source's connector under a heartbeated lease, and acknowledges.
//!
//! A failed delivery is acknowledged as failed, which records the Source's
//! delivery health; the plane keeps the claim until it lapses, so the
//! artifact is tried again a lease later until it expires. A fetch that
//! fails leaves the claim to lapse the same way.

use futures_util::StreamExt;
use sekai_client::CallOptions;
use sekai_client::claim::{ClaimAttempt, RuntimeClaimError, WorkFence, WorkKind};
use sekai_client::protocol::sekai::{
    ConnectorSource, ExportDeliveryAckOptions, ExportDeliveryFence, ExportDeliveryWork,
    ExportObjectSetChunk, FetchExportArtifactRequest, GetSourceRequest, GetSourceResponse,
    ack_work_request, claim_work_response,
};
use sekai_source_sdk::ExportArtifact;
use sha2::{Digest, Sha256};

use crate::runtime::{LIST_LIMIT, Ran, Runtime};
use crate::sync::{SyncFailure, blocking, prepare};

impl Runtime {
    /// The Source `source_id` in the namespace at `index`, when this
    /// runtime delivers through its type.
    async fn delivery_source(
        &self,
        index: usize,
        namespace: &str,
        source_id: &str,
    ) -> Option<ConnectorSource> {
        let response: GetSourceResponse = self.clients[index]
            .raw()
            .unary(
                "/sekai.SekaiService/GetSource",
                GetSourceRequest {
                    namespace: namespace.into(),
                    source_id: source_id.into(),
                },
                CallOptions::new(),
            )
            .await
            .ok()?;
        response
            .source
            .filter(|source| source.status == "active" && self.connectors.delivers(source))
    }

    /// Claims the next deliverable artifact in the namespace at `index`
    /// that a Source of a type this runtime delivers through names.
    pub async fn claim_delivery(
        &self,
        index: usize,
    ) -> Result<Option<(ConnectorSource, ExportDeliveryWork)>, RuntimeClaimError> {
        // Only Sources of a type that delivers fill the page, so artifacts
        // other deliverers take never starve this runtime. An empty list
        // would mean any type, so a runtime that delivers nothing asks for
        // nothing.
        let types = self.connectors.delivery_types();
        if types.is_empty() {
            return Ok(None);
        }
        let claims = self.clients[index].runtime_claim();
        let listed = claims
            .list_export_delivery_work(&self.options.runtime_id, LIST_LIMIT, types)
            .await?;
        for artifact in listed {
            // The plane filters too; a plane that ignores the option still
            // never has this runtime deliver an artifact no Source names.
            if artifact.delivery_source_id.is_empty() {
                continue;
            }
            let Some(source) = self
                .delivery_source(index, &artifact.namespace, &artifact.delivery_source_id)
                .await
            else {
                continue;
            };
            let attempt = claims
                .claim_work(
                    WorkKind::ExportDelivery,
                    &self.options.runtime_id,
                    &artifact.receipt_id,
                    self.options.lease,
                    None,
                )
                .await;
            match attempt {
                Ok(ClaimAttempt::Claimed(claim_work_response::Payload::ExportDelivery(work))) => {
                    return Ok(Some((source, work)));
                }
                Ok(_) | Err(RuntimeClaimError::Contention) => continue,
                // Claimed by another runtime since the list, or gone.
                Err(RuntimeClaimError::Unavailable(_) | RuntimeClaimError::FenceLost) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// The artifact's bytes, fetched under `fence`, when their digest is
    /// `digest`. `None` when the fetch fails; `Some(Err)` on a mismatch.
    async fn fetch(
        &self,
        index: usize,
        receipt_id: &str,
        fence: &WorkFence,
        digest: &str,
    ) -> Option<Result<Vec<u8>, SyncFailure>> {
        let mut stream = self.clients[index]
            .raw()
            .server_streaming::<_, ExportObjectSetChunk>(
                "/sekai.SekaiService/FetchExportArtifact",
                FetchExportArtifactRequest {
                    receipt_id: receipt_id.into(),
                    claim: Some(ExportDeliveryFence {
                        runtime_id: fence.runtime_id.clone(),
                        claim_generation: fence.generation,
                        fencing_token: fence.fencing_token.clone(),
                    }),
                },
                CallOptions::new(),
            )
            .await
            .ok()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.ok()?;
            bytes.extend(chunk.data);
            if chunk.done {
                let verified = format!("sha256:{:x}", Sha256::digest(&bytes)) == digest;
                return Some(if verified {
                    Ok(bytes)
                } else {
                    Err(SyncFailure::Invalid)
                });
            }
        }
        None
    }

    /// Delivers a claimed artifact through `source` and acknowledges it.
    pub async fn deliver(
        &self,
        index: usize,
        source: ConnectorSource,
        work: ExportDeliveryWork,
    ) -> Result<Ran, RuntimeClaimError> {
        let claims = self.clients[index].runtime_claim();
        let artifact = work.artifact.unwrap_or_default();
        let receipt_id = artifact.receipt_id.clone();
        let fence = WorkFence {
            kind: WorkKind::ExportDelivery,
            work_id: receipt_id.clone(),
            runtime_id: work.claim_owner,
            generation: work.claim_generation,
            fencing_token: work.fencing_token,
        };
        let outcome = match prepare(&source, &self.bindings) {
            Err(failure) => Err(failure),
            Ok(prepared) => {
                match self
                    .fetch(index, &receipt_id, &fence, &artifact.content_digest)
                    .await
                {
                    None => return Ok(Ran::DeliveryLost { receipt_id }),
                    Some(Err(failure)) => Err(failure),
                    Some(Ok(bytes)) => {
                        let connectors = self.connectors.clone();
                        let artifact = artifact.clone();
                        let job = move || {
                            connectors.deliver(
                                &prepared,
                                &ExportArtifact {
                                    receipt_id: &artifact.receipt_id,
                                    namespace: &artifact.namespace,
                                    definition_id: &artifact.definition_id,
                                    content_digest: &artifact.content_digest,
                                    bytes: &bytes,
                                },
                            )
                        };
                        match self.heartbeated(&claims, &fence, blocking(job)).await {
                            Some(outcome) => outcome,
                            None => return Ok(Ran::DeliveryLost { receipt_id }),
                        }
                    }
                }
            }
        };
        let (status, reason, options) = match outcome {
            Ok(()) => (
                "completed",
                String::new(),
                Some(ack_work_request::Options::ExportDelivery(
                    ExportDeliveryAckOptions {
                        content_digest: artifact.content_digest,
                    },
                )),
            ),
            Err(failure) => ("failed", failure.wire_name().to_string(), None),
        };
        match claims.ack_work(&fence, status, reason, options).await {
            Ok(_) => Ok(Ran::Delivered {
                receipt_id,
                outcome,
            }),
            Err(RuntimeClaimError::FenceLost) => Ok(Ran::DeliveryLost { receipt_id }),
            Err(error) => Err(error),
        }
    }
}
