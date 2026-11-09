//! The claim loop: Source sync work from the plane's one work queue
//! (ADR 0149), run under a heartbeated lease and acknowledged with its
//! outcome. Saved-export delivery runs the same way ([`crate::delivery`]).
//!
//! The plane holds every piece of state. A runtime that dies mid-sync
//! leaves a lease that lapses; another runtime then claims the Source under
//! a new generation, and the dead runtime's fence can neither heartbeat nor
//! acknowledge. A runtime claims only Sources of types it implements, so
//! two runtime versions can serve one namespace during a rolling deploy.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use sekai_client::claim::{
    ClaimAttempt, RuntimeClaimClient, RuntimeClaimError, WorkFence, WorkKind,
};
use sekai_client::protocol::sekai::{SourceSyncWork, ack_work_response, claim_work_response};
use sekai_client::{ClientConfig, CoreLoopClient, GrpcTransport, SdkError};

use crate::credentials::CredentialBindings;
use crate::sync::{Connectors, SyncFailure, prepare};

/// How many claimable items one pass looks at per namespace and kind.
pub(crate) const LIST_LIMIT: i32 = 50;

/// What this runtime is and how long its leases run.
#[derive(Debug, Clone)]
pub struct RuntimeOptions {
    pub runtime_id: String,
    /// The labels Sources' placement must match, registered per namespace.
    pub labels: BTreeMap<String, String>,
    pub lease: Duration,
}

/// The end of one claimed sync or delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ran {
    /// Acknowledged; `Err` is the failure class the plane recorded.
    Finished {
        source_id: String,
        outcome: Result<(), SyncFailure>,
    },
    /// The claim was lost (lapsed, taken over or fenced by a disable);
    /// nothing was acknowledged.
    Lost { source_id: String },
    /// A saved-export artifact delivered through a Source, acknowledged;
    /// `Err` is the failure class the Source's health recorded.
    Delivered {
        receipt_id: String,
        outcome: Result<(), SyncFailure>,
    },
    /// The delivery claim was lost, or the bytes could not be fetched under
    /// it; the claim lapses and the artifact is delivered again.
    DeliveryLost { receipt_id: String },
}

/// One connector runtime, serving a fixed set of namespaces.
pub struct Runtime {
    pub(crate) clients: Vec<CoreLoopClient<GrpcTransport>>,
    pub(crate) options: RuntimeOptions,
    pub(crate) bindings: CredentialBindings,
    pub(crate) connectors: Connectors,
}

impl Runtime {
    /// Connects one client per namespace from `plane`, which names the
    /// target, principal and credential.
    pub async fn connect(
        plane: ClientConfig,
        namespaces: &[String],
        options: RuntimeOptions,
        bindings: CredentialBindings,
        connectors: Connectors,
    ) -> Result<Self, SdkError> {
        let mut clients = Vec::with_capacity(namespaces.len());
        for namespace in namespaces {
            clients.push(CoreLoopClient::connect(plane.clone().with_namespace(namespace)).await?);
        }
        Ok(Self {
            clients,
            options,
            bindings,
            connectors,
        })
    }

    /// Registers this runtime's labels in every namespace. Idempotent; run
    /// at start so placement sees the current labels.
    pub async fn register(&self) -> Result<(), RuntimeClaimError> {
        for client in &self.clients {
            client
                .runtime_claim()
                .register_transform_runtime(&self.options.runtime_id, self.options.labels.clone())
                .await?;
        }
        Ok(())
    }

    /// Claims the next due Source of an implemented type in the namespace
    /// at `index`.
    pub async fn claim(&self, index: usize) -> Result<Option<SourceSyncWork>, RuntimeClaimError> {
        let claims = self.clients[index].runtime_claim();
        let listed = claims
            .list_source_sync_work(
                &self.options.runtime_id,
                LIST_LIMIT,
                self.connectors.types(),
            )
            .await?;
        for source in listed {
            // The plane filters by type too; a plane that ignores the
            // filter still never hands this runtime a type it lacks.
            if !self.connectors.implements(&source) {
                continue;
            }
            let attempt = claims
                .claim_work(
                    WorkKind::SourceSync,
                    &self.options.runtime_id,
                    &source.source_id,
                    self.options.lease,
                    None,
                )
                .await;
            match attempt {
                Ok(ClaimAttempt::Claimed(claim_work_response::Payload::SourceSync(work))) => {
                    return Ok(Some(work));
                }
                Ok(_) | Err(RuntimeClaimError::Contention) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Runs a claimed sync, heartbeating while it runs, and acknowledges
    /// its outcome. A failure is acknowledged once; the plane does not hand
    /// the Source out again before its next interval.
    pub async fn run(&self, index: usize, work: SourceSyncWork) -> Result<Ran, RuntimeClaimError> {
        let claims = self.clients[index].runtime_claim();
        let source = work.source.unwrap_or_default();
        let source_id = source.source_id.clone();
        let fence = WorkFence {
            kind: WorkKind::SourceSync,
            work_id: source_id.clone(),
            runtime_id: work.claim_owner,
            generation: work.claim_generation,
            fencing_token: work.fencing_token,
        };
        let outcome = match prepare(&source, &self.bindings) {
            Err(failure) => Err(failure),
            Ok(prepared) => {
                match self
                    .heartbeated(&claims, &fence, self.sync(index, &source, prepared))
                    .await
                {
                    Some(outcome) => outcome,
                    None => return Ok(Ran::Lost { source_id }),
                }
            }
        };
        let (status, reason) = match outcome {
            Ok(()) => ("completed", String::new()),
            Err(failure) => ("failed", failure.wire_name().to_string()),
        };
        match claims.ack_work(&fence, status, reason, None).await {
            Ok(ack_work_response::Payload::SourceSync(_)) | Ok(_) => {
                Ok(Ran::Finished { source_id, outcome })
            }
            Err(RuntimeClaimError::FenceLost) => Ok(Ran::Lost { source_id }),
            Err(error) => Err(error),
        }
    }

    /// Runs `work`, heartbeating `fence` first and then every third of the
    /// lease. `None` when the fence is lost: `work` is then dropped, a blocking job in it
    /// ends on its own, and the new holder runs again.
    pub(crate) async fn heartbeated<T>(
        &self,
        claims: &RuntimeClaimClient<'_>,
        fence: &WorkFence,
        work: impl Future<Output = Result<T, SyncFailure>>,
    ) -> Option<Result<T, SyncFailure>> {
        // A fence that lapsed before the work starts stops it here, so a
        // stale holder reads and writes nothing.
        if let Err(RuntimeClaimError::FenceLost) =
            claims.heartbeat_work(fence, self.options.lease).await
        {
            return None;
        }
        let mut work = std::pin::pin!(work);
        let mut beat = tokio::time::interval(self.options.lease / 3);
        beat.tick().await;
        loop {
            tokio::select! {
                done = &mut work => return Some(done),
                _ = beat.tick() => match claims.heartbeat_work(fence, self.options.lease).await {
                    Ok(_) => {}
                    Err(RuntimeClaimError::FenceLost) => return None,
                    // A plane blip: the lease outlasts a few.
                    Err(_) => {}
                },
            }
        }
    }

    /// One pass: claims and runs every due Source sync, then every
    /// deliverable artifact of a Source this runtime can run, in each
    /// namespace in turn.
    pub async fn pass(&self) -> Result<Vec<Ran>, RuntimeClaimError> {
        let mut ran = Vec::new();
        for index in 0..self.clients.len() {
            while let Some(work) = self.claim(index).await? {
                ran.push(self.run(index, work).await?);
            }
            while let Some((source, work)) = self.claim_delivery(index).await? {
                ran.push(self.deliver(index, source, work).await?);
            }
        }
        Ok(ran)
    }

    /// Passes every `poll` until `shutdown` resolves. A failed pass is
    /// retried on the next poll; the plane keeps the work.
    pub async fn serve(&self, poll: Duration, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut ticks = tokio::time::interval(poll);
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                _ = ticks.tick() => {
                    if let Err(error) = self.pass().await {
                        eprintln!("connector runtime pass failed: {error}");
                    }
                }
            }
        }
    }
}
