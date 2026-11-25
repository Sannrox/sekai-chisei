//! The claim loop: Source sync work from the plane's one work queue
//! (ADR 0149), run under a heartbeated lease and acknowledged with its
//! outcome. Saved-export delivery ([`crate::delivery`]) and external
//! effects ([`crate::effect`]) run the same way.
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
use sekai_client::protocol::sekai::{
    SourceSyncWork, ack_work_request, ack_work_response, claim_work_response,
};
use sekai_client::{ClientConfig, CoreLoopClient, GrpcTransport, SdkError};
use sekai_source_sdk::SyncNotes;

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

/// The end of one claimed sync, delivery or external effect.
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
    /// An external effect, acknowledged with its outcome.
    Effect {
        effect_id: String,
        outcome: crate::Effected,
    },
    /// A Source discovery, acknowledged; `Err` is the failure class the
    /// request recorded.
    Discovered {
        discovery_id: String,
        outcome: Result<(), SyncFailure>,
    },
    /// The discovery's claim was lost; nothing was acknowledged, and
    /// another runtime may run it.
    DiscoveryLost { discovery_id: String },
    /// The effect's claim was lost, or Chisei could not be reached to
    /// redeem; nothing was acknowledged. The next holder cannot redeem a
    /// permit this one redeemed, so it records `outcome_unknown`.
    EffectLost { effect_id: String },
    /// A model step run ([`crate::llm_rows`]) written back, or ended with
    /// `Err` naming why: a failure reason code or a quarantine reason.
    Transformed {
        run_id: String,
        outcome: Result<(), String>,
    },
    /// The model step's claim was lost; nothing was written.
    TransformLost { run_id: String },
}

/// One connector runtime, serving a fixed set of namespaces.
pub struct Runtime {
    pub(crate) clients: Vec<CoreLoopClient<GrpcTransport>>,
    pub(crate) options: RuntimeOptions,
    pub(crate) bindings: CredentialBindings,
    pub(crate) connectors: Connectors,
    pub(crate) gateway: Option<crate::llm_rows::GatewayRoute>,
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
            gateway: None,
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
                // Claimed by another runtime since the list, or gone.
                Err(RuntimeClaimError::Unavailable(_) | RuntimeClaimError::FenceLost) => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Runs a claimed sync, heartbeating while it runs, and acknowledges
    /// its outcome with the notes its pages carried. A failure is
    /// acknowledged once; the plane does not hand the Source out again
    /// before its next interval.
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
        let mut notes = SyncNotes::default();
        let outcome = match prepare(&source, &self.bindings) {
            Err(failure) => Err(failure),
            Ok(prepared) => {
                match self
                    .heartbeated(
                        &claims,
                        &fence,
                        self.sync(index, &source, prepared, &mut notes),
                    )
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
        let acked = ack_with_notes(&notes, |options| {
            claims.ack_work(&fence, status, reason.clone(), options)
        })
        .await;
        match acked {
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
        let mut beat = tokio::time::interval(heartbeat_period(self.options.lease));
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
    /// deliverable artifact and every pending external effect of a Source
    /// this runtime can run, then every model step run it may claim, then
    /// every requested Source discovery, in each namespace in turn. A
    /// namespace that fails to claim or run is logged and skipped; later
    /// namespaces still run. The first such error is returned after the
    /// pass.
    pub async fn pass(&self) -> Result<Vec<Ran>, RuntimeClaimError> {
        let mut ran = Vec::new();
        let mut first_error = None;
        for index in 0..self.clients.len() {
            if let Err(error) = self.pass_namespace(index, &mut ran).await {
                eprintln!("connector runtime pass failed: {error}");
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(ran),
        }
    }

    async fn pass_namespace(
        &self,
        index: usize,
        ran: &mut Vec<Ran>,
    ) -> Result<(), RuntimeClaimError> {
        while let Some(work) = self.claim(index).await? {
            ran.push(self.run(index, work).await?);
        }
        while let Some((source, work)) = self.claim_delivery(index).await? {
            ran.push(self.deliver(index, source, work).await?);
        }
        while let Some(work) = self.claim_effect(index).await? {
            ran.push(self.apply(index, work).await?);
        }
        while let Some(work) = self.claim_llm_rows(index).await? {
            ran.push(self.run_llm_rows(index, work).await?);
        }
        while let Some(work) = self.claim_discovery(index).await? {
            ran.push(self.run_discovery(index, work).await?);
        }
        Ok(())
    }

    /// Passes every `poll` until `shutdown` resolves. A failed pass is
    /// retried on the next poll; the plane keeps the work.
    pub async fn serve(&self, poll: Duration, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        // `interval` panics on a zero period.
        let mut ticks = tokio::time::interval(poll.max(MIN_PERIOD));
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

/// Acknowledges a source sync through `ack`, with `notes` when there are
/// any. A plane that predates notes refuses options on this kind as
/// `INVALID_ARGUMENT`, so the acknowledgement goes again without them: the
/// outcome is kept and only the notes are lost, visibly in the log.
async fn ack_with_notes<F, Fut>(
    notes: &SyncNotes,
    ack: F,
) -> Result<ack_work_response::Payload, RuntimeClaimError>
where
    F: Fn(Option<ack_work_request::Options>) -> Fut,
    Fut: Future<Output = Result<ack_work_response::Payload, RuntimeClaimError>>,
{
    if notes.is_empty() {
        return ack(None).await;
    }
    let options = ack_work_request::Options::SourceSyncNotes(crate::pages::notes_to_proto(notes));
    match ack(Some(options)).await {
        Err(RuntimeClaimError::Invalid(_)) => {
            eprintln!("the plane refused source sync notes; acknowledged without them");
            ack(None).await
        }
        acked => acked,
    }
}

/// The shortest timer period; `tokio::time::interval` panics on zero.
const MIN_PERIOD: Duration = Duration::from_millis(1);

/// Heartbeats run three times per lease, never with a zero period.
fn heartbeat_period(lease: Duration) -> Duration {
    (lease / 3).max(MIN_PERIOD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_client::SdkErrorCode;
    use sekai_source_sdk::{SkipReason, SyncNote};
    use std::sync::Mutex;

    fn acknowledged() -> ack_work_response::Payload {
        ack_work_response::Payload::SourceSync(Default::default())
    }

    /// Acknowledges as a plane would that refuses any options, recording
    /// what each attempt sent.
    async fn ack_on_older_plane(
        notes: &SyncNotes,
    ) -> (
        Result<ack_work_response::Payload, RuntimeClaimError>,
        Vec<bool>,
    ) {
        let sent = Mutex::new(Vec::new());
        let acked = ack_with_notes(notes, |options| {
            let with_notes = options.is_some();
            sent.lock().unwrap().push(with_notes);
            async move {
                if with_notes {
                    Err(RuntimeClaimError::Invalid(SdkError::new(
                        SdkErrorCode::InvalidArgument,
                    )))
                } else {
                    Ok(acknowledged())
                }
            }
        })
        .await;
        (acked, sent.into_inner().unwrap())
    }

    #[tokio::test]
    async fn an_older_plane_gets_the_outcome_without_the_notes() {
        let mut notes = SyncNotes::default();
        notes
            .push(SyncNote::SkippedRecord {
                partition: 0,
                offset: 7,
                reason: SkipReason::MissingId,
            })
            .unwrap();
        let (acked, sent) = ack_on_older_plane(&notes).await;
        assert_eq!(acked.unwrap(), acknowledged());
        assert_eq!(sent, [true, false]);
        // No notes, no options: an older plane accepts the first attempt.
        let (acked, sent) = ack_on_older_plane(&SyncNotes::default()).await;
        assert_eq!(acked.unwrap(), acknowledged());
        assert_eq!(sent, [false]);
    }

    #[test]
    fn a_tiny_lease_still_gets_a_nonzero_heartbeat_period() {
        assert_eq!(heartbeat_period(Duration::from_millis(2)), MIN_PERIOD);
        assert_eq!(heartbeat_period(Duration::ZERO), MIN_PERIOD);
        assert_eq!(
            heartbeat_period(Duration::from_millis(60_000)),
            Duration::from_millis(20_000)
        );
    }
}
