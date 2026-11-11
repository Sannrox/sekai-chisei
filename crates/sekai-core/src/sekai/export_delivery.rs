//! Saved-export delivery as the `export_delivery` work kind (ADR 0148,
//! ADR 0149).
//!
//! A completed, unexpired, unacknowledged artifact is claimable work. Its
//! claim record lives in the artifact row, and the claim engine
//! ([`crate::sekai::work_claim`]) decides who holds it. A claim is a
//! reference: the bytes still come through `FetchExportArtifact`, under the
//! claim's fence. Acknowledging checks the receipt digest and deletes the
//! bytes in the same transaction as the fence check.
//!
//! The old delivery RPCs stay unfenced while no live claim holds an
//! artifact. While one does, only its fence reads or acknowledges it. A
//! lapsed claim no longer hides the artifact. Retention bounds reclaims,
//! so the kind sets no lease-expiry limit.

use sekai_domain::receipt::OperationReceipt;
use sekai_types::governed_transform::normalize_transform_claim_ttl_ms;

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::data_export::{completed_digest, export_receipt};
use crate::sekai::data_export_artifact_store::ArtifactMeta;
use crate::sekai::work_claim::{ClaimError, ClaimRecord, Fence, Hold};

/// Why a delivery call was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryError {
    /// No such artifact, or it expired, was acknowledged, never completed,
    /// or a live claim hides it from an unfenced caller.
    Unavailable,
    /// The claim engine refused the transition.
    Claim(ClaimError),
    /// The receipt never completed, so there is no digest to acknowledge.
    Incomplete,
    /// The digest does not match the completed receipt.
    Digest,
    Store(String),
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("export artifact unavailable"),
            Self::Claim(error) => error.fmt(formatter),
            Self::Incomplete => formatter.write_str("export artifact is not complete"),
            Self::Digest => formatter.write_str("export artifact digest mismatch"),
            Self::Store(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for DeliveryError {}

impl From<String> for DeliveryError {
    fn from(error: String) -> Self {
        Self::Store(error)
    }
}

/// A completed artifact a caller may deliver, with its current claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverableExportArtifact {
    pub receipt_id: String,
    pub namespace: String,
    pub definition_id: String,
    pub initiating_actor: String,
    pub content_digest: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub claim: ClaimRecord,
}

impl DeliverableExportArtifact {
    fn new(receipt: &OperationReceipt, content_digest: String, artifact: ArtifactMeta) -> Self {
        Self {
            receipt_id: artifact.receipt_id,
            namespace: artifact.namespace,
            definition_id: artifact.definition_id,
            initiating_actor: receipt.initiating_actor.clone(),
            content_digest,
            created_at_ms: artifact.created_at_ms,
            expires_at_ms: artifact.expires_at_ms,
            claim: artifact.claim,
        }
    }
}

impl ArtifactMeta {
    /// What the artifact's state means for its claim.
    pub fn hold(&self, now_ms: i64) -> Hold {
        if self.acked_at_ms.is_some() || self.expires_at_ms < now_ms {
            Hold::Closed
        } else if self.claim.owner.is_empty() {
            Hold::Open
        } else {
            Hold::Held
        }
    }

    /// Whether `fence` may read or acknowledge the artifact now. Without a
    /// fence, any caller may while no live claim holds it.
    pub fn admits(&self, fence: Option<Fence<'_>>, now_ms: i64) -> bool {
        let hold = self.hold(now_ms);
        match fence {
            Some(fence) => self.claim.require_live(hold, fence, now_ms).is_ok(),
            None => self.claim.is_takeable(hold, 0, now_ms),
        }
    }

    /// A lease never outlives the artifact.
    fn lease_ms(&self, ttl_ms: i64, now_ms: i64) -> i64 {
        normalize_transform_claim_ttl_ms(ttl_ms).min(self.expires_at_ms.saturating_sub(now_ms))
    }

    fn take(&mut self, owner: &str, ttl_ms: i64, now_ms: i64) -> Result<(), DeliveryError> {
        let hold = self.hold(now_ms);
        self.claim
            .count_lapse(hold, 0, now_ms)
            .map_err(DeliveryError::Claim)?;
        let lease_ms = self.lease_ms(ttl_ms, now_ms);
        self.claim.grant(owner, lease_ms, now_ms, |_| {
            uuid::Uuid::new_v4().to_string()
        });
        Ok(())
    }

    fn renew(&mut self, fence: Fence<'_>, ttl_ms: i64, now_ms: i64) -> Result<(), DeliveryError> {
        let lease_ms = self.lease_ms(ttl_ms, now_ms);
        self.claim
            .heartbeat(self.hold(now_ms), fence, lease_ms, now_ms)
            .map_err(DeliveryError::Claim)
    }

    /// Records delivery. A retry of an acknowledged artifact succeeds
    /// unfenced, or under the fence that acknowledged it.
    pub(crate) fn acknowledge(
        &mut self,
        fence: Option<Fence<'_>>,
        now_ms: i64,
    ) -> Result<(), DeliveryError> {
        if self.acked_at_ms.is_some() {
            return match fence {
                Some(fence) if !self.claim.matches(fence) => {
                    Err(DeliveryError::Claim(ClaimError::FenceLost))
                }
                _ => Ok(()),
            };
        }
        let hold = self.hold(now_ms);
        match fence {
            Some(fence) => self
                .claim
                .release(hold, fence, now_ms)
                .map_err(DeliveryError::Claim)?,
            None if self.claim.is_takeable(hold, 0, now_ms) => {
                // Ends a lapsed claim, so its fence cannot replay this ack.
                self.claim.fencing_token.clear();
                self.claim.expires_at_ms = 0;
            }
            None => return Err(DeliveryError::Unavailable),
        }
        self.acked_at_ms = Some(now_ms);
        Ok(())
    }
}

/// Completed artifacts in `namespace` no live claim holds, oldest first,
/// with the receipt each was run under.
fn open_artifacts(
    db: &RuntimeDb,
    namespace: &str,
    now_ms: i64,
) -> Result<Vec<(OperationReceipt, String, ArtifactMeta)>, String> {
    let mut open = Vec::new();
    for artifact in db.list_unacked_export_artifacts(namespace, now_ms)? {
        if !artifact.admits(None, now_ms) {
            continue;
        }
        let Some(receipt) = export_receipt(db, &artifact.receipt_id)? else {
            continue;
        };
        let Some(content_digest) = completed_digest(&receipt) else {
            continue;
        };
        open.push((receipt, content_digest, artifact));
    }
    Ok(open)
}

/// Completed, unexpired, unacknowledged artifacts in `namespace` that no
/// live claim holds, oldest first. Both the old list and claimable-work
/// listing read this.
pub fn list_deliverable_export_artifacts(
    db: &RuntimeDb,
    namespace: &str,
    now_ms: i64,
) -> Result<Vec<DeliverableExportArtifact>, String> {
    Ok(open_artifacts(db, namespace, now_ms)?
        .into_iter()
        .map(|(receipt, digest, artifact)| {
            DeliverableExportArtifact::new(&receipt, digest, artifact)
        })
        .collect())
}

/// Claims the artifact of `receipt` for `owner`. The lease is capped at the
/// artifact's expiry.
pub fn claim(
    db: &RuntimeDb,
    receipt: &OperationReceipt,
    owner: &str,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<DeliverableExportArtifact, DeliveryError> {
    if owner.trim().is_empty() {
        return Err(DeliveryError::Unavailable);
    }
    let content_digest = completed_digest(receipt).ok_or(DeliveryError::Unavailable)?;
    let artifact = db.edit_export_artifact(&receipt.operation_id, |artifact| {
        artifact.take(owner, ttl_ms, now_ms)
    })?;
    Ok(DeliverableExportArtifact::new(
        receipt,
        content_digest,
        artifact,
    ))
}

/// Claims the oldest open artifact in `namespace` that `may_claim` admits,
/// given its receipt and definition id. A row lost to a concurrent claimer
/// is skipped.
pub fn claim_next(
    db: &RuntimeDb,
    namespace: &str,
    owner: &str,
    ttl_ms: i64,
    now_ms: i64,
    may_claim: impl Fn(&OperationReceipt, &str) -> bool,
) -> Result<DeliverableExportArtifact, DeliveryError> {
    for (receipt, _, artifact) in open_artifacts(db, namespace, now_ms)? {
        if !may_claim(&receipt, &artifact.definition_id) {
            continue;
        }
        match claim(db, &receipt, owner, ttl_ms, now_ms) {
            Err(DeliveryError::Claim(ClaimError::Held | ClaimError::Closed))
            | Err(DeliveryError::Unavailable) => continue,
            claimed => return claimed,
        }
    }
    Err(DeliveryError::Unavailable)
}

/// Extends the live claim `fence` on the artifact of `receipt`.
pub fn heartbeat(
    db: &RuntimeDb,
    receipt: &OperationReceipt,
    fence: Fence<'_>,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<DeliverableExportArtifact, DeliveryError> {
    let content_digest = completed_digest(receipt).ok_or(DeliveryError::Unavailable)?;
    let artifact = db.edit_export_artifact(&receipt.operation_id, |artifact| {
        artifact.renew(fence, ttl_ms, now_ms)
    })?;
    Ok(DeliverableExportArtifact::new(
        receipt,
        content_digest,
        artifact,
    ))
}

/// Acknowledges delivery of a completed artifact whose digest the caller
/// verified: under `fence`, or unfenced while no live claim holds it.
/// Idempotent once acknowledged.
pub fn acknowledge_export_delivery(
    db: &RuntimeDb,
    receipt_id: &str,
    content_digest: &str,
    fence: Option<Fence<'_>>,
    now_ms: i64,
) -> Result<(), DeliveryError> {
    let receipt = export_receipt(db, receipt_id)?.ok_or(DeliveryError::Unavailable)?;
    let digest = completed_digest(&receipt).ok_or(DeliveryError::Incomplete)?;
    if digest != content_digest {
        return Err(DeliveryError::Digest);
    }
    db.acknowledge_export_artifact(receipt_id, fence, now_ms)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sekai::data_export::{ExportFormat, ExportReceipt, ExportSource};
    use crate::sekai::data_export_artifact_store::ARTIFACT_RETENTION_MS;

    /// When the test artifacts are opened; they expire a retention later.
    pub(crate) const OPENED_AT_MS: i64 = 100;

    /// A completed artifact in `namespace` holding `b"abcd"`.
    pub(crate) fn completed_artifact(db: &RuntimeDb, namespace: &str) -> OperationReceipt {
        completed_artifact_at(db, namespace, OPENED_AT_MS)
    }

    fn completed_artifact_at(
        db: &RuntimeDb,
        namespace: &str,
        opened_at_ms: i64,
    ) -> OperationReceipt {
        let source = ExportSource {
            namespace: namespace.into(),
            source_kind: "object_set",
            source_id: "Ticket".into(),
            source_version: "sha256:q".into(),
            definition_digest: "sha256:d".into(),
            format: ExportFormat::Csv,
            columns: Vec::new(),
            granted_via: "alice".into(),
            fingerprint_properties: Vec::new(),
            fingerprint_group_size: 0,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let mut receipt = ExportReceipt::begin(db.clone(), "alice", &source, now).unwrap();
        let receipt_id = receipt.operation_id().to_string();
        db.open_export_artifact(&receipt_id, namespace, "nightly", opened_at_ms)
            .unwrap();
        db.put_export_artifact_chunk(&receipt_id, 0, b"abcd")
            .unwrap();
        assert!(receipt.record(b"abcd", 1));
        receipt.complete(now).unwrap();
        export_receipt(db, &receipt_id).unwrap().unwrap()
    }

    fn fence(claim: &ClaimRecord) -> Fence<'_> {
        Fence {
            owner: &claim.owner,
            generation: claim.generation,
            token: &claim.fencing_token,
        }
    }

    fn namespace(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
    }

    /// While a live claim holds an artifact, the old list hides it and only
    /// the claim's fence reads or acknowledges it.
    fn a_live_claim_hides_the_artifact_from_unfenced_callers(db: &RuntimeDb, prefix: &str) {
        let ns = namespace(prefix);
        let receipt = completed_artifact(db, &ns);
        let id = receipt.operation_id.as_str();
        let digest = completed_digest(&receipt).unwrap();
        let held = claim(db, &receipt, "runtime-a", 1_000, 1_000)
            .unwrap()
            .claim;
        assert!(
            list_deliverable_export_artifacts(db, &ns, 1_500)
                .unwrap()
                .is_empty()
        );
        assert!(!db.export_artifact_is_deliverable(id, None, 1_500).unwrap());
        assert!(
            db.export_artifact_chunks_after(id, -1, 8, None, 1_500)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            acknowledge_export_delivery(db, id, &digest, None, 1_500),
            Err(DeliveryError::Unavailable)
        );
        assert_eq!(
            db.export_artifact_chunks_after(id, -1, 8, Some(fence(&held)), 1_500)
                .unwrap(),
            vec![(0, b"abcd".to_vec())]
        );
        assert_eq!(
            acknowledge_export_delivery(db, id, "sha256:other", Some(fence(&held)), 1_500),
            Err(DeliveryError::Digest)
        );

        // Claimed through the work family, acknowledged through the old RPC
        // path with the fence; a retry replays, an unfenced one too.
        acknowledge_export_delivery(db, id, &digest, Some(fence(&held)), 1_600).unwrap();
        acknowledge_export_delivery(db, id, &digest, Some(fence(&held)), 1_700).unwrap();
        acknowledge_export_delivery(db, id, &digest, None, 1_700).unwrap();
        assert!(
            db.export_artifact_chunks_after(id, -1, 8, Some(fence(&held)), 1_700)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            claim(db, &receipt, "runtime-b", 1_000, 1_800).unwrap_err(),
            DeliveryError::Claim(ClaimError::Closed)
        );
    }

    /// The reverse: delivered unfenced through the old RPCs, the artifact is
    /// no longer claimable work, and a lapsed claim's fence cannot replay it.
    fn an_unfenced_delivery_closes_the_work(db: &RuntimeDb, prefix: &str) {
        let ns = namespace(prefix);
        let receipt = completed_artifact(db, &ns);
        let id = receipt.operation_id.as_str();
        let digest = completed_digest(&receipt).unwrap();
        let lapsed = claim(db, &receipt, "runtime-a", 1_000, 1_000)
            .unwrap()
            .claim;
        assert_eq!(
            list_deliverable_export_artifacts(db, &ns, 2_000)
                .unwrap()
                .len(),
            1,
            "a lapsed claim no longer hides the artifact"
        );
        acknowledge_export_delivery(db, id, &digest, None, 2_000).unwrap();
        assert_eq!(
            acknowledge_export_delivery(db, id, &digest, Some(fence(&lapsed)), 2_100),
            Err(DeliveryError::Claim(ClaimError::FenceLost))
        );
        assert_eq!(
            claim_next(db, &ns, "runtime-b", 1_000, 2_100, |_, _| true),
            Err(DeliveryError::Unavailable)
        );
        assert!(
            list_deliverable_export_artifacts(db, &ns, 2_100)
                .unwrap()
                .is_empty()
        );
    }

    /// Claims are capped at the artifact's expiry, and an expired artifact
    /// is not claimable.
    fn expiry_bounds_the_claim(db: &RuntimeDb, prefix: &str) {
        let ns = namespace(prefix);
        let receipt = completed_artifact(db, &ns);
        let expires_at_ms = OPENED_AT_MS + ARTIFACT_RETENTION_MS;
        let near_end = expires_at_ms - 10;
        let held = claim(db, &receipt, "runtime-a", 60_000, near_end).unwrap();
        assert_eq!(held.claim.expires_at_ms, expires_at_ms);
        let renewed = heartbeat(db, &receipt, fence(&held.claim), 60_000, near_end + 5).unwrap();
        assert_eq!(renewed.claim.expires_at_ms, expires_at_ms);
        assert_eq!(
            claim(db, &receipt, "runtime-b", 1_000, expires_at_ms + 1).unwrap_err(),
            DeliveryError::Claim(ClaimError::Closed)
        );
        assert_eq!(
            claim_next(db, &ns, "runtime-b", 1_000, expires_at_ms + 1, |_, _| true),
            Err(DeliveryError::Unavailable)
        );
    }

    /// Claim-next takes the oldest open artifact the caller may claim and
    /// skips the rest.
    fn claim_next_takes_the_oldest_admitted(db: &RuntimeDb, prefix: &str) {
        let ns = namespace(prefix);
        let second = completed_artifact_at(db, &ns, OPENED_AT_MS + 1);
        let first = completed_artifact_at(db, &ns, OPENED_AT_MS);
        let taken = claim_next(db, &ns, "runtime-a", 1_000, 1_000, |_, _| true).unwrap();
        assert_eq!(taken.receipt_id, first.operation_id);
        assert_eq!(taken.claim.owner, "runtime-a");
        let next = claim_next(db, &ns, "runtime-b", 1_000, 1_000, |_, _| true).unwrap();
        assert_eq!(next.receipt_id, second.operation_id);
        assert_eq!(
            claim_next(db, &ns, "runtime-c", 1_000, 1_000, |_, _| true),
            Err(DeliveryError::Unavailable)
        );
        let other = namespace(prefix);
        completed_artifact(db, &other);
        assert_eq!(
            claim_next(db, &other, "runtime-c", 1_000, 1_000, |_, _| false),
            Err(DeliveryError::Unavailable),
            "a caller the receipt does not admit gets nothing"
        );
    }

    /// Two claimers racing for one artifact: exactly one holds it.
    fn two_claimers_cannot_both_hold(db: &RuntimeDb, prefix: &str) {
        let ns = namespace(prefix);
        let receipt = completed_artifact(db, &ns);
        let barrier = std::sync::Barrier::new(2);
        let won: Vec<bool> = std::thread::scope(|scope| {
            let racers: Vec<_> = ["runtime-a", "runtime-b"]
                .into_iter()
                .map(|owner| {
                    let (db, receipt, barrier) = (db.clone(), &receipt, &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        claim(&db, receipt, owner, 1_000, 1_000).is_ok()
                    })
                })
                .collect();
            racers
                .into_iter()
                .map(|racer| racer.join().unwrap())
                .collect()
        });
        assert_eq!(won.iter().filter(|won| **won).count(), 1);
    }

    fn contract(db: &RuntimeDb, prefix: &str) {
        a_live_claim_hides_the_artifact_from_unfenced_callers(db, prefix);
        an_unfenced_delivery_closes_the_work(db, prefix);
        expiry_bounds_the_claim(db, prefix);
        claim_next_takes_the_oldest_admitted(db, prefix);
        two_claimers_cannot_both_hold(db, prefix);
    }

    #[test]
    fn sqlite_export_delivery_follows_the_contract() {
        contract(&RuntimeDb::memory(), "sqlite");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_export_delivery_follows_the_contract() {
        contract(
            &crate::sekai::work_claim_conformance::postgres(),
            &format!("pg{}", std::process::id()),
        );
    }
}
