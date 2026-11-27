//! External effects (ADR 0148): an admitted Action's `external_mutate`
//! change, applied through the Source that owns the record. The plane hands
//! it only to a runtime the Source's placement admits. The runtime claims
//! it, redeems the change's permit with Chisei, applies the change through
//! the Source's connector under a heartbeated lease, reports execution
//! evidence, and acknowledges.
//!
//! The Action's parameters carry the change: `permit_id`, `source_id` (the
//! record's object source id), `record_kind` (the kind the Source projects
//! the record as, which execution evidence attaches to), `change` (a string
//! map) and `permit`, the
//! signed permit in the protocol's JSON form. Action parameters are
//! scalars, so `change` and `permit` arrive as JSON strings. The
//! permit is no bearer token: Chisei redeems it only for its bound executor,
//! which is the principal this runtime authenticates as. The version the
//! change was decided against is the permit's `record_version`
//! precondition, and the connector writes only while the record still has
//! it.
//!
//! A change is applied at most once. Only a single-use permit is redeemed
//! (`max_invocations` 1); anything else fails as invalid. The redemption is
//! keyed by the claim's generation, so a runtime that takes over a lapsed
//! claim cannot redeem again. A refused redemption under a later generation therefore means an
//! earlier holder may have written: the effect is acknowledged as
//! `outcome_unknown` and never retried. A refusal under the first
//! generation, such as the kill switch, applied nothing and is `failed`.
//! Nothing is applied after a refused redemption.

use std::collections::BTreeMap;

use sekai_client::CallOptions;
use sekai_client::claim::{ClaimAttempt, RuntimeClaimError, WorkFence, WorkKind};
use sekai_client::protocol::chisei::{
    ExternalActionPermit, ExternalActionRedemption, RedeemExternalActionPermitRequest,
    RedeemExternalActionPermitResponse,
};
use sekai_client::protocol::sekai::{
    ConnectorSource, EvidenceCausality, EvidenceEnvelope, ExternalEffectWork,
    SubmitEvidenceRequest, SubmitEvidenceResponse, claim_work_response,
};
use sekai_source_sdk::{Operation, RecordChange};
use sha2::{Digest, Sha256};

use crate::runtime::{LIST_LIMIT, Ran, Runtime};
use crate::sync::{Prepared, SyncFailure, blocking};

/// The host capability every apply offers: the connector checks that the
/// record still has the version the change was decided against before it
/// writes. Relational checks under a row lock; GitHub, which has no
/// conditional write, with a read just before the write. A permit that
/// requires another capability is refused at redemption.
pub const HOST_CAPABILITY: &str = "version_checked_write";

const EVIDENCE_ENVELOPE_VERSION: &str = "sekai.evidence/v1";
const EXECUTION_EVIDENCE_TYPE: &str = "external_action_execution";
const EXECUTION_EVIDENCE_SCHEMA: &str = "external-action.execution-evidence/v1";

/// How an applied external effect ended, as acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Effected {
    /// Applied; the record's new version.
    Completed { version: String },
    /// Nothing was applied.
    Failed(SyncFailure),
    /// The change may have been applied; it is never retried.
    OutcomeUnknown,
}

impl Effected {
    fn ack(&self) -> (&'static str, String) {
        match self {
            Self::Completed { .. } => ("completed", String::new()),
            Self::Failed(failure) => ("failed", failure.wire_name().into()),
            Self::OutcomeUnknown => ("outcome_unknown", String::new()),
        }
    }

    fn evidence_state(&self) -> &'static str {
        match self {
            Self::Completed { .. } => "completed",
            Self::Failed(_) => "failed",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

/// The change an effect carries, checked against its Source.
struct Intent {
    permit: ExternalActionPermit,
    resource: String,
    kind: String,
    change: RecordChange,
}

impl Intent {
    /// Reads the Action's parameters. Fails closed on anything missing or
    /// on a record outside the claimed Source.
    fn parse(work: &ExternalEffectWork, source: &ConnectorSource) -> Result<Self, SyncFailure> {
        let effect = work.effect.as_ref().ok_or(SyncFailure::Invalid)?;
        let params: serde_json::Value =
            serde_json::from_str(&work.parameters_json).map_err(|_| SyncFailure::Invalid)?;
        let text = |name: &str| params.get(name).and_then(serde_json::Value::as_str);
        let permit: ExternalActionPermit = text("permit")
            .and_then(|json| serde_json::from_str(json).ok())
            .ok_or(SyncFailure::Invalid)?;
        let resource = text("source_id").ok_or(SyncFailure::Invalid)?;
        let kind = text("record_kind").ok_or(SyncFailure::Invalid)?;
        let change: BTreeMap<String, String> = text("change")
            .and_then(|json| serde_json::from_str(json).ok())
            .ok_or(SyncFailure::Invalid)?;
        let (tokens, key) = resource.rsplit_once('#').ok_or(SyncFailure::Invalid)?;
        let expected_version = permit
            .immutable_preconditions
            .get("record_version")
            .cloned()
            .ok_or(SyncFailure::Invalid)?;
        let routed = format!("{}:{}", source.source, source.source_instance);
        // Single use is what makes a takeover safe: a permit that allows a
        // second invocation would let the next holder write again.
        if text("permit_id") != Some(permit.permit_id.as_str())
            || permit.max_invocations != 1
            || permit.namespace != effect.namespace
            || tokens != routed
            || key.is_empty()
            || kind.is_empty()
            || change.is_empty()
        {
            return Err(SyncFailure::Invalid);
        }
        Ok(Self {
            change: RecordChange {
                idempotency_key: effect.effect_id.clone(),
                key: key.into(),
                expected_version,
                change,
            },
            resource: resource.into(),
            kind: kind.into(),
            permit,
        })
    }

    /// The redemption of this change under `fence`: what the runtime is
    /// about to do, computed from the change rather than copied from the
    /// permit, so Chisei compares the authorized change with this one.
    fn redemption(&self, fence: &WorkFence, executor: &str) -> RedeemExternalActionPermitRequest {
        let execution_id = execution_id(fence);
        RedeemExternalActionPermitRequest {
            permit: Some(self.permit.clone()),
            executor: executor.into(),
            requesting_harness: self.permit.requesting_harness.clone(),
            canonical_arguments_digest: self.change.arguments_digest(&self.resource),
            target_selectors: vec![format!(
                "project:{}/{}",
                self.permit.namespace, self.resource
            )],
            // The connector enforces the version at the write itself.
            observed_preconditions: [(
                "record_version".to_string(),
                self.change.expected_version.clone(),
            )]
            .into(),
            host_capabilities: vec![HOST_CAPABILITY.into()],
            idempotency_key: format!("{execution_id}:redeem"),
            execution_id,
            invoked_at_ms: 0,
        }
    }
}

/// One execution per claim generation, so a takeover never replays a
/// predecessor's redemption.
fn execution_id(fence: &WorkFence) -> String {
    format!("{}:{}", fence.work_id, fence.generation)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

impl Runtime {
    /// Claims the next pending external effect in the namespace at `index`
    /// on a Source of a type this runtime applies through.
    pub async fn claim_effect(
        &self,
        index: usize,
    ) -> Result<Option<ExternalEffectWork>, RuntimeClaimError> {
        // An empty list would mean any type, so a runtime that applies
        // nothing asks for nothing.
        let types = self.connectors.types_for(Operation::Apply);
        if types.is_empty() {
            return Ok(None);
        }
        let claims = self.clients[index].runtime_claim();
        let listed = claims
            .list_external_effect_work(&self.options.runtime_id, LIST_LIMIT, types)
            .await?;
        for work in listed {
            // The plane filters too; a plane that ignores the option still
            // never has this runtime apply through a type it lacks.
            if !work
                .source
                .as_ref()
                .is_some_and(|source| self.connectors.runs(source, Operation::Apply))
            {
                continue;
            }
            let effect_id = work.effect.unwrap_or_default().effect_id;
            let attempt = claims
                .claim_work(
                    WorkKind::ExternalEffect,
                    &self.options.runtime_id,
                    &effect_id,
                    self.options.lease,
                    None,
                )
                .await;
            match attempt {
                Ok(ClaimAttempt::Claimed(claim_work_response::Payload::ExternalEffect(work))) => {
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

    /// Redeems, applies and acknowledges a claimed external effect.
    pub async fn apply(
        &self,
        index: usize,
        work: ExternalEffectWork,
    ) -> Result<Ran, RuntimeClaimError> {
        let claims = self.clients[index].runtime_claim();
        let effect = work.effect.clone().unwrap_or_default();
        let effect_id = effect.effect_id.clone();
        let source = work.source.clone().unwrap_or_default();
        let fence = WorkFence {
            kind: WorkKind::ExternalEffect,
            work_id: effect_id.clone(),
            runtime_id: effect.claim_owner.clone(),
            generation: i64::try_from(effect.claim_generation).unwrap_or(i64::MAX),
            fencing_token: effect.claim_fencing_token.clone(),
        };
        let outcome = match self
            .prepare_source(&source, work.credential.as_ref())
            .and_then(|prepared| Ok((prepared, Intent::parse(&work, &source)?)))
        {
            Err(failure) => Effected::Failed(failure),
            // The lease is kept alive from before the redemption to the
            // last report, so plane latency alone never costs the claim.
            Ok((prepared, intent)) => {
                let run = self.redeem_and_apply(index, &fence, prepared, intent);
                match self.heartbeated(&claims, &fence, run).await {
                    // The write may land after the lease is gone; the next
                    // holder cannot redeem and records that.
                    None | Some(Ok(None)) => return Ok(Ran::EffectLost { effect_id }),
                    Some(Ok(Some(outcome))) => outcome,
                    Some(Err(failure)) => Effected::Failed(failure),
                }
            }
        };
        let (status, reason) = outcome.ack();
        match claims.ack_work(&fence, status, reason, None).await {
            Ok(_) => Ok(Ran::Effect { effect_id, outcome }),
            Err(RuntimeClaimError::FenceLost) => Ok(Ran::EffectLost { effect_id }),
            Err(error) => Err(error),
        }
    }

    /// Redeems the change's permit, reports, applies the change and reports
    /// again. `None` when the plane stayed unreachable for the redemption,
    /// which leaves the claim to lapse.
    async fn redeem_and_apply(
        &self,
        index: usize,
        fence: &WorkFence,
        prepared: Prepared,
        intent: Intent,
    ) -> Result<Option<Effected>, SyncFailure> {
        let redemption = match self.redeem(index, &intent, fence).await {
            Redeemed::Lost => return Ok(None),
            // An earlier holder redeemed and may have written.
            Redeemed::Refused if fence.generation > 1 => return Ok(Some(Effected::OutcomeUnknown)),
            Redeemed::Refused => return Ok(Some(Effected::Failed(SyncFailure::Refused))),
            Redeemed::Granted(redemption) => redemption,
        };
        let started_at_ms = now_ms().max(redemption.redeemed_at_ms);
        self.report(
            index,
            &intent,
            &redemption,
            fence,
            "accepted",
            started_at_ms,
        )
        .await;
        let connectors = self.connectors.clone();
        let change = intent.change.clone();
        let outcome = match blocking(move || connectors.apply(&prepared, &change)).await {
            Ok(version) => Effected::Completed { version },
            // A lost connection may have lost the reply, not the write.
            Err(SyncFailure::Unreachable) => Effected::OutcomeUnknown,
            Err(failure) => Effected::Failed(failure),
        };
        let state = outcome.evidence_state();
        self.report(index, &intent, &redemption, fence, state, started_at_ms)
            .await;
        Ok(Some(outcome))
    }

    /// Redeems the change's permit for this claim's generation. A transport
    /// failure is retried with the same key, which Chisei replays; one that
    /// persists leaves the claim to lapse.
    async fn redeem(&self, index: usize, intent: &Intent, fence: &WorkFence) -> Redeemed {
        let client = &self.clients[index];
        let request = intent.redemption(fence, &client.config().principal);
        for _ in 0..3 {
            let reply = client
                .raw()
                .unary::<_, RedeemExternalActionPermitResponse>(
                    "/chisei.ChiseiService/RedeemExternalActionPermit",
                    request.clone(),
                    CallOptions::new(),
                )
                .await;
            match reply {
                Ok(RedeemExternalActionPermitResponse {
                    redemption: Some(redemption),
                }) => return Redeemed::Granted(redemption),
                Ok(_) => return Redeemed::Refused,
                Err(error) if error.retryable => continue,
                Err(_) => return Redeemed::Refused,
            }
        }
        Redeemed::Lost
    }

    /// Submits one execution-evidence report for `redemption`. Evidence is
    /// an attributed observation, not the outcome: a report the plane does
    /// not take leaves the acknowledge as the record, and its absence is
    /// what the missing-evidence alert reports.
    async fn report(
        &self,
        index: usize,
        intent: &Intent,
        redemption: &ExternalActionRedemption,
        fence: &WorkFence,
        state: &str,
        started_at_ms: i64,
    ) {
        let client = &self.clients[index];
        let host = client.config().principal.clone();
        let terminal = state != "accepted";
        // The accepted report is the same bytes however often it is sent.
        let observed_at_ms = if terminal {
            now_ms().max(started_at_ms)
        } else {
            started_at_ms
        };
        let content = serde_json::json!({
            "version": EXECUTION_EVIDENCE_SCHEMA,
            "permit_id": intent.permit.permit_id,
            "redemption_id": redemption.redemption_id,
            "execution_id": execution_id(fence),
            "host_identity": host,
            "lifecycle_state": state,
            "observed_at_ms": observed_at_ms,
            "started_at_ms": started_at_ms,
            "finished_at_ms": terminal.then_some(observed_at_ms),
            "enforced_preconditions": {
                "record_version": intent.change.expected_version,
            },
            "normalized_effects": ["record_updated"],
            "affected_resource_references": [intent.resource],
            "host_schema_version": "host-evidence/v1",
            "host_software_version": concat!("sekai-connector-runtime/", env!("CARGO_PKG_VERSION")),
        });
        let Ok(content_json) = serde_json::to_vec(&content) else {
            return;
        };
        let envelope = EvidenceEnvelope {
            contract_version: EVIDENCE_ENVELOPE_VERSION.into(),
            source_type: "host_executor".into(),
            source_instance: format!("{host}:external-effect"),
            source_record_id: redemption.redemption_id.clone(),
            source_version: format!("state-{state}"),
            source_sequence: if terminal { 2 } else { 1 },
            namespace: intent.permit.namespace.clone(),
            target_external_id: intent.resource.clone(),
            target_kind: intent.kind.clone(),
            evidence_type: EXECUTION_EVIDENCE_TYPE.into(),
            signal: "delivery".into(),
            schema_id: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_version: EXECUTION_EVIDENCE_SCHEMA.into(),
            schema_compatibility: "exact".into(),
            observed_at_ms,
            collected_at_ms: observed_at_ms,
            content_digest: format!("{:x}", Sha256::digest(&content_json)),
            content_json,
            producer_identity: host,
            confidence_bps: 8_000,
            classification: "internal".into(),
            idempotency_key: format!("{}-{state}", redemption.redemption_id),
            intent: "upsert".into(),
            causality: Some(EvidenceCausality {
                operation_id: intent.permit.operation_id.clone(),
                subject_references: vec![intent.resource.clone()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let submitted = client
            .raw()
            .unary::<_, SubmitEvidenceResponse>(
                "/sekai.SekaiService/SubmitEvidence",
                SubmitEvidenceRequest {
                    envelope: Some(envelope),
                },
                CallOptions::new(),
            )
            .await;
        if !matches!(&submitted, Ok(response) if response.result.as_ref().is_some_and(|result| result.admitted))
        {
            eprintln!(
                "external effect {}: {state} evidence was not admitted",
                fence.work_id
            );
        }
    }
}

/// What redeeming a permit under one claim came to.
enum Redeemed {
    Granted(ExternalActionRedemption),
    Refused,
    /// The plane could not be reached; the claim is left to lapse.
    Lost,
}
