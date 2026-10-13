//! Versioned runtime-claim client for Action and isolated-process transform work.
//!
//! Lives in `sekai-client` so Shikigami and kako pin one crate with
//! `sekai-proto`. The plane remains authoritative; this module maps wire
//! codes onto fence loss, contention, denial, and unavailability without
//! embedding credentials or provider semantics.
//!
//! `SdkError` does not retain arbitrary server status text. Allowlisted
//! `delegator_*` tokens are kept as `reason_code` so claim and owned-claim
//! RPCs can surface them instead of collapsing to contention or fence loss.
//! Other owned-claim `FailedPrecondition` stays fence loss. Other initial
//! `Claim*` `FailedPrecondition` stays contention. Empty-queue
//! `ClaimTransformWork` is `NotFound` (idle); a targeted run_id that is gone
//! or held is contention. Fence loss is never mapped to idle.

use std::fmt;
use std::time::Duration;

use uuid::Uuid;

use crate::protocol::sekai::{
    AckActionWorkRequest, AckActionWorkResponse, ClaimActionWorkRequest, ClaimActionWorkResponse,
    ClaimTransformWorkRequest, ClaimTransformWorkResponse, HeartbeatActionClaimRequest,
    HeartbeatActionClaimResponse, HeartbeatTransformClaimRequest, HeartbeatTransformClaimResponse,
    ListClaimableActionWorkRequest, ListClaimableActionWorkResponse,
    ListClaimableTransformWorkRequest, ListClaimableTransformWorkResponse,
    ReadTransformRunInputsRequest, ReadTransformRunInputsResponse, ReportActionClaimEventRequest,
    ReportActionClaimEventResponse, TransformRunInputRow, WriteTransformRunResultRequest,
    WriteTransformRunResultResponse,
};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::{
    CallOptions, CancellableStream, CoreLoopClient, GrpcTransport, SdkError, SdkErrorCode,
};

/// Machine-readable claim/apply refusals reused from the identity contract.
pub const DELEGATOR_DISABLED: &str = "delegator_disabled";
pub const DELEGATOR_NOT_MEMBER: &str = "delegator_not_member";
pub const DELEGATOR_GRANT_MISSING: &str = "delegator_grant_missing";
pub const DELEGATOR_RECORD_MISSING: &str = "delegator_record_missing";

const LIST_ACTION: &str = "/sekai.SekaiService/ListClaimableActionWork";
const CLAIM_ACTION: &str = "/sekai.SekaiService/ClaimActionWork";
const HEARTBEAT_ACTION: &str = "/sekai.SekaiService/HeartbeatActionClaim";
const ACK_ACTION: &str = "/sekai.SekaiService/AckActionWork";
const REPORT_ACTION: &str = "/sekai.SekaiService/ReportActionClaimEvent";
const LIST_TRANSFORM: &str = "/sekai.SekaiService/ListClaimableTransformWork";
const CLAIM_TRANSFORM: &str = "/sekai.SekaiService/ClaimTransformWork";
const HEARTBEAT_TRANSFORM: &str = "/sekai.SekaiService/HeartbeatTransformClaim";
const READ_TRANSFORM: &str = "/sekai.SekaiService/ReadTransformRunInputs";
const WRITE_TRANSFORM: &str = "/sekai.SekaiService/WriteTransformRunResult";

/// Dispatch kind a worker lists or claims. Transform work uses the isolated
/// JobSpec profile; Action work uses `runtime_dispatch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchKind {
    Action,
    IsolatedTransform,
}

impl DispatchKind {
    pub fn list_rpc(self) -> &'static str {
        match self {
            Self::Action => LIST_ACTION,
            Self::IsolatedTransform => LIST_TRANSFORM,
        }
    }

    pub fn claim_rpc(self) -> &'static str {
        match self {
            Self::Action => CLAIM_ACTION,
            Self::IsolatedTransform => CLAIM_TRANSFORM,
        }
    }
}

/// Outcome of a claim attempt that must not collapse fence loss into idle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimAttempt<T> {
    Claimed(T),
    Idle,
    Contended,
}

/// Typed claim-protocol failure. Fence loss stays distinct from idle,
/// contention, denial, unavailability, and delegator refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeClaimError {
    Contention,
    FenceLost,
    DelegatorRefused(&'static str),
    Denied(SdkError),
    Unavailable(SdkError),
    Invalid(SdkError),
    Transport(SdkError),
}

pub(crate) fn allowlisted_reason_code(message: &str) -> Option<&'static str> {
    match message.trim() {
        DELEGATOR_DISABLED => Some(DELEGATOR_DISABLED),
        DELEGATOR_NOT_MEMBER => Some(DELEGATOR_NOT_MEMBER),
        DELEGATOR_GRANT_MISSING => Some(DELEGATOR_GRANT_MISSING),
        DELEGATOR_RECORD_MISSING => Some(DELEGATOR_RECORD_MISSING),
        _ => None,
    }
}

impl RuntimeClaimError {
    fn from_sdk(error: SdkError, owned_fence: bool) -> Self {
        if let Some(reason) = error.reason_code {
            return Self::DelegatorRefused(reason);
        }
        match error.code {
            SdkErrorCode::FailedPrecondition if owned_fence => Self::FenceLost,
            SdkErrorCode::FailedPrecondition => Self::Contention,
            SdkErrorCode::PermissionDenied | SdkErrorCode::Unauthenticated => Self::Denied(error),
            SdkErrorCode::Unavailable
            | SdkErrorCode::DeadlineExceeded
            | SdkErrorCode::Aborted
            | SdkErrorCode::ResourceExhausted
            | SdkErrorCode::Cancelled => Self::Unavailable(error),
            SdkErrorCode::InvalidArgument => Self::Invalid(error),
            _ => Self::Transport(error),
        }
    }

    /// List is not a claim race. `FailedPrecondition` here is the experimental
    /// gate or a state check, not contention; `SdkError` strips the message.
    fn from_list(error: SdkError) -> Self {
        match error.code {
            SdkErrorCode::FailedPrecondition => Self::Unavailable(error),
            _ => Self::from_sdk(error, false),
        }
    }

    fn from_action_claim(error: SdkError) -> Result<ClaimAttempt<std::convert::Infallible>, Self> {
        if let Some(reason) = error.reason_code {
            return Err(Self::DelegatorRefused(reason));
        }
        match error.code {
            SdkErrorCode::FailedPrecondition => Ok(ClaimAttempt::Contended),
            _ => Err(Self::from_sdk(error, false)),
        }
    }

    fn from_transform_claim(
        error: SdkError,
        run_id: &str,
    ) -> Result<ClaimAttempt<std::convert::Infallible>, Self> {
        if let Some(reason) = error.reason_code {
            return Err(Self::DelegatorRefused(reason));
        }
        match error.code {
            SdkErrorCode::NotFound if run_id.trim().is_empty() => Ok(ClaimAttempt::Idle),
            SdkErrorCode::NotFound | SdkErrorCode::FailedPrecondition => {
                Ok(ClaimAttempt::Contended)
            }
            _ => Err(Self::from_sdk(error, false)),
        }
    }

    fn from_held_stream(error: SdkError) -> Self {
        Self::from_sdk(error, true)
    }
}

impl fmt::Display for RuntimeClaimError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contention => formatter.write_str("claim lost to contention"),
            Self::FenceLost => formatter.write_str("claim fence was lost"),
            Self::DelegatorRefused(reason) => write!(formatter, "delegator refused: {reason}"),
            Self::Denied(error) => write!(formatter, "claim denied: {error}"),
            Self::Unavailable(error) => write!(formatter, "claim unavailable: {error}"),
            Self::Invalid(error) => write!(formatter, "claim request invalid: {error}"),
            Self::Transport(error) => write!(formatter, "claim transport: {error}"),
        }
    }
}

impl std::error::Error for RuntimeClaimError {}

/// Held Action claim fence. Heartbeat and ack require this exact tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionFence {
    pub effect_id: String,
    pub runtime_id: String,
    pub generation: u64,
    pub fencing_token: String,
}

/// Held isolated-transform claim fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransformFence {
    pub run_id: String,
    pub runtime_id: String,
    pub generation: i64,
    pub fencing_token: String,
}

/// Terminal or park acknowledgement for Action work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionAck {
    Completed {
        reason: String,
        artifact_json: String,
    },
    Failed {
        reason: String,
    },
    Parked {
        reason: String,
        request_id: String,
        checkpoint_store_id: String,
        checkpoint_ref: String,
        checkpoint_digest: String,
    },
}

/// Page selector for a fenced transform input stream.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct TransformRead {
    pub alias: String,
    pub after_alias: String,
    pub after_row_id: i64,
    pub limit: i32,
    /// Unset reads every partition. `Some("")` selects the empty identity.
    pub partition_key: Option<String>,
    pub max_bytes: i64,
}

/// Fenced write-back payload for an isolated-process run.
#[derive(Clone, Debug, PartialEq)]
pub struct TransformWrite {
    pub rows: Vec<TransformRunInputRow>,
    pub output_digest: String,
    pub quarantined: bool,
    pub quality_rule: String,
    pub partitions: Vec<crate::protocol::sekai::TransformPartitionWrite>,
}

/// Stream of transform input rows whose item errors use the claim taxonomy.
pub struct TransformInputStream {
    inner: CancellableStream<ReadTransformRunInputsResponse>,
}

impl TransformInputStream {
    pub fn cancel(&self) {
        self.inner.cancel();
    }
}

impl Stream for TransformInputStream {
    type Item = Result<ReadTransformRunInputsResponse, RuntimeClaimError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.get_mut().inner).poll_next(context) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(RuntimeClaimError::from_held_stream(error))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Typed runtime-claim surface over the existing native transport.
pub struct RuntimeClaimClient<'a> {
    client: &'a CoreLoopClient<GrpcTransport>,
}

impl CoreLoopClient<GrpcTransport> {
    /// Runtime-claim helpers for Action and isolated-process transform work.
    pub fn runtime_claim(&self) -> RuntimeClaimClient<'_> {
        RuntimeClaimClient { client: self }
    }
}

impl<'a> RuntimeClaimClient<'a> {
    fn namespace(&self) -> Result<&str, RuntimeClaimError> {
        match self.client.config().namespace.as_deref() {
            Some(namespace) if !namespace.trim().is_empty() => Ok(namespace),
            _ => Err(RuntimeClaimError::Invalid(SdkError::invalid_argument())),
        }
    }

    fn options(&self, retryable: bool) -> CallOptions {
        let mut options = CallOptions::new().retryable(retryable);
        if let Some(namespace) = self.client.config().namespace.clone() {
            options = options.with_namespace(namespace);
        }
        options
    }

    async fn unary<Req, Resp>(
        &self,
        path: &str,
        request: Req,
        retryable: bool,
        owned_fence: bool,
    ) -> Result<Resp, RuntimeClaimError>
    where
        Req: prost::Message + Default + Clone + Send + 'static,
        Resp: prost::Message + Default + Send + 'static,
    {
        self.client
            .raw()
            .unary(path, request, self.options(retryable))
            .await
            .map_err(|error| RuntimeClaimError::from_sdk(error, owned_fence))
    }

    async fn list_unary<Req, Resp>(
        &self,
        path: &str,
        request: Req,
    ) -> Result<Resp, RuntimeClaimError>
    where
        Req: prost::Message + Default + Clone + Send + 'static,
        Resp: prost::Message + Default + Send + 'static,
    {
        self.client
            .raw()
            .unary(path, request, self.options(true))
            .await
            .map_err(RuntimeClaimError::from_list)
    }

    pub async fn list_action_work(
        &self,
        runtime_id: impl Into<String>,
        limit: u32,
    ) -> Result<Vec<crate::protocol::sekai::ActionEffect>, RuntimeClaimError> {
        let namespace = self.namespace()?.to_string();
        let listed: ListClaimableActionWorkResponse = self
            .list_unary(
                LIST_ACTION,
                ListClaimableActionWorkRequest {
                    namespace,
                    runtime_id: runtime_id.into(),
                    limit,
                },
            )
            .await?;
        Ok(listed.effects)
    }

    pub async fn claim_action_work(
        &self,
        effect_id: impl Into<String>,
        runtime_id: impl Into<String>,
        ttl: Duration,
        request_id: Option<String>,
    ) -> Result<ClaimAttempt<ClaimActionWorkResponse>, RuntimeClaimError> {
        let ttl_ms = duration_millis(ttl)?;
        let request_id = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        match self
            .client
            .raw()
            .unary(
                CLAIM_ACTION,
                ClaimActionWorkRequest {
                    effect_id: effect_id.into(),
                    runtime_id: runtime_id.into(),
                    request_id,
                    ttl_ms,
                },
                self.options(false),
            )
            .await
        {
            Ok(response) => Ok(ClaimAttempt::Claimed(response)),
            Err(error) => match RuntimeClaimError::from_action_claim(error)? {
                ClaimAttempt::Idle => Ok(ClaimAttempt::Idle),
                ClaimAttempt::Contended => Ok(ClaimAttempt::Contended),
                ClaimAttempt::Claimed(_) => unreachable!("infallible claim mapping"),
            },
        }
    }

    /// List then claim the next Action item. Empty list is idle. A lost race
    /// is contention. Heartbeat failures after a successful claim are fence
    /// loss, not idle.
    pub async fn claim_next_action(
        &self,
        runtime_id: impl Into<String>,
        ttl: Duration,
    ) -> Result<ClaimAttempt<ClaimActionWorkResponse>, RuntimeClaimError> {
        let runtime_id = runtime_id.into();
        let listed = self.list_action_work(&runtime_id, 1).await?;
        let Some(candidate) = listed.into_iter().next() else {
            return Ok(ClaimAttempt::Idle);
        };
        self.claim_action_work(candidate.effect_id, runtime_id, ttl, None)
            .await
    }

    pub async fn heartbeat_action(
        &self,
        fence: &ActionFence,
        ttl: Duration,
    ) -> Result<HeartbeatActionClaimResponse, RuntimeClaimError> {
        self.unary(
            HEARTBEAT_ACTION,
            HeartbeatActionClaimRequest {
                effect_id: fence.effect_id.clone(),
                runtime_id: fence.runtime_id.clone(),
                claim_generation: fence.generation,
                fencing_token: fence.fencing_token.clone(),
                ttl_ms: duration_millis(ttl)?,
            },
            false,
            true,
        )
        .await
    }

    pub async fn ack_action(
        &self,
        fence: &ActionFence,
        ack: ActionAck,
    ) -> Result<AckActionWorkResponse, RuntimeClaimError> {
        let request = match ack {
            ActionAck::Completed {
                reason,
                artifact_json,
            } => AckActionWorkRequest {
                effect_id: fence.effect_id.clone(),
                runtime_id: fence.runtime_id.clone(),
                claim_generation: fence.generation,
                fencing_token: fence.fencing_token.clone(),
                outcome: "completed".into(),
                reason,
                request_id: String::new(),
                checkpoint_store_id: String::new(),
                checkpoint_ref: String::new(),
                checkpoint_digest: String::new(),
                artifact_json,
            },
            ActionAck::Failed { reason } => AckActionWorkRequest {
                effect_id: fence.effect_id.clone(),
                runtime_id: fence.runtime_id.clone(),
                claim_generation: fence.generation,
                fencing_token: fence.fencing_token.clone(),
                outcome: "failed".into(),
                reason,
                request_id: String::new(),
                checkpoint_store_id: String::new(),
                checkpoint_ref: String::new(),
                checkpoint_digest: String::new(),
                artifact_json: String::new(),
            },
            ActionAck::Parked {
                reason,
                request_id,
                checkpoint_store_id,
                checkpoint_ref,
                checkpoint_digest,
            } => AckActionWorkRequest {
                effect_id: fence.effect_id.clone(),
                runtime_id: fence.runtime_id.clone(),
                claim_generation: fence.generation,
                fencing_token: fence.fencing_token.clone(),
                outcome: "parked".into(),
                reason,
                request_id,
                checkpoint_store_id,
                checkpoint_ref,
                checkpoint_digest,
                artifact_json: String::new(),
            },
        };
        self.unary(ACK_ACTION, request, false, true).await
    }

    pub async fn report_action_event(
        &self,
        fence: &ActionFence,
        kind: impl Into<String>,
        checkpoint_digest: impl Into<String>,
        reason_code: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Result<ReportActionClaimEventResponse, RuntimeClaimError> {
        self.unary(
            REPORT_ACTION,
            ReportActionClaimEventRequest {
                effect_id: fence.effect_id.clone(),
                runtime_id: fence.runtime_id.clone(),
                claim_generation: fence.generation,
                fencing_token: fence.fencing_token.clone(),
                kind: kind.into(),
                checkpoint_digest: checkpoint_digest.into(),
                reason_code: reason_code.into(),
                request_id: request_id.into(),
            },
            false,
            true,
        )
        .await
    }

    pub async fn list_transform_work(
        &self,
        runtime_id: impl Into<String>,
        limit: i32,
    ) -> Result<Vec<crate::protocol::sekai::TransformWork>, RuntimeClaimError> {
        let namespace = self.namespace()?.to_string();
        let listed: ListClaimableTransformWorkResponse = self
            .list_unary(
                LIST_TRANSFORM,
                ListClaimableTransformWorkRequest {
                    namespace,
                    runtime_id: runtime_id.into(),
                    limit,
                },
            )
            .await?;
        Ok(listed.work)
    }

    pub async fn claim_transform_work(
        &self,
        runtime_id: impl Into<String>,
        run_id: impl Into<String>,
        ttl: Duration,
    ) -> Result<ClaimAttempt<ClaimTransformWorkResponse>, RuntimeClaimError> {
        let namespace = self.namespace()?.to_string();
        let run_id = run_id.into();
        match self
            .client
            .raw()
            .unary(
                CLAIM_TRANSFORM,
                ClaimTransformWorkRequest {
                    namespace,
                    runtime_id: runtime_id.into(),
                    run_id: run_id.clone(),
                    ttl_ms: duration_millis(ttl)?,
                },
                self.options(false),
            )
            .await
        {
            Ok(response) => Ok(ClaimAttempt::Claimed(response)),
            Err(error) => match RuntimeClaimError::from_transform_claim(error, &run_id)? {
                ClaimAttempt::Idle => Ok(ClaimAttempt::Idle),
                ClaimAttempt::Contended => Ok(ClaimAttempt::Contended),
                ClaimAttempt::Claimed(_) => unreachable!("infallible claim mapping"),
            },
        }
    }

    pub async fn heartbeat_transform(
        &self,
        fence: &TransformFence,
        ttl: Duration,
    ) -> Result<HeartbeatTransformClaimResponse, RuntimeClaimError> {
        self.unary(
            HEARTBEAT_TRANSFORM,
            HeartbeatTransformClaimRequest {
                run_id: fence.run_id.clone(),
                runtime_id: fence.runtime_id.clone(),
                claim_generation: fence.generation,
                fencing_token: fence.fencing_token.clone(),
                ttl_ms: duration_millis(ttl)?,
            },
            false,
            true,
        )
        .await
    }

    pub async fn read_transform_inputs(
        &self,
        fence: &TransformFence,
        alias: impl Into<String>,
        after_alias: impl Into<String>,
        after_row_id: i64,
        limit: i32,
    ) -> Result<TransformInputStream, RuntimeClaimError> {
        self.read_transform_input_page(
            fence,
            TransformRead {
                alias: alias.into(),
                after_alias: after_alias.into(),
                after_row_id,
                limit,
                partition_key: None,
                max_bytes: 0,
            },
        )
        .await
    }

    pub async fn read_transform_input_page(
        &self,
        fence: &TransformFence,
        read: TransformRead,
    ) -> Result<TransformInputStream, RuntimeClaimError> {
        let inner = self
            .client
            .raw()
            .server_streaming(
                READ_TRANSFORM,
                ReadTransformRunInputsRequest {
                    run_id: fence.run_id.clone(),
                    runtime_id: fence.runtime_id.clone(),
                    claim_generation: fence.generation,
                    fencing_token: fence.fencing_token.clone(),
                    alias: read.alias,
                    after_row_id: read.after_row_id,
                    limit: read.limit,
                    after_alias: read.after_alias,
                    partition_key: read.partition_key,
                    max_bytes: read.max_bytes,
                },
                self.options(false),
            )
            .await
            .map_err(|error| RuntimeClaimError::from_sdk(error, true))?;
        Ok(TransformInputStream { inner })
    }

    pub async fn write_transform_result(
        &self,
        fence: &TransformFence,
        write: TransformWrite,
    ) -> Result<WriteTransformRunResultResponse, RuntimeClaimError> {
        self.unary(
            WRITE_TRANSFORM,
            WriteTransformRunResultRequest {
                run_id: fence.run_id.clone(),
                runtime_id: fence.runtime_id.clone(),
                claim_generation: fence.generation,
                fencing_token: fence.fencing_token.clone(),
                rows: write.rows,
                output_digest: write.output_digest,
                quarantined: write.quarantined,
                quality_rule: write.quality_rule,
                partitions: write.partitions,
            },
            false,
            true,
        )
        .await
    }
}

fn duration_millis(duration: Duration) -> Result<i64, RuntimeClaimError> {
    let millis = i64::try_from(duration.as_millis())
        .map_err(|_| RuntimeClaimError::Invalid(SdkError::invalid_argument()))?;
    if millis <= 0 {
        return Err(RuntimeClaimError::Invalid(SdkError::invalid_argument()));
    }
    Ok(millis)
}

impl ActionFence {
    pub fn from_effect(
        effect: &crate::protocol::sekai::ActionEffect,
        runtime_id: impl Into<String>,
    ) -> Self {
        Self {
            effect_id: effect.effect_id.clone(),
            runtime_id: runtime_id.into(),
            generation: effect.claim_generation,
            fencing_token: effect.claim_fencing_token.clone(),
        }
    }
}

impl TransformFence {
    pub fn from_work(
        work: &crate::protocol::sekai::TransformWork,
        runtime_id: impl Into<String>,
    ) -> Self {
        Self {
            run_id: work.run_id.clone(),
            runtime_id: runtime_id.into(),
            generation: work.claim_generation,
            fencing_token: work.fencing_token.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_failed_precondition_is_fence_lost_not_idle_or_contention() {
        let error =
            RuntimeClaimError::from_sdk(SdkError::new(SdkErrorCode::FailedPrecondition), true);
        assert!(matches!(error, RuntimeClaimError::FenceLost), "{error}");
        assert_eq!(error.to_string(), "claim fence was lost");
    }

    #[test]
    fn initial_failed_precondition_is_contention() {
        let mapped =
            RuntimeClaimError::from_action_claim(SdkError::new(SdkErrorCode::FailedPrecondition))
                .expect("contention is a claim attempt");
        assert!(matches!(mapped, ClaimAttempt::Contended));
    }

    fn sdk_with_reason(code: SdkErrorCode, reason: &'static str) -> SdkError {
        let mut error = SdkError::new(code);
        error.reason_code = Some(reason);
        error
    }

    #[test]
    fn claim_delegator_refusal_is_not_contention() {
        let error = RuntimeClaimError::from_action_claim(sdk_with_reason(
            SdkErrorCode::FailedPrecondition,
            DELEGATOR_DISABLED,
        ))
        .expect_err("delegator refusal is not a claim attempt");
        assert!(
            matches!(
                error,
                RuntimeClaimError::DelegatorRefused(DELEGATOR_DISABLED)
            ),
            "{error}"
        );
        assert_eq!(error.to_string(), "delegator refused: delegator_disabled");
    }

    #[test]
    fn ack_delegator_refusal_is_not_fence_lost() {
        let error = RuntimeClaimError::from_sdk(
            sdk_with_reason(SdkErrorCode::FailedPrecondition, DELEGATOR_NOT_MEMBER),
            true,
        );
        assert!(
            matches!(
                error,
                RuntimeClaimError::DelegatorRefused(DELEGATOR_NOT_MEMBER)
            ),
            "{error}"
        );
    }

    #[test]
    fn allowlisted_reason_codes_are_the_identity_tokens() {
        assert_eq!(
            allowlisted_reason_code("delegator_grant_missing"),
            Some(DELEGATOR_GRANT_MISSING)
        );
        assert_eq!(allowlisted_reason_code("already claimed"), None);
        assert_eq!(
            allowlisted_reason_code(" delegator_disabled "),
            Some(DELEGATOR_DISABLED)
        );
    }

    #[test]
    fn transform_not_found_is_idle_not_fence_lost() {
        let mapped =
            RuntimeClaimError::from_transform_claim(SdkError::new(SdkErrorCode::NotFound), "")
                .expect("idle is a claim attempt");
        assert!(matches!(mapped, ClaimAttempt::Idle));
    }

    #[test]
    fn targeted_transform_not_found_is_contention() {
        let mapped =
            RuntimeClaimError::from_transform_claim(SdkError::new(SdkErrorCode::NotFound), "run-1")
                .expect("targeted miss is contention");
        assert!(matches!(mapped, ClaimAttempt::Contended));
    }

    #[test]
    fn held_stream_failed_precondition_is_fence_lost() {
        let error =
            RuntimeClaimError::from_held_stream(SdkError::new(SdkErrorCode::FailedPrecondition));
        assert!(matches!(error, RuntimeClaimError::FenceLost), "{error}");
    }

    #[test]
    fn action_not_found_is_not_idle() {
        let error = RuntimeClaimError::from_action_claim(SdkError::new(SdkErrorCode::NotFound))
            .unwrap_err();
        assert!(
            matches!(error, RuntimeClaimError::Transport(_)),
            "missing Action effect is not an empty queue: {error}"
        );
    }

    #[test]
    fn list_failed_precondition_is_unavailable_not_contention() {
        let error = RuntimeClaimError::from_list(SdkError::new(SdkErrorCode::FailedPrecondition));
        assert!(
            matches!(error, RuntimeClaimError::Unavailable(_)),
            "list experimental-gate is not contention: {error}"
        );
    }

    #[test]
    fn denial_and_unavailability_stay_distinct() {
        assert!(matches!(
            RuntimeClaimError::from_sdk(SdkError::new(SdkErrorCode::PermissionDenied), true),
            RuntimeClaimError::Denied(_)
        ));
        assert!(matches!(
            RuntimeClaimError::from_sdk(SdkError::new(SdkErrorCode::Unauthenticated), false),
            RuntimeClaimError::Denied(_)
        ));
        assert!(matches!(
            RuntimeClaimError::from_sdk(SdkError::new(SdkErrorCode::Unavailable), true),
            RuntimeClaimError::Unavailable(_)
        ));
    }

    #[test]
    fn zero_ttl_is_invalid() {
        let error = duration_millis(Duration::from_millis(0)).unwrap_err();
        assert!(matches!(error, RuntimeClaimError::Invalid(_)));
    }
}
