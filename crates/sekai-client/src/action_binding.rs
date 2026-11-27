//! Typed Action binding calls (ADR 0090, `sekai.action-binding/v1`, #3036).
//!
//! A binding travels as its `sekai.action-binding/v1` JSON; the plane
//! validates it, so this client never parses or rewrites it.

use crate::protocol::sekai::{
    ActionBindingRecord, GetActionBindingRequest, GetActionBindingResponse,
    ListActionBindingHistoryRequest, ListActionBindingHistoryResponse, ListActionBindingsRequest,
    ListActionBindingsResponse, PutActionBindingRequest, PutActionBindingResponse,
    RunActionBindingRequest, RunActionBindingResponse,
};
use crate::{CallOptions, CoreLoopClient, GrpcTransport, SdkError, SdkErrorCode};

const PUT: &str = "/sekai.SekaiService/PutActionBinding";
const GET: &str = "/sekai.SekaiService/GetActionBinding";
const LIST: &str = "/sekai.SekaiService/ListActionBindings";
const HISTORY: &str = "/sekai.SekaiService/ListActionBindingHistory";
const RUN: &str = "/sekai.SekaiService/RunActionBinding";

/// Install, read, and run Action bindings over the native transport.
pub struct ActionBindingClient<'a> {
    client: &'a CoreLoopClient<GrpcTransport>,
}

impl CoreLoopClient<GrpcTransport> {
    /// Action binding calls; use as `client.action_bindings().get(..)`.
    pub fn action_bindings(&self) -> ActionBindingClient<'_> {
        ActionBindingClient { client: self }
    }
}

impl ActionBindingClient<'_> {
    /// Installs or replaces a binding; the stored binding comes back with its
    /// new revision. Not retried: a replay of a changed binding is a new
    /// revision.
    pub async fn put(
        &self,
        binding_json: impl Into<String>,
    ) -> Result<ActionBindingRecord, SdkError> {
        let PutActionBindingResponse {
            binding_json,
            revision,
        } = self
            .call(
                PUT,
                PutActionBindingRequest {
                    binding_json: binding_json.into(),
                },
                false,
            )
            .await?;
        Ok(ActionBindingRecord {
            binding_json,
            revision,
        })
    }

    /// The binding, or `None` when it is missing or the caller may not read
    /// it; the plane does not tell the two apart.
    pub async fn get(
        &self,
        namespace: impl Into<String>,
        binding_id: impl Into<String>,
    ) -> Result<Option<ActionBindingRecord>, SdkError> {
        let request = GetActionBindingRequest {
            namespace: namespace.into(),
            binding_id: binding_id.into(),
        };
        match self
            .call::<_, GetActionBindingResponse>(GET, request, true)
            .await
        {
            Ok(response) => Ok(response.binding),
            Err(error) if error.code == SdkErrorCode::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// One page of the namespace's bindings the caller may read, by
    /// binding id. Pass the previous `next_page_token`, or empty to start.
    pub async fn list(
        &self,
        namespace: impl Into<String>,
        page_size: u32,
        page_token: impl Into<String>,
    ) -> Result<ListActionBindingsResponse, SdkError> {
        let page_size = i32::try_from(page_size).map_err(|_| SdkError::invalid_argument())?;
        self.call(
            LIST,
            ListActionBindingsRequest {
                namespace: namespace.into(),
                page_size,
                page_token: page_token.into(),
            },
            true,
        )
        .await
    }

    /// One page of a binding's run history, newest first. Does not advance
    /// the cursor. Pass the previous `next_page_token`, or empty to start.
    pub async fn history(
        &self,
        namespace: impl Into<String>,
        binding_id: impl Into<String>,
        page_size: u32,
        page_token: impl Into<String>,
    ) -> Result<ListActionBindingHistoryResponse, SdkError> {
        let page_size = i32::try_from(page_size).map_err(|_| SdkError::invalid_argument())?;
        self.call(
            HISTORY,
            ListActionBindingHistoryRequest {
                namespace: namespace.into(),
                binding_id: binding_id.into(),
                page_size,
                page_token: page_token.into(),
            },
            true,
        )
        .await
    }

    /// Runs an object-change or dataset-commit binding once over at most
    /// `limit` events. Retrying is safe: event-derived idempotency keys make
    /// a resubmit a replay.
    pub async fn run(
        &self,
        namespace: impl Into<String>,
        binding_id: impl Into<String>,
        limit: u32,
    ) -> Result<RunActionBindingResponse, SdkError> {
        let limit = i32::try_from(limit).map_err(|_| SdkError::invalid_argument())?;
        self.call(
            RUN,
            RunActionBindingRequest {
                namespace: namespace.into(),
                binding_id: binding_id.into(),
                limit,
            },
            true,
        )
        .await
    }

    async fn call<Req, Resp>(
        &self,
        path: &str,
        request: Req,
        retryable: bool,
    ) -> Result<Resp, SdkError>
    where
        Req: prost::Message + Default + Clone + Send + 'static,
        Resp: prost::Message + Default + Send + 'static,
    {
        let mut options = CallOptions::new().retryable(retryable);
        if let Some(namespace) = self.client.config().namespace.clone() {
            options = options.with_namespace(namespace);
        }
        self.client.raw().unary(path, request, options).await
    }
}
