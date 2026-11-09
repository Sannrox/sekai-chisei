//! The one claimable-work RPC family (ADR 0149): `ListClaimableWork`,
//! `ClaimWork`, `HeartbeatWorkClaim` and `AckWork`. Each call names a kind
//! and runs that kind's own RPC path, with its authorization, runtime-token
//! binding and claim engine, so a claim taken through either family is the
//! same claim to both. Export delivery has no claim RPCs of its own: it
//! runs the saved-export delivery checks, and its deprecated list, fetch
//! and acknowledge honor the claims taken here. Source sync has none
//! either; it names its namespace on every call, since a Source id is only
//! unique inside one.

use super::*;
use crate::runtime_token::RuntimeTokenClaims;
use crate::sekai::work_claim::{Fence, WorkKind as Kind};

impl SekaiServiceImpl {
    pub(super) async fn list_claimable_work_rpc(
        &self,
        req: Request<ListClaimableWorkRequest>,
    ) -> Result<Response<ListClaimableWorkResponse>, Status> {
        let kind = admitted_kind(&req, req.get_ref().kind)?;
        let (metadata, extensions, inner) = req.into_parts();
        let turn = inner.options.map(|options| match options {
            list_claimable_work_request::Options::AgentTurn(turn) => turn,
        });
        let payloads: Vec<claimable_work::Payload> = match kind {
            Kind::Transform => {
                refuse_turn_options(turn)?;
                let body = ListClaimableTransformWorkRequest {
                    namespace: inner.namespace,
                    runtime_id: inner.runtime_id,
                    limit: inner.limit,
                };
                rpc_data::list_claimable_transform_work(
                    self,
                    Request::from_parts(metadata, extensions, body),
                )
                .await?
                .into_inner()
                .work
                .into_iter()
                .map(claimable_work::Payload::Transform)
                .collect()
            }
            Kind::Action => {
                refuse_turn_options(turn)?;
                let body = ListClaimableActionWorkRequest {
                    namespace: inner.namespace,
                    runtime_id: inner.runtime_id,
                    limit: u32::try_from(inner.limit)
                        .map_err(|_| Status::invalid_argument("limit must not be negative"))?,
                };
                rpc_actions::list_claimable_action_work(
                    self,
                    Request::from_parts(metadata, extensions, body),
                )
                .await?
                .into_inner()
                .effects
                .into_iter()
                .map(claimable_work::Payload::Action)
                .collect()
            }
            Kind::AgentTurn => {
                let body = ListClaimableAgentTurnsRequest {
                    namespace: inner.namespace,
                    limit: inner.limit,
                    accepts_continuation: turn.is_some_and(|turn| turn.accepts_continuation),
                };
                self.list_claimable_agent_turns_rpc(Request::from_parts(metadata, extensions, body))
                    .await?
                    .into_inner()
                    .turns
                    .into_iter()
                    .map(claimable_work::Payload::AgentTurn)
                    .collect()
            }
            Kind::ExportDelivery => {
                refuse_turn_options(turn)?;
                let req = Request::from_parts(metadata, extensions, ());
                self.list_claimable_export_deliveries(&req, &inner.namespace, inner.limit)?
                    .into_iter()
                    .map(claimable_work::Payload::ExportDelivery)
                    .collect()
            }
            Kind::SourceSync => {
                refuse_turn_options(turn)?;
                let req = Request::from_parts(metadata, extensions, ());
                self.list_claimable_source_syncs(
                    &req,
                    &inner.namespace,
                    &inner.runtime_id,
                    inner.limit,
                )?
                .into_iter()
                .map(claimable_work::Payload::SourceSync)
                .collect()
            }
            _ => return Err(unserved(kind)),
        };
        Ok(Response::new(ListClaimableWorkResponse {
            work: payloads
                .into_iter()
                .map(|payload| ClaimableWork {
                    payload: Some(payload),
                })
                .collect(),
        }))
    }

    pub(super) async fn claim_work_rpc(
        &self,
        req: Request<ClaimWorkRequest>,
    ) -> Result<Response<ClaimWorkResponse>, Status> {
        let kind = admitted_kind(&req, req.get_ref().kind)?;
        let (metadata, extensions, inner) = req.into_parts();
        let turn = inner.options.map(|options| match options {
            claim_work_request::Options::AgentTurn(turn) => turn,
        });
        let payload = match kind {
            Kind::Transform => {
                refuse_turn_options(turn)?;
                refuse_request_id(&inner.request_id)?;
                let body = ClaimTransformWorkRequest {
                    namespace: inner.namespace,
                    runtime_id: inner.runtime_id,
                    run_id: inner.work_id,
                    ttl_ms: inner.ttl_ms,
                };
                claim_work_response::Payload::Transform(
                    rpc_data::claim_transform_work(
                        self,
                        Request::from_parts(metadata, extensions, body),
                    )
                    .await?
                    .into_inner(),
                )
            }
            Kind::Action => {
                refuse_turn_options(turn)?;
                let body = ClaimActionWorkRequest {
                    effect_id: inner.work_id,
                    runtime_id: inner.runtime_id,
                    request_id: inner.request_id,
                    ttl_ms: inner.ttl_ms,
                };
                claim_work_response::Payload::Action(
                    rpc_actions::claim_action_work(
                        self,
                        Request::from_parts(metadata, extensions, body),
                    )
                    .await?
                    .into_inner(),
                )
            }
            Kind::AgentTurn => {
                refuse_request_id(&inner.request_id)?;
                let body = ClaimAgentTurnRequest {
                    namespace: inner.namespace,
                    runtime_id: inner.runtime_id,
                    turn_id: inner.work_id,
                    ttl_ms: inner.ttl_ms,
                    accepts_continuation: turn.is_some_and(|turn| turn.accepts_continuation),
                };
                claim_work_response::Payload::AgentTurn(
                    self.claim_agent_turn_rpc(Request::from_parts(metadata, extensions, body))
                        .await?
                        .into_inner(),
                )
            }
            Kind::ExportDelivery => {
                refuse_turn_options(turn)?;
                refuse_request_id(&inner.request_id)?;
                let req = Request::from_parts(metadata, extensions, ());
                claim_work_response::Payload::ExportDelivery(self.claim_export_delivery(
                    &req,
                    &inner.namespace,
                    &inner.runtime_id,
                    &inner.work_id,
                    inner.ttl_ms,
                )?)
            }
            Kind::SourceSync => {
                refuse_turn_options(turn)?;
                refuse_request_id(&inner.request_id)?;
                let req = Request::from_parts(metadata, extensions, ());
                claim_work_response::Payload::SourceSync(self.claim_source_sync(
                    &req,
                    &inner.namespace,
                    &inner.runtime_id,
                    &inner.work_id,
                    inner.ttl_ms,
                )?)
            }
            _ => return Err(unserved(kind)),
        };
        Ok(Response::new(ClaimWorkResponse {
            payload: Some(payload),
        }))
    }

    pub(super) async fn heartbeat_work_claim_rpc(
        &self,
        req: Request<HeartbeatWorkClaimRequest>,
    ) -> Result<Response<HeartbeatWorkClaimResponse>, Status> {
        let kind = admitted_kind(&req, req.get_ref().kind)?;
        let (metadata, extensions, inner) = req.into_parts();
        let payload = match kind {
            Kind::Transform => {
                let body = HeartbeatTransformClaimRequest {
                    run_id: inner.work_id,
                    runtime_id: inner.runtime_id,
                    claim_generation: inner.claim_generation,
                    fencing_token: inner.fencing_token,
                    ttl_ms: inner.ttl_ms,
                };
                heartbeat_work_claim_response::Payload::Transform(
                    rpc_data::heartbeat_transform_claim(
                        self,
                        Request::from_parts(metadata, extensions, body),
                    )
                    .await?
                    .into_inner(),
                )
            }
            Kind::Action => {
                let body = HeartbeatActionClaimRequest {
                    effect_id: inner.work_id,
                    runtime_id: inner.runtime_id,
                    claim_generation: action_generation(inner.claim_generation)?,
                    fencing_token: inner.fencing_token,
                    ttl_ms: inner.ttl_ms,
                };
                heartbeat_work_claim_response::Payload::Action(
                    rpc_actions::heartbeat_action_claim(
                        self,
                        Request::from_parts(metadata, extensions, body),
                    )
                    .await?
                    .into_inner(),
                )
            }
            Kind::AgentTurn => {
                let body = HeartbeatAgentTurnClaimRequest {
                    turn_id: inner.work_id,
                    runtime_id: inner.runtime_id,
                    claim_generation: inner.claim_generation,
                    fencing_token: inner.fencing_token,
                    ttl_ms: inner.ttl_ms,
                };
                heartbeat_work_claim_response::Payload::AgentTurn(
                    self.heartbeat_agent_turn_claim_rpc(Request::from_parts(
                        metadata, extensions, body,
                    ))
                    .await?
                    .into_inner(),
                )
            }
            Kind::ExportDelivery => {
                let req = Request::from_parts(metadata, extensions, ());
                let fence = Fence {
                    owner: &inner.runtime_id,
                    generation: inner.claim_generation,
                    token: &inner.fencing_token,
                };
                heartbeat_work_claim_response::Payload::ExportDelivery(
                    self.heartbeat_export_delivery(&req, &inner.work_id, fence, inner.ttl_ms)?,
                )
            }
            Kind::SourceSync => {
                let req = Request::from_parts(metadata, extensions, ());
                let fence = Fence {
                    owner: &inner.runtime_id,
                    generation: inner.claim_generation,
                    token: &inner.fencing_token,
                };
                heartbeat_work_claim_response::Payload::SourceSync(self.heartbeat_source_sync(
                    &req,
                    &inner.namespace,
                    &inner.work_id,
                    fence,
                    inner.ttl_ms,
                )?)
            }
            _ => return Err(unserved(kind)),
        };
        Ok(Response::new(HeartbeatWorkClaimResponse {
            payload: Some(payload),
        }))
    }

    pub(super) async fn ack_work_rpc(
        &self,
        req: Request<AckWorkRequest>,
    ) -> Result<Response<AckWorkResponse>, Status> {
        let kind = admitted_kind(&req, req.get_ref().kind)?;
        let (metadata, extensions, inner) = req.into_parts();
        let mismatched = || Status::invalid_argument("options do not match the work kind");
        let payload = match kind {
            Kind::Transform => {
                return Err(Status::invalid_argument(
                    "transform work is acknowledged by WriteTransformRunResult",
                ));
            }
            Kind::Action => {
                let options = match inner.options {
                    None => ActionAckOptions::default(),
                    Some(ack_work_request::Options::Action(options)) => options,
                    Some(_) => return Err(mismatched()),
                };
                let body = AckActionWorkRequest {
                    effect_id: inner.work_id,
                    runtime_id: inner.runtime_id,
                    claim_generation: action_generation(inner.claim_generation)?,
                    fencing_token: inner.fencing_token,
                    outcome: inner.outcome,
                    reason: inner.reason,
                    request_id: options.request_id,
                    checkpoint_store_id: options.checkpoint_store_id,
                    checkpoint_ref: options.checkpoint_ref,
                    checkpoint_digest: options.checkpoint_digest,
                    artifact_json: options.artifact_json,
                };
                ack_work_response::Payload::Action(
                    rpc_actions::ack_action_work(
                        self,
                        Request::from_parts(metadata, extensions, body),
                    )
                    .await?
                    .into_inner(),
                )
            }
            Kind::AgentTurn => {
                let options = match inner.options {
                    None => AgentTurnAckOptions::default(),
                    Some(ack_work_request::Options::AgentTurn(options)) => options,
                    Some(_) => return Err(mismatched()),
                };
                let body = AckAgentTurnRequest {
                    turn_id: inner.work_id,
                    runtime_id: inner.runtime_id,
                    claim_generation: inner.claim_generation,
                    fencing_token: inner.fencing_token,
                    outcome: inner.outcome,
                    reason: inner.reason,
                    parked_action_instance_id: options.parked_action_instance_id,
                };
                ack_work_response::Payload::AgentTurn(
                    self.ack_agent_turn_rpc(Request::from_parts(metadata, extensions, body))
                        .await?
                        .into_inner(),
                )
            }
            Kind::ExportDelivery => {
                let Some(ack_work_request::Options::ExportDelivery(options)) = inner.options else {
                    return Err(Status::invalid_argument(
                        "export delivery needs ExportDeliveryAckOptions with the digest",
                    ));
                };
                if inner.outcome != "completed" {
                    return Err(Status::invalid_argument(
                        "export delivery is acknowledged as completed",
                    ));
                }
                let req = Request::from_parts(metadata, extensions, ());
                let fence = Fence {
                    owner: &inner.runtime_id,
                    generation: inner.claim_generation,
                    token: &inner.fencing_token,
                };
                ack_work_response::Payload::ExportDelivery(self.ack_export_delivery(
                    &req,
                    &inner.work_id,
                    fence,
                    &options.content_digest,
                )?)
            }
            Kind::SourceSync => {
                if inner.options.is_some() {
                    return Err(mismatched());
                }
                let req = Request::from_parts(metadata, extensions, ());
                let fence = Fence {
                    owner: &inner.runtime_id,
                    generation: inner.claim_generation,
                    token: &inner.fencing_token,
                };
                ack_work_response::Payload::SourceSync(self.ack_source_sync(
                    &req,
                    &inner.namespace,
                    &inner.work_id,
                    fence,
                    &inner.outcome,
                    &inner.reason,
                )?)
            }
            _ => return Err(unserved(kind)),
        };
        Ok(Response::new(AckWorkResponse {
            payload: Some(payload),
        }))
    }
}

/// The request's kind, once the call passes the checks the kind's own RPC
/// gets at the boundary: a runtime token is bound to one claim of one kind,
/// and transform RPCs are not open to enterprise-scoped credentials.
fn admitted_kind<T>(req: &Request<T>, raw: i32) -> Result<Kind, Status> {
    let kind = match WorkKind::try_from(raw) {
        Ok(WorkKind::Transform) => Kind::Transform,
        Ok(WorkKind::Action) => Kind::Action,
        Ok(WorkKind::AgentTurn) => Kind::AgentTurn,
        Ok(WorkKind::ExportDelivery) => Kind::ExportDelivery,
        Ok(WorkKind::SourceSync) => Kind::SourceSync,
        Ok(WorkKind::Unspecified) | Err(_) => {
            return Err(Status::invalid_argument(
                "kind must be transform, action, agent_turn, export_delivery or source_sync",
            ));
        }
    };
    if let Some(claims) = req.extensions().get::<RuntimeTokenClaims>() {
        let bound = match kind {
            Kind::Action => !claims.is_turn(),
            Kind::AgentTurn => claims.is_turn(),
            _ => false,
        };
        if !bound {
            return Err(Status::permission_denied(
                "runtime token admits only calls for its claimed work",
            ));
        }
    }
    let enterprise_scoped = req
        .metadata()
        .get(crate::grpc::AUTH_SOURCE_HEADER)
        .is_some_and(|source| source == "enterprise");
    if matches!(kind, Kind::Transform | Kind::SourceSync) && enterprise_scoped {
        return Err(Status::permission_denied(
            "RPC is not available to enterprise-scoped credentials",
        ));
    }
    Ok(kind)
}

fn unserved(kind: Kind) -> Status {
    Status::unimplemented(format!("work kind {kind} is not served here"))
}

fn refuse_turn_options(options: Option<AgentTurnWorkOptions>) -> Result<(), Status> {
    match options {
        Some(_) => Err(Status::invalid_argument(
            "options do not match the work kind",
        )),
        None => Ok(()),
    }
}

fn refuse_request_id(request_id: &str) -> Result<(), Status> {
    if request_id.is_empty() {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "request_id is for action work only",
        ))
    }
}

/// Action claims count generations unsigned on their own wire.
fn action_generation(generation: i64) -> Result<u64, Status> {
    u64::try_from(generation)
        .map_err(|_| Status::invalid_argument("claim_generation must not be negative"))
}
