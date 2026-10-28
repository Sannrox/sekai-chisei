//! Agent-turn RPCs (ADR 0137, #1950). A manual wake needs administration of
//! the instance's namespace; workers list, claim, heartbeat and acknowledge
//! with the same authority as isolated transform work.

use super::*;
use crate::sekai::agent_turn::{self, Cause, Outcome, TurnError, Wake};

fn turn_status(error: TurnError) -> Status {
    let message = error.to_string();
    match error {
        TurnError::NotFound => Status::not_found(message),
        TurnError::Frozen(_) | TurnError::NotClaimable | TurnError::StaleClaim => {
            Status::failed_precondition(message)
        }
        TurnError::Invalid(_) => Status::invalid_argument(message),
        TurnError::Internal(_) => Status::internal(message),
    }
}

fn to_proto(turn: agent_turn::AgentTurn) -> AgentTurn {
    AgentTurn {
        turn_id: turn.turn_id,
        namespace: turn.namespace,
        instance_id: turn.instance_id,
        principal_id: turn.principal_id,
        cause: turn.cause.as_str().into(),
        cause_ref: turn.cause_ref,
        due_at_ms: turn.due_at_ms,
        admitted_by: turn.admitted_by,
        status: turn.status,
        claim_owner: turn.claim_owner,
        claim_generation: turn.claim_generation,
        fencing_token: turn.fencing_token,
        claim_expires_at_ms: turn.claim_expires_at_ms,
        created_at_ms: turn.created_at_ms,
        finished_at_ms: turn.finished_at_ms,
        reason: turn.reason,
    }
}

/// What a worker call names: a namespace, or one turn in it.
enum Scope<'a> {
    Namespace(&'a str),
    Turn(&'a str),
}

impl SekaiServiceImpl {
    /// Worker authority over `namespace`, as for isolated transform claims,
    /// including the caller's tenant context.
    /// A fenced call names only its turn, whose namespace is read after the
    /// caller is known to be a worker.
    fn authorize_turn_worker<T: 'static>(
        &self,
        req: &Request<T>,
        scope: Scope<'_>,
    ) -> Result<(), Status> {
        let principals = caller_principals(req);
        require_authenticated(&principals)?;
        require_credential_admin(&principals)?;
        let namespace = match scope {
            Scope::Namespace(namespace) => namespace.to_string(),
            Scope::Turn(turn_id) => agent_turn::get(self.db.runtime(), turn_id)
                .map_err(turn_status)?
                .map(|turn| turn.namespace)
                .ok_or_else(|| turn_status(TurnError::NotFound))?,
        };
        check_team_namespace(self.db.runtime(), &principals, &namespace, true)?;
        if let Some(context) = request_tenant_context(self.db.runtime(), req)?.as_ref() {
            enforce_namespace_tenant_context(self.db.runtime(), Some(context), &namespace, true)?;
        }
        Ok(())
    }

    pub(super) async fn wake_site_agent_instance_rpc(
        &self,
        req: Request<WakeSiteAgentInstanceRequest>,
    ) -> Result<Response<WakeSiteAgentInstanceResponse>, Status> {
        let namespace = req.get_ref().namespace.clone();
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &namespace,
            true,
        )?;
        let actor = authorize_source_type_namespace_admin(self, &principals, &namespace)?;
        let inner = req.into_inner();
        let now = now_millis();
        let turn = agent_turn::admit(
            self.db.runtime(),
            Wake {
                namespace: inner.namespace,
                instance_id: inner.instance_id,
                cause: Cause::Manual,
                cause_ref: inner.request_id,
                due_at_ms: now,
            },
            &actor,
            now,
        )
        .map_err(turn_status)?;
        Ok(Response::new(WakeSiteAgentInstanceResponse {
            turn: Some(to_proto(turn)),
        }))
    }

    pub(super) async fn list_claimable_agent_turns_rpc(
        &self,
        req: Request<ListClaimableAgentTurnsRequest>,
    ) -> Result<Response<ListClaimableAgentTurnsResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::Namespace(&req.get_ref().namespace))?;
        let inner = req.into_inner();
        let turns = agent_turn::list_claimable(
            self.db.runtime(),
            &inner.namespace,
            now_millis(),
            i64::from(inner.limit),
        )
        .map_err(turn_status)?;
        Ok(Response::new(ListClaimableAgentTurnsResponse {
            turns: turns.into_iter().map(to_proto).collect(),
        }))
    }

    pub(super) async fn claim_agent_turn_rpc(
        &self,
        req: Request<ClaimAgentTurnRequest>,
    ) -> Result<Response<ClaimAgentTurnResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::Namespace(&req.get_ref().namespace))?;
        let inner = req.into_inner();
        let turn = agent_turn::claim(
            self.db.runtime(),
            &inner.namespace,
            &inner.runtime_id,
            &inner.turn_id,
            inner.ttl_ms,
            now_millis(),
        )
        .map_err(turn_status)?;
        Ok(Response::new(ClaimAgentTurnResponse {
            turn: Some(to_proto(turn)),
        }))
    }

    pub(super) async fn heartbeat_agent_turn_claim_rpc(
        &self,
        req: Request<HeartbeatAgentTurnClaimRequest>,
    ) -> Result<Response<HeartbeatAgentTurnClaimResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::Turn(&req.get_ref().turn_id))?;
        let inner = req.into_inner();
        let turn = agent_turn::heartbeat(
            self.db.runtime(),
            &inner.turn_id,
            &inner.runtime_id,
            inner.claim_generation,
            &inner.fencing_token,
            inner.ttl_ms,
            now_millis(),
        )
        .map_err(turn_status)?;
        Ok(Response::new(HeartbeatAgentTurnClaimResponse {
            turn: Some(to_proto(turn)),
        }))
    }

    pub(super) async fn ack_agent_turn_rpc(
        &self,
        req: Request<AckAgentTurnRequest>,
    ) -> Result<Response<AckAgentTurnResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::Turn(&req.get_ref().turn_id))?;
        let inner = req.into_inner();
        let outcome = match inner.outcome.as_str() {
            "completed" => Outcome::Completed,
            "failed" => Outcome::Failed,
            _ => {
                return Err(Status::invalid_argument(
                    "outcome must be completed or failed",
                ));
            }
        };
        let turn = agent_turn::acknowledge(
            self.db.runtime(),
            &inner.turn_id,
            &inner.runtime_id,
            inner.claim_generation,
            &inner.fencing_token,
            outcome,
            &inner.reason,
            now_millis(),
        )
        .map_err(turn_status)?;
        Ok(Response::new(AckAgentTurnResponse {
            turn: Some(to_proto(turn)),
        }))
    }
}
