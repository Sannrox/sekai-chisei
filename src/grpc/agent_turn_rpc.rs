//! Agent-turn RPCs (ADR 0137, #1950). A manual wake needs administration of
//! the instance's namespace; workers list, claim, heartbeat and acknowledge
//! as credential admin or as a service principal registered as a turn
//! worker, and a claim's runtime token acts for its turn (ADR 0142).

use super::*;
use crate::runtime_token::RuntimeTokenClaims;
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
        parked_action_instance_id: turn.parked_action_id,
        park_count: turn.park_count,
    }
}

/// What a claim of a turn that parked resumes from: its Action as decided
/// (ADR 0142). `None` for a turn that never parked.
fn continuation_for(
    db: &RuntimeDb,
    turn: &agent_turn::AgentTurn,
) -> Result<Option<AgentTurnContinuation>, Status> {
    if turn.parked_action_id.is_empty() {
        return Ok(None);
    }
    let action = db
        .get_action_instance(&turn.parked_action_id)
        .map_err(Status::internal)?;
    Ok(Some(AgentTurnContinuation {
        action_instance_id: turn.parked_action_id.clone(),
        status: action
            .as_ref()
            .map_or_else(|| "missing".to_string(), |action| action.status.clone()),
        approval_decision: action
            .as_ref()
            .map(|action| action.approval_decision.clone())
            .unwrap_or_default(),
        deny_reason: action.map(|action| action.deny_reason).unwrap_or_default(),
    }))
}

fn entry_to_proto(entry: agent_turn::InstanceEntry) -> AgentTurn {
    match entry {
        agent_turn::InstanceEntry::Turn(turn) => {
            let mut turn = to_proto(turn);
            // Operator history is a read of the instance, not a claim.
            turn.fencing_token.clear();
            turn
        }
        agent_turn::InstanceEntry::RefusedWake {
            turn_id,
            namespace,
            instance_id,
            principal_id,
            cause,
            cause_ref,
            refused_at_ms,
            refused_by,
            reason,
        } => AgentTurn {
            turn_id,
            namespace,
            instance_id,
            principal_id,
            cause,
            cause_ref,
            due_at_ms: 0,
            admitted_by: refused_by,
            status: "refused".into(),
            claim_owner: String::new(),
            claim_generation: 0,
            fencing_token: String::new(),
            claim_expires_at_ms: 0,
            created_at_ms: refused_at_ms,
            finished_at_ms: refused_at_ms,
            reason,
            parked_action_instance_id: String::new(),
            park_count: 0,
        },
    }
}

/// What a worker call names: a namespace, or one turn in it. An ack may
/// also name a turn it already acknowledged, so a lost response is retried.
enum Scope<'a> {
    Namespace(&'a str),
    Turn(&'a str),
    AckedTurn(&'a str),
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
        // A turn token is its own authority, for its turn's live claim only.
        if let Some(claims) = req.extensions().get::<RuntimeTokenClaims>() {
            let (turn_id, acked) = match scope {
                Scope::Turn(turn_id) => (turn_id, false),
                Scope::AckedTurn(turn_id) => (turn_id, true),
                Scope::Namespace(_) => {
                    return Err(Status::permission_denied(
                        "runtime token admits only calls for its claimed turn",
                    ));
                }
            };
            let turn = agent_turn::get(self.db.runtime(), turn_id)
                .map_err(turn_status)?
                .ok_or_else(|| turn_status(TurnError::NotFound))?;
            // The store replays the same fence and outcome, or refuses.
            if acked && turn.is_acknowledged() {
                return self.authorize_acked_turn_token(req, claims, &turn);
            }
            return self.authorize_turn_token(req, claims, &turn);
        }
        let principals = caller_principals(req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), req)?;
        // A registered turn worker (ADR 0142), or credential admin. The
        // tenant check below keeps a service principal to its namespaces.
        let turn_worker = service_principal_scope(self.db.runtime(), tenant_context.as_ref())?
            .is_some_and(|scope| {
                scope.has_capability(crate::sekai::service_principal::AGENT_TURN_WORKER)
            });
        if !turn_worker {
            require_credential_admin(&principals)?;
        }
        let namespace = match scope {
            Scope::Namespace(namespace) => namespace.to_string(),
            Scope::Turn(turn_id) | Scope::AckedTurn(turn_id) => {
                agent_turn::get(self.db.runtime(), turn_id)
                    .map_err(turn_status)?
                    .map(|turn| turn.namespace)
                    .ok_or_else(|| turn_status(TurnError::NotFound))?
            }
        };
        check_team_namespace(self.db.runtime(), &principals, &namespace, true)?;
        if let Some(context) = tenant_context.as_ref() {
            enforce_namespace_tenant_context(self.db.runtime(), Some(context), &namespace, true)?;
        }
        Ok(())
    }

    /// A turn token covers `turn` while the turn is claimed at the token's
    /// generation by its runtime, under the token's tenant (ADR 0142).
    fn authorize_turn_token<T: 'static>(
        &self,
        req: &Request<T>,
        claims: &RuntimeTokenClaims,
        turn: &agent_turn::AgentTurn,
    ) -> Result<(), Status> {
        let live = turn.is_live_claim(now_millis())
            && u64::try_from(turn.claim_generation).ok() == Some(claims.claim_generation)
            && turn.principal_id == claims.subject
            && claims.covers_turn(
                &turn.namespace,
                &turn.turn_id,
                &turn.claim_owner,
                claims.claim_generation,
            );
        if !live {
            return Err(Status::permission_denied(
                "runtime token does not cover this turn's claim",
            ));
        }
        enforce_namespace_tenant_context(
            self.db.runtime(),
            request_tenant_context(self.db.runtime(), req)?.as_ref(),
            &turn.namespace,
            true,
        )
    }

    /// A turn token retrying the ack of a turn it acknowledged: the turn was
    /// last claimed at the token's generation by its runtime.
    fn authorize_acked_turn_token<T: 'static>(
        &self,
        req: &Request<T>,
        claims: &RuntimeTokenClaims,
        turn: &agent_turn::AgentTurn,
    ) -> Result<(), Status> {
        let covered = u64::try_from(turn.claim_generation).ok() == Some(claims.claim_generation)
            && turn.principal_id == claims.subject
            && claims.covers_turn(
                &turn.namespace,
                &turn.turn_id,
                &turn.claim_owner,
                claims.claim_generation,
            );
        if !covered {
            return Err(Status::permission_denied(
                "runtime token does not cover this turn's claim",
            ));
        }
        enforce_namespace_tenant_context(
            self.db.runtime(),
            request_tenant_context(self.db.runtime(), req)?.as_ref(),
            &turn.namespace,
            true,
        )
    }

    /// An Action submitted with a turn token is the turn's: the turn must
    /// still be claimed by the token, in the namespace the Action names.
    pub(crate) fn authorize_turn_submission<T: 'static>(
        &self,
        req: &Request<T>,
        namespace: &str,
    ) -> Result<(), Status> {
        let Some(claims) = req.extensions().get::<RuntimeTokenClaims>() else {
            return Ok(());
        };
        if !claims.is_turn() || claims.namespace != namespace {
            return Err(Status::permission_denied(
                "runtime token does not cover this submission",
            ));
        }
        let turn = agent_turn::get(self.db.runtime(), &claims.turn_id)
            .map_err(turn_status)?
            .ok_or_else(|| {
                Status::permission_denied("runtime token does not cover this submission")
            })?;
        self.authorize_turn_token(req, claims, &turn)?;
        // A frozen instance's turn submits nothing, here as at admission.
        if crate::sekai::site_agent_instance::frozen_instance_for(
            self.db.runtime(),
            &turn.namespace,
            &turn.principal_id,
        )
        .map_err(Status::internal)?
        .is_some()
        {
            return Err(Status::failed_precondition("site agent instance is frozen"));
        }
        Ok(())
    }

    /// The turn token for `turn` as claimed by `req`'s caller, or empty
    /// with zero expiry when the plane has no signing key or the caller has
    /// no tenant context (ADR 0142).
    fn turn_token_for<T: 'static>(
        &self,
        req: &Request<T>,
        turn: &agent_turn::AgentTurn,
        now_ms: i64,
    ) -> Result<(String, i64), Status> {
        let tenant_context = request_tenant_context(self.db.runtime(), req)?;
        let (Some(authority), Some(context)) = (
            self.runtime_token_authority.as_deref(),
            tenant_context.as_ref(),
        ) else {
            return Ok((String::new(), 0));
        };
        let Ok(claim_generation) = u64::try_from(turn.claim_generation) else {
            return Ok((String::new(), 0));
        };
        let binding = crate::runtime_token::TurnBinding {
            namespace: &turn.namespace,
            turn_id: &turn.turn_id,
            principal: &turn.principal_id,
            runtime_id: &turn.claim_owner,
            claim_generation,
            claim_expires_at_ms: turn.claim_expires_at_ms,
        };
        let Some(claims) = RuntimeTokenClaims::for_turn(authority, context, binding, now_ms) else {
            return Ok((String::new(), 0));
        };
        let token = claims.sign(authority).map_err(Status::internal)?;
        Ok((token, claims.expires_at_ms))
    }

    /// A turn token renewed on heartbeat: the same turn, principal and
    /// actor, expiring with the renewed claim and never after the authority
    /// it was first minted with.
    fn refresh_turn_token(
        &self,
        claims: &RuntimeTokenClaims,
        turn: &agent_turn::AgentTurn,
        now_ms: i64,
    ) -> Result<(String, i64), Status> {
        let Some(authority) = self.runtime_token_authority.as_deref() else {
            return Ok((String::new(), 0));
        };
        let mut renewed = claims.clone();
        renewed.expires_at_ms = turn
            .claim_expires_at_ms
            .min(now_ms.saturating_add(crate::runtime_token::RUNTIME_TOKEN_MAX_LIFETIME_MS))
            .min(claims.authority_expires_at_ms);
        renewed.jti = uuid::Uuid::new_v4().to_string();
        let token = renewed.sign(authority).map_err(Status::internal)?;
        Ok((token, renewed.expires_at_ms))
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

    pub(super) async fn list_site_agent_instance_turns_rpc(
        &self,
        req: Request<ListSiteAgentInstanceTurnsRequest>,
    ) -> Result<Response<ListSiteAgentInstanceTurnsResponse>, Status> {
        let (metadata, extensions, inner) = req.into_parts();
        let visible = self
            .get_visible_object(Request::from_parts(
                metadata,
                extensions,
                GetObjectRequest {
                    id: inner.instance_id.clone(),
                },
            ))
            .await;
        let object = match visible {
            Ok(response) => response.into_inner().object,
            Err(status) => return Err(status),
        };
        let Some(object) = object else {
            return Err(Status::not_found("not found"));
        };
        if object.kind != crate::sekai::site_agent_instance::KIND
            || object.namespace != inner.namespace
        {
            return Err(Status::not_found("not found"));
        }
        let before = agent_turn::parse_page_token(&inner.page_token).map_err(turn_status)?;
        let turns = agent_turn::list_for_instance(
            self.db.runtime(),
            &inner.namespace,
            &inner.instance_id,
            before
                .as_ref()
                .map(|(time_ms, turn_id)| (*time_ms, turn_id.as_str())),
            i64::from(inner.limit),
        )
        .map_err(turn_status)?;
        let cap = if inner.limit <= 0 {
            50
        } else {
            i64::from(inner.limit).min(500)
        };
        let next_page_token = if turns.len() as i64 == cap {
            turns
                .last()
                .map(agent_turn::InstanceEntry::page_token)
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Response::new(ListSiteAgentInstanceTurnsResponse {
            turns: turns.into_iter().map(entry_to_proto).collect(),
            next_page_token,
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
        let now = now_millis();
        let inner = req.get_ref();
        let turn = agent_turn::claim(
            self.db.runtime(),
            &inner.namespace,
            &inner.runtime_id,
            &inner.turn_id,
            inner.ttl_ms,
            now,
        )
        .map_err(turn_status)?;
        let (runtime_token, runtime_token_expires_at_ms) = self.turn_token_for(&req, &turn, now)?;
        let continuation = continuation_for(self.db.runtime(), &turn)?;
        Ok(Response::new(ClaimAgentTurnResponse {
            turn: Some(to_proto(turn)),
            runtime_token,
            runtime_token_expires_at_ms,
            continuation,
        }))
    }

    pub(super) async fn heartbeat_agent_turn_claim_rpc(
        &self,
        req: Request<HeartbeatAgentTurnClaimRequest>,
    ) -> Result<Response<HeartbeatAgentTurnClaimResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::Turn(&req.get_ref().turn_id))?;
        let now = now_millis();
        let inner = req.get_ref();
        let turn = agent_turn::heartbeat(
            self.db.runtime(),
            &inner.turn_id,
            &inner.runtime_id,
            inner.claim_generation,
            &inner.fencing_token,
            inner.ttl_ms,
            now,
        )
        .map_err(turn_status)?;
        // A heartbeat with a turn token refreshes it as the token's own
        // claim: its worker stays its actor (ADR 0142).
        let (runtime_token, runtime_token_expires_at_ms) =
            match req.extensions().get::<RuntimeTokenClaims>() {
                Some(claims) => self.refresh_turn_token(claims, &turn, now)?,
                None => self.turn_token_for(&req, &turn, now)?,
            };
        Ok(Response::new(HeartbeatAgentTurnClaimResponse {
            turn: Some(to_proto(turn)),
            runtime_token,
            runtime_token_expires_at_ms,
        }))
    }

    pub(super) async fn ack_agent_turn_rpc(
        &self,
        req: Request<AckAgentTurnRequest>,
    ) -> Result<Response<AckAgentTurnResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::AckedTurn(&req.get_ref().turn_id))?;
        let inner = req.into_inner();
        let now = now_millis();
        let turn = match inner.outcome.as_str() {
            "completed" | "failed" => agent_turn::acknowledge(
                self.db.runtime(),
                &inner.turn_id,
                &inner.runtime_id,
                inner.claim_generation,
                &inner.fencing_token,
                if inner.outcome == "completed" {
                    Outcome::Completed
                } else {
                    Outcome::Failed
                },
                &inner.reason,
                now,
            ),
            // The turn's Action awaits approval; the turn resumes after it
            // is decided (ADR 0142).
            "parked" => agent_turn::park(
                self.db.runtime(),
                &inner.turn_id,
                &inner.runtime_id,
                inner.claim_generation,
                &inner.fencing_token,
                &inner.parked_action_instance_id,
                &inner.reason,
                now,
            ),
            _ => {
                return Err(Status::invalid_argument(
                    "outcome must be completed, failed or parked",
                ));
            }
        }
        .map_err(turn_status)?;
        Ok(Response::new(AckAgentTurnResponse {
            turn: Some(to_proto(turn)),
        }))
    }

    /// Live working memory of one instance, returned only when both the
    /// instance principal and the requester can read each item (#1968).
    pub(super) async fn list_site_agent_working_memory_rpc(
        &self,
        req: Request<ListSiteAgentWorkingMemoryRequest>,
    ) -> Result<Response<ListSiteAgentWorkingMemoryResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.get_ref();
        let namespace = inner.namespace.trim();
        let instance_id = inner.instance_id.trim();
        if namespace.is_empty() || instance_id.is_empty() {
            return Err(Status::invalid_argument(
                "namespace and instance_id are required",
            ));
        }
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let mut turn_subject = None;
        if let Some(claims) = req.extensions().get::<RuntimeTokenClaims>() {
            let turn_id = if inner.turn_id.trim().is_empty() {
                claims.turn_id.clone()
            } else {
                inner.turn_id.trim().to_string()
            };
            self.authorize_turn_worker(&req, Scope::Turn(&turn_id))?;
            let turn = agent_turn::get(self.db.runtime(), &turn_id)
                .map_err(turn_status)?
                .ok_or_else(|| turn_status(TurnError::NotFound))?;
            if turn.namespace != namespace || turn.instance_id != instance_id {
                return Err(Status::not_found("not found"));
            }
            turn_subject = Some(claims.subject.clone());
        } else {
            enforce_collaboration_namespace(
                self.db.runtime(),
                tenant_context.as_ref(),
                namespace,
                false,
            )?;
            let named = inner.turn_id.trim();
            if !named.is_empty() {
                let turn = agent_turn::get(self.db.runtime(), named)
                    .map_err(turn_status)?
                    .ok_or_else(|| Status::not_found("not found"))?;
                if turn.namespace != namespace || turn.instance_id != instance_id {
                    return Err(Status::not_found("not found"));
                }
            }
        }
        let requester = requester_principal(&req);
        let db = self.db.runtime();
        let instance = db
            .get_object(instance_id)
            .map_err(Status::internal)?
            .filter(|object| {
                object.kind == crate::sekai::site_agent_instance::KIND
                    && object.namespace == namespace
            });
        let Some(instance) = instance else {
            return Err(Status::not_found("not found"));
        };
        let agent = instance
            .properties
            .get("principal_id")
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        if agent.is_empty() {
            return Err(Status::not_found("not found"));
        }
        // A turn token is bound to its claim's principal. It does not inherit
        // a later instance principal's clearance.
        if turn_subject.is_some_and(|subject| subject != agent) {
            return Err(Status::not_found("not found"));
        }
        require_visible_collaboration_read_root(
            db,
            &self.security,
            instance,
            std::slice::from_ref(&requester),
            tenant_context.as_ref(),
            &format!("list_site_agent_working_memory:{instance_id}"),
            None,
        )
        .map_err(hide_read_root_as_missing)?;
        let limit = if inner.limit <= 0 {
            crate::domain::DEFAULT_LIST_LIMIT
        } else {
            inner.limit.min(crate::domain::MAX_LIST_LIMIT)
        } as usize;
        let live =
            crate::sekai::site_agent_memory::list_live_for_instance(db, namespace, instance_id)
                .map_err(Status::internal)?;
        let mut items = Vec::new();
        for item in live {
            // Guest ceiling and shared-space kind/marking are request-shaped;
            // they sit on top of the independent principal checks (#1968).
            if !collaboration_permits_memory(db, tenant_context.as_ref(), &item)? {
                continue;
            }
            if !principal_may_read_memory(self, item.clone(), &agent)? {
                continue;
            }
            if !principal_may_read_memory(self, item.clone(), &requester)? {
                continue;
            }
            // Live `content` is the agent-turn payload. Its restricted
            // classification covers change history, not this read (ADR 0139).
            items.push(to_proto_obj(&item));
            if items.len() == limit {
                break;
            }
        }
        Ok(Response::new(ListSiteAgentWorkingMemoryResponse { items }))
    }
}

/// The person the calling token acts for: `act`, else the caller.
fn requester_principal<T: 'static>(req: &Request<T>) -> String {
    if let Some(context) = req
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        return context
            .act
            .as_deref()
            .map(str::trim)
            .filter(|act| !act.is_empty())
            .unwrap_or(context.principal.subject.as_str())
            .to_string();
    }
    caller_principals(req)
        .into_iter()
        .next()
        .unwrap_or_else(|| "anonymous".into())
}

/// Guest ceiling and shared-space kind/marking for this request. Independent
/// of either principal; a hidden item is `false`, a store outage stays an
/// error.
fn collaboration_permits_memory(
    db: &RuntimeDb,
    tenant_context: Option<&crate::enterprise::AuthenticatedContext>,
    object: &crate::domain::Object,
) -> Result<bool, Status> {
    match collaboration_object_permitted(
        db,
        tenant_context,
        object,
        crate::enterprise::NamespaceAction::Read,
    ) {
        Ok(permitted) => Ok(permitted),
        Err(status)
            if status.code() == tonic::Code::Internal
                || status.code() == tonic::Code::Unavailable =>
        {
            Err(status)
        }
        Err(_) => Ok(false),
    }
}

/// Whether `principal` may read `object` on its own: namespace, grants,
/// object-security policy and markings. A hidden item is `false`; a store
/// outage stays an error.
fn principal_may_read_memory(
    service: &SekaiServiceImpl,
    object: crate::domain::Object,
    principal: &str,
) -> Result<bool, Status> {
    let object_id = object.id.clone();
    let principals = [principal.to_string()];
    match require_visible_object_contents(
        service.db.runtime(),
        &service.security,
        object,
        &principals,
        None,
        &format!("list_site_agent_working_memory:{object_id}"),
        None,
    ) {
        Ok(_) => Ok(true),
        Err(status)
            if status.code() == tonic::Code::Internal
                || status.code() == tonic::Code::Unavailable =>
        {
            Err(status)
        }
        Err(_) => Ok(false),
    }
}
