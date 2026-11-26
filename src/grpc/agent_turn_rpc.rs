//! Agent-turn RPCs (ADR 0137, #1950). A manual wake needs administration of
//! the instance's namespace; workers list, claim, heartbeat and acknowledge
//! as credential admin or as a service principal registered as a turn
//! worker, and a claim's runtime token acts for its turn (ADR 0142,
//! ADR 0143).

use super::*;
use crate::runtime_token::RuntimeTokenClaims;
use crate::sekai::agent_turn::transcript;
use crate::sekai::agent_turn::{self, Cause, Outcome, TurnError, Wake};
use crate::sekai::interactive_agent_turn;
use std::collections::HashSet;

/// Namespace-invariant object-access residual for one working-memory list.
struct MemoryDecider {
    /// `None` is an invalid active policy or a namespace the principal
    /// cannot read: every item is omitted.
    compiled: Option<crate::sekai::policy_decision::CompiledObjectAccess>,
    deny_unmarked: bool,
    trusted: bool,
    namespace_ok: bool,
}

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
        transcript: None,
        definition_revision_digest: String::new(),
        agent_member: String::new(),
        trace_id: String::new(),
    }
}

/// An interactive turn on the wire (ADR 0173): no instance, and the member
/// as the principal it acts as.
fn interactive_to_proto(turn: interactive_agent_turn::InteractiveAgentTurn) -> AgentTurn {
    AgentTurn {
        turn_id: turn.turn_id,
        namespace: turn.namespace,
        instance_id: String::new(),
        principal_id: turn.member_id,
        cause: interactive_agent_turn::CAUSE.into(),
        cause_ref: turn.request_id,
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
        transcript: None,
        definition_revision_digest: turn.definition_revision_digest,
        agent_member: turn.agent_member,
        trace_id: turn.trace_id,
    }
}

/// A turn a worker call or turn token names: a site-agent turn, or an
/// interactive turn, routed by its `iturn-` id (ADR 0173).
enum AnyTurn {
    Site(agent_turn::AgentTurn),
    Interactive(interactive_agent_turn::InteractiveAgentTurn),
}

impl AnyTurn {
    fn load(db: &RuntimeDb, turn_id: &str) -> Result<Option<Self>, Status> {
        Ok(if interactive_agent_turn::is_interactive_turn_id(turn_id) {
            interactive_agent_turn::get(db, turn_id)
                .map_err(turn_status)?
                .map(Self::Interactive)
        } else {
            agent_turn::get(db, turn_id)
                .map_err(turn_status)?
                .map(Self::Site)
        })
    }

    fn require(db: &RuntimeDb, turn_id: &str) -> Result<Self, Status> {
        Self::load(db, turn_id)?.ok_or_else(|| turn_status(TurnError::NotFound))
    }

    fn namespace(&self) -> &str {
        match self {
            Self::Site(turn) => &turn.namespace,
            Self::Interactive(turn) => &turn.namespace,
        }
    }

    fn turn_id(&self) -> &str {
        match self {
            Self::Site(turn) => &turn.turn_id,
            Self::Interactive(turn) => &turn.turn_id,
        }
    }

    /// Whom the turn acts as: its instance principal, or its member.
    fn principal_id(&self) -> &str {
        match self {
            Self::Site(turn) => &turn.principal_id,
            Self::Interactive(turn) => &turn.member_id,
        }
    }

    /// The person a token for the turn names as `act`. An interactive turn
    /// acts as its member, so it has none.
    fn requester(&self) -> Option<&str> {
        match self {
            Self::Site(turn) => turn.requester(),
            Self::Interactive(_) => None,
        }
    }

    fn claim_owner(&self) -> &str {
        match self {
            Self::Site(turn) => &turn.claim_owner,
            Self::Interactive(turn) => &turn.claim_owner,
        }
    }

    fn claim_generation(&self) -> i64 {
        match self {
            Self::Site(turn) => turn.claim_generation,
            Self::Interactive(turn) => turn.claim_generation,
        }
    }

    fn claim_expires_at_ms(&self) -> i64 {
        match self {
            Self::Site(turn) => turn.claim_expires_at_ms,
            Self::Interactive(turn) => turn.claim_expires_at_ms,
        }
    }

    fn is_live_claim(&self, now_ms: i64) -> bool {
        match self {
            Self::Site(turn) => turn.is_live_claim(now_ms),
            Self::Interactive(turn) => turn.is_live_claim(now_ms),
        }
    }

    fn is_acknowledged(&self) -> bool {
        match self {
            Self::Site(turn) => turn.is_acknowledged(),
            Self::Interactive(turn) => turn.is_finished(),
        }
    }

    fn into_proto(self) -> AgentTurn {
        match self {
            Self::Site(turn) => to_proto(turn),
            Self::Interactive(turn) => interactive_to_proto(turn),
        }
    }
}

/// Whether `principals` are cleared for a transcript prompt `marking` under
/// the namespace's lattice (ADR 0157). An unknown marking is not cleared.
fn prompt_marking_cleared(
    db: &RuntimeDb,
    namespace: &str,
    marking: &str,
    principals: &[String],
) -> Result<bool, Status> {
    let lattice = load_classification_lattice(db, namespace)?;
    let authority = resolve_principal_authority(db, principals)?;
    let result = crate::sekai::classification_lattice::evaluate_lattice_access(
        "agent_turn.prompt",
        Some(marking),
        &authority,
        lattice.as_ref(),
    );
    Ok(result.decision != markings::MarkingDecision::Deny)
}

/// A transcript on the wire, without prompt text. Action steps carry their
/// Action's status, decision and receipt as they stand now.
fn transcript_to_proto(
    db: &RuntimeDb,
    stored: transcript::TurnTranscript,
) -> Result<AgentTurnTranscript, Status> {
    let mut steps = Vec::with_capacity(stored.steps.len());
    for step in stored.steps {
        let record = step.record;
        let action = if record.action_instance_id.is_empty() {
            None
        } else {
            db.get_action_instance(&record.action_instance_id)
                .map_err(Status::internal)?
        };
        steps.push(AgentTurnStep {
            step_id: record.step_id,
            kind: record.kind.as_str().into(),
            name: record.name,
            target: record.target,
            action_instance_id: record.action_instance_id,
            sequence: step.sequence,
            recorded_at_ms: step.recorded_at_ms,
            action_status: action
                .as_ref()
                .map(|action| action.status.clone())
                .unwrap_or_default(),
            action_approval_decision: action
                .as_ref()
                .map(|action| action.approval_decision.clone())
                .unwrap_or_default(),
            action_receipt: action.map(|action| action.operation_id).unwrap_or_default(),
        });
    }
    Ok(AgentTurnTranscript {
        usage: stored.usage.map(|usage| AgentTurnUsage {
            model_route: usage.model_route,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
        }),
        prompt_reference: stored.prompt_reference,
        prompt_marking: stored.prompt_marking,
        prompt_text_stored: stored.prompt_text_stored,
        prompt_text: String::new(),
        prompt_text_withheld: false,
        erased_at_ms: stored.erased_at_ms,
        steps,
    })
}

/// The transcript a list returns for one turn, or `None` when the worker
/// recorded nothing. Prompt text is attached only when asked for and the
/// reader is cleared; otherwise a stored text is marked withheld.
fn listed_transcript(
    db: &RuntimeDb,
    namespace: &str,
    turn_id: &str,
    include_prompt_text: bool,
    reader: &[String],
) -> Result<Option<AgentTurnTranscript>, Status> {
    let stored = transcript::get(db, turn_id).map_err(turn_status)?;
    if stored == transcript::TurnTranscript::default() {
        return Ok(None);
    }
    let mut listed = transcript_to_proto(db, stored)?;
    if listed.prompt_text_stored {
        let cleared = include_prompt_text
            && prompt_marking_cleared(db, namespace, &listed.prompt_marking, reader)?;
        match cleared
            .then(|| transcript::prompt_text(db, turn_id))
            .transpose()
            .map_err(turn_status)?
            .flatten()
        {
            Some(text) => listed.prompt_text = text,
            None => listed.prompt_text_withheld = true,
        }
    }
    Ok(Some(listed))
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
            transcript: None,
            definition_revision_digest: String::new(),
            agent_member: String::new(),
            trace_id: String::new(),
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
            let turn = AnyTurn::require(self.db.runtime(), turn_id)?;
            refuse_instance_as_worker(claims.worker.as_deref().unwrap_or(""), turn.principal_id())?;
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
                let turn = AnyTurn::require(self.db.runtime(), turn_id)?;
                refuse_instance_as_worker(&calling_worker_subject(req), turn.principal_id())?;
                turn.namespace().to_string()
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
        turn: &AnyTurn,
    ) -> Result<(), Status> {
        let live = turn.is_live_claim(now_millis())
            && u64::try_from(turn.claim_generation()).ok() == Some(claims.claim_generation)
            && turn.principal_id() == claims.subject
            && claims.covers_turn(
                turn.namespace(),
                turn.turn_id(),
                turn.claim_owner(),
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
            turn.namespace(),
            true,
        )?;
        if let AnyTurn::Interactive(turn) = turn {
            self.require_member_access(turn)?;
        }
        Ok(())
    }

    /// An interactive turn acts with its member's access as it stands now
    /// (ADR 0173 decision 3). A member who lost write access to the
    /// namespace fails the turn with the refusal as its reason.
    fn require_member_access(
        &self,
        turn: &interactive_agent_turn::InteractiveAgentTurn,
    ) -> Result<(), Status> {
        let member = [turn.member_id.clone()];
        let Err(refused) = check_team_namespace(self.db.runtime(), &member, &turn.namespace, true)
        else {
            return Ok(());
        };
        if refused.code() == tonic::Code::PermissionDenied {
            interactive_agent_turn::fail_unfinished(
                self.db.runtime(),
                &turn.turn_id,
                &format!("member access revoked: {}", refused.message()),
                now_millis(),
            )
            .map_err(turn_status)?;
        }
        Err(refused)
    }

    /// A turn token retrying the ack of a turn it acknowledged: the turn was
    /// last claimed at the token's generation by its runtime.
    fn authorize_acked_turn_token<T: 'static>(
        &self,
        req: &Request<T>,
        claims: &RuntimeTokenClaims,
        turn: &AnyTurn,
    ) -> Result<(), Status> {
        let covered = u64::try_from(turn.claim_generation()).ok() == Some(claims.claim_generation)
            && turn.principal_id() == claims.subject
            && claims.covers_turn(
                turn.namespace(),
                turn.turn_id(),
                turn.claim_owner(),
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
            turn.namespace(),
            true,
        )
    }

    /// An Action submitted with a turn token is the turn's: the turn must
    /// still be claimed by the token, in the namespace the Action names. An
    /// interactive turn submits only the Action types its agent member
    /// allows (ADR 0173 decision 4). Returns the claim the admission commits
    /// under, `None` without a turn token.
    pub(crate) fn authorize_turn_submission<T: 'static>(
        &self,
        req: &Request<T>,
        namespace: &str,
        type_id: &str,
    ) -> Result<Option<crate::sekai::action_instance::AgentTurnFence>, Status> {
        let Some(claims) = req.extensions().get::<RuntimeTokenClaims>() else {
            return Ok(None);
        };
        if !claims.is_turn() || claims.namespace != namespace {
            return Err(Status::permission_denied(
                "runtime token does not cover this submission",
            ));
        }
        let turn = AnyTurn::load(self.db.runtime(), &claims.turn_id)?.ok_or_else(|| {
            Status::permission_denied("runtime token does not cover this submission")
        })?;
        self.authorize_turn_token(req, claims, &turn)?;
        let mut fence = crate::sekai::action_instance::AgentTurnFence {
            turn_id: claims.turn_id.clone(),
            claim_generation: claims.claim_generation,
            interactive: None,
        };
        let turn = match turn {
            AnyTurn::Interactive(turn) => {
                interactive_agent_turn::require_allowed_action_type(
                    self.db.runtime(),
                    &turn,
                    type_id,
                )
                .map_err(Status::permission_denied)?;
                fence.interactive = Some(crate::sekai::action_instance::InteractiveTurnReceipt {
                    definition_revision_digest: turn.definition_revision_digest,
                    agent_member: turn.agent_member,
                    trace_id: turn.trace_id,
                });
                return Ok(Some(fence));
            }
            AnyTurn::Site(turn) => turn,
        };
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
        Ok(Some(fence))
    }

    /// The turn token for `turn` as claimed by `req`'s caller, or empty
    /// with zero expiry when the plane has no signing key or the caller has
    /// no tenant context (ADR 0142).
    fn turn_token_for<T: 'static>(
        &self,
        req: &Request<T>,
        turn: &AnyTurn,
        now_ms: i64,
    ) -> Result<(String, i64), Status> {
        let tenant_context = request_tenant_context(self.db.runtime(), req)?;
        let (Some(authority), Some(context)) = (
            self.runtime_token_authority.as_deref(),
            tenant_context.as_ref(),
        ) else {
            return Ok((String::new(), 0));
        };
        let Ok(claim_generation) = u64::try_from(turn.claim_generation()) else {
            return Ok((String::new(), 0));
        };
        let binding = crate::runtime_token::TurnBinding {
            namespace: turn.namespace(),
            turn_id: turn.turn_id(),
            principal: turn.principal_id(),
            requester: turn.requester(),
            runtime_id: turn.claim_owner(),
            claim_generation,
            claim_expires_at_ms: turn.claim_expires_at_ms(),
        };
        let Some(claims) = RuntimeTokenClaims::for_turn(authority, context, binding, now_ms) else {
            return Ok((String::new(), 0));
        };
        let token = claims.sign(authority).map_err(Status::internal)?;
        Ok((token, claims.expires_at_ms))
    }

    /// A turn token renewed on heartbeat: the same turn, principal,
    /// requester and worker, expiring with the renewed claim and never
    /// after the authority it was first minted with.
    fn refresh_turn_token(
        &self,
        claims: &RuntimeTokenClaims,
        turn: &AnyTurn,
        now_ms: i64,
    ) -> Result<(String, i64), Status> {
        let Some(authority) = self.runtime_token_authority.as_deref() else {
            return Ok((String::new(), 0));
        };
        let mut renewed = claims.clone();
        renewed.expires_at_ms = turn
            .claim_expires_at_ms()
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

    /// Admits an interactive turn acting as the caller (ADR 0173). Only a
    /// member admits, for themself: an agent, a registered service
    /// principal, a machine credential, a runtime token or a delegated
    /// caller is refused, so agent autonomy grants never attach to the turn.
    pub(super) async fn admit_interactive_agent_turn_rpc(
        &self,
        req: Request<AdmitInteractiveAgentTurnRequest>,
    ) -> Result<Response<AdmitInteractiveAgentTurnResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let [member] = principals.as_slice() else {
            return Err(Status::permission_denied(
                "an interactive turn acts as one member",
            ));
        };
        let member = member.clone();
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        if req.extensions().get::<RuntimeTokenClaims>().is_some()
            || freeze_actor_is_agent(self.db.runtime(), &member, tenant_context.as_ref())?
        {
            return Err(Status::permission_denied(
                "only a member admits an interactive turn, for themself",
            ));
        }
        let inner = req.into_inner();
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &inner.namespace,
            true,
        )?;
        check_team_namespace(self.db.runtime(), &principals, &inner.namespace, true)?;
        let turn = interactive_agent_turn::admit(
            self.db.runtime(),
            interactive_agent_turn::Admission {
                namespace: inner.namespace,
                member_id: member,
                definition_revision_digest: inner.definition_revision_digest,
                agent_member: inner.agent_member,
                request_id: inner.request_id,
                trace_id: inner.trace_id,
            },
            now_millis(),
        )
        .map_err(turn_status)?;
        Ok(Response::new(AdmitInteractiveAgentTurnResponse {
            turn: Some(interactive_to_proto(turn)),
        }))
    }

    pub(super) async fn list_site_agent_instance_turns_rpc(
        &self,
        req: Request<ListSiteAgentInstanceTurnsRequest>,
    ) -> Result<Response<ListSiteAgentInstanceTurnsResponse>, Status> {
        let reader = caller_principals(&req);
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
        let runtime = self.db.runtime();
        let mut listed = Vec::with_capacity(turns.len());
        for entry in turns {
            let mut turn = entry_to_proto(entry);
            turn.transcript = listed_transcript(
                runtime,
                &inner.namespace,
                &turn.turn_id,
                inner.include_prompt_text,
                &reader,
            )?;
            listed.push(turn);
        }
        Ok(Response::new(ListSiteAgentInstanceTurnsResponse {
            turns: listed,
            next_page_token,
        }))
    }

    /// Records part of a claimed turn's transcript under its claim's fence
    /// (ADR 0157). The prompt marking must be one the turn's instance
    /// principal is cleared for; an action step must name an Action in the
    /// turn's namespace.
    pub(super) async fn append_agent_turn_transcript_rpc(
        &self,
        req: Request<AppendAgentTurnTranscriptRequest>,
    ) -> Result<Response<AppendAgentTurnTranscriptResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::Turn(&req.get_ref().turn_id))?;
        let inner = req.into_inner();
        let runtime = self.db.runtime();
        let turn = agent_turn::get(runtime, &inner.turn_id)
            .map_err(turn_status)?
            .ok_or_else(|| Status::not_found("turn not found"))?;
        let prompt = match inner.prompt {
            Some(prompt) => {
                if !prompt.marking.is_empty()
                    && !prompt_marking_cleared(
                        runtime,
                        &turn.namespace,
                        &prompt.marking,
                        std::slice::from_ref(&turn.principal_id),
                    )?
                {
                    return Err(Status::permission_denied(
                        "the turn's principal is not cleared for the prompt marking",
                    ));
                }
                Some(transcript::PromptRecord {
                    reference: prompt.reference,
                    marking: prompt.marking,
                    text: (!prompt.text.is_empty()).then_some(prompt.text),
                })
            }
            None => None,
        };
        let step = match inner.step {
            Some(step) => {
                let kind = transcript::StepKind::parse(&step.kind).ok_or_else(|| {
                    Status::invalid_argument("step kind must be tool_call or action")
                })?;
                if !step.action_instance_id.is_empty() {
                    let action = runtime
                        .get_action_instance(&step.action_instance_id)
                        .map_err(Status::internal)?;
                    if action.is_none_or(|action| action.namespace != turn.namespace) {
                        return Err(Status::not_found("action instance not found"));
                    }
                }
                Some(transcript::StepRecord {
                    step_id: step.step_id,
                    kind,
                    name: step.name,
                    target: step.target,
                    action_instance_id: step.action_instance_id,
                })
            }
            None => None,
        };
        let append = transcript::TranscriptAppend {
            usage: inner.usage.map(|usage| transcript::TurnUsage {
                model_route: usage.model_route,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
            }),
            prompt,
            step,
        };
        let stored = transcript::append(
            runtime,
            &inner.turn_id,
            &inner.runtime_id,
            inner.claim_generation,
            &inner.fencing_token,
            append,
            now_millis(),
        )
        .map_err(turn_status)?;
        Ok(Response::new(AppendAgentTurnTranscriptResponse {
            transcript: Some(transcript_to_proto(runtime, stored)?),
        }))
    }

    pub(super) async fn list_claimable_agent_turns_rpc(
        &self,
        req: Request<ListClaimableAgentTurnsRequest>,
    ) -> Result<Response<ListClaimableAgentTurnsResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::Namespace(&req.get_ref().namespace))?;
        let inner = req.into_inner();
        let now = now_millis();
        let limit = i64::from(inner.limit);
        let mut turns: Vec<AgentTurn> = agent_turn::list_claimable_maybe_resuming(
            self.db.runtime(),
            &inner.namespace,
            now,
            limit,
            inner.accepts_continuation,
        )
        .map_err(turn_status)?
        .into_iter()
        .map(to_proto)
        .collect();
        // Interactive turns fill what the site-agent turns leave of the page.
        if inner.accepts_interactive {
            let cap = usize::try_from(if limit <= 0 { 50 } else { limit.min(500) }).unwrap_or(0);
            let room = i64::try_from(cap.saturating_sub(turns.len())).unwrap_or(0);
            if room > 0 {
                turns.extend(
                    interactive_agent_turn::list_claimable(
                        self.db.runtime(),
                        &inner.namespace,
                        now,
                        room,
                    )
                    .map_err(turn_status)?
                    .into_iter()
                    .map(interactive_to_proto),
                );
            }
        }
        Ok(Response::new(ListClaimableAgentTurnsResponse { turns }))
    }

    pub(super) async fn claim_agent_turn_rpc(
        &self,
        req: Request<ClaimAgentTurnRequest>,
    ) -> Result<Response<ClaimAgentTurnResponse>, Status> {
        self.authorize_turn_worker(&req, Scope::Namespace(&req.get_ref().namespace))?;
        let now = now_millis();
        let worker = calling_worker_subject(&req);
        let inner = req.get_ref();
        let interactive_id = interactive_agent_turn::is_interactive_turn_id(&inner.turn_id);
        if interactive_id && !inner.accepts_interactive {
            return Err(Status::failed_precondition(
                "claiming an interactive turn requires accepts_interactive",
            ));
        }
        let turn = if interactive_id {
            // The member's own credential never runs its turn (ADR 0173).
            if let Some(turn) = interactive_agent_turn::get(self.db.runtime(), &inner.turn_id)
                .map_err(turn_status)?
                .filter(|turn| turn.namespace == inner.namespace)
            {
                refuse_member_as_worker(&worker, &turn.member_id)?;
            }
            interactive_agent_turn::claim(
                self.db.runtime(),
                &inner.namespace,
                &inner.runtime_id,
                &inner.turn_id,
                &worker,
                inner.ttl_ms,
                now,
            )
            .map(AnyTurn::Interactive)
        } else if inner.turn_id.trim().is_empty() {
            let site = agent_turn::claim_next_for_worker(
                self.db.runtime(),
                &inner.namespace,
                &inner.runtime_id,
                &worker,
                inner.ttl_ms,
                now,
                inner.accepts_continuation,
            );
            match site {
                // Site-agent turns first; an interactive one when none is due.
                Err(TurnError::NotFound) if inner.accepts_interactive => {
                    interactive_agent_turn::claim_next(
                        self.db.runtime(),
                        &inner.namespace,
                        &inner.runtime_id,
                        &worker,
                        inner.ttl_ms,
                        now,
                    )
                    .map(AnyTurn::Interactive)
                }
                other => other.map(AnyTurn::Site),
            }
        } else {
            if let Some(turn) = agent_turn::get(self.db.runtime(), &inner.turn_id)
                .map_err(turn_status)?
                .filter(|turn| turn.namespace == inner.namespace)
            {
                refuse_instance_as_worker(&worker, &turn.principal_id)?;
            }
            agent_turn::claim_accepting_continuation(
                self.db.runtime(),
                &inner.namespace,
                &inner.runtime_id,
                &inner.turn_id,
                inner.ttl_ms,
                now,
                inner.accepts_continuation,
            )
            .map(AnyTurn::Site)
        }
        .map_err(turn_status)?;
        let (runtime_token, runtime_token_expires_at_ms) = self.turn_token_for(&req, &turn, now)?;
        let continuation = match &turn {
            AnyTurn::Site(turn) => continuation_for(self.db.runtime(), turn)?,
            AnyTurn::Interactive(_) => None,
        };
        Ok(Response::new(ClaimAgentTurnResponse {
            turn: Some(turn.into_proto()),
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
        let turn = if interactive_agent_turn::is_interactive_turn_id(&inner.turn_id) {
            interactive_agent_turn::heartbeat(
                self.db.runtime(),
                &inner.turn_id,
                &inner.runtime_id,
                inner.claim_generation,
                &inner.fencing_token,
                inner.ttl_ms,
                now,
            )
            .map(AnyTurn::Interactive)
        } else {
            agent_turn::heartbeat(
                self.db.runtime(),
                &inner.turn_id,
                &inner.runtime_id,
                inner.claim_generation,
                &inner.fencing_token,
                inner.ttl_ms,
                now,
            )
            .map(AnyTurn::Site)
        }
        .map_err(turn_status)?;
        // A heartbeat with a turn token refreshes it as the token's own
        // claim: the same principal, requester and worker (ADR 0143).
        let (runtime_token, runtime_token_expires_at_ms) =
            match req.extensions().get::<RuntimeTokenClaims>() {
                Some(claims) => self.refresh_turn_token(claims, &turn, now)?,
                None => self.turn_token_for(&req, &turn, now)?,
            };
        Ok(Response::new(HeartbeatAgentTurnClaimResponse {
            turn: Some(turn.into_proto()),
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
        if interactive_agent_turn::is_interactive_turn_id(&inner.turn_id) {
            // Parking an interactive turn is not yet supported: it fails
            // closed rather than leaving a turn nothing resumes.
            let outcome = match inner.outcome.as_str() {
                "completed" => Outcome::Completed,
                "failed" => Outcome::Failed,
                "parked" => {
                    return Err(Status::failed_precondition(
                        "an interactive turn cannot park yet",
                    ));
                }
                _ => {
                    return Err(Status::invalid_argument(
                        "outcome must be completed, failed or parked",
                    ));
                }
            };
            let turn = interactive_agent_turn::acknowledge(
                self.db.runtime(),
                &inner.turn_id,
                &inner.runtime_id,
                inner.claim_generation,
                &inner.fencing_token,
                outcome,
                &inner.reason,
                now,
            )
            .map_err(turn_status)?;
            return Ok(Response::new(AckAgentTurnResponse {
                turn: Some(interactive_to_proto(turn)),
            }));
        }
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

    /// Live working memory of one instance. The caller is that instance's
    /// principal; an item is returned only when that principal and the
    /// requester can each read it (#1968).
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
        // The calling subject is this instance's principal. A delegated
        // caller does not inherit another instance principal's clearance.
        let subject = req
            .extensions()
            .get::<crate::enterprise::AuthenticatedContext>()
            .map(|context| context.principal.subject.clone())
            .or_else(|| caller_principals(&req).into_iter().next())
            .unwrap_or_default();
        if subject != agent {
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
        let mut cursor = crate::sekai::site_agent_memory::parse_page_token(&inner.page_token)
            .map_err(Status::invalid_argument)?;
        let agent_decider = compile_memory_decider(self, namespace, &agent)?;
        let requester_decider = if requester == agent {
            None
        } else {
            Some(compile_memory_decider(self, namespace, &requester)?)
        };
        let need_grants = agent_decider.deny_unmarked
            || requester_decider
                .as_ref()
                .is_some_and(|decider| decider.deny_unmarked);
        let schema = self
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        let mut items = Vec::new();
        loop {
            let remaining = (limit + 1).saturating_sub(items.len());
            if remaining == 0 {
                break;
            }
            let page_size = remaining.min(crate::domain::MAX_LIST_LIMIT as usize) as i32;
            let page = crate::sekai::site_agent_memory::list_live_page(
                db,
                namespace,
                instance_id,
                cursor.as_deref(),
                page_size,
            )
            .map_err(Status::internal)?;
            if page.is_empty() {
                break;
            }
            let fetched = page.len();
            let (agent_grants, requester_grants) =
                memory_page_grants(db, &page, &agent, &requester, need_grants)?;
            for item in page {
                cursor = Some(item.id.clone());
                // Guest ceiling and shared-space kind/marking are request-shaped;
                // they sit on top of the independent principal checks (#1968).
                if !collaboration_permits_memory(db, tenant_context.as_ref(), &item)? {
                    continue;
                }
                if !principal_may_read_memory(self, &agent_decider, &item, &agent, &agent_grants)? {
                    continue;
                }
                let requester_ok = match &requester_decider {
                    Some(decider) => principal_may_read_memory(
                        self,
                        decider,
                        &item,
                        &requester,
                        &requester_grants,
                    )?,
                    None => true,
                };
                if !requester_ok {
                    continue;
                }
                // Same projection as GetObject: grants, then restricted `content`
                // redacted for the requester (`act`) and the instance principal.
                // The agent sees live notes only when that principal is an
                // object admin, as GetObject would (#2033).
                let item = match self.project_for_response(
                    item,
                    &schema,
                    &principals,
                    tenant_context.as_ref(),
                ) {
                    Ok(item) => item,
                    Err(status) if status.code() == tonic::Code::PermissionDenied => continue,
                    Err(status) => return Err(status),
                };
                items.push(to_proto_obj(&item));
                if items.len() == limit + 1 {
                    break;
                }
            }
            if items.len() == limit + 1 || fetched < page_size as usize {
                break;
            }
        }
        let next_page_token = if items.len() == limit + 1 {
            items.truncate(limit);
            items.last().map(|item| item.id.clone()).unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Response::new(ListSiteAgentWorkingMemoryResponse {
            items,
            next_page_token,
        }))
    }
}

const INSTANCE_AS_WORKER: &str = "turn worker must not be the instance principal";

fn refuse_instance_as_worker(worker: &str, principal_id: &str) -> Result<(), Status> {
    let worker = worker.trim();
    let principal_id = principal_id.trim();
    if !worker.is_empty() && worker == principal_id {
        return Err(Status::permission_denied(INSTANCE_AS_WORKER));
    }
    Ok(())
}

fn refuse_member_as_worker(worker: &str, member_id: &str) -> Result<(), Status> {
    if !worker.trim().is_empty() && worker.trim() == member_id {
        return Err(Status::permission_denied(
            "turn worker must not be the turn's member",
        ));
    }
    Ok(())
}

/// Claiming worker: turn-token `worker`, else the caller's subject.
fn calling_worker_subject<T: 'static>(req: &Request<T>) -> String {
    if let Some(claims) = req.extensions().get::<RuntimeTokenClaims>() {
        return claims.worker.clone().unwrap_or_default();
    }
    if let Some(context) = req
        .extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
    {
        return context.principal.subject.clone();
    }
    caller_principals(req)
        .into_iter()
        .find(|principal| principal != "anonymous")
        .unwrap_or_default()
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

fn compile_memory_decider(
    service: &SekaiServiceImpl,
    namespace: &str,
    principal: &str,
) -> Result<MemoryDecider, Status> {
    let runtime = service.db.runtime();
    let principals = [principal.to_string()];
    let namespace_ok = match check_team_namespace(runtime, &principals, namespace, false) {
        Ok(()) => true,
        Err(status) if memory_auth_outage(&status) => return Err(status),
        Err(_) => false,
    };
    let deny_unmarked = deny_unmarked_for_namespace(runtime, namespace)?;
    let trusted = crate::sekai::markings::is_trusted_service_principal(principal);
    if !namespace_ok {
        return Ok(MemoryDecider {
            compiled: None,
            deny_unmarked,
            trusted,
            namespace_ok: false,
        });
    }
    let policy =
        match runtime.active_object_policy(namespace, crate::sekai::site_agent_memory::KIND) {
            Ok(policy) => policy,
            Err(error) if error.starts_with("object_security_denied") => {
                return Ok(MemoryDecider {
                    compiled: None,
                    deny_unmarked,
                    trusted,
                    namespace_ok: true,
                });
            }
            Err(_) => return Err(Status::unavailable("object authorization unavailable")),
        };
    let lattice = load_classification_lattice(runtime, namespace)?;
    let authority = resolve_principal_authority(runtime, &principals)?;
    let context = principal_policy_context_from(&principals, None);
    let activation = runtime
        .get_object_security_activation(namespace)
        .map_err(|_| Status::unavailable("object authorization unavailable"))?;
    let activation_digest = match activation.as_ref() {
        Some(activation) => {
            crate::sekai::object_security::object_security_activation_digest(activation)
                .unwrap_or_else(|_| "legacy".into())
        }
        None => "legacy".into(),
    };
    let compiled = crate::sekai::policy_decision::compile_object_access(
        crate::sekai::policy_decision::PolicyCompileRequest {
            namespace,
            kind: crate::sekai::site_agent_memory::KIND,
            operation: crate::sekai::object_security::ObjectSecurityOperation::Read,
            context: &context,
            authority: &authority,
            lattice: lattice.as_ref(),
            policy: policy.as_ref(),
            activation_digest: &activation_digest,
            purpose: None,
            purpose_authorization: None,
            now_ms: now_millis(),
            namespace_granted: true,
        },
    )
    .map_err(Status::internal)?;
    Ok(MemoryDecider {
        compiled: Some(compiled),
        deny_unmarked,
        trusted,
        namespace_ok: true,
    })
}

fn memory_page_grants(
    db: &RuntimeDb,
    page: &[crate::domain::Object],
    agent: &str,
    requester: &str,
    need_grants: bool,
) -> Result<(HashSet<String>, HashSet<String>), Status> {
    if !need_grants {
        return Ok((HashSet::new(), HashSet::new()));
    }
    let grant_ids = page
        .iter()
        .filter(|object| crate::sekai::markings::object_marking_token(object).is_none())
        .map(|object| object.id.clone())
        .collect::<Vec<_>>();
    if grant_ids.is_empty() {
        return Ok((HashSet::new(), HashSet::new()));
    }
    let grants = db
        .list_grants_for_object_ids(&grant_ids)
        .map_err(Status::internal)?;
    let for_principal = |principal: &str| {
        grants
            .iter()
            .filter(|grant| grant.principal == principal)
            .map(|grant| grant.object_id.clone())
            .collect::<HashSet<_>>()
    };
    Ok((for_principal(agent), for_principal(requester)))
}

fn memory_policy_allows(decider: &MemoryDecider, object: &crate::domain::Object) -> bool {
    let Some(compiled) = &decider.compiled else {
        return false;
    };
    let decision = compiled.decide(object);
    !matches!(
        (decision.outcome, decision.denied_by),
        (
            crate::sekai::policy_decision::PolicyOutcome::Deny,
            Some(layer)
        ) if layer != crate::sekai::policy_decision::PolicyLayer::Marking
    )
}

fn memory_marking_allows(
    decider: &MemoryDecider,
    object: &crate::domain::Object,
    explicit_grants: &HashSet<String>,
) -> bool {
    if crate::sekai::markings::object_marking_token(object).is_none() {
        return crate::sekai::markings::unmarked_access_decision(
            decider.deny_unmarked,
            decider.trusted,
            explicit_grants.contains(&object.id),
        ) != crate::sekai::markings::MarkingDecision::Deny;
    }
    let Some(compiled) = &decider.compiled else {
        return false;
    };
    compiled.decide(object).denied_by != Some(crate::sekai::policy_decision::PolicyLayer::Marking)
}

fn memory_auth_outage(status: &Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Internal | tonic::Code::Unavailable
    )
}

/// Whether `principal` may read `object` on its own: namespace, grants,
/// object-security policy and markings. `tenant_context` stays `None` so
/// the check is that principal, not the request's scopes or `act`
/// (`runtime_object_visible_to`). A hidden item is `false`; a store
/// outage stays an error.
fn principal_may_read_memory(
    service: &SekaiServiceImpl,
    decider: &MemoryDecider,
    object: &crate::domain::Object,
    principal: &str,
    explicit_grants: &HashSet<String>,
) -> Result<bool, Status> {
    if !decider.namespace_ok {
        return Ok(false);
    }
    let principals = [principal.to_string()];
    match check_object_acl_with_audit(
        service.db.runtime(),
        &service.security,
        &object.id,
        &principals,
        None,
        crate::sekai::object_security::ObjectSecurityOperation::Read,
    ) {
        Ok(()) => {}
        Err(status) if memory_auth_outage(&status) => return Err(status),
        Err(_) => return Ok(false),
    }
    Ok(memory_policy_allows(decider, object)
        && memory_marking_allows(decider, object, explicit_grants))
}
