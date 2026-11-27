//! Interactive agent turns (ADR 0173, #3046): a member runs an agent from a
//! published, certified definition revision, and the turn acts as that
//! member, never more.
//!
//! These turns live in `sekai_interactive_agent_turn`, a table older planes
//! never read: their claim and listing paths map every `sekai_agent_turn`
//! row strictly and would fail a whole namespace on an instance-less row.
//! Turn ids carry the [`ID_PREFIX`], so a lookup routes by id and never
//! probes both tables.
//!
//! A turn parks on an Action it submitted that awaits approval and is
//! claimable again, with that Action as its continuation, once the decision
//! stands, as an instance turn does (ADR 0142).

use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::db::postgres::{PostgresDb, off_runtime};
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::agent_turn::{MAX_PARKS, Outcome, TurnError, parked_action_decided};
use crate::sekai::governed_transform::{
    MAX_TRANSFORM_LEASE_EXPIRIES, normalize_transform_claim_ttl_ms,
};
use crate::sekai::site_agent_instance;
use crate::sekai::work_claim::{ClaimError, ClaimRecord, Fence, Hold};

/// The wire cause of an interactive turn.
pub const CAUSE: &str = "interactive";
/// Prefix of every interactive turn id; instance turns use `turn-`.
pub const ID_PREFIX: &str = "iturn-";
/// Longest accepted request id or trace id.
pub const MAX_REFERENCE_LEN: usize = 256;

const PENDING: &str = "pending";
const CLAIMED: &str = "claimed";
const COMPLETED: &str = "completed";
const FAILED: &str = "failed";
const PARKED: &str = "parked";
const PARKED_TOO_OFTEN: &str = "parked too often";
const LEASE_EXHAUSTED: &str = "claim lapsed too often";
/// How many due candidates one claim-next tries before reporting an empty
/// queue; each try re-checks its row under the row lock.
const CLAIM_NEXT_CANDIDATES: i64 = 16;

/// An interactive turn and, once finished, its receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveAgentTurn {
    pub turn_id: String,
    pub namespace: String,
    /// The member the turn acts as; the only caller who may admit it.
    pub member_id: String,
    pub definition_revision_digest: String,
    pub agent_member: String,
    /// Caller-supplied trace id of the run, named on its receipts.
    pub trace_id: String,
    /// Idempotency key: one turn per member, revision, agent and request id.
    pub request_id: String,
    pub due_at_ms: i64,
    pub admitted_by: String,
    pub status: String,
    pub claim_owner: String,
    pub claim_generation: i64,
    pub fencing_token: String,
    pub claim_expires_at_ms: i64,
    pub lease_expiries: i64,
    pub created_at_ms: i64,
    pub finished_at_ms: i64,
    pub reason: String,
    pub parked_action_id: String,
    pub park_count: i64,
}

impl InteractiveAgentTurn {
    /// Whether the turn completed or failed.
    pub fn is_finished(&self) -> bool {
        matches!(self.status.as_str(), COMPLETED | FAILED)
    }

    /// Whether the turn waits on the decision of its parked Action.
    pub fn is_parked(&self) -> bool {
        self.status == PARKED
    }

    /// Whether the turn is claimed and its lease has not lapsed at `now_ms`.
    pub fn is_live_claim(&self, now_ms: i64) -> bool {
        self.status == CLAIMED && self.claim_expires_at_ms > now_ms
    }

    /// The turn's claim state, for the claim engine (ADR 0149).
    pub fn claim_record(&self) -> ClaimRecord {
        ClaimRecord {
            owner: self.claim_owner.clone(),
            generation: self.claim_generation,
            fencing_token: self.fencing_token.clone(),
            expires_at_ms: self.claim_expires_at_ms,
            lease_expiries: self.lease_expiries,
        }
    }

    fn set_claim_record(&mut self, record: ClaimRecord) {
        self.claim_owner = record.owner;
        self.claim_generation = record.generation;
        self.fencing_token = record.fencing_token;
        self.claim_expires_at_ms = record.expires_at_ms;
        self.lease_expiries = record.lease_expiries;
    }

    fn hold(&self) -> Hold {
        match self.status.as_str() {
            PENDING => Hold::Open,
            CLAIMED => Hold::Held,
            _ => Hold::Closed,
        }
    }

    fn claimable(&self, now_ms: i64) -> bool {
        self.due_at_ms <= now_ms && self.claim_record().is_takeable(self.hold(), 0, now_ms)
    }
}

fn fence<'a>(owner: &'a str, generation: i64, token: &'a str) -> Fence<'a> {
    Fence {
        owner,
        generation,
        token,
    }
}

/// An interactive turn to admit for `member_id`.
#[derive(Debug, Clone)]
pub struct Admission {
    pub namespace: String,
    pub member_id: String,
    pub definition_revision_digest: String,
    pub agent_member: String,
    pub request_id: String,
    pub trace_id: String,
}

/// Whether `turn_id` names an interactive turn.
pub fn is_interactive_turn_id(turn_id: &str) -> bool {
    turn_id.starts_with(ID_PREFIX)
}

/// Admits `admission` as its member. The caller has already established
/// that the member is the authenticated caller and may write the namespace.
/// An existing identity returns its turn unchanged, so a retry with the same
/// request id is one turn.
pub fn admit(
    db: &RuntimeDb,
    admission: Admission,
    now_ms: i64,
) -> Result<InteractiveAgentTurn, TurnError> {
    for (name, value) in [
        ("namespace", &admission.namespace),
        ("member_id", &admission.member_id),
        (
            "definition_revision_digest",
            &admission.definition_revision_digest,
        ),
        ("agent_member", &admission.agent_member),
    ] {
        if value.trim().is_empty() {
            return Err(TurnError::Invalid(format!("{name} required")));
        }
    }
    for (name, value) in [
        ("request_id", &admission.request_id),
        ("trace_id", &admission.trace_id),
    ] {
        if value.trim().is_empty() || value.len() > MAX_REFERENCE_LEN {
            return Err(TurnError::Invalid(format!(
                "{name} required, at most {MAX_REFERENCE_LEN} bytes"
            )));
        }
    }
    let turn_id = turn_id(&admission);
    if let Some(existing) = get(db, &turn_id)? {
        return Ok(existing);
    }
    site_agent_instance::require_certified_agent_member(
        db,
        &admission.namespace,
        &admission.definition_revision_digest,
        &admission.agent_member,
        now_ms,
    )
    .map_err(TurnError::Invalid)?;
    let turn = InteractiveAgentTurn {
        turn_id,
        admitted_by: admission.member_id.clone(),
        namespace: admission.namespace,
        member_id: admission.member_id,
        definition_revision_digest: admission.definition_revision_digest,
        agent_member: admission.agent_member,
        trace_id: admission.trace_id,
        request_id: admission.request_id,
        due_at_ms: now_ms,
        status: PENDING.into(),
        claim_owner: String::new(),
        claim_generation: 0,
        fencing_token: String::new(),
        claim_expires_at_ms: 0,
        lease_expiries: 0,
        created_at_ms: now_ms,
        finished_at_ms: 0,
        reason: String::new(),
        parked_action_id: String::new(),
        park_count: 0,
    };
    match db {
        RuntimeDb::Sqlite(store) => store.insert_interactive_agent_turn(&turn),
        RuntimeDb::Postgres(store) => off_runtime(|| store.insert_interactive_agent_turn(&turn)),
    }?;
    // A concurrent admission of the same identity may have won.
    get(db, &turn.turn_id)?.ok_or(TurnError::NotFound)
}

/// The interactive turn `turn_id`, if any. Ids without [`ID_PREFIX`] are
/// never interactive and are not looked up.
pub fn get(db: &RuntimeDb, turn_id: &str) -> Result<Option<InteractiveAgentTurn>, TurnError> {
    if !is_interactive_turn_id(turn_id) {
        return Ok(None);
    }
    match db {
        RuntimeDb::Sqlite(store) => store.interactive_agent_turn(turn_id),
        RuntimeDb::Postgres(store) => off_runtime(|| store.interactive_agent_turn(turn_id)),
    }
}

/// Due turns in `namespace` a worker may claim, oldest due first: pending
/// turns, turns whose claim lapsed and parked turns whose Action's decision
/// stands. Without `include_resuming`, a turn that ever parked is left out:
/// it resumes with a continuation. `limit` caps as the site-turn list
/// does: 50 when not positive, at most 500. Only workers that set
/// `accepts_interactive` see them.
pub fn list_claimable_maybe_resuming(
    db: &RuntimeDb,
    namespace: &str,
    now_ms: i64,
    limit: i64,
    include_resuming: bool,
) -> Result<Vec<InteractiveAgentTurn>, TurnError> {
    let limit = if limit <= 0 { 50 } else { limit.min(500) };
    candidates(db, namespace, "", now_ms, limit, include_resuming)
}

/// [`list_claimable_maybe_resuming`], resuming turns included.
pub fn list_claimable(
    db: &RuntimeDb,
    namespace: &str,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<InteractiveAgentTurn>, TurnError> {
    list_claimable_maybe_resuming(db, namespace, now_ms, limit, true)
}

/// Up to `limit` due turns not of `skip_member`. The store reads parks only
/// once their Action left `parked` or is gone, so parks still awaiting
/// approval never crowd the page; the durable check then drops a grant whose
/// recording has not landed.
fn candidates(
    db: &RuntimeDb,
    namespace: &str,
    skip_member: &str,
    now_ms: i64,
    limit: i64,
    include_resuming: bool,
) -> Result<Vec<InteractiveAgentTurn>, TurnError> {
    let turns = match db {
        RuntimeDb::Sqlite(store) => store.claimable_interactive_agent_turns(
            namespace,
            skip_member,
            now_ms,
            limit,
            include_resuming,
        ),
        RuntimeDb::Postgres(store) => off_runtime(|| {
            store.claimable_interactive_agent_turns(
                namespace,
                skip_member,
                now_ms,
                limit,
                include_resuming,
            )
        }),
    }?;
    let mut kept = Vec::with_capacity(turns.len());
    for turn in turns {
        if !turn.is_parked() || parked_action_decided(db, &turn.parked_action_id)? {
            kept.push(turn);
        }
    }
    Ok(kept)
}

/// Claims `turn_id` for `runtime_id`. A worker whose subject is the turn's
/// member is refused, as a worker that is the instance principal is
/// (ADR 0146): the member's own credential must not run its turn. A worker
/// claiming through this call accepts continuation.
pub fn claim(
    db: &RuntimeDb,
    namespace: &str,
    runtime_id: &str,
    turn_id: &str,
    worker_principal: &str,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<InteractiveAgentTurn, TurnError> {
    claim_accepting_continuation(
        db,
        namespace,
        runtime_id,
        turn_id,
        worker_principal,
        ttl_ms,
        now_ms,
        true,
    )
}

/// [`claim`]. A parked turn resumes once its Action is decided, and a turn
/// that ever parked is claimed only by a worker that
/// `accepts_continuation`.
#[allow(clippy::too_many_arguments)]
pub fn claim_accepting_continuation(
    db: &RuntimeDb,
    namespace: &str,
    runtime_id: &str,
    turn_id: &str,
    worker_principal: &str,
    ttl_ms: i64,
    now_ms: i64,
    accepts_continuation: bool,
) -> Result<InteractiveAgentTurn, TurnError> {
    if runtime_id.trim().is_empty() {
        return Err(TurnError::Invalid("runtime_id required".into()));
    }
    // Read the park's decision outside the claim's transaction: the store's
    // connection is not reentrant. A decision never reverts (ADR 0142).
    let checked = get(db, turn_id)?
        .filter(|turn| turn.is_parked())
        .map(|turn| -> Result<_, TurnError> {
            let decided = parked_action_decided(db, &turn.parked_action_id)?;
            Ok((turn.claim_generation, turn.parked_action_id, decided))
        })
        .transpose()?;
    let mut exhausted = false;
    let claimed = edit(db, turn_id, |turn| {
        if turn.namespace != namespace {
            return Err(TurnError::NotFound);
        }
        if turn.member_id == worker_principal {
            return Err(TurnError::Invalid(
                "a turn's worker must not be its member".into(),
            ));
        }
        // A turn that ever parked resumes with a continuation, a lapsed
        // resumed claim included.
        if !turn.parked_action_id.is_empty() && !accepts_continuation {
            return Err(TurnError::Invalid(
                "claimer does not accept continuation".into(),
            ));
        }
        // Resume only the park whose decision was read: a turn reclaimed and
        // parked again meanwhile waits on its new Action.
        let resuming = turn.is_parked()
            && checked
                .as_ref()
                .is_some_and(|(generation, action, decided)| {
                    *decided
                        && *generation == turn.claim_generation
                        && *action == turn.parked_action_id
                });
        if !resuming && !turn.claimable(now_ms) {
            return Err(TurnError::NotClaimable);
        }
        let hold = if resuming { Hold::Open } else { turn.hold() };
        exhausted = !assign_claim(turn, runtime_id, ttl_ms, now_ms, hold)?;
        Ok(())
    })?;
    if exhausted {
        return Err(TurnError::NotClaimable);
    }
    Ok(claimed)
}

/// Claims the oldest due turn in `namespace` whose member is not
/// `worker_principal`. An empty queue is [`TurnError::NotFound`]. Each
/// candidate is re-checked under its row lock, so two workers racing for
/// one turn leave one winner and the other moves on.
pub fn claim_next(
    db: &RuntimeDb,
    namespace: &str,
    runtime_id: &str,
    worker_principal: &str,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<InteractiveAgentTurn, TurnError> {
    claim_next_accepting_continuation(
        db,
        namespace,
        runtime_id,
        worker_principal,
        ttl_ms,
        now_ms,
        true,
    )
}

/// [`claim_next`], offering turns that ever parked only when
/// `accepts_continuation`.
pub fn claim_next_accepting_continuation(
    db: &RuntimeDb,
    namespace: &str,
    runtime_id: &str,
    worker_principal: &str,
    ttl_ms: i64,
    now_ms: i64,
    accepts_continuation: bool,
) -> Result<InteractiveAgentTurn, TurnError> {
    if runtime_id.trim().is_empty() {
        return Err(TurnError::Invalid("runtime_id required".into()));
    }
    let candidates = candidates(
        db,
        namespace,
        worker_principal,
        now_ms,
        CLAIM_NEXT_CANDIDATES,
        accepts_continuation,
    )?;
    for candidate in candidates {
        match claim_accepting_continuation(
            db,
            namespace,
            runtime_id,
            &candidate.turn_id,
            worker_principal,
            ttl_ms,
            now_ms,
            accepts_continuation,
        ) {
            Err(TurnError::NotClaimable) => continue,
            other => return other,
        }
    }
    Err(TurnError::NotFound)
}

/// Extends the live claim. A lapsed or superseded claim is stale.
pub fn heartbeat(
    db: &RuntimeDb,
    turn_id: &str,
    runtime_id: &str,
    claim_generation: i64,
    fencing_token: &str,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<InteractiveAgentTurn, TurnError> {
    edit(db, turn_id, |turn| {
        let mut record = turn.claim_record();
        record
            .heartbeat(
                turn.hold(),
                fence(runtime_id, claim_generation, fencing_token),
                normalize_transform_claim_ttl_ms(ttl_ms),
                now_ms,
            )
            .map_err(|_| TurnError::StaleClaim)?;
        turn.set_claim_record(record);
        Ok(())
    })
}

/// Finishes the turn under the current claim and returns its receipt. A
/// retry with the same claim and outcome returns the same receipt.
#[allow(clippy::too_many_arguments)]
pub fn acknowledge(
    db: &RuntimeDb,
    turn_id: &str,
    runtime_id: &str,
    claim_generation: i64,
    fencing_token: &str,
    outcome: Outcome,
    reason: &str,
    now_ms: i64,
) -> Result<InteractiveAgentTurn, TurnError> {
    let status = match outcome {
        Outcome::Completed => COMPLETED,
        Outcome::Failed => FAILED,
    };
    edit(db, turn_id, |turn| {
        if !turn
            .claim_record()
            .matches(fence(runtime_id, claim_generation, fencing_token))
        {
            return Err(TurnError::StaleClaim);
        }
        if turn.status == status {
            return Ok(());
        }
        let mut record = turn.claim_record();
        record
            .release(
                turn.hold(),
                fence(runtime_id, claim_generation, fencing_token),
                now_ms,
            )
            .map_err(|_| TurnError::StaleClaim)?;
        turn.set_claim_record(record);
        turn.status = status.into();
        turn.reason = reason.into();
        turn.finished_at_ms = now_ms;
        Ok(())
    })
}

/// Ends a turn that has not finished, parked ones included, as failed with
/// `reason`, whoever holds it: the member lost the access the turn acts with (ADR 0173 decision 3).
/// A finished turn is left as it is.
pub fn fail_unfinished(
    db: &RuntimeDb,
    turn_id: &str,
    reason: &str,
    now_ms: i64,
) -> Result<InteractiveAgentTurn, TurnError> {
    edit(db, turn_id, |turn| {
        if turn.is_finished() {
            return Ok(());
        }
        let mut record = turn.claim_record();
        record.expires_at_ms = 0;
        turn.set_claim_record(record);
        turn.status = FAILED.into();
        turn.reason = reason.into();
        turn.finished_at_ms = now_ms;
        Ok(())
    })
}

/// Parks the turn under its current, unexpired claim on `action_id`, an
/// Action the turn submitted under this claim that awaits approval or whose
/// decision already stands (ADR 0142). The claim ends; the turn is
/// claimable again once the Action is decided. A retry with the same claim
/// and Action returns the same receipt. A turn parked [`MAX_PARKS`] times
/// fails instead.
#[allow(clippy::too_many_arguments)]
pub fn park(
    db: &RuntimeDb,
    turn_id: &str,
    runtime_id: &str,
    claim_generation: i64,
    fencing_token: &str,
    action_id: &str,
    reason: &str,
    now_ms: i64,
) -> Result<InteractiveAgentTurn, TurnError> {
    // Read before the turn's transaction, whose connection is not reentrant.
    let action = db
        .get_action_instance(action_id)?
        .ok_or_else(|| TurnError::Invalid(format!("action instance {action_id} not found")))?;
    let submitted_here = action.agent_turn.as_ref().is_some_and(|fence| {
        fence.turn_id == turn_id
            && i64::try_from(fence.claim_generation).ok() == Some(claim_generation)
    });
    let awaiting_approval = action.status == crate::sekai::action_instance::STATUS_PARKED;
    let decision_stands = parked_action_decided(db, action_id)?;
    edit(db, turn_id, |turn| {
        let held = fence(runtime_id, claim_generation, fencing_token);
        if !turn.claim_record().matches(held) {
            return Err(TurnError::StaleClaim);
        }
        // A retry of this park replays its receipt, the failing fourth one
        // included.
        let parked_here =
            turn.is_parked() || (turn.status == FAILED && turn.reason == PARKED_TOO_OFTEN);
        if parked_here && turn.parked_action_id == action_id {
            return Ok(());
        }
        if !turn.is_live_claim(now_ms) {
            return Err(TurnError::StaleClaim);
        }
        if !submitted_here || !(awaiting_approval || decision_stands) {
            return Err(TurnError::Invalid(
                "a turn parks only on an Action it submitted under this claim that awaits approval or whose decision stands"
                    .into(),
            ));
        }
        turn.park_count += 1;
        turn.claim_expires_at_ms = 0;
        turn.parked_action_id = action_id.into();
        turn.reason = reason.into();
        if turn.park_count > MAX_PARKS {
            turn.status = FAILED.into();
            turn.reason = PARKED_TOO_OFTEN.into();
            turn.finished_at_ms = now_ms;
            return Ok(());
        }
        turn.status = PARKED.into();
        Ok(())
    })
}

/// Refuses `action_type` unless the turn's agent member lists it in
/// `allowed_action_types` at the turn's revision (ADR 0173 decision 4). An
/// unreadable member refuses every type. Returns the approval rule a
/// submission parks with: `agent_tool:{agent member}:{policy}` when the
/// member binds the type as an Action tool with an approval policy, else
/// empty. The type's own approvers decide it.
pub fn require_allowed_action_type(
    db: &RuntimeDb,
    turn: &InteractiveAgentTurn,
    action_type: &str,
) -> Result<String, String> {
    let member = db
        .get_definition_member(
            &turn.namespace,
            &turn.definition_revision_digest,
            crate::sekai::agent_promotion::MEMBER_KIND_AGENT,
            &turn.agent_member,
        )?
        .ok_or_else(|| {
            format!(
                "agent member {} is gone from its revision",
                turn.agent_member
            )
        })?;
    let definition: crate::sekai::agent_definition::AgentDefinition =
        serde_json::from_str(&member.definition_json)
            .map_err(|_| "agent definition is unreadable".to_string())?;
    if !definition
        .allowed_action_types
        .iter()
        .any(|allowed| allowed == action_type)
    {
        return Err(format!(
            "agent member {} does not allow Action type {action_type}",
            turn.agent_member
        ));
    }
    Ok(definition
        .tools
        .iter()
        .find(|tool| {
            tool.kind == crate::sekai::agent_definition::TOOL_KIND_ACTION
                && tool.name == action_type
        })
        .and_then(|tool| tool.approval_policy.as_deref())
        .map(|policy| format!("agent_tool:{}:{policy}", turn.agent_member))
        .unwrap_or_default())
}

/// Claims `turn` for `runtime_id` through the claim engine. `Ok(false)`
/// means the lapsed lease reached its limit and the turn failed; persist it.
fn assign_claim(
    turn: &mut InteractiveAgentTurn,
    runtime_id: &str,
    ttl_ms: i64,
    now_ms: i64,
    hold: Hold,
) -> Result<bool, TurnError> {
    let mut record = turn.claim_record();
    match record.count_lapse(hold, MAX_TRANSFORM_LEASE_EXPIRIES, now_ms) {
        Ok(_) => {}
        Err(ClaimError::LeaseLimit) => {
            record.expires_at_ms = 0;
            turn.set_claim_record(record);
            turn.status = FAILED.into();
            turn.reason = LEASE_EXHAUSTED.into();
            turn.finished_at_ms = now_ms;
            return Ok(false);
        }
        Err(_) => return Err(TurnError::NotClaimable),
    }
    record.grant(
        runtime_id,
        normalize_transform_claim_ttl_ms(ttl_ms),
        now_ms,
        |_| uuid::Uuid::new_v4().to_string(),
    );
    turn.set_claim_record(record);
    turn.status = CLAIMED.into();
    Ok(true)
}

/// Loads, edits and persists one turn under a row lock. A failed `change`
/// leaves the row as it was, except a lease-limit failure, which `claim`
/// reports after the row is persisted.
fn edit(
    db: &RuntimeDb,
    turn_id: &str,
    change: impl FnOnce(&mut InteractiveAgentTurn) -> Result<(), TurnError>,
) -> Result<InteractiveAgentTurn, TurnError> {
    if !is_interactive_turn_id(turn_id) {
        return Err(TurnError::NotFound);
    }
    match db {
        RuntimeDb::Sqlite(store) => store.edit_interactive_agent_turn(turn_id, change),
        RuntimeDb::Postgres(store) => {
            off_runtime(|| store.edit_interactive_agent_turn(turn_id, change))
        }
    }
}

fn turn_id(admission: &Admission) -> String {
    let mut hasher = Sha256::new();
    for part in [
        admission.namespace.as_str(),
        admission.member_id.as_str(),
        admission.definition_revision_digest.as_str(),
        admission.agent_member.as_str(),
        admission.request_id.as_str(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("{ID_PREFIX}{:x}", hasher.finalize())
}

/// SQLite schema; the PostgreSQL migration is
/// `postgres/0191_interactive_agent_turns.sql`.
const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_interactive_agent_turn (
    turn_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    member_id TEXT NOT NULL,
    definition_revision_digest TEXT NOT NULL,
    agent_member TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    due_at_ms INTEGER NOT NULL,
    admitted_by TEXT NOT NULL,
    status TEXT NOT NULL,
    claim_owner TEXT NOT NULL DEFAULT '',
    claim_generation INTEGER NOT NULL DEFAULT 0,
    fencing_token TEXT NOT NULL DEFAULT '',
    claim_expires_at_ms INTEGER NOT NULL DEFAULT 0,
    lease_expiries INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    finished_at_ms INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    parked_action_id TEXT NOT NULL DEFAULT '',
    park_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sekai_interactive_agent_turn_claim
    ON sekai_interactive_agent_turn (namespace, due_at_ms, turn_id)
    WHERE status IN ('pending', 'claimed', 'parked');
CREATE INDEX IF NOT EXISTS sekai_interactive_agent_turn_member
    ON sekai_interactive_agent_turn (namespace, member_id, created_at_ms DESC, turn_id DESC);
";

const COLUMNS: &str = "turn_id, namespace, member_id, definition_revision_digest, agent_member,
    trace_id, request_id, due_at_ms, admitted_by, status, claim_owner, claim_generation,
    fencing_token, claim_expires_at_ms, lease_expiries, created_at_ms, finished_at_ms, reason,
    parked_action_id, park_count";

fn map_turn(row: &Row<'_>) -> rusqlite::Result<InteractiveAgentTurn> {
    Ok(InteractiveAgentTurn {
        turn_id: row.get(0)?,
        namespace: row.get(1)?,
        member_id: row.get(2)?,
        definition_revision_digest: row.get(3)?,
        agent_member: row.get(4)?,
        trace_id: row.get(5)?,
        request_id: row.get(6)?,
        due_at_ms: row.get(7)?,
        admitted_by: row.get(8)?,
        status: row.get(9)?,
        claim_owner: row.get(10)?,
        claim_generation: row.get(11)?,
        fencing_token: row.get(12)?,
        claim_expires_at_ms: row.get(13)?,
        lease_expiries: row.get(14)?,
        created_at_ms: row.get(15)?,
        finished_at_ms: row.get(16)?,
        reason: row.get(17)?,
        parked_action_id: row.get(18)?,
        park_count: row.get(19)?,
    })
}

fn pg_turn(row: &postgres::Row) -> InteractiveAgentTurn {
    InteractiveAgentTurn {
        turn_id: row.get(0),
        namespace: row.get(1),
        member_id: row.get(2),
        definition_revision_digest: row.get(3),
        agent_member: row.get(4),
        trace_id: row.get(5),
        request_id: row.get(6),
        due_at_ms: row.get(7),
        admitted_by: row.get(8),
        status: row.get(9),
        claim_owner: row.get(10),
        claim_generation: row.get(11),
        fencing_token: row.get(12),
        claim_expires_at_ms: row.get(13),
        lease_expiries: row.get(14),
        created_at_ms: row.get(15),
        finished_at_ms: row.get(16),
        reason: row.get(17),
        parked_action_id: row.get(18),
        park_count: row.get(19),
    }
}

impl SekaiDb {
    pub(crate) fn migrate_interactive_agent_turns(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    fn interactive_agent_turn(
        &self,
        turn_id: &str,
    ) -> Result<Option<InteractiveAgentTurn>, TurnError> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {COLUMNS} FROM sekai_interactive_agent_turn WHERE turn_id = ?1"),
                params![turn_id],
                map_turn,
            )
            .optional()?)
    }

    fn claimable_interactive_agent_turns(
        &self,
        namespace: &str,
        skip_member: &str,
        now_ms: i64,
        limit: i64,
        include_resuming: bool,
    ) -> Result<Vec<InteractiveAgentTurn>, TurnError> {
        // The Action table is created on first use; a parked turn has one.
        self.migrate_action_instances()?;
        let conn = self.conn();
        let mut statement = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM sekai_interactive_agent_turn
             WHERE namespace = ?1 AND due_at_ms <= ?2 AND member_id <> ?3
               AND (?5 OR parked_action_id = '')
               AND (status = 'pending' OR (status = 'claimed' AND claim_expires_at_ms <= ?2)
                    OR (status = 'parked' AND NOT EXISTS (
                        SELECT 1 FROM sekai_action_instances action
                        WHERE action.instance_id = sekai_interactive_agent_turn.parked_action_id
                          AND action.status = 'parked')))
             ORDER BY due_at_ms, turn_id
             LIMIT ?4"
        ))?;
        let turns = statement
            .query_map(
                params![namespace, now_ms, skip_member, limit, include_resuming],
                map_turn,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(turns)
    }

    fn edit_interactive_agent_turn(
        &self,
        turn_id: &str,
        change: impl FnOnce(&mut InteractiveAgentTurn) -> Result<(), TurnError>,
    ) -> Result<InteractiveAgentTurn, TurnError> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut turn = tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM sekai_interactive_agent_turn WHERE turn_id = ?1"),
                params![turn_id],
                map_turn,
            )
            .optional()?
            .ok_or(TurnError::NotFound)?;
        change(&mut turn)?;
        tx.execute(
            "UPDATE sekai_interactive_agent_turn SET status = ?2, claim_owner = ?3,
                 claim_generation = ?4, fencing_token = ?5, claim_expires_at_ms = ?6,
                 lease_expiries = ?7, finished_at_ms = ?8, reason = ?9,
                 parked_action_id = ?10, park_count = ?11
             WHERE turn_id = ?1",
            params![
                turn.turn_id,
                turn.status,
                turn.claim_owner,
                turn.claim_generation,
                turn.fencing_token,
                turn.claim_expires_at_ms,
                turn.lease_expiries,
                turn.finished_at_ms,
                turn.reason,
                turn.parked_action_id,
                turn.park_count,
            ],
        )?;
        tx.commit()?;
        Ok(turn)
    }

    fn insert_interactive_agent_turn(&self, turn: &InteractiveAgentTurn) -> Result<(), TurnError> {
        self.conn().execute(
            &format!(
                "INSERT INTO sekai_interactive_agent_turn ({COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                         ?17, ?18, ?19, ?20)
                 ON CONFLICT(turn_id) DO NOTHING"
            ),
            params![
                turn.turn_id,
                turn.namespace,
                turn.member_id,
                turn.definition_revision_digest,
                turn.agent_member,
                turn.trace_id,
                turn.request_id,
                turn.due_at_ms,
                turn.admitted_by,
                turn.status,
                turn.claim_owner,
                turn.claim_generation,
                turn.fencing_token,
                turn.claim_expires_at_ms,
                turn.lease_expiries,
                turn.created_at_ms,
                turn.finished_at_ms,
                turn.reason,
                turn.parked_action_id,
                turn.park_count,
            ],
        )?;
        Ok(())
    }
}

impl PostgresDb {
    fn interactive_agent_turn(
        &self,
        turn_id: &str,
    ) -> Result<Option<InteractiveAgentTurn>, TurnError> {
        Ok(self
            .connection()?
            .query_opt(
                &format!("SELECT {COLUMNS} FROM sekai_interactive_agent_turn WHERE turn_id = $1"),
                &[&turn_id],
            )?
            .as_ref()
            .map(pg_turn))
    }

    fn claimable_interactive_agent_turns(
        &self,
        namespace: &str,
        skip_member: &str,
        now_ms: i64,
        limit: i64,
        include_resuming: bool,
    ) -> Result<Vec<InteractiveAgentTurn>, TurnError> {
        Ok(self
            .connection()?
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_interactive_agent_turn
                     WHERE namespace = $1 AND due_at_ms <= $2 AND member_id <> $3
                       AND ($5 OR parked_action_id = '')
                       AND (status = 'pending'
                            OR (status = 'claimed' AND claim_expires_at_ms <= $2)
                            OR (status = 'parked' AND NOT EXISTS (
                                SELECT 1 FROM sekai_action_instances action
                                WHERE action.instance_id
                                      = sekai_interactive_agent_turn.parked_action_id
                                  AND action.status = 'parked')))
                     ORDER BY due_at_ms, turn_id
                     LIMIT $4"
                ),
                &[&namespace, &now_ms, &skip_member, &limit, &include_resuming],
            )?
            .iter()
            .map(pg_turn)
            .collect())
    }

    fn edit_interactive_agent_turn(
        &self,
        turn_id: &str,
        change: impl FnOnce(&mut InteractiveAgentTurn) -> Result<(), TurnError>,
    ) -> Result<InteractiveAgentTurn, TurnError> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction()?;
        let row = tx
            .query_opt(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_interactive_agent_turn
                     WHERE turn_id = $1 FOR UPDATE"
                ),
                &[&turn_id],
            )?
            .ok_or(TurnError::NotFound)?;
        let mut turn = pg_turn(&row);
        change(&mut turn)?;
        tx.execute(
            "UPDATE sekai_interactive_agent_turn SET status = $2, claim_owner = $3,
                 claim_generation = $4, fencing_token = $5, claim_expires_at_ms = $6,
                 lease_expiries = $7, finished_at_ms = $8, reason = $9,
                 parked_action_id = $10, park_count = $11
             WHERE turn_id = $1",
            &[
                &turn.turn_id,
                &turn.status,
                &turn.claim_owner,
                &turn.claim_generation,
                &turn.fencing_token,
                &turn.claim_expires_at_ms,
                &turn.lease_expiries,
                &turn.finished_at_ms,
                &turn.reason,
                &turn.parked_action_id,
                &turn.park_count,
            ],
        )?;
        tx.commit()?;
        Ok(turn)
    }

    fn insert_interactive_agent_turn(&self, turn: &InteractiveAgentTurn) -> Result<(), TurnError> {
        self.connection()?.execute(
            &format!(
                "INSERT INTO sekai_interactive_agent_turn ({COLUMNS})
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                         $17, $18, $19, $20)
                 ON CONFLICT (turn_id) DO NOTHING"
            ),
            &[
                &turn.turn_id,
                &turn.namespace,
                &turn.member_id,
                &turn.definition_revision_digest,
                &turn.agent_member,
                &turn.trace_id,
                &turn.request_id,
                &turn.due_at_ms,
                &turn.admitted_by,
                &turn.status,
                &turn.claim_owner,
                &turn.claim_generation,
                &turn.fencing_token,
                &turn.claim_expires_at_ms,
                &turn.lease_expiries,
                &turn.created_at_ms,
                &turn.finished_at_ms,
                &turn.reason,
                &turn.parked_action_id,
                &turn.park_count,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::site_agent_instance::tests::published_revision;
    use std::sync::Arc;

    fn runtime() -> RuntimeDb {
        RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    fn admission(digest: &str, agent_member: &str, request_id: &str) -> Admission {
        Admission {
            namespace: "site".into(),
            member_id: "alice".into(),
            definition_revision_digest: digest.into(),
            agent_member: agent_member.into(),
            request_id: request_id.into(),
            trace_id: "trace-1".into(),
        }
    }

    /// A member's turn is stored as theirs and pending, under an `iturn-`
    /// id, and a retry with the same request id is the same turn.
    #[test]
    fn a_member_admits_one_turn_per_request_id() {
        let db = runtime();
        let digest = published_revision(&db, "", true);
        let turn = admit(&db, admission(&digest, "triage", "req-1"), 10).unwrap();
        assert!(turn.turn_id.starts_with(ID_PREFIX), "{}", turn.turn_id);
        assert_eq!(turn.member_id, "alice");
        assert_eq!(turn.admitted_by, "alice");
        assert_eq!(turn.definition_revision_digest, digest);
        assert_eq!(turn.agent_member, "triage");
        assert_eq!(turn.trace_id, "trace-1");
        assert_eq!(turn.status, PENDING);
        let retried = admit(&db, admission(&digest, "triage", "req-1"), 20).unwrap();
        assert_eq!(retried, turn);
        let other = admit(&db, admission(&digest, "triage", "req-2"), 30).unwrap();
        assert_ne!(other.turn_id, turn.turn_id);
        // Instance-turn ids are never looked up in this table.
        assert_eq!(get(&db, "turn-anything").unwrap(), None);
    }

    /// Only an agent member of a published, certified revision runs, and
    /// a refused admission stores nothing.
    #[test]
    fn admission_binds_only_to_a_certified_agent_member() {
        let db = runtime();
        let certified = published_revision(&db, "", true);
        let uncertified = published_revision(&db, &certified, false);
        for (digest, member, expected) in [
            ("missing", "triage", "is not published"),
            (uncertified.as_str(), "triage", "no current certification"),
            (certified.as_str(), "ticket", "is not an agent member"),
        ] {
            let request = admission(digest, member, "req-1");
            let id = turn_id(&request);
            let error = admit(&db, request, 10).unwrap_err();
            assert!(
                matches!(&error, TurnError::Invalid(message) if message.contains(expected)),
                "{error:?}"
            );
            assert_eq!(get(&db, &id).unwrap(), None);
        }
    }

    /// Both stores keep a turn as written and leave a racing insert of the
    /// same id alone.
    fn store_contract(db: &RuntimeDb, namespace: &str) {
        let request = Admission {
            namespace: namespace.into(),
            ..admission("rev", "triage", "req-1")
        };
        let turn = InteractiveAgentTurn {
            turn_id: turn_id(&request),
            namespace: request.namespace.clone(),
            member_id: "alice".into(),
            definition_revision_digest: "rev".into(),
            agent_member: "triage".into(),
            trace_id: "trace-1".into(),
            request_id: "req-1".into(),
            due_at_ms: 5,
            admitted_by: "alice".into(),
            status: PENDING.into(),
            claim_owner: String::new(),
            claim_generation: 0,
            fencing_token: String::new(),
            claim_expires_at_ms: 0,
            lease_expiries: 0,
            created_at_ms: 5,
            finished_at_ms: 0,
            reason: String::new(),
            parked_action_id: String::new(),
            park_count: 0,
        };
        let insert = |turn: &InteractiveAgentTurn| match db {
            RuntimeDb::Sqlite(store) => store.insert_interactive_agent_turn(turn),
            RuntimeDb::Postgres(store) => store.insert_interactive_agent_turn(turn),
        };
        insert(&turn).unwrap();
        let racing = InteractiveAgentTurn {
            trace_id: "trace-2".into(),
            ..turn.clone()
        };
        insert(&racing).unwrap();
        assert_eq!(get(db, &turn.turn_id).unwrap(), Some(turn.clone()));
        claim_contract(db, namespace, &turn.turn_id);
        let parked = InteractiveAgentTurn {
            turn_id: format!("{ID_PREFIX}parked-{namespace}"),
            status: PARKED.into(),
            claim_generation: 1,
            parked_action_id: format!("act-gone-{namespace}"),
            park_count: 1,
            ..turn
        };
        insert(&parked).unwrap();
        park_contract(db, namespace, &parked);
    }

    /// A turn parked on an Action that is gone, whose decision therefore
    /// stands: it resumes only for a worker that accepts continuation, and
    /// the park survives the store's edit.
    fn park_contract(db: &RuntimeDb, namespace: &str, parked: &InteractiveAgentTurn) {
        let listed = |resuming, now_ms| {
            list_claimable_maybe_resuming(db, namespace, now_ms, 0, resuming)
                .unwrap()
                .into_iter()
                .map(|turn| turn.turn_id)
                .collect::<Vec<_>>()
        };
        assert!(listed(false, 10).is_empty());
        assert_eq!(listed(true, 10), std::slice::from_ref(&parked.turn_id));
        assert!(matches!(
            claim_accepting_continuation(
                db,
                namespace,
                "rt",
                &parked.turn_id,
                "worker",
                1_000,
                10,
                false
            ),
            Err(TurnError::Invalid(_))
        ));
        assert!(matches!(
            claim_next_accepting_continuation(db, namespace, "rt", "worker", 1_000, 10, false),
            Err(TurnError::NotFound)
        ));
        let resumed =
            claim_next_accepting_continuation(db, namespace, "rt", "worker", 1_000, 10, true)
                .unwrap();
        assert_eq!(
            (
                resumed.status.as_str(),
                resumed.claim_generation,
                resumed.parked_action_id.as_str(),
                resumed.park_count,
            ),
            (CLAIMED, 2, parked.parked_action_id.as_str(), 1)
        );
        // A lapsed resumed claim still carries its continuation.
        let lapsed = resumed.claim_expires_at_ms + 1;
        assert!(listed(false, lapsed).is_empty());
        assert_eq!(listed(true, lapsed), std::slice::from_ref(&parked.turn_id));
        assert!(matches!(
            claim_accepting_continuation(
                db,
                namespace,
                "rt",
                &parked.turn_id,
                "worker",
                1_000,
                lapsed,
                false
            ),
            Err(TurnError::Invalid(_))
        ));
        assert!(matches!(
            park(
                db,
                &parked.turn_id,
                "rt",
                2,
                &resumed.fencing_token,
                "act-missing",
                "approval",
                20,
            ),
            Err(TurnError::Invalid(_))
        ));
        let failed = fail_unfinished(db, &parked.turn_id, "member access revoked", 30).unwrap();
        assert_eq!(get(db, &parked.turn_id).unwrap(), Some(failed));
    }

    /// Claim, heartbeat and acknowledge one pending turn due at 5: the
    /// member never claims it, one claim holds at a time, a superseded
    /// fence is stale, and a retried ack keeps the first receipt.
    fn claim_contract(db: &RuntimeDb, namespace: &str, turn_id: &str) {
        let listed = list_claimable_maybe_resuming(db, namespace, 10, 0, true).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|turn| turn.turn_id.as_str())
                .collect::<Vec<_>>(),
            [turn_id]
        );
        assert!(
            list_claimable_maybe_resuming(db, namespace, 4, 0, true)
                .unwrap()
                .is_empty(),
            "not yet due"
        );
        assert!(matches!(
            claim_next_accepting_continuation(db, namespace, "rt-a", "alice", 1_000, 10, true),
            Err(TurnError::NotFound)
        ));
        assert!(matches!(
            claim_accepting_continuation(db, namespace, "rt-a", turn_id, "alice", 1_000, 10, true),
            Err(TurnError::Invalid(_))
        ));
        let first =
            claim_next_accepting_continuation(db, namespace, "rt-a", "worker", 1_000, 10, true)
                .unwrap();
        assert_eq!(
            (first.status.as_str(), first.claim_generation),
            (CLAIMED, 1)
        );
        assert!(matches!(
            claim_accepting_continuation(db, namespace, "rt-b", turn_id, "worker", 1_000, 20, true),
            Err(TurnError::NotClaimable)
        ));
        let lapsed = first.claim_expires_at_ms + 1;
        let second = claim_accepting_continuation(
            db, namespace, "rt-b", turn_id, "worker", 1_000, lapsed, true,
        )
        .unwrap();
        assert_eq!(
            (second.claim_owner.as_str(), second.claim_generation),
            ("rt-b", 2)
        );
        assert!(matches!(
            heartbeat(db, turn_id, "rt-a", 1, &first.fencing_token, 1_000, lapsed),
            Err(TurnError::StaleClaim)
        ));
        let beat = heartbeat(
            db,
            turn_id,
            "rt-b",
            2,
            &second.fencing_token,
            60_000,
            lapsed + 1,
        )
        .unwrap();
        assert!(beat.claim_expires_at_ms > second.claim_expires_at_ms);
        let done = acknowledge(
            db,
            turn_id,
            "rt-b",
            2,
            &second.fencing_token,
            Outcome::Completed,
            "answered",
            lapsed + 2,
        )
        .unwrap();
        assert!(done.is_finished());
        assert_eq!(
            (done.reason.as_str(), done.finished_at_ms),
            ("answered", lapsed + 2)
        );
        let retried = acknowledge(
            db,
            turn_id,
            "rt-b",
            2,
            &second.fencing_token,
            Outcome::Completed,
            "again",
            lapsed + 3,
        )
        .unwrap();
        assert_eq!(retried, done);
        assert!(
            list_claimable_maybe_resuming(db, namespace, lapsed + 4, 0, true)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fail_unfinished(db, turn_id, "revoked", lapsed + 5).unwrap(),
            done
        );
    }

    /// Revoking the member's access fails a claimed turn, which no worker
    /// can then claim or heartbeat.
    #[test]
    fn a_failed_unfinished_turn_ends_its_claim() {
        let db = runtime();
        let digest = published_revision(&db, "", true);
        let turn = admit(&db, admission(&digest, "triage", "req-1"), 10).unwrap();
        let claimed = claim_accepting_continuation(
            &db,
            "site",
            "rt",
            &turn.turn_id,
            "worker",
            1_000,
            10,
            true,
        )
        .unwrap();
        let failed = fail_unfinished(&db, &turn.turn_id, "member access revoked", 20).unwrap();
        assert_eq!(
            (failed.status.as_str(), failed.reason.as_str()),
            (FAILED, "member access revoked")
        );
        assert!(!failed.is_live_claim(20));
        assert!(matches!(
            heartbeat(
                &db,
                &turn.turn_id,
                "rt",
                1,
                &claimed.fencing_token,
                1_000,
                30
            ),
            Err(TurnError::StaleClaim)
        ));
        assert!(matches!(
            claim_accepting_continuation(
                &db,
                "site",
                "rt",
                &turn.turn_id,
                "worker",
                1_000,
                30,
                true
            ),
            Err(TurnError::NotClaimable)
        ));
    }

    /// A turn submits only the Action types its agent member allows at
    /// its revision.
    #[test]
    fn the_revision_bounds_the_action_types() {
        let db = runtime();
        let digest = published_revision(&db, "", true);
        let turn = admit(&db, admission(&digest, "triage", "req-1"), 10).unwrap();
        require_allowed_action_type(&db, &turn, "Ticket.inspect").unwrap();
        let refused = require_allowed_action_type(&db, &turn, "Ticket.close").unwrap_err();
        assert!(refused.contains("does not allow"), "{refused}");
    }

    #[test]
    fn sqlite_store_follows_the_contract() {
        store_contract(&runtime(), "site");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_store_follows_the_contract() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => {
                PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap())
            }
            Err(_) => PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(Arc::new(db.unwrap()));
        let namespace = format!("iturn-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        store_contract(&db, &namespace);
    }

    #[test]
    fn admission_requires_request_and_trace_ids() {
        let db = runtime();
        let digest = published_revision(&db, "", true);
        let mut missing_trace = admission(&digest, "triage", "req-1");
        missing_trace.trace_id = " ".into();
        let mut long_request = admission(&digest, "triage", &"r".repeat(MAX_REFERENCE_LEN + 1));
        long_request.trace_id = "trace".into();
        for request in [missing_trace, long_request] {
            assert!(matches!(
                admit(&db, request, 10),
                Err(TurnError::Invalid(_))
            ));
        }
    }
}
