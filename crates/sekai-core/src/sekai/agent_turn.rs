//! Agent-turn queue for site agent instances (ADR 0137, #1950).
//!
//! The plane owns which turns exist; workers pull them with the transform
//! claim contract: a claim carries a generation and a fencing token, a lapsed
//! claim may be reclaimed with a higher generation, and only the current
//! claim may heartbeat or acknowledge. A turn that lapses
//! [`MAX_TRANSFORM_LEASE_EXPIRIES`] times fails instead of looping.
//!
//! A turn's identity is its instance, cause and cause reference (schedule
//! due time, change window, or manual request id); admitting an identity
//! that exists returns the existing turn. Admission and claim refuse a
//! frozen instance and record the refusal on the decision ledger; Action
//! admission is the barrier that stops a frozen principal from acting, so a
//! turn granted concurrently with a freeze cannot act either. The turn
//! row is its receipt: it names the cause, the instance's principal it acts
//! as, and the outcome. Both stores keep turns; instances are written only
//! on SQLite until their parity slice (ADR 0136), so a PostgreSQL plane has
//! no instance to wake yet.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::db::postgres::{PostgresDb, off_runtime};
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::obs::signals::TransformPoolGauge;
use crate::sekai::audit;
use crate::sekai::governed_transform::{
    MAX_TRANSFORM_LEASE_EXPIRIES, normalize_transform_claim_ttl_ms,
};
use crate::sekai::site_agent_instance;

/// Execution profile of agent-turn queue gauges (ADR 0129, 0137).
pub const PROFILE: &str = "agent-turn";
/// Decision ledger action of a refused turn.
pub const REFUSED_DECISION: &str = "agent_turn.refused";

const PENDING: &str = "pending";
const CLAIMED: &str = "claimed";
const COMPLETED: &str = "completed";
const FAILED: &str = "failed";
const REFUSED: &str = "refused";
const PARKED: &str = "parked";
/// How often one turn may park on an Action before a further park fails it,
/// as for runtime work (ADR 0142).
pub const MAX_PARKS: i64 = 3;
const PARKED_TOO_OFTEN: &str = "parked too often";
const LEASE_EXHAUSTED: &str = "claim lapsed too often";

/// What woke the turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Schedule,
    ObjectChange,
    Manual,
}

impl Cause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schedule => "schedule",
            Self::ObjectChange => "object_change",
            Self::Manual => "manual",
        }
    }

    pub fn parse(value: &str) -> Result<Self, TurnError> {
        match value {
            "schedule" => Ok(Self::Schedule),
            "object_change" => Ok(Self::ObjectChange),
            "manual" => Ok(Self::Manual),
            other => Err(TurnError::Invalid(format!("unknown turn cause {other}"))),
        }
    }
}

/// How the worker finished a claimed turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    Failed,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Completed => COMPLETED,
            Self::Failed => FAILED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnError {
    NotFound,
    /// The instance is frozen; the refusal is on the decision ledger.
    Frozen(String),
    /// The turn is held by a live claim or already finished.
    NotClaimable,
    /// The caller's claim is not the current one.
    StaleClaim,
    Invalid(String),
    Internal(String),
}

impl std::fmt::Display for TurnError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("agent turn not found"),
            Self::Frozen(message) | Self::Invalid(message) | Self::Internal(message) => {
                formatter.write_str(message)
            }
            Self::NotClaimable => formatter.write_str("agent turn is not claimable"),
            Self::StaleClaim => formatter.write_str("stale agent turn claim"),
        }
    }
}

impl From<String> for TurnError {
    fn from(message: String) -> Self {
        Self::Internal(message)
    }
}

impl From<rusqlite::Error> for TurnError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<postgres::Error> for TurnError {
    fn from(error: postgres::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

/// A queued turn and, once finished, its receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTurn {
    pub turn_id: String,
    pub namespace: String,
    pub instance_id: String,
    /// The instance's principal at admission; the turn acts as it.
    pub principal_id: String,
    pub cause: Cause,
    /// Schedule due time, change window, or manual request id.
    pub cause_ref: String,
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
    /// The Action the turn parked on (ADR 0142); kept once the turn is
    /// reclaimed, so its claim carries the continuation.
    pub parked_action_id: String,
    /// How often the turn parked; at most [`MAX_PARKS`].
    pub park_count: i64,
}

impl AgentTurn {
    /// Whether the turn was acknowledged: completed, failed or parked.
    pub fn is_acknowledged(&self) -> bool {
        self.status == COMPLETED || self.status == FAILED || self.status == PARKED
    }

    /// Whether the turn is parked on an Action awaiting its decision.
    pub fn is_parked(&self) -> bool {
        self.status == PARKED
    }

    /// Whether the turn is claimed and its lease has not lapsed at `now_ms`.
    pub fn is_live_claim(&self, now_ms: i64) -> bool {
        self.status == CLAIMED && self.claim_expires_at_ms > now_ms
    }

    fn claimable(&self, now_ms: i64) -> bool {
        self.due_at_ms <= now_ms
            && match self.status.as_str() {
                PENDING => true,
                CLAIMED => self.claim_expires_at_ms <= now_ms,
                _ => false,
            }
    }

    fn fence_matches(&self, runtime_id: &str, generation: i64, fencing_token: &str) -> bool {
        !fencing_token.is_empty()
            && self.claim_owner == runtime_id
            && self.claim_generation == generation
            && self.fencing_token == fencing_token
    }
}

/// A turn to admit.
#[derive(Debug, Clone)]
pub struct Wake {
    pub namespace: String,
    pub instance_id: String,
    pub cause: Cause,
    pub cause_ref: String,
    pub due_at_ms: i64,
}

/// Admits `wake` as `actor`. An existing identity returns its turn unchanged.
pub fn admit(db: &RuntimeDb, wake: Wake, actor: &str, now_ms: i64) -> Result<AgentTurn, TurnError> {
    if wake.cause_ref.trim().is_empty() {
        return Err(TurnError::Invalid("cause_ref required".into()));
    }
    let turn_id = turn_id(&wake);
    if let Some(existing) = get(db, &turn_id)? {
        return Ok(existing);
    }
    let instance = instance(db, &wake.namespace, &wake.instance_id)?;
    let turn = AgentTurn {
        turn_id,
        principal_id: instance
            .properties
            .get("principal_id")
            .cloned()
            .unwrap_or_default(),
        namespace: wake.namespace,
        instance_id: wake.instance_id,
        cause: wake.cause,
        cause_ref: wake.cause_ref,
        due_at_ms: wake.due_at_ms,
        admitted_by: actor.into(),
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
    if let Err(message) = site_agent_instance::require_not_frozen(&instance) {
        refuse(db, &turn, actor, &message, now_ms)?;
        return Err(TurnError::Frozen(message));
    }
    match db {
        RuntimeDb::Sqlite(store) => store.insert_agent_turn(&turn),
        RuntimeDb::Postgres(store) => off_runtime(|| store.insert_agent_turn(&turn)),
    }?;
    // A concurrent admission of the same identity may have won.
    get(db, &turn.turn_id)?.ok_or(TurnError::NotFound)
}

/// The turn `turn_id`, if any.
pub fn get(db: &RuntimeDb, turn_id: &str) -> Result<Option<AgentTurn>, TurnError> {
    match db {
        RuntimeDb::Sqlite(store) => load(&store.conn(), turn_id),
        RuntimeDb::Postgres(store) => off_runtime(|| store.agent_turn(turn_id)),
    }
}

/// Due turns in `namespace` a worker may claim, oldest due first.
pub fn list_claimable(
    db: &RuntimeDb,
    namespace: &str,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<AgentTurn>, TurnError> {
    let cap = if limit <= 0 { 50 } else { limit.min(500) };
    let mut claimable = match db {
        RuntimeDb::Sqlite(store) => store.claimable_agent_turns(namespace, now_ms, cap)?,
        RuntimeDb::Postgres(store) => {
            off_runtime(|| store.claimable_agent_turns(namespace, now_ms, cap))?
        }
    };
    // A parked turn is listed once its Action is decided. Parked turns are
    // read on their own, so ones still awaiting a decision never crowd out
    // claimable turns or decided parks behind them.
    claimable.extend(decided_parked_turns(db, Some(namespace), cap)?);
    claimable.sort_by(|left, right| {
        (left.due_at_ms, &left.turn_id).cmp(&(right.due_at_ms, &right.turn_id))
    });
    claimable.truncate(usize::try_from(cap).unwrap_or(usize::MAX));
    Ok(claimable)
}

/// Up to `want` parked turns, of `namespace` or of every namespace, whose
/// Action's decision stands, oldest due first. The store selects only parks
/// whose Action left `parked` or is gone, so turns still awaiting approval
/// cost nothing however many there are; the durable check then reads just
/// those, normally already-decided Actions.
fn decided_parked_turns(
    db: &RuntimeDb,
    namespace: Option<&str>,
    want: i64,
) -> Result<Vec<AgentTurn>, TurnError> {
    const PAGE: i64 = 200;
    let mut decided = Vec::new();
    let mut offset = 0;
    while i64::try_from(decided.len()).unwrap_or(i64::MAX) < want {
        let page = match db {
            RuntimeDb::Sqlite(store) => store.resuming_agent_turns(namespace, offset, PAGE)?,
            RuntimeDb::Postgres(store) => {
                off_runtime(|| store.resuming_agent_turns(namespace, offset, PAGE))?
            }
        };
        let read = i64::try_from(page.len()).unwrap_or(i64::MAX);
        for turn in page {
            if parked_action_decided(db, &turn.parked_action_id)? {
                decided.push(turn);
            }
        }
        if read < PAGE {
            break;
        }
        offset = offset.saturating_add(read);
    }
    decided.truncate(usize::try_from(want).unwrap_or(usize::MAX));
    Ok(decided)
}

/// Whether the Action a turn parked on has a decision that stands (ADR
/// 0142): it is gone, denied, or past `parked` with the approval recorded on
/// its receipt. A grant whose recording fails is undone and parked again,
/// so an Action's status alone is not yet a decision.
fn parked_action_decided(db: &RuntimeDb, action_id: &str) -> Result<bool, TurnError> {
    use crate::sekai::action_instance::{STATUS_DENIED, STATUS_PARKED};
    let Some(action) = db.get_action_instance(action_id)? else {
        return Ok(true);
    };
    if action.status == STATUS_PARKED {
        return Ok(false);
    }
    if action.status == STATUS_DENIED {
        return Ok(true);
    }
    Ok(db
        .get_operation_receipt(&action.operation_id)?
        .is_some_and(|receipt| {
            receipt
                .events
                .iter()
                .any(|event| event.kind == sekai_domain::receipt::ReceiptEventKind::ApprovalDecided)
        }))
}

/// Parks the turn under its current, unexpired claim on `action_id`, an
/// Action the turn submitted under this claim that parked for approval
/// (ADR 0142). Approval may already stand; the turn still records the
/// Action as its continuation and is then immediately resumable. The claim
/// ends; the turn is claimable again once the Action is decided. A retry
/// with the same claim and Action returns the same receipt. A turn parked
/// [`MAX_PARKS`] times fails instead.
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
) -> Result<AgentTurn, TurnError> {
    // Read before the turn's transaction, whose connection is not reentrant.
    // A grant may land after submit returns parked and before this
    // acknowledgement; a standing decision still lets the turn record its
    // continuation.
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
        if !turn.fence_matches(runtime_id, claim_generation, fencing_token) {
            return Err(TurnError::StaleClaim);
        }
        // A retry of this park replays its receipt, the failing fourth one
        // included.
        let parked_here =
            turn.is_parked() || (turn.status == FAILED && turn.reason == PARKED_TOO_OFTEN);
        if parked_here && turn.parked_action_id == action_id {
            return Ok(());
        }
        if turn.status != CLAIMED || turn.claim_expires_at_ms <= now_ms {
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

/// Claims `turn_id` for `runtime_id`. A turn whose instance is frozen since
/// admission is refused, audited, and never claimable again.
pub fn claim(
    db: &RuntimeDb,
    namespace: &str,
    runtime_id: &str,
    turn_id: &str,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<AgentTurn, TurnError> {
    if runtime_id.trim().is_empty() {
        return Err(TurnError::Invalid("runtime_id required".into()));
    }
    let turn = get(db, turn_id)?
        .filter(|turn| turn.namespace == namespace)
        .ok_or(TurnError::NotFound)?;
    // Read before the claim transaction: the store's connection is not
    // reentrant. A claim concurrent with a freeze may still be granted; the
    // turn acts only through its principal's Actions, which admission
    // refuses while the instance is frozen (#1934), so it cannot act.
    let instance = match instance(db, namespace, &turn.instance_id) {
        // A deleted instance's turn ends, so it cannot stall the queue.
        Err(TurnError::NotFound) => {
            retire(db, turn_id, "site agent instance is gone", now_ms)?;
            return Err(TurnError::NotFound);
        }
        found => found?,
    };
    if let Err(message) = site_agent_instance::require_not_frozen(&instance) {
        // Audit first: a crash before the turn ends leaves it claimable, and
        // the next claim finds the refusal recorded and ends it.
        if turn.claimable(now_ms) || turn.is_parked() {
            refuse(db, &turn, runtime_id, &message, now_ms)?;
            retire(db, turn_id, &message, now_ms)?;
        }
        return Err(TurnError::Frozen(message));
    }
    // A parked turn is claimable again once its Action is decided; read
    // here, outside the claim's transaction. A decision never reverts, so
    // a turn found resumable stays so (ADR 0142).
    let resumes = turn.is_parked() && parked_action_decided(db, &turn.parked_action_id)?;
    if turn.is_parked() && !resumes {
        return Err(TurnError::NotClaimable);
    }
    let checked = (turn.claim_generation, turn.parked_action_id.clone());
    let mut exhausted = false;
    let claimed = edit(db, turn_id, |turn| {
        // Resume only the park whose decision was read: a turn reclaimed and
        // parked again meanwhile waits on its new Action.
        let resuming = resumes
            && turn.is_parked()
            && (turn.claim_generation, &turn.parked_action_id) == (checked.0, &checked.1);
        if !resuming && !turn.claimable(now_ms) {
            return Err(TurnError::NotClaimable);
        }
        if turn.status == CLAIMED {
            turn.lease_expiries += 1;
            if turn.lease_expiries >= MAX_TRANSFORM_LEASE_EXPIRIES {
                exhausted = true;
                turn.status = FAILED.into();
                turn.reason = LEASE_EXHAUSTED.into();
                turn.finished_at_ms = now_ms;
                turn.claim_expires_at_ms = 0;
                return Ok(());
            }
        }
        turn.status = CLAIMED.into();
        turn.claim_owner = runtime_id.into();
        turn.claim_generation += 1;
        turn.fencing_token = uuid::Uuid::new_v4().to_string();
        turn.claim_expires_at_ms = now_ms.saturating_add(normalize_transform_claim_ttl_ms(ttl_ms));
        Ok(())
    })?;
    if exhausted {
        return Err(TurnError::NotClaimable);
    }
    Ok(claimed)
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
) -> Result<AgentTurn, TurnError> {
    edit(db, turn_id, |turn| {
        if turn.status != CLAIMED
            || turn.claim_expires_at_ms <= now_ms
            || !turn.fence_matches(runtime_id, claim_generation, fencing_token)
        {
            return Err(TurnError::StaleClaim);
        }
        turn.claim_expires_at_ms = now_ms.saturating_add(normalize_transform_claim_ttl_ms(ttl_ms));
        Ok(())
    })
}

/// Finishes the turn under the current, unexpired claim and returns its
/// receipt. A retry with the same claim and outcome returns the same receipt.
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
) -> Result<AgentTurn, TurnError> {
    edit(db, turn_id, |turn| {
        if !turn.fence_matches(runtime_id, claim_generation, fencing_token) {
            return Err(TurnError::StaleClaim);
        }
        if turn.status == outcome.as_str() {
            return Ok(());
        }
        if turn.status != CLAIMED || turn.claim_expires_at_ms <= now_ms {
            return Err(TurnError::StaleClaim);
        }
        turn.status = outcome.as_str().into();
        turn.reason = reason.into();
        turn.finished_at_ms = now_ms;
        turn.claim_expires_at_ms = 0;
        Ok(())
    })
}

/// Queue depth of the `agent-turn` profile as one `default` pool. Carries
/// no tenant or namespace label. Queued counts every unfinished turn no live
/// claim holds; claimable those already due.
pub fn pool_gauge(db: &RuntimeDb, now_ms: i64) -> Result<TransformPoolGauge, TurnError> {
    let (mut queued, mut claimable, mut oldest_due) = match db {
        RuntimeDb::Sqlite(store) => store.agent_turn_depth(now_ms),
        RuntimeDb::Postgres(store) => off_runtime(|| store.agent_turn_depth(now_ms)),
    }?;
    // A parked turn whose Action is decided is runnable work too; one still
    // awaiting approval is not (ADR 0142).
    for turn in decided_parked_turns(db, None, i64::MAX)? {
        queued += 1;
        claimable += 1;
        oldest_due = Some(oldest_due.map_or(turn.due_at_ms, |due| due.min(turn.due_at_ms)));
    }
    Ok(TransformPoolGauge {
        pool: "default".into(),
        queued,
        claimable,
        oldest_claimable_age_seconds: oldest_due
            .map_or(0.0, |due| now_ms.saturating_sub(due).max(0) as f64 / 1000.0),
    })
}

/// Ends a turn no live claim holds as refused with `reason`; a held or
/// finished turn is left alone.
fn retire(db: &RuntimeDb, turn_id: &str, reason: &str, now_ms: i64) -> Result<(), TurnError> {
    let ended = edit(db, turn_id, |turn| {
        // A parked turn holds no claim either; it ends with its instance.
        if !turn.claimable(now_ms) && !turn.is_parked() {
            return Err(TurnError::NotClaimable);
        }
        turn.status = REFUSED.into();
        turn.reason = reason.into();
        turn.finished_at_ms = now_ms;
        turn.claim_expires_at_ms = 0;
        Ok(())
    });
    match ended {
        Ok(_) | Err(TurnError::NotClaimable) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Loads, edits and persists one turn under a row lock.
fn edit(
    db: &RuntimeDb,
    turn_id: &str,
    change: impl FnOnce(&mut AgentTurn) -> Result<(), TurnError>,
) -> Result<AgentTurn, TurnError> {
    match db {
        RuntimeDb::Sqlite(store) => store.edit_agent_turn(turn_id, change),
        RuntimeDb::Postgres(store) => off_runtime(|| store.edit_agent_turn(turn_id, change)),
    }
}

fn turn_id(wake: &Wake) -> String {
    let mut hasher = Sha256::new();
    for part in [
        wake.namespace.as_str(),
        wake.instance_id.as_str(),
        wake.cause.as_str(),
        wake.cause_ref.as_str(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("turn-{:x}", hasher.finalize())
}

fn instance(
    db: &RuntimeDb,
    namespace: &str,
    instance_id: &str,
) -> Result<crate::domain::Object, TurnError> {
    db.get_object(instance_id)?
        .filter(|object| object.kind == site_agent_instance::KIND && object.namespace == namespace)
        .ok_or(TurnError::NotFound)
}

/// Records a refused turn once per turn identity: a repeated wake of a
/// frozen instance, or a racing plane, finds the first refusal and stops.
fn refuse(
    db: &RuntimeDb,
    turn: &AgentTurn,
    actor: &str,
    message: &str,
    now_ms: i64,
) -> Result<(), String> {
    let id = format!("{REFUSED_DECISION}:{}", turn.turn_id);
    if db.get_decision(&id)?.is_some() {
        return Ok(());
    }
    let recorded = db.record_decision(&audit::Decision {
        id: id.clone(),
        timestamp: now_ms,
        actor: actor.into(),
        action: REFUSED_DECISION.into(),
        reason: message.into(),
        evidence: HashMap::from([
            ("namespace".to_string(), turn.namespace.clone()),
            ("cause".to_string(), turn.cause.as_str().to_string()),
            ("cause_ref".to_string(), turn.cause_ref.clone()),
            ("principal_id".to_string(), turn.principal_id.clone()),
        ]),
        target_id: turn.instance_id.clone(),
        outcome: "deny".into(),
    });
    match recorded {
        Err(_) if db.get_decision(&id)?.is_some() => Ok(()),
        other => other,
    }
}

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_agent_turn (
    turn_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    cause TEXT NOT NULL,
    cause_ref TEXT NOT NULL,
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
CREATE INDEX IF NOT EXISTS sekai_agent_turn_queue
    ON sekai_agent_turn (status, due_at_ms);
";

const COLUMNS: &str = "turn_id, namespace, instance_id, principal_id, cause, cause_ref, due_at_ms,
    admitted_by, status, claim_owner, claim_generation, fencing_token, claim_expires_at_ms,
    lease_expiries, created_at_ms, finished_at_ms, reason, parked_action_id, park_count";

/// [`COLUMNS`] of the `turn` alias, for queries that join the turn table.
fn qualified_columns() -> String {
    COLUMNS
        .split(',')
        .map(|column| format!("turn.{}", column.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn map_turn(row: &Row<'_>) -> rusqlite::Result<AgentTurn> {
    let cause: String = row.get(4)?;
    Ok(AgentTurn {
        turn_id: row.get(0)?,
        namespace: row.get(1)?,
        instance_id: row.get(2)?,
        principal_id: row.get(3)?,
        cause: Cause::parse(&cause).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                error.to_string().into(),
            )
        })?,
        cause_ref: row.get(5)?,
        due_at_ms: row.get(6)?,
        admitted_by: row.get(7)?,
        status: row.get(8)?,
        claim_owner: row.get(9)?,
        claim_generation: row.get(10)?,
        fencing_token: row.get(11)?,
        claim_expires_at_ms: row.get(12)?,
        lease_expiries: row.get(13)?,
        created_at_ms: row.get(14)?,
        finished_at_ms: row.get(15)?,
        reason: row.get(16)?,
        parked_action_id: row.get(17)?,
        park_count: row.get(18)?,
    })
}

fn load(conn: &rusqlite::Connection, turn_id: &str) -> Result<Option<AgentTurn>, TurnError> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM sekai_agent_turn WHERE turn_id = ?1"),
            params![turn_id],
            map_turn,
        )
        .optional()?)
}

fn persist(conn: &rusqlite::Connection, turn: &AgentTurn) -> Result<(), TurnError> {
    conn.execute(
        "UPDATE sekai_agent_turn SET status = ?2, claim_owner = ?3, claim_generation = ?4,
             fencing_token = ?5, claim_expires_at_ms = ?6, lease_expiries = ?7,
             finished_at_ms = ?8, reason = ?9, parked_action_id = ?10, park_count = ?11
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
    Ok(())
}

impl SekaiDb {
    pub(crate) fn migrate_agent_turns(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())?;
        // Parked turns (ADR 0142), added in place on an existing table.
        for (column, definition) in [
            ("parked_action_id", "TEXT NOT NULL DEFAULT ''"),
            ("park_count", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let present: bool = self
                .conn()
                .query_row(
                    "SELECT COUNT(*) > 0 FROM pragma_table_info('sekai_agent_turn')
                     WHERE name = ?1",
                    params![column],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if !present {
                self.conn()
                    .execute(
                        &format!("ALTER TABLE sekai_agent_turn ADD COLUMN {column} {definition}"),
                        [],
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    fn insert_agent_turn(&self, turn: &AgentTurn) -> Result<(), TurnError> {
        self.conn().execute(
            &format!(
                "INSERT INTO sekai_agent_turn ({COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                         ?18, ?19)
                 ON CONFLICT(turn_id) DO NOTHING"
            ),
            params![
                turn.turn_id,
                turn.namespace,
                turn.instance_id,
                turn.principal_id,
                turn.cause.as_str(),
                turn.cause_ref,
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

    fn claimable_agent_turns(
        &self,
        namespace: &str,
        now_ms: i64,
        limit: i64,
    ) -> Result<Vec<AgentTurn>, TurnError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM sekai_agent_turn
             WHERE namespace = ?1 AND due_at_ms <= ?2
               AND (status = '{PENDING}' OR (status = '{CLAIMED}' AND claim_expires_at_ms <= ?2))
             ORDER BY due_at_ms, turn_id
             LIMIT ?3"
        ))?;
        let rows = stmt.query_map(params![namespace, now_ms, limit], map_turn)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Parked turns of `namespace`, or of every namespace, whose Action left
    /// `parked` or is gone, oldest due first (ADR 0142).
    fn resuming_agent_turns(
        &self,
        namespace: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<AgentTurn>, TurnError> {
        // The Action table is created on first use; a parked turn has one.
        self.migrate_action_instances()?;
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {} FROM sekai_agent_turn turn
             LEFT JOIN sekai_action_instances action
               ON action.instance_id = turn.parked_action_id
             WHERE (?1 IS NULL OR turn.namespace = ?1) AND turn.status = '{PARKED}'
               AND (action.instance_id IS NULL OR action.status != '{}')
             ORDER BY turn.due_at_ms, turn.turn_id
             LIMIT ?3 OFFSET ?2",
            qualified_columns(),
            crate::sekai::action_instance::STATUS_PARKED
        ))?;
        let rows = stmt.query_map(params![namespace, offset, limit], map_turn)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    fn edit_agent_turn(
        &self,
        turn_id: &str,
        change: impl FnOnce(&mut AgentTurn) -> Result<(), TurnError>,
    ) -> Result<AgentTurn, TurnError> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut turn = load(&tx, turn_id)?.ok_or(TurnError::NotFound)?;
        change(&mut turn)?;
        persist(&tx, &turn)?;
        tx.commit()?;
        Ok(turn)
    }

    /// `(queued, claimable, oldest claimable due time)`; see [`pool_gauge`].
    fn agent_turn_depth(&self, now_ms: i64) -> Result<(u64, u64, Option<i64>), TurnError> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT COUNT(*),
                            COALESCE(SUM(due_at_ms <= ?1), 0),
                            MIN(CASE WHEN due_at_ms <= ?1 THEN due_at_ms END)
                     FROM sekai_agent_turn
                     WHERE status = '{PENDING}'
                        OR (status = '{CLAIMED}' AND claim_expires_at_ms <= ?1)"
                ),
                params![now_ms],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u64,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .map_err(TurnError::from)
    }
}

fn pg_turn(row: &postgres::Row) -> Result<AgentTurn, TurnError> {
    Ok(AgentTurn {
        turn_id: row.try_get(0)?,
        namespace: row.try_get(1)?,
        instance_id: row.try_get(2)?,
        principal_id: row.try_get(3)?,
        cause: Cause::parse(row.try_get(4)?)?,
        cause_ref: row.try_get(5)?,
        due_at_ms: row.try_get(6)?,
        admitted_by: row.try_get(7)?,
        status: row.try_get(8)?,
        claim_owner: row.try_get(9)?,
        claim_generation: row.try_get(10)?,
        fencing_token: row.try_get(11)?,
        claim_expires_at_ms: row.try_get(12)?,
        lease_expiries: row.try_get(13)?,
        created_at_ms: row.try_get(14)?,
        finished_at_ms: row.try_get(15)?,
        reason: row.try_get(16)?,
        parked_action_id: row.try_get(17)?,
        park_count: row.try_get(18)?,
    })
}

impl PostgresDb {
    fn agent_turn(&self, turn_id: &str) -> Result<Option<AgentTurn>, TurnError> {
        self.connection()?
            .query_opt(
                &format!("SELECT {COLUMNS} FROM sekai_agent_turn WHERE turn_id = $1"),
                &[&turn_id],
            )?
            .as_ref()
            .map(pg_turn)
            .transpose()
    }

    fn insert_agent_turn(&self, turn: &AgentTurn) -> Result<(), TurnError> {
        self.connection()?.execute(
            &format!(
                "INSERT INTO sekai_agent_turn ({COLUMNS})
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                         $18, $19)
                 ON CONFLICT (turn_id) DO NOTHING"
            ),
            &[
                &turn.turn_id,
                &turn.namespace,
                &turn.instance_id,
                &turn.principal_id,
                &turn.cause.as_str(),
                &turn.cause_ref,
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

    fn claimable_agent_turns(
        &self,
        namespace: &str,
        now_ms: i64,
        limit: i64,
    ) -> Result<Vec<AgentTurn>, TurnError> {
        self.connection()?
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM sekai_agent_turn
                     WHERE namespace = $1 AND due_at_ms <= $2
                       AND (status = '{PENDING}'
                            OR (status = '{CLAIMED}' AND claim_expires_at_ms <= $2))
                     ORDER BY due_at_ms, turn_id
                     LIMIT $3"
                ),
                &[&namespace, &now_ms, &limit],
            )?
            .iter()
            .map(pg_turn)
            .collect()
    }

    /// See the SQLite store.
    fn resuming_agent_turns(
        &self,
        namespace: Option<&str>,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<AgentTurn>, TurnError> {
        self.connection()?
            .query(
                &format!(
                    "SELECT {} FROM sekai_agent_turn turn
                     LEFT JOIN sekai_action_instances action
                       ON action.instance_id = turn.parked_action_id
                     WHERE ($1::TEXT IS NULL OR turn.namespace = $1)
                       AND turn.status = '{PARKED}'
                       AND (action.instance_id IS NULL OR action.status != '{}')
                     ORDER BY turn.due_at_ms, turn.turn_id
                     LIMIT $3 OFFSET $2",
                    qualified_columns(),
                    crate::sekai::action_instance::STATUS_PARKED
                ),
                &[&namespace, &offset, &limit],
            )?
            .iter()
            .map(pg_turn)
            .collect()
    }

    fn edit_agent_turn(
        &self,
        turn_id: &str,
        change: impl FnOnce(&mut AgentTurn) -> Result<(), TurnError>,
    ) -> Result<AgentTurn, TurnError> {
        let mut connection = self.connection()?;
        let mut tx = connection.transaction()?;
        let row = tx
            .query_opt(
                &format!("SELECT {COLUMNS} FROM sekai_agent_turn WHERE turn_id = $1 FOR UPDATE"),
                &[&turn_id],
            )?
            .ok_or(TurnError::NotFound)?;
        let mut turn = pg_turn(&row)?;
        change(&mut turn)?;
        tx.execute(
            "UPDATE sekai_agent_turn SET status = $2, claim_owner = $3, claim_generation = $4,
                 fencing_token = $5, claim_expires_at_ms = $6, lease_expiries = $7,
                 finished_at_ms = $8, reason = $9, parked_action_id = $10, park_count = $11
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

    fn agent_turn_depth(&self, now_ms: i64) -> Result<(u64, u64, Option<i64>), TurnError> {
        let row = self.connection()?.query_one(
            &format!(
                "SELECT COUNT(*),
                        COUNT(*) FILTER (WHERE due_at_ms <= $1),
                        MIN(due_at_ms) FILTER (WHERE due_at_ms <= $1)
                 FROM sekai_agent_turn
                 WHERE status = '{PENDING}'
                    OR (status = '{CLAIMED}' AND claim_expires_at_ms <= $1)"
            ),
            &[&now_ms],
        )?;
        Ok((
            row.try_get::<_, i64>(0)?.max(0) as u64,
            row.try_get::<_, i64>(1)?.max(0) as u64,
            row.try_get(2)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::audit::DecisionFilter;

    /// Seeds instance `{ns}-{name}`; ids are global, so the namespace keeps
    /// concurrent runs on one PostgreSQL database apart.
    fn seed(db: &RuntimeDb, ns: &str, name: &str, frozen: bool) -> String {
        let id = format!("{ns}-{name}");
        db.create_object(&crate::domain::Object {
            id: id.clone(),
            kind: site_agent_instance::KIND.into(),
            name: name.into(),
            namespace: ns.into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("principal_id".to_string(), format!("agent:{id}")),
                (
                    site_agent_instance::FROZEN_PROPERTY.to_string(),
                    frozen.to_string(),
                ),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
        id
    }

    fn wake(ns: &str, instance: &str, cause: Cause, cause_ref: &str) -> Wake {
        Wake {
            namespace: ns.into(),
            instance_id: instance.into(),
            cause,
            cause_ref: cause_ref.into(),
            due_at_ms: 100,
        }
    }

    fn refusals(db: &RuntimeDb, instance: &str) -> Vec<audit::Decision> {
        db.list_decisions(&DecisionFilter {
            action: Some(REFUSED_DECISION.into()),
            target_id: Some(instance.into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap()
    }

    fn freeze(db: &RuntimeDb, instance: &str) {
        let mut object = db.get_object(instance).unwrap().unwrap();
        object
            .properties
            .insert(site_agent_instance::FROZEN_PROPERTY.into(), "true".into());
        db.update_object(&object).unwrap();
    }

    /// The queue contract on one store: one turn per identity, a fenced
    /// claim that a lapse hands to a higher generation, a receipt naming the
    /// cause, and audited refusals of a frozen instance.
    fn turn_contract(db: &RuntimeDb, ns: &str) {
        let line = seed(db, ns, "line", false);
        let first = admit(db, wake(ns, &line, Cause::Schedule, "100"), "plane", 1).unwrap();
        let again = admit(db, wake(ns, &line, Cause::Schedule, "100"), "plane", 2).unwrap();
        assert_eq!(first, again, "an existing identity is a no-op");
        assert_eq!(first.principal_id, format!("agent:{line}"));
        let manual = admit(db, wake(ns, &line, Cause::Manual, "req-1"), "op", 3).unwrap();
        assert_ne!(manual.turn_id, first.turn_id);
        assert!(
            list_claimable(db, ns, 99, 10).unwrap().is_empty(),
            "not due"
        );
        assert_eq!(list_claimable(db, ns, 100, 10).unwrap().len(), 2);
        assert!(
            list_claimable(db, &format!("{ns}-other"), 100, 10)
                .unwrap()
                .is_empty()
        );

        // A lapsed claim is reclaimed; the stale claim cannot write back.
        let held = claim(db, ns, "worker-a", &first.turn_id, 1_000, 100).unwrap();
        assert_eq!(
            claim(db, ns, "worker-b", &first.turn_id, 1_000, 500),
            Err(TurnError::NotClaimable),
            "a live claim is held"
        );
        let taken = claim(db, ns, "worker-b", &first.turn_id, 1_000, 1_100).unwrap();
        assert!(taken.claim_generation > held.claim_generation);
        assert_eq!(
            heartbeat(
                db,
                &first.turn_id,
                "worker-a",
                held.claim_generation,
                &held.fencing_token,
                1_000,
                1_200
            ),
            Err(TurnError::StaleClaim)
        );
        let ack = |fence: &AgentTurn, at| {
            acknowledge(
                db,
                &first.turn_id,
                &fence.claim_owner,
                fence.claim_generation,
                &fence.fencing_token,
                Outcome::Completed,
                "done",
                at,
            )
        };
        assert_eq!(ack(&held, 1_200), Err(TurnError::StaleClaim));
        let kept = heartbeat(
            db,
            &first.turn_id,
            "worker-b",
            taken.claim_generation,
            &taken.fencing_token,
            1_000,
            1_500,
        )
        .unwrap();
        assert_eq!(kept.claim_expires_at_ms, 2_500);
        let receipt = ack(&taken, 1_600).unwrap();
        assert_eq!(
            (
                receipt.cause,
                receipt.cause_ref.as_str(),
                receipt.status.as_str()
            ),
            (Cause::Schedule, "100", COMPLETED)
        );
        assert_eq!(ack(&taken, 1_700).unwrap(), receipt, "a retried ack");

        // A lapsed claim cannot finish the turn even before a reclaim.
        let lapsing = claim(db, ns, "worker-c", &manual.turn_id, 1_000, 1_700).unwrap();
        assert_eq!(
            acknowledge(
                db,
                &manual.turn_id,
                "worker-c",
                lapsing.claim_generation,
                &lapsing.fencing_token,
                Outcome::Completed,
                "late",
                2_700,
            ),
            Err(TurnError::StaleClaim)
        );

        // A frozen instance's manual wake is refused and audited once.
        let frozen = seed(db, ns, "frozen", true);
        for at in [1, 2] {
            assert!(matches!(
                admit(db, wake(ns, &frozen, Cause::Manual, "req-1"), "op", at),
                Err(TurnError::Frozen(_))
            ));
        }
        let refused = refusals(db, &frozen);
        assert_eq!(refused.len(), 1, "one decision per refused identity");
        assert_eq!(refused[0].evidence["cause"], "manual");

        // A freeze after admission refuses the turn at claim.
        freeze(db, &line);
        assert!(matches!(
            claim(db, ns, "worker", &manual.turn_id, 1_000, 3_000),
            Err(TurnError::Frozen(_))
        ));
        assert_eq!(refusals(db, &line).len(), 1);
        assert!(list_claimable(db, ns, 3_000, 10).unwrap().is_empty());

        // A deleted instance's turn is retired at claim, not left queued.
        let gone = seed(db, ns, "gone", false);
        let orphan = admit(db, wake(ns, &gone, Cause::Manual, "req-2"), "op", 4).unwrap();
        db.delete_object(&gone).unwrap();
        assert_eq!(
            claim(db, ns, "worker", &orphan.turn_id, 1_000, 3_000),
            Err(TurnError::NotFound)
        );
        assert!(list_claimable(db, ns, 3_000, 10).unwrap().is_empty());
    }

    /// An Action of `instance`'s principal in `ns`, submitted under `turn`'s
    /// claim at `generation`, that parked for approval.
    fn parked_action(db: &RuntimeDb, ns: &str, turn: &AgentTurn, tag: &str) -> String {
        let mut action = crate::sekai::action_instance::sample_for_test(
            crate::sekai::action_instance::STATUS_PARKED,
        );
        action.instance_id = format!("{ns}-action-{tag}");
        action.namespace = ns.into();
        action.principal = turn.principal_id.clone();
        action.idempotency_key = format!("{ns}-key-{tag}");
        action.operation_id = format!("{ns}-op-{tag}");
        action.agent_turn = Some(crate::sekai::action_instance::AgentTurnFence {
            turn_id: turn.turn_id.clone(),
            claim_generation: u64::try_from(turn.claim_generation).unwrap(),
        });
        db.put_action_instance(&action).unwrap();
        action.instance_id
    }

    /// Decides a parked Action as `status`, as an approver's decision does:
    /// a grant also records the decision on the Action's receipt, the point
    /// after which it is no longer undone.
    fn decide(db: &RuntimeDb, action_id: &str, status: &str) {
        if status != crate::sekai::action_instance::STATUS_DENIED {
            let action = db.get_action_instance(action_id).unwrap().unwrap();
            db.put_operation_receipt(&sekai_domain::receipt::OperationReceipt {
                version: sekai_domain::receipt::OPERATION_RECEIPT_VERSION.into(),
                operation_id: action.operation_id.clone(),
                parent_operation_id: None,
                namespace: action.namespace.clone(),
                operation_class: "action_instance".into(),
                initiating_actor: "approver".into(),
                schema_version: "v1".into(),
                policy_version: "v1".into(),
                started_at_ms: 1,
                completed_at_ms: None,
                events: vec![sekai_domain::receipt::OperationReceiptEvent {
                    event_id: format!("{action_id}-decided"),
                    operation_id: action.operation_id,
                    parent_event_id: None,
                    timestamp_ms: 1,
                    kind: sekai_domain::receipt::ReceiptEventKind::ApprovalDecided,
                    surface: sekai_domain::receipt::ReceiptSurface::Approval,
                    actor: "approver".into(),
                    references: Vec::new(),
                    attributes: Default::default(),
                }],
                uncovered_surfaces: vec![],
                reporter_grants: vec![],
                ontology_digest: None,
                artifact: None,
            })
            .unwrap();
        }
        decide_status_only(db, action_id, status);
    }

    /// Moves a parked Action to `status` without recording a decision.
    fn decide_status_only(db: &RuntimeDb, action_id: &str, status: &str) {
        match db {
            RuntimeDb::Sqlite(store) => {
                store
                    .conn()
                    .execute(
                        "UPDATE sekai_action_instances
                         SET status = ?2, body_json = json_set(body_json, '$.status', ?2)
                         WHERE instance_id = ?1",
                        params![action_id, status],
                    )
                    .unwrap();
            }
            RuntimeDb::Postgres(store) => {
                store
                    .connection()
                    .unwrap()
                    .execute(
                        "UPDATE sekai_action_instances
                         SET status = $2,
                             body_json = jsonb_set(body_json::jsonb, '{status}', to_jsonb($2::text))::text
                         WHERE instance_id = $1",
                        &[&action_id, &status],
                    )
                    .unwrap();
            }
        }
    }

    /// Parking on one store (ADR 0142): a turn parks only on an Action it
    /// submitted under its claim that awaits approval or whose decision
    /// already stands, is not claimable until that Action is decided, then
    /// resumes at a new generation with the parked Action named; a retry
    /// replays; a fourth park fails it.
    fn park_contract(db: &RuntimeDb, ns: &str) {
        let line = seed(db, ns, "parker", false);
        let turn = admit(db, wake(ns, &line, Cause::Manual, "park"), "plane", 1).unwrap();
        let mut now = 100;
        let mut held = claim(db, ns, "runner-a", &turn.turn_id, 1_000, now).unwrap();
        let fence = |held: &AgentTurn| {
            (
                held.claim_owner.clone(),
                held.claim_generation,
                held.fencing_token.clone(),
            )
        };

        // Not an Action of this claim: refused.
        let mut other_claim = held.clone();
        other_claim.claim_generation += 7;
        let foreign = parked_action(db, ns, &other_claim, "foreign");
        let (owner, generation, token) = fence(&held);
        assert!(matches!(
            park(
                db,
                &turn.turn_id,
                &owner,
                generation,
                &token,
                &foreign,
                "awaiting approval",
                now
            ),
            Err(TurnError::Invalid(_))
        ));

        for round in 1..=MAX_PARKS {
            let action = parked_action(db, ns, &held, &format!("round-{round}"));
            let (owner, generation, token) = fence(&held);
            let parked = park(
                db,
                &turn.turn_id,
                &owner,
                generation,
                &token,
                &action,
                "awaiting approval",
                now,
            )
            .unwrap();
            assert!(parked.is_parked());
            assert_eq!(parked.reason, "awaiting approval");
            assert_eq!(
                (parked.parked_action_id.as_str(), parked.park_count),
                (action.as_str(), round)
            );
            // A retry with the same claim and Action replays the receipt.
            assert_eq!(
                park(
                    db,
                    &turn.turn_id,
                    &owner,
                    generation,
                    &token,
                    &action,
                    "awaiting approval",
                    now
                )
                .unwrap(),
                parked
            );
            // Awaiting its decision, the turn is neither listed nor claimable.
            now += 10;
            assert!(list_claimable(db, ns, now, 10).unwrap().is_empty());
            assert_eq!(
                claim(db, ns, "runner-b", &turn.turn_id, 1_000, now).unwrap_err(),
                TurnError::NotClaimable
            );
            // Admitted but not yet recorded, a grant may still be undone:
            // the turn waits.
            decide_status_only(db, &action, "admitted");
            assert!(list_claimable(db, ns, now, 10).unwrap().is_empty());
            // Once decided it resumes at a new generation, naming the Action.
            decide(db, &action, "admitted");
            assert_eq!(list_claimable(db, ns, now, 10).unwrap().len(), 1);
            let resumed = claim(db, ns, "runner-b", &turn.turn_id, 1_000, now).unwrap();
            assert_eq!(resumed.claim_generation, held.claim_generation + 1);
            assert_eq!(resumed.parked_action_id, action);
            held = resumed;
        }

        // A further park fails the turn.
        let last = parked_action(db, ns, &held, "last");
        let (owner, generation, token) = fence(&held);
        let failed = park(
            db,
            &turn.turn_id,
            &owner,
            generation,
            &token,
            &last,
            "awaiting approval",
            now,
        )
        .unwrap();
        assert_eq!(
            (failed.status.as_str(), failed.reason.as_str()),
            (FAILED, PARKED_TOO_OFTEN)
        );
        // A lost response to it is retried to the same receipt.
        assert_eq!(
            park(
                db,
                &turn.turn_id,
                &owner,
                generation,
                &token,
                &last,
                "awaiting approval",
                now
            )
            .unwrap(),
            failed
        );
    }

    /// Approval may land after the Action parks and before the worker
    /// acknowledges. The turn still records the Action as its continuation
    /// and is immediately resumable.
    fn park_after_decision_contract(db: &RuntimeDb, ns: &str) {
        let line = seed(db, ns, "racer", false);
        let turn = admit(db, wake(ns, &line, Cause::Manual, "race"), "plane", 1).unwrap();
        let held = claim(db, ns, "runner-a", &turn.turn_id, 1_000, 100).unwrap();
        let action = parked_action(db, ns, &held, "raced");
        decide(db, &action, "admitted");
        let parked = park(
            db,
            &turn.turn_id,
            &held.claim_owner,
            held.claim_generation,
            &held.fencing_token,
            &action,
            "awaiting approval",
            100,
        )
        .unwrap();
        assert!(parked.is_parked());
        assert_eq!(
            (parked.parked_action_id.as_str(), parked.reason.as_str()),
            (action.as_str(), "awaiting approval")
        );
        let listed = list_claimable(db, ns, 100, 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].turn_id, turn.turn_id);
        let resumed = claim(db, ns, "runner-b", &turn.turn_id, 1_000, 100).unwrap();
        assert_eq!(resumed.claim_generation, held.claim_generation + 1);
        assert_eq!(resumed.parked_action_id, action);
    }

    #[test]
    fn a_decided_park_is_listed_behind_undecided_ones() {
        let db = RuntimeDb::memory();
        let ns = "queue";
        let mut parked = Vec::new();
        for (name, due) in [("older", 100), ("newer", 200)] {
            let line = seed(&db, ns, name, false);
            let turn = admit(
                &db,
                Wake {
                    due_at_ms: due,
                    ..wake(ns, &line, Cause::Manual, name)
                },
                "plane",
                1,
            )
            .unwrap();
            let held = claim(&db, ns, "runner-a", &turn.turn_id, 1_000, 300).unwrap();
            let action = parked_action(&db, ns, &held, name);
            park(
                &db,
                &turn.turn_id,
                &held.claim_owner,
                held.claim_generation,
                &held.fencing_token,
                &action,
                "awaiting approval",
                300,
            )
            .unwrap();
            parked.push((turn.turn_id, action));
        }
        // Only the newer park is decided; a limit of one still finds it.
        decide(&db, &parked[1].1, "denied");
        let listed = list_claimable(&db, ns, 400, 1).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].turn_id, parked[1].0);
        // The decided park is runnable work in the queue gauge; the one
        // awaiting approval is not.
        let gauge = pool_gauge(&db, 400).unwrap();
        assert_eq!((gauge.queued, gauge.claimable), (1, 1));

        // Its instance frozen, a claim retires it rather than leaving it
        // listed for ever.
        freeze(&db, &format!("{ns}-newer"));
        assert!(matches!(
            claim(&db, ns, "runner-b", &parked[1].0, 1_000, 400),
            Err(TurnError::Frozen(_))
        ));
        assert_eq!(get(&db, &parked[1].0).unwrap().unwrap().status, REFUSED);
        assert!(list_claimable(&db, ns, 400, 10).unwrap().is_empty());
        assert_eq!(pool_gauge(&db, 400).unwrap().claimable, 0);
    }

    #[test]
    fn sqlite_turns_park_and_resume() {
        park_contract(&RuntimeDb::memory(), "park");
        park_after_decision_contract(&RuntimeDb::memory(), "race");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_turns_park_and_resume() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        let ns = format!("parks-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        park_contract(&db, &ns);
        let raced = format!("race-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        park_after_decision_contract(&db, &raced);
    }

    #[test]
    fn sqlite_turns_follow_the_contract() {
        turn_contract(&RuntimeDb::memory(), "site");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_turns_follow_the_contract() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        let ns = format!("turns-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        turn_contract(&db, &ns);
    }

    #[test]
    fn a_turn_that_keeps_lapsing_fails() {
        let db = RuntimeDb::memory();
        let line = seed(&db, "site", "line", false);
        let turn = admit(&db, wake("site", &line, Cause::Schedule, "100"), "plane", 1).unwrap();
        let mut now = 100;
        for _ in 0..MAX_TRANSFORM_LEASE_EXPIRIES {
            claim(&db, "site", "worker", &turn.turn_id, 1_000, now).unwrap();
            now += 1_000;
        }
        assert_eq!(
            claim(&db, "site", "worker", &turn.turn_id, 1_000, now),
            Err(TurnError::NotClaimable)
        );
        assert!(list_claimable(&db, "site", now, 10).unwrap().is_empty());
    }

    #[test]
    fn depth_counts_waiting_and_due_turns_without_tenant_labels() {
        let db = RuntimeDb::memory();
        let line = seed(&db, "site", "line", false);
        let due = admit(&db, wake("site", &line, Cause::Schedule, "100"), "plane", 1).unwrap();
        let mut later = wake("site", &line, Cause::Schedule, "900");
        later.due_at_ms = 900;
        admit(&db, later, "plane", 1).unwrap();
        let gauge = pool_gauge(&db, 600).unwrap();
        assert_eq!((gauge.queued, gauge.claimable), (2, 1));
        assert_eq!(gauge.oldest_claimable_age_seconds, 0.5);
        claim(&db, "site", "worker", &due.turn_id, 1_000, 600).unwrap();
        let held = pool_gauge(&db, 700).unwrap();
        assert_eq!((held.queued, held.claimable), (1, 0));
        let scraped =
            crate::sekai::governed_transform::transform_work_depth_metrics(&db, 700).unwrap();
        assert!(
            scraped
                .contains(r#"sekai_transform_work_queued{profile="agent-turn",pool="default"} 1"#)
        );
        assert_eq!(
            scraped
                .matches("# TYPE sekai_transform_work_queued ")
                .count(),
            1,
            "one header per family across profiles"
        );
    }
}
