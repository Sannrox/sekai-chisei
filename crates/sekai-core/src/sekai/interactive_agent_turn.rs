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
//! This slice admits and stores turns only. No claim path reads the table
//! yet, so an admitted turn stays pending until the claim slice lands; a
//! turn token naming one is refused because the instance-turn lookup does
//! not find it.

use rusqlite::{OptionalExtension, Row, params};
use sha2::{Digest, Sha256};

use crate::db::postgres::{PostgresDb, off_runtime};
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::sekai::agent_turn::TurnError;
use crate::sekai::site_agent_instance;

/// The wire cause of an interactive turn.
pub const CAUSE: &str = "interactive";
/// Prefix of every interactive turn id; instance turns use `turn-`.
pub const ID_PREFIX: &str = "iturn-";
/// Longest accepted request id or trace id.
pub const MAX_REFERENCE_LEN: usize = 256;

const PENDING: &str = "pending";

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
        assert_eq!(get(db, &turn.turn_id).unwrap(), Some(turn));
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
