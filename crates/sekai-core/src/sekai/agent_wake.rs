//! Schedule and change wakes of site agent instances (ADR 0137, #1951,
//! #1952).
//!
//! An instance's `wake_policies` holds self-describing tokens, not
//! references to a separate record: `schedule:<every_ms>` wakes it every
//! `every_ms`, at least [`MIN_EVERY_MS`]; `change:<debounce_ms>` wakes it
//! when an object in its responsibility changes, at most once per window of
//! `debounce_ms`, at least [`MIN_DEBOUNCE_MS`]. The instance's governed
//! update Action is the only way to change them, so a change leaves a
//! receipt.
//!
//! Each tick admits one turn per instance, token and due time, with cause
//! `schedule` and cause reference `<token>@<due_ms>`. The turn identity makes
//! a repeated tick, a restart or a second plane a no-op. Due times are offset
//! per instance by a phase derived from its id, so instances on one interval
//! do not all fall due together; every plane derives the same phase. Only
//! the latest due time is admitted: a tick after an outage does not backfill
//! the fires it missed. A frozen instance's fire is refused and audited by
//! turn admission.
//!
//! Change wakes read committed object mutations after a durable cursor per
//! instance and token. The plane's gRPC layer decides what the instance's
//! principal may see; this module keeps the cursor and the window rule.

use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::db::postgres::{PostgresDb, off_runtime};
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::{ListFilter, Object};
use crate::sekai::agent_turn::{self, AgentTurn, Cause, TurnError, Wake};
use crate::sekai::site_agent_instance::{KIND, WAKE_POLICIES_PROPERTY};

/// Shortest schedule interval an instance may declare.
pub const MIN_EVERY_MS: i64 = 60_000;
/// Shortest change debounce window an instance may declare.
pub const MIN_DEBOUNCE_MS: i64 = 1_000;
const SCHEDULE_PREFIX: &str = "schedule:";
const CHANGE_PREFIX: &str = "change:";
const PAGE: i32 = 500;

/// One parsed wake token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakePolicy {
    Schedule { every_ms: i64 },
    Change { debounce_ms: i64 },
}

/// Parses a comma-separated `wake_policies` value into `(token, policy)`
/// pairs; any unknown or malformed token refuses the whole value.
pub fn parse(value: &str) -> Result<Vec<(&str, WakePolicy)>, String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| parse_token(token).map(|policy| (token, policy)))
        .collect()
}

fn parse_token(token: &str) -> Result<WakePolicy, String> {
    let interval = |prefix: &str, min: i64| -> Option<Result<i64, String>> {
        let value = token.strip_prefix(prefix)?;
        Some(match value.parse::<i64>() {
            Ok(ms) if ms >= min => Ok(ms),
            Ok(_) => Err(format!("wake policy {token} is shorter than {min} ms")),
            Err(_) => Err(format!("wake policy {token} has no interval in ms")),
        })
    };
    if let Some(every_ms) = interval(SCHEDULE_PREFIX, MIN_EVERY_MS) {
        return every_ms.map(|every_ms| WakePolicy::Schedule { every_ms });
    }
    if let Some(debounce_ms) = interval(CHANGE_PREFIX, MIN_DEBOUNCE_MS) {
        return debounce_ms.map(|debounce_ms| WakePolicy::Change { debounce_ms });
    }
    Err(format!(
        "unknown wake policy {token}; expected {SCHEDULE_PREFIX}<every_ms> or {CHANGE_PREFIX}<debounce_ms>"
    ))
}

/// The latest due time at or before `now_ms` of an `every_ms` schedule on
/// `instance_id`.
pub fn due_at(instance_id: &str, every_ms: i64, now_ms: i64) -> i64 {
    let digest = Sha256::digest(instance_id.as_bytes());
    let seed = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"));
    let phase = (seed % every_ms as u64) as i64;
    now_ms.saturating_sub(phase).div_euclid(every_ms) * every_ms + phase
}

/// Every site agent instance, in id order.
pub fn instances(db: &RuntimeDb) -> Result<Vec<Object>, String> {
    let mut all = Vec::new();
    loop {
        let page = db.list_objects(&ListFilter {
            kind: Some(KIND.into()),
            limit: PAGE,
            offset: i32::try_from(all.len()).map_err(|error| error.to_string())?,
            ..Default::default()
        })?;
        let done = page.len() < PAGE as usize;
        all.extend(page);
        if done {
            return Ok(all);
        }
    }
}

/// The parsed wake tokens of `instance`; none when its value is malformed.
pub fn policies(instance: &Object) -> Vec<(String, WakePolicy)> {
    let value = instance
        .properties
        .get(WAKE_POLICIES_PROPERTY)
        .map(String::as_str)
        .unwrap_or_default();
    parse(value)
        .map(|policies| {
            policies
                .into_iter()
                .map(|(token, policy)| (token.to_string(), policy))
                .collect()
        })
        .unwrap_or_default()
}

/// Admits the due schedule turn of every instance, as `actor`. An instance
/// that is frozen, gone, or carries a malformed token is skipped; the turns
/// returned are those due now, new or already admitted.
pub fn tick(db: &RuntimeDb, now_ms: i64, actor: &str) -> Result<Vec<AgentTurn>, String> {
    let mut turns = Vec::new();
    for instance in instances(db)? {
        for (token, policy) in policies(&instance) {
            let WakePolicy::Schedule { every_ms } = policy else {
                continue;
            };
            let due = due_at(&instance.id, every_ms, now_ms);
            let wake = Wake {
                namespace: instance.namespace.clone(),
                instance_id: instance.id.clone(),
                cause: Cause::Schedule,
                cause_ref: format!("{token}@{due}"),
                due_at_ms: due,
            };
            if let Some(turn) = admit_or_skip(db, wake, actor, now_ms)? {
                turns.push(turn);
            }
        }
    }
    Ok(turns)
}

/// Admits the change turn of the debounce window holding `committed_at_ms`.
/// Changes in one window share a turn, due when the window closes.
pub fn admit_change(
    db: &RuntimeDb,
    instance: &Object,
    token: &str,
    debounce_ms: i64,
    committed_at_ms: i64,
    actor: &str,
    now_ms: i64,
) -> Result<Option<AgentTurn>, String> {
    let window = committed_at_ms - committed_at_ms.rem_euclid(debounce_ms);
    let wake = Wake {
        namespace: instance.namespace.clone(),
        instance_id: instance.id.clone(),
        cause: Cause::ObjectChange,
        cause_ref: format!("{token}@{window}"),
        due_at_ms: window.saturating_add(debounce_ms),
    };
    admit_or_skip(db, wake, actor, now_ms)
}

/// A frozen instance's refusal is audited by admission; a gone one is
/// skipped.
fn admit_or_skip(
    db: &RuntimeDb,
    wake: Wake,
    actor: &str,
    now_ms: i64,
) -> Result<Option<AgentTurn>, String> {
    match agent_turn::admit(db, wake, actor, now_ms) {
        Ok(turn) => Ok(Some(turn)),
        Err(TurnError::Frozen(_) | TurnError::NotFound) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// The mutation sequence a change token has read up to; `None` before its
/// first tick.
pub fn change_cursor(
    db: &RuntimeDb,
    instance_id: &str,
    token: &str,
) -> Result<Option<u64>, String> {
    let seq = match db {
        RuntimeDb::Sqlite(store) => store.agent_wake_cursor(instance_id, token),
        RuntimeDb::Postgres(store) => off_runtime(|| store.agent_wake_cursor(instance_id, token)),
    }?;
    seq.map(|seq| u64::try_from(seq).map_err(|error| error.to_string()))
        .transpose()
}

/// Moves the cursor from `previous` to `next`; false when another plane
/// moved it first. Admissions are idempotent, so the loser loses nothing.
pub fn advance_change_cursor(
    db: &RuntimeDb,
    instance_id: &str,
    token: &str,
    previous: Option<u64>,
    next: u64,
) -> Result<bool, String> {
    let to_i64 = |seq: u64| i64::try_from(seq).map_err(|error| error.to_string());
    let previous = previous.map(to_i64).transpose()?;
    let next = to_i64(next)?;
    match db {
        RuntimeDb::Sqlite(store) => {
            store.advance_agent_wake_cursor(instance_id, token, previous, next)
        }
        RuntimeDb::Postgres(store) => {
            off_runtime(|| store.advance_agent_wake_cursor(instance_id, token, previous, next))
        }
    }
}

const CREATE_SQLITE: &str = "
CREATE TABLE IF NOT EXISTS sekai_agent_wake_cursor (
    instance_id TEXT NOT NULL,
    token TEXT NOT NULL,
    after_seq INTEGER NOT NULL,
    PRIMARY KEY (instance_id, token)
);
";

impl SekaiDb {
    pub(crate) fn migrate_agent_wake_cursors(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(CREATE_SQLITE)
            .map_err(|error| error.to_string())
    }

    fn agent_wake_cursor(&self, instance_id: &str, token: &str) -> Result<Option<i64>, String> {
        self.conn()
            .query_row(
                "SELECT after_seq FROM sekai_agent_wake_cursor WHERE instance_id = ?1 AND token = ?2",
                params![instance_id, token],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn advance_agent_wake_cursor(
        &self,
        instance_id: &str,
        token: &str,
        previous: Option<i64>,
        next: i64,
    ) -> Result<bool, String> {
        let conn = self.conn();
        let changed = match previous {
            None => conn.execute(
                "INSERT INTO sekai_agent_wake_cursor (instance_id, token, after_seq)
                 VALUES (?1, ?2, ?3) ON CONFLICT (instance_id, token) DO NOTHING",
                params![instance_id, token, next],
            ),
            Some(previous) => conn.execute(
                "UPDATE sekai_agent_wake_cursor SET after_seq = ?4
                 WHERE instance_id = ?1 AND token = ?2 AND after_seq = ?3",
                params![instance_id, token, previous, next],
            ),
        }
        .map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }
}

impl PostgresDb {
    fn agent_wake_cursor(&self, instance_id: &str, token: &str) -> Result<Option<i64>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT after_seq FROM sekai_agent_wake_cursor WHERE instance_id = $1 AND token = $2",
                &[&instance_id, &token],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0)))
    }

    fn advance_agent_wake_cursor(
        &self,
        instance_id: &str,
        token: &str,
        previous: Option<i64>,
        next: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let changed = match previous {
            None => connection.execute(
                "INSERT INTO sekai_agent_wake_cursor (instance_id, token, after_seq)
                 VALUES ($1, $2, $3) ON CONFLICT (instance_id, token) DO NOTHING",
                &[&instance_id, &token, &next],
            ),
            Some(previous) => connection.execute(
                "UPDATE sekai_agent_wake_cursor SET after_seq = $4
                 WHERE instance_id = $1 AND token = $2 AND after_seq = $3",
                &[&instance_id, &token, &previous, &next],
            ),
        }
        .map_err(|error| error.to_string())?;
        Ok(changed == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn tokens_parse_or_refuse() {
        assert_eq!(
            parse("schedule:60000, schedule:3600000").unwrap(),
            vec![
                ("schedule:60000", WakePolicy::Schedule { every_ms: 60_000 }),
                (
                    "schedule:3600000",
                    WakePolicy::Schedule {
                        every_ms: 3_600_000
                    }
                ),
            ]
        );
        assert!(parse("").unwrap().is_empty());
        assert!(
            parse("schedule:59999").is_err(),
            "below the minimum interval"
        );
        assert!(parse("nightly").is_err(), "unknown form");
        assert_eq!(
            parse("change:5000").unwrap(),
            vec![("change:5000", WakePolicy::Change { debounce_ms: 5_000 })]
        );
        assert!(parse("change:999").is_err(), "below the minimum window");
        assert!(parse("schedule:60000,schedule:x").is_err());
    }

    #[test]
    fn due_times_are_phased_per_instance_and_stable() {
        let every = 3_600_000;
        let a = due_at("line-7", every, 10 * every);
        assert!(a <= 10 * every && a > 9 * every);
        assert_eq!(
            due_at("line-7", every, a),
            a,
            "a due time is its own due time"
        );
        assert_eq!(due_at("line-7", every, a + every - 1), a);
        assert_eq!(due_at("line-7", every, a + every), a + every);
        assert_ne!(
            a.rem_euclid(every),
            due_at("line-8", every, 10 * every).rem_euclid(every),
            "instances on one interval are spread"
        );
    }

    /// A change cursor starts absent, moves only from the value a caller
    /// read, and refuses a racing advance.
    fn cursor_contract(db: &RuntimeDb, instance: &str) {
        let token = "change:5000";
        assert_eq!(change_cursor(db, instance, token).unwrap(), None);
        assert!(advance_change_cursor(db, instance, token, None, 7).unwrap());
        assert!(!advance_change_cursor(db, instance, token, None, 9).unwrap());
        assert_eq!(change_cursor(db, instance, token).unwrap(), Some(7));
        assert!(advance_change_cursor(db, instance, token, Some(7), 12).unwrap());
        assert!(
            !advance_change_cursor(db, instance, token, Some(7), 15).unwrap(),
            "a stale advance loses"
        );
        assert_eq!(change_cursor(db, instance, token).unwrap(), Some(12));
    }

    #[test]
    fn sqlite_change_cursors_follow_the_contract() {
        cursor_contract(&RuntimeDb::memory(), "line-7");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_change_cursors_follow_the_contract() {
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
        cursor_contract(
            &db,
            &format!("wake-{}-{}", std::process::id(), uuid::Uuid::new_v4()),
        );
    }

    fn seed(db: &RuntimeDb, id: &str, wake: &str, frozen: bool) {
        db.create_object(&crate::domain::Object {
            id: id.into(),
            kind: KIND.into(),
            name: id.into(),
            namespace: "site".into(),
            external_id: String::new(),
            properties: HashMap::from([
                ("principal_id".to_string(), format!("agent:{id}")),
                (WAKE_POLICIES_PROPERTY.to_string(), wake.to_string()),
                ("frozen".to_string(), frozen.to_string()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();
    }

    #[test]
    fn one_fire_yields_one_turn_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sekai.db");
        let open = || {
            RuntimeDb::Sqlite(std::sync::Arc::new(
                crate::db::sekai::SekaiDb::new(path.to_str().unwrap()).unwrap(),
            ))
        };
        let every = 3_600_000;
        let now = 100 * every;
        let first = {
            let db = open();
            seed(&db, "line-7", "schedule:3600000", false);
            seed(&db, "quiet", "", false);
            seed(&db, "frozen", "schedule:3600000", true);
            let turns = tick(&db, now, "plane").unwrap();
            assert_eq!(turns.len(), 1, "only the awake scheduled instance");
            turns.into_iter().next().unwrap()
        };
        assert_eq!(first.cause, Cause::Schedule);
        let due = due_at("line-7", every, now);
        assert_eq!(first.cause_ref, format!("schedule:3600000@{due}"));
        assert_eq!(first.due_at_ms, due);

        let db = open();
        let again = tick(&db, now + 1, "other-plane").unwrap();
        assert_eq!(again, vec![first.clone()], "the restart admits nothing new");
        assert_eq!(
            agent_turn::list_claimable(&db, "site", now + 1, 10)
                .unwrap()
                .len(),
            1
        );
        let next = tick(&db, due + every, "plane").unwrap();
        assert_ne!(
            next[0].turn_id, first.turn_id,
            "the next fire is a new turn"
        );
        let refused = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some(agent_turn::REFUSED_DECISION.into()),
                target_id: Some("frozen".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(refused.len(), 2, "one audited refusal per fire");
    }
}
