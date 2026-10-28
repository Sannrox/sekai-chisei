//! Schedule wakes of site agent instances (ADR 0137, #1951).
//!
//! An instance's `wake_policies` holds self-describing tokens, not
//! references to a separate record: `schedule:<every_ms>` wakes it every
//! `every_ms`, at least [`MIN_EVERY_MS`]. The instance's governed update
//! Action is the only way to change them, so a change leaves a receipt.
//!
//! Each tick admits one turn per instance, token and due time, with cause
//! `schedule` and cause reference `<token>@<due_ms>`. The turn identity makes
//! a repeated tick, a restart or a second plane a no-op. Due times are offset
//! per instance by a phase derived from its id, so instances on one interval
//! do not all fall due together; every plane derives the same phase. Only
//! the latest due time is admitted: a tick after an outage does not backfill
//! the fires it missed. A frozen instance's fire is refused and audited by
//! turn admission.

use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::domain::ListFilter;
use crate::sekai::agent_turn::{self, AgentTurn, Cause, TurnError, Wake};
use crate::sekai::site_agent_instance::{KIND, WAKE_POLICIES_PROPERTY};

/// Shortest schedule interval an instance may declare.
pub const MIN_EVERY_MS: i64 = 60_000;
const SCHEDULE_PREFIX: &str = "schedule:";
const PAGE: i32 = 500;

/// One parsed wake token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakePolicy {
    Schedule { every_ms: i64 },
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
    let every_ms = token
        .strip_prefix(SCHEDULE_PREFIX)
        .and_then(|every| every.parse::<i64>().ok())
        .ok_or_else(|| {
            format!("unknown wake policy {token}; expected {SCHEDULE_PREFIX}<every_ms>")
        })?;
    if every_ms < MIN_EVERY_MS {
        return Err(format!(
            "wake policy {token} fires more often than every {MIN_EVERY_MS} ms"
        ));
    }
    Ok(WakePolicy::Schedule { every_ms })
}

/// The latest due time at or before `now_ms` of an `every_ms` schedule on
/// `instance_id`.
pub fn due_at(instance_id: &str, every_ms: i64, now_ms: i64) -> i64 {
    let digest = Sha256::digest(instance_id.as_bytes());
    let seed = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"));
    let phase = (seed % every_ms as u64) as i64;
    now_ms.saturating_sub(phase).div_euclid(every_ms) * every_ms + phase
}

/// Admits the due schedule turn of every instance, as `actor`. An instance
/// that is frozen, gone, or carries a malformed token is skipped; the turns
/// returned are those due now, new or already admitted.
pub fn tick(db: &RuntimeDb, now_ms: i64, actor: &str) -> Result<Vec<AgentTurn>, String> {
    let mut turns = Vec::new();
    let mut offset = 0;
    loop {
        let page = db.list_objects(&ListFilter {
            kind: Some(KIND.into()),
            limit: PAGE,
            offset,
            ..Default::default()
        })?;
        for instance in &page {
            let value = instance
                .properties
                .get(WAKE_POLICIES_PROPERTY)
                .map(String::as_str)
                .unwrap_or_default();
            let Ok(policies) = parse(value) else {
                continue;
            };
            for (token, WakePolicy::Schedule { every_ms }) in policies {
                let due = due_at(&instance.id, every_ms, now_ms);
                let wake = Wake {
                    namespace: instance.namespace.clone(),
                    instance_id: instance.id.clone(),
                    cause: Cause::Schedule,
                    cause_ref: format!("{token}@{due}"),
                    due_at_ms: due,
                };
                match agent_turn::admit(db, wake, actor, now_ms) {
                    Ok(turn) => turns.push(turn),
                    Err(TurnError::Frozen(_) | TurnError::NotFound) => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        if page.len() < PAGE as usize {
            return Ok(turns);
        }
        offset += PAGE;
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
        assert!(parse("schedule:59999").is_err(), "below the minimum");
        assert!(parse("nightly").is_err(), "unknown form");
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
