//! Control-plane write freeze (#1458).
//!
//! A freeze is a durable row: scope, mode, reason. Admission checks it on the
//! next write or Action commit. Unfreeze is the same write with `enabled=false`.
//! Review-only and two-person unfreeze stay out until review queues exist.

use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use rusqlite::params;
use std::borrow::Cow;

pub const SCOPE_NAMESPACE: &str = "namespace";
pub const SCOPE_PRINCIPAL: &str = "principal";
pub const SCOPE_ACTION: &str = "action";
pub const SCOPE_TENANT: &str = "tenant";

pub const MODE_BLOCK_WRITES: &str = "block_writes";
pub const MODE_BLOCK_AGENT_ACTIONS: &str = "block_agent_actions";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFreeze {
    pub scope_kind: String,
    pub scope_value: String,
    pub mode: String,
    pub reason: String,
    pub enabled: bool,
    pub updated_ms: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct WriteFreezeCheck<'a> {
    pub namespace: &'a str,
    pub tenant: &'a str,
    pub principal: &'a str,
    pub action_type: &'a str,
    pub agent: bool,
    pub write: bool,
}

impl WriteFreeze {
    pub fn validate(&self) -> Result<(), String> {
        match self.scope_kind.as_str() {
            SCOPE_NAMESPACE | SCOPE_PRINCIPAL | SCOPE_ACTION | SCOPE_TENANT => {}
            other => return Err(format!("unknown freeze scope_kind {other}")),
        }
        if self.scope_value.trim().is_empty() || self.scope_value.trim() != self.scope_value {
            return Err("freeze scope_value must be a canonical non-empty identifier".into());
        }
        match self.mode.as_str() {
            MODE_BLOCK_WRITES | MODE_BLOCK_AGENT_ACTIONS => {}
            other => return Err(format!("unknown freeze mode {other}")),
        }
        if self.reason.trim().is_empty() {
            return Err("freeze reason required".into());
        }
        Ok(())
    }

    pub fn matches(&self, check: &WriteFreezeCheck<'_>) -> bool {
        if !self.enabled {
            return false;
        }
        let scope_hit = match self.scope_kind.as_str() {
            SCOPE_NAMESPACE => self.scope_value == check.namespace,
            SCOPE_TENANT => !check.tenant.is_empty() && self.scope_value == check.tenant,
            SCOPE_PRINCIPAL => self.scope_value == check.principal,
            SCOPE_ACTION => !check.action_type.is_empty() && self.scope_value == check.action_type,
            _ => false,
        };
        if !scope_hit {
            return false;
        }
        match self.mode.as_str() {
            MODE_BLOCK_WRITES => check.write,
            MODE_BLOCK_AGENT_ACTIONS => check.write && check.agent,
            _ => false,
        }
    }
}

pub fn blocking_freeze<'a>(
    freezes: &'a [WriteFreeze],
    check: &WriteFreezeCheck<'_>,
) -> Option<&'a WriteFreeze> {
    freezes.iter().find(|freeze| freeze.matches(check))
}

pub fn is_agent_principal(principal: &str) -> bool {
    principal.starts_with("agent:")
}

/// Agent Actions include `agent:` principals, a delegated `act`, machine
/// credentials, and registered service principals (which cannot contain `:`).
/// Lookup errors fail closed so a broken registration cannot bypass an
/// agent freeze.
pub fn actor_is_agent(
    db: &RuntimeDb,
    principal: &str,
    delegating_actor: Option<&str>,
    machine_credential: bool,
) -> Result<bool, String> {
    if machine_credential || is_agent_principal(principal) {
        return Ok(true);
    }
    if delegating_actor.is_some_and(|actor| !actor.trim().is_empty()) {
        return Ok(true);
    }
    Ok(db.get_service_principal(principal)?.is_some())
}

/// Prefer the request tenant; if omitted, use a registered service
/// principal's owning tenant so non-RPC admits still match tenant freezes.
pub fn acting_or_registered_tenant<'a>(
    db: &RuntimeDb,
    supplied: &'a str,
    principal: &str,
) -> Result<Cow<'a, str>, String> {
    if !supplied.trim().is_empty() {
        return Ok(Cow::Borrowed(supplied));
    }
    Ok(db
        .get_service_principal(principal)?
        .map(|registration| registration.tenant_id)
        .filter(|tenant| !tenant.trim().is_empty())
        .map(Cow::Owned)
        .unwrap_or(Cow::Borrowed(supplied)))
}

pub fn write_check<'a>(
    namespace: &'a str,
    tenant: &'a str,
    principal: &'a str,
    action_type: &'a str,
) -> WriteFreezeCheck<'a> {
    write_check_with_agent(
        namespace,
        tenant,
        principal,
        action_type,
        is_agent_principal(principal),
    )
}

pub fn write_check_with_agent<'a>(
    namespace: &'a str,
    tenant: &'a str,
    principal: &'a str,
    action_type: &'a str,
    agent: bool,
) -> WriteFreezeCheck<'a> {
    WriteFreezeCheck {
        namespace,
        tenant,
        principal,
        action_type,
        agent,
        write: true,
    }
}

/// Principal freeze matches the acting principal and, when present, the
/// human the actor is acting for (`delegating_actor` / `act`).
pub fn write_checks_for_actors<'a>(
    namespace: &'a str,
    tenant: &'a str,
    principal: &'a str,
    delegating_actor: Option<&'a str>,
    action_type: &'a str,
    agent: bool,
) -> Vec<WriteFreezeCheck<'a>> {
    let mut checks = vec![write_check_with_agent(
        namespace,
        tenant,
        principal,
        action_type,
        agent,
    )];
    if let Some(actor) = delegating_actor
        .map(str::trim)
        .filter(|actor| !actor.is_empty() && *actor != principal)
    {
        checks.push(write_check_with_agent(
            namespace,
            tenant,
            actor,
            action_type,
            true,
        ));
    }
    checks
}

pub fn freeze_reason(
    db: &RuntimeDb,
    check: WriteFreezeCheck<'_>,
) -> Result<Option<String>, String> {
    freeze_reason_any(db, &[check])
}

pub fn freeze_reason_any(
    db: &RuntimeDb,
    checks: &[WriteFreezeCheck<'_>],
) -> Result<Option<String>, String> {
    let freezes = db.list_write_freezes()?;
    Ok(checks
        .iter()
        .find_map(|check| blocking_freeze(&freezes, check))
        .map(|freeze| {
            format!(
                "write freeze ({}/{}/{}): {}",
                freeze.scope_kind, freeze.scope_value, freeze.mode, freeze.reason
            )
        }))
}

/// Admission refusal from a write freeze check.
///
/// gRPC callers map [`Frozen`](WriteFreezeError::Frozen) to failed
/// precondition and [`Internal`](WriteFreezeError::Internal) to internal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteFreezeError {
    Frozen(String),
    Internal(String),
}

pub fn refuse_if_frozen(
    db: &RuntimeDb,
    check: WriteFreezeCheck<'_>,
) -> Result<(), WriteFreezeError> {
    refuse_if_frozen_any(db, &[check])
}

pub fn refuse_if_frozen_any(
    db: &RuntimeDb,
    checks: &[WriteFreezeCheck<'_>],
) -> Result<(), WriteFreezeError> {
    match freeze_reason_any(db, checks) {
        Ok(Some(reason)) => Err(WriteFreezeError::Frozen(reason)),
        Ok(None) => Ok(()),
        Err(error) => Err(WriteFreezeError::Internal(error)),
    }
}

impl SekaiDb {
    pub fn migrate_write_freeze(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_write_freeze (
                scope_kind TEXT NOT NULL,
                scope_value TEXT NOT NULL,
                mode TEXT NOT NULL,
                reason TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                updated_ms INTEGER NOT NULL,
                PRIMARY KEY (scope_kind, scope_value)
            );",
        )
        .map_err(|e| e.to_string())
    }

    pub fn set_write_freeze(&self, freeze: &WriteFreeze) -> Result<(), String> {
        freeze.validate()?;
        let conn = self.conn();
        upsert_write_freeze(&conn, freeze)
    }

    pub fn set_write_freeze_with_decision(
        &self,
        freeze: &WriteFreeze,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        freeze.validate()?;
        crate::sekai::audit::validate_decision(decision)?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        upsert_write_freeze(&tx, freeze)?;
        crate::sekai::ledger::insert_chained_decision(&tx, decision)?;
        tx.commit().map_err(|e| e.to_string())
    }

    pub fn list_write_freezes(&self) -> Result<Vec<WriteFreeze>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT scope_kind, scope_value, mode, reason, enabled, updated_ms
                 FROM sekai_write_freeze ORDER BY scope_kind, scope_value",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(WriteFreeze {
                    scope_kind: row.get(0)?,
                    scope_value: row.get(1)?,
                    mode: row.get(2)?,
                    reason: row.get(3)?,
                    enabled: row.get::<_, i64>(4)? != 0,
                    updated_ms: row.get(5)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

fn upsert_write_freeze(conn: &rusqlite::Connection, freeze: &WriteFreeze) -> Result<(), String> {
    conn.execute(
        "INSERT INTO sekai_write_freeze (scope_kind, scope_value, mode, reason, enabled, updated_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (scope_kind, scope_value) DO UPDATE SET
            mode = excluded.mode,
            reason = excluded.reason,
            enabled = excluded.enabled,
            updated_ms = excluded.updated_ms",
        params![
            freeze.scope_kind,
            freeze.scope_value,
            freeze.mode,
            freeze.reason,
            freeze.enabled as i64,
            freeze.updated_ms
        ],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn freeze(kind: &str, value: &str, mode: &str) -> WriteFreeze {
        WriteFreeze {
            scope_kind: kind.into(),
            scope_value: value.into(),
            mode: mode.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        }
    }

    fn check<'a>(
        namespace: &'a str,
        principal: &'a str,
        action_type: &'a str,
        agent: bool,
    ) -> WriteFreezeCheck<'a> {
        WriteFreezeCheck {
            namespace,
            tenant: "",
            principal,
            action_type,
            agent,
            write: true,
        }
    }

    #[test]
    fn namespace_freeze_blocks_writes_in_scope_only() {
        let freeze = freeze(SCOPE_NAMESPACE, "ops", MODE_BLOCK_WRITES);
        assert!(freeze.matches(&check("ops", "alice", "", false)));
        assert!(!freeze.matches(&check("other", "alice", "", false)));
        let mut read = check("ops", "alice", "", false);
        read.write = false;
        assert!(!freeze.matches(&read));
    }

    #[test]
    fn agent_mode_spares_human_writes() {
        let freeze = freeze(SCOPE_NAMESPACE, "ops", MODE_BLOCK_AGENT_ACTIONS);
        assert!(freeze.matches(&check("ops", "agent:bot", "", true)));
        assert!(!freeze.matches(&check("ops", "alice", "", false)));
    }

    #[test]
    fn principal_freeze_matches_delegating_actor() {
        let freeze = freeze(SCOPE_PRINCIPAL, "alice", MODE_BLOCK_WRITES);
        let checks =
            write_checks_for_actors("ops", "", "agent:bot", Some("alice"), "dispatch", true);
        assert!(checks.iter().any(|check| freeze.matches(check)));
        let spared = write_checks_for_actors("ops", "", "agent:bot", Some("bob"), "dispatch", true);
        assert!(spared.iter().all(|check| !freeze.matches(check)));
    }

    #[test]
    fn principal_and_action_scopes_match_exactly() {
        let principal = freeze(SCOPE_PRINCIPAL, "agent:bot", MODE_BLOCK_WRITES);
        assert!(principal.matches(&check("ops", "agent:bot", "notify", true)));
        assert!(!principal.matches(&check("ops", "alice", "notify", false)));
        let action = freeze(SCOPE_ACTION, "notify", MODE_BLOCK_WRITES);
        assert!(action.matches(&check("ops", "alice", "notify", false)));
        assert!(!action.matches(&check("ops", "alice", "mutate", false)));
    }

    #[test]
    fn disabled_freeze_does_not_block() {
        let mut freeze = freeze(SCOPE_NAMESPACE, "ops", MODE_BLOCK_WRITES);
        freeze.enabled = false;
        assert!(blocking_freeze(&[freeze], &check("ops", "alice", "", false)).is_none());
    }

    #[test]
    fn persist_round_trip_and_unfreeze() {
        let db = SekaiDb::new(":memory:").unwrap();
        let mut row = freeze(SCOPE_NAMESPACE, "ops", MODE_BLOCK_WRITES);
        db.set_write_freeze(&row).unwrap();
        let listed = db.list_write_freezes().unwrap();
        assert_eq!(listed, vec![row.clone()]);
        row.enabled = false;
        row.reason = "lifted".into();
        row.updated_ms = 2;
        db.set_write_freeze(&row).unwrap();
        assert!(!db.list_write_freezes().unwrap()[0].enabled);
    }

    #[test]
    fn tenant_freeze_requires_a_tenant_on_the_check() {
        let freeze = freeze(SCOPE_TENANT, "acme", MODE_BLOCK_WRITES);
        let mut with_tenant = check("ops", "alice", "", false);
        with_tenant.tenant = "acme";
        assert!(freeze.matches(&with_tenant));
        assert!(!freeze.matches(&check("ops", "alice", "", false)));
    }

    #[test]
    fn runtime_refuse_names_the_blocking_row() {
        let db = crate::db::runtime_db::RuntimeDb::memory();
        db.set_write_freeze(&freeze(SCOPE_NAMESPACE, "ops", MODE_BLOCK_WRITES))
            .unwrap();
        let blocked = freeze_reason(&db, write_check("ops", "", "alice", "")).unwrap();
        assert_eq!(
            blocked.as_deref(),
            Some("write freeze (namespace/ops/block_writes): incident")
        );
        assert!(
            freeze_reason(&db, write_check("other", "", "alice", ""))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn actor_is_agent_covers_prefix_delegation_machine_and_registration() {
        let db = crate::db::runtime_db::RuntimeDb::memory();
        assert!(actor_is_agent(&db, "agent:bot", None, false).unwrap());
        assert!(actor_is_agent(&db, "worker-a", Some("alice"), false).unwrap());
        assert!(actor_is_agent(&db, "worker-a", None, true).unwrap());
        assert!(!actor_is_agent(&db, "worker-a", None, false).unwrap());
        db.put_service_principal(
            &crate::sekai::service_principal::ServicePrincipalRegistration {
                principal: "worker-a".into(),
                tenant_id: String::new(),
                namespaces: vec!["ops".into()],
                action_types: vec!["dispatch".into()],
                registered_by: "local".into(),
                created_at_ms: 1,
                updated_at_ms: 1,
            },
        )
        .unwrap();
        assert!(actor_is_agent(&db, "worker-a", None, false).unwrap());
    }

    #[test]
    fn freeze_and_receipt_commit_together() {
        let db = crate::db::runtime_db::RuntimeDb::memory();
        let row = freeze(SCOPE_NAMESPACE, "ops", MODE_BLOCK_WRITES);
        db.set_write_freeze_with_decision(
            &row,
            &crate::sekai::audit::Decision {
                id: "write_freeze:namespace:ops:test".into(),
                timestamp: 1,
                actor: "local".into(),
                action: "write_freeze".into(),
                reason: "incident".into(),
                evidence: std::collections::HashMap::from([
                    ("scope_kind".into(), "namespace".into()),
                    ("enabled".into(), "true".into()),
                ]),
                target_id: String::new(),
                outcome: "enabled".into(),
            },
        )
        .unwrap();
        assert!(db.list_write_freezes().unwrap()[0].enabled);
        let receipts = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("write_freeze".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, "enabled");
    }
}
