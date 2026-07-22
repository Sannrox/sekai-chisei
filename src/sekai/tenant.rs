use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::collections::HashMap;
use uuid::Uuid;

pub const TENANT_CONTRACT_VERSION: &str = "tenant.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantState {
    Active,
    Suspended,
    ClosurePending,
}

impl TenantState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::ClosurePending => "closure_pending",
        }
    }

    fn parse(value: &str) -> Result<Self, TenantError> {
        match value {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "closure_pending" => Ok(Self::ClosurePending),
            _ => Err(TenantError::Storage(format!(
                "invalid tenant state {value:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRecord {
    pub contract_version: String,
    pub id: String,
    pub state: TenantState,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantError {
    NotFound,
    Conflict(String),
    InvalidTransition {
        from: TenantState,
        action: &'static str,
    },
    AdmissionBlocked(TenantState),
    Storage(String),
}

impl SekaiDb {
    pub(crate) fn migrate_tenants(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_tenants (
                id TEXT PRIMARY KEY,
                contract_version TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('active','suspended','closure_pending')),
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sekai_tenant_requests (
                idempotency_key TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                response_contract_version TEXT NOT NULL,
                response_state TEXT NOT NULL,
                response_created_at_ms INTEGER NOT NULL,
                response_updated_at_ms INTEGER NOT NULL,
                FOREIGN KEY(tenant_id) REFERENCES sekai_tenants(id)
             );",
            )
            .map_err(|error| error.to_string())
    }

    pub fn create_tenant(
        &self,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<TenantRecord, TenantError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if let Some(record) = request_result(&tx, idempotency_key, "create")? {
            tx.commit().map_err(storage)?;
            return Ok(record);
        }
        let id = format!("tenant_{}", Uuid::new_v4().simple());
        tx.execute(
            "INSERT INTO sekai_tenants (id,contract_version,state,created_at_ms,updated_at_ms)
             VALUES (?1,?2,'active',?3,?3)",
            params![id, TENANT_CONTRACT_VERSION, now_ms],
        )
        .map_err(storage)?;
        let record = tenant_by_id(&tx, &id)?.ok_or(TenantError::NotFound)?;
        insert_request(&tx, idempotency_key, "create", &record)?;
        insert_audit(&tx, actor, "tenant.create", &id, "", "active", now_ms)?;
        tx.commit().map_err(storage)?;
        Ok(record)
    }

    pub fn get_tenant(&self, id: &str) -> Result<Option<TenantRecord>, TenantError> {
        tenant_by_id(&self.conn(), id)
    }

    pub fn suspend_tenant(
        &self,
        id: &str,
        actor: &str,
        key: &str,
        now_ms: i64,
    ) -> Result<TenantRecord, TenantError> {
        self.transition_tenant(id, actor, key, "suspend", TenantState::Suspended, now_ms)
    }

    pub fn reactivate_tenant(
        &self,
        id: &str,
        actor: &str,
        key: &str,
        now_ms: i64,
    ) -> Result<TenantRecord, TenantError> {
        self.transition_tenant(id, actor, key, "reactivate", TenantState::Active, now_ms)
    }

    pub fn request_tenant_closure(
        &self,
        id: &str,
        actor: &str,
        key: &str,
        now_ms: i64,
    ) -> Result<TenantRecord, TenantError> {
        self.transition_tenant(
            id,
            actor,
            key,
            "request_closure",
            TenantState::ClosurePending,
            now_ms,
        )
    }

    fn transition_tenant(
        &self,
        id: &str,
        actor: &str,
        key: &str,
        action: &'static str,
        target: TenantState,
        now_ms: i64,
    ) -> Result<TenantRecord, TenantError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if let Some(record) = request_result(&tx, key, action)? {
            if record.id != id {
                return Err(TenantError::Conflict(
                    "idempotency key belongs to another tenant".into(),
                ));
            }
            tx.commit().map_err(storage)?;
            return Ok(record);
        }
        let before = tenant_by_id(&tx, id)?.ok_or(TenantError::NotFound)?;
        let valid = matches!(
            (before.state, target),
            (TenantState::Active, TenantState::Suspended)
                | (TenantState::Suspended, TenantState::Active)
                | (TenantState::Active, TenantState::ClosurePending)
                | (TenantState::Suspended, TenantState::ClosurePending)
        );
        if !valid {
            return Err(TenantError::InvalidTransition {
                from: before.state,
                action,
            });
        }
        tx.execute(
            "UPDATE sekai_tenants SET state=?1,updated_at_ms=?2 WHERE id=?3 AND state=?4",
            params![target.as_str(), now_ms, id, before.state.as_str()],
        )
        .map_err(storage)?;
        insert_audit(
            &tx,
            actor,
            &format!("tenant.{action}"),
            id,
            before.state.as_str(),
            target.as_str(),
            now_ms,
        )?;
        let record = tenant_by_id(&tx, id)?.ok_or(TenantError::NotFound)?;
        insert_request(&tx, key, action, &record)?;
        tx.commit().map_err(storage)?;
        Ok(record)
    }

    /// Admission hook consumed once namespaces gain tenant ownership (#112).
    pub fn require_tenant_admission(&self, id: &str) -> Result<(), TenantError> {
        let tenant = self.get_tenant(id)?.ok_or(TenantError::NotFound)?;
        match tenant.state {
            TenantState::Active => Ok(()),
            state => Err(TenantError::AdmissionBlocked(state)),
        }
    }
}

fn tenant_by_id(
    conn: &rusqlite::Connection,
    id: &str,
) -> Result<Option<TenantRecord>, TenantError> {
    conn.query_row(
        "SELECT contract_version,id,state,created_at_ms,updated_at_ms FROM sekai_tenants WHERE id=?1",
        params![id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get(3)?, row.get(4)?)),
    ).optional().map_err(storage)?.map(|(contract_version,id,state,created_at_ms,updated_at_ms)| Ok(TenantRecord {
        contract_version, id, state: TenantState::parse(&state)?, created_at_ms, updated_at_ms
    })).transpose()
}

fn request_result(
    conn: &rusqlite::Connection,
    key: &str,
    action: &str,
) -> Result<Option<TenantRecord>, TenantError> {
    let found: Option<(String, TenantRecord)> = conn
        .query_row(
            "SELECT action,tenant_id,response_contract_version,response_state,
                    response_created_at_ms,response_updated_at_ms
             FROM sekai_tenant_requests WHERE idempotency_key=?1",
            params![key],
            |row| {
                let state: String = row.get(3)?;
                let state =
                    TenantState::parse(&state).map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok((
                    row.get(0)?,
                    TenantRecord {
                        contract_version: row.get(2)?,
                        id: row.get(1)?,
                        state,
                        created_at_ms: row.get(4)?,
                        updated_at_ms: row.get(5)?,
                    },
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    match found {
        Some((stored_action, _)) if stored_action != action => Err(TenantError::Conflict(
            "idempotency key was used for another action".into(),
        )),
        Some((_, record)) => Ok(Some(record)),
        None => Ok(None),
    }
}

fn insert_request(
    conn: &rusqlite::Connection,
    key: &str,
    action: &str,
    record: &TenantRecord,
) -> Result<(), TenantError> {
    conn.execute(
        "INSERT INTO sekai_tenant_requests
            (idempotency_key,action,tenant_id,response_contract_version,response_state,
             response_created_at_ms,response_updated_at_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            key,
            action,
            record.id,
            record.contract_version,
            record.state.as_str(),
            record.created_at_ms,
            record.updated_at_ms
        ],
    )
    .map_err(storage)?;
    Ok(())
}

fn insert_audit(
    conn: &rusqlite::Connection,
    actor: &str,
    action: &str,
    tenant_id: &str,
    from: &str,
    to: &str,
    now_ms: i64,
) -> Result<(), TenantError> {
    let evidence = HashMap::from([
        ("contract_version".into(), TENANT_CONTRACT_VERSION.into()),
        ("from_state".into(), from.into()),
        ("to_state".into(), to.into()),
        ("data_class".into(), "internal".into()),
    ]);
    crate::sekai::ledger::insert_chained_decision(
        conn,
        &Decision {
            id: Uuid::new_v4().to_string(),
            timestamp: now_ms,
            actor: actor.into(),
            action: action.into(),
            reason: "tenant lifecycle transition".into(),
            evidence,
            target_id: tenant_id.into(),
            outcome: "applied".into(),
        },
    )
    .map_err(TenantError::Storage)
}

fn storage(error: impl ToString) -> TenantError {
    TenantError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn lifecycle_is_idempotent_audited_and_blocks_admission() {
        let db = SekaiDb::new(":memory:").unwrap();
        let created = db.create_tenant("root", "create-1", 10).unwrap();
        assert_eq!(created, db.create_tenant("root", "create-1", 11).unwrap());
        assert!(db.require_tenant_admission(&created.id).is_ok());

        let suspended = db
            .suspend_tenant(&created.id, "root", "suspend-1", 20)
            .unwrap();
        assert_eq!(
            suspended,
            db.suspend_tenant(&created.id, "root", "suspend-1", 21)
                .unwrap()
        );
        assert_eq!(
            db.require_tenant_admission(&created.id),
            Err(TenantError::AdmissionBlocked(TenantState::Suspended))
        );
        assert!(matches!(
            db.suspend_tenant(&created.id, "root", "suspend-2", 22),
            Err(TenantError::InvalidTransition { .. })
        ));

        db.reactivate_tenant(&created.id, "operator", "reactivate-1", 30)
            .unwrap();
        assert_eq!(
            db.suspend_tenant(&created.id, "root", "suspend-1", 31)
                .unwrap(),
            suspended
        );
        assert_eq!(db.create_tenant("root", "create-1", 32).unwrap(), created);
        let closing = db
            .request_tenant_closure(&created.id, "operator", "close-1", 40)
            .unwrap();
        assert_eq!(closing.state, TenantState::ClosurePending);
        assert!(matches!(
            db.reactivate_tenant(&created.id, "operator", "reactivate-2", 50),
            Err(TenantError::InvalidTransition { .. })
        ));
        assert_eq!(
            db.list_decisions(&crate::sekai::audit::DecisionFilter {
                target_id: Some(created.id),
                limit: 20,
                ..Default::default()
            })
            .unwrap()
            .len(),
            4
        );
    }

    #[test]
    fn concurrent_create_retries_return_one_tenant() {
        let path = std::env::temp_dir().join(format!("sekai-tenant-{}.db", Uuid::new_v4()));
        let db = Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let db = db.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    db.create_tenant("root", "same-create", 10).unwrap()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let tenants = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(tenants[0], tenants[1]);
        assert_eq!(
            db.list_decisions(&crate::sekai::audit::DecisionFilter {
                target_id: Some(tenants[0].id.clone()),
                limit: 20,
                ..Default::default()
            })
            .unwrap()
            .len(),
            1
        );
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
