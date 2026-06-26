use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, params};
use std::collections::{HashMap, HashSet};

pub const WORK_UNIT_STATUS_PENDING: &str = "pending";
pub const WORK_UNIT_STATUS_ADMITTED: &str = "admitted";
pub const WORK_UNIT_STATUS_RUNNING: &str = "running";
pub const WORK_UNIT_STATUS_COMPLETED: &str = "completed";
pub const WORK_UNIT_STATUS_FAILED: &str = "failed";
pub const WORK_UNIT_STATUS_TIMED_OUT: &str = "timed_out";
pub const WORK_UNIT_STATUS_CANCELLED: &str = "cancelled";
pub const WORK_UNIT_STATUS_STALE: &str = "stale";
pub const WORK_UNIT_STATUS_RECONCILED: &str = "reconciled";

pub const RESERVATION_STATUS_ACTIVE: &str = "active";
pub const RESERVATION_STATUS_RELEASED: &str = "released";

pub const ADMISSION_POLICY_FIFO: &str = "fifo";

#[derive(Debug, Clone, PartialEq)]
pub struct ContentionScope {
    pub id: String,
    pub name: String,
    pub parent_scope_id: String,
    pub max_concurrency: i32,
    pub admission_policy: String,
    pub heartbeat_ttl_seconds: i32,
    pub timeout_seconds: i32,
    pub owner_principal: String,
    pub created: i64,
    pub updated: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkUnit {
    pub id: String,
    pub kind: String,
    pub actor: String,
    pub target_object_id: String,
    pub status: String,
    pub requested_spec: String,
    pub scope_id: String,
    pub priority: i32,
    pub timeout_seconds: i32,
    pub heartbeat_ttl_seconds: i32,
    pub created_at: i64,
    pub admitted_at: i64,
    pub started_at: i64,
    pub finished_at: i64,
    pub last_heartbeat_at: i64,
    pub failure_reason: String,
    pub cancel_reason: String,
    pub owner_principal: String,
    pub creator_principal: String,
    pub idempotency_key: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reservation {
    pub id: String,
    pub work_unit_id: String,
    pub scope_id: String,
    pub status: String,
    pub lease_owner: String,
    pub leased_at: i64,
    pub expires_at: i64,
    pub released_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunEvent {
    pub id: String,
    pub work_unit_id: String,
    pub event_type: String,
    pub message: String,
    pub evidence: HashMap<String, String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReconciliationRecord {
    pub id: String,
    pub work_unit_id: String,
    pub reservation_id: String,
    pub reason: String,
    pub action: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct WorkUnitFilter {
    pub status: Option<String>,
    pub statuses: Vec<String>,
    pub actor: Option<String>,
    pub scope_id: Option<String>,
    pub target_object_id: Option<String>,
    pub owner_principal: Option<String>,
    pub creator_principal: Option<String>,
    pub created_after: i64,
    pub updated_after: i64,
    pub page_token: Option<String>,
    pub limit: i32,
    pub offset: i32,
}

#[derive(Debug, Clone, Default)]
pub struct ReservationFilter {
    pub work_unit_id: Option<String>,
    pub scope_id: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionResult {
    pub admitted: bool,
    pub queue_position: i32,
    pub reason: String,
    pub work_unit: WorkUnit,
    pub reservations: Vec<Reservation>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReconcileSummary {
    pub work_units_reconciled: i32,
    pub reservations_released: i32,
    pub details: Vec<ReconciliationRecord>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CoordinationSnapshot {
    pub pending_count: i32,
    pub running_count: i32,
    pub stale_count: i32,
    pub active_reservation_count: i32,
    pub oldest_pending_age_ms: i64,
    pub oldest_running_age_ms: i64,
    pub stale_reservation_count: i32,
    pub blocked_scopes: Vec<ScopeBlockage>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScopeBlockage {
    pub scope_id: String,
    pub scope_name: String,
    pub reason: String,
    pub pending_count: i32,
    pub active_count: i32,
}

#[derive(Debug, Clone, Default)]
pub struct ReconcileFilter {
    pub dry_run: bool,
    pub work_unit_id: Option<String>,
    pub scope_id: Option<String>,
    pub limit: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestDedup {
    pub request_id: String,
    pub operation: String,
    pub principal: String,
    pub scope_id: String,
    pub work_unit_id: String,
    pub created_at: i64,
}

impl SekaiDb {
    pub fn migrate_coordination(&self) {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_contention_scopes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                parent_scope_id TEXT NOT NULL DEFAULT '',
                max_concurrency INTEGER NOT NULL,
                admission_policy TEXT NOT NULL DEFAULT 'fifo',
                heartbeat_ttl_seconds INTEGER NOT NULL DEFAULT 300,
                timeout_seconds INTEGER NOT NULL DEFAULT 0,
                owner_principal TEXT NOT NULL DEFAULT '',
                created INTEGER NOT NULL,
                updated INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_coordination_scopes_parent ON sekai_contention_scopes(parent_scope_id);
            CREATE TABLE IF NOT EXISTS sekai_work_units (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                actor TEXT NOT NULL,
                target_object_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                requested_spec TEXT NOT NULL DEFAULT '',
                scope_id TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0,
                timeout_seconds INTEGER NOT NULL DEFAULT 0,
                heartbeat_ttl_seconds INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                admitted_at INTEGER NOT NULL DEFAULT 0,
                started_at INTEGER NOT NULL DEFAULT 0,
                finished_at INTEGER NOT NULL DEFAULT 0,
                last_heartbeat_at INTEGER NOT NULL DEFAULT 0,
                failure_reason TEXT NOT NULL DEFAULT '',
                cancel_reason TEXT NOT NULL DEFAULT '',
                owner_principal TEXT NOT NULL DEFAULT '',
                creator_principal TEXT NOT NULL DEFAULT '',
                idempotency_key TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_work_units_scope_status_created ON sekai_work_units(scope_id, status, created_at, id);
            CREATE INDEX IF NOT EXISTS idx_work_units_target_created ON sekai_work_units(target_object_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_work_units_owner_created ON sekai_work_units(owner_principal, created_at);
            CREATE INDEX IF NOT EXISTS idx_work_units_creator_created ON sekai_work_units(creator_principal, created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_work_units_idempotency ON sekai_work_units(idempotency_key) WHERE idempotency_key != '';
            CREATE TABLE IF NOT EXISTS sekai_reservations (
                id TEXT PRIMARY KEY,
                work_unit_id TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                status TEXT NOT NULL,
                lease_owner TEXT NOT NULL DEFAULT '',
                leased_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                released_at INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reservations_scope_status_leased ON sekai_reservations(scope_id, status, leased_at);
            CREATE INDEX IF NOT EXISTS idx_reservations_work_unit_status ON sekai_reservations(work_unit_id, status);
            CREATE INDEX IF NOT EXISTS idx_reservations_expiry_status ON sekai_reservations(expires_at, status);
            CREATE TABLE IF NOT EXISTS sekai_run_events (
                id TEXT PRIMARY KEY,
                work_unit_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                evidence_json TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_run_events_work_unit_created ON sekai_run_events(work_unit_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_run_events_type_created ON sekai_run_events(event_type, created_at);
            CREATE TABLE IF NOT EXISTS sekai_reconciliations (
                id TEXT PRIMARY KEY,
                work_unit_id TEXT NOT NULL DEFAULT '',
                reservation_id TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reconciliations_work_unit_created ON sekai_reconciliations(work_unit_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_reconciliations_reservation_created ON sekai_reconciliations(reservation_id, created_at);
            CREATE TABLE IF NOT EXISTS sekai_coordination_requests (
                request_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                principal TEXT NOT NULL DEFAULT '',
                scope_id TEXT NOT NULL DEFAULT '',
                work_unit_id TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                PRIMARY KEY (request_id, operation)
            );",
        )
        .unwrap();
        for migration in [
            "ALTER TABLE sekai_work_units ADD COLUMN creator_principal TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE sekai_work_units ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE sekai_work_units ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0",
        ] {
            let _ = conn.execute(migration, []);
        }
    }

    pub fn create_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        validate_scope(scope)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sekai_contention_scopes (id,name,parent_scope_id,max_concurrency,admission_policy,heartbeat_ttl_seconds,timeout_seconds,owner_principal,created,updated)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                scope.id,
                scope.name,
                scope.parent_scope_id,
                scope.max_concurrency,
                scope.admission_policy,
                scope.heartbeat_ttl_seconds,
                scope.timeout_seconds,
                scope.owner_principal,
                scope.created,
                scope.updated,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn update_contention_scope(&self, scope: &ContentionScope) -> Result<(), String> {
        validate_scope(scope)?;
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute(
                "UPDATE sekai_contention_scopes
                 SET name=?2,parent_scope_id=?3,max_concurrency=?4,admission_policy=?5,heartbeat_ttl_seconds=?6,timeout_seconds=?7,owner_principal=?8,updated=?9
                 WHERE id=?1",
                params![
                    scope.id,
                    scope.name,
                    scope.parent_scope_id,
                    scope.max_concurrency,
                    scope.admission_policy,
                    scope.heartbeat_ttl_seconds,
                    scope.timeout_seconds,
                    scope.owner_principal,
                    scope.updated,
                ],
            )
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("scope not found".into());
        }
        Ok(())
    }

    pub fn get_contention_scope(&self, id: &str) -> Result<Option<ContentionScope>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id,name,parent_scope_id,max_concurrency,admission_policy,heartbeat_ttl_seconds,timeout_seconds,owner_principal,created,updated
             FROM sekai_contention_scopes WHERE id=?1",
            params![id],
            row_to_contention_scope,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn list_contention_scopes(&self) -> Result<Vec<ContentionScope>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id,name,parent_scope_id,max_concurrency,admission_policy,heartbeat_ttl_seconds,timeout_seconds,owner_principal,created,updated
                 FROM sekai_contention_scopes ORDER BY name, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], row_to_contention_scope)
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn create_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        validate_work_unit(work_unit)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sekai_work_units
             (id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
            params![
                work_unit.id,
                work_unit.kind,
                work_unit.actor,
                work_unit.target_object_id,
                work_unit.status,
                work_unit.requested_spec,
                work_unit.scope_id,
                work_unit.priority,
                work_unit.timeout_seconds,
                work_unit.heartbeat_ttl_seconds,
                work_unit.created_at,
                work_unit.admitted_at,
                work_unit.started_at,
                work_unit.finished_at,
                work_unit.last_heartbeat_at,
                work_unit.failure_reason,
                work_unit.cancel_reason,
                work_unit.owner_principal,
                work_unit.creator_principal,
                work_unit.idempotency_key,
                work_unit.updated_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_work_unit(&self, id: &str) -> Result<Option<WorkUnit>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at
             FROM sekai_work_units WHERE id=?1",
            params![id],
            row_to_work_unit,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn get_work_unit_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<WorkUnit>, String> {
        if idempotency_key.is_empty() {
            return Ok(None);
        }
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at
             FROM sekai_work_units WHERE idempotency_key=?1",
            params![idempotency_key],
            row_to_work_unit,
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn update_work_unit(&self, work_unit: &WorkUnit) -> Result<(), String> {
        validate_work_unit(work_unit)?;
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute(
                "UPDATE sekai_work_units
                 SET kind=?2,actor=?3,target_object_id=?4,status=?5,requested_spec=?6,scope_id=?7,priority=?8,timeout_seconds=?9,heartbeat_ttl_seconds=?10,admitted_at=?11,started_at=?12,finished_at=?13,last_heartbeat_at=?14,failure_reason=?15,cancel_reason=?16,owner_principal=?17,creator_principal=?18,idempotency_key=?19,updated_at=?20
                 WHERE id=?1",
                params![
                    work_unit.id,
                    work_unit.kind,
                    work_unit.actor,
                    work_unit.target_object_id,
                    work_unit.status,
                    work_unit.requested_spec,
                    work_unit.scope_id,
                    work_unit.priority,
                    work_unit.timeout_seconds,
                    work_unit.heartbeat_ttl_seconds,
                    work_unit.admitted_at,
                    work_unit.started_at,
                    work_unit.finished_at,
                    work_unit.last_heartbeat_at,
                    work_unit.failure_reason,
                    work_unit.cancel_reason,
                    work_unit.owner_principal,
                    work_unit.creator_principal,
                    work_unit.idempotency_key,
                    work_unit.updated_at,
                ],
            )
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("work unit not found".into());
        }
        Ok(())
    }

    pub fn list_work_units(&self, filter: &WorkUnitFilter) -> Result<Vec<WorkUnit>, String> {
        let conn = self.conn.lock().unwrap();
        let mut sql = "SELECT id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at FROM sekai_work_units WHERE 1=1".to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
        if !filter.statuses.is_empty() {
            let placeholders: Vec<String> = filter
                .statuses
                .iter()
                .map(|status| {
                    params_vec.push(Box::new(status.clone()));
                    format!("?{}", params_vec.len())
                })
                .collect();
            sql.push_str(&format!(" AND status IN ({})", placeholders.join(",")));
        } else if let Some(status) = &filter.status {
            sql.push_str(&format!(" AND status = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(status.clone()));
        }
        if let Some(actor) = &filter.actor {
            sql.push_str(&format!(" AND actor = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(actor.clone()));
        }
        if let Some(scope_id) = &filter.scope_id {
            sql.push_str(&format!(" AND scope_id = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(scope_id.clone()));
        }
        if let Some(target) = &filter.target_object_id {
            sql.push_str(&format!(
                " AND target_object_id = ?{}",
                params_vec.len() + 1
            ));
            params_vec.push(Box::new(target.clone()));
        }
        if let Some(owner) = &filter.owner_principal {
            sql.push_str(&format!(" AND owner_principal = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(owner.clone()));
        }
        if let Some(creator) = &filter.creator_principal {
            sql.push_str(&format!(
                " AND creator_principal = ?{}",
                params_vec.len() + 1
            ));
            params_vec.push(Box::new(creator.clone()));
        }
        if filter.created_after > 0 {
            sql.push_str(&format!(" AND created_at > ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(filter.created_after));
        }
        if filter.updated_after > 0 {
            sql.push_str(&format!(" AND updated_at > ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(filter.updated_after));
        }
        if let Some(page_token) = &filter.page_token
            && let Some((created_at, id)) = parse_page_token(page_token)
        {
            {
                sql.push_str(&format!(
                    " AND (created_at > ?{} OR (created_at = ?{} AND id > ?{}))",
                    params_vec.len() + 1,
                    params_vec.len() + 2,
                    params_vec.len() + 3
                ));
                params_vec.push(Box::new(created_at));
                params_vec.push(Box::new(created_at));
                params_vec.push(Box::new(id));
            }
        }
        sql.push_str(" ORDER BY created_at, id");
        if filter.limit > 0 {
            sql.push_str(&format!(" LIMIT ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(filter.limit + 1));
            if filter.offset > 0 {
                sql.push_str(&format!(" OFFSET ?{}", params_vec.len() + 1));
                params_vec.push(Box::new(filter.offset));
            }
        } else if filter.offset > 0 {
            sql.push_str(&format!(" LIMIT -1 OFFSET ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(filter.offset));
        }
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_work_unit)
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn create_reservation(&self, reservation: &Reservation) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sekai_reservations
             (id,work_unit_id,scope_id,status,lease_owner,leased_at,expires_at,released_at,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                reservation.id,
                reservation.work_unit_id,
                reservation.scope_id,
                reservation.status,
                reservation.lease_owner,
                reservation.leased_at,
                reservation.expires_at,
                reservation.released_at,
                reservation.created_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_reservations(
        &self,
        filter: &ReservationFilter,
    ) -> Result<Vec<Reservation>, String> {
        let conn = self.conn.lock().unwrap();
        let mut sql = "SELECT id,work_unit_id,scope_id,status,lease_owner,leased_at,expires_at,released_at,created_at FROM sekai_reservations WHERE 1=1".to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
        if let Some(work_unit_id) = &filter.work_unit_id {
            sql.push_str(&format!(" AND work_unit_id = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(work_unit_id.clone()));
        }
        if let Some(scope_id) = &filter.scope_id {
            sql.push_str(&format!(" AND scope_id = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(scope_id.clone()));
        }
        if let Some(status) = &filter.status {
            sql.push_str(&format!(" AND status = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(status.clone()));
        }
        sql.push_str(" ORDER BY leased_at, id");
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_reservation)
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn append_run_event(&self, event: &RunEvent) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let evidence_json = serde_json::to_string(&event.evidence).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO sekai_run_events (id,work_unit_id,event_type,message,evidence_json,created_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                event.id,
                event.work_unit_id,
                event.event_type,
                event.message,
                evidence_json,
                event.created_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_dedup_request(
        &self,
        request_id: &str,
        operation: &str,
    ) -> Result<Option<RequestDedup>, String> {
        if request_id.is_empty() {
            return Ok(None);
        }
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT request_id,operation,principal,scope_id,work_unit_id,created_at
             FROM sekai_coordination_requests WHERE request_id = ?1 AND operation = ?2",
            params![request_id, operation],
            |row| {
                Ok(RequestDedup {
                    request_id: row.get(0)?,
                    operation: row.get(1)?,
                    principal: row.get(2)?,
                    scope_id: row.get(3)?,
                    work_unit_id: row.get(4)?,
                    created_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    pub fn record_dedup_request(&self, request: &RequestDedup) -> Result<(), String> {
        if request.request_id.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO sekai_coordination_requests
             (request_id,operation,principal,scope_id,work_unit_id,created_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                request.request_id,
                request.operation,
                request.principal,
                request.scope_id,
                request.work_unit_id,
                request.created_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn list_run_events(
        &self,
        work_unit_id: &str,
        limit: i32,
        after: i64,
        event_types: &[String],
        page_token: Option<&str>,
    ) -> Result<Vec<RunEvent>, String> {
        let conn = self.conn.lock().unwrap();
        let mut sql = "SELECT id,work_unit_id,event_type,message,evidence_json,created_at FROM sekai_run_events WHERE work_unit_id = ?1 AND created_at >= ?2".to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> =
            vec![Box::new(work_unit_id.to_string()), Box::new(after)];
        if !event_types.is_empty() {
            let placeholders: Vec<String> = event_types
                .iter()
                .map(|event_type| {
                    params_vec.push(Box::new(event_type.clone()));
                    format!("?{}", params_vec.len())
                })
                .collect();
            sql.push_str(&format!(" AND event_type IN ({})", placeholders.join(",")));
        }
        if let Some(page_token) = page_token
            && let Some((created_at, id)) = parse_page_token(page_token)
        {
            {
                sql.push_str(&format!(
                    " AND (created_at > ?{} OR (created_at = ?{} AND id > ?{}))",
                    params_vec.len() + 1,
                    params_vec.len() + 2,
                    params_vec.len() + 3
                ));
                params_vec.push(Box::new(created_at));
                params_vec.push(Box::new(created_at));
                params_vec.push(Box::new(id));
            }
        }
        sql.push_str(&format!(
            " ORDER BY created_at, id LIMIT ?{}",
            params_vec.len() + 1
        ));
        params_vec.push(Box::new(if limit > 0 { limit + 1 } else { 101 }));
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_run_event)
            .map_err(|e| e.to_string())?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn create_reconciliation_record(
        &self,
        record: &ReconciliationRecord,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sekai_reconciliations (id,work_unit_id,reservation_id,reason,action,created_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                record.id,
                record.work_unit_id,
                record.reservation_id,
                record.reason,
                record.action,
                record.created_at,
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn try_admit_work_unit(
        &self,
        work_unit_id: &str,
        lease_owner: &str,
        now_ms: i64,
    ) -> Result<AdmissionResult, String> {
        let conn = self.conn.lock().unwrap();
        let mut work_unit = conn
            .query_row(
                "SELECT id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at
                 FROM sekai_work_units WHERE id=?1",
                params![work_unit_id],
                row_to_work_unit,
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "work unit not found".to_string())?;
        if work_unit.status != WORK_UNIT_STATUS_PENDING {
            return Ok(AdmissionResult {
                admitted: false,
                queue_position: 0,
                reason: format!("work unit is not pending: {}", work_unit.status),
                reservations: vec![],
                work_unit,
            });
        }
        let candidate_chain = scope_chain_locked(&conn, &work_unit.scope_id)?;
        let all_pending = {
            let mut stmt = conn
                .prepare(
                    "SELECT id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at
                     FROM sekai_work_units WHERE status = ?1 ORDER BY created_at, id",
                )
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map(params![WORK_UNIT_STATUS_PENDING], row_to_work_unit)
                .map_err(|e| e.to_string())?;
            rows.filter_map(Result::ok).collect::<Vec<_>>()
        };
        let mut conflicting_older = 0;
        for other in &all_pending {
            if other.id == work_unit.id {
                break;
            }
            let other_chain = scope_chain_locked(&conn, &other.scope_id)?;
            if chains_overlap(&candidate_chain, &other_chain) {
                conflicting_older += 1;
            }
        }
        if conflicting_older > 0 {
            return Ok(AdmissionResult {
                admitted: false,
                queue_position: conflicting_older + 1,
                reason: "older pending work unit holds queue precedence".into(),
                reservations: vec![],
                work_unit,
            });
        }
        for scope in &candidate_chain {
            let active_count: i32 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sekai_reservations WHERE scope_id = ?1 AND status = ?2 AND released_at = 0 AND expires_at > ?3",
                    params![scope.id, RESERVATION_STATUS_ACTIVE, now_ms],
                    |row| row.get(0),
                )
                .map_err(|e| e.to_string())?;
            if active_count >= scope.max_concurrency {
                return Ok(AdmissionResult {
                    admitted: false,
                    queue_position: 1,
                    reason: format!("scope {} is saturated", scope.name),
                    reservations: vec![],
                    work_unit,
                });
            }
        }
        let mut reservations = Vec::new();
        for scope in &candidate_chain {
            let ttl_seconds = if work_unit.heartbeat_ttl_seconds > 0 {
                work_unit.heartbeat_ttl_seconds
            } else {
                scope.heartbeat_ttl_seconds
            };
            let reservation = Reservation {
                id: format!("res:{}:{}", work_unit.id, scope.id),
                work_unit_id: work_unit.id.clone(),
                scope_id: scope.id.clone(),
                status: RESERVATION_STATUS_ACTIVE.into(),
                lease_owner: lease_owner.to_string(),
                leased_at: now_ms,
                expires_at: now_ms + (ttl_seconds as i64 * 1000),
                released_at: 0,
                created_at: now_ms,
            };
            conn.execute(
                "INSERT INTO sekai_reservations
                 (id,work_unit_id,scope_id,status,lease_owner,leased_at,expires_at,released_at,created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    reservation.id,
                    reservation.work_unit_id,
                    reservation.scope_id,
                    reservation.status,
                    reservation.lease_owner,
                    reservation.leased_at,
                    reservation.expires_at,
                    reservation.released_at,
                    reservation.created_at,
                ],
            )
            .map_err(|e| e.to_string())?;
            reservations.push(reservation);
        }
        ensure_transition(&work_unit.status, WORK_UNIT_STATUS_RUNNING)?;
        work_unit.status = WORK_UNIT_STATUS_RUNNING.into();
        work_unit.admitted_at = now_ms;
        work_unit.started_at = now_ms;
        work_unit.last_heartbeat_at = now_ms;
        work_unit.updated_at = now_ms;
        conn.execute(
            "UPDATE sekai_work_units SET status=?2,admitted_at=?3,started_at=?4,last_heartbeat_at=?5,updated_at=?6 WHERE id=?1",
            params![work_unit.id, work_unit.status, work_unit.admitted_at, work_unit.started_at, work_unit.last_heartbeat_at, work_unit.updated_at],
        )
        .map_err(|e| e.to_string())?;
        let event = RunEvent {
            id: format!("evt:{}:admitted:{}", work_unit.id, now_ms),
            work_unit_id: work_unit.id.clone(),
            event_type: "admitted".into(),
            message: format!("work unit admitted into scope {}", work_unit.scope_id),
            evidence: HashMap::from([("scope_id".into(), work_unit.scope_id.clone())]),
            created_at: now_ms,
        };
        let evidence_json = serde_json::to_string(&event.evidence).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO sekai_run_events (id,work_unit_id,event_type,message,evidence_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![event.id, event.work_unit_id, event.event_type, event.message, evidence_json, event.created_at],
        )
        .map_err(|e| e.to_string())?;
        Ok(AdmissionResult {
            admitted: true,
            queue_position: 0,
            reason: String::new(),
            reservations,
            work_unit,
        })
    }

    pub fn heartbeat_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        let conn = self.conn.lock().unwrap();
        let mut work_unit = conn
            .query_row(
                "SELECT id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at
                 FROM sekai_work_units WHERE id=?1",
                params![work_unit_id],
                row_to_work_unit,
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "work unit not found".to_string())?;
        if !matches!(
            work_unit.status.as_str(),
            WORK_UNIT_STATUS_RUNNING | WORK_UNIT_STATUS_ADMITTED
        ) {
            return Err(format!(
                "cannot heartbeat work unit in status {}",
                work_unit.status
            ));
        }
        let chain = scope_chain_locked(&conn, &work_unit.scope_id)?;
        for scope in &chain {
            let ttl_seconds = if work_unit.heartbeat_ttl_seconds > 0 {
                work_unit.heartbeat_ttl_seconds
            } else {
                scope.heartbeat_ttl_seconds
            };
            conn.execute(
                "UPDATE sekai_reservations SET expires_at = ?3 WHERE work_unit_id = ?1 AND scope_id = ?2 AND status = ?4 AND released_at = 0",
                params![work_unit.id, scope.id, now_ms + (ttl_seconds as i64 * 1000), RESERVATION_STATUS_ACTIVE],
            )
            .map_err(|e| e.to_string())?;
        }
        work_unit.last_heartbeat_at = now_ms;
        work_unit.updated_at = now_ms;
        conn.execute(
            "UPDATE sekai_work_units SET last_heartbeat_at = ?2, updated_at = ?3 WHERE id = ?1",
            params![
                work_unit.id,
                work_unit.last_heartbeat_at,
                work_unit.updated_at
            ],
        )
        .map_err(|e| e.to_string())?;
        let event = RunEvent {
            id: format!("evt:{}:heartbeat:{}", work_unit.id, now_ms),
            work_unit_id: work_unit.id.clone(),
            event_type: "heartbeat".into(),
            message: "heartbeat received".into(),
            evidence: HashMap::new(),
            created_at: now_ms,
        };
        let evidence_json = serde_json::to_string(&event.evidence).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO sekai_run_events (id,work_unit_id,event_type,message,evidence_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![event.id, event.work_unit_id, event.event_type, event.message, evidence_json, event.created_at],
        )
        .map_err(|e| e.to_string())?;
        Ok(work_unit)
    }

    pub fn complete_work_unit(&self, work_unit_id: &str, now_ms: i64) -> Result<WorkUnit, String> {
        self.finish_work_unit(work_unit_id, WORK_UNIT_STATUS_COMPLETED, "", "", now_ms)
    }

    pub fn fail_work_unit(
        &self,
        work_unit_id: &str,
        failure_reason: &str,
        now_ms: i64,
    ) -> Result<WorkUnit, String> {
        self.finish_work_unit(
            work_unit_id,
            WORK_UNIT_STATUS_FAILED,
            failure_reason,
            "",
            now_ms,
        )
    }

    pub fn cancel_work_unit(
        &self,
        work_unit_id: &str,
        cancel_reason: &str,
        now_ms: i64,
    ) -> Result<WorkUnit, String> {
        self.finish_work_unit(
            work_unit_id,
            WORK_UNIT_STATUS_CANCELLED,
            "",
            cancel_reason,
            now_ms,
        )
    }

    pub fn release_reservations_for_work_unit(
        &self,
        work_unit_id: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        let conn = self.conn.lock().unwrap();
        let count = conn
            .execute(
                "UPDATE sekai_reservations
                 SET status = ?2, released_at = ?3
                 WHERE work_unit_id = ?1 AND status = ?4 AND released_at = 0",
                params![
                    work_unit_id,
                    RESERVATION_STATUS_RELEASED,
                    now_ms,
                    RESERVATION_STATUS_ACTIVE
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(count as i32)
    }

    pub fn reconcile_work_units(
        &self,
        now_ms: i64,
        filter: &ReconcileFilter,
    ) -> Result<ReconcileSummary, String> {
        let conn = self.conn.lock().unwrap();
        let mut summary = ReconcileSummary::default();

        let mut sql = "SELECT id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at
                 FROM sekai_work_units
                 WHERE status IN (?1, ?2, ?3)"
            .to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = vec![
            Box::new(WORK_UNIT_STATUS_PENDING.to_string()),
            Box::new(WORK_UNIT_STATUS_ADMITTED.to_string()),
            Box::new(WORK_UNIT_STATUS_RUNNING.to_string()),
        ];
        if let Some(work_unit_id) = &filter.work_unit_id {
            sql.push_str(&format!(" AND id = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(work_unit_id.clone()));
        }
        if let Some(scope_id) = &filter.scope_id {
            sql.push_str(&format!(" AND scope_id = ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(scope_id.clone()));
        }
        sql.push_str(" ORDER BY created_at, id");
        if filter.limit > 0 {
            sql.push_str(&format!(" LIMIT ?{}", params_vec.len() + 1));
            params_vec.push(Box::new(filter.limit));
        }
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_work_unit)
            .map_err(|e| e.to_string())?;
        let live_units: Vec<WorkUnit> = rows.filter_map(Result::ok).collect();

        for mut work_unit in live_units {
            let active_reservations: Vec<Reservation> = {
                let mut r_stmt = conn
                    .prepare(
                        "SELECT id,work_unit_id,scope_id,status,lease_owner,leased_at,expires_at,released_at,created_at
                         FROM sekai_reservations
                         WHERE work_unit_id = ?1 AND status = ?2 AND released_at = 0",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = r_stmt
                    .query_map(
                        params![work_unit.id, RESERVATION_STATUS_ACTIVE],
                        row_to_reservation,
                    )
                    .map_err(|e| e.to_string())?;
                rows.filter_map(Result::ok).collect()
            };
            let timed_out = work_unit.started_at > 0
                && work_unit.timeout_seconds > 0
                && now_ms >= work_unit.started_at + (work_unit.timeout_seconds as i64 * 1000);
            let stale = !active_reservations.is_empty()
                && active_reservations
                    .iter()
                    .any(|reservation| reservation.expires_at <= now_ms);
            if !timed_out && !stale {
                continue;
            }
            let new_status = if timed_out {
                WORK_UNIT_STATUS_TIMED_OUT
            } else {
                WORK_UNIT_STATUS_STALE
            };
            let reason = if timed_out {
                "work unit exceeded timeout"
            } else {
                "reservation lease expired"
            };
            let released = active_reservations.len() as i32;
            if !filter.dry_run {
                conn.execute(
                    "UPDATE sekai_reservations
                     SET status = ?2, released_at = ?3
                     WHERE work_unit_id = ?1 AND status = ?4 AND released_at = 0",
                    params![
                        work_unit.id,
                        RESERVATION_STATUS_RELEASED,
                        now_ms,
                        RESERVATION_STATUS_ACTIVE
                    ],
                )
                .map_err(|e| e.to_string())?;
            }
            summary.reservations_released += released;
            work_unit.status = new_status.into();
            work_unit.finished_at = now_ms;
            work_unit.updated_at = now_ms;
            if timed_out {
                work_unit.failure_reason = reason.into();
            }
            let record = ReconciliationRecord {
                id: format!("reconcile:{}:{}", work_unit.id, now_ms),
                work_unit_id: work_unit.id.clone(),
                reservation_id: String::new(),
                reason: reason.into(),
                action: if filter.dry_run {
                    "would_release_reservations".into()
                } else {
                    "release_reservations".into()
                },
                created_at: now_ms,
            };
            if !filter.dry_run {
                conn.execute(
                    "UPDATE sekai_work_units SET status = ?2, finished_at = ?3, failure_reason = ?4, updated_at = ?5 WHERE id = ?1",
                    params![work_unit.id, work_unit.status, work_unit.finished_at, work_unit.failure_reason, work_unit.updated_at],
                )
                .map_err(|e| e.to_string())?;
                let event = RunEvent {
                    id: format!("evt:{}:reconcile:{}", work_unit.id, now_ms),
                    work_unit_id: work_unit.id.clone(),
                    event_type: if timed_out { "timed_out" } else { "stale" }.into(),
                    message: reason.into(),
                    evidence: HashMap::new(),
                    created_at: now_ms,
                };
                let evidence_json =
                    serde_json::to_string(&event.evidence).map_err(|e| e.to_string())?;
                conn.execute(
                    "INSERT INTO sekai_run_events (id,work_unit_id,event_type,message,evidence_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![event.id, event.work_unit_id, event.event_type, event.message, evidence_json, event.created_at],
                )
                .map_err(|e| e.to_string())?;
                conn.execute(
                    "INSERT INTO sekai_reconciliations (id,work_unit_id,reservation_id,reason,action,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![record.id, record.work_unit_id, record.reservation_id, record.reason, record.action, record.created_at],
                )
                .map_err(|e| e.to_string())?;
            }
            summary.details.push(record);
            summary.work_units_reconciled += 1;
        }
        Ok(summary)
    }

    pub fn coordination_snapshot(&self, now_ms: i64) -> Result<CoordinationSnapshot, String> {
        let work_units = self.list_work_units(&WorkUnitFilter::default())?;
        let reservations = self.list_reservations(&ReservationFilter::default())?;
        let scopes = self.list_contention_scopes()?;
        let pending: Vec<&WorkUnit> = work_units
            .iter()
            .filter(|work_unit| work_unit.status == WORK_UNIT_STATUS_PENDING)
            .collect();
        let running_count = work_units
            .iter()
            .filter(|work_unit| work_unit.status == WORK_UNIT_STATUS_RUNNING)
            .count() as i32;
        let stale_count = work_units
            .iter()
            .filter(|work_unit| {
                work_unit.status == WORK_UNIT_STATUS_STALE
                    || work_unit.status == WORK_UNIT_STATUS_TIMED_OUT
            })
            .count() as i32;
        let oldest_running_age_ms = work_units
            .iter()
            .filter(|work_unit| work_unit.status == WORK_UNIT_STATUS_RUNNING)
            .map(|work_unit| now_ms.saturating_sub(work_unit.started_at.max(work_unit.created_at)))
            .max()
            .unwrap_or(0);
        let stale_reservation_count = reservations
            .iter()
            .filter(|reservation| {
                reservation.status == RESERVATION_STATUS_ACTIVE
                    && reservation.released_at == 0
                    && reservation.expires_at <= now_ms
            })
            .count() as i32;
        let active_reservation_count = reservations
            .iter()
            .filter(|reservation| {
                reservation.status == RESERVATION_STATUS_ACTIVE
                    && reservation.released_at == 0
                    && reservation.expires_at > now_ms
            })
            .count() as i32;
        let oldest_pending_age_ms = pending
            .iter()
            .map(|work_unit| now_ms.saturating_sub(work_unit.created_at))
            .max()
            .unwrap_or(0);
        let scope_names: HashMap<String, String> = scopes
            .iter()
            .map(|scope| (scope.id.clone(), scope.name.clone()))
            .collect();
        let mut blocked_scopes = Vec::new();
        for scope in &scopes {
            let pending_count = pending
                .iter()
                .filter(|work_unit| work_unit.scope_id == scope.id)
                .count() as i32;
            if pending_count == 0 {
                continue;
            }
            let active_count = reservations
                .iter()
                .filter(|reservation| {
                    reservation.scope_id == scope.id
                        && reservation.status == RESERVATION_STATUS_ACTIVE
                        && reservation.released_at == 0
                        && reservation.expires_at > now_ms
                })
                .count() as i32;
            let reason = if active_count >= scope.max_concurrency {
                format!("scope {} is saturated", scope.name)
            } else {
                "older pending work unit holds queue precedence".into()
            };
            blocked_scopes.push(ScopeBlockage {
                scope_id: scope.id.clone(),
                scope_name: scope_names
                    .get(&scope.id)
                    .cloned()
                    .unwrap_or_else(|| scope.id.clone()),
                reason,
                pending_count,
                active_count,
            });
        }
        Ok(CoordinationSnapshot {
            pending_count: pending.len() as i32,
            running_count,
            stale_count,
            active_reservation_count,
            oldest_pending_age_ms,
            oldest_running_age_ms,
            stale_reservation_count,
            blocked_scopes,
        })
    }

    fn finish_work_unit(
        &self,
        work_unit_id: &str,
        status: &str,
        failure_reason: &str,
        cancel_reason: &str,
        now_ms: i64,
    ) -> Result<WorkUnit, String> {
        let conn = self.conn.lock().unwrap();
        let mut work_unit = conn
            .query_row(
                "SELECT id,kind,actor,target_object_id,status,requested_spec,scope_id,priority,timeout_seconds,heartbeat_ttl_seconds,created_at,admitted_at,started_at,finished_at,last_heartbeat_at,failure_reason,cancel_reason,owner_principal,creator_principal,idempotency_key,updated_at
                 FROM sekai_work_units WHERE id=?1",
                params![work_unit_id],
                row_to_work_unit,
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "work unit not found".to_string())?;
        if is_terminal_status(&work_unit.status) {
            return Ok(work_unit);
        }
        ensure_transition(&work_unit.status, status)?;
        conn.execute(
            "UPDATE sekai_reservations
             SET status = ?2, released_at = ?3
             WHERE work_unit_id = ?1 AND status = ?4 AND released_at = 0",
            params![
                work_unit.id,
                RESERVATION_STATUS_RELEASED,
                now_ms,
                RESERVATION_STATUS_ACTIVE
            ],
        )
        .map_err(|e| e.to_string())?;
        work_unit.status = status.into();
        work_unit.finished_at = now_ms;
        work_unit.failure_reason = failure_reason.into();
        work_unit.cancel_reason = cancel_reason.into();
        work_unit.updated_at = now_ms;
        conn.execute(
            "UPDATE sekai_work_units
             SET status = ?2, finished_at = ?3, failure_reason = ?4, cancel_reason = ?5, updated_at = ?6
             WHERE id = ?1",
            params![
                work_unit.id,
                work_unit.status,
                work_unit.finished_at,
                work_unit.failure_reason,
                work_unit.cancel_reason,
                work_unit.updated_at
            ],
        )
        .map_err(|e| e.to_string())?;
        let event = RunEvent {
            id: format!("evt:{}:{}:{}", work_unit.id, status, now_ms),
            work_unit_id: work_unit.id.clone(),
            event_type: status.into(),
            message: if !failure_reason.is_empty() {
                failure_reason.into()
            } else if !cancel_reason.is_empty() {
                cancel_reason.into()
            } else {
                format!("work unit {}", status)
            },
            evidence: HashMap::new(),
            created_at: now_ms,
        };
        let evidence_json = serde_json::to_string(&event.evidence).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO sekai_run_events (id,work_unit_id,event_type,message,evidence_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            params![event.id, event.work_unit_id, event.event_type, event.message, evidence_json, event.created_at],
        )
        .map_err(|e| e.to_string())?;
        Ok(work_unit)
    }
}

fn validate_scope(scope: &ContentionScope) -> Result<(), String> {
    if scope.id.is_empty() {
        return Err("scope id required".into());
    }
    if scope.name.is_empty() {
        return Err("scope name required".into());
    }
    if scope.max_concurrency < 1 {
        return Err("scope max_concurrency must be >= 1".into());
    }
    if scope.admission_policy.is_empty() {
        return Err("scope admission policy required".into());
    }
    Ok(())
}

fn validate_work_unit(work_unit: &WorkUnit) -> Result<(), String> {
    if work_unit.id.is_empty() {
        return Err("work unit id required".into());
    }
    if work_unit.kind.is_empty() {
        return Err("work unit kind required".into());
    }
    if work_unit.actor.is_empty() {
        return Err("work unit actor required".into());
    }
    if work_unit.scope_id.is_empty() {
        return Err("work unit scope_id required".into());
    }
    if work_unit.status.is_empty() {
        return Err("work unit status required".into());
    }
    if work_unit.owner_principal.is_empty() {
        return Err("work unit owner_principal required".into());
    }
    if work_unit.creator_principal.is_empty() {
        return Err("work unit creator_principal required".into());
    }
    Ok(())
}

fn is_terminal_status(status: &str) -> bool {
    matches!(
        status,
        WORK_UNIT_STATUS_COMPLETED
            | WORK_UNIT_STATUS_FAILED
            | WORK_UNIT_STATUS_TIMED_OUT
            | WORK_UNIT_STATUS_CANCELLED
            | WORK_UNIT_STATUS_STALE
            | WORK_UNIT_STATUS_RECONCILED
    )
}

fn ensure_transition(current: &str, next: &str) -> Result<(), String> {
    let legal = matches!(
        (current, next),
        (WORK_UNIT_STATUS_PENDING, WORK_UNIT_STATUS_RUNNING)
            | (WORK_UNIT_STATUS_PENDING, WORK_UNIT_STATUS_CANCELLED)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_RUNNING)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_COMPLETED)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_FAILED)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_CANCELLED)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_COMPLETED)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_FAILED)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_CANCELLED)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_STALE)
            | (WORK_UNIT_STATUS_RUNNING, WORK_UNIT_STATUS_TIMED_OUT)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_STALE)
            | (WORK_UNIT_STATUS_ADMITTED, WORK_UNIT_STATUS_TIMED_OUT)
    );
    if legal {
        Ok(())
    } else {
        Err(format!(
            "invalid work unit transition: {} -> {}",
            current, next
        ))
    }
}

pub fn make_page_token(created_at: i64, id: &str) -> String {
    format!("{}|{}", created_at, id)
}

fn parse_page_token(page_token: &str) -> Option<(i64, String)> {
    let (left, right) = page_token.split_once('|')?;
    let created_at = left.parse::<i64>().ok()?;
    Some((created_at, right.to_string()))
}

fn scope_chain_locked(
    conn: &rusqlite::Connection,
    scope_id: &str,
) -> Result<Vec<ContentionScope>, String> {
    let mut chain = Vec::new();
    let mut current_id = scope_id.to_string();
    let mut seen = HashSet::new();
    while !current_id.is_empty() {
        if !seen.insert(current_id.clone()) {
            return Err(format!("scope cycle detected at {}", current_id));
        }
        let scope = conn
            .query_row(
                "SELECT id,name,parent_scope_id,max_concurrency,admission_policy,heartbeat_ttl_seconds,timeout_seconds,owner_principal,created,updated
                 FROM sekai_contention_scopes WHERE id=?1",
                params![current_id],
                row_to_contention_scope,
            )
            .optional()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("scope not found: {}", scope_id))?;
        current_id = scope.parent_scope_id.clone();
        chain.push(scope);
    }
    chain.reverse();
    Ok(chain)
}

fn chains_overlap(left: &[ContentionScope], right: &[ContentionScope]) -> bool {
    let left_ids: HashSet<&str> = left.iter().map(|scope| scope.id.as_str()).collect();
    right
        .iter()
        .any(|scope| left_ids.contains(scope.id.as_str()))
}

fn row_to_contention_scope(row: &rusqlite::Row) -> rusqlite::Result<ContentionScope> {
    Ok(ContentionScope {
        id: row.get(0)?,
        name: row.get(1)?,
        parent_scope_id: row.get(2)?,
        max_concurrency: row.get(3)?,
        admission_policy: row.get(4)?,
        heartbeat_ttl_seconds: row.get(5)?,
        timeout_seconds: row.get(6)?,
        owner_principal: row.get(7)?,
        created: row.get(8)?,
        updated: row.get(9)?,
    })
}

fn row_to_work_unit(row: &rusqlite::Row) -> rusqlite::Result<WorkUnit> {
    Ok(WorkUnit {
        id: row.get(0)?,
        kind: row.get(1)?,
        actor: row.get(2)?,
        target_object_id: row.get(3)?,
        status: row.get(4)?,
        requested_spec: row.get(5)?,
        scope_id: row.get(6)?,
        priority: row.get(7)?,
        timeout_seconds: row.get(8)?,
        heartbeat_ttl_seconds: row.get(9)?,
        created_at: row.get(10)?,
        admitted_at: row.get(11)?,
        started_at: row.get(12)?,
        finished_at: row.get(13)?,
        last_heartbeat_at: row.get(14)?,
        failure_reason: row.get(15)?,
        cancel_reason: row.get(16)?,
        owner_principal: row.get(17)?,
        creator_principal: row.get(18)?,
        idempotency_key: row.get(19)?,
        updated_at: row.get(20)?,
    })
}

fn row_to_reservation(row: &rusqlite::Row) -> rusqlite::Result<Reservation> {
    Ok(Reservation {
        id: row.get(0)?,
        work_unit_id: row.get(1)?,
        scope_id: row.get(2)?,
        status: row.get(3)?,
        lease_owner: row.get(4)?,
        leased_at: row.get(5)?,
        expires_at: row.get(6)?,
        released_at: row.get(7)?,
        created_at: row.get(8)?,
    })
}

fn row_to_run_event(row: &rusqlite::Row) -> rusqlite::Result<RunEvent> {
    let evidence_json: String = row.get(4)?;
    let evidence = serde_json::from_str(&evidence_json).unwrap_or_default();
    Ok(RunEvent {
        id: row.get(0)?,
        work_unit_id: row.get(1)?,
        event_type: row.get(2)?,
        message: row.get(3)?,
        evidence,
        created_at: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> SekaiDb {
        let db = SekaiDb::new(":memory:").unwrap();
        db.migrate_coordination();
        db
    }

    fn root_scope() -> ContentionScope {
        ContentionScope {
            id: "scope-root".into(),
            name: "root".into(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 30,
            timeout_seconds: 0,
            owner_principal: "tester".into(),
            created: 1,
            updated: 1,
        }
    }

    fn child_scope() -> ContentionScope {
        ContentionScope {
            id: "scope-child".into(),
            name: "root/child".into(),
            parent_scope_id: "scope-root".into(),
            max_concurrency: 1,
            admission_policy: ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 30,
            timeout_seconds: 0,
            owner_principal: "tester".into(),
            created: 1,
            updated: 1,
        }
    }

    fn work_unit(id: &str, scope_id: &str, created_at: i64) -> WorkUnit {
        WorkUnit {
            id: id.into(),
            kind: "build".into(),
            actor: "tester".into(),
            target_object_id: String::new(),
            status: WORK_UNIT_STATUS_PENDING.into(),
            requested_spec: "do work".into(),
            scope_id: scope_id.into(),
            priority: 0,
            timeout_seconds: 60,
            heartbeat_ttl_seconds: 2,
            created_at,
            admitted_at: 0,
            started_at: 0,
            finished_at: 0,
            last_heartbeat_at: 0,
            failure_reason: String::new(),
            cancel_reason: String::new(),
            owner_principal: "tester".into(),
            creator_principal: "tester".into(),
            idempotency_key: String::new(),
            updated_at: created_at,
        }
    }

    #[test]
    fn admits_fifo_on_same_scope() {
        let db = db();
        db.create_contention_scope(&root_scope()).unwrap();
        db.create_work_unit(&work_unit("wu-1", "scope-root", 10))
            .unwrap();
        db.create_work_unit(&work_unit("wu-2", "scope-root", 20))
            .unwrap();

        let first = db.try_admit_work_unit("wu-1", "tester", 100).unwrap();
        assert!(first.admitted);
        let second = db.try_admit_work_unit("wu-2", "tester", 101).unwrap();
        assert!(!second.admitted);
        assert!(second.reason.contains("saturated"));
    }

    #[test]
    fn parent_scope_blocks_sibling_scope() {
        let db = db();
        db.create_contention_scope(&root_scope()).unwrap();
        db.create_contention_scope(&child_scope()).unwrap();
        let sibling = ContentionScope {
            id: "scope-sibling".into(),
            name: "root/sibling".into(),
            parent_scope_id: "scope-root".into(),
            max_concurrency: 1,
            admission_policy: ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 30,
            timeout_seconds: 0,
            owner_principal: "tester".into(),
            created: 1,
            updated: 1,
        };
        db.create_contention_scope(&sibling).unwrap();
        db.create_work_unit(&work_unit("wu-a", "scope-child", 10))
            .unwrap();
        db.create_work_unit(&work_unit("wu-b", "scope-sibling", 20))
            .unwrap();

        assert!(
            db.try_admit_work_unit("wu-a", "tester", 100)
                .unwrap()
                .admitted
        );
        let blocked = db.try_admit_work_unit("wu-b", "tester", 101).unwrap();
        assert!(!blocked.admitted);
        assert!(blocked.reason.contains("saturated"));
    }

    #[test]
    fn heartbeat_and_reconcile_release_stale_work() {
        let db = db();
        db.create_contention_scope(&root_scope()).unwrap();
        db.create_work_unit(&work_unit("wu-1", "scope-root", 10))
            .unwrap();
        db.try_admit_work_unit("wu-1", "tester", 100).unwrap();
        db.heartbeat_work_unit("wu-1", 150).unwrap();

        let summary = db
            .reconcile_work_units(2501, &ReconcileFilter::default())
            .unwrap();
        assert_eq!(summary.work_units_reconciled, 1);
        let work_unit = db.get_work_unit("wu-1").unwrap().unwrap();
        assert_eq!(work_unit.status, WORK_UNIT_STATUS_STALE);
        let reservations = db
            .list_reservations(&ReservationFilter {
                work_unit_id: Some("wu-1".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            reservations
                .iter()
                .all(|reservation| reservation.released_at > 0)
        );
    }
}
