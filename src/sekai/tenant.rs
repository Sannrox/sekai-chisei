use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::collections::HashMap;
use uuid::Uuid;

pub const TENANT_CONTRACT_VERSION: &str = "tenant.v1";
pub const NAMESPACE_OWNERSHIP_CONTRACT_VERSION: &str = "namespace-ownership.v1";
pub const TENANT_MEMBERSHIP_CONTRACT_VERSION: &str = "tenant-membership.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRole {
    Owner,
    Admin,
    Member,
    BillingViewer,
}

impl TenantRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::BillingViewer => "billing_viewer",
        }
    }

    pub fn parse(value: &str) -> Result<Self, TenantError> {
        match value {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            "billing_viewer" => Ok(Self::BillingViewer),
            _ => Err(TenantError::Storage(format!(
                "invalid tenant role {value:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantMembership {
    pub contract_version: String,
    pub tenant_id: String,
    pub subject_id: String,
    pub role: TenantRole,
    pub active: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceOwnership {
    pub contract_version: String,
    pub namespace: String,
    pub tenant_id: String,
    pub migrated_from_namespace: String,
    pub created_at_ms: i64,
}

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
    PermissionDenied,
    LastOwner,
    Conflict(String),
    InvalidTransition {
        from: TenantState,
        action: &'static str,
    },
    AdmissionBlocked(TenantState),
    Storage(String),
}

impl SekaiDb {
    pub(crate) fn migrate_tenant_memberships(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_tenant_memberships (
                    tenant_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    contract_version TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','admin','member','billing_viewer')),
                    status TEXT NOT NULL CHECK(status IN ('active','revoked')),
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    revoked_at_ms INTEGER,
                    PRIMARY KEY(tenant_id,subject_id),
                    FOREIGN KEY(tenant_id) REFERENCES sekai_tenants(id)
                 );
                 CREATE INDEX IF NOT EXISTS idx_sekai_tenant_memberships_subject
                    ON sekai_tenant_memberships(subject_id,status);",
            )
            .map_err(|error| error.to_string())
    }

    pub(crate) fn migrate_namespace_ownership(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_namespace_ownership (
                    namespace TEXT PRIMARY KEY,
                    contract_version TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    migrated_from_namespace TEXT NOT NULL DEFAULT '',
                    created_at_ms INTEGER NOT NULL,
                    FOREIGN KEY(tenant_id) REFERENCES sekai_tenants(id)
                 );
                 CREATE INDEX IF NOT EXISTS idx_sekai_namespace_ownership_tenant
                    ON sekai_namespace_ownership(tenant_id);
                 CREATE TRIGGER IF NOT EXISTS trg_tenant_object_insert
                 BEFORE INSERT ON sekai_objects
                 WHEN EXISTS (
                    SELECT 1 FROM sekai_namespace_ownership ownership
                    JOIN sekai_tenants tenant ON tenant.id=ownership.tenant_id
                    WHERE ownership.namespace=NEW.namespace AND tenant.state!='active'
                 ) BEGIN SELECT RAISE(ABORT, 'tenant cannot admit namespace writes'); END;
                 CREATE TRIGGER IF NOT EXISTS trg_tenant_object_update
                 BEFORE UPDATE ON sekai_objects
                 WHEN EXISTS (
                    SELECT 1 FROM sekai_namespace_ownership ownership
                    JOIN sekai_tenants tenant ON tenant.id=ownership.tenant_id
                    WHERE ownership.namespace IN (OLD.namespace,NEW.namespace)
                      AND tenant.state!='active'
                 ) BEGIN SELECT RAISE(ABORT, 'tenant cannot admit namespace writes'); END;
                 CREATE TRIGGER IF NOT EXISTS trg_tenant_object_delete
                 BEFORE DELETE ON sekai_objects
                 WHEN EXISTS (
                    SELECT 1 FROM sekai_namespace_ownership ownership
                    JOIN sekai_tenants tenant ON tenant.id=ownership.tenant_id
                    WHERE ownership.namespace=OLD.namespace AND tenant.state!='active'
                 ) BEGIN SELECT RAISE(ABORT, 'tenant cannot admit namespace writes'); END;
                 CREATE TRIGGER IF NOT EXISTS trg_tenant_link_insert
                 BEFORE INSERT ON sekai_links
                 WHEN EXISTS (
                    SELECT 1 FROM sekai_objects object
                    JOIN sekai_namespace_ownership ownership ON ownership.namespace=object.namespace
                    JOIN sekai_tenants tenant ON tenant.id=ownership.tenant_id
                    WHERE object.id IN (NEW.from_id,NEW.to_id) AND tenant.state!='active'
                 ) BEGIN SELECT RAISE(ABORT, 'tenant cannot admit namespace writes'); END;
                 CREATE TRIGGER IF NOT EXISTS trg_tenant_link_delete
                 BEFORE DELETE ON sekai_links
                 WHEN EXISTS (
                    SELECT 1 FROM sekai_objects object
                    JOIN sekai_namespace_ownership ownership ON ownership.namespace=object.namespace
                    JOIN sekai_tenants tenant ON tenant.id=ownership.tenant_id
                    WHERE object.id IN (OLD.from_id,OLD.to_id) AND tenant.state!='active'
                 ) BEGIN SELECT RAISE(ABORT, 'tenant cannot admit namespace writes'); END;",
            )
            .map_err(|error| error.to_string())
    }

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

    pub fn create_tenant_membership(
        &self,
        tenant_id: &str,
        subject_id: &str,
        role: TenantRole,
        actor: &str,
        platform_admin: bool,
        now_ms: i64,
    ) -> Result<TenantMembership, TenantError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        require_membership_mutation_authority(&tx, tenant_id, actor, platform_admin, role)?;
        let active_memberships: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sekai_tenant_memberships WHERE tenant_id=?1 AND status='active'",
                params![tenant_id],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if active_memberships == 0 && role != TenantRole::Owner {
            return Err(TenantError::LastOwner);
        }
        let existing = membership_by_subject(&tx, tenant_id, subject_id)?;
        if existing
            .as_ref()
            .is_some_and(|membership| membership.active)
        {
            return Err(TenantError::Conflict(
                "active tenant membership already exists".into(),
            ));
        }
        if existing.is_some() {
            tx.execute(
                "UPDATE sekai_tenant_memberships
                 SET role=?1,status='active',updated_at_ms=?2,revoked_at_ms=NULL
                 WHERE tenant_id=?3 AND subject_id=?4",
                params![role.as_str(), now_ms, tenant_id, subject_id],
            )
            .map_err(storage)?;
        } else {
            tx.execute(
                "INSERT INTO sekai_tenant_memberships
                 (tenant_id,subject_id,contract_version,role,status,created_at_ms,updated_at_ms)
                 VALUES (?1,?2,?3,?4,'active',?5,?5)",
                params![
                    tenant_id,
                    subject_id,
                    TENANT_MEMBERSHIP_CONTRACT_VERSION,
                    role.as_str(),
                    now_ms
                ],
            )
            .map_err(storage)?;
        }
        insert_membership_audit(
            &tx,
            actor,
            tenant_id,
            subject_id,
            "membership.create",
            ("", role.as_str()),
            now_ms,
        )?;
        let membership =
            membership_by_subject(&tx, tenant_id, subject_id)?.ok_or(TenantError::NotFound)?;
        tx.commit().map_err(storage)?;
        Ok(membership)
    }

    pub fn change_tenant_membership_role(
        &self,
        tenant_id: &str,
        subject_id: &str,
        role: TenantRole,
        actor: &str,
        platform_admin: bool,
        now_ms: i64,
    ) -> Result<TenantMembership, TenantError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let before = membership_by_subject(&tx, tenant_id, subject_id)?
            .filter(|membership| membership.active)
            .ok_or(TenantError::NotFound)?;
        if !platform_admin
            && actor_membership_role(&tx, tenant_id, actor)? == Some(TenantRole::Admin)
            && matches!(before.role, TenantRole::Owner | TenantRole::Admin)
        {
            return Err(TenantError::PermissionDenied);
        }
        require_membership_mutation_authority(&tx, tenant_id, actor, platform_admin, role)?;
        if before.role == TenantRole::Owner
            && role != TenantRole::Owner
            && active_owner_count(&tx, tenant_id)? == 1
        {
            return Err(TenantError::LastOwner);
        }
        tx.execute(
            "UPDATE sekai_tenant_memberships SET role=?1,updated_at_ms=?2
             WHERE tenant_id=?3 AND subject_id=?4 AND status='active'",
            params![role.as_str(), now_ms, tenant_id, subject_id],
        )
        .map_err(storage)?;
        insert_membership_audit(
            &tx,
            actor,
            tenant_id,
            subject_id,
            "membership.role_change",
            (before.role.as_str(), role.as_str()),
            now_ms,
        )?;
        let membership =
            membership_by_subject(&tx, tenant_id, subject_id)?.ok_or(TenantError::NotFound)?;
        tx.commit().map_err(storage)?;
        Ok(membership)
    }

    pub fn revoke_tenant_membership(
        &self,
        tenant_id: &str,
        subject_id: &str,
        actor: &str,
        platform_admin: bool,
        now_ms: i64,
    ) -> Result<TenantMembership, TenantError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let before = membership_by_subject(&tx, tenant_id, subject_id)?
            .filter(|membership| membership.active)
            .ok_or(TenantError::NotFound)?;
        require_membership_mutation_authority(&tx, tenant_id, actor, platform_admin, before.role)?;
        if before.role == TenantRole::Owner && active_owner_count(&tx, tenant_id)? == 1 {
            return Err(TenantError::LastOwner);
        }
        tx.execute(
            "UPDATE sekai_tenant_memberships
             SET status='revoked',updated_at_ms=?1,revoked_at_ms=?1
             WHERE tenant_id=?2 AND subject_id=?3 AND status='active'",
            params![now_ms, tenant_id, subject_id],
        )
        .map_err(storage)?;
        insert_membership_audit(
            &tx,
            actor,
            tenant_id,
            subject_id,
            "membership.revoke",
            (before.role.as_str(), "revoked"),
            now_ms,
        )?;
        let membership =
            membership_by_subject(&tx, tenant_id, subject_id)?.ok_or(TenantError::NotFound)?;
        tx.commit().map_err(storage)?;
        Ok(membership)
    }

    pub fn list_tenant_memberships(
        &self,
        tenant_id: &str,
        actor: &str,
        platform_admin: bool,
    ) -> Result<Vec<TenantMembership>, TenantError> {
        let conn = self.conn();
        require_membership_read_authority(&conn, tenant_id, actor, platform_admin)?;
        let mut statement = conn.prepare(
            "SELECT contract_version,tenant_id,subject_id,role,status,created_at_ms,updated_at_ms,revoked_at_ms
             FROM sekai_tenant_memberships WHERE tenant_id=?1 AND status='active'
             ORDER BY subject_id",
        ).map_err(storage)?;
        statement
            .query_map(params![tenant_id], row_to_membership)
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)
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

    pub fn namespace_ownership(
        &self,
        namespace: &str,
    ) -> Result<Option<NamespaceOwnership>, TenantError> {
        self.conn()
            .query_row(
                "SELECT contract_version,namespace,tenant_id,migrated_from_namespace,created_at_ms
                 FROM sekai_namespace_ownership WHERE namespace=?1",
                params![namespace],
                |row| {
                    Ok(NamespaceOwnership {
                        contract_version: row.get(0)?,
                        namespace: row.get(1)?,
                        tenant_id: row.get(2)?,
                        migrated_from_namespace: row.get(3)?,
                        created_at_ms: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(storage)
    }

    pub fn bind_namespace_to_tenant(
        &self,
        namespace: &str,
        tenant_id: &str,
        migrated_from_namespace: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<NamespaceOwnership, TenantError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let tenant = tenant_by_id(&tx, tenant_id)?.ok_or(TenantError::NotFound)?;
        if tenant.state != TenantState::Active {
            return Err(TenantError::AdmissionBlocked(tenant.state));
        }
        if let Some(existing) = tx
            .query_row(
                "SELECT contract_version,namespace,tenant_id,migrated_from_namespace,created_at_ms
                 FROM sekai_namespace_ownership WHERE namespace=?1",
                params![namespace],
                |row| {
                    Ok(NamespaceOwnership {
                        contract_version: row.get(0)?,
                        namespace: row.get(1)?,
                        tenant_id: row.get(2)?,
                        migrated_from_namespace: row.get(3)?,
                        created_at_ms: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(storage)?
        {
            if existing.tenant_id == tenant_id
                && existing.migrated_from_namespace == migrated_from_namespace
            {
                tx.commit().map_err(storage)?;
                return Ok(existing);
            }
            insert_namespace_ownership_audit(
                &tx,
                actor,
                namespace,
                &existing.tenant_id,
                tenant_id,
                "rejected",
                now_ms,
            )?;
            tx.commit().map_err(storage)?;
            return Err(TenantError::Conflict(
                "namespace ownership is immutable; create a new namespace and migrate data".into(),
            ));
        }
        if migrated_from_namespace == namespace {
            return Err(TenantError::Conflict(
                "a namespace cannot migrate from itself".into(),
            ));
        }
        if !migrated_from_namespace.is_empty() {
            let source_exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sekai_namespace_ownership WHERE namespace=?1)",
                    params![migrated_from_namespace],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if !source_exists {
                return Err(TenantError::NotFound);
            }
        }
        let external_id = format!("namespace:{namespace}");
        let boundaries = {
            let mut statement = tx
                .prepare(
                    "SELECT id,kind FROM sekai_objects WHERE external_id=?1 ORDER BY id LIMIT 2",
                )
                .map_err(storage)?;
            statement
                .query_map(params![external_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?
        };
        if boundaries.len() > 1 || boundaries.iter().any(|(_, kind)| kind != "namespace") {
            return Err(TenantError::Conflict(
                "canonical namespace identity is not uniquely held by a namespace boundary".into(),
            ));
        }
        let properties = serde_json::to_string(&HashMap::from([
            ("tenant_owned".to_string(), "true".to_string()),
            ("runtime_boundary".to_string(), namespace.to_string()),
        ]))
        .map_err(storage)?;
        if let Some((boundary_id, _)) = boundaries.first() {
            tx.execute(
                "UPDATE sekai_objects
                 SET namespace=?1, properties=json_set(properties,'$.tenant_owned','true'), updated=?2
                 WHERE id=?3",
                params![namespace, now_ms, boundary_id],
            )
            .map_err(storage)?;
        } else {
            tx.execute(
                "INSERT INTO sekai_objects (id,kind,name,namespace,external_id,properties,created,updated)
                 VALUES (?1,'namespace',?2,?2,?1,?3,?4,?4)",
                params![external_id, namespace, properties, now_ms],
            )
            .map_err(storage)?;
        }
        tx.execute(
            "INSERT INTO sekai_namespace_ownership
             (namespace,contract_version,tenant_id,migrated_from_namespace,created_at_ms)
             VALUES (?1,?2,?3,?4,?5)",
            params![
                namespace,
                NAMESPACE_OWNERSHIP_CONTRACT_VERSION,
                tenant_id,
                migrated_from_namespace,
                now_ms
            ],
        )
        .map_err(storage)?;
        insert_namespace_ownership_audit(&tx, actor, namespace, "", tenant_id, "applied", now_ms)?;
        tx.commit().map_err(storage)?;
        Ok(NamespaceOwnership {
            contract_version: NAMESPACE_OWNERSHIP_CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            tenant_id: tenant_id.into(),
            migrated_from_namespace: migrated_from_namespace.into(),
            created_at_ms: now_ms,
        })
    }
}

fn insert_namespace_ownership_audit(
    conn: &rusqlite::Connection,
    actor: &str,
    namespace: &str,
    from_tenant: &str,
    to_tenant: &str,
    outcome: &str,
    now_ms: i64,
) -> Result<(), TenantError> {
    crate::sekai::ledger::insert_chained_decision(
        conn,
        &Decision {
            id: Uuid::new_v4().to_string(),
            timestamp: now_ms,
            actor: actor.into(),
            action: "namespace.tenant_ownership".into(),
            reason: if outcome == "applied" {
                "namespace tenant ownership created".into()
            } else {
                "cross-tenant ownership change rejected".into()
            },
            evidence: HashMap::from([
                (
                    "contract_version".into(),
                    NAMESPACE_OWNERSHIP_CONTRACT_VERSION.into(),
                ),
                ("from_tenant".into(), from_tenant.into()),
                ("to_tenant".into(), to_tenant.into()),
                ("data_class".into(), "internal".into()),
            ]),
            target_id: format!("namespace:{namespace}"),
            outcome: outcome.into(),
        },
    )
    .map_err(TenantError::Storage)
}

fn row_to_membership(row: &rusqlite::Row<'_>) -> rusqlite::Result<TenantMembership> {
    let role: String = row.get(3)?;
    Ok(TenantMembership {
        contract_version: row.get(0)?,
        tenant_id: row.get(1)?,
        subject_id: row.get(2)?,
        role: TenantRole::parse(&role).map_err(|_| rusqlite::Error::InvalidQuery)?,
        active: row.get::<_, String>(4)? == "active",
        created_at_ms: row.get(5)?,
        updated_at_ms: row.get(6)?,
        revoked_at_ms: row.get(7)?,
    })
}

fn membership_by_subject(
    conn: &rusqlite::Connection,
    tenant_id: &str,
    subject_id: &str,
) -> Result<Option<TenantMembership>, TenantError> {
    conn.query_row(
        "SELECT contract_version,tenant_id,subject_id,role,status,created_at_ms,updated_at_ms,revoked_at_ms
         FROM sekai_tenant_memberships WHERE tenant_id=?1 AND subject_id=?2",
        params![tenant_id, subject_id],
        row_to_membership,
    )
    .optional()
    .map_err(storage)
}

fn active_owner_count(conn: &rusqlite::Connection, tenant_id: &str) -> Result<i64, TenantError> {
    conn.query_row(
        "SELECT COUNT(*) FROM sekai_tenant_memberships
         WHERE tenant_id=?1 AND role='owner' AND status='active'",
        params![tenant_id],
        |row| row.get(0),
    )
    .map_err(storage)
}

fn actor_membership_role(
    conn: &rusqlite::Connection,
    tenant_id: &str,
    actor: &str,
) -> Result<Option<TenantRole>, TenantError> {
    Ok(membership_by_subject(conn, tenant_id, actor)?
        .filter(|membership| membership.active)
        .map(|membership| membership.role))
}

fn require_membership_read_authority(
    conn: &rusqlite::Connection,
    tenant_id: &str,
    actor: &str,
    platform_admin: bool,
) -> Result<(), TenantError> {
    if tenant_by_id(conn, tenant_id)?.is_none() {
        return Err(TenantError::NotFound);
    }
    if platform_admin
        || matches!(
            actor_membership_role(conn, tenant_id, actor)?,
            Some(TenantRole::Owner | TenantRole::Admin)
        )
    {
        Ok(())
    } else {
        Err(TenantError::PermissionDenied)
    }
}

fn require_membership_mutation_authority(
    conn: &rusqlite::Connection,
    tenant_id: &str,
    actor: &str,
    platform_admin: bool,
    target_role: TenantRole,
) -> Result<(), TenantError> {
    if tenant_by_id(conn, tenant_id)?.is_none() {
        return Err(TenantError::NotFound);
    }
    if platform_admin {
        return Ok(());
    }
    match actor_membership_role(conn, tenant_id, actor)? {
        Some(TenantRole::Owner) => Ok(()),
        Some(TenantRole::Admin)
            if matches!(target_role, TenantRole::Member | TenantRole::BillingViewer) =>
        {
            Ok(())
        }
        _ => Err(TenantError::PermissionDenied),
    }
}

fn insert_membership_audit(
    conn: &rusqlite::Connection,
    actor: &str,
    tenant_id: &str,
    subject_id: &str,
    action: &str,
    transition: (&str, &str),
    now_ms: i64,
) -> Result<(), TenantError> {
    let (from, to) = transition;
    crate::sekai::ledger::insert_chained_decision(
        conn,
        &Decision {
            id: Uuid::new_v4().to_string(),
            timestamp: now_ms,
            actor: actor.into(),
            action: action.into(),
            reason: "tenant membership changed".into(),
            evidence: HashMap::from([
                (
                    "contract_version".into(),
                    TENANT_MEMBERSHIP_CONTRACT_VERSION.into(),
                ),
                ("tenant_id".into(), tenant_id.into()),
                ("from_role".into(), from.into()),
                ("to_role".into(), to.into()),
                ("data_class".into(), "internal".into()),
            ]),
            target_id: format!("tenant-membership:{tenant_id}:{subject_id}"),
            outcome: "applied".into(),
        },
    )
    .map_err(TenantError::Storage)
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

    #[test]
    fn memberships_are_tenant_scoped_live_authorized_and_preserve_the_last_owner() {
        let db = SekaiDb::new(":memory:").unwrap();
        let first = db.create_tenant("root", "members-a", 1).unwrap();
        let second = db.create_tenant("root", "members-b", 2).unwrap();
        let owner = "external:owner";
        db.create_tenant_membership(&first.id, owner, TenantRole::Owner, "root", true, 3)
            .unwrap();
        db.create_tenant_membership(
            &second.id,
            "external:second-owner",
            TenantRole::Owner,
            "root",
            true,
            4,
        )
        .unwrap();
        db.create_tenant_membership(
            &second.id,
            owner,
            TenantRole::BillingViewer,
            "root",
            true,
            5,
        )
        .unwrap();

        assert_eq!(
            db.list_tenant_memberships(&first.id, owner, false).unwrap()[0].role,
            TenantRole::Owner
        );
        assert_eq!(
            db.list_tenant_memberships(&second.id, owner, false),
            Err(TenantError::PermissionDenied)
        );

        let admin = "external:admin";
        db.create_tenant_membership(&first.id, admin, TenantRole::Admin, owner, false, 5)
            .unwrap();
        db.create_tenant_membership(
            &first.id,
            "external:member",
            TenantRole::Member,
            admin,
            false,
            6,
        )
        .unwrap();
        assert_eq!(
            db.create_tenant_membership(
                &first.id,
                "external:owner-2",
                TenantRole::Owner,
                admin,
                false,
                7,
            ),
            Err(TenantError::PermissionDenied)
        );
        assert_eq!(
            db.change_tenant_membership_role(
                &first.id,
                owner,
                TenantRole::Member,
                admin,
                false,
                7,
            ),
            Err(TenantError::PermissionDenied)
        );
        assert_eq!(
            db.revoke_tenant_membership(&first.id, owner, owner, false, 8),
            Err(TenantError::LastOwner)
        );

        db.create_tenant_membership(
            &first.id,
            "external:owner-2",
            TenantRole::Owner,
            owner,
            false,
            9,
        )
        .unwrap();
        db.revoke_tenant_membership(&first.id, owner, "external:owner-2", false, 10)
            .unwrap();
        assert_eq!(
            db.list_tenant_memberships(&first.id, owner, false),
            Err(TenantError::PermissionDenied),
            "revocation must affect the next authority check"
        );
        assert_eq!(
            db.list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("membership.revoke".into()),
                limit: 20,
                ..Default::default()
            })
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn namespace_ownership_is_unique_immutable_and_supports_new_namespace_migration() {
        let db = SekaiDb::new(":memory:").unwrap();
        let first = db.create_tenant("root", "tenant-a", 1).unwrap();
        let second = db.create_tenant("root", "tenant-b", 2).unwrap();
        db.create_object(&crate::domain::Object {
            id: "namespace:legacy".into(),
            kind: "namespace".into(),
            name: "legacy".into(),
            namespace: "legacy".into(),
            external_id: "namespace:legacy".into(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        db.bind_namespace_to_tenant("legacy", &first.id, "", "root", 2)
            .unwrap();
        assert_eq!(
            db.namespace_ownership("legacy").unwrap().unwrap().tenant_id,
            first.id.clone()
        );

        let owned = db
            .bind_namespace_to_tenant("alpha", &first.id, "", "root", 3)
            .unwrap();
        assert_eq!(owned, db.namespace_ownership("alpha").unwrap().unwrap());
        assert_eq!(
            db.bind_namespace_to_tenant("alpha", &first.id, "", "root", 4)
                .unwrap(),
            owned
        );
        assert!(matches!(
            db.bind_namespace_to_tenant("alpha", &second.id, "", "root", 5),
            Err(TenantError::Conflict(_))
        ));

        let migrated = db
            .bind_namespace_to_tenant("alpha-v2", &second.id, "alpha", "root", 6)
            .unwrap();
        assert_eq!(migrated.migrated_from_namespace, "alpha");
        assert_eq!(
            db.find_namespace_boundary("alpha-v2")
                .unwrap()
                .unwrap()
                .properties
                .get("tenant_owned")
                .map(String::as_str),
            Some("true")
        );
        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("namespace.tenant_ownership".into()),
                limit: 20,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(decisions.len(), 4);
        assert!(
            decisions
                .iter()
                .any(|decision| decision.outcome == "rejected")
        );

        db.suspend_tenant(&first.id, "root", "suspend-owned", 7)
            .unwrap();
        assert!(
            db.create_object(&crate::domain::Object {
                id: "blocked-write".into(),
                kind: "note".into(),
                name: "blocked".into(),
                namespace: "alpha".into(),
                external_id: String::new(),
                properties: HashMap::new(),
                created: 8,
                updated: 8,
            })
            .unwrap_err()
            .contains("tenant cannot admit namespace writes")
        );
        db.create_object(&crate::domain::Object {
            id: "local-write".into(),
            kind: "note".into(),
            name: "local".into(),
            namespace: "unowned-local".into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 8,
            updated: 8,
        })
        .unwrap();
    }
}
