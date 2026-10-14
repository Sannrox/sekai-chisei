//! SQLite store for service-principal scope registrations (#1508).

use rusqlite::{OptionalExtension, params};

use crate::db::sekai::SekaiDb;
use crate::sekai::service_principal::ServicePrincipalRegistration;

impl SekaiDb {
    pub(crate) fn migrate_service_principals(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_service_principals (
                    principal TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    namespaces_json TEXT NOT NULL,
                    action_types_json TEXT NOT NULL,
                    registered_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );",
            )
            .map_err(|error| error.to_string())
    }

    /// Insert or replace a registration; an update keeps `created_at_ms`.
    /// `None` when the principal is registered under another tenant: the
    /// ownership check and the returned row are part of the write, so
    /// neither can race.
    pub fn put_service_principal(
        &self,
        registration: &ServicePrincipalRegistration,
    ) -> Result<Option<ServicePrincipalRegistration>, String> {
        let registration = registration.clone().normalized()?;
        let created_at_ms = self
            .conn()
            .query_row(
                "INSERT INTO sekai_service_principals (
                    principal, tenant_id, namespaces_json, action_types_json,
                    registered_by, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(principal) DO UPDATE SET
                    tenant_id=excluded.tenant_id,
                    namespaces_json=excluded.namespaces_json,
                    action_types_json=excluded.action_types_json,
                    registered_by=excluded.registered_by,
                    updated_at_ms=excluded.updated_at_ms
                 WHERE sekai_service_principals.tenant_id=excluded.tenant_id
                 RETURNING created_at_ms",
                params![
                    registration.principal,
                    registration.tenant_id,
                    to_json(&registration.namespaces)?,
                    to_json(&registration.action_types)?,
                    registration.registered_by,
                    registration.created_at_ms,
                    registration.updated_at_ms,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        Ok(
            created_at_ms.map(|created_at_ms| ServicePrincipalRegistration {
                created_at_ms,
                ..registration
            }),
        )
    }

    pub fn get_service_principal(
        &self,
        principal: &str,
    ) -> Result<Option<ServicePrincipalRegistration>, String> {
        let row = self
            .conn()
            .query_row(
                "SELECT tenant_id, namespaces_json, action_types_json, registered_by,
                        created_at_ms, updated_at_ms
                 FROM sekai_service_principals WHERE principal=?1",
                params![principal],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        row.map(
            |(tenant_id, namespaces, action_types, registered_by, created_at_ms, updated_at_ms)| {
                Ok(ServicePrincipalRegistration {
                    principal: principal.into(),
                    tenant_id,
                    namespaces: from_json(&namespaces)?,
                    action_types: from_json(&action_types)?,
                    registered_by,
                    created_at_ms,
                    updated_at_ms,
                })
            },
        )
        .transpose()
    }

    /// Remove `tenant_id`'s registration of `principal`; `false` when none existed.
    pub fn delete_service_principal(
        &self,
        principal: &str,
        tenant_id: &str,
    ) -> Result<bool, String> {
        self.conn()
            .execute(
                "DELETE FROM sekai_service_principals WHERE principal=?1 AND tenant_id=?2",
                params![principal, tenant_id],
            )
            .map(|deleted| deleted > 0)
            .map_err(|error| error.to_string())
    }
}

pub(crate) fn to_json(values: &[String]) -> Result<String, String> {
    serde_json::to_string(values).map_err(|error| error.to_string())
}

pub(crate) fn from_json(raw: &str) -> Result<Vec<String>, String> {
    serde_json::from_str(raw).map_err(|error| format!("invalid service principal scope: {error}"))
}
