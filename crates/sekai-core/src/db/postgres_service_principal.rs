//! PostgreSQL store for service-principal scope registrations (#1508).

use crate::db::postgres::PostgresDb;
use crate::db::service_principal::{from_json, to_json};
use crate::sekai::service_principal::ServicePrincipalRegistration;

impl PostgresDb {
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
            .connection()?
            .query_opt(
                "INSERT INTO sekai_service_principals (
                    principal, tenant_id, namespaces_json, action_types_json,
                    registered_by, created_at_ms, updated_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT(principal) DO UPDATE SET
                    tenant_id=excluded.tenant_id,
                    namespaces_json=excluded.namespaces_json,
                    action_types_json=excluded.action_types_json,
                    registered_by=excluded.registered_by,
                    updated_at_ms=excluded.updated_at_ms
                 WHERE sekai_service_principals.tenant_id=excluded.tenant_id
                 RETURNING created_at_ms",
                &[
                    &registration.principal,
                    &registration.tenant_id,
                    &to_json(&registration.namespaces)?,
                    &to_json(&registration.action_types)?,
                    &registration.registered_by,
                    &registration.created_at_ms,
                    &registration.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, i64>(0));
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
        self.connection()?
            .query_opt(
                "SELECT tenant_id, namespaces_json, action_types_json, registered_by,
                        created_at_ms, updated_at_ms
                 FROM sekai_service_principals WHERE principal=$1",
                &[&principal],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                Ok(ServicePrincipalRegistration {
                    principal: principal.into(),
                    tenant_id: row.get(0),
                    namespaces: from_json(row.get(1))?,
                    action_types: from_json(row.get(2))?,
                    registered_by: row.get(3),
                    created_at_ms: row.get(4),
                    updated_at_ms: row.get(5),
                })
            })
            .transpose()
    }

    /// Remove `tenant_id`'s registration of `principal`; `false` when none existed.
    pub fn delete_service_principal(
        &self,
        principal: &str,
        tenant_id: &str,
    ) -> Result<bool, String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_service_principals WHERE principal=$1 AND tenant_id=$2",
                &[&principal, &tenant_id],
            )
            .map(|deleted| deleted > 0)
            .map_err(|error| error.to_string())
    }
}
