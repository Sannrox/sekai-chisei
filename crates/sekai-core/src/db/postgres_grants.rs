use crate::db::postgres::PostgresDb;
use crate::sekai::security::{Grant, NamespaceGrantPolicy, Role};

const GRANT_COLUMNS: &str =
    "id, object_id, principal, role, created, purpose, not_after_ms, exception_reason";
const POSTGRES_LIVE_GRANT: &str =
    "(g.not_after_ms = 0 OR g.not_after_ms > (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint)";
const DEFAULT_OPEN_ENDED_MIGRATION_MS: i64 = 90 * 24 * 60 * 60 * 1000;

impl PostgresDb {
    pub fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_grants (id, object_id, principal, role, created, purpose, not_after_ms, exception_reason)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (object_id, principal) DO UPDATE SET
                    id = EXCLUDED.id,
                    role = EXCLUDED.role,
                    created = EXCLUDED.created,
                    purpose = EXCLUDED.purpose,
                    not_after_ms = EXCLUDED.not_after_ms,
                    exception_reason = EXCLUDED.exception_reason",
                &[
                    &grant.id,
                    &grant.object_id,
                    &grant.principal,
                    &grant.role.as_str(),
                    &grant.created,
                    &grant.purpose,
                    &grant.not_after_ms,
                    &grant.exception_reason,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn create_grant_with_decision(
        &self,
        grant: &Grant,
        decision: &crate::sekai::audit::Decision,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_grants (id, object_id, principal, role, created, purpose, not_after_ms, exception_reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (object_id, principal) DO UPDATE SET
                id = EXCLUDED.id,
                role = EXCLUDED.role,
                created = EXCLUDED.created,
                purpose = EXCLUDED.purpose,
                not_after_ms = EXCLUDED.not_after_ms,
                exception_reason = EXCLUDED.exception_reason",
            &[
                &grant.id,
                &grant.object_id,
                &grant.principal,
                &grant.role.as_str(),
                &grant.created,
                &grant.purpose,
                &grant.not_after_ms,
                &grant.exception_reason,
            ],
        )
        .map_err(|error| error.to_string())?;
        crate::db::postgres_decision::insert_chained_decision(&mut tx, decision)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        self.connection()?
            .query_opt(
                &format!(
                    "DELETE FROM sekai_grants WHERE id = $1
                     RETURNING {GRANT_COLUMNS}"
                ),
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_grant)
            .transpose()
    }

    pub fn get_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        self.connection()?
            .query_opt(
                &format!("SELECT {GRANT_COLUMNS} FROM sekai_grants WHERE id = $1"),
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_grant)
            .transpose()
    }

    pub fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        self.query_grants(
            &format!(
                "SELECT {GRANT_COLUMNS}
                 FROM sekai_grants WHERE object_id = $1 ORDER BY created, id"
            ),
            &[&object_id],
        )
    }

    pub fn list_all_grants(&self) -> Result<Vec<Grant>, String> {
        self.query_grants(
            &format!("SELECT {GRANT_COLUMNS} FROM sekai_grants ORDER BY object_id, principal"),
            &[],
        )
    }

    pub fn set_namespace_grant_policy(&self, policy: &NamespaceGrantPolicy) -> Result<(), String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO sekai_namespace_grant_policy (namespace, max_duration_ms, require_terms)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (namespace) DO UPDATE SET
                    max_duration_ms = EXCLUDED.max_duration_ms,
                    require_terms = EXCLUDED.require_terms",
                &[&policy.namespace, &policy.max_duration_ms, &policy.require_terms],
            )
            .map_err(|error| error.to_string())?;
        if policy.require_terms {
            let now_ms = crate::sekai::security::unix_now_ms();
            let duration = if policy.max_duration_ms > 0 {
                policy.max_duration_ms
            } else {
                DEFAULT_OPEN_ENDED_MIGRATION_MS
            };
            let end = now_ms.saturating_add(duration);
            connection
                .execute(
                    "UPDATE sekai_grants
                     SET not_after_ms = $1
                     WHERE not_after_ms = 0
                       AND exception_reason = ''
                       AND object_id IN (
                         SELECT id FROM sekai_objects
                         WHERE namespace = $2
                            OR (kind = 'namespace'
                                AND (external_id = 'namespace:' || $2
                                     OR external_id = $2
                                     OR name = $2))
                       )",
                    &[&end, &policy.namespace],
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub fn namespace_grant_policy(
        &self,
        namespace: &str,
    ) -> Result<Option<NamespaceGrantPolicy>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT namespace, max_duration_ms, require_terms
                 FROM sekai_namespace_grant_policy WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| NamespaceGrantPolicy {
                namespace: row.get(0),
                max_duration_ms: row.get(1),
                require_terms: row.get(2),
            }))
    }

    /// Namespace roles held by one principal, keyed by namespace name.
    pub fn list_namespace_roles_for_principal(
        &self,
        principal: &str,
    ) -> Result<Vec<(String, Role)>, String> {
        let rows = self
            .connection()?
            .query(
                &format!(
                    "SELECT o.external_id, g.role
                     FROM sekai_grants g
                     JOIN sekai_objects o ON o.id = g.object_id
                     WHERE g.principal = $1 AND o.kind = 'namespace'
                       AND {POSTGRES_LIVE_GRANT}
                     ORDER BY o.external_id"
                ),
                &[&principal],
            )
            .map_err(|error| error.to_string())?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let external_id: String = row.get(0);
                let role: String = row.get(1);
                (
                    external_id
                        .strip_prefix("namespace:")
                        .unwrap_or(&external_id)
                        .to_string(),
                    Role::parse(&role).unwrap_or(Role::Viewer),
                )
            })
            .collect())
    }

    fn query_grants(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<Grant>, String> {
        let rows = self
            .connection()?
            .query(sql, params)
            .map_err(|error| error.to_string())?;
        let mut grants = Vec::with_capacity(rows.len());
        for row in rows {
            match row_to_grant(row) {
                Ok(grant) => grants.push(grant),
                Err(error) => tracing::warn!(%error, "invalid PostgreSQL grant; skipping row"),
            }
        }
        Ok(grants)
    }
}

fn row_to_grant(row: postgres::Row) -> Result<Grant, String> {
    let id: String = row.get(0);
    let role_name: String = row.get(3);
    let role = Role::parse(&role_name)
        .ok_or_else(|| format!("unsupported role {role_name:?} for grant {id}"))?;
    Ok(Grant {
        id,
        object_id: row.get(1),
        principal: row.get(2),
        role,
        created: row.get(4),
        purpose: row.get(5),
        not_after_ms: row.get(6),
        exception_reason: row.get(7),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_roles_match_persisted_role_names() {
        for role in [Role::Viewer, Role::Editor, Role::Admin] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
    }
}
