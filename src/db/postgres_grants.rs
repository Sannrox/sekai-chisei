use crate::db::postgres::PostgresDb;
use crate::sekai::security::{Grant, Role};

impl PostgresDb {
    pub fn create_grant(&self, grant: &Grant) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_grants (id, object_id, principal, role, created)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (object_id, principal) DO UPDATE SET
                    id = EXCLUDED.id,
                    role = EXCLUDED.role,
                    created = EXCLUDED.created",
                &[
                    &grant.id,
                    &grant.object_id,
                    &grant.principal,
                    &grant.role.as_str(),
                    &grant.created,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn delete_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        self.connection()?
            .query_opt(
                "DELETE FROM sekai_grants WHERE id = $1
                 RETURNING id, object_id, principal, role, created",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_grant)
            .transpose()
    }

    pub fn get_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        self.connection()?
            .query_opt(
                "SELECT id, object_id, principal, role, created
                 FROM sekai_grants WHERE id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_grant)
            .transpose()
    }

    pub fn list_grants(&self, object_id: &str) -> Result<Vec<Grant>, String> {
        self.query_grants(
            "SELECT id, object_id, principal, role, created
             FROM sekai_grants WHERE object_id = $1 ORDER BY created, id",
            &[&object_id],
        )
    }

    pub fn list_all_grants(&self) -> Result<Vec<Grant>, String> {
        self.query_grants(
            "SELECT id, object_id, principal, role, created
             FROM sekai_grants ORDER BY object_id, principal",
            &[],
        )
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
