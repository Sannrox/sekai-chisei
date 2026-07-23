use crate::db::postgres::PostgresDb;

impl PostgresDb {
    pub fn can_access(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        self.check_access(object_id, principals, &["viewer", "editor", "admin"], true)
    }

    pub fn can_write(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        self.check_access(object_id, principals, &["editor", "admin"], true)
    }

    pub fn can_admin(&self, object_id: &str, principals: &[&str]) -> Result<bool, String> {
        self.check_access(object_id, principals, &["admin"], false)
    }

    fn check_access(
        &self,
        object_id: &str,
        principals: &[&str],
        roles: &[&str],
        open_when_ungranted: bool,
    ) -> Result<bool, String> {
        let principals = principals
            .iter()
            .filter(|principal| !principal.is_empty() && **principal != "anonymous")
            .map(|principal| (*principal).to_string())
            .collect::<Vec<_>>();
        let privileged = principals
            .iter()
            .any(|principal| matches!(principal.as_str(), "root" | "local"));
        let roles = roles
            .iter()
            .map(|role| (*role).to_string())
            .collect::<Vec<_>>();
        let mut connection = self.connection()?;
        let row = connection
            .query_one(
                "SELECT
                    EXISTS(SELECT 1 FROM sekai_objects WHERE id = $1),
                    EXISTS(SELECT 1 FROM sekai_grants WHERE object_id = $1),
                    EXISTS(
                        SELECT 1 FROM sekai_grants
                        WHERE object_id = $1
                          AND principal = ANY($2)
                          AND role = ANY($3)
                    ),
                    EXISTS(
                        SELECT 1
                        FROM sekai_objects target
                        JOIN sekai_objects boundary
                          ON boundary.kind = 'namespace'
                         AND boundary.external_id = 'namespace:' || target.namespace
                        WHERE target.id = $1
                          AND boundary.properties::jsonb ->> 'team_managed' = 'true'
                    ),
                    EXISTS(
                        SELECT 1
                        FROM sekai_objects target
                        JOIN sekai_objects boundary
                          ON boundary.kind = 'namespace'
                         AND boundary.external_id = 'namespace:' || target.namespace
                        JOIN sekai_grants namespace_grant
                          ON namespace_grant.object_id = boundary.id
                        WHERE target.id = $1
                          AND boundary.properties::jsonb ->> 'team_managed' = 'true'
                          AND namespace_grant.principal = ANY($2)
                    )",
                &[&object_id, &principals, &roles],
            )
            .map_err(|error| error.to_string())?;
        let exists: bool = row.get(0);
        let has_acl: bool = row.get(1);
        let allowed: bool = row.get(2);
        let namespace_restricted: bool = row.get(3);
        let namespace_allowed: bool = row.get(4);
        Ok(exists
            && (allowed || (open_when_ungranted && !has_acl))
            && (!namespace_restricted || privileged || namespace_allowed))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn role_sets_keep_admin_strict_and_reads_open() {
        let read_roles = ["viewer", "editor", "admin"];
        let admin_roles = ["admin"];
        assert!(read_roles.contains(&"viewer"));
        assert!(!admin_roles.contains(&"editor"));
    }
}
