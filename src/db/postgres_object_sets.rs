use crate::db::postgres::PostgresDb;
use crate::domain::{ListFilter, ObjectSet};

const OBJECT_SET_COLUMNS: &str = "id, name, description, filter, owner_principal, created";

impl PostgresDb {
    pub fn create_object_set(&self, set: &ObjectSet) -> Result<(), String> {
        let filter = serde_json::to_string(&set.filter).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_sets
                    (id, name, description, filter, owner_principal, created)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &set.id,
                    &set.name,
                    &set.description,
                    &filter,
                    &set.owner_principal,
                    &set.created,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_object_set(&self, id: &str) -> Result<Option<ObjectSet>, String> {
        self.connection()?
            .query_opt(
                &format!("SELECT {OBJECT_SET_COLUMNS} FROM sekai_object_sets WHERE id = $1"),
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object_set)
            .transpose()
    }

    pub fn list_object_sets(&self) -> Result<Vec<ObjectSet>, String> {
        self.query_object_sets(
            &format!("SELECT {OBJECT_SET_COLUMNS} FROM sekai_object_sets ORDER BY created, id"),
            &[],
        )
    }

    pub fn list_object_sets_for_principals(
        &self,
        principals: &[&str],
    ) -> Result<Vec<ObjectSet>, String> {
        if principals.is_empty() {
            return Ok(Vec::new());
        }
        let principals = principals
            .iter()
            .map(|principal| (*principal).to_string())
            .collect::<Vec<_>>();
        self.query_object_sets(
            &format!(
                "SELECT {OBJECT_SET_COLUMNS} FROM sekai_object_sets
                 WHERE owner_principal = ANY($1) ORDER BY created, id"
            ),
            &[&principals],
        )
    }

    pub fn delete_object_set(&self, id: &str) -> Result<bool, String> {
        self.connection()?
            .execute("DELETE FROM sekai_object_sets WHERE id = $1", &[&id])
            .map(|removed| removed > 0)
            .map_err(|error| error.to_string())
    }

    pub fn delete_object_set_for_principals(
        &self,
        id: &str,
        principals: &[&str],
    ) -> Result<bool, String> {
        if principals.is_empty() {
            return Ok(false);
        }
        let principals = principals
            .iter()
            .map(|principal| (*principal).to_string())
            .collect::<Vec<_>>();
        self.connection()?
            .execute(
                "DELETE FROM sekai_object_sets
                 WHERE id = $1 AND owner_principal = ANY($2)",
                &[&id, &principals],
            )
            .map(|removed| removed > 0)
            .map_err(|error| error.to_string())
    }

    fn query_object_sets(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<ObjectSet>, String> {
        self.connection()?
            .query(sql, params)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_object_set)
            .collect()
    }
}

fn row_to_object_set(row: postgres::Row) -> Result<ObjectSet, String> {
    let id: String = row.get(0);
    let filter_json: String = row.get(3);
    let filter = parse_filter(&id, &filter_json)?;
    Ok(ObjectSet {
        id,
        name: row.get(1),
        description: row.get(2),
        filter,
        owner_principal: row.get(4),
        created: row.get(5),
    })
}

fn parse_filter(id: &str, json: &str) -> Result<ListFilter, String> {
    serde_json::from_str(json)
        .map_err(|error| format!("invalid filter for object set {id}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_persisted_filter() {
        let filter =
            parse_filter("set-1", r#"{"kind":"model","limit":25,"descending":true}"#).unwrap();
        assert_eq!(filter.kind.as_deref(), Some("model"));
        assert_eq!(filter.limit, 25);
        assert!(filter.descending);
    }

    #[test]
    fn reports_object_set_for_invalid_filter() {
        let error = parse_filter("set-bad", "{").unwrap_err();
        assert!(error.contains("object set set-bad"));
    }
}
