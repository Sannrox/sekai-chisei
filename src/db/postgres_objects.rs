use std::collections::HashMap;

use crate::db::postgres::PostgresDb;
use crate::domain::{Direction, Link, Object, is_valid_property_key};

const OBJECT_COLUMNS: &str = "id, kind, name, namespace, external_id, properties, created, updated";
const LINK_COLUMNS: &str = "id, from_id, to_id, relation, created";

impl PostgresDb {
    pub fn create_object(&self, object: &Object) -> Result<(), String> {
        let properties =
            serde_json::to_string(&object.properties).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_objects
                    (id, kind, name, namespace, external_id, properties, created, updated)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &object.id,
                    &object.kind,
                    &object.name,
                    &object.namespace,
                    &object.external_id,
                    &properties,
                    &object.created,
                    &object.updated,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_object(&self, id: &str) -> Result<Option<Object>, String> {
        self.connection()?
            .query_opt(
                &format!("SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE id = $1"),
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()
    }

    pub fn update_object(&self, object: &Object) -> Result<(), String> {
        if self.update_object_with_existing(object)?.is_none() {
            return Err("not found".into());
        }
        Ok(())
    }

    pub fn update_object_with_existing(&self, object: &Object) -> Result<Option<Object>, String> {
        let properties =
            serde_json::to_string(&object.properties).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let before = transaction
            .query_opt(
                &format!("SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE id = $1 FOR UPDATE"),
                &[&object.id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()?;
        if before.is_some() {
            transaction
                .execute(
                    "UPDATE sekai_objects SET
                        kind = $2, name = $3, namespace = $4, external_id = $5,
                        properties = $6, updated = $7
                     WHERE id = $1",
                    &[
                        &object.id,
                        &object.kind,
                        &object.name,
                        &object.namespace,
                        &object.external_id,
                        &properties,
                        &object.updated,
                    ],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(before)
    }

    pub fn delete_object(&self, id: &str) -> Result<(), String> {
        self.delete_object_with_existing(id).map(|_| ())
    }

    pub fn delete_object_with_existing(&self, id: &str) -> Result<Option<Object>, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let before = transaction
            .query_opt(
                &format!("SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE id = $1 FOR UPDATE"),
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()?;
        transaction
            .execute(
                "DELETE FROM sekai_links WHERE from_id = $1 OR to_id = $1",
                &[&id],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute("DELETE FROM sekai_objects WHERE id = $1", &[&id])
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(before)
    }

    pub fn find_by_external_id(&self, external_id: &str) -> Result<Option<Object>, String> {
        self.connection()?
            .query_opt(
                &format!(
                    "SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE external_id = $1 LIMIT 1"
                ),
                &[&external_id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()
    }

    pub fn find_by_property(
        &self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>, String> {
        if !is_valid_property_key(key) {
            return Err("invalid property key".into());
        }
        self.query_objects(
            &format!(
                "SELECT {OBJECT_COLUMNS} FROM sekai_objects
                 WHERE kind = $1 AND (properties::jsonb ->> $2) = $3"
            ),
            &[&kind, &key, &value],
        )
    }

    pub fn create_link(&self, link: &Link) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_links (id, from_id, to_id, relation, created)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING",
                &[
                    &link.id,
                    &link.from_id,
                    &link.to_id,
                    &link.relation,
                    &link.created,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn create_link_once(&self, link: &Link) -> Result<bool, String> {
        self.connection()?
            .execute(
                "INSERT INTO sekai_links (id, from_id, to_id, relation, created)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING",
                &[
                    &link.id,
                    &link.from_id,
                    &link.to_id,
                    &link.relation,
                    &link.created,
                ],
            )
            .map(|inserted| inserted == 1)
            .map_err(|error| error.to_string())
    }

    pub fn delete_link(&self, id: &str) -> Result<(), String> {
        self.connection()?
            .execute("DELETE FROM sekai_links WHERE id = $1", &[&id])
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_link(&self, id: &str) -> Result<Option<Link>, String> {
        self.connection()?
            .query_opt(
                &format!("SELECT {LINK_COLUMNS} FROM sekai_links WHERE id = $1"),
                &[&id],
            )
            .map(|row| row.map(row_to_link))
            .map_err(|error| error.to_string())
    }

    pub fn get_links(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
    ) -> Result<Vec<Link>, String> {
        self.get_links_query(object_id, relation, direction, None)
    }

    pub fn get_links_limited(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
        limit: usize,
    ) -> Result<Vec<Link>, String> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.get_links_query(
            object_id,
            relation,
            direction,
            Some(limit.min(i64::MAX as usize) as i64),
        )
    }

    pub fn get_linked_objects(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
    ) -> Result<Vec<Object>, String> {
        let links = self.get_links(object_id, relation, direction)?;
        let mut objects = Vec::with_capacity(links.len());
        for link in links {
            let target_id = match direction {
                Direction::Outgoing => link.to_id,
                Direction::Incoming => link.from_id,
            };
            if let Some(object) = self.get_object(&target_id)? {
                objects.push(object);
            }
        }
        Ok(objects)
    }

    fn get_links_query(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
        limit: Option<i64>,
    ) -> Result<Vec<Link>, String> {
        let column = match direction {
            Direction::Outgoing => "from_id",
            Direction::Incoming => "to_id",
        };
        let mut sql = format!("SELECT {LINK_COLUMNS} FROM sekai_links WHERE {column} = $1");
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&object_id];
        if !relation.is_empty() {
            sql.push_str(" AND relation = $2");
            params.push(&relation);
        }
        sql.push_str(" ORDER BY relation, id, from_id, to_id");
        if let Some(limit) = &limit {
            sql.push_str(if relation.is_empty() {
                " LIMIT $2"
            } else {
                " LIMIT $3"
            });
            params.push(limit);
        }
        self.connection()?
            .query(&sql, &params)
            .map(|rows| rows.into_iter().map(row_to_link).collect())
            .map_err(|error| error.to_string())
    }

    fn query_objects(
        &self,
        sql: &str,
        params: &[&(dyn postgres::types::ToSql + Sync)],
    ) -> Result<Vec<Object>, String> {
        self.connection()?
            .query(sql, params)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_object)
            .collect()
    }
}

fn row_to_object(row: postgres::Row) -> Result<Object, String> {
    let properties_json: String = row.get(5);
    let properties: HashMap<String, String> =
        serde_json::from_str(&properties_json).map_err(|error| {
            format!(
                "invalid properties for object {}: {error}",
                row.get::<_, String>(0)
            )
        })?;
    Ok(Object {
        id: row.get(0),
        kind: row.get(1),
        name: row.get(2),
        namespace: row.get(3),
        external_id: row.get(4),
        properties,
        created: row.get(6),
        updated: row.get(7),
    })
}

fn row_to_link(row: postgres::Row) -> Link {
    Link {
        id: row.get(0),
        from_id: row.get(1),
        to_id: row.get(2),
        relation: row.get(3),
        created: row.get(4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_and_link_column_order_matches_decoders() {
        assert_eq!(OBJECT_COLUMNS.split(',').count(), 8);
        assert_eq!(LINK_COLUMNS.split(',').count(), 5);
    }

    #[test]
    fn property_lookup_rejects_unsafe_keys_before_connecting() {
        let result = PostgresDb::connect("", 1).unwrap_err();
        assert!(result.contains("must not be empty"));
        assert!(!is_valid_property_key("name') OR TRUE --"));
    }
}
