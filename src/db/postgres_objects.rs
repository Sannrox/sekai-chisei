use std::collections::HashMap;

use crate::db::object_security::postgres_object_security_filter;
use crate::db::postgres::PostgresDb;
use crate::domain::{
    Direction, Link, ListFilter, MAX_LIST_LIMIT, Object, PropertyFilter, excluded_kinds_sql,
    is_valid_property_key, storage_properties_json,
};
use crate::sekai::lineage::{LineageEdge, LineageNode, LineageResult};
use crate::sekai::object_security::PrincipalPolicyContext;
use postgres::IsolationLevel;

const OBJECT_COLUMNS: &str = "id, kind, name, namespace, external_id, properties, created, updated";
const LINK_COLUMNS: &str = "id, from_id, to_id, relation, created";

fn postgres_stored_property_text(key_sql: &str) -> String {
    format!("(sekai_jsonb_object(o.properties) ->> {key_sql})")
}

impl PostgresDb {
    pub fn create_object(&self, object: &Object) -> Result<(), String> {
        let properties = storage_properties_json(&object.properties)?;
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

    pub fn get_object_with_policy_context(
        &self,
        id: &str,
        context: &PrincipalPolicyContext,
    ) -> Result<Option<Object>, String> {
        let context = context.clone().normalized();
        self.connection()?
            .query_opt(
                &format!(
                    "SELECT {OBJECT_COLUMNS} FROM sekai_objects o
                     WHERE o.id=$1{}",
                    postgres_object_security_filter("$2", "$3")
                ),
                &[&id, &context.subjects, &context.scopes],
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
        let properties = storage_properties_json(&object.properties)?;
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

    pub fn find_all_by_external_id(&self, external_id: &str) -> Result<Vec<Object>, String> {
        self.connection()?
            .query(
                &format!("SELECT {OBJECT_COLUMNS} FROM sekai_objects WHERE external_id = $1"),
                &[&external_id],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_object)
            .collect()
    }

    pub fn list_objects(&self, filter: &ListFilter) -> Result<Vec<Object>, String> {
        self.list_objects_query(filter, None, None, &[])
            .map(|result| result.0)
    }

    pub fn list_objects_with_total_for_principals(
        &self,
        filter: &ListFilter,
        principals: &[&str],
    ) -> Result<(Vec<Object>, i32), String> {
        self.list_objects_query(filter, Some(principals), None, &[])
    }

    pub fn list_objects_with_total_for_policy_context(
        &self,
        filter: &ListFilter,
        principals: &[&str],
        excluded_kinds: &[&str],
        context: &PrincipalPolicyContext,
    ) -> Result<(Vec<Object>, i32), String> {
        self.list_objects_query(filter, Some(principals), Some(context), excluded_kinds)
    }

    fn list_objects_query(
        &self,
        filter: &ListFilter,
        principals: Option<&[&str]>,
        policy_context: Option<&PrincipalPolicyContext>,
        excluded_kinds: &[&str],
    ) -> Result<(Vec<Object>, i32), String> {
        let mut where_parts = Vec::new();
        let mut params: Vec<Box<dyn postgres::types::ToSql + Sync>> = Vec::new();
        if let Some(kind) = &filter.kind {
            let parameter = push_text_param(&mut params, kind.clone());
            where_parts.push(format!("o.kind = {parameter}"));
        }
        let kind_exclusion = excluded_kinds_sql("o.kind", excluded_kinds)?;
        if !kind_exclusion.is_empty() {
            where_parts.push(kind_exclusion.trim_start_matches(" AND ").to_string());
        }
        if let Some(name) = &filter.name {
            let parameter = push_text_param(&mut params, name.clone());
            where_parts.push(format!("o.name = {parameter}"));
        }
        if let Some(namespace) = &filter.namespace {
            let parameter = push_text_param(&mut params, namespace.clone());
            where_parts.push(format!("o.namespace = {parameter}"));
        }
        for property_filter in &filter.property_filters {
            where_parts.push(postgres_property_filter(property_filter, &mut params)?);
        }
        for interface in &filter.interface_filter {
            let parameter = push_text_param(&mut params, interface.clone());
            where_parts.push(format!(
                "EXISTS (
                    SELECT 1 FROM sekai_object_types t
                    WHERE t.kind = o.kind
                      AND t.implements_json::jsonb ? {parameter}
                )"
            ));
        }
        if let Some(principals) = principals {
            let privileged = principals
                .iter()
                .any(|principal| matches!(*principal, "root" | "local"));
            let effective = principals
                .iter()
                .filter(|principal| !principal.is_empty() && **principal != "anonymous")
                .map(|principal| (*principal).to_string())
                .collect::<Vec<_>>();
            params.push(Box::new(effective));
            let parameter = format!("${}", params.len());
            where_parts.push(format!(
                "(NOT EXISTS (
                    SELECT 1 FROM sekai_grants g WHERE g.object_id = o.id
                 ) OR EXISTS (
                    SELECT 1 FROM sekai_grants g
                    WHERE g.object_id = o.id AND g.principal = ANY({parameter})
                 ))"
            ));
            if !privileged {
                where_parts.push(format!(
                    "(NOT EXISTS (
                        SELECT 1 FROM sekai_objects boundary
                        WHERE boundary.kind = 'namespace'
                          AND boundary.external_id = 'namespace:' || o.namespace
                          AND boundary.properties::jsonb ->> 'team_managed' = 'true'
                    ) OR EXISTS (
                        SELECT 1 FROM sekai_objects boundary
                        JOIN sekai_grants namespace_grant
                          ON namespace_grant.object_id = boundary.id
                        WHERE boundary.kind = 'namespace'
                          AND boundary.external_id = 'namespace:' || o.namespace
                          AND boundary.properties::jsonb ->> 'team_managed' = 'true'
                          AND namespace_grant.principal = ANY({parameter})
                    ))"
                ));
            }
        }
        if let Some(context) = policy_context {
            let context = context.clone().normalized();
            params.push(Box::new(context.subjects));
            let subjects = format!("${}", params.len());
            params.push(Box::new(context.scopes));
            let scopes = format!("${}", params.len());
            where_parts.push(
                postgres_object_security_filter(&subjects, &scopes)
                    .trim_start_matches(" AND ")
                    .to_string(),
            );
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", where_parts.join(" AND "))
        };
        let refs = params
            .iter()
            .map(|value| value.as_ref() as &(dyn postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let mut connection = self.connection()?;
        let mut transaction = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .map_err(|error| error.to_string())?;
        let total: i64 = transaction
            .query_one(
                &format!("SELECT COUNT(*) FROM sekai_objects o{where_sql}"),
                &refs,
            )
            .map_err(|error| error.to_string())?
            .get(0);

        let direction = if filter.descending { "DESC" } else { "ASC" };
        let order_expression = match filter.order_by.as_str() {
            "" => "o.id ASC".to_string(),
            "created" => format!("o.created {direction}, o.id ASC"),
            "updated" => format!("o.updated {direction}, o.id ASC"),
            "name" => format!("o.name {direction}, o.id ASC"),
            property if property.starts_with("property:") => {
                let key = property.trim_start_matches("property:");
                if !is_valid_property_key(key) {
                    return Err("invalid property order key".into());
                }
                params.push(Box::new(key.to_string()));
                let value = postgres_stored_property_text(&format!("${}", params.len()));
                let numeric = postgres_numeric_predicate(&value);
                format!(
                    "CASE WHEN {value} IS NULL THEN 1 ELSE 0 END,
                     CASE WHEN {numeric} THEN 0 ELSE 1 END,
                     CASE WHEN {numeric}
                          THEN BTRIM({value})::double precision END {direction},
                     CASE WHEN {numeric} THEN '' ELSE {value} END {direction},
                     o.id ASC"
                )
            }
            _ => return Err("invalid order_by field".into()),
        };
        let limit = if filter.limit == i32::MAX {
            i32::MAX
        } else if filter.limit <= 0 {
            MAX_LIST_LIMIT
        } else {
            filter.limit.min(MAX_LIST_LIMIT)
        };
        params.push(Box::new(limit));
        let limit_parameter = format!("${}", params.len());
        params.push(Box::new(filter.offset.max(0)));
        let offset_parameter = format!("${}", params.len());
        let refs = params
            .iter()
            .map(|value| value.as_ref() as &(dyn postgres::types::ToSql + Sync))
            .collect::<Vec<_>>();
        let rows = transaction
            .query(
                &format!(
                    "SELECT {OBJECT_COLUMNS} FROM sekai_objects o{where_sql}
                     ORDER BY {order_expression}
                     LIMIT {limit_parameter} OFFSET {offset_parameter}"
                ),
                &refs,
            )
            .map_err(|error| error.to_string())?;
        let objects = rows
            .into_iter()
            .map(row_to_object)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok((objects, total.min(i32::MAX as i64) as i32))
    }

    pub fn find_by_property(
        &self,
        kind: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<Object>, String> {
        self.find_by_property_with_policy_context(kind, key, value, None)
    }

    pub fn find_by_property_with_policy_context(
        &self,
        kind: &str,
        key: &str,
        value: &str,
        context: Option<&PrincipalPolicyContext>,
    ) -> Result<Vec<Object>, String> {
        if !is_valid_property_key(key) {
            return Err("invalid property key".into());
        }
        let context = context.map(|context| context.clone().normalized());
        let sql = if context.is_some() {
            format!(
                "SELECT {OBJECT_COLUMNS} FROM sekai_objects o
                 WHERE o.kind = $1 AND (sekai_jsonb_object(o.properties) ->> $2) = $3{}",
                postgres_object_security_filter("$4", "$5")
            )
        } else {
            format!(
                "SELECT {OBJECT_COLUMNS} FROM sekai_objects
                 WHERE kind = $1 AND (sekai_jsonb_object(properties) ->> $2) = $3"
            )
        };
        match context {
            Some(context) => self.query_objects(
                &sql,
                &[&kind, &key, &value, &context.subjects, &context.scopes],
            ),
            None => self.query_objects(&sql, &[&kind, &key, &value]),
        }
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
        self.get_linked_objects_with_policy_context(object_id, relation, direction, None)
    }

    pub fn get_linked_objects_with_policy_context(
        &self,
        object_id: &str,
        relation: &str,
        direction: &Direction,
        context: Option<&PrincipalPolicyContext>,
    ) -> Result<Vec<Object>, String> {
        let links = self.get_links(object_id, relation, direction)?;
        let mut objects = Vec::with_capacity(links.len());
        for link in links {
            let target_id = match direction {
                Direction::Outgoing => link.to_id,
                Direction::Incoming => link.from_id,
            };
            let object = if let Some(context) = context {
                self.get_object_with_policy_context(&target_id, context)?
            } else {
                self.get_object(&target_id)?
            };
            if let Some(object) = object {
                objects.push(object);
            }
        }
        Ok(objects)
    }

    pub fn get_lineage(&self, object_id: &str, max_nodes: usize) -> Result<LineageResult, String> {
        use std::collections::{HashSet, VecDeque};
        let max = if max_nodes == 0 {
            200
        } else {
            max_nodes.min(500)
        };
        let start = self.get_object(object_id)?.ok_or("object not found")?;
        let mut result = LineageResult::default();
        let mut visited = HashSet::from([start.id.clone()]);
        let mut queue = VecDeque::from([start.clone()]);
        result.nodes.push(LineageNode {
            role: lineage_role(&start.kind),
            ephemeral: false,
            object: start,
        });
        while let Some(object) = queue.pop_front() {
            if result.nodes.len() >= max {
                result.truncated = true;
                break;
            }
            for direction in [Direction::Outgoing, Direction::Incoming] {
                for link in self.get_links(&object.id, "", &direction)? {
                    if !is_lineage_relation(&link.relation) {
                        continue;
                    }
                    let target = match direction {
                        Direction::Outgoing => &link.to_id,
                        Direction::Incoming => &link.from_id,
                    };
                    if !visited.insert(target.clone()) {
                        continue;
                    }
                    if let Some(object) = self.get_object(target)? {
                        result.edges.push(LineageEdge {
                            from: link.from_id,
                            to: link.to_id,
                            relation: link.relation,
                        });
                        result.nodes.push(LineageNode {
                            role: lineage_role(&object.kind),
                            ephemeral: false,
                            object: object.clone(),
                        });
                        queue.push_back(object);
                    }
                    if result.nodes.len() >= max {
                        result.truncated = true;
                        break;
                    }
                }
            }
        }
        Ok(result)
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

fn push_text_param(
    params: &mut Vec<Box<dyn postgres::types::ToSql + Sync>>,
    value: String,
) -> String {
    params.push(Box::new(value));
    format!("${}", params.len())
}

fn postgres_property_filter(
    filter: &PropertyFilter,
    params: &mut Vec<Box<dyn postgres::types::ToSql + Sync>>,
) -> Result<String, String> {
    if !is_valid_property_key(&filter.key) {
        return Err("invalid property key".into());
    }
    match filter.op.to_ascii_lowercase().as_str() {
        "eq" => {
            let (property, value) = push_property_comparison(filter, params);
            Ok(format!("{property} = {value}"))
        }
        "ne" | "neq" => {
            let (property, value) = push_property_comparison(filter, params);
            Ok(format!("{property} IS NOT NULL AND {property} <> {value}"))
        }
        "contains" | "prefix" => {
            params.push(Box::new(filter.key.clone()));
            let property = postgres_stored_property_text(&format!("${}", params.len()));
            let suffix = if filter.op.eq_ignore_ascii_case("contains") {
                "%"
            } else {
                ""
            };
            params.push(Box::new(format!(
                "{suffix}{}{percent}",
                escape_like_pattern(&filter.value),
                percent = "%"
            )));
            Ok(format!("{property} ILIKE ${} ESCAPE '\\'", params.len()))
        }
        "in" => {
            let values = filter
                .value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Ok("FALSE".into());
            }
            params.push(Box::new(filter.key.clone()));
            let property = postgres_stored_property_text(&format!("${}", params.len()));
            params.push(Box::new(values));
            Ok(format!("{property} = ANY(${})", params.len()))
        }
        "gt" | "gte" | "lt" | "lte" => {
            let (property, value) = push_property_comparison(filter, params);
            let compare = match filter.op.to_ascii_lowercase().as_str() {
                "gt" => ">",
                "gte" => ">=",
                "lt" => "<",
                "lte" => "<=",
                _ => unreachable!(),
            };
            let property_numeric = postgres_numeric_predicate(&property);
            let value_numeric = postgres_numeric_predicate(&value);
            Ok(format!(
                "CASE WHEN {property_numeric} AND {value_numeric}
                    THEN BTRIM({property})::double precision {compare}
                         BTRIM({value})::double precision
                    ELSE {property} {compare} {value}
                 END"
            ))
        }
        _ => Err("unsupported property filter operator".into()),
    }
}

fn push_property_comparison(
    filter: &PropertyFilter,
    params: &mut Vec<Box<dyn postgres::types::ToSql + Sync>>,
) -> (String, String) {
    params.push(Box::new(filter.key.clone()));
    let property = postgres_stored_property_text(&format!("${}", params.len()));
    params.push(Box::new(filter.value.clone()));
    let value = format!("${}", params.len());
    (property, value)
}

fn escape_like_pattern(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn postgres_numeric_predicate(expression: &str) -> String {
    format!("sekai_is_numeric_text({expression})")
}

fn lineage_role(kind: &str) -> String {
    match kind {
        "namespace" => "namespace",
        "commit" => "commit",
        "pull_request" => "pr",
        _ => "other",
    }
    .into()
}

fn is_lineage_relation(relation: &str) -> bool {
    matches!(
        relation,
        "contains"
            | "produces"
            | "targets"
            | "executed"
            | "depends_on"
            | "evidence_for"
            | "derived_from"
    )
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
