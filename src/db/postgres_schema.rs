use crate::db::postgres::PostgresDb;
use crate::sekai::schema::{InterfaceDef, ObjectType, PropertyDef};

impl PostgresDb {
    pub fn upsert_object_type(&self, object_type: &ObjectType) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let properties =
            serde_json::to_string(&object_type.properties).map_err(|error| error.to_string())?;
        let implements =
            serde_json::to_string(&object_type.implements).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_object_types
                    (kind, description, properties_json, implements_json, created, updated)
                 VALUES ($1, $2, $3, $4, $5, $5)
                 ON CONFLICT (kind) DO UPDATE SET
                    description = EXCLUDED.description,
                    properties_json = EXCLUDED.properties_json,
                    implements_json = EXCLUDED.implements_json,
                    updated = EXCLUDED.updated",
                &[
                    &object_type.kind,
                    &object_type.description,
                    &properties,
                    &implements,
                    &now,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_object_type(&self, kind: &str) -> Result<Option<ObjectType>, String> {
        self.connection()?
            .query_opt(
                "SELECT kind, description, properties_json, implements_json
                 FROM sekai_object_types WHERE kind = $1",
                &[&kind],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object_type)
            .transpose()
    }

    pub fn list_object_types(&self) -> Result<Vec<ObjectType>, String> {
        self.connection()?
            .query(
                "SELECT kind, description, properties_json, implements_json
                 FROM sekai_object_types ORDER BY kind",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_object_type)
            .collect()
    }

    pub fn upsert_interface(&self, interface: &InterfaceDef) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        let properties =
            serde_json::to_string(&interface.properties).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_interfaces
                    (name, description, properties_json, created, updated)
                 VALUES ($1, $2, $3, $4, $4)
                 ON CONFLICT (name) DO UPDATE SET
                    description = EXCLUDED.description,
                    properties_json = EXCLUDED.properties_json,
                    updated = EXCLUDED.updated",
                &[&interface.name, &interface.description, &properties, &now],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_interfaces(&self) -> Result<Vec<InterfaceDef>, String> {
        self.connection()?
            .query(
                "SELECT name, description, properties_json
                 FROM sekai_interfaces ORDER BY name",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_interface)
            .collect()
    }
}

fn row_to_object_type(row: postgres::Row) -> Result<ObjectType, String> {
    let kind: String = row.get(0);
    let properties_json: String = row.get(2);
    let implements_json: String = row.get(3);
    Ok(ObjectType {
        kind: kind.clone(),
        description: row.get(1),
        properties: parse_properties(&format!("object type {kind}"), &properties_json)?,
        is_builtin: false,
        implements: serde_json::from_str(&implements_json)
            .map_err(|error| format!("invalid interfaces for object type {kind}: {error}"))?,
    })
}

fn row_to_interface(row: postgres::Row) -> Result<InterfaceDef, String> {
    let name: String = row.get(0);
    let properties_json: String = row.get(2);
    Ok(InterfaceDef {
        name: name.clone(),
        description: row.get(1),
        properties: parse_properties(&format!("interface {name}"), &properties_json)?,
        is_builtin: false,
    })
}

fn parse_properties(owner: &str, json: &str) -> Result<Vec<PropertyDef>, String> {
    serde_json::from_str(json).map_err(|error| format!("invalid properties for {owner}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_schema_json_is_not_silently_defaulted() {
        assert!(parse_properties("object type bad", "{").is_err());
    }
}
