//! Schema definition loading, repair, validation, and convergence.
//!
//! Callers receive domain snapshots and outcomes rather than registry locks.
//! This private module owns durable/cache ordering and global plus per-kind
//! corruption state. It intentionally does not add schema history or versions.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SchemaDefinitionLifecycleError {
    Unavailable(String),
    InvalidDefinition(String),
    InvalidComputedProperty(String),
    Persistence(String),
}

#[derive(Clone)]
pub(super) struct SchemaDefinitionLifecycle {
    db: Arc<RuntimeDb>,
    registry: Arc<RwLock<SchemaRegistry>>,
    unavailable_error: Arc<RwLock<Option<String>>>,
    kind_errors: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl SchemaDefinitionLifecycle {
    pub(super) fn load(db: Arc<RuntimeDb>) -> Self {
        let (types, interfaces, unavailable_error, kind_errors) =
            match (db.list_object_types_with_errors(), db.list_interfaces()) {
                (Ok((types, errors)), Ok(interfaces)) => {
                    log_kind_errors(&errors);
                    (types, interfaces, None, errors)
                }
                (Err(error), _) | (_, Err(error)) => {
                    tracing::error!(%error, "failed to load schema registry");
                    (
                        Vec::new(),
                        Vec::new(),
                        Some(error),
                        std::collections::HashMap::new(),
                    )
                }
            };
        Self {
            db,
            registry: Arc::new(RwLock::new(SchemaRegistry::from_types_and_interfaces(
                types, interfaces,
            ))),
            unavailable_error: Arc::new(RwLock::new(unavailable_error)),
            kind_errors: Arc::new(RwLock::new(kind_errors)),
        }
    }

    pub(super) fn snapshot(&self) -> Result<SchemaRegistry, SchemaDefinitionLifecycleError> {
        if let Some(error) = self
            .unavailable_error
            .read()
            .map_err(|_| unavailable("schema registry lock poisoned"))?
            .as_ref()
        {
            return Err(unavailable(format!("schema registry unavailable: {error}")));
        }
        self.registry
            .read()
            .map_err(|_| unavailable("schema registry lock poisoned"))
            .map(|registry| registry.clone())
    }

    pub(super) fn ensure_kind_loaded(
        &self,
        kind: &str,
    ) -> Result<(), SchemaDefinitionLifecycleError> {
        // Definitions are durable and shared across service instances. Reload
        // before schema-governed writes so a process-local cache never admits
        // a mutation against an obsolete definition.
        self.refresh()?;
        let errors = self
            .kind_errors
            .read()
            .map_err(|_| unavailable("schema registry lock poisoned"))?;
        if let Some(error) = errors.get(kind) {
            return Err(unavailable(format!(
                "schema type {kind} unavailable: {error}"
            )));
        }
        Ok(())
    }

    pub(super) fn put_definition(
        &self,
        definition: schema::ObjectType,
    ) -> Result<schema::ObjectType, SchemaDefinitionLifecycleError> {
        self.refresh()?;
        let registry = self.snapshot()?;
        schema::validate_object_type_definition(
            &definition,
            registry.get(&definition.kind),
            &registry,
        )
        .map_err(SchemaDefinitionLifecycleError::InvalidDefinition)?;
        self.validate_computed_properties(&definition)?;
        self.db
            .upsert_object_type(&definition)
            .map_err(SchemaDefinitionLifecycleError::Persistence)?;
        self.registry
            .write()
            .map_err(|_| unavailable("schema registry lock poisoned"))?
            .register(definition.clone());
        self.kind_errors
            .write()
            .map_err(|_| unavailable("schema registry lock poisoned"))?
            .remove(&definition.kind);
        Ok(definition)
    }

    pub(super) fn refresh_snapshot(
        &self,
    ) -> Result<SchemaRegistry, SchemaDefinitionLifecycleError> {
        self.refresh()?;
        self.snapshot()
    }

    fn validate_computed_properties(
        &self,
        definition: &schema::ObjectType,
    ) -> Result<(), SchemaDefinitionLifecycleError> {
        for property in &definition.properties {
            if property.prop_type != schema::PropertyType::Computed
                || property.compute_expr.is_empty()
            {
                continue;
            }
            if self
                .db
                .get_function(&property.compute_expr)
                .map_err(unavailable)?
                .is_none()
            {
                return Err(SchemaDefinitionLifecycleError::InvalidComputedProperty(
                    format!(
                        "computed property {} references unknown function {}",
                        property.name, property.compute_expr
                    ),
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn register_interface(
        &self,
        interface: schema::InterfaceDef,
    ) -> Result<(), SchemaDefinitionLifecycleError> {
        self.registry
            .write()
            .map_err(|_| unavailable("schema registry lock poisoned"))?
            .register_interface(interface);
        Ok(())
    }

    fn refresh(&self) -> Result<(), SchemaDefinitionLifecycleError> {
        match (
            self.db.list_object_types_with_errors(),
            self.db.list_interfaces(),
        ) {
            (Ok((types, errors)), Ok(interfaces)) => {
                log_kind_errors(&errors);
                *self
                    .registry
                    .write()
                    .map_err(|_| unavailable("schema registry lock poisoned"))? =
                    SchemaRegistry::from_types_and_interfaces(types, interfaces);
                *self
                    .kind_errors
                    .write()
                    .map_err(|_| unavailable("schema registry lock poisoned"))? = errors;
                *self
                    .unavailable_error
                    .write()
                    .map_err(|_| unavailable("schema registry lock poisoned"))? = None;
                Ok(())
            }
            (Err(error), _) | (_, Err(error)) => {
                *self
                    .unavailable_error
                    .write()
                    .map_err(|_| unavailable("schema registry lock poisoned"))? =
                    Some(error.clone());
                Err(unavailable(format!("schema registry unavailable: {error}")))
            }
        }
    }
}

fn unavailable(message: impl Into<String>) -> SchemaDefinitionLifecycleError {
    SchemaDefinitionLifecycleError::Unavailable(message.into())
}

fn log_kind_errors(errors: &std::collections::HashMap<String, String>) {
    for (kind, error) in errors {
        tracing::error!(kind, %error, "failed to load schema type");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;

    fn runtime_db() -> Arc<RuntimeDb> {
        Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )))
    }

    fn definition(kind: &str) -> schema::ObjectType {
        schema::ObjectType {
            kind: kind.into(),
            description: format!("Schema for {kind}"),
            properties: Vec::new(),
            is_builtin: false,
            implements: Vec::new(),
        }
    }

    #[test]
    fn interface_repairs_one_corrupt_kind_and_converges_durable_cache_state() {
        let db = runtime_db();
        db.conn()
            .execute(
                "INSERT INTO sekai_object_types
                 (kind, description, properties_json, created, updated)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                ("broken", "Broken schema", "[", 1_i64),
            )
            .unwrap();
        let lifecycle = SchemaDefinitionLifecycle::load(db.clone());

        assert!(matches!(
            lifecycle.ensure_kind_loaded("broken"),
            Err(SchemaDefinitionLifecycleError::Unavailable(error))
                if error.contains("broken")
        ));
        lifecycle.put_definition(definition("broken")).unwrap();

        lifecycle.ensure_kind_loaded("broken").unwrap();
        assert!(lifecycle.snapshot().unwrap().get("broken").is_some());
        assert!(db.get_object_type("broken").unwrap().is_some());
    }

    #[test]
    fn interface_refreshes_definitions_written_by_another_instance() {
        let db = runtime_db();
        let writer = SchemaDefinitionLifecycle::load(db.clone());
        let reader = SchemaDefinitionLifecycle::load(db);

        writer.put_definition(definition("shared")).unwrap();
        assert!(reader.snapshot().unwrap().get("shared").is_none());

        assert!(reader.refresh_snapshot().unwrap().get("shared").is_some());
    }

    #[test]
    fn interface_recovers_after_a_global_schema_table_failure() {
        let db = runtime_db();
        {
            let conn = db.conn();
            conn.execute("DROP TABLE sekai_object_types", []).unwrap();
            conn.execute(
                "CREATE TABLE sekai_object_types (kind TEXT PRIMARY KEY)",
                [],
            )
            .unwrap();
        }
        let lifecycle = SchemaDefinitionLifecycle::load(db.clone());
        assert!(lifecycle.ensure_kind_loaded("loose").is_err());

        db.conn()
            .execute("DROP TABLE sekai_object_types", [])
            .unwrap();
        db.migrate_all().unwrap();

        lifecycle.ensure_kind_loaded("loose").unwrap();
    }
}
