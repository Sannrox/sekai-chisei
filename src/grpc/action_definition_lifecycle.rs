//! Legacy graph Action definition loading, validation, and convergence.
//!
//! This private lifecycle owns builtin protection and durable/cache ordering.
//! It intentionally remains separate from governed Action types, whose
//! execution and versioning semantics are different.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ActionDefinitionLifecycleError {
    Unavailable(String),
    InvalidDefinition(String),
    ProtectedBuiltin(String),
    Persistence(String),
}

#[derive(Clone)]
pub(super) struct ActionDefinitionLifecycle {
    db: Arc<RuntimeDb>,
    executor: Arc<RwLock<Arc<ActionExecutor>>>,
    mutation: Arc<Mutex<()>>,
}

impl ActionDefinitionLifecycle {
    pub(super) fn load(db: Arc<RuntimeDb>) -> Self {
        let executor = match load_executor(&db) {
            Ok(executor) => executor,
            Err(error) => {
                tracing::error!(?error, "failed to initialize action registry");
                ActionExecutor::new()
            }
        };
        Self {
            db,
            executor: Arc::new(RwLock::new(Arc::new(executor))),
            mutation: Arc::new(Mutex::new(())),
        }
    }

    pub(super) fn fresh_snapshot(
        &self,
    ) -> Result<Arc<ActionExecutor>, ActionDefinitionLifecycleError> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| unavailable("action registry mutation unavailable"))?;
        self.refresh_locked()
    }

    pub(super) fn put_definition(
        &self,
        definition: action::ActionTypeDef,
        schema: &SchemaRegistry,
    ) -> Result<action::ActionTypeDef, ActionDefinitionLifecycleError> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| unavailable("action registry mutation unavailable"))?;
        action::validate_action_type_definition(
            &definition,
            ActionExecutor::new().has_action(&definition.name),
        )
        .map_err(ActionDefinitionLifecycleError::InvalidDefinition)?;
        action::validate_action_type_against_schema(&definition, schema)
            .map_err(ActionDefinitionLifecycleError::InvalidDefinition)?;
        let stored = self
            .db
            .upsert_action_type(&definition)
            .map_err(ActionDefinitionLifecycleError::Persistence)?;
        self.refresh_locked()?;
        Ok(stored)
    }

    pub(super) fn delete_definition(
        &self,
        name: &str,
    ) -> Result<(), ActionDefinitionLifecycleError> {
        let _mutation = self
            .mutation
            .lock()
            .map_err(|_| unavailable("action registry mutation unavailable"))?;
        if ActionExecutor::new().has_action(name) {
            return Err(ActionDefinitionLifecycleError::ProtectedBuiltin(
                "cannot delete builtin action".into(),
            ));
        }
        self.db
            .delete_action_type(name)
            .map_err(ActionDefinitionLifecycleError::Persistence)?;
        self.refresh_locked()?;
        Ok(())
    }

    fn refresh_locked(&self) -> Result<Arc<ActionExecutor>, ActionDefinitionLifecycleError> {
        let refreshed = Arc::new(load_executor(&self.db)?);
        *self
            .executor
            .write()
            .map_err(|_| unavailable("action registry unavailable"))? = refreshed.clone();
        Ok(refreshed)
    }
}

fn load_executor(db: &RuntimeDb) -> Result<ActionExecutor, ActionDefinitionLifecycleError> {
    let definitions = db
        .list_action_types()
        .map_err(ActionDefinitionLifecycleError::Persistence)?;
    ActionExecutor::from_action_types(definitions)
        .map_err(|error| unavailable(format!("action registry unavailable: {error}")))
}

fn unavailable(message: impl Into<String>) -> ActionDefinitionLifecycleError {
    ActionDefinitionLifecycleError::Unavailable(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::sekai::schema::PropertyType;

    fn runtime_db() -> Arc<RuntimeDb> {
        Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )))
    }

    fn definition(name: &str, created: i64) -> action::ActionTypeDef {
        action::ActionTypeDef {
            name: name.into(),
            description: "Create a project from an asset".into(),
            params: vec![action::ActionParamDef {
                name: "project_name".into(),
                param_type: PropertyType::String,
                required: true,
                enum_values: Vec::new(),
            }],
            ops: vec![action::ActionOp {
                op: "create_object".into(),
                property: "project".into(),
                value_from: "project_name".into(),
                relation: String::new(),
            }],
            target_kind: "asset".into(),
            created,
            required_purpose: "delivery".into(),
        }
    }

    #[test]
    fn interface_preserves_created_time_and_required_purpose_on_replay() {
        let db = runtime_db();
        let lifecycle = ActionDefinitionLifecycle::load(db.clone());
        let schema = SchemaRegistry::new();

        let first = lifecycle
            .put_definition(definition("promote_asset", 41), &schema)
            .unwrap();
        let mut replay = definition("promote_asset", 99);
        replay.description = "Updated description".into();
        let stored = lifecycle.put_definition(replay, &schema).unwrap();

        assert_eq!(first.created, 41);
        assert_eq!(stored.created, 41);
        assert_eq!(stored.required_purpose, "delivery");
        assert_eq!(
            db.list_action_types().unwrap()[0].description,
            "Updated description"
        );
    }

    #[test]
    fn interface_refreshes_definitions_written_by_another_instance() {
        let db = runtime_db();
        let writer = ActionDefinitionLifecycle::load(db.clone());
        let reader = ActionDefinitionLifecycle::load(db);

        writer
            .put_definition(definition("shared_action", 1), &SchemaRegistry::new())
            .unwrap();

        assert!(reader.fresh_snapshot().unwrap().has_action("shared_action"));
    }

    #[test]
    fn interface_protects_builtins_and_rejects_schema_invalid_definitions() {
        let db = runtime_db();
        let lifecycle = ActionDefinitionLifecycle::load(db);
        let schema = SchemaRegistry::new();

        assert!(matches!(
            lifecycle.delete_definition("create_object"),
            Err(ActionDefinitionLifecycleError::ProtectedBuiltin(_))
        ));
        let mut invalid = definition("invalid_target", 1);
        invalid.target_kind = "missing_kind".into();
        assert!(matches!(
            lifecycle.put_definition(invalid, &schema),
            Err(ActionDefinitionLifecycleError::InvalidDefinition(_))
        ));
    }

    #[test]
    fn interface_fails_closed_when_durable_definitions_are_corrupt() {
        let db = runtime_db();
        db.conn()
            .execute(
                "INSERT INTO sekai_action_types
                 (name, description, target_kind, body_json, created, updated)
                 VALUES (?1, '', 'asset', '[', 1, 1)",
                ["corrupt_action"],
            )
            .unwrap();

        let lifecycle = ActionDefinitionLifecycle::load(db);

        assert!(matches!(
            lifecycle.fresh_snapshot(),
            Err(ActionDefinitionLifecycleError::Persistence(_))
        ));
    }
}
