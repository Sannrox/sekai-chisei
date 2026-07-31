//! SQLite persistence for immutable evaluation plans and evaluator definitions.

use crate::chisei::evaluation_plan::{
    AVAILABILITY_ENABLED, EvaluationPlan, EvaluatorAvailability, EvaluatorDefinition,
    prepare_availability, prepare_definition, prepare_plan,
};
use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

impl SekaiDb {
    pub(crate) fn migrate_evaluation_plans(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_evaluator_definitions (
                    definition_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    evaluator_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    implementation_digest TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    UNIQUE(namespace, evaluator_id, version)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluator_definitions_namespace
                    ON chisei_evaluator_definitions(namespace, evaluator_id, version);
                CREATE TABLE IF NOT EXISTS chisei_evaluator_availability (
                    definition_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    changed_at_ms INTEGER NOT NULL,
                    FOREIGN KEY(definition_id) REFERENCES chisei_evaluator_definitions(definition_id)
                );
                CREATE TABLE IF NOT EXISTS chisei_evaluator_availability_events (
                    definition_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    changed_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(definition_id, request_id),
                    FOREIGN KEY(definition_id) REFERENCES chisei_evaluator_definitions(definition_id)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluator_availability_events_time
                    ON chisei_evaluator_availability_events(definition_id, changed_at_ms);
                CREATE TABLE IF NOT EXISTS chisei_evaluation_plans (
                    plan_version_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    UNIQUE(namespace, plan_id, version)
                );
                CREATE INDEX IF NOT EXISTS idx_chisei_evaluation_plans_namespace
                    ON chisei_evaluation_plans(namespace, plan_id, version);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn put_evaluator_definition(
        &self,
        definition: EvaluatorDefinition,
        actor: &str,
        now_ms: i64,
    ) -> Result<EvaluatorDefinition, String> {
        let definition = prepare_definition(definition, actor, now_ms)?;
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(existing) = get_definition_tx(&transaction, &definition.definition_id)? {
            return immutable_definition_replay(existing, &definition);
        }
        let body_json = serde_json::to_string(&definition).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO chisei_evaluator_definitions
                 (definition_id, namespace, evaluator_id, version, implementation_digest,
                  content_digest, body_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    definition.definition_id,
                    definition.namespace,
                    definition.evaluator_id,
                    definition.version,
                    definition.implementation_digest,
                    definition.content_digest,
                    body_json,
                    definition.created_at_ms,
                ],
            )
            .map_err(map_definition_insert_error)?;
        let initial = prepare_availability(
            &definition,
            AVAILABILITY_ENABLED,
            "",
            "evaluator definition registered",
            &format!("definition-created:{}", definition.content_digest),
            actor,
            now_ms,
        )?;
        insert_availability_event_tx(&transaction, &initial)?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(definition)
    }

    pub fn get_evaluator_definition(
        &self,
        definition_id: &str,
    ) -> Result<Option<EvaluatorDefinition>, String> {
        let connection = self.conn();
        get_definition_connection(&connection, definition_id)
    }

    pub fn list_evaluator_definitions(
        &self,
        namespace: &str,
        evaluator_id: Option<&str>,
    ) -> Result<Vec<EvaluatorDefinition>, String> {
        let connection = self.conn();
        let mut definitions = Vec::new();
        if let Some(evaluator_id) = evaluator_id {
            let mut statement = connection
                .prepare(
                    "SELECT body_json FROM chisei_evaluator_definitions
                 WHERE namespace=?1 AND evaluator_id=?2 ORDER BY evaluator_id, version",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map(params![namespace, evaluator_id], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|error| error.to_string())?;
            for row in rows {
                definitions.push(decode_definition(&row.map_err(|error| error.to_string())?)?);
            }
        } else {
            let mut statement = connection
                .prepare(
                    "SELECT body_json FROM chisei_evaluator_definitions
                 WHERE namespace=?1 ORDER BY evaluator_id, version",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map(params![namespace], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            for row in rows {
                definitions.push(decode_definition(&row.map_err(|error| error.to_string())?)?);
            }
        }
        Ok(definitions)
    }

    pub fn get_evaluator_availability(
        &self,
        definition_id: &str,
    ) -> Result<Option<EvaluatorAvailability>, String> {
        self.conn()
            .query_row(
                "SELECT body_json FROM chisei_evaluator_availability WHERE definition_id=?1",
                params![definition_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|body| decode_availability(&body))
            .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn set_evaluator_availability(
        &self,
        definition_id: &str,
        state: &str,
        superseded_by_definition_id: &str,
        reason: &str,
        request_id: &str,
        actor: &str,
        now_ms: i64,
    ) -> Result<EvaluatorAvailability, String> {
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let definition = get_definition_tx(&transaction, definition_id)?
            .ok_or_else(|| "evaluator definition not found".to_string())?;
        let availability = prepare_availability(
            &definition,
            state,
            superseded_by_definition_id,
            reason,
            request_id,
            actor,
            now_ms,
        )?;
        if let Some(existing) = get_availability_event_tx(&transaction, definition_id, request_id)?
        {
            return availability_replay(existing, &availability);
        }
        if !superseded_by_definition_id.is_empty() {
            let successor = get_definition_tx(&transaction, superseded_by_definition_id)?
                .ok_or_else(|| "superseding evaluator definition not found".to_string())?;
            if successor.namespace != definition.namespace {
                return Err(
                    "superseding evaluator definition must be in the same namespace".into(),
                );
            }
        }
        insert_availability_event_tx(&transaction, &availability)?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(availability)
    }

    pub fn put_evaluation_plan(
        &self,
        plan: EvaluationPlan,
        actor: &str,
        now_ms: i64,
    ) -> Result<EvaluationPlan, String> {
        let plan = prepare_plan(plan, actor, now_ms)?;
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(existing) = get_plan_tx(&transaction, &plan.plan_version_id)? {
            return immutable_plan_replay(existing, &plan);
        }
        require_enabled_plan_definitions_tx(&transaction, &plan)?;
        let body_json = serde_json::to_string(&plan).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO chisei_evaluation_plans
                 (plan_version_id, namespace, plan_id, version, content_digest, body_json, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    plan.plan_version_id,
                    plan.namespace,
                    plan.plan_id,
                    plan.version,
                    plan.content_digest,
                    body_json,
                    plan.created_at_ms,
                ],
            )
            .map_err(map_plan_insert_error)?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(plan)
    }

    pub fn get_evaluation_plan(
        &self,
        plan_version_id: &str,
    ) -> Result<Option<EvaluationPlan>, String> {
        let connection = self.conn();
        get_plan_connection(&connection, plan_version_id)
    }

    pub fn list_evaluation_plans(
        &self,
        namespace: &str,
        plan_id: Option<&str>,
    ) -> Result<Vec<EvaluationPlan>, String> {
        let connection = self.conn();
        let mut plans = Vec::new();
        if let Some(plan_id) = plan_id {
            let mut statement = connection
                .prepare(
                    "SELECT body_json FROM chisei_evaluation_plans
                 WHERE namespace=?1 AND plan_id=?2 ORDER BY plan_id, version",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map(params![namespace, plan_id], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            for row in rows {
                plans.push(decode_plan(&row.map_err(|error| error.to_string())?)?);
            }
        } else {
            let mut statement = connection
                .prepare(
                    "SELECT body_json FROM chisei_evaluation_plans
                 WHERE namespace=?1 ORDER BY plan_id, version",
                )
                .map_err(|error| error.to_string())?;
            let rows = statement
                .query_map(params![namespace], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            for row in rows {
                plans.push(decode_plan(&row.map_err(|error| error.to_string())?)?);
            }
        }
        Ok(plans)
    }
}

fn get_definition_connection(
    connection: &rusqlite::Connection,
    definition_id: &str,
) -> Result<Option<EvaluatorDefinition>, String> {
    connection
        .query_row(
            "SELECT body_json FROM chisei_evaluator_definitions WHERE definition_id=?1",
            params![definition_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|body| decode_definition(&body))
        .transpose()
}

fn get_definition_tx(
    transaction: &Transaction<'_>,
    definition_id: &str,
) -> Result<Option<EvaluatorDefinition>, String> {
    transaction
        .query_row(
            "SELECT body_json FROM chisei_evaluator_definitions WHERE definition_id=?1",
            params![definition_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|body| decode_definition(&body))
        .transpose()
}

fn get_plan_connection(
    connection: &rusqlite::Connection,
    plan_version_id: &str,
) -> Result<Option<EvaluationPlan>, String> {
    connection
        .query_row(
            "SELECT body_json FROM chisei_evaluation_plans WHERE plan_version_id=?1",
            params![plan_version_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|body| decode_plan(&body))
        .transpose()
}

fn get_plan_tx(
    transaction: &Transaction<'_>,
    plan_version_id: &str,
) -> Result<Option<EvaluationPlan>, String> {
    transaction
        .query_row(
            "SELECT body_json FROM chisei_evaluation_plans WHERE plan_version_id=?1",
            params![plan_version_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|body| decode_plan(&body))
        .transpose()
}

fn get_availability_event_tx(
    transaction: &Transaction<'_>,
    definition_id: &str,
    request_id: &str,
) -> Result<Option<EvaluatorAvailability>, String> {
    transaction
        .query_row(
            "SELECT body_json FROM chisei_evaluator_availability_events
             WHERE definition_id=?1 AND request_id=?2",
            params![definition_id, request_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|body| decode_availability(&body))
        .transpose()
}

fn require_enabled_plan_definitions_tx(
    transaction: &Transaction<'_>,
    plan: &EvaluationPlan,
) -> Result<(), String> {
    let mut definitions = std::collections::BTreeMap::new();
    for node in &plan.nodes {
        let definition_id = node.evaluator_definition_id.as_str();
        if let Some(definition) = definitions.get(definition_id) {
            require_stochastic_gate_eligibility(node, definition)?;
            continue;
        }
        let row = transaction
            .query_row(
                "SELECT d.namespace, a.state, d.body_json
                 FROM chisei_evaluator_definitions d
                 JOIN chisei_evaluator_availability a
                   ON a.definition_id=d.definition_id
                 WHERE d.definition_id=?1",
                params![definition_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "unknown evaluator definition".to_string())?;
        if row.0 != plan.namespace {
            return Err("evaluator definition is in a different namespace".into());
        }
        if row.1 != AVAILABILITY_ENABLED {
            return Err("evaluator definition is unavailable for new plans".into());
        }
        let definition = decode_definition(&row.2)?;
        require_stochastic_gate_eligibility(node, &definition)?;
        definitions.insert(definition_id, definition);
    }
    Ok(())
}

fn require_stochastic_gate_eligibility(
    node: &crate::chisei::evaluation_plan::EvaluationPlanNode,
    definition: &EvaluatorDefinition,
) -> Result<(), String> {
    if node.classification == crate::chisei::evaluation_plan::NODE_REQUIRED
        && definition.execution_class == crate::chisei::evaluation_plan::STOCHASTIC_EXECUTION_CLASS
        && !definition
            .stochastic_policy
            .as_ref()
            .is_some_and(|policy| policy.gate_eligible)
    {
        return Err(
            "required stochastic node needs an evaluator with explicit gate eligibility".into(),
        );
    }
    Ok(())
}

fn insert_availability_event_tx(
    transaction: &Transaction<'_>,
    availability: &EvaluatorAvailability,
) -> Result<(), String> {
    let body_json = serde_json::to_string(availability).map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO chisei_evaluator_availability_events
             (definition_id, request_id, request_digest, body_json, changed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                availability.definition_id,
                availability.request_id,
                availability.request_digest,
                body_json,
                availability.changed_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO chisei_evaluator_availability
             (definition_id, state, body_json, changed_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(definition_id) DO UPDATE SET
                state=excluded.state,
                body_json=excluded.body_json,
                changed_at_ms=excluded.changed_at_ms",
            params![
                availability.definition_id,
                availability.state,
                body_json,
                availability.changed_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn immutable_definition_replay(
    existing: EvaluatorDefinition,
    candidate: &EvaluatorDefinition,
) -> Result<EvaluatorDefinition, String> {
    if existing.content_digest == candidate.content_digest {
        Ok(existing)
    } else {
        Err("evaluator definition version already exists with different content".into())
    }
}

fn immutable_plan_replay(
    existing: EvaluationPlan,
    candidate: &EvaluationPlan,
) -> Result<EvaluationPlan, String> {
    if existing.content_digest == candidate.content_digest {
        Ok(existing)
    } else {
        Err("evaluation plan version already exists with different content".into())
    }
}

fn availability_replay(
    existing: EvaluatorAvailability,
    candidate: &EvaluatorAvailability,
) -> Result<EvaluatorAvailability, String> {
    if existing.request_digest == candidate.request_digest {
        Ok(existing)
    } else {
        Err("availability request_id already exists with different content".into())
    }
}

fn decode_definition(body: &str) -> Result<EvaluatorDefinition, String> {
    serde_json::from_str(body).map_err(|error| format!("corrupt evaluator definition: {error}"))
}

fn decode_availability(body: &str) -> Result<EvaluatorAvailability, String> {
    serde_json::from_str(body).map_err(|error| format!("corrupt evaluator availability: {error}"))
}

fn decode_plan(body: &str) -> Result<EvaluationPlan, String> {
    serde_json::from_str(body).map_err(|error| format!("corrupt evaluation plan: {error}"))
}

fn map_definition_insert_error(error: rusqlite::Error) -> String {
    if error.to_string().contains("UNIQUE constraint failed") {
        "evaluator definition version already exists with different content".into()
    } else {
        error.to_string()
    }
}

fn map_plan_insert_error(error: rusqlite::Error) -> String {
    if error.to_string().contains("UNIQUE constraint failed") {
        "evaluation plan version already exists with different content".into()
    } else {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_plan::*;

    fn definition() -> EvaluatorDefinition {
        EvaluatorDefinition {
            contract_version: EVALUATOR_DEFINITION_CONTRACT.into(),
            definition_id: String::new(),
            namespace: "acme".into(),
            evaluator_id: "schema-check".into(),
            version: "1".into(),
            implementation_digest: format!("sha256:{}", "a".repeat(64)),
            execution_class: DETERMINISTIC_EXECUTION_CLASS.into(),
            supported_predicate_kinds: vec!["schema_conforms".into()],
            supported_input_schemas: vec!["schema://document/v1".into()],
            supported_result_schemas: vec!["schema://pass-fail/v1".into()],
            parameter_schema_json:
                r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#
                    .into(),
            evidence_classifications: vec!["public".into()],
            resource_limits: EvaluatorResourceLimits {
                timeout_ms: 100,
                max_input_bytes: 100,
                max_output_bytes: 100,
                max_evidence_items: 1,
            },
            stochastic_policy: None,
            source_ref: "repo://schema-check".into(),
            content_digest: String::new(),
            created_by: String::new(),
            created_at_ms: 0,
        }
    }

    #[test]
    fn definitions_are_immutable_and_availability_is_audited_idempotently() {
        let db = SekaiDb::new(":memory:").unwrap();
        let stored = db
            .put_evaluator_definition(definition(), "operator", 10)
            .unwrap();
        assert_eq!(
            db.get_evaluator_availability(&stored.definition_id)
                .unwrap()
                .unwrap()
                .state,
            AVAILABILITY_ENABLED
        );
        let disabled = db
            .set_evaluator_availability(
                &stored.definition_id,
                AVAILABILITY_DISABLED,
                "",
                "maintenance",
                "request-1",
                "operator",
                20,
            )
            .unwrap();
        let replay = db
            .set_evaluator_availability(
                &stored.definition_id,
                AVAILABILITY_DISABLED,
                "",
                "maintenance",
                "request-1",
                "other",
                30,
            )
            .unwrap();
        assert_eq!(disabled, replay);
        assert_eq!(
            db.list_evaluator_definitions("acme", None).unwrap().len(),
            1
        );

        let mut changed = definition();
        changed.source_ref = "repo://different".into();
        assert!(
            db.put_evaluator_definition(changed, "operator", 30)
                .unwrap_err()
                .contains("different content")
        );
    }
}
