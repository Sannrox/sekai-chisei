//! PostgreSQL persistence for immutable evaluation plans and evaluator definitions.

use crate::chisei::evaluation_plan::{
    AVAILABILITY_ENABLED, EvaluationPlan, EvaluatorAvailability, EvaluatorDefinition,
    prepare_availability, prepare_definition, prepare_plan,
};
use crate::db::postgres::PostgresDb;
use postgres::{GenericClient, Transaction};

impl PostgresDb {
    pub fn put_evaluator_definition(
        &self,
        definition: EvaluatorDefinition,
        actor: &str,
        now_ms: i64,
    ) -> Result<EvaluatorDefinition, String> {
        let definition = prepare_definition(definition, actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 465))",
                &[&definition.definition_id],
            )
            .map_err(|error| error.to_string())?;
        if let Some(existing) = get_definition(&mut transaction, &definition.definition_id)? {
            return immutable_definition_replay(existing, &definition);
        }
        let body_json = serde_json::to_string(&definition).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO chisei_evaluator_definitions
                 (definition_id, namespace, evaluator_id, version, implementation_digest,
                  content_digest, body_json, created_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
                &[
                    &definition.definition_id,
                    &definition.namespace,
                    &definition.evaluator_id,
                    &definition.version,
                    &definition.implementation_digest,
                    &definition.content_digest,
                    &body_json,
                    &definition.created_at_ms,
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
        insert_availability_event(&mut transaction, &initial)?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(definition)
    }

    pub fn get_evaluator_definition(
        &self,
        definition_id: &str,
    ) -> Result<Option<EvaluatorDefinition>, String> {
        let mut connection = self.connection()?;
        get_definition(&mut *connection, definition_id)
    }

    pub fn list_evaluator_definitions(
        &self,
        namespace: &str,
        evaluator_id: Option<&str>,
    ) -> Result<Vec<EvaluatorDefinition>, String> {
        let rows = if let Some(evaluator_id) = evaluator_id {
            self.connection()?.query(
                "SELECT body_json FROM chisei_evaluator_definitions
                 WHERE namespace=$1 AND evaluator_id=$2 ORDER BY evaluator_id, version",
                &[&namespace, &evaluator_id],
            )
        } else {
            self.connection()?.query(
                "SELECT body_json FROM chisei_evaluator_definitions
                 WHERE namespace=$1 ORDER BY evaluator_id, version",
                &[&namespace],
            )
        }
        .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| decode_definition(row.get(0)))
            .collect()
    }

    pub fn get_evaluator_availability(
        &self,
        definition_id: &str,
    ) -> Result<Option<EvaluatorAvailability>, String> {
        self.connection()?
            .query_opt(
                "SELECT body_json FROM chisei_evaluator_availability WHERE definition_id=$1",
                &[&definition_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| decode_availability(row.get(0)))
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
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 465))",
                &[&definition_id],
            )
            .map_err(|error| error.to_string())?;
        let definition = get_definition(&mut transaction, definition_id)?
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
        if let Some(existing) = get_availability_event(&mut transaction, definition_id, request_id)?
        {
            return availability_replay(existing, &availability);
        }
        if !superseded_by_definition_id.is_empty() {
            let successor = get_definition(&mut transaction, superseded_by_definition_id)?
                .ok_or_else(|| "superseding evaluator definition not found".to_string())?;
            if successor.namespace != definition.namespace {
                return Err(
                    "superseding evaluator definition must be in the same namespace".into(),
                );
            }
        }
        insert_availability_event(&mut transaction, &availability)?;
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
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 465))",
                &[&plan.plan_version_id],
            )
            .map_err(|error| error.to_string())?;
        if let Some(existing) = get_plan(&mut transaction, &plan.plan_version_id)? {
            return immutable_plan_replay(existing, &plan);
        }
        require_enabled_plan_definitions(&mut transaction, &plan)?;
        let body_json = serde_json::to_string(&plan).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO chisei_evaluation_plans
                 (plan_version_id, namespace, plan_id, version, content_digest, body_json, created_at_ms)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &plan.plan_version_id,
                    &plan.namespace,
                    &plan.plan_id,
                    &plan.version,
                    &plan.content_digest,
                    &body_json,
                    &plan.created_at_ms,
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
        let mut connection = self.connection()?;
        get_plan(&mut *connection, plan_version_id)
    }

    pub fn list_evaluation_plans(
        &self,
        namespace: &str,
        plan_id: Option<&str>,
    ) -> Result<Vec<EvaluationPlan>, String> {
        let rows = if let Some(plan_id) = plan_id {
            self.connection()?.query(
                "SELECT body_json FROM chisei_evaluation_plans
                 WHERE namespace=$1 AND plan_id=$2 ORDER BY plan_id, version",
                &[&namespace, &plan_id],
            )
        } else {
            self.connection()?.query(
                "SELECT body_json FROM chisei_evaluation_plans
                 WHERE namespace=$1 ORDER BY plan_id, version",
                &[&namespace],
            )
        }
        .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| decode_plan(row.get(0)))
            .collect()
    }
}

fn get_definition(
    client: &mut impl GenericClient,
    definition_id: &str,
) -> Result<Option<EvaluatorDefinition>, String> {
    client
        .query_opt(
            "SELECT body_json FROM chisei_evaluator_definitions WHERE definition_id=$1",
            &[&definition_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| decode_definition(row.get(0)))
        .transpose()
}

fn get_plan(
    client: &mut impl GenericClient,
    plan_version_id: &str,
) -> Result<Option<EvaluationPlan>, String> {
    client
        .query_opt(
            "SELECT body_json FROM chisei_evaluation_plans WHERE plan_version_id=$1",
            &[&plan_version_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| decode_plan(row.get(0)))
        .transpose()
}

fn get_availability_event(
    client: &mut impl GenericClient,
    definition_id: &str,
    request_id: &str,
) -> Result<Option<EvaluatorAvailability>, String> {
    client
        .query_opt(
            "SELECT body_json FROM chisei_evaluator_availability_events
             WHERE definition_id=$1 AND request_id=$2",
            &[&definition_id, &request_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| decode_availability(row.get(0)))
        .transpose()
}

fn require_enabled_plan_definitions(
    transaction: &mut Transaction<'_>,
    plan: &EvaluationPlan,
) -> Result<(), String> {
    let definition_ids = plan
        .nodes
        .iter()
        .map(|node| node.evaluator_definition_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for definition_id in definition_ids {
        let row = transaction
            .query_opt(
                "SELECT d.namespace, a.state
                 FROM chisei_evaluator_definitions d
                 JOIN chisei_evaluator_availability a
                   ON a.definition_id=d.definition_id
                 WHERE d.definition_id=$1
                 FOR SHARE OF a",
                &[&definition_id],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "unknown evaluator definition".to_string())?;
        let namespace: String = row.get(0);
        let state: String = row.get(1);
        if namespace != plan.namespace {
            return Err("evaluator definition is in a different namespace".into());
        }
        if state != AVAILABILITY_ENABLED {
            return Err("evaluator definition is unavailable for new plans".into());
        }
    }
    Ok(())
}

fn insert_availability_event(
    transaction: &mut Transaction<'_>,
    availability: &EvaluatorAvailability,
) -> Result<(), String> {
    let body_json = serde_json::to_string(availability).map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO chisei_evaluator_availability_events
             (definition_id, request_id, request_digest, body_json, changed_at_ms)
             VALUES ($1,$2,$3,$4,$5)",
            &[
                &availability.definition_id,
                &availability.request_id,
                &availability.request_digest,
                &body_json,
                &availability.changed_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO chisei_evaluator_availability
             (definition_id, state, body_json, changed_at_ms)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT(definition_id) DO UPDATE SET
                state=excluded.state,
                body_json=excluded.body_json,
                changed_at_ms=excluded.changed_at_ms",
            &[
                &availability.definition_id,
                &availability.state,
                &body_json,
                &availability.changed_at_ms,
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

fn map_definition_insert_error(error: postgres::Error) -> String {
    if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
        "evaluator definition version already exists with different content".into()
    } else {
        error.to_string()
    }
}

fn map_plan_insert_error(error: postgres::Error) -> String {
    if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
        "evaluation plan version already exists with different content".into()
    } else {
        error.to_string()
    }
}
