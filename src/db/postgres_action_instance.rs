//! PostgreSQL ActionInstance store (#397).

use crate::db::postgres::PostgresDb;
use crate::sekai::action_instance::ActionInstance;

impl PostgresDb {
    pub fn get_action_instance_by_idempotency(
        &self,
        namespace: &str,
        idempotency_key: &str,
    ) -> Result<Option<ActionInstance>, String> {
        self.connection()?
            .query_opt(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1 AND idempotency_key = $2",
                &[&namespace, &idempotency_key],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action instance body: {e}"))
            })
            .transpose()
    }

    pub fn get_action_instance_by_operation_id(
        &self,
        operation_id: &str,
    ) -> Result<Option<ActionInstance>, String> {
        if operation_id.trim().is_empty() {
            return Ok(None);
        }
        self.connection()?
            .query_opt(
                "SELECT body_json FROM sekai_action_instances WHERE operation_id = $1",
                &[&operation_id],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action instance body: {e}"))
            })
            .transpose()
    }

    pub fn get_action_instance(&self, instance_id: &str) -> Result<Option<ActionInstance>, String> {
        self.connection()?
            .query_opt(
                "SELECT body_json FROM sekai_action_instances WHERE instance_id = $1",
                &[&instance_id],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action instance body: {e}"))
            })
            .transpose()
    }

    pub fn list_action_instances(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ActionInstance>, String> {
        let limit = limit.clamp(1, 500) as i64;
        let type_filter = type_id.filter(|t| !t.trim().is_empty());
        let status_filter = status.filter(|s| !s.trim().is_empty());
        let rows = match (type_filter, status_filter) {
            (Some(type_id), Some(status)) => self.connection()?.query(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1 AND type_id = $2 AND status = $3
                 ORDER BY created_at_ms DESC LIMIT $4",
                &[&namespace, &type_id, &status, &limit],
            ),
            (Some(type_id), None) => self.connection()?.query(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1 AND type_id = $2
                 ORDER BY created_at_ms DESC LIMIT $3",
                &[&namespace, &type_id, &limit],
            ),
            (None, Some(status)) => self.connection()?.query(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1 AND status = $2
                 ORDER BY created_at_ms DESC LIMIT $3",
                &[&namespace, &status, &limit],
            ),
            (None, None) => self.connection()?.query(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1
                 ORDER BY created_at_ms DESC LIMIT $2",
                &[&namespace, &limit],
            ),
        }
        .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body: String = row.get(0);
            out.push(
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action instance body: {e}"))?,
            );
        }
        Ok(out)
    }

    pub fn put_action_instance(&self, instance: &ActionInstance) -> Result<ActionInstance, String> {
        instance.validate_fields()?;
        if let Some(existing) =
            self.get_action_instance_by_idempotency(&instance.namespace, &instance.idempotency_key)?
        {
            if existing.request_digest == instance.request_digest {
                return Ok(existing);
            }
            return Err("idempotency key conflict: same key with different request digest".into());
        }
        let body_json = serde_json::to_string(instance).map_err(|e| e.to_string())?;
        let evidence_json =
            serde_json::to_string(&instance.evidence_submission_ids).map_err(|e| e.to_string())?;
        let result = self.connection()?.execute(
            "INSERT INTO sekai_action_instances
             (instance_id, namespace, type_id, version, principal, parameters_json,
              request_digest, idempotency_key, operation_id, status, deny_reason,
              evidence_submission_ids_json, policy_decision, budget_decision,
              created_at_ms, decided_at_ms, body_json)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
             ON CONFLICT (namespace, idempotency_key) DO NOTHING",
            &[
                &instance.instance_id,
                &instance.namespace,
                &instance.type_id,
                &instance.version,
                &instance.principal,
                &instance.parameters_json,
                &instance.request_digest,
                &instance.idempotency_key,
                &instance.operation_id,
                &instance.status,
                &instance.deny_reason,
                &evidence_json,
                &instance.policy_decision,
                &instance.budget_decision,
                &instance.created_at_ms,
                &instance.decided_at_ms,
                &body_json,
            ],
        );
        match result {
            Ok(0) => {
                if let Some(existing) = self.get_action_instance_by_idempotency(
                    &instance.namespace,
                    &instance.idempotency_key,
                )? {
                    if existing.request_digest == instance.request_digest {
                        return Ok(existing);
                    }
                    return Err(
                        "idempotency key conflict: same key with different request digest".into(),
                    );
                }
                Err("idempotency key conflict".into())
            }
            Ok(_) => Ok(instance.clone()),
            Err(e) => Err(e.to_string()),
        }
    }
}
