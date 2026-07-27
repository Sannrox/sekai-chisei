//! Governed ActionInstance admission (#397 / research #395).
//!
//! Thin durable decision envelope: type + parameters + idempotency →
//! admit/deny with bound `operation_id`. Not graph `ExecuteAction`.
//! Effects materialization is #398.

use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STATUS_ADMITTED: &str = "admitted";
pub const STATUS_DENIED: &str = "denied";

/// Policy action name used when resolving ActionPolicy for submits.
pub const SUBMIT_POLICY_ACTION: &str = "submit_action_instance";

/// Budget root for hierarchical action-class metering of submits.
pub const SUBMIT_BUDGET_ROOT: &str = "action:governed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionInstance {
    pub instance_id: String,
    pub namespace: String,
    pub type_id: String,
    pub version: String,
    pub principal: String,
    /// JSON object. Untrusted user/producer content — never treated as instructions.
    pub parameters_json: String,
    pub request_digest: String,
    pub idempotency_key: String,
    /// Bound operation correlation spine for receipts/harvest (#400).
    pub operation_id: String,
    /// `admitted` or `denied`.
    pub status: String,
    pub deny_reason: String,
    pub evidence_submission_ids: Vec<String>,
    pub policy_decision: String,
    pub budget_decision: String,
    pub created_at_ms: i64,
    pub decided_at_ms: i64,
}

impl ActionInstance {
    pub fn validate_fields(&self) -> Result<(), String> {
        if self.namespace.trim().is_empty() {
            return Err("namespace required".into());
        }
        if self.type_id.trim().is_empty() {
            return Err("type_id required".into());
        }
        if self.version.trim().is_empty() {
            return Err("version required".into());
        }
        if self.idempotency_key.trim().is_empty() {
            return Err("idempotency_key required".into());
        }
        if self.idempotency_key.chars().any(char::is_whitespace) {
            return Err("idempotency_key must not contain whitespace".into());
        }
        validate_parameters_json(&self.parameters_json)?;
        if self.status != STATUS_ADMITTED && self.status != STATUS_DENIED {
            return Err(format!("invalid status {:?}", self.status));
        }
        Ok(())
    }
}

/// Canonical digest of the decision-relevant request body.
/// Bound to the idempotency key: same key + different digest is a conflict.
pub fn compute_request_digest(
    namespace: &str,
    type_id: &str,
    version: &str,
    parameters_json: &str,
    evidence_submission_ids: &[String],
) -> Result<String, String> {
    let params: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|e| format!("parameters_json must be JSON: {e}"))?;
    if !params.is_object() {
        return Err("parameters_json must be a JSON object".into());
    }
    let mut evidence = evidence_submission_ids.to_vec();
    evidence.sort();
    evidence.dedup();
    let body = serde_json::json!({
        "namespace": namespace,
        "type_id": type_id,
        "version": version,
        "parameters": params,
        "evidence_submission_ids": evidence,
    });
    let canonical = serde_json::to_string(&body).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn validate_parameters_json(parameters_json: &str) -> Result<(), String> {
    let params: serde_json::Value = serde_json::from_str(parameters_json)
        .map_err(|e| format!("parameters_json must be JSON: {e}"))?;
    if !params.is_object() {
        return Err("parameters_json must be a JSON object".into());
    }
    Ok(())
}

/// Hierarchical budget subject for governed ActionInstance submit.
/// Empty `budget_scope` uses the namespace default root; non-empty scopes pin a
/// dedicated leaf under the governed root.
pub fn submit_budget_subject(namespace: &str, actor: &str, budget_scope: &str) -> String {
    let root = if budget_scope.trim().is_empty() {
        SUBMIT_BUDGET_ROOT.to_string()
    } else {
        format!("{SUBMIT_BUDGET_ROOT}:{}", budget_scope.trim())
    };
    if namespace.trim().is_empty() {
        return root;
    }
    if actor.trim().is_empty() {
        return format!("{root}/project:{}", namespace.trim());
    }
    format!("{root}/project:{}/agent:{}", namespace.trim(), actor.trim())
}

impl SekaiDb {
    pub fn migrate_action_instances(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sekai_action_instances (
                instance_id TEXT PRIMARY KEY,
                namespace TEXT NOT NULL,
                type_id TEXT NOT NULL,
                version TEXT NOT NULL,
                principal TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                status TEXT NOT NULL,
                deny_reason TEXT NOT NULL DEFAULT '',
                evidence_submission_ids_json TEXT NOT NULL,
                policy_decision TEXT NOT NULL DEFAULT '',
                budget_decision TEXT NOT NULL DEFAULT '',
                created_at_ms INTEGER NOT NULL,
                decided_at_ms INTEGER NOT NULL,
                body_json TEXT NOT NULL,
                UNIQUE (namespace, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS idx_action_instances_ns
                ON sekai_action_instances(namespace, created_at_ms DESC);
            CREATE INDEX IF NOT EXISTS idx_action_instances_op
                ON sekai_action_instances(operation_id);
            CREATE INDEX IF NOT EXISTS idx_action_instances_type
                ON sekai_action_instances(namespace, type_id, version);",
        )
        .map_err(|e| e.to_string())
    }

    pub fn get_action_instance_by_idempotency(
        &self,
        namespace: &str,
        idempotency_key: &str,
    ) -> Result<Option<ActionInstance>, String> {
        self.migrate_action_instances()?;
        let conn = self.conn();
        conn.query_row(
            "SELECT body_json FROM sekai_action_instances
             WHERE namespace = ?1 AND idempotency_key = ?2",
            params![namespace, idempotency_key],
            |row| {
                let body: String = row.get(0)?;
                Ok(body)
            },
        )
        .optional()
        .map_err(|e| e.to_string())?
        .map(|body| {
            serde_json::from_str(&body).map_err(|e| format!("corrupt action instance body: {e}"))
        })
        .transpose()
    }

    pub fn get_action_instance(&self, instance_id: &str) -> Result<Option<ActionInstance>, String> {
        self.migrate_action_instances()?;
        let conn = self.conn();
        conn.query_row(
            "SELECT body_json FROM sekai_action_instances WHERE instance_id = ?1",
            params![instance_id],
            |row| {
                let body: String = row.get(0)?;
                Ok(body)
            },
        )
        .optional()
        .map_err(|e| e.to_string())?
        .map(|body| {
            serde_json::from_str(&body).map_err(|e| format!("corrupt action instance body: {e}"))
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
        self.migrate_action_instances()?;
        let limit = limit.clamp(1, 500);
        let type_filter = type_id.filter(|t| !t.trim().is_empty());
        let status_filter = status.filter(|s| !s.trim().is_empty());
        let conn = self.conn();
        let mut bodies: Vec<String> = Vec::new();
        match (type_filter, status_filter) {
            (Some(type_id), Some(status)) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body_json FROM sekai_action_instances
                         WHERE namespace = ?1 AND type_id = ?2 AND status = ?3
                         ORDER BY created_at_ms DESC LIMIT ?4",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![namespace, type_id, status, limit as i64], |row| {
                        row.get(0)
                    })
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    bodies.push(row.map_err(|e| e.to_string())?);
                }
            }
            (Some(type_id), None) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body_json FROM sekai_action_instances
                         WHERE namespace = ?1 AND type_id = ?2
                         ORDER BY created_at_ms DESC LIMIT ?3",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![namespace, type_id, limit as i64], |row| row.get(0))
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    bodies.push(row.map_err(|e| e.to_string())?);
                }
            }
            (None, Some(status)) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body_json FROM sekai_action_instances
                         WHERE namespace = ?1 AND status = ?2
                         ORDER BY created_at_ms DESC LIMIT ?3",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![namespace, status, limit as i64], |row| row.get(0))
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    bodies.push(row.map_err(|e| e.to_string())?);
                }
            }
            (None, None) => {
                let mut stmt = conn
                    .prepare(
                        "SELECT body_json FROM sekai_action_instances
                         WHERE namespace = ?1
                         ORDER BY created_at_ms DESC LIMIT ?2",
                    )
                    .map_err(|e| e.to_string())?;
                let rows = stmt
                    .query_map(params![namespace, limit as i64], |row| row.get(0))
                    .map_err(|e| e.to_string())?;
                for row in rows {
                    bodies.push(row.map_err(|e| e.to_string())?);
                }
            }
        }
        bodies
            .into_iter()
            .map(|body| {
                serde_json::from_str(&body)
                    .map_err(|e| format!("corrupt action instance body: {e}"))
            })
            .collect()
    }

    /// Insert a newly decided instance. Caller must already have checked
    /// idempotency. Returns conflict if the unique key races.
    pub fn put_action_instance(&self, instance: &ActionInstance) -> Result<ActionInstance, String> {
        self.migrate_action_instances()?;
        instance.validate_fields()?;
        // Avoid holding conn across a re-get on race.
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
        let conn = self.conn();
        match conn.execute(
            "INSERT INTO sekai_action_instances
             (instance_id, namespace, type_id, version, principal, parameters_json,
              request_digest, idempotency_key, operation_id, status, deny_reason,
              evidence_submission_ids_json, policy_decision, budget_decision,
              created_at_ms, decided_at_ms, body_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                instance.instance_id,
                instance.namespace,
                instance.type_id,
                instance.version,
                instance.principal,
                instance.parameters_json,
                instance.request_digest,
                instance.idempotency_key,
                instance.operation_id,
                instance.status,
                instance.deny_reason,
                evidence_json,
                instance.policy_decision,
                instance.budget_decision,
                instance.created_at_ms,
                instance.decided_at_ms,
                body_json,
            ],
        ) {
            Ok(_) => Ok(instance.clone()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                // Race: re-read and apply digest rules.
                drop(conn);
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
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: &str) -> ActionInstance {
        ActionInstance {
            instance_id: "ai-1".into(),
            namespace: "acme".into(),
            type_id: "review.intake".into(),
            version: "1.0.0".into(),
            principal: "tester".into(),
            parameters_json: r#"{"summary":"hello"}"#.into(),
            request_digest: compute_request_digest(
                "acme",
                "review.intake",
                "1.0.0",
                r#"{"summary":"hello"}"#,
                &[],
            )
            .unwrap(),
            idempotency_key: "key-1".into(),
            operation_id: "op-1".into(),
            status: status.into(),
            deny_reason: String::new(),
            evidence_submission_ids: vec![],
            policy_decision: "allow".into(),
            budget_decision: "allow".into(),
            created_at_ms: 10,
            decided_at_ms: 10,
        }
    }

    #[test]
    fn digest_is_stable_and_order_insensitive_for_evidence() {
        let a = compute_request_digest(
            "acme",
            "t",
            "1",
            r#"{"a":1,"b":2}"#,
            &["e2".into(), "e1".into()],
        )
        .unwrap();
        let b = compute_request_digest(
            "acme",
            "t",
            "1",
            r#"{"a":1,"b":2}"#,
            &["e1".into(), "e2".into()],
        )
        .unwrap();
        assert_eq!(a, b);
        let c = compute_request_digest("acme", "t", "1", r#"{"a":1,"b":3}"#, &[]).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn put_get_list_and_idempotent_replay() {
        let db = SekaiDb::new(":memory:").unwrap();
        let put = db.put_action_instance(&sample(STATUS_ADMITTED)).unwrap();
        assert_eq!(put.instance_id, "ai-1");
        let got = db.get_action_instance("ai-1").unwrap().unwrap();
        assert_eq!(got.status, STATUS_ADMITTED);

        let replay = db.put_action_instance(&sample(STATUS_ADMITTED)).unwrap();
        assert_eq!(replay.instance_id, "ai-1");

        let mut conflict = sample(STATUS_ADMITTED);
        conflict.instance_id = "ai-2".into();
        conflict.parameters_json = r#"{"summary":"other"}"#.into();
        conflict.request_digest = compute_request_digest(
            "acme",
            "review.intake",
            "1.0.0",
            r#"{"summary":"other"}"#,
            &[],
        )
        .unwrap();
        let err = db.put_action_instance(&conflict).unwrap_err();
        assert!(err.contains("conflict"), "{err}");

        let listed = db
            .list_action_instances("acme", Some("review.intake"), None, 10)
            .unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn budget_subject_hierarchy() {
        assert_eq!(
            submit_budget_subject("acme", "tester", ""),
            "action:governed/project:acme/agent:tester"
        );
        assert_eq!(
            submit_budget_subject("acme", "tester", "reviews"),
            "action:governed:reviews/project:acme/agent:tester"
        );
    }
}
