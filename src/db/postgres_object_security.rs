use std::collections::BTreeMap;

use postgres::{GenericClient, Transaction};
use uuid::Uuid;

use crate::db::object_security::{cursor_key_from_secret, mapping_digest, predicate_columns};
use crate::db::postgres::PostgresDb;
use crate::sekai::object_security::{
    ObjectSecurityActivation, ObjectSecurityPolicy, ObjectSecurityPolicyRevision,
};

impl PostgresDb {
    pub fn put_object_security_policy(
        &self,
        policy: &ObjectSecurityPolicy,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityPolicyRevision, String> {
        validate_write(actor, idempotency_key, now_ms)?;
        let policy = policy.clone().prepare()?;
        let canonical = policy.canonical_bytes()?;
        let digest = policy.revision_digest()?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_request(&mut tx, &policy.namespace, actor, idempotency_key)?;
        if let Some(result) = replay(
            &mut tx,
            &policy.namespace,
            actor,
            "put",
            idempotency_key,
            &digest,
        )? {
            return serde_json::from_str(&result).map_err(|error| error.to_string());
        }
        lock_revision(&mut tx, &policy.namespace, &digest)?;
        if let Some(existing) = load_revision(&mut tx, &policy.namespace, &digest)? {
            if existing.canonical_policy_json != canonical {
                return Err("object_security_conflict: revision digest collision".into());
            }
            persist_request(
                &mut tx,
                &policy.namespace,
                actor,
                "put",
                idempotency_key,
                &digest,
                &existing,
                now_ms,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(existing);
        }
        let revision = ObjectSecurityPolicyRevision {
            namespace: policy.namespace.clone(),
            kind: policy.kind.clone(),
            revision_digest: digest.clone(),
            canonical_policy_json: canonical,
            created_by: actor.into(),
            created_at_ms: now_ms,
        };
        insert_revision(&mut tx, &revision, &policy)?;
        persist_request(
            &mut tx,
            &policy.namespace,
            actor,
            "put",
            idempotency_key,
            &digest,
            &revision,
            now_ms,
        )?;
        tx.execute(
            "INSERT INTO sekai_object_security_audit
             (event_id, namespace, actor, action, revision_digest, policy_count, reason_code, created_at_ms)
             VALUES ($1, $2, $3, 'put_revision', $4, 1, 'stored', $5)",
            &[&Uuid::new_v4().to_string(), &policy.namespace, &actor, &digest, &now_ms],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(revision)
    }

    pub fn get_object_security_policy(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRevision>, String> {
        load_revision(&mut *self.connection()?, namespace, revision_digest)
    }

    pub fn activate_object_security_policies(
        &self,
        namespace: &str,
        policies: &BTreeMap<String, String>,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityActivation, String> {
        validate_write(actor, idempotency_key, now_ms)?;
        if namespace.is_empty() || policies.is_empty() {
            return Err(
                "object_security_activation_incomplete: namespace and policies required".into(),
            );
        }
        let request_digest = mapping_digest(namespace, policies);
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.query_one("SELECT pg_advisory_xact_lock(hashtext($1))", &[&namespace])
            .map_err(|error| error.to_string())?;
        lock_request(&mut tx, namespace, actor, idempotency_key)?;
        if let Some(result) = replay(
            &mut tx,
            namespace,
            actor,
            "activate",
            idempotency_key,
            &request_digest,
        )? {
            return serde_json::from_str(&result).map_err(|error| error.to_string());
        }
        let instantiated = tx
            .query(
                "SELECT DISTINCT kind FROM sekai_objects WHERE namespace=$1 ORDER BY kind",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
        if instantiated.len() != policies.len()
            || instantiated.iter().any(|kind| !policies.contains_key(kind))
        {
            return Err(
                "object_security_activation_incomplete: every instantiated kind requires exactly one revision"
                    .into(),
            );
        }
        for (kind, digest) in policies {
            let revision = load_revision(&mut tx, namespace, digest)?.ok_or_else(|| {
                "object_security_policy_not_found: activation revision unavailable".to_string()
            })?;
            if revision.kind != *kind
                || ObjectSecurityPolicy::from_canonical_input(&revision.canonical_policy_json)
                    .is_err()
            {
                return Err(
                    "object_security_policy_invalid: activation revision is invalid".into(),
                );
            }
        }
        let activation = ObjectSecurityActivation {
            namespace: namespace.into(),
            activation_id: request_digest.clone(),
            policies: policies.clone(),
            activated_by: actor.into(),
            activated_at_ms: now_ms,
        };
        tx.execute(
            "INSERT INTO sekai_object_security_activations
             (namespace, activation_id, activated_by, activated_at_ms)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(namespace) DO UPDATE SET activation_id=excluded.activation_id,
                 activated_by=excluded.activated_by, activated_at_ms=excluded.activated_at_ms",
            &[&namespace, &request_digest, &actor, &now_ms],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_object_security_active_policies WHERE namespace=$1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
        for (kind, digest) in policies {
            tx.execute(
                "INSERT INTO sekai_object_security_active_policies
                 (namespace, kind, revision_digest) VALUES ($1, $2, $3)",
                &[&namespace, &kind, &digest],
            )
            .map_err(|error| error.to_string())?;
        }
        persist_request(
            &mut tx,
            namespace,
            actor,
            "activate",
            idempotency_key,
            &request_digest,
            &activation,
            now_ms,
        )?;
        tx.execute(
            "INSERT INTO sekai_object_security_audit
             (event_id, namespace, actor, action, revision_digest, policy_count, reason_code, created_at_ms)
             VALUES ($1, $2, $3, 'activate', $4, $5, 'complete_mapping', $6)",
            &[
                &Uuid::new_v4().to_string(),
                &namespace,
                &actor,
                &request_digest,
                &(policies.len() as i32),
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(activation)
    }

    pub fn get_object_security_activation(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityActivation>, String> {
        let mut connection = self.connection()?;
        let rows = connection
            .query(
                "SELECT activation.activation_id, activation.activated_by,
                        activation.activated_at_ms, policy.kind, policy.revision_digest
                 FROM sekai_object_security_activations AS activation
                 LEFT JOIN sekai_object_security_active_policies AS policy
                   ON policy.namespace = activation.namespace
                 WHERE activation.namespace=$1
                 ORDER BY policy.kind",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?;
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let policies = rows
            .iter()
            .filter_map(|row| {
                let kind = row.get::<_, Option<String>>(3)?;
                let digest = row.get::<_, Option<String>>(4)?;
                Some((kind, digest))
            })
            .collect();
        Ok(Some(ObjectSecurityActivation {
            namespace: namespace.into(),
            activation_id: first.get(0),
            policies,
            activated_by: first.get(1),
            activated_at_ms: first.get(2),
        }))
    }

    pub fn list_activated_object_security_namespaces(&self) -> Result<Vec<String>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT namespace FROM sekai_object_security_activations ORDER BY namespace",
                &[],
            )
            .map_err(|error| error.to_string())?
            .iter()
            .map(|row| row.get(0))
            .collect())
    }

    pub fn has_object_security_activations(&self) -> Result<bool, String> {
        self.connection()?
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM sekai_object_security_activations)",
                &[],
            )
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }

    pub fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let existing = transaction
            .query_opt(
                "SELECT secret_value FROM sekai_object_security_runtime_secrets
                 WHERE name = 'object_query_cursor_hmac'",
                &[],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0));
        let secret = existing
            .unwrap_or_else(|| format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()));
        transaction
            .execute(
                "INSERT INTO sekai_object_security_runtime_secrets
                    (name, secret_value)
                 VALUES ('object_query_cursor_hmac', $1)
                 ON CONFLICT (name) DO NOTHING",
                &[&secret],
            )
            .map_err(|error| error.to_string())?;
        let secret = transaction
            .query_one(
                "SELECT secret_value FROM sekai_object_security_runtime_secrets
                 WHERE name = 'object_query_cursor_hmac'",
                &[],
            )
            .map(|row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(cursor_key_from_secret(&secret))
    }
}

fn insert_revision(
    tx: &mut Transaction<'_>,
    revision: &ObjectSecurityPolicyRevision,
    policy: &ObjectSecurityPolicy,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_object_security_revisions
         (namespace, revision_digest, kind, canonical_policy_json, created_by, created_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &revision.namespace,
            &revision.revision_digest,
            &revision.kind,
            &revision.canonical_policy_json,
            &revision.created_by,
            &revision.created_at_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    for (rule_index, rule) in policy.rules.iter().enumerate() {
        tx.execute(
            "INSERT INTO sekai_object_security_rules
             (namespace, revision_digest, rule_index, operation) VALUES ($1, $2, $3, $4)",
            &[
                &revision.namespace,
                &revision.revision_digest,
                &(rule_index as i32),
                &rule.operation.as_str(),
            ],
        )
        .map_err(|error| error.to_string())?;
        for (predicate_index, predicate) in rule.predicates.iter().enumerate() {
            let (kind, property, value) = predicate_columns(predicate);
            tx.execute(
                "INSERT INTO sekai_object_security_predicates
                 (namespace, revision_digest, rule_index, predicate_index,
                  predicate_kind, property_key, fixed_value)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &revision.namespace,
                    &revision.revision_digest,
                    &(rule_index as i32),
                    &(predicate_index as i32),
                    &kind,
                    &property,
                    &value,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub(crate) fn load_active_policy_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    kind: &str,
) -> Result<Option<ObjectSecurityPolicy>, String> {
    let digest = client
        .query_opt(
            "SELECT revision_digest FROM sekai_object_security_active_policies
             WHERE namespace=$1 AND kind=$2",
            &[&namespace, &kind],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get::<_, String>(0));
    let Some(digest) = digest else {
        return Ok(None);
    };
    let canonical = client
        .query_opt(
            "SELECT canonical_policy_json FROM sekai_object_security_revisions
             WHERE namespace=$1 AND revision_digest=$2",
            &[&namespace, &digest],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get::<_, Vec<u8>>(0));
    let Some(canonical) = canonical else {
        return Ok(None);
    };
    ObjectSecurityPolicy::from_canonical_input(&canonical).map(Some)
}

fn load_revision(
    client: &mut impl GenericClient,
    namespace: &str,
    digest: &str,
) -> Result<Option<ObjectSecurityPolicyRevision>, String> {
    client
        .query_opt(
            "SELECT namespace, kind, revision_digest, canonical_policy_json, created_by, created_at_ms
             FROM sekai_object_security_revisions WHERE namespace=$1 AND revision_digest=$2",
            &[&namespace, &digest],
        )
        .map_err(|error| error.to_string())?
        .map(|row| ObjectSecurityPolicyRevision {
            namespace: row.get(0),
            kind: row.get(1),
            revision_digest: row.get(2),
            canonical_policy_json: row.get(3),
            created_by: row.get(4),
            created_at_ms: row.get(5),
        })
        .pipe(Ok)
}

trait Pipe: Sized {
    fn pipe<T>(self, function: impl FnOnce(Self) -> T) -> T {
        function(self)
    }
}
impl<T> Pipe for T {}

fn lock_request(
    tx: &mut Transaction<'_>,
    namespace: &str,
    actor: &str,
    key: &str,
) -> Result<(), String> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))",
        &[&format!("{namespace}:{actor}"), &key],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn lock_revision(tx: &mut Transaction<'_>, namespace: &str, digest: &str) -> Result<(), String> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))",
        &[&namespace, &digest],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn replay(
    client: &mut impl GenericClient,
    namespace: &str,
    actor: &str,
    operation: &str,
    key: &str,
    request_digest: &str,
) -> Result<Option<String>, String> {
    match client
        .query_opt(
            "SELECT request_digest, result_json FROM sekai_object_security_requests
             WHERE namespace=$1 AND actor=$2 AND operation=$3 AND idempotency_key=$4",
            &[&namespace, &actor, &operation, &key],
        )
        .map_err(|error| error.to_string())?
    {
        Some(row) if row.get::<_, String>(0) == request_digest => Ok(Some(row.get(1))),
        Some(_) => {
            Err("object_security_idempotency_conflict: key reused for different input".into())
        }
        None => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_request<T: serde::Serialize>(
    client: &mut impl GenericClient,
    namespace: &str,
    actor: &str,
    operation: &str,
    key: &str,
    request_digest: &str,
    result: &T,
    now_ms: i64,
) -> Result<(), String> {
    let result = serde_json::to_string(result).map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO sekai_object_security_requests
             (namespace, actor, operation, idempotency_key, request_digest, result_json, created_at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &namespace,
                &actor,
                &operation,
                &key,
                &request_digest,
                &result,
                &now_ms,
            ],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn validate_write(actor: &str, key: &str, now_ms: i64) -> Result<(), String> {
    if actor.trim().is_empty()
        || key.trim().is_empty()
        || key.len() > 256
        || now_ms <= 0
        || actor.contains('\0')
        || key.contains('\0')
    {
        return Err("invalid object-security write context".into());
    }
    Ok(())
}
