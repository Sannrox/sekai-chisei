//! Backend-neutral durable object-security policy contract.

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::object_security::{
    ObjectSecurityActivation, ObjectSecurityPolicy, ObjectSecurityPolicyRevision,
};

pub const POSTGRES_OBJECT_SECURITY_SURFACE: &str = "sekai.object-security";

pub trait ObjectSecurityBackend: Send + Sync {
    fn put_object_security_policy(
        &self,
        policy: &ObjectSecurityPolicy,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityPolicyRevision, String>;
    fn get_object_security_policy(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRevision>, String>;
    fn activate_object_security_policies(
        &self,
        namespace: &str,
        policies: &BTreeMap<String, String>,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityActivation, String>;
    fn get_object_security_activation(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityActivation>, String>;
    fn has_object_security_activations(&self) -> Result<bool, String>;
    fn object_query_cursor_key(&self) -> Result<[u8; 32], String>;
}

impl ObjectSecurityBackend for SekaiDb {
    fn put_object_security_policy(
        &self,
        policy: &ObjectSecurityPolicy,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityPolicyRevision, String> {
        self.put_object_security_policy(policy, actor, idempotency_key, now_ms)
    }
    fn get_object_security_policy(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRevision>, String> {
        self.get_object_security_policy(namespace, revision_digest)
    }
    fn activate_object_security_policies(
        &self,
        namespace: &str,
        policies: &BTreeMap<String, String>,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityActivation, String> {
        self.activate_object_security_policies(namespace, policies, actor, idempotency_key, now_ms)
    }
    fn get_object_security_activation(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityActivation>, String> {
        self.get_object_security_activation(namespace)
    }
    fn has_object_security_activations(&self) -> Result<bool, String> {
        self.has_object_security_activations()
    }
    fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
        self.object_query_cursor_key()
    }
}

impl ObjectSecurityBackend for PostgresDb {
    fn put_object_security_policy(
        &self,
        policy: &ObjectSecurityPolicy,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityPolicyRevision, String> {
        self.put_object_security_policy(policy, actor, idempotency_key, now_ms)
    }
    fn get_object_security_policy(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRevision>, String> {
        self.get_object_security_policy(namespace, revision_digest)
    }
    fn activate_object_security_policies(
        &self,
        namespace: &str,
        policies: &BTreeMap<String, String>,
        actor: &str,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityActivation, String> {
        self.activate_object_security_policies(namespace, policies, actor, idempotency_key, now_ms)
    }
    fn get_object_security_activation(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityActivation>, String> {
        self.get_object_security_activation(namespace)
    }
    fn has_object_security_activations(&self) -> Result<bool, String> {
        self.has_object_security_activations()
    }
    fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
        self.object_query_cursor_key()
    }
}

impl SekaiDb {
    pub(crate) fn migrate_object_security(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_object_security_revisions (
                    namespace TEXT NOT NULL,
                    revision_digest TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    canonical_policy_json BLOB NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, revision_digest)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_security_rules (
                    namespace TEXT NOT NULL,
                    revision_digest TEXT NOT NULL,
                    rule_index INTEGER NOT NULL,
                    operation TEXT NOT NULL,
                    PRIMARY KEY(namespace, revision_digest, rule_index)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_security_predicates (
                    namespace TEXT NOT NULL,
                    revision_digest TEXT NOT NULL,
                    rule_index INTEGER NOT NULL,
                    predicate_index INTEGER NOT NULL,
                    predicate_kind TEXT NOT NULL,
                    property_key TEXT NOT NULL DEFAULT '',
                    fixed_value TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(namespace, revision_digest, rule_index, predicate_index)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_security_activations (
                    namespace TEXT PRIMARY KEY,
                    activation_id TEXT NOT NULL,
                    activated_by TEXT NOT NULL,
                    activated_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sekai_object_security_active_policies (
                    namespace TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    revision_digest TEXT NOT NULL,
                    PRIMARY KEY(namespace, kind)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_security_requests (
                    namespace TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, actor, operation, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS sekai_object_security_audit (
                    event_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    revision_digest TEXT NOT NULL DEFAULT '',
                    policy_count INTEGER NOT NULL,
                    reason_code TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sekai_object_security_runtime_secrets (
                    name TEXT PRIMARY KEY,
                    secret_value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sekai_purpose_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    contract_version TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    kind TEXT NOT NULL DEFAULT '',
                    not_before_ms INTEGER NOT NULL,
                    not_after_ms INTEGER NOT NULL,
                    policy_activation_digest TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    revoked_at_ms INTEGER NOT NULL DEFAULT 0
                );",
            )
            .map_err(|error| error.to_string())
    }

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
        let request_digest = digest.clone();
        let mut connection = self.conn();
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(result) = replay_sqlite(
            &tx,
            &policy.namespace,
            actor,
            "put",
            idempotency_key,
            &request_digest,
        )? {
            return serde_json::from_str(&result).map_err(|error| error.to_string());
        }
        if let Some(existing) = load_revision_sqlite(&tx, &policy.namespace, &digest)? {
            if existing.canonical_policy_json != canonical {
                return Err("object_security_conflict: revision digest collision".into());
            }
            persist_request_sqlite(
                &tx,
                &policy.namespace,
                actor,
                "put",
                idempotency_key,
                &request_digest,
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
        insert_revision_sqlite(&tx, &revision, &policy)?;
        persist_request_sqlite(
            &tx,
            &policy.namespace,
            actor,
            "put",
            idempotency_key,
            &request_digest,
            &revision,
            now_ms,
        )?;
        tx.execute(
            "INSERT INTO sekai_object_security_audit
             (event_id, namespace, actor, action, revision_digest, policy_count, reason_code, created_at_ms)
             VALUES (?1, ?2, ?3, 'put_revision', ?4, 1, 'stored', ?5)",
            params![Uuid::new_v4().to_string(), policy.namespace, actor, digest, now_ms],
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
        load_revision_sqlite(&self.conn(), namespace, revision_digest)
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
        let mut connection = self.conn();
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(result) = replay_sqlite(
            &tx,
            namespace,
            actor,
            "activate",
            idempotency_key,
            &request_digest,
        )? {
            return serde_json::from_str(&result).map_err(|error| error.to_string());
        }
        let mut statement = tx
            .prepare("SELECT DISTINCT kind FROM sekai_objects WHERE namespace=?1 ORDER BY kind")
            .map_err(|error| error.to_string())?;
        let instantiated = statement
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        drop(statement);
        if instantiated.len() != policies.len()
            || instantiated.iter().any(|kind| !policies.contains_key(kind))
        {
            return Err(
                "object_security_activation_incomplete: every instantiated kind requires exactly one revision"
                    .into(),
            );
        }
        for (kind, digest) in policies {
            let revision = load_revision_sqlite(&tx, namespace, digest)?.ok_or_else(|| {
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
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace) DO UPDATE SET activation_id=excluded.activation_id,
                 activated_by=excluded.activated_by, activated_at_ms=excluded.activated_at_ms",
            params![namespace, request_digest, actor, now_ms],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "DELETE FROM sekai_object_security_active_policies WHERE namespace=?1",
            params![namespace],
        )
        .map_err(|error| error.to_string())?;
        for (kind, digest) in policies {
            tx.execute(
                "INSERT INTO sekai_object_security_active_policies
                 (namespace, kind, revision_digest) VALUES (?1, ?2, ?3)",
                params![namespace, kind, digest],
            )
            .map_err(|error| error.to_string())?;
        }
        persist_request_sqlite(
            &tx,
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
             VALUES (?1, ?2, ?3, 'activate', ?4, ?5, 'complete_mapping', ?6)",
            params![
                Uuid::new_v4().to_string(),
                namespace,
                actor,
                request_digest,
                policies.len() as i64,
                now_ms
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
        let connection = self.conn();
        let mut statement = connection
            .prepare(
                "SELECT activation.activation_id, activation.activated_by,
                        activation.activated_at_ms, policy.kind, policy.revision_digest
                 FROM sekai_object_security_activations AS activation
                 LEFT JOIN sekai_object_security_active_policies AS policy
                   ON policy.namespace = activation.namespace
                 WHERE activation.namespace=?1
                 ORDER BY policy.kind",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        let Some((activation_id, activated_by, activated_at_ms, _, _)) = rows.first() else {
            return Ok(None);
        };
        let policies = rows
            .iter()
            .filter_map(|(_, _, _, kind, digest)| Some((kind.clone()?, digest.clone()?)))
            .collect();
        Ok(Some(ObjectSecurityActivation {
            namespace: namespace.into(),
            activation_id: activation_id.clone(),
            policies,
            activated_by: activated_by.clone(),
            activated_at_ms: *activated_at_ms,
        }))
    }

    pub fn list_activated_object_security_namespaces(&self) -> Result<Vec<String>, String> {
        let connection = self.conn();
        let mut statement = connection
            .prepare("SELECT namespace FROM sekai_object_security_activations ORDER BY namespace")
            .map_err(|error| error.to_string())?;
        let namespaces = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(namespaces)
    }

    pub fn has_object_security_activations(&self) -> Result<bool, String> {
        self.conn()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sekai_object_security_activations)",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }

    pub fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let existing = transaction
            .query_row(
                "SELECT secret_value FROM sekai_object_security_runtime_secrets
                 WHERE name = 'object_query_cursor_hmac'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let secret = existing
            .unwrap_or_else(|| format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()));
        transaction
            .execute(
                "INSERT OR IGNORE INTO sekai_object_security_runtime_secrets
                    (name, secret_value)
                 VALUES ('object_query_cursor_hmac', ?1)",
                params![secret],
            )
            .map_err(|error| error.to_string())?;
        let secret = transaction
            .query_row(
                "SELECT secret_value FROM sekai_object_security_runtime_secrets
                 WHERE name = 'object_query_cursor_hmac'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(cursor_key_from_secret(&secret))
    }

    pub fn put_purpose_authorization(
        &self,
        authorization: &crate::sekai::purpose_authorization::PurposeAuthorization,
    ) -> Result<crate::sekai::purpose_authorization::PurposeAuthorization, String> {
        let authorization = authorization.prepare()?;
        self.conn()
            .execute(
                "INSERT INTO sekai_purpose_authorizations
                 (authorization_id, contract_version, actor, purpose, namespace, kind,
                  not_before_ms, not_after_ms, policy_activation_digest, created_by,
                  created_at_ms, revoked_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    authorization.authorization_id,
                    authorization.contract_version,
                    authorization.actor,
                    authorization.purpose,
                    authorization.namespace,
                    authorization.kind,
                    authorization.not_before_ms,
                    authorization.not_after_ms,
                    authorization.policy_activation_digest,
                    authorization.created_by,
                    authorization.created_at_ms,
                    authorization.revoked_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(authorization)
    }

    pub fn revoke_purpose_authorization(
        &self,
        authorization_id: &str,
        revoked_at_ms: i64,
    ) -> Result<crate::sekai::purpose_authorization::PurposeAuthorization, String> {
        if authorization_id.is_empty() || revoked_at_ms <= 0 {
            return Err("purpose authorization revocation identity or time is invalid".into());
        }
        let updated = self
            .conn()
            .execute(
                "UPDATE sekai_purpose_authorizations
                 SET revoked_at_ms = ?1
                 WHERE authorization_id = ?2 AND revoked_at_ms = 0",
                params![revoked_at_ms, authorization_id],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("purpose authorization is missing or already revoked".into());
        }
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT authorization_id, contract_version, actor, purpose, namespace, kind,
                        not_before_ms, not_after_ms, policy_activation_digest, created_by,
                        created_at_ms, revoked_at_ms
                 FROM sekai_purpose_authorizations
                 WHERE authorization_id = ?1",
            )
            .map_err(|error| error.to_string())?;
        statement
            .query_row(params![authorization_id], row_to_purpose_authorization)
            .map_err(|error| error.to_string())
    }

    pub fn find_purpose_authorization(
        &self,
        actor: &str,
        purpose: &str,
        namespace: &str,
        kind: &str,
        activation_digest: &str,
        now_ms: i64,
    ) -> Result<Option<crate::sekai::purpose_authorization::PurposeAuthorization>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT authorization_id, contract_version, actor, purpose, namespace, kind,
                        not_before_ms, not_after_ms, policy_activation_digest, created_by,
                        created_at_ms, revoked_at_ms
                 FROM sekai_purpose_authorizations
                 WHERE actor=?1 AND purpose=?2 AND namespace=?3
                   AND (kind='' OR kind=?4)
                   AND policy_activation_digest=?5
                   AND contract_version=?7
                   AND revoked_at_ms=0
                   AND not_before_ms<=?6 AND not_after_ms>=?6
                 ORDER BY kind DESC, authorization_id
                 LIMIT 1",
            )
            .map_err(|error| error.to_string())?;
        statement
            .query_row(
                params![
                    actor,
                    purpose,
                    namespace,
                    kind,
                    activation_digest,
                    now_ms,
                    crate::sekai::purpose_authorization::PURPOSE_AUTHORIZATION_VERSION
                ],
                row_to_purpose_authorization,
            )
            .optional()
            .map_err(|error| error.to_string())
    }
}

fn row_to_purpose_authorization(
    row: &rusqlite::Row,
) -> rusqlite::Result<crate::sekai::purpose_authorization::PurposeAuthorization> {
    let authorization = crate::sekai::purpose_authorization::PurposeAuthorization {
        authorization_id: row.get(0)?,
        contract_version: row.get(1)?,
        actor: row.get(2)?,
        purpose: row.get(3)?,
        namespace: row.get(4)?,
        kind: row.get(5)?,
        not_before_ms: row.get(6)?,
        not_after_ms: row.get(7)?,
        policy_activation_digest: row.get(8)?,
        created_by: row.get(9)?,
        created_at_ms: row.get(10)?,
        revoked_at_ms: row.get(11)?,
    };
    authorization.prepare().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        )
    })
}

fn insert_revision_sqlite(
    tx: &Transaction<'_>,
    revision: &ObjectSecurityPolicyRevision,
    policy: &ObjectSecurityPolicy,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_object_security_revisions
         (namespace, revision_digest, kind, canonical_policy_json, created_by, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            revision.namespace,
            revision.revision_digest,
            revision.kind,
            revision.canonical_policy_json,
            revision.created_by,
            revision.created_at_ms
        ],
    )
    .map_err(|error| error.to_string())?;
    for (rule_index, rule) in policy.rules.iter().enumerate() {
        tx.execute(
            "INSERT INTO sekai_object_security_rules
             (namespace, revision_digest, rule_index, operation) VALUES (?1, ?2, ?3, ?4)",
            params![
                revision.namespace,
                revision.revision_digest,
                rule_index as i64,
                rule.operation.as_str()
            ],
        )
        .map_err(|error| error.to_string())?;
        for (predicate_index, predicate) in rule.predicates.iter().enumerate() {
            let (kind, property, value) = predicate_columns(predicate);
            tx.execute(
                "INSERT INTO sekai_object_security_predicates
                 (namespace, revision_digest, rule_index, predicate_index,
                  predicate_kind, property_key, fixed_value)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    revision.namespace,
                    revision.revision_digest,
                    rule_index as i64,
                    predicate_index as i64,
                    kind,
                    property,
                    value
                ],
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub(crate) fn load_active_policy_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
    kind: &str,
) -> Result<Option<ObjectSecurityPolicy>, String> {
    let digest = connection
        .query_row(
            "SELECT revision_digest FROM sekai_object_security_active_policies
             WHERE namespace=?1 AND kind=?2",
            params![namespace, kind],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(digest) = digest else {
        return Ok(None);
    };
    let canonical = connection
        .query_row(
            "SELECT canonical_policy_json FROM sekai_object_security_revisions
             WHERE namespace=?1 AND revision_digest=?2",
            params![namespace, digest],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(canonical) = canonical else {
        return Ok(None);
    };
    ObjectSecurityPolicy::from_canonical_input(&canonical).map(Some)
}

pub(crate) fn predicate_columns(
    predicate: &crate::sekai::object_security::ObjectSecurityPredicate,
) -> (&'static str, &str, &str) {
    use crate::sekai::object_security::ObjectSecurityPredicate::*;
    match predicate {
        AllowAll => ("allow_all", "", ""),
        SubjectEqualsProperty { property } => ("subject_equals_property", property, ""),
        RequiredScopeEquals { value } => ("required_scope_equals", "", value),
        PropertyEquals { property, value } => ("property_equals", property, value),
    }
}

fn load_revision_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
    digest: &str,
) -> Result<Option<ObjectSecurityPolicyRevision>, String> {
    connection
        .query_row(
            "SELECT namespace, kind, revision_digest, canonical_policy_json, created_by, created_at_ms
             FROM sekai_object_security_revisions WHERE namespace=?1 AND revision_digest=?2",
            params![namespace, digest],
            |row| {
                Ok(ObjectSecurityPolicyRevision {
                    namespace: row.get(0)?,
                    kind: row.get(1)?,
                    revision_digest: row.get(2)?,
                    canonical_policy_json: row.get(3)?,
                    created_by: row.get(4)?,
                    created_at_ms: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|error| error.to_string())
}

fn replay_sqlite(
    tx: &Transaction<'_>,
    namespace: &str,
    actor: &str,
    operation: &str,
    key: &str,
    request_digest: &str,
) -> Result<Option<String>, String> {
    let stored = tx
        .query_row(
            "SELECT request_digest, result_json FROM sekai_object_security_requests
             WHERE namespace=?1 AND actor=?2 AND operation=?3 AND idempotency_key=?4",
            params![namespace, actor, operation, key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    match stored {
        Some((stored_digest, result)) if stored_digest == request_digest => Ok(Some(result)),
        Some(_) => {
            Err("object_security_idempotency_conflict: key reused for different input".into())
        }
        None => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_request_sqlite<T: serde::Serialize>(
    tx: &Transaction<'_>,
    namespace: &str,
    actor: &str,
    operation: &str,
    key: &str,
    request_digest: &str,
    result: &T,
    now_ms: i64,
) -> Result<(), String> {
    let result = serde_json::to_string(result).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_object_security_requests
         (namespace, actor, operation, idempotency_key, request_digest, result_json, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            namespace,
            actor,
            operation,
            key,
            request_digest,
            result,
            now_ms
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

pub(crate) fn mapping_digest(namespace: &str, policies: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sekai.object-security-activation/v1\0");
    hasher.update(namespace.as_bytes());
    hasher.update([0]);
    hasher.update(serde_json::to_vec(policies).unwrap_or_default());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn cursor_key_from_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
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
