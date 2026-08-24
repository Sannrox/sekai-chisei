//! PostgreSQL persistence for versioned object security policies.

use postgres::{GenericClient, Transaction};

use crate::db::object_security::cursor_key_from_secret;
use crate::db::postgres::PostgresDb;
use crate::sekai::object_security::{
    ActivateObjectSecurityProfile, ObjectSecurityPolicyInput, ObjectSecurityPolicyRecord,
    ObjectSecurityPolicyRevision, ObjectSecurityPolicyRevocation, ObjectSecurityProfile,
    ObjectSecurityWriteResult, RevokeObjectSecurityPolicy,
};

impl PostgresDb {
    pub fn replay_object_security_write(
        &self,
        namespace: &str,
        actor: &str,
        idempotency_key: &str,
        operation: &str,
        request_digest: &str,
    ) -> Result<Option<ObjectSecurityWriteResult>, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let result = replay_postgres(
            &mut transaction,
            namespace,
            actor,
            idempotency_key,
            operation,
            request_digest,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn create_object_security_policy(
        &self,
        input: &ObjectSecurityPolicyInput,
        actor: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityWriteResult, String> {
        let policy = input.prepare(actor, now_ms)?;
        let request_digest = input.request_digest(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_namespace(&mut transaction, &input.namespace)?;
        if let Some(result) = replay_postgres(
            &mut transaction,
            &input.namespace,
            actor,
            &input.idempotency_key,
            "create_policy",
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }

        if let Some(existing) =
            load_policy_postgres(&mut transaction, &policy.namespace, &policy.policy_digest)?
        {
            let result = ObjectSecurityWriteResult::CreatePolicy { record: existing };
            persist_result_postgres(
                &mut transaction,
                &policy.namespace,
                actor,
                &input.idempotency_key,
                "create_policy",
                &request_digest,
                &result,
                &policy.policy_digest,
                &policy.policy_digest,
                "",
                "created",
                now_ms,
            )?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        let body_json = serde_json::to_string(&policy).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_object_security_policies (
                    namespace, object_kind, revision, policy_digest, body_json,
                    created_by, created_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &policy.namespace,
                    &policy.object_kind,
                    &policy.revision,
                    &policy.policy_digest,
                    &body_json,
                    &policy.created_by,
                    &policy.created_at_ms,
                ],
            )
            .map_err(map_policy_constraint)?;
        let result = ObjectSecurityWriteResult::CreatePolicy {
            record: ObjectSecurityPolicyRecord {
                policy: policy.clone(),
                revocation: None,
            },
        };
        persist_result_postgres(
            &mut transaction,
            &policy.namespace,
            actor,
            &input.idempotency_key,
            "create_policy",
            &request_digest,
            &result,
            &policy.policy_digest,
            &policy.policy_digest,
            "",
            "created",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn get_object_security_policy(
        &self,
        namespace: &str,
        policy_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRecord>, String> {
        load_policy_postgres(&mut *self.connection()?, namespace, policy_digest)
    }

    pub fn activate_object_security_profile(
        &self,
        request: &ActivateObjectSecurityProfile,
        advertised_object_kinds: &[String],
        actor: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityWriteResult, String> {
        let (profile, request_digest) =
            request.prepare(advertised_object_kinds.iter().cloned(), actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_namespace(&mut transaction, &request.namespace)?;
        if let Some(result) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            "activate_profile",
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }

        let current = load_profile_postgres(&mut transaction, &request.namespace)?;
        match (&current, request.expected_profile_digest.as_str()) {
            (None, "") => {}
            (None, _) => {
                return Err(
                    "stale_object_security_profile: expected profile is unavailable".into(),
                );
            }
            (Some(_), "") => {
                return Err(
                    "stale_object_security_profile: replacement requires expected_profile_digest"
                        .into(),
                );
            }
            (Some(current), expected) if current.profile_digest != expected => {
                return Err("stale_object_security_profile: active profile has changed".into());
            }
            (Some(_), _) => {}
        }
        for binding in &profile.bindings {
            let record =
                load_policy_postgres(&mut transaction, &profile.namespace, &binding.policy_digest)?
                    .ok_or_else(|| {
                        "object_security_policy_unavailable: bound policy is unavailable"
                            .to_string()
                    })?;
            if record.policy.object_kind != binding.object_kind || record.revocation.is_some() {
                return Err(
                    "object_security_policy_unavailable: bound policy is invalid or revoked".into(),
                );
            }
        }
        let body_json = serde_json::to_string(&profile).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_object_security_profiles (
                    namespace, profile_digest, body_json, activated_by, activated_at_ms
                 ) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT(namespace) DO UPDATE SET
                    profile_digest=excluded.profile_digest,
                    body_json=excluded.body_json,
                    activated_by=excluded.activated_by,
                    activated_at_ms=excluded.activated_at_ms",
                &[
                    &profile.namespace,
                    &profile.profile_digest,
                    &body_json,
                    &profile.activated_by,
                    &profile.activated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        let result = ObjectSecurityWriteResult::ActivateProfile {
            profile: profile.clone(),
        };
        persist_result_postgres(
            &mut transaction,
            &profile.namespace,
            actor,
            &request.idempotency_key,
            "activate_profile",
            &request_digest,
            &result,
            &profile.profile_digest,
            "",
            &profile.profile_digest,
            if current.is_some() {
                "replaced"
            } else {
                "activated"
            },
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn get_object_security_profile(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityProfile>, String> {
        load_profile_postgres(&mut *self.connection()?, namespace)
    }

    pub fn object_security_kind_is_active(&self, object_kind: &str) -> Result<bool, String> {
        self.connection()?
            .query_one(
                "SELECT EXISTS (
                    SELECT 1
                    FROM sekai_object_security_profiles profile
                    CROSS JOIN LATERAL jsonb_array_elements(
                        profile.body_json::jsonb -> 'bindings'
                    ) binding(value)
                    WHERE binding.value ->> 'object_kind' = $1
                )",
                &[&object_kind],
            )
            .map(|row| row.get(0))
            .map_err(|error| error.to_string())
    }

    pub fn active_object_security_policies_for_kind(
        &self,
        object_kind: &str,
    ) -> Result<Vec<ObjectSecurityPolicyRecord>, String> {
        let mut connection = self.connection()?;
        let bindings = connection
            .query(
                "SELECT profile.namespace, binding.value ->> 'policy_digest'
                 FROM sekai_object_security_profiles profile
                 CROSS JOIN LATERAL jsonb_array_elements(
                    profile.body_json::jsonb -> 'bindings'
                 ) binding(value)
                 WHERE binding.value ->> 'object_kind' = $1
                 ORDER BY profile.namespace",
                &[&object_kind],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
            .collect::<Vec<_>>();
        bindings
            .into_iter()
            .map(|(namespace, policy_digest)| {
                load_policy_postgres(&mut *connection, &namespace, &policy_digest)?.ok_or_else(
                    || {
                        "object_security_policy_unavailable: active policy revision is unavailable"
                            .into()
                    },
                )
            })
            .collect()
    }

    pub fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
        let generated = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_object_security_runtime_secrets (name, secret_value)
                 VALUES ('object_query_cursor_hmac', $1)
                 ON CONFLICT(name) DO NOTHING",
                &[&generated],
            )
            .map_err(|error| error.to_string())?;
        let secret: String = transaction
            .query_one(
                "SELECT secret_value FROM sekai_object_security_runtime_secrets
                 WHERE name = 'object_query_cursor_hmac'",
                &[],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(cursor_key_from_secret(&secret))
    }

    pub fn revoke_object_security_policy(
        &self,
        request: &RevokeObjectSecurityPolicy,
        actor: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityWriteResult, String> {
        let request_digest = request.validate(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_namespace(&mut transaction, &request.namespace)?;
        if let Some(result) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            "revoke_policy",
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        let mut record =
            load_policy_postgres(&mut transaction, &request.namespace, &request.policy_digest)?
                .ok_or_else(|| {
                    "object_security_policy_unavailable: policy is unavailable".to_string()
                })?;
        if record.revocation.is_some() {
            return Err("object_security_policy_revoked: policy is already revoked".into());
        }
        let revocation = ObjectSecurityPolicyRevocation {
            namespace: request.namespace.clone(),
            policy_digest: request.policy_digest.clone(),
            reason: request.reason.trim().into(),
            revoked_by: actor.into(),
            revoked_at_ms: now_ms,
        };
        let body_json = serde_json::to_string(&revocation).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO sekai_object_security_revocations (
                    namespace, policy_digest, body_json, revoked_by, revoked_at_ms
                 ) VALUES ($1, $2, $3, $4, $5)",
                &[
                    &revocation.namespace,
                    &revocation.policy_digest,
                    &body_json,
                    &revocation.revoked_by,
                    &revocation.revoked_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        record.revocation = Some(revocation);
        let result = ObjectSecurityWriteResult::RevokePolicy {
            record: record.clone(),
        };
        persist_result_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            "revoke_policy",
            &request_digest,
            &result,
            &request.policy_digest,
            &request.policy_digest,
            "",
            "revoked",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }
}

fn lock_namespace(transaction: &mut Transaction<'_>, namespace: &str) -> Result<(), String> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 667))",
            &[&namespace],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub(crate) fn load_policy_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    policy_digest: &str,
) -> Result<Option<ObjectSecurityPolicyRecord>, String> {
    client
        .query_opt(
            "SELECT policy.body_json, revocation.body_json
             FROM sekai_object_security_policies policy
             LEFT JOIN sekai_object_security_revocations revocation
               ON revocation.namespace=policy.namespace
              AND revocation.policy_digest=policy.policy_digest
             WHERE policy.namespace=$1 AND policy.policy_digest=$2",
            &[&namespace, &policy_digest],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            let policy_json: String = row.get(0);
            let revocation_json: Option<String> = row.get(1);
            let policy: ObjectSecurityPolicyRevision =
                serde_json::from_str(&policy_json).map_err(|error| error.to_string())?;
            policy.verify()?;
            let revocation = revocation_json
                .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
                .transpose()?;
            Ok(ObjectSecurityPolicyRecord { policy, revocation })
        })
        .transpose()
}

pub(crate) fn load_profile_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
) -> Result<Option<ObjectSecurityProfile>, String> {
    client
        .query_opt(
            "SELECT body_json FROM sekai_object_security_profiles WHERE namespace=$1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            let json: String = row.get(0);
            let profile: ObjectSecurityProfile =
                serde_json::from_str(&json).map_err(|error| error.to_string())?;
            profile.verify()?;
            Ok(profile)
        })
        .transpose()
}

fn replay_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    actor: &str,
    idempotency_key: &str,
    operation: &str,
    request_digest: &str,
) -> Result<Option<ObjectSecurityWriteResult>, String> {
    let existing = client
        .query_opt(
            "SELECT operation, request_digest, result_json
             FROM sekai_object_security_requests
             WHERE namespace=$1 AND actor=$2 AND idempotency_key=$3",
            &[&namespace, &actor, &idempotency_key],
        )
        .map_err(|error| error.to_string())?;
    let Some(row) = existing else {
        return Ok(None);
    };
    let stored_operation: String = row.get(0);
    let stored_digest: String = row.get(1);
    let result_json: String = row.get(2);
    if stored_operation != operation || stored_digest != request_digest {
        return Err(
            "object_security_idempotency_conflict: idempotency key has different input".into(),
        );
    }
    serde_json::from_str(&result_json)
        .map(Some)
        .map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn persist_result_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    actor: &str,
    idempotency_key: &str,
    operation: &str,
    request_digest: &str,
    result: &ObjectSecurityWriteResult,
    target_digest: &str,
    policy_digest: &str,
    profile_digest: &str,
    reason_code: &str,
    now_ms: i64,
) -> Result<(), String> {
    let result_json = serde_json::to_string(result).map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO sekai_object_security_requests (
                namespace, actor, idempotency_key, operation, request_digest,
                result_json, created_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &namespace,
                &actor,
                &idempotency_key,
                &operation,
                &request_digest,
                &result_json,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    let event_id = format!("object-security-{}", uuid::Uuid::new_v4().simple());
    client
        .execute(
            "INSERT INTO sekai_object_security_audit (
                event_id, namespace, actor, action, target_digest, policy_digest,
                profile_digest, reason_code, request_digest, created_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &[
                &event_id,
                &namespace,
                &actor,
                &operation,
                &target_digest,
                &policy_digest,
                &profile_digest,
                &reason_code,
                &request_digest,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn map_policy_constraint(error: postgres::Error) -> String {
    if error
        .code()
        .is_some_and(|code| code == &postgres::error::SqlState::UNIQUE_VIOLATION)
    {
        "object_security_policy_conflict: revision identity is already in use".into()
    } else {
        error.to_string()
    }
}
