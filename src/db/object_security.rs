//! Backend-neutral persistence for versioned object security policies.

use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::object_security::{
    ActivateObjectSecurityProfile, ObjectSecurityPolicyInput, ObjectSecurityPolicyRecord,
    ObjectSecurityPolicyRevision, ObjectSecurityPolicyRevocation, ObjectSecurityProfile,
    ObjectSecurityWriteResult, PrincipalSecurityContext, RevokeObjectSecurityPolicy,
};

pub const POSTGRES_OBJECT_SECURITY_SURFACE: &str = "sekai.object-security";

pub(crate) fn sqlite_object_security_filter(
    principal: &PrincipalSecurityContext,
    operation: &str,
    allowed_legacy_markings: &[&str],
    trusted_legacy_markings: bool,
    start_param: usize,
) -> Result<(String, Vec<Box<dyn rusqlite::types::ToSql>>), String> {
    let attributes_json =
        serde_json::to_string(&principal.attributes).map_err(|error| error.to_string())?;
    let entitlements_json =
        serde_json::to_string(&principal.entitlements).map_err(|error| error.to_string())?;
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![
        Box::new(attributes_json),
        Box::new(entitlements_json),
        Box::new(operation.to_string()),
    ];
    let attributes = format!("?{}", start_param + 1);
    let entitlements = format!("?{}", start_param + 2);
    let operation = format!("?{}", start_param + 3);
    let scalar = |side: &str| {
        format!(
            "CASE json_extract(condition.value, '$.{side}.source')
                WHEN 'fixed' THEN json_extract(condition.value, '$.{side}.value')
                WHEN 'object_property' THEN json_extract(
                    sekai_objects.properties,
                    '$.' || json_extract(condition.value, '$.{side}.name')
                )
                WHEN 'operation_context' THEN {operation}
                WHEN 'principal_attribute' THEN json_extract(
                    {attributes},
                    '$.' || json_extract(condition.value, '$.{side}.name')
                )
                ELSE NULL
             END"
        )
    };
    let left = scalar("left");
    let right = scalar("right");
    let left_source = "json_extract(condition.value, '$.left.source')";
    let right_source = "json_extract(condition.value, '$.right.source')";
    let operator = "json_extract(condition.value, '$.operator')";
    let condition_match = format!(
        "(
            ({operator} = 'equals'
             AND {left_source} != 'principal_entitlement'
             AND {right_source} != 'principal_entitlement'
             AND ({left}) IS NOT NULL AND ({right}) IS NOT NULL
             AND ({left}) = ({right}))
            OR
            ({operator} = 'not_equals'
             AND {left_source} != 'principal_entitlement'
             AND {right_source} != 'principal_entitlement'
             AND ({left}) IS NOT NULL AND ({right}) IS NOT NULL
             AND ({left}) != ({right}))
            OR
            ({operator} = 'contains'
             AND {left_source} = 'principal_entitlement'
             AND ({right}) IS NOT NULL
             AND EXISTS (
                SELECT 1 FROM json_each({entitlements}) entitlement
                WHERE entitlement.value = ({right})
             ))
            OR
            ({operator} = 'contains'
             AND {right_source} = 'principal_entitlement'
             AND ({left}) IS NOT NULL
             AND EXISTS (
                SELECT 1 FROM json_each({entitlements}) entitlement
                WHERE entitlement.value = ({left})
             ))
        )"
    );
    let policy_match = format!(
        "EXISTS (
            SELECT 1
            FROM sekai_object_security_profiles profile
            JOIN json_each(profile.body_json, '$.bindings') binding
            JOIN sekai_object_security_policies policy
              ON policy.namespace = profile.namespace
             AND policy.policy_digest = json_extract(binding.value, '$.policy_digest')
            JOIN json_each(policy.body_json, '$.rules') rule
            WHERE profile.namespace = sekai_objects.namespace
              AND json_extract(binding.value, '$.object_kind') = sekai_objects.kind
              AND policy.object_kind = sekai_objects.kind
              AND NOT EXISTS (
                  SELECT 1 FROM sekai_object_security_revocations revocation
                  WHERE revocation.namespace = policy.namespace
                    AND revocation.policy_digest = policy.policy_digest
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(rule.value, '$.conditions') condition
                  WHERE NOT {condition_match}
              )
        )"
    );
    let legacy_marking = if trusted_legacy_markings {
        "1 = 1".to_string()
    } else {
        let marking = "LOWER(TRIM(json_extract(sekai_objects.properties, '$.access_marking')))";
        let mut expression = format!(
            "({marking} IS NULL OR {marking} = ''
              OR {marking} NOT IN ('public','internal','confidential','restricted')"
        );
        if !allowed_legacy_markings.is_empty() {
            let placeholders = allowed_legacy_markings
                .iter()
                .map(|marking| {
                    params.push(Box::new((*marking).to_string()));
                    format!("?{}", start_param + params.len())
                })
                .collect::<Vec<_>>()
                .join(",");
            expression.push_str(&format!(" OR {marking} IN ({placeholders})"));
        }
        expression.push(')');
        expression
    };
    Ok((
        format!(
            " AND (
                (
                    NOT EXISTS (
                        SELECT 1 FROM sekai_object_security_profiles active_profile
                        WHERE active_profile.namespace = sekai_objects.namespace
                    )
                    AND {legacy_marking}
                )
                OR {policy_match}
            )"
        ),
        params,
    ))
}

pub(crate) fn postgres_object_security_filter(
    principal: &PrincipalSecurityContext,
    operation: &str,
    allowed_legacy_markings: &[&str],
    trusted_legacy_markings: bool,
    start_param: usize,
) -> Result<(String, Vec<Box<dyn postgres::types::ToSql + Sync>>), String> {
    let attributes_json =
        serde_json::to_string(&principal.attributes).map_err(|error| error.to_string())?;
    let entitlements = principal.entitlements.iter().cloned().collect::<Vec<_>>();
    let mut params: Vec<Box<dyn postgres::types::ToSql + Sync>> = vec![
        Box::new(attributes_json),
        Box::new(entitlements),
        Box::new(operation.to_string()),
    ];
    let attributes = format!("${}", start_param + 1);
    let entitlements = format!("${}", start_param + 2);
    let operation = format!("${}", start_param + 3);
    let scalar = |side: &str| {
        format!(
            "CASE condition.value -> '{side}' ->> 'source'
                WHEN 'fixed' THEN condition.value -> '{side}' ->> 'value'
                WHEN 'object_property' THEN
                    o.properties::jsonb ->> (condition.value -> '{side}' ->> 'name')
                WHEN 'operation_context' THEN {operation}
                WHEN 'principal_attribute' THEN
                    {attributes}::jsonb ->> (condition.value -> '{side}' ->> 'name')
                ELSE NULL
             END"
        )
    };
    let left = scalar("left");
    let right = scalar("right");
    let left_source = "condition.value -> 'left' ->> 'source'";
    let right_source = "condition.value -> 'right' ->> 'source'";
    let operator = "condition.value ->> 'operator'";
    let condition_match = format!(
        "(
            ({operator} = 'equals'
             AND {left_source} != 'principal_entitlement'
             AND {right_source} != 'principal_entitlement'
             AND ({left}) IS NOT NULL AND ({right}) IS NOT NULL
             AND ({left}) = ({right}))
            OR
            ({operator} = 'not_equals'
             AND {left_source} != 'principal_entitlement'
             AND {right_source} != 'principal_entitlement'
             AND ({left}) IS NOT NULL AND ({right}) IS NOT NULL
             AND ({left}) != ({right}))
            OR
            ({operator} = 'contains'
             AND {left_source} = 'principal_entitlement'
             AND ({right}) IS NOT NULL
             AND ({right}) = ANY({entitlements}))
            OR
            ({operator} = 'contains'
             AND {right_source} = 'principal_entitlement'
             AND ({left}) IS NOT NULL
             AND ({left}) = ANY({entitlements}))
        )"
    );
    let policy_match = format!(
        "EXISTS (
            SELECT 1
            FROM sekai_object_security_profiles profile
            CROSS JOIN LATERAL jsonb_array_elements(
                profile.body_json::jsonb -> 'bindings'
            ) binding(value)
            JOIN sekai_object_security_policies policy
              ON policy.namespace = profile.namespace
             AND policy.policy_digest = binding.value ->> 'policy_digest'
            CROSS JOIN LATERAL jsonb_array_elements(
                policy.body_json::jsonb -> 'rules'
            ) rule(value)
            WHERE profile.namespace = o.namespace
              AND binding.value ->> 'object_kind' = o.kind
              AND policy.object_kind = o.kind
              AND NOT EXISTS (
                  SELECT 1 FROM sekai_object_security_revocations revocation
                  WHERE revocation.namespace = policy.namespace
                    AND revocation.policy_digest = policy.policy_digest
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements(rule.value -> 'conditions') condition(value)
                  WHERE NOT {condition_match}
              )
        )"
    );
    let legacy_marking = if trusted_legacy_markings {
        "TRUE".to_string()
    } else {
        let marking = "LOWER(BTRIM(o.properties::jsonb ->> 'access_marking'))";
        let mut expression = format!(
            "({marking} IS NULL OR {marking} = ''
              OR {marking} NOT IN ('public','internal','confidential','restricted')"
        );
        if !allowed_legacy_markings.is_empty() {
            let placeholders = allowed_legacy_markings
                .iter()
                .map(|marking| {
                    params.push(Box::new((*marking).to_string()));
                    format!("${}", start_param + params.len())
                })
                .collect::<Vec<_>>()
                .join(",");
            expression.push_str(&format!(" OR {marking} IN ({placeholders})"));
        }
        expression.push(')');
        expression
    };
    Ok((
        format!(
            "(
                (
                    NOT EXISTS (
                        SELECT 1 FROM sekai_object_security_profiles active_profile
                        WHERE active_profile.namespace = o.namespace
                    )
                    AND {legacy_marking}
                )
                OR {policy_match}
            )"
        ),
        params,
    ))
}

pub trait ObjectSecurityBackend: Send + Sync {
    fn create_object_security_policy(
        &self,
        input: &ObjectSecurityPolicyInput,
        actor: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityWriteResult, String>;

    fn get_object_security_policy(
        &self,
        namespace: &str,
        policy_digest: &str,
    ) -> Result<Option<ObjectSecurityPolicyRecord>, String>;

    fn activate_object_security_profile(
        &self,
        request: &ActivateObjectSecurityProfile,
        advertised_object_kinds: &[String],
        actor: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityWriteResult, String>;

    fn get_object_security_profile(
        &self,
        namespace: &str,
    ) -> Result<Option<ObjectSecurityProfile>, String>;

    fn object_security_kind_is_active(&self, object_kind: &str) -> Result<bool, String>;

    fn active_object_security_policies_for_kind(
        &self,
        object_kind: &str,
    ) -> Result<Vec<ObjectSecurityPolicyRecord>, String>;

    fn object_query_cursor_key(&self) -> Result<[u8; 32], String>;

    fn revoke_object_security_policy(
        &self,
        request: &RevokeObjectSecurityPolicy,
        actor: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityWriteResult, String>;

    fn get_active_object_security_policy(
        &self,
        namespace: &str,
        object_kind: &str,
    ) -> Result<Option<ObjectSecurityPolicyRecord>, String> {
        let Some(profile) = self.get_object_security_profile(namespace)? else {
            return Ok(None);
        };
        let Some(policy_digest) = profile.policy_digest_for(object_kind) else {
            return Err(
                "object_security_profile_invalid: active profile has no policy for object type"
                    .into(),
            );
        };
        self.get_object_security_policy(namespace, policy_digest)?
            .ok_or_else(|| {
                "object_security_policy_unavailable: active policy revision is unavailable".into()
            })
            .map(Some)
    }
}

macro_rules! forward {
    ($target:ty) => {
        fn create_object_security_policy(
            &self,
            input: &ObjectSecurityPolicyInput,
            actor: &str,
            now_ms: i64,
        ) -> Result<ObjectSecurityWriteResult, String> {
            <$target>::create_object_security_policy(self, input, actor, now_ms)
        }

        fn get_object_security_policy(
            &self,
            namespace: &str,
            policy_digest: &str,
        ) -> Result<Option<ObjectSecurityPolicyRecord>, String> {
            <$target>::get_object_security_policy(self, namespace, policy_digest)
        }

        fn activate_object_security_profile(
            &self,
            request: &ActivateObjectSecurityProfile,
            advertised_object_kinds: &[String],
            actor: &str,
            now_ms: i64,
        ) -> Result<ObjectSecurityWriteResult, String> {
            <$target>::activate_object_security_profile(
                self,
                request,
                advertised_object_kinds,
                actor,
                now_ms,
            )
        }

        fn get_object_security_profile(
            &self,
            namespace: &str,
        ) -> Result<Option<ObjectSecurityProfile>, String> {
            <$target>::get_object_security_profile(self, namespace)
        }

        fn object_security_kind_is_active(&self, object_kind: &str) -> Result<bool, String> {
            <$target>::object_security_kind_is_active(self, object_kind)
        }

        fn active_object_security_policies_for_kind(
            &self,
            object_kind: &str,
        ) -> Result<Vec<ObjectSecurityPolicyRecord>, String> {
            <$target>::active_object_security_policies_for_kind(self, object_kind)
        }

        fn object_query_cursor_key(&self) -> Result<[u8; 32], String> {
            <$target>::object_query_cursor_key(self)
        }

        fn revoke_object_security_policy(
            &self,
            request: &RevokeObjectSecurityPolicy,
            actor: &str,
            now_ms: i64,
        ) -> Result<ObjectSecurityWriteResult, String> {
            <$target>::revoke_object_security_policy(self, request, actor, now_ms)
        }
    };
}

impl ObjectSecurityBackend for SekaiDb {
    forward!(SekaiDb);
}

impl ObjectSecurityBackend for PostgresDb {
    forward!(PostgresDb);
}

impl SekaiDb {
    pub(crate) fn migrate_object_security(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_object_security_policies (
                    namespace TEXT NOT NULL,
                    object_kind TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, policy_digest),
                    UNIQUE(namespace, object_kind, revision)
                );
                CREATE INDEX IF NOT EXISTS idx_object_security_policy_kind
                    ON sekai_object_security_policies(namespace, object_kind, created_at_ms);

                CREATE TABLE IF NOT EXISTS sekai_object_security_revocations (
                    namespace TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    revoked_by TEXT NOT NULL,
                    revoked_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, policy_digest),
                    FOREIGN KEY(namespace, policy_digest)
                        REFERENCES sekai_object_security_policies(namespace, policy_digest)
                );

                CREATE TABLE IF NOT EXISTS sekai_object_security_profiles (
                    namespace TEXT PRIMARY KEY,
                    profile_digest TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    activated_by TEXT NOT NULL,
                    activated_at_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sekai_object_security_requests (
                    namespace TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, actor, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS sekai_object_security_audit (
                    event_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_digest TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    profile_digest TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_object_security_audit_namespace
                    ON sekai_object_security_audit(namespace, created_at_ms, event_id);

                CREATE TABLE IF NOT EXISTS sekai_object_security_runtime_secrets (
                    name TEXT PRIMARY KEY,
                    secret_value TEXT NOT NULL
                );",
            )
            .map_err(|error| error.to_string())
    }

    pub fn create_object_security_policy(
        &self,
        input: &ObjectSecurityPolicyInput,
        actor: &str,
        now_ms: i64,
    ) -> Result<ObjectSecurityWriteResult, String> {
        let policy = input.prepare(actor, now_ms)?;
        let request_digest = input.request_digest(actor, now_ms)?;
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(result) = replay_sqlite(
            &transaction,
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
            load_policy_sqlite(&transaction, &policy.namespace, &policy.policy_digest)?
        {
            let result = ObjectSecurityWriteResult::CreatePolicy { record: existing };
            persist_result_sqlite(
                &transaction,
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
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    policy.namespace,
                    policy.object_kind,
                    policy.revision,
                    policy.policy_digest,
                    body_json,
                    policy.created_by,
                    policy.created_at_ms,
                ],
            )
            .map_err(map_policy_constraint)?;
        let result = ObjectSecurityWriteResult::CreatePolicy {
            record: ObjectSecurityPolicyRecord {
                policy: policy.clone(),
                revocation: None,
            },
        };
        persist_result_sqlite(
            &transaction,
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
        load_policy_sqlite(&self.conn(), namespace, policy_digest)
    }

    pub fn replay_object_security_write(
        &self,
        namespace: &str,
        actor: &str,
        idempotency_key: &str,
        operation: &str,
        request_digest: &str,
    ) -> Result<Option<ObjectSecurityWriteResult>, String> {
        replay_sqlite(
            &self.conn(),
            namespace,
            actor,
            idempotency_key,
            operation,
            request_digest,
        )
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
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(result) = replay_sqlite(
            &transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            "activate_profile",
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }

        let current = load_profile_sqlite(&transaction, &request.namespace)?;
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
                load_policy_sqlite(&transaction, &profile.namespace, &binding.policy_digest)?
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
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(namespace) DO UPDATE SET
                    profile_digest=excluded.profile_digest,
                    body_json=excluded.body_json,
                    activated_by=excluded.activated_by,
                    activated_at_ms=excluded.activated_at_ms",
                params![
                    profile.namespace,
                    profile.profile_digest,
                    body_json,
                    profile.activated_by,
                    profile.activated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        let result = ObjectSecurityWriteResult::ActivateProfile {
            profile: profile.clone(),
        };
        persist_result_sqlite(
            &transaction,
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
        load_profile_sqlite(&self.conn(), namespace)
    }

    pub fn object_security_kind_is_active(&self, object_kind: &str) -> Result<bool, String> {
        self.conn()
            .query_row(
                "SELECT EXISTS (
                    SELECT 1
                    FROM sekai_object_security_profiles profile,
                         json_each(profile.body_json, '$.bindings') binding
                    WHERE json_extract(binding.value, '$.object_kind') = ?1
                )",
                params![object_kind],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }

    pub fn active_object_security_policies_for_kind(
        &self,
        object_kind: &str,
    ) -> Result<Vec<ObjectSecurityPolicyRecord>, String> {
        let connection = self.conn();
        let bindings = {
            let mut statement = connection
                .prepare(
                    "SELECT namespace, body_json
                     FROM sekai_object_security_profiles
                     ORDER BY namespace",
                )
                .map_err(|error| error.to_string())?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|error| error.to_string())?
                .map(|row| {
                    let (namespace, json) = row.map_err(|error| error.to_string())?;
                    let profile: ObjectSecurityProfile =
                        serde_json::from_str(&json).map_err(|error| error.to_string())?;
                    profile.verify()?;
                    Ok(profile
                        .policy_digest_for(object_kind)
                        .map(|digest| (namespace, digest.to_string())))
                })
                .collect::<Result<Vec<_>, String>>()?
        };
        bindings
            .into_iter()
            .flatten()
            .map(|(namespace, policy_digest)| {
                load_policy_sqlite(&connection, &namespace, &policy_digest)?.ok_or_else(|| {
                    "object_security_policy_unavailable: active policy revision is unavailable"
                        .into()
                })
            })
            .collect()
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
        let secret = existing.unwrap_or_else(|| {
            format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            )
        });
        transaction
            .execute(
                "INSERT OR IGNORE INTO sekai_object_security_runtime_secrets
                    (name, secret_value)
                 VALUES ('object_query_cursor_hmac', ?1)",
                params![secret],
            )
            .map_err(|error| error.to_string())?;
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
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(result) = replay_sqlite(
            &transaction,
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
            load_policy_sqlite(&transaction, &request.namespace, &request.policy_digest)?
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
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    revocation.namespace,
                    revocation.policy_digest,
                    body_json,
                    revocation.revoked_by,
                    revocation.revoked_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        record.revocation = Some(revocation);
        let result = ObjectSecurityWriteResult::RevokePolicy {
            record: record.clone(),
        };
        persist_result_sqlite(
            &transaction,
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

pub(crate) fn load_policy_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
    policy_digest: &str,
) -> Result<Option<ObjectSecurityPolicyRecord>, String> {
    connection
        .query_row(
            "SELECT policy.body_json, revocation.body_json
             FROM sekai_object_security_policies policy
             LEFT JOIN sekai_object_security_revocations revocation
               ON revocation.namespace=policy.namespace
              AND revocation.policy_digest=policy.policy_digest
             WHERE policy.namespace=?1 AND policy.policy_digest=?2",
            params![namespace, policy_digest],
            |row| {
                let policy_json: String = row.get(0)?;
                let revocation_json: Option<String> = row.get(1)?;
                Ok((policy_json, revocation_json))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|(policy_json, revocation_json)| {
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

pub(crate) fn load_profile_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
) -> Result<Option<ObjectSecurityProfile>, String> {
    connection
        .query_row(
            "SELECT body_json FROM sekai_object_security_profiles WHERE namespace=?1",
            params![namespace],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|json| {
            let profile: ObjectSecurityProfile =
                serde_json::from_str(&json).map_err(|error| error.to_string())?;
            profile.verify()?;
            Ok(profile)
        })
        .transpose()
}

fn replay_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
    actor: &str,
    idempotency_key: &str,
    operation: &str,
    request_digest: &str,
) -> Result<Option<ObjectSecurityWriteResult>, String> {
    let existing = connection
        .query_row(
            "SELECT operation, request_digest, result_json
             FROM sekai_object_security_requests
             WHERE namespace=?1 AND actor=?2 AND idempotency_key=?3",
            params![namespace, actor, idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((stored_operation, stored_digest, result_json)) = existing else {
        return Ok(None);
    };
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
fn persist_result_sqlite(
    transaction: &Transaction<'_>,
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
    transaction
        .execute(
            "INSERT INTO sekai_object_security_requests (
                namespace, actor, idempotency_key, operation, request_digest,
                result_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                namespace,
                actor,
                idempotency_key,
                operation,
                request_digest,
                result_json,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO sekai_object_security_audit (
                event_id, namespace, actor, action, target_digest, policy_digest,
                profile_digest, reason_code, request_digest, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                format!("object-security-{}", uuid::Uuid::new_v4().simple()),
                namespace,
                actor,
                operation,
                target_digest,
                policy_digest,
                profile_digest,
                reason_code,
                request_digest,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn map_policy_constraint(error: rusqlite::Error) -> String {
    if matches!(error, rusqlite::Error::SqliteFailure(_, _)) {
        "object_security_policy_conflict: revision identity is already in use".into()
    } else {
        error.to_string()
    }
}

pub(crate) fn cursor_key_from_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}
