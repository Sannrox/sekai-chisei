//! SQLite persistence for checkpointed definition fact migration.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::collections::{BTreeMap, HashMap};

use crate::db::object_security::load_active_policy_sqlite;
use crate::db::postgres::PostgresDb;
use crate::db::postgres_audit::insert_changes as insert_postgres_object_changes;
use crate::db::postgres_object_security::load_active_policy_postgres;
use crate::db::postgres_objects::postgres_object_security_filter;
use crate::db::sekai::{SekaiDb, sqlite_object_security_filter};
use crate::domain::{Object, storage_properties_json};
use crate::sekai::audit::{insert_object_changes, object_diff_changes};
use crate::sekai::definition_migration::{
    ExecuteFactMigration, FactMigrationResult, MODE_EXECUTE, MODE_ROLLBACK,
    PreparedObjectMigration, STATUS_COMMITTED, finish_migration_result, plan_fact_migration,
    require_ancestor, require_published_candidate,
};
use crate::sekai::definition_proposal::{DefinitionProposal, STATUS_MERGED};
use crate::sekai::object_security::{
    ObjectSecurityOperation, ObjectSecurityPolicy, PrincipalPolicyContext, PropertyGrantAccess,
};

impl SekaiDb {
    pub fn execute_definition_fact_migration(
        &self,
        request: &ExecuteFactMigration,
        actor: &str,
        policy_context: &PrincipalPolicyContext,
        now_ms: i64,
    ) -> Result<FactMigrationResult, String> {
        if actor.trim().is_empty() || now_ms <= 0 {
            return Err("canonical actor and now_ms required".into());
        }
        let request_digest = request.prepare()?;
        let policy_context = policy_context.clone().normalized();
        let mut connection = self.conn();
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(existing) = replay_migration_sqlite(
            &tx,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(existing);
        }
        if request.mode == MODE_ROLLBACK {
            let result = rollback_sqlite(
                &tx,
                request,
                actor,
                &policy_context,
                &request_digest,
                now_ms,
            )?;
            persist_migration_request_sqlite(
                &tx,
                request,
                actor,
                &request_digest,
                &result,
                now_ms,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        let from =
            load_revision_required_sqlite(&tx, &request.namespace, &request.from_revision_digest)?;
        let to =
            load_revision_required_sqlite(&tx, &request.namespace, &request.to_revision_digest)?;
        let from_members = load_members_sqlite(&tx, &request.namespace, &from.revision_digest)?;
        let to_members = load_members_sqlite(&tx, &request.namespace, &to.revision_digest)?;
        let published =
            load_published_digest_sqlite(&tx, &request.namespace)?.ok_or_else(|| {
                "definition_revision_not_found: published head is unavailable".to_string()
            })?;
        require_published_candidate(&published, &to)?;
        let ancestors = load_ancestors_sqlite(&tx, &to)?;
        require_ancestor(&from, &to, &ancestors)?;
        let objects = list_namespace_objects_sqlite(&tx, &request.namespace, &policy_context)?;
        let bindings = load_bindings_sqlite(&tx, &request.namespace)?;
        let (compatibility, mut planned) =
            plan_fact_migration(&from, &from_members, &to, &to_members, &objects, &bindings)?;
        for item in &mut planned {
            if item.outcome != "migrate" {
                continue;
            }
            let policy = load_active_policy_sqlite(&tx, &item.object.namespace, &item.object.kind)?;
            reconcile_planned_grants(policy.as_ref(), &policy_context, item)?;
        }
        if matches!(compatibility.class.as_str(), "breaking" | "conditional")
            && !has_merged_proposal_sqlite(
                &tx,
                &request.namespace,
                &request.from_revision_digest,
                &request.to_revision_digest,
            )?
        {
            return Err(
                "fact_migration_unapproved: breaking or conditional changes require a merged proposal"
                    .into(),
            );
        }
        let blocked = planned.iter().any(|item| item.outcome == "blocked");
        let executed = request.mode == MODE_EXECUTE && !blocked;
        if executed {
            for item in &planned {
                if item.outcome != "migrate" {
                    continue;
                }
                let mut updated = item.object.clone();
                updated.properties = item.after_properties.clone();
                updated.updated = now_ms;
                let policy = load_active_policy_sqlite(&tx, &updated.namespace, &updated.kind)?;
                if !apply_live_object_grants(
                    policy.as_ref(),
                    &policy_context,
                    &item.object,
                    &mut updated,
                )? {
                    return Err(
                        "object_security_denied: object is not granted for fact migration".into(),
                    );
                }
                let previous_binding = bindings
                    .get(&item.object.id)
                    .cloned()
                    .unwrap_or_else(|| from.revision_digest.clone());
                tx.execute(
                    "INSERT OR REPLACE INTO sekai_fact_migration_snapshots
                     (namespace, migration_id, object_id, properties_json, revision_digest)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        request.namespace,
                        request.migration_id,
                        item.object.id,
                        storage_properties_json(&item.object.properties)?,
                        previous_binding
                    ],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "UPDATE sekai_objects SET properties=?2, updated=?3 WHERE id=?1",
                    params![
                        updated.id,
                        storage_properties_json(&updated.properties)?,
                        updated.updated
                    ],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "INSERT INTO sekai_object_revision_bindings
                     (object_id, namespace, revision_digest) VALUES (?1, ?2, ?3)
                     ON CONFLICT(object_id) DO UPDATE SET revision_digest=excluded.revision_digest",
                    params![item.object.id, request.namespace, to.revision_digest],
                )
                .map_err(|error| error.to_string())?;
                insert_object_changes(
                    &tx,
                    &object_diff_changes(actor, Some(&item.object), Some(&updated), now_ms),
                )?;
            }
        }
        let result = finish_migration_result(
            request,
            &compatibility,
            &planned,
            actor,
            now_ms,
            executed,
            false,
        )?;
        tx.execute(
            "INSERT INTO sekai_fact_migrations
             (namespace, migration_id, result_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace, migration_id) DO UPDATE SET
                result_json=excluded.result_json",
            params![
                request.namespace,
                request.migration_id,
                serde_json::to_string(&result).map_err(|error| error.to_string())?,
                now_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        persist_migration_request_sqlite(&tx, request, actor, &request_digest, &result, now_ms)?;
        if executed {
            insert_migration_audit_sqlite(
                &tx,
                request,
                actor,
                MODE_EXECUTE,
                &request_digest,
                &result.result_digest,
                now_ms,
            )?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn get_definition_fact_migration(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<Option<FactMigrationResult>, String> {
        self.conn()
            .query_row(
                "SELECT result_json FROM sekai_fact_migrations
                 WHERE namespace=?1 AND migration_id=?2",
                params![namespace, migration_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn count_definition_fact_migration_audit(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<i64, String> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_fact_migration_audit
                 WHERE namespace=?1 AND migration_id=?2",
                params![namespace, migration_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())
    }
}

fn replay_migration_sqlite(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
    actor: &str,
    key: &str,
    request_digest: &str,
) -> Result<Option<FactMigrationResult>, String> {
    let stored = tx
        .query_row(
            "SELECT request_digest, result_json FROM sekai_fact_migration_requests
             WHERE namespace=?1 AND actor=?2 AND idempotency_key=?3",
            params![namespace, actor, key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    match stored {
        Some((digest, json)) if digest == request_digest => serde_json::from_str(&json)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(_) => {
            Err("definition_idempotency_conflict: key is bound to different canonical input".into())
        }
        None => Ok(None),
    }
}

fn persist_migration_request_sqlite(
    tx: &rusqlite::Transaction<'_>,
    request: &ExecuteFactMigration,
    actor: &str,
    request_digest: &str,
    result: &FactMigrationResult,
    now_ms: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_fact_migration_requests
         (namespace, actor, idempotency_key, request_digest, result_json, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            request.namespace,
            actor,
            request.idempotency_key,
            request_digest,
            serde_json::to_string(result).map_err(|error| error.to_string())?,
            now_ms
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn migration_audit_event_id(request_digest: &str, actor: &str, idempotency_key: &str) -> String {
    format!("fact-migration-audit:{request_digest}:{actor}:{idempotency_key}")
}

fn require_rollback_identity(
    request: &ExecuteFactMigration,
    stored: &FactMigrationResult,
) -> Result<(), String> {
    if stored.from_revision_digest != request.from_revision_digest
        || stored.to_revision_digest != request.to_revision_digest
    {
        return Err(
            "fact_migration_revision_mismatch: rollback must name the stored parent and candidate"
                .into(),
        );
    }
    Ok(())
}

fn apply_live_object_grants(
    policy: Option<&ObjectSecurityPolicy>,
    context: &PrincipalPolicyContext,
    existing: &Object,
    object: &mut Object,
) -> Result<bool, String> {
    let Some(policy) = policy else {
        return Ok(true);
    };
    if !policy.allows(context, existing, ObjectSecurityOperation::Read) {
        return Ok(false);
    }
    policy.apply_property_grant_mutation(Some(existing), object)?;
    preserve_policy_driving_properties(policy, existing, object);
    if !policy.allows(context, object, ObjectSecurityOperation::Read) {
        return Ok(false);
    }
    Ok(true)
}

fn preserve_policy_driving_properties(
    policy: &ObjectSecurityPolicy,
    existing: &Object,
    object: &mut Object,
) {
    for property in policy.policy_driving_properties() {
        if let Some(value) = existing.properties.get(&property) {
            object.properties.insert(property, value.clone());
        }
    }
}

fn reconcile_planned_grants(
    policy: Option<&ObjectSecurityPolicy>,
    context: &PrincipalPolicyContext,
    item: &mut PreparedObjectMigration,
) -> Result<(), String> {
    let mut updated = item.object.clone();
    updated.properties = item.after_properties.clone();
    if !apply_live_object_grants(policy, context, &item.object, &mut updated)? {
        return Err("object_security_denied: object is not granted for fact migration".into());
    }
    item.after_properties = updated.properties;
    item.stripped_properties = item
        .object
        .properties
        .keys()
        .filter(|key| !item.after_properties.contains_key(*key))
        .cloned()
        .collect();
    item.stripped_properties.sort();
    Ok(())
}

fn restore_snapshot_properties(
    policy: Option<&ObjectSecurityPolicy>,
    context: &PrincipalPolicyContext,
    current: &Object,
    snapshot: HashMap<String, String>,
) -> Result<HashMap<String, String>, String> {
    let Some(policy) = policy else {
        return Ok(snapshot);
    };
    if !policy.allows(context, current, ObjectSecurityOperation::Read) {
        return Err(
            "fact_migration_rollback_denied: snapshot cannot be restored under live grants".into(),
        );
    }
    if policy.property_grants_enforced() {
        let mut keys = current.properties.keys().cloned().collect::<Vec<_>>();
        keys.extend(snapshot.keys().cloned());
        keys.sort();
        keys.dedup();
        for key in keys {
            if current.properties.get(&key) != snapshot.get(&key)
                && !policy.allows_property_access(&key, PropertyGrantAccess::Write)
            {
                return Err(
                    "fact_migration_rollback_denied: snapshot cannot be restored under live grants"
                        .into(),
                );
            }
        }
    }
    Ok(snapshot)
}

fn insert_migration_audit_sqlite(
    tx: &rusqlite::Transaction<'_>,
    request: &ExecuteFactMigration,
    actor: &str,
    action: &str,
    request_digest: &str,
    result_digest: &str,
    now_ms: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO sekai_fact_migration_audit (
            event_id, namespace, migration_id, actor, action,
            from_revision_digest, to_revision_digest, request_digest, result_digest, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            migration_audit_event_id(request_digest, actor, &request.idempotency_key),
            request.namespace,
            request.migration_id,
            actor,
            action,
            request.from_revision_digest,
            request.to_revision_digest,
            request_digest,
            result_digest,
            now_ms
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn rollback_sqlite(
    tx: &rusqlite::Transaction<'_>,
    request: &ExecuteFactMigration,
    actor: &str,
    policy_context: &PrincipalPolicyContext,
    request_digest: &str,
    now_ms: i64,
) -> Result<FactMigrationResult, String> {
    let mut stored: FactMigrationResult = tx
        .query_row(
            "SELECT result_json FROM sekai_fact_migrations
             WHERE namespace=?1 AND migration_id=?2",
            params![request.namespace, request.migration_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "fact_migration_not_found: migration is unavailable".to_string())
        .and_then(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))?;
    if stored.status != STATUS_COMMITTED {
        return Err(
            "fact_migration_not_committed: only a committed migration can roll back".into(),
        );
    }
    require_rollback_identity(request, &stored)?;
    let mut statement = tx
        .prepare(
            "SELECT object_id, properties_json, revision_digest FROM sekai_fact_migration_snapshots
             WHERE namespace=?1 AND migration_id=?2 ORDER BY object_id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![request.namespace, request.migration_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    drop(statement);
    for (object_id, properties_json, revision_digest) in rows {
        let Some(current) = load_visible_object_sqlite(tx, &object_id, policy_context)? else {
            return Err(
                "fact_migration_rollback_denied: snapshot cannot be restored under live grants"
                    .into(),
            );
        };
        let snapshot_properties: HashMap<String, String> =
            serde_json::from_str(&properties_json).map_err(|error| error.to_string())?;
        let policy = load_active_policy_sqlite(tx, &current.namespace, &current.kind)?;
        let mut restored = current.clone();
        restored.properties = restore_snapshot_properties(
            policy.as_ref(),
            policy_context,
            &current,
            snapshot_properties,
        )?;
        restored.updated = now_ms;
        tx.execute(
            "UPDATE sekai_objects SET properties=?2, updated=?3 WHERE id=?1",
            params![
                restored.id,
                storage_properties_json(&restored.properties)?,
                restored.updated
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_object_revision_bindings
             (object_id, namespace, revision_digest) VALUES (?1, ?2, ?3)
             ON CONFLICT(object_id) DO UPDATE SET revision_digest=excluded.revision_digest",
            params![object_id, request.namespace, revision_digest],
        )
        .map_err(|error| error.to_string())?;
        insert_object_changes(
            tx,
            &object_diff_changes(actor, Some(&current), Some(&restored), now_ms),
        )?;
    }
    stored.mode = MODE_ROLLBACK.into();
    stored.status = crate::sekai::definition_migration::STATUS_ROLLED_BACK.into();
    stored.actor = actor.into();
    stored.updated_at_ms = now_ms;
    stored.result_digest = String::new();
    stored.result_digest = {
        let encoded = serde_json::to_vec(&stored).map_err(|error| error.to_string())?;
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"fact_migration_result");
        hasher.update([0]);
        hasher.update(encoded);
        format!("sha256:{:x}", hasher.finalize())
    };
    tx.execute(
        "INSERT INTO sekai_fact_migrations
         (namespace, migration_id, result_json, created_at_ms)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(namespace, migration_id) DO UPDATE SET result_json=excluded.result_json",
        params![
            request.namespace,
            request.migration_id,
            serde_json::to_string(&stored).map_err(|error| error.to_string())?,
            now_ms
        ],
    )
    .map_err(|error| error.to_string())?;
    insert_migration_audit_sqlite(
        tx,
        request,
        actor,
        MODE_ROLLBACK,
        request_digest,
        &stored.result_digest,
        now_ms,
    )?;
    Ok(stored)
}

fn load_revision_required_sqlite(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
    digest: &str,
) -> Result<crate::sekai::definition_branch::DefinitionRevision, String> {
    let body: String = tx
        .query_row(
            "SELECT body_json FROM sekai_definition_revisions
             WHERE namespace=?1 AND revision_digest=?2",
            params![namespace, digest],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "definition_revision_not_found: revision is unavailable".to_string())?;
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

fn load_members_sqlite(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
    digest: &str,
) -> Result<Vec<crate::sekai::definition_branch::DefinitionMember>, String> {
    let revision = load_revision_required_sqlite(tx, namespace, digest)?;
    let mut members = Vec::new();
    for member in revision.members {
        let body: String = tx
            .query_row(
                "SELECT body_json FROM sekai_definition_members
                 WHERE namespace=?1 AND member_digest=?2",
                params![namespace, member.member_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "definition_member_not_found: member is unavailable".to_string())?;
        members.push(serde_json::from_str(&body).map_err(|error| error.to_string())?);
    }
    Ok(members)
}

fn load_published_digest_sqlite(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
) -> Result<Option<String>, String> {
    tx.query_row(
        "SELECT revision_digest FROM sekai_definition_published_heads WHERE namespace=?1",
        params![namespace],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn load_ancestors_sqlite(
    tx: &rusqlite::Transaction<'_>,
    to: &crate::sekai::definition_branch::DefinitionRevision,
) -> Result<Vec<crate::sekai::definition_branch::DefinitionRevision>, String> {
    let mut ancestors = Vec::new();
    let mut current = to.parent_revision_digest.clone();
    for _ in 0..4_096 {
        if current.is_empty() {
            break;
        }
        let Ok(revision) = load_revision_required_sqlite(tx, &to.namespace, &current) else {
            break;
        };
        current = revision.parent_revision_digest.clone();
        ancestors.push(revision);
    }
    Ok(ancestors)
}

fn list_namespace_objects_sqlite(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
    policy_context: &PrincipalPolicyContext,
) -> Result<Vec<Object>, String> {
    let subjects =
        serde_json::to_string(&policy_context.subjects).map_err(|error| error.to_string())?;
    let scopes =
        serde_json::to_string(&policy_context.scopes).map_err(|error| error.to_string())?;
    let mut statement = tx
        .prepare(&format!(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated
             FROM sekai_objects WHERE namespace=?1{} ORDER BY id",
            sqlite_object_security_filter(1)
        ))
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![namespace, subjects, scopes], |row| {
            let properties: String = row.get(5)?;
            Ok(Object {
                id: row.get(0)?,
                kind: row.get(1)?,
                name: row.get(2)?,
                namespace: row.get(3)?,
                external_id: row.get(4)?,
                properties: serde_json::from_str(&properties).unwrap_or_default(),
                created: row.get(6)?,
                updated: row.get(7)?,
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(rows)
}

fn load_visible_object_sqlite(
    tx: &rusqlite::Transaction<'_>,
    object_id: &str,
    policy_context: &PrincipalPolicyContext,
) -> Result<Option<Object>, String> {
    let subjects =
        serde_json::to_string(&policy_context.subjects).map_err(|error| error.to_string())?;
    let scopes =
        serde_json::to_string(&policy_context.scopes).map_err(|error| error.to_string())?;
    tx.query_row(
        &format!(
            "SELECT id, kind, name, namespace, external_id, properties, created, updated
             FROM sekai_objects WHERE id=?1{}",
            sqlite_object_security_filter(1)
        ),
        params![object_id, subjects, scopes],
        |row| {
            let properties: String = row.get(5)?;
            Ok(Object {
                id: row.get(0)?,
                kind: row.get(1)?,
                name: row.get(2)?,
                namespace: row.get(3)?,
                external_id: row.get(4)?,
                properties: serde_json::from_str(&properties).unwrap_or_default(),
                created: row.get(6)?,
                updated: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(|error| error.to_string())
}

fn load_bindings_sqlite(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
) -> Result<BTreeMap<String, String>, String> {
    let mut statement = tx
        .prepare(
            "SELECT object_id, revision_digest FROM sekai_object_revision_bindings
             WHERE namespace=?1",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![namespace], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(rows.into_iter().collect())
}

fn has_merged_proposal_sqlite(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
    from_digest: &str,
    to_digest: &str,
) -> Result<bool, String> {
    let mut statement = tx
        .prepare(
            "SELECT body_json FROM sekai_definition_proposals
             WHERE namespace=?1 AND status=?2",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![namespace, STATUS_MERGED], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    for body in rows {
        let proposal: DefinitionProposal =
            serde_json::from_str(&body).map_err(|error| error.to_string())?;
        if proposal.base_digest == from_digest && proposal.candidate_digest == to_digest {
            return Ok(true);
        }
    }
    Ok(false)
}

impl PostgresDb {
    pub fn execute_definition_fact_migration(
        &self,
        request: &ExecuteFactMigration,
        actor: &str,
        policy_context: &PrincipalPolicyContext,
        now_ms: i64,
    ) -> Result<FactMigrationResult, String> {
        if actor.trim().is_empty() || now_ms <= 0 {
            return Err("canonical actor and now_ms required".into());
        }
        let request_digest = request.prepare()?;
        let policy_context = policy_context.clone().normalized();
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if let Some(existing) = replay_migration_postgres(
            &mut tx,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(existing);
        }
        if request.mode == MODE_ROLLBACK {
            let result = rollback_postgres(
                &mut tx,
                request,
                actor,
                &policy_context,
                &request_digest,
                now_ms,
            )?;
            persist_migration_request_postgres(
                &mut tx,
                request,
                actor,
                &request_digest,
                &result,
                now_ms,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(result);
        }
        let from = load_revision_required_postgres(
            &mut tx,
            &request.namespace,
            &request.from_revision_digest,
        )?;
        let to = load_revision_required_postgres(
            &mut tx,
            &request.namespace,
            &request.to_revision_digest,
        )?;
        let from_members =
            load_members_postgres(&mut tx, &request.namespace, &from.revision_digest)?;
        let to_members = load_members_postgres(&mut tx, &request.namespace, &to.revision_digest)?;
        let published =
            load_published_digest_postgres(&mut tx, &request.namespace)?.ok_or_else(|| {
                "definition_revision_not_found: published head is unavailable".to_string()
            })?;
        require_published_candidate(&published, &to)?;
        let ancestors = load_ancestors_postgres(&mut tx, &to)?;
        require_ancestor(&from, &to, &ancestors)?;
        let objects =
            list_namespace_objects_postgres(&mut tx, &request.namespace, &policy_context)?;
        let bindings = load_bindings_postgres(&mut tx, &request.namespace)?;
        let (compatibility, mut planned) =
            plan_fact_migration(&from, &from_members, &to, &to_members, &objects, &bindings)?;
        for item in &mut planned {
            if item.outcome != "migrate" {
                continue;
            }
            let policy =
                load_active_policy_postgres(&mut tx, &item.object.namespace, &item.object.kind)?;
            reconcile_planned_grants(policy.as_ref(), &policy_context, item)?;
        }
        if matches!(compatibility.class.as_str(), "breaking" | "conditional")
            && !has_merged_proposal_postgres(
                &mut tx,
                &request.namespace,
                &request.from_revision_digest,
                &request.to_revision_digest,
            )?
        {
            return Err(
                "fact_migration_unapproved: breaking or conditional changes require a merged proposal"
                    .into(),
            );
        }
        let blocked = planned.iter().any(|item| item.outcome == "blocked");
        let executed = request.mode == MODE_EXECUTE && !blocked;
        if executed {
            for item in &planned {
                if item.outcome != "migrate" {
                    continue;
                }
                let mut updated = item.object.clone();
                updated.properties = item.after_properties.clone();
                updated.updated = now_ms;
                let policy =
                    load_active_policy_postgres(&mut tx, &updated.namespace, &updated.kind)?;
                if !apply_live_object_grants(
                    policy.as_ref(),
                    &policy_context,
                    &item.object,
                    &mut updated,
                )? {
                    return Err(
                        "object_security_denied: object is not granted for fact migration".into(),
                    );
                }
                let previous_binding = bindings
                    .get(&item.object.id)
                    .cloned()
                    .unwrap_or_else(|| from.revision_digest.clone());
                let snapshot = storage_properties_json(&item.object.properties)?;
                tx.execute(
                    "INSERT INTO sekai_fact_migration_snapshots
                     (namespace, migration_id, object_id, properties_json, revision_digest)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (namespace, migration_id, object_id) DO UPDATE SET
                        properties_json = EXCLUDED.properties_json,
                        revision_digest = EXCLUDED.revision_digest",
                    &[
                        &request.namespace,
                        &request.migration_id,
                        &item.object.id,
                        &snapshot,
                        &previous_binding,
                    ],
                )
                .map_err(|error| error.to_string())?;
                let properties = storage_properties_json(&updated.properties)?;
                tx.execute(
                    "UPDATE sekai_objects SET properties=$2, updated=$3 WHERE id=$1",
                    &[&updated.id, &properties, &updated.updated],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "INSERT INTO sekai_object_revision_bindings
                     (object_id, namespace, revision_digest) VALUES ($1, $2, $3)
                     ON CONFLICT (object_id) DO UPDATE SET revision_digest = EXCLUDED.revision_digest",
                    &[&item.object.id, &request.namespace, &to.revision_digest],
                )
                .map_err(|error| error.to_string())?;
                insert_postgres_object_changes(
                    &mut tx,
                    &object_diff_changes(actor, Some(&item.object), Some(&updated), now_ms),
                )?;
            }
        }
        let result = finish_migration_result(
            request,
            &compatibility,
            &planned,
            actor,
            now_ms,
            executed,
            false,
        )?;
        let result_json = serde_json::to_string(&result).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_fact_migrations
             (namespace, migration_id, result_json, created_at_ms)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (namespace, migration_id) DO UPDATE SET result_json = EXCLUDED.result_json",
            &[
                &request.namespace,
                &request.migration_id,
                &result_json,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        persist_migration_request_postgres(
            &mut tx,
            request,
            actor,
            &request_digest,
            &result,
            now_ms,
        )?;
        if executed {
            insert_migration_audit_postgres(
                &mut tx,
                request,
                actor,
                MODE_EXECUTE,
                &request_digest,
                &result.result_digest,
                now_ms,
            )?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn get_definition_fact_migration(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<Option<FactMigrationResult>, String> {
        self.connection()?
            .query_opt(
                "SELECT result_json FROM sekai_fact_migrations
                 WHERE namespace=$1 AND migration_id=$2",
                &[&namespace, &migration_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .transpose()
    }

    pub fn count_definition_fact_migration_audit(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<i64, String> {
        let row = self
            .connection()?
            .query_one(
                "SELECT COUNT(*) FROM sekai_fact_migration_audit
                 WHERE namespace=$1 AND migration_id=$2",
                &[&namespace, &migration_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(row.get(0))
    }
}

fn replay_migration_postgres(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    actor: &str,
    key: &str,
    request_digest: &str,
) -> Result<Option<FactMigrationResult>, String> {
    let stored = tx
        .query_opt(
            "SELECT request_digest, result_json FROM sekai_fact_migration_requests
             WHERE namespace=$1 AND actor=$2 AND idempotency_key=$3",
            &[&namespace, &actor, &key],
        )
        .map_err(|error| error.to_string())?;
    match stored {
        Some(row) => {
            let digest: String = row.get(0);
            let json: String = row.get(1);
            if digest != request_digest {
                return Err(
                    "definition_idempotency_conflict: key is bound to different canonical input"
                        .into(),
                );
            }
            serde_json::from_str(&json)
                .map(Some)
                .map_err(|error| error.to_string())
        }
        None => Ok(None),
    }
}

fn persist_migration_request_postgres(
    tx: &mut postgres::Transaction<'_>,
    request: &ExecuteFactMigration,
    actor: &str,
    request_digest: &str,
    result: &FactMigrationResult,
    now_ms: i64,
) -> Result<(), String> {
    let result_json = serde_json::to_string(result).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_fact_migration_requests
         (namespace, actor, idempotency_key, request_digest, result_json, created_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &request.namespace,
            &actor,
            &request.idempotency_key,
            &request_digest,
            &result_json,
            &now_ms,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn insert_migration_audit_postgres(
    tx: &mut postgres::Transaction<'_>,
    request: &ExecuteFactMigration,
    actor: &str,
    action: &str,
    request_digest: &str,
    result_digest: &str,
    now_ms: i64,
) -> Result<(), String> {
    let event_id = migration_audit_event_id(request_digest, actor, &request.idempotency_key);
    tx.execute(
        "INSERT INTO sekai_fact_migration_audit (
            event_id, namespace, migration_id, actor, action,
            from_revision_digest, to_revision_digest, request_digest, result_digest, created_at_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[
            &event_id,
            &request.namespace,
            &request.migration_id,
            &actor,
            &action,
            &request.from_revision_digest,
            &request.to_revision_digest,
            &request_digest,
            &result_digest,
            &now_ms,
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn rollback_postgres(
    tx: &mut postgres::Transaction<'_>,
    request: &ExecuteFactMigration,
    actor: &str,
    policy_context: &PrincipalPolicyContext,
    request_digest: &str,
    now_ms: i64,
) -> Result<FactMigrationResult, String> {
    let row = tx
        .query_opt(
            "SELECT result_json FROM sekai_fact_migrations
             WHERE namespace=$1 AND migration_id=$2",
            &[&request.namespace, &request.migration_id],
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "fact_migration_not_found: migration is unavailable".to_string())?;
    let json: String = row.get(0);
    let mut stored: FactMigrationResult =
        serde_json::from_str(&json).map_err(|error| error.to_string())?;
    if stored.status != STATUS_COMMITTED {
        return Err(
            "fact_migration_not_committed: only a committed migration can roll back".into(),
        );
    }
    require_rollback_identity(request, &stored)?;
    let rows = tx
        .query(
            "SELECT object_id, properties_json, revision_digest FROM sekai_fact_migration_snapshots
             WHERE namespace=$1 AND migration_id=$2 ORDER BY object_id",
            &[&request.namespace, &request.migration_id],
        )
        .map_err(|error| error.to_string())?;
    for row in rows {
        let object_id: String = row.get(0);
        let properties_json: String = row.get(1);
        let revision_digest: String = row.get(2);
        let Some(current) = load_visible_object_postgres(tx, &object_id, policy_context)? else {
            return Err(
                "fact_migration_rollback_denied: snapshot cannot be restored under live grants"
                    .into(),
            );
        };
        let snapshot_properties: HashMap<String, String> =
            serde_json::from_str(&properties_json).map_err(|error| error.to_string())?;
        let policy = load_active_policy_postgres(tx, &current.namespace, &current.kind)?;
        let mut restored = current.clone();
        restored.properties = restore_snapshot_properties(
            policy.as_ref(),
            policy_context,
            &current,
            snapshot_properties,
        )?;
        restored.updated = now_ms;
        let properties = storage_properties_json(&restored.properties)?;
        tx.execute(
            "UPDATE sekai_objects SET properties=$2, updated=$3 WHERE id=$1",
            &[&restored.id, &properties, &restored.updated],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_object_revision_bindings
             (object_id, namespace, revision_digest) VALUES ($1, $2, $3)
             ON CONFLICT (object_id) DO UPDATE SET revision_digest = EXCLUDED.revision_digest",
            &[&object_id, &request.namespace, &revision_digest],
        )
        .map_err(|error| error.to_string())?;
        insert_postgres_object_changes(
            tx,
            &object_diff_changes(actor, Some(&current), Some(&restored), now_ms),
        )?;
    }
    stored.mode = MODE_ROLLBACK.into();
    stored.status = crate::sekai::definition_migration::STATUS_ROLLED_BACK.into();
    stored.actor = actor.into();
    stored.updated_at_ms = now_ms;
    stored.result_digest = String::new();
    stored.result_digest = {
        let encoded = serde_json::to_vec(&stored).map_err(|error| error.to_string())?;
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"fact_migration_result");
        hasher.update([0]);
        hasher.update(encoded);
        format!("sha256:{:x}", hasher.finalize())
    };
    let result_json = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_fact_migrations
         (namespace, migration_id, result_json, created_at_ms)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (namespace, migration_id) DO UPDATE SET result_json = EXCLUDED.result_json",
        &[
            &request.namespace,
            &request.migration_id,
            &result_json,
            &now_ms,
        ],
    )
    .map_err(|error| error.to_string())?;
    insert_migration_audit_postgres(
        tx,
        request,
        actor,
        MODE_ROLLBACK,
        request_digest,
        &stored.result_digest,
        now_ms,
    )?;
    Ok(stored)
}

fn load_revision_required_postgres(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    digest: &str,
) -> Result<crate::sekai::definition_branch::DefinitionRevision, String> {
    let row = tx
        .query_opt(
            "SELECT body_json FROM sekai_definition_revisions
             WHERE namespace=$1 AND revision_digest=$2",
            &[&namespace, &digest],
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "definition_revision_not_found: revision is unavailable".to_string())?;
    let body: String = row.get(0);
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

fn load_members_postgres(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    digest: &str,
) -> Result<Vec<crate::sekai::definition_branch::DefinitionMember>, String> {
    let revision = load_revision_required_postgres(tx, namespace, digest)?;
    let mut members = Vec::new();
    for member in revision.members {
        let row = tx
            .query_opt(
                "SELECT body_json FROM sekai_definition_members
                 WHERE namespace=$1 AND member_digest=$2",
                &[&namespace, &member.member_digest],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "definition_member_not_found: member is unavailable".to_string())?;
        let body: String = row.get(0);
        members.push(serde_json::from_str(&body).map_err(|error| error.to_string())?);
    }
    Ok(members)
}

fn load_published_digest_postgres(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
) -> Result<Option<String>, String> {
    Ok(tx
        .query_opt(
            "SELECT revision_digest FROM sekai_definition_published_heads WHERE namespace=$1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0)))
}

fn load_ancestors_postgres(
    tx: &mut postgres::Transaction<'_>,
    to: &crate::sekai::definition_branch::DefinitionRevision,
) -> Result<Vec<crate::sekai::definition_branch::DefinitionRevision>, String> {
    let mut ancestors = Vec::new();
    let mut current = to.parent_revision_digest.clone();
    for _ in 0..4_096 {
        if current.is_empty() {
            break;
        }
        let Ok(revision) = load_revision_required_postgres(tx, &to.namespace, &current) else {
            break;
        };
        current = revision.parent_revision_digest.clone();
        ancestors.push(revision);
    }
    Ok(ancestors)
}

fn list_namespace_objects_postgres(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    policy_context: &PrincipalPolicyContext,
) -> Result<Vec<Object>, String> {
    let sql = format!(
        "SELECT id, kind, name, namespace, external_id, properties, created, updated
         FROM sekai_objects o WHERE o.namespace=$1{} ORDER BY o.id",
        postgres_object_security_filter("$2", "$3")
    );
    let rows = tx
        .query(
            &sql,
            &[&namespace, &policy_context.subjects, &policy_context.scopes],
        )
        .map_err(|error| error.to_string())?;
    rows.into_iter()
        .map(|row| {
            let properties_json: String = row.get(5);
            Ok(Object {
                id: row.get(0),
                kind: row.get(1),
                name: row.get(2),
                namespace: row.get(3),
                external_id: row.get(4),
                properties: serde_json::from_str(&properties_json).unwrap_or_default(),
                created: row.get(6),
                updated: row.get(7),
            })
        })
        .collect()
}

fn load_visible_object_postgres(
    tx: &mut postgres::Transaction<'_>,
    object_id: &str,
    policy_context: &PrincipalPolicyContext,
) -> Result<Option<Object>, String> {
    let sql = format!(
        "SELECT id, kind, name, namespace, external_id, properties, created, updated
         FROM sekai_objects o WHERE o.id=$1{}",
        postgres_object_security_filter("$2", "$3")
    );
    tx.query_opt(
        &sql,
        &[&object_id, &policy_context.subjects, &policy_context.scopes],
    )
    .map_err(|error| error.to_string())?
    .map(|row| {
        let properties_json: String = row.get(5);
        Ok(Object {
            id: row.get(0),
            kind: row.get(1),
            name: row.get(2),
            namespace: row.get(3),
            external_id: row.get(4),
            properties: serde_json::from_str(&properties_json).unwrap_or_default(),
            created: row.get(6),
            updated: row.get(7),
        })
    })
    .transpose()
}

fn load_bindings_postgres(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
) -> Result<BTreeMap<String, String>, String> {
    let rows = tx
        .query(
            "SELECT object_id, revision_digest FROM sekai_object_revision_bindings
             WHERE namespace=$1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?;
    Ok(rows
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect())
}

fn has_merged_proposal_postgres(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
    from_digest: &str,
    to_digest: &str,
) -> Result<bool, String> {
    let rows = tx
        .query(
            "SELECT body_json FROM sekai_definition_proposals
             WHERE namespace=$1 AND status=$2",
            &[&namespace, &STATUS_MERGED],
        )
        .map_err(|error| error.to_string())?;
    for row in rows {
        let body: String = row.get(0);
        let proposal: DefinitionProposal =
            serde_json::from_str(&body).map_err(|error| error.to_string())?;
        if proposal.base_digest == from_digest && proposal.candidate_digest == to_digest {
            return Ok(true);
        }
    }
    Ok(false)
}
