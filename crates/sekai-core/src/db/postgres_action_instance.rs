//! PostgreSQL ActionInstance store (#397).

use crate::db::postgres::PostgresDb;
use crate::db::postgres_audit::{
    insert_created_object_in, lock_object_lifecycle, row_to_object, update_object_in,
};
use crate::sekai::action_instance::{
    ActionInstance, AdmissionLease, AdmissionUndo, FencedAdmissionWrite, ParkedGrantOutcome,
    ParkedGrantWrite, STATUS_PARKED, object_state_digest,
};

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
        self.list_action_instances_page(namespace, type_id, status, limit, 0)
    }

    pub fn list_action_instances_page(
        &self,
        namespace: &str,
        type_id: Option<&str>,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ActionInstance>, String> {
        let limit = limit.clamp(1, 500) as i64;
        let offset = i64::try_from(offset).map_err(|_| "action instance offset overflow")?;
        let type_filter = type_id.filter(|t| !t.trim().is_empty());
        let status_filter = status.filter(|s| !s.trim().is_empty());
        let rows = match (type_filter, status_filter) {
            (Some(type_id), Some(status)) => self.connection()?.query(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1 AND type_id = $2 AND status = $3
                 ORDER BY created_at_ms DESC, instance_id DESC LIMIT $4 OFFSET $5",
                &[&namespace, &type_id, &status, &limit, &offset],
            ),
            (Some(type_id), None) => self.connection()?.query(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1 AND type_id = $2
                 ORDER BY created_at_ms DESC, instance_id DESC LIMIT $3 OFFSET $4",
                &[&namespace, &type_id, &limit, &offset],
            ),
            (None, Some(status)) => self.connection()?.query(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1 AND status = $2
                 ORDER BY created_at_ms DESC, instance_id DESC LIMIT $3 OFFSET $4",
                &[&namespace, &status, &limit, &offset],
            ),
            (None, None) => self.connection()?.query(
                "SELECT body_json FROM sekai_action_instances
                 WHERE namespace = $1
                 ORDER BY created_at_ms DESC, instance_id DESC LIMIT $2 OFFSET $3",
                &[&namespace, &limit, &offset],
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

    pub fn delete_action_instance(&self, instance_id: &str) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM sekai_action_instances WHERE instance_id = $1",
                &[&instance_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Applies an admission's object write only while `lease` still names the
    /// reservation's owner and generation and has not expired (#1930). A
    /// takeover bumps the generation, so a stale owner's write is refused.
    /// Each of `references` must still be stored as planning read it (#1941).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_admission_object_write(
        &self,
        instance_id: &str,
        lease: &AdmissionLease,
        write: &ParkedGrantWrite,
        expected: Option<&crate::domain::Object>,
        references: &[crate::domain::Object],
        actor: &str,
        attribution: &crate::sekai::audit::ChangeAttribution,
    ) -> Result<FencedAdmissionWrite<Option<crate::domain::Object>>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if !postgres_admission_fence_holds(&mut tx, instance_id, lease, true)? {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
        // Each reference must be stored as planning read it, and stays so
        // until commit: `FOR SHARE` holds off a concurrent change (#1941).
        // Ids in order, so two admissions lock in one order.
        let mut ordered: Vec<&crate::domain::Object> = references.iter().collect();
        ordered.sort_by(|left, right| left.id.cmp(&right.id));
        for reference in ordered {
            let current = tx
                .query_opt(
                    &format!(
                        "SELECT {} FROM sekai_objects WHERE id = $1 FOR SHARE",
                        crate::db::postgres_audit::OBJECT_COLUMNS
                    ),
                    &[&reference.id],
                )
                .map_err(|error| error.to_string())?
                .map(row_to_object)
                .transpose()?;
            if !current.is_some_and(|current| current.persisted_state_matches(reference)) {
                return Err(format!(
                    "{}{}",
                    crate::sekai::action_instance::REFERENCE_CHANGED,
                    reference.id
                ));
            }
        }
        let previous = match write {
            ParkedGrantWrite::Create(object) => {
                insert_created_object_in(&mut tx, object, actor, None, attribution)?;
                None
            }
            ParkedGrantWrite::Update(object) => {
                // Keep PostgreSQL's monotonic revision token: an update that
                // does not advance `updated` is a revision conflict, as on
                // every other PostgreSQL object update.
                lock_object_lifecycle(&mut tx, &object.id)?;
                let stored: Option<i64> = tx
                    .query_opt(
                        "SELECT updated FROM sekai_objects WHERE id = $1 FOR UPDATE",
                        &[&object.id],
                    )
                    .map_err(|error| error.to_string())?
                    .map(|row| row.get(0));
                if stored.is_some_and(|stored| object.updated <= stored) {
                    return Err("object revision conflict".into());
                }
                Some(
                    update_object_in(&mut tx, object, expected, actor, None, attribution)?
                        .ok_or_else(|| format!("object {} not found", object.id))?,
                )
            }
        };
        // The commit marker a takeover reads (#1931), in this transaction.
        // The state as persisted, read back in this transaction.
        let object_id = match write {
            ParkedGrantWrite::Create(object) | ParkedGrantWrite::Update(object) => {
                object.id.clone()
            }
        };
        let persisted = tx
            .query_opt(
                &format!(
                    "SELECT {} FROM sekai_objects WHERE id = $1",
                    crate::db::postgres_audit::OBJECT_COLUMNS
                ),
                &[&object_id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()?;
        let written = object_state_digest(persisted.as_ref())?;
        tx.execute(
            "UPDATE sekai_action_instances
             SET body_json = jsonb_set(
                 jsonb_set(body_json::jsonb, '{admission_lease,write_committed}', 'true'),
                 '{admission_lease,written_object_digest}', to_jsonb($2::text))::text
             WHERE instance_id = $1",
            &[&instance_id, &written],
        )
        .map_err(|error| error.to_string())?;
        // Object locks taken above may have blocked past the lease; check
        // again before committing. The reservation row is already held
        // `FOR SHARE`, so this read does not wait.
        if !postgres_admission_fence_holds(&mut tx, instance_id, lease, true)? {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(FencedAdmissionWrite::Applied(previous))
    }

    /// Releases a failed admission in one transaction: while `lease` still
    /// names the reservation's owner and generation, undoes its object write
    /// and deletes the reservation (#1930). Returns whether this owner
    /// released it.
    pub fn release_admission(
        &self,
        instance_id: &str,
        lease: &AdmissionLease,
        undo: &AdmissionUndo,
        actor: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if !postgres_admission_fence_holds(&mut tx, instance_id, lease, false)? {
            return Ok(false);
        }
        fn current(
            tx: &mut postgres::Transaction<'_>,
            id: &str,
        ) -> Result<Option<crate::domain::Object>, String> {
            lock_object_lifecycle(tx, id)?;
            tx.query_opt(
                &format!(
                    "SELECT {} FROM sekai_objects WHERE id = $1 FOR UPDATE",
                    crate::db::postgres_audit::OBJECT_COLUMNS
                ),
                &[&id],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()
        }
        match undo {
            AdmissionUndo::None => {}
            AdmissionUndo::AbortCreate {
                object_id,
                object_kind,
            } => {
                if current(&mut tx, object_id)?.is_some_and(|object| {
                    object.kind == *object_kind && object.created == object.updated
                }) {
                    tx.execute("DELETE FROM sekai_objects WHERE id = $1", &[object_id])
                        .map_err(|error| error.to_string())?;
                    tx.execute(
                        "DELETE FROM sekai_object_changes WHERE object_id = $1",
                        &[object_id],
                    )
                    .map_err(|error| error.to_string())?;
                }
            }
            AdmissionUndo::RestoreUpdate {
                previous,
                applied_updated,
            } => {
                if let Some(object) = current(&mut tx, &previous.id)?
                    && object.updated == *applied_updated
                {
                    let mut restored = previous.clone();
                    restored.updated = object.updated.saturating_add(1);
                    update_object_in(
                        &mut tx,
                        &restored,
                        None,
                        actor,
                        None,
                        &crate::sekai::audit::ChangeAttribution::default(),
                    )?;
                }
            }
        }
        tx.execute(
            "DELETE FROM sekai_action_instances WHERE instance_id = $1",
            &[&instance_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// Marks an approver decision's follow-ups recorded (#1948); see the
    /// SQLite store.
    pub fn mark_decision_follow_ups_recorded(&self, instance_id: &str) -> Result<(), String> {
        self.connection()?
            .execute(
                "UPDATE sekai_action_instances
                 SET body_json = jsonb_set(body_json::jsonb, '{admission_lease,decision_follow_ups_recorded}', 'true')::text
                 WHERE instance_id = $1
                   AND (body_json::jsonb #>> '{admission_lease,decision_follow_ups_recorded}')::boolean = false",
                &[&instance_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Marks the admission's follow-ups recorded (#1943); see the SQLite
    /// store.
    pub fn mark_admission_follow_ups_recorded(&self, instance_id: &str) -> Result<(), String> {
        self.connection()?
            .execute(
                "UPDATE sekai_action_instances
                 SET body_json = jsonb_set(body_json::jsonb, '{admission_lease,follow_ups_recorded}', 'true')::text
                 WHERE instance_id = $1
                   AND (body_json::jsonb #>> '{admission_lease,follow_ups_recorded}')::boolean = false",
                &[&instance_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Takes over an abandoned reservation (#1931); see the SQLite store.
    pub fn take_over_admission(
        &self,
        instance: &ActionInstance,
        expired: &AdmissionLease,
        next: &AdmissionLease,
    ) -> Result<bool, String> {
        let mut taken = instance.clone();
        taken.admission_lease = Some(next.clone());
        let body_json = serde_json::to_string(&taken).map_err(|error| error.to_string())?;
        let generation = i64::try_from(expired.generation)
            .unwrap_or(i64::MAX)
            .to_string();
        let now = crate::sekai::action_instance::lease_clock_ms();
        let updated = self
            .connection()?
            .execute(
                "UPDATE sekai_action_instances SET body_json = $2
                 WHERE instance_id = $1
                   AND body_json::jsonb #>> '{admission_lease,owner}' = $3
                   AND body_json::jsonb #>> '{admission_lease,generation}' = $4
                   AND (body_json::jsonb #>> '{admission_lease,expires_at_ms}')::bigint <= $5
                   AND (body_json::jsonb #>> '{admission_lease,write_committed}')::boolean = $6
                   AND (body_json::jsonb #>> '{admission_lease,receipt_recorded}')::boolean = false",
                &[
                    &instance.instance_id,
                    &body_json,
                    &expired.owner,
                    &generation,
                    &now,
                    &expired.write_committed.unwrap_or(false),
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(updated == 1)
    }

    /// Deletes the reservation only while `lease` still names its owner and
    /// generation. Expiry is not checked: an owner may always clean up.
    pub fn delete_action_instance_fenced(
        &self,
        instance_id: &str,
        lease: &AdmissionLease,
    ) -> Result<bool, String> {
        let generation = i64::try_from(lease.generation)
            .unwrap_or(i64::MAX)
            .to_string();
        let deleted = self
            .connection()?
            .execute(
                "DELETE FROM sekai_action_instances
                 WHERE instance_id = $1
                   AND body_json::jsonb #>> '{admission_lease,owner}' = $2
                   AND body_json::jsonb #>> '{admission_lease,generation}' = $3",
                &[&instance_id, &lease.owner, &generation],
            )
            .map_err(|error| error.to_string())?;
        Ok(deleted == 1)
    }

    /// Moves a parked instance to its decided state. Returns false when the
    /// instance is no longer parked, so the first decision wins.
    pub fn decide_parked_action_instance(&self, decided: &ActionInstance) -> Result<bool, String> {
        self.transition_action_instance(STATUS_PARKED, decided, &decided.review.assignee)
    }

    /// Replaces an instance only while it still has `expected_status`.
    pub fn transition_action_instance(
        &self,
        expected_status: &str,
        decided: &ActionInstance,
        expected_assignee: &str,
    ) -> Result<bool, String> {
        decided.validate_fields()?;
        let body_json = serde_json::to_string(decided).map_err(|e| e.to_string())?;
        self.connection()?
            .execute(
                "UPDATE sekai_action_instances
                 SET status = $2, deny_reason = $3, policy_decision = $4, budget_decision = $5,
                     decided_at_ms = $6, body_json = $7
                 WHERE instance_id = $1 AND status = $8
                   AND coalesce(body_json::jsonb #>> '{review,assignee}', '') = $9",
                &[
                    &decided.instance_id,
                    &decided.status,
                    &decided.deny_reason,
                    &decided.policy_decision,
                    &decided.budget_decision,
                    &decided.decided_at_ms,
                    &body_json,
                    &expected_status,
                    &expected_assignee,
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    /// Grants a parked instance and applies its object write in one
    /// transaction, matching SQLite (#1139, #1314).
    pub fn grant_parked_action_instance(
        &self,
        granted: &ActionInstance,
        target_object_id: &str,
        parked_object_digest: &str,
        write: Option<&ParkedGrantWrite>,
        actor: &str,
        claim: Option<&crate::sekai::action_instance::ExecutionClaim>,
    ) -> Result<ParkedGrantOutcome, String> {
        granted.validate_fields()?;
        let body_json = serde_json::to_string(granted).map_err(|e| e.to_string())?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let status: Option<String> = transaction
            .query_opt(
                "SELECT status FROM sekai_action_instances WHERE instance_id = $1 FOR UPDATE",
                &[&granted.instance_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if status.as_deref() != Some(STATUS_PARKED) {
            return Ok(ParkedGrantOutcome::NotParked);
        }
        if let Some(claim) = claim {
            // Share-locked: a takeover replacing the claim commits first.
            let holder: Option<Option<String>> = transaction
                .query_opt(
                    "SELECT body_json::jsonb ->> 'claim_holder' FROM sekai_plan_executions
                     WHERE namespace = $1 AND plan_id = $2 FOR SHARE",
                    &[&granted.namespace, &claim.plan_id],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get(0));
            if holder.flatten().as_deref() != Some(claim.holder.as_str()) {
                return Ok(ParkedGrantOutcome::ClaimLost);
            }
        }
        if !target_object_id.is_empty() {
            // Same order as postgres object update/delete: lifecycle lock, then row.
            lock_object_lifecycle(&mut transaction, target_object_id)?;
            let current = transaction
                .query_opt(
                    "SELECT id, kind, name, namespace, external_id, properties, created, updated
                     FROM sekai_objects WHERE id = $1 FOR UPDATE",
                    &[&target_object_id],
                )
                .map_err(|error| error.to_string())?
                .map(row_to_object)
                .transpose()?;
            if object_state_digest(current.as_ref())? != parked_object_digest {
                return Ok(ParkedGrantOutcome::Stale);
            }
        }
        let previous = match write {
            Some(ParkedGrantWrite::Create(object)) => {
                insert_created_object_in(
                    &mut transaction,
                    object,
                    actor,
                    None,
                    &crate::sekai::audit::ChangeAttribution::action(
                        &granted.instance_id,
                        &granted.operation_id,
                    ),
                )?;
                None
            }
            Some(ParkedGrantWrite::Update(object)) => Some(
                update_object_in(
                    &mut transaction,
                    object,
                    None,
                    actor,
                    None,
                    &crate::sekai::audit::ChangeAttribution::action(
                        &granted.instance_id,
                        &granted.operation_id,
                    ),
                )?
                .ok_or_else(|| format!("object {} not found", object.id))?,
            ),
            None => None,
        };
        let updated = transaction
            .execute(
                "UPDATE sekai_action_instances
                 SET status = $2, deny_reason = $3, policy_decision = $4, budget_decision = $5,
                     decided_at_ms = $6, body_json = $7
                 WHERE instance_id = $1 AND status = $8
                   AND coalesce(body_json::jsonb #>> '{review,assignee}', '') = $9",
                &[
                    &granted.instance_id,
                    &granted.status,
                    &granted.deny_reason,
                    &granted.policy_decision,
                    &granted.budget_decision,
                    &granted.decided_at_ms,
                    &body_json,
                    &STATUS_PARKED,
                    &granted.review.assignee,
                ],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Ok(ParkedGrantOutcome::NotParked);
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(ParkedGrantOutcome::Granted { previous })
    }

    pub fn put_decision_memory(
        &self,
        memory: &crate::sekai::decision_memory::DecisionMemory,
    ) -> Result<(), String> {
        let body = serde_json::to_string(memory).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO sekai_action_decision_memory
                 (memory_id, namespace, type_id, instance_id, decided_at_ms, body_json)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (memory_id) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    type_id = EXCLUDED.type_id,
                    instance_id = EXCLUDED.instance_id,
                    decided_at_ms = EXCLUDED.decided_at_ms,
                    body_json = EXCLUDED.body_json",
                &[
                    &memory.memory_id,
                    &memory.namespace,
                    &memory.type_id,
                    &memory.instance_id,
                    &memory.decided_at_ms,
                    &body,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_decision_memory(
        &self,
        namespace: &str,
        type_id: &str,
    ) -> Result<Vec<crate::sekai::decision_memory::DecisionMemory>, String> {
        self.list_decision_memory_page(namespace, type_id, 0, i64::MAX)
    }

    pub fn list_decision_memory_page(
        &self,
        namespace: &str,
        type_id: &str,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<crate::sekai::decision_memory::DecisionMemory>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT body_json FROM sekai_action_decision_memory
                 WHERE namespace = $1 AND type_id = $2
                 ORDER BY decided_at_ms DESC
                 LIMIT $3 OFFSET $4",
                &[&namespace, &type_id, &limit, &offset],
            )
            .map_err(|error| error.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let body: String = row.get(0);
            out.push(
                serde_json::from_str(&body)
                    .map_err(|error| format!("corrupt decision memory: {error}"))?,
            );
        }
        Ok(out)
    }

    pub fn get_decision_memory(
        &self,
        memory_id: &str,
    ) -> Result<Option<crate::sekai::decision_memory::DecisionMemory>, String> {
        self.connection()?
            .query_opt(
                "SELECT body_json FROM sekai_action_decision_memory WHERE memory_id = $1",
                &[&memory_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                serde_json::from_str(&body).map_err(|error| error.to_string())
            })
            .transpose()
    }

    pub fn mark_decision_memory_superseded(&self, memory_id: &str) -> Result<bool, String> {
        let Some(mut memory) = self.get_decision_memory(memory_id)? else {
            return Ok(false);
        };
        memory.superseded = true;
        self.put_decision_memory(&memory)?;
        Ok(true)
    }
}

/// Whether `lease` holds the instance's admission reservation inside the
/// transaction, and, with `check_expiry`, is still live on the lease clock. The row is locked
/// `FOR SHARE`, so a takeover that bumps the generation waits for the fenced
/// write to commit.
pub(crate) fn postgres_admission_fence_holds<C: postgres::GenericClient>(
    client: &mut C,
    instance_id: &str,
    lease: &AdmissionLease,
    check_expiry: bool,
) -> Result<bool, String> {
    let stored = client
        .query_opt(
            "SELECT body_json::jsonb #>> '{admission_lease,owner}',
                    (body_json::jsonb #>> '{admission_lease,generation}')::bigint,
                    (body_json::jsonb #>> '{admission_lease,expires_at_ms}')::bigint
             FROM sekai_action_instances WHERE instance_id = $1 FOR SHARE",
            &[&instance_id],
        )
        .map_err(|error| error.to_string())?;
    // Read the clock after `FOR SHARE` returns, so time spent waiting for
    // the row lock counts against the lease.
    let now_ms = check_expiry.then(crate::sekai::action_instance::lease_clock_ms);
    Ok(stored.is_some_and(|row| {
        lease.holds(
            row.get::<_, Option<String>>(0).as_deref(),
            row.get(1),
            row.get(2),
            now_ms,
        )
    }))
}
