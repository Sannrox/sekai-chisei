//! PostgreSQL ActionInstance store (#397).

use crate::db::postgres::PostgresDb;
use crate::db::postgres_audit::{
    insert_created_object_in, lock_object_lifecycle, lock_object_lifecycles, row_to_object,
    update_object_in,
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
        let mut stored = instance.clone();
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        postgres_redact_if_forgotten_writer(&mut tx, &mut stored)?;
        let body_json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let evidence_json =
            serde_json::to_string(&stored.evidence_submission_ids).map_err(|e| e.to_string())?;
        let result = tx.execute(
            "INSERT INTO sekai_action_instances
             (instance_id, namespace, type_id, version, principal, parameters_json,
              request_digest, idempotency_key, operation_id, status, deny_reason,
              evidence_submission_ids_json, policy_decision, budget_decision,
              created_at_ms, decided_at_ms, body_json)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
             ON CONFLICT (namespace, idempotency_key) DO NOTHING",
            &[
                &stored.instance_id,
                &stored.namespace,
                &stored.type_id,
                &stored.version,
                &stored.principal,
                &stored.parameters_json,
                &stored.request_digest,
                &stored.idempotency_key,
                &stored.operation_id,
                &stored.status,
                &stored.deny_reason,
                &evidence_json,
                &stored.policy_decision,
                &stored.budget_decision,
                &stored.created_at_ms,
                &stored.decided_at_ms,
                &body_json,
            ],
        );
        match result {
            Ok(0) => {
                drop(tx);
                drop(connection);
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
            Ok(_) => {
                tx.commit().map_err(|error| error.to_string())?;
                Ok(stored)
            }
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
        references: &[crate::sekai::action_instance::PlanReference],
        actor: &str,
        attribution: &crate::sekai::audit::ChangeAttribution,
    ) -> Result<FencedAdmissionWrite<Option<crate::domain::Object>>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let written = match write {
            ParkedGrantWrite::Create(object) | ParkedGrantWrite::Update(object) => object,
        };
        // Object then Action: written object and references in id order,
        // then the reservation row (#2036).
        postgres_share_lock_object_ids(
            &mut tx,
            std::iter::once(written.id.as_str()).chain(
                references
                    .iter()
                    .map(crate::sekai::action_instance::PlanReference::id),
            ),
        )?;
        if matches!(write, ParkedGrantWrite::Update(_)) {
            // Keep PostgreSQL's monotonic revision token: an update that
            // does not advance `updated` is a revision conflict, as on
            // every other PostgreSQL object update.
            let stored: Option<i64> = tx
                .query_opt(
                    "SELECT updated FROM sekai_objects WHERE id = $1 FOR UPDATE",
                    &[&written.id],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get(0));
            if stored.is_some_and(|stored| written.updated <= stored) {
                return Err("object revision conflict".into());
            }
        }
        if !postgres_admission_fence_holds(&mut tx, instance_id, lease, true)? {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
        if let Some(reason) = postgres_reservation_refusal(&mut tx, instance_id, Some(written))? {
            postgres_deny_reservation(&mut tx, instance_id, &reason)?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(FencedAdmissionWrite::Refused(reason));
        }
        if let Some(changed) = postgres_changed_reference(&mut tx, references)? {
            return Err(format!(
                "{}{changed}",
                crate::sekai::action_instance::REFERENCE_CHANGED
            ));
        }
        let previous = match write {
            ParkedGrantWrite::Create(object) => {
                insert_created_object_in(&mut tx, object, actor, None, attribution)?;
                None
            }
            ParkedGrantWrite::Update(object) => Some(
                update_object_in(&mut tx, object, expected, actor, None, attribution)?
                    .ok_or_else(|| format!("object {} not found", object.id))?,
            ),
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
        // Object locks taken above may have blocked past the turn's lease;
        // check it again before the marker that would exempt this write from
        // it. The turn row is then share-locked to commit (ADR 0142).
        if postgres_turn_fence_refusal(&mut tx, instance_id)?.is_some() {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
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
        postgres_redact_forgotten_memory_actions(
            &mut tx,
            Some(match write {
                ParkedGrantWrite::Create(object) | ParkedGrantWrite::Update(object) => object,
            }),
        )?;
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
        // Object then Action: the undo target before the reservation row (#2036).
        match undo {
            AdmissionUndo::AbortCreate { object_id, .. } => {
                postgres_share_lock_object_ids(&mut tx, [object_id.as_str()])?;
            }
            AdmissionUndo::RestoreUpdate { previous, .. } => {
                postgres_share_lock_object_ids(&mut tx, [previous.id.as_str()])?;
            }
            AdmissionUndo::None => {}
        }
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
        let lease_json = serde_json::to_string(next).map_err(|error| error.to_string())?;
        let generation = i64::try_from(expired.generation)
            .unwrap_or(i64::MAX)
            .to_string();
        let now = crate::sekai::action_instance::lease_clock_ms();
        let updated = self
            .connection()?
            .execute(
                "UPDATE sekai_action_instances
                 SET body_json = jsonb_set(body_json::jsonb, '{admission_lease}', $2::text::jsonb)::text
                 WHERE instance_id = $1
                   AND body_json::jsonb #>> '{admission_lease,owner}' = $3
                   AND body_json::jsonb #>> '{admission_lease,generation}' = $4
                   AND (body_json::jsonb #>> '{admission_lease,expires_at_ms}')::bigint <= $5
                   AND (body_json::jsonb #>> '{admission_lease,write_committed}')::boolean = $6
                   AND (body_json::jsonb #>> '{admission_lease,receipt_recorded}')::boolean = false
                   AND status = $7",
                &[
                    &instance.instance_id,
                    &lease_json,
                    &expired.owner,
                    &generation,
                    &now,
                    &expired.write_committed.unwrap_or(false),
                    &instance.status,
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
        let mut stored = decided.clone();
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        postgres_redact_if_forgotten_writer(&mut tx, &mut stored)?;
        let existing_params: Option<String> = tx
            .query_opt(
                "SELECT parameters_json FROM sekai_action_instances WHERE instance_id = $1",
                &[&decided.instance_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if crate::sekai::site_agent_memory::stored_writer_already_redacted(
            existing_params.as_deref(),
            &stored,
        ) {
            crate::sekai::site_agent_memory::redact_writer_instance(&mut stored);
        }
        let body_json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let updated = tx
            .execute(
                "UPDATE sekai_action_instances
                 SET status = $2, deny_reason = $3, policy_decision = $4, budget_decision = $5,
                     decided_at_ms = $6, body_json = $7, parameters_json = $10
                 WHERE instance_id = $1 AND status = $8
                   AND coalesce(body_json::jsonb #>> '{review,assignee}', '') = $9",
                &[
                    &stored.instance_id,
                    &stored.status,
                    &stored.deny_reason,
                    &stored.policy_decision,
                    &stored.budget_decision,
                    &stored.decided_at_ms,
                    &body_json,
                    &expected_status,
                    &expected_assignee,
                    &stored.parameters_json,
                ],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(updated == 1)
    }

    /// Grants a parked instance and applies its object write in one
    /// transaction, matching SQLite (#1139, #1314).
    #[allow(clippy::too_many_arguments)]
    pub fn grant_parked_action_instance(
        &self,
        granted: &ActionInstance,
        target_object_id: &str,
        parked_object_digest: &str,
        write: Option<&ParkedGrantWrite>,
        references: &[crate::sekai::action_instance::PlanReference],
        actor: &str,
        claim: Option<&crate::sekai::action_instance::ExecutionClaim>,
    ) -> Result<ParkedGrantOutcome, String> {
        granted.validate_fields()?;
        let mut stored = granted.clone();
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let peeked: Option<String> = transaction
            .query_opt(
                "SELECT status FROM sekai_action_instances WHERE instance_id = $1",
                &[&granted.instance_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if peeked.as_deref() != Some(STATUS_PARKED) {
            return Ok(ParkedGrantOutcome::NotParked);
        }
        let written = write.map(|write| match write {
            ParkedGrantWrite::Create(object) | ParkedGrantWrite::Update(object) => object,
        });
        let writer_target =
            crate::sekai::site_agent_memory::writer_object_id(&granted.parameters_json);
        // Object then Action: every object this grant will row-lock, in id
        // order, then the parked instance (#2036).
        postgres_share_lock_object_ids(
            &mut transaction,
            std::iter::once(target_object_id)
                .chain(written.iter().map(|object| object.id.as_str()))
                .chain(writer_target.as_deref())
                .chain(
                    references
                        .iter()
                        .map(crate::sekai::action_instance::PlanReference::id),
                ),
        )?;
        let current = if target_object_id.is_empty() {
            None
        } else {
            transaction
                .query_opt(
                    "SELECT id, kind, name, namespace, external_id, properties, created, updated
                     FROM sekai_objects WHERE id = $1 FOR UPDATE",
                    &[&target_object_id],
                )
                .map_err(|error| error.to_string())?
                .map(row_to_object)
                .transpose()?
        };
        if let Some(reason) = postgres_site_agent_refusal(
            &mut transaction,
            &granted.namespace,
            &granted.principal,
            written,
        )? {
            return Ok(ParkedGrantOutcome::Refused(reason));
        }
        if postgres_changed_reference(&mut transaction, references)?.is_some() {
            return Ok(ParkedGrantOutcome::Stale);
        }
        let row = transaction
            .query_opt(
                "SELECT status, parameters_json FROM sekai_action_instances
                 WHERE instance_id = $1 FOR UPDATE",
                &[&granted.instance_id],
            )
            .map_err(|error| error.to_string())?;
        let Some((status, existing_params)): Option<(String, String)> =
            row.map(|row| (row.get(0), row.get(1)))
        else {
            return Ok(ParkedGrantOutcome::NotParked);
        };
        if status != STATUS_PARKED {
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
        if !target_object_id.is_empty()
            && object_state_digest(current.as_ref())? != parked_object_digest
        {
            return Ok(ParkedGrantOutcome::Stale);
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
        postgres_redact_if_forgotten_writer(&mut transaction, &mut stored)?;
        if crate::sekai::site_agent_memory::stored_writer_already_redacted(
            Some(&existing_params),
            &stored,
        ) {
            crate::sekai::site_agent_memory::redact_writer_instance(&mut stored);
        }
        let body_json = serde_json::to_string(&stored).map_err(|e| e.to_string())?;
        let updated = transaction
            .execute(
                "UPDATE sekai_action_instances
                 SET status = $2, deny_reason = $3, policy_decision = $4, budget_decision = $5,
                     decided_at_ms = $6, body_json = $7, parameters_json = $10
                 WHERE instance_id = $1 AND status = $8
                   AND coalesce(body_json::jsonb #>> '{review,assignee}', '') = $9",
                &[
                    &stored.instance_id,
                    &stored.status,
                    &stored.deny_reason,
                    &stored.policy_decision,
                    &stored.budget_decision,
                    &stored.decided_at_ms,
                    &body_json,
                    &STATUS_PARKED,
                    &stored.review.assignee,
                    &stored.parameters_json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Ok(ParkedGrantOutcome::NotParked);
        }
        postgres_redact_forgotten_memory_actions(&mut transaction, written)?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(ParkedGrantOutcome::Granted { previous })
    }

    pub fn put_decision_memory(
        &self,
        memory: &crate::sekai::decision_memory::DecisionMemory,
    ) -> Result<(), String> {
        let mut stored = memory.clone();
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if crate::sekai::site_agent_memory::is_writer_action(&stored.type_id)
            && postgres_target_is_forgotten(&mut tx, &stored)?
        {
            crate::sekai::site_agent_memory::redact_decision_memory(&mut stored);
        }
        postgres_insert_decision_memory(&mut tx, &stored)?;
        tx.commit().map_err(|error| error.to_string())
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
/// Why the reservation's site agent refuses its write now, read in `tx`.
pub(crate) fn postgres_reservation_refusal<C: postgres::GenericClient>(
    client: &mut C,
    instance_id: &str,
    written: Option<&crate::domain::Object>,
) -> Result<Option<String>, String> {
    if let Some(reason) = postgres_turn_fence_refusal(client, instance_id)? {
        return Ok(Some(reason));
    }
    let row = client
        .query_one(
            "SELECT namespace, principal FROM sekai_action_instances WHERE instance_id = $1",
            &[&instance_id],
        )
        .map_err(|error| error.to_string())?;
    let (namespace, principal): (String, String) = (row.get(0), row.get(1));
    postgres_site_agent_refusal(client, &namespace, &principal, written)
}

/// See `sqlite_turn_fence_refusal`. The turn row is share-locked, so a
/// reclaim that bumps its generation waits for this commit.
pub(crate) fn postgres_turn_fence_refusal<C: postgres::GenericClient>(
    client: &mut C,
    instance_id: &str,
) -> Result<Option<String>, String> {
    let row = client
        .query_one(
            "SELECT body_json::jsonb #>> '{agent_turn,turn_id}',
                    (body_json::jsonb #>> '{agent_turn,claim_generation}')::BIGINT,
                    (body_json::jsonb #>> '{admission_lease,write_committed}')::BOOLEAN
             FROM sekai_action_instances WHERE instance_id = $1",
            &[&instance_id],
        )
        .map_err(|error| error.to_string())?;
    let (turn_id, turn_generation, write_committed): (Option<String>, Option<i64>, Option<bool>) =
        (row.get(0), row.get(1), row.get(2));
    // A write that committed under the fence stays authorized (#1931).
    let Some(turn_id) = turn_id.filter(|_| write_committed != Some(true)) else {
        return Ok(None);
    };
    let live = client
        .query_opt(
            "SELECT 1 FROM sekai_agent_turn
             WHERE turn_id = $1 AND status = 'claimed' AND claim_generation = $2
               AND claim_expires_at_ms > $3
             FOR SHARE",
            &[
                &turn_id,
                &turn_generation.unwrap_or(-1),
                &crate::sekai::action_instance::lease_clock_ms(),
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(live
        .is_none()
        .then(|| format!("agent turn {turn_id} is no longer claimed by this submission")))
}

fn postgres_insert_decision_memory<C: postgres::GenericClient>(
    client: &mut C,
    memory: &crate::sekai::decision_memory::DecisionMemory,
) -> Result<(), String> {
    let body = serde_json::to_string(memory).map_err(|error| error.to_string())?;
    client
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

fn postgres_redact_if_forgotten_writer<C: postgres::GenericClient>(
    client: &mut C,
    instance: &mut ActionInstance,
) -> Result<(), String> {
    if postgres_writer_target_forgotten(client, instance)? {
        crate::sekai::site_agent_memory::redact_writer_instance(instance);
    }
    Ok(())
}

fn postgres_writer_target_forgotten<C: postgres::GenericClient>(
    client: &mut C,
    instance: &ActionInstance,
) -> Result<bool, String> {
    if !crate::sekai::site_agent_memory::is_writer_action(&instance.type_id) {
        return Ok(false);
    }
    let Some(object_id) =
        crate::sekai::site_agent_memory::writer_object_id(&instance.parameters_json)
    else {
        return Ok(false);
    };
    let forgotten: Option<String> = client
        .query_opt(
            "SELECT properties::jsonb ->> 'forgotten' FROM sekai_objects
             WHERE id = $1 AND kind = $2 AND namespace = $3 FOR UPDATE",
            &[
                &object_id,
                &crate::sekai::site_agent_memory::KIND,
                &instance.namespace,
            ],
        )
        .map_err(|error| error.to_string())?
        .and_then(|row| row.get(0));
    Ok(forgotten.as_deref() == Some("true"))
}

fn postgres_target_is_forgotten<C: postgres::GenericClient>(
    client: &mut C,
    memory: &crate::sekai::decision_memory::DecisionMemory,
) -> Result<bool, String> {
    let Some(object_id) =
        crate::sekai::site_agent_memory::writer_object_id(&memory.parameters_json)
            .or_else(|| crate::sekai::site_agent_memory::writer_object_id(&memory.facts_json))
    else {
        return Ok(false);
    };
    let forgotten: Option<String> = client
        .query_opt(
            "SELECT properties::jsonb ->> 'forgotten' FROM sekai_objects
             WHERE id = $1 AND kind = $2 AND namespace = $3 FOR UPDATE",
            &[
                &object_id,
                &crate::sekai::site_agent_memory::KIND,
                &memory.namespace,
            ],
        )
        .map_err(|error| error.to_string())?
        .and_then(|row| row.get(0));
    Ok(forgotten.as_deref() == Some("true"))
}

/// Empty forgotten memory `content` in writer Action parameters, in this
/// transaction (#1969). Leaves each stored request digest as it was.
pub(crate) fn postgres_redact_forgotten_memory_actions<C: postgres::GenericClient>(
    client: &mut C,
    written: Option<&crate::domain::Object>,
) -> Result<(), String> {
    use crate::sekai::decision_memory::DecisionMemory;
    use crate::sekai::site_agent_memory::{
        ACTION_CREATE, ACTION_FORGET, ACTION_UPDATE, is_forgotten, redact_writer_instance,
    };
    let Some(object) = written.filter(|object| is_forgotten(object)) else {
        return Ok(());
    };
    let rows = client
        .query(
            "SELECT instance_id, parameters_json, body_json FROM sekai_action_instances
             WHERE namespace = $1
               AND type_id IN ($2, $3, $4)
               AND parameters_json::jsonb ->> 'object_id' = $5
             ORDER BY instance_id
             FOR UPDATE",
            &[
                &object.namespace,
                &ACTION_CREATE,
                &ACTION_UPDATE,
                &ACTION_FORGET,
                &object.id,
            ],
        )
        .map_err(|error| error.to_string())?;
    let mut updates = Vec::new();
    for row in rows {
        let instance_id: String = row.get(0);
        let parameters_json: String = row.get(1);
        let body_json: String = row.get(2);
        let mut instance: ActionInstance = serde_json::from_str(&body_json)
            .map_err(|error| format!("corrupt action instance body: {error}"))?;
        instance.parameters_json = parameters_json;
        if !redact_writer_instance(&mut instance) {
            continue;
        }
        let parameters_json = instance.parameters_json.clone();
        let body_json = serde_json::to_string(&instance).map_err(|error| error.to_string())?;
        updates.push((instance_id, parameters_json, body_json));
    }
    for (instance_id, parameters_json, body_json) in updates {
        client
            .execute(
                "UPDATE sekai_action_instances
                 SET parameters_json = $2, body_json = $3
                 WHERE instance_id = $1",
                &[&instance_id, &parameters_json, &body_json],
            )
            .map_err(|error| error.to_string())?;
    }
    let rows = match client.query(
        "SELECT memory_id, body_json FROM sekai_action_decision_memory
         WHERE namespace = $1 AND type_id IN ($2, $3, $4)
           AND (
             CASE
               WHEN coalesce(body_json::jsonb ->> 'parameters_json', '') IN ('', 'null')
                 THEN NULL
               ELSE (body_json::jsonb ->> 'parameters_json')::jsonb ->> 'object_id'
             END = $5
             OR CASE
               WHEN coalesce(body_json::jsonb ->> 'facts_json', '') IN ('', 'null')
                 THEN NULL
               ELSE (body_json::jsonb ->> 'facts_json')::jsonb ->> 'object_id'
             END = $5
           )
         ORDER BY memory_id
         FOR UPDATE",
        &[
            &object.namespace,
            &ACTION_CREATE,
            &ACTION_UPDATE,
            &ACTION_FORGET,
            &object.id,
        ],
    ) {
        Ok(rows) => rows,
        Err(error) if error.to_string().contains("sekai_action_decision_memory") => {
            return Ok(());
        }
        Err(error) => return Err(error.to_string()),
    };
    let mut updates = Vec::new();
    for row in rows {
        let memory_id: String = row.get(0);
        let body_json: String = row.get(1);
        let mut memory: DecisionMemory = serde_json::from_str(&body_json)
            .map_err(|error| format!("corrupt decision memory: {error}"))?;
        let object_id = crate::sekai::site_agent_memory::writer_object_id(&memory.parameters_json)
            .or_else(|| crate::sekai::site_agent_memory::writer_object_id(&memory.facts_json));
        if object_id.as_deref() != Some(object.id.as_str()) {
            continue;
        }
        if !crate::sekai::site_agent_memory::redact_decision_memory(&mut memory) {
            continue;
        }
        let body_json = serde_json::to_string(&memory).map_err(|error| error.to_string())?;
        updates.push((memory_id, body_json));
    }
    for (memory_id, body_json) in updates {
        client
            .execute(
                "UPDATE sekai_action_decision_memory SET body_json = $2 WHERE memory_id = $1",
                &[&memory_id, &body_json],
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Why a site agent write is refused as it commits (#1970); see the SQLite
/// store. The instances read are share-locked, so a freeze or principal
/// change committing during this transaction waits for it, and one that
/// committed first is seen.
pub(crate) fn postgres_site_agent_refusal<C: postgres::GenericClient>(
    client: &mut C,
    namespace: &str,
    principal: &str,
    written: Option<&crate::domain::Object>,
) -> Result<Option<String>, String> {
    use crate::sekai::{site_agent_instance as instance, site_agent_memory as memory};
    let frozen = client
        .query(
            "SELECT id, properties::jsonb ->> 'frozen' FROM sekai_objects
             WHERE kind = $1 AND namespace = $2
               AND properties::jsonb ->> 'principal_id' = $3
             ORDER BY id FOR SHARE",
            &[&instance::KIND, &namespace, &principal],
        )
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|row| row.get::<_, Option<String>>(1).as_deref() == Some("true"))
        .map(|row| row.get::<_, String>(0));
    if let Some(id) = frozen {
        return Ok(Some(format!("site agent instance {id} is frozen")));
    }
    let Some(owner) = written
        .filter(|object| object.kind == memory::KIND)
        .and_then(|object| object.properties.get(memory::INSTANCE_PROPERTY))
    else {
        return Ok(None);
    };
    let current = client
        .query_opt(
            "SELECT properties::jsonb ->> 'principal_id', properties::jsonb ->> 'frozen'
             FROM sekai_objects WHERE id = $1 AND kind = $2 AND namespace = $3 FOR SHARE",
            &[owner, &instance::KIND, &namespace],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            (
                row.get::<_, Option<String>>(0),
                row.get::<_, Option<String>>(1),
            )
        });
    Ok(crate::sekai::action_instance::memory_refusal(
        owner, principal, current,
    ))
}

/// Marks the reservation denied with `reason`, in `tx`.
pub(crate) fn postgres_deny_reservation<C: postgres::GenericClient>(
    client: &mut C,
    instance_id: &str,
    reason: &str,
) -> Result<(), String> {
    client
        .execute(
            "UPDATE sekai_action_instances
             SET status = $2, deny_reason = $3,
                 body_json = jsonb_set(jsonb_set(body_json::jsonb, '{status}', to_jsonb($2::text)),
                     '{deny_reason}', to_jsonb($3::text))::text
             WHERE instance_id = $1",
            &[
                &instance_id,
                &crate::sekai::action_instance::STATUS_DENIED,
                &reason,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

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

/// Lifecycle and `FOR SHARE` row locks for `object_ids` in sorted unique
/// order, before any Action row lock in the same transaction (#2036).
fn postgres_share_lock_object_ids(
    tx: &mut postgres::Transaction<'_>,
    object_ids: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), String> {
    let ids = crate::db::postgres_audit::ordered_object_lock_ids(object_ids);
    lock_object_lifecycles(tx, &ids)?;
    for id in ids {
        tx.query_opt(
            "SELECT 1 FROM sekai_objects WHERE id = $1 FOR SHARE",
            &[&id],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// The id of the first of `references` no longer as planning read it
/// (#1941). A present one is read `FOR SHARE` and an absent one holds its
/// lifecycle lock, which a create takes, so each stays as read until commit;
/// in id order, so two writers lock in one order. Callers take those same
/// object locks before any Action row lock (#2036).
fn postgres_changed_reference(
    tx: &mut postgres::Transaction<'_>,
    references: &[crate::sekai::action_instance::PlanReference],
) -> Result<Option<String>, String> {
    use crate::sekai::action_instance::PlanReference;
    let mut ordered: Vec<&PlanReference> = references.iter().collect();
    ordered.sort_by(|left, right| left.id().cmp(right.id()));
    for reference in ordered {
        if matches!(reference, PlanReference::Absent(_)) {
            lock_object_lifecycle(tx, reference.id())?;
        }
        let current = tx
            .query_opt(
                &format!(
                    "SELECT {} FROM sekai_objects WHERE id = $1 FOR SHARE",
                    crate::db::postgres_audit::OBJECT_COLUMNS
                ),
                &[&reference.id()],
            )
            .map_err(|error| error.to_string())?
            .map(row_to_object)
            .transpose()?;
        if !reference.holds(current.as_ref()) {
            return Ok(Some(reference.id().to_string()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use crate::db::runtime_db::RuntimeDb;
    use crate::domain::Object;
    use crate::sekai::action_instance::{
        FencedAdmissionWrite, ParkedGrantOutcome, ParkedGrantWrite, PlanReference, STATUS_ADMITTED,
        STATUS_DENIED, object_state_digest, reserve_for_test, sample_for_test,
    };
    use crate::sekai::plan_execution::{EXECUTION_RUNNING, PlanExecution};
    use crate::sekai::site_agent_memory::{
        ACTION_CREATE, ACTION_UPDATE, CONTENT_PROPERTY, FORGOTTEN_PROPERTY, KIND,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Barrier};

    fn postgres_deadlock(error: &str) -> bool {
        error.contains("40P01") || error.contains("deadlock detected")
    }

    fn record(id: &str, kind: &str, updated: i64, properties: HashMap<String, String>) -> Object {
        Object {
            id: id.into(),
            kind: kind.into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: String::new(),
            properties,
            created: updated,
            updated,
        }
    }

    /// Admission, parked grant, plan-step close and forget on overlapping
    /// objects wait in one lock order and neither deadlock nor drop a
    /// successful write (#2036).
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_admission_grant_close_and_forget_do_not_deadlock() {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        let db = Arc::new(RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect())));
        let run = uuid::Uuid::new_v4().simple().to_string();
        let note_id = format!("note-{run}");
        let grant_id = format!("grant-{run}");
        let created_id = format!("created-{run}");
        let mut note_properties = HashMap::new();
        note_properties.insert("instance_id".into(), format!("line-{run}"));
        note_properties.insert(CONTENT_PROPERTY.into(), "secret".into());
        let note = record(&note_id, KIND, 500, note_properties);
        db.create_object_with_audit(&note, "a").unwrap();
        db.create_object_with_audit(
            &record(&grant_id, "customer_record", 500, HashMap::new()),
            "a",
        )
        .unwrap();
        let mut writer = sample_for_test(STATUS_ADMITTED);
        writer.instance_id = format!("writer-{run}");
        writer.idempotency_key = format!("key-writer-{run}");
        writer.operation_id = format!("op-writer-{run}");
        writer.type_id = ACTION_CREATE.into();
        writer.parameters_json = format!(r#"{{"object_id":"{note_id}","content":"secret"}}"#);
        db.put_action_instance(&writer).unwrap();
        let decision = |id: &str, object_id: &str, content: &str| {
            let parameters = format!(r#"{{"object_id":"{object_id}","content":"{content}"}}"#);
            crate::sekai::decision_memory::DecisionMemory {
                memory_id: id.into(),
                namespace: "acme".into(),
                type_id: ACTION_UPDATE.into(),
                version: "1".into(),
                instance_id: id.into(),
                outcome: "grant".into(),
                reason: "ok".into(),
                conditions_json: String::new(),
                facts_json: parameters.clone(),
                decided_by: "operator".into(),
                decided_at_ms: 10,
                superseded: false,
                parameters_json: parameters,
            }
        };
        db.put_decision_memory(&decision(&format!("mem-{run}"), &note_id, "secret"))
            .unwrap();
        for index in 0..32 {
            db.put_decision_memory(&decision(
                &format!("noise-{run}-{index}"),
                &format!("other-{run}-{index}"),
                "noise",
            ))
            .unwrap();
        }
        let grant_target = db.get_object(&grant_id).unwrap().unwrap();
        let parked_digest = object_state_digest(Some(&grant_target)).unwrap();
        let mut parked = sample_for_test(crate::sekai::action_instance::STATUS_PARKED);
        parked.instance_id = format!("parked-{run}");
        parked.idempotency_key = format!("key-parked-{run}");
        parked.operation_id = format!("op-parked-{run}");
        db.put_action_instance(&parked).unwrap();
        db.put_plan_execution(&PlanExecution {
            namespace: "acme".into(),
            plan_id: format!("plan-{run}"),
            simulation_id: "sim-1".into(),
            simulation_digest: "sha256:one".into(),
            status: EXECUTION_RUNNING.into(),
            next_step: 0,
            steps: Vec::new(),
            stop_reason: String::new(),
            stopped_at_step: None,
            started_by: "planner".into(),
            updated_at_ms: 1,
            revision: 0,
            claim_holder: format!("run-{run}"),
            claim_until_ms: 10_000,
        })
        .unwrap();

        let note = db.get_object(&note_id).unwrap().unwrap();
        let grant_target = db.get_object(&grant_id).unwrap().unwrap();
        let barrier = Arc::new(Barrier::new(4));
        let admission = {
            let (db, barrier, note, created_id, run) = (
                Arc::clone(&db),
                Arc::clone(&barrier),
                note.clone(),
                created_id.clone(),
                run.clone(),
            );
            std::thread::spawn(move || {
                let (instance_id, lease) = reserve_for_test(&db, &format!("ai-admit-{run}"), 100);
                let write = ParkedGrantWrite::Create(record(
                    &created_id,
                    "customer_record",
                    700,
                    HashMap::new(),
                ));
                barrier.wait();
                db.apply_admission_object_write(
                    &instance_id,
                    &lease,
                    &write,
                    None,
                    &[PlanReference::Present(note)],
                    "a",
                    &crate::sekai::audit::ChangeAttribution::default(),
                )
                .map(|outcome| match outcome {
                    FencedAdmissionWrite::Applied(_) => "Applied".into(),
                    FencedAdmissionWrite::FenceLost => "FenceLost".into(),
                    FencedAdmissionWrite::Refused(reason) => format!("Refused({reason})"),
                })
            })
        };
        let forget = {
            let (db, barrier, mut forgotten, run) = (
                Arc::clone(&db),
                Arc::clone(&barrier),
                note.clone(),
                run.clone(),
            );
            forgotten.updated += 1;
            forgotten
                .properties
                .insert(CONTENT_PROPERTY.into(), String::new());
            forgotten
                .properties
                .insert(FORGOTTEN_PROPERTY.into(), "true".into());
            std::thread::spawn(move || {
                let (instance_id, lease) = reserve_for_test(&db, &format!("ai-forget-{run}"), 100);
                let write = ParkedGrantWrite::Update(forgotten);
                barrier.wait();
                db.apply_admission_object_write(
                    &instance_id,
                    &lease,
                    &write,
                    None,
                    &[],
                    "a",
                    &crate::sekai::audit::ChangeAttribution::default(),
                )
                .map(|outcome| match outcome {
                    FencedAdmissionWrite::Applied(_) => "Applied".into(),
                    FencedAdmissionWrite::FenceLost => "FenceLost".into(),
                    FencedAdmissionWrite::Refused(reason) => format!("Refused({reason})"),
                })
            })
        };
        let grant = {
            let (db, barrier, parked, grant_target, note, parked_digest) = (
                Arc::clone(&db),
                Arc::clone(&barrier),
                parked,
                grant_target,
                note,
                parked_digest,
            );
            std::thread::spawn(move || {
                let mut updated = grant_target.clone();
                updated.updated += 1;
                updated.name = "granted".into();
                let granted = crate::sekai::action_instance::ActionInstance {
                    status: STATUS_ADMITTED.into(),
                    ..parked
                };
                barrier.wait();
                db.grant_parked_action_instance(
                    &granted,
                    &grant_target.id,
                    &parked_digest,
                    Some(&ParkedGrantWrite::Update(updated)),
                    &[PlanReference::Present(note)],
                    "a",
                    None,
                )
                .map(|outcome| match outcome {
                    ParkedGrantOutcome::Granted { .. } => "Granted".into(),
                    ParkedGrantOutcome::NotParked => "NotParked".into(),
                    ParkedGrantOutcome::Refused(reason) => format!("Refused({reason})"),
                    ParkedGrantOutcome::ClaimLost => "ClaimLost".into(),
                    ParkedGrantOutcome::Stale => "Stale".into(),
                })
            })
        };
        let close = {
            let (db, barrier, run) = (Arc::clone(&db), Arc::clone(&barrier), run.clone());
            std::thread::spawn(move || {
                let mut closing = sample_for_test(STATUS_DENIED);
                closing.instance_id = format!("close-{run}");
                closing.idempotency_key = format!("close-{run}");
                closing.operation_id = format!("op-close-{run}");
                closing.request_digest = "plan_execution_stopped:step_refused".into();
                barrier.wait();
                db.close_plan_step_key(&closing, &format!("plan-{run}"), &format!("run-{run}"))
                    .map(|inserted| format!("inserted={inserted}"))
            })
        };

        let outcomes = [admission, forget, grant, close].map(|worker| worker.join().unwrap());
        for outcome in &outcomes {
            if let Err(error) = outcome {
                assert!(
                    !postgres_deadlock(error),
                    "deadlock (SQLSTATE 40P01): {error}; outcomes={outcomes:?}"
                );
            }
        }
        let created = db.get_object(&created_id).unwrap();
        if outcomes[0]
            .as_ref()
            .is_ok_and(|outcome| outcome.contains("Applied"))
        {
            assert!(created.is_some(), "admission applied but object missing");
        }
        let stored_note = db.get_object(&note_id).unwrap().unwrap();
        if outcomes[1]
            .as_ref()
            .is_ok_and(|outcome| outcome.contains("Applied"))
        {
            assert_eq!(
                stored_note
                    .properties
                    .get(FORGOTTEN_PROPERTY)
                    .map(String::as_str),
                Some("true")
            );
            assert_eq!(
                stored_note
                    .properties
                    .get(CONTENT_PROPERTY)
                    .map(String::as_str),
                Some("")
            );
            let memory = db
                .get_decision_memory(&format!("mem-{run}"))
                .unwrap()
                .unwrap();
            assert!(
                !memory.parameters_json.contains("secret"),
                "{}",
                memory.parameters_json
            );
        }
        if outcomes[2]
            .as_ref()
            .is_ok_and(|outcome| outcome.contains("Granted"))
        {
            assert_eq!(db.get_object(&grant_id).unwrap().unwrap().name, "granted");
        }
        assert_eq!(
            outcomes[3].as_ref().map(String::as_str),
            Ok("inserted=true")
        );
        let noise = db
            .get_decision_memory(&format!("noise-{run}-0"))
            .unwrap()
            .unwrap();
        assert!(
            noise.parameters_json.contains("noise"),
            "{}",
            noise.parameters_json
        );
    }
}
