//! PostgreSQL receipt persistence used by `RuntimeDb`.

use crate::db::chisei_receipt::{
    open_receipt_min_started_at_ms, validate_evaluation_receipt_event_order,
};
use crate::db::postgres::PostgresDb;
use postgres::GenericClient;
use sekai_domain::receipt::{
    OperationReceipt, OperationReceiptEvent, OperationReporterGrant, ReceiptEventKind,
};

impl PostgresDb {
    pub fn put_operation_receipt(&self, receipt: &OperationReceipt) -> Result<(), String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        self.upsert_operation_receipt_on(&mut tx, receipt)?;
        crate::db::postgres_receipt_chain::append_operation_receipt_chain(&mut tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// Records an admission's receipt only while `lease` still names the
    /// reservation's owner and generation and has not expired (#1930).
    /// Returns whether it was recorded.
    pub fn put_admission_receipt(
        &self,
        instance_id: &str,
        lease: &crate::sekai::action_instance::AdmissionLease,
        receipt: &OperationReceipt,
    ) -> Result<bool, String> {
        self.put_admission_receipt_checked(
            instance_id,
            lease,
            receipt,
            crate::sekai::action_instance::CommitCheck::None,
        )
        .map(|written| {
            matches!(
                written,
                crate::sekai::action_instance::FencedAdmissionWrite::Applied(())
            )
        })
    }

    /// See the SQLite store (#1970).
    pub fn put_admission_receipt_checked(
        &self,
        instance_id: &str,
        lease: &crate::sekai::action_instance::AdmissionLease,
        receipt: &OperationReceipt,
        check: crate::sekai::action_instance::CommitCheck,
    ) -> Result<crate::sekai::action_instance::FencedAdmissionWrite<()>, String> {
        use crate::sekai::action_instance::FencedAdmissionWrite;
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        if !crate::db::postgres_action_instance::postgres_admission_fence_holds(
            &mut tx,
            instance_id,
            lease,
            true,
        )? {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
        // A receipt that commits an Action checks its turn's fence (ADR
        // 0142), and an admitted one its site agent too (#1970).
        use crate::sekai::action_instance::CommitCheck;
        let refusal = match check {
            CommitCheck::SiteAgent => {
                crate::db::postgres_action_instance::postgres_reservation_refusal(
                    &mut tx,
                    instance_id,
                    None,
                )?
            }
            CommitCheck::TurnFence => {
                crate::db::postgres_action_instance::postgres_turn_fence_refusal(
                    &mut tx,
                    instance_id,
                )?
            }
            CommitCheck::None => None,
        };
        if let Some(reason) = refusal {
            crate::db::postgres_action_instance::postgres_deny_reservation(
                &mut tx,
                instance_id,
                &reason,
            )?;
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(FencedAdmissionWrite::Refused(reason));
        }
        self.upsert_operation_receipt_on(&mut tx, receipt)?;
        crate::db::postgres_receipt_chain::append_operation_receipt_chain(&mut tx, receipt)?;
        // The marker a takeover checks (#1931); updating the row also makes
        // a waiting takeover recheck its condition against this commit.
        tx.execute(
            "UPDATE sekai_action_instances
             SET body_json = jsonb_set(body_json::jsonb, '{admission_lease,receipt_recorded}', 'true')::text
             WHERE instance_id = $1",
            &[&instance_id],
        )
        .map_err(|error| error.to_string())?;
        // The marker a takeover checks (#1931); updating the row also makes
        // a waiting takeover recheck its condition against this commit.
        tx.execute(
            "UPDATE sekai_action_instances
             SET body_json = jsonb_set(body_json::jsonb, '{admission_lease,receipt_recorded}', 'true')::text
             WHERE instance_id = $1",
            &[&instance_id],
        )
        .map_err(|error| error.to_string())?;
        // The receipt chain may have waited on its own lock; check the lease
        // again before committing.
        if !crate::db::postgres_action_instance::postgres_admission_fence_holds(
            &mut tx,
            instance_id,
            lease,
            true,
        )? {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
        // So may the turn's lease have lapsed meanwhile (ADR 0142).
        if check != CommitCheck::None
            && crate::db::postgres_action_instance::postgres_turn_fence_refusal(
                &mut tx,
                instance_id,
            )?
            .is_some()
        {
            return Ok(FencedAdmissionWrite::FenceLost);
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(FencedAdmissionWrite::Applied(()))
    }

    fn upsert_operation_receipt_on<C: GenericClient>(
        &self,
        client: &mut C,
        receipt: &OperationReceipt,
    ) -> Result<(), String> {
        let receipt_json = serde_json::to_string(receipt).map_err(|error| error.to_string())?;
        let request_id = intent_attr(receipt, "request_id");
        let lookup_request_id = intent_attr(receipt, "lookup_request_id");
        let caller_scope = intent_attr(receipt, "caller_scope");
        client
            .execute(
                "INSERT INTO chisei_operation_receipts(
                    operation_id, request_id, lookup_request_id, initiating_actor,
                    caller_scope, namespace, receipt_json, updated_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (operation_id) DO UPDATE SET
                    request_id = EXCLUDED.request_id,
                    lookup_request_id = CASE
                      WHEN chisei_operation_receipts.alias_retired = 1 THEN NULL
                      ELSE EXCLUDED.lookup_request_id
                    END,
                    initiating_actor = EXCLUDED.initiating_actor,
                    caller_scope = COALESCE(
                        EXCLUDED.caller_scope, chisei_operation_receipts.caller_scope
                    ),
                    namespace = EXCLUDED.namespace,
                    receipt_json = EXCLUDED.receipt_json,
                    updated_at = EXCLUDED.updated_at",
                &[
                    &receipt.operation_id,
                    &request_id,
                    &lookup_request_id,
                    &receipt.initiating_actor,
                    &caller_scope,
                    &receipt.namespace,
                    &receipt_json,
                    &chrono::Utc::now().timestamp_millis(),
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn get_operation_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        let receipt_json = self
            .connection()?
            .query_opt(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id = $1",
                &[&operation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0));
        receipt_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn list_operation_receipts_in_window(
        &self,
        namespace: &str,
        start_timestamp_ms: i64,
        end_timestamp_ms: i64,
        limit: usize,
    ) -> Result<Vec<OperationReceipt>, String> {
        // Callers may pass max+1 to detect overflow; allow that sentinel.
        let limit = i64::try_from(limit.min(5_001)).unwrap_or(5_001);
        // Keep #645 harvest semantics for recent opens; drop abandoned NULLs
        // that started before the window's open-receipt overlap TTL.
        let open_min_started_at_ms = open_receipt_min_started_at_ms(start_timestamp_ms);
        let rows = self
            .connection()?
            .query(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE namespace=$1
                   AND ((receipt_json::jsonb->>'started_at_ms')::bigint) < $3
                   AND (
                     (
                       receipt_json::jsonb->>'completed_at_ms' IS NOT NULL
                       AND NULLIF(receipt_json::jsonb->>'completed_at_ms', '')::bigint >= $2
                     )
                     OR (
                       receipt_json::jsonb->>'completed_at_ms' IS NULL
                       AND ((receipt_json::jsonb->>'started_at_ms')::bigint) >= $5
                     )
                   )
                 ORDER BY ((receipt_json::jsonb->>'started_at_ms')::bigint), operation_id
                 LIMIT $4",
                &[
                    &namespace,
                    &start_timestamp_ms,
                    &end_timestamp_ms,
                    &limit,
                    &open_min_started_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        let mut receipts = Vec::with_capacity(rows.len());
        for row in rows {
            let json: String = row.get(0);
            receipts.push(serde_json::from_str(&json).map_err(|error| error.to_string())?);
        }
        Ok(receipts)
    }

    pub fn update_operation_receipt<F>(
        &self,
        operation_id: &str,
        update: F,
    ) -> Result<OperationReceipt, String>
    where
        F: FnOnce(&mut OperationReceipt) -> Result<(), String>,
    {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&format!("receipt:{operation_id}")],
            )
            .map_err(|error| format!("lock operation receipt {operation_id}: {error}"))?;
        let receipt_json: String = transaction
            .query_opt(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id = $1",
                &[&operation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0))
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        let original = receipt.clone();
        update(&mut receipt)?;
        if receipt == original {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(receipt);
        }
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "UPDATE chisei_operation_receipts
                 SET receipt_json = $1, updated_at = $2
                 WHERE operation_id = $3",
                &[
                    &updated_json,
                    &chrono::Utc::now().timestamp_millis(),
                    &operation_id,
                ],
            )
            .map_err(|error| error.to_string())?;
        crate::db::postgres_receipt_chain::append_operation_receipt_chain(
            &mut transaction,
            &receipt,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(receipt)
    }

    pub fn reserve_gateway_request_alias(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let receipt_exists: bool = transaction
            .query_one(
                "SELECT EXISTS(
                   SELECT 1 FROM chisei_operation_receipts
                   WHERE caller_scope = $1 AND lookup_request_id = $2
                 )",
                &[&caller_scope, &request_alias],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if receipt_exists {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
        let existing = transaction
            .query_opt(
                "SELECT request_id, operation_id, dispatch_started
                 FROM chisei_gateway_request_aliases
                 WHERE caller_scope = $1 AND request_alias = $2",
                &[&caller_scope, &request_alias],
            )
            .map_err(|error| error.to_string())?;
        if let Some(row) = existing {
            let existing_request_id: String = row.get(0);
            let existing_operation_id: String = row.get(1);
            let dispatch_started: i64 = row.get(2);
            let resumable = existing_request_id == request_id
                && existing_operation_id == operation_id
                && dispatch_started == 0;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(resumable);
        }
        let reserved = transaction
            .execute(
                "INSERT INTO chisei_gateway_request_aliases(
                    caller_scope, request_alias, request_id, operation_id, reserved_at
                 ) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING",
                &[
                    &caller_scope,
                    &request_alias,
                    &request_id,
                    &operation_id,
                    &chrono::Utc::now().timestamp_millis(),
                ],
            )
            .map_err(|error| error.to_string())?
            == 1;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(reserved)
    }

    pub fn claim_gateway_request_alias_dispatch(
        &self,
        caller_scope: &str,
        request_alias: &str,
        request_id: &str,
        operation_id: &str,
        dispatch_token: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let claimed = transaction
            .execute(
                "UPDATE chisei_gateway_request_aliases
                 SET dispatch_started = 1, dispatch_token = $1
                 WHERE caller_scope = $2 AND request_alias = $3 AND request_id = $4
                   AND operation_id = $5 AND dispatch_started = 0",
                &[
                    &dispatch_token,
                    &caller_scope,
                    &request_alias,
                    &request_id,
                    &operation_id,
                ],
            )
            .map_err(|error| error.to_string())?
            == 1;
        let same_claim = if claimed {
            true
        } else {
            transaction
                .query_opt(
                    "SELECT dispatch_token = $1
                     FROM chisei_gateway_request_aliases
                     WHERE caller_scope = $2 AND request_alias = $3 AND request_id = $4
                       AND operation_id = $5 AND dispatch_started = 1",
                    &[
                        &dispatch_token,
                        &caller_scope,
                        &request_alias,
                        &request_id,
                        &operation_id,
                    ],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, bool>(0))
                .unwrap_or(false)
        };
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(same_claim)
    }

    pub fn find_gateway_receipt_by_logical_operation_id(
        &self,
        operation_id: &str,
        attempt: Option<u32>,
    ) -> Result<Option<OperationReceipt>, String> {
        let prefix = format!("{operation_id}:__attempt__:");
        let attempt = attempt.map(|value| value.to_string());
        let rows = self
            .connection()?
            .query(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE position($1 in operation_id) = 1
                   AND ($2::text IS NULL OR operation_id LIKE '%:' || $2)
                 ORDER BY updated_at DESC, operation_id DESC
                 LIMIT 2",
                &[&prefix, &attempt],
            )
            .map_err(|error| error.to_string())?;
        if rows.len() > 1 {
            return Err("logical operation id matches multiple receipt attempts".into());
        }
        rows.into_iter()
            .next()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .transpose()
    }

    pub fn find_operation_receipt_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<OperationReceipt>, String> {
        let receipt_json = self
            .connection()?
            .query_opt(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE request_id = $1",
                &[&request_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0));
        receipt_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn find_operation_receipt_by_lookup_request_id(
        &self,
        request_id: &str,
        caller_scope: Option<&str>,
        initiating_actor: Option<&str>,
    ) -> Result<Option<OperationReceipt>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT receipt_json FROM chisei_operation_receipts
                 WHERE lookup_request_id = $1
                   AND ($2::text IS NULL OR caller_scope = $2)
                   AND ($3::text IS NULL OR initiating_actor = $3)
                 ORDER BY operation_id
                 LIMIT 2",
                &[&request_id, &caller_scope, &initiating_actor],
            )
            .map_err(|error| error.to_string())?;
        if rows.len() > 1 {
            return Err("request id matches multiple operation receipts".into());
        }
        rows.into_iter()
            .next()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .transpose()
    }

    pub fn append_operation_receipt_event(
        &self,
        operation_id: &str,
        event: OperationReceiptEvent,
    ) -> Result<(OperationReceipt, bool), String> {
        if event.operation_id != operation_id {
            return Err("event operation id does not match receipt".into());
        }
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // Serialize concurrent reporters on the same operation_id.
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&format!("receipt:{operation_id}")],
            )
            .map_err(|error| format!("lock operation receipt {operation_id}: {error}"))?;
        let receipt_json: String = transaction
            .query_opt(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id = $1",
                &[&operation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0))
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        if let Some(existing) = receipt
            .events
            .iter()
            .find(|existing| existing.event_id == event.event_id)
        {
            let mut replay = event.clone();
            replay.timestamp_ms = existing.timestamp_ms;
            if existing == &replay {
                transaction.commit().map_err(|error| error.to_string())?;
                return Ok((receipt, false));
            }
            return Err(format!(
                "event {} already exists with different evidence",
                event.event_id
            ));
        }
        validate_evaluation_receipt_event_order(&receipt, &event)?;
        if let Some((metric, value, passed)) = crate::db::chisei_receipt::outcome_evidence(&event)?
        {
            for existing in &receipt.events {
                let Some((existing_metric, existing_value, existing_passed)) =
                    crate::db::chisei_receipt::outcome_evidence(existing)?
                else {
                    continue;
                };
                if existing_metric == metric
                    && (existing_value != value || existing_passed != passed)
                {
                    return Err(format!(
                        "outcome metric {metric} already exists with different evidence"
                    ));
                }
            }
        }
        let parent_id = event
            .parent_event_id
            .as_deref()
            .ok_or_else(|| "reported event requires a causal parent".to_string())?;
        if !receipt
            .events
            .iter()
            .any(|existing| existing.event_id == parent_id)
        {
            return Err(format!("causal parent {parent_id} not found"));
        }
        receipt
            .uncovered_surfaces
            .retain(|entry| entry.surface != event.surface);
        if event.kind == ReceiptEventKind::OutcomeRecorded {
            if receipt.completed_at_ms.is_some() {
                return Err("operation receipt already has a terminal outcome".into());
            }
            receipt.completed_at_ms = Some(event.timestamp_ms);
        }
        let produced_at_ms = event.timestamp_ms;
        receipt.events.push(event);
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        let durable_at_ms = chrono::Utc::now().timestamp_millis();
        transaction
            .execute(
                "UPDATE chisei_operation_receipts
                 SET receipt_json = $1, updated_at = $2
                 WHERE operation_id = $3",
                &[&updated_json, &durable_at_ms, &operation_id],
            )
            .map_err(|error| error.to_string())?;
        crate::db::postgres_receipt_chain::append_operation_receipt_chain(
            &mut transaction,
            &receipt,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        crate::db::chisei_receipt::record_receipt_durability_lag(produced_at_ms, durable_at_ms);
        Ok((receipt, true))
    }

    pub fn authorize_operation_reporter(
        &self,
        operation_id: &str,
        principal: &str,
        event_kinds: Vec<ReceiptEventKind>,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&format!("receipt:{operation_id}")],
            )
            .map_err(|error| format!("lock operation receipt {operation_id}: {error}"))?;
        let receipt_json: String = transaction
            .query_opt(
                "SELECT receipt_json FROM chisei_operation_receipts WHERE operation_id = $1",
                &[&operation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0))
            .ok_or_else(|| format!("operation receipt {operation_id} not found"))?;
        let mut receipt: OperationReceipt =
            serde_json::from_str(&receipt_json).map_err(|error| error.to_string())?;
        let mut normalized = event_kinds;
        normalized.sort_by_key(|kind| kind.as_str());
        normalized.dedup();
        if let Some(grant) = receipt
            .reporter_grants
            .iter_mut()
            .find(|grant| grant.principal == principal)
        {
            let mut existing = grant.event_kinds.clone();
            existing.sort_by_key(|kind| kind.as_str());
            existing.dedup();
            if existing == normalized {
                transaction.commit().map_err(|error| error.to_string())?;
                return Ok(false);
            }
            grant.event_kinds = normalized;
        } else {
            receipt.reporter_grants.push(OperationReporterGrant {
                principal: principal.to_string(),
                event_kinds: normalized,
            });
        }
        let updated_json = serde_json::to_string(&receipt).map_err(|error| error.to_string())?;
        transaction
            .execute(
                "UPDATE chisei_operation_receipts
                 SET receipt_json = $1, updated_at = $2
                 WHERE operation_id = $3",
                &[
                    &updated_json,
                    &chrono::Utc::now().timestamp_millis(),
                    &operation_id,
                ],
            )
            .map_err(|error| error.to_string())?;
        crate::db::postgres_receipt_chain::append_operation_receipt_chain(
            &mut transaction,
            &receipt,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

fn intent_attr(receipt: &OperationReceipt, key: &str) -> Option<String> {
    receipt.events.iter().find_map(|event| {
        (event.kind == ReceiptEventKind::IntentRecorded)
            .then(|| event.attributes.get(key))
            .flatten()
            .filter(|value| !value.is_empty())
            .cloned()
    })
}
