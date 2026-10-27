//! PostgreSQL parity for external action permits (issue, redeem, reconcile, delegation).

use std::collections::HashMap;

use crate::chisei::external_action::{AuthorizationRecord, REDEMPTION_VERSION};
use crate::chisei::external_permit::{
    DEFAULT_SITE_ID, ExternalPermitPolicy, HostContext, OFFLINE_REDEMPTION_MODE, Permit,
    Redemption, RedemptionTiming,
};
use ed25519_dalek::VerifyingKey;
use sekai_core::db::postgres::{PostgresDb, advisory_lock_key};
use sekai_core::db::postgres_decision::insert_chained_decision;
use sekai_core::sekai::audit::Decision;

pub trait PostgresExternalPermitPostgresDbExt {
    fn set_external_permit_policy(
        &self,
        policy: &ExternalPermitPolicy,
        now_ms: i64,
    ) -> Result<(), String>;

    fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String>;

    fn put_permit(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        issued_by: &str,
    ) -> Result<Permit, String>;

    fn replay_permit(
        &self,
        authorization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Permit>, String>;

    fn revoke_permit(
        &self,
        handle: &str,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn set_permit_kill_switch(
        &self,
        kind: &str,
        value: &str,
        enabled: bool,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String>;

    fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String>;

    fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String>;

    fn validate_permit_state(&self, permit: &Permit) -> Result<(), String>;

    fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String>;

    #[allow(clippy::too_many_arguments)]
    fn redeem_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        now_ms: i64,
    ) -> Result<Redemption, String>;

    #[allow(clippy::too_many_arguments)]
    fn redeem_or_reconcile_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        timing: RedemptionTiming,
    ) -> Result<Redemption, String>;

    fn replay_redemption(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        execution_id: &str,
    ) -> Result<Option<Redemption>, String>;
}

impl PostgresExternalPermitPostgresDbExt for PostgresDb {
    fn set_external_permit_policy(
        &self,
        policy: &ExternalPermitPolicy,
        now_ms: i64,
    ) -> Result<(), String> {
        if policy.scope.trim().is_empty()
            || policy.max_delegation_depth > 8
            || policy.offline_max_duration_ms < 0
        {
            return Err("invalid external permit policy bounds".into());
        }
        let json = serde_json::to_string(policy).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "INSERT INTO chisei_external_permit_policies(scope,policy_json,updated_at_ms)
                 VALUES($1,$2,$3)
                 ON CONFLICT(scope) DO UPDATE SET
                    policy_json = EXCLUDED.policy_json,
                    updated_at_ms = EXCLUDED.updated_at_ms",
                &[&policy.scope, &json, &now_ms],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
        let json: Option<String> = self
            .connection()?
            .query_opt(
                "SELECT policy_json FROM chisei_external_permit_policies WHERE scope=$1",
                &[&scope],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        json.map(|value| serde_json::from_str(&value).map_err(|error| error.to_string()))
            .transpose()
            .map(|value| value.unwrap_or_else(|| ExternalPermitPolicy::disabled(scope)))
    }

    fn put_permit(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        issued_by: &str,
    ) -> Result<Permit, String> {
        let json = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let inserted = tx
            .execute(
                "INSERT INTO chisei_external_action_permits(
                    permit_id, authorization_id, issuance_idempotency_key, permit_json, issued_at_ms
                 ) VALUES($1,$2,$3,$4,$5)
                 ON CONFLICT DO NOTHING",
                &[
                    &permit.permit_id,
                    &permit.authorization_id,
                    &idempotency_key,
                    &json,
                    &permit.issued_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT issuance_idempotency_key, permit_json
                 FROM chisei_external_action_permits
                 WHERE authorization_id=$1",
                &[&permit.authorization_id.as_str()],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "authorization permit row missing after put".to_string())?;
        let stored_key: String = row.get(0);
        let stored_json: String = row.get(1);
        if stored_key != idempotency_key {
            return Err(
                "authorization already has a permit under a different idempotency key".into(),
            );
        }
        let stored: Permit =
            serde_json::from_str(&stored_json).map_err(|error| error.to_string())?;
        if inserted == 1 {
            insert_chained_decision(
                &mut tx,
                &Decision {
                    id: format!("{}:audit:issued", stored.permit_id),
                    timestamp: stored.issued_at_ms,
                    actor: issued_by.into(),
                    action: format!("external_action_permit/{}", stored.action_type),
                    reason: "external_action_permit_issued".into(),
                    evidence: HashMap::from([
                        ("authorization_id".into(), stored.authorization_id.clone()),
                        ("request_digest".into(), stored.request_digest.clone()),
                        ("signed_digest".into(), stored.signed_digest.clone()),
                        ("key_id".into(), stored.key_id.clone()),
                    ]),
                    target_id: stored.permit_id.clone(),
                    outcome: "issued".into(),
                },
            )?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    fn replay_permit(
        &self,
        authorization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Permit>, String> {
        let existing = self
            .connection()?
            .query_opt(
                "SELECT issuance_idempotency_key, permit_json
                 FROM chisei_external_action_permits
                 WHERE authorization_id=$1",
                &[&authorization_id],
            )
            .map_err(|error| error.to_string())?;
        match existing {
            Some(row) => {
                let stored_key: String = row.get(0);
                let json: String = row.get(1);
                if stored_key != idempotency_key {
                    return Err(
                        "authorization already has a permit under a different idempotency key"
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

    fn revoke_permit(
        &self,
        handle: &str,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let changed = tx
            .execute(
                "INSERT INTO chisei_external_action_revocations(
                    revocation_handle, reason, revoked_at_ms
                 ) VALUES($1,$2,$3)
                 ON CONFLICT DO NOTHING",
                &[&handle, &reason, &now_ms],
            )
            .map_err(|error| error.to_string())?
            == 1;
        if changed {
            insert_chained_decision(
                &mut tx,
                &Decision {
                    id: format!("{handle}:audit:revoked"),
                    timestamp: now_ms,
                    actor: actor.into(),
                    action: "external_action_permit/revoke".into(),
                    reason: reason.into(),
                    evidence: HashMap::from([("revocation_handle".into(), handle.into())]),
                    target_id: handle.into(),
                    outcome: "revoked".into(),
                },
            )?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(changed)
    }

    fn set_permit_kill_switch(
        &self,
        kind: &str,
        value: &str,
        enabled: bool,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        if !matches!(
            kind,
            "action_type" | "executor" | "harness" | "namespace" | "signing_key"
        ) {
            return Err("unsupported kill-switch scope".into());
        }
        let changed = if enabled {
            self.connection()?.execute(
                "INSERT INTO chisei_external_action_kill_switches(
                    scope_kind, scope_value, reason, enabled_at_ms
                 ) VALUES($1,$2,$3,$4)
                 ON CONFLICT(scope_kind, scope_value) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    enabled_at_ms = EXCLUDED.enabled_at_ms",
                &[&kind, &value, &reason, &now_ms],
            )
        } else {
            self.connection()?.execute(
                "DELETE FROM chisei_external_action_kill_switches
                 WHERE scope_kind=$1 AND scope_value=$2",
                &[&kind, &value],
            )
        }
        .map_err(|error| error.to_string())?;
        Ok(changed != 0)
    }

    fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String> {
        if permit.delegation_depth == 0 || permit.parent_permit_id.is_empty() {
            return Err("delegated permit must name its parent".into());
        }
        self.validate_delegation_chain(permit)?;
        let json = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // Mirror SQLite Immediate: lock the parent before checking consumption
        // so a concurrent redeem cannot consume the same authority.
        lock_permit_authority(&mut tx, &permit.parent_permit_id)?;
        let parent_redemptions: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM chisei_external_action_redemptions WHERE permit_id=$1",
                &[&permit.parent_permit_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if parent_redemptions != 0 {
            return Err("partially consumed permit authority cannot be delegated".into());
        }
        tx.execute(
            "INSERT INTO chisei_external_action_delegated_permits(
                permit_id, parent_permit_id, permit_json, issued_at_ms
             ) VALUES($1,$2,$3,$4)",
            &[
                &permit.permit_id,
                &permit.parent_permit_id,
                &json,
                &permit.issued_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        insert_chained_decision(
            &mut tx,
            &Decision {
                id: format!("{}:audit:delegated", permit.permit_id),
                timestamp: permit.issued_at_ms,
                actor: issued_by.into(),
                action: "external_action_permit/delegate".into(),
                reason: "narrow_child_permit_issued".into(),
                evidence: HashMap::from([
                    ("parent_permit_id".into(), permit.parent_permit_id.clone()),
                    ("initiating_actor".into(), permit.initiating_actor.clone()),
                    (
                        "delegation_depth".into(),
                        permit.delegation_depth.to_string(),
                    ),
                ]),
                target_id: permit.permit_id.clone(),
                outcome: "delegated".into(),
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(permit.clone())
    }

    fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        validate_delegation_chain_on(&mut tx, permit)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn validate_permit_state(&self, permit: &Permit) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        validate_permit_state_on(&mut tx, permit)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        validate_permit_state_on(&mut tx, permit)?;
        let count: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM chisei_external_action_redemptions WHERE permit_id=$1",
                &[&permit.permit_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if count != 0 {
            return Err("partially consumed permit authority cannot be delegated".into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn redeem_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        now_ms: i64,
    ) -> Result<Redemption, String> {
        self.redeem_or_reconcile_permit(
            permit,
            context,
            trusted_key,
            idempotency_key,
            execution_id,
            host_site_id,
            RedemptionTiming {
                invoked_at_ms: 0,
                reconciled_at_ms: now_ms,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn redeem_or_reconcile_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        host_site_id: &str,
        timing: RedemptionTiming,
    ) -> Result<Redemption, String> {
        let RedemptionTiming {
            invoked_at_ms,
            reconciled_at_ms: now_ms,
        } = timing;
        let host_site_id = crate::config::validate_site_id(host_site_id)?;
        let permit_site = if permit.site_id.trim().is_empty() {
            DEFAULT_SITE_ID
        } else {
            permit.site_id.as_str()
        };
        if permit_site != host_site_id {
            return Err(format!(
                "permit is pinned to site '{permit_site}' (host site '{host_site_id}'); foreign pin fail closed"
            ));
        }
        let offline_reconciliation = permit.redemption_mode == OFFLINE_REDEMPTION_MODE;
        if offline_reconciliation
            && (invoked_at_ms < permit.not_before_ms
                || invoked_at_ms >= permit.expires_at_ms
                || invoked_at_ms > now_ms)
        {
            return Err("offline invocation time must be within the signed lease and no later than reconciliation".into());
        }
        if !offline_reconciliation && invoked_at_ms != 0 {
            return Err("invoked_at_ms is only valid for offline reconciliation".into());
        }
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // Mirror SQLite Immediate: lock before replay, delegated-child, and
        // ordinal allocation so concurrent redeem/delegate cannot split authority.
        lock_permit_authority(&mut tx, &permit.permit_id)?;
        validate_delegation_chain_on(&mut tx, permit)?;
        let stored_json = load_permit_json(&mut tx, &permit.permit_id)?;
        let supplied = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        if stored_json.as_deref() != Some(supplied.as_str()) {
            return Err("permit is not the issued durable permit".into());
        }
        if let Some(json) = tx
            .query_opt(
                "SELECT redemption_json FROM chisei_external_action_redemptions
                 WHERE permit_id=$1 AND idempotency_key=$2",
                &[&permit.permit_id, &idempotency_key],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0))
        {
            let existing: Redemption =
                serde_json::from_str(&json).map_err(|error| error.to_string())?;
            if existing.execution_id != execution_id {
                return Err("redemption idempotency key reused for a different execution".into());
            }
            return Ok(existing);
        }
        let delegated_child: Option<String> = tx
            .query_opt(
                "SELECT permit_id FROM chisei_external_action_delegated_permits
                 WHERE parent_permit_id=$1",
                &[&permit.permit_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if delegated_child.is_some() {
            return Err("permit authority was transferred to a delegated child".into());
        }
        permit.verify_signature(trusted_key)?;
        let validation_time = if offline_reconciliation {
            invoked_at_ms
        } else {
            now_ms
        };
        permit.verify_host_context(context, validation_time)?;
        let authorization_json: Option<String> = tx
            .query_opt(
                "SELECT record_json FROM chisei_external_action_authorizations
                 WHERE authorization_id=$1",
                &[&permit.authorization_id],
            )
            .map_err(|error| error.to_string())?
            .and_then(|row| row.get::<_, Option<String>>(0));
        let authorization: AuthorizationRecord = authorization_json
            .as_deref()
            .ok_or_else(|| "permit authorization is missing".to_string())
            .and_then(|json| serde_json::from_str(json).map_err(|error| error.to_string()))?;
        if !offline_reconciliation
            && (authorization.decision.decision != "permit"
                || authorization.decision.cancelled_at_ms != 0
                || authorization.decision.request_digest != permit.request_digest)
        {
            return Err("permit authorization is no longer active".into());
        }
        let revoked: Option<String> = tx
            .query_opt(
                "SELECT reason FROM chisei_external_action_revocations
                 WHERE revocation_handle=$1",
                &[&permit.revocation_handle],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if !offline_reconciliation && let Some(reason) = revoked {
            return Err(format!("permit revoked: {reason}"));
        }
        for (kind, value) in [
            ("action_type", permit.action_type.as_str()),
            ("executor", permit.executor.as_str()),
            ("harness", permit.requesting_harness.as_str()),
            ("namespace", permit.namespace.as_str()),
            ("signing_key", permit.key_id.as_str()),
        ] {
            let reason: Option<String> = tx
                .query_opt(
                    "SELECT reason FROM chisei_external_action_kill_switches
                     WHERE scope_kind=$1 AND scope_value=$2",
                    &[&kind, &value],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get(0));
            if !offline_reconciliation && let Some(reason) = reason {
                return Err(format!("{kind} kill switch active: {reason}"));
            }
        }
        let count: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM chisei_external_action_redemptions WHERE permit_id=$1",
                &[&permit.permit_id],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        if count >= permit.max_invocations {
            return Err("permit invocation count exhausted".into());
        }
        let redemption = Redemption {
            version: REDEMPTION_VERSION.into(),
            permit_id: permit.permit_id.clone(),
            redemption_id: format!("redemption-{}", uuid::Uuid::new_v4().simple()),
            executor: context.executor.clone(),
            execution_id: execution_id.into(),
            idempotency_key: idempotency_key.into(),
            redeemed_at_ms: if offline_reconciliation {
                invoked_at_ms
            } else {
                now_ms
            },
            invocation_ordinal: count + 1,
            evidence_due_at_ms: permit.expires_at_ms,
            site_id: host_site_id.clone(),
        };
        let json = serde_json::to_string(&redemption).map_err(|error| error.to_string())?;
        let ordinal = i64::from(redemption.invocation_ordinal);
        tx.execute(
            "INSERT INTO chisei_external_action_redemptions(
                permit_id, idempotency_key, execution_id, redemption_json,
                redeemed_at_ms, invocation_ordinal, redemption_id, evidence_due_at_ms
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &permit.permit_id,
                &idempotency_key,
                &execution_id,
                &json,
                &redemption.redeemed_at_ms,
                &ordinal,
                &redemption.redemption_id,
                &redemption.evidence_due_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        insert_chained_decision(
            &mut tx,
            &Decision {
                id: format!("{}:audit:redeemed", redemption.redemption_id),
                timestamp: redemption.redeemed_at_ms,
                actor: context.executor.clone(),
                action: format!(
                    "external_action_{}/{}",
                    if offline_reconciliation {
                        "reconcile"
                    } else {
                        "redeem"
                    },
                    permit.action_type
                ),
                reason: if offline_reconciliation {
                    "offline_invocation_reconciled_after_local_consumption".into()
                } else {
                    "external_action_permit_redeemed_before_execution".into()
                },
                evidence: HashMap::from([
                    ("permit_id".into(), permit.permit_id.clone()),
                    ("execution_id".into(), redemption.execution_id.clone()),
                    (
                        "invocation_ordinal".into(),
                        redemption.invocation_ordinal.to_string(),
                    ),
                    ("site_id".into(), redemption.site_id.clone()),
                ]),
                target_id: permit.permit_id.clone(),
                outcome: if offline_reconciliation {
                    "offline_invocation_recorded_with_weaker_guarantees".into()
                } else {
                    "authorization_consumed".into()
                },
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(redemption)
    }

    fn replay_redemption(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        execution_id: &str,
    ) -> Result<Option<Redemption>, String> {
        let mut connection = self.connection()?;
        let stored_json = connection
            .query_opt(
                "SELECT permit_json FROM (
                    SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=$1
                    UNION ALL
                    SELECT permit_json FROM chisei_external_action_delegated_permits WHERE permit_id=$1
                 ) q LIMIT 1",
                &[&permit.permit_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0));
        let supplied = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        if stored_json.as_deref() != Some(supplied.as_str()) {
            return Err("permit is not the issued durable permit".into());
        }
        let existing = connection
            .query_opt(
                "SELECT redemption_json FROM chisei_external_action_redemptions
                 WHERE permit_id=$1 AND idempotency_key=$2",
                &[&permit.permit_id, &idempotency_key],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0));
        existing
            .map(|json| {
                serde_json::from_str::<Redemption>(&json).map_err(|error| error.to_string())
            })
            .transpose()
            .and_then(|value| {
                if value
                    .as_ref()
                    .is_some_and(|redemption| redemption.execution_id != execution_id)
                {
                    Err("redemption idempotency key reused for a different execution".into())
                } else {
                    Ok(value)
                }
            })
    }
}

fn lock_permit_authority(
    tx: &mut postgres::Transaction<'_>,
    permit_id: &str,
) -> Result<(), String> {
    let lock_key = advisory_lock_key(&["external_action_permit", permit_id]);
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        &[&lock_key],
    )
    .map(|_| ())
    .map_err(|error| format!("lock external-action permit: {error}"))
}

fn load_permit_json(
    tx: &mut postgres::Transaction<'_>,
    permit_id: &str,
) -> Result<Option<String>, String> {
    Ok(tx
        .query_opt(
            "SELECT permit_json FROM (
                SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=$1
                UNION ALL
                SELECT permit_json FROM chisei_external_action_delegated_permits WHERE permit_id=$1
             ) q LIMIT 1",
            &[&permit_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0)))
}

fn validate_permit_state_on(
    tx: &mut postgres::Transaction<'_>,
    permit: &Permit,
) -> Result<(), String> {
    validate_delegation_chain_on(tx, permit)?;
    let stored_json = load_permit_json(tx, &permit.permit_id)?;
    let supplied = serde_json::to_string(permit).map_err(|error| error.to_string())?;
    if stored_json.as_deref() != Some(supplied.as_str()) {
        return Err("permit is not the issued durable permit".into());
    }
    let delegated_child: Option<String> = tx
        .query_opt(
            "SELECT permit_id FROM chisei_external_action_delegated_permits
             WHERE parent_permit_id=$1",
            &[&permit.permit_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    if delegated_child.is_some() {
        return Err("permit authority was transferred to a delegated child".into());
    }
    let authorization_json: Option<String> = tx
        .query_opt(
            "SELECT record_json FROM chisei_external_action_authorizations
             WHERE authorization_id=$1",
            &[&permit.authorization_id],
        )
        .map_err(|error| error.to_string())?
        .and_then(|row| row.get::<_, Option<String>>(0));
    let authorization: AuthorizationRecord = authorization_json
        .as_deref()
        .ok_or_else(|| "permit authorization is missing".to_string())
        .and_then(|json| serde_json::from_str(json).map_err(|error| error.to_string()))?;
    if authorization.decision.decision != "permit"
        || authorization.decision.cancelled_at_ms != 0
        || authorization.decision.request_digest != permit.request_digest
    {
        return Err("permit authorization is no longer active".into());
    }
    let revoked: Option<String> = tx
        .query_opt(
            "SELECT reason FROM chisei_external_action_revocations
             WHERE revocation_handle=$1",
            &[&permit.revocation_handle],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    if let Some(reason) = revoked {
        return Err(format!("permit revoked: {reason}"));
    }
    for (kind, value) in [
        ("action_type", permit.action_type.as_str()),
        ("executor", permit.executor.as_str()),
        ("harness", permit.requesting_harness.as_str()),
        ("namespace", permit.namespace.as_str()),
        ("signing_key", permit.key_id.as_str()),
    ] {
        let reason: Option<String> = tx
            .query_opt(
                "SELECT reason FROM chisei_external_action_kill_switches
                 WHERE scope_kind=$1 AND scope_value=$2",
                &[&kind, &value],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if let Some(reason) = reason {
            return Err(format!("{kind} kill switch active: {reason}"));
        }
    }
    let count: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM chisei_external_action_redemptions WHERE permit_id=$1",
            &[&permit.permit_id],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    let count = u32::try_from(count).unwrap_or(u32::MAX);
    if count >= permit.max_invocations {
        return Err("permit invocation count exhausted".into());
    }
    Ok(())
}

fn validate_delegation_chain_on(
    tx: &mut postgres::Transaction<'_>,
    permit: &Permit,
) -> Result<(), String> {
    if permit.delegation_depth as usize != permit.parent_chain.len() {
        return Err("delegation chain depth mismatch".into());
    }
    let current_policy = if permit.delegation_depth == 0 {
        None
    } else {
        let json: Option<String> = tx
            .query_opt(
                "SELECT policy_json FROM chisei_external_permit_policies WHERE scope=$1",
                &[&permit.policy_scope],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        let policy: ExternalPermitPolicy = json
            .ok_or_else(|| "delegation policy is missing or disabled".to_string())
            .and_then(|value| serde_json::from_str(&value).map_err(|error| error.to_string()))?;
        if permit.delegation_depth > policy.max_delegation_depth {
            return Err("delegation exceeds the current policy depth".into());
        }
        Some(policy)
    };
    for (index, parent_id) in permit.parent_chain.iter().enumerate() {
        let json = load_permit_json(tx, parent_id)?;
        let parent: Permit = json
            .ok_or_else(|| "delegation parent is missing".to_string())
            .and_then(|value| serde_json::from_str(&value).map_err(|error| error.to_string()))?;
        if parent.expires_at_ms <= permit.issued_at_ms {
            return Err("delegation parent expired before child issuance".into());
        }
        if !current_policy
            .as_ref()
            .is_some_and(|policy| policy.permitted_delegators.contains(&parent.subject_actor))
        {
            return Err("delegation chain contains an actor no longer permitted by policy".into());
        }
        let revoked: Option<String> = tx
            .query_opt(
                "SELECT reason FROM chisei_external_action_revocations
                 WHERE revocation_handle=$1",
                &[&parent.revocation_handle],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        if revoked.is_some() {
            return Err("delegation parent is revoked".into());
        }
        if parent.parent_chain != permit.parent_chain[..index] {
            return Err("delegation parent chain is malformed".into());
        }
    }
    Ok(())
}
