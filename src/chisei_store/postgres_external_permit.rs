//! PostgreSQL parity for external action permits (issue, policy, revoke, kill-switch).

use std::collections::HashMap;

use crate::chisei::external_permit::{ExternalPermitPolicy, Permit};
use crate::db::postgres::PostgresDb;
use crate::db::postgres_decision::insert_chained_decision;
use crate::sekai::audit::Decision;

impl PostgresDb {
    pub fn set_external_permit_policy(
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

    pub fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
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

    pub fn put_permit(
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

    pub fn replay_permit(
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

    pub fn revoke_permit(
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

    pub fn set_permit_kill_switch(
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
}
