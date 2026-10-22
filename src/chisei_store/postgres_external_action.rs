//! PostgreSQL external-action authorization and blast-radius reservation.

use crate::chisei::external_action::{
    AuthorizationClaim, AuthorizationRecord, ExternalActionRequest,
};
use crate::db::postgres::PostgresDb;

/// Claim lease duration for in-progress authorization claims (matches SQLite).
const CLAIM_LEASE_MS: i64 = 30_000;

impl PostgresDb {
    pub fn claim_external_action_authorization(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
        authorization_id: &str,
        now_ms: i64,
    ) -> Result<AuthorizationClaim, String> {
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let inserted = transaction
            .execute(
                "INSERT INTO chisei_external_action_authorizations
                 (actor, operation_id, idempotency_key, request_digest, authorization_id,
                  record_json, claimed_at_ms)
                 VALUES ($1, $2, $3, $4, $5, NULL, $6)
                 ON CONFLICT DO NOTHING",
                &[
                    &request.actor,
                    &request.operation_id,
                    &request.idempotency_key,
                    &request_digest,
                    &authorization_id,
                    &now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        if inserted == 1 {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(AuthorizationClaim::Claimed(authorization_id.to_string()));
        }
        let row = transaction
            .query_one(
                "SELECT request_digest, record_json, claimed_at_ms, authorization_id
                 FROM chisei_external_action_authorizations
                 WHERE actor = $1 AND operation_id = $2 AND idempotency_key = $3",
                &[
                    &request.actor,
                    &request.operation_id,
                    &request.idempotency_key,
                ],
            )
            .map_err(|error| error.to_string())?;
        let stored_digest: String = row.get(0);
        let record_json: Option<String> = row.get(1);
        let claimed_at_ms: i64 = row.get(2);
        let stored_authorization_id: String = row.get(3);
        if stored_digest != request_digest {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(AuthorizationClaim::Conflict);
        }
        let claim = match record_json {
            Some(json) => serde_json::from_str(&json)
                .map(|record| AuthorizationClaim::Existing(Box::new(record)))
                .map_err(|error| error.to_string())?,
            None if now_ms.saturating_sub(claimed_at_ms) >= CLAIM_LEASE_MS => {
                let reclaimed = transaction
                    .execute(
                        "UPDATE chisei_external_action_authorizations SET claimed_at_ms = $1
                         WHERE actor = $2 AND operation_id = $3 AND idempotency_key = $4
                           AND record_json IS NULL AND claimed_at_ms = $5",
                        &[
                            &now_ms,
                            &request.actor,
                            &request.operation_id,
                            &request.idempotency_key,
                            &claimed_at_ms,
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                if reclaimed == 1 {
                    AuthorizationClaim::Claimed(stored_authorization_id)
                } else {
                    AuthorizationClaim::InProgress
                }
            }
            None => AuthorizationClaim::InProgress,
        };
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(claim)
    }

    pub fn abandon_external_action_claim(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "DELETE FROM chisei_external_action_authorizations
                 WHERE actor = $1 AND operation_id = $2 AND idempotency_key = $3
                   AND request_digest = $4 AND record_json IS NULL",
                &[
                    &request.actor,
                    &request.operation_id,
                    &request.idempotency_key,
                    &request_digest,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Atomically replace one exact lifecycle snapshot. A concurrent terminal
    /// transition makes this return `false` instead of overwriting its result.
    pub fn compare_and_swap_external_action_authorization(
        &self,
        expected: &AuthorizationRecord,
        next: &AuthorizationRecord,
    ) -> Result<bool, String> {
        let expected_json = serde_json::to_string(expected).map_err(|error| error.to_string())?;
        let next_json = serde_json::to_string(next).map_err(|error| error.to_string())?;
        self.connection()?
            .execute(
                "UPDATE chisei_external_action_authorizations SET record_json = $1
                 WHERE authorization_id = $2 AND request_digest = $3 AND record_json = $4",
                &[
                    &next_json,
                    &next.decision.authorization_id,
                    &next.decision.request_digest,
                    &expected_json,
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    /// Atomically reserve cumulative external effects for one operation.
    pub fn reserve_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
        max_mutations: Option<u32>,
        max_deletes: Option<u32>,
    ) -> Result<(), String> {
        let mutations = request.total_affected_resources()?;
        let deletes = if request.risk_class == "destructive" {
            mutations
        } else {
            0
        };
        let mutations_i64 = i64::from(mutations);
        let deletes_i64 = i64::from(deletes);
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key =
            blast_radius_lock_key(&request.actor, &request.namespace, &request.operation_id);
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock_key],
            )
            .map_err(|error| format!("lock external-action blast radius: {error}"))?;
        let existing_claim = transaction
            .query_opt(
                "SELECT actor, namespace, operation_id, mutations, deletes
                 FROM chisei_external_action_blast_claims WHERE authorization_id = $1",
                &[&authorization_id],
            )
            .map_err(|error| error.to_string())?;
        if let Some(row) = existing_claim {
            let existing = (
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
                u32::try_from(row.get::<_, i64>(3)).unwrap_or(u32::MAX),
                u32::try_from(row.get::<_, i64>(4)).unwrap_or(u32::MAX),
            );
            let expected = (
                request.actor.clone(),
                request.namespace.clone(),
                request.operation_id.clone(),
                mutations,
                deletes,
            );
            if existing != expected {
                return Err("external-action blast reservation identity conflict".into());
            }
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(());
        }
        let (used_mutations, used_deletes) = transaction
            .query_opt(
                "SELECT mutations, deletes FROM chisei_external_action_reservations
                 WHERE actor = $1 AND namespace = $2 AND operation_id = $3",
                &[&request.actor, &request.namespace, &request.operation_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                (
                    u32::try_from(row.get::<_, i64>(0)).unwrap_or(u32::MAX),
                    u32::try_from(row.get::<_, i64>(1)).unwrap_or(u32::MAX),
                )
            })
            .unwrap_or_default();
        let next_mutations = used_mutations.saturating_add(mutations);
        let next_deletes = used_deletes.saturating_add(deletes);
        if max_mutations.is_some_and(|cap| next_mutations > cap)
            || max_deletes.is_some_and(|cap| next_deletes > cap)
        {
            return Err("external-action blast-radius cap exceeded".into());
        }
        let next_mutations_i64 = i64::from(next_mutations);
        let next_deletes_i64 = i64::from(next_deletes);
        transaction
            .execute(
                "INSERT INTO chisei_external_action_reservations
                    (actor, namespace, operation_id, mutations, deletes)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (actor, namespace, operation_id) DO UPDATE SET
                    mutations = EXCLUDED.mutations,
                    deletes = EXCLUDED.deletes",
                &[
                    &request.actor,
                    &request.namespace,
                    &request.operation_id,
                    &next_mutations_i64,
                    &next_deletes_i64,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "INSERT INTO chisei_external_action_blast_claims
                    (authorization_id, actor, namespace, operation_id, mutations, deletes)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &authorization_id,
                    &request.actor,
                    &request.namespace,
                    &request.operation_id,
                    &mutations_i64,
                    &deletes_i64,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn release_external_action_blast_radius(
        &self,
        authorization_id: &str,
        request: &ExternalActionRequest,
    ) -> Result<(), String> {
        let mutations = request.total_affected_resources()?;
        let deletes = if request.risk_class == "destructive" {
            mutations
        } else {
            0
        };
        let mutations_i64 = i64::from(mutations);
        let deletes_i64 = i64::from(deletes);
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // Mirror SQLite Immediate transaction serialization for concurrent release.
        let lock_key =
            blast_radius_lock_key(&request.actor, &request.namespace, &request.operation_id);
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock_key],
            )
            .map_err(|error| format!("lock external-action blast release: {error}"))?;
        let released_at_ms = chrono::Utc::now().timestamp_millis();
        let inserted = transaction
            .execute(
                "INSERT INTO chisei_external_action_releases
                    (authorization_id, released_at_ms)
                 VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[&authorization_id, &released_at_ms],
            )
            .map_err(|error| error.to_string())?;
        if inserted == 1 {
            transaction
                .execute(
                    "UPDATE chisei_external_action_reservations
                     SET mutations = GREATEST(0, mutations - $4),
                         deletes = GREATEST(0, deletes - $5)
                     WHERE actor = $1 AND namespace = $2 AND operation_id = $3",
                    &[
                        &request.actor,
                        &request.namespace,
                        &request.operation_id,
                        &mutations_i64,
                        &deletes_i64,
                    ],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn get_external_action_authorization(
        &self,
        actor: &str,
        operation_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<AuthorizationRecord>, String> {
        let record_json = self
            .connection()?
            .query_opt(
                "SELECT record_json FROM chisei_external_action_authorizations
                 WHERE actor = $1 AND operation_id = $2 AND idempotency_key = $3",
                &[&actor, &operation_id, &idempotency_key],
            )
            .map_err(|error| error.to_string())?
            .and_then(|row| row.get::<_, Option<String>>(0));
        record_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn put_external_action_authorization(
        &self,
        record: &AuthorizationRecord,
    ) -> Result<(), String> {
        let record_json = serde_json::to_string(record).map_err(|error| error.to_string())?;
        let updated = self
            .connection()?
            .execute(
                "UPDATE chisei_external_action_authorizations SET record_json = $1
                 WHERE actor = $2 AND operation_id = $3 AND idempotency_key = $4
                   AND request_digest = $5",
                &[
                    &record_json,
                    &record.request.actor,
                    &record.request.operation_id,
                    &record.request.idempotency_key,
                    &record.decision.request_digest,
                ],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("external-action authorization claim not found".into());
        }
        Ok(())
    }

    pub fn get_external_action_authorization_by_id(
        &self,
        authorization_id: &str,
    ) -> Result<Option<AuthorizationRecord>, String> {
        let record_json = self
            .connection()?
            .query_opt(
                "SELECT record_json FROM chisei_external_action_authorizations
                 WHERE authorization_id = $1",
                &[&authorization_id],
            )
            .map_err(|error| error.to_string())?
            .and_then(|row| row.get::<_, Option<String>>(0));
        record_json
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String> {
        let rows = self
            .connection()?
            .query(
                "SELECT record_json FROM chisei_external_action_authorizations
                 WHERE record_json IS NOT NULL",
                &[],
            )
            .map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| {
                let json: String = row.get(0);
                serde_json::from_str(&json).map_err(|error| error.to_string())
            })
            .collect()
    }
}

fn blast_radius_lock_key(actor: &str, namespace: &str, operation_id: &str) -> String {
    format!("external-action-blast:{actor}:{namespace}:{operation_id}")
}
