//! Versioned contracts and durable authorization state for host-executed actions.
//!
//! Chisei decides whether bounded external authority may be granted. It never
//! executes the action and this module deliberately does not issue permits;
//! permit signing and redemption are owned by the follow-on permit work.

use crate::db::sekai::SekaiDb;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const REQUEST_VERSION: &str = "external-action.request/v1";
pub const DECISION_VERSION: &str = "external-action.decision/v1";
pub const PERMIT_VERSION: &str = "external-action.permit/v1";
pub const REDEMPTION_VERSION: &str = "external-action.redemption/v1";
pub const EVIDENCE_VERSION: &str = "external-action.evidence/v1";
pub const ASSURANCE_VERSION: &str = "external-action.assurance/v1";
pub const AUTHORIZATION_KIND: &str = "external_action_authorization";
const CLAIM_LEASE_MS: i64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionRequest {
    pub version: String,
    pub operation_id: String,
    pub parent_operation_id: String,
    pub attempt_id: String,
    pub request_id: String,
    pub actor: String,
    pub namespace: String,
    pub requesting_harness: String,
    pub intended_executor: String,
    pub action_type: String,
    pub parameter_schema: String,
    pub canonical_arguments_digest: String,
    pub policy_summary: BTreeMap<String, String>,
    pub target_selectors: Vec<String>,
    pub immutable_preconditions: BTreeMap<String, String>,
    pub risk_class: String,
    pub expected_effects: Vec<String>,
    pub requested_invocation_count: u32,
    pub deadline_ms: i64,
    pub estimated_cost_micros: u64,
    pub estimated_volume: u64,
    pub affected_resource_count: u32,
    pub rollback_capability: String,
    pub required_host_capabilities: Vec<String>,
    pub idempotency_key: String,
    pub policy_project: String,
}

impl ExternalActionRequest {
    pub fn authoritative_risk_class(&self) -> Result<&'static str, String> {
        let contract = self
            .action_type
            .rsplit_once('/')
            .map(|(contract, _version)| contract)
            .ok_or_else(|| "action_type must be a versioned contract".to_string())?;
        if contract.ends_with(".read") {
            Ok("read")
        } else if contract.ends_with(".write") {
            Ok("write")
        } else if contract.ends_with(".destructive") {
            Ok("destructive")
        } else {
            Err("action_type must encode its read, write, or destructive risk class".into())
        }
    }

    pub fn total_affected_resources(&self) -> Result<u32, String> {
        self.affected_resource_count
            .checked_mul(self.requested_invocation_count)
            .ok_or_else(|| "external-action total affected-resource count overflows".to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != REQUEST_VERSION {
            return Err(format!(
                "unsupported external-action request version {}",
                self.version
            ));
        }
        for (name, value) in [
            ("operation_id", &self.operation_id),
            ("attempt_id", &self.attempt_id),
            ("request_id", &self.request_id),
            ("actor", &self.actor),
            ("namespace", &self.namespace),
            ("requesting_harness", &self.requesting_harness),
            ("intended_executor", &self.intended_executor),
            ("action_type", &self.action_type),
            ("parameter_schema", &self.parameter_schema),
            (
                "canonical_arguments_digest",
                &self.canonical_arguments_digest,
            ),
            ("risk_class", &self.risk_class),
            ("idempotency_key", &self.idempotency_key),
            ("policy_project", &self.policy_project),
        ] {
            if value.trim().is_empty() || value.trim() != value {
                return Err(format!("{name} must be non-empty canonical text"));
            }
        }
        if !matches!(self.risk_class.as_str(), "read" | "write" | "destructive") {
            return Err("risk_class must be read, write, or destructive".into());
        }
        if self.risk_class != self.authoritative_risk_class()? {
            return Err("risk_class does not match the versioned action_type contract".into());
        }
        let project_selector = format!("project:{}", self.policy_project);
        if self.target_selectors.is_empty()
            || self.target_selectors.iter().any(|selector| {
                selector != &project_selector
                    && !selector.starts_with(&format!("{project_selector}/"))
            })
        {
            return Err("target selectors must be rooted in the canonical policy project".into());
        }
        if self.requested_invocation_count == 0 {
            return Err("requested_invocation_count must be greater than zero".into());
        }
        if matches!(self.risk_class.as_str(), "write" | "destructive")
            && self.affected_resource_count == 0
        {
            return Err("mutating external actions must affect at least one resource".into());
        }
        self.total_affected_resources()?;
        if self.deadline_ms <= 0 {
            return Err("deadline_ms must be greater than zero".into());
        }
        if self.policy_summary.keys().any(|key| {
            let key = key.to_ascii_lowercase();
            [
                "token",
                "secret",
                "password",
                "passphrase",
                "credential",
                "private_key",
                "api_key",
            ]
            .iter()
            .any(|sensitive| key.contains(sensitive))
        }) {
            return Err("policy_summary must not contain secret-bearing fields".into());
        }
        if self.policy_summary.len() > 64
            || self.immutable_preconditions.len() > 64
            || self.target_selectors.len() > 128
            || self.expected_effects.len() > 128
            || self.required_host_capabilities.len() > 128
        {
            return Err("external-action request exceeds bounded contract limits".into());
        }
        let scalar_fields = [
            &self.operation_id,
            &self.parent_operation_id,
            &self.attempt_id,
            &self.request_id,
            &self.actor,
            &self.namespace,
            &self.requesting_harness,
            &self.intended_executor,
            &self.action_type,
            &self.parameter_schema,
            &self.canonical_arguments_digest,
            &self.rollback_capability,
            &self.idempotency_key,
            &self.policy_project,
        ];
        if scalar_fields.iter().any(|value| value.len() > 4_096)
            || self
                .policy_summary
                .iter()
                .chain(self.immutable_preconditions.iter())
                .any(|(key, value)| key.len() > 128 || value.len() > 4_096)
            || self
                .target_selectors
                .iter()
                .chain(self.expected_effects.iter())
                .chain(self.required_host_capabilities.iter())
                .any(|value| value.len() > 4_096)
        {
            return Err("external-action request field exceeds size limit".into());
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > 64 * 1024
        {
            return Err("external-action request exceeds 64 KiB".into());
        }
        Ok(())
    }

    /// Stable, domain-separated digest over the full policy-relevant request.
    pub fn canonical_digest(&self) -> Result<String, String> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(b"sekai-chisei:external-action-request:v1\0");
        hasher.update((encoded.len() as u64).to_be_bytes());
        hasher.update(encoded);
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalActionDecision {
    pub version: String,
    pub authorization_id: String,
    pub request_digest: String,
    pub decision: String,
    pub reason: String,
    pub approval_id: String,
    pub policy_scope: String,
    pub policy_version: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub cancelled_at_ms: i64,
    pub assurance: AssuranceDeclaration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceDeclaration {
    pub version: String,
    pub authorization_only: bool,
    pub host_must_verify_permit: bool,
    pub host_must_enforce_constraints: bool,
    pub physical_effect_verified: bool,
}

impl Default for AssuranceDeclaration {
    fn default() -> Self {
        Self {
            version: ASSURANCE_VERSION.into(),
            authorization_only: true,
            host_must_verify_permit: true,
            host_must_enforce_constraints: true,
            physical_effect_verified: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRecord {
    pub request: ExternalActionRequest,
    pub decision: ExternalActionDecision,
    pub approval_status: String,
    #[serde(default)]
    pub budget_reserved: bool,
    #[serde(default)]
    pub blast_radius_reserved: bool,
    #[serde(default)]
    pub decision_actor: String,
    #[serde(default)]
    pub decision_updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationClaim {
    Claimed(String),
    Existing(Box<AuthorizationRecord>),
    Conflict,
    InProgress,
}

impl SekaiDb {
    fn ensure_external_action_tables(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_external_action_reservations (
                    actor TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    mutations INTEGER NOT NULL,
                    deletes INTEGER NOT NULL,
                    PRIMARY KEY(actor, namespace, operation_id)
                );
                CREATE TABLE IF NOT EXISTS chisei_external_action_authorizations (
                    actor TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    authorization_id TEXT NOT NULL UNIQUE,
                    record_json TEXT,
                    claimed_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(actor, operation_id, idempotency_key)
                );
                CREATE TABLE IF NOT EXISTS chisei_external_action_releases (
                    authorization_id TEXT PRIMARY KEY,
                    released_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chisei_external_action_blast_claims (
                    authorization_id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    mutations INTEGER NOT NULL,
                    deletes INTEGER NOT NULL
                );",
            )
            .map_err(|error| error.to_string())
    }

    pub fn claim_external_action_authorization(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
        authorization_id: &str,
        now_ms: i64,
    ) -> Result<AuthorizationClaim, String> {
        self.ensure_external_action_tables()?;
        let conn = self.conn();
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO chisei_external_action_authorizations
             (actor,operation_id,idempotency_key,request_digest,authorization_id,record_json,claimed_at_ms)
             VALUES(?1,?2,?3,?4,?5,NULL,?6)",
            rusqlite::params![request.actor, request.operation_id, request.idempotency_key, request_digest, authorization_id, now_ms],
        ).map_err(|error| error.to_string())?;
        if inserted == 1 {
            return Ok(AuthorizationClaim::Claimed(authorization_id.to_string()));
        }
        let (stored_digest, record_json, claimed_at_ms, stored_authorization_id) = conn
            .query_row(
                "SELECT request_digest, record_json, claimed_at_ms, authorization_id FROM chisei_external_action_authorizations
             WHERE actor=?1 AND operation_id=?2 AND idempotency_key=?3",
                rusqlite::params![request.actor, request.operation_id, request.idempotency_key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?;
        if stored_digest != request_digest {
            return Ok(AuthorizationClaim::Conflict);
        }
        match record_json {
            Some(json) => serde_json::from_str(&json)
                .map(|record| AuthorizationClaim::Existing(Box::new(record)))
                .map_err(|error| error.to_string()),
            None if now_ms.saturating_sub(claimed_at_ms) >= CLAIM_LEASE_MS => {
                let reclaimed = conn
                    .execute(
                        "UPDATE chisei_external_action_authorizations SET claimed_at_ms=?1
                     WHERE actor=?2 AND operation_id=?3 AND idempotency_key=?4
                       AND record_json IS NULL AND claimed_at_ms=?5",
                        rusqlite::params![
                            now_ms,
                            request.actor,
                            request.operation_id,
                            request.idempotency_key,
                            claimed_at_ms
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                Ok(if reclaimed == 1 {
                    AuthorizationClaim::Claimed(stored_authorization_id)
                } else {
                    AuthorizationClaim::InProgress
                })
            }
            None => Ok(AuthorizationClaim::InProgress),
        }
    }

    pub fn abandon_external_action_claim(
        &self,
        request: &ExternalActionRequest,
        request_digest: &str,
    ) -> Result<(), String> {
        self.ensure_external_action_tables()?;
        self.conn()
            .execute(
                "DELETE FROM chisei_external_action_authorizations
             WHERE actor=?1 AND operation_id=?2 AND idempotency_key=?3
               AND request_digest=?4 AND record_json IS NULL",
                rusqlite::params![
                    request.actor,
                    request.operation_id,
                    request.idempotency_key,
                    request_digest
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
        self.ensure_external_action_tables()?;
        let expected_json = serde_json::to_string(expected).map_err(|error| error.to_string())?;
        let next_json = serde_json::to_string(next).map_err(|error| error.to_string())?;
        self.conn()
            .execute(
                "UPDATE chisei_external_action_authorizations SET record_json=?1
             WHERE authorization_id=?2 AND request_digest=?3 AND record_json=?4",
                rusqlite::params![
                    next_json,
                    next.decision.authorization_id,
                    next.decision.request_digest,
                    expected_json
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
        self.ensure_external_action_tables()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let existing_claim: Option<(String, String, String, u32, u32)> = tx
            .query_row(
                "SELECT actor,namespace,operation_id,mutations,deletes
                 FROM chisei_external_action_blast_claims WHERE authorization_id=?1",
                rusqlite::params![authorization_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(existing) = existing_claim {
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
            return Ok(());
        }
        let (used_mutations, used_deletes) = tx
            .query_row(
                "SELECT mutations, deletes FROM chisei_external_action_reservations WHERE actor=?1 AND namespace=?2 AND operation_id=?3",
                rusqlite::params![request.actor, request.namespace, request.operation_id],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        let next_mutations = used_mutations.saturating_add(mutations);
        let next_deletes = used_deletes.saturating_add(deletes);
        if max_mutations.is_some_and(|cap| next_mutations > cap)
            || max_deletes.is_some_and(|cap| next_deletes > cap)
        {
            return Err("external-action blast-radius cap exceeded".into());
        }
        tx.execute(
            "INSERT INTO chisei_external_action_reservations(actor,namespace,operation_id,mutations,deletes)
             VALUES(?1,?2,?3,?4,?5) ON CONFLICT(actor,namespace,operation_id)
             DO UPDATE SET mutations=?4,deletes=?5",
            rusqlite::params![request.actor, request.namespace, request.operation_id, next_mutations, next_deletes],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO chisei_external_action_blast_claims
             (authorization_id,actor,namespace,operation_id,mutations,deletes)
             VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                authorization_id,
                request.actor,
                request.namespace,
                request.operation_id,
                mutations,
                deletes
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())
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
        self.ensure_external_action_tables()?;
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO chisei_external_action_releases(authorization_id,released_at_ms)
             VALUES(?1,?2)",
            rusqlite::params![authorization_id, chrono::Utc::now().timestamp_millis()],
        ).map_err(|error| error.to_string())?;
        if inserted == 1 {
            transaction
                .execute(
                    "UPDATE chisei_external_action_reservations
                 SET mutations=MAX(0, mutations-?4), deletes=MAX(0, deletes-?5)
                 WHERE actor=?1 AND namespace=?2 AND operation_id=?3",
                    rusqlite::params![
                        request.actor,
                        request.namespace,
                        request.operation_id,
                        mutations,
                        deletes
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
        self.ensure_external_action_tables()?;
        self.conn()
            .query_row(
                "SELECT record_json FROM chisei_external_action_authorizations
             WHERE actor=?1 AND operation_id=?2 AND idempotency_key=?3",
                rusqlite::params![actor, operation_id, idempotency_key],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .flatten()
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn put_external_action_authorization(
        &self,
        record: &AuthorizationRecord,
    ) -> Result<(), String> {
        let record_json = serde_json::to_string(record).map_err(|error| error.to_string())?;
        self.ensure_external_action_tables()?;
        let updated = self
            .conn()
            .execute(
                "UPDATE chisei_external_action_authorizations SET record_json=?1
             WHERE actor=?2 AND operation_id=?3 AND idempotency_key=?4 AND request_digest=?5",
                rusqlite::params![
                    record_json,
                    record.request.actor,
                    record.request.operation_id,
                    record.request.idempotency_key,
                    record.decision.request_digest
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
        self.ensure_external_action_tables()?;
        self.conn().query_row(
            "SELECT record_json FROM chisei_external_action_authorizations WHERE authorization_id=?1",
            rusqlite::params![authorization_id],
            |row| row.get::<_, Option<String>>(0),
        ).optional().map_err(|error| error.to_string())?
            .flatten()
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    pub fn list_external_action_authorizations(&self) -> Result<Vec<AuthorizationRecord>, String> {
        self.ensure_external_action_tables()?;
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT record_json FROM chisei_external_action_authorizations
                 WHERE record_json IS NOT NULL",
            )
            .map_err(|error| error.to_string())?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?
            .map(|json| {
                json.map_err(|error| error.to_string())
                    .and_then(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn fixture() -> ExternalActionRequest {
        ExternalActionRequest {
            version: REQUEST_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: "op-0".into(),
            attempt_id: "attempt-1".into(),
            request_id: "request-1".into(),
            actor: "agent-1".into(),
            namespace: "team-a".into(),
            requesting_harness: "harness-a".into(),
            intended_executor: "executor-a".into(),
            action_type: "repository.write/v1".into(),
            parameter_schema: "repository.write.params/v1".into(),
            canonical_arguments_digest: "sha256:arguments".into(),
            policy_summary: BTreeMap::from([
                ("branch".into(), "feature".into()),
                ("repository".into(), "example/repo".into()),
            ]),
            target_selectors: vec!["project:team-a/repo:example/repo".into()],
            immutable_preconditions: BTreeMap::from([("head".into(), "abc123".into())]),
            risk_class: "write".into(),
            expected_effects: vec!["git.commit".into()],
            requested_invocation_count: 1,
            deadline_ms: 4_102_444_800_000,
            estimated_cost_micros: 0,
            estimated_volume: 1,
            affected_resource_count: 1,
            rollback_capability: "revert_commit".into(),
            required_host_capabilities: vec!["git.ref-precondition/v1".into()],
            idempotency_key: "idem-1".into(),
            policy_project: "team-a".into(),
        }
    }

    #[test]
    fn canonical_fixture_digest_is_stable_and_map_order_independent() {
        let request = fixture();
        let digest = request.canonical_digest().unwrap();
        assert_eq!(
            digest,
            "sha256:a12982d7ae7bb021a5e537f302331218c2aa10a1d5c9902ed13b3da9477722bf"
        );
        let mut reordered = request.clone();
        reordered.policy_summary = request.policy_summary.into_iter().rev().collect();
        assert_eq!(reordered.canonical_digest().unwrap(), digest);
    }

    #[test]
    fn authorization_storage_round_trips() {
        let db = SekaiDb::new(":memory:").unwrap();
        let request = fixture();
        let record = AuthorizationRecord {
            request: request.clone(),
            decision: ExternalActionDecision {
                version: DECISION_VERSION.into(),
                authorization_id: "external-auth-1".into(),
                request_digest: request.canonical_digest().unwrap(),
                decision: "deny".into(),
                reason: "test".into(),
                approval_id: String::new(),
                policy_scope: "team-a".into(),
                policy_version: "sha256:policy".into(),
                created_at_ms: 1,
                expires_at_ms: request.deadline_ms,
                cancelled_at_ms: 0,
                assurance: AssuranceDeclaration::default(),
            },
            approval_status: String::new(),
            budget_reserved: false,
            blast_radius_reserved: false,
            decision_actor: "agent-1".into(),
            decision_updated_at_ms: 1,
        };
        assert_eq!(
            db.claim_external_action_authorization(
                &request,
                &record.decision.request_digest,
                &record.decision.authorization_id,
                1,
            )
            .unwrap(),
            AuthorizationClaim::Claimed("external-auth-1".into())
        );
        db.put_external_action_authorization(&record).unwrap();
        assert_eq!(
            db.get_external_action_authorization("agent-1", "op-1", "idem-1")
                .unwrap(),
            Some(record)
        );
    }

    #[test]
    fn authorization_claims_and_terminal_transitions_are_atomic() {
        let db = SekaiDb::new(":memory:").unwrap();
        let request = fixture();
        let digest = request.canonical_digest().unwrap();
        assert_eq!(
            db.claim_external_action_authorization(&request, &digest, "auth-cas", 1)
                .unwrap(),
            AuthorizationClaim::Claimed("auth-cas".into())
        );
        assert_eq!(
            db.claim_external_action_authorization(&request, &digest, "auth-other", 2)
                .unwrap(),
            AuthorizationClaim::InProgress
        );
        db.abandon_external_action_claim(&request, &digest).unwrap();
        assert_eq!(
            db.claim_external_action_authorization(&request, &digest, "auth-cas", 3)
                .unwrap(),
            AuthorizationClaim::Claimed("auth-cas".into())
        );

        let base = AuthorizationRecord {
            request: request.clone(),
            decision: ExternalActionDecision {
                version: DECISION_VERSION.into(),
                authorization_id: "auth-cas".into(),
                request_digest: digest,
                decision: "require_approval".into(),
                reason: "pending".into(),
                approval_id: "approval-1".into(),
                policy_scope: "agent:agent-1".into(),
                policy_version: "policy-1".into(),
                created_at_ms: 3,
                expires_at_ms: request.deadline_ms,
                cancelled_at_ms: 0,
                assurance: AssuranceDeclaration::default(),
            },
            approval_status: "pending".into(),
            budget_reserved: true,
            blast_radius_reserved: true,
            decision_actor: "agent-1".into(),
            decision_updated_at_ms: 3,
        };
        db.put_external_action_authorization(&base).unwrap();
        let mut cancelled = base.clone();
        cancelled.decision.decision = "deny".into();
        cancelled.approval_status = "cancelled".into();
        assert!(
            db.compare_and_swap_external_action_authorization(&base, &cancelled)
                .unwrap()
        );
        let mut stale_approval = base.clone();
        stale_approval.decision.decision = "permit".into();
        assert!(
            !db.compare_and_swap_external_action_authorization(&base, &stale_approval)
                .unwrap()
        );
    }
}
