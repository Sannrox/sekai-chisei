//! Signed, short-lived authority for host-executed external actions.

use crate::chisei::external_action::{AuthorizationRecord, PERMIT_VERSION, REDEMPTION_VERSION};
use crate::db::sekai::SekaiDb;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SIGNATURE_ALGORITHM: &str = crate::shomei::SIGNATURE_ALGORITHM;
pub const REDEMPTION_MODE: &str = "online_atomic";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permit {
    pub version: String,
    pub permit_id: String,
    pub authorization_id: String,
    pub request_digest: String,
    pub issuer: String,
    pub subject_actor: String,
    pub namespace: String,
    pub operation_id: String,
    pub requesting_harness: String,
    pub executor: String,
    pub action_type: String,
    pub parameter_schema: String,
    pub canonical_arguments_digest: String,
    pub target_selectors: Vec<String>,
    pub immutable_preconditions: BTreeMap<String, String>,
    pub allowed_effects: Vec<String>,
    pub required_host_capabilities: Vec<String>,
    pub constraints: Vec<String>,
    pub risk_class: String,
    pub budget_micros: u64,
    pub volume_limit: u64,
    pub blast_radius_limit: u32,
    pub max_invocations: u32,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub redemption_mode: String,
    pub approval_identities: Vec<String>,
    pub policy_version: String,
    pub schema_version: String,
    pub capability_version: String,
    pub pricing_version: String,
    pub nonce: String,
    pub delegation_depth: u32,
    pub parent_permit_id: String,
    pub revocation_handle: String,
    pub signature_algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub issued_at_ms: i64,
    pub revocation_latency_ms: i64,
    pub signed_digest: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostContext {
    pub executor: String,
    pub requesting_harness: String,
    pub canonical_arguments_digest: String,
    pub target_selectors: Vec<String>,
    pub observed_preconditions: BTreeMap<String, String>,
    pub host_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redemption {
    pub version: String,
    pub permit_id: String,
    pub redemption_id: String,
    pub executor: String,
    pub execution_id: String,
    pub idempotency_key: String,
    pub redeemed_at_ms: i64,
    pub invocation_ordinal: u32,
}

pub struct Issuance<'a> {
    pub approval_identities: Vec<String>,
    pub issuer: &'a str,
    pub key_id: &'a str,
    pub permit_id: String,
    pub nonce: String,
    pub now_ms: i64,
}

impl Permit {
    fn unsigned_bytes(&self) -> Result<Vec<u8>, String> {
        let mut unsigned = self.clone();
        unsigned.signed_digest.clear();
        unsigned.signature.clear();
        crate::shomei::canonical_json(&unsigned)
    }

    pub fn sign(&mut self, key: &SigningKey) -> Result<(), String> {
        self.public_key = hex(key.verifying_key().as_bytes());
        let bytes = self.unsigned_bytes()?;
        self.signed_digest = digest(b"sekai-chisei:external-action-permit:v1\0", &bytes);
        self.signature = key.sign(self.signed_digest.as_bytes()).to_bytes().to_vec();
        Ok(())
    }

    pub fn verify_signature(&self, trusted_key: &VerifyingKey) -> Result<(), String> {
        if self.version != PERMIT_VERSION || self.signature_algorithm != SIGNATURE_ALGORITHM {
            return Err("unsupported permit or signature version".into());
        }
        if self.public_key != hex(trusted_key.as_bytes()) {
            return Err("permit public key does not match the trusted signing key".into());
        }
        let expected = digest(
            b"sekai-chisei:external-action-permit:v1\0",
            &self.unsigned_bytes()?,
        );
        if expected != self.signed_digest {
            return Err("permit signed digest mismatch".into());
        }
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "permit signature must contain 64 bytes".to_string())?;
        trusted_key
            .verify_strict(
                self.signed_digest.as_bytes(),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| "permit signature verification failed".to_string())
    }

    pub fn verify_trust(&self, issuer: &str, key_id: &str) -> Result<(), String> {
        if self.issuer != issuer || self.key_id != key_id {
            return Err("permit issuer or signing key is not trusted".into());
        }
        Ok(())
    }

    pub fn verify_host_context(&self, context: &HostContext, now_ms: i64) -> Result<(), String> {
        if now_ms < self.not_before_ms || now_ms >= self.expires_at_ms {
            return Err("permit is outside its validity window".into());
        }
        if self.redemption_mode != REDEMPTION_MODE || self.delegation_depth != 0 {
            return Err("permit requires unsupported redemption or delegation semantics".into());
        }
        if context.executor != self.executor
            || context.requesting_harness != self.requesting_harness
            || context.canonical_arguments_digest != self.canonical_arguments_digest
            || context.target_selectors != self.target_selectors
        {
            return Err("host execution identity or exact request binding changed".into());
        }
        if context.observed_preconditions != self.immutable_preconditions {
            return Err("resource preconditions changed; reauthorization required".into());
        }
        let advertised: BTreeSet<_> = context.host_capabilities.iter().collect();
        if self
            .required_host_capabilities
            .iter()
            .any(|value| !advertised.contains(value))
        {
            return Err("host cannot enforce all required permit constraints".into());
        }
        let expected = self
            .required_host_capabilities
            .iter()
            .map(|value| format!("host_capability:{value}"))
            .collect::<Vec<_>>();
        if self.constraints != expected {
            return Err("permit constraint declaration is inconsistent".into());
        }
        Ok(())
    }
}

pub fn issue(
    authorization: &AuthorizationRecord,
    signing_key: &SigningKey,
    issuance: Issuance<'_>,
) -> Result<Permit, String> {
    if authorization.decision.decision != "permit" || authorization.decision.cancelled_at_ms != 0 {
        return Err("authorization does not permit issuance".into());
    }
    if issuance.now_ms >= authorization.decision.expires_at_ms {
        return Err("authorization expired before permit issuance".into());
    }
    let request = &authorization.request;
    if request
        .target_selectors
        .iter()
        .any(|target| target.contains('*') || target.contains('?') || target.contains("://"))
    {
        return Err("v1 permits refuse wildcard and arbitrary network targets".into());
    }
    if [
        request.action_type.as_str(),
        request.parameter_schema.as_str(),
    ]
    .iter()
    .any(|value| value.contains("shell") || value.contains("command") || value.contains("exec"))
    {
        return Err("v1 permits refuse unrestricted command contracts".into());
    }
    let mut permit = Permit {
        version: PERMIT_VERSION.into(),
        permit_id: issuance.permit_id,
        authorization_id: authorization.decision.authorization_id.clone(),
        request_digest: authorization.decision.request_digest.clone(),
        issuer: issuance.issuer.into(),
        subject_actor: request.actor.clone(),
        namespace: request.namespace.clone(),
        operation_id: request.operation_id.clone(),
        requesting_harness: request.requesting_harness.clone(),
        executor: request.intended_executor.clone(),
        action_type: request.action_type.clone(),
        parameter_schema: request.parameter_schema.clone(),
        canonical_arguments_digest: request.canonical_arguments_digest.clone(),
        target_selectors: request.target_selectors.clone(),
        immutable_preconditions: request.immutable_preconditions.clone(),
        allowed_effects: request.expected_effects.clone(),
        required_host_capabilities: request.required_host_capabilities.clone(),
        constraints: request
            .required_host_capabilities
            .iter()
            .map(|value| format!("host_capability:{value}"))
            .collect(),
        risk_class: request.risk_class.clone(),
        budget_micros: request.estimated_cost_micros,
        volume_limit: request.estimated_volume,
        blast_radius_limit: request.affected_resource_count,
        max_invocations: request.requested_invocation_count,
        not_before_ms: issuance.now_ms,
        expires_at_ms: authorization.decision.expires_at_ms,
        redemption_mode: REDEMPTION_MODE.into(),
        approval_identities: issuance.approval_identities,
        policy_version: authorization.decision.policy_version.clone(),
        schema_version: request.parameter_schema.clone(),
        capability_version: request.action_type.clone(),
        pricing_version: "request-estimate/v1".into(),
        nonce: issuance.nonce,
        delegation_depth: 0,
        parent_permit_id: String::new(),
        revocation_handle: format!("revoke-{}", authorization.decision.authorization_id),
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
        key_id: issuance.key_id.into(),
        public_key: String::new(),
        issued_at_ms: issuance.now_ms,
        revocation_latency_ms: 0,
        signed_digest: String::new(),
        signature: Vec::new(),
    };
    permit.sign(signing_key)?;
    Ok(permit)
}

impl SekaiDb {
    fn ensure_external_permit_tables(&self) -> Result<(), String> {
        self.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_external_action_permits (
                permit_id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE,
                issuance_idempotency_key TEXT NOT NULL, permit_json TEXT NOT NULL, issued_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_redemptions (
                permit_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, execution_id TEXT NOT NULL,
                redemption_json TEXT NOT NULL, redeemed_at_ms INTEGER NOT NULL,
                invocation_ordinal INTEGER NOT NULL,
                PRIMARY KEY(permit_id,idempotency_key), UNIQUE(permit_id,execution_id),
                UNIQUE(permit_id,invocation_ordinal)
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_revocations (
                revocation_handle TEXT PRIMARY KEY, reason TEXT NOT NULL, revoked_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_kill_switches (
                scope_kind TEXT NOT NULL, scope_value TEXT NOT NULL, reason TEXT NOT NULL,
                enabled_at_ms INTEGER NOT NULL, PRIMARY KEY(scope_kind,scope_value)
             );"
        ).map(|_| ()).map_err(|error| error.to_string())
    }

    pub fn put_permit(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        issued_by: &str,
    ) -> Result<Permit, String> {
        self.ensure_external_permit_tables()?;
        let json = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO chisei_external_action_permits(permit_id,authorization_id,issuance_idempotency_key,permit_json,issued_at_ms) VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params![permit.permit_id, permit.authorization_id, idempotency_key, json, permit.issued_at_ms]
        ).map_err(|error| error.to_string())?;
        let (stored_key, stored_json): (String, String) = tx.query_row(
            "SELECT issuance_idempotency_key,permit_json FROM chisei_external_action_permits WHERE authorization_id=?1",
            [&permit.authorization_id], |row| Ok((row.get(0)?, row.get(1)?))
        ).map_err(|error| error.to_string())?;
        if stored_key != idempotency_key {
            return Err(
                "authorization already has a permit under a different idempotency key".into(),
            );
        }
        let stored: Permit =
            serde_json::from_str(&stored_json).map_err(|error| error.to_string())?;
        if inserted == 1 {
            crate::sekai::ledger::insert_chained_decision(
                &tx,
                &crate::sekai::audit::Decision {
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
        self.ensure_external_permit_tables()?;
        let existing: Option<(String, String)> = self.conn().query_row(
            "SELECT issuance_idempotency_key,permit_json FROM chisei_external_action_permits WHERE authorization_id=?1",
            [authorization_id], |row| Ok((row.get(0)?, row.get(1)?))
        ).optional().map_err(|error| error.to_string())?;
        match existing {
            Some((stored_key, _)) if stored_key != idempotency_key => {
                Err("authorization already has a permit under a different idempotency key".into())
            }
            Some((_, json)) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|error| error.to_string()),
            None => Ok(None),
        }
    }

    pub fn revoke_permit(&self, handle: &str, reason: &str, now_ms: i64) -> Result<bool, String> {
        self.ensure_external_permit_tables()?;
        self.conn().execute(
            "INSERT OR IGNORE INTO chisei_external_action_revocations(revocation_handle,reason,revoked_at_ms) VALUES(?1,?2,?3)",
            rusqlite::params![handle, reason, now_ms]
        ).map(|count| count == 1).map_err(|error| error.to_string())
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
        self.ensure_external_permit_tables()?;
        let changed = if enabled {
            self.conn().execute("INSERT INTO chisei_external_action_kill_switches(scope_kind,scope_value,reason,enabled_at_ms) VALUES(?1,?2,?3,?4) ON CONFLICT(scope_kind,scope_value) DO UPDATE SET reason=?3,enabled_at_ms=?4", rusqlite::params![kind,value,reason,now_ms])
        } else {
            self.conn().execute("DELETE FROM chisei_external_action_kill_switches WHERE scope_kind=?1 AND scope_value=?2", rusqlite::params![kind,value])
        }.map_err(|error| error.to_string())?;
        Ok(changed != 0)
    }

    pub fn redeem_permit(
        &self,
        permit: &Permit,
        context: &HostContext,
        trusted_key: &VerifyingKey,
        idempotency_key: &str,
        execution_id: &str,
        now_ms: i64,
    ) -> Result<Redemption, String> {
        self.ensure_external_permit_tables()?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let stored_json: Option<String> = tx
            .query_row(
                "SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=?1",
                [&permit.permit_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if stored_json.as_deref()
            != Some(
                serde_json::to_string(permit)
                    .map_err(|error| error.to_string())?
                    .as_str(),
            )
        {
            return Err("permit is not the issued durable permit".into());
        }
        if let Some(json) = tx.query_row("SELECT redemption_json FROM chisei_external_action_redemptions WHERE permit_id=?1 AND idempotency_key=?2", rusqlite::params![permit.permit_id,idempotency_key], |row| row.get::<_,String>(0)).optional().map_err(|error| error.to_string())? {
            let existing: Redemption = serde_json::from_str(&json).map_err(|error| error.to_string())?;
            if existing.execution_id != execution_id { return Err("redemption idempotency key reused for a different execution".into()); }
            return Ok(existing);
        }
        permit.verify_signature(trusted_key)?;
        permit.verify_host_context(context, now_ms)?;
        let authorization_json: Option<String> = tx.query_row("SELECT record_json FROM chisei_external_action_authorizations WHERE authorization_id=?1", [&permit.authorization_id], |row| row.get(0)).optional().map_err(|error| error.to_string())?.flatten();
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
            .query_row(
                "SELECT reason FROM chisei_external_action_revocations WHERE revocation_handle=?1",
                [&permit.revocation_handle],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(reason) = revoked {
            return Err(format!("permit revoked: {reason}"));
        }
        for (kind, value) in [
            ("action_type", &permit.action_type),
            ("executor", &permit.executor),
            ("harness", &permit.requesting_harness),
            ("namespace", &permit.namespace),
            ("signing_key", &permit.key_id),
        ] {
            let reason: Option<String> = tx.query_row("SELECT reason FROM chisei_external_action_kill_switches WHERE scope_kind=?1 AND scope_value=?2", rusqlite::params![kind,value], |row| row.get(0)).optional().map_err(|error| error.to_string())?;
            if let Some(reason) = reason {
                return Err(format!("{kind} kill switch active: {reason}"));
            }
        }
        let count: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM chisei_external_action_redemptions WHERE permit_id=?1",
                [&permit.permit_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
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
            redeemed_at_ms: now_ms,
            invocation_ordinal: count + 1,
        };
        let json = serde_json::to_string(&redemption).map_err(|error| error.to_string())?;
        tx.execute("INSERT INTO chisei_external_action_redemptions(permit_id,idempotency_key,execution_id,redemption_json,redeemed_at_ms,invocation_ordinal) VALUES(?1,?2,?3,?4,?5,?6)", rusqlite::params![permit.permit_id,idempotency_key,execution_id,json,now_ms,redemption.invocation_ordinal]).map_err(|error| error.to_string())?;
        crate::sekai::ledger::insert_chained_decision(
            &tx,
            &crate::sekai::audit::Decision {
                id: format!("{}:audit:redeemed", redemption.redemption_id),
                timestamp: redemption.redeemed_at_ms,
                actor: context.executor.clone(),
                action: format!("external_action_redeem/{}", permit.action_type),
                reason: "external_action_permit_redeemed_before_execution".into(),
                evidence: HashMap::from([
                    ("permit_id".into(), permit.permit_id.clone()),
                    ("execution_id".into(), redemption.execution_id.clone()),
                    (
                        "invocation_ordinal".into(),
                        redemption.invocation_ordinal.to_string(),
                    ),
                ]),
                target_id: permit.permit_id.clone(),
                outcome: "authorization_consumed".into(),
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(redemption)
    }

    /// Validate online lifecycle state without consuming an invocation. Hosts
    /// must still redeem immediately before execution; redemption repeats all
    /// checks atomically with consumption.
    pub fn validate_permit_state(&self, permit: &Permit) -> Result<(), String> {
        self.ensure_external_permit_tables()?;
        let conn = self.conn();
        let stored_json: Option<String> = conn
            .query_row(
                "SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=?1",
                [&permit.permit_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let supplied = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        if stored_json.as_deref() != Some(supplied.as_str()) {
            return Err("permit is not the issued durable permit".into());
        }
        let authorization_json: Option<String> = conn.query_row("SELECT record_json FROM chisei_external_action_authorizations WHERE authorization_id=?1", [&permit.authorization_id], |row| row.get(0)).optional().map_err(|error| error.to_string())?.flatten();
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
        let revoked: Option<String> = conn
            .query_row(
                "SELECT reason FROM chisei_external_action_revocations WHERE revocation_handle=?1",
                [&permit.revocation_handle],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(reason) = revoked {
            return Err(format!("permit revoked: {reason}"));
        }
        for (kind, value) in [
            ("action_type", &permit.action_type),
            ("executor", &permit.executor),
            ("harness", &permit.requesting_harness),
            ("namespace", &permit.namespace),
            ("signing_key", &permit.key_id),
        ] {
            let reason: Option<String> = conn.query_row("SELECT reason FROM chisei_external_action_kill_switches WHERE scope_kind=?1 AND scope_value=?2", rusqlite::params![kind,value], |row| row.get(0)).optional().map_err(|error| error.to_string())?;
            if let Some(reason) = reason {
                return Err(format!("{kind} kill switch active: {reason}"));
            }
        }
        let redemption_count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM chisei_external_action_redemptions WHERE permit_id=?1",
                [&permit.permit_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if redemption_count >= permit.max_invocations {
            return Err("permit invocation count exhausted".into());
        }
        Ok(())
    }

    pub fn replay_redemption(
        &self,
        permit: &Permit,
        idempotency_key: &str,
        execution_id: &str,
    ) -> Result<Option<Redemption>, String> {
        self.ensure_external_permit_tables()?;
        let conn = self.conn();
        let stored_json: Option<String> = conn
            .query_row(
                "SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=?1",
                [&permit.permit_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let supplied = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        if stored_json.as_deref() != Some(supplied.as_str()) {
            return Err("permit is not the issued durable permit".into());
        }
        let existing = conn.query_row("SELECT redemption_json FROM chisei_external_action_redemptions WHERE permit_id=?1 AND idempotency_key=?2", rusqlite::params![permit.permit_id,idempotency_key], |row| row.get::<_,String>(0)).optional().map_err(|error| error.to_string())?;
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

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn signing_key_from_hex(value: &str) -> Result<SigningKey, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("permit signing key must be 64 lowercase hex characters".into());
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "permit signing key must be lowercase hex".to_string())?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "permit signing key must contain 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::external_action::{
        ASSURANCE_VERSION, AssuranceDeclaration, AuthorizationClaim, ExternalActionDecision,
        ExternalActionRequest, REQUEST_VERSION,
    };
    use std::sync::{Arc, Barrier};

    fn authorization(deadline_ms: i64, invocations: u32) -> AuthorizationRecord {
        let request = ExternalActionRequest {
            version: REQUEST_VERSION.into(),
            operation_id: "op-1".into(),
            parent_operation_id: String::new(),
            attempt_id: "attempt-1".into(),
            request_id: "request-1".into(),
            actor: "agent:test".into(),
            namespace: "test".into(),
            requesting_harness: "harness:test".into(),
            intended_executor: "executor:test".into(),
            action_type: "repository.read/v1".into(),
            parameter_schema: "repository.read.params/v1".into(),
            canonical_arguments_digest: "sha256:args".into(),
            policy_summary: BTreeMap::from([("path".into(), "README.md".into())]),
            target_selectors: vec!["project:test/README.md".into()],
            immutable_preconditions: BTreeMap::from([(
                "resource_version".into(),
                "git:abc123".into(),
            )]),
            risk_class: "read".into(),
            expected_effects: vec!["read_file".into()],
            requested_invocation_count: invocations,
            deadline_ms,
            estimated_cost_micros: 10,
            estimated_volume: 1024,
            affected_resource_count: 1,
            rollback_capability: "not_applicable".into(),
            required_host_capabilities: vec![
                "exact_target_binding".into(),
                "resource_version_check".into(),
            ],
            idempotency_key: "authorize-1".into(),
            policy_project: "test".into(),
        };
        let digest = request.canonical_digest().unwrap();
        AuthorizationRecord {
            request,
            decision: ExternalActionDecision {
                version: "external-action.decision/v1".into(),
                authorization_id: "auth-1".into(),
                request_digest: digest,
                decision: "permit".into(),
                reason: "allowed".into(),
                approval_id: String::new(),
                policy_scope: "project:test".into(),
                policy_version: "sha256:policy".into(),
                created_at_ms: 1_000,
                expires_at_ms: deadline_ms,
                cancelled_at_ms: 0,
                assurance: AssuranceDeclaration {
                    version: ASSURANCE_VERSION.into(),
                    authorization_only: true,
                    host_must_verify_permit: true,
                    host_must_enforce_constraints: true,
                    physical_effect_verified: false,
                },
            },
            approval_status: String::new(),
            budget_reserved: true,
            blast_radius_reserved: true,
            decision_actor: "agent:test".into(),
            decision_updated_at_ms: 1_000,
        }
    }

    fn persist_authorization(db: &SekaiDb, record: &AuthorizationRecord) {
        assert!(matches!(
            db.claim_external_action_authorization(
                &record.request,
                &record.decision.request_digest,
                &record.decision.authorization_id,
                1_000
            )
            .unwrap(),
            AuthorizationClaim::Claimed(_)
        ));
        db.put_external_action_authorization(record).unwrap();
    }

    fn signed(record: &AuthorizationRecord) -> (Permit, SigningKey) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let permit = issue(
            record,
            &key,
            Issuance {
                approval_identities: vec![],
                issuer: "issuer:test",
                key_id: "key-1",
                permit_id: "permit-1".into(),
                nonce: "nonce-1".into(),
                now_ms: 2_000,
            },
        )
        .unwrap();
        (permit, key)
    }

    fn context(permit: &Permit) -> HostContext {
        HostContext {
            executor: permit.executor.clone(),
            requesting_harness: permit.requesting_harness.clone(),
            canonical_arguments_digest: permit.canonical_arguments_digest.clone(),
            target_selectors: permit.target_selectors.clone(),
            observed_preconditions: permit.immutable_preconditions.clone(),
            host_capabilities: permit.required_host_capabilities.clone(),
        }
    }

    #[test]
    fn canonical_fixture_is_stable_and_verifies_offline() {
        let record = authorization(10_000, 1);
        let (first, key) = signed(&record);
        let (second, _) = signed(&record);
        assert_eq!(first.signed_digest, second.signed_digest);
        assert_eq!(first.signature, second.signature);
        first.verify_trust("issuer:test", "key-1").unwrap();
        first.verify_signature(&key.verifying_key()).unwrap();
        first.verify_host_context(&context(&first), 2_001).unwrap();
    }

    #[test]
    fn policy_relevant_tampering_invalidates_signature() {
        let record = authorization(10_000, 2);
        let (permit, key) = signed(&record);
        for field in [
            "subject_actor",
            "operation_id",
            "executor",
            "action_type",
            "canonical_arguments_digest",
            "target_selectors",
            "immutable_preconditions",
            "budget_micros",
            "volume_limit",
            "blast_radius_limit",
            "not_before_ms",
            "expires_at_ms",
            "max_invocations",
            "policy_version",
        ] {
            let mut json = serde_json::to_value(&permit).unwrap();
            let value = json.as_object_mut().unwrap().get_mut(field).unwrap();
            *value = match value {
                serde_json::Value::String(_) => serde_json::Value::String("tampered".into()),
                serde_json::Value::Number(_) => serde_json::json!(999999),
                serde_json::Value::Array(_) => serde_json::json!(["tampered"]),
                serde_json::Value::Object(_) => serde_json::json!({"tampered":"true"}),
                other => panic!("unexpected {other:?}"),
            };
            let changed: Permit = serde_json::from_value(json).unwrap();
            assert!(
                changed.verify_signature(&key.verifying_key()).is_err(),
                "{field} was not bound"
            );
        }
    }

    #[test]
    fn redemption_is_atomic_idempotent_and_durable_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permit.db");
        let record = authorization(10_000, 1);
        let (permit, key) = signed(&record);
        {
            let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
            persist_authorization(&db, &record);
            db.put_permit(&permit, "issue-1", "agent:test").unwrap();
            let first = db
                .redeem_permit(
                    &permit,
                    &context(&permit),
                    &key.verifying_key(),
                    "redeem-1",
                    "execution-1",
                    3_000,
                )
                .unwrap();
            let retry = db
                .redeem_permit(
                    &permit,
                    &context(&permit),
                    &key.verifying_key(),
                    "redeem-1",
                    "execution-1",
                    3_001,
                )
                .unwrap();
            assert_eq!(first, retry);
        }
        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        db.revoke_permit(
            &permit.revocation_handle,
            "revoked after lost response",
            10_001,
        )
        .unwrap();
        let retry = db
            .redeem_permit(
                &permit,
                &context(&permit),
                &key.verifying_key(),
                "redeem-1",
                "execution-1",
                11_000,
            )
            .unwrap();
        assert_eq!(retry.execution_id, "execution-1");
        let error = db
            .redeem_permit(
                &permit,
                &context(&permit),
                &key.verifying_key(),
                "redeem-2",
                "execution-2",
                3_002,
            )
            .unwrap_err();
        assert!(error.contains("validity window") || error.contains("revoked"));
    }

    #[test]
    fn concurrent_replicas_cannot_exceed_the_permit_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replica.db");
        let record = authorization(10_000, 1);
        let (permit, key) = signed(&record);
        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        persist_authorization(&db, &record);
        db.put_permit(&permit, "issue-1", "agent:test").unwrap();
        drop(db);
        let barrier = Arc::new(Barrier::new(2));
        let mut joins = Vec::new();
        for ordinal in 0..2 {
            let barrier = barrier.clone();
            let path = path.clone();
            let permit = permit.clone();
            let key = key.clone();
            joins.push(std::thread::spawn(move || {
                let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
                barrier.wait();
                db.redeem_permit(
                    &permit,
                    &context(&permit),
                    &key.verifying_key(),
                    &format!("redeem-{ordinal}"),
                    &format!("execution-{ordinal}"),
                    3_000,
                )
            }));
        }
        let successes = joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(successes, 1);
    }

    #[test]
    fn toctou_revocation_and_kill_switch_stop_future_redemption() {
        let record = authorization(10_000, 3);
        let (permit, key) = signed(&record);
        let db = SekaiDb::new(":memory:").unwrap();
        persist_authorization(&db, &record);
        db.put_permit(&permit, "issue-1", "agent:test").unwrap();
        let mut changed = context(&permit);
        changed
            .observed_preconditions
            .insert("resource_version".into(), "git:def456".into());
        assert!(
            db.redeem_permit(&permit, &changed, &key.verifying_key(), "r-1", "e-1", 3_000)
                .unwrap_err()
                .contains("reauthorization")
        );
        db.revoke_permit(&permit.revocation_handle, "operator revoked", 3_001)
            .unwrap();
        assert!(
            db.redeem_permit(
                &permit,
                &context(&permit),
                &key.verifying_key(),
                "r-2",
                "e-2",
                3_002
            )
            .unwrap_err()
            .contains("revoked")
        );

        let record2 = {
            let mut value = authorization(10_000, 1);
            value.request.idempotency_key = "authorize-2".into();
            value.decision.authorization_id = "auth-2".into();
            value.decision.request_digest = value.request.canonical_digest().unwrap();
            value
        };
        let (permit2, key2) = {
            let key = SigningKey::from_bytes(&[7; 32]);
            let permit = issue(
                &record2,
                &key,
                Issuance {
                    approval_identities: vec![],
                    issuer: "issuer:test",
                    key_id: "key-1",
                    permit_id: "permit-2".into(),
                    nonce: "nonce-2".into(),
                    now_ms: 2_000,
                },
            )
            .unwrap();
            (permit, key)
        };
        persist_authorization(&db, &record2);
        db.put_permit(&permit2, "issue-2", "agent:test").unwrap();
        db.set_permit_kill_switch("executor", &permit2.executor, true, "emergency", 3_003)
            .unwrap();
        assert!(
            db.redeem_permit(
                &permit2,
                &context(&permit2),
                &key2.verifying_key(),
                "r-3",
                "e-3",
                3_004
            )
            .unwrap_err()
            .contains("kill switch")
        );
    }
}
