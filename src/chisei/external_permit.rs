//! Signed, short-lived authority for host-executed external actions.

use crate::chisei::external_action::{AuthorizationRecord, PERMIT_VERSION, REDEMPTION_VERSION};
#[cfg(test)]
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SIGNATURE_ALGORITHM: &str = crate::shomei::SIGNATURE_ALGORITHM;
pub const REDEMPTION_MODE: &str = "online_atomic";
pub const OFFLINE_REDEMPTION_MODE: &str = "offline_bounded";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalPermitPolicy {
    pub scope: String,
    pub offline_action_types: Vec<String>,
    pub offline_max_duration_ms: i64,
    pub offline_max_invocations: u32,
    pub permitted_delegators: Vec<String>,
    pub max_delegation_depth: u32,
}

impl ExternalPermitPolicy {
    pub fn disabled(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            offline_action_types: Vec::new(),
            offline_max_duration_ms: 0,
            offline_max_invocations: 0,
            permitted_delegators: Vec::new(),
            max_delegation_depth: 0,
        }
    }
}

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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_scope: String,
    pub schema_version: String,
    pub capability_version: String,
    pub pricing_version: String,
    pub nonce: String,
    pub delegation_depth: u32,
    pub parent_permit_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub initiating_actor: String,
    pub revocation_handle: String,
    pub signature_algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub issued_at_ms: i64,
    pub revocation_latency_ms: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub offline_revocation_unavailable: bool,
    /// Region/site pin for online redeem. Default `"local"` for single-region
    /// and for legacy permits that omit the field (#293).
    #[serde(default = "default_permit_site_id")]
    pub site_id: String,
    pub signed_digest: String,
    pub signature: Vec<u8>,
}

fn default_permit_site_id() -> String {
    crate::sekai::lease::DEFAULT_SITE_ID.into()
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
    #[serde(default)]
    pub evidence_due_at_ms: i64,
    /// Site pin that performed the redeem (evidence attribute).
    #[serde(default = "default_permit_site_id")]
    pub site_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedemptionTiming {
    pub invoked_at_ms: i64,
    pub reconciled_at_ms: i64,
}

pub struct Issuance<'a> {
    pub approval_identities: Vec<String>,
    pub issuer: &'a str,
    pub key_id: &'a str,
    pub permit_id: String,
    pub nonce: String,
    pub now_ms: i64,
    /// Region/site pin stamped onto the signed permit (default `"local"`).
    pub site_id: &'a str,
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
        if !matches!(
            self.redemption_mode.as_str(),
            REDEMPTION_MODE | OFFLINE_REDEMPTION_MODE
        ) {
            return Err("permit uses an unsupported redemption mode".into());
        }
        if self.initiating_actor.trim().is_empty()
            && (self.delegation_depth != 0 || self.redemption_mode == OFFLINE_REDEMPTION_MODE)
        {
            return Err("permit does not preserve the initiating actor".into());
        }
        if self.delegation_depth as usize != self.parent_chain.len()
            || self.parent_chain.last().map(String::as_str).unwrap_or("") != self.parent_permit_id
        {
            return Err("permit delegation chain is incomplete".into());
        }
        if self.redemption_mode == OFFLINE_REDEMPTION_MODE
            && (!self.offline_revocation_unavailable || self.revocation_latency_ms <= 0)
        {
            return Err("offline permit does not declare its revocation limitation".into());
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
        let mut declared = expected.clone();
        if self.redemption_mode == OFFLINE_REDEMPTION_MODE {
            declared.push("offline_no_global_single_use".into());
            declared.push("offline_revocation_unavailable_until_expiry".into());
        }
        declared.sort();
        let mut constraints = self.constraints.clone();
        constraints.sort();
        if constraints != declared {
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
    let site_id = crate::config::validate_site_id(issuance.site_id)?;
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
        policy_scope: authorization.decision.policy_scope.clone(),
        schema_version: request.parameter_schema.clone(),
        capability_version: request.action_type.clone(),
        pricing_version: "request-estimate/v1".into(),
        nonce: issuance.nonce,
        delegation_depth: 0,
        parent_permit_id: String::new(),
        parent_chain: Vec::new(),
        initiating_actor: request.actor.clone(),
        revocation_handle: format!("revoke-{}", authorization.decision.authorization_id),
        signature_algorithm: SIGNATURE_ALGORITHM.into(),
        key_id: issuance.key_id.into(),
        public_key: String::new(),
        issued_at_ms: issuance.now_ms,
        revocation_latency_ms: 0,
        offline_revocation_unavailable: false,
        site_id,
        signed_digest: String::new(),
        signature: Vec::new(),
    };
    permit.sign(signing_key)?;
    Ok(permit)
}

pub fn issue_offline(
    authorization: &AuthorizationRecord,
    policy: &ExternalPermitPolicy,
    signing_key: &SigningKey,
    issuance: Issuance<'_>,
) -> Result<Permit, String> {
    if !policy
        .offline_action_types
        .iter()
        .any(|value| value == &authorization.request.action_type)
        || policy.offline_max_duration_ms <= 0
        || policy.offline_max_invocations == 0
    {
        return Err("action policy does not permit bounded offline operation".into());
    }
    if authorization.request.risk_class == "destructive" {
        return Err("action class requires online revocation and single-use guarantees".into());
    }
    let now_ms = issuance.now_ms;
    let mut permit = issue(authorization, signing_key, issuance)?;
    permit.redemption_mode = OFFLINE_REDEMPTION_MODE.into();
    permit.max_invocations = permit.max_invocations.min(policy.offline_max_invocations);
    permit.expires_at_ms = permit
        .expires_at_ms
        .min(now_ms.saturating_add(policy.offline_max_duration_ms));
    permit.revocation_latency_ms = permit.expires_at_ms.saturating_sub(now_ms);
    permit.offline_revocation_unavailable = true;
    permit
        .constraints
        .push("offline_no_global_single_use".into());
    permit
        .constraints
        .push("offline_revocation_unavailable_until_expiry".into());
    permit.sign(signing_key)?;
    Ok(permit)
}

pub struct Delegation<'a> {
    pub delegator: &'a str,
    pub subject_actor: &'a str,
    pub permit_id: String,
    pub nonce: String,
    pub now_ms: i64,
    pub expires_at_ms: i64,
    pub target_selectors: Vec<String>,
    pub allowed_effects: Vec<String>,
    pub budget_micros: u64,
    pub volume_limit: u64,
    pub blast_radius_limit: u32,
    pub max_invocations: u32,
    pub risk_class: &'a str,
}

pub fn delegate(
    parent: &Permit,
    policy: &ExternalPermitPolicy,
    signing_key: &SigningKey,
    input: Delegation<'_>,
) -> Result<Permit, String> {
    parent.verify_signature(&signing_key.verifying_key())?;
    if parent.redemption_mode != REDEMPTION_MODE {
        return Err("offline permits cannot be delegated because local consumption is not globally observable".into());
    }
    if !policy
        .permitted_delegators
        .iter()
        .any(|value| value == input.delegator)
    {
        return Err("policy does not name this actor as a permitted delegator".into());
    }
    if input.delegator != parent.subject_actor {
        return Err("delegator is not the current permit subject".into());
    }
    let depth = parent.delegation_depth.saturating_add(1);
    if policy.max_delegation_depth == 0 || depth > policy.max_delegation_depth {
        return Err("delegation depth exceeds policy".into());
    }
    if input.now_ms < parent.not_before_ms
        || input.now_ms >= parent.expires_at_ms
        || input.expires_at_ms > parent.expires_at_ms
        || input.expires_at_ms <= input.now_ms
        || input.max_invocations == 0
        || input.max_invocations > parent.max_invocations
        || input.budget_micros > parent.budget_micros
        || input.volume_limit > parent.volume_limit
        || input.blast_radius_limit > parent.blast_radius_limit
        || input.risk_class != parent.risk_class
        || !is_subset(&input.target_selectors, &parent.target_selectors)
        || !is_subset(&input.allowed_effects, &parent.allowed_effects)
    {
        return Err("delegation would expand or invalidate the parent envelope".into());
    }
    let mut child = parent.clone();
    child.permit_id = input.permit_id;
    child.subject_actor = input.subject_actor.into();
    child.target_selectors = input.target_selectors;
    child.allowed_effects = input.allowed_effects;
    child.budget_micros = input.budget_micros;
    child.volume_limit = input.volume_limit;
    child.blast_radius_limit = input.blast_radius_limit;
    child.max_invocations = input.max_invocations;
    child.not_before_ms = input.now_ms;
    child.expires_at_ms = input.expires_at_ms;
    child.nonce = input.nonce;
    child.delegation_depth = depth;
    child.parent_permit_id = parent.permit_id.clone();
    child.parent_chain.push(parent.permit_id.clone());
    child.revocation_handle = format!("revoke-{}", child.permit_id);
    child.issued_at_ms = input.now_ms;
    child.sign(signing_key)?;
    Ok(child)
}

fn is_subset(values: &[String], parent: &[String]) -> bool {
    values.iter().all(|value| parent.contains(value))
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn validate_delegation_chain_on(
    conn: &rusqlite::Connection,
    permit: &Permit,
) -> Result<(), String> {
    if permit.delegation_depth as usize != permit.parent_chain.len() {
        return Err("delegation chain depth mismatch".into());
    }
    let current_policy = if permit.delegation_depth == 0 {
        None
    } else {
        let json: Option<String> = conn
            .query_row(
                "SELECT policy_json FROM chisei_external_permit_policies WHERE scope=?1",
                [&permit.policy_scope],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let policy: ExternalPermitPolicy = json
            .ok_or_else(|| "delegation policy is missing or disabled".to_string())
            .and_then(|value| serde_json::from_str(&value).map_err(|error| error.to_string()))?;
        if permit.delegation_depth > policy.max_delegation_depth {
            return Err("delegation exceeds the current policy depth".into());
        }
        Some(policy)
    };
    for (index, parent_id) in permit.parent_chain.iter().enumerate() {
        let json: Option<String> = conn.query_row(
            "SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=?1
             UNION ALL SELECT permit_json FROM chisei_external_action_delegated_permits WHERE permit_id=?1 LIMIT 1",
            [parent_id], |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
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
        let revoked: Option<String> = conn
            .query_row(
                "SELECT reason FROM chisei_external_action_revocations WHERE revocation_handle=?1",
                [&parent.revocation_handle],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if revoked.is_some() {
            return Err("delegation parent is revoked".into());
        }
        if parent.parent_chain != permit.parent_chain[..index] {
            return Err("delegation parent chain is malformed".into());
        }
    }
    Ok(())
}

impl SekaiDb {
    pub(crate) fn ensure_external_permit_tables(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_external_action_permits (
                permit_id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE,
                issuance_idempotency_key TEXT NOT NULL, permit_json TEXT NOT NULL, issued_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_redemptions (
                permit_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, execution_id TEXT NOT NULL,
                redemption_json TEXT NOT NULL, redeemed_at_ms INTEGER NOT NULL,
                invocation_ordinal INTEGER NOT NULL, redemption_id TEXT,
                evidence_due_at_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(permit_id,idempotency_key), UNIQUE(permit_id,execution_id),
                UNIQUE(permit_id,invocation_ordinal)
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_revocations (
                revocation_handle TEXT PRIMARY KEY, reason TEXT NOT NULL, revoked_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_kill_switches (
                scope_kind TEXT NOT NULL, scope_value TEXT NOT NULL, reason TEXT NOT NULL,
                enabled_at_ms INTEGER NOT NULL, PRIMARY KEY(scope_kind,scope_value)
             );
             CREATE TABLE IF NOT EXISTS chisei_external_action_delegated_permits (
                permit_id TEXT PRIMARY KEY, parent_permit_id TEXT NOT NULL,
                permit_json TEXT NOT NULL, issued_at_ms INTEGER NOT NULL
             );
             CREATE UNIQUE INDEX IF NOT EXISTS idx_external_action_one_child_per_parent
             ON chisei_external_action_delegated_permits(parent_permit_id);
             CREATE TABLE IF NOT EXISTS chisei_external_permit_policies (
                scope TEXT PRIMARY KEY, policy_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL
             );"
        ).map_err(|error| error.to_string())?;
        for (column, definition) in [
            ("redemption_id", "TEXT"),
            ("evidence_due_at_ms", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let exists = {
                let mut statement = conn
                    .prepare("PRAGMA table_info(chisei_external_action_redemptions)")
                    .map_err(|error| error.to_string())?;
                statement
                    .query_map([], |row| row.get::<_, String>(1))
                    .map_err(|error| error.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?
                    .iter()
                    .any(|name| name == column)
            };
            if !exists {
                conn.execute_batch(&format!(
                    "ALTER TABLE chisei_external_action_redemptions ADD COLUMN {column} {definition}"
                )).map_err(|error| error.to_string())?;
            }
        }
        conn.execute_batch(
            "UPDATE chisei_external_action_redemptions
             SET redemption_id=COALESCE(
                     redemption_id,
                     json_extract(redemption_json,'$.redemption_id')
                 ),
                 evidence_due_at_ms=CASE
                     WHEN evidence_due_at_ms=0 THEN COALESCE(
                         json_extract(redemption_json,'$.evidence_due_at_ms'),
                         (SELECT json_extract(p.permit_json,'$.expires_at_ms')
                          FROM chisei_external_action_permits p
                          WHERE p.permit_id=chisei_external_action_redemptions.permit_id),
                         0
                     )
                     ELSE evidence_due_at_ms
                 END
             WHERE redemption_id IS NULL OR evidence_due_at_ms=0;
             UPDATE chisei_external_action_redemptions
             SET redemption_json=json_set(
                 redemption_json,
                 '$.evidence_due_at_ms',
                 evidence_due_at_ms
             )
             WHERE COALESCE(json_extract(redemption_json,'$.evidence_due_at_ms'),0)
                   != evidence_due_at_ms;
             CREATE INDEX IF NOT EXISTS idx_external_action_redemptions_evidence_due
             ON chisei_external_action_redemptions(evidence_due_at_ms,redemption_id);",
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
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

    pub fn put_delegated_permit(&self, permit: &Permit, issued_by: &str) -> Result<Permit, String> {
        self.ensure_external_permit_tables()?;
        if permit.delegation_depth == 0 || permit.parent_permit_id.is_empty() {
            return Err("delegated permit must name its parent".into());
        }
        self.validate_delegation_chain(permit)?;
        let json = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let parent_redemptions: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM chisei_external_action_redemptions WHERE permit_id=?1",
                [&permit.parent_permit_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if parent_redemptions != 0 {
            return Err("partially consumed permit authority cannot be delegated".into());
        }
        tx.execute(
            "INSERT INTO chisei_external_action_delegated_permits(permit_id,parent_permit_id,permit_json,issued_at_ms) VALUES(?1,?2,?3,?4)",
            rusqlite::params![permit.permit_id, permit.parent_permit_id, json, permit.issued_at_ms],
        ).map_err(|error| error.to_string())?;
        crate::sekai::ledger::insert_chained_decision(
            &tx,
            &crate::sekai::audit::Decision {
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
        self.ensure_external_permit_tables()?;
        let json = serde_json::to_string(policy).map_err(|error| error.to_string())?;
        self.conn().execute(
            "INSERT INTO chisei_external_permit_policies(scope,policy_json,updated_at_ms) VALUES(?1,?2,?3)
             ON CONFLICT(scope) DO UPDATE SET policy_json=?2,updated_at_ms=?3",
            rusqlite::params![policy.scope, json, now_ms],
        ).map(|_| ()).map_err(|error| error.to_string())
    }

    pub fn get_external_permit_policy(&self, scope: &str) -> Result<ExternalPermitPolicy, String> {
        self.ensure_external_permit_tables()?;
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT policy_json FROM chisei_external_permit_policies WHERE scope=?1",
                [scope],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| serde_json::from_str(&value).map_err(|error| error.to_string()))
            .transpose()
            .map(|value| value.unwrap_or_else(|| ExternalPermitPolicy::disabled(scope)))
    }

    pub fn validate_delegation_chain(&self, permit: &Permit) -> Result<(), String> {
        self.ensure_external_permit_tables()?;
        let conn = self.conn();
        validate_delegation_chain_on(&conn, permit)
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

    #[allow(clippy::too_many_arguments)]
    pub fn redeem_permit(
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
    pub fn redeem_or_reconcile_permit(
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
        // Fail closed: online (and offline reconcile) authority is pin-home only.
        let permit_site = if permit.site_id.trim().is_empty() {
            crate::sekai::lease::DEFAULT_SITE_ID
        } else {
            permit.site_id.as_str()
        };
        if permit_site != host_site_id {
            return Err(format!(
                "permit is pinned to site '{permit_site}' (host site '{host_site_id}'); foreign pin fail closed"
            ));
        }
        self.ensure_external_permit_tables()?;
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
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        validate_delegation_chain_on(&tx, permit)?;
        let stored_json: Option<String> = tx
            .query_row(
                "SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=?1
                 UNION ALL SELECT permit_json FROM chisei_external_action_delegated_permits WHERE permit_id=?1 LIMIT 1",
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
        let delegated_child: Option<String> = tx.query_row(
            "SELECT permit_id FROM chisei_external_action_delegated_permits WHERE parent_permit_id=?1",
            [&permit.permit_id], |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        if delegated_child.is_some() {
            return Err("permit authority was transferred to a delegated child".into());
        }
        permit.verify_signature(trusted_key)?;
        // Online redemption authorizes a future invocation and therefore uses
        // live time, revocation, authorization, and kill-switch state. Offline
        // reconciliation records an invocation that may already have happened
        // while disconnected: validate its signed host binding, but never hide
        // the resulting evidence merely because the lease later expired or was
        // revoked before the executor reconnected.
        let validation_time = if offline_reconciliation {
            invoked_at_ms
        } else {
            now_ms
        };
        permit.verify_host_context(context, validation_time)?;
        let authorization_json: Option<String> = tx.query_row("SELECT record_json FROM chisei_external_action_authorizations WHERE authorization_id=?1", [&permit.authorization_id], |row| row.get(0)).optional().map_err(|error| error.to_string())?.flatten();
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
            .query_row(
                "SELECT reason FROM chisei_external_action_revocations WHERE revocation_handle=?1",
                [&permit.revocation_handle],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if !offline_reconciliation && let Some(reason) = revoked {
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
            if !offline_reconciliation && let Some(reason) = reason {
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
        tx.execute("INSERT INTO chisei_external_action_redemptions(permit_id,idempotency_key,execution_id,redemption_json,redeemed_at_ms,invocation_ordinal,redemption_id,evidence_due_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", rusqlite::params![permit.permit_id,idempotency_key,execution_id,json,redemption.redeemed_at_ms,redemption.invocation_ordinal,redemption.redemption_id,redemption.evidence_due_at_ms]).map_err(|error| error.to_string())?;
        crate::sekai::ledger::insert_chained_decision(
            &tx,
            &crate::sekai::audit::Decision {
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

    /// Validate online lifecycle state without consuming an invocation. Hosts
    /// must still redeem immediately before execution; redemption repeats all
    /// checks atomically with consumption.
    pub fn validate_permit_state(&self, permit: &Permit) -> Result<(), String> {
        self.ensure_external_permit_tables()?;
        self.validate_delegation_chain(permit)?;
        let conn = self.conn();
        let stored_json: Option<String> = conn
            .query_row(
                "SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=?1
                 UNION ALL SELECT permit_json FROM chisei_external_action_delegated_permits WHERE permit_id=?1 LIMIT 1",
                [&permit.permit_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let supplied = serde_json::to_string(permit).map_err(|error| error.to_string())?;
        if stored_json.as_deref() != Some(supplied.as_str()) {
            return Err("permit is not the issued durable permit".into());
        }
        let delegated_child: Option<String> = conn
            .query_row(
                "SELECT permit_id FROM chisei_external_action_delegated_permits WHERE parent_permit_id=?1",
                [&permit.permit_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if delegated_child.is_some() {
            return Err("permit authority was transferred to a delegated child".into());
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
                "SELECT permit_json FROM chisei_external_action_permits WHERE permit_id=?1
                 UNION ALL SELECT permit_json FROM chisei_external_action_delegated_permits WHERE permit_id=?1 LIMIT 1",
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

    pub fn validate_permit_for_delegation(&self, permit: &Permit) -> Result<(), String> {
        self.validate_permit_state(permit)?;
        let count: u32 = self
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM chisei_external_action_redemptions WHERE permit_id=?1",
                [&permit.permit_id],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if count != 0 {
            return Err("partially consumed permit authority cannot be delegated".into());
        }
        Ok(())
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

    fn persist_authorization(db: &RuntimeDb, record: &AuthorizationRecord) {
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
                site_id: "local",
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
    fn legacy_online_v1_permit_without_append_only_fields_still_verifies() {
        let record = authorization(10_000, 1);
        let (mut legacy, key) = signed(&record);
        legacy.policy_scope.clear();
        legacy.initiating_actor.clear();
        legacy.parent_chain.clear();
        legacy.offline_revocation_unavailable = false;
        legacy.sign(&key).unwrap();
        let json = serde_json::to_string(&legacy).unwrap();
        assert!(!json.contains("initiating_actor"));
        let restored: Permit = serde_json::from_str(&json).unwrap();
        restored.verify_signature(&key.verifying_key()).unwrap();
        restored
            .verify_host_context(&context(&restored), 2_001)
            .unwrap();
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
            let db = RuntimeDb::Sqlite(std::sync::Arc::new(
                SekaiDb::new(path.to_str().unwrap()).unwrap(),
            ));
            persist_authorization(&db, &record);
            db.put_permit(&permit, "issue-1", "agent:test").unwrap();
            let first = db
                .redeem_permit(
                    &permit,
                    &context(&permit),
                    &key.verifying_key(),
                    "redeem-1",
                    "execution-1",
                    "local",
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
                    "local",
                    3_001,
                )
                .unwrap();
            assert_eq!(first, retry);
        }
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(path.to_str().unwrap()).unwrap(),
        ));
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
                "local",
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
                "local",
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
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(path.to_str().unwrap()).unwrap(),
        ));
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
                let db = RuntimeDb::Sqlite(std::sync::Arc::new(
                    SekaiDb::new(path.to_str().unwrap()).unwrap(),
                ));
                barrier.wait();
                db.redeem_permit(
                    &permit,
                    &context(&permit),
                    &key.verifying_key(),
                    &format!("redeem-{ordinal}"),
                    &format!("execution-{ordinal}"),
                    "local",
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
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        persist_authorization(&db, &record);
        db.put_permit(&permit, "issue-1", "agent:test").unwrap();
        let mut changed = context(&permit);
        changed
            .observed_preconditions
            .insert("resource_version".into(), "git:def456".into());
        assert!(
            db.redeem_permit(
                &permit,
                &changed,
                &key.verifying_key(),
                "r-1",
                "e-1",
                "local",
                3_000
            )
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
                "local",
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
                    site_id: "local",
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
                "local",
                3_004
            )
            .unwrap_err()
            .contains("kill switch")
        );
    }

    fn permit_policy() -> ExternalPermitPolicy {
        ExternalPermitPolicy {
            scope: "project:test".into(),
            offline_action_types: vec!["repository.read/v1".into()],
            offline_max_duration_ms: 2_000,
            offline_max_invocations: 2,
            permitted_delegators: vec!["agent:test".into(), "agent:child".into()],
            max_delegation_depth: 2,
        }
    }

    #[test]
    fn offline_lease_is_bounded_and_declares_weaker_guarantees() {
        let record = authorization(10_000, 9);
        let key = SigningKey::from_bytes(&[7; 32]);
        let permit = issue_offline(
            &record,
            &permit_policy(),
            &key,
            Issuance {
                approval_identities: vec![],
                issuer: "issuer:test",
                key_id: "key-1",
                permit_id: "offline-1".into(),
                nonce: "offline-nonce".into(),
                now_ms: 2_000,
                site_id: "local",
            },
        )
        .unwrap();
        assert_eq!(permit.redemption_mode, OFFLINE_REDEMPTION_MODE);
        assert_eq!(permit.max_invocations, 2);
        assert_eq!(permit.expires_at_ms, 4_000);
        assert!(permit.offline_revocation_unavailable);
        assert!(
            permit
                .constraints
                .contains(&"offline_no_global_single_use".into())
        );
        permit
            .verify_host_context(&context(&permit), 3_999)
            .unwrap();

        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        persist_authorization(&db, &record);
        db.put_permit(&permit, "offline-issue", "agent:test")
            .unwrap();
        db.revoke_permit(
            &permit.revocation_handle,
            "learned after disconnected execution",
            4_001,
        )
        .unwrap();
        let reconciled = db
            .redeem_or_reconcile_permit(
                &permit,
                &context(&permit),
                &key.verifying_key(),
                "offline-reconcile-1",
                "offline-execution-1",
                "local",
                RedemptionTiming {
                    invoked_at_ms: 3_000,
                    reconciled_at_ms: 5_000,
                },
            )
            .unwrap();
        assert_eq!(reconciled.invocation_ordinal, 1);
        assert_eq!(reconciled.execution_id, "offline-execution-1");
        assert_eq!(
            db.replay_redemption(&permit, "offline-reconcile-1", "offline-execution-1")
                .unwrap(),
            Some(reconciled)
        );
        db.redeem_or_reconcile_permit(
            &permit,
            &context(&permit),
            &key.verifying_key(),
            "offline-reconcile-2",
            "offline-execution-2",
            "local",
            RedemptionTiming {
                invoked_at_ms: 3_500,
                reconciled_at_ms: 5_001,
            },
        )
        .unwrap();
        assert!(
            db.redeem_or_reconcile_permit(
                &permit,
                &context(&permit),
                &key.verifying_key(),
                "offline-reconcile-3",
                "offline-execution-3",
                "local",
                RedemptionTiming {
                    invoked_at_ms: 3_750,
                    reconciled_at_ms: 5_002,
                }
            )
            .unwrap_err()
            .contains("invocation count exhausted")
        );

        let mut destructive = authorization(10_000, 1);
        destructive.request.action_type = "repository.delete.destructive/v1".into();
        destructive.request.parameter_schema = "repository.delete.params/v1".into();
        destructive.request.risk_class = "destructive".into();
        destructive.decision.request_digest = destructive.request.canonical_digest().unwrap();
        let mut destructive_policy = permit_policy();
        destructive_policy
            .offline_action_types
            .push("repository.delete.destructive/v1".into());
        assert!(
            issue_offline(
                &destructive,
                &destructive_policy,
                &key,
                Issuance {
                    approval_identities: vec![],
                    issuer: "issuer:test",
                    key_id: "key-1",
                    permit_id: "offline-2".into(),
                    nonce: "n".into(),
                    now_ms: 2_000,
                    site_id: "local",
                }
            )
            .unwrap_err()
            .contains("online revocation")
        );

        let mut ineligible = permit_policy();
        ineligible.offline_action_types.clear();
        assert!(
            issue_offline(
                &record,
                &ineligible,
                &key,
                Issuance {
                    approval_identities: vec![],
                    issuer: "issuer:test",
                    key_id: "key-1",
                    permit_id: "offline-3".into(),
                    nonce: "n".into(),
                    now_ms: 2_000,
                    site_id: "local",
                }
            )
            .unwrap_err()
            .contains("does not permit")
        );
    }

    #[test]
    fn delegation_is_narrow_policy_named_and_parent_chain_is_live() {
        let record = authorization(10_000, 3);
        let (root, key) = signed(&record);
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        persist_authorization(&db, &record);
        db.set_external_permit_policy(&permit_policy(), 2_500)
            .unwrap();
        db.put_permit(&root, "root", "agent:test").unwrap();
        let child = delegate(
            &root,
            &permit_policy(),
            &key,
            Delegation {
                delegator: "agent:test",
                subject_actor: "agent:child",
                permit_id: "child-1".into(),
                nonce: "child-nonce".into(),
                now_ms: 3_000,
                expires_at_ms: 8_000,
                target_selectors: root.target_selectors.clone(),
                allowed_effects: root.allowed_effects.clone(),
                budget_micros: 5,
                volume_limit: 512,
                blast_radius_limit: 1,
                max_invocations: 1,
                risk_class: &root.risk_class,
            },
        )
        .unwrap();
        assert_eq!(child.initiating_actor, "agent:test");
        assert_eq!(child.parent_chain, vec![root.permit_id.clone()]);
        db.put_delegated_permit(&child, "agent:test").unwrap();
        db.validate_delegation_chain(&child).unwrap();
        assert!(
            db.validate_permit_state(&root)
                .unwrap_err()
                .contains("transferred")
        );
        let sibling = delegate(
            &root,
            &permit_policy(),
            &key,
            Delegation {
                delegator: "agent:test",
                subject_actor: "agent:sibling",
                permit_id: "child-2".into(),
                nonce: "sibling".into(),
                now_ms: 3_001,
                expires_at_ms: 8_000,
                target_selectors: root.target_selectors.clone(),
                allowed_effects: root.allowed_effects.clone(),
                budget_micros: 5,
                volume_limit: 512,
                blast_radius_limit: 1,
                max_invocations: 1,
                risk_class: &root.risk_class,
            },
        )
        .unwrap();
        assert!(
            db.put_delegated_permit(&sibling, "agent:test")
                .unwrap_err()
                .contains("UNIQUE")
        );

        let mut expanding_targets = root.target_selectors.clone();
        expanding_targets.push("project:test/secret".into());
        assert!(
            delegate(
                &root,
                &permit_policy(),
                &key,
                Delegation {
                    delegator: "agent:test",
                    subject_actor: "agent:child",
                    permit_id: "bad".into(),
                    nonce: "bad".into(),
                    now_ms: 3_000,
                    expires_at_ms: 8_000,
                    target_selectors: expanding_targets,
                    allowed_effects: root.allowed_effects.clone(),
                    budget_micros: 5,
                    volume_limit: 512,
                    blast_radius_limit: 1,
                    max_invocations: 1,
                    risk_class: &root.risk_class,
                }
            )
            .unwrap_err()
            .contains("expand")
        );

        db.revoke_permit(&root.revocation_handle, "root revoked", 3_100)
            .unwrap();
        assert!(
            db.validate_delegation_chain(&child)
                .unwrap_err()
                .contains("revoked")
        );
        let mut missing = child.clone();
        missing.parent_chain = vec!["missing".into()];
        missing.parent_permit_id = "missing".into();
        assert!(
            db.validate_delegation_chain(&missing)
                .unwrap_err()
                .contains("missing")
        );
    }

    #[test]
    fn delegation_rejects_unnamed_delegator_and_over_depth() {
        let record = authorization(10_000, 2);
        let (root, key) = signed(&record);
        let mut policy = permit_policy();
        assert!(
            delegate(
                &root,
                &policy,
                &key,
                Delegation {
                    delegator: "agent:unknown",
                    subject_actor: "agent:child",
                    permit_id: "bad".into(),
                    nonce: "bad".into(),
                    now_ms: 3_000,
                    expires_at_ms: 8_000,
                    target_selectors: root.target_selectors.clone(),
                    allowed_effects: root.allowed_effects.clone(),
                    budget_micros: 5,
                    volume_limit: 512,
                    blast_radius_limit: 1,
                    max_invocations: 1,
                    risk_class: &root.risk_class,
                }
            )
            .unwrap_err()
            .contains("permitted delegator")
        );
        policy.max_delegation_depth = 0;
        assert!(
            delegate(
                &root,
                &policy,
                &key,
                Delegation {
                    delegator: "agent:test",
                    subject_actor: "agent:child",
                    permit_id: "bad".into(),
                    nonce: "bad".into(),
                    now_ms: 3_000,
                    expires_at_ms: 8_000,
                    target_selectors: root.target_selectors.clone(),
                    allowed_effects: root.allowed_effects.clone(),
                    budget_micros: 5,
                    volume_limit: 512,
                    blast_radius_limit: 1,
                    max_invocations: 1,
                    risk_class: &root.risk_class,
                }
            )
            .unwrap_err()
            .contains("depth")
        );

        let mut offline = root.clone();
        offline.redemption_mode = OFFLINE_REDEMPTION_MODE.into();
        offline.offline_revocation_unavailable = true;
        offline.revocation_latency_ms = 1_000;
        offline.sign(&key).unwrap();
        assert!(
            delegate(
                &offline,
                &permit_policy(),
                &key,
                Delegation {
                    delegator: "agent:test",
                    subject_actor: "agent:child",
                    permit_id: "offline-child".into(),
                    nonce: "bad".into(),
                    now_ms: 3_000,
                    expires_at_ms: 8_000,
                    target_selectors: offline.target_selectors.clone(),
                    allowed_effects: offline.allowed_effects.clone(),
                    budget_micros: 5,
                    volume_limit: 512,
                    blast_radius_limit: 1,
                    max_invocations: 1,
                    risk_class: &offline.risk_class,
                }
            )
            .unwrap_err()
            .contains("cannot be delegated")
        );
    }

    #[test]
    fn issue_stamps_default_local_site_and_redeem_exposes_pin() {
        let record = authorization(10_000, 1);
        let (permit, key) = signed(&record);
        assert_eq!(permit.site_id, "local");
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        persist_authorization(&db, &record);
        db.put_permit(&permit, "issue-1", "agent:test").unwrap();
        let redemption = db
            .redeem_permit(
                &permit,
                &context(&permit),
                &key.verifying_key(),
                "r-1",
                "e-1",
                "local",
                3_000,
            )
            .unwrap();
        assert_eq!(redemption.site_id, "local");
    }

    #[test]
    fn dual_region_foreign_pin_redeem_fails_closed() {
        let record = authorization(10_000, 1);
        let key = SigningKey::from_bytes(&[7; 32]);
        let permit = issue(
            &record,
            &key,
            Issuance {
                approval_identities: vec![],
                issuer: "issuer:test",
                key_id: "key-1",
                permit_id: "permit-us".into(),
                nonce: "nonce-us".into(),
                now_ms: 2_000,
                site_id: "us-east",
            },
        )
        .unwrap();
        assert_eq!(permit.site_id, "us-east");
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        persist_authorization(&db, &record);
        db.put_permit(&permit, "issue-us", "agent:test").unwrap();
        let foreign = db.redeem_permit(
            &permit,
            &context(&permit),
            &key.verifying_key(),
            "r-foreign",
            "e-foreign",
            "eu-west",
            3_000,
        );
        assert!(
            foreign.unwrap_err().contains("pinned to site 'us-east'"),
            "foreign region must fail closed"
        );
        let home = db
            .redeem_permit(
                &permit,
                &context(&permit),
                &key.verifying_key(),
                "r-home",
                "e-home",
                "us-east",
                3_000,
            )
            .unwrap();
        assert_eq!(home.site_id, "us-east");
        // Second distinct redeem at home fails on invocation count, not pin.
        let double = db.redeem_permit(
            &permit,
            &context(&permit),
            &key.verifying_key(),
            "r-home-2",
            "e-home-2",
            "us-east",
            3_001,
        );
        assert!(double.unwrap_err().contains("exhausted"));
    }

    #[test]
    fn legacy_permit_without_site_id_defaults_to_local() {
        let record = authorization(10_000, 1);
        let (mut permit, key) = signed(&record);
        let mut json: serde_json::Value = serde_json::to_value(&permit).unwrap();
        json.as_object_mut().unwrap().remove("site_id");
        let restored: Permit = serde_json::from_value(json).unwrap();
        assert_eq!(restored.site_id, "local");
        // Re-sign after restore so the digest includes the defaulted field only
        // when present; omit field then sign without site_id in unsigned form
        // by clearing and re-signing with explicit local.
        permit.site_id = "local".into();
        permit.sign(&key).unwrap();
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        persist_authorization(&db, &record);
        db.put_permit(&permit, "issue-legacy", "agent:test")
            .unwrap();
        db.redeem_permit(
            &permit,
            &context(&permit),
            &key.verifying_key(),
            "r-legacy",
            "e-legacy",
            "local",
            3_000,
        )
        .unwrap();
    }
}
