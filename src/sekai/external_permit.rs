//! Signed external-action permit vocabulary (ADR 0096 rule 5).
//!
//! Chisei issues and redeems these records. Sekai persists host-reported
//! execution evidence against the same shapes.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Default single-region site pin (`SEKAI_SITE_ID` default). Same value as
/// [`crate::sekai::lease::DEFAULT_SITE_ID`]. Inlined here because importing
/// `sekai::lease` would cycle through `runtime_db`.
pub const DEFAULT_SITE_ID: &str = "local";
pub const PERMIT_VERSION: &str = "external-action.permit/v1";
pub const SIGNATURE_ALGORITHM: &str = crate::shomei::SIGNATURE_ALGORITHM;
pub const REDEMPTION_MODE: &str = "online_atomic";
pub const OFFLINE_REDEMPTION_MODE: &str = "offline_bounded";

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
    DEFAULT_SITE_ID.into()
}

fn is_false(value: &bool) -> bool {
    !*value
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
