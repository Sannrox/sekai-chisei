//! Bounded autonomous action envelopes (#715).
//!
//! Admit autonomous Actions only inside a signed envelope whose state,
//! policy, model, prompt, evidence, simulation, budget, and lease pins are
//! current. The envelope is not a runtime grant.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::object_sync::contains_secret_like_text;
use crate::shomei;

pub const ENVELOPE_CONTRACT: &str = "sekai.autonomous-envelope/v1";
pub const PROFILE_SIMULATE: &str = "adapter.autonomy.simulate";
pub const PROFILE_EVALUATE: &str = "adapter.autonomy.evaluate";
pub const PROFILE_VERSION: &str = "1.0.0";
pub const STATUS_LIVE: &str = "live";
pub const STATUS_STOPPED: &str = "stopped";
pub const STATUS_ROLLED_BACK: &str = "rolled_back";
pub const STATUS_LEASE_LOST: &str = "lease_lost";
pub const RECEIPT_CURRENT: &str = "current";
pub const RECEIPT_INVALIDATED: &str = "invalidated";
pub const AUTONOMY_UNAVAILABLE: &str = "autonomous envelope is unavailable";
pub const PROTOCOL_UNSUPPORTED: &str = "autonomous envelope revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "autonomous envelopes are unavailable on the PostgreSQL community runtime";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousPins {
    pub state_digest: String,
    pub policy_digest: String,
    pub model_digest: String,
    pub prompt_digest: String,
    pub evidence_digest: String,
    pub simulation_digest: String,
    pub budget_digest: String,
    pub lease_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousEnvelope {
    pub contract_version: String,
    pub envelope_id: String,
    pub namespace: String,
    pub owner: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub pins: AutonomousPins,
    pub signer_id: String,
    pub signer_digest: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    #[serde(default)]
    pub envelope_digest: String,
    #[serde(default)]
    pub receipt_digest: String,
    #[serde(default)]
    pub receipt_status: String,
    pub status: String,
    #[serde(default)]
    pub predecessor_id: String,
    #[serde(default)]
    pub admitted_by: String,
    #[serde(default)]
    pub admitted_at_ms: i64,
}

#[derive(Serialize)]
struct EnvelopePin<'a> {
    contract_version: &'a str,
    envelope_id: &'a str,
    namespace: &'a str,
    owner: &'a str,
    adapter_id: &'a str,
    adapter_version: &'a str,
    pins: &'a AutonomousPins,
    signer_id: &'a str,
    signer_digest: &'a str,
    public_key_hex: &'a str,
    predecessor_id: &'a str,
}

pub fn envelope_digest_for(envelope: &AutonomousEnvelope) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&EnvelopePin {
            contract_version: &envelope.contract_version,
            envelope_id: &envelope.envelope_id,
            namespace: &envelope.namespace,
            owner: &envelope.owner,
            adapter_id: &envelope.adapter_id,
            adapter_version: &envelope.adapter_version,
            pins: &envelope.pins,
            signer_id: &envelope.signer_id,
            signer_digest: &envelope.signer_digest,
            public_key_hex: &envelope.public_key_hex,
            predecessor_id: &envelope.predecessor_id,
        })?
    ))
}

pub fn admit_envelope(
    db: &RuntimeDb,
    actor: &str,
    envelope: &AutonomousEnvelope,
    now_ms: i64,
) -> Result<AutonomousEnvelope, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("admit", now_ms)?;
    if let Some(existing) =
        db.get_autonomous_envelope(&envelope.namespace, &envelope.envelope_id)?
    {
        let validated = validate_envelope(envelope, actor, now_ms)?;
        return replay_existing(existing, &validated, actor);
    }
    let validated = validate_envelope(envelope, actor, now_ms)?;
    match db.put_autonomous_envelope(&validated) {
        Ok(()) => Ok(validated),
        Err(error) if error == AUTONOMY_UNAVAILABLE => {
            let existing = db
                .get_autonomous_envelope(&validated.namespace, &validated.envelope_id)?
                .ok_or(AUTONOMY_UNAVAILABLE)?;
            replay_existing(existing, &validated, actor)
        }
        Err(error) => Err(error),
    }
}

pub fn require_live_envelope(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    envelope_id: &str,
) -> Result<AutonomousEnvelope, String> {
    // Live means this envelope identity still carries its admitted pins and a
    // current receipt. Pins are identity, not a grant over live policy, budget,
    // or lease stores. Stale is a later admit with different pins for the same
    // envelope_id; lease loss and receipt invalidation are explicit.
    required("envelope id", envelope_id)?;
    let envelope = owned_envelope(db, namespace, envelope_id, actor)?;
    if envelope.status != STATUS_LIVE || envelope.receipt_status != RECEIPT_CURRENT {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    verify_signature(&envelope)?;
    Ok(envelope)
}

pub fn get_envelope(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    envelope_id: &str,
) -> Result<AutonomousEnvelope, String> {
    owned_envelope(db, namespace, envelope_id, actor)
}

pub fn stop_envelope(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    envelope_id: &str,
    now_ms: i64,
) -> Result<AutonomousEnvelope, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("stop", now_ms)?;
    let current = owned_envelope(db, namespace, envelope_id, actor)?;
    if current.status == STATUS_STOPPED {
        return Ok(current);
    }
    if current.status != STATUS_LIVE || current.receipt_status != RECEIPT_CURRENT {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    let mut next = current.clone();
    next.status = STATUS_STOPPED.into();
    next.admitted_at_ms = now_ms;
    db.cas_autonomous_envelope(&current, &next)?;
    Ok(next)
}

pub fn rollback_envelope(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    envelope_id: &str,
    now_ms: i64,
) -> Result<AutonomousEnvelope, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("rollback", now_ms)?;
    let current = owned_envelope(db, namespace, envelope_id, actor)?;
    if current.status == STATUS_ROLLED_BACK {
        return Ok(current);
    }
    if current.status == STATUS_LEASE_LOST {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    let mut next = current.clone();
    next.status = STATUS_ROLLED_BACK.into();
    next.admitted_at_ms = now_ms;
    db.cas_autonomous_envelope(&current, &next)?;
    Ok(next)
}

pub fn note_lease_loss(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    envelope_id: &str,
    now_ms: i64,
) -> Result<AutonomousEnvelope, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("lease-loss", now_ms)?;
    let current = owned_envelope(db, namespace, envelope_id, actor)?;
    if current.status == STATUS_LEASE_LOST {
        return Ok(current);
    }
    let mut next = current.clone();
    next.status = STATUS_LEASE_LOST.into();
    next.admitted_at_ms = now_ms;
    db.cas_autonomous_envelope(&current, &next)?;
    Ok(next)
}

pub fn invalidate_receipt(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    envelope_id: &str,
    now_ms: i64,
) -> Result<AutonomousEnvelope, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("invalidate", now_ms)?;
    let current = owned_envelope(db, namespace, envelope_id, actor)?;
    if current.receipt_status == RECEIPT_INVALIDATED {
        return Ok(current);
    }
    if current.status != STATUS_LIVE {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    let mut next = current.clone();
    next.receipt_status = RECEIPT_INVALIDATED.into();
    next.admitted_at_ms = now_ms;
    db.cas_autonomous_envelope(&current, &next)?;
    Ok(next)
}

fn validate_envelope(
    envelope: &AutonomousEnvelope,
    actor: &str,
    now_ms: i64,
) -> Result<AutonomousEnvelope, String> {
    if envelope.contract_version != ENVELOPE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    if envelope.adapter_version != PROFILE_VERSION
        || (envelope.adapter_id != PROFILE_SIMULATE && envelope.adapter_id != PROFILE_EVALUATE)
    {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    required("envelope id", &envelope.envelope_id)?;
    required("namespace", &envelope.namespace)?;
    required("owner", &envelope.owner)?;
    required("signer id", &envelope.signer_id)?;
    reject_secret(&envelope.envelope_id)?;
    reject_secret(&envelope.namespace)?;
    reject_secret(&envelope.owner)?;
    reject_secret(&envelope.signer_id)?;
    reject_secret(&envelope.predecessor_id)?;
    if envelope.owner != actor
        || has_whitespace(&envelope.namespace)
        || has_whitespace(&envelope.envelope_id)
    {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    if envelope.status != STATUS_LIVE {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    validate_pins(&envelope.pins)?;
    let mut next = envelope.clone();
    next.receipt_status = RECEIPT_CURRENT.into();
    next.admitted_by = actor.into();
    next.admitted_at_ms = now_ms;
    let digest = envelope_digest_for(&next)?;
    if !envelope.envelope_digest.is_empty() && envelope.envelope_digest != digest {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    next.envelope_digest = digest;
    let receipt_digest = receipt_digest_for(&next)?;
    if !envelope.receipt_digest.is_empty() && envelope.receipt_digest != receipt_digest {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    next.receipt_digest = receipt_digest;
    verify_signature(&next)?;
    Ok(next)
}

// Pins are the envelope's current identity, not a live grant over policy,
// budget, or lease stores. A later admit with different pins for the same
// envelope identity is stale and fails closed.
fn validate_pins(pins: &AutonomousPins) -> Result<(), String> {
    for (label, value) in [
        ("state", pins.state_digest.as_str()),
        ("policy", pins.policy_digest.as_str()),
        ("model", pins.model_digest.as_str()),
        ("prompt", pins.prompt_digest.as_str()),
        ("evidence", pins.evidence_digest.as_str()),
        ("simulation", pins.simulation_digest.as_str()),
        ("budget", pins.budget_digest.as_str()),
        ("lease", pins.lease_digest.as_str()),
    ] {
        if !digest_token(value) {
            return Err(AUTONOMY_UNAVAILABLE.into());
        }
        reject_secret(label)?;
    }
    Ok(())
}

fn receipt_digest_for(envelope: &AutonomousEnvelope) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&(
            envelope.envelope_id.as_str(),
            envelope.namespace.as_str(),
            envelope.envelope_digest.as_str(),
            envelope.pins.evidence_digest.as_str(),
            envelope.pins.simulation_digest.as_str(),
        ))?
    ))
}

fn owned_envelope(
    db: &RuntimeDb,
    namespace: &str,
    envelope_id: &str,
    actor: &str,
) -> Result<AutonomousEnvelope, String> {
    required("namespace", namespace)?;
    required("envelope id", envelope_id)?;
    required("actor", actor)?;
    reject_secret(namespace)?;
    reject_secret(envelope_id)?;
    reject_secret(actor)?;
    let envelope = db
        .get_autonomous_envelope(namespace, envelope_id)?
        .ok_or(AUTONOMY_UNAVAILABLE)?;
    if envelope.owner != actor {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    if envelope.contract_version != ENVELOPE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    Ok(envelope)
}

fn replay_existing(
    existing: AutonomousEnvelope,
    incoming: &AutonomousEnvelope,
    actor: &str,
) -> Result<AutonomousEnvelope, String> {
    if existing.status != STATUS_LIVE
        || existing.receipt_status != RECEIPT_CURRENT
        || existing.owner != actor
    {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    if existing.envelope_digest != incoming.envelope_digest || existing.pins != incoming.pins {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    Ok(existing)
}

// The signature is independently verifiable over the envelope digest. The
// public key is bound into signer_digest and the digest, so a different key
// is a different envelope identity. This is not a runtime grant or signer
// registry.
fn verify_signature(envelope: &AutonomousEnvelope) -> Result<(), String> {
    let public_key = decode_hex(&envelope.public_key_hex, 32)?;
    let signature = decode_hex(&envelope.signature_hex, 64)?;
    let expected_signer = format!("sha256:{:x}", Sha256::digest(public_key));
    if envelope.signer_digest != expected_signer {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| AUTONOMY_UNAVAILABLE)?;
    let signature = Signature::from_bytes(&signature);
    key.verify(envelope.envelope_digest.as_bytes(), &signature)
        .map_err(|_| AUTONOMY_UNAVAILABLE.to_string())?;
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, len: usize) -> Result<[u8; N], String> {
    if value.len() != len * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    let mut out = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
            .map_err(|_| AUTONOMY_UNAVAILABLE.to_string())?;
    }
    Ok(out)
}

fn digest_token(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn reject_secret(value: &str) -> Result<(), String> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("bearer ")
        || lower.contains("sk-")
        || lower.contains("ghp_")
        || lower.contains("gho_")
        || lower.contains("ghu_")
        || lower.contains("ghs_")
        || lower.contains("ghr_")
        || lower.contains("github_pat_")
        || lower.contains("-----begin")
        || contains_secret_like_text(value)
    {
        return Err(AUTONOMY_UNAVAILABLE.into());
    }
    Ok(())
}

fn has_whitespace(value: &str) -> bool {
    value.chars().any(char::is_whitespace)
}

fn require_positive_timestamp(action: &str, now_ms: i64) -> Result<(), String> {
    if now_ms <= 0 {
        Err(format!("{action} timestamp must be positive"))
    } else {
        Ok(())
    }
}

fn required(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn digest(tag: u8) -> String {
        format!("sha256:{tag:02x}{}", "ab".repeat(31))
    }

    fn pins() -> AutonomousPins {
        AutonomousPins {
            state_digest: digest(1),
            policy_digest: digest(2),
            model_digest: digest(3),
            prompt_digest: digest(4),
            evidence_digest: digest(5),
            simulation_digest: digest(6),
            budget_digest: digest(7),
            lease_digest: digest(8),
        }
    }

    fn envelope(adapter: &str, envelope_id: &str) -> AutonomousEnvelope {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut envelope = AutonomousEnvelope {
            contract_version: ENVELOPE_CONTRACT.into(),
            envelope_id: envelope_id.into(),
            namespace: "ops".into(),
            owner: "operator".into(),
            adapter_id: adapter.into(),
            adapter_version: PROFILE_VERSION.into(),
            pins: pins(),
            signer_id: "signer:ops".into(),
            signer_digest: format!("sha256:{:x}", Sha256::digest(public_key)),
            public_key_hex: hex(&public_key),
            signature_hex: String::new(),
            envelope_digest: String::new(),
            receipt_digest: String::new(),
            receipt_status: RECEIPT_CURRENT.into(),
            status: STATUS_LIVE.into(),
            predecessor_id: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        };
        sign(&mut envelope);
        envelope
    }

    fn sign(envelope: &mut AutonomousEnvelope) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        envelope.envelope_digest = envelope_digest_for(envelope).unwrap();
        let signature = signing_key.sign(envelope.envelope_digest.as_bytes());
        envelope.signature_hex = hex(&signature.to_bytes());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn lifecycle(adapter: &str, envelope_id: &str) {
        let runtime = RuntimeDb::memory();
        let admitted =
            admit_envelope(&runtime, "operator", &envelope(adapter, envelope_id), 1_000).unwrap();
        assert_eq!(admitted.status, STATUS_LIVE);
        assert_eq!(admitted.receipt_status, RECEIPT_CURRENT);
        assert_eq!(
            admit_envelope(&runtime, "operator", &admitted, 1_100)
                .unwrap()
                .envelope_digest,
            admitted.envelope_digest
        );
        let mut stale = envelope(adapter, envelope_id);
        stale.pins.policy_digest = digest(9);
        sign(&mut stale);
        assert_eq!(
            admit_envelope(&runtime, "operator", &stale, 1_200).unwrap_err(),
            AUTONOMY_UNAVAILABLE
        );
        let mut model = envelope(adapter, &format!("{envelope_id}-model"));
        model.pins.model_digest = "not-a-digest".into();
        sign(&mut model);
        assert_eq!(
            admit_envelope(&runtime, "operator", &model, 1_300).unwrap_err(),
            AUTONOMY_UNAVAILABLE
        );
        assert_eq!(
            get_envelope(&runtime, "intruder", "ops", envelope_id).unwrap_err(),
            AUTONOMY_UNAVAILABLE
        );
        let stopped = stop_envelope(&runtime, "operator", "ops", envelope_id, 2_000).unwrap();
        assert_eq!(stopped.status, STATUS_STOPPED);
        assert_eq!(
            stop_envelope(&runtime, "operator", "ops", envelope_id, 2_100)
                .unwrap()
                .status,
            STATUS_STOPPED
        );
        assert_eq!(
            admit_envelope(&runtime, "operator", &admitted, 2_200).unwrap_err(),
            AUTONOMY_UNAVAILABLE
        );
        let rolled = rollback_envelope(&runtime, "operator", "ops", envelope_id, 3_000).unwrap();
        assert_eq!(rolled.status, STATUS_ROLLED_BACK);
        let other = format!("{envelope_id}-lease");
        admit_envelope(&runtime, "operator", &envelope(adapter, &other), 4_000).unwrap();
        let lost = note_lease_loss(&runtime, "operator", "ops", &other, 4_100).unwrap();
        assert_eq!(lost.status, STATUS_LEASE_LOST);
        assert_eq!(
            rollback_envelope(&runtime, "operator", "ops", &other, 4_200).unwrap_err(),
            AUTONOMY_UNAVAILABLE
        );
        let receipt_id = format!("{envelope_id}-receipt");
        admit_envelope(&runtime, "operator", &envelope(adapter, &receipt_id), 5_000).unwrap();
        let invalidated =
            invalidate_receipt(&runtime, "operator", "ops", &receipt_id, 5_100).unwrap();
        assert_eq!(invalidated.receipt_status, RECEIPT_INVALIDATED);
        assert_eq!(
            admit_envelope(&runtime, "operator", &envelope(adapter, &receipt_id), 5_200)
                .unwrap_err(),
            AUTONOMY_UNAVAILABLE
        );
        assert_eq!(
            stop_envelope(&runtime, "operator", "ops", &receipt_id, 5_300).unwrap_err(),
            AUTONOMY_UNAVAILABLE
        );
        require_live_envelope(&runtime, "operator", "ops", envelope_id).unwrap_err();
        let live = format!("{envelope_id}-live");
        admit_envelope(&runtime, "operator", &envelope(adapter, &live), 6_000).unwrap();
        require_live_envelope(&runtime, "operator", "ops", &live).unwrap();
    }

    #[test]
    fn two_adapters_pass_current_pin_stop_rollback_lease_and_receipt_invalidation() {
        lifecycle(PROFILE_SIMULATE, "auto:simulate");
        lifecycle(PROFILE_EVALUATE, "auto:evaluate");
    }

    #[test]
    fn hidden_fields_unknown_versions_and_postgres_fail_closed() {
        let mut hidden = serde_json::to_value(envelope(PROFILE_SIMULATE, "auto:h")).unwrap();
        hidden
            .as_object_mut()
            .unwrap()
            .insert("token".into(), serde_json::json!("sk-live"));
        assert!(serde_json::from_value::<AutonomousEnvelope>(hidden).is_err());
        let runtime = RuntimeDb::memory();
        let mut unknown = envelope(PROFILE_SIMULATE, "auto:v0");
        unknown.contract_version = "sekai.autonomous-envelope/v0".into();
        sign(&mut unknown);
        assert_eq!(
            admit_envelope(&runtime, "operator", &unknown, 1_000).unwrap_err(),
            PROTOCOL_UNSUPPORTED
        );
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "autonomous envelopes are unavailable on the PostgreSQL community runtime"
        );
    }
}
