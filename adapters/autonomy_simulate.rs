//! Domain-neutral simulation autonomy adapter (#715).

use sekai_chisei::sekai::autonomous_envelope::{
    AutonomousEnvelope, AutonomousPins, ENVELOPE_CONTRACT, PROFILE_SIMULATE, PROFILE_VERSION,
};
use serde::Deserialize;

pub const ADAPTER_ID: &str = PROFILE_SIMULATE;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulateDocument {
    pub envelope_id: String,
    pub namespace: String,
    pub owner: String,
    pub state_digest: String,
    pub policy_digest: String,
    pub model_digest: String,
    pub prompt_digest: String,
    pub evidence_digest: String,
    pub simulation_digest: String,
    pub budget_digest: String,
    pub lease_digest: String,
}

pub fn parse(bytes: &[u8]) -> Result<SimulateDocument, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("simulate document is invalid: {error}"))
}

pub fn translate_envelope(document: &SimulateDocument) -> Result<AutonomousEnvelope, String> {
    Ok(AutonomousEnvelope {
        contract_version: ENVELOPE_CONTRACT.into(),
        envelope_id: document.envelope_id.clone(),
        namespace: document.namespace.clone(),
        owner: document.owner.clone(),
        adapter_id: PROFILE_SIMULATE.into(),
        adapter_version: PROFILE_VERSION.into(),
        pins: AutonomousPins {
            state_digest: document.state_digest.clone(),
            policy_digest: document.policy_digest.clone(),
            model_digest: document.model_digest.clone(),
            prompt_digest: document.prompt_digest.clone(),
            evidence_digest: document.evidence_digest.clone(),
            simulation_digest: document.simulation_digest.clone(),
            budget_digest: document.budget_digest.clone(),
            lease_digest: document.lease_digest.clone(),
        },
        signer_id: "signer:ops".into(),
        signer_digest: String::new(),
        public_key_hex: String::new(),
        signature_hex: String::new(),
        envelope_digest: String::new(),
        receipt_digest: String::new(),
        receipt_status: "current".into(),
        status: "live".into(),
        predecessor_id: String::new(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    })
}
