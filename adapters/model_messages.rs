//! Domain-neutral Messages model-platform adapter (#713).

use sekai_chisei::sekai::model_platform::{
    EVIDENCE_CONTRACT, MODEL_PLATFORM_CONTRACT, ModelCapabilityFixture, ModelFallbackFixture,
    ModelPlatformCertification, ModelProtocolFixtures, ModelReceiptFixture, ModelStreamingFixture,
    ModelUsageFixture, PROFILE_MESSAGES, PROFILE_VERSION,
};
use serde::Deserialize;

pub const ADAPTER_ID: &str = PROFILE_MESSAGES;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessagesDocument {
    pub certification_id: String,
    pub namespace: String,
    pub owner: String,
    pub evidence_id: String,
    pub requested: Vec<String>,
    pub supported: Vec<String>,
    pub events: Vec<String>,
    pub interrupted: bool,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub retry_safety: String,
    pub operation_id: String,
}

pub fn parse(bytes: &[u8]) -> Result<MessagesDocument, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("messages document is invalid: {error}"))
}

pub fn translate_certification(
    document: &MessagesDocument,
) -> Result<ModelPlatformCertification, String> {
    Ok(ModelPlatformCertification {
        contract_version: MODEL_PLATFORM_CONTRACT.into(),
        evidence_contract: EVIDENCE_CONTRACT.into(),
        certification_id: document.certification_id.clone(),
        namespace: document.namespace.clone(),
        owner: document.owner.clone(),
        adapter_id: PROFILE_MESSAGES.into(),
        adapter_version: PROFILE_VERSION.into(),
        evidence_id: document.evidence_id.clone(),
        evidence_version: PROFILE_VERSION.into(),
        protocol: ModelProtocolFixtures {
            capability: ModelCapabilityFixture {
                requested: document.requested.clone(),
                supported: document.supported.clone(),
            },
            streaming: ModelStreamingFixture {
                events: document.events.clone(),
                interrupted: document.interrupted,
            },
            usage: ModelUsageFixture {
                input_tokens: document.input_tokens,
                output_tokens: document.output_tokens,
                usage_units: 1,
                ambiguous: false,
            },
            fallback: ModelFallbackFixture {
                retry_safety: document.retry_safety.clone(),
            },
            receipt: ModelReceiptFixture {
                surface: "model_call".into(),
                kind: "model_called".into(),
                operation_id: document.operation_id.clone(),
                receipt_digest: String::new(),
            },
        },
        capability_digest: String::new(),
        streaming_digest: String::new(),
        usage_digest: String::new(),
        fallback_digest: String::new(),
        receipt_digest: String::new(),
        evidence_digest: String::new(),
        status: "live".into(),
        admitted_by: String::new(),
        admitted_at_ms: 0,
    })
}
