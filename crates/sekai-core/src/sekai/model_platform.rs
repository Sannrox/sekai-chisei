//! Model-platform adapter certification (#713).
//!
//! Require providers to pass capability, streaming, usage, fallback, and
//! receipt protocol fixtures. Certification pins
//! `sekai.evaluation-evidence/v1` and is not a runtime grant.

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::object_sync::contains_secret_like_text;
use crate::shomei;

pub const MODEL_PLATFORM_CONTRACT: &str = "sekai.model-platform-certification/v1";
pub const EVIDENCE_CONTRACT: &str = "sekai.evaluation-evidence/v1";
pub const PROFILE_RESPONSES: &str = "adapter.model.responses";
pub const PROFILE_MESSAGES: &str = "adapter.model.messages";
pub const PROFILE_VERSION: &str = "1.0.0";
pub const STATUS_LIVE: &str = "live";
pub const STATUS_REVOKED: &str = "revoked";
pub const MODEL_UNAVAILABLE: &str = "model platform certification is unavailable";
pub const PROTOCOL_UNSUPPORTED: &str = "model platform certification revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "model platform certifications are unavailable on the PostgreSQL community runtime";
const REQUIRED_CAPABILITIES: &[&str] = &["streaming", "usage", "fallback", "receipt"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilityFixture {
    pub requested: Vec<String>,
    pub supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelStreamingFixture {
    pub events: Vec<String>,
    pub interrupted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelUsageFixture {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub usage_units: u64,
    #[serde(default)]
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelFallbackFixture {
    pub retry_safety: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelReceiptFixture {
    pub surface: String,
    pub kind: String,
    pub operation_id: String,
    #[serde(default)]
    pub receipt_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProtocolFixtures {
    pub capability: ModelCapabilityFixture,
    pub streaming: ModelStreamingFixture,
    pub usage: ModelUsageFixture,
    pub fallback: ModelFallbackFixture,
    pub receipt: ModelReceiptFixture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPlatformCertification {
    pub contract_version: String,
    pub evidence_contract: String,
    pub certification_id: String,
    pub namespace: String,
    pub owner: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub evidence_id: String,
    pub evidence_version: String,
    pub protocol: ModelProtocolFixtures,
    #[serde(default)]
    pub capability_digest: String,
    #[serde(default)]
    pub streaming_digest: String,
    #[serde(default)]
    pub usage_digest: String,
    #[serde(default)]
    pub fallback_digest: String,
    #[serde(default)]
    pub receipt_digest: String,
    #[serde(default)]
    pub evidence_digest: String,
    pub status: String,
    #[serde(default)]
    pub admitted_by: String,
    #[serde(default)]
    pub admitted_at_ms: i64,
}

#[derive(Serialize)]
struct EvidencePin<'a> {
    contract_version: &'a str,
    evidence_contract: &'a str,
    evidence_id: &'a str,
    evidence_version: &'a str,
    owner: &'a str,
    adapter_id: &'a str,
    adapter_version: &'a str,
    namespace: &'a str,
    certification_id: &'a str,
    capability_digest: &'a str,
    streaming_digest: &'a str,
    usage_digest: &'a str,
    fallback_digest: &'a str,
    receipt_digest: &'a str,
    status: &'a str,
}

pub fn evidence_digest_for(certification: &ModelPlatformCertification) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&EvidencePin {
            contract_version: &certification.contract_version,
            evidence_contract: &certification.evidence_contract,
            evidence_id: &certification.evidence_id,
            evidence_version: &certification.evidence_version,
            owner: &certification.owner,
            adapter_id: &certification.adapter_id,
            adapter_version: &certification.adapter_version,
            namespace: &certification.namespace,
            certification_id: &certification.certification_id,
            capability_digest: &certification.capability_digest,
            streaming_digest: &certification.streaming_digest,
            usage_digest: &certification.usage_digest,
            fallback_digest: &certification.fallback_digest,
            receipt_digest: &certification.receipt_digest,
            status: &certification.status,
        })?
    ))
}

pub fn certify_model_platform(
    db: &RuntimeDb,
    actor: &str,
    certification: &ModelPlatformCertification,
    now_ms: i64,
) -> Result<ModelPlatformCertification, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("certify", now_ms)?;
    if let Some(existing) = db.get_model_platform_certification(
        &certification.namespace,
        &certification.certification_id,
    )? {
        let validated = validate_certification(certification, actor, now_ms)?;
        return replay_existing(existing, &validated, actor);
    }
    let validated = validate_certification(certification, actor, now_ms)?;
    match db.put_model_platform_certification(&validated) {
        Ok(()) => Ok(validated),
        Err(error) if error == MODEL_UNAVAILABLE => {
            let existing = db
                .get_model_platform_certification(
                    &validated.namespace,
                    &validated.certification_id,
                )?
                .ok_or(MODEL_UNAVAILABLE)?;
            replay_existing(existing, &validated, actor)
        }
        Err(error) => Err(error),
    }
}

pub fn get_model_platform(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
) -> Result<ModelPlatformCertification, String> {
    let certification = owned_certification(db, namespace, certification_id, actor)?;
    if certification.status == STATUS_REVOKED {
        return Err(MODEL_UNAVAILABLE.into());
    }
    Ok(certification)
}

pub fn verify_model_platform(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
    submitted: &ModelPlatformCertification,
) -> Result<ModelPlatformCertification, String> {
    let certified = owned_certification(db, namespace, certification_id, actor)?;
    if certified.status == STATUS_REVOKED {
        return Err(MODEL_UNAVAILABLE.into());
    }
    let validated = validate_certification(submitted, actor, certified.admitted_at_ms.max(1))?;
    if validated.namespace != certified.namespace
        || validated.certification_id != certified.certification_id
        || validated.evidence_digest != certified.evidence_digest
        || validated.adapter_id != certified.adapter_id
        || validated.owner != certified.owner
    {
        return Err(MODEL_UNAVAILABLE.into());
    }
    Ok(certified)
}

pub fn revoke_model_platform(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
    now_ms: i64,
) -> Result<ModelPlatformCertification, String> {
    required("actor", actor)?;
    reject_secret(actor)?;
    require_positive_timestamp("revoke", now_ms)?;
    let current = owned_certification(db, namespace, certification_id, actor)?;
    if current.status == STATUS_REVOKED {
        return Ok(current);
    }
    let mut next = current.clone();
    next.status = STATUS_REVOKED.into();
    next.admitted_at_ms = now_ms;
    next.evidence_digest = evidence_digest_for(&next)?;
    db.cas_model_platform_certification(&current, &next)?;
    Ok(next)
}

fn validate_certification(
    certification: &ModelPlatformCertification,
    actor: &str,
    now_ms: i64,
) -> Result<ModelPlatformCertification, String> {
    if certification.contract_version != MODEL_PLATFORM_CONTRACT
        || certification.evidence_contract != EVIDENCE_CONTRACT
    {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    if certification.adapter_version != PROFILE_VERSION
        || (certification.adapter_id != PROFILE_RESPONSES
            && certification.adapter_id != PROFILE_MESSAGES)
    {
        return Err(MODEL_UNAVAILABLE.into());
    }
    required("certification id", &certification.certification_id)?;
    required("namespace", &certification.namespace)?;
    required("owner", &certification.owner)?;
    required("evidence id", &certification.evidence_id)?;
    required("evidence version", &certification.evidence_version)?;
    reject_secret(&certification.certification_id)?;
    reject_secret(&certification.namespace)?;
    reject_secret(&certification.owner)?;
    reject_secret(&certification.evidence_id)?;
    if certification.owner != actor
        || has_whitespace(&certification.namespace)
        || has_whitespace(&certification.certification_id)
        || certification.evidence_version != PROFILE_VERSION
    {
        return Err(MODEL_UNAVAILABLE.into());
    }
    if certification.status != STATUS_LIVE {
        return Err(MODEL_UNAVAILABLE.into());
    }
    validate_protocol(&certification.adapter_id, &certification.protocol)?;
    let mut next = certification.clone();
    next.capability_digest = member_digest("capability", &certification.protocol.capability)?;
    next.streaming_digest = member_digest("streaming", &certification.protocol.streaming)?;
    next.usage_digest = member_digest("usage", &certification.protocol.usage)?;
    next.fallback_digest = member_digest("fallback", &certification.protocol.fallback)?;
    required("operation id", &certification.protocol.receipt.operation_id)?;
    reject_secret(&certification.protocol.receipt.operation_id)?;
    if has_whitespace(&certification.protocol.receipt.operation_id) {
        return Err(MODEL_UNAVAILABLE.into());
    }
    let receipt_digest = member_digest(
        "receipt",
        &(
            certification.protocol.receipt.surface.as_str(),
            certification.protocol.receipt.kind.as_str(),
            certification.protocol.receipt.operation_id.as_str(),
        ),
    )?;
    if !certification.protocol.receipt.receipt_digest.is_empty()
        && certification.protocol.receipt.receipt_digest != receipt_digest
    {
        return Err(MODEL_UNAVAILABLE.into());
    }
    next.protocol.receipt.receipt_digest = receipt_digest.clone();
    next.receipt_digest = receipt_digest;
    next.admitted_by = actor.into();
    next.admitted_at_ms = now_ms;
    next.status = STATUS_LIVE.into();
    let digest = evidence_digest_for(&next)?;
    if !certification.evidence_digest.is_empty() && certification.evidence_digest != digest {
        return Err(MODEL_UNAVAILABLE.into());
    }
    next.evidence_digest = digest;
    Ok(next)
}

fn validate_protocol(adapter_id: &str, protocol: &ModelProtocolFixtures) -> Result<(), String> {
    if protocol.capability.supported.is_empty() {
        return Err(MODEL_UNAVAILABLE.into());
    }
    for supported in &protocol.capability.supported {
        required("supported capability", supported)?;
        reject_secret(supported)?;
    }
    for required_capability in REQUIRED_CAPABILITIES {
        if !protocol
            .capability
            .supported
            .iter()
            .any(|value| value == required_capability)
        {
            return Err(MODEL_UNAVAILABLE.into());
        }
    }
    for requested in &protocol.capability.requested {
        required("requested capability", requested)?;
        reject_secret(requested)?;
        if !protocol
            .capability
            .supported
            .iter()
            .any(|value| value == requested)
        {
            return Err(MODEL_UNAVAILABLE.into());
        }
    }
    if protocol.streaming.events.is_empty() {
        return Err(MODEL_UNAVAILABLE.into());
    }
    let (delta, allowed_events, terminal): (&str, &[&str], &str) =
        if adapter_id == PROFILE_RESPONSES {
            (
                "response.output_text.delta",
                &[
                    "response.output_text.delta",
                    "response.completed",
                    "response.failed",
                ],
                if protocol.streaming.interrupted {
                    "response.failed"
                } else {
                    "response.completed"
                },
            )
        } else {
            (
                "content_block_delta",
                &["content_block_delta", "message_stop", "error"],
                if protocol.streaming.interrupted {
                    "error"
                } else {
                    "message_stop"
                },
            )
        };
    let terminals = if adapter_id == PROFILE_RESPONSES {
        ["response.completed", "response.failed"]
    } else {
        ["message_stop", "error"]
    };
    for event in &protocol.streaming.events {
        required("streaming event", event)?;
        reject_secret(event)?;
        if !allowed_events.contains(&event.as_str()) {
            return Err(MODEL_UNAVAILABLE.into());
        }
    }
    if !protocol.streaming.events.iter().any(|event| event == delta)
        || protocol
            .streaming
            .events
            .iter()
            .filter(|event| terminals.contains(&event.as_str()))
            .count()
            != 1
        || protocol.streaming.events.last().map(String::as_str) != Some(terminal)
        || protocol.streaming.events[..protocol.streaming.events.len() - 1]
            .iter()
            .any(|event| terminals.contains(&event.as_str()))
    {
        return Err(MODEL_UNAVAILABLE.into());
    }
    if protocol.usage.ambiguous
        || protocol.usage.usage_units != 1
        || protocol.usage.input_tokens == 0
        || protocol.usage.output_tokens == 0
    {
        return Err(MODEL_UNAVAILABLE.into());
    }
    if protocol.fallback.retry_safety != "safe" && protocol.fallback.retry_safety != "ambiguous" {
        return Err(MODEL_UNAVAILABLE.into());
    }
    if protocol.receipt.surface != "model_call" || protocol.receipt.kind != "model_called" {
        return Err(MODEL_UNAVAILABLE.into());
    }
    if protocol.streaming.interrupted && protocol.fallback.retry_safety != "ambiguous" {
        return Err(MODEL_UNAVAILABLE.into());
    }
    Ok(())
}

fn member_digest<T: Serialize>(label: &str, value: &T) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&(label, value))?
    ))
}

fn owned_certification(
    db: &RuntimeDb,
    namespace: &str,
    certification_id: &str,
    actor: &str,
) -> Result<ModelPlatformCertification, String> {
    required("namespace", namespace)?;
    required("certification id", certification_id)?;
    required("actor", actor)?;
    reject_secret(namespace)?;
    reject_secret(certification_id)?;
    reject_secret(actor)?;
    let certification = db
        .get_model_platform_certification(namespace, certification_id)?
        .ok_or(MODEL_UNAVAILABLE)?;
    if certification.owner != actor {
        return Err(MODEL_UNAVAILABLE.into());
    }
    if certification.contract_version != MODEL_PLATFORM_CONTRACT
        || certification.evidence_contract != EVIDENCE_CONTRACT
    {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    Ok(certification)
}

fn replay_existing(
    existing: ModelPlatformCertification,
    incoming: &ModelPlatformCertification,
    actor: &str,
) -> Result<ModelPlatformCertification, String> {
    if existing.status == STATUS_REVOKED || existing.owner != actor {
        return Err(MODEL_UNAVAILABLE.into());
    }
    if existing.evidence_digest != incoming.evidence_digest {
        return Err(MODEL_UNAVAILABLE.into());
    }
    Ok(existing)
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
        return Err(MODEL_UNAVAILABLE.into());
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

    fn protocol(adapter: &str, certification_id: &str) -> ModelProtocolFixtures {
        let events = if adapter == PROFILE_RESPONSES {
            vec![
                "response.output_text.delta".into(),
                "response.completed".into(),
            ]
        } else {
            vec!["content_block_delta".into(), "message_stop".into()]
        };
        ModelProtocolFixtures {
            capability: ModelCapabilityFixture {
                requested: vec!["streaming".into()],
                supported: REQUIRED_CAPABILITIES
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            },
            streaming: ModelStreamingFixture {
                events,
                interrupted: false,
            },
            usage: ModelUsageFixture {
                input_tokens: 3,
                output_tokens: 2,
                usage_units: 1,
                ambiguous: false,
            },
            fallback: ModelFallbackFixture {
                retry_safety: "safe".into(),
            },
            receipt: ModelReceiptFixture {
                surface: "model_call".into(),
                kind: "model_called".into(),
                operation_id: format!("op:{certification_id}"),
                receipt_digest: String::new(),
            },
        }
    }

    fn certification(adapter: &str, certification_id: &str) -> ModelPlatformCertification {
        ModelPlatformCertification {
            contract_version: MODEL_PLATFORM_CONTRACT.into(),
            evidence_contract: EVIDENCE_CONTRACT.into(),
            certification_id: certification_id.into(),
            namespace: "ops".into(),
            owner: "integrator".into(),
            adapter_id: adapter.into(),
            adapter_version: PROFILE_VERSION.into(),
            evidence_id: format!("ev:{certification_id}"),
            evidence_version: PROFILE_VERSION.into(),
            protocol: protocol(adapter, certification_id),
            capability_digest: String::new(),
            streaming_digest: String::new(),
            usage_digest: String::new(),
            fallback_digest: String::new(),
            receipt_digest: String::new(),
            evidence_digest: String::new(),
            status: STATUS_LIVE.into(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        }
    }

    fn lifecycle(adapter: &str, certification_id: &str) {
        let runtime = RuntimeDb::memory();
        let certified = certify_model_platform(
            &runtime,
            "integrator",
            &certification(adapter, certification_id),
            1_000,
        )
        .unwrap();
        assert_eq!(certified.adapter_id, adapter);
        assert!(!certified.evidence_digest.is_empty());
        assert_eq!(
            certify_model_platform(&runtime, "integrator", &certified, 1_100)
                .unwrap()
                .evidence_digest,
            certified.evidence_digest
        );
        assert_eq!(
            verify_model_platform(&runtime, "integrator", "ops", certification_id, &certified)
                .unwrap()
                .evidence_digest,
            certified.evidence_digest
        );
        let mut unsupported = certification(adapter, "mp:bad-cap");
        unsupported.protocol.capability.requested = vec!["batch".into()];
        assert_eq!(
            certify_model_platform(&runtime, "integrator", &unsupported, 2_000).unwrap_err(),
            MODEL_UNAVAILABLE
        );
        let mut ambiguous = certification(adapter, "mp:bad-usage");
        ambiguous.protocol.usage.ambiguous = true;
        assert_eq!(
            certify_model_platform(&runtime, "integrator", &ambiguous, 2_100).unwrap_err(),
            MODEL_UNAVAILABLE
        );
        assert_eq!(
            get_model_platform(&runtime, "intruder", "ops", certification_id).unwrap_err(),
            MODEL_UNAVAILABLE
        );
        let mut garbage = certification(adapter, "mp:bad-stream");
        garbage.protocol.streaming.events = vec!["garbage".into()];
        assert_eq!(
            certify_model_platform(&runtime, "integrator", &garbage, 2_200).unwrap_err(),
            MODEL_UNAVAILABLE
        );
        let revoked =
            revoke_model_platform(&runtime, "integrator", "ops", certification_id, 3_000).unwrap();
        assert_eq!(revoked.status, STATUS_REVOKED);
        assert_eq!(
            get_model_platform(&runtime, "integrator", "ops", certification_id).unwrap_err(),
            MODEL_UNAVAILABLE
        );
        assert_eq!(
            verify_model_platform(&runtime, "integrator", "ops", certification_id, &certified)
                .unwrap_err(),
            MODEL_UNAVAILABLE
        );
    }

    #[test]
    fn two_adapters_pass_protocol_fixtures_and_fail_closed() {
        lifecycle(PROFILE_RESPONSES, "mp:responses");
        lifecycle(PROFILE_MESSAGES, "mp:messages");
    }

    #[test]
    fn hidden_fields_unknown_versions_and_postgres_fail_closed() {
        let mut hidden = serde_json::to_value(certification(PROFILE_RESPONSES, "mp:h")).unwrap();
        hidden
            .as_object_mut()
            .unwrap()
            .insert("token".into(), serde_json::json!("sk-live"));
        assert!(serde_json::from_value::<ModelPlatformCertification>(hidden).is_err());
        let runtime = RuntimeDb::memory();
        let mut unknown = certification(PROFILE_RESPONSES, "mp:v0");
        unknown.contract_version = "sekai.model-platform-certification/v0".into();
        assert_eq!(
            certify_model_platform(&runtime, "integrator", &unknown, 1_000).unwrap_err(),
            PROTOCOL_UNSUPPORTED
        );
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "model platform certifications are unavailable on the PostgreSQL community runtime"
        );
    }
}
