//! Connector certification (#710).
//!
//! A signed, revocable verification record after one connector passes
//! authority and failure conformance. Certification is not a runtime grant.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, GITHUB_OBJECT_SYNC_TYPE_DIGEST,
};
use crate::shomei;

pub const CONNECTOR_CONTRACT: &str = "sekai.connector-certification/v1";
pub const REVOCATION_NONE: &str = "";
pub const REVOCATION_REVOKED: &str = "revoked";
pub const CONNECTOR_UNAVAILABLE: &str = "connector certification is unavailable";
pub const PROTOCOL_UNSUPPORTED: &str = "connector certification revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "connector certifications are unavailable on the PostgreSQL community runtime";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCertification {
    pub contract_version: String,
    pub certification_id: String,
    pub namespace: String,
    pub owner: String,
    pub connector_id: String,
    pub connector_version: String,
    pub type_digest: String,
    pub producer_identity: String,
    pub signer_id: String,
    pub signer_digest: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub test_suite_digest: String,
    pub test_result_digest: String,
    pub connector_digest: String,
    pub certification_digest: String,
    #[serde(default)]
    pub revocation: String,
    #[serde(default)]
    pub revocation_reason: String,
    #[serde(default)]
    pub revoked_at_ms: i64,
    #[serde(default)]
    pub predecessor_id: String,
    #[serde(default)]
    pub superseded_by: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
}

#[derive(Serialize)]
struct ConnectorPin<'a> {
    connector_id: &'a str,
    connector_version: &'a str,
    type_digest: &'a str,
    producer_identity: &'a str,
}

#[derive(Serialize)]
struct CertificationPin<'a> {
    contract_version: &'a str,
    certification_id: &'a str,
    namespace: &'a str,
    owner: &'a str,
    connector_id: &'a str,
    predecessor_id: &'a str,
    connector_digest: &'a str,
    signer_id: &'a str,
    signer_digest: &'a str,
    public_key_hex: &'a str,
    test_suite_digest: &'a str,
    test_result_digest: &'a str,
}

pub fn connector_digest_for(certification: &ConnectorCertification) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&ConnectorPin {
            connector_id: &certification.connector_id,
            connector_version: &certification.connector_version,
            type_digest: &certification.type_digest,
            producer_identity: &certification.producer_identity,
        })?
    ))
}

pub fn certification_digest_for(
    certification: &ConnectorCertification,
    connector_digest: &str,
) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&CertificationPin {
            contract_version: &certification.contract_version,
            certification_id: &certification.certification_id,
            namespace: &certification.namespace,
            owner: &certification.owner,
            connector_id: &certification.connector_id,
            predecessor_id: &certification.predecessor_id,
            connector_digest,
            signer_id: &certification.signer_id,
            signer_digest: &certification.signer_digest,
            public_key_hex: &certification.public_key_hex,
            test_suite_digest: &certification.test_suite_digest,
            test_result_digest: &certification.test_result_digest,
        })?
    ))
}

pub fn certify_connector(
    db: &RuntimeDb,
    actor: &str,
    certification: &ConnectorCertification,
    now_ms: i64,
) -> Result<ConnectorCertification, String> {
    required("actor", actor)?;
    require_positive_timestamp("certify", now_ms)?;
    let validated = validate_certification(certification, actor, now_ms)?;
    if let Some(existing) =
        db.get_connector_certification(&validated.namespace, &validated.certification_id)?
    {
        return replay_or_conflict(&existing, &validated);
    }
    let predecessor = load_predecessor(db, &validated)?;
    let committed = if let Some(predecessor) = predecessor {
        db.commit_connector_certifications(&[&predecessor, &validated])
    } else {
        reject_live_collision(db, &validated)?;
        db.commit_connector_certifications(&[&validated])
    };
    match committed {
        Ok(()) => Ok(validated),
        Err(error) if error == CONNECTOR_UNAVAILABLE => {
            let existing = db
                .get_connector_certification(&validated.namespace, &validated.certification_id)?
                .ok_or(CONNECTOR_UNAVAILABLE)?;
            replay_or_conflict(&existing, &validated)
        }
        Err(error) => Err(error),
    }
}

pub fn get_connector(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
) -> Result<ConnectorCertification, String> {
    required("actor", actor)?;
    owned_certification(db, namespace, certification_id, actor)
}

pub fn verify_connector(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
    submitted: &ConnectorCertification,
) -> Result<ConnectorCertification, String> {
    let certified = get_connector(db, actor, namespace, certification_id)?;
    if certified.revocation == REVOCATION_REVOKED || !certified.superseded_by.is_empty() {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    if submitted.namespace != namespace
        || submitted.certification_id != certification_id
        || submitted.connector_id != certified.connector_id
        || submitted.connector_version != certified.connector_version
        || submitted.owner != certified.owner
        || submitted.signer_id != certified.signer_id
        || submitted.public_key_hex != certified.public_key_hex
        || submitted.contract_version != certified.contract_version
        || submitted.producer_identity != certified.producer_identity
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    let connector_digest = connector_digest_for(submitted)?;
    let certification_digest = certification_digest_for(submitted, &connector_digest)?;
    if certified.connector_digest != connector_digest
        || certified.certification_digest != certification_digest
        || certified.type_digest != submitted.type_digest
        || certified.signer_digest != submitted.signer_digest
        || certified.signature_hex != submitted.signature_hex
        || certified.test_suite_digest != submitted.test_suite_digest
        || certified.test_result_digest != submitted.test_result_digest
        || (!submitted.connector_digest.is_empty()
            && submitted.connector_digest != connector_digest)
        || (!submitted.certification_digest.is_empty()
            && submitted.certification_digest != certification_digest)
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    verify_signature(submitted)?;
    verify_signature(&certified)?;
    Ok(certified)
}

pub fn revoke_connector(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
    reason: &str,
    now_ms: i64,
) -> Result<ConnectorCertification, String> {
    required("actor", actor)?;
    required("revocation reason", reason)?;
    require_positive_timestamp("revoke", now_ms)?;
    reject_secret(reason)?;
    let current = owned_certification(db, namespace, certification_id, actor)?;
    if current.revocation == REVOCATION_REVOKED {
        return Ok(current);
    }
    if !current.superseded_by.is_empty() {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    let mut next = current.clone();
    next.revocation = REVOCATION_REVOKED.into();
    next.revocation_reason = reason.into();
    next.revoked_at_ms = now_ms;
    db.cas_connector_certification(&current, &next)?;
    Ok(next)
}

fn validate_certification(
    certification: &ConnectorCertification,
    actor: &str,
    now_ms: i64,
) -> Result<ConnectorCertification, String> {
    if certification.contract_version != CONNECTOR_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    required("certification id", &certification.certification_id)?;
    required("namespace", &certification.namespace)?;
    required("producer identity", &certification.producer_identity)?;
    required("signer id", &certification.signer_id)?;
    reject_secret(&certification.certification_id)?;
    reject_secret(&certification.namespace)?;
    reject_secret(&certification.producer_identity)?;
    reject_secret(&certification.signer_id)?;
    reject_secret(&certification.owner)?;
    reject_secret(&certification.predecessor_id)?;
    if certification.owner != actor {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    if certification.connector_id != ADAPTER_GITHUB_OBJECT_SYNC
        || certification.connector_version != ADAPTER_GITHUB_OBJECT_SYNC_VERSION
        || certification.type_digest != GITHUB_OBJECT_SYNC_TYPE_DIGEST
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    if !digest_token(&certification.signer_digest)
        || !digest_token(&certification.test_suite_digest)
        || !digest_token(&certification.test_result_digest)
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    verify_signature(certification)?;
    if certification.revocation != REVOCATION_NONE
        || !certification.revocation_reason.is_empty()
        || certification.revoked_at_ms != 0
        || !certification.superseded_by.is_empty()
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    if !certification.predecessor_id.is_empty()
        && certification.predecessor_id == certification.certification_id
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    let connector_digest = connector_digest_for(certification)?;
    let certification_digest = certification_digest_for(certification, &connector_digest)?;
    if !certification.connector_digest.is_empty()
        && certification.connector_digest != connector_digest
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    if !certification.certification_digest.is_empty()
        && certification.certification_digest != certification_digest
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    Ok(ConnectorCertification {
        connector_digest,
        certification_digest,
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        revocation: String::new(),
        revocation_reason: String::new(),
        revoked_at_ms: 0,
        superseded_by: String::new(),
        ..certification.clone()
    })
}

fn replay_or_conflict(
    existing: &ConnectorCertification,
    incoming: &ConnectorCertification,
) -> Result<ConnectorCertification, String> {
    if existing.owner != incoming.owner
        || existing.connector_id != incoming.connector_id
        || existing.connector_version != incoming.connector_version
        || existing.type_digest != incoming.type_digest
        || existing.producer_identity != incoming.producer_identity
        || existing.connector_digest != incoming.connector_digest
        || existing.certification_digest != incoming.certification_digest
        || existing.signer_id != incoming.signer_id
        || existing.signer_digest != incoming.signer_digest
        || existing.public_key_hex != incoming.public_key_hex
        || existing.signature_hex != incoming.signature_hex
        || existing.test_suite_digest != incoming.test_suite_digest
        || existing.test_result_digest != incoming.test_result_digest
        || existing.predecessor_id != incoming.predecessor_id
        || existing.revocation != REVOCATION_NONE
        || !existing.superseded_by.is_empty()
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    Ok(existing.clone())
}

fn reject_live_collision(db: &RuntimeDb, incoming: &ConnectorCertification) -> Result<(), String> {
    for existing in db.list_connector_certifications(&incoming.namespace)? {
        if existing.connector_id != incoming.connector_id
            || existing.certification_id == incoming.certification_id
        {
            continue;
        }
        if incoming.predecessor_id.is_empty() {
            return Err(CONNECTOR_UNAVAILABLE.into());
        }
        if existing.superseded_by.is_empty() && existing.revocation != REVOCATION_REVOKED {
            return Err(CONNECTOR_UNAVAILABLE.into());
        }
    }
    Ok(())
}

fn load_predecessor(
    db: &RuntimeDb,
    incoming: &ConnectorCertification,
) -> Result<Option<ConnectorCertification>, String> {
    if incoming.predecessor_id.is_empty() {
        reject_live_collision(db, incoming)?;
        return Ok(None);
    }
    let mut predecessor = owned_certification(
        db,
        &incoming.namespace,
        &incoming.predecessor_id,
        &incoming.owner,
    )?;
    if predecessor.connector_id != incoming.connector_id || !predecessor.superseded_by.is_empty() {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    predecessor.superseded_by = incoming.certification_id.clone();
    Ok(Some(predecessor))
}

fn owned_certification(
    db: &RuntimeDb,
    namespace: &str,
    certification_id: &str,
    actor: &str,
) -> Result<ConnectorCertification, String> {
    required("namespace", namespace)?;
    required("certification id", certification_id)?;
    let certified = db
        .get_connector_certification(namespace, certification_id)?
        .ok_or(CONNECTOR_UNAVAILABLE)?;
    if certified.owner != actor {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    if certified.contract_version != CONNECTOR_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    Ok(certified)
}

fn verify_signature(certification: &ConnectorCertification) -> Result<(), String> {
    let public_key = decode_hex(&certification.public_key_hex, 32)?;
    let signature = decode_hex(&certification.signature_hex, 64)?;
    let expected_signer = format!("sha256:{:x}", Sha256::digest(public_key));
    if certification.signer_digest != expected_signer {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| CONNECTOR_UNAVAILABLE)?;
    let signature = Signature::from_bytes(&signature);
    let digest = certification_digest_for(certification, &connector_digest_for(certification)?)?;
    key.verify(digest.as_bytes(), &signature)
        .map_err(|_| CONNECTOR_UNAVAILABLE.to_string())?;
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, len: usize) -> Result<[u8; N], String> {
    if value.len() != len * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    let mut out = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
            .map_err(|_| CONNECTOR_UNAVAILABLE.to_string())?;
    }
    Ok(out)
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
    {
        return Err(CONNECTOR_UNAVAILABLE.into());
    }
    Ok(())
}

fn digest_token(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
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

    fn db() -> RuntimeDb {
        RuntimeDb::memory()
    }

    fn digest(tag: u8) -> String {
        format!("sha256:{tag:02x}{}", "ab".repeat(31))
    }

    fn certification() -> ConnectorCertification {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut certification = ConnectorCertification {
            contract_version: CONNECTOR_CONTRACT.into(),
            certification_id: "cert:github-1".into(),
            namespace: "ops".into(),
            owner: "reviewer".into(),
            connector_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
            connector_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
            type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
            producer_identity: "connector/github-primary".into(),
            signer_id: "signer:ops".into(),
            signer_digest: format!("sha256:{:x}", Sha256::digest(public_key)),
            public_key_hex: hex(&public_key),
            signature_hex: String::new(),
            test_suite_digest: digest(4),
            test_result_digest: digest(5),
            connector_digest: String::new(),
            certification_digest: String::new(),
            revocation: String::new(),
            revocation_reason: String::new(),
            revoked_at_ms: 0,
            predecessor_id: String::new(),
            superseded_by: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        };
        sign(&mut certification);
        certification
    }

    fn sign(certification: &mut ConnectorCertification) {
        use ed25519_dalek::Signer;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        certification.connector_digest = connector_digest_for(certification).unwrap();
        certification.certification_digest =
            certification_digest_for(certification, &certification.connector_digest).unwrap();
        let signature = signing_key.sign(certification.certification_digest.as_bytes());
        certification.signature_hex = hex(&signature.to_bytes());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn certify(runtime: &RuntimeDb) -> ConnectorCertification {
        certify_connector(runtime, "reviewer", &certification(), 1_000).unwrap()
    }

    #[test]
    fn read_retry_replay_and_verify_pass_for_the_github_connector() {
        let runtime = db();
        let certified = certify(&runtime);
        let viewed = get_connector(&runtime, "reviewer", "ops", "cert:github-1").unwrap();
        assert_eq!(viewed.certification_digest, certified.certification_digest);
        assert_eq!(
            certify_connector(&runtime, "reviewer", &certification(), 2_000).unwrap(),
            certified
        );
        verify_connector(
            &runtime,
            "reviewer",
            "ops",
            "cert:github-1",
            &certification(),
        )
        .unwrap();
    }

    #[test]
    fn deny_secret_package_change_and_revocation_fail_closed() {
        let runtime = db();
        certify(&runtime);
        let mut hidden = serde_json::to_value(certification()).unwrap();
        hidden
            .as_object_mut()
            .unwrap()
            .insert("token".into(), serde_json::json!("sk-live"));
        assert!(serde_json::from_value::<ConnectorCertification>(hidden).is_err());
        let mut secret_producer = certification();
        secret_producer.certification_id = "cert:secret".into();
        secret_producer.producer_identity = "ghp_exampleleak".into();
        sign(&mut secret_producer);
        assert_eq!(
            certify_connector(&runtime, "reviewer", &secret_producer, 1_500).unwrap_err(),
            CONNECTOR_UNAVAILABLE
        );
        let mut foreign = certification();
        foreign.certification_id = "cert:foreign".into();
        foreign.owner = "intruder".into();
        sign(&mut foreign);
        assert_eq!(
            certify_connector(&runtime, "reviewer", &foreign, 1_600).unwrap_err(),
            CONNECTOR_UNAVAILABLE
        );
        assert_eq!(
            get_connector(&runtime, "intruder", "ops", "cert:github-1").unwrap_err(),
            CONNECTOR_UNAVAILABLE
        );
        let mut changed = certification();
        changed.test_result_digest = digest(9);
        assert_eq!(
            verify_connector(&runtime, "reviewer", "ops", "cert:github-1", &changed).unwrap_err(),
            CONNECTOR_UNAVAILABLE
        );
        let mut next = certification();
        next.certification_id = "cert:github-2".into();
        next.predecessor_id = "cert:github-1".into();
        next.producer_identity = "connector/github-replica".into();
        sign(&mut next);
        let recertified = certify_connector(&runtime, "reviewer", &next, 3_000).unwrap();
        let previous = get_connector(&runtime, "reviewer", "ops", "cert:github-1").unwrap();
        assert_eq!(previous.superseded_by, "cert:github-2");
        assert_eq!(
            verify_connector(
                &runtime,
                "reviewer",
                "ops",
                "cert:github-1",
                &certification()
            )
            .unwrap_err(),
            CONNECTOR_UNAVAILABLE
        );
        verify_connector(&runtime, "reviewer", "ops", "cert:github-2", &recertified).unwrap();
        let revoked = revoke_connector(
            &runtime,
            "reviewer",
            "ops",
            "cert:github-2",
            "signer rotated",
            4_000,
        )
        .unwrap();
        assert_eq!(revoked.revocation, REVOCATION_REVOKED);
        assert_eq!(
            verify_connector(&runtime, "reviewer", "ops", "cert:github-2", &recertified)
                .unwrap_err(),
            CONNECTOR_UNAVAILABLE
        );
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "connector certifications are unavailable on the PostgreSQL community runtime"
        );
    }
}
