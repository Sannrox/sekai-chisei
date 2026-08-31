//! Capability-package certification (#707).
//!
//! A certification binds signer, manifest, compatibility, tests, and
//! revocation to one package digest. Certification is not a runtime grant.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::db::runtime_db::RuntimeDb;
use crate::shomei;

pub const PACKAGE_CONTRACT: &str = "sekai.capability-package-certification/v1";
pub const MEMBER_CHANGE_SET: &str = "change_set";
pub const MEMBER_ACTION_TYPE: &str = "action_type";
pub const MEMBER_ONTOLOGY: &str = "ontology";
pub const MEMBER_EVALUATION: &str = "evaluation";
pub const REVOCATION_NONE: &str = "";
pub const REVOCATION_REVOKED: &str = "revoked";
pub const PACKAGE_UNAVAILABLE: &str = "capability package is unavailable";
pub const PROTOCOL_UNSUPPORTED: &str = "capability package revision is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "capability packages are unavailable on the PostgreSQL community runtime";
const MAX_MEMBERS: usize = 32;
const MAX_COMPAT: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMember {
    pub kind: String,
    pub member_id: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPackageCertification {
    pub contract_version: String,
    pub certification_id: String,
    pub namespace: String,
    pub owner: String,
    pub package_id: String,
    pub package_digest: String,
    pub signer_id: String,
    pub signer_digest: String,
    pub members: Vec<PackageMember>,
    pub compatibility: Vec<String>,
    pub test_suite_digest: String,
    pub test_result_digest: String,
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
    pub certification_digest: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
}

#[derive(Serialize)]
struct ManifestPin<'a> {
    package_id: &'a str,
    members: &'a [PackageMember],
    compatibility: &'a [String],
}

#[derive(Serialize)]
struct CertificationPin<'a> {
    contract_version: &'a str,
    certification_id: &'a str,
    namespace: &'a str,
    owner: &'a str,
    package_id: &'a str,
    predecessor_id: &'a str,
    package_digest: &'a str,
    signer_id: &'a str,
    signer_digest: &'a str,
    test_suite_digest: &'a str,
    test_result_digest: &'a str,
}

pub fn package_digest_for(
    package_id: &str,
    members: &[PackageMember],
    compatibility: &[String],
) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&ManifestPin {
            package_id,
            members,
            compatibility,
        })?
    ))
}

pub fn certification_digest_for(
    certification: &CapabilityPackageCertification,
    package_digest: &str,
) -> Result<String, String> {
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&CertificationPin {
            contract_version: &certification.contract_version,
            certification_id: &certification.certification_id,
            namespace: &certification.namespace,
            owner: &certification.owner,
            package_id: &certification.package_id,
            predecessor_id: &certification.predecessor_id,
            package_digest,
            signer_id: &certification.signer_id,
            signer_digest: &certification.signer_digest,
            test_suite_digest: &certification.test_suite_digest,
            test_result_digest: &certification.test_result_digest,
        })?
    ))
}

pub fn certify_package(
    db: &RuntimeDb,
    actor: &str,
    certification: &CapabilityPackageCertification,
    now_ms: i64,
) -> Result<CapabilityPackageCertification, String> {
    required("actor", actor)?;
    require_positive_timestamp("certify", now_ms)?;
    let validated = validate_certification(certification, actor, now_ms)?;
    if let Some(existing) =
        db.get_capability_package(&validated.namespace, &validated.certification_id)?
    {
        return replay_or_conflict(&existing, &validated);
    }
    let predecessor = load_predecessor(db, &validated)?;
    let committed = if let Some(predecessor) = predecessor {
        db.commit_capability_packages(&[&predecessor, &validated])
    } else {
        reject_live_package_collision(db, &validated)?;
        db.commit_capability_packages(&[&validated])
    };
    match committed {
        Ok(()) => Ok(validated),
        Err(error) if error == PACKAGE_UNAVAILABLE => {
            let existing = db
                .get_capability_package(&validated.namespace, &validated.certification_id)?
                .ok_or(PACKAGE_UNAVAILABLE)?;
            replay_or_conflict(&existing, &validated)
        }
        Err(error) => Err(error),
    }
}

pub fn get_package(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
) -> Result<CapabilityPackageCertification, String> {
    required("actor", actor)?;
    owned_package(db, namespace, certification_id, actor)
}

pub fn verify_package(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
    submitted: &CapabilityPackageCertification,
) -> Result<CapabilityPackageCertification, String> {
    let package = get_package(db, actor, namespace, certification_id)?;
    if package.revocation == REVOCATION_REVOKED || !package.superseded_by.is_empty() {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if submitted.namespace != namespace
        || submitted.certification_id != certification_id
        || submitted.package_id != package.package_id
        || submitted.signer_id != package.signer_id
        || submitted.owner != package.owner
        || submitted.contract_version != package.contract_version
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    let package_digest = package_digest_for(
        &submitted.package_id,
        &submitted.members,
        &submitted.compatibility,
    )?;
    let certification_digest = certification_digest_for(submitted, &package_digest)?;
    if package.package_digest != package_digest
        || package.certification_digest != certification_digest
        || package.signer_digest != submitted.signer_digest
        || package.test_suite_digest != submitted.test_suite_digest
        || package.test_result_digest != submitted.test_result_digest
        || package.members != submitted.members
        || package.compatibility != submitted.compatibility
        || (!submitted.package_digest.is_empty() && submitted.package_digest != package_digest)
        || (!submitted.certification_digest.is_empty()
            && submitted.certification_digest != certification_digest)
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(package)
}

pub fn revoke_package(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    certification_id: &str,
    reason: &str,
    now_ms: i64,
) -> Result<CapabilityPackageCertification, String> {
    required("actor", actor)?;
    required("revocation reason", reason)?;
    require_positive_timestamp("revoke", now_ms)?;
    let current = owned_package(db, namespace, certification_id, actor)?;
    if current.revocation == REVOCATION_REVOKED {
        return Ok(current);
    }
    if !current.superseded_by.is_empty() {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    let mut next = current.clone();
    next.revocation = REVOCATION_REVOKED.into();
    next.revocation_reason = reason.into();
    next.revoked_at_ms = now_ms;
    db.cas_capability_package(&current, &next)?;
    Ok(next)
}

fn validate_certification(
    certification: &CapabilityPackageCertification,
    actor: &str,
    now_ms: i64,
) -> Result<CapabilityPackageCertification, String> {
    if certification.contract_version != PACKAGE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    required("certification id", &certification.certification_id)?;
    required("namespace", &certification.namespace)?;
    required("package id", &certification.package_id)?;
    required("signer id", &certification.signer_id)?;
    if certification.owner != actor {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if certification.members.is_empty() || certification.members.len() > MAX_MEMBERS {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if certification.compatibility.is_empty() || certification.compatibility.len() > MAX_COMPAT {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    let mut seen_members = BTreeSet::new();
    for member in &certification.members {
        required("member id", &member.member_id)?;
        if !supported_member_kind(&member.kind) || !digest_token(&member.digest) {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
        if !seen_members.insert((member.kind.as_str(), member.member_id.as_str())) {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
    }
    let mut seen_compat = BTreeSet::new();
    for token in &certification.compatibility {
        required("compatibility", token)?;
        if !seen_compat.insert(token.as_str()) {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
    }
    if !digest_token(&certification.signer_digest)
        || !digest_token(&certification.test_suite_digest)
        || !digest_token(&certification.test_result_digest)
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if certification.revocation != REVOCATION_NONE {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if !certification.revocation_reason.is_empty()
        || certification.revoked_at_ms != 0
        || !certification.superseded_by.is_empty()
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if !certification.predecessor_id.is_empty()
        && certification.predecessor_id == certification.certification_id
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    let package_digest = package_digest_for(
        &certification.package_id,
        &certification.members,
        &certification.compatibility,
    )?;
    let certification_digest = certification_digest_for(certification, &package_digest)?;
    if !certification.package_digest.is_empty() && certification.package_digest != package_digest {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if !certification.certification_digest.is_empty()
        && certification.certification_digest != certification_digest
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(CapabilityPackageCertification {
        package_digest,
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
    existing: &CapabilityPackageCertification,
    incoming: &CapabilityPackageCertification,
) -> Result<CapabilityPackageCertification, String> {
    if existing.owner != incoming.owner
        || existing.package_id != incoming.package_id
        || existing.package_digest != incoming.package_digest
        || existing.certification_digest != incoming.certification_digest
        || existing.signer_id != incoming.signer_id
        || existing.signer_digest != incoming.signer_digest
        || existing.members != incoming.members
        || existing.compatibility != incoming.compatibility
        || existing.test_suite_digest != incoming.test_suite_digest
        || existing.test_result_digest != incoming.test_result_digest
        || existing.predecessor_id != incoming.predecessor_id
        || existing.revocation != REVOCATION_NONE
        || !existing.superseded_by.is_empty()
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(existing.clone())
}

fn reject_live_package_collision(
    db: &RuntimeDb,
    incoming: &CapabilityPackageCertification,
) -> Result<(), String> {
    for existing in db.list_capability_packages(&incoming.namespace)? {
        if existing.package_id != incoming.package_id
            || existing.certification_id == incoming.certification_id
        {
            continue;
        }
        if incoming.predecessor_id.is_empty() {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
        if existing.superseded_by.is_empty() && existing.revocation != REVOCATION_REVOKED {
            return Err(PACKAGE_UNAVAILABLE.into());
        }
    }
    Ok(())
}

fn load_predecessor(
    db: &RuntimeDb,
    incoming: &CapabilityPackageCertification,
) -> Result<Option<CapabilityPackageCertification>, String> {
    if incoming.predecessor_id.is_empty() {
        reject_live_package_collision(db, incoming)?;
        return Ok(None);
    }
    let mut predecessor = owned_package(
        db,
        &incoming.namespace,
        &incoming.predecessor_id,
        &incoming.owner,
    )?;
    if predecessor.package_id != incoming.package_id || !predecessor.superseded_by.is_empty() {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    predecessor.superseded_by = incoming.certification_id.clone();
    Ok(Some(predecessor))
}

fn owned_package(
    db: &RuntimeDb,
    namespace: &str,
    certification_id: &str,
    actor: &str,
) -> Result<CapabilityPackageCertification, String> {
    required("namespace", namespace)?;
    required("certification id", certification_id)?;
    let package = db
        .get_capability_package(namespace, certification_id)?
        .ok_or(PACKAGE_UNAVAILABLE)?;
    if package.owner != actor {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if package.contract_version != PACKAGE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    Ok(package)
}

fn supported_member_kind(kind: &str) -> bool {
    matches!(
        kind,
        MEMBER_CHANGE_SET | MEMBER_ACTION_TYPE | MEMBER_ONTOLOGY | MEMBER_EVALUATION
    )
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

    fn members() -> Vec<PackageMember> {
        vec![
            PackageMember {
                kind: MEMBER_CHANGE_SET.into(),
                member_id: "cs:intake".into(),
                digest: digest(1),
            },
            PackageMember {
                kind: MEMBER_ACTION_TYPE.into(),
                member_id: "act:review".into(),
                digest: digest(2),
            },
        ]
    }

    fn certification() -> CapabilityPackageCertification {
        let members = members();
        let compatibility = vec!["sekai.governed-action/v1".into()];
        let package_digest = package_digest_for("pkg:intake", &members, &compatibility).unwrap();
        let mut certification = CapabilityPackageCertification {
            contract_version: PACKAGE_CONTRACT.into(),
            certification_id: "cert:1".into(),
            namespace: "ops".into(),
            owner: "reviewer".into(),
            package_id: "pkg:intake".into(),
            package_digest: package_digest.clone(),
            signer_id: "signer:ops".into(),
            signer_digest: digest(3),
            members,
            compatibility,
            test_suite_digest: digest(4),
            test_result_digest: digest(5),
            revocation: String::new(),
            revocation_reason: String::new(),
            revoked_at_ms: 0,
            predecessor_id: String::new(),
            superseded_by: String::new(),
            certification_digest: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        };
        certification.certification_digest =
            certification_digest_for(&certification, &package_digest).unwrap();
        certification
    }

    fn certify(runtime: &RuntimeDb) -> CapabilityPackageCertification {
        certify_package(runtime, "reviewer", &certification(), 1_000).unwrap()
    }

    fn evidence(cert: &CapabilityPackageCertification) -> CapabilityPackageCertification {
        cert.clone()
    }

    #[test]
    fn independent_verification_reproduces_certification() {
        let runtime = db();
        let certified = certify(&runtime);
        let viewed = get_package(&runtime, "reviewer", "ops", "cert:1").unwrap();
        assert_eq!(viewed.certification_digest, certified.certification_digest);
        assert!(viewed.revocation.is_empty());
        let verified =
            verify_package(&runtime, "reviewer", "ops", "cert:1", &evidence(&certified)).unwrap();
        assert_eq!(
            verified.certification_digest,
            certified.certification_digest
        );
        assert_eq!(
            certify_package(&runtime, "reviewer", &certification(), 2_000).unwrap(),
            certified
        );
    }

    #[test]
    fn content_or_dependency_change_invalidates_certification() {
        let runtime = db();
        let certified = certify(&runtime);
        let mut changed = certified.members.clone();
        changed[0].digest = digest(9);
        let mut changed_evidence = evidence(&certified);
        changed_evidence.members = changed;
        assert_eq!(
            verify_package(&runtime, "reviewer", "ops", "cert:1", &changed_evidence).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut next = certification();
        next.certification_id = "cert:2".into();
        next.predecessor_id = "cert:1".into();
        next.members[1].digest = digest(8);
        next.package_digest.clear();
        next.certification_digest.clear();
        let recertified = certify_package(&runtime, "reviewer", &next, 3_000).unwrap();
        let previous = get_package(&runtime, "reviewer", "ops", "cert:1").unwrap();
        assert_eq!(previous.superseded_by, "cert:2");
        assert_ne!(
            previous.certification_digest,
            recertified.certification_digest
        );
        assert_eq!(
            verify_package(&runtime, "reviewer", "ops", "cert:1", &evidence(&certified))
                .unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        verify_package(
            &runtime,
            "reviewer",
            "ops",
            "cert:2",
            &evidence(&recertified),
        )
        .unwrap();
    }

    #[test]
    fn stale_revoked_unknown_and_foreign_content_fail_closed() {
        let runtime = db();
        certify(&runtime);
        let mut unknown = serde_json::to_value(certification()).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("hidden".into(), serde_json::json!("nope"));
        assert!(serde_json::from_value::<CapabilityPackageCertification>(unknown).is_err());
        let mut expanding = certification();
        expanding.members.push(PackageMember {
            kind: "plugin".into(),
            member_id: "plug:1".into(),
            digest: digest(7),
        });
        expanding.package_digest.clear();
        expanding.certification_digest.clear();
        expanding.certification_id = "cert:x".into();
        assert_eq!(
            certify_package(&runtime, "reviewer", &expanding, 2_000).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        assert_eq!(
            get_package(&runtime, "intruder", "ops", "cert:1").unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut foreign_signer = certification();
        foreign_signer.signer_id = "signer:other".into();
        assert_eq!(
            verify_package(&runtime, "reviewer", "ops", "cert:1", &foreign_signer).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let revoked = revoke_package(
            &runtime,
            "reviewer",
            "ops",
            "cert:1",
            "signer rotated",
            4_000,
        )
        .unwrap();
        assert_eq!(revoked.revocation, REVOCATION_REVOKED);
        assert_eq!(revoked.revoked_at_ms, 4_000);
        assert_eq!(
            verify_package(&runtime, "reviewer", "ops", "cert:1", &evidence(&revoked)).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let history = get_package(&runtime, "reviewer", "ops", "cert:1").unwrap();
        assert_eq!(history.revocation_reason, "signer rotated");
        assert_eq!(
            certify_package(&runtime, "reviewer", &certification(), 5_000).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut unchained = certification();
        unchained.certification_id = "cert:2".into();
        unchained.package_digest.clear();
        unchained.certification_digest.clear();
        assert_eq!(
            certify_package(&runtime, "reviewer", &unchained, 6_000).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut chained = unchained;
        chained.predecessor_id = "cert:1".into();
        chained.certification_digest.clear();
        let recertified = certify_package(&runtime, "reviewer", &chained, 7_000).unwrap();
        assert_eq!(
            get_package(&runtime, "reviewer", "ops", "cert:1")
                .unwrap()
                .superseded_by,
            "cert:2"
        );
        verify_package(
            &runtime,
            "reviewer",
            "ops",
            "cert:2",
            &evidence(&recertified),
        )
        .unwrap();
    }

    #[test]
    fn postgres_surface_is_explicitly_unavailable() {
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "capability packages are unavailable on the PostgreSQL community runtime"
        );
    }
}
