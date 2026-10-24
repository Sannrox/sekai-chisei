//! Signed, namespace-independent definition packages (#1700, ADR 0093 in the
//! composing platform).
//!
//! A package holds published definition members as kind, id, and canonical
//! `definition_json`. Member and package digests omit the namespace, so the
//! same definitions have the same package digest in every namespace. The
//! package travels in an Ed25519-signed envelope whose provenance names the
//! source namespace and revision. Import verifies the envelope against a
//! trusted keyring and recomputes every digest before anything is written.
//! A package carries definitions only: never objects, datasets, sources,
//! credentials, or run history.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::shomei::TrustedKeyring;

pub const PACKAGE_CONTRACT: &str = "sekai.definition-package/v1";
/// The signature could not be verified against the trusted keyring.
pub const REFUSAL_UNVERIFIED: &str = "definition_package_unverified";
/// A digest does not match the content it covers.
pub const REFUSAL_TAMPERED: &str = "definition_package_tampered";
/// The format, a member kind, or a member document is not supported.
pub const REFUSAL_INCOMPATIBLE: &str = "definition_package_incompatible";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMember {
    pub kind: String,
    pub id: String,
    /// Canonical JSON of the member document.
    pub definition_json: String,
    /// SHA-256 over kind, id, and `definition_json`, without the namespace.
    pub member_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionPackage {
    pub contract_version: String,
    /// Sorted by kind, then id.
    pub members: Vec<PackageMember>,
    /// SHA-256 over the canonical member list.
    pub package_digest: String,
}

/// Where a package came from. Signed, but outside the package digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageProvenance {
    pub source_namespace: String,
    pub source_revision_digest: String,
    pub exported_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSignature {
    pub identity: String,
    pub key_id: String,
    /// Hex Ed25519 signature over the envelope's signing bytes.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageEnvelope {
    pub package: DefinitionPackage,
    pub provenance: PackageProvenance,
    pub signature: PackageSignature,
}

#[derive(Serialize)]
struct MemberPin<'a> {
    kind: &'a str,
    id: &'a str,
    definition_json: &'a str,
}

#[derive(Serialize)]
struct PackagePin<'a> {
    contract_version: &'a str,
    members: Vec<(&'a str, &'a str, &'a str)>,
}

#[derive(Serialize)]
struct SigningPin<'a> {
    package_digest: &'a str,
    provenance: &'a PackageProvenance,
    identity: &'a str,
    key_id: &'a str,
}

fn domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, String> {
    let canonical = crate::shomei::canonical_json_with_finite_numbers(value)?;
    let mut hasher = Sha256::new();
    hasher.update(PACKAGE_CONTRACT.as_bytes());
    hasher.update(b"\n");
    hasher.update(domain.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn member_digest(kind: &str, id: &str, definition_json: &str) -> Result<String, String> {
    domain_digest(
        "member",
        &MemberPin {
            kind,
            id,
            definition_json,
        },
    )
}

fn package_digest(members: &[PackageMember]) -> Result<String, String> {
    domain_digest(
        "package",
        &PackagePin {
            contract_version: PACKAGE_CONTRACT,
            members: members
                .iter()
                .map(|member| {
                    (
                        member.kind.as_str(),
                        member.id.as_str(),
                        member.member_digest.as_str(),
                    )
                })
                .collect(),
        },
    )
}

fn signing_bytes(
    package_digest: &str,
    provenance: &PackageProvenance,
    identity: &str,
    key_id: &str,
) -> Result<Vec<u8>, String> {
    let canonical = crate::shomei::canonical_json_with_finite_numbers(&SigningPin {
        package_digest,
        provenance,
        identity,
        key_id,
    })?;
    let mut bytes = format!("{PACKAGE_CONTRACT}\nsignature\n").into_bytes();
    bytes.extend(canonical);
    Ok(bytes)
}

fn canonical_member_json(kind: &str, id: &str, definition_json: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(definition_json).map_err(|error| {
        format!("{REFUSAL_INCOMPATIBLE}: member {kind}/{id} is not JSON: {error}")
    })?;
    let canonical = crate::shomei::canonical_json_with_finite_numbers(&value)
        .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: member {kind}/{id}: {error}"))?;
    String::from_utf8(canonical)
        .map_err(|_| format!("{REFUSAL_INCOMPATIBLE}: member {kind}/{id} is not UTF-8"))
}

/// Builds a package from `(kind, id, definition_json)` members. Member JSON
/// is canonicalized first, so the digests cover the bytes an import stores.
pub fn build_package(
    members: impl IntoIterator<Item = (String, String, String)>,
) -> Result<DefinitionPackage, String> {
    let mut members = members
        .into_iter()
        .map(|(kind, id, definition_json)| {
            let definition_json = canonical_member_json(&kind, &id, &definition_json)?;
            Ok(PackageMember {
                member_digest: member_digest(&kind, &id, &definition_json)?,
                kind,
                id,
                definition_json,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    members.sort_by(|left, right| (&left.kind, &left.id).cmp(&(&right.kind, &right.id)));
    let mut seen = BTreeSet::new();
    if !members
        .iter()
        .all(|member| seen.insert((&member.kind, &member.id)))
    {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: package contains duplicate member identities"
        ));
    }
    Ok(DefinitionPackage {
        contract_version: PACKAGE_CONTRACT.into(),
        package_digest: package_digest(&members)?,
        members,
    })
}

pub fn sign_package(
    package: DefinitionPackage,
    provenance: PackageProvenance,
    identity: &str,
    key_id: &str,
    key: &SigningKey,
) -> Result<PackageEnvelope, String> {
    let bytes = signing_bytes(&package.package_digest, &provenance, identity, key_id)?;
    let value = key
        .sign(&bytes)
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(PackageEnvelope {
        package,
        provenance,
        signature: PackageSignature {
            identity: identity.into(),
            key_id: key_id.into(),
            value,
        },
    })
}

fn decode_signature(value: &str) -> Result<[u8; 64], String> {
    if value.len() != 128 || !value.is_ascii() {
        return Err(format!("{REFUSAL_UNVERIFIED}: signature is malformed"));
    }
    let mut bytes = [0_u8; 64];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{REFUSAL_UNVERIFIED}: signature is malformed"))?;
    }
    Ok(bytes)
}

/// Parses and verifies an envelope: the format, every member and package
/// digest, and the signature against `keyring`. Errors start with one of the
/// `REFUSAL_*` codes.
pub fn verify_envelope(json: &str, keyring: &TrustedKeyring) -> Result<PackageEnvelope, String> {
    let envelope: PackageEnvelope = serde_json::from_str(json)
        .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: envelope is not readable: {error}"))?;
    let package = &envelope.package;
    if package.members.len() > crate::sekai::definition_branch::MAX_DEFINITION_MEMBERS {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: package exceeds the supported member count"
        ));
    }
    if package.contract_version != PACKAGE_CONTRACT {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: unsupported package format {:?}",
            package.contract_version
        ));
    }
    let rebuilt = build_package(package.members.iter().map(|member| {
        (
            member.kind.clone(),
            member.id.clone(),
            member.definition_json.clone(),
        )
    }))?;
    let canonical = rebuilt
        .members
        .iter()
        .map(|member| ((&member.kind, &member.id), &member.definition_json))
        .collect::<std::collections::BTreeMap<_, _>>();
    if let Some(member) = package
        .members
        .iter()
        .find(|member| canonical.get(&(&member.kind, &member.id)) != Some(&&member.definition_json))
    {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: member {}/{} JSON is not canonical",
            member.kind, member.id
        ));
    }
    if rebuilt.members != package.members {
        return Err(format!(
            "{REFUSAL_TAMPERED}: a member digest or the member order does not match"
        ));
    }
    if rebuilt.package_digest != package.package_digest {
        return Err(format!(
            "{REFUSAL_TAMPERED}: package digest does not match its members"
        ));
    }
    let signature = &envelope.signature;
    let bytes = signing_bytes(
        &package.package_digest,
        &envelope.provenance,
        &signature.identity,
        &signature.key_id,
    )?;
    keyring
        .verify_message(
            &signature.identity,
            &signature.key_id,
            &bytes,
            &decode_signature(&signature.value)?,
        )
        .map_err(|error| format!("{REFUSAL_UNVERIFIED}: {error}"))?;
    Ok(envelope)
}

/// Refuses an import whose members, prepared for the target namespace,
/// would not change `published`, or whose documents use constructs the merge
/// gates cannot classify. Runs before anything is written.
pub fn check_importable(
    published: &crate::sekai::definition_branch::DefinitionRevision,
    published_members: &[crate::sekai::definition_branch::DefinitionMember],
    members: &[crate::sekai::definition_branch::DefinitionMember],
) -> Result<(), String> {
    fn identities(
        members: &[crate::sekai::definition_branch::DefinitionMember],
    ) -> BTreeSet<(&str, &str, &str)> {
        members
            .iter()
            .map(|member| {
                (
                    member.member_kind.as_str(),
                    member.member_id.as_str(),
                    member.member_digest.as_str(),
                )
            })
            .collect()
    }
    if identities(published_members) == identities(members) {
        return Err(
            "definition_proposal_no_change: package matches the published member set".into(),
        );
    }
    let draft = crate::sekai::definition_branch::prepare_revision(
        &published.namespace,
        &published.revision_digest,
        members.iter().map(
            |member| crate::sekai::definition_branch::DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            },
        ),
        false,
        "import",
        1,
    )
    .and_then(|draft| {
        crate::sekai::definition_diff::classify_definition_revision_compatibility(
            published,
            published_members,
            &draft,
            members,
        )
    });
    draft
        .map(|_| ())
        .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    fn keyring() -> TrustedKeyring {
        let mut keyring = TrustedKeyring::new();
        keyring
            .trust("exporter", "k1", key().verifying_key())
            .unwrap();
        keyring
    }

    fn envelope() -> PackageEnvelope {
        let package = build_package([
            (
                "object_type".to_string(),
                "Ticket".to_string(),
                r#"{"name":"Ticket"}"#.to_string(),
            ),
            (
                "action_type".to_string(),
                "close".to_string(),
                r#"{"name":"close"}"#.to_string(),
            ),
        ])
        .unwrap();
        let provenance = PackageProvenance {
            source_namespace: "team-a".into(),
            source_revision_digest: format!("sha256:{}", "a".repeat(64)),
            exported_at_ms: 1,
        };
        sign_package(package, provenance, "exporter", "k1", &key()).unwrap()
    }

    #[test]
    fn package_digest_ignores_input_order_and_namespace() {
        let forward = envelope().package;
        let reversed = build_package(forward.members.iter().rev().map(|member| {
            (
                member.kind.clone(),
                member.id.clone(),
                member.definition_json.clone(),
            )
        }))
        .unwrap();
        assert_eq!(forward, reversed);
        assert_eq!(forward.members[0].kind, "action_type");
    }

    #[test]
    fn verify_accepts_a_signed_envelope_and_names_each_refusal() {
        let signed = envelope();
        let json = serde_json::to_string(&signed).unwrap();
        assert_eq!(verify_envelope(&json, &keyring()).unwrap(), signed);

        let tampered = json.replace(r#"{\"name\":\"Ticket\"}"#, r#"{\"name\":\"Tickey\"}"#);
        assert_ne!(tampered, json);
        let refused = verify_envelope(&tampered, &keyring()).unwrap_err();
        assert!(refused.starts_with(REFUSAL_TAMPERED), "{refused}");

        let refused = verify_envelope(&json, &TrustedKeyring::new()).unwrap_err();
        assert!(refused.starts_with(REFUSAL_UNVERIFIED), "{refused}");

        let mut resigned = signed.clone();
        resigned.provenance.source_namespace = "elsewhere".into();
        let refused =
            verify_envelope(&serde_json::to_string(&resigned).unwrap(), &keyring()).unwrap_err();
        assert!(refused.starts_with(REFUSAL_UNVERIFIED), "{refused}");

        let spaced = json.replace(r#"{\"name\":\"Ticket\"}"#, r#"{ \"name\": \"Ticket\" }"#);
        assert_ne!(spaced, json);
        let refused = verify_envelope(&spaced, &keyring()).unwrap_err();
        assert!(refused.starts_with(REFUSAL_INCOMPATIBLE), "{refused}");

        let foreign = json.replace(PACKAGE_CONTRACT, "sekai.definition-package/v9");
        let refused = verify_envelope(&foreign, &keyring()).unwrap_err();
        assert!(refused.starts_with(REFUSAL_INCOMPATIBLE), "{refused}");
    }
}
