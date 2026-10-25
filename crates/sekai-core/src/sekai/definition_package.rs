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
//! credentials, or run history. Governed transform definitions are `transform`
//! members (#1799); their documents omit namespace so the digest is stable
//! across namespaces. Import checks transform output against the candidate
//! (and the target, when the package does not carry that type). Merge writes
//! those members into the transform store.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::sekai::governed_transform::{
    AnalyticalSpec, CONTRACT_VERSION as TRANSFORM_CONTRACT, GovernedTransform, IsolatedProcessSpec,
    TransformSchedule, TransformStep, TransformTrigger,
};
use crate::shomei::TrustedKeyring;

pub const PACKAGE_CONTRACT: &str = "sekai.definition-package/v1";
/// The signature could not be verified against the trusted keyring.
pub const REFUSAL_UNVERIFIED: &str = "definition_package_unverified";
/// A digest does not match the content it covers.
pub const REFUSAL_TAMPERED: &str = "definition_package_tampered";
/// The format, a member kind, or a member document is not supported.
pub const REFUSAL_INCOMPATIBLE: &str = "definition_package_incompatible";
/// Package member kind for a governed transform definition.
pub const MEMBER_KIND_TRANSFORM: &str = "transform";
/// Transform output columns are not present on the output definition.
pub const REFUSAL_TRANSFORM_OUTPUT: &str = "transform_output_incompatible";
/// A store transform is not a published member, so merge cannot restore it.
pub const REFUSAL_TRANSFORM_STORE: &str = "transform_store_conflict";

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

/// Namespace-free governed transform document carried as a package member.
/// `namespace` and `definition_digest` stay off the digest so the same
/// pipeline has the same member digest in every namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageTransformDocument {
    contract_version: String,
    transform_id: String,
    input_dataset_id: String,
    output_dataset_id: String,
    #[serde(default)]
    steps: Vec<TransformStep>,
    #[serde(default)]
    quality_rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    analytical: Option<AnalyticalSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    isolated_process: Option<IsolatedProcessSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    schedule: Option<TransformSchedule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trigger: Option<TransformTrigger>,
}

impl PackageTransformDocument {
    fn from_transform(transform: &GovernedTransform) -> Self {
        Self {
            contract_version: transform.contract_version.clone(),
            transform_id: transform.transform_id.clone(),
            input_dataset_id: transform.input_dataset_id.clone(),
            output_dataset_id: transform.output_dataset_id.clone(),
            steps: transform.steps.clone(),
            quality_rule: transform.quality_rule.clone(),
            analytical: transform.analytical.clone(),
            isolated_process: transform.isolated_process.clone(),
            // Packages do not carry schedule or trigger; those stay local.
            schedule: None,
            trigger: None,
        }
    }

    fn bind(self, namespace: &str) -> Result<GovernedTransform, String> {
        GovernedTransform {
            contract_version: self.contract_version,
            namespace: namespace.into(),
            transform_id: self.transform_id,
            input_dataset_id: self.input_dataset_id,
            output_dataset_id: self.output_dataset_id,
            steps: self.steps,
            quality_rule: self.quality_rule,
            definition_digest: String::new(),
            analytical: self.analytical,
            isolated_process: self.isolated_process,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .map_err(|error| error.message())
    }
}

/// Store writes implied by publishing `next` over `previous`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransformStoreEdits {
    pub upserts: Vec<GovernedTransform>,
    pub deletions: Vec<String>,
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
    if let Some(member) = package
        .members
        .iter()
        .find(|member| !crate::sekai::definition_branch::member_kind_is_supported(&member.kind))
    {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: unsupported member kind {}",
            member.kind
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

/// True when `definition_json` is a governed-transform document, including
/// documents that still carry `namespace` or `definition_digest`.
pub fn transform_member_is_governed(definition_json: &str) -> bool {
    parse_transform_document(definition_json).is_some()
}

fn parse_transform_document(
    definition_json: &str,
) -> Option<Result<PackageTransformDocument, String>> {
    let mut value: serde_json::Value = serde_json::from_str(definition_json).ok()?;
    let contract = value.get("contract_version")?.as_str()?;
    if contract != TRANSFORM_CONTRACT {
        return None;
    }
    if let Some(object) = value.as_object_mut() {
        object.remove("namespace");
        object.remove("definition_digest");
    }
    Some(serde_json::from_value(value).map_err(|error| {
        format!("{REFUSAL_INCOMPATIBLE}: transform document is unreadable: {error}")
    }))
}

/// Canonical member JSON for a governed transform, without namespace.
pub fn package_transform_json(transform: &GovernedTransform) -> Result<String, String> {
    let value = serde_json::to_value(PackageTransformDocument::from_transform(transform))
        .map_err(|error| error.to_string())?;
    let canonical = crate::shomei::canonical_json_with_finite_numbers(&value)?;
    String::from_utf8(canonical).map_err(|_| "canonical transform JSON is not UTF-8".into())
}

/// Published members overlaid with the namespace's governed transforms.
/// Store documents win on the same identity so export reflects what runs.
pub fn members_for_export(
    members: impl IntoIterator<Item = (String, String, String)>,
    transforms: impl IntoIterator<Item = GovernedTransform>,
) -> Result<Vec<(String, String, String)>, String> {
    let mut by_identity = BTreeMap::new();
    for (kind, id, json) in members {
        by_identity.insert((kind, id), json);
    }
    for transform in transforms {
        let json = package_transform_json(&transform)?;
        by_identity.insert((MEMBER_KIND_TRANSFORM.into(), transform.transform_id), json);
    }
    Ok(by_identity
        .into_iter()
        .map(|((kind, id), json)| (kind, id, json))
        .collect())
}

fn bind_transform_member(
    namespace: &str,
    member_id: &str,
    definition_json: &str,
) -> Result<Option<GovernedTransform>, String> {
    let Some(parsed) = parse_transform_document(definition_json) else {
        return Ok(None);
    };
    let document = parsed?;
    if document.transform_id != member_id {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: transform member {member_id} does not match document id {}",
            document.transform_id
        ));
    }
    document
        .bind(namespace)
        .map(Some)
        .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: transform {member_id}: {error}"))
}

fn object_type_properties(definition_json: &str) -> Result<Option<BTreeSet<String>>, String> {
    let value: serde_json::Value = serde_json::from_str(definition_json)
        .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: object type is not JSON: {error}"))?;
    match value.get("properties") {
        None => Ok(None),
        Some(serde_json::Value::Array(items)) => {
            let mut names = BTreeSet::new();
            for item in items {
                let Some(name) = item.as_str() else {
                    return Err(format!(
                        "{REFUSAL_INCOMPATIBLE}: object type properties must be strings"
                    ));
                };
                names.insert(name.to_string());
            }
            Ok(Some(names))
        }
        Some(_) => Err(format!(
            "{REFUSAL_INCOMPATIBLE}: object type properties must be an array"
        )),
    }
}

fn transform_output_columns(transform: &GovernedTransform) -> Option<Vec<String>> {
    let mut columns: Option<Vec<String>> = None;
    for step in &transform.steps {
        if !step.kind.trim().eq_ignore_ascii_case("project") || step.columns.is_empty() {
            continue;
        }
        columns = Some(match columns {
            None => step.columns.clone(),
            Some(prior) => step
                .columns
                .iter()
                .filter(|column| prior.iter().any(|kept| kept == *column))
                .cloned()
                .collect(),
        });
    }
    columns
}

fn object_types_by_id(
    members: &[crate::sekai::definition_branch::DefinitionMember],
) -> BTreeMap<&str, &crate::sekai::definition_branch::DefinitionMember> {
    members
        .iter()
        .filter(|member| member.member_kind == "object_type")
        .map(|member| (member.member_id.as_str(), member))
        .collect()
}

/// Import-time I/O check: each governed transform's output columns must sit
/// on the output object type in the candidate, or in the target when the
/// package does not carry that type.
pub fn check_transform_io(
    published: &[crate::sekai::definition_branch::DefinitionMember],
    members: &[crate::sekai::definition_branch::DefinitionMember],
) -> Result<(), String> {
    let candidate_types = object_types_by_id(members);
    let published_types = object_types_by_id(published);
    for member in members
        .iter()
        .filter(|member| member.member_kind == MEMBER_KIND_TRANSFORM)
    {
        let Some(transform) = bind_transform_member(
            &member.namespace,
            &member.member_id,
            &member.definition_json,
        )?
        else {
            continue;
        };
        let output_id = transform.output_dataset_id.as_str();
        let Some(definition) = candidate_types
            .get(output_id)
            .copied()
            .or_else(|| published_types.get(output_id).copied())
        else {
            continue;
        };
        let Some(columns) = transform_output_columns(&transform) else {
            continue;
        };
        let Some(properties) = object_type_properties(&definition.definition_json)? else {
            continue;
        };
        if let Some(column) = columns.iter().find(|column| !properties.contains(*column)) {
            return Err(format!(
                "{REFUSAL_INCOMPATIBLE}: {REFUSAL_TRANSFORM_OUTPUT}: transform {} output {output_id} does not match definition {output_id} ({column})",
                transform.transform_id
            ));
        }
    }
    Ok(())
}

/// Governed transform members that merge should write to, or delete from,
/// the runtime transform store. Unchanged members leave the store row
/// (including local schedule and trigger) untouched. A changed member is
/// written without schedule or trigger, so merge cannot keep a pipeline
/// auto-running. A store row that is not a published member is refused so
/// rollback cannot drop a Put-only pipeline.
pub fn transform_store_edits(
    namespace: &str,
    previous: &[crate::sekai::definition_branch::DefinitionMember],
    next: &[crate::sekai::definition_branch::DefinitionMember],
    store: &[GovernedTransform],
) -> Result<TransformStoreEdits, String> {
    fn governed(
        namespace: &str,
        members: &[crate::sekai::definition_branch::DefinitionMember],
    ) -> Result<BTreeMap<String, GovernedTransform>, String> {
        let mut out = BTreeMap::new();
        for member in members
            .iter()
            .filter(|member| member.member_kind == MEMBER_KIND_TRANSFORM)
        {
            if let Some(transform) =
                bind_transform_member(namespace, &member.member_id, &member.definition_json)?
            {
                out.insert(transform.transform_id.clone(), transform);
            }
        }
        Ok(out)
    }
    check_transform_io(previous, next)?;
    let previous = governed(namespace, previous)?;
    let next = governed(namespace, next)?;
    let store_by_id: BTreeMap<&str, &GovernedTransform> = store
        .iter()
        .filter(|transform| transform.namespace == namespace)
        .map(|transform| (transform.transform_id.as_str(), transform))
        .collect();
    for id in next.keys() {
        if store_by_id.contains_key(id.as_str()) && !previous.contains_key(id) {
            return Err(format!(
                "{REFUSAL_INCOMPATIBLE}: {REFUSAL_TRANSFORM_STORE}: transform {id} exists in the store but is not a published member"
            ));
        }
    }
    let mut deletions = Vec::new();
    for id in previous.keys() {
        if !next.contains_key(id) {
            deletions.push(id.clone());
        }
    }
    let mut upserts = Vec::new();
    for (id, transform) in next {
        match previous.get(&id) {
            Some(prior) if prior.definition_digest == transform.definition_digest => {}
            _ => upserts.push(transform),
        }
    }
    Ok(TransformStoreEdits { upserts, deletions })
}

/// Refuses an import whose members, prepared for the target namespace,
/// would not change `published`, or whose documents use constructs the merge
/// gates cannot classify. Runs before anything is written.
pub fn check_importable(
    published: &crate::sekai::definition_branch::DefinitionRevision,
    published_members: &[crate::sekai::definition_branch::DefinitionMember],
    members: &[crate::sekai::definition_branch::DefinitionMember],
    store: &[GovernedTransform],
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
    check_transform_io(published_members, members)?;
    transform_store_edits(&published.namespace, published_members, members, store)?;
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

    fn projection(namespace: &str, output: &str, columns: &[&str]) -> GovernedTransform {
        GovernedTransform {
            contract_version: TRANSFORM_CONTRACT.into(),
            namespace: namespace.into(),
            transform_id: "ProjectTickets".into(),
            input_dataset_id: "tickets".into(),
            output_dataset_id: output.into(),
            steps: vec![TransformStep {
                kind: "project".into(),
                column: String::new(),
                op: String::new(),
                value: String::new(),
                columns: columns.iter().map(|column| (*column).to_string()).collect(),
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    fn prepared_member(
        namespace: &str,
        kind: &str,
        id: &str,
        json: &str,
    ) -> crate::sekai::definition_branch::DefinitionMember {
        crate::sekai::definition_branch::DefinitionMemberInput {
            member_kind: kind.into(),
            member_id: id.into(),
            definition_json: json.into(),
            member_digest: String::new(),
        }
        .prepare(namespace)
        .unwrap()
    }

    #[test]
    fn export_overlay_is_namespace_independent() {
        let ticket = r#"{"name":"Ticket","properties":["title"]}"#;
        let left = build_package(
            members_for_export(
                [("object_type".into(), "Ticket".into(), ticket.into())],
                [projection("team-a", "Ticket", &["title"])],
            )
            .unwrap(),
        )
        .unwrap();
        let right = build_package(
            members_for_export(
                [("object_type".into(), "Ticket".into(), ticket.into())],
                [projection("team-b", "Ticket", &["title"])],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(left.package_digest, right.package_digest);
        assert_eq!(left.members[1].kind, MEMBER_KIND_TRANSFORM);
        assert!(!left.members[1].definition_json.contains("team-a"));
        assert!(
            !left.members[1]
                .definition_json
                .contains("definition_digest")
        );
        assert!(!left.members[1].definition_json.contains("schedule"));
        assert!(!left.members[1].definition_json.contains("trigger"));
    }

    #[test]
    fn transform_output_mismatch_is_named_and_blocks_import() {
        let ticket = prepared_member(
            "team-b",
            "object_type",
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        );
        let json =
            package_transform_json(&projection("team-a", "Ticket", &["title", "body"])).unwrap();
        let transform = prepared_member("team-b", MEMBER_KIND_TRANSFORM, "ProjectTickets", &json);
        let error = check_transform_io(std::slice::from_ref(&ticket), &[ticket.clone(), transform])
            .unwrap_err();
        assert!(
            error.starts_with(&format!(
                "{REFUSAL_INCOMPATIBLE}: {REFUSAL_TRANSFORM_OUTPUT}"
            )),
            "{error}"
        );

        let matching = package_transform_json(&projection("team-a", "Ticket", &["title"])).unwrap();
        let transform =
            prepared_member("team-b", MEMBER_KIND_TRANSFORM, "ProjectTickets", &matching);
        let published = [ticket.clone()];
        let incoming = [ticket.clone(), transform];
        check_transform_io(&published, &incoming).unwrap();

        let mut narrowed = projection("team-a", "Ticket", &["title"]);
        narrowed.steps.push(TransformStep {
            kind: " project ".into(),
            column: String::new(),
            op: String::new(),
            value: String::new(),
            columns: vec!["title".into(), "body".into()],
        });
        narrowed.definition_digest.clear();
        let narrowed = package_transform_json(&narrowed.prepare().unwrap()).unwrap();
        let transform =
            prepared_member("team-b", MEMBER_KIND_TRANSFORM, "ProjectTickets", &narrowed);
        check_transform_io(&published, &[ticket, transform]).unwrap();
    }

    #[test]
    fn transform_store_edits_upsert_and_delete_governed_members() {
        let v1 = package_transform_json(&projection("team-a", "out", &["title"])).unwrap();
        let v2 = package_transform_json(&projection("team-a", "out", &["title", "body"])).unwrap();
        let previous = vec![prepared_member(
            "team-b",
            MEMBER_KIND_TRANSFORM,
            "ProjectTickets",
            &v1,
        )];
        let next = vec![prepared_member(
            "team-b",
            MEMBER_KIND_TRANSFORM,
            "ProjectTickets",
            &v2,
        )];
        let changed = transform_store_edits("team-b", &previous, &next, &[]).unwrap();
        assert_eq!(changed.deletions, [] as [String; 0]);
        assert_eq!(changed.upserts[0].output_dataset_id, "out");
        assert_eq!(changed.upserts[0].namespace, "team-b");
        assert!(changed.upserts[0].schedule.is_none());

        let restored = transform_store_edits("team-b", &next, &[], &[]).unwrap();
        assert_eq!(restored.deletions, ["ProjectTickets"]);
        assert!(restored.upserts.is_empty());

        let unchanged = transform_store_edits("team-b", &previous, &previous, &[]).unwrap();
        assert!(unchanged.upserts.is_empty());
        assert!(unchanged.deletions.is_empty());

        let mut scheduled = projection("team-b", "out", &["title"]);
        scheduled.schedule = Some(TransformSchedule { every_ms: 60_000 });
        scheduled.trigger = Some(TransformTrigger {
            on_input_commit: true,
            ..TransformTrigger::default()
        });
        scheduled.definition_digest.clear();
        let scheduled = scheduled.prepare().unwrap();
        let replaced =
            transform_store_edits("team-b", &previous, &next, std::slice::from_ref(&scheduled))
                .unwrap();
        assert!(replaced.upserts[0].schedule.is_none());
        assert!(replaced.upserts[0].trigger.is_none());
        assert_eq!(replaced.upserts[0].steps[0].columns, ["title", "body"]);

        let skipped = transform_store_edits(
            "team-b",
            &previous,
            &previous,
            std::slice::from_ref(&scheduled),
        )
        .unwrap();
        assert!(skipped.upserts.is_empty());

        let drifted = projection("team-b", "out", &["title", "body"]);
        let leftover = transform_store_edits(
            "team-b",
            &previous,
            &previous,
            std::slice::from_ref(&drifted),
        )
        .unwrap();
        assert!(leftover.upserts.is_empty());

        let error = transform_store_edits("team-b", &[], &next, &[scheduled]).unwrap_err();
        assert!(
            error.starts_with(&format!(
                "{REFUSAL_INCOMPATIBLE}: {REFUSAL_TRANSFORM_STORE}"
            )),
            "{error}"
        );
    }
}
