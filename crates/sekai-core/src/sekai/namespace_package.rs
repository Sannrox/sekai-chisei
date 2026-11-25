//! Namespace packages (#3093, ADR 0169): one signed inventory of a
//! namespace's governed resources, for install into a namespace of another
//! tenant.
//!
//! A package is a `sekai.namespace-package/v1` manifest. It has a name and a
//! version, the ontology digest, one entry per resource, and a withheld list.
//! - The `definition_package` entry carries the definition members the caller
//!   may read as a [`DefinitionPackage`]. Its digest is that package's
//!   namespace-free digest, and the ontology digest is the same value, so a
//!   target that applies the members reproduces it. Governed transforms are
//!   not carried in v1.
//! - A `dataset_version` entry is an output (a dataset the caller selected,
//!   carrying its name, columns and partition keys) or an input (a dataset a
//!   carried resource depends on, which the installer maps; it carries no
//!   document). Its digest is the schema digest: columns and partition keys,
//!   not the name, so a mapped dataset can match under another name. v1
//!   export emits no inputs: with transforms out, no carried resource depends
//!   on an uncarried dataset.
//! - The withheld list counts definition members the caller may not read, by
//!   member kind, never naming them.
//!
//! The package digest covers the whole canonical manifest, and the envelope
//! signature is the definition package signature under this contract. A
//! package never carries credentials, run history, receipts or audit.
//! Content (`content_included`) is always false until datasets can carry it.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::sekai::dataset::Dataset;
use crate::sekai::definition_package::{
    self, DefinitionPackage, PackageProvenance, PackageSignature,
};
use crate::shomei::TrustedKeyring;

pub const NAMESPACE_PACKAGE_CONTRACT: &str = "sekai.namespace-package/v1";
/// Entry kind for the carried definition members.
pub const KIND_DEFINITION_PACKAGE: &str = "definition_package";
/// Entry kind for a dataset's definition.
pub const KIND_DATASET_VERSION: &str = "dataset_version";
/// The id of the one `definition_package` entry.
pub const DEFINITIONS_ENTRY_ID: &str = "definitions";
/// The signature could not be verified against the trusted keyring.
pub const REFUSAL_UNVERIFIED: &str = "namespace_package_unverified";
/// A digest does not match the content it covers.
pub const REFUSAL_TAMPERED: &str = "namespace_package_tampered";
/// The format, an entry kind, or an entry document is not supported.
pub const REFUSAL_INCOMPATIBLE: &str = "namespace_package_incompatible";
pub const MAX_PACKAGE_NAME_BYTES: usize = 128;
/// Datasets one package may select.
pub const MAX_PACKAGE_DATASETS: usize = 256;

/// Whether the package creates the resource or depends on one the installer
/// maps in the target namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EntryRole {
    Output,
    Input,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageEntry {
    pub kind: String,
    pub id: String,
    pub role: EntryRole,
    /// The definition package digest, or a dataset's schema digest.
    pub digest: String,
    pub content_included: bool,
    /// Canonical JSON of what an output creates; empty for an input.
    pub document_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithheldCount {
    pub kind: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespacePackage {
    pub contract_version: String,
    pub name: String,
    pub version: u32,
    pub ontology_digest: String,
    /// Sorted by kind, then id.
    pub entries: Vec<PackageEntry>,
    /// Sorted by kind; every count is positive.
    pub withheld: Vec<WithheldCount>,
    /// SHA-256 over the canonical manifest above.
    pub package_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespacePackageEnvelope {
    pub package: NamespacePackage,
    pub provenance: PackageProvenance,
    pub signature: PackageSignature,
}

/// What a `dataset_version` output entry creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetDocument {
    pub name: String,
    pub columns: Vec<DatasetColumn>,
    pub partition_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub col_type: String,
    pub classification: String,
}

impl DatasetDocument {
    pub fn of(dataset: &Dataset) -> Self {
        Self {
            name: dataset.name.clone(),
            columns: dataset
                .columns
                .iter()
                .map(|column| DatasetColumn {
                    name: column.name.clone(),
                    col_type: column.col_type.clone(),
                    classification: column.classification.clone(),
                })
                .collect(),
            partition_keys: dataset.partition_keys.clone(),
        }
    }

    /// Columns in order and partition keys; the name stays out so an installer
    /// can map an input to a dataset of the same shape under another name.
    pub fn schema_digest(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct SchemaPin<'a> {
            columns: &'a [DatasetColumn],
            partition_keys: &'a [String],
        }
        definition_package::contract_digest(
            NAMESPACE_PACKAGE_CONTRACT,
            "dataset_schema",
            &SchemaPin {
                columns: &self.columns,
                partition_keys: &self.partition_keys,
            },
        )
    }
}

/// Refuses a package name outside `[a-z0-9._-]`, an empty or over-long one,
/// and version 0. Versions order installations, so they are integers.
pub fn validate_name_and_version(name: &str, version: u32) -> Result<(), String> {
    let allowed =
        |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte);
    if name.is_empty() || name.len() > MAX_PACKAGE_NAME_BYTES || !name.bytes().all(allowed) {
        return Err(format!(
            "package name must be 1 to {MAX_PACKAGE_NAME_BYTES} characters of a-z, 0-9, '.', '_' or '-'"
        ));
    }
    if version == 0 {
        return Err("package version must be at least 1".into());
    }
    Ok(())
}

fn canonical_string<T: Serialize>(value: &T) -> Result<String, String> {
    String::from_utf8(crate::shomei::canonical_json_with_finite_numbers(value)?)
        .map_err(|_| "canonical JSON is not UTF-8".to_string())
}

fn manifest_digest(package: &NamespacePackage) -> Result<String, String> {
    #[derive(Serialize)]
    struct ManifestPin<'a> {
        contract_version: &'a str,
        name: &'a str,
        version: u32,
        ontology_digest: &'a str,
        entries: &'a [PackageEntry],
        withheld: &'a [WithheldCount],
    }
    definition_package::contract_digest(
        NAMESPACE_PACKAGE_CONTRACT,
        "package",
        &ManifestPin {
            contract_version: &package.contract_version,
            name: &package.name,
            version: package.version,
            ontology_digest: &package.ontology_digest,
            entries: &package.entries,
            withheld: &package.withheld,
        },
    )
}

/// Builds a manifest from the readable definitions, the selected datasets
/// (outputs), the datasets they depend on without carrying (inputs), and
/// withheld counts by kind. Duplicate datasets are refused.
pub fn build_namespace_package(
    name: &str,
    version: u32,
    definitions: &DefinitionPackage,
    outputs: &[Dataset],
    inputs: &[Dataset],
    withheld: BTreeMap<String, u64>,
) -> Result<NamespacePackage, String> {
    validate_name_and_version(name, version)?;
    let mut entries = vec![PackageEntry {
        kind: KIND_DEFINITION_PACKAGE.into(),
        id: DEFINITIONS_ENTRY_ID.into(),
        role: EntryRole::Output,
        digest: definitions.package_digest.clone(),
        content_included: false,
        document_json: canonical_string(definitions)?,
    }];
    for (role, datasets) in [(EntryRole::Output, outputs), (EntryRole::Input, inputs)] {
        for dataset in datasets {
            let document = DatasetDocument::of(dataset);
            entries.push(PackageEntry {
                kind: KIND_DATASET_VERSION.into(),
                id: dataset.id.clone(),
                role,
                digest: document.schema_digest()?,
                content_included: false,
                document_json: match role {
                    EntryRole::Output => canonical_string(&document)?,
                    EntryRole::Input => String::new(),
                },
            });
        }
    }
    entries.sort_by(|left, right| (&left.kind, &left.id).cmp(&(&right.kind, &right.id)));
    if entries
        .windows(2)
        .any(|pair| (&pair[0].kind, &pair[0].id) == (&pair[1].kind, &pair[1].id))
    {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: package lists a resource twice"
        ));
    }
    let mut package = NamespacePackage {
        contract_version: NAMESPACE_PACKAGE_CONTRACT.into(),
        name: name.into(),
        version,
        ontology_digest: definitions.package_digest.clone(),
        entries,
        withheld: withheld
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .map(|(kind, count)| WithheldCount { kind, count })
            .collect(),
        package_digest: String::new(),
    };
    package.package_digest = manifest_digest(&package)?;
    Ok(package)
}

pub fn sign_namespace_package(
    package: NamespacePackage,
    provenance: PackageProvenance,
    identity: &str,
    key_id: &str,
    key: &SigningKey,
) -> Result<NamespacePackageEnvelope, String> {
    let signature = definition_package::sign_digest(
        NAMESPACE_PACKAGE_CONTRACT,
        &package.package_digest,
        &provenance,
        identity,
        key_id,
        key,
    )?;
    Ok(NamespacePackageEnvelope {
        package,
        provenance,
        signature,
    })
}

/// Recomputes one entry's digest from its document; inputs carry none.
fn check_entry(entry: &PackageEntry, ontology_digest: &str) -> Result<(), String> {
    let name = format!("{}/{}", entry.kind, entry.id);
    if entry.content_included {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: entry {name} carries content, which this plane cannot install"
        ));
    }
    match (entry.kind.as_str(), entry.role) {
        (KIND_DEFINITION_PACKAGE, EntryRole::Output) if entry.id == DEFINITIONS_ENTRY_ID => {
            let carried: DefinitionPackage = serde_json::from_str(&entry.document_json)
                .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: entry {name}: {error}"))?;
            let rebuilt = definition_package::build_package(carried.members.iter().map(|member| {
                (
                    member.kind.clone(),
                    member.id.clone(),
                    member.definition_json.clone(),
                )
            }))
            .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: entry {name}: {error}"))?;
            if rebuilt != carried || rebuilt.package_digest != entry.digest {
                return Err(format!(
                    "{REFUSAL_TAMPERED}: entry {name} does not match its definitions"
                ));
            }
            if entry.digest != ontology_digest {
                return Err(format!(
                    "{REFUSAL_TAMPERED}: ontology digest does not match entry {name}"
                ));
            }
            Ok(())
        }
        (KIND_DATASET_VERSION, EntryRole::Output) => {
            let document: DatasetDocument = serde_json::from_str(&entry.document_json)
                .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: entry {name}: {error}"))?;
            if document.schema_digest()? != entry.digest {
                return Err(format!(
                    "{REFUSAL_TAMPERED}: entry {name} does not match its schema"
                ));
            }
            Ok(())
        }
        (KIND_DATASET_VERSION, EntryRole::Input) if entry.document_json.is_empty() => {
            crate::sekai::definition_branch::validate_digest("digest", &entry.digest)
                .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: entry {name}: {error}"))
        }
        _ => Err(format!("{REFUSAL_INCOMPATIBLE}: unsupported entry {name}")),
    }
}

/// Parses and verifies an envelope: the format, every entry digest, the
/// ontology and package digests, and the signature against `keyring`.
/// Nothing is trusted before this returns. Errors start with a `REFUSAL_*`
/// code and name the entry they concern.
pub fn verify_namespace_envelope(
    json: &str,
    keyring: &TrustedKeyring,
) -> Result<NamespacePackageEnvelope, String> {
    let envelope: NamespacePackageEnvelope = serde_json::from_str(json)
        .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: envelope is not readable: {error}"))?;
    let package = &envelope.package;
    if package.contract_version != NAMESPACE_PACKAGE_CONTRACT {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: unsupported package format {:?}",
            package.contract_version
        ));
    }
    validate_name_and_version(&package.name, package.version)
        .map_err(|error| format!("{REFUSAL_INCOMPATIBLE}: {error}"))?;
    if package.entries.len() > MAX_PACKAGE_DATASETS * 2 + 1 {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: package exceeds the supported entry count"
        ));
    }
    // Entries first, so an unknown kind is refused by name.
    for entry in &package.entries {
        check_entry(entry, &package.ontology_digest)?;
    }
    let sorted_unique = package
        .entries
        .windows(2)
        .all(|pair| (&pair[0].kind, &pair[0].id) < (&pair[1].kind, &pair[1].id))
        && package
            .withheld
            .windows(2)
            .all(|pair| pair[0].kind < pair[1].kind);
    if !sorted_unique || package.withheld.iter().any(|withheld| withheld.count == 0) {
        return Err(format!(
            "{REFUSAL_TAMPERED}: entries or withheld counts are out of order"
        ));
    }
    if !package
        .entries
        .iter()
        .any(|entry| entry.kind == KIND_DEFINITION_PACKAGE)
    {
        return Err(format!(
            "{REFUSAL_INCOMPATIBLE}: package has no {KIND_DEFINITION_PACKAGE} entry"
        ));
    }
    if manifest_digest(package)? != package.package_digest {
        return Err(format!(
            "{REFUSAL_TAMPERED}: package digest does not match its manifest"
        ));
    }
    definition_package::verify_digest_signature(
        NAMESPACE_PACKAGE_CONTRACT,
        &package.package_digest,
        &envelope.provenance,
        &envelope.signature,
        keyring,
    )
    .map_err(|error| format!("{REFUSAL_UNVERIFIED}: {error}"))?;
    Ok(envelope)
}

#[cfg(test)]
mod tests;
