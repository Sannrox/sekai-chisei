//! Versioned client-package publications (#702).
//!
//! A publication binds language, package identity, protocol digest, source
//! digest, package digest, and provenance. The plane does not upload registry
//! bytes or treat discovery as a grant.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::runtime_db::RuntimeDb;
use crate::shomei;

pub const PACKAGE_CONTRACT: &str = "sekai.client-package/v1";
pub const LANG_RUST: &str = "rust";
pub const LANG_TYPESCRIPT: &str = "typescript";
pub const LANG_PYTHON: &str = "python";
pub const PACKAGE_UNAVAILABLE: &str = "client package is unavailable";
pub const PROTOCOL_UNSUPPORTED: &str = "client package protocol is unsupported";
pub const POSTGRES_UNAVAILABLE: &str =
    "client packages are unavailable on the PostgreSQL community runtime";

const LANGUAGES: &[&str] = &[LANG_RUST, LANG_TYPESCRIPT, LANG_PYTHON];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPackage {
    pub contract_version: String,
    pub package_id: String,
    pub namespace: String,
    pub owner: String,
    pub language: String,
    pub package_name: String,
    pub package_version: String,
    pub protocol_digest: String,
    pub source_digest: String,
    pub package_digest: String,
    #[serde(default)]
    pub catalog_version: String,
    pub operation_id: String,
    #[serde(default)]
    pub predecessor_id: String,
    #[serde(default)]
    pub superseded_by: String,
    pub admitted_by: String,
    pub admitted_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifacts {
    pub protocol: String,
    pub source: String,
    pub package: String,
}

#[derive(Serialize)]
struct DigestPin<'a> {
    kind: &'a str,
    body: &'a str,
}

pub fn digest_bytes(kind: &str, body: &str) -> Result<String, String> {
    required("digest kind", kind)?;
    Ok(format!(
        "sha256:{}",
        shomei::digest_serializable(&DigestPin { kind, body })?
    ))
}

pub fn artifacts_from(
    protocol: &str,
    source: &str,
    package: &[u8],
) -> Result<PackageArtifacts, String> {
    Ok(PackageArtifacts {
        protocol: digest_bytes("protocol", protocol)?,
        source: digest_bytes("source", source)?,
        package: digest_blob("package", package)?,
    })
}

pub fn publish_client_package(
    db: &RuntimeDb,
    actor: &str,
    package: &ClientPackage,
    artifacts: &PackageArtifacts,
    now_ms: i64,
) -> Result<ClientPackage, String> {
    required("actor", actor)?;
    require_positive_timestamp("publish", now_ms)?;
    let validated = validate_package(package, artifacts, actor, now_ms)?;
    if let Some(existing) = db.get_client_package(&validated.namespace, &validated.package_id)? {
        return replay_or_conflict(&existing, &validated);
    }
    reject_live_identity_collision(db, &validated)?;
    let predecessor = load_predecessor(db, &validated)?;
    if let Some(predecessor) = predecessor {
        db.commit_client_packages(&[&predecessor, &validated])?;
    } else {
        db.commit_client_packages(&[&validated])?;
    }
    Ok(validated)
}

pub fn get_client_package(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    package_id: &str,
) -> Result<ClientPackage, String> {
    required("actor", actor)?;
    let package = owned_package(db, namespace, package_id, actor)?;
    if package.contract_version != PACKAGE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    Ok(package)
}

pub fn verify_client_package(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    package_id: &str,
    artifacts: &PackageArtifacts,
) -> Result<ClientPackage, String> {
    let package = get_client_package(db, actor, namespace, package_id)?;
    if package.protocol_digest != artifacts.protocol
        || package.source_digest != artifacts.source
        || package.package_digest != artifacts.package
        || !digest_token(&package.protocol_digest)
        || !digest_token(&package.source_digest)
        || !digest_token(&package.package_digest)
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(package)
}

pub fn smoke_client_package(
    db: &RuntimeDb,
    actor: &str,
    namespace: &str,
    package_id: &str,
    artifacts: &PackageArtifacts,
) -> Result<ClientPackage, String> {
    let package = verify_client_package(db, actor, namespace, package_id, artifacts)?;
    if !package.superseded_by.is_empty() {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if !LANGUAGES.contains(&package.language.as_str()) {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(package)
}

fn validate_package(
    package: &ClientPackage,
    artifacts: &PackageArtifacts,
    actor: &str,
    now_ms: i64,
) -> Result<ClientPackage, String> {
    required("package id", &package.package_id)?;
    required("namespace", &package.namespace)?;
    required("package name", &package.package_name)?;
    required("package version", &package.package_version)?;
    required("operation id", &package.operation_id)?;
    if package.contract_version != PACKAGE_CONTRACT {
        return Err(PROTOCOL_UNSUPPORTED.into());
    }
    if !LANGUAGES.contains(&package.language.as_str()) {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if !digest_token(&artifacts.protocol)
        || !digest_token(&artifacts.source)
        || !digest_token(&artifacts.package)
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if package.protocol_digest != artifacts.protocol
        || package.source_digest != artifacts.source
        || package.package_digest != artifacts.package
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if !package.predecessor_id.is_empty() && package.predecessor_id == package.package_id {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    if !package.superseded_by.is_empty() {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(ClientPackage {
        owner: actor.into(),
        admitted_by: actor.into(),
        admitted_at_ms: now_ms,
        superseded_by: String::new(),
        ..package.clone()
    })
}

fn replay_or_conflict(
    existing: &ClientPackage,
    incoming: &ClientPackage,
) -> Result<ClientPackage, String> {
    if existing.owner != incoming.owner
        || existing.language != incoming.language
        || existing.package_name != incoming.package_name
        || existing.package_version != incoming.package_version
        || existing.protocol_digest != incoming.protocol_digest
        || existing.source_digest != incoming.source_digest
        || existing.package_digest != incoming.package_digest
        || existing.catalog_version != incoming.catalog_version
        || existing.predecessor_id != incoming.predecessor_id
        || !existing.superseded_by.is_empty()
    {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(existing.clone())
}

fn reject_live_identity_collision(db: &RuntimeDb, package: &ClientPackage) -> Result<(), String> {
    for existing in db.list_client_packages(&package.namespace)? {
        if existing.package_id == package.package_id
            || existing.language != package.language
            || existing.package_name != package.package_name
            || existing.package_version != package.package_version
            || !existing.superseded_by.is_empty()
        {
            continue;
        }
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(())
}

fn load_predecessor(
    db: &RuntimeDb,
    package: &ClientPackage,
) -> Result<Option<ClientPackage>, String> {
    let mut live = Vec::new();
    for existing in db.list_client_packages(&package.namespace)? {
        if existing.language == package.language
            && existing.package_name == package.package_name
            && existing.superseded_by.is_empty()
            && existing.package_id != package.package_id
        {
            live.push(existing);
        }
    }
    match live.as_mut_slice() {
        [] => {
            if !package.predecessor_id.is_empty() {
                return Err(PACKAGE_UNAVAILABLE.into());
            }
            Ok(None)
        }
        [predecessor] => {
            if (!package.predecessor_id.is_empty()
                && package.predecessor_id != predecessor.package_id)
                || predecessor.owner != package.owner
                || !is_later_version(&package.package_version, &predecessor.package_version)
            {
                return Err(PACKAGE_UNAVAILABLE.into());
            }
            predecessor.superseded_by = package.package_id.clone();
            Ok(Some(predecessor.clone()))
        }
        _ => Err(PACKAGE_UNAVAILABLE.into()),
    }
}

fn owned_package(
    db: &RuntimeDb,
    namespace: &str,
    package_id: &str,
    actor: &str,
) -> Result<ClientPackage, String> {
    required("namespace", namespace)?;
    required("package id", package_id)?;
    let Some(package) = db.get_client_package(namespace, package_id)? else {
        return Err(PACKAGE_UNAVAILABLE.into());
    };
    if package.owner != actor {
        return Err(PACKAGE_UNAVAILABLE.into());
    }
    Ok(package)
}

fn is_later_version(successor: &str, predecessor: &str) -> bool {
    match (parse_version(successor), parse_version(predecessor)) {
        (Some(mut successor), Some(mut predecessor)) => {
            let width = successor.len().max(predecessor.len());
            successor.resize(width, 0);
            predecessor.resize(width, 0);
            successor > predecessor
        }
        _ => false,
    }
}

fn parse_version(value: &str) -> Option<Vec<u64>> {
    let mut parts = Vec::new();
    for part in value.split('.') {
        parts.push(part.parse().ok()?);
    }
    if parts.is_empty() { None } else { Some(parts) }
}

fn digest_blob(kind: &str, body: &[u8]) -> Result<String, String> {
    required("digest kind", kind)?;
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0_u8]);
    hasher.update(body);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn digest_token(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn require_positive_timestamp(label: &str, now_ms: i64) -> Result<(), String> {
    if now_ms <= 0 {
        Err(format!("{label} timestamp must be positive"))
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

    fn artifacts() -> PackageArtifacts {
        artifacts_from("proto-v1", "source-v1", b"pkg-v1").unwrap()
    }

    fn package(
        id: &str,
        version: &str,
        language: &str,
        artifacts: &PackageArtifacts,
    ) -> ClientPackage {
        ClientPackage {
            contract_version: PACKAGE_CONTRACT.into(),
            package_id: id.into(),
            namespace: "sdk".into(),
            owner: String::new(),
            language: language.into(),
            package_name: "sekai-client".into(),
            package_version: version.into(),
            protocol_digest: artifacts.protocol.clone(),
            source_digest: artifacts.source.clone(),
            package_digest: artifacts.package.clone(),
            catalog_version: "catalog-v1".into(),
            operation_id: format!("op:{id}"),
            predecessor_id: String::new(),
            superseded_by: String::new(),
            admitted_by: String::new(),
            admitted_at_ms: 0,
        }
    }

    fn publish(runtime: &RuntimeDb, id: &str, version: &str) -> ClientPackage {
        let artifacts = artifacts();
        publish_client_package(
            runtime,
            "integrator",
            &package(id, version, LANG_RUST, &artifacts),
            &artifacts,
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn authorized_publish_verifies_source_protocol_package_and_provenance() {
        let runtime = db();
        let artifacts = artifacts();
        let published = publish(&runtime, "pkg:rust-0.1.0", "0.1.0");
        assert_eq!(published.contract_version, PACKAGE_CONTRACT);
        assert_eq!(published.owner, "integrator");
        assert_eq!(published.protocol_digest, artifacts.protocol);
        let viewed = get_client_package(&runtime, "integrator", "sdk", "pkg:rust-0.1.0").unwrap();
        assert_eq!(viewed.operation_id, "op:pkg:rust-0.1.0");
        let verified =
            verify_client_package(&runtime, "integrator", "sdk", "pkg:rust-0.1.0", &artifacts)
                .unwrap();
        assert_eq!(verified.package_digest, artifacts.package);
        smoke_client_package(&runtime, "integrator", "sdk", "pkg:rust-0.1.0", &artifacts).unwrap();
        for language in [LANG_TYPESCRIPT, LANG_PYTHON] {
            let published = publish_client_package(
                &runtime,
                "integrator",
                &package(&format!("pkg:{language}"), "0.1.0", language, &artifacts),
                &artifacts,
                1_100,
            )
            .unwrap();
            assert_eq!(published.language, language);
        }
    }

    #[test]
    fn replay_is_idempotent_and_same_version_cannot_be_silently_replaced() {
        let runtime = db();
        let first = publish(&runtime, "pkg:rust-0.1.0", "0.1.0");
        let artifacts = artifacts();
        let second = publish_client_package(
            &runtime,
            "integrator",
            &package("pkg:rust-0.1.0", "0.1.0", LANG_RUST, &artifacts),
            &artifacts,
            2_000,
        )
        .unwrap();
        assert_eq!(first, second);
        let mutated = artifacts_from("proto-v1", "source-v1", b"pkg-v2").unwrap();
        let mut other_id = package("pkg:rust-0.1.0-dup", "0.1.0", LANG_RUST, &artifacts);
        other_id.package_digest = artifacts.package.clone();
        assert_eq!(
            publish_client_package(&runtime, "integrator", &other_id, &artifacts, 2_500)
                .unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut changed = package("pkg:rust-0.1.0", "0.1.0", LANG_RUST, &mutated);
        changed.package_digest = mutated.package.clone();
        assert_eq!(
            publish_client_package(&runtime, "integrator", &changed, &mutated, 3_000).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut replaced = first.clone();
        replaced.package_digest = mutated.package;
        assert_eq!(
            runtime.commit_client_packages(&[&replaced]).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
    }

    #[test]
    fn successor_supersedes_predecessor_and_smoke_refuses_the_old_version() {
        let runtime = db();
        publish(&runtime, "pkg:rust-0.1.0", "0.1.0");
        let artifacts = artifacts();
        let next = package("pkg:rust-0.2.0", "0.2.0", LANG_RUST, &artifacts);
        let published =
            publish_client_package(&runtime, "integrator", &next, &artifacts, 2_000).unwrap();
        assert!(published.superseded_by.is_empty());
        let previous = get_client_package(&runtime, "integrator", "sdk", "pkg:rust-0.1.0").unwrap();
        assert_eq!(previous.superseded_by, "pkg:rust-0.2.0");
        assert_eq!(
            smoke_client_package(&runtime, "integrator", "sdk", "pkg:rust-0.1.0", &artifacts)
                .unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        smoke_client_package(&runtime, "integrator", "sdk", "pkg:rust-0.2.0", &artifacts).unwrap();
        let mut stale = package("pkg:rust-0.1.1", "0.1.1", LANG_RUST, &artifacts);
        stale.predecessor_id = "pkg:rust-0.2.0".into();
        assert_eq!(
            publish_client_package(&runtime, "integrator", &stale, &artifacts, 3_000).unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        assert!(
            get_client_package(&runtime, "integrator", "sdk", "pkg:rust-0.2.0")
                .unwrap()
                .superseded_by
                .is_empty()
        );
    }

    #[test]
    fn tamper_unknown_language_stale_protocol_and_foreign_owner_fail_unavailable() {
        let runtime = db();
        let artifacts = artifacts();
        publish(&runtime, "pkg:rust-0.1.0", "0.1.0");
        let tampered = artifacts_from("proto-v1", "source-v1", b"other").unwrap();
        assert_eq!(
            verify_client_package(&runtime, "integrator", "sdk", "pkg:rust-0.1.0", &tampered)
                .unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut unknown = package("pkg:hidden", "0.1.0", "go", &artifacts);
        unknown.language = "go".into();
        assert_eq!(
            publish_client_package(&runtime, "integrator", &unknown, &artifacts, 2_000)
                .unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut stale = package("pkg:stale", "0.1.0", LANG_RUST, &artifacts);
        stale.contract_version = "sekai.client-package/v0".into();
        assert_eq!(
            publish_client_package(&runtime, "integrator", &stale, &artifacts, 2_000).unwrap_err(),
            PROTOCOL_UNSUPPORTED
        );
        assert_eq!(
            get_client_package(&runtime, "intruder", "sdk", "pkg:rust-0.1.0").unwrap_err(),
            PACKAGE_UNAVAILABLE
        );
        let mut extra =
            serde_json::to_value(package("pkg:x", "0.1.0", LANG_RUST, &artifacts)).unwrap();
        extra
            .as_object_mut()
            .unwrap()
            .insert("hidden".into(), serde_json::json!("nope"));
        assert!(serde_json::from_value::<ClientPackage>(extra).is_err());
    }

    #[test]
    fn zero_timestamp_and_postgres_surface_fail_closed() {
        let runtime = db();
        let artifacts = artifacts();
        assert_eq!(
            publish_client_package(
                &runtime,
                "integrator",
                &package("pkg:rust-0.1.0", "0.1.0", LANG_RUST, &artifacts),
                &artifacts,
                0,
            )
            .unwrap_err(),
            "publish timestamp must be positive"
        );
        assert_eq!(
            POSTGRES_UNAVAILABLE,
            "client packages are unavailable on the PostgreSQL community runtime"
        );
    }
}
