use crate::db::sekai::SekaiDb;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

use crate::sekai::audit::Decision;

pub const MANIFEST_VERSION: &str = "sekai.capability-package/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageComponent {
    pub kind: String,
    pub name: String,
    pub definition: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPackageManifest {
    pub manifest_version: String,
    pub name: String,
    pub version: String,
    pub components: Vec<PackageComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInstallation {
    pub namespace: String,
    pub package_name: String,
    pub current_version: String,
    pub previous_version: String,
    pub state: String,
    pub installed_by: String,
    pub updated_by: String,
    pub installed_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageLifecycleEvent {
    pub sequence: i64,
    pub namespace: String,
    pub package_name: String,
    pub package_version: String,
    pub action: String,
    pub actor: String,
    pub request_id: String,
    pub manifest_digest: String,
    pub evidence: String,
    pub recorded_at_ms: i64,
}

const COMPONENT_KINDS: &[&str] = &[
    "schema",
    "relation",
    "action",
    "policy_default",
    "eval_suite",
    "retrieval_rule",
    "adapter_declaration",
];

impl CapabilityPackageManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err("unsupported capability package manifest version".into());
        }
        if !valid_identifier(&self.name) || !valid_version(&self.version) {
            return Err("package name and version must be non-empty bounded identifiers".into());
        }
        if self.components.is_empty() || self.components.len() > 128 {
            return Err("package must contain between 1 and 128 components".into());
        }
        let mut identities = BTreeSet::new();
        for component in &self.components {
            if !COMPONENT_KINDS.contains(&component.kind.as_str()) {
                return Err(format!(
                    "unsupported package component kind: {}",
                    component.kind
                ));
            }
            if !valid_identifier(&component.name) || !component.definition.is_object() {
                return Err(
                    "component names must be bounded identifiers and definitions must be objects"
                        .into(),
                );
            }
            if !identities.insert((&component.kind, &component.name)) {
                return Err(format!(
                    "duplicate package component identity: {}/{}",
                    component.kind, component.name
                ));
            }
            validate_component_definition(&component.kind, &component.definition)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !looks_like_credential(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn looks_like_credential(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "sk-",
        "ghp_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "bearer-",
        "akia",
        "asia",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
        || (lower.starts_with("eyj") && lower.matches('.').count() == 2)
        || (value.len() >= 20 && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

fn valid_version(value: &str) -> bool {
    parse_package_version(value).is_some()
}

fn parse_package_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(version)
}

fn validate_component_definition(kind: &str, value: &serde_json::Value) -> Result<(), String> {
    let map = value
        .as_object()
        .ok_or_else(|| "component definition must be an object".to_string())?;
    let allowed_keys: &[&str] = match kind {
        "schema" => &["properties"],
        "relation" => &["from", "to", "relation"],
        "action" => &["risk", "ops"],
        "policy_default" => &["decision"],
        "eval_suite" => &["checks"],
        "retrieval_rule" => &["relations", "max_depth"],
        "adapter_declaration" => &["adapter_type", "protocol"],
        _ => return Err(format!("unsupported package component kind: {kind}")),
    };
    if let Some(key) = map.keys().find(|key| !allowed_keys.contains(&key.as_str())) {
        return Err(format!(
            "{kind} definition contains unsupported field {key}"
        ));
    }
    let identifier = |key: &str| -> Result<&str, String> {
        let value = map
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{kind} definition requires string field {key}"))?;
        if !valid_identifier(value) {
            return Err(format!("{kind}.{key} must be a bounded identifier"));
        }
        Ok(value)
    };
    let identifiers = |key: &str| -> Result<Vec<&str>, String> {
        let values = map
            .get(key)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("{kind} definition requires array field {key}"))?;
        if values.is_empty() || values.len() > 64 {
            return Err(format!(
                "{kind}.{key} must contain between 1 and 64 identifiers"
            ));
        }
        values
            .iter()
            .map(|value| {
                let value = value
                    .as_str()
                    .ok_or_else(|| format!("{kind}.{key} entries must be strings"))?;
                if !valid_identifier(value) {
                    return Err(format!("{kind}.{key} entries must be bounded identifiers"));
                }
                Ok(value)
            })
            .collect()
    };
    match kind {
        "schema" => {
            identifiers("properties")?;
        }
        "relation" => {
            identifier("from")?;
            identifier("to")?;
            identifier("relation")?;
        }
        "action" => {
            let risk = identifier("risk")?;
            if !matches!(risk, "read" | "write" | "destructive") {
                return Err("action.risk must be read, write, or destructive".into());
            }
            let ops = identifiers("ops")?;
            if ops.iter().any(|op| {
                !matches!(
                    *op,
                    "create_object"
                        | "set_property"
                        | "create_link"
                        | "delete_link"
                        | "delete_object"
                )
            }) {
                return Err("action.ops contains an unsupported declarative operation".into());
            }
        }
        "policy_default" => {
            let decision = identifier("decision")?;
            if !matches!(decision, "allow" | "deny" | "require_approval") {
                return Err("policy_default.decision is unsupported".into());
            }
        }
        "eval_suite" => {
            let checks = identifiers("checks")?;
            if checks.iter().any(|check| {
                !matches!(
                    *check,
                    "manifest_digest" | "component_bounds" | "category_present"
                )
            }) {
                return Err("eval_suite.checks contains an unsupported check".into());
            }
        }
        "retrieval_rule" => {
            identifiers("relations")?;
            let depth = map
                .get("max_depth")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "retrieval_rule.max_depth must be an integer".to_string())?;
            if depth == 0 || depth > 3 {
                return Err("retrieval_rule.max_depth must be between 1 and 3".into());
            }
        }
        "adapter_declaration" => {
            identifier("adapter_type")?;
            identifier("protocol")?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

impl SekaiDb {
    pub(crate) fn migrate_capability_packages(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_capability_package_versions (
                    namespace TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    package_version TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, package_name, package_version)
                );
                CREATE TABLE IF NOT EXISTS sekai_capability_package_installations (
                    namespace TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    current_version TEXT NOT NULL,
                    previous_version TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('active','disabled')),
                    installed_by TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    installed_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, package_name)
                );
                CREATE TABLE IF NOT EXISTS sekai_capability_package_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    namespace TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    package_version TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    recorded_at_ms INTEGER NOT NULL,
                    UNIQUE(namespace, actor, request_id)
                );
                CREATE INDEX IF NOT EXISTS idx_capability_package_events_lookup
                    ON sekai_capability_package_events(namespace, package_name, sequence);",
            )
            .map_err(|error| error.to_string())
    }

    pub fn install_capability_package(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        validate_context(namespace, actor, request_id)?;
        let manifest_digest = manifest.digest()?;
        let request_digest = request_digest("install", namespace, manifest, "")?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some(existing) = replay(&tx, namespace, actor, request_id, &request_digest)? {
            return existing
                .ok_or_else(|| "idempotent install no longer has an active installation".into());
        }
        if load_installation(&tx, namespace, &manifest.name)?.is_some() {
            return Err("package already installed in namespace".into());
        }
        store_manifest(&tx, namespace, manifest, &manifest_digest, now_ms)?;
        tx.execute(
            "INSERT INTO sekai_capability_package_installations
             (namespace,package_name,current_version,previous_version,state,installed_by,updated_by,installed_at_ms,updated_at_ms)
             VALUES(?1,?2,?3,'','active',?4,?4,?5,?5)",
            params![namespace, manifest.name, manifest.version, actor, now_ms],
        ).map_err(|error| error.to_string())?;
        append_event(
            &tx,
            namespace,
            manifest,
            "install",
            actor,
            request_id,
            &request_digest,
            &manifest_digest,
            "manifest_validated",
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        drop(conn);
        self.get_capability_package(namespace, &manifest.name)?
            .ok_or_else(|| "package installation missing after commit".into())
    }

    pub fn upgrade_capability_package(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        validate_context(namespace, actor, request_id)?;
        let manifest_digest = manifest.digest()?;
        let request_digest = request_digest("upgrade", namespace, manifest, "")?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some(existing) = replay(&tx, namespace, actor, request_id, &request_digest)? {
            return existing
                .ok_or_else(|| "idempotent upgrade no longer has an active installation".into());
        }
        let current = load_installation(&tx, namespace, &manifest.name)?
            .ok_or_else(|| "package is not installed in namespace".to_string())?;
        let current_version = parse_package_version(&current.current_version)
            .ok_or_else(|| "installed package version is invalid".to_string())?;
        let next_version = parse_package_version(&manifest.version)
            .ok_or_else(|| "upgrade package version is invalid".to_string())?;
        if next_version <= current_version {
            return Err("upgrade version must be newer than the installed version".into());
        }
        store_manifest(&tx, namespace, manifest, &manifest_digest, now_ms)?;
        tx.execute(
            "UPDATE sekai_capability_package_installations SET previous_version=current_version,current_version=?1,state='active',updated_by=?2,updated_at_ms=?3 WHERE namespace=?4 AND package_name=?5",
            params![manifest.version, actor, now_ms, namespace, manifest.name],
        ).map_err(|error| error.to_string())?;
        append_event(
            &tx,
            namespace,
            manifest,
            "upgrade",
            actor,
            request_id,
            &request_digest,
            &manifest_digest,
            "manifest_validated",
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        drop(conn);
        self.get_capability_package(namespace, &manifest.name)?
            .ok_or_else(|| "package installation missing after commit".into())
    }

    pub fn rollback_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        self.transition_capability_package(
            namespace,
            package_name,
            "rollback",
            actor,
            request_id,
            now_ms,
        )
    }

    pub fn disable_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        self.transition_capability_package(
            namespace,
            package_name,
            "disable",
            actor,
            request_id,
            now_ms,
        )
    }

    pub fn uninstall_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        validate_context(namespace, actor, request_id)?;
        let request_digest = simple_request_digest("uninstall", namespace, package_name);
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some(original_result) = replay(&tx, namespace, actor, request_id, &request_digest)? {
            if original_result.is_none()
                && load_installation(&tx, namespace, package_name)?.is_none()
            {
                return Ok(());
            }
            return Err("stale uninstall retry conflicts with a newer installation".into());
        }
        let current = load_installation(&tx, namespace, package_name)?
            .ok_or_else(|| "package is not installed in namespace".to_string())?;
        let (manifest, stored_digest) =
            load_manifest_record(&tx, namespace, package_name, &current.current_version)?;
        let digest = manifest.digest()?;
        if digest != stored_digest {
            return Err("capability package manifest digest mismatch".into());
        }
        tx.execute("DELETE FROM sekai_capability_package_installations WHERE namespace=?1 AND package_name=?2", params![namespace, package_name]).map_err(|error| error.to_string())?;
        append_event(
            &tx,
            namespace,
            &manifest,
            "uninstall",
            actor,
            request_id,
            &request_digest,
            &digest,
            "history_retained",
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn evaluate_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        validate_context(namespace, actor, request_id)?;
        let request_digest = simple_request_digest("evaluate", namespace, package_name);
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if replay(&tx, namespace, actor, request_id, &request_digest)?.is_some() {
            return Ok(true);
        }
        let current = load_installation(&tx, namespace, package_name)?
            .ok_or_else(|| "package is not installed in namespace".to_string())?;
        if current.state != "active" {
            return Err("disabled package cannot be evaluated".into());
        }
        let (manifest, stored_digest) =
            load_manifest_record(&tx, namespace, package_name, &current.current_version)?;
        let digest = manifest.digest()?;
        if digest != stored_digest {
            return Err("capability package manifest digest mismatch".into());
        }
        let checks_run = run_eval_suites(&manifest)?;
        append_event(
            &tx,
            namespace,
            &manifest,
            "evaluate",
            actor,
            request_id,
            &request_digest,
            &digest,
            &format!("{checks_run}_checks_passed"),
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    fn transition_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
        action: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageInstallation, String> {
        validate_context(namespace, actor, request_id)?;
        let request_digest = simple_request_digest(action, namespace, package_name);
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some(existing) = replay(&tx, namespace, actor, request_id, &request_digest)? {
            return existing.ok_or_else(|| {
                "idempotent transition no longer has an active installation".into()
            });
        }
        let current = load_installation(&tx, namespace, package_name)?
            .ok_or_else(|| "package is not installed in namespace".to_string())?;
        let (version, previous, state) = match action {
            "rollback" if !current.previous_version.is_empty() => {
                (current.previous_version.clone(), String::new(), "active")
            }
            "rollback" => return Err("package has no previous version to roll back to".into()),
            "disable" if current.state == "active" => (
                current.current_version.clone(),
                current.previous_version.clone(),
                "disabled",
            ),
            "disable" => return Err("package is already disabled".into()),
            _ => return Err("unsupported package transition".into()),
        };
        let (manifest, stored_digest) =
            load_manifest_record(&tx, namespace, package_name, &version)?;
        let digest = manifest.digest()?;
        if digest != stored_digest {
            return Err("capability package manifest digest mismatch".into());
        }
        tx.execute("UPDATE sekai_capability_package_installations SET current_version=?1,previous_version=?2,state=?3,updated_by=?4,updated_at_ms=?5 WHERE namespace=?6 AND package_name=?7", params![version, previous, state, actor, now_ms, namespace, package_name]).map_err(|error| error.to_string())?;
        append_event(
            &tx,
            namespace,
            &manifest,
            action,
            actor,
            request_id,
            &request_digest,
            &digest,
            "transition_applied",
            now_ms,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        drop(conn);
        self.get_capability_package(namespace, package_name)?
            .ok_or_else(|| "package installation missing after commit".into())
    }

    pub fn get_capability_package(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Option<PackageInstallation>, String> {
        load_installation(&self.conn(), namespace, package_name)
    }

    pub fn get_capability_package_manifest(
        &self,
        namespace: &str,
        package_name: &str,
        version: &str,
    ) -> Result<Option<CapabilityPackageManifest>, String> {
        let conn = self.conn();
        conn.query_row("SELECT manifest_json FROM sekai_capability_package_versions WHERE namespace=?1 AND package_name=?2 AND package_version=?3", params![namespace, package_name, version], |row| row.get::<_, String>(0)).optional().map_err(|error| error.to_string())?.map(|json| serde_json::from_str(&json).map_err(|error| error.to_string())).transpose()
    }

    pub fn list_capability_package_events(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Vec<PackageLifecycleEvent>, String> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT sequence,namespace,package_name,package_version,action,actor,request_id,manifest_digest,evidence,recorded_at_ms FROM sekai_capability_package_events WHERE namespace=?1 AND package_name=?2 ORDER BY sequence").map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace, package_name], |row| {
                Ok(PackageLifecycleEvent {
                    sequence: row.get(0)?,
                    namespace: row.get(1)?,
                    package_name: row.get(2)?,
                    package_version: row.get(3)?,
                    action: row.get(4)?,
                    actor: row.get(5)?,
                    request_id: row.get(6)?,
                    manifest_digest: row.get(7)?,
                    evidence: row.get(8)?,
                    recorded_at_ms: row.get(9)?,
                })
            })
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())
    }
}

fn run_eval_suites(manifest: &CapabilityPackageManifest) -> Result<usize, String> {
    let mut checks_run = 0;
    for suite in manifest
        .components
        .iter()
        .filter(|component| component.kind == "eval_suite")
    {
        let checks = suite.definition["checks"]
            .as_array()
            .ok_or_else(|| "eval suite checks missing after validation".to_string())?;
        for check in checks {
            match check.as_str().unwrap_or_default() {
                "manifest_digest" => {}
                "component_bounds" => manifest.validate()?,
                "category_present" => {
                    let present = manifest.components.iter().any(|component| {
                        component.kind == "schema"
                            && component.definition["properties"].as_array().is_some_and(
                                |properties| {
                                    properties.iter().any(|property| property == "category")
                                },
                            )
                    });
                    if !present {
                        return Err("category_present evaluation check failed".into());
                    }
                }
                _ => return Err("unsupported evaluation check".into()),
            }
            checks_run += 1;
        }
    }
    if checks_run == 0 {
        return Err("package has no evaluation checks".into());
    }
    Ok(checks_run)
}

fn validate_context(namespace: &str, actor: &str, request_id: &str) -> Result<(), String> {
    if namespace.trim().is_empty() || actor.trim().is_empty() || request_id.trim().is_empty() {
        return Err("namespace, actor, and request_id are required".into());
    }
    Ok(())
}

fn store_manifest(
    tx: &Transaction<'_>,
    namespace: &str,
    manifest: &CapabilityPackageManifest,
    digest: &str,
    now_ms: i64,
) -> Result<(), String> {
    let json = serde_json::to_string(manifest).map_err(|error| error.to_string())?;
    let existing: Option<String> = tx.query_row("SELECT manifest_digest FROM sekai_capability_package_versions WHERE namespace=?1 AND package_name=?2 AND package_version=?3", params![namespace, manifest.name, manifest.version], |row| row.get(0)).optional().map_err(|error| error.to_string())?;
    if existing
        .as_deref()
        .is_some_and(|existing| existing != digest)
    {
        return Err("package version is immutable".into());
    }
    tx.execute("INSERT OR IGNORE INTO sekai_capability_package_versions(namespace,package_name,package_version,manifest_json,manifest_digest,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6)", params![namespace, manifest.name, manifest.version, json, digest, now_ms]).map_err(|error| error.to_string())?;
    Ok(())
}

fn load_manifest_record(
    tx: &Transaction<'_>,
    namespace: &str,
    name: &str,
    version: &str,
) -> Result<(CapabilityPackageManifest, String), String> {
    let (json, digest): (String, String) = tx.query_row("SELECT manifest_json,manifest_digest FROM sekai_capability_package_versions WHERE namespace=?1 AND package_name=?2 AND package_version=?3", params![namespace, name, version], |row| Ok((row.get(0)?, row.get(1)?))).map_err(|error| error.to_string())?;
    Ok((
        serde_json::from_str(&json).map_err(|error| error.to_string())?,
        digest,
    ))
}

fn load_installation(
    conn: &rusqlite::Connection,
    namespace: &str,
    name: &str,
) -> Result<Option<PackageInstallation>, String> {
    conn.query_row("SELECT namespace,package_name,current_version,previous_version,state,installed_by,updated_by,installed_at_ms,updated_at_ms FROM sekai_capability_package_installations WHERE namespace=?1 AND package_name=?2", params![namespace, name], |row| Ok(PackageInstallation { namespace: row.get(0)?, package_name: row.get(1)?, current_version: row.get(2)?, previous_version: row.get(3)?, state: row.get(4)?, installed_by: row.get(5)?, updated_by: row.get(6)?, installed_at_ms: row.get(7)?, updated_at_ms: row.get(8)? })).optional().map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn append_event(
    tx: &Transaction<'_>,
    namespace: &str,
    manifest: &CapabilityPackageManifest,
    action: &str,
    actor: &str,
    request_id: &str,
    request_digest: &str,
    manifest_digest: &str,
    evidence: &str,
    now_ms: i64,
) -> Result<(), String> {
    let result_json = serde_json::to_string(&load_installation(tx, namespace, &manifest.name)?)
        .map_err(|error| error.to_string())?;
    tx.execute("INSERT INTO sekai_capability_package_events(namespace,package_name,package_version,action,actor,request_id,request_digest,manifest_digest,evidence,result_json,recorded_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![namespace, manifest.name, manifest.version, action, actor, request_id, request_digest, manifest_digest, evidence, result_json, now_ms]).map_err(|error| error.to_string())?;
    let audit_evidence = HashMap::from([
        ("namespace".into(), namespace.into()),
        ("package_name".into(), manifest.name.clone()),
        ("package_version".into(), manifest.version.clone()),
        ("manifest_digest".into(), manifest_digest.into()),
        ("request_id".into(), request_id.into()),
        ("lifecycle_evidence".into(), evidence.into()),
    ]);
    crate::sekai::ledger::insert_chained_decision(
        tx,
        &Decision {
            id: format!(
                "capability-package:{:x}",
                Sha256::digest(format!("{namespace}\0{actor}\0{request_id}"))
            ),
            timestamp: now_ms,
            actor: actor.into(),
            action: format!("capability_package.{action}"),
            reason: "governed capability package lifecycle transition".into(),
            evidence: audit_evidence,
            target_id: format!("capability-package:{namespace}:{}", manifest.name),
            outcome: "succeeded".into(),
        },
    )?;
    Ok(())
}

fn replay(
    tx: &Transaction<'_>,
    namespace: &str,
    actor: &str,
    request_id: &str,
    expected_digest: &str,
) -> Result<Option<Option<PackageInstallation>>, String> {
    let prior: Option<(String, String)> = tx.query_row("SELECT request_digest,result_json FROM sekai_capability_package_events WHERE namespace=?1 AND actor=?2 AND request_id=?3", params![namespace, actor, request_id], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(|error| error.to_string())?;
    match prior {
        None => Ok(None),
        Some((digest, _)) if digest != expected_digest => {
            Err("request_id was already used for different package input".into())
        }
        Some((_, result_json)) => Ok(Some(
            serde_json::from_str(&result_json).map_err(|error| error.to_string())?,
        )),
    }
}

fn request_digest(
    action: &str,
    namespace: &str,
    manifest: &CapabilityPackageManifest,
    extra: &str,
) -> Result<String, String> {
    let json = serde_json::to_string(manifest).map_err(|error| error.to_string())?;
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(format!("{action}\0{namespace}\0{json}\0{extra}"))
    ))
}

fn simple_request_digest(action: &str, namespace: &str, package_name: &str) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(format!("{action}\0{namespace}\0{package_name}"))
    )
}
