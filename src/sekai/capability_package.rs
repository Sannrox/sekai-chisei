use crate::db::sekai::SekaiDb;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

use crate::sekai::audit::Decision;

pub const MANIFEST_VERSION: &str = "sekai.capability-package/v1";
pub const PACKAGE_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const PACKAGE_TRUST_UNSIGNED_ALLOWED: &str = "unsigned_allowed";
pub const PACKAGE_TRUST_SIGNED: &str = "signed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageComponent {
    pub kind: String,
    pub name: String,
    pub definition: serde_json::Value,
}

/// Optional ed25519 signature over the unsigned manifest digest.
/// Excluded from `digest()` so the signature cannot depend on itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PackageSignature {
    pub algorithm: String,
    pub signer_identity: String,
    pub key_id: String,
    /// Base64 (standard) encoding of the 64-byte ed25519 signature.
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPackageManifest {
    pub manifest_version: String,
    pub name: String,
    pub version: String,
    pub components: Vec<PackageComponent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PackageSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageTrustPolicy {
    pub namespace: String,
    /// `unsigned_allowed` (default/grandfather) or `signed`.
    pub required_trust_level: String,
    pub updated_by: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSigner {
    pub namespace: String,
    pub identity: String,
    pub key_id: String,
    /// Base64 of the 32-byte ed25519 verifying key.
    pub public_key_b64: String,
    pub created_by: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageTrustDecision {
    pub allowed: bool,
    pub required_trust_level: String,
    pub signature_present: bool,
    pub signature_valid: bool,
    pub signer_identity: String,
    pub key_id: String,
    pub reason: String,
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
        let mut unsigned = self.clone();
        unsigned.signature = None;
        let bytes = serde_json::to_vec(&unsigned).map_err(|error| error.to_string())?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    /// Sign the unsigned digest with an ed25519 signing key.
    pub fn sign(
        &mut self,
        signer_identity: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Result<(), String> {
        let digest = self.digest()?;
        let signature = signing_key.sign(digest.as_bytes());
        self.signature = Some(PackageSignature {
            algorithm: PACKAGE_SIGNATURE_ALGORITHM.into(),
            signer_identity: signer_identity.into(),
            key_id: key_id.into(),
            signature_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                signature.to_bytes().as_ref(),
            ),
        });
        Ok(())
    }
}

/// Evaluate whether a package may be installed under the namespace trust policy.
pub fn evaluate_package_trust(
    policy_level: &str,
    trusted_signers: &[(String, String, VerifyingKey)],
    manifest: &CapabilityPackageManifest,
) -> Result<PackageTrustDecision, String> {
    let level = if policy_level.is_empty() {
        PACKAGE_TRUST_UNSIGNED_ALLOWED
    } else {
        policy_level
    };
    if level != PACKAGE_TRUST_UNSIGNED_ALLOWED && level != PACKAGE_TRUST_SIGNED {
        return Err(format!("unsupported package trust level: {level}"));
    }
    let Some(signature) = &manifest.signature else {
        let allowed = level == PACKAGE_TRUST_UNSIGNED_ALLOWED;
        return Ok(PackageTrustDecision {
            allowed,
            required_trust_level: level.into(),
            signature_present: false,
            signature_valid: false,
            signer_identity: String::new(),
            key_id: String::new(),
            reason: if allowed {
                "unsigned package allowed by namespace policy".into()
            } else {
                "signed package required by namespace policy".into()
            },
        });
    };
    if signature.algorithm != PACKAGE_SIGNATURE_ALGORITHM {
        return Ok(PackageTrustDecision {
            allowed: false,
            required_trust_level: level.into(),
            signature_present: true,
            signature_valid: false,
            signer_identity: signature.signer_identity.clone(),
            key_id: signature.key_id.clone(),
            reason: format!(
                "unsupported package signature algorithm {}",
                signature.algorithm
            ),
        });
    }
    // Signature parse/decode failures are trust denials (attacker-controlled
    // material), not hard errors — return denied decisions so install/upgrade
    // callers can record lifecycle evidence consistently.
    let digest = match manifest.digest() {
        Ok(digest) => digest,
        Err(error) => {
            return Ok(PackageTrustDecision {
                allowed: false,
                required_trust_level: level.into(),
                signature_present: true,
                signature_valid: false,
                signer_identity: signature.signer_identity.clone(),
                key_id: signature.key_id.clone(),
                reason: format!("manifest digest unavailable for verification: {error}"),
            });
        }
    };
    let signature_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        signature.signature_b64.as_bytes(),
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok(PackageTrustDecision {
                allowed: false,
                required_trust_level: level.into(),
                signature_present: true,
                signature_valid: false,
                signer_identity: signature.signer_identity.clone(),
                key_id: signature.key_id.clone(),
                reason: format!("invalid package signature encoding: {error}"),
            });
        }
    };
    let signature_array: [u8; 64] = match signature_bytes.as_slice().try_into() {
        Ok(array) => array,
        Err(_) => {
            return Ok(PackageTrustDecision {
                allowed: false,
                required_trust_level: level.into(),
                signature_present: true,
                signature_valid: false,
                signer_identity: signature.signer_identity.clone(),
                key_id: signature.key_id.clone(),
                reason: "package signature must be 64 bytes".into(),
            });
        }
    };
    let ed_signature = Signature::from_bytes(&signature_array);
    let trusted = trusted_signers.iter().find(|(identity, key_id, _)| {
        identity == &signature.signer_identity && key_id == &signature.key_id
    });
    let Some((_, _, verifying_key)) = trusted else {
        // A supplied signature must always bind to a registered key, even under
        // unsigned_allowed (which only makes signatures optional, not free-form).
        return Ok(PackageTrustDecision {
            allowed: false,
            required_trust_level: level.into(),
            signature_present: true,
            signature_valid: false,
            signer_identity: signature.signer_identity.clone(),
            key_id: signature.key_id.clone(),
            reason: format!(
                "signer {} key {} is not trusted for this namespace",
                signature.signer_identity, signature.key_id
            ),
        });
    };
    let valid = verifying_key
        .verify(digest.as_bytes(), &ed_signature)
        .is_ok();
    Ok(PackageTrustDecision {
        allowed: valid,
        required_trust_level: level.into(),
        signature_present: true,
        signature_valid: valid,
        signer_identity: signature.signer_identity.clone(),
        key_id: signature.key_id.clone(),
        reason: if valid {
            format!(
                "valid signature from trusted signer {}/{}",
                signature.signer_identity, signature.key_id
            )
        } else {
            "package signature verification failed".into()
        },
    })
}

pub fn package_trust_evidence(decision: &PackageTrustDecision) -> String {
    // Structured JSON so attacker-controlled signer/key/reason values cannot
    // inject delimiters into a semicolon-separated audit string.
    serde_json::json!({
        "trust_level": decision.required_trust_level,
        "signature_present": decision.signature_present,
        "signature_valid": decision.signature_valid,
        "signer": decision.signer_identity,
        "key_id": decision.key_id,
        "reason": decision.reason,
        "allowed": decision.allowed,
    })
    .to_string()
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

pub(crate) fn parse_package_version(value: &str) -> Option<(u64, u64, u64)> {
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
                    ON sekai_capability_package_events(namespace, package_name, sequence);
                CREATE TABLE IF NOT EXISTS sekai_capability_package_trust_policy (
                    namespace TEXT PRIMARY KEY,
                    required_trust_level TEXT NOT NULL
                        CHECK(required_trust_level IN ('unsigned_allowed','signed')),
                    updated_by TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sekai_capability_package_signers (
                    namespace TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    public_key_b64 TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, identity, key_id)
                );",
            )
            .map_err(|error| error.to_string())
    }

    pub fn set_capability_package_trust_policy(
        &self,
        namespace: &str,
        required_trust_level: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageTrustPolicy, String> {
        if namespace.trim().is_empty() || actor.trim().is_empty() || request_id.trim().is_empty() {
            return Err("namespace, actor, and request_id required".into());
        }
        if required_trust_level != PACKAGE_TRUST_UNSIGNED_ALLOWED
            && required_trust_level != PACKAGE_TRUST_SIGNED
        {
            return Err(format!(
                "required_trust_level must be {PACKAGE_TRUST_UNSIGNED_ALLOWED} or {PACKAGE_TRUST_SIGNED}"
            ));
        }
        self.migrate_capability_packages()?;
        let request_digest = format!(
            "sha256:{:x}",
            Sha256::digest(format!(
                "trust_policy\0{namespace}\0{required_trust_level}\0{request_id}"
            ))
        );
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some((prior_digest, result_json)) = tx
            .query_row(
                "SELECT request_digest,result_json FROM sekai_capability_package_events
                 WHERE namespace=?1 AND actor=?2 AND request_id=?3",
                params![namespace, actor, request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
        {
            if prior_digest != request_digest {
                return Err("request_id was already used for different trust policy input".into());
            }
            return serde_json::from_str(&result_json).map_err(|error| error.to_string());
        }
        let policy = PackageTrustPolicy {
            namespace: namespace.into(),
            required_trust_level: required_trust_level.into(),
            updated_by: actor.into(),
            updated_at_ms: now_ms,
        };
        tx.execute(
            "INSERT INTO sekai_capability_package_trust_policy(namespace,required_trust_level,updated_by,updated_at_ms)
             VALUES(?1,?2,?3,?4)
             ON CONFLICT(namespace) DO UPDATE SET
               required_trust_level=excluded.required_trust_level,
               updated_by=excluded.updated_by,
               updated_at_ms=excluded.updated_at_ms",
            params![namespace, required_trust_level, actor, now_ms],
        )
        .map_err(|error| error.to_string())?;
        let evidence =
            format!("trust_policy_set;required_trust_level={required_trust_level};actor={actor}");
        let result_json = serde_json::to_string(&policy).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_capability_package_events
             (namespace,package_name,package_version,action,actor,request_id,request_digest,manifest_digest,evidence,result_json,recorded_at_ms)
             VALUES(?1,'__trust_policy__','0.0.0','trust_policy',?2,?3,?4,'',?5,?6,?7)",
            params![
                namespace,
                actor,
                request_id,
                request_digest,
                evidence,
                result_json,
                now_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        let audit_evidence = HashMap::from([
            ("namespace".into(), namespace.into()),
            ("required_trust_level".into(), required_trust_level.into()),
            ("request_id".into(), request_id.into()),
            ("lifecycle_evidence".into(), evidence),
        ]);
        crate::sekai::ledger::insert_chained_decision(
            &tx,
            &Decision {
                id: format!(
                    "capability-package-trust-policy:{:x}",
                    Sha256::digest(format!("{namespace}\0{actor}\0{request_id}"))
                ),
                timestamp: now_ms,
                actor: actor.into(),
                action: "capability_package.trust_policy".into(),
                reason: "namespace capability-package trust policy change".into(),
                evidence: audit_evidence,
                target_id: format!("capability-package-trust:{namespace}"),
                outcome: "succeeded".into(),
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(policy)
    }

    pub fn get_capability_package_trust_policy(
        &self,
        namespace: &str,
    ) -> Result<PackageTrustPolicy, String> {
        self.migrate_capability_packages()?;
        let conn = self.conn();
        let policy = conn
            .query_row(
                "SELECT namespace,required_trust_level,updated_by,updated_at_ms
                 FROM sekai_capability_package_trust_policy WHERE namespace=?1",
                params![namespace],
                |row| {
                    Ok(PackageTrustPolicy {
                        namespace: row.get(0)?,
                        required_trust_level: row.get(1)?,
                        updated_by: row.get(2)?,
                        updated_at_ms: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        Ok(policy.unwrap_or(PackageTrustPolicy {
            namespace: namespace.into(),
            required_trust_level: PACKAGE_TRUST_UNSIGNED_ALLOWED.into(),
            updated_by: "system".into(),
            updated_at_ms: 0,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put_capability_package_signer(
        &self,
        namespace: &str,
        identity: &str,
        key_id: &str,
        public_key_b64: &str,
        actor: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<PackageSigner, String> {
        if namespace.trim().is_empty()
            || identity.trim().is_empty()
            || key_id.trim().is_empty()
            || actor.trim().is_empty()
            || request_id.trim().is_empty()
        {
            return Err("namespace, identity, key_id, actor, and request_id required".into());
        }
        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            public_key_b64.as_bytes(),
        )
        .map_err(|error| format!("invalid public key encoding: {error}"))?;
        let key_array: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "ed25519 public key must be 32 bytes".to_string())?;
        let _ = VerifyingKey::from_bytes(&key_array)
            .map_err(|error| format!("invalid ed25519 public key: {error}"))?;
        self.migrate_capability_packages()?;
        let request_digest = format!(
            "sha256:{:x}",
            Sha256::digest(format!(
                "trust_signer\0{namespace}\0{identity}\0{key_id}\0{public_key_b64}\0{request_id}"
            ))
        );
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        if let Some((prior_digest, result_json)) = tx
            .query_row(
                "SELECT request_digest,result_json FROM sekai_capability_package_events
                 WHERE namespace=?1 AND actor=?2 AND request_id=?3",
                params![namespace, actor, request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
        {
            if prior_digest != request_digest {
                return Err("request_id was already used for different trust signer input".into());
            }
            return serde_json::from_str(&result_json).map_err(|error| error.to_string());
        }
        let signer = PackageSigner {
            namespace: namespace.into(),
            identity: identity.into(),
            key_id: key_id.into(),
            public_key_b64: public_key_b64.into(),
            created_by: actor.into(),
            created_at_ms: now_ms,
        };
        tx.execute(
            "INSERT INTO sekai_capability_package_signers
             (namespace,identity,key_id,public_key_b64,created_by,created_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(namespace,identity,key_id) DO UPDATE SET
               public_key_b64=excluded.public_key_b64,
               created_by=excluded.created_by,
               created_at_ms=excluded.created_at_ms",
            params![namespace, identity, key_id, public_key_b64, actor, now_ms],
        )
        .map_err(|error| error.to_string())?;
        let evidence = format!("signer_put;identity={identity};key_id={key_id};actor={actor}");
        let result_json = serde_json::to_string(&signer).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_capability_package_events
             (namespace,package_name,package_version,action,actor,request_id,request_digest,manifest_digest,evidence,result_json,recorded_at_ms)
             VALUES(?1,'__trust_signer__','0.0.0','trust_signer',?2,?3,?4,'',?5,?6,?7)",
            params![
                namespace,
                actor,
                request_id,
                request_digest,
                evidence,
                result_json,
                now_ms
            ],
        )
        .map_err(|error| error.to_string())?;
        let audit_evidence = HashMap::from([
            ("namespace".into(), namespace.into()),
            ("signer_identity".into(), identity.into()),
            ("key_id".into(), key_id.into()),
            ("request_id".into(), request_id.into()),
            ("lifecycle_evidence".into(), evidence),
        ]);
        crate::sekai::ledger::insert_chained_decision(
            &tx,
            &Decision {
                id: format!(
                    "capability-package-trust-signer:{:x}",
                    Sha256::digest(format!("{namespace}\0{actor}\0{request_id}"))
                ),
                timestamp: now_ms,
                actor: actor.into(),
                action: "capability_package.trust_signer".into(),
                reason: "namespace capability-package trusted signer put".into(),
                evidence: audit_evidence,
                target_id: format!("capability-package-trust:{namespace}"),
                outcome: "succeeded".into(),
            },
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(signer)
    }

    pub fn list_capability_package_signers(
        &self,
        namespace: &str,
    ) -> Result<Vec<PackageSigner>, String> {
        self.migrate_capability_packages()?;
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT namespace,identity,key_id,public_key_b64,created_by,created_at_ms
                 FROM sekai_capability_package_signers WHERE namespace=?1
                 ORDER BY identity, key_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| {
                Ok(PackageSigner {
                    namespace: row.get(0)?,
                    identity: row.get(1)?,
                    key_id: row.get(2)?,
                    public_key_b64: row.get(3)?,
                    created_by: row.get(4)?,
                    created_at_ms: row.get(5)?,
                })
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Ok(rows)
    }

    fn load_package_trust_signers_tx(
        tx: &Transaction<'_>,
        namespace: &str,
    ) -> Result<Vec<(String, String, VerifyingKey)>, String> {
        let mut stmt = tx
            .prepare(
                "SELECT identity,key_id,public_key_b64 FROM sekai_capability_package_signers
                 WHERE namespace=?1 ORDER BY identity, key_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        let mut keys = Vec::new();
        for (identity, key_id, public_key_b64) in rows {
            let key_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                public_key_b64.as_bytes(),
            )
            .map_err(|error| format!("stored signer key invalid: {error}"))?;
            let key_array: [u8; 32] = key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "stored signer key must be 32 bytes".to_string())?;
            let verifying = VerifyingKey::from_bytes(&key_array)
                .map_err(|error| format!("stored signer key invalid: {error}"))?;
            keys.push((identity, key_id, verifying));
        }
        Ok(keys)
    }

    fn load_package_trust_policy_tx(
        tx: &Transaction<'_>,
        namespace: &str,
    ) -> Result<PackageTrustPolicy, String> {
        let policy = tx
            .query_row(
                "SELECT namespace,required_trust_level,updated_by,updated_at_ms
                 FROM sekai_capability_package_trust_policy WHERE namespace=?1",
                params![namespace],
                |row| {
                    Ok(PackageTrustPolicy {
                        namespace: row.get(0)?,
                        required_trust_level: row.get(1)?,
                        updated_by: row.get(2)?,
                        updated_at_ms: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        Ok(policy.unwrap_or(PackageTrustPolicy {
            namespace: namespace.into(),
            required_trust_level: PACKAGE_TRUST_UNSIGNED_ALLOWED.into(),
            updated_by: "system".into(),
            updated_at_ms: 0,
        }))
    }

    /// Evaluate package trust inside an open transaction.
    ///
    /// Returns the decision even when denied so callers can record audit
    /// evidence after rolling back the mutation transaction.
    fn evaluate_package_trust_tx(
        tx: &Transaction<'_>,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
    ) -> Result<PackageTrustDecision, String> {
        let policy = Self::load_package_trust_policy_tx(tx, namespace)?;
        let signers = Self::load_package_trust_signers_tx(tx, namespace)?;
        evaluate_package_trust(&policy.required_trust_level, &signers, manifest)
    }

    /// Record a denied trust decision without installing the package.
    ///
    /// Uses the original install/upgrade `request_digest` so retries stay inside
    /// the existing `(namespace, actor, request_id)` idempotency keyspace and
    /// replay the same denial instead of looking like a conflicting request.
    #[allow(clippy::too_many_arguments)]
    pub fn record_package_trust_denial(
        &self,
        namespace: &str,
        manifest: &CapabilityPackageManifest,
        actor: &str,
        request_id: &str,
        operation_request_digest: &str,
        decision: &PackageTrustDecision,
        now_ms: i64,
    ) -> Result<(), String> {
        self.migrate_capability_packages()?;
        let evidence = package_trust_evidence(decision);
        let denial_error = format!("package trust denied: {}", decision.reason);
        let result_json =
            serde_json::to_string(&serde_json::json!({"error": denial_error}))
                .map_err(|error| error.to_string())?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        // Best-effort: ignore unique conflicts on retry of the same denial.
        let _ = tx.execute(
            "INSERT OR IGNORE INTO sekai_capability_package_events
             (namespace,package_name,package_version,action,actor,request_id,request_digest,manifest_digest,evidence,result_json,recorded_at_ms)
             VALUES(?1,?2,?3,'trust_denied',?4,?5,?6,?7,?8,?9,?10)",
            params![
                namespace,
                manifest.name,
                manifest.version,
                actor,
                request_id,
                operation_request_digest,
                manifest.digest().unwrap_or_default(),
                evidence,
                result_json,
                now_ms
            ],
        );
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
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
        let trust = Self::evaluate_package_trust_tx(&tx, namespace, manifest)?;
        if !trust.allowed {
            let error = format!("package trust denied: {}", trust.reason);
            drop(tx);
            drop(conn);
            let _ = self.record_package_trust_denial(
                namespace,
                manifest,
                actor,
                request_id,
                &request_digest,
                &trust,
                now_ms,
            );
            return Err(error);
        }
        let trust_evidence = package_trust_evidence(&trust);
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
            &format!("manifest_validated;{trust_evidence}"),
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
        let trust = Self::evaluate_package_trust_tx(&tx, namespace, manifest)?;
        if !trust.allowed {
            let error = format!("package trust denied: {}", trust.reason);
            drop(tx);
            drop(conn);
            let _ = self.record_package_trust_denial(
                namespace,
                manifest,
                actor,
                request_id,
                &request_digest,
                &trust,
                now_ms,
            );
            return Err(error);
        }
        let trust_evidence = package_trust_evidence(&trust);
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
            &format!("manifest_validated;{trust_evidence}"),
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

    pub fn list_capability_package_decisions(
        &self,
        namespace: &str,
        package_name: &str,
    ) -> Result<Vec<Decision>, String> {
        self.list_decisions(&crate::sekai::audit::DecisionFilter {
            target_id: Some(format!("capability-package:{namespace}:{package_name}")),
            ..crate::sekai::audit::DecisionFilter::default()
        })
    }
}

pub(crate) fn run_eval_suites(manifest: &CapabilityPackageManifest) -> Result<usize, String> {
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

pub(crate) fn validate_context(
    namespace: &str,
    actor: &str,
    request_id: &str,
) -> Result<(), String> {
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
    let existing: Option<(String, String)> = tx
        .query_row(
            "SELECT manifest_digest,manifest_json FROM sekai_capability_package_versions
             WHERE namespace=?1 AND package_name=?2 AND package_version=?3",
            params![namespace, manifest.name, manifest.version],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if let Some((existing_digest, existing_json)) = existing {
        if existing_digest != digest {
            return Err("package version is immutable".into());
        }
        // Same unsigned content must also keep the same signature provenance so
        // reinstalls cannot leave a stale signer on record.
        if existing_json != json {
            return Err(
                "package version signature/provenance must match the previously stored manifest"
                    .into(),
            );
        }
        return Ok(());
    }
    tx.execute(
        "INSERT INTO sekai_capability_package_versions
         (namespace,package_name,package_version,manifest_json,manifest_digest,created_at_ms)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            namespace,
            manifest.name,
            manifest.version,
            json,
            digest,
            now_ms
        ],
    )
    .map_err(|error| error.to_string())?;
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
    let prior: Option<(String, String, String)> = tx
        .query_row(
            "SELECT request_digest,result_json,action FROM sekai_capability_package_events
             WHERE namespace=?1 AND actor=?2 AND request_id=?3",
            params![namespace, actor, request_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    match prior {
        None => Ok(None),
        Some((digest, _, _)) if digest != expected_digest => {
            Err("request_id was already used for different package input".into())
        }
        Some((_, result_json, action)) if action == "trust_denied" => {
            Err(parse_trust_denial_error(&result_json))
        }
        Some((_, result_json, _)) => Ok(Some(
            serde_json::from_str(&result_json).map_err(|error| error.to_string())?,
        )),
    }
}

fn parse_trust_denial_error(result_json: &str) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(result_json)
        && let Some(error) = value.get("error").and_then(|item| item.as_str())
    {
        return error.to_string();
    }
    "package trust denied (idempotent replay of prior denial)".into()
}

pub(crate) fn request_digest(
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

pub(crate) fn simple_request_digest(action: &str, namespace: &str, package_name: &str) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(format!("{action}\0{namespace}\0{package_name}"))
    )
}

#[cfg(test)]
mod package_trust_tests {
    use super::*;

    fn sample_manifest(name: &str, version: &str) -> CapabilityPackageManifest {
        CapabilityPackageManifest {
            manifest_version: MANIFEST_VERSION.into(),
            name: name.into(),
            version: version.into(),
            components: vec![PackageComponent {
                kind: "policy_default".into(),
                name: "default-allow".into(),
                definition: serde_json::json!({"decision": "allow"}),
            }],
            signature: None,
        }
    }

    #[test]
    fn unsigned_packages_install_under_default_policy() {
        let db = SekaiDb::new(":memory:").unwrap();
        let manifest = sample_manifest("demo-pkg", "1.0.0");
        let installed = db
            .install_capability_package("ns", &manifest, "operator", "install-1", 10)
            .unwrap();
        assert_eq!(installed.current_version, "1.0.0");
    }

    #[test]
    fn unsigned_allowed_still_rejects_unregistered_signer() {
        // Signatures are optional under unsigned_allowed, but a supplied
        // signature must still bind to a registered key (or be omitted).
        let db = SekaiDb::new(":memory:").unwrap();
        let mut manifest = sample_manifest("optional-sig", "1.0.0");
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        manifest
            .sign("issuer:unknown", "key-x", &signing)
            .expect("sign");
        assert!(
            db.install_capability_package("ns", &manifest, "operator", "opt-1", 10)
                .unwrap_err()
                .contains("not trusted")
        );
    }

    #[test]
    fn trust_root_mutations_write_audit_decisions() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.set_capability_package_trust_policy("ns", PACKAGE_TRUST_SIGNED, "admin", "pol-1", 1)
            .unwrap();
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let public_key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signing.verifying_key().as_bytes(),
        );
        db.put_capability_package_signer(
            "ns",
            "issuer:ops",
            "key-1",
            &public_key_b64,
            "admin",
            "sig-1",
            2,
        )
        .unwrap();
        let decisions = db
            .list_capability_package_decisions("ns", "__trust_policy__")
            .unwrap();
        // Decisions are keyed by trust target, not package name; query via ledger
        // by scanning package-adjacent decisions through the events path is enough
        // when the event rows exist and decisions are non-empty for the trust target.
        let events = db
            .list_capability_package_events("ns", "__trust_policy__")
            .unwrap();
        assert!(events.iter().any(|event| event.action == "trust_policy"));
        let signer_events = db
            .list_capability_package_events("ns", "__trust_signer__")
            .unwrap();
        assert!(
            signer_events
                .iter()
                .any(|event| event.action == "trust_signer")
        );
        // Chained audit decisions use target_id capability-package-trust:{ns}.
        let conn = db.conn();
        let decision_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sekai_decisions
                 WHERE target_id=?1 AND action IN (
                   'capability_package.trust_policy','capability_package.trust_signer'
                 )",
                params!["capability-package-trust:ns"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(decision_count, 2);
        let _ = decisions;
    }

    #[test]
    fn signed_policy_rejects_unsigned_and_accepts_valid_signature() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.set_capability_package_trust_policy("ns", PACKAGE_TRUST_SIGNED, "admin", "policy-1", 5)
            .unwrap();
        let mut manifest = sample_manifest("signed-pkg", "1.0.0");
        assert!(
            db.install_capability_package("ns", &manifest, "operator", "u1", 10)
                .unwrap_err()
                .contains("signed package required")
        );

        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let public_key_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            verifying.as_bytes(),
        );
        db.put_capability_package_signer(
            "ns",
            "issuer:ops",
            "key-1",
            &public_key_b64,
            "admin",
            "signer-1",
            6,
        )
        .unwrap();
        manifest
            .sign("issuer:ops", "key-1", &signing)
            .expect("sign");
        let installed = db
            .install_capability_package("ns", &manifest, "operator", "s1", 20)
            .unwrap();
        assert_eq!(installed.package_name, "signed-pkg");

        let mut bad = sample_manifest("bad-pkg", "1.0.0");
        bad.sign("issuer:ops", "key-1", &signing).unwrap();
        if let Some(signature) = bad.signature.as_mut() {
            signature.signature_b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 64]);
        }
        assert!(
            db.install_capability_package("ns", &bad, "operator", "b1", 30)
                .unwrap_err()
                .contains("signature")
        );

        let mut untrusted = sample_manifest("other-pkg", "1.0.0");
        let other = SigningKey::from_bytes(&[9u8; 32]);
        untrusted.sign("issuer:evil", "key-x", &other).unwrap();
        assert!(
            db.install_capability_package("ns", &untrusted, "operator", "e1", 40)
                .unwrap_err()
                .contains("not trusted")
        );

        let denials = db
            .list_capability_package_events("ns", "signed-pkg")
            .unwrap();
        assert!(
            denials
                .iter()
                .any(|event| event.action == "trust_denied"),
            "unsigned install must record trust_denied"
        );
    }

    #[test]
    fn denied_install_replays_same_request_id() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.set_capability_package_trust_policy("ns", PACKAGE_TRUST_SIGNED, "admin", "policy-r", 1)
            .unwrap();
        let manifest = sample_manifest("replay-pkg", "1.0.0");
        let first = db
            .install_capability_package("ns", &manifest, "operator", "same-req", 2)
            .unwrap_err();
        assert!(first.contains("signed package required"));
        let second = db
            .install_capability_package("ns", &manifest, "operator", "same-req", 3)
            .unwrap_err();
        assert!(
            second.contains("signed package required"),
            "identical denial must replay, not conflict on request_id: {second}"
        );
        assert!(
            !second.contains("already used for different package input"),
            "denial must keep the original operation digest: {second}"
        );
    }

    #[test]
    fn malformed_signature_is_denied_and_audited() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.set_capability_package_trust_policy("ns", PACKAGE_TRUST_SIGNED, "admin", "policy-m", 1)
            .unwrap();
        let mut manifest = sample_manifest("malformed-pkg", "1.0.0");
        manifest.signature = Some(PackageSignature {
            algorithm: PACKAGE_SIGNATURE_ALGORITHM.into(),
            signer_identity: "issuer:ops".into(),
            key_id: "key-1".into(),
            signature_b64: "not-valid-base64!!!".into(),
        });
        assert!(
            db.install_capability_package("ns", &manifest, "operator", "mal-1", 2)
                .unwrap_err()
                .contains("signature encoding")
        );
        let events = db
            .list_capability_package_events("ns", "malformed-pkg")
            .unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.action == "trust_denied"),
            "malformed signature must record trust_denied"
        );
    }

    #[test]
    fn upgrade_trust_denial_is_audited() {
        let db = SekaiDb::new(":memory:").unwrap();
        let base = sample_manifest("upgrade-pkg", "1.0.0");
        db.install_capability_package("ns", &base, "operator", "base", 1)
            .unwrap();
        db.set_capability_package_trust_policy("ns", PACKAGE_TRUST_SIGNED, "admin", "policy-u", 2)
            .unwrap();
        let unsigned_upgrade = sample_manifest("upgrade-pkg", "1.1.0");
        assert!(
            db.upgrade_capability_package("ns", &unsigned_upgrade, "operator", "up-deny", 3)
                .unwrap_err()
                .contains("signed package required")
        );
        let events = db
            .list_capability_package_events("ns", "upgrade-pkg")
            .unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.action == "trust_denied"),
            "rejected upgrade must record trust_denied"
        );
        let still = db.get_capability_package("ns", "upgrade-pkg").unwrap().unwrap();
        assert_eq!(still.current_version, "1.0.0");
    }

    #[test]
    fn trust_policy_change_is_audited_and_does_not_silently_retrust() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.set_capability_package_trust_policy(
            "ns",
            PACKAGE_TRUST_SIGNED,
            "admin",
            "policy-audit",
            1,
        )
        .unwrap();
        let policy = db.get_capability_package_trust_policy("ns").unwrap();
        assert_eq!(policy.required_trust_level, PACKAGE_TRUST_SIGNED);
        let replay = db
            .set_capability_package_trust_policy(
                "ns",
                PACKAGE_TRUST_SIGNED,
                "admin",
                "policy-audit",
                2,
            )
            .unwrap();
        assert_eq!(replay.required_trust_level, PACKAGE_TRUST_SIGNED);
        let events = db
            .list_capability_package_events("ns", "__trust_policy__")
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(events.iter().any(|event| event.action == "trust_policy"));
    }
}
