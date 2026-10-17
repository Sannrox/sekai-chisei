//! Handoff manifest records and canonical digests.
//!
//! The rusqlite host stays in the plane.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HANDOFF_VERSION: &str = "sekai.handoff/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffReference {
    pub kind: String,
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub omitted: bool,
    #[serde(default)]
    pub omission_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffManifest {
    pub schema_version: String,
    pub id: String,
    pub namespace: String,
    pub parent_operation_id: String,
    pub parent_attempt_id: String,
    pub parent_work_unit_id: String,
    pub references: Vec<HandoffReference>,
    pub creator_principal: String,
    pub intended_principal: String,
    pub intended_scope: String,
    pub purpose: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub digest: String,
    pub supersedes_manifest_id: String,
    pub revoked: bool,
}

impl HandoffManifest {
    pub fn canonical_digest(&self) -> Result<String, String> {
        let mut canonical = self.clone();
        canonical.digest.clear();
        // Revocation is live control state, not part of the immutable manifest.
        canonical.revoked = false;
        let bytes = serde_json::to_vec(&canonical).map_err(|e| e.to_string())?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != HANDOFF_VERSION {
            return Err("unsupported handoff schema version".into());
        }
        for (name, value) in [
            ("id", self.id.as_str()),
            ("namespace", self.namespace.as_str()),
            ("creator_principal", self.creator_principal.as_str()),
            ("intended_principal", self.intended_principal.as_str()),
            ("intended_scope", self.intended_scope.as_str()),
            ("purpose", self.purpose.as_str()),
        ] {
            if value.trim().is_empty() || value.trim() != value {
                return Err(format!("{name} is required and must be canonical"));
            }
        }
        if self.created_at_ms <= 0 || self.expires_at_ms <= self.created_at_ms {
            return Err("handoff expiry must be after creation".into());
        }
        if self.references.is_empty() {
            return Err("at least one handoff reference is required".into());
        }
        for reference in &self.references {
            if reference.kind.trim().is_empty() || reference.id.trim().is_empty() {
                return Err("handoff reference kind and id are required".into());
            }
            if reference.omitted {
                if !matches!(
                    reference.omission_reason.as_str(),
                    "policy" | "retention" | "unavailable"
                ) {
                    return Err("omission reason must be policy, retention, or unavailable".into());
                }
            } else if reference.version.trim().is_empty() || !reference.omission_reason.is_empty() {
                return Err("included references require a version and no omission reason".into());
            }
        }
        if !self.digest.is_empty() && self.digest != self.canonical_digest()? {
            return Err("handoff digest does not match canonical manifest".into());
        }
        Ok(())
    }
}
