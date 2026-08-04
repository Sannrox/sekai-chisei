//! Checked-in inventory of ChiseiService RPCs for PostgreSQL parity.
//!
//! PostgreSQL may advertise complete reusable Chisei surfaces only when this
//! inventory is complete and every listed evidence path exists. Partial
//! surfaces may be advertised earlier when their harnesses pass.

use crate::runtime_backend::{
    BackendCapabilities, BackendIdentity, RUNTIME_BACKEND_CONTRACT_VERSION,
};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

pub const CHISEI_RPC_INVENTORY_VERSION: &str = "chisei.rpc-inventory/v1";
pub const CHISEI_RPC_INVENTORY_JSON: &str =
    include_str!("../../tests/fixtures/chisei_rpc_inventory/v1.json");
pub const CHISEI_SERVICE_PROTO: &str = include_str!("../../proto/chisei.proto");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcPersistenceKind {
    Persistent,
    Computed,
    Query,
}

pub use crate::db::sekai_rpc_inventory::ProductTier;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RpcInventoryEntry {
    pub rpc: String,
    pub kind: RpcPersistenceKind,
    pub surfaces: Vec<String>,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub durable_dependencies: Vec<String>,
    /// Product tier for docs/SDKs/agents (#386). Defaults to advanced when absent.
    #[serde(default)]
    pub product_tier: ProductTier,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InternalSurfaceEvidence {
    pub surface: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChiseiRpcInventory {
    pub version: String,
    pub service: String,
    pub proto: Vec<String>,
    pub entries: Vec<RpcInventoryEntry>,
    pub complete_chisei_surfaces: Vec<String>,
    #[serde(default)]
    pub remaining_surfaces: Vec<String>,
    #[serde(default)]
    pub prerequisite_issues: Vec<u64>,
    #[serde(default)]
    pub evidence_harnesses: Vec<String>,
    #[serde(default)]
    pub internal_surfaces: Vec<InternalSurfaceEvidence>,
}

impl ChiseiRpcInventory {
    pub fn load() -> Result<Self, String> {
        let inventory: Self = serde_json::from_str(CHISEI_RPC_INVENTORY_JSON)
            .map_err(|error| format!("parse chisei rpc inventory: {error}"))?;
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != CHISEI_RPC_INVENTORY_VERSION {
            return Err(format!(
                "unsupported inventory version {:?}; expected {CHISEI_RPC_INVENTORY_VERSION:?}",
                self.version
            ));
        }
        if self.service != "ChiseiService" {
            return Err(format!(
                "inventory service must be ChiseiService, got {}",
                self.service
            ));
        }
        let expected_proto = ["proto/chisei.proto"];
        if self.proto != expected_proto {
            return Err(format!(
                "inventory proto paths must be {expected_proto:?}, got {:?}",
                self.proto
            ));
        }

        let proto_rpcs = parse_service_rpcs(CHISEI_SERVICE_PROTO, "ChiseiService")?;

        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if entry.rpc.trim().is_empty() {
                return Err("inventory contains empty rpc name".into());
            }
            if !seen.insert(entry.rpc.as_str()) {
                return Err(format!("duplicate inventory rpc {}", entry.rpc));
            }
            if entry.evidence.is_empty() {
                return Err(format!("rpc {} is missing evidence links", entry.rpc));
            }
            match entry.kind {
                RpcPersistenceKind::Persistent => {
                    if entry.surfaces.is_empty() {
                        return Err(format!(
                            "persistent rpc {} must declare at least one surface",
                            entry.rpc
                        ));
                    }
                }
                RpcPersistenceKind::Computed | RpcPersistenceKind::Query => {
                    if entry.durable_dependencies.is_empty() {
                        return Err(format!(
                            "computed/query rpc {} must name durable dependencies",
                            entry.rpc
                        ));
                    }
                }
            }
            for surface in entry
                .surfaces
                .iter()
                .chain(entry.durable_dependencies.iter())
            {
                if !(surface.starts_with("chisei.")
                    || surface.starts_with("gateway.")
                    || surface.starts_with("operations."))
                {
                    return Err(format!(
                        "rpc {} surface/dependency {surface} must be chisei/gateway/operations",
                        entry.rpc
                    ));
                }
            }
        }

        let inventory_rpcs = self
            .entries
            .iter()
            .map(|entry| entry.rpc.as_str())
            .collect::<BTreeSet<_>>();
        let missing = proto_rpcs
            .difference(&inventory_rpcs)
            .cloned()
            .collect::<Vec<_>>();
        let stale = inventory_rpcs
            .difference(&proto_rpcs)
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() || !stale.is_empty() {
            return Err(format!(
                "inventory does not match ChiseiService RPCs; missing={missing:?} stale={stale:?}"
            ));
        }

        let complete = self
            .complete_chisei_surfaces
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let remaining = self
            .remaining_surfaces
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for surface in &complete {
            if remaining.contains(surface) {
                return Err(format!(
                    "surface {surface} cannot be both complete and remaining"
                ));
            }
        }
        for internal in &self.internal_surfaces {
            if internal.evidence.is_empty() {
                return Err(format!(
                    "internal surface {} is missing evidence",
                    internal.surface
                ));
            }
            if !complete.contains(internal.surface.as_str()) {
                return Err(format!(
                    "internal surface {} must be listed in complete_chisei_surfaces",
                    internal.surface
                ));
            }
        }

        for path in self.all_evidence_paths() {
            if (path.starts_with("tests/") || path.starts_with("src/") || path.starts_with("docs/"))
                && !Path::new(path).exists()
            {
                return Err(format!("inventory evidence path does not exist: {path}"));
            }
        }

        for surface in complete.iter().chain(remaining.iter()) {
            let lower = surface.to_ascii_lowercase();
            for banned in ["tenant", "oidc", "oauth"] {
                if lower.contains(banned) {
                    return Err(format!(
                        "chisei inventory must not include {banned} surface {surface}"
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn all_evidence_paths(&self) -> BTreeSet<&str> {
        let mut paths = BTreeSet::new();
        for entry in &self.entries {
            for path in &entry.evidence {
                paths.insert(path.as_str());
            }
        }
        for internal in &self.internal_surfaces {
            for path in &internal.evidence {
                paths.insert(path.as_str());
            }
        }
        for path in &self.evidence_harnesses {
            paths.insert(path.as_str());
        }
        paths
    }

    pub fn entry(&self, rpc: &str) -> Option<&RpcInventoryEntry> {
        self.entries.iter().find(|entry| entry.rpc == rpc)
    }

    pub fn entries_for_tier(&self, tier: ProductTier) -> impl Iterator<Item = &RpcInventoryEntry> {
        self.entries
            .iter()
            .filter(move |entry| entry.product_tier == tier)
    }

    pub fn by_kind(&self) -> HashMap<&'static str, usize> {
        let mut counts = HashMap::from([
            ("persistent", 0usize),
            ("computed", 0usize),
            ("query", 0usize),
        ]);
        for entry in &self.entries {
            match entry.kind {
                RpcPersistenceKind::Persistent => *counts.get_mut("persistent").unwrap() += 1,
                RpcPersistenceKind::Computed => *counts.get_mut("computed").unwrap() += 1,
                RpcPersistenceKind::Query => *counts.get_mut("query").unwrap() += 1,
            }
        }
        counts
    }

    pub fn by_product_tier(&self) -> HashMap<&'static str, usize> {
        let mut counts = HashMap::from([
            ("core", 0usize),
            ("advanced", 0usize),
            ("experimental", 0usize),
        ]);
        for entry in &self.entries {
            *counts.get_mut(entry.product_tier.as_str()).unwrap() += 1;
        }
        counts
    }
}

pub fn parse_service_rpcs<'a>(proto: &'a str, service: &str) -> Result<BTreeSet<&'a str>, String> {
    let marker = format!("service {service}");
    let service_body = proto
        .split(&marker)
        .nth(1)
        .ok_or_else(|| format!("proto is missing service {service}"))?;
    let body = service_body
        .split_once('{')
        .and_then(|(_, rest)| rest.rsplit_once('}'))
        .map(|(body, _)| body)
        .ok_or_else(|| format!("{service} body is malformed"))?;
    let mut rpcs = BTreeSet::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("rpc ") {
            let name = rest
                .split_whitespace()
                .next()
                .and_then(|token| token.split('(').next())
                .unwrap_or_default()
                .trim();
            if !name.is_empty() {
                rpcs.insert(name);
            }
        }
    }
    if rpcs.is_empty() {
        return Err(format!("no RPCs found in {service}"));
    }
    Ok(rpcs)
}

/// PostgreSQL capabilities for the complete reusable Chisei surface set.
///
/// Community runtime selection still requires Sekai, gateway, and operations
/// surfaces beyond this set; see #238 for community PostgreSQL activation.
pub fn postgres_complete_chisei_capabilities() -> Result<BackendCapabilities, String> {
    let inventory = ChiseiRpcInventory::load()?;
    if !inventory.remaining_surfaces.is_empty() {
        return Err(format!(
            "chisei inventory still has remaining surfaces: {:?}",
            inventory.remaining_surfaces
        ));
    }
    let mut surfaces = inventory.complete_chisei_surfaces.clone();
    surfaces.sort();
    surfaces.dedup();
    Ok(BackendCapabilities {
        contract_version: RUNTIME_BACKEND_CONTRACT_VERSION.into(),
        backend: BackendIdentity::Postgres,
        reusable_surfaces: surfaces,
        migration_version: None,
    })
}

/// Alias retained for callers written against the partial-progress helper.
pub fn postgres_partial_chisei_capabilities() -> Result<BackendCapabilities, String> {
    postgres_complete_chisei_capabilities()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_matches_proto_and_evidence_paths() {
        let inventory = ChiseiRpcInventory::load().expect("inventory must validate");
        assert_eq!(inventory.entries.len(), 30);
        assert!(inventory.entry("EvaluateGovernedSubject").is_some());
        assert!(inventory.entry("ExportGovernedSubjectProvenance").is_some());
        assert!(
            inventory
                .entry("GetGovernedSubjectProvenanceTrustRoot")
                .is_none()
        );
        assert_eq!(inventory.by_kind()["persistent"], 21);
        assert!(inventory.entry("GetOperationReceipt").is_some());
        assert!(inventory.entry("GetEvalSuite").is_some());
        assert!(inventory.entry("GetEvalRun").is_some());
        assert!(inventory.entry("GetSampleObservation").is_some());
        assert!(inventory.entry("ClaimGatewayDispatch").is_some());
        assert!(inventory.entry("ResolveEvaluationPlan").is_some());
        assert!(inventory.entry("ExecuteEvaluationManifest").is_some());
        assert!(inventory.entry("GetEvaluationExecution").is_none());
        assert!(inventory.entry("CancelEvaluationExecution").is_some());
        assert!(inventory.entry("Chat").is_none());
        assert!(inventory.entry("ResolvePolicy").is_none());
        assert_eq!(
            inventory.entry("PlanExecution").unwrap().product_tier,
            ProductTier::Core
        );
        assert!(inventory.entry("EvolveSuggest").is_none());
        assert!(inventory.entry("SetNamespaceWorkerPolicy").is_none());
        assert!(inventory.entry("RecordPortfolioObservation").is_none());
        assert!(inventory.entry("CreateEvalSuite").is_none());
        assert!(inventory.entry("RunPipeline").is_none());
        assert!(inventory.entry("RecordGatewayAudit").is_none());
        assert!(inventory.entry("IssueExternalActionPermit").is_none());
        assert!(inventory.entry("RecordGunshiFeedback").is_none());
        let tiers = inventory.by_product_tier();
        assert_eq!(tiers["core"], 9, "unexpected core chisei pack: {tiers:?}");
        assert_eq!(
            inventory.entries_for_tier(ProductTier::Core).count(),
            tiers["core"]
        );
        assert!(
            inventory
                .complete_chisei_surfaces
                .iter()
                .any(|surface| surface == "chisei.execution")
        );
        assert!(
            inventory
                .complete_chisei_surfaces
                .iter()
                .any(|surface| surface == "chisei.learning")
        );
        assert!(inventory.remaining_surfaces.is_empty());
    }

    #[test]
    fn complete_chisei_capabilities_do_not_claim_community_complete() {
        let complete = postgres_complete_chisei_capabilities().unwrap();
        assert_eq!(complete.backend, BackendIdentity::Postgres);
        assert!(
            complete
                .validate_required(crate::runtime_backend::COMMUNITY_REQUIRED_SURFACES)
                .is_err(),
            "community still needs Sekai and operations surfaces (#238)"
        );
        for surface in [
            "chisei.budget",
            "chisei.execution",
            "chisei.policy",
            "chisei.learning",
            "chisei.approvals",
            "gateway.governance",
        ] {
            assert!(
                complete
                    .reusable_surfaces
                    .iter()
                    .any(|item| item == surface),
                "missing {surface}"
            );
        }
        assert!(
            complete
                .reusable_surfaces
                .iter()
                .all(|surface| !surface.to_ascii_lowercase().contains("tenant"))
        );
    }
}
