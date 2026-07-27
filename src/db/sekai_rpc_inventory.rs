//! Checked-in inventory of reusable `SekaiService` RPCs for PostgreSQL parity.
//!
//! The inventory is the fail-closed bridge between `proto/sekai.proto` and the
//! shared SQLite/PostgreSQL evidence harnesses. PostgreSQL may advertise the
//! complete reusable Sekai surface set only when this inventory is complete
//! and every listed evidence path exists.

use crate::db::graph::POSTGRES_GRAPH_SURFACES;
use crate::db::reusable::{POSTGRES_FOUNDATION_SURFACES, postgres_reusable_capabilities};
use crate::runtime_backend::{
    BackendCapabilities, BackendIdentity, RUNTIME_BACKEND_CONTRACT_VERSION,
};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

pub const SEKAI_RPC_INVENTORY_VERSION: &str = "sekai.rpc-inventory/v1";
pub const SEKAI_RPC_INVENTORY_JSON: &str =
    include_str!("../../tests/fixtures/sekai_rpc_inventory/v1.json");
pub const SEKAI_SERVICE_PROTO: &str = include_str!("../../proto/sekai.proto");

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcPersistenceKind {
    Persistent,
    Computed,
    Query,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RpcInventoryEntry {
    pub rpc: String,
    pub kind: RpcPersistenceKind,
    pub surfaces: Vec<String>,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub durable_dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct InternalSurfaceEvidence {
    pub surface: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SekaiRpcInventory {
    pub version: String,
    pub service: String,
    pub proto: String,
    pub entries: Vec<RpcInventoryEntry>,
    pub complete_sekai_surfaces: Vec<String>,
    #[serde(default)]
    pub prerequisite_issues: Vec<u64>,
    #[serde(default)]
    pub evidence_harnesses: Vec<String>,
    #[serde(default)]
    pub internal_surfaces: Vec<InternalSurfaceEvidence>,
}

impl SekaiRpcInventory {
    pub fn load() -> Result<Self, String> {
        let inventory: Self = serde_json::from_str(SEKAI_RPC_INVENTORY_JSON)
            .map_err(|error| format!("parse sekai rpc inventory: {error}"))?;
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != SEKAI_RPC_INVENTORY_VERSION {
            return Err(format!(
                "unsupported inventory version {:?}; expected {SEKAI_RPC_INVENTORY_VERSION:?}",
                self.version
            ));
        }
        if self.service != "SekaiService" {
            return Err(format!(
                "inventory service must be SekaiService, got {}",
                self.service
            ));
        }
        if self.proto != "proto/sekai.proto" {
            return Err(format!(
                "inventory proto path must be proto/sekai.proto, got {}",
                self.proto
            ));
        }

        let proto_rpcs = parse_sekai_service_rpcs(SEKAI_SERVICE_PROTO)?;
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
                "inventory does not match proto/sekai.proto SekaiService RPCs; missing={missing:?} stale={stale:?}"
            ));
        }

        let mut complete = self
            .complete_sekai_surfaces
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        for surface in POSTGRES_GRAPH_SURFACES
            .iter()
            .chain(POSTGRES_FOUNDATION_SURFACES.iter())
        {
            if !complete.contains(*surface) {
                return Err(format!(
                    "complete_sekai_surfaces is missing implemented surface {surface}"
                ));
            }
        }
        for entry in &self.entries {
            for surface in &entry.surfaces {
                if !complete.contains(surface.as_str()) {
                    return Err(format!(
                        "rpc {} references surface {surface} outside complete_sekai_surfaces",
                        entry.rpc
                    ));
                }
            }
            for surface in &entry.durable_dependencies {
                if !surface.starts_with("sekai.") {
                    return Err(format!(
                        "rpc {} durable dependency {surface} must be a sekai surface",
                        entry.rpc
                    ));
                }
            }
        }
        for internal in &self.internal_surfaces {
            if !complete.contains(internal.surface.as_str()) {
                // Internal surfaces may extend the complete set.
                complete.insert(internal.surface.as_str());
            }
            if internal.evidence.is_empty() {
                return Err(format!(
                    "internal surface {} is missing evidence",
                    internal.surface
                ));
            }
        }

        // Fail closed when a listed evidence path is absent from the checkout.
        for path in self.all_evidence_paths() {
            if (path.starts_with("tests/") || path.starts_with("src/")) && !Path::new(path).exists()
            {
                return Err(format!("inventory evidence path does not exist: {path}"));
            }
        }

        // Tenant / identity surfaces must stay absent from the complete set.
        for surface in &self.complete_sekai_surfaces {
            let lower = surface.to_ascii_lowercase();
            for banned in ["tenant", "oidc", "oauth"] {
                if lower.contains(banned) {
                    return Err(format!(
                        "complete_sekai_surfaces must not include {banned} surface {surface}"
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
}

pub fn parse_sekai_service_rpcs(proto: &str) -> Result<BTreeSet<&str>, String> {
    let service = proto
        .split("service SekaiService")
        .nth(1)
        .ok_or_else(|| "proto/sekai.proto is missing service SekaiService".to_string())?;
    let body = service
        .split_once('{')
        .and_then(|(_, rest)| rest.rsplit_once('}'))
        .map(|(body, _)| body)
        .ok_or_else(|| "SekaiService body is malformed".to_string())?;
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
        return Err("no RPCs found in SekaiService".into());
    }
    Ok(rpcs)
}

/// PostgreSQL capabilities for the complete reusable Sekai surface set.
///
/// This is distinct from community runtime selection: Chisei, gateway, and
/// operations surfaces remain outside the complete-Sekai advertisement.
pub fn postgres_complete_sekai_capabilities() -> Result<BackendCapabilities, String> {
    let inventory = SekaiRpcInventory::load()?;
    let mut surfaces = inventory.complete_sekai_surfaces.clone();
    surfaces.sort();
    surfaces.dedup();
    let capabilities = BackendCapabilities {
        contract_version: RUNTIME_BACKEND_CONTRACT_VERSION.into(),
        backend: BackendIdentity::Postgres,
        reusable_surfaces: surfaces,
        migration_version: None,
    };
    // Complete Sekai still must include every implemented foundation surface.
    let required = postgres_reusable_capabilities().reusable_surfaces;
    let required_refs = required.iter().map(String::as_str).collect::<Vec<_>>();
    capabilities.validate_required(&required_refs)?;
    Ok(capabilities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_matches_proto_and_evidence_paths() {
        let inventory = SekaiRpcInventory::load().expect("inventory must validate");
        assert_eq!(inventory.entries.len(), 134);
        assert!(inventory.entry("ResolveSemanticRef").is_some());
        assert!(inventory.entry("ExpandRelations").is_some());
        assert!(inventory.entry("ExplainDerivation").is_some());
        assert!(inventory.entry("SearchText").is_some());
        assert!(inventory.entry("EvaluateScenario").is_some());
        assert!(inventory.by_kind()["persistent"] >= 100);
        assert!(inventory.by_kind()["computed"] >= 1);
        assert!(inventory.entry("CreateObject").is_some());
        assert!(inventory.entry("ExecuteFunction").is_some());
        assert_eq!(
            inventory.entry("ExecuteFunction").unwrap().kind,
            RpcPersistenceKind::Computed
        );
    }

    #[test]
    fn complete_sekai_capabilities_include_all_foundation_surfaces() {
        let complete = postgres_complete_sekai_capabilities().unwrap();
        let foundations = postgres_reusable_capabilities();
        assert_eq!(complete.backend, BackendIdentity::Postgres);
        for surface in &foundations.reusable_surfaces {
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
        let fixture: BackendCapabilities = serde_json::from_str(include_str!(
            "../../tests/fixtures/runtime_backend/postgres-sekai-complete-v1.json"
        ))
        .unwrap();
        assert_eq!(complete, fixture);
    }

    #[test]
    fn proto_parser_rejects_empty_service() {
        assert!(parse_sekai_service_rpcs("service Other {}").is_err());
    }
}
