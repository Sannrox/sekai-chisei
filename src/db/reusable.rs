//! Capability metadata for PostgreSQL reusable Sekai foundations.

use crate::db::graph::POSTGRES_GRAPH_SURFACES;
use crate::runtime_backend::{
    BackendCapabilities, BackendIdentity, RUNTIME_BACKEND_CONTRACT_VERSION,
};

pub const POSTGRES_FOUNDATION_SURFACES: &[&str] = &[
    "sekai.action-definitions",
    "sekai.attestations",
    "sekai.capability-packages",
    "sekai.credentials",
    "sekai.coordination",
    "sekai.datasets",
    "sekai.evidence",
    "sekai.handoffs",
    "sekai.leases",
    "sekai.ontology-definitions",
    "sekai.retention",
    "sekai.scoped-content",
    "sekai.reconciliation",
];

pub fn postgres_reusable_capabilities() -> BackendCapabilities {
    let mut reusable_surfaces = POSTGRES_GRAPH_SURFACES
        .iter()
        .chain(POSTGRES_FOUNDATION_SURFACES)
        .map(|surface| (*surface).to_string())
        .collect::<Vec<_>>();
    reusable_surfaces.sort();
    reusable_surfaces.dedup();
    BackendCapabilities {
        contract_version: RUNTIME_BACKEND_CONTRACT_VERSION.into(),
        backend: BackendIdentity::Postgres,
        reusable_surfaces,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_reports_only_implemented_partial_surfaces() {
        let fixture: BackendCapabilities = serde_json::from_str(include_str!(
            "../../tests/fixtures/runtime_backend/postgres-sekai-foundations-v1.json"
        ))
        .unwrap();
        assert_eq!(postgres_reusable_capabilities(), fixture);
        assert!(
            fixture
                .validate_required(crate::runtime_backend::COMMUNITY_REQUIRED_SURFACES)
                .is_err()
        );
        assert!(
            fixture
                .reusable_surfaces
                .iter()
                .all(|surface| !surface.contains("tenant"))
        );
    }
}
