//! Built-in external evidence adapter profiles.
//!
//! These describe the reference adapters under `adapters/` as control-plane
//! discovery metadata. Collection remains outside core; admission still requires
//! registered schemas and producer capability.

use serde::{Deserialize, Serialize};

/// One reference evidence adapter the control plane ships and documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAdapterProfile {
    /// Stable adapter id (usually matches schema_id).
    pub adapter_id: String,
    /// Product/family grouping used by composition layers as a connector kind.
    pub family: String,
    pub evidence_type: String,
    pub schema_id: String,
    pub schema_version: String,
    pub source_type: String,
    pub signal: String,
    /// How the reference adapter is fed: document | webhook | poll.
    pub delivery: String,
    pub requires_expiry: bool,
    /// Cargo example target name when present.
    pub reference_example: String,
    pub description: String,
}

/// Connector family grouping one or more adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAdapterFamily {
    pub family: String,
    pub display_name: String,
    pub description: String,
    pub adapter_ids: Vec<String>,
}

/// Built-in reference adapters known to this release.
pub fn built_in_evidence_adapters() -> Vec<EvidenceAdapterProfile> {
    vec![
        EvidenceAdapterProfile {
            adapter_id: "adapter.github.check_run".into(),
            family: "source_control.check_run".into(),
            evidence_type: "source_control.check_run".into(),
            schema_id: "adapter.github.check_run".into(),
            schema_version: "1.0.0".into(),
            source_type: "github_check_run".into(),
            signal: "verification".into(),
            delivery: "webhook".into(),
            requires_expiry: false,
            reference_example: "evidence_github_check_webhook".into(),
            description:
                "GitHub check_run webhook payload to source-control verification evidence.".into(),
        },
        EvidenceAdapterProfile {
            adapter_id: "adapter.http.health_snapshot".into(),
            family: "operations.health".into(),
            evidence_type: "operations.health_snapshot".into(),
            schema_id: "adapter.http.health_snapshot".into(),
            schema_version: "1.0.0".into(),
            source_type: "http_health_endpoint".into(),
            signal: "operational_health".into(),
            delivery: "poll".into(),
            requires_expiry: true,
            reference_example: "evidence_http_health_poll".into(),
            description: "Bounded HTTP health poll to expiring operational-health evidence.".into(),
        },
        EvidenceAdapterProfile {
            adapter_id: "adapter.ontology.concept_catalog".into(),
            family: "ontology.concept_catalog".into(),
            evidence_type: "ontology.concept_catalog".into(),
            schema_id: "adapter.ontology.concept_catalog".into(),
            schema_version: "1.0.0".into(),
            source_type: "concept_catalog_document".into(),
            signal: "other".into(),
            delivery: "document".into(),
            requires_expiry: false,
            reference_example: "evidence_ontology_concept_catalog".into(),
            description: "Structured concept-catalog document for ontology definition proposals."
                .into(),
        },
        EvidenceAdapterProfile {
            adapter_id: "adapter.social.post_snapshot".into(),
            family: "social.observation".into(),
            evidence_type: "social.post_snapshot".into(),
            schema_id: "adapter.social.post_snapshot".into(),
            schema_version: "1.0.0".into(),
            source_type: "social_observation_document".into(),
            signal: "other".into(),
            delivery: "document".into(),
            requires_expiry: false,
            reference_example: "evidence_social_post_snapshot".into(),
            description: "Fixed-window social post metrics (24h or 7d).".into(),
        },
        EvidenceAdapterProfile {
            adapter_id: "adapter.social.reply".into(),
            family: "social.observation".into(),
            evidence_type: "social.reply".into(),
            schema_id: "adapter.social.reply".into(),
            schema_version: "1.0.0".into(),
            source_type: "social_observation_document".into(),
            signal: "other".into(),
            delivery: "document".into(),
            requires_expiry: false,
            reference_example: "evidence_social_reply".into(),
            description: "Single social reply observation with untrusted remote text.".into(),
        },
        EvidenceAdapterProfile {
            adapter_id: "adapter.github.object_sync".into(),
            family: "source_control.object_sync".into(),
            evidence_type: "source_control.object_sync".into(),
            schema_id: "adapter.github.object_sync".into(),
            schema_version: "1.0.0".into(),
            source_type: "github_issue_or_pull_request".into(),
            signal: "object_sync".into(),
            delivery: "webhook".into(),
            requires_expiry: false,
            reference_example: String::new(),
            description:
                "GitHub Issue or PullRequest observation mapped onto a shared type-revision object. Webhook delivery is transport into that identity, not a second source."
                    .into(),
        },
    ]
}

/// Distinct connector families derived from built-in adapters.
pub fn built_in_evidence_adapter_families() -> Vec<EvidenceAdapterFamily> {
    let mut families: Vec<EvidenceAdapterFamily> = Vec::new();
    for adapter in built_in_evidence_adapters() {
        if let Some(existing) = families.iter_mut().find(|f| f.family == adapter.family) {
            if !existing.adapter_ids.contains(&adapter.adapter_id) {
                existing.adapter_ids.push(adapter.adapter_id.clone());
            }
            continue;
        }
        let (display_name, description) = family_metadata(&adapter.family);
        families.push(EvidenceAdapterFamily {
            family: adapter.family.clone(),
            display_name: display_name.into(),
            description: description.into(),
            adapter_ids: vec![adapter.adapter_id.clone()],
        });
    }
    families
}

fn family_metadata(family: &str) -> (&'static str, &'static str) {
    match family {
        "source_control.check_run" => (
            "Source control checks",
            "GitHub check_run and compatible CI verification observations.",
        ),
        "operations.health" => (
            "Operational health",
            "HTTP health snapshots with bounded freshness.",
        ),
        "ontology.concept_catalog" => (
            "Ontology concept catalog",
            "Structured catalogs that feed ontology definition proposals.",
        ),
        "social.observation" => (
            "Social observation",
            "Fixed-window post metrics and reply observations.",
        ),
        "source_control.object_sync" => (
            "Source-control object sync",
            "GitHub Issue and PullRequest records upserted onto shared type revisions. No second source; delivery is transport.",
        ),
        _ => ("Adapter family", "External evidence adapter family."),
    }
}

/// True when `kind` is a built-in connector family id.
pub fn is_built_in_adapter_family(kind: &str) -> bool {
    built_in_evidence_adapter_families()
        .iter()
        .any(|family| family.family == kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_is_nonempty_and_stable() {
        let adapters = built_in_evidence_adapters();
        assert!(adapters.len() >= 5);
        let ids: BTreeSet<_> = adapters.iter().map(|a| a.adapter_id.as_str()).collect();
        assert_eq!(ids.len(), adapters.len());
        assert!(ids.contains("adapter.social.post_snapshot"));
        assert!(ids.contains("adapter.social.reply"));
        let families = built_in_evidence_adapter_families();
        assert!(families.iter().any(|f| f.family == "social.observation"));
        let social = families
            .iter()
            .find(|f| f.family == "social.observation")
            .unwrap();
        assert_eq!(social.adapter_ids.len(), 2);
        assert!(is_built_in_adapter_family("social.observation"));
        assert!(!is_built_in_adapter_family("not.a.family"));
    }
}
