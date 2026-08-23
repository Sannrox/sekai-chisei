//! Fixed source-sync adapter profiles.
//!
//! Source adapters mutate server-owned projections through `ApplySourceBatch`;
//! they are intentionally separate from evidence adapter discovery.

use serde::{Deserialize, Serialize};

use crate::sekai::object_sync::{
    ADAPTER_GITHUB_OBJECT_SYNC, ADAPTER_GITHUB_OBJECT_SYNC_VERSION, FAMILY_OBJECT_SYNC,
    GITHUB_OBJECT_SYNC_RECORD_TYPES, GITHUB_OBJECT_SYNC_TYPE_DIGEST, SOURCE_BATCH_VERSION,
    SOURCE_GITHUB, SOURCE_TYPE_REVISION_VERSION,
};

/// One fixed, out-of-process source adapter supported by this release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAdapterProfile {
    pub adapter_id: String,
    pub adapter_version: String,
    pub family: String,
    pub source: String,
    pub contract_version: String,
    pub type_revision_contract_version: String,
    pub type_digest: String,
    pub record_types: Vec<String>,
    pub apply_rpc: String,
    pub state_rpc: String,
    pub description: String,
}

/// The bounded source-sync profile shipped in this release.
pub fn built_in_source_adapters() -> Vec<SourceAdapterProfile> {
    vec![SourceAdapterProfile {
        adapter_id: ADAPTER_GITHUB_OBJECT_SYNC.into(),
        adapter_version: ADAPTER_GITHUB_OBJECT_SYNC_VERSION.into(),
        family: FAMILY_OBJECT_SYNC.into(),
        source: SOURCE_GITHUB.into(),
        contract_version: SOURCE_BATCH_VERSION.into(),
        type_revision_contract_version: SOURCE_TYPE_REVISION_VERSION.into(),
        type_digest: GITHUB_OBJECT_SYNC_TYPE_DIGEST.into(),
        record_types: GITHUB_OBJECT_SYNC_RECORD_TYPES
            .iter()
            .map(|record_type| (*record_type).into())
            .collect(),
        apply_rpc: "SekaiService.ApplySourceBatch".into(),
        state_rpc: "SekaiService.GetSourceSyncState".into(),
        description: "GitHub Issue and PullRequest records mapped onto one repository number \
                      identity with opaque-checkpoint snapshot paging."
            .into(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_adapter_profile_is_fixed_and_not_an_evidence_schema() {
        let profiles = built_in_source_adapters();
        assert_eq!(profiles.len(), 1);
        let profile = &profiles[0];
        assert_eq!(profile.adapter_id, "adapter.github.object_sync");
        assert_eq!(profile.contract_version, "sekai.source-batch/v1");
        assert_eq!(
            profile.type_revision_contract_version,
            "sekai.source-type-revision/v1"
        );
        assert_eq!(profile.type_digest, GITHUB_OBJECT_SYNC_TYPE_DIGEST);
        assert_eq!(profile.record_types, ["Issue", "PullRequest"]);
    }
}
