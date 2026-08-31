//! Built-in workflow-action adapter profiles.
//!
//! These describe the reference adapters under `adapters/` as control-plane
//! discovery metadata. Collection remains outside core; admission stays on
//! ActionInstance.

use serde::{Deserialize, Serialize};

use crate::sekai::workflow_action::{
    APPROVAL_TYPE_ID, BRIDGE_CONTRACT, JOB_TYPE_ID, PROFILE_APPROVAL_STEP, PROFILE_JOB_STEP,
    PROFILE_VERSION, USAGE_APPROVAL, USAGE_STEP,
};

/// One reference workflow adapter the control plane ships and documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowAdapterProfile {
    pub adapter_id: String,
    pub adapter_version: String,
    pub family: String,
    pub contract_version: String,
    pub usage_kind: String,
    pub type_id: String,
    pub description: String,
}

/// Built-in reference adapters known to this release.
pub fn built_in_workflow_adapters() -> Vec<WorkflowAdapterProfile> {
    vec![
        WorkflowAdapterProfile {
            adapter_id: PROFILE_JOB_STEP.into(),
            adapter_version: PROFILE_VERSION.into(),
            family: "workflow.job_step".into(),
            contract_version: BRIDGE_CONTRACT.into(),
            usage_kind: USAGE_STEP.into(),
            type_id: JOB_TYPE_ID.into(),
            description: "Sequential job-step documents projected onto ActionInstance admission."
                .into(),
        },
        WorkflowAdapterProfile {
            adapter_id: PROFILE_APPROVAL_STEP.into(),
            adapter_version: PROFILE_VERSION.into(),
            family: "workflow.approval_step".into(),
            contract_version: BRIDGE_CONTRACT.into(),
            usage_kind: USAGE_APPROVAL.into(),
            type_id: APPROVAL_TYPE_ID.into(),
            description: "Approval-gate documents projected onto ActionInstance admission.".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_reference_workflow_adapters_are_catalogued() {
        let profiles = built_in_workflow_adapters();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].adapter_id, PROFILE_JOB_STEP);
        assert_eq!(profiles[1].adapter_id, PROFILE_APPROVAL_STEP);
        assert!(
            profiles
                .iter()
                .all(|profile| profile.contract_version == BRIDGE_CONTRACT)
        );
    }
}
