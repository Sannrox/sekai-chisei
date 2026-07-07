//! Governed-action approval holds (Plan 9, Phase B).
//!
//! When policy resolves `require_approval`, the proposed action is held as an
//! `action_approval` Sekai object instead of executing. The exact params are
//! persisted (needed to resume on approval) while sensitive values are redacted
//! when surfaced to clients. Approve/deny transitions and the resume path live
//! in the gRPC service.

use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use std::collections::HashMap;

pub const ACTION_APPROVAL_KIND: &str = "action_approval";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Denied => "denied",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "pending" => Some(ApprovalStatus::Pending),
            "approved" => Some(ApprovalStatus::Approved),
            "denied" => Some(ApprovalStatus::Denied),
            _ => None,
        }
    }
}

/// A held action awaiting an approval decision.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionApproval {
    pub id: String,
    pub status: ApprovalStatus,
    /// Proposing principal.
    pub actor: String,
    pub action: String,
    /// Exact params to replay on approval.
    pub params: HashMap<String, String>,
    pub work_unit: String,
    pub policy_scope: String,
    pub risk_class: String,
    pub target_id: String,
    pub created: i64,
    pub updated: i64,
    /// Principal that approved/denied (empty while pending).
    pub decided_by: String,
    pub outcome: String,
}

impl ActionApproval {
    /// Build a new pending hold with a fresh id.
    #[allow(clippy::too_many_arguments)]
    pub fn pending(
        actor: impl Into<String>,
        action: impl Into<String>,
        params: HashMap<String, String>,
        work_unit: impl Into<String>,
        policy_scope: impl Into<String>,
        risk_class: impl Into<String>,
        target_id: impl Into<String>,
        now: i64,
    ) -> Self {
        Self {
            id: format!("action-approval-{}", uuid::Uuid::new_v4().simple()),
            status: ApprovalStatus::Pending,
            actor: actor.into(),
            action: action.into(),
            params,
            work_unit: work_unit.into(),
            policy_scope: policy_scope.into(),
            risk_class: risk_class.into(),
            target_id: target_id.into(),
            created: now,
            updated: now,
            decided_by: String::new(),
            outcome: String::new(),
        }
    }

    /// Params with sensitive values masked, for display to clients.
    pub fn redacted_params(&self) -> HashMap<String, String> {
        self.params
            .iter()
            .map(|(key, value)| {
                let value = if is_sensitive_name(key) {
                    "[redacted]".to_string()
                } else {
                    value.clone()
                };
                (key.clone(), value)
            })
            .collect()
    }

    fn to_properties(&self) -> Result<HashMap<String, String>, String> {
        let params_json = serde_json::to_string(&self.params).map_err(|e| e.to_string())?;
        Ok(HashMap::from([
            ("status".to_string(), self.status.as_str().to_string()),
            ("actor".to_string(), self.actor.clone()),
            ("action".to_string(), self.action.clone()),
            ("params_json".to_string(), params_json),
            ("work_unit".to_string(), self.work_unit.clone()),
            ("policy_scope".to_string(), self.policy_scope.clone()),
            ("risk_class".to_string(), self.risk_class.clone()),
            ("target_id".to_string(), self.target_id.clone()),
            ("decided_by".to_string(), self.decided_by.clone()),
            ("outcome".to_string(), self.outcome.clone()),
        ]))
    }

    fn from_object(object: &Object) -> Self {
        let params = object
            .properties
            .get("params_json")
            .and_then(|json| serde_json::from_str(json).ok())
            .unwrap_or_default();
        let get = |key: &str| object.properties.get(key).cloned().unwrap_or_default();
        Self {
            id: object.id.clone(),
            status: ApprovalStatus::parse(&get("status")).unwrap_or(ApprovalStatus::Pending),
            actor: get("actor"),
            action: get("action"),
            params,
            work_unit: get("work_unit"),
            policy_scope: get("policy_scope"),
            risk_class: get("risk_class"),
            target_id: get("target_id"),
            created: object.created,
            updated: object.updated,
            decided_by: get("decided_by"),
            outcome: get("outcome"),
        }
    }
}

fn is_sensitive_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains("password")
        || lower.contains("passphrase")
        || lower.contains("passwd")
        || lower.contains("credential")
}

fn approval_external_id(id: &str) -> String {
    format!("{ACTION_APPROVAL_KIND}:{id}")
}

impl SekaiDb {
    pub fn create_action_approval(&self, approval: &ActionApproval) -> Result<(), String> {
        let object = Object {
            id: approval.id.clone(),
            kind: ACTION_APPROVAL_KIND.to_string(),
            name: approval.action.clone(),
            namespace: String::new(),
            external_id: approval_external_id(&approval.id),
            properties: approval.to_properties()?,
            created: approval.created,
            updated: approval.updated,
        };
        self.create_object(&object)
    }

    pub fn get_action_approval(&self, id: &str) -> Result<Option<ActionApproval>, String> {
        Ok(self
            .get_object(id)?
            .filter(|object| object.kind == ACTION_APPROVAL_KIND)
            .map(|object| ActionApproval::from_object(&object)))
    }

    pub fn update_action_approval(&self, approval: &ActionApproval) -> Result<(), String> {
        let mut object = self
            .get_object(&approval.id)?
            .ok_or_else(|| "approval not found".to_string())?;
        object.properties = approval.to_properties()?;
        object.updated = approval.updated;
        self.update_object(&object)
    }

    /// List approvals, optionally filtered by status, most recent first.
    pub fn list_action_approvals(
        &self,
        status: Option<ApprovalStatus>,
    ) -> Result<Vec<ActionApproval>, String> {
        let filter = crate::domain::ListFilter {
            kind: Some(ACTION_APPROVAL_KIND.to_string()),
            ..Default::default()
        };
        let mut approvals: Vec<ActionApproval> = self
            .list_all_objects(&filter)?
            .iter()
            .map(ActionApproval::from_object)
            .filter(|approval| status.is_none_or(|status| approval.status == status))
            .collect();
        approvals.sort_by(|a, b| b.created.cmp(&a.created).then(a.id.cmp(&b.id)));
        Ok(approvals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ActionApproval {
        ActionApproval::pending(
            "codex-app",
            "rotate_key",
            HashMap::from([
                ("id".to_string(), "obj-1".to_string()),
                ("api_key".to_string(), "super-secret".to_string()),
            ]),
            "wu-42",
            "agent:codex-app",
            "destructive",
            "obj-1",
            1000,
        )
    }

    #[test]
    fn redacted_params_masks_sensitive_values() {
        let approval = sample();
        let redacted = approval.redacted_params();
        assert_eq!(redacted["id"], "obj-1");
        assert_eq!(redacted["api_key"], "[redacted]");
        // Stored params keep the real value for resume.
        assert_eq!(approval.params["api_key"], "super-secret");
    }

    #[test]
    fn storage_round_trip_and_status_filter() {
        let db = SekaiDb::new(":memory:").unwrap();
        let approval = sample();
        db.create_action_approval(&approval).unwrap();

        let fetched = db.get_action_approval(&approval.id).unwrap().unwrap();
        assert_eq!(fetched, approval);
        assert_eq!(fetched.params["api_key"], "super-secret");

        // Pending filter includes it; approved filter excludes it.
        assert_eq!(
            db.list_action_approvals(Some(ApprovalStatus::Pending))
                .unwrap()
                .len(),
            1
        );
        assert!(
            db.list_action_approvals(Some(ApprovalStatus::Approved))
                .unwrap()
                .is_empty()
        );

        // Transition to approved.
        let mut updated = fetched;
        updated.status = ApprovalStatus::Approved;
        updated.decided_by = "admin".to_string();
        updated.outcome = "executed".to_string();
        updated.updated = 2000;
        db.update_action_approval(&updated).unwrap();
        let reread = db.get_action_approval(&approval.id).unwrap().unwrap();
        assert_eq!(reread.status, ApprovalStatus::Approved);
        assert_eq!(reread.decided_by, "admin");
        assert_eq!(
            db.list_action_approvals(Some(ApprovalStatus::Pending))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn get_ignores_non_approval_objects() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_object(&Object {
            id: "obj-1".into(),
            kind: "namespace".into(),
            name: "n".into(),
            namespace: String::new(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 0,
            updated: 0,
        })
        .unwrap();
        assert!(db.get_action_approval("obj-1").unwrap().is_none());
    }
}
