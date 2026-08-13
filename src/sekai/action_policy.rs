//! Governed-action policy (Plan 9, Phase A).
//!
//! A per-scope policy over action types and ops: allow / deny / require-approval.
//! Policies are stored Sekai-natively as objects of kind `action_policy` with
//! `external_id = action_policy:{scope}` and reloaded like namespace model
//! policy. Enforcement happens at governed write and admission boundaries, and decisions
//! flow through the existing Sekai audit path.

use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use crate::sekai::action::RiskClass;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const ACTION_POLICY_KIND: &str = "action_policy";
pub const BLAST_RADIUS_KIND: &str = "action_blast_radius";

/// The decision a policy renders for an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionDecision {
    Allow,
    Deny,
    RequireApproval,
}

impl ActionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionDecision::Allow => "allow",
            ActionDecision::Deny => "deny",
            ActionDecision::RequireApproval => "require_approval",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(ActionDecision::Allow),
            "deny" => Some(ActionDecision::Deny),
            "require_approval" | "require-approval" | "approval" => {
                Some(ActionDecision::RequireApproval)
            }
            _ => None,
        }
    }
}

/// A governed-action policy for a single scope (e.g. `agent:codex-app` or a
/// namespace). Resolution precedence for a given action is: per-action
/// override, then per-risk-class override, then the scope default.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionPolicy {
    pub scope: String,
    /// Default when nothing more specific matches. `Allow` keeps the system
    /// backward compatible (no policy == allow everything).
    pub default_decision: ActionDecision,
    /// Per-action-name overrides.
    pub action_overrides: HashMap<String, ActionDecision>,
    /// Per-risk-class overrides.
    pub risk_overrides: HashMap<RiskClass, ActionDecision>,
    /// Phase C blast-radius caps per work unit (0/None == unlimited).
    pub max_mutations_per_work_unit: Option<u32>,
    pub max_deletes_per_work_unit: Option<u32>,
}

impl ActionPolicy {
    /// A permissive policy for `scope`: allow everything, no caps.
    pub fn allow_all(scope: impl Into<String>) -> Self {
        Self {
            scope: scope.into(),
            default_decision: ActionDecision::Allow,
            action_overrides: HashMap::new(),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        }
    }

    /// Resolve the decision for an action given its name and risk class.
    pub fn decide(&self, action: &str, risk: RiskClass) -> ActionDecision {
        if let Some(decision) = self.action_overrides.get(action) {
            return *decision;
        }
        if let Some(decision) = self.risk_overrides.get(&risk) {
            return *decision;
        }
        self.default_decision
    }

    /// Serialize to a Sekai object property map (mirrors namespace policy
    /// storage: human-readable, CSV-style values).
    pub(crate) fn to_properties(&self) -> HashMap<String, String> {
        let mut properties = HashMap::new();
        properties.insert("scope".to_string(), self.scope.clone());
        properties.insert(
            "default_decision".to_string(),
            self.default_decision.as_str().to_string(),
        );

        let mut action_pairs: Vec<String> = self
            .action_overrides
            .iter()
            .map(|(name, decision)| format!("{}:{}", name, decision.as_str()))
            .collect();
        action_pairs.sort();
        properties.insert("action_overrides".to_string(), action_pairs.join(","));

        let mut risk_pairs: Vec<String> = self
            .risk_overrides
            .iter()
            .map(|(risk, decision)| format!("{}:{}", risk.as_str(), decision.as_str()))
            .collect();
        risk_pairs.sort();
        properties.insert("risk_overrides".to_string(), risk_pairs.join(","));

        properties.insert(
            "max_mutations_per_work_unit".to_string(),
            self.max_mutations_per_work_unit
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        properties.insert(
            "max_deletes_per_work_unit".to_string(),
            self.max_deletes_per_work_unit
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        properties
    }

    /// Parse from a Sekai object property map.
    ///
    /// Fail closed when a durable policy body is present but incomplete or
    /// corrupted: missing/unknown `default_decision` and unparsable override
    /// tokens are errors (never silently coerced to allow-all).
    pub fn from_properties(
        scope: &str,
        properties: &HashMap<String, String>,
    ) -> Result<Self, String> {
        let Some(raw_default) = properties
            .get("default_decision")
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        else {
            return Err(format!(
                "action policy {scope:?} is missing default_decision"
            ));
        };
        let Some(default_decision) = ActionDecision::parse(raw_default) else {
            return Err(format!(
                "action policy {scope:?} has invalid default_decision"
            ));
        };

        let mut action_overrides = HashMap::new();
        if let Some(raw) = properties.get("action_overrides") {
            for pair in raw.split(',').filter(|token| !token.trim().is_empty()) {
                let Some((name, decision)) = pair.split_once(':') else {
                    return Err(format!(
                        "action policy {scope:?} has unparsable action override"
                    ));
                };
                let name = name.trim();
                if name.is_empty() {
                    return Err(format!(
                        "action policy {scope:?} has unparsable action override"
                    ));
                }
                let Some(decision) = ActionDecision::parse(decision) else {
                    return Err(format!(
                        "action policy {scope:?} has invalid action override decision"
                    ));
                };
                action_overrides.insert(name.to_string(), decision);
            }
        }

        let mut risk_overrides = HashMap::new();
        if let Some(raw) = properties.get("risk_overrides") {
            for pair in raw.split(',').filter(|token| !token.trim().is_empty()) {
                let Some((risk, decision)) = pair.split_once(':') else {
                    return Err(format!(
                        "action policy {scope:?} has unparsable risk override"
                    ));
                };
                let Some(risk) = RiskClass::parse(risk) else {
                    return Err(format!(
                        "action policy {scope:?} has invalid risk override class"
                    ));
                };
                let Some(decision) = ActionDecision::parse(decision) else {
                    return Err(format!(
                        "action policy {scope:?} has invalid risk override decision"
                    ));
                };
                risk_overrides.insert(risk, decision);
            }
        }

        Ok(Self {
            scope: scope.to_string(),
            default_decision,
            action_overrides,
            risk_overrides,
            max_mutations_per_work_unit: parse_optional_u32(
                scope,
                "max_mutations_per_work_unit",
                properties.get("max_mutations_per_work_unit"),
            )?,
            max_deletes_per_work_unit: parse_optional_u32(
                scope,
                "max_deletes_per_work_unit",
                properties.get("max_deletes_per_work_unit"),
            )?,
        })
    }
}

fn parse_optional_u32(
    scope: &str,
    field: &str,
    value: Option<&String>,
) -> Result<Option<u32>, String> {
    let Some(raw) = value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let parsed = raw
        .parse::<u32>()
        .map_err(|_| format!("action policy {scope:?} has invalid {field}"))?;
    if parsed == 0 {
        Ok(None)
    } else {
        Ok(Some(parsed))
    }
}

/// Candidate scopes for an action, most specific first: actor, then project
/// (`project:<project>` when present), then namespace (legacy format).
/// Enforcement tries each in order and uses the first policy found.
pub fn candidate_scopes(actor: &str, namespace: &str, project: &str) -> Vec<String> {
    let mut scopes = Vec::new();
    if !actor.trim().is_empty() {
        scopes.push(format!("agent:{}", actor.trim()));
    }
    if !project.trim().is_empty() {
        scopes.push(format!("project:{}", project.trim()));
    }
    if !namespace.trim().is_empty() {
        scopes.push(namespace.trim().to_string());
    }
    scopes
}

fn action_policy_id(scope: &str) -> String {
    let sanitized: String = scope
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("action-policy-{sanitized}")
}

fn action_policy_external_id(scope: &str) -> String {
    format!("{ACTION_POLICY_KIND}:{scope}")
}

impl SekaiDb {
    /// Insert or update the action policy for a scope.
    pub fn upsert_action_policy(&self, policy: &ActionPolicy) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp();
        let external_id = action_policy_external_id(&policy.scope);
        let properties = policy.to_properties();
        if let Some(mut existing) = self.find_by_external_id(&external_id)? {
            existing.name = policy.scope.clone();
            existing.properties = properties;
            existing.updated = now;
            self.update_object(&existing)
        } else {
            self.create_object(&Object {
                id: action_policy_id(&policy.scope),
                kind: ACTION_POLICY_KIND.to_string(),
                name: policy.scope.clone(),
                namespace: String::new(),
                external_id,
                properties,
                created: now,
                updated: now,
            })
        }
    }

    /// Fetch the action policy for an exact scope, if one exists.
    pub fn get_action_policy(&self, scope: &str) -> Result<Option<ActionPolicy>, String> {
        let external_id = action_policy_external_id(scope);
        self.find_by_external_id(&external_id)?
            .map(|object| ActionPolicy::from_properties(scope, &object.properties))
            .transpose()
    }

    /// List all stored action policies, ordered by scope.
    pub fn list_action_policies(&self) -> Result<Vec<ActionPolicy>, String> {
        let filter = crate::domain::ListFilter {
            kind: Some(ACTION_POLICY_KIND.to_string()),
            ..Default::default()
        };
        let mut policies: Vec<ActionPolicy> = self
            .list_all_objects(&filter)?
            .into_iter()
            .map(|object| {
                let scope = if object.name.trim().is_empty() {
                    object
                        .external_id
                        .strip_prefix(&format!("{ACTION_POLICY_KIND}:"))
                        .unwrap_or(&object.name)
                        .to_string()
                } else {
                    object.name.clone()
                };
                ActionPolicy::from_properties(&scope, &object.properties)
            })
            .collect::<Result<Vec<_>, _>>()?;
        policies.sort_by(|a, b| a.scope.cmp(&b.scope));
        Ok(policies)
    }

    /// Resolve the effective policy for an actor/namespace/project, honoring
    /// agent-then-project-then-namespace precedence. Returns `None` when no
    /// policy applies. Admission callers must fail closed on `None`.
    pub fn resolve_action_policy(
        &self,
        actor: &str,
        namespace: &str,
        project: &str,
    ) -> Result<Option<ActionPolicy>, String> {
        for scope in candidate_scopes(actor, namespace, project) {
            if let Some(policy) = self.get_action_policy(&scope)? {
                return Ok(Some(policy));
            }
        }
        Ok(None)
    }

    /// Current `(mutations, deletes)` recorded against a work unit for
    /// blast-radius accounting. Missing counters read as zero.
    pub fn get_blast_radius(&self, work_unit: &str) -> Result<(u32, u32), String> {
        let external_id = format!("{BLAST_RADIUS_KIND}:{work_unit}");
        match self.find_by_external_id(&external_id)? {
            Some(object) => {
                let read = |key: &str| {
                    object
                        .properties
                        .get(key)
                        .and_then(|value| value.parse::<u32>().ok())
                        .unwrap_or(0)
                };
                Ok((read("mutations"), read("deletes")))
            }
            None => Ok((0, 0)),
        }
    }

    /// Add to a work unit's blast-radius counters, creating the record if
    /// needed. Returns the updated `(mutations, deletes)`.
    pub fn add_blast_radius(
        &self,
        work_unit: &str,
        mutations: u32,
        deletes: u32,
    ) -> Result<(u32, u32), String> {
        let now = chrono::Utc::now().timestamp();
        let external_id = format!("{BLAST_RADIUS_KIND}:{work_unit}");
        if let Some(mut object) = self.find_by_external_id(&external_id)? {
            let current = |key: &str| {
                object
                    .properties
                    .get(key)
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or(0)
            };
            let new_mutations = current("mutations").saturating_add(mutations);
            let new_deletes = current("deletes").saturating_add(deletes);
            object
                .properties
                .insert("mutations".to_string(), new_mutations.to_string());
            object
                .properties
                .insert("deletes".to_string(), new_deletes.to_string());
            object.updated = now;
            self.update_object(&object)?;
            Ok((new_mutations, new_deletes))
        } else {
            let work_unit_digest = format!("{:x}", Sha256::digest(work_unit.as_bytes()));
            self.create_object(&Object {
                id: format!("blast-radius-{work_unit_digest}"),
                kind: BLAST_RADIUS_KIND.to_string(),
                name: work_unit.to_string(),
                namespace: String::new(),
                external_id,
                properties: HashMap::from([
                    ("mutations".to_string(), mutations.to_string()),
                    ("deletes".to_string(), deletes.to_string()),
                ]),
                created: now,
                updated: now,
            })?;
            Ok((mutations, deletes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with_overrides() -> ActionPolicy {
        let mut policy = ActionPolicy::allow_all("agent:codex-app");
        policy.default_decision = ActionDecision::Allow;
        policy
            .action_overrides
            .insert("delete_link".to_string(), ActionDecision::Deny);
        policy
            .risk_overrides
            .insert(RiskClass::Destructive, ActionDecision::RequireApproval);
        policy.max_deletes_per_work_unit = Some(5);
        policy
    }

    #[test]
    fn decide_precedence_action_then_risk_then_default() {
        let policy = policy_with_overrides();
        // Per-action override wins over the risk override.
        assert_eq!(
            policy.decide("delete_link", RiskClass::Destructive),
            ActionDecision::Deny
        );
        // Risk override applies when no action override exists.
        assert_eq!(
            policy.decide("delete_object", RiskClass::Destructive),
            ActionDecision::RequireApproval
        );
        // Default applies otherwise.
        assert_eq!(
            policy.decide("set_property", RiskClass::Write),
            ActionDecision::Allow
        );
    }

    #[test]
    fn properties_round_trip() {
        let policy = policy_with_overrides();
        let properties = policy.to_properties();
        let restored = ActionPolicy::from_properties("agent:codex-app", &properties).unwrap();
        assert_eq!(restored, policy);
    }

    #[test]
    fn from_properties_rejects_unknown_default_decision() {
        let properties = HashMap::from([("default_decision".to_string(), "typo".to_string())]);
        let err = ActionPolicy::from_properties("ns", &properties).unwrap_err();
        assert!(
            err.contains("invalid default_decision"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_properties_rejects_missing_default_decision() {
        let err = ActionPolicy::from_properties("ns", &HashMap::new()).unwrap_err();
        assert!(
            err.contains("missing default_decision"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn from_properties_rejects_unparsable_override_tokens() {
        let properties = HashMap::from([
            ("default_decision".to_string(), "allow".to_string()),
            (
                "action_overrides".to_string(),
                "good:deny,broken".to_string(),
            ),
        ]);
        let err = ActionPolicy::from_properties("ns", &properties).unwrap_err();
        assert!(
            err.contains("unparsable action override"),
            "unexpected error: {err}"
        );

        let properties = HashMap::from([
            ("default_decision".to_string(), "deny".to_string()),
            (
                "risk_overrides".to_string(),
                "destructive:deny,write:bogus".to_string(),
            ),
        ]);
        let err = ActionPolicy::from_properties("ns", &properties).unwrap_err();
        assert!(
            err.contains("invalid risk override decision"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn candidate_scopes_prefers_agent_then_namespace() {
        assert_eq!(
            candidate_scopes("codex-app", "sekai-chisei", "sekai-chisei"),
            vec![
                "agent:codex-app".to_string(),
                "project:sekai-chisei".to_string(),
                "sekai-chisei".to_string()
            ]
        );
        assert_eq!(
            candidate_scopes("", "sekai-chisei", "sekai-chisei"),
            vec![
                "project:sekai-chisei".to_string(),
                "sekai-chisei".to_string()
            ]
        );
        assert_eq!(
            candidate_scopes("", "", "sekai-chisei"),
            vec!["project:sekai-chisei".to_string()]
        );
        assert_eq!(candidate_scopes("", "", ""), Vec::<String>::new());
    }

    #[test]
    fn storage_round_trip_and_resolution() {
        let db = SekaiDb::new(":memory:").unwrap();
        let agent_policy = policy_with_overrides();
        db.upsert_action_policy(&agent_policy).unwrap();

        let mut ns_policy = ActionPolicy::allow_all("sekai-chisei");
        ns_policy.default_decision = ActionDecision::Deny;
        db.upsert_action_policy(&ns_policy).unwrap();

        // Exact fetch round-trips.
        assert_eq!(
            db.get_action_policy("agent:codex-app").unwrap(),
            Some(agent_policy.clone())
        );

        // Agent scope wins over namespace when both exist.
        let resolved = db
            .resolve_action_policy("codex-app", "sekai-chisei", "sekai-chisei")
            .unwrap()
            .unwrap();
        assert_eq!(resolved.scope, "agent:codex-app");

        // Falls back to namespace when no agent policy exists.
        let resolved = db
            .resolve_action_policy("other-agent", "sekai-chisei", "sekai-chisei")
            .unwrap()
            .unwrap();
        assert_eq!(resolved.scope, "sekai-chisei");
        assert_eq!(resolved.default_decision, ActionDecision::Deny);

        // No policy at all -> None (allow-all).
        assert!(
            db.resolve_action_policy("nobody", "unknown-ns", "unknown-ns")
                .unwrap()
                .is_none()
        );

        // Update in place.
        let mut updated = agent_policy.clone();
        updated.default_decision = ActionDecision::RequireApproval;
        db.upsert_action_policy(&updated).unwrap();
        assert_eq!(
            db.get_action_policy("agent:codex-app")
                .unwrap()
                .unwrap()
                .default_decision,
            ActionDecision::RequireApproval
        );

        // List returns both, sorted by scope.
        let all = db.list_action_policies().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].scope, "agent:codex-app");
        assert_eq!(all[1].scope, "sekai-chisei");
    }

    #[test]
    fn blast_radius_ids_do_not_collide_for_distinct_work_units() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.add_blast_radius("a/b", 1, 0).unwrap();
        db.add_blast_radius("a-b", 2, 1).unwrap();
        assert_eq!(db.get_blast_radius("a/b").unwrap(), (1, 0));
        assert_eq!(db.get_blast_radius("a-b").unwrap(), (2, 1));
    }
}
