//! Governed-action policy.
//!
//! A per-scope policy over action types and ops: allow / deny / require-approval.
//! Policies are stored Sekai-natively as objects of kind `action_policy` with
//! `external_id = action_policy:{scope}` and reloaded like namespace model
//! policy. Enforcement happens at governed write and admission boundaries, and decisions
//! flow through the existing Sekai audit path. Vocabulary lives in Sekai
//! (ADR 0096 rule 5).

use crate::risk_class::RiskClass;
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

/// The clause of an `ActionPolicy` that decided an action. Displays as
/// `action_override:<action>`, `risk_override:<class>`, or
/// `default_decision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRule<'a> {
    ActionOverride(&'a str),
    RiskOverride(RiskClass),
    Default,
}

impl std::fmt::Display for PolicyRule<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyRule::ActionOverride(action) => write!(formatter, "action_override:{action}"),
            PolicyRule::RiskOverride(risk) => write!(formatter, "risk_override:{}", risk.as_str()),
            PolicyRule::Default => formatter.write_str("default_decision"),
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
    /// Blast-radius caps per work unit (0/None == unlimited).
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
        self.decide_with_rule(action, risk).0
    }

    /// `decide`, plus the clause that rendered the decision, for callers
    /// that must explain it (a parked Action names its rule, #1867).
    pub fn decide_with_rule<'a>(
        &self,
        action: &'a str,
        risk: RiskClass,
    ) -> (ActionDecision, PolicyRule<'a>) {
        if let Some(decision) = self.action_overrides.get(action) {
            return (*decision, PolicyRule::ActionOverride(action));
        }
        if let Some(decision) = self.risk_overrides.get(&risk) {
            return (*decision, PolicyRule::RiskOverride(risk));
        }
        (self.default_decision, PolicyRule::Default)
    }

    /// A stable digest of the policy body (default, overrides and caps, not
    /// the scope). Receipts name the policy that decided a submit by it, so
    /// a later replay can tell which body was in force (#3016).
    pub fn version(&self) -> String {
        let mut properties: Vec<(String, String)> = self
            .to_properties()
            .into_iter()
            .filter(|(key, _)| key != "scope")
            .collect();
        properties.sort();
        let mut hasher = Sha256::new();
        for (key, value) in properties {
            hasher.update(key.as_bytes());
            hasher.update([0]);
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
        format!("sha256:{:x}", hasher.finalize())
    }

    /// Serialize to a Sekai object property map (mirrors namespace policy
    /// storage: human-readable, CSV-style values).
    pub fn to_properties(&self) -> HashMap<String, String> {
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
                // Decision tokens never contain ':', so split at the last one;
                // an action name may itself contain ':'.
                let Some((name, decision)) = pair.rsplit_once(':') else {
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

pub fn parse_optional_u32(
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

/// Object id for a newly stored action policy. Distinct scopes stay distinct
/// even when they differ only in punctuation. Existing rows keep their original
/// ids; lookups go by `external_id`.
pub fn action_policy_id(scope: &str) -> String {
    let sanitized: String = scope
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let digest = format!("{:x}", Sha256::digest(scope.as_bytes()));
    format!("action-policy-{sanitized}-{}", &digest[..12])
}

pub fn action_policy_external_id(scope: &str) -> String {
    format!("{ACTION_POLICY_KIND}:{scope}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_tracks_the_body_not_the_scope() {
        let mut policy = ActionPolicy::allow_all("agent:a");
        let base = policy.version();
        assert_eq!(base, ActionPolicy::allow_all("ns").version());
        policy
            .risk_overrides
            .insert(RiskClass::Write, ActionDecision::RequireApproval);
        let with_override = policy.version();
        assert_ne!(base, with_override);
        policy.default_decision = ActionDecision::Deny;
        assert_ne!(with_override, policy.version());
    }

    #[test]
    fn action_override_name_with_colon_round_trips() {
        let policy = ActionPolicy {
            scope: "s".into(),
            default_decision: ActionDecision::Deny,
            action_overrides: HashMap::from([("object:delete".to_string(), ActionDecision::Deny)]),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        };
        let read = ActionPolicy::from_properties("s", &policy.to_properties()).unwrap();
        assert_eq!(read.action_overrides, policy.action_overrides);
    }

    #[test]
    fn action_policy_id_keeps_punctuation_variants_distinct() {
        assert_ne!(action_policy_id("agent:foo"), action_policy_id("agent-foo"));
    }
}
