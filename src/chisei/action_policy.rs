//! Action policy decisions by action and risk class.
//!
//! Chisei decides external actions against it; Sekai stores policies and
//! re-exports the type (ADR 0092 rule 3).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::chisei::risk_class::RiskClass;

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
