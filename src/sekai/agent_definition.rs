//! Canonical Agent draft documents. Persistence does not authorize execution.
//!
//! A definition may bind tools (#1644): governed Actions, queries and gateway
//! tools. A tool's effect is derived, never declared by the author: queries
//! read; an Action's effect comes from its governed type; a gateway tool is
//! treated as destructive until the gateway publishes its annotations.
//! Publishing a revision whose mutating or destructive tool has no approval
//! policy is refused with [`REFUSAL_TOOL_APPROVAL`]. Drafts may omit policies.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const AGENT_DEFINITION_VERSION: &str = "sekai.agent-definition/v1";
const MAX_ACTION_TYPES: usize = 128;
const MAX_INSTRUCTION_BYTES: usize = 128 * 1024;
const MAX_TOOLS: usize = 128;
pub const TOOL_KIND_ACTION: &str = "action";
pub const TOOL_KIND_QUERY: &str = "query";
pub const TOOL_KIND_GATEWAY: &str = "gateway";
/// Prefix of the publish refusal; the tool name follows after a colon.
pub const REFUSAL_TOOL_APPROVAL: &str = "agent_tool_approval_required";

/// One tool an agent revision may call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolBinding {
    /// `action`, `query` or `gateway`.
    pub kind: String,
    pub name: String,
    /// Required before publish when the tool mutates or destroys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_policy: Option<String>,
}

/// Refuse a revision when any of its agent members binds a mutating or
/// destructive tool without an approval policy. `action_types` are the
/// namespace's registered governed Action types, all versions.
pub fn require_revision_tool_approvals(
    members: &[crate::sekai::definition_branch::DefinitionMember],
    action_types: &[crate::sekai::governed_action_type::GovernedActionType],
) -> Result<(), String> {
    for member in members
        .iter()
        .filter(|member| member.member_kind == "agent")
    {
        let definition: AgentDefinition = serde_json::from_str(&member.definition_json)
            .map_err(|_| "agent definition is unreadable".to_string())?;
        definition.require_tool_approvals(|name| {
            action_types
                .iter()
                .filter(|action| action.type_id == name)
                .cloned()
                .collect()
        })?;
    }
    Ok(())
}

/// Parse stored governed Action type bodies; an unreadable one is skipped,
/// which leaves its type unknown and therefore destructive.
pub fn parse_action_types(
    bodies: impl IntoIterator<Item = String>,
) -> Vec<crate::sekai::governed_action_type::GovernedActionType> {
    bodies
        .into_iter()
        .filter_map(|body| serde_json::from_str(&body).ok())
        .collect()
}

/// What a tool can do, ordered by consequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolEffect {
    Read,
    Mutating,
    Destructive,
}

/// The effect of a governed Action from its registered versions: the most
/// consequential version wins, and an unknown type is destructive.
pub fn action_effect(
    versions: &[crate::sekai::governed_action_type::GovernedActionType],
) -> ToolEffect {
    use crate::sekai::governed_action_type::{
        EFFECT_KIND_EXTERNAL_MUTATE, EFFECT_KIND_NOTIFY, EFFECT_KIND_RUNTIME_DISPATCH,
    };
    if versions.is_empty() {
        return ToolEffect::Destructive;
    }
    versions
        .iter()
        .map(|version| {
            let kinds = &version.allowed_effect_kinds;
            if kinds.iter().any(|kind| kind == EFFECT_KIND_EXTERNAL_MUTATE) {
                ToolEffect::Destructive
            } else if !version.object_mutation.is_empty()
                || kinds
                    .iter()
                    .any(|kind| kind == EFFECT_KIND_RUNTIME_DISPATCH || kind == EFFECT_KIND_NOTIFY)
            {
                ToolEffect::Mutating
            } else {
                ToolEffect::Read
            }
        })
        .max()
        .unwrap_or(ToolEffect::Destructive)
}

/// The effect of one binding. `action_versions` returns the registered
/// versions of a governed Action type in the definition's namespace.
pub fn tool_effect(
    binding: &ToolBinding,
    action_versions: impl Fn(&str) -> Vec<crate::sekai::governed_action_type::GovernedActionType>,
) -> ToolEffect {
    match binding.kind.as_str() {
        TOOL_KIND_QUERY => ToolEffect::Read,
        TOOL_KIND_ACTION => action_effect(&action_versions(&binding.name)),
        _ => ToolEffect::Destructive,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinition {
    pub contract_version: String,
    pub name: String,
    pub task_class: String,
    pub instructions: String,
    pub allowed_action_types: Vec<String>,
    /// Tools this revision may call (#1644). Omitted when empty, so
    /// definitions without tools keep their digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolBinding>,
}

impl AgentDefinition {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != AGENT_DEFINITION_VERSION {
            return Err("unsupported Agent definition version".into());
        }
        canonical_name(&self.name)?;
        canonical_name(&self.task_class)?;
        if self.instructions.trim().is_empty()
            || self.instructions.len() > MAX_INSTRUCTION_BYTES
            || self.instructions.contains('\0')
        {
            return Err("Agent instructions must be nonempty bounded text".into());
        }
        if self.allowed_action_types.len() > MAX_ACTION_TYPES {
            return Err("Agent Action allowlist exceeds the supported size".into());
        }
        let mut names = BTreeSet::new();
        for name in &self.allowed_action_types {
            canonical_name(name)?;
            if !names.insert(name) {
                return Err("Agent Action allowlist contains duplicates".into());
            }
        }
        if self.tools.len() > MAX_TOOLS {
            return Err("Agent tool list exceeds the supported size".into());
        }
        let mut tools = BTreeSet::new();
        for tool in &self.tools {
            if ![TOOL_KIND_ACTION, TOOL_KIND_QUERY, TOOL_KIND_GATEWAY].contains(&tool.kind.as_str())
            {
                return Err("Agent tool kind must be action, query or gateway".into());
            }
            canonical_name(&tool.name)?;
            if let Some(policy) = &tool.approval_policy {
                canonical_name(policy)?;
            }
            if !tools.insert((&tool.kind, &tool.name)) {
                return Err("Agent tool list contains duplicates".into());
            }
        }
        Ok(())
    }

    /// Refuse publish when a mutating or destructive tool has no approval
    /// policy, naming the first such tool.
    pub fn require_tool_approvals(
        &self,
        action_versions: impl Fn(&str) -> Vec<crate::sekai::governed_action_type::GovernedActionType>,
    ) -> Result<(), String> {
        match self.tools.iter().find(|tool| {
            tool.approval_policy.is_none()
                && tool_effect(tool, &action_versions) != ToolEffect::Read
        }) {
            Some(tool) => Err(format!("{REFUSAL_TOOL_APPROVAL}:{}", tool.name)),
            None => Ok(()),
        }
    }
}

fn canonical_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 256
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(
            "Agent names and Action references must be canonical bounded identifiers".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::DefinitionMemberInput;

    fn input() -> DefinitionMemberInput {
        DefinitionMemberInput {
            member_kind: "agent".into(),
            member_id: "triage".into(),
            member_digest: String::new(),
            definition_json: serde_json::json!({
                "contract_version": AGENT_DEFINITION_VERSION, "name": "Triage",
                "task_class": "lookup", "instructions": "Inspect records.",
                "allowed_action_types": ["Ticket.inspect"]
            })
            .to_string(),
        }
    }

    fn action_type(
        effects: &[&str],
        mutation: &str,
    ) -> crate::sekai::governed_action_type::GovernedActionType {
        crate::sekai::governed_action_type::GovernedActionType {
            allowed_effect_kinds: effects.iter().map(|kind| (*kind).to_string()).collect(),
            object_mutation: mutation.into(),
            ..Default::default()
        }
    }

    fn with_tools(tools: serde_json::Value) -> AgentDefinition {
        let mut value: serde_json::Value = serde_json::from_str(&input().definition_json).unwrap();
        value["tools"] = tools;
        let definition: AgentDefinition = serde_json::from_value(value).unwrap();
        definition.validate().unwrap();
        definition
    }

    #[test]
    fn effects_come_from_the_governed_type_and_fail_safe() {
        use crate::sekai::governed_action_type::{EFFECT_KIND_EXTERNAL_MUTATE, EFFECT_KIND_NOTIFY};
        assert_eq!(action_effect(&[action_type(&[], "")]), ToolEffect::Read);
        assert_eq!(
            action_effect(&[action_type(&[], "update")]),
            ToolEffect::Mutating
        );
        assert_eq!(
            action_effect(&[action_type(&[EFFECT_KIND_NOTIFY], "")]),
            ToolEffect::Mutating
        );
        assert_eq!(
            action_effect(&[
                action_type(&[], ""),
                action_type(&[EFFECT_KIND_EXTERNAL_MUTATE], "")
            ]),
            ToolEffect::Destructive,
            "the most consequential version wins"
        );
        assert_eq!(
            action_effect(&[]),
            ToolEffect::Destructive,
            "unknown types fail safe"
        );
    }

    #[test]
    fn publish_needs_a_policy_for_every_tool_that_changes_things() {
        let lookup = |name: &str| match name {
            "Ticket.inspect" => vec![action_type(&[], "")],
            "Ticket.close" => vec![action_type(&["external_mutate"], "")],
            _ => Vec::new(),
        };
        let definition = with_tools(serde_json::json!([
            {"kind": "query", "name": "open_tickets"},
            {"kind": "action", "name": "Ticket.inspect"},
            {"kind": "action", "name": "Ticket.close"}
        ]));
        assert_eq!(
            definition.require_tool_approvals(lookup),
            Err(format!("{REFUSAL_TOOL_APPROVAL}:Ticket.close"))
        );
        let approved = with_tools(serde_json::json!([
            {"kind": "action", "name": "Ticket.inspect"},
            {"kind": "action", "name": "Ticket.close", "approval_policy": "owner"},
            {"kind": "gateway", "name": "kb.search", "approval_policy": "owner"}
        ]));
        assert_eq!(approved.require_tool_approvals(lookup), Ok(()));
        let gateway = with_tools(serde_json::json!([{"kind": "gateway", "name": "kb.search"}]));
        assert!(
            gateway.require_tool_approvals(lookup).is_err(),
            "gateway tools fail safe"
        );
    }

    #[test]
    fn a_revision_is_refused_when_any_agent_member_needs_a_policy() {
        let member =
            |definition: &AgentDefinition| crate::sekai::definition_branch::DefinitionMember {
                contract_version: String::new(),
                namespace: "demo".into(),
                member_kind: "agent".into(),
                member_id: "triage".into(),
                definition_json: serde_json::to_string(definition).unwrap(),
                member_digest: String::new(),
            };
        let reads = crate::sekai::governed_action_type::GovernedActionType {
            type_id: "Ticket.inspect".into(),
            ..Default::default()
        };
        let safe = with_tools(serde_json::json!([{"kind": "action", "name": "Ticket.inspect"}]));
        let risky = with_tools(serde_json::json!([{"kind": "action", "name": "Ticket.close"}]));
        assert_eq!(
            require_revision_tool_approvals(&[member(&safe)], std::slice::from_ref(&reads)),
            Ok(())
        );
        assert_eq!(
            require_revision_tool_approvals(&[member(&safe), member(&risky)], &[reads]),
            Err(format!("{REFUSAL_TOOL_APPROVAL}:Ticket.close"))
        );
        assert_eq!(
            parse_action_types(["{not json".to_string()]).len(),
            0,
            "an unreadable type stays unknown"
        );
    }

    #[test]
    fn tool_lists_are_validated_and_omitted_when_empty() {
        for tools in [
            serde_json::json!([{"kind": "shell", "name": "x"}]),
            serde_json::json!([{"kind": "query", "name": " x"}]),
            serde_json::json!([{"kind": "query", "name": "x"}, {"kind": "query", "name": "x"}]),
            serde_json::json!([{"kind": "query", "name": "x", "effect": "read"}]),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(&input().definition_json).unwrap();
            value["tools"] = tools.clone();
            let invalid = DefinitionMemberInput {
                definition_json: value.to_string(),
                ..input()
            };
            assert!(invalid.prepare("demo").is_err(), "{tools}");
        }
        let parsed: AgentDefinition = serde_json::from_str(&input().definition_json).unwrap();
        assert!(!serde_json::to_string(&parsed).unwrap().contains("tools"));
    }

    #[test]
    fn agent_documents_are_typed_and_content_bound() {
        let original = input();
        let member = original.prepare("demo").unwrap();
        member.verify().unwrap();
        let parsed: AgentDefinition = serde_json::from_str(&member.definition_json).unwrap();
        parsed.validate().unwrap();
        assert_ne!(
            member.member_digest,
            original.prepare("other").unwrap().member_digest
        );
        for (field, value) in [
            ("contract_version", serde_json::json!("v2")),
            ("name", serde_json::json!(" ")),
            ("task_class", serde_json::json!("lookup ")),
            ("instructions", serde_json::json!("")),
            ("allowed_action_types", serde_json::json!(["read", "read"])),
            ("allowed_action_types", serde_json::json!([" read"])),
            ("model_key", serde_json::json!("not-a-supported-field")),
        ] {
            let mut value_json: serde_json::Value =
                serde_json::from_str(&original.definition_json).unwrap();
            value_json[field] = value;
            let invalid = DefinitionMemberInput {
                definition_json: value_json.to_string(),
                ..original.clone()
            };
            assert!(invalid.prepare("demo").is_err(), "{field}");
        }
        let invalid = DefinitionMemberInput {
            definition_json: original
                .definition_json
                .replacen("{", "{\"name\":\"duplicate\",", 1),
            ..original
        };
        assert!(invalid.prepare("demo").is_err());
        let mut corrupt = member;
        corrupt.definition_json = corrupt
            .definition_json
            .replace("Inspect records.", "Changed instructions.");
        assert!(corrupt.verify().is_err());
    }
}
