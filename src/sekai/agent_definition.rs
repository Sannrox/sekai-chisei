//! Canonical Agent draft documents. Persistence does not authorize execution.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const AGENT_DEFINITION_VERSION: &str = "sekai.agent-definition/v1";
const MAX_ACTION_TYPES: usize = 128;
const MAX_INSTRUCTION_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDefinition {
    pub contract_version: String,
    pub name: String,
    pub task_class: String,
    pub instructions: String,
    pub allowed_action_types: Vec<String>,
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
        Ok(())
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
