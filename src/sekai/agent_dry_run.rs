//! Agent dry run: one input, a step trace, no Action submitted (ADR 0109).

use crate::sekai::agent_definition::AgentDefinition;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const DRY_RUN_CONFIG_REF: &str = "dry_run";
pub const DRY_RUN_SUITE_PREFIX: &str = "dry_run:";
pub const DISPOSITION_WOULD_SUBMIT: &str = "would_submit";
pub const DISPOSITION_REFUSED: &str = "refused";
pub const REFUSAL_DISALLOWED_ACTION: &str = "action_type_not_allowed";
pub const REFUSAL_INVALID_PARAMETERS: &str = "invalid_parameters";
pub const REFUSAL_MODEL_UNAVAILABLE: &str = "agent_dry_run_model_unavailable";
pub const REFUSAL_DRY_RUN: &str = "agent_promotion_certification_dry_run";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedAction {
    pub action_type: String,
    pub parameters_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub name: String,
    pub arguments_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunModelRequest {
    pub namespace: String,
    pub revision_digest: String,
    pub member_id: String,
    pub input: String,
    pub instructions: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunModelReply {
    pub route: String,
    pub output: String,
    pub tool_calls: Vec<ToolCall>,
    pub proposed_actions: Vec<ProposedAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionTrace {
    pub action_type: String,
    pub parameters_json: String,
    pub disposition: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunTrace {
    pub model_steps: Vec<(String, String)>,
    pub tool_calls: Vec<ToolCall>,
    pub actions: Vec<ActionTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DryRunFailure {
    RouteAdmission(String),
    Budget(String),
    Model(String),
}

pub trait AgentDryRunHost: Send + Sync {
    fn admit_and_complete(
        &self,
        request: &DryRunModelRequest,
    ) -> Result<DryRunModelReply, DryRunFailure>;
}

/// Counts attempts so tests can prove admission and budget failures are not retried.
pub struct ScriptedHost {
    pub route: Result<String, String>,
    pub budget: Result<(), String>,
    pub reply: DryRunModelReply,
    pub attempts: AtomicUsize,
}

impl ScriptedHost {
    pub fn proposing(actions: Vec<ProposedAction>) -> Self {
        Self {
            route: Ok("native/scripted".into()),
            budget: Ok(()),
            reply: DryRunModelReply {
                route: "native/scripted".into(),
                output: "scripted".into(),
                tool_calls: Vec::new(),
                proposed_actions: actions,
            },
            attempts: AtomicUsize::new(0),
        }
    }

    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl AgentDryRunHost for ScriptedHost {
    fn admit_and_complete(
        &self,
        _request: &DryRunModelRequest,
    ) -> Result<DryRunModelReply, DryRunFailure> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if let Err(reason) = &self.route {
            return Err(DryRunFailure::RouteAdmission(reason.clone()));
        }
        if let Err(reason) = &self.budget {
            return Err(DryRunFailure::Budget(reason.clone()));
        }
        Ok(self.reply.clone())
    }
}

pub fn classify_actions<F>(
    definition: &AgentDefinition,
    reply: DryRunModelReply,
    validate_submit: F,
) -> DryRunTrace
where
    F: Fn(&str, &str) -> Result<(), String>,
{
    let actions = reply
        .proposed_actions
        .into_iter()
        .map(|action| {
            if !definition
                .allowed_action_types
                .iter()
                .any(|allowed| allowed == &action.action_type)
            {
                ActionTrace {
                    action_type: action.action_type,
                    parameters_json: action.parameters_json,
                    disposition: DISPOSITION_REFUSED.into(),
                    reason: REFUSAL_DISALLOWED_ACTION.into(),
                }
            } else if validate_submit(&action.action_type, &action.parameters_json).is_err() {
                ActionTrace {
                    action_type: action.action_type,
                    parameters_json: action.parameters_json,
                    disposition: DISPOSITION_REFUSED.into(),
                    reason: REFUSAL_INVALID_PARAMETERS.into(),
                }
            } else {
                ActionTrace {
                    action_type: action.action_type,
                    parameters_json: action.parameters_json,
                    disposition: DISPOSITION_WOULD_SUBMIT.into(),
                    reason: String::new(),
                }
            }
        })
        .collect();
    DryRunTrace {
        model_steps: vec![(reply.route, reply.output)],
        tool_calls: reply.tool_calls,
        actions,
    }
}

/// Same type lookup and closed v1 parameter schema as ActionInstance admit.
pub fn validate_dry_run_proposed_action(
    runtime: &crate::db::runtime_db::RuntimeDb,
    namespace: &str,
    action_type: &str,
    parameters_json: &str,
) -> Result<(), String> {
    crate::sekai::action_instance::validate_parameters_json(parameters_json)?;
    let types = runtime.list_governed_action_types(namespace, Some(action_type), true)?;
    let type_def = types
        .last()
        .ok_or_else(|| "unknown governed action type".to_string())?;
    crate::sekai::parameter_schema::validate_parameter_schema(&type_def.parameter_schema_json)?;
    crate::sekai::parameter_schema::validate_parameters(
        &type_def.parameter_schema_json,
        parameters_json,
    )
}

pub fn run_is_dry_run(config_ref: &str, suite_id: &str) -> bool {
    config_ref == DRY_RUN_CONFIG_REF || suite_id.starts_with(DRY_RUN_SUITE_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_only(_action_type: &str, parameters_json: &str) -> Result<(), String> {
        crate::sekai::action_instance::validate_parameters_json(parameters_json)
    }

    fn definition(allowed: &[&str]) -> AgentDefinition {
        AgentDefinition {
            contract_version: crate::sekai::agent_definition::AGENT_DEFINITION_VERSION.into(),
            name: "Triage".into(),
            task_class: "lookup".into(),
            instructions: "Inspect records.".into(),
            allowed_action_types: allowed.iter().map(|name| (*name).into()).collect(),
        }
    }

    #[test]
    fn allowed_actions_are_would_submit_and_disallowed_are_refused() {
        let reply = DryRunModelReply {
            route: "native/scripted".into(),
            output: "ok".into(),
            tool_calls: vec![ToolCall {
                name: "lookup".into(),
                arguments_json: r#"{"id":"1"}"#.into(),
            }],
            proposed_actions: vec![
                ProposedAction {
                    action_type: "Ticket.inspect".into(),
                    parameters_json: r#"{"id":"1"}"#.into(),
                },
                ProposedAction {
                    action_type: "Ticket.close".into(),
                    parameters_json: "{}".into(),
                },
            ],
        };
        let trace = classify_actions(&definition(&["Ticket.inspect"]), reply, json_only);
        assert_eq!(trace.model_steps[0].0, "native/scripted");
        assert_eq!(trace.tool_calls[0].name, "lookup");
        assert_eq!(trace.actions[0].disposition, DISPOSITION_WOULD_SUBMIT);
        assert_eq!(trace.actions[1].disposition, DISPOSITION_REFUSED);
        assert_eq!(trace.actions[1].reason, REFUSAL_DISALLOWED_ACTION);
    }

    #[test]
    fn malformed_parameters_are_refused_even_when_the_type_is_allowed() {
        let reply = DryRunModelReply {
            route: "native/scripted".into(),
            output: "ok".into(),
            tool_calls: Vec::new(),
            proposed_actions: vec![ProposedAction {
                action_type: "Ticket.inspect".into(),
                parameters_json: "not-json".into(),
            }],
        };
        let trace = classify_actions(&definition(&["Ticket.inspect"]), reply, json_only);
        assert_eq!(trace.actions[0].disposition, DISPOSITION_REFUSED);
        assert_eq!(trace.actions[0].reason, REFUSAL_INVALID_PARAMETERS);
    }

    #[test]
    fn dry_run_marks_are_never_suite_results() {
        assert!(run_is_dry_run(
            DRY_RUN_CONFIG_REF,
            &format!("{DRY_RUN_SUITE_PREFIX}demo:triage")
        ));
        assert!(!run_is_dry_run("native-default", "agent-suite"));
    }

    #[test]
    fn scripted_host_reports_guard_failures_once() {
        let host = ScriptedHost {
            route: Err("model_review.not_enabled".into()),
            budget: Ok(()),
            reply: DryRunModelReply {
                route: String::new(),
                output: String::new(),
                tool_calls: Vec::new(),
                proposed_actions: Vec::new(),
            },
            attempts: AtomicUsize::new(0),
        };
        let request = DryRunModelRequest {
            namespace: "demo".into(),
            revision_digest: "sha256:abc".into(),
            member_id: "triage".into(),
            input: "look up ticket 1".into(),
            instructions: "Inspect records.".into(),
        };
        assert_eq!(
            host.admit_and_complete(&request),
            Err(DryRunFailure::RouteAdmission(
                "model_review.not_enabled".into()
            ))
        );
        assert_eq!(host.attempts(), 1);
        let budget = ScriptedHost {
            route: Ok("native/scripted".into()),
            budget: Err("budget exceeded".into()),
            reply: host.reply.clone(),
            attempts: AtomicUsize::new(0),
        };
        assert_eq!(
            budget.admit_and_complete(&request),
            Err(DryRunFailure::Budget("budget exceeded".into()))
        );
        assert_eq!(budget.attempts(), 1);
    }

    #[test]
    fn catalog_schema_failures_are_refused_even_when_the_type_is_allowed() {
        let schema = r#"{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}"#;
        let reply = DryRunModelReply {
            route: "native/scripted".into(),
            output: "ok".into(),
            tool_calls: Vec::new(),
            proposed_actions: vec![ProposedAction {
                action_type: "Ticket.inspect".into(),
                parameters_json: "{}".into(),
            }],
        };
        let trace = classify_actions(&definition(&["Ticket.inspect"]), reply, |_, params| {
            crate::sekai::parameter_schema::validate_parameters(schema, params)
        });
        assert_eq!(trace.actions[0].disposition, DISPOSITION_REFUSED);
        assert_eq!(trace.actions[0].reason, REFUSAL_INVALID_PARAMETERS);
    }
}
