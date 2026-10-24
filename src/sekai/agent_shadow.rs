//! Agent revision shadows: replay recorded trigger envelopes through DryRunAgent (#1631).
//!
//! There is no live trigger path and no cron in the plane. Each envelope is
//! dry-run against the active and candidate Agent members. Proposed Actions
//! are compared; none are submitted. Budget is the same admit-and-complete
//! check DryRunAgent uses, charged once per replay.

use crate::sekai::agent_definition::AgentDefinition;
use crate::sekai::agent_dry_run::{
    ActionTrace, AgentDryRunHost, DryRunFailure, DryRunModelRequest, classify_actions,
};
use serde::{Deserialize, Serialize};

pub const AGENT_SHADOW_CONTRACT: &str = "sekai.agent-shadow/v1";
pub const SHADOW_CONFIG_REF: &str = "agent_shadow";
pub const SHADOW_SUITE_PREFIX: &str = "agent_shadow:";
pub const REQUIRED_SUITE_PREFIX: &str = "agent_shadow_required:";
pub const REQUIRED_CONFIG_REF: &str = "agent_shadow_required";
pub const REFUSAL_SHADOW: &str = "agent_promotion_requires_shadow_report";
pub const REFUSAL_SHADOW_CERTIFY: &str = "agent_promotion_certification_shadow";
pub const MAX_SHADOW_SAMPLES: usize = 16;

/// One recorded trigger the active revision already saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerEnvelope {
    pub id: String,
    pub input: String,
}

/// One envelope where the candidate proposed different Actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowSample {
    pub envelope_id: String,
    pub input: String,
    pub active: Vec<ActionTrace>,
    pub candidate: Vec<ActionTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowReport {
    pub contract_version: String,
    pub namespace: String,
    pub member_id: String,
    pub active_revision_digest: String,
    pub candidate_revision_digest: String,
    pub shadow_id: String,
    pub evaluated: u32,
    pub unchanged: u32,
    pub differed: u32,
    /// Completions charged against the namespace budget (`METRIC_TOKENS`).
    pub cost_tokens: u32,
    pub latency_ms: i64,
    pub passing: bool,
    pub verdict_reason: String,
    pub require_for_promotion: bool,
    pub samples: Vec<ShadowSample>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowFailure {
    Budget(String),
    RouteAdmission(String),
    Model(String),
}

impl From<DryRunFailure> for ShadowFailure {
    fn from(error: DryRunFailure) -> Self {
        match error {
            DryRunFailure::Budget(reason) => Self::Budget(reason),
            DryRunFailure::RouteAdmission(reason) => Self::RouteAdmission(reason),
            DryRunFailure::Model(reason) => Self::Model(reason),
        }
    }
}

/// One shadow comparison of an active Agent revision against a candidate.
pub struct ShadowRun<'a> {
    pub namespace: &'a str,
    pub member_id: &'a str,
    pub active_digest: &'a str,
    pub candidate_digest: &'a str,
    pub active: &'a AgentDefinition,
    pub candidate: &'a AgentDefinition,
    pub envelopes: &'a [TriggerEnvelope],
    pub require_for_promotion: bool,
    pub shadow_id: &'a str,
}

/// Replay each envelope through DryRunAgent for both revisions.
pub fn run_shadow<F>(
    run: &ShadowRun<'_>,
    host: &dyn AgentDryRunHost,
    validate_submit: F,
) -> Result<ShadowReport, ShadowFailure>
where
    F: Fn(&str, &str) -> Result<(), String> + Copy,
{
    let mut unchanged = 0u32;
    let mut differed = 0u32;
    let mut cost_tokens = 0u32;
    let mut samples = Vec::new();
    let started = std::time::Instant::now();
    for envelope in run.envelopes {
        let active_trace = replay(
            run.namespace,
            run.active_digest,
            run.member_id,
            envelope,
            run.active,
            host,
            validate_submit,
        )?;
        cost_tokens += 1;
        let candidate_trace = replay(
            run.namespace,
            run.candidate_digest,
            run.member_id,
            envelope,
            run.candidate,
            host,
            validate_submit,
        )?;
        cost_tokens += 1;
        if action_key(&active_trace.actions) == action_key(&candidate_trace.actions) {
            unchanged += 1;
        } else {
            differed += 1;
            if samples.len() < MAX_SHADOW_SAMPLES {
                samples.push(ShadowSample {
                    envelope_id: envelope.id.clone(),
                    input: envelope.input.clone(),
                    active: active_trace.actions,
                    candidate: candidate_trace.actions,
                });
            }
        }
    }
    let evaluated = u32::try_from(run.envelopes.len()).unwrap_or(u32::MAX);
    let (passing, verdict_reason) = if evaluated == 0 {
        (false, "no recorded trigger envelopes".into())
    } else {
        (true, String::new())
    };
    let latency_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
    Ok(ShadowReport {
        contract_version: AGENT_SHADOW_CONTRACT.into(),
        namespace: run.namespace.into(),
        member_id: run.member_id.into(),
        active_revision_digest: run.active_digest.into(),
        candidate_revision_digest: run.candidate_digest.into(),
        shadow_id: run.shadow_id.into(),
        evaluated,
        unchanged,
        differed,
        cost_tokens,
        latency_ms,
        passing,
        verdict_reason,
        require_for_promotion: run.require_for_promotion,
        samples,
    })
}

fn replay<F>(
    namespace: &str,
    revision_digest: &str,
    member_id: &str,
    envelope: &TriggerEnvelope,
    definition: &AgentDefinition,
    host: &dyn AgentDryRunHost,
    validate_submit: F,
) -> Result<crate::sekai::agent_dry_run::DryRunTrace, ShadowFailure>
where
    F: Fn(&str, &str) -> Result<(), String>,
{
    let request = DryRunModelRequest {
        namespace: namespace.into(),
        revision_digest: revision_digest.into(),
        member_id: member_id.into(),
        input: envelope.input.clone(),
        instructions: definition.instructions.clone(),
    };
    let reply = host.admit_and_complete(&request)?;
    Ok(classify_actions(definition, reply, validate_submit))
}

fn action_key(actions: &[ActionTrace]) -> Vec<(String, serde_json::Value, String)> {
    actions
        .iter()
        .map(|action| {
            let parameters = serde_json::from_str(&action.parameters_json)
                .unwrap_or_else(|_| serde_json::Value::String(action.parameters_json.clone()));
            (
                action.action_type.clone(),
                parameters,
                action.disposition.clone(),
            )
        })
        .collect()
}

pub fn suite_id(namespace: &str, member_id: &str) -> String {
    format!(
        "{SHADOW_SUITE_PREFIX}{}:{namespace}:{}:{member_id}",
        namespace.len(),
        member_id.len()
    )
}

pub fn required_suite_id(namespace: &str) -> String {
    format!("{REQUIRED_SUITE_PREFIX}{namespace}")
}

pub fn run_is_shadow(config_ref: &str, suite_id: &str) -> bool {
    config_ref == SHADOW_CONFIG_REF
        || config_ref == REQUIRED_CONFIG_REF
        || suite_id.starts_with(SHADOW_SUITE_PREFIX)
        || suite_id.starts_with(REQUIRED_SUITE_PREFIX)
}

/// A namespace that requires a shadow report refuses promotion until one
/// passing report exists for this candidate. The report never certifies.
pub fn require_shadow_report(
    required: bool,
    report: Option<&ShadowReport>,
    candidate_digest: &str,
    expected_active: Option<&str>,
) -> Result<(), String> {
    if !required {
        return Ok(());
    }
    match report {
        Some(report)
            if report.passing
                && report.candidate_revision_digest == candidate_digest
                && expected_active
                    .map(|active| report.active_revision_digest == active)
                    .unwrap_or(true) =>
        {
            Ok(())
        }
        _ => Err(REFUSAL_SHADOW.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::agent_dry_run::{
        DISPOSITION_WOULD_SUBMIT, DryRunFailure, DryRunModelReply, DryRunModelRequest,
        ProposedAction, ScriptedHost,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn definition(instructions: &str, allowed: &[&str]) -> AgentDefinition {
        AgentDefinition {
            contract_version: crate::sekai::agent_definition::AGENT_DEFINITION_VERSION.into(),
            name: "Triage".into(),
            task_class: "lookup".into(),
            instructions: instructions.into(),
            allowed_action_types: allowed.iter().map(|name| (*name).into()).collect(),
            tools: Vec::new(),
        }
    }

    fn json_ok(_action_type: &str, parameters_json: &str) -> Result<(), String> {
        crate::sekai::action_instance::validate_parameters_json(parameters_json)
    }

    fn compare<'a>(
        active: &'a AgentDefinition,
        candidate: &'a AgentDefinition,
        envelopes: &'a [TriggerEnvelope],
    ) -> ShadowRun<'a> {
        ShadowRun {
            namespace: "acme",
            member_id: "triage",
            active_digest: "sha256:active",
            candidate_digest: "sha256:candidate",
            active,
            candidate,
            envelopes,
            require_for_promotion: false,
            shadow_id: "shadow-1",
        }
    }

    struct InstructionHost {
        remaining: AtomicUsize,
        attempts: AtomicUsize,
    }

    impl InstructionHost {
        fn with_budget(remaining: usize) -> Self {
            Self {
                remaining: AtomicUsize::new(remaining),
                attempts: AtomicUsize::new(0),
            }
        }
    }

    impl AgentDryRunHost for InstructionHost {
        fn admit_and_complete(
            &self,
            request: &DryRunModelRequest,
        ) -> Result<DryRunModelReply, DryRunFailure> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.remaining.load(Ordering::SeqCst) == 0 {
                return Err(DryRunFailure::Budget("budget exceeded".into()));
            }
            self.remaining.fetch_sub(1, Ordering::SeqCst);
            let action_type = if request.instructions.contains("Close") {
                "Ticket.close"
            } else {
                "Ticket.inspect"
            };
            Ok(DryRunModelReply {
                route: "native/scripted".into(),
                output: "scripted".into(),
                tool_calls: Vec::new(),
                proposed_actions: vec![ProposedAction {
                    action_type: action_type.into(),
                    parameters_json: r#"{"id":"1"}"#.into(),
                }],
            })
        }
    }

    #[test]
    fn changed_instruction_lists_the_differing_proposal() {
        let host = InstructionHost::with_budget(8);
        let envelopes = [TriggerEnvelope {
            id: "env-1".into(),
            input: "ticket 1 arrived".into(),
        }];
        let active = definition("Inspect records.", &["Ticket.inspect", "Ticket.close"]);
        let candidate = definition("Close tickets.", &["Ticket.inspect", "Ticket.close"]);
        let report =
            run_shadow(&compare(&active, &candidate, &envelopes), &host, json_ok).expect("shadow");
        assert_eq!(report.evaluated, 1);
        assert_eq!(report.differed, 1);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.samples[0].active[0].action_type, "Ticket.inspect");
        assert_eq!(report.samples[0].candidate[0].action_type, "Ticket.close");
        assert_eq!(
            report.samples[0].active[0].disposition,
            DISPOSITION_WOULD_SUBMIT
        );
        assert_eq!(report.cost_tokens, 2);
        assert!(report.passing);
    }

    #[test]
    fn equivalent_json_objects_count_as_unchanged() {
        struct FlipJsonHost;
        impl AgentDryRunHost for FlipJsonHost {
            fn admit_and_complete(
                &self,
                request: &DryRunModelRequest,
            ) -> Result<DryRunModelReply, DryRunFailure> {
                let parameters_json = if request.instructions.contains("Close") {
                    r#"{"n":2,"id":"1"}"#
                } else {
                    r#"{"id":"1","n":2}"#
                };
                Ok(DryRunModelReply {
                    route: "native/scripted".into(),
                    output: "scripted".into(),
                    tool_calls: Vec::new(),
                    proposed_actions: vec![ProposedAction {
                        action_type: "Ticket.inspect".into(),
                        parameters_json: parameters_json.into(),
                    }],
                })
            }
        }
        let envelopes = [TriggerEnvelope {
            id: "env-1".into(),
            input: "ticket 1 arrived".into(),
        }];
        let active = definition("Inspect records.", &["Ticket.inspect"]);
        let candidate = definition("Close tickets.", &["Ticket.inspect"]);
        let report = run_shadow(
            &compare(&active, &candidate, &envelopes),
            &FlipJsonHost,
            json_ok,
        )
        .expect("shadow");
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.differed, 0);
        assert!(report.samples.is_empty());
    }

    #[test]
    fn shadow_replays_never_go_through_a_submit_host() {
        // ScriptedHost only returns proposed Actions. There is no submit path
        // on AgentDryRunHost; a shadow cannot create an Action instance.
        let host = ScriptedHost::proposing(vec![ProposedAction {
            action_type: "Ticket.inspect".into(),
            parameters_json: r#"{"id":"1"}"#.into(),
        }]);
        let envelopes = [TriggerEnvelope {
            id: "env-1".into(),
            input: "ticket 1 arrived".into(),
        }];
        let active = definition("Inspect records.", &["Ticket.inspect"]);
        let report =
            run_shadow(&compare(&active, &active, &envelopes), &host, json_ok).expect("shadow");
        assert_eq!(report.differed, 0);
        assert_eq!(host.attempts(), 2);
    }

    #[test]
    fn exhausted_budget_refuses_without_further_replays() {
        let host = InstructionHost::with_budget(1);
        let envelopes = [TriggerEnvelope {
            id: "env-1".into(),
            input: "ticket 1 arrived".into(),
        }];
        let active = definition("Inspect records.", &["Ticket.inspect"]);
        let candidate = definition("Close tickets.", &["Ticket.close"]);
        let error = run_shadow(&compare(&active, &candidate, &envelopes), &host, json_ok)
            .expect_err("budget");
        assert_eq!(error, ShadowFailure::Budget("budget exceeded".into()));
        assert_eq!(host.attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn promotion_requires_a_passing_report_when_the_namespace_asks() {
        let report = ShadowReport {
            contract_version: AGENT_SHADOW_CONTRACT.into(),
            namespace: "acme".into(),
            member_id: "triage".into(),
            active_revision_digest: "sha256:active".into(),
            candidate_revision_digest: "sha256:candidate".into(),
            shadow_id: "shadow-1".into(),
            evaluated: 1,
            unchanged: 0,
            differed: 1,
            cost_tokens: 2,
            latency_ms: 0,
            passing: true,
            verdict_reason: String::new(),
            require_for_promotion: true,
            samples: Vec::new(),
        };
        assert!(require_shadow_report(false, None, "sha256:candidate", None).is_ok());
        assert_eq!(
            require_shadow_report(true, None, "sha256:candidate", None).unwrap_err(),
            REFUSAL_SHADOW
        );
        assert!(require_shadow_report(true, Some(&report), "sha256:candidate", None).is_ok());
        assert_eq!(
            require_shadow_report(true, Some(&report), "sha256:other", None).unwrap_err(),
            REFUSAL_SHADOW
        );
        assert!(
            require_shadow_report(
                true,
                Some(&report),
                "sha256:candidate",
                Some("sha256:active")
            )
            .is_ok()
        );
        assert_eq!(
            require_shadow_report(
                true,
                Some(&report),
                "sha256:candidate",
                Some("sha256:published")
            )
            .unwrap_err(),
            REFUSAL_SHADOW
        );
        let mut failed = report.clone();
        failed.passing = false;
        assert_eq!(
            require_shadow_report(true, Some(&failed), "sha256:candidate", None).unwrap_err(),
            REFUSAL_SHADOW
        );
    }

    #[test]
    fn shadow_records_cannot_certify() {
        assert!(run_is_shadow(
            SHADOW_CONFIG_REF,
            &suite_id("acme", "triage")
        ));
        assert!(run_is_shadow(
            REQUIRED_CONFIG_REF,
            &required_suite_id("acme")
        ));
        assert_ne!(suite_id("a:b", "c"), suite_id("a", "b:c"));
        assert!(!run_is_shadow("dry_run", "dry_run:acme:triage"));
    }
}
