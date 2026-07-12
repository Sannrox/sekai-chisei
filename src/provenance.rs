use std::collections::{BTreeSet, HashMap};

use crate::db::sekai::SekaiDb;
use crate::sekai::attestation::{
    AttestationVerification, EVIDENCE_ATTESTATION_HASH, EVIDENCE_ATTESTATION_ID,
};
use crate::sekai::audit::Decision;
use crate::sekai::dataset::{RowFilter, RowQuery};
use crate::sekai::ledger::LedgerVerification;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCall {
    pub request_id: String,
    pub timestamp_ms: i64,
    pub provider: String,
    pub requested_model: String,
    pub resolved_model: String,
    pub route_bias: String,
    pub policy_scope: String,
    pub policy_version: String,
    pub status: String,
    pub refusal_reason: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_usd_micros: i64,
}

#[derive(Debug, Clone)]
pub struct ProvenanceReport {
    pub work_unit_id: String,
    pub calls: Vec<ModelCall>,
    pub decisions: Vec<Decision>,
    pub assurance: Option<AssuranceSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub attestation_id: String,
    pub decision_id: String,
    pub verification: AttestationVerification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceSummary {
    pub ledger: LedgerVerification,
    pub attestations: Vec<VerifiedAttestation>,
}

impl AssuranceSummary {
    pub fn verifiable(&self, evidence_present: bool) -> bool {
        evidence_present
            && self.ledger.ok
            && self
                .attestations
                .iter()
                .all(|attestation| attestation.verification.ok)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedAction {
    pub decision_id: String,
    pub timestamp_ms: i64,
    pub actor: String,
    pub action: String,
    pub target_id: String,
    pub risk_class: String,
    pub decision: String,
    pub outcome: String,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataEgress {
    pub decision_id: String,
    pub request_id: String,
    pub provider: String,
    pub model: String,
    pub included_fields: i64,
    pub redacted_fields: i64,
    pub included: Vec<String>,
    pub redacted: Vec<String>,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyException {
    pub decision_id: String,
    pub action: String,
    pub outcome: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub clean: bool,
    pub enforced_refusals: usize,
    pub exceptions: Vec<PolicyException>,
}

impl ProvenanceReport {
    pub fn total_cost_usd_micros(&self) -> i64 {
        self.calls.iter().map(|call| call.cost_usd_micros).sum()
    }

    pub fn policy_verdict(&self) -> PolicyVerdict {
        let exceptions = self
            .decisions
            .iter()
            .filter(|decision| is_policy_exception(decision))
            .map(|decision| PolicyException {
                decision_id: decision.id.clone(),
                action: decision.action.clone(),
                outcome: decision.outcome.clone(),
                reason: decision.reason.clone(),
            })
            .collect::<Vec<_>>();
        let enforced_refusals = self
            .calls
            .iter()
            .filter(|call| !call.refusal_reason.is_empty())
            .count()
            + self
                .decisions
                .iter()
                .filter(|decision| is_enforced_refusal(decision))
                .count();
        PolicyVerdict {
            clean: exceptions.is_empty(),
            enforced_refusals,
            exceptions,
        }
    }

    pub fn governed_actions(&self) -> Vec<GovernedAction> {
        self.decisions
            .iter()
            .filter(|decision| decision.evidence.contains_key("risk_class"))
            .map(|decision| GovernedAction {
                decision_id: decision.id.clone(),
                timestamp_ms: decision.timestamp,
                actor: decision.actor.clone(),
                action: decision.action.clone(),
                target_id: decision.target_id.clone(),
                risk_class: decision
                    .evidence
                    .get("risk_class")
                    .cloned()
                    .unwrap_or_default(),
                decision: decision
                    .evidence
                    .get("decision")
                    .cloned()
                    .unwrap_or_else(|| inferred_action_decision(decision).into()),
                outcome: decision.outcome.clone(),
                dry_run: decision
                    .evidence
                    .get("dry_run")
                    .is_some_and(|value| value == "true"),
            })
            .collect()
    }

    pub fn data_egress(&self) -> Vec<DataEgress> {
        self.decisions
            .iter()
            .filter(|decision| {
                decision.actor == "chisei.egress" || decision.action == "gateway.egress"
            })
            .map(|decision| DataEgress {
                decision_id: decision.id.clone(),
                request_id: decision.target_id.clone(),
                provider: decision
                    .evidence
                    .get("provider")
                    .cloned()
                    .unwrap_or_default(),
                model: decision
                    .evidence
                    .get("model")
                    .or_else(|| decision.evidence.get("resolved_model"))
                    .or_else(|| decision.evidence.get("requested_model"))
                    .cloned()
                    .unwrap_or_default(),
                included_fields: evidence_i64(decision, "included_count"),
                redacted_fields: evidence_i64(decision, "redacted_count"),
                included: evidence_list(decision, "included_fields"),
                redacted: evidence_list(decision, "redacted_fields"),
                outcome: decision.outcome.clone(),
            })
            .collect()
    }
}

fn evidence_i64(decision: &Decision, key: &str) -> i64 {
    decision
        .evidence
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn evidence_list(decision: &Decision, key: &str) -> Vec<String> {
    decision
        .evidence
        .get(key)
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default()
}

fn inferred_action_decision(decision: &Decision) -> &'static str {
    if decision.reason.contains("denied") || decision.reason.contains("exceeded") {
        "deny"
    } else {
        "allow"
    }
}

fn is_policy_exception(decision: &Decision) -> bool {
    decision
        .evidence
        .get("policy_violation")
        .is_some_and(|value| value == "true")
        || matches!(
            decision.outcome.as_str(),
            "bypassed" | "violated" | "policy_violation" | "leak_warned"
        )
}

fn is_enforced_refusal(decision: &Decision) -> bool {
    matches!(
        decision.outcome.as_str(),
        "denied" | "blocked" | "leak_blocked" | "redacted" | "skipped"
    ) || decision.reason.contains("denied")
        || decision.reason.contains("exceeded")
}

pub fn assemble_report(db: &SekaiDb, work_unit_id: &str) -> Result<ProvenanceReport, String> {
    if work_unit_id.trim().is_empty() {
        return Err("work unit id must not be empty".into());
    }
    let rows = db.query_rows(
        "llm_calls",
        &RowQuery {
            filters: vec![RowFilter {
                column: "work_unit_id".into(),
                op: "eq".into(),
                value: work_unit_id.into(),
            }],
            ..Default::default()
        },
    )?;
    let request_ids = rows
        .iter()
        .filter_map(|row| row.get("request_id"))
        .cloned()
        .collect::<BTreeSet<_>>();
    let decisions = db.list_work_unit_decisions(work_unit_id, &request_ids)?;
    let assurance = Some(assemble_assurance(db, &decisions)?);

    let mut calls = rows.into_iter().map(model_call).collect::<Vec<_>>();
    calls.sort_by_key(|call| call.timestamp_ms);
    Ok(ProvenanceReport {
        work_unit_id: work_unit_id.into(),
        calls,
        decisions,
        assurance,
    })
}

fn assemble_assurance(db: &SekaiDb, decisions: &[Decision]) -> Result<AssuranceSummary, String> {
    let ledger = db.verify_ledger()?;
    let mut attestations = Vec::new();
    for decision in decisions {
        let Some(attestation_id) = decision.evidence.get(EVIDENCE_ATTESTATION_ID) else {
            continue;
        };
        let attestation = db.get_attestation(attestation_id)?;
        let mut verification = db.verify_attestation(attestation_id)?;
        if let Some(attestation) = &attestation {
            let id_matches = attestation.decision_id == decision.id;
            let hash_matches =
                decision.evidence.get(EVIDENCE_ATTESTATION_HASH) == Some(&attestation.content_hash);
            if !id_matches || !hash_matches {
                verification.ok = false;
                verification.decision_linked = false;
                let binding_error = format!(
                    "reported decision {} does not bind attestation {}",
                    decision.id, attestation_id
                );
                verification.error = if verification.error.is_empty() {
                    binding_error
                } else {
                    format!("{}; {binding_error}", verification.error)
                };
            }
        }
        attestations.push(VerifiedAttestation {
            attestation_id: attestation_id.clone(),
            decision_id: decision.id.clone(),
            verification,
        });
    }
    Ok(AssuranceSummary {
        ledger,
        attestations,
    })
}

fn model_call(row: HashMap<String, String>) -> ModelCall {
    let value = |key: &str| row.get(key).cloned().unwrap_or_default();
    let number = |key: &str| value(key).parse().unwrap_or(0);
    ModelCall {
        request_id: value("request_id"),
        timestamp_ms: number("timestamp_ms"),
        provider: value("provider"),
        requested_model: value("model"),
        resolved_model: value("resolved_model"),
        route_bias: value("route_bias"),
        policy_scope: value("policy_scope"),
        policy_version: value("policy_version"),
        status: value("status"),
        refusal_reason: value("refusal_reason"),
        input_tokens: number("input_tokens"),
        output_tokens: number("output_tokens"),
        cost_usd_micros: number("cost_usd_micros"),
    }
}

pub fn render_text(report: &ProvenanceReport) -> String {
    let verdict = report.policy_verdict();
    let verdict_summary = if verdict.clean {
        format!(
            "policy-clean: no recorded policy violations ({} refusal(s) enforced)",
            verdict.enforced_refusals
        )
    } else {
        format!(
            "policy exceptions: {} recorded exception(s)",
            verdict.exceptions.len()
        )
    };
    let mut output = format!(
        "Provenance for {}\n\nSummary\n  {}\n  model calls: {}\n  audit decisions: {}\n  cost: ${:.6}\n\nModel calls\n",
        report.work_unit_id,
        verdict_summary,
        report.calls.len(),
        report.decisions.len(),
        report.total_cost_usd_micros() as f64 / 1_000_000.0,
    );
    for call in &report.calls {
        let model = if call.resolved_model.is_empty() {
            &call.requested_model
        } else {
            &call.resolved_model
        };
        output.push_str(&format!(
            "  {}  provider={} model={} status={} tokens={}/{} cost=${:.6}",
            call.request_id,
            call.provider,
            model,
            call.status,
            call.input_tokens,
            call.output_tokens,
            call.cost_usd_micros as f64 / 1_000_000.0
        ));
        if !call.refusal_reason.is_empty() {
            output.push_str(&format!(" refusal={}", call.refusal_reason));
        }
        if !call.route_bias.is_empty() || !call.policy_scope.is_empty() {
            output.push_str(&format!(
                " route_reason={} policy={}@{}",
                if call.route_bias.is_empty() {
                    "policy"
                } else {
                    &call.route_bias
                },
                call.policy_scope,
                call.policy_version,
            ));
        }
        output.push('\n');
    }
    output.push_str("\nAudit trail\n");
    for decision in &report.decisions {
        output.push_str(&format!(
            "  {}  actor={} action={} outcome={} reason={}\n",
            decision.id, decision.actor, decision.action, decision.outcome, decision.reason
        ));
    }
    if !verdict.exceptions.is_empty() {
        output.push_str("\nPolicy exceptions\n");
        for exception in verdict.exceptions {
            output.push_str(&format!(
                "  {}  action={} outcome={} reason={}\n",
                exception.decision_id, exception.action, exception.outcome, exception.reason
            ));
        }
    }
    let actions = report.governed_actions();
    output.push_str("\nGoverned actions and commands\n");
    if actions.is_empty() {
        output.push_str("  none recorded\n");
    }
    for action in actions {
        output.push_str(&format!(
            "  {}  actor={} action={} target={} risk={} decision={} outcome={}{}\n",
            action.decision_id,
            action.actor,
            action.action,
            action.target_id,
            action.risk_class,
            action.decision,
            action.outcome,
            if action.dry_run { " dry-run" } else { "" }
        ));
    }
    output.push_str("\nData access and egress\n");
    let egress = report.data_egress();
    if egress.is_empty() {
        output.push_str("  no recorded context egress\n");
    }
    for record in egress {
        output.push_str(&format!(
            "  {}  request={} provider={} model={} included_fields={} redacted_fields={} outcome={}\n",
            record.decision_id, record.request_id, record.provider, record.model,
            record.included_fields, record.redacted_fields, record.outcome
        ));
        if !record.included.is_empty() {
            output.push_str(&format!("    cleared: {}\n", record.included.join(", ")));
        }
        if !record.redacted.is_empty() {
            output.push_str(&format!("    denied: {}\n", record.redacted.join(", ")));
        }
    }
    output.push_str("  coverage: model calls, recorded context egress, policy decisions, and governed actions; activity outside governed surfaces is not captured\n");
    output.push_str("\nVerification\n");
    match &report.assurance {
        Some(assurance) => {
            let evidence_present = !report.calls.is_empty() || !report.decisions.is_empty();
            output.push_str(&format!(
                "  {}: audit ledger {} ({} entries checked, head seq {}), {} policy attestation(s) verified\n",
                if assurance.verifiable(evidence_present) { "verifiable" } else { "not verifiable" },
                if assurance.ledger.ok { "valid" } else { "INVALID" },
                assurance.ledger.entries_checked,
                assurance.ledger.head_seq,
                assurance.attestations.iter().filter(|item| item.verification.ok).count(),
            ));
            for item in &assurance.attestations {
                output.push_str(&format!(
                    "  attestation={} decision={} status={} hash={} replay={} linked={}{}\n",
                    item.attestation_id,
                    item.decision_id,
                    if item.verification.ok {
                        "valid"
                    } else {
                        "INVALID"
                    },
                    item.verification.hash_ok,
                    item.verification.replay_ok,
                    item.verification.decision_linked,
                    if item.verification.error.is_empty() {
                        String::new()
                    } else {
                        format!(" error={}", item.verification.error)
                    },
                ));
            }
        }
        None => output.push_str("  recorded truth only; verification was not performed\n"),
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::dataset::{ColumnDef, Dataset};

    #[test]
    fn assembles_calls_and_request_linked_decisions() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: "llm_calls".into(),
            name: "LLM calls".into(),
            columns: vec![ColumnDef {
                name: "work_unit_id".into(),
                col_type: "string".into(),
            }],
            object_id: String::new(),
            created: 1,
        })
        .unwrap();
        db.append_rows(
            "llm_calls",
            &[HashMap::from([
                ("request_id".into(), "req-1".into()),
                ("work_unit_id".into(), "task-1".into()),
                ("provider".into(), "anthropic".into()),
                ("resolved_model".into(), "claude".into()),
                ("status".into(), "200".into()),
                ("input_tokens".into(), "10".into()),
                ("output_tokens".into(), "5".into()),
                ("cost_usd_micros".into(), "42".into()),
            ])],
        )
        .unwrap();
        db.record_decision(&Decision {
            id: "dec-1".into(),
            timestamp: 2,
            actor: "gateway".into(),
            action: "gateway.policy".into(),
            reason: "matched".into(),
            evidence: HashMap::from([("request_id".into(), "req-1".into())]),
            target_id: "llm_calls".into(),
            outcome: "allowed".into(),
        })
        .unwrap();

        let report = assemble_report(&db, "task-1").unwrap();
        assert_eq!(report.calls.len(), 1);
        assert_eq!(report.decisions.len(), 1);
        assert_eq!(report.total_cost_usd_micros(), 42);
        assert!(report.assurance.as_ref().unwrap().ledger.ok);
        assert!(render_text(&report).contains("provider=anthropic model=claude"));
    }

    #[test]
    fn includes_work_unit_budget_warnings() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: "llm_calls".into(),
            name: "LLM calls".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
        })
        .unwrap();
        db.append_rows(
            "llm_calls",
            &[HashMap::from([
                ("request_id".into(), "req-1".into()),
                ("work_unit_id".into(), "task-1".into()),
                ("timestamp_ms".into(), "10".into()),
            ])],
        )
        .unwrap();
        db.record_decision(&Decision {
            id: "warning".into(),
            timestamp: 11,
            actor: "gateway".into(),
            action: "gateway.budget_warning".into(),
            reason: "threshold".into(),
            evidence: HashMap::from([
                ("scope_kind".into(), "work_unit".into()),
                (
                    "budget_subject".into(),
                    "project:p/agent:a/work_unit:task-1".into(),
                ),
            ]),
            target_id: "llm_calls".into(),
            outcome: "warned".into(),
        })
        .unwrap();

        assert_eq!(assemble_report(&db, "task-1").unwrap().decisions.len(), 1);
    }

    #[test]
    fn evidence_matching_is_exact_for_free_form_work_unit_ids() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: "llm_calls".into(),
            name: "LLM calls".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
        })
        .unwrap();
        db.append_rows(
            "llm_calls",
            &[HashMap::from([
                ("request_id".into(), "req".into()),
                ("work_unit_id".into(), "task_%".into()),
            ])],
        )
        .unwrap();
        for (id, key, value) in [
            ("work", "work_unit", "task_%"),
            ("work-id", "work_unit_id", "task_%"),
            ("case-variant", "work_unit", "TASK_%"),
        ] {
            db.record_decision(&Decision {
                id: id.into(),
                timestamp: 1,
                actor: "agent".into(),
                action: "action".into(),
                reason: String::new(),
                evidence: HashMap::from([(key.into(), value.into())]),
                target_id: "object".into(),
                outcome: "allowed".into(),
            })
            .unwrap();
        }

        let report = assemble_report(&db, "task_%").unwrap();
        assert_eq!(
            report
                .decisions
                .iter()
                .map(|d| d.id.as_str())
                .collect::<Vec<_>>(),
            vec!["work", "work-id"]
        );
    }

    #[test]
    fn verdict_distinguishes_enforced_blocks_from_policy_exceptions() {
        let report = ProvenanceReport {
            work_unit_id: "task".into(),
            calls: vec![ModelCall {
                request_id: "refused".into(),
                refusal_reason: "budget".into(),
                ..empty_call()
            }],
            decisions: vec![
                Decision {
                    id: "blocked".into(),
                    timestamp: 1,
                    actor: "privacy".into(),
                    action: "leak_check".into(),
                    reason: "leak checker evaluated outbound payload".into(),
                    evidence: HashMap::new(),
                    target_id: "req".into(),
                    outcome: "leak_blocked".into(),
                },
                Decision {
                    id: "warned".into(),
                    timestamp: 2,
                    actor: "privacy".into(),
                    action: "leak_check".into(),
                    reason: "possible secret".into(),
                    evidence: HashMap::new(),
                    target_id: "req".into(),
                    outcome: "leak_warned".into(),
                },
            ],
            assurance: None,
        };

        let verdict = report.policy_verdict();
        assert!(!verdict.clean);
        assert_eq!(verdict.enforced_refusals, 2);
        assert_eq!(verdict.exceptions[0].decision_id, "warned");
        assert!(render_text(&report).contains("policy exceptions: 1 recorded exception"));
    }

    #[test]
    fn renders_governed_actions_from_attributed_decisions() {
        let report = ProvenanceReport {
            work_unit_id: "task".into(),
            calls: vec![],
            decisions: vec![Decision {
                id: "action-1".into(),
                timestamp: 3,
                actor: "agent".into(),
                action: "run_command".into(),
                reason: "execute_action".into(),
                evidence: HashMap::from([
                    ("work_unit".into(), "task".into()),
                    ("risk_class".into(), "write".into()),
                    ("decision".into(), "allow".into()),
                ]),
                target_id: "workspace".into(),
                outcome: "command completed".into(),
            }],
            assurance: None,
        };

        let actions = report.governed_actions();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action, "run_command");
        assert!(
            render_text(&report)
                .contains("action=run_command target=workspace risk=write decision=allow")
        );
    }

    #[test]
    fn request_target_decisions_surface_egress_counts() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: "llm_calls".into(),
            name: "LLM calls".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
        })
        .unwrap();
        db.append_rows(
            "llm_calls",
            &[HashMap::from([
                ("request_id".into(), "req-egress".into()),
                ("work_unit_id".into(), "task".into()),
            ])],
        )
        .unwrap();
        db.record_decision(&Decision {
            id: "egress".into(),
            timestamp: 1,
            actor: "chisei.egress".into(),
            action: "context_egress".into(),
            reason: "context egress policy applied".into(),
            evidence: HashMap::from([
                ("provider".into(), "anthropic".into()),
                ("model".into(), "claude".into()),
                ("included_count".into(), "4".into()),
                ("redacted_count".into(), "2".into()),
                ("included_fields".into(), r#"["object#1.title"]"#.into()),
                ("redacted_fields".into(), r#"["object#1.secret"]"#.into()),
            ]),
            target_id: "req-egress".into(),
            outcome: "redacted".into(),
        })
        .unwrap();
        db.record_decision(&Decision {
            id: "colliding-object".into(),
            timestamp: 2,
            actor: "agent".into(),
            action: "set_property".into(),
            reason: "object mutation".into(),
            evidence: HashMap::new(),
            target_id: "req-egress".into(),
            outcome: "updated".into(),
        })
        .unwrap();

        let report = assemble_report(&db, "task").unwrap();
        assert_eq!(report.decisions.len(), 1);
        assert_eq!(report.data_egress()[0].redacted_fields, 2);
        assert!(
            render_text(&report)
                .contains("provider=anthropic model=claude included_fields=4 redacted_fields=2")
        );
        assert!(render_text(&report).contains("cleared: object#1.title"));
        assert!(render_text(&report).contains("denied: object#1.secret"));
    }

    #[test]
    fn verifies_linked_policy_attestations_and_the_audit_ledger() {
        use crate::sekai::action::RiskClass;
        use crate::sekai::action_policy::{ActionDecision, ActionPolicy};
        use crate::sekai::attestation::{
            ActionAttestationInput, EVIDENCE_ATTESTATION_HASH, build_action_attestation,
        };

        let db = SekaiDb::new(":memory:").unwrap();
        db.create_dataset(&Dataset {
            id: "llm_calls".into(),
            name: "LLM calls".into(),
            columns: vec![],
            object_id: String::new(),
            created: 1,
        })
        .unwrap();
        db.append_rows(
            "llm_calls",
            &[HashMap::from([
                ("request_id".into(), "req".into()),
                ("work_unit_id".into(), "task".into()),
            ])],
        )
        .unwrap();
        let policy = ActionPolicy {
            scope: "agent:tester".into(),
            default_decision: ActionDecision::Allow,
            action_overrides: HashMap::new(),
            risk_overrides: HashMap::new(),
            max_mutations_per_work_unit: None,
            max_deletes_per_work_unit: None,
        };
        let attestation = build_action_attestation(ActionAttestationInput {
            decision_id: "decision",
            policy: &policy,
            action: "set_property",
            actor: "tester",
            risk: RiskClass::Write,
            namespace: "default",
            decision: ActionDecision::Allow,
            created: 1,
        });
        let decision = Decision {
            id: "decision".into(),
            timestamp: 1,
            actor: "tester".into(),
            action: "set_property".into(),
            reason: "execute_action".into(),
            evidence: HashMap::from([
                ("request_id".into(), "req".into()),
                (EVIDENCE_ATTESTATION_ID.into(), attestation.id.clone()),
                (
                    EVIDENCE_ATTESTATION_HASH.into(),
                    attestation.content_hash.clone(),
                ),
            ]),
            target_id: "object".into(),
            outcome: "updated".into(),
        };
        db.record_decision_with_attestation(&decision, Some(&attestation))
            .unwrap();

        let report = assemble_report(&db, "task").unwrap();
        let assurance = report.assurance.as_ref().unwrap();
        assert!(assurance.verifiable(true));
        assert_eq!(assurance.attestations.len(), 1);
        assert!(render_text(&report).contains("verifiable: audit ledger valid"));

        let mut cross_linked = decision.clone();
        cross_linked.id = "different-decision".into();
        let cross_linked_assurance = assemble_assurance(&db, &[cross_linked]).unwrap();
        assert!(!cross_linked_assurance.attestations[0].verification.ok);
        assert!(
            !cross_linked_assurance.attestations[0]
                .verification
                .decision_linked
        );
    }

    fn empty_call() -> ModelCall {
        ModelCall {
            request_id: String::new(),
            timestamp_ms: 0,
            provider: String::new(),
            requested_model: String::new(),
            resolved_model: String::new(),
            route_bias: String::new(),
            policy_scope: String::new(),
            policy_version: String::new(),
            status: String::new(),
            refusal_reason: String::new(),
            input_tokens: 0,
            output_tokens: 0,
            cost_usd_micros: 0,
        }
    }
}
