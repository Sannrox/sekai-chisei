//! Promote authorized Gunshi operator feedback into durable eval-suite cases.
//!
//! Cases are append-only under suite ids prefixed with `feedback-`, with
//! deterministic case ids so promotion is idempotent.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::chisei::eval::{Assertion, Case, Suite};
use crate::chisei::gunshi::{OperatorResponse, ResourceSelection};
use crate::chisei::gunshi_feedback::{FEEDBACK_RECORD_VERSION, GunshiFeedbackRecord};
use crate::db::runtime_db::RuntimeDb;
use crate::sekai::audit::Decision;

pub const FEEDBACK_SUITE_PREFIX: &str = "feedback-";
pub const PROMOTE_ACTION: &str = "gunshi.feedback_promoted_to_eval";
pub const PROMOTED_CASE_VERSION: &str = "gunshi.feedback-eval-case/v1";
const MAX_SPEC_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedbackEvalCasePayload {
    pub contract_version: String,
    pub feedback_contract_version: String,
    pub issuance_id: String,
    pub allocation_id: String,
    pub operation_id: String,
    pub namespace: String,
    pub operation_class: String,
    pub operator_response: OperatorResponse,
    pub operator_rationale_redacted: String,
    pub selected_resources: Option<ResourceSelection>,
    pub outcome_accepted: Option<bool>,
    pub outcome_quality: Option<f64>,
    pub outcome_receipt_reference: Option<String>,
    pub source_actor: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromoteFeedbackResult {
    pub suite_id: String,
    pub case_id: String,
    pub created: bool,
    pub suite: Suite,
}

/// Deterministic case id for a feedback promotion (idempotent key).
pub fn feedback_case_id(issuance_id: &str, allocation_id: &str) -> String {
    let digest = Sha256::digest(format!("{issuance_id}\0{allocation_id}").as_bytes());
    format!("gunshi-fb-{}", &format!("{digest:x}")[..24])
}

pub fn default_feedback_suite_id(namespace: &str, operation_class: &str) -> String {
    format!("{FEEDBACK_SUITE_PREFIX}{namespace}:{operation_class}")
}

pub fn is_feedback_suite_id(suite_id: &str) -> bool {
    suite_id.starts_with(FEEDBACK_SUITE_PREFIX)
}

pub fn redact_rationale(rationale: &str) -> String {
    let trimmed = rationale.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Keep length signal without retaining free-form sensitive content by default.
    if trimmed.len() <= 48 {
        return "[redacted]".into();
    }
    format!("[redacted:{} chars]", trimmed.chars().count())
}

pub fn case_from_feedback(record: &GunshiFeedbackRecord) -> Result<Case, String> {
    if record.contract_version != FEEDBACK_RECORD_VERSION {
        return Err(format!(
            "unsupported feedback contract {}",
            record.contract_version
        ));
    }
    record.plan.validate()?;
    let case_id = feedback_case_id(&record.issuance_id, &record.plan.allocation_id);
    let payload = FeedbackEvalCasePayload {
        contract_version: PROMOTED_CASE_VERSION.into(),
        feedback_contract_version: record.contract_version.clone(),
        issuance_id: record.issuance_id.clone(),
        allocation_id: record.plan.allocation_id.clone(),
        operation_id: record.plan.operation_id.clone(),
        namespace: record.plan.namespace.clone(),
        operation_class: record.plan.operation_class.clone(),
        operator_response: record.choice.response,
        operator_rationale_redacted: redact_rationale(&record.choice.rationale),
        selected_resources: record.choice.selected_resources.clone(),
        outcome_accepted: record.outcome.as_ref().map(|outcome| outcome.accepted),
        outcome_quality: record.outcome.as_ref().map(|outcome| outcome.quality),
        outcome_receipt_reference: record
            .outcome
            .as_ref()
            .map(|outcome| outcome.receipt_reference.clone()),
        source_actor: record.actor.clone(),
    };
    let spec = serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())?;
    if spec.len() > MAX_SPEC_BYTES {
        return Err("promoted feedback case exceeds the size limit".into());
    }
    let response_value = match record.choice.response {
        OperatorResponse::Accepted => "accepted",
        OperatorResponse::Modified => "modified",
        OperatorResponse::Rejected => "rejected",
    };
    let mut assertions = vec![Assertion {
        assert_type: "gunshi_operator_response".into(),
        value: response_value.into(),
    }];
    if let Some(outcome) = &record.outcome {
        assertions.push(Assertion {
            assert_type: "gunshi_outcome_accepted".into(),
            value: outcome.accepted.to_string(),
        });
    }
    Ok(Case {
        id: case_id,
        name: format!(
            "Gunshi feedback {} / {}",
            record.plan.allocation_id, record.issuance_id
        ),
        namespace: record.plan.namespace.clone(),
        spec,
        assertions,
    })
}

/// Load feedback by decision id components and promote into a feedback- suite.
pub fn promote_feedback_to_eval(
    db: &RuntimeDb,
    actor: &str,
    suite_id: &str,
    issuance_id: &str,
    allocation_id: &str,
    namespace: &str,
    now_ms: i64,
) -> Result<PromoteFeedbackResult, String> {
    required("actor", actor)?;
    required("suite id", suite_id)?;
    required("issuance id", issuance_id)?;
    required("allocation id", allocation_id)?;
    required("namespace", namespace)?;
    if !is_feedback_suite_id(suite_id) {
        return Err(format!(
            "feedback promotion requires a suite id starting with {FEEDBACK_SUITE_PREFIX:?}"
        ));
    }
    if now_ms < 0 {
        return Err("timestamp must be non-negative".into());
    }
    let record = load_feedback_record(db, namespace, allocation_id, issuance_id)?;
    if record.plan.namespace != namespace {
        return Err("feedback namespace does not match request namespace".into());
    }
    let case = case_from_feedback(&record)?;
    let existing = db.get_eval_suite_record(suite_id)?;
    let (suite, created) = match existing {
        Some(mut suite) => {
            if let Some(existing_case) = suite.cases.iter().find(|item| item.id == case.id) {
                if existing_case != &case {
                    return Err(format!(
                        "feedback case {} already exists with different content",
                        case.id
                    ));
                }
                return Ok(PromoteFeedbackResult {
                    suite_id: suite.id.clone(),
                    case_id: case.id,
                    created: false,
                    suite,
                });
            }
            // All cases in a feedback suite must stay within the same namespace.
            if suite
                .cases
                .iter()
                .any(|item| item.namespace != record.plan.namespace)
            {
                return Err("feedback suite contains cases from another namespace".into());
            }
            suite.cases.push(case.clone());
            suite.cases.sort_by(|left, right| left.id.cmp(&right.id));
            db.append_feedback_eval_suite(&suite)?;
            (suite, true)
        }
        None => {
            let suite = Suite {
                id: suite_id.into(),
                name: format!(
                    "Gunshi feedback ({}/{})",
                    record.plan.namespace, record.plan.operation_class
                ),
                description: "Operator feedback promoted into evaluation cases".into(),
                cases: vec![case.clone()],
            };
            db.append_feedback_eval_suite(&suite)?;
            (suite, true)
        }
    };
    audit_promotion(db, actor, &suite, &case, &record, created, now_ms)?;
    Ok(PromoteFeedbackResult {
        suite_id: suite.id.clone(),
        case_id: case.id,
        created,
        suite,
    })
}

fn load_feedback_record(
    db: &RuntimeDb,
    namespace: &str,
    allocation_id: &str,
    issuance_id: &str,
) -> Result<GunshiFeedbackRecord, String> {
    crate::chisei::gunshi_feedback::load_choice_feedback(db, namespace, allocation_id, issuance_id)
}

fn audit_promotion(
    db: &RuntimeDb,
    actor: &str,
    suite: &Suite,
    case: &Case,
    record: &GunshiFeedbackRecord,
    created: bool,
    now_ms: i64,
) -> Result<(), String> {
    let decision = Decision {
        id: format!(
            "gunshi-fb-promote:{}:{}:{}",
            suite.id,
            case.id,
            if created { "new" } else { "idempotent" }
        ),
        timestamp: now_ms,
        actor: actor.into(),
        action: PROMOTE_ACTION.into(),
        reason: if created {
            "promoted operator feedback into eval suite".into()
        } else {
            "idempotent feedback promotion".into()
        },
        evidence: HashMap::from([
            ("namespace".into(), record.plan.namespace.clone()),
            ("data_class".into(), "internal".into()),
            ("suite_id".into(), suite.id.clone()),
            ("case_id".into(), case.id.clone()),
            ("issuance_id".into(), record.issuance_id.clone()),
            ("allocation_id".into(), record.plan.allocation_id.clone()),
            ("created".into(), created.to_string()),
        ]),
        target_id: case.id.clone(),
        outcome: if created {
            "promoted".into()
        } else {
            "unchanged".into()
        },
    };
    db.record_decision(&decision)
}

fn required(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::gunshi::{
        AllocationPlan, AttemptStrategy, BaselineStrategy, EscalationRules, ExpectedOutcome,
        OperatorChoice, OperatorResponse, ResourceSelection, StopConditions, Strategy,
        VerificationStrategy,
    };
    use crate::chisei::gunshi_feedback::record_issued_recommendations;
    use crate::db::runtime_db::RuntimeDb;

    fn plan() -> AllocationPlan {
        AllocationPlan {
            contract_version: crate::chisei::gunshi::ALLOCATION_CONTRACT_VERSION.into(),
            allocation_id: "alloc-1".into(),
            operation_id: "op-1".into(),
            namespace: "support".into(),
            operation_class: "triage".into(),
            priority: 1,
            strategy: Strategy {
                strategy_id: "balanced".into(),
                version: "1".into(),
                baseline: BaselineStrategy::Conservative,
            },
            policy_version: "governance-v1".into(),
            advisory: true,
            selection: ResourceSelection {
                agent_id: "agent".into(),
                runtime: "local".into(),
                model: "local".into(),
                tools: vec!["search".into()],
            },
            attempts: AttemptStrategy {
                max_attempts: 1,
                parallel_attempts: 1,
                speculative: false,
            },
            verification: VerificationStrategy {
                checks: vec!["operation_receipt_complete".into()],
                acceptance_criteria: vec!["classified".into()],
                human_review_required: false,
            },
            budget_ceiling_usd_micros: 1_000,
            stop_conditions: StopConditions {
                max_cost_usd_micros: 1_000,
                max_attempts: 1,
                deadline_ms: None,
                stop_on_acceptance: true,
            },
            escalation: EscalationRules {
                approval_required: false,
                escalate_on_budget_exhaustion: false,
                escalate_after_failed_attempts: 0,
            },
            evidence: vec![],
            expected: ExpectedOutcome {
                quality: 0.9,
                cost_usd_micros: 100,
                latency_ms: 10,
                uncertainty: 0.1,
            },
            explanation: vec!["test".into()],
            input_fingerprint: "fp".into(),
        }
    }

    fn seed_feedback(db: &RuntimeDb) -> GunshiFeedbackRecord {
        let plan = plan();
        record_issued_recommendations(
            db,
            "issuer",
            "iss-1",
            "digest",
            std::slice::from_ref(&plan),
            10,
            5,
        )
        .unwrap();
        let choice = OperatorChoice {
            operation_id: plan.operation_id.clone(),
            allocation_id: plan.allocation_id.clone(),
            response: OperatorResponse::Accepted,
            selected_resources: None,
            max_attempts: None,
            budget_ceiling_usd_micros: None,
            rationale: "looks good secret-token-should-redact".into(),
            decided_at_ms: 20,
        };
        crate::chisei::gunshi_feedback::record_feedback(
            db, "reviewer", "iss-1", &plan, &choice, None,
        )
        .unwrap()
    }

    #[test]
    fn promotes_feedback_idempotently_into_feedback_suite() {
        let db = RuntimeDb::memory();
        let record = seed_feedback(&db);
        let suite_id = default_feedback_suite_id("support", "triage");
        let first = promote_feedback_to_eval(
            &db,
            "admin",
            &suite_id,
            &record.issuance_id,
            &record.plan.allocation_id,
            "support",
            100,
        )
        .unwrap();
        assert!(first.created);
        assert_eq!(first.suite.cases.len(), 1);
        assert!(first.suite.cases[0].spec.contains("\"operator_response\""));
        assert!(
            !first.suite.cases[0]
                .spec
                .contains("secret-token-should-redact")
        );

        let second = promote_feedback_to_eval(
            &db,
            "admin",
            &suite_id,
            &record.issuance_id,
            &record.plan.allocation_id,
            "support",
            101,
        )
        .unwrap();
        assert!(!second.created);
        assert_eq!(second.suite.cases.len(), 1);
        assert_eq!(first.case_id, second.case_id);
    }

    #[test]
    fn rejects_non_feedback_suite_ids() {
        let db = RuntimeDb::memory();
        let record = seed_feedback(&db);
        assert!(
            promote_feedback_to_eval(
                &db,
                "admin",
                "fleet-eval",
                &record.issuance_id,
                &record.plan.allocation_id,
                "support",
                100,
            )
            .unwrap_err()
            .contains("feedback-")
        );
    }

    #[test]
    fn rejects_cross_namespace_promotion() {
        let db = RuntimeDb::memory();
        let record = seed_feedback(&db);
        let suite_id = default_feedback_suite_id("other", "triage");
        // Lookup is namespaced; foreign namespace cannot see the feedback row.
        let err = promote_feedback_to_eval(
            &db,
            "admin",
            &suite_id,
            &record.issuance_id,
            &record.plan.allocation_id,
            "other",
            100,
        )
        .unwrap_err();
        assert!(
            err.contains("no operator choice") || err.contains("namespace"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn case_id_is_stable() {
        assert_eq!(
            feedback_case_id("iss-1", "alloc-1"),
            feedback_case_id("iss-1", "alloc-1")
        );
        assert_ne!(
            feedback_case_id("iss-1", "alloc-1"),
            feedback_case_id("iss-2", "alloc-1")
        );
    }
}
