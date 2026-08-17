use crate::chisei::gunshi::{
    AdvisoryComparison, AdvisoryScorecard, AllocationPlan, ObservedOutcome, OperatorChoice,
    compare_advisory, score_advisory_comparisons,
};
use crate::chisei::receipt::{OperationReceipt, ReceiptEventKind};
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

pub const FEEDBACK_RECORD_VERSION: &str = "gunshi.feedback/v1";
const CHOICE_ACTION: &str = "gunshi.operator_choice";
const OUTCOME_ACTION: &str = "gunshi.observed_outcome";
const ISSUED_ACTION: &str = "gunshi.recommendation_issued";
const ISSUANCE_ACTION: &str = "gunshi.recommendation_request";
const MAX_FEEDBACK_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GunshiFeedbackRecord {
    pub contract_version: String,
    pub issuance_id: String,
    pub actor: String,
    pub plan: AllocationPlan,
    pub choice: OperatorChoice,
    pub outcome: Option<ObservedOutcome>,
    pub comparison: AdvisoryComparison,
}

pub fn record_issued_recommendations(
    db: &RuntimeDb,
    actor: &str,
    issuance_id: &str,
    request_digest: &str,
    plans: &[AllocationPlan],
    issued_at_ms: i64,
    capacity_captured_at_ms: i64,
) -> Result<(), String> {
    required("recommendation actor", actor)?;
    required("recommendation issuance", issuance_id)?;
    required("recommendation request digest", request_digest)?;
    if issued_at_ms < 0 {
        return Err("recommendation issue time must be non-negative".into());
    }
    let mut decisions = plans
        .iter()
        .map(|plan| {
            plan.validate()?;
            let plan_json = serde_json::to_string(plan).map_err(|error| error.to_string())?;
            if plan_json.len() > MAX_FEEDBACK_BYTES {
                return Err("Gunshi recommendation exceeds the size limit".into());
            }
            Ok(Decision {
                id: record_id("issued", &plan.namespace, &plan.allocation_id, issuance_id),
                timestamp: issued_at_ms,
                actor: actor.into(),
                action: ISSUED_ACTION.into(),
                reason: "issued advisory recommendation".into(),
                evidence: HashMap::from([
                    ("namespace".into(), plan.namespace.clone()),
                    ("data_class".into(), "internal".into()),
                    ("allocation_id".into(), plan.allocation_id.clone()),
                    ("operation_id".into(), plan.operation_id.clone()),
                    ("issuance_id".into(), issuance_id.into()),
                    (
                        "capacity_captured_at_ms".into(),
                        capacity_captured_at_ms.to_string(),
                    ),
                    ("allocation_plan".into(), plan_json),
                ]),
                target_id: plan.allocation_id.clone(),
                outcome: "advisory".into(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let allocation_json = serde_json::to_vec(plans).map_err(|error| error.to_string())?;
    let allocation_digest = format!("{:x}", Sha256::digest(&allocation_json));
    let namespaces = plans
        .iter()
        .map(|plan| plan.namespace.as_str())
        .collect::<BTreeSet<_>>();
    decisions.insert(
        0,
        Decision {
            id: issuance_record_id(&namespaces, issuance_id),
            timestamp: issued_at_ms,
            actor: actor.into(),
            action: ISSUANCE_ACTION.into(),
            reason: "issued advisory recommendation request".into(),
            evidence: HashMap::from([
                ("data_class".into(), "internal".into()),
                ("issuance_id".into(), issuance_id.into()),
                ("request_digest".into(), request_digest.into()),
                ("allocation_digest".into(), allocation_digest),
            ]),
            target_id: issuance_id.into(),
            outcome: "advisory".into(),
        },
    );
    db.record_decisions_idempotently_by(&decisions, |existing, requested| {
        if existing.action == ISSUANCE_ACTION && requested.action == ISSUANCE_ACTION {
            return existing.evidence.get("request_digest")
                == requested.evidence.get("request_digest")
                && existing.evidence.get("allocation_digest")
                    == requested.evidence.get("allocation_digest");
        }
        existing.action == requested.action
            && existing.target_id == requested.target_id
            && existing.evidence.get("namespace") == requested.evidence.get("namespace")
            && existing.evidence.get("allocation_plan") == requested.evidence.get("allocation_plan")
    })
}

pub fn record_feedback(
    db: &RuntimeDb,
    actor: &str,
    issuance_id: &str,
    plan: &AllocationPlan,
    choice: &OperatorChoice,
    outcome: Option<&ObservedOutcome>,
) -> Result<GunshiFeedbackRecord, String> {
    required("feedback actor", actor)?;
    required("recommendation issuance", issuance_id)?;
    let comparison = compare_advisory(plan, choice, outcome)?;
    if choice.decided_at_ms < 0 {
        return Err("operator decision time must be non-negative".into());
    }
    if let Some(outcome) = outcome
        && (outcome.completed_at_ms < choice.decided_at_ms || outcome.completed_at_ms < 0)
    {
        return Err("observed outcome cannot precede the operator decision".into());
    }
    let issued = require_issued_plan(db, issuance_id, plan)?;
    if choice.decided_at_ms < issued.timestamp {
        return Err("operator decision cannot precede recommendation issuance".into());
    }
    if let Some(outcome) = outcome {
        let receipt = db
            .get_operation_receipt(&outcome.receipt_reference)?
            .ok_or_else(|| "observed outcome receipt is not governed by Sekai".to_string())?;
        let logical_operation_id = receipt
            .events
            .iter()
            .find(|event| event.kind == ReceiptEventKind::IntentRecorded)
            .and_then(|event| event.attributes.get("logical_operation_id"))
            .map(String::as_str);
        let operation_matches = receipt.operation_id == plan.operation_id
            || logical_operation_id == Some(plan.operation_id.as_str());
        if !operation_matches
            || receipt.namespace != plan.namespace
            || receipt.operation_class != plan.operation_class
        {
            return Err("observed outcome receipt does not match the allocation scope".into());
        }
        let completeness = receipt.completeness();
        if !completeness.complete {
            return Err("observed outcome receipt is incomplete".into());
        }
        validate_outcome_receipt(&receipt, outcome)?;
    }
    let record = GunshiFeedbackRecord {
        contract_version: FEEDBACK_RECORD_VERSION.into(),
        issuance_id: issuance_id.into(),
        actor: actor.into(),
        plan: plan.clone(),
        choice: choice.clone(),
        outcome: outcome.cloned(),
        comparison,
    };
    let record_json = serde_json::to_string(&record).map_err(|error| error.to_string())?;
    if record_json.len() > MAX_FEEDBACK_BYTES {
        return Err("Gunshi feedback record exceeds the size limit".into());
    }
    let mut decisions = vec![feedback_decision(
        record_id("choice", &plan.namespace, &plan.allocation_id, issuance_id),
        actor,
        issuance_id,
        CHOICE_ACTION,
        plan,
        choice,
        None,
    )?];
    if let Some(outcome) = outcome {
        decisions.push(feedback_decision(
            record_id("outcome", &plan.namespace, &plan.allocation_id, issuance_id),
            actor,
            issuance_id,
            OUTCOME_ACTION,
            plan,
            choice,
            Some(outcome),
        )?);
    }
    db.record_decisions_idempotently_by(&decisions, feedback_decisions_equivalent)?;
    Ok(record)
}

fn feedback_decisions_equivalent(existing: &Decision, requested: &Decision) -> bool {
    if existing.action != requested.action
        || existing.target_id != requested.target_id
        || existing.timestamp != requested.timestamp
        || existing.reason != requested.reason
        || existing.outcome != requested.outcome
    {
        return false;
    }
    let (Ok(mut existing_record), Ok(mut requested_record)) =
        (decode_record(existing), decode_record(requested))
    else {
        return false;
    };
    existing_record.actor.clear();
    requested_record.actor.clear();
    existing_record == requested_record
}

pub fn require_issued_plan(
    db: &RuntimeDb,
    issuance_id: &str,
    plan: &AllocationPlan,
) -> Result<Decision, String> {
    let issued = db
        .get_decision(&record_id(
            "issued",
            &plan.namespace,
            &plan.allocation_id,
            issuance_id,
        ))?
        .filter(|decision| decision.action == ISSUED_ACTION)
        .ok_or_else(|| "allocation was not issued by Gunshi".to_string())?;
    let stored: AllocationPlan = serde_json::from_str(
        issued
            .evidence
            .get("allocation_plan")
            .ok_or_else(|| "issued recommendation has no allocation plan".to_string())?,
    )
    .map_err(|error| format!("decode issued recommendation: {error}"))?;
    if stored == *plan {
        Ok(issued)
    } else {
        Err("allocation does not match the issued Gunshi recommendation".into())
    }
}

fn validate_outcome_receipt(
    receipt: &OperationReceipt,
    outcome: &ObservedOutcome,
) -> Result<(), String> {
    if receipt.completed_at_ms != Some(outcome.completed_at_ms) {
        return Err("observed completion time does not match its receipt".into());
    }
    let terminals = receipt
        .events
        .iter()
        .filter(|event| event.kind == ReceiptEventKind::OutcomeRecorded)
        .collect::<Vec<_>>();
    let [terminal] = terminals.as_slice() else {
        return Err("observed outcome receipt must have exactly one outcome event".into());
    };
    let accepted = match terminal.attributes.get("passed") {
        Some(passed) => passed
            .parse::<bool>()
            .map_err(|_| "observed outcome receipt passed result is invalid".to_string())?,
        None => terminal
            .attributes
            .get("status")
            .is_some_and(|status| matches!(status.as_str(), "completed" | "succeeded" | "success")),
    };
    let quality = if let Some(score) = terminal.attributes.get("score") {
        let score = score
            .parse::<f64>()
            .map_err(|_| "observed outcome receipt score is invalid".to_string())?;
        if !score.is_finite() || !(0.0..=100.0).contains(&score) {
            return Err("observed outcome receipt score must be between 0 and 100".into());
        }
        score / 100.0
    } else {
        terminal
            .attributes
            .get("outcome_value")
            .ok_or_else(|| "observed outcome receipt has no quality result".to_string())?
            .parse::<f64>()
            .map_err(|_| "observed outcome receipt quality result is invalid".to_string())?
    };
    let (cost, has_cost) = receipted_metric(receipt, terminal, "cost_usd_micros")?;
    let (latency, has_latency) = receipted_metric(receipt, terminal, "latency_ms")?;
    let attempts = receipt
        .events
        .iter()
        .filter(|event| event.kind == ReceiptEventKind::AttemptStarted)
        .count() as u32;
    if !has_cost || !has_latency || attempts == 0 {
        return Err("observed outcome receipt lacks cost, latency, or attempt evidence".into());
    }
    if accepted != outcome.accepted
        || quality != outcome.quality
        || cost != outcome.cost_usd_micros
        || latency != outcome.latency_ms
        || attempts != outcome.attempts
    {
        return Err("observed outcome metrics do not match their governed receipt".into());
    }
    Ok(())
}

fn receipted_metric(
    receipt: &OperationReceipt,
    terminal: &crate::chisei::receipt::OperationReceiptEvent,
    name: &str,
) -> Result<(i64, bool), String> {
    if let Some(value) = terminal.attributes.get(name) {
        return value
            .parse::<i64>()
            .map(|value| (value, true))
            .map_err(|_| format!("observed outcome receipt {name} is invalid"));
    }
    let mut total = 0_i64;
    let mut found = false;
    for value in receipt
        .events
        .iter()
        .filter_map(|event| event.attributes.get(name))
    {
        let value = value
            .parse::<i64>()
            .map_err(|_| format!("observed outcome receipt {name} is invalid"))?;
        total = total
            .checked_add(value)
            .ok_or_else(|| format!("observed outcome receipt {name} overflows"))?;
        found = true;
    }
    Ok((total, found))
}

pub fn advisory_scorecard(db: &RuntimeDb, namespace: &str) -> Result<AdvisoryScorecard, String> {
    required("scorecard namespace", namespace)?;
    let choices = feedback_decisions(db, CHOICE_ACTION, namespace)?;
    let outcomes = feedback_decisions(db, OUTCOME_ACTION, namespace)?
        .into_iter()
        .map(|decision| {
            decode_record(&decision).map(|record| {
                (
                    (
                        record.issuance_id.clone(),
                        record.plan.allocation_id.clone(),
                    ),
                    record,
                )
            })
        })
        .collect::<Result<HashMap<_, _>, _>>()?;
    let comparisons = choices
        .into_iter()
        .map(|decision| {
            let choice = decode_record(&decision)?;
            Ok(outcomes
                .get(&(
                    choice.issuance_id.clone(),
                    choice.plan.allocation_id.clone(),
                ))
                .map(|record| record.comparison.clone())
                .unwrap_or(choice.comparison))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(score_advisory_comparisons(&comparisons))
}

fn feedback_decisions(
    db: &RuntimeDb,
    action: &str,
    namespace: &str,
) -> Result<Vec<Decision>, String> {
    db.list_decisions_for_action_namespace(action, namespace)
}

fn feedback_decision(
    id: String,
    actor: &str,
    issuance_id: &str,
    action: &str,
    plan: &AllocationPlan,
    choice: &OperatorChoice,
    outcome: Option<&ObservedOutcome>,
) -> Result<Decision, String> {
    let comparison = compare_advisory(plan, choice, outcome)?;
    let record = GunshiFeedbackRecord {
        contract_version: FEEDBACK_RECORD_VERSION.into(),
        issuance_id: issuance_id.into(),
        actor: actor.into(),
        plan: plan.clone(),
        choice: choice.clone(),
        outcome: outcome.cloned(),
        comparison,
    };
    Ok(Decision {
        id,
        timestamp: outcome
            .map(|value| value.completed_at_ms)
            .unwrap_or(choice.decided_at_ms),
        actor: actor.into(),
        action: action.into(),
        reason: choice.rationale.clone(),
        evidence: HashMap::from([
            ("namespace".into(), plan.namespace.clone()),
            ("data_class".into(), "internal".into()),
            ("allocation_id".into(), plan.allocation_id.clone()),
            ("operation_id".into(), plan.operation_id.clone()),
            ("issuance_id".into(), issuance_id.into()),
            (
                "feedback_record".into(),
                serde_json::to_string(&record).map_err(|error| error.to_string())?,
            ),
        ]),
        target_id: plan.allocation_id.clone(),
        outcome: match outcome {
            Some(value) if value.accepted => "observed_accepted".into(),
            Some(_) => "observed_rejected".into(),
            None => format!("{:?}", choice.response).to_ascii_lowercase(),
        },
    })
}

fn decode_record(decision: &Decision) -> Result<GunshiFeedbackRecord, String> {
    let json = decision
        .evidence
        .get("feedback_record")
        .ok_or_else(|| format!("feedback decision {} has no record", decision.id))?;
    let record: GunshiFeedbackRecord =
        serde_json::from_str(json).map_err(|error| format!("decode {}: {error}", decision.id))?;
    if record.contract_version != FEEDBACK_RECORD_VERSION {
        return Err(format!(
            "unsupported feedback record contract {}",
            record.contract_version
        ));
    }
    Ok(record)
}

fn record_id(kind: &str, namespace: &str, allocation_id: &str, issuance_id: &str) -> String {
    let digest = Sha256::digest(format!("{namespace}\0{allocation_id}\0{issuance_id}").as_bytes());
    let digest = format!("{digest:x}");
    format!("gunshi-{kind}-{}", &digest[..32])
}

/// Load a stored operator-choice feedback record by issuance and allocation.
pub fn load_choice_feedback(
    db: &RuntimeDb,
    namespace: &str,
    allocation_id: &str,
    issuance_id: &str,
) -> Result<GunshiFeedbackRecord, String> {
    let decision = db
        .get_decision(&record_id("choice", namespace, allocation_id, issuance_id))?
        .filter(|decision| decision.action == CHOICE_ACTION)
        .ok_or_else(|| "no operator choice feedback found for allocation".to_string())?;
    decode_record(&decision)
}

fn issuance_record_id(namespaces: &BTreeSet<&str>, issuance_id: &str) -> String {
    let namespace_scope = namespaces.iter().copied().collect::<Vec<_>>().join("\0");
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{namespace_scope}\0{issuance_id}").as_bytes())
    );
    format!("gunshi-issuance-{}", &digest[..32])
}

fn required(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{name} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::gunshi::*;
    use std::collections::BTreeSet;

    fn plan() -> AllocationPlan {
        recommend_baseline(&AllocationRequest {
            capacity: CapacityEnvelope {
                captured_at_ms: 1,
                policy_version: "policy".into(),
                agents: vec![AgentCapacity {
                    agent_id: "agent".into(),
                    runtime: "native".into(),
                    models: BTreeSet::from(["model".into()]),
                    tools: BTreeSet::new(),
                    operation_classes: BTreeSet::from(["triage".into()]),
                    available_slots: 1,
                    healthy: true,
                }],
                model_profiles: vec![ModelProfile {
                    model: "model".into(),
                    quality: 0.8,
                    cost_per_attempt_usd_micros: 10,
                    latency_ms: 20,
                    uncertainty: 0.1,
                }],
                budget_remaining_usd_micros: 10,
                max_parallel_attempts: 1,
                human_attention_minutes: 1,
            },
            operations: vec![PendingOperation {
                operation_id: "op".into(),
                namespace: "support".into(),
                operation_class: "triage".into(),
                priority: 1,
                risk: OperationRisk::Low,
                submitted_at_ms: 1,
                required_tools: BTreeSet::new(),
                allowed_models: BTreeSet::new(),
                max_attempts: 1,
                budget_ceiling_usd_micros: 10,
                acceptance_criteria: vec![],
                approval_required: false,
                human_attention_minutes_required: 0,
            }],
            strategy: Strategy {
                strategy_id: "baseline".into(),
                version: "1".into(),
                baseline: BaselineStrategy::Conservative,
            },
        })
        .unwrap()
        .plans
        .remove(0)
    }

    fn choice(plan: &AllocationPlan) -> OperatorChoice {
        OperatorChoice {
            operation_id: plan.operation_id.clone(),
            allocation_id: plan.allocation_id.clone(),
            response: OperatorResponse::Accepted,
            selected_resources: None,
            max_attempts: None,
            budget_ceiling_usd_micros: None,
            rationale: "accepted as proposed".into(),
            decided_at_ms: 10,
        }
    }

    #[test]
    fn issuance_records_are_scoped_to_the_recommended_namespaces() {
        let support = BTreeSet::from(["support"]);
        let analytics = BTreeSet::from(["analytics"]);

        assert_ne!(
            issuance_record_id(&support, "issuance-a"),
            issuance_record_id(&analytics, "issuance-a")
        );
    }

    fn persist_receipt(db: &RuntimeDb, plan: &AllocationPlan) {
        persist_receipt_as(db, plan, &plan.operation_id, false);
    }

    fn persist_receipt_as(
        db: &RuntimeDb,
        plan: &AllocationPlan,
        receipt_operation_id: &str,
        include_logical_operation_id: bool,
    ) {
        use crate::chisei::receipt::{
            OPERATION_RECEIPT_VERSION, OperationReceipt, OperationReceiptEvent, ReceiptEventKind,
        };
        let kinds = [
            ReceiptEventKind::IntentRecorded,
            ReceiptEventKind::PolicyDecided,
            ReceiptEventKind::RouteSelected,
            ReceiptEventKind::BudgetDecided,
            ReceiptEventKind::AttemptStarted,
            ReceiptEventKind::OutcomeRecorded,
        ];
        let mut events = kinds
            .into_iter()
            .enumerate()
            .map(|(index, kind)| OperationReceiptEvent {
                event_id: format!("event-{index}"),
                operation_id: receipt_operation_id.into(),
                parent_event_id: (index > 0).then(|| format!("event-{}", index - 1)),
                timestamp_ms: index as i64 + 1,
                kind,
                surface: kind.surface(),
                actor: "alice".into(),
                references: Vec::new(),
                attributes: Default::default(),
            })
            .collect::<Vec<_>>();
        if include_logical_operation_id {
            events[0]
                .attributes
                .insert("logical_operation_id".into(), plan.operation_id.clone());
        }
        let terminal = events.last_mut().unwrap();
        terminal.attributes.insert("passed".into(), "true".into());
        terminal.attributes.insert("score".into(), "90".into());
        terminal
            .attributes
            .insert("cost_usd_micros".into(), "9".into());
        terminal.attributes.insert("latency_ms".into(), "18".into());
        db.put_operation_receipt(&OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: receipt_operation_id.into(),
            parent_operation_id: None,
            namespace: plan.namespace.clone(),
            operation_class: plan.operation_class.clone(),
            initiating_actor: "alice".into(),
            schema_version: "test/v1".into(),
            policy_version: plan.policy_version.clone(),
            started_at_ms: 1,
            completed_at_ms: Some(20),
            events,
            uncovered_surfaces: Vec::new(),
            reporter_grants: Vec::new(),
            ontology_digest: None,
        })
        .unwrap();
    }

    #[test]
    fn outcome_feedback_accepts_a_native_receipt_bound_by_logical_operation_id() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let plan = plan();
        let choice = choice(&plan);
        record_issued_recommendations(
            &db,
            "alice",
            "issuance-native",
            "request-native",
            std::slice::from_ref(&plan),
            1,
            1,
        )
        .unwrap();
        persist_receipt_as(&db, &plan, "native-plan-id", true);
        let outcome = ObservedOutcome {
            operation_id: plan.operation_id.clone(),
            receipt_reference: "native-plan-id".into(),
            accepted: true,
            quality: 0.9,
            cost_usd_micros: 9,
            latency_ms: 18,
            attempts: 1,
            completed_at_ms: 20,
        };

        let feedback = record_feedback(
            &db,
            "alice",
            "issuance-native",
            &plan,
            &choice,
            Some(&outcome),
        )
        .unwrap();

        assert_eq!(
            feedback.comparison.outcome_receipt_reference.as_deref(),
            Some("native-plan-id")
        );
    }

    #[test]
    fn choices_and_outcomes_are_idempotent_and_scoreable() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let plan = plan();
        let choice = choice(&plan);
        record_issued_recommendations(
            &db,
            "alice",
            "issuance-a",
            "request-a",
            std::slice::from_ref(&plan),
            1,
            1,
        )
        .unwrap();
        assert!(
            record_issued_recommendations(
                &db,
                "alice",
                "issuance-a",
                "different-request",
                std::slice::from_ref(&plan),
                2,
                1,
            )
            .is_err()
        );
        record_issued_recommendations(
            &db,
            "bob",
            "issuance-a",
            "request-a",
            std::slice::from_ref(&plan),
            2,
            1,
        )
        .unwrap();
        let issued = db
            .get_decision(&record_id(
                "issued",
                &plan.namespace,
                &plan.allocation_id,
                "issuance-a",
            ))
            .unwrap()
            .unwrap();
        assert_eq!(issued.actor, "alice");
        assert_eq!(issued.timestamp, 1);
        persist_receipt(&db, &plan);
        let outcome = ObservedOutcome {
            operation_id: plan.operation_id.clone(),
            receipt_reference: plan.operation_id.clone(),
            accepted: true,
            quality: 0.9,
            cost_usd_micros: 9,
            latency_ms: 18,
            attempts: 1,
            completed_at_ms: 20,
        };
        record_feedback(&db, "alice", "issuance-a", &plan, &choice, None).unwrap();
        record_feedback(&db, "bob", "issuance-a", &plan, &choice, Some(&outcome)).unwrap();
        record_feedback(&db, "bob", "issuance-a", &plan, &choice, Some(&outcome)).unwrap();

        let stored_choice = db
            .get_decision(&record_id(
                "choice",
                &plan.namespace,
                &plan.allocation_id,
                "issuance-a",
            ))
            .unwrap()
            .unwrap();
        let stored_outcome = db
            .get_decision(&record_id(
                "outcome",
                &plan.namespace,
                &plan.allocation_id,
                "issuance-a",
            ))
            .unwrap()
            .unwrap();
        assert_eq!(stored_choice.actor, "alice");
        assert_eq!(stored_outcome.actor, "bob");

        let scorecard = advisory_scorecard(&db, "support").unwrap();
        assert_eq!(scorecard.comparisons, 1);
        assert_eq!(scorecard.accepted, 1);
        assert_eq!(scorecard.observed_outcomes, 1);

        record_issued_recommendations(
            &db,
            "alice",
            "issuance-b",
            "request-b",
            std::slice::from_ref(&plan),
            3,
            1,
        )
        .unwrap();
        record_feedback(&db, "carol", "issuance-b", &plan, &choice, None).unwrap();
        let repeated = advisory_scorecard(&db, "support").unwrap();
        assert_eq!(repeated.comparisons, 2);
        assert_eq!(repeated.accepted, 2);
    }

    #[test]
    fn conflicting_feedback_and_predecision_outcomes_are_rejected() {
        let db = RuntimeDb::Sqlite(std::sync::Arc::new(SekaiDb::new(":memory:").unwrap()));
        let plan = plan();
        let choice = choice(&plan);
        record_issued_recommendations(
            &db,
            "alice",
            "issuance-a",
            "request-a",
            std::slice::from_ref(&plan),
            1,
            1,
        )
        .unwrap();
        persist_receipt(&db, &plan);
        let mut pre_issuance = choice.clone();
        pre_issuance.decided_at_ms = 0;
        assert!(record_feedback(&db, "alice", "issuance-a", &plan, &pre_issuance, None,).is_err());
        record_feedback(&db, "alice", "issuance-a", &plan, &choice, None).unwrap();
        let mut changed = choice.clone();
        changed.response = OperatorResponse::Rejected;
        assert!(record_feedback(&db, "alice", "issuance-a", &plan, &changed, None).is_err());

        let early = ObservedOutcome {
            operation_id: plan.operation_id.clone(),
            receipt_reference: plan.operation_id.clone(),
            accepted: true,
            quality: 1.0,
            cost_usd_micros: 0,
            latency_ms: 0,
            attempts: 1,
            completed_at_ms: 9,
        };
        assert!(record_feedback(&db, "alice", "issuance-a", &plan, &choice, Some(&early)).is_err());
    }
}
