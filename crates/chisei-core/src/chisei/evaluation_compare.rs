//! Receipt-backed comparison of two finished evaluation executions.
//!
//! A comparison is a read-side projection over immutable, receipted runs. It
//! runs no evaluator, resolves nothing, and grants nothing: each side is
//! rebuilt from the canonical operation receipt of one exact manifest digest,
//! and the diff is a pure function of those two receipts. Only `pass` (and the
//! `allow` verdict) is treated as good; every other closed state is a
//! non-pass, so the diff never invents a ranking between kinds of
//! inconclusive outcome. Evaluator output and evidence payloads are never
//! persisted in the receipts and therefore never appear here.

use crate::chisei::evaluation_execution::{
    EXECUTION_OPERATION_CLASS, EvaluationGateDecision, EvaluationStepReceipt,
    REASON_EXECUTION_CANCELLED, STATUS_PASS, VERDICT_ALLOW, execution_operation_id,
    step_and_gate_evidence,
};
use crate::chisei::evaluation_plan::NODE_REQUIRED;
use crate::chisei::receipt::OperationReceipt;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const COMPARISON_CONTRACT: &str = "chisei.evaluation-comparison/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonError {
    /// The receipt is not the evaluation execution receipt of this manifest
    /// digest in this namespace.
    Unbound,
    /// The execution has not reached a comparable terminal decision.
    NotFinished(&'static str),
    /// The receipt cannot be trusted as terminal evidence.
    Invalid(String),
}

impl fmt::Display for ComparisonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unbound => formatter.write_str("evaluation execution receipt binding is invalid"),
            Self::NotFinished(state) => write!(formatter, "evaluation execution is {state}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ComparisonError {}

/// One finished execution reduced to the bounded evidence a comparison needs.
#[derive(Debug, Clone, PartialEq)]
pub struct FinishedExecution {
    pub namespace: String,
    pub manifest_digest: String,
    pub operation_id: String,
    pub steps: Vec<EvaluationStepReceipt>,
    pub decision: EvaluationGateDecision,
}

impl FinishedExecution {
    /// Rebuild a finished execution from the canonical receipt of one exact
    /// manifest digest. A receipt for another namespace or manifest is
    /// [`ComparisonError::Unbound`], so callers can report it exactly like an
    /// absent receipt.
    pub fn from_receipt(
        namespace: &str,
        manifest_digest: &str,
        receipt: &OperationReceipt,
    ) -> Result<Self, ComparisonError> {
        let operation_id = execution_operation_id(manifest_digest);
        if receipt.operation_id != operation_id
            || receipt.namespace != namespace
            || receipt.operation_class != EXECUTION_OPERATION_CLASS
        {
            return Err(ComparisonError::Unbound);
        }
        let (steps, decision) =
            step_and_gate_evidence(receipt).map_err(ComparisonError::Invalid)?;
        let Some(decision) = decision else {
            return Err(ComparisonError::NotFinished("running"));
        };
        if decision.reason_code == REASON_EXECUTION_CANCELLED {
            return Err(ComparisonError::NotFinished("cancelled"));
        }
        if decision.manifest_digest != manifest_digest
            || steps
                .iter()
                .any(|step| step.manifest_digest != manifest_digest)
        {
            return Err(ComparisonError::Invalid(
                "evaluation receipt evidence is bound to a different manifest".into(),
            ));
        }
        let mut nodes = BTreeSet::new();
        if !steps.iter().all(|step| nodes.insert(step.node_id.as_str())) {
            return Err(ComparisonError::Invalid(
                "evaluation receipt repeats a node".into(),
            ));
        }
        let completeness = receipt.completeness();
        if !completeness.complete {
            return Err(ComparisonError::Invalid(format!(
                "terminal evaluation receipt is incomplete: {:?}",
                completeness.errors
            )));
        }
        Ok(Self {
            namespace: namespace.into(),
            manifest_digest: manifest_digest.into(),
            operation_id,
            steps,
            decision,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    Unchanged,
    /// A non-pass became a pass.
    Improved,
    /// A pass became a non-pass.
    Regressed,
    /// Any other difference: a different non-pass state or reason code.
    Changed,
    /// Present only in the candidate.
    Added,
    /// Present only in the baseline.
    Removed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The gate verdict worsened, or a required node regressed or was added
    /// without passing. Advisory movement never decides this.
    Regressed,
    /// Nothing regressed, and the gate verdict or a required node improved.
    Improved,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeSide {
    pub classification: String,
    pub status: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeComparison {
    pub node_id: String,
    pub baseline: Option<NodeSide>,
    pub candidate: Option<NodeSide>,
    pub change: Change,
    /// Which receipt digests differ, when the node exists on both sides.
    pub differs_in: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComparedExecution {
    pub manifest_digest: String,
    pub operation_id: String,
    pub verdict: String,
    pub reason_code: String,
    pub decision_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GateComparison {
    pub baseline_verdict: String,
    pub candidate_verdict: String,
    pub change: Change,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ComparisonSummary {
    pub unchanged: u32,
    pub improved: u32,
    pub regressed: u32,
    pub changed: u32,
    pub added: u32,
    pub removed: u32,
    pub required_improvements: u32,
    pub advisory_improvements: u32,
    pub required_regressions: u32,
    pub advisory_regressions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluationComparison {
    pub contract_version: &'static str,
    pub namespace: String,
    pub baseline: ComparedExecution,
    pub candidate: ComparedExecution,
    pub gate: GateComparison,
    pub nodes: Vec<NodeComparison>,
    pub summary: ComparisonSummary,
    pub outcome: Outcome,
}

/// Diff two finished executions of one namespace, node by node and by gate
/// verdict. Both sides must belong to `namespace`.
pub fn compare(
    baseline: &FinishedExecution,
    candidate: &FinishedExecution,
) -> Result<EvaluationComparison, ComparisonError> {
    if baseline.namespace != candidate.namespace {
        return Err(ComparisonError::Unbound);
    }
    let baseline_steps = by_node(&baseline.steps);
    let candidate_steps = by_node(&candidate.steps);
    let mut node_ids: Vec<&str> = baseline_steps
        .keys()
        .chain(candidate_steps.keys())
        .copied()
        .collect();
    node_ids.sort_unstable();
    node_ids.dedup();

    let mut summary = ComparisonSummary::default();
    let mut nodes = Vec::with_capacity(node_ids.len());
    for node_id in node_ids {
        let before = baseline_steps.get(node_id).copied();
        let after = candidate_steps.get(node_id).copied();
        let change = match (before, after) {
            (Some(before), Some(after)) => step_change(before, after),
            (None, Some(_)) => Change::Added,
            (Some(_), None) => Change::Removed,
            (None, None) => continue,
        };
        let candidate_required = after.is_some_and(|step| step.classification == NODE_REQUIRED);
        let candidate_blocks = candidate_required
            && match change {
                Change::Regressed => true,
                Change::Added => after.is_some_and(|step| step.status != STATUS_PASS),
                _ => false,
            };
        let candidate_advisory_regression = !candidate_required
            && match change {
                Change::Regressed => true,
                Change::Added => after.is_some_and(|step| step.status != STATUS_PASS),
                _ => false,
            };
        if candidate_blocks {
            summary.required_regressions += 1;
        }
        if candidate_advisory_regression {
            summary.advisory_regressions += 1;
        }
        if change == Change::Improved {
            if candidate_required {
                summary.required_improvements += 1;
            } else {
                summary.advisory_improvements += 1;
            }
        }
        match change {
            Change::Unchanged => summary.unchanged += 1,
            Change::Improved => summary.improved += 1,
            Change::Regressed => summary.regressed += 1,
            Change::Changed => summary.changed += 1,
            Change::Added => summary.added += 1,
            Change::Removed => summary.removed += 1,
        }
        nodes.push(NodeComparison {
            node_id: node_id.into(),
            baseline: before.map(node_side),
            candidate: after.map(node_side),
            change,
            differs_in: match (before, after) {
                (Some(before), Some(after)) => differing_digests(before, after),
                _ => Vec::new(),
            },
        });
    }

    let gate = GateComparison {
        baseline_verdict: baseline.decision.verdict.clone(),
        candidate_verdict: candidate.decision.verdict.clone(),
        change: verdict_change(&baseline.decision, &candidate.decision),
    };
    let outcome = if gate.change == Change::Regressed || summary.required_regressions > 0 {
        Outcome::Regressed
    } else if gate.change == Change::Improved || summary.required_improvements > 0 {
        Outcome::Improved
    } else {
        Outcome::Unchanged
    };
    Ok(EvaluationComparison {
        contract_version: COMPARISON_CONTRACT,
        namespace: baseline.namespace.clone(),
        baseline: compared_execution(baseline),
        candidate: compared_execution(candidate),
        gate,
        nodes,
        summary,
        outcome,
    })
}

fn by_node(steps: &[EvaluationStepReceipt]) -> BTreeMap<&str, &EvaluationStepReceipt> {
    steps
        .iter()
        .map(|step| (step.node_id.as_str(), step))
        .collect()
}

fn node_side(step: &EvaluationStepReceipt) -> NodeSide {
    NodeSide {
        classification: step.classification.clone(),
        status: step.status.clone(),
        reason_code: step.reason_code.clone(),
    }
}

fn compared_execution(execution: &FinishedExecution) -> ComparedExecution {
    ComparedExecution {
        manifest_digest: execution.manifest_digest.clone(),
        operation_id: execution.operation_id.clone(),
        verdict: execution.decision.verdict.clone(),
        reason_code: execution.decision.reason_code.clone(),
        decision_digest: execution.decision.decision_digest.clone(),
    }
}

fn step_change(before: &EvaluationStepReceipt, after: &EvaluationStepReceipt) -> Change {
    match (before.status == STATUS_PASS, after.status == STATUS_PASS) {
        (false, true) => Change::Improved,
        (true, false) => Change::Regressed,
        _ if before.status != after.status || before.reason_code != after.reason_code => {
            Change::Changed
        }
        _ => Change::Unchanged,
    }
}

fn verdict_change(before: &EvaluationGateDecision, after: &EvaluationGateDecision) -> Change {
    match (
        before.verdict == VERDICT_ALLOW,
        after.verdict == VERDICT_ALLOW,
    ) {
        (false, true) => Change::Improved,
        (true, false) => Change::Regressed,
        _ if before.verdict != after.verdict || before.reason_code != after.reason_code => {
            Change::Changed
        }
        _ => Change::Unchanged,
    }
}

fn differing_digests(
    before: &EvaluationStepReceipt,
    after: &EvaluationStepReceipt,
) -> Vec<&'static str> {
    let mut differs = Vec::new();
    if before.input_digest != after.input_digest {
        differs.push("input");
    }
    if before.parameters_digest != after.parameters_digest {
        differs.push("parameters");
    }
    if before.evaluator_definition_digest != after.evaluator_definition_digest {
        differs.push("evaluator_definition");
    }
    if before.implementation_digest != after.implementation_digest {
        differs.push("implementation");
    }
    if before.evidence_digests != after.evidence_digests {
        differs.push("evidence");
    }
    if before.dependency_result_digests != after.dependency_result_digests {
        differs.push("dependency_results");
    }
    if before.result_digest != after.result_digest {
        differs.push("result");
    }
    differs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_execution::{
        STATUS_ERROR, STATUS_FAIL, STATUS_SKIPPED, STATUS_UNAVAILABLE, STATUS_UNKNOWN,
        VERDICT_DENY, VERDICT_UNKNOWN,
    };
    use crate::chisei::evaluation_plan::NODE_ADVISORY;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn step(node_id: &str, classification: &str, status: &str) -> EvaluationStepReceipt {
        EvaluationStepReceipt {
            contract_version: "chisei.evaluation-step-receipt/v1".into(),
            manifest_digest: digest('a'),
            node_id: node_id.into(),
            classification: classification.into(),
            status: status.into(),
            reason_code: if status == STATUS_PASS {
                "predicate_satisfied".into()
            } else {
                "predicate_not_satisfied".into()
            },
            input_digest: digest('1'),
            parameters_digest: digest('2'),
            evaluator_definition_digest: digest('3'),
            implementation_digest: digest('4'),
            evidence_digests: vec![],
            dependency_result_digests: vec![],
            result_digest: digest('5'),
            stochastic_evidence: None,
            step_receipt_digest: digest('6'),
        }
    }

    fn execution(
        manifest: char,
        verdict: &str,
        steps: Vec<EvaluationStepReceipt>,
    ) -> FinishedExecution {
        let manifest_digest = digest(manifest);
        FinishedExecution {
            namespace: "acme".into(),
            operation_id: execution_operation_id(&manifest_digest),
            manifest_digest: manifest_digest.clone(),
            steps,
            decision: EvaluationGateDecision {
                contract_version: "chisei.evaluation-gate-decision/v1".into(),
                manifest_digest,
                reducer: "required_all_pass_advisory_observed/v1".into(),
                verdict: verdict.into(),
                reason_code: format!("gate_{verdict}"),
                step_receipt_digests: vec![],
                invariant_coverage: vec![],
                decision_digest: digest('7'),
            },
        }
    }

    fn change_of(comparison: &EvaluationComparison, node_id: &str) -> Change {
        comparison
            .nodes
            .iter()
            .find(|node| node.node_id == node_id)
            .unwrap_or_else(|| panic!("node {node_id} missing"))
            .change
    }

    #[test]
    fn identical_executions_are_unchanged() {
        let steps = vec![
            step("b", NODE_REQUIRED, STATUS_PASS),
            step("a", NODE_ADVISORY, STATUS_FAIL),
        ];
        let comparison = compare(
            &execution('a', VERDICT_ALLOW, steps.clone()),
            &execution('b', VERDICT_ALLOW, steps),
        )
        .unwrap();
        assert_eq!(comparison.outcome, Outcome::Unchanged);
        assert_eq!(comparison.gate.change, Change::Unchanged);
        assert_eq!(comparison.summary.unchanged, 2);
        assert_eq!(
            comparison
                .nodes
                .iter()
                .map(|node| node.node_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"],
            "nodes are ordered by identity"
        );
        assert!(
            comparison
                .nodes
                .iter()
                .all(|node| node.differs_in.is_empty())
        );
    }

    #[test]
    fn required_regression_regresses_the_outcome_and_names_differing_digests() {
        let baseline = execution(
            'a',
            VERDICT_ALLOW,
            vec![step("artifact-digest", NODE_REQUIRED, STATUS_PASS)],
        );
        let mut regressed = step("artifact-digest", NODE_REQUIRED, STATUS_FAIL);
        regressed.input_digest = digest('9');
        regressed.result_digest = digest('8');
        let candidate = execution('b', VERDICT_DENY, vec![regressed]);
        let comparison = compare(&baseline, &candidate).unwrap();
        assert_eq!(comparison.outcome, Outcome::Regressed);
        assert_eq!(comparison.gate.change, Change::Regressed);
        assert_eq!(comparison.summary.required_regressions, 1);
        let node = &comparison.nodes[0];
        assert_eq!(node.change, Change::Regressed);
        assert_eq!(node.differs_in, ["input", "result"]);
        assert_eq!(node.baseline.as_ref().unwrap().status, STATUS_PASS);
        assert_eq!(node.candidate.as_ref().unwrap().status, STATUS_FAIL);
    }

    #[test]
    fn advisory_regression_is_observed_but_never_decides_the_outcome() {
        let baseline = execution(
            'a',
            VERDICT_ALLOW,
            vec![
                step("gate", NODE_REQUIRED, STATUS_PASS),
                step("style", NODE_ADVISORY, STATUS_PASS),
            ],
        );
        let candidate = execution(
            'b',
            VERDICT_ALLOW,
            vec![
                step("gate", NODE_REQUIRED, STATUS_PASS),
                step("style", NODE_ADVISORY, STATUS_FAIL),
            ],
        );
        let comparison = compare(&baseline, &candidate).unwrap();
        assert_eq!(change_of(&comparison, "style"), Change::Regressed);
        assert_eq!(comparison.summary.advisory_regressions, 1);
        assert_eq!(comparison.summary.required_regressions, 0);
        assert_eq!(comparison.outcome, Outcome::Unchanged);
    }

    #[test]
    fn advisory_improvement_is_observed_but_never_decides_the_outcome() {
        let baseline = execution(
            'a',
            VERDICT_ALLOW,
            vec![
                step("gate", NODE_REQUIRED, STATUS_PASS),
                step("style", NODE_ADVISORY, STATUS_FAIL),
            ],
        );
        let candidate = execution(
            'b',
            VERDICT_ALLOW,
            vec![
                step("gate", NODE_REQUIRED, STATUS_PASS),
                step("style", NODE_ADVISORY, STATUS_PASS),
            ],
        );
        let comparison = compare(&baseline, &candidate).unwrap();
        assert_eq!(change_of(&comparison, "style"), Change::Improved);
        assert_eq!(comparison.summary.improved, 1);
        assert_eq!(comparison.summary.advisory_improvements, 1);
        assert_eq!(comparison.summary.required_improvements, 0);
        assert_eq!(comparison.outcome, Outcome::Unchanged);
    }

    #[test]
    fn improvement_needs_a_pass_that_was_not_one() {
        let baseline = execution(
            'a',
            VERDICT_DENY,
            vec![step("gate", NODE_REQUIRED, STATUS_FAIL)],
        );
        let candidate = execution(
            'b',
            VERDICT_ALLOW,
            vec![step("gate", NODE_REQUIRED, STATUS_PASS)],
        );
        let comparison = compare(&baseline, &candidate).unwrap();
        assert_eq!(comparison.outcome, Outcome::Improved);
        assert_eq!(comparison.gate.change, Change::Improved);
        assert_eq!(change_of(&comparison, "gate"), Change::Improved);
    }

    #[test]
    fn moving_between_inconclusive_states_is_changed_not_ranked() {
        for (before, after) in [
            (STATUS_FAIL, STATUS_UNKNOWN),
            (STATUS_UNAVAILABLE, STATUS_ERROR),
            (STATUS_SKIPPED, STATUS_FAIL),
        ] {
            let comparison = compare(
                &execution('a', VERDICT_DENY, vec![step("n", NODE_REQUIRED, before)]),
                &execution('b', VERDICT_UNKNOWN, vec![step("n", NODE_REQUIRED, after)]),
            )
            .unwrap();
            assert_eq!(
                change_of(&comparison, "n"),
                Change::Changed,
                "{before} -> {after}"
            );
            assert_eq!(comparison.gate.change, Change::Changed);
            assert_eq!(comparison.outcome, Outcome::Unchanged);
        }
    }

    #[test]
    fn a_reason_code_shift_within_one_status_is_changed() {
        let baseline = execution(
            'a',
            VERDICT_DENY,
            vec![step("n", NODE_REQUIRED, STATUS_FAIL)],
        );
        let mut shifted = step("n", NODE_REQUIRED, STATUS_FAIL);
        shifted.reason_code = "other_reason".into();
        let candidate = execution('b', VERDICT_DENY, vec![shifted]);
        let comparison = compare(&baseline, &candidate).unwrap();
        assert_eq!(change_of(&comparison, "n"), Change::Changed);
        assert_eq!(comparison.outcome, Outcome::Unchanged);
    }

    #[test]
    fn added_and_removed_nodes_are_reported_and_a_failing_required_addition_regresses() {
        let baseline = execution(
            'a',
            VERDICT_ALLOW,
            vec![
                step("kept", NODE_REQUIRED, STATUS_PASS),
                step("dropped", NODE_ADVISORY, STATUS_PASS),
            ],
        );
        let candidate = execution(
            'b',
            VERDICT_ALLOW,
            vec![
                step("kept", NODE_REQUIRED, STATUS_PASS),
                step("new-required", NODE_REQUIRED, STATUS_FAIL),
                step("new-advisory", NODE_ADVISORY, STATUS_FAIL),
            ],
        );
        let comparison = compare(&baseline, &candidate).unwrap();
        assert_eq!(change_of(&comparison, "dropped"), Change::Removed);
        assert_eq!(change_of(&comparison, "new-required"), Change::Added);
        assert_eq!(comparison.summary.removed, 1);
        assert_eq!(comparison.summary.added, 2);
        assert_eq!(comparison.summary.required_regressions, 1);
        assert_eq!(comparison.summary.advisory_regressions, 1);
        assert_eq!(comparison.outcome, Outcome::Regressed);
        assert!(
            comparison
                .nodes
                .iter()
                .filter(|node| matches!(node.change, Change::Added | Change::Removed))
                .all(|node| node.differs_in.is_empty())
        );
    }

    #[test]
    fn a_passing_addition_is_not_a_regression() {
        let baseline = execution(
            'a',
            VERDICT_ALLOW,
            vec![step("a", NODE_REQUIRED, STATUS_PASS)],
        );
        let candidate = execution(
            'b',
            VERDICT_ALLOW,
            vec![
                step("a", NODE_REQUIRED, STATUS_PASS),
                step("b", NODE_REQUIRED, STATUS_PASS),
            ],
        );
        let comparison = compare(&baseline, &candidate).unwrap();
        assert_eq!(comparison.summary.added, 1);
        assert_eq!(comparison.outcome, Outcome::Unchanged);
    }

    #[test]
    fn executions_from_different_namespaces_do_not_compare() {
        let baseline = execution('a', VERDICT_ALLOW, vec![]);
        let mut candidate = execution('b', VERDICT_ALLOW, vec![]);
        candidate.namespace = "other".into();
        assert_eq!(
            compare(&baseline, &candidate),
            Err(ComparisonError::Unbound)
        );
    }

    #[test]
    fn serialized_comparison_uses_closed_snake_case_vocabulary() {
        let comparison = compare(
            &execution(
                'a',
                VERDICT_ALLOW,
                vec![step("n", NODE_REQUIRED, STATUS_PASS)],
            ),
            &execution(
                'b',
                VERDICT_DENY,
                vec![step("n", NODE_REQUIRED, STATUS_FAIL)],
            ),
        )
        .unwrap();
        let value = serde_json::to_value(&comparison).unwrap();
        assert_eq!(value["contract_version"], COMPARISON_CONTRACT);
        assert_eq!(value["outcome"], "regressed");
        assert_eq!(value["gate"]["change"], "regressed");
        assert_eq!(value["nodes"][0]["change"], "regressed");
        assert_eq!(value["nodes"][0]["baseline"]["status"], "pass");
    }
}
