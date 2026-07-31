//! Provider-neutral comparison of claim-only and epistemically framed Kioku context.
//!
//! The comparison is intentionally report-only. It consumes immutable generic
//! [`crate::chisei::eval::Run`] records and payload-free, digest-bound case
//! authority projections; it never changes the context-expansion gate or
//! enables a rollout. Case evidence is a closed document so raw claims,
//! evidence payloads, and provider output cannot be smuggled into an
//! evaluation run.

use crate::chisei::eval::{EvalStore, GateDecision, Run};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const EPISTEMIC_EVALUATION_CONTRACT: &str = "chisei.epistemic-context-evaluation/v1";
pub const EPISTEMIC_CASE_EVIDENCE_CONTRACT: &str = "chisei.epistemic-case-evidence/v1";
pub const CLAIM_ONLY_CONTEXT_VARIANT: &str = "claim_only";
pub const EPISTEMIC_FRAMED_CONTEXT_VARIANT: &str = "epistemic_framed";

pub const FIXTURE_SUPPORTING_ONLY: &str = "supporting_only";
pub const FIXTURE_CONTESTED: &str = "contested";
pub const FIXTURE_INSUFFICIENT: &str = "insufficient";
pub const FIXTURE_STALE: &str = "stale";
pub const FIXTURE_IRRELEVANT: &str = "irrelevant";
pub const FIXTURE_HIGH_CONFIDENCE_WRONG: &str = "high_confidence_wrong";

const REQUIRED_FIXTURE_KINDS: [&str; 6] = [
    FIXTURE_SUPPORTING_ONLY,
    FIXTURE_CONTESTED,
    FIXTURE_INSUFFICIENT,
    FIXTURE_STALE,
    FIXTURE_IRRELEVANT,
    FIXTURE_HIGH_CONFIDENCE_WRONG,
];
const MAX_EPISTEMIC_CASES: usize = 100_000;

/// Closed, normalised evidence for one evaluation case.
///
/// This is stored in the generic `CaseResult.result` field as JSON. The
/// `deny_unknown_fields` boundary is deliberate: a run may contain only
/// digests, labels, bounded counters, and token/latency measurements—not raw
/// claim text, evidence content, prompts, or provider responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpistemicCaseEvidence {
    pub contract_version: String,
    pub context_variant: String,
    pub fixture_kind: String,
    pub eligible_memory_set_digest: String,
    pub classification_ceiling: String,
    pub source_content_digest: String,
    pub token_capacity: u32,
    pub task_success: bool,
    pub unsupported_claim_count: u32,
    pub claim_count: u32,
    pub contradiction_present: bool,
    pub contradiction_handled: bool,
    pub expected_confidence_micros: u32,
    pub observed_confidence_micros: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub receipt_digest: String,
    pub outcome_digest: String,
}

/// Canonical, payload-free receipt projection supplied by the evaluation
/// authority. The projection contains only normalized measurements; callers
/// derive it from the canonical operation receipt before invoking the
/// comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemicReceiptEvidence {
    pub operation_id: String,
    pub task_success: bool,
    pub observed_confidence_micros: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub latency_ms: u64,
}

/// Canonical, payload-free Kioku outcome projection supplied by the evaluation
/// authority. It is derived from the receipt-bound Kioku outcome record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemicOutcomeEvidence {
    pub memory_id: String,
    pub memory_version: u32,
    pub operation_id: String,
    pub unsupported_claim_count: u32,
    pub claim_count: u32,
    pub contradiction_present: bool,
    pub contradiction_handled: bool,
}

/// Authoritative case evidence. The generic eval run stores only the digest
/// references and normalized values; this object is supplied by the receipt /
/// Kioku outcome authority so the comparison can verify those digests and
/// derive every measured value from canonical inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemicCaseAuthority {
    pub fixture_kind: String,
    pub eligible_memory_set_digest: String,
    pub classification_ceiling: String,
    pub source_content_digest: String,
    pub token_capacity: u32,
    pub expected_confidence_micros: u32,
    pub receipt: EpistemicReceiptEvidence,
    pub outcome: EpistemicOutcomeEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemicMetricSummary {
    pub case_count: u32,
    pub claim_count: u64,
    pub task_success_count: u64,
    pub unsupported_claim_count: u64,
    pub contradiction_handled_count: u64,
    pub calibration_total_micros: u64,
    pub latency_total_ms: u64,
    pub task_success_bps: u32,
    pub unsupported_claim_bps: u32,
    pub contradiction_cases: u32,
    pub contradiction_handling_bps: u32,
    pub calibration_error_micros: u32,
    pub mean_latency_ms: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
}

/// Explicit tolerances for a comparison. The defaults are strict: a candidate
/// must not regress any required metric. Callers can widen a bound for a
/// documented evaluation plan, but the bound is part of the returned report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemicRegressionPolicy {
    pub max_task_success_drop_bps: u32,
    pub max_unsupported_claim_increase_bps: u32,
    pub max_contradiction_handling_drop_bps: u32,
    pub max_calibration_error_increase_micros: u32,
    pub max_latency_increase_bps: u32,
    pub max_token_increase_bps: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpistemicRegressionGate {
    pub verdict: String,
    pub allowed: bool,
    pub reason: String,
    pub regressions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpistemicComparisonReport {
    pub contract_version: String,
    pub suite_id: String,
    pub baseline_run_id: String,
    pub candidate_run_id: String,
    pub baseline_config_ref: String,
    pub candidate_config_ref: String,
    pub fixture_digest: String,
    pub baseline_metrics: EpistemicMetricSummary,
    pub candidate_metrics: EpistemicMetricSummary,
    pub baseline_gate: GateDecision,
    pub regression_policy: EpistemicRegressionPolicy,
    pub regression_gate: EpistemicRegressionGate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FixtureBinding<'a> {
    case_id: &'a str,
    fixture_kind: &'a str,
    eligible_memory_set_digest: &'a str,
    classification_ceiling: &'a str,
    source_content_digest: &'a str,
    token_capacity: u32,
    expected_confidence_micros: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedCase {
    case_id: String,
    evidence: EpistemicCaseEvidence,
    receipt: EpistemicReceiptEvidence,
    outcome: EpistemicOutcomeEvidence,
}

/// Compare two already persisted runs using the existing generic pass-rate
/// gate plus the required epistemic metrics.
pub fn compare_epistemic_runs(
    store: &EvalStore,
    baseline_id: &str,
    candidate_id: &str,
    baseline_authority: &BTreeMap<String, EpistemicCaseAuthority>,
    candidate_authority: &BTreeMap<String, EpistemicCaseAuthority>,
    policy: EpistemicRegressionPolicy,
) -> Result<EpistemicComparisonReport, String> {
    let baseline = store
        .get_run(baseline_id)
        .ok_or_else(|| format!("baseline eval run not found: {baseline_id}"))?;
    let candidate = store
        .get_run(candidate_id)
        .ok_or_else(|| format!("candidate eval run not found: {candidate_id}"))?;
    let baseline_gate = store
        .compare_runs(baseline_id, candidate_id)
        .ok_or_else(|| "baseline/candidate eval runs are unavailable".to_string())?;
    compare_epistemic_run_pair(
        &baseline,
        &candidate,
        baseline_authority,
        candidate_authority,
        baseline_gate,
        policy,
    )
}

/// Compare a pair of immutable run values. This is useful for deterministic
/// fixture tests and for callers that have already loaded runs from a shared
/// `EvalStore`.
pub(crate) fn compare_epistemic_run_pair(
    baseline: &Run,
    candidate: &Run,
    baseline_authority: &BTreeMap<String, EpistemicCaseAuthority>,
    candidate_authority: &BTreeMap<String, EpistemicCaseAuthority>,
    baseline_gate: GateDecision,
    policy: EpistemicRegressionPolicy,
) -> Result<EpistemicComparisonReport, String> {
    validate_policy(policy)?;
    if baseline.id.trim().is_empty() || candidate.id.trim().is_empty() {
        return Err("baseline and candidate run ids are required".into());
    }
    if baseline.id == candidate.id {
        return Err("baseline and candidate run ids must differ".into());
    }
    if baseline.suite_id.is_empty() || baseline.suite_id != candidate.suite_id {
        return Err("baseline and candidate must use the same evaluation suite".into());
    }
    if baseline.config_ref.trim().is_empty() || candidate.config_ref.trim().is_empty() {
        return Err("baseline and candidate configuration identities are required".into());
    }
    if baseline.config_ref == candidate.config_ref {
        return Err("baseline and candidate configuration identities must differ".into());
    }

    let baseline_cases =
        validate_run_cases(baseline, CLAIM_ONLY_CONTEXT_VARIANT, baseline_authority)?;
    let candidate_cases = validate_run_cases(
        candidate,
        EPISTEMIC_FRAMED_CONTEXT_VARIANT,
        candidate_authority,
    )?;
    let baseline_by_id = index_cases(baseline_cases)?;
    let candidate_by_id = index_cases(candidate_cases)?;
    if baseline_by_id.keys().collect::<Vec<_>>() != candidate_by_id.keys().collect::<Vec<_>>() {
        return Err("baseline and candidate case sets must match exactly".into());
    }
    let fixture_binding_digest = fixture_digest(&baseline_by_id)?;
    if fixture_digest(&candidate_by_id)? != fixture_binding_digest {
        return Err("baseline and candidate fixture bindings differ".into());
    }
    let baseline_metrics = summarize(&baseline_by_id)?;
    let candidate_metrics = summarize(&candidate_by_id)?;
    let regression_gate = regression_gate(
        &baseline_metrics,
        &candidate_metrics,
        &baseline_gate,
        policy,
    );

    Ok(EpistemicComparisonReport {
        contract_version: EPISTEMIC_EVALUATION_CONTRACT.into(),
        suite_id: baseline.suite_id.clone(),
        baseline_run_id: baseline.id.clone(),
        candidate_run_id: candidate.id.clone(),
        baseline_config_ref: baseline.config_ref.clone(),
        candidate_config_ref: candidate.config_ref.clone(),
        fixture_digest: fixture_binding_digest,
        baseline_metrics,
        candidate_metrics,
        baseline_gate,
        regression_policy: policy,
        regression_gate,
    })
}

fn validate_policy(policy: EpistemicRegressionPolicy) -> Result<(), String> {
    if policy.max_task_success_drop_bps > 10_000
        || policy.max_unsupported_claim_increase_bps > 10_000
        || policy.max_contradiction_handling_drop_bps > 10_000
        || policy.max_latency_increase_bps > 100_000
        || policy.max_token_increase_bps > 100_000
        || policy.max_calibration_error_increase_micros > 1_000_000
    {
        return Err("epistemic regression policy bound is out of range".into());
    }
    Ok(())
}

fn validate_run_cases(
    run: &Run,
    expected_variant: &str,
    authority: &BTreeMap<String, EpistemicCaseAuthority>,
) -> Result<Vec<ValidatedCase>, String> {
    if run.results.is_empty() {
        return Err(format!("eval run {} has no cases", run.id));
    }
    if run.results.len() > MAX_EPISTEMIC_CASES {
        return Err(format!("eval run {} contains too many cases", run.id));
    }
    let mut cases = Vec::with_capacity(run.results.len());
    for result in &run.results {
        if result.case_id.trim().is_empty() {
            return Err(format!("eval run {} contains a case without an id", run.id));
        }
        if result.status != "done" {
            return Err(format!(
                "case {} is not in the terminal done state",
                result.case_id
            ));
        }
        if !result.reason.trim().is_empty() {
            return Err(format!(
                "case {} contains a non-normalized reason; raw provider output is not allowed",
                result.case_id
            ));
        }
        if result.elapsed < 0 {
            return Err(format!("case {} has negative latency", result.case_id));
        }
        let value: Value = serde_json::from_str(&result.result).map_err(|error| {
            format!(
                "case {} has invalid normalized evidence: {error}",
                result.case_id
            )
        })?;
        let evidence: EpistemicCaseEvidence = serde_json::from_value(value).map_err(|error| {
            format!(
                "case {} has invalid normalized evidence: {error}",
                result.case_id
            )
        })?;
        validate_case_evidence(&result.case_id, &evidence, expected_variant)?;
        let canonical = authority
            .get(&result.case_id)
            .ok_or_else(|| format!("case {} is missing canonical authority", result.case_id))?;
        validate_case_authority(&result.case_id, &evidence, result, canonical)?;
        if canonical.receipt.task_success != result.passed {
            return Err(format!(
                "case {} passed flag does not match task_success evidence",
                result.case_id
            ));
        }
        cases.push(ValidatedCase {
            case_id: result.case_id.clone(),
            evidence,
            receipt: canonical.receipt.clone(),
            outcome: canonical.outcome.clone(),
        });
    }
    if authority.len() != cases.len()
        || cases
            .iter()
            .any(|case| !authority.contains_key(&case.case_id))
    {
        return Err(format!(
            "eval run {} canonical authority does not match its case set",
            run.id
        ));
    }
    let kinds = cases
        .iter()
        .map(|case| case.evidence.fixture_kind.as_str())
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_FIXTURE_KINDS {
        if !kinds.contains(required) {
            return Err(format!(
                "eval run {} is missing fixture kind {required}",
                run.id
            ));
        }
    }
    Ok(cases)
}

fn validate_case_evidence(
    case_id: &str,
    evidence: &EpistemicCaseEvidence,
    expected_variant: &str,
) -> Result<(), String> {
    if evidence.contract_version != EPISTEMIC_CASE_EVIDENCE_CONTRACT {
        return Err(format!(
            "case {case_id} uses an unsupported evidence contract"
        ));
    }
    if evidence.context_variant != expected_variant {
        return Err(format!(
            "case {case_id} uses context variant {}, expected {expected_variant}",
            evidence.context_variant
        ));
    }
    if !REQUIRED_FIXTURE_KINDS.contains(&evidence.fixture_kind.as_str()) {
        return Err(format!("case {case_id} has an unknown fixture kind"));
    }
    if !matches!(
        evidence.classification_ceiling.as_str(),
        "public" | "internal" | "confidential" | "restricted"
    ) {
        return Err(format!(
            "case {case_id} has an invalid classification ceiling"
        ));
    }
    for (name, digest) in [
        (
            "eligible_memory_set_digest",
            evidence.eligible_memory_set_digest.as_str(),
        ),
        (
            "source_content_digest",
            evidence.source_content_digest.as_str(),
        ),
        ("receipt_digest", evidence.receipt_digest.as_str()),
        ("outcome_digest", evidence.outcome_digest.as_str()),
    ] {
        if !is_digest(digest) {
            return Err(format!("case {case_id} has an invalid {name}"));
        }
    }
    if evidence.token_capacity == 0 {
        return Err(format!("case {case_id} must declare token capacity"));
    }
    if evidence.unsupported_claim_count > evidence.claim_count {
        return Err(format!(
            "case {case_id} has invalid unsupported-claim counts"
        ));
    }
    if evidence.task_success && evidence.claim_count == 0 {
        return Err(format!(
            "case {case_id} reports success without any normalized claims"
        ));
    }
    if evidence.expected_confidence_micros > 1_000_000
        || evidence.observed_confidence_micros > 1_000_000
    {
        return Err(format!("case {case_id} has invalid confidence values"));
    }
    if evidence.contradiction_handled && !evidence.contradiction_present {
        return Err(format!(
            "case {case_id} reports contradiction handling without a contradiction"
        ));
    }
    let expected_contradiction = evidence.fixture_kind == FIXTURE_CONTESTED;
    if evidence.contradiction_present != expected_contradiction {
        return Err(format!(
            "case {case_id} has contradiction coverage inconsistent with its fixture kind"
        ));
    }
    let used_tokens = evidence
        .input_tokens
        .checked_add(evidence.output_tokens)
        .ok_or_else(|| format!("case {case_id} token usage overflowed"))?;
    if used_tokens > evidence.token_capacity {
        return Err(format!(
            "case {case_id} exceeds its declared token capacity"
        ));
    }
    Ok(())
}

/// Compute the digest that must be recorded for a canonical receipt projection.
pub fn canonical_epistemic_receipt_digest(
    receipt: &EpistemicReceiptEvidence,
) -> Result<String, String> {
    digest_json(receipt)
}

/// Compute the digest that must be recorded for a canonical Kioku outcome
/// projection.
pub fn canonical_epistemic_outcome_digest(
    outcome: &EpistemicOutcomeEvidence,
) -> Result<String, String> {
    digest_json(outcome)
}

fn validate_case_authority(
    case_id: &str,
    evidence: &EpistemicCaseEvidence,
    result: &crate::chisei::eval::CaseResult,
    authority: &EpistemicCaseAuthority,
) -> Result<(), String> {
    if authority.receipt.operation_id.trim().is_empty()
        || authority.outcome.operation_id.trim().is_empty()
        || authority.outcome.memory_id.trim().is_empty()
        || authority.outcome.memory_version == 0
    {
        return Err(format!(
            "case {case_id} canonical authority is missing an operation or memory identity"
        ));
    }
    if authority.receipt.operation_id != authority.outcome.operation_id {
        return Err(format!(
            "case {case_id} receipt and outcome operation identities differ"
        ));
    }
    if authority.receipt.observed_confidence_micros > 1_000_000
        || authority
            .receipt
            .input_tokens
            .saturating_add(authority.receipt.output_tokens)
            > authority.token_capacity
    {
        return Err(format!(
            "case {case_id} canonical receipt exceeds the fixture bounds"
        ));
    }
    if authority.outcome.unsupported_claim_count > authority.outcome.claim_count {
        return Err(format!(
            "case {case_id} canonical outcome has invalid claim counts"
        ));
    }
    if authority.outcome.contradiction_handled != evidence.contradiction_handled
        || authority.outcome.contradiction_present != evidence.contradiction_present
    {
        return Err(format!(
            "case {case_id} canonical outcome contradiction labels do not match the run"
        ));
    }
    if authority.fixture_kind != evidence.fixture_kind
        || authority.eligible_memory_set_digest != evidence.eligible_memory_set_digest
        || authority.classification_ceiling != evidence.classification_ceiling
        || authority.source_content_digest != evidence.source_content_digest
        || authority.token_capacity != evidence.token_capacity
        || authority.expected_confidence_micros != evidence.expected_confidence_micros
    {
        return Err(format!(
            "case {case_id} canonical fixture binding does not match the run"
        ));
    }
    if authority.receipt.task_success != evidence.task_success
        || authority.receipt.observed_confidence_micros != evidence.observed_confidence_micros
        || authority.receipt.input_tokens != evidence.input_tokens
        || authority.receipt.output_tokens != evidence.output_tokens
        || authority.outcome.unsupported_claim_count != evidence.unsupported_claim_count
        || authority.outcome.claim_count != evidence.claim_count
        || result.elapsed as u64 != authority.receipt.latency_ms
    {
        return Err(format!(
            "case {case_id} normalized metrics do not match canonical authority"
        ));
    }
    let receipt_digest = canonical_epistemic_receipt_digest(&authority.receipt)?;
    if evidence.receipt_digest != receipt_digest {
        return Err(format!(
            "case {case_id} receipt digest does not match canonical authority"
        ));
    }
    let outcome_digest = canonical_epistemic_outcome_digest(&authority.outcome)?;
    if evidence.outcome_digest != outcome_digest {
        return Err(format!(
            "case {case_id} outcome digest does not match canonical authority"
        ));
    }
    Ok(())
}

fn index_cases(cases: Vec<ValidatedCase>) -> Result<BTreeMap<String, ValidatedCase>, String> {
    let mut indexed = BTreeMap::new();
    for case in cases {
        if indexed.insert(case.case_id.clone(), case).is_some() {
            return Err("evaluation run contains duplicate case ids".into());
        }
    }
    Ok(indexed)
}

fn fixture_digest(cases: &BTreeMap<String, ValidatedCase>) -> Result<String, String> {
    let bindings = cases
        .iter()
        .map(|(case_id, case)| FixtureBinding {
            case_id,
            fixture_kind: &case.evidence.fixture_kind,
            eligible_memory_set_digest: &case.evidence.eligible_memory_set_digest,
            classification_ceiling: &case.evidence.classification_ceiling,
            source_content_digest: &case.evidence.source_content_digest,
            token_capacity: case.evidence.token_capacity,
            expected_confidence_micros: case.evidence.expected_confidence_micros,
        })
        .collect::<Vec<_>>();
    digest_json(&bindings)
}

fn summarize(cases: &BTreeMap<String, ValidatedCase>) -> Result<EpistemicMetricSummary, String> {
    let case_count = cases.len() as u32;
    let task_successes = cases
        .values()
        .filter(|case| case.receipt.task_success)
        .count() as u64;
    let unsupported_claims = cases.values().try_fold(0_u64, |total, case| {
        total
            .checked_add(u64::from(case.outcome.unsupported_claim_count))
            .ok_or_else(|| "unsupported-claim aggregate overflowed".to_string())
    })?;
    let claim_count = cases.values().try_fold(0_u64, |total, case| {
        total
            .checked_add(u64::from(case.outcome.claim_count))
            .ok_or_else(|| "claim-count aggregate overflowed".to_string())
    })?;
    let contested = cases
        .values()
        .filter(|case| case.outcome.contradiction_present)
        .collect::<Vec<_>>();
    let handled = contested
        .iter()
        .filter(|case| case.outcome.contradiction_handled)
        .count() as u64;
    let calibration_total = cases.values().try_fold(0_u64, |total, case| {
        total
            .checked_add(u64::from(
                case.evidence
                    .expected_confidence_micros
                    .abs_diff(case.receipt.observed_confidence_micros),
            ))
            .ok_or_else(|| "calibration aggregate overflowed".to_string())
    })?;
    let total_input_tokens = cases.values().try_fold(0_u64, |total, case| {
        total
            .checked_add(u64::from(case.receipt.input_tokens))
            .ok_or_else(|| "input-token aggregate overflowed".to_string())
    })?;
    let total_output_tokens = cases.values().try_fold(0_u64, |total, case| {
        total
            .checked_add(u64::from(case.receipt.output_tokens))
            .ok_or_else(|| "output-token aggregate overflowed".to_string())
    })?;
    let total_tokens = total_input_tokens
        .checked_add(total_output_tokens)
        .ok_or_else(|| "token aggregate overflowed".to_string())?;
    let latency_total = cases.values().try_fold(0_u64, |total, case| {
        total
            .checked_add(case.receipt.latency_ms)
            .ok_or_else(|| "latency aggregate overflowed".to_string())
    })?;
    Ok(EpistemicMetricSummary {
        case_count,
        claim_count,
        task_success_count: task_successes,
        unsupported_claim_count: unsupported_claims,
        contradiction_handled_count: handled,
        calibration_total_micros: calibration_total,
        latency_total_ms: latency_total,
        task_success_bps: rate_bps(task_successes, u64::from(case_count)),
        unsupported_claim_bps: rate_bps(unsupported_claims, claim_count),
        contradiction_cases: contested.len() as u32,
        contradiction_handling_bps: rate_bps(handled, contested.len() as u64),
        calibration_error_micros: mean_u64(calibration_total, u64::from(case_count)) as u32,
        mean_latency_ms: mean_u64(latency_total, u64::from(case_count)),
        total_input_tokens,
        total_output_tokens,
        total_tokens,
    })
}

fn regression_gate(
    baseline: &EpistemicMetricSummary,
    candidate: &EpistemicMetricSummary,
    baseline_gate: &GateDecision,
    policy: EpistemicRegressionPolicy,
) -> EpistemicRegressionGate {
    let mut regressions = Vec::new();
    if baseline_gate.verdict != "pass" {
        regressions.push("generic baseline pass-rate gate did not pass".into());
    }
    if fraction_drop_exceeds(
        candidate.task_success_count,
        u64::from(candidate.case_count),
        baseline.task_success_count,
        u64::from(baseline.case_count),
        policy.max_task_success_drop_bps,
    ) {
        regressions.push("task_success_regressed".into());
    }
    if baseline.claim_count == 0 || candidate.claim_count == 0 {
        regressions.push("unsupported_claim_rate_unavailable".into());
    } else if fraction_increase_exceeds(
        candidate.unsupported_claim_count,
        candidate.claim_count,
        baseline.unsupported_claim_count,
        baseline.claim_count,
        policy.max_unsupported_claim_increase_bps,
        10_000,
    ) {
        regressions.push("unsupported_claim_rate_regressed".into());
    }
    if candidate.contradiction_cases < baseline.contradiction_cases
        || fraction_drop_exceeds(
            candidate.contradiction_handled_count,
            u64::from(candidate.contradiction_cases),
            baseline.contradiction_handled_count,
            u64::from(baseline.contradiction_cases),
            policy.max_contradiction_handling_drop_bps,
        )
    {
        regressions.push("contradiction_handling_regressed".into());
    }
    if fraction_increase_exceeds(
        candidate.calibration_total_micros,
        u64::from(candidate.case_count),
        baseline.calibration_total_micros,
        u64::from(baseline.case_count),
        policy.max_calibration_error_increase_micros,
        1_000_000,
    ) {
        regressions.push("calibration_regressed".into());
    }
    if ratio_increase_exceeds(
        candidate.latency_total_ms,
        u64::from(candidate.case_count),
        baseline.latency_total_ms,
        u64::from(baseline.case_count),
        policy.max_latency_increase_bps,
    ) {
        regressions.push("latency_regressed".into());
    }
    if ratio_increase_exceeds(
        candidate.total_tokens,
        1,
        baseline.total_tokens,
        1,
        policy.max_token_increase_bps,
    ) {
        regressions.push("token_usage_regressed".into());
    }
    let allowed = regressions.is_empty();
    EpistemicRegressionGate {
        verdict: if allowed { "pass" } else { "fail" }.into(),
        allowed,
        reason: if allowed {
            "candidate meets the generic and epistemic regression gates".into()
        } else {
            regressions.join(", ")
        },
        regressions,
    }
}

fn fraction_drop_exceeds(
    candidate_numerator: u64,
    candidate_denominator: u64,
    baseline_numerator: u64,
    baseline_denominator: u64,
    max_drop_bps: u32,
) -> bool {
    if candidate_denominator == 0 || baseline_denominator == 0 {
        return true;
    }
    let left = u128::from(candidate_numerator) * 10_000 * u128::from(baseline_denominator)
        + u128::from(max_drop_bps)
            * u128::from(candidate_denominator)
            * u128::from(baseline_denominator);
    let right = u128::from(baseline_numerator) * u128::from(candidate_denominator) * 10_000;
    left < right
}

fn fraction_increase_exceeds(
    candidate_numerator: u64,
    candidate_denominator: u64,
    baseline_numerator: u64,
    baseline_denominator: u64,
    max_increase: u32,
    tolerance_denominator: u32,
) -> bool {
    if candidate_denominator == 0 || baseline_denominator == 0 {
        return true;
    }
    let left = u128::from(candidate_numerator)
        * u128::from(tolerance_denominator)
        * u128::from(baseline_denominator);
    let right = u128::from(baseline_numerator)
        * u128::from(candidate_denominator)
        * u128::from(tolerance_denominator)
        + u128::from(max_increase)
            * u128::from(candidate_denominator)
            * u128::from(baseline_denominator);
    left > right
}

fn ratio_increase_exceeds(
    candidate_numerator: u64,
    candidate_denominator: u64,
    baseline_numerator: u64,
    baseline_denominator: u64,
    max_increase_bps: u32,
) -> bool {
    if candidate_denominator == 0 || baseline_denominator == 0 {
        return true;
    }
    let left = u128::from(candidate_numerator) * u128::from(baseline_denominator) * 10_000;
    let right = u128::from(baseline_numerator)
        * u128::from(candidate_denominator)
        * u128::from(10_000_u32.saturating_add(max_increase_bps));
    left > right
}

fn rate_bps(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    ((u128::from(numerator) * 10_000 + u128::from(denominator / 2)) / u128::from(denominator))
        .min(10_000) as u32
}

fn mean_u64(total: u64, count: u64) -> u64 {
    if count == 0 {
        0
    } else {
        (u128::from(total) / u128::from(count)) as u64
    }
}

fn is_digest(value: &str) -> bool {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(format!("sha256:{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::eval::{CaseResult, Run};
    use serde_json::json;

    fn digest(seed: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }

    fn evidence(
        kind: &str,
        variant: &str,
        success: bool,
        unsupported: u32,
        contradiction_handled: bool,
        input_tokens: u32,
    ) -> EpistemicCaseEvidence {
        EpistemicCaseEvidence {
            contract_version: EPISTEMIC_CASE_EVIDENCE_CONTRACT.into(),
            context_variant: variant.into(),
            fixture_kind: kind.into(),
            eligible_memory_set_digest: digest(&format!("memory-set:{kind}")),
            classification_ceiling: "internal".into(),
            source_content_digest: digest(&format!("source:{kind}")),
            token_capacity: 128,
            task_success: success,
            unsupported_claim_count: unsupported,
            claim_count: if kind == FIXTURE_INSUFFICIENT { 0 } else { 1 },
            contradiction_present: kind == FIXTURE_CONTESTED,
            contradiction_handled,
            expected_confidence_micros: 800_000,
            observed_confidence_micros: if success { 800_000 } else { 500_000 },
            input_tokens,
            output_tokens: 8,
            receipt_digest: String::new(),
            outcome_digest: String::new(),
        }
    }

    fn arm(
        id: &str,
        config_ref: &str,
        variant: &str,
        degraded: bool,
    ) -> (Run, BTreeMap<String, EpistemicCaseAuthority>) {
        let cases = [
            (FIXTURE_SUPPORTING_ONLY, true, 0, false),
            (
                FIXTURE_CONTESTED,
                !degraded,
                0,
                variant == EPISTEMIC_FRAMED_CONTEXT_VARIANT && !degraded,
            ),
            (FIXTURE_INSUFFICIENT, false, 0, false),
            (FIXTURE_STALE, false, 0, false),
            (FIXTURE_IRRELEVANT, true, 0, false),
            (
                FIXTURE_HIGH_CONFIDENCE_WRONG,
                false,
                if degraded { 1 } else { 0 },
                false,
            ),
        ];
        let mut authorities = BTreeMap::new();
        let results = cases
            .into_iter()
            .map(|(kind, success, unsupported, handled)| {
                let mut case_evidence = evidence(
                    kind,
                    variant,
                    success,
                    unsupported,
                    handled,
                    if variant == EPISTEMIC_FRAMED_CONTEXT_VARIANT {
                        44
                    } else {
                        40
                    },
                );
                let receipt = EpistemicReceiptEvidence {
                    operation_id: format!("operation-{variant}-{kind}"),
                    task_success: case_evidence.task_success,
                    observed_confidence_micros: case_evidence.observed_confidence_micros,
                    input_tokens: case_evidence.input_tokens,
                    output_tokens: case_evidence.output_tokens,
                    latency_ms: 10,
                };
                let outcome = EpistemicOutcomeEvidence {
                    memory_id: format!("memory-{kind}"),
                    memory_version: 1,
                    operation_id: receipt.operation_id.clone(),
                    unsupported_claim_count: case_evidence.unsupported_claim_count,
                    claim_count: case_evidence.claim_count,
                    contradiction_present: case_evidence.contradiction_present,
                    contradiction_handled: case_evidence.contradiction_handled,
                };
                case_evidence.receipt_digest =
                    canonical_epistemic_receipt_digest(&receipt).unwrap();
                case_evidence.outcome_digest =
                    canonical_epistemic_outcome_digest(&outcome).unwrap();
                let case_id = format!("case-{kind}");
                authorities.insert(
                    case_id.clone(),
                    EpistemicCaseAuthority {
                        fixture_kind: case_evidence.fixture_kind.clone(),
                        eligible_memory_set_digest: case_evidence
                            .eligible_memory_set_digest
                            .clone(),
                        classification_ceiling: case_evidence.classification_ceiling.clone(),
                        source_content_digest: case_evidence.source_content_digest.clone(),
                        token_capacity: case_evidence.token_capacity,
                        expected_confidence_micros: case_evidence.expected_confidence_micros,
                        receipt,
                        outcome,
                    },
                );
                CaseResult {
                    case_id,
                    passed: success,
                    status: "done".into(),
                    result: serde_json::to_string(&case_evidence).unwrap(),
                    score: if success { 100 } else { 0 },
                    reason: String::new(),
                    elapsed: 10,
                }
            })
            .collect();
        (
            Run {
                id: id.into(),
                suite_id: "epistemic-context-fixtures-v1".into(),
                config_ref: config_ref.into(),
                results,
                timestamp: 1,
            },
            authorities,
        )
    }

    #[test]
    fn compares_matched_claim_only_and_epistemic_runs() {
        let store = EvalStore::new();
        let (baseline, baseline_authority) = arm(
            "baseline",
            "kioku-context:claim-only:v1",
            CLAIM_ONLY_CONTEXT_VARIANT,
            false,
        );
        let (candidate, candidate_authority) = arm(
            "candidate",
            "kioku-context:epistemic:v1",
            EPISTEMIC_FRAMED_CONTEXT_VARIANT,
            false,
        );
        store.create_run(baseline);
        store.create_run(candidate);
        let report = compare_epistemic_runs(
            &store,
            "baseline",
            "candidate",
            &baseline_authority,
            &candidate_authority,
            EpistemicRegressionPolicy {
                max_token_increase_bps: 1_000,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(report.baseline_config_ref, "kioku-context:claim-only:v1");
        assert_eq!(report.candidate_config_ref, "kioku-context:epistemic:v1");
        assert_eq!(report.baseline_metrics.case_count, 6);
        assert_eq!(report.baseline_metrics.contradiction_cases, 1);
        assert_eq!(report.baseline_metrics.contradiction_handling_bps, 0);
        assert_eq!(report.candidate_metrics.contradiction_handling_bps, 10_000);
        assert!(report.regression_gate.allowed);
        assert_eq!(report.fixture_digest.len(), 71);

        let (mut arm_specific_candidate, mut arm_specific_authority) = arm(
            "candidate-arm-specific",
            "kioku-context:epistemic:v1",
            EPISTEMIC_FRAMED_CONTEXT_VARIANT,
            false,
        );
        let mut value: serde_json::Value =
            serde_json::from_str(&arm_specific_candidate.results[0].result).unwrap();
        value["claim_count"] = json!(2);
        let case_id = arm_specific_candidate.results[0].case_id.clone();
        let authority = arm_specific_authority.get_mut(&case_id).unwrap();
        authority.outcome.claim_count = 2;
        authority.receipt.operation_id = "operation-arm-specific".into();
        authority.outcome.operation_id = authority.receipt.operation_id.clone();
        value["receipt_digest"] =
            json!(canonical_epistemic_receipt_digest(&authority.receipt).unwrap());
        value["outcome_digest"] =
            json!(canonical_epistemic_outcome_digest(&authority.outcome).unwrap());
        arm_specific_candidate.results[0].result = serde_json::to_string(&value).unwrap();
        let arm_specific_report = compare_epistemic_run_pair(
            &store.get_run("baseline").unwrap(),
            &arm_specific_candidate,
            &baseline_authority,
            &arm_specific_authority,
            report.baseline_gate.clone(),
            EpistemicRegressionPolicy {
                max_token_increase_bps: 1_000,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(arm_specific_report.fixture_digest, report.fixture_digest);
        assert_eq!(
            arm_specific_report.candidate_metrics.unsupported_claim_bps,
            0
        );
    }

    #[test]
    fn rejects_raw_or_mismatched_case_evidence() {
        let (mut baseline, baseline_authority) =
            arm("baseline", "claim-only", CLAIM_ONLY_CONTEXT_VARIANT, false);
        let (mut candidate, candidate_authority) = arm(
            "candidate",
            "epistemic",
            EPISTEMIC_FRAMED_CONTEXT_VARIANT,
            false,
        );
        let mut value: Value = serde_json::from_str(&candidate.results[0].result).unwrap();
        value["raw_claim"] = json!("do not persist this");
        candidate.results[0].result = serde_json::to_string(&value).unwrap();
        let error = compare_epistemic_run_pair(
            &baseline,
            &candidate,
            &baseline_authority,
            &candidate_authority,
            GateDecision {
                verdict: "pass".into(),
                reason: String::new(),
                baseline_score: 1.0,
                candidate_score: 1.0,
            },
            Default::default(),
        )
        .unwrap_err();
        assert!(error.contains("invalid normalized evidence"));

        baseline.results[0].result = baseline.results[0]
            .result
            .replace("eligible_memory_set_digest", "source_content_digest");
        let (_, incomplete_candidate_authority) = arm(
            "candidate-2",
            "epistemic",
            EPISTEMIC_FRAMED_CONTEXT_VARIANT,
            false,
        );
        let (candidate_2, _) = arm(
            "candidate-2",
            "epistemic",
            EPISTEMIC_FRAMED_CONTEXT_VARIANT,
            false,
        );
        let error = compare_epistemic_run_pair(
            &baseline,
            &candidate_2,
            &baseline_authority,
            &incomplete_candidate_authority,
            GateDecision {
                verdict: "pass".into(),
                reason: String::new(),
                baseline_score: 1.0,
                candidate_score: 1.0,
            },
            Default::default(),
        )
        .unwrap_err();
        assert!(error.contains("invalid normalized evidence"));

        let (mut incomplete, incomplete_authority) = arm(
            "incomplete",
            "claim-only",
            CLAIM_ONLY_CONTEXT_VARIANT,
            false,
        );
        incomplete.results[0].status = "running".into();
        let (candidate_3, candidate_3_authority) = arm(
            "candidate-3",
            "epistemic",
            EPISTEMIC_FRAMED_CONTEXT_VARIANT,
            false,
        );
        let error = compare_epistemic_run_pair(
            &incomplete,
            &candidate_3,
            &incomplete_authority,
            &candidate_3_authority,
            GateDecision {
                verdict: "pass".into(),
                reason: String::new(),
                baseline_score: 1.0,
                candidate_score: 1.0,
            },
            Default::default(),
        )
        .unwrap_err();
        assert!(error.contains("terminal done state"));
    }

    #[test]
    fn regression_gate_fails_closed_for_candidate_regressions() {
        let store = EvalStore::new();
        let (baseline, baseline_authority) =
            arm("baseline", "claim-only", CLAIM_ONLY_CONTEXT_VARIANT, false);
        let (candidate, candidate_authority) = arm(
            "candidate",
            "epistemic",
            EPISTEMIC_FRAMED_CONTEXT_VARIANT,
            true,
        );
        store.create_run(baseline);
        store.create_run(candidate);
        let report = compare_epistemic_runs(
            &store,
            "baseline",
            "candidate",
            &baseline_authority,
            &candidate_authority,
            Default::default(),
        )
        .unwrap();
        assert!(!report.regression_gate.allowed);
        assert!(
            report
                .regression_gate
                .regressions
                .iter()
                .any(|reason| reason == "task_success_regressed")
        );
        assert!(
            report
                .regression_gate
                .regressions
                .iter()
                .any(|reason| reason == "unsupported_claim_rate_regressed")
        );
    }
}
