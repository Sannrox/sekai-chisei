//! Governed execution telemetry (ADR 0156): bounded aggregates over the
//! operation receipts of readable namespaces, grouped by one closed dimension.
//!
//! Improvement reads this instead of an external trace collector. It returns
//! counts, spend, tokens, model-call latency percentiles, outcome classes, and
//! verification pass counts. It never returns or groups by prompt, input,
//! output, or provider-response content; group keys come from identifier-like
//! receipt fields and anything else collapses into [`OTHER_KEY`]. The result
//! carries a digest over its canonical form, so a learning candidate can bind
//! it as evidence and a re-read of the same closed window reproduces it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::chisei::receipt::{OperationReceipt, OperationReceiptEvent, ReceiptEventKind};
use crate::db::runtime_db::RuntimeDb;
use crate::operation_statistics::{
    MAX_STATISTICS_RECEIPTS, MAX_STATISTICS_WINDOW_MS, classify_receipt, event_model,
    list_receipts_in_window,
};

pub const TELEMETRY_CONTRACT: &str = "chisei.execution-telemetry/v1";
/// The only record kind this version aggregates.
pub const RECORD_KIND_OPERATION_RECEIPT: &str = "operation_receipt";
pub const MAX_TELEMETRY_NAMESPACES: usize = 16;
/// Group key for a receipt that does not record the dimension at all.
pub const UNRECORDED_KEY: &str = "unrecorded";
/// Group key for a recorded value that is not a bounded identifier, so free
/// text never becomes a key.
pub const OTHER_KEY: &str = "other";
const MAX_KEY_BYTES: usize = 128;

/// The closed set of dimensions a read may group by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TelemetryDimension {
    /// The receipt's `operation_class`.
    TaskClass,
    /// The model of each model call; calls are attributed to their own model.
    Model,
    /// `prompt_variant` on route or model-call events.
    PromptVariant,
    /// `tool` on action events.
    Tool,
    /// `evaluator` on verification events.
    Evaluator,
    /// The receipt's outcome class (verified, failed, parked, ...).
    OutcomeClass,
}

impl TelemetryDimension {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim() {
            "task_class" => Self::TaskClass,
            "model" => Self::Model,
            "prompt_variant" => Self::PromptVariant,
            "tool" => Self::Tool,
            "evaluator" => Self::Evaluator,
            "outcome_class" => Self::OutcomeClass,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskClass => "task_class",
            Self::Model => "model",
            Self::PromptVariant => "prompt_variant",
            Self::Tool => "tool",
            Self::Evaluator => "evaluator",
            Self::OutcomeClass => "outcome_class",
        }
    }
}

/// Aggregates for one group key. A receipt that records several values of a
/// multi-valued dimension counts once in each of their groups.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TelemetryGroup {
    pub key: String,
    pub receipts: i64,
    pub model_calls: i64,
    pub priced_model_calls: i64,
    pub spend_usd_micros: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub latency_samples: i64,
    pub latency_p50_ms: i64,
    pub latency_p90_ms: i64,
    pub latency_p99_ms: i64,
    /// Receipts per outcome class, including the failure classes.
    pub outcomes: BTreeMap<String, i64>,
    pub verifications: i64,
    pub verifications_passed: i64,
}

/// A fact the window could not supply. Reported instead of counted as zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TelemetryGap {
    pub fact: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionTelemetry {
    pub contract_version: String,
    /// Readable namespaces the aggregates cover, sorted.
    pub namespaces: Vec<String>,
    /// Requested namespaces the caller may not read. They contribute nothing;
    /// not even their record counts are disclosed.
    pub withheld_namespaces: Vec<String>,
    /// Receipts in readable namespaces left out because they carry a marking
    /// the caller is not cleared for. Counted, never aggregated.
    pub withheld_receipts: i64,
    pub since_ms: i64,
    pub until_ms: i64,
    pub group_by: TelemetryDimension,
    pub record_kinds: Vec<String>,
    pub receipts: i64,
    /// Receipts that record no value for `group_by`.
    pub unrecorded_receipts: i64,
    pub groups: Vec<TelemetryGroup>,
    pub gaps: Vec<TelemetryGap>,
    /// `sha256:` over the canonical JSON of every other field.
    #[serde(skip)]
    pub digest: String,
}

/// Aggregates the window over `readable` namespaces. The caller has already
/// split the request into readable and `withheld` namespaces; `admit` decides
/// per receipt (marking clearance) and a rejected receipt only counts as
/// withheld. A window past [`MAX_STATISTICS_WINDOW_MS`] or one holding more
/// than [`MAX_STATISTICS_RECEIPTS`] receipts is refused, never truncated.
pub fn query_execution_telemetry(
    db: &RuntimeDb,
    readable: &[String],
    withheld: &[String],
    since_ms: i64,
    until_ms: i64,
    group_by: TelemetryDimension,
    admit: impl FnMut(&OperationReceipt) -> bool,
) -> Result<ExecutionTelemetry, TelemetryError> {
    if since_ms < 0 || until_ms <= since_ms {
        return Err(TelemetryError::Invalid(
            "until_ms must be after a non-negative since_ms".into(),
        ));
    }
    if until_ms - since_ms > MAX_STATISTICS_WINDOW_MS {
        return Err(TelemetryError::NarrowWindow(
            "the window exceeds 366 days".into(),
        ));
    }
    let namespaces: Vec<String> = readable
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let receipts =
        list_receipts_in_window(db, &namespaces, since_ms, until_ms).map_err(|error| {
            if error.contains("limit exceeded") {
                TelemetryError::NarrowWindow(format!(
                    "the window holds more than {MAX_STATISTICS_RECEIPTS} receipts"
                ))
            } else {
                TelemetryError::Store(error)
            }
        })?;
    let scanned = receipts.len();
    let receipts: Vec<OperationReceipt> = receipts.into_iter().filter(admit).collect();
    let withheld_receipts = (scanned - receipts.len()) as i64;
    let mut groups: BTreeMap<String, GroupAccumulator> = BTreeMap::new();
    let mut unrecorded_receipts = 0;
    let mut facts = FactPresence::default();
    for receipt in &receipts {
        let outcome = classify_receipt(receipt, until_ms).as_str();
        let calls = model_calls(receipt, since_ms, until_ms);
        let verifications = verifications(receipt, since_ms, until_ms);
        facts.observe(&calls, verifications.0);
        let keys = receipt_keys(receipt, group_by, &calls, outcome);
        if keys.is_empty() {
            unrecorded_receipts += 1;
        }
        let keys = if keys.is_empty() {
            BTreeSet::from([UNRECORDED_KEY.to_string()])
        } else {
            keys
        };
        for key in keys {
            let group = groups.entry(key.clone()).or_default();
            group.receipts += 1;
            *group.outcomes.entry(outcome.into()).or_default() += 1;
            group.verifications += verifications.0;
            group.verifications_passed += verifications.1;
            for call in &calls {
                // The model dimension attributes each call to its own model.
                if group_by != TelemetryDimension::Model || call.model_key == key {
                    group.add_call(call);
                }
            }
        }
    }
    let mut telemetry = ExecutionTelemetry {
        contract_version: TELEMETRY_CONTRACT.into(),
        namespaces,
        withheld_namespaces: withheld
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        withheld_receipts,
        since_ms,
        until_ms,
        group_by,
        record_kinds: vec![RECORD_KIND_OPERATION_RECEIPT.into()],
        receipts: receipts.len() as i64,
        unrecorded_receipts,
        groups: groups
            .into_iter()
            .map(|(key, group)| group.finish(key))
            .collect(),
        gaps: facts.gaps(receipts.len(), unrecorded_receipts, group_by),
        digest: String::new(),
    };
    telemetry.digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_json::to_vec(&telemetry).map_err(|e| TelemetryError::Store(e.to_string()))?
        )
    );
    Ok(telemetry)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryError {
    Invalid(String),
    /// Past the window or scan cap; the caller should ask for less.
    NarrowWindow(String),
    Store(String),
}

/// One in-window model call's numeric facts.
struct ModelCall {
    model_key: String,
    cost_usd_micros: Option<i64>,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    latency_ms: Option<i64>,
}

fn model_calls(receipt: &OperationReceipt, since_ms: i64, until_ms: i64) -> Vec<ModelCall> {
    let route_model = receipt
        .events
        .iter()
        .find(|event| event.kind == ReceiptEventKind::RouteSelected)
        .and_then(event_model);
    receipt
        .events
        .iter()
        .filter(|event| {
            event.kind == ReceiptEventKind::ModelCalled && in_window(event, since_ms, until_ms)
        })
        .map(|event| ModelCall {
            model_key: event_model(event)
                .or_else(|| route_model.clone())
                .map_or_else(|| UNRECORDED_KEY.into(), |model| bounded_key(&model)),
            cost_usd_micros: non_negative(event, "cost_usd_micros"),
            input_tokens: non_negative(event, "input_tokens"),
            output_tokens: non_negative(event, "output_tokens"),
            latency_ms: non_negative(event, "latency_ms"),
        })
        .collect()
}

/// In-window verifications and how many of them passed.
fn verifications(receipt: &OperationReceipt, since_ms: i64, until_ms: i64) -> (i64, i64) {
    receipt
        .events
        .iter()
        .filter(|event| {
            event.kind == ReceiptEventKind::VerificationRecorded
                && in_window(event, since_ms, until_ms)
        })
        .fold((0, 0), |(total, passed), event| {
            let status = event
                .attributes
                .get("status")
                .or_else(|| event.attributes.get("verdict"))
                .map(String::as_str)
                .unwrap_or_default();
            let pass = matches!(status, "pass" | "passed" | "verified" | "succeeded")
                || event.attributes.get("passed").map(String::as_str) == Some("true");
            (total + 1, passed + i64::from(pass))
        })
}

/// The receipt's values for `dimension`; empty when it records none.
fn receipt_keys(
    receipt: &OperationReceipt,
    dimension: TelemetryDimension,
    calls: &[ModelCall],
    outcome: &str,
) -> BTreeSet<String> {
    let attribute = |kinds: &[ReceiptEventKind], name: &str| -> BTreeSet<String> {
        receipt
            .events
            .iter()
            .filter(|event| kinds.contains(&event.kind))
            .filter_map(|event| event.attributes.get(name))
            .filter(|value| !value.trim().is_empty())
            .map(|value| bounded_key(value))
            .collect()
    };
    match dimension {
        TelemetryDimension::TaskClass if receipt.operation_class.trim().is_empty() => {
            BTreeSet::new()
        }
        TelemetryDimension::TaskClass => BTreeSet::from([bounded_key(&receipt.operation_class)]),
        TelemetryDimension::Model => calls.iter().map(|call| call.model_key.clone()).collect(),
        TelemetryDimension::PromptVariant => attribute(
            &[
                ReceiptEventKind::RouteSelected,
                ReceiptEventKind::ModelCalled,
            ],
            "prompt_variant",
        ),
        TelemetryDimension::Tool => attribute(&[ReceiptEventKind::ActionPerformed], "tool"),
        TelemetryDimension::Evaluator => {
            attribute(&[ReceiptEventKind::VerificationRecorded], "evaluator")
        }
        TelemetryDimension::OutcomeClass => BTreeSet::from([outcome.to_string()]),
    }
}

/// An identifier-like value as a key, or [`OTHER_KEY`] for anything that could
/// carry free text.
fn bounded_key(value: &str) -> String {
    let value = value.trim();
    let identifier = !value.is_empty()
        && value.len() <= MAX_KEY_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-+".contains(&byte));
    if identifier {
        value.into()
    } else {
        OTHER_KEY.into()
    }
}

fn in_window(event: &OperationReceiptEvent, since_ms: i64, until_ms: i64) -> bool {
    event.timestamp_ms >= since_ms && event.timestamp_ms < until_ms
}

fn non_negative(event: &OperationReceiptEvent, name: &str) -> Option<i64> {
    event
        .attributes
        .get(name)
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
}

#[derive(Default)]
struct GroupAccumulator {
    receipts: i64,
    model_calls: i64,
    priced_model_calls: i64,
    spend_usd_micros: i64,
    input_tokens: i64,
    output_tokens: i64,
    latencies: Vec<i64>,
    outcomes: BTreeMap<String, i64>,
    verifications: i64,
    verifications_passed: i64,
}

impl GroupAccumulator {
    fn add_call(&mut self, call: &ModelCall) {
        self.model_calls += 1;
        if let Some(cost) = call.cost_usd_micros {
            self.priced_model_calls += 1;
            self.spend_usd_micros = self.spend_usd_micros.saturating_add(cost);
        }
        self.input_tokens = self
            .input_tokens
            .saturating_add(call.input_tokens.unwrap_or(0));
        self.output_tokens = self
            .output_tokens
            .saturating_add(call.output_tokens.unwrap_or(0));
        self.latencies.extend(call.latency_ms);
    }

    fn finish(mut self, key: String) -> TelemetryGroup {
        self.latencies.sort_unstable();
        let percentile = |p: usize| nearest_rank(&self.latencies, p);
        TelemetryGroup {
            key,
            receipts: self.receipts,
            model_calls: self.model_calls,
            priced_model_calls: self.priced_model_calls,
            spend_usd_micros: self.spend_usd_micros,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            latency_samples: self.latencies.len() as i64,
            latency_p50_ms: percentile(50),
            latency_p90_ms: percentile(90),
            latency_p99_ms: percentile(99),
            outcomes: self.outcomes,
            verifications: self.verifications,
            verifications_passed: self.verifications_passed,
        }
    }
}

/// Nearest-rank percentile of sorted samples; 0 when there are none, which
/// `latency_samples = 0` makes explicit.
fn nearest_rank(sorted: &[i64], percent: usize) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (percent * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

/// Which facts the window held at all, to report the rest as gaps.
#[derive(Default)]
struct FactPresence {
    model_calls: bool,
    latency: bool,
    token_usage: bool,
    verifications: bool,
}

impl FactPresence {
    fn observe(&mut self, calls: &[ModelCall], verifications: i64) {
        self.model_calls |= !calls.is_empty();
        self.latency |= calls.iter().any(|call| call.latency_ms.is_some());
        self.token_usage |= calls
            .iter()
            .any(|call| call.input_tokens.is_some() || call.output_tokens.is_some());
        self.verifications |= verifications > 0;
    }

    fn gaps(
        &self,
        receipts: usize,
        unrecorded: i64,
        group_by: TelemetryDimension,
    ) -> Vec<TelemetryGap> {
        let gap = |fact: &str, reason: &str| TelemetryGap {
            fact: fact.into(),
            reason: reason.into(),
        };
        if receipts == 0 {
            return vec![gap(RECORD_KIND_OPERATION_RECEIPT, "no_records_in_window")];
        }
        let mut gaps = Vec::new();
        if !self.model_calls {
            gaps.push(gap("model_calls", "no_records_in_window"));
        } else {
            if !self.latency {
                gaps.push(gap("latency", "not_recorded"));
            }
            if !self.token_usage {
                gaps.push(gap("token_usage", "not_recorded"));
            }
        }
        if !self.verifications {
            gaps.push(gap("verifications", "no_records_in_window"));
        }
        if unrecorded == receipts as i64 {
            gaps.push(gap(group_by.as_str(), "not_recorded"));
        }
        gaps
    }
}

#[cfg(test)]
#[path = "execution_telemetry_tests.rs"]
mod tests;
