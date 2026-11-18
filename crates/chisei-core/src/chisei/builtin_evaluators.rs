//! Compiled, parameterized deterministic evaluators for common output checks.
//!
//! Each built-in has one exact implementation digest, a closed parameter
//! schema (the evaluation-plan subset), and a semantic parameter check that
//! plan publication runs before execution can ever see the parameters. Every
//! built-in reads one value from each bound evidence item's content at the
//! JSON Pointer `path` and passes only when every item passes. No evidence is
//! `unknown`; an absent or wrongly typed value is `fail`.

use crate::chisei::evaluation_execution::{
    DeterministicEvaluator, DeterministicEvaluatorInput, DeterministicEvaluatorOutput,
    DeterministicEvaluatorRegistry, EVALUATOR_RESULT_CONTRACT, STATUS_FAIL, STATUS_PASS,
    STATUS_UNKNOWN, canonicalize_value,
};
use chrono::{DateTime, NaiveDate, Utc};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

// Each digest is SHA-256 of `chisei.builtin-evaluator/<kind>.v1`; a changed
// implementation ships under a new kind version and digest beside the old one.
pub const EXACT_MATCH_IMPLEMENTATION_DIGEST: &str =
    "sha256:0c63c8a1dac4e3a7db0022dcb10aef2154812ecd804fde881d609533dc057bd4";
pub const REGEX_MATCH_IMPLEMENTATION_DIGEST: &str =
    "sha256:027d48a71422eba2f48077a1d8d137aac946ef5a67d8a72c48459f469c35902f";
pub const NUMERIC_RANGE_IMPLEMENTATION_DIGEST: &str =
    "sha256:c3138ddbe9bda3dd3aad8e6cf970de103bc5dc868a4ee5d7d4278effa2458a16";
pub const DATE_RANGE_IMPLEMENTATION_DIGEST: &str =
    "sha256:b53319ef47f40ea77672a92d18fb38e5311489a4154675ee8639a91e42123429";
pub const EDIT_DISTANCE_IMPLEMENTATION_DIGEST: &str =
    "sha256:65760e10a0f3b36d1bc718467a4330cd6d4592ca6139a9cf7627e94a924393e0";
pub const TOKEN_OVERLAP_IMPLEMENTATION_DIGEST: &str =
    "sha256:4277adf08bf9649c62d4e166f19c07c574bd28ae373654729a6ff9599881c1ed";
pub const SIZE_BOUNDS_IMPLEMENTATION_DIGEST: &str =
    "sha256:671f12059f6d74eaff3430fe635fe5d537a4deb41e10b07584c5d9b61472265f";

/// Compiled-program cap for a namespace-supplied pattern. The regex engine
/// matches in time linear in the input, so this bounds the per-byte cost.
const REGEX_SIZE_LIMIT: usize = 256 * 1024;
const REGEX_DFA_SIZE_LIMIT: usize = 1024 * 1024;
const REGEX_NEST_LIMIT: u32 = 32;
/// Longest value, in characters, that edit distance compares. Expected text is
/// capped at 4096 characters by the schema, so one comparison stays bounded.
const MAX_EDIT_DISTANCE_VALUE_CHARS: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    ExactMatch,
    RegexMatch,
    NumericRange,
    DateRange,
    EditDistance,
    TokenOverlap,
    SizeBounds,
}

const KINDS: [Kind; 7] = [
    Kind::ExactMatch,
    Kind::RegexMatch,
    Kind::NumericRange,
    Kind::DateRange,
    Kind::EditDistance,
    Kind::TokenOverlap,
    Kind::SizeBounds,
];

impl Kind {
    fn from_digest(implementation_digest: &str) -> Option<Self> {
        KINDS
            .into_iter()
            .find(|kind| kind.digest() == implementation_digest)
    }

    fn digest(self) -> &'static str {
        match self {
            Self::ExactMatch => EXACT_MATCH_IMPLEMENTATION_DIGEST,
            Self::RegexMatch => REGEX_MATCH_IMPLEMENTATION_DIGEST,
            Self::NumericRange => NUMERIC_RANGE_IMPLEMENTATION_DIGEST,
            Self::DateRange => DATE_RANGE_IMPLEMENTATION_DIGEST,
            Self::EditDistance => EDIT_DISTANCE_IMPLEMENTATION_DIGEST,
            Self::TokenOverlap => TOKEN_OVERLAP_IMPLEMENTATION_DIGEST,
            Self::SizeBounds => SIZE_BOUNDS_IMPLEMENTATION_DIGEST,
        }
    }

    /// Metrics label; the version label is always `v1`.
    fn metrics_label(self) -> &'static str {
        match self {
            Self::ExactMatch => "exact_match",
            Self::RegexMatch => "regex_match",
            Self::NumericRange => "numeric_range",
            Self::DateRange => "date_range",
            Self::EditDistance => "edit_distance",
            Self::TokenOverlap => "token_overlap",
            Self::SizeBounds => "size_bounds",
        }
    }

    /// The parameter schema a definition naming this digest must declare.
    fn parameter_schema(self) -> &'static str {
        match self {
            Self::ExactMatch => {
                r#"{"type":"object","additionalProperties":false,"required":["path","expected"],"properties":{"path":{"type":"string","maxLength":512},"expected":{"type":"string","maxLength":4096},"ignore_case":{"type":"boolean"},"normalize_whitespace":{"type":"boolean"}}}"#
            }
            Self::RegexMatch => {
                r#"{"type":"object","additionalProperties":false,"required":["path","pattern"],"properties":{"path":{"type":"string","maxLength":512},"pattern":{"type":"string","minLength":1,"maxLength":1024},"ignore_case":{"type":"boolean"}}}"#
            }
            Self::NumericRange => {
                r#"{"type":"object","additionalProperties":false,"required":["path"],"properties":{"path":{"type":"string","maxLength":512},"minimum":{"type":"number"},"maximum":{"type":"number"}}}"#
            }
            Self::DateRange => {
                r#"{"type":"object","additionalProperties":false,"required":["path"],"properties":{"path":{"type":"string","maxLength":512},"not_before":{"type":"string","maxLength":64},"not_after":{"type":"string","maxLength":64}}}"#
            }
            Self::EditDistance => {
                r#"{"type":"object","additionalProperties":false,"required":["path","expected","max_normalized_distance"],"properties":{"path":{"type":"string","maxLength":512},"expected":{"type":"string","maxLength":4096},"max_normalized_distance":{"type":"number","minimum":0,"maximum":1},"ignore_case":{"type":"boolean"},"normalize_whitespace":{"type":"boolean"}}}"#
            }
            Self::TokenOverlap => {
                r#"{"type":"object","additionalProperties":false,"required":["path","reference","n","min_recall"],"properties":{"path":{"type":"string","maxLength":512},"reference":{"type":"string","minLength":1,"maxLength":16384},"n":{"type":"integer","minimum":1,"maximum":4},"min_recall":{"type":"number","minimum":0,"maximum":1},"ignore_case":{"type":"boolean"}}}"#
            }
            Self::SizeBounds => {
                r#"{"type":"object","additionalProperties":false,"required":["path"],"properties":{"path":{"type":"string","maxLength":512},"min_items":{"type":"integer","minimum":0,"maximum":1000000},"max_items":{"type":"integer","minimum":0,"maximum":1000000},"distinct":{"type":"boolean"}}}"#
            }
        }
    }
}

/// Registers every built-in in `registry` under its exact digest.
pub fn register_builtin_evaluators(
    registry: &DeterministicEvaluatorRegistry,
) -> Result<(), String> {
    for kind in KINDS {
        registry.register_with_metrics(
            kind.digest(),
            kind.metrics_label(),
            "v1",
            Arc::new(BuiltinEvaluator { kind }),
        )?;
    }
    Ok(())
}

/// The parameter schema JSON a definition must declare when it names a
/// built-in implementation digest, or `None` for any other digest.
pub fn builtin_parameter_schema(implementation_digest: &str) -> Option<&'static str> {
    Kind::from_digest(implementation_digest).map(Kind::parameter_schema)
}

/// Plan-time semantic check of a node's parameters for a built-in digest
/// (pattern compiles, bounds are ordered, dates parse, ...). Other digests are
/// accepted unchanged; their schema check is the caller's.
pub fn validate_builtin_parameters(
    implementation_digest: &str,
    parameters_json: &str,
) -> Result<(), String> {
    let Some(kind) = Kind::from_digest(implementation_digest) else {
        return Ok(());
    };
    let parameters: Value = serde_json::from_str(parameters_json)
        .map_err(|error| format!("parameters_json must be JSON: {error}"))?;
    Check::parse(kind, &parameters).map(|_| ())
}

#[derive(Debug)]
struct BuiltinEvaluator {
    kind: Kind,
}

impl DeterministicEvaluator for BuiltinEvaluator {
    fn evaluate(
        &self,
        input: &DeterministicEvaluatorInput,
    ) -> Result<DeterministicEvaluatorOutput, String> {
        let check = Check::parse(self.kind, &input.parameters)?;
        let total = input.evidence.len();
        let mut passed = 0_usize;
        let mut first_failure = None;
        for item in &input.evidence {
            match check.apply(&item.content)? {
                Ok(()) => passed += 1,
                Err(reason) => {
                    first_failure.get_or_insert(reason);
                }
            }
        }
        let (status, reason_code) = match (total, first_failure) {
            (0, _) => (STATUS_UNKNOWN, "evidence_missing"),
            (_, Some(reason)) => (STATUS_FAIL, reason),
            (_, None) => (STATUS_PASS, "all_items_passed"),
        };
        Ok(DeterministicEvaluatorOutput {
            contract_version: EVALUATOR_RESULT_CONTRACT.into(),
            status: status.into(),
            reason_code: reason_code.into(),
            result: serde_json::json!({"items": total, "passed": passed}),
        })
    }
}

/// One item's verdict: `Ok` passes, `Err` carries the failing reason code.
type ItemVerdict = Result<(), &'static str>;

/// Parsed, semantically valid parameters for one built-in.
enum Check {
    ExactMatch {
        path: String,
        expected: String,
        text: TextNormalization,
    },
    RegexMatch {
        path: String,
        pattern: Regex,
    },
    NumericRange {
        path: String,
        minimum: Option<f64>,
        maximum: Option<f64>,
    },
    DateRange {
        path: String,
        not_before: Option<DateTime<Utc>>,
        not_after: Option<DateTime<Utc>>,
    },
    EditDistance {
        path: String,
        expected: Vec<char>,
        max_normalized_distance: f64,
        text: TextNormalization,
    },
    TokenOverlap {
        path: String,
        reference: BTreeMap<Vec<String>, usize>,
        reference_total: usize,
        n: usize,
        min_recall: f64,
        ignore_case: bool,
    },
    SizeBounds {
        path: String,
        min_items: Option<usize>,
        max_items: Option<usize>,
        distinct: bool,
    },
}

#[derive(Clone, Copy)]
struct TextNormalization {
    ignore_case: bool,
    normalize_whitespace: bool,
}

impl TextNormalization {
    /// Locale-independent: Unicode lowercase and collapsed Unicode whitespace.
    fn apply(self, text: &str) -> String {
        let text = if self.normalize_whitespace {
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        } else {
            text.to_string()
        };
        if self.ignore_case {
            text.to_lowercase()
        } else {
            text
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactMatchParameters {
    path: String,
    expected: String,
    #[serde(default)]
    ignore_case: bool,
    #[serde(default)]
    normalize_whitespace: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegexMatchParameters {
    path: String,
    pattern: String,
    #[serde(default)]
    ignore_case: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NumericRangeParameters {
    path: String,
    minimum: Option<f64>,
    maximum: Option<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DateRangeParameters {
    path: String,
    not_before: Option<String>,
    not_after: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditDistanceParameters {
    path: String,
    expected: String,
    max_normalized_distance: f64,
    #[serde(default)]
    ignore_case: bool,
    #[serde(default)]
    normalize_whitespace: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenOverlapParameters {
    path: String,
    reference: String,
    n: usize,
    min_recall: f64,
    #[serde(default)]
    ignore_case: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SizeBoundsParameters {
    path: String,
    min_items: Option<usize>,
    max_items: Option<usize>,
    #[serde(default)]
    distinct: bool,
}

fn parameters<T: DeserializeOwned>(kind: Kind, parameters: &Value) -> Result<T, String> {
    T::deserialize(parameters)
        .map_err(|error| format!("{} parameters are invalid: {error}", kind.metrics_label()))
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.starts_with('/') {
        Ok(())
    } else {
        Err("path must be empty or a JSON Pointer starting with '/'".into())
    }
}

fn unit_interval(name: &str, value: f64) -> Result<(), String> {
    if (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(format!("{name} must be between 0 and 1"))
    }
}

fn ordered<T: PartialOrd>(minimum: Option<&T>, maximum: Option<&T>) -> Result<(), String> {
    match (minimum, maximum) {
        (None, None) => Err("at least one bound is required".into()),
        (Some(minimum), Some(maximum)) if minimum > maximum => {
            Err("lower bound must not exceed upper bound".into())
        }
        _ => Ok(()),
    }
}

/// Parses an RFC 3339 date-time, or a calendar date as midnight UTC.
fn parse_instant(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .map(|instant| instant.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDate::parse_from_str(text, "%Y-%m-%d")
                .ok()
                .and_then(|date| date.and_hms_opt(0, 0, 0))
                .map(|instant| instant.and_utc())
        })
}

fn tokens(text: &str, ignore_case: bool) -> Vec<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| {
            if ignore_case {
                token.to_lowercase()
            } else {
                token.to_string()
            }
        })
        .collect()
}

fn ngram_counts(tokens: &[String], n: usize) -> BTreeMap<Vec<String>, usize> {
    let mut counts = BTreeMap::new();
    for window in tokens.windows(n) {
        *counts.entry(window.to_vec()).or_insert(0) += 1;
    }
    counts
}

/// Levenshtein distance over Unicode scalar values, two rows of memory.
fn edit_distance(left: &[char], right: &[char]) -> usize {
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (i, left_char) in left.iter().enumerate() {
        current[0] = i + 1;
        for (j, right_char) in right.iter().enumerate() {
            let substitution = previous[j] + usize::from(left_char != right_char);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

impl Check {
    fn parse(kind: Kind, raw: &Value) -> Result<Self, String> {
        let check = match kind {
            Kind::ExactMatch => {
                let p: ExactMatchParameters = parameters(kind, raw)?;
                let text = TextNormalization {
                    ignore_case: p.ignore_case,
                    normalize_whitespace: p.normalize_whitespace,
                };
                Self::ExactMatch {
                    expected: text.apply(&p.expected),
                    path: p.path,
                    text,
                }
            }
            Kind::RegexMatch => {
                let p: RegexMatchParameters = parameters(kind, raw)?;
                let pattern = RegexBuilder::new(&p.pattern)
                    .case_insensitive(p.ignore_case)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                    .nest_limit(REGEX_NEST_LIMIT)
                    .build()
                    .map_err(|error| {
                        format!("pattern is not an admitted regular expression: {error}")
                    })?;
                Self::RegexMatch {
                    path: p.path,
                    pattern,
                }
            }
            Kind::NumericRange => {
                let p: NumericRangeParameters = parameters(kind, raw)?;
                ordered(p.minimum.as_ref(), p.maximum.as_ref())?;
                Self::NumericRange {
                    path: p.path,
                    minimum: p.minimum,
                    maximum: p.maximum,
                }
            }
            Kind::DateRange => {
                let p: DateRangeParameters = parameters(kind, raw)?;
                let bound = |name: &str, text: Option<&String>| {
                    text.map(|text| {
                        parse_instant(text).ok_or_else(|| {
                            format!("{name} must be an RFC 3339 date-time or YYYY-MM-DD date")
                        })
                    })
                    .transpose()
                };
                let not_before = bound("not_before", p.not_before.as_ref())?;
                let not_after = bound("not_after", p.not_after.as_ref())?;
                ordered(not_before.as_ref(), not_after.as_ref())?;
                Self::DateRange {
                    path: p.path,
                    not_before,
                    not_after,
                }
            }
            Kind::EditDistance => {
                let p: EditDistanceParameters = parameters(kind, raw)?;
                unit_interval("max_normalized_distance", p.max_normalized_distance)?;
                let text = TextNormalization {
                    ignore_case: p.ignore_case,
                    normalize_whitespace: p.normalize_whitespace,
                };
                Self::EditDistance {
                    expected: text.apply(&p.expected).chars().collect(),
                    path: p.path,
                    max_normalized_distance: p.max_normalized_distance,
                    text,
                }
            }
            Kind::TokenOverlap => {
                let p: TokenOverlapParameters = parameters(kind, raw)?;
                unit_interval("min_recall", p.min_recall)?;
                if !(1..=4).contains(&p.n) {
                    return Err("n must be between 1 and 4".into());
                }
                let reference = ngram_counts(&tokens(&p.reference, p.ignore_case), p.n);
                let reference_total = reference.values().sum();
                if reference_total == 0 {
                    return Err("reference must contain at least n tokens".into());
                }
                Self::TokenOverlap {
                    path: p.path,
                    reference,
                    reference_total,
                    n: p.n,
                    min_recall: p.min_recall,
                    ignore_case: p.ignore_case,
                }
            }
            Kind::SizeBounds => {
                let p: SizeBoundsParameters = parameters(kind, raw)?;
                ordered(p.min_items.as_ref(), p.max_items.as_ref())?;
                Self::SizeBounds {
                    path: p.path,
                    min_items: p.min_items,
                    max_items: p.max_items,
                    distinct: p.distinct,
                }
            }
        };
        validate_path(check.path())?;
        Ok(check)
    }

    fn path(&self) -> &str {
        match self {
            Self::ExactMatch { path, .. }
            | Self::RegexMatch { path, .. }
            | Self::NumericRange { path, .. }
            | Self::DateRange { path, .. }
            | Self::EditDistance { path, .. }
            | Self::TokenOverlap { path, .. }
            | Self::SizeBounds { path, .. } => path,
        }
    }

    /// Checks one evidence item. The outer error is an evaluator error (a
    /// value too large to compare); the inner result is the item verdict.
    fn apply(&self, content: &Value) -> Result<ItemVerdict, String> {
        let Some(value) = content.pointer(self.path()) else {
            return Ok(Err("value_missing"));
        };
        let within = |ok: bool, reason| if ok { Ok(()) } else { Err(reason) };
        let verdict = match self {
            Self::ExactMatch { expected, text, .. } => match value.as_str() {
                Some(actual) => within(text.apply(actual) == *expected, "value_mismatch"),
                None => Err("value_type_mismatch"),
            },
            Self::RegexMatch { pattern, .. } => match value.as_str() {
                Some(actual) => within(pattern.is_match(actual), "pattern_not_matched"),
                None => Err("value_type_mismatch"),
            },
            Self::NumericRange {
                minimum, maximum, ..
            } => match value.as_f64() {
                Some(actual) => within(
                    minimum.is_none_or(|minimum| actual >= minimum)
                        && maximum.is_none_or(|maximum| actual <= maximum),
                    "value_out_of_range",
                ),
                None => Err("value_type_mismatch"),
            },
            Self::DateRange {
                not_before,
                not_after,
                ..
            } => match value.as_str().and_then(parse_instant) {
                Some(actual) => within(
                    not_before.is_none_or(|bound| actual >= bound)
                        && not_after.is_none_or(|bound| actual <= bound),
                    "value_out_of_range",
                ),
                None => Err("value_type_mismatch"),
            },
            Self::EditDistance {
                expected,
                max_normalized_distance,
                text,
                ..
            } => match value.as_str() {
                Some(actual) => {
                    let actual: Vec<char> = text.apply(actual).chars().collect();
                    let longest = actual.len().max(expected.len());
                    // Compare the ratio, not `max * longest`: an exact integer
                    // quotient rounds to the same double as an equal decimal
                    // parameter, so inclusive bounds hold at the boundary.
                    let within_distance = |distance: usize| {
                        longest == 0 || distance as f64 / longest as f64 <= *max_normalized_distance
                    };
                    // Distance is at least the length difference; decide that
                    // case without the quadratic comparison.
                    if !within_distance(actual.len().abs_diff(expected.len())) {
                        Err("distance_exceeded")
                    } else if actual.len() > MAX_EDIT_DISTANCE_VALUE_CHARS {
                        return Err(format!(
                            "edit_distance value exceeds {MAX_EDIT_DISTANCE_VALUE_CHARS} characters"
                        ));
                    } else {
                        within(
                            within_distance(edit_distance(&actual, expected)),
                            "distance_exceeded",
                        )
                    }
                }
                None => Err("value_type_mismatch"),
            },
            Self::TokenOverlap {
                reference,
                reference_total,
                n,
                min_recall,
                ignore_case,
                ..
            } => match value.as_str() {
                Some(actual) => {
                    let candidate = ngram_counts(&tokens(actual, *ignore_case), *n);
                    let overlap: usize = reference
                        .iter()
                        .map(|(ngram, count)| {
                            (*count).min(candidate.get(ngram).copied().unwrap_or(0))
                        })
                        .sum();
                    within(
                        overlap as f64 / *reference_total as f64 >= *min_recall,
                        "overlap_below_minimum",
                    )
                }
                None => Err("value_type_mismatch"),
            },
            Self::SizeBounds {
                min_items,
                max_items,
                distinct,
                ..
            } => match value.as_array() {
                Some(items) => {
                    let size = if *distinct {
                        items
                            .iter()
                            .map(|item| {
                                let mut item = item.clone();
                                canonicalize_value(&mut item);
                                item.to_string()
                            })
                            .collect::<BTreeSet<_>>()
                            .len()
                    } else {
                        items.len()
                    };
                    within(
                        min_items.is_none_or(|minimum| size >= minimum)
                            && max_items.is_none_or(|maximum| size <= maximum),
                        "size_out_of_bounds",
                    )
                }
                None => Err("value_type_mismatch"),
            },
        };
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_execution::EvaluationEvidenceInput;
    use crate::chisei::evaluation_plan::validate_parameters;
    use serde_json::json;

    fn run(kind: Kind, parameters: Value, values: &[Value]) -> DeterministicEvaluatorOutput {
        let input = DeterministicEvaluatorInput {
            contract_version: String::new(),
            manifest_digest: String::new(),
            node_id: "node".into(),
            subject_profile: String::new(),
            subject_identity: String::new(),
            subject_content_digest: String::new(),
            parameters,
            invariants: vec![],
            evidence: values
                .iter()
                .map(|value| EvaluationEvidenceInput {
                    evidence_object_id: String::new(),
                    submission_id: String::new(),
                    content_digest: String::new(),
                    schema_id: String::new(),
                    schema_version: String::new(),
                    content: json!({ "value": value }),
                })
                .collect(),
            dependency_results: vec![],
        };
        BuiltinEvaluator { kind }.evaluate(&input).unwrap()
    }

    fn verdict(kind: Kind, parameters: Value, value: Value) -> (String, String) {
        let output = run(kind, parameters, &[value]);
        (output.status, output.reason_code)
    }

    fn pass() -> (String, String) {
        (STATUS_PASS.into(), "all_items_passed".into())
    }

    fn fail(reason: &str) -> (String, String) {
        (STATUS_FAIL.into(), reason.into())
    }

    #[test]
    fn digests_are_distinct_and_schemas_are_in_the_plan_subset() {
        let digests: BTreeSet<_> = KINDS.iter().map(|kind| kind.digest()).collect();
        assert_eq!(digests.len(), KINDS.len());
        for kind in KINDS {
            use sha2::{Digest, Sha256};
            let derived = Sha256::digest(format!(
                "chisei.builtin-evaluator/{}.v1",
                kind.metrics_label()
            ));
            assert_eq!(kind.digest(), format!("sha256:{derived:x}"));
            assert_eq!(Kind::from_digest(kind.digest()), Some(kind));
            crate::chisei::evaluation_plan::validate_parameter_schema(kind.parameter_schema())
                .unwrap();
        }
        assert_eq!(
            builtin_parameter_schema(&format!("sha256:{}", "a".repeat(64))),
            None
        );
    }

    #[test]
    fn exact_match_normalizes_only_when_asked() {
        let p = json!({"path": "/value", "expected": "Hello  World"});
        assert_eq!(
            verdict(Kind::ExactMatch, p.clone(), json!("Hello  World")),
            pass()
        );
        assert_eq!(
            verdict(Kind::ExactMatch, p, json!("hello world")),
            fail("value_mismatch")
        );
        let p = json!({"path": "/value", "expected": "Hello  World",
            "ignore_case": true, "normalize_whitespace": true});
        assert_eq!(
            verdict(Kind::ExactMatch, p.clone(), json!(" hello\tworld ")),
            pass()
        );
        assert_eq!(
            verdict(Kind::ExactMatch, p, json!(42)),
            fail("value_type_mismatch")
        );
    }

    #[test]
    fn every_evidence_item_must_pass_and_no_evidence_is_unknown() {
        let p = json!({"path": "/value", "expected": "ok"});
        let output = run(Kind::ExactMatch, p.clone(), &[json!("ok"), json!("no")]);
        assert_eq!(output.status, STATUS_FAIL);
        assert_eq!(output.result, json!({"items": 2, "passed": 1}));
        let output = run(Kind::ExactMatch, p.clone(), &[]);
        assert_eq!(
            (output.status.as_str(), output.reason_code.as_str()),
            (STATUS_UNKNOWN, "evidence_missing")
        );
        let missing = json!({"path": "/absent", "expected": "ok"});
        assert_eq!(
            verdict(Kind::ExactMatch, missing, json!("ok")),
            fail("value_missing")
        );
    }

    #[test]
    fn regex_matches_and_refuses_oversized_programs() {
        let p = json!({"path": "/value", "pattern": "^INV-[0-9]{4}$"});
        assert_eq!(
            verdict(Kind::RegexMatch, p.clone(), json!("INV-2026")),
            pass()
        );
        assert_eq!(
            verdict(Kind::RegexMatch, p, json!("inv-2026")),
            fail("pattern_not_matched")
        );
        let p = json!({"path": "/value", "pattern": "^inv", "ignore_case": true});
        assert_eq!(verdict(Kind::RegexMatch, p, json!("INV-1")), pass());

        let oversized = json!({"path": "", "pattern": "(?:a{1000}){1000}"}).to_string();
        let error =
            validate_builtin_parameters(REGEX_MATCH_IMPLEMENTATION_DIGEST, &oversized).unwrap_err();
        assert!(error.contains("pattern"), "{error}");
        let unparsable = json!({"path": "", "pattern": "("}).to_string();
        assert!(
            validate_builtin_parameters(REGEX_MATCH_IMPLEMENTATION_DIGEST, &unparsable).is_err()
        );
    }

    #[test]
    fn catastrophic_backtracking_patterns_stay_linear() {
        // Exponential in a backtracking engine; linear here.
        let p = json!({"path": "/value", "pattern": "^(a+)+$"});
        let input = format!("{}b", "a".repeat(100_000));
        let started = std::time::Instant::now();
        assert_eq!(
            verdict(Kind::RegexMatch, p, json!(input)),
            fail("pattern_not_matched")
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn numeric_and_date_ranges_are_inclusive() {
        let p = json!({"path": "/value", "minimum": 1, "maximum": 2.5});
        assert_eq!(verdict(Kind::NumericRange, p.clone(), json!(2.5)), pass());
        assert_eq!(
            verdict(Kind::NumericRange, p.clone(), json!(2.51)),
            fail("value_out_of_range")
        );
        assert_eq!(
            verdict(Kind::NumericRange, p, json!("2")),
            fail("value_type_mismatch")
        );
        let p = json!({"path": "/value", "not_before": "2026-01-01",
            "not_after": "2026-12-31T23:59:59Z"});
        assert_eq!(
            verdict(Kind::DateRange, p.clone(), json!("2026-01-01")),
            pass()
        );
        assert_eq!(
            verdict(
                Kind::DateRange,
                p.clone(),
                json!("2026-06-01T12:00:00+02:00")
            ),
            pass()
        );
        assert_eq!(
            verdict(
                Kind::DateRange,
                p.clone(),
                json!("2025-12-31T23:00:00-02:00")
            ),
            pass()
        );
        assert_eq!(
            verdict(Kind::DateRange, p.clone(), json!("2027-01-01")),
            fail("value_out_of_range")
        );
        assert_eq!(
            verdict(Kind::DateRange, p, json!("next tuesday")),
            fail("value_type_mismatch")
        );
    }

    #[test]
    fn edit_distance_normalizes_by_the_longer_text() {
        let p = json!({"path": "/value", "expected": "kitten", "max_normalized_distance": 0.5});
        // kitten -> sitting is 3 edits over 7 characters.
        assert_eq!(
            verdict(Kind::EditDistance, p.clone(), json!("sitting")),
            pass()
        );
        let strict =
            json!({"path": "/value", "expected": "kitten", "max_normalized_distance": 0.4});
        assert_eq!(
            verdict(Kind::EditDistance, strict.clone(), json!("sitting")),
            fail("distance_exceeded")
        );
        // Decided by length alone, without the quadratic comparison.
        assert_eq!(
            verdict(Kind::EditDistance, strict, json!("k".repeat(100_000))),
            fail("distance_exceeded")
        );
        // 29 edits over 100 characters meets an inclusive 0.29 bound, which
        // `0.29 * 100.0 == 28.999999999999996` would wrongly fail.
        let boundary = json!({"path": "/value", "expected": "a".repeat(100),
            "max_normalized_distance": 0.29});
        let value = format!("{}{}", "b".repeat(29), "a".repeat(71));
        assert_eq!(verdict(Kind::EditDistance, boundary, json!(value)), pass());
        let exact = json!({"path": "/value", "expected": "", "max_normalized_distance": 0});
        assert_eq!(verdict(Kind::EditDistance, exact, json!("")), pass());
    }

    #[test]
    fn token_overlap_is_clipped_reference_recall() {
        let p = json!({"path": "/value", "reference": "the cat sat on the mat",
            "n": 1, "min_recall": 0.8, "ignore_case": true});
        // Five of six reference unigrams are present ("the" counted once).
        assert_eq!(
            verdict(Kind::TokenOverlap, p.clone(), json!("The cat sat on a mat")),
            pass()
        );
        assert_eq!(
            verdict(Kind::TokenOverlap, p, json!("a dog sat")),
            fail("overlap_below_minimum")
        );
        // 57 of 100 reference unigrams meets an inclusive 0.57 minimum.
        let reference: Vec<String> = (0..100).map(|index| format!("t{index}")).collect();
        let boundary = json!({"path": "/value", "reference": reference.join(" "),
            "n": 1, "min_recall": 0.57});
        assert_eq!(
            verdict(
                Kind::TokenOverlap,
                boundary,
                json!(reference[..57].join(" "))
            ),
            pass()
        );
        let bigram =
            json!({"path": "/value", "reference": "red apple pie", "n": 2, "min_recall": 1});
        assert_eq!(
            verdict(Kind::TokenOverlap, bigram.clone(), json!("red apple pie!")),
            pass()
        );
        assert_eq!(
            verdict(Kind::TokenOverlap, bigram, json!("apple red pie")),
            fail("overlap_below_minimum")
        );
    }

    #[test]
    fn size_bounds_counts_items_or_distinct_items() {
        let p = json!({"path": "/value", "min_items": 2, "max_items": 3});
        assert_eq!(
            verdict(Kind::SizeBounds, p.clone(), json!([1, 1, 2])),
            pass()
        );
        assert_eq!(
            verdict(Kind::SizeBounds, p, json!([1, 2, 3, 4])),
            fail("size_out_of_bounds")
        );
        let distinct = json!({"path": "/value", "min_items": 3, "distinct": true});
        assert_eq!(
            verdict(
                Kind::SizeBounds,
                distinct,
                json!([{"a": 1, "b": 2}, {"b": 2, "a": 1}, 3])
            ),
            fail("size_out_of_bounds")
        );
    }

    #[test]
    fn semantic_parameter_errors_are_refused_before_execution() {
        let cases = [
            (NUMERIC_RANGE_IMPLEMENTATION_DIGEST, json!({"path": "/v"})),
            (
                NUMERIC_RANGE_IMPLEMENTATION_DIGEST,
                json!({"path": "/v", "minimum": 3, "maximum": 2}),
            ),
            (
                DATE_RANGE_IMPLEMENTATION_DIGEST,
                json!({"path": "/v", "not_before": "yesterday"}),
            ),
            (
                SIZE_BOUNDS_IMPLEMENTATION_DIGEST,
                json!({"path": "/v", "min_items": 4, "max_items": 1}),
            ),
            (
                TOKEN_OVERLAP_IMPLEMENTATION_DIGEST,
                json!({"path": "/v", "reference": "one", "n": 2, "min_recall": 0.5}),
            ),
            (
                EXACT_MATCH_IMPLEMENTATION_DIGEST,
                json!({"path": "value", "expected": "x"}),
            ),
        ];
        for (digest, parameters) in cases {
            let parameters = parameters.to_string();
            let schema = builtin_parameter_schema(digest).unwrap();
            validate_parameters(schema, &parameters).unwrap();
            assert!(
                validate_builtin_parameters(digest, &parameters).is_err(),
                "{parameters}"
            );
        }
        // The schema itself refuses out-of-range or unknown parameters.
        let schema = builtin_parameter_schema(EDIT_DISTANCE_IMPLEMENTATION_DIGEST).unwrap();
        assert!(
            validate_parameters(
                schema,
                r#"{"path":"/v","expected":"x","max_normalized_distance":1.5}"#
            )
            .is_err()
        );
        assert!(
            validate_parameters(
                schema,
                r#"{"path":"/v","expected":"x","max_normalized_distance":0.5,"extra":true}"#
            )
            .is_err()
        );
    }
}
