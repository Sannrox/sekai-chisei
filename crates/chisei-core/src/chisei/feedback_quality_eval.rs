//! Promote application-feedback quality records into eval-suite cases (#1233).
//!
//! Distinct from Gunshi operator-feedback promotion: cases use
//! `feedback.quality-eval-case/v1` and never carry operator choice or
//! allocation fields.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::chisei::decision_ledger::Decision;
use crate::chisei::eval::{Assertion, Case, Suite};
use crate::chisei_store::{ChiseiDecisionStore, ChiseiEvalStore, ChiseiStore};
use sekai_core::sekai::feedback_quality::{QUALITY_CASE_VERSION, QualityCorpusCase};

pub const QUALITY_SUITE_PREFIX: &str = "feedback-quality-";
pub const PROMOTE_ACTION: &str = "feedback.quality_promoted_to_eval";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromoteQualityResult {
    pub suite_id: String,
    pub case_id: String,
    pub created: bool,
}

pub fn quality_suite_id(namespace: &str) -> String {
    format!("{QUALITY_SUITE_PREFIX}{namespace}")
}

pub fn quality_case_id(record: &QualityCorpusCase) -> String {
    format!(
        "fb-q-{}-{}",
        record.finding_id,
        record.evidence_coverage.replace(',', "-")
    )
}

/// Distinguish generated quality labels from ordinary authored assertions.
pub fn is_generated_quality_case(case: &Case) -> bool {
    let Ok(payload) = serde_json::from_str::<QualityCorpusCase>(&case.spec) else {
        return false;
    };
    if payload.contract_version != QUALITY_CASE_VERSION
        || payload.namespace != case.namespace
        || quality_case_id(&payload) != case.id
    {
        return false;
    }
    let expected = vec![
        Assertion {
            assert_type: "feedback_quality".into(),
            value: payload.quality,
        },
        Assertion {
            assert_type: "feedback_match_class".into(),
            value: payload.match_class,
        },
        Assertion {
            assert_type: "feedback_verification_result".into(),
            value: payload.verification_result,
        },
    ];
    case.assertions == expected
}

fn case_from(record: &QualityCorpusCase) -> Result<Case, String> {
    if record.contract_version != QUALITY_CASE_VERSION {
        return Err(format!(
            "unsupported quality contract {}",
            record.contract_version
        ));
    }
    if record.namespace.trim().is_empty() || record.finding_id.trim().is_empty() {
        return Err("quality case namespace and finding are required".into());
    }
    let spec = serde_json::to_string_pretty(record).map_err(|error| error.to_string())?;
    Ok(Case {
        id: quality_case_id(record),
        name: format!("feedback quality {}", record.finding_id),
        namespace: record.namespace.clone(),
        spec,
        assertions: vec![
            Assertion {
                assert_type: "feedback_quality".into(),
                value: record.quality.clone(),
            },
            Assertion {
                assert_type: "feedback_match_class".into(),
                value: record.match_class.clone(),
            },
            Assertion {
                assert_type: "feedback_verification_result".into(),
                value: record.verification_result.clone(),
            },
        ],
    })
}

/// Append a quality corpus case to the namespace's `feedback-quality-` suite.
pub fn promote_quality_to_eval(
    db: &ChiseiStore,
    actor: &str,
    record: &QualityCorpusCase,
    now_ms: i64,
) -> Result<PromoteQualityResult, String> {
    if actor.trim().is_empty() {
        return Err("actor is required".into());
    }
    if now_ms < 0 {
        return Err("timestamp must be non-negative".into());
    }
    let case = case_from(record)?;
    let suite_id = quality_suite_id(&record.namespace);
    let existing = db.get_eval_suite_record(&suite_id)?;
    let (suite, created) = match existing {
        Some(mut suite) => {
            if suite
                .cases
                .iter()
                .any(|item| item.namespace != record.namespace)
            {
                return Err("quality suite contains cases from another namespace".into());
            }
            if let Some(existing_case) = suite.cases.iter().find(|item| item.id == case.id) {
                if existing_case != &case {
                    return Err(format!(
                        "quality case {} already exists with different content",
                        case.id
                    ));
                }
                return Ok(PromoteQualityResult {
                    suite_id: suite.id,
                    case_id: case.id,
                    created: false,
                });
            }
            suite.cases.push(case.clone());
            suite.cases.sort_by(|left, right| left.id.cmp(&right.id));
            db.append_feedback_eval_suite(&suite)?;
            (suite, true)
        }
        None => {
            let suite = Suite {
                id: suite_id.clone(),
                name: format!("Feedback quality ({})", record.namespace),
                description: "Application-feedback quality records promoted into evaluation cases"
                    .into(),
                cases: vec![case.clone()],
            };
            db.append_feedback_eval_suite(&suite)?;
            (suite, true)
        }
    };
    let decision = Decision {
        id: format!(
            "feedback-quality-promote:{}:{}:{}",
            suite.id,
            case.id,
            if created { "new" } else { "idempotent" }
        ),
        timestamp: now_ms,
        actor: actor.into(),
        action: PROMOTE_ACTION.into(),
        reason: if created {
            "promoted application-feedback quality into eval suite".into()
        } else {
            "idempotent quality promotion".into()
        },
        evidence: HashMap::from([
            ("namespace".into(), record.namespace.clone()),
            ("data_class".into(), "internal".into()),
            ("suite_id".into(), suite.id.clone()),
            ("case_id".into(), case.id.clone()),
            ("finding_id".into(), record.finding_id.clone()),
            ("created".into(), created.to_string()),
        ]),
        target_id: case.id.clone(),
        outcome: if created {
            "promoted".into()
        } else {
            "unchanged".into()
        },
    };
    db.record_decision(&decision)?;
    Ok(PromoteQualityResult {
        suite_id: suite.id,
        case_id: case.id,
        created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei_store::ChiseiStore;
    use sekai_core::sekai::feedback_quality::QUALITY_CASE_VERSION;

    fn case(finding: &str, quality: &str) -> QualityCorpusCase {
        QualityCorpusCase {
            contract_version: QUALITY_CASE_VERSION.into(),
            namespace: "ops".into(),
            finding_id: finding.into(),
            signature: "api:timeout".into(),
            quality: quality.into(),
            match_class: "absent_telemetry".into(),
            verification_result: "inconclusive".into(),
            tenkai_versions: "0.5.0".into(),
            evidence_coverage: "absent_telemetry".into(),
        }
    }

    #[test]
    fn promotes_quality_cases_without_gunshi_fields() {
        let db = ChiseiStore::memory();
        let first =
            promote_quality_to_eval(&db, "reviewer", &case("find-1", "useful"), 10).unwrap();
        assert!(first.created);
        let second =
            promote_quality_to_eval(&db, "reviewer", &case("find-1", "useful"), 11).unwrap();
        assert!(!second.created);
        let other =
            promote_quality_to_eval(&db, "reviewer", &case("find-2", "improved"), 12).unwrap();
        assert!(other.created);
        let suite = db.get_eval_suite_record(&first.suite_id).unwrap().unwrap();
        assert_eq!(suite.id, "feedback-quality-ops");
        assert_eq!(suite.cases.len(), 2);
        assert!(suite.cases.iter().all(|item| item.namespace == "ops"));
        assert!(
            !suite
                .cases
                .iter()
                .any(|item| item.spec.contains("operator_response")
                    || item.spec.contains("allocation_id")
                    || item.spec.contains("gunshi"))
        );
        assert!(
            suite.cases[0]
                .assertions
                .iter()
                .any(|assertion| assertion.assert_type == "feedback_quality")
        );
        assert!(is_generated_quality_case(&suite.cases[0]));
        let mut forged = suite.cases[0].clone();
        forged.assertions.push(Assertion {
            assert_type: "status".into(),
            value: "ok".into(),
        });
        assert!(!is_generated_quality_case(&forged));
    }

    #[test]
    fn refuses_cross_namespace_quality_suite() {
        let db = ChiseiStore::memory();
        promote_quality_to_eval(&db, "reviewer", &case("find-1", "useful"), 10).unwrap();
        let mut foreign = case("find-2", "useful");
        foreign.namespace = "other".into();
        foreign.finding_id = "find-other".into();
        promote_quality_to_eval(&db, "reviewer", &foreign, 11).unwrap();
        let mixed = QualityCorpusCase {
            contract_version: QUALITY_CASE_VERSION.into(),
            namespace: "ops".into(),
            finding_id: "find-x".into(),
            signature: "api:timeout".into(),
            quality: "useful".into(),
            match_class: "absent_telemetry".into(),
            verification_result: "inconclusive".into(),
            tenkai_versions: "0.5.0".into(),
            evidence_coverage: "absent_telemetry".into(),
        };
        promote_quality_to_eval(&db, "reviewer", &mixed, 12).unwrap();
        let suite = db
            .get_eval_suite_record(&quality_suite_id("ops"))
            .unwrap()
            .unwrap();
        assert!(suite.cases.iter().all(|item| item.namespace == "ops"));
        let other = db
            .get_eval_suite_record(&quality_suite_id("other"))
            .unwrap()
            .unwrap();
        assert!(other.cases.iter().all(|item| item.namespace == "other"));
    }
}
