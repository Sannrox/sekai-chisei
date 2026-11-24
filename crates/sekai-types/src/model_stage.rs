//! Model stages (#3023).
//!
//! A stage (for example `staging` or `production`) names the version of one
//! model that consumers should use. A stage with an evaluation suite moves only
//! through a promotion whose evaluation run passed that suite for the version
//! (ADR 0079) and whose version a second principal approved for the stage
//! (#3159). A stage without one follows each newly registered version.
//! Transform inputs may pin a stage instead of a version; the pin resolves to
//! the stage's version when a run is admitted.

use serde::{Deserialize, Serialize};

pub const MODEL_STAGE_NOT_FOUND: &str = "model stage not found";

/// Prefix of a transform model input that pins a stage: `stage:<model>/<stage>`.
pub const STAGE_PIN_PREFIX: &str = "stage:";

/// Operation class of a promotion receipt.
pub const PROMOTION_OPERATION_CLASS: &str = "model_stage_promotion";

/// Refusal reasons a promotion records on its receipt.
pub const REFUSAL_SUITE_MISSING: &str = "model_stage.suite_missing";
pub const REFUSAL_SUITE_FAILED: &str = "model_stage.suite_failed";
pub const REFUSAL_VERSION_MISMATCH: &str = "model_stage.evaluation_version_mismatch";
pub const REFUSAL_STAGE_MOVED: &str = "model_stage.stage_moved";
pub const REFUSAL_REVIEW_NOT_APPROVED: &str = "model_stage.review_not_approved";

/// Operation class of a review submission or decision receipt (#3159).
pub const REVIEW_OPERATION_CLASS: &str = "model_stage_review";

pub const MODEL_STAGE_REVIEW_NOT_FOUND: &str = "model stage review not found";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStage {
    pub namespace: String,
    pub model_name: String,
    pub stage: String,
    /// Suite a promotion must pass; empty for a gateless stage.
    pub evaluation_suite_id: String,
    /// Current version id; empty until the first promotion or registration.
    pub version_id: String,
    pub updated_at_ms: i64,
}

impl ModelStage {
    pub fn is_gateless(&self) -> bool {
        self.evaluation_suite_id.is_empty()
    }
}

/// Where one review of a version for a stage stands. A decision is final: a
/// rejected version is not resubmitted, a fixed model is a new version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReviewState {
    Pending,
    Approved,
    Rejected,
}

impl ReviewState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "rejected" => Self::Rejected,
            _ => return None,
        })
    }
}

/// A second principal's review of one model version for one stage (#3159).
/// A promotion to a gated stage needs an approved review of that version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStageReview {
    pub namespace: String,
    pub model_name: String,
    pub stage: String,
    pub version_id: String,
    pub state: ReviewState,
    pub submitted_by: String,
    pub submitted_at_ms: i64,
    /// Empty while pending.
    pub decided_by: String,
    pub reason: String,
    pub decided_at_ms: i64,
}

/// Whether a caller presenting `principals` may decide a review `submitter`
/// submitted: none of the caller's identities is the submitter, even for a
/// namespace administrator. The rule parked Actions apply (`may_decide`).
pub fn may_decide_review(submitter: &str, principals: &[String]) -> bool {
    !principals.is_empty() && principals.iter().all(|principal| principal != submitter)
}

/// A stage name is a short lowercase token, so a stage pin parses unambiguously
/// after the last `/` even when the model name contains one.
pub fn validate_stage_name(stage: &str) -> Result<(), String> {
    let valid = !stage.is_empty()
        && stage.len() <= 64
        && stage.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte)
        });
    if valid {
        Ok(())
    } else {
        Err("model stage name must be 1-64 of [a-z0-9_-]".into())
    }
}

/// The `(model_name, stage)` a model input value pins, or `None` when the value
/// is a literal version id.
pub fn parse_stage_pin(value: &str) -> Option<(&str, &str)> {
    let rest = value.strip_prefix(STAGE_PIN_PREFIX)?;
    let (model_name, stage) = rest.rsplit_once('/')?;
    (!model_name.is_empty() && validate_stage_name(stage).is_ok()).then_some((model_name, stage))
}

/// Whether evaluation run evidence admits promoting `version_id` to a stage
/// gated by `suite_id`: the run belongs to that suite, was run against that
/// version (`config_ref`), and every one of at least one case passed.
pub fn evaluation_admits(
    suite_id: &str,
    version_id: &str,
    run_suite_id: &str,
    run_config_ref: &str,
    case_results: &[bool],
) -> Result<(), &'static str> {
    if run_suite_id != suite_id {
        return Err(REFUSAL_SUITE_MISSING);
    }
    if run_config_ref != version_id {
        return Err(REFUSAL_VERSION_MISMATCH);
    }
    if case_results.is_empty() || !case_results.iter().all(|passed| *passed) {
        return Err(REFUSAL_SUITE_FAILED);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_submitter_never_decides_their_own_review() {
        let caller = |names: &[&str]| {
            names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>()
        };
        assert!(may_decide_review("alice", &caller(&["bob"])));
        assert!(!may_decide_review("alice", &caller(&["bob", "alice"])));
        assert!(!may_decide_review("alice", &caller(&[])));
    }

    #[test]
    fn stage_pins_parse_after_the_last_slash() {
        assert_eq!(
            parse_stage_pin("stage:team/churn/production"),
            Some(("team/churn", "production"))
        );
        assert_eq!(parse_stage_pin("mv_abc"), None);
        assert_eq!(parse_stage_pin("stage:churn/Prod"), None);
        assert_eq!(parse_stage_pin("stage:/production"), None);
    }

    #[test]
    fn evaluation_needs_the_suite_the_version_and_all_cases_passing() {
        let admit = |suite, config, cases: &[bool]| {
            evaluation_admits("suite-a", "mv_1", suite, config, cases)
        };
        assert_eq!(admit("suite-a", "mv_1", &[true, true]), Ok(()));
        assert_eq!(
            admit("suite-b", "mv_1", &[true]),
            Err(REFUSAL_SUITE_MISSING)
        );
        assert_eq!(
            admit("suite-a", "mv_2", &[true]),
            Err(REFUSAL_VERSION_MISMATCH)
        );
        assert_eq!(
            admit("suite-a", "mv_1", &[true, false]),
            Err(REFUSAL_SUITE_FAILED)
        );
        assert_eq!(admit("suite-a", "mv_1", &[]), Err(REFUSAL_SUITE_FAILED));
    }
}
