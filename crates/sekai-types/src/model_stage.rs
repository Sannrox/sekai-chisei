//! Model stages (#3023).
//!
//! A stage (for example `staging` or `production`) names the version of one
//! model that consumers should use. A stage with an evaluation suite moves only
//! through a promotion whose evaluation run passed that suite for the version
//! (ADR 0079). A stage without one follows each newly registered version.
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
