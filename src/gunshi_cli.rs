use crate::chisei::gunshi::{
    AdvisoryPolicy, AllocationRequest, BaselineAllocation, KiokuEvidence, recommend_advisory,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub const RECOMMENDATION_INPUT_VERSION: &str = "gunshi.recommendation-input/v1";
pub const RECOMMENDATION_BUNDLE_VERSION: &str = "gunshi.recommendation-bundle/v1";

pub fn usage() -> &'static str {
    "sekaictl gunshi recommend <input.json> --output <recommendations.json>"
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationInput {
    pub contract_version: String,
    pub request: AllocationRequest,
    pub advisory_policy: AdvisoryPolicy,
    #[serde(default)]
    pub kioku_evidence: Vec<KiokuEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationBundle {
    pub contract_version: String,
    pub advisory: bool,
    pub input_digest: String,
    pub allocation: BaselineAllocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendConfig {
    pub input: PathBuf,
    pub output: PathBuf,
}

impl RecommendConfig {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let args = args.into_iter().collect::<Vec<_>>();
        let mut input = None;
        let mut output = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--output" => {
                    index += 1;
                    output = Some(
                        args.get(index)
                            .filter(|value| !value.starts_with('-'))
                            .map(PathBuf::from)
                            .ok_or_else(|| "--output requires a path".to_string())?,
                    );
                }
                flag if flag.starts_with('-') => return Err(format!("unknown option {flag:?}")),
                path if input.is_none() => input = Some(PathBuf::from(path)),
                path => return Err(format!("unexpected input path {path:?}")),
            }
            index += 1;
        }
        let config = Self {
            input: input.ok_or_else(|| "recommendation input path is required".to_string())?,
            output: output.ok_or_else(|| "--output is required".to_string())?,
        };
        if paths_refer_to_same_file(&config.input, &config.output)? {
            return Err("recommendation input and output must be different files".into());
        }
        Ok(config)
    }
}

pub fn run_recommend(config: RecommendConfig) -> Result<RecommendationBundle, BoxErr> {
    let bytes = std::fs::read(&config.input)?;
    let input: RecommendationInput = serde_json::from_slice(&bytes)?;
    if input.contract_version != RECOMMENDATION_INPUT_VERSION {
        return Err(std::io::Error::other(format!(
            "unsupported recommendation input contract {}",
            input.contract_version
        ))
        .into());
    }
    let allocation = recommend_advisory(
        &input.request,
        &input.kioku_evidence,
        &input.advisory_policy,
    )
    .map_err(std::io::Error::other)?;
    let bundle = RecommendationBundle {
        contract_version: RECOMMENDATION_BUNDLE_VERSION.into(),
        advisory: true,
        input_digest: format!("{:x}", Sha256::digest(&bytes)),
        allocation,
    };
    let json = serde_json::to_string_pretty(&bundle)?;
    write_atomically(&config.output, format!("{json}\n").as_bytes())?;
    Ok(bundle)
}

fn paths_refer_to_same_file(input: &Path, output: &Path) -> Result<bool, String> {
    if input == output {
        return Ok(true);
    }
    if output.exists() {
        return same_file::is_same_file(input, output)
            .map_err(|error| format!("compare recommendation paths: {error}"));
    }
    Ok(false)
}

fn write_atomically(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(not(unix))]
    if path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "atomic recommendation replacement is unsupported on this platform",
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("recommendations");
    let temporary = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::gunshi::{
        AgentCapacity, BaselineStrategy, CapacityEnvelope, ModelProfile, OperationRisk,
        PendingOperation, Strategy,
    };
    use std::collections::BTreeSet;

    fn input() -> RecommendationInput {
        RecommendationInput {
            contract_version: RECOMMENDATION_INPUT_VERSION.into(),
            request: AllocationRequest {
                capacity: CapacityEnvelope {
                    captured_at_ms: 2_000,
                    policy_version: "policy-v1".into(),
                    agents: vec![AgentCapacity {
                        agent_id: "agent-a".into(),
                        runtime: "native".into(),
                        models: BTreeSet::from(["small".into(), "large".into()]),
                        tools: BTreeSet::from(["search".into()]),
                        operation_classes: BTreeSet::from(["triage".into()]),
                        available_slots: 1,
                        healthy: true,
                    }],
                    model_profiles: vec![
                        ModelProfile {
                            model: "small".into(),
                            quality: 0.7,
                            cost_per_attempt_usd_micros: 10,
                            latency_ms: 20,
                            uncertainty: 0.2,
                        },
                        ModelProfile {
                            model: "large".into(),
                            quality: 0.9,
                            cost_per_attempt_usd_micros: 20,
                            latency_ms: 30,
                            uncertainty: 0.1,
                        },
                    ],
                    budget_remaining_usd_micros: 40,
                    max_parallel_attempts: 1,
                    human_attention_minutes: 5,
                },
                operations: vec![PendingOperation {
                    operation_id: "op-1".into(),
                    namespace: "support".into(),
                    operation_class: "triage".into(),
                    priority: 10,
                    risk: OperationRisk::Low,
                    submitted_at_ms: 1_000,
                    required_tools: BTreeSet::from(["search".into()]),
                    allowed_models: BTreeSet::from(["small".into(), "large".into()]),
                    max_attempts: 2,
                    budget_ceiling_usd_micros: 40,
                    acceptance_criteria: vec!["classified".into()],
                    approval_required: false,
                    human_attention_minutes_required: 0,
                }],
                strategy: Strategy {
                    strategy_id: "priority".into(),
                    version: "1".into(),
                    baseline: BaselineStrategy::PriorityFirst,
                },
            },
            advisory_policy: AdvisoryPolicy {
                max_memory_age_ms: 2_000,
                min_score: 0.5,
                max_evidence_references: 4,
            },
            kioku_evidence: vec![KiokuEvidence {
                memory_id: "memory-1".into(),
                namespace: "support".into(),
                operation_class: "triage".into(),
                model: "large".into(),
                score: 0.95,
                passed: true,
                status: "active".into(),
                observed_at_ms: 1_500,
                receipt_reference: Some("receipt-1".into()),
            }],
        }
    }

    #[test]
    fn parser_requires_distinct_input_and_output() {
        assert!(RecommendConfig::from_args(["input.json".into()]).is_err());
        assert!(
            RecommendConfig::from_args([
                "input.json".into(),
                "--output".into(),
                "input.json".into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn recommendation_artifact_is_reproducible_and_advisory() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-gunshi-recommend-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let input_path = directory.join("input.json");
        let first_path = directory.join("first.json");
        let second_path = directory.join("second.json");
        std::fs::write(&input_path, serde_json::to_vec_pretty(&input()).unwrap()).unwrap();

        let first = run_recommend(RecommendConfig {
            input: input_path.clone(),
            output: first_path.clone(),
        })
        .unwrap();
        let second = run_recommend(RecommendConfig {
            input: input_path.clone(),
            output: second_path.clone(),
        })
        .unwrap();

        assert_eq!(first, second);
        assert_eq!(
            std::fs::read(&first_path).unwrap(),
            std::fs::read(&second_path).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&first_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(first.advisory);
        let recommendation = &first.allocation.plans[0];
        assert!(recommendation.advisory);
        assert_eq!(recommendation.selection.model, "large");
        assert_eq!(recommendation.selection.runtime, "native");
        assert_eq!(recommendation.attempts.max_attempts, 2);
        assert_eq!(recommendation.budget_ceiling_usd_micros, 40);
        assert_eq!(
            recommendation.verification.acceptance_criteria,
            ["classified"]
        );
        assert_eq!(recommendation.evidence[0].reference, "memory-1");
        assert_eq!(recommendation.evidence[1].reference, "receipt-1");

        let replacement = write_atomically(&first_path, b"replacement");
        #[cfg(unix)]
        {
            replacement.unwrap();
            assert_eq!(std::fs::read(&first_path).unwrap(), b"replacement");
        }
        #[cfg(not(unix))]
        assert_eq!(
            replacement.unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );

        for path in [input_path, first_path, second_path] {
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn unsupported_input_contract_does_not_publish_output() {
        let directory = std::env::temp_dir().join(format!(
            "sekai-gunshi-version-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let input_path = directory.join("input.json");
        let output_path = directory.join("output.json");
        let mut input = input();
        input.contract_version = "gunshi.recommendation-input/v0".into();
        std::fs::write(&input_path, serde_json::to_vec(&input).unwrap()).unwrap();

        assert!(
            run_recommend(RecommendConfig {
                input: input_path.clone(),
                output: output_path.clone(),
            })
            .is_err()
        );
        assert!(!output_path.exists());

        std::fs::remove_file(input_path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn recommendation_input_rejects_nested_unknown_fields() {
        let mut value = serde_json::to_value(input()).unwrap();
        value["request"]["operations"][0]["human_attention_minutes_requred"] =
            serde_json::json!(10);
        assert!(serde_json::from_value::<RecommendationInput>(value).is_err());
    }
}
