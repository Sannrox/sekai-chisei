use crate::chisei::gunshi::{
    AdvisoryScorecard, BaselineAllocation, ObservedOutcome, OperatorChoice, recommend_advisory,
};
pub use crate::chisei::gunshi::{RECOMMENDATION_INPUT_VERSION, RecommendationInput};
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{
    AuthorizeGunshiAutoDispatchRequest, GetGunshiAllocationStatusRequest,
    GetGunshiScorecardRequest, InstallGunshiAllocationBaselineRequest,
    IssueGunshiRecommendationsRequest, PromoteGunshiAllocationPolicyRequest,
    PromoteGunshiFeedbackToEvalRequest, RecordGunshiFeedbackRequest,
    RollbackGunshiAllocationPolicyRequest, SetGunshiAllocationKillSwitchRequest,
    SetGunshiAutoOptInRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

pub const RECOMMENDATION_BUNDLE_VERSION: &str = "gunshi.recommendation-bundle/v1";
pub const ISSUED_RECOMMENDATION_BUNDLE_VERSION: &str = "gunshi.recommendation-bundle/v2";

pub fn usage() -> &'static str {
    "sekaictl gunshi recommend <input.json> --output <recommendations.json>\n  sekaictl gunshi issue <input.json> --output <recommendations.json>\n  sekaictl gunshi respond <recommendations.json> <choice.json> --operation <id> [--outcome <outcome.json>]\n  sekaictl gunshi scorecard --namespace <name>\n  sekaictl gunshi allocation-status --namespace <name>\n  sekaictl gunshi install-baseline --namespace <name> --snapshot <snapshot.json> --gate <gate.json>\n  sekaictl gunshi promote --namespace <name> --candidate <candidate.json> --baseline-eval <eval.json> --candidate-eval <eval.json> --expected-revision <id>\n  sekaictl gunshi rollback --namespace <name> --expected-revision <id> --reason <text>\n  sekaictl gunshi auto-opt-in --namespace <name> --expected-revision <id> [--off]\n  sekaictl gunshi kill-switch --namespace <name> --reason <text> [--clear]\n  sekaictl gunshi authorize-auto --namespace <name> --plan <plan.json> --operation <op.json> --capacity <capacity.json>\n  sekaictl gunshi promote-feedback --namespace <name> --suite-id <feedback-...> --issuance-id <id> --allocation-id <id>"
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationBundle {
    pub contract_version: String,
    pub advisory: bool,
    pub input_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuance_id: Option<String>,
    pub allocation: BaselineAllocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendConfig {
    pub input: PathBuf,
    pub output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackConfig {
    pub recommendations: PathBuf,
    pub choice: PathBuf,
    pub operation_id: String,
    pub outcome: Option<PathBuf>,
}

impl FeedbackConfig {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let args = args.into_iter().collect::<Vec<_>>();
        let mut paths = Vec::new();
        let mut operation_id = None;
        let mut outcome = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--operation" => {
                    index += 1;
                    operation_id = Some(required_arg(&args, index, "--operation")?);
                }
                "--outcome" => {
                    index += 1;
                    outcome = Some(PathBuf::from(required_arg(&args, index, "--outcome")?));
                }
                flag if flag.starts_with('-') => return Err(format!("unknown option {flag:?}")),
                path => paths.push(PathBuf::from(path)),
            }
            index += 1;
        }
        if paths.len() != 2 {
            return Err("respond requires recommendation and choice paths".into());
        }
        Ok(Self {
            recommendations: paths.remove(0),
            choice: paths.remove(0),
            operation_id: operation_id.ok_or_else(|| "--operation is required".to_string())?,
            outcome,
        })
    }
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
        issuance_id: None,
        allocation,
    };
    let json = serde_json::to_string_pretty(&bundle)?;
    write_atomically(&config.output, format!("{json}\n").as_bytes())?;
    Ok(bundle)
}

pub async fn issue_recommendations(
    config: RecommendConfig,
) -> Result<RecommendationBundle, BoxErr> {
    let bytes = std::fs::read(&config.input)?;
    let input: RecommendationInput = serde_json::from_slice(&bytes)?;
    if input.contract_version != RECOMMENDATION_INPUT_VERSION {
        return Err(std::io::Error::other(format!(
            "unsupported recommendation input contract {}",
            input.contract_version
        ))
        .into());
    }
    let issuance_id = format!("issuance-{}", uuid::Uuid::new_v4().simple());
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .issue_gunshi_recommendations(IssueGunshiRecommendationsRequest {
            input_json: serde_json::to_string(&input)?,
            issuance_id,
        })
        .await?
        .into_inner();
    let bundle = RecommendationBundle {
        contract_version: ISSUED_RECOMMENDATION_BUNDLE_VERSION.into(),
        advisory: true,
        input_digest: format!("{:x}", Sha256::digest(&bytes)),
        issuance_id: Some(response.issuance_id),
        allocation: serde_json::from_str(&response.allocation_json)?,
    };
    let json = serde_json::to_string_pretty(&bundle)?;
    write_atomically(&config.output, format!("{json}\n").as_bytes())?;
    Ok(bundle)
}

pub async fn record_response(config: FeedbackConfig) -> Result<serde_json::Value, BoxErr> {
    let bundle: RecommendationBundle =
        serde_json::from_slice(&std::fs::read(&config.recommendations)?)?;
    if bundle.contract_version != ISSUED_RECOMMENDATION_BUNDLE_VERSION || !bundle.advisory {
        return Err(
            std::io::Error::other("unsupported or non-advisory recommendation bundle").into(),
        );
    }
    let plans = bundle
        .allocation
        .plans
        .iter()
        .filter(|plan| plan.operation_id == config.operation_id)
        .collect::<Vec<_>>();
    let [plan] = plans.as_slice() else {
        return Err(std::io::Error::other(format!(
            "recommendation bundle must contain exactly one plan for operation {}",
            config.operation_id
        ))
        .into());
    };
    let choice: OperatorChoice = serde_json::from_slice(&std::fs::read(&config.choice)?)?;
    let outcome: Option<ObservedOutcome> = config
        .outcome
        .as_ref()
        .map(|path| -> Result<_, BoxErr> { Ok(serde_json::from_slice(&std::fs::read(path)?)?) })
        .transpose()?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .record_gunshi_feedback(RecordGunshiFeedbackRequest {
            plan_json: serde_json::to_string(plan)?,
            choice_json: serde_json::to_string(&choice)?,
            outcome_json: outcome
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?
                .unwrap_or_default(),
            issuance_id: bundle.issuance_id.ok_or_else(|| {
                std::io::Error::other("recommendation bundle has no governed issuance identity")
            })?,
        })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.feedback_json)?)
}

pub async fn get_scorecard(namespace: String) -> Result<AdvisoryScorecard, BoxErr> {
    if namespace.trim().is_empty() || namespace.trim() != namespace {
        return Err(std::io::Error::other("namespace must be non-empty and canonical").into());
    }
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .get_gunshi_scorecard(GetGunshiScorecardRequest { namespace })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.scorecard_json)?)
}

pub async fn get_allocation_status(namespace: String) -> Result<serde_json::Value, BoxErr> {
    require_namespace(&namespace)?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .get_gunshi_allocation_status(GetGunshiAllocationStatusRequest { namespace })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.status_json)?)
}

pub async fn install_baseline(
    namespace: String,
    snapshot_path: PathBuf,
    gate_path: PathBuf,
) -> Result<serde_json::Value, BoxErr> {
    require_namespace(&namespace)?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .install_gunshi_allocation_baseline(InstallGunshiAllocationBaselineRequest {
            namespace,
            snapshot_json: std::fs::read_to_string(snapshot_path)?,
            gate_json: std::fs::read_to_string(gate_path)?,
        })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.status_json)?)
}

pub async fn promote_policy(
    namespace: String,
    candidate_path: PathBuf,
    baseline_eval_path: PathBuf,
    candidate_eval_path: PathBuf,
    expected_revision: String,
) -> Result<serde_json::Value, BoxErr> {
    require_namespace(&namespace)?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .promote_gunshi_allocation_policy(PromoteGunshiAllocationPolicyRequest {
            namespace,
            candidate_json: std::fs::read_to_string(candidate_path)?,
            baseline_evaluation_json: std::fs::read_to_string(baseline_eval_path)?,
            candidate_evaluation_json: std::fs::read_to_string(candidate_eval_path)?,
            expected_revision,
        })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.status_json)?)
}

pub async fn rollback_policy(
    namespace: String,
    expected_revision: String,
    reason: String,
) -> Result<serde_json::Value, BoxErr> {
    require_namespace(&namespace)?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .rollback_gunshi_allocation_policy(RollbackGunshiAllocationPolicyRequest {
            namespace,
            expected_revision,
            reason,
        })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.status_json)?)
}

pub async fn set_auto_opt_in(
    namespace: String,
    opt_in: bool,
    expected_revision: String,
) -> Result<serde_json::Value, BoxErr> {
    require_namespace(&namespace)?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .set_gunshi_auto_opt_in(SetGunshiAutoOptInRequest {
            namespace,
            opt_in,
            expected_revision,
        })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.status_json)?)
}

pub async fn set_kill_switch(
    namespace: String,
    enabled: bool,
    reason: String,
) -> Result<serde_json::Value, BoxErr> {
    require_namespace(&namespace)?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .set_gunshi_allocation_kill_switch(SetGunshiAllocationKillSwitchRequest {
            namespace,
            enabled,
            reason,
        })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.status_json)?)
}

pub async fn authorize_auto(
    namespace: String,
    plan_path: PathBuf,
    operation_path: PathBuf,
    capacity_path: PathBuf,
) -> Result<serde_json::Value, BoxErr> {
    require_namespace(&namespace)?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .authorize_gunshi_auto_dispatch(AuthorizeGunshiAutoDispatchRequest {
            namespace,
            plan_json: std::fs::read_to_string(plan_path)?,
            operation_json: std::fs::read_to_string(operation_path)?,
            capacity_json: std::fs::read_to_string(capacity_path)?,
        })
        .await?
        .into_inner();
    Ok(serde_json::json!({
        "authorization": serde_json::from_str::<serde_json::Value>(&response.authorization_json)?,
        "receipt_attributes": serde_json::from_str::<serde_json::Value>(&response.receipt_attributes_json)?,
    }))
}

pub async fn promote_feedback(
    namespace: String,
    suite_id: String,
    issuance_id: String,
    allocation_id: String,
) -> Result<serde_json::Value, BoxErr> {
    require_namespace(&namespace)?;
    let response = ChiseiServiceClient::new(connect_sekai(&gunshi_target()).await?)
        .promote_gunshi_feedback_to_eval(PromoteGunshiFeedbackToEvalRequest {
            namespace,
            suite_id,
            issuance_id,
            allocation_id,
        })
        .await?
        .into_inner();
    Ok(serde_json::from_str(&response.result_json)?)
}

pub fn scorecard_namespace(args: &[String]) -> Result<String, String> {
    if args.len() == 2 && args[0] == "--namespace" {
        let namespace = args[1].clone();
        if !namespace.trim().is_empty() && namespace.trim() == namespace {
            return Ok(namespace);
        }
    }
    Err("scorecard requires --namespace <name>".into())
}

fn require_namespace(namespace: &str) -> Result<(), BoxErr> {
    if namespace.trim().is_empty() || namespace.trim() != namespace {
        return Err(std::io::Error::other("namespace must be non-empty and canonical").into());
    }
    Ok(())
}

pub fn flag_value(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == flag {
            return Ok(Some(required_arg(args, index + 1, flag)?));
        }
        index += 1;
    }
    Ok(None)
}

pub fn require_flag(args: &[String], flag: &str) -> Result<String, String> {
    flag_value(args, flag)?.ok_or_else(|| format!("{flag} is required"))
}

fn gunshi_target() -> String {
    std::env::var("CHISEI_GRPC_URL")
        .or_else(|_| std::env::var("SEKAI_SOCKET"))
        .unwrap_or_else(|_| "./data/sekai.sock".into())
}

fn required_arg(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index)
        .filter(|value| !value.starts_with('-') && !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
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
        AdvisoryPolicy, AgentCapacity, AllocationRequest, BaselineStrategy, CapacityEnvelope,
        KiokuEvidence, ModelProfile, OperationRisk, PendingOperation, Strategy,
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
    fn feedback_parser_requires_two_inputs_and_an_operation() {
        let config = FeedbackConfig::from_args([
            "recommendations.json".into(),
            "choice.json".into(),
            "--operation".into(),
            "op-1".into(),
            "--outcome".into(),
            "outcome.json".into(),
        ])
        .unwrap();
        assert_eq!(config.operation_id, "op-1");
        assert_eq!(config.outcome, Some(PathBuf::from("outcome.json")));
        assert!(
            FeedbackConfig::from_args(["recommendations.json".into(), "choice.json".into(),])
                .is_err()
        );
    }

    #[test]
    fn scorecard_parser_requires_a_canonical_namespace() {
        assert_eq!(
            scorecard_namespace(&["--namespace".into(), "support".into()]).unwrap(),
            "support"
        );
        assert!(scorecard_namespace(&["--namespace".into(), " support ".into()]).is_err());
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
