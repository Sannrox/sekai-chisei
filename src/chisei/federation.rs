//! Portable governance artifacts and federation primitives.
//!
//! Federation exchanges policy and aggregate governance signal, never the
//! prompts, responses, graph objects, or per-observation records that produced
//! them. The portable envelope is deliberately deterministic so a receiver can
//! verify provenance and content before adopting an artifact.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};

use crate::chisei::eval::EvalStore;

pub const PORTABLE_ARTIFACT_SCHEMA: &str = "sekai.governance/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceArtifact {
    EvalSuite(PortableEvalSuite),
    RoutingPrior(PortableRoutingPrior),
    ActionPolicy(PortableActionPolicy),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableEvalSuite {
    pub name: String,
    pub description: String,
    /// Opaque test specifications only. Importers must reject content-bearing
    /// fields; concrete prompts and results remain local.
    pub cases: Vec<PortableEvalCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableEvalCase {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub assertion_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableRoutingPrior {
    pub task_class: String,
    pub model_capability: String,
    /// Basis points keep the canonical representation stable across runtimes.
    pub success_rate_bps: u16,
    pub sample_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableActionPolicy {
    pub scope_class: String,
    pub default_decision: String,
    pub action_overrides: BTreeMap<String, String>,
    pub risk_overrides: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    pub publisher_id: String,
    pub source_artifact_id: String,
    pub created_at: i64,
    pub parent_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableArtifact {
    pub schema: String,
    pub artifact_id: String,
    pub version: u64,
    pub provenance: ArtifactProvenance,
    pub artifact: GovernanceArtifact,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    Invalid(String),
    HashMismatch,
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "invalid governance artifact: {reason}"),
            Self::HashMismatch => write!(formatter, "governance artifact content hash mismatch"),
        }
    }
}

impl std::error::Error for ArtifactError {}

/// The only signal a participant may submit to federation. It contains a
/// bucketed outcome and count, not an observation, prompt, response, object id,
/// actor id, or provider credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedContribution {
    pub participant_id: String,
    pub contribution_id: String,
    pub task_class: String,
    pub model_capability: String,
    pub successes: u64,
    pub attempts: u64,
    pub source_artifact_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedPrior {
    pub task_class: String,
    pub model_capability: String,
    pub success_rate_bps: u16,
    pub sample_size: u64,
    pub participant_count: u64,
    pub source_hashes: Vec<String>,
}

/// Receipt retained by the coordinator. Participant identifiers are hashed so
/// a later audit can detect replay without publishing network membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionReceipt {
    pub contribution_id: String,
    pub participant_hash: String,
    pub accepted: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAdoptionStatus {
    PendingEvaluation,
    GatePassed,
    GateFailed,
    Promoted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelEvalEvidence {
    pub suite_id: String,
    pub baseline_run_id: String,
    pub candidate_run_id: String,
    pub baseline_score: f64,
    pub candidate_score: f64,
    pub allowed_regression: f64,
}

impl ModelEvalEvidence {
    pub fn passed(&self) -> bool {
        self.baseline_score.is_finite()
            && self.candidate_score.is_finite()
            && self.allowed_regression.is_finite()
            && self.allowed_regression >= 0.0
            && self.candidate_score + self.allowed_regression >= self.baseline_score
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelAdoption {
    pub candidate_id: String,
    pub model_id: String,
    pub required_suites: Vec<String>,
    pub evidence: BTreeMap<String, ModelEvalEvidence>,
    pub status: ModelAdoptionStatus,
    pub created_at: i64,
    pub promoted_at: Option<i64>,
}

/// Server-owned adoption state. Callers may submit eval evidence, but cannot
/// mark a candidate passed or promoted themselves.
pub struct ModelSovereigntyRegistry {
    active_model: Option<String>,
    adoptions: HashMap<String, ModelAdoption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactAdoption {
    pub local_namespace: String,
    pub artifact_id: String,
    pub version: u64,
    pub content_hash: String,
    pub adopted_at: i64,
}

/// Registry for exchanging verified governance artifacts. Publisher trust is
/// configured locally; publishing an envelope never grants its publisher trust.
pub struct GovernanceRegistry {
    trusted_publishers: HashSet<String>,
    artifacts: HashMap<String, Vec<PortableArtifact>>,
    adoptions: HashMap<(String, String), ArtifactAdoption>,
}

impl GovernanceRegistry {
    pub fn new(trusted_publishers: impl IntoIterator<Item = String>) -> Self {
        Self {
            trusted_publishers: trusted_publishers.into_iter().collect(),
            artifacts: HashMap::new(),
            adoptions: HashMap::new(),
        }
    }

    pub fn publish(&mut self, artifact: PortableArtifact) -> Result<(), ArtifactError> {
        artifact.verify()?;
        if !self
            .trusted_publishers
            .contains(&artifact.provenance.publisher_id)
        {
            return Err(ArtifactError::Invalid(format!(
                "publisher {:?} is not trusted",
                artifact.provenance.publisher_id
            )));
        }

        let versions = self
            .artifacts
            .entry(artifact.artifact_id.clone())
            .or_default();
        if let Some(existing) = versions
            .iter()
            .find(|existing| existing.version == artifact.version)
        {
            return if existing.content_hash == artifact.content_hash {
                Ok(())
            } else {
                Err(ArtifactError::Invalid(format!(
                    "artifact {:?} version {} already has different content",
                    artifact.artifact_id, artifact.version
                )))
            };
        }

        match versions.last() {
            None => {
                if artifact.version != 1 || artifact.provenance.parent_hash.is_some() {
                    return Err(ArtifactError::Invalid(
                        "the first published version must be version 1 without a parent".into(),
                    ));
                }
            }
            Some(previous) => {
                if artifact.version != previous.version + 1 {
                    return Err(ArtifactError::Invalid(format!(
                        "artifact version must follow version {}",
                        previous.version
                    )));
                }
                if artifact.provenance.parent_hash.as_deref()
                    != Some(previous.content_hash.as_str())
                {
                    return Err(ArtifactError::Invalid(
                        "artifact parent hash does not match the prior version".into(),
                    ));
                }
            }
        }
        versions.push(artifact);
        Ok(())
    }

    pub fn latest(&self, artifact_id: &str) -> Option<&PortableArtifact> {
        self.artifacts.get(artifact_id)?.last()
    }

    pub fn list_latest(&self) -> Vec<&PortableArtifact> {
        let mut artifacts = self
            .artifacts
            .values()
            .filter_map(|versions| versions.last())
            .collect::<Vec<_>>();
        artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        artifacts
    }

    pub fn adopt(
        &mut self,
        local_namespace: impl Into<String>,
        artifact_id: &str,
        version: u64,
        adopted_at: i64,
    ) -> Result<ArtifactAdoption, ArtifactError> {
        let local_namespace = local_namespace.into();
        require_nonempty("local_namespace", &local_namespace)?;
        let artifact = self
            .artifacts
            .get(artifact_id)
            .and_then(|versions| versions.iter().find(|item| item.version == version))
            .ok_or_else(|| {
                ArtifactError::Invalid(format!(
                    "artifact {artifact_id:?} version {version} is not published"
                ))
            })?;
        artifact.verify()?;
        let adoption = ArtifactAdoption {
            local_namespace: local_namespace.clone(),
            artifact_id: artifact_id.to_string(),
            version,
            content_hash: artifact.content_hash.clone(),
            adopted_at,
        };
        self.adoptions
            .insert((local_namespace, artifact_id.to_string()), adoption.clone());
        Ok(adoption)
    }

    pub fn adoption(&self, local_namespace: &str, artifact_id: &str) -> Option<&ArtifactAdoption> {
        self.adoptions
            .get(&(local_namespace.to_string(), artifact_id.to_string()))
    }
}

impl Default for ModelSovereigntyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelSovereigntyRegistry {
    pub fn new() -> Self {
        Self {
            active_model: None,
            adoptions: HashMap::new(),
        }
    }

    pub fn active_model(&self) -> Option<&str> {
        self.active_model.as_deref()
    }

    pub fn begin_adoption(
        &mut self,
        candidate_id: impl Into<String>,
        model_id: impl Into<String>,
        mut required_suites: Vec<String>,
        created_at: i64,
    ) -> Result<ModelAdoption, ArtifactError> {
        let candidate_id = candidate_id.into();
        let model_id = model_id.into();
        require_nonempty("candidate_id", &candidate_id)?;
        require_nonempty("model_id", &model_id)?;
        required_suites.sort();
        required_suites.dedup();
        if required_suites.is_empty() || required_suites.iter().any(|suite| suite.trim().is_empty())
        {
            return Err(ArtifactError::Invalid(
                "model adoption requires at least one named eval suite".into(),
            ));
        }
        if self.adoptions.contains_key(&candidate_id) {
            return Err(ArtifactError::Invalid(format!(
                "model candidate {candidate_id:?} already exists"
            )));
        }
        let adoption = ModelAdoption {
            candidate_id: candidate_id.clone(),
            model_id,
            required_suites,
            evidence: BTreeMap::new(),
            status: ModelAdoptionStatus::PendingEvaluation,
            created_at,
            promoted_at: None,
        };
        self.adoptions.insert(candidate_id, adoption.clone());
        Ok(adoption)
    }

    pub fn record_eval_from_store(
        &mut self,
        eval: &EvalStore,
        candidate_id: &str,
        suite_id: &str,
        baseline_run_id: &str,
        candidate_run_id: &str,
        allowed_regression: f64,
    ) -> Result<ModelAdoption, ArtifactError> {
        let adoption = self.adoptions.get(candidate_id).ok_or_else(|| {
            ArtifactError::Invalid(format!("unknown model candidate {candidate_id:?}"))
        })?;
        let baseline = eval.get_run(baseline_run_id).ok_or_else(|| {
            ArtifactError::Invalid(format!("unknown baseline eval run {baseline_run_id:?}"))
        })?;
        let candidate = eval.get_run(candidate_run_id).ok_or_else(|| {
            ArtifactError::Invalid(format!("unknown candidate eval run {candidate_run_id:?}"))
        })?;
        if baseline.suite_id != suite_id || candidate.suite_id != suite_id {
            return Err(ArtifactError::Invalid(
                "eval runs must belong to the required suite".into(),
            ));
        }
        if candidate.config_ref != adoption.model_id {
            return Err(ArtifactError::Invalid(format!(
                "candidate eval run targets {:?}, not adoption model {:?}",
                candidate.config_ref, adoption.model_id
            )));
        }
        let comparison = eval
            .compare_runs(baseline_run_id, candidate_run_id)
            .ok_or_else(|| ArtifactError::Invalid("eval runs cannot be compared".into()))?;
        self.record_eval(
            candidate_id,
            ModelEvalEvidence {
                suite_id: suite_id.to_string(),
                baseline_run_id: baseline_run_id.to_string(),
                candidate_run_id: candidate_run_id.to_string(),
                baseline_score: comparison.baseline_score,
                candidate_score: comparison.candidate_score,
                allowed_regression,
            },
        )
    }

    fn record_eval(
        &mut self,
        candidate_id: &str,
        evidence: ModelEvalEvidence,
    ) -> Result<ModelAdoption, ArtifactError> {
        validate_eval_evidence(&evidence)?;
        let adoption = self.adoptions.get_mut(candidate_id).ok_or_else(|| {
            ArtifactError::Invalid(format!("unknown model candidate {candidate_id:?}"))
        })?;
        if adoption.status != ModelAdoptionStatus::PendingEvaluation {
            return Err(ArtifactError::Invalid(
                "eval evidence cannot change after the gate is decided".into(),
            ));
        }
        if !adoption.required_suites.contains(&evidence.suite_id) {
            return Err(ArtifactError::Invalid(format!(
                "eval suite {:?} is not required by this adoption",
                evidence.suite_id
            )));
        }
        if adoption.evidence.contains_key(&evidence.suite_id) {
            return Err(ArtifactError::Invalid(format!(
                "eval suite {:?} already recorded",
                evidence.suite_id
            )));
        }
        let passed = evidence.passed();
        adoption
            .evidence
            .insert(evidence.suite_id.clone(), evidence);
        if !passed {
            adoption.status = ModelAdoptionStatus::GateFailed;
        } else if adoption.evidence.len() == adoption.required_suites.len() {
            adoption.status = ModelAdoptionStatus::GatePassed;
        }
        Ok(adoption.clone())
    }

    pub fn promote(
        &mut self,
        candidate_id: &str,
        promoted_at: i64,
    ) -> Result<ModelAdoption, ArtifactError> {
        let adoption = self.adoptions.get_mut(candidate_id).ok_or_else(|| {
            ArtifactError::Invalid(format!("unknown model candidate {candidate_id:?}"))
        })?;
        if adoption.status != ModelAdoptionStatus::GatePassed {
            return Err(ArtifactError::Invalid(
                "only an eval-gated model candidate can be promoted".into(),
            ));
        }
        adoption.status = ModelAdoptionStatus::Promoted;
        adoption.promoted_at = Some(promoted_at);
        self.active_model = Some(adoption.model_id.clone());
        Ok(adoption.clone())
    }

    pub fn get(&self, candidate_id: &str) -> Option<&ModelAdoption> {
        self.adoptions.get(candidate_id)
    }
}

fn validate_eval_evidence(evidence: &ModelEvalEvidence) -> Result<(), ArtifactError> {
    require_nonempty("suite_id", &evidence.suite_id)?;
    require_nonempty("baseline_run_id", &evidence.baseline_run_id)?;
    require_nonempty("candidate_run_id", &evidence.candidate_run_id)?;
    if evidence.baseline_run_id == evidence.candidate_run_id {
        return Err(ArtifactError::Invalid(
            "baseline and candidate eval runs must differ".into(),
        ));
    }
    if !evidence.baseline_score.is_finite()
        || !evidence.candidate_score.is_finite()
        || !evidence.allowed_regression.is_finite()
        || evidence.allowed_regression < 0.0
    {
        return Err(ArtifactError::Invalid(
            "eval scores and allowed regression must be finite and non-negative".into(),
        ));
    }
    Ok(())
}

/// Aggregates governance signal with a minimum-participant disclosure gate.
/// No method exposes individual contributions after ingestion.
pub struct FederationAggregator {
    minimum_participants: usize,
    seen_contributions: HashSet<String>,
    buckets: HashMap<(String, String), AggregateBucket>,
    receipts: Vec<ContributionReceipt>,
}

#[derive(Default)]
struct AggregateBucket {
    successes: u64,
    attempts: u64,
    participants: HashSet<String>,
    source_hashes: HashSet<String>,
}

impl FederationAggregator {
    pub fn new(minimum_participants: usize) -> Result<Self, ArtifactError> {
        if minimum_participants < 2 {
            return Err(ArtifactError::Invalid(
                "federation requires at least two participants per published bucket".into(),
            ));
        }
        Ok(Self {
            minimum_participants,
            seen_contributions: HashSet::new(),
            buckets: HashMap::new(),
            receipts: Vec::new(),
        })
    }

    pub fn ingest(
        &mut self,
        contribution: FederatedContribution,
    ) -> Result<ContributionReceipt, ArtifactError> {
        validate_contribution(&contribution)?;
        let participant_hash = opaque_hash(&contribution.participant_id);
        if self
            .seen_contributions
            .contains(&contribution.contribution_id)
        {
            let receipt = ContributionReceipt {
                contribution_id: contribution.contribution_id,
                participant_hash,
                accepted: false,
                reason: "duplicate contribution".into(),
            };
            self.receipts.push(receipt.clone());
            return Ok(receipt);
        }

        let bucket = self
            .buckets
            .entry((
                contribution.task_class.clone(),
                contribution.model_capability.clone(),
            ))
            .or_default();
        if bucket.participants.contains(&participant_hash) {
            self.seen_contributions
                .insert(contribution.contribution_id.clone());
            let receipt = ContributionReceipt {
                contribution_id: contribution.contribution_id,
                participant_hash,
                accepted: false,
                reason: "participant already contributed to this bucket".into(),
            };
            self.receipts.push(receipt.clone());
            return Ok(receipt);
        }
        let successes = bucket
            .successes
            .checked_add(contribution.successes)
            .ok_or_else(|| ArtifactError::Invalid("success count overflow".into()))?;
        let attempts = bucket
            .attempts
            .checked_add(contribution.attempts)
            .ok_or_else(|| ArtifactError::Invalid("attempt count overflow".into()))?;
        self.seen_contributions
            .insert(contribution.contribution_id.clone());
        bucket.successes = successes;
        bucket.attempts = attempts;
        bucket.participants.insert(participant_hash.clone());
        bucket
            .source_hashes
            .insert(contribution.source_artifact_hash);

        let receipt = ContributionReceipt {
            contribution_id: contribution.contribution_id,
            participant_hash,
            accepted: true,
            reason: "aggregate governance signal accepted".into(),
        };
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    pub fn publishable_priors(&self) -> Vec<FederatedPrior> {
        let mut priors = self
            .buckets
            .iter()
            .filter(|(_, bucket)| bucket.participants.len() >= self.minimum_participants)
            .map(|((task_class, model_capability), bucket)| {
                let mut source_hashes = bucket.source_hashes.iter().cloned().collect::<Vec<_>>();
                source_hashes.sort();
                FederatedPrior {
                    task_class: task_class.clone(),
                    model_capability: model_capability.clone(),
                    success_rate_bps: ((u128::from(bucket.successes) * 10_000)
                        / u128::from(bucket.attempts)) as u16,
                    sample_size: bucket.attempts,
                    participant_count: bucket.participants.len() as u64,
                    source_hashes,
                }
            })
            .collect::<Vec<_>>();
        priors.sort_by(|left, right| {
            left.task_class
                .cmp(&right.task_class)
                .then_with(|| left.model_capability.cmp(&right.model_capability))
        });
        priors
    }

    pub fn receipts(&self) -> &[ContributionReceipt] {
        &self.receipts
    }
}

fn validate_contribution(contribution: &FederatedContribution) -> Result<(), ArtifactError> {
    require_nonempty("participant_id", &contribution.participant_id)?;
    require_nonempty("contribution_id", &contribution.contribution_id)?;
    require_nonempty("task_class", &contribution.task_class)?;
    require_nonempty("model_capability", &contribution.model_capability)?;
    require_sha256("source_artifact_hash", &contribution.source_artifact_hash)?;
    if contribution.attempts == 0 {
        return Err(ArtifactError::Invalid("attempts must be positive".into()));
    }
    if contribution.successes > contribution.attempts {
        return Err(ArtifactError::Invalid(
            "successes must not exceed attempts".into(),
        ));
    }
    Ok(())
}

fn require_sha256(field: &str, value: &str) -> Result<(), ArtifactError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ArtifactError::Invalid(format!(
            "{field} must be a SHA-256 hex digest"
        )))
    }
}

fn opaque_hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

impl PortableArtifact {
    pub fn new(
        artifact_id: impl Into<String>,
        version: u64,
        provenance: ArtifactProvenance,
        artifact: GovernanceArtifact,
    ) -> Result<Self, ArtifactError> {
        let mut envelope = Self {
            schema: PORTABLE_ARTIFACT_SCHEMA.into(),
            artifact_id: artifact_id.into(),
            version,
            provenance,
            artifact,
            content_hash: String::new(),
        };
        envelope.validate_fields()?;
        envelope.content_hash = envelope.calculate_hash()?;
        Ok(envelope)
    }

    pub fn verify(&self) -> Result<(), ArtifactError> {
        self.validate_fields()?;
        if self.calculate_hash()? != self.content_hash {
            return Err(ArtifactError::HashMismatch);
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), ArtifactError> {
        require_nonempty("artifact_id", &self.artifact_id)?;
        require_nonempty("publisher_id", &self.provenance.publisher_id)?;
        require_nonempty("source_artifact_id", &self.provenance.source_artifact_id)?;
        if self.schema != PORTABLE_ARTIFACT_SCHEMA {
            return Err(ArtifactError::Invalid(format!(
                "unsupported schema {:?}",
                self.schema
            )));
        }
        if self.version == 0 {
            return Err(ArtifactError::Invalid("version must be positive".into()));
        }
        match &self.artifact {
            GovernanceArtifact::EvalSuite(suite) => {
                require_nonempty("eval suite name", &suite.name)?;
                if suite.cases.is_empty() {
                    return Err(ArtifactError::Invalid(
                        "eval suite must contain at least one case".into(),
                    ));
                }
                for case in &suite.cases {
                    require_nonempty("eval case id", &case.id)?;
                    require_nonempty("eval case namespace", &case.namespace)?;
                    if case.assertion_types.is_empty() {
                        return Err(ArtifactError::Invalid(format!(
                            "eval case {:?} has no assertion types",
                            case.id
                        )));
                    }
                }
            }
            GovernanceArtifact::RoutingPrior(prior) => {
                require_nonempty("task_class", &prior.task_class)?;
                require_nonempty("model_capability", &prior.model_capability)?;
                if prior.success_rate_bps > 10_000 {
                    return Err(ArtifactError::Invalid(
                        "success_rate_bps exceeds 10000".into(),
                    ));
                }
                if prior.sample_size == 0 {
                    return Err(ArtifactError::Invalid(
                        "sample_size must be positive".into(),
                    ));
                }
            }
            GovernanceArtifact::ActionPolicy(policy) => {
                require_nonempty("scope_class", &policy.scope_class)?;
                validate_decision(&policy.default_decision)?;
                for decision in policy
                    .action_overrides
                    .values()
                    .chain(policy.risk_overrides.values())
                {
                    validate_decision(decision)?;
                }
            }
        }
        Ok(())
    }

    fn calculate_hash(&self) -> Result<String, ArtifactError> {
        #[derive(Serialize)]
        struct HashInput<'a> {
            schema: &'a str,
            artifact_id: &'a str,
            version: u64,
            provenance: &'a ArtifactProvenance,
            artifact: &'a GovernanceArtifact,
        }
        let bytes = serde_json::to_vec(&HashInput {
            schema: &self.schema,
            artifact_id: &self.artifact_id,
            version: self.version,
            provenance: &self.provenance,
            artifact: &self.artifact,
        })
        .map_err(|error| ArtifactError::Invalid(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ArtifactError> {
    if value.trim().is_empty() {
        Err(ArtifactError::Invalid(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn validate_decision(value: &str) -> Result<(), ArtifactError> {
    match value {
        "allow" | "deny" | "require_approval" => Ok(()),
        _ => Err(ArtifactError::Invalid(format!(
            "unsupported action decision {value:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> ArtifactProvenance {
        ArtifactProvenance {
            publisher_id: "org.example".into(),
            source_artifact_id: "suite-local-1".into(),
            created_at: 1_700_000_000,
            parent_hash: None,
        }
    }

    fn suite() -> GovernanceArtifact {
        GovernanceArtifact::EvalSuite(PortableEvalSuite {
            name: "safe refactoring".into(),
            description: "Checks behavior-preserving edits".into(),
            cases: vec![PortableEvalCase {
                id: "compile".into(),
                name: "compiles".into(),
                namespace: "rust".into(),
                assertion_types: vec!["exit_code".into()],
            }],
        })
    }

    #[test]
    fn portable_artifact_round_trips_and_verifies() {
        let artifact =
            PortableArtifact::new("eval-safe-refactor", 1, provenance(), suite()).unwrap();
        let encoded = serde_json::to_string(&artifact).unwrap();
        let decoded: PortableArtifact = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, artifact);
        decoded.verify().unwrap();
    }

    #[test]
    fn changed_artifact_fails_hash_verification() {
        let mut artifact =
            PortableArtifact::new("eval-safe-refactor", 1, provenance(), suite()).unwrap();
        let GovernanceArtifact::EvalSuite(suite) = &mut artifact.artifact else {
            panic!("expected eval suite");
        };
        suite.name = "tampered".into();

        assert_eq!(artifact.verify(), Err(ArtifactError::HashMismatch));
    }

    #[test]
    fn routing_prior_requires_aggregate_evidence() {
        let error = PortableArtifact::new(
            "routing-rust-capable",
            1,
            provenance(),
            GovernanceArtifact::RoutingPrior(PortableRoutingPrior {
                task_class: "rust".into(),
                model_capability: "capable".into(),
                success_rate_bps: 9_000,
                sample_size: 0,
            }),
        )
        .unwrap_err();

        assert_eq!(
            error,
            ArtifactError::Invalid("sample_size must be positive".into())
        );
    }

    fn contribution(
        participant: &str,
        contribution_id: &str,
        successes: u64,
        attempts: u64,
    ) -> FederatedContribution {
        FederatedContribution {
            participant_id: participant.into(),
            contribution_id: contribution_id.into(),
            task_class: "rust-refactor".into(),
            model_capability: "capable".into(),
            successes,
            attempts,
            source_artifact_hash: "a".repeat(64),
        }
    }

    #[test]
    fn federation_publishes_only_after_disclosure_threshold() {
        let mut aggregator = FederationAggregator::new(2).unwrap();
        aggregator
            .ingest(contribution("org-a", "one", 8, 10))
            .unwrap();
        assert!(aggregator.publishable_priors().is_empty());

        aggregator
            .ingest(contribution("org-b", "two", 9, 10))
            .unwrap();
        assert_eq!(
            aggregator.publishable_priors(),
            vec![FederatedPrior {
                task_class: "rust-refactor".into(),
                model_capability: "capable".into(),
                success_rate_bps: 8_500,
                sample_size: 20,
                participant_count: 2,
                source_hashes: vec!["a".repeat(64)],
            }]
        );
    }

    #[test]
    fn federation_rejects_replay_without_double_counting() {
        let mut aggregator = FederationAggregator::new(2).unwrap();
        let first = contribution("org-a", "same", 8, 10);
        assert!(aggregator.ingest(first.clone()).unwrap().accepted);
        assert!(!aggregator.ingest(first).unwrap().accepted);
        aggregator
            .ingest(contribution("org-b", "other", 10, 10))
            .unwrap();

        assert_eq!(aggregator.publishable_priors()[0].sample_size, 20);
        assert_ne!(aggregator.receipts()[0].participant_hash, "org-a");
    }

    #[test]
    fn federation_accepts_one_contribution_per_participant_bucket() {
        let mut aggregator = FederationAggregator::new(2).unwrap();
        assert!(
            aggregator
                .ingest(contribution("org-a", "one", 8, 10))
                .unwrap()
                .accepted
        );
        assert!(
            !aggregator
                .ingest(contribution("org-a", "two", 10, 10))
                .unwrap()
                .accepted
        );
        aggregator
            .ingest(contribution("org-b", "three", 10, 10))
            .unwrap();

        let prior = &aggregator.publishable_priors()[0];
        assert_eq!(prior.sample_size, 20);
        assert_eq!(prior.success_rate_bps, 9_000);
    }

    #[test]
    fn federation_rejects_non_aggregate_or_unproven_signal() {
        let mut aggregator = FederationAggregator::new(2).unwrap();
        let mut invalid = contribution("org-a", "one", 2, 1);
        assert!(aggregator.ingest(invalid.clone()).is_err());
        invalid.successes = 1;
        invalid.source_artifact_hash = "not-a-hash".into();
        assert!(aggregator.ingest(invalid).is_err());
    }

    fn passing_evidence(suite_id: &str) -> ModelEvalEvidence {
        ModelEvalEvidence {
            suite_id: suite_id.into(),
            baseline_run_id: format!("{suite_id}-baseline"),
            candidate_run_id: format!("{suite_id}-candidate"),
            baseline_score: 0.90,
            candidate_score: 0.91,
            allowed_regression: 0.01,
        }
    }

    #[test]
    fn model_promotion_requires_every_eval_suite() {
        let mut registry = ModelSovereigntyRegistry::new();
        registry
            .begin_adoption(
                "candidate-1",
                "provider/new-model",
                vec!["quality".into(), "security".into()],
                100,
            )
            .unwrap();

        registry
            .record_eval("candidate-1", passing_evidence("quality"))
            .unwrap();
        assert!(registry.promote("candidate-1", 200).is_err());
        registry
            .record_eval("candidate-1", passing_evidence("security"))
            .unwrap();
        let promoted = registry.promote("candidate-1", 200).unwrap();

        assert_eq!(promoted.status, ModelAdoptionStatus::Promoted);
        assert_eq!(registry.active_model(), Some("provider/new-model"));
    }

    #[test]
    fn regressing_model_is_permanently_gate_failed() {
        let mut registry = ModelSovereigntyRegistry::new();
        registry
            .begin_adoption("candidate-1", "new-model", vec!["quality".into()], 100)
            .unwrap();
        let mut evidence = passing_evidence("quality");
        evidence.candidate_score = 0.5;
        let failed = registry.record_eval("candidate-1", evidence).unwrap();

        assert_eq!(failed.status, ModelAdoptionStatus::GateFailed);
        assert!(registry.promote("candidate-1", 200).is_err());
        assert!(
            registry
                .record_eval("candidate-1", passing_evidence("quality"))
                .is_err()
        );
    }

    #[test]
    fn caller_cannot_submit_unrequired_or_reused_eval_run() {
        let mut registry = ModelSovereigntyRegistry::new();
        registry
            .begin_adoption("candidate-1", "new-model", vec!["quality".into()], 100)
            .unwrap();
        assert!(
            registry
                .record_eval("candidate-1", passing_evidence("other"))
                .is_err()
        );
        let mut evidence = passing_evidence("quality");
        evidence.candidate_run_id = evidence.baseline_run_id.clone();
        assert!(registry.record_eval("candidate-1", evidence).is_err());
    }

    #[test]
    fn model_gate_derives_scores_from_server_owned_eval_runs() {
        use crate::chisei::eval::{CaseResult, Run};

        let eval = EvalStore::new();
        let result = |case_id: &str, passed: bool| CaseResult {
            case_id: case_id.into(),
            passed,
            status: String::new(),
            result: String::new(),
            score: if passed { 100 } else { 0 },
            reason: String::new(),
            elapsed: 0,
        };
        eval.create_run(Run {
            id: "baseline".into(),
            suite_id: "quality".into(),
            config_ref: "old-model".into(),
            results: vec![result("one", true), result("two", false)],
            timestamp: 1,
        });
        eval.create_run(Run {
            id: "candidate".into(),
            suite_id: "quality".into(),
            config_ref: "new-model".into(),
            results: vec![result("one", true), result("two", true)],
            timestamp: 2,
        });
        let mut registry = ModelSovereigntyRegistry::new();
        registry
            .begin_adoption("candidate-1", "new-model", vec!["quality".into()], 100)
            .unwrap();

        let adoption = registry
            .record_eval_from_store(
                &eval,
                "candidate-1",
                "quality",
                "baseline",
                "candidate",
                0.0,
            )
            .unwrap();
        assert_eq!(adoption.status, ModelAdoptionStatus::GatePassed);
    }

    #[test]
    fn registry_enforces_trust_and_version_lineage() {
        let mut registry = GovernanceRegistry::new(vec!["org.example".into()]);
        let first = PortableArtifact::new("eval-safe-refactor", 1, provenance(), suite()).unwrap();
        registry.publish(first.clone()).unwrap();

        let mut second_provenance = provenance();
        second_provenance.parent_hash = Some(first.content_hash.clone());
        let second =
            PortableArtifact::new("eval-safe-refactor", 2, second_provenance, suite()).unwrap();
        registry.publish(second.clone()).unwrap();
        assert_eq!(registry.latest("eval-safe-refactor"), Some(&second));

        let mut untrusted_provenance = provenance();
        untrusted_provenance.publisher_id = "unknown.example".into();
        let untrusted = PortableArtifact::new("other", 1, untrusted_provenance, suite()).unwrap();
        assert!(registry.publish(untrusted).is_err());
    }

    #[test]
    fn registry_rejects_forks_and_conflicting_versions() {
        let mut registry = GovernanceRegistry::new(vec!["org.example".into()]);
        let first = PortableArtifact::new("eval-safe-refactor", 1, provenance(), suite()).unwrap();
        registry.publish(first.clone()).unwrap();

        let conflict = PortableArtifact::new(
            "eval-safe-refactor",
            1,
            provenance(),
            GovernanceArtifact::EvalSuite(PortableEvalSuite {
                name: "different".into(),
                description: String::new(),
                cases: vec![PortableEvalCase {
                    id: "case".into(),
                    name: "case".into(),
                    namespace: "rust".into(),
                    assertion_types: vec!["exit_code".into()],
                }],
            }),
        )
        .unwrap();
        assert!(registry.publish(conflict).is_err());

        let mut wrong_parent = provenance();
        wrong_parent.parent_hash = Some("b".repeat(64));
        let fork = PortableArtifact::new("eval-safe-refactor", 2, wrong_parent, suite()).unwrap();
        assert!(registry.publish(fork).is_err());
    }

    #[test]
    fn adoption_pins_an_exact_verified_version() {
        let mut registry = GovernanceRegistry::new(vec!["org.example".into()]);
        let artifact =
            PortableArtifact::new("eval-safe-refactor", 1, provenance(), suite()).unwrap();
        registry.publish(artifact.clone()).unwrap();
        let adoption = registry
            .adopt("local-team", "eval-safe-refactor", 1, 200)
            .unwrap();

        assert_eq!(adoption.content_hash, artifact.content_hash);
        assert_eq!(
            registry.adoption("local-team", "eval-safe-refactor"),
            Some(&adoption)
        );
        assert!(
            registry
                .adopt("local-team", "eval-safe-refactor", 2, 201)
                .is_err()
        );
    }
}
