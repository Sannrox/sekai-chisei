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
        if !self
            .seen_contributions
            .insert(contribution.contribution_id.clone())
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
            .entry((contribution.task_class, contribution.model_capability))
            .or_default();
        let successes = bucket
            .successes
            .checked_add(contribution.successes)
            .ok_or_else(|| ArtifactError::Invalid("success count overflow".into()))?;
        let attempts = bucket
            .attempts
            .checked_add(contribution.attempts)
            .ok_or_else(|| ArtifactError::Invalid("attempt count overflow".into()))?;
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
    fn federation_rejects_non_aggregate_or_unproven_signal() {
        let mut aggregator = FederationAggregator::new(2).unwrap();
        let mut invalid = contribution("org-a", "one", 2, 1);
        assert!(aggregator.ingest(invalid.clone()).is_err());
        invalid.successes = 1;
        invalid.source_artifact_hash = "not-a-hash".into();
        assert!(aggregator.ingest(invalid).is_err());
    }
}
