//! Portable governance artifacts and federation primitives.
//!
//! Federation exchanges policy and aggregate governance signal, never the
//! prompts, responses, graph objects, or per-observation records that produced
//! them. The portable envelope is deliberately deterministic so a receiver can
//! verify provenance and content before adopting an artifact.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
}
