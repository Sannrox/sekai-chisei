//! Model version references (#3020).
//!
//! The plane holds a reference to a trained model, never its bytes: the
//! digest, the adapter that loads it, where the registry keeps it, and the
//! lineage and markings it inherits from the run that trained it. A registry
//! adapter outside the plane (ADR 0147) stores the bytes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MODEL_VERSION_NOT_FOUND: &str = "model version not found";

/// One column of a tabular model input or output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelColumn {
    pub name: String,
    pub col_type: String,
}

/// A named tabular input the adapter's `predict` reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInput {
    pub name: String,
    pub columns: Vec<ModelColumn>,
}

/// What the plane sees of a model adapter: named tabular inputs and one
/// tabular output. `predict`, `save` and `load` live in the adapter itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterContract {
    pub inputs: Vec<ModelInput>,
    pub output: Vec<ModelColumn>,
}

impl AdapterContract {
    /// Refuses a contract with no inputs or output, a blank or repeated
    /// input name, or a blank or repeated column within one table.
    pub fn validate(&self) -> Result<(), String> {
        if self.inputs.is_empty() {
            return Err("adapter contract needs at least one input".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for input in &self.inputs {
            if input.name.trim().is_empty() {
                return Err("adapter contract input name is required".into());
            }
            if !names.insert(input.name.as_str()) {
                return Err(format!("adapter contract repeats input {}", input.name));
            }
            validate_columns(&format!("input {}", input.name), &input.columns)?;
        }
        validate_columns("output", &self.output)
    }
}

fn validate_columns(table: &str, columns: &[ModelColumn]) -> Result<(), String> {
    if columns.is_empty() {
        return Err(format!(
            "adapter contract {table} needs at least one column"
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for column in columns {
        if column.name.trim().is_empty() || column.col_type.trim().is_empty() {
            return Err(format!(
                "adapter contract {table} column needs a name and type"
            ));
        }
        if !names.insert(column.name.as_str()) {
            return Err(format!(
                "adapter contract {table} repeats column {}",
                column.name
            ));
        }
    }
    Ok(())
}

/// What a caller supplies to register a model version. Markings and training
/// inputs are not supplied: they come from the producing run's receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelVersionRegistration {
    pub namespace: String,
    pub model_name: String,
    pub digest: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub registry_locator: String,
    pub contract: AdapterContract,
    pub run_id: String,
    pub actor: String,
}

impl ModelVersionRegistration {
    pub fn validate(&self) -> Result<(), String> {
        for (field, value) in [
            ("namespace", &self.namespace),
            ("model_name", &self.model_name),
            ("digest", &self.digest),
            ("adapter_id", &self.adapter_id),
            ("adapter_version", &self.adapter_version),
            ("registry_locator", &self.registry_locator),
            ("run_id", &self.run_id),
        ] {
            if value.trim().is_empty() {
                return Err(format!("model version {field} is required"));
            }
        }
        self.contract.validate()
    }
}

/// A training dataset version the model was fitted on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingInput {
    pub dataset_id: String,
    pub version_id: String,
}

/// A registered model version. Its lineage edges are `run_id` (the run
/// receipt that trained it) and `training_inputs`; `marking` is that run's
/// output marking, the most restrictive of the training inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelVersion {
    pub version_id: String,
    pub namespace: String,
    pub model_name: String,
    pub digest: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub registry_locator: String,
    pub contract: AdapterContract,
    /// Classification token, empty when every training input is unmarked.
    pub marking: String,
    pub run_id: String,
    pub training_inputs: Vec<TrainingInput>,
    pub actor: String,
    pub created_at_ms: i64,
}

impl ModelVersion {
    /// Builds the record from a registration and the producing run's
    /// receipt fields: its namespace, output marking and pinned inputs.
    pub fn from_run(
        registration: ModelVersionRegistration,
        run_namespace: &str,
        run_marking: &str,
        run_inputs: &BTreeMap<String, String>,
        created_at_ms: i64,
    ) -> Result<Self, String> {
        registration.validate()?;
        if run_namespace != registration.namespace {
            return Err("model version run belongs to another namespace".into());
        }
        Ok(Self {
            version_id: model_version_id(
                &registration.namespace,
                &registration.model_name,
                &registration.digest,
            ),
            marking: run_marking.trim().to_string(),
            training_inputs: run_inputs
                .iter()
                .map(|(dataset_id, version_id)| TrainingInput {
                    dataset_id: dataset_id.clone(),
                    version_id: version_id.clone(),
                })
                .collect(),
            namespace: registration.namespace,
            model_name: registration.model_name,
            digest: registration.digest,
            adapter_id: registration.adapter_id,
            adapter_version: registration.adapter_version,
            registry_locator: registration.registry_locator,
            contract: registration.contract,
            run_id: registration.run_id,
            actor: registration.actor,
            created_at_ms,
        })
    }
}

/// The version id is a function of what the model is, so registering the
/// same digest again names the same version.
pub fn model_version_id(namespace: &str, model_name: &str, digest: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [namespace, model_name, digest] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("mv_{}", &hex_digest(&hasher.finalize())[..32])
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn column(name: &str) -> ModelColumn {
        ModelColumn {
            name: name.into(),
            col_type: "float".into(),
        }
    }

    fn registration() -> ModelVersionRegistration {
        ModelVersionRegistration {
            namespace: "ml".into(),
            model_name: "churn".into(),
            digest: "sha256:abc".into(),
            adapter_id: "tabular-classifier".into(),
            adapter_version: "1".into(),
            registry_locator: "churn/abc".into(),
            contract: AdapterContract {
                inputs: vec![ModelInput {
                    name: "features".into(),
                    columns: vec![column("tenure")],
                }],
                output: vec![column("score")],
            },
            run_id: "run-1".into(),
            actor: "trainer".into(),
        }
    }

    #[test]
    fn version_takes_marking_and_inputs_from_the_run() {
        let inputs = BTreeMap::from([("customers".to_string(), "v7".to_string())]);
        let version = ModelVersion::from_run(registration(), "ml", "secret", &inputs, 1).unwrap();
        assert_eq!(version.marking, "secret");
        assert_eq!(
            version.training_inputs,
            vec![TrainingInput {
                dataset_id: "customers".into(),
                version_id: "v7".into(),
            }]
        );
        assert_eq!(
            version.version_id,
            model_version_id("ml", "churn", "sha256:abc")
        );
    }

    #[test]
    fn version_refuses_a_run_from_another_namespace() {
        let error =
            ModelVersion::from_run(registration(), "other", "", &BTreeMap::new(), 1).unwrap_err();
        assert!(error.contains("another namespace"), "{error}");
    }

    #[test]
    fn contract_refuses_repeated_inputs_and_empty_output() {
        let mut repeated = registration().contract;
        repeated.inputs.push(repeated.inputs[0].clone());
        assert!(repeated.validate().is_err());
        let mut no_output = registration().contract;
        no_output.output.clear();
        assert!(no_output.validate().is_err());
    }
}
