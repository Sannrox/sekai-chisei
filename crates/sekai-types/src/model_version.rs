//! Model version references (#3020).
//!
//! The plane holds a reference to a trained model, never its bytes: the
//! digest, the adapter that loads it, where the registry keeps it, and the
//! lineage and markings it inherits from the run that trained it. A registry
//! adapter outside the plane (ADR 0147) stores the bytes.

use crate::governed_transform::{
    CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, MODEL_PIN_PREFIX, TransformSchedule,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

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

/// A model a transform run trained, as its runner reports it on write-back
/// (#3021). The runner stores the bytes in the registry first; the plane
/// fills the namespace, run, actor, markings and training inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelOutputWrite {
    pub model_name: String,
    pub digest: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub registry_locator: String,
    pub contract: AdapterContract,
}

/// The versions a successful run of a transform declaring `declared` model
/// outputs publishes: exactly one per declared model, no other. Each version
/// takes the run's namespace and output marking, names the run, and records
/// the run's pinned inputs except the model versions it scored with as its
/// training inputs.
pub struct RunModelOutputs<'a> {
    pub declared: &'a BTreeSet<String>,
    pub writes: &'a [ModelOutputWrite],
    pub namespace: &'a str,
    pub run_id: &'a str,
    pub actor: &'a str,
    pub run_marking: &'a str,
    pub run_inputs: &'a BTreeMap<String, String>,
    pub now_ms: i64,
}

impl RunModelOutputs<'_> {
    pub fn versions(&self) -> Result<Vec<ModelVersion>, String> {
        let written: BTreeSet<&str> = self
            .writes
            .iter()
            .map(|write| write.model_name.trim())
            .collect();
        if written.len() != self.writes.len() {
            return Err("a run publishes one version per model output".into());
        }
        if !written
            .iter()
            .copied()
            .eq(self.declared.iter().map(String::as_str))
        {
            return Err(format!(
                "model outputs must match the definition's declared models {:?}",
                self.declared
            ));
        }
        let training: BTreeMap<String, String> = self
            .run_inputs
            .iter()
            .filter(|(key, _)| !key.starts_with(MODEL_PIN_PREFIX))
            .map(|(key, version)| (key.clone(), version.clone()))
            .collect();
        self.writes
            .iter()
            .map(|write| {
                ModelVersion::from_run(
                    ModelVersionRegistration {
                        namespace: self.namespace.to_string(),
                        model_name: write.model_name.trim().to_string(),
                        digest: write.digest.trim().to_string(),
                        adapter_id: write.adapter_id.trim().to_string(),
                        adapter_version: write.adapter_version.trim().to_string(),
                        registry_locator: write.registry_locator.trim().to_string(),
                        contract: write.contract.clone(),
                        run_id: self.run_id.to_string(),
                        actor: self.actor.to_string(),
                    },
                    self.namespace,
                    self.run_marking,
                    &training,
                    self.now_ms,
                )
            })
            .collect()
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

/// The engine of a transform generated by binding a model to a dataset
/// (#3076). Its code is the name of the one model input; a runtime that
/// runs this engine feeds the input dataset's rows to the pinned model under
/// that name and writes the rows it returns.
pub const MODEL_ENGINE: &str = "model";

/// Where the batch transform generated for a single-table model reads,
/// writes and runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelBinding {
    pub transform_id: String,
    pub input_dataset_id: String,
    pub output_dataset_id: String,
    /// The image of a runtime that can run [`MODEL_ENGINE`].
    pub runtime_image: String,
    /// Due interval, scheduled like any other transform (ADR 0103).
    pub schedule: Option<TransformSchedule>,
}

impl ModelVersion {
    /// Generates the batch transform that scores `binding`'s input dataset
    /// with this version (#3076). The transform pins this version under the
    /// contract's input name, so its runs' receipts name it. Refuses a model
    /// with more than one input table; its output is always one table.
    pub fn bind(&self, binding: ModelBinding) -> Result<GovernedTransform, String> {
        let [input] = self.contract.inputs.as_slice() else {
            return Err(format!(
                "only a single-table model binds to a dataset; {} has {} input tables",
                self.model_name,
                self.contract.inputs.len()
            ));
        };
        Ok(GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: self.namespace.clone(),
            transform_id: binding.transform_id,
            input_dataset_id: binding.input_dataset_id,
            output_dataset_id: binding.output_dataset_id,
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                llm_step: None,
                engine: MODEL_ENGINE.into(),
                runtime_image: binding.runtime_image,
                inputs: Vec::new(),
                requires: BTreeMap::new(),
                code: input.name.clone(),
                model_inputs: BTreeMap::from([(input.name.clone(), self.version_id.clone())]),
                model_outputs: Default::default(),
            }),
            schedule: binding.schedule,
            trigger: None,
        })
    }
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

    #[test]
    fn a_single_table_model_binds_and_a_multi_table_one_is_refused() {
        let version =
            ModelVersion::from_run(registration(), "ml", "", &BTreeMap::new(), 1).unwrap();
        let binding = ModelBinding {
            transform_id: "score-customers".into(),
            input_dataset_id: "customers".into(),
            output_dataset_id: "churn-scores".into(),
            runtime_image: "model-runner:1".into(),
            schedule: Some(TransformSchedule { every_ms: 60_000 }),
        };
        let transform = version.bind(binding.clone()).unwrap().prepare().unwrap();
        assert_eq!(
            crate::governed_transform::model_input_pins(&transform),
            BTreeMap::from([("model:features".to_string(), version.version_id.clone())])
        );
        let spec = transform.isolated_process.as_ref().unwrap();
        assert_eq!(
            (spec.engine.as_str(), spec.code.as_str()),
            (MODEL_ENGINE, "features")
        );
        assert_eq!(transform.schedule, binding.schedule);

        let mut two_tables = version;
        two_tables.contract.inputs.push(ModelInput {
            name: "history".into(),
            columns: vec![column("tenure")],
        });
        assert!(
            two_tables
                .bind(binding)
                .unwrap_err()
                .contains("single-table")
        );
    }
}
