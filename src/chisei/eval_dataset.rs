//! Versioned eval datasets generated from synthetic tenant seeds (#1673).
//!
//! A dataset is generated, not stored: a checked-in definition names a
//! synthetic tenant (generator, namespace, seed and size preset, #1450) and
//! case templates over its objects, and generation is deterministic. A
//! dataset's version is derived from its digest, so the same definition and
//! generator version always give the same version, and any change (another
//! seed, a template edit, a generator change) gives a new one. Resolving a
//! name and version regenerates the dataset and refuses a version the
//! definition no longer produces, so a version is immutable by construction.
//!
//! Cases feed the existing evaluation executor as evidence
//! ([`EvalDataset::evidence`]), so their runs leave the executor's usual
//! step receipts; there is no eval store of their own. Cases name only the
//! synthetic tenant they were generated from, so their tool calls run
//! against fixture tenants alone.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::chisei::evaluation_execution::EvaluationEvidenceInput;
use crate::chisei::evaluation_manifest::digest_json;
use crate::sekai::synthetic::{SizePreset, Spec, SupplyChain, generate};

pub const EVAL_DATASET_DEFINITION_CONTRACT: &str = "chisei.eval-dataset-definition/v1";
pub const EVAL_DATASET_CONTRACT: &str = "chisei.eval-dataset/v1";
/// Evidence schema of one case handed to the executor.
pub const EVAL_CASE_SCHEMA: &str = "chisei.eval-case/v1";
/// Bumped whenever generation from the same definition would change, so
/// such a change is a new version, never a rewritten one.
pub const GENERATOR_VERSION: &str = "eval-dataset-generator/v1";
const DATASET_NOT_FOUND: &str = "eval dataset version not found";

/// What a dataset is generated from. Checked in; never edited in place for
/// a version anyone relies on, since an edit is a new version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalDatasetDefinition {
    pub contract_version: String,
    pub name: String,
    /// The synthetic domain generator; `supply_chain` is the one there is.
    pub generator: String,
    /// The fixture tenant the cases are generated into and run against.
    pub namespace: String,
    pub seed: u64,
    pub preset: SizePreset,
    pub templates: Vec<CaseTemplate>,
}

/// One case per object of `kind`: its `input_properties` are the input and
/// its `expected_property` the expected outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTemplate {
    pub id: String,
    pub kind: String,
    pub input_properties: Vec<String>,
    pub expected_property: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalCase {
    pub case_id: String,
    /// The fixture object and the input properties the template selected.
    pub input: BTreeMap<String, String>,
    pub expected: String,
    pub tags: Vec<String>,
}

/// One immutable dataset version: `name` at `version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalDataset {
    pub contract_version: String,
    pub name: String,
    pub version: String,
    pub generator_version: String,
    pub namespace: String,
    pub seed: u64,
    pub preset: SizePreset,
    /// The synthetic plan the cases were drawn from.
    pub plan_digest: String,
    pub definition_digest: String,
    pub cases: Vec<EvalCase>,
    /// Over everything above but `version`, which is derived from it.
    pub digest: String,
}

/// What the digest covers: every field but `version` and `digest`.
#[derive(Serialize)]
struct DigestInput<'a> {
    contract_version: &'a str,
    name: &'a str,
    generator_version: &'a str,
    namespace: &'a str,
    seed: u64,
    preset: SizePreset,
    plan_digest: &'a str,
    definition_digest: &'a str,
    cases: &'a [EvalCase],
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl EvalDatasetDefinition {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != EVAL_DATASET_DEFINITION_CONTRACT {
            return Err(format!(
                "eval dataset definition contract_version must be {EVAL_DATASET_DEFINITION_CONTRACT}"
            ));
        }
        if !identifier(&self.name) || !identifier(&self.namespace) {
            return Err("eval dataset name and namespace must be [A-Za-z0-9_-]".into());
        }
        if self.generator != "supply_chain" {
            return Err(format!("unknown synthetic generator {:?}", self.generator));
        }
        if self.templates.is_empty() {
            return Err(format!("eval dataset {} has no case templates", self.name));
        }
        let mut ids = std::collections::HashSet::new();
        for template in &self.templates {
            if !identifier(&template.id) || !ids.insert(template.id.as_str()) {
                return Err(format!(
                    "eval dataset {} template ids must be unique [A-Za-z0-9_-]",
                    self.name
                ));
            }
            if template.input_properties.is_empty()
                || template
                    .input_properties
                    .contains(&template.expected_property)
            {
                return Err(format!(
                    "template {} needs input properties other than its expected one",
                    template.id
                ));
            }
        }
        Ok(())
    }

    /// Generate the dataset. Deterministic: the same definition gives the
    /// same cases, digest and version.
    pub fn generate(&self) -> Result<EvalDataset, String> {
        self.validate()?;
        let plan = generate(
            &SupplyChain,
            &Spec {
                namespace: self.namespace.clone(),
                seed: self.seed,
                preset: self.preset,
            },
        )?;
        // Cases describe the tenant as `apply` leaves it, after its
        // declared actions, since that is what a case's tools read.
        let objects = plan.final_objects()?;
        let mut cases = Vec::new();
        for template in &self.templates {
            let mut matched = 0usize;
            for object in objects.iter().filter(|object| object.kind == template.kind) {
                let Some(expected) = object.properties.get(&template.expected_property) else {
                    return Err(format!(
                        "template {}: {} has no {}",
                        template.id, object.kind, template.expected_property
                    ));
                };
                let mut input = BTreeMap::from([
                    ("namespace".to_string(), plan.namespace.clone()),
                    ("object_id".to_string(), object.id.clone()),
                    ("kind".to_string(), object.kind.clone()),
                ]);
                for property in &template.input_properties {
                    let value = object.properties.get(property).ok_or_else(|| {
                        format!(
                            "template {}: {} has no {property}",
                            template.id, object.kind
                        )
                    })?;
                    input.insert(property.clone(), value.clone());
                }
                cases.push(EvalCase {
                    case_id: format!("{}:{}", template.id, object.id),
                    input,
                    expected: expected.clone(),
                    tags: template.tags.clone(),
                });
                matched += 1;
            }
            if matched == 0 {
                return Err(format!(
                    "template {} matches no {} object",
                    template.id, template.kind
                ));
            }
        }
        let plan_digest = format!("sha256:{}", plan.digest);
        let definition_digest = digest_json(self)?;
        let digest = digest_json(&DigestInput {
            contract_version: EVAL_DATASET_CONTRACT,
            name: &self.name,
            generator_version: GENERATOR_VERSION,
            namespace: &plan.namespace,
            seed: self.seed,
            preset: self.preset,
            plan_digest: &plan_digest,
            definition_digest: &definition_digest,
            cases: &cases,
        })?;
        let version = version_of(&digest);
        Ok(EvalDataset {
            contract_version: EVAL_DATASET_CONTRACT.into(),
            name: self.name.clone(),
            version,
            generator_version: GENERATOR_VERSION.into(),
            namespace: plan.namespace,
            seed: self.seed,
            preset: self.preset,
            plan_digest,
            definition_digest,
            cases,
            digest,
        })
    }
}

/// `v` and the first 16 hex digits of the digest.
fn version_of(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("v{}", &hex[..16.min(hex.len())])
}

impl EvalDataset {
    /// `name@version`.
    pub fn address(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// One case as evaluation evidence for the existing executor. Its
    /// content names the dataset version and digest, so a receipt over it
    /// pins the exact case set.
    pub fn evidence(&self, case: &EvalCase) -> Result<EvaluationEvidenceInput, String> {
        let content = serde_json::json!({
            "dataset": self.address(),
            "dataset_digest": self.digest,
            "case_id": case.case_id,
            "input": case.input,
            "expected": case.expected,
            "tags": case.tags,
        });
        Ok(EvaluationEvidenceInput {
            evidence_object_id: format!("evidence:eval-case:{}:{}", self.name, case.case_id),
            submission_id: format!("submission:eval-dataset:{}", self.address()),
            content_digest: digest_json(&content)?,
            schema_id: EVAL_CASE_SCHEMA.into(),
            schema_version: "1".into(),
            content,
        })
    }
}

/// The dataset `name` at `version`, regenerated from the definition
/// `<definitions>/<name>.json`. A version the definition does not produce
/// (an older seed or template) is not found: versions are never rewritten.
pub fn resolve(definitions: &Path, name: &str, version: &str) -> Result<EvalDataset, String> {
    if !identifier(name) {
        return Err(DATASET_NOT_FOUND.into());
    }
    let path = definitions.join(format!("{name}.json"));
    let json = std::fs::read_to_string(&path).map_err(|_| DATASET_NOT_FOUND.to_string())?;
    let definition: EvalDatasetDefinition = serde_json::from_str(&json)
        .map_err(|error| format!("eval dataset definition {name}: {error}"))?;
    if definition.name != name {
        return Err(format!(
            "eval dataset definition {name} names {}",
            definition.name
        ));
    }
    let dataset = definition.generate()?;
    if dataset.version != version {
        return Err(DATASET_NOT_FOUND.into());
    }
    Ok(dataset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::evaluation_execution::{
        DeterministicEvaluator, DeterministicEvaluatorInput, DeterministicEvaluatorOutput,
        DeterministicEvaluatorRegistry, EVALUATOR_RESULT_CONTRACT, STATUS_PASS,
        build_evaluator_input, execute_registered_node,
    };
    use crate::chisei::evaluation_manifest::{
        MANIFEST_CONTRACT, RESOLVER_VERSION, ResolvedEvaluationManifest, ResolvedEvaluationNode,
        ResolvedEvaluatorBinding, ResolvedInvariantBinding,
    };
    use crate::chisei::evaluation_plan::{EvaluatorResourceLimits, NODE_REQUIRED};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn definitions() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/evaluation/datasets")
    }

    fn definition() -> EvalDatasetDefinition {
        serde_json::from_str(
            &std::fs::read_to_string(definitions().join("supply-chain-triage.json")).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn the_same_seed_gives_the_same_dataset_and_another_seed_a_new_version() {
        let first = definition().generate().unwrap();
        let again = definition().generate().unwrap();
        assert_eq!(first, again);
        assert!(first.version.starts_with('v'));
        let reseeded = EvalDatasetDefinition {
            seed: 1674,
            ..definition()
        }
        .generate()
        .unwrap();
        assert_ne!(reseeded.digest, first.digest);
        assert_ne!(reseeded.version, first.version);
        // A template edit is a new version too.
        let mut edited = definition();
        edited.templates[0].tags.push("edited".into());
        assert_ne!(edited.generate().unwrap().version, first.version);
        // Incidents are triaged by the plan's actions; cases see that.
        assert!(
            first
                .cases
                .iter()
                .filter(|case| case.case_id.starts_with("incident-state:"))
                .any(|case| case.expected != "open")
        );
        // Every case names only the fixture tenant it came from.
        assert!(
            first
                .cases
                .iter()
                .all(|case| case.input["namespace"] == "eval-supply-chain")
        );
    }

    #[test]
    fn a_version_resolves_by_name_and_only_while_the_definition_produces_it() {
        let dataset = definition().generate().unwrap();
        assert!(dataset.cases.len() >= 1_000, "{}", dataset.cases.len());
        let resolved = resolve(&definitions(), "supply-chain-triage", &dataset.version).unwrap();
        assert_eq!(resolved.digest, dataset.digest);
        for (name, version) in [
            ("supply-chain-triage", "v0000000000000000"),
            ("missing", dataset.version.as_str()),
            ("../escape", dataset.version.as_str()),
        ] {
            assert_eq!(
                resolve(&definitions(), name, version).unwrap_err(),
                DATASET_NOT_FOUND,
                "{name}"
            );
        }
    }

    #[test]
    fn malformed_definitions_are_refused() {
        let mut no_templates = definition();
        no_templates.templates.clear();
        assert!(no_templates.generate().is_err());
        let mut leaks_answer = definition();
        leaks_answer.templates[0]
            .input_properties
            .push("status".into());
        assert!(leaks_answer.generate().is_err());
        let mut unknown_kind = definition();
        unknown_kind.templates[0].kind = "synthetic_spaceship".into();
        assert!(unknown_kind.generate().is_err());
        let mut generator = definition();
        generator.generator = "real_tenant".into();
        assert!(generator.generate().is_err());
    }

    /// Passes when a case's input carries a value for its expected outcome,
    /// so the test can see a case reach an evaluator through the executor.
    struct CaseShape;

    impl DeterministicEvaluator for CaseShape {
        fn evaluate(
            &self,
            input: &DeterministicEvaluatorInput,
        ) -> Result<DeterministicEvaluatorOutput, String> {
            let case = &input.evidence[0].content;
            Ok(DeterministicEvaluatorOutput {
                contract_version: EVALUATOR_RESULT_CONTRACT.into(),
                status: if case["expected"].is_string() && case["input"]["object_id"].is_string() {
                    STATUS_PASS.into()
                } else {
                    "fail".into()
                },
                reason_code: "case_shape".into(),
                result: serde_json::json!({"case_id": case["case_id"]}),
            })
        }
    }

    #[test]
    fn a_generated_case_runs_through_the_existing_executor() {
        let dataset = definition().generate().unwrap();
        let evidence = dataset.evidence(&dataset.cases[0]).unwrap();
        let digest = |byte: char| format!("sha256:{}", byte.to_string().repeat(64));
        let registry = DeterministicEvaluatorRegistry::default();
        registry
            .register(&digest('e'), Arc::new(CaseShape))
            .unwrap();
        let node = ResolvedEvaluationNode {
            node_id: "case".into(),
            evaluator: ResolvedEvaluatorBinding {
                definition_id: "definition:case-shape".into(),
                definition_digest: digest('d'),
                implementation_digest: digest('e'),
                stochastic_policy: None,
            },
            depends_on_node_ids: Vec::new(),
            input_bindings: Vec::new(),
            parameters_json: "{}".into(),
            invariants: vec![ResolvedInvariantBinding {
                invariant_version_id: "invariant:case-shape".into(),
                content_digest: digest('a'),
                predicate_kind: "fixture_predicate/v1".into(),
                input_schema: EVAL_CASE_SCHEMA.into(),
                result_schema: EVALUATOR_RESULT_CONTRACT.into(),
                evidence_types: Vec::new(),
                provenance_evidence_object_ids: Vec::new(),
                waiver_version_ids: Vec::new(),
            }],
            evidence_object_ids: vec![evidence.evidence_object_id.clone()],
            classification: NODE_REQUIRED.into(),
        };
        let manifest = ResolvedEvaluationManifest {
            contract_version: MANIFEST_CONTRACT.into(),
            resolver_version: RESOLVER_VERSION.into(),
            manifest_id: "manifest:eval-dataset".into(),
            manifest_digest: digest('f'),
            namespace: dataset.namespace.clone(),
            plan_version_id: "plan:eval-dataset".into(),
            plan_digest: digest('1'),
            subject_profile: "chisei.eval-dataset/v1".into(),
            subject_identity: dataset.address(),
            subject_content_digest: dataset.digest.clone(),
            invariant_set_id: "set:eval-dataset".into(),
            invariant_set_digest: digest('3'),
            invariant_profile_digest: digest('4'),
            evaluation_time_ms: 1,
            resolved_by: "root".into(),
            requirements: Vec::new(),
            nodes: vec![node],
            evidence: Vec::new(),
            waivers: Vec::new(),
            created_at_ms: 1,
        };
        let node = &manifest.nodes[0];
        let input =
            build_evaluator_input(&manifest, node, vec![evidence.clone()], &BTreeMap::new())
                .unwrap();
        let execution = execute_registered_node(
            &registry,
            &manifest,
            node,
            input,
            &EvaluatorResourceLimits {
                timeout_ms: 1_000,
                max_input_bytes: 64 * 1024,
                max_output_bytes: 16 * 1024,
                max_evidence_items: 16,
            },
            std::time::Duration::from_secs(1),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(execution.receipt.status, STATUS_PASS);
        // The executor's own receipt pins the case evidence.
        assert!(
            serde_json::to_string(&execution.receipt)
                .unwrap()
                .contains(&evidence.content_digest)
        );
    }
}
