//! Eval datasets recorded from decided Action instances (ADR 0153, #3513).
//!
//! A recorded definition is put as a selection (an Action type, a decision
//! window and an optional decision) and frozen at put time into the list of
//! matching instances. A case is only a reference: the instance id, its
//! `request_digest`, the decision and when it was made. No parameter or
//! property value is copied; the case input resolves from the instance at run
//! time (`src/composition/recorded_eval_cases.rs`), so erasure and markings
//! keep working on the source alone.
//!
//! The version digest covers the selection and every case reference, so a
//! source that stops resolving retires the version instead of shrinking it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{EVAL_DATASET_CONTRACT, EvalCase, EvalDataset, identifier, version_of};
use crate::chisei::evaluation_manifest::digest_json;
use sekai_core::sekai::synthetic::SizePreset;

pub const RECORDED_DATASET_DEFINITION_CONTRACT: &str = "chisei.eval-recorded-dataset-definition/v1";
/// The generator version a recorded dataset names in place of a synthetic one.
pub const RECORDED_GENERATOR_VERSION: &str = "recorded/v1";
pub const DECISION_GRANT: &str = "grant";
pub const DECISION_DENY: &str = "deny";
/// The most cases one recorded version freezes. A selection matching more is
/// refused rather than cut, so a version never depends on scan order.
pub const MAX_RECORDED_CASES: usize = 1_000;
/// The case input keys: references only, never values.
pub const INPUT_INSTANCE_ID: &str = "instance_id";
pub const INPUT_REQUEST_DIGEST: &str = "request_digest";
pub const INPUT_ACTION_TYPE: &str = "action_type";
pub const INPUT_DECIDED_AT_MS: &str = "decided_at_ms";

/// What a put of a recorded definition names: which decided instances of the
/// namespace become cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedDatasetSelection {
    pub contract_version: String,
    pub name: String,
    /// The governed Action type whose decided instances are cases.
    pub action_type: String,
    /// Instances decided in `[decided_from_ms, decided_to_ms)`.
    pub decided_from_ms: i64,
    pub decided_to_ms: i64,
    /// Only `grant` or only `deny` decisions; both when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
}

impl RecordedDatasetSelection {
    pub fn parse(json: &str) -> Result<Self, String> {
        let selection: Self = serde_json::from_str(json)
            .map_err(|error| format!("recorded eval dataset definition: {error}"))?;
        selection.validate()?;
        Ok(selection)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != RECORDED_DATASET_DEFINITION_CONTRACT {
            return Err(format!(
                "recorded eval dataset contract_version must be {RECORDED_DATASET_DEFINITION_CONTRACT}"
            ));
        }
        if !identifier(&self.name) {
            return Err("eval dataset name must be [A-Za-z0-9_-]".into());
        }
        if self.action_type.trim().is_empty() || self.action_type.len() > 256 {
            return Err("recorded eval dataset needs an action_type".into());
        }
        if self.decided_from_ms < 0 || self.decided_from_ms >= self.decided_to_ms {
            return Err("decided_from_ms must be before decided_to_ms".into());
        }
        if let Some(decision) = &self.decision
            && decision != DECISION_GRANT
            && decision != DECISION_DENY
        {
            return Err("decision must be grant or deny".into());
        }
        Ok(())
    }

    /// Whether `decision` at `decided_at_ms` falls in this selection.
    pub fn admits(&self, decision: &str, decided_at_ms: i64) -> bool {
        (self.decided_from_ms..self.decided_to_ms).contains(&decided_at_ms)
            && self
                .decision
                .as_deref()
                .is_none_or(|wanted| wanted == decision)
    }
}

/// Whether `json` names the recorded definition contract, so a put can route
/// it before parsing either kind strictly.
pub fn is_recorded_definition(json: &str) -> bool {
    #[derive(Deserialize)]
    struct Contract {
        #[serde(default)]
        contract_version: String,
    }
    serde_json::from_str::<Contract>(json)
        .is_ok_and(|contract| contract.contract_version == RECORDED_DATASET_DEFINITION_CONTRACT)
}

/// One case: a reference to a decided instance, never its values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedCase {
    pub instance_id: String,
    pub request_digest: String,
    /// `grant` or `deny`.
    pub decision: String,
    pub decided_at_ms: i64,
}

/// A frozen recorded definition: the selection and the cases it matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedEvalDatasetDefinition {
    pub selection: RecordedDatasetSelection,
    /// By instance id.
    pub cases: Vec<RecordedCase>,
}

impl RecordedEvalDatasetDefinition {
    /// Freezes `cases` under `selection`, sorted by instance id. Refuses an
    /// empty or oversized set and a case the selection does not admit.
    pub fn freeze(
        selection: RecordedDatasetSelection,
        mut cases: Vec<RecordedCase>,
    ) -> Result<Self, String> {
        selection.validate()?;
        if cases.is_empty() {
            return Err("no decided instance matches the selection".into());
        }
        if cases.len() > MAX_RECORDED_CASES {
            return Err(format!(
                "the selection matches more than {MAX_RECORDED_CASES} decided instances; narrow the window"
            ));
        }
        cases.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
        if cases
            .windows(2)
            .any(|pair| pair[0].instance_id == pair[1].instance_id)
        {
            return Err("a recorded case names an instance twice".into());
        }
        if let Some(case) = cases
            .iter()
            .find(|case| !selection.admits(&case.decision, case.decided_at_ms))
        {
            return Err(format!(
                "instance {} is outside the selection",
                case.instance_id
            ));
        }
        Ok(Self { selection, cases })
    }

    /// The dataset version over `namespace`. Each case's input holds the
    /// references only; its expected outcome is the decision.
    pub fn dataset(&self, namespace: &str) -> Result<EvalDataset, String> {
        let cases: Vec<EvalCase> = self
            .cases
            .iter()
            .map(|case| EvalCase {
                case_id: case.instance_id.clone(),
                input: BTreeMap::from([
                    (INPUT_INSTANCE_ID.into(), case.instance_id.clone()),
                    (INPUT_REQUEST_DIGEST.into(), case.request_digest.clone()),
                    (INPUT_ACTION_TYPE.into(), self.selection.action_type.clone()),
                    (INPUT_DECIDED_AT_MS.into(), case.decided_at_ms.to_string()),
                ]),
                expected: case.decision.clone(),
                tags: vec!["recorded".into(), case.decision.clone()],
            })
            .collect();
        let definition_digest = digest_json(self)?;
        #[derive(Serialize)]
        struct DigestInput<'a> {
            contract_version: &'a str,
            name: &'a str,
            generator_version: &'a str,
            namespace: &'a str,
            definition_digest: &'a str,
            cases: &'a [EvalCase],
        }
        let digest = digest_json(&DigestInput {
            contract_version: EVAL_DATASET_CONTRACT,
            name: &self.selection.name,
            generator_version: RECORDED_GENERATOR_VERSION,
            namespace,
            definition_digest: &definition_digest,
            cases: &cases,
        })?;
        Ok(EvalDataset {
            contract_version: EVAL_DATASET_CONTRACT.into(),
            name: self.selection.name.clone(),
            version: version_of(&digest),
            generator_version: RECORDED_GENERATOR_VERSION.into(),
            namespace: namespace.into(),
            seed: 0,
            // Recorded datasets have no synthetic tenant; the preset is unused.
            preset: SizePreset::Demo,
            plan_digest: String::new(),
            definition_digest,
            cases,
            digest,
        })
    }
}

/// Whether `dataset` was built from a recorded definition.
pub fn is_recorded_dataset(dataset: &EvalDataset) -> bool {
    dataset.generator_version == RECORDED_GENERATOR_VERSION
}

/// One stored version of a recorded definition, under a name in the
/// namespace whose instances it references. Written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecordedEvalDataset {
    pub namespace: String,
    pub definition: RecordedEvalDatasetDefinition,
    pub version: String,
    pub digest: String,
    pub case_count: u64,
    pub created_by: String,
    pub created_at_ms: i64,
}

impl StoredRecordedEvalDataset {
    pub fn new(
        namespace: &str,
        definition: RecordedEvalDatasetDefinition,
        created_by: &str,
        created_at_ms: i64,
    ) -> Result<Self, String> {
        let dataset = definition.dataset(namespace)?;
        Ok(Self {
            namespace: namespace.into(),
            case_count: definition.cases.len() as u64,
            definition,
            version: dataset.version,
            digest: dataset.digest,
            created_by: created_by.into(),
            created_at_ms,
        })
    }
}

/// Stored recorded definition versions, per namespace and name. The same
/// semantics as [`super::EvalDatasetDefinitionStore`], in their own table so
/// a binary that predates recorded definitions never reads one.
pub trait RecordedEvalDatasetStore {
    fn put_recorded_eval_dataset(
        &self,
        record: &StoredRecordedEvalDataset,
    ) -> Result<StoredRecordedEvalDataset, String>;
    fn get_recorded_eval_dataset(
        &self,
        namespace: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<StoredRecordedEvalDataset>, String>;
    fn list_recorded_eval_datasets(
        &self,
        namespace: &str,
        after_name: &str,
        limit: usize,
    ) -> Result<Vec<StoredRecordedEvalDataset>, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection() -> RecordedDatasetSelection {
        RecordedDatasetSelection {
            contract_version: RECORDED_DATASET_DEFINITION_CONTRACT.into(),
            name: "refund-reviews".into(),
            action_type: "refund".into(),
            decided_from_ms: 100,
            decided_to_ms: 200,
            decision: None,
        }
    }

    fn case(id: &str, decision: &str, at: i64) -> RecordedCase {
        RecordedCase {
            instance_id: id.into(),
            request_digest: format!("sha256:{id}"),
            decision: decision.into(),
            decided_at_ms: at,
        }
    }

    #[test]
    fn a_version_covers_every_reference_and_no_value() {
        let frozen = RecordedEvalDatasetDefinition::freeze(
            selection(),
            vec![
                case("b", DECISION_DENY, 150),
                case("a", DECISION_GRANT, 120),
            ],
        )
        .unwrap();
        let dataset = frozen.dataset("acme").unwrap();
        assert_eq!(dataset.cases[0].case_id, "a", "cases sort by instance id");
        assert_eq!(dataset.cases[0].expected, DECISION_GRANT);
        assert!(is_recorded_dataset(&dataset));
        // Same references, same version; any changed reference, a new one.
        let again = RecordedEvalDatasetDefinition::freeze(
            selection(),
            vec![
                case("a", DECISION_GRANT, 120),
                case("b", DECISION_DENY, 150),
            ],
        )
        .unwrap();
        assert_eq!(again.dataset("acme").unwrap().version, dataset.version);
        let mut changed = again.clone();
        changed.cases[1].request_digest = "sha256:other".into();
        assert_ne!(changed.dataset("acme").unwrap().version, dataset.version);
        let without = RecordedEvalDatasetDefinition::freeze(
            selection(),
            vec![case("a", DECISION_GRANT, 120)],
        )
        .unwrap();
        assert_ne!(without.dataset("acme").unwrap().version, dataset.version);
    }

    #[test]
    fn a_selection_freezes_only_what_it_admits() {
        let mut only_grants = selection();
        only_grants.decision = Some(DECISION_GRANT.into());
        assert!(only_grants.admits(DECISION_GRANT, 100));
        assert!(!only_grants.admits(DECISION_DENY, 100));
        assert!(
            !only_grants.admits(DECISION_GRANT, 200),
            "the window is half-open"
        );
        assert!(
            RecordedEvalDatasetDefinition::freeze(only_grants, vec![case("a", DECISION_DENY, 150)])
                .is_err()
        );
        assert!(RecordedEvalDatasetDefinition::freeze(selection(), Vec::new()).is_err());
        assert!(
            RecordedEvalDatasetDefinition::freeze(
                selection(),
                vec![
                    case("a", DECISION_GRANT, 120),
                    case("a", DECISION_DENY, 130)
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn the_contract_routes_a_put_and_refuses_unknown_fields() {
        let json = serde_json::to_string(&selection()).unwrap();
        assert!(is_recorded_definition(&json));
        assert!(!is_recorded_definition(
            r#"{"contract_version":"chisei.eval-dataset-definition/v1"}"#
        ));
        assert_eq!(RecordedDatasetSelection::parse(&json).unwrap(), selection());
        let with_cases = json.replace('}', r#","cases":[]}"#);
        assert!(RecordedDatasetSelection::parse(&with_cases).is_err());
        let mut backwards = selection();
        backwards.decided_to_ms = backwards.decided_from_ms;
        assert!(backwards.validate().is_err());
    }
}
