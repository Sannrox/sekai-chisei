//! Plane-owned incremental dataset transforms (#880, #1287).
//!
//! Definitions are content-addressed and receipt-bound. Execution is the
//! in-process `projection` host of `sekai.governed-transform-execution/v1`.
//! The plane owns the JobSpec, transaction, lineage, and run receipt. Engine
//! choice is a later profile on that contract. Outputs are datasets, not
//! type-revision object identity. Secrets are rejected in definitions.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const CONTRACT_VERSION: &str = "sekai.governed-transform/v1";
pub const TRANSFORM_CLASS: &str = "projection";
/// DiscoverCapabilities name for the in-process transform host.
pub const HOSTED_COMPUTE_CAPABILITY: &str = "sekai.transforms.projection";

const FORBIDDEN_KEYS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "access_key",
    "private_key",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformError {
    InvalidArgument(String),
    Quarantined(String),
    NotFound(&'static str),
}

impl TransformError {
    pub fn message(&self) -> String {
        match self {
            Self::InvalidArgument(message) | Self::Quarantined(message) => message.clone(),
            Self::NotFound(message) => (*message).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformStep {
    pub kind: String,
    pub column: String,
    pub op: String,
    pub value: String,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedTransform {
    pub contract_version: String,
    pub namespace: String,
    pub transform_id: String,
    pub input_dataset_id: String,
    pub output_dataset_id: String,
    pub steps: Vec<TransformStep>,
    pub quality_rule: String,
    pub definition_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformRun {
    pub run_id: String,
    pub namespace: String,
    pub transform_id: String,
    pub definition_digest: String,
    pub input_digest: String,
    pub output_digest: String,
    pub last_input_row_id: i64,
    pub incremental: bool,
    pub quarantined: bool,
    pub quality_rule: String,
    pub rows_in: i32,
    pub rows_out: i32,
    pub lineage_parent: String,
    pub created_at_ms: i64,
}

impl GovernedTransform {
    pub fn prepare(mut self) -> Result<Self, TransformError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(TransformError::InvalidArgument(
                "unsupported governed-transform contract version".into(),
            ));
        }
        require_token("namespace", &self.namespace)?;
        require_token("transform_id", &self.transform_id)?;
        require_token("input_dataset_id", &self.input_dataset_id)?;
        require_token("output_dataset_id", &self.output_dataset_id)?;
        if self.input_dataset_id == self.output_dataset_id {
            return Err(TransformError::InvalidArgument(
                "transform output must be a distinct dataset".into(),
            ));
        }
        if self.steps.is_empty() {
            return Err(TransformError::InvalidArgument(
                "transform steps required".into(),
            ));
        }
        reject_secrets(&self)?;
        for step in &self.steps {
            let kind = step.kind.trim().to_ascii_lowercase();
            if kind != "filter" && kind != "project" {
                return Err(TransformError::InvalidArgument(
                    "unsupported transform step".into(),
                ));
            }
        }
        self.definition_digest = definition_digest(&self);
        Ok(self)
    }
}

pub fn definition_digest(transform: &GovernedTransform) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, CONTRACT_VERSION);
    hash_field(&mut hasher, &transform.namespace);
    hash_field(&mut hasher, &transform.transform_id);
    hash_field(&mut hasher, &transform.input_dataset_id);
    hash_field(&mut hasher, &transform.output_dataset_id);
    hash_field(&mut hasher, &transform.quality_rule);
    if let Ok(steps) = serde_json::to_vec(&transform.steps) {
        hasher.update((steps.len() as u64).to_le_bytes());
        hasher.update(steps);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

pub fn apply_steps(
    rows: &[HashMap<String, String>],
    steps: &[TransformStep],
) -> Vec<HashMap<String, String>> {
    let mut out = rows.to_vec();
    for step in steps {
        match step.kind.trim().to_ascii_lowercase().as_str() {
            "filter" => {
                out.retain(|row| match step.op.as_str() {
                    "eq" | "" => row
                        .get(&step.column)
                        .is_some_and(|value| value == &step.value),
                    "neq" => row
                        .get(&step.column)
                        .is_some_and(|value| value != &step.value),
                    _ => true,
                });
            }
            "project" if !step.columns.is_empty() => {
                for row in &mut out {
                    row.retain(|key, _| step.columns.contains(key));
                }
            }
            _ => {}
        }
    }
    out
}

pub fn evaluate_quality(
    rows: &[HashMap<String, String>],
    rule: &str,
) -> Result<(), TransformError> {
    let rule = rule.trim();
    if rule.is_empty() {
        return Ok(());
    }
    if let Some(column) = rule.strip_prefix("required:") {
        if rows
            .iter()
            .any(|row| row.get(column).is_none_or(|value| value.trim().is_empty()))
        {
            return Err(TransformError::Quarantined(format!("quality rule {rule}")));
        }
        return Ok(());
    }
    if rule == "min_rows:1" && rows.is_empty() {
        return Err(TransformError::Quarantined(
            "quality rule min_rows:1".into(),
        ));
    }
    Ok(())
}

/// Checkpoint of the last successful run for incremental selection.
pub type TransformCheckpoint = (i64, String, String);

/// Incremental selection requires the current JobSpec. The live receipt is
/// kept so a later quarantine still names the retained output.
pub fn bind_checkpoint(
    incremental: bool,
    checkpoint: Option<(TransformCheckpoint, String)>,
    definition_digest: &str,
) -> (bool, Option<TransformCheckpoint>) {
    match checkpoint {
        Some((pin, digest)) => (incremental && digest == definition_digest, Some(pin)),
        None => (false, None),
    }
}

/// Compute one run. The caller persists `output_rows` (unless quarantined),
/// then fills `run.output_digest` from live output rows and writes the receipt.
pub fn compute_run(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    input_records: &[(i64, HashMap<String, String>)],
    incremental: bool,
    now_ms: i64,
    run_id: String,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    let after_id = if incremental {
        checkpoint.map(|checkpoint| checkpoint.0).unwrap_or(0)
    } else {
        0
    };
    let selected: Vec<&(i64, HashMap<String, String>)> = input_records
        .iter()
        .filter(|(id, _)| *id > after_id)
        .collect();
    let last_input_row_id = selected.iter().map(|(id, _)| *id).max().unwrap_or(after_id);
    let input_rows: Vec<HashMap<String, String>> =
        selected.iter().map(|(_, row)| (*row).clone()).collect();
    let output_rows = apply_steps(&input_rows, &transform.steps);
    if let Err(error) = evaluate_quality(&output_rows, &transform.quality_rule) {
        let run = TransformRun {
            run_id,
            namespace: transform.namespace.clone(),
            transform_id: transform.transform_id.clone(),
            definition_digest: transform.definition_digest.clone(),
            input_digest: rows_digest(&input_rows),
            output_digest: checkpoint
                .map(|checkpoint| checkpoint.2.clone())
                .unwrap_or_default(),
            last_input_row_id: after_id,
            incremental,
            quarantined: true,
            quality_rule: error.message(),
            rows_in: input_rows.len() as i32,
            rows_out: 0,
            lineage_parent: checkpoint
                .map(|checkpoint| checkpoint.1.clone())
                .unwrap_or_default(),
            created_at_ms: now_ms,
        };
        return (run, Vec::new());
    }
    let run = TransformRun {
        run_id,
        namespace: transform.namespace.clone(),
        transform_id: transform.transform_id.clone(),
        definition_digest: transform.definition_digest.clone(),
        input_digest: rows_digest(&input_rows),
        output_digest: String::new(),
        last_input_row_id,
        incremental,
        quarantined: false,
        quality_rule: transform.quality_rule.clone(),
        rows_in: input_rows.len() as i32,
        rows_out: output_rows.len() as i32,
        lineage_parent: checkpoint
            .map(|checkpoint| checkpoint.1.clone())
            .unwrap_or_default(),
        created_at_ms: now_ms,
    };
    (run, output_rows)
}

pub fn rows_digest(rows: &[HashMap<String, String>]) -> String {
    let mut hasher = Sha256::new();
    let mut ordered: Vec<BTreeMap<String, String>> = rows
        .iter()
        .map(|row| row.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .collect();
    ordered.sort_by(|left, right| format!("{left:?}").cmp(&format!("{right:?}")));
    hasher.update(serde_json::to_vec(&ordered).unwrap_or_default());
    format!("sha256:{:x}", hasher.finalize())
}

fn reject_secrets(transform: &GovernedTransform) -> Result<(), TransformError> {
    let blob = serde_json::to_string(transform)
        .unwrap_or_default()
        .to_ascii_lowercase();
    for key in FORBIDDEN_KEYS {
        if blob.contains(key) {
            return Err(TransformError::InvalidArgument(
                "transform definition must not contain credentials".into(),
            ));
        }
    }
    Ok(())
}

fn require_token(field: &str, value: &str) -> Result<(), TransformError> {
    if value.trim().is_empty() {
        return Err(TransformError::InvalidArgument(format!("{field} required")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transform() -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: vec![TransformStep {
                kind: "filter".into(),
                column: "keep".into(),
                op: "eq".into(),
                value: "yes".into(),
                columns: Vec::new(),
            }],
            quality_rule: String::new(),
            definition_digest: String::new(),
        }
        .prepare()
        .unwrap()
    }

    #[test]
    fn bind_checkpoint_drops_a_pin_from_a_different_digest() {
        let pin = (7, "run".into(), "out".into());
        let (incremental, checkpoint) =
            bind_checkpoint(true, Some((pin.clone(), "old".into())), "new");
        assert!(!incremental);
        assert_eq!(checkpoint.as_ref(), Some(&pin));
        let (incremental, checkpoint) =
            bind_checkpoint(true, Some((pin.clone(), "same".into())), "same");
        assert!(incremental);
        assert_eq!(checkpoint.as_ref(), Some(&pin));
        let (incremental, checkpoint) =
            bind_checkpoint(false, Some((pin.clone(), "same".into())), "same");
        assert!(!incremental);
        assert_eq!(checkpoint, Some(pin));
    }

    #[test]
    fn changed_definition_gets_a_new_digest() {
        let first = transform();
        let mut second = first.clone();
        second.steps[0].value = "no".into();
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_ne!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn adjacent_dataset_ids_do_not_share_a_digest() {
        let mut left = transform();
        left.input_dataset_id = "a".into();
        left.output_dataset_id = "bc".into();
        left.definition_digest.clear();
        let left = left.prepare().unwrap();
        let mut right = transform();
        right.input_dataset_id = "ab".into();
        right.output_dataset_id = "c".into();
        right.definition_digest.clear();
        let right = right.prepare().unwrap();
        assert_ne!(left.definition_digest, right.definition_digest);
    }

    #[test]
    fn secrets_are_rejected_in_definitions() {
        let mut bad = transform();
        bad.steps[0].column = "api_key".into();
        bad.definition_digest.clear();
        let error = bad.prepare().unwrap_err();
        assert!(error.message().contains("credentials"));
    }

    #[test]
    fn quality_rule_names_the_failure() {
        let rows = vec![HashMap::from([("name".into(), String::new())])];
        let error = evaluate_quality(&rows, "required:name").unwrap_err();
        assert_eq!(error.message(), "quality rule required:name");
    }

    #[test]
    fn full_rebuild_quarantine_keeps_the_live_receipt() {
        let mut transform = transform();
        transform.quality_rule = "min_rows:1".into();
        transform.definition_digest.clear();
        let transform = transform.prepare().unwrap();
        let pin = (9, "live-run".into(), "live-out".into());
        let (run, rows) = compute_run(&transform, Some(&pin), &[], false, 40, "new-run".into());
        assert!(run.quarantined);
        assert!(rows.is_empty());
        assert_eq!(run.lineage_parent, "live-run");
        assert_eq!(run.output_digest, "live-out");
        assert!(!run.incremental);
    }
}
