//! Plane-owned incremental dataset transforms (#880).
//!
//! Definitions are content-addressed and receipt-bound. Execution is an
//! in-process class of `sekai.governed-transform-execution/v1` `projection`.
//! This is not an engine pick. Outputs are datasets, not type-revision
//! object identity. Secrets are rejected in definitions.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub const CONTRACT_VERSION: &str = "sekai.governed-transform/v1";
pub const TRANSFORM_CLASS: &str = "projection";

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
    hasher.update(CONTRACT_VERSION.as_bytes());
    hasher.update(transform.namespace.as_bytes());
    hasher.update(transform.transform_id.as_bytes());
    hasher.update(transform.input_dataset_id.as_bytes());
    hasher.update(transform.output_dataset_id.as_bytes());
    hasher.update(transform.quality_rule.as_bytes());
    if let Ok(steps) = serde_json::to_vec(&transform.steps) {
        hasher.update(steps);
    }
    format!("sha256:{:x}", hasher.finalize())
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
    fn changed_definition_gets_a_new_digest() {
        let first = transform();
        let mut second = first.clone();
        second.steps[0].value = "no".into();
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_ne!(first.definition_digest, second.definition_digest);
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
}
