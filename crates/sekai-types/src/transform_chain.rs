//! Static DAG of governed transforms executed as one receipted operation (#2119).
//!
//! The plane owns the chain: kako remains a single-job runner. Named edges
//! compile onto existing transform dataset I/O at registration. Step receipts
//! stay `ReceiptKind::TransformRun`; the chain receipt is the same kind with
//! `profile = "chain"` and `trigger_ref` listing step run ids.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::governed_transform::{GovernedTransform, TransformError, TransformRun, hash_field};

pub const CHAIN_CONTRACT: &str = "sekai.transform-chain/v1";
pub const CHAIN_PROFILE: &str = "chain";
pub const CHAIN_COMPUTE_CAPABILITY: &str = "sekai.transforms.chain";
pub const CHAIN_STATUS_CAPABILITY: &str = "sekai.transforms.chain.status";
pub const CHAIN_WORK_RUNNING: &str = "running";
pub const CHAIN_WORK_COMPLETED: &str = "completed";
pub const CHAIN_WORK_FAILED: &str = "failed";
pub const CHAIN_WORK_CANCELLED: &str = "cancelled";
pub const CHAIN_ASSERT_NOT_NULL: &str = "not_null";
pub const CHAIN_ASSERT_UNIQUE: &str = "unique";
pub const CHAIN_ASSERT_ROW_COUNT_MIN: &str = "row_count_min";
pub const CHAIN_ASSERT_ROW_COUNT_MAX: &str = "row_count_max";
pub const CHAIN_ASSERT_ACCEPTED_VALUES: &str = "accepted_values";
pub const CHAIN_NAMED_OUTPUT: &str = "output";
pub const CHAIN_CYCLE: &str = "transform chain cycle";
pub const CHAIN_MISSING_NAME: &str = "named chain edge is missing";
pub const CHAIN_AMBIGUOUS_NAME: &str = "named chain edge is ambiguous";
pub const CHAIN_DATASET_MISMATCH: &str = "named chain edge datasets do not match";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ChainAssertion {
    pub kind: String,
    #[serde(default)]
    pub column: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ChainStep {
    pub name: String,
    pub transform_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transform_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<ChainAssertion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ChainEdge {
    pub from_step: String,
    pub output: String,
    pub to_step: String,
    pub input: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformChain {
    pub contract_version: String,
    pub namespace: String,
    pub chain_id: String,
    pub steps: Vec<ChainStep>,
    pub edges: Vec<ChainEdge>,
    pub definition_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ChainStepRun {
    pub step: String,
    pub transform_run_id: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformChainRun {
    pub run_id: String,
    pub namespace: String,
    pub chain_id: String,
    pub definition_digest: String,
    #[serde(default)]
    pub definition_json: String,
    #[serde(default)]
    pub tenant_id: String,
    pub identity: String,
    pub status: String,
    #[serde(default)]
    pub failed_step: String,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub steps: Vec<ChainStepRun>,
    pub created_at_ms: i64,
    #[serde(default)]
    pub completed_at_ms: i64,
    #[serde(default)]
    pub input_digest: String,
    #[serde(default)]
    pub output_digest: String,
}

impl TransformChain {
    pub fn prepare(mut self) -> Result<Self, TransformError> {
        if self.contract_version != CHAIN_CONTRACT {
            return Err(TransformError::InvalidArgument(
                "unsupported transform-chain contract version".into(),
            ));
        }
        require_token("namespace", &self.namespace)?;
        require_token("chain_id", &self.chain_id)?;
        if self.steps.is_empty() {
            return Err(TransformError::InvalidArgument(
                "transform chain requires at least one step".into(),
            ));
        }
        let mut names = BTreeSet::new();
        for step in &self.steps {
            require_token("step.name", &step.name)?;
            require_token("step.transform_id", &step.transform_id)?;
            if !names.insert(step.name.as_str()) {
                return Err(TransformError::InvalidArgument(format!(
                    "duplicate chain step name {}",
                    step.name
                )));
            }
            for assertion in &step.assertions {
                validate_assertion(assertion)?;
            }
        }
        for edge in &self.edges {
            require_token("edge.from_step", &edge.from_step)?;
            require_token("edge.output", &edge.output)?;
            require_token("edge.to_step", &edge.to_step)?;
            require_token("edge.input", &edge.input)?;
            if !names.contains(edge.from_step.as_str()) || !names.contains(edge.to_step.as_str()) {
                return Err(TransformError::InvalidArgument(CHAIN_MISSING_NAME.into()));
            }
        }
        if chain_has_cycle(&self) {
            return Err(TransformError::InvalidArgument(CHAIN_CYCLE.into()));
        }
        self.definition_digest = chain_digest(&self);
        Ok(self)
    }

    pub fn step(&self, name: &str) -> Option<&ChainStep> {
        self.steps.iter().find(|step| step.name == name)
    }

    pub fn topo_order(&self) -> Vec<&ChainStep> {
        let mut remaining: BTreeMap<&str, u32> = self
            .steps
            .iter()
            .map(|step| (step.name.as_str(), 0))
            .collect();
        for edge in &self.edges {
            if let Some(count) = remaining.get_mut(edge.to_step.as_str()) {
                *count = count.saturating_add(1);
            }
        }
        let mut ready: Vec<&str> = remaining
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(name, _)| *name)
            .collect();
        ready.sort_unstable();
        let mut order = Vec::new();
        while let Some(name) = ready.first().copied() {
            ready.remove(0);
            if let Some(step) = self.step(name) {
                order.push(step);
            }
            remaining.remove(name);
            let mut unlocked = Vec::new();
            for edge in &self.edges {
                if edge.from_step == name
                    && let Some(count) = remaining.get_mut(edge.to_step.as_str())
                {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        unlocked.push(edge.to_step.as_str());
                    }
                }
            }
            unlocked.sort_unstable();
            ready.extend(unlocked);
            ready.sort_unstable();
            ready.dedup();
        }
        order
    }
}

impl TransformChainRun {
    pub fn step_status(&self, name: &str) -> Option<&str> {
        self.steps
            .iter()
            .find(|step| step.step == name)
            .map(|step| step.status.as_str())
    }

    pub fn step_run_id(&self, name: &str) -> Option<&str> {
        self.steps
            .iter()
            .find(|step| step.step == name)
            .map(|step| step.transform_run_id.as_str())
    }

    pub fn record_step(&mut self, name: &str, transform_run_id: &str, status: &str) {
        if let Some(existing) = self.steps.iter_mut().find(|step| step.step == name) {
            existing.transform_run_id = transform_run_id.to_string();
            existing.status = status.to_string();
            return;
        }
        self.steps.push(ChainStepRun {
            step: name.to_string(),
            transform_run_id: transform_run_id.to_string(),
            status: status.to_string(),
        });
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status.as_str(),
            CHAIN_WORK_COMPLETED | CHAIN_WORK_FAILED | CHAIN_WORK_CANCELLED
        )
    }
}

pub fn chain_run_identity(idempotency_key: &str) -> String {
    idempotency_key.to_string()
}

pub fn compile_named_edges(
    chain: &TransformChain,
    transforms: &BTreeMap<String, GovernedTransform>,
) -> Result<Vec<(ChainEdge, String)>, TransformError> {
    let mut compiled = Vec::new();
    for edge in &chain.edges {
        let from = chain.step(&edge.from_step).ok_or_else(|| {
            TransformError::InvalidArgument(format!("{CHAIN_MISSING_NAME}: {}", edge.from_step))
        })?;
        let to = chain.step(&edge.to_step).ok_or_else(|| {
            TransformError::InvalidArgument(format!("{CHAIN_MISSING_NAME}: {}", edge.to_step))
        })?;
        let from_transform = transforms
            .get(&from.transform_id)
            .ok_or(TransformError::NotFound("governed transform not found"))?;
        let to_transform = transforms
            .get(&to.transform_id)
            .ok_or(TransformError::NotFound("governed transform not found"))?;
        let from_dataset = resolve_named_output(from_transform, &edge.output)?;
        let to_dataset = resolve_named_input(to_transform, &edge.input)?;
        if from_dataset != to_dataset {
            return Err(TransformError::InvalidArgument(
                CHAIN_DATASET_MISMATCH.into(),
            ));
        }
        compiled.push((edge.clone(), from_dataset));
    }
    Ok(compiled)
}

pub fn evaluate_assertions(
    assertions: &[ChainAssertion],
    rows: &[HashMap<String, String>],
) -> Result<(), TransformError> {
    for assertion in assertions {
        match assertion.kind.as_str() {
            CHAIN_ASSERT_NOT_NULL => {
                require_token("assertion.column", &assertion.column)?;
                if rows.iter().any(|row| {
                    row.get(&assertion.column)
                        .is_none_or(|value| value.trim().is_empty())
                }) {
                    return Err(TransformError::InvalidArgument(format!(
                        "assertion not_null failed on {}",
                        assertion.column
                    )));
                }
            }
            CHAIN_ASSERT_UNIQUE => {
                require_token("assertion.column", &assertion.column)?;
                let mut seen = BTreeSet::new();
                for row in rows {
                    let value = row.get(&assertion.column).map(String::as_str).unwrap_or("");
                    if !seen.insert(value) {
                        return Err(TransformError::InvalidArgument(format!(
                            "assertion unique failed on {}",
                            assertion.column
                        )));
                    }
                }
            }
            CHAIN_ASSERT_ROW_COUNT_MIN => {
                let min = parse_bound(&assertion.value)?;
                if rows.len() < min {
                    return Err(TransformError::InvalidArgument(format!(
                        "assertion row_count_min failed: {} < {min}",
                        rows.len()
                    )));
                }
            }
            CHAIN_ASSERT_ROW_COUNT_MAX => {
                let max = parse_bound(&assertion.value)?;
                if rows.len() > max {
                    return Err(TransformError::InvalidArgument(format!(
                        "assertion row_count_max failed: {} > {max}",
                        rows.len()
                    )));
                }
            }
            CHAIN_ASSERT_ACCEPTED_VALUES => {
                require_token("assertion.column", &assertion.column)?;
                require_token("assertion.value", &assertion.value)?;
                let allowed: BTreeSet<&str> = assertion
                    .value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .collect();
                if rows.iter().any(|row| {
                    !allowed.contains(row.get(&assertion.column).map(String::as_str).unwrap_or(""))
                }) {
                    return Err(TransformError::InvalidArgument(format!(
                        "assertion accepted_values failed on {}",
                        assertion.column
                    )));
                }
            }
            other => {
                return Err(TransformError::InvalidArgument(format!(
                    "unsupported chain assertion {other}"
                )));
            }
        }
    }
    Ok(())
}

/// TransformRun-shaped chain receipt so ADR 0114 keeps `ReceiptKind::TransformRun`.
pub fn chain_receipt(
    run: &TransformChainRun,
    input_digest: &str,
    output_digest: &str,
) -> TransformRun {
    let step_runs: BTreeMap<&str, &str> = run
        .steps
        .iter()
        .map(|step| (step.step.as_str(), step.transform_run_id.as_str()))
        .collect();
    let trigger_ref = serde_json::to_string(&step_runs).unwrap_or_else(|_| "{}".into());
    TransformRun {
        run_id: run.run_id.clone(),
        namespace: run.namespace.clone(),
        transform_id: run.chain_id.clone(),
        definition_digest: run.definition_digest.clone(),
        input_digest: input_digest.to_string(),
        output_digest: output_digest.to_string(),
        last_input_row_id: 0,
        incremental: false,
        quarantined: run.status == CHAIN_WORK_FAILED || run.status == CHAIN_WORK_CANCELLED,
        quality_rule: run.error.clone(),
        rows_in: 0,
        rows_out: 0,
        lineage_parent: String::new(),
        created_at_ms: run.created_at_ms,
        markings_in: String::new(),
        markings_out: String::new(),
        profile: CHAIN_PROFILE.into(),
        engine: String::new(),
        runtime_image: String::new(),
        dispatch_status: run.status.clone(),
        trigger_cause: CHAIN_PROFILE.into(),
        trigger_ref,
        input_partitions: Vec::new(),
        output_partitions: Vec::new(),
        input_versions: BTreeMap::new(),
    }
}

fn require_token(field: &str, value: &str) -> Result<(), TransformError> {
    if value.trim().is_empty() {
        return Err(TransformError::InvalidArgument(format!("{field} required")));
    }
    Ok(())
}

fn validate_assertion(assertion: &ChainAssertion) -> Result<(), TransformError> {
    require_token("assertion.kind", &assertion.kind)?;
    match assertion.kind.as_str() {
        CHAIN_ASSERT_NOT_NULL | CHAIN_ASSERT_UNIQUE => {
            require_token("assertion.column", &assertion.column)
        }
        CHAIN_ASSERT_ROW_COUNT_MIN | CHAIN_ASSERT_ROW_COUNT_MAX => {
            parse_bound(&assertion.value).map(|_| ())
        }
        CHAIN_ASSERT_ACCEPTED_VALUES => {
            require_token("assertion.column", &assertion.column)?;
            require_token("assertion.value", &assertion.value)
        }
        other => Err(TransformError::InvalidArgument(format!(
            "unsupported chain assertion {other}"
        ))),
    }
}

fn parse_bound(value: &str) -> Result<usize, TransformError> {
    value.parse::<usize>().map_err(|_| {
        TransformError::InvalidArgument(
            "chain assertion bound must be a non-negative integer".into(),
        )
    })
}

fn resolve_named_output(
    transform: &GovernedTransform,
    name: &str,
) -> Result<String, TransformError> {
    let mut matches = Vec::new();
    if name == CHAIN_NAMED_OUTPUT || name == transform.output_dataset_id {
        matches.push(transform.output_dataset_id.clone());
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [dataset] => Ok(dataset.clone()),
        [] => Err(TransformError::InvalidArgument(format!(
            "{CHAIN_MISSING_NAME}: {name}"
        ))),
        _ => Err(TransformError::InvalidArgument(format!(
            "{CHAIN_AMBIGUOUS_NAME}: {name}"
        ))),
    }
}

fn resolve_named_input(
    transform: &GovernedTransform,
    name: &str,
) -> Result<String, TransformError> {
    let mut datasets = Vec::new();
    for (alias, dataset_id) in transform.input_bindings() {
        if name == alias || name == dataset_id {
            datasets.push(dataset_id);
        }
    }
    datasets.sort();
    datasets.dedup();
    match datasets.as_slice() {
        [dataset] => Ok(dataset.clone()),
        [] => Err(TransformError::InvalidArgument(format!(
            "{CHAIN_MISSING_NAME}: {name}"
        ))),
        _ => Err(TransformError::InvalidArgument(format!(
            "{CHAIN_AMBIGUOUS_NAME}: {name}"
        ))),
    }
}

fn chain_has_cycle(chain: &TransformChain) -> bool {
    chain.topo_order().len() != chain.steps.len()
}

fn chain_digest(chain: &TransformChain) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, CHAIN_CONTRACT);
    hash_field(&mut hasher, &chain.namespace);
    hash_field(&mut hasher, &chain.chain_id);
    if let Ok(steps) = serde_json::to_vec(&chain.steps) {
        hasher.update((steps.len() as u64).to_le_bytes());
        hasher.update(steps);
    }
    if let Ok(edges) = serde_json::to_vec(&chain.edges) {
        hasher.update((edges.len() as u64).to_le_bytes());
        hasher.update(edges);
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governed_transform::CONTRACT_VERSION;

    fn transform(id: &str, input: &str, output: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: id.into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: "sha256:x".into(),
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
    }

    fn chain() -> TransformChain {
        TransformChain {
            contract_version: CHAIN_CONTRACT.into(),
            namespace: "ops".into(),
            chain_id: "pipe".into(),
            steps: vec![
                ChainStep {
                    name: "a".into(),
                    transform_id: "t1".into(),
                    transform_digest: String::new(),
                    assertions: Vec::new(),
                },
                ChainStep {
                    name: "b".into(),
                    transform_id: "t2".into(),
                    transform_digest: String::new(),
                    assertions: Vec::new(),
                },
                ChainStep {
                    name: "c".into(),
                    transform_id: "t3".into(),
                    transform_digest: String::new(),
                    assertions: Vec::new(),
                },
            ],
            edges: vec![
                ChainEdge {
                    from_step: "a".into(),
                    output: "mid1".into(),
                    to_step: "b".into(),
                    input: "mid1".into(),
                },
                ChainEdge {
                    from_step: "b".into(),
                    output: "output".into(),
                    to_step: "c".into(),
                    input: "mid2".into(),
                },
            ],
            definition_digest: String::new(),
        }
        .prepare()
        .unwrap()
    }

    #[test]
    fn prepare_refuses_cycles_and_duplicate_names() {
        let mut cyclic = chain();
        cyclic.definition_digest.clear();
        cyclic.edges.push(ChainEdge {
            from_step: "c".into(),
            output: "out".into(),
            to_step: "a".into(),
            input: "in".into(),
        });
        assert!(cyclic.prepare().is_err());
        let mut dup = chain();
        dup.definition_digest.clear();
        dup.steps.push(ChainStep {
            name: "a".into(),
            transform_id: "t9".into(),
            transform_digest: String::new(),
            assertions: Vec::new(),
        });
        assert!(dup.prepare().is_err());
    }

    #[test]
    fn named_edges_compile_or_refuse() {
        let chain = chain();
        let mut transforms = BTreeMap::new();
        transforms.insert("t1".into(), transform("t1", "in", "mid1"));
        transforms.insert("t2".into(), transform("t2", "mid1", "mid2"));
        transforms.insert("t3".into(), transform("t3", "mid2", "out"));
        let compiled = compile_named_edges(&chain, &transforms).unwrap();
        assert_eq!(compiled.len(), 2);
        assert_eq!(compiled[0].1, "mid1");
        assert_eq!(compiled[1].1, "mid2");

        let mut missing = chain.clone();
        missing.edges[0].output = "nope".into();
        assert!(compile_named_edges(&missing, &transforms).is_err());

        transforms.insert("t2".into(), transform("t2", "other", "mid2"));
        assert!(compile_named_edges(&chain, &transforms).is_err());
    }

    #[test]
    fn assertions_fail_closed() {
        let rows = vec![
            HashMap::from([("id".into(), "1".into()), ("keep".into(), "yes".into())]),
            HashMap::from([("id".into(), "2".into()), ("keep".into(), "yes".into())]),
        ];
        evaluate_assertions(
            &[ChainAssertion {
                kind: CHAIN_ASSERT_NOT_NULL.into(),
                column: "id".into(),
                value: String::new(),
            }],
            &rows,
        )
        .unwrap();
        assert!(
            evaluate_assertions(
                &[ChainAssertion {
                    kind: CHAIN_ASSERT_NOT_NULL.into(),
                    column: "missing".into(),
                    value: String::new(),
                }],
                &rows,
            )
            .is_err()
        );
        assert!(
            evaluate_assertions(
                &[ChainAssertion {
                    kind: CHAIN_ASSERT_UNIQUE.into(),
                    column: "keep".into(),
                    value: String::new(),
                }],
                &rows,
            )
            .is_err()
        );
        evaluate_assertions(
            &[ChainAssertion {
                kind: CHAIN_ASSERT_ROW_COUNT_MIN.into(),
                column: String::new(),
                value: "2".into(),
            }],
            &rows,
        )
        .unwrap();
        assert!(
            evaluate_assertions(
                &[ChainAssertion {
                    kind: CHAIN_ASSERT_ACCEPTED_VALUES.into(),
                    column: "keep".into(),
                    value: "no".into(),
                }],
                &rows,
            )
            .is_err()
        );
    }

    #[test]
    fn chain_receipt_classifies_as_transform_run() {
        let run = TransformChainRun {
            run_id: "cr1".into(),
            namespace: "ops".into(),
            chain_id: "pipe".into(),
            definition_digest: "sha256:abc".into(),
            definition_json: String::new(),
            tenant_id: String::new(),
            identity: "k".into(),
            status: CHAIN_WORK_FAILED.into(),
            failed_step: "b".into(),
            error: "cancelled".into(),
            steps: vec![ChainStepRun {
                step: "a".into(),
                transform_run_id: "r1".into(),
                status: CHAIN_WORK_COMPLETED.into(),
            }],
            created_at_ms: 10,
            completed_at_ms: 20,
            input_digest: String::new(),
            output_digest: String::new(),
        };
        let receipt = chain_receipt(&run, "in", "out");
        assert_eq!(receipt.profile, CHAIN_PROFILE);
        assert!(receipt.quarantined);
        assert!(receipt.trigger_ref.contains("r1"));
        let json = serde_json::to_string(&receipt).unwrap();
        assert_eq!(
            crate::receipt_chain::classify_receipt_json(&json).unwrap(),
            crate::receipt_chain::ReceiptKind::TransformRun
        );
    }
}
