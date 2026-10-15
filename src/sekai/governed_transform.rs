//! Plane-owned incremental dataset transforms (#880, #1287, #1385, #1386, #1387).
//!
//! Definitions are content-addressed and receipt-bound. Execution is the
//! in-process `projection` host of `sekai.governed-transform-execution/v1`,
//! the analytical SQL profile on the same JobSpec ([ADR 0101]), or the
//! isolated-process profile that admits work for an external runner
//! ([ADR 0102]). The plane admits scheduled and change-triggered runs
//! ([ADR 0103]) and owns the JobSpec, transaction, lineage, and run
//! receipt. Outputs are datasets, not type-revision object identity. Secrets
//! are rejected in definitions.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

pub const CONTRACT_VERSION: &str = "sekai.governed-transform/v1";
pub const TRANSFORM_CLASS: &str = "projection";
pub const ANALYTICAL_CLASS: &str = "analytical";
pub const ISOLATED_CLASS: &str = "isolated_process";
/// DiscoverCapabilities name for the in-process transform host.
pub const HOSTED_COMPUTE_CAPABILITY: &str = "sekai.transforms.projection";
/// DiscoverCapabilities name for the analytical SQL profile.
pub const ANALYTICAL_COMPUTE_CAPABILITY: &str = "sekai.transforms.analytical";
/// DiscoverCapabilities name for the isolated-process JobSpec profile.
pub const ISOLATED_COMPUTE_CAPABILITY: &str = "sekai.transforms.isolated_process";
/// DiscoverCapabilities name for unsaved preview runs (ADR 0110).
pub const PREVIEW_COMPUTE_CAPABILITY: &str = "sekai.transforms.preview";
/// Preview identities are never governed run ids.
pub const PREVIEW_ID_PREFIX: &str = "preview:";
/// Default sample rows per input when PreviewGovernedTransform omits row_cap.
pub const DEFAULT_PREVIEW_ROW_CAP: usize = 256;
/// Plane maximum sample rows per input.
pub const MAX_PREVIEW_ROW_CAP: usize = 1024;
/// Requested row_cap exceeded the plane maximum.
pub const PREVIEW_ROW_CAP: &str = "transform_preview_row_cap";
pub const PREVIEW_RESULT_ALIAS: &str = "__preview_result";
pub const PREVIEW_AUTH_ALIAS: &str = "__preview_auth";
/// DiscoverCapabilities name for scheduled and change-triggered admission.
pub const SCHEDULER_COMPUTE_CAPABILITY: &str = "sekai.transforms.scheduler";
pub const TRANSFORM_WORK_PENDING: &str = "pending";
pub const TRANSFORM_WORK_CLAIMED: &str = "claimed";
pub const TRANSFORM_WORK_COMPLETED: &str = "completed";
pub const TRANSFORM_WORK_FAILED: &str = "failed";
pub const TRANSFORM_WORK_CANCELLED: &str = "cancelled";
pub const TRANSFORM_TRIGGER_MANUAL: &str = "manual";
pub const TRANSFORM_TRIGGER_SCHEDULE: &str = "schedule";
pub const TRANSFORM_TRIGGER_UPSTREAM: &str = "upstream";
pub const TRANSFORM_TRIGGER_SOURCE_BATCH: &str = "source_batch";
pub const TRANSFORM_TRIGGER_CANCELLED: &str = "cancelled";
pub const TRANSFORM_OUTPUT_FRESH: &str = "fresh";
pub const TRANSFORM_OUTPUT_STALE: &str = "stale";
pub const TRANSFORM_OUTPUT_BLOCKED: &str = "blocked";
pub const TRANSFORM_DEPENDENCY_CYCLE: &str = "transform dependency cycle";
pub const DEFAULT_TRANSFORM_TENANT_CONCURRENCY: i64 = 4;
pub const DEFAULT_TRANSFORM_CLAIM_TTL_MS: i64 = 60_000;
pub const MAX_TRANSFORM_LEASE_EXPIRIES: i64 = 3;
pub const MAX_TRANSFORM_CLAIM_QUOTA_SKIPS: usize = 16;
pub const STALE_TRANSFORM_CLAIM: &str = "stale transform claim";
pub const STALE_TRANSFORM_ADMISSION: &str = "stale isolated transform admission";
pub const TRANSFORM_DIGEST_MISMATCH: &str = "transform output digest mismatch";
pub const TRANSFORM_DEFINITION_CHANGED: &str = "transform definition changed";
/// Order-independent 256-bit sum of per-row SHA-256 hashes.
/// Reference-platform analog: governed incremental `semantic_version` / `v2_semantics`
/// force a SNAPSHOT rebuild; old encodings are not folded as the new sum.
pub const OUTPUT_DIGEST_PREFIX: &str = "sha256-sum-v1:";
/// Sorted map of partition identity to `sha256-sum-v1:` member digest.
/// Does not fold into `OUTPUT_DIGEST_PREFIX` (#1358 / ADR 0103).
pub const PARTITIONED_DIGEST_PREFIX: &str = "sha256-partitions-v1:";
/// Receipt identity when the caller cannot read the bound datasets.
/// Not derived from the partition value, so it is not dictionary-attackable.
pub const REDACTED_PARTITION_IDENTITY: &str = "redacted";
pub const DATASET_PARTITION_CONTRACT: &str = "sekai.dataset-partition/v1";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransformStep {
    pub kind: String,
    pub column: String,
    pub op: String,
    pub value: String,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransformInput {
    pub alias: String,
    pub dataset_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AnalyticalSpec {
    #[serde(default)]
    pub inputs: Vec<TransformInput>,
    #[serde(default)]
    pub sql: String,
    #[serde(default)]
    pub memory_limit_bytes: u64,
    #[serde(default)]
    pub time_limit_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IsolatedProcessSpec {
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub runtime_image: String,
    #[serde(default)]
    pub inputs: Vec<TransformInput>,
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
    /// Absent on the `projection` profile so existing definition digests stay
    /// stable. Present for the analytical SQL profile (#1385).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analytical: Option<AnalyticalSpec>,
    /// Absent on in-process profiles so existing definition digests stay
    /// stable. Present for the isolated-process JobSpec (#1386).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolated_process: Option<IsolatedProcessSpec>,
    /// Absent unless the definition carries a due interval (#1387).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<TransformSchedule>,
    /// Absent unless a committed input or source batch should admit a run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<TransformTrigger>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransformSchedule {
    pub every_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransformTrigger {
    #[serde(default)]
    pub on_input_commit: bool,
    #[serde(default)]
    pub debounce_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransformOutputState {
    pub namespace: String,
    pub dataset_id: String,
    pub freshness: String,
    pub upstream_version: String,
    pub blocked_run_id: String,
    pub updated_at_ms: i64,
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
    /// Unique input marking tokens for this run, comma-separated.
    #[serde(default)]
    pub markings_in: String,
    /// Union of input markings written on the output, empty when unmarked.
    #[serde(default)]
    pub markings_out: String,
    /// JobSpec profile recorded on the receipt. Empty on historical in-process
    /// rows; `isolated_process` when the run is admitted for an external worker.
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub runtime_image: String,
    /// Empty for in-process compute. `pending` / `claimed` / `completed` /
    /// `failed` for isolated-process dispatch.
    #[serde(default)]
    pub dispatch_status: String,
    /// Why this run was admitted: `manual`, `schedule`, `upstream`,
    /// `source_batch`, or `cancelled`. Empty on historical rows.
    #[serde(default)]
    pub trigger_cause: String,
    /// Schedule bucket, upstream run id, source batch digest, or cancelled run.
    #[serde(default)]
    pub trigger_ref: String,
    /// Partitions read for this run. Empty on unpartitioned historical rows.
    #[serde(default)]
    pub input_partitions: Vec<TransformPartition>,
    /// Partitions written for this run. Empty on unpartitioned historical rows.
    #[serde(default)]
    pub output_partitions: Vec<TransformPartition>,
}

/// Rows read from one preview input after policy and the sample cap.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PreviewInputStat {
    pub alias: String,
    pub dataset_id: String,
    pub rows_read: i32,
}

/// Non-committing preview result. `preview_id` is not a governed run id.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreviewGovernedTransformResult {
    pub preview_id: String,
    pub output_schema_json: String,
    pub rows: Vec<HashMap<String, String>>,
    pub inputs: Vec<PreviewInputStat>,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransformWork {
    pub run_id: String,
    pub namespace: String,
    pub transform_id: String,
    pub definition_digest: String,
    pub engine: String,
    pub runtime_image: String,
    pub status: String,
    pub claim_owner: String,
    pub claim_generation: i64,
    pub fencing_token: String,
    pub claim_expires_at_ms: i64,
    pub lease_expiries: i64,
    pub created_at_ms: i64,
    /// Submitting tenant captured at enqueue. Empty on community runs.
    /// Claim and list responses carry this so a runner keys quotas on the
    /// owner, not the namespace.
    #[serde(default)]
    pub tenant_id: String,
}

#[derive(Debug, Default)]
pub struct ClaimTransformWorkOutcome {
    pub claimed: Option<(TransformWork, GovernedTransform)>,
    pub failed_run_ids: Vec<String>,
    pub counted_lease_expiry: bool,
}

/// In-process scheduled or triggered work that has a Put quota owner.
/// Tick skips these so the RPC can admit tenant quota before the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueOwnedInProcessTransform {
    pub namespace: String,
    pub transform_id: String,
    pub tenant_id: String,
    pub cause: String,
    pub cause_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransformRunInputRow {
    pub alias: String,
    pub dataset_id: String,
    pub row_id: i64,
    pub values: HashMap<String, String>,
    pub partition_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TransformPartition {
    pub partition_key: String,
    pub digest: String,
    pub rows: i32,
    #[serde(default)]
    pub dataset_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransformPartitionWrite {
    pub partition_key: String,
    pub rows: Vec<HashMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteTransformRunCommand {
    pub run_id: String,
    pub runtime_id: String,
    pub claim_generation: i64,
    pub fencing_token: String,
    pub rows: Vec<HashMap<String, String>>,
    pub output_digest: String,
    pub quarantined: bool,
    pub quality_rule: String,
    pub replaced_partitions: Vec<TransformPartitionWrite>,
    pub partition_key: Option<String>,
    pub max_bytes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreparedPartitionCommit {
    pub envelope_digest: String,
    pub written: Vec<TransformPartition>,
    pub replacements: Vec<(String, Vec<HashMap<String, String>>)>,
    pub merged_rows: Vec<HashMap<String, String>>,
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
        require_token("output_dataset_id", &self.output_dataset_id)?;
        if self.analytical.is_some() && self.isolated_process.is_some() {
            return Err(TransformError::InvalidArgument(
                "cannot combine analytical and isolated_process profiles".into(),
            ));
        }
        if let Some(spec) = self.isolated_process.as_mut() {
            prepare_isolated(&mut self.input_dataset_id, spec, &self.steps)?;
        } else if let Some(spec) = self.analytical.as_mut() {
            prepare_analytical(&mut self.input_dataset_id, spec, &self.steps)?;
        } else {
            require_token("input_dataset_id", &self.input_dataset_id)?;
            if self.steps.is_empty() {
                return Err(TransformError::InvalidArgument(
                    "transform steps required".into(),
                ));
            }
        }
        if self
            .input_bindings()
            .iter()
            .any(|(_, dataset_id)| dataset_id == &self.output_dataset_id)
        {
            return Err(TransformError::InvalidArgument(
                "transform output must be a distinct dataset".into(),
            ));
        }
        reject_secrets(&self)?;
        if let Some(schedule) = &self.schedule
            && schedule.every_ms <= 0
        {
            return Err(TransformError::InvalidArgument(
                "schedule.every_ms must be positive".into(),
            ));
        }
        if let Some(trigger) = &self.trigger {
            if !trigger.on_input_commit {
                return Err(TransformError::InvalidArgument(
                    "trigger requires on_input_commit".into(),
                ));
            }
            if trigger.debounce_ms < 0 {
                return Err(TransformError::InvalidArgument(
                    "trigger.debounce_ms must be >= 0".into(),
                ));
            }
        }
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

    pub fn is_analytical(&self) -> bool {
        self.analytical.is_some()
    }

    pub fn is_isolated_process(&self) -> bool {
        self.isolated_process.is_some()
    }

    /// Compiled filter/project steps keep the projection watermark.
    /// Explicit SQL always rebuilds from all input rows. Isolated-process
    /// runs always rebuild; the worker owns incrementality.
    pub fn allows_incremental(&self) -> bool {
        if self.isolated_process.is_some() {
            return false;
        }
        match &self.analytical {
            None => true,
            Some(spec) if spec.inputs.len() > 1 || self.steps.is_empty() => false,
            Some(spec) => {
                let alias = spec
                    .inputs
                    .first()
                    .map(|input| input.alias.as_str())
                    .unwrap_or("input");
                crate::sekai::transform_engine::compile_steps_sql(&self.steps, alias)
                    .is_ok_and(|sql| sql == spec.sql)
            }
        }
    }

    /// Alias + dataset_id pairs the run path must load.
    pub fn input_bindings(&self) -> Vec<(String, String)> {
        if let Some(spec) = &self.isolated_process
            && !spec.inputs.is_empty()
        {
            return spec
                .inputs
                .iter()
                .map(|input| (input.alias.clone(), input.dataset_id.clone()))
                .collect();
        }
        if let Some(spec) = &self.analytical
            && !spec.inputs.is_empty()
        {
            return spec
                .inputs
                .iter()
                .map(|input| (input.alias.clone(), input.dataset_id.clone()))
                .collect();
        }
        let alias = if self.is_analytical() || self.is_isolated_process() {
            "input".to_string()
        } else {
            self.input_dataset_id.clone()
        };
        vec![(alias, self.input_dataset_id.clone())]
    }

    pub fn consumes_dataset(&self, dataset_id: &str) -> bool {
        self.input_bindings()
            .iter()
            .any(|(_, bound)| bound == dataset_id)
    }

    pub fn change_trigger(&self) -> Option<&TransformTrigger> {
        self.trigger
            .as_ref()
            .filter(|trigger| trigger.on_input_commit)
    }
}

impl TransformRun {
    pub fn stamp_trigger(&mut self, cause: &str, reference: &str) {
        if self.trigger_cause.is_empty() {
            self.trigger_cause = cause.to_string();
            self.trigger_ref = reference.to_string();
        }
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
    if let Some(spec) = &transform.analytical {
        hash_field(&mut hasher, ANALYTICAL_CLASS);
        hash_field(&mut hasher, &spec.sql);
        hasher.update(spec.memory_limit_bytes.to_le_bytes());
        hasher.update(spec.time_limit_ms.to_le_bytes());
        if let Ok(inputs) = serde_json::to_vec(&spec.inputs) {
            hasher.update((inputs.len() as u64).to_le_bytes());
            hasher.update(inputs);
        }
    }
    if let Some(spec) = &transform.isolated_process {
        hash_field(&mut hasher, ISOLATED_CLASS);
        hash_field(&mut hasher, &spec.engine);
        hash_field(&mut hasher, &spec.runtime_image);
        if let Ok(inputs) = serde_json::to_vec(&spec.inputs) {
            hasher.update((inputs.len() as u64).to_le_bytes());
            hasher.update(inputs);
        }
    }
    if let Some(schedule) = &transform.schedule {
        hash_field(&mut hasher, "schedule");
        hasher.update(schedule.every_ms.to_le_bytes());
    }
    if let Some(trigger) = &transform.trigger {
        hash_field(&mut hasher, "trigger");
        hasher.update([u8::from(trigger.on_input_commit)]);
        hasher.update(trigger.debounce_ms.to_le_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub fn refuse_dependency_cycle(
    published: &[GovernedTransform],
    incoming: &GovernedTransform,
) -> Result<(), TransformError> {
    let mut graph: Vec<GovernedTransform> = published
        .iter()
        .filter(|transform| {
            transform.namespace != incoming.namespace
                || transform.transform_id != incoming.transform_id
        })
        .cloned()
        .collect();
    graph.push(incoming.clone());
    if dependency_graph_has_cycle(&graph) {
        return Err(TransformError::InvalidArgument(
            TRANSFORM_DEPENDENCY_CYCLE.into(),
        ));
    }
    Ok(())
}

pub fn schedule_bucket(every_ms: i64, now_ms: i64) -> i64 {
    if every_ms <= 0 { 0 } else { now_ms / every_ms }
}

pub fn schedule_due_bucket(last_bucket: Option<i64>, every_ms: i64, now_ms: i64) -> Option<i64> {
    if every_ms <= 0 {
        return None;
    }
    let bucket = schedule_bucket(every_ms, now_ms);
    match last_bucket {
        Some(last) if last >= bucket => None,
        _ => Some(bucket),
    }
}

pub fn trigger_is_due(first_seen_ms: i64, debounce_ms: i64, now_ms: i64) -> bool {
    now_ms.saturating_sub(first_seen_ms) >= debounce_ms.max(0)
}

fn dependency_graph_has_cycle(transforms: &[GovernedTransform]) -> bool {
    let mut producers: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, transform) in transforms.iter().enumerate() {
        producers
            .entry(transform.output_dataset_id.clone())
            .or_default()
            .push(index);
    }
    let mut adj = vec![Vec::new(); transforms.len()];
    for (consumer, transform) in transforms.iter().enumerate() {
        for (_, dataset_id) in transform.input_bindings() {
            if let Some(upstreams) = producers.get(&dataset_id) {
                for &producer in upstreams {
                    if producer != consumer {
                        adj[producer].push(consumer);
                    }
                }
            }
        }
    }
    let mut state = vec![0u8; transforms.len()];
    (0..transforms.len()).any(|node| state[node] == 0 && graph_cycle_from(node, &adj, &mut state))
}

fn graph_cycle_from(node: usize, adj: &[Vec<usize>], state: &mut [u8]) -> bool {
    state[node] = 1;
    for &next in &adj[node] {
        if state[next] == 1 {
            return true;
        }
        if state[next] == 0 && graph_cycle_from(next, adj, state) {
            return true;
        }
    }
    state[node] = 2;
    false
}

fn prepare_analytical(
    input_dataset_id: &mut String,
    spec: &mut AnalyticalSpec,
    steps: &[TransformStep],
) -> Result<(), TransformError> {
    if spec.inputs.is_empty() {
        require_token("input_dataset_id", input_dataset_id)?;
        *input_dataset_id = input_dataset_id.trim().to_string();
        spec.inputs.push(TransformInput {
            alias: "input".into(),
            dataset_id: input_dataset_id.clone(),
        });
    } else {
        let mut seen = std::collections::BTreeSet::new();
        for input in spec.inputs.iter_mut() {
            input.alias = input.alias.trim().to_string();
            input.dataset_id = input.dataset_id.trim().to_string();
            require_token("input alias", &input.alias)?;
            require_token("input dataset_id", &input.dataset_id)?;
            if !seen.insert(input.alias.to_ascii_lowercase()) {
                return Err(TransformError::InvalidArgument(
                    "transform input aliases must be unique".into(),
                ));
            }
        }
        let first = spec.inputs[0].dataset_id.clone();
        let trimmed_input = input_dataset_id.trim().to_string();
        if trimmed_input.is_empty() {
            *input_dataset_id = first;
        } else if trimmed_input != first {
            return Err(TransformError::InvalidArgument(
                "input_dataset_id must match the first analytical input".into(),
            ));
        } else {
            *input_dataset_id = trimmed_input;
        }
    }
    if spec.sql.trim().is_empty() {
        if steps.is_empty() {
            return Err(TransformError::InvalidArgument(
                "analytical transform requires sql or steps".into(),
            ));
        }
        if spec.inputs.len() > 1 {
            return Err(TransformError::InvalidArgument(
                "analytical steps require a single input or explicit sql".into(),
            ));
        }
        let alias = spec
            .inputs
            .first()
            .map(|input| input.alias.as_str())
            .unwrap_or("input");
        spec.sql = crate::sekai::transform_engine::compile_steps_sql(steps, alias)?;
    } else {
        crate::sekai::transform_engine::validate_analytical_sql(&spec.sql)?;
    }
    spec.memory_limit_bytes = crate::sekai::transform_engine::host_limit(
        spec.memory_limit_bytes,
        crate::sekai::transform_engine::DEFAULT_MEMORY_LIMIT_BYTES,
    );
    spec.time_limit_ms = crate::sekai::transform_engine::host_limit(
        spec.time_limit_ms,
        crate::sekai::transform_engine::DEFAULT_TIME_LIMIT_MS,
    );
    Ok(())
}

fn prepare_isolated(
    input_dataset_id: &mut String,
    spec: &mut IsolatedProcessSpec,
    steps: &[TransformStep],
) -> Result<(), TransformError> {
    if !steps.is_empty() {
        return Err(TransformError::InvalidArgument(
            "isolated_process profile rejects in-process steps".into(),
        ));
    }
    require_token("engine", &spec.engine)?;
    require_token("runtime_image", &spec.runtime_image)?;
    if spec.inputs.is_empty() {
        require_token("input_dataset_id", input_dataset_id)?;
        *input_dataset_id = input_dataset_id.trim().to_string();
        spec.inputs.push(TransformInput {
            alias: "input".into(),
            dataset_id: input_dataset_id.clone(),
        });
    } else {
        let mut seen = std::collections::BTreeSet::new();
        for input in spec.inputs.iter_mut() {
            input.alias = input.alias.trim().to_string();
            input.dataset_id = input.dataset_id.trim().to_string();
            require_token("input alias", &input.alias)?;
            require_token("input dataset_id", &input.dataset_id)?;
            if !seen.insert(input.alias.to_ascii_lowercase()) {
                return Err(TransformError::InvalidArgument(
                    "isolated_process input aliases must be unique".into(),
                ));
            }
        }
        let first = spec.inputs[0].dataset_id.clone();
        let trimmed_input = input_dataset_id.trim().to_string();
        if trimmed_input.is_empty() {
            *input_dataset_id = first;
        } else if trimmed_input != first {
            return Err(TransformError::InvalidArgument(
                "input_dataset_id must match the first isolated_process input".into(),
            ));
        } else {
            *input_dataset_id = trimmed_input;
        }
    }
    Ok(())
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

fn apply_profile(
    transform: &GovernedTransform,
    tables: &[crate::sekai::transform_engine::EngineTable],
    deadline: Option<std::time::Instant>,
) -> Result<Vec<HashMap<String, String>>, TransformError> {
    if transform.isolated_process.is_some() {
        return Err(TransformError::InvalidArgument(
            "isolated_process runs cannot execute in-process".into(),
        ));
    }
    if let Some(spec) = &transform.analytical {
        crate::sekai::transform_engine::execute_sql_until(
            &spec.sql,
            tables,
            spec.memory_limit_bytes,
            spec.time_limit_ms,
            deadline,
        )
    } else {
        Ok(apply_steps(
            tables
                .first()
                .map(|table| table.rows.as_slice())
                .unwrap_or(&[]),
            &transform.steps,
        ))
    }
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

/// Incremental selection requires the current JobSpec and a live output
/// digest in the current encoding. An old or malformed digest forces a
/// full rebuild (reference-platform snapshot) instead of folding.
pub fn bind_checkpoint(
    incremental: bool,
    checkpoint: Option<(TransformCheckpoint, String)>,
    definition_digest: &str,
    partition_keys: &[String],
) -> (bool, Option<TransformCheckpoint>) {
    match checkpoint {
        Some((pin, digest)) => (
            incremental
                && digest == definition_digest
                && live_output_digest_matches_keys(&pin.2, partition_keys),
            Some(pin),
        ),
        None => (false, None),
    }
}

/// Row id exclusive lower bound for an incremental read. Full rebuilds start at 0.
pub fn checkpoint_after_id(incremental: bool, checkpoint: Option<&TransformCheckpoint>) -> i64 {
    if incremental {
        checkpoint.map(|checkpoint| checkpoint.0).unwrap_or(0)
    } else {
        0
    }
}

/// Named input table for a multi-dataset analytical run.
pub struct TransformInputRows<'a> {
    pub alias: &'a str,
    pub records: &'a [(i64, HashMap<String, String>)],
    pub columns: &'a [String],
}

/// Compute one run. The caller persists `output_rows` (unless quarantined),
/// then fills `run.output_digest` with `fold_output_digest` (incremental) or
/// `rows_digest(&output_rows)` (full rebuild) and writes the receipt.
pub fn compute_run(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    input_records: &[(i64, HashMap<String, String>)],
    incremental: bool,
    now_ms: i64,
    run_id: String,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    compute_run_tables(
        transform,
        checkpoint,
        &[TransformInputRows {
            alias: "input",
            records: input_records,
            columns: &[],
        }],
        incremental,
        now_ms,
        run_id,
    )
}

pub fn compute_run_tables(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    inputs: &[TransformInputRows<'_>],
    incremental: bool,
    now_ms: i64,
    run_id: String,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    compute_run_tables_until(
        transform,
        checkpoint,
        inputs,
        incremental,
        now_ms,
        run_id,
        None,
    )
}

pub fn compute_run_tables_until(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    inputs: &[TransformInputRows<'_>],
    incremental: bool,
    now_ms: i64,
    run_id: String,
    deadline: Option<std::time::Instant>,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    let after_id = checkpoint_after_id(incremental, checkpoint);
    let mut last_input_row_id = after_id;
    let mut tables: Vec<crate::sekai::transform_engine::EngineTable> = Vec::new();
    let mut rows_in = 0i32;
    let mut used = 0u64;
    let memory_limit = transform.analytical.as_ref().map(|spec| {
        crate::sekai::transform_engine::host_limit(
            spec.memory_limit_bytes,
            crate::sekai::transform_engine::DEFAULT_MEMORY_LIMIT_BYTES,
        )
    });
    for input in inputs {
        let mut rows = Vec::new();
        for (id, row) in input.records {
            if *id <= after_id {
                continue;
            }
            last_input_row_id = last_input_row_id.max(*id);
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return quarantined_run(
                    transform,
                    checkpoint,
                    &tables,
                    after_id,
                    incremental,
                    now_ms,
                    run_id,
                    rows_in,
                    crate::sekai::transform_engine::BUDGET_TIME,
                );
            }
            if let Some(limit) = memory_limit {
                used = used.saturating_add(row_payload_bytes(row));
                if used > limit {
                    return quarantined_run(
                        transform,
                        checkpoint,
                        &tables,
                        after_id,
                        incremental,
                        now_ms,
                        run_id,
                        rows_in,
                        crate::sekai::transform_engine::BUDGET_MEMORY,
                    );
                }
            }
            rows.push(row.clone());
            rows_in += 1;
        }
        tables.push(crate::sekai::transform_engine::EngineTable {
            alias: input.alias.to_string(),
            rows,
            columns: input.columns.to_vec(),
        });
    }
    let output_rows = match apply_profile(transform, &tables, deadline) {
        Ok(rows) => rows,
        Err(error) => {
            return quarantined_run(
                transform,
                checkpoint,
                &tables,
                after_id,
                incremental,
                now_ms,
                run_id,
                rows_in,
                &error.message(),
            );
        }
    };
    if let Err(error) = evaluate_quality(&output_rows, &transform.quality_rule) {
        return quarantined_run(
            transform,
            checkpoint,
            &tables,
            after_id,
            incremental,
            now_ms,
            run_id,
            rows_in,
            &error.message(),
        );
    }
    let run = TransformRun {
        run_id,
        namespace: transform.namespace.clone(),
        transform_id: transform.transform_id.clone(),
        definition_digest: transform.definition_digest.clone(),
        input_digest: run_input_digest(transform, &tables),
        output_digest: String::new(),
        last_input_row_id,
        incremental,
        quarantined: false,
        quality_rule: transform.quality_rule.clone(),
        rows_in,
        rows_out: output_rows.len() as i32,
        lineage_parent: checkpoint
            .map(|checkpoint| checkpoint.1.clone())
            .unwrap_or_default(),
        created_at_ms: now_ms,
        markings_in: String::new(),
        markings_out: String::new(),
        profile: String::new(),
        engine: String::new(),
        runtime_image: String::new(),
        dispatch_status: String::new(),
        trigger_cause: String::new(),
        trigger_ref: String::new(),
        input_partitions: Vec::new(),
        output_partitions: Vec::new(),
    };
    (run, output_rows)
}

/// Admit an isolated-process run as pending work. The plane does not compute
/// output rows; a claimed worker writes them back under a fence.
pub fn admit_isolated_run(
    transform: &GovernedTransform,
    inputs: &[TransformInputRows<'_>],
    now_ms: i64,
    run_id: String,
) -> Result<TransformRun, TransformError> {
    let spec = transform.isolated_process.as_ref().ok_or_else(|| {
        TransformError::InvalidArgument("isolated_process profile required".into())
    })?;
    let mut last_input_row_id = 0i64;
    let mut tables: Vec<crate::sekai::transform_engine::EngineTable> = Vec::new();
    let mut rows_in = 0i32;
    for input in inputs {
        let mut rows = Vec::new();
        for (id, row) in input.records {
            last_input_row_id = last_input_row_id.max(*id);
            rows.push(row.clone());
            rows_in += 1;
        }
        tables.push(crate::sekai::transform_engine::EngineTable {
            alias: input.alias.to_string(),
            rows,
            columns: input.columns.to_vec(),
        });
    }
    Ok(TransformRun {
        run_id,
        namespace: transform.namespace.clone(),
        transform_id: transform.transform_id.clone(),
        definition_digest: transform.definition_digest.clone(),
        input_digest: run_input_digest(transform, &tables),
        output_digest: String::new(),
        last_input_row_id,
        incremental: false,
        quarantined: false,
        quality_rule: transform.quality_rule.clone(),
        rows_in,
        rows_out: 0,
        lineage_parent: String::new(),
        created_at_ms: now_ms,
        markings_in: String::new(),
        markings_out: String::new(),
        profile: ISOLATED_CLASS.into(),
        engine: spec.engine.clone(),
        runtime_image: spec.runtime_image.clone(),
        dispatch_status: TRANSFORM_WORK_PENDING.into(),
        trigger_cause: String::new(),
        trigger_ref: String::new(),
        input_partitions: Vec::new(),
        output_partitions: Vec::new(),
    })
}

pub fn normalize_transform_claim_ttl_ms(ttl_ms: i64) -> i64 {
    if ttl_ms <= 0 {
        DEFAULT_TRANSFORM_CLAIM_TTL_MS
    } else {
        ttl_ms.min(300_000)
    }
}

pub fn transform_work_is_claimable(work: &TransformWork, now_ms: i64) -> bool {
    match work.status.as_str() {
        TRANSFORM_WORK_PENDING => true,
        TRANSFORM_WORK_CLAIMED => {
            work.claim_expires_at_ms <= now_ms && work.lease_expiries < MAX_TRANSFORM_LEASE_EXPIRIES
        }
        TRANSFORM_WORK_CANCELLED | TRANSFORM_WORK_COMPLETED | TRANSFORM_WORK_FAILED => false,
        _ => false,
    }
}

/// Claim-time puts stay on CLAIMED so a delayed insert cannot land after
/// cancel. Restore after a taken hold may rewrite the row on the completing
/// fence, including terminal work.
pub fn transform_quota_hold_status_allows(status: &str, restore: bool) -> bool {
    if status == TRANSFORM_WORK_CLAIMED {
        return true;
    }
    restore
        && matches!(
            status,
            TRANSFORM_WORK_COMPLETED | TRANSFORM_WORK_CANCELLED | TRANSFORM_WORK_FAILED
        )
}

fn transform_claim_identity_matches(
    work: &TransformWork,
    runtime_id: &str,
    claim_generation: i64,
    fencing_token: &str,
) -> bool {
    work.claim_owner == runtime_id
        && work.claim_generation == claim_generation
        && work.fencing_token == fencing_token
        && !fencing_token.trim().is_empty()
}

pub fn transform_claim_is_current(
    work: &TransformWork,
    runtime_id: &str,
    claim_generation: i64,
    fencing_token: &str,
) -> bool {
    work.status == TRANSFORM_WORK_CLAIMED
        && transform_claim_identity_matches(work, runtime_id, claim_generation, fencing_token)
}

pub fn transform_completed_write_matches(
    work: &TransformWork,
    runtime_id: &str,
    claim_generation: i64,
    fencing_token: &str,
) -> bool {
    work.status == TRANSFORM_WORK_COMPLETED
        && transform_claim_identity_matches(work, runtime_id, claim_generation, fencing_token)
}

pub fn transform_claim_fence_matches(
    work: &TransformWork,
    runtime_id: &str,
    claim_generation: i64,
    fencing_token: &str,
    now_ms: i64,
) -> bool {
    transform_claim_is_current(work, runtime_id, claim_generation, fencing_token)
        && work.claim_expires_at_ms > now_ms
}

#[allow(clippy::too_many_arguments)]
fn quarantined_run(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    tables: &[crate::sekai::transform_engine::EngineTable],
    after_id: i64,
    incremental: bool,
    now_ms: i64,
    run_id: String,
    rows_in: i32,
    reason: &str,
) -> (TransformRun, Vec<HashMap<String, String>>) {
    (
        TransformRun {
            run_id,
            namespace: transform.namespace.clone(),
            transform_id: transform.transform_id.clone(),
            definition_digest: transform.definition_digest.clone(),
            input_digest: run_input_digest(transform, tables),
            output_digest: checkpoint
                .map(|checkpoint| checkpoint.2.clone())
                .unwrap_or_default(),
            last_input_row_id: after_id,
            incremental,
            quarantined: true,
            quality_rule: reason.into(),
            rows_in,
            rows_out: 0,
            lineage_parent: checkpoint
                .map(|checkpoint| checkpoint.1.clone())
                .unwrap_or_default(),
            created_at_ms: now_ms,
            markings_in: String::new(),
            markings_out: String::new(),
            profile: String::new(),
            engine: String::new(),
            runtime_image: String::new(),
            dispatch_status: String::new(),
            trigger_cause: String::new(),
            trigger_ref: String::new(),
            input_partitions: Vec::new(),
            output_partitions: Vec::new(),
        },
        Vec::new(),
    )
}

fn run_input_digest(
    transform: &GovernedTransform,
    tables: &[crate::sekai::transform_engine::EngineTable],
) -> String {
    if transform.is_analytical() || transform.is_isolated_process() {
        let mut hasher = Sha256::new();
        for table in tables {
            hash_field(&mut hasher, &table.alias);
            hash_field(&mut hasher, &rows_digest(&table.rows));
        }
        format!("sha256:{:x}", hasher.finalize())
    } else {
        rows_digest(
            tables
                .first()
                .map(|table| table.rows.as_slice())
                .unwrap_or(&[]),
        )
    }
}

pub(crate) fn budget_quarantined_run(
    transform: &GovernedTransform,
    checkpoint: Option<&TransformCheckpoint>,
    incremental: bool,
    now_ms: i64,
    run_id: String,
    rows_in: i32,
    reason: &str,
) -> TransformRun {
    TransformRun {
        run_id,
        namespace: transform.namespace.clone(),
        transform_id: transform.transform_id.clone(),
        definition_digest: transform.definition_digest.clone(),
        input_digest: String::new(),
        output_digest: checkpoint
            .map(|checkpoint| checkpoint.2.clone())
            .unwrap_or_default(),
        last_input_row_id: checkpoint_after_id(incremental, checkpoint),
        incremental,
        quarantined: true,
        quality_rule: reason.into(),
        rows_in,
        rows_out: 0,
        lineage_parent: checkpoint
            .map(|checkpoint| checkpoint.1.clone())
            .unwrap_or_default(),
        created_at_ms: now_ms,
        markings_in: String::new(),
        markings_out: String::new(),
        profile: String::new(),
        engine: String::new(),
        runtime_image: String::new(),
        dispatch_status: String::new(),
        trigger_cause: String::new(),
        trigger_ref: String::new(),
        input_partitions: Vec::new(),
        output_partitions: Vec::new(),
    }
}

pub(crate) fn row_payload_bytes(row: &HashMap<String, String>) -> u64 {
    row.iter().fold(64u64, |used, (key, value)| {
        used.saturating_add(key.len() as u64)
            .saturating_add(value.len() as u64)
            .saturating_add(32)
    })
}

pub(crate) fn row_stream_bytes(row: &TransformRunInputRow) -> u64 {
    row_payload_bytes(&row.values)
        .saturating_add(row.alias.len() as u64)
        .saturating_add(row.dataset_id.len() as u64)
        .saturating_add(row.partition_key.len() as u64)
        .saturating_add(96)
}

pub(crate) struct InputLoadBudget {
    used: u64,
    limit: u64,
    deadline: Instant,
    pub exceeded: Option<&'static str>,
}

impl InputLoadBudget {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(crate) fn expire_if_past(&mut self) {
        if self.exceeded.is_none() && Instant::now() >= self.deadline {
            self.exceeded = Some(crate::sekai::transform_engine::BUDGET_TIME);
        }
    }

    pub(crate) fn for_transform(transform: &GovernedTransform) -> Option<Self> {
        let spec = transform.analytical.as_ref()?;
        Some(Self {
            used: 0,
            limit: crate::sekai::transform_engine::host_limit(
                spec.memory_limit_bytes,
                crate::sekai::transform_engine::DEFAULT_MEMORY_LIMIT_BYTES,
            ),
            deadline: Instant::now()
                + Duration::from_millis(crate::sekai::transform_engine::host_limit(
                    spec.time_limit_ms,
                    crate::sekai::transform_engine::DEFAULT_TIME_LIMIT_MS,
                )),
            exceeded: None,
        })
    }

    pub(crate) fn for_preview(transform: &GovernedTransform) -> Self {
        Self::for_transform(transform).unwrap_or(Self {
            used: 0,
            limit: crate::sekai::transform_engine::DEFAULT_MEMORY_LIMIT_BYTES,
            deadline: Instant::now()
                + Duration::from_millis(crate::sekai::transform_engine::DEFAULT_TIME_LIMIT_MS),
            exceeded: None,
        })
    }

    pub(crate) fn allow_encoded(&mut self, encoded_len: u64) -> bool {
        if self.exceeded.is_some() {
            return false;
        }
        if Instant::now() >= self.deadline {
            self.exceeded = Some(crate::sekai::transform_engine::BUDGET_TIME);
            return false;
        }
        if encoded_len > self.limit.saturating_sub(self.used) {
            self.exceeded = Some(crate::sekai::transform_engine::BUDGET_MEMORY);
            return false;
        }
        true
    }

    pub(crate) fn charge(&mut self, row: &HashMap<String, String>) -> bool {
        if self.exceeded.is_some() {
            return false;
        }
        if Instant::now() >= self.deadline {
            self.exceeded = Some(crate::sekai::transform_engine::BUDGET_TIME);
            return false;
        }
        self.used = self.used.saturating_add(row_payload_bytes(row));
        if self.used > self.limit {
            self.exceeded = Some(crate::sekai::transform_engine::BUDGET_MEMORY);
            return false;
        }
        true
    }
}

/// Union input dataset/object/row markings for a transform receipt.
/// Unknown or incomparable tokens fail closed. The live output marking is
/// always folded into markings_out so a rebuild cannot strip a stricter stamp.
pub fn derive_transform_markings<'a>(
    lattice: Option<&crate::sekai::classification_lattice::ClassificationLattice>,
    input_object_tokens: impl IntoIterator<Item = Option<&'a str>>,
    prior_output_token: Option<&str>,
    rows: impl IntoIterator<Item = &'a HashMap<String, String>>,
) -> Result<(String, String), String> {
    use crate::sekai::classification_lattice::union_input_marking_tokens;
    use crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY;
    let mut input_tokens: Vec<Option<String>> = Vec::new();
    for token in input_object_tokens {
        if let Some(token) = token.map(str::trim).filter(|value| !value.is_empty()) {
            input_tokens.push(Some(token.to_string()));
        }
    }
    for row in rows {
        match row.get(OBJECT_CLASSIFICATION_PROPERTY) {
            None => {}
            Some(value) if value.trim().is_empty() => {}
            Some(value) => input_tokens.push(Some(value.trim().to_string())),
        }
    }
    let (markings_in, input_union) =
        union_input_marking_tokens(lattice, input_tokens.iter().map(|token| token.as_deref()))?;
    let markings_out = if let Some(prior) = prior_output_token
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        union_input_marking_tokens(lattice, [input_union.as_deref(), Some(prior)])?.1
    } else {
        input_union
    };
    Ok((markings_in.join(","), markings_out.unwrap_or_default()))
}

/// Fold a live output stamp into the admitted token so write-back cannot
/// strip a stricter classification applied after admission.
/// Isolated write-back may not replace a newer committed result. A strictly
/// older live receipt becomes this run's lineage parent. Same-millisecond
/// admissions use run_id as a deterministic tie-break, not a sequence number.
pub fn bind_isolated_write_lineage(
    run: &mut TransformRun,
    live: Option<&TransformRun>,
) -> Result<(), String> {
    let Some(live) = live else {
        return Ok(());
    };
    if live.run_id == run.run_id {
        return Ok(());
    }
    if (live.created_at_ms, live.run_id.as_str()) > (run.created_at_ms, run.run_id.as_str()) {
        return Err(STALE_TRANSFORM_ADMISSION.into());
    }
    run.lineage_parent = live.run_id.clone();
    Ok(())
}

pub fn fold_live_output_marking(
    lattice: Option<&crate::sekai::classification_lattice::ClassificationLattice>,
    admitted_out: &str,
    live_output: Option<&str>,
) -> Result<String, String> {
    Ok(derive_transform_markings(
        lattice,
        [Some(admitted_out)],
        live_output,
        &[] as &[HashMap<String, String>],
    )?
    .1)
}

/// Marked derived output must stamp a bound dataset object. Unbound datasets
/// are readable without marking clearance.
pub fn require_bound_output_for_markings(
    output_object_id: &str,
    markings_out: &str,
) -> Result<(), String> {
    if markings_out.trim().is_empty() || !output_object_id.trim().is_empty() {
        return Ok(());
    }
    Err("output markings unresolvable: dataset has no backing object".into())
}

pub fn rows_digest(rows: &[HashMap<String, String>]) -> String {
    encode_digest(fold_row_hashes([0u8; 32], rows))
}

/// Fold newly appended output rows into a stored digest. The digest is an
/// order-independent 256-bit sum of per-row SHA-256 hashes, so this equals
/// `rows_digest` of the combined live set. Returns `None` when `previous` is
/// not the current encoding, so callers force a full rebuild.
pub fn fold_output_digest(
    previous: &str,
    added_rows: &[HashMap<String, String>],
) -> Option<String> {
    Some(encode_digest(fold_row_hashes(
        parse_output_digest(previous)?,
        added_rows,
    )))
}

fn row_canonical_hash(row: &HashMap<String, String>) -> [u8; 32] {
    let ordered: BTreeMap<&str, &str> = row
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    Sha256::digest(serde_json::to_vec(&ordered).unwrap_or_default()).into()
}

fn add_u256(acc: &mut [u8; 32], addend: &[u8; 32]) {
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let sum = u16::from(acc[index]) + u16::from(addend[index]) + carry;
        acc[index] = sum as u8;
        carry = sum >> 8;
    }
}

fn fold_row_hashes(mut acc: [u8; 32], rows: &[HashMap<String, String>]) -> [u8; 32] {
    for row in rows {
        add_u256(&mut acc, &row_canonical_hash(row));
    }
    acc
}

fn encode_digest(bytes: [u8; 32]) -> String {
    let mut hex = String::with_capacity(OUTPUT_DIGEST_PREFIX.len() + 64);
    hex.push_str(OUTPUT_DIGEST_PREFIX);
    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

pub fn parse_output_digest(value: &str) -> Option<[u8; 32]> {
    parse_prefixed_digest(value, OUTPUT_DIGEST_PREFIX)
}

pub fn parse_partitioned_digest(value: &str) -> Option<[u8; 32]> {
    parse_prefixed_digest(value, PARTITIONED_DIGEST_PREFIX)
}

pub fn live_output_digest_is_current(value: &str) -> bool {
    parse_output_digest(value).is_some() || parse_partitioned_digest(value).is_some()
}

pub fn live_output_digest_matches_keys(value: &str, keys: &[String]) -> bool {
    if keys.is_empty() {
        parse_output_digest(value).is_some()
    } else {
        parse_partitioned_digest(value).is_some()
    }
}

fn parse_prefixed_digest(value: &str, prefix: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix(prefix)?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

/// Rewrite receipt identities after a partition-key field is redacted.
pub fn rewrite_partition_identities(
    receipts: &mut [TransformPartition],
    replacements: &HashMap<String, String>,
) -> bool {
    let mut changed = false;
    for receipt in receipts {
        if let Some(new_key) = replacements.get(&receipt.partition_key)
            && new_key != &receipt.partition_key
        {
            receipt.partition_key = new_key.clone();
            changed = true;
        }
    }
    changed
}

pub fn redact_run_partition_receipts(
    dataset_id: &str,
    input_partitions: &mut [TransformPartition],
    output_partitions: &mut [TransformPartition],
) -> bool {
    let mut changed = false;
    for receipt in input_partitions
        .iter_mut()
        .chain(output_partitions.iter_mut())
    {
        if receipt.dataset_id != dataset_id {
            continue;
        }
        if !receipt.partition_key.is_empty() && receipt.partition_key != "[redacted]" {
            receipt.partition_key = "[redacted]".into();
            changed = true;
        }
        if !receipt.digest.is_empty() && receipt.digest != "[redacted]" {
            receipt.digest = "[redacted]".into();
            changed = true;
        }
    }
    changed
}

pub fn partition_value(keys: &[String], row: &HashMap<String, String>) -> String {
    match keys {
        [] => String::new(),
        [key] => row.get(key).cloned().unwrap_or_default(),
        keys => {
            let parts: Vec<&str> = keys
                .iter()
                .map(|key| row.get(key).map(String::as_str).unwrap_or(""))
                .collect();
            serde_json::to_string(&parts).unwrap_or_default()
        }
    }
}

pub fn group_rows_by_partition(
    keys: &[String],
    rows: &[HashMap<String, String>],
) -> BTreeMap<String, Vec<HashMap<String, String>>> {
    let mut grouped = BTreeMap::new();
    for row in rows {
        grouped
            .entry(partition_value(keys, row))
            .or_insert_with(Vec::new)
            .push(row.clone());
    }
    grouped
}

pub fn partitioned_dataset_digest(partitions: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PARTITIONED_DIGEST_PREFIX.as_bytes());
    for (key, digest) in partitions {
        hash_field(&mut hasher, key);
        hash_field(&mut hasher, digest);
    }
    encode_prefixed_digest(PARTITIONED_DIGEST_PREFIX, hasher.finalize().into())
}

fn encode_prefixed_digest(prefix: &str, bytes: [u8; 32]) -> String {
    let mut hex = String::with_capacity(prefix.len() + 64);
    hex.push_str(prefix);
    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }
    hex
}

pub fn partition_records(
    keys: &[String],
    rows: &[HashMap<String, String>],
    dataset_id: &str,
) -> Vec<TransformPartition> {
    group_rows_by_partition(keys, rows)
        .into_iter()
        .map(|(partition_key, rows)| TransformPartition {
            digest: rows_digest(&rows),
            rows: rows.len() as i32,
            partition_key,
            dataset_id: dataset_id.to_string(),
        })
        .collect()
}

/// Receipts for each input using that dataset's own `partition_keys`.
/// Unpartitioned inputs are omitted; they must not borrow another input's keys.
pub fn input_partition_receipts<I>(inputs: I) -> Vec<TransformPartition>
where
    I: IntoIterator<Item = (String, Vec<String>, Vec<HashMap<String, String>>)>,
{
    let mut receipts = Vec::new();
    for (dataset_id, keys, rows) in inputs {
        if keys.is_empty() {
            continue;
        }
        receipts.extend(partition_records(&keys, &rows, &dataset_id));
    }
    receipts
}

/// Group snapshot rows by `(alias, partition_key)` so two inputs that share an
/// identity stay separate receipts. Callers omit unpartitioned datasets.
pub fn receipts_from_snapshot_rows<I>(rows: I) -> Vec<TransformPartition>
where
    I: IntoIterator<Item = TransformRunInputRow>,
{
    let mut grouped: BTreeMap<(String, String, String), Vec<HashMap<String, String>>> =
        BTreeMap::new();
    for row in rows {
        grouped
            .entry((row.alias, row.dataset_id, row.partition_key))
            .or_default()
            .push(row.values);
    }
    grouped
        .into_iter()
        .map(
            |((_, dataset_id, partition_key), rows)| TransformPartition {
                digest: rows_digest(&rows),
                rows: rows.len() as i32,
                partition_key,
                dataset_id,
            },
        )
        .collect()
}

pub fn trim_page_to_bytes(
    rows: Vec<TransformRunInputRow>,
    max_bytes: i64,
) -> Vec<TransformRunInputRow> {
    if max_bytes <= 0 || rows.is_empty() {
        return rows;
    }
    let cap = max_bytes as u64;
    let mut used = 0u64;
    let mut kept = Vec::new();
    for row in rows {
        let size = row_stream_bytes(&row);
        if !kept.is_empty() && used.saturating_add(size) > cap {
            break;
        }
        used = used.saturating_add(size);
        kept.push(row);
    }
    kept
}

pub fn prepare_partition_commit(
    keys: &[String],
    live: &[HashMap<String, String>],
    writes: &[TransformPartitionWrite],
    output_digest: &str,
) -> Result<PreparedPartitionCommit, String> {
    if keys.is_empty() {
        return Err("partition write requires dataset partition_keys".into());
    }
    if writes.is_empty() {
        return Err("partition write requires replaced partitions".into());
    }
    let mut grouped = group_rows_by_partition(keys, live);
    let mut replacements = Vec::new();
    let mut written = Vec::new();
    let mut seen = HashSet::new();
    for write in writes {
        let key = write.partition_key.as_str();
        if !seen.insert(key.to_string()) {
            return Err(format!("duplicate partition write for {key}"));
        }
        for row in &write.rows {
            if partition_value(keys, row) != key {
                return Err(format!("row does not belong to partition {key}"));
            }
        }
        grouped.insert(key.to_string(), write.rows.clone());
        replacements.push((key.to_string(), write.rows.clone()));
        written.push(TransformPartition {
            partition_key: key.to_string(),
            digest: rows_digest(&write.rows),
            rows: write.rows.len() as i32,
            dataset_id: String::new(),
        });
    }
    let mut member_digests = BTreeMap::new();
    let mut merged_rows = Vec::new();
    for (key, rows) in &grouped {
        if rows.is_empty() {
            continue;
        }
        member_digests.insert(key.clone(), rows_digest(rows));
        merged_rows.extend(rows.iter().cloned());
    }
    let envelope_digest = partitioned_dataset_digest(&member_digests);
    if envelope_digest != output_digest {
        return Err(TRANSFORM_DIGEST_MISMATCH.into());
    }
    Ok(PreparedPartitionCommit {
        envelope_digest,
        written,
        replacements,
        merged_rows,
    })
}

/// Whole-dataset digest: `sha256-sum-v1:` when unpartitioned, otherwise the
/// `sha256-partitions-v1:` envelope over member `sha256-sum-v1:` digests.
pub fn dataset_digest(keys: &[String], rows: &[HashMap<String, String>]) -> String {
    if keys.is_empty() {
        return rows_digest(rows);
    }
    partitioned_dataset_digest(
        &group_rows_by_partition(keys, rows)
            .into_iter()
            .map(|(key, rows)| (key, rows_digest(&rows)))
            .collect(),
    )
}

/// Incremental projection rewrites only partitions that received new output
/// rows. Untouched live partitions stay on disk.
pub fn rewritten_partitions(
    keys: &[String],
    live: &[HashMap<String, String>],
    new_output: &[HashMap<String, String>],
) -> Vec<(String, Vec<HashMap<String, String>>)> {
    if keys.is_empty() || new_output.is_empty() {
        return Vec::new();
    }
    let live_groups = group_rows_by_partition(keys, live);
    group_rows_by_partition(keys, new_output)
        .into_iter()
        .map(|(key, new_rows)| {
            let mut merged = live_groups.get(&key).cloned().unwrap_or_default();
            merged.extend(new_rows);
            (key, merged)
        })
        .collect()
}

pub fn receipts_for_touched_partitions(
    keys: &[String],
    live_after: &[HashMap<String, String>],
    new_output: &[HashMap<String, String>],
    dataset_id: &str,
) -> Vec<TransformPartition> {
    let live_groups = group_rows_by_partition(keys, live_after);
    group_rows_by_partition(keys, new_output)
        .into_keys()
        .map(|key| {
            let rows = live_groups.get(&key).cloned().unwrap_or_default();
            TransformPartition {
                partition_key: key,
                digest: rows_digest(&rows),
                rows: rows.len() as i32,
                dataset_id: dataset_id.to_string(),
            }
        })
        .collect()
}

pub fn partitions_from_replacements(
    replacements: &[(String, Vec<HashMap<String, String>>)],
    dataset_id: &str,
) -> Vec<TransformPartition> {
    replacements
        .iter()
        .map(|(partition_key, rows)| TransformPartition {
            partition_key: partition_key.clone(),
            digest: rows_digest(rows),
            rows: rows.len() as i32,
            dataset_id: dataset_id.to_string(),
        })
        .collect()
}

pub fn bind_receipts_to_dataset(receipts: &mut [TransformPartition], dataset_id: &str) {
    for receipt in receipts {
        receipt.dataset_id = dataset_id.to_string();
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

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

pub fn new_preview_id() -> String {
    format!("{PREVIEW_ID_PREFIX}{}", uuid::Uuid::new_v4())
}

pub fn is_preview_id(id: &str) -> bool {
    id.starts_with(PREVIEW_ID_PREFIX)
}

pub fn resolve_preview_row_cap(requested: u32) -> Result<usize, String> {
    if requested == 0 {
        return Ok(DEFAULT_PREVIEW_ROW_CAP);
    }
    if (requested as usize) > MAX_PREVIEW_ROW_CAP {
        return Err(PREVIEW_ROW_CAP.into());
    }
    Ok(requested as usize)
}

pub fn preview_output_schema_json(columns: &[String]) -> String {
    serde_json::json!({ "columns": columns }).to_string()
}

pub fn preview_schema_from_rows(rows: &[HashMap<String, String>]) -> String {
    let mut columns: Vec<String> = rows.iter().flat_map(|row| row.keys().cloned()).collect();
    columns.sort();
    columns.dedup();
    preview_output_schema_json(&columns)
}

pub fn apply_preview_column_allowlist(
    records: &mut [(i64, HashMap<String, String>)],
    allowed: Option<&[String]>,
) {
    let Some(allowed) = allowed else {
        return;
    };
    let allowed: std::collections::HashSet<&str> = allowed.iter().map(String::as_str).collect();
    for (_, row) in records {
        row.retain(|key, _| allowed.contains(key.as_str()));
    }
}

pub fn preview_writeback_run(
    work: &TransformWork,
    command: &WriteTransformRunCommand,
    now_ms: i64,
) -> TransformRun {
    TransformRun {
        run_id: command.run_id.clone(),
        namespace: work.namespace.clone(),
        transform_id: work.transform_id.clone(),
        definition_digest: work.definition_digest.clone(),
        input_digest: String::new(),
        output_digest: command.output_digest.clone(),
        last_input_row_id: 0,
        incremental: false,
        quarantined: command.quarantined,
        quality_rule: command.quality_rule.clone(),
        rows_in: 0,
        rows_out: i32::try_from(command.rows.len()).unwrap_or(i32::MAX),
        lineage_parent: String::new(),
        created_at_ms: now_ms,
        markings_in: String::new(),
        markings_out: String::new(),
        profile: ISOLATED_CLASS.into(),
        engine: work.engine.clone(),
        runtime_image: work.runtime_image.clone(),
        dispatch_status: TRANSFORM_WORK_COMPLETED.into(),
        trigger_cause: String::new(),
        trigger_ref: String::new(),
        input_partitions: Vec::new(),
        output_partitions: Vec::new(),
    }
}

pub fn current_preview_auth_covers_admitted(
    admitted: &HashMap<String, Vec<String>>,
    current: &HashMap<String, Vec<String>>,
) -> bool {
    current.iter().all(|(dataset, current_cols)| {
        admitted.get(dataset).is_some_and(|admitted_cols| {
            admitted_cols
                .iter()
                .all(|column| current_cols.iter().any(|current| current == column))
        })
    })
}

pub fn preview_result_from_writeback(
    preview_id: &str,
    command: &WriteTransformRunCommand,
    inputs: Vec<PreviewInputStat>,
) -> PreviewGovernedTransformResult {
    PreviewGovernedTransformResult {
        preview_id: preview_id.to_string(),
        output_schema_json: preview_schema_from_rows(&command.rows),
        rows: command.rows.clone(),
        inputs,
        error: if command.quarantined {
            command.quality_rule.clone()
        } else {
            String::new()
        },
    }
}

/// Sampled in-process preview. Budget codes fail; other quarantine is `error`.
pub fn compute_preview_tables(
    transform: &GovernedTransform,
    inputs: &[TransformInputRows<'_>],
    now_ms: i64,
    preview_id: String,
) -> Result<(Vec<HashMap<String, String>>, String), String> {
    let deadline = transform.analytical.as_ref().and_then(|spec| {
        if spec.time_limit_ms == 0 {
            None
        } else {
            Some(std::time::Instant::now() + std::time::Duration::from_millis(spec.time_limit_ms))
        }
    });
    let (run, rows) =
        compute_run_tables_until(transform, None, inputs, false, now_ms, preview_id, deadline);
    if run.quarantined {
        let code = run.quality_rule;
        if code == crate::sekai::transform_engine::BUDGET_TIME
            || code == crate::sekai::transform_engine::BUDGET_MEMORY
        {
            return Err(code);
        }
        return Ok((rows, code));
    }
    Ok((rows, String::new()))
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
            analytical: None,
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    #[test]
    fn projection_digest_ignores_absent_analytical_profile() {
        let first = transform();
        let mut second = first.clone();
        second.analytical = None;
        second.isolated_process = None;
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_eq!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn projection_digest_ignores_absent_isolated_process_profile() {
        let first = transform();
        let mut second = first.clone();
        second.isolated_process = None;
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_eq!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn projection_digest_ignores_absent_schedule_and_trigger() {
        let first = transform();
        let mut second = first.clone();
        second.schedule = None;
        second.trigger = None;
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_eq!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn schedule_participates_in_digest() {
        let first = transform();
        let mut second = first.clone();
        second.schedule = Some(TransformSchedule { every_ms: 60_000 });
        second.definition_digest.clear();
        let second = second.prepare().unwrap();
        assert_ne!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn cycle_is_refused_from_published_definitions() {
        let upstream = transform();
        let mut downstream = transform();
        downstream.transform_id = "t2".into();
        downstream.input_dataset_id = "out".into();
        downstream.output_dataset_id = "mid".into();
        downstream.definition_digest.clear();
        let downstream = downstream.prepare().unwrap();
        refuse_dependency_cycle(std::slice::from_ref(&upstream), &downstream).unwrap();

        let mut back = transform();
        back.transform_id = "t3".into();
        back.input_dataset_id = "mid".into();
        back.output_dataset_id = "in".into();
        back.definition_digest.clear();
        let back = back.prepare().unwrap();
        let error = refuse_dependency_cycle(&[upstream, downstream], &back).unwrap_err();
        assert_eq!(error.message(), TRANSFORM_DEPENDENCY_CYCLE);
    }

    #[test]
    fn schedule_admits_each_bucket_once() {
        assert_eq!(schedule_due_bucket(None, 1_000, 1_500), Some(1));
        assert_eq!(schedule_due_bucket(Some(1), 1_000, 1_500), None);
        assert_eq!(schedule_due_bucket(Some(1), 1_000, 2_000), Some(2));
    }

    #[test]
    fn trigger_debounce_coalesces_until_the_window() {
        assert!(!trigger_is_due(10, 1_000, 500));
        assert!(trigger_is_due(10, 1_000, 1_010));
        assert!(trigger_is_due(10, 0, 10));
    }

    #[test]
    fn isolated_process_engine_participates_in_digest() {
        let first = isolated_transform("duckdb", "ghcr.io/sekai/runner:1");
        let second = isolated_transform("duckdb", "ghcr.io/sekai/runner:2");
        assert_ne!(first.definition_digest, second.definition_digest);
    }

    #[test]
    fn isolated_process_prepare_trims_input_aliases() {
        let mut transform = isolated_transform("python", "runner:1");
        transform.isolated_process.as_mut().unwrap().inputs = vec![TransformInput {
            alias: " left ".into(),
            dataset_id: " in ".into(),
        }];
        transform.input_dataset_id = " in ".into();
        transform.definition_digest.clear();
        let prepared = transform.prepare().unwrap();
        let spec = prepared.isolated_process.as_ref().unwrap();
        assert_eq!(spec.inputs[0].alias, "left");
        assert_eq!(spec.inputs[0].dataset_id, "in");
        assert_eq!(prepared.input_dataset_id, "in");
    }

    #[test]
    fn expired_claimed_work_returns_to_the_queue_until_the_lease_cap() {
        let work = TransformWork {
            status: TRANSFORM_WORK_CLAIMED.into(),
            claim_expires_at_ms: 10,
            lease_expiries: 0,
            ..TransformWork::default()
        };
        assert!(transform_work_is_claimable(&work, 11));
        let dead = TransformWork {
            lease_expiries: MAX_TRANSFORM_LEASE_EXPIRIES,
            ..work.clone()
        };
        assert!(!transform_work_is_claimable(&dead, 11));
        assert!(!transform_work_is_claimable(
            &TransformWork {
                status: TRANSFORM_WORK_COMPLETED.into(),
                ..work
            },
            11
        ));
    }

    #[test]
    fn write_back_fence_rejects_stale_generation_and_expired_lease() {
        let work = TransformWork {
            status: TRANSFORM_WORK_CLAIMED.into(),
            claim_owner: "runner-a".into(),
            claim_generation: 2,
            fencing_token: "fence".into(),
            claim_expires_at_ms: 50,
            ..TransformWork::default()
        };
        assert!(transform_claim_fence_matches(
            &work, "runner-a", 2, "fence", 40
        ));
        assert!(!transform_claim_fence_matches(
            &work, "runner-a", 1, "fence", 40
        ));
        assert!(!transform_claim_fence_matches(
            &work, "runner-a", 2, "other", 40
        ));
        assert!(!transform_claim_fence_matches(
            &work, "runner-a", 2, "fence", 50
        ));
        assert!(transform_claim_is_current(&work, "runner-a", 2, "fence"));
        let completed = TransformWork {
            status: TRANSFORM_WORK_COMPLETED.into(),
            claim_expires_at_ms: 10,
            ..work
        };
        assert!(transform_completed_write_matches(
            &completed, "runner-a", 2, "fence"
        ));
        assert!(!transform_completed_write_matches(
            &completed, "runner-b", 2, "fence"
        ));
        assert!(!transform_completed_write_matches(
            &completed, "runner-a", 1, "fence"
        ));
        assert!(!transform_completed_write_matches(
            &completed, "runner-a", 2, "other"
        ));
        assert!(!transform_completed_write_matches(
            &completed, "runner-a", 2, ""
        ));
        assert!(!transform_claim_is_current(
            &completed, "runner-a", 2, "fence"
        ));
    }

    fn isolated_transform(engine: &str, runtime_image: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "iso".into(),
            input_dataset_id: "in".into(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                engine: engine.into(),
                runtime_image: runtime_image.into(),
                inputs: Vec::new(),
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    #[test]
    fn bind_checkpoint_drops_a_pin_from_a_different_digest() {
        let pin = (7, "run".into(), rows_digest(&[]));
        let (incremental, checkpoint) =
            bind_checkpoint(true, Some((pin.clone(), "old".into())), "new", &[]);
        assert!(!incremental);
        assert_eq!(checkpoint.as_ref(), Some(&pin));
        let (incremental, checkpoint) =
            bind_checkpoint(true, Some((pin.clone(), "same".into())), "same", &[]);
        assert!(incremental);
        assert_eq!(checkpoint.as_ref(), Some(&pin));
        let (incremental, checkpoint) =
            bind_checkpoint(false, Some((pin.clone(), "same".into())), "same", &[]);
        assert!(!incremental);
        assert_eq!(checkpoint, Some(pin));
    }

    #[test]
    fn bind_checkpoint_forces_rebuild_for_old_or_malformed_output_digest() {
        let definition = "same";
        let old = (7, "run".into(), format!("sha256:{}", "ab".repeat(32)));
        let (incremental, checkpoint) = bind_checkpoint(
            true,
            Some((old.clone(), definition.into())),
            definition,
            &[],
        );
        assert!(!incremental);
        assert_eq!(checkpoint.as_ref(), Some(&old));
        let empty = (7, "run".into(), String::new());
        let (incremental, _) =
            bind_checkpoint(true, Some((empty, definition.into())), definition, &[]);
        assert!(!incremental);
        let malformed = (7, "run".into(), "sha256-sum-v1:zzzz".into());
        let (incremental, _) =
            bind_checkpoint(true, Some((malformed, definition.into())), definition, &[]);
        assert!(!incremental);
        let partitioned = (
            7,
            "run".into(),
            partitioned_dataset_digest(&BTreeMap::new()),
        );
        let (incremental, _) = bind_checkpoint(
            true,
            Some((partitioned.clone(), definition.into())),
            definition,
            &[],
        );
        assert!(!incremental);
        let (incremental, _) = bind_checkpoint(
            true,
            Some((partitioned, definition.into())),
            definition,
            &["region".into()],
        );
        assert!(incremental);
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

    #[test]
    fn incremental_output_digest_matches_full_recompute() {
        let first = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("keep".into(), "yes".into()),
        ])];
        let second = vec![HashMap::from([
            ("id".into(), "2".into()),
            ("keep".into(), "yes".into()),
        ])];
        let folded = fold_output_digest(&rows_digest(&first), &second).expect("current encoding");
        let mut combined = first.clone();
        combined.extend(second.clone());
        assert_eq!(folded, rows_digest(&combined));
        assert!(folded.starts_with(OUTPUT_DIGEST_PREFIX));
        assert!(fold_output_digest(&format!("sha256:{}", "ab".repeat(32)), &second).is_none());
        let swapped = vec![second[0].clone(), first[0].clone()];
        assert_eq!(rows_digest(&combined), rows_digest(&swapped));
    }

    #[test]
    fn output_digest_counts_duplicate_rows() {
        let row = HashMap::from([("id".into(), "1".into())]);
        let one = [row.clone()];
        let two = [row.clone(), row];
        assert_ne!(rows_digest(&one), rows_digest(&two));
    }

    #[test]
    fn checkpoint_after_id_is_exclusive() {
        let pin = (7, "run".into(), "out".into());
        assert_eq!(checkpoint_after_id(true, Some(&pin)), 7);
        assert_eq!(checkpoint_after_id(false, Some(&pin)), 0);
        assert_eq!(checkpoint_after_id(true, None), 0);
    }

    #[test]
    fn derived_markings_union_rows_and_fail_closed_on_unknown() {
        let rows = vec![
            HashMap::from([
                ("id".into(), "1".into()),
                (
                    crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "internal".into(),
                ),
            ]),
            HashMap::from([
                ("id".into(), "2".into()),
                (
                    crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "confidential".into(),
                ),
            ]),
        ];
        let (inputs, output) = derive_transform_markings(None, [None], None, &rows).unwrap();
        assert_eq!(inputs, "internal,confidential");
        assert_eq!(output, "confidential");
        let (inputs, output) =
            derive_transform_markings(None, [Some("public")], Some("internal"), &[]).unwrap();
        assert_eq!(inputs, "public");
        assert_eq!(output, "internal");
        let (inputs, output) = derive_transform_markings(
            None,
            [Some("public"), Some("confidential")],
            None,
            &[] as &[HashMap<String, String>],
        )
        .unwrap();
        assert!(inputs.contains("confidential"));
        assert_eq!(output, "confidential");
        assert!(
            derive_transform_markings(
                None,
                [None],
                None,
                &[HashMap::from([(
                    crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.into(),
                    "secret-sauce".into()
                )])]
            )
            .unwrap_err()
            .contains("unknown classification marking")
        );
        assert_eq!(
            fold_live_output_marking(None, "", Some("confidential")).unwrap(),
            "confidential"
        );
        assert_eq!(
            fold_live_output_marking(None, "public", Some("confidential")).unwrap(),
            "confidential"
        );
        assert_eq!(
            fold_live_output_marking(None, "confidential", Some("public")).unwrap(),
            "confidential"
        );
        assert!(require_bound_output_for_markings("", "confidential").is_err());
        assert!(require_bound_output_for_markings("out-obj", "confidential").is_ok());
        assert!(require_bound_output_for_markings("", "").is_ok());
    }

    #[test]
    fn isolated_write_lineage_rejects_a_newer_live_receipt() {
        let older = sample_run("a", 10);
        let newer = sample_run("b", 20);
        let mut rejected = older.clone();
        assert_eq!(
            bind_isolated_write_lineage(&mut rejected, Some(&newer)).unwrap_err(),
            STALE_TRANSFORM_ADMISSION
        );
        let mut child = newer.clone();
        bind_isolated_write_lineage(&mut child, Some(&older)).unwrap();
        assert_eq!(child.lineage_parent, "a");
        let mut first = older.clone();
        bind_isolated_write_lineage(&mut first, None).unwrap();
        assert!(first.lineage_parent.is_empty());
    }

    fn sample_run(id: &str, created_at_ms: i64) -> TransformRun {
        TransformRun {
            run_id: id.into(),
            namespace: "ops".into(),
            transform_id: "t".into(),
            definition_digest: String::new(),
            input_digest: String::new(),
            output_digest: String::new(),
            last_input_row_id: 0,
            incremental: false,
            quarantined: false,
            quality_rule: String::new(),
            rows_in: 0,
            rows_out: 0,
            lineage_parent: String::new(),
            created_at_ms,
            markings_in: String::new(),
            markings_out: String::new(),
            profile: String::new(),
            engine: String::new(),
            runtime_image: String::new(),
            dispatch_status: String::new(),
            trigger_cause: String::new(),
            trigger_ref: String::new(),
            input_partitions: Vec::new(),
            output_partitions: Vec::new(),
        }
    }

    fn analytical_from_bindings(inputs: Vec<TransformInput>) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: "t1".into(),
            input_dataset_id: String::new(),
            output_dataset_id: "out".into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: Some(AnalyticalSpec {
                inputs,
                sql: String::new(),
                memory_limit_bytes: 0,
                time_limit_ms: 0,
            }),
            isolated_process: None,
            schedule: None,
            trigger: None,
        }
    }

    #[test]
    fn analytical_aliases_are_unique_case_insensitively() {
        let mut transform = analytical_from_bindings(vec![
            TransformInput {
                alias: "Orders".into(),
                dataset_id: "a".into(),
            },
            TransformInput {
                alias: "orders".into(),
                dataset_id: "b".into(),
            },
        ]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM \"Orders\"".into();
        let error = transform.prepare().unwrap_err();
        assert!(error.message().contains("unique"), "{}", error.message());
    }

    #[test]
    fn analytical_prepare_fills_input_dataset_id_from_first_binding() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "customers".into(),
            dataset_id: "cust".into(),
        }]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM customers".into();
        let prepared = transform.prepare().unwrap();
        assert_eq!(prepared.input_dataset_id, "cust");
        assert_eq!(
            prepared.input_bindings(),
            vec![("customers".into(), "cust".into())]
        );
    }

    #[test]
    fn analytical_steps_compile_against_first_input_alias() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "customers".into(),
            dataset_id: "cust".into(),
        }]);
        transform.steps = vec![TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }];
        let prepared = transform.prepare().unwrap();
        assert_eq!(
            prepared.analytical.as_ref().unwrap().sql,
            "SELECT * FROM (SELECT * FROM \"customers\") WHERE \"keep\" = 'yes'"
        );
    }

    #[test]
    fn analytical_steps_rejected_with_multiple_inputs() {
        let mut transform = analytical_from_bindings(vec![
            TransformInput {
                alias: "customers".into(),
                dataset_id: "cust".into(),
            },
            TransformInput {
                alias: "orders".into(),
                dataset_id: "ord".into(),
            },
        ]);
        transform.steps = vec![TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }];
        let error = transform.prepare().unwrap_err();
        assert!(
            error.message().contains("explicit sql"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn compiled_analytical_steps_keep_incremental() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "customers".into(),
            dataset_id: "cust".into(),
        }]);
        transform.steps = vec![TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }];
        let prepared = transform.prepare().unwrap();
        assert!(prepared.allows_incremental());
    }

    #[test]
    fn explicit_order_by_sql_rebuilds() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "input".into(),
            dataset_id: "in".into(),
        }]);
        transform.analytical.as_mut().unwrap().sql =
            "SELECT * FROM input ORDER BY id LIMIT 1".into();
        let prepared = transform.prepare().unwrap();
        assert!(!prepared.allows_incremental());
    }

    #[test]
    fn secondary_analytical_input_cannot_be_the_output() {
        let mut transform = analytical_from_bindings(vec![
            TransformInput {
                alias: "source".into(),
                dataset_id: "in".into(),
            },
            TransformInput {
                alias: "prior".into(),
                dataset_id: "out".into(),
            },
        ]);
        transform.analytical.as_mut().unwrap().sql =
            "SELECT * FROM source UNION ALL SELECT * FROM prior".into();
        let error = transform.prepare().unwrap_err();
        assert!(
            error.message().contains("distinct dataset"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn analytical_limits_clamp_to_host_maxima() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "input".into(),
            dataset_id: "in".into(),
        }]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM input".into();
        transform.analytical.as_mut().unwrap().memory_limit_bytes = u64::MAX;
        transform.analytical.as_mut().unwrap().time_limit_ms = u64::MAX;
        let prepared = transform.prepare().unwrap();
        let spec = prepared.analytical.as_ref().unwrap();
        assert_eq!(
            spec.memory_limit_bytes,
            crate::sekai::transform_engine::DEFAULT_MEMORY_LIMIT_BYTES
        );
        assert_eq!(
            spec.time_limit_ms,
            crate::sekai::transform_engine::DEFAULT_TIME_LIMIT_MS
        );
    }

    #[test]
    fn analytical_input_digest_includes_alias_identity() {
        let mut transform = analytical_from_bindings(vec![
            TransformInput {
                alias: "left".into(),
                dataset_id: "a".into(),
            },
            TransformInput {
                alias: "right".into(),
                dataset_id: "b".into(),
            },
        ]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM left".into();
        let transform = transform.prepare().unwrap();
        let left = vec![(1, HashMap::from([("id".into(), "1".into())]))];
        let right = vec![(1, HashMap::from([("id".into(), "2".into())]))];
        let (first, _) = compute_run_tables(
            &transform,
            None,
            &[
                TransformInputRows {
                    alias: "left",
                    records: &left,
                    columns: &[],
                },
                TransformInputRows {
                    alias: "right",
                    records: &right,
                    columns: &[],
                },
            ],
            false,
            10,
            "r1".into(),
        );
        let (swapped, _) = compute_run_tables(
            &transform,
            None,
            &[
                TransformInputRows {
                    alias: "left",
                    records: &right,
                    columns: &[],
                },
                TransformInputRows {
                    alias: "right",
                    records: &left,
                    columns: &[],
                },
            ],
            false,
            10,
            "r2".into(),
        );
        assert_ne!(first.input_digest, swapped.input_digest);
    }

    #[test]
    fn analytical_input_copy_respects_memory_budget() {
        let mut transform = analytical_from_bindings(vec![TransformInput {
            alias: "input".into(),
            dataset_id: "in".into(),
        }]);
        transform.analytical.as_mut().unwrap().sql = "SELECT * FROM input".into();
        transform.analytical.as_mut().unwrap().memory_limit_bytes = 80;
        let transform = transform.prepare().unwrap();
        let records = vec![(1, HashMap::from([("blob".into(), "x".repeat(200))]))];
        let (run, rows) = compute_run_tables(
            &transform,
            None,
            &[TransformInputRows {
                alias: "input",
                records: &records,
                columns: &[],
            }],
            false,
            10,
            "r1".into(),
        );
        assert!(run.quarantined);
        assert_eq!(
            run.quality_rule,
            crate::sekai::transform_engine::BUDGET_MEMORY
        );
        assert!(rows.is_empty());
    }

    #[test]
    fn input_partition_receipts_use_each_input_keys() {
        let left_keys = vec!["region".into()];
        let right_keys = vec!["customer_id".into()];
        let left = vec![HashMap::from([
            ("id".into(), "c1".into()),
            ("region".into(), "east".into()),
        ])];
        let right = vec![HashMap::from([
            ("id".into(), "o1".into()),
            ("customer_id".into(), "c1".into()),
        ])];
        let receipts = input_partition_receipts([
            ("customers".into(), left_keys, left),
            ("orders".into(), right_keys, right),
            (
                "plain".into(),
                Vec::new(),
                vec![HashMap::from([("id".into(), "x".into())])],
            ),
        ]);
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].partition_key, "east");
        assert_eq!(receipts[0].dataset_id, "customers");
        assert_eq!(receipts[1].partition_key, "c1");
        assert_eq!(receipts[1].dataset_id, "orders");
    }

    #[test]
    fn snapshot_receipts_keep_each_input_partition_separate() {
        let receipts = receipts_from_snapshot_rows([
            TransformRunInputRow {
                alias: "left".into(),
                dataset_id: "customers".into(),
                row_id: 1,
                values: HashMap::from([("region".into(), "east".into())]),
                partition_key: "east".into(),
            },
            TransformRunInputRow {
                alias: "right".into(),
                dataset_id: "orders".into(),
                row_id: 1,
                values: HashMap::from([("region".into(), "east".into())]),
                partition_key: "east".into(),
            },
            TransformRunInputRow {
                alias: "left".into(),
                dataset_id: "customers".into(),
                row_id: 2,
                values: HashMap::from([("region".into(), String::new())]),
                partition_key: String::new(),
            },
        ]);
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0].partition_key, "");
        assert_eq!(receipts[1].partition_key, "east");
        assert_eq!(receipts[2].partition_key, "east");
        assert_eq!(receipts[0].rows, 1);
        assert_eq!(receipts[1].rows, 1);
        assert_eq!(receipts[2].rows, 1);
    }

    #[test]
    fn trim_page_counts_partition_identity_bytes() {
        let row = |key: &str| TransformRunInputRow {
            alias: "in".into(),
            dataset_id: "ds".into(),
            row_id: 1,
            values: HashMap::from([("region".into(), key.into())]),
            partition_key: key.into(),
        };
        let big = "e".repeat(200);
        let first = row(&big);
        let cap = row_stream_bytes(&first) as i64 + 10;
        let page = trim_page_to_bytes(vec![first, row(&big)], cap);
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn rewritten_partitions_keeps_untouched_keys_off_the_list() {
        let keys = vec!["region".into()];
        let live = vec![
            HashMap::from([("id".into(), "1".into()), ("region".into(), "east".into())]),
            HashMap::from([("id".into(), "2".into()), ("region".into(), "west".into())]),
        ];
        let added = vec![HashMap::from([
            ("id".into(), "3".into()),
            ("region".into(), "east".into()),
        ])];
        let rewritten = rewritten_partitions(&keys, &live, &added);
        assert_eq!(rewritten.len(), 1);
        assert_eq!(rewritten[0].0, "east");
        assert_eq!(rewritten[0].1.len(), 2);
        assert!(dataset_digest(&keys, &live).starts_with(PARTITIONED_DIGEST_PREFIX));
    }

    #[test]
    fn partitioned_digest_does_not_fold_as_sum_v1() {
        let mut partitions = BTreeMap::new();
        partitions.insert(
            "east".into(),
            rows_digest(&[HashMap::from([("id".into(), "1".into())])]),
        );
        let digest = partitioned_dataset_digest(&partitions);
        assert!(digest.starts_with(PARTITIONED_DIGEST_PREFIX));
        assert!(parse_output_digest(&digest).is_none());
        assert!(parse_partitioned_digest(&digest).is_some());
        assert!(fold_output_digest(&digest, &[]).is_none());
    }

    #[test]
    fn prepare_partition_commit_keeps_untouched_rows() {
        let keys = vec!["region".into()];
        let live = vec![
            HashMap::from([("id".into(), "1".into()), ("region".into(), "east".into())]),
            HashMap::from([("id".into(), "2".into()), ("region".into(), "west".into())]),
        ];
        let west = vec![HashMap::from([
            ("id".into(), "2".into()),
            ("region".into(), "west".into()),
            ("keep".into(), "yes".into()),
        ])];
        let mut merged_groups = group_rows_by_partition(&keys, &live);
        merged_groups.insert("west".into(), west.clone());
        let envelope = partitioned_dataset_digest(
            &merged_groups
                .iter()
                .map(|(key, rows)| (key.clone(), rows_digest(rows)))
                .collect(),
        );
        let prepared = prepare_partition_commit(
            &keys,
            &live,
            &[TransformPartitionWrite {
                partition_key: "west".into(),
                rows: west,
            }],
            &envelope,
        )
        .unwrap();
        assert_eq!(prepared.written.len(), 1);
        assert_eq!(prepared.written[0].partition_key, "west");
        assert_eq!(prepared.merged_rows.len(), 2);
        assert!(
            prepare_partition_commit(
                &keys,
                &live,
                &[TransformPartitionWrite {
                    partition_key: "west".into(),
                    rows: vec![HashMap::from([
                        ("id".into(), "2".into()),
                        ("region".into(), "west".into())
                    ])],
                }],
                "sha256-sum-v1:deadbeef",
            )
            .is_err()
        );
    }

    #[test]
    fn prepare_partition_commit_drops_empty_partitions_from_envelope() {
        let keys = vec!["region".into()];
        let live = vec![
            HashMap::from([("id".into(), "1".into()), ("region".into(), "east".into())]),
            HashMap::from([("id".into(), "2".into()), ("region".into(), "west".into())]),
        ];
        let remaining = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("region".into(), "east".into()),
        ])];
        let envelope = dataset_digest(&keys, &remaining);
        let prepared = prepare_partition_commit(
            &keys,
            &live,
            &[TransformPartitionWrite {
                partition_key: "west".into(),
                rows: Vec::new(),
            }],
            &envelope,
        )
        .unwrap();
        assert_eq!(prepared.written[0].rows, 0);
        assert_eq!(prepared.envelope_digest, envelope);
        assert_eq!(prepared.merged_rows, remaining);
    }

    #[test]
    fn rewrite_partition_identities_replaces_matching_keys() {
        let mut receipts = vec![
            TransformPartition {
                partition_key: "east".into(),
                digest: "d1".into(),
                rows: 1,
                dataset_id: "in".into(),
            },
            TransformPartition {
                partition_key: "west".into(),
                digest: "d2".into(),
                rows: 1,
                dataset_id: "out".into(),
            },
        ];
        let replacements = HashMap::from([("east".into(), "[redacted]".into())]);
        assert!(rewrite_partition_identities(&mut receipts, &replacements));
        assert_eq!(receipts[0].partition_key, "[redacted]");
        assert_eq!(receipts[1].partition_key, "west");
        receipts[0].partition_key = "east".into();
        assert!(redact_run_partition_receipts("in", &mut receipts, &mut []));
        assert_eq!(receipts[0].partition_key, "[redacted]");
        assert_eq!(receipts[0].digest, "[redacted]");
        assert_eq!(receipts[1].partition_key, "west");
        assert_eq!(receipts[1].digest, "d2");
        let mut empty = [TransformPartition {
            partition_key: String::new(),
            digest: "d3".into(),
            rows: 1,
            dataset_id: "in".into(),
        }];
        assert!(redact_run_partition_receipts("in", &mut empty, &mut []));
        assert!(empty[0].partition_key.is_empty());
        assert_eq!(empty[0].digest, "[redacted]");
    }

    #[test]
    fn prepare_partition_commit_rejects_duplicate_partition_identity() {
        let keys = vec!["region".into()];
        let live = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("region".into(), "east".into()),
        ])];
        let first = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("region".into(), "east".into()),
            ("keep".into(), "first".into()),
        ])];
        let second = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("region".into(), "east".into()),
            ("keep".into(), "second".into()),
        ])];
        let envelope = dataset_digest(&keys, &second);
        let error = prepare_partition_commit(
            &keys,
            &live,
            &[
                TransformPartitionWrite {
                    partition_key: "east".into(),
                    rows: first,
                },
                TransformPartitionWrite {
                    partition_key: "east".into(),
                    rows: second,
                },
            ],
            &envelope,
        )
        .unwrap_err();
        assert!(error.contains("duplicate partition write"));
    }

    #[test]
    fn composite_partition_value_does_not_collide_on_embedded_separators() {
        let keys = vec!["left".into(), "right".into()];
        let first = HashMap::from([
            ("left".into(), "a\u{1f}b".into()),
            ("right".into(), "c".into()),
        ]);
        let second = HashMap::from([
            ("left".into(), "a".into()),
            ("right".into(), "b\u{1f}c".into()),
        ]);
        assert_ne!(
            partition_value(&keys, &first),
            partition_value(&keys, &second)
        );
        assert_eq!(
            partition_value(
                &["region".into()],
                &HashMap::from([("region".into(), "east".into())])
            ),
            "east"
        );
    }

    #[test]
    fn preview_id_is_not_a_run_id_prefix_collision() {
        let id = new_preview_id();
        assert!(is_preview_id(&id));
        assert!(!is_preview_id("run-1"));
        assert!(id.starts_with(PREVIEW_ID_PREFIX));
    }

    #[test]
    fn preview_row_cap_defaults_and_rejects_plane_maximum() {
        assert_eq!(resolve_preview_row_cap(0).unwrap(), DEFAULT_PREVIEW_ROW_CAP);
        assert_eq!(resolve_preview_row_cap(512).unwrap(), 512);
        assert_eq!(resolve_preview_row_cap(1024).unwrap(), 1024);
        assert_eq!(resolve_preview_row_cap(1025).unwrap_err(), PREVIEW_ROW_CAP);
    }

    #[test]
    fn preview_column_allowlist_drops_ungranted_keys() {
        let mut records = vec![(
            1,
            HashMap::from([
                ("keep".into(), "yes".into()),
                ("secret".into(), "no".into()),
            ]),
        )];
        apply_preview_column_allowlist(&mut records, Some(&["keep".into()]));
        assert_eq!(records[0].1, HashMap::from([("keep".into(), "yes".into())]));
    }
}
