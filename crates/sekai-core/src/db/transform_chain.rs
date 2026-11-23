//! Governed transform-chain persistence and execution (#2119).

use std::collections::{BTreeMap, HashMap};

use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::sekai::SekaiDb;
use crate::sekai::dataset::RowQuery;
use crate::sekai::governed_transform::{
    ISOLATED_CLASS, TRANSFORM_WORK_CANCELLED, TRANSFORM_WORK_CLAIMED, TRANSFORM_WORK_COMPLETED,
    TRANSFORM_WORK_FAILED, TRANSFORM_WORK_PENDING, TransformRun, dataset_digest,
};
use crate::sekai::transform_chain::{
    CHAIN_WORK_CANCELLED, CHAIN_WORK_COMPLETED, CHAIN_WORK_FAILED, CHAIN_WORK_RUNNING, ChainStep,
    TransformChain, TransformChainRun, chain_endpoint_digest, chain_receipt, chain_run_identity,
    compile_named_edges, evaluate_assertions,
};

pub(crate) trait ChainStore {
    fn persist_chain(&self, chain: &TransformChain, created_at_ms: i64) -> Result<(), String>;
    fn load_chain(&self, namespace: &str, chain_id: &str)
    -> Result<Option<TransformChain>, String>;
    fn persist_run(&self, run: &TransformChainRun) -> Result<(), String>;
    /// Inserts a new run. Returns false when `(namespace, chain_id, identity)` already exists.
    fn try_insert_run(&self, run: &TransformChainRun) -> Result<bool, String>;
    fn load_run(&self, run_id: &str) -> Result<Option<TransformChainRun>, String>;
    fn load_run_by_identity(
        &self,
        namespace: &str,
        chain_id: &str,
        identity: &str,
    ) -> Result<Option<TransformChainRun>, String>;
    fn load_run_id_for_step(&self, transform_run_id: &str) -> Result<Option<String>, String>;
    fn try_claim_step(&self, run_id: &str, step: &str, now_ms: i64) -> Result<bool, String>;
    fn bind_step_run(
        &self,
        run_id: &str,
        step: &str,
        transform_run_id: &str,
    ) -> Result<bool, String>;
    /// CAS-extend an empty-id claim after `CHAIN_STEP_CLAIM_LEASE_MS`. Crash
    /// after transform commit and before bind can re-dispatch past the lease;
    /// bind still requires an empty `transform_run_id`.
    fn reclaim_stale_step(&self, run_id: &str, step: &str, now_ms: i64) -> Result<bool, String>;
    /// Reopen a failed or cancelled run. Keeps completed steps and running
    /// steps whose bound transform run is still pending or claimed, and
    /// drops every other step so it dispatches again.
    fn begin_retry(&self, run_id: &str) -> Result<bool, String>;
    fn dataset_partition_keys(&self, dataset_id: &str) -> Result<Vec<String>, String>;
    fn get_transform(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::GovernedTransform>, String>;
    fn run_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        tenant_id: &str,
        expected_definition_digest: &str,
        now_ms: i64,
    ) -> Result<TransformRun, String>;
    fn get_transform_run(&self, run_id: &str) -> Result<Option<TransformRun>, String>;
    fn query_output_rows(&self, dataset_id: &str) -> Result<Vec<HashMap<String, String>>, String>;
    /// Move a RUNNING run to the terminal status in `run` and append its chain
    /// receipt in one transaction. Returns false, writing nothing, when the
    /// stored run is no longer RUNNING.
    fn finish_run(&self, run: &TransformChainRun, receipt: &TransformRun) -> Result<bool, String>;
}

pub(crate) const CHAIN_STEP_CLAIM_LEASE_MS: i64 = 60_000;

pub(crate) fn put_transform_chain<S: ChainStore>(
    store: &S,
    chain: TransformChain,
    created_at_ms: i64,
) -> Result<TransformChain, String> {
    let mut chain = chain.prepare().map_err(|error| error.message())?;
    let transforms = load_step_transforms(store, &chain)?;
    for step in &mut chain.steps {
        let transform = transforms
            .get(&step.transform_id)
            .ok_or_else(|| "governed transform not found".to_string())?;
        step.transform_digest = transform.definition_digest.clone();
    }
    let chain = chain.prepare().map_err(|error| error.message())?;
    compile_named_edges(&chain, &transforms).map_err(|error| error.message())?;
    store.persist_chain(&chain, created_at_ms)?;
    Ok(chain)
}

pub(crate) fn run_transform_chain<S: ChainStore>(
    store: &S,
    namespace: &str,
    chain_id: &str,
    idempotency_key: &str,
    tenant_id: &str,
    now_ms: i64,
) -> Result<(TransformChainRun, bool), String> {
    let chain = store
        .load_chain(namespace, chain_id)?
        .ok_or_else(|| "transform chain not found".to_string())?;
    let key = if idempotency_key.trim().is_empty() {
        Uuid::new_v4().to_string()
    } else {
        idempotency_key.to_string()
    };
    let identity = chain_run_identity(&key);
    if let Some(existing) = store.load_run_by_identity(namespace, chain_id, &identity)? {
        return continue_existing_run(store, existing, now_ms);
    }
    let definition_json = serde_json::to_string(&chain).map_err(|error| error.to_string())?;
    let run = TransformChainRun {
        run_id: format!("chain-{}", Uuid::new_v4()),
        namespace: chain.namespace.clone(),
        chain_id: chain.chain_id.clone(),
        definition_digest: chain.definition_digest.clone(),
        definition_json,
        tenant_id: tenant_id.to_string(),
        identity,
        status: CHAIN_WORK_RUNNING.into(),
        failed_step: String::new(),
        error: String::new(),
        steps: Vec::new(),
        created_at_ms: now_ms,
        completed_at_ms: 0,
        input_digest: String::new(),
        output_digest: String::new(),
    };
    if !store.try_insert_run(&run)? {
        let existing = store
            .load_run_by_identity(namespace, chain_id, &run.identity)?
            .ok_or_else(|| "transform chain run identity conflict".to_string())?;
        return continue_existing_run(store, existing, now_ms);
    }
    Ok((
        advance_transform_chain(store, &run.run_id, now_ms, false, true)?,
        false,
    ))
}

fn continue_existing_run<S: ChainStore>(
    store: &S,
    existing: TransformChainRun,
    now_ms: i64,
) -> Result<(TransformChainRun, bool), String> {
    if existing.status == CHAIN_WORK_COMPLETED {
        return Ok((existing, true));
    }
    let retry = existing.status == CHAIN_WORK_FAILED || existing.status == CHAIN_WORK_CANCELLED;
    Ok((
        advance_transform_chain(store, &existing.run_id, now_ms, retry, true)?,
        false,
    ))
}

pub(crate) fn peek_transform_chain_run<S: ChainStore>(
    store: &S,
    run_id: &str,
) -> Result<Option<TransformChainRun>, String> {
    store.load_run(run_id)
}

/// Reconciles already-dispatched steps. Downstream dispatch stays on Run so
/// a crash after transform commit resumes when Run is retried with the same
/// idempotency key.
pub(crate) fn get_transform_chain_run<S: ChainStore>(
    store: &S,
    run_id: &str,
    now_ms: i64,
) -> Result<Option<TransformChainRun>, String> {
    let Some(run) = store.load_run(run_id)? else {
        return Ok(None);
    };
    if run.status == CHAIN_WORK_RUNNING {
        return Ok(Some(advance_transform_chain(
            store, run_id, now_ms, false, false,
        )?));
    }
    Ok(Some(run))
}

/// Continues an admitted chain Run after a step transform is written.
/// Quota admission stays on the chain RPC; this hook does not re-admit.
pub(crate) fn on_transform_run_written<S: ChainStore>(
    store: &S,
    transform_run: &TransformRun,
    now_ms: i64,
) -> Result<(), String> {
    let Some(chain_run_id) = store.load_run_id_for_step(&transform_run.run_id)? else {
        return Ok(());
    };
    let Some(mut run) = store.load_run(&chain_run_id)? else {
        return Ok(());
    };
    let Some(step_name) = run
        .steps
        .iter()
        .find(|step| step.transform_run_id == transform_run.run_id)
        .map(|step| step.step.clone())
    else {
        return Ok(());
    };
    if transform_run.quarantined
        || transform_run.dispatch_status == TRANSFORM_WORK_FAILED
        || transform_run.dispatch_status == TRANSFORM_WORK_CANCELLED
    {
        fail_chain(
            store,
            &mut run,
            &step_name,
            if transform_run.dispatch_status == TRANSFORM_WORK_CANCELLED {
                CHAIN_WORK_CANCELLED
            } else {
                CHAIN_WORK_FAILED
            },
            if transform_run.quality_rule.is_empty() {
                "step failed"
            } else {
                &transform_run.quality_rule
            },
            now_ms,
        )?;
        return Ok(());
    }
    if transform_run.dispatch_status == TRANSFORM_WORK_PENDING
        || transform_run.dispatch_status == TRANSFORM_WORK_CLAIMED
    {
        return Ok(());
    }
    let chain = pinned_chain(&run)?;
    if let Err(error) = finish_completed_step(store, &chain, &mut run, &step_name, transform_run) {
        fail_chain(
            store,
            &mut run,
            &step_name,
            CHAIN_WORK_FAILED,
            &error,
            now_ms,
        )?;
        return Ok(());
    }
    store.persist_run(&run)?;
    let _ = advance_transform_chain(store, &run.run_id, now_ms, false, true)?;
    Ok(())
}

fn advance_transform_chain<S: ChainStore>(
    store: &S,
    run_id: &str,
    now_ms: i64,
    retry: bool,
    dispatch: bool,
) -> Result<TransformChainRun, String> {
    let mut run = store
        .load_run(run_id)?
        .ok_or_else(|| "transform chain run not found".to_string())?;
    if run.status == CHAIN_WORK_COMPLETED {
        return Ok(run);
    }
    let chain = match pinned_chain(&run) {
        Ok(chain) => chain,
        Err(error) => {
            fail_chain(store, &mut run, "chain", CHAIN_WORK_FAILED, &error, now_ms)?;
            return Ok(run);
        }
    };
    let transforms = match load_step_transforms(store, &chain) {
        Ok(transforms) => transforms,
        Err(error) => {
            fail_chain(store, &mut run, "chain", CHAIN_WORK_FAILED, &error, now_ms)?;
            return Ok(run);
        }
    };
    if let Err(error) = compile_named_edges(&chain, &transforms) {
        fail_chain(
            store,
            &mut run,
            "chain",
            CHAIN_WORK_FAILED,
            &error.message(),
            now_ms,
        )?;
        return Ok(run);
    }
    if retry {
        if !store.begin_retry(&run.run_id)? {
            return advance_transform_chain(store, run_id, now_ms, false, dispatch);
        }
        // begin_retry kept completed steps and running steps whose transform
        // run is still pending or claimed; reconcile_running_step resumes those.
        run = store
            .load_run(run_id)?
            .ok_or_else(|| "transform chain run not found".to_string())?;
    }
    if run.status != CHAIN_WORK_RUNNING {
        return Ok(run);
    }
    for step in chain.topo_order() {
        match run.step_status(&step.name) {
            Some(CHAIN_WORK_COMPLETED) => continue,
            Some(CHAIN_WORK_FAILED) | Some(CHAIN_WORK_CANCELLED) => return Ok(run),
            Some(CHAIN_WORK_RUNNING) => {
                match reconcile_running_step(store, &chain, &mut run, step, now_ms, dispatch)? {
                    StepProgress::Continue => continue,
                    StepProgress::Return => return Ok(run),
                    StepProgress::Recover => {
                        if start_step(store, &chain, &mut run, step, now_ms, true)? {
                            return Ok(run);
                        }
                        continue;
                    }
                }
            }
            _ => {}
        }
        if upstream_blocked(&chain, &run, step) {
            fail_chain(
                store,
                &mut run,
                &step.name,
                CHAIN_WORK_FAILED,
                "upstream step failed",
                now_ms,
            )?;
            return Ok(run);
        }
        if !upstream_complete(&chain, &run, step) {
            continue;
        }
        if !dispatch {
            continue;
        }
        if start_step(store, &chain, &mut run, step, now_ms, false)? {
            return Ok(run);
        }
    }
    if chain
        .steps
        .iter()
        .all(|step| run.step_status(&step.name) == Some(CHAIN_WORK_COMPLETED))
    {
        complete_chain(store, &mut run, &chain, now_ms)?;
    }
    Ok(run)
}

enum StepProgress {
    Continue,
    Return,
    Recover,
}

fn reconcile_running_step<S: ChainStore>(
    store: &S,
    chain: &TransformChain,
    run: &mut TransformChainRun,
    step: &ChainStep,
    now_ms: i64,
    dispatch: bool,
) -> Result<StepProgress, String> {
    let step_run_id = run.step_run_id(&step.name).unwrap_or("").to_string();
    if step_run_id.is_empty() {
        if dispatch && store.reclaim_stale_step(&run.run_id, &step.name, now_ms)? {
            return Ok(StepProgress::Recover);
        }
        return Ok(StepProgress::Return);
    }
    let Some(transform_run) = store.get_transform_run(&step_run_id)? else {
        return Ok(StepProgress::Return);
    };
    if transform_run.dispatch_status == TRANSFORM_WORK_PENDING
        || transform_run.dispatch_status == TRANSFORM_WORK_CLAIMED
    {
        return Ok(StepProgress::Return);
    }
    if transform_run.quarantined
        || transform_run.dispatch_status == TRANSFORM_WORK_FAILED
        || transform_run.dispatch_status == TRANSFORM_WORK_CANCELLED
    {
        fail_chain(
            store,
            run,
            &step.name,
            if transform_run.dispatch_status == TRANSFORM_WORK_CANCELLED {
                CHAIN_WORK_CANCELLED
            } else {
                CHAIN_WORK_FAILED
            },
            if transform_run.quality_rule.is_empty() {
                "step failed"
            } else {
                &transform_run.quality_rule
            },
            now_ms,
        )?;
        return Ok(StepProgress::Return);
    }
    if transform_run.dispatch_status != TRANSFORM_WORK_COMPLETED {
        return Ok(StepProgress::Return);
    }
    if let Err(error) = finish_completed_step(store, chain, run, &step.name, &transform_run) {
        fail_chain(store, run, &step.name, CHAIN_WORK_FAILED, &error, now_ms)?;
        return Ok(StepProgress::Return);
    }
    store.persist_run(run)?;
    Ok(StepProgress::Continue)
}

fn start_step<S: ChainStore>(
    store: &S,
    chain: &TransformChain,
    run: &mut TransformChainRun,
    step: &ChainStep,
    now_ms: i64,
    already_claimed: bool,
) -> Result<bool, String> {
    if let Err(error) = assert_upstream_outputs(store, chain, run, step) {
        fail_chain(store, run, &step.name, CHAIN_WORK_FAILED, &error, now_ms)?;
        return Ok(true);
    }
    if !already_claimed && !store.try_claim_step(&run.run_id, &step.name, now_ms)? {
        if let Some(fresh) = store.load_run(&run.run_id)? {
            *run = fresh;
        }
        return Ok(true);
    }
    if !already_claimed {
        run.record_step(&step.name, "", CHAIN_WORK_RUNNING);
        store.persist_run(run)?;
    }
    let transform_run = match store.run_transform(
        &chain.namespace,
        &step.transform_id,
        &run.tenant_id,
        &step.transform_digest,
        now_ms,
    ) {
        Ok(transform_run) => transform_run,
        Err(error) => {
            fail_chain(store, run, &step.name, CHAIN_WORK_FAILED, &error, now_ms)?;
            return Ok(true);
        }
    };
    let transform_run_id = transform_run.run_id.clone();
    if !store.bind_step_run(&run.run_id, &step.name, &transform_run_id)? {
        if let Some(fresh) = store.load_run(&run.run_id)? {
            *run = fresh;
        }
        return Ok(true);
    }
    run.record_step(&step.name, &transform_run_id, CHAIN_WORK_RUNNING);
    store.persist_run(run)?;
    let transform_run = store
        .get_transform_run(&transform_run_id)?
        .unwrap_or(transform_run);
    if transform_run.profile == ISOLATED_CLASS
        && (transform_run.dispatch_status == TRANSFORM_WORK_PENDING
            || transform_run.dispatch_status == TRANSFORM_WORK_CLAIMED)
    {
        return Ok(true);
    }
    if transform_run.quarantined
        || transform_run.dispatch_status == TRANSFORM_WORK_FAILED
        || transform_run.dispatch_status == TRANSFORM_WORK_CANCELLED
    {
        fail_chain(
            store,
            run,
            &step.name,
            if transform_run.dispatch_status == TRANSFORM_WORK_CANCELLED {
                CHAIN_WORK_CANCELLED
            } else {
                CHAIN_WORK_FAILED
            },
            if transform_run.quality_rule.is_empty() {
                "step failed"
            } else {
                &transform_run.quality_rule
            },
            now_ms,
        )?;
        return Ok(true);
    }
    if let Err(error) = finish_completed_step(store, chain, run, &step.name, &transform_run) {
        fail_chain(store, run, &step.name, CHAIN_WORK_FAILED, &error, now_ms)?;
        return Ok(true);
    }
    store.persist_run(run)?;
    Ok(false)
}

fn pinned_chain(run: &TransformChainRun) -> Result<TransformChain, String> {
    if run.definition_json.is_empty() {
        return Err("transform chain run is missing pinned definition".into());
    }
    serde_json::from_str(&run.definition_json).map_err(|error| error.to_string())
}

fn finish_completed_step<S: ChainStore>(
    store: &S,
    chain: &TransformChain,
    run: &mut TransformChainRun,
    step_name: &str,
    transform_run: &TransformRun,
) -> Result<(), String> {
    let step = chain
        .step(step_name)
        .ok_or_else(|| "chain step not found".to_string())?;
    let transform = store
        .get_transform(&chain.namespace, &step.transform_id)?
        .ok_or_else(|| "governed transform not found".to_string())?;
    if !step.transform_digest.is_empty() && transform.definition_digest != step.transform_digest {
        return Err("governed transform definition changed".into());
    }
    let rows = store.query_output_rows(&transform.output_dataset_id)?;
    if !transform_run.output_digest.is_empty() {
        let keys = store.dataset_partition_keys(&transform.output_dataset_id)?;
        if dataset_digest(&keys, &rows) != transform_run.output_digest {
            return Err("step output changed before assertion".into());
        }
    }
    evaluate_assertions(&step.assertions, &rows).map_err(|error| error.message())?;
    run.record_step(step_name, &transform_run.run_id, CHAIN_WORK_COMPLETED);
    Ok(())
}

fn complete_chain<S: ChainStore>(
    store: &S,
    run: &mut TransformChainRun,
    chain: &TransformChain,
    now_ms: i64,
) -> Result<(), String> {
    let mut next = run.clone();
    next.status = CHAIN_WORK_COMPLETED.into();
    next.completed_at_ms = now_ms;
    let (input_digest, output_digest) = endpoint_digests(store, chain, &next)?;
    next.input_digest = input_digest;
    next.output_digest = output_digest;
    let receipt = chain_receipt(&next, &next.input_digest, &next.output_digest);
    finish_chain(store, run, next, &receipt)
}

fn fail_chain<S: ChainStore>(
    store: &S,
    run: &mut TransformChainRun,
    failed_step: &str,
    status: &str,
    error: &str,
    now_ms: i64,
) -> Result<(), String> {
    let mut next = run.clone();
    let existing_run_id = next.step_run_id(failed_step).unwrap_or("").to_string();
    if existing_run_id.is_empty() && next.step_status(failed_step).is_none() {
        next.record_step(failed_step, "", status);
    } else {
        next.record_step(failed_step, &existing_run_id, status);
    }
    next.status = status.to_string();
    next.failed_step = failed_step.to_string();
    next.error = error.to_string();
    next.completed_at_ms = now_ms;
    let receipt = chain_receipt(&next, "", "");
    finish_chain(store, run, next, &receipt)
}

/// Apply a terminal transition. When another caller already ended the run,
/// `run` becomes the stored run and its recorded cause and receipt stay.
fn finish_chain<S: ChainStore>(
    store: &S,
    run: &mut TransformChainRun,
    next: TransformChainRun,
    receipt: &TransformRun,
) -> Result<(), String> {
    *run = if store.finish_run(&next, receipt)? {
        next
    } else {
        store
            .load_run(&run.run_id)?
            .ok_or_else(|| "transform chain run not found".to_string())?
    };
    Ok(())
}

fn endpoint_digests<S: ChainStore>(
    store: &S,
    chain: &TransformChain,
    run: &TransformChainRun,
) -> Result<(String, String), String> {
    // Every root step's input and every sink step's output, not only the
    // first and last in topological order (#2881).
    let mut inputs = Vec::new();
    for step in chain.root_steps() {
        let digest = step_transform_run(store, run, &step.name)?
            .map(|run| run.input_digest)
            .unwrap_or_default();
        inputs.push((step.name.as_str(), digest));
    }
    let mut outputs = Vec::new();
    for step in chain.sink_steps() {
        let digest = step_transform_run(store, run, &step.name)?
            .map(|run| run.output_digest)
            .unwrap_or_default();
        outputs.push((step.name.as_str(), digest));
    }
    let pairs = |endpoints: &[(&str, String)]| {
        let pairs: Vec<(&str, &str)> = endpoints
            .iter()
            .map(|(step, digest)| (*step, digest.as_str()))
            .collect();
        chain_endpoint_digest(&pairs)
    };
    Ok((pairs(&inputs), pairs(&outputs)))
}

/// The step's recorded transform run, if it ran.
fn step_transform_run<S: ChainStore>(
    store: &S,
    run: &TransformChainRun,
    step: &str,
) -> Result<Option<TransformRun>, String> {
    match run.step_run_id(step) {
        Some(run_id) if !run_id.is_empty() => store.get_transform_run(run_id),
        _ => Ok(None),
    }
}

fn upstream_complete(chain: &TransformChain, run: &TransformChainRun, step: &ChainStep) -> bool {
    chain.edges.iter().all(|edge| {
        edge.to_step != step.name || run.step_status(&edge.from_step) == Some(CHAIN_WORK_COMPLETED)
    })
}

fn upstream_blocked(chain: &TransformChain, run: &TransformChainRun, step: &ChainStep) -> bool {
    chain.edges.iter().any(|edge| {
        edge.to_step == step.name
            && matches!(
                run.step_status(&edge.from_step),
                Some(CHAIN_WORK_FAILED) | Some(CHAIN_WORK_CANCELLED)
            )
    })
}

fn assert_upstream_outputs<S: ChainStore>(
    store: &S,
    chain: &TransformChain,
    run: &TransformChainRun,
    step: &ChainStep,
) -> Result<(), String> {
    for edge in chain.edges.iter().filter(|edge| edge.to_step == step.name) {
        let Some(upstream_run_id) = run.step_run_id(&edge.from_step) else {
            continue;
        };
        if upstream_run_id.is_empty() {
            continue;
        }
        let Some(upstream_run) = store.get_transform_run(upstream_run_id)? else {
            return Err("upstream transform run not found".into());
        };
        if upstream_run.output_digest.is_empty() {
            continue;
        }
        let Some(upstream_step) = chain.step(&edge.from_step) else {
            continue;
        };
        let transform = store
            .get_transform(&chain.namespace, &upstream_step.transform_id)?
            .ok_or_else(|| "governed transform not found".to_string())?;
        let rows = store.query_output_rows(&transform.output_dataset_id)?;
        let keys = store.dataset_partition_keys(&transform.output_dataset_id)?;
        if dataset_digest(&keys, &rows) != upstream_run.output_digest {
            return Err("upstream step output changed before downstream admission".into());
        }
    }
    Ok(())
}

fn load_step_transforms<S: ChainStore>(
    store: &S,
    chain: &TransformChain,
) -> Result<BTreeMap<String, crate::sekai::governed_transform::GovernedTransform>, String> {
    let mut transforms = BTreeMap::new();
    for step in &chain.steps {
        let transform = store
            .get_transform(&chain.namespace, &step.transform_id)?
            .ok_or_else(|| "governed transform not found".to_string())?;
        transforms.insert(step.transform_id.clone(), transform);
    }
    Ok(transforms)
}

impl ChainStore for SekaiDb {
    fn persist_chain(&self, chain: &TransformChain, created_at_ms: i64) -> Result<(), String> {
        let json = serde_json::to_string(chain).map_err(|error| error.to_string())?;
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO sekai_transform_chain
                 (namespace, chain_id, definition_json, definition_digest, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    chain.namespace,
                    chain.chain_id,
                    json,
                    chain.definition_digest,
                    created_at_ms
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn load_chain(
        &self,
        namespace: &str,
        chain_id: &str,
    ) -> Result<Option<TransformChain>, String> {
        self.conn()
            .query_row(
                "SELECT definition_json FROM sekai_transform_chain
                 WHERE namespace = ?1 AND chain_id = ?2",
                params![namespace, chain_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|json| serde_json::from_str(&json).map_err(|error| error.to_string()))
            .transpose()
    }

    fn persist_run(&self, run: &TransformChainRun) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        // Terminal status is monotonic here; retry uses begin_retry.
        tx.execute(
            "INSERT INTO sekai_transform_chain_run
             (run_id, namespace, chain_id, definition_digest, definition_json, tenant_id, identity, status, failed_step, error, created_at_ms, completed_at_ms, input_digest, output_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(run_id) DO UPDATE SET
                status = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.status
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND excluded.status = 'running' THEN sekai_transform_chain_run.status
                    ELSE excluded.status
                END,
                failed_step = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.failed_step
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND excluded.status = 'running' THEN sekai_transform_chain_run.failed_step
                    ELSE excluded.failed_step
                END,
                error = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.error
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND excluded.status = 'running' THEN sekai_transform_chain_run.error
                    ELSE excluded.error
                END,
                completed_at_ms = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.completed_at_ms
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND excluded.status = 'running' THEN sekai_transform_chain_run.completed_at_ms
                    ELSE excluded.completed_at_ms
                END,
                input_digest = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.input_digest
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND excluded.status = 'running' THEN sekai_transform_chain_run.input_digest
                    ELSE excluded.input_digest
                END,
                output_digest = CASE
                    WHEN sekai_transform_chain_run.status = 'completed' THEN sekai_transform_chain_run.output_digest
                    WHEN sekai_transform_chain_run.status IN ('failed', 'cancelled') AND excluded.status = 'running' THEN sekai_transform_chain_run.output_digest
                    ELSE excluded.output_digest
                END",
            params![
                run.run_id,
                run.namespace,
                run.chain_id,
                run.definition_digest,
                run.definition_json,
                run.tenant_id,
                run.identity,
                run.status,
                run.failed_step,
                run.error,
                run.created_at_ms,
                run.completed_at_ms,
                run.input_digest,
                run.output_digest
            ],
        )
        .map_err(|error| error.to_string())?;
        upsert_step_runs_sqlite(&tx, run)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn try_insert_run(&self, run: &TransformChainRun) -> Result<bool, String> {
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_transform_chain_run
                 (run_id, namespace, chain_id, definition_digest, definition_json, tenant_id, identity, status, failed_step, error, created_at_ms, completed_at_ms, input_digest, output_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(namespace, chain_id, identity) DO NOTHING",
                params![
                    run.run_id,
                    run.namespace,
                    run.chain_id,
                    run.definition_digest,
                    run.definition_json,
                    run.tenant_id,
                    run.identity,
                    run.status,
                    run.failed_step,
                    run.error,
                    run.created_at_ms,
                    run.completed_at_ms,
                    run.input_digest,
                    run.output_digest
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    fn load_run(&self, run_id: &str) -> Result<Option<TransformChainRun>, String> {
        load_run_sqlite(&self.conn(), "run_id = ?1", params![run_id])
    }

    fn load_run_by_identity(
        &self,
        namespace: &str,
        chain_id: &str,
        identity: &str,
    ) -> Result<Option<TransformChainRun>, String> {
        load_run_sqlite(
            &self.conn(),
            "namespace = ?1 AND chain_id = ?2 AND identity = ?3",
            params![namespace, chain_id, identity],
        )
    }

    fn load_run_id_for_step(&self, transform_run_id: &str) -> Result<Option<String>, String> {
        self.conn()
            .query_row(
                "SELECT chain_run_id FROM sekai_transform_chain_step_run
                 WHERE transform_run_id = ?1",
                params![transform_run_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn try_claim_step(&self, run_id: &str, step: &str, now_ms: i64) -> Result<bool, String> {
        let changed = self
            .conn()
            .execute(
                "INSERT OR IGNORE INTO sekai_transform_chain_step_run
                 (chain_run_id, step_name, transform_run_id, status, claimed_at_ms)
                 VALUES (?1, ?2, '', 'running', ?3)",
                params![run_id, step, now_ms],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    fn bind_step_run(
        &self,
        run_id: &str,
        step: &str,
        transform_run_id: &str,
    ) -> Result<bool, String> {
        let changed = self
            .conn()
            .execute(
                "UPDATE sekai_transform_chain_step_run
                 SET transform_run_id = ?3
                 WHERE chain_run_id = ?1 AND step_name = ?2 AND transform_run_id = ''",
                params![run_id, step, transform_run_id],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    fn reclaim_stale_step(&self, run_id: &str, step: &str, now_ms: i64) -> Result<bool, String> {
        let deadline = now_ms.saturating_sub(CHAIN_STEP_CLAIM_LEASE_MS);
        let changed = self
            .conn()
            .execute(
                "UPDATE sekai_transform_chain_step_run
                 SET claimed_at_ms = ?3
                 WHERE chain_run_id = ?1 AND step_name = ?2
                   AND transform_run_id = '' AND claimed_at_ms <= ?4",
                params![run_id, step, now_ms, deadline],
            )
            .map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    fn begin_retry(&self, run_id: &str) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let changed = tx
            .execute(
                "UPDATE sekai_transform_chain_run
                 SET status = 'running', failed_step = '', error = '', completed_at_ms = 0
                 WHERE run_id = ?1 AND status IN ('failed', 'cancelled')",
                params![run_id],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute(
            "DELETE FROM sekai_transform_chain_step_run
             WHERE chain_run_id = ?1 AND status != 'completed'
               AND NOT (status = 'running' AND transform_run_id IN (
                   SELECT run_id FROM sekai_governed_transform_run
                   WHERE dispatch_status IN ('pending', 'claimed')))",
            params![run_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    fn dataset_partition_keys(&self, dataset_id: &str) -> Result<Vec<String>, String> {
        Ok(self
            .get_dataset(dataset_id)?
            .map(|dataset| dataset.partition_keys)
            .unwrap_or_default())
    }

    fn get_transform(
        &self,
        namespace: &str,
        transform_id: &str,
    ) -> Result<Option<crate::sekai::governed_transform::GovernedTransform>, String> {
        self.get_governed_transform(namespace, transform_id)
    }

    fn run_transform(
        &self,
        namespace: &str,
        transform_id: &str,
        tenant_id: &str,
        expected_definition_digest: &str,
        now_ms: i64,
    ) -> Result<TransformRun, String> {
        self.run_governed_transform_owned(
            namespace,
            transform_id,
            false,
            now_ms,
            tenant_id,
            expected_definition_digest,
        )
    }

    fn get_transform_run(&self, run_id: &str) -> Result<Option<TransformRun>, String> {
        self.get_governed_transform_run(run_id)
    }

    fn query_output_rows(&self, dataset_id: &str) -> Result<Vec<HashMap<String, String>>, String> {
        self.query_rows(dataset_id, &RowQuery::default())
    }

    fn finish_run(&self, run: &TransformChainRun, receipt: &TransformRun) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let changed = tx
            .execute(
                "UPDATE sekai_transform_chain_run
                 SET status = ?2, failed_step = ?3, error = ?4, completed_at_ms = ?5,
                     input_digest = ?6, output_digest = ?7
                 WHERE run_id = ?1 AND status = 'running'",
                params![
                    run.run_id,
                    run.status,
                    run.failed_step,
                    run.error,
                    run.completed_at_ms,
                    run.input_digest,
                    run.output_digest
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Ok(false);
        }
        upsert_step_runs_sqlite(&tx, run)?;
        crate::db::receipt_chain::append_transform_run_chain(&tx, receipt)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }
}

/// Upsert step rows; a step that reached a terminal status keeps it.
fn upsert_step_runs_sqlite(
    tx: &rusqlite::Transaction<'_>,
    run: &TransformChainRun,
) -> Result<(), String> {
    for step in &run.steps {
        tx.execute(
            "INSERT INTO sekai_transform_chain_step_run
             (chain_run_id, step_name, transform_run_id, status)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(chain_run_id, step_name) DO UPDATE SET
                transform_run_id = CASE WHEN transform_run_id = '' THEN excluded.transform_run_id ELSE transform_run_id END,
                status = CASE WHEN status IN ('completed', 'failed', 'cancelled') THEN status ELSE excluded.status END",
            params![run.run_id, step.step, step.transform_run_id, step.status],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn load_run_sqlite(
    conn: &rusqlite::Connection,
    where_sql: &str,
    params: impl rusqlite::Params,
) -> Result<Option<TransformChainRun>, String> {
    let sql = format!(
        "SELECT run_id, namespace, chain_id, definition_digest, definition_json, tenant_id, identity, status, failed_step, error, created_at_ms, completed_at_ms, input_digest, output_digest
         FROM sekai_transform_chain_run WHERE {where_sql}"
    );
    let row = conn
        .query_row(&sql, params, |row| {
            Ok(TransformChainRun {
                run_id: row.get(0)?,
                namespace: row.get(1)?,
                chain_id: row.get(2)?,
                definition_digest: row.get(3)?,
                definition_json: row.get(4)?,
                tenant_id: row.get(5)?,
                identity: row.get(6)?,
                status: row.get(7)?,
                failed_step: row.get(8)?,
                error: row.get(9)?,
                steps: Vec::new(),
                created_at_ms: row.get(10)?,
                completed_at_ms: row.get(11)?,
                input_digest: row.get(12)?,
                output_digest: row.get(13)?,
            })
        })
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(mut run) = row else {
        return Ok(None);
    };
    let mut stmt = conn
        .prepare(
            "SELECT step_name, transform_run_id, status FROM sekai_transform_chain_step_run
             WHERE chain_run_id = ?1 ORDER BY step_name",
        )
        .map_err(|error| error.to_string())?;
    let steps = stmt
        .query_map(params![run.run_id], |row| {
            Ok(crate::sekai::transform_chain::ChainStepRun {
                step: row.get(0)?,
                transform_run_id: row.get(1)?,
                status: row.get(2)?,
            })
        })
        .map_err(|error| error.to_string())?;
    run.steps = steps
        .map(|row| row.map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(run))
}

impl SekaiDb {
    pub fn put_transform_chain(
        &self,
        chain: &TransformChain,
        created_at_ms: i64,
    ) -> Result<TransformChain, String> {
        put_transform_chain(self, chain.clone(), created_at_ms)
    }

    pub fn run_transform_chain(
        &self,
        namespace: &str,
        chain_id: &str,
        idempotency_key: &str,
        tenant_id: &str,
        now_ms: i64,
    ) -> Result<(TransformChainRun, bool), String> {
        run_transform_chain(
            self,
            namespace,
            chain_id,
            idempotency_key,
            tenant_id,
            now_ms,
        )
    }

    pub fn peek_transform_chain_run(
        &self,
        run_id: &str,
    ) -> Result<Option<TransformChainRun>, String> {
        peek_transform_chain_run(self, run_id)
    }

    pub fn peek_transform_chain_run_by_identity(
        &self,
        namespace: &str,
        chain_id: &str,
        identity: &str,
    ) -> Result<Option<TransformChainRun>, String> {
        self.load_run_by_identity(namespace, chain_id, identity)
    }

    pub fn get_transform_chain_run(
        &self,
        run_id: &str,
        now_ms: i64,
    ) -> Result<Option<TransformChainRun>, String> {
        get_transform_chain_run(self, run_id, now_ms)
    }

    pub fn get_transform_chain(
        &self,
        namespace: &str,
        chain_id: &str,
    ) -> Result<Option<TransformChain>, String> {
        self.load_chain(namespace, chain_id)
    }

    /// The namespace's chain definitions, ordered by chain id.
    pub fn list_transform_chains(&self, namespace: &str) -> Result<Vec<TransformChain>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
                "SELECT definition_json FROM sekai_transform_chain
                 WHERE namespace = ?1 ORDER BY chain_id",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![namespace], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let json = row.map_err(|error| error.to_string())?;
            serde_json::from_str(&json).map_err(|error| error.to_string())
        })
        .collect()
    }

    /// One page of a chain's runs, newest first. `after` is the
    /// `(created_at_ms, run_id)` of the last run on the previous page, so a
    /// run started while paging never shifts older runs between pages.
    /// Stored status is returned as is; running runs are not advanced.
    pub fn list_transform_chain_runs(
        &self,
        namespace: &str,
        chain_id: &str,
        after: Option<(i64, &str)>,
        limit: usize,
    ) -> Result<Vec<TransformChainRun>, String> {
        let conn = self.conn();
        let (after_ms, after_id) = after.unwrap_or((i64::MAX, ""));
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = conn
            .prepare(
                "SELECT run_id FROM sekai_transform_chain_run
                 WHERE namespace = ?1 AND chain_id = ?2
                   AND (created_at_ms < ?3 OR (created_at_ms = ?3 AND run_id < ?4) OR ?5)
                 ORDER BY created_at_ms DESC, run_id DESC LIMIT ?6",
            )
            .map_err(|error| error.to_string())?;
        let ids = stmt
            .query_map(
                params![
                    namespace,
                    chain_id,
                    after_ms,
                    after_id,
                    after.is_none(),
                    limit
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        ids.iter()
            .filter_map(|id| load_run_sqlite(&conn, "run_id = ?1", params![id]).transpose())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::receipt_chain::{export_receipt_chain, install_test_signer};
    use crate::sekai::dataset::{ColumnDef, Dataset};
    use crate::sekai::governed_transform::{
        CONTRACT_VERSION, GovernedTransform, IsolatedProcessSpec, TRANSFORM_WORK_COMPLETED,
        TransformStep, WriteTransformRunCommand, rows_digest,
    };
    use crate::sekai::transform_chain::{
        CHAIN_ASSERT_NOT_NULL, CHAIN_CONTRACT, CHAIN_MISSING_NAME, CHAIN_PROFILE, ChainAssertion,
        ChainEdge, ChainStep,
    };
    use sekai_types::receipt_chain::{SigningKeySet, verify_bundle};
    use std::collections::HashMap;

    fn db() -> SekaiDb {
        SekaiDb::new(":memory:").unwrap()
    }

    fn db_with_receipts() -> SekaiDb {
        SekaiDb::memory_for_chisei_sql_functions()
    }

    fn dataset(id: &str) -> Dataset {
        Dataset {
            id: id.into(),
            name: id.into(),
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
                ColumnDef {
                    name: "keep".into(),
                    col_type: "string".into(),
                    classification: "public".into(),
                },
            ],
            object_id: String::new(),
            created: 1,
            partition_keys: Vec::new(),
        }
    }

    fn step_filter() -> TransformStep {
        TransformStep {
            kind: "filter".into(),
            column: "keep".into(),
            op: "eq".into(),
            value: "yes".into(),
            columns: Vec::new(),
        }
    }

    fn projection(id: &str, input: &str, output: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: id.into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: vec![step_filter()],
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

    fn isolated(id: &str, input: &str, output: &str) -> GovernedTransform {
        GovernedTransform {
            contract_version: CONTRACT_VERSION.into(),
            namespace: "ops".into(),
            transform_id: id.into(),
            input_dataset_id: input.into(),
            output_dataset_id: output.into(),
            steps: Vec::new(),
            quality_rule: String::new(),
            definition_digest: String::new(),
            analytical: None,
            isolated_process: Some(IsolatedProcessSpec {
                llm_step: None,
                engine: "python".into(),
                runtime_image: "runner:1".into(),
                inputs: Vec::new(),
                requires: Default::default(),
                code: String::new(),
                model_inputs: Default::default(),
                model_outputs: Default::default(),
            }),
            schedule: None,
            trigger: None,
        }
        .prepare()
        .unwrap()
    }

    fn three_step_chain() -> TransformChain {
        TransformChain {
            contract_version: CHAIN_CONTRACT.into(),
            namespace: "ops".into(),
            chain_id: "pipe".into(),
            steps: vec![
                ChainStep {
                    name: "a".into(),
                    transform_id: "t1".into(),
                    transform_digest: String::new(),
                    assertions: vec![ChainAssertion {
                        kind: CHAIN_ASSERT_NOT_NULL.into(),
                        column: "id".into(),
                        value: String::new(),
                    }],
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
    }

    fn seed_projection(db: &SekaiDb) {
        for id in ["in", "mid1", "mid2", "out"] {
            db.create_dataset(&dataset(id)).unwrap();
        }
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&projection("t1", "in", "mid1"), 10)
            .unwrap();
        db.put_governed_transform(&projection("t2", "mid1", "mid2"), 11)
            .unwrap();
        db.put_governed_transform(&projection("t3", "mid2", "out"), 12)
            .unwrap();
    }

    fn seed_isolated(db: &SekaiDb) {
        for id in ["in", "mid1", "mid2", "out"] {
            db.create_dataset(&dataset(id)).unwrap();
        }
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), "1".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_governed_transform(&isolated("t1", "in", "mid1"), 10)
            .unwrap();
        db.put_governed_transform(&isolated("t2", "mid1", "mid2"), 11)
            .unwrap();
        db.put_governed_transform(&isolated("t3", "mid2", "out"), 12)
            .unwrap();
    }

    fn write_claimed(db: &SekaiDb, now_ms: i64) -> TransformRun {
        let (work, _) = db
            .claim_transform_work("ops", "runner-a", "", 60_000, now_ms)
            .unwrap()
            .expect("claimable work");
        let output = vec![HashMap::from([
            ("id".into(), "1".into()),
            ("keep".into(), "yes".into()),
        ])];
        db.write_transform_run(
            WriteTransformRunCommand {
                run_id: work.run_id.clone(),
                runtime_id: work.claim_owner.clone(),
                claim_generation: work.claim_generation,
                fencing_token: work.fencing_token.clone(),
                rows: output.clone(),
                output_digest: rows_digest(&output),
                quarantined: false,
                quality_rule: String::new(),
                ..WriteTransformRunCommand::default()
            },
            now_ms + 10,
        )
        .unwrap()
    }

    /// Two independent steps are both roots and both sinks; the chain run's
    /// digests cover each of them, not only the first and last (#2881).
    #[test]
    fn several_root_and_sink_steps_all_enter_the_chain_digests() {
        let db = db();
        for id in ["in", "in2", "mid1", "mid2"] {
            db.create_dataset(&dataset(id)).unwrap();
        }
        for input in ["in", "in2"] {
            db.append_rows(
                input,
                &[HashMap::from([
                    ("id".into(), input.into()),
                    ("keep".into(), "yes".into()),
                ])],
            )
            .unwrap();
        }
        db.put_governed_transform(&projection("t1", "in", "mid1"), 10)
            .unwrap();
        db.put_governed_transform(&projection("t2", "in2", "mid2"), 11)
            .unwrap();
        let mut chain = three_step_chain();
        chain.steps.truncate(2);
        chain.steps[0].assertions.clear();
        chain.edges.clear();
        let chain = db.put_transform_chain(&chain, 20).unwrap();
        assert_eq!(chain.root_steps().len(), 2);
        assert_eq!(chain.sink_steps().len(), 2);

        let (run, _) = db.run_transform_chain("ops", "pipe", "k1", "", 30).unwrap();
        assert_eq!(run.status, CHAIN_WORK_COMPLETED);
        let step = |name: &str| {
            db.get_transform_run(run.step_run_id(name).unwrap())
                .unwrap()
                .unwrap()
        };
        let (a, b) = (step("a"), step("b"));
        assert_ne!(a.input_digest, b.input_digest);
        assert_eq!(
            run.input_digest,
            chain_endpoint_digest(&[("a", &a.input_digest), ("b", &b.input_digest)])
        );
        assert_eq!(
            run.output_digest,
            chain_endpoint_digest(&[("a", &a.output_digest), ("b", &b.output_digest)])
        );
    }

    #[test]
    fn three_step_projection_chain_completes_and_receipts_verify() {
        let db = db_with_receipts();
        let keys = SigningKeySet::from_seed_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
            1,
        )
        .unwrap();
        let _guard = install_test_signer(keys.clone());
        seed_projection(&db);
        let chain = db.put_transform_chain(&three_step_chain(), 20).unwrap();
        assert!(chain.definition_digest.starts_with("sha256:"));
        assert!(!chain.steps[0].transform_digest.is_empty());
        assert_eq!(
            chain.steps[0].transform_digest,
            db.get_governed_transform("ops", "t1")
                .unwrap()
                .unwrap()
                .definition_digest
        );
        let (run, replayed) = db.run_transform_chain("ops", "pipe", "k1", "", 30).unwrap();
        assert!(!replayed);
        assert_eq!(run.status, CHAIN_WORK_COMPLETED);
        assert_eq!(run.steps.len(), 3);
        assert!(
            run.steps
                .iter()
                .all(|step| step.status == CHAIN_WORK_COMPLETED)
        );
        assert_eq!(db.query_rows("out", &RowQuery::default()).unwrap().len(), 1);
        let (again, replayed) = db.run_transform_chain("ops", "pipe", "k1", "", 40).unwrap();
        assert!(replayed);
        assert_eq!(again.run_id, run.run_id);
        let bundle = export_receipt_chain(&db, "ops").unwrap();
        verify_bundle(&bundle, &[keys.current_public_key_hex().as_str()]).unwrap();
        let chain_entry = bundle
            .entries
            .iter()
            .find(|entry| entry.receipt_id == run.run_id)
            .expect("chain receipt");
        let receipt: TransformRun = serde_json::from_str(&chain_entry.receipt_json).unwrap();
        assert_eq!(receipt.profile, CHAIN_PROFILE);
        assert!(receipt.trigger_ref.contains(&run.steps[0].transform_run_id));
        assert!(!receipt.output_digest.is_empty());
        assert_eq!(run.output_digest, receipt.output_digest);
        assert!(!receipt.trigger_ref.to_ascii_lowercase().contains("secret"));
    }

    #[test]
    fn put_refuses_missing_named_edge() {
        let db = db();
        seed_projection(&db);
        let mut chain = three_step_chain();
        chain.edges[0].output = "missing".into();
        let error = db.put_transform_chain(&chain, 20).unwrap_err();
        assert!(error.contains(CHAIN_MISSING_NAME));
    }

    #[test]
    fn assertion_failure_skips_downstream() {
        let db = db();
        seed_projection(&db);
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), String::new()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (run, _) = db
            .run_transform_chain("ops", "pipe", "k-assert", "", 30)
            .unwrap();
        assert_eq!(run.status, CHAIN_WORK_FAILED);
        assert_eq!(run.failed_step, "a");
        assert!(
            run.step_status("b").is_none() || run.step_status("b") != Some(CHAIN_WORK_COMPLETED)
        );
        assert!(run.step_status("c").is_none());
    }

    fn chain_receipts(db: &SekaiDb, run_id: &str) -> usize {
        export_receipt_chain(db, "ops")
            .unwrap()
            .entries
            .iter()
            .filter(|entry| entry.receipt_id == run_id)
            .count()
    }

    #[test]
    fn a_late_step_event_leaves_a_failed_run_unchanged() {
        let db = db_with_receipts();
        let keys = SigningKeySet::from_seed_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
            1,
        )
        .unwrap();
        let _guard = install_test_signer(keys);
        seed_projection(&db);
        db.append_rows(
            "in",
            &[HashMap::from([
                ("id".into(), String::new()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (failed, _) = db
            .run_transform_chain("ops", "pipe", "k-late", "", 30)
            .unwrap();
        assert_eq!(failed.status, CHAIN_WORK_FAILED);
        assert_eq!(chain_receipts(&db, &failed.run_id), 1);

        let mut late = db
            .get_governed_transform_run(failed.step_run_id("a").unwrap())
            .unwrap()
            .unwrap();
        late.dispatch_status = TRANSFORM_WORK_FAILED.into();
        late.quality_rule = "late failure".into();
        on_transform_run_written(&db, &late, 90).unwrap();
        let reread = db
            .get_transform_chain_run(&failed.run_id, 95)
            .unwrap()
            .unwrap();
        for run in [db.load_run(&failed.run_id).unwrap().unwrap(), reread] {
            assert_eq!(run.status, CHAIN_WORK_FAILED);
            assert_eq!(run.failed_step, failed.failed_step);
            assert_eq!(run.error, failed.error);
            assert_eq!(run.completed_at_ms, failed.completed_at_ms);
        }
        assert_eq!(chain_receipts(&db, &failed.run_id), 1);

        // Retry with the same idempotency key reopens the run.
        let (retried, _) = db
            .run_transform_chain("ops", "pipe", "k-late", "", 100)
            .unwrap();
        assert_eq!(retried.run_id, failed.run_id);
        assert_eq!(retried.status, CHAIN_WORK_FAILED);
        assert_eq!(retried.completed_at_ms, 100);
        assert_eq!(chain_receipts(&db, &failed.run_id), 2);
    }

    #[test]
    fn a_second_completion_appends_no_receipt() {
        let db = db_with_receipts();
        let keys = SigningKeySet::from_seed_hex(
            "0000000000000000000000000000000000000000000000000000000000000003",
            1,
        )
        .unwrap();
        let _guard = install_test_signer(keys);
        seed_projection(&db);
        let chain = db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (run, _) = db
            .run_transform_chain("ops", "pipe", "k-twice", "", 30)
            .unwrap();
        assert_eq!(run.status, CHAIN_WORK_COMPLETED);
        assert_eq!(chain_receipts(&db, &run.run_id), 1);

        // A caller that read the run while it was still running.
        let mut stale = run.clone();
        stale.status = CHAIN_WORK_RUNNING.into();
        stale.completed_at_ms = 0;
        complete_chain(&db, &mut stale, &chain, 500).unwrap();
        assert_eq!(stale.completed_at_ms, run.completed_at_ms);
        assert_eq!(chain_receipts(&db, &run.run_id), 1);
    }

    #[test]
    fn kill_isolated_mid_chain_skips_downstream_and_rerun_skips_completed() {
        let db = db();
        seed_isolated(&db);
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (run, _) = db
            .run_transform_chain("ops", "pipe", "k-kill", "", 30)
            .unwrap();
        assert_eq!(run.status, CHAIN_WORK_RUNNING);
        assert_eq!(run.step_status("a"), Some(CHAIN_WORK_RUNNING));
        assert!(run.step_status("b").is_none());
        let first = write_claimed(&db, 40);
        assert_eq!(first.dispatch_status, TRANSFORM_WORK_COMPLETED);
        let after_a = db
            .get_transform_chain_run(&run.run_id, 50)
            .unwrap()
            .unwrap();
        assert_eq!(after_a.step_status("a"), Some(CHAIN_WORK_COMPLETED));
        assert_eq!(after_a.step_status("b"), Some(CHAIN_WORK_RUNNING));
        assert!(after_a.step_status("c").is_none());
        let b_run_id = after_a.step_run_id("b").unwrap().to_string();
        db.cancel_governed_transform_run(&b_run_id, 60).unwrap();
        let failed = db
            .get_transform_chain_run(&run.run_id, 70)
            .unwrap()
            .unwrap();
        assert_eq!(failed.status, CHAIN_WORK_CANCELLED);
        assert_eq!(failed.failed_step, "b");
        assert!(failed.step_status("c").is_none());
        let a_run = failed.step_run_id("a").unwrap().to_string();
        let (rerun, replayed) = db
            .run_transform_chain("ops", "pipe", "k-kill", "", 80)
            .unwrap();
        assert!(!replayed);
        assert_eq!(rerun.run_id, run.run_id);
        assert_eq!(rerun.step_run_id("a"), Some(a_run.as_str()));
        assert_eq!(rerun.step_status("b"), Some(CHAIN_WORK_RUNNING));
        assert_ne!(rerun.step_run_id("b"), Some(b_run_id.as_str()));
        write_claimed(&db, 90);
        write_claimed(&db, 110);
        let done = db
            .get_transform_chain_run(&run.run_id, 130)
            .unwrap()
            .unwrap();
        assert_eq!(done.status, CHAIN_WORK_COMPLETED);
        assert_eq!(done.steps.len(), 3);
        assert_eq!(db.query_rows("out", &RowQuery::default()).unwrap().len(), 1);
    }

    #[test]
    fn retry_keeps_a_step_whose_isolated_run_is_still_pending() {
        let db = db();
        seed_isolated(&db);
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (run, _) = db
            .run_transform_chain("ops", "pipe", "k-pending", "", 30)
            .unwrap();
        assert_eq!(run.step_status("a"), Some(CHAIN_WORK_RUNNING));
        let a_run = run.step_run_id("a").unwrap().to_string();
        // Break the b -> c edge so the chain fails while step a is pending.
        db.put_governed_transform(&isolated("t3", "in", "out"), 40)
            .unwrap();
        let failed = db
            .get_transform_chain_run(&run.run_id, 50)
            .unwrap()
            .unwrap();
        assert_eq!(failed.status, CHAIN_WORK_FAILED);
        assert_eq!(failed.failed_step, "chain");
        db.put_governed_transform(&isolated("t3", "mid2", "out"), 60)
            .unwrap();
        let (rerun, replayed) = db
            .run_transform_chain("ops", "pipe", "k-pending", "", 70)
            .unwrap();
        assert!(!replayed);
        assert_eq!(rerun.status, CHAIN_WORK_RUNNING);
        assert_eq!(rerun.step_status("a"), Some(CHAIN_WORK_RUNNING));
        assert_eq!(rerun.step_run_id("a"), Some(a_run.as_str()));
        assert!(rerun.step_status("chain").is_none());
        let t1_runs = db
            .list_governed_transform_runs("ops", 100)
            .unwrap()
            .into_iter()
            .filter(|transform_run| transform_run.transform_id == "t1")
            .count();
        assert_eq!(t1_runs, 1);
        for now_ms in [80, 100, 120] {
            write_claimed(&db, now_ms);
        }
        let done = db
            .get_transform_chain_run(&run.run_id, 140)
            .unwrap()
            .unwrap();
        assert_eq!(done.status, CHAIN_WORK_COMPLETED);
    }

    #[test]
    fn identity_is_scoped_to_chain() {
        let db = db();
        seed_projection(&db);
        let mut other = three_step_chain();
        other.chain_id = "pipe2".into();
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        db.put_transform_chain(&other, 21).unwrap();
        let (first, _) = db
            .run_transform_chain("ops", "pipe", "same", "", 30)
            .unwrap();
        let (second, _) = db
            .run_transform_chain("ops", "pipe2", "same", "", 31)
            .unwrap();
        assert_ne!(first.run_id, second.run_id);
        assert_eq!(first.identity, second.identity);
        assert_eq!(first.status, CHAIN_WORK_COMPLETED);
        assert_eq!(second.status, CHAIN_WORK_COMPLETED);
    }

    #[test]
    fn persist_run_does_not_regress_completed_status() {
        let db = db();
        seed_projection(&db);
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (run, _) = db
            .run_transform_chain("ops", "pipe", "k-stale", "", 30)
            .unwrap();
        assert_eq!(run.status, CHAIN_WORK_COMPLETED);
        let mut stale = run.clone();
        stale.status = CHAIN_WORK_RUNNING.into();
        stale.completed_at_ms = 0;
        stale.input_digest.clear();
        stale.output_digest.clear();
        db.persist_run(&stale).unwrap();
        let loaded = db.load_run(&run.run_id).unwrap().unwrap();
        assert_eq!(loaded.status, CHAIN_WORK_COMPLETED);
        assert_eq!(loaded.completed_at_ms, run.completed_at_ms);
        assert_eq!(loaded.output_digest, run.output_digest);
    }

    #[test]
    fn mutated_upstream_output_fails_downstream_admission() {
        let db = db();
        seed_isolated(&db);
        db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let (run, _) = db
            .run_transform_chain("ops", "pipe", "k-mutate", "", 30)
            .unwrap();
        write_claimed(&db, 40);
        let after_a = db
            .get_transform_chain_run(&run.run_id, 50)
            .unwrap()
            .unwrap();
        assert_eq!(after_a.step_status("a"), Some(CHAIN_WORK_COMPLETED));
        let b_run_id = after_a.step_run_id("b").unwrap().to_string();
        db.append_rows(
            "mid1",
            &[HashMap::from([
                ("id".into(), "2".into()),
                ("keep".into(), "yes".into()),
            ])],
        )
        .unwrap();
        db.cancel_governed_transform_run(&b_run_id, 60).unwrap();
        let (rerun, replayed) = db
            .run_transform_chain("ops", "pipe", "k-mutate", "", 80)
            .unwrap();
        assert!(!replayed);
        assert_eq!(rerun.status, CHAIN_WORK_FAILED);
        assert_eq!(rerun.failed_step, "b");
        assert!(rerun.error.contains("upstream step output changed"));
        assert_eq!(rerun.step_status("a"), Some(CHAIN_WORK_COMPLETED));
        assert!(rerun.step_status("c").is_none());
    }

    #[test]
    fn identity_conflict_joins_the_existing_run() {
        let db = db();
        seed_projection(&db);
        let chain = db.put_transform_chain(&three_step_chain(), 20).unwrap();
        let first = TransformChainRun {
            run_id: "chain-first".into(),
            namespace: "ops".into(),
            chain_id: "pipe".into(),
            definition_digest: chain.definition_digest.clone(),
            definition_json: serde_json::to_string(&chain).unwrap(),
            tenant_id: String::new(),
            identity: "same-key".into(),
            status: CHAIN_WORK_RUNNING.into(),
            failed_step: String::new(),
            error: String::new(),
            steps: Vec::new(),
            created_at_ms: 30,
            completed_at_ms: 0,
            input_digest: String::new(),
            output_digest: String::new(),
        };
        assert!(db.try_insert_run(&first).unwrap());
        let mut second = first.clone();
        second.run_id = "chain-second".into();
        assert!(!db.try_insert_run(&second).unwrap());
        let (joined, replayed) = db
            .run_transform_chain("ops", "pipe", "same-key", "", 40)
            .unwrap();
        assert!(!replayed);
        assert_eq!(joined.run_id, "chain-first");
        assert_eq!(joined.status, CHAIN_WORK_COMPLETED);
    }
}
