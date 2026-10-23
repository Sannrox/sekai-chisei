//! Parallel eval runs over a dataset version (#1674).
//!
//! A run executes every case of one eval dataset version (#1673) against a
//! named agent, model and tool version, at most `concurrency` cases at a
//! time, within a run budget. Each case's result is durable per (run, case)
//! and written once: a restarted run reads what is recorded, skips those
//! cases, and counts their cost, so a case is never run into the ledger
//! twice. A case starts only if the spent budget, the budget reserved by
//! cases in flight and its own cost cap fit the run budget; once one does
//! not, the run stops starting cases and ends `budget_exhausted` with the
//! unrun cases listed. Runs are started from outside the plane (CI or the
//! delivery plane per release); there is no in-plane scheduler.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::chisei::eval_dataset::{EvalCase, EvalDataset};
use crate::chisei::eval_policy::{
    CasePolicy, CasePolicyOutcome, CaseReceipts, RunPolicyReport, score_case, score_run,
};

pub const EVAL_RUN_CONTRACT: &str = "chisei.eval-run/v1";
pub const MAX_CONCURRENCY: u32 = 64;
/// Upper bound on a run budget and a case cap, so every sum of spend and
/// reservations fits an `i64`.
pub const MAX_BUDGET_MICROS: i64 = 1_000_000_000_000_000;
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_BUDGET_EXHAUSTED: &str = "budget_exhausted";
/// Some cases failed to run (not to pass); running again resumes them.
pub const STATUS_INCOMPLETE: &str = "incomplete";
pub const RUN_CONFLICT: &str = "eval run id is already used by another run spec";

/// What one run is: the dataset version and what it is run against, and its
/// limits. Fixed at the first start; a restart must repeat it exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRunSpec {
    pub contract_version: String,
    pub namespace: String,
    pub run_id: String,
    pub dataset: String,
    pub dataset_version: String,
    pub agent: String,
    /// `provider/model` the cases run against.
    pub model: String,
    pub tool_version: String,
    /// The evaluator definition every case runs through, and its content
    /// digest, so a restart cannot switch evaluators mid-run.
    pub evaluator_definition_id: String,
    pub evaluator_digest: String,
    pub concurrency: u32,
    /// The run's spending limit, in cost micro-units.
    pub budget_micros: i64,
    /// What one case may cost at most; reserved before a case starts.
    pub max_case_cost_micros: i64,
}

impl EvalRunSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != EVAL_RUN_CONTRACT {
            return Err(format!("contract_version must be {EVAL_RUN_CONTRACT}"));
        }
        for (field, value) in [
            ("namespace", &self.namespace),
            ("run_id", &self.run_id),
            ("dataset", &self.dataset),
            ("dataset_version", &self.dataset_version),
            ("agent", &self.agent),
            ("model", &self.model),
            ("tool_version", &self.tool_version),
            ("evaluator_definition_id", &self.evaluator_definition_id),
            ("evaluator_digest", &self.evaluator_digest),
        ] {
            if value.trim().is_empty()
                || value.len() > 200
                || value.chars().any(char::is_whitespace)
            {
                return Err(format!(
                    "{field} must be 1 to 200 characters without whitespace"
                ));
            }
        }
        if !(1..=MAX_CONCURRENCY).contains(&self.concurrency) {
            return Err(format!("concurrency must be 1 to {MAX_CONCURRENCY}"));
        }
        if !(1..=MAX_BUDGET_MICROS).contains(&self.budget_micros)
            || !(1..=MAX_BUDGET_MICROS).contains(&self.max_case_cost_micros)
        {
            return Err(format!(
                "budget_micros and max_case_cost_micros must be 1 to {MAX_BUDGET_MICROS}"
            ));
        }
        Ok(())
    }
}

/// What running one case produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseOutcome {
    pub passed: bool,
    pub reason: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_micros: i64,
    /// The receipts the case's run left, as the executor reports them; read
    /// by policy scoring and never stored (#1676). `None` when the executor
    /// cannot report them, which scores as `missing_receipts`.
    #[serde(skip)]
    pub receipts: Option<CaseReceipts>,
    /// The case's policy outcome, scored from `receipts` before the result
    /// is recorded. Absent on results recorded before scoring existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<CasePolicyOutcome>,
}

/// One case's durable result: its ledger line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalCaseResult {
    pub case_id: String,
    pub outcome: CaseOutcome,
    pub recorded_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalRunReport {
    pub status: String,
    pub cases_total: usize,
    /// Every recorded result, including those of earlier starts: the ledger.
    pub results: Vec<EvalCaseResult>,
    pub spent_micros: i64,
    /// Cases with no result: never started for the budget, or failed to run.
    pub unrun_cases: Vec<String>,
    /// Spend reserved for cases a crashed start never recorded; counted
    /// against the budget, not in the ledger.
    pub uncertain_micros: i64,
    /// Policy violations over every recorded case, by kind (#1676).
    pub policy: RunPolicyReport,
}

/// Durable per-run state. Implementations make each write idempotent: the
/// first spec and the first result per case win.
pub trait EvalRunStore: Sync {
    /// Records the run, or returns the one already recorded under its id.
    fn put_dataset_run(&self, spec: &EvalRunSpec, now_ms: i64) -> Result<EvalRunSpec, String>;
    /// While `holder` holds the run's lease: renews it until `until_ms` and
    /// adds `reserve_micros` to the run's uncertain spend before a case is
    /// dispatched, so a crash after the evaluator charged still counts
    /// against the budget. False when the lease is lost.
    fn reserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String>;
    /// While `holder` holds the lease, in one write: records the result (or
    /// keeps the one already recorded) and moves `reserve_micros` out of the
    /// uncertain spend. `None` when the lease is lost; the reservation then
    /// stays counted.
    fn record_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        result: &EvalCaseResult,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<Option<EvalCaseResult>, String>;
    /// Gives back a reservation for a case that spent nothing, while
    /// `holder` holds the lease.
    fn unreserve_dataset_run_case(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        reserve_micros: i64,
        now_ms: i64,
    ) -> Result<(), String>;
    /// Spend reserved for cases whose outcome was never recorded.
    fn dataset_run_uncertain_micros(&self, namespace: &str, run_id: &str) -> Result<i64, String>;
    fn list_dataset_run_cases(
        &self,
        namespace: &str,
        run_id: &str,
    ) -> Result<Vec<EvalCaseResult>, String>;
    /// Takes (`renew` false: free or lapsed) or renews (`renew` true: still
    /// held by `holder`) the run's lease until `until_ms`, so one start runs
    /// a run's cases at a time. False when another start holds it.
    fn lease_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String>;
    /// Frees the lease if `holder` has it.
    fn release_dataset_run(
        &self,
        namespace: &str,
        run_id: &str,
        holder: &str,
    ) -> Result<(), String>;
}

/// How long a start holds its run without renewing; it renews before every
/// case, and a crashed start's lease lapses for the next.
pub const RUN_LEASE_MS: i64 = 120_000;
pub const RUN_IN_PROGRESS: &str = "another start of this eval run is in progress";

/// Why a case produced no result. Either way it stays unrun for a later
/// start; what differs is whether its reservation can be given back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseError {
    /// Nothing was dispatched to anything that charges.
    NothingSpent(String),
    /// A model may have charged (a timed-out or failed provider call): the
    /// reservation stays counted against the budget.
    SpendUnknown(String),
}

/// Runs one case against the run's agent, model and tool version.
pub trait EvalCaseExecutor: Sync {
    /// The longest one case may take; the run's lease covers twice that.
    fn max_case_ms(&self) -> i64 {
        RUN_LEASE_MS / 2
    }

    fn run_case(
        &self,
        spec: &EvalRunSpec,
        dataset: &EvalDataset,
        case: &EvalCase,
    ) -> Result<CaseOutcome, CaseError>;

    /// What the case principal may call and may not read, against which the
    /// case's receipts are scored. The default grants nothing and hides
    /// nothing, so any tool call is ungranted.
    fn case_policy(
        &self,
        _spec: &EvalRunSpec,
        _dataset: &EvalDataset,
        _case: &EvalCase,
    ) -> CasePolicy {
        CasePolicy::default()
    }
}

struct Budget {
    spent: i64,
    reserved: i64,
    exhausted: bool,
}

/// Runs, or resumes, `spec` over `dataset`. Errors only for a spec that
/// does not match the dataset or the recorded run, or a store failure; a
/// case that fails to run is left unrun, and the run is `incomplete`.
pub fn run(
    store: &impl EvalRunStore,
    executor: &impl EvalCaseExecutor,
    spec: &EvalRunSpec,
    dataset: &EvalDataset,
    now_ms: impl Fn() -> i64 + Sync,
) -> Result<EvalRunReport, String> {
    spec.validate()?;
    if dataset.name != spec.dataset || dataset.version != spec.dataset_version {
        return Err(format!(
            "eval run {} names {}@{}, not {}",
            spec.run_id,
            spec.dataset,
            spec.dataset_version,
            dataset.address()
        ));
    }
    if &store.put_dataset_run(spec, now_ms())? != spec {
        return Err(RUN_CONFLICT.into());
    }
    let holder = uuid::Uuid::new_v4().to_string();
    let lease_ms = RUN_LEASE_MS.max(executor.max_case_ms().saturating_mul(2));
    let now = now_ms();
    if !store.lease_dataset_run(
        &spec.namespace,
        &spec.run_id,
        &holder,
        false,
        now,
        now + lease_ms,
    )? {
        return Err(RUN_IN_PROGRESS.into());
    }
    let report = run_leased(store, executor, spec, dataset, &holder, lease_ms, &now_ms);
    // The lease lapses on its own if this fails; the next start waits that long.
    let _ = store.release_dataset_run(&spec.namespace, &spec.run_id, &holder);
    report
}

fn run_leased(
    store: &impl EvalRunStore,
    executor: &impl EvalCaseExecutor,
    spec: &EvalRunSpec,
    dataset: &EvalDataset,
    holder: &str,
    lease_ms: i64,
    now_ms: &(impl Fn() -> i64 + Sync),
) -> Result<EvalRunReport, String> {
    let recorded = store.list_dataset_run_cases(&spec.namespace, &spec.run_id)?;
    let done: BTreeSet<&str> = recorded
        .iter()
        .map(|result| result.case_id.as_str())
        .collect();
    let queue: Mutex<VecDeque<&EvalCase>> = Mutex::new(
        dataset
            .cases
            .iter()
            .filter(|case| !done.contains(case.case_id.as_str()))
            .collect(),
    );
    // Spend reserved by a start that crashed before recording counts too.
    let uncertain = store.dataset_run_uncertain_micros(&spec.namespace, &spec.run_id)?;
    let budget = Mutex::new(Budget {
        spent: recorded
            .iter()
            .map(|result| result.outcome.cost_micros)
            .sum::<i64>()
            + uncertain,
        reserved: 0,
        exhausted: false,
    });
    // Signalled whenever a reservation is released, so a worker waiting for
    // in-flight cases to settle rechecks the budget.
    let settled = std::sync::Condvar::new();
    let failed = Mutex::new(Vec::new());
    let store_error = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..spec.concurrency {
            scope.spawn(|| {
                loop {
                    // Reserve before taking a case, so no more than the budget
                    // is ever committed to cases in flight.
                    {
                        let mut budget = budget.lock().unwrap_or_else(|error| error.into_inner());
                        loop {
                            if budget.exhausted
                                || store_error
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .is_some()
                            {
                                return;
                            }
                            if budget.spent + budget.reserved + spec.max_case_cost_micros
                                <= spec.budget_micros
                            {
                                break;
                            }
                            // Out of budget only once nothing in flight can
                            // still give some back.
                            if budget.reserved == 0 {
                                budget.exhausted = true;
                                settled.notify_all();
                                return;
                            }
                            budget = settled
                                .wait(budget)
                                .unwrap_or_else(|error| error.into_inner());
                        }
                        budget.reserved += spec.max_case_cost_micros;
                    }
                    let case = queue
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .pop_front();
                    let release = |spent: i64| {
                        let mut budget = budget.lock().unwrap_or_else(|error| error.into_inner());
                        budget.reserved -= spec.max_case_cost_micros;
                        budget.spent += spent;
                        settled.notify_all();
                    };
                    let Some(case) = case else {
                        release(0);
                        return;
                    };
                    // Renews the lease and reserves the case's cap durably
                    // before dispatch; a start that lost its lease (it
                    // lapsed) runs nothing more.
                    let now = now_ms();
                    let cap = spec.max_case_cost_micros;
                    match store.reserve_dataset_run_case(
                        &spec.namespace,
                        &spec.run_id,
                        holder,
                        cap,
                        now,
                        now + lease_ms,
                    ) {
                        Ok(true) => {}
                        Ok(false) => {
                            release(0);
                            *store_error
                                .lock()
                                .unwrap_or_else(|error| error.into_inner()) =
                                Some(RUN_IN_PROGRESS.to_string());
                            return;
                        }
                        Err(error) => {
                            release(0);
                            *store_error
                                .lock()
                                .unwrap_or_else(|error| error.into_inner()) = Some(error);
                            return;
                        }
                    }
                    match executor.run_case(spec, dataset, case) {
                        Ok(mut outcome) => {
                            let policy = executor.case_policy(spec, dataset, case);
                            outcome.policy = Some(score_case(
                                &case.case_id,
                                &policy,
                                outcome.receipts.take().as_ref(),
                            ));
                            let result = EvalCaseResult {
                                case_id: case.case_id.clone(),
                                outcome,
                                recorded_at_ms: now_ms(),
                            };
                            match store.record_dataset_run_case(
                                &spec.namespace,
                                &spec.run_id,
                                holder,
                                &result,
                                cap,
                                now_ms(),
                            ) {
                                // The stored result is the ledger line, even
                                // if another start recorded it first.
                                Ok(Some(stored)) => release(stored.outcome.cost_micros),
                                Ok(None) => {
                                    // Lost the lease: the reservation stays
                                    // counted, and the next start decides.
                                    release(cap);
                                    *store_error
                                        .lock()
                                        .unwrap_or_else(|error| error.into_inner()) =
                                        Some(RUN_IN_PROGRESS.to_string());
                                    return;
                                }
                                Err(error) => {
                                    release(cap);
                                    *store_error
                                        .lock()
                                        .unwrap_or_else(|error| error.into_inner()) = Some(error);
                                    return;
                                }
                            }
                        }
                        Err(CaseError::NothingSpent(_)) => {
                            // Spent nothing: the reservation goes back, and
                            // only once that is durable is it free here too.
                            match store.unreserve_dataset_run_case(
                                &spec.namespace,
                                &spec.run_id,
                                holder,
                                cap,
                                now_ms(),
                            ) {
                                Ok(()) => release(0),
                                Err(error) => {
                                    release(cap);
                                    *store_error
                                        .lock()
                                        .unwrap_or_else(|error| error.into_inner()) = Some(error);
                                    return;
                                }
                            }
                            failed
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .push(case.case_id.clone());
                        }
                        Err(CaseError::SpendUnknown(_)) => {
                            // The durable reservation stays; here it counts as
                            // spent.
                            release(cap);
                            failed
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .push(case.case_id.clone());
                        }
                    }
                }
            });
        }
    });
    if let Some(error) = store_error
        .into_inner()
        .unwrap_or_else(|error| error.into_inner())
    {
        return Err(error);
    }
    let results = store.list_dataset_run_cases(&spec.namespace, &spec.run_id)?;
    let recorded: BTreeSet<&str> = results
        .iter()
        .map(|result| result.case_id.as_str())
        .collect();
    let unrun_cases: Vec<String> = dataset
        .cases
        .iter()
        .filter(|case| !recorded.contains(case.case_id.as_str()))
        .map(|case| case.case_id.clone())
        .collect();
    let exhausted = budget
        .into_inner()
        .unwrap_or_else(|error| error.into_inner())
        .exhausted;
    let failed = failed
        .into_inner()
        .unwrap_or_else(|error| error.into_inner());
    let status = if unrun_cases.is_empty() {
        STATUS_COMPLETED
    } else if failed.is_empty() && exhausted {
        STATUS_BUDGET_EXHAUSTED
    } else {
        STATUS_INCOMPLETE
    };
    let policy = score_run(
        results
            .iter()
            .map(|result| (result.case_id.as_str(), result.outcome.policy.as_ref())),
    );
    Ok(EvalRunReport {
        policy,
        uncertain_micros: store.dataset_run_uncertain_micros(&spec.namespace, &spec.run_id)?,
        status: status.into(),
        cases_total: dataset.cases.len(),
        spent_micros: results
            .iter()
            .map(|result| result.outcome.cost_micros)
            .sum(),
        results,
        unrun_cases,
    })
}

/// Whether any trial of a stochastic step may have reached a provider. A
/// trial refused before dispatch (no evaluator capacity, no time left,
/// cancelled, or skipped after a terminal failure) accounts no tokens and
/// names why; anything else may have been charged.
fn may_have_dispatched(
    evidence: &crate::chisei::evaluation_execution::StochasticStepEvidence,
) -> bool {
    use crate::chisei::evaluation_execution::{
        REASON_EVALUATOR_CAPACITY, REASON_EXECUTION_CANCELLED,
        REASON_STOCHASTIC_POPULATION_INCOMPLETE, REASON_TOTAL_BUDGET,
    };
    evidence.trials.iter().any(|trial| {
        trial.input_tokens + trial.output_tokens + trial.retry_accounted_tokens > 0
            || ![
                REASON_EVALUATOR_CAPACITY,
                REASON_TOTAL_BUDGET,
                REASON_EXECUTION_CANCELLED,
                REASON_STOCHASTIC_POPULATION_INCOMPLETE,
            ]
            .contains(&trial.reason_code.as_str())
    })
}

/// Runs each case through the existing evaluation executor (#1090): one
/// node of a registered evaluator definition per case, the case as its
/// evidence, so a case's verdict is the executor's step receipt. A
/// stochastic definition must run on the run's model; its trial tokens are
/// priced with `pricing` into the case's cost.
pub struct DefinitionCaseExecutor<'a> {
    pub definition: &'a crate::chisei::evaluation_plan::EvaluatorDefinition,
    pub deterministic: &'a crate::chisei::evaluation_execution::DeterministicEvaluatorRegistry,
    pub stochastic: &'a crate::chisei::evaluation_execution::StochasticEvaluatorRegistry,
    pub pricing: Option<chisei_provider::pricing::ModelPricing>,
    /// The project budget hierarchy; a stochastic case reserves its most
    /// tokens there before any provider is contacted, as executions do.
    pub budget: &'a crate::chisei::budget::BudgetTracker,
}

impl DefinitionCaseExecutor<'_> {
    /// Refuses a definition the run cannot use: one that does not accept eval
    /// cases, or a stochastic one on another model than the run's.
    pub fn check(&self, spec: &EvalRunSpec) -> Result<(), String> {
        use crate::chisei::evaluation_plan::{
            DETERMINISTIC_EXECUTION_CLASS, STOCHASTIC_EXECUTION_CLASS,
        };
        let definition = self.definition;
        if definition.namespace != spec.namespace {
            return Err("evaluator definition is not in the run's namespace".into());
        }
        if definition.definition_id != spec.evaluator_definition_id
            || definition.content_digest != spec.evaluator_digest
        {
            return Err("the run is bound to another evaluator definition".into());
        }
        if !definition
            .supported_input_schemas
            .iter()
            .any(|schema| schema == crate::chisei::eval_dataset::EVAL_CASE_SCHEMA)
        {
            return Err(format!(
                "evaluator definition {} does not accept {}",
                definition.definition_id,
                crate::chisei::eval_dataset::EVAL_CASE_SCHEMA
            ));
        }
        match definition.execution_class.as_str() {
            DETERMINISTIC_EXECUTION_CLASS => Ok(()),
            STOCHASTIC_EXECUTION_CLASS => {
                let policy = definition
                    .stochastic_policy
                    .as_ref()
                    .ok_or("stochastic evaluator definition has no policy")?;
                if format!("{}/{}", policy.provider, policy.model) != spec.model
                    && policy.model != spec.model
                {
                    return Err(format!(
                        "evaluator definition runs {}, not the run's model {}",
                        policy.model, spec.model
                    ));
                }
                // Priced before anything runs, and bounded: a case's most
                // tokens, all priced as output, must fit its reservation.
                let pricing = self
                    .pricing
                    .as_ref()
                    .ok_or("no pricing for the run's model")?;
                let tokens = i64::from(policy.max_total_tokens);
                let worst =
                    crate::cost_estimate::cost_usd_micros(&spec.model, pricing, 0, tokens, 0, 0)
                        .ok_or("case cost bound is too large")?
                        .max(
                            crate::cost_estimate::cost_usd_micros(
                                &spec.model,
                                pricing,
                                tokens,
                                0,
                                0,
                                0,
                            )
                            .ok_or("case cost bound is too large")?,
                        );
                if worst > spec.max_case_cost_micros {
                    return Err(format!(
                        "a case may cost up to {worst} micros, above max_case_cost_micros {}",
                        spec.max_case_cost_micros
                    ));
                }
                Ok(())
            }
            other => Err(format!("execution class {other} cannot run eval cases")),
        }
    }
}

impl EvalCaseExecutor for DefinitionCaseExecutor<'_> {
    fn max_case_ms(&self) -> i64 {
        i64::try_from(self.definition.resource_limits.timeout_ms).unwrap_or(i64::MAX)
    }

    fn run_case(
        &self,
        spec: &EvalRunSpec,
        dataset: &EvalDataset,
        case: &EvalCase,
    ) -> Result<CaseOutcome, CaseError> {
        use crate::chisei::evaluation_execution::{
            STATUS_FAIL, STATUS_PASS, build_evaluator_input, execute_registered_node,
            execute_stochastic_node,
        };
        use crate::chisei::evaluation_manifest::{
            MANIFEST_CONTRACT, RESOLVER_VERSION, ResolvedEvaluationManifest,
            ResolvedEvaluationNode, ResolvedEvaluatorBinding, ResolvedInvariantBinding,
            digest_json,
        };
        use crate::chisei::evaluation_plan::NODE_REQUIRED;
        let definition = self.definition;
        let nothing = CaseError::NothingSpent;
        let stochastic = definition.stochastic_policy.is_some();
        // Before dispatch nothing is spent; once a stochastic node runs, a
        // failure may follow a charge.
        let after = |error: String| {
            if stochastic {
                CaseError::SpendUnknown(error)
            } else {
                CaseError::NothingSpent(error)
            }
        };
        let evidence = dataset.evidence(case).map_err(nothing)?;
        // The subject is the case as run against the agent, model and tool
        // version, so receipts of two releases differ where they should.
        let subject_identity = format!(
            "{}#{}@{}/{}/{}",
            dataset.address(),
            case.case_id,
            spec.agent,
            spec.model,
            spec.tool_version
        );
        let node = ResolvedEvaluationNode {
            node_id: "eval-case".into(),
            evaluator: ResolvedEvaluatorBinding {
                definition_id: definition.definition_id.clone(),
                definition_digest: definition.content_digest.clone(),
                implementation_digest: definition.implementation_digest.clone(),
                stochastic_policy: definition.stochastic_policy.clone(),
            },
            depends_on_node_ids: Vec::new(),
            input_bindings: Vec::new(),
            parameters_json: "{}".into(),
            invariants: vec![ResolvedInvariantBinding {
                invariant_version_id: format!("invariant:eval-run:{}", spec.run_id),
                content_digest: dataset.digest.clone(),
                predicate_kind: definition
                    .supported_predicate_kinds
                    .first()
                    .cloned()
                    .unwrap_or_default(),
                input_schema: crate::chisei::eval_dataset::EVAL_CASE_SCHEMA.into(),
                result_schema: definition
                    .supported_result_schemas
                    .first()
                    .cloned()
                    .unwrap_or_default(),
                evidence_types: Vec::new(),
                provenance_evidence_object_ids: Vec::new(),
                waiver_version_ids: Vec::new(),
            }],
            evidence_object_ids: vec![evidence.evidence_object_id.clone()],
            classification: NODE_REQUIRED.into(),
        };
        let mut manifest = ResolvedEvaluationManifest {
            contract_version: MANIFEST_CONTRACT.into(),
            resolver_version: RESOLVER_VERSION.into(),
            manifest_id: format!("manifest:eval-run:{}:{}", spec.run_id, case.case_id),
            manifest_digest: String::new(),
            namespace: spec.namespace.clone(),
            plan_version_id: format!("eval-run:{}", spec.run_id),
            plan_digest: dataset.digest.clone(),
            subject_profile: crate::chisei::eval_dataset::EVAL_CASE_SCHEMA.into(),
            subject_identity,
            subject_content_digest: evidence.content_digest.clone(),
            invariant_set_id: format!("eval-run:{}", spec.run_id),
            invariant_set_digest: dataset.digest.clone(),
            invariant_profile_digest: definition.content_digest.clone(),
            evaluation_time_ms: 0,
            resolved_by: "eval-run".into(),
            requirements: Vec::new(),
            nodes: vec![node],
            evidence: Vec::new(),
            waivers: Vec::new(),
            created_at_ms: 0,
        };
        manifest.manifest_digest = digest_json(&manifest).map_err(nothing)?;
        let node = &manifest.nodes[0];
        let input = build_evaluator_input(
            &manifest,
            node,
            vec![evidence],
            &std::collections::BTreeMap::new(),
        )
        .map_err(nothing)?;
        let limits = &definition.resource_limits;
        let budget = std::time::Duration::from_millis(limits.timeout_ms.max(1));
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // The project token reservation for a stochastic case: settled to the
        // tokens a verdict reports, refunded when nothing was dispatched, and
        // kept when spend is unknown.
        let mut project_reservation = None;
        if let Some(policy) = &definition.stochastic_policy {
            let amount = i32::try_from(policy.max_total_tokens)
                .map_err(|_| nothing("case token budget is too large".into()))?;
            let scope = format!("project:{}/eval-run:{}", spec.namespace, spec.run_id);
            self.budget
                .check_and_reserve_idempotent(
                    &scope,
                    amount,
                    // One reservation per dispatch attempt: a resumed case
                    // that may have charged before reserves again.
                    &format!(
                        "eval-run-reserve:{}:{}:{}:{}",
                        spec.namespace,
                        spec.run_id,
                        case.case_id,
                        uuid::Uuid::new_v4()
                    ),
                )
                .map_err(|error| nothing(format!("project token budget: {error}")))?;
            project_reservation = Some((scope, amount));
        }
        let settle_project = |actual: i32| {
            if let Some((scope, amount)) = &project_reservation {
                // Best effort, as executions settle: the reservation already
                // held the tokens, so a failed settle only over-counts.
                let _ = self.budget.try_adjust_with_metric(
                    scope,
                    *amount,
                    actual,
                    crate::db::chisei_budget::METRIC_TOKENS,
                );
            }
        };
        let execution = if definition.stochastic_policy.is_some() {
            execute_stochastic_node(
                self.stochastic,
                &manifest,
                node,
                input,
                limits,
                budget,
                cancelled,
            )
            .map_err(after)?
        } else {
            execute_registered_node(
                self.deterministic,
                &manifest,
                node,
                input,
                limits,
                budget,
                cancelled,
            )
            .map_err(after)?
        };
        let receipt = execution.receipt;
        let (input_tokens, output_tokens, retry_tokens) = receipt
            .stochastic_evidence
            .as_ref()
            .map_or((0, 0, 0), |evidence| {
                (
                    u64::from(evidence.total_input_tokens),
                    u64::from(evidence.total_output_tokens),
                    u64::from(evidence.total_retry_accounted_tokens),
                )
            });
        let cost_micros = match (&self.pricing, input_tokens + output_tokens + retry_tokens) {
            (_, 0) => 0,
            (Some(pricing), _) => {
                let price = |input: u64, output: u64| {
                    crate::cost_estimate::cost_usd_micros(
                        &spec.model,
                        pricing,
                        input as i64,
                        output as i64,
                        0,
                        0,
                    )
                    .ok_or_else(|| after("case cost estimate is too large".into()))
                };
                // Tokens of failed, retried trials are priced at the higher
                // rate, since which side they spent is not known.
                price(input_tokens, output_tokens)?
                    + price(retry_tokens, 0)?.max(price(0, retry_tokens)?)
            }
            // Tokens without a price would spend the budget unseen.
            (None, _) => return Err(after("no pricing for the run's model".into())),
        };
        // Only a verdict is a result; anything else leaves the case to a
        // later start.
        // A stochastic non-verdict may hide a charged trial whatever tokens
        // it reports, so it keeps its whole reservation; one refused before
        // any trial (no stochastic evidence) dispatched nothing.
        let verdict = receipt.status == STATUS_PASS || receipt.status == STATUS_FAIL;
        if !verdict {
            let error = format!("evaluator {}: {}", receipt.status, receipt.reason_code);
            return Err(
                if receipt
                    .stochastic_evidence
                    .as_ref()
                    .is_none_or(|evidence| !may_have_dispatched(evidence))
                {
                    settle_project(0);
                    CaseError::NothingSpent(error)
                } else {
                    after(error)
                },
            );
        }
        settle_project(
            i32::try_from(input_tokens + output_tokens + retry_tokens).unwrap_or(i32::MAX),
        );
        Ok(CaseOutcome {
            passed: receipt.status == STATUS_PASS,
            reason: receipt.reason_code,
            input_tokens,
            output_tokens,
            cost_micros,
            // An evaluator definition judges the case's evidence: it calls
            // no tool, writes no output to anyone, and applies no Action.
            receipts: Some(CaseReceipts::default()),
            policy: None,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::chisei::eval_dataset::EvalCase;
    use crate::sekai::synthetic::SizePreset;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An in-memory store with the durable semantics: first write wins.
    #[derive(Default)]
    pub(crate) struct MemoryStore {
        runs: Mutex<HashMap<(String, String), EvalRunSpec>>,
        cases: Mutex<BTreeMap<(String, String, String), EvalCaseResult>>,
        leases: Mutex<HashMap<(String, String), (String, i64)>>,
        uncertain: Mutex<HashMap<(String, String), i64>>,
    }

    impl MemoryStore {
        fn holds(&self, namespace: &str, run_id: &str, holder: &str, now_ms: i64) -> bool {
            self.leases
                .lock()
                .unwrap()
                .get(&(namespace.to_string(), run_id.to_string()))
                .is_some_and(|(current, until)| current == holder && *until >= now_ms)
        }

        fn adjust(&self, namespace: &str, run_id: &str, by: i64) {
            let mut uncertain = self.uncertain.lock().unwrap();
            let value = uncertain
                .entry((namespace.to_string(), run_id.to_string()))
                .or_insert(0);
            *value = (*value + by).max(0);
        }
    }

    impl EvalRunStore for MemoryStore {
        fn put_dataset_run(&self, spec: &EvalRunSpec, _now_ms: i64) -> Result<EvalRunSpec, String> {
            Ok(self
                .runs
                .lock()
                .unwrap()
                .entry((spec.namespace.clone(), spec.run_id.clone()))
                .or_insert_with(|| spec.clone())
                .clone())
        }
        fn reserve_dataset_run_case(
            &self,
            namespace: &str,
            run_id: &str,
            holder: &str,
            reserve_micros: i64,
            now_ms: i64,
            until_ms: i64,
        ) -> Result<bool, String> {
            if !self.holds(namespace, run_id, holder, now_ms) {
                return Ok(false);
            }
            self.leases.lock().unwrap().insert(
                (namespace.to_string(), run_id.to_string()),
                (holder.to_string(), until_ms),
            );
            self.adjust(namespace, run_id, reserve_micros);
            Ok(true)
        }
        fn record_dataset_run_case(
            &self,
            namespace: &str,
            run_id: &str,
            holder: &str,
            result: &EvalCaseResult,
            reserve_micros: i64,
            now_ms: i64,
        ) -> Result<Option<EvalCaseResult>, String> {
            if !self.holds(namespace, run_id, holder, now_ms) {
                return Ok(None);
            }
            self.adjust(namespace, run_id, -reserve_micros);
            Ok(Some(
                self.cases
                    .lock()
                    .unwrap()
                    .entry((namespace.into(), run_id.into(), result.case_id.clone()))
                    .or_insert_with(|| result.clone())
                    .clone(),
            ))
        }
        fn unreserve_dataset_run_case(
            &self,
            namespace: &str,
            run_id: &str,
            holder: &str,
            reserve_micros: i64,
            now_ms: i64,
        ) -> Result<(), String> {
            if self.holds(namespace, run_id, holder, now_ms) {
                self.adjust(namespace, run_id, -reserve_micros);
            }
            Ok(())
        }
        fn dataset_run_uncertain_micros(
            &self,
            namespace: &str,
            run_id: &str,
        ) -> Result<i64, String> {
            Ok(*self
                .uncertain
                .lock()
                .unwrap()
                .get(&(namespace.to_string(), run_id.to_string()))
                .unwrap_or(&0))
        }
        fn list_dataset_run_cases(
            &self,
            namespace: &str,
            run_id: &str,
        ) -> Result<Vec<EvalCaseResult>, String> {
            Ok(self
                .cases
                .lock()
                .unwrap()
                .iter()
                .filter(|((ns, run, _), _)| ns == namespace && run == run_id)
                .map(|(_, result)| result.clone())
                .collect())
        }
        fn lease_dataset_run(
            &self,
            namespace: &str,
            run_id: &str,
            holder: &str,
            renew: bool,
            now_ms: i64,
            until_ms: i64,
        ) -> Result<bool, String> {
            let mut leases = self.leases.lock().unwrap();
            let key = (namespace.to_string(), run_id.to_string());
            let held = match leases.get(&key) {
                Some((current, until)) if renew => current == holder && *until >= now_ms,
                Some((current, until)) => current.is_empty() || *until < now_ms,
                None => !renew,
            };
            if held {
                leases.insert(key, (holder.to_string(), until_ms));
            }
            Ok(held)
        }
        fn release_dataset_run(
            &self,
            namespace: &str,
            run_id: &str,
            holder: &str,
        ) -> Result<(), String> {
            let mut leases = self.leases.lock().unwrap();
            let key = (namespace.to_string(), run_id.to_string());
            if leases
                .get(&key)
                .is_some_and(|(current, _)| current == holder)
            {
                leases.remove(&key);
            }
            Ok(())
        }
    }

    /// Costs `cost` per case, tracks the most cases in flight at once, and
    /// fails every case once `fail_after` cases have run (a stopped run).
    struct Fake {
        cost: i64,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
        ran: AtomicUsize,
        fail_after: usize,
    }

    impl Fake {
        fn new(cost: i64, fail_after: usize) -> Self {
            Self {
                cost,
                in_flight: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                ran: AtomicUsize::new(0),
                fail_after,
            }
        }
    }

    impl EvalCaseExecutor for Fake {
        fn run_case(
            &self,
            _spec: &EvalRunSpec,
            _dataset: &EvalDataset,
            case: &EvalCase,
        ) -> Result<CaseOutcome, CaseError> {
            if self.ran.fetch_add(1, Ordering::SeqCst) >= self.fail_after {
                return Err(CaseError::NothingSpent("stopped".into()));
            }
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(2));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(CaseOutcome {
                passed: !case.case_id.ends_with('7'),
                reason: "fixture".into(),
                input_tokens: 10,
                output_tokens: 5,
                cost_micros: self.cost,
                receipts: Some(CaseReceipts::default()),
                policy: None,
            })
        }
    }

    pub(crate) fn dataset(cases: usize) -> EvalDataset {
        EvalDataset {
            contract_version: crate::chisei::eval_dataset::EVAL_DATASET_CONTRACT.into(),
            name: "triage".into(),
            version: "v0123456789abcdef".into(),
            generator_version: crate::chisei::eval_dataset::GENERATOR_VERSION.into(),
            namespace: "eval-fixture".into(),
            seed: 1,
            preset: SizePreset::Demo,
            plan_digest: "sha256:plan".into(),
            definition_digest: "sha256:definition".into(),
            cases: (0..cases)
                .map(|index| EvalCase {
                    case_id: format!("case-{index:04}"),
                    input: BTreeMap::new(),
                    expected: "open".into(),
                    tags: Vec::new(),
                })
                .collect(),
            digest: "sha256:dataset".into(),
        }
    }

    pub(crate) fn spec(concurrency: u32, budget_micros: i64) -> EvalRunSpec {
        EvalRunSpec {
            contract_version: EVAL_RUN_CONTRACT.into(),
            namespace: "acme".into(),
            run_id: "release-1.4.0".into(),
            dataset: "triage".into(),
            dataset_version: "v0123456789abcdef".into(),
            agent: "triage-agent@1.4.0".into(),
            model: "openai/fixture".into(),
            tool_version: "tools@7".into(),
            evaluator_definition_id: "definition:triage".into(),
            evaluator_digest: "sha256:definition".into(),
            concurrency,
            budget_micros,
            max_case_cost_micros: 100,
        }
    }

    /// Fails every case `Fake` passes whose id ends in `3`, as a release
    /// that broke a tenth of the cases would.
    struct Regressed(Fake);

    impl EvalCaseExecutor for Regressed {
        fn run_case(
            &self,
            spec: &EvalRunSpec,
            dataset: &EvalDataset,
            case: &EvalCase,
        ) -> Result<CaseOutcome, CaseError> {
            let mut outcome = self.0.run_case(spec, dataset, case)?;
            outcome.passed &= !case.case_id.ends_with('3');
            Ok(outcome)
        }
    }

    /// The eval-at-scale acceptance (#1584): 1,000 cases run in parallel
    /// within a set budget, policy violations are counted per run, and a
    /// comparison flags a seeded regression while an unchanged release
    /// passes.
    #[test]
    fn a_thousand_cases_run_within_budget_and_a_seeded_regression_is_flagged() {
        use crate::chisei::eval_compare::{
            ComparedRun, ComparisonGate, VERDICT_FAIL, VERDICT_PASS, compare_runs,
        };
        let store = MemoryStore::default();
        let dataset = dataset(1_000);
        let run_spec = |run_id: &str| EvalRunSpec {
            run_id: run_id.into(),
            ..spec(16, 20_000)
        };
        let (baseline, unchanged, regressed) = (
            run_spec("release-1"),
            run_spec("release-2"),
            run_spec("release-3"),
        );
        let parallel = Fake::new(10, usize::MAX);
        let first = run(&store, &parallel, &baseline, &dataset, || 1).unwrap();
        assert_eq!(first.status, STATUS_COMPLETED);
        assert_eq!(first.results.len(), 1_000);
        assert!(first.spent_micros <= baseline.budget_micros);
        assert!(
            parallel.peak.load(Ordering::SeqCst) > 1,
            "cases ran in parallel"
        );
        assert!(first.policy.counts.values().all(|count| *count == 0));
        let same = run(
            &store,
            &Fake::new(10, usize::MAX),
            &unchanged,
            &dataset,
            || 2,
        )
        .unwrap();
        let worse = run(
            &store,
            &Regressed(Fake::new(10, usize::MAX)),
            &regressed,
            &dataset,
            || 3,
        )
        .unwrap();
        let compare = |candidate: &EvalRunSpec, results: &[EvalCaseResult]| {
            compare_runs(
                &dataset,
                ComparedRun {
                    spec: &baseline,
                    results: &first.results,
                },
                ComparedRun {
                    spec: candidate,
                    results,
                },
                ComparisonGate::default(),
            )
            .unwrap()
        };
        assert_eq!(compare(&unchanged, &same.results).verdict, VERDICT_PASS);
        let flagged = compare(&regressed, &worse.results);
        assert_eq!(flagged.verdict, VERDICT_FAIL);
        assert!(flagged.significant_regression);
        assert_eq!(flagged.regressions, 100);
    }

    #[test]
    fn never_more_than_the_concurrency_limit_is_in_flight() {
        let store = MemoryStore::default();
        let fake = Fake::new(10, usize::MAX);
        let report = run(&store, &fake, &spec(3, 1_000_000), &dataset(60), || 1).unwrap();
        assert_eq!(report.status, STATUS_COMPLETED);
        assert_eq!(report.results.len(), 60);
        assert!(fake.peak.load(Ordering::SeqCst) <= 3);
        assert!(
            fake.peak.load(Ordering::SeqCst) > 1,
            "cases ran in parallel"
        );
    }

    #[test]
    fn a_stopped_run_resumes_with_one_result_per_case_and_an_exact_ledger() {
        let store = MemoryStore::default();
        let stopping = Fake::new(37, 20);
        let first = run(&store, &stopping, &spec(4, 1_000_000), &dataset(50), || 1).unwrap();
        assert_eq!(first.status, STATUS_INCOMPLETE);
        assert_eq!(first.results.len(), 20);
        assert_eq!(first.unrun_cases.len(), 30);
        let resumed = Fake::new(37, usize::MAX);
        let second = run(&store, &resumed, &spec(4, 1_000_000), &dataset(50), || 2).unwrap();
        assert_eq!(second.status, STATUS_COMPLETED);
        // Only the 30 missing cases ran again.
        assert_eq!(resumed.ran.load(Ordering::SeqCst), 30);
        let ids: BTreeSet<_> = second.results.iter().map(|r| r.case_id.clone()).collect();
        assert_eq!(ids.len(), 50);
        assert_eq!(second.results.len(), 50);
        assert_eq!(second.spent_micros, 50 * 37);
        assert_eq!(
            second.spent_micros,
            second
                .results
                .iter()
                .map(|r| r.outcome.cost_micros)
                .sum::<i64>()
        );
    }

    #[test]
    fn a_run_stops_at_its_budget_and_lists_the_unrun_cases() {
        let store = MemoryStore::default();
        let fake = Fake::new(100, usize::MAX);
        // Room for exactly 7 cases at their 100-unit cap.
        let report = run(&store, &fake, &spec(2, 750), &dataset(20), || 1).unwrap();
        assert_eq!(report.status, STATUS_BUDGET_EXHAUSTED);
        assert_eq!(report.results.len(), 7);
        assert_eq!(report.unrun_cases.len(), 13);
        assert!(report.spent_micros <= 750);
        // A restart with the same budget starts nothing more.
        let again = Fake::new(100, usize::MAX);
        let report = run(&store, &again, &spec(2, 750), &dataset(20), || 2).unwrap();
        assert_eq!(again.ran.load(Ordering::SeqCst), 0);
        assert_eq!(report.status, STATUS_BUDGET_EXHAUSTED);
    }

    #[test]
    fn budget_held_by_cases_in_flight_is_waited_for_not_given_up() {
        // The budget fits one cap; each case costs nothing, so every case
        // runs, one at a time, rather than the run stopping early.
        let store = MemoryStore::default();
        let fake = Fake::new(0, usize::MAX);
        let report = run(&store, &fake, &spec(4, 100), &dataset(12), || 1).unwrap();
        assert_eq!(report.status, STATUS_COMPLETED);
        assert_eq!(report.results.len(), 12);
        assert_eq!(fake.peak.load(Ordering::SeqCst), 1);
    }

    struct Unknown;

    impl EvalCaseExecutor for Unknown {
        fn run_case(
            &self,
            _spec: &EvalRunSpec,
            _dataset: &EvalDataset,
            _case: &EvalCase,
        ) -> Result<CaseOutcome, CaseError> {
            Err(CaseError::SpendUnknown("provider timed out".into()))
        }
    }

    /// Reports receipts with one seeded violation on each of the first four
    /// cases (the fourth reports none), the rest clean.
    struct Agentic;

    impl EvalCaseExecutor for Agentic {
        fn run_case(
            &self,
            _spec: &EvalRunSpec,
            _dataset: &EvalDataset,
            case: &EvalCase,
        ) -> Result<CaseOutcome, CaseError> {
            use crate::chisei::eval_policy::{ActionReceipt, OutputReceipt, ToolCallReceipt};
            let receipt = |kind: &str| format!("{}/{kind}", case.case_id);
            let mut receipts = CaseReceipts {
                tool_calls: vec![ToolCallReceipt {
                    receipt_id: receipt("lookup"),
                    tool: "lookup".into(),
                }],
                outputs: vec![OutputReceipt {
                    receipt_id: receipt("answer"),
                    text: "reorder approved".into(),
                }],
                actions: vec![ActionReceipt {
                    receipt_id: receipt("reorder"),
                    action_type: "reorder".into(),
                    applied: true,
                    approval_receipt_id: Some(receipt("approval")),
                }],
            };
            match case.case_id.as_str() {
                "case-0001" => receipts.tool_calls[0].tool = "drop_table".into(),
                "case-0002" => receipts.outputs[0].text = "the part is SKU-SECRET".into(),
                "case-0003" => receipts.actions[0].approval_receipt_id = None,
                _ => {}
            }
            Ok(CaseOutcome {
                // Policy is scored apart from the verdict.
                passed: true,
                reason: "fixture".into(),
                input_tokens: 1,
                output_tokens: 1,
                cost_micros: 1,
                receipts: (case.case_id != "case-0004").then_some(receipts),
                policy: None,
            })
        }

        fn case_policy(&self, _: &EvalRunSpec, _: &EvalDataset, _: &EvalCase) -> CasePolicy {
            CasePolicy {
                granted_tools: ["lookup".to_string()].into(),
                unreadable_values: ["SKU-SECRET".to_string()].into(),
            }
        }
    }

    #[test]
    fn a_run_counts_each_seeded_policy_violation_once_and_a_restart_keeps_them() {
        use crate::chisei::eval_policy::{POLICY_SCORER_VERSION, ViolationKind};
        let store = MemoryStore::default();
        let report = run(&store, &Agentic, &spec(4, 1_000_000), &dataset(10), || 1).unwrap();
        assert_eq!(report.status, STATUS_COMPLETED);
        assert_eq!(report.policy.scorer_version, POLICY_SCORER_VERSION);
        let expected = BTreeMap::from([
            (ViolationKind::UngrantedToolCall, 1),
            (ViolationKind::MarkingLeak, 1),
            (ViolationKind::ActionOutsideApproval, 1),
            (ViolationKind::MissingReceipts, 1),
        ]);
        assert_eq!(report.policy.counts, expected);
        let linked: Vec<_> = report
            .policy
            .violations
            .iter()
            .map(|violation| (violation.case_id.as_str(), violation.receipt_id.as_str()))
            .collect();
        assert_eq!(
            linked,
            [
                ("case-0001", "case-0001/lookup"),
                ("case-0002", "case-0002/answer"),
                ("case-0003", "case-0003/reorder"),
                ("case-0004", ""),
            ]
        );
        // The receipts are not kept, only what was scored from them; a
        // restart reads the same outcome back without running anything.
        assert!(
            report
                .results
                .iter()
                .all(|result| result.outcome.receipts.is_none())
        );
        let again = Fake::new(1, usize::MAX);
        let resumed = run(&store, &again, &spec(4, 1_000_000), &dataset(10), || 2).unwrap();
        assert_eq!(again.ran.load(Ordering::SeqCst), 0);
        assert_eq!(resumed.policy, report.policy);
    }

    #[test]
    fn a_clean_run_reports_zero_for_every_policy_kind() {
        let store = MemoryStore::default();
        let report = run(
            &store,
            &Fake::new(1, usize::MAX),
            &spec(2, 1_000_000),
            &dataset(8),
            || 1,
        )
        .unwrap();
        assert_eq!(report.policy.counts.len(), 4);
        assert!(report.policy.counts.values().all(|count| *count == 0));
        assert!(report.policy.violations.is_empty());
    }

    #[test]
    fn a_failure_that_may_have_charged_keeps_its_reservation() {
        let store = MemoryStore::default();
        // Each failing case keeps its 100-unit cap counted, so at most 5
        // attempts fit 550, and a restart attempts nothing more.
        let first = run(&store, &Unknown, &spec(1, 550), &dataset(20), || 1).unwrap();
        assert_eq!(first.status, STATUS_INCOMPLETE);
        assert!(first.results.is_empty());
        assert_eq!(first.uncertain_micros, 500);
        let again = Fake::new(1, usize::MAX);
        let second = run(&store, &again, &spec(1, 550), &dataset(20), || 2).unwrap();
        assert_eq!(again.ran.load(Ordering::SeqCst), 0);
        assert_eq!(second.status, STATUS_BUDGET_EXHAUSTED);
    }

    #[test]
    fn a_run_id_is_bound_to_its_first_spec_and_dataset() {
        let store = MemoryStore::default();
        let fake = Fake::new(1, usize::MAX);
        run(&store, &fake, &spec(1, 1_000), &dataset(2), || 1).unwrap();
        let mut other = spec(1, 1_000);
        other.model = "openai/other".into();
        assert_eq!(
            run(&store, &fake, &other, &dataset(2), || 1).unwrap_err(),
            RUN_CONFLICT
        );
        let mut wrong = spec(1, 1_000);
        wrong.run_id = "release-2".into();
        wrong.dataset_version = "v-other".into();
        assert!(run(&store, &fake, &wrong, &dataset(2), || 1).is_err());
        let mut bad = spec(0, 1_000);
        bad.run_id = "release-3".into();
        assert!(run(&store, &fake, &bad, &dataset(2), || 1).is_err());
    }
}
