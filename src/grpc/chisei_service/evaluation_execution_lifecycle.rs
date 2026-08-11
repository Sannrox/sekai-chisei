//! Private lifecycle for durable Evaluation execution.
//!
//! The gRPC adapter authenticates callers and translates protocol messages.
//! This module owns execution creation and replay, frozen-budget recovery,
//! evaluator availability, per-manifest serialization, cancellation, worker
//! dispatch, durable step and gate ordering, and terminal process-state cleanup.

use super::*;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Mutex as AsyncMutex;

pub(super) struct EvaluationExecutionLifecycle {
    db: Arc<RuntimeDb>,
    budget: Arc<BudgetTracker>,
    evaluator_registry: Arc<evaluation_execution_domain::DeterministicEvaluatorRegistry>,
    stochastic_evaluator_registry: Arc<evaluation_execution_domain::StochasticEvaluatorRegistry>,
    cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    execution_locks: Arc<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>>,
    safe_providers: HashSet<String>,
}

impl EvaluationExecutionLifecycle {
    pub(super) fn new(
        db: Arc<RuntimeDb>,
        budget: Arc<BudgetTracker>,
        evaluator_registry: Arc<evaluation_execution_domain::DeterministicEvaluatorRegistry>,
        stochastic_evaluator_registry: Arc<
            evaluation_execution_domain::StochasticEvaluatorRegistry,
        >,
        safe_providers: HashSet<String>,
    ) -> Self {
        Self {
            db,
            budget,
            evaluator_registry,
            stochastic_evaluator_registry,
            cancellations: Arc::new(Mutex::new(HashMap::new())),
            execution_locks: Arc::new(Mutex::new(HashMap::new())),
            safe_providers,
        }
    }

    pub(super) async fn execute(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        actor: &str,
        max_total_duration_ms: u64,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, Status> {
        for node in &manifest.nodes {
            if let Some(definition) = self
                .db
                .get_evaluator_definition(&node.evaluator.definition_id)
                .map_err(Status::internal)?
            {
                self.ensure_external_evaluator_registered(&definition);
            }
        }
        let index = self.ensure_execution(manifest, actor, max_total_duration_ms)?;
        let receipt = self
            .db
            .get_operation_receipt(&index.operation_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
        let frozen_total_duration_ms = evaluation_total_budget_ms(&receipt)?;
        if frozen_total_duration_ms > max_total_duration_ms {
            return Err(Status::failed_precondition(
                "existing evaluation execution budget exceeds the requested bound",
            ));
        }
        let cancelled = self.cancellation_for(&manifest.manifest_digest)?;
        let execution_lock = self.execution_lock_for(&manifest.manifest_digest)?;
        let _guard = execution_lock.lock().await;
        let projection = self
            .dispatch(
                manifest.clone(),
                index,
                frozen_total_duration_ms,
                cancelled,
                self.stochastic_egress_reasons(manifest),
            )
            .await?;
        self.cleanup_terminal(manifest, &execution_lock, &projection)?;
        Ok(projection)
    }

    pub(super) async fn cancel(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        index: &evaluation_execution_domain::EvaluationExecutionIndex,
        actor: &str,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, Status> {
        let cancelled = self.cancellation_for(&manifest.manifest_digest)?;
        cancelled.store(true, Ordering::Release);
        let receipt = self
            .db
            .get_operation_receipt(&index.operation_id)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
        let max_total_duration_ms = evaluation_total_budget_ms(&receipt)?;
        if receipt.completed_at_ms.is_none() && !evaluation_cancellation_requested(&receipt) {
            self.request_cancellation(index, &receipt, actor)?;
        }
        let execution_lock = self.execution_lock_for(&manifest.manifest_digest)?;
        let _guard = execution_lock.lock().await;
        let projection = self
            .dispatch(
                manifest.clone(),
                index.clone(),
                max_total_duration_ms,
                cancelled,
                BTreeMap::new(),
            )
            .await?;
        self.cleanup_terminal(manifest, &execution_lock, &projection)?;
        Ok(projection)
    }

    fn ensure_external_evaluator_registered(
        &self,
        definition: &evaluation_plan_domain::EvaluatorDefinition,
    ) {
        if definition.execution_class != evaluation_plan_domain::EXTERNAL_ADAPTER_EXECUTION_CLASS {
            return;
        }
        if let Err(error) = self.evaluator_registry.register_external_adapter(
            &definition.namespace,
            &definition.content_digest,
            &definition.implementation_digest,
            &definition.adapter_endpoint,
        ) {
            tracing::warn!(
                namespace = %definition.namespace,
                implementation_digest = %definition.implementation_digest,
                error = %error,
                "external evaluator adapter is not executable"
            );
        }
    }

    fn ensure_execution(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        actor: &str,
        max_total_duration_ms: u64,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionIndex, Status> {
        if let Some(index) = self
            .db
            .get_evaluation_execution_index(&manifest.manifest_digest)
            .map_err(Status::internal)?
        {
            if index.namespace != manifest.namespace
                || index.executor_version != evaluation_execution_domain::EXECUTOR_VERSION
                || index.operation_id != evaluation_operation_id(&manifest.manifest_digest)
            {
                return Err(Status::data_loss(
                    "evaluation execution index binding is invalid",
                ));
            }
            return Ok(index);
        }
        let topological_order =
            evaluation_execution_domain::deterministic_topological_order(manifest)
                .map_err(Status::data_loss)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let receipt = initial_evaluation_receipt(
            manifest,
            actor,
            now_ms,
            max_total_duration_ms,
            &topological_order,
        )?;
        let index = evaluation_execution_domain::EvaluationExecutionIndex {
            manifest_digest: manifest.manifest_digest.clone(),
            operation_id: receipt.operation_id.clone(),
            namespace: manifest.namespace.clone(),
            executor_version: evaluation_execution_domain::EXECUTOR_VERSION.into(),
            started_by: actor.into(),
            created_at_ms: now_ms,
        };
        self.db
            .create_evaluation_execution(&index, &receipt)
            .map_err(Status::internal)
    }

    fn request_cancellation(
        &self,
        index: &evaluation_execution_domain::EvaluationExecutionIndex,
        receipt: &OperationReceipt,
        actor: &str,
    ) -> Result<(), Status> {
        let append = self.db.append_operation_receipt_event(
            &index.operation_id,
            evaluation_cancellation_event(receipt, actor, chrono::Utc::now().timestamp_millis()),
        );
        if let Err(error) = append {
            let reconciled = self
                .db
                .get_operation_receipt(&index.operation_id)
                .map_err(Status::internal)?
                .is_some_and(|receipt| {
                    receipt.completed_at_ms.is_some() || evaluation_cancellation_requested(&receipt)
                });
            if !reconciled {
                return Err(Status::internal(error));
            }
        }
        Ok(())
    }

    fn cancellation_for(&self, manifest_digest: &str) -> Result<Arc<AtomicBool>, Status> {
        let mut cancellations = self
            .cancellations
            .lock()
            .map_err(|_| Status::internal("evaluation cancellation lock poisoned"))?;
        Ok(cancellations
            .entry(manifest_digest.to_string())
            .or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone())
    }

    fn execution_lock_for(&self, manifest_digest: &str) -> Result<Arc<AsyncMutex<()>>, Status> {
        let mut locks = self
            .execution_locks
            .lock()
            .map_err(|_| Status::internal("evaluation execution lock poisoned"))?;
        Ok(locks
            .entry(manifest_digest.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone())
    }

    fn cleanup_terminal(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        execution_lock: &Arc<AsyncMutex<()>>,
        projection: &evaluation_execution_domain::EvaluationExecutionProjection,
    ) -> Result<(), Status> {
        if projection.decision.is_none() {
            return Ok(());
        }
        self.cancellations
            .lock()
            .map_err(|_| Status::internal("evaluation cancellation lock poisoned"))?
            .remove(&manifest.manifest_digest);
        let mut locks = self
            .execution_locks
            .lock()
            .map_err(|_| Status::internal("evaluation execution lock poisoned"))?;
        if locks
            .get(&manifest.manifest_digest)
            .is_some_and(|lock| Arc::ptr_eq(lock, execution_lock))
        {
            locks.remove(&manifest.manifest_digest);
        }
        Ok(())
    }

    async fn dispatch(
        &self,
        manifest: evaluation_manifest_domain::ResolvedEvaluationManifest,
        index: evaluation_execution_domain::EvaluationExecutionIndex,
        max_total_duration_ms: u64,
        cancelled: Arc<AtomicBool>,
        stochastic_egress_reasons: BTreeMap<String, String>,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, Status> {
        let db = self.db.clone();
        let budget = self.budget.clone();
        let evaluator_registry = self.evaluator_registry.clone();
        let stochastic_evaluator_registry = self.stochastic_evaluator_registry.clone();
        tokio::task::spawn_blocking(move || {
            let engine = evaluation_execution_domain::EvaluationExecutionEngine::new(
                &evaluator_registry,
                &stochastic_evaluator_registry,
                &stochastic_egress_reasons,
                &budget,
            );
            run_evaluation_execution(
                &db,
                &engine,
                &manifest,
                &index,
                max_total_duration_ms,
                cancelled,
            )
        })
        .await
        .map_err(|error| Status::internal(format!("evaluation worker failed: {error}")))?
    }

    fn stochastic_egress_reasons(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    ) -> BTreeMap<String, String> {
        let mut reasons = BTreeMap::new();
        for node in &manifest.nodes {
            let Some(policy) = &node.evaluator.stochastic_policy else {
                continue;
            };
            if policy.egress_policy
                == evaluation_plan_domain::STOCHASTIC_EGRESS_ALLOWLISTED_EXTERNAL
                && !crate::chisei::privacy::provider_safe_to_send(
                    &policy.provider,
                    &self.safe_providers,
                )
            {
                reasons.insert(
                    node.node_id.clone(),
                    evaluation_execution_domain::REASON_STOCHASTIC_EGRESS_DENIED.into(),
                );
            }
        }
        reasons
    }

    #[cfg(test)]
    pub(super) fn ensure_execution_for_test(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        actor: &str,
        max_total_duration_ms: u64,
    ) -> Result<evaluation_execution_domain::EvaluationExecutionIndex, Status> {
        self.ensure_execution(manifest, actor, max_total_duration_ms)
    }

    #[cfg(test)]
    pub(super) fn request_cancellation_for_test(
        &self,
        index: &evaluation_execution_domain::EvaluationExecutionIndex,
        receipt: &OperationReceipt,
        actor: &str,
    ) -> Result<(), Status> {
        self.request_cancellation(index, receipt, actor)
    }

    #[cfg(test)]
    pub(super) fn stochastic_egress_reasons_for_test(
        &self,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    ) -> BTreeMap<String, String> {
        self.stochastic_egress_reasons(manifest)
    }

    #[cfg(test)]
    pub(super) fn stochastic_budget_reason(
        budget: &BudgetTracker,
        manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
        node: &evaluation_manifest_domain::ResolvedEvaluationNode,
    ) -> Option<String> {
        let policy = node.evaluator.stochastic_policy.as_ref()?;
        let Ok(amount) = i32::try_from(policy.max_total_tokens) else {
            return Some(evaluation_execution_domain::REASON_STOCHASTIC_TOKEN_BUDGET.into());
        };
        let scope = format!(
            "project:{}/stochastic-evaluation:{}",
            manifest.namespace, node.node_id
        );
        let idempotency_key = format!(
            "stochastic-evaluation-reserve:{}:{}",
            manifest.manifest_digest, node.node_id
        );
        budget
            .check_and_reserve_idempotent(&scope, amount, &idempotency_key)
            .err()
            .map(|_| evaluation_execution_domain::REASON_STOCHASTIC_TOKEN_BUDGET.into())
    }
}

fn get_evaluation_projection(
    db: &RuntimeDb,
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    index: &evaluation_execution_domain::EvaluationExecutionIndex,
) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, Status> {
    let receipt = db
        .get_operation_receipt(&index.operation_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
    evaluation_total_budget_ms(&receipt)?;
    evaluation_projection_from_receipt(manifest, index, &receipt).map_err(Status::data_loss)
}

fn load_evaluation_node_evidence(
    db: &RuntimeDb,
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    node: &evaluation_manifest_domain::ResolvedEvaluationNode,
) -> Result<Vec<evaluation_execution_domain::EvaluationEvidenceInput>, String> {
    let by_object = manifest
        .evidence
        .iter()
        .map(|evidence| (evidence.evidence_object_id.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let mut inputs = Vec::with_capacity(node.evidence_object_ids.len());
    for object_id in &node.evidence_object_ids {
        let binding = by_object
            .get(object_id.as_str())
            .ok_or_else(|| "manifest node evidence binding is missing".to_string())?;
        let submission = db
            .get_evidence_submission(&binding.submission_id)?
            .ok_or_else(|| evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE.to_string())?;
        let envelope = submission
            .envelope
            .ok_or_else(|| evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE.to_string())?;
        let retained_content_digest = crate::sekai::evidence_store::canonical_content_digest(
            &envelope.content,
        )
        .map_err(|_| evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE.to_string())?;
        if submission.id != binding.submission_id
            || submission.namespace != manifest.namespace
            || submission.content_digest != binding.content_digest
            || submission.schema_id != binding.schema_id
            || submission.schema_version != binding.schema_version
            || envelope.content_digest != binding.content_digest
            || retained_content_digest != binding.content_digest
            || envelope.schema_id != binding.schema_id
            || envelope.schema_version != binding.schema_version
        {
            return Err(evaluation_execution_domain::REASON_EVIDENCE_UNAVAILABLE.into());
        }
        inputs.push(evaluation_execution_domain::EvaluationEvidenceInput {
            evidence_object_id: binding.evidence_object_id.clone(),
            submission_id: binding.submission_id.clone(),
            content_digest: binding.content_digest.clone(),
            schema_id: binding.schema_id.clone(),
            schema_version: binding.schema_version.clone(),
            content: envelope.content,
        });
    }
    Ok(inputs)
}

fn unavailable_evaluation_node_evidence(
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    node: &evaluation_manifest_domain::ResolvedEvaluationNode,
) -> Result<Vec<evaluation_execution_domain::EvaluationEvidenceInput>, String> {
    let by_object = manifest
        .evidence
        .iter()
        .map(|evidence| (evidence.evidence_object_id.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    node.evidence_object_ids
        .iter()
        .map(|object_id| {
            let binding = by_object
                .get(object_id.as_str())
                .ok_or_else(|| "manifest node evidence binding is missing".to_string())?;
            Ok(evaluation_execution_domain::EvaluationEvidenceInput {
                evidence_object_id: binding.evidence_object_id.clone(),
                submission_id: binding.submission_id.clone(),
                content_digest: binding.content_digest.clone(),
                schema_id: binding.schema_id.clone(),
                schema_version: binding.schema_version.clone(),
                content: serde_json::Value::Null,
            })
        })
        .collect()
}

fn run_evaluation_execution(
    db: &RuntimeDb,
    engine: &evaluation_execution_domain::EvaluationExecutionEngine<'_>,
    manifest: &evaluation_manifest_domain::ResolvedEvaluationManifest,
    index: &evaluation_execution_domain::EvaluationExecutionIndex,
    max_total_duration_ms: u64,
    cancelled: Arc<AtomicBool>,
) -> Result<evaluation_execution_domain::EvaluationExecutionProjection, Status> {
    let existing = get_evaluation_projection(db, manifest, index)?;
    if existing.decision.is_some() {
        return Ok(existing);
    }
    let invocation_started = Instant::now();
    let total_budget = Duration::from_millis(max_total_duration_ms);
    let elapsed_before_invocation_ms = chrono::Utc::now()
        .timestamp_millis()
        .saturating_sub(index.created_at_ms)
        .max(0) as u64;
    let elapsed_before_invocation = Duration::from_millis(elapsed_before_invocation_ms);
    let order = evaluation_execution_domain::deterministic_topological_order(manifest)
        .map_err(Status::data_loss)?;
    let nodes = manifest
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut prior_steps = existing
        .steps
        .into_iter()
        .map(|step| (step.node_id.clone(), step))
        .collect::<BTreeMap<_, _>>();

    for node_id in order {
        if prior_steps.contains_key(&node_id) {
            continue;
        }
        if db
            .get_operation_receipt(&index.operation_id)
            .map_err(Status::internal)?
            .is_some_and(|receipt| evaluation_cancellation_requested(&receipt))
        {
            cancelled.store(true, Ordering::Release);
        }
        let node = nodes
            .get(node_id.as_str())
            .ok_or_else(|| Status::data_loss("evaluation node is missing"))?;
        let evidence = load_evaluation_node_evidence(db, manifest, node);
        let evaluator_evidence = match &evidence {
            Ok(evidence) => evidence.clone(),
            Err(_) => {
                unavailable_evaluation_node_evidence(manifest, node).map_err(Status::data_loss)?
            }
        };
        let definition = db
            .get_evaluator_definition(&node.evaluator.definition_id)
            .map_err(Status::internal)?
            .and_then(|definition| {
                let canonical = evaluation_plan_domain::prepare_definition(
                    definition.clone(),
                    &definition.created_by,
                    definition.created_at_ms,
                )
                .ok()?;
                (canonical == definition
                    && definition.content_digest == node.evaluator.definition_digest
                    && definition.implementation_digest == node.evaluator.implementation_digest
                    && definition.stochastic_policy == node.evaluator.stochastic_policy)
                    .then_some(definition)
            });
        let remaining = total_budget
            .saturating_sub(elapsed_before_invocation)
            .saturating_sub(invocation_started.elapsed());
        let input = evaluation_execution_domain::build_evaluator_input(
            manifest,
            node,
            evaluator_evidence,
            &prior_steps,
        )
        .map_err(Status::data_loss)?;
        let mut execution = engine
            .execute_node(evaluation_execution_domain::EvaluationNodeExecution {
                manifest,
                node,
                input: input.clone(),
                evidence_available: evidence.is_ok(),
                prior_steps: &prior_steps,
                definition: definition.as_ref(),
                remaining,
                cancelled: cancelled.clone(),
            })
            .map_err(|error| match error {
                evaluation_execution_domain::EvaluationExecutionError::Internal(message) => {
                    Status::internal(message)
                }
            })?;
        if db
            .get_operation_receipt(&index.operation_id)
            .map_err(Status::internal)?
            .is_some_and(|receipt| evaluation_cancellation_requested(&receipt))
            && execution.receipt.reason_code
                != evaluation_execution_domain::REASON_EXECUTION_CANCELLED
        {
            cancelled.store(true, Ordering::Release);
            execution = evaluation_execution_domain::make_nonexecuted_node(
                manifest,
                node,
                &input,
                evaluation_execution_domain::STATUS_SKIPPED,
                evaluation_execution_domain::REASON_EXECUTION_CANCELLED,
            )
            .map_err(Status::internal)?;
        }
        let event = evaluation_step_event(
            &index.operation_id,
            node,
            &execution.receipt,
            chrono::Utc::now().timestamp_millis(),
        )?;
        let (receipt, recorded) = match db
            .append_operation_receipt_event(&index.operation_id, event)
        {
            Ok(result) => result,
            Err(error) => {
                let receipt = db
                    .get_operation_receipt(&index.operation_id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
                let projection = evaluation_projection_from_receipt(manifest, index, &receipt)
                    .map_err(Status::data_loss)?;
                let durable_step = projection
                    .steps
                    .iter()
                    .find(|step| step.node_id == node.node_id);
                let durable_step_matches =
                    durable_step.is_some_and(|step| step == &execution.receipt);
                let durable_cancellation_won =
                    evaluation_cancellation_requested(&receipt) && durable_step.is_some();
                if projection.decision.is_some() || durable_step_matches || durable_cancellation_won
                {
                    (receipt, false)
                } else if evaluation_cancellation_requested(&receipt) {
                    cancelled.store(true, Ordering::Release);
                    execution = evaluation_execution_domain::make_nonexecuted_node(
                        manifest,
                        node,
                        &input,
                        evaluation_execution_domain::STATUS_SKIPPED,
                        evaluation_execution_domain::REASON_EXECUTION_CANCELLED,
                    )
                    .map_err(Status::internal)?;
                    let cancellation_event = evaluation_step_event(
                        &index.operation_id,
                        node,
                        &execution.receipt,
                        chrono::Utc::now().timestamp_millis(),
                    )?;
                    db.append_operation_receipt_event(&index.operation_id, cancellation_event)
                        .map_err(Status::internal)?
                } else {
                    return Err(Status::internal(error));
                }
            }
        };
        let projection = evaluation_projection_from_receipt(manifest, index, &receipt)
            .map_err(Status::data_loss)?;
        if recorded {
            let durable_step = projection
                .steps
                .iter()
                .find(|step| step.node_id == node.node_id)
                .ok_or_else(|| Status::data_loss("durable evaluation step is missing"))?;
            let (metrics_evaluator, metrics_version) = engine.metric_labels(manifest, node);
            crate::obs::signals::record_evaluation_step(
                metrics_evaluator,
                metrics_version,
                &durable_step.status,
                execution.elapsed,
            );
        }
        prior_steps = projection
            .steps
            .into_iter()
            .map(|step| (step.node_id.clone(), step))
            .collect();
    }

    let steps = prior_steps.values().cloned().collect::<Vec<_>>();
    let decision =
        evaluation_execution_domain::reduce_gate(manifest, &steps).map_err(Status::data_loss)?;
    let parent_event_id = order_parent_event_id(manifest, &index.operation_id);
    let event = evaluation_gate_event(
        &index.operation_id,
        parent_event_id.clone(),
        &decision,
        chrono::Utc::now().timestamp_millis(),
    )?;
    let receipt = match db.append_operation_receipt_event(&index.operation_id, event) {
        Ok((receipt, _)) => receipt,
        Err(error) => {
            let receipt = db
                .get_operation_receipt(&index.operation_id)
                .map_err(Status::internal)?
                .ok_or_else(|| Status::data_loss("evaluation execution receipt is missing"))?;
            let projection = evaluation_projection_from_receipt(manifest, index, &receipt)
                .map_err(Status::data_loss)?;
            if projection.decision.is_some() {
                receipt
            } else {
                if !evaluation_cancellation_requested(&receipt) {
                    return Err(Status::internal(error));
                }
                cancelled.store(true, Ordering::Release);
                let cancellation_decision =
                    evaluation_execution_domain::reduce_cancelled_gate(manifest, &steps)
                        .map_err(Status::data_loss)?;
                let cancellation_event = evaluation_gate_event(
                    &index.operation_id,
                    parent_event_id,
                    &cancellation_decision,
                    chrono::Utc::now().timestamp_millis(),
                )?;
                db.append_operation_receipt_event(&index.operation_id, cancellation_event)
                    .map_err(Status::internal)?
                    .0
            }
        }
    };
    evaluation_projection_from_receipt(manifest, index, &receipt).map_err(Status::data_loss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_state_is_shared_per_manifest() {
        let db = Arc::new(RuntimeDb::memory());
        let lifecycle = EvaluationExecutionLifecycle::new(
            db.clone(),
            Arc::new(BudgetTracker::new(db)),
            Arc::new(evaluation_execution_domain::DeterministicEvaluatorRegistry::default()),
            Arc::new(evaluation_execution_domain::StochasticEvaluatorRegistry::default()),
            HashSet::new(),
        );

        let first_cancellation = lifecycle.cancellation_for("sha256:manifest").unwrap();
        let second_cancellation = lifecycle.cancellation_for("sha256:manifest").unwrap();
        assert!(Arc::ptr_eq(&first_cancellation, &second_cancellation));

        let first_lock = lifecycle.execution_lock_for("sha256:manifest").unwrap();
        let second_lock = lifecycle.execution_lock_for("sha256:manifest").unwrap();
        assert!(Arc::ptr_eq(&first_lock, &second_lock));
    }
}
