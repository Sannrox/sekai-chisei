//! Gateway receipt admission behind one private interface.
//!
//! The gRPC adapter authenticates the caller and enforces the trusted-principal
//! and negative-adjustment gates. This module owns the ordered admission path:
//! budget idempotency, completeness fail-closed, identity conflict, Kioku
//! preflight, durable put, post-commit attribution audit, and sample persist.

use super::*;

const GATEWAY_RECEIPT_ACTION: &str = "operation.receipt.upsert";

impl ChiseiServiceImpl {
    pub(super) fn record_usage_from_authenticated(
        &self,
        actor: String,
        r: RecordUsageRequest,
    ) -> Result<RecordUsageResponse, Status> {
        let metric = budget_metric(&r.metric)?;
        let budget_subject = budget_subject(
            &r.subject,
            &r.project,
            &r.agent,
            &r.key_id,
            &r.work_unit,
            &r.user_id,
        )?;
        self.budget
            .record_idempotent_with_metric(
                &budget_subject,
                r.tokens_used,
                metric,
                &r.idempotency_key,
            )
            .map_err(Status::internal)?;
        if !r.operation_receipt_json.trim().is_empty() {
            self.persist_gateway_operation_receipt(&r.operation_receipt_json, &actor)?;
        }
        let sample_recorded = if let Some(observation) = r.sample_observation {
            if observation.request_id.trim().is_empty()
                || observation.namespace.trim().is_empty()
                || observation.spec.trim().is_empty()
                || observation.output_content.trim().is_empty()
            {
                return Err(Status::invalid_argument(
                    "sample observation requires request_id, namespace, spec, and output_content",
                ));
            }
            if self.config.scoring_enabled {
                self.db
                    .put_sample_observation(&crate::chisei::scoring::SampleObservation {
                        request_id: observation.request_id,
                        namespace: observation.namespace,
                        spec: observation.spec,
                        resolved_model: observation.resolved_model,
                        output_content: observation.output_content,
                        sample_reason: observation.sample_reason,
                        input_tokens: observation.input_tokens,
                        output_tokens: observation.output_tokens,
                        stop_reason: observation.stop_reason,
                        timestamp: observation.timestamp,
                        scored: false,
                        task_class: crate::chisei::scoring::normalize_task_class(
                            &observation.task_class,
                        ),
                        cost_usd_micros: observation.cost_usd_micros,
                    })
                    .map_err(Status::internal)?;
                true
            } else {
                false
            }
        } else {
            false
        };
        let u = self.budget.get_usage_with_metric(&budget_subject, metric);
        Ok(RecordUsageResponse {
            usage: Some(BudgetUsage {
                user_id: u.user_id,
                tokens_used: u.tokens_used,
                max_tokens: u.max_tokens,
                period_type: u.period_type.as_str().into(),
                period_start: u.period_start,
            }),
            sample_recorded,
        })
    }

    fn persist_gateway_operation_receipt(
        &self,
        receipt_json: &str,
        authenticated_principal: &str,
    ) -> Result<(), Status> {
        let receipt: OperationReceipt = serde_json::from_str(receipt_json)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let completeness = receipt.completeness();
        if !completeness.complete {
            return Err(Status::invalid_argument(format!(
                "gateway receipt is incomplete: missing={:?} errors={:?}",
                completeness.missing_surfaces, completeness.errors
            )));
        }
        let now = chrono::Utc::now().timestamp_millis();
        let has_kioku_context = receipt.events.iter().any(|receipt_event| {
            receipt_event.kind == ReceiptEventKind::ContextGoverned
                && receipt_event
                    .references
                    .iter()
                    .any(|reference| reference.kind == "kioku_memory" && !reference.omitted)
        }) || !self
            .db
            .list_kioku_outcome_assignments(&receipt.operation_id)
            .map_err(Status::internal)?
            .is_empty();
        let existing = self
            .db
            .get_operation_receipt(&receipt.operation_id)
            .map_err(Status::internal)?;
        if existing
            .as_ref()
            .is_some_and(|existing| existing != &receipt)
        {
            return Err(Status::already_exists(
                "operation receipt already exists with different evidence",
            ));
        }
        if existing.is_none() && has_kioku_context {
            reported_operation_event_lifecycle::record_reported_memory_outcomes(
                &self.db,
                &receipt,
                authenticated_principal,
                now,
                false,
                None,
                true,
            )
            .map_err(|error| {
                Status::invalid_argument(format!("Kioku outcome attribution invalid: {error}"))
            })?;
        }
        self.db
            .put_operation_receipt(&receipt)
            .map_err(Status::internal)?;
        if existing.is_none()
            && has_kioku_context
            && let Err(error) = reported_operation_event_lifecycle::record_reported_memory_outcomes(
                &self.db,
                &receipt,
                authenticated_principal,
                now,
                false,
                None,
                false,
            )
        {
            let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                actor: "chisei.kioku".into(),
                action: "kioku.outcome_attribution".into(),
                reason: error,
                evidence: HashMap::from([("operation_id".into(), receipt.operation_id.clone())]),
                target_id: receipt.operation_id.clone(),
                outcome: "failed".into(),
            });
        }
        self.db
            .record_decisions_idempotently(&[crate::sekai::audit::Decision {
                id: format!("{}:gateway-receipt", receipt.operation_id),
                timestamp: now,
                actor: authenticated_principal.into(),
                action: GATEWAY_RECEIPT_ACTION.into(),
                reason: "gateway operation completed".into(),
                evidence: HashMap::from([("operation_id".into(), receipt.operation_id.clone())]),
                target_id: receipt.operation_id,
                outcome: "recorded".into(),
            }])
            .map_err(Status::internal)
    }
}
