//! Gateway decide lifecycle behind one private interface.
//!
//! The gRPC adapter authenticates the caller and translates protocol messages.
//! This module owns the ordered decide path: namespace admission, trusted-gateway
//! scope checks, context-admission gates, token/request budget and continuation
//! degradation, policy resolution, sampling, audit, and decision projection.

use super::*;
use crate::chisei::gateway_decide::{
    GATEWAY_DECIDE_CONTRACT_VERSION, GatewayDecideDenyReason, GatewayDecideInputs,
    GatewayDecideOutcome, GatewayDecideRequest, budget_grant_id, compose_gateway_decide,
};
use crate::sekai::coordination::{
    RESERVATION_STATUS_ACTIVE, ReservationFilter, WORK_UNIT_STATUS_RUNNING,
};

impl ChiseiServiceImpl {
    pub(super) async fn decide_from_authenticated_request(
        &self,
        actor: String,
        delegated_principal: Option<String>,
        r: DecideGatewayExecutionRequest,
    ) -> Result<DecideGatewayExecutionResponse, Status> {
        let namespace = r.namespace.trim();
        if namespace.is_empty() {
            return Ok(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: GatewayDecideDenyReason::InvalidRequest.as_str().into(),
                deny_message: "namespace is required".into(),
                ..Default::default()
            });
        }
        if let Err(status) =
            require_execution_namespace_access(&self.db, &self.config, &actor, namespace)
        {
            let reason = if status.code() == tonic::Code::PermissionDenied {
                GatewayDecideDenyReason::Unauthorized
            } else {
                GatewayDecideDenyReason::InvalidRequest
            };
            return Ok(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: reason.as_str().into(),
                deny_message: status.message().to_string(),
                ..Default::default()
            });
        }

        let domain_request = GatewayDecideRequest {
            contract_version: r.contract_version.clone(),
            namespace: namespace.into(),
            principal: actor.clone(),
            requested_model: r.requested_model.trim().to_string(),
            operation_class: r.operation_class.trim().to_string(),
            estimated_cost_usd_micros: r.estimated_cost_usd_micros,
            correlation_operation_id: r.correlation_operation_id.trim().to_string(),
            correlation_attempt: r.correlation_attempt,
        };
        if let Err(message) = domain_request.validate() {
            return Ok(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: GatewayDecideDenyReason::InvalidRequest.as_str().into(),
                deny_message: message,
                ..Default::default()
            });
        }
        let context_admission_policy = match self.policy.context_admission_policy(namespace) {
            Ok(Some(policy)) => policy,
            Ok(None) => {
                return Ok(DecideGatewayExecutionResponse {
                    contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                    admitted: false,
                    deny_reason: GatewayDecideDenyReason::PolicyDenied.as_str().into(),
                    deny_message: "context admission policy is required".into(),
                    context_admission_reasons: vec!["context_admission:missing".into()],
                    ..Default::default()
                });
            }
            Err(_error) => {
                return Ok(DecideGatewayExecutionResponse {
                    contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                    admitted: false,
                    deny_reason: GatewayDecideDenyReason::PolicyDenied.as_str().into(),
                    deny_message: "context admission policy unavailable".into(),
                    context_admission_reasons: vec!["context_admission:unavailable".into()],
                    ..Default::default()
                });
            }
        };
        let context_admission_policy_version = context_admission_policy.version();
        let context_admission_descriptor_version =
            crate::chisei::epistemic_descriptor::EPISTEMIC_DESCRIPTOR_VERSION.to_string();
        let operation_risk =
            crate::chisei::policy::OperationRisk::from_labels(&r.operation_class, &r.task_class);
        let operation_context_gate = context_admission_policy
            .operation_admission(operation_risk)
            .map_err(Status::failed_precondition)?;
        if operation_context_gate.blocks_provider() {
            return Ok(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: GatewayDecideDenyReason::PolicyDenied.as_str().into(),
                deny_message: "context admission policy requires review or verification".into(),
                context_admission_policy_version: operation_context_gate.policy_version.clone(),
                context_admission_descriptor_version: operation_context_gate
                    .descriptor_version
                    .clone(),
                context_admission_decision: operation_context_gate.action.as_str().into(),
                context_admission_reasons: vec![operation_context_gate.reason_code.clone()],
                ..Default::default()
            });
        }

        let project = if r.project.trim().is_empty() {
            namespace
        } else {
            r.project.trim()
        };
        let trusted_gateway = matches!(actor.as_str(), "root" | "local" | "chisei-gateway");
        if project != namespace
            || (!trusted_gateway
                && ((!r.agent.trim().is_empty() && r.agent.trim() != actor)
                    || (!r.user_id.trim().is_empty() && r.user_id.trim() != actor)
                    || !r.key_id.trim().is_empty()))
        {
            return Ok(DecideGatewayExecutionResponse {
                contract_version: GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                admitted: false,
                deny_reason: GatewayDecideDenyReason::Unauthorized.as_str().into(),
                deny_message: "gateway decision scopes are not authorized for the caller".into(),
                ..Default::default()
            });
        }
        let budget_subject = budget_subject(
            "",
            project,
            r.agent.trim(),
            r.key_id.trim(),
            r.work_unit.trim(),
            "",
        )
        .unwrap_or_else(|_| format!("project:{project}"));
        let estimated_tokens = r.estimated_tokens.max(0);
        let metric = crate::db::chisei_budget::METRIC_TOKENS;
        let token_budget_check =
            self.budget
                .check_with_metric(&budget_subject, estimated_tokens, metric);
        let request_budget_check = self.budget.check_with_metric(
            &budget_subject,
            i32::try_from(r.expected_calls.max(1)).unwrap_or(i32::MAX),
            crate::db::chisei_budget::METRIC_REQUESTS,
        );
        let within_cap = token_budget_check.is_ok() && request_budget_check.is_ok();
        let decision_budget_scope = request_budget_check
            .as_ref()
            .err()
            .or_else(|| token_budget_check.as_ref().err())
            .as_ref()
            .and_then(|error| {
                error
                    .strip_prefix("budget exceeded at ")
                    .and_then(|rest| rest.split_once(": used"))
                    .map(|(scope, _)| scope.to_string())
            })
            .unwrap_or_else(|| budget_subject.clone());
        let mut route_bias = self
            .budget
            .route_bias(
                &budget_subject,
                estimated_tokens,
                metric,
                r.task_class.trim(),
            )
            .as_str()
            .to_string();
        let continuation_started = !r.work_unit.trim().is_empty()
            && active_continuation_allocation(
                &self.db,
                r.work_unit.trim(),
                &[
                    actor.as_str(),
                    r.agent.as_str(),
                    r.key_id.as_str(),
                    r.user_id.as_str(),
                ],
                chrono::Utc::now().timestamp_millis(),
            )
            && self
                .budget
                .get_usage_with_metric(&budget_subject, metric)
                .tokens_used
                > 0;
        let (budget_allowed, degradation_level, budget_warning) = if within_cap {
            (
                true,
                if route_bias == "cheap" {
                    "cheap_cloud"
                } else {
                    "capable"
                },
                false,
            )
        } else if request_budget_check.is_ok() && continuation_started {
            (true, "warn", true)
        } else if request_budget_check.is_ok()
            && r.local_free_available
            && crate::chisei::model_routing::is_cheap_eligible_task_class(r.task_class.trim())
        {
            route_bias = "local_free".to_string();
            // The canonical decision may admit only after policy resolution
            // proves that this recommendation resolves to a local-free model.
            // The gateway independently rejects any non-local result.
            (true, "local_free", true)
        } else {
            (false, "hard_cap", true)
        };

        // Keep the gateway decision on the same policy-resolution path as
        // the internal policy resolver. The retired edge fallback previously
        // supplied scoped policies, eval regressions, lifecycle checks, and
        // canonical live-model resolution; the canonical PDP must preserve
        // those semantics itself.
        let policy_request = ResolvePolicyRequest {
            namespace: namespace.to_string(),
            preferred_runtime: r.preferred_runtime.trim().to_string(),
            preferred_model: r.requested_model.trim().to_string(),
            subject: String::new(),
            project: project.to_string(),
            agent: r.agent.trim().to_string(),
            key_id: r.key_id.trim().to_string(),
            task_class: r.task_class.trim().to_string(),
            user_id: r.user_id.trim().to_string(),
            expected_calls: r.expected_calls.max(1),
            budget_route_bias: route_bias.clone(),
            route_override: r.route_override.trim().to_string(),
            capability_requirements_json: r.capability_requirements_json.clone(),
        };
        let (route, policy_resolution) =
            match self.resolve_policy_for_actor(policy_request, &actor).await {
                Ok(resolution) => {
                    if !resolution.route_bias.trim().is_empty() {
                        route_bias = resolution.route_bias.clone();
                    }
                    (
                        Ok((
                            resolution.runtime.clone(),
                            resolution.model.clone(),
                            resolution.policy_version.clone(),
                        )),
                        Some(resolution),
                    )
                }
                Err(status) => {
                    // Capability-document failures use FailedPrecondition so a
                    // mixed native catalog or provider matrix is
                    // capability_unsupported, not policy_denied.
                    let reason = match status.code() {
                        tonic::Code::ResourceExhausted => GatewayDecideDenyReason::BudgetDenied,
                        tonic::Code::FailedPrecondition => {
                            GatewayDecideDenyReason::CapabilityUnsupported
                        }
                        tonic::Code::PermissionDenied => GatewayDecideDenyReason::ResidencyDenied,
                        tonic::Code::InvalidArgument => GatewayDecideDenyReason::PolicyDenied,
                        _ => GatewayDecideDenyReason::PolicyDenied,
                    };
                    (Err((reason, status.message().to_string())), None)
                }
            };

        let grant = budget_grant_id(
            &budget_subject,
            &domain_request.correlation_operation_id,
            domain_request.correlation_attempt,
        );
        let composed = compose_gateway_decide(GatewayDecideInputs {
            request: domain_request.clone(),
            route,
            budget_allowed,
            budget_scope: decision_budget_scope.clone(),
            budget_grant_id: grant.clone(),
            route_bias: route_bias.clone(),
            degradation_level: degradation_level.into(),
            budget_warning,
        });

        let mut response = DecideGatewayExecutionResponse {
            contract_version: composed.contract_version.clone(),
            admitted: composed.allows_upstream(),
            deny_reason: String::new(),
            deny_message: String::new(),
            resolved_runtime: String::new(),
            resolved_model: String::new(),
            policy_version: String::new(),
            budget_scope: decision_budget_scope.clone(),
            budget_grant_id: grant,
            route_bias,
            degradation_level: degradation_level.into(),
            budget_warning,
            policy_scope: policy_resolution
                .as_ref()
                .map(|resolution| resolution.policy_scope.clone())
                .unwrap_or_default(),
            data_class: policy_resolution
                .as_ref()
                .map(|resolution| resolution.data_class.clone())
                .unwrap_or_default(),
            fallback_models: policy_resolution
                .as_ref()
                .map(|resolution| resolution.fallback_models.clone())
                .unwrap_or_default(),
            eval_regressed: policy_resolution
                .as_ref()
                .is_some_and(|resolution| resolution.eval_regressed),
            eval_regression_reason: policy_resolution
                .as_ref()
                .map(|resolution| resolution.eval_regression_reason.clone())
                .unwrap_or_default(),
            context_admission_policy_version: context_admission_policy_version.clone(),
            context_admission_descriptor_version: context_admission_descriptor_version.clone(),
            context_admission_decision: operation_context_gate.action.as_str().to_string(),
            context_admission_reasons: vec![operation_context_gate.reason_code.clone()],
            sampling_evaluated: false,
            sampled: false,
            sample_rate: 0.0,
            sample_reason: String::new(),
            prepared_spec: String::new(),
        };
        match &composed.outcome {
            GatewayDecideOutcome::Admit(admit) => {
                response.resolved_runtime = admit.resolved_runtime.clone();
                response.resolved_model = admit.resolved_model.clone();
                response.policy_version = admit.policy_version.clone();
                response.budget_grant_id = admit.budget_grant_id.clone();
            }
            GatewayDecideOutcome::Deny(deny) => {
                response.deny_reason = deny.reason.as_str().into();
                response.deny_message = deny.message.clone();
            }
        }
        if response.admitted && !r.pipeline_spec.trim().is_empty() {
            match self.gateway_pipeline_decision(GatewayPipelineInput {
                actor: &actor,
                delegated_principal: delegated_principal.as_deref(),
                request_id: &domain_request.correlation_operation_id,
                namespace,
                spec: &r.pipeline_spec,
                model: &response.resolved_model,
                runtime: &response.resolved_runtime,
                task_class: &r.task_class,
            }) {
                Ok(decision) => {
                    response.sampling_evaluated = true;
                    response.sampled = decision.sampling.sampled;
                    response.sample_rate = decision.sampling.effective_rate;
                    response.sample_reason = decision.sampling.reason;
                    response.prepared_spec = decision.run.prepared_spec;
                }
                Err(error) => {
                    response.admitted = false;
                    response.deny_reason = GatewayDecideDenyReason::PolicyDenied.as_str().into();
                    response.deny_message =
                        format!("gateway pipeline decision unavailable: {error}");
                    response.resolved_runtime.clear();
                    response.resolved_model.clear();
                    response.policy_version.clear();
                    response.budget_grant_id.clear();
                    response.sampling_evaluated = false;
                    response.sampled = false;
                    response.sample_rate = 0.0;
                    response.sample_reason.clear();
                    response.prepared_spec.clear();
                }
            }
        }

        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: format!(
                "gateway-decide:{}:{}:{}",
                namespace,
                domain_request.correlation_operation_id,
                domain_request.correlation_attempt
            ),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor,
            action: "gateway.decide".into(),
            reason: if response.admitted {
                "gateway fat-decide admitted".into()
            } else {
                response.deny_message.clone()
            },
            evidence: std::collections::HashMap::from([
                ("namespace".into(), namespace.into()),
                (
                    "correlation_operation_id".into(),
                    domain_request.correlation_operation_id.clone(),
                ),
                ("admitted".into(), response.admitted.to_string()),
                ("deny_reason".into(), response.deny_reason.clone()),
                ("resolved_model".into(), response.resolved_model.clone()),
                ("budget_scope".into(), response.budget_scope.clone()),
                (
                    "contract_version".into(),
                    GATEWAY_DECIDE_CONTRACT_VERSION.into(),
                ),
            ]),
            target_id: domain_request.correlation_operation_id,
            outcome: if response.admitted {
                "admitted".into()
            } else {
                "denied".into()
            },
        });

        Ok(response)
    }

    pub(super) fn gateway_pipeline_decision(
        &self,
        input: GatewayPipelineInput<'_>,
    ) -> Result<GatewayPipelineDecision, Status> {
        let context_actor = execution_context_actor(
            &self.db,
            &self.config,
            input.actor,
            input.delegated_principal,
            input.namespace,
        )?;
        let context_admission_policy = self
            .policy
            .context_admission_policy(input.namespace)
            .map_err(Status::failed_precondition)?;
        let mut request = pipe::PipelineRequest {
            request_id: input.request_id.to_string(),
            namespace: input.namespace.to_string(),
            spec: input.spec.to_string(),
            model: input.model.to_string(),
            runtime: input.runtime.to_string(),
            task_type: "gateway_llm_call".into(),
            priority: 0,
            risk_score: 0.0,
            budget_pressure: self.budget.namespace_pressure(input.namespace),
            review_model: String::new(),
            egress_records: vec![],
            external_egress: true,
            template_only: TaskClass::parse(input.task_class) == TaskClass::TemplateOnly,
            expanded_context_items: 0,
            evidence_references: vec![],
            memory_references: vec![],
            memory_holdouts: vec![],
            memory_actor: context_actor,
            memory_assignment_id: String::new(),
            memory_token_budget: 512,
            allowed_evidence_classes: HashSet::new(),
            context_admission_policy,
            context_admission: pipe::ContextAdmissionSummary::default(),
            risk_score_ready: false,
            risk_signals: vec![],
            operation_risk_override: None,
        };
        let context_expansion_gate = self.pipeline_context_expansion_gate(input.namespace);
        let evidence_context_gates =
            self.applicable_evidence_context_gates(&request, context_expansion_gate.allowed)?;
        let allowed_evidence_classes = evidence_context_gates
            .iter()
            .filter(|class_gate| class_gate.effective_allowed)
            .map(|class_gate| pipe::EvidenceContextClass {
                source_type: class_gate.source_type.clone(),
                evidence_type: class_gate.evidence_type.clone(),
            })
            .collect::<HashSet<_>>();
        let run = self.pipeline.run_with_context_admission(
            &mut request,
            &self.db,
            context_expansion_gate.allowed,
            allowed_evidence_classes,
        );
        self.record_context_expansion_gate(
            input.request_id,
            input.namespace,
            &context_expansion_gate,
            run.expanded_context_items,
        )?;
        self.record_evidence_context_gates(
            input.request_id,
            input.namespace,
            &evidence_context_gates,
            &run.evidence_references,
        )?;
        let sampling = crate::chisei::sampling::require_sampling(&run.steps)
            .map_err(Status::failed_precondition)?;
        Ok(GatewayPipelineDecision { run, sampling })
    }
}

fn active_continuation_allocation(
    db: &RuntimeDb,
    work_unit_id: &str,
    budget_identities: &[&str],
    now_ms: i64,
) -> bool {
    let Ok(Some(work_unit)) = db.get_work_unit(work_unit_id) else {
        return false;
    };
    if work_unit.status != WORK_UNIT_STATUS_RUNNING
        || !budget_identities.iter().any(|identity| {
            *identity == work_unit.owner_principal || *identity == work_unit.creator_principal
        })
    {
        return false;
    }
    db.list_reservations(&ReservationFilter {
        work_unit_id: Some(work_unit_id.to_string()),
        status: Some(RESERVATION_STATUS_ACTIVE.to_string()),
        ..Default::default()
    })
    .is_ok_and(|reservations| {
        reservations.iter().any(|reservation| {
            reservation.released_at == 0
                && reservation.expires_at > now_ms
                && budget_identities
                    .iter()
                    .any(|identity| *identity == reservation.lease_owner)
        })
    })
}
