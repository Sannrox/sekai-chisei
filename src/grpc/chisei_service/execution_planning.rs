//! Native execution planning behind one private interface.
//!
//! The gRPC adapter authenticates the caller, binds an optional Gunshi allocation,
//! and translates protocol messages. This module owns the ordered planning lifecycle:
//! Kioku context enrichment, policy and routing resolution, preferred-model
//! selection, budget and evaluation gates, egress and privacy decisions,
//! sampling, audit, plan projection, and plan-receipt recording. Receipts are
//! recorded after Gunshi stamps so allocation identity is present; they are
//! not folded into `plan_from_input`.

use super::live_model::{final_runtime_for_model, route_override_allowed};
use super::*;

impl ChiseiServiceImpl {
    pub(super) async fn plan_from_input(
        &self,
        input: ExecutionInput,
        authenticated_actor: &str,
    ) -> Result<ExecutionPlan, Status> {
        let plan_id = uuid::Uuid::new_v4().to_string();
        let mut context_projection_latency_ms = 0_u64;
        let normalized_user_id =
            execution_budget_scope(&input.namespace, authenticated_actor, &input.user_id);
        let scoped_pressure = self.budget.scope_pressure(&normalized_user_id);
        let namespace_pressure = self
            .budget
            .scope_pressure(&format!("project:{}", input.namespace.trim()));
        let budget_pressure = strongest_pressure(scoped_pressure, namespace_pressure);
        let namespace_hint = input.namespace.trim().to_string();
        let effective_policy = self.policy.effective_policy(&input.namespace);
        let context_admission_policy = self
            .policy
            .context_admission_policy(&input.namespace)
            .map_err(Status::failed_precondition)?;
        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&input.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        let template_only =
            data_class == DataClass::Sensitive && task_class == TaskClass::TemplateOnly;
        let mut pipeline_req = pipe::PipelineRequest {
            request_id: input.request_id.clone(),
            namespace: input.namespace.clone(),
            spec: input.spec.clone(),
            model: input.preferred_model.clone(),
            runtime: input.preferred_runtime.clone(),
            task_type: input.task_type.clone(),
            priority: input.priority,
            risk_score: 0.0,
            budget_pressure: budget_pressure.clone(),
            review_model: String::new(),
            egress_records: vec![],
            external_egress: !safe_only,
            template_only,
            expanded_context_items: 0,
            evidence_references: vec![],
            memory_references: vec![],
            memory_holdouts: vec![],
            memory_actor: authenticated_actor.into(),
            memory_assignment_id: plan_id.clone(),
            memory_token_budget: 512,
            allowed_evidence_classes: std::collections::HashSet::new(),
            context_admission_policy: context_admission_policy.clone(),
            context_admission: pipe::ContextAdmissionSummary::default(),
            risk_score_ready: false,
            risk_signals: vec![],
            operation_risk_override: None,
        };
        let affinity = crate::chisei::affinity::get_affinity(&self.db, namespace_hint.as_str());
        let context_expansion_gate = self.pipeline_context_expansion_gate(&input.namespace);
        let evidence_context_gates =
            self.applicable_evidence_context_gates(&pipeline_req, context_expansion_gate.allowed)?;
        let allowed_evidence_classes = evidence_context_gates
            .iter()
            .filter(|class_gate| class_gate.effective_allowed)
            .map(|class_gate| pipe::EvidenceContextClass {
                source_type: class_gate.source_type.clone(),
                evidence_type: class_gate.evidence_type.clone(),
            })
            .collect::<HashSet<_>>();
        let projection_started = Instant::now();
        let initial_run = self.pipeline.run_with_context_admission(
            &mut pipeline_req,
            &self.db,
            context_expansion_gate.allowed,
            allowed_evidence_classes.clone(),
        );
        context_projection_latency_ms = context_projection_latency_ms.saturating_add(
            u64::try_from(projection_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        );
        let fallback_runtime = pipeline_req.runtime.clone();
        let (initial_runtime, initial_model, initial_pref_runtime, initial_pref_model) = self
            .resolve_model_for_run(
                &input,
                &fallback_runtime,
                &initial_run,
                effective_policy.as_ref(),
                safe_only,
                &safe_providers,
            )
            .await?;
        let initial_provider = crate::llm::provider_name(&initial_model).to_string();
        let initial_provider_is_external =
            crate::chisei::egress::is_external_provider(&initial_provider);
        let (
            run,
            resolved_runtime,
            resolved_model,
            provider,
            provider_is_external,
            effective_preferred_runtime,
            effective_preferred_model,
        ) = if initial_provider_is_external || safe_only || template_only {
            (
                initial_run,
                initial_runtime,
                initial_model,
                initial_provider,
                true,
                initial_pref_runtime,
                initial_pref_model,
            )
        } else {
            let mut local_pipeline_req = pipe::PipelineRequest {
                request_id: input.request_id.clone(),
                namespace: input.namespace.clone(),
                spec: input.spec.clone(),
                model: input.preferred_model.clone(),
                runtime: input.preferred_runtime.clone(),
                task_type: input.task_type.clone(),
                priority: input.priority,
                risk_score: 0.0,
                budget_pressure: budget_pressure.clone(),
                review_model: String::new(),
                egress_records: vec![],
                external_egress: false,
                template_only,
                expanded_context_items: 0,
                evidence_references: vec![],
                memory_references: vec![],
                memory_holdouts: vec![],
                memory_actor: authenticated_actor.into(),
                memory_assignment_id: plan_id.clone(),
                memory_token_budget: 512,
                allowed_evidence_classes: std::collections::HashSet::new(),
                context_admission_policy: context_admission_policy.clone(),
                context_admission: pipe::ContextAdmissionSummary::default(),
                risk_score_ready: false,
                risk_signals: vec![],
                operation_risk_override: None,
            };
            let projection_started = Instant::now();
            let local_run = self.pipeline.run_with_context_admission(
                &mut local_pipeline_req,
                &self.db,
                context_expansion_gate.allowed,
                allowed_evidence_classes,
            );
            context_projection_latency_ms = context_projection_latency_ms.saturating_add(
                u64::try_from(projection_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
            let (local_runtime, local_model, local_pref_runtime, local_pref_model) = self
                .resolve_model_for_run(
                    &input,
                    &local_pipeline_req.runtime,
                    &local_run,
                    effective_policy.as_ref(),
                    safe_only,
                    &safe_providers,
                )
                .await?;
            let local_provider = crate::llm::provider_name(&local_model).to_string();
            if crate::chisei::egress::is_external_provider(&local_provider) {
                (
                    initial_run,
                    initial_runtime,
                    initial_model,
                    initial_provider,
                    true,
                    initial_pref_runtime,
                    initial_pref_model,
                )
            } else {
                (
                    local_run,
                    local_runtime,
                    local_model,
                    local_provider,
                    false,
                    local_pref_runtime,
                    local_pref_model,
                )
            }
        };
        self.record_context_expansion_gate(
            &input.request_id,
            &input.namespace,
            &context_expansion_gate,
            run.expanded_context_items,
        )?;
        self.record_evidence_context_gates(
            &input.request_id,
            &input.namespace,
            &evidence_context_gates,
            &run.evidence_references,
        )?;
        let egress_decisions =
            build_egress_decisions(&run.egress_records, &provider, provider_is_external);
        let prepared_messages = build_prepared_messages(&input, &run.prepared_spec);
        let estimate_req = ProviderExecutionRequest {
            model: resolved_model.clone(),
            system: input.system.clone(),
            messages: prepared_messages.clone(),
            tools: input.tools.clone(),
            max_tokens: input.max_tokens,
            user_id: Some(normalized_user_id.clone()),
        };
        let estimated_tokens = estimate_chat_request(&estimate_req);
        let allowed = self
            .budget
            .check_with_metric(&normalized_user_id, estimated_tokens, METRIC_TOKENS)
            .is_ok();
        let usage = self
            .budget
            .get_usage_with_metric(&normalized_user_id, METRIC_TOKENS);
        let budget_reason = if allowed {
            String::new()
        } else {
            format!(
                "budget exceeded: used {} + {} > {}",
                usage.tokens_used, estimated_tokens, usage.max_tokens
            )
        };
        let mut normalized_input = input.clone();
        normalized_input.user_id = normalized_user_id;
        normalized_input.estimated_tokens = estimated_tokens;
        // Persist the pre-policy preference actually used for resolve (request,
        // route override, recommendation, bias, or runtime fallback)—not only
        // empty raw request fields—so historical dry-run can replay accurately.
        normalized_input.preferred_runtime = effective_preferred_runtime;
        normalized_input.preferred_model = effective_preferred_model;
        let mut warnings = run.warnings();
        let final_route_bias_value =
            crate::chisei::model_routing::route_bias(&run.steps).map(str::to_string);
        let final_route_bias = final_route_bias_value.as_deref();
        let review_policy = if let Some(p) = run.review_policy.as_ref() {
            let model = if p.model.is_empty() {
                resolved_model.clone()
            } else {
                self.resolve_live_model(
                    &p.model,
                    effective_policy.as_ref(),
                    final_route_bias,
                    safe_only,
                    &safe_providers,
                    None,
                )
                .await
                .unwrap_or_else(|_| resolved_model.clone())
            };
            Some(ReviewPolicy {
                confidence_threshold: p.confidence_threshold,
                max_cycles: p.max_cycles,
                model,
            })
        } else {
            None
        };
        let namespace_eval_signal = if namespace_hint.is_empty() {
            None
        } else {
            self.eval.namespace_regression_signal(&namespace_hint)
        };
        if let Some(signal) = namespace_eval_signal
            .as_ref()
            .filter(|signal| signal.regressed)
        {
            warnings.push(signal.reason.clone());
        }
        let eval_regressed = namespace_eval_signal
            .as_ref()
            .map(|signal| signal.regressed)
            .unwrap_or(false);
        let eval_regression_reason = namespace_eval_signal
            .as_ref()
            .filter(|signal| signal.regressed)
            .map(|signal| signal.reason.clone())
            .unwrap_or_default();
        let mut executable = allowed && !eval_regressed;
        if run.context_admission.blocks_provider() {
            executable = false;
            if run.context_admission.requires_review {
                warnings.push("context admission requires review".into());
            }
            if run.context_admission.requires_verification {
                warnings.push("context admission requires verification".into());
            }
        }
        let low_success_namespace = affinity.low_success;
        // Sampling: the pipeline decides from request metadata; the eval-driven
        // adaptive trigger (oversample regressed namespaces) is applied here since the
        // eval store lives on the service.
        let mut sampling = crate::chisei::sampling::decode_sampling(&run.steps).unwrap_or(
            crate::chisei::sampling::SamplingDecision {
                sampled: false,
                effective_rate: self.config.sample_rate,
                reason: "not_sampled".into(),
            },
        );
        if eval_regressed && !sampling.sampled {
            sampling.sampled = true;
            sampling.effective_rate = 1.0;
            sampling.reason = "eval_regressed".into();
        }
        if sampling.sampled {
            let mut evidence = std::collections::HashMap::new();
            evidence.insert(
                "effective_rate".to_string(),
                sampling.effective_rate.to_string(),
            );
            evidence.insert("risk_score".to_string(), run.risk_score.to_string());
            evidence.insert("model".to_string(), resolved_model.clone());
            let _ = self.db.record_decision(&crate::sekai::audit::Decision {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis(),
                actor: "chisei.sampling".into(),
                action: "sample".into(),
                reason: sampling.reason.clone(),
                evidence,
                target_id: input.request_id.clone(),
                outcome: "sampled".into(),
            });
        }
        if safe_only {
            let provider_safe =
                crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers);
            if !provider_safe {
                self.record_privacy_audit(
                    "blocked",
                    &input.request_id,
                    &provider,
                    data_class,
                    task_class,
                    "unsafe_provider",
                );
                return Err(Status::failed_precondition(
                    crate::chisei::privacy::gate_reason(data_class, task_class, &provider),
                ));
            }
            self.record_privacy_audit(
                "forced_local",
                &input.request_id,
                &provider,
                data_class,
                task_class,
                "safe_provider_required",
            );
        } else if template_only && provider_is_external {
            self.record_privacy_audit(
                "allowed_template_only",
                &input.request_id,
                &provider,
                data_class,
                task_class,
                "template_only_sanitization_contract",
            );
        }
        let mut egress_decisions = egress_decisions;
        let leak_findings = self.leak_findings_for_payload(
            &input.namespace,
            &provider,
            data_class,
            &payload_for_leak_check(&input.system, &prepared_messages, &input.tools),
        );
        if !leak_findings.is_empty() {
            egress_decisions.extend(leak_findings_to_decisions(
                &provider,
                provider_is_external,
                &leak_findings,
            ));
            self.record_leak_audit("leak_check", &input.request_id, &provider, &leak_findings);
            if leak_findings
                .iter()
                .any(|finding| finding.action == LeakAction::Block)
            {
                executable = false;
                warnings.push("privacy leak checker blocked outbound payload".into());
            }
        }
        if data_class == DataClass::Sensitive
            && task_class == TaskClass::TemplateOnly
            && !crate::chisei::privacy::provider_safe_to_send(&provider, &safe_providers)
            && let Some(warning) = self
                .run_leak_reviewer(&input.request_id, &provider, &input.spec)
                .await
        {
            warnings.push(warning);
        }
        self.record_egress_audit(
            "prepare_context",
            &input.request_id,
            &provider,
            &resolved_model,
            &egress_decisions,
        );
        let context_bytes = context_bytes(&input.system, &prepared_messages);
        let context_tokens = estimate_context_tokens(&input.system, &prepared_messages);
        let context_truncated = run
            .evidence_references
            .iter()
            .any(|reference| reference.descriptor.source_rows_truncated)
            || run
                .memory_references
                .iter()
                .any(|reference| reference.descriptor.source_rows_truncated);
        Ok(ExecutionPlan {
            plan_id,
            input: Some(normalized_input),
            resolved_runtime,
            resolved_model: resolved_model.clone(),
            enriched_spec: run.prepared_spec.clone(),
            prepared_system: input.system.clone(),
            prepared_messages,
            tools: input.tools.clone(),
            budget: Some(BudgetVerdict {
                allowed,
                usage: Some(BudgetUsage {
                    user_id: usage.user_id,
                    tokens_used: usage.tokens_used,
                    max_tokens: usage.max_tokens,
                    period_type: usage.period_type.as_str().into(),
                    period_start: usage.period_start,
                }),
                reason: budget_reason,
            }),
            steps: run
                .steps
                .iter()
                .map(|s| StepDecision {
                    step: s.step.clone(),
                    action: s.action.clone(),
                    reasoning: s.reasoning.clone(),
                    confidence: s.confidence,
                    suggestion: s.suggestion.clone(),
                    value: s.value.clone(),
                })
                .collect(),
            review_policy,
            risk_score: run.risk_score,
            low_success_namespace,
            executable,
            warnings,
            max_tokens: input.max_tokens,
            created_at: chrono::Utc::now().timestamp_millis(),
            affinity_namespaces: affinity.namespaces,
            eval_regressed,
            eval_regression_reason,
            sampled: sampling.sampled,
            sample_rate: sampling.effective_rate,
            sample_reason: sampling.reason,
            egress_decisions,
            task_class: task_class.as_str().into(),
            evidence_references: run
                .evidence_references
                .iter()
                .map(context_evidence_reference)
                .collect(),
            memory_references: run
                .memory_references
                .iter()
                .map(memory_context_reference)
                .collect(),
            planning_actor: authenticated_actor.into(),
            memory_holdouts: run
                .memory_holdouts
                .iter()
                .map(|holdout| MemoryHoldoutReference {
                    memory_id: holdout.memory_id.clone(),
                    memory_version: holdout.memory_version,
                    classification: holdout.classification.clone(),
                    content_digest: holdout.content_digest.clone(),
                })
                .collect(),
            context_admission_policy_version: run.context_admission.policy_version.clone(),
            context_admission_descriptor_version: run.context_admission.descriptor_version.clone(),
            context_admission_decision: run.context_admission.decision.clone(),
            context_admission_reasons: run.context_admission.reason_codes.clone(),
            context_admission_source_digests: run.context_admission.source_digests.clone(),
            context_admission_requires_review: run.context_admission.requires_review,
            context_admission_requires_verification: run.context_admission.requires_verification,
            context_bytes,
            context_tokens,
            context_projection_latency_ms,
            context_truncated,
            gunshi_issuance_id: String::new(),
            gunshi_allocation_id: String::new(),
            gunshi_agent_id: String::new(),
            gunshi_policy_version: String::new(),
            gunshi_input_fingerprint: String::new(),
            gunshi_budget_ceiling_usd_micros: 0,
            gunshi_max_attempts: 0,
            gunshi_human_review_required: false,
        })
    }

    pub(super) fn record_planned_operation(
        &self,
        plan: &ExecutionPlan,
        actor: &str,
    ) -> Result<(), String> {
        let input = plan
            .input
            .as_ref()
            .ok_or_else(|| "plan input required".to_string())?;
        let operation_id = plan.plan_id.clone();
        let policy_version = self
            .policy
            .effective_policy(&input.namespace)
            .map(|policy| policy.version())
            .unwrap_or_else(|| "implicit-allow/v1".to_string());
        let started = plan.created_at;
        let mut events = vec![
            receipt_event(
                &operation_id,
                "intent",
                None,
                started,
                ReceiptEventKind::IntentRecorded,
                actor,
                {
                    let mut attributes = BTreeMap::from([
                        ("request_id".into(), input.request_id.clone()),
                        ("task_type".into(), input.task_type.clone()),
                        ("intent_hash".into(), content_hash([input.spec.as_bytes()])),
                        // Effective pre-policy preference (request, override,
                        // recommendation, bias, or runtime fallback).
                        ("preferred_runtime".into(), input.preferred_runtime.clone()),
                        ("preferred_model".into(), input.preferred_model.clone()),
                    ]);
                    if !input.logical_operation_id.trim().is_empty() {
                        attributes.insert(
                            "logical_operation_id".into(),
                            input.logical_operation_id.trim().into(),
                        );
                    }
                    if !input.attempt_id.trim().is_empty() {
                        attributes.insert("attempt_id".into(), input.attempt_id.trim().into());
                    }
                    if !plan.gunshi_allocation_id.is_empty() {
                        attributes.extend([
                            ("gunshi_issuance_id".into(), plan.gunshi_issuance_id.clone()),
                            (
                                "gunshi_allocation_id".into(),
                                plan.gunshi_allocation_id.clone(),
                            ),
                            ("gunshi_agent_id".into(), plan.gunshi_agent_id.clone()),
                            (
                                "gunshi_policy_version".into(),
                                plan.gunshi_policy_version.clone(),
                            ),
                            (
                                "gunshi_input_fingerprint".into(),
                                plan.gunshi_input_fingerprint.clone(),
                            ),
                        ]);
                    }
                    attributes
                },
            ),
            receipt_event(
                &operation_id,
                "context",
                Some("intent"),
                started,
                ReceiptEventKind::ContextGoverned,
                "chisei.pipeline",
                {
                    let mut attributes = BTreeMap::from([
                        (
                            "prepared_context_hash".into(),
                            content_hash(
                                std::iter::once(plan.prepared_system.as_bytes()).chain(
                                    plan.prepared_messages
                                        .iter()
                                        .map(|message| message.content.as_bytes()),
                                ),
                            ),
                        ),
                        ("raw_context_stored".into(), "false".into()),
                    ]);
                    attributes.extend(epistemic_descriptor_receipt_attributes(plan));
                    attributes
                },
            ),
            receipt_event(
                &operation_id,
                "policy",
                Some("context"),
                started,
                ReceiptEventKind::PolicyDecided,
                "chisei.policy",
                {
                    let mut attributes = BTreeMap::from([
                        ("policy_version".into(), policy_version.clone()),
                        ("executable".into(), plan.executable.to_string()),
                        ("risk_score".into(), plan.risk_score.to_string()),
                        (
                            "route_policy_decision".into(),
                            if plan.resolved_runtime.is_empty() && plan.resolved_model.is_empty() {
                                "deny".into()
                            } else {
                                "allow".into()
                            },
                        ),
                    ]);
                    if !plan.context_admission_policy_version.is_empty() {
                        attributes.insert(
                            "context_admission_policy_version".into(),
                            plan.context_admission_policy_version.clone(),
                        );
                        attributes.insert(
                            "context_admission_descriptor_version".into(),
                            plan.context_admission_descriptor_version.clone(),
                        );
                        attributes.insert(
                            "context_admission_decision".into(),
                            plan.context_admission_decision.clone(),
                        );
                        attributes.insert(
                            "context_admission_reasons".into(),
                            plan.context_admission_reasons.join(","),
                        );
                        attributes.insert(
                            "context_admission_source_digests".into(),
                            plan.context_admission_source_digests.join(","),
                        );
                    }
                    attributes
                },
            ),
            receipt_event(
                &operation_id,
                "route",
                Some("policy"),
                started,
                ReceiptEventKind::RouteSelected,
                "chisei.routing",
                {
                    let mut attributes = BTreeMap::from([
                        ("runtime".into(), plan.resolved_runtime.clone()),
                        ("model".into(), plan.resolved_model.clone()),
                        // Effective pre-policy preference (also on Intent) for dry-run.
                        ("preferred_runtime".into(), input.preferred_runtime.clone()),
                        ("preferred_model".into(), input.preferred_model.clone()),
                        (
                            "route_override".into(),
                            if input.route_override.trim().is_empty() {
                                String::new()
                            } else {
                                input.route_override.trim().into()
                            },
                        ),
                        (
                            "bias_bypassed".into(),
                            (!input.route_override.trim().is_empty()).to_string(),
                        ),
                    ]);
                    if !plan.gunshi_allocation_id.is_empty() {
                        attributes.insert(
                            "gunshi_allocation_id".into(),
                            plan.gunshi_allocation_id.clone(),
                        );
                        attributes.insert("gunshi_agent_id".into(), plan.gunshi_agent_id.clone());
                    }
                    attributes
                },
            ),
            receipt_event(
                &operation_id,
                "budget",
                Some("route"),
                started,
                ReceiptEventKind::BudgetDecided,
                "chisei.budget",
                {
                    let mut attributes = BTreeMap::from([
                        (
                            "allowed".into(),
                            plan.budget
                                .as_ref()
                                .is_some_and(|budget| budget.allowed)
                                .to_string(),
                        ),
                        (
                            "estimated_tokens".into(),
                            input.estimated_tokens.to_string(),
                        ),
                    ]);
                    if !plan.gunshi_allocation_id.is_empty() {
                        attributes.insert(
                            "gunshi_budget_ceiling_usd_micros".into(),
                            plan.gunshi_budget_ceiling_usd_micros.to_string(),
                        );
                        attributes.insert(
                            "gunshi_max_attempts".into(),
                            plan.gunshi_max_attempts.to_string(),
                        );
                        attributes.insert(
                            "gunshi_human_review_required".into(),
                            plan.gunshi_human_review_required.to_string(),
                        );
                    }
                    attributes
                },
            ),
        ];
        let mut context = GovernedReference {
            kind: "execution_context".into(),
            reference: format!("operation:{operation_id}:context"),
            content_hash: events[1].attributes.get("prepared_context_hash").cloned(),
            disclosed_fields: vec!["system".into(), "messages.content".into()],
            omitted: true,
            omission_reason: Some("raw private context is not copied into receipts".into()),
        };
        context.disclosed_fields.sort();
        events[1].references.push(context);
        events[1]
            .references
            .extend(
                plan.evidence_references
                    .iter()
                    .map(|reference| GovernedReference {
                        kind: "external_evidence".into(),
                        reference: format!(
                            "evidence:{}@{}",
                            reference.submission_id, reference.source_version
                        ),
                        content_hash: Some(reference.content_digest.clone()),
                        disclosed_fields: reference.disclosed_fields.clone(),
                        omitted: false,
                        omission_reason: None,
                    }),
            );
        events[1]
            .references
            .extend(
                plan.memory_references
                    .iter()
                    .map(|reference| GovernedReference {
                        kind: "kioku_memory".into(),
                        reference: format!(
                            "memory:{}@{}",
                            reference.memory_id, reference.memory_version
                        ),
                        content_hash: Some(reference.content_digest.clone()),
                        disclosed_fields: vec!["claim".into()],
                        omitted: false,
                        omission_reason: None,
                    }),
            );
        if !plan.egress_decisions.is_empty() {
            events.push(receipt_event(
                &operation_id,
                "egress",
                Some("budget"),
                started,
                ReceiptEventKind::EgressDecided,
                "chisei.egress",
                BTreeMap::from([
                    (
                        "decision_count".into(),
                        plan.egress_decisions.len().to_string(),
                    ),
                    (
                        "redacted_field_count".into(),
                        plan.egress_decisions
                            .iter()
                            .map(|decision| decision.redacted.len())
                            .sum::<usize>()
                            .to_string(),
                    ),
                ]),
            ));
        }
        let (completed_at_ms, uncovered_surfaces) = if plan.executable {
            (
                None,
                vec![
                    UncoveredSurface {
                        surface: ReceiptSurface::Attempt,
                        reason: "operation is planned but has not started".into(),
                    },
                    UncoveredSurface {
                        surface: ReceiptSurface::ModelCall,
                        reason: "operation is planned but has not called a model".into(),
                    },
                    UncoveredSurface {
                        surface: ReceiptSurface::Outcome,
                        reason: "operation is planned but has no terminal outcome".into(),
                    },
                ],
            )
        } else {
            let parent = if plan.egress_decisions.is_empty() {
                "budget"
            } else {
                "egress"
            };
            events.push(receipt_event(
                &operation_id,
                "outcome",
                Some(parent),
                started,
                ReceiptEventKind::OutcomeRecorded,
                actor,
                BTreeMap::from([
                    ("status".into(), "denied".into()),
                    ("completion_reason".into(), "plan_not_executable".into()),
                    ("warning_count".into(), plan.warnings.len().to_string()),
                ]),
            ));
            (Some(started), Vec::new())
        };
        let receipt = OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id,
            parent_operation_id: None,
            namespace: input.namespace.clone(),
            operation_class: if input.task_type.trim().is_empty() {
                "model_inference".into()
            } else {
                input.task_type.trim().into()
            },
            initiating_actor: actor.to_string(),
            schema_version: EXECUTION_SCHEMA_VERSION.into(),
            policy_version,
            started_at_ms: started,
            completed_at_ms,
            events,
            uncovered_surfaces,
            reporter_grants: Vec::new(),
            ontology_digest: None,
        };
        let holdouts = plan
            .memory_holdouts
            .iter()
            .map(|holdout| (holdout.memory_id.clone(), holdout.memory_version))
            .collect::<Vec<_>>();
        self.db
            .put_operation_receipt_with_kioku_holdouts(&receipt, &holdouts, actor, started)?;
        Ok(())
    }

    /// Resolve runtime/model and return the effective pre-policy preference
    /// that was fed into policy resolution: `(resolved_runtime, resolved_model,
    /// preferred_runtime, preferred_model)`.
    pub(super) async fn resolve_model_for_run(
        &self,
        input: &ExecutionInput,
        fallback_runtime: &str,
        run: &pipe::RunResult,
        policy: Option<&crate::chisei::policy::Policy>,
        safe_only: bool,
        safe_providers: &std::collections::HashSet<String>,
    ) -> Result<(String, String, String, String), Status> {
        let route_override = input.route_override.trim();
        if !route_override.is_empty() && !route_override_allowed(policy, route_override) {
            return Err(Status::invalid_argument(format!(
                "route override {route_override:?} is not allowed by namespace policy"
            )));
        }
        let recommended_model = run
            .recommended_model()
            .map(|(model, _)| model.to_string())
            .unwrap_or_else(|| input.preferred_model.clone());
        let route_bias_value =
            crate::chisei::model_routing::route_bias(&run.steps).map(str::to_string);
        let route_bias = route_bias_value.as_deref();
        let preferred_model = if route_override.is_empty() {
            choose_preferred_model(
                &input.preferred_model,
                &recommended_model,
                route_bias,
                policy,
            )
        } else {
            route_override.to_string()
        };
        let override_runtime = (!route_override.is_empty())
            .then(|| crate::provider_resolution::resolve_model(route_override))
            .transpose()
            .map_err(Status::invalid_argument)?
            .map(|model| model.provider);
        let preferred_runtime = if let Some(runtime) = override_runtime.as_deref() {
            runtime.to_string()
        } else if input.preferred_runtime.is_empty() {
            fallback_runtime.to_string()
        } else {
            input.preferred_runtime.clone()
        };
        let (runtime, model) = self
            .policy
            .resolve(&input.namespace, &preferred_runtime, &preferred_model)
            .map_err(Status::invalid_argument)?;
        let model = self
            .resolve_live_model_with_override(
                &model,
                policy,
                if route_override.is_empty() {
                    route_bias
                } else {
                    None
                },
                safe_only,
                safe_providers,
                None,
                !route_override.is_empty(),
            )
            .await
            .map_err(Status::failed_precondition)?;
        let runtime = final_runtime_for_model(policy, &runtime, &model)
            .map_err(Status::failed_precondition)?;
        // Single-plane residency (#289): fail closed before any provider contact.
        let data_class = policy
            .map(|policy| policy.data_class.as_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("unclassified");
        let provider = crate::llm::provider_name(&model);
        self.policy
            .enforce_residency(&input.namespace, provider, &model, data_class)
            .map_err(Status::permission_denied)?;
        Ok((runtime, model, preferred_runtime, preferred_model))
    }
}

pub(super) fn choose_preferred_model(
    explicit_model: &str,
    recommended_model: &str,
    route_bias: Option<&str>,
    policy: Option<&crate::chisei::policy::Policy>,
) -> String {
    if !explicit_model.is_empty() {
        return explicit_model.to_string();
    }
    let Some(route_bias) = route_bias else {
        return recommended_model.to_string();
    };
    let alias = format!("ollama/{route_bias}");
    if let Some(policy) = policy {
        if policy.default_model == alias
            || policy.allowed_models.iter().any(|model| model == &alias)
        {
            return alias;
        }
        if policy.default_model == route_bias
            || policy
                .allowed_models
                .iter()
                .any(|model| model == route_bias)
        {
            return route_bias.to_string();
        }
    }
    recommended_model.to_string()
}
