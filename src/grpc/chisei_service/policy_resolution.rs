//! Policy resolution behind one private domain interface.
//!
//! The gRPC adapter owns caller authentication and protocol translation. This
//! module owns ordered policy scope selection, regression handling, privacy and
//! capability gates, cost-tier and portfolio routing, exclusive local-free and
//! portfolio runtime helpers, runtime canonicalization, and fallback projection.

use super::*;

impl ChiseiServiceImpl {
    #[cfg(test)]
    pub(super) async fn resolve_policy(
        &self,
        req: Request<ResolvePolicyRequest>,
    ) -> Result<Response<ResolvePolicyResponse>, Status> {
        let actor = authenticated_actor(&req);
        let resolution = self
            .resolve_policy_for_actor(req.into_inner(), &actor)
            .await?;
        Ok(Response::new(ResolvePolicyResponse {
            resolution: Some(resolution),
        }))
    }

    pub(super) async fn resolve_policy_for_actor(
        &self,
        r: ResolvePolicyRequest,
        actor: &str,
    ) -> Result<PolicyResolution, Status> {
        let requested_namespace = if r.namespace.trim().is_empty() {
            r.project.trim()
        } else {
            r.namespace.trim()
        };
        require_team_namespace_actor_access(&self.db, actor, requested_namespace)?;
        let registry = self.refresh_provider_registry_for_resolution().await?;
        crate::provider_profile::with_provider_registry_snapshot(registry, async {
        let capability_requirements = if r.capability_requirements_json.is_empty() {
            None
        } else {
            Some(
                crate::provider_profile::CapabilityRequirements::parse_json(
                    &r.capability_requirements_json,
                )
                .map_err(|error| Status::failed_precondition(error.to_string()))?,
            )
        };
        let scopes = policy_scopes(&r);
        let (policy_scope, effective_policy) = self
            .policy
            .effective_policy_for_scopes(&scopes)
            .map(|(scope, policy)| (scope, Some(policy)))
            .unwrap_or_else(|| {
                let fallback = if r.namespace.trim().is_empty() {
                    r.project.trim().to_string()
                } else {
                    r.namespace.trim().to_string()
                };
                (fallback, None)
            });
        let mut regression_scopes = vec![policy_scope.as_str()];
        if !r.namespace.trim().is_empty() && r.namespace != policy_scope {
            regression_scopes.push(r.namespace.as_str());
        }
        let mut regression_reasons = Vec::new();
        for scope in regression_scopes {
            let namespace_signal = self
                .eval
                .namespace_regression_signal(scope)
                .filter(|signal| signal.regressed);
            let task_class_signal = crate::chisei::scoring::task_class_regression_signal(
                &self.db,
                scope,
                &r.task_class,
            );
            let namespace_created = namespace_signal
                .as_ref()
                .and_then(|signal| signal.iteration.as_ref())
                .map(|iteration| iteration.created)
                .unwrap_or(i64::MIN);
            if let Some(signal) = task_class_signal
                && signal.observed_at >= namespace_created
            {
                if signal.regressed {
                    regression_reasons.push(signal.reason);
                }
                continue;
            }
            if let Some(signal) = namespace_signal {
                regression_reasons.push(signal.reason);
            }
        }
        let eval_regressed = !regression_reasons.is_empty();
        let eval_regression_reason = regression_reasons.join(" | ");
        validate_explicit_requested_model(&r.preferred_model).map_err(Status::invalid_argument)?;
        let route_override = r.route_override.trim();
        if !route_override.is_empty() {
            validate_explicit_requested_model(route_override).map_err(Status::invalid_argument)?;
            if !route_override_allowed(effective_policy.as_ref(), route_override) {
                return Err(Status::invalid_argument(format!(
                    "route override {route_override:?} is not allowed by effective policy"
                )));
            }
        }
        let requested_preferred_model = &r.preferred_model;
        let preferred_model = if !route_override.is_empty() {
            route_override
        } else { eval_regressed
            .then_some(())
            .as_ref()
            .and(effective_policy.as_ref())
            .map(|policy| policy.default_model.as_str())
            .filter(|model| !model.is_empty())
            .unwrap_or(requested_preferred_model) };
        validate_explicit_requested_model(preferred_model).map_err(Status::invalid_argument)?;
        let override_runtime = (!route_override.is_empty())
            .then(|| crate::provider_resolution::resolve_model(route_override))
            .transpose()
            .map_err(Status::invalid_argument)?
            .map(|model| model.provider);
        let preferred_runtime = override_runtime.as_deref().unwrap_or(&r.preferred_runtime);
        let (mut runtime, model) = if let Some(policy) = effective_policy.as_ref() {
            self.policy
                .apply_policy(policy, preferred_runtime, preferred_model)
                .map_err(Status::invalid_argument)?
        } else {
            self.policy
                .resolve(&policy_scope, preferred_runtime, preferred_model)
                .map_err(Status::invalid_argument)?
        };

        let data_class = self.data_class(effective_policy.as_ref());
        let task_class = TaskClass::parse(&r.task_class);
        let safe_providers = crate::chisei::privacy::safe_providers(&self.config);
        let safe_only = !crate::chisei::privacy::external_allowed(data_class, task_class);
        // Resolve the capable-tier model first; this is the baseline the request
        // would get with no cost tiering.
        let capable_model = if r.preferred_model == "auto"
            && effective_policy.is_none()
            && capability_requirements.is_none()
        {
            let resolved = crate::provider_resolution::resolve_model(&model)
                .map_err(Status::failed_precondition)?;
            if resolved.provider != runtime {
                return Err(Status::failed_precondition(
                    "automatic model default does not match the requested runtime",
                ));
            }
            if safe_only
                && !crate::chisei::privacy::provider_safe_to_send(
                    &resolved.provider,
                    &safe_providers,
                )
            {
                return Err(Status::permission_denied(
                    crate::chisei::privacy::gate_reason(data_class, task_class, &resolved.provider),
                ));
            }
            resolved.canonical_model
        } else {
            self.resolve_live_model_with_override(
                &model,
                effective_policy.as_ref(),
                None,
                safe_only,
                &safe_providers,
                capability_requirements.as_ref(),
                !route_override.is_empty(),
            )
            .await
            .map_err(|err| {
                if err.starts_with("capability_unsupported:") {
                    Status::failed_precondition(err)
                } else if safe_only {
                    Status::permission_denied(format!(
                        "{}: {err}",
                        crate::chisei::privacy::gate_reason(data_class, task_class, "unsafe")
                    ))
                } else {
                    Status::failed_precondition(err)
                }
            })?
        };

        // Eval-gated cost tiering: only explicit bulk task classes route to the
        // cheaper tier, and only while no eval regression is active for the
        // scope. Everything else (primary/unknown) stays on the capable tier.
        // A bare "cheap" is rejected by apply_policy, so the cheaper tier is
        // selected via the provider-scoped "{runtime}/cheap" alias, which only
        // resolves for a recognized provider family. Cheap resolution is
        // best-effort: any failure falls back to the capable model.
        //
        // A promoted "capable" revert (chisei::controller) overrides the static heuristic even
        // when it would otherwise say cheap: it's evidence-backed (gated against held eval
        // history, not just the live per-request signal) and stays active until an operator or a
        // later promotion clears it, covering gaps the live regression check alone can't (e.g. a
        // regressed iteration since pruned). Promotions are written under the candidate's raw
        // namespace (from sampled observations), which may differ from `policy_scope` (the first
        // *matching policy* scope - subject/agent/gateway-key rank ahead of namespace); check both
        // so a subject/agent-scoped policy doesn't silently hide the override. Normalize the class
        // the same way promotion/scoring do (trim + lowercase) - the override is keyed by the
        // normalized class, but `cheap_route_bias` below normalizes internally, so an unnormalized
        // lookup here would miss the override for non-canonical casing/whitespace.
        let normalized_task_class = crate::chisei::scoring::normalize_task_class(&r.task_class);
        let capable_override_active = self
            .active_promotions
            .capable_override_active(&policy_scope, &normalized_task_class)
            || self
                .active_promotions
                .capable_override_active(&r.namespace, &normalized_task_class);
        let wants_local_free = r.budget_route_bias == "local_free";
        if !route_override.is_empty() && wants_local_free {
            return Err(Status::resource_exhausted(
                "hard budget cap reached; a route override cannot fall back to local-free routing",
            ));
        }
        if wants_local_free && (eval_regressed || capable_override_active) {
            let safety_reason = if eval_regressed {
                eval_regression_reason.as_str()
            } else {
                "an active capable-tier override"
            };
            return Err(Status::resource_exhausted(format!(
                "hard budget cap reached and the local-free tier is blocked by the quality safety net: {safety_reason}"
            )));
        }
        let local_free_model = if wants_local_free {
            self.resolve_live_model(
                "ollama/cheap",
                effective_policy.as_ref(),
                Some("cheap"),
                safe_only,
                &safe_providers,
                capability_requirements.as_ref(),
            )
            .await
            .ok()
            .and_then(|model| {
                local_free_runtime_for_model(effective_policy.as_ref(), &model)
                    .map(|local_runtime| (local_runtime, model))
            })
        } else {
            None
        };
        if wants_local_free && local_free_model.is_none() {
            return Err(Status::resource_exhausted(
                "hard budget cap reached and no policy-allowed local-free model is available",
            ));
        }
        let wants_cheap = route_override.is_empty() && !capable_override_active
            && cheap_route_bias(&r.task_class, eval_regressed) == Some("cheap");
        let cheap_model = if wants_cheap && is_known_provider_runtime(&runtime) {
            self.resolve_live_model(
                &format!("{}/cheap", runtime.trim()),
                effective_policy.as_ref(),
                Some("cheap"),
                safe_only,
                &safe_providers,
                capability_requirements.as_ref(),
            )
            .await
            .ok()
        } else {
            None
        };
        // Record the cheap bias only when it produced an actual demotion to a
        // strictly cheaper cost tier, so the audited route_bias reflects
        // realized cost reductions rather than intent or equal-cost swaps.
        let (mut model, mut route_bias) = match local_free_model {
            Some((_local_runtime, local_model)) => (local_model, Some("local_free")),
            None => match cheap_model {
                Some(cheap)
                    if crate::chisei::model_routing::named_model_cost_rank(&cheap)
                        < crate::chisei::model_routing::named_model_cost_rank(&capable_model) =>
                {
                    (cheap, Some("cheap"))
                }
                _ => (capable_model.clone(), None),
            },
        };

        // Portfolio routing supersedes the static cheap/capable heuristic when
        // a scope has an objective and sufficiently sampled frontier data.
        // A regressed eval or promoted capable override reverts immediately;
        // ordinary changes require repeated confirmation plus a cooldown.
        let objective = self
            .portfolio
            .objective(&policy_scope)
            .ok()
            .flatten()
            .map(|objective| (policy_scope.clone(), objective))
            .or_else(|| {
                if r.namespace.trim().is_empty() || r.namespace == policy_scope {
                    None
                } else {
                    self.portfolio
                        .objective(&r.namespace)
                        .ok()
                        .flatten()
                        .map(|objective| (r.namespace.clone(), objective))
                }
            });
        if route_override.is_empty() && !wants_local_free && let Some((portfolio_scope, objective)) = objective {
            let now = chrono::Utc::now().timestamp_millis();
            if eval_regressed || capable_override_active {
                if let Ok(selection) = self.portfolio.damped_route(
                    &portfolio_scope,
                    &normalized_task_class,
                    &capable_model,
                    crate::chisei::portfolio::LEGACY_PROMPT_VARIANT,
                    now,
                    true,
                ) {
                    self.record_portfolio_shift(
                        &portfolio_scope,
                        &normalized_task_class,
                        &selection,
                        &objective,
                        "reverted",
                    );
                    model = capable_model.clone();
                    route_bias = None;
                }
            } else {
                let demand = PortfolioDemand {
                    task_class: normalized_task_class.clone(),
                    expected_calls: r.expected_calls.max(1),
                    quality_bar: None,
                };
                if let Ok(plan) = self.portfolio.allocate(&objective, &[demand])
                    && let Some(allocation) = plan.allocations.first()
                    && portfolio_model_allowed(effective_policy.as_ref(), &allocation.model)
                    && portfolio_runtime_for_model(
                        effective_policy.as_ref(),
                        &runtime,
                        &allocation.model,
                    )
                    .is_some()
                    && let Ok(proposed) = self
                        .resolve_live_model(
                            &allocation.model,
                            effective_policy.as_ref(),
                            None,
                            safe_only,
                            &safe_providers,
                            capability_requirements.as_ref(),
                        )
                        .await
                    && proposed == allocation.model
                    && let Ok(selection) = self.portfolio.damped_route(
                        &portfolio_scope,
                        &normalized_task_class,
                        &proposed,
                        &allocation.prompt_variant,
                        now,
                        false,
                    )
                    && portfolio_model_allowed(effective_policy.as_ref(), &selection.model)
                    && portfolio_runtime_for_model(
                        effective_policy.as_ref(),
                        &runtime,
                        &selection.model,
                    )
                    .is_some()
                    && let Ok(selected) = self
                        .resolve_live_model(
                            &selection.model,
                            effective_policy.as_ref(),
                            None,
                            safe_only,
                            &safe_providers,
                            capability_requirements.as_ref(),
                        )
                        .await
                    && selected == selection.model
                {
                    self.record_portfolio_shift(
                        &portfolio_scope,
                        &normalized_task_class,
                        &selection,
                        &objective,
                        "shifted",
                    );
                    model = selected;
                    route_bias = Some("portfolio");
                }
            }
        }

        runtime = final_runtime_for_model(effective_policy.as_ref(), &runtime, &model)
            .map_err(Status::failed_precondition)?;
        let provider = runtime.as_str();
        if safe_only && !crate::chisei::privacy::provider_safe_to_send(provider, &safe_providers) {
            return Err(Status::permission_denied(
                crate::chisei::privacy::gate_reason(data_class, task_class, provider),
            ));
        }
        let fallback_models = if route_override.is_empty() {
            effective_policy
                .as_ref()
                .into_iter()
                .flat_map(|policy| policy.allowed_models.iter())
                .filter_map(|candidate| {
                    crate::provider_resolution::resolve_model(candidate)
                        .ok()
                        .map(|resolved| resolved.canonical_model)
                })
                .filter(|candidate| candidate != &model)
                .filter(|candidate| {
                    final_runtime_for_model(effective_policy.as_ref(), &runtime, candidate).is_ok()
                })
                .filter(|candidate| {
                    let provider = crate::llm::provider_name(candidate);
                    !safe_only
                        || crate::chisei::privacy::provider_safe_to_send(provider, &safe_providers)
                })
                .take(8)
                .collect()
        } else {
            Vec::new()
        };

        Ok(PolicyResolution {
                runtime,
                model,
                eval_regressed,
                eval_regression_reason,
                data_class: data_class.as_str().into(),
                route_bias: route_bias.unwrap_or_default().to_string(),
                policy_scope: effective_policy
                    .as_ref()
                    .map(|_| policy_scope.clone())
                    .unwrap_or_default(),
                policy_version: effective_policy
                    .as_ref()
                    .map(|policy| policy.version())
                    .unwrap_or_default(),
                fallback_models,
            })
        })
        .await
    }

    pub(super) fn record_portfolio_shift(
        &self,
        scope: &str,
        task_class: &str,
        selection: &crate::chisei::portfolio::RouteSelection,
        objective: &Objective,
        outcome: &str,
    ) {
        if !selection.shifted {
            return;
        }
        let _ = self.db.record_decision(&crate::sekai::audit::Decision {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            actor: "chisei.portfolio".into(),
            action: "chisei.portfolio_route_shift".into(),
            reason: selection.reason.clone(),
            evidence: HashMap::from([
                ("task_class".into(), task_class.to_string()),
                ("previous_model".into(), selection.previous_model.clone()),
                (
                    "previous_prompt_variant".into(),
                    selection.previous_prompt_variant.clone(),
                ),
                ("selected_model".into(), selection.model.clone()),
                (
                    "selected_prompt_variant".into(),
                    selection.prompt_variant.clone(),
                ),
                ("objective_mode".into(), objective.mode.as_str().into()),
                (
                    "budget_usd_micros".into(),
                    objective.budget_usd_micros.to_string(),
                ),
                ("quality_bar".into(), objective.quality_bar.to_string()),
                ("min_samples".into(), objective.min_samples.to_string()),
            ]),
            target_id: scope.to_string(),
            outcome: outcome.to_string(),
        });
    }
}

pub(super) fn portfolio_model_allowed(policy: Option<&Policy>, model: &str) -> bool {
    policy.is_none_or(|policy| {
        policy.allowed_models.is_empty()
            || policy.allowed_models.iter().any(|allowed| allowed == model)
    })
}

pub(super) fn portfolio_runtime_for_model(
    policy: Option<&Policy>,
    current_runtime: &str,
    model: &str,
) -> Option<String> {
    let model_runtime = crate::llm::provider_name(model);
    if model_runtime == current_runtime.trim() {
        return Some(model_runtime.to_string());
    }
    policy
        .filter(|policy| {
            policy.allowed_runtimes.is_empty()
                || policy
                    .allowed_runtimes
                    .iter()
                    .any(|allowed| allowed == model_runtime)
        })
        .map(|_| model_runtime.to_string())
}

pub(super) fn local_free_runtime_for_model(policy: Option<&Policy>, model: &str) -> Option<String> {
    let runtime = crate::llm::provider_name(model);
    if runtime != "ollama" {
        return None;
    }
    match policy {
        None => Some(runtime.to_string()),
        Some(policy)
            if policy.allowed_runtimes.is_empty()
                || policy
                    .allowed_runtimes
                    .iter()
                    .any(|allowed| allowed == runtime) =>
        {
            Some(runtime.to_string())
        }
        Some(_) => None,
    }
}
