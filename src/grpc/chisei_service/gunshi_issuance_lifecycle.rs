//! Gunshi issuance behind one private interface.
//!
//! The gRPC adapter authenticates the caller and translates protocol messages.
//! This module owns the ordered issuance lifecycle: canonical issuance identity,
//! governed Kioku evidence load, advisory recommendation, durable issuance
//! recording, auto-dispatch authorization, residency attributes, allocation-policy
//! mutation, and status plus scorecard projection.

use super::*;

impl ChiseiServiceImpl {
    pub(super) fn issue_recommendations_from_authenticated(
        &self,
        actor: String,
        request: IssueGunshiRecommendationsRequest,
    ) -> Result<IssueGunshiRecommendationsResponse, Status> {
        let issuance_id = request.issuance_id.trim();
        if issuance_id.is_empty()
            || issuance_id.len() > 128
            || issuance_id != request.issuance_id
            || !issuance_id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_.:".contains(character))
        {
            return Err(Status::invalid_argument(
                "issuance_id must be a canonical identifier of at most 128 characters",
            ));
        }
        let issuance_id = issuance_id.to_string();
        let mut input: crate::chisei::gunshi::RecommendationInput =
            serde_json::from_str(&request.input_json).map_err(|error| {
                Status::invalid_argument(format!("invalid recommendation input: {error}"))
            })?;
        if input.contract_version != crate::chisei::gunshi::RECOMMENDATION_INPUT_VERSION {
            return Err(Status::invalid_argument(format!(
                "unsupported recommendation input contract {}",
                input.contract_version
            )));
        }
        if !input.kioku_evidence.is_empty() {
            return Err(Status::invalid_argument(
                "server-issued recommendations load governed Kioku evidence; inline evidence is not accepted",
            ));
        }
        if input.request.operations.is_empty() {
            return Err(Status::invalid_argument(
                "server-issued recommendations require at least one operation",
            ));
        }
        let mut scopes = input
            .request
            .operations
            .iter()
            .map(|operation| {
                (
                    operation.namespace.clone(),
                    operation.operation_class.clone(),
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        for (namespace, _) in &scopes {
            require_namespace_write_access(&self.db, &actor, namespace)?;
        }
        for (namespace, operation_class) in std::mem::take(&mut scopes) {
            input.kioku_evidence.extend(
                crate::chisei::gunshi::load_kioku_evidence(&self.db, &namespace, &operation_class)
                    .map_err(Status::internal)?,
            );
        }
        input
            .kioku_evidence
            .sort_by(|left, right| left.memory_id.cmp(&right.memory_id));
        input
            .kioku_evidence
            .dedup_by(|left, right| left.memory_id == right.memory_id);
        let request_digest = {
            use sha2::Digest;
            let input_json =
                serde_json::to_vec(&input).map_err(|error| Status::internal(error.to_string()))?;
            format!("{:x}", sha2::Sha256::digest(input_json))
        };
        let allocation = crate::chisei::gunshi::recommend_advisory(
            &input.request,
            &input.kioku_evidence,
            &input.advisory_policy,
        )
        .map_err(Status::failed_precondition)?;
        crate::chisei::gunshi_feedback::record_issued_recommendations(
            &self.db,
            &actor,
            &issuance_id,
            &request_digest,
            &allocation.plans,
            chrono::Utc::now().timestamp_millis(),
            input.request.capacity.captured_at_ms,
        )
        .map_err(Status::failed_precondition)?;
        let operations = input
            .request
            .operations
            .iter()
            .map(|operation| (operation.operation_id.as_str(), operation))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut auto_dispatch_authorization_json = Vec::with_capacity(allocation.plans.len());
        let mut receipt_attributes_json = Vec::with_capacity(allocation.plans.len());
        for plan in &allocation.plans {
            let operation = operations.get(plan.operation_id.as_str()).ok_or_else(|| {
                Status::internal("Gunshi allocation references an unknown operation")
            })?;
            let (mut authorization, mut attributes) =
                crate::chisei::gunshi_auto::authorize_namespace_auto_dispatch(
                    &self.db,
                    &plan.namespace,
                    plan,
                    operation,
                    &input.request.capacity,
                )
                .map_err(Status::failed_precondition)?;
            let data_class = self
                .policy
                .effective_policy(&plan.namespace)
                .map(|policy| policy.data_class)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "unclassified".into());
            let provider = crate::llm::provider_name(&plan.selection.model);
            match self.policy.enforce_residency(
                &plan.namespace,
                provider,
                &plan.selection.model,
                &data_class,
            ) {
                Ok(decision) => {
                    attributes.extend(self.policy.residency_receipt_attributes(&decision));
                }
                Err(error) => {
                    authorization.authorized = false;
                    authorization.mode = crate::chisei::gunshi_dispatch::DispatchMode::AdvisoryOnly;
                    authorization.reasons.push(error);
                    attributes.insert("residency_allowed".into(), "false".into());
                    attributes.insert(
                        "residency_denial_reasons".into(),
                        authorization.reasons.last().cloned().unwrap_or_default(),
                    );
                }
            }
            auto_dispatch_authorization_json.push(
                serde_json::to_string(&authorization)
                    .map_err(|error| Status::internal(error.to_string()))?,
            );
            receipt_attributes_json.push(
                serde_json::to_string(&attributes)
                    .map_err(|error| Status::internal(error.to_string()))?,
            );
        }
        Ok(IssueGunshiRecommendationsResponse {
            allocation_json: serde_json::to_string(&allocation)
                .map_err(|error| Status::internal(error.to_string()))?,
            issuance_id,
            auto_dispatch_authorization_json,
            receipt_attributes_json,
        })
    }

    pub(super) fn set_allocation_policy_from_authenticated(
        &self,
        actor: String,
        input: SetGunshiAllocationPolicyRequest,
    ) -> Result<SetGunshiAllocationPolicyResponse, Status> {
        require_namespace_write_access(&self.db, &actor, &input.namespace)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let status = match input.operation.as_str() {
            "install" => {
                let snapshot = serde_json::from_str(&input.snapshot_json).map_err(|error| {
                    Status::invalid_argument(format!("invalid allocation snapshot: {error}"))
                })?;
                let gate = serde_json::from_str(&input.gate_json).map_err(|error| {
                    Status::invalid_argument(format!("invalid evaluation gate: {error}"))
                })?;
                let status = crate::chisei::gunshi_auto::install_baseline(
                    &self.db,
                    &actor,
                    &input.namespace,
                    snapshot,
                    gate,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?;
                serde_json::to_value(status).map_err(|error| Status::internal(error.to_string()))?
            }
            "promote" => {
                let candidate = serde_json::from_str(&input.candidate_json).map_err(|error| {
                    Status::invalid_argument(format!("invalid candidate snapshot: {error}"))
                })?;
                let baseline =
                    serde_json::from_str(&input.baseline_evaluation_json).map_err(|error| {
                        Status::invalid_argument(format!("invalid baseline evaluation: {error}"))
                    })?;
                let candidate_evaluation = serde_json::from_str(&input.candidate_evaluation_json)
                    .map_err(|error| {
                    Status::invalid_argument(format!("invalid candidate evaluation: {error}"))
                })?;
                let status = crate::chisei::gunshi_auto::promote(
                    &self.db,
                    crate::chisei::gunshi_auto::PromoteRequest {
                        actor,
                        namespace: input.namespace,
                        candidate,
                        baseline,
                        candidate_evaluation,
                        expected_revision: input.expected_revision,
                        now_ms,
                    },
                )
                .map_err(Status::failed_precondition)?;
                serde_json::to_value(status).map_err(|error| Status::internal(error.to_string()))?
            }
            "rollback" => serde_json::to_value(
                crate::chisei::gunshi_auto::rollback(
                    &self.db,
                    &actor,
                    &input.namespace,
                    &input.expected_revision,
                    &input.reason,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?,
            )
            .map_err(|error| Status::internal(error.to_string()))?,
            "auto_opt_in" => serde_json::to_value(
                crate::chisei::gunshi_auto::set_auto_opt_in(
                    &self.db,
                    &actor,
                    &input.namespace,
                    input.enabled,
                    &input.expected_revision,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?,
            )
            .map_err(|error| Status::internal(error.to_string()))?,
            "kill_switch" => serde_json::to_value(
                crate::chisei::gunshi_auto::set_kill_switch(
                    &self.db,
                    &actor,
                    &input.namespace,
                    input.enabled,
                    &input.reason,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?,
            )
            .map_err(|error| Status::internal(error.to_string()))?,
            "feedback" => {
                let plan: crate::chisei::gunshi::AllocationPlan =
                    serde_json::from_str(&input.allocation_json).map_err(|error| {
                        Status::invalid_argument(format!("invalid allocation plan: {error}"))
                    })?;
                if plan.namespace != input.namespace {
                    return Err(Status::invalid_argument(
                        "feedback allocation namespace does not match the policy namespace",
                    ));
                }
                let choice = serde_json::from_str(&input.choice_json).map_err(|error| {
                    Status::invalid_argument(format!("invalid operator choice: {error}"))
                })?;
                let outcome = (!input.outcome_json.trim().is_empty())
                    .then(|| serde_json::from_str(&input.outcome_json))
                    .transpose()
                    .map_err(|error| {
                        Status::invalid_argument(format!("invalid observed outcome: {error}"))
                    })?;
                serde_json::to_value(
                    crate::chisei::gunshi_feedback::record_feedback(
                        &self.db,
                        &actor,
                        &input.issuance_id,
                        &plan,
                        &choice,
                        outcome.as_ref(),
                    )
                    .map_err(Status::failed_precondition)?,
                )
                .map_err(|error| Status::internal(error.to_string()))?
            }
            "promote_feedback" => {
                let result = crate::chisei::gunshi_feedback_eval::promote_feedback_to_eval(
                    &self.db,
                    &actor,
                    &input.suite_id,
                    &input.issuance_id,
                    &input.allocation_id,
                    &input.namespace,
                    now_ms,
                )
                .map_err(Status::failed_precondition)?;
                if let Err(error) = self.eval.put_suite(result.suite.clone())
                    && self.eval.get_suite(&result.suite_id).as_ref() != Some(&result.suite)
                {
                    tracing::warn!(
                        %error,
                        suite_id = %result.suite_id,
                        "eval store sync after feedback promotion"
                    );
                }
                serde_json::to_value(result).map_err(|error| Status::internal(error.to_string()))?
            }
            _ => {
                return Err(Status::invalid_argument(
                    "operation must be install, promote, rollback, auto_opt_in, kill_switch, feedback, or promote_feedback",
                ));
            }
        };
        Ok(SetGunshiAllocationPolicyResponse {
            status_json: serde_json::to_string(&status)
                .map_err(|error| Status::internal(error.to_string()))?,
        })
    }

    pub(super) fn allocation_status_from_authenticated(
        &self,
        actor: String,
        request: GetGunshiAllocationStatusRequest,
    ) -> Result<GetGunshiAllocationStatusResponse, Status> {
        let namespace = request.namespace.clone();
        require_namespace_access(&self.db, &actor, &namespace)?;
        let status = crate::chisei::gunshi_auto::get_status(&self.db, &namespace)
            .map_err(Status::internal)?;
        let status_json = match status {
            Some(status) => serde_json::to_string(&status)
                .map_err(|error| Status::internal(error.to_string()))?,
            None => "{}".into(),
        };
        let scorecard = crate::chisei::gunshi_feedback::advisory_scorecard(&self.db, &namespace)
            .map_err(Status::internal)?;
        Ok(GetGunshiAllocationStatusResponse {
            status_json,
            scorecard_json: serde_json::to_string(&scorecard)
                .map_err(|error| Status::internal(error.to_string()))?,
        })
    }
}
