//! External-action authorization and transition behind one private interface.
//!
//! The gRPC adapter authenticates the caller and projects protobuf. This module
//! owns claim/idempotency, policy load, blast-radius and budget reservation,
//! persist ordering, permit issuance, and approve/deny/cancel CAS transitions.

use super::*;

impl ChiseiServiceImpl {
    pub(super) fn issue_external_permit(
        &self,
        authorization: &external::AuthorizationRecord,
        actor: &str,
        idempotency_key: &str,
        offline: bool,
    ) -> Result<permit::Permit, Status> {
        if idempotency_key.trim().is_empty() {
            return Err(Status::invalid_argument("idempotency_key required"));
        }
        if actor != authorization.request.actor && !matches!(actor, "root" | "local") {
            return Err(Status::permission_denied("permit issuance denied"));
        }
        require_namespace_write_access(&self.db, actor, &authorization.request.namespace)?;
        if let Some(value) = self
            .db
            .replay_permit(&authorization.decision.authorization_id, idempotency_key)
            .map_err(|error| {
                if error.contains("different idempotency") {
                    Status::already_exists(error)
                } else {
                    Status::internal(error)
                }
            })?
        {
            let requested_mode = if offline {
                permit::OFFLINE_REDEMPTION_MODE
            } else {
                permit::REDEMPTION_MODE
            };
            if value.redemption_mode != requested_mode {
                return Err(Status::already_exists(
                    "authorization already issued with a different redemption mode",
                ));
            }
            return Ok(value);
        }
        let key = permit_signing_key(&self.config)?;
        let approvals = if authorization.approval_status == "approved" {
            vec![authorization.decision_actor.clone()]
        } else {
            Vec::new()
        };
        let issuance = permit::Issuance {
            approval_identities: approvals,
            issuer: &self.config.permit_issuer,
            key_id: &self.config.permit_key_id,
            permit_id: format!("permit-{}", uuid::Uuid::new_v4().simple()),
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            now_ms: chrono::Utc::now().timestamp_millis(),
            site_id: &self.config.site_id,
        };
        let value = if offline {
            let policy = self
                .db
                .get_external_permit_policy(&authorization.decision.policy_scope)
                .map_err(Status::internal)?;
            permit::issue_offline(authorization, &policy, &key, issuance)
        } else {
            permit::issue(authorization, &key, issuance)
        }
        .map_err(Status::failed_precondition)?;
        self.db
            .put_permit(&value, idempotency_key, actor)
            .map_err(|error| {
                if error.contains("different idempotency") {
                    Status::already_exists(error)
                } else {
                    Status::internal(error)
                }
            })
    }

    fn require_current_policy_allows_permit_replay(
        &self,
        actor: &str,
        existing: &external::AuthorizationRecord,
        now_ms: i64,
    ) -> Result<(), Status> {
        if existing.decision.policy_scope.trim().is_empty()
            || existing.decision.policy_version.trim().is_empty()
        {
            return Err(Status::failed_precondition(
                "external-action permit replay requires a policy snapshot",
            ));
        }
        let policy = self
            .db
            .resolve_action_policy(
                actor,
                &existing.request.namespace,
                &existing.request.policy_project,
            )
            .map_err(Status::internal)?;
        let Some(policy) = policy.as_ref() else {
            return Err(Status::failed_precondition(
                "external-action permit replay requires a current action policy",
            ));
        };
        let plan = external_lifecycle::AuthorizationPlan::resolve(
            existing.request.clone(),
            existing.decision.authorization_id.clone(),
            existing.decision.request_digest.clone(),
            actor,
            Some(policy),
            now_ms,
        )
        .map_err(Status::invalid_argument)?;
        if plan.policy_decision != crate::sekai::action_policy::ActionDecision::Allow {
            return Err(Status::permission_denied(
                "external-action permit replay denied by current policy",
            ));
        }
        Ok(())
    }

    pub(super) fn authorize_from_authenticated(
        &self,
        actor: String,
        input: AuthorizeExternalActionRequest,
    ) -> Result<AuthorizeExternalActionResponse, Status> {
        let offline = input.offline;
        let request = input
            .request
            .ok_or_else(|| Status::invalid_argument("request required"))?;
        let request = external_request_from_proto(request);
        request.validate().map_err(Status::invalid_argument)?;
        if request.actor != actor {
            return Err(Status::permission_denied(
                "external-action actor must match authenticated principal",
            ));
        }
        require_namespace_write_access(&self.db, &actor, &request.namespace)?;
        require_external_project_access(
            &self.db,
            &actor,
            &request.namespace,
            &request.policy_project,
        )?;
        let now = chrono::Utc::now().timestamp_millis();
        external_lifecycle::reclaim_expired(&self.db, &self.budget, now)
            .map_err(Status::internal)?;
        let request_digest = request
            .canonical_digest()
            .map_err(Status::invalid_argument)?;
        let mut authorization_id = format!("external-auth-{}", uuid::Uuid::new_v4().simple());
        match self
            .db
            .claim_external_action_authorization(&request, &request_digest, &authorization_id, now)
            .map_err(Status::internal)?
        {
            external::AuthorizationClaim::Claimed(claimed_id) => {
                authorization_id = claimed_id;
            }
            external::AuthorizationClaim::Existing(existing) => {
                external_lifecycle::ensure_audit(&self.db, &existing).map_err(Status::internal)?;
                if existing.decision.decision == "permit" {
                    self.require_current_policy_allows_permit_replay(&actor, &existing, now)?;
                }
                let permit = (existing.decision.decision == "permit")
                    .then(|| {
                        self.issue_external_permit(
                            &existing,
                            &actor,
                            &existing.request.idempotency_key,
                            offline,
                        )
                    })
                    .transpose()?
                    .map(|permit| external_permit_to_proto(&permit));
                return Ok(AuthorizeExternalActionResponse {
                    decision: Some(external_decision_to_proto(&existing.decision)),
                    permit,
                });
            }
            external::AuthorizationClaim::Conflict => {
                return Err(Status::already_exists(
                    "idempotency key was reused with a different canonical request digest",
                ));
            }
            external::AuthorizationClaim::InProgress => {
                return Err(Status::unavailable(
                    "external-action authorization decision is in progress",
                ));
            }
        }

        let policy =
            match self
                .db
                .resolve_action_policy(&actor, &request.namespace, &request.policy_project)
            {
                Ok(policy) => policy,
                Err(error) => {
                    let _ = self
                        .db
                        .abandon_external_action_claim(&request, &request_digest);
                    return Err(Status::internal(error));
                }
            };
        let mut plan = external_lifecycle::AuthorizationPlan::resolve(
            request.clone(),
            authorization_id.clone(),
            request_digest.clone(),
            &actor,
            policy.as_ref(),
            now,
        )
        .map_err(Status::invalid_argument)?;
        if plan.policy_decision != crate::sekai::action_policy::ActionDecision::Deny
            && (plan.max_mutations.is_some() || plan.max_deletes.is_some())
        {
            match self.db.reserve_external_action_blast_radius(
                &authorization_id,
                &request,
                plan.max_mutations,
                plan.max_deletes,
            ) {
                Ok(()) => plan.record.blast_radius_reserved = true,
                Err(_) => {
                    plan.policy_decision = crate::sekai::action_policy::ActionDecision::Deny;
                    plan.record.decision.reason =
                        "external-action cumulative blast-radius cap exceeded".into();
                }
            }
        }
        if plan.policy_decision != crate::sekai::action_policy::ActionDecision::Deny {
            let requested_units =
                i32::try_from(request.requested_invocation_count).unwrap_or(i32::MAX);
            if self
                .budget
                .check_and_reserve_idempotent(
                    &external_lifecycle::budget_scope(&request),
                    requested_units,
                    &format!("external-action-reserve:{authorization_id}"),
                )
                .is_ok()
            {
                plan.record.budget_reserved = true;
            } else {
                plan.policy_decision = crate::sekai::action_policy::ActionDecision::Deny;
                plan.record.decision.reason = "external-action budget exhausted".into();
                external_lifecycle::release_reservations(&self.db, &self.budget, &mut plan.record)
                    .map_err(Status::internal)?;
            }
        }
        let mut record = plan.finish();
        if let Err(error) = self.db.put_external_action_authorization(&record) {
            let _ = self
                .db
                .abandon_external_action_claim(&request, &request_digest);
            external_lifecycle::release_reservations(&self.db, &self.budget, &mut record)
                .map_err(Status::internal)?;
            return Err(Status::internal(error));
        }
        external_lifecycle::ensure_audit(&self.db, &record).map_err(Status::internal)?;
        let permit = (record.decision.decision == "permit")
            .then(|| {
                self.issue_external_permit(
                    &record,
                    &actor,
                    &record.request.idempotency_key,
                    offline,
                )
            })
            .transpose()?
            .map(|permit| external_permit_to_proto(&permit));
        Ok(AuthorizeExternalActionResponse {
            decision: Some(external_decision_to_proto(&record.decision)),
            permit,
        })
    }

    pub(super) fn transition_from_authenticated(
        &self,
        actor: String,
        input: TransitionExternalActionRequest,
    ) -> Result<TransitionExternalActionResponse, Status> {
        match input.transition.as_str() {
            "approve" | "deny" => {
                if !matches!(actor.as_str(), "root" | "local") {
                    return Err(Status::permission_denied(
                        "external-action approval requires control-plane administration",
                    ));
                }
                let mut record = self
                    .db
                    .get_external_action_authorization_by_id(&input.authorization_id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::not_found("external-action authorization not found"))?;
                let expected = record.clone();
                let now = chrono::Utc::now().timestamp_millis();
                let current_policy = self
                    .db
                    .resolve_action_policy(
                        &record.request.actor,
                        &record.request.namespace,
                        &record.request.policy_project,
                    )
                    .map_err(Status::internal)?;
                let access_revoked = require_namespace_write_access(
                    &self.db,
                    &record.request.actor,
                    &record.request.namespace,
                )
                .and_then(|_| {
                    require_external_project_access(
                        &self.db,
                        &record.request.actor,
                        &record.request.namespace,
                        &record.request.policy_project,
                    )
                })
                .is_err();
                external_lifecycle::approve_or_deny(
                    &mut record,
                    &input.transition,
                    &input.reason,
                    &actor,
                    now,
                    access_revoked,
                    current_policy.as_ref(),
                )
                .map_err(Status::failed_precondition)?;
                if !self
                    .db
                    .compare_and_swap_external_action_authorization(&expected, &record)
                    .map_err(Status::internal)?
                {
                    return Err(Status::aborted(
                        "external-action authorization changed concurrently",
                    ));
                }
                if record.decision.decision != "permit" {
                    let reserved = record.clone();
                    external_lifecycle::release_reservations(&self.db, &self.budget, &mut record)
                        .map_err(Status::internal)?;
                    external_lifecycle::persist_released_flags(&self.db, &reserved, &record)
                        .map_err(Status::internal)?;
                }
                external_lifecycle::ensure_audit(&self.db, &record).map_err(Status::internal)?;
                let permit = (record.decision.decision == "permit")
                    .then(|| {
                        self.issue_external_permit(
                            &record,
                            &record.request.actor,
                            &record.request.idempotency_key,
                            input.offline,
                        )
                    })
                    .transpose()?
                    .map(|permit| external_permit_to_proto(&permit));
                Ok(TransitionExternalActionResponse {
                    decision: Some(external_decision_to_proto(&record.decision)),
                    permit,
                    changed: true,
                })
            }
            "cancel" => {
                let mut record = self
                    .db
                    .get_external_action_authorization_by_id(&input.authorization_id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::not_found("external-action authorization not found"))?;
                if actor != record.request.actor && !matches!(actor.as_str(), "root" | "local") {
                    return Err(Status::permission_denied(
                        "external-action cancellation denied",
                    ));
                }
                let now = chrono::Utc::now().timestamp_millis();
                let changed = record.decision.cancelled_at_ms == 0;
                if changed {
                    let expected = record.clone();
                    external_lifecycle::cancel(&mut record, &actor, &input.reason, now);
                    if !self
                        .db
                        .compare_and_swap_external_action_authorization(&expected, &record)
                        .map_err(Status::internal)?
                    {
                        return Err(Status::aborted(
                            "external-action authorization changed concurrently",
                        ));
                    }
                }
                let reserved = record.clone();
                external_lifecycle::release_reservations(&self.db, &self.budget, &mut record)
                    .map_err(Status::internal)?;
                external_lifecycle::persist_released_flags(&self.db, &reserved, &record)
                    .map_err(Status::internal)?;
                external_lifecycle::ensure_audit(&self.db, &record).map_err(Status::internal)?;
                Ok(TransitionExternalActionResponse {
                    decision: Some(external_decision_to_proto(&record.decision)),
                    permit: None,
                    changed,
                })
            }
            "revoke" => {
                if !matches!(actor.as_str(), "root" | "local") {
                    return Err(Status::permission_denied(
                        "permit revocation requires control-plane administration",
                    ));
                }
                if input.revocation_handle.trim().is_empty() || input.reason.trim().is_empty() {
                    return Err(Status::invalid_argument(
                        "revocation_handle and reason required",
                    ));
                }
                let now = chrono::Utc::now().timestamp_millis();
                let changed = self
                    .db
                    .revoke_permit(&input.revocation_handle, &actor, &input.reason, now)
                    .map_err(Status::internal)?;
                Ok(TransitionExternalActionResponse {
                    decision: None,
                    permit: None,
                    changed,
                })
            }
            "delegate" => {
                let parent = external_permit_from_proto(
                    input
                        .parent
                        .ok_or_else(|| Status::invalid_argument("parent permit required"))?,
                );
                if actor != parent.subject_actor {
                    return Err(Status::permission_denied(
                        "delegation requires the current permit subject",
                    ));
                }
                require_namespace_write_access(&self.db, &actor, &parent.namespace)?;
                let key = permit_signing_key(&self.config)?;
                parent
                    .verify_trust(&self.config.permit_issuer, &self.config.permit_key_id)
                    .and_then(|_| parent.verify_signature(&key.verifying_key()))
                    .map_err(Status::failed_precondition)?;
                self.db
                    .validate_permit_for_delegation(&parent)
                    .and_then(|_| self.db.validate_delegation_chain(&parent))
                    .map_err(Status::failed_precondition)?;
                let policy = self
                    .db
                    .get_external_permit_policy(&parent.policy_scope)
                    .map_err(Status::internal)?;
                let child = permit::delegate(
                    &parent,
                    &policy,
                    &key,
                    permit::Delegation {
                        delegator: &actor,
                        subject_actor: &input.subject_actor,
                        permit_id: format!("permit-{}", uuid::Uuid::new_v4().simple()),
                        nonce: uuid::Uuid::new_v4().simple().to_string(),
                        now_ms: chrono::Utc::now().timestamp_millis(),
                        expires_at_ms: input.expires_at_ms,
                        target_selectors: input.target_selectors,
                        allowed_effects: input.allowed_effects,
                        budget_micros: input.budget_micros,
                        volume_limit: input.volume_limit,
                        blast_radius_limit: input.blast_radius_limit,
                        max_invocations: input.max_invocations,
                        risk_class: &input.risk_class,
                    },
                )
                .map_err(Status::failed_precondition)?;
                let child = self
                    .db
                    .put_delegated_permit(&child, &actor)
                    .map_err(Status::failed_precondition)?;
                Ok(TransitionExternalActionResponse {
                    decision: None,
                    permit: Some(external_permit_to_proto(&child)),
                    changed: true,
                })
            }
            _ => Err(Status::invalid_argument(
                "transition must be approve, deny, cancel, revoke, or delegate",
            )),
        }
    }
}
