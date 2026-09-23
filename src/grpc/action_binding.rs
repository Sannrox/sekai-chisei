//! Install and run object-change automation bindings (#1092, ADR 0090).

use super::*;
use crate::sekai::action_binding::ActionBinding;
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
};
use crate::sekai::object_change_subscription::{
    OUTCOME_DISCONNECTED, OUTCOME_PAGE, OUTCOME_RESNAPSHOT, ObjectChangeReadRequest,
    ObjectChangeScope, authorization_pin, read_object_change_subscription,
};

const BINDING_UNAVAILABLE: &str = "action binding unavailable";

impl SekaiServiceImpl {
    pub(super) async fn put_action_binding_definition(
        &self,
        req: Request<PutActionBindingRequest>,
    ) -> Result<Response<PutActionBindingResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let binding: ActionBinding = serde_json::from_str(&req.into_inner().binding_json)
            .map_err(|error| Status::invalid_argument(format!("binding_json: {error}")))?;
        binding.validate().map_err(Status::invalid_argument)?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &binding.namespace,
            true,
        )?;
        // Installing unattended writes is a namespace-administration act.
        let actor = authorize_source_type_namespace_admin(self, &principals, &binding.namespace)?;
        let type_def = self
            .db
            .runtime()
            .require_enabled_governed_action_type(
                &binding.namespace,
                &binding.type_id,
                &binding.version,
            )
            .map_err(|_| Status::failed_precondition("bound action type unavailable"))?;
        let schema = serde_json::from_str::<serde_json::Value>(&type_def.parameter_schema_json)
            .ok()
            .filter(|schema| {
                schema
                    .get("properties")
                    .is_some_and(|value| value.is_object())
            })
            .ok_or_else(|| {
                Status::failed_precondition("bound action type parameter schema unavailable")
            })?;
        let declared = schema["properties"]
            .as_object()
            .map(|properties| properties.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        if let Some(name) = binding
            .parameters
            .keys()
            .find(|name| !declared.contains(name))
        {
            return Err(Status::invalid_argument(format!(
                "parameter {name:?} is not declared by the bound action type"
            )));
        }
        // An unmapped required parameter would make every event fail schema
        // validation and be skipped for good, so refuse it at install (#1142).
        if let Some(name) = schema
            .get("required")
            .and_then(|required| required.as_array())
            .into_iter()
            .flatten()
            .filter_map(|name| name.as_str())
            .find(|name| !binding.parameters.contains_key(*name))
        {
            return Err(Status::invalid_argument(format!(
                "required parameter {name:?} of the bound action type is not mapped"
            )));
        }
        check_team_namespace(
            self.db.runtime(),
            std::slice::from_ref(&binding.run_as),
            &binding.namespace,
            true,
        )
        .map_err(|_| Status::failed_precondition("run_as lacks namespace write"))?;
        let stored = self
            .db
            .runtime()
            .put_action_binding(&binding, &actor, now_millis())
            .map_err(map_binding_store_error)?;
        Ok(Response::new(PutActionBindingResponse {
            binding_json: serde_json::to_string(&stored)
                .map_err(|error| Status::internal(error.to_string()))?,
            revision: stored.revision,
        }))
    }

    /// Reads the binding's own subscription as its service principal and
    /// submits one Action per bound event. Page events are persisted before
    /// any submit, so a crash mid-page finishes on the next run; event-derived
    /// idempotency keys make those resubmits replays.
    pub(super) async fn run_action_binding_once(
        &self,
        req: Request<RunActionBindingRequest>,
    ) -> Result<Response<RunActionBindingResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let input = req.into_inner();
        let (binding, mut cursor) = self
            .db
            .runtime()
            .get_action_binding(input.namespace.trim(), input.binding_id.trim())
            .map_err(map_binding_store_error)?
            .ok_or_else(|| Status::not_found(BINDING_UNAVAILABLE))?;
        enforce_namespace_tenant_context(
            self.db.runtime(),
            tenant_context.as_ref(),
            &binding.namespace,
            true,
        )?;
        let caller_runs_binding = principals
            .iter()
            .any(|principal| principal == &binding.run_as);
        if !caller_runs_binding
            && authorize_source_type_namespace_admin(self, &principals, &binding.namespace).is_err()
        {
            return Err(Status::permission_denied(BINDING_UNAVAILABLE));
        }
        if !binding.enabled {
            return Err(Status::failed_precondition("action binding is disabled"));
        }
        let run_as = vec![binding.run_as.clone()];
        // The service principal's grants decide both what it reads and what
        // it may submit, checked before any page is consumed.
        check_team_namespace(self.db.runtime(), &run_as, &binding.namespace, true)
            .map_err(|_| Status::failed_precondition("run_as lacks namespace write"))?;

        let scope = ObjectChangeScope {
            namespace: binding.namespace.clone(),
            kind: binding.kind.clone(),
            object_ids: Vec::new(),
            property_filters: binding.property_filters.clone(),
        };
        let (visible, _) = list_objects_with_marking(
            self.db.runtime(),
            &domain::ListFilter {
                kind: Some(scope.kind.clone()),
                name: None,
                namespace: Some(scope.namespace.clone()),
                property_filters: scope.property_filters.clone(),
                interface_filter: Vec::new(),
                limit: domain::MAX_LIST_LIMIT,
                offset: 0,
                order_by: "name".into(),
                descending: false,
            },
            &run_as,
            &crate::sekai::object_security::PrincipalPolicyContext::default(),
            None,
            None,
            |objects, _, _| Ok(objects),
        )?;

        let mut response = RunActionBindingResponse {
            outcome: OUTCOME_PAGE.into(),
            page_digest: cursor.last_page_digest.clone(),
            binding_revision: binding.revision,
            ..Default::default()
        };
        if cursor.pending_events.is_empty() {
            let activation_id = self
                .db
                .runtime()
                .get_object_security_activation(&scope.namespace)
                .map_err(|_| Status::unavailable("object authorization unavailable"))?
                .map(|activation| activation.activation_id)
                .unwrap_or_else(|| "legacy".into());
            let pin = authorization_pin(&activation_id, &run_as)
                .map_err(|_| Status::internal("object-change authorization pin unavailable"))?;
            let subscription_id = format!("action-binding.{}", binding.binding_id);
            let read = |snapshot_revision: &str| {
                read_object_change_subscription(
                    self.db.runtime(),
                    &binding.run_as,
                    &ObjectChangeReadRequest {
                        subscription_id: subscription_id.clone(),
                        scope: scope.clone(),
                        snapshot_revision: snapshot_revision.to_string(),
                        limit: input.limit,
                        retention_ms: 0,
                        last_page_digest: String::new(),
                        revoke: false,
                    },
                    now_millis(),
                    &visible,
                    &pin,
                )
                .map_err(|error| Status::failed_precondition(format!("subscription: {error}")))
            };
            let inspect = || {
                crate::sekai::event_subscription::inspect_event_subscription(
                    self.db.runtime(),
                    &binding.run_as,
                    &binding.namespace,
                    &subscription_id,
                )
                .ok()
            };
            // A marker with no pending events means an earlier run read a page
            // (committing the subscription cursor) but never persisted its
            // events. Put the subscription back so the page is delivered again.
            if let Some(marker) = cursor.read_marker.take()
                && let Some(current) = inspect()
                && current != marker
            {
                self.db
                    .runtime()
                    .advance_event_subscription_cursor(&marker, &current)
                    .map_err(|error| {
                        Status::failed_precondition(format!("subscription: {error}"))
                    })?;
            }
            cursor.read_marker = inspect();
            self.db
                .runtime()
                .advance_action_binding_cursor(&binding, &cursor, now_millis())
                .map_err(map_binding_store_error)?;
            let mut page = read(&cursor.snapshot_revision)?;
            if page.outcome == OUTCOME_RESNAPSHOT {
                // No backfill: the binding acts on changes after its pin.
                let first_pin = cursor.snapshot_revision.is_empty();
                cursor.snapshot_revision = page.snapshot_revision.clone();
                if first_pin {
                    page = read(&cursor.snapshot_revision)?;
                }
            }
            response.outcome = page.outcome.clone();
            response.disconnect_reason = page.disconnect_reason.clone();
            response.page_digest = page.page_digest.clone();
            if page.outcome == OUTCOME_DISCONNECTED {
                cursor.snapshot_revision.clear();
            }
            if page.outcome == OUTCOME_PAGE {
                cursor.last_page_digest = page.page_digest.clone();
                cursor.pending_events = page.events;
            }
            // Cleared in the same write that persists the page's events.
            cursor.read_marker = None;
            self.db
                .runtime()
                .advance_action_binding_cursor(&binding, &cursor, now_millis())
                .map_err(map_binding_store_error)?;
        }

        for event in std::mem::take(&mut cursor.pending_events) {
            response
                .submissions
                .push(self.submit_bound_event(&binding, &event, &visible));
        }
        self.db
            .runtime()
            .advance_action_binding_cursor(&binding, &cursor, now_millis())
            .map_err(map_binding_store_error)?;
        Ok(Response::new(response))
    }

    fn submit_bound_event(
        &self,
        binding: &ActionBinding,
        event: &crate::sekai::object_change_subscription::ObjectChangeEvent,
        visible: &[domain::Object],
    ) -> ActionBindingSubmission {
        let mut submission = ActionBindingSubmission {
            event_id: event.event_id.clone(),
            object_id: event.object_id.clone(),
            op: event.op.clone(),
            ..Default::default()
        };
        if !binding.ops.contains(&event.op) {
            submission.skipped_reason = "op_not_bound".into();
            return submission;
        }
        let object = visible.iter().find(|object| object.id == event.object_id);
        let parameters_json = match binding.parameters_for(event, object) {
            Ok(parameters) => parameters,
            Err(reason) => {
                submission.skipped_reason = reason.into();
                return submission;
            }
        };
        let idempotency_key = match binding.idempotency_key(event) {
            Ok(key) => key,
            Err(error) => {
                submission.skipped_reason = format!("internal: {error}");
                return submission;
            }
        };
        let request = ActionInstanceAdmissionRequest {
            namespace: binding.namespace.clone(),
            type_id: binding.type_id.clone(),
            version: binding.version.clone(),
            parameters_json,
            request_id: format!("op-{idempotency_key}"),
            idempotency_key,
            evidence_submission_ids: Vec::new(),
            ontology_digest: String::new(),
            autonomous_envelope_id: String::new(),
            policy_context: crate::sekai::object_security::PrincipalPolicyContext::default(),
            budget_already_reserved: false,
        };
        let result = if let Some(clerk) = &self.cross_store {
            clerk.admit(request, &binding.run_as, now_millis())
        } else {
            ActionInstanceAdmission::new(self.db.runtime(), None).admit(
                request,
                &binding.run_as,
                now_millis(),
            )
        };
        match result {
            Ok(outcome) => {
                submission.instance_id = outcome.instance.instance_id;
                submission.status = outcome.instance.status;
                submission.replay = outcome.replay;
            }
            Err(error) => {
                submission.skipped_reason = match error {
                    ActionInstanceAdmissionError::InvalidArgument(message) => {
                        format!("invalid_argument: {message}")
                    }
                    ActionInstanceAdmissionError::FailedPrecondition(message) => {
                        format!("failed_precondition: {message}")
                    }
                    ActionInstanceAdmissionError::AlreadyExists(message) => {
                        format!("already_exists: {message}")
                    }
                    ActionInstanceAdmissionError::PermissionDenied(_) => "access_denied".into(),
                    ActionInstanceAdmissionError::Internal(_) => "internal".into(),
                };
            }
        }
        submission
    }
}

fn map_binding_store_error(error: String) -> Status {
    if error == crate::db::runtime_db::ACTION_BINDINGS_UNAVAILABLE {
        Status::unavailable(error)
    } else if error.contains("must") || error.contains("unsupported") || error.contains("invalid") {
        Status::invalid_argument(error)
    } else {
        Status::internal(error)
    }
}
