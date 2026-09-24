//! Install and run object-change automation bindings (#1092, ADR 0090).

use super::*;
use crate::sekai::action_binding::{ActionBinding, ParameterSource, ReadMarker};
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
};
use crate::sekai::object_change_subscription::{
    OP_DELETE, OUTCOME_DISCONNECTED, OUTCOME_PAGE, OUTCOME_RESNAPSHOT, ObjectChangeReadRequest,
    ObjectChangeScope, authorization_pin, read_object_change_subscription_with_resolved_objects,
};
use std::collections::{HashMap, HashSet};

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
        let mut event_property_keys = binding
            .property_filters
            .iter()
            .map(|filter| filter.key.clone())
            .collect::<HashSet<_>>();
        event_property_keys.extend(
            binding
                .parameters
                .values()
                .filter_map(|source| match source {
                    ParameterSource::Property(property) => Some(property.clone()),
                    _ => None,
                }),
        );
        let mut visible_objects = Vec::new();
        let mut objects_resolved = false;

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
            let read = |snapshot_revision: &str,
                        visible_objects: &mut Vec<domain::Object>,
                        objects_resolved: &mut bool|
             -> Result<_, Status> {
                *objects_resolved = false;
                let mut resolver_error = None;
                let result = read_object_change_subscription_with_resolved_objects(
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
                    visible_objects,
                    |object_ids| {
                        *objects_resolved = true;
                        load_action_binding_objects(
                            self,
                            &binding,
                            object_ids,
                            &run_as,
                            &event_property_keys,
                        )
                        .map_err(|status| {
                            resolver_error = Some(status);
                            "action binding event objects unavailable".to_string()
                        })
                    },
                    &pin,
                );
                if let Some(status) = resolver_error {
                    return Err(status);
                }
                result
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
            // An `Absent` marker means the read created the subscription; rewind
            // it to its pin, where an empty cursor restarts delivery (#1141).
            let restore = match (cursor.read_marker.take(), inspect()) {
                (Some(ReadMarker::Subscription(marker)), Some(current)) if current != *marker => {
                    Some((*marker, current))
                }
                (Some(ReadMarker::Absent), Some(current))
                    if current.cursor.committed_offset > 0
                        || !current.cursor.last_page_digest.is_empty() =>
                {
                    let mut pinned = current.clone();
                    pinned.cursor.committed_offset = 0;
                    pinned.cursor.last_page_digest.clear();
                    Some((pinned, current))
                }
                _ => None,
            };
            if let Some((restored, current)) = restore {
                self.db
                    .runtime()
                    .advance_event_subscription_cursor(&restored, &current)
                    .map_err(|error| {
                        Status::failed_precondition(format!("subscription: {error}"))
                    })?;
            }
            cursor.read_marker = Some(match inspect() {
                Some(subscription) => ReadMarker::Subscription(Box::new(subscription)),
                None => ReadMarker::Absent,
            });
            self.db
                .runtime()
                .advance_action_binding_cursor(&binding, &cursor, now_millis())
                .map_err(map_binding_store_error)?;
            let mut page = read(
                &cursor.snapshot_revision,
                &mut visible_objects,
                &mut objects_resolved,
            )?;
            if page.outcome == OUTCOME_RESNAPSHOT {
                // No backfill: the binding acts on changes after its pin.
                let first_pin = cursor.snapshot_revision.is_empty();
                cursor.snapshot_revision = page.snapshot_revision.clone();
                if first_pin {
                    // Durable before the read creates the subscription, so a
                    // crash rewinds to this pin instead of re-pinning past the
                    // page's events (#1141).
                    self.db
                        .runtime()
                        .advance_action_binding_cursor(&binding, &cursor, now_millis())
                        .map_err(map_binding_store_error)?;
                    page = read(
                        &cursor.snapshot_revision,
                        &mut visible_objects,
                        &mut objects_resolved,
                    )?;
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

        if !objects_resolved && !cursor.pending_events.is_empty() {
            let pending_ids = cursor
                .pending_events
                .iter()
                .filter(|event| event.op != OP_DELETE)
                .map(|event| event.object_id.clone())
                .collect::<Vec<_>>();
            visible_objects = load_action_binding_objects(
                self,
                &binding,
                &pending_ids,
                &run_as,
                &event_property_keys,
            )?;
        }

        let visible_by_id = visible_objects
            .into_iter()
            .map(|object| (object.id.clone(), object))
            .collect::<HashMap<_, _>>();

        for event in std::mem::take(&mut cursor.pending_events) {
            response.submissions.push(self.submit_bound_event(
                &binding,
                &event,
                visible_by_id.get(&event.object_id),
            ));
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
        object: Option<&domain::Object>,
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

fn load_action_binding_objects(
    service: &SekaiServiceImpl,
    binding: &ActionBinding,
    object_ids: &[String],
    principals: &[String],
    property_keys: &HashSet<String>,
) -> Result<Vec<domain::Object>, Status> {
    let principal_refs = principals.iter().map(String::as_str).collect::<Vec<_>>();
    let context = crate::sekai::object_security::PrincipalPolicyContext::default();
    let objects = service
        .db
        .runtime()
        .list_objects_by_ids_with_policy_context(object_ids, &principal_refs, &context)
        .map_err(Status::internal)?;
    Ok(objects
        .into_iter()
        .filter_map(|mut object| {
            if object.namespace != binding.namespace
                || object.kind != binding.kind
                || RESERVED_GOVERNANCE_KINDS.contains(&object.kind.as_str())
                || !object_passes_marking(service.db.runtime(), &object, principals)
                    .unwrap_or(false)
            {
                return None;
            }
            object
                .properties
                .retain(|key, _| property_keys.contains(key));
            Some(object)
        })
        .collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::action_binding::{
        ACTION_BINDING_CONTRACT, ActionBindingCursor, ParameterSource,
    };
    use crate::sekai::object_change_subscription::read_object_change_subscription;
    use std::collections::{BTreeMap, HashMap};
    use tonic::metadata::MetadataValue;

    fn local<T>(payload: T) -> Request<T> {
        let mut request = Request::new(payload);
        request
            .metadata_mut()
            .insert("x-principal", MetadataValue::from_static("local"));
        request
    }

    #[tokio::test]
    async fn a_crash_after_the_first_pinned_read_redelivers_the_page() {
        // #1141: the first pin creates the subscription inside the read, so
        // the marker records its absence; a run that finds the page read but
        // unpersisted rewinds the new subscription to its pin.
        let db = Arc::new(RuntimeDb::memory());
        let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
            db.clone(),
        ));
        let (_, grants) = db
            .ensure_team_namespace("demo", "svc-escalator", security::Role::Editor, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }
        db.put_governed_action_type(
            crate::sekai::governed_action_type::GovernedActionType {
                namespace: "demo".into(),
                type_id: "component.escalate".into(),
                version: "1".into(),
                description: "Escalate a degraded component".into(),
                parameter_schema_json: r#"{"type":"object","properties":{"component":{"type":"string"},"severity":{"type":"string"}},"required":["component","severity"],"additionalProperties":false}"#.into(),
                allowed_effect_kinds: vec!["notify".into()],
                enabled: true,
                ..Default::default()
            },
            "local",
            1,
        )
        .unwrap();
        db.upsert_action_policy(&crate::sekai::action_policy::ActionPolicy::allow_all(
            "demo",
        ))
        .unwrap();
        let mut object = domain::Object {
            id: "billing-api".into(),
            kind: "component".into(),
            name: "billing-api".into(),
            namespace: "demo".into(),
            external_id: String::new(),
            properties: HashMap::from([("severity".into(), "low".into())]),
            created: 1,
            updated: 1,
        };
        db.create_object_with_audit(&object, "local").unwrap();
        let binding = db
            .put_action_binding(
                &ActionBinding {
                    contract_version: ACTION_BINDING_CONTRACT.into(),
                    binding_id: "escalate".into(),
                    namespace: "demo".into(),
                    kind: "component".into(),
                    property_filters: Vec::new(),
                    ops: vec!["update".into()],
                    type_id: "component.escalate".into(),
                    version: "1".into(),
                    run_as: "svc-escalator".into(),
                    parameters: BTreeMap::from([
                        ("component".into(), ParameterSource::ObjectId),
                        (
                            "severity".into(),
                            ParameterSource::Property("severity".into()),
                        ),
                    ]),
                    enabled: true,
                    revision: 0,
                    created_by: String::new(),
                    updated_at_ms: 0,
                },
                "local",
                2,
            )
            .unwrap();

        // The crashed run: it pinned (durably, with the marker), a change
        // landed, and its read created the subscription and committed the
        // page before the events were persisted.
        let run_as = vec!["svc-escalator".to_string()];
        let pin = authorization_pin("legacy", &run_as).unwrap();
        let request = |snapshot_revision: &str| ObjectChangeReadRequest {
            subscription_id: "action-binding.escalate".into(),
            scope: ObjectChangeScope {
                namespace: "demo".into(),
                kind: "component".into(),
                object_ids: Vec::new(),
                property_filters: Vec::new(),
            },
            snapshot_revision: snapshot_revision.into(),
            limit: 16,
            retention_ms: 0,
            last_page_digest: String::new(),
            revoke: false,
        };
        let now = now_millis();
        let pinned =
            read_object_change_subscription(&db, "svc-escalator", &request(""), now, &[], &pin)
                .unwrap();
        assert_eq!(pinned.outcome, OUTCOME_RESNAPSHOT);
        db.advance_action_binding_cursor(
            &binding,
            &ActionBindingCursor {
                snapshot_revision: pinned.snapshot_revision.clone(),
                read_marker: Some(ReadMarker::Absent),
                ..Default::default()
            },
            now,
        )
        .unwrap();
        object.properties.insert("severity".into(), "high".into());
        object.updated = 3;
        db.update_object_with_audit(&object, "local").unwrap();
        let lost = read_object_change_subscription(
            &db,
            "svc-escalator",
            &request(&pinned.snapshot_revision),
            now_millis(),
            std::slice::from_ref(&object),
            &pin,
        )
        .unwrap();
        assert_eq!(lost.outcome, OUTCOME_PAGE);
        assert_eq!(lost.events.len(), 1);

        let run = svc
            .run_action_binding(local(RunActionBindingRequest {
                namespace: "demo".into(),
                binding_id: "escalate".into(),
                limit: 16,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(run.submissions.len(), 1);
        assert!(
            db.get_action_binding("demo", "escalate")
                .unwrap()
                .unwrap()
                .1
                .read_marker
                .is_none()
        );
    }
}
