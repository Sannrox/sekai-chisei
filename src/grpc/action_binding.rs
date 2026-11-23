//! Install and run object-change automation bindings (#1092, ADR 0090), and
//! submit scheduled bindings from the plane's schedule tick (#3033).

use super::*;
use crate::sekai::action_binding::{
    ActionBinding, DATASET_COMMIT_PINNED, OP_DATASET_COMMIT, ParameterSource, ReadMarker,
};
use crate::sekai::action_instance_admission::{
    ActionInstanceAdmission, ActionInstanceAdmissionError, ActionInstanceAdmissionRequest,
};
use crate::sekai::object_change_subscription::{
    OP_DELETE, OUTCOME_DISCONNECTED, OUTCOME_PAGE, OUTCOME_RESNAPSHOT, ObjectChangeReadRequest,
    ObjectChangeScope, authorization_pin, page_limit,
    read_object_change_subscription_with_resolved_objects,
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
        self.check_bound_action(
            &binding.namespace,
            &binding.type_id,
            &binding.version,
            &binding.run_as,
            &binding.parameters.keys().cloned().collect::<Vec<_>>(),
        )?;
        self.check_binding_markings(&binding.namespace, &binding.markings)?;
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

    /// Checks what a binding install pins: the bound type and version exist
    /// and are enabled, every mapped parameter is declared, every required
    /// one is mapped, and `run_as` holds namespace write.
    pub(super) fn check_bound_action(
        &self,
        namespace: &str,
        type_id: &str,
        version: &str,
        run_as: &str,
        mapped: &[String],
    ) -> Result<(), Status> {
        let type_def = self
            .db
            .runtime()
            .require_enabled_governed_action_type(namespace, type_id, version)
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
        if let Some(name) = mapped.iter().find(|name| !declared.contains(name)) {
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
            .find(|name| !mapped.iter().any(|mapped| mapped == name))
        {
            return Err(Status::invalid_argument(format!(
                "required parameter {name:?} of the bound action type is not mapped"
            )));
        }
        check_team_namespace(self.db.runtime(), &[run_as.to_string()], namespace, true)
            .map_err(|_| Status::failed_precondition("run_as lacks namespace write"))?;
        Ok(())
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
        if binding.schedule.is_some() {
            return Err(Status::failed_precondition(
                "a scheduled action binding runs on the plane schedule tick",
            ));
        }
        let run_as = vec![binding.run_as.clone()];
        let (tenant, resource_tenant) = self.prepare_bound_run(
            tenant_context.as_ref(),
            &binding.namespace,
            &binding.run_as,
            &binding.type_id,
        )?;
        if binding.dataset_commit.is_some() {
            return self
                .run_dataset_commit_binding(
                    &binding,
                    &cursor,
                    input.limit,
                    &tenant,
                    &resource_tenant,
                )
                .map(Response::new);
        }

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
                        load_bound_objects(
                            self,
                            &binding.namespace,
                            &binding.kind,
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
            visible_objects = load_bound_objects(
                self,
                &binding.namespace,
                &binding.kind,
                &pending_ids,
                &run_as,
                &event_property_keys,
            )?;
        }

        let visible_by_id = visible_objects
            .into_iter()
            .map(|object| (object.id.clone(), object))
            .collect::<HashMap<_, _>>();

        for event in &cursor.pending_events {
            let submission = self.submit_bound_event(
                &binding,
                event,
                visible_by_id.get(&event.object_id),
                &tenant,
                &resource_tenant,
            );
            if let Some(reason) = submission
                .skipped_reason
                .strip_prefix("failed_precondition: ")
                .filter(|reason| reason.contains("write freeze"))
            {
                return Err(Status::failed_precondition(reason.to_string()));
            }
            // Store and other internal admission failures are retryable; keep
            // the page so the next run replays it.
            if is_internal_skip(&submission.skipped_reason) {
                return Err(Status::internal(submission.skipped_reason.clone()));
            }
            response.submissions.push(submission);
        }
        cursor.pending_events.clear();
        self.db
            .runtime()
            .advance_action_binding_cursor(&binding, &cursor, now_millis())
            .map_err(map_binding_store_error)?;
        Ok(Response::new(response))
    }

    /// Submits one Action per dataset version committed since the last run
    /// (#3034). The first run records every scoped dataset's latest version
    /// and submits nothing (no backfill). Each dataset's cursor moves only
    /// after its versions were admitted, so a crash in between replays them
    /// under the same keys. A dataset `run_as` cannot read is skipped and
    /// never named, and its cursor moves past what it hid.
    fn run_dataset_commit_binding(
        &self,
        binding: &ActionBinding,
        cursor: &crate::sekai::action_binding::ActionBindingCursor,
        limit: i32,
        tenant: &str,
        resource_tenant: &str,
    ) -> Result<RunActionBindingResponse, Status> {
        let db = self.db.runtime();
        let run_as = [binding.run_as.clone()];
        let mut response = RunActionBindingResponse {
            outcome: OUTCOME_PAGE.into(),
            binding_revision: binding.revision,
            ..Default::default()
        };
        let pinned = cursor.snapshot_revision == DATASET_COMMIT_PINNED;
        let cursors = db
            .action_binding_dataset_cursors(binding)
            .map_err(map_binding_store_error)?;
        let limit = page_limit(limit);
        for (dataset, object) in self.dataset_commit_scope(binding)? {
            let mut versions = db
                .list_dataset_versions(&dataset.id)
                .map_err(Status::internal)?;
            versions.sort_by_key(|version| version.seq);
            let after = cursors.get(&dataset.id).copied().unwrap_or(0);
            let latest = versions
                .last()
                .map_or(after, |version| version.seq.max(after));
            let readable =
                dataset_binding_after_access(db, &self.security, &run_as, &dataset, false).is_ok()
                    && object_passes_marking(db, &object, &run_as).unwrap_or(false);
            if !pinned || !readable {
                if latest > after {
                    db.advance_action_binding_dataset_cursor(binding, &dataset.id, latest)
                        .map_err(map_binding_store_error)?;
                }
                continue;
            }
            let markings = snapshot_markings(&binding.markings, Some(&object));
            let mut delivered = after;
            for version in versions.iter().filter(|version| version.seq > after) {
                if response.submissions.len() >= limit {
                    break;
                }
                delivered = version.seq;
                if version.purged {
                    continue;
                }
                let mut submission = ActionBindingSubmission {
                    object_id: object.id.clone(),
                    op: OP_DATASET_COMMIT.into(),
                    dataset_id: dataset.id.clone(),
                    version_id: version.version_id.clone(),
                    ..Default::default()
                };
                let outcome = binding
                    .dataset_idempotency_key(&dataset.id, &version.version_id)
                    .map_err(|error| format!("internal: {error}"))
                    .and_then(|idempotency_key| {
                        self.admit_bound_action(
                            BoundAction {
                                namespace: &binding.namespace,
                                markings: &markings,
                                source_object_id: &object.id,
                                type_id: &binding.type_id,
                                version: &binding.version,
                                run_as: &binding.run_as,
                                parameters_json: binding
                                    .dataset_parameters(&dataset.id, &version.version_id),
                                idempotency_key,
                            },
                            tenant,
                            resource_tenant,
                        )
                    });
                match outcome {
                    Ok((instance_id, status, replay)) => {
                        submission.instance_id = instance_id;
                        submission.status = status;
                        submission.replay = replay;
                    }
                    Err(reason) => {
                        if let Some(reason) = reason
                            .strip_prefix("failed_precondition: ")
                            .filter(|reason| reason.contains("write freeze"))
                        {
                            return Err(Status::failed_precondition(reason.to_string()));
                        }
                        // Retryable: the cursor stays before this version.
                        if is_internal_skip(&reason) {
                            return Err(Status::internal(reason));
                        }
                        submission.skipped_reason = reason;
                    }
                }
                response.submissions.push(submission);
            }
            if delivered > after {
                db.advance_action_binding_dataset_cursor(binding, &dataset.id, delivered)
                    .map_err(map_binding_store_error)?;
            }
        }
        if !pinned {
            let pin = crate::sekai::action_binding::ActionBindingCursor {
                snapshot_revision: DATASET_COMMIT_PINNED.into(),
                ..Default::default()
            };
            db.advance_action_binding_cursor(binding, &pin, now_millis())
                .map_err(map_binding_store_error)?;
        }
        Ok(response)
    }

    /// The datasets a dataset-commit binding watches, with their binding
    /// objects: those bound to an object in the binding's namespace,
    /// narrowed to `dataset_id` when it names one.
    fn dataset_commit_scope(
        &self,
        binding: &ActionBinding,
    ) -> Result<Vec<(dataset::Dataset, domain::Object)>, Status> {
        let trigger = binding
            .dataset_commit
            .as_ref()
            .map_or("", |trigger| trigger.dataset_id.as_str());
        let db = self.db.runtime();
        let mut scoped = Vec::new();
        for dataset in db.list_datasets().map_err(Status::internal)? {
            if dataset.object_id.is_empty() || (!trigger.is_empty() && dataset.id != trigger) {
                continue;
            }
            let Some(object) = db
                .get_object(&dataset.object_id)
                .map_err(Status::internal)?
            else {
                continue;
            };
            if object.namespace == binding.namespace {
                scoped.push((dataset, object));
            }
        }
        Ok(scoped)
    }

    /// Submits the current bucket of every enabled scheduled binding as its
    /// service principal, through normal admission (#3033). The bucket's
    /// idempotency key is the only fence: planes ticking at once, and a tick
    /// rerun after a crash, replay one instance, and nothing is recorded
    /// after the submit. A binding refused by grants, a write freeze, or
    /// admission is logged and retried on the next tick; the others still
    /// run. Fails with the first internal failure after every binding was
    /// tried.
    pub(crate) fn tick_scheduled_action_bindings(&self, now_ms: i64) -> Result<(), String> {
        let mut internal = None;
        for binding in self.db.runtime().list_scheduled_action_bindings()? {
            let Some(schedule) = binding.schedule else {
                continue;
            };
            let due_at_ms = binding.due_at_ms(schedule, now_ms);
            let outcome = self
                .prepare_bound_run(None, &binding.namespace, &binding.run_as, &binding.type_id)
                .map_err(|status| status.message().to_string())
                .and_then(|(tenant, resource_tenant)| {
                    self.admit_bound_action(
                        BoundAction {
                            namespace: &binding.namespace,
                            markings: &binding.markings,
                            source_object_id: "",
                            type_id: &binding.type_id,
                            version: &binding.version,
                            run_as: &binding.run_as,
                            parameters_json: binding.tick_parameters(),
                            idempotency_key: binding.tick_idempotency_key(due_at_ms)?,
                        },
                        &tenant,
                        &resource_tenant,
                    )
                });
            if let Err(reason) = outcome {
                tracing::warn!(
                    namespace = %binding.namespace,
                    binding_id = %binding.binding_id,
                    due_at_ms,
                    reason = %reason,
                    "scheduled action binding did not submit"
                );
                if is_internal_skip(&reason) {
                    internal.get_or_insert(reason);
                }
            }
        }
        internal.map_or(Ok(()), Err)
    }

    /// A binding's markings must be known to the namespace lattice and
    /// comparable, so every Action it submits can carry their join (#1706).
    pub(super) fn check_binding_markings(
        &self,
        namespace: &str,
        markings: &[String],
    ) -> Result<(), Status> {
        const MAX_BINDING_MARKINGS: usize = 16;
        if markings.is_empty() {
            return Ok(());
        }
        if markings.len() > MAX_BINDING_MARKINGS {
            return Err(Status::invalid_argument(format!(
                "at most {MAX_BINDING_MARKINGS} binding markings are allowed"
            )));
        }
        let lattice = self
            .db
            .runtime()
            .get_classification_lattice(namespace)
            .map_err(|_| Status::unavailable("classification lattice unavailable"))?;
        crate::sekai::classification_lattice::union_input_marking_tokens(
            lattice.as_ref(),
            markings.iter().map(|token| Some(token.as_str())),
        )
        .map_err(|error| Status::invalid_argument(format!("binding markings: {error}")))?;
        Ok(())
    }

    /// Checks a binding's service principal before any event is read: its
    /// grants decide both what it reads and what it may submit, and a write
    /// freeze on its tenant or the resource tenant stops the run. Returns
    /// the acting tenant and the shared-space resource tenant.
    /// The clearance gate a bound run submits under: its service
    /// principal must be cleared for the marking an instance carries.
    pub(crate) fn bound_marking_gate(
        &self,
        run_as: &str,
        namespace: &str,
    ) -> crate::sekai::action_instance_admission::MarkingGate {
        super::rpc_actions::submitter_marking_gate(self, &[run_as.to_string()], namespace)
    }

    pub(crate) fn prepare_bound_run(
        &self,
        tenant_context: Option<&RequestEnterpriseContext>,
        namespace: &str,
        run_as: &str,
        type_id: &str,
    ) -> Result<(String, String), Status> {
        check_team_namespace(self.db.runtime(), &[run_as.to_string()], namespace, true)
            .map_err(|_| Status::failed_precondition("run_as lacks namespace write"))?;
        let tenant = crate::sekai::write_freeze::acting_or_registered_tenant(
            self.db.runtime(),
            acting_tenant(tenant_context),
            run_as,
        )
        .map_err(Status::internal)?
        .into_owned();
        let resource_tenant = shared_space_resource_tenant(
            self.db.runtime(),
            tenant_context,
            namespace,
            crate::enterprise::NamespaceAction::Write,
        )
        .unwrap_or_default();
        let mut freeze_checks = crate::sekai::write_freeze::write_checks_for_actors(
            namespace,
            &tenant,
            run_as,
            None,
            type_id.trim(),
            true,
        );
        if !resource_tenant.is_empty() && resource_tenant != tenant {
            freeze_checks.extend(crate::sekai::write_freeze::write_checks_for_actors(
                namespace,
                &resource_tenant,
                run_as,
                None,
                type_id.trim(),
                true,
            ));
        }
        crate::sekai::write_freeze::refuse_if_frozen_any(self.db.runtime(), &freeze_checks)
            .map_err(crate::grpc::write_freeze_status)?;
        Ok((tenant, resource_tenant))
    }

    fn submit_bound_event(
        &self,
        binding: &ActionBinding,
        event: &crate::sekai::object_change_subscription::ObjectChangeEvent,
        object: Option<&domain::Object>,
        tenant: &str,
        resource_tenant: &str,
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
        let markings = snapshot_markings(&binding.markings, object);
        match self.admit_bound_action(
            BoundAction {
                namespace: &binding.namespace,
                markings: &markings,
                source_object_id: &event.object_id,
                type_id: &binding.type_id,
                version: &binding.version,
                run_as: &binding.run_as,
                parameters_json,
                idempotency_key,
            },
            tenant,
            resource_tenant,
        ) {
            Ok((instance_id, status, replay)) => {
                submission.instance_id = instance_id;
                submission.status = status;
                submission.replay = replay;
            }
            Err(reason) => submission.skipped_reason = reason,
        }
        submission
    }

    /// Submits one bound Action as its service principal through normal
    /// admission, so ACL, policy, budget, schema and approval apply to every
    /// event. Returns the instance id, its status and whether the submit
    /// replayed, or a bounded reason it was refused.
    pub(super) fn admit_bound_action(
        &self,
        action: BoundAction<'_>,
        tenant: &str,
        resource_tenant: &str,
    ) -> Result<(String, String, bool), String> {
        let request = ActionInstanceAdmissionRequest {
            agent_turn: None,
            namespace: action.namespace.to_string(),
            type_id: action.type_id.to_string(),
            version: action.version.to_string(),
            parameters_json: action.parameters_json,
            request_id: format!("op-{}", action.idempotency_key),
            idempotency_key: action.idempotency_key,
            evidence_submission_ids: Vec::new(),
            ontology_digest: String::new(),
            autonomous_envelope_id: String::new(),
            policy_context: crate::sekai::object_security::PrincipalPolicyContext::default(),
            delegating_actor: None,
            budget_already_reserved: false,
            resource_tenant: resource_tenant.to_string(),
            binding_markings: action.markings.to_vec(),
            source_object_id: action.source_object_id.to_string(),
            // The service principal must be cleared for what the instance
            // carries (#1706), as any submitter is.
            marking_gate: super::rpc_actions::submitter_marking_gate(
                self,
                &[action.run_as.to_string()],
                action.namespace,
            ),
            expected_object_revision: String::new(),
            offline: None,
        };
        let result = if let Some(clerk) = &self.cross_store {
            clerk.admit(request, action.run_as, now_millis(), tenant, true)
        } else {
            ActionInstanceAdmission::new(self.db.runtime(), None)
                .with_proposal(Some(&crate::chisei::system_one_action::SystemOneProposal))
                .with_tenant(tenant)
                .with_machine_credential(true)
                .admit(request, action.run_as, now_millis())
        };
        match result {
            Ok(outcome) => Ok((
                outcome.instance.instance_id,
                outcome.instance.status,
                outcome.replay,
            )),
            Err(error) => Err(match error {
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
            }),
        }
    }
}

/// The binding's markings and the marking of the object snapshot its
/// parameters were read from (#1706), so the instance is never marked below
/// the values it carries even if the object is declassified meanwhile.
pub(super) fn snapshot_markings(
    binding: &[String],
    snapshot: Option<&domain::Object>,
) -> Vec<String> {
    let mut markings = binding.to_vec();
    if let Some(token) = snapshot.and_then(crate::sekai::markings::object_marking_token) {
        markings.push(token.to_string());
    }
    markings
}

/// One Action a binding submits for one event.
pub(super) struct BoundAction<'a> {
    pub namespace: &'a str,
    /// The binding's markings, joined into the instance's at admission.
    pub markings: &'a [String],
    /// The object the event concerns; admission reads its marking.
    pub source_object_id: &'a str,
    pub type_id: &'a str,
    pub version: &'a str,
    pub run_as: &'a str,
    pub parameters_json: String,
    pub idempotency_key: String,
}

/// The objects of `kind` in `namespace` among `object_ids` that `principals`
/// may read, with only `property_keys` kept and marked ones dropped.
/// Properties the active object policy does not grant, and restricted ones
/// `principals` may not read, are removed rather than redacted, so a mapping
/// that needs one skips its event instead of submitting a placeholder.
pub(super) fn load_bound_objects(
    service: &SekaiServiceImpl,
    namespace: &str,
    kind: &str,
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
    let schema = service
        .schema_definitions
        .snapshot()
        .map_err(map_schema_definition_lifecycle_error)?;
    let restricted = restricted_property_names_for_kind(&schema, kind);
    let mut visible = Vec::with_capacity(objects.len());
    for object in objects {
        if object.namespace != namespace
            || object.kind != kind
            || RESERVED_GOVERNANCE_KINDS.contains(&object.kind.as_str())
            || !object_passes_marking(service.db.runtime(), &object, principals).unwrap_or(false)
        {
            continue;
        }
        // Taken before projection, which may hide it from `principals`.
        let snapshot_marking =
            crate::sekai::markings::object_marking_token(&object).map(str::to_string);
        let mut object = service
            .db
            .runtime()
            .project_object_property_grants(object)
            .map_err(|error| {
                if error.starts_with("object_security_denied") {
                    Status::permission_denied("access denied")
                } else {
                    Status::unavailable("object authorization unavailable")
                }
            })?;
        let reads_restricted =
            can_read_restricted_properties(&service.security, &object, principals);
        object.properties.retain(|key, _| {
            property_keys.contains(key) && (reads_restricted || !restricted.contains(key))
        });
        // The marking stays with the snapshot, so an Action built from it
        // carries it (#1706). Bindings cannot map it, so it never reaches
        // parameters.
        if let Some(marking) = snapshot_marking {
            object.properties.insert(
                crate::sekai::markings::OBJECT_CLASSIFICATION_PROPERTY.to_string(),
                marking,
            );
        }
        visible.push(object);
    }
    Ok(visible)
}

fn is_internal_skip(reason: &str) -> bool {
    reason == "internal" || reason.starts_with("internal:")
}

fn map_binding_store_error(error: String) -> Status {
    if error.contains("must") || error.contains("unsupported") || error.contains("invalid") {
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
                    schedule: None,
                    dataset_commit: None,
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
                    markings: Vec::new(),
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

    #[tokio::test]
    async fn write_freeze_refuses_binding_run_before_consuming_pending_events() {
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
        let binding = db
            .put_action_binding(
                &ActionBinding {
                    contract_version: ACTION_BINDING_CONTRACT.into(),
                    binding_id: "escalate".into(),
                    namespace: "demo".into(),
                    kind: "component".into(),
                    property_filters: Vec::new(),
                    ops: vec!["update".into()],
                    schedule: None,
                    dataset_commit: None,
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
                    markings: Vec::new(),
                    enabled: true,
                    revision: 0,
                    created_by: String::new(),
                    updated_at_ms: 0,
                },
                "local",
                2,
            )
            .unwrap();
        db.advance_action_binding_cursor(
            &binding,
            &ActionBindingCursor {
                snapshot_revision: "pin".into(),
                pending_events: vec![
                    crate::sekai::object_change_subscription::ObjectChangeEvent {
                        offset: 1,
                        event_id: "evt-frozen".into(),
                        object_id: "billing-api".into(),
                        kind: "component".into(),
                        op: "update".into(),
                        field: "severity".into(),
                        committed_at_ms: 3,
                        operation_id: "op-frozen".into(),
                    },
                ],
                ..Default::default()
            },
            now_millis(),
        )
        .unwrap();
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "demo".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 1,
        })
        .unwrap();
        let refused = svc
            .run_action_binding(local(RunActionBindingRequest {
                namespace: "demo".into(),
                binding_id: "escalate".into(),
                limit: 16,
            }))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(refused.message().contains("write freeze"));
        let pending = db
            .get_action_binding("demo", "escalate")
            .unwrap()
            .unwrap()
            .1
            .pending_events;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, "evt-frozen");
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "demo".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_WRITES.into(),
            reason: "lifted".into(),
            enabled: false,
            updated_ms: 2,
        })
        .unwrap();
        let after = db
            .get_action_binding("demo", "escalate")
            .unwrap()
            .unwrap()
            .1
            .pending_events;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].event_id, "evt-frozen");
        db.set_write_freeze(&crate::sekai::write_freeze::WriteFreeze {
            scope_kind: crate::sekai::write_freeze::SCOPE_NAMESPACE.into(),
            scope_value: "demo".into(),
            mode: crate::sekai::write_freeze::MODE_BLOCK_AGENT_ACTIONS.into(),
            reason: "incident".into(),
            enabled: true,
            updated_ms: 3,
        })
        .unwrap();
        let refused_agent = svc
            .run_action_binding(local(RunActionBindingRequest {
                namespace: "demo".into(),
                binding_id: "escalate".into(),
                limit: 16,
            }))
            .await
            .unwrap_err();
        assert_eq!(refused_agent.code(), tonic::Code::FailedPrecondition);
        assert!(refused_agent.message().contains("write freeze"));
        let still_pending = db
            .get_action_binding("demo", "escalate")
            .unwrap()
            .unwrap()
            .1
            .pending_events;
        assert_eq!(still_pending.len(), 1);
        assert_eq!(still_pending[0].event_id, "evt-frozen");
    }

    /// A binding that submits `component.escalate` for `billing-api` every
    /// minute as `svc-escalator`, under `decision` as the namespace policy.
    fn scheduled_escalator(
        decision: crate::sekai::action_policy::ActionDecision,
    ) -> (Arc<RuntimeDb>, SekaiServiceImpl) {
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
        db.upsert_action_policy(&crate::sekai::action_policy::ActionPolicy {
            default_decision: decision,
            ..crate::sekai::action_policy::ActionPolicy::allow_all("demo")
        })
        .unwrap();
        db.put_action_binding(
            &ActionBinding {
                contract_version: ACTION_BINDING_CONTRACT.into(),
                binding_id: "escalate-hourly".into(),
                namespace: "demo".into(),
                kind: String::new(),
                property_filters: Vec::new(),
                ops: Vec::new(),
                schedule: Some(crate::sekai::action_binding::ActionBindingSchedule {
                    every_ms: 60_000,
                }),
                dataset_commit: None,
                type_id: "component.escalate".into(),
                version: "1".into(),
                run_as: "svc-escalator".into(),
                parameters: BTreeMap::from([
                    (
                        "component".into(),
                        ParameterSource::Constant("billing-api".into()),
                    ),
                    ("severity".into(), ParameterSource::Constant("low".into())),
                ]),
                markings: Vec::new(),
                enabled: true,
                revision: 0,
                created_by: String::new(),
                updated_at_ms: 0,
            },
            "local",
            2,
        )
        .unwrap();
        (db, svc)
    }

    fn instances(db: &RuntimeDb) -> Vec<crate::sekai::action_instance::ActionInstance> {
        db.list_action_instances("demo", Some("component.escalate"), None, 100)
            .unwrap()
    }

    async fn tick(svc: &SekaiServiceImpl, now_ms: i64) {
        super::super::rpc_data::run_schedule_tick(svc, now_ms, "system:transform-scheduler")
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn planes_ticking_one_bucket_at_once_admit_one_scheduled_action() {
        let (db, svc) = scheduled_escalator(crate::sekai::action_policy::ActionDecision::Allow);
        let now = 1_000 * 60_000;
        let (left, right) = (svc.clone(), svc.clone());
        tokio::join!(tick(&left, now), tick(&right, now));
        assert_eq!(instances(&db).len(), 1);

        // Nothing is recorded after the submit, so a tick rerun after a crash
        // there is this same submit again, and replays.
        tick(&svc, now + 30_000).await;
        assert_eq!(instances(&db).len(), 1);

        // Five missed buckets collapse into the one holding the tick.
        tick(&svc, now + 6 * 60_000).await;
        assert_eq!(instances(&db).len(), 2);

        let manual = svc
            .run_action_binding_once(local(RunActionBindingRequest {
                namespace: "demo".into(),
                binding_id: "escalate-hourly".into(),
                limit: 10,
            }))
            .await
            .unwrap_err();
        assert_eq!(manual.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_scheduled_action_under_require_approval_parks() {
        let (db, svc) =
            scheduled_escalator(crate::sekai::action_policy::ActionDecision::RequireApproval);
        tick(&svc, 1_000 * 60_000).await;
        let parked = instances(&db);
        assert_eq!(parked.len(), 1);
        assert_eq!(
            parked[0].status,
            crate::sekai::action_instance::STATUS_PARKED
        );
        assert_eq!(parked[0].principal, "svc-escalator");
    }

    fn bound_escalator() -> (Arc<RuntimeDb>, SekaiServiceImpl) {
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
        db.create_object_with_audit(
            &domain::Object {
                id: "billing-api".into(),
                kind: "component".into(),
                name: "billing-api".into(),
                namespace: "demo".into(),
                external_id: String::new(),
                properties: HashMap::from([("severity".into(), "high".into())]),
                created: 1,
                updated: 1,
            },
            "local",
        )
        .unwrap();
        let binding = db
            .put_action_binding(
                &ActionBinding {
                    contract_version: ACTION_BINDING_CONTRACT.into(),
                    binding_id: "escalate".into(),
                    namespace: "demo".into(),
                    kind: "component".into(),
                    property_filters: Vec::new(),
                    ops: vec!["update".into()],
                    schedule: None,
                    dataset_commit: None,
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
                    markings: Vec::new(),
                    enabled: true,
                    revision: 0,
                    created_by: String::new(),
                    updated_at_ms: 0,
                },
                "local",
                2,
            )
            .unwrap();
        db.advance_action_binding_cursor(
            &binding,
            &ActionBindingCursor {
                snapshot_revision: "pin".into(),
                pending_events: vec![
                    crate::sekai::object_change_subscription::ObjectChangeEvent {
                        offset: 1,
                        event_id: "evt-pending".into(),
                        object_id: "billing-api".into(),
                        kind: "component".into(),
                        op: "update".into(),
                        field: "severity".into(),
                        committed_at_ms: 3,
                        operation_id: "op-pending".into(),
                    },
                ],
                ..Default::default()
            },
            now_millis(),
        )
        .unwrap();
        (db, svc)
    }

    #[tokio::test]
    async fn internal_admission_failure_keeps_pending_events_for_one_later_submit() {
        let (db, svc) = bound_escalator();
        db.conn()
            .execute(
                "INSERT INTO sekai_classification_lattices
                 (namespace, contract_version, digest, lattice_json, created_by, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                ("demo", "v1", "stale", "{", "root", 1_i64),
            )
            .unwrap();
        let refused = svc
            .run_action_binding(local(RunActionBindingRequest {
                namespace: "demo".into(),
                binding_id: "escalate".into(),
                limit: 16,
            }))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Internal);
        let pending = db
            .get_action_binding("demo", "escalate")
            .unwrap()
            .unwrap()
            .1
            .pending_events;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, "evt-pending");
        assert!(
            db.list_action_instances("demo", None, None, 10)
                .unwrap()
                .is_empty()
        );

        db.conn()
            .execute(
                "DELETE FROM sekai_classification_lattices WHERE namespace = ?1",
                ["demo"],
            )
            .unwrap();
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
        assert!(run.submissions[0].skipped_reason.is_empty());
        assert!(!run.submissions[0].replay);
        let remaining = db
            .get_action_binding("demo", "escalate")
            .unwrap()
            .unwrap()
            .1
            .pending_events;
        assert!(remaining.is_empty());
        assert_eq!(
            db.list_action_instances("demo", None, None, 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn policy_refusal_skips_pending_events_and_is_not_retried() {
        let (db, svc) = bound_escalator();
        let binding = db
            .get_action_binding("demo", "escalate")
            .unwrap()
            .unwrap()
            .0;
        db.advance_action_binding_cursor(
            &binding,
            &ActionBindingCursor {
                snapshot_revision: "pin".into(),
                pending_events: vec![
                    crate::sekai::object_change_subscription::ObjectChangeEvent {
                        offset: 1,
                        event_id: "evt-create".into(),
                        object_id: "billing-api".into(),
                        kind: "component".into(),
                        op: "create".into(),
                        field: String::new(),
                        committed_at_ms: 3,
                        operation_id: "op-create".into(),
                    },
                ],
                ..Default::default()
            },
            now_millis(),
        )
        .unwrap();
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
        assert_eq!(run.submissions[0].skipped_reason, "op_not_bound");
        let remaining = db
            .get_action_binding("demo", "escalate")
            .unwrap()
            .unwrap()
            .1
            .pending_events;
        assert!(remaining.is_empty());
        assert!(
            db.list_action_instances("demo", None, None, 10)
                .unwrap()
                .is_empty()
        );
    }

    /// `bound_escalator`'s namespace with a dataset-commit binding on every
    /// dataset in `demo`, and datasets `orders` and `secret` bound to objects
    /// there. `secret`'s object is readable only by another principal.
    fn dataset_escalator() -> (Arc<RuntimeDb>, SekaiServiceImpl) {
        let (db, svc) = bound_escalator();
        for (id, object) in [("orders", "orders-object"), ("secret", "secret-object")] {
            db.create_object_with_audit(
                &domain::Object {
                    id: object.into(),
                    kind: "dataset".into(),
                    name: object.into(),
                    namespace: "demo".into(),
                    external_id: String::new(),
                    properties: HashMap::new(),
                    created: 1,
                    updated: 1,
                },
                "local",
            )
            .unwrap();
            db.create_dataset(&crate::sekai::dataset::Dataset {
                id: id.into(),
                name: id.into(),
                columns: Vec::new(),
                object_id: object.into(),
                created: 1,
                partition_keys: Vec::new(),
            })
            .unwrap();
        }
        svc.security.add_grant(&security::Grant {
            id: "secret-reader".into(),
            object_id: "secret-object".into(),
            principal: "other-reader".into(),
            role: security::Role::Viewer,
            created: 1,
            ..Default::default()
        });
        db.put_action_binding(
            &ActionBinding {
                contract_version: ACTION_BINDING_CONTRACT.into(),
                binding_id: "on-commit".into(),
                namespace: "demo".into(),
                kind: String::new(),
                property_filters: Vec::new(),
                ops: Vec::new(),
                schedule: None,
                dataset_commit: Some(
                    crate::sekai::action_binding::ActionBindingDatasetCommit::default(),
                ),
                type_id: "component.escalate".into(),
                version: "1".into(),
                run_as: "svc-escalator".into(),
                parameters: BTreeMap::from([
                    ("component".into(), ParameterSource::DatasetId),
                    ("severity".into(), ParameterSource::VersionId),
                ]),
                markings: Vec::new(),
                enabled: true,
                revision: 0,
                created_by: String::new(),
                updated_at_ms: 0,
            },
            "local",
            2,
        )
        .unwrap();
        (db, svc)
    }

    async fn run_on_commit(svc: &SekaiServiceImpl) -> RunActionBindingResponse {
        svc.run_action_binding_once(local(RunActionBindingRequest {
            namespace: "demo".into(),
            binding_id: "on-commit".into(),
            limit: 16,
        }))
        .await
        .unwrap()
        .into_inner()
    }

    fn append(db: &RuntimeDb, dataset_id: &str) -> String {
        db.append_rows(dataset_id, &[HashMap::from([("k".into(), "v".into())])])
            .unwrap();
        db.list_dataset_versions(dataset_id)
            .unwrap()
            .last()
            .unwrap()
            .version_id
            .clone()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_committed_dataset_version_admits_one_action_even_after_a_crash() {
        let (db, svc) = dataset_escalator();
        append(&db, "orders");
        // The first run pins: versions before it are not backfilled.
        assert!(run_on_commit(&svc).await.submissions.is_empty());
        assert!(instances(&db).is_empty());

        let version = append(&db, "orders");
        let first = run_on_commit(&svc).await;
        assert_eq!(first.submissions.len(), 1);
        let submission = &first.submissions[0];
        assert_eq!(
            (
                submission.dataset_id.as_str(),
                submission.version_id.as_str()
            ),
            ("orders", version.as_str())
        );
        assert_eq!(submission.op, "dataset_commit");
        assert!(!submission.replay, "{submission:?}");
        let admitted = instances(&db);
        assert_eq!(admitted.len(), 1);
        assert!(admitted[0].parameters_json.contains(&version));

        assert!(run_on_commit(&svc).await.submissions.is_empty());

        // A crash between the submit and the cursor write: the cursor is
        // still before the version, so the rerun replays the same instance.
        let (binding, _) = db.get_action_binding("demo", "on-commit").unwrap().unwrap();
        let RuntimeDb::Sqlite(sqlite) = db.as_ref() else {
            unreachable!("memory store is SQLite")
        };
        sqlite
            .conn()
            .execute(
                "UPDATE sekai_action_binding_dataset_cursors SET seq = seq - 1
                 WHERE binding_id = 'on-commit' AND dataset_id = 'orders'",
                [],
            )
            .unwrap();
        let replayed = run_on_commit(&svc).await;
        assert_eq!(replayed.submissions.len(), 1);
        assert!(replayed.submissions[0].replay);
        assert_eq!(replayed.binding_revision, binding.revision);
        assert_eq!(instances(&db).len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dataset_run_as_cannot_read_is_never_submitted_or_named() {
        let (db, svc) = dataset_escalator();
        run_on_commit(&svc).await;
        append(&db, "secret");
        append(&db, "orders");
        let response = run_on_commit(&svc).await;
        assert_eq!(response.submissions.len(), 1);
        assert_eq!(response.submissions[0].dataset_id, "orders");
        assert!(!format!("{response:?}").contains("secret"));
        assert_eq!(instances(&db).len(), 1);
    }
}
