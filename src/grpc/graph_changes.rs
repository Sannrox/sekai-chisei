//! `ApplyGraphChanges`: a client's graph changes, authorized one by one as the
//! single-record RPCs would, then committed all or none (#3062).
//!
//! Each change is planned against the state the earlier changes in the call
//! leave behind, so a link may join objects the same call creates. Every
//! planned change carries the stored state it was authorized against; the
//! store fails the whole call if any of it moved. Responses read objects back
//! through `GetObject`'s path, so the caller sees only what it may read.

use super::object_mutation_lifecycle::ObjectWriteCaller;
use super::*;
use crate::sekai::graph_changes::{
    GraphChangeBatch, GraphChangeError, GraphChangeInput, GraphChangeOutcome, GraphChangeReceipt,
    MAX_GRAPH_CHANGES, MAX_REQUEST_ID_LEN, PlannedGraphChange, instance_refusal, replay_stored,
    request_digest,
};
use sekai_types::object_change::ChangeAttribution;

/// The state a call leaves behind, change by change.
#[derive(Default)]
struct Overlay {
    /// Objects this call created or patched, as they will be stored.
    objects: HashMap<String, domain::Object>,
    /// Links this call created or deleted.
    links: HashSet<String>,
}

impl SekaiServiceImpl {
    pub(super) async fn apply_graph_changes_rpc(
        &self,
        req: Request<ApplyGraphChangesRequest>,
    ) -> Result<Response<ApplyGraphChangesResponse>, Status> {
        let service = self.clone();
        self.spawn_db(move || service.apply_graph_changes_blocking(req))
            .await
    }

    fn apply_graph_changes_blocking(
        &self,
        req: Request<ApplyGraphChangesRequest>,
    ) -> Result<Response<ApplyGraphChangesResponse>, Status> {
        let caller = ObjectWriteCaller::from_request(self.db.runtime(), &req)?;
        require_authenticated(&caller.principals)?;
        let session_namespace = Self::mcp_session_namespace(&req);
        let (metadata, extensions, input) = req.into_parts();
        if input.namespace.is_empty() {
            return Err(Status::invalid_argument("namespace required"));
        }
        if session_namespace
            .as_deref()
            .is_some_and(|namespace| namespace != input.namespace)
        {
            return Err(Status::permission_denied("namespace outside this session"));
        }
        if input.request_id.trim().is_empty() || input.request_id.len() > MAX_REQUEST_ID_LEN {
            return Err(Status::invalid_argument(format!(
                "request_id required, at most {MAX_REQUEST_ID_LEN} bytes"
            )));
        }
        if input.changes.is_empty() || input.changes.len() > MAX_GRAPH_CHANGES {
            return Err(Status::invalid_argument(format!(
                "between 1 and {MAX_GRAPH_CHANGES} changes required"
            )));
        }
        let actor = caller.principals.first().cloned().unwrap_or_default();
        let changes = input
            .changes
            .iter()
            .map(|change| {
                change
                    .change
                    .clone()
                    .ok_or(Status::invalid_argument("empty change"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let digest = request_digest(
            &actor,
            &input.namespace,
            &input.action_instance_id,
            &changes.iter().map(canonical_input).collect::<Vec<_>>(),
        )
        .map_err(Status::internal)?;
        let read_back = |receipt: GraphChangeReceipt, replayed: bool| {
            self.graph_change_response(&metadata, &extensions, receipt, replayed)
        };
        let stored = self
            .db
            .runtime()
            .get_graph_change_request(&input.namespace, &input.request_id)
            .map_err(graph_change_status)?;
        if let Some(GraphChangeOutcome::Replayed(receipt)) =
            replay_stored(stored, &digest).map_err(graph_change_status)?
        {
            return read_back(receipt, true);
        }
        let attribution = self.graph_change_attribution(&input, &actor)?;
        let policy_generation = object_security_generation(self.db.runtime(), &input.namespace)?;
        let mut overlay = Overlay::default();
        let mut planned = Vec::with_capacity(changes.len());
        let mut receipt = GraphChangeReceipt::default();
        let now = now_millis();
        for change in changes {
            let change = self.plan_graph_change(
                &caller,
                &metadata,
                &extensions,
                &input.namespace,
                &mut overlay,
                change,
                now,
            )?;
            match &change {
                PlannedGraphChange::CreateObject(object)
                | PlannedGraphChange::UpdateObject { object, .. } => {
                    receipt.object_ids.push(object.id.clone())
                }
                PlannedGraphChange::CreateLink { link, .. } => receipt.links.push(link.clone()),
                _ => {}
            }
            planned.push(change);
        }
        let batch = GraphChangeBatch {
            namespace: input.namespace,
            request_id: input.request_id,
            request_digest: digest,
            actor,
            action_instance_id: input.action_instance_id,
            policy_generation,
            attribution,
            changes: planned,
            receipt,
            now_ms: now,
        };
        match self
            .db
            .runtime()
            .apply_graph_changes(&batch)
            .map_err(graph_change_status)?
        {
            GraphChangeOutcome::Applied(receipt) => read_back(receipt, false),
            GraphChangeOutcome::Replayed(receipt) => read_back(receipt, true),
            _ => Err(Status::internal("unknown graph change outcome")),
        }
    }

    /// Who the change audit names. A bound Action instance must already be
    /// admitted to this caller in this namespace; the store checks it again
    /// in the transaction.
    fn graph_change_attribution(
        &self,
        input: &ApplyGraphChangesRequest,
        actor: &str,
    ) -> Result<ChangeAttribution, Status> {
        if input.action_instance_id.is_empty() {
            return Ok(ChangeAttribution::direct());
        }
        let instance = self
            .db
            .runtime()
            .get_action_instance(&input.action_instance_id)
            .map_err(Status::internal)?;
        let row = instance.as_ref().map(|instance| {
            (
                instance.namespace.clone(),
                instance.principal.clone(),
                instance.status.clone(),
            )
        });
        if let Some(refusal) = instance_refusal(row, &input.namespace, actor) {
            return Err(graph_change_status(GraphChangeError::Instance(refusal)));
        }
        let instance = instance.ok_or_else(|| Status::internal("admitted instance vanished"))?;
        Ok(ChangeAttribution::action(
            &instance.instance_id,
            &instance.operation_id,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_graph_change(
        &self,
        caller: &ObjectWriteCaller,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
        namespace: &str,
        overlay: &mut Overlay,
        change: graph_change::Change,
        now: i64,
    ) -> Result<PlannedGraphChange, Status> {
        match change {
            graph_change::Change::CreateObject(mut object) => {
                if object.namespace.is_empty() {
                    object.namespace = namespace.to_string();
                }
                if object.namespace != namespace {
                    return Err(outside_namespace());
                }
                if object.kind == markings::PRINCIPAL_PROFILE_KIND {
                    return Err(Status::invalid_argument(
                        "principal profiles are created through CreateObject",
                    ));
                }
                if overlay.objects.contains_key(&object.id) {
                    return Err(repeated_object(&object.id));
                }
                if object.created == 0 {
                    object.created = now;
                }
                if object.updated == 0 {
                    object.updated = object.created;
                }
                self.admit_object_create(caller, &object)?;
                let domain_object = from_proto_obj(&object);
                self.screen_object_write(caller, &domain_object)?;
                let domain_object = self.authorize_object_create(caller, &object, domain_object)?;
                overlay
                    .objects
                    .insert(domain_object.id.clone(), domain_object.clone());
                Ok(PlannedGraphChange::CreateObject(domain_object))
            }
            graph_change::Change::PatchObject(patch) => {
                if overlay.objects.contains_key(&patch.object_id) {
                    return Err(repeated_object(&patch.object_id));
                }
                if patch.expected_revision.is_empty() {
                    return Err(Status::invalid_argument("expected_revision required"));
                }
                // Stored state first, then the caller's view: a write between
                // the two makes the view newer than `existing`, and the store
                // refuses the stale `existing`.
                let existing = self
                    .db
                    .runtime()
                    .get_object(&patch.object_id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::not_found("not found"))?;
                let visible = self.visible_object(metadata, extensions, &patch.object_id)?;
                if visible.revision != patch.expected_revision {
                    return Err(object_changed(&patch.object_id));
                }
                if existing.namespace != namespace {
                    return Err(outside_namespace());
                }
                if existing.kind == "namespace" || existing.kind == markings::PRINCIPAL_PROFILE_KIND
                {
                    return Err(Status::invalid_argument(
                        "namespace and principal profile objects change through their own RPCs",
                    ));
                }
                let mut patched = existing.clone();
                for key in &patch.remove_properties {
                    patched.properties.remove(key);
                }
                patched.properties.extend(patch.set_properties);
                patched.updated = now.max(existing.updated + 1);
                let object = to_proto_obj(&patched);
                self.admit_object_update(caller, &object, Some(&existing))?;
                self.screen_object_write(caller, &patched)?;
                let patched = self.authorize_object_update(caller, Some(&existing), patched)?;
                overlay.objects.insert(patched.id.clone(), patched.clone());
                Ok(PlannedGraphChange::UpdateObject {
                    object: patched,
                    expected: existing,
                })
            }
            graph_change::Change::CreateLink(link) => {
                let mut link = domain::Link {
                    id: link.id,
                    from_id: link.from_id,
                    to_id: link.to_id,
                    relation: link.relation,
                    created: link.created,
                };
                if link.id.trim().is_empty() {
                    link.id = format!("link-{}", Uuid::new_v4().simple());
                }
                if link.created == 0 {
                    link.created = now;
                }
                if !overlay.links.insert(link.id.clone()) {
                    return Err(Status::invalid_argument(format!(
                        "link {} appears in more than one change",
                        link.id
                    )));
                }
                let (from, to) =
                    self.graph_link_endpoints(caller, namespace, overlay, &link, "create_link")?;
                let ontology = self
                    .db
                    .runtime()
                    .load_ontology_registry()
                    .map_err(Status::internal)?;
                super::authorized_link_mutation::validate_mapped_link(
                    &ontology,
                    &link.relation,
                    &from.kind,
                    &to.kind,
                )?;
                Ok(PlannedGraphChange::CreateLink { link, from, to })
            }
            graph_change::Change::DeleteLinkId(id) => {
                if !overlay.links.insert(id.clone()) {
                    return Err(Status::invalid_argument(format!(
                        "link {id} appears in more than one change"
                    )));
                }
                let link = self
                    .db
                    .runtime()
                    .get_link(&id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::not_found("link not found"))?;
                let (from, to) =
                    self.graph_link_endpoints(caller, namespace, overlay, &link, "delete_link")?;
                Ok(PlannedGraphChange::DeleteLink { link, from, to })
            }
        }
    }

    /// Both endpoints of `link` as this call leaves them, each authorized as
    /// CreateLink and DeleteLink authorize theirs.
    fn graph_link_endpoints(
        &self,
        caller: &ObjectWriteCaller,
        namespace: &str,
        overlay: &Overlay,
        link: &domain::Link,
        operation: &str,
    ) -> Result<(domain::Object, domain::Object), Status> {
        let mut endpoints = Vec::with_capacity(2);
        for id in [&link.from_id, &link.to_id] {
            let object = match overlay.objects.get(id) {
                Some(object) => object.clone(),
                None => self
                    .db
                    .runtime()
                    .get_object(id)
                    .map_err(Status::internal)?
                    .ok_or_else(|| Status::not_found("link endpoint not found"))?,
            };
            self.authorize_link_endpoint(
                &caller.principals,
                caller.tenant_context.as_ref(),
                &object,
                operation,
            )?;
            if object.namespace != namespace {
                return Err(outside_namespace());
            }
            endpoints.push(object);
        }
        for object in &endpoints {
            self.refuse_generic_write_for_published_type(&object.namespace, &object.kind)?;
        }
        let to = endpoints.pop().expect("two endpoints");
        let from = endpoints.pop().expect("two endpoints");
        Ok((from, to))
    }

    /// The object as GetObject returns it to this caller, with its revision.
    fn visible_object(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
        id: &str,
    ) -> Result<Object, Status> {
        self.get_visible_object_blocking(Request::from_parts(
            metadata.clone(),
            extensions.clone(),
            GetObjectRequest { id: id.to_string() },
        ))?
        .into_inner()
        .object
        .ok_or_else(|| Status::not_found("not found"))
    }

    /// Reads each written object back through the caller's view. An object
    /// the caller can no longer read, or that is gone, is left out.
    fn graph_change_response(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        extensions: &tonic::Extensions,
        receipt: GraphChangeReceipt,
        replayed: bool,
    ) -> Result<Response<ApplyGraphChangesResponse>, Status> {
        let mut objects = Vec::with_capacity(receipt.object_ids.len());
        for id in &receipt.object_ids {
            match self.visible_object(metadata, extensions, id) {
                Ok(object) => objects.push(object),
                Err(status) if status.code() == tonic::Code::NotFound => {}
                Err(status) => return Err(status),
            }
        }
        Ok(Response::new(ApplyGraphChangesResponse {
            objects,
            links: receipt.links.iter().map(to_proto_link).collect(),
            replayed,
        }))
    }
}

/// The digest form of one change: maps sorted, defaults not filled in.
fn canonical_input(change: &graph_change::Change) -> GraphChangeInput {
    match change {
        graph_change::Change::CreateObject(object) => GraphChangeInput::CreateObject {
            id: object.id.clone(),
            kind: object.kind.clone(),
            name: object.name.clone(),
            namespace: object.namespace.clone(),
            external_id: object.external_id.clone(),
            properties: object.properties.clone().into_iter().collect(),
            created: object.created,
            updated: object.updated,
        },
        graph_change::Change::PatchObject(patch) => GraphChangeInput::PatchObject {
            object_id: patch.object_id.clone(),
            expected_revision: patch.expected_revision.clone(),
            set: patch.set_properties.clone().into_iter().collect(),
            remove: patch.remove_properties.clone(),
        },
        graph_change::Change::CreateLink(link) => GraphChangeInput::CreateLink {
            id: link.id.clone(),
            from_id: link.from_id.clone(),
            to_id: link.to_id.clone(),
            relation: link.relation.clone(),
            created: link.created,
        },
        graph_change::Change::DeleteLinkId(id) => GraphChangeInput::DeleteLink { id: id.clone() },
    }
}

fn object_changed(id: &str) -> Status {
    Status::failed_precondition(format!(
        "graph_change_conflict: object {id} changed since it was read"
    ))
}

fn repeated_object(id: &str) -> Status {
    Status::invalid_argument(format!("object {id} appears in more than one change"))
}

fn outside_namespace() -> Status {
    Status::invalid_argument("every object a change touches must be in the request namespace")
}

fn graph_change_status(error: GraphChangeError) -> Status {
    match error {
        GraphChangeError::RequestConflict => Status::already_exists(
            "graph_change_request_conflict: request_id was used with a different body",
        ),
        GraphChangeError::ObjectChanged(id) => object_changed(&id),
        GraphChangeError::ObjectExists(id) => {
            Status::already_exists(format!("object {id} already exists"))
        }
        GraphChangeError::LinkExists(id) => {
            Status::already_exists(format!("link {id} already exists"))
        }
        GraphChangeError::LinkMissing(id) => Status::failed_precondition(format!(
            "graph_change_conflict: link {id} changed since it was read"
        )),
        GraphChangeError::PolicyChanged => Status::failed_precondition(
            "graph_change_conflict: the namespace's object policy changed; retry",
        ),
        GraphChangeError::Instance(refusal) => Status::failed_precondition(format!(
            "action_instance_not_applicable: {}",
            refusal.reason()
        )),
        GraphChangeError::Rejected(message) => map_graph_mutation_error(message),
        GraphChangeError::Store(message) => Status::internal(message),
        _ => Status::internal("graph change failed"),
    }
}

#[cfg(test)]
#[path = "graph_changes_tests.rs"]
mod tests;
