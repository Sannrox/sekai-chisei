//! Offline sync scope RPCs (#1632, ADR 0124).
//!
//! Membership is computed with the online read checks: the scope's matches
//! come from the marked, policy-filtered object list, and linked objects
//! join only if the caller may read them. Objects leave the server only as
//! an online read projects them, so hidden properties never do. Scopes and
//! cursors belong to the principal that defined them.

use super::*;
use crate::sekai::object_change_subscription::authorization_pin;
use crate::sekai::object_security::ObjectSecurityOperation;
use crate::sekai::purpose_authorization::PurposePresentation;
use crate::sekai::sync_scope::{
    self, DEFAULT_PAGE, LinkDirection, MAX_PAGE, Member, ScopeDefinition, ScopeFilter, ScopeLink,
    SyncError, SyncPosition, SyncScope,
};
use std::collections::BTreeMap;

/// A fingerprint of an object as the caller reads it.
fn fingerprint(object: &domain::Object) -> String {
    let created = object.created.to_string();
    let updated = object.updated.to_string();
    let mut properties: Vec<(&String, &String)> = object.properties.iter().collect();
    properties.sort();
    sync_scope::fingerprint(
        [
            object.kind.as_str(),
            object.name.as_str(),
            object.namespace.as_str(),
            object.external_id.as_str(),
            created.as_str(),
            updated.as_str(),
        ]
        .into_iter()
        .chain(
            properties
                .into_iter()
                .flat_map(|(key, value)| [key.as_str(), value.as_str()]),
        ),
    )
}

/// A member as the caller reads `object`: its fingerprint and the property
/// names it shows.
fn member(object: &domain::Object) -> Member {
    let mut properties: Vec<String> = object.properties.keys().cloned().collect();
    properties.sort();
    Member {
        object_id: object.id.clone(),
        fingerprint: fingerprint(object),
        properties,
    }
}

fn member_list(members: &BTreeMap<String, domain::Object>) -> Vec<Member> {
    members.values().map(member).collect()
}

/// Whether a stored position pin was taken under the scope definition the
/// current pin names. A pin is `<definition>.<authorization>`; a changed
/// authorization keeps the cursor and arrives as purges (#1633), a changed
/// definition does not. A pin from before the split never matches.
fn same_definition(stored: &str, pin: &str) -> bool {
    match (stored.split_once('.'), pin.split_once('.')) {
        (Some((stored, _)), Some((current, _))) => stored == current,
        _ => false,
    }
}

/// When the client must sync again before showing data: now plus the
/// scope's maximum offline age, or 0 for no limit.
fn offline_until(scope: &SyncScope) -> i64 {
    match scope.definition.max_offline_age_ms {
        0 => 0,
        age => now_millis().saturating_add(age),
    }
}

struct Caller<'a> {
    service: &'a SekaiServiceImpl,
    principals: Vec<String>,
    policy_context: crate::sekai::object_security::PrincipalPolicyContext,
    tenant_context: Option<RequestEnterpriseContext>,
    purpose: Option<PurposePresentation>,
}

fn sync_status(error: SyncError) -> Status {
    match error {
        SyncError::Invalid(message) => Status::invalid_argument(message),
        SyncError::NotFound => Status::not_found("sync scope not found"),
        SyncError::Storage(message) => Status::internal(message),
    }
}

fn check_contract(version: &str) -> Result<(), Status> {
    if version == sync_scope::SYNC_CONTRACT {
        Ok(())
    } else {
        Err(Status::invalid_argument(format!(
            "contract_version must be {}",
            sync_scope::SYNC_CONTRACT
        )))
    }
}

fn page_limit(limit: u32) -> usize {
    match limit {
        0 => DEFAULT_PAGE as usize,
        limit => limit.min(MAX_PAGE) as usize,
    }
}

impl<'a> Caller<'a> {
    fn new<T: 'static>(service: &'a SekaiServiceImpl, req: &Request<T>) -> Result<Self, Status> {
        let principals = caller_principals(req);
        require_authenticated(&principals)?;
        Ok(Self {
            service,
            policy_context: principal_policy_context(req),
            tenant_context: request_tenant_context(service.db.runtime(), req)?,
            purpose: request_purpose_presentation(req, &principals),
            principals,
        })
    }

    fn db(&self) -> &RuntimeDb {
        self.service.db.runtime()
    }

    fn owner(&self) -> String {
        self.principals.first().cloned().unwrap_or_default()
    }

    /// Read access to the namespace, as the object change feed requires.
    fn authorize_namespace(&self, namespace: &str) -> Result<(), Status> {
        let tenant = self.tenant_context.as_ref();
        enforce_namespace_tenant_context(self.db(), tenant, namespace, false)?;
        check_team_namespace(self.db(), &self.principals, namespace, false)?;
        authorize_source_sync_namespace(self.service, &self.principals, tenant, namespace, false)
    }

    /// The caller's scope. Another principal's scope is `NOT_FOUND`.
    fn scope(&self, namespace: &str, scope_id: &str) -> Result<SyncScope, Status> {
        self.authorize_namespace(namespace)?;
        self.db()
            .get_sync_scope(namespace, &self.owner(), scope_id)
            .map_err(sync_status)?
            .ok_or_else(|| sync_status(SyncError::NotFound))
    }

    /// What a position was computed under: the namespace's object policy
    /// activation, the caller's principals and the scope definition. A
    /// position from another definition, even one saved while the scope was
    /// being replaced, never matches.
    fn pin(&self, scope: &SyncScope) -> Result<String, Status> {
        let activation = object_security_generation(self.db(), &scope.namespace)?;
        let authorization =
            authorization_pin(&activation, &self.principals).map_err(Status::internal)?;
        let definition =
            crate::db::sync_scope::definition_json(&scope.definition).map_err(sync_status)?;
        Ok(format!(
            "{}.{}",
            sync_scope::fingerprint([definition.as_str()]),
            sync_scope::fingerprint([authorization.as_str()])
        ))
    }

    fn visible(&self, object: &domain::Object) -> bool {
        object_is_visible_for_purpose(
            self.db(),
            &self.service.security,
            object,
            &self.principals,
            self.tenant_context.as_ref(),
            ObjectSecurityOperation::Read,
            self.purpose.as_ref(),
        )
    }

    /// Filters on properties the caller may not query are refused, as on an
    /// online list: matches would reveal the values.
    fn check_filters(&self, namespace: &str, definition: &ScopeDefinition) -> Result<(), Status> {
        if definition.property_filters.is_empty() {
            return Ok(());
        }
        let keys: Vec<String> = definition
            .property_filters
            .iter()
            .map(|filter| filter.key.clone())
            .collect();
        let schema = self
            .service
            .schema_definitions
            .snapshot()
            .map_err(map_schema_definition_lifecycle_error)?;
        ensure_property_query_allowed(
            &schema,
            &self.principals,
            self.tenant_context.as_ref(),
            &definition.kind,
            keys.clone(),
        )?;
        ensure_property_grant_query_allowed(
            self.db(),
            Some(namespace),
            Some(&definition.kind),
            keys,
        )
    }

    /// The scope's visible members now, by id, as the caller reads them.
    /// More than the scope's quota is refused, naming the quota.
    fn members(&self, scope: &SyncScope) -> Result<BTreeMap<String, domain::Object>, Status> {
        let definition = &scope.definition;
        self.check_filters(&scope.namespace, definition)?;
        let quota = definition.max_objects as usize;
        let over_quota = || {
            Status::resource_exhausted(format!(
                "sync scope `{}` has more than its quota of {quota} objects (max_objects)",
                scope.scope_id
            ))
        };
        let mut members = BTreeMap::new();
        let mut offset = 0;
        loop {
            let filter = domain::ListFilter {
                kind: Some(definition.kind.clone()),
                name: None,
                namespace: Some(scope.namespace.clone()),
                property_filters: definition
                    .property_filters
                    .iter()
                    .map(|filter| domain::PropertyFilter {
                        key: filter.key.clone(),
                        op: filter.op.clone(),
                        value: filter.value.clone(),
                    })
                    .collect(),
                interface_filter: Vec::new(),
                limit: domain::MAX_LIST_LIMIT,
                offset,
                order_by: "name".into(),
                descending: false,
            };
            let (page, _) = list_objects_with_marking(
                self.db(),
                &filter,
                &self.principals,
                &self.policy_context,
                self.purpose.as_ref(),
                self.tenant_context.as_ref(),
                |objects, _, _| Ok(objects),
            )?;
            let full = page.len() as i32 == domain::MAX_LIST_LIMIT;
            // The list applies markings and object policy; grants are
            // checked here as on any online read.
            for object in page.into_iter().filter(|object| self.visible(object)) {
                members.insert(object.id.clone(), object);
            }
            if members.len() > quota {
                return Err(over_quota());
            }
            if !full {
                break;
            }
            offset += domain::MAX_LIST_LIMIT;
        }
        if let Some(link) = &definition.link {
            let direction = match link.direction {
                LinkDirection::Outgoing => domain::Direction::Outgoing,
                LinkDirection::Incoming => domain::Direction::Incoming,
            };
            let mut frontier: Vec<String> = members.keys().cloned().collect();
            for _ in 0..link.max_hops {
                let mut next = Vec::new();
                for id in &frontier {
                    let linked = self
                        .db()
                        .get_linked_objects_with_policy_context(
                            id,
                            &link.relation,
                            &direction,
                            &self.policy_context,
                        )
                        .map_err(Status::internal)?;
                    for object in linked {
                        if object.namespace != scope.namespace
                            || members.contains_key(&object.id)
                            || is_reserved_governance_kind(&object.kind)
                            || !self.visible(&object)
                        {
                            continue;
                        }
                        next.push(object.id.clone());
                        members.insert(object.id.clone(), object);
                        if members.len() > quota {
                            return Err(over_quota());
                        }
                    }
                }
                frontier = next;
            }
        }
        let projected = self.service.resolve_computed_for_responses_with_policy(
            members.into_values().collect(),
            &self.principals,
            Some(&self.policy_context),
            self.tenant_context.as_ref(),
            self.purpose.as_ref(),
        )?;
        Ok(projected
            .into_iter()
            .map(|object| (object.id.clone(), object))
            .collect())
    }

    /// Objects as an online read shows them, dropping any the caller may no
    /// longer read.
    fn project(&self, objects: Vec<domain::Object>) -> Result<Vec<domain::Object>, Status> {
        let readable = objects
            .into_iter()
            .filter(|object| self.visible(object))
            .collect();
        self.service.resolve_computed_for_responses_with_policy(
            readable,
            &self.principals,
            Some(&self.policy_context),
            self.tenant_context.as_ref(),
            self.purpose.as_ref(),
        )
    }

    /// Record on `position` what a response ending there delivered for
    /// `ids`: each object's fingerprint, or empty when it was not sent.
    fn record_delivery(
        &self,
        position: &mut SyncPosition,
        ids: &[String],
        sent: &[domain::Object],
    ) -> Result<(), Status> {
        let delivered: Vec<(String, String)> = ids
            .iter()
            .map(|id| {
                let fingerprint = sent
                    .iter()
                    .find(|object| &object.id == id)
                    .map(fingerprint)
                    .unwrap_or_default();
                (id.clone(), fingerprint)
            })
            .collect();
        self.db()
            .record_sync_delivery(&position.position_id, &delivered)
            .map_err(sync_status)?;
        position.delivered.extend(delivered);
        Ok(())
    }

    fn load(&self, ids: &[String]) -> Result<Vec<domain::Object>, Status> {
        let mut objects = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(object) = self.db().get_object(id).map_err(Status::internal)? {
                objects.push(object);
            }
        }
        Ok(objects)
    }

    /// A stored position of the caller's scope.
    fn position(
        &self,
        scope: &SyncScope,
        position_id: &str,
    ) -> Result<Option<SyncPosition>, Status> {
        Ok(self
            .db()
            .get_sync_position(position_id)
            .map_err(sync_status)?
            .filter(|position| {
                position.namespace == scope.namespace
                    && position.owner == scope.owner
                    && position.scope_id == scope.scope_id
            }))
    }

    /// Store a position. `distinguisher` keeps two positions with the same members
    /// apart: the predecessor for a delta, a fresh id for a snapshot.
    fn save_position(
        &self,
        scope: &SyncScope,
        pin: String,
        members: Vec<Member>,
        distinguisher: &str,
        origin: Option<&str>,
    ) -> Result<SyncPosition, Status> {
        let position = SyncPosition {
            position_id: sync_scope::position_id(
                &scope.namespace,
                &scope.owner,
                &scope.scope_id,
                &pin,
                &members,
                distinguisher,
            ),
            namespace: scope.namespace.clone(),
            owner: scope.owner.clone(),
            scope_id: scope.scope_id.clone(),
            authorization_pin: pin,
            members,
            successor: None,
            origin: origin.map(str::to_string),
            delivered: BTreeMap::new(),
        };
        self.db()
            // A snapshot (no origin) retires the scope's other cursors.
            .save_sync_position(&position, origin.is_none(), now_millis())
            .map_err(sync_status)?;
        Ok(position)
    }
}

// Every handler runs on the bounded database worker pool: membership reads
// the object store and the link graph.
/// The device-proof check every sync RPC runs (#1634, ADR 0126): a
/// device-bound credential proves possession of its key over this request.
fn check_device<T: prost::Message>(req: &Request<T>, method: &str) -> Result<(), Status> {
    crate::grpc::require_device_proof(req, &format!("/sekai.SekaiService/{method}"), false)
}

/// Whether the caller is a device its issuer revoked: sync then answers
/// only with a wipe instruction.
fn device_must_wipe<T>(req: &Request<T>) -> bool {
    req.extensions()
        .get::<crate::enterprise::AuthenticatedContext>()
        .and_then(|context| context.device.as_ref())
        .is_some_and(|device| device.wipe)
}

pub(super) async fn put_sync_scope(
    service: &SekaiServiceImpl,
    req: Request<PutSyncScopeRequest>,
) -> Result<Response<SyncScopeResponse>, Status> {
    check_device(&req, "PutSyncScope")?;
    if device_must_wipe(&req) {
        return Err(Status::permission_denied(
            "the device was revoked and must wipe",
        ));
    }
    let owned = service.clone();
    service
        .spawn_db(move || put_sync_scope_blocking(&owned, req))
        .await
}

pub(super) async fn read_sync_snapshot(
    service: &SekaiServiceImpl,
    req: Request<ReadSyncSnapshotRequest>,
) -> Result<Response<ReadSyncSnapshotResponse>, Status> {
    check_device(&req, "ReadSyncSnapshot")?;
    if device_must_wipe(&req) {
        return Ok(Response::new(ReadSyncSnapshotResponse {
            contract_version: sync_scope::SYNC_CONTRACT.into(),
            wipe_required: true,
            ..Default::default()
        }));
    }
    let owned = service.clone();
    service
        .spawn_db(move || read_sync_snapshot_blocking(&owned, req))
        .await
}

pub(super) async fn read_sync_deltas(
    service: &SekaiServiceImpl,
    req: Request<ReadSyncDeltasRequest>,
) -> Result<Response<ReadSyncDeltasResponse>, Status> {
    check_device(&req, "ReadSyncDeltas")?;
    if device_must_wipe(&req) {
        return Ok(Response::new(ReadSyncDeltasResponse {
            contract_version: sync_scope::SYNC_CONTRACT.into(),
            wipe_required: true,
            ..Default::default()
        }));
    }
    let owned = service.clone();
    service
        .spawn_db(move || read_sync_deltas_blocking(&owned, req))
        .await
}

fn put_sync_scope_blocking(
    service: &SekaiServiceImpl,
    req: Request<PutSyncScopeRequest>,
) -> Result<Response<SyncScopeResponse>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    check_contract(&input.contract_version)?;
    sync_scope::validate_scope_id(&input.scope_id).map_err(Status::invalid_argument)?;
    caller.authorize_namespace(&input.namespace)?;
    if is_reserved_governance_kind(&input.kind) {
        return Err(Status::not_found("object kind unavailable"));
    }
    let link = input
        .link
        .map(|link| {
            let direction = match link.direction.as_str() {
                "" | "outgoing" => Ok(LinkDirection::Outgoing),
                "incoming" => Ok(LinkDirection::Incoming),
                other => Err(Status::invalid_argument(format!(
                    "link direction `{other}` must be outgoing or incoming"
                ))),
            }?;
            Ok::<_, Status>(ScopeLink {
                relation: link.relation,
                direction,
                max_hops: link.max_hops,
            })
        })
        .transpose()?;
    let definition = ScopeDefinition {
        kind: input.kind,
        property_filters: input
            .property_filters
            .into_iter()
            .map(|filter| ScopeFilter {
                key: filter.key,
                op: filter.op,
                value: filter.value,
            })
            .collect(),
        link,
        max_objects: input.max_objects,
        max_offline_age_ms: input.max_offline_age_ms,
    };
    definition.validate().map_err(Status::invalid_argument)?;
    caller.check_filters(&input.namespace, &definition)?;
    let scope = caller
        .db()
        .put_sync_scope(&SyncScope {
            namespace: input.namespace,
            owner: caller.owner(),
            scope_id: input.scope_id,
            definition,
            updated_at_ms: now_millis(),
        })
        .map_err(sync_status)?;
    Ok(Response::new(SyncScopeResponse {
        contract_version: sync_scope::SYNC_CONTRACT.into(),
        namespace: scope.namespace,
        scope_id: scope.scope_id,
        max_objects: scope.definition.max_objects,
        max_offline_age_ms: scope.definition.max_offline_age_ms,
    }))
}

fn read_sync_snapshot_blocking(
    service: &SekaiServiceImpl,
    req: Request<ReadSyncSnapshotRequest>,
) -> Result<Response<ReadSyncSnapshotResponse>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    check_contract(&input.contract_version)?;
    let scope = caller.scope(&input.namespace, &input.scope_id)?;
    let pin = caller.pin(&scope)?;
    let (mut position, after) = if input.page_token.is_empty() {
        // Fingerprints are taken now; an object that changes while the
        // client pages reads differently at the first delta and is sent again.
        let members = member_list(&caller.members(&scope)?);
        let distinguisher = uuid::Uuid::new_v4().to_string();
        // One replica per principal and scope: a new snapshot retires the
        // old cursors in the same transaction it saves its own.
        let position = caller.save_position(&scope, pin, members, &distinguisher, None)?;
        (position, String::new())
    } else {
        let (position_id, after) =
            sync_scope::parse_snapshot_token(&input.page_token).map_err(sync_status)?;
        let position = caller
            .position(&scope, position_id)?
            .filter(|position| position.authorization_pin == pin)
            .ok_or_else(|| {
                Status::failed_precondition("the snapshot is no longer valid; start a new one")
            })?;
        (position, after.to_string())
    };
    let limit = page_limit(input.limit);
    let remaining: Vec<String> = position
        .members
        .iter()
        .map(|member| member.object_id.clone())
        .filter(|id| after.is_empty() || id.as_str() > after.as_str())
        .collect();
    let page: Vec<String> = remaining.iter().take(limit).cloned().collect();
    let last_page = remaining.len() <= limit;
    let objects = caller.project(caller.load(&page)?)?;
    // The deltas start from what these pages actually delivered.
    caller.record_delivery(&mut position, &page, &objects)?;
    Ok(Response::new(ReadSyncSnapshotResponse {
        contract_version: sync_scope::SYNC_CONTRACT.into(),
        objects: objects.iter().map(to_proto_obj).collect(),
        next_page_token: match (last_page, page.last()) {
            (false, Some(last)) => sync_scope::snapshot_token(&position.position_id, last),
            _ => String::new(),
        },
        cursor: if last_page {
            position.position_id.clone()
        } else {
            String::new()
        },
        total_objects: position.members.len() as u32,
        offline_until_ms: if last_page { offline_until(&scope) } else { 0 },
        wipe_required: false,
    }))
}

fn resnapshot() -> Response<ReadSyncDeltasResponse> {
    Response::new(ReadSyncDeltasResponse {
        contract_version: sync_scope::SYNC_CONTRACT.into(),
        resnapshot_required: true,
        ..Default::default()
    })
}

fn read_sync_deltas_blocking(
    service: &SekaiServiceImpl,
    req: Request<ReadSyncDeltasRequest>,
) -> Result<Response<ReadSyncDeltasResponse>, Status> {
    let caller = Caller::new(service, &req)?;
    let input = req.into_inner();
    check_contract(&input.contract_version)?;
    let scope = caller.scope(&input.namespace, &input.scope_id)?;
    let pin = caller.pin(&scope)?;
    let Some(position) = caller
        .position(&scope, &input.cursor)?
        .filter(|position| same_definition(&position.authorization_pin, &pin))
    else {
        return Ok(resnapshot());
    };
    let db = caller.db();
    // A filter the caller may no longer query ends the cursor: the client
    // discards its replica and its next snapshot is checked afresh.
    let mut current = match caller.members(&scope) {
        Ok(current) => current,
        Err(status) if status.code() == tonic::Code::PermissionDenied => {
            return Ok(resnapshot());
        }
        Err(status) => return Err(status),
    };
    let now = member_list(&current);
    let limit = page_limit(input.limit);
    let baseline = position.baseline();
    // The client read this cursor, so it holds that answer: the cursor it
    // came from and that cursor's other answers are done. Newer cursors are
    // untouched, and this one stays valid for a retry.
    db.prune_sync_before(&position.position_id)
        .map_err(sync_status)?;
    // Which changes a cursor's delta covers is fixed at its first read: a
    // retry answers with the same transition.
    let recorded = match &position.successor {
        Some(successor) => Some(successor.clone()),
        None => {
            let sent = sync_scope::page(&sync_scope::diff_members(&baseline, &now), limit);
            let held = sync_scope::advance(&baseline, &now, &sent);
            let next = caller.save_position(
                &scope,
                pin.clone(),
                held,
                &position.position_id,
                Some(&position.position_id),
            )?;
            db.set_sync_successor(&position.position_id, &next.position_id)
                .map_err(sync_status)?
        }
    };
    let Some(transition) = recorded
        .map(|id| caller.position(&scope, &id))
        .transpose()?
        .flatten()
    else {
        return Ok(resnapshot());
    };
    let mut diff = sync_scope::diff_members(&baseline, &transition.members);
    let upserts: Vec<domain::Object> = diff
        .upserts
        .iter()
        .filter_map(|id| current.remove(id))
        .collect();
    // An upsert that can no longer be sent (deleted or hidden since the
    // first read of this cursor) is a removal: a client that applied an
    // earlier answer to this cursor may hold it. Removing what the client
    // lacks is harmless.
    let unsent: Vec<String> = diff
        .upserts
        .iter()
        .filter(|id| !upserts.iter().any(|object| &object.id == *id))
        .cloned()
        .collect();
    diff.removes.extend(unsent.iter().cloned());
    diff.removes.sort();
    // The answer gets its own cursor, holding exactly what it sent: the
    // transition's members with the bodies actually sent and without the
    // ones that could not be. Two answers with the same bodies share it.
    let mut answered: BTreeMap<String, Member> = transition
        .members
        .iter()
        .filter(|member| !unsent.contains(&member.object_id))
        .map(|member| (member.object_id.clone(), member.clone()))
        .collect();
    for object in &upserts {
        answered.insert(object.id.clone(), member(object));
    }
    let answered: Vec<Member> = answered.into_values().collect();
    let purges = purges(&caller, &scope, &baseline, &diff.removes, &upserts)?;
    let next = caller.save_position(
        &scope,
        pin,
        answered,
        &position.position_id,
        Some(&position.position_id),
    )?;
    let pending = sync_scope::diff_members(&next.members, &now);
    Ok(Response::new(ReadSyncDeltasResponse {
        contract_version: sync_scope::SYNC_CONTRACT.into(),
        upserts: upserts
            .into_iter()
            .map(|object| to_proto_obj(&object))
            .collect(),
        removed_object_ids: diff.removes,
        cursor: next.position_id,
        more: !pending.upserts.is_empty() || !pending.removes.is_empty(),
        resnapshot_required: false,
        purges,
        // Only a read that leaves nothing pending renews the deadline, so a
        // replica still holding data it must drop gains no time.
        offline_until_ms: if pending.upserts.is_empty() && pending.removes.is_empty() {
            offline_until(&scope)
        } else {
            0
        },
        wipe_required: false,
    }))
}

/// What the client must delete because the caller may no longer read it
/// (#1633). A removed object that still exists in the namespace but is
/// hidden from the caller is purged whole. An upserted object that no
/// longer shows a property the client read, while the property still
/// exists, purges that property: the names are ones the client already
/// held, so no hidden name is disclosed.
fn purges(
    caller: &Caller<'_>,
    scope: &SyncScope,
    baseline: &[Member],
    removes: &[String],
    upserts: &[domain::Object],
) -> Result<Vec<SyncPurge>, Status> {
    let db = caller.db();
    let stored = |id: &str| {
        db.get_object(id)
            .map(|object| object.filter(|object| object.namespace == scope.namespace))
            .map_err(Status::internal)
    };
    let mut purges = Vec::new();
    for id in removes {
        if let Some(object) = stored(id)?
            && !caller.visible(&object)
        {
            purges.push(SyncPurge {
                object_id: id.clone(),
                properties: Vec::new(),
            });
        }
    }
    let held: BTreeMap<&str, &[String]> = baseline
        .iter()
        .map(|member| (member.object_id.as_str(), member.properties.as_slice()))
        .collect();
    for object in upserts {
        let Some(read) = held.get(object.id.as_str()).filter(|read| !read.is_empty()) else {
            continue;
        };
        let lost: Vec<&String> = read
            .iter()
            .filter(|property| !object.properties.contains_key(*property))
            .collect();
        if lost.is_empty() {
            continue;
        }
        let Some(raw) = stored(&object.id)? else {
            continue;
        };
        let hidden: Vec<String> = lost
            .into_iter()
            .filter(|property| raw.properties.contains_key(*property))
            .cloned()
            .collect();
        if !hidden.is_empty() {
            purges.push(SyncPurge {
                object_id: object.id.clone(),
                properties: hidden,
            });
        }
    }
    purges.sort_by(|a, b| a.object_id.cmp(&b.object_id));
    Ok(purges)
}
