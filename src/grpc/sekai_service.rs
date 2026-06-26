#![allow(clippy::result_large_err, clippy::collapsible_if, clippy::manual_clamp)]

use std::sync::Arc;
use tonic::{Request, Response, Status};

use super::pb::sekai::sekai_service_server::SekaiService;
use super::pb::sekai::*;
use crate::db::sekai::SekaiDb;
use crate::domain;
use crate::sekai::action::ActionExecutor;
use crate::sekai::schema::SchemaRegistry;
use crate::sekai::security::SecurityChecker;
use crate::sekai::{audit, coordination, dataset, function, security};

pub struct SekaiServiceImpl {
    db: Arc<SekaiDb>,
    actions: ActionExecutor,
    security: Arc<SecurityChecker>,
}

impl SekaiServiceImpl {
    pub fn new(db: Arc<SekaiDb>) -> Self {
        db.migrate_coordination();
        db.migrate_functions();
        db.migrate_grants();
        let security = Arc::new(SecurityChecker::new());
        let grants = db.list_all_grants().unwrap_or_default();
        security.load(&grants);
        Self {
            db,
            actions: ActionExecutor::new(),
            security,
        }
    }
}

fn caller_principals(req: &Request<impl std::any::Any>) -> Vec<String> {
    req.metadata()
        .get("x-principal")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["anonymous".to_string()])
}

fn require_authenticated(principals: &[String]) -> Result<(), Status> {
    if principals.is_empty() || principals.iter().all(|principal| principal == "anonymous") {
        return Err(Status::unauthenticated("principal required"));
    }
    Ok(())
}

fn check_read(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_access(object_id, &refs) {
        return Err(Status::permission_denied("access denied"));
    }
    Ok(())
}

fn check_write(
    security: &SecurityChecker,
    object_id: &str,
    principals: &[String],
) -> Result<(), Status> {
    let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
    if !security.can_write(object_id, &refs) {
        return Err(Status::permission_denied("write denied"));
    }
    Ok(())
}

fn principal_matches(owner_principal: &str, principals: &[String]) -> bool {
    !owner_principal.is_empty()
        && principals
            .iter()
            .any(|principal| principal == owner_principal)
}

fn check_scope_read(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    if principal_matches(&scope.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("scope access denied"))
    }
}

fn check_scope_write(
    scope: &coordination::ContentionScope,
    principals: &[String],
) -> Result<(), Status> {
    check_scope_read(scope, principals)
}

fn check_work_unit_read(
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_read(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit access denied"))
    }
}

fn check_work_unit_write(
    security: &SecurityChecker,
    work_unit: &coordination::WorkUnit,
    principals: &[String],
) -> Result<(), Status> {
    if !work_unit.target_object_id.is_empty() {
        check_write(security, &work_unit.target_object_id, principals)
    } else if principal_matches(&work_unit.owner_principal, principals) {
        Ok(())
    } else {
        Err(Status::permission_denied("work unit write denied"))
    }
}

fn to_proto_obj(o: &domain::Object) -> Object {
    Object {
        id: o.id.clone(),
        kind: o.kind.clone(),
        name: o.name.clone(),
        namespace: o.namespace.clone(),
        external_id: o.external_id.clone(),
        properties: o.properties.clone(),
        created: o.created,
        updated: o.updated,
    }
}

fn to_proto_link(l: &domain::Link) -> Link {
    Link {
        id: l.id.clone(),
        from_id: l.from_id.clone(),
        to_id: l.to_id.clone(),
        relation: l.relation.clone(),
        created: l.created,
    }
}

fn from_proto_obj(o: &Object) -> domain::Object {
    domain::Object {
        id: o.id.clone(),
        kind: o.kind.clone(),
        name: o.name.clone(),
        namespace: o.namespace.clone(),
        external_id: o.external_id.clone(),
        properties: o.properties.clone(),
        created: o.created,
        updated: o.updated,
    }
}

fn to_proto_dataset(d: &dataset::Dataset) -> Dataset {
    Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| ColumnDef {
                name: c.name.clone(),
                r#type: c.col_type.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}

fn from_proto_dataset(d: &Dataset) -> dataset::Dataset {
    dataset::Dataset {
        id: d.id.clone(),
        name: d.name.clone(),
        columns: d
            .columns
            .iter()
            .map(|c| dataset::ColumnDef {
                name: c.name.clone(),
                col_type: c.r#type.clone(),
            })
            .collect(),
        object_id: d.object_id.clone(),
        created: d.created,
    }
}

fn from_proto_row_filters(filters: &[RowFilter]) -> Vec<dataset::RowFilter> {
    filters
        .iter()
        .map(|f| dataset::RowFilter {
            column: f.column.clone(),
            op: f.op.clone(),
            value: f.value.clone(),
        })
        .collect()
}

fn to_proto_virtual_table(vt: &dataset::VirtualTable) -> VirtualTable {
    VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: vt
            .filters
            .iter()
            .map(|f| RowFilter {
                column: f.column.clone(),
                op: f.op.clone(),
                value: f.value.clone(),
            })
            .collect(),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}

fn from_proto_virtual_table(vt: &VirtualTable) -> dataset::VirtualTable {
    dataset::VirtualTable {
        id: vt.id.clone(),
        name: vt.name.clone(),
        dataset_id: vt.dataset_id.clone(),
        filters: from_proto_row_filters(&vt.filters),
        columns: vt.columns.clone(),
        created: vt.created,
    }
}

fn to_proto_function(f: &function::Function) -> Function {
    Function {
        name: f.name.clone(),
        description: f.description.clone(),
        params: f
            .params
            .iter()
            .map(|p| FuncParam {
                name: p.name.clone(),
                r#type: p.param_type.clone(),
                required: p.required,
            })
            .collect(),
        pipeline: f
            .pipeline
            .iter()
            .map(|s| PipelineStep {
                op: s.op.clone(),
                kind: s.kind.clone(),
                property: s.property.clone(),
                value: s.value.clone(),
                relation: s.relation.clone(),
                dir: s.dir.clone(),
                func: s.func.clone(),
                field: s.field.clone(),
                r#as: s.alias.clone(),
            })
            .collect(),
        created: f.created,
    }
}

fn from_proto_function(f: &Function) -> function::Function {
    function::Function {
        name: f.name.clone(),
        description: f.description.clone(),
        params: f
            .params
            .iter()
            .map(|p| function::FuncParam {
                name: p.name.clone(),
                param_type: p.r#type.clone(),
                required: p.required,
            })
            .collect(),
        pipeline: f
            .pipeline
            .iter()
            .map(|s| function::PipelineStep {
                op: s.op.clone(),
                kind: s.kind.clone(),
                property: s.property.clone(),
                value: s.value.clone(),
                relation: s.relation.clone(),
                dir: s.dir.clone(),
                func: s.func.clone(),
                field: s.field.clone(),
                alias: s.r#as.clone(),
            })
            .collect(),
        created: f.created,
    }
}

fn to_proto_grant(g: &security::Grant) -> Grant {
    Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role: g.role.as_str().to_string(),
        created: g.created,
    }
}

fn to_proto_contention_scope(scope: &coordination::ContentionScope) -> ContentionScope {
    ContentionScope {
        id: scope.id.clone(),
        name: scope.name.clone(),
        parent_scope_id: scope.parent_scope_id.clone(),
        max_concurrency: scope.max_concurrency,
        admission_policy: scope.admission_policy.clone(),
        heartbeat_ttl_seconds: scope.heartbeat_ttl_seconds,
        timeout_seconds: scope.timeout_seconds,
        owner_principal: scope.owner_principal.clone(),
        created: scope.created,
        updated: scope.updated,
    }
}

fn from_proto_contention_scope(scope: &ContentionScope) -> coordination::ContentionScope {
    coordination::ContentionScope {
        id: scope.id.clone(),
        name: scope.name.clone(),
        parent_scope_id: scope.parent_scope_id.clone(),
        max_concurrency: scope.max_concurrency,
        admission_policy: scope.admission_policy.clone(),
        heartbeat_ttl_seconds: scope.heartbeat_ttl_seconds,
        timeout_seconds: scope.timeout_seconds,
        owner_principal: scope.owner_principal.clone(),
        created: scope.created,
        updated: scope.updated,
    }
}

fn to_proto_work_unit(work_unit: &coordination::WorkUnit) -> WorkUnit {
    WorkUnit {
        id: work_unit.id.clone(),
        kind: work_unit.kind.clone(),
        actor: work_unit.actor.clone(),
        target_object_id: work_unit.target_object_id.clone(),
        status: work_unit.status.clone(),
        requested_spec: work_unit.requested_spec.clone(),
        scope_id: work_unit.scope_id.clone(),
        priority: work_unit.priority,
        timeout_seconds: work_unit.timeout_seconds,
        heartbeat_ttl_seconds: work_unit.heartbeat_ttl_seconds,
        created_at: work_unit.created_at,
        admitted_at: work_unit.admitted_at,
        started_at: work_unit.started_at,
        finished_at: work_unit.finished_at,
        last_heartbeat_at: work_unit.last_heartbeat_at,
        failure_reason: work_unit.failure_reason.clone(),
        cancel_reason: work_unit.cancel_reason.clone(),
        owner_principal: work_unit.owner_principal.clone(),
        creator_principal: work_unit.creator_principal.clone(),
        idempotency_key: work_unit.idempotency_key.clone(),
        updated_at: work_unit.updated_at,
    }
}

fn from_proto_work_unit(work_unit: &WorkUnit) -> coordination::WorkUnit {
    coordination::WorkUnit {
        id: work_unit.id.clone(),
        kind: work_unit.kind.clone(),
        actor: work_unit.actor.clone(),
        target_object_id: work_unit.target_object_id.clone(),
        status: work_unit.status.clone(),
        requested_spec: work_unit.requested_spec.clone(),
        scope_id: work_unit.scope_id.clone(),
        priority: work_unit.priority,
        timeout_seconds: work_unit.timeout_seconds,
        heartbeat_ttl_seconds: work_unit.heartbeat_ttl_seconds,
        created_at: work_unit.created_at,
        admitted_at: work_unit.admitted_at,
        started_at: work_unit.started_at,
        finished_at: work_unit.finished_at,
        last_heartbeat_at: work_unit.last_heartbeat_at,
        failure_reason: work_unit.failure_reason.clone(),
        cancel_reason: work_unit.cancel_reason.clone(),
        owner_principal: work_unit.owner_principal.clone(),
        creator_principal: work_unit.creator_principal.clone(),
        idempotency_key: work_unit.idempotency_key.clone(),
        updated_at: work_unit.updated_at,
    }
}

fn to_proto_reservation(reservation: &coordination::Reservation) -> Reservation {
    Reservation {
        id: reservation.id.clone(),
        work_unit_id: reservation.work_unit_id.clone(),
        scope_id: reservation.scope_id.clone(),
        status: reservation.status.clone(),
        lease_owner: reservation.lease_owner.clone(),
        leased_at: reservation.leased_at,
        expires_at: reservation.expires_at,
        released_at: reservation.released_at,
        created_at: reservation.created_at,
    }
}

fn to_proto_run_event(event: &coordination::RunEvent) -> RunEvent {
    RunEvent {
        id: event.id.clone(),
        work_unit_id: event.work_unit_id.clone(),
        event_type: event.event_type.clone(),
        message: event.message.clone(),
        evidence: event.evidence.clone(),
        created_at: event.created_at,
    }
}

fn from_proto_work_unit_filter(filter: &WorkUnitFilter) -> coordination::WorkUnitFilter {
    coordination::WorkUnitFilter {
        status: if filter.status.is_empty() {
            None
        } else {
            Some(filter.status.clone())
        },
        actor: if filter.actor.is_empty() {
            None
        } else {
            Some(filter.actor.clone())
        },
        scope_id: if filter.scope_id.is_empty() {
            None
        } else {
            Some(filter.scope_id.clone())
        },
        target_object_id: if filter.target_object_id.is_empty() {
            None
        } else {
            Some(filter.target_object_id.clone())
        },
        owner_principal: if filter.owner_principal.is_empty() {
            None
        } else {
            Some(filter.owner_principal.clone())
        },
        statuses: filter.statuses.clone(),
        created_after: filter.created_after,
        updated_after: filter.updated_after,
        creator_principal: if filter.creator_principal.is_empty() {
            None
        } else {
            Some(filter.creator_principal.clone())
        },
        page_token: if filter.page_token.is_empty() {
            None
        } else {
            Some(filter.page_token.clone())
        },
        limit: filter.limit,
        offset: filter.offset,
    }
}

fn to_proto_snapshot(snapshot: &coordination::CoordinationSnapshot) -> CoordinationSnapshot {
    CoordinationSnapshot {
        pending_count: snapshot.pending_count,
        running_count: snapshot.running_count,
        stale_count: snapshot.stale_count,
        active_reservation_count: snapshot.active_reservation_count,
        oldest_pending_age_ms: snapshot.oldest_pending_age_ms,
        oldest_running_age_ms: snapshot.oldest_running_age_ms,
        stale_reservation_count: snapshot.stale_reservation_count,
        blocked_scopes: snapshot
            .blocked_scopes
            .iter()
            .map(|scope| ScopeBlockage {
                scope_id: scope.scope_id.clone(),
                scope_name: scope.scope_name.clone(),
                reason: scope.reason.clone(),
                pending_count: scope.pending_count,
                active_count: scope.active_count,
            })
            .collect(),
    }
}

fn dedup_principal(principals: &[String]) -> String {
    principals.first().cloned().unwrap_or_default()
}

fn trim_page<T>(items: &mut Vec<T>, limit: i32) {
    if limit > 0 && items.len() > limit as usize {
        items.truncate(limit as usize);
    }
}

fn initialize_work_unit_for_create(work_unit: &mut coordination::WorkUnit, principal: &str) {
    if work_unit.owner_principal.is_empty() {
        work_unit.owner_principal = principal.into();
    }
    if work_unit.creator_principal.is_empty() {
        work_unit.creator_principal = principal.into();
    }
    work_unit.status = coordination::WORK_UNIT_STATUS_PENDING.into();
    work_unit.admitted_at = 0;
    work_unit.started_at = 0;
    work_unit.finished_at = 0;
    work_unit.last_heartbeat_at = 0;
    work_unit.failure_reason.clear();
    work_unit.cancel_reason.clear();
    work_unit.updated_at = work_unit.created_at;
}

fn aggregate_reconcile_summary(
    summary: &mut coordination::ReconcileSummary,
    next: coordination::ReconcileSummary,
) {
    summary.work_units_reconciled += next.work_units_reconciled;
    summary.reservations_released += next.reservations_released;
    summary.details.extend(next.details);
}

fn reconcile_owned_scope(
    db: &SekaiDb,
    now_ms: i64,
    scope_id: String,
    dry_run: bool,
    limit: i32,
    summary: &mut coordination::ReconcileSummary,
) -> Result<(), Status> {
    if limit > 0 && summary.work_units_reconciled >= limit {
        return Ok(());
    }
    let remaining = if limit > 0 {
        limit - summary.work_units_reconciled
    } else {
        0
    };
    let next = db
        .reconcile_work_units(
            now_ms,
            &coordination::ReconcileFilter {
                dry_run,
                work_unit_id: None,
                scope_id: Some(scope_id),
                limit: remaining,
            },
        )
        .map_err(Status::internal)?;
    aggregate_reconcile_summary(summary, next);
    Ok(())
}

fn from_proto_grant(g: &Grant) -> Result<security::Grant, Status> {
    let role = security::Role::parse(&g.role).ok_or(Status::invalid_argument("invalid role"))?;
    Ok(security::Grant {
        id: g.id.clone(),
        object_id: g.object_id.clone(),
        principal: g.principal.clone(),
        role,
        created: g.created,
    })
}

#[tonic::async_trait]
impl SekaiService for SekaiServiceImpl {
    async fn create_object(
        &self,
        req: Request<CreateObjectRequest>,
    ) -> Result<Response<CreateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let obj = req
            .into_inner()
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        if obj.id.is_empty() {
            return Err(Status::invalid_argument("id required"));
        }
        check_write(&self.security, &obj.id, &principals)?;
        let domain_obj = from_proto_obj(&obj);
        SchemaRegistry::new()
            .validate(&domain_obj)
            .map_err(Status::invalid_argument)?;
        self.db
            .create_object(&domain_obj)
            .map_err(Status::internal)?;
        Ok(Response::new(CreateObjectResponse { object: Some(obj) }))
    }
    async fn get_object(
        &self,
        req: Request<GetObjectRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let id = req.into_inner().id;
        check_read(&self.security, &id, &principals)?;
        let obj = self
            .db
            .get_object(&id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    async fn update_object(
        &self,
        req: Request<UpdateObjectRequest>,
    ) -> Result<Response<UpdateObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let obj = req
            .into_inner()
            .object
            .ok_or(Status::invalid_argument("object required"))?;
        check_write(&self.security, &obj.id, &principals)?;
        let domain_obj = from_proto_obj(&obj);
        self.db
            .update_object(&domain_obj)
            .map_err(Status::internal)?;
        Ok(Response::new(UpdateObjectResponse { object: Some(obj) }))
    }
    async fn delete_object(
        &self,
        req: Request<DeleteObjectRequest>,
    ) -> Result<Response<DeleteObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let id = req.into_inner().id;
        check_write(&self.security, &id, &principals)?;
        self.db.delete_object(&id).map_err(Status::internal)?;
        Ok(Response::new(DeleteObjectResponse {}))
    }
    async fn list_objects(
        &self,
        req: Request<ListObjectsRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let f = req.into_inner().filter.unwrap_or_default();
        let filter = domain::ListFilter {
            kind: if f.kind.is_empty() {
                None
            } else {
                Some(f.kind)
            },
            name: if f.name.is_empty() {
                None
            } else {
                Some(f.name)
            },
            namespace: if f.namespace.is_empty() {
                None
            } else {
                Some(f.namespace)
            },
        };
        let objs = self.db.list_objects(&filter).map_err(Status::internal)?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        let filtered = self.security.filter_objects(&objs, &refs);
        Ok(Response::new(ListObjectsResponse {
            objects: filtered.iter().map(|o| to_proto_obj(o)).collect(),
        }))
    }
    async fn find_by_external_id(
        &self,
        req: Request<FindByExternalIdRequest>,
    ) -> Result<Response<GetObjectResponse>, Status> {
        let principals = caller_principals(&req);
        let external_id = req.into_inner().external_id;
        let obj = self
            .db
            .find_by_external_id(&external_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("not found"))?;
        check_read(&self.security, &obj.id, &principals)?;
        Ok(Response::new(GetObjectResponse {
            object: Some(to_proto_obj(&obj)),
        }))
    }
    async fn find_by_property(
        &self,
        req: Request<FindByPropertyRequest>,
    ) -> Result<Response<ListObjectsResponse>, Status> {
        let principals = caller_principals(&req);
        let r = req.into_inner();
        let objs = self
            .db
            .find_by_property(&r.kind, &r.key, &r.value)
            .map_err(Status::internal)?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        let filtered = self.security.filter_objects(&objs, &refs);
        Ok(Response::new(ListObjectsResponse {
            objects: filtered.iter().map(|o| to_proto_obj(o)).collect(),
        }))
    }
    async fn create_link(
        &self,
        req: Request<CreateLinkRequest>,
    ) -> Result<Response<CreateLinkResponse>, Status> {
        let l = req
            .into_inner()
            .link
            .ok_or(Status::invalid_argument("link required"))?;
        let dl = domain::Link {
            id: l.id.clone(),
            from_id: l.from_id.clone(),
            to_id: l.to_id.clone(),
            relation: l.relation.clone(),
            created: l.created,
        };
        self.db.create_link(&dl).map_err(Status::internal)?;
        Ok(Response::new(CreateLinkResponse { link: Some(l) }))
    }
    async fn delete_link(
        &self,
        req: Request<DeleteLinkRequest>,
    ) -> Result<Response<DeleteLinkResponse>, Status> {
        self.db
            .delete_link(&req.into_inner().id)
            .map_err(Status::internal)?;
        Ok(Response::new(DeleteLinkResponse {}))
    }
    async fn get_links(
        &self,
        req: Request<GetLinksRequest>,
    ) -> Result<Response<GetLinksResponse>, Status> {
        let r = req.into_inner();
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let links = self
            .db
            .get_links(&r.object_id, &r.relation, &dir)
            .map_err(Status::internal)?;
        Ok(Response::new(GetLinksResponse {
            links: links.iter().map(to_proto_link).collect(),
        }))
    }
    async fn get_linked_objects(
        &self,
        req: Request<GetLinkedObjectsRequest>,
    ) -> Result<Response<GetLinkedObjectsResponse>, Status> {
        let r = req.into_inner();
        let dir = if r.direction == "incoming" {
            domain::Direction::Incoming
        } else {
            domain::Direction::Outgoing
        };
        let objs = self
            .db
            .get_linked_objects(&r.object_id, &r.relation, &dir)
            .map_err(Status::internal)?;
        Ok(Response::new(GetLinkedObjectsResponse {
            objects: objs.iter().map(to_proto_obj).collect(),
        }))
    }
    async fn traverse(
        &self,
        req: Request<TraverseRequest>,
    ) -> Result<Response<TraverseResponse>, Status> {
        let q = req
            .into_inner()
            .query
            .ok_or(Status::invalid_argument("query required"))?;
        let gq = crate::sekai::query::GraphQuery {
            start_id: q.start_id,
            start_external_id: q.start_external_id,
            relations: q.relations,
            direction: if q.direction == "incoming" {
                domain::Direction::Incoming
            } else {
                domain::Direction::Outgoing
            },
            max_depth: q.max_depth,
            kind_filter: q.kind_filter,
            property_filter: q.property_filter,
        };
        let res = crate::sekai::query::traverse(&self.db, &gq).map_err(Status::internal)?;
        Ok(Response::new(TraverseResponse {
            result: Some(GraphResult {
                objects: res.objects.iter().map(to_proto_obj).collect(),
                links: res.links.iter().map(to_proto_link).collect(),
            }),
        }))
    }
    async fn list_schema_types(
        &self,
        _req: Request<ListSchemaTypesRequest>,
    ) -> Result<Response<ListSchemaTypesResponse>, Status> {
        Ok(Response::new(ListSchemaTypesResponse { types: vec![] }))
    }
    async fn execute_action(
        &self,
        req: Request<ExecuteActionRequest>,
    ) -> Result<Response<ExecuteActionResponse>, Status> {
        let r = req
            .into_inner()
            .request
            .ok_or(Status::invalid_argument("request required"))?;
        let msg = self
            .actions
            .execute(&self.db, &r.action, &r.params, &r.actor)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(ExecuteActionResponse {
            result: Some(ActionResult {
                action: r.action,
                message: msg,
            }),
        }))
    }
    async fn get_lineage(
        &self,
        req: Request<GetLineageRequest>,
    ) -> Result<Response<GetLineageResponse>, Status> {
        let r = req.into_inner();
        let res = crate::sekai::lineage::get_lineage(&self.db, &r.object_id, r.max_nodes as usize)
            .map_err(Status::internal)?;
        let nodes = res
            .nodes
            .iter()
            .map(|n| LineageNode {
                object: Some(to_proto_obj(&n.object)),
                role: n.role.clone(),
                ephemeral: n.ephemeral,
            })
            .collect();
        let edges = res
            .edges
            .iter()
            .map(|e| LineageEdge {
                from: e.from.clone(),
                to: e.to.clone(),
                relation: e.relation.clone(),
            })
            .collect();
        Ok(Response::new(GetLineageResponse {
            result: Some(LineageResult {
                nodes,
                edges,
                truncated: res.truncated,
            }),
        }))
    }
    async fn create_contention_scope(
        &self,
        req: Request<CreateContentionScopeRequest>,
    ) -> Result<Response<CreateContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let mut scope = inner
            .scope
            .ok_or(Status::invalid_argument("scope required"))
            .map(|scope| from_proto_contention_scope(&scope))?;
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if let Some(existing) = self
            .db
            .get_dedup_request(&inner.request_id, "create_contention_scope")
            .map_err(Status::internal)?
            .filter(|record| record.principal == owner)
        {
            let scope = self
                .db
                .get_contention_scope(&existing.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            return Ok(Response::new(CreateContentionScopeResponse {
                scope: Some(to_proto_contention_scope(&scope)),
            }));
        }
        if scope.owner_principal.is_empty() {
            scope.owner_principal = owner;
        }
        self.db
            .create_contention_scope(&scope)
            .map_err(Status::invalid_argument)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "create_contention_scope".into(),
                principal: dedup_principal(&principals),
                scope_id: scope.id.clone(),
                work_unit_id: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CreateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn update_contention_scope(
        &self,
        req: Request<UpdateContentionScopeRequest>,
    ) -> Result<Response<UpdateContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let scope = inner
            .scope
            .ok_or(Status::invalid_argument("scope required"))
            .map(|scope| from_proto_contention_scope(&scope))?;
        let existing = self
            .db
            .get_contention_scope(&scope.id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_write(&existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "update_contention_scope")
            .map_err(Status::internal)?
        {
            if record.scope_id == scope.id && record.principal == dedup_principal(&principals) {
                let scope = self
                    .db
                    .get_contention_scope(&scope.id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("scope not found"))?;
                return Ok(Response::new(UpdateContentionScopeResponse {
                    scope: Some(to_proto_contention_scope(&scope)),
                }));
            }
        }
        self.db
            .update_contention_scope(&scope)
            .map_err(Status::invalid_argument)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "update_contention_scope".into(),
                principal: dedup_principal(&principals),
                scope_id: scope.id.clone(),
                work_unit_id: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(UpdateContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn get_contention_scope(
        &self,
        req: Request<GetContentionScopeRequest>,
    ) -> Result<Response<GetContentionScopeResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let scope = self
            .db
            .get_contention_scope(&req.into_inner().id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_read(&scope, &principals)?;
        Ok(Response::new(GetContentionScopeResponse {
            scope: Some(to_proto_contention_scope(&scope)),
        }))
    }
    async fn list_contention_scopes(
        &self,
        req: Request<ListContentionScopesRequest>,
    ) -> Result<Response<ListContentionScopesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let scopes = self
            .db
            .list_contention_scopes()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|scope| check_scope_read(scope, &principals).is_ok())
            .map(|scope| to_proto_contention_scope(&scope))
            .collect();
        Ok(Response::new(ListContentionScopesResponse { scopes }))
    }
    async fn create_work_unit(
        &self,
        req: Request<CreateWorkUnitRequest>,
    ) -> Result<Response<CreateWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let mut work_unit = inner
            .work_unit
            .ok_or(Status::invalid_argument("work_unit required"))
            .map(|work_unit| from_proto_work_unit(&work_unit))?;
        let principal = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        if let Some(existing) = self
            .db
            .get_dedup_request(&inner.request_id, "create_work_unit")
            .map_err(Status::internal)?
            .filter(|record| record.principal == principal)
        {
            let work_unit = self
                .db
                .get_work_unit(&existing.work_unit_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("work unit not found"))?;
            return Ok(Response::new(CreateWorkUnitResponse {
                work_unit: Some(to_proto_work_unit(&work_unit)),
            }));
        }
        if !work_unit.idempotency_key.is_empty() {
            if let Some(existing) = self
                .db
                .get_work_unit_by_idempotency_key(&work_unit.idempotency_key)
                .map_err(Status::internal)?
            {
                check_work_unit_read(&self.security, &existing, &principals)?;
                return Ok(Response::new(CreateWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&existing)),
                }));
            }
        }
        if !work_unit.target_object_id.is_empty() {
            check_write(&self.security, &work_unit.target_object_id, &principals)?;
        }
        let scope = self
            .db
            .get_contention_scope(&work_unit.scope_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("scope not found"))?;
        check_scope_read(&scope, &principals)?;
        initialize_work_unit_for_create(&mut work_unit, &principal);
        self.db
            .create_work_unit(&work_unit)
            .map_err(Status::invalid_argument)?;
        let event = coordination::RunEvent {
            id: format!("evt:{}:created:{}", work_unit.id, work_unit.created_at),
            work_unit_id: work_unit.id.clone(),
            event_type: "created".into(),
            message: "work unit created".into(),
            evidence: std::collections::HashMap::from([(
                "scope_id".into(),
                work_unit.scope_id.clone(),
            )]),
            created_at: work_unit.created_at,
        };
        self.db.append_run_event(&event).map_err(Status::internal)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "create_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CreateWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn get_work_unit(
        &self,
        req: Request<GetWorkUnitRequest>,
    ) -> Result<Response<GetWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let work_unit = self
            .db
            .get_work_unit(&req.into_inner().id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.security, &work_unit, &principals)?;
        Ok(Response::new(GetWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn list_work_units(
        &self,
        req: Request<ListWorkUnitsRequest>,
    ) -> Result<Response<ListWorkUnitsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let filter = req.into_inner().filter.unwrap_or_default();
        let limit = filter.limit;
        let mut work_units = self
            .db
            .list_work_units(&from_proto_work_unit_filter(&filter))
            .map_err(Status::internal)?
            .into_iter()
            .filter(|work_unit| {
                check_work_unit_read(&self.security, work_unit, &principals).is_ok()
            })
            .collect::<Vec<_>>();
        let next_page_token = if limit > 0 && work_units.len() > limit as usize {
            let next = work_units
                .get((limit as usize).saturating_sub(1))
                .map(|work_unit| coordination::make_page_token(work_unit.created_at, &work_unit.id))
                .unwrap_or_default();
            trim_page(&mut work_units, limit);
            next
        } else {
            String::new()
        };
        Ok(Response::new(ListWorkUnitsResponse {
            work_units: work_units.iter().map(to_proto_work_unit).collect(),
            next_page_token,
        }))
    }
    async fn try_admit_work_unit(
        &self,
        req: Request<TryAdmitWorkUnitRequest>,
    ) -> Result<Response<TryAdmitWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let work_unit = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &work_unit, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "try_admit_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id
                && record.principal == dedup_principal(&principals)
            {
                let current = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                let reservations = self
                    .db
                    .list_reservations(&coordination::ReservationFilter {
                        work_unit_id: Some(work_unit_id.clone()),
                        status: Some(coordination::RESERVATION_STATUS_ACTIVE.into()),
                        ..Default::default()
                    })
                    .map_err(Status::internal)?;
                return Ok(Response::new(TryAdmitWorkUnitResponse {
                    admitted: current.status == coordination::WORK_UNIT_STATUS_RUNNING,
                    queue_position: 0,
                    reason: String::new(),
                    work_unit: Some(to_proto_work_unit(&current)),
                    reservations: reservations.iter().map(to_proto_reservation).collect(),
                }));
            }
        }
        let owner = principals
            .first()
            .cloned()
            .ok_or(Status::unauthenticated("principal required"))?;
        let result = self
            .db
            .try_admit_work_unit(&work_unit_id, &owner, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "try_admit_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: result.work_unit.scope_id.clone(),
                work_unit_id: result.work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(TryAdmitWorkUnitResponse {
            admitted: result.admitted,
            queue_position: result.queue_position,
            reason: result.reason,
            work_unit: Some(to_proto_work_unit(&result.work_unit)),
            reservations: result
                .reservations
                .iter()
                .map(to_proto_reservation)
                .collect(),
        }))
    }
    async fn heartbeat_work_unit(
        &self,
        req: Request<HeartbeatWorkUnitRequest>,
    ) -> Result<Response<HeartbeatWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "heartbeat_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(HeartbeatWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .heartbeat_work_unit(&work_unit_id, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "heartbeat_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(HeartbeatWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn complete_work_unit(
        &self,
        req: Request<CompleteWorkUnitRequest>,
    ) -> Result<Response<CompleteWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "complete_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(CompleteWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .complete_work_unit(&work_unit_id, chrono::Utc::now().timestamp_millis())
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "complete_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CompleteWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn fail_work_unit(
        &self,
        req: Request<FailWorkUnitRequest>,
    ) -> Result<Response<FailWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "fail_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == inner.work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&inner.work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(FailWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .fail_work_unit(
                &inner.work_unit_id,
                &inner.failure_reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "fail_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(FailWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn cancel_work_unit(
        &self,
        req: Request<CancelWorkUnitRequest>,
    ) -> Result<Response<CancelWorkUnitResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let existing = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "cancel_work_unit")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == inner.work_unit_id {
                let work_unit = self
                    .db
                    .get_work_unit(&inner.work_unit_id)
                    .map_err(Status::internal)?
                    .ok_or(Status::not_found("work unit not found"))?;
                return Ok(Response::new(CancelWorkUnitResponse {
                    work_unit: Some(to_proto_work_unit(&work_unit)),
                }));
            }
        }
        let work_unit = self
            .db
            .cancel_work_unit(
                &inner.work_unit_id,
                &inner.cancel_reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::failed_precondition)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "cancel_work_unit".into(),
                principal: dedup_principal(&principals),
                scope_id: work_unit.scope_id.clone(),
                work_unit_id: work_unit.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(CancelWorkUnitResponse {
            work_unit: Some(to_proto_work_unit(&work_unit)),
        }))
    }
    async fn release_reservation(
        &self,
        req: Request<ReleaseReservationRequest>,
    ) -> Result<Response<ReleaseReservationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit_id = inner.work_unit_id;
        let existing = self
            .db
            .get_work_unit(&work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_write(&self.security, &existing, &principals)?;
        if let Some(record) = self
            .db
            .get_dedup_request(&inner.request_id, "release_reservation")
            .map_err(Status::internal)?
        {
            if record.work_unit_id == work_unit_id {
                return Ok(Response::new(ReleaseReservationResponse { released: 0 }));
            }
        }
        let released = self
            .db
            .release_reservations_for_work_unit(
                &work_unit_id,
                chrono::Utc::now().timestamp_millis(),
            )
            .map_err(Status::internal)?;
        self.db
            .record_dedup_request(&coordination::RequestDedup {
                request_id: inner.request_id,
                operation: "release_reservation".into(),
                principal: dedup_principal(&principals),
                scope_id: existing.scope_id.clone(),
                work_unit_id: existing.id.clone(),
                created_at: chrono::Utc::now().timestamp_millis(),
            })
            .map_err(Status::internal)?;
        Ok(Response::new(ReleaseReservationResponse { released }))
    }
    async fn list_reservations(
        &self,
        req: Request<ListReservationsRequest>,
    ) -> Result<Response<ListReservationsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let reservations = self
            .db
            .list_reservations(&coordination::ReservationFilter {
                work_unit_id: if inner.work_unit_id.is_empty() {
                    None
                } else {
                    Some(inner.work_unit_id)
                },
                scope_id: if inner.scope_id.is_empty() {
                    None
                } else {
                    Some(inner.scope_id)
                },
                status: if inner.status.is_empty() {
                    None
                } else {
                    Some(inner.status)
                },
            })
            .map_err(Status::internal)?;
        let mut visible = Vec::new();
        for reservation in reservations {
            if let Some(work_unit) = self
                .db
                .get_work_unit(&reservation.work_unit_id)
                .map_err(Status::internal)?
            {
                if check_work_unit_read(&self.security, &work_unit, &principals).is_ok() {
                    visible.push(to_proto_reservation(&reservation));
                }
            }
        }
        Ok(Response::new(ListReservationsResponse {
            reservations: visible,
        }))
    }
    async fn list_run_events(
        &self,
        req: Request<ListRunEventsRequest>,
    ) -> Result<Response<ListRunEventsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let work_unit = self
            .db
            .get_work_unit(&inner.work_unit_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("work unit not found"))?;
        check_work_unit_read(&self.security, &work_unit, &principals)?;
        let limit = inner.limit;
        let mut events = self
            .db
            .list_run_events(
                &inner.work_unit_id,
                inner.limit,
                inner.after,
                &inner.event_types,
                if inner.page_token.is_empty() {
                    None
                } else {
                    Some(inner.page_token.as_str())
                },
            )
            .map_err(Status::internal)?
            .into_iter()
            .collect::<Vec<_>>();
        let next_page_token = if limit > 0 && events.len() > limit as usize {
            let next = events
                .get((limit as usize).saturating_sub(1))
                .map(|event| coordination::make_page_token(event.created_at, &event.id))
                .unwrap_or_default();
            trim_page(&mut events, limit);
            next
        } else {
            String::new()
        };
        Ok(Response::new(ListRunEventsResponse {
            events: events.iter().map(to_proto_run_event).collect(),
            next_page_token,
        }))
    }
    async fn reconcile_work_units(
        &self,
        req: Request<ReconcileWorkUnitsRequest>,
    ) -> Result<Response<ReconcileWorkUnitsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let summary = if !inner.work_unit_id.is_empty() {
            let work_unit = self
                .db
                .get_work_unit(&inner.work_unit_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("work unit not found"))?;
            let scope = self
                .db
                .get_contention_scope(&work_unit.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            check_scope_write(&scope, &principals)?;
            if !inner.scope_id.is_empty() && inner.scope_id != work_unit.scope_id {
                return Ok(Response::new(ReconcileWorkUnitsResponse {
                    work_units_reconciled: 0,
                    reservations_released: 0,
                    details: Vec::new(),
                }));
            }
            self.db
                .reconcile_work_units(
                    now_ms,
                    &coordination::ReconcileFilter {
                        dry_run: inner.dry_run,
                        work_unit_id: Some(inner.work_unit_id),
                        scope_id: if inner.scope_id.is_empty() {
                            None
                        } else {
                            Some(inner.scope_id)
                        },
                        limit: inner.limit,
                    },
                )
                .map_err(Status::internal)?
        } else if !inner.scope_id.is_empty() {
            let scope = self
                .db
                .get_contention_scope(&inner.scope_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("scope not found"))?;
            check_scope_write(&scope, &principals)?;
            self.db
                .reconcile_work_units(
                    now_ms,
                    &coordination::ReconcileFilter {
                        dry_run: inner.dry_run,
                        work_unit_id: None,
                        scope_id: Some(inner.scope_id),
                        limit: inner.limit,
                    },
                )
                .map_err(Status::internal)?
        } else {
            let mut owned_scope_ids: Vec<String> = self
                .db
                .list_contention_scopes()
                .map_err(Status::internal)?
                .into_iter()
                .filter(|scope| principal_matches(&scope.owner_principal, &principals))
                .map(|scope| scope.id)
                .collect();
            owned_scope_ids.sort();
            if owned_scope_ids.is_empty() {
                return Err(Status::permission_denied(
                    "reconcile requires scope ownership",
                ));
            }
            let mut summary = coordination::ReconcileSummary::default();
            for scope_id in owned_scope_ids {
                reconcile_owned_scope(
                    &self.db,
                    now_ms,
                    scope_id,
                    inner.dry_run,
                    inner.limit,
                    &mut summary,
                )?;
            }
            summary
        };
        Ok(Response::new(ReconcileWorkUnitsResponse {
            work_units_reconciled: summary.work_units_reconciled,
            reservations_released: summary.reservations_released,
            details: summary
                .details
                .iter()
                .map(|detail| ReconciliationDetail {
                    work_unit_id: detail.work_unit_id.clone(),
                    reservation_id: detail.reservation_id.clone(),
                    reason: detail.reason.clone(),
                    action: detail.action.clone(),
                })
                .collect(),
        }))
    }
    async fn get_coordination_snapshot(
        &self,
        req: Request<GetCoordinationSnapshotRequest>,
    ) -> Result<Response<GetCoordinationSnapshotResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let visible_scopes = self
            .db
            .list_contention_scopes()
            .map_err(Status::internal)?
            .into_iter()
            .any(|scope| principal_matches(&scope.owner_principal, &principals));
        if !visible_scopes {
            return Err(Status::permission_denied(
                "snapshot requires scope ownership",
            ));
        }
        let snapshot = self
            .db
            .coordination_snapshot(chrono::Utc::now().timestamp_millis())
            .map_err(Status::internal)?;
        Ok(Response::new(GetCoordinationSnapshotResponse {
            snapshot: Some(to_proto_snapshot(&snapshot)),
        }))
    }
    // --- Remaining RPCs return unimplemented for now (wired in detail later) ---
    async fn create_function(
        &self,
        req: Request<CreateFunctionRequest>,
    ) -> Result<Response<CreateFunctionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let function = req
            .into_inner()
            .function
            .ok_or(Status::invalid_argument("function required"))?;
        let parsed = from_proto_function(&function);
        self.db
            .create_function(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateFunctionResponse {
            function: Some(to_proto_function(&parsed)),
        }))
    }
    async fn list_functions(
        &self,
        req: Request<ListFunctionsRequest>,
    ) -> Result<Response<ListFunctionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let functions = self
            .db
            .list_functions()
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_function)
            .collect();
        Ok(Response::new(ListFunctionsResponse { functions }))
    }
    async fn execute_function(
        &self,
        req: Request<ExecuteFunctionRequest>,
    ) -> Result<Response<ExecuteFunctionResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let function = self
            .db
            .get_function(&inner.name)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("function not found"))?;
        let refs: Vec<&str> = principals.iter().map(|s| s.as_str()).collect();
        let result = function::execute_with_filter(&self.db, &function, &inner.params, |object| {
            self.security.can_access(&object.id, &refs)
        })
        .map_err(Status::invalid_argument)?;
        Ok(Response::new(ExecuteFunctionResponse {
            result: Some(FunctionResult {
                objects: result.objects.iter().map(to_proto_obj).collect(),
                aggregates: result.aggregates,
            }),
        }))
    }
    async fn create_dataset(
        &self,
        req: Request<CreateDatasetRequest>,
    ) -> Result<Response<CreateDatasetResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let dataset = req
            .into_inner()
            .dataset
            .ok_or(Status::invalid_argument("dataset required"))?;
        let parsed = from_proto_dataset(&dataset);
        if !parsed.object_id.is_empty() {
            check_write(&self.security, &parsed.object_id, &principals)?;
        }
        self.db
            .create_dataset(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateDatasetResponse {
            dataset: Some(to_proto_dataset(&parsed)),
        }))
    }
    async fn list_datasets(
        &self,
        req: Request<ListDatasetsRequest>,
    ) -> Result<Response<ListDatasetsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let datasets = self
            .db
            .list_datasets()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|dataset| {
                dataset.object_id.is_empty()
                    || check_read(&self.security, &dataset.object_id, &principals).is_ok()
            })
            .collect::<Vec<_>>()
            .iter()
            .map(to_proto_dataset)
            .collect();
        Ok(Response::new(ListDatasetsResponse { datasets }))
    }
    async fn append_rows(
        &self,
        req: Request<AppendRowsRequest>,
    ) -> Result<Response<AppendRowsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let dataset = self
            .db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_write(&self.security, &dataset.object_id, &principals)?;
        }
        let rows: Vec<_> = inner.rows.into_iter().map(|r| r.values).collect();
        let count = self
            .db
            .append_rows(&inner.dataset_id, &rows)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(AppendRowsResponse { count }))
    }
    async fn query_rows(
        &self,
        req: Request<QueryRowsRequest>,
    ) -> Result<Response<QueryRowsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let dataset = self
            .db
            .get_dataset(&inner.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_read(&self.security, &dataset.object_id, &principals)?;
        }
        let query = inner.query.unwrap_or_default();
        let rows = self
            .db
            .query_rows(
                &inner.dataset_id,
                &dataset::RowQuery {
                    filters: from_proto_row_filters(&query.filters),
                    columns: query.columns,
                    limit: query.limit,
                    offset: query.offset,
                },
            )
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(QueryRowsResponse {
            rows: rows.into_iter().map(|values| Row { values }).collect(),
        }))
    }
    async fn create_virtual_table(
        &self,
        req: Request<CreateVirtualTableRequest>,
    ) -> Result<Response<CreateVirtualTableResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let table = req
            .into_inner()
            .table
            .ok_or(Status::invalid_argument("table required"))?;
        let parsed = from_proto_virtual_table(&table);
        let dataset = self
            .db
            .get_dataset(&parsed.dataset_id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("dataset not found"))?;
        if !dataset.object_id.is_empty() {
            check_write(&self.security, &dataset.object_id, &principals)?;
        }
        self.db
            .create_virtual_table(&parsed)
            .map_err(Status::invalid_argument)?;
        Ok(Response::new(CreateVirtualTableResponse {
            table: Some(to_proto_virtual_table(&parsed)),
        }))
    }
    async fn list_virtual_tables(
        &self,
        req: Request<ListVirtualTablesRequest>,
    ) -> Result<Response<ListVirtualTablesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tables = self
            .db
            .list_virtual_tables()
            .map_err(Status::internal)?
            .into_iter()
            .filter(|table| {
                self.db
                    .get_dataset(&table.dataset_id)
                    .ok()
                    .flatten()
                    .map(|dataset| {
                        dataset.object_id.is_empty()
                            || check_read(&self.security, &dataset.object_id, &principals).is_ok()
                    })
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>()
            .iter()
            .map(to_proto_virtual_table)
            .collect();
        Ok(Response::new(ListVirtualTablesResponse { tables }))
    }
    async fn create_grant(
        &self,
        req: Request<CreateGrantRequest>,
    ) -> Result<Response<CreateGrantResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let grant = req
            .into_inner()
            .grant
            .ok_or(Status::invalid_argument("grant required"))?;
        let parsed = from_proto_grant(&grant)?;
        check_write(&self.security, &parsed.object_id, &principals)?;
        self.db
            .create_grant(&parsed)
            .map_err(Status::invalid_argument)?;
        self.security.add_grant(&parsed);
        Ok(Response::new(CreateGrantResponse {
            grant: Some(to_proto_grant(&parsed)),
        }))
    }
    async fn delete_grant(
        &self,
        req: Request<DeleteGrantRequest>,
    ) -> Result<Response<DeleteGrantResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        let existing = self
            .db
            .get_grant(&id)
            .map_err(Status::internal)?
            .ok_or(Status::not_found("grant not found"))?;
        check_write(&self.security, &existing.object_id, &principals)?;
        let deleted = self.db.delete_grant(&id).map_err(Status::internal)?;
        if let Some(grant) = deleted {
            self.security
                .remove_grant(&grant.object_id, &grant.principal);
        }
        Ok(Response::new(DeleteGrantResponse {}))
    }
    async fn list_grants(
        &self,
        req: Request<ListGrantsRequest>,
    ) -> Result<Response<ListGrantsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let object_id = req.into_inner().object_id;
        check_write(&self.security, &object_id, &principals)?;
        let grants = self
            .db
            .list_grants(&object_id)
            .map_err(Status::internal)?
            .iter()
            .map(to_proto_grant)
            .collect();
        Ok(Response::new(ListGrantsResponse { grants }))
    }
    async fn check_access(
        &self,
        req: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_read(&self.security, &inner.object_id, &principals)?;
        let refs: Vec<&str> = inner.principals.iter().map(String::as_str).collect();
        Ok(Response::new(CheckAccessResponse {
            allowed: self.security.can_access(&inner.object_id, &refs),
        }))
    }
    async fn list_decisions(
        &self,
        req: Request<ListDecisionsRequest>,
    ) -> Result<Response<ListDecisionsResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let visible_limit = if inner.limit > 0 {
            inner.limit as usize
        } else {
            100
        };
        let batch_size = visible_limit.max(50).min(200);
        let max_scan = visible_limit.saturating_mul(10).max(200);
        let actor_filter = if inner.actor.is_empty() {
            None
        } else {
            Some(inner.actor.clone())
        };
        let action_filter = if inner.action.is_empty() {
            None
        } else {
            Some(inner.action.clone())
        };
        let mut decisions = Vec::new();
        let mut offset = 0;
        let mut scanned = 0usize;
        while decisions.len() < visible_limit && scanned < max_scan {
            let batch = self
                .db
                .list_decisions(&audit::DecisionFilter {
                    actor: actor_filter.clone(),
                    action: action_filter.clone(),
                    after: inner.after,
                    limit: batch_size as i32,
                    offset,
                })
                .map_err(Status::internal)?;
            if batch.is_empty() {
                break;
            }
            scanned += batch.len();
            offset += batch.len() as i32;
            for decision in batch {
                if decision.target_id.is_empty()
                    || check_read(&self.security, &decision.target_id, &principals).is_err()
                {
                    continue;
                }
                decisions.push(Decision {
                    id: decision.id,
                    timestamp: decision.timestamp,
                    actor: decision.actor,
                    action: decision.action,
                    reason: decision.reason,
                    evidence: decision.evidence,
                    target_id: decision.target_id,
                    outcome: decision.outcome,
                });
                if decisions.len() >= visible_limit {
                    break;
                }
            }
        }
        if decisions.len() < visible_limit && scanned >= max_scan {
            return Err(Status::resource_exhausted(
                "decision visibility scan limit exceeded; refine filters",
            ));
        }
        Ok(Response::new(ListDecisionsResponse { decisions }))
    }
    async fn list_object_changes(
        &self,
        req: Request<ListObjectChangesRequest>,
    ) -> Result<Response<ListObjectChangesResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        check_read(&self.security, &inner.object_id, &principals)?;
        let changes = self
            .db
            .list_object_changes(&inner.object_id, inner.limit, inner.offset)
            .map_err(Status::internal)?
            .into_iter()
            .map(|c| ObjectChange {
                id: c.id,
                object_id: c.object_id,
                field: c.field,
                old_value: c.old_value,
                new_value: c.new_value,
                changed_by: c.changed_by,
                timestamp: c.timestamp,
            })
            .collect();
        Ok(Response::new(ListObjectChangesResponse { changes }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tonic::metadata::MetadataValue;

    fn service() -> SekaiServiceImpl {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());
        db.migrate_datasets();
        db.migrate_functions();
        db.migrate_grants();
        db.migrate_audit();
        SekaiServiceImpl::new(db)
    }

    fn with_principal<T>(payload: T) -> Request<T> {
        with_named_principal(payload, "tester")
    }

    fn with_named_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    #[tokio::test]
    async fn dataset_rpc_round_trip() {
        let svc = service();
        let created = svc
            .create_dataset(with_principal(CreateDatasetRequest {
                dataset: Some(Dataset {
                    id: "ds1".into(),
                    name: "metrics".into(),
                    columns: vec![ColumnDef {
                        name: "value".into(),
                        r#type: "int".into(),
                    }],
                    object_id: "".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.dataset.unwrap().id, "ds1");

        let rows = vec![
            Row {
                values: HashMap::from([("value".into(), "1".into())]),
            },
            Row {
                values: HashMap::from([("value".into(), "2".into())]),
            },
        ];
        let append = svc
            .append_rows(with_principal(AppendRowsRequest {
                dataset_id: "ds1".into(),
                rows,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(append.count, 2);

        let queried = svc
            .query_rows(with_principal(QueryRowsRequest {
                dataset_id: "ds1".into(),
                query: Some(RowQuery {
                    filters: vec![RowFilter {
                        column: "value".into(),
                        op: "gte".into(),
                        value: "2".into(),
                    }],
                    columns: vec![],
                    limit: 0,
                    offset: 0,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(queried.rows.len(), 1);
    }

    #[tokio::test]
    async fn function_rpc_round_trip() {
        let svc = service();
        svc.create_object(with_principal(CreateObjectRequest {
            object: Some(Object {
                id: "c1".into(),
                kind: "component".into(),
                name: "comp".into(),
                namespace: "".into(),
                external_id: "".into(),
                properties: HashMap::from([
                    ("language".into(), "rust".into()),
                    ("task_total".into(), "5".into()),
                ]),
                created: 0,
                updated: 0,
            }),
        }))
        .await
        .unwrap();

        svc.create_function(with_principal(CreateFunctionRequest {
            function: Some(Function {
                name: "sum_tasks".into(),
                description: "".into(),
                params: vec![FuncParam {
                    name: "lang".into(),
                    r#type: "string".into(),
                    required: true,
                }],
                pipeline: vec![
                    PipelineStep {
                        op: "filter".into(),
                        kind: "component".into(),
                        property: "language".into(),
                        value: "$lang".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "".into(),
                        field: "".into(),
                        r#as: "".into(),
                    },
                    PipelineStep {
                        op: "aggregate".into(),
                        kind: "".into(),
                        property: "".into(),
                        value: "".into(),
                        relation: "".into(),
                        dir: "".into(),
                        func: "sum".into(),
                        field: "task_total".into(),
                        r#as: "total".into(),
                    },
                ],
                created: 1,
            }),
        }))
        .await
        .unwrap();

        let executed = svc
            .execute_function(with_principal(ExecuteFunctionRequest {
                name: "sum_tasks".into(),
                params: HashMap::from([("lang".into(), "rust".into())]),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(executed.result.unwrap().aggregates["total"], "5");
    }

    #[tokio::test]
    async fn grant_and_audit_rpcs_round_trip() {
        let svc = service();
        let admin_grant = security::Grant {
            id: "admin".into(),
            object_id: "o1".into(),
            principal: "tester".into(),
            role: security::Role::Admin,
            created: 0,
        };
        svc.db.create_grant(&admin_grant).unwrap();
        svc.security.add_grant(&admin_grant);
        svc.db
            .record_decision(&audit::Decision {
                id: "d1".into(),
                timestamp: 10,
                actor: "tester".into(),
                action: "create".into(),
                reason: "".into(),
                evidence: HashMap::new(),
                target_id: "o1".into(),
                outcome: "ok".into(),
            })
            .unwrap();
        svc.db
            .record_object_change(&audit::ObjectChange {
                id: "c1".into(),
                object_id: "o1".into(),
                field: "name".into(),
                old_value: "a".into(),
                new_value: "b".into(),
                changed_by: "tester".into(),
                timestamp: 11,
            })
            .unwrap();

        let created = svc
            .create_grant(with_principal(CreateGrantRequest {
                grant: Some(Grant {
                    id: "g1".into(),
                    object_id: "o1".into(),
                    principal: "alice".into(),
                    role: "viewer".into(),
                    created: 1,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.grant.unwrap().principal, "alice");

        let access = svc
            .check_access(with_principal(CheckAccessRequest {
                object_id: "o1".into(),
                principals: vec!["alice".into()],
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(access.allowed);

        let listed = svc
            .list_decisions(with_principal(ListDecisionsRequest {
                actor: "tester".into(),
                action: "".into(),
                after: 0,
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.decisions.len(), 1);

        let changes = svc
            .list_object_changes(with_principal(ListObjectChangesRequest {
                object_id: "o1".into(),
                limit: 10,
                offset: 0,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(changes.changes.len(), 1);
    }

    #[tokio::test]
    async fn coordination_rpcs_round_trip() {
        let svc = service();
        let scope = svc
            .create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: "req-scope-1".into(),
                scope: Some(ContentionScope {
                    id: "scope-1".into(),
                    name: "build".into(),
                    parent_scope_id: String::new(),
                    max_concurrency: 1,
                    admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                    heartbeat_ttl_seconds: 30,
                    timeout_seconds: 60,
                    owner_principal: String::new(),
                    created: 100,
                    updated: 100,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .scope
            .unwrap();
        assert_eq!(scope.owner_principal, "tester");

        let work_unit = svc
            .create_work_unit(with_principal(CreateWorkUnitRequest {
                work_unit: Some(WorkUnit {
                    id: "wu-1".into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: "cargo test -q".into(),
                    scope_id: "scope-1".into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 101,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "idem-wu-1".into(),
                    updated_at: 101,
                }),
                request_id: "req-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(work_unit.owner_principal, "tester");

        let admitted = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-admit-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted);
        assert_eq!(admitted.reservations.len(), 1);

        let reservations = svc
            .list_reservations(with_principal(ListReservationsRequest {
                work_unit_id: "wu-1".into(),
                scope_id: String::new(),
                status: coordination::RESERVATION_STATUS_ACTIVE.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reservations.reservations.len(), 1);

        let heartbeat = svc
            .heartbeat_work_unit(with_principal(HeartbeatWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-heartbeat-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert!(heartbeat.last_heartbeat_at > 0);

        let completed = svc
            .complete_work_unit(with_principal(CompleteWorkUnitRequest {
                work_unit_id: "wu-1".into(),
                request_id: "req-complete-wu-1".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(completed.status, coordination::WORK_UNIT_STATUS_COMPLETED);

        let events = svc
            .list_run_events(with_principal(ListRunEventsRequest {
                work_unit_id: "wu-1".into(),
                limit: 20,
                after: 0,
                event_types: vec![],
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == "created")
        );
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == "admitted")
        );
        assert!(
            events
                .events
                .iter()
                .any(|event| event.event_type == coordination::WORK_UNIT_STATUS_COMPLETED)
        );
    }

    #[tokio::test]
    async fn coordination_hierarchy_blocks_siblings_and_snapshot_reports_contention() {
        let svc = service();
        for scope in [
            ContentionScope {
                id: "root".into(),
                name: "gradle".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 100,
                updated: 100,
            },
            ContentionScope {
                id: "child-a".into(),
                name: "gradle/a".into(),
                parent_scope_id: "root".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 101,
                updated: 101,
            },
            ContentionScope {
                id: "child-b".into(),
                name: "gradle/b".into(),
                parent_scope_id: "root".into(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 102,
                updated: 102,
            },
        ] {
            svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: format!("req-scope-{}", scope.id),
                scope: Some(scope),
            }))
            .await
            .unwrap();
        }
        for (id, scope_id, created_at) in [("wu-a", "child-a", 200), ("wu-b", "child-b", 201)] {
            svc.create_work_unit(with_principal(CreateWorkUnitRequest {
                work_unit: Some(WorkUnit {
                    id: id.into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: format!("run {}", id),
                    scope_id: scope_id.into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: format!("idem-{}", id),
                    updated_at: created_at,
                }),
                request_id: format!("req-{}", id),
            }))
            .await
            .unwrap();
        }

        let admitted = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-a".into(),
                request_id: "req-admit-wu-a".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(admitted.admitted);

        let blocked = svc
            .try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
                work_unit_id: "wu-b".into(),
                request_id: "req-admit-wu-b".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!blocked.admitted);
        assert!(blocked.reason.contains("saturated"));

        let snapshot = svc
            .get_coordination_snapshot(with_principal(GetCoordinationSnapshotRequest {}))
            .await
            .unwrap()
            .into_inner()
            .snapshot
            .unwrap();
        assert_eq!(snapshot.pending_count, 1);
        assert_eq!(snapshot.running_count, 1);
        assert!(!snapshot.blocked_scopes.is_empty());
    }

    #[tokio::test]
    async fn coordination_create_and_transition_requests_are_idempotent() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-idem".into(),
            scope: Some(ContentionScope {
                id: "scope-idem".into(),
                name: "idem".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();

        let create = CreateWorkUnitRequest {
            request_id: "req-create-idem".into(),
            work_unit: Some(WorkUnit {
                id: "wu-idem".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "echo hi".into(),
                scope_id: "scope-idem".into(),
                priority: 0,
                timeout_seconds: 60,
                heartbeat_ttl_seconds: 30,
                created_at: 2,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "idem-key-1".into(),
                updated_at: 2,
            }),
        };
        let first = svc
            .create_work_unit(with_principal(create.clone()))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        let second = svc
            .create_work_unit(with_principal(create))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(first.id, second.id);

        let admit = TryAdmitWorkUnitRequest {
            work_unit_id: "wu-idem".into(),
            request_id: "req-admit-idem".into(),
        };
        let first_admit = svc
            .try_admit_work_unit(with_principal(admit.clone()))
            .await
            .unwrap()
            .into_inner();
        let second_admit = svc
            .try_admit_work_unit(with_principal(admit))
            .await
            .unwrap()
            .into_inner();
        assert!(first_admit.admitted);
        assert!(second_admit.admitted);

        let complete = CompleteWorkUnitRequest {
            work_unit_id: "wu-idem".into(),
            request_id: "req-complete-idem".into(),
        };
        let first_complete = svc
            .complete_work_unit(with_principal(complete.clone()))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        let second_complete = svc
            .complete_work_unit(with_principal(complete))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(
            first_complete.status,
            coordination::WORK_UNIT_STATUS_COMPLETED
        );
        assert_eq!(second_complete.status, first_complete.status);
    }

    #[tokio::test]
    async fn coordination_filters_paginates_and_dry_run_reconciles() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-filter".into(),
            scope: Some(ContentionScope {
                id: "scope-filter".into(),
                name: "filter".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 10,
                updated: 10,
            }),
        }))
        .await
        .unwrap();

        for (id, key, created_at) in [("wu-f1", "filter-1", 11), ("wu-f2", "filter-2", 12)] {
            svc.create_work_unit(with_principal(CreateWorkUnitRequest {
                request_id: format!("req-create-{}", id),
                work_unit: Some(WorkUnit {
                    id: id.into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: format!("spec {}", id),
                    scope_id: "scope-filter".into(),
                    priority: 0,
                    timeout_seconds: 1,
                    heartbeat_ttl_seconds: 1,
                    created_at,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: key.into(),
                    updated_at: created_at,
                }),
            }))
            .await
            .unwrap();
        }
        svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-f1".into(),
            request_id: "req-admit-f1".into(),
        }))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-f1").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-f1"],
            )
            .unwrap();

        let first_page = svc
            .list_work_units(with_principal(ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-filter".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![
                        coordination::WORK_UNIT_STATUS_PENDING.into(),
                        coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    ],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: String::new(),
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(first_page.work_units.len(), 1);
        assert!(!first_page.next_page_token.is_empty());

        let second_page = svc
            .list_work_units(with_principal(ListWorkUnitsRequest {
                filter: Some(WorkUnitFilter {
                    status: String::new(),
                    actor: String::new(),
                    scope_id: "scope-filter".into(),
                    target_object_id: String::new(),
                    owner_principal: String::new(),
                    limit: 1,
                    offset: 0,
                    statuses: vec![
                        coordination::WORK_UNIT_STATUS_PENDING.into(),
                        coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    ],
                    created_after: 0,
                    updated_after: 0,
                    creator_principal: String::new(),
                    page_token: first_page.next_page_token,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(second_page.work_units.len(), 1);

        let reconcile = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: true,
                work_unit_id: "wu-f1".into(),
                scope_id: String::new(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!reconcile.details.is_empty());

        let still_running = svc
            .get_work_unit(with_principal(GetWorkUnitRequest { id: "wu-f1".into() }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn create_work_unit_ignores_client_supplied_lifecycle_state() {
        let svc = service();
        svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
            request_id: "req-scope-sanitize".into(),
            scope: Some(ContentionScope {
                id: "scope-sanitize".into(),
                name: "sanitize".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 30,
                timeout_seconds: 60,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            }),
        }))
        .await
        .unwrap();

        let created = svc
            .create_work_unit(with_principal(CreateWorkUnitRequest {
                request_id: "req-create-sanitize".into(),
                work_unit: Some(WorkUnit {
                    id: "wu-sanitize".into(),
                    kind: "build".into(),
                    actor: "tester".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_RUNNING.into(),
                    requested_spec: "echo hi".into(),
                    scope_id: "scope-sanitize".into(),
                    priority: 0,
                    timeout_seconds: 60,
                    heartbeat_ttl_seconds: 30,
                    created_at: 5,
                    admitted_at: 99,
                    started_at: 99,
                    finished_at: 99,
                    last_heartbeat_at: 99,
                    failure_reason: "boom".into(),
                    cancel_reason: "stop".into(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "sanitize-1".into(),
                    updated_at: 77,
                }),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();

        assert_eq!(created.status, coordination::WORK_UNIT_STATUS_PENDING);
        assert_eq!(created.admitted_at, 0);
        assert_eq!(created.started_at, 0);
        assert_eq!(created.finished_at, 0);
        assert_eq!(created.last_heartbeat_at, 0);
        assert!(created.failure_reason.is_empty());
        assert!(created.cancel_reason.is_empty());
        assert_eq!(created.updated_at, created.created_at);
    }

    #[tokio::test]
    async fn reconcile_requires_scope_ownership_for_target_scope() {
        let svc = service();
        for (scope_id, owner, created) in [("scope-a", "tester", 1), ("scope-b", "other", 2)] {
            svc.create_contention_scope(with_named_principal(
                CreateContentionScopeRequest {
                    request_id: format!("req-{}", scope_id),
                    scope: Some(ContentionScope {
                        id: scope_id.into(),
                        name: scope_id.into(),
                        parent_scope_id: String::new(),
                        max_concurrency: 1,
                        admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                        heartbeat_ttl_seconds: 1,
                        timeout_seconds: 1,
                        owner_principal: String::new(),
                        created,
                        updated: created,
                    }),
                },
                owner,
            ))
            .await
            .unwrap();
        }

        svc.create_work_unit(with_named_principal(
            CreateWorkUnitRequest {
                request_id: "req-wu-other".into(),
                work_unit: Some(WorkUnit {
                    id: "wu-other".into(),
                    kind: "build".into(),
                    actor: "other".into(),
                    target_object_id: String::new(),
                    status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                    requested_spec: "run".into(),
                    scope_id: "scope-b".into(),
                    priority: 0,
                    timeout_seconds: 1,
                    heartbeat_ttl_seconds: 1,
                    created_at: 10,
                    admitted_at: 0,
                    started_at: 0,
                    finished_at: 0,
                    last_heartbeat_at: 0,
                    failure_reason: String::new(),
                    cancel_reason: String::new(),
                    owner_principal: String::new(),
                    creator_principal: String::new(),
                    idempotency_key: "other-1".into(),
                    updated_at: 10,
                }),
            },
            "other",
        ))
        .await
        .unwrap();
        svc.try_admit_work_unit(with_named_principal(
            TryAdmitWorkUnitRequest {
                work_unit_id: "wu-other".into(),
                request_id: "req-admit-other".into(),
            },
            "other",
        ))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-other").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-other"],
            )
            .unwrap();

        let denied = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: false,
                work_unit_id: String::new(),
                scope_id: "scope-b".into(),
                limit: 10,
            }))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let still_running = svc
            .get_work_unit(with_named_principal(
                GetWorkUnitRequest {
                    id: "wu-other".into(),
                },
                "other",
            ))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }

    #[tokio::test]
    async fn reconcile_with_mismatched_scope_and_work_unit_returns_empty() {
        let svc = service();
        for scope in [
            ContentionScope {
                id: "scope-one".into(),
                name: "scope-one".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 1,
                updated: 1,
            },
            ContentionScope {
                id: "scope-two".into(),
                name: "scope-two".into(),
                parent_scope_id: String::new(),
                max_concurrency: 1,
                admission_policy: coordination::ADMISSION_POLICY_FIFO.into(),
                heartbeat_ttl_seconds: 1,
                timeout_seconds: 1,
                owner_principal: String::new(),
                created: 2,
                updated: 2,
            },
        ] {
            svc.create_contention_scope(with_principal(CreateContentionScopeRequest {
                request_id: format!("req-{}", scope.id),
                scope: Some(scope),
            }))
            .await
            .unwrap();
        }

        svc.create_work_unit(with_principal(CreateWorkUnitRequest {
            request_id: "req-wu-mismatch".into(),
            work_unit: Some(WorkUnit {
                id: "wu-mismatch".into(),
                kind: "build".into(),
                actor: "tester".into(),
                target_object_id: String::new(),
                status: coordination::WORK_UNIT_STATUS_PENDING.into(),
                requested_spec: "run".into(),
                scope_id: "scope-one".into(),
                priority: 0,
                timeout_seconds: 1,
                heartbeat_ttl_seconds: 1,
                created_at: 10,
                admitted_at: 0,
                started_at: 0,
                finished_at: 0,
                last_heartbeat_at: 0,
                failure_reason: String::new(),
                cancel_reason: String::new(),
                owner_principal: String::new(),
                creator_principal: String::new(),
                idempotency_key: "mismatch-1".into(),
                updated_at: 10,
            }),
        }))
        .await
        .unwrap();
        svc.try_admit_work_unit(with_principal(TryAdmitWorkUnitRequest {
            work_unit_id: "wu-mismatch".into(),
            request_id: "req-admit-mismatch".into(),
        }))
        .await
        .unwrap();
        let mut stale_candidate = svc.db.get_work_unit("wu-mismatch").unwrap().unwrap();
        stale_candidate.started_at = 1;
        stale_candidate.last_heartbeat_at = 1;
        stale_candidate.updated_at = 1;
        svc.db.update_work_unit(&stale_candidate).unwrap();
        svc.db
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE sekai_reservations SET expires_at = 1 WHERE work_unit_id = ?1",
                rusqlite::params!["wu-mismatch"],
            )
            .unwrap();

        let reconcile = svc
            .reconcile_work_units(with_principal(ReconcileWorkUnitsRequest {
                dry_run: false,
                work_unit_id: "wu-mismatch".into(),
                scope_id: "scope-two".into(),
                limit: 10,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reconcile.work_units_reconciled, 0);
        assert_eq!(reconcile.reservations_released, 0);
        assert!(reconcile.details.is_empty());

        let still_running = svc
            .get_work_unit(with_principal(GetWorkUnitRequest {
                id: "wu-mismatch".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .work_unit
            .unwrap();
        assert_eq!(still_running.status, coordination::WORK_UNIT_STATUS_RUNNING);
    }
}
