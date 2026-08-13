//! Authorized link mutation behind one private interface.
//!
//! The gRPC adapter authenticates the caller and projects protobuf. This module
//! owns tenant and team-namespace admission, ACL write checks, marking
//! enforcement, ontology domain/range validation on create, and persist
//! ordering including fail-if-exists.

use super::*;

impl SekaiServiceImpl {
    pub(super) async fn create_authorized_link(
        &self,
        req: Request<CreateLinkRequest>,
    ) -> Result<Response<CreateLinkResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let inner = req.into_inner();
        let fail_if_exists = inner.fail_if_exists;
        let l = inner
            .link
            .ok_or(Status::invalid_argument("link required"))?;
        let mut endpoints = Vec::with_capacity(2);
        for object_id in [&l.from_id, &l.to_id] {
            let object = self
                .db
                .get_object(object_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("link endpoint not found"))?;
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &object.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &object.namespace, true)?;
            check_write(&self.security, object_id, &principals)?;
            enforce_object_marking_access(
                &self.db,
                &object,
                &principals,
                &format!("create_link:{object_id}"),
            )?;
            endpoints.push(object);
        }
        if self.db.get_link(&l.id).map_err(Status::internal)?.is_none() {
            let ontology = self.db.load_ontology_registry().map_err(Status::internal)?;
            validate_mapped_link(
                &ontology,
                &l.relation,
                &endpoints[0].kind,
                &endpoints[1].kind,
            )?;
        }
        let dl = domain::Link {
            id: l.id.clone(),
            from_id: l.from_id.clone(),
            to_id: l.to_id.clone(),
            relation: l.relation.clone(),
            created: l.created,
        };
        if fail_if_exists {
            if !self
                .db
                .create_link_once(&dl)
                .map_err(map_graph_mutation_error)?
            {
                return Err(Status::already_exists("link already exists"));
            }
        } else {
            self.db.create_link(&dl).map_err(map_graph_mutation_error)?;
        }
        Ok(Response::new(CreateLinkResponse { link: Some(l) }))
    }

    pub(super) async fn delete_authorized_link(
        &self,
        req: Request<DeleteLinkRequest>,
    ) -> Result<Response<DeleteLinkResponse>, Status> {
        let principals = caller_principals(&req);
        let tenant_context = request_tenant_context(&self.db, &req)?;
        require_authenticated(&principals)?;
        let id = req.into_inner().id;
        let Some(link) = self.db.get_link(&id).map_err(Status::internal)? else {
            return Ok(Response::new(DeleteLinkResponse {}));
        };
        for object_id in [&link.from_id, &link.to_id] {
            let object = self
                .db
                .get_object(object_id)
                .map_err(Status::internal)?
                .ok_or(Status::not_found("link endpoint not found"))?;
            enforce_namespace_tenant_context(
                &self.db,
                tenant_context.as_ref(),
                &object.namespace,
                true,
            )?;
            check_team_namespace(&self.db, &principals, &object.namespace, true)?;
            check_write(&self.security, object_id, &principals)?;
            enforce_object_marking_access(
                &self.db,
                &object,
                &principals,
                &format!("delete_link:{object_id}"),
            )?;
        }
        self.db.delete_link(&id).map_err(Status::internal)?;
        Ok(Response::new(DeleteLinkResponse {}))
    }
}

fn ontology_link_violations(
    registry: &ontology::OntologyRegistry,
    relation: &ontology::OntologyRelation,
    from_kind: &str,
    to_kind: &str,
) -> (bool, bool) {
    (
        !registry.kind_satisfies_class(from_kind, &relation.domain),
        !registry.kind_satisfies_class(to_kind, &relation.range),
    )
}

fn validate_mapped_link(
    registry: &ontology::OntologyRegistry,
    mapped_relation: &str,
    from_kind: &str,
    to_kind: &str,
) -> Result<(), Status> {
    if registry
        .constraints_for_mapped_relation(mapped_relation)
        .into_iter()
        .any(|relation| {
            let (domain, range) = ontology_link_violations(registry, relation, from_kind, to_kind);
            domain || range
        })
    {
        return Err(Status::failed_precondition(
            "link endpoints violate ontology constraint",
        ));
    }
    Ok(())
}
