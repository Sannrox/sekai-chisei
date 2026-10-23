//! Stored embedding specs (#1609, ADR 0117): credential admins manage what
//! embedding catch-up embeds in a namespace they administer.

use super::*;
use crate::sekai::embedding_index::{EmbeddingSpec, EmbeddingStore, StoredEmbeddingSpec};

fn to_proto(stored: StoredEmbeddingSpec) -> EmbeddingSpecDefinition {
    let spec = stored.spec;
    EmbeddingSpecDefinition {
        namespace: spec.namespace,
        spec_id: spec.id,
        object_kind: spec.object_kind,
        properties: spec.properties,
        chunk_chars: u32::try_from(spec.chunk_chars).unwrap_or(u32::MAX),
        dimension: u32::try_from(spec.dimension).unwrap_or(u32::MAX),
        batch_size: u32::try_from(spec.batch_size).unwrap_or(u32::MAX),
        model: stored.model,
        updated_by: stored.updated_by,
        updated_at_ms: stored.updated_at_ms,
    }
}

/// Credential admin with the namespace grant, as for classification lattices.
fn authorize<T: 'static>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    namespace: &str,
    write: bool,
) -> Result<Vec<String>, Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    require_credential_admin(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), req)?;
    enforce_namespace_tenant_context(
        service.db.runtime(),
        tenant_context.as_ref(),
        namespace,
        write,
    )?;
    check_team_namespace(service.db.runtime(), &principals, namespace, write)?;
    Ok(principals)
}

pub(super) async fn put_embedding_spec(
    service: &SekaiServiceImpl,
    req: Request<PutEmbeddingSpecRequest>,
) -> Result<Response<PutEmbeddingSpecResponse>, Status> {
    let namespace = req
        .get_ref()
        .spec
        .as_ref()
        .map(|spec| spec.namespace.clone())
        .unwrap_or_default();
    let principals = authorize(service, &req, &namespace, true)?;
    let input = req
        .into_inner()
        .spec
        .ok_or_else(|| Status::invalid_argument("spec required"))?;
    let spec = EmbeddingSpec {
        id: input.spec_id,
        namespace: input.namespace,
        object_kind: input.object_kind,
        properties: input.properties,
        chunk_chars: input.chunk_chars as usize,
        dimension: input.dimension as usize,
        batch_size: input.batch_size as usize,
    };
    spec.validate()
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    // Only a hosted catalog route has an origin to classify as local or
    // external; route admission itself is checked on every catch-up.
    if !crate::provider_profile::resolve_provider_id(&input.model)
        .is_ok_and(crate::provider_profile::is_hosted_provider)
    {
        return Err(Status::invalid_argument(
            "model must name a hosted catalog route: hosted.<name>/<model>",
        ));
    }
    let stored = StoredEmbeddingSpec {
        spec,
        model: input.model,
        updated_by: principals.first().cloned().unwrap_or_default(),
        updated_at_ms: now_millis(),
        revision: 0,
    };
    service
        .db
        .runtime()
        .put_embedding_spec(&stored)
        .map_err(|_| Status::internal("embedding spec storage unavailable"))?;
    Ok(Response::new(PutEmbeddingSpecResponse {
        spec: Some(to_proto(stored)),
    }))
}

pub(super) async fn list_embedding_specs(
    service: &SekaiServiceImpl,
    req: Request<ListEmbeddingSpecsRequest>,
) -> Result<Response<ListEmbeddingSpecsResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    authorize(service, &req, &namespace, false)?;
    let specs = service
        .db
        .runtime()
        .list_embedding_specs(Some(&namespace))
        .map_err(|_| Status::internal("embedding spec storage unavailable"))?;
    Ok(Response::new(ListEmbeddingSpecsResponse {
        specs: specs.into_iter().map(to_proto).collect(),
    }))
}

pub(super) async fn delete_embedding_spec(
    service: &SekaiServiceImpl,
    req: Request<DeleteEmbeddingSpecRequest>,
) -> Result<Response<DeleteEmbeddingSpecResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    authorize(service, &req, &namespace, true)?;
    let deleted = service
        .db
        .runtime()
        .delete_embedding_spec(&namespace, &req.into_inner().spec_id)
        .map_err(|_| Status::internal("embedding spec storage unavailable"))?;
    Ok(Response::new(DeleteEmbeddingSpecResponse { deleted }))
}
