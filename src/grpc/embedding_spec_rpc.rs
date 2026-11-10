//! Stored embedding specs (#1609, ADR 0117): credential admins manage what
//! embedding catch-up embeds in a namespace they administer.

use super::*;
use crate::sekai::embedding_index::{
    EMBEDDING_SPEC_LIMIT, EmbeddingSpec, EmbeddingStore, StoredEmbeddingSpec,
};

/// `ListEmbeddingSpecs` page size cap, and the size of a page asking for 0.
const MAX_PAGE_SIZE: usize = 100;

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
        .map_err(|error| {
            if error == EMBEDDING_SPEC_LIMIT {
                Status::resource_exhausted(error)
            } else {
                Status::internal("embedding spec storage unavailable")
            }
        })?;
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
    let input = req.into_inner();
    let page_size = match usize::try_from(input.page_size) {
        Ok(0) => MAX_PAGE_SIZE,
        Ok(size) => size.min(MAX_PAGE_SIZE),
        Err(_) => return Err(Status::invalid_argument("page_size must not be negative")),
    };
    // A namespace holds a bounded number of specs, so one read pages them
    // by id. The token is the last id of the previous page. Sorted here, not
    // by the store, so order and token comparison agree whatever the
    // database collation.
    let mut specs = service
        .db
        .runtime()
        .list_embedding_specs(Some(&namespace))
        .map_err(|_| Status::internal("embedding spec storage unavailable"))?;
    specs.sort_by(|a, b| a.spec.id.cmp(&b.spec.id));
    let mut specs = specs
        .into_iter()
        .filter(|stored| stored.spec.id > input.page_token)
        .take(page_size + 1)
        .collect::<Vec<_>>();
    let next_page_token = if specs.len() > page_size {
        specs.truncate(page_size);
        specs
            .last()
            .map(|stored| stored.spec.id.clone())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(Response::new(ListEmbeddingSpecsResponse {
        specs: specs.into_iter().map(to_proto).collect(),
        next_page_token,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::embedding_index::{MAX_DIMENSION, MAX_SPECS_PER_NAMESPACE};
    use std::sync::Arc;
    use tonic::metadata::MetadataValue;

    const NS: &str = "embeds";
    const MODEL: &str = "hosted.local/embed-small";

    fn as_principal<T>(payload: T, principal: &str) -> Request<T> {
        let mut req = Request::new(payload);
        req.metadata_mut()
            .insert("x-principal", MetadataValue::try_from(principal).unwrap());
        req
    }

    fn definition(id: &str) -> EmbeddingSpecDefinition {
        EmbeddingSpecDefinition {
            namespace: NS.into(),
            spec_id: id.into(),
            object_kind: "note".into(),
            properties: vec!["title".into()],
            chunk_chars: 200,
            dimension: 4,
            batch_size: 8,
            model: MODEL.into(),
            ..Default::default()
        }
    }

    async fn put(
        svc: &SekaiServiceImpl,
        principal: &str,
        spec: EmbeddingSpecDefinition,
    ) -> Result<EmbeddingSpecDefinition, Status> {
        put_embedding_spec(
            svc,
            as_principal(PutEmbeddingSpecRequest { spec: Some(spec) }, principal),
        )
        .await
        .map(|response| response.into_inner().spec.unwrap())
    }

    async fn list(
        svc: &SekaiServiceImpl,
        page_size: i32,
        page_token: &str,
    ) -> Result<ListEmbeddingSpecsResponse, Status> {
        list_embedding_specs(
            svc,
            as_principal(
                ListEmbeddingSpecsRequest {
                    namespace: NS.into(),
                    page_size,
                    page_token: page_token.into(),
                },
                "root",
            ),
        )
        .await
        .map(Response::into_inner)
    }

    async fn delete(svc: &SekaiServiceImpl, id: &str) -> bool {
        delete_embedding_spec(
            svc,
            as_principal(
                DeleteEmbeddingSpecRequest {
                    namespace: NS.into(),
                    spec_id: id.into(),
                },
                "root",
            ),
        )
        .await
        .unwrap()
        .into_inner()
        .deleted
    }

    /// Put, list and delete through the RPC handlers on one backend:
    /// authorization, the route rule, the #2244 limits and paging.
    async fn exercise_spec_rpcs(db: RuntimeDb) {
        let svc = SekaiServiceImpl::new(crate::db::store::SekaiStore::from_shared_runtime(
            Arc::new(db),
        ));
        let (_, grants) = svc
            .db
            .runtime()
            .ensure_team_namespace(NS, "alice", security::Role::Admin, "local")
            .unwrap();
        for grant in grants {
            svc.security.add_grant(&grant);
        }

        // A namespace admin is not a credential admin.
        let denied = put(&svc, "alice", definition("notes")).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied, "{denied:?}");
        let builtin = EmbeddingSpecDefinition {
            model: "openai/text-embedding-3-small".into(),
            ..definition("notes")
        };
        let builtin = put(&svc, "root", builtin).await.unwrap_err();
        assert_eq!(builtin.code(), tonic::Code::InvalidArgument);
        let oversized = EmbeddingSpecDefinition {
            dimension: MAX_DIMENSION as u32 + 1,
            ..definition("notes")
        };
        let oversized = put(&svc, "root", oversized).await.unwrap_err();
        assert_eq!(oversized.code(), tonic::Code::InvalidArgument);

        let stored = put(&svc, "root", definition("notes")).await.unwrap();
        assert_eq!(stored.updated_by, "root");
        assert_eq!(list(&svc, 0, "").await.unwrap().specs, [stored]);

        // Fill the namespace; a further spec is refused, a replaced one is not.
        for index in 1..MAX_SPECS_PER_NAMESPACE {
            put(&svc, "root", definition(&format!("s{index:02}")))
                .await
                .unwrap();
        }
        let full = put(&svc, "root", definition("s99")).await.unwrap_err();
        assert_eq!(full.code(), tonic::Code::ResourceExhausted, "{full:?}");
        put(&svc, "root", definition("notes")).await.unwrap();

        // Pages of 5 cover every spec once, in id order.
        let mut paged = Vec::new();
        let mut token = String::new();
        loop {
            let page = list(&svc, 5, &token).await.unwrap();
            assert!(page.specs.len() <= 5);
            paged.extend(page.specs.into_iter().map(|spec| spec.spec_id));
            if page.next_page_token.is_empty() {
                break;
            }
            token = page.next_page_token;
        }
        let all = list(&svc, 0, "")
            .await
            .unwrap()
            .specs
            .into_iter()
            .map(|spec| spec.spec_id)
            .collect::<Vec<_>>();
        assert_eq!(all.len(), MAX_SPECS_PER_NAMESPACE);
        assert_eq!(paged, all);
        let negative = list(&svc, -1, "").await.unwrap_err();
        assert_eq!(negative.code(), tonic::Code::InvalidArgument);

        assert!(delete(&svc, "notes").await);
        assert!(!delete(&svc, "notes").await);
        put(&svc, "root", definition("s99")).await.unwrap();
    }

    #[tokio::test]
    async fn spec_rpcs_authorize_bound_and_page() {
        let db = RuntimeDb::memory();
        crate::chisei_store::apply_chisei_schema(&db);
        exercise_spec_rpcs(db).await;
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
    fn postgres_spec_rpcs_authorize_bound_and_page() {
        let scratch = crate::db::ScratchDatabase::create();
        let db = RuntimeDb::Postgres(Arc::new(scratch.connect()));
        // The PostgreSQL store blocks in place, so a multi-thread runtime.
        // The store drops after the runtime: closing its pool blocks.
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(exercise_spec_rpcs(db.clone()));
        drop(db);
    }
}
