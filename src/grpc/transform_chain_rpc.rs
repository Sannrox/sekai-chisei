//! Experimental transform chain reads (#3084): list a namespace's chains, get
//! one chain, and page a chain's runs.
//!
//! Each read needs namespace read access. A caller bound to another tenant
//! sees the namespace as missing. Runs carry the same receipt reveal rule as
//! GetTransformChainRun, which also lives here as a facade route.

use super::rpc_data::{to_proto_transform_chain, to_proto_transform_chain_run};
use super::*;

const CHAIN_RUN_PAGE_MAX: usize = 100;

fn authorize_chain_read<T: 'static>(
    service: &SekaiServiceImpl,
    req: &Request<T>,
    namespace: &str,
) -> Result<Vec<String>, Status> {
    let principals = caller_principals(req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), req)?;
    if namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace is required"));
    }
    if let Some(context) = tenant_context.as_ref() {
        enforce_namespace_tenant_context(service.db.runtime(), Some(context), namespace, false)
            .map_err(|_| Status::not_found("not found"))?;
    }
    check_team_namespace(service.db.runtime(), &principals, namespace, false)?;
    Ok(principals)
}

async fn list_transform_chains(
    service: &SekaiServiceImpl,
    req: Request<ListTransformChainsRequest>,
) -> Result<Response<ListTransformChainsResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    authorize_chain_read(service, &req, &namespace)?;
    let chains = service
        .db
        .runtime()
        .list_transform_chains(&namespace)
        .map_err(Status::internal)?;
    Ok(Response::new(ListTransformChainsResponse {
        chains: chains.iter().map(to_proto_transform_chain).collect(),
    }))
}

async fn get_transform_chain(
    service: &SekaiServiceImpl,
    req: Request<GetTransformChainRequest>,
) -> Result<Response<GetTransformChainResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    authorize_chain_read(service, &req, &namespace)?;
    let chain = service
        .db
        .runtime()
        .get_transform_chain(&namespace, &req.get_ref().chain_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("not found"))?;
    Ok(Response::new(GetTransformChainResponse {
        chain: Some(to_proto_transform_chain(&chain)),
    }))
}

/// The page token is `<created_at_ms>:<run_id>` of the last run returned.
/// Callers treat it as opaque.
fn parse_run_page_token(token: &str) -> Result<Option<(i64, &str)>, Status> {
    if token.is_empty() {
        return Ok(None);
    }
    token
        .split_once(':')
        .and_then(|(ms, run_id)| Some((ms.parse().ok()?, run_id)))
        .filter(|(_, run_id)| !run_id.is_empty())
        .map(Some)
        .ok_or_else(|| Status::invalid_argument("page_token is not valid"))
}

async fn list_transform_chain_runs(
    service: &SekaiServiceImpl,
    req: Request<ListTransformChainRunsRequest>,
) -> Result<Response<ListTransformChainRunsResponse>, Status> {
    let namespace = req.get_ref().namespace.clone();
    let principals = authorize_chain_read(service, &req, &namespace)?;
    let inner = req.into_inner();
    let page_size = match usize::try_from(inner.page_size) {
        Ok(0) => CHAIN_RUN_PAGE_MAX,
        Ok(size) => size.min(CHAIN_RUN_PAGE_MAX),
        Err(_) => return Err(Status::invalid_argument("page_size must not be negative")),
    };
    let after = parse_run_page_token(&inner.page_token)?;
    let mut runs = service
        .db
        .runtime()
        .list_transform_chain_runs(&namespace, &inner.chain_id, after, page_size + 1)
        .map_err(Status::internal)?;
    let next_page_token = if runs.len() > page_size {
        runs.truncate(page_size);
        runs.last()
            .map(|run| format!("{}:{}", run.created_at_ms, run.run_id))
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(Response::new(ListTransformChainRunsResponse {
        runs: runs
            .iter()
            .map(|run| to_proto_transform_chain_run(service, &principals, run))
            .collect::<Result<_, _>>()?,
        next_page_token,
    }))
}

/// Trait routes for the facade's `delegate_rpcs!` list.
impl SekaiServiceImpl {
    pub(super) async fn get_transform_chain_run_rpc(
        &self,
        req: Request<GetTransformChainRunRequest>,
    ) -> Result<Response<GetTransformChainRunResponse>, Status> {
        rpc_data::get_transform_chain_run(self, req).await
    }
    pub(super) async fn list_transform_chains_rpc(
        &self,
        req: Request<ListTransformChainsRequest>,
    ) -> Result<Response<ListTransformChainsResponse>, Status> {
        list_transform_chains(self, req).await
    }
    pub(super) async fn get_transform_chain_rpc(
        &self,
        req: Request<GetTransformChainRequest>,
    ) -> Result<Response<GetTransformChainResponse>, Status> {
        get_transform_chain(self, req).await
    }
    pub(super) async fn list_transform_chain_runs_rpc(
        &self,
        req: Request<ListTransformChainRunsRequest>,
    ) -> Result<Response<ListTransformChainRunsResponse>, Status> {
        list_transform_chain_runs(self, req).await
    }
}
