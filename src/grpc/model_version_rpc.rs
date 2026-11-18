//! Experimental GetModelVersion and ListModelVersions RPCs (#3020).
//!
//! A caller reads a namespace's versions with namespace read access, and sees
//! a marked version only when its authority covers the version's marking,
//! which is the most restrictive of the training inputs. A version the caller
//! may not see reads as missing. An unmarked version is visible to every
//! namespace reader unless the namespace denies unmarked reads.

use super::*;
use crate::sekai::model_version as domain_model;

const MODEL_VERSION_PAGE_MAX: usize = 100;

pub(super) async fn get_model_version(
    service: &SekaiServiceImpl,
    req: Request<GetModelVersionRequest>,
) -> Result<Response<GetModelVersionResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    authorize_namespace_read(
        service,
        &principals,
        tenant_context.as_ref(),
        &inner.namespace,
    )?;
    let version = service
        .db
        .runtime()
        .get_model_version(&inner.namespace, &inner.version_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found(domain_model::MODEL_VERSION_NOT_FOUND))?;
    if !version_visible(service, &principals, &version)? {
        return Err(Status::not_found(domain_model::MODEL_VERSION_NOT_FOUND));
    }
    Ok(Response::new(GetModelVersionResponse {
        version: Some(to_proto_model_version(version)),
    }))
}

pub(super) async fn list_model_versions(
    service: &SekaiServiceImpl,
    req: Request<ListModelVersionsRequest>,
) -> Result<Response<ListModelVersionsResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let inner = req.into_inner();
    authorize_namespace_read(
        service,
        &principals,
        tenant_context.as_ref(),
        &inner.namespace,
    )?;
    let page_size = match usize::try_from(inner.page_size) {
        Ok(0) => MODEL_VERSION_PAGE_MAX,
        Ok(size) => size.min(MODEL_VERSION_PAGE_MAX),
        Err(_) => return Err(Status::invalid_argument("page_size must not be negative")),
    };
    let after = (!inner.page_token.is_empty()).then_some(inner.page_token.as_str());
    let mut visible = Vec::new();
    // The store returns versions in ascending id, so the token is the last id.
    for version in service
        .db
        .runtime()
        .list_model_versions(&inner.namespace, &inner.model_name)
        .map_err(Status::internal)?
    {
        if after.is_some_and(|after| version.version_id.as_str() <= after) {
            continue;
        }
        if version_visible(service, &principals, &version)? {
            visible.push(version);
        }
        if visible.len() > page_size {
            break;
        }
    }
    let next_page_token = if visible.len() > page_size {
        visible.truncate(page_size);
        visible
            .last()
            .map(|version| version.version_id.clone())
            .unwrap_or_default()
    } else {
        String::new()
    };
    Ok(Response::new(ListModelVersionsResponse {
        versions: visible.into_iter().map(to_proto_model_version).collect(),
        next_page_token,
    }))
}

/// Another tenant's namespace reads as missing, not as denied.
fn authorize_namespace_read(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
) -> Result<(), Status> {
    if namespace.trim().is_empty() {
        return Err(Status::invalid_argument("namespace is required"));
    }
    if tenant_context.is_some() {
        enforce_namespace_tenant_context(service.db.runtime(), tenant_context, namespace, false)
            .map_err(|_| Status::not_found(domain_model::MODEL_VERSION_NOT_FOUND))?;
    }
    check_team_namespace(service.db.runtime(), principals, namespace, false)
}

fn version_visible(
    service: &SekaiServiceImpl,
    principals: &[String],
    version: &domain_model::ModelVersion,
) -> Result<bool, Status> {
    let db = service.db.runtime();
    if version.marking.is_empty() {
        // A namespace that hides unmarked objects hides unmarked versions
        // too; versions carry no grants, so only trusted services read them.
        let trusted = markings::is_trusted_service_principal(marking_subject(principals));
        let decision = markings::unmarked_access_decision(
            deny_unmarked_for_namespace(db, &version.namespace)?,
            trusted,
            false,
        );
        return Ok(decision != markings::MarkingDecision::Deny);
    }
    let lattice = load_classification_lattice(db, &version.namespace)?;
    let authority = resolve_principal_authority(db, principals)?;
    let result = crate::sekai::classification_lattice::evaluate_lattice_access(
        "model_version.read",
        Some(&version.marking),
        &authority,
        lattice.as_ref(),
    );
    Ok(result.decision != markings::MarkingDecision::Deny)
}

fn to_proto_columns(columns: Vec<domain_model::ModelColumn>) -> Vec<ColumnDef> {
    columns
        .into_iter()
        .map(|column| ColumnDef {
            name: column.name,
            r#type: column.col_type,
            ..Default::default()
        })
        .collect()
}

fn to_proto_model_version(version: domain_model::ModelVersion) -> ModelVersion {
    ModelVersion {
        version_id: version.version_id,
        namespace: version.namespace,
        model_name: version.model_name,
        digest: version.digest,
        adapter_id: version.adapter_id,
        adapter_version: version.adapter_version,
        registry_locator: version.registry_locator,
        contract: Some(ModelAdapterContract {
            inputs: version
                .contract
                .inputs
                .into_iter()
                .map(|input| ModelInput {
                    name: input.name,
                    columns: to_proto_columns(input.columns),
                })
                .collect(),
            output: to_proto_columns(version.contract.output),
        }),
        marking: version.marking,
        run_id: version.run_id,
        training_inputs: version
            .training_inputs
            .into_iter()
            .map(|input| ModelTrainingInput {
                dataset_id: input.dataset_id,
                version_id: input.version_id,
            })
            .collect(),
        actor: version.actor,
        created_at_ms: version.created_at_ms,
    }
}
