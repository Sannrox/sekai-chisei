//! `ExportNamespacePackage` (#3093, ADR 0169): packages a namespace's
//! governed resources as a signed `sekai.namespace-package/v1` manifest.
//!
//! The package carries the published definitions the caller may read,
//! counting the rest by member kind, and the definitions (columns,
//! classifications, partition keys) of the datasets the caller selects.
//! Governed transforms stay out of v1. It is signed with the definition
//! package key (`SEKAI_DEFINITION_PACKAGE_*`). Export writes nothing.

use std::collections::{BTreeMap, BTreeSet};

use super::rpc_data::authorize_packaged_dataset;
use super::rpc_definition_package::{PackageSigner, package_signer_from_env};
use super::*;
use crate::sekai::definition_package::{
    self as definition_package, MEMBER_KIND_TRANSFORM, PackageProvenance,
};
use crate::sekai::namespace_package::{self as package_domain, MAX_PACKAGE_DATASETS};

impl SekaiServiceImpl {
    pub(super) async fn export_namespace_package_rpc(
        &self,
        req: Request<ExportNamespacePackageRequest>,
    ) -> Result<Response<ExportNamespacePackageResponse>, Status> {
        require_authenticated(&caller_principals(&req))?;
        let signer = package_signer_from_env()?;
        export_namespace_package_as(self, req, &signer)
    }
}

/// Export with an explicit signer.
pub(super) fn export_namespace_package_as(
    service: &SekaiServiceImpl,
    req: Request<ExportNamespacePackageRequest>,
    signer: &PackageSigner,
) -> Result<Response<ExportNamespacePackageResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    package_domain::validate_name_and_version(&input.package_name, input.package_version)
        .map_err(Status::invalid_argument)?;
    let selected: BTreeSet<String> = input.dataset_ids.into_iter().collect();
    if selected.len() > MAX_PACKAGE_DATASETS {
        return Err(Status::invalid_argument(format!(
            "a package selects at most {MAX_PACKAGE_DATASETS} datasets"
        )));
    }
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let db = service.db.runtime();
    let head = db
        .get_published_definition_revision(&input.namespace)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    let members = match &head {
        Some(head) => db
            .get_definition_members(&input.namespace, &head.revision_digest)
            .map_err(|_| Status::internal("definition revision unavailable"))?,
        None => Vec::new(),
    };
    // Governed transforms are not carried in v1 (ADR 0169). A member the
    // caller may not read is withheld: counted by kind, never named.
    let mut withheld = BTreeMap::<String, u64>::new();
    let readable = members
        .into_iter()
        .filter(|member| member.member_kind != MEMBER_KIND_TRANSFORM)
        .filter(|member| {
            let read = authorize_definition_member_read(
                service,
                &principals,
                &member.member_kind,
                &member.member_id,
            )
            .is_ok();
            if !read {
                *withheld.entry(member.member_kind.clone()).or_default() += 1;
            }
            read
        })
        .map(|member| (member.member_kind, member.member_id, member.definition_json))
        .collect::<Vec<_>>();
    let definitions = definition_package::build_package(readable).map_err(Status::internal)?;

    let mut outputs = Vec::with_capacity(selected.len());
    for id in &selected {
        // Missing and unreadable read alike, so a refusal discloses nothing.
        let refused = || Status::permission_denied(format!("dataset {id} is not readable"));
        let dataset = db
            .get_dataset(id)
            .map_err(Status::internal)?
            .ok_or_else(refused)?;
        let namespace =
            authorize_packaged_dataset(service, &principals, tenant_context.as_ref(), &dataset)
                .map_err(|_| refused())?;
        if namespace.as_deref() != Some(input.namespace.as_str()) {
            return Err(Status::failed_precondition(format!(
                "dataset {id} is not bound to an object in namespace {}",
                input.namespace
            )));
        }
        outputs.push(dataset);
    }

    let package = package_domain::build_namespace_package(
        &input.package_name,
        input.package_version,
        &definitions,
        &outputs,
        &[],
        withheld,
    )
    .map_err(Status::internal)?;
    let envelope = package_domain::sign_namespace_package(
        package,
        PackageProvenance {
            source_namespace: input.namespace,
            source_revision_digest: head.map(|head| head.revision_digest).unwrap_or_default(),
            exported_at_ms: now_millis(),
        },
        &signer.identity,
        &signer.key_id,
        &signer.key,
    )
    .map_err(Status::internal)?;
    Ok(Response::new(ExportNamespacePackageResponse {
        package_digest: envelope.package.package_digest.clone(),
        ontology_digest: envelope.package.ontology_digest.clone(),
        envelope_json: serde_json::to_string(&envelope)
            .map_err(|_| Status::internal("namespace package could not be encoded"))?,
    }))
}
