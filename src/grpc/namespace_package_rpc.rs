//! Namespace packages (#3093, ADR 0169).
//!
//! `ExportNamespacePackage` packages a namespace's governed resources as a
//! signed `sekai.namespace-package/v1` manifest. It carries the published
//! definitions the caller may read, counting the rest by member kind, and the
//! definitions (columns, classifications, partition keys) of the datasets the
//! caller selects. Governed transforms stay out of v1. It is signed with the
//! definition package key (`SEKAI_DEFINITION_PACKAGE_*`). Export writes
//! nothing.
//!
//! `InstallNamespacePackage` verifies a package and every dataset mapping
//! before its first write, then opens the definitions as a proposal, creates
//! the output datasets bound to objects in the target namespace, and records
//! the installation. Each step is idempotent, so a retry after a crash
//! converges; the record is written last.

use std::collections::{BTreeMap, BTreeSet};

use super::rpc_data::{authorize_dataset, authorize_packaged_dataset};
use super::rpc_definition_package::{
    ImportSource, PackageSigner, open_import_proposal, package_keyring_from_env,
    package_signer_from_env, prepare_package_members,
};
use super::*;
use crate::sekai::definition_package::{
    self as definition_package, MEMBER_KIND_TRANSFORM, PackageProvenance,
};
use crate::sekai::namespace_package::{
    self as package_domain, DatasetDocument, EntryRole, InstalledResource, KIND_DATASET_VERSION,
    KIND_DEFINITION_PACKAGE, MAX_PACKAGE_DATASETS, NamespacePackageInstallation as Installation,
};
use crate::shomei::TrustedKeyring;

impl SekaiServiceImpl {
    pub(super) async fn export_namespace_package_rpc(
        &self,
        req: Request<ExportNamespacePackageRequest>,
    ) -> Result<Response<ExportNamespacePackageResponse>, Status> {
        require_authenticated(&caller_principals(&req))?;
        let signer = package_signer_from_env()?;
        export_namespace_package_as(self, req, &signer)
    }

    pub(super) async fn install_namespace_package_rpc(
        &self,
        req: Request<InstallNamespacePackageRequest>,
    ) -> Result<Response<InstallNamespacePackageResponse>, Status> {
        require_authenticated(&caller_principals(&req))?;
        let keyring = package_keyring_from_env()?;
        install_namespace_package_with(self, req, &keyring)
    }

    pub(super) async fn get_namespace_package_installation_rpc(
        &self,
        req: Request<GetNamespacePackageInstallationRequest>,
    ) -> Result<Response<GetNamespacePackageInstallationResponse>, Status> {
        let principals = caller_principals(&req);
        require_authenticated(&principals)?;
        let tenant_context = request_tenant_context(self.db.runtime(), &req)?;
        let input = req.into_inner();
        authorize_source_sync_namespace(
            self,
            &principals,
            tenant_context.as_ref(),
            &input.namespace,
            false,
        )?;
        let installation = self
            .db
            .runtime()
            .get_namespace_package_installation(&input.namespace, &input.package_name)
            .map_err(|_| Status::internal("package installation unavailable"))?
            .ok_or_else(|| Status::not_found("package installation not found"))?;
        Ok(Response::new(GetNamespacePackageInstallationResponse {
            installation: Some(to_proto_installation(self, installation)?),
        }))
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

/// One dataset entry, checked against its target before anything is
/// written.
enum PlannedDataset {
    /// Created on install; `exists` when a retry finds it already created.
    Output {
        dataset: crate::sekai::dataset::Dataset,
        exists: bool,
    },
    Input,
}

/// Install against an explicit keyring.
pub(super) fn install_namespace_package_with(
    service: &SekaiServiceImpl,
    req: Request<InstallNamespacePackageRequest>,
    keyring: &TrustedKeyring,
) -> Result<Response<InstallNamespacePackageResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let mut input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    let envelope = package_domain::verify_namespace_envelope(&input.envelope_json, keyring)
        .map_err(Status::failed_precondition)?;
    let package = &envelope.package;
    let db = service.db.runtime();
    if let Some(installed) = db
        .get_namespace_package_installation(&input.namespace, &package.name)
        .map_err(|_| Status::internal("package installation unavailable"))?
    {
        // The same package again changes nothing; another version is an
        // upgrade, which a later layer adds.
        if installed.package_digest != package.package_digest {
            return Err(Status::failed_precondition(format!(
                "namespace {} already holds version {} of package {}",
                input.namespace, installed.package_version, package.name
            )));
        }
        return Ok(Response::new(InstallNamespacePackageResponse {
            installation: Some(to_proto_installation(service, installed)?),
        }));
    }

    let mut planned = Vec::new();
    for entry in package
        .entries
        .iter()
        .filter(|entry| entry.kind == KIND_DATASET_VERSION)
    {
        let target = input.datasets.remove(&entry.id).ok_or_else(|| {
            Status::invalid_argument(format!(
                "entry {KIND_DATASET_VERSION}/{} is not mapped to a dataset",
                entry.id
            ))
        })?;
        let plan = plan_dataset(
            service,
            &principals,
            tenant_context.as_ref(),
            &input.namespace,
            entry,
            &target,
        )?;
        planned.push((entry, target.dataset_id, plan));
    }
    if let Some(unknown) = input.datasets.keys().next() {
        return Err(Status::invalid_argument(format!(
            "package has no entry {KIND_DATASET_VERSION}/{unknown}"
        )));
    }

    let definitions = envelope
        .definitions()
        .map_err(Status::failed_precondition)?;
    let members = prepare_package_members(&input.namespace, &definitions)?;
    let proposal_ids = if members.is_empty() {
        None
    } else {
        let id = format!("package/{}/v{}", package.name, package.version);
        Some((id.clone(), id))
    };
    if let Some((_, proposal_id)) = &proposal_ids {
        refuse_unless_empty(service, &input.namespace, proposal_id)?;
    }

    // Every check passed; the writes follow, each idempotent.
    let mut resources = Vec::new();
    if let Some((branch_id, proposal_id)) = &proposal_ids {
        open_import_proposal(
            service,
            &principals,
            &input.namespace,
            members,
            ImportSource {
                branch_id: branch_id.clone(),
                proposal_id: proposal_id.clone(),
                package_digest: package.package_digest.clone(),
                commit: String::new(),
                idempotency_key: format!("namespace-package/{}", package.package_digest),
                expected_published_digest: None,
            },
        )?;
        resources.push(InstalledResource {
            kind: KIND_DEFINITION_PACKAGE.into(),
            entry_id: package_domain::DEFINITIONS_ENTRY_ID.into(),
            role: EntryRole::Output,
            resource_id: proposal_id.clone(),
        });
    }
    for (entry, dataset_id, plan) in planned {
        if let PlannedDataset::Output {
            dataset,
            exists: false,
        } = &plan
        {
            db.create_dataset(dataset)
                .map_err(|_| Status::aborted(format!("dataset {dataset_id} was not created")))?;
        }
        resources.push(InstalledResource {
            kind: entry.kind.clone(),
            entry_id: entry.id.clone(),
            role: entry.role,
            resource_id: dataset_id,
        });
    }
    let (branch_id, proposal_id) = proposal_ids.unwrap_or_default();
    let installation = Installation {
        installation_id: package_domain::installation_id(&input.namespace, &package.name)
            .map_err(Status::internal)?,
        namespace: input.namespace.clone(),
        package_name: package.name.clone(),
        package_version: package.version,
        package_digest: package.package_digest.clone(),
        ontology_digest: package.ontology_digest.clone(),
        source_namespace: envelope.provenance.source_namespace.clone(),
        signer_identity: envelope.signature.identity.clone(),
        branch_id,
        proposal_id,
        resources,
        installed_by: principals.first().cloned().unwrap_or_default(),
        installed_at_ms: now_millis(),
    };
    let stored = db
        .put_namespace_package_installation(&installation)
        .map_err(|_| Status::internal("package installation unavailable"))?;
    if stored.package_digest != installation.package_digest {
        return Err(Status::aborted(format!(
            "another install of package {} won the race",
            package.name
        )));
    }
    Ok(Response::new(InstallNamespacePackageResponse {
        installation: Some(to_proto_installation(service, stored)?),
    }))
}

/// Checks one dataset entry against its target in `namespace`: an output
/// binds a new dataset to an object there (or finds the identical one a
/// retry created), an input names a readable dataset bound there with the
/// entry's schema. Refusals name the entry.
fn plan_dataset(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&crate::enterprise::AuthenticatedContext>,
    namespace: &str,
    entry: &package_domain::PackageEntry,
    target: &NamespacePackageDatasetTarget,
) -> Result<PlannedDataset, Status> {
    let name = format!("{}/{}", entry.kind, entry.id);
    let db = service.db.runtime();
    // As CreateDataset: pin keys are reserved for object-set inputs.
    if target.dataset_id.is_empty()
        || crate::sekai::object_set_input::is_pin_key(&target.dataset_id)
    {
        return Err(Status::invalid_argument(format!(
            "entry {name} needs a target dataset id outside {}",
            crate::sekai::object_set_input::PIN_PREFIX
        )));
    }
    let existing = db
        .get_dataset(&target.dataset_id)
        .map_err(Status::internal)?;
    match entry.role {
        EntryRole::Output => {
            let object = db
                .get_object(&target.object_id)
                .map_err(Status::internal)?
                .filter(|object| object.namespace == namespace)
                .ok_or_else(|| {
                    Status::failed_precondition(format!(
                        "entry {name} needs an object in namespace {namespace} to bind to"
                    ))
                })?;
            let document: DatasetDocument = serde_json::from_str(&entry.document_json)
                .map_err(|_| Status::failed_precondition(format!("entry {name} is unreadable")))?;
            let dataset = crate::sekai::dataset::Dataset {
                id: target.dataset_id.clone(),
                name: document.name,
                columns: document
                    .columns
                    .into_iter()
                    .map(|column| crate::sekai::dataset::ColumnDef {
                        name: column.name,
                        col_type: column.col_type,
                        classification: column.classification,
                    })
                    .collect(),
                object_id: object.id,
                created: now_millis(),
                partition_keys: document.partition_keys,
            };
            authorize_dataset(service, principals, tenant_context, &dataset, true)?;
            let exists = match existing {
                None => false,
                Some(found) if same_definition(&found, &dataset) => true,
                Some(_) => {
                    return Err(Status::already_exists(format!(
                        "entry {name}: dataset {} already exists",
                        target.dataset_id
                    )));
                }
            };
            Ok(PlannedDataset::Output { dataset, exists })
        }
        EntryRole::Input => {
            if !target.object_id.is_empty() {
                return Err(Status::invalid_argument(format!(
                    "entry {name} is an input; it maps to an existing dataset without an object"
                )));
            }
            let refused = || {
                Status::failed_precondition(format!(
                    "entry {name}: dataset {} is not a readable dataset in namespace {namespace}",
                    target.dataset_id
                ))
            };
            let dataset = existing.ok_or_else(refused)?;
            let bound = authorize_packaged_dataset(service, principals, tenant_context, &dataset)
                .map_err(|_| refused())?;
            if bound.as_deref() != Some(namespace) {
                return Err(refused());
            }
            if DatasetDocument::of(&dataset)
                .schema_digest()
                .map_err(Status::internal)?
                != entry.digest
            {
                return Err(Status::failed_precondition(format!(
                    "entry {name}: dataset {} does not match its schema",
                    target.dataset_id
                )));
            }
            Ok(PlannedDataset::Input)
        }
        _ => Err(Status::failed_precondition(format!(
            "entry {name} has an unsupported role"
        ))),
    }
}

/// A dataset a retry finds is the one this install creates: same name,
/// columns, partition keys and binding.
fn same_definition(
    found: &crate::sekai::dataset::Dataset,
    planned: &crate::sekai::dataset::Dataset,
) -> bool {
    DatasetDocument::of(found) == DatasetDocument::of(planned)
        && found.object_id == planned.object_id
}

/// Install opens the definitions on an empty namespace only: merging into
/// one that holds definitions is a non-goal of #3093. A retry whose proposal
/// already exists (and may have merged) passes.
fn refuse_unless_empty(
    service: &SekaiServiceImpl,
    namespace: &str,
    proposal_id: &str,
) -> Result<(), Status> {
    let db = service.db.runtime();
    if db
        .get_definition_proposal(namespace, proposal_id)
        .map_err(|_| Status::internal("definition proposal unavailable"))?
        .is_some()
    {
        return Ok(());
    }
    let Some(head) = db
        .get_published_definition_revision(namespace)
        .map_err(|_| Status::internal("definition revision unavailable"))?
    else {
        return Ok(());
    };
    if head.members.is_empty() {
        return Ok(());
    }
    Err(Status::failed_precondition(format!(
        "namespace {namespace} already holds definitions; a package installs into an empty namespace"
    )))
}

/// The installation with its status, derived from its definitions proposal.
fn to_proto_installation(
    service: &SekaiServiceImpl,
    installation: Installation,
) -> Result<NamespacePackageInstallation, Status> {
    let db = service.db.runtime();
    let (merged, published_digest) = if installation.proposal_id.is_empty() {
        (None, None)
    } else {
        let proposal = db
            .get_definition_proposal(&installation.namespace, &installation.proposal_id)
            .map_err(|_| Status::internal("definition proposal unavailable"))?;
        match proposal {
            Some(proposal)
                if proposal.status == crate::sekai::definition_proposal::STATUS_MERGED =>
            {
                let members = db
                    .get_definition_members(&installation.namespace, &proposal.candidate_digest)
                    .map_err(|_| Status::internal("definition revision unavailable"))?;
                let published =
                    definition_package::build_package(members.into_iter().map(|member| {
                        (member.member_kind, member.member_id, member.definition_json)
                    }))
                    .map_err(Status::internal)?;
                (Some(true), Some(published.package_digest))
            }
            _ => (Some(false), None),
        }
    };
    let status =
        package_domain::installation_status(&installation, merged, published_digest.as_deref());
    Ok(NamespacePackageInstallation {
        installation_id: installation.installation_id,
        namespace: installation.namespace,
        package_name: installation.package_name,
        package_version: installation.package_version,
        package_digest: installation.package_digest,
        ontology_digest: installation.ontology_digest,
        status: status.into(),
        branch_id: installation.branch_id,
        proposal_id: installation.proposal_id,
        resources: installation
            .resources
            .into_iter()
            .map(|resource| NamespacePackageInstalledResource {
                kind: resource.kind,
                entry_id: resource.entry_id,
                role: match resource.role {
                    EntryRole::Output => "output",
                    EntryRole::Input => "input",
                    _ => "unknown",
                }
                .into(),
                resource_id: resource.resource_id,
            })
            .collect(),
        source_namespace: installation.source_namespace,
        signer_identity: installation.signer_identity,
        installed_by: installation.installed_by,
        installed_at_ms: installation.installed_at_ms,
    })
}
