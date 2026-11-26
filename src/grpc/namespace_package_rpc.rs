//! Namespace packages (#3093, ADR 0169).
//!
//! `ExportNamespacePackage` packages a namespace's governed resources as a
//! signed `sekai.namespace-package/v1` manifest. It carries the published
//! definitions the caller may read, counting the rest by member kind, and the
//! definitions (columns, classifications, partition keys) of the datasets the
//! caller selects. For the datasets opted into content it also carries the
//! rows of their latest version, which takes an export grant and leaves out
//! the columns the caller's egress may not release. Governed transforms stay
//! out of v1. It is signed with the definition package key
//! (`SEKAI_DEFINITION_PACKAGE_*`). Export writes nothing but a refusal record
//! when the export grant is missing.
//!
//! `InstallNamespacePackage` verifies a package and every dataset mapping,
//! carried rows included, before its first write. It then opens the
//! definitions as a proposal, creates the output datasets bound to objects in
//! the target namespace, appends carried rows as one new version, and records
//! the installation. Each step is idempotent, so a retry after a crash
//! converges; the record is written last.
//!
//! Installing a later version of an installed package upgrades it (#3093
//! decision 8): the definitions open as the next version's proposal against
//! the published head, each dataset an earlier version created keeps its id
//! and takes the new definition and rows, new entries install as above, and
//! resources the new version no longer carries stay in place, listed as
//! retained. A resource changed outside the installation since the last
//! install is refused by name, never overwritten.

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
    self as package_domain, ContentRow, DatasetContentDocument, DatasetDocument, EntryRole,
    InstalledResource, KIND_DATASET_VERSION, KIND_DEFINITION_PACKAGE, MAX_PACKAGE_CONTENT_BYTES,
    MAX_PACKAGE_DATASETS, NamespacePackageInstallation as Installation,
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
    let with_content: BTreeSet<String> = input.content_dataset_ids.into_iter().collect();
    if let Some(id) = with_content.difference(&selected).next() {
        return Err(Status::invalid_argument(format!(
            "content dataset {id} is not one of the selected datasets"
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
    let mut content = BTreeMap::new();
    let mut content_budget = MAX_PACKAGE_CONTENT_BYTES;
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
        if with_content.contains(id) {
            let (rows, withheld_columns) = packaged_rows(
                service,
                &principals,
                tenant_context.as_ref(),
                &input.namespace,
                &dataset,
                &mut content_budget,
            )?;
            if withheld_columns > 0 {
                *withheld
                    .entry(package_domain::WITHHELD_DATASET_COLUMN.into())
                    .or_default() += withheld_columns;
            }
            content.insert(id.clone(), rows);
        }
        outputs.push(dataset);
    }

    let package = package_domain::build_namespace_package_with_content(
        &input.package_name,
        input.package_version,
        &definitions,
        &outputs,
        &[],
        content,
        withheld,
    )
    .map_err(|error| {
        // Rows the store holds that their column type does not parse as.
        if error.starts_with(package_domain::REFUSAL_INCOMPATIBLE) {
            Status::failed_precondition(error)
        } else {
            Status::internal(error)
        }
    })?;
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

/// The rows of `dataset`'s latest version that a package carries, and how
/// many columns it leaves out. Taking rows out of the plane needs an export
/// grant on `namespace`, as `ExportDatasetVersion` does; a caller without one
/// is refused by name. A column the caller's egress may not release, or a
/// restricted column the caller (or the actor it acts for) may not read, is
/// left out of every row. Rows count against `budget`, the bytes the package
/// may still carry.
fn packaged_rows(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&RequestEnterpriseContext>,
    namespace: &str,
    dataset: &crate::sekai::dataset::Dataset,
    budget: &mut usize,
) -> Result<(Vec<ContentRow>, u64), Status> {
    let id = &dataset.id;
    let db = service.db.runtime();
    super::data_export_rpc::export_grantee(db, principals, namespace, KIND_DATASET_VERSION, id)
        .map_err(|_| {
            Status::permission_denied(format!(
                "dataset {id} content needs an export grant on namespace {namespace}"
            ))
        })?;
    let object = db
        .get_object(&dataset.object_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::permission_denied(format!("dataset {id} is not readable")))?;
    // Cell grants name object value instances, which rows do not carry.
    if db
        .active_object_policy(&object.namespace, &object.kind)
        .map_err(|_| Status::unavailable("object authorization unavailable"))?
        .is_some_and(|policy| policy.value_instance_grants_enforced())
    {
        return Err(Status::failed_precondition(format!(
            "dataset {id} content cannot be packaged: its bound object type has cell grants"
        )));
    }
    let restricted_readable =
        can_read_restricted_properties(&service.security, &object, principals)
            && tenant_context
                .and_then(|context| context.act.as_ref())
                .is_none_or(|actor| {
                    can_read_restricted_properties(
                        &service.security,
                        &object,
                        std::slice::from_ref(actor),
                    )
                });
    let disclosure = service.egress_disclosure(principals, tenant_context);
    let released: BTreeSet<&str> = dataset
        .columns
        .iter()
        .filter(|column| {
            disclosure.releases(&column.classification)
                && (restricted_readable
                    || !crate::sekai::schema::is_restricted_property_classification(
                        &column.classification,
                    ))
        })
        .map(|column| column.name.as_str())
        .collect();
    let withheld_columns = (dataset.columns.len() - released.len()) as u64;

    let version_id = db.latest_dataset_version_id(id).map_err(Status::internal)?;
    let mut rows = Vec::new();
    if version_id.is_empty() {
        return Ok((rows, withheld_columns));
    }
    let version = db
        .get_dataset_version(id, &version_id, 0)
        .map_err(Status::internal)?;
    if version.purged {
        return Err(Status::failed_precondition(format!(
            "dataset {id} content is past retention"
        )));
    }
    let too_large = || {
        Status::failed_precondition(format!(
            "{}: dataset {id} brings the package over {MAX_PACKAGE_CONTENT_BYTES} bytes of rows",
            package_domain::REFUSAL_CONTENT_TOO_LARGE
        ))
    };
    let mut after = i64::MIN;
    loop {
        let page = db
            .dataset_version_rows_after(id, &version_id, after, CONTENT_PAGE)
            .map_err(Status::internal)?;
        let Some((last, _)) = page.last() else {
            break;
        };
        after = *last;
        for (_, values) in page {
            let row: ContentRow = values
                .into_iter()
                .filter(|(name, _)| released.contains(name.as_str()))
                .collect();
            let bytes = package_domain::row_bytes(&row).map_err(Status::internal)?;
            *budget = budget.checked_sub(bytes).ok_or_else(too_large)?;
            rows.push(row);
        }
    }
    Ok((rows, withheld_columns))
}

/// Version rows read per page while packaging content.
const CONTENT_PAGE: usize = 1_000;

/// Carried rows of an output, whether install still has to append them, and
/// the [`package_domain::rows_digest`] its latest version holds once done.
struct PlannedContent {
    rows: Vec<std::collections::HashMap<String, String>>,
    append: bool,
    digest: String,
}

/// What install does to an output dataset.
enum DatasetWrite {
    Create,
    /// An upgrade changes the definition of a dataset an earlier version
    /// created.
    Update,
    /// Already as the entry describes: a retry, or an unchanged upgrade.
    Keep,
}

/// One dataset entry, checked against its target before anything is
/// written.
enum PlannedDataset {
    Output {
        dataset: crate::sekai::dataset::Dataset,
        write: DatasetWrite,
        content: Option<PlannedContent>,
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
    // An installation of this package already there makes this an upgrade
    // (#3093 decision 8), unless it is the same package again.
    let previous = db
        .get_namespace_package_installation(&input.namespace, &package.name)
        .map_err(|_| Status::internal("package installation unavailable"))?;
    if let Some(installed) = &previous {
        if installed.package_digest == package.package_digest {
            return Ok(Response::new(InstallNamespacePackageResponse {
                installation: Some(to_proto_installation(service, installed.clone())?),
            }));
        }
        if package.version <= installed.package_version {
            return Err(Status::failed_precondition(format!(
                "namespace {} already holds version {} of package {}; an upgrade needs a later version",
                input.namespace, installed.package_version, package.name
            )));
        }
    }
    let earlier = |entry: &package_domain::PackageEntry| {
        previous.as_ref().and_then(|installed| {
            installed
                .resources
                .iter()
                .find(|resource| resource.kind == entry.kind && resource.entry_id == entry.id)
        })
    };

    let mut planned = Vec::new();
    for entry in package
        .entries
        .iter()
        .filter(|entry| entry.kind == KIND_DATASET_VERSION)
    {
        let name = format!("{}/{}", entry.kind, entry.id);
        let mapped = input.datasets.remove(&entry.id);
        let (dataset_id, plan) = match earlier(entry) {
            // An upgrade keeps each dataset an earlier version installed.
            Some(resource) => {
                if resource.role != entry.role {
                    return Err(Status::failed_precondition(format!(
                        "entry {name} changed role since the installed version"
                    )));
                }
                if let Some(target) =
                    mapped.filter(|target| target.dataset_id != resource.resource_id)
                {
                    return Err(Status::invalid_argument(format!(
                        "entry {name} is installed as dataset {}, not {}",
                        resource.resource_id, target.dataset_id
                    )));
                }
                let plan = match entry.role {
                    EntryRole::Output => plan_upgraded_output(
                        service,
                        &principals,
                        tenant_context.as_ref(),
                        entry,
                        resource,
                    )?,
                    _ => plan_dataset(
                        service,
                        &principals,
                        tenant_context.as_ref(),
                        &input.namespace,
                        entry,
                        &NamespacePackageDatasetTarget {
                            dataset_id: resource.resource_id.clone(),
                            object_id: String::new(),
                        },
                    )?,
                };
                (resource.resource_id.clone(), plan)
            }
            None => {
                let target = mapped.ok_or_else(|| {
                    Status::invalid_argument(format!("entry {name} is not mapped to a dataset"))
                })?;
                let plan = plan_dataset(
                    service,
                    &principals,
                    tenant_context.as_ref(),
                    &input.namespace,
                    entry,
                    &target,
                )?;
                (target.dataset_id, plan)
            }
        };
        planned.push((entry, dataset_id, plan));
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
    let mut proposal_ids = if members.is_empty() {
        None
    } else {
        let id = format!("package/{}/v{}", package.name, package.version);
        Some((id.clone(), id))
    };
    let definitions = match &proposal_ids {
        Some((_, proposal_id)) => definitions_target(
            service,
            &input.namespace,
            proposal_id,
            &package.ontology_digest,
            previous.as_ref(),
        )?,
        None => DefinitionsTarget::Open(None),
    };
    if let (DefinitionsTarget::Unchanged, Some(installed)) = (&definitions, &previous) {
        // The merged proposal of the installed version stays the record.
        proposal_ids = Some((installed.branch_id.clone(), installed.proposal_id.clone()));
    }

    // Every check passed; the writes follow, each idempotent.
    let mut resources = Vec::new();
    if let (Some((branch_id, proposal_id)), DefinitionsTarget::Open(expected_published_digest)) =
        (&proposal_ids, definitions)
    {
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
                expected_published_digest,
            },
        )?;
    }
    if let Some((_, proposal_id)) = &proposal_ids {
        resources.push(InstalledResource {
            kind: KIND_DEFINITION_PACKAGE.into(),
            entry_id: package_domain::DEFINITIONS_ENTRY_ID.into(),
            role: EntryRole::Output,
            resource_id: proposal_id.clone(),
            schema_digest: String::new(),
            rows_digest: String::new(),
        });
    }
    for (entry, dataset_id, plan) in planned {
        let mut rows_digest = String::new();
        if let PlannedDataset::Output {
            dataset,
            write,
            content,
        } = &plan
        {
            match write {
                DatasetWrite::Create => db.create_dataset(dataset).map_err(|_| {
                    Status::aborted(format!("dataset {dataset_id} was not created"))
                })?,
                DatasetWrite::Update => db.update_dataset(dataset).map_err(|_| {
                    Status::aborted(format!("dataset {dataset_id} was not updated"))
                })?,
                DatasetWrite::Keep => {}
            }
            if let Some(content) = content {
                // One append, so the rows land as one new version.
                if content.append {
                    db.append_rows(&dataset_id, &content.rows).map_err(|_| {
                        Status::aborted(format!("dataset {dataset_id} content was not written"))
                    })?;
                }
                rows_digest.clone_from(&content.digest);
            }
        }
        resources.push(InstalledResource {
            kind: entry.kind.clone(),
            entry_id: entry.id.clone(),
            role: entry.role,
            resource_id: dataset_id,
            schema_digest: entry.digest.clone(),
            rows_digest,
        });
    }
    // What earlier versions created and this one no longer carries stays in
    // place and is reported.
    let carried: BTreeSet<(String, String)> = resources
        .iter()
        .map(|resource| (resource.kind.clone(), resource.entry_id.clone()))
        .collect();
    let mut retained = BTreeMap::new();
    for resource in previous
        .iter()
        .flat_map(|installed| installed.resources.iter().chain(&installed.retained))
    {
        let key = (resource.kind.clone(), resource.entry_id.clone());
        if !carried.contains(&key) {
            retained.entry(key).or_insert_with(|| resource.clone());
        }
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
        retained: retained.into_values().collect(),
        installed_by: principals.first().cloned().unwrap_or_default(),
        installed_at_ms: now_millis(),
    };
    let stored = match &previous {
        Some(installed) => db.replace_namespace_package_installation(installed, &installation),
        None => db.put_namespace_package_installation(&installation),
    }
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

/// The dataset an output entry describes, as `id` bound to `object_id`, and
/// the rows it carries.
fn entry_dataset(
    entry: &package_domain::PackageEntry,
    id: &str,
    object_id: &str,
    created: i64,
) -> Result<(crate::sekai::dataset::Dataset, Option<Vec<ContentRow>>), Status> {
    let unreadable =
        || Status::failed_precondition(format!("entry {}/{} is unreadable", entry.kind, entry.id));
    let (document, rows) = if entry.content_included {
        let carried: DatasetContentDocument =
            serde_json::from_str(&entry.document_json).map_err(|_| unreadable())?;
        (carried.definition(), Some(carried.rows))
    } else {
        let document: DatasetDocument =
            serde_json::from_str(&entry.document_json).map_err(|_| unreadable())?;
        (document, None)
    };
    let dataset = crate::sekai::dataset::Dataset {
        id: id.to_string(),
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
        object_id: object_id.to_string(),
        created,
        partition_keys: document.partition_keys,
    };
    Ok((dataset, rows))
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
            let (dataset, rows) =
                entry_dataset(entry, &target.dataset_id, &object.id, now_millis())?;
            authorize_dataset(service, principals, tenant_context, &dataset, true)?;
            let write = match existing {
                None => DatasetWrite::Create,
                Some(found) if same_definition(&found, &dataset) => DatasetWrite::Keep,
                Some(_) => {
                    return Err(Status::already_exists(format!(
                        "entry {name}: dataset {} already exists",
                        target.dataset_id
                    )));
                }
            };
            let owned = match write {
                // A dataset this install has not created yet holds nothing.
                DatasetWrite::Create => Owned::Fresh,
                _ => Owned::Nothing,
            };
            let content = rows
                .map(|rows| plan_content(service, &name, &dataset, owned, rows))
                .transpose()?;
            Ok(PlannedDataset::Output {
                dataset,
                write,
                content,
            })
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

/// Checks an output an earlier version created against the entry of the
/// version being installed. The dataset keeps its id and binding. Its
/// definition is updated, under the dataset write grant, only while its schema
/// is still the one the installation recorded; carried rows go in as for
/// [`plan_content`]. Anything changed outside the installation is refused by
/// name, never overwritten.
fn plan_upgraded_output(
    service: &SekaiServiceImpl,
    principals: &[String],
    tenant_context: Option<&crate::enterprise::AuthenticatedContext>,
    entry: &package_domain::PackageEntry,
    resource: &InstalledResource,
) -> Result<PlannedDataset, Status> {
    let name = format!("{}/{}", entry.kind, entry.id);
    let changed = || {
        Status::failed_precondition(format!(
            "entry {name}: dataset {} changed outside the installation",
            resource.resource_id
        ))
    };
    let existing = service
        .db
        .runtime()
        .get_dataset(&resource.resource_id)
        .map_err(Status::internal)?
        .ok_or_else(changed)?;
    let (dataset, rows) =
        entry_dataset(entry, &existing.id, &existing.object_id, existing.created)?;
    authorize_dataset(service, principals, tenant_context, &existing, true)?;
    authorize_dataset(service, principals, tenant_context, &dataset, true)?;
    let found = DatasetDocument::of(&existing);
    let write = if found == DatasetDocument::of(&dataset) {
        DatasetWrite::Keep
    } else if found.schema_digest().map_err(Status::internal)? == resource.schema_digest {
        DatasetWrite::Update
    } else {
        return Err(changed());
    };
    let owned = if resource.rows_digest.is_empty() {
        Owned::Nothing
    } else {
        Owned::Rows(&resource.rows_digest)
    };
    let content = rows
        .map(|rows| plan_content(service, &name, &dataset, owned, rows))
        .transpose()?;
    Ok(PlannedDataset::Output {
        dataset,
        write,
        content,
    })
}

/// What the installation already holds in an output it is about to append to.
#[derive(Clone, Copy)]
enum Owned<'a> {
    /// The dataset is created by this install.
    Fresh,
    /// The installation wrote no rows to it yet: it takes carried rows while
    /// it has no version.
    Nothing,
    /// The installation wrote rows with this digest: an upgrade appends over
    /// them while the latest version still holds them.
    Rows(&'a str),
}

/// Checks carried rows against the schema of the dataset they go into, and
/// decides which still have to be appended. A dataset version holds every row
/// appended so far, so the aim is a latest version holding exactly the carried
/// rows. One that already does is done, so the rows land once per `(package
/// digest, target dataset)`. A fresh dataset, or one without a version, takes
/// them all. In an upgrade, a latest version still holding what the
/// installation wrote takes the carried rows it lacks; a version that drops
/// rows cannot apply to an append-only dataset and is refused by name. Any
/// other content was written outside the installation and is refused by name.
fn plan_content(
    service: &SekaiServiceImpl,
    name: &str,
    dataset: &crate::sekai::dataset::Dataset,
    owned: Owned<'_>,
    rows: Vec<ContentRow>,
) -> Result<PlannedContent, Status> {
    let schema = DatasetDocument::of(dataset);
    package_domain::check_rows(&schema.columns, &rows)
        .map_err(|error| Status::failed_precondition(format!("entry {name}: {error}")))?;
    let digest = package_domain::rows_digest(&rows).map_err(Status::internal)?;
    let latest = match owned {
        Owned::Fresh => LatestRows::NoVersion,
        _ => latest_rows(service, &dataset.id)?,
    };
    let changed = || {
        Status::failed_precondition(format!(
            "entry {name}: dataset {} changed outside the installation",
            dataset.id
        ))
    };
    let missing = match latest {
        LatestRows::NoVersion => rows,
        LatestRows::Rows(found) => {
            let found_digest = package_domain::rows_digest(&found).map_err(Status::internal)?;
            if found_digest == digest {
                Vec::new()
            } else if matches!(owned, Owned::Rows(wrote) if wrote == found_digest) {
                rows_beyond(&found, rows).ok_or_else(|| {
                    Status::failed_precondition(format!(
                        "entry {name}: the package drops rows dataset {} holds, and a dataset only takes appended rows",
                        dataset.id
                    ))
                })?
            } else {
                return Err(changed());
            }
        }
        LatestRows::Other => return Err(changed()),
    };
    Ok(PlannedContent {
        append: !missing.is_empty(),
        rows: missing
            .into_iter()
            .map(|row| row.into_iter().collect())
            .collect(),
        digest,
    })
}

/// The rows of `carried` beyond those `found` holds, counting duplicates, or
/// `None` when `found` holds a row `carried` lacks.
fn rows_beyond(found: &[ContentRow], carried: Vec<ContentRow>) -> Option<Vec<ContentRow>> {
    let mut held = BTreeMap::<&ContentRow, usize>::new();
    for row in found {
        *held.entry(row).or_default() += 1;
    }
    let mut beyond = Vec::new();
    for row in carried {
        match held.get_mut(&row) {
            Some(count) if *count > 0 => *count -= 1,
            _ => beyond.push(row),
        }
    }
    held.values().all(|count| *count == 0).then_some(beyond)
}

/// The latest version of a dataset, as install compares it.
enum LatestRows {
    NoVersion,
    Rows(Vec<ContentRow>),
    /// Purged, or larger than any package carries: not rows an install wrote.
    Other,
}

fn latest_rows(service: &SekaiServiceImpl, dataset_id: &str) -> Result<LatestRows, Status> {
    let db = service.db.runtime();
    let version_id = db
        .latest_dataset_version_id(dataset_id)
        .map_err(Status::internal)?;
    if version_id.is_empty() {
        return Ok(LatestRows::NoVersion);
    }
    if db
        .get_dataset_version(dataset_id, &version_id, 0)
        .map_err(Status::internal)?
        .purged
    {
        return Ok(LatestRows::Other);
    }
    let mut budget = MAX_PACKAGE_CONTENT_BYTES;
    let mut rows = Vec::new();
    let mut after = i64::MIN;
    loop {
        let page = db
            .dataset_version_rows_after(dataset_id, &version_id, after, CONTENT_PAGE)
            .map_err(Status::internal)?;
        let Some((last, _)) = page.last() else {
            break;
        };
        after = *last;
        for (_, values) in page {
            let row: ContentRow = values.into_iter().collect();
            let bytes = package_domain::row_bytes(&row).map_err(Status::internal)?;
            let Some(left) = budget.checked_sub(bytes) else {
                return Ok(LatestRows::Other);
            };
            budget = left;
            rows.push(row);
        }
    }
    Ok(LatestRows::Rows(rows))
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

/// What install does with a package's definitions.
enum DefinitionsTarget {
    /// Open the proposal, against this published head when it is `Some`.
    Open(Option<String>),
    /// An upgrade whose definitions equal the merged ones of the installed
    /// version: nothing to propose.
    Unchanged,
}

/// Where the definitions proposal `proposal_id` may open, and the published
/// head it must open against. A retry whose proposal already exists (and may
/// have merged) passes. A first install, or an upgrade whose earlier proposal
/// never merged, opens only into a namespace without definitions: merging
/// into one that holds definitions is a non-goal of #3093. An upgrade over
/// merged definitions opens against the published head, and only while that
/// head still holds the installed ontology digest; an earlier proposal still
/// open is refused, so two versions are never under review at once.
fn definitions_target(
    service: &SekaiServiceImpl,
    namespace: &str,
    proposal_id: &str,
    ontology_digest: &str,
    previous: Option<&Installation>,
) -> Result<DefinitionsTarget, Status> {
    let db = service.db.runtime();
    let proposal = |id: &str| {
        db.get_definition_proposal(namespace, id)
            .map_err(|_| Status::internal("definition proposal unavailable"))
    };
    if proposal(proposal_id)?.is_some() {
        return Ok(DefinitionsTarget::Open(None));
    }
    let earlier = match previous.filter(|installed| !installed.proposal_id.is_empty()) {
        Some(installed) => proposal(&installed.proposal_id)?.map(|found| (installed, found)),
        None => None,
    };
    let head = db
        .get_published_definition_revision(namespace)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    match earlier {
        Some((installed, found))
            if found.status == crate::sekai::definition_proposal::STATUS_OPEN =>
        {
            Err(Status::failed_precondition(format!(
                "proposal {} of version {} is still open; merge or close it before upgrading",
                installed.proposal_id, installed.package_version
            )))
        }
        Some((installed, found))
            if found.status == crate::sekai::definition_proposal::STATUS_MERGED =>
        {
            let head = head.ok_or_else(|| Status::internal("definition revision unavailable"))?;
            if published_package_digest(service, namespace, &head.revision_digest)?
                != installed.ontology_digest
            {
                return Err(Status::failed_precondition(format!(
                    "the definitions of namespace {namespace} changed outside the installation"
                )));
            }
            if installed.ontology_digest == ontology_digest {
                return Ok(DefinitionsTarget::Unchanged);
            }
            Ok(DefinitionsTarget::Open(Some(head.revision_digest)))
        }
        _ => match head {
            Some(head) if !head.members.is_empty() => Err(Status::failed_precondition(format!(
                "namespace {namespace} already holds definitions; a package installs into an empty namespace"
            ))),
            _ => Ok(DefinitionsTarget::Open(None)),
        },
    }
}

/// The namespace-free package digest of the definitions at `revision_digest`,
/// the value an installation's ontology digest is compared with.
fn published_package_digest(
    service: &SekaiServiceImpl,
    namespace: &str,
    revision_digest: &str,
) -> Result<String, Status> {
    let members = service
        .db
        .runtime()
        .get_definition_members(namespace, revision_digest)
        .map_err(|_| Status::internal("definition revision unavailable"))?;
    definition_package::build_package(
        members
            .into_iter()
            .map(|member| (member.member_kind, member.member_id, member.definition_json)),
    )
    .map(|package| package.package_digest)
    .map_err(Status::internal)
}

/// The installation with its status, derived from its definitions proposal.
fn to_proto_installation(
    service: &SekaiServiceImpl,
    installation: Installation,
) -> Result<NamespacePackageInstallation, Status> {
    let (merged, published_digest) = if installation.proposal_id.is_empty() {
        (None, None)
    } else {
        let proposal = service
            .db
            .runtime()
            .get_definition_proposal(&installation.namespace, &installation.proposal_id)
            .map_err(|_| Status::internal("definition proposal unavailable"))?;
        match proposal {
            Some(proposal)
                if proposal.status == crate::sekai::definition_proposal::STATUS_MERGED =>
            {
                let digest = published_package_digest(
                    service,
                    &installation.namespace,
                    &proposal.candidate_digest,
                )?;
                (Some(true), Some(digest))
            }
            _ => (Some(false), None),
        }
    };
    let status =
        package_domain::installation_status(&installation, merged, published_digest.as_deref());
    let to_proto = |resource: InstalledResource| NamespacePackageInstalledResource {
        kind: resource.kind,
        entry_id: resource.entry_id,
        role: match resource.role {
            EntryRole::Output => "output",
            EntryRole::Input => "input",
            _ => "unknown",
        }
        .into(),
        resource_id: resource.resource_id,
    };
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
        resources: installation.resources.into_iter().map(to_proto).collect(),
        retained_resources: installation.retained.into_iter().map(to_proto).collect(),
        source_namespace: installation.source_namespace,
        signer_identity: installation.signer_identity,
        installed_by: installation.installed_by,
        installed_at_ms: installation.installed_at_ms,
    })
}
