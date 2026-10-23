//! Experimental ApplyDefinitionChangeBundle and GetDefinitionBundleApply
//! (#1693): an approved proposal's change bundle applied as one durable,
//! resumable record. See `crate::sekai::definition_bundle_apply`.
//!
//! The caller needs what merging the proposal needs. Every call regenerates
//! the bundle from the proposal's pinned revisions and refuses it unless it
//! still has the digest the reviewers approved. Steps run in order and each is
//! recorded done only after its effect; a failed step records the failure and
//! leaves the published revision unchanged.

use super::rpc_data::{bundle_backings, bundle_branch_name, fill_bundle_branch};
use super::rpc_definitions::authorize_definition_proposal_merge;
use super::*;
use crate::sekai::definition_bundle_apply::{
    APPLY_REVISION_CONFLICT, BundleApply, BundleApplyStore, STATUS_COMPLETED, StepKind,
};
use crate::sekai::definition_change_bundle::{DefinitionChangeBundle, apply_backfill};
use crate::sekai::object_type_index::ObjectTypeDatasource;

const DATA_MOVED: &str = "definition_bundle_apply_data_moved: a merged dataset was written before the publish; apply again to backfill it";

pub(super) async fn apply_definition_change_bundle(
    service: &SekaiServiceImpl,
    req: Request<ApplyDefinitionChangeBundleRequest>,
) -> Result<Response<ApplyDefinitionChangeBundleResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.get_ref().clone();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        true,
    )?;
    if input.bundle_digest.is_empty() {
        return Err(Status::invalid_argument(
            "bundle_digest is required: apply what the reviewers approved",
        ));
    }
    let db = service.db.runtime();
    let proposal = db
        .get_definition_proposal(&input.namespace, &input.proposal_id)
        .map_err(|_| Status::internal("definition proposal unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    // The record names datasets, proposals and the applier: it is for a
    // caller who may read both revisions, as GetDefinitionBundleApply.
    let (from, from_members, to, to_members) = load_authorized_definition_revisions(
        service,
        &principals,
        &input.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
    let stored = db
        .get_definition_bundle_apply(&input.namespace, &input.proposal_id)
        .map_err(Status::internal)?;
    if let Some((apply, _)) = &stored
        && apply.status == STATUS_COMPLETED
    {
        return Ok(Response::new(ApplyDefinitionChangeBundleResponse {
            apply: Some(to_proto_apply(apply)),
        }));
    }
    // A merged proposal still finishes an apply whose publish landed; a
    // closed one never applies.
    if proposal.status == crate::sekai::definition_proposal::STATUS_CLOSED {
        return Err(Status::failed_precondition("definition proposal is closed"));
    }
    let actor = authorize_definition_proposal_merge(
        service,
        &principals,
        tenant_context.as_ref(),
        &proposal,
    )?;

    let bundle = crate::sekai::definition_change_bundle::generate_change_bundle(
        &from,
        &from_members,
        &to,
        &to_members,
        &super::definition_change_bundle_rpc::hints_from_proto(input.hints.clone()),
    )
    .map_err(Status::invalid_argument)?;
    // The approvers approved the proposal digest, which binds the bundle's
    // digest: an applier cannot pick other hints than the ones approved.
    if proposal.migration_plan_digest.is_empty()
        || proposal.migration_plan_digest != bundle.bundle_digest
        || bundle.bundle_digest != input.bundle_digest
    {
        return Err(Status::failed_precondition(
            "definition_bundle_apply_unapproved_bundle: the regenerated bundle is not the one the proposal carries",
        ));
    }
    if bundle.steps.iter().any(|step| step.manual) {
        return Err(Status::failed_precondition(
            "definition_bundle_apply_manual_steps: the bundle has migration steps only a person can carry out",
        ));
    }
    let (backings, _unbacked, snapshot) = bundle_backings(service, &input.namespace, &bundle)?;
    let datasets = backings
        .iter()
        .map(|(_, source)| source.dataset_id.clone())
        .collect::<Vec<_>>();
    // Every object type the bundle backfills, backed or not, with its
    // datasource configuration now: the publish requires it unchanged, so a
    // type gaining a dataset meanwhile cannot publish unmigrated.
    let fingerprints = snapshot
        .iter()
        .map(|(kind, source)| {
            let fingerprint = source
                .as_ref()
                .map(crate::sekai::object_type_index::datasource_fingerprint)
                .unwrap_or_default();
            (kind.clone(), fingerprint)
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let now = now_millis();
    let (mut apply, mut revision) = match stored {
        Some((apply, revision)) => {
            if apply.bundle_digest != bundle.bundle_digest {
                return Err(Status::failed_precondition(
                    "definition_bundle_apply_changed: this proposal's apply ran another bundle",
                ));
            }
            (apply, revision)
        }
        None => (
            BundleApply::plan(
                &input.namespace,
                &input.proposal_id,
                &bundle.bundle_digest,
                &datasets,
                &actor,
                now,
            ),
            0,
        ),
    };
    // A type rebound to another dataset, newly backed, or no longer backed
    // since the last attempt: the steps follow the datasets backing it now.
    apply.reconcile(&datasets, now);
    // A datasource reconfigured since its steps ran starts its dataset over:
    // its branch and merge used the old configuration.
    for (kind, source) in &backings {
        let changed = apply
            .datasource_fingerprints
            .get(kind)
            .is_some_and(|previous| previous != &fingerprints[kind]);
        if changed {
            let dataset = &source.dataset_id;
            let (_, tenant) = super::rpc_data::branch_caller(service, &req, dataset, true)?;
            match db.delete_dataset_branch(
                dataset,
                &bundle_branch_name(&bundle.bundle_digest),
                &tenant,
            ) {
                Ok(()) => {}
                Err(error) if error == crate::sekai::dataset_branch::BRANCH_NOT_FOUND => {}
                Err(error) => return Err(super::rpc_data::branch_status(error)),
            }
            apply.restart_dataset(dataset, now);
        }
    }
    apply.datasource_fingerprints = fingerprints;
    apply.resume(&actor, now);
    revision = save(db, &apply, revision)?;

    let context = StepContext {
        service,
        req: &req,
        bundle: &bundle,
        backings: &backings,
        branch: bundle_branch_name(&bundle.bundle_digest),
        proposal: &proposal,
        actor: &actor,
        expected_published_digest: &input.expected_published_digest,
    };
    while let Some(index) = apply.next_step() {
        match context.run(&mut apply, &mut revision, index) {
            Ok(detail) => apply.complete_step(index, &detail, now_millis()),
            Err(status) if status.code() == tonic::Code::Aborted => return Err(status),
            Err(status) => apply.fail_step(index, status.message(), now_millis()),
        }
        revision = save(db, &apply, revision)?;
        if apply.status != crate::sekai::definition_bundle_apply::STATUS_RUNNING {
            break;
        }
    }
    Ok(Response::new(ApplyDefinitionChangeBundleResponse {
        apply: Some(to_proto_apply(&apply)),
    }))
}

pub(super) async fn get_definition_bundle_apply(
    service: &SekaiServiceImpl,
    req: Request<GetDefinitionBundleApplyRequest>,
) -> Result<Response<GetDefinitionBundleApplyResponse>, Status> {
    let principals = caller_principals(&req);
    require_authenticated(&principals)?;
    let tenant_context = request_tenant_context(service.db.runtime(), &req)?;
    let input = req.into_inner();
    authorize_source_sync_namespace(
        service,
        &principals,
        tenant_context.as_ref(),
        &input.namespace,
        false,
    )?;
    let db = service.db.runtime();
    let proposal = db
        .get_definition_proposal(&input.namespace, &input.proposal_id)
        .map_err(|_| Status::internal("definition proposal unavailable"))?
        .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
    load_authorized_definition_revisions(
        service,
        &principals,
        &input.namespace,
        &proposal.base_digest,
        &proposal.candidate_digest,
    )?;
    let (apply, _) = db
        .get_definition_bundle_apply(&input.namespace, &input.proposal_id)
        .map_err(Status::internal)?
        .ok_or_else(|| Status::not_found("definition bundle apply unavailable"))?;
    Ok(Response::new(GetDefinitionBundleApplyResponse {
        apply: Some(to_proto_apply(&apply)),
    }))
}

/// Write the record against the revision last read.
fn save(db: &RuntimeDb, apply: &BundleApply, revision: i64) -> Result<i64, Status> {
    db.put_definition_bundle_apply(apply, revision)
        .map_err(|error| {
            if error == APPLY_REVISION_CONFLICT {
                Status::aborted(error)
            } else {
                Status::internal(error)
            }
        })
}

struct StepContext<'a, T> {
    service: &'a SekaiServiceImpl,
    req: &'a Request<T>,
    bundle: &'a DefinitionChangeBundle,
    backings: &'a [(String, ObjectTypeDatasource)],
    branch: String,
    proposal: &'a crate::sekai::definition_proposal::DefinitionProposal,
    actor: &'a str,
    expected_published_digest: &'a str,
}

impl<T: 'static> StepContext<'_, T> {
    fn backing(&self, dataset: &str) -> Result<&(String, ObjectTypeDatasource), Status> {
        self.backings
            .iter()
            .find(|(_, source)| source.dataset_id == dataset)
            .ok_or_else(|| Status::failed_precondition("dataset no longer backs the bundle"))
    }

    /// Run one step; its detail on success. ABORTED means another writer
    /// raced the record or the branch and the caller should retry.
    fn run(
        &self,
        apply: &mut BundleApply,
        revision: &mut i64,
        index: usize,
    ) -> Result<String, Status> {
        let db = self.service.db.runtime();
        let step = apply.steps[index].clone();
        match step.kind() {
            Some(StepKind::Backfill(dataset)) => {
                let (object_type, source) = self.backing(dataset)?;
                // A branch this apply has not filled (a dry run's, perhaps
                // under another datasource configuration) is replaced: the
                // backfill is written from the configuration this apply uses.
                if step.effect.is_empty() {
                    let (_, tenant) =
                        super::rpc_data::branch_caller(self.service, self.req, dataset, true)?;
                    match db.delete_dataset_branch(dataset, &self.branch, &tenant) {
                        Ok(()) => {}
                        Err(error) if error == crate::sekai::dataset_branch::BRANCH_NOT_FOUND => {}
                        Err(error) => return Err(super::rpc_data::branch_status(error)),
                    }
                }
                fill_bundle_branch(
                    self.service,
                    self.req,
                    self.bundle,
                    object_type,
                    source,
                    &self.branch,
                    &apply.owned_columns(dataset),
                )?;
                // The incarnation filled: verify and merge must find it.
                let incarnation = self.bundle_branch(dataset)?.incarnation;
                apply.note_step(index, &incarnation, now_millis());
                Ok(incarnation)
            }
            Some(StepKind::Verify(dataset)) => {
                let (object_type, source) = self.backing(dataset)?;
                self.filled_branch(apply, index, dataset)?;
                let rows = db
                    .dataset_branch_rows(dataset, &self.branch)
                    .map_err(super::rpc_data::branch_status)?;
                let column = |property: &str| mapped(source, property);
                // Filled means the backfill changes nothing more.
                if apply_backfill(self.bundle, object_type, &rows, column) != rows {
                    return Err(Status::failed_precondition(
                        "definition_bundle_apply_unverified: the branch is missing backfilled values",
                    ));
                }
                Ok(format!("{} rows", rows.len()))
            }
            Some(StepKind::Merge(dataset)) => {
                let (object_type, source) = self.backing(dataset)?;
                let (_, tenant) =
                    super::rpc_data::branch_caller(self.service, self.req, dataset, true)?;
                // A retry after the proposal was opened merges that one, which
                // replays as merged once it landed (and the branch is gone).
                let mut dataset_proposal = step.effect.clone();
                if dataset_proposal.is_empty() {
                    let branch = self.filled_branch(apply, index, dataset)?;
                    // The bundle wrote the branch, so the definition proposal
                    // is its proposer and the applier merges it: the merge
                    // receipt names the change, and the dataset's
                    // two-person rule holds for any applier.
                    let proposed = db
                        .propose_dataset_branch(
                            &crate::sekai::dataset_branch::ProposeDatasetBranch {
                                dataset_id: dataset.into(),
                                branch: self.branch.clone(),
                                actor: format!("definition-proposal:{}", self.proposal.proposal_id),
                                tenant: tenant.clone(),
                                expected_incarnation: Some(branch.incarnation.clone()),
                            },
                        )
                        .map_err(super::rpc_data::branch_status)?;
                    // The parent the merge must still find is the version the
                    // branch forked from, so rows written since the fork are
                    // never replaced by the backfill of older data.
                    if proposed.parent_version_id != branch.base_version_id {
                        return Err(self.rebuild(apply, dataset, &tenant));
                    }
                    dataset_proposal = proposed.id;
                    apply.note_step(index, &dataset_proposal, now_millis());
                    *revision = save(db, apply, *revision)?;
                }
                // The column rules are checked again on the definitions the
                // merge reads under its dataset lock: a source reclassified
                // since the backfill never reaches live data under a new name.
                let owned = apply.owned_columns(dataset);
                let merged = db.merge_dataset_branch_checked(
                    &crate::sekai::dataset_branch::MergeDatasetBranch {
                        dataset_id: dataset.into(),
                        proposal_id: dataset_proposal.clone(),
                        actor: self.actor.into(),
                        tenant: tenant.clone(),
                        reason: format!(
                            "definition change bundle for proposal {}",
                            self.proposal.proposal_id
                        ),
                    },
                    &|columns| {
                        super::rpc_data::check_backfill_columns(
                            self.bundle,
                            object_type,
                            columns,
                            &source.key_column,
                            |property| mapped(source, property),
                            &owned,
                        )
                    },
                );
                let merged = match merged {
                    Ok(merged) => merged,
                    // The proposal can no longer merge (the dataset moved, the
                    // branch changed or went, the proposal closed): refill
                    // from the start. A merged proposal replays, never here.
                    Err(error)
                        if [
                            crate::sekai::dataset_branch::PROPOSAL_STALE_PARENT,
                            crate::sekai::dataset_branch::PROPOSAL_STALE_BRANCH,
                            crate::sekai::dataset_branch::PROPOSAL_NOT_OPEN,
                            crate::sekai::dataset_branch::PROPOSAL_NOT_FOUND,
                        ]
                        .contains(&error.as_str()) =>
                    {
                        return Err(self.rebuild(apply, dataset, &tenant));
                    }
                    Err(error) if error.starts_with("definition_change_bundle_") => {
                        return Err(Status::failed_precondition(error));
                    }
                    Err(error) => return Err(super::rpc_data::branch_status(error)),
                };
                if merged.status != crate::sekai::dataset_branch::STATUS_MERGED {
                    return Err(Status::internal("dataset merge did not complete"));
                }
                self.define_target_columns(apply, revision, dataset, object_type, source)?;
                // The dataset merge proposal names the merged version and its
                // receipt.
                Ok(dataset_proposal)
            }
            Some(StepKind::Publish) => {
                // A merged proposal published its candidate, whoever merged
                // it: an applier taking over after a crash finishes here.
                let current = db
                    .get_definition_proposal(&self.proposal.namespace, &self.proposal.proposal_id)
                    .map_err(|_| Status::internal("definition proposal unavailable"))?
                    .ok_or_else(|| Status::not_found("definition resource unavailable"))?;
                if current.status == crate::sekai::definition_proposal::STATUS_MERGED {
                    return Ok(current.candidate_digest);
                }
                // Every merged dataset must still be at the version its merge
                // wrote, checked again in the publish transaction itself:
                // rows written since were not backfilled.
                let expected = self.merged_versions(apply)?;
                if self.restart_moved(apply, &expected)? {
                    return Err(Status::failed_precondition(DATA_MOVED));
                }
                // So must every migrated datasource still be configured as
                // the steps found it.
                let datasources = apply
                    .datasource_fingerprints
                    .iter()
                    .map(|(kind, fingerprint)| (kind.clone(), fingerprint.clone()))
                    .collect::<Vec<_>>();
                let request = crate::sekai::definition_proposal::MergeDefinitionProposal {
                    namespace: self.proposal.namespace.clone(),
                    proposal_id: self.proposal.proposal_id.clone(),
                    expected_published_digest: self.expected_published_digest.into(),
                    idempotency_key: apply.publish_idempotency_key(),
                    expected_dataset_versions: expected.clone(),
                    expected_datasources: datasources,
                };
                request.request_digest().map_err(Status::invalid_argument)?;
                let result = match db.merge_definition_proposal(&request, self.actor, now_millis())
                {
                    Ok(result) => result,
                    Err(error)
                        if error.starts_with(
                            crate::sekai::definition_proposal::MERGE_DATASET_MOVED,
                        ) =>
                    {
                        self.restart_moved(apply, &expected)?;
                        return Err(Status::failed_precondition(DATA_MOVED));
                    }
                    // The next apply sees the new configuration and starts
                    // the affected datasets over.
                    Err(error)
                        if error.starts_with(
                            crate::sekai::definition_proposal::MERGE_DATASOURCE_CHANGED,
                        ) =>
                    {
                        return Err(Status::failed_precondition(error));
                    }
                    Err(error) => return Err(map_definition_write_error(error)),
                };
                let crate::sekai::definition_branch::DefinitionWriteResult::MergeProposal {
                    result,
                } = result
                else {
                    return Err(Status::internal("definition replay result is invalid"));
                };
                Ok(result.published_revision.revision_digest.clone())
            }
            None => Err(Status::internal("unknown definition bundle apply step")),
        }
    }

    /// The bundle branch of `dataset` in the caller's tenant.
    fn bundle_branch(
        &self,
        dataset: &str,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranch, Status> {
        let (_, tenant) = super::rpc_data::branch_caller(self.service, self.req, dataset, true)?;
        self.service
            .db
            .runtime()
            .list_dataset_branches(dataset)
            .map_err(super::rpc_data::branch_status)?
            .into_iter()
            .find(|branch| branch.name == self.branch && branch.tenant == tenant)
            .ok_or_else(|| Status::failed_precondition("the bundle branch is missing"))
    }

    /// The bundle branch, if it is still the incarnation this apply filled;
    /// otherwise the dataset's steps start over.
    fn filled_branch(
        &self,
        apply: &mut BundleApply,
        index: usize,
        dataset: &str,
    ) -> Result<crate::sekai::dataset_branch::DatasetBranch, Status> {
        let filled = apply
            .steps
            .iter()
            .find(|step| step.kind() == Some(StepKind::Backfill(dataset)))
            .map(|step| step.effect.clone())
            .unwrap_or_default();
        match self.bundle_branch(dataset) {
            Ok(branch) if branch.incarnation == filled => Ok(branch),
            _ => {
                apply.restart_dataset(dataset, now_millis());
                Err(Status::failed_precondition(format!(
                    "definition_bundle_apply_branch_changed: the bundle branch is not the one {} filled; apply again to refill it",
                    apply.steps[index].name
                )))
            }
        }
    }

    /// Define the columns the backfill wrote that the dataset does not
    /// define yet, so a datasource mapping to them stays valid. Copies come
    /// only from public columns and defaults are approved literals, so they
    /// are public. The columns are recorded as this apply's before they are
    /// added, so a retry knows them as its own.
    fn define_target_columns(
        &self,
        apply: &mut BundleApply,
        revision: &mut i64,
        dataset: &str,
        object_type: &str,
        source: &ObjectTypeDatasource,
    ) -> Result<(), Status> {
        let db = self.service.db.runtime();
        let defined = db
            .get_dataset(dataset)
            .map_err(Status::internal)?
            .ok_or_else(|| Status::not_found("dataset not found"))?
            .columns;
        let missing = self
            .bundle
            .backfill
            .iter()
            .filter(|assignment| assignment.object_type == object_type)
            .map(|assignment| mapped(source, &assignment.property))
            .filter(|column| !defined.iter().any(|defined| &defined.name == column))
            .collect::<std::collections::BTreeSet<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        let owned = apply.bundle_columns.entry(dataset.into()).or_default();
        for column in &missing {
            if !owned.contains(column) {
                owned.push(column.clone());
            }
        }
        apply.updated_at_ms = now_millis();
        *revision = save(db, apply, *revision)?;
        // Appended against the definitions read in the store transaction,
        // so a concurrent change to another column is never overwritten.
        let columns = missing
            .into_iter()
            .map(|name| crate::sekai::dataset::ColumnDef {
                name,
                col_type: "string".into(),
                classification: "public".into(),
            })
            .collect::<Vec<_>>();
        db.add_dataset_columns(dataset, &columns)
            .map_err(Status::internal)
    }

    /// Each merged dataset with the version its merge wrote.
    fn merged_versions(&self, apply: &BundleApply) -> Result<Vec<(String, String)>, Status> {
        let db = self.service.db.runtime();
        apply
            .datasets()
            .into_iter()
            .map(|dataset| {
                let merge = apply
                    .steps
                    .iter()
                    .find(|step| step.kind() == Some(StepKind::Merge(&dataset)))
                    .map(|step| step.effect.clone())
                    .unwrap_or_default();
                let version = db
                    .get_dataset_branch_proposal(&dataset, &merge)
                    .map_err(super::rpc_data::branch_status)?
                    .merged_version_id;
                Ok((dataset, version))
            })
            .collect()
    }

    /// Start over every dataset written since its merge; whether any was.
    fn restart_moved(
        &self,
        apply: &mut BundleApply,
        expected: &[(String, String)],
    ) -> Result<bool, Status> {
        let db = self.service.db.runtime();
        let mut moved = false;
        for (dataset, version) in expected {
            let latest = db
                .latest_dataset_version_id(dataset)
                .map_err(Status::internal)?;
            if &latest != version {
                apply.restart_dataset(dataset, now_millis());
                moved = true;
            }
        }
        Ok(moved)
    }

    /// The dataset changed since the backfill: drop the derived branch and
    /// start the dataset's steps over, so the next apply refills it from the
    /// new version.
    fn rebuild(&self, apply: &mut BundleApply, dataset: &str, tenant: &str) -> Status {
        let dropped =
            self.service
                .db
                .runtime()
                .delete_dataset_branch(dataset, &self.branch, tenant);
        apply.restart_dataset(dataset, now_millis());
        match dropped {
            Ok(()) => Status::failed_precondition(
                "definition_bundle_apply_stale_base: the dataset changed since the backfill; apply again to refill from the new version",
            ),
            Err(error) => super::rpc_data::branch_status(error),
        }
    }
}

/// A property's column under the datasource's mapping.
fn mapped(source: &ObjectTypeDatasource, property: &str) -> String {
    source
        .property_mapping
        .get(property)
        .cloned()
        .unwrap_or_else(|| property.to_string())
}

fn to_proto_apply(apply: &BundleApply) -> DefinitionBundleApply {
    DefinitionBundleApply {
        contract_version: apply.contract_version.clone(),
        namespace: apply.namespace.clone(),
        proposal_id: apply.proposal_id.clone(),
        bundle_digest: apply.bundle_digest.clone(),
        status: apply.status.clone(),
        steps: apply
            .steps
            .iter()
            .map(|step| DefinitionBundleApplyStep {
                name: step.name.clone(),
                status: step.status.clone(),
                detail: step.detail.clone(),
            })
            .collect(),
        failed_step: apply.failed_step.clone(),
        error: apply.error.clone(),
        applied_by: apply.applied_by.clone(),
        created_at_ms: apply.created_at_ms,
        updated_at_ms: apply.updated_at_ms,
    }
}
