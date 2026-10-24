//! PostgreSQL persistence for governed definition branches.

use std::collections::BTreeMap;

use postgres::{GenericClient, Transaction};

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::sekai::definition_branch::{
    ApplyDefinitionBranchEdit, CreateDefinitionBranch, DefinitionBranch,
    DefinitionBranchEditResult, DefinitionMember, DefinitionRevision, DefinitionWriteResult,
    apply_member_changes, changed_member_digests, validate_revision_members,
};
use crate::sekai::definition_proposal::{
    ApproveDefinitionProposal, CloseDefinitionProposal, CreateDefinitionProposal,
    DefinitionProposal, DefinitionProposalApproval, DefinitionProposalMergeResult,
    MergeDefinitionProposal, PROPOSAL_CONTRACT_VERSION, PreparedProposalDigestInput,
    ProposeDefinitionImport, ProposeDefinitionRollback, PublishedDefinitionHistoryStore,
    PublishedDefinitionRevisionHistoryEntry, ReplacementProposal, STATUS_CLOSED, STATUS_MERGED,
    STATUS_OPEN, dataset_column_names, history_entry_from_merged_proposal,
    list_published_definition_history, merge_receipt_id, object_property_keys,
    proposal_content_digest, reject_foreign_member_grants, require_descendant_candidate,
    require_rollback_migration_plan, rollback_may_drop_live_object_type_properties,
    rollback_member_edits,
};

impl PostgresDb {
    pub fn seed_published_definition_revision(
        &self,
        revision: &DefinitionRevision,
        members: &[DefinitionMember],
    ) -> Result<(), String> {
        if !revision.published {
            return Err("seed revision must be published".into());
        }
        crate::sekai::agent_promotion::refuse_direct_agent_publication(revision)?;
        validate_revision_members(revision, members)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        // #1174: concurrent seeds for one namespace serialize on the head
        // lock, so the second reads the first's head instead of racing it
        // to the insert.
        lock_published_head(&mut transaction, &revision.namespace)?;
        insert_members_postgres(&mut transaction, members)?;
        insert_revision_postgres(&mut transaction, revision)?;
        write_published_head_postgres(
            &mut transaction,
            &revision.namespace,
            &revision.revision_digest,
            revision.created_at_ms,
            None,
        )?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn get_definition_revision(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<DefinitionRevision>, String> {
        let mut connection = self.connection()?;
        load_revision_postgres(&mut *connection, namespace, revision_digest)
    }

    pub fn get_definition_members(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Vec<DefinitionMember>, String> {
        let mut connection = self.connection()?;
        let Some(revision) = load_revision_postgres(&mut *connection, namespace, revision_digest)?
        else {
            return Ok(Vec::new());
        };
        load_members_postgres(&mut *connection, &revision)
    }

    pub fn get_definition_member(
        &self,
        namespace: &str,
        revision_digest: &str,
        member_kind: &str,
        member_id: &str,
    ) -> Result<Option<DefinitionMember>, String> {
        let mut connection = self.connection()?;
        let Some(revision) = load_revision_postgres(&mut *connection, namespace, revision_digest)?
        else {
            return Ok(None);
        };
        load_member_postgres(&mut *connection, &revision, member_kind, member_id)
    }

    pub fn get_definition_branch(
        &self,
        namespace: &str,
        branch_id: &str,
    ) -> Result<Option<DefinitionBranch>, String> {
        load_branch_postgres(&mut *self.connection()?, namespace, branch_id, false)
    }

    pub fn create_definition_branch(
        &self,
        request: &CreateDefinitionBranch,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        request.validate()?;
        validate_write_context(actor, now_ms)?;
        let request_digest = request.request_digest()?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_write(&mut transaction, request, actor)?;

        if let Some(replayed) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let parent = load_revision_postgres(
            &mut transaction,
            &request.namespace,
            &request.parent_revision_digest,
        )?
        .filter(|revision| revision.published)
        .ok_or_else(|| {
            "definition_revision_not_found: parent revision is unavailable".to_string()
        })?;
        // `published` means the revision was a published head, not that it is
        // the current pointer. Merge still compare-and-swaps `published_heads`.
        if load_branch_postgres(
            &mut transaction,
            &request.namespace,
            &request.branch_id,
            true,
        )?
        .is_some()
        {
            return Err("definition_branch_conflict: branch identity is already in use".into());
        }
        let branch = DefinitionBranch {
            contract_version: crate::sekai::definition_branch::BRANCH_CONTRACT_VERSION.into(),
            namespace: request.namespace.clone(),
            branch_id: request.branch_id.clone(),
            base_revision_digest: parent.revision_digest.clone(),
            head_revision_digest: parent.revision_digest,
            created_by: actor.into(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };
        transaction
            .execute(
                "INSERT INTO sekai_definition_branches (
                    namespace, branch_id, base_revision_digest, head_revision_digest,
                    created_by, created_at_ms, updated_at_ms
                 ) VALUES ($1, $2, $3, $4, $5, $6, $6)",
                &[
                    &branch.namespace,
                    &branch.branch_id,
                    &branch.base_revision_digest,
                    &branch.head_revision_digest,
                    &branch.created_by,
                    &branch.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        let result = DefinitionWriteResult::CreateBranch {
            branch: branch.clone(),
        };
        persist_result_postgres(
            &mut transaction,
            request,
            actor,
            &request_digest,
            &result,
            "",
            &branch.head_revision_digest,
            "create_branch",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn apply_definition_branch_edit(
        &self,
        request: &ApplyDefinitionBranchEdit,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let (upserts, removals, request_digest) = request.prepare()?;
        validate_write_context(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_write(&mut transaction, request, actor)?;

        if let Some(replayed) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let mut branch = load_branch_postgres(
            &mut transaction,
            &request.namespace,
            &request.branch_id,
            true,
        )?
        .ok_or_else(|| "definition_branch_not_found: branch is unavailable".to_string())?;
        if branch.head_revision_digest != request.expected_head_digest {
            return Err("stale_definition_branch_head: expected head is no longer current".into());
        }
        let parent = load_revision_postgres(
            &mut transaction,
            &request.namespace,
            &branch.head_revision_digest,
        )?
        .ok_or_else(|| "definition_revision_not_found: branch head is unavailable".to_string())?;
        let changed_member_digests = changed_member_digests(&parent, &upserts, &removals)?;
        let candidate = apply_member_changes(&parent, &upserts, &removals, actor, now_ms)?;
        insert_members_postgres(&mut transaction, &upserts)?;
        let revision = insert_revision_postgres(&mut transaction, &candidate)?;
        let updated = transaction
            .execute(
                "UPDATE sekai_definition_branches
                 SET head_revision_digest=$1, updated_at_ms=$2
                 WHERE namespace=$3 AND branch_id=$4 AND head_revision_digest=$5",
                &[
                    &revision.revision_digest,
                    &now_ms,
                    &request.namespace,
                    &request.branch_id,
                    &request.expected_head_digest,
                ],
            )
            .map_err(|error| error.to_string())?;
        if updated != 1 {
            return Err("stale_definition_branch_head: expected head is no longer current".into());
        }
        let previous_head_digest = branch.head_revision_digest.clone();
        branch.head_revision_digest = revision.revision_digest.clone();
        branch.updated_at_ms = now_ms;
        let result = DefinitionWriteResult::ApplyEdit {
            result: Box::new(DefinitionBranchEditResult {
                branch: branch.clone(),
                previous_head_digest: previous_head_digest.clone(),
                revision,
                changed_member_digests,
            }),
        };
        persist_result_postgres(
            &mut transaction,
            request,
            actor,
            &request_digest,
            &result,
            &previous_head_digest,
            &branch.head_revision_digest,
            "apply_edit",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn get_published_definition_revision(
        &self,
        namespace: &str,
    ) -> Result<Option<DefinitionRevision>, String> {
        let mut connection = self.connection()?;
        let Some(digest) = load_published_head_postgres(&mut *connection, namespace)? else {
            return Ok(None);
        };
        load_revision_postgres(&mut *connection, namespace, &digest)
    }

    pub fn list_published_definition_revisions(
        &self,
        namespace: &str,
        member_kind: &str,
        member_id: &str,
        page_token: &str,
        page_size: i32,
    ) -> Result<(Vec<PublishedDefinitionRevisionHistoryEntry>, String), String> {
        let mut connection = self.connection()?;
        let mut store = PostgresHistoryStore(&mut *connection);
        list_published_definition_history(
            &mut store,
            namespace,
            member_kind,
            member_id,
            page_token,
            page_size,
        )
    }

    pub fn get_definition_proposal(
        &self,
        namespace: &str,
        proposal_id: &str,
    ) -> Result<Option<DefinitionProposal>, String> {
        load_proposal_postgres(&mut *self.connection()?, namespace, proposal_id)
    }

    pub fn propose_definition_import(
        &self,
        request: &ProposeDefinitionImport,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let request_digest = request.prepare()?;
        validate_write_context(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_write(&mut transaction, request, actor)?;
        lock_published_head(&mut transaction, &request.namespace)?;
        if let Some(replayed) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        if load_proposal_postgres(&mut transaction, &request.namespace, &request.proposal_id)?
            .is_some()
        {
            return Err("definition_proposal_conflict: proposal identity is already in use".into());
        }
        if load_branch_postgres(
            &mut transaction,
            &request.namespace,
            &request.branch_id,
            true,
        )?
        .is_some()
        {
            return Err("definition_branch_conflict: branch identity is already in use".into());
        }
        let published = load_published_head_postgres(&mut transaction, &request.namespace)?
            .ok_or_else(|| {
                "definition_revision_not_found: published head is unavailable".to_string()
            })?;
        if published != request.expected_published_digest {
            return Err(
                "stale_published_definition_head: expected published digest does not match published head"
                    .into(),
            );
        }
        let published_revision =
            load_revision_postgres(&mut transaction, &request.namespace, &published)?
                .filter(|revision| revision.published)
                .ok_or_else(|| {
                    "definition_revision_not_found: published revision is unavailable".to_string()
                })?;
        let published_members = load_members_postgres(&mut transaction, &published_revision)?;
        crate::sekai::definition_package::check_importable(
            &published_revision,
            &published_members,
            &request.members,
        )?;
        let proposal = open_replacement_proposal_postgres(
            &mut transaction,
            &ReplacementProposal {
                namespace: &request.namespace,
                branch_id: &request.branch_id,
                proposal_id: &request.proposal_id,
                members: request.members.clone(),
                restored_from_digest: "",
                migration_plan_digest: "",
                source_package_digest: &request.source_package_digest,
            },
            &published,
            &published_revision,
            actor,
            now_ms,
        )?;
        let result = DefinitionWriteResult::CreateProposal {
            proposal: proposal.clone(),
        };
        persist_result_postgres(
            &mut transaction,
            request,
            actor,
            &request_digest,
            &result,
            &published,
            &proposal.candidate_digest,
            "propose_import",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    /// Namespaces that have a published definition revision, sorted.
    pub fn list_published_definition_namespaces(&self) -> Result<Vec<String>, String> {
        Ok(self
            .connection()?
            .query(
                "SELECT namespace FROM sekai_definition_published_heads ORDER BY namespace",
                &[],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect())
    }

    pub fn propose_definition_rollback(
        &self,
        request: &ProposeDefinitionRollback,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let request_digest = request.prepare()?;
        validate_write_context(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_write(&mut transaction, request, actor)?;
        lock_published_head(&mut transaction, &request.namespace)?;
        if let Some(replayed) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        if load_proposal_postgres(&mut transaction, &request.namespace, &request.proposal_id)?
            .is_some()
        {
            return Err("definition_proposal_conflict: proposal identity is already in use".into());
        }
        if load_branch_postgres(
            &mut transaction,
            &request.namespace,
            &request.branch_id,
            true,
        )?
        .is_some()
        {
            return Err("definition_branch_conflict: branch identity is already in use".into());
        }
        let published = load_published_head_postgres(&mut transaction, &request.namespace)?
            .ok_or_else(|| {
                "definition_revision_not_found: published head is unavailable".to_string()
            })?;
        if published != request.expected_published_digest {
            return Err(
                "stale_published_definition_head: expected published digest does not match published head"
                    .into(),
            );
        }
        if published == request.restore_from_digest {
            return Err(
                "definition_proposal_no_change: restore digest must differ from published head"
                    .into(),
            );
        }
        let published_revision =
            load_revision_postgres(&mut transaction, &request.namespace, &published)?
                .filter(|revision| revision.published)
                .ok_or_else(|| {
                    "definition_revision_not_found: published revision is unavailable".to_string()
                })?;
        let restore = load_revision_postgres(
            &mut transaction,
            &request.namespace,
            &request.restore_from_digest,
        )?
        .filter(|revision| revision.published)
        .ok_or_else(|| {
            "definition_revision_not_found: restore revision is unavailable".to_string()
        })?;
        if restore.namespace != request.namespace {
            return Err("definition_revision_not_found: restore revision is unavailable".into());
        }
        let restore_members = load_members_postgres(&mut transaction, &restore)?;
        let proposal = open_replacement_proposal_postgres(
            &mut transaction,
            &ReplacementProposal {
                namespace: &request.namespace,
                branch_id: &request.branch_id,
                proposal_id: &request.proposal_id,
                members: restore_members,
                restored_from_digest: &request.restore_from_digest,
                migration_plan_digest: &request.migration_plan_digest,
                source_package_digest: "",
            },
            &published,
            &published_revision,
            actor,
            now_ms,
        )?;
        let result = DefinitionWriteResult::CreateProposal {
            proposal: proposal.clone(),
        };
        persist_result_postgres(
            &mut transaction,
            request,
            actor,
            &request_digest,
            &result,
            &published,
            &proposal.candidate_digest,
            "propose_rollback",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn create_definition_proposal(
        &self,
        request: &CreateDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let (eval_plan_digests, named_foreign_digests, proposal_digest, request_digest) =
            request.prepare()?;
        validate_write_context(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_write(&mut transaction, request, actor)?;
        lock_published_head(&mut transaction, &request.namespace)?;
        if let Some(replayed) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        if load_proposal_postgres(&mut transaction, &request.namespace, &request.proposal_id)?
            .is_some()
        {
            return Err("definition_proposal_conflict: proposal identity is already in use".into());
        }
        let branch = load_branch_postgres(
            &mut transaction,
            &request.namespace,
            &request.branch_id,
            true,
        )?
        .ok_or_else(|| "definition_branch_not_found: branch is unavailable".to_string())?;
        if branch.head_revision_digest != request.candidate_digest {
            return Err(
                "stale_definition_proposal_candidate: branch head does not match candidate".into(),
            );
        }
        if branch.base_revision_digest != request.base_digest {
            return Err(
                "stale_published_definition_head: branch base does not match pinned base".into(),
            );
        }
        let published = load_published_head_postgres(&mut transaction, &request.namespace)?
            .ok_or_else(|| {
                "definition_revision_not_found: published head is unavailable".to_string()
            })?;
        if published != request.base_digest {
            return Err(
                "stale_published_definition_head: published head does not match pinned base".into(),
            );
        }
        let candidate = load_revision_postgres(
            &mut transaction,
            &request.namespace,
            &request.candidate_digest,
        )?
        .ok_or_else(|| {
            "definition_revision_not_found: candidate revision is unavailable".to_string()
        })?;
        reject_foreign_member_grants(&candidate, &named_foreign_digests)?;
        let proposal = DefinitionProposal {
            contract_version: PROPOSAL_CONTRACT_VERSION.into(),
            namespace: request.namespace.clone(),
            branch_id: request.branch_id.clone(),
            proposal_id: request.proposal_id.clone(),
            base_digest: request.base_digest.clone(),
            candidate_digest: request.candidate_digest.clone(),
            proposal_digest,
            eval_plan_digests,
            named_foreign_digests,
            approvals: Vec::new(),
            status: STATUS_OPEN.into(),
            created_by: actor.into(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            receipt_id: String::new(),
            close_reason_code: String::new(),
            restored_from_digest: String::new(),
            migration_plan_digest: request.migration_plan_digest.clone(),
            major_revision: request.major_revision,
            source_package_digest: String::new(),
        };
        insert_proposal_postgres(&mut transaction, &proposal)?;
        let result = DefinitionWriteResult::CreateProposal {
            proposal: proposal.clone(),
        };
        persist_result_postgres(
            &mut transaction,
            request,
            actor,
            &request_digest,
            &result,
            &request.base_digest,
            &request.candidate_digest,
            "create_proposal",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn approve_definition_proposal(
        &self,
        request: &ApproveDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let request_digest = request.request_digest()?;
        validate_write_context(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_write(&mut transaction, request, actor)?;
        if let Some(replayed) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let mut proposal =
            load_proposal_postgres(&mut transaction, &request.namespace, &request.proposal_id)?
                .ok_or_else(|| {
                    "definition_proposal_not_found: proposal is unavailable".to_string()
                })?;
        proposal.require_open()?;
        if !proposal
            .approvals
            .iter()
            .any(|approval| approval.actor == actor)
        {
            proposal.approvals.push(DefinitionProposalApproval {
                actor: actor.into(),
                approved_at_ms: now_ms,
            });
        }
        proposal.updated_at_ms = now_ms;
        update_proposal_postgres(&mut transaction, &proposal)?;
        let result = DefinitionWriteResult::ApproveProposal {
            proposal: proposal.clone(),
        };
        persist_result_postgres(
            &mut transaction,
            request,
            actor,
            &request_digest,
            &result,
            &proposal.base_digest,
            &proposal.candidate_digest,
            "approve_proposal",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn merge_definition_proposal(
        &self,
        request: &MergeDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let request_digest = request.request_digest()?;
        // Blocking consumer bindings (ADR 0067, amended) are checked before
        // anything is published.
        if let Some(proposal) =
            self.get_definition_proposal(&request.namespace, &request.proposal_id)?
        {
            crate::sekai::definition_consumer_impact::refuse_breaking_blocking_bindings(
                crate::sekai::definition_consumer_impact::GateReads {
                    list: |filter: &crate::domain::ListFilter| self.list_objects(filter),
                    revision: |digest: &str| {
                        let Some(revision) =
                            self.get_definition_revision(&proposal.namespace, digest)?
                        else {
                            return Ok(None);
                        };
                        let members = self.get_definition_members(&proposal.namespace, digest)?;
                        Ok(Some((revision, members)))
                    },
                },
                &proposal,
            )?;
        }
        validate_write_context(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_write(&mut transaction, request, actor)?;
        lock_published_head(&mut transaction, &request.namespace)?;
        if let Some(replayed) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let mut proposal =
            load_proposal_postgres(&mut transaction, &request.namespace, &request.proposal_id)?
                .ok_or_else(|| {
                    "definition_proposal_not_found: proposal is unavailable".to_string()
                })?;
        proposal.require_open()?;
        if proposal.approvals.is_empty() {
            return Err(
                "definition_proposal_missing_approval: merge requires a live approval".into(),
            );
        }
        let branch = load_branch_postgres(
            &mut transaction,
            &proposal.namespace,
            &proposal.branch_id,
            true,
        )?
        .ok_or_else(|| "definition_branch_not_found: branch is unavailable".to_string())?;
        if branch.head_revision_digest != proposal.candidate_digest {
            return Err(
                "stale_definition_proposal_candidate: branch head does not match candidate".into(),
            );
        }
        if branch.base_revision_digest != proposal.base_digest {
            return Err(
                "stale_published_definition_head: branch base does not match pinned base".into(),
            );
        }
        let published = load_published_head_postgres(&mut transaction, &proposal.namespace)?
            .ok_or_else(|| {
                "definition_revision_not_found: published head is unavailable".to_string()
            })?;
        if published != request.expected_published_digest {
            return Err(
                "stale_published_definition_head: expected published digest does not match published head"
                    .into(),
            );
        }
        if published != proposal.base_digest {
            return Err(
                "stale_published_definition_head: published head does not match pinned base".into(),
            );
        }
        // Each dataset's rows lock, taken in order, holds its writers off
        // until the publish commits.
        let mut expected = request.expected_dataset_versions.clone();
        expected.sort();
        for (dataset, version) in &expected {
            crate::db::postgres::lock_dataset_rows(&mut transaction, dataset)?;
            let latest: Option<String> = transaction
                .query_opt(
                    "SELECT version_id FROM sekai_dataset_versions
                     WHERE dataset_id = $1 ORDER BY seq DESC LIMIT 1",
                    &[dataset],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get(0));
            if latest.unwrap_or_default() != *version {
                return Err(format!(
                    "{}: dataset {dataset} was written since its migration",
                    crate::sekai::definition_proposal::MERGE_DATASET_MOVED
                ));
            }
        }
        // The binding lock, which registration takes too, holds a concurrent
        // registration off until the publish, including for a binding that
        // does not exist yet. Taken in kind order.
        let mut datasources = request.expected_datasources.clone();
        datasources.sort();
        for (kind, fingerprint) in &datasources {
            crate::db::postgres::lock_object_type_datasource(
                &mut transaction,
                &request.namespace,
                kind,
            )?;
            let current = transaction
                .query_opt(
                    "SELECT dataset_id, key_column, property_mapping, hidden_column, edits_only
                     FROM sekai_object_type_datasource WHERE namespace = $1 AND kind = $2",
                    &[&request.namespace, kind],
                )
                .map_err(|error| error.to_string())?;
            let actual = match current {
                Some(row) => crate::sekai::object_type_index::datasource_fingerprint(
                    &crate::sekai::object_type_index::ObjectTypeDatasource {
                        contract_version: crate::sekai::object_type_index::CONTRACT_VERSION.into(),
                        namespace: request.namespace.clone(),
                        kind: kind.clone(),
                        definition_digest: String::new(),
                        dataset_id: row.get(0),
                        key_column: row.get(1),
                        property_mapping: serde_json::from_str(&row.get::<_, String>(2))
                            .map_err(|error| error.to_string())?,
                        hidden_column: row.get(3),
                        edits_only: row.get(4),
                    },
                ),
                None => String::new(),
            };
            if actual != *fingerprint {
                return Err(format!(
                    "{}: object type {kind} was reconfigured since its migration",
                    crate::sekai::definition_proposal::MERGE_DATASOURCE_CHANGED
                ));
            }
        }
        let candidate = load_revision_postgres(
            &mut transaction,
            &proposal.namespace,
            &proposal.candidate_digest,
        )?
        .ok_or_else(|| {
            "definition_revision_not_found: candidate revision is unavailable".to_string()
        })?;
        reject_foreign_member_grants(&candidate, &proposal.named_foreign_digests)?;
        require_descendant_candidate(&candidate, &proposal.base_digest, |digest| {
            load_revision_postgres(&mut transaction, &proposal.namespace, digest)
        })?;
        let published_revision =
            load_revision_postgres(&mut transaction, &proposal.namespace, &published)?.ok_or_else(
                || "definition_revision_not_found: published revision is unavailable".to_string(),
            )?;
        let published_members = load_members_postgres(&mut transaction, &published_revision)?;
        let candidate_members = load_members_postgres(&mut transaction, &candidate)?;
        // #1644: tool approvals hold on every merge path, not only the RPC.
        let action_types = transaction
            .query(
                "SELECT body_json FROM sekai_governed_action_types \
                 WHERE namespace = $1 AND enabled",
                &[&proposal.namespace],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.get::<_, String>(0));
        crate::sekai::agent_definition::require_revision_tool_approvals(
            &candidate_members,
            &crate::sekai::agent_definition::parse_action_types(action_types),
        )?;
        crate::sekai::definition_diff::require_merge_compatibility(
            &published_revision,
            &published_members,
            &candidate,
            &candidate_members,
        )?;
        // #1687: an unsuppressed error finding the candidate introduces
        // blocks the merge, on every merge path, judged on every consumer
        // binding the namespace holds.
        let (consumed, consumed_properties) = crate::sekai::ontology_lint::consumer_references(
            &consumer_bindings_postgres(&mut transaction, &proposal.namespace)?,
        );
        crate::sekai::ontology_lint::require_definition_lint(
            &published_members,
            &candidate_members,
            &consumed,
            &consumed_properties,
        )?;
        if !proposal.restored_from_digest.is_empty() {
            if proposal.migration_plan_digest.is_empty() {
                let rollback_diff = crate::sekai::definition_diff::compare_definition_revisions(
                    &published_revision,
                    &published_members,
                    &candidate,
                    &candidate_members,
                )?;
                if rollback_may_drop_live_object_type_properties(&proposal, &rollback_diff) {
                    require_rollback_migration_plan(
                        &proposal,
                        &rollback_diff,
                        &list_live_kind_properties_postgres(&mut transaction, &proposal.namespace)?,
                    )?;
                }
            } else {
                crate::sekai::definition_branch::validate_digest(
                    "migration_plan_digest",
                    &proposal.migration_plan_digest,
                )?;
            }
        }
        let bound = get_agent_definition_certification_postgres(
            &mut transaction,
            &proposal.namespace,
            &candidate.revision_digest,
            true,
        )?;
        let baseline = get_agent_definition_certification_postgres(
            &mut transaction,
            &proposal.namespace,
            &published_revision.revision_digest,
            false,
        )?;
        crate::sekai::agent_promotion::require_agent_promotion(
            &published_revision.members,
            &candidate.members,
            bound.as_ref(),
            baseline.as_ref(),
            now_ms,
        )?;
        let receipt_id = merge_receipt_id(
            &proposal.namespace,
            &proposal.proposal_id,
            &proposal.proposal_digest,
            &proposal.base_digest,
            &proposal.candidate_digest,
            &published,
            &proposal.restored_from_digest,
        )?;
        let published_revision = mark_revision_published_postgres(&mut transaction, &candidate)?;
        write_published_head_postgres(
            &mut transaction,
            &proposal.namespace,
            &published_revision.revision_digest,
            now_ms,
            Some(&published),
        )?;
        transaction
            .execute(
                "UPDATE sekai_object_type_index_join_status
                 SET ready = FALSE, generation = '', rebuilt_at_ms = $1 WHERE namespace = $2",
                &[&now_ms, &proposal.namespace],
            )
            .map_err(|error| error.to_string())?;
        proposal.status = STATUS_MERGED.into();
        proposal.updated_at_ms = now_ms;
        proposal.receipt_id = receipt_id.clone();
        update_proposal_postgres(&mut transaction, &proposal)?;
        let result = DefinitionWriteResult::MergeProposal {
            result: Box::new(DefinitionProposalMergeResult {
                proposal: proposal.clone(),
                previous_published_digest: published,
                published_revision: published_revision.clone(),
                receipt_id,
            }),
        };
        persist_result_postgres(
            &mut transaction,
            request,
            actor,
            &request_digest,
            &result,
            &proposal.base_digest,
            &proposal.candidate_digest,
            "merge_proposal",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }

    pub fn close_definition_proposal(
        &self,
        request: &CloseDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let request_digest = request.request_digest()?;
        validate_write_context(actor, now_ms)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_write(&mut transaction, request, actor)?;
        if let Some(replayed) = replay_postgres(
            &mut transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let mut proposal =
            load_proposal_postgres(&mut transaction, &request.namespace, &request.proposal_id)?
                .ok_or_else(|| {
                    "definition_proposal_not_found: proposal is unavailable".to_string()
                })?;
        proposal.require_open()?;
        proposal.status = STATUS_CLOSED.into();
        proposal.close_reason_code = request.reason_code.clone();
        proposal.updated_at_ms = now_ms;
        update_proposal_postgres(&mut transaction, &proposal)?;
        let result = DefinitionWriteResult::CloseProposal {
            proposal: proposal.clone(),
        };
        persist_result_postgres(
            &mut transaction,
            request,
            actor,
            &request_digest,
            &result,
            &proposal.base_digest,
            &proposal.candidate_digest,
            "close_proposal",
            now_ms,
        )?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(result)
    }
}

fn list_live_kind_properties_postgres(
    transaction: &mut Transaction<'_>,
    namespace: &str,
) -> Result<Vec<(String, std::collections::BTreeSet<String>)>, String> {
    let mut live = Vec::new();
    for row in transaction
        .query(
            "SELECT kind, properties FROM sekai_objects WHERE namespace=$1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?
    {
        let kind: String = row.get(0);
        let properties: String = row.get(1);
        live.push((kind, object_property_keys(&properties)));
    }
    for row in transaction
        .query(
            "SELECT o.kind, d.columns
             FROM sekai_datasets d
             INNER JOIN sekai_objects o ON o.id = d.object_id
             WHERE o.namespace=$1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?
    {
        let kind: String = row.get(0);
        let columns: String = row.get(1);
        live.push((kind, dataset_column_names(&columns)));
    }
    Ok(live)
}

fn validate_write_context(actor: &str, now_ms: i64) -> Result<(), String> {
    if actor.trim().is_empty() || actor.trim() != actor || actor.chars().any(char::is_control) {
        return Err("canonical actor required".into());
    }
    if now_ms <= 0 {
        return Err("now_ms must be positive".into());
    }
    Ok(())
}

fn lock_write<T: serde::Serialize>(
    transaction: &mut Transaction<'_>,
    request: &T,
    actor: &str,
) -> Result<(), String> {
    let value = serde_json::to_value(request).map_err(|error| error.to_string())?;
    let namespace = string_field(&value, "namespace")?;
    let idempotency_key = string_field(&value, "idempotency_key")?;
    let mut keys = vec![advisory_lock_key(&[
        namespace,
        "request",
        actor,
        idempotency_key,
    ])];
    if let Some(branch_id) = optional_string_field(&value, "branch_id") {
        keys.push(advisory_lock_key(&[namespace, "branch", branch_id]));
    }
    if let Some(proposal_id) = optional_string_field(&value, "proposal_id") {
        keys.push(advisory_lock_key(&[namespace, "proposal", proposal_id]));
    }
    for key in keys {
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 666))",
                &[&key],
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn lock_published_head(transaction: &mut Transaction<'_>, namespace: &str) -> Result<(), String> {
    let key = advisory_lock_key(&[namespace, "published_head"]);
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 666))",
            &[&key],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn insert_members_postgres(
    transaction: &mut Transaction<'_>,
    members: &[DefinitionMember],
) -> Result<(), String> {
    for member in members {
        member.verify()?;
        let body_json = serde_json::to_string(member).map_err(|error| error.to_string())?;
        let inserted = transaction
            .execute(
                "INSERT INTO sekai_definition_members (
                    namespace, member_digest, member_kind, member_id, definition_json, body_json
                 ) VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (namespace, member_digest) DO NOTHING",
                &[
                    &member.namespace,
                    &member.member_digest,
                    &member.member_kind,
                    &member.member_id,
                    &member.definition_json,
                    &body_json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if inserted == 0 {
            let row = transaction
                .query_one(
                    "SELECT body_json FROM sekai_definition_members
                     WHERE namespace=$1 AND member_digest=$2",
                    &[&member.namespace, &member.member_digest],
                )
                .map_err(|error| error.to_string())?;
            let existing: String = row.get(0);
            if existing != body_json {
                return Err("immutable_definition_member_conflict: digest is already bound".into());
            }
        }
    }
    Ok(())
}

fn insert_revision_postgres(
    transaction: &mut Transaction<'_>,
    revision: &DefinitionRevision,
) -> Result<DefinitionRevision, String> {
    revision.verify()?;
    let body_json = serde_json::to_string(revision).map_err(|error| error.to_string())?;
    let inserted = transaction
        .execute(
            "INSERT INTO sekai_definition_revisions (
                namespace, revision_digest, parent_revision_digest, published, body_json,
                created_by, created_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (namespace, revision_digest) DO NOTHING",
            &[
                &revision.namespace,
                &revision.revision_digest,
                &revision.parent_revision_digest,
                &revision.published,
                &body_json,
                &revision.created_by,
                &revision.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    if inserted == 0 {
        let row = transaction
            .query_one(
                "SELECT body_json FROM sekai_definition_revisions
                 WHERE namespace=$1 AND revision_digest=$2",
                &[&revision.namespace, &revision.revision_digest],
            )
            .map_err(|error| error.to_string())?;
        let existing: String = row.get(0);
        let existing: DefinitionRevision = serde_json::from_str(&existing)
            .map_err(|error| format!("corrupt definition revision: {error}"))?;
        existing.verify()?;
        if existing.contract_version != revision.contract_version
            || existing.namespace != revision.namespace
            || existing.revision_digest != revision.revision_digest
            || existing.parent_revision_digest != revision.parent_revision_digest
            || existing.members != revision.members
            || existing.published != revision.published
        {
            return Err("immutable_definition_revision_conflict: digest is already bound".into());
        }
        return Ok(existing);
    }
    Ok(revision.clone())
}

fn load_published_head_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
) -> Result<Option<String>, String> {
    client
        .query_opt(
            "SELECT revision_digest FROM sekai_definition_published_heads WHERE namespace=$1",
            &[&namespace],
        )
        .map_err(|error| error.to_string())?
        .map(|row| Ok(row.get(0)))
        .transpose()
}

fn write_published_head_postgres(
    transaction: &mut Transaction<'_>,
    namespace: &str,
    revision_digest: &str,
    now_ms: i64,
    expected: Option<&str>,
) -> Result<(), String> {
    match expected {
        None => {
            // A head bound by any writer, including one that committed after
            // this transaction started, wins: the same digest is an
            // idempotent seed, anything else is a stale head.
            transaction
                .execute(
                    "INSERT INTO sekai_definition_published_heads (
                        namespace, revision_digest, updated_at_ms
                     ) VALUES ($1, $2, $3)
                     ON CONFLICT (namespace) DO NOTHING",
                    &[&namespace, &revision_digest, &now_ms],
                )
                .map_err(|error| error.to_string())?;
            let existing = load_published_head_postgres(transaction, namespace)?;
            if existing.as_deref() != Some(revision_digest) {
                return Err(
                    "stale_published_definition_head: published head is already bound".into(),
                );
            }
            Ok(())
        }
        Some(previous) => {
            let updated = transaction
                .execute(
                    "UPDATE sekai_definition_published_heads
                     SET revision_digest=$1, updated_at_ms=$2
                     WHERE namespace=$3 AND revision_digest=$4",
                    &[&revision_digest, &now_ms, &namespace, &previous],
                )
                .map_err(|error| error.to_string())?;
            if updated != 1 {
                return Err(
                    "stale_published_definition_head: published head does not match pinned base"
                        .into(),
                );
            }
            Ok(())
        }
    }
}

fn load_proposal_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    proposal_id: &str,
) -> Result<Option<DefinitionProposal>, String> {
    client
        .query_opt(
            "SELECT body_json FROM sekai_definition_proposals
             WHERE namespace=$1 AND proposal_id=$2",
            &[&namespace, &proposal_id],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            let body: String = row.get(0);
            let proposal: DefinitionProposal = serde_json::from_str(&body)
                .map_err(|error| format!("corrupt definition proposal: {error}"))?;
            proposal.verify()?;
            Ok(proposal)
        })
        .transpose()
}

/// PostgreSQL twin of `open_replacement_proposal_sqlite`.
fn open_replacement_proposal_postgres(
    transaction: &mut postgres::Transaction<'_>,
    replacement: &ReplacementProposal<'_>,
    published: &str,
    published_revision: &DefinitionRevision,
    actor: &str,
    now_ms: i64,
) -> Result<DefinitionProposal, String> {
    let (upserts, removals) = rollback_member_edits(published_revision, &replacement.members)?;
    let branch = DefinitionBranch {
        contract_version: crate::sekai::definition_branch::BRANCH_CONTRACT_VERSION.into(),
        namespace: replacement.namespace.to_string(),
        branch_id: replacement.branch_id.to_string(),
        base_revision_digest: published.to_string(),
        head_revision_digest: published.to_string(),
        created_by: actor.into(),
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    transaction
        .execute(
            "INSERT INTO sekai_definition_branches (
                namespace, branch_id, base_revision_digest, head_revision_digest,
                created_by, created_at_ms, updated_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6, $6)",
            &[
                &branch.namespace,
                &branch.branch_id,
                &branch.base_revision_digest,
                &branch.head_revision_digest,
                &branch.created_by,
                &branch.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    let candidate =
        match apply_member_changes(published_revision, &upserts, &removals, actor, now_ms) {
            Err(error) if error.starts_with("definition_edit_no_change") => {
                return Err(
                    "definition_proposal_no_change: proposed members match the published member set"
                        .into(),
                );
            }
            other => other?,
        };
    insert_members_postgres(transaction, &upserts)?;
    let revision = insert_revision_postgres(transaction, &candidate)?;
    let updated = transaction
        .execute(
            "UPDATE sekai_definition_branches
             SET head_revision_digest=$1, updated_at_ms=$2
             WHERE namespace=$3 AND branch_id=$4 AND head_revision_digest=$5",
            &[
                &revision.revision_digest,
                &now_ms,
                &replacement.namespace,
                &replacement.branch_id,
                &published,
            ],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("stale_definition_branch_head: expected head is no longer current".into());
    }
    let proposal_digest = proposal_content_digest(&PreparedProposalDigestInput {
        namespace: replacement.namespace,
        branch_id: replacement.branch_id,
        proposal_id: replacement.proposal_id,
        base_digest: published,
        candidate_digest: &revision.revision_digest,
        eval_plan_digests: &[],
        named_foreign_digests: &[],
        restored_from_digest: replacement.restored_from_digest,
        migration_plan_digest: replacement.migration_plan_digest,
        major_revision: false,
        source_package_digest: replacement.source_package_digest,
    })?;
    let proposal = DefinitionProposal {
        contract_version: PROPOSAL_CONTRACT_VERSION.into(),
        namespace: replacement.namespace.to_string(),
        branch_id: replacement.branch_id.to_string(),
        proposal_id: replacement.proposal_id.to_string(),
        base_digest: published.to_string(),
        candidate_digest: revision.revision_digest.clone(),
        proposal_digest,
        eval_plan_digests: Vec::new(),
        named_foreign_digests: Vec::new(),
        approvals: Vec::new(),
        status: STATUS_OPEN.into(),
        created_by: actor.into(),
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
        receipt_id: String::new(),
        close_reason_code: String::new(),
        restored_from_digest: replacement.restored_from_digest.into(),
        migration_plan_digest: replacement.migration_plan_digest.into(),
        major_revision: false,
        source_package_digest: replacement.source_package_digest.into(),
    };
    insert_proposal_postgres(transaction, &proposal)?;
    Ok(proposal)
}

fn insert_proposal_postgres(
    transaction: &mut Transaction<'_>,
    proposal: &DefinitionProposal,
) -> Result<(), String> {
    proposal.verify()?;
    let body_json = serde_json::to_string(proposal).map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO sekai_definition_proposals (
                namespace, proposal_id, branch_id, proposal_digest, status, body_json,
                created_by, created_at_ms, updated_at_ms, receipt_id, close_reason_code
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            &[
                &proposal.namespace,
                &proposal.proposal_id,
                &proposal.branch_id,
                &proposal.proposal_digest,
                &proposal.status,
                &body_json,
                &proposal.created_by,
                &proposal.created_at_ms,
                &proposal.updated_at_ms,
                &proposal.receipt_id,
                &proposal.close_reason_code,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn update_proposal_postgres(
    transaction: &mut Transaction<'_>,
    proposal: &DefinitionProposal,
) -> Result<(), String> {
    proposal.verify()?;
    let body_json = serde_json::to_string(proposal).map_err(|error| error.to_string())?;
    let updated = transaction
        .execute(
            "UPDATE sekai_definition_proposals
             SET status=$1, body_json=$2, updated_at_ms=$3, receipt_id=$4, close_reason_code=$5
             WHERE namespace=$6 AND proposal_id=$7",
            &[
                &proposal.status,
                &body_json,
                &proposal.updated_at_ms,
                &proposal.receipt_id,
                &proposal.close_reason_code,
                &proposal.namespace,
                &proposal.proposal_id,
            ],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("definition_proposal_not_found: proposal is unavailable".into());
    }
    Ok(())
}

fn mark_revision_published_postgres(
    transaction: &mut Transaction<'_>,
    revision: &DefinitionRevision,
) -> Result<DefinitionRevision, String> {
    // `published` records that this revision was a published head. The current
    // pointer lives in `published_heads`; previous heads stay published so a
    // later branch can start from them. Content identity does not include this flag.
    let mut published = revision.clone();
    published.published = true;
    published.verify()?;
    let body_json = serde_json::to_string(&published).map_err(|error| error.to_string())?;
    let updated = transaction
        .execute(
            "UPDATE sekai_definition_revisions
             SET published=TRUE, body_json=$1
             WHERE namespace=$2 AND revision_digest=$3",
            &[&body_json, &published.namespace, &published.revision_digest],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("definition_revision_not_found: candidate revision is unavailable".into());
    }
    Ok(published)
}

fn get_agent_definition_certification_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    revision_digest: &str,
    for_update: bool,
) -> Result<Option<crate::sekai::agent_promotion::AgentDefinitionCertification>, String> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    Ok(client
        .query_opt(
            &format!(
                "SELECT suite_id, certification_id, baseline_status, latest_status,
                        expires_at_ms, revoked_at_ms, bound_by, bound_at_ms, mean_score_milli
                 FROM sekai_agent_definition_certifications
                 WHERE namespace=$1 AND revision_digest=$2{lock}"
            ),
            &[&namespace, &revision_digest],
        )
        .map_err(|error| error.to_string())?
        .map(
            |row| crate::sekai::agent_promotion::AgentDefinitionCertification {
                namespace: namespace.into(),
                revision_digest: revision_digest.into(),
                suite_id: row.get(0),
                certification_id: row.get(1),
                baseline_status: row.get(2),
                latest_status: row.get(3),
                expires_at_ms: row.get(4),
                revoked_at_ms: row.get(5),
                bound_by: row.get(6),
                bound_at_ms: row.get(7),
                mean_score_milli: row.get(8),
            },
        ))
}

impl PostgresDb {
    pub fn put_agent_definition_certification(
        &self,
        certification: &crate::sekai::agent_promotion::AgentDefinitionCertification,
    ) -> Result<(), String> {
        certification.validate()?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_published_head(&mut transaction, &certification.namespace)?;
        let existing = get_agent_definition_certification_postgres(
            &mut transaction,
            &certification.namespace,
            &certification.revision_digest,
            true,
        )?;
        crate::sekai::agent_promotion::refuse_revoke_undo(
            existing.as_ref(),
            certification.revoked_at_ms,
        )?;
        transaction
            .execute(
                "INSERT INTO sekai_agent_definition_certifications (
                    namespace, revision_digest, suite_id, certification_id,
                    baseline_status, latest_status, expires_at_ms, revoked_at_ms,
                    bound_by, bound_at_ms, mean_score_milli
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (namespace, revision_digest) DO UPDATE SET
                    suite_id=EXCLUDED.suite_id,
                    certification_id=EXCLUDED.certification_id,
                    baseline_status=EXCLUDED.baseline_status,
                    latest_status=EXCLUDED.latest_status,
                    expires_at_ms=EXCLUDED.expires_at_ms,
                    revoked_at_ms=CASE
                        WHEN sekai_agent_definition_certifications.revoked_at_ms > 0
                        THEN sekai_agent_definition_certifications.revoked_at_ms
                        ELSE EXCLUDED.revoked_at_ms
                    END,
                    bound_by=EXCLUDED.bound_by,
                    bound_at_ms=EXCLUDED.bound_at_ms,
                    mean_score_milli=EXCLUDED.mean_score_milli",
                &[
                    &certification.namespace,
                    &certification.revision_digest,
                    &certification.suite_id,
                    &certification.certification_id,
                    &certification.baseline_status,
                    &certification.latest_status,
                    &certification.expires_at_ms,
                    &certification.revoked_at_ms,
                    &certification.bound_by,
                    &certification.bound_at_ms,
                    &certification.mean_score_milli,
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn get_agent_definition_certification(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<crate::sekai::agent_promotion::AgentDefinitionCertification>, String> {
        Ok(self
            .connection()?
            .query_opt(
                "SELECT suite_id, certification_id, baseline_status, latest_status,
                        expires_at_ms, revoked_at_ms, bound_by, bound_at_ms, mean_score_milli
                 FROM sekai_agent_definition_certifications
                 WHERE namespace=$1 AND revision_digest=$2",
                &[&namespace, &revision_digest],
            )
            .map_err(|error| error.to_string())?
            .map(
                |row| crate::sekai::agent_promotion::AgentDefinitionCertification {
                    namespace: namespace.into(),
                    revision_digest: revision_digest.into(),
                    suite_id: row.get(0),
                    certification_id: row.get(1),
                    baseline_status: row.get(2),
                    latest_status: row.get(3),
                    expires_at_ms: row.get(4),
                    revoked_at_ms: row.get(5),
                    bound_by: row.get(6),
                    bound_at_ms: row.get(7),
                    mean_score_milli: row.get(8),
                },
            ))
    }
}

fn load_revision_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    revision_digest: &str,
) -> Result<Option<DefinitionRevision>, String> {
    client
        .query_opt(
            "SELECT body_json FROM sekai_definition_revisions
             WHERE namespace=$1 AND revision_digest=$2",
            &[&namespace, &revision_digest],
        )
        .map_err(|error| error.to_string())?
        .map(|row| {
            let body: String = row.get(0);
            let revision: DefinitionRevision = serde_json::from_str(&body)
                .map_err(|error| format!("corrupt definition revision: {error}"))?;
            revision.verify()?;
            if revision.namespace != namespace || revision.revision_digest != revision_digest {
                return Err("corrupt definition revision: lookup identity mismatch".into());
            }
            Ok(revision)
        })
        .transpose()
}

fn load_branch_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    branch_id: &str,
    for_update: bool,
) -> Result<Option<DefinitionBranch>, String> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let statement = format!(
        "SELECT base_revision_digest, head_revision_digest, created_by,
                created_at_ms, updated_at_ms
         FROM sekai_definition_branches WHERE namespace=$1 AND branch_id=$2{suffix}"
    );
    let branch = client
        .query_opt(&statement, &[&namespace, &branch_id])
        .map_err(|error| error.to_string())?
        .map(|row| DefinitionBranch {
            contract_version: crate::sekai::definition_branch::BRANCH_CONTRACT_VERSION.into(),
            namespace: namespace.into(),
            branch_id: branch_id.into(),
            base_revision_digest: row.get(0),
            head_revision_digest: row.get(1),
            created_by: row.get(2),
            created_at_ms: row.get(3),
            updated_at_ms: row.get(4),
        });
    Ok(branch)
}

pub fn load_members_postgres(
    client: &mut impl GenericClient,
    revision: &DefinitionRevision,
) -> Result<Vec<DefinitionMember>, String> {
    if revision.members.is_empty() {
        return Ok(Vec::new());
    }
    let digests = revision
        .members
        .iter()
        .map(|member| member.member_digest.clone())
        .collect::<Vec<_>>();
    let rows = client
        .query(
            "SELECT member_digest, body_json FROM sekai_definition_members
             WHERE namespace=$1 AND member_digest = ANY($2)",
            &[&revision.namespace, &digests],
        )
        .map_err(|error| error.to_string())?;
    let mut by_digest = BTreeMap::new();
    for row in rows {
        let digest: String = row.get(0);
        let body: String = row.get(1);
        if by_digest.insert(digest, body).is_some() {
            return Err("corrupt definition revision: duplicate member digest".into());
        }
    }
    let mut members = Vec::with_capacity(revision.members.len());
    for reference in &revision.members {
        let body = by_digest
            .get(&reference.member_digest)
            .ok_or_else(|| "corrupt definition revision: member is missing".to_string())?;
        members.push(DefinitionMember::from_stored_body(
            body, revision, reference,
        )?);
    }
    Ok(members)
}

fn load_member_postgres(
    client: &mut impl GenericClient,
    revision: &DefinitionRevision,
    member_kind: &str,
    member_id: &str,
) -> Result<Option<DefinitionMember>, String> {
    let Some(reference) = revision
        .members
        .iter()
        .find(|member| member.member_kind == member_kind && member.member_id == member_id)
    else {
        return Ok(None);
    };
    let row = client
        .query_opt(
            "SELECT body_json FROM sekai_definition_members
             WHERE namespace=$1 AND member_digest=$2",
            &[&revision.namespace, &reference.member_digest],
        )
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "corrupt definition revision: member is missing".to_string())?;
    let body: String = row.get(0);
    Ok(Some(DefinitionMember::from_stored_body(
        &body, revision, reference,
    )?))
}

fn replay_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    actor: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<Option<DefinitionWriteResult>, String> {
    let Some(row) = client
        .query_opt(
            "SELECT request_digest, result_json FROM sekai_definition_requests
             WHERE namespace=$1 AND actor=$2 AND idempotency_key=$3",
            &[&namespace, &actor, &idempotency_key],
        )
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let stored_digest: String = row.get(0);
    if stored_digest != request_digest {
        return Err(
            "definition_idempotency_conflict: key is bound to different canonical input".into(),
        );
    }
    let result_json: String = row.get(1);
    serde_json::from_str(&result_json)
        .map(Some)
        .map_err(|error| format!("corrupt definition replay result: {error}"))
}

struct PostgresHistoryStore<'a, C: GenericClient>(&'a mut C);

impl<C: GenericClient> PublishedDefinitionHistoryStore for PostgresHistoryStore<'_, C> {
    fn fetch_merged_history(
        &mut self,
        namespace: &str,
        cursor: Option<(i64, String)>,
        limit: usize,
    ) -> Result<Vec<PublishedDefinitionRevisionHistoryEntry>, String> {
        fetch_merged_history_postgres(self.0, namespace, cursor, limit)
    }

    fn load_history_revision(
        &mut self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<DefinitionRevision>, String> {
        load_revision_postgres(self.0, namespace, revision_digest)
    }
}

fn fetch_merged_history_postgres(
    client: &mut impl GenericClient,
    namespace: &str,
    cursor: Option<(i64, String)>,
    limit: usize,
) -> Result<Vec<PublishedDefinitionRevisionHistoryEntry>, String> {
    let has_cursor: i32 = i32::from(cursor.is_some());
    let (ms, proposal_id) = match cursor {
        Some((ms, proposal_id)) => (ms, proposal_id),
        None => (0, String::new()),
    };
    let limit = limit as i64;
    let rows = client
        .query(
            "SELECT p.body_json, p.receipt_id, p.updated_at_ms, p.proposal_id, a.actor
             FROM sekai_definition_proposals p
             INNER JOIN sekai_definition_branch_audit a
               ON a.namespace = p.namespace
              AND a.branch_id = p.proposal_id
              AND a.action = 'merge_proposal'
             WHERE p.namespace = $1
               AND p.status = 'merged'
               AND p.receipt_id <> ''
               AND ($2 = 0 OR p.updated_at_ms < $3 OR (p.updated_at_ms = $3 AND p.proposal_id < $4))
             ORDER BY p.updated_at_ms DESC, p.proposal_id DESC
             LIMIT $5",
            &[&namespace, &has_cursor, &ms, &proposal_id, &limit],
        )
        .map_err(|error| error.to_string())?;
    let mut entries = Vec::new();
    for row in rows {
        let body_json: String = row.get(0);
        let receipt_id: String = row.get(1);
        let updated_at_ms: i64 = row.get(2);
        let proposal_id: String = row.get(3);
        let actor: String = row.get(4);
        entries.push(history_entry_from_merged_proposal(
            &body_json,
            receipt_id,
            updated_at_ms,
            proposal_id,
            actor,
        )?);
    }
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn persist_result_postgres<T: serde::Serialize>(
    transaction: &mut Transaction<'_>,
    request: &T,
    actor: &str,
    request_digest: &str,
    result: &DefinitionWriteResult,
    previous_head_digest: &str,
    result_head_digest: &str,
    action: &str,
    now_ms: i64,
) -> Result<(), String> {
    let value = serde_json::to_value(request).map_err(|error| error.to_string())?;
    let namespace = string_field(&value, "namespace")?;
    let branch_id = optional_string_field(&value, "branch_id")
        .or_else(|| optional_string_field(&value, "proposal_id"))
        .ok_or_else(|| "definition request branch_id missing".to_string())?;
    let idempotency_key = string_field(&value, "idempotency_key")?;
    let result_json = serde_json::to_string(result).map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO sekai_definition_requests (
                namespace, actor, idempotency_key, request_digest, result_json, created_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &namespace,
                &actor,
                &idempotency_key,
                &request_digest,
                &result_json,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO sekai_definition_branch_audit (
                event_id, namespace, branch_id, actor, action, previous_head_digest,
                result_head_digest, request_digest, created_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &format!("definition-audit:{request_digest}"),
                &namespace,
                &branch_id,
                &actor,
                &action,
                &previous_head_digest,
                &result_head_digest,
                &request_digest,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn string_field<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    optional_string_field(value, field).ok_or_else(|| format!("definition request {field} missing"))
}

fn optional_string_field<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(serde_json::Value::as_str)
}

/// Every definition consumer binding object of `namespace`, read in the
/// merge transaction for the lint gate.
fn consumer_bindings_postgres(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &str,
) -> Result<Vec<crate::domain::Object>, String> {
    transaction
        .query(
            "SELECT id, properties FROM sekai_objects WHERE namespace = $1 AND kind = $2",
            &[
                &namespace,
                &crate::sekai::definition_consumer_impact::BINDING_KIND,
            ],
        )
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|row| {
            crate::db::definition_branch::binding_object(
                namespace,
                row.get(0),
                row.get::<_, &str>(1),
            )
        })
        .collect()
}
