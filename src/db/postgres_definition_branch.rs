//! PostgreSQL persistence for governed definition branches.

use postgres::{GenericClient, Transaction};

use crate::db::postgres::PostgresDb;
use crate::sekai::definition_branch::{
    ApplyDefinitionBranchEdit, CreateDefinitionBranch, DefinitionBranch,
    DefinitionBranchEditResult, DefinitionMember, DefinitionRevision, DefinitionWriteResult,
    apply_member_changes, changed_member_digests, validate_revision_members,
};
use crate::sekai::definition_proposal::{
    ApproveDefinitionProposal, CloseDefinitionProposal, CreateDefinitionProposal,
    DefinitionProposal, DefinitionProposalApproval, DefinitionProposalMergeResult,
    MergeDefinitionProposal, PROPOSAL_CONTRACT_VERSION, STATUS_CLOSED, STATUS_MERGED, STATUS_OPEN,
    reject_foreign_member_grants,
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
        validate_revision_members(revision, members)?;
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
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

    pub fn get_definition_proposal(
        &self,
        namespace: &str,
        proposal_id: &str,
    ) -> Result<Option<DefinitionProposal>, String> {
        load_proposal_postgres(&mut *self.connection()?, namespace, proposal_id)
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
        if published != proposal.base_digest {
            return Err(
                "stale_published_definition_head: published head does not match pinned base".into(),
            );
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
        let published_revision = mark_revision_published_postgres(&mut transaction, &candidate)?;
        write_published_head_postgres(
            &mut transaction,
            &proposal.namespace,
            &published_revision.revision_digest,
            now_ms,
            Some(&published),
        )?;
        proposal.status = STATUS_MERGED.into();
        proposal.updated_at_ms = now_ms;
        update_proposal_postgres(&mut transaction, &proposal)?;
        let result = DefinitionWriteResult::MergeProposal {
            result: Box::new(DefinitionProposalMergeResult {
                proposal: proposal.clone(),
                previous_published_digest: published,
                published_revision: published_revision.clone(),
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
    let mut keys = vec![format!("{namespace}\0{actor}\0{idempotency_key}")];
    if let Some(branch_id) = optional_string_field(&value, "branch_id") {
        keys.push(format!("{namespace}\0{branch_id}"));
    }
    if let Some(proposal_id) = optional_string_field(&value, "proposal_id") {
        keys.push(format!("{namespace}\0proposal\0{proposal_id}"));
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
    let key = format!("{namespace}\0published_head");
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
            let existing = load_published_head_postgres(transaction, namespace)?;
            if let Some(existing) = existing {
                if existing != revision_digest {
                    return Err(
                        "stale_published_definition_head: published head is already bound".into(),
                    );
                }
                return Ok(());
            }
            transaction
                .execute(
                    "INSERT INTO sekai_definition_published_heads (
                        namespace, revision_digest, updated_at_ms
                     ) VALUES ($1, $2, $3)",
                    &[&namespace, &revision_digest, &now_ms],
                )
                .map_err(|error| error.to_string())?;
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
                created_by, created_at_ms, updated_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
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
             SET status=$1, body_json=$2, updated_at_ms=$3
             WHERE namespace=$4 AND proposal_id=$5",
            &[
                &proposal.status,
                &body_json,
                &proposal.updated_at_ms,
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

fn load_members_postgres(
    client: &mut impl GenericClient,
    revision: &DefinitionRevision,
) -> Result<Vec<DefinitionMember>, String> {
    let mut members = Vec::with_capacity(revision.members.len());
    for reference in &revision.members {
        let row = client
            .query_opt(
                "SELECT body_json FROM sekai_definition_members
                 WHERE namespace=$1 AND member_digest=$2",
                &[&revision.namespace, &reference.member_digest],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "corrupt definition revision: member is missing".to_string())?;
        let body: String = row.get(0);
        let member: DefinitionMember = serde_json::from_str(&body)
            .map_err(|error| format!("corrupt definition member: {error}"))?;
        member.verify()?;
        if member.member_kind != reference.member_kind || member.member_id != reference.member_id {
            return Err("corrupt definition revision: member identity mismatch".into());
        }
        members.push(member);
    }
    Ok(members)
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
