//! Backend-neutral persistence for governed definition branches.

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::sekai::definition_branch::{
    ApplyDefinitionBranchEdit, CreateDefinitionBranch, DefinitionBranch,
    DefinitionBranchEditResult, DefinitionMember, DefinitionRevision, DefinitionWriteResult,
    apply_member_changes, changed_member_digests, validate_revision_members,
};
use crate::sekai::definition_proposal::{
    ApproveDefinitionProposal, CloseDefinitionProposal, CreateDefinitionProposal,
    DefinitionProposal, DefinitionProposalApproval, DefinitionProposalMergeResult,
    MergeDefinitionProposal, PROPOSAL_CONTRACT_VERSION, STATUS_CLOSED, STATUS_MERGED, STATUS_OPEN,
    merge_receipt_id, reject_foreign_member_grants, require_descendant_candidate,
};

pub const POSTGRES_DEFINITION_BRANCH_SURFACE: &str = "sekai.definition-branch";

pub trait DefinitionBranchBackend: Send + Sync {
    fn seed_published_definition_revision(
        &self,
        revision: &DefinitionRevision,
        members: &[DefinitionMember],
    ) -> Result<(), String>;

    fn get_definition_revision(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<DefinitionRevision>, String>;

    fn get_definition_members(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Vec<DefinitionMember>, String>;

    fn get_definition_branch(
        &self,
        namespace: &str,
        branch_id: &str,
    ) -> Result<Option<DefinitionBranch>, String>;

    fn create_definition_branch(
        &self,
        request: &CreateDefinitionBranch,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String>;

    fn apply_definition_branch_edit(
        &self,
        request: &ApplyDefinitionBranchEdit,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String>;

    fn get_published_definition_revision(
        &self,
        namespace: &str,
    ) -> Result<Option<DefinitionRevision>, String>;

    fn get_definition_proposal(
        &self,
        namespace: &str,
        proposal_id: &str,
    ) -> Result<Option<DefinitionProposal>, String>;

    fn create_definition_proposal(
        &self,
        request: &CreateDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String>;

    fn approve_definition_proposal(
        &self,
        request: &ApproveDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String>;

    fn merge_definition_proposal(
        &self,
        request: &MergeDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String>;

    fn close_definition_proposal(
        &self,
        request: &CloseDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn seed_published_definition_revision(
            &self,
            revision: &DefinitionRevision,
            members: &[DefinitionMember],
        ) -> Result<(), String> {
            <$target>::seed_published_definition_revision(self, revision, members)
        }

        fn get_definition_revision(
            &self,
            namespace: &str,
            revision_digest: &str,
        ) -> Result<Option<DefinitionRevision>, String> {
            <$target>::get_definition_revision(self, namespace, revision_digest)
        }

        fn get_definition_members(
            &self,
            namespace: &str,
            revision_digest: &str,
        ) -> Result<Vec<DefinitionMember>, String> {
            <$target>::get_definition_members(self, namespace, revision_digest)
        }

        fn get_definition_branch(
            &self,
            namespace: &str,
            branch_id: &str,
        ) -> Result<Option<DefinitionBranch>, String> {
            <$target>::get_definition_branch(self, namespace, branch_id)
        }

        fn create_definition_branch(
            &self,
            request: &CreateDefinitionBranch,
            actor: &str,
            now_ms: i64,
        ) -> Result<DefinitionWriteResult, String> {
            <$target>::create_definition_branch(self, request, actor, now_ms)
        }

        fn apply_definition_branch_edit(
            &self,
            request: &ApplyDefinitionBranchEdit,
            actor: &str,
            now_ms: i64,
        ) -> Result<DefinitionWriteResult, String> {
            <$target>::apply_definition_branch_edit(self, request, actor, now_ms)
        }

        fn get_published_definition_revision(
            &self,
            namespace: &str,
        ) -> Result<Option<DefinitionRevision>, String> {
            <$target>::get_published_definition_revision(self, namespace)
        }

        fn get_definition_proposal(
            &self,
            namespace: &str,
            proposal_id: &str,
        ) -> Result<Option<DefinitionProposal>, String> {
            <$target>::get_definition_proposal(self, namespace, proposal_id)
        }

        fn create_definition_proposal(
            &self,
            request: &CreateDefinitionProposal,
            actor: &str,
            now_ms: i64,
        ) -> Result<DefinitionWriteResult, String> {
            <$target>::create_definition_proposal(self, request, actor, now_ms)
        }

        fn approve_definition_proposal(
            &self,
            request: &ApproveDefinitionProposal,
            actor: &str,
            now_ms: i64,
        ) -> Result<DefinitionWriteResult, String> {
            <$target>::approve_definition_proposal(self, request, actor, now_ms)
        }

        fn merge_definition_proposal(
            &self,
            request: &MergeDefinitionProposal,
            actor: &str,
            now_ms: i64,
        ) -> Result<DefinitionWriteResult, String> {
            <$target>::merge_definition_proposal(self, request, actor, now_ms)
        }

        fn close_definition_proposal(
            &self,
            request: &CloseDefinitionProposal,
            actor: &str,
            now_ms: i64,
        ) -> Result<DefinitionWriteResult, String> {
            <$target>::close_definition_proposal(self, request, actor, now_ms)
        }
    };
}

impl DefinitionBranchBackend for SekaiDb {
    forward!(SekaiDb);
}

impl DefinitionBranchBackend for PostgresDb {
    forward!(PostgresDb);
}

impl SekaiDb {
    pub(crate) fn migrate_definition_branches(&self) -> Result<(), String> {
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_definition_members (
                    namespace TEXT NOT NULL,
                    member_digest TEXT NOT NULL,
                    member_kind TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    definition_json TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    PRIMARY KEY(namespace, member_digest)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_definition_member_identity_content
                    ON sekai_definition_members(namespace, member_kind, member_id, member_digest);

                CREATE TABLE IF NOT EXISTS sekai_definition_revisions (
                    namespace TEXT NOT NULL,
                    revision_digest TEXT NOT NULL,
                    parent_revision_digest TEXT NOT NULL,
                    published INTEGER NOT NULL CHECK(published IN (0, 1)),
                    body_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, revision_digest)
                );
                CREATE INDEX IF NOT EXISTS idx_definition_revision_parent
                    ON sekai_definition_revisions(namespace, parent_revision_digest);

                CREATE TABLE IF NOT EXISTS sekai_definition_branches (
                    namespace TEXT NOT NULL,
                    branch_id TEXT NOT NULL,
                    base_revision_digest TEXT NOT NULL,
                    head_revision_digest TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, branch_id)
                );
                CREATE INDEX IF NOT EXISTS idx_definition_branch_head
                    ON sekai_definition_branches(namespace, head_revision_digest);

                CREATE TABLE IF NOT EXISTS sekai_definition_requests (
                    namespace TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, actor, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS sekai_definition_branch_audit (
                    event_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    branch_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    previous_head_digest TEXT NOT NULL,
                    result_head_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_definition_branch_audit_history
                    ON sekai_definition_branch_audit(namespace, branch_id, created_at_ms, event_id);

                CREATE TABLE IF NOT EXISTS sekai_definition_published_heads (
                    namespace TEXT PRIMARY KEY,
                    revision_digest TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sekai_definition_proposals (
                    namespace TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    branch_id TEXT NOT NULL,
                    proposal_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    body_json TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    receipt_id TEXT NOT NULL DEFAULT '',
                    close_reason_code TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(namespace, proposal_id)
                );
                CREATE INDEX IF NOT EXISTS idx_definition_proposal_branch
                    ON sekai_definition_proposals(namespace, branch_id, created_at_ms, proposal_id);

                INSERT OR IGNORE INTO sekai_definition_published_heads (
                    namespace, revision_digest, updated_at_ms
                )
                SELECT r.namespace, r.revision_digest, r.created_at_ms
                FROM sekai_definition_revisions r
                WHERE r.published = 1
                  AND r.revision_digest = (
                    SELECT r2.revision_digest
                    FROM sekai_definition_revisions r2
                    WHERE r2.namespace = r.namespace AND r2.published = 1
                    ORDER BY r2.created_at_ms DESC, r2.revision_digest DESC
                    LIMIT 1
                  );",
            )
            .map_err(|error| error.to_string())?;
        self.conn()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS sekai_object_revision_bindings (
                    object_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    revision_digest TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sekai_fact_migrations (
                    namespace TEXT NOT NULL,
                    migration_id TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, migration_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_fact_migration_snapshots (
                    namespace TEXT NOT NULL,
                    migration_id TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    properties_json TEXT NOT NULL,
                    revision_digest TEXT NOT NULL,
                    PRIMARY KEY(namespace, migration_id, object_id)
                );
                CREATE TABLE IF NOT EXISTS sekai_fact_migration_requests (
                    namespace TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    PRIMARY KEY(namespace, actor, idempotency_key)
                );",
            )
            .map_err(|error| error.to_string())?;
        for statement in [
            "ALTER TABLE sekai_definition_proposals ADD COLUMN receipt_id TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE sekai_definition_proposals ADD COLUMN close_reason_code TEXT NOT NULL DEFAULT ''",
        ] {
            match self.conn().execute(statement, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(_, Some(message)))
                    if message.contains("duplicate column name") => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }

    pub fn seed_published_definition_revision(
        &self,
        revision: &DefinitionRevision,
        members: &[DefinitionMember],
    ) -> Result<(), String> {
        if !revision.published {
            return Err("seed revision must be published".into());
        }
        validate_revision_members(revision, members)?;
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        insert_members_sqlite(&transaction, members)?;
        insert_revision_sqlite(&transaction, revision)?;
        write_published_head_sqlite(
            &transaction,
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
        load_revision_sqlite(&self.conn(), namespace, revision_digest)
    }

    pub fn get_definition_members(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Vec<DefinitionMember>, String> {
        let Some(revision) = self.get_definition_revision(namespace, revision_digest)? else {
            return Ok(Vec::new());
        };
        load_members_sqlite(&self.conn(), &revision)
    }

    pub fn get_definition_branch(
        &self,
        namespace: &str,
        branch_id: &str,
    ) -> Result<Option<DefinitionBranch>, String> {
        load_branch_sqlite(&self.conn(), namespace, branch_id)
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
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;

        if let Some(replayed) = replay_sqlite(
            &transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let parent = load_revision_sqlite(
            &transaction,
            &request.namespace,
            &request.parent_revision_digest,
        )?
        .filter(|revision| revision.published)
        .ok_or_else(|| {
            "definition_revision_not_found: parent revision is unavailable".to_string()
        })?;
        // `published` means the revision was a published head, not that it is
        // the current pointer. Merge still compare-and-swaps `published_heads`.
        if parent.namespace != request.namespace {
            return Err("definition_revision_not_found: parent revision is unavailable".into());
        }
        if load_branch_sqlite(&transaction, &request.namespace, &request.branch_id)?.is_some() {
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
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![
                    branch.namespace,
                    branch.branch_id,
                    branch.base_revision_digest,
                    branch.head_revision_digest,
                    branch.created_by,
                    branch.created_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
        let result = DefinitionWriteResult::CreateBranch {
            branch: branch.clone(),
        };
        persist_result_sqlite(
            &transaction,
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
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;

        if let Some(replayed) = replay_sqlite(
            &transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let mut branch = load_branch_sqlite(&transaction, &request.namespace, &request.branch_id)?
            .ok_or_else(|| "definition_branch_not_found: branch is unavailable".to_string())?;
        if branch.head_revision_digest != request.expected_head_digest {
            return Err("stale_definition_branch_head: expected head is no longer current".into());
        }
        let parent = load_revision_sqlite(
            &transaction,
            &request.namespace,
            &branch.head_revision_digest,
        )?
        .ok_or_else(|| "definition_revision_not_found: branch head is unavailable".to_string())?;
        let changed_member_digests = changed_member_digests(&parent, &upserts, &removals)?;
        let candidate = apply_member_changes(&parent, &upserts, &removals, actor, now_ms)?;
        insert_members_sqlite(&transaction, &upserts)?;
        let revision = insert_revision_sqlite(&transaction, &candidate)?;
        let updated = transaction
            .execute(
                "UPDATE sekai_definition_branches
                 SET head_revision_digest=?1, updated_at_ms=?2
                 WHERE namespace=?3 AND branch_id=?4 AND head_revision_digest=?5",
                params![
                    revision.revision_digest,
                    now_ms,
                    request.namespace,
                    request.branch_id,
                    request.expected_head_digest,
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
        persist_result_sqlite(
            &transaction,
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
        let connection = self.conn();
        let Some(digest) = load_published_head_sqlite(&connection, namespace)? else {
            return Ok(None);
        };
        load_revision_sqlite(&connection, namespace, &digest)
    }

    pub fn get_definition_proposal(
        &self,
        namespace: &str,
        proposal_id: &str,
    ) -> Result<Option<DefinitionProposal>, String> {
        load_proposal_sqlite(&self.conn(), namespace, proposal_id)
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
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(replayed) = replay_sqlite(
            &transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        if load_proposal_sqlite(&transaction, &request.namespace, &request.proposal_id)?.is_some() {
            return Err("definition_proposal_conflict: proposal identity is already in use".into());
        }
        let branch = load_branch_sqlite(&transaction, &request.namespace, &request.branch_id)?
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
        let published =
            load_published_head_sqlite(&transaction, &request.namespace)?.ok_or_else(|| {
                "definition_revision_not_found: published head is unavailable".to_string()
            })?;
        if published != request.base_digest {
            return Err(
                "stale_published_definition_head: published head does not match pinned base".into(),
            );
        }
        let candidate =
            load_revision_sqlite(&transaction, &request.namespace, &request.candidate_digest)?
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
        };
        insert_proposal_sqlite(&transaction, &proposal)?;
        let result = DefinitionWriteResult::CreateProposal {
            proposal: proposal.clone(),
        };
        persist_result_sqlite(
            &transaction,
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
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(replayed) = replay_sqlite(
            &transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let mut proposal =
            load_proposal_sqlite(&transaction, &request.namespace, &request.proposal_id)?
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
        update_proposal_sqlite(&transaction, &proposal)?;
        let result = DefinitionWriteResult::ApproveProposal {
            proposal: proposal.clone(),
        };
        persist_result_sqlite(
            &transaction,
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
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(replayed) = replay_sqlite(
            &transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let mut proposal =
            load_proposal_sqlite(&transaction, &request.namespace, &request.proposal_id)?
                .ok_or_else(|| {
                    "definition_proposal_not_found: proposal is unavailable".to_string()
                })?;
        proposal.require_open()?;
        if proposal.approvals.is_empty() {
            return Err(
                "definition_proposal_missing_approval: merge requires a live approval".into(),
            );
        }
        let branch = load_branch_sqlite(&transaction, &proposal.namespace, &proposal.branch_id)?
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
        let published =
            load_published_head_sqlite(&transaction, &proposal.namespace)?.ok_or_else(|| {
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
        let candidate = load_revision_sqlite(
            &transaction,
            &proposal.namespace,
            &proposal.candidate_digest,
        )?
        .ok_or_else(|| {
            "definition_revision_not_found: candidate revision is unavailable".to_string()
        })?;
        reject_foreign_member_grants(&candidate, &proposal.named_foreign_digests)?;
        require_descendant_candidate(&candidate, &proposal.base_digest, |digest| {
            load_revision_sqlite(&transaction, &proposal.namespace, digest)
        })?;
        let receipt_id = merge_receipt_id(
            &proposal.namespace,
            &proposal.proposal_id,
            &proposal.proposal_digest,
            &proposal.base_digest,
            &proposal.candidate_digest,
            &published,
        )?;
        let published_revision = mark_revision_published_sqlite(&transaction, &candidate, now_ms)?;
        write_published_head_sqlite(
            &transaction,
            &proposal.namespace,
            &published_revision.revision_digest,
            now_ms,
            Some(&published),
        )?;
        proposal.status = STATUS_MERGED.into();
        proposal.updated_at_ms = now_ms;
        proposal.receipt_id = receipt_id.clone();
        update_proposal_sqlite(&transaction, &proposal)?;
        let result = DefinitionWriteResult::MergeProposal {
            result: Box::new(DefinitionProposalMergeResult {
                proposal: proposal.clone(),
                previous_published_digest: published,
                published_revision: published_revision.clone(),
                receipt_id,
            }),
        };
        persist_result_sqlite(
            &transaction,
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
        let mut connection = self.conn();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(replayed) = replay_sqlite(
            &transaction,
            &request.namespace,
            actor,
            &request.idempotency_key,
            &request_digest,
        )? {
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(replayed);
        }
        let mut proposal =
            load_proposal_sqlite(&transaction, &request.namespace, &request.proposal_id)?
                .ok_or_else(|| {
                    "definition_proposal_not_found: proposal is unavailable".to_string()
                })?;
        proposal.require_open()?;
        proposal.status = STATUS_CLOSED.into();
        proposal.close_reason_code = request.reason_code.clone();
        proposal.updated_at_ms = now_ms;
        update_proposal_sqlite(&transaction, &proposal)?;
        let result = DefinitionWriteResult::CloseProposal {
            proposal: proposal.clone(),
        };
        persist_result_sqlite(
            &transaction,
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

fn insert_members_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    members: &[DefinitionMember],
) -> Result<(), String> {
    for member in members {
        member.verify()?;
        let body_json = serde_json::to_string(member).map_err(|error| error.to_string())?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT body_json FROM sekai_definition_members
                 WHERE namespace=?1 AND member_digest=?2",
                params![member.namespace, member.member_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(existing) = existing {
            if existing != body_json {
                return Err("immutable_definition_member_conflict: digest is already bound".into());
            }
            continue;
        }
        transaction
            .execute(
                "INSERT INTO sekai_definition_members (
                    namespace, member_digest, member_kind, member_id, definition_json, body_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    member.namespace,
                    member.member_digest,
                    member.member_kind,
                    member.member_id,
                    member.definition_json,
                    body_json,
                ],
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn insert_revision_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    revision: &DefinitionRevision,
) -> Result<DefinitionRevision, String> {
    revision.verify()?;
    let body_json = serde_json::to_string(revision).map_err(|error| error.to_string())?;
    let existing: Option<String> = transaction
        .query_row(
            "SELECT body_json FROM sekai_definition_revisions
             WHERE namespace=?1 AND revision_digest=?2",
            params![revision.namespace, revision.revision_digest],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    if let Some(existing) = existing {
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
    transaction
        .execute(
            "INSERT INTO sekai_definition_revisions (
                namespace, revision_digest, parent_revision_digest, published, body_json,
                created_by, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                revision.namespace,
                revision.revision_digest,
                revision.parent_revision_digest,
                revision.published as i32,
                body_json,
                revision.created_by,
                revision.created_at_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(revision.clone())
}

fn load_revision_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
    revision_digest: &str,
) -> Result<Option<DefinitionRevision>, String> {
    connection
        .query_row(
            "SELECT body_json FROM sekai_definition_revisions
             WHERE namespace=?1 AND revision_digest=?2",
            params![namespace, revision_digest],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|body| {
            let revision: DefinitionRevision = serde_json::from_str(&body)
                .map_err(|error| format!("corrupt definition revision: {error}"))?;
            revision.verify()?;
            Ok(revision)
        })
        .transpose()
}

fn load_branch_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
    branch_id: &str,
) -> Result<Option<DefinitionBranch>, String> {
    connection
        .query_row(
            "SELECT base_revision_digest, head_revision_digest, created_by,
                    created_at_ms, updated_at_ms
             FROM sekai_definition_branches WHERE namespace=?1 AND branch_id=?2",
            params![namespace, branch_id],
            |row| {
                Ok(DefinitionBranch {
                    contract_version: crate::sekai::definition_branch::BRANCH_CONTRACT_VERSION
                        .into(),
                    namespace: namespace.into(),
                    branch_id: branch_id.into(),
                    base_revision_digest: row.get(0)?,
                    head_revision_digest: row.get(1)?,
                    created_by: row.get(2)?,
                    created_at_ms: row.get(3)?,
                    updated_at_ms: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|error| error.to_string())
}

fn load_published_head_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
) -> Result<Option<String>, String> {
    connection
        .query_row(
            "SELECT revision_digest FROM sekai_definition_published_heads WHERE namespace=?1",
            params![namespace],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())
}

fn write_published_head_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    namespace: &str,
    revision_digest: &str,
    now_ms: i64,
    expected: Option<&str>,
) -> Result<(), String> {
    match expected {
        None => {
            let existing = load_published_head_sqlite(transaction, namespace)?;
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
                     ) VALUES (?1, ?2, ?3)",
                    params![namespace, revision_digest, now_ms],
                )
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        Some(previous) => {
            let updated = transaction
                .execute(
                    "UPDATE sekai_definition_published_heads
                     SET revision_digest=?1, updated_at_ms=?2
                     WHERE namespace=?3 AND revision_digest=?4",
                    params![revision_digest, now_ms, namespace, previous],
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

fn load_proposal_sqlite(
    connection: &rusqlite::Connection,
    namespace: &str,
    proposal_id: &str,
) -> Result<Option<DefinitionProposal>, String> {
    connection
        .query_row(
            "SELECT body_json FROM sekai_definition_proposals
             WHERE namespace=?1 AND proposal_id=?2",
            params![namespace, proposal_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| error.to_string())?
        .map(|body| {
            let proposal: DefinitionProposal = serde_json::from_str(&body)
                .map_err(|error| format!("corrupt definition proposal: {error}"))?;
            proposal.verify()?;
            Ok(proposal)
        })
        .transpose()
}

fn insert_proposal_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    proposal: &DefinitionProposal,
) -> Result<(), String> {
    proposal.verify()?;
    let body_json = serde_json::to_string(proposal).map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO sekai_definition_proposals (
                namespace, proposal_id, branch_id, proposal_digest, status, body_json,
                created_by, created_at_ms, updated_at_ms, receipt_id, close_reason_code
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                proposal.namespace,
                proposal.proposal_id,
                proposal.branch_id,
                proposal.proposal_digest,
                proposal.status,
                body_json,
                proposal.created_by,
                proposal.created_at_ms,
                proposal.updated_at_ms,
                proposal.receipt_id,
                proposal.close_reason_code,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn update_proposal_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    proposal: &DefinitionProposal,
) -> Result<(), String> {
    proposal.verify()?;
    let body_json = serde_json::to_string(proposal).map_err(|error| error.to_string())?;
    let updated = transaction
        .execute(
            "UPDATE sekai_definition_proposals
             SET status=?1, body_json=?2, updated_at_ms=?3, receipt_id=?4, close_reason_code=?5
             WHERE namespace=?6 AND proposal_id=?7",
            params![
                proposal.status,
                body_json,
                proposal.updated_at_ms,
                proposal.receipt_id,
                proposal.close_reason_code,
                proposal.namespace,
                proposal.proposal_id,
            ],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("definition_proposal_not_found: proposal is unavailable".into());
    }
    Ok(())
}

fn mark_revision_published_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    revision: &DefinitionRevision,
    _now_ms: i64,
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
             SET published=1, body_json=?1
             WHERE namespace=?2 AND revision_digest=?3",
            params![body_json, published.namespace, published.revision_digest],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err("definition_revision_not_found: candidate revision is unavailable".into());
    }
    Ok(published)
}

fn load_members_sqlite(
    connection: &rusqlite::Connection,
    revision: &DefinitionRevision,
) -> Result<Vec<DefinitionMember>, String> {
    let mut members = Vec::with_capacity(revision.members.len());
    for reference in &revision.members {
        let body: Option<String> = connection
            .query_row(
                "SELECT body_json FROM sekai_definition_members
                 WHERE namespace=?1 AND member_digest=?2",
                params![revision.namespace, reference.member_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let body =
            body.ok_or_else(|| "corrupt definition revision: member is missing".to_string())?;
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

fn replay_sqlite(
    transaction: &rusqlite::Transaction<'_>,
    namespace: &str,
    actor: &str,
    idempotency_key: &str,
    request_digest: &str,
) -> Result<Option<DefinitionWriteResult>, String> {
    let stored: Option<(String, String)> = transaction
        .query_row(
            "SELECT request_digest, result_json FROM sekai_definition_requests
             WHERE namespace=?1 AND actor=?2 AND idempotency_key=?3",
            params![namespace, actor, idempotency_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((stored_digest, result_json)) = stored else {
        return Ok(None);
    };
    if stored_digest != request_digest {
        return Err(
            "definition_idempotency_conflict: key is bound to different canonical input".into(),
        );
    }
    serde_json::from_str(&result_json)
        .map(Some)
        .map_err(|error| format!("corrupt definition replay result: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn persist_result_sqlite<T: serde::Serialize>(
    transaction: &rusqlite::Transaction<'_>,
    request: &T,
    actor: &str,
    request_digest: &str,
    result: &DefinitionWriteResult,
    previous_head_digest: &str,
    result_head_digest: &str,
    action: &str,
    now_ms: i64,
) -> Result<(), String> {
    let request_value = serde_json::to_value(request).map_err(|error| error.to_string())?;
    let namespace = request_value
        .get("namespace")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "definition request namespace missing".to_string())?;
    let branch_id = request_value
        .get("branch_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            request_value
                .get("proposal_id")
                .and_then(serde_json::Value::as_str)
        })
        .ok_or_else(|| "definition request branch_id missing".to_string())?;
    let idempotency_key = request_value
        .get("idempotency_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "definition request idempotency_key missing".to_string())?;
    let result_json = serde_json::to_string(result).map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO sekai_definition_requests (
                namespace, actor, idempotency_key, request_digest, result_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                namespace,
                actor,
                idempotency_key,
                request_digest,
                result_json,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO sekai_definition_branch_audit (
                event_id, namespace, branch_id, actor, action, previous_head_digest,
                result_head_digest, request_digest, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                format!("definition-audit:{request_digest}"),
                namespace,
                branch_id,
                actor,
                action,
                previous_head_digest,
                result_head_digest,
                request_digest,
                now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sekai::definition_branch::{
        DefinitionMemberInput, DefinitionRevisionMember, prepare_revision,
    };

    fn parent_fixture(
        db: &SekaiDb,
    ) -> (DefinitionRevision, DefinitionMember, CreateDefinitionBranch) {
        let member = DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Ticket".into(),
            definition_json: r#"{"name":"Ticket"}"#.into(),
            member_digest: String::new(),
        }
        .prepare("team-a")
        .unwrap();
        let revision = prepare_revision(
            "team-a",
            "",
            [DefinitionRevisionMember {
                member_kind: member.member_kind.clone(),
                member_id: member.member_id.clone(),
                member_digest: member.member_digest.clone(),
            }],
            true,
            "root",
            1,
        )
        .unwrap();
        db.seed_published_definition_revision(&revision, std::slice::from_ref(&member))
            .unwrap();
        let request = CreateDefinitionBranch {
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            parent_revision_digest: revision.revision_digest.clone(),
            idempotency_key: "create-1".into(),
        };
        (revision, member, request)
    }

    #[test]
    fn branch_edit_is_replayable_and_parent_is_immutable() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (parent, _, create) = parent_fixture(&db);
        let created = db.create_definition_branch(&create, "author", 2).unwrap();
        assert_eq!(
            created,
            db.create_definition_branch(&create, "author", 3).unwrap()
        );
        let edit = ApplyDefinitionBranchEdit {
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            expected_head_digest: parent.revision_digest.clone(),
            upserts: vec![DefinitionMemberInput {
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
                definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
                member_digest: String::new(),
            }],
            removals: Vec::new(),
            idempotency_key: "edit-1".into(),
        };
        let applied = db.apply_definition_branch_edit(&edit, "author", 4).unwrap();
        assert_eq!(
            applied,
            db.apply_definition_branch_edit(&edit, "author", 5).unwrap()
        );
        assert_eq!(
            db.get_definition_revision("team-a", &parent.revision_digest)
                .unwrap()
                .unwrap(),
            parent
        );
    }

    #[test]
    fn stale_head_and_conflicting_replay_fail_closed() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (parent, _, create) = parent_fixture(&db);
        db.create_definition_branch(&create, "author", 2).unwrap();
        let mut edit = ApplyDefinitionBranchEdit {
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            expected_head_digest: parent.revision_digest,
            upserts: vec![DefinitionMemberInput {
                member_kind: "control".into(),
                member_id: "retention".into(),
                definition_json: r#"{"mode":"strict"}"#.into(),
                member_digest: String::new(),
            }],
            removals: Vec::new(),
            idempotency_key: "edit-1".into(),
        };
        db.apply_definition_branch_edit(&edit, "author", 3).unwrap();
        edit.idempotency_key = "edit-2".into();
        assert!(
            db.apply_definition_branch_edit(&edit, "author", 4)
                .unwrap_err()
                .contains("stale_definition_branch_head")
        );
        let mut conflicting = create;
        conflicting.branch_id = "other".into();
        assert!(
            db.create_definition_branch(&conflicting, "author", 5)
                .unwrap_err()
                .contains("definition_idempotency_conflict")
        );
    }

    #[test]
    fn published_heads_are_backfilled_from_existing_published_revisions() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (parent, _, _) = parent_fixture(&db);
        db.conn()
            .execute("DELETE FROM sekai_definition_published_heads", [])
            .unwrap();
        assert!(
            db.get_published_definition_revision("team-a")
                .unwrap()
                .is_none()
        );
        db.migrate_definition_branches().unwrap();
        assert_eq!(
            db.get_published_definition_revision("team-a")
                .unwrap()
                .unwrap()
                .revision_digest,
            parent.revision_digest
        );
    }

    #[test]
    fn unknown_parent_and_non_published_parent_are_unavailable() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (_, _, mut create) = parent_fixture(&db);
        create.parent_revision_digest = format!("sha256:{}", "a".repeat(64));
        assert!(
            db.create_definition_branch(&create, "author", 2)
                .unwrap_err()
                .contains("definition_revision_not_found")
        );
    }

    #[test]
    fn failed_head_advance_rolls_back_revision_request_and_audit() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (parent, _, create) = parent_fixture(&db);
        db.create_definition_branch(&create, "author", 2).unwrap();
        db.conn()
            .execute_batch(
                "CREATE TRIGGER reject_definition_head_advance
                 BEFORE UPDATE ON sekai_definition_branches
                 BEGIN
                     SELECT RAISE(ABORT, 'injected branch-head failure');
                 END;",
            )
            .unwrap();
        let edit = ApplyDefinitionBranchEdit {
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            expected_head_digest: parent.revision_digest.clone(),
            upserts: vec![DefinitionMemberInput {
                member_kind: "control".into(),
                member_id: "retention".into(),
                definition_json: r#"{"mode":"strict"}"#.into(),
                member_digest: String::new(),
            }],
            removals: Vec::new(),
            idempotency_key: "edit-interrupted".into(),
        };
        let changed_digest = edit.upserts[0].prepare("team-a").unwrap().member_digest;
        assert!(
            db.apply_definition_branch_edit(&edit, "author", 3)
                .unwrap_err()
                .contains("injected branch-head failure")
        );
        let connection = db.conn();
        let head: String = connection
            .query_row(
                "SELECT head_revision_digest FROM sekai_definition_branches
                 WHERE namespace='team-a' AND branch_id='feature'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(head, parent.revision_digest);
        let member_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sekai_definition_members
                 WHERE namespace='team-a' AND member_digest=?1",
                params![changed_digest],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(member_count, 0);
        let request_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sekai_definition_requests
                 WHERE namespace='team-a' AND idempotency_key='edit-interrupted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(request_count, 0);
        let audit_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sekai_definition_branch_audit
                 WHERE namespace='team-a' AND action='apply_edit'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(audit_count, 0);
    }

    #[test]
    fn merge_denies_a_candidate_that_does_not_descend_from_the_pinned_base() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (parent, _, create) = parent_fixture(&db);
        db.create_definition_branch(&create, "author", 2).unwrap();
        let disconnected_member = DefinitionMemberInput {
            member_kind: "object_type".into(),
            member_id: "Incident".into(),
            definition_json: r#"{"name":"Incident"}"#.into(),
            member_digest: String::new(),
        }
        .prepare("team-a")
        .unwrap();
        let disconnected = prepare_revision(
            "team-a",
            "",
            [DefinitionRevisionMember {
                member_kind: disconnected_member.member_kind.clone(),
                member_id: disconnected_member.member_id.clone(),
                member_digest: disconnected_member.member_digest.clone(),
            }],
            false,
            "author",
            3,
        )
        .unwrap();
        {
            let mut connection = db.conn();
            let transaction = connection.transaction().unwrap();
            insert_members_sqlite(&transaction, &[disconnected_member]).unwrap();
            insert_revision_sqlite(&transaction, &disconnected).unwrap();
            transaction
                .execute(
                    "UPDATE sekai_definition_branches
                     SET head_revision_digest=?1, updated_at_ms=3
                     WHERE namespace='team-a' AND branch_id='feature'",
                    params![disconnected.revision_digest],
                )
                .unwrap();
            transaction.commit().unwrap();
        }
        db.create_definition_proposal(
            &CreateDefinitionProposal {
                namespace: "team-a".into(),
                branch_id: "feature".into(),
                proposal_id: "cs-foreign".into(),
                base_digest: parent.revision_digest.clone(),
                candidate_digest: disconnected.revision_digest.clone(),
                eval_plan_digests: Vec::new(),
                named_foreign_digests: Vec::new(),
                idempotency_key: "propose-foreign".into(),
            },
            "author",
            4,
        )
        .unwrap();
        db.approve_definition_proposal(
            &ApproveDefinitionProposal {
                namespace: "team-a".into(),
                proposal_id: "cs-foreign".into(),
                idempotency_key: "approve-foreign".into(),
            },
            "author",
            5,
        )
        .unwrap();
        let error = db
            .merge_definition_proposal(
                &MergeDefinitionProposal {
                    namespace: "team-a".into(),
                    proposal_id: "cs-foreign".into(),
                    expected_published_digest: parent.revision_digest.clone(),
                    idempotency_key: "merge-foreign".into(),
                },
                "author",
                6,
            )
            .unwrap_err();
        assert!(error.contains("incompatible_definition_proposal_candidate"));
        assert!(!error.contains("AlreadyExists"));
        assert_eq!(
            db.get_published_definition_revision("team-a")
                .unwrap()
                .unwrap()
                .revision_digest,
            parent.revision_digest
        );
    }

    #[test]
    fn interrupted_merge_leaves_published_head_without_a_receipt() {
        let db = SekaiDb::new(":memory:").unwrap();
        let (parent, _, create) = parent_fixture(&db);
        db.create_definition_branch(&create, "author", 2).unwrap();
        let edit = ApplyDefinitionBranchEdit {
            namespace: "team-a".into(),
            branch_id: "feature".into(),
            expected_head_digest: parent.revision_digest.clone(),
            upserts: vec![DefinitionMemberInput {
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
                definition_json: r#"{"name":"Ticket","properties":["title"]}"#.into(),
                member_digest: String::new(),
            }],
            removals: Vec::new(),
            idempotency_key: "edit-1".into(),
        };
        let DefinitionWriteResult::ApplyEdit { result } =
            db.apply_definition_branch_edit(&edit, "author", 3).unwrap()
        else {
            panic!("expected edit");
        };
        db.create_definition_proposal(
            &CreateDefinitionProposal {
                namespace: "team-a".into(),
                branch_id: "feature".into(),
                proposal_id: "cs-1".into(),
                base_digest: parent.revision_digest.clone(),
                candidate_digest: result.revision.revision_digest.clone(),
                eval_plan_digests: Vec::new(),
                named_foreign_digests: Vec::new(),
                idempotency_key: "propose-1".into(),
            },
            "author",
            4,
        )
        .unwrap();
        db.approve_definition_proposal(
            &ApproveDefinitionProposal {
                namespace: "team-a".into(),
                proposal_id: "cs-1".into(),
                idempotency_key: "approve-1".into(),
            },
            "author",
            5,
        )
        .unwrap();
        db.conn()
            .execute_batch(
                "CREATE TRIGGER reject_definition_merge_receipt
                 BEFORE INSERT ON sekai_definition_requests
                 WHEN NEW.idempotency_key = 'merge-interrupted'
                 BEGIN
                     SELECT RAISE(ABORT, 'injected merge receipt failure');
                 END;",
            )
            .unwrap();
        assert!(
            db.merge_definition_proposal(
                &MergeDefinitionProposal {
                    namespace: "team-a".into(),
                    proposal_id: "cs-1".into(),
                    expected_published_digest: parent.revision_digest.clone(),
                    idempotency_key: "merge-interrupted".into(),
                },
                "author",
                6,
            )
            .unwrap_err()
            .contains("injected merge receipt failure")
        );
        let connection = db.conn();
        let published: String = connection
            .query_row(
                "SELECT revision_digest FROM sekai_definition_published_heads
                 WHERE namespace='team-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(published, parent.revision_digest);
        let status: String = connection
            .query_row(
                "SELECT status FROM sekai_definition_proposals
                 WHERE namespace='team-a' AND proposal_id='cs-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, STATUS_OPEN);
        let request_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sekai_definition_requests
                 WHERE namespace='team-a' AND idempotency_key='merge-interrupted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(request_count, 0);
        let audit_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sekai_definition_branch_audit
                 WHERE namespace='team-a' AND action='merge_proposal'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(audit_count, 0);
    }
}
