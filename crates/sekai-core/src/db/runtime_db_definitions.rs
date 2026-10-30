//! Dual-backend community-store dispatch for definitions.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_definition_revision(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<DefinitionRevision>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_definition_revision(
                db.as_ref(),
                namespace,
                revision_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_revision(
                    db.as_ref(),
                    namespace,
                    revision_digest,
                )
            }),
        }
    }

    pub fn get_definition_members(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Vec<DefinitionMember>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_definition_members(
                db.as_ref(),
                namespace,
                revision_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_members(
                    db.as_ref(),
                    namespace,
                    revision_digest,
                )
            }),
        }
    }

    pub fn get_definition_member(
        &self,
        namespace: &str,
        revision_digest: &str,
        member_kind: &str,
        member_id: &str,
    ) -> Result<Option<DefinitionMember>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_definition_member(
                db.as_ref(),
                namespace,
                revision_digest,
                member_kind,
                member_id,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_member(
                    db.as_ref(),
                    namespace,
                    revision_digest,
                    member_kind,
                    member_id,
                )
            }),
        }
    }

    pub fn get_definition_branch(
        &self,
        namespace: &str,
        branch_id: &str,
    ) -> Result<Option<DefinitionBranch>, String> {
        match self {
            Self::Sqlite(db) => {
                DefinitionBranchBackend::get_definition_branch(db.as_ref(), namespace, branch_id)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_branch(db.as_ref(), namespace, branch_id)
            }),
        }
    }

    pub fn create_definition_branch(
        &self,
        request: &CreateDefinitionBranch,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::create_definition_branch(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::create_definition_branch(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn apply_definition_branch_edit(
        &self,
        request: &ApplyDefinitionBranchEdit,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::apply_definition_branch_edit(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::apply_definition_branch_edit(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn seed_published_definition_revision(
        &self,
        revision: &DefinitionRevision,
        members: &[DefinitionMember],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::seed_published_definition_revision(
                db.as_ref(),
                revision,
                members,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::seed_published_definition_revision(
                    db.as_ref(),
                    revision,
                    members,
                )
            }),
        }
    }

    pub fn execute_definition_fact_migration(
        &self,
        request: &crate::sekai::definition_migration::ExecuteFactMigration,
        actor: &str,
        policy_context: &PrincipalPolicyContext,
        now_ms: i64,
    ) -> Result<crate::sekai::definition_migration::FactMigrationResult, String> {
        match self {
            Self::Sqlite(db) => {
                db.execute_definition_fact_migration(request, actor, policy_context, now_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.execute_definition_fact_migration(request, actor, policy_context, now_ms)
            }),
        }
    }

    pub fn get_definition_fact_migration(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<Option<crate::sekai::definition_migration::FactMigrationResult>, String> {
        match self {
            Self::Sqlite(db) => db.get_definition_fact_migration(namespace, migration_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_definition_fact_migration(namespace, migration_id)
            }),
        }
    }

    pub fn count_definition_fact_migration_audit(
        &self,
        namespace: &str,
        migration_id: &str,
    ) -> Result<i64, String> {
        match self {
            Self::Sqlite(db) => db.count_definition_fact_migration_audit(namespace, migration_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.count_definition_fact_migration_audit(namespace, migration_id)
            }),
        }
    }

    pub fn list_published_definition_namespaces(&self) -> Result<Vec<String>, String> {
        match self {
            Self::Sqlite(db) => db.list_published_definition_namespaces(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.list_published_definition_namespaces())
            }
        }
    }

    pub fn get_published_definition_revision(
        &self,
        namespace: &str,
    ) -> Result<Option<DefinitionRevision>, String> {
        match self {
            Self::Sqlite(db) => {
                DefinitionBranchBackend::get_published_definition_revision(db.as_ref(), namespace)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_published_definition_revision(db.as_ref(), namespace)
            }),
        }
    }

    pub fn list_published_definition_revisions(
        &self,
        namespace: &str,
        member_kind: &str,
        member_id: &str,
        page_token: &str,
        page_size: i32,
    ) -> Result<(Vec<PublishedDefinitionRevisionHistoryEntry>, String), String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::list_published_definition_revisions(
                db.as_ref(),
                namespace,
                member_kind,
                member_id,
                page_token,
                page_size,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::list_published_definition_revisions(
                    db.as_ref(),
                    namespace,
                    member_kind,
                    member_id,
                    page_token,
                    page_size,
                )
            }),
        }
    }

    pub fn get_definition_proposal(
        &self,
        namespace: &str,
        proposal_id: &str,
    ) -> Result<Option<DefinitionProposal>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_definition_proposal(
                db.as_ref(),
                namespace,
                proposal_id,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_definition_proposal(
                    db.as_ref(),
                    namespace,
                    proposal_id,
                )
            }),
        }
    }

    pub fn create_definition_proposal(
        &self,
        request: &CreateDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::create_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::create_definition_proposal(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn propose_definition_import(
        &self,
        request: &crate::sekai::definition_proposal::ProposeDefinitionImport,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::propose_definition_import(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::propose_definition_import(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn propose_definition_rollback(
        &self,
        request: &ProposeDefinitionRollback,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::propose_definition_rollback(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::propose_definition_rollback(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn approve_definition_proposal(
        &self,
        request: &ApproveDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::approve_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::approve_definition_proposal(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn merge_definition_proposal(
        &self,
        request: &MergeDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        let result = match self {
            Self::Sqlite(db) => DefinitionBranchBackend::merge_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::merge_definition_proposal(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }?;
        if matches!(result, DefinitionWriteResult::MergeProposal { .. }) {
            self.invalidate_namespace_hop_projection(&request.namespace, now_ms)?;
        }
        Ok(result)
    }

    pub fn close_definition_proposal(
        &self,
        request: &CloseDefinitionProposal,
        actor: &str,
        now_ms: i64,
    ) -> Result<DefinitionWriteResult, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::close_definition_proposal(
                db.as_ref(),
                request,
                actor,
                now_ms,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::close_definition_proposal(
                    db.as_ref(),
                    request,
                    actor,
                    now_ms,
                )
            }),
        }
    }

    pub fn put_service_principal(
        &self,
        registration: &crate::sekai::service_principal::ServicePrincipalRegistration,
    ) -> Result<Option<crate::sekai::service_principal::ServicePrincipalRegistration>, String> {
        match self {
            Self::Sqlite(db) => db.put_service_principal(registration),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_service_principal(registration))
            }
        }
    }

    pub fn get_service_principal(
        &self,
        principal: &str,
    ) -> Result<Option<crate::sekai::service_principal::ServicePrincipalRegistration>, String> {
        match self {
            Self::Sqlite(db) => db.get_service_principal(principal),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_service_principal(principal))
            }
        }
    }

    pub fn delete_service_principal(
        &self,
        principal: &str,
        tenant_id: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.delete_service_principal(principal, tenant_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.delete_service_principal(principal, tenant_id)
            }),
        }
    }

    pub fn put_agent_definition_certification(
        &self,
        certification: &crate::sekai::agent_promotion::AgentDefinitionCertification,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::put_agent_definition_certification(
                db.as_ref(),
                certification,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::put_agent_definition_certification(
                    db.as_ref(),
                    certification,
                )
            }),
        }
    }

    pub fn get_agent_definition_certification(
        &self,
        namespace: &str,
        revision_digest: &str,
    ) -> Result<Option<crate::sekai::agent_promotion::AgentDefinitionCertification>, String> {
        match self {
            Self::Sqlite(db) => DefinitionBranchBackend::get_agent_definition_certification(
                db.as_ref(),
                namespace,
                revision_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                DefinitionBranchBackend::get_agent_definition_certification(
                    db.as_ref(),
                    namespace,
                    revision_digest,
                )
            }),
        }
    }
}
