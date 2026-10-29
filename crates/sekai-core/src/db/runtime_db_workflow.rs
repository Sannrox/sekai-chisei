//! Dual-backend community-store dispatch for workflow.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn get_workflow_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<crate::sekai::workflow_action::WorkflowActionBinding>, String> {
        match self {
            Self::Sqlite(db) => db.get_workflow_binding(namespace, binding_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_workflow_binding(namespace, binding_id))
            }
        }
    }

    pub fn get_workflow_callback(
        &self,
        namespace: &str,
        binding_id: &str,
        cursor: u64,
    ) -> Result<Option<crate::sekai::workflow_action::WorkflowCallback>, String> {
        match self {
            Self::Sqlite(db) => db.get_workflow_callback(namespace, binding_id, cursor),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_workflow_callback(namespace, binding_id, cursor)
            }),
        }
    }

    pub fn get_workflow_command(
        &self,
        namespace: &str,
        binding_id: &str,
        command: &str,
        expected_cursor: u64,
    ) -> Result<Option<crate::sekai::workflow_action::WorkflowCommandRecord>, String> {
        match self {
            Self::Sqlite(db) => {
                db.get_workflow_command(namespace, binding_id, command, expected_cursor)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_workflow_command(namespace, binding_id, command, expected_cursor)
            }),
        }
    }

    pub fn commit_workflow_transition(
        &self,
        expected: Option<&crate::sekai::workflow_action::WorkflowActionBinding>,
        next: &crate::sekai::workflow_action::WorkflowActionBinding,
        callback: Option<&crate::sekai::workflow_action::WorkflowCallback>,
        command: &crate::sekai::workflow_action::WorkflowCommandRecord,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.commit_workflow_transition(expected, next, callback, command),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.commit_workflow_transition(expected, next, callback, command)
            }),
        }
    }
}
