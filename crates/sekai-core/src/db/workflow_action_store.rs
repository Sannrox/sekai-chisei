//! SQLite persistence for workflow-action bindings (#709).

use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::sekai::SekaiDb;
use crate::sekai::workflow_action::{
    WORKFLOW_UNAVAILABLE, WorkflowActionBinding, WorkflowCallback, WorkflowCommandRecord,
};

impl SekaiDb {
    pub fn get_workflow_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<WorkflowActionBinding>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_workflow_action_bindings
                 WHERE namespace = ?1 AND binding_id = ?2",
                params![namespace, binding_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("decode workflow action: {error}"))
        })
        .transpose()
    }

    pub fn get_workflow_callback(
        &self,
        namespace: &str,
        binding_id: &str,
        cursor: u64,
    ) -> Result<Option<WorkflowCallback>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_workflow_action_callbacks
                 WHERE namespace = ?1 AND binding_id = ?2 AND cursor_value = ?3",
                params![namespace, binding_id, cursor as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode workflow callback: {error}"))
        })
        .transpose()
    }

    pub fn get_workflow_command(
        &self,
        namespace: &str,
        binding_id: &str,
        command: &str,
        expected_cursor: u64,
    ) -> Result<Option<WorkflowCommandRecord>, String> {
        let json: Option<String> = self
            .conn()
            .query_row(
                "SELECT record_json FROM sekai_workflow_action_commands
                 WHERE namespace = ?1 AND binding_id = ?2 AND command = ?3 AND expected_cursor = ?4",
                params![namespace, binding_id, command, expected_cursor as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|error| format!("decode workflow command: {error}"))
        })
        .transpose()
    }

    pub fn commit_workflow_transition(
        &self,
        expected: Option<&WorkflowActionBinding>,
        next: &WorkflowActionBinding,
        callback: Option<&WorkflowCallback>,
        command: &WorkflowCommandRecord,
    ) -> Result<(), String> {
        let next_json = serde_json::to_string(next)
            .map_err(|error| format!("encode workflow action: {error}"))?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        if let Some(expected) = expected {
            if expected.namespace != next.namespace
                || expected.binding_id != next.binding_id
                || expected.owner != next.owner
            {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
            let current = tx
                .query_row(
                    "SELECT record_json FROM sekai_workflow_action_bindings
                     WHERE namespace = ?1 AND binding_id = ?2",
                    params![expected.namespace, expected.binding_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let current: WorkflowActionBinding =
                serde_json::from_str(&current.ok_or(WORKFLOW_UNAVAILABLE)?)
                    .map_err(|error| format!("decode workflow action: {error}"))?;
            if current != *expected {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
            let changed = tx
                .execute(
                    "UPDATE sekai_workflow_action_bindings
                     SET record_json = ?1
                     WHERE namespace = ?2 AND binding_id = ?3 AND owner = ?4",
                    params![next_json, next.namespace, next.binding_id, next.owner],
                )
                .map_err(|error| error.to_string())?;
            if changed == 0 {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
        } else {
            let changed = tx
                .execute(
                    "INSERT INTO sekai_workflow_action_bindings
                        (namespace, binding_id, owner, record_json)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(namespace, binding_id) DO NOTHING",
                    params![next.namespace, next.binding_id, next.owner, next_json],
                )
                .map_err(constraint_unavailable)?;
            if changed == 0 {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
        }
        if let Some(callback) = callback {
            if callback.namespace != next.namespace || callback.binding_id != next.binding_id {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
            let callback_json = serde_json::to_string(callback)
                .map_err(|error| format!("encode workflow callback: {error}"))?;
            let changed = tx
                .execute(
                    "INSERT INTO sekai_workflow_action_callbacks
                        (namespace, binding_id, cursor_value, record_json)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(namespace, binding_id, cursor_value) DO NOTHING",
                    params![
                        callback.namespace,
                        callback.binding_id,
                        callback.cursor as i64,
                        callback_json
                    ],
                )
                .map_err(constraint_unavailable)?;
            if changed == 0 {
                let existing = tx
                    .query_row(
                        "SELECT record_json FROM sekai_workflow_action_callbacks
                         WHERE namespace = ?1 AND binding_id = ?2 AND cursor_value = ?3",
                        params![
                            callback.namespace,
                            callback.binding_id,
                            callback.cursor as i64
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(|error| error.to_string())?;
                let existing: WorkflowCallback = serde_json::from_str(&existing)
                    .map_err(|error| format!("decode workflow callback: {error}"))?;
                if existing != *callback {
                    return Err(WORKFLOW_UNAVAILABLE.into());
                }
            }
        }
        if command.namespace != next.namespace
            || command.binding_id != next.binding_id
            || command.result != *next
        {
            return Err(WORKFLOW_UNAVAILABLE.into());
        }
        let command_json = serde_json::to_string(command)
            .map_err(|error| format!("encode workflow command: {error}"))?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_workflow_action_commands
                    (namespace, binding_id, command, expected_cursor, record_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(namespace, binding_id, command, expected_cursor) DO NOTHING",
                params![
                    command.namespace,
                    command.binding_id,
                    command.command,
                    command.expected_cursor as i64,
                    command_json
                ],
            )
            .map_err(constraint_unavailable)?;
        if changed == 0 {
            return Err(WORKFLOW_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn constraint_unavailable(error: rusqlite::Error) -> String {
    let text = error.to_string();
    if text.to_ascii_lowercase().contains("unique") {
        WORKFLOW_UNAVAILABLE.into()
    } else {
        text
    }
}
