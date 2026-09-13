//! PostgreSQL persistence for workflow-action bindings (#823).

use postgres::{GenericClient, Transaction};

use crate::db::postgres::PostgresDb;
use crate::sekai::workflow_action::{
    WORKFLOW_UNAVAILABLE, WorkflowActionBinding, WorkflowCallback, WorkflowCommandRecord,
};

const BINDING_LOCK_SEED: i64 = 8_231;

impl PostgresDb {
    pub fn get_workflow_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<WorkflowActionBinding>, String> {
        load_binding(&mut *self.connection()?, namespace, binding_id)
    }

    pub fn get_workflow_callback(
        &self,
        namespace: &str,
        binding_id: &str,
        cursor: u64,
    ) -> Result<Option<WorkflowCallback>, String> {
        let cursor = i64::try_from(cursor).map_err(|error| error.to_string())?;
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_workflow_action_callbacks
                 WHERE namespace = $1 AND binding_id = $2 AND cursor_value = $3",
                &[&namespace, &binding_id, &cursor],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                serde_json::from_str(&row.get::<_, String>(0))
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
        let expected_cursor = i64::try_from(expected_cursor).map_err(|error| error.to_string())?;
        self.connection()?
            .query_opt(
                "SELECT record_json FROM sekai_workflow_action_commands
                 WHERE namespace = $1 AND binding_id = $2 AND command = $3 AND expected_cursor = $4",
                &[&namespace, &binding_id, &command, &expected_cursor],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                serde_json::from_str(&row.get::<_, String>(0))
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_binding(&mut tx, &next.namespace, &next.binding_id)?;
        if let Some(expected) = expected {
            if expected.namespace != next.namespace
                || expected.binding_id != next.binding_id
                || expected.owner != next.owner
            {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
            let current = load_binding(&mut tx, &expected.namespace, &expected.binding_id)?
                .ok_or(WORKFLOW_UNAVAILABLE)?;
            if current != *expected {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
            let changed = tx
                .execute(
                    "UPDATE sekai_workflow_action_bindings
                     SET record_json = $1
                     WHERE namespace = $2 AND binding_id = $3 AND owner = $4",
                    &[&next_json, &next.namespace, &next.binding_id, &next.owner],
                )
                .map_err(constraint_unavailable)?;
            if changed == 0 {
                return Err(WORKFLOW_UNAVAILABLE.into());
            }
        } else {
            let changed = tx
                .execute(
                    "INSERT INTO sekai_workflow_action_bindings
                        (namespace, binding_id, owner, record_json)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (namespace, binding_id) DO NOTHING",
                    &[&next.namespace, &next.binding_id, &next.owner, &next_json],
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
            let cursor = i64::try_from(callback.cursor).map_err(|error| error.to_string())?;
            let changed = tx
                .execute(
                    "INSERT INTO sekai_workflow_action_callbacks
                        (namespace, binding_id, cursor_value, record_json)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (namespace, binding_id, cursor_value) DO NOTHING",
                    &[
                        &callback.namespace,
                        &callback.binding_id,
                        &cursor,
                        &callback_json,
                    ],
                )
                .map_err(constraint_unavailable)?;
            if changed == 0 {
                let existing = tx
                    .query_one(
                        "SELECT record_json FROM sekai_workflow_action_callbacks
                         WHERE namespace = $1 AND binding_id = $2 AND cursor_value = $3",
                        &[&callback.namespace, &callback.binding_id, &cursor],
                    )
                    .map_err(|error| error.to_string())?;
                let existing: WorkflowCallback =
                    serde_json::from_str(&existing.get::<_, String>(0))
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
        let expected_cursor =
            i64::try_from(command.expected_cursor).map_err(|error| error.to_string())?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_workflow_action_commands
                    (namespace, binding_id, command, expected_cursor, record_json)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (namespace, binding_id, command, expected_cursor) DO NOTHING",
                &[
                    &command.namespace,
                    &command.binding_id,
                    &command.command,
                    &expected_cursor,
                    &command_json,
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

fn lock_binding(tx: &mut Transaction<'_>, namespace: &str, binding_id: &str) -> Result<(), String> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1 || '/' || $2, $3))",
        &[&namespace, &binding_id, &BINDING_LOCK_SEED],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn load_binding(
    conn: &mut impl GenericClient,
    namespace: &str,
    binding_id: &str,
) -> Result<Option<WorkflowActionBinding>, String> {
    conn.query_opt(
        "SELECT record_json FROM sekai_workflow_action_bindings
         WHERE namespace = $1 AND binding_id = $2",
        &[&namespace, &binding_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| {
        serde_json::from_str(&row.get::<_, String>(0))
            .map_err(|error| format!("decode workflow action: {error}"))
    })
    .transpose()
}

fn constraint_unavailable(error: postgres::Error) -> String {
    if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
        WORKFLOW_UNAVAILABLE.into()
    } else {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::db::postgres::PostgresDb;
    use crate::db::runtime_db::RuntimeDb;
    use crate::sekai::workflow_action::{
        BRIDGE_CONTRACT, COMMAND_CALLBACK, COMMAND_CANCEL, COMMAND_PARK, COMMAND_SUBMIT,
        PROFILE_JOB_STEP, PROFILE_VERSION, STATUS_CANCELLED, STATUS_PARKED, STATUS_RESUMED,
        STATUS_SUBMITTED,
    };

    fn binding(scope: &str, cursor: u64, status: &str) -> WorkflowActionBinding {
        WorkflowActionBinding {
            contract_version: BRIDGE_CONTRACT.into(),
            binding_id: format!("sha256:{scope}"),
            namespace: scope.into(),
            owner: "integrator".into(),
            profile_id: PROFILE_JOB_STEP.into(),
            profile_version: PROFILE_VERSION.into(),
            source_instance: format!("runner:{scope}"),
            step_id: format!("job:{scope}"),
            type_id: "workflow.job_step".into(),
            version: "1".into(),
            parameters_digest: "sha256:params".into(),
            cursor,
            callback_id: format!("cb:{scope}"),
            callback_digest: "sha256:cb".into(),
            artifact_digest: String::new(),
            usage_kind: "step".into(),
            usage_units: 1,
            idempotency_key: format!("idemp:{scope}"),
            instance_id: format!("inst:{scope}"),
            operation_id: format!("op:{scope}"),
            instance_status: "admitted".into(),
            status: status.into(),
            last_command: COMMAND_SUBMIT.into(),
            last_command_digest: "sha256:cmd".into(),
            binding_digest: format!("sha256:bind:{scope}:{cursor}"),
            admitted_by: "integrator".into(),
            admitted_at_ms: 1_000,
            updated_at_ms: 1_000 + cursor as i64,
        }
    }

    fn command(
        next: &WorkflowActionBinding,
        name: &str,
        expected_cursor: u64,
    ) -> WorkflowCommandRecord {
        WorkflowCommandRecord {
            namespace: next.namespace.clone(),
            binding_id: next.binding_id.clone(),
            command: name.into(),
            expected_cursor,
            command_digest: format!("sha256:{name}:{expected_cursor}"),
            result: next.clone(),
            admitted_by: "integrator".into(),
            admitted_at_ms: next.updated_at_ms,
        }
    }

    fn callback(next: &WorkflowActionBinding) -> WorkflowCallback {
        WorkflowCallback {
            namespace: next.namespace.clone(),
            binding_id: next.binding_id.clone(),
            callback_id: next.callback_id.clone(),
            cursor: next.cursor,
            payload_digest: "sha256:payload".into(),
            admitted_by: "integrator".into(),
            admitted_at_ms: next.updated_at_ms,
        }
    }

    fn assert_transition_matrix(runtime: &RuntimeDb, scope: &str) {
        let submitted = binding(scope, 0, STATUS_SUBMITTED);
        let submit_cmd = command(&submitted, COMMAND_SUBMIT, 0);
        runtime
            .commit_workflow_transition(None, &submitted, None, &submit_cmd)
            .unwrap();
        assert_eq!(
            runtime
                .get_workflow_binding(&submitted.namespace, &submitted.binding_id)
                .unwrap()
                .unwrap(),
            submitted
        );
        assert_eq!(
            runtime
                .get_workflow_command(
                    &submitted.namespace,
                    &submitted.binding_id,
                    COMMAND_SUBMIT,
                    0
                )
                .unwrap()
                .unwrap(),
            submit_cmd
        );
        assert_eq!(
            runtime
                .commit_workflow_transition(None, &submitted, None, &submit_cmd)
                .unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );

        let mut colliding = submitted.clone();
        colliding.binding_id = format!("sha256:{scope}-other");
        colliding.instance_id = format!("inst:{scope}-other");
        colliding.operation_id = format!("op:{scope}-other");
        colliding.idempotency_key = format!("idemp:{scope}-other");
        colliding.binding_digest = format!("sha256:bind:{scope}-other:0");
        assert_eq!(
            runtime
                .commit_workflow_transition(
                    None,
                    &colliding,
                    None,
                    &command(&colliding, COMMAND_SUBMIT, 0),
                )
                .unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        assert_eq!(
            runtime
                .get_workflow_binding(&colliding.namespace, &colliding.binding_id)
                .unwrap(),
            None
        );

        let mut parked = submitted.clone();
        parked.cursor = 1;
        parked.status = STATUS_PARKED.into();
        parked.last_command = COMMAND_PARK.into();
        runtime
            .commit_workflow_transition(
                Some(&submitted),
                &parked,
                None,
                &command(&parked, COMMAND_PARK, 0),
            )
            .unwrap();

        let mut foreign = parked.clone();
        foreign.owner = "intruder".into();
        foreign.cursor = 2;
        foreign.status = STATUS_CANCELLED.into();
        foreign.last_command = COMMAND_CANCEL.into();
        assert_eq!(
            runtime
                .commit_workflow_transition(
                    Some(&parked),
                    &foreign,
                    None,
                    &command(&foreign, COMMAND_CANCEL, 1),
                )
                .unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );

        let mut cancelled = parked.clone();
        cancelled.cursor = 2;
        cancelled.status = STATUS_CANCELLED.into();
        cancelled.last_command = COMMAND_CANCEL.into();
        runtime
            .commit_workflow_transition(
                Some(&parked),
                &cancelled,
                None,
                &command(&cancelled, COMMAND_CANCEL, 1),
            )
            .unwrap();
        assert_eq!(
            runtime
                .get_workflow_binding(&submitted.namespace, &submitted.binding_id)
                .unwrap()
                .unwrap(),
            cancelled
        );

        let mut stale = submitted.clone();
        stale.cursor = 3;
        stale.status = STATUS_RESUMED.into();
        stale.last_command = COMMAND_CALLBACK.into();
        assert_eq!(
            runtime
                .commit_workflow_transition(
                    Some(&submitted),
                    &stale,
                    Some(&callback(&stale)),
                    &command(&stale, COMMAND_CALLBACK, 0),
                )
                .unwrap_err(),
            WORKFLOW_UNAVAILABLE
        );
        assert_eq!(
            runtime
                .get_workflow_binding(&submitted.namespace, &submitted.binding_id)
                .unwrap()
                .unwrap()
                .cursor,
            2
        );
        assert!(
            runtime
                .get_workflow_callback(&submitted.namespace, &submitted.binding_id, 3)
                .unwrap()
                .is_none()
        );
    }

    fn postgres_runtime() -> RuntimeDb {
        let database_url = std::env::var("SEKAI_TEST_POSTGRES_URL").unwrap_or_else(|_| {
            panic!("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database")
        });
        let db = if let Ok(ca_certificate_path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            let ca_certificate = std::fs::read(&ca_certificate_path).unwrap_or_else(|error| {
                panic!("read PostgreSQL test CA certificate {ca_certificate_path}: {error}")
            });
            PostgresDb::connect_with_ca_certificate(&database_url, 4, &ca_certificate).unwrap()
        } else {
            PostgresDb::connect(&database_url, 4).unwrap()
        };
        RuntimeDb::Postgres(Arc::new(db))
    }

    #[test]
    fn sqlite_workflow_transition_matrix() {
        assert_transition_matrix(&RuntimeDb::memory(), "sqlite-wf");
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_workflow_transition_matrix() {
        assert_transition_matrix(
            &postgres_runtime(),
            &format!("pg-wf-{}", uuid::Uuid::new_v4()),
        );
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
    fn postgres_concurrent_callback_and_cancel_race() {
        let runtime = Arc::new(postgres_runtime());
        let submitted = binding(
            &format!("pg-race-{}", uuid::Uuid::new_v4()),
            0,
            STATUS_SUBMITTED,
        );
        runtime
            .commit_workflow_transition(
                None,
                &submitted,
                None,
                &command(&submitted, COMMAND_SUBMIT, 0),
            )
            .unwrap();
        let mut callback_next = submitted.clone();
        callback_next.cursor = 1;
        callback_next.status = STATUS_RESUMED.into();
        callback_next.last_command = COMMAND_CALLBACK.into();
        let mut cancel_next = submitted.clone();
        cancel_next.cursor = 1;
        cancel_next.status = STATUS_CANCELLED.into();
        cancel_next.last_command = COMMAND_CANCEL.into();
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = [
            (
                callback_next.clone(),
                Some(callback(&callback_next)),
                command(&callback_next, COMMAND_CALLBACK, 0),
            ),
            (
                cancel_next.clone(),
                None,
                command(&cancel_next, COMMAND_CANCEL, 0),
            ),
        ]
        .into_iter()
        .map(|(next, cb, cmd)| {
            let runtime = Arc::clone(&runtime);
            let expected = submitted.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                runtime.commit_workflow_transition(Some(&expected), &next, cb.as_ref(), &cmd)
            })
        })
        .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        let ok = results.iter().filter(|result| result.is_ok()).count();
        let denied = results
            .iter()
            .filter(|result| result.as_ref().err() == Some(&WORKFLOW_UNAVAILABLE.to_string()))
            .count();
        assert_eq!(ok, 1);
        assert_eq!(denied, 1);
    }
}
