//! PostgreSQL storage for object-change Action bindings (ADR 0090). Same
//! table and semantics as SQLite (`crates/sekai-core/src/sekai/action_binding.rs`). Installs
//! serialize on a per-binding advisory lock so concurrent reinstalls each get
//! their own revision; the cursor write is conditional on the revision, so it
//! needs none.

use std::collections::HashMap;

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::sekai::action_binding::{
    ActionBinding, ActionBindingCursor, decode_binding_body, decode_stored, encode_binding_body,
    encode_cursor, scheduled_bindings,
};

impl PostgresDb {
    /// Installs or replaces a binding. A new revision restarts delivery from
    /// a fresh snapshot, so events are never admitted under a stale mapping.
    pub fn put_action_binding(
        &self,
        binding: &ActionBinding,
        actor: &str,
        now_ms: i64,
    ) -> Result<ActionBinding, String> {
        binding.validate()?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key =
            advisory_lock_key(&["action_binding", &binding.namespace, &binding.binding_id]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let previous: Option<i64> = tx
            .query_opt(
                "SELECT revision FROM sekai_action_bindings WHERE namespace = $1 AND binding_id = $2",
                &[&binding.namespace, &binding.binding_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0));
        let mut stored = binding.clone();
        stored.revision = previous.map_or(1, |revision| revision as u64 + 1);
        stored.created_by = actor.to_string();
        stored.updated_at_ms = now_ms;
        let body = encode_binding_body(&stored)?;
        tx.execute(
            "INSERT INTO sekai_action_bindings
                (namespace, binding_id, revision, body_json, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (namespace, binding_id) DO UPDATE SET
                revision = EXCLUDED.revision,
                body_json = EXCLUDED.body_json,
                snapshot_revision = '',
                last_page_digest = '',
                pending_events_json = '[]',
                read_marker_json = '',
                updated_at_ms = EXCLUDED.updated_at_ms",
            &[
                &stored.namespace,
                &stored.binding_id,
                &(stored.revision as i64),
                &body,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    pub fn get_action_binding(
        &self,
        namespace: &str,
        binding_id: &str,
    ) -> Result<Option<(ActionBinding, ActionBindingCursor)>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT body_json, snapshot_revision, last_page_digest, pending_events_json,
                        read_marker_json
                 FROM sekai_action_bindings WHERE namespace = $1 AND binding_id = $2",
                &[&namespace, &binding_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                let pending: String = row.get(3);
                let marker: String = row.get(4);
                decode_stored(&body, row.get(1), row.get(2), &pending, &marker)
            })
            .transpose()
    }

    /// Advances delivery state only for the revision that read the page, so
    /// a reinstall during a run cannot inherit the old cursor.
    pub fn advance_action_binding_cursor(
        &self,
        binding: &ActionBinding,
        cursor: &ActionBindingCursor,
        now_ms: i64,
    ) -> Result<(), String> {
        let (pending, marker) = encode_cursor(cursor)?;
        let mut connection = self.connection()?;
        connection
            .execute(
                "UPDATE sekai_action_bindings
                 SET snapshot_revision = $4, last_page_digest = $5, pending_events_json = $6,
                     read_marker_json = $8, updated_at_ms = $7
                 WHERE namespace = $1 AND binding_id = $2 AND revision = $3",
                &[
                    &binding.namespace,
                    &binding.binding_id,
                    &(binding.revision as i64),
                    &cursor.snapshot_revision,
                    &cursor.last_page_digest,
                    &pending,
                    &now_ms,
                    &marker,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Enabled scheduled bindings in every namespace, for the schedule tick.
    pub fn list_scheduled_action_bindings(&self) -> Result<Vec<ActionBinding>, String> {
        let mut connection = self.connection()?;
        let rows = connection
            .query(
                "SELECT body_json FROM sekai_action_bindings ORDER BY namespace, binding_id",
                &[],
            )
            .map_err(|error| error.to_string())?;
        scheduled_bindings(rows.into_iter().map(|row| row.get::<_, String>(0)))
    }

    /// The last delivered dataset version `seq` per dataset for this binding
    /// revision. Rows of an older revision are not returned.
    pub fn action_binding_dataset_cursors(
        &self,
        binding: &ActionBinding,
    ) -> Result<HashMap<String, i64>, String> {
        let mut connection = self.connection()?;
        let rows = connection
            .query(
                "SELECT dataset_id, seq FROM sekai_action_binding_dataset_cursors
                 WHERE namespace = $1 AND binding_id = $2 AND revision = $3",
                &[
                    &binding.namespace,
                    &binding.binding_id,
                    &(binding.revision as i64),
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }

    /// Moves one dataset's cursor forward, only while `binding.revision` is
    /// still installed. A row of an older revision is replaced.
    pub fn advance_action_binding_dataset_cursor(
        &self,
        binding: &ActionBinding,
        dataset_id: &str,
        seq: i64,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "INSERT INTO sekai_action_binding_dataset_cursors AS cursor
                    (namespace, binding_id, dataset_id, revision, seq)
                 SELECT $1, $2, $3, $4, $5
                 WHERE EXISTS (SELECT 1 FROM sekai_action_bindings
                               WHERE namespace = $1 AND binding_id = $2 AND revision = $4)
                 ON CONFLICT (namespace, binding_id, dataset_id) DO UPDATE SET
                    seq = CASE WHEN cursor.revision = EXCLUDED.revision
                               THEN GREATEST(cursor.seq, EXCLUDED.seq) ELSE EXCLUDED.seq END,
                    revision = EXCLUDED.revision",
                &[
                    &binding.namespace,
                    &binding.binding_id,
                    &dataset_id,
                    &(binding.revision as i64),
                    &seq,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn list_action_bindings(&self, namespace: &str) -> Result<Vec<ActionBinding>, String> {
        let mut connection = self.connection()?;
        let rows = connection
            .query(
                "SELECT body_json FROM sekai_action_bindings
                 WHERE namespace = $1
                 ORDER BY binding_id",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?;
        let mut bindings = Vec::new();
        for row in rows {
            let body: String = row.get(0);
            let binding = decode_binding_body(&body)?;
            bindings.push(binding);
        }
        Ok(bindings)
    }
}
