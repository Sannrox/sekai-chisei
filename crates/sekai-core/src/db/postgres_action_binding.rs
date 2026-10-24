//! PostgreSQL storage for object-change Action bindings (ADR 0090). Same
//! table and semantics as SQLite (`src/sekai/action_binding.rs`). Installs
//! serialize on a per-binding advisory lock so concurrent reinstalls each get
//! their own revision; the cursor write is conditional on the revision, so it
//! needs none.

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::sekai::action_binding::{
    ActionBinding, ActionBindingCursor, decode_stored, encode_cursor,
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
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
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
}
