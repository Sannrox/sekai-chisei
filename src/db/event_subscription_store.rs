//! SQLite persistence for event subscriptions (#691).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::event_stream::{EventStreamBinding, EventStreamCheckpoint};
use crate::sekai::event_subscription::{
    CURSOR_CONFLICT, EventSubscription, STATUS_REVOKED, SUBSCRIBE_UNAVAILABLE,
};

impl SekaiDb {
    pub fn put_event_subscription(&self, subscription: &EventSubscription) -> Result<(), String> {
        let json = serde_json::to_string(subscription)
            .map_err(|error| format!("encode event subscription: {error}"))?;
        let changed = self
            .conn()
            .execute(
                "INSERT INTO sekai_event_subscriptions
                    (namespace, subscription_id, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(namespace, subscription_id) DO UPDATE SET
                    owner = excluded.owner,
                    record_json = excluded.record_json
                 WHERE sekai_event_subscriptions.owner = excluded.owner
                   AND ifnull(json_extract(sekai_event_subscriptions.record_json, '$.status'), '')
                        = 'active'",
                params![
                    subscription.namespace,
                    subscription.subscription_id,
                    subscription.owner,
                    json
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
        Ok(())
    }

    pub fn get_event_subscription(
        &self,
        namespace: &str,
        subscription_id: &str,
    ) -> Result<Option<EventSubscription>, String> {
        load_subscription(&self.conn(), namespace, subscription_id)
    }

    pub fn revoke_event_subscription(
        &self,
        namespace: &str,
        subscription_id: &str,
        owner: &str,
    ) -> Result<EventSubscription, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let mut current =
            load_subscription(&tx, namespace, subscription_id)?.ok_or(SUBSCRIBE_UNAVAILABLE)?;
        if current.owner != owner {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
        if current.status != STATUS_REVOKED {
            current.status = STATUS_REVOKED.into();
            let json = serde_json::to_string(&current)
                .map_err(|error| format!("encode event subscription: {error}"))?;
            tx.execute(
                "UPDATE sekai_event_subscriptions
                 SET record_json = ?1
                 WHERE namespace = ?2 AND subscription_id = ?3 AND owner = ?4",
                params![json, namespace, subscription_id, owner],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(current)
    }

    pub fn advance_event_subscription_cursor(
        &self,
        next: &EventSubscription,
        expected: &EventSubscription,
    ) -> Result<(), String> {
        let json = serde_json::to_string(next)
            .map_err(|error| format!("encode event subscription: {error}"))?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let binding = load_stream_binding(&tx, &next.stream_id)?;
        if binding.is_none_or(|stream| stream.definition_digest != next.definition_digest) {
            return Err(CURSOR_CONFLICT.into());
        }
        let checkpoint = load_stream_checkpoint(&tx, &next.stream_id)?;
        if checkpoint.is_none_or(|current| {
            current.generation != next.cursor.generation
                || current.feed_epoch != next.cursor.feed_epoch
                || current.committed_offset < next.cursor.committed_offset
        }) {
            return Err(CURSOR_CONFLICT.into());
        }
        let changed = tx
            .execute(
                "UPDATE sekai_event_subscriptions
                 SET record_json = ?1
                 WHERE namespace = ?2
                   AND subscription_id = ?3
                   AND owner = ?4
                   AND ifnull(json_extract(record_json, '$.status'), '') = ?5
                   AND json_extract(record_json, '$.cursor.committed_offset') = ?6
                   AND ifnull(json_extract(record_json, '$.cursor.last_page_digest'), '') = ?7
                   AND json_extract(record_json, '$.cursor.generation') = ?8
                   AND ifnull(json_extract(record_json, '$.cursor.feed_epoch'), '') = ?9",
                params![
                    json,
                    next.namespace,
                    next.subscription_id,
                    next.owner,
                    expected.status,
                    expected.cursor.committed_offset as i64,
                    expected.cursor.last_page_digest,
                    expected.cursor.generation as i64,
                    expected.cursor.feed_epoch,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(CURSOR_CONFLICT.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn load_subscription(
    conn: &rusqlite::Connection,
    namespace: &str,
    subscription_id: &str,
) -> Result<Option<EventSubscription>, String> {
    let json: Option<String> = conn
        .query_row(
            "SELECT record_json FROM sekai_event_subscriptions
             WHERE namespace = ?1 AND subscription_id = ?2",
            params![namespace, subscription_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    json.map(|value| {
        serde_json::from_str(&value).map_err(|error| format!("decode event subscription: {error}"))
    })
    .transpose()
}

fn load_stream_binding(
    conn: &rusqlite::Connection,
    stream_id: &str,
) -> Result<Option<EventStreamBinding>, String> {
    let json: Option<String> = conn
        .query_row(
            "SELECT record_json FROM sekai_event_stream_bindings WHERE stream_id = ?1",
            params![stream_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    json.map(|value| {
        serde_json::from_str(&value)
            .map_err(|error| format!("decode event stream binding: {error}"))
    })
    .transpose()
}

fn load_stream_checkpoint(
    conn: &rusqlite::Connection,
    stream_id: &str,
) -> Result<Option<EventStreamCheckpoint>, String> {
    let json: Option<String> = conn
        .query_row(
            "SELECT record_json FROM sekai_event_stream_checkpoints WHERE stream_id = ?1",
            params![stream_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    json.map(|value| {
        serde_json::from_str(&value)
            .map_err(|error| format!("decode event stream checkpoint: {error}"))
    })
    .transpose()
}
