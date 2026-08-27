//! SQLite persistence for event-stream projections (#684).

use rusqlite::{OptionalExtension, params};

use super::sekai::SekaiDb;
use crate::sekai::event_stream::{
    BATCH_GAP, BATCH_MALFORMED, CHECKPOINT_CONFLICT, EventStreamBinding, EventStreamCheckpoint,
    PROJECT_UNAVAILABLE, StreamEvent, admitted_event_digest,
};

impl SekaiDb {
    pub fn put_event_stream_binding(&self, binding: &EventStreamBinding) -> Result<(), String> {
        let json = serde_json::to_string(binding)
            .map_err(|error| format!("encode event stream binding: {error}"))?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let previous = load_binding(&tx, &binding.stream_id)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_event_stream_bindings
                    (stream_id, namespace, owner, record_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(stream_id) DO UPDATE SET
                    namespace = excluded.namespace,
                    record_json = excluded.record_json
                 WHERE sekai_event_stream_bindings.owner = excluded.owner",
                params![binding.stream_id, binding.namespace, binding.owner, json],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(PROJECT_UNAVAILABLE.into());
        }
        if previous.is_some_and(|existing| definition_changed(&existing, binding)) {
            tx.execute(
                "DELETE FROM sekai_event_stream_checkpoints WHERE stream_id = ?1",
                params![binding.stream_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "DELETE FROM sekai_event_stream_admitted_events WHERE stream_id = ?1",
                params![binding.stream_id],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_event_stream_binding(
        &self,
        stream_id: &str,
    ) -> Result<Option<EventStreamBinding>, String> {
        load_binding(&self.conn(), stream_id)
    }

    pub fn advance_event_stream_checkpoint(
        &self,
        next: &EventStreamCheckpoint,
        expected: &EventStreamCheckpoint,
        definition_digest: &str,
        admitted: Option<&[StreamEvent]>,
    ) -> Result<(), String> {
        let json = serde_json::to_string(next)
            .map_err(|error| format!("encode event stream checkpoint: {error}"))?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let current = load_binding(&tx, &next.stream_id)?;
        if current.is_none_or(|binding| binding.definition_digest != definition_digest) {
            return Err(CHECKPOINT_CONFLICT.into());
        }
        let changed = tx
            .execute(
                "INSERT INTO sekai_event_stream_checkpoints
                    (stream_id, committed_offset, record_json)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(stream_id) DO UPDATE SET
                    committed_offset = excluded.committed_offset,
                    record_json = excluded.record_json
                 WHERE json_extract(sekai_event_stream_checkpoints.record_json, '$.committed_offset')
                        = ?4
                   AND ifnull(json_extract(sekai_event_stream_checkpoints.record_json, '$.last_batch_digest'), '')
                        = ?5
                   AND json_extract(sekai_event_stream_checkpoints.record_json, '$.generation')
                        = ?6
                   AND ifnull(json_extract(sekai_event_stream_checkpoints.record_json, '$.feed_epoch'), '')
                        = ?7",
                params![
                    next.stream_id,
                    next.committed_offset as i64,
                    json,
                    expected.committed_offset as i64,
                    expected.last_batch_digest,
                    expected.generation as i64,
                    expected.feed_epoch,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(CHECKPOINT_CONFLICT.into());
        }
        if let Some(events) = admitted {
            persist_admitted_events(&tx, next, events)?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn ensure_event_stream_admitted_events(
        &self,
        batch: &crate::sekai::event_stream::EventStreamBatch,
    ) -> Result<(), String> {
        persist_admitted_events_ignore(
            &self.conn(),
            &batch.stream_id,
            batch.generation,
            &batch.feed_epoch,
            &batch.events,
        )
    }

    pub fn verify_event_stream_admitted_events(
        &self,
        stream_id: &str,
        generation: u64,
        feed_epoch: &str,
        events: &[StreamEvent],
    ) -> Result<(), String> {
        verify_admitted_events(&self.conn(), stream_id, generation, feed_epoch, events)
    }

    pub fn get_event_stream_checkpoint(
        &self,
        stream_id: &str,
    ) -> Result<Option<EventStreamCheckpoint>, String> {
        let json: Option<String> = self
            .conn()
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
}

fn load_binding(
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

fn persist_admitted_events(
    tx: &rusqlite::Transaction<'_>,
    checkpoint: &EventStreamCheckpoint,
    events: &[StreamEvent],
) -> Result<(), String> {
    persist_admitted_events_ignore(
        tx,
        &checkpoint.stream_id,
        checkpoint.generation,
        &checkpoint.feed_epoch,
        events,
    )
}

fn persist_admitted_events_ignore(
    conn: &rusqlite::Connection,
    stream_id: &str,
    generation: u64,
    feed_epoch: &str,
    events: &[StreamEvent],
) -> Result<(), String> {
    let mut insert = conn
        .prepare(
            "INSERT OR IGNORE INTO sekai_event_stream_admitted_events
                (stream_id, event_offset, generation, feed_epoch, event_digest)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .map_err(|error| error.to_string())?;
    for event in events {
        insert
            .execute(params![
                stream_id,
                event.offset as i64,
                generation as i64,
                feed_epoch,
                admitted_event_digest(event)?,
            ])
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn verify_admitted_events(
    conn: &rusqlite::Connection,
    stream_id: &str,
    generation: u64,
    feed_epoch: &str,
    events: &[StreamEvent],
) -> Result<(), String> {
    for event in events {
        let stored: Option<(i64, String, String)> = conn
            .query_row(
                "SELECT generation, feed_epoch, event_digest
                 FROM sekai_event_stream_admitted_events
                 WHERE stream_id = ?1 AND event_offset = ?2",
                params![stream_id, event.offset as i64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((stored_generation, stored_epoch, stored_digest)) = stored else {
            return Err(BATCH_GAP.into());
        };
        if stored_generation as u64 != generation
            || stored_epoch != feed_epoch
            || stored_digest != admitted_event_digest(event)?
        {
            return Err(BATCH_MALFORMED.into());
        }
    }
    Ok(())
}

fn definition_changed(existing: &EventStreamBinding, next: &EventStreamBinding) -> bool {
    existing.namespace != next.namespace
        || existing.source != next.source
        || existing.source_instance != next.source_instance
        || existing.schema_revision != next.schema_revision
        || existing.type_digest != next.type_digest
        || existing.columns != next.columns
}
