//! PostgreSQL persistence for event-stream projections and subscriptions (#822).

use postgres::{GenericClient, Transaction};

use crate::db::postgres::PostgresDb;
use crate::sekai::event_stream::{
    BATCH_GAP, BATCH_MALFORMED, CHECKPOINT_CONFLICT, EventStreamBinding, EventStreamCheckpoint,
    PROJECT_UNAVAILABLE, StreamEvent, admitted_event_digest, replay_checkpoint_matches_batch,
};
use crate::sekai::event_subscription::{
    CURSOR_CONFLICT, EventSubscription, STATUS_REVOKED, SUBSCRIBE_UNAVAILABLE,
};
use crate::sekai::object_set_membership::ObjectSetMembership;

const STREAM_LOCK_SEED: i64 = 8_221;
const SUBSCRIPTION_LOCK_SEED: i64 = 8_222;

impl PostgresDb {
    pub fn put_event_stream_binding(&self, binding: &EventStreamBinding) -> Result<(), String> {
        let json = serde_json::to_string(binding)
            .map_err(|error| format!("encode event stream binding: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_stream(&mut tx, &binding.stream_id)?;
        let previous = load_binding(&mut tx, &binding.stream_id)?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_event_stream_bindings
                    (stream_id, namespace, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (stream_id) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    record_json = EXCLUDED.record_json
                 WHERE sekai_event_stream_bindings.owner = EXCLUDED.owner",
                &[
                    &binding.stream_id,
                    &binding.namespace,
                    &binding.owner,
                    &json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(PROJECT_UNAVAILABLE.into());
        }
        if previous.is_some_and(|existing| definition_changed(&existing, binding)) {
            tx.execute(
                "DELETE FROM sekai_event_stream_checkpoints WHERE stream_id = $1",
                &[&binding.stream_id],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "DELETE FROM sekai_event_stream_admitted_events WHERE stream_id = $1",
                &[&binding.stream_id],
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
        load_binding(&mut *self.connection()?, stream_id)
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_stream(&mut tx, &next.stream_id)?;
        let current = load_binding(&mut tx, &next.stream_id)?;
        if current.is_none_or(|binding| binding.definition_digest != definition_digest) {
            return Err(CHECKPOINT_CONFLICT.into());
        }
        let expected_offset =
            i64::try_from(expected.committed_offset).map_err(|error| error.to_string())?;
        let expected_generation =
            i64::try_from(expected.generation).map_err(|error| error.to_string())?;
        let next_offset =
            i64::try_from(next.committed_offset).map_err(|error| error.to_string())?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_event_stream_checkpoints
                    (stream_id, committed_offset, record_json)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (stream_id) DO UPDATE SET
                    committed_offset = EXCLUDED.committed_offset,
                    record_json = EXCLUDED.record_json
                 WHERE (sekai_event_stream_checkpoints.record_json::jsonb->>'committed_offset')::bigint
                        = $4
                   AND COALESCE(sekai_event_stream_checkpoints.record_json::jsonb->>'last_batch_digest', '')
                        = $5
                   AND (sekai_event_stream_checkpoints.record_json::jsonb->>'generation')::bigint
                        = $6
                   AND COALESCE(sekai_event_stream_checkpoints.record_json::jsonb->>'feed_epoch', '')
                        = $7",
                &[
                    &next.stream_id,
                    &next_offset,
                    &json,
                    &expected_offset,
                    &expected.last_batch_digest,
                    &expected_generation,
                    &expected.feed_epoch,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(CHECKPOINT_CONFLICT.into());
        }
        if let Some(events) = admitted {
            persist_admitted_events(&mut tx, next, events)?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn ensure_event_stream_admitted_events(
        &self,
        batch: &crate::sekai::event_stream::EventStreamBatch,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_stream(&mut tx, &batch.stream_id)?;
        let checkpoint = load_checkpoint(&mut tx, &batch.stream_id)?.ok_or(CHECKPOINT_CONFLICT)?;
        if !replay_checkpoint_matches_batch(&checkpoint, batch) {
            return Err(CHECKPOINT_CONFLICT.into());
        }
        persist_admitted_events_ignore(
            &mut tx,
            &batch.stream_id,
            batch.generation,
            &batch.feed_epoch,
            &batch.events,
        )?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn verify_event_stream_admitted_events(
        &self,
        stream_id: &str,
        generation: u64,
        feed_epoch: &str,
        events: &[StreamEvent],
    ) -> Result<(), String> {
        verify_admitted_events(
            &mut *self.connection()?,
            stream_id,
            generation,
            feed_epoch,
            events,
        )
    }

    pub fn get_event_stream_checkpoint(
        &self,
        stream_id: &str,
    ) -> Result<Option<EventStreamCheckpoint>, String> {
        load_checkpoint(&mut *self.connection()?, stream_id)
    }

    pub fn put_event_subscription(&self, subscription: &EventSubscription) -> Result<(), String> {
        let json = serde_json::to_string(subscription)
            .map_err(|error| format!("encode event subscription: {error}"))?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_subscription(
            &mut tx,
            &subscription.namespace,
            &subscription.subscription_id,
        )?;
        let changed = tx
            .execute(
                "INSERT INTO sekai_event_subscriptions
                    (namespace, subscription_id, owner, record_json)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (namespace, subscription_id) DO UPDATE SET
                    owner = EXCLUDED.owner,
                    record_json = EXCLUDED.record_json
                 WHERE sekai_event_subscriptions.owner = EXCLUDED.owner
                   AND COALESCE(sekai_event_subscriptions.record_json::jsonb->>'status', '')
                        = 'active'",
                &[
                    &subscription.namespace,
                    &subscription.subscription_id,
                    &subscription.owner,
                    &json,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn get_event_subscription(
        &self,
        namespace: &str,
        subscription_id: &str,
    ) -> Result<Option<EventSubscription>, String> {
        load_subscription(&mut *self.connection()?, namespace, subscription_id)
    }

    pub fn revoke_event_subscription(
        &self,
        namespace: &str,
        subscription_id: &str,
        owner: &str,
    ) -> Result<EventSubscription, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        lock_subscription(&mut tx, namespace, subscription_id)?;
        let mut current =
            load_subscription(&mut tx, namespace, subscription_id)?.ok_or(SUBSCRIBE_UNAVAILABLE)?;
        if current.owner != owner {
            return Err(SUBSCRIBE_UNAVAILABLE.into());
        }
        if current.status != STATUS_REVOKED {
            current.status = STATUS_REVOKED.into();
            let json = serde_json::to_string(&current)
                .map_err(|error| format!("encode event subscription: {error}"))?;
            tx.execute(
                "UPDATE sekai_event_subscriptions
                 SET record_json = $1
                 WHERE namespace = $2 AND subscription_id = $3 AND owner = $4",
                &[&json, &namespace, &subscription_id, &owner],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute(
            "DELETE FROM sekai_object_set_memberships
             WHERE namespace = $1 AND subscription_id = $2",
            &[&namespace, &subscription_id],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(current)
    }

    pub fn advance_event_subscription_cursor(
        &self,
        next: &EventSubscription,
        expected: &EventSubscription,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        advance_cursor(&mut tx, next, expected)?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// The cursor advance plus the subscription's ObjectSet membership
    /// (#3038), in one transaction: a crash keeps both or neither.
    pub fn advance_event_subscription_cursor_with_membership(
        &self,
        next: &EventSubscription,
        expected: &EventSubscription,
        membership: &ObjectSetMembership,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        advance_cursor(&mut tx, next, expected)?;
        upsert_membership(&mut tx, &next.namespace, &next.subscription_id, membership)?;
        tx.commit().map_err(|error| error.to_string())
    }

    /// Replaces the subscription's ObjectSet membership outside a cursor
    /// advance: the baseline a resnapshot pairs with (#3038).
    pub fn put_object_set_membership(
        &self,
        namespace: &str,
        subscription_id: &str,
        membership: &ObjectSetMembership,
    ) -> Result<(), String> {
        let mut connection = self.connection()?;
        upsert_membership(&mut *connection, namespace, subscription_id, membership)
    }

    /// The ObjectSet membership last committed with the subscription's
    /// cursor, if any.
    pub fn get_object_set_membership(
        &self,
        namespace: &str,
        subscription_id: &str,
    ) -> Result<Option<ObjectSetMembership>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT epoch, member_ids_json, pending_ids_json
                 FROM sekai_object_set_memberships
                 WHERE namespace = $1 AND subscription_id = $2",
                &[&namespace, &subscription_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let decode = |index: usize| {
                    serde_json::from_str(&row.get::<_, String>(index))
                        .map_err(|error| format!("decode object-set membership: {error}"))
                };
                Ok(ObjectSetMembership {
                    epoch: row.get(0),
                    member_ids: decode(1)?,
                    pending_ids: decode(2)?,
                })
            })
            .transpose()
    }
}

fn upsert_membership(
    client: &mut impl postgres::GenericClient,
    namespace: &str,
    subscription_id: &str,
    membership: &ObjectSetMembership,
) -> Result<(), String> {
    let members = serde_json::to_string(&membership.member_ids)
        .map_err(|error| format!("encode object-set membership: {error}"))?;
    let pending = serde_json::to_string(&membership.pending_ids)
        .map_err(|error| format!("encode object-set membership: {error}"))?;
    client
        .execute(
            "INSERT INTO sekai_object_set_memberships
                (namespace, subscription_id, epoch, member_ids_json, pending_ids_json)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (namespace, subscription_id) DO UPDATE SET
                epoch = EXCLUDED.epoch,
                member_ids_json = EXCLUDED.member_ids_json,
                pending_ids_json = EXCLUDED.pending_ids_json",
            &[
                &namespace,
                &subscription_id,
                &membership.epoch,
                &members,
                &pending,
            ],
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn advance_cursor(
    tx: &mut Transaction<'_>,
    next: &EventSubscription,
    expected: &EventSubscription,
) -> Result<(), String> {
    let json = serde_json::to_string(next)
        .map_err(|error| format!("encode event subscription: {error}"))?;
    lock_stream(tx, &next.stream_id)?;
    lock_subscription(tx, &next.namespace, &next.subscription_id)?;
    let current =
        load_subscription(tx, &next.namespace, &next.subscription_id)?.ok_or(CURSOR_CONFLICT)?;
    if current != *expected {
        return Err(CURSOR_CONFLICT.into());
    }
    let binding = load_binding(tx, &next.stream_id)?;
    if binding.is_none_or(|stream| stream.definition_digest != next.definition_digest) {
        return Err(CURSOR_CONFLICT.into());
    }
    let checkpoint = load_checkpoint(tx, &next.stream_id)?;
    if checkpoint.is_none_or(|current| {
        current.generation != next.cursor.generation
            || current.feed_epoch != next.cursor.feed_epoch
            || current.committed_offset < next.cursor.committed_offset
    }) {
        return Err(CURSOR_CONFLICT.into());
    }
    let expected_offset =
        i64::try_from(expected.cursor.committed_offset).map_err(|error| error.to_string())?;
    let expected_generation =
        i64::try_from(expected.cursor.generation).map_err(|error| error.to_string())?;
    let changed = tx
        .execute(
            "UPDATE sekai_event_subscriptions
             SET record_json = $1
             WHERE namespace = $2
               AND subscription_id = $3
               AND owner = $4
               AND COALESCE(record_json::jsonb->>'status', '') = $5
               AND (record_json::jsonb->'cursor'->>'committed_offset')::bigint = $6
               AND COALESCE(record_json::jsonb->'cursor'->>'last_page_digest', '') = $7
               AND (record_json::jsonb->'cursor'->>'generation')::bigint = $8
               AND COALESCE(record_json::jsonb->'cursor'->>'feed_epoch', '') = $9",
            &[
                &json,
                &next.namespace,
                &next.subscription_id,
                &next.owner,
                &expected.status,
                &expected_offset,
                &expected.cursor.last_page_digest,
                &expected_generation,
                &expected.cursor.feed_epoch,
            ],
        )
        .map_err(|error| error.to_string())?;
    if changed == 0 {
        return Err(CURSOR_CONFLICT.into());
    }
    Ok(())
}

fn lock_stream(tx: &mut Transaction<'_>, stream_id: &str) -> Result<(), String> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
        &[&stream_id, &STREAM_LOCK_SEED],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn lock_subscription(
    tx: &mut Transaction<'_>,
    namespace: &str,
    subscription_id: &str,
) -> Result<(), String> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1 || '/' || $2, $3))",
        &[&namespace, &subscription_id, &SUBSCRIPTION_LOCK_SEED],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn load_binding(
    conn: &mut impl GenericClient,
    stream_id: &str,
) -> Result<Option<EventStreamBinding>, String> {
    conn.query_opt(
        "SELECT record_json FROM sekai_event_stream_bindings WHERE stream_id = $1",
        &[&stream_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| {
        serde_json::from_str(&row.get::<_, String>(0))
            .map_err(|error| format!("decode event stream binding: {error}"))
    })
    .transpose()
}

fn load_checkpoint(
    conn: &mut impl GenericClient,
    stream_id: &str,
) -> Result<Option<EventStreamCheckpoint>, String> {
    conn.query_opt(
        "SELECT record_json FROM sekai_event_stream_checkpoints WHERE stream_id = $1",
        &[&stream_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| {
        serde_json::from_str(&row.get::<_, String>(0))
            .map_err(|error| format!("decode event stream checkpoint: {error}"))
    })
    .transpose()
}

fn load_subscription(
    conn: &mut impl GenericClient,
    namespace: &str,
    subscription_id: &str,
) -> Result<Option<EventSubscription>, String> {
    conn.query_opt(
        "SELECT record_json FROM sekai_event_subscriptions
         WHERE namespace = $1 AND subscription_id = $2",
        &[&namespace, &subscription_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| {
        serde_json::from_str(&row.get::<_, String>(0))
            .map_err(|error| format!("decode event subscription: {error}"))
    })
    .transpose()
}

fn persist_admitted_events(
    tx: &mut Transaction<'_>,
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
    conn: &mut impl GenericClient,
    stream_id: &str,
    generation: u64,
    feed_epoch: &str,
    events: &[StreamEvent],
) -> Result<(), String> {
    let generation = i64::try_from(generation).map_err(|error| error.to_string())?;
    for event in events {
        let offset = i64::try_from(event.offset).map_err(|error| error.to_string())?;
        let digest = admitted_event_digest(event)?;
        conn.execute(
            "INSERT INTO sekai_event_stream_admitted_events
                (stream_id, event_offset, generation, feed_epoch, event_digest)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (stream_id, event_offset) DO NOTHING",
            &[&stream_id, &offset, &generation, &feed_epoch, &digest],
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn verify_admitted_events(
    conn: &mut impl GenericClient,
    stream_id: &str,
    generation: u64,
    feed_epoch: &str,
    events: &[StreamEvent],
) -> Result<(), String> {
    for event in events {
        let offset = i64::try_from(event.offset).map_err(|error| error.to_string())?;
        let stored = conn
            .query_opt(
                "SELECT generation, feed_epoch, event_digest
                 FROM sekai_event_stream_admitted_events
                 WHERE stream_id = $1 AND event_offset = $2",
                &[&stream_id, &offset],
            )
            .map_err(|error| error.to_string())?;
        let Some(row) = stored else {
            return Err(BATCH_GAP.into());
        };
        let stored_generation: i64 = row.get(0);
        let stored_epoch: String = row.get(1);
        let stored_digest: String = row.get(2);
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
