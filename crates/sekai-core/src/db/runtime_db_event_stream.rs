//! Dual-backend community-store dispatch for event stream.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn put_event_stream_binding(
        &self,
        binding: &crate::sekai::event_stream::EventStreamBinding,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_event_stream_binding(binding),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_event_stream_binding(binding))
            }
        }
    }

    pub fn get_event_stream_binding(
        &self,
        stream_id: &str,
    ) -> Result<Option<crate::sekai::event_stream::EventStreamBinding>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_stream_binding(stream_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_event_stream_binding(stream_id))
            }
        }
    }

    pub fn advance_event_stream_checkpoint(
        &self,
        next: &crate::sekai::event_stream::EventStreamCheckpoint,
        expected: &crate::sekai::event_stream::EventStreamCheckpoint,
        definition_digest: &str,
        admitted: Option<&[crate::sekai::event_stream::StreamEvent]>,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.advance_event_stream_checkpoint(next, expected, definition_digest, admitted)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_event_stream_checkpoint(next, expected, definition_digest, admitted)
            }),
        }
    }

    pub fn ensure_event_stream_admitted_events(
        &self,
        batch: &crate::sekai::event_stream::EventStreamBatch,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.ensure_event_stream_admitted_events(batch),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.ensure_event_stream_admitted_events(batch))
            }
        }
    }

    pub fn verify_event_stream_admitted_events(
        &self,
        stream_id: &str,
        generation: u64,
        feed_epoch: &str,
        events: &[crate::sekai::event_stream::StreamEvent],
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.verify_event_stream_admitted_events(stream_id, generation, feed_epoch, events)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.verify_event_stream_admitted_events(stream_id, generation, feed_epoch, events)
            }),
        }
    }

    pub fn get_event_stream_checkpoint(
        &self,
        stream_id: &str,
    ) -> Result<Option<crate::sekai::event_stream::EventStreamCheckpoint>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_stream_checkpoint(stream_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_event_stream_checkpoint(stream_id))
            }
        }
    }

    pub fn put_event_subscription(
        &self,
        subscription: &crate::sekai::event_subscription::EventSubscription,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.put_event_subscription(subscription),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_event_subscription(subscription))
            }
        }
    }

    pub fn get_event_subscription(
        &self,
        namespace: &str,
        subscription_id: &str,
    ) -> Result<Option<crate::sekai::event_subscription::EventSubscription>, String> {
        match self {
            Self::Sqlite(db) => db.get_event_subscription(namespace, subscription_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_event_subscription(namespace, subscription_id)
            }),
        }
    }

    pub fn revoke_event_subscription_record(
        &self,
        namespace: &str,
        subscription_id: &str,
        owner: &str,
    ) -> Result<crate::sekai::event_subscription::EventSubscription, String> {
        match self {
            Self::Sqlite(db) => db.revoke_event_subscription(namespace, subscription_id, owner),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.revoke_event_subscription(namespace, subscription_id, owner)
            }),
        }
    }

    pub fn advance_event_subscription_cursor(
        &self,
        next: &crate::sekai::event_subscription::EventSubscription,
        expected: &crate::sekai::event_subscription::EventSubscription,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.advance_event_subscription_cursor(next, expected),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_event_subscription_cursor(next, expected)
            }),
        }
    }
}
