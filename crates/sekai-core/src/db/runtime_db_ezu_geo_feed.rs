//! Dual-backend community-store dispatch for ezu geo feed.
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
use super::*;

impl RuntimeDb {
    pub fn put_ezu_geo_feed(
        &self,
        feed: &crate::sekai::ezu_geo_feed::EzuGeoFeed,
        actor: &str,
        now_ms: i64,
    ) -> Result<crate::sekai::ezu_geo_feed::EzuGeoFeed, String> {
        match self {
            Self::Sqlite(db) => db.put_ezu_geo_feed(feed, actor, now_ms),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.put_ezu_geo_feed(feed, actor, now_ms))
            }
        }
    }

    pub fn get_ezu_geo_feed(
        &self,
        namespace: &str,
        feed_id: &str,
    ) -> Result<Option<(crate::sekai::ezu_geo_feed::EzuGeoFeed, u64)>, String> {
        match self {
            Self::Sqlite(db) => db.get_ezu_geo_feed(namespace, feed_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.get_ezu_geo_feed(namespace, feed_id))
            }
        }
    }

    pub fn lease_ezu_geo_feed_run(
        &self,
        feed: &crate::sekai::ezu_geo_feed::EzuGeoFeed,
        run_id: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.lease_ezu_geo_feed_run(feed, run_id, renew, now_ms, until_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.lease_ezu_geo_feed_run(feed, run_id, renew, now_ms, until_ms)
            }),
        }
    }

    pub fn raise_ezu_geo_feed_write_fence(
        &self,
        feed: &crate::sekai::ezu_geo_feed::EzuGeoFeed,
        run_id: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.raise_ezu_geo_feed_write_fence(feed, run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.raise_ezu_geo_feed_write_fence(feed, run_id))
            }
        }
    }

    pub fn release_ezu_geo_feed_run(
        &self,
        feed: &crate::sekai::ezu_geo_feed::EzuGeoFeed,
        run_id: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_ezu_geo_feed_run(feed, run_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.release_ezu_geo_feed_run(feed, run_id))
            }
        }
    }

    pub fn advance_ezu_geo_feed(
        &self,
        feed: &crate::sekai::ezu_geo_feed::EzuGeoFeed,
        run_id: &str,
        through: u64,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.advance_ezu_geo_feed(feed, run_id, through, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_ezu_geo_feed(feed, run_id, through, now_ms)
            }),
        }
    }

    pub fn get_ezu_geo_feed_progress(
        &self,
        namespace: &str,
        feed_id: &str,
    ) -> Result<Option<crate::sekai::ezu_geo_feed::EzuGeoFeedProgress>, String> {
        match self {
            Self::Sqlite(db) => db.get_ezu_geo_feed_progress(namespace, feed_id),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.get_ezu_geo_feed_progress(namespace, feed_id)
            }),
        }
    }

    pub fn begin_ezu_geo_feed_backfill(
        &self,
        feed: &crate::sekai::ezu_geo_feed::EzuGeoFeed,
        run_id: &str,
        now_ms: i64,
    ) -> Result<Option<crate::sekai::ezu_geo_feed::EzuGeoFeedProgress>, String> {
        match self {
            Self::Sqlite(db) => db.begin_ezu_geo_feed_backfill(feed, run_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.begin_ezu_geo_feed_backfill(feed, run_id, now_ms)
            }),
        }
    }

    pub fn list_ezu_geo_feed_objects(
        &self,
        namespace: &str,
        kind: &str,
        after_id: &str,
        limit: u32,
    ) -> Result<Vec<crate::domain::Object>, String> {
        match self {
            Self::Sqlite(db) => db.list_ezu_geo_feed_objects(namespace, kind, after_id, limit),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.list_ezu_geo_feed_objects(namespace, kind, after_id, limit)
            }),
        }
    }

    pub fn advance_ezu_geo_feed_backfill(
        &self,
        feed: &crate::sekai::ezu_geo_feed::EzuGeoFeed,
        run_id: &str,
        after_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.advance_ezu_geo_feed_backfill(feed, run_id, after_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.advance_ezu_geo_feed_backfill(feed, run_id, after_id, now_ms)
            }),
        }
    }

    pub fn complete_ezu_geo_feed_backfill(
        &self,
        feed: &crate::sekai::ezu_geo_feed::EzuGeoFeed,
        run_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.complete_ezu_geo_feed_backfill(feed, run_id, now_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.complete_ezu_geo_feed_backfill(feed, run_id, now_ms)
            }),
        }
    }
}
