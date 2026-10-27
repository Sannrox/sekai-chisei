//! PostgreSQL storage for Ezu geo feeds (#1797). Same tables and semantics
//! as SQLite (`sekai::ezu_geo_feed`). Installs serialize on a per-feed
//! advisory lock and `FOR UPDATE` on the feed row so a concurrent lease
//! takeover or fence raise cannot lose its `write_fence`; the cursor write
//! is conditional, so it needs none.

use crate::db::postgres::{PostgresDb, advisory_lock_key};
use crate::db::postgres_audit::row_to_object;
use crate::domain::Object;
use crate::sekai::ezu_geo_feed::{EzuGeoFeed, EzuGeoFeedProgress};

/// Committed `MAX(audit_seq)` for the namespace, the same cursor incremental
/// uses (`object_change_watermark`). Identity values are assigned before commit.
fn namespace_change_watermark(
    tx: &mut postgres::Transaction<'_>,
    namespace: &str,
) -> Result<u64, String> {
    tx.query_one(
        "SELECT COALESCE(MAX(c.audit_seq), 0)
         FROM sekai_object_changes c
         LEFT JOIN sekai_objects o ON o.id = c.object_id
         WHERE o.namespace = $1
            OR EXISTS (
              SELECT 1 FROM sekai_object_changes n
              WHERE n.object_id = c.object_id
                AND n.field = '_namespace'
                AND n.old_value = $1
            )",
        &[&namespace],
    )
    .map(|row| row.get::<_, i64>(0).max(0) as u64)
    .map_err(|error| error.to_string())
}

impl PostgresDb {
    pub fn put_ezu_geo_feed(
        &self,
        feed: &EzuGeoFeed,
        actor: &str,
        now_ms: i64,
    ) -> Result<EzuGeoFeed, String> {
        feed.validate()?;
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = advisory_lock_key(&["ezu_geo_feed", &feed.namespace, &feed.feed_id]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let previous: Option<(i64, String)> = tx
            .query_opt(
                "SELECT revision, body_json FROM sekai_ezu_geo_feeds
                 WHERE namespace = $1 AND feed_id = $2
                 FOR UPDATE",
                &[&feed.namespace, &feed.feed_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| (row.get(0), row.get(1)));
        let previous_fence = previous
            .as_ref()
            .and_then(|(_, body)| serde_json::from_str::<EzuGeoFeed>(body).ok())
            .map(|previous| previous.write_fence)
            .unwrap_or(0);
        let watermark = namespace_change_watermark(&mut tx, &feed.namespace)?;
        let mut stored = feed.clone();
        let reinstall = previous.is_some();
        stored.revision = previous.map_or(1, |(revision, _)| revision as u64 + 1);
        stored.write_fence = if reinstall {
            crate::sekai::ezu_geo_feed::next_write_fence(previous_fence, watermark)
        } else {
            0
        };
        stored.created_by = actor.to_string();
        stored.updated_at_ms = now_ms;
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO sekai_ezu_geo_feeds
                (namespace, feed_id, revision, body_json, updated_at_ms)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (namespace, feed_id) DO UPDATE SET
                revision = EXCLUDED.revision,
                body_json = EXCLUDED.body_json,
                run_id = '',
                run_lease_until_ms = 0,
                backfill_watermark = 0,
                backfill_after_id = '',
                backfill_active = FALSE,
                updated_at_ms = EXCLUDED.updated_at_ms",
            &[
                &stored.namespace,
                &stored.feed_id,
                &(stored.revision as i64),
                &body,
                &now_ms,
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(stored)
    }

    pub fn get_ezu_geo_feed(
        &self,
        namespace: &str,
        feed_id: &str,
    ) -> Result<Option<(EzuGeoFeed, u64)>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT body_json, after_seq
                 FROM sekai_ezu_geo_feeds WHERE namespace = $1 AND feed_id = $2",
                &[&namespace, &feed_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let body: String = row.get(0);
                let seq: i64 = row.get(1);
                let feed: EzuGeoFeed = serde_json::from_str(&body)
                    .map_err(|error| format!("corrupt ezu geo feed: {error}"))?;
                Ok((feed, seq.max(0) as u64))
            })
            .transpose()
    }

    pub fn lease_ezu_geo_feed_run(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        renew: bool,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        if renew {
            return connection
                .execute(
                    "UPDATE sekai_ezu_geo_feeds SET run_id = $4, run_lease_until_ms = $6
                     WHERE namespace = $1 AND feed_id = $2 AND revision = $3
                       AND run_id = $4 AND run_lease_until_ms >= $5",
                    &[
                        &feed.namespace,
                        &feed.feed_id,
                        &(feed.revision as i64),
                        &run_id,
                        &now_ms,
                        &until_ms,
                    ],
                )
                .map(|updated| updated == 1)
                .map_err(|error| error.to_string());
        }
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT run_id, run_lease_until_ms, body_json, revision
                 FROM sekai_ezu_geo_feeds WHERE namespace = $1 AND feed_id = $2
                 FOR UPDATE",
                &[&feed.namespace, &feed.feed_id],
            )
            .map_err(|error| error.to_string())?;
        let Some(row) = row else {
            return Ok(false);
        };
        let held_run: String = row.get(0);
        let lease_until: i64 = row.get(1);
        let body: String = row.get(2);
        let revision: i64 = row.get(3);
        if revision != feed.revision as i64 || !(held_run.is_empty() || lease_until < now_ms) {
            return Ok(false);
        }
        let mut stored: EzuGeoFeed = serde_json::from_str(&body)
            .map_err(|error| format!("corrupt ezu geo feed: {error}"))?;
        if !held_run.is_empty() {
            let watermark = namespace_change_watermark(&mut tx, &feed.namespace)?;
            stored.write_fence =
                crate::sekai::ezu_geo_feed::next_write_fence(stored.write_fence, watermark);
        }
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        let updated = tx
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET run_id = $3, run_lease_until_ms = $4, body_json = $5
                 WHERE namespace = $1 AND feed_id = $2 AND revision = $6",
                &[
                    &feed.namespace,
                    &feed.feed_id,
                    &run_id,
                    &until_ms,
                    &body,
                    &(feed.revision as i64),
                ],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(updated == 1)
    }

    pub fn raise_ezu_geo_feed_write_fence(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT run_id, body_json, revision
                 FROM sekai_ezu_geo_feeds WHERE namespace = $1 AND feed_id = $2
                 FOR UPDATE",
                &[&feed.namespace, &feed.feed_id],
            )
            .map_err(|error| error.to_string())?;
        let Some(row) = row else {
            return Ok(false);
        };
        let held_run: String = row.get(0);
        let body: String = row.get(1);
        let revision: i64 = row.get(2);
        if held_run != run_id || revision != feed.revision as i64 {
            return Ok(false);
        }
        let mut stored: EzuGeoFeed = serde_json::from_str(&body)
            .map_err(|error| format!("corrupt ezu geo feed: {error}"))?;
        let watermark = namespace_change_watermark(&mut tx, &feed.namespace)?;
        stored.write_fence =
            crate::sekai::ezu_geo_feed::next_write_fence(stored.write_fence, watermark);
        let body = serde_json::to_string(&stored).map_err(|error| error.to_string())?;
        let updated = tx
            .execute(
                "UPDATE sekai_ezu_geo_feeds SET body_json = $3
                 WHERE namespace = $1 AND feed_id = $2 AND run_id = $4 AND revision = $5",
                &[
                    &feed.namespace,
                    &feed.feed_id,
                    &body,
                    &run_id,
                    &(feed.revision as i64),
                ],
            )
            .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(updated == 1)
    }

    pub fn release_ezu_geo_feed_run(&self, feed: &EzuGeoFeed, run_id: &str) -> Result<(), String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "UPDATE sekai_ezu_geo_feeds SET run_id = '', run_lease_until_ms = 0
                 WHERE namespace = $1 AND feed_id = $2 AND run_id = $3",
                &[&feed.namespace, &feed.feed_id, &run_id],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn advance_ezu_geo_feed(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        through: u64,
        now_ms: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET after_seq = $4, updated_at_ms = $5
                 WHERE namespace = $1 AND feed_id = $2 AND revision = $3
                   AND run_id = $6 AND run_lease_until_ms >= $5
                   AND after_seq < $4",
                &[
                    &feed.namespace,
                    &feed.feed_id,
                    &(feed.revision as i64),
                    &(through as i64),
                    &now_ms,
                    &run_id,
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    pub fn get_ezu_geo_feed_progress(
        &self,
        namespace: &str,
        feed_id: &str,
    ) -> Result<Option<EzuGeoFeedProgress>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT after_seq, backfill_watermark, backfill_after_id, backfill_active
                 FROM sekai_ezu_geo_feeds WHERE namespace = $1 AND feed_id = $2",
                &[&namespace, &feed_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                Ok(EzuGeoFeedProgress {
                    after_seq: row.get::<_, i64>(0).max(0) as u64,
                    backfill_watermark: row.get::<_, i64>(1).max(0) as u64,
                    backfill_after_id: row.get(2),
                    backfill_active: row.get(3),
                })
            })
            .transpose()
    }

    pub fn begin_ezu_geo_feed_backfill(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        now_ms: i64,
    ) -> Result<Option<EzuGeoFeedProgress>, String> {
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = advisory_lock_key(&["ezu_geo_feed", &feed.namespace, &feed.feed_id]);
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 467))",
            &[&lock_key],
        )
        .map_err(|error| error.to_string())?;
        let row = tx
            .query_opt(
                "SELECT after_seq, backfill_after_id, backfill_watermark, backfill_active,
                        run_id, revision
                 FROM sekai_ezu_geo_feeds WHERE namespace = $1 AND feed_id = $2
                 FOR UPDATE",
                &[&feed.namespace, &feed.feed_id],
            )
            .map_err(|error| error.to_string())?;
        let Some(row) = row else {
            return Ok(None);
        };
        let after_seq: i64 = row.get(0);
        let after_id: String = row.get(1);
        let stored_watermark: i64 = row.get(2);
        let active: bool = row.get(3);
        let held_run: String = row.get(4);
        let revision: i64 = row.get(5);
        if held_run != run_id || revision != feed.revision as i64 {
            return Ok(None);
        }
        if active {
            return Ok(Some(EzuGeoFeedProgress {
                after_seq: after_seq.max(0) as u64,
                backfill_watermark: stored_watermark.max(0) as u64,
                backfill_after_id: after_id,
                backfill_active: true,
            }));
        }
        // Identity values are assigned before commit. Without this lock,
        // MAX(audit_seq) can sit above an in-flight insert; handing that
        // value to the incremental cursor would skip the late commit.
        // SHARE ROW EXCLUSIVE waits for those inserts and blocks new ones
        // until this transaction ends, so the captured max is a committed
        // prefix. SQLite does the same by taking an IMMEDIATE transaction
        // on the shared file.
        tx.execute(
            "LOCK TABLE sekai_object_changes IN SHARE ROW EXCLUSIVE MODE",
            &[],
        )
        .map_err(|error| error.to_string())?;
        let watermark = namespace_change_watermark(&mut tx, &feed.namespace)?;
        tx.execute(
            "UPDATE sekai_ezu_geo_feeds
             SET backfill_watermark = $3, backfill_after_id = '', backfill_active = TRUE,
                 updated_at_ms = $4
             WHERE namespace = $1 AND feed_id = $2 AND run_id = $5 AND revision = $6",
            &[
                &feed.namespace,
                &feed.feed_id,
                &(watermark as i64),
                &now_ms,
                &run_id,
                &(feed.revision as i64),
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(Some(EzuGeoFeedProgress {
            after_seq: after_seq.max(0) as u64,
            backfill_watermark: watermark,
            backfill_after_id: String::new(),
            backfill_active: true,
        }))
    }

    pub fn list_ezu_geo_feed_objects(
        &self,
        namespace: &str,
        kind: &str,
        after_id: &str,
        limit: u32,
    ) -> Result<Vec<Object>, String> {
        let mut connection = self.connection()?;
        let limit = i64::from(limit);
        connection
            .query(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects
                 WHERE namespace = $1 AND kind = $2 AND id > $3
                 ORDER BY id ASC
                 LIMIT $4",
                &[&namespace, &kind, &after_id, &limit],
            )
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(row_to_object)
            .collect()
    }

    pub fn advance_ezu_geo_feed_backfill(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        after_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET backfill_after_id = $4, updated_at_ms = $5
                 WHERE namespace = $1 AND feed_id = $2 AND revision = $3
                   AND run_id = $6 AND run_lease_until_ms >= $5
                   AND backfill_active",
                &[
                    &feed.namespace,
                    &feed.feed_id,
                    &(feed.revision as i64),
                    &after_id,
                    &now_ms,
                    &run_id,
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }

    /// Hands the incremental cursor to the captured watermark and clears the
    /// backfill page. Forward only. Pre-watermark removals are not expired;
    /// a new or rebuilt Ezu has none.
    pub fn complete_ezu_geo_feed_backfill(
        &self,
        feed: &EzuGeoFeed,
        run_id: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        let mut connection = self.connection()?;
        connection
            .execute(
                "UPDATE sekai_ezu_geo_feeds
                 SET after_seq = CASE
                        WHEN after_seq < backfill_watermark THEN backfill_watermark
                        ELSE after_seq
                     END,
                     backfill_active = FALSE,
                     backfill_after_id = '',
                     updated_at_ms = $4
                 WHERE namespace = $1 AND feed_id = $2 AND revision = $3
                   AND run_id = $5 AND run_lease_until_ms >= $4
                   AND backfill_active",
                &[
                    &feed.namespace,
                    &feed.feed_id,
                    &(feed.revision as i64),
                    &now_ms,
                    &run_id,
                ],
            )
            .map(|updated| updated == 1)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_ezu_geo_feed_cursors_move_forward_once_per_revision() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        let namespace = format!("ezu-geo-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        crate::sekai::ezu_geo_feed::tests::cursor_contract(&db, &namespace);
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL"]
    fn postgres_ezu_geo_feed_backfill_hands_the_cursor_to_the_watermark() {
        let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
            .expect("SEKAI_TEST_POSTGRES_URL must point to an isolated PostgreSQL test database");
        let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
            Ok(path) => crate::db::postgres::PostgresDb::connect_with_ca_certificate(
                &url,
                4,
                &std::fs::read(path).unwrap(),
            ),
            Err(_) => crate::db::postgres::PostgresDb::connect(&url, 4),
        };
        let db = crate::db::runtime_db::RuntimeDb::Postgres(std::sync::Arc::new(db.unwrap()));
        let namespace = format!("ezu-bf-{}-{}", std::process::id(), uuid::Uuid::new_v4());
        crate::sekai::ezu_geo_feed::tests::backfill_contract(&db, &namespace);
    }
}
