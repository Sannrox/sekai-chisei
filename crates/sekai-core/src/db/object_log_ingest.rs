//! Durable intents to ingest an admitted Action's object into the object
//! log (#2289).
//!
//! The transaction that writes an admission's object records its intent:
//! a snapshot of the object as written and a `seq` that orders one object's
//! writes (their transactions serialize on the object row). The receipt's
//! transaction marks it ready; a write whose admission never receipts stays
//! unready, is never drained, and is pruned once its admission can no
//! longer receipt. A receipt an older binary recorded leaves the intent
//! unready; the sweep makes it ready from the receipt's durable marker.
//! Any replica drains ready intents: a claim
//! takes one for a lease, the drain appends its snapshot to the log, and
//! completion deletes the row only while that claim still holds, and
//! raises the object's watermark to its `seq` in the same transaction, so
//! a write at or below it retires without the log's word. A crash
//! leaves the row for the next claim after the lease lapses. The lease only
//! saves duplicate work: the append is fenced on the log itself
//! (`crate::sekai::object_log_ingest`).

use crate::db::postgres::PostgresDb;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::domain::Object;
use rusqlite::{OptionalExtension, params};

pub(crate) const SQLITE_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS sekai_object_log_ingest_intents (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL UNIQUE,
    object_id TEXT NOT NULL,
    object_json TEXT NOT NULL,
    ready INTEGER NOT NULL DEFAULT 0,
    from_grant INTEGER NOT NULL DEFAULT 0,
    recorded_at_ms INTEGER NOT NULL,
    claim_owner TEXT NOT NULL DEFAULT '',
    claimed_until_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_object_log_ingest_intents_ready
    ON sekai_object_log_ingest_intents (ready, claimed_until_ms, seq);
CREATE INDEX IF NOT EXISTS idx_object_log_ingest_intents_object
    ON sekai_object_log_ingest_intents (object_id, seq);
CREATE TABLE IF NOT EXISTS sekai_object_log_ingest_watermarks (
    object_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL
);";

/// Which write recorded an intent; each is receipted its own way.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Writer {
    /// An admission: its receipt sets the lease's `receipt_recorded`.
    Admission,
    /// A grant of a parked admission: its decision's receipt records
    /// `approval_decided`.
    Grant,
}

fn object_json(object: &Object) -> Result<String, String> {
    serde_json::to_string(object).map_err(|error| error.to_string())
}

/// Records, in the transaction that writes `object` for `instance_id`, an
/// unready intent under a fresh `seq`. A repeat for the instance (a grant
/// after its first attempt was undone) replaces the earlier row.
pub(crate) fn sqlite_record_written(
    tx: &rusqlite::Transaction<'_>,
    instance_id: &str,
    object: &Object,
    writer: Writer,
) -> Result<(), String> {
    let json = object_json(object)?;
    tx.execute(
        "DELETE FROM sekai_object_log_ingest_intents WHERE instance_id = ?1",
        params![instance_id],
    )
    .and_then(|_| {
        tx.execute(
            "INSERT INTO sekai_object_log_ingest_intents
                 (instance_id, object_id, object_json, from_grant, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                instance_id,
                object.id,
                json,
                writer == Writer::Grant,
                crate::sekai::action_instance::lease_clock_ms()
            ],
        )
    })
    .map(|_| ())
    .map_err(|error| error.to_string())
}

/// Marks `instance_id`'s intent ready in its receipt's transaction. Every
/// admission object write records one, in its own transaction.
pub(crate) fn sqlite_mark_ready(
    tx: &rusqlite::Transaction<'_>,
    instance_id: &str,
) -> Result<(), String> {
    tx.execute(
        "UPDATE sekai_object_log_ingest_intents SET ready = 1 WHERE instance_id = ?1",
        params![instance_id],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

/// See [`sqlite_record_written`].
pub(crate) fn postgres_record_written(
    tx: &mut postgres::Transaction<'_>,
    instance_id: &str,
    object: &Object,
    writer: Writer,
) -> Result<(), String> {
    tx.execute(
        "DELETE FROM sekai_object_log_ingest_intents WHERE instance_id = $1",
        &[&instance_id],
    )
    .map_err(|error| error.to_string())?;
    tx.execute(
        "INSERT INTO sekai_object_log_ingest_intents
             (instance_id, object_id, object_json, from_grant, recorded_at_ms)
         VALUES ($1, $2, $3, $4, $5)",
        &[
            &instance_id,
            &object.id,
            &object_json(object)?,
            &(writer == Writer::Grant),
            &crate::sekai::action_instance::lease_clock_ms(),
        ],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

/// See [`sqlite_mark_ready`].
pub(crate) fn postgres_mark_ready(
    tx: &mut postgres::Transaction<'_>,
    instance_id: &str,
) -> Result<(), String> {
    tx.execute(
        "UPDATE sekai_object_log_ingest_intents SET ready = TRUE WHERE instance_id = $1",
        &[&instance_id],
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

/// A claimed intent: the object as its admission wrote it, and where that
/// write falls among the object's writes.
pub struct ClaimedIntent {
    pub seq: i64,
    pub instance_id: String,
    pub object: Object,
}

/// Which intent a claim may take.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum IntentScope<'a> {
    /// The ready intent tried least recently, then the oldest.
    Next,
    /// Only this instance's intent, once ready.
    Instance(&'a str),
}

fn claimed(seq: i64, instance_id: String, json: &str) -> Result<ClaimedIntent, String> {
    Ok(ClaimedIntent {
        seq,
        instance_id,
        object: serde_json::from_str(json).map_err(|error| error.to_string())?,
    })
}

/// Claim statement: ready intents only, `Next` past a released intent's
/// retry delay, `Instance` at once. `{lock}` is the backend's row lock.
const CLAIM: &str = "UPDATE sekai_object_log_ingest_intents
     SET claim_owner = {owner}, claimed_until_ms = {until}
     WHERE seq = (
         SELECT i.seq FROM sekai_object_log_ingest_intents i
         WHERE i.ready = {ready}
           AND ({instance} = '' AND i.claimed_until_ms <= {now}
                OR i.instance_id = {instance}
                   AND (i.claim_owner = '' OR i.claimed_until_ms <= {now}))
         ORDER BY i.claimed_until_ms, i.seq
         LIMIT 1 {lock}
     )
     RETURNING seq, instance_id, object_json";

/// Unready intents whose admission can no longer receipt: the instance is
/// gone (released), denied, or parked again after a grant that did not
/// record. A grant that writes again records a new intent; an in-flight
/// admission keeps its instance in another state.
const PRUNE: &str = "DELETE FROM sekai_object_log_ingest_intents
     WHERE ready = {unready}
       AND NOT EXISTS (
           SELECT 1 FROM sekai_action_instances a
           WHERE a.instance_id = sekai_object_log_ingest_intents.instance_id
             AND a.status NOT IN ('denied', 'parked')
       )";

/// Makes ready the unready intents whose write is receipted although the
/// receipt did not ready them: an older binary recorded it. An admission's
/// receipt sets its lease's `receipt_recorded` in the receipt's
/// transaction; a grant's decision receipt records `approval_decided`.
/// Both binaries write both. `{receipted}` is the backend's admission test
/// and `{decided}` its grant test, both on instance `a`.
const PROMOTE: &str = "UPDATE sekai_object_log_ingest_intents SET ready = {ready}
     WHERE ready = {unready}
       AND EXISTS (
           SELECT 1 FROM sekai_action_instances a
           WHERE a.instance_id = sekai_object_log_ingest_intents.instance_id
             AND a.status = 'admitted'
             AND CASE WHEN sekai_object_log_ingest_intents.from_grant = {ready}
                      THEN {decided} ELSE {receipted} END
       )";

const SQLITE_RECEIPTED: &str =
    "COALESCE(json_extract(a.body_json, '$.admission_lease.receipt_recorded'), 0) = 1";
const SQLITE_DECIDED: &str = "EXISTS (
    SELECT 1 FROM chisei_operation_receipts r, json_each(r.receipt_json, '$.events') e
    WHERE r.operation_id = a.operation_id
      AND json_extract(e.value, '$.kind') = 'approval_decided')";
const POSTGRES_RECEIPTED: &str =
    "COALESCE((a.body_json::jsonb #>> '{admission_lease,receipt_recorded}')::boolean, FALSE)";
const POSTGRES_DECIDED: &str = "EXISTS (
    SELECT 1 FROM chisei_operation_receipts r
    WHERE r.operation_id = a.operation_id
      AND jsonb_path_exists(r.receipt_json::jsonb, '$.events[*] ? (@.kind == \"approval_decided\")'))";

/// Watermarks of objects with no intent left: every later write gets a
/// higher `seq`, so nothing still needs them.
const PRUNE_WATERMARKS: &str = "DELETE FROM sekai_object_log_ingest_watermarks
     WHERE NOT EXISTS (
         SELECT 1 FROM sekai_object_log_ingest_intents i
         WHERE i.object_id = sekai_object_log_ingest_watermarks.object_id
     )";

/// A ready intent for an admission an older binary receipted without one,
/// recorded only while the object still holds exactly that admission's
/// committed write, so its `seq` cannot fall behind a later write's.
const RECORD_IF_CURRENT: &str = "INSERT INTO sekai_object_log_ingest_intents
         (instance_id, object_id, object_json, ready, recorded_at_ms)
     VALUES ({instance}, {object}, {json}, {ready}, {now})
     ON CONFLICT (instance_id) DO NOTHING";

fn scope_instance<'a>(scope: IntentScope<'a>) -> &'a str {
    match scope {
        IntentScope::Next => "",
        IntentScope::Instance(id) => id,
    }
}

impl SekaiDb {
    fn claim_object_log_ingest_intent(
        &self,
        scope: IntentScope<'_>,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<ClaimedIntent>, String> {
        // One statement under SQLite's database write lock.
        let sql = CLAIM
            .replace("{owner}", "?1")
            .replace("{until}", "?2")
            .replace("{now}", "?3")
            .replace("{instance}", "?4")
            .replace("{ready}", "1")
            .replace("{lock}", "");
        self.conn()
            .query_row(
                &sql,
                params![
                    owner,
                    now_ms.saturating_add(lease_ms),
                    now_ms,
                    scope_instance(scope)
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, String>(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
            .map(|(seq, instance_id, json)| claimed(seq, instance_id, &json))
            .transpose()
    }

    fn complete_object_log_ingest_intent(
        &self,
        intent: &ClaimedIntent,
        owner: &str,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|error| error.to_string())?;
        let deleted = tx
            .execute(
                "DELETE FROM sekai_object_log_ingest_intents
                 WHERE instance_id = ?1 AND claim_owner = ?2",
                params![intent.instance_id, owner],
            )
            .map_err(|error| error.to_string())?;
        if deleted == 1 {
            tx.execute(
                "INSERT INTO sekai_object_log_ingest_watermarks (object_id, seq) VALUES (?1, ?2)
                 ON CONFLICT (object_id) DO UPDATE SET seq = MAX(seq, excluded.seq)",
                params![intent.object.id, intent.seq],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(deleted == 1)
    }

    fn object_log_ingest_watermark(&self, object_id: &str) -> Result<Option<i64>, String> {
        self.conn()
            .query_row(
                "SELECT seq FROM sekai_object_log_ingest_watermarks WHERE object_id = ?1",
                params![object_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    fn prune_object_log_ingest_intents(&self) -> Result<(), String> {
        let promote = PROMOTE
            .replace("{ready}", "1")
            .replace("{unready}", "0")
            .replace("{decided}", SQLITE_DECIDED)
            .replace("{receipted}", SQLITE_RECEIPTED);
        let conn = self.conn();
        for sql in [
            promote,
            PRUNE.replace("{unready}", "0"),
            PRUNE_WATERMARKS.into(),
        ] {
            conn.execute(&sql, []).map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn record_object_log_ingest_intent_if_current(
        &self,
        instance_id: &str,
        object_id: &str,
        committed_digest: &str,
    ) -> Result<bool, String> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let current = tx
            .query_row(
                "SELECT id, kind, name, namespace, external_id, properties, created, updated
                 FROM sekai_objects WHERE id = ?1",
                params![object_id],
                crate::db::sekai::row_to_object,
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some(object) = current.filter(|object| {
            crate::sekai::action_instance::object_state_digest(Some(object))
                .is_ok_and(|digest| digest == committed_digest)
        }) else {
            return Ok(false);
        };
        let sql = RECORD_IF_CURRENT
            .replace("{instance}", "?1")
            .replace("{object}", "?2")
            .replace("{json}", "?3")
            .replace("{ready}", "1")
            .replace("{now}", "?4");
        tx.execute(
            &sql,
            params![
                instance_id,
                object.id,
                object_json(&object)?,
                crate::sekai::action_instance::lease_clock_ms()
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    fn release_object_log_ingest_intent(
        &self,
        instance_id: &str,
        owner: &str,
        retry_at_ms: i64,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE sekai_object_log_ingest_intents SET claim_owner = '', claimed_until_ms = ?3
                 WHERE instance_id = ?1 AND claim_owner = ?2",
                params![instance_id, owner, retry_at_ms],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn count_object_log_ingest_intents(&self) -> Result<u64, String> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM sekai_object_log_ingest_intents WHERE ready = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|count| count.max(0) as u64)
            .map_err(|error| error.to_string())
    }
}

impl PostgresDb {
    fn claim_object_log_ingest_intent(
        &self,
        scope: IntentScope<'_>,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<ClaimedIntent>, String> {
        // `SKIP LOCKED`: concurrent claimers take different intents.
        let sql = CLAIM
            .replace("{owner}", "$1")
            .replace("{until}", "$2")
            .replace("{now}", "$3")
            .replace("{instance}", "$4")
            .replace("{ready}", "TRUE")
            .replace("{lock}", "FOR UPDATE SKIP LOCKED");
        self.connection()?
            .query_opt(
                &sql,
                &[
                    &owner,
                    &now_ms.saturating_add(lease_ms),
                    &now_ms,
                    &scope_instance(scope),
                ],
            )
            .map_err(|error| error.to_string())?
            .map(|row| claimed(row.get(0), row.get(1), row.get::<_, &str>(2)))
            .transpose()
    }

    fn complete_object_log_ingest_intent(
        &self,
        intent: &ClaimedIntent,
        owner: &str,
    ) -> Result<bool, String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        let deleted = tx
            .execute(
                "DELETE FROM sekai_object_log_ingest_intents
                 WHERE instance_id = $1 AND claim_owner = $2",
                &[&intent.instance_id, &owner],
            )
            .map_err(|error| error.to_string())?;
        if deleted == 1 {
            tx.execute(
                "INSERT INTO sekai_object_log_ingest_watermarks (object_id, seq) VALUES ($1, $2)
                 ON CONFLICT (object_id) DO UPDATE
                 SET seq = GREATEST(sekai_object_log_ingest_watermarks.seq, EXCLUDED.seq)",
                &[&intent.object.id, &intent.seq],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.commit().map_err(|error| error.to_string())?;
        Ok(deleted == 1)
    }

    fn object_log_ingest_watermark(&self, object_id: &str) -> Result<Option<i64>, String> {
        self.connection()?
            .query_opt(
                "SELECT seq FROM sekai_object_log_ingest_watermarks WHERE object_id = $1",
                &[&object_id],
            )
            .map(|row| row.map(|row| row.get(0)))
            .map_err(|error| error.to_string())
    }

    fn prune_object_log_ingest_intents(&self) -> Result<(), String> {
        let promote = PROMOTE
            .replace("{ready}", "TRUE")
            .replace("{unready}", "FALSE")
            .replace("{decided}", POSTGRES_DECIDED)
            .replace("{receipted}", POSTGRES_RECEIPTED);
        let mut conn = self.connection()?;
        for sql in [
            promote,
            PRUNE.replace("{unready}", "FALSE"),
            PRUNE_WATERMARKS.into(),
        ] {
            conn.execute(&sql, &[]).map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn record_object_log_ingest_intent_if_current(
        &self,
        instance_id: &str,
        object_id: &str,
        committed_digest: &str,
    ) -> Result<bool, String> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction().map_err(|error| error.to_string())?;
        // The row lock orders this record after any write in flight and
        // before any write that follows.
        let current = tx
            .query_opt(
                &format!(
                    "SELECT {} FROM sekai_objects WHERE id = $1 FOR UPDATE",
                    crate::db::postgres_audit::OBJECT_COLUMNS
                ),
                &[&object_id],
            )
            .map_err(|error| error.to_string())?
            .map(crate::db::postgres_audit::row_to_object)
            .transpose()?;
        let Some(object) = current.filter(|object| {
            crate::sekai::action_instance::object_state_digest(Some(object))
                .is_ok_and(|digest| digest == committed_digest)
        }) else {
            return Ok(false);
        };
        let sql = RECORD_IF_CURRENT
            .replace("{instance}", "$1")
            .replace("{object}", "$2")
            .replace("{json}", "$3")
            .replace("{ready}", "TRUE")
            .replace("{now}", "$4");
        tx.execute(
            &sql,
            &[
                &instance_id,
                &object.id,
                &object_json(&object)?,
                &crate::sekai::action_instance::lease_clock_ms(),
            ],
        )
        .map_err(|error| error.to_string())?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    fn release_object_log_ingest_intent(
        &self,
        instance_id: &str,
        owner: &str,
        retry_at_ms: i64,
    ) -> Result<(), String> {
        self.connection()?
            .execute(
                "UPDATE sekai_object_log_ingest_intents SET claim_owner = '', claimed_until_ms = $3
                 WHERE instance_id = $1 AND claim_owner = $2",
                &[&instance_id, &owner, &retry_at_ms],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn count_object_log_ingest_intents(&self) -> Result<u64, String> {
        self.connection()?
            .query_one(
                "SELECT COUNT(*) FROM sekai_object_log_ingest_intents WHERE ready",
                &[],
            )
            .map(|row| row.get::<_, i64>(0).max(0) as u64)
            .map_err(|error| error.to_string())
    }
}

impl RuntimeDb {
    /// Records an intent outside an admission, as a write of `object` by
    /// `instance_id` would, and makes it ready as its receipt would.
    #[cfg(test)]
    pub fn record_object_log_ingest_intent(
        &self,
        instance_id: &str,
        object: &Object,
        ready: bool,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                let mut conn = db.conn();
                let tx = conn.transaction().map_err(|error| error.to_string())?;
                sqlite_record_written(&tx, instance_id, object, Writer::Admission)?;
                if ready {
                    sqlite_mark_ready(&tx, instance_id)?;
                }
                tx.commit().map_err(|error| error.to_string())
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                let mut conn = db.connection()?;
                let mut tx = conn.transaction().map_err(|error| error.to_string())?;
                postgres_record_written(&mut tx, instance_id, object, Writer::Admission)?;
                if ready {
                    postgres_mark_ready(&mut tx, instance_id)?;
                }
                tx.commit().map_err(|error| error.to_string())
            }),
        }
    }

    /// Makes `instance_id`'s intent ready, as its receipt would; nothing
    /// when it has none. Replay uses it for a receipt an older binary
    /// recorded over a newer binary's write.
    pub fn mark_object_log_ingest_intent_ready(&self, instance_id: &str) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                let mut conn = db.conn();
                let tx = conn.transaction().map_err(|error| error.to_string())?;
                sqlite_mark_ready(&tx, instance_id)?;
                tx.commit().map_err(|error| error.to_string())
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                let mut conn = db.connection()?;
                let mut tx = conn.transaction().map_err(|error| error.to_string())?;
                postgres_mark_ready(&mut tx, instance_id)?;
                tx.commit().map_err(|error| error.to_string())
            }),
        }
    }

    /// Claims one ready intent for `owner` until `now_ms + lease_ms`. Skips
    /// an intent under a live claim. `Next` also waits out a released
    /// intent's retry delay; `Instance` does not.
    pub fn claim_object_log_ingest_intent(
        &self,
        scope: IntentScope<'_>,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<ClaimedIntent>, String> {
        match self {
            Self::Sqlite(db) => db.claim_object_log_ingest_intent(scope, owner, now_ms, lease_ms),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.claim_object_log_ingest_intent(scope, owner, now_ms, lease_ms)
            }),
        }
    }

    /// Deletes the intent while `owner` still holds its claim. `false` when
    /// another claimer took it over or it is already gone.
    pub fn complete_object_log_ingest_intent(
        &self,
        intent: &ClaimedIntent,
        owner: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.complete_object_log_ingest_intent(intent, owner),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.complete_object_log_ingest_intent(intent, owner)
            }),
        }
    }

    /// The highest `seq` drained for `object_id`, while it has intents.
    pub fn object_log_ingest_watermark(&self, object_id: &str) -> Result<Option<i64>, String> {
        match self {
            Self::Sqlite(db) => db.object_log_ingest_watermark(object_id),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.object_log_ingest_watermark(object_id))
            }
        }
    }

    /// Makes ready the intents an older binary's receipt left unready,
    /// deletes unready intents whose admission can no longer receipt, and
    /// drops watermarks no intent needs.
    pub fn prune_object_log_ingest_intents(&self) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.prune_object_log_ingest_intents(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.prune_object_log_ingest_intents())
            }
        }
    }

    /// For a replay of an admission an older binary receipted without an
    /// intent: records a ready one while `object_id` still holds exactly the
    /// write `committed_digest` names. Returns whether it did.
    pub fn record_object_log_ingest_intent_if_current(
        &self,
        instance_id: &str,
        object_id: &str,
        committed_digest: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => db.record_object_log_ingest_intent_if_current(
                instance_id,
                object_id,
                committed_digest,
            ),
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.record_object_log_ingest_intent_if_current(
                    instance_id,
                    object_id,
                    committed_digest,
                )
            }),
        }
    }

    /// Hands a failed intent back while `owner` still holds it. The sweep
    /// retries it from `retry_at_ms`, after intents never tried; a drain
    /// for this instance (its admit or a replay) may retry it at once.
    pub fn release_object_log_ingest_intent(
        &self,
        instance_id: &str,
        owner: &str,
        retry_at_ms: i64,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => {
                db.release_object_log_ingest_intent(instance_id, owner, retry_at_ms)
            }
            Self::Postgres(db) => crate::db::postgres::off_runtime(|| {
                db.release_object_log_ingest_intent(instance_id, owner, retry_at_ms)
            }),
        }
    }

    /// Ready intents not yet drained: the object-log ingest backlog.
    pub fn count_object_log_ingest_intents(&self) -> Result<u64, String> {
        match self {
            Self::Sqlite(db) => db.count_object_log_ingest_intents(),
            Self::Postgres(db) => {
                crate::db::postgres::off_runtime(|| db.count_object_log_ingest_intents())
            }
        }
    }
}
