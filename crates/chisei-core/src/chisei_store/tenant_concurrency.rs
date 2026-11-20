//! Tenant concurrency holds (#2753) on both community backends.
//!
//! One row per `(tenant, admission key)`. Admit takes a slot when live holds
//! (until_ms >= now) are below the configured max, or renews the same key.
//! A crashed holder's row stops counting once it expires, so another process
//! can take the slot. Release is holder-matched unless `holder` is empty
//! (successor reclaim of the same key).

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sekai_core::db::postgres::PostgresDb;
use sekai_core::db::runtime_db::RuntimeDb;
use sekai_core::db::sekai::SekaiDb;

use super::ChiseiStore;

pub(crate) const SQLITE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS chisei_tenant_concurrency_holds (
    tenant_id TEXT NOT NULL,
    hold_key TEXT NOT NULL,
    holder TEXT NOT NULL,
    until_ms INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, hold_key)
);
CREATE INDEX IF NOT EXISTS idx_chisei_tenant_concurrency_holds_live
    ON chisei_tenant_concurrency_holds (tenant_id, until_ms);
";

pub trait TenantConcurrencyStore {
    /// Inserts or renews `(tenant_id, hold_key)` when a live slot is free.
    /// False when another live hold already occupies the max.
    fn take_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        max: i32,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String>;

    /// Extends `until_ms` when `holder` still has a live row for this key.
    fn renew_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String>;

    /// Drops the row when `holder` still has it. An empty holder deletes the
    /// key so a successor can reclaim after a crash, before re-admitting.
    fn release_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
    ) -> Result<(), String>;
}

fn sqlite_take(
    db: &SekaiDb,
    tenant_id: &str,
    hold_key: &str,
    holder: &str,
    max: i32,
    now_ms: i64,
    until_ms: i64,
) -> Result<bool, String> {
    let mut conn = db.conn();
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| error.to_string())?;
    let this_until: Option<i64> = tx
        .query_row(
            "SELECT until_ms FROM chisei_tenant_concurrency_holds
             WHERE tenant_id = ?1 AND hold_key = ?2",
            params![tenant_id, hold_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let this_live = this_until.is_some_and(|until| until >= now_ms);
    if !this_live {
        let live: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM chisei_tenant_concurrency_holds
                 WHERE tenant_id = ?1 AND until_ms >= ?2",
                params![tenant_id, now_ms],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if live >= i64::from(max.max(0)) {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
    }
    tx.execute(
        "INSERT INTO chisei_tenant_concurrency_holds (tenant_id, hold_key, holder, until_ms)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(tenant_id, hold_key) DO UPDATE SET
            holder = excluded.holder,
            until_ms = excluded.until_ms",
        params![tenant_id, hold_key, holder, until_ms],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(true)
}

fn sqlite_renew(
    db: &SekaiDb,
    tenant_id: &str,
    hold_key: &str,
    holder: &str,
    now_ms: i64,
    until_ms: i64,
) -> Result<bool, String> {
    db.conn()
        .execute(
            "UPDATE chisei_tenant_concurrency_holds SET until_ms = ?4
             WHERE tenant_id = ?1 AND hold_key = ?2 AND holder = ?3 AND until_ms >= ?5",
            params![tenant_id, hold_key, holder, until_ms, now_ms],
        )
        .map(|updated| updated == 1)
        .map_err(|error| error.to_string())
}

fn sqlite_release(
    db: &SekaiDb,
    tenant_id: &str,
    hold_key: &str,
    holder: &str,
) -> Result<(), String> {
    let conn = db.conn();
    let result = if holder.is_empty() {
        conn.execute(
            "DELETE FROM chisei_tenant_concurrency_holds
             WHERE tenant_id = ?1 AND hold_key = ?2",
            params![tenant_id, hold_key],
        )
    } else {
        conn.execute(
            "DELETE FROM chisei_tenant_concurrency_holds
             WHERE tenant_id = ?1 AND hold_key = ?2 AND holder = ?3",
            params![tenant_id, hold_key, holder],
        )
    };
    result.map(|_| ()).map_err(|error| error.to_string())
}

impl TenantConcurrencyStore for SekaiDb {
    fn take_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        max: i32,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        sqlite_take(self, tenant_id, hold_key, holder, max, now_ms, until_ms)
    }

    fn renew_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        sqlite_renew(self, tenant_id, hold_key, holder, now_ms, until_ms)
    }

    fn release_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
    ) -> Result<(), String> {
        sqlite_release(self, tenant_id, hold_key, holder)
    }
}

fn lock_key(tenant_id: &str) -> String {
    format!("tenant-concurrency:{tenant_id}")
}

fn postgres_take(
    db: &PostgresDb,
    tenant_id: &str,
    hold_key: &str,
    holder: &str,
    max: i32,
    now_ms: i64,
    until_ms: i64,
) -> Result<bool, String> {
    let mut connection = db.connection()?;
    let mut tx = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    let key = lock_key(tenant_id);
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 2753))",
        &[&key],
    )
    .map_err(|error| format!("lock tenant concurrency {tenant_id}: {error}"))?;
    let this_until: Option<i64> = tx
        .query_opt(
            "SELECT until_ms FROM chisei_tenant_concurrency_holds
             WHERE tenant_id = $1 AND hold_key = $2",
            &[&tenant_id, &hold_key],
        )
        .map_err(|error| error.to_string())?
        .map(|row| row.get(0));
    let this_live = this_until.is_some_and(|until| until >= now_ms);
    if !this_live {
        let live: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM chisei_tenant_concurrency_holds
                 WHERE tenant_id = $1 AND until_ms >= $2",
                &[&tenant_id, &now_ms],
            )
            .map_err(|error| error.to_string())?
            .get(0);
        if live >= i64::from(max.max(0)) {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(false);
        }
    }
    tx.execute(
        "INSERT INTO chisei_tenant_concurrency_holds (tenant_id, hold_key, holder, until_ms)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, hold_key) DO UPDATE SET
            holder = EXCLUDED.holder,
            until_ms = EXCLUDED.until_ms",
        &[&tenant_id, &hold_key, &holder, &until_ms],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())?;
    Ok(true)
}

fn postgres_renew(
    db: &PostgresDb,
    tenant_id: &str,
    hold_key: &str,
    holder: &str,
    now_ms: i64,
    until_ms: i64,
) -> Result<bool, String> {
    let mut connection = db.connection()?;
    connection
        .execute(
            "UPDATE chisei_tenant_concurrency_holds SET until_ms = $4
             WHERE tenant_id = $1 AND hold_key = $2 AND holder = $3 AND until_ms >= $5",
            &[&tenant_id, &hold_key, &holder, &until_ms, &now_ms],
        )
        .map(|updated| updated == 1)
        .map_err(|error| error.to_string())
}

fn postgres_release(
    db: &PostgresDb,
    tenant_id: &str,
    hold_key: &str,
    holder: &str,
) -> Result<(), String> {
    let mut connection = db.connection()?;
    let result = if holder.is_empty() {
        connection.execute(
            "DELETE FROM chisei_tenant_concurrency_holds
             WHERE tenant_id = $1 AND hold_key = $2",
            &[&tenant_id, &hold_key],
        )
    } else {
        connection.execute(
            "DELETE FROM chisei_tenant_concurrency_holds
             WHERE tenant_id = $1 AND hold_key = $2 AND holder = $3",
            &[&tenant_id, &hold_key, &holder],
        )
    };
    result.map(|_| ()).map_err(|error| error.to_string())
}

impl TenantConcurrencyStore for PostgresDb {
    fn take_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        max: i32,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        postgres_take(self, tenant_id, hold_key, holder, max, now_ms, until_ms)
    }

    fn renew_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        postgres_renew(self, tenant_id, hold_key, holder, now_ms, until_ms)
    }

    fn release_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
    ) -> Result<(), String> {
        postgres_release(self, tenant_id, hold_key, holder)
    }
}

impl ChiseiStore {
    pub(crate) fn take_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        max: i32,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        self.runtime()
            .take_tenant_concurrency_hold(tenant_id, hold_key, holder, max, now_ms, until_ms)
    }

    pub(crate) fn renew_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        self.runtime()
            .renew_tenant_concurrency_hold(tenant_id, hold_key, holder, now_ms, until_ms)
    }

    pub(crate) fn release_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
    ) -> Result<(), String> {
        self.runtime()
            .release_tenant_concurrency_hold(tenant_id, hold_key, holder)
    }
}

impl TenantConcurrencyStore for RuntimeDb {
    fn take_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        max: i32,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.take_tenant_concurrency_hold(tenant_id, hold_key, holder, max, now_ms, until_ms)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.take_tenant_concurrency_hold(tenant_id, hold_key, holder, max, now_ms, until_ms)
            }),
        }
    }

    fn renew_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
        now_ms: i64,
        until_ms: i64,
    ) -> Result<bool, String> {
        match self {
            Self::Sqlite(db) => {
                db.renew_tenant_concurrency_hold(tenant_id, hold_key, holder, now_ms, until_ms)
            }
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.renew_tenant_concurrency_hold(tenant_id, hold_key, holder, now_ms, until_ms)
            }),
        }
    }

    fn release_tenant_concurrency_hold(
        &self,
        tenant_id: &str,
        hold_key: &str,
        holder: &str,
    ) -> Result<(), String> {
        match self {
            Self::Sqlite(db) => db.release_tenant_concurrency_hold(tenant_id, hold_key, holder),
            Self::Postgres(db) => sekai_core::db::postgres::off_runtime(|| {
                db.release_tenant_concurrency_hold(tenant_id, hold_key, holder)
            }),
        }
    }
}
