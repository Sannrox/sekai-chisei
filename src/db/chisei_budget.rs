use chrono::Datelike;
use rusqlite::{OptionalExtension, params};

use crate::db::sekai::SekaiDb;

/// Default metric for token-based budgets (the only metric before Phase C's
/// request-rate quotas reused this table with a `requests` metric).
pub const METRIC_TOKENS: &str = "tokens";
pub const METRIC_REQUESTS: &str = "requests";

/// Root of every budget scope chain. A bare `global` limit applies to every
/// scope in the system; leaving it unset preserves today's "no limit = allow"
/// behavior at that level.
pub const GLOBAL_SCOPE: &str = "global";

/// Builds the root-to-leaf chain of ancestor scope ids for `scope_id`.
///
/// Scope ids are constructed (not stored) as `/`-joined segments, e.g.
/// `project:p/agent:a/work_unit:w`. The chain for that id is
/// `["global", "project:p", "project:p/agent:a", "agent:a", "project:p/agent:a/work_unit:w"]`.
/// A flat, single-segment scope id (e.g. a legacy explicit `subject`) chains
/// through `global` only. For `agent` segments we additionally append a flat
/// `agent:<id>` scope so both scoped and flat `agent:` limits apply.
pub(crate) fn scope_chain(scope_id: &str) -> Vec<String> {
    if scope_id.is_empty() || scope_id == GLOBAL_SCOPE {
        return vec![GLOBAL_SCOPE.to_string()];
    }
    let mut chain = vec![GLOBAL_SCOPE.to_string()];
    let mut acc = String::new();
    for segment in scope_id.split('/') {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(segment);
        if !chain.contains(&acc) {
            chain.push(acc.clone());
        }
        if let Some((kind, _)) = segment.split_once(':')
            && kind == "agent"
        {
            let flat_scope = segment.to_string();
            if !chain.contains(&flat_scope) {
                chain.push(flat_scope);
            }
        }
    }
    chain
}

/// The parent of `scope_id` in the chain built by [`scope_chain`].
pub(crate) fn parent_scope_id(scope_id: &str) -> String {
    if scope_id.is_empty() || scope_id == GLOBAL_SCOPE {
        return String::new();
    }
    match scope_id.rsplit_once('/') {
        Some((parent, _)) => parent.to_string(),
        None => GLOBAL_SCOPE.to_string(),
    }
}

pub(crate) fn period_start_ms(period_type: &str, now_ms: i64) -> i64 {
    let now = chrono::DateTime::from_timestamp_millis(now_ms).unwrap_or_default();
    let date = now.date_naive();
    let start_date = match period_type {
        "weekly" => {
            let days_from_monday = date.weekday().num_days_from_monday() as i64;
            date - chrono::Duration::days(days_from_monday)
        }
        "monthly" => date.with_day(1).unwrap_or(date),
        _ => date,
    };
    start_date
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc()
        .timestamp_millis()
}

impl SekaiDb {
    pub(crate) fn migrate_budget(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_budget_limits (
                scope_id TEXT NOT NULL,
                metric TEXT NOT NULL DEFAULT 'tokens',
                parent_scope_id TEXT NOT NULL DEFAULT '',
                max_amount INTEGER NOT NULL,
                period_type TEXT NOT NULL,
                PRIMARY KEY (scope_id, metric)
            );
            CREATE TABLE IF NOT EXISTS chisei_budget_usage (
                scope_id TEXT NOT NULL,
                metric TEXT NOT NULL DEFAULT 'tokens',
                period_start INTEGER NOT NULL,
                amount_used INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (scope_id, metric, period_start)
            );
            CREATE TABLE IF NOT EXISTS chisei_budget_usage_events (
                idempotency_key TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL,
                metric TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| e.to_string())
    }

    pub(crate) fn budget_set_limit(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        let conn = self.conn();
        let parent = parent_scope_id(scope_id);
        conn.execute(
            "INSERT INTO chisei_budget_limits (scope_id, metric, parent_scope_id, max_amount, period_type)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(scope_id, metric) DO UPDATE SET
                parent_scope_id = excluded.parent_scope_id,
                max_amount = excluded.max_amount,
                period_type = excluded.period_type",
            params![scope_id, metric, parent, max_amount, period_type],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Checks every bounded level of `scope_id`'s ancestor chain for headroom
    /// and, if all pass, atomically deducts `amount` at every level (bounded
    /// or not, so a limit added later at an ancestor sees accurate history).
    /// Levels without a limit row are unlimited. An immediate transaction
    /// serializes the whole check-then-write sequence, so concurrent
    /// reservations against a shared ancestor never over-admit.
    pub(crate) fn budget_check_and_reserve_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        let chain = scope_chain(scope_id);
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        for scope in &chain {
            let limit: Option<(i64, String)> = transaction
                .query_row(
                    "SELECT max_amount, period_type FROM chisei_budget_limits WHERE scope_id=?1 AND metric=?2",
                    params![scope, metric],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            let Some((max_amount, period_type)) = limit else {
                continue;
            };
            let period_start = period_start_ms(&period_type, now_ms);
            let used: i64 = transaction
                .query_row(
                    "SELECT amount_used FROM chisei_budget_usage WHERE scope_id=?1 AND metric=?2 AND period_start=?3",
                    params![scope, metric, period_start],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or(0);
            if used + amount > max_amount {
                return Err(format!(
                    "budget exceeded at {scope}: used {used} + {amount} > {max_amount}"
                ));
            }
        }
        for scope in &chain {
            let period_type = transaction
                .query_row(
                    "SELECT period_type FROM chisei_budget_limits WHERE scope_id=?1 AND metric=?2",
                    params![scope, metric],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or_else(|| "daily".to_string());
            let period_start = period_start_ms(&period_type, now_ms);
            transaction
                .execute(
                    "INSERT INTO chisei_budget_usage (scope_id, metric, period_start, amount_used)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(scope_id, metric, period_start) DO UPDATE SET
                    amount_used = amount_used + excluded.amount_used",
                    params![scope, metric, period_start, amount],
                )
                .map_err(|e| e.to_string())?;
        }
        transaction.commit().map_err(|e| e.to_string())
    }

    /// Read-only variant of [`Self::budget_check_and_reserve_chain`] — checks
    /// headroom at every bounded level without deducting anything.
    pub(crate) fn budget_check_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        let chain = scope_chain(scope_id);
        let conn = self.conn();
        for scope in &chain {
            let limit: Option<(i64, String)> = conn
                .query_row(
                    "SELECT max_amount, period_type FROM chisei_budget_limits WHERE scope_id=?1 AND metric=?2",
                    params![scope, metric],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            let Some((max_amount, period_type)) = limit else {
                continue;
            };
            let period_start = period_start_ms(&period_type, now_ms);
            let used: i64 = conn
                .query_row(
                    "SELECT amount_used FROM chisei_budget_usage WHERE scope_id=?1 AND metric=?2 AND period_start=?3",
                    params![scope, metric, period_start],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or(0);
            if used + amount > max_amount {
                return Err(format!(
                    "budget exceeded at {scope}: used {used} + {amount} > {max_amount}"
                ));
            }
        }
        Ok(())
    }

    /// Applies `delta` (positive or negative, floored at 0) to every level of
    /// `scope_id`'s ancestor chain — used both for plain usage recording and
    /// for reconciling an earlier reservation to actual usage.
    pub(crate) fn budget_adjust_chain(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        let chain = scope_chain(scope_id);
        let conn = self.conn();
        for scope in &chain {
            let period_type = conn
                .query_row(
                    "SELECT period_type FROM chisei_budget_limits WHERE scope_id=?1 AND metric=?2",
                    params![scope, metric],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or_else(|| "daily".to_string());
            let period_start = period_start_ms(&period_type, now_ms);
            let used: i64 = conn
                .query_row(
                    "SELECT amount_used FROM chisei_budget_usage WHERE scope_id=?1 AND metric=?2 AND period_start=?3",
                    params![scope, metric, period_start],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or(0);
            let updated = (used + delta).max(0);
            conn.execute(
                "INSERT INTO chisei_budget_usage (scope_id, metric, period_start, amount_used)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(scope_id, metric, period_start) DO UPDATE SET amount_used = excluded.amount_used",
                params![scope, metric, period_start, updated],
            )
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Applies a usage delta once for a stable caller-generated key. The event
    /// marker and every scope-chain update commit in one SQLite transaction.
    pub(crate) fn budget_record_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        if idempotency_key.is_empty() {
            self.budget_adjust_chain(scope_id, metric, amount, now_ms)?;
            return Ok(true);
        }
        let chain = scope_chain(scope_id);
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO chisei_budget_usage_events
                 (idempotency_key, scope_id, metric, amount, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![idempotency_key, scope_id, metric, amount, now_ms],
            )
            .map_err(|e| e.to_string())?;
        if inserted == 0 {
            let stored = tx
                .query_row(
                    "SELECT scope_id, metric, amount FROM chisei_budget_usage_events
                     WHERE idempotency_key=?1",
                    params![idempotency_key],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .map_err(|e| e.to_string())?;
            if stored != (scope_id.to_string(), metric.to_string(), amount) {
                return Err("idempotency key was already used for different budget usage".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(false);
        }
        for scope in &chain {
            let period_type = tx
                .query_row(
                    "SELECT period_type FROM chisei_budget_limits WHERE scope_id=?1 AND metric=?2",
                    params![scope, metric],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or_else(|| "daily".to_string());
            let period_start = period_start_ms(&period_type, now_ms);
            tx.execute(
                "INSERT INTO chisei_budget_usage (scope_id, metric, period_start, amount_used)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(scope_id, metric, period_start) DO UPDATE SET
                    amount_used = MAX(0, amount_used + excluded.amount_used)",
                params![scope, metric, period_start, amount],
            )
            .map_err(|e| e.to_string())?;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Current usage/limit for `scope_id` alone (not the whole chain) — the
    /// scope's own reported numbers, matching `BudgetUsage`'s single-scope shape.
    pub(crate) fn budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String> {
        let conn = self.conn();
        let limit: Option<(i64, String)> = conn
            .query_row(
                "SELECT max_amount, period_type FROM chisei_budget_limits WHERE scope_id=?1 AND metric=?2",
                params![scope_id, metric],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let (max_amount, period_type) = limit.unwrap_or((0, "daily".to_string()));
        let period_start = period_start_ms(&period_type, now_ms);
        let used: i64 = conn
            .query_row(
                "SELECT amount_used FROM chisei_budget_usage WHERE scope_id=?1 AND metric=?2 AND period_start=?3",
                params![scope_id, metric, period_start],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or(0);
        Ok((used, max_amount, period_type))
    }

    /// Worst pressure level among scopes whose id starts with `namespace`
    /// (matches the pre-hierarchy prefix-scan semantics of
    /// `BudgetTracker::namespace_pressure`, now backed by SQL `LIKE`).
    pub(crate) fn budget_namespace_pressure(
        &self,
        namespace: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        if namespace.is_empty() {
            return Ok(0);
        }
        let conn = self.conn();
        let pattern = format!("{namespace}%");
        let mut stmt = conn
            .prepare(
                "SELECT scope_id, max_amount, period_type FROM chisei_budget_limits
                 WHERE metric=?1 AND scope_id LIKE ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![metric, pattern], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut worst = 0;
        for row in rows {
            let (scope_id, max_amount, period_type) = row.map_err(|e| e.to_string())?;
            if max_amount <= 0 {
                continue;
            }
            let period_start = period_start_ms(&period_type, now_ms);
            let used: i64 = conn
                .query_row(
                    "SELECT amount_used FROM chisei_budget_usage WHERE scope_id=?1 AND metric=?2 AND period_start=?3",
                    params![scope_id, metric, period_start],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .unwrap_or(0);
            let pct = used * 100 / max_amount;
            let level = if pct >= 90 {
                2
            } else if pct >= 70 {
                1
            } else {
                0
            };
            worst = worst.max(level);
        }
        Ok(worst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::{Arc, Barrier};

    #[test]
    fn scope_chain_includes_flat_agent_scope() {
        let chain = scope_chain("project:sekai/agent:codex-app/work_unit:wu-1");
        assert_eq!(
            chain,
            vec![
                "global".to_string(),
                "project:sekai".to_string(),
                "project:sekai/agent:codex-app".to_string(),
                "agent:codex-app".to_string(),
                "project:sekai/agent:codex-app/work_unit:wu-1".to_string(),
            ]
        );
    }

    #[test]
    fn monthly_period_starts_at_first_of_month() {
        let now_ms = chrono::Utc
            .with_ymd_and_hms(2026, 6, 30, 12, 30, 0)
            .unwrap()
            .timestamp_millis();
        let actual = period_start_ms("monthly", now_ms);
        let expected = chrono::Utc
            .with_ymd_and_hms(2026, 6, 1, 0, 0, 0)
            .unwrap()
            .timestamp_millis();
        assert_eq!(actual, expected);
    }

    #[test]
    fn concurrent_reservations_do_not_exceed_shared_limit() {
        let path = std::env::temp_dir().join(format!("sekai-budget-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(SekaiDb::new(path.to_str().unwrap()).unwrap());
        db.budget_set_limit("global", METRIC_TOKENS, 10, "daily")
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));

        let handles = (0..2)
            .map(|_| {
                let db = Arc::clone(&db);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    db.budget_check_and_reserve_chain("global", METRIC_TOKENS, 6, 0)
                })
            })
            .collect::<Vec<_>>();
        let successes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(Result::is_ok)
            .count();

        assert_eq!(successes, 1);
        assert_eq!(db.budget_usage("global", METRIC_TOKENS, 0).unwrap().0, 6);
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
    }
}
