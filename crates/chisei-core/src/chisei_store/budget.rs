//! SQLite persistence for Chisei budget limits, usage, and transfers.

use rusqlite::{OptionalExtension, params};
use sekai_core::db::chisei_budget::{
    BUDGET_METRICS, BudgetScopeUsage, BudgetTransferRecord, UNLIMITED_PERIOD_TYPE, parent_scope_id,
    period_start_ms, scope_chain, work_unit_default_scope,
};
use sekai_core::db::sekai::SekaiDb;

/// The limit that governs one scope and metric: its own limit, else its
/// parent's work-unit default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveLimit {
    pub max_amount: i64,
    pub period_type: String,
    pub home_site_id: String,
    pub from_work_unit_default: bool,
}

/// Reads a scope's own limit, falling back to its work-unit default, in one
/// statement. `?3` is NULL for a scope that is not a work unit, so the
/// fallback never matches.
const EFFECTIVE_LIMIT_SQL: &str = "SELECT max_amount, period_type, home_site_id, 0
     FROM chisei_budget_limits WHERE scope_id=?1 AND metric=?2
     UNION ALL
     SELECT max_amount, period_type, home_site_id, 1
     FROM chisei_budget_work_unit_defaults WHERE scope_id=?3 AND metric=?2
     ORDER BY 4 LIMIT 1";

fn effective_limit(
    conn: &rusqlite::Connection,
    scope: &str,
    metric: &str,
) -> Result<Option<EffectiveLimit>, String> {
    conn.query_row(
        EFFECTIVE_LIMIT_SQL,
        params![scope, metric, work_unit_default_scope(scope)],
        |row| {
            Ok(EffectiveLimit {
                max_amount: row.get(0)?,
                period_type: row.get(1)?,
                home_site_id: row.get(2)?,
                from_work_unit_default: row.get::<_, i64>(3)? == 1,
            })
        },
    )
    .optional()
    .map_err(|e| e.to_string())
}

/// The period a scope's usage is charged to: its effective limit's, or the
/// unlimited default.
fn charge_period_type(
    conn: &rusqlite::Connection,
    scope: &str,
    metric: &str,
) -> Result<String, String> {
    Ok(effective_limit(conn, scope, metric)?.map_or_else(
        || UNLIMITED_PERIOD_TYPE.to_string(),
        |limit| limit.period_type,
    ))
}

/// Every metric's limit of one scope.
const OWN_LIMITS_SQL: &str = "SELECT metric, max_amount, period_type
     FROM chisei_budget_limits WHERE scope_id=?1 ORDER BY metric";

/// Every metric's effective limit of one work unit: its own limits, plus the
/// work-unit default (`?2`) for each metric it has no limit of its own for.
const WORK_UNIT_LIMITS_SQL: &str = "SELECT metric, max_amount, period_type
     FROM chisei_budget_limits WHERE scope_id=?1
     UNION ALL
     SELECT metric, max_amount, period_type
     FROM chisei_budget_work_unit_defaults AS defaults
     WHERE defaults.scope_id=?2 AND NOT EXISTS (
       SELECT 1 FROM chisei_budget_limits AS own
       WHERE own.scope_id=?1 AND own.metric=defaults.metric
     )
     ORDER BY metric";

fn query_limits(
    conn: &rusqlite::Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<(String, i64, String)>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    stmt.query_map(params, |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())
}

pub trait BudgetSekaiDbExt {
    fn budget_limits_for_scope(
        &self,
        scope_id: &str,
    ) -> Result<Vec<(String, String, i64, String)>, String>;
    fn budget_set_limit(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String>;
    fn budget_set_limit_scoped(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
        home_site_id: &str,
        pool_id: &str,
    ) -> Result<(), String>;
    /// Sets the limit every `work_unit:` child of `scope_id` without a limit
    /// of its own gets for `metric` (#1862).
    fn budget_set_work_unit_default(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
        home_site_id: &str,
    ) -> Result<(), String>;
    /// Removes `scope_id`'s work-unit default for `metric`. Removing an
    /// unset default succeeds.
    fn budget_clear_work_unit_default(&self, scope_id: &str, metric: &str) -> Result<(), String>;
    fn budget_set_pool_ceiling(
        &self,
        pool_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String>;
    /// Checks every bounded level of `scope_id`'s ancestor chain for headroom
    /// and, if all pass, atomically deducts `amount` at every level (bounded
    /// or not, so a limit added later at an ancestor sees accurate history).
    /// Levels without a limit row are unlimited. An immediate transaction
    /// serializes the whole check-then-write sequence, so concurrent
    /// reservations against a shared ancestor never over-admit.
    fn budget_check_and_reserve_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String>;
    fn budget_check_and_reserve_chain_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<(), String>;
    #[allow(clippy::too_many_arguments)]
    fn budget_check_and_reserve_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: Option<&str>,
        require_home_pin: bool,
        local_site_id: &str,
        partition_simulated: bool,
    ) -> Result<(), String>;
    #[allow(clippy::too_many_arguments)]
    fn budget_check_and_reserve_chain_inner(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: Option<&str>,
        require_home_pin: bool,
        local_site_id: &str,
        partition_simulated: bool,
    ) -> Result<(), String>;
    /// Read-only variant of [`Self::budget_check_and_reserve_chain`] — checks
    /// headroom at every bounded level without deducting anything.
    fn budget_check_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String>;
    #[allow(clippy::too_many_arguments)]
    fn budget_check_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
        _partition_simulated: bool,
    ) -> Result<(), String>;
    fn budget_assert_home_writable(
        &self,
        scope_id: &str,
        metric: &str,
        local_site_id: &str,
    ) -> Result<(), String>;
    /// Applies `delta` (positive or negative, floored at 0) to every level of
    /// `scope_id`'s ancestor chain — used both for plain usage recording and
    /// for reconciling an earlier reservation to actual usage.
    fn budget_adjust_chain(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
    ) -> Result<(), String>;
    fn budget_adjust_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
    ) -> Result<(), String>;
    #[allow(clippy::too_many_arguments)]
    fn budget_transfer_capacity(
        &self,
        transfer_id: &str,
        metric: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        actor: &str,
        now_ms: i64,
    ) -> Result<BudgetTransferRecord, String>;
    #[allow(clippy::too_many_arguments)]
    fn budget_record_transfer_refused(
        &self,
        transfer_id: &str,
        metric: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<BudgetTransferRecord, String>;
    fn budget_get_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<Option<BudgetTransferRecord>, String>;
    /// Applies a usage delta once for a stable caller-generated key. The event
    /// marker and every scope-chain update commit in one SQLite transaction.
    fn budget_record_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String>;
    /// [`Self::budget_record_idempotent`] that, when `require_home_pin`,
    /// refuses a positive debit of a scope homed on another site, checked
    /// in the debit's transaction.
    #[allow(clippy::too_many_arguments)]
    fn budget_record_idempotent_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        idempotency_key: &str,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
    ) -> Result<bool, String>;
    /// Current usage/limit for `scope_id` alone (not the whole chain) — the
    /// scope's own reported numbers, matching `BudgetUsage`'s single-scope shape.
    fn budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String>;
    /// Usage of every scope in the chain of `scope_id`, for each metric in
    /// [`BUDGET_METRICS`], read in one transaction so the levels agree.
    fn budget_usage_chain(
        &self,
        scope_id: &str,
        now_ms: i64,
    ) -> Result<Vec<BudgetScopeUsage>, String>;
    #[cfg(feature = "gateway-test-support")]
    #[doc(hidden)]
    fn gateway_test_budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String>;
    /// Worst pressure level among scopes whose id starts with `namespace`
    /// (matches the pre-hierarchy prefix-scan semantics of
    /// `BudgetTracker::namespace_pressure`, now backed by SQL `LIKE`).
    fn budget_namespace_pressure(
        &self,
        namespace: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<i32, String>;
}

impl BudgetSekaiDbExt for SekaiDb {
    fn budget_limits_for_scope(
        &self,
        scope_id: &str,
    ) -> Result<Vec<(String, String, i64, String)>, String> {
        let scopes = scope_chain(scope_id);
        let conn = self.conn();
        let mut limits = Vec::new();
        for scope in scopes {
            // Only a work unit reads the defaults, so a plane without budget
            // tables still reports `chisei_budget_limits` missing.
            let rows = match work_unit_default_scope(&scope) {
                Some(parent) => query_limits(&conn, WORK_UNIT_LIMITS_SQL, params![scope, parent])?,
                None => query_limits(&conn, OWN_LIMITS_SQL, params![scope])?,
            };
            for (metric, max_amount, period_type) in rows {
                limits.push((scope.clone(), metric, max_amount, period_type));
            }
        }
        Ok(limits)
    }

    fn budget_set_limit(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        self.budget_set_limit_scoped(scope_id, metric, max_amount, period_type, "", "")
    }

    fn budget_set_limit_scoped(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
        home_site_id: &str,
        pool_id: &str,
    ) -> Result<(), String> {
        if max_amount < 0 {
            return Err("budget max_amount must be non-negative".into());
        }
        let mut conn = self.conn();
        let parent = parent_scope_id(scope_id);
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO chisei_budget_limits
                (scope_id, metric, parent_scope_id, max_amount, period_type, home_site_id, pool_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(scope_id, metric) DO UPDATE SET
                parent_scope_id = excluded.parent_scope_id,
                max_amount = excluded.max_amount,
                period_type = excluded.period_type,
                home_site_id = excluded.home_site_id,
                pool_id = excluded.pool_id",
            params![
                scope_id,
                metric,
                parent,
                max_amount,
                period_type,
                home_site_id,
                pool_id
            ],
        )
        .map_err(|e| e.to_string())?;
        if !pool_id.is_empty() {
            enforce_pool_member_sum(&tx, pool_id, metric)?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    /// Sets the limit every `work_unit:` child of `scope_id` without a limit
    /// of its own gets for `metric` (#1862).
    fn budget_set_work_unit_default(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
        home_site_id: &str,
    ) -> Result<(), String> {
        if max_amount < 0 {
            return Err("budget max_amount must be non-negative".into());
        }
        self.conn()
            .execute(
                "INSERT INTO chisei_budget_work_unit_defaults
                    (scope_id, metric, max_amount, period_type, home_site_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(scope_id, metric) DO UPDATE SET
                    max_amount = excluded.max_amount,
                    period_type = excluded.period_type,
                    home_site_id = excluded.home_site_id",
                params![scope_id, metric, max_amount, period_type, home_site_id],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Removes `scope_id`'s work-unit default for `metric`. Removing an
    /// unset default succeeds.
    fn budget_clear_work_unit_default(&self, scope_id: &str, metric: &str) -> Result<(), String> {
        self.conn()
            .execute(
                "DELETE FROM chisei_budget_work_unit_defaults WHERE scope_id=?1 AND metric=?2",
                params![scope_id, metric],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn budget_set_pool_ceiling(
        &self,
        pool_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        if pool_id.trim().is_empty() {
            return Err("pool_id required".into());
        }
        if max_amount < 0 {
            return Err("pool max_amount must be non-negative".into());
        }
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO chisei_budget_pools (pool_id, metric, max_amount, period_type)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(pool_id, metric) DO UPDATE SET
                max_amount = excluded.max_amount,
                period_type = excluded.period_type",
            params![pool_id, metric, max_amount, period_type],
        )
        .map_err(|e| e.to_string())?;
        enforce_pool_member_sum(&tx, pool_id, metric)?;
        tx.commit().map_err(|e| e.to_string())
    }

    /// Checks every bounded level of `scope_id`'s ancestor chain for headroom
    /// and, if all pass, atomically deducts `amount` at every level (bounded
    /// or not, so a limit added later at an ancestor sees accurate history).
    /// Levels without a limit row are unlimited. An immediate transaction
    /// serializes the whole check-then-write sequence, so concurrent
    /// reservations against a shared ancestor never over-admit.
    fn budget_check_and_reserve_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        self.budget_check_and_reserve_chain_inner(
            scope_id, metric, amount, now_ms, None, false, "", false,
        )
    }

    fn budget_check_and_reserve_chain_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: &str,
    ) -> Result<(), String> {
        self.budget_check_and_reserve_chain_inner(
            scope_id,
            metric,
            amount,
            now_ms,
            Some(idempotency_key),
            false,
            "",
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn budget_check_and_reserve_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: Option<&str>,
        require_home_pin: bool,
        local_site_id: &str,
        partition_simulated: bool,
    ) -> Result<(), String> {
        self.budget_check_and_reserve_chain_inner(
            scope_id,
            metric,
            amount,
            now_ms,
            idempotency_key,
            require_home_pin,
            local_site_id,
            partition_simulated,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn budget_check_and_reserve_chain_inner(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        idempotency_key: Option<&str>,
        require_home_pin: bool,
        local_site_id: &str,
        partition_simulated: bool,
    ) -> Result<(), String> {
        let _ = partition_simulated; // local limits already bound combined ceiling under split
        let chain = scope_chain(scope_id);
        let mut conn = self.conn();
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        if let Some(idempotency_key) = idempotency_key {
            let inserted = transaction
                .execute(
                    "INSERT OR IGNORE INTO chisei_budget_usage_events
                 (idempotency_key, scope_id, metric, amount, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![idempotency_key, scope_id, metric, amount, now_ms],
                )
                .map_err(|error| error.to_string())?;
            if inserted == 0 {
                let stored = transaction.query_row(
                    "SELECT scope_id,metric,amount FROM chisei_budget_usage_events WHERE idempotency_key=?1",
                    params![idempotency_key],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?)),
                ).map_err(|error| error.to_string())?;
                if stored != (scope_id.to_string(), metric.to_string(), amount) {
                    return Err(
                        "idempotency key was already used for different budget reservation".into(),
                    );
                }
                return transaction.commit().map_err(|error| error.to_string());
            }
        }
        for scope in &chain {
            let Some(EffectiveLimit {
                max_amount,
                period_type,
                home_site_id,
                ..
            }) = effective_limit(&transaction, scope, metric)?
            else {
                continue;
            };
            if require_home_pin {
                assert_home_pin(scope, &home_site_id, local_site_id)?;
            }
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
            let period_type = charge_period_type(&transaction, scope, metric)?;
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
            transaction
                .execute(
                    "INSERT INTO chisei_budget_attributions
                   (source_scope_id,applied_scope_id,metric,period_start,amount_used)
                 VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(source_scope_id,applied_scope_id,metric,period_start)
                 DO UPDATE SET amount_used=amount_used+excluded.amount_used",
                    params![scope_id, scope, metric, period_start, amount],
                )
                .map_err(|e| e.to_string())?;
        }
        transaction.commit().map_err(|e| e.to_string())
    }

    /// Read-only variant of [`Self::budget_check_and_reserve_chain`] — checks
    /// headroom at every bounded level without deducting anything.
    fn budget_check_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        self.budget_check_chain_for_site(scope_id, metric, amount, now_ms, false, "", false)
    }

    #[allow(clippy::too_many_arguments)]
    fn budget_check_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
        _partition_simulated: bool,
    ) -> Result<(), String> {
        let chain = scope_chain(scope_id);
        let conn = self.conn();
        for scope in &chain {
            let Some(EffectiveLimit {
                max_amount,
                period_type,
                home_site_id,
                ..
            }) = effective_limit(&conn, scope, metric)?
            else {
                continue;
            };
            if require_home_pin {
                assert_home_pin(scope, &home_site_id, local_site_id)?;
            }
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

    fn budget_assert_home_writable(
        &self,
        scope_id: &str,
        metric: &str,
        local_site_id: &str,
    ) -> Result<(), String> {
        let chain = scope_chain(scope_id);
        let conn = self.conn();
        for scope in &chain {
            if let Some(limit) = effective_limit(&conn, scope, metric)? {
                assert_home_pin(scope, &limit.home_site_id, local_site_id)?;
            }
        }
        Ok(())
    }

    /// Applies `delta` (positive or negative, floored at 0) to every level of
    /// `scope_id`'s ancestor chain — used both for plain usage recording and
    /// for reconciling an earlier reservation to actual usage.
    fn budget_adjust_chain(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        self.budget_adjust_chain_for_site(scope_id, metric, delta, now_ms, false, "")
    }

    fn budget_adjust_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
    ) -> Result<(), String> {
        let chain = scope_chain(scope_id);
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        if require_home_pin && delta > 0 {
            for scope in &chain {
                if let Some(limit) = effective_limit(&tx, scope, metric)? {
                    assert_home_pin(scope, &limit.home_site_id, local_site_id)?;
                }
            }
        }
        adjust_chain_tx(&tx, scope_id, metric, delta, now_ms)?;
        tx.commit().map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    fn budget_transfer_capacity(
        &self,
        transfer_id: &str,
        metric: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        actor: &str,
        now_ms: i64,
    ) -> Result<BudgetTransferRecord, String> {
        if transfer_id.trim().is_empty() {
            return Err("transfer_id required".into());
        }
        if amount <= 0 {
            return Err("transfer amount must be positive".into());
        }
        if from_scope_id == to_scope_id {
            return Err("transfer from_scope and to_scope must differ".into());
        }
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        if let Some(existing) = load_transfer_tx(&tx, transfer_id)? {
            if existing.from_scope_id != from_scope_id
                || existing.to_scope_id != to_scope_id
                || existing.amount != amount
                || existing.metric != metric
            {
                return Err("transfer_id was already used for a different budget transfer".into());
            }
            if existing.status != "completed" {
                return Err(format!(
                    "transfer_id already recorded with status {}",
                    existing.status
                ));
            }
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(existing);
        }

        let from = load_limit_row_tx(&tx, from_scope_id, metric)?
            .ok_or_else(|| format!("from scope limit not found: {from_scope_id}"))?;
        let to = load_limit_row_tx(&tx, to_scope_id, metric)?
            .ok_or_else(|| format!("to scope limit not found: {to_scope_id}"))?;
        if from.pool_id.is_empty() || from.pool_id != to.pool_id {
            return Err(
                "budget transfer requires both scopes to share the same non-empty pool_id".into(),
            );
        }
        let period_start = period_start_ms(&from.period_type, now_ms);
        let used_from: i64 = tx
            .query_row(
                "SELECT amount_used FROM chisei_budget_usage
                 WHERE scope_id=?1 AND metric=?2 AND period_start=?3",
                params![from_scope_id, metric, period_start],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or(0);
        let available = from.max_amount - used_from;
        if amount > available {
            return Err(format!(
                "insufficient transferable capacity at {from_scope_id}: available {available} < {amount}"
            ));
        }
        let new_from = from.max_amount - amount;
        let new_to = to.max_amount + amount;
        tx.execute(
            "UPDATE chisei_budget_limits SET max_amount=?1 WHERE scope_id=?2 AND metric=?3",
            params![new_from, from_scope_id, metric],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE chisei_budget_limits SET max_amount=?1 WHERE scope_id=?2 AND metric=?3",
            params![new_to, to_scope_id, metric],
        )
        .map_err(|e| e.to_string())?;
        enforce_pool_member_sum(&tx, &from.pool_id, metric)?;
        let record = BudgetTransferRecord {
            transfer_id: transfer_id.to_string(),
            metric: metric.to_string(),
            pool_id: from.pool_id.clone(),
            from_scope_id: from_scope_id.to_string(),
            to_scope_id: to_scope_id.to_string(),
            amount,
            actor: actor.to_string(),
            status: "completed".into(),
            reason: String::new(),
            created_at: now_ms,
        };
        insert_transfer_tx(&tx, &record)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn budget_record_transfer_refused(
        &self,
        transfer_id: &str,
        metric: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        actor: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<BudgetTransferRecord, String> {
        if transfer_id.trim().is_empty() {
            return Err("transfer_id required".into());
        }
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        if let Some(existing) = load_transfer_tx(&tx, transfer_id)? {
            tx.commit().map_err(|e| e.to_string())?;
            return Ok(existing);
        }
        let pool_id = load_limit_row_tx(&tx, from_scope_id, metric)?
            .map(|row| row.pool_id)
            .unwrap_or_default();
        let record = BudgetTransferRecord {
            transfer_id: transfer_id.to_string(),
            metric: metric.to_string(),
            pool_id,
            from_scope_id: from_scope_id.to_string(),
            to_scope_id: to_scope_id.to_string(),
            amount,
            actor: actor.to_string(),
            status: "refused".into(),
            reason: reason.to_string(),
            created_at: now_ms,
        };
        insert_transfer_tx(&tx, &record)?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(record)
    }

    fn budget_get_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<Option<BudgetTransferRecord>, String> {
        let conn = self.conn();
        conn.query_row(
            "SELECT transfer_id, metric, pool_id, from_scope_id, to_scope_id, amount,
                    actor, status, reason, created_at
             FROM chisei_budget_transfers WHERE transfer_id=?1",
            params![transfer_id],
            |row| {
                Ok(BudgetTransferRecord {
                    transfer_id: row.get(0)?,
                    metric: row.get(1)?,
                    pool_id: row.get(2)?,
                    from_scope_id: row.get(3)?,
                    to_scope_id: row.get(4)?,
                    amount: row.get(5)?,
                    actor: row.get(6)?,
                    status: row.get(7)?,
                    reason: row.get(8)?,
                    created_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(|e| e.to_string())
    }

    /// Applies a usage delta once for a stable caller-generated key. The event
    /// marker and every scope-chain update commit in one SQLite transaction.
    fn budget_record_idempotent(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.budget_record_idempotent_for_site(
            scope_id,
            metric,
            amount,
            idempotency_key,
            now_ms,
            false,
            "",
        )
    }

    /// [`Self::budget_record_idempotent`] that, when `require_home_pin`,
    /// refuses a positive debit of a scope homed on another site, checked
    /// in the debit's transaction.
    #[allow(clippy::too_many_arguments)]
    fn budget_record_idempotent_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        idempotency_key: &str,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
    ) -> Result<bool, String> {
        if idempotency_key.is_empty() {
            self.budget_adjust_chain_for_site(
                scope_id,
                metric,
                amount,
                now_ms,
                require_home_pin,
                local_site_id,
            )?;
            return Ok(true);
        }
        let chain = scope_chain(scope_id);
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
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
                // Same key, different payload: the caller reused a key rather
                // than retrying. Distinct from a replay and worth alerting on.
                sekai_core::obs::signals::record_deduplication(
                    sekai_core::obs::labels::Subsystem::Chisei,
                    sekai_core::obs::labels::DeduplicationEvent::IdempotencyConflict,
                );
                return Err("idempotency key was already used for different budget usage".into());
            }
            tx.commit().map_err(|e| e.to_string())?;
            // Same key, same payload: a retry that this write correctly
            // suppressed.
            sekai_core::obs::signals::record_deduplication(
                sekai_core::obs::labels::Subsystem::Chisei,
                sekai_core::obs::labels::DeduplicationEvent::IdempotentReplay,
            );
            return Ok(false);
        }
        // Only a new debit is pinned: a replay of a recorded one is
        // acknowledged from any site. A refusal rolls the event back.
        if require_home_pin && amount > 0 {
            for scope in &chain {
                if let Some(limit) = effective_limit(&tx, scope, metric)? {
                    assert_home_pin(scope, &limit.home_site_id, local_site_id)?;
                }
            }
        }
        for scope in &chain {
            let period_type = charge_period_type(&tx, scope, metric)?;
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
    fn budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String> {
        let conn = self.conn();
        let (max_amount, period_type) = effective_limit(&conn, scope_id, metric)?
            .map_or((0, UNLIMITED_PERIOD_TYPE.to_string()), |limit| {
                (limit.max_amount, limit.period_type)
            });
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

    /// Usage of every scope in the chain of `scope_id`, for each metric in
    /// [`BUDGET_METRICS`], read in one transaction so the levels agree.
    fn budget_usage_chain(
        &self,
        scope_id: &str,
        now_ms: i64,
    ) -> Result<Vec<BudgetScopeUsage>, String> {
        let mut conn = self.conn();
        let transaction = conn.transaction().map_err(|e| e.to_string())?;
        let mut levels = Vec::new();
        for scope in scope_chain(scope_id) {
            for metric in BUDGET_METRICS {
                let limit = effective_limit(&transaction, &scope, metric)?;
                let period_type = limit
                    .as_ref()
                    .map_or(UNLIMITED_PERIOD_TYPE, |limit| limit.period_type.as_str())
                    .to_string();
                let period_start = period_start_ms(&period_type, now_ms);
                let used: i64 = transaction
                    .query_row(
                        "SELECT amount_used FROM chisei_budget_usage
                         WHERE scope_id=?1 AND metric=?2 AND period_start=?3",
                        params![scope, metric, period_start],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| e.to_string())?
                    .unwrap_or(0);
                levels.push(BudgetScopeUsage {
                    scope_id: scope.clone(),
                    metric: metric.to_string(),
                    period_type,
                    period_start,
                    used,
                    from_work_unit_default: limit
                        .as_ref()
                        .is_some_and(|limit| limit.from_work_unit_default),
                    limit: limit.map(|limit| limit.max_amount),
                });
            }
        }
        transaction.commit().map_err(|e| e.to_string())?;
        Ok(levels)
    }

    #[cfg(feature = "gateway-test-support")]
    #[doc(hidden)]
    fn gateway_test_budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String> {
        self.budget_usage(scope_id, metric, now_ms)
    }

    /// Worst pressure level among scopes whose id starts with `namespace`
    /// (matches the pre-hierarchy prefix-scan semantics of
    /// `BudgetTracker::namespace_pressure`, now backed by SQL `LIKE`).
    fn budget_namespace_pressure(
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

struct LimitRow {
    max_amount: i64,
    period_type: String,
    #[allow(dead_code)]
    home_site_id: String,
    pool_id: String,
}

fn assert_home_pin(scope: &str, home_site_id: &str, local_site_id: &str) -> Result<(), String> {
    if home_site_id.is_empty() {
        return Ok(());
    }
    if local_site_id.is_empty() {
        return Err(format!(
            "budget scope {scope} is home-pinned to {home_site_id} but local site_id is unset"
        ));
    }
    if home_site_id != local_site_id {
        return Err(format!(
            "budget scope {scope} is pinned to home site {home_site_id}; local site is {local_site_id}"
        ));
    }
    Ok(())
}

fn enforce_pool_member_sum(
    tx: &rusqlite::Transaction<'_>,
    pool_id: &str,
    metric: &str,
) -> Result<(), String> {
    let ceiling: Option<i64> = tx
        .query_row(
            "SELECT max_amount FROM chisei_budget_pools WHERE pool_id=?1 AND metric=?2",
            params![pool_id, metric],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let Some(ceiling) = ceiling else {
        return Ok(());
    };
    let sum: i64 = tx
        .query_row(
            "SELECT COALESCE(SUM(max_amount), 0) FROM chisei_budget_limits
             WHERE pool_id=?1 AND metric=?2",
            params![pool_id, metric],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    if sum > ceiling {
        return Err(format!(
            "pool {pool_id} member limits sum {sum} exceeds combined ceiling {ceiling}"
        ));
    }
    Ok(())
}

fn load_limit_row_tx(
    tx: &rusqlite::Transaction<'_>,
    scope_id: &str,
    metric: &str,
) -> Result<Option<LimitRow>, String> {
    tx.query_row(
        "SELECT max_amount, period_type, home_site_id, pool_id
         FROM chisei_budget_limits WHERE scope_id=?1 AND metric=?2",
        params![scope_id, metric],
        |row| {
            Ok(LimitRow {
                max_amount: row.get(0)?,
                period_type: row.get(1)?,
                home_site_id: row.get(2)?,
                pool_id: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(|e| e.to_string())
}

fn load_transfer_tx(
    tx: &rusqlite::Transaction<'_>,
    transfer_id: &str,
) -> Result<Option<BudgetTransferRecord>, String> {
    tx.query_row(
        "SELECT transfer_id, metric, pool_id, from_scope_id, to_scope_id, amount,
                actor, status, reason, created_at
         FROM chisei_budget_transfers WHERE transfer_id=?1",
        params![transfer_id],
        |row| {
            Ok(BudgetTransferRecord {
                transfer_id: row.get(0)?,
                metric: row.get(1)?,
                pool_id: row.get(2)?,
                from_scope_id: row.get(3)?,
                to_scope_id: row.get(4)?,
                amount: row.get(5)?,
                actor: row.get(6)?,
                status: row.get(7)?,
                reason: row.get(8)?,
                created_at: row.get(9)?,
            })
        },
    )
    .optional()
    .map_err(|e| e.to_string())
}

fn insert_transfer_tx(
    tx: &rusqlite::Transaction<'_>,
    record: &BudgetTransferRecord,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO chisei_budget_transfers
            (transfer_id, metric, pool_id, from_scope_id, to_scope_id, amount,
             actor, status, reason, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            record.transfer_id,
            record.metric,
            record.pool_id,
            record.from_scope_id,
            record.to_scope_id,
            record.amount,
            record.actor,
            record.status,
            record.reason,
            record.created_at,
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Backend-neutral budget persistence used by dual-backend conformance.
/// Nested so its method names do not collide with [`BudgetSekaiDbExt`].
pub mod backend {
    use super::BudgetScopeUsage;
    use super::BudgetSekaiDbExt;
    use crate::chisei_store::postgres_budget::BudgetPostgresDbExt;
    use sekai_core::db::sekai::SekaiDb;

    pub trait ChiseiBudgetBackend: Send + Sync {
        fn budget_set_limit(
            &self,
            scope_id: &str,
            metric: &str,
            max_amount: i64,
            period_type: &str,
        ) -> Result<(), String>;
        fn budget_set_work_unit_default(
            &self,
            scope_id: &str,
            metric: &str,
            max_amount: i64,
            period_type: &str,
            home_site_id: &str,
        ) -> Result<(), String>;
        fn budget_clear_work_unit_default(
            &self,
            scope_id: &str,
            metric: &str,
        ) -> Result<(), String>;
        fn budget_check_and_reserve_chain(
            &self,
            scope_id: &str,
            metric: &str,
            amount: i64,
            now_ms: i64,
        ) -> Result<(), String>;
        fn budget_check_and_reserve_chain_idempotent(
            &self,
            scope_id: &str,
            metric: &str,
            amount: i64,
            now_ms: i64,
            idempotency_key: &str,
        ) -> Result<(), String>;
        fn budget_usage(
            &self,
            scope_id: &str,
            metric: &str,
            now_ms: i64,
        ) -> Result<(i64, i64, String), String>;
        fn budget_record_idempotent(
            &self,
            scope_id: &str,
            metric: &str,
            amount: i64,
            idempotency_key: &str,
            now_ms: i64,
        ) -> Result<bool, String>;
        #[allow(clippy::too_many_arguments)]
        fn budget_record_idempotent_for_site(
            &self,
            scope_id: &str,
            metric: &str,
            amount: i64,
            idempotency_key: &str,
            now_ms: i64,
            require_home_pin: bool,
            local_site_id: &str,
        ) -> Result<bool, String>;
        fn budget_limits_for_scope(
            &self,
            scope_id: &str,
        ) -> Result<Vec<(String, String, i64, String)>, String>;
        fn budget_usage_chain(
            &self,
            scope_id: &str,
            now_ms: i64,
        ) -> Result<Vec<BudgetScopeUsage>, String>;
    }

    macro_rules! forward_budget {
        ($ext:ident) => {
            fn budget_set_limit(
                &self,
                scope_id: &str,
                metric: &str,
                max_amount: i64,
                period_type: &str,
            ) -> Result<(), String> {
                $ext::budget_set_limit(self, scope_id, metric, max_amount, period_type)
            }
            fn budget_set_work_unit_default(
                &self,
                scope_id: &str,
                metric: &str,
                max_amount: i64,
                period_type: &str,
                home_site_id: &str,
            ) -> Result<(), String> {
                $ext::budget_set_work_unit_default(
                    self,
                    scope_id,
                    metric,
                    max_amount,
                    period_type,
                    home_site_id,
                )
            }
            fn budget_clear_work_unit_default(
                &self,
                scope_id: &str,
                metric: &str,
            ) -> Result<(), String> {
                $ext::budget_clear_work_unit_default(self, scope_id, metric)
            }
            fn budget_check_and_reserve_chain(
                &self,
                scope_id: &str,
                metric: &str,
                amount: i64,
                now_ms: i64,
            ) -> Result<(), String> {
                $ext::budget_check_and_reserve_chain(self, scope_id, metric, amount, now_ms)
            }
            fn budget_check_and_reserve_chain_idempotent(
                &self,
                scope_id: &str,
                metric: &str,
                amount: i64,
                now_ms: i64,
                idempotency_key: &str,
            ) -> Result<(), String> {
                $ext::budget_check_and_reserve_chain_idempotent(
                    self,
                    scope_id,
                    metric,
                    amount,
                    now_ms,
                    idempotency_key,
                )
            }
            fn budget_usage(
                &self,
                scope_id: &str,
                metric: &str,
                now_ms: i64,
            ) -> Result<(i64, i64, String), String> {
                $ext::budget_usage(self, scope_id, metric, now_ms)
            }
            fn budget_record_idempotent(
                &self,
                scope_id: &str,
                metric: &str,
                amount: i64,
                idempotency_key: &str,
                now_ms: i64,
            ) -> Result<bool, String> {
                $ext::budget_record_idempotent(
                    self,
                    scope_id,
                    metric,
                    amount,
                    idempotency_key,
                    now_ms,
                )
            }
            fn budget_record_idempotent_for_site(
                &self,
                scope_id: &str,
                metric: &str,
                amount: i64,
                idempotency_key: &str,
                now_ms: i64,
                require_home_pin: bool,
                local_site_id: &str,
            ) -> Result<bool, String> {
                $ext::budget_record_idempotent_for_site(
                    self,
                    scope_id,
                    metric,
                    amount,
                    idempotency_key,
                    now_ms,
                    require_home_pin,
                    local_site_id,
                )
            }
            fn budget_limits_for_scope(
                &self,
                scope_id: &str,
            ) -> Result<Vec<(String, String, i64, String)>, String> {
                $ext::budget_limits_for_scope(self, scope_id)
            }
            fn budget_usage_chain(
                &self,
                scope_id: &str,
                now_ms: i64,
            ) -> Result<Vec<BudgetScopeUsage>, String> {
                $ext::budget_usage_chain(self, scope_id, now_ms)
            }
        };
    }

    impl ChiseiBudgetBackend for SekaiDb {
        forward_budget!(BudgetSekaiDbExt);
    }
    impl ChiseiBudgetBackend for sekai_core::db::postgres::PostgresDb {
        forward_budget!(BudgetPostgresDbExt);
    }
}

/// Add `delta` to `scope_id` and every ancestor's usage and attribution, in
/// the caller's write transaction, so a caller can pair it atomically with
/// another write, such as releasing a reservation (#1902).
pub fn adjust_chain_tx(
    tx: &rusqlite::Transaction<'_>,
    scope_id: &str,
    metric: &str,
    delta: i64,
    now_ms: i64,
) -> Result<(), String> {
    let chain = scope_chain(scope_id);
    for scope in &chain {
        let period_type = charge_period_type(tx, scope, metric)?;
        let period_start = period_start_ms(&period_type, now_ms);
        // Relative update under Immediate txn (mirrors Postgres) so concurrent
        // adjust/complete paths cannot lose usage via read-modify-write.
        tx.execute(
            "INSERT INTO chisei_budget_usage (scope_id, metric, period_start, amount_used)
             VALUES (?1, ?2, ?3, MAX(0, ?4))
             ON CONFLICT(scope_id, metric, period_start) DO UPDATE SET
                amount_used = MAX(0, amount_used + ?4)",
            params![scope, metric, period_start, delta],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO chisei_budget_attributions
               (source_scope_id,applied_scope_id,metric,period_start,amount_used)
             VALUES (?1,?2,?3,?4,MAX(0,?5))
             ON CONFLICT(source_scope_id,applied_scope_id,metric,period_start)
             DO UPDATE SET amount_used=MAX(0,amount_used+?5)",
            params![scope_id, scope, metric, period_start, delta],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sekai_core::db::chisei_budget::METRIC_TOKENS;
    use std::sync::{Arc, Barrier};

    #[test]
    fn concurrent_reservations_do_not_exceed_shared_limit() {
        let path = std::env::temp_dir().join(format!("sekai-budget-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(crate::chisei_store::open_sekai_with_chisei_schema(
            path.to_str().unwrap(),
        ));
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
