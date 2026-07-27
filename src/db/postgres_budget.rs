use crate::db::chisei_budget::{
    BudgetTransferRecord, parent_scope_id, period_start_ms, scope_chain,
};
use crate::db::postgres::PostgresDb;

impl PostgresDb {
    pub fn budget_set_limit(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        self.budget_set_limit_scoped(scope_id, metric, max_amount, period_type, "", "")
    }

    pub fn budget_set_limit_scoped(
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
        let parent = parent_scope_id(scope_id);
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO chisei_budget_limits
                (scope_id, metric, parent_scope_id, max_amount, period_type, home_site_id, pool_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(scope_id, metric) DO UPDATE SET
                parent_scope_id = excluded.parent_scope_id,
                max_amount = excluded.max_amount,
                period_type = excluded.period_type,
                home_site_id = excluded.home_site_id,
                pool_id = excluded.pool_id",
            &[
                &scope_id,
                &metric,
                &parent,
                &max_amount,
                &period_type,
                &home_site_id,
                &pool_id,
            ],
        )
        .map_err(|error| error.to_string())?;
        if !pool_id.is_empty() {
            pg_enforce_pool_member_sum(&mut tx, pool_id, metric)?;
        }
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn budget_set_pool_ceiling(
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT INTO chisei_budget_pools (pool_id, metric, max_amount, period_type)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT(pool_id, metric) DO UPDATE SET
                max_amount = excluded.max_amount,
                period_type = excluded.period_type",
            &[&pool_id, &metric, &max_amount, &period_type],
        )
        .map_err(|error| error.to_string())?;
        pg_enforce_pool_member_sum(&mut tx, pool_id, metric)?;
        tx.commit().map_err(|error| error.to_string())
    }

    pub fn budget_check_and_reserve_chain(
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

    pub fn budget_check_and_reserve_chain_idempotent(
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
    pub fn budget_check_and_reserve_chain_for_site(
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
        let _ = partition_simulated;
        let chain = scope_chain(scope_id);
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;

        // Every reservation locks the same root-to-leaf keys in the same order.
        // Overlapping hierarchies therefore serialize without deadlocking and
        // cannot each spend the same shared-ancestor headroom.
        for scope in &chain {
            let key = budget_lock_key(metric, scope);
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    &[&key],
                )
                .map_err(|error| format!("lock budget scope {scope}: {error}"))?;
        }

        if let Some(idempotency_key) = idempotency_key {
            let inserted = transaction
                .execute(
                    "INSERT INTO chisei_budget_usage_events
                        (idempotency_key, scope_id, metric, amount, created_at)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT DO NOTHING",
                    &[&idempotency_key, &scope_id, &metric, &amount, &now_ms],
                )
                .map_err(|error| error.to_string())?;
            if inserted == 0 {
                let stored = transaction
                    .query_one(
                        "SELECT scope_id, metric, amount FROM chisei_budget_usage_events
                         WHERE idempotency_key = $1",
                        &[&idempotency_key],
                    )
                    .map_err(|error| error.to_string())?;
                let stored = (
                    stored.get::<_, String>(0),
                    stored.get::<_, String>(1),
                    stored.get::<_, i64>(2),
                );
                if stored != (scope_id.to_string(), metric.to_string(), amount) {
                    return Err(
                        "idempotency key was already used for different budget reservation".into(),
                    );
                }
                return transaction.commit().map_err(|error| error.to_string());
            }
        }

        for scope in &chain {
            let limit = transaction
                .query_opt(
                    "SELECT max_amount, period_type, home_site_id
                     FROM chisei_budget_limits
                     WHERE scope_id = $1 AND metric = $2",
                    &[&scope, &metric],
                )
                .map_err(|error| error.to_string())?;
            let Some(limit) = limit else { continue };
            let max_amount: i64 = limit.get(0);
            let period_type: String = limit.get(1);
            let home_site_id: String = limit.get(2);
            if require_home_pin {
                pg_assert_home_pin(scope, &home_site_id, local_site_id)?;
            }
            let period_start = period_start_ms(&period_type, now_ms);
            let used = transaction
                .query_opt(
                    "SELECT amount_used FROM chisei_budget_usage
                     WHERE scope_id = $1 AND metric = $2 AND period_start = $3",
                    &[&scope, &metric, &period_start],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, i64>(0))
                .unwrap_or(0);
            if used + amount > max_amount {
                return Err(format!(
                    "budget exceeded at {scope}: used {used} + {amount} > {max_amount}"
                ));
            }
        }

        for scope in &chain {
            let period_type = transaction
                .query_opt(
                    "SELECT period_type FROM chisei_budget_limits
                     WHERE scope_id = $1 AND metric = $2",
                    &[&scope, &metric],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, String>(0))
                .unwrap_or_else(|| "daily".to_string());
            let period_start = period_start_ms(&period_type, now_ms);
            transaction
                .execute(
                    "INSERT INTO chisei_budget_usage
                        (scope_id, metric, period_start, amount_used)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT(scope_id, metric, period_start) DO UPDATE SET
                        amount_used = chisei_budget_usage.amount_used + excluded.amount_used",
                    &[&scope, &metric, &period_start, &amount],
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO chisei_budget_attributions
                        (source_scope_id, applied_scope_id, metric, period_start, amount_used)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (source_scope_id, applied_scope_id, metric, period_start)
                     DO UPDATE SET
                        amount_used = chisei_budget_attributions.amount_used
                            + EXCLUDED.amount_used",
                    &[&scope_id, &scope, &metric, &period_start, &amount],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn budget_check_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        self.budget_check_chain_for_site(scope_id, metric, amount, now_ms, false, "", false)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_check_chain_for_site(
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
        let mut connection = self.connection()?;
        for scope in chain {
            let limit = connection
                .query_opt(
                    "SELECT max_amount, period_type, home_site_id FROM chisei_budget_limits
                     WHERE scope_id = $1 AND metric = $2",
                    &[&scope, &metric],
                )
                .map_err(|error| error.to_string())?;
            let Some(limit) = limit else { continue };
            let max_amount: i64 = limit.get(0);
            let period_type: String = limit.get(1);
            let home_site_id: String = limit.get(2);
            if require_home_pin {
                pg_assert_home_pin(&scope, &home_site_id, local_site_id)?;
            }
            let period_start = period_start_ms(&period_type, now_ms);
            let used = connection
                .query_opt(
                    "SELECT amount_used FROM chisei_budget_usage
                     WHERE scope_id = $1 AND metric = $2 AND period_start = $3",
                    &[&scope, &metric, &period_start],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, i64>(0))
                .unwrap_or(0);
            if used + amount > max_amount {
                return Err(format!(
                    "budget exceeded at {scope}: used {used} + {amount} > {max_amount}"
                ));
            }
        }
        Ok(())
    }

    pub fn budget_assert_home_writable(
        &self,
        scope_id: &str,
        metric: &str,
        local_site_id: &str,
    ) -> Result<(), String> {
        let chain = scope_chain(scope_id);
        let mut connection = self.connection()?;
        for scope in chain {
            let home = connection
                .query_opt(
                    "SELECT home_site_id FROM chisei_budget_limits
                     WHERE scope_id = $1 AND metric = $2",
                    &[&scope, &metric],
                )
                .map_err(|error| error.to_string())?;
            if let Some(row) = home {
                let home_site_id: String = row.get(0);
                pg_assert_home_pin(&scope, &home_site_id, local_site_id)?;
            }
        }
        Ok(())
    }

    pub fn budget_adjust_chain_for_site(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
        require_home_pin: bool,
        local_site_id: &str,
    ) -> Result<(), String> {
        if require_home_pin && delta > 0 {
            self.budget_assert_home_writable(scope_id, metric, local_site_id)?;
        }
        self.budget_adjust_chain(scope_id, metric, delta, now_ms)
    }

    pub fn budget_adjust_chain(
        &self,
        scope_id: &str,
        metric: &str,
        delta: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        let chain = scope_chain(scope_id);
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for scope in &chain {
            let key = budget_lock_key(metric, scope);
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    &[&key],
                )
                .map_err(|error| format!("lock budget scope {scope}: {error}"))?;
        }
        for scope in &chain {
            let period_type = transaction
                .query_opt(
                    "SELECT period_type FROM chisei_budget_limits
                     WHERE scope_id = $1 AND metric = $2",
                    &[&scope, &metric],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, String>(0))
                .unwrap_or_else(|| "daily".to_string());
            let period_start = period_start_ms(&period_type, now_ms);
            transaction
                .execute(
                    "INSERT INTO chisei_budget_usage
                        (scope_id, metric, period_start, amount_used)
                     VALUES ($1, $2, $3, GREATEST($4, 0))
                     ON CONFLICT(scope_id, metric, period_start) DO UPDATE SET
                        amount_used = GREATEST(chisei_budget_usage.amount_used + $4, 0)",
                    &[&scope, &metric, &period_start, &delta],
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO chisei_budget_attributions
                        (source_scope_id, applied_scope_id, metric, period_start, amount_used)
                     VALUES ($1, $2, $3, $4, GREATEST($5, 0))
                     ON CONFLICT (source_scope_id, applied_scope_id, metric, period_start)
                     DO UPDATE SET
                        amount_used = GREATEST(
                            chisei_budget_attributions.amount_used + $5, 0
                        )",
                    &[&scope_id, &scope, &metric, &period_start, &delta],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())
    }

    /// Applies a usage delta once for a stable caller-generated key.
    pub fn budget_record_idempotent(
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
        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for scope in &chain {
            let key = budget_lock_key(metric, scope);
            transaction
                .query_one(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    &[&key],
                )
                .map_err(|error| format!("lock budget scope {scope}: {error}"))?;
        }
        let inserted = transaction
            .execute(
                "INSERT INTO chisei_budget_usage_events
                    (idempotency_key, scope_id, metric, amount, created_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT DO NOTHING",
                &[&idempotency_key, &scope_id, &metric, &amount, &now_ms],
            )
            .map_err(|error| error.to_string())?;
        if inserted == 0 {
            let stored = transaction
                .query_one(
                    "SELECT scope_id, metric, amount FROM chisei_budget_usage_events
                     WHERE idempotency_key = $1",
                    &[&idempotency_key],
                )
                .map_err(|error| error.to_string())?;
            let stored = (
                stored.get::<_, String>(0),
                stored.get::<_, String>(1),
                stored.get::<_, i64>(2),
            );
            if stored != (scope_id.to_string(), metric.to_string(), amount) {
                crate::obs::signals::record_deduplication(
                    crate::obs::labels::Subsystem::Chisei,
                    crate::obs::labels::DeduplicationEvent::IdempotencyConflict,
                );
                return Err("idempotency key was already used for different budget usage".into());
            }
            transaction.commit().map_err(|error| error.to_string())?;
            crate::obs::signals::record_deduplication(
                crate::obs::labels::Subsystem::Chisei,
                crate::obs::labels::DeduplicationEvent::IdempotentReplay,
            );
            return Ok(false);
        }
        for scope in &chain {
            let period_type = transaction
                .query_opt(
                    "SELECT period_type FROM chisei_budget_limits
                     WHERE scope_id = $1 AND metric = $2",
                    &[&scope, &metric],
                )
                .map_err(|error| error.to_string())?
                .map(|row| row.get::<_, String>(0))
                .unwrap_or_else(|| "daily".to_string());
            let period_start = period_start_ms(&period_type, now_ms);
            transaction
                .execute(
                    "INSERT INTO chisei_budget_usage
                        (scope_id, metric, period_start, amount_used)
                     VALUES ($1, $2, $3, GREATEST($4, 0))
                     ON CONFLICT(scope_id, metric, period_start) DO UPDATE SET
                        amount_used = GREATEST(chisei_budget_usage.amount_used + $4, 0)",
                    &[&scope, &metric, &period_start, &amount],
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "INSERT INTO chisei_budget_attributions
                        (source_scope_id, applied_scope_id, metric, period_start, amount_used)
                     VALUES ($1, $2, $3, $4, GREATEST($5, 0))
                     ON CONFLICT (source_scope_id, applied_scope_id, metric, period_start)
                     DO UPDATE SET
                        amount_used = GREATEST(
                            chisei_budget_attributions.amount_used + $5, 0
                        )",
                    &[&scope_id, &scope, &metric, &period_start, &amount],
                )
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn budget_usage(
        &self,
        scope_id: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<(i64, i64, String), String> {
        let mut connection = self.connection()?;
        let limit = connection
            .query_opt(
                "SELECT max_amount, period_type FROM chisei_budget_limits
                 WHERE scope_id = $1 AND metric = $2",
                &[&scope_id, &metric],
            )
            .map_err(|error| error.to_string())?;
        let (max_amount, period_type) = limit
            .map(|row| (row.get(0), row.get(1)))
            .unwrap_or((0_i64, "daily".to_string()));
        let period_start = period_start_ms(&period_type, now_ms);
        let used = connection
            .query_opt(
                "SELECT amount_used FROM chisei_budget_usage
                 WHERE scope_id = $1 AND metric = $2 AND period_start = $3",
                &[&scope_id, &metric, &period_start],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get(0))
            .unwrap_or(0_i64);
        Ok((used, max_amount, period_type))
    }

    pub fn budget_namespace_pressure(
        &self,
        namespace: &str,
        metric: &str,
        now_ms: i64,
    ) -> Result<i32, String> {
        if namespace.is_empty() {
            return Ok(0);
        }
        let mut connection = self.connection()?;
        let pattern = format!("{namespace}%");
        let rows = connection
            .query(
                "SELECT limits.scope_id, limits.max_amount, limits.period_type,
                        COALESCE(usage.amount_used, 0)
                 FROM chisei_budget_limits AS limits
                 LEFT JOIN chisei_budget_usage AS usage
                   ON usage.scope_id = limits.scope_id
                  AND usage.metric = limits.metric
                  AND usage.period_start = CASE limits.period_type
                    WHEN 'weekly' THEN $3
                    WHEN 'monthly' THEN $4
                    ELSE $5
                  END
                 WHERE limits.metric = $1 AND limits.scope_id LIKE $2",
                &[
                    &metric,
                    &pattern,
                    &period_start_ms("weekly", now_ms),
                    &period_start_ms("monthly", now_ms),
                    &period_start_ms("daily", now_ms),
                ],
            )
            .map_err(|error| error.to_string())?;
        let mut worst = 0;
        for row in rows {
            let max_amount: i64 = row.get(1);
            if max_amount <= 0 {
                continue;
            }
            let used: i64 = row.get(3);
            let percentage = used * 100 / max_amount;
            worst = worst.max(if percentage >= 90 {
                2
            } else if percentage >= 70 {
                1
            } else {
                0
            });
        }
        Ok(worst)
    }
}

fn budget_lock_key(metric: &str, scope: &str) -> String {
    format!("budget:{}:{metric}:{}:{scope}", metric.len(), scope.len())
}

fn pg_assert_home_pin(scope: &str, home_site_id: &str, local_site_id: &str) -> Result<(), String> {
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

fn pg_enforce_pool_member_sum(
    tx: &mut postgres::Transaction<'_>,
    pool_id: &str,
    metric: &str,
) -> Result<(), String> {
    let ceiling = tx
        .query_opt(
            "SELECT max_amount FROM chisei_budget_pools WHERE pool_id = $1 AND metric = $2",
            &[&pool_id, &metric],
        )
        .map_err(|error| error.to_string())?;
    let Some(ceiling) = ceiling else {
        return Ok(());
    };
    let ceiling: i64 = ceiling.get(0);
    let sum: i64 = tx
        .query_one(
            "SELECT COALESCE(SUM(max_amount), 0) FROM chisei_budget_limits
             WHERE pool_id = $1 AND metric = $2",
            &[&pool_id, &metric],
        )
        .map_err(|error| error.to_string())?
        .get(0);
    if sum > ceiling {
        return Err(format!(
            "pool {pool_id} member limits sum {sum} exceeds combined ceiling {ceiling}"
        ));
    }
    Ok(())
}

impl PostgresDb {
    #[allow(clippy::too_many_arguments)]
    pub fn budget_transfer_capacity(
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        for scope in [from_scope_id, to_scope_id] {
            let key = budget_lock_key(metric, scope);
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&key],
            )
            .map_err(|error| format!("lock budget scope {scope}: {error}"))?;
        }
        if let Some(existing) = pg_load_transfer(&mut tx, transfer_id)? {
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
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(existing);
        }
        let from = tx
            .query_opt(
                "SELECT max_amount, period_type, pool_id FROM chisei_budget_limits
                 WHERE scope_id = $1 AND metric = $2",
                &[&from_scope_id, &metric],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("from scope limit not found: {from_scope_id}"))?;
        let to = tx
            .query_opt(
                "SELECT max_amount, period_type, pool_id FROM chisei_budget_limits
                 WHERE scope_id = $1 AND metric = $2",
                &[&to_scope_id, &metric],
            )
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("to scope limit not found: {to_scope_id}"))?;
        let from_max: i64 = from.get(0);
        let from_period: String = from.get(1);
        let from_pool: String = from.get(2);
        let to_max: i64 = to.get(0);
        let to_pool: String = to.get(2);
        if from_pool.is_empty() || from_pool != to_pool {
            return Err(
                "budget transfer requires both scopes to share the same non-empty pool_id".into(),
            );
        }
        let period_start = period_start_ms(&from_period, now_ms);
        let used_from = tx
            .query_opt(
                "SELECT amount_used FROM chisei_budget_usage
                 WHERE scope_id = $1 AND metric = $2 AND period_start = $3",
                &[&from_scope_id, &metric, &period_start],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, i64>(0))
            .unwrap_or(0);
        let available = from_max - used_from;
        if amount > available {
            return Err(format!(
                "insufficient transferable capacity at {from_scope_id}: available {available} < {amount}"
            ));
        }
        let new_from = from_max - amount;
        let new_to = to_max + amount;
        tx.execute(
            "UPDATE chisei_budget_limits SET max_amount = $1 WHERE scope_id = $2 AND metric = $3",
            &[&new_from, &from_scope_id, &metric],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "UPDATE chisei_budget_limits SET max_amount = $1 WHERE scope_id = $2 AND metric = $3",
            &[&new_to, &to_scope_id, &metric],
        )
        .map_err(|error| error.to_string())?;
        pg_enforce_pool_member_sum(&mut tx, &from_pool, metric)?;
        let record = BudgetTransferRecord {
            transfer_id: transfer_id.to_string(),
            metric: metric.to_string(),
            pool_id: from_pool,
            from_scope_id: from_scope_id.to_string(),
            to_scope_id: to_scope_id.to_string(),
            amount,
            actor: actor.to_string(),
            status: "completed".into(),
            reason: String::new(),
            created_at: now_ms,
        };
        pg_insert_transfer(&mut tx, &record)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn budget_record_transfer_refused(
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
        let mut connection = self.connection()?;
        let mut tx = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if let Some(existing) = pg_load_transfer(&mut tx, transfer_id)? {
            tx.commit().map_err(|error| error.to_string())?;
            return Ok(existing);
        }
        let pool_id = tx
            .query_opt(
                "SELECT pool_id FROM chisei_budget_limits WHERE scope_id = $1 AND metric = $2",
                &[&from_scope_id, &metric],
            )
            .map_err(|error| error.to_string())?
            .map(|row| row.get::<_, String>(0))
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
        pg_insert_transfer(&mut tx, &record)?;
        tx.commit().map_err(|error| error.to_string())?;
        Ok(record)
    }

    pub fn budget_get_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<Option<BudgetTransferRecord>, String> {
        let mut connection = self.connection()?;
        connection
            .query_opt(
                "SELECT transfer_id, metric, pool_id, from_scope_id, to_scope_id, amount,
                        actor, status, reason, created_at
                 FROM chisei_budget_transfers WHERE transfer_id = $1",
                &[&transfer_id],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                Ok(BudgetTransferRecord {
                    transfer_id: row.get(0),
                    metric: row.get(1),
                    pool_id: row.get(2),
                    from_scope_id: row.get(3),
                    to_scope_id: row.get(4),
                    amount: row.get(5),
                    actor: row.get(6),
                    status: row.get(7),
                    reason: row.get(8),
                    created_at: row.get(9),
                })
            })
            .transpose()
    }
}

fn pg_load_transfer(
    tx: &mut postgres::Transaction<'_>,
    transfer_id: &str,
) -> Result<Option<BudgetTransferRecord>, String> {
    tx.query_opt(
        "SELECT transfer_id, metric, pool_id, from_scope_id, to_scope_id, amount,
                actor, status, reason, created_at
         FROM chisei_budget_transfers WHERE transfer_id = $1",
        &[&transfer_id],
    )
    .map_err(|error| error.to_string())?
    .map(|row| {
        Ok(BudgetTransferRecord {
            transfer_id: row.get(0),
            metric: row.get(1),
            pool_id: row.get(2),
            from_scope_id: row.get(3),
            to_scope_id: row.get(4),
            amount: row.get(5),
            actor: row.get(6),
            status: row.get(7),
            reason: row.get(8),
            created_at: row.get(9),
        })
    })
    .transpose()
}

fn pg_insert_transfer(
    tx: &mut postgres::Transaction<'_>,
    record: &BudgetTransferRecord,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO chisei_budget_transfers
            (transfer_id, metric, pool_id, from_scope_id, to_scope_id, amount,
             actor, status, reason, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        &[
            &record.transfer_id,
            &record.metric,
            &record.pool_id,
            &record.from_scope_id,
            &record.to_scope_id,
            &record.amount,
            &record.actor,
            &record.status,
            &record.reason,
            &record.created_at,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_lock_keys_are_nul_free_and_unambiguous() {
        let first = budget_lock_key("tokens:a", "b");
        let second = budget_lock_key("tokens", "a:b");
        assert_ne!(first, second);
        assert!(!first.as_bytes().contains(&0));
        assert!(!second.as_bytes().contains(&0));
    }
}
