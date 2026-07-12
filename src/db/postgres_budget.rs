use crate::db::chisei_budget::{parent_scope_id, period_start_ms, scope_chain};
use crate::db::postgres::PostgresDb;

impl PostgresDb {
    pub fn budget_set_limit(
        &self,
        scope_id: &str,
        metric: &str,
        max_amount: i64,
        period_type: &str,
    ) -> Result<(), String> {
        let parent = parent_scope_id(scope_id);
        self.connection()?
            .execute(
                "INSERT INTO chisei_budget_limits
                    (scope_id, metric, parent_scope_id, max_amount, period_type)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT(scope_id, metric) DO UPDATE SET
                    parent_scope_id = excluded.parent_scope_id,
                    max_amount = excluded.max_amount,
                    period_type = excluded.period_type",
                &[&scope_id, &metric, &parent, &max_amount, &period_type],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn budget_check_and_reserve_chain(
        &self,
        scope_id: &str,
        metric: &str,
        amount: i64,
        now_ms: i64,
    ) -> Result<(), String> {
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

        for scope in &chain {
            let limit = transaction
                .query_opt(
                    "SELECT max_amount, period_type FROM chisei_budget_limits
                     WHERE scope_id = $1 AND metric = $2",
                    &[&scope, &metric],
                )
                .map_err(|error| error.to_string())?;
            let Some(limit) = limit else { continue };
            let max_amount: i64 = limit.get(0);
            let period_type: String = limit.get(1);
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
        let chain = scope_chain(scope_id);
        let mut connection = self.connection()?;
        for scope in chain {
            let limit = connection
                .query_opt(
                    "SELECT max_amount, period_type FROM chisei_budget_limits
                     WHERE scope_id = $1 AND metric = $2",
                    &[&scope, &metric],
                )
                .map_err(|error| error.to_string())?;
            let Some(limit) = limit else { continue };
            let max_amount: i64 = limit.get(0);
            let period_type: String = limit.get(1);
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
        }
        transaction.commit().map_err(|error| error.to_string())
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
