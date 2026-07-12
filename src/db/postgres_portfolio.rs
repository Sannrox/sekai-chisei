use crate::chisei::portfolio::{
    FrontierPoint, Objective, ObjectiveMode, Observation, RouteSelection,
};
use crate::db::postgres::PostgresDb;

impl PostgresDb {
    pub fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String> {
        self.connection()?
            .execute(
                "INSERT INTO chisei_portfolio_observations
                    (namespace, task_class, model, quality_score, cost_usd_micros,
                     sample_count, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT(namespace, task_class, model) DO UPDATE SET
                    quality_score =
                        ((chisei_portfolio_observations.quality_score * chisei_portfolio_observations.sample_count)
                         + (excluded.quality_score * excluded.sample_count))
                        / (chisei_portfolio_observations.sample_count + excluded.sample_count),
                    cost_usd_micros = CAST(trunc(
                        ((chisei_portfolio_observations.cost_usd_micros::numeric * chisei_portfolio_observations.sample_count)
                         + (excluded.cost_usd_micros::numeric * excluded.sample_count))
                        / (chisei_portfolio_observations.sample_count + excluded.sample_count)
                        ) AS BIGINT),
                    sample_count = chisei_portfolio_observations.sample_count + excluded.sample_count,
                    updated_at = GREATEST(chisei_portfolio_observations.updated_at, excluded.updated_at)",
                &[
                    &observation.namespace,
                    &observation.task_class,
                    &observation.model,
                    &observation.quality_score,
                    &observation.cost_usd_micros,
                    &observation.sample_count,
                    &observation.updated_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn portfolio_points(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String> {
        self.connection()?
            .query(
                "SELECT model, quality_score, cost_usd_micros, sample_count, updated_at
                 FROM chisei_portfolio_observations
                 WHERE namespace = $1 AND task_class = $2
                 ORDER BY cost_usd_micros, quality_score DESC, model",
                &[&namespace, &task_class],
            )
            .map(|rows| {
                rows.into_iter()
                    .map(|row| FrontierPoint {
                        model: row.get(0),
                        quality_score: row.get(1),
                        cost_usd_micros: row.get(2),
                        sample_count: row.get(3),
                        updated_at: row.get(4),
                    })
                    .collect()
            })
            .map_err(|error| error.to_string())
    }

    pub fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String> {
        let namespace = objective.namespace.trim();
        self.connection()?
            .execute(
                "INSERT INTO chisei_portfolio_objectives
                    (namespace, mode, budget_usd_micros, quality_bar, min_samples, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT(namespace) DO UPDATE SET
                    mode = excluded.mode,
                    budget_usd_micros = excluded.budget_usd_micros,
                    quality_bar = excluded.quality_bar,
                    min_samples = excluded.min_samples,
                    updated_at = excluded.updated_at",
                &[
                    &namespace,
                    &objective.mode.as_str(),
                    &objective.budget_usd_micros,
                    &objective.quality_bar,
                    &objective.min_samples,
                    &objective.updated_at,
                ],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    pub fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
        self.connection()?
            .query_opt(
                "SELECT namespace, mode, budget_usd_micros, quality_bar, min_samples, updated_at
                 FROM chisei_portfolio_objectives WHERE namespace = $1",
                &[&namespace],
            )
            .map_err(|error| error.to_string())?
            .map(|row| {
                let mode: String = row.get(1);
                Ok(Objective {
                    namespace: row.get(0),
                    mode: ObjectiveMode::parse(&mode)?,
                    budget_usd_micros: row.get(2),
                    quality_bar: row.get(3),
                    min_samples: row.get(4),
                    updated_at: row.get(5),
                })
            })
            .transpose()
    }

    pub fn portfolio_damped_route(
        &self,
        namespace: &str,
        task_class: &str,
        proposed_model: &str,
        now_ms: i64,
        force: bool,
    ) -> Result<RouteSelection, String> {
        const CONFIRMATIONS: i64 = 3;
        const COOLDOWN_MS: i64 = 15 * 60 * 1000;

        let mut connection = self.connection()?;
        let mut transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let lock_key = route_lock_key(namespace, task_class);
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock_key],
            )
            .map_err(|error| format!("lock portfolio route: {error}"))?;
        let state = transaction
            .query_opt(
                "SELECT current_model, pending_model, pending_count, shifted_at
                 FROM chisei_portfolio_routes WHERE namespace = $1 AND task_class = $2",
                &[&namespace, &task_class],
            )
            .map_err(|error| error.to_string())?;
        let Some(state) = state else {
            transaction
                .execute(
                    "INSERT INTO chisei_portfolio_routes
                        (namespace, task_class, current_model, pending_model,
                         pending_count, shifted_at, updated_at)
                     VALUES ($1, $2, $3, '', 0, $4, $4)",
                    &[&namespace, &task_class, &proposed_model, &now_ms],
                )
                .map_err(|error| error.to_string())?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(RouteSelection {
                model: proposed_model.to_string(),
                previous_model: String::new(),
                shifted: !force,
                reason: if force {
                    "initialized on regression-safe model".into()
                } else {
                    "initial allocation".into()
                },
            });
        };
        let current: String = state.get(0);
        let pending: String = state.get(1);
        let pending_count: i64 = state.get(2);
        let shifted_at: i64 = state.get(3);

        if current == proposed_model {
            transaction
                .execute(
                    "UPDATE chisei_portfolio_routes
                     SET pending_model = '', pending_count = 0, updated_at = $3
                     WHERE namespace = $1 AND task_class = $2",
                    &[&namespace, &task_class, &now_ms],
                )
                .map_err(|error| error.to_string())?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(RouteSelection {
                model: current.clone(),
                previous_model: current,
                shifted: false,
                reason: "allocation unchanged".into(),
            });
        }

        if force {
            update_current_route(
                &mut transaction,
                namespace,
                task_class,
                proposed_model,
                now_ms,
            )?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(RouteSelection {
                model: proposed_model.to_string(),
                previous_model: current,
                shifted: true,
                reason: "forced regression reversion".into(),
            });
        }

        let next_count = if pending == proposed_model {
            pending_count + 1
        } else {
            1
        };
        let cooldown_elapsed = now_ms.saturating_sub(shifted_at) >= COOLDOWN_MS;
        let selection = if next_count >= CONFIRMATIONS && cooldown_elapsed {
            update_current_route(
                &mut transaction,
                namespace,
                task_class,
                proposed_model,
                now_ms,
            )?;
            RouteSelection {
                model: proposed_model.to_string(),
                previous_model: current,
                shifted: true,
                reason: format!("allocation confirmed {CONFIRMATIONS} times after cooldown"),
            }
        } else {
            transaction
                .execute(
                    "UPDATE chisei_portfolio_routes
                     SET pending_model = $3, pending_count = $4, updated_at = $5
                     WHERE namespace = $1 AND task_class = $2",
                    &[
                        &namespace,
                        &task_class,
                        &proposed_model,
                        &next_count,
                        &now_ms,
                    ],
                )
                .map_err(|error| error.to_string())?;
            RouteSelection {
                model: current.clone(),
                previous_model: current,
                shifted: false,
                reason: if cooldown_elapsed {
                    format!("waiting for allocation confirmation {next_count}/{CONFIRMATIONS}")
                } else {
                    "allocation held during cooldown".into()
                },
            }
        };
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(selection)
    }
}

fn update_current_route(
    transaction: &mut postgres::Transaction<'_>,
    namespace: &str,
    task_class: &str,
    proposed_model: &str,
    now_ms: i64,
) -> Result<(), String> {
    transaction
        .execute(
            "UPDATE chisei_portfolio_routes
             SET current_model = $3, pending_model = '', pending_count = 0,
                 shifted_at = $4, updated_at = $4
             WHERE namespace = $1 AND task_class = $2",
            &[&namespace, &task_class, &proposed_model, &now_ms],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn route_lock_key(namespace: &str, task_class: &str) -> String {
    format!(
        "portfolio:{}:{namespace}:{}:{task_class}",
        namespace.len(),
        task_class.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_lock_key_is_unambiguous() {
        assert_ne!(route_lock_key("a:b", "c"), route_lock_key("a", "b:c"));
    }
}
