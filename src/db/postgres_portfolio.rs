use crate::chisei::portfolio::{
    FrontierPoint, Objective, ObjectiveMode, Observation, RouteSelection,
};
use crate::db::postgres::PostgresDb;

impl PostgresDb {
    pub fn portfolio_record_observation(&self, observation: &Observation) -> Result<(), String> {
        let prompt_variant =
            crate::chisei::portfolio::normalize_prompt_variant(&observation.prompt_variant);
        self.connection()?
            .execute(
                "INSERT INTO chisei_portfolio_observations
                    (namespace, task_class, model, prompt_variant, quality_score, cost_usd_micros,
                     sample_count, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT(namespace, task_class, model, prompt_variant) DO UPDATE SET
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
                    &prompt_variant,
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
                "SELECT model, prompt_variant, quality_score, cost_usd_micros, sample_count, updated_at
                 FROM chisei_portfolio_observations
                 WHERE namespace = $1 AND task_class = $2
                 ORDER BY cost_usd_micros, quality_score DESC, model, prompt_variant",
                &[&namespace, &task_class],
            )
            .map(|rows| {
                rows.into_iter()
                    .map(|row| FrontierPoint {
                        model: row.get(0),
                        prompt_variant: row.get(1),
                        quality_score: row.get(2),
                        cost_usd_micros: row.get(3),
                        sample_count: row.get(4),
                        updated_at: row.get(5),
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
        proposed_prompt_variant: &str,
        now_ms: i64,
        force: bool,
    ) -> Result<RouteSelection, String> {
        const CONFIRMATIONS: i64 = 3;
        const COOLDOWN_MS: i64 = 15 * 60 * 1000;
        let proposed_prompt_variant =
            crate::chisei::portfolio::normalize_prompt_variant(proposed_prompt_variant);

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
                "SELECT current_model, current_prompt_variant, pending_model, pending_prompt_variant, pending_count, shifted_at
                 FROM chisei_portfolio_routes WHERE namespace = $1 AND task_class = $2",
                &[&namespace, &task_class],
            )
            .map_err(|error| error.to_string())?;
        let Some(state) = state else {
            transaction
                .execute(
                    "INSERT INTO chisei_portfolio_routes
                    (namespace, task_class, current_model, current_prompt_variant, pending_model,
                         pending_prompt_variant, pending_count, shifted_at, updated_at)
                     VALUES ($1, $2, $3, $4, '', '', 0, $5, $5)",
                    &[
                        &namespace,
                        &task_class,
                        &proposed_model,
                        &proposed_prompt_variant,
                        &now_ms,
                    ],
                )
                .map_err(|error| error.to_string())?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(RouteSelection {
                model: proposed_model.to_string(),
                prompt_variant: proposed_prompt_variant.to_string(),
                previous_model: String::new(),
                previous_prompt_variant: String::new(),
                shifted: !force,
                reason: if force {
                    "initialized on regression-safe model".into()
                } else {
                    "initial allocation".into()
                },
            });
        };
        let current: String = state.get(0);
        let current_variant: String = state.get(1);
        let pending: String = state.get(2);
        let pending_variant: String = state.get(3);
        let pending_count: i64 = state.get(4);
        let shifted_at: i64 = state.get(5);

        if current == proposed_model && current_variant == proposed_prompt_variant {
            transaction
                .execute(
                    "UPDATE chisei_portfolio_routes
                     SET pending_model = '', pending_prompt_variant = '', pending_count = 0, updated_at = $3
                     WHERE namespace = $1 AND task_class = $2",
                    &[&namespace, &task_class, &now_ms],
                )
                .map_err(|error| error.to_string())?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(RouteSelection {
                model: current.clone(),
                prompt_variant: current_variant.clone(),
                previous_model: current,
                previous_prompt_variant: current_variant,
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
                &proposed_prompt_variant,
                now_ms,
            )?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(RouteSelection {
                model: proposed_model.to_string(),
                prompt_variant: proposed_prompt_variant.to_string(),
                previous_model: current,
                previous_prompt_variant: current_variant,
                shifted: true,
                reason: "forced regression reversion".into(),
            });
        }

        let next_count = if pending == proposed_model && pending_variant == proposed_prompt_variant
        {
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
                &proposed_prompt_variant,
                now_ms,
            )?;
            RouteSelection {
                model: proposed_model.to_string(),
                prompt_variant: proposed_prompt_variant.to_string(),
                previous_model: current,
                previous_prompt_variant: current_variant,
                shifted: true,
                reason: format!("allocation confirmed {CONFIRMATIONS} times after cooldown"),
            }
        } else {
            transaction
                .execute(
                    "UPDATE chisei_portfolio_routes
                     SET pending_model = $3, pending_prompt_variant = $4, pending_count = $5, updated_at = $6
                     WHERE namespace = $1 AND task_class = $2",
                    &[
                        &namespace,
                        &task_class,
                        &proposed_model,
                        &proposed_prompt_variant,
                        &next_count,
                        &now_ms,
                    ],
                )
                .map_err(|error| error.to_string())?;
            RouteSelection {
                model: current.clone(),
                prompt_variant: current_variant.clone(),
                previous_model: current,
                previous_prompt_variant: current_variant,
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
    proposed_prompt_variant: &str,
    now_ms: i64,
) -> Result<(), String> {
    transaction
        .execute(
            "UPDATE chisei_portfolio_routes
             SET current_model = $3, current_prompt_variant = $4, pending_model = '', pending_prompt_variant = '', pending_count = 0,
                 shifted_at = $5, updated_at = $5
             WHERE namespace = $1 AND task_class = $2",
            &[&namespace, &task_class, &proposed_model, &proposed_prompt_variant, &now_ms],
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
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use super::*;
    use crate::db::portfolio_route_test_cases::assert_route_contract;

    const TEST_DATABASE_URL_ENV: &str = "SEKAI_TEST_POSTGRES_URL";
    const TEST_CA_CERT_ENV: &str = "SEKAI_TEST_POSTGRES_CA_CERT";

    fn test_database() -> PostgresDb {
        let database_url = std::env::var(TEST_DATABASE_URL_ENV).unwrap_or_else(|_| {
            panic!("{TEST_DATABASE_URL_ENV} must point to an isolated PostgreSQL test database")
        });
        if let Ok(ca_certificate_path) = std::env::var(TEST_CA_CERT_ENV) {
            let ca_certificate = std::fs::read(&ca_certificate_path).unwrap_or_else(|error| {
                panic!("read PostgreSQL test CA certificate {ca_certificate_path}: {error}")
            });
            PostgresDb::connect_with_test_ca(&database_url, 4, &ca_certificate).unwrap()
        } else {
            PostgresDb::connect(&database_url, 4).unwrap()
        }
    }

    #[test]
    fn route_lock_key_is_unambiguous() {
        assert_ne!(route_lock_key("a:b", "c"), route_lock_key("a", "b:c"));
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database; set SEKAI_TEST_POSTGRES_CA_CERT for a private CA"]
    fn damped_route_matches_shared_contract() {
        let db = test_database();
        let run_id = uuid::Uuid::new_v4().simple().to_string();
        assert_route_contract(|case, task_class, proposed_model, now_ms, force| {
            db.portfolio_damped_route(
                &format!("route-contract-{run_id}-{case}"),
                task_class,
                proposed_model,
                crate::chisei::portfolio::LEGACY_PROMPT_VARIANT,
                now_ms,
                force,
            )
        });
    }

    #[test]
    #[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database; set SEKAI_TEST_POSTGRES_CA_CERT for a private CA"]
    fn advisory_lock_serializes_updates_for_the_same_route() {
        let db = Arc::new(test_database());
        let namespace = format!("route-lock-{}", uuid::Uuid::new_v4().simple());
        let task_class = "primary";
        db.portfolio_damped_route(
            &namespace,
            task_class,
            "small",
            crate::chisei::portfolio::LEGACY_PROMPT_VARIANT,
            0,
            false,
        )
        .unwrap();

        let mut lock_connection = db.connection().unwrap();
        let mut lock_transaction = lock_connection.transaction().unwrap();
        let lock_key = route_lock_key(&namespace, task_class);
        lock_transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock_key],
            )
            .unwrap();

        let (started_sender, started_receiver) = mpsc::channel();
        let (result_sender, result_receiver) = mpsc::channel();
        let workers = (0..2)
            .map(|_| {
                let worker_db = Arc::clone(&db);
                let worker_namespace = namespace.clone();
                let worker_started = started_sender.clone();
                let worker_result = result_sender.clone();
                std::thread::spawn(move || {
                    worker_started.send(()).unwrap();
                    let result = worker_db.portfolio_damped_route(
                        &worker_namespace,
                        task_class,
                        "large",
                        crate::chisei::portfolio::LEGACY_PROMPT_VARIANT,
                        15 * 60 * 1000,
                        false,
                    );
                    worker_result.send(result).unwrap();
                })
            })
            .collect::<Vec<_>>();
        drop(started_sender);
        drop(result_sender);

        for _ in 0..2 {
            started_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("route worker did not start");
        }

        assert!(
            result_receiver
                .recv_timeout(Duration::from_millis(250))
                .is_err(),
            "route update completed while the matching advisory lock was held"
        );
        lock_transaction.commit().unwrap();

        let mut reasons = (0..2)
            .map(|_| {
                let selection = result_receiver
                    .recv_timeout(Duration::from_secs(5))
                    .expect("route update remained blocked after advisory lock release")
                    .unwrap();
                assert_eq!(selection.model, "small");
                selection.reason
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        reasons.sort();
        assert_eq!(
            reasons,
            [
                "waiting for allocation confirmation 1/3",
                "waiting for allocation confirmation 2/3",
            ]
        );
    }
}
