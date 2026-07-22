use rusqlite::params;

use crate::chisei::portfolio::{
    FrontierPoint, Objective, ObjectiveMode, Observation, RouteSelection,
};
use crate::db::sekai::SekaiDb;

impl SekaiDb {
    pub(crate) fn migrate_portfolio(&self) -> Result<(), String> {
        let mut conn = self.conn();
        let observation_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chisei_portfolio_observations')",
                [],
                |row| row.get(0),
            )
            .map_err(|err| err.to_string())?;
        let has_prompt_variant = if observation_exists {
            let mut statement = conn
                .prepare("PRAGMA table_info(chisei_portfolio_observations)")
                .map_err(|err| err.to_string())?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|err| err.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.to_string())?;
            columns.iter().any(|column| column == "prompt_variant")
        } else {
            true
        };
        let transaction = conn.transaction().map_err(|err| err.to_string())?;
        if observation_exists && !has_prompt_variant {
            transaction.execute_batch(
                "ALTER TABLE chisei_portfolio_observations RENAME TO chisei_portfolio_observations_legacy;
                 CREATE TABLE chisei_portfolio_observations (
                    namespace TEXT NOT NULL, task_class TEXT NOT NULL, model TEXT NOT NULL,
                    prompt_variant TEXT NOT NULL, quality_score REAL NOT NULL,
                    cost_usd_micros INTEGER NOT NULL, sample_count INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (namespace, task_class, model, prompt_variant));
                 INSERT INTO chisei_portfolio_observations
                    (namespace, task_class, model, prompt_variant, quality_score,
                     cost_usd_micros, sample_count, updated_at)
                 SELECT namespace, task_class, model, 'legacy@1', quality_score,
                        cost_usd_micros, sample_count, updated_at
                 FROM chisei_portfolio_observations_legacy;
                 DROP TABLE chisei_portfolio_observations_legacy;",
            ).map_err(|err| err.to_string())?;
        }
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS chisei_portfolio_observations (
                namespace TEXT NOT NULL,
                task_class TEXT NOT NULL,
                model TEXT NOT NULL,
                prompt_variant TEXT NOT NULL,
                quality_score REAL NOT NULL,
                cost_usd_micros INTEGER NOT NULL,
                sample_count INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (namespace, task_class, model, prompt_variant)
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_portfolio_frontier
                ON chisei_portfolio_observations(namespace, task_class, cost_usd_micros);
            CREATE TABLE IF NOT EXISTS chisei_portfolio_objectives (
                namespace TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                budget_usd_micros INTEGER NOT NULL,
                quality_bar REAL NOT NULL,
                min_samples INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chisei_portfolio_routes (
                namespace TEXT NOT NULL,
                task_class TEXT NOT NULL,
                current_model TEXT NOT NULL,
                pending_model TEXT NOT NULL DEFAULT '',
                pending_count INTEGER NOT NULL DEFAULT 0,
                shifted_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (namespace, task_class)
            );",
            )
            .map_err(|err| err.to_string())?;
        for statement in [
            "ALTER TABLE chisei_portfolio_routes ADD COLUMN current_prompt_variant TEXT NOT NULL DEFAULT 'legacy@1'",
            "ALTER TABLE chisei_portfolio_routes ADD COLUMN pending_prompt_variant TEXT NOT NULL DEFAULT ''",
        ] {
            if let Err(error) = transaction.execute(statement, [])
                && !error.to_string().contains("duplicate column name")
            {
                return Err(error.to_string());
            }
        }
        transaction.commit().map_err(|err| err.to_string())
    }

    pub(crate) fn portfolio_record_observation(
        &self,
        observation: &Observation,
    ) -> Result<(), String> {
        let conn = self.conn();
        let prompt_variant =
            crate::chisei::portfolio::normalize_prompt_variant(&observation.prompt_variant);
        conn.execute(
            "INSERT INTO chisei_portfolio_observations
                (namespace, task_class, model, prompt_variant, quality_score, cost_usd_micros, sample_count, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(namespace, task_class, model, prompt_variant) DO UPDATE SET
                quality_score =
                    ((quality_score * sample_count) + (excluded.quality_score * excluded.sample_count))
                    / (sample_count + excluded.sample_count),
                cost_usd_micros =
                    ((cost_usd_micros * sample_count) + (excluded.cost_usd_micros * excluded.sample_count))
                    / (sample_count + excluded.sample_count),
                sample_count = sample_count + excluded.sample_count,
                updated_at = MAX(updated_at, excluded.updated_at)",
            params![
                observation.namespace,
                observation.task_class,
                observation.model,
                prompt_variant,
                observation.quality_score,
                observation.cost_usd_micros,
                observation.sample_count,
                observation.updated_at
            ],
        )
        .map_err(|err| err.to_string())?;
        Ok(())
    }

    pub(crate) fn portfolio_points(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String> {
        let conn = self.conn();
        let mut stmt = conn
            .prepare(
            "SELECT model, prompt_variant, quality_score, cost_usd_micros, sample_count, updated_at
                 FROM chisei_portfolio_observations
                 WHERE namespace = ?1 AND task_class = ?2
                 ORDER BY cost_usd_micros, quality_score DESC, model, prompt_variant",
            )
            .map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map(params![namespace, task_class], |row| {
                Ok(FrontierPoint {
                    model: row.get(0)?,
                    prompt_variant: row.get(1)?,
                    quality_score: row.get(2)?,
                    cost_usd_micros: row.get(3)?,
                    sample_count: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|err| err.to_string())
    }

    pub(crate) fn portfolio_set_objective(&self, objective: &Objective) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO chisei_portfolio_objectives
                (namespace, mode, budget_usd_micros, quality_bar, min_samples, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(namespace) DO UPDATE SET
                mode = excluded.mode,
                budget_usd_micros = excluded.budget_usd_micros,
                quality_bar = excluded.quality_bar,
                min_samples = excluded.min_samples,
                updated_at = excluded.updated_at",
            params![
                objective.namespace.trim(),
                objective.mode.as_str(),
                objective.budget_usd_micros,
                objective.quality_bar,
                objective.min_samples,
                objective.updated_at
            ],
        )
        .map_err(|err| err.to_string())?;
        Ok(())
    }

    pub(crate) fn portfolio_objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
        use rusqlite::OptionalExtension;

        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT namespace, mode, budget_usd_micros, quality_bar, min_samples, updated_at
                 FROM chisei_portfolio_objectives WHERE namespace = ?1",
                params![namespace],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, f64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|err| err.to_string())?;
        row.map(
            |(namespace, mode, budget_usd_micros, quality_bar, min_samples, updated_at)| {
                Ok(Objective {
                    namespace,
                    mode: ObjectiveMode::parse(&mode)?,
                    budget_usd_micros,
                    quality_bar,
                    min_samples,
                    updated_at,
                })
            },
        )
        .transpose()
    }

    pub(crate) fn portfolio_damped_route(
        &self,
        namespace: &str,
        task_class: &str,
        proposed_model: &str,
        proposed_prompt_variant: &str,
        now_ms: i64,
        force: bool,
    ) -> Result<RouteSelection, String> {
        use rusqlite::OptionalExtension;
        let proposed_prompt_variant =
            crate::chisei::portfolio::normalize_prompt_variant(proposed_prompt_variant);

        const CONFIRMATIONS: i64 = 3;
        const COOLDOWN_MS: i64 = 15 * 60 * 1000;

        let conn = self.conn();
        let state = conn
            .query_row(
                "SELECT current_model, current_prompt_variant, pending_model, pending_prompt_variant, pending_count, shifted_at
                 FROM chisei_portfolio_routes WHERE namespace = ?1 AND task_class = ?2",
                params![namespace, task_class],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|err| err.to_string())?;
        let Some((current, current_variant, pending, pending_variant, pending_count, shifted_at)) =
            state
        else {
            conn.execute(
                "INSERT INTO chisei_portfolio_routes
                    (namespace, task_class, current_model, current_prompt_variant, pending_model, pending_prompt_variant, pending_count, shifted_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, '', '', 0, ?5, ?5)",
                params![namespace, task_class, proposed_model, &proposed_prompt_variant, now_ms],
            )
            .map_err(|err| err.to_string())?;
            return Ok(RouteSelection {
                model: proposed_model.to_string(),
                prompt_variant: proposed_prompt_variant.clone(),
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

        if current == proposed_model && current_variant == proposed_prompt_variant {
            conn.execute(
                "UPDATE chisei_portfolio_routes
                 SET pending_model = '', pending_prompt_variant = '', pending_count = 0, updated_at = ?3
                 WHERE namespace = ?1 AND task_class = ?2",
                params![namespace, task_class, now_ms],
            )
            .map_err(|err| err.to_string())?;
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
            conn.execute(
                "UPDATE chisei_portfolio_routes
                 SET current_model = ?3, current_prompt_variant = ?4, pending_model = '', pending_prompt_variant = '', pending_count = 0,
                     shifted_at = ?5, updated_at = ?5
                 WHERE namespace = ?1 AND task_class = ?2",
                params![namespace, task_class, proposed_model, &proposed_prompt_variant, now_ms],
            )
            .map_err(|err| err.to_string())?;
            return Ok(RouteSelection {
                model: proposed_model.to_string(),
                prompt_variant: proposed_prompt_variant.clone(),
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
        if next_count >= CONFIRMATIONS && cooldown_elapsed {
            conn.execute(
                "UPDATE chisei_portfolio_routes
                 SET current_model = ?3, current_prompt_variant = ?4, pending_model = '', pending_prompt_variant = '', pending_count = 0,
                     shifted_at = ?5, updated_at = ?5
                 WHERE namespace = ?1 AND task_class = ?2",
                params![namespace, task_class, proposed_model, &proposed_prompt_variant, now_ms],
            )
            .map_err(|err| err.to_string())?;
            Ok(RouteSelection {
                model: proposed_model.to_string(),
                prompt_variant: proposed_prompt_variant.clone(),
                previous_model: current,
                previous_prompt_variant: current_variant,
                shifted: true,
                reason: format!("allocation confirmed {CONFIRMATIONS} times after cooldown"),
            })
        } else {
            conn.execute(
                "UPDATE chisei_portfolio_routes
                 SET pending_model = ?3, pending_prompt_variant = ?4, pending_count = ?5, updated_at = ?6
                 WHERE namespace = ?1 AND task_class = ?2",
                params![namespace, task_class, proposed_model, &proposed_prompt_variant, next_count, now_ms],
            )
            .map_err(|err| err.to_string())?;
            Ok(RouteSelection {
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
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::portfolio_route_test_cases::assert_route_contract;

    #[test]
    fn damped_route_matches_shared_contract() {
        let db = SekaiDb::new(":memory:").unwrap();
        assert_route_contract(|namespace, task_class, proposed_model, now_ms, force| {
            db.portfolio_damped_route(
                namespace,
                task_class,
                proposed_model,
                crate::chisei::portfolio::LEGACY_PROMPT_VARIANT,
                now_ms,
                force,
            )
        });
    }

    #[test]
    fn migration_backfills_legacy_observations_and_routes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("portfolio.db");
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection.execute_batch(
                "CREATE TABLE chisei_portfolio_observations (
                    namespace TEXT NOT NULL, task_class TEXT NOT NULL, model TEXT NOT NULL,
                    quality_score REAL NOT NULL, cost_usd_micros INTEGER NOT NULL,
                    sample_count INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    PRIMARY KEY (namespace, task_class, model));
                 INSERT INTO chisei_portfolio_observations VALUES
                    ('acme', 'primary', 'model-a', 87.5, 17, 4, 20);
                 CREATE TABLE chisei_portfolio_routes (
                    namespace TEXT NOT NULL, task_class TEXT NOT NULL, current_model TEXT NOT NULL,
                    pending_model TEXT NOT NULL DEFAULT '', pending_count INTEGER NOT NULL DEFAULT 0,
                    shifted_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    PRIMARY KEY (namespace, task_class));
                 INSERT INTO chisei_portfolio_routes VALUES
                    ('acme', 'primary', 'model-a', '', 0, 10, 20);",
            ).unwrap();
        }

        let db = SekaiDb::new(path.to_str().unwrap()).unwrap();
        let points = db.portfolio_points("acme", "primary").unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(
            points[0].prompt_variant,
            crate::chisei::portfolio::LEGACY_PROMPT_VARIANT
        );
        assert_eq!(points[0].quality_score, 87.5);
        assert_eq!(points[0].cost_usd_micros, 17);
        assert_eq!(points[0].sample_count, 4);
        assert_eq!(points[0].updated_at, 20);

        let unchanged = db
            .portfolio_damped_route("acme", "primary", "model-a", "", 21, false)
            .unwrap();
        assert_eq!(
            unchanged.prompt_variant,
            crate::chisei::portfolio::LEGACY_PROMPT_VARIANT
        );
        assert!(!unchanged.shifted);
    }

    #[test]
    fn persistence_boundary_canonicalizes_an_empty_variant() {
        let db = SekaiDb::new(":memory:").unwrap();
        db.portfolio_record_observation(&Observation {
            namespace: "acme".into(),
            task_class: "primary".into(),
            model: "model-a".into(),
            prompt_variant: String::new(),
            quality_score: 80.0,
            cost_usd_micros: 10,
            sample_count: 1,
            updated_at: 1,
        })
        .unwrap();
        let points = db.portfolio_points("acme", "primary").unwrap();
        assert_eq!(
            points[0].prompt_variant,
            crate::chisei::portfolio::LEGACY_PROMPT_VARIANT
        );
    }
}
