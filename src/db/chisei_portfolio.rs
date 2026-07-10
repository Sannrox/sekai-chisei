use rusqlite::params;

use crate::chisei::portfolio::FrontierPoint;
use crate::db::sekai::SekaiDb;

impl SekaiDb {
    pub(crate) fn migrate_portfolio(&self) -> Result<(), String> {
        let conn = self.conn();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS chisei_portfolio_observations (
                namespace TEXT NOT NULL,
                task_class TEXT NOT NULL,
                model TEXT NOT NULL,
                quality_score REAL NOT NULL,
                cost_usd_micros INTEGER NOT NULL,
                sample_count INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (namespace, task_class, model)
            );
            CREATE INDEX IF NOT EXISTS idx_chisei_portfolio_frontier
                ON chisei_portfolio_observations(namespace, task_class, cost_usd_micros);",
        )
        .map_err(|err| err.to_string())
    }

    pub(crate) fn portfolio_record_observation(
        &self,
        namespace: &str,
        task_class: &str,
        model: &str,
        quality_score: f64,
        cost_usd_micros: i64,
        sample_count: i64,
        updated_at: i64,
    ) -> Result<(), String> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO chisei_portfolio_observations
                (namespace, task_class, model, quality_score, cost_usd_micros, sample_count, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(namespace, task_class, model) DO UPDATE SET
                quality_score =
                    ((quality_score * sample_count) + (excluded.quality_score * excluded.sample_count))
                    / (sample_count + excluded.sample_count),
                cost_usd_micros =
                    ((cost_usd_micros * sample_count) + (excluded.cost_usd_micros * excluded.sample_count))
                    / (sample_count + excluded.sample_count),
                sample_count = sample_count + excluded.sample_count,
                updated_at = MAX(updated_at, excluded.updated_at)",
            params![
                namespace,
                task_class,
                model,
                quality_score,
                cost_usd_micros,
                sample_count,
                updated_at
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
                "SELECT model, quality_score, cost_usd_micros, sample_count, updated_at
                 FROM chisei_portfolio_observations
                 WHERE namespace = ?1 AND task_class = ?2
                 ORDER BY cost_usd_micros, quality_score DESC, model",
            )
            .map_err(|err| err.to_string())?;
        let rows = stmt
            .query_map(params![namespace, task_class], |row| {
                Ok(FrontierPoint {
                    model: row.get(0)?,
                    quality_score: row.get(1)?,
                    cost_usd_micros: row.get(2)?,
                    sample_count: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            })
            .map_err(|err| err.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|err| err.to_string())
    }
}
