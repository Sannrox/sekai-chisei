use std::sync::Arc;

use crate::db::sekai::SekaiDb;

#[derive(Debug, Clone, PartialEq)]
pub struct FrontierPoint {
    pub model: String,
    pub quality_score: f64,
    pub cost_usd_micros: i64,
    pub sample_count: i64,
    pub updated_at: i64,
}

pub struct PortfolioStore {
    db: Arc<SekaiDb>,
}

impl PortfolioStore {
    pub fn new(db: Arc<SekaiDb>) -> Self {
        Self { db }
    }

    pub fn record(
        &self,
        namespace: &str,
        task_class: &str,
        model: &str,
        quality_score: f64,
        cost_usd_micros: i64,
        sample_count: i64,
        updated_at: i64,
    ) -> Result<(), String> {
        let namespace = namespace.trim();
        let task_class = normalize_task_class(task_class);
        let model = model.trim();
        if namespace.is_empty() {
            return Err("portfolio observation namespace required".into());
        }
        if model.is_empty() {
            return Err("portfolio observation model required".into());
        }
        if !quality_score.is_finite() || !(0.0..=100.0).contains(&quality_score) {
            return Err("portfolio quality_score must be finite and between 0 and 100".into());
        }
        if cost_usd_micros < 0 {
            return Err("portfolio cost_usd_micros must be non-negative".into());
        }
        if sample_count <= 0 {
            return Err("portfolio sample_count must be positive".into());
        }
        self.db.portfolio_record_observation(
            namespace,
            &task_class,
            model,
            quality_score,
            cost_usd_micros,
            sample_count,
            updated_at,
        )
    }

    pub fn points(&self, namespace: &str, task_class: &str) -> Result<Vec<FrontierPoint>, String> {
        self.db
            .portfolio_points(namespace.trim(), &normalize_task_class(task_class))
    }

    /// Returns the non-dominated quality/cost curve ordered from cheapest to
    /// most expensive. A point is dominated when another model is no more
    /// expensive and no lower quality, with at least one strict improvement.
    pub fn frontier(
        &self,
        namespace: &str,
        task_class: &str,
    ) -> Result<Vec<FrontierPoint>, String> {
        let points = self.points(namespace, task_class)?;
        Ok(points
            .iter()
            .filter(|point| {
                !points.iter().any(|other| {
                    other.model != point.model
                        && other.cost_usd_micros <= point.cost_usd_micros
                        && other.quality_score >= point.quality_score
                        && (other.cost_usd_micros < point.cost_usd_micros
                            || other.quality_score > point.quality_score)
                })
            })
            .cloned()
            .collect())
    }
}

pub fn normalize_task_class(task_class: &str) -> String {
    let normalized = task_class.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        "primary".into()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> PortfolioStore {
        PortfolioStore::new(Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    #[test]
    fn observations_are_aggregated_by_weighted_mean() {
        let store = store();
        store
            .record("acme", " Primary ", "model-a", 80.0, 10, 1, 10)
            .unwrap();
        store
            .record("acme", "primary", "model-a", 90.0, 20, 3, 20)
            .unwrap();

        let point = store.points("acme", "PRIMARY").unwrap().pop().unwrap();
        assert_eq!(point.quality_score, 87.5);
        assert_eq!(point.cost_usd_micros, 17);
        assert_eq!(point.sample_count, 4);
        assert_eq!(point.updated_at, 20);
    }

    #[test]
    fn frontier_removes_dominated_models() {
        let store = store();
        for (model, quality, cost) in [
            ("cheap", 75.0, 5),
            ("dominated", 74.0, 8),
            ("balanced", 85.0, 10),
            ("capable", 95.0, 30),
        ] {
            store
                .record("acme", "primary", model, quality, cost, 3, 1)
                .unwrap();
        }

        let models: Vec<_> = store
            .frontier("acme", "primary")
            .unwrap()
            .into_iter()
            .map(|point| point.model)
            .collect();
        assert_eq!(models, vec!["cheap", "balanced", "capable"]);
    }

    #[test]
    fn invalid_observations_are_rejected() {
        let store = store();
        assert!(store.record("", "primary", "model", 80.0, 1, 1, 1).is_err());
        assert!(store.record("acme", "primary", "", 80.0, 1, 1, 1).is_err());
        assert!(
            store
                .record("acme", "primary", "model", f64::NAN, 1, 1, 1)
                .is_err()
        );
        assert!(
            store
                .record("acme", "primary", "model", 80.0, -1, 1, 1)
                .is_err()
        );
    }
}
