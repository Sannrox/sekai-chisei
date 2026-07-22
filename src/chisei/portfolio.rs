use std::sync::Arc;

use crate::db::sekai::SekaiDb;

pub const LEGACY_PROMPT_VARIANT: &str = "legacy@1";

#[derive(Debug, Clone, PartialEq)]
pub struct FrontierPoint {
    pub model: String,
    pub prompt_variant: String,
    pub quality_score: f64,
    pub cost_usd_micros: i64,
    pub sample_count: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub namespace: String,
    pub task_class: String,
    pub model: String,
    pub prompt_variant: String,
    pub quality_score: f64,
    pub cost_usd_micros: i64,
    pub sample_count: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectiveMode {
    MaximizeValue,
    MinimizeCost,
}

impl ObjectiveMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "maximize_value" | "max_value" => Ok(Self::MaximizeValue),
            "minimize_cost" | "min_cost" => Ok(Self::MinimizeCost),
            other => Err(format!("unsupported portfolio objective mode '{other}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaximizeValue => "maximize_value",
            Self::MinimizeCost => "minimize_cost",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Objective {
    pub namespace: String,
    pub mode: ObjectiveMode,
    pub budget_usd_micros: i64,
    pub quality_bar: f64,
    pub min_samples: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskDemand {
    pub task_class: String,
    pub expected_calls: i64,
    pub quality_bar: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Allocation {
    pub task_class: String,
    pub model: String,
    pub prompt_variant: String,
    pub quality_score: f64,
    pub cost_per_call_usd_micros: i64,
    pub expected_calls: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AllocationPlan {
    pub allocations: Vec<Allocation>,
    pub total_cost_usd_micros: i64,
    pub total_value: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RouteSelection {
    pub model: String,
    pub prompt_variant: String,
    pub previous_model: String,
    pub previous_prompt_variant: String,
    pub shifted: bool,
    pub reason: String,
}

pub struct PortfolioStore {
    db: Arc<SekaiDb>,
}

impl PortfolioStore {
    pub fn new(db: Arc<SekaiDb>) -> Self {
        Self { db }
    }

    pub fn record(&self, observation: &Observation) -> Result<(), String> {
        let namespace = observation.namespace.trim();
        let task_class = normalize_task_class(&observation.task_class);
        let model = observation.model.trim();
        let prompt_variant = normalize_prompt_variant(&observation.prompt_variant);
        if namespace.is_empty() {
            return Err("portfolio observation namespace required".into());
        }
        if model.is_empty() {
            return Err("portfolio observation model required".into());
        }
        if !observation.quality_score.is_finite()
            || !(0.0..=100.0).contains(&observation.quality_score)
        {
            return Err("portfolio quality_score must be finite and between 0 and 100".into());
        }
        if observation.cost_usd_micros < 0 {
            return Err("portfolio cost_usd_micros must be non-negative".into());
        }
        if observation.sample_count <= 0 {
            return Err("portfolio sample_count must be positive".into());
        }
        let normalized = Observation {
            namespace: namespace.to_string(),
            task_class,
            model: model.to_string(),
            prompt_variant,
            ..observation.clone()
        };
        self.db.portfolio_record_observation(&normalized)
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
                    (other.model != point.model || other.prompt_variant != point.prompt_variant)
                        && other.cost_usd_micros <= point.cost_usd_micros
                        && other.quality_score >= point.quality_score
                        && (other.cost_usd_micros < point.cost_usd_micros
                            || other.quality_score > point.quality_score)
                })
            })
            .cloned()
            .collect())
    }

    pub fn set_objective(&self, objective: &Objective) -> Result<(), String> {
        if objective.namespace.trim().is_empty() {
            return Err("portfolio objective namespace required".into());
        }
        if objective.budget_usd_micros < 0 {
            return Err("portfolio budget_usd_micros must be non-negative".into());
        }
        if !objective.quality_bar.is_finite() || !(0.0..=100.0).contains(&objective.quality_bar) {
            return Err("portfolio quality_bar must be finite and between 0 and 100".into());
        }
        if objective.min_samples <= 0 {
            return Err("portfolio min_samples must be positive".into());
        }
        self.db.portfolio_set_objective(objective)
    }

    pub fn objective(&self, namespace: &str) -> Result<Option<Objective>, String> {
        self.db.portfolio_objective(namespace.trim())
    }

    pub fn allocate(
        &self,
        objective: &Objective,
        demands: &[TaskDemand],
    ) -> Result<AllocationPlan, String> {
        const MAX_DEMANDS: usize = 64;
        const MAX_CANDIDATES_PER_DEMAND: usize = 128;
        if demands.is_empty() {
            return Err("at least one portfolio task demand required".into());
        }
        if demands.len() > MAX_DEMANDS {
            return Err(format!(
                "portfolio allocation supports at most {MAX_DEMANDS} task demands"
            ));
        }

        let mut choices = Vec::with_capacity(demands.len());
        for demand in demands {
            if demand.expected_calls <= 0 {
                return Err(format!(
                    "expected_calls must be positive for task class {:?}",
                    demand.task_class
                ));
            }
            let quality_bar = demand.quality_bar.unwrap_or(objective.quality_bar);
            if !quality_bar.is_finite() || !(0.0..=100.0).contains(&quality_bar) {
                return Err(format!(
                    "quality bar must be finite and between 0 and 100 for task class {:?}",
                    demand.task_class
                ));
            }
            let task_class = normalize_task_class(&demand.task_class);
            let candidates: Vec<_> = self
                .frontier(&objective.namespace, &task_class)?
                .into_iter()
                .filter(|point| {
                    point.sample_count >= objective.min_samples
                        && point.quality_score >= quality_bar
                })
                .collect();
            if candidates.len() > MAX_CANDIDATES_PER_DEMAND {
                return Err(format!(
                    "portfolio allocation supports at most {MAX_CANDIDATES_PER_DEMAND} candidates per task demand"
                ));
            }
            let selected = candidates.first().cloned().ok_or_else(|| {
                format!(
                    "no sufficiently sampled model clears quality bar {quality_bar:.1} for task class {task_class}"
                )
            })?;
            choices.push((demand.clone(), candidates, 0usize, selected));
        }

        if objective.mode == ObjectiveMode::MaximizeValue {
            let selected_indices = maximize_value_indices(&choices, objective.budget_usd_micros)?;
            for ((_, candidates, selected_index, selected), next_index) in
                choices.iter_mut().zip(selected_indices)
            {
                *selected_index = next_index;
                *selected = candidates[next_index].clone();
            }
        }

        let total_cost = plan_cost(&choices)?;
        if objective.budget_usd_micros > 0 && total_cost > objective.budget_usd_micros {
            return Err(format!(
                "minimum quality allocation costs {total_cost} micros, above budget {}",
                objective.budget_usd_micros
            ));
        }

        let allocations: Vec<_> = choices
            .into_iter()
            .map(|(demand, _, _, point)| Allocation {
                task_class: normalize_task_class(&demand.task_class),
                model: point.model,
                prompt_variant: point.prompt_variant,
                quality_score: point.quality_score,
                cost_per_call_usd_micros: point.cost_usd_micros,
                expected_calls: demand.expected_calls,
            })
            .collect();
        let total_value = allocations
            .iter()
            .map(|allocation| allocation.quality_score * allocation.expected_calls as f64)
            .sum();
        Ok(AllocationPlan {
            allocations,
            total_cost_usd_micros: total_cost,
            total_value,
        })
    }

    pub fn damped_route(
        &self,
        namespace: &str,
        task_class: &str,
        proposed_model: &str,
        proposed_prompt_variant: &str,
        now_ms: i64,
        force: bool,
    ) -> Result<RouteSelection, String> {
        if namespace.trim().is_empty() || proposed_model.trim().is_empty() {
            return Err("portfolio route namespace and proposed model required".into());
        }
        self.db.portfolio_damped_route(
            namespace.trim(),
            &normalize_task_class(task_class),
            proposed_model.trim(),
            &normalize_prompt_variant(proposed_prompt_variant),
            now_ms,
            force,
        )
    }
}

type Choice = (TaskDemand, Vec<FrontierPoint>, usize, FrontierPoint);

#[derive(Clone)]
struct AllocationState {
    cost: i64,
    value: f64,
    selected_indices: Vec<usize>,
}

fn maximize_value_indices(choices: &[Choice], budget: i64) -> Result<Vec<usize>, String> {
    const MAX_OPTIMIZER_STATES: usize = 100_000;

    if budget == 0 {
        return Ok(choices
            .iter()
            .map(|(_, candidates, _, _)| candidates.len() - 1)
            .collect());
    }

    let mut states = vec![AllocationState {
        cost: 0,
        value: 0.0,
        selected_indices: Vec::with_capacity(choices.len()),
    }];
    for (demand, candidates, _, _) in choices {
        let mut next = Vec::new();
        for state in &states {
            for (index, candidate) in candidates.iter().enumerate() {
                let Some(candidate_cost) =
                    candidate.cost_usd_micros.checked_mul(demand.expected_calls)
                else {
                    continue;
                };
                let Some(cost) = state.cost.checked_add(candidate_cost) else {
                    continue;
                };
                if cost > budget {
                    continue;
                }
                let mut selected_indices = state.selected_indices.clone();
                selected_indices.push(index);
                next.push(AllocationState {
                    cost,
                    value: state.value + candidate.quality_score * demand.expected_calls as f64,
                    selected_indices,
                });
                if next.len() > MAX_OPTIMIZER_STATES {
                    return Err("portfolio allocation search is too complex".into());
                }
            }
        }
        if next.is_empty() {
            return Err(format!(
                "minimum quality allocation is above budget {budget}"
            ));
        }
        next.sort_by(|left, right| {
            left.cost
                .cmp(&right.cost)
                .then_with(|| right.value.total_cmp(&left.value))
                .then_with(|| left.selected_indices.cmp(&right.selected_indices))
        });
        let mut best_value = f64::NEG_INFINITY;
        states = next
            .into_iter()
            .filter(|state| {
                if state.value > best_value {
                    best_value = state.value;
                    true
                } else {
                    false
                }
            })
            .collect();
    }

    states.sort_by(|left, right| {
        right
            .value
            .total_cmp(&left.value)
            .then_with(|| left.cost.cmp(&right.cost))
            .then_with(|| left.selected_indices.cmp(&right.selected_indices))
    });
    Ok(states.remove(0).selected_indices)
}

fn plan_cost(choices: &[Choice]) -> Result<i64, String> {
    choices
        .iter()
        .try_fold(0i64, |total, (demand, _, _, point)| {
            point
                .cost_usd_micros
                .checked_mul(demand.expected_calls)
                .and_then(|cost| total.checked_add(cost))
                .ok_or_else(|| "portfolio allocation cost overflow".to_string())
        })
}

pub fn normalize_task_class(task_class: &str) -> String {
    let normalized = task_class.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        "primary".into()
    } else {
        normalized
    }
}

pub fn normalize_prompt_variant(prompt_variant: &str) -> String {
    let normalized = prompt_variant.trim();
    if normalized.is_empty() {
        LEGACY_PROMPT_VARIANT.into()
    } else {
        normalized.into()
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
            .record(&observation(
                "acme",
                " Primary ",
                "model-a",
                80.0,
                10,
                1,
                10,
            ))
            .unwrap();
        store
            .record(&observation("acme", "primary", "model-a", 90.0, 20, 3, 20))
            .unwrap();

        let point = store.points("acme", "PRIMARY").unwrap().pop().unwrap();
        assert_eq!(point.quality_score, 87.5);
        assert_eq!(point.cost_usd_micros, 17);
        assert_eq!(point.sample_count, 4);
        assert_eq!(point.updated_at, 20);
    }

    #[test]
    fn prompt_variants_remain_distinct_and_participate_in_dominance() {
        let store = store();
        for (variant, quality, cost) in [("concise@1", 90.0, 10), ("verbose@1", 70.0, 12)] {
            let mut observation = observation("acme", "primary", "model-a", quality, cost, 3, 1);
            observation.prompt_variant = variant.into();
            store.record(&observation).unwrap();
        }

        let points = store.points("acme", "primary").unwrap();
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].prompt_variant, "concise@1");
        assert_eq!(points[0].quality_score, 90.0);
        assert_eq!(points[1].prompt_variant, "verbose@1");
        assert_eq!(
            store.frontier("acme", "primary").unwrap(),
            vec![points[0].clone()]
        );
    }

    #[test]
    fn allocation_returns_variant_qualified_selection() {
        let store = store();
        for (variant, quality, cost) in [("cheap@1", 85.0, 10), ("strong@2", 95.0, 30)] {
            let mut observation = observation("acme", "primary", "model-a", quality, cost, 5, 1);
            observation.prompt_variant = variant.into();
            store.record(&observation).unwrap();
        }
        let plan = store
            .allocate(
                &objective(ObjectiveMode::MinimizeCost, 100),
                &[TaskDemand {
                    task_class: "primary".into(),
                    expected_calls: 1,
                    quality_bar: Some(90.0),
                }],
            )
            .unwrap();
        assert_eq!(plan.allocations[0].model, "model-a");
        assert_eq!(plan.allocations[0].prompt_variant, "strong@2");
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
                .record(&observation("acme", "primary", model, quality, cost, 3, 1))
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
        assert!(
            store
                .record(&observation("", "primary", "model", 80.0, 1, 1, 1))
                .is_err()
        );
        assert!(
            store
                .record(&observation("acme", "primary", "", 80.0, 1, 1, 1))
                .is_err()
        );
        assert!(
            store
                .record(&observation("acme", "primary", "model", f64::NAN, 1, 1, 1))
                .is_err()
        );
        assert!(
            store
                .record(&observation("acme", "primary", "model", 80.0, -1, 1, 1))
                .is_err()
        );
    }

    fn seeded_store() -> PortfolioStore {
        let store = store();
        for (task_class, model, quality, cost) in [
            ("primary", "small", 80.0, 10),
            ("primary", "medium", 90.0, 20),
            ("primary", "large", 95.0, 50),
            ("bulk", "small", 75.0, 5),
            ("bulk", "medium", 85.0, 15),
        ] {
            store
                .record(&observation("acme", task_class, model, quality, cost, 5, 1))
                .unwrap();
        }
        store
    }

    fn objective(mode: ObjectiveMode, budget: i64) -> Objective {
        Objective {
            namespace: "acme".into(),
            mode,
            budget_usd_micros: budget,
            quality_bar: 75.0,
            min_samples: 3,
            updated_at: 1,
        }
    }

    fn observation(
        namespace: &str,
        task_class: &str,
        model: &str,
        quality_score: f64,
        cost_usd_micros: i64,
        sample_count: i64,
        updated_at: i64,
    ) -> Observation {
        Observation {
            namespace: namespace.into(),
            task_class: task_class.into(),
            model: model.into(),
            prompt_variant: LEGACY_PROMPT_VARIANT.into(),
            quality_score,
            cost_usd_micros,
            sample_count,
            updated_at,
        }
    }

    #[test]
    fn minimize_cost_selects_cheapest_points_above_quality_bars() {
        let store = seeded_store();
        let plan = store
            .allocate(
                &objective(ObjectiveMode::MinimizeCost, 100),
                &[
                    TaskDemand {
                        task_class: "primary".into(),
                        expected_calls: 2,
                        quality_bar: Some(85.0),
                    },
                    TaskDemand {
                        task_class: "bulk".into(),
                        expected_calls: 3,
                        quality_bar: None,
                    },
                ],
            )
            .unwrap();
        assert_eq!(plan.allocations[0].model, "medium");
        assert_eq!(plan.allocations[1].model, "small");
        assert_eq!(plan.total_cost_usd_micros, 55);
    }

    #[test]
    fn maximize_value_spends_budget_on_best_allocation() {
        let store = seeded_store();
        let plan = store
            .allocate(
                &objective(ObjectiveMode::MaximizeValue, 60),
                &[
                    TaskDemand {
                        task_class: "primary".into(),
                        expected_calls: 2,
                        quality_bar: None,
                    },
                    TaskDemand {
                        task_class: "bulk".into(),
                        expected_calls: 2,
                        quality_bar: None,
                    },
                ],
            )
            .unwrap();
        assert_eq!(plan.allocations[0].model, "small");
        assert_eq!(plan.allocations[1].model, "medium");
        assert_eq!(plan.total_cost_usd_micros, 50);
    }

    #[test]
    fn maximize_value_handles_upgrades_with_deferred_payoff() {
        let store = store();
        for (task_class, model, quality, cost) in [
            ("a", "a-free", 0.0, 0),
            ("a", "a-step", 1.0, 100),
            ("a", "a-best", 100.0, 101),
            ("b", "b-free", 0.0, 0),
            ("b", "b-best", 50.0, 100),
        ] {
            store
                .record(&observation("acme", task_class, model, quality, cost, 1, 1))
                .unwrap();
        }
        let mut objective = objective(ObjectiveMode::MaximizeValue, 101);
        objective.quality_bar = 0.0;
        objective.min_samples = 1;

        let plan = store
            .allocate(
                &objective,
                &[
                    TaskDemand {
                        task_class: "a".into(),
                        expected_calls: 1,
                        quality_bar: None,
                    },
                    TaskDemand {
                        task_class: "b".into(),
                        expected_calls: 1,
                        quality_bar: None,
                    },
                ],
            )
            .unwrap();
        assert_eq!(plan.allocations[0].model, "a-best");
        assert_eq!(plan.allocations[1].model, "b-free");
        assert_eq!(plan.total_value, 100.0);
        assert_eq!(plan.total_cost_usd_micros, 101);
    }

    #[test]
    fn unlimited_budget_reports_cost_overflow() {
        let store = store();
        for task_class in ["a", "b"] {
            store
                .record(&observation(
                    "acme",
                    task_class,
                    "expensive",
                    100.0,
                    i64::MAX,
                    1,
                    1,
                ))
                .unwrap();
        }
        let mut objective = objective(ObjectiveMode::MaximizeValue, 0);
        objective.min_samples = 1;
        let error = store
            .allocate(
                &objective,
                &[
                    TaskDemand {
                        task_class: "a".into(),
                        expected_calls: 1,
                        quality_bar: None,
                    },
                    TaskDemand {
                        task_class: "b".into(),
                        expected_calls: 1,
                        quality_bar: None,
                    },
                ],
            )
            .unwrap_err();
        assert!(error.contains("overflow"));
    }

    #[test]
    fn finite_budget_skips_candidates_whose_total_cost_overflows() {
        let store = store();
        for (model, quality, cost) in [("affordable", 80.0, 1), ("overflowing", 100.0, i64::MAX)] {
            store
                .record(&observation("acme", "primary", model, quality, cost, 1, 1))
                .unwrap();
        }
        let mut objective = objective(ObjectiveMode::MaximizeValue, 10);
        objective.min_samples = 1;
        let plan = store
            .allocate(
                &objective,
                &[TaskDemand {
                    task_class: "primary".into(),
                    expected_calls: 2,
                    quality_bar: None,
                }],
            )
            .unwrap();
        assert_eq!(plan.allocations[0].model, "affordable");
        assert_eq!(plan.total_cost_usd_micros, 2);
    }

    #[test]
    fn allocation_fails_when_quality_floor_is_unaffordable() {
        let store = seeded_store();
        let error = store
            .allocate(
                &objective(ObjectiveMode::MinimizeCost, 10),
                &[TaskDemand {
                    task_class: "primary".into(),
                    expected_calls: 1,
                    quality_bar: Some(90.0),
                }],
            )
            .unwrap_err();
        assert!(error.contains("above budget"));
    }

    #[test]
    fn route_changes_require_cooldown_and_repeated_confirmation() {
        let store = store();
        let initial = store
            .damped_route("acme", "primary", "small", LEGACY_PROMPT_VARIANT, 0, false)
            .unwrap();
        assert!(initial.shifted);

        for now in [1, 2] {
            let held = store
                .damped_route(
                    "acme",
                    "primary",
                    "large",
                    LEGACY_PROMPT_VARIANT,
                    now,
                    false,
                )
                .unwrap();
            assert_eq!(held.model, "small");
            assert!(!held.shifted);
        }
        let shifted = store
            .damped_route(
                "acme",
                "primary",
                "large",
                LEGACY_PROMPT_VARIANT,
                15 * 60 * 1000,
                false,
            )
            .unwrap();
        assert_eq!(shifted.model, "large");
        assert!(shifted.shifted);
    }

    #[test]
    fn forced_regression_route_bypasses_damping() {
        let store = store();
        store
            .damped_route("acme", "primary", "small", LEGACY_PROMPT_VARIANT, 0, false)
            .unwrap();
        let reverted = store
            .damped_route("acme", "primary", "capable", LEGACY_PROMPT_VARIANT, 1, true)
            .unwrap();
        assert_eq!(reverted.model, "capable");
        assert_eq!(reverted.previous_model, "small");
        assert!(reverted.shifted);
    }

    #[test]
    fn variant_only_route_change_uses_existing_damping() {
        let store = store();
        store
            .damped_route("acme", "primary", "model-a", "prompt@1", 0, false)
            .unwrap();
        for now in [15 * 60 * 1000, 15 * 60 * 1000 + 1] {
            let held = store
                .damped_route("acme", "primary", "model-a", "prompt@2", now, false)
                .unwrap();
            assert_eq!(held.prompt_variant, "prompt@1");
            assert!(!held.shifted);
        }
        let shifted = store
            .damped_route(
                "acme",
                "primary",
                "model-a",
                "prompt@2",
                15 * 60 * 1000 + 2,
                false,
            )
            .unwrap();
        assert!(shifted.shifted);
        assert_eq!(shifted.model, "model-a");
        assert_eq!(shifted.prompt_variant, "prompt@2");
        assert_eq!(shifted.previous_prompt_variant, "prompt@1");
    }
}
