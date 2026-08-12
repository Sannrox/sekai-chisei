use std::collections::HashMap;
use std::sync::Arc;

use crate::db::chisei_budget::{METRIC_TOKENS, scope_chain};
use crate::db::runtime_db::RuntimeDb;
#[cfg(test)]
use crate::db::sekai::SekaiDb;
use crate::sekai::audit::Decision;

pub use crate::db::chisei_budget::BudgetTransferRecord;

/// Operator-visible multi-region budget topology (#294).
///
/// `active_active_global_sc` is intentionally **not** a supported mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BudgetTopologyMode {
    /// Single shared store / single site (default). Today's chain reserve.
    #[default]
    SingleRegion,
    /// Per-scope home site pins; foreign pin fails closed; no transfer.
    RegionalPinned,
    /// Regional homes plus rare audited transfer of limit capacity for pools.
    RegionalWithTransfer,
}

impl BudgetTopologyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleRegion => "single_region",
            Self::RegionalPinned => "regional_pinned",
            Self::RegionalWithTransfer => "regional_with_transfer",
        }
    }

    /// Parse config values. Unknown / rejected modes (including global SC) err.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "single_region" | "single-region" | "single" => Ok(Self::SingleRegion),
            "regional_pinned" | "regional-pinned" | "pinned" => Ok(Self::RegionalPinned),
            "regional_with_transfer" | "regional-with-transfer" | "transfer" => {
                Ok(Self::RegionalWithTransfer)
            }
            "active_active_global_sc" | "global_sc" | "active_active" => Err(
                "budget topology active_active_global_sc is not supported; use single_region, regional_pinned, or regional_with_transfer"
                    .into(),
            ),
            other => Err(format!(
                "unsupported budget topology mode '{other}'; expected single_region, regional_pinned, or regional_with_transfer"
            )),
        }
    }

    pub fn requires_home_pin(self) -> bool {
        !matches!(self, Self::SingleRegion)
    }

    pub fn allows_transfer(self) -> bool {
        matches!(self, Self::RegionalWithTransfer)
    }
}

/// Process-local budget authority topology settings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BudgetTopologyConfig {
    pub mode: BudgetTopologyMode,
    /// Local site identity used for home-pin checks (independent of #293).
    pub site_id: String,
    /// When true, refuse transfers and any debit that cannot prove pooled ceilings.
    pub partition_simulated: bool,
}

impl BudgetTopologyConfig {
    pub fn from_env() -> Result<Self, String> {
        let mode_raw = std::env::var("SEKAI_BUDGET_TOPOLOGY")
            .or_else(|_| std::env::var("BUDGET_TOPOLOGY_MODE"))
            .unwrap_or_default();
        let mode = BudgetTopologyMode::parse(&mode_raw)?;
        let site_id = std::env::var("SEKAI_BUDGET_SITE_ID")
            .or_else(|_| std::env::var("BUDGET_SITE_ID"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let partition_simulated = matches!(
            std::env::var("SEKAI_BUDGET_PARTITION_SIMULATED")
                .unwrap_or_default()
                .trim(),
            "1" | "true" | "TRUE" | "yes" | "YES"
        );
        if mode.requires_home_pin() && site_id.is_empty() {
            return Err(
                "SEKAI_BUDGET_SITE_ID (or BUDGET_SITE_ID) is required when budget topology is regional_pinned or regional_with_transfer"
                    .into(),
            );
        }
        Ok(Self {
            mode,
            site_id,
            partition_simulated,
        })
    }

    pub fn single_region() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PeriodType {
    Daily,
    Weekly,
    Monthly,
}

impl PeriodType {
    /// Parse untrusted period type inputs. Unknown values return `Err` so callers
    /// can surface a clear invalid-argument rejection.
    pub fn parse_strict(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "day" | "days" | "daily" => Ok(Self::Daily),
            "week" | "weeks" | "weekly" => Ok(Self::Weekly),
            "month" | "months" | "monthly" => Ok(Self::Monthly),
            value => Err(format!("unsupported period type '{value}'")),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "week" | "weeks" | "weekly" => Self::Weekly,
            "month" | "months" | "monthly" => Self::Monthly,
            "day" | "days" | "daily" => Self::Daily,
            _ => Self::Daily,
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Usage {
    pub user_id: String,
    pub tokens_used: i32,
    pub max_tokens: i32,
    pub period_type: PeriodType,
    pub period_start: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PressureLevel {
    None,
    Moderate,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetRouteBias {
    Capable,
    Cheap,
}

impl BudgetRouteBias {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capable => "capable",
            Self::Cheap => "cheap",
        }
    }
}

const CHEAP_BIAS_THRESHOLD_PERCENT: i64 = 70;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Token-budget enforcement over the hierarchical scope chain persisted in
/// `chisei_budget_limits`/`chisei_budget_usage` (see `db::chisei_budget`).
///
/// `user_id`/`subject` arguments here are scope ids: either a flat legacy
/// subject (e.g. an explicit `subject` field, chaining only through the
/// unset `global` root) or a `/`-joined hierarchical id such as
/// `project:p/agent:a/work_unit:w`, whose ancestors (`global`, `project:p`,
/// `project:p/agent:a`) are all checked and deducted together atomically.
///
/// Gateway preflight, fat-decide budget admission, and
/// auto-allocation paths that share this tracker all hit the **same** store
/// APIs — there is no process-local or region-shadow ledger for durable spend.
pub struct BudgetTracker {
    db: Arc<RuntimeDb>,
    topology: BudgetTopologyConfig,
}

impl BudgetTracker {
    pub fn new(db: Arc<RuntimeDb>) -> Self {
        Self {
            db,
            topology: BudgetTopologyConfig::single_region(),
        }
    }

    pub fn with_topology(db: Arc<RuntimeDb>, topology: BudgetTopologyConfig) -> Self {
        Self { db, topology }
    }

    pub fn topology(&self) -> &BudgetTopologyConfig {
        &self.topology
    }

    fn require_home_pin(&self) -> bool {
        self.topology.mode.requires_home_pin()
    }

    fn local_site_id(&self) -> &str {
        &self.topology.site_id
    }

    pub fn set_limit(
        &self,
        scope_id: &str,
        max_tokens: i32,
        period: PeriodType,
    ) -> Result<(), String> {
        self.set_limit_with_metric(scope_id, METRIC_TOKENS, max_tokens, period)
    }

    pub fn set_limit_with_metric(
        &self,
        scope_id: &str,
        metric: &str,
        max_tokens: i32,
        period: PeriodType,
    ) -> Result<(), String> {
        self.set_limit_scoped(scope_id, metric, max_tokens, period, "", "")
    }

    /// Set a scope limit with optional home site pin and pool membership.
    ///
    /// `home_site_id` is required for durable multi-region pins under
    /// `regional_pinned` / `regional_with_transfer`. `pool_id` groups scopes
    /// under a combined ceiling enforced by
    /// [`Self::set_pool_ceiling`] + transfer invariants.
    pub fn set_limit_scoped(
        &self,
        scope_id: &str,
        metric: &str,
        max_tokens: i32,
        period: PeriodType,
        home_site_id: &str,
        pool_id: &str,
    ) -> Result<(), String> {
        let home = if home_site_id.trim().is_empty() && self.require_home_pin() {
            self.local_site_id()
        } else {
            home_site_id.trim()
        };
        self.db
            .budget_set_limit_scoped(
                scope_id,
                metric,
                max_tokens as i64,
                period.as_str(),
                home,
                pool_id.trim(),
            )
            .inspect_err(
                |err| tracing::error!(error = %err, scope_id, "failed to persist budget limit"),
            )
    }

    /// Declare a pooled combined ceiling for scopes sharing `pool_id`.
    pub fn set_pool_ceiling(
        &self,
        pool_id: &str,
        metric: &str,
        max_amount: i64,
        period: PeriodType,
    ) -> Result<(), String> {
        if !self.topology.mode.allows_transfer() && self.topology.mode.requires_home_pin() {
            // regional_pinned may still declare independent regional ceilings
            // without a shared pool; pool ceilings are for transfer topology.
        }
        self.db
            .budget_set_pool_ceiling(pool_id, metric, max_amount, period.as_str())
    }

    pub fn check(&self, scope_id: &str, estimated: i32) -> Result<(), String> {
        self.check_with_metric(scope_id, estimated, METRIC_TOKENS)
    }

    pub fn check_with_metric(
        &self,
        scope_id: &str,
        estimated: i32,
        metric: &str,
    ) -> Result<(), String> {
        self.db.budget_check_chain_for_site(
            scope_id,
            metric,
            estimated as i64,
            now_ms(),
            self.require_home_pin(),
            self.local_site_id(),
            self.topology.partition_simulated,
        )
    }

    /// Atomically checks budget headroom across the whole ancestor chain and
    /// reserves `estimated` at every level.
    pub fn check_and_reserve(&self, scope_id: &str, estimated: i32) -> Result<(), String> {
        self.check_and_reserve_with_metric(scope_id, estimated, METRIC_TOKENS)
    }

    pub fn check_and_reserve_with_metric(
        &self,
        scope_id: &str,
        estimated: i32,
        metric: &str,
    ) -> Result<(), String> {
        self.db.budget_check_and_reserve_chain_for_site(
            scope_id,
            metric,
            estimated as i64,
            now_ms(),
            None,
            self.require_home_pin(),
            self.local_site_id(),
            self.topology.partition_simulated,
        )
    }

    pub fn check_and_reserve_idempotent(
        &self,
        scope_id: &str,
        estimated: i32,
        idempotency_key: &str,
    ) -> Result<(), String> {
        self.db.budget_check_and_reserve_chain_for_site(
            scope_id,
            METRIC_TOKENS,
            i64::from(estimated),
            now_ms(),
            Some(idempotency_key),
            self.require_home_pin(),
            self.local_site_id(),
            self.topology.partition_simulated,
        )
    }

    /// Rare audited movement of **limit capacity** between scope homes.
    /// Not a 2PC on live request traffic — only for `regional_with_transfer`.
    pub fn transfer_capacity(
        &self,
        transfer_id: &str,
        from_scope_id: &str,
        to_scope_id: &str,
        amount: i64,
        metric: &str,
        actor: &str,
    ) -> Result<BudgetTransferRecord, String> {
        if !self.topology.mode.allows_transfer() {
            return Err(format!(
                "budget transfer requires regional_with_transfer topology (current={})",
                self.topology.mode.as_str()
            ));
        }
        if self.topology.partition_simulated {
            let had = self.db.budget_get_transfer(transfer_id)?.is_some();
            let refused = self.db.budget_record_transfer_refused(
                transfer_id,
                metric,
                from_scope_id,
                to_scope_id,
                amount,
                actor,
                "partition_simulated: transfer refused fail-closed",
                now_ms(),
            )?;
            if !had {
                self.audit_transfer(&refused, actor)?;
            }
            return Err(format!(
                "budget transfer refused under partition: {}",
                refused.reason
            ));
        }
        let had = self.db.budget_get_transfer(transfer_id)?.is_some();
        let record = self.db.budget_transfer_capacity(
            transfer_id,
            metric,
            from_scope_id,
            to_scope_id,
            amount,
            actor,
            now_ms(),
        )?;
        if !had {
            self.audit_transfer(&record, actor)?;
        }
        Ok(record)
    }

    pub fn get_transfer(&self, transfer_id: &str) -> Result<Option<BudgetTransferRecord>, String> {
        self.db.budget_get_transfer(transfer_id)
    }

    fn audit_transfer(&self, record: &BudgetTransferRecord, actor: &str) -> Result<(), String> {
        let mut evidence = HashMap::new();
        evidence.insert("transfer_id".into(), record.transfer_id.clone());
        evidence.insert("metric".into(), record.metric.clone());
        evidence.insert("pool_id".into(), record.pool_id.clone());
        evidence.insert("from_scope_id".into(), record.from_scope_id.clone());
        evidence.insert("to_scope_id".into(), record.to_scope_id.clone());
        evidence.insert("amount".into(), record.amount.to_string());
        evidence.insert("status".into(), record.status.clone());
        evidence.insert("topology".into(), self.topology.mode.as_str().into());
        evidence.insert("site_id".into(), self.topology.site_id.clone());
        if !record.reason.is_empty() {
            evidence.insert("reason".into(), record.reason.clone());
        }
        let decision = Decision {
            id: format!("budget-transfer:{}", record.transfer_id),
            timestamp: record.created_at,
            actor: actor.to_string(),
            action: "budget.transfer".into(),
            reason: if record.status == "completed" {
                "audited budget capacity transfer".into()
            } else {
                format!("budget transfer {}", record.status)
            },
            evidence,
            target_id: record.from_scope_id.clone(),
            outcome: record.status.clone(),
        };
        self.db.record_decision(&decision)
    }

    /// Adjust reservation to actual usage after the call completes.
    pub fn adjust(&self, scope_id: &str, reserved: i32, actual: i32) {
        self.adjust_with_metric(scope_id, reserved, actual, METRIC_TOKENS)
    }

    pub fn adjust_with_metric(&self, scope_id: &str, reserved: i32, actual: i32, metric: &str) {
        let delta = actual as i64 - reserved as i64;
        if let Err(err) = self.db.budget_adjust_chain_for_site(
            scope_id,
            metric,
            delta,
            now_ms(),
            self.require_home_pin(),
            self.local_site_id(),
        ) {
            tracing::error!(error = %err, scope_id, "failed to adjust budget usage");
        }
    }

    pub fn record(&self, scope_id: &str, tokens: i32) {
        self.record_with_metric(scope_id, tokens, METRIC_TOKENS)
    }

    pub fn record_with_metric(&self, scope_id: &str, amount: i32, metric: &str) {
        if let Err(err) = self.db.budget_adjust_chain_for_site(
            scope_id,
            metric,
            amount as i64,
            now_ms(),
            self.require_home_pin(),
            self.local_site_id(),
        ) {
            tracing::error!(error = %err, scope_id, "failed to record budget usage");
        }
    }

    pub fn record_idempotent_with_metric(
        &self,
        scope_id: &str,
        amount: i32,
        metric: &str,
        idempotency_key: &str,
    ) -> Result<bool, String> {
        // Idempotent record still goes through the shared store; pin is
        // enforced on positive debits of limited scopes.
        if amount > 0 && self.require_home_pin() {
            self.db
                .budget_assert_home_writable(scope_id, metric, self.local_site_id())?;
        }
        self.db.budget_record_idempotent(
            scope_id,
            metric,
            i64::from(amount),
            idempotency_key,
            now_ms(),
        )
    }

    pub fn get_usage(&self, scope_id: &str) -> Usage {
        self.get_usage_with_metric(scope_id, METRIC_TOKENS)
    }

    pub fn get_usage_with_metric(&self, scope_id: &str, metric: &str) -> Usage {
        let (used, max, period_type) = self
            .db
            .budget_usage(scope_id, metric, now_ms())
            .unwrap_or((0, 0, "daily".to_string()));
        Usage {
            user_id: scope_id.into(),
            tokens_used: used as i32,
            max_tokens: max as i32,
            period_type: PeriodType::parse(&period_type),
            period_start: 0,
        }
    }

    /// Returns the bounded scope with the least remaining headroom in the
    /// hierarchy. When the whole chain is unlimited, preserves the requested
    /// scope's ordinary zero-limit usage representation.
    pub fn most_constrained_usage_with_metric(&self, scope_id: &str, metric: &str) -> Usage {
        scope_chain(scope_id)
            .into_iter()
            .map(|scope| self.get_usage_with_metric(&scope, metric))
            .filter(|usage| usage.max_tokens > 0)
            .min_by_key(|usage| usage.max_tokens.saturating_sub(usage.tokens_used))
            .unwrap_or_else(|| self.get_usage_with_metric(scope_id, metric))
    }

    /// Maps projected token-budget pressure to an advisory routing bias. The
    /// most constrained bounded scope in the hierarchy wins. Unknown, primary,
    /// and reasoning work stay capable by default; request-count quotas never
    /// influence model selection.
    pub fn route_bias(
        &self,
        scope_id: &str,
        estimated: i32,
        metric: &str,
        task_class: &str,
    ) -> BudgetRouteBias {
        if metric != METRIC_TOKENS
            || !crate::chisei::model_routing::is_cheap_eligible_task_class(task_class)
        {
            return BudgetRouteBias::Capable;
        }

        let pressured = self
            .projected_pressure_percent(scope_id, estimated, metric)
            .is_some_and(|pressure| pressure >= CHEAP_BIAS_THRESHOLD_PERCENT);
        if pressured {
            BudgetRouteBias::Cheap
        } else {
            BudgetRouteBias::Capable
        }
    }

    /// Highest projected utilization across the bounded hierarchy. `None`
    /// means no scope in the chain has a limit for this metric.
    pub fn projected_pressure_percent(
        &self,
        scope_id: &str,
        estimated: i32,
        metric: &str,
    ) -> Option<i64> {
        let projected = i64::from(estimated.max(0));
        scope_chain(scope_id)
            .into_iter()
            .filter_map(|scope| {
                let usage = self.get_usage_with_metric(&scope, metric);
                let limit = i64::from(usage.max_tokens);
                (limit > 0).then(|| {
                    (i64::from(usage.tokens_used).max(0) + projected).saturating_mul(100) / limit
                })
            })
            .max()
    }

    pub fn namespace_pressure(&self, namespace: &str) -> PressureLevel {
        let level = self
            .db
            .budget_namespace_pressure(namespace, METRIC_TOKENS, now_ms())
            .unwrap_or(0);
        match level {
            2 => PressureLevel::Critical,
            1 => PressureLevel::Moderate,
            _ => PressureLevel::None,
        }
    }

    pub fn scope_pressure(&self, scope_id: &str) -> PressureLevel {
        match self.projected_pressure_percent(scope_id, 0, METRIC_TOKENS) {
            Some(percent) if percent >= 90 => PressureLevel::Critical,
            Some(percent) if percent >= 70 => PressureLevel::Moderate,
            _ => PressureLevel::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> BudgetTracker {
        BudgetTracker::new(Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        ))))
    }

    fn tracker_with(topology: BudgetTopologyConfig) -> BudgetTracker {
        BudgetTracker::with_topology(
            Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
                SekaiDb::new(":memory:").unwrap(),
            ))),
            topology,
        )
    }

    #[test]
    fn topology_default_is_single_region() {
        let t = tracker();
        assert_eq!(t.topology().mode, BudgetTopologyMode::SingleRegion);
        assert!(!t.topology().mode.requires_home_pin());
        assert!(!t.topology().mode.allows_transfer());
    }

    #[test]
    fn topology_parse_rejects_global_sc() {
        assert!(BudgetTopologyMode::parse("active_active_global_sc").is_err());
        assert!(BudgetTopologyMode::parse("global_sc").is_err());
        assert_eq!(
            BudgetTopologyMode::parse("single_region").unwrap(),
            BudgetTopologyMode::SingleRegion
        );
        assert_eq!(
            BudgetTopologyMode::parse("regional_with_transfer").unwrap(),
            BudgetTopologyMode::RegionalWithTransfer
        );
    }

    #[test]
    fn foreign_home_pin_fails_closed_on_reserve() {
        let t = tracker_with(BudgetTopologyConfig {
            mode: BudgetTopologyMode::RegionalPinned,
            site_id: "us-east".into(),
            partition_simulated: false,
        });
        t.set_limit_scoped(
            "region:eu",
            METRIC_TOKENS,
            100,
            PeriodType::Daily,
            "eu-west",
            "",
        )
        .unwrap();
        let err = t.check_and_reserve("region:eu", 10).unwrap_err();
        assert!(
            err.contains("pinned") || err.contains("home"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn regional_with_transfer_partition_cannot_overspend_combined_ceiling() {
        // Combined pool ceiling 100, pre-split us=60 / eu=40. Under partition,
        // each home can only spend its local allocation; total ≤ 100.
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let us = BudgetTracker::with_topology(
            db.clone(),
            BudgetTopologyConfig {
                mode: BudgetTopologyMode::RegionalWithTransfer,
                site_id: "us-east".into(),
                partition_simulated: true,
            },
        );
        let eu = BudgetTracker::with_topology(
            db.clone(),
            BudgetTopologyConfig {
                mode: BudgetTopologyMode::RegionalWithTransfer,
                site_id: "eu-west".into(),
                partition_simulated: true,
            },
        );
        us.set_pool_ceiling("org", METRIC_TOKENS, 100, PeriodType::Daily)
            .unwrap();
        us.set_limit_scoped(
            "region:us",
            METRIC_TOKENS,
            60,
            PeriodType::Daily,
            "us-east",
            "org",
        )
        .unwrap();
        eu.set_limit_scoped(
            "region:eu",
            METRIC_TOKENS,
            40,
            PeriodType::Daily,
            "eu-west",
            "org",
        )
        .unwrap();

        assert!(us.check_and_reserve("region:us", 60).is_ok());
        assert!(eu.check_and_reserve("region:eu", 40).is_ok());
        assert!(us.check_and_reserve("region:us", 1).is_err());
        assert!(eu.check_and_reserve("region:eu", 1).is_err());
        // Foreign pin still fails closed under partition.
        assert!(us.check_and_reserve("region:eu", 1).is_err());

        let used_us = us.get_usage("region:us").tokens_used;
        let used_eu = eu.get_usage("region:eu").tokens_used;
        assert_eq!(used_us + used_eu, 100);
        assert!(used_us + used_eu <= 100);

        // Transfer refused under partition (fail closed).
        let err = us
            .transfer_capacity(
                "xfer-part-1",
                "region:us",
                "region:eu",
                10,
                METRIC_TOKENS,
                "ops",
            )
            .unwrap_err();
        assert!(err.contains("partition"), "{err}");
        let refused = us.get_transfer("xfer-part-1").unwrap().unwrap();
        assert_eq!(refused.status, "refused");
    }

    #[test]
    fn transfer_moves_capacity_and_is_audited_idempotent() {
        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let t = BudgetTracker::with_topology(
            db.clone(),
            BudgetTopologyConfig {
                mode: BudgetTopologyMode::RegionalWithTransfer,
                site_id: "us-east".into(),
                partition_simulated: false,
            },
        );
        t.set_pool_ceiling("org", METRIC_TOKENS, 100, PeriodType::Daily)
            .unwrap();
        t.set_limit_scoped(
            "region:us",
            METRIC_TOKENS,
            100,
            PeriodType::Daily,
            "us-east",
            "org",
        )
        .unwrap();
        t.set_limit_scoped(
            "region:eu",
            METRIC_TOKENS,
            0,
            PeriodType::Daily,
            "eu-west",
            "org",
        )
        .unwrap();

        let first = t
            .transfer_capacity(
                "xfer-1",
                "region:us",
                "region:eu",
                40,
                METRIC_TOKENS,
                "operator",
            )
            .unwrap();
        assert_eq!(first.status, "completed");
        assert_eq!(first.amount, 40);
        // Replay same transfer_id is idempotent.
        let replay = t
            .transfer_capacity(
                "xfer-1",
                "region:us",
                "region:eu",
                40,
                METRIC_TOKENS,
                "operator",
            )
            .unwrap();
        assert_eq!(replay.status, "completed");
        assert_eq!(t.get_usage("region:us").max_tokens, 60);
        assert_eq!(t.get_usage("region:eu").max_tokens, 40);

        // Audit decision recorded.
        let decisions = db
            .list_decisions(&crate::sekai::audit::DecisionFilter {
                action: Some("budget.transfer".into()),
                target_id: Some("region:us".into()),
                ..Default::default()
            })
            .unwrap();
        assert!(
            decisions.iter().any(|d| d.id == "budget-transfer:xfer-1"),
            "missing transfer audit: {decisions:?}"
        );

        // After transfer, local home can spend its remaining share only.
        assert!(t.check_and_reserve("region:us", 60).is_ok());
        assert!(t.check_and_reserve("region:us", 1).is_err());
    }

    #[test]
    fn dual_home_race_against_split_limits_never_overspends_pool() {
        use std::sync::Barrier;
        use std::thread;

        let db = Arc::new(RuntimeDb::Sqlite(std::sync::Arc::new(
            SekaiDb::new(":memory:").unwrap(),
        )));
        let setup = BudgetTracker::with_topology(
            db.clone(),
            BudgetTopologyConfig {
                mode: BudgetTopologyMode::RegionalWithTransfer,
                site_id: "us-east".into(),
                partition_simulated: false,
            },
        );
        setup
            .set_pool_ceiling("org", METRIC_TOKENS, 100, PeriodType::Daily)
            .unwrap();
        setup
            .set_limit_scoped(
                "region:us",
                METRIC_TOKENS,
                50,
                PeriodType::Daily,
                "us-east",
                "org",
            )
            .unwrap();
        setup
            .set_limit_scoped(
                "region:eu",
                METRIC_TOKENS,
                50,
                PeriodType::Daily,
                "eu-west",
                "org",
            )
            .unwrap();

        let barrier = Arc::new(Barrier::new(20));
        let mut handles = Vec::new();
        for i in 0..20 {
            let db = db.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                let site = if i % 2 == 0 { "us-east" } else { "eu-west" };
                let scope = if i % 2 == 0 { "region:us" } else { "region:eu" };
                let t = BudgetTracker::with_topology(
                    db,
                    BudgetTopologyConfig {
                        mode: BudgetTopologyMode::RegionalWithTransfer,
                        site_id: site.into(),
                        partition_simulated: true,
                    },
                );
                barrier.wait();
                t.check_and_reserve(scope, 10).is_ok()
            }));
        }
        let admitted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        // Each region admits at most 5 × 10 = 50 → combined ≤ 100.
        assert!(admitted <= 10, "admitted {admitted}");
        let used =
            setup.get_usage("region:us").tokens_used + setup.get_usage("region:eu").tokens_used;
        assert!(used <= 100, "combined used {used}");
        assert_eq!(used, admitted as i32 * 10);
    }

    #[test]
    fn test_budget_check_and_record() {
        let t = tracker();
        t.set_limit("alice", 1000, PeriodType::Daily).unwrap();
        assert!(t.check("alice", 500).is_ok());
        t.record("alice", 800);
        assert!(t.check("alice", 300).is_err());
        assert!(t.check("alice", 100).is_ok()); // 800+100 < 1000... wait no 800+100=900 <= 1000
    }

    #[test]
    fn test_no_limit_allows_all() {
        let t = tracker();
        assert!(t.check("bob", 999999).is_ok());
    }

    #[test]
    fn test_pressure() {
        let t = tracker();
        t.set_limit("ns1:alice", 100, PeriodType::Daily).unwrap();
        t.record("ns1:alice", 75);
        assert_eq!(t.namespace_pressure("ns1"), PressureLevel::Moderate);
        t.record("ns1:alice", 20);
        assert_eq!(t.namespace_pressure("ns1"), PressureLevel::Critical);
    }

    #[test]
    fn budget_bias_downgrades_only_eligible_work_under_chain_pressure() {
        let t = tracker();
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        t.record("project:p/agent:a", 65);

        assert_eq!(
            t.route_bias("project:p/agent:a", 5, METRIC_TOKENS, "background"),
            BudgetRouteBias::Cheap
        );
        assert_eq!(
            t.route_bias("project:p/agent:a", 5, METRIC_TOKENS, "primary"),
            BudgetRouteBias::Capable
        );
        assert_eq!(
            t.route_bias("project:p/agent:a", 5, METRIC_TOKENS, "reasoning"),
            BudgetRouteBias::Capable
        );
        assert_eq!(
            t.route_bias("project:p/agent:a", 5, METRIC_TOKENS, "unknown"),
            BudgetRouteBias::Capable
        );
    }

    #[test]
    fn budget_bias_stays_capable_without_pressure_or_for_non_token_quotas() {
        let t = tracker();
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        t.record("project:p", 10);
        assert_eq!(
            t.route_bias("project:p", 5, METRIC_TOKENS, "bulk"),
            BudgetRouteBias::Capable
        );
        assert_eq!(
            t.route_bias("project:p", 100, "requests", "bulk"),
            BudgetRouteBias::Capable
        );
    }

    #[test]
    fn parent_cap_rejects_child_within_its_own_limit() {
        let t = tracker();
        // Project-level pool of 100 shared across agents; agent's own cap is
        // generous (500) but the project ancestor is nearly exhausted.
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        t.set_limit("project:p/agent:a", 500, PeriodType::Daily)
            .unwrap();
        t.record("project:p/agent:a", 90);
        // Agent-level check alone would allow (90+20=110 <= 500) but the
        // project ancestor (90+20=110 > 100) must reject it.
        assert!(t.check_and_reserve("project:p/agent:a", 20).is_err());
        // A smaller request that fits under both levels succeeds.
        assert!(t.check_and_reserve("project:p/agent:a", 5).is_ok());
    }

    #[test]
    fn most_constrained_usage_reports_limiting_ancestor() {
        let t = tracker();
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        t.set_limit("project:p/agent:a", 500, PeriodType::Daily)
            .unwrap();
        t.record("project:p/agent:a/work_unit:w", 80);

        let usage =
            t.most_constrained_usage_with_metric("project:p/agent:a/work_unit:w", METRIC_TOKENS);
        assert_eq!(usage.user_id, "project:p");
        assert_eq!(usage.tokens_used, 80);
        assert_eq!(usage.max_tokens, 100);
    }

    #[test]
    fn checks_and_records_against_flat_agent_scope() {
        let t = tracker();
        t.set_limit("agent:codex-app", 100, PeriodType::Daily)
            .unwrap();
        t.set_limit("project:p", 500, PeriodType::Daily).unwrap();
        t.record("project:p/agent:codex-app", 90);
        assert_eq!(t.get_usage("agent:codex-app").tokens_used, 90);
        assert_eq!(t.get_usage("project:p").tokens_used, 90);
        assert!(t.check("project:p/agent:codex-app", 5).is_ok());
        assert!(
            t.check_and_reserve("project:p/agent:codex-app", 11)
                .is_err()
        );
    }

    #[test]
    fn chain_deducts_at_every_level() {
        let t = tracker();
        t.set_limit("project:p", 1000, PeriodType::Daily).unwrap();
        t.set_limit("project:p/agent:a", 1000, PeriodType::Daily)
            .unwrap();
        t.check_and_reserve("project:p/agent:a/work_unit:w", 40)
            .unwrap();
        assert_eq!(t.get_usage("project:p").tokens_used, 40);
        assert_eq!(t.get_usage("project:p/agent:a").tokens_used, 40);
        assert_eq!(t.get_usage("project:p/agent:a/work_unit:w").tokens_used, 40);
    }

    #[test]
    fn parse_strict_period_type_accepts_aliases_and_rejects_unknown() {
        assert!(PeriodType::parse_strict("day").is_ok());
        assert!(PeriodType::parse_strict("Week").is_ok());
        assert!(PeriodType::parse_strict("monthly").is_ok());
        assert!(PeriodType::parse_strict("months").is_ok());
        assert!(PeriodType::parse_strict("").is_ok());
        assert!(PeriodType::parse_strict("fiscal").is_err());
    }

    #[test]
    fn parse_period_type_defaults_untrusted_to_daily() {
        assert!(matches!(PeriodType::parse("fiscal"), PeriodType::Daily));
        assert!(matches!(PeriodType::parse("yearly"), PeriodType::Daily));
    }

    #[test]
    fn later_ancestor_limit_sees_prior_unbounded_usage() {
        let t = tracker();
        // No limit anywhere yet: usage still accrues at every level.
        t.record("project:p/agent:a", 30);
        // Now cap the project after the fact — it should already see the 30
        // recorded while unbounded, and reject a request that would exceed it.
        t.set_limit("project:p", 40, PeriodType::Daily).unwrap();
        assert!(t.check_and_reserve("project:p/agent:a", 20).is_err());
        assert!(t.check_and_reserve("project:p/agent:a", 5).is_ok());
    }

    #[test]
    fn concurrent_reservations_never_over_admit_shared_parent() {
        use std::thread;
        let t = Arc::new(tracker());
        t.set_limit("project:p", 100, PeriodType::Daily).unwrap();
        let mut handles = Vec::new();
        for i in 0..20 {
            let t = t.clone();
            handles.push(thread::spawn(move || {
                t.check_and_reserve(&format!("project:p/agent:a{i}"), 10)
                    .is_ok()
            }));
        }
        let admitted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(admitted, 10);
        assert_eq!(t.get_usage("project:p").tokens_used, 100);
    }

    #[test]
    fn concurrent_adjusts_do_not_lose_usage_updates() {
        use std::sync::Barrier;
        use std::thread;
        let t = Arc::new(tracker());
        t.set_limit("project:p", 10_000, PeriodType::Daily).unwrap();
        t.record("project:p", 0);
        let barrier = Arc::new(Barrier::new(20));
        let mut handles = Vec::new();
        for _ in 0..20 {
            let t = t.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                t.record("project:p", 5);
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(t.get_usage("project:p").tokens_used, 100);
    }
}
