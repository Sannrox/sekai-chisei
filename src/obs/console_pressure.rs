//! Governance pressure view for the operator console (Issue #286).
//!
//! Near-live tiles from existing public projections: operation statistics and
//! Gunshi allocation status / kill switch. No shadow database.

use crate::chisei::gunshi_auto::{self, NamespaceAllocationStatus};
use crate::db::runtime_db::RuntimeDb;
use crate::obs::console::{is_safe_namespace, principal_can_access_namespace};
use crate::operation_statistics::{self, OperationStatistics};
use crate::sekai::security::Role;
use serde::Serialize;

/// Default pressure window (24 hours).
pub const PRESSURE_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;

/// Documented refresh semantics: clients may reload this route on an operator-
/// chosen interval; the server is request/response only (no SSE in v1).
pub const PRESSURE_REFRESH_SEMANTICS: &str = "Request/response only. Reload the page or poll GET /console/n/{ns}/pressure \
     (or /console/api/n/{ns}/pressure) on an operator-chosen interval. \
     There is no SSE or shadow database for v1.";

#[derive(Debug, Clone, Serialize)]
pub struct PressureSnapshot {
    pub namespace: String,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub statistics: StatisticsTiles,
    pub gunshi: GunshiTiles,
    pub refresh_semantics: &'static str,
    pub can_mutate_kill_switch: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatisticsTiles {
    pub logical_operations: i64,
    pub receipts: i64,
    pub model_calls: i64,
    pub total_cost_usd_micros: i64,
    pub outcomes_rejected: i64,
    pub outcomes_failed: i64,
    pub outcomes_verified: i64,
    pub waiting_operations: i64,
    pub learnings_admitted: i64,
    pub available: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GunshiTiles {
    pub installed: bool,
    pub active_revision_id: Option<String>,
    pub auto_opt_in: bool,
    pub kill_switch: bool,
    pub kill_switch_reason: String,
    pub auto_dispatch_live: bool,
    pub changed_at_ms: Option<i64>,
    pub error: Option<String>,
}

impl From<&OperationStatistics> for StatisticsTiles {
    fn from(stats: &OperationStatistics) -> Self {
        Self {
            logical_operations: stats.totals.logical_operations,
            receipts: stats.totals.receipts,
            model_calls: stats.totals.model_calls,
            total_cost_usd_micros: stats.totals.total_cost_usd_micros,
            outcomes_rejected: stats.outcomes.rejected,
            outcomes_failed: stats.outcomes.failed,
            outcomes_verified: stats.outcomes.verified,
            waiting_operations: stats.totals.waiting_operations,
            learnings_admitted: stats.learning.learnings_admitted,
            available: true,
            error: None,
        }
    }
}

impl From<&NamespaceAllocationStatus> for GunshiTiles {
    fn from(status: &NamespaceAllocationStatus) -> Self {
        Self {
            installed: true,
            active_revision_id: Some(status.active_revision_id.clone()),
            auto_opt_in: status.auto_opt_in,
            kill_switch: status.kill_switch,
            kill_switch_reason: status.kill_switch_reason.clone(),
            auto_dispatch_live: status.auto_dispatch_live,
            changed_at_ms: Some(status.changed_at_ms),
            error: None,
        }
    }
}

fn empty_gunshi() -> GunshiTiles {
    GunshiTiles {
        installed: false,
        active_revision_id: None,
        auto_opt_in: false,
        kill_switch: false,
        kill_switch_reason: String::new(),
        auto_dispatch_live: false,
        changed_at_ms: None,
        error: None,
    }
}

/// Namespace write access for kill-switch (mirrors gRPC require_namespace_write_access).
pub fn principal_can_write_namespace(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
) -> Result<bool, String> {
    if !is_safe_namespace(namespace) {
        return Ok(false);
    }
    if matches!(principal, "root" | "local") {
        return Ok(true);
    }
    let memberships = db.list_namespace_roles_for_principal(principal)?;
    Ok(memberships
        .iter()
        .any(|(ns, role)| ns == namespace && matches!(role, Role::Editor | Role::Admin)))
}

pub fn load_pressure_snapshot(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
) -> Result<PressureSnapshot, String> {
    if !is_safe_namespace(namespace) {
        return Err("invalid namespace".into());
    }
    if !principal_can_access_namespace(db, principal, namespace).unwrap_or(false) {
        return Err("namespace access denied".into());
    }
    let end = chrono::Utc::now().timestamp_millis();
    let start = end.saturating_sub(PRESSURE_WINDOW_MS);
    let statistics = match operation_statistics::query_operation_statistics(
        db,
        &[namespace.to_string()],
        start,
        end,
    ) {
        Ok(stats) => StatisticsTiles::from(&stats),
        Err(error) => StatisticsTiles {
            available: false,
            error: Some(error),
            ..StatisticsTiles {
                logical_operations: 0,
                receipts: 0,
                model_calls: 0,
                total_cost_usd_micros: 0,
                outcomes_rejected: 0,
                outcomes_failed: 0,
                outcomes_verified: 0,
                waiting_operations: 0,
                learnings_admitted: 0,
                available: false,
                error: None,
            }
        },
    };
    let gunshi = match gunshi_auto::get_status(db, namespace) {
        Ok(Some(status)) => GunshiTiles::from(&status),
        Ok(None) => empty_gunshi(),
        Err(error) => GunshiTiles {
            error: Some(error),
            ..empty_gunshi()
        },
    };
    let can_mutate_kill_switch =
        principal_can_write_namespace(db, principal, namespace).unwrap_or(false);
    Ok(PressureSnapshot {
        namespace: namespace.into(),
        window_start_ms: start,
        window_end_ms: end,
        statistics,
        gunshi,
        refresh_semantics: PRESSURE_REFRESH_SEMANTICS,
        can_mutate_kill_switch,
    })
}

pub fn apply_kill_switch(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    enabled: bool,
    reason: &str,
) -> Result<NamespaceAllocationStatus, String> {
    if !principal_can_write_namespace(db, principal, namespace)? {
        return Err("namespace write access denied".into());
    }
    gunshi_auto::set_kill_switch(
        db,
        principal,
        namespace,
        enabled,
        reason,
        chrono::Utc::now().timestamp_millis(),
    )
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn tile(label: &str, value: &str, note: &str) -> String {
    format!(
        r#"<div class="tile"><div class="tile-label">{}</div><div class="tile-value">{}</div><div class="meta">{}</div></div>"#,
        escape_html(label),
        escape_html(value),
        escape_html(note)
    )
}

pub fn render_pressure_page(snapshot: &PressureSnapshot, flash: Option<&str>) -> String {
    let stats = &snapshot.statistics;
    let gunshi = &snapshot.gunshi;
    let flash_html = flash
        .map(|m| format!(r#"<p class="error" role="status">{}</p>"#, escape_html(m)))
        .unwrap_or_default();

    let stats_note = if stats.available {
        format!(
            "window {} … {} (ms)",
            snapshot.window_start_ms, snapshot.window_end_ms
        )
    } else {
        stats
            .error
            .clone()
            .unwrap_or_else(|| "statistics unavailable".into())
    };

    let mut tiles = String::new();
    tiles.push_str(&tile(
        "Logical operations",
        &stats.logical_operations.to_string(),
        &stats_note,
    ));
    tiles.push_str(&tile(
        "Receipts",
        &stats.receipts.to_string(),
        "in-window receipts",
    ));
    tiles.push_str(&tile(
        "Model calls",
        &stats.model_calls.to_string(),
        "priced + unpriced",
    ));
    tiles.push_str(&tile(
        "Spend (USD µ)",
        &stats.total_cost_usd_micros.to_string(),
        "total_cost_usd_micros",
    ));
    tiles.push_str(&tile(
        "Rejected outcomes",
        &stats.outcomes_rejected.to_string(),
        "denials / rejects",
    ));
    tiles.push_str(&tile(
        "Failed outcomes",
        &stats.outcomes_failed.to_string(),
        "failed class",
    ));
    tiles.push_str(&tile(
        "Verified outcomes",
        &stats.outcomes_verified.to_string(),
        "verified class",
    ));
    tiles.push_str(&tile(
        "Waiting operations",
        &stats.waiting_operations.to_string(),
        "still open in window",
    ));

    let revision = gunshi
        .active_revision_id
        .as_deref()
        .unwrap_or(if gunshi.installed {
            "—"
        } else {
            "not installed"
        });
    let live = if gunshi.auto_dispatch_live {
        "live"
    } else {
        "advisory / off"
    };
    let kill = if gunshi.kill_switch {
        format!("ON — {}", gunshi.kill_switch_reason)
    } else {
        "off".into()
    };

    let kill_form = if snapshot.can_mutate_kill_switch && gunshi.installed {
        if gunshi.kill_switch {
            format!(
                r#"
<form method="post" action="/console/n/{ns}/pressure/kill-switch" class="panel">
  <h3>Clear kill switch</h3>
  <p class="meta">Requires namespace write access. Confirm explicitly.</p>
  <label><input type="checkbox" name="confirm" value="1" required> I confirm clearing the kill switch for {ns}</label>
  <input type="hidden" name="enabled" value="0">
  <label for="reason">Reason (optional when clearing)</label>
  <input id="reason" name="reason" type="text" autocomplete="off">
  <button type="submit">Clear kill switch</button>
</form>"#,
                ns = escape_html(&snapshot.namespace)
            )
        } else {
            format!(
                r#"
<form method="post" action="/console/n/{ns}/pressure/kill-switch" class="panel">
  <h3>Enable kill switch</h3>
  <p class="meta">Forces advisory mode and opts the namespace out of auto-dispatch. Requires confirmation + reason.</p>
  <label><input type="checkbox" name="confirm" value="1" required> I confirm enabling the kill switch for {ns}</label>
  <input type="hidden" name="enabled" value="1">
  <label for="reason">Reason</label>
  <input id="reason" name="reason" type="text" required autocomplete="off">
  <button type="submit">Enable kill switch</button>
</form>"#,
                ns = escape_html(&snapshot.namespace)
            )
        }
    } else if !gunshi.installed {
        r#"<p class="stub">No Gunshi allocation policy installed for this namespace. Use <code>sekaictl gunshi install-baseline</code> first.</p>"#.into()
    } else {
        r#"<p class="stub">Kill switch requires namespace editor/admin write access.</p>"#.into()
    };

    format!(
        r#"
<section class="panel" aria-labelledby="pressure-heading">
  <h1 id="pressure-heading">Governance pressure</h1>
  <p>Namespace <strong>{ns}</strong>. Near-live tiles from authorized statistics and Gunshi allocation status.</p>
  <p class="meta">{refresh}</p>
  {flash}
  <div class="tile-grid">{tiles}</div>
</section>
<section class="panel" aria-labelledby="gunshi-heading">
  <h2 id="gunshi-heading">Auto-dispatch / Gunshi</h2>
  <ul>
    <li>Active revision: <code>{revision}</code></li>
    <li>Auto opt-in: <strong>{opt_in}</strong></li>
    <li>Auto-dispatch posture: <strong>{live}</strong></li>
    <li>Kill switch: <strong>{kill}</strong></li>
  </ul>
  {gunshi_error}
  {kill_form}
</section>
<section class="panel">
  <h2>Not yet on this surface</h2>
  <p class="stub">Provider circuit health, cache effectiveness, and multi-site federation panels remain follow-ups (#162 / federation track). Approval queue depth is not projected until a dedicated list API is wired.</p>
</section>"#,
        ns = escape_html(&snapshot.namespace),
        refresh = escape_html(snapshot.refresh_semantics),
        flash = flash_html,
        tiles = tiles,
        revision = escape_html(revision),
        opt_in = gunshi.auto_opt_in,
        live = live,
        kill = escape_html(&kill),
        gunshi_error = gunshi
            .error
            .as_ref()
            .map(|e| format!(r#"<p class="error">{}</p>"#, escape_html(e)))
            .unwrap_or_default(),
        kill_form = kill_form,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::gunshi::OperationRisk;
    use crate::chisei::gunshi_dispatch::AutoDispatchPolicy;
    use crate::chisei::gunshi_optimization::OptimizationPolicy;
    use crate::chisei::gunshi_policy::{AllocationPolicySnapshot, PolicyEvaluationGate};
    use crate::db::sekai::SekaiDb;
    use crate::domain::Object;
    use crate::sekai::security::Grant;
    use std::collections::{BTreeSet, HashMap as StdHashMap};
    use std::sync::Arc;

    fn test_db() -> Arc<RuntimeDb> {
        Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").expect("db"),
        )))
    }

    fn seed_ns(db: &RuntimeDb, namespace: &str, principal: &str, role: Role) {
        let object_id = format!("ns-{namespace}");
        if db.get_object(&object_id).ok().flatten().is_none() {
            db.create_object(&Object {
                id: object_id.clone(),
                kind: "namespace".into(),
                name: namespace.into(),
                namespace: String::new(),
                external_id: format!("namespace:{namespace}"),
                properties: StdHashMap::new(),
                created: 1,
                updated: 1,
            })
            .unwrap();
        }
        db.create_grant(&Grant {
            id: format!("g-{namespace}-{principal}"),
            object_id,
            principal: principal.into(),
            role,
            created: 1,
        })
        .unwrap();
    }

    fn install_baseline(db: &RuntimeDb, namespace: &str) {
        let snapshot = AllocationPolicySnapshot {
            revision_id: "rev-1".into(),
            governance_policy_version: "governance-v1".into(),
            dispatch: AutoDispatchPolicy {
                policy_id: "auto-low-risk".into(),
                version: "rev-1".into(),
                governance_policy_version: "governance-v1".into(),
                enabled: false,
                allowed_namespaces: BTreeSet::from([namespace.into()]),
                allowed_operation_classes: BTreeSet::from(["triage".into()]),
                maximum_risk: OperationRisk::Low,
                maximum_budget_usd_micros: 10_000,
                maximum_attempts: 1,
                require_governed_evidence: false,
                maximum_evidence_age_ms: 0,
                minimum_evidence_score: 0.0,
                minimum_advisory_comparisons: 1,
                minimum_observed_outcomes: 1,
                minimum_operator_acceptance_rate: 0.0,
            },
            optimization: OptimizationPolicy {
                policy_id: "balanced".into(),
                version: "rev-1".into(),
                maximum_best_of_n: 2,
                maximum_fallbacks: 1,
                early_stop_quality: 0.8,
                speculative_uncertainty_threshold: 0.2,
                human_review_uncertainty_threshold: 0.4,
                maximum_human_attention_minutes: 5,
            },
        };
        let gate = PolicyEvaluationGate {
            gate_id: "fleet-promotion".into(),
            version: "1".into(),
            suite_id: "fleet-eval".into(),
            minimum_samples: 1,
            minimum_success_rate: 0.0,
            minimum_operator_acceptance_rate: 0.0,
            minimum_mean_quality: 0.0,
            maximum_quality_regression: 1.0,
            maximum_cost_per_success_usd_micros: 1_000_000.0,
            maximum_cost_increase_usd_micros: 1_000_000.0,
            maximum_p95_latency_ms: 1_000_000.0,
            maximum_latency_increase_ms: 1_000_000.0,
        };
        gunshi_auto::install_baseline(db, "root", namespace, snapshot, gate, 1_000).unwrap();
    }

    #[test]
    fn pressure_snapshot_empty_namespace_is_degraded_friendly() {
        let db = test_db();
        seed_ns(&db, "alpha", "alice", Role::Viewer);
        let snap = load_pressure_snapshot(&db, "alice", "alpha").unwrap();
        assert_eq!(snap.namespace, "alpha");
        assert!(snap.statistics.available);
        assert_eq!(snap.statistics.receipts, 0);
        assert!(!snap.gunshi.installed);
        assert!(!snap.can_mutate_kill_switch);
        let html = render_pressure_page(&snap, None);
        assert!(html.contains("Governance pressure"));
        assert!(html.contains("not installed") || html.contains("No Gunshi"));
        assert!(!html.contains("beta")); // no foreign namespace labels
    }

    #[test]
    fn kill_switch_requires_write_and_confirm_path() {
        let db = test_db();
        seed_ns(&db, "alpha", "alice", Role::Admin);
        seed_ns(&db, "alpha", "bob", Role::Viewer);
        install_baseline(&db, "alpha");

        assert!(principal_can_write_namespace(&db, "alice", "alpha").unwrap());
        assert!(!principal_can_write_namespace(&db, "bob", "alpha").unwrap());

        let denied = apply_kill_switch(&db, "bob", "alpha", true, "incident");
        assert!(denied.unwrap_err().contains("write access"));

        let status = apply_kill_switch(&db, "alice", "alpha", true, "incident-42").unwrap();
        assert!(status.kill_switch);
        assert!(!status.auto_dispatch_live);
        assert_eq!(status.kill_switch_reason, "incident-42");

        let snap = load_pressure_snapshot(&db, "alice", "alpha").unwrap();
        assert!(snap.gunshi.kill_switch);
        let html = render_pressure_page(&snap, None);
        assert!(html.contains("Clear kill switch"));
        assert!(html.contains("incident-42"));
    }

    #[test]
    fn foreign_namespace_denied() {
        let db = test_db();
        seed_ns(&db, "alpha", "alice", Role::Viewer);
        let err = load_pressure_snapshot(&db, "alice", "beta").unwrap_err();
        assert!(err.contains("denied") || err.contains("invalid"));
    }
}
