//! Policy workspace for the operator console (Issue #287).
//!
//! Effective summary, historical dry-run, and confirmed Gunshi allocation
//! promote/rollback. UI is not a privilege escalation path: same membership
//! and write checks as gRPC.

use crate::chisei::gunshi_auto::{self, NamespaceAllocationStatus, PromoteRequest};
use crate::chisei::gunshi_policy::{AllocationPolicySnapshot, PolicyEvaluation};
use crate::chisei::policy::Policy;
use crate::chisei::policy_dry_run::{self, PolicyDryRunReport};
use crate::db::runtime_db::RuntimeDb;
use crate::domain::{ListFilter, Object};
use crate::obs::console::{is_safe_namespace, principal_can_access_namespace};
use crate::obs::console_pressure::principal_can_write_namespace;
use crate::sekai::audit::Decision;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct EffectivePolicyView {
    pub namespace: String,
    pub routing_configured: bool,
    pub routing_version: String,
    pub default_runtime: String,
    pub default_model: String,
    pub allowed_runtimes: Vec<String>,
    pub allowed_models: Vec<String>,
    pub data_class: String,
    pub budget_limit_count: usize,
    pub action_policy_configured: bool,
    pub gunshi: Option<NamespaceAllocationStatus>,
    pub can_write: bool,
}

pub fn load_routing_policy(db: &RuntimeDb, namespace: &str) -> Option<Policy> {
    for kind in ["namespace_policy", "policy"] {
        let Ok(objects) = db.list_all_objects(&ListFilter {
            kind: Some(kind.into()),
            ..Default::default()
        }) else {
            continue;
        };
        for obj in objects {
            if policy_namespace(&obj) != namespace {
                continue;
            }
            return Some(policy_from_properties(&obj.properties));
        }
    }
    None
}

fn policy_namespace(obj: &Object) -> String {
    if !obj.namespace.trim().is_empty() {
        return obj.namespace.trim().to_string();
    }
    for prefix in ["namespace_policy:", "policy:", "namespace:"] {
        if let Some(value) = obj.external_id.strip_prefix(prefix)
            && !value.trim().is_empty()
        {
            return value.trim().to_string();
        }
    }
    obj.name.trim().to_string()
}

fn policy_from_properties(properties: &HashMap<String, String>) -> Policy {
    Policy {
        allowed_runtimes: csv_property(properties.get("allowed_runtimes")),
        allowed_models: csv_property(properties.get("allowed_models")),
        default_runtime: properties
            .get("default_runtime")
            .cloned()
            .unwrap_or_default(),
        default_model: properties.get("default_model").cloned().unwrap_or_default(),
        data_class: properties.get("data_class").cloned().unwrap_or_default(),
    }
}

fn csv_property(value: Option<&String>) -> Vec<String> {
    value
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn load_effective_policy_view(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
) -> Result<EffectivePolicyView, String> {
    if !is_safe_namespace(namespace) {
        return Err("invalid namespace".into());
    }
    if !principal_can_access_namespace(db, principal, namespace).unwrap_or(false) {
        return Err("namespace access denied".into());
    }
    let routing = load_routing_policy(db, namespace);
    let budgets = db
        .budget_limits_for_scope(&format!("project:{namespace}"))
        .unwrap_or_default();
    let action = db
        .get_action_policy(&format!("project:{namespace}"))
        .ok()
        .flatten()
        .or_else(|| db.get_action_policy(namespace).ok().flatten());
    let gunshi = gunshi_auto::get_status(db, namespace).unwrap_or(None);
    let can_write = principal_can_write_namespace(db, principal, namespace).unwrap_or(false);
    Ok(EffectivePolicyView {
        namespace: namespace.into(),
        routing_configured: routing.is_some(),
        routing_version: routing.as_ref().map(Policy::version).unwrap_or_default(),
        default_runtime: routing
            .as_ref()
            .map(|p| p.default_runtime.clone())
            .unwrap_or_default(),
        default_model: routing
            .as_ref()
            .map(|p| p.default_model.clone())
            .unwrap_or_default(),
        allowed_runtimes: routing
            .as_ref()
            .map(|p| p.allowed_runtimes.clone())
            .unwrap_or_default(),
        allowed_models: routing
            .as_ref()
            .map(|p| p.allowed_models.clone())
            .unwrap_or_default(),
        data_class: routing
            .as_ref()
            .map(|p| p.data_class.clone())
            .unwrap_or_default(),
        budget_limit_count: budgets.len(),
        action_policy_configured: action.is_some(),
        gunshi,
        can_write,
    })
}

pub fn run_console_dry_run(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    start_timestamp_ms: i64,
    end_timestamp_ms: i64,
    candidate: &Policy,
) -> Result<PolicyDryRunReport, String> {
    if !principal_can_access_namespace(db, principal, namespace).unwrap_or(false) {
        return Err("namespace access denied".into());
    }
    if end_timestamp_ms <= start_timestamp_ms {
        return Err("end_timestamp_ms must be greater than start_timestamp_ms".into());
    }
    let receipts = db.list_operation_receipts_in_window(
        namespace,
        start_timestamp_ms,
        end_timestamp_ms,
        policy_dry_run::MAX_DRY_RUN_RECEIPTS.saturating_add(1),
    )?;
    if receipts.len() > policy_dry_run::MAX_DRY_RUN_RECEIPTS {
        return Err(format!(
            "policy dry-run receipt limit exceeded ({})",
            policy_dry_run::MAX_DRY_RUN_RECEIPTS
        ));
    }
    let report = policy_dry_run::dry_run_policy_over_receipts(
        namespace,
        start_timestamp_ms,
        end_timestamp_ms,
        candidate,
        &receipts,
    )?;
    // Audit like the gRPC path: fail closed if audit cannot persist.
    let request_id = format!(
        "console-policy-dry-run-{}",
        chrono::Utc::now().timestamp_millis()
    );
    let decision_id = {
        format!(
            "policy-dry-run:{:x}",
            Sha256::digest(format!(
                "{}\0{}\0{}\0{}\0{}\0{}",
                report.namespace,
                principal,
                request_id,
                report.candidate_policy_version,
                report.start_timestamp_ms,
                report.end_timestamp_ms
            ))
        )
    };
    db.record_decision(&Decision {
        id: decision_id,
        timestamp: chrono::Utc::now().timestamp_millis(),
        actor: principal.into(),
        action: "policy.dry_run".into(),
        reason: "console historical policy dry-run".into(),
        evidence: HashMap::from([
            ("namespace".into(), report.namespace.clone()),
            (
                "candidate_policy_version".into(),
                report.candidate_policy_version.clone(),
            ),
            ("evaluated".into(), report.counts.evaluated.to_string()),
            ("would_deny".into(), report.counts.would_deny.to_string()),
            ("request_id".into(), request_id),
            ("surface".into(), "console".into()),
        ]),
        target_id: report.namespace.clone(),
        outcome: "completed".into(),
    })?;
    Ok(report)
}

pub fn console_promote(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    expected_revision: &str,
    candidate_json: &str,
    baseline_eval_json: &str,
    candidate_eval_json: &str,
) -> Result<NamespaceAllocationStatus, String> {
    if !principal_can_write_namespace(db, principal, namespace)? {
        return Err("namespace write access denied".into());
    }
    let candidate: AllocationPolicySnapshot =
        serde_json::from_str(candidate_json).map_err(|e| format!("invalid candidate JSON: {e}"))?;
    let baseline: PolicyEvaluation = serde_json::from_str(baseline_eval_json)
        .map_err(|e| format!("invalid baseline evaluation JSON: {e}"))?;
    let candidate_evaluation: PolicyEvaluation = serde_json::from_str(candidate_eval_json)
        .map_err(|e| format!("invalid candidate evaluation JSON: {e}"))?;
    gunshi_auto::promote(
        db,
        PromoteRequest {
            actor: principal.into(),
            namespace: namespace.into(),
            candidate,
            baseline,
            candidate_evaluation,
            expected_revision: expected_revision.into(),
            now_ms: chrono::Utc::now().timestamp_millis(),
        },
    )
}

pub fn console_rollback(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    expected_revision: &str,
    reason: &str,
) -> Result<NamespaceAllocationStatus, String> {
    if !principal_can_write_namespace(db, principal, namespace)? {
        return Err("namespace write access denied".into());
    }
    gunshi_auto::rollback(
        db,
        principal,
        namespace,
        expected_revision,
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

pub fn render_policy_page(
    view: &EffectivePolicyView,
    dry_run: Option<&PolicyDryRunReport>,
    flash: Option<&str>,
) -> String {
    let flash_html = flash
        .map(|m| format!(r#"<p class="error" role="status">{}</p>"#, escape_html(m)))
        .unwrap_or_default();
    let routing_status = if view.routing_configured {
        "configured"
    } else {
        "unconfigured"
    };
    let gunshi_html = match &view.gunshi {
        Some(status) => format!(
            r#"<ul>
  <li>Active revision: <code>{}</code></li>
  <li>Rollback revision: <code>{}</code></li>
  <li>Auto opt-in: <strong>{}</strong></li>
  <li>Kill switch: <strong>{}</strong> {}</li>
  <li>Auto-dispatch live: <strong>{}</strong></li>
</ul>"#,
            escape_html(&status.active_revision_id),
            escape_html(status.rollback_revision_id.as_deref().unwrap_or("—")),
            status.auto_opt_in,
            status.kill_switch,
            if status.kill_switch {
                format!("({})", escape_html(&status.kill_switch_reason))
            } else {
                String::new()
            },
            status.auto_dispatch_live,
        ),
        None => r#"<p class="stub">No Gunshi allocation policy installed.</p>"#.into(),
    };

    let dry_run_html = if let Some(report) = dry_run {
        let mut samples = String::new();
        for (class, ids) in &report.samples {
            samples.push_str(&format!(
                "<li><strong>{}</strong>: {}</li>",
                escape_html(class),
                escape_html(&ids.join(", "))
            ));
        }
        format!(
            r#"
<section class="panel" aria-labelledby="dryrun-result">
  <h2 id="dryrun-result">Dry-run result</h2>
  <p>Candidate version <code>{}</code> · evaluated {} · unchanged {} · re_routed {} · would_deny {} · would_allow {} · insufficient_history {}</p>
  <ul>{samples}</ul>
  <p class="stub">Dry-run never activates policy. A <code>policy.dry_run</code> audit decision was recorded.</p>
</section>"#,
            escape_html(&report.candidate_policy_version),
            report.counts.evaluated,
            report.counts.unchanged,
            report.counts.re_routed,
            report.counts.would_deny,
            report.counts.would_allow,
            report.counts.insufficient_history,
            samples = samples,
        )
    } else {
        String::new()
    };

    let now = chrono::Utc::now().timestamp_millis();
    let start_default = now.saturating_sub(24 * 60 * 60 * 1000);

    let write_forms = if view.can_write {
        let expected = view
            .gunshi
            .as_ref()
            .map(|s| s.active_revision_id.as_str())
            .unwrap_or("");
        format!(
            r#"
<section class="panel" aria-labelledby="promote-heading">
  <h2 id="promote-heading">Promote allocation policy</h2>
  <p class="meta">Requires write access, explicit confirm, and eval-gated JSON matching <code>sekaictl gunshi promote</code>.</p>
  <form method="post" action="/console/n/{ns}/policy/promote">
    <label><input type="checkbox" name="confirm" value="1" required> I confirm promote for {ns}</label>
    <label for="expected_revision">Expected revision</label>
    <input id="expected_revision" name="expected_revision" type="text" value="{expected}" required>
    <label for="candidate_json">Candidate snapshot JSON</label>
    <textarea id="candidate_json" name="candidate_json" rows="6" required></textarea>
    <label for="baseline_eval_json">Baseline evaluation JSON</label>
    <textarea id="baseline_eval_json" name="baseline_eval_json" rows="4" required></textarea>
    <label for="candidate_eval_json">Candidate evaluation JSON</label>
    <textarea id="candidate_eval_json" name="candidate_eval_json" rows="4" required></textarea>
    <button type="submit">Promote</button>
  </form>
</section>
<section class="panel" aria-labelledby="rollback-heading">
  <h2 id="rollback-heading">Rollback allocation policy</h2>
  <form method="post" action="/console/n/{ns}/policy/rollback">
    <label><input type="checkbox" name="confirm" value="1" required> I confirm rollback for {ns}</label>
    <label for="rb_expected">Expected revision</label>
    <input id="rb_expected" name="expected_revision" type="text" value="{expected}" required>
    <label for="rb_reason">Reason</label>
    <input id="rb_reason" name="reason" type="text" required>
    <button type="submit">Rollback</button>
  </form>
</section>"#,
            ns = escape_html(&view.namespace),
            expected = escape_html(expected),
        )
    } else {
        r#"<p class="stub">Promote/rollback require namespace editor/admin write access.</p>"#
            .into()
    };

    format!(
        r#"
<section class="panel" aria-labelledby="policy-heading">
  <h1 id="policy-heading">Policy workspace</h1>
  <p>Namespace <strong>{ns}</strong>. Inspect effective policy, dry-run a candidate route policy, and promote/rollback Gunshi allocations with confirmation.</p>
  {flash}
  <h2>Effective summary</h2>
  <ul>
    <li>Routing: <strong>{routing}</strong> version <code>{rver}</code></li>
    <li>Default runtime/model: <code>{dr}</code> / <code>{dm}</code></li>
    <li>Allowed runtimes: <code>{ar}</code></li>
    <li>Allowed models: <code>{am}</code></li>
    <li>Data class: <code>{dc}</code></li>
    <li>Budget limits: <strong>{budgets}</strong></li>
    <li>Action policy: <strong>{action}</strong></li>
  </ul>
  <h3>Gunshi allocation</h3>
  {gunshi}
</section>
<section class="panel" aria-labelledby="dryrun-heading">
  <h2 id="dryrun-heading">Historical dry-run</h2>
  <p class="meta">No side effects on policy activation. Creates an audit decision.</p>
  <form method="post" action="/console/n/{ns}/policy/dry-run">
    <label for="start_ms">Start timestamp (ms)</label>
    <input id="start_ms" name="start_timestamp_ms" type="text" value="{start}" required>
    <label for="end_ms">End timestamp (ms)</label>
    <input id="end_ms" name="end_timestamp_ms" type="text" value="{end}" required>
    <label for="allowed_runtimes">Allowed runtimes (comma-separated)</label>
    <input id="allowed_runtimes" name="allowed_runtimes" type="text" value="{ar}">
    <label for="allowed_models">Allowed models (comma-separated)</label>
    <input id="allowed_models" name="allowed_models" type="text" value="{am}">
    <label for="default_runtime">Default runtime</label>
    <input id="default_runtime" name="default_runtime" type="text" value="{dr}">
    <label for="default_model">Default model</label>
    <input id="default_model" name="default_model" type="text" value="{dm}">
    <label for="data_class">Data class</label>
    <input id="data_class" name="data_class" type="text" value="{dc}">
    <button type="submit">Run dry-run</button>
  </form>
</section>
{dry_run_html}
{write_forms}
<section class="panel">
  <h2>Non-goals on this surface</h2>
  <p class="stub">Free-form YAML without schema validation is not offered. Silent apply from dry-run is forbidden. Use CLI for complex multi-step eval suite authoring when preferred.</p>
</section>"#,
        ns = escape_html(&view.namespace),
        flash = flash_html,
        routing = routing_status,
        rver = escape_html(&view.routing_version),
        dr = escape_html(&view.default_runtime),
        dm = escape_html(&view.default_model),
        ar = escape_html(&view.allowed_runtimes.join(",")),
        am = escape_html(&view.allowed_models.join(",")),
        dc = escape_html(&view.data_class),
        budgets = view.budget_limit_count,
        action = if view.action_policy_configured {
            "configured"
        } else {
            "unconfigured"
        },
        gunshi = gunshi_html,
        start = start_default,
        end = now,
        dry_run_html = dry_run_html,
        write_forms = write_forms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::domain::Object;
    use crate::sekai::security::{Grant, Role};
    use std::collections::HashMap as StdHashMap;
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

    #[test]
    fn effective_view_and_dry_run_are_namespace_scoped() {
        let db = test_db();
        seed_ns(&db, "alpha", "alice", Role::Editor);
        db.create_object(&Object {
            id: "pol-alpha".into(),
            kind: "namespace_policy".into(),
            name: "alpha".into(),
            namespace: "alpha".into(),
            external_id: "namespace_policy:alpha".into(),
            properties: StdHashMap::from([
                ("allowed_runtimes".into(), "ollama".into()),
                ("allowed_models".into(), "llama".into()),
                ("default_runtime".into(), "ollama".into()),
                ("default_model".into(), "llama".into()),
                ("data_class".into(), "internal".into()),
            ]),
            created: 1,
            updated: 1,
        })
        .unwrap();

        let view = load_effective_policy_view(&db, "alice", "alpha").unwrap();
        assert!(view.routing_configured);
        assert_eq!(view.default_runtime, "ollama");
        assert!(view.can_write);

        assert!(load_effective_policy_view(&db, "alice", "beta").is_err());

        let candidate = Policy {
            allowed_runtimes: vec!["ollama".into()],
            allowed_models: vec!["llama".into()],
            default_runtime: "ollama".into(),
            default_model: "llama".into(),
            data_class: "internal".into(),
        };
        // Foreign principal cannot dry-run (membership fail closed).
        assert!(run_console_dry_run(&db, "bob", "alpha", 0, 10_000, &candidate).is_err());

        let empty_report = PolicyDryRunReport {
            namespace: "alpha".into(),
            start_timestamp_ms: 0,
            end_timestamp_ms: 1,
            candidate_policy_version: candidate.version(),
            counts: policy_dry_run::DryRunDeltaCounts {
                evaluated: 0,
                unchanged: 0,
                re_routed: 0,
                would_deny: 0,
                would_allow: 0,
                insufficient_history: 0,
            },
            samples: Default::default(),
            results: vec![],
        };
        let html = render_policy_page(&view, Some(&empty_report), None);
        assert!(html.contains("Dry-run result"));
        assert!(html.contains("Promote allocation policy"));
        assert!(!html.contains("beta"));
    }
}
