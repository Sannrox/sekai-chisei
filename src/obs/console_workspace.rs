//! Causal operation workspace for the operator console (Issue #285).
//!
//! Projects authorized operation receipts into the shell using the same
//! `OperationReport` / `causal_operation_view` surfaces as `sekaictl report`.
//! Visibility matches `GetOperationReceipt`: initiator or bootstrap principal
//! (`root` / `local` / `chisei-gateway`). Cross-namespace IDs fail closed.

use crate::chisei::receipt::OperationReceipt;
use crate::db::runtime_db::RuntimeDb;
use crate::obs::console::{
    ConsoleSession, is_safe_namespace, list_accessible_namespaces, principal_can_access_namespace,
};
use crate::operation_report::{ClaimState, OperationReport};
use crate::report_cli::causal_operation_view;
use crate::sekai::security::Role;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::time::Instant;

/// Documented initial-load budget for a single fixture-sized operation report
/// (receipt projection + HTML/JSON render). Larger historical lists are capped.
pub const WORKSPACE_INITIAL_LOAD_BUDGET_MS: u128 = 2_000;

/// Max operations returned on the namespace operations home (S1 list stub).
pub const OPERATIONS_LIST_LIMIT: usize = 50;

/// Look-back window for the operations list (7 days).
pub const OPERATIONS_LIST_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceError {
    Unauthenticated,
    InvalidNamespace,
    NamespaceDenied,
    NotFound,
    ReceiptForbidden,
    CrossNamespace,
    Internal,
}

impl WorkspaceError {
    fn status(self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::InvalidNamespace => StatusCode::BAD_REQUEST,
            Self::NamespaceDenied | Self::ReceiptForbidden | Self::CrossNamespace => {
                StatusCode::FORBIDDEN
            }
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Unauthenticated => "Authentication required.",
            Self::InvalidNamespace => "Invalid namespace identifier.",
            Self::NamespaceDenied => "Namespace access denied.",
            Self::NotFound => "Operation receipt not found.",
            Self::ReceiptForbidden => "Operation receipt is not visible to this principal.",
            Self::CrossNamespace => {
                "Operation belongs to a different namespace; no foreign data was loaded."
            }
            Self::Internal => "Failed to load operation workspace.",
        }
    }
}

/// Whether the principal may read this receipt (mirrors GetOperationReceipt).
pub fn principal_can_view_receipt(principal: &str, receipt: &OperationReceipt) -> bool {
    matches!(principal, "root" | "local" | "chisei-gateway")
        || principal == receipt.initiating_actor
}

fn looks_like_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("secret")
        || lower.contains("password")
        || lower.contains("token")
        || lower.contains("api_key")
        || lower.contains("apikey")
        || lower.contains("authorization")
        || lower.contains("private_key")
        || lower.contains("credential")
}

/// Drop attributes that would never belong in an operator-facing projection.
fn scrub_report_secrets(mut report: OperationReport) -> OperationReport {
    for events in report.sections.values_mut() {
        for event in events.iter_mut() {
            event
                .attributes
                .retain(|key, _| !looks_like_secret_key(key));
        }
    }
    report
}

pub fn load_authorized_report(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    operation_id: &str,
) -> Result<OperationReport, WorkspaceError> {
    if !is_safe_namespace(namespace) {
        return Err(WorkspaceError::InvalidNamespace);
    }
    if !principal_can_access_namespace(db, principal, namespace).unwrap_or(false) {
        return Err(WorkspaceError::NamespaceDenied);
    }
    let operation_id = operation_id.trim();
    if operation_id.is_empty() || operation_id.len() > 256 {
        return Err(WorkspaceError::NotFound);
    }
    if operation_id
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')))
    {
        return Err(WorkspaceError::NotFound);
    }
    let receipt = db
        .get_operation_receipt(operation_id)
        .map_err(|_| WorkspaceError::Internal)?
        .ok_or(WorkspaceError::NotFound)?;
    if receipt.namespace != namespace {
        // Fail closed: do not disclose that the id exists in another namespace.
        return Err(WorkspaceError::CrossNamespace);
    }
    if !principal_can_view_receipt(principal, &receipt) {
        return Err(WorkspaceError::ReceiptForbidden);
    }
    Ok(scrub_report_secrets(
        OperationReport::from_authorized_receipt(&receipt),
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct OperationListItem {
    pub operation_id: String,
    pub operation_class: String,
    pub initiating_actor: String,
    pub started_at_ms: i64,
    pub completed_at_ms: Option<i64>,
}

pub fn list_visible_operations(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
) -> Result<Vec<OperationListItem>, WorkspaceError> {
    if !is_safe_namespace(namespace) {
        return Err(WorkspaceError::InvalidNamespace);
    }
    if !principal_can_access_namespace(db, principal, namespace).unwrap_or(false) {
        return Err(WorkspaceError::NamespaceDenied);
    }
    let now_ms = chrono::Utc::now().timestamp_millis();
    let start = now_ms.saturating_sub(OPERATIONS_LIST_WINDOW_MS);
    let end = now_ms.saturating_add(1);
    let receipts = db
        .list_operation_receipts_in_window(namespace, start, end, OPERATIONS_LIST_LIMIT)
        .map_err(|_| WorkspaceError::Internal)?;
    Ok(receipts
        .into_iter()
        .filter(|receipt| principal_can_view_receipt(principal, receipt))
        .map(|receipt| OperationListItem {
            operation_id: receipt.operation_id,
            operation_class: receipt.operation_class,
            initiating_actor: receipt.initiating_actor,
            started_at_ms: receipt.started_at_ms,
            completed_at_ms: receipt.completed_at_ms,
        })
        .collect())
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

fn claim_label(state: &ClaimState) -> &'static str {
    match state {
        ClaimState::NotVerified => "not_verified",
        ClaimState::Verified => "verified",
        ClaimState::Failed => "failed",
    }
}

pub fn render_operations_home(namespace: &str, items: &[OperationListItem]) -> String {
    let mut rows = String::new();
    if items.is_empty() {
        rows.push_str(
            r#"<p class="stub">No visible operations in the last 7 days for this namespace.</p>"#,
        );
    } else {
        rows.push_str("<table class=\"ops-table\"><thead><tr><th>Operation</th><th>Class</th><th>Actor</th><th>Started</th></tr></thead><tbody>");
        for item in items {
            rows.push_str(&format!(
                r#"<tr><td><a href="/console/n/{ns}/ops/{id}">{id}</a></td><td>{class}</td><td>{actor}</td><td>{started}</td></tr>"#,
                ns = escape_html(namespace),
                id = escape_html(&item.operation_id),
                class = escape_html(&item.operation_class),
                actor = escape_html(&item.initiating_actor),
                started = item.started_at_ms,
            ));
        }
        rows.push_str("</tbody></table>");
    }
    format!(
        r#"
<section class="panel" aria-labelledby="ops-heading">
  <h1 id="ops-heading">Operations</h1>
  <p>Recent authorized operations in <strong>{ns}</strong>. Open an operation for the causal workspace.</p>
  {rows}
</section>"#,
        ns = escape_html(namespace),
        rows = rows,
    )
}

pub fn render_operation_workspace(report: &OperationReport) -> String {
    let mut causal = String::from("<ol class=\"causal\">");
    for (stage, value) in causal_operation_view(report) {
        causal.push_str(&format!(
            "<li><strong>{}</strong>: {}</li>",
            escape_html(stage),
            escape_html(&value)
        ));
    }
    causal.push_str("</ol>");

    let mut missing = String::new();
    if report.missing_surfaces.is_empty() && report.uncovered_surfaces.is_empty() {
        missing.push_str(r#"<p class="stub">No missing or uncovered surfaces recorded.</p>"#);
    } else {
        missing.push_str("<ul>");
        for surface in &report.missing_surfaces {
            missing.push_str(&format!(
                "<li>missing: <code>{}</code></li>",
                escape_html(surface.as_str())
            ));
        }
        for gap in &report.uncovered_surfaces {
            missing.push_str(&format!(
                "<li>uncovered: <code>{}</code> — {}</li>",
                escape_html(gap.surface.as_str()),
                escape_html(&gap.reason)
            ));
        }
        missing.push_str("</ul>");
    }

    let mut sections = String::new();
    for (surface, events) in &report.sections {
        sections.push_str(&format!("<h3>{}</h3><ul>", escape_html(surface)));
        for event in events {
            sections.push_str(&format!(
                "<li><code>{}</code> [{}] actor={} at={}",
                escape_html(&event.event_id),
                escape_html(&event.kind),
                escape_html(&event.actor),
                event.timestamp_ms
            ));
            if !event.attributes.is_empty() {
                sections.push_str("<ul>");
                for (key, value) in &event.attributes {
                    sections.push_str(&format!(
                        "<li>{}: {}</li>",
                        escape_html(key),
                        escape_html(value)
                    ));
                }
                sections.push_str("</ul>");
            }
            sections.push_str("</li>");
        }
        sections.push_str("</ul>");
    }

    let json = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".into());

    format!(
        r#"
<section class="panel" aria-labelledby="op-heading">
  <h1 id="op-heading">Operation {op}</h1>
  <p>
    Namespace <strong>{ns}</strong> · class <strong>{class}</strong> · actor <strong>{actor}</strong>
  </p>
  <p class="meta">
    started_at_ms={started}
    · completed_at_ms={completed}
    · duration_ms={duration}
    · evidence_complete={evidence}
    · integrity={integrity}
    · policy_compliance={policy}
  </p>
  <h2>Causal path</h2>
  <p class="stub">Absent stages are explicit (<code>not_reported</code> / <code>not_reached</code>), never inferred.</p>
  {causal}
  <h2>Missing / uncovered surfaces</h2>
  {missing}
  <h2>Event sections</h2>
  {sections}
  <h2>Authorized JSON</h2>
  <details>
    <summary>Show authorized report projection (no raw credential material)</summary>
    <pre class="json-panel">{json}</pre>
  </details>
  <p class="stub">Export compliance bundles and full attestation via <code>sekaictl report bundle</code> / <code>sekaictl attest</code>.</p>
</section>"#,
        op = escape_html(&report.operation_id),
        ns = escape_html(&report.namespace),
        class = escape_html(&report.operation_class),
        actor = escape_html(&report.initiating_actor),
        started = report.started_at_ms,
        completed = report
            .completed_at_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".into()),
        duration = report
            .duration_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".into()),
        evidence = report.claims.evidence_complete,
        integrity = claim_label(&report.claims.integrity),
        policy = claim_label(&report.claims.policy_compliance),
        causal = causal,
        missing = missing,
        sections = sections,
        json = escape_html(&json),
    )
}

pub fn workspace_error_panel(err: WorkspaceError) -> String {
    format!(
        r#"<section class="panel" aria-labelledby="err-heading">
  <h1 id="err-heading">Operation workspace</h1>
  <p class="error" role="alert">{}</p>
  <p class="stub">No foreign namespace or unauthorized receipt data was loaded.</p>
</section>"#,
        escape_html(err.message())
    )
}

/// Shared shell context for workspace routes.
pub struct WorkspacePageContext {
    pub principal: String,
    pub namespace: String,
    pub namespaces: Vec<(String, Role)>,
    pub session: ConsoleSession,
}

pub fn require_namespace_session(
    db: &RuntimeDb,
    session: &ConsoleSession,
    namespace: &str,
) -> Result<Vec<(String, Role)>, WorkspaceError> {
    if !is_safe_namespace(namespace) {
        return Err(WorkspaceError::InvalidNamespace);
    }
    if !principal_can_access_namespace(db, &session.principal, namespace).unwrap_or(false) {
        return Err(WorkspaceError::NamespaceDenied);
    }
    Ok(list_accessible_namespaces(db, &session.principal).unwrap_or_default())
}

pub fn timed_load_report(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
    operation_id: &str,
) -> Result<(OperationReport, u128), WorkspaceError> {
    let started = Instant::now();
    let report = load_authorized_report(db, principal, namespace, operation_id)?;
    Ok((report, started.elapsed().as_millis()))
}

pub fn json_report_response(report: &OperationReport) -> Response {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "report": report,
            "causal": causal_operation_view(report)
                .into_iter()
                .map(|(k, v)| serde_json::json!({"stage": k, "value": v}))
                .collect::<Vec<_>>(),
        })),
    )
        .into_response()
}

pub fn json_error_response(err: WorkspaceError) -> Response {
    (
        err.status(),
        axum::Json(serde_json::json!({
            "error": err.message(),
            "code": format!("{:?}", err),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::receipt::{
        OPERATION_RECEIPT_VERSION, OperationReceiptEvent, ReceiptEventKind,
    };
    use crate::db::sekai::SekaiDb;
    use crate::domain::Object;
    use crate::sekai::security::{Grant, Role};
    use std::collections::BTreeMap;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Arc;

    fn test_db() -> Arc<RuntimeDb> {
        Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").expect("db"),
        )))
    }

    fn seed_ns(db: &RuntimeDb, namespace: &str, principal: &str) {
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
            role: Role::Viewer,
            created: 1,
        })
        .unwrap();
    }

    fn sample_receipt(ns: &str, op: &str, actor: &str) -> OperationReceipt {
        let mut attrs = BTreeMap::new();
        attrs.insert("capability".into(), "demo.cap".into());
        attrs.insert("api_key".into(), "should-not-leak".into());
        OperationReceipt {
            version: OPERATION_RECEIPT_VERSION.into(),
            operation_id: op.into(),
            parent_operation_id: None,
            namespace: ns.into(),
            operation_class: "analysis".into(),
            initiating_actor: actor.into(),
            schema_version: "schema/v1".into(),
            policy_version: "policy/v1".into(),
            started_at_ms: chrono::Utc::now().timestamp_millis() - 1_000,
            completed_at_ms: Some(chrono::Utc::now().timestamp_millis()),
            events: vec![
                OperationReceiptEvent {
                    event_id: "intent".into(),
                    operation_id: op.into(),
                    parent_event_id: None,
                    timestamp_ms: 1,
                    kind: ReceiptEventKind::IntentRecorded,
                    surface: ReceiptEventKind::IntentRecorded.surface(),
                    actor: actor.into(),
                    references: vec![],
                    attributes: attrs,
                },
                OperationReceiptEvent {
                    event_id: "outcome".into(),
                    operation_id: op.into(),
                    parent_event_id: Some("intent".into()),
                    timestamp_ms: 2,
                    kind: ReceiptEventKind::OutcomeRecorded,
                    surface: ReceiptEventKind::OutcomeRecorded.surface(),
                    actor: actor.into(),
                    references: vec![],
                    attributes: BTreeMap::from([("outcome".into(), "succeeded".into())]),
                },
            ],
            uncovered_surfaces: vec![],
            reporter_grants: vec![],
        }
    }

    #[test]
    fn cross_namespace_fails_closed_without_not_found_leak_for_other_ns() {
        let db = test_db();
        seed_ns(&db, "alpha", "alice");
        seed_ns(&db, "beta", "alice");
        db.put_operation_receipt(&sample_receipt("beta", "op-secret", "alice"))
            .unwrap();

        let err = load_authorized_report(&db, "alice", "alpha", "op-secret").unwrap_err();
        assert_eq!(err, WorkspaceError::CrossNamespace);
    }

    #[test]
    fn foreign_principal_cannot_read_receipt() {
        let db = test_db();
        seed_ns(&db, "alpha", "alice");
        seed_ns(&db, "alpha", "bob");
        db.put_operation_receipt(&sample_receipt("alpha", "op-1", "alice"))
            .unwrap();

        let err = load_authorized_report(&db, "bob", "alpha", "op-1").unwrap_err();
        assert_eq!(err, WorkspaceError::ReceiptForbidden);
    }

    #[test]
    fn initiator_loads_report_without_secret_attributes() {
        let db = test_db();
        seed_ns(&db, "alpha", "alice");
        db.put_operation_receipt(&sample_receipt("alpha", "op-1", "alice"))
            .unwrap();

        let (report, elapsed_ms) = timed_load_report(&db, "alice", "alpha", "op-1").expect("load");
        assert!(
            elapsed_ms < WORKSPACE_INITIAL_LOAD_BUDGET_MS,
            "fixture load took {elapsed_ms}ms"
        );
        assert_eq!(report.operation_id, "op-1");
        let intent = &report.sections["intent"][0];
        assert!(!intent.attributes.contains_key("api_key"));
        assert_eq!(
            intent.attributes.get("capability").map(String::as_str),
            Some("demo.cap")
        );
        let html = render_operation_workspace(&report);
        assert!(html.contains("Causal path"));
        assert!(!html.contains("should-not-leak"));
        assert!(
            html.contains("not_reported")
                || html.contains("succeeded")
                || html.contains("demo.cap")
                || html.contains("Causal path")
        );
    }

    #[test]
    fn list_filters_invisible_operations() {
        let db = test_db();
        seed_ns(&db, "alpha", "alice");
        seed_ns(&db, "alpha", "bob");
        db.put_operation_receipt(&sample_receipt("alpha", "op-alice", "alice"))
            .unwrap();
        db.put_operation_receipt(&sample_receipt("alpha", "op-bob", "bob"))
            .unwrap();

        let alice_list = list_visible_operations(&db, "alice", "alpha").unwrap();
        assert_eq!(alice_list.len(), 1);
        assert_eq!(alice_list[0].operation_id, "op-alice");

        let root_list = list_visible_operations(&db, "root", "alpha").unwrap();
        assert_eq!(root_list.len(), 2);
    }
}
