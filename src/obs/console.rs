//! Authenticated operator console shell (Issue #284).
//!
//! Hybrid public-API model from research #283:
//! - shell is served from the control-plane ops HTTP listener;
//! - session credentials match gRPC principal tokens (Bearer / principal
//!   credentials, plus deprecated `SEKAI_AUTH_TOKEN` when configured);
//! - all data routes fail closed when unauthenticated or when the principal
//!   cannot access the requested namespace;
//! - raw tokens are never stored in browser-readable storage (HttpOnly
//!   opaque session cookie only).

use crate::db::runtime_db::RuntimeDb;
use crate::grpc::TokenAuthInterceptor;
use crate::sekai::security::Role;
use axum::Form;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Cookie name for the opaque console session identifier.
pub const SESSION_COOKIE: &str = "sekai_console_sid";

/// Default session lifetime (8 hours). Process-local; not shared across replicas.
pub const DEFAULT_SESSION_TTL_SECS: u64 = 8 * 60 * 60;

const MAX_NAMESPACE_LEN: usize = 128;

#[derive(Clone)]
pub struct ConsoleState {
    pub db: Arc<RuntimeDb>,
    pub auth: TokenAuthInterceptor,
    pub sessions: Arc<SessionStore>,
    pub session_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct ConsoleSession {
    pub principal: String,
    pub credential_id: String,
    pub token_hash: String,
    pub expires_unix: u64,
}

#[derive(Default)]
pub struct SessionStore {
    by_id: RwLock<HashMap<String, ConsoleSession>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, id: String, session: ConsoleSession) {
        self.by_id
            .write()
            .expect("console session lock")
            .insert(id, session);
    }

    pub fn get(&self, id: &str) -> Option<ConsoleSession> {
        self.by_id
            .read()
            .expect("console session lock")
            .get(id)
            .cloned()
    }

    pub fn remove(&self, id: &str) {
        self.by_id.write().expect("console session lock").remove(id);
    }

    fn purge_expired(&self, now: u64) {
        let mut map = self.by_id.write().expect("console session lock");
        map.retain(|_, session| session.expires_unix > now);
    }
}

pub fn router(state: ConsoleState) -> Router {
    Router::new()
        .route("/console", get(console_root))
        .route("/console/", get(console_home))
        .route("/console/login", get(login_get).post(login_post))
        .route("/console/logout", post(logout_post))
        .route("/console/api/session", get(api_session))
        .route("/console/api/namespaces", get(api_namespaces))
        .route("/console/n/{namespace}", get(namespace_root))
        .route("/console/n/{namespace}/ops", get(screen_operations))
        .route(
            "/console/n/{namespace}/ops/{operation_id}",
            get(screen_operation_workspace),
        )
        .route(
            "/console/api/n/{namespace}/ops/{operation_id}",
            get(api_operation_workspace),
        )
        .route("/console/n/{namespace}/pressure", get(screen_pressure))
        .route("/console/api/n/{namespace}/pressure", get(api_pressure))
        .route(
            "/console/n/{namespace}/pressure/kill-switch",
            post(pressure_kill_switch),
        )
        .route("/console/n/{namespace}/policy", get(screen_policy))
        .route(
            "/console/n/{namespace}/policy/dry-run",
            post(policy_dry_run),
        )
        .route(
            "/console/n/{namespace}/policy/promote",
            post(policy_promote),
        )
        .route(
            "/console/n/{namespace}/policy/rollback",
            post(policy_rollback),
        )
        .with_state(state)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Operations,
    Pressure,
    Policy,
}

impl Screen {
    fn label(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Operations => "Operations",
            Self::Pressure => "Pressure",
            Self::Policy => "Policy",
        }
    }

    fn path_suffix(self) -> &'static str {
        match self {
            Self::Home => "",
            Self::Operations => "/ops",
            Self::Pressure => "/pressure",
            Self::Policy => "/policy",
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn parse_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name)
            && let Some(value) = rest.strip_prefix('=')
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn set_session_cookie(id: &str, max_age: u64) -> HeaderValue {
    // SameSite=Strict + HttpOnly keeps the opaque session id off the JS surface.
    // Secure is omitted so loopback HTTP local-first runs work; production TLS
    // reverse proxies should add Secure when terminating HTTPS.
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={id}; Path=/console; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    ))
    .expect("session cookie header")
}

fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static(
        "sekai_console_sid=; Path=/console; HttpOnly; SameSite=Strict; Max-Age=0",
    )
}

fn credential_still_active(db: &RuntimeDb, session: &ConsoleSession) -> bool {
    if session.credential_id == "legacy-root" {
        return true;
    }
    match db.get_principal_credential(&session.token_hash) {
        Ok(Some(credential)) => {
            credential.status == "active"
                && credential.principal == session.principal
                && credential.id == session.credential_id
        }
        _ => false,
    }
}

fn resolve_session(state: &ConsoleState, headers: &HeaderMap) -> Option<ConsoleSession> {
    let sid = parse_cookie_value(headers, SESSION_COOKIE)?;
    state.sessions.purge_expired(now_unix());
    let session = state.sessions.get(&sid)?;
    if session.expires_unix <= now_unix() {
        state.sessions.remove(&sid);
        return None;
    }
    if !credential_still_active(&state.db, &session) {
        state.sessions.remove(&sid);
        return None;
    }
    Some(session)
}

/// Namespace identifiers allowed in console URLs (fail closed on anything else).
pub fn is_safe_namespace(namespace: &str) -> bool {
    if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_LEN {
        return false;
    }
    namespace
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Whether the authenticated principal may open the given namespace context.
///
/// Bootstrap principals (`root`, `local`) may select any canonical namespace so
/// local-first operators can navigate without pre-seeded memberships.
/// Other principals require an explicit namespace grant/membership.
pub fn principal_can_access_namespace(
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
        .any(|(member_namespace, _role)| member_namespace == namespace))
}

pub fn list_accessible_namespaces(
    db: &RuntimeDb,
    principal: &str,
) -> Result<Vec<(String, Role)>, String> {
    if matches!(principal, "root" | "local") {
        return Ok(Vec::new());
    }
    db.list_namespace_roles_for_principal(principal)
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

const CONSOLE_CSS: &str = r#"
:root {
  color-scheme: light dark;
  --bg: #0f1419;
  --fg: #e7ecf1;
  --muted: #9aa7b5;
  --panel: #1a222c;
  --accent: #5b9fd4;
  --danger: #d45b5b;
  --border: #2c3845;
  --focus: #f0c14b;
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f8fa;
    --fg: #1b1f24;
    --muted: #5b6570;
    --panel: #ffffff;
    --accent: #0b5cab;
    --danger: #b42318;
    --border: #d0d7de;
    --focus: #9a6700;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  line-height: 1.45;
  min-height: 100vh;
}
a { color: var(--accent); }
a:focus-visible, button:focus-visible, select:focus-visible, input:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
.skip-link {
  position: absolute;
  left: -999px;
  top: 0;
  background: var(--panel);
  color: var(--fg);
  padding: 0.5rem 0.75rem;
  z-index: 10;
}
.skip-link:focus { left: 0.5rem; top: 0.5rem; }
.shell-header {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem 1.25rem;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 1.25rem;
  border-bottom: 1px solid var(--border);
  background: var(--panel);
}
.brand { font-weight: 650; letter-spacing: 0.02em; }
.nav {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem 0.85rem;
  align-items: center;
}
.nav a {
  text-decoration: none;
  color: var(--fg);
  padding: 0.35rem 0.5rem;
  border-radius: 0.35rem;
}
.nav a[aria-current="page"] {
  background: color-mix(in srgb, var(--accent) 18%, transparent);
  color: var(--accent);
  font-weight: 600;
}
.meta { color: var(--muted); font-size: 0.9rem; }
main {
  max-width: 56rem;
  margin: 0 auto;
  padding: 1.25rem;
}
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 0.6rem;
  padding: 1rem 1.1rem;
  margin-bottom: 1rem;
}
label { display: block; margin-bottom: 0.35rem; font-weight: 600; }
input[type="password"], input[type="text"], select {
  width: min(100%, 28rem);
  padding: 0.5rem 0.65rem;
  border-radius: 0.4rem;
  border: 1px solid var(--border);
  background: var(--bg);
  color: var(--fg);
}
button, .button {
  display: inline-block;
  margin-top: 0.75rem;
  padding: 0.45rem 0.85rem;
  border-radius: 0.4rem;
  border: 1px solid var(--border);
  background: var(--accent);
  color: #fff;
  font: inherit;
  cursor: pointer;
  text-decoration: none;
}
button.secondary {
  background: transparent;
  color: var(--fg);
}
.error { color: var(--danger); margin: 0.5rem 0; }
.stub { color: var(--muted); }
.inline-form { display: inline; margin: 0; }
.ops-table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; }
.ops-table th, .ops-table td {
  text-align: left;
  padding: 0.4rem 0.5rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
.ops-table th { color: var(--muted); font-weight: 600; }
.causal { padding-left: 1.25rem; }
.json-panel {
  overflow: auto;
  max-height: 28rem;
  padding: 0.75rem;
  border: 1px solid var(--border);
  border-radius: 0.4rem;
  background: var(--bg);
  font-size: 0.85rem;
}
.tile-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(11rem, 1fr));
  gap: 0.75rem;
  margin-top: 0.75rem;
}
.tile {
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 0.65rem 0.75rem;
  background: var(--bg);
}
.tile-label { color: var(--muted); font-size: 0.85rem; }
.tile-value { font-size: 1.35rem; font-weight: 650; margin-top: 0.2rem; }
textarea {
  width: min(100%, 40rem);
  padding: 0.5rem 0.65rem;
  border-radius: 0.4rem;
  border: 1px solid var(--border);
  background: var(--bg);
  color: var(--fg);
  font: inherit;
}
"#;

fn html_page(title: &str, body: &str) -> Html<String> {
    let mut page = String::with_capacity(body.len() + CONSOLE_CSS.len() + 256);
    page.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    page.push_str(
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>",
    );
    page.push_str(&escape_html(title));
    page.push_str("</title>\n<style>");
    page.push_str(CONSOLE_CSS);
    page.push_str("</style>\n</head>\n<body>\n");
    page.push_str("<a class=\"skip-link\" href=\"#main\">Skip to main content</a>\n");
    page.push_str(body);
    page.push_str("\n</body>\n</html>");
    Html(page)
}

fn login_page(error: Option<&str>) -> Html<String> {
    let error_html = error
        .map(|e| format!(r#"<p class="error" role="alert">{}</p>"#, escape_html(e)))
        .unwrap_or_default();
    let body = format!(
        r#"
<header class="shell-header">
  <div class="brand">Sekai operator console</div>
  <div class="meta">Unauthenticated</div>
</header>
<main id="main">
  <section class="panel" aria-labelledby="login-heading">
    <h1 id="login-heading">Sign in</h1>
    <p class="meta">Use the same principal Bearer token as gRPC / <code>sekaictl</code>. Tokens are not stored in <code>localStorage</code>.</p>
    {error_html}
    <form method="post" action="/console/login" autocomplete="off">
      <label for="token">API token</label>
      <input id="token" name="token" type="password" required autofocus autocomplete="current-password" aria-required="true">
      <button type="submit">Sign in</button>
    </form>
  </section>
</main>"#
    );
    html_page("Sign in · Sekai console", &body)
}

fn shell_chrome(
    principal: &str,
    namespace: Option<&str>,
    namespaces: &[(String, Role)],
    active: Screen,
    main: &str,
) -> Html<String> {
    let principal_esc = escape_html(principal);
    let ns_switch = if matches!(principal, "root" | "local") {
        let current = namespace.map(escape_html).unwrap_or_default();
        format!(
            r#"
<form class="nav" method="get" action="/console/n/_/ops" id="ns-switcher" aria-label="Namespace context"
  onsubmit="var n=document.getElementById('namespace').value.trim(); if(!n){{return false;}} this.action='/console/n/'+encodeURIComponent(n)+'/ops';">
  <label for="namespace" class="meta">Namespace</label>
  <input id="namespace" name="namespace" type="text" value="{current}" placeholder="namespace" autocomplete="off" spellcheck="false">
  <button type="submit" class="secondary">Open</button>
</form>"#,
            current = current
        )
    } else {
        let mut options = String::new();
        if namespaces.is_empty() {
            options.push_str(r#"<option value="">No namespace memberships</option>"#);
        } else {
            for (ns, role) in namespaces {
                let selected = namespace == Some(ns.as_str());
                options.push_str(&format!(
                    r#"<option value="{v}"{sel}>{v} ({role})</option>"#,
                    v = escape_html(ns),
                    sel = if selected { " selected" } else { "" },
                    role = escape_html(role.as_str()),
                ));
            }
        }
        format!(
            r#"
<form class="nav" method="get" action="/console/" id="ns-switcher" aria-label="Namespace context">
  <label for="namespace" class="meta">Namespace</label>
  <select id="namespace" name="namespace" onchange="if(this.value){{window.location='/console/n/'+encodeURIComponent(this.value)+'/ops'}}">
    {options}
  </select>
</form>"#
        )
    };

    let nav = if let Some(ns) = namespace {
        let ns_esc = escape_html(ns);
        let link = |screen: Screen| {
            let current = if active == screen {
                r#" aria-current="page""#
            } else {
                ""
            };
            format!(
                r#"<a href="/console/n/{ns}{suffix}"{current}>{label}</a>"#,
                ns = ns_esc,
                suffix = screen.path_suffix(),
                current = current,
                label = screen.label(),
            )
        };
        format!(
            r#"<nav class="nav" aria-label="Primary">
  {ops}{pressure}{policy}
</nav>"#,
            ops = link(Screen::Operations),
            pressure = link(Screen::Pressure),
            policy = link(Screen::Policy),
        )
    } else {
        r#"<nav class="nav" aria-label="Primary"><span class="meta">Select a namespace to open Operations, Pressure, or Policy.</span></nav>"#
            .to_string()
    };

    let body = format!(
        r#"
<header class="shell-header">
  <div class="brand"><a href="/console/" style="color:inherit;text-decoration:none">Sekai operator console</a></div>
  {ns_switch}
  {nav}
  <div class="meta">
    Signed in as <strong>{principal}</strong>
    <form class="inline-form" method="post" action="/console/logout">
      <button type="submit" class="secondary">Sign out</button>
    </form>
  </div>
</header>
<main id="main">
{main}
</main>"#,
        principal = principal_esc,
        ns_switch = ns_switch,
        nav = nav,
        main = main,
    );
    let title = match namespace {
        Some(ns) => format!("{} · {} · Sekai console", active.label(), ns),
        None => "Sekai operator console".into(),
    };
    html_page(&title, &body)
}

async fn console_root() -> Redirect {
    Redirect::to("/console/")
}

async fn console_home(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    let main = r#"
<section class="panel" aria-labelledby="home-heading">
  <h1 id="home-heading">Console home</h1>
  <p>Authenticated shell for governed operations. Domain workspaces (causal operations, pressure, policy) load only after a namespace is selected and authorized.</p>
  <p class="stub">Use the namespace switcher in the header. Keyboard users can tab through primary navigation once a namespace is active.</p>
</section>"#;
    shell_chrome(&session.principal, None, &namespaces, Screen::Home, main).into_response()
}

async fn login_get(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if resolve_session(&state, &headers).is_some() {
        return Redirect::to("/console/").into_response();
    }
    login_page(None).into_response()
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    token: String,
}

async fn login_post(State(state): State<ConsoleState>, Form(form): Form<LoginForm>) -> Response {
    let token = form.token.trim();
    if token.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            login_page(Some("Token is required.")),
        )
            .into_response();
    }
    let Some(credential) = state.auth.resolve_credential(token) else {
        return (
            StatusCode::UNAUTHORIZED,
            login_page(Some("Invalid or inactive credentials.")),
        )
            .into_response();
    };
    let sid = new_session_id();
    let ttl = state.session_ttl.as_secs().max(60);
    let session = ConsoleSession {
        principal: credential.principal,
        credential_id: credential.id,
        token_hash: credential.token_hash,
        expires_unix: now_unix().saturating_add(ttl),
    };
    state.sessions.insert(sid.clone(), session);
    let mut response = Redirect::to("/console/").into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_session_cookie(&sid, ttl));
    response
}

async fn logout_post(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Some(sid) = parse_cookie_value(&headers, SESSION_COOKIE) {
        state.sessions.remove(&sid);
    }
    let mut response = Redirect::to("/console/login").into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie());
    response
}

async fn api_session(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "authenticated": false
            })),
        )
            .into_response();
    };
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "authenticated": true,
            "principal": session.principal,
            "credential_id": session.credential_id,
        })),
    )
        .into_response()
}

async fn api_namespaces(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "unauthenticated"
            })),
        )
            .into_response();
    };
    match list_accessible_namespaces(&state.db, &session.principal) {
        Ok(namespaces) => {
            let items: Vec<_> = namespaces
                .into_iter()
                .map(|(namespace, role)| {
                    serde_json::json!({
                        "namespace": namespace,
                        "role": role.as_str(),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "principal": session.principal,
                    "bootstrap": matches!(session.principal.as_str(), "root" | "local"),
                    "namespaces": items,
                })),
            )
                .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({ "error": err })),
        )
            .into_response(),
    }
}

async fn namespace_root(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Response {
    // Auth check first so unauthenticated users are not redirected into a
    // namespaced path before login.
    if resolve_session(&state, &headers).is_none() {
        return Redirect::to("/console/login").into_response();
    }
    Redirect::to(&format!("/console/n/{namespace}/ops")).into_response()
}

async fn screen_operations(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    match crate::obs::console_workspace::list_visible_operations(
        &state.db,
        &session.principal,
        &namespace,
    ) {
        Ok(items) => {
            let main = crate::obs::console_workspace::render_operations_home(&namespace, &items);
            shell_chrome(
                &session.principal,
                Some(&namespace),
                &namespaces,
                Screen::Operations,
                &main,
            )
            .into_response()
        }
        Err(err) => {
            let status = match err {
                crate::obs::console_workspace::WorkspaceError::InvalidNamespace => {
                    StatusCode::BAD_REQUEST
                }
                crate::obs::console_workspace::WorkspaceError::NamespaceDenied => {
                    StatusCode::FORBIDDEN
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                shell_chrome(
                    &session.principal,
                    None,
                    &namespaces,
                    Screen::Home,
                    &crate::obs::console_workspace::workspace_error_panel(err),
                ),
            )
                .into_response()
        }
    }
}

async fn screen_operation_workspace(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path((namespace, operation_id)): Path<(String, String)>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    match crate::obs::console_workspace::timed_load_report(
        &state.db,
        &session.principal,
        &namespace,
        &operation_id,
    ) {
        Ok((report, _elapsed_ms)) => {
            let main = crate::obs::console_workspace::render_operation_workspace(&report);
            shell_chrome(
                &session.principal,
                Some(&namespace),
                &namespaces,
                Screen::Operations,
                &main,
            )
            .into_response()
        }
        Err(err) => {
            let status = match err {
                crate::obs::console_workspace::WorkspaceError::NotFound => StatusCode::NOT_FOUND,
                crate::obs::console_workspace::WorkspaceError::InvalidNamespace => {
                    StatusCode::BAD_REQUEST
                }
                crate::obs::console_workspace::WorkspaceError::NamespaceDenied
                | crate::obs::console_workspace::WorkspaceError::ReceiptForbidden
                | crate::obs::console_workspace::WorkspaceError::CrossNamespace => {
                    StatusCode::FORBIDDEN
                }
                crate::obs::console_workspace::WorkspaceError::Unauthenticated => {
                    StatusCode::UNAUTHORIZED
                }
                crate::obs::console_workspace::WorkspaceError::Internal => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            };
            (
                status,
                shell_chrome(
                    &session.principal,
                    principal_can_access_namespace(&state.db, &session.principal, &namespace)
                        .unwrap_or(false)
                        .then_some(namespace.as_str()),
                    &namespaces,
                    Screen::Operations,
                    &crate::obs::console_workspace::workspace_error_panel(err),
                ),
            )
                .into_response()
        }
    }
}

async fn api_operation_workspace(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path((namespace, operation_id)): Path<(String, String)>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return crate::obs::console_workspace::json_error_response(
            crate::obs::console_workspace::WorkspaceError::Unauthenticated,
        );
    };
    match crate::obs::console_workspace::load_authorized_report(
        &state.db,
        &session.principal,
        &namespace,
        &operation_id,
    ) {
        Ok(report) => crate::obs::console_workspace::json_report_response(&report),
        Err(err) => crate::obs::console_workspace::json_error_response(err),
    }
}

async fn screen_pressure(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    match crate::obs::console_pressure::load_pressure_snapshot(
        &state.db,
        &session.principal,
        &namespace,
    ) {
        Ok(snapshot) => {
            let main = crate::obs::console_pressure::render_pressure_page(&snapshot, None);
            shell_chrome(
                &session.principal,
                Some(&namespace),
                &namespaces,
                Screen::Pressure,
                &main,
            )
            .into_response()
        }
        Err(error) => {
            let denied = error.contains("denied") || error.contains("invalid");
            (
                if denied {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                shell_chrome(
                    &session.principal,
                    None,
                    &namespaces,
                    Screen::Home,
                    &format!(
                        r#"<section class="panel"><h1>Governance pressure</h1><p class="error" role="alert">{}</p></section>"#,
                        // reuse workspace HTML escaper via simple escape
                        error
                            .replace('&', "&amp;")
                            .replace('<', "&lt;")
                            .replace('>', "&gt;")
                    ),
                ),
            )
                .into_response()
        }
    }
}

async fn api_pressure(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "unauthenticated"})),
        )
            .into_response();
    };
    match crate::obs::console_pressure::load_pressure_snapshot(
        &state.db,
        &session.principal,
        &namespace,
    ) {
        Ok(snapshot) => (StatusCode::OK, axum::Json(snapshot)).into_response(),
        Err(error) => {
            let status = if error.contains("denied") || error.contains("invalid") {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, axum::Json(serde_json::json!({"error": error}))).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct KillSwitchForm {
    enabled: String,
    reason: Option<String>,
    confirm: Option<String>,
}

async fn pressure_kill_switch(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
    Form(form): Form<KillSwitchForm>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    if form.confirm.as_deref() != Some("1") {
        let snapshot = crate::obs::console_pressure::load_pressure_snapshot(
            &state.db,
            &session.principal,
            &namespace,
        );
        let main = match snapshot {
            Ok(snap) => crate::obs::console_pressure::render_pressure_page(
                &snap,
                Some("Confirmation checkbox is required."),
            ),
            Err(error) => format!(
                r#"<section class="panel"><h1>Governance pressure</h1><p class="error">{error}</p></section>"#
            ),
        };
        return (
            StatusCode::BAD_REQUEST,
            shell_chrome(
                &session.principal,
                Some(&namespace),
                &namespaces,
                Screen::Pressure,
                &main,
            ),
        )
            .into_response();
    }
    let enabled = form.enabled == "1";
    let reason = form.reason.unwrap_or_default();
    match crate::obs::console_pressure::apply_kill_switch(
        &state.db,
        &session.principal,
        &namespace,
        enabled,
        &reason,
    ) {
        Ok(_) => Redirect::to(&format!("/console/n/{namespace}/pressure")).into_response(),
        Err(error) => {
            let snapshot = crate::obs::console_pressure::load_pressure_snapshot(
                &state.db,
                &session.principal,
                &namespace,
            );
            let main = match snapshot {
                Ok(snap) => crate::obs::console_pressure::render_pressure_page(&snap, Some(&error)),
                Err(_) => format!(
                    r#"<section class="panel"><h1>Governance pressure</h1><p class="error">{}</p></section>"#,
                    error
                        .replace('&', "&amp;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;")
                ),
            };
            (
                StatusCode::FORBIDDEN,
                shell_chrome(
                    &session.principal,
                    Some(&namespace),
                    &namespaces,
                    Screen::Pressure,
                    &main,
                ),
            )
                .into_response()
        }
    }
}

async fn screen_policy(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    match crate::obs::console_policy::load_effective_policy_view(
        &state.db,
        &session.principal,
        &namespace,
    ) {
        Ok(view) => {
            let main = crate::obs::console_policy::render_policy_page(&view, None, None);
            shell_chrome(
                &session.principal,
                Some(&namespace),
                &namespaces,
                Screen::Policy,
                &main,
            )
            .into_response()
        }
        Err(error) => (
            StatusCode::FORBIDDEN,
            shell_chrome(
                &session.principal,
                None,
                &namespaces,
                Screen::Home,
                &format!(
                    r#"<section class="panel"><h1>Policy</h1><p class="error">{}</p></section>"#,
                    error
                        .replace('&', "&amp;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;")
                ),
            ),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct DryRunForm {
    start_timestamp_ms: String,
    end_timestamp_ms: String,
    allowed_runtimes: Option<String>,
    allowed_models: Option<String>,
    default_runtime: Option<String>,
    default_model: Option<String>,
    data_class: Option<String>,
}

fn split_csv(raw: Option<String>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

async fn policy_dry_run(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
    Form(form): Form<DryRunForm>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    let start = form.start_timestamp_ms.parse::<i64>().unwrap_or(0);
    let end = form.end_timestamp_ms.parse::<i64>().unwrap_or(0);
    let candidate = crate::chisei::policy::Policy {
        allowed_runtimes: split_csv(form.allowed_runtimes),
        allowed_models: split_csv(form.allowed_models),
        default_runtime: form.default_runtime.unwrap_or_default(),
        default_model: form.default_model.unwrap_or_default(),
        data_class: form.data_class.unwrap_or_default(),
    };
    let view = crate::obs::console_policy::load_effective_policy_view(
        &state.db,
        &session.principal,
        &namespace,
    );
    match (
        view,
        crate::obs::console_policy::run_console_dry_run(
            &state.db,
            &session.principal,
            &namespace,
            start,
            end,
            &candidate,
        ),
    ) {
        (Ok(view), Ok(report)) => {
            let main = crate::obs::console_policy::render_policy_page(&view, Some(&report), None);
            shell_chrome(
                &session.principal,
                Some(&namespace),
                &namespaces,
                Screen::Policy,
                &main,
            )
            .into_response()
        }
        (Ok(view), Err(error)) => (
            StatusCode::BAD_REQUEST,
            shell_chrome(
                &session.principal,
                Some(&namespace),
                &namespaces,
                Screen::Policy,
                &crate::obs::console_policy::render_policy_page(&view, None, Some(&error)),
            ),
        )
            .into_response(),
        (Err(error), _) => (
            StatusCode::FORBIDDEN,
            shell_chrome(
                &session.principal,
                None,
                &namespaces,
                Screen::Home,
                &format!(
                    r#"<section class="panel"><h1>Policy</h1><p class="error">{}</p></section>"#,
                    error
                        .replace('&', "&amp;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;")
                ),
            ),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct PromoteForm {
    confirm: Option<String>,
    expected_revision: String,
    candidate_json: String,
    baseline_eval_json: String,
    candidate_eval_json: String,
}

#[derive(Debug, Deserialize)]
struct RollbackForm {
    confirm: Option<String>,
    expected_revision: String,
    reason: String,
}

async fn policy_promote(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
    Form(form): Form<PromoteForm>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    if form.confirm.as_deref() != Some("1") {
        return policy_flash(
            &state,
            &session,
            &namespaces,
            &namespace,
            "Confirmation checkbox is required for promote.",
            StatusCode::BAD_REQUEST,
        );
    }
    match crate::obs::console_policy::console_promote(
        &state.db,
        &session.principal,
        &namespace,
        &form.expected_revision,
        &form.candidate_json,
        &form.baseline_eval_json,
        &form.candidate_eval_json,
    ) {
        Ok(_) => Redirect::to(&format!("/console/n/{namespace}/policy")).into_response(),
        Err(error) => policy_flash(
            &state,
            &session,
            &namespaces,
            &namespace,
            &error,
            StatusCode::FORBIDDEN,
        ),
    }
}

async fn policy_rollback(
    State(state): State<ConsoleState>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
    Form(form): Form<RollbackForm>,
) -> Response {
    let Some(session) = resolve_session(&state, &headers) else {
        return Redirect::to("/console/login").into_response();
    };
    let namespaces = list_accessible_namespaces(&state.db, &session.principal).unwrap_or_default();
    if form.confirm.as_deref() != Some("1") {
        return policy_flash(
            &state,
            &session,
            &namespaces,
            &namespace,
            "Confirmation checkbox is required for rollback.",
            StatusCode::BAD_REQUEST,
        );
    }
    match crate::obs::console_policy::console_rollback(
        &state.db,
        &session.principal,
        &namespace,
        &form.expected_revision,
        &form.reason,
    ) {
        Ok(_) => Redirect::to(&format!("/console/n/{namespace}/policy")).into_response(),
        Err(error) => policy_flash(
            &state,
            &session,
            &namespaces,
            &namespace,
            &error,
            StatusCode::FORBIDDEN,
        ),
    }
}

fn policy_flash(
    state: &ConsoleState,
    session: &ConsoleSession,
    namespaces: &[(String, crate::sekai::security::Role)],
    namespace: &str,
    message: &str,
    status: StatusCode,
) -> Response {
    let view = crate::obs::console_policy::load_effective_policy_view(
        &state.db,
        &session.principal,
        namespace,
    );
    let main = match view {
        Ok(view) => crate::obs::console_policy::render_policy_page(&view, None, Some(message)),
        Err(error) => format!(
            r#"<section class="panel"><h1>Policy</h1><p class="error">{}</p></section>"#,
            error
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        ),
    };
    (
        status,
        shell_chrome(
            &session.principal,
            Some(namespace),
            namespaces,
            Screen::Policy,
            &main,
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sekai::SekaiDb;
    use crate::domain::Object;
    use crate::gateway_keys::hash_gateway_key;
    use crate::sekai::credentials::PrincipalCredentialStore;
    use crate::sekai::security::Grant;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use std::collections::HashMap as StdHashMap;
    use tower::ServiceExt;

    fn test_db() -> Arc<RuntimeDb> {
        Arc::new(RuntimeDb::Sqlite(Arc::new(
            SekaiDb::new(":memory:").expect("memory db"),
        )))
    }

    fn test_state(db: Arc<RuntimeDb>, legacy: Option<&str>) -> ConsoleState {
        let store = Arc::new(PrincipalCredentialStore::new());
        if let Ok(credentials) = db.list_active_credentials() {
            store.load(&credentials);
        }
        ConsoleState {
            db: db.clone(),
            auth: TokenAuthInterceptor::new(store, db, legacy.map(str::to_string)),
            sessions: Arc::new(SessionStore::new()),
            session_ttl: Duration::from_secs(3600),
        }
    }

    fn seed_namespace_grant(db: &RuntimeDb, namespace: &str, principal: &str, role: Role) {
        let object_id = format!("ns-obj-{namespace}");
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
        .expect("create namespace object");
        db.create_grant(&Grant {
            id: format!("grant-{namespace}-{principal}"),
            object_id,
            principal: principal.into(),
            role,
            created: 1,
        })
        .expect("create grant");
    }

    async fn login(app: &Router, token: &str) -> (StatusCode, Option<String>) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/console/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("token={}", urlencoding_token(token))))
                    .unwrap(),
            )
            .await
            .expect("login");
        let status = response.status();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split(';')
                    .next()
                    .and_then(|part| part.strip_prefix(&format!("{SESSION_COOKIE}=")))
                    .map(str::to_string)
            });
        (status, cookie)
    }

    fn urlencoding_token(token: &str) -> String {
        // Tokens used in tests are alphanumeric / hyphen; keep encoding simple.
        token
            .chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                _ => format!("%{:02X}", c as u8),
            })
            .collect()
    }

    #[test]
    fn safe_namespace_rejects_path_and_space() {
        assert!(is_safe_namespace("team-a"));
        assert!(!is_safe_namespace(""));
        assert!(!is_safe_namespace("../etc"));
        assert!(!is_safe_namespace("a b"));
        assert!(!is_safe_namespace("a/b"));
    }

    #[test]
    fn principal_namespace_access_is_membership_scoped() {
        let db = test_db();
        seed_namespace_grant(&db, "alpha", "alice", Role::Viewer);
        seed_namespace_grant(&db, "beta", "bob", Role::Editor);

        assert!(principal_can_access_namespace(&db, "alice", "alpha").unwrap());
        assert!(!principal_can_access_namespace(&db, "alice", "beta").unwrap());
        assert!(principal_can_access_namespace(&db, "root", "beta").unwrap());
    }

    #[tokio::test]
    async fn unauthenticated_data_routes_fail_closed() {
        let db = test_db();
        let app = router(test_state(db, None));

        let home = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/console/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(home.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            home.headers().get(header::LOCATION).unwrap(),
            "/console/login"
        );

        let api = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/console/api/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api.status(), StatusCode::UNAUTHORIZED);

        let ops = app
            .oneshot(
                Request::builder()
                    .uri("/console/n/alpha/ops")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ops.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn login_with_principal_token_and_namespace_authorization() {
        let db = test_db();
        let token = "alice-console-token";
        let token_hash = hash_gateway_key(token);
        db.create_principal_credential("alice", &token_hash, 1)
            .expect("credential");
        seed_namespace_grant(&db, "alpha", "alice", Role::Admin);
        seed_namespace_grant(&db, "beta", "bob", Role::Admin);

        let app = router(test_state(db, None));
        let (status, sid) = login(&app, token).await;
        assert!(
            status.is_redirection(),
            "expected redirect after login, got {status}"
        );
        let sid = sid.expect("session cookie");

        let cookie = format!("{SESSION_COOKIE}={sid}");
        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/console/n/alpha/ops")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let body = to_bytes(allowed.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Operations"));
        assert!(body.contains("<strong>alpha</strong>"));
        assert!(body.contains("aria-label=\"Primary\""));
        assert!(body.contains("Skip to main content"));

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/console/n/beta/ops")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let denied_body = to_bytes(denied.into_body(), usize::MAX).await.unwrap();
        let denied_body = String::from_utf8(denied_body.to_vec()).unwrap();
        assert!(denied_body.contains("Namespace access denied"));
        assert!(!denied_body.contains("Active namespace: <strong>beta</strong>"));

        let namespaces = app
            .oneshot(
                Request::builder()
                    .uri("/console/api/namespaces")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(namespaces.status(), StatusCode::OK);
        let ns_body = to_bytes(namespaces.into_body(), usize::MAX).await.unwrap();
        let ns_json: serde_json::Value = serde_json::from_slice(&ns_body).unwrap();
        assert_eq!(ns_json["principal"], "alice");
        let listed = ns_json["namespaces"].as_array().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["namespace"], "alpha");
    }

    #[tokio::test]
    async fn invalid_token_is_rejected() {
        let db = test_db();
        let app = router(test_state(db, None));
        let (status, cookie) = login(&app, "not-a-real-token").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(cookie.is_none());
    }

    #[tokio::test]
    async fn legacy_root_token_can_open_any_namespace() {
        let db = test_db();
        let app = router(test_state(db, Some("legacy-root-secret")));
        let (status, sid) = login(&app, "legacy-root-secret").await;
        assert!(status.is_redirection());
        let cookie = format!("{SESSION_COOKIE}={}", sid.expect("sid"));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/console/n/any-ns/pressure")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Governance pressure"));
        assert!(body.contains("any-ns"));
    }

    #[tokio::test]
    async fn logout_clears_session() {
        let db = test_db();
        let token = "logout-token";
        db.create_principal_credential("carol", &hash_gateway_key(token), 1)
            .unwrap();
        let app = router(test_state(db, None));
        let (_, sid) = login(&app, token).await;
        let sid = sid.expect("sid");
        let cookie = format!("{SESSION_COOKIE}={sid}");

        let logout = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/console/logout")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(logout.status().is_redirection());

        let after = app
            .oneshot(
                Request::builder()
                    .uri("/console/api/session")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    }
}
