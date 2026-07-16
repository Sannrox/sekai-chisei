use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::sekai::SekaiDb;
use crate::gateway_keys::hash_gateway_key;
use crate::provider_profile::ProviderRegistry;

pub const DEFAULT_STATE_DIR: &str = "./data";
pub const DEFAULT_CREDENTIAL_PATH: &str = "./data/local-credential.json";
const LOCAL_PRINCIPAL: &str = "local-onboarding";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalCredential {
    pub principal: String,
    pub token: String,
    pub database: String,
    pub socket: String,
}

pub fn ensure_local_credential(
    db_path: &str,
    socket: &str,
    credential_path: &Path,
) -> Result<LocalCredential, String> {
    let db = SekaiDb::new(db_path).map_err(|error| format!("initialize database: {error}"))?;
    let database_identity = canonical_path(db_path)?;
    if credential_path.exists() {
        let credential: LocalCredential = serde_json::from_slice(
            &std::fs::read(credential_path)
                .map_err(|error| format!("read {}: {error}", credential_path.display()))?,
        )
        .map_err(|error| format!("parse {}: {error}", credential_path.display()))?;
        if credential.database != database_identity || credential.socket != socket {
            return Err(format!(
                "{} belongs to a different local state directory; remove it or pass matching --database and --socket values",
                credential_path.display()
            ));
        }
        if db
            .get_principal_credential(&hash_gateway_key(&credential.token))?
            .is_some_and(|record| record.principal == LOCAL_PRINCIPAL)
        {
            return Ok(credential);
        }
        let replacement = new_local_credential(&database_identity, socket);
        if db
            .list_credentials(Some(LOCAL_PRINCIPAL), Some("active"))?
            .is_empty()
        {
            db.create_principal_credential(
                LOCAL_PRINCIPAL,
                &hash_gateway_key(&replacement.token),
                chrono::Utc::now().timestamp_millis(),
            )?;
        } else {
            db.rotate_principal_credential(LOCAL_PRINCIPAL, &hash_gateway_key(&replacement.token))?;
        }
        std::fs::remove_file(credential_path)
            .map_err(|error| format!("replace {}: {error}", credential_path.display()))?;
        write_private_json(credential_path, &replacement)?;
        return Ok(replacement);
    }

    let credential = new_local_credential(&database_identity, socket);
    if db
        .list_credentials(Some(LOCAL_PRINCIPAL), Some("active"))?
        .is_empty()
    {
        db.create_principal_credential(
            LOCAL_PRINCIPAL,
            &hash_gateway_key(&credential.token),
            chrono::Utc::now().timestamp_millis(),
        )?;
    } else {
        db.rotate_principal_credential(LOCAL_PRINCIPAL, &hash_gateway_key(&credential.token))?;
    }
    write_private_json(credential_path, &credential)?;
    Ok(credential)
}

fn new_local_credential(db_path: &str, socket: &str) -> LocalCredential {
    LocalCredential {
        principal: LOCAL_PRINCIPAL.into(),
        token: format!(
            "sekai_{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        ),
        database: db_path.into(),
        socket: socket.into(),
    }
}

pub fn default_credential_path() -> PathBuf {
    std::env::var_os("CHISEI_LOCAL_CREDENTIAL_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CREDENTIAL_PATH))
}

pub fn load_local_credential() -> Option<LocalCredential> {
    let path = default_credential_path();
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn canonical_path(path: &str) -> Result<String, String> {
    std::fs::canonicalize(path)
        .map_err(|error| format!("resolve database path {path:?}: {error}"))?
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("database path {path:?} is not valid UTF-8"))
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warning,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub boundary: &'static str,
    pub status: CheckStatus,
    pub detail: String,
    pub fix: Option<String>,
}

impl DoctorCheck {
    fn ok(boundary: &'static str, detail: impl Into<String>) -> Self {
        Self {
            boundary,
            status: CheckStatus::Ok,
            detail: detail.into(),
            fix: None,
        }
    }

    fn warning(boundary: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            boundary,
            status: CheckStatus::Warning,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }

    fn failed(boundary: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            boundary,
            status: CheckStatus::Failed,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

pub fn run_doctor(agent: Option<&str>) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.push(check_client(agent));
    checks.push(check_socket());
    checks.push(check_gateway_port());
    checks.push(check_database());
    checks.push(check_transport_security());
    checks.extend(check_providers());
    checks.push(check_harness_contract(agent));
    checks
}

pub fn render_doctor(checks: &[DoctorCheck]) -> String {
    let mut out = String::new();
    for check in checks {
        let status = match check.status {
            CheckStatus::Ok => "ok",
            CheckStatus::Warning => "warn",
            CheckStatus::Failed => "fail",
        };
        out.push_str(&format!(
            "[{status}] {}: {}\n",
            check.boundary, check.detail
        ));
        if let Some(fix) = &check.fix {
            out.push_str(&format!("       fix: {fix}\n"));
        }
    }
    let failures = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Failed)
        .count();
    let warnings = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Warning)
        .count();
    out.push_str(&format!("doctor: {failures} failed, {warnings} warnings\n"));
    out
}

fn check_client(agent: Option<&str>) -> DoctorCheck {
    let Some((agent, binary)) = agent.map(|agent| {
        (
            agent,
            match agent {
                "codex-app" => "codex",
                "claude-code" => "claude",
                other => other,
            },
        )
    }) else {
        return DoctorCheck::warning(
            "client",
            "no harness selected",
            "rerun `sekaictl doctor codex-app` or `sekaictl doctor claude-code`",
        );
    };
    if command_exists(binary) {
        DoctorCheck::ok("client", format!("{agent} client `{binary}` is available"))
    } else {
        DoctorCheck::failed(
            "client",
            format!("{agent} client `{binary}` is missing"),
            format!("install `{binary}` and ensure it is on PATH"),
        )
    }
}

fn command_exists(binary: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|path| {
            let candidate = path.join(binary);
            executable_file(&candidate)
        })
    })
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

fn check_socket() -> DoctorCheck {
    let socket = std::env::var("SEKAI_SOCKET").unwrap_or_else(|_| "./data/sekai.sock".into());
    let path = Path::new(&socket);
    if !path.exists() {
        return DoctorCheck::ok(
            "control-plane socket",
            format!("{socket} is ready to be created"),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
        {
            return DoctorCheck::failed(
                "control-plane socket",
                format!("{socket} exists but is not a Unix socket"),
                format!(
                    "move the file away, then rerun `sekaictl launch`; do not delete it until its contents are understood"
                ),
            );
        }
    }
    DoctorCheck::warning(
        "control-plane socket",
        format!("{socket} exists; liveness will be verified during launch"),
        format!("if launch reports it stale, stop the old server and remove {socket}"),
    )
}

fn check_gateway_port() -> DoctorCheck {
    let bind = std::env::var("GATEWAY_BIND").unwrap_or_else(|_| "127.0.0.1:8788".into());
    let address = match bind.parse::<std::net::SocketAddr>() {
        Ok(address) => address,
        Err(error) => {
            return DoctorCheck::failed(
                "gateway port",
                format!("GATEWAY_BIND {bind:?} is invalid: {error}"),
                "set GATEWAY_BIND to a loopback address such as 127.0.0.1:8788",
            );
        }
    };
    match std::net::TcpListener::bind(address) {
        Ok(listener) => {
            drop(listener);
            DoctorCheck::ok("gateway port", format!("{bind} is available"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => DoctorCheck::warning(
            "gateway port",
            format!("{bind} is occupied: {error}"),
            "reuse the running Chisei gateway or set GATEWAY_BIND to an unused loopback port",
        ),
        Err(error) => DoctorCheck::failed(
            "gateway port",
            format!("{bind} cannot be bound: {error}"),
            "choose an available loopback address and check local socket permissions",
        ),
    }
}

fn check_database() -> DoctorCheck {
    let path = std::env::var("DB_PATH").unwrap_or_else(|_| "./data/sekai.db".into());
    if !Path::new(&path).exists() {
        return DoctorCheck::ok(
            "database and migrations",
            format!("{path} does not exist and will be created by launch"),
        );
    }
    let result =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| error.to_string())
            .and_then(|connection| {
                let integrity: String = connection
                    .query_row("PRAGMA quick_check", [], |row| row.get(0))
                    .map_err(|error| error.to_string())?;
                if integrity == "ok" {
                    Ok(())
                } else {
                    Err(format!("SQLite quick_check: {integrity}"))
                }
            });
    match result {
        Ok(()) => DoctorCheck::ok(
            "database and migrations",
            format!(
                "{path} opens read-only and passes SQLite quick_check; launch applies pending migrations"
            ),
        ),
        Err(error) => DoctorCheck::failed(
            "database and migrations",
            error,
            format!(
                "check directory permissions and SQLite integrity for {path}; restore from backup rather than deleting durable state"
            ),
        ),
    }
}

fn check_transport_security() -> DoctorCheck {
    let cert = std::env::var("SEKAI_TLS_CERT")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let key = std::env::var("SEKAI_TLS_KEY")
        .ok()
        .filter(|v| !v.trim().is_empty());
    if cert.is_some() != key.is_some() {
        return DoctorCheck::failed(
            "TLS/auth",
            "SEKAI_TLS_CERT and SEKAI_TLS_KEY must be configured together",
            "set both TLS paths or unset both and use the default local Unix socket",
        );
    }
    if std::env::var("SEKAI_INSECURE").ok().as_deref() == Some("1") {
        return DoctorCheck::warning(
            "TLS/auth",
            "SEKAI_INSECURE=1 is set and launch will override it",
            "remove SEKAI_INSECURE from the shell or .env",
        );
    }
    DoctorCheck::ok("TLS/auth", "secure local socket defaults are active")
}

fn check_providers() -> Vec<DoctorCheck> {
    let registry = ProviderRegistry::built_in();
    ["openai", "anthropic", "xai", "meta"].into_iter().map(|provider| {
        let profile = registry.profile(provider).expect("built-in profile");
        let credential = profile.endpoint.api_key_env.as_deref().and_then(|key| std::env::var(key).ok()).is_some_and(|value| !value.trim().is_empty());
        if credential || matches!(provider, "openai" | "anthropic") {
            DoctorCheck::ok("provider", format!("{provider} profile {} is available ({})", profile.profile_version, if credential { "credential configured" } else { "client passthrough supported" }))
        } else {
            DoctorCheck::warning("provider", format!("{provider} profile {} has no verified credential", profile.profile_version), format!("set {} only after the provider endpoint and required capabilities are verified", profile.endpoint.api_key_env.as_deref().unwrap_or("the provider API key")))
        }
    }).collect()
}

fn check_harness_contract(agent: Option<&str>) -> DoctorCheck {
    match agent {
        Some("codex-app") => DoctorCheck::ok(
            "harness contract",
            "codex-app supports the Responses v1 gateway profile",
        ),
        Some("claude-code") => DoctorCheck::ok(
            "harness contract",
            "claude-code supports the Anthropic Messages gateway profile",
        ),
        Some(other) => DoctorCheck::failed(
            "harness contract",
            format!("{other} has no published onboarding adapter"),
            "use codex-app, claude-code, or a client conforming to docs/responses-harness-profile.md",
        ),
        None => DoctorCheck::warning(
            "harness contract",
            "no harness capability set was selected",
            "pass a harness name to doctor",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reuses_private_local_credential() {
        let root = std::env::temp_dir().join(format!("chisei-onboarding-{}", Uuid::new_v4()));
        let db = root.join("sekai.db");
        let credential_path = root.join("credential.json");
        let first =
            ensure_local_credential(db.to_str().unwrap(), "./data/sekai.sock", &credential_path)
                .unwrap();
        let second =
            ensure_local_credential(db.to_str().unwrap(), "./data/sekai.sock", &credential_path)
                .unwrap();
        assert_eq!(first.token, second.token);
        assert_eq!(first.principal, LOCAL_PRINCIPAL);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&credential_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replaces_a_revoked_local_credential() {
        let root = std::env::temp_dir().join(format!("chisei-onboarding-{}", Uuid::new_v4()));
        let db_path = root.join("sekai.db");
        let credential_path = root.join("credential.json");
        let first = ensure_local_credential(
            db_path.to_str().unwrap(),
            "./data/sekai.sock",
            &credential_path,
        )
        .unwrap();
        let db = SekaiDb::new(db_path.to_str().unwrap()).unwrap();
        db.revoke_principal_credential(LOCAL_PRINCIPAL).unwrap();
        let second = ensure_local_credential(
            db_path.to_str().unwrap(),
            "./data/sekai.sock",
            &credential_path,
        )
        .unwrap();
        assert_ne!(first.token, second.token);
        assert!(
            db.get_principal_credential(&hash_gateway_key(&second.token))
                .unwrap()
                .is_some()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
