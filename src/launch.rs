use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::gateway_keys::default_virtual_key;
use crate::gateway_setup::{GatewaySetupConfig, run_setup};

const SERVER_BIN: &str = "sekai-chisei";
const GATEWAY_BIN: &str = "chisei-gateway";
const LOG_DIR: &str = "./data/logs";
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const READY_POLL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchConfig {
    pub agent: String,
    pub project: String,
    pub model: String,
    pub socket: String,
    pub gateway_bind: String,
    pub budget_tokens: i32,
    pub budget_period: String,
    pub no_app: bool,
    pub keep_config: bool,
}

impl LaunchConfig {
    pub fn from_env_and_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut agent = None;
        let mut config = Self {
            agent: String::new(),
            project: "sekai-chisei".to_string(),
            model: "gpt-5.5".to_string(),
            socket: std::env::var("SEKAI_SOCKET")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "./data/sekai.sock".to_string()),
            gateway_bind: std::env::var("GATEWAY_BIND")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "127.0.0.1:8788".to_string()),
            budget_tokens: 500_000,
            budget_period: "day".to_string(),
            no_app: false,
            keep_config: false,
        };

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--project" => config.project = next_arg(&mut args, &arg)?,
                "--model" => config.model = next_arg(&mut args, &arg)?,
                "--socket" => config.socket = next_arg(&mut args, &arg)?,
                "--gateway-bind" => config.gateway_bind = next_arg(&mut args, &arg)?,
                "--budget" | "--budget-tokens" => {
                    config.budget_tokens = next_arg(&mut args, &arg)?
                        .parse()
                        .map_err(|_| format!("{arg} must be an integer"))?;
                }
                "--budget-period" => config.budget_period = next_arg(&mut args, &arg)?,
                "--no-app" => config.no_app = true,
                "--keep-config" => config.keep_config = true,
                "--help" | "-h" => return Err(usage()),
                other if other.starts_with('-') => {
                    return Err(format!("unknown argument {other:?}\n\n{}", usage()));
                }
                other => {
                    if agent.replace(other.to_string()).is_some() {
                        return Err(format!(
                            "unexpected extra argument {other:?}\n\n{}",
                            usage()
                        ));
                    }
                }
            }
        }

        config.agent = agent.ok_or_else(|| format!("missing <agent>\n\n{}", usage()))?;
        if !config.no_app && config.agent != "codex-app" {
            return Err(format!(
                "launch currently opens an app only for agent \"codex-app\"; use --no-app to bring the stack up for agent {:?}",
                config.agent
            ));
        }
        Ok(config)
    }
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{flag} requires a value"))
}

pub fn usage() -> String {
    "Usage: sekaictl launch <agent> [--project <name>] [--model <model>] [--socket <path>] [--gateway-bind <addr>] [--budget <tokens>] [--budget-period <day|week|month>] [--no-app] [--keep-config]\n\nBrings up the local stack and opens the client app wired through the Chisei gateway:\n  1. loads ./.env into the environment for any unset variables\n  2. starts the sekai server on the Unix socket if it is not already running\n  3. seeds the agent project, gateway key, budget, and model policy (idempotent)\n  4. starts chisei-gateway if it is not already running: with OPENAI_API_KEY set it rewrites\n     Codex local-login auth for api.openai.com; without it, it forwards the Codex ChatGPT-plan\n     login to the ChatGPT backend unchanged\n  5. routes ~/.codex/config.toml through the gateway (the app is set to model \"auto\" so the\n     gateway resolves the real model via chisei policy), opens the Codex app, and restores the\n     config when the app quits (skip the revert with --keep-config)\n\n--model sets the gateway's default model (what \"auto\" resolves to), not a fixed app model.\n\nExample: sekaictl launch codex-app".to_string()
}

/// Loads ./.env into the environment for any unset variables. Call before
/// `LaunchConfig::from_env_and_args` so `.env` values feed the defaults.
pub fn load_local_env() {
    load_dotenv(Path::new(".env"));
}

pub async fn run_launch(
    config: LaunchConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    load_local_env();
    std::fs::create_dir_all(LOG_DIR)?;
    recover_stale_codex_config();

    ensure_server(&config).await?;
    seed_agent(&config).await?;
    ensure_gateway(&config).await?;

    if config.no_app {
        println!(
            "stack is up; gateway at http://{}",
            connect_addr(&config.gateway_bind)
        );
        return Ok(());
    }
    launch_codex_app(&config).await
}

async fn ensure_server(
    config: &LaunchConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if socket_ready(&config.socket).await {
        println!("sekai server already running at {}", config.socket);
        return Ok(());
    }

    let mut envs = vec![
        ("SEKAI_SOCKET".to_string(), config.socket.clone()),
        // The gateway supplies OpenAI upstream auth (ChatGPT-plan passthrough or a
        // gateway-owned key), so the control plane must treat openai as available
        // even without a local key — otherwise it rejects the resolved model and
        // the gateway fails open, forwarding the unresolved "auto" upstream.
        (
            "CHISEI_GATEWAY_PROVIDED_PROVIDERS".to_string(),
            "openai".to_string(),
        ),
    ];
    let auth_token = std::env::var("SEKAI_AUTH_TOKEN").unwrap_or_default();
    if auth_token.trim().is_empty() {
        envs.push(("SEKAI_INSECURE".to_string(), "1".to_string()));
        println!("starting sekai server in SEKAI_INSECURE=1 local mode");
    }
    let mut child = spawn_service(SERVER_BIN, &envs)?;

    let socket = config.socket.clone();
    wait_for(SERVER_BIN, &mut child, move || {
        let socket = socket.clone();
        async move { socket_ready(&socket).await }
    })
    .await
}

async fn seed_agent(config: &LaunchConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_setup(GatewaySetupConfig {
        chisei_grpc_target: config.socket.clone(),
        agent: config.agent.clone(),
        project: config.project.clone(),
        gateway_key_name: config.agent.clone(),
        gateway_key_secret: default_virtual_key(&config.agent),
        budget_tokens: config.budget_tokens,
        budget_period: config.budget_period.clone(),
        allowed_models: Vec::new(),
        default_model: config.model.clone(),
        default_runtime: "openai".to_string(),
    })
    .await
}

async fn ensure_gateway(
    config: &LaunchConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = connect_addr(&config.gateway_bind);
    if tcp_ready(&addr).await {
        println!("chisei-gateway already running at {addr}");
        return Ok(());
    }

    let mut envs = vec![
        ("SEKAI_SOCKET".to_string(), config.socket.clone()),
        ("GATEWAY_BIND".to_string(), config.gateway_bind.clone()),
        (
            "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH".to_string(),
            "1".to_string(),
        ),
    ];
    let has_api_key = !std::env::var("OPENAI_API_KEY")
        .unwrap_or_default()
        .trim()
        .is_empty();
    if has_api_key {
        // API-key mode: treat the Codex local-login bearer as identity only and
        // rewrite upstream auth to OPENAI_API_KEY for api.openai.com.
        envs.push((
            "CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH".to_string(),
            "1".to_string(),
        ));
        println!("starting chisei-gateway in API-key rewrite mode (OPENAI_API_KEY is set)");
    } else {
        // ChatGPT-plan mode: forward the Codex OAuth bearer and account headers
        // unchanged to the ChatGPT Codex backend, headroom-style.
        if std::env::var("CHISEI_OPENAI_BASE_URL")
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            envs.push((
                "CHISEI_OPENAI_BASE_URL".to_string(),
                "https://chatgpt.com/backend-api/codex".to_string(),
            ));
        }
        println!(
            "starting chisei-gateway in ChatGPT-plan passthrough mode (no OPENAI_API_KEY; forwarding Codex local login to the ChatGPT backend)"
        );
    }
    let mut child = spawn_service(GATEWAY_BIN, &envs)?;

    wait_for(GATEWAY_BIN, &mut child, move || {
        let addr = addr.clone();
        async move { tcp_ready(&addr).await }
    })
    .await
}

async fn launch_codex_app(
    config: &LaunchConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let base_url = format!("http://{}/v1", connect_addr(&config.gateway_bind));

    if codex_app_running() {
        println!(
            "warning: the Codex app is already running; it only reads config on a fresh start. Quit Codex fully and rerun `sekaictl launch codex-app` if traffic does not reach the gateway."
        );
    }

    // The desktop app ignores `codex app -c model_provider(s)` overrides for its
    // sessions, so routing must live in the user-level config. Apply it there and
    // restore the original once the app quits (unless --keep-config).
    let config_path = codex_config_path();
    let pristine = pristine_backup_path(&config_path);
    let original = std::fs::read_to_string(&config_path).unwrap_or_default();
    let managed = if chisei_routed(&original) {
        println!(
            "chisei provider already present in {}; leaving it in place (not reverting on app quit)",
            config_path.display()
        );
        false
    } else {
        std::fs::write(&pristine, &original)?;
        std::fs::write(
            &config_path,
            apply_chisei_config(&original, &base_url, &config.agent, &config.project),
        )?;
        println!(
            "applied chisei provider to {} (original saved to {})",
            config_path.display(),
            pristine.display()
        );
        true
    };

    println!("launching Codex app through {base_url}");
    let open_result = open_codex_app(config, &base_url);
    if let Err(err) = open_result {
        if managed {
            restore_codex_config(&config_path, &pristine)?;
        }
        return Err(err);
    }

    println!("verify traffic with:");
    println!(
        "  SEKAI_SOCKET={} sekaictl gateway report --by agent --since 10m",
        config.socket
    );

    if !managed {
        return Ok(());
    }
    if config.keep_config {
        println!(
            "--keep-config set: config stays routed through the gateway; restore {} over {} to revert",
            pristine.display(),
            config_path.display()
        );
        return Ok(());
    }

    println!("waiting for the Codex app to quit; the config reverts on exit (Ctrl-C also reverts)");
    wait_for_codex_app_exit().await;
    restore_codex_config(&config_path, &pristine)?;
    println!(
        "Codex app closed; restored {} — gateway and server stay running",
        config_path.display()
    );
    Ok(())
}

fn open_codex_app(
    config: &LaunchConfig,
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let provider_inline = format!(
        "{{name=\"Chisei Gateway\", base_url=\"{base_url}\", wire_api=\"responses\", requires_openai_auth=true, env_http_headers={{\"x-chisei-agent\"=\"CHISEI_CODEX_AGENT\", \"x-chisei-project\"=\"CHISEI_CODEX_PROJECT\"}}}}"
    );
    let status = Command::new("codex")
        .arg("app")
        .arg("-c")
        .arg(format!("model=\"{GATEWAY_AUTO_MODEL}\""))
        .arg("-c")
        .arg("model_provider=\"chisei\"")
        .arg("-c")
        .arg(format!("model_providers.chisei={provider_inline}"))
        .arg(std::env::current_dir()?)
        .env("CHISEI_CODEX_AGENT", &config.agent)
        .env("CHISEI_CODEX_PROJECT", &config.project)
        .env("CHISEI_CODEX_API_KEY", default_virtual_key(&config.agent))
        .status()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                std::io::Error::other(
                    "codex command not found; install the Codex app/CLI from https://openai.com/codex first",
                )
            } else {
                err
            }
        })?;
    if !status.success() {
        return Err(format!("codex app exited with {status}").into());
    }
    Ok(())
}

/// Waits until the Codex app process disappears (it may take a few seconds to
/// appear after `codex app` returns) or Ctrl-C is pressed.
async fn wait_for_codex_app_exit() {
    let watch = async {
        let appear_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while !codex_app_running() {
            if tokio::time::Instant::now() > appear_deadline {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        while codex_app_running() {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    tokio::select! {
        _ = watch => {}
        _ = tokio::signal::ctrl_c() => {
            println!("\nreceived Ctrl-C");
        }
    }
}

fn codex_config_path() -> PathBuf {
    let home = std::env::var("CODEX_HOME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".codex"));
    home.join("config.toml")
}

fn pristine_backup_path(config_path: &Path) -> PathBuf {
    let mut name = config_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    name.push_str(".chisei-pristine");
    config_path.with_file_name(name)
}

/// Reverts by stripping the chisei-managed lines from the *current* config
/// rather than writing back the launch-time snapshot: the Codex app rewrites
/// config.toml while running (trusted projects, marketplace timestamps), and
/// those changes must survive the revert. The pristine snapshot stays on disk
/// only until the strip succeeds, as a crash-recovery fallback.
fn restore_codex_config(
    config_path: &Path,
    pristine: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let current = std::fs::read_to_string(config_path).unwrap_or_default();
    std::fs::write(config_path, strip_chisei_config(&current))?;
    std::fs::remove_file(pristine).ok();
    Ok(())
}

/// Reverts a config left routed by a crashed earlier launch, if any. The
/// pristine marker file signals that a managed revert is still pending.
fn recover_stale_codex_config() {
    let config_path = codex_config_path();
    let pristine = pristine_backup_path(&config_path);
    if pristine.exists() && restore_codex_config(&config_path, &pristine).is_ok() {
        println!(
            "reverted {} left routed by an earlier launch",
            config_path.display()
        );
    }
}

fn chisei_routed(content: &str) -> bool {
    content.contains("[model_providers.chisei]")
}

const SAVED_PREFIX: &str = "#chisei-saved# ";
const MANAGED_COMMENT: &str =
    "# Managed by `sekaictl launch codex-app`; reverted automatically when the app quits.";
/// App-facing model. The app sends this placeholder; the gateway resolves it via
/// chisei policy to the namespace `default_model` (set by `--model`) and rewrites
/// the outgoing request. This is why the app never needs a model picker: model
/// choice is a governed, server-side decision.
const GATEWAY_AUTO_MODEL: &str = "auto";

/// Extracts the assignment key from a TOML line (the text before the first `=`),
/// or `None` for comments, table headers, and blank lines.
fn top_level_key(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
        return None;
    }
    let key = trimmed.split('=').next()?.trim();
    (!key.is_empty()).then_some(key)
}

/// Top-level keys `launch` takes over while the app is routed. Their originals
/// are commented out with `SAVED_PREFIX` so the revert can restore them.
const MANAGED_KEYS: &[&str] = &["model", "model_provider"];

/// Sets `model = "auto"` and `model_provider = "chisei"` at the top level
/// (commenting out any existing assignments so the revert can restore them) and
/// appends the chisei provider stanza. The app then sends `auto` and the gateway
/// resolves the real model.
fn apply_chisei_config(content: &str, base_url: &str, agent: &str, project: &str) -> String {
    let mut out = format!("model = \"{GATEWAY_AUTO_MODEL}\"\nmodel_provider = \"chisei\"\n");
    let mut in_top_level = true;
    for line in content.lines() {
        if line.trim_start().starts_with('[') {
            in_top_level = false;
        }
        if in_top_level && top_level_key(line).is_some_and(|key| MANAGED_KEYS.contains(&key)) {
            out.push_str(SAVED_PREFIX);
        }
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&format!(
        "{MANAGED_COMMENT}\n[model_providers.chisei]\nname = \"Chisei Gateway\"\nbase_url = \"{base_url}\"\nwire_api = \"responses\"\nrequires_openai_auth = true\nhttp_headers = {{ \"x-chisei-agent\" = \"{agent}\", \"x-chisei-project\" = \"{project}\" }}\n"
    ));
    out
}

/// Inverse of `apply_chisei_config`: drops the managed top-level assignments and
/// provider table, and uncomments any saved-out originals. Lines the app added or
/// changed while running are preserved.
fn strip_chisei_config(content: &str) -> String {
    let managed_lines = [
        format!("model = \"{GATEWAY_AUTO_MODEL}\""),
        "model_provider = \"chisei\"".to_string(),
    ];
    let mut out = String::new();
    let mut in_top_level = true;
    let mut in_chisei_table = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_top_level = false;
            in_chisei_table = trimmed.starts_with("[model_providers.chisei]");
            if in_chisei_table {
                continue;
            }
        }
        if in_chisei_table || line == MANAGED_COMMENT {
            continue;
        }
        if in_top_level && managed_lines.iter().any(|managed| trimmed == managed) {
            continue;
        }
        if let Some(saved) = line.strip_prefix(SAVED_PREFIX) {
            out.push_str(saved);
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn codex_app_running() -> bool {
    Command::new("pgrep")
        .args(["-x", "Codex"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

async fn socket_ready(path: &str) -> bool {
    tokio::net::UnixStream::connect(path).await.is_ok()
}

async fn tcp_ready(addr: &str) -> bool {
    tokio::net::TcpStream::connect(addr).await.is_ok()
}

fn connect_addr(bind: &str) -> String {
    bind.replacen("0.0.0.0", "127.0.0.1", 1)
}

fn spawn_service(
    name: &str,
    envs: &[(String, String)],
) -> Result<std::process::Child, Box<dyn std::error::Error + Send + Sync>> {
    let log_path = PathBuf::from(LOG_DIR).join(format!("{name}.log"));
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_err = log.try_clone()?;

    let mut command = match service_command(name)? {
        ServiceCommand::Binary(path) => Command::new(path),
        ServiceCommand::CargoRun => {
            let mut command = Command::new("cargo");
            command.args(["run", "--quiet", "--bin", name]);
            command
        }
    };
    let child = command
        .envs(envs.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()?;
    println!(
        "started {name} (pid {}) — logs: {}",
        child.id(),
        log_path.display()
    );
    Ok(child)
}

enum ServiceCommand {
    Binary(PathBuf),
    CargoRun,
}

fn service_command(name: &str) -> Result<ServiceCommand, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(current) = std::env::current_exe()
        && let Some(dir) = current.parent()
    {
        let sibling = dir.join(name);
        if sibling.is_file() {
            return Ok(ServiceCommand::Binary(sibling));
        }
    }
    if Path::new("Cargo.toml").exists() {
        return Ok(ServiceCommand::CargoRun);
    }
    Err(format!(
        "cannot find the {name} binary next to sekaictl, and no Cargo.toml in the current directory to build it from"
    )
    .into())
}

async fn wait_for<F, Fut>(
    name: &str,
    child: &mut std::process::Child,
    mut check: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "{name} exited ({status}) before becoming ready; check {LOG_DIR}/{name}.log"
            )
            .into());
        }
        tokio::time::sleep(READY_POLL).await;
    }
    Err(format!(
        "{name} did not become ready within {}s; check {LOG_DIR}/{name}.log",
        READY_TIMEOUT.as_secs()
    )
    .into())
}

fn load_dotenv(path: &Path) {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return;
    };
    for (key, value) in parse_dotenv(&contents) {
        if std::env::var_os(&key).is_none() {
            unsafe {
                std::env::set_var(&key, &value);
            }
        }
    }
}

fn parse_dotenv(contents: &str) -> Vec<(String, String)> {
    let mut vars = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|rest| rest.strip_suffix('\''))
            })
            .unwrap_or(value);
        vars.push((key.to_string(), value.to_string()));
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_launch_args() {
        let config = LaunchConfig::from_env_and_args([
            "codex-app".to_string(),
            "--project".to_string(),
            "demo".to_string(),
            "--model".to_string(),
            "gpt-5.5".to_string(),
            "--budget".to_string(),
            "42".to_string(),
            "--gateway-bind".to_string(),
            "0.0.0.0:9000".to_string(),
        ])
        .unwrap();

        assert_eq!(config.agent, "codex-app");
        assert_eq!(config.project, "demo");
        assert_eq!(config.model, "gpt-5.5");
        assert_eq!(config.budget_tokens, 42);
        assert_eq!(config.gateway_bind, "0.0.0.0:9000");
        assert!(!config.no_app);
    }

    #[test]
    fn requires_agent() {
        let err = LaunchConfig::from_env_and_args([]).unwrap_err();
        assert!(err.contains("missing <agent>"));
    }

    #[test]
    fn rejects_unsupported_app_agent() {
        let err = LaunchConfig::from_env_and_args(["claude-code".to_string()]).unwrap_err();
        assert!(err.contains("--no-app"));

        let config =
            LaunchConfig::from_env_and_args(["claude-code".to_string(), "--no-app".to_string()])
                .unwrap();
        assert!(config.no_app);
    }

    #[test]
    fn parses_dotenv_lines() {
        let vars = parse_dotenv(
            "# comment\n\nOPENAI_API_KEY=sk-test\nexport GATEWAY_BIND=\"127.0.0.1:8788\"\nQUOTED='v a l'\nNOEQUALS\n=missing\n",
        );
        assert_eq!(
            vars,
            vec![
                ("OPENAI_API_KEY".to_string(), "sk-test".to_string()),
                ("GATEWAY_BIND".to_string(), "127.0.0.1:8788".to_string()),
                ("QUOTED".to_string(), "v a l".to_string()),
            ]
        );
    }

    #[test]
    fn applies_and_detects_chisei_config() {
        let original = "model = \"gpt-5.5\"\nmodel_provider = \"other\"\n\n[projects.\"/x\"]\ntrust_level = \"trusted\"\nmodel_provider = \"keep-me\"\n";
        assert!(!chisei_routed(original));

        let updated = apply_chisei_config(
            original,
            "http://127.0.0.1:8788/v1",
            "codex-app",
            "sekai-chisei",
        );
        assert!(chisei_routed(&updated));
        // The app is set to defer to the gateway via the "auto" model.
        assert!(updated.starts_with("model = \"auto\"\nmodel_provider = \"chisei\"\n"));
        // Old top-level assignments are commented out; table-scoped keys are kept.
        assert!(updated.contains("#chisei-saved# model = \"gpt-5.5\""));
        assert!(updated.contains("#chisei-saved# model_provider = \"other\""));
        assert!(updated.contains("model_provider = \"keep-me\""));
        assert!(updated.contains("[model_providers.chisei]"));
        assert!(updated.contains("base_url = \"http://127.0.0.1:8788/v1\""));
        assert!(
            updated.contains(
                "http_headers = { \"x-chisei-agent\" = \"codex-app\", \"x-chisei-project\" = \"sekai-chisei\" }"
            )
        );
    }

    #[test]
    fn strip_reverts_apply_and_keeps_app_edits() {
        let original = "model = \"gpt-5.5\"\nmodel_provider = \"other\"\n\n[projects.\"/x\"]\ntrust_level = \"trusted\"\n";
        let updated = apply_chisei_config(
            original,
            "http://127.0.0.1:8788/v1",
            "codex-app",
            "sekai-chisei",
        );
        // The app rewrites config.toml while running; simulate an entry it added.
        let updated = format!("{updated}\n[projects.\"/y\"]\ntrust_level = \"trusted\"\n");

        let reverted = strip_chisei_config(&updated);
        assert!(!chisei_routed(&reverted));
        assert!(reverted.starts_with("model = \"gpt-5.5\"\nmodel_provider = \"other\"\n"));
        assert!(reverted.contains("[projects.\"/y\"]"));
        assert!(!reverted.contains("model_provider = \"chisei\""));
        assert!(!reverted.contains("model = \"auto\""));
        assert!(!reverted.contains(SAVED_PREFIX));
    }

    #[test]
    fn strip_restores_config_without_a_model_line() {
        // A user config that never had a top-level model line round-trips cleanly.
        let original = "model_provider = \"openai\"\n\n[features]\njs_repl = false\n";
        let updated = apply_chisei_config(
            original,
            "http://127.0.0.1:8788/v1",
            "codex-app",
            "sekai-chisei",
        );
        assert!(updated.contains("#chisei-saved# model_provider = \"openai\""));
        let reverted = strip_chisei_config(&updated);
        assert_eq!(reverted, original);
    }

    #[test]
    fn pristine_backup_sits_next_to_config() {
        assert_eq!(
            pristine_backup_path(Path::new("/home/u/.codex/config.toml")),
            PathBuf::from("/home/u/.codex/config.toml.chisei-pristine")
        );
    }

    #[test]
    fn rewrites_wildcard_bind_for_connect() {
        assert_eq!(connect_addr("0.0.0.0:8788"), "127.0.0.1:8788");
        assert_eq!(connect_addr("127.0.0.1:8788"), "127.0.0.1:8788");
    }
}
