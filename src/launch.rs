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

/// The provider family an app agent belongs to. It drives the four choices that
/// were previously Codex-hardcoded: the seeded `default_runtime`/`default_model`
/// (`seed_agent`), the server's `CHISEI_GATEWAY_PROVIDED_PROVIDERS`
/// (`ensure_server`), the gateway upstream-credential env (`ensure_gateway`), and
/// which app `run_launch` opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    /// `codex-app`: OpenAI-family wire (`/v1/responses`), config-file routed.
    OpenAi,
    /// `claude-code`: Anthropic-family wire (`/v1/messages`), env-var routed.
    Anthropic,
}

impl AgentKind {
    fn from_agent(agent: &str) -> Option<Self> {
        match agent {
            "codex-app" => Some(Self::OpenAi),
            "claude-code" => Some(Self::Anthropic),
            _ => None,
        }
    }

    /// The `default_model` the namespace policy resolves `auto`/unknown requests
    /// to, and the primary model Claude Code is told to send.
    fn default_model(self) -> &'static str {
        match self {
            Self::OpenAi => "gpt-5.5",
            Self::Anthropic => "claude-sonnet-4-6",
        }
    }

    /// The background haiku-class model Claude Code drives via
    /// `ANTHROPIC_SMALL_FAST_MODEL`; it must also be a policy-allowed model or the
    /// client's background requests get denied. OpenAI-family agents have none.
    fn small_fast_model(self) -> Option<&'static str> {
        match self {
            Self::OpenAi => None,
            Self::Anthropic => Some("claude-haiku-4-5"),
        }
    }

    /// The runtime/provider name used for the seeded policy, the control-plane's
    /// `CHISEI_GATEWAY_PROVIDED_PROVIDERS`, and upstream routing. Runtime and
    /// provider names coincide here.
    fn provider(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
        }
    }

    /// The canonical app-agent name this kind seeds and identifies as.
    fn agent_name(self) -> &'static str {
        match self {
            Self::OpenAi => "codex-app",
            Self::Anthropic => "claude-code",
        }
    }
}

/// Every provider family the shared local gateway serves. The gateway routes
/// upstream by resolved model, so one process fronts all of these at once; the
/// launcher configures the server, gateway, and namespace policy for every kind
/// regardless of which app is opened, so the standing gateway can serve any
/// client started later.
const ALL_KINDS: [AgentKind; 2] = [AgentKind::OpenAi, AgentKind::Anthropic];

/// How the gateway obtains Anthropic upstream credentials for `claude-code`,
/// chosen automatically from the environment (symmetric to the Codex path):
/// `ANTHROPIC_API_KEY` present → API-key mode; absent → subscription passthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnthropicUpstream {
    /// The gateway swaps the seeded virtual key for its own `ANTHROPIC_API_KEY`
    /// upstream (sanctioned, pay-per-token).
    ApiKey,
    /// No `ANTHROPIC_API_KEY`: Claude Code keeps its own subscription OAuth token
    /// (`sk-ant-oat-*`), which the gateway forwards verbatim to api.anthropic.com;
    /// identity/attribution ride `x-chisei-*` headers (stripped before upstream).
    SubscriptionPassthrough,
}

/// Picks the Anthropic upstream mode from the environment. Read once per launch;
/// the value is stable across `ensure_gateway` and `launch_claude_code` because
/// the process environment does not change between them.
fn anthropic_upstream_mode() -> AnthropicUpstream {
    if std::env::var("ANTHROPIC_API_KEY")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        AnthropicUpstream::SubscriptionPassthrough
    } else {
        AnthropicUpstream::ApiKey
    }
}

/// Extra env for the `chisei-gateway` child on the Anthropic path.
///
/// The gateway now resolves its own Anthropic upstream robustly: it reads only
/// `CHISEI_ANTHROPIC_BASE_URL` (no `ANTHROPIC_BASE_URL` fallback) and normalizes
/// the base to end in `/v1`. So the launcher no longer needs to pin the base URL
/// to sidestep the old footgun where the gateway fell back to the client-facing
/// `ANTHROPIC_BASE_URL` (often `https://api.anthropic.com` with no `/v1`, which
/// misrouted every request to `…/messages`). The only Anthropic-specific env the
/// launcher still adds is auth passthrough in subscription mode, so the client's
/// subscription OAuth token is forwarded upstream instead of being replaced.
fn anthropic_gateway_env(mode: AnthropicUpstream) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if mode == AnthropicUpstream::SubscriptionPassthrough {
        env.push((
            "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH".to_string(),
            "1".to_string(),
        ));
    }
    env
}

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
    pub estimate_context_tokens: Option<i64>,
    pub estimate_turns: i64,
}

impl LaunchConfig {
    pub fn from_env_and_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut agent = None;
        // Left empty here so the per-kind default can fill it once the agent is
        // known; an explicit `--model` sets it non-empty and wins.
        let mut config = Self {
            agent: String::new(),
            project: "sekai-chisei".to_string(),
            model: String::new(),
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
            estimate_context_tokens: None,
            estimate_turns: 1,
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
                "--estimate-context-tokens" => {
                    config.estimate_context_tokens = Some(
                        next_arg(&mut args, &arg)?
                            .parse()
                            .ok()
                            .filter(|value| *value > 0)
                            .ok_or_else(|| format!("{arg} must be a positive integer"))?,
                    );
                }
                "--estimate-turns" => {
                    config.estimate_turns = next_arg(&mut args, &arg)?
                        .parse()
                        .ok()
                        .filter(|value| *value > 0)
                        .ok_or_else(|| format!("{arg} must be a positive integer"))?;
                }
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
        let kind = AgentKind::from_agent(&config.agent);
        if !config.no_app && kind.is_none() {
            return Err(format!(
                "launch opens an app only for known app agents (codex-app, claude-code); use --no-app to bring the shared gateway up for agent {:?}",
                config.agent
            ));
        }
        if config.model.is_empty() {
            config.model = kind
                .map(|kind| kind.default_model().to_string())
                .unwrap_or_else(|| "gpt-5.5".to_string());
        }
        Ok(config)
    }

    fn kind(&self) -> Option<AgentKind> {
        AgentKind::from_agent(&self.agent)
    }
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn usage_text() -> String {
    "Usage: sekaictl launch <agent> [--project <name>] [--model <model>] [--socket <path>] [--gateway-bind <addr>] [--budget <tokens>] [--budget-period <day|week|month>] [--no-app] [--keep-config]\n\nKnown app agents: codex-app (OpenAI-family), claude-code (Anthropic-family).\nThe gateway routes by model, so one shared gateway serves every client; each\nlaunch brings it up (or reuses it) and configures the namespace policy for all\nclients. Use --no-app to bring the shared gateway up without opening an app.\n\nBrings up the local stack and opens the client app wired through the Chisei gateway:\n  1. loads ./.env into the environment for any unset variables\n  2. starts the sekai server on the Unix socket if it is not already running\n  3. seeds the agent project, gateway key, budget, and model policy (idempotent)\n  4. starts chisei-gateway if it is not already running:\n     - codex-app: with OPENAI_API_KEY set it rewrites Codex local-login auth for api.openai.com;\n       without it, it forwards the Codex ChatGPT-plan login to the ChatGPT backend unchanged\n     - claude-code: with ANTHROPIC_API_KEY set it swaps in that key for api.anthropic.com;\n       without it, it forwards Claude Code's own subscription login unchanged (passthrough)\n  5. wires the client through the gateway and opens it:\n     - codex-app: routes ~/.codex/config.toml (model \"auto\", resolved server-side), opens the\n       Codex app, and restores the config when it quits (skip the revert with --keep-config)\n     - claude-code: spawns `claude` with ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN/ANTHROPIC_MODEL\n       env vars (process-scoped; nothing to revert)\n\n--model sets the gateway's default model (what codex-app's \"auto\" resolves to, and the primary\nmodel claude-code is told to send), not necessarily a fixed app model.\n\nExample: sekaictl launch codex-app\n         sekaictl launch claude-code\n         sekaictl launch codex-app --no-app   # just bring the shared gateway up".to_string()
}

pub fn usage() -> String {
    usage_text().replacen(
        "[--no-app]",
        "[--estimate-context-tokens <tokens>] [--estimate-turns <count>] [--no-app]",
        1,
    )
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
    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "./data/sekai.db".into());
    let credential = crate::onboarding::ensure_local_credential(
        &db_path,
        &config.socket,
        &crate::onboarding::default_credential_path(),
    )?;
    if let Some(context_tokens) = config.estimate_context_tokens {
        let estimate_config = crate::cost_estimate::CostEstimateConfig {
            model: config.model.clone(),
            context_tokens,
            turns: config.estimate_turns,
            output_tokens_per_turn: None,
        };
        match crate::cost_estimate::pricing_from_env()
            .and_then(|pricing| crate::cost_estimate::estimate_cost(&estimate_config, &pricing))
        {
            Ok(estimate) => println!(
                "{}",
                crate::cost_estimate::render_estimate(&estimate_config, &estimate)
            ),
            Err(error) => eprintln!("warning: pre-launch cost estimate unavailable: {error}"),
        }
    }
    std::fs::create_dir_all(LOG_DIR)?;
    recover_stale_codex_config();

    ensure_server(&config, &db_path).await?;
    seed_agent(&config).await?;
    ensure_gateway(&config, &credential.token).await?;

    if config.no_app {
        let addr = connect_addr(&config.gateway_bind);
        println!("shared gateway is up at http://{addr} (serves every client, routed by model)");
        println!("start apps against it, e.g.:");
        println!("  sekaictl launch codex-app");
        println!("  sekaictl launch claude-code");
        return Ok(());
    }
    match config.kind() {
        Some(AgentKind::OpenAi) => launch_codex_app(&config).await,
        Some(AgentKind::Anthropic) => launch_claude_code(&config).await,
        // Unknown agents without --no-app are rejected in `from_env_and_args`.
        None => Err(format!("no app launcher for agent {:?}", config.agent).into()),
    }
}

async fn ensure_server(
    config: &LaunchConfig,
    db_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if socket_ready(&config.socket).await {
        println!("sekai server already running at {}", config.socket);
        return Ok(());
    }

    // The gateway supplies upstream auth (ChatGPT-plan passthrough, a gateway-owned
    // OpenAI key, or ANTHROPIC_API_KEY), so the control plane must treat every
    // served provider as available even without a local key — otherwise it rejects
    // the resolved model and the gateway fails open, forwarding an unresolved
    // request upstream. The shared gateway serves all clients, so this is always
    // the full set (`openai,anthropic`).
    let mut envs = vec![
        ("SEKAI_SOCKET".to_string(), config.socket.clone()),
        (
            "CHISEI_GATEWAY_PROVIDED_PROVIDERS".to_string(),
            provider_list(&ALL_KINDS),
        ),
    ];
    envs.push(("SEKAI_BIND".to_string(), "127.0.0.1".to_string()));
    envs.push(("DB_PATH".to_string(), db_path.to_string()));
    envs.push(("SEKAI_INSECURE".to_string(), String::new()));
    // The generated credential lives in the database. Do not also expose it as
    // the deprecated root-token compatibility credential in the server child.
    envs.push(("SEKAI_AUTH_TOKEN".to_string(), String::new()));
    println!("starting authenticated sekai server on local-only endpoints");
    let mut child = spawn_service(SERVER_BIN, &envs)?;

    let socket = config.socket.clone();
    wait_for(SERVER_BIN, &mut child, move || {
        let socket = socket.clone();
        async move { socket_ready(&socket).await }
    })
    .await
}

async fn seed_agent(config: &LaunchConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(kind) = config.kind() else {
        // Unknown agent brought up with --no-app: seed it verbatim (legacy path),
        // its own single runtime/model — no shared-namespace union.
        return run_setup(GatewaySetupConfig {
            chisei_grpc_target: config.socket.clone(),
            agent: config.agent.clone(),
            project: config.project.clone(),
            gateway_key_name: config.agent.clone(),
            gateway_key_secret: default_virtual_key(&config.agent),
            budget_tokens: config.budget_tokens,
            budget_period: config.budget_period.clone(),
            request_budget: None,
            request_budget_period: "day".to_string(),
            allowed_models: Vec::new(),
            allowed_runtimes: Vec::new(),
            tier: "standard".to_string(),
            default_model: config.model.clone(),
            default_runtime: "openai".to_string(),
            merge_into_existing: false,
            policy_scopes: Vec::new(),
        })
        .await;
    };

    // One shared namespace policy serves every client, so this launch seeds its
    // own agent/key/budget but a *union* policy: all runtimes and the union of
    // every kind's models. That lets the other client be launched separately
    // later without its seed clobbering this one's policy. The namespace default
    // (used only for Codex's `auto`) stays OpenAI-family — the launched Codex
    // model when launching codex-app, else gpt-5.5.
    //
    // Only Codex owns the `auto` default, so a non-OpenAI (claude-code) launch
    // merges into the existing policy: it unions the allowed lists but preserves
    // whatever default_model/default_runtime a prior Codex launch set, instead of
    // resetting `auto` back to gpt-5.5.
    let (default_runtime, default_model) = namespace_default(kind, &config.model);
    run_setup(GatewaySetupConfig {
        chisei_grpc_target: config.socket.clone(),
        agent: kind.agent_name().to_string(),
        project: config.project.clone(),
        gateway_key_name: kind.agent_name().to_string(),
        gateway_key_secret: default_virtual_key(kind.agent_name()),
        budget_tokens: config.budget_tokens,
        budget_period: config.budget_period.clone(),
        request_budget: None,
        request_budget_period: "day".to_string(),
        allowed_models: union_allowed_models(&config.model),
        allowed_runtimes: union_allowed_runtimes(),
        tier: "standard".to_string(),
        default_model,
        default_runtime,
        merge_into_existing: kind != AgentKind::OpenAi,
        policy_scopes: Vec::new(),
    })
    .await
}

/// Runtimes the shared namespace permits — every provider family.
fn union_allowed_runtimes() -> Vec<String> {
    ALL_KINDS
        .iter()
        .map(|kind| kind.provider().to_string())
        .collect()
}

/// Models the shared namespace permits: each kind's default and small/fast model,
/// plus `primary` (the launched agent's possibly-`--model`-overridden model),
/// deduped and order-preserving.
fn union_allowed_models(primary: &str) -> Vec<String> {
    let mut models: Vec<String> = Vec::new();
    for kind in ALL_KINDS {
        for model in std::iter::once(kind.default_model()).chain(kind.small_fast_model()) {
            if !models.iter().any(|existing| existing == model) {
                models.push(model.to_string());
            }
        }
    }
    if !primary.is_empty() && !models.iter().any(|existing| existing == primary) {
        models.push(primary.to_string());
    }
    models
}

/// The `auto`-resolution default for the shared namespace. Only Codex sends
/// `auto`, so the default stays OpenAI-family: the launched Codex model when
/// launching codex-app (honoring `--model`), otherwise gpt-5.5. Returns
/// `(default_runtime, default_model)`.
fn namespace_default(launched: AgentKind, launched_model: &str) -> (String, String) {
    let model = if launched == AgentKind::OpenAi {
        launched_model.to_string()
    } else {
        AgentKind::OpenAi.default_model().to_string()
    };
    (AgentKind::OpenAi.provider().to_string(), model)
}

async fn ensure_gateway(
    config: &LaunchConfig,
    auth_token: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = connect_addr(&config.gateway_bind);
    if tcp_ready(&addr).await {
        println!("chisei-gateway already running at {addr}");
        println!(
            "note: reusing the live gateway; it must already serve every client (started by `sekaictl launch …`) — a gateway brought up by other means may not be"
        );
        return Ok(());
    }

    let mut envs = vec![
        ("SEKAI_SOCKET".to_string(), config.socket.clone()),
        ("GATEWAY_BIND".to_string(), config.gateway_bind.clone()),
        ("SEKAI_AUTH_TOKEN".to_string(), auth_token.to_string()),
    ];

    // The gateway routes upstream by resolved model, so one process fronts every
    // provider family. Configure all of them so the standing gateway can serve any
    // client started later, regardless of which app triggered this launch.
    let kinds = ALL_KINDS;
    let has_openai_key = !std::env::var("OPENAI_API_KEY")
        .unwrap_or_default()
        .trim()
        .is_empty();
    let anthropic_mode = anthropic_upstream_mode();
    for kind in &kinds {
        match kind {
            AgentKind::OpenAi => {
                envs.extend(openai_gateway_env(
                    has_openai_key,
                    std::env::var("CHISEI_OPENAI_BASE_URL").ok().as_deref(),
                ));
                if has_openai_key {
                    println!(
                        "  openai: API-key rewrite mode for api.openai.com (OPENAI_API_KEY set)"
                    );
                } else {
                    println!(
                        "  openai: ChatGPT-plan passthrough (forwarding Codex login to the ChatGPT backend)"
                    );
                }
            }
            AgentKind::Anthropic => {
                envs.extend(anthropic_gateway_env(anthropic_mode));
                match anthropic_mode {
                    AnthropicUpstream::ApiKey => {
                        println!("  anthropic: ANTHROPIC_API_KEY upstream for api.anthropic.com")
                    }
                    AnthropicUpstream::SubscriptionPassthrough => println!(
                        "  anthropic: subscription passthrough (forwarding Claude Code's login to api.anthropic.com)"
                    ),
                }
            }
        }
    }
    let envs = dedup_env(envs);
    println!("starting chisei-gateway serving: {}", provider_list(&kinds));

    let mut child = spawn_service(GATEWAY_BIN, &envs)?;
    wait_for(GATEWAY_BIN, &mut child, move || {
        let addr = addr.clone();
        async move { tcp_ready(&addr).await }
    })
    .await
}

/// Comma-joined provider names for the served kinds (deduped, order-preserving);
/// `"openai"` when none are known (legacy fallback). Feeds the control plane's
/// `CHISEI_GATEWAY_PROVIDED_PROVIDERS`.
fn provider_list(kinds: &[AgentKind]) -> String {
    let mut providers: Vec<&str> = Vec::new();
    for kind in kinds {
        let provider = kind.provider();
        if !providers.contains(&provider) {
            providers.push(provider);
        }
    }
    if providers.is_empty() {
        "openai".to_string()
    } else {
        providers.join(",")
    }
}

/// Gateway env for the OpenAI path (Codex). Enables auth passthrough, then either
/// rewrites the Codex local-login bearer to `OPENAI_API_KEY` (when a key is
/// present) or points the upstream at the ChatGPT Codex backend (pinned only when
/// the operator has not set `CHISEI_OPENAI_BASE_URL`).
fn openai_gateway_env(has_openai_key: bool, existing_base: Option<&str>) -> Vec<(String, String)> {
    let mut env = vec![(
        "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH".to_string(),
        "1".to_string(),
    )];
    if has_openai_key {
        env.push((
            "CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH".to_string(),
            "1".to_string(),
        ));
    } else if existing_base.map(str::trim).unwrap_or("").is_empty() {
        env.push((
            "CHISEI_OPENAI_BASE_URL".to_string(),
            "https://chatgpt.com/backend-api/codex".to_string(),
        ));
    }
    env
}

/// Drops duplicate env keys, keeping the first occurrence. Combining per-kind
/// env sets can repeat shared keys (e.g. `CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH`);
/// the values agree, so first-wins is safe and keeps the child env tidy.
fn dedup_env(env: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(env.len());
    for (key, value) in env {
        if !out.iter().any(|(existing, _)| existing == &key) {
            out.push((key, value));
        }
    }
    out
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
        "  SEKAI_SOCKET={} sekaictl gateway report --by agent-within-project --since 10m",
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

/// Base URL Claude Code is pointed at. Unlike the Codex provider `base_url`, this
/// is the gateway host root with **no `/v1` suffix** — Claude Code appends
/// `/v1/messages` (and `/v1/messages/count_tokens`) itself.
fn claude_code_base_url(gateway_bind: &str) -> String {
    format!("http://{}", connect_addr(gateway_bind))
}

/// The env vars set on the `claude` child so it routes through the gateway. No
/// config file is involved (contrast the Codex path), so this is the whole
/// wiring. The auth wiring depends on the upstream mode:
///
/// - `ApiKey`: send the seeded virtual key as `ANTHROPIC_AUTH_TOKEN`; the gateway
///   resolves identity from the key store and swaps in its own `ANTHROPIC_API_KEY`
///   upstream. `x-chisei-agent` is deliberately **not** sent — it would flip the
///   gateway into passthrough and forward the virtual key (not a real Anthropic
///   credential) upstream.
/// - `SubscriptionPassthrough`: leave `ANTHROPIC_AUTH_TOKEN` unset so Claude Code
///   keeps its own subscription OAuth token, and carry identity/attribution in
///   `x-chisei-*` custom headers. Claude Code appends `ANTHROPIC_CUSTOM_HEADERS`
///   (newline-separated `Name: value`) to every request; the gateway derives
///   identity from `x-chisei-agent` and strips all `x-chisei-*` before forwarding
///   upstream (so api.anthropic.com sees an untampered subscription request).
fn claude_code_env(config: &LaunchConfig, upstream: AnthropicUpstream) -> Vec<(String, String)> {
    let mut env = vec![
        (
            "ANTHROPIC_BASE_URL".to_string(),
            claude_code_base_url(&config.gateway_bind),
        ),
        ("ANTHROPIC_MODEL".to_string(), config.model.clone()),
    ];
    if let Some(small_fast) = config.kind().and_then(AgentKind::small_fast_model) {
        env.push((
            "ANTHROPIC_SMALL_FAST_MODEL".to_string(),
            small_fast.to_string(),
        ));
    }
    match upstream {
        AnthropicUpstream::ApiKey => {
            env.push((
                "ANTHROPIC_AUTH_TOKEN".to_string(),
                default_virtual_key(&config.agent),
            ));
        }
        AnthropicUpstream::SubscriptionPassthrough => {
            env.push((
                "ANTHROPIC_CUSTOM_HEADERS".to_string(),
                format!(
                    "x-chisei-agent: {}\nx-chisei-project: {}",
                    config.agent, config.project
                ),
            ));
        }
    }
    env
}

/// Spawns Claude Code wired through the gateway. Claude Code is a CLI configured
/// entirely by environment variables, so — unlike the Codex app — there is no
/// config file to rewrite, revert, or crash-recover: the env is process-scoped
/// and vanishes when `claude` exits.
async fn launch_claude_code(
    config: &LaunchConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let env = claude_code_env(config, anthropic_upstream_mode());
    let base_url = claude_code_base_url(&config.gateway_bind);
    println!("launching Claude Code through {base_url}");

    // Inherit the TTY so the interactive TUI works; `status()` wires stdin/stdout/
    // stderr to the parent by default.
    let status = Command::new("claude")
        .envs(env.iter().map(|(key, value)| (key, value)))
        .status()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                std::io::Error::other(
                    "claude command not found; install Claude Code from https://docs.claude.com/en/docs/claude-code first",
                )
            } else {
                err
            }
        })?;
    if !status.success() {
        return Err(format!("claude exited with {status}").into());
    }

    println!("verify traffic with:");
    println!(
        "  SEKAI_SOCKET={} sekaictl gateway report --by work-unit --since 10m",
        config.socket
    );
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
            "--estimate-context-tokens".to_string(),
            "12000".to_string(),
            "--estimate-turns".to_string(),
            "4".to_string(),
        ])
        .unwrap();

        assert_eq!(config.agent, "codex-app");
        assert_eq!(config.project, "demo");
        assert_eq!(config.model, "gpt-5.5");
        assert_eq!(config.budget_tokens, 42);
        assert_eq!(config.gateway_bind, "0.0.0.0:9000");
        assert_eq!(config.estimate_context_tokens, Some(12_000));
        assert_eq!(config.estimate_turns, 4);
        assert!(!config.no_app);
    }

    #[test]
    fn requires_agent() {
        let err = LaunchConfig::from_env_and_args([]).unwrap_err();
        assert!(err.contains("missing <agent>"));
    }

    #[test]
    fn rejects_unknown_app_agent() {
        let err = LaunchConfig::from_env_and_args(["mystery-agent".to_string()]).unwrap_err();
        assert!(err.contains("--no-app"));
        assert!(err.contains("codex-app, claude-code"));

        // An unknown agent is still fine with --no-app (stack only, no app).
        let config =
            LaunchConfig::from_env_and_args(["mystery-agent".to_string(), "--no-app".to_string()])
                .unwrap();
        assert!(config.no_app);
        assert_eq!(config.kind(), None);
        // Unknown agents keep the historical gpt-5.5 default model.
        assert_eq!(config.model, "gpt-5.5");
    }

    #[test]
    fn claude_code_is_app_opening_without_no_app() {
        let config = LaunchConfig::from_env_and_args(["claude-code".to_string()]).unwrap();
        assert_eq!(config.agent, "claude-code");
        assert!(!config.no_app);
        assert_eq!(config.kind(), Some(AgentKind::Anthropic));
    }

    #[test]
    fn kind_resolution_picks_runtime_and_default_model() {
        let codex = LaunchConfig::from_env_and_args(["codex-app".to_string()]).unwrap();
        assert_eq!(codex.kind(), Some(AgentKind::OpenAi));
        assert_eq!(codex.kind().unwrap().provider(), "openai");
        assert_eq!(codex.model, "gpt-5.5");
        assert_eq!(codex.kind().unwrap().small_fast_model(), None);

        let claude = LaunchConfig::from_env_and_args(["claude-code".to_string()]).unwrap();
        assert_eq!(claude.kind(), Some(AgentKind::Anthropic));
        assert_eq!(claude.kind().unwrap().provider(), "anthropic");
        assert_eq!(claude.model, "claude-sonnet-4-6");
        assert_eq!(
            claude.kind().unwrap().small_fast_model(),
            Some("claude-haiku-4-5")
        );
    }

    #[test]
    fn explicit_model_overrides_kind_default() {
        let config = LaunchConfig::from_env_and_args([
            "claude-code".to_string(),
            "--model".to_string(),
            "claude-opus-4-8".to_string(),
        ])
        .unwrap();
        assert_eq!(config.model, "claude-opus-4-8");
    }

    #[test]
    fn claude_code_base_url_has_no_v1_suffix() {
        assert_eq!(
            claude_code_base_url("127.0.0.1:8788"),
            "http://127.0.0.1:8788"
        );
        // Wildcard binds are rewritten to a connectable loopback address.
        assert_eq!(
            claude_code_base_url("0.0.0.0:8788"),
            "http://127.0.0.1:8788"
        );
    }

    #[test]
    fn claude_code_env_api_key_mode() {
        let config = LaunchConfig::from_env_and_args([
            "claude-code".to_string(),
            "--gateway-bind".to_string(),
            "127.0.0.1:9000".to_string(),
        ])
        .unwrap();
        let env = claude_code_env(&config, AnthropicUpstream::ApiKey);

        let get = |key: &str| env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        assert_eq!(get("ANTHROPIC_BASE_URL"), Some("http://127.0.0.1:9000"));
        assert_eq!(get("ANTHROPIC_MODEL"), Some("claude-sonnet-4-6"));
        assert_eq!(get("ANTHROPIC_SMALL_FAST_MODEL"), Some("claude-haiku-4-5"));
        // API-key mode: the seeded virtual key is the bearer; no attribution
        // header (it would flip the gateway into passthrough).
        assert_eq!(get("ANTHROPIC_AUTH_TOKEN"), Some("sk-chisei-claude-code"));
        assert_eq!(get("ANTHROPIC_CUSTOM_HEADERS"), None);
    }

    #[test]
    fn anthropic_gateway_env_enables_passthrough_only_in_subscription_mode() {
        let get = |env: &[(String, String)], key: &str| {
            env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        };

        // Subscription passthrough: enable auth passthrough. The base URL is no
        // longer pinned — the gateway normalizes its own upstream to /v1 and does
        // not fall back to ANTHROPIC_BASE_URL, so the pin is redundant.
        let env = anthropic_gateway_env(AnthropicUpstream::SubscriptionPassthrough);
        assert_eq!(
            get(&env, "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH").as_deref(),
            Some("1")
        );
        assert_eq!(get(&env, "CHISEI_ANTHROPIC_BASE_URL"), None);

        // API-key mode: neither the base pin nor auth passthrough.
        let env = anthropic_gateway_env(AnthropicUpstream::ApiKey);
        assert_eq!(get(&env, "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH"), None);
        assert_eq!(get(&env, "CHISEI_ANTHROPIC_BASE_URL"), None);
    }

    #[test]
    fn all_kinds_covers_both_provider_families() {
        // The shared gateway always serves every kind, so the provider list feeding
        // the control plane is the full set.
        assert_eq!(provider_list(&ALL_KINDS), "openai,anthropic");
    }

    #[test]
    fn union_policy_covers_both_clients() {
        // The namespace allows both runtimes so a Codex and a Claude Code launch
        // can share it without clobbering each other's policy.
        assert_eq!(union_allowed_runtimes(), vec!["openai", "anthropic"]);

        // Union models: every kind's default + small/fast, plus the launched
        // primary (deduped). Launching claude-code with its default adds nothing new.
        let models = union_allowed_models("claude-sonnet-4-6");
        assert!(models.contains(&"gpt-5.5".to_string()));
        assert!(models.contains(&"claude-sonnet-4-6".to_string()));
        assert!(models.contains(&"claude-haiku-4-5".to_string()));

        // An overridden primary is added.
        let overridden = union_allowed_models("claude-opus-4-8");
        assert!(overridden.contains(&"claude-opus-4-8".to_string()));
        // No duplicates.
        let mut sorted = overridden.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), overridden.len());
    }

    #[test]
    fn namespace_default_stays_openai_for_auto() {
        // Codex sends `auto`; the namespace default must resolve to a gpt model.
        // Launching claude-code must NOT flip the default to a Claude model.
        assert_eq!(
            namespace_default(AgentKind::Anthropic, "claude-sonnet-4-6"),
            ("openai".to_string(), "gpt-5.5".to_string())
        );
        // Launching codex-app honors its --model as the auto target.
        assert_eq!(
            namespace_default(AgentKind::OpenAi, "gpt-6"),
            ("openai".to_string(), "gpt-6".to_string())
        );
    }

    #[test]
    fn provider_list_dedups_and_joins() {
        assert_eq!(
            provider_list(&[AgentKind::OpenAi, AgentKind::Anthropic]),
            "openai,anthropic"
        );
        assert_eq!(provider_list(&[AgentKind::Anthropic]), "anthropic");
        // Empty (unknown agent) falls back to openai.
        assert_eq!(provider_list(&[]), "openai");
    }

    #[test]
    fn openai_gateway_env_modes() {
        let get = |env: &[(String, String)], key: &str| {
            env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
        };

        // No key, no operator base: passthrough + pin the ChatGPT backend.
        let env = openai_gateway_env(false, None);
        assert_eq!(
            get(&env, "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH").as_deref(),
            Some("1")
        );
        assert_eq!(
            get(&env, "CHISEI_OPENAI_BASE_URL").as_deref(),
            Some("https://chatgpt.com/backend-api/codex")
        );
        assert_eq!(
            get(&env, "CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH"),
            None
        );

        // Key present: rewrite mode, no base pin.
        let env = openai_gateway_env(true, None);
        assert_eq!(
            get(&env, "CHISEI_GATEWAY_REWRITE_OPENAI_PASSTHROUGH_AUTH").as_deref(),
            Some("1")
        );
        assert_eq!(get(&env, "CHISEI_OPENAI_BASE_URL"), None);

        // Operator base set: respected (not overridden).
        let env = openai_gateway_env(false, Some("https://my.internal/v1"));
        assert_eq!(get(&env, "CHISEI_OPENAI_BASE_URL"), None);
    }

    #[test]
    fn dedup_env_keeps_first_occurrence() {
        // Combining the OpenAI + Anthropic (passthrough) env repeats the shared
        // passthrough flag; dedup collapses it to a single entry.
        let combined: Vec<(String, String)> = openai_gateway_env(false, None)
            .into_iter()
            .chain(anthropic_gateway_env(
                AnthropicUpstream::SubscriptionPassthrough,
            ))
            .collect();
        let deduped = dedup_env(combined);
        let passthrough = deduped
            .iter()
            .filter(|(k, _)| k == "CHISEI_GATEWAY_ALLOW_AUTH_PASSTHROUGH")
            .count();
        assert_eq!(passthrough, 1, "shared passthrough flag must appear once");
        // The OpenAI ChatGPT-backend base survives; the Anthropic base is no
        // longer emitted by the launcher (the gateway normalizes its own).
        assert!(deduped.iter().any(|(k, _)| k == "CHISEI_OPENAI_BASE_URL"));
        assert!(
            !deduped
                .iter()
                .any(|(k, _)| k == "CHISEI_ANTHROPIC_BASE_URL")
        );
    }

    #[test]
    fn claude_code_env_subscription_passthrough_mode() {
        let config = LaunchConfig::from_env_and_args([
            "claude-code".to_string(),
            "--project".to_string(),
            "demo".to_string(),
        ])
        .unwrap();
        let env = claude_code_env(&config, AnthropicUpstream::SubscriptionPassthrough);

        let get = |key: &str| env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        assert_eq!(get("ANTHROPIC_MODEL"), Some("claude-sonnet-4-6"));
        assert_eq!(get("ANTHROPIC_SMALL_FAST_MODEL"), Some("claude-haiku-4-5"));
        // Passthrough: leave Claude Code's own OAuth token in place (no
        // ANTHROPIC_AUTH_TOKEN) and carry identity/attribution in x-chisei-*.
        assert_eq!(get("ANTHROPIC_AUTH_TOKEN"), None);
        assert_eq!(
            get("ANTHROPIC_CUSTOM_HEADERS"),
            Some("x-chisei-agent: claude-code\nx-chisei-project: demo")
        );
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
