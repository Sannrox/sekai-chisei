use std::collections::{HashMap, HashSet};
use std::env;

use crate::support::METRIC_REQUESTS;

use crate::client::GatewayClient;
use chrono::Utc;
use tonic::Request as GrpcRequest;

use crate::client::connect_sekai;
use chisei_provider::gateway_keys::default_virtual_key;
use sekai_domain::gateway_keys::hash_gateway_key;
use sekai_proto::chisei::chisei_service_client::ChiseiServiceClient;
use sekai_proto::chisei::{SetBudgetLimitRequest, SetNamespacePolicyRequest};
use sekai_proto::sekai::sekai_service_client::SekaiServiceClient;
use sekai_proto::sekai::{
    ColumnDef, CreateDatasetRequest, CreateLinkRequest, CreateObjectRequest, Dataset,
    FindByExternalIdRequest, Link, ListFilter, ListObjectsRequest, Object, UpdateDatasetRequest,
    UpdateObjectRequest,
};

const DEFAULT_CONTEXT_ADMISSION_POLICY_JSON: &str = r#"{"contract_version":"chisei.context-admission/v1","default_action":"include","unknown_action":"hold_out","rules":[]}"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySetupConfig {
    pub chisei_grpc_target: String,
    pub agent: String,
    pub project: String,
    pub gateway_key_name: String,
    pub gateway_key_secret: String,
    pub budget_tokens: i32,
    pub budget_period: String,
    pub request_budget: Option<i32>,
    pub request_budget_period: String,
    pub allowed_models: Vec<String>,
    /// Runtimes the namespace policy permits. Empty means "just `default_runtime`"
    /// (the common single-provider case). Set to more than one to let a shared
    /// namespace serve multiple provider families (e.g. openai + anthropic).
    pub allowed_runtimes: Vec<String>,
    pub tier: String,
    pub default_model: String,
    pub default_runtime: String,
    /// When true, merge into any existing namespace policy instead of
    /// overwriting it: union `allowed_models`/`allowed_runtimes` with the
    /// stored policy and preserve its `default_model`/`default_runtime` (falling
    /// back to this config's defaults only when no policy exists yet). Used so a
    /// second client's launch (e.g. `claude-code` after `codex-app`) does not
    /// clobber the shared namespace `auto` default the first client set.
    pub merge_into_existing: bool,
    /// Optional scope identifiers for additional policy rows to seed in addition
    /// to the project scope. Common examples are `agent:<name>` and
    /// `gateway_key:<name>`, which then participate in the policy-scopes chain
    /// used by canonical gateway decisions.
    pub policy_scopes: Vec<String>,
}

impl GatewaySetupConfig {
    pub fn from_env_and_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config = Self {
            chisei_grpc_target: std::env::var("CHISEI_GRPC_URL")
                .or_else(|_| std::env::var("SEKAI_SOCKET"))
                .unwrap_or_else(|_| "./data/sekai.sock".to_string()),
            agent: "codex-app".to_string(),
            project: "sekai-chisei".to_string(),
            gateway_key_name: "codex-app".to_string(),
            gateway_key_secret: default_virtual_key("codex-app"),
            budget_tokens: 500_000,
            budget_period: "day".to_string(),
            request_budget: None,
            request_budget_period: "day".to_string(),
            allowed_models: Vec::new(),
            allowed_runtimes: Vec::new(),
            tier: "standard".to_string(),
            default_model: "gpt-5.5".to_string(),
            default_runtime: "openai".to_string(),
            merge_into_existing: false,
            policy_scopes: Vec::new(),
        };

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--chisei-grpc-url" | "--target" => {
                    config.chisei_grpc_target = next_arg(&mut args, &arg)?;
                }
                "--agent" => config.agent = next_arg(&mut args, &arg)?,
                "--project" | "--namespace" => config.project = next_arg(&mut args, &arg)?,
                "--gateway-key-name" | "--key-name" => {
                    config.gateway_key_name = next_arg(&mut args, &arg)?;
                    if config.gateway_key_secret.is_empty()
                        || config.gateway_key_secret == default_virtual_key("codex-app")
                    {
                        config.gateway_key_secret = default_virtual_key(&config.gateway_key_name);
                    }
                }
                "--gateway-key" | "--key" | "--gateway-key-secret" => {
                    config.gateway_key_secret = next_arg(&mut args, &arg)?;
                }
                "--budget" | "--budget-tokens" => {
                    config.budget_tokens = next_arg(&mut args, &arg)?
                        .parse()
                        .map_err(|_| format!("{arg} must be an integer"))?;
                }
                "--budget-period" => config.budget_period = next_arg(&mut args, &arg)?,
                "--request-budget" => {
                    config.request_budget = Some(
                        next_arg(&mut args, &arg)?
                            .parse()
                            .map_err(|_| format!("{arg} must be an integer"))?,
                    );
                }
                "--request-budget-period" => {
                    config.request_budget_period = next_arg(&mut args, &arg)?
                }
                "--allowed-model" => config.allowed_models.push(next_arg(&mut args, &arg)?),
                "--allowed-models" => {
                    config.allowed_models = split_csv(&next_arg(&mut args, &arg)?);
                }
                "--scope-policy" => config.policy_scopes.push(next_arg(&mut args, &arg)?),
                "--allowed-runtime" => config.allowed_runtimes.push(next_arg(&mut args, &arg)?),
                "--allowed-runtimes" => {
                    config.allowed_runtimes = split_csv(&next_arg(&mut args, &arg)?);
                }
                "--tier" => config.tier = next_arg(&mut args, &arg)?,
                "--default-model" => config.default_model = next_arg(&mut args, &arg)?,
                "--default-runtime" => config.default_runtime = next_arg(&mut args, &arg)?,
                "--merge-policy" => config.merge_into_existing = true,
                "--help" | "-h" => return Err(usage()),
                other => return Err(format!("unknown argument {other:?}\n\n{}", usage())),
            }
        }

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("agent", &self.agent),
            ("project", &self.project),
            ("gateway_key_name", &self.gateway_key_name),
            ("gateway_key_secret", &self.gateway_key_secret),
            ("default_model", &self.default_model),
            ("default_runtime", &self.default_runtime),
            ("tier", &self.tier),
            ("chisei_grpc_target", &self.chisei_grpc_target),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} must not be empty"));
            }
        }
        if self.budget_tokens <= 0 {
            return Err("budget_tokens must be positive".to_string());
        }
        if self
            .request_budget
            .is_some_and(|request_budget| request_budget <= 0)
        {
            return Err("request_budget must be positive".to_string());
        }
        if self.request_budget_period.trim().is_empty() {
            return Err("request_budget_period must not be empty".to_string());
        }
        for scope in &self.policy_scopes {
            if scope.trim().is_empty() {
                return Err("policy scope must not be empty".to_string());
            }
        }
        Ok(())
    }

    /// The runtimes the namespace policy should permit: the explicit
    /// `allowed_runtimes` when set, otherwise just `default_runtime`.
    fn effective_allowed_runtimes(&self) -> Vec<String> {
        if self.allowed_runtimes.is_empty() {
            vec![self.default_runtime.clone()]
        } else {
            self.allowed_runtimes.clone()
        }
    }
}

pub async fn run_setup(
    config: GatewaySetupConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_sekai(&config.chisei_grpc_target).await?;
    let mut sekai = SekaiServiceClient::new(channel.clone());
    let mut chisei = ChiseiServiceClient::new(channel);

    // Resolve the effective namespace policy BEFORE seeding graph objects.
    // `ensure_gateway_objects` also writes the `policy:<project>` graph object,
    // so the merge must happen first or that write would clobber the existing
    // policy before we could read it. When merging, union the allowed lists with
    // the stored policy and preserve its default_model/default_runtime so a
    // second client's launch does not reset the shared `auto` default.
    let desired_allowed_models = if config.allowed_models.is_empty() {
        vec![config.default_model.clone()]
    } else {
        config.allowed_models.clone()
    };
    let desired_allowed_runtimes = config.effective_allowed_runtimes();
    let scope_allowed_models = desired_allowed_models.clone();
    let scope_allowed_runtimes = desired_allowed_runtimes.clone();
    let scope_default_model = config.default_model.clone();
    let scope_default_runtime = config.default_runtime.clone();
    let (allowed_models, allowed_runtimes, default_model, default_runtime) = match (
        config.merge_into_existing,
        fetch_existing_policy(&mut sekai, &config).await?,
    ) {
        (true, Some(existing)) => (
            csv_union(&existing.allowed_models, &desired_allowed_models),
            csv_union(&existing.allowed_runtimes, &desired_allowed_runtimes),
            first_non_empty(&existing.default_model, &config.default_model),
            first_non_empty(&existing.default_runtime, &config.default_runtime),
        ),
        _ => (
            desired_allowed_models,
            desired_allowed_runtimes,
            config.default_model.clone(),
            config.default_runtime.clone(),
        ),
    };

    // A config carrying the resolved policy so the graph policy object and the
    // chisei namespace policy are seeded from the same values.
    let resolved_config = GatewaySetupConfig {
        allowed_models: allowed_models.clone(),
        allowed_runtimes: allowed_runtimes.clone(),
        default_model: default_model.clone(),
        default_runtime: default_runtime.clone(),
        merge_into_existing: false,
        ..config.clone()
    };

    ensure_gateway_objects(&mut sekai, &resolved_config).await?;
    ensure_llm_calls_dataset(&mut sekai).await?;
    chisei
        .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
            user_id: format!("agent:{}", config.agent),
            max_tokens: config.budget_tokens,
            period_type: config.budget_period.clone(),
            // Leave `subject` empty so the server seeds the limit at the
            // same project/agent scope the gateway's request path checks
            // against (`project:{project}/agent:{agent}`), while allowing
            // the chain's additional flat `agent:{agent}` enforcement.
            subject: String::new(),
            project: config.project.clone(),
            agent: config.agent.clone(),
            key_id: config.gateway_key_name.clone(),
            work_unit: String::new(),
            metric: String::new(),
        }))
        .await?;

    if let Some(request_budget) = config.request_budget {
        chisei
            .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
                user_id: String::new(),
                max_tokens: request_budget,
                period_type: config.request_budget_period.clone(),
                // Project-scoped request quota first so the project-level cap
                // is enforced for all agents in this namespace.
                subject: format!("project:{}", config.project),
                project: config.project.clone(),
                agent: String::new(),
                key_id: String::new(),
                work_unit: String::new(),
                metric: METRIC_REQUESTS.to_string(),
            }))
            .await?;

        // Agent-pair request quota for this agent; combined with the project cap
        // this creates a true shared-cap + per-agent rate limiter.
        chisei
            .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
                user_id: String::new(),
                max_tokens: request_budget,
                period_type: config.request_budget_period.clone(),
                subject: String::new(),
                project: config.project.clone(),
                agent: config.agent.clone(),
                key_id: String::new(),
                work_unit: String::new(),
                metric: METRIC_REQUESTS.to_string(),
            }))
            .await?;
    }

    let context_admission_policy_json = if config.merge_into_existing {
        String::new()
    } else {
        DEFAULT_CONTEXT_ADMISSION_POLICY_JSON.to_string()
    };

    chisei
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: config.project.clone(),
            allowed_runtimes,
            allowed_models,
            default_runtime: default_runtime.clone(),
            default_model: default_model.clone(),
            data_class: String::new(),
            context_admission_policy_json: context_admission_policy_json.clone(),
            impact_route_policy_json: String::new(),
        }))
        .await?;

    let mut policy_scopes: HashSet<String> = config.policy_scopes.into_iter().collect();
    let resolved_policy_scopes = resolved_config.policy_scopes.clone();
    policy_scopes.remove(&config.project);
    for scope in policy_scopes {
        chisei
            .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
                namespace: scope.clone(),
                allowed_runtimes: scope_allowed_runtimes.clone(),
                allowed_models: scope_allowed_models.clone(),
                default_runtime: scope_default_runtime.clone(),
                default_model: scope_default_model.clone(),
                data_class: String::new(),
                context_admission_policy_json: context_admission_policy_json.clone(),
                impact_route_policy_json: String::new(),
            }))
            .await?;
    }

    println!("seeded chisei gateway setup");
    println!("  agent: {}", config.agent);
    println!("  project: {}", config.project);
    println!("  user_id: agent:{}", config.agent);
    println!("  tier: {}", config.tier);
    println!("  gateway key name: {}", config.gateway_key_name);
    println!(
        "  virtual key: {}",
        displayed_virtual_key(&config.gateway_key_name, &config.gateway_key_secret)
    );
    println!(
        "  budget: {} tokens per {}",
        config.budget_tokens, config.budget_period
    );
    if let Some(request_budget) = config.request_budget {
        println!(
            "  request budget: {} requests per {}",
            request_budget, config.request_budget_period
        );
    }
    if !resolved_policy_scopes.is_empty() {
        println!(
            "  additional policy scopes: {}",
            resolved_policy_scopes.join(", ")
        );
    }
    println!("  default model: {default_model}");
    Ok(())
}

/// Existing namespace policy fields read back from the stored `policy:<ns>`
/// object for merge-into-existing seeding.
struct ExistingNamespacePolicy {
    allowed_models: Vec<String>,
    allowed_runtimes: Vec<String>,
    default_model: String,
    default_runtime: String,
}

/// Reads the stored namespace policy object (`external_id = policy:<namespace>`)
/// if one exists. Returns `None` when the namespace has no policy yet.
///
/// This graph object is the persistent source of truth for the namespace policy:
/// `chisei_service::persist_namespace_policy` writes this exact object on every
/// `set_namespace_policy`, `ensure_gateway_objects` writes the same object, and
/// the in-memory `PolicyResolver` that governs `auto` resolution is loaded from
/// it at startup. So the two writers never diverge and reading the graph object
/// is equivalent to reading chisei's authoritative namespace policy.
async fn fetch_existing_policy(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    config: &GatewaySetupConfig,
) -> Result<Option<ExistingNamespacePolicy>, Box<dyn std::error::Error + Send + Sync>> {
    let namespace = &config.project;
    let resp = match sekai
        .find_by_external_id(gateway_request(FindByExternalIdRequest {
            external_id: format!("policy:{namespace}"),
        }))
        .await
    {
        Ok(resp) => resp,
        Err(err) if err.code() == tonic::Code::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let Some(object) = resp.into_inner().object else {
        return Ok(None);
    };
    let prop = |key: &str| object.properties.get(key).cloned().unwrap_or_default();
    Ok(Some(ExistingNamespacePolicy {
        allowed_models: split_csv(&prop("allowed_models")),
        allowed_runtimes: split_csv(&prop("allowed_runtimes")),
        default_model: prop("default_model"),
        default_runtime: prop("default_runtime"),
    }))
}

/// Order-preserving union of two string lists (existing first, then new).
fn csv_union(existing: &[String], incoming: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in existing.iter().chain(incoming.iter()) {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !out.iter().any(|item| item == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Returns `primary` when it is non-empty, otherwise `fallback`.
fn first_non_empty(primary: &str, fallback: &str) -> String {
    if primary.trim().is_empty() {
        fallback.to_string()
    } else {
        primary.to_string()
    }
}

/// Text the setup summary shows for the virtual key. The default key is derived
/// from the key name and printed so clients can be configured; an
/// operator-supplied secret is never echoed, since setup output ends up in logs.
fn displayed_virtual_key(name: &str, secret: &str) -> String {
    if secret == default_virtual_key(name) {
        secret.to_string()
    } else {
        "******** (operator-supplied, not shown)".to_string()
    }
}

pub async fn run_gateway_key_command<I>(
    args: I,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    I: IntoIterator<Item = String>,
{
    let args = args.into_iter().collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("create") {
        let config = GatewaySetupConfig::from_env_and_args(normalize_key_create_args(
            args.into_iter().skip(1),
        ))
        .map_err(|err| format!("invalid chisei-gateway key create config: {err}"))?;
        return run_setup(config).await;
    }
    let command = GatewayKeyCommand::from_env_and_args(args)?;
    let channel = connect_sekai(&command.target).await?;
    let mut sekai = SekaiServiceClient::new(channel);
    match command.action {
        GatewayKeyAction::List { project } => {
            println!("name\tproject\ttier\tagent\tstatus\tsecret_storage\tupdated");
            let namespace = project.unwrap_or_default();
            let mut offset = 0;
            loop {
                let resp = sekai
                    .list_objects(gateway_request(ListObjectsRequest {
                        filter: Some(ListFilter {
                            kind: "gateway_key".to_string(),
                            name: String::new(),
                            namespace: namespace.clone(),
                            limit: 1000,
                            offset,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }))
                    .await?
                    .into_inner();
                for object in resp.objects.iter() {
                    println!(
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        object.name,
                        object.namespace,
                        object
                            .properties
                            .get("tier")
                            .filter(|value| !value.is_empty())
                            .cloned()
                            .unwrap_or_else(|| "standard".to_string()),
                        object.properties.get("agent").cloned().unwrap_or_default(),
                        object
                            .properties
                            .get("status")
                            .cloned()
                            .unwrap_or_else(|| "active".to_string()),
                        object
                            .properties
                            .get("secret_storage")
                            .cloned()
                            .unwrap_or_default(),
                        object.updated
                    );
                }
                if resp.objects.is_empty() {
                    break;
                }
                if (offset + resp.objects.len() as i32) >= resp.total {
                    break;
                }
                offset += 1000;
            }
        }
        GatewayKeyAction::Rotate { name, secret } => {
            let mut object = gateway_key_object(&mut sekai, &name).await?;
            object
                .properties
                .insert("key_hash".to_string(), hash_gateway_key(&secret));
            object
                .properties
                .insert("secret_storage".to_string(), "sha256".to_string());
            object
                .properties
                .insert("status".to_string(), "active".to_string());
            object.properties.insert(
                "rotated_at".to_string(),
                Utc::now().timestamp_millis().to_string(),
            );
            object.updated = Utc::now().timestamp_millis();
            sekai
                .update_object(gateway_request(UpdateObjectRequest {
                    object: Some(object),
                    lease_precondition: None,
                }))
                .await?;
            println!("rotated gateway key {name}");
            if let Err(err) = refresh_gateway_cache("rotate", &name).await {
                eprintln!("warning: rotated {name} but failed to refresh gateway key cache: {err}");
            } else {
                println!("refreshed gateway key cache");
            }
        }
        GatewayKeyAction::Revoke { name } => {
            let mut object = gateway_key_object(&mut sekai, &name).await?;
            object
                .properties
                .insert("status".to_string(), "revoked".to_string());
            object.properties.insert(
                "revoked_at".to_string(),
                Utc::now().timestamp_millis().to_string(),
            );
            object.updated = Utc::now().timestamp_millis();
            sekai
                .update_object(gateway_request(UpdateObjectRequest {
                    object: Some(object),
                    lease_precondition: None,
                }))
                .await?;
            println!("revoked gateway key {name}");
            if let Err(err) = refresh_gateway_cache("revoke", &name).await {
                eprintln!("warning: revoked {name} but failed to refresh gateway key cache: {err}");
            } else {
                println!("refreshed gateway key cache");
            }
        }
    }
    Ok(())
}

async fn refresh_gateway_cache(
    action: &str,
    key_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut url =
        env::var("CHISEI_GATEWAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8788".to_string());
    url = url
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .to_string();
    let endpoint = format!("{url}/_chisei/admin/refresh");

    let mut request = reqwest::Client::new().post(endpoint);
    if let Ok(token) = env::var("CHISEI_GATEWAY_ADMIN_TOKEN")
        && !token.trim().is_empty()
    {
        request = request.bearer_auth(token);
    }

    let response = request.send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "gateway refresh for {action} of key {key_name} failed with {status}: {body}"
        )
        .into());
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayKeyCommand {
    target: String,
    action: GatewayKeyAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GatewayKeyAction {
    List { project: Option<String> },
    Rotate { name: String, secret: String },
    Revoke { name: String },
}

impl GatewayKeyCommand {
    fn from_env_and_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut target = std::env::var("CHISEI_GRPC_URL")
            .or_else(|_| std::env::var("SEKAI_SOCKET"))
            .unwrap_or_else(|_| "./data/sekai.sock".to_string());
        let mut args = args.into_iter();
        let Some(command) = args.next() else {
            return Err(key_usage());
        };
        let mut name = String::new();
        let mut secret = String::new();
        let mut project = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--chisei-grpc-url" | "--target" => target = next_arg(&mut args, &arg)?,
                "--project" | "--namespace" => project = Some(next_arg(&mut args, &arg)?),
                "--gateway-key-name" | "--key-name" => name = next_arg(&mut args, &arg)?,
                "--gateway-key" | "--key" | "--gateway-key-secret" => {
                    secret = next_arg(&mut args, &arg)?;
                }
                "--help" | "-h" => return Err(key_usage()),
                other => return Err(format!("unknown key argument {other:?}\n\n{}", key_usage())),
            }
        }
        if target.trim().is_empty() {
            return Err("target must not be empty".to_string());
        }
        let action = match command.as_str() {
            "list" => GatewayKeyAction::List { project },
            "rotate" => {
                if name.trim().is_empty() {
                    return Err("key rotate requires --gateway-key-name".to_string());
                }
                if secret.trim().is_empty() {
                    return Err("key rotate requires --gateway-key".to_string());
                }
                GatewayKeyAction::Rotate { name, secret }
            }
            "revoke" => {
                if name.trim().is_empty() {
                    return Err("key revoke requires --gateway-key-name".to_string());
                }
                GatewayKeyAction::Revoke { name }
            }
            other => return Err(format!("unknown key command {other:?}\n\n{}", key_usage())),
        };
        Ok(Self { target, action })
    }
}

async fn gateway_key_object(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    name: &str,
) -> Result<Object, Box<dyn std::error::Error + Send + Sync>> {
    let resp = sekai
        .find_by_external_id(gateway_request(FindByExternalIdRequest {
            external_id: format!("gateway_key:{name}"),
        }))
        .await?
        .into_inner();
    resp.object
        .ok_or_else(|| format!("gateway key {name:?} not found").into())
}

async fn ensure_gateway_objects(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    config: &GatewaySetupConfig,
) -> Result<(), tonic::Status> {
    let now = Utc::now().timestamp_millis();
    let project_id = format!("project-{}", sanitize_id(&config.project));
    let agent_id = format!("agent-{}", sanitize_id(&config.agent));
    let key_id = format!("gateway-key-{}", sanitize_id(&config.gateway_key_name));
    let budget_id = format!(
        "budget-{}-{}",
        sanitize_id(&config.agent),
        sanitize_id(&config.budget_period)
    );
    let policy_id = format!("policy-{}", sanitize_id(&config.project));

    upsert_object(
        sekai,
        Object {
            revision: String::new(),
            id: project_id.clone(),
            kind: "project".to_string(),
            name: config.project.clone(),
            namespace: config.project.clone(),
            external_id: format!("project:{}", config.project),
            properties: HashMap::from([("gateway_managed".to_string(), "true".to_string())]),
            created: now,
            updated: now,
        },
    )
    .await?;
    upsert_object(
        sekai,
        Object {
            revision: String::new(),
            id: agent_id.clone(),
            kind: "agent".to_string(),
            name: config.agent.clone(),
            namespace: config.project.clone(),
            external_id: format!("agent:{}", config.agent),
            properties: HashMap::from([
                ("project".to_string(), config.project.clone()),
                ("user_id".to_string(), format!("agent:{}", config.agent)),
            ]),
            created: now,
            updated: now,
        },
    )
    .await?;
    upsert_object(
        sekai,
        Object {
            revision: String::new(),
            id: key_id.clone(),
            kind: "gateway_key".to_string(),
            name: config.gateway_key_name.clone(),
            namespace: config.project.clone(),
            external_id: format!("gateway_key:{}", config.gateway_key_name),
            properties: HashMap::from([
                ("agent".to_string(), config.agent.clone()),
                ("project".to_string(), config.project.clone()),
                ("status".to_string(), "active".to_string()),
                ("tier".to_string(), config.tier.clone()),
                (
                    "key_hash".to_string(),
                    hash_gateway_key(&config.gateway_key_secret),
                ),
                ("secret_storage".to_string(), "sha256".to_string()),
            ]),
            created: now,
            updated: now,
        },
    )
    .await?;
    upsert_object(
        sekai,
        Object {
            revision: String::new(),
            id: budget_id.clone(),
            kind: "budget".to_string(),
            name: format!("{} {}", config.agent, config.budget_period),
            namespace: config.project.clone(),
            external_id: format!("budget:{}:{}", config.agent, config.budget_period),
            properties: HashMap::from([
                ("subject".to_string(), format!("agent:{}", config.agent)),
                ("max_tokens".to_string(), config.budget_tokens.to_string()),
                ("period".to_string(), config.budget_period.clone()),
            ]),
            created: now,
            updated: now,
        },
    )
    .await?;
    upsert_object(
        sekai,
        Object {
            revision: String::new(),
            id: policy_id.clone(),
            kind: "policy".to_string(),
            name: config.project.clone(),
            namespace: config.project.clone(),
            external_id: format!("policy:{}", config.project),
            properties: HashMap::from([
                ("namespace".to_string(), config.project.clone()),
                (
                    "allowed_runtimes".to_string(),
                    config.effective_allowed_runtimes().join(","),
                ),
                (
                    "allowed_models".to_string(),
                    if config.allowed_models.is_empty() {
                        config.default_model.clone()
                    } else {
                        config.allowed_models.join(",")
                    },
                ),
                (
                    "default_runtime".to_string(),
                    config.default_runtime.clone(),
                ),
                ("default_model".to_string(), config.default_model.clone()),
            ]),
            created: now,
            updated: now,
        },
    )
    .await?;

    for (id, from_id, to_id, relation) in [
        (
            format!("{key_id}-identifies-{agent_id}"),
            key_id.as_str(),
            agent_id.as_str(),
            "identifies",
        ),
        (
            format!("{key_id}-used-for-{agent_id}"),
            key_id.as_str(),
            agent_id.as_str(),
            "used_for",
        ),
        (
            format!("{agent_id}-works-on-{project_id}"),
            agent_id.as_str(),
            project_id.as_str(),
            "works_on",
        ),
        (
            format!("{agent_id}-owns-{project_id}"),
            agent_id.as_str(),
            project_id.as_str(),
            "owns",
        ),
        (
            format!("{budget_id}-limits-{agent_id}"),
            budget_id.as_str(),
            agent_id.as_str(),
            "limits",
        ),
        (
            format!("{budget_id}-targets-{agent_id}"),
            budget_id.as_str(),
            agent_id.as_str(),
            "targets",
        ),
        (
            format!("{policy_id}-applies-to-{project_id}"),
            policy_id.as_str(),
            project_id.as_str(),
            "applies_to",
        ),
        (
            format!("{policy_id}-targets-{project_id}"),
            policy_id.as_str(),
            project_id.as_str(),
            "targets",
        ),
    ] {
        let _ = sekai
            .create_link(gateway_request(CreateLinkRequest {
                fail_if_exists: false,
                link: Some(Link {
                    id,
                    from_id: from_id.to_string(),
                    to_id: to_id.to_string(),
                    relation: relation.to_string(),
                    created: now,
                }),
            }))
            .await?;
    }

    Ok(())
}

async fn upsert_object(
    sekai: &mut SekaiServiceClient<GatewayClient>,
    mut object: Object,
) -> Result<(), tonic::Status> {
    match sekai
        .find_by_external_id(gateway_request(FindByExternalIdRequest {
            external_id: object.external_id.clone(),
        }))
        .await
    {
        Ok(resp) => {
            if let Some(existing) = resp.into_inner().object {
                object.id = existing.id;
                object.created = existing.created;
                sekai
                    .update_object(gateway_request(UpdateObjectRequest {
                        object: Some(object),
                        lease_precondition: None,
                    }))
                    .await?;
                return Ok(());
            }
        }
        Err(err) if err.code() == tonic::Code::NotFound => {}
        Err(err) => return Err(err),
    }

    sekai
        .create_object(gateway_request(CreateObjectRequest {
            object: Some(object),
            lease_precondition: None,
        }))
        .await?;
    Ok(())
}

async fn ensure_llm_calls_dataset(
    sekai: &mut SekaiServiceClient<GatewayClient>,
) -> Result<(), tonic::Status> {
    let columns = chisei_provider::gateway_contract::LLM_CALLS_COLUMNS
        .iter()
        .copied()
        .map(|name| ColumnDef {
            name: name.to_string(),
            r#type: "string".to_string(),
            classification: crate::support::llm_call_column_classification(name).to_string(),
        })
        .collect();

    let dataset = Dataset {
        id: "llm_calls".to_string(),
        name: "LLM calls".to_string(),
        columns,
        object_id: String::new(),
        created: Utc::now().timestamp_millis(),
        partition_keys: Vec::new(),
    };
    match sekai
        .create_dataset(gateway_request(CreateDatasetRequest {
            dataset: Some(dataset.clone()),
        }))
        .await
    {
        Ok(_) => Ok(()),
        Err(err)
            if err.code() == tonic::Code::InvalidArgument
                && err.message().contains("UNIQUE constraint failed") =>
        {
            match sekai
                .update_dataset(gateway_request(UpdateDatasetRequest {
                    dataset: Some(dataset),
                }))
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if error.code() == tonic::Code::Unimplemented => Ok(()),
                Err(error) => Err(error),
            }
        }
        Err(err) => Err(err),
    }
}

fn gateway_request<T>(message: T) -> GrpcRequest<T> {
    let mut request = GrpcRequest::new(message);
    request
        .metadata_mut()
        .insert("x-principal", "local".parse().unwrap());
    request
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn normalize_key_create_args<I>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter().collect::<Vec<_>>();
    if args.first().is_some_and(|arg| !arg.starts_with('-')) {
        let name = args.remove(0);
        let mut normalized = vec!["--gateway-key-name".to_string(), name];
        normalized.extend(args);
        normalized
    } else {
        args
    }
}

pub fn usage() -> String {
    "Usage: sekaictl admin gateway setup [--target <grpc-url>] [--agent <name>] [--project <name>] [--gateway-key-name <name>] [--gateway-key <secret>] [--budget <tokens>] [--budget-period <day|week|month>] [--request-budget <requests>] [--request-budget-period <day|week|month>] [--scope-policy <scope>] [--tier <standard|background|heavy>] [--default-model <model>] [--allowed-model <model>] [--allowed-runtimes <list>] [--allowed-runtime <runtime>] [--default-runtime <runtime>] [--allowed-models <list>]\n       sekaictl admin gateway key <create|list|rotate|revoke> [options]\n\nRun `sekaictl admin gateway key --help` for gateway-key lifecycle commands.".to_string()
}

pub fn key_usage() -> String {
    "Usage: sekaictl admin gateway key create [<name>] [--target <grpc-url>] [--agent <name>] [--project <name>] [--gateway-key-name <name>] [--gateway-key <secret>] [--budget <tokens>] [--budget-period <day|week|month>] [--request-budget <requests>] [--request-budget-period <day|week|month>] [--scope-policy <scope>] [--tier <standard|background|heavy>] [--default-model <model>] [--allowed-model <model>] [--default-runtime <runtime>] [--allowed-runtimes <list>] [--allowed-runtime <runtime>] [--allowed-models <list>]\n       sekaictl admin gateway key list [--target <grpc-url>] [--project <name>]\n       sekaictl admin gateway key rotate [--target <grpc-url>] --gateway-key-name <name> --gateway-key <new-secret>\n       sekaictl admin gateway key revoke [--target <grpc-url>] --gateway-key-name <name>".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_masks_operator_supplied_virtual_key() {
        assert!(!displayed_virtual_key("codex-app", "s3cr3t").contains("s3cr3t"));
        assert_eq!(
            displayed_virtual_key("codex-app", &default_virtual_key("codex-app")),
            "sk-chisei-codex-app"
        );
    }

    #[test]
    fn parses_setup_args() {
        let config = GatewaySetupConfig::from_env_and_args([
            "--target".to_string(),
            "http://127.0.0.1:50051".to_string(),
            "--agent".to_string(),
            "codex-app".to_string(),
            "--project".to_string(),
            "sekai-chisei".to_string(),
            "--budget".to_string(),
            "42".to_string(),
            "--gateway-key".to_string(),
            "sk-chisei-test".to_string(),
            "--allowed-model".to_string(),
            "gpt-5.5".to_string(),
            "--request-budget".to_string(),
            "7".to_string(),
            "--request-budget-period".to_string(),
            "week".to_string(),
            "--scope-policy".to_string(),
            "agent:codex-app".to_string(),
        ])
        .unwrap();

        assert_eq!(config.chisei_grpc_target, "http://127.0.0.1:50051");
        assert_eq!(config.agent, "codex-app");
        assert_eq!(config.project, "sekai-chisei");
        assert_eq!(config.gateway_key_secret, "sk-chisei-test");
        assert_eq!(config.budget_tokens, 42);
        assert_eq!(config.allowed_models, vec!["gpt-5.5"]);
        assert_eq!(config.request_budget, Some(7));
        assert_eq!(config.request_budget_period, "week");
        assert_eq!(config.policy_scopes, vec!["agent:codex-app"]);
    }

    #[test]
    fn normalizes_key_create_positional_name() {
        assert_eq!(
            normalize_key_create_args([
                "codex-app".to_string(),
                "--agent".to_string(),
                "codex-app".to_string()
            ]),
            vec![
                "--gateway-key-name".to_string(),
                "codex-app".to_string(),
                "--agent".to_string(),
                "codex-app".to_string()
            ]
        );
        assert_eq!(
            normalize_key_create_args(["--agent".to_string(), "codex-app".to_string()]),
            vec!["--agent".to_string(), "codex-app".to_string()]
        );
    }
}
