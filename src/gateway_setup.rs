use std::collections::HashMap;

use crate::grpc::client::GatewayClient;
use chrono::Utc;
use tonic::Request as GrpcRequest;

use crate::gateway_keys::{default_virtual_key, hash_gateway_key};
use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::chisei::{SetBudgetLimitRequest, SetNamespacePolicyRequest};
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    ColumnDef, CreateDatasetRequest, CreateLinkRequest, CreateObjectRequest, Dataset,
    FindByExternalIdRequest, Link, ListFilter, ListObjectsRequest, Object, UpdateObjectRequest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySetupConfig {
    pub chisei_grpc_target: String,
    pub agent: String,
    pub project: String,
    pub gateway_key_name: String,
    pub gateway_key_secret: String,
    pub budget_tokens: i32,
    pub budget_period: String,
    pub allowed_models: Vec<String>,
    pub default_model: String,
    pub default_runtime: String,
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
            allowed_models: Vec::new(),
            default_model: "gpt-5.5".to_string(),
            default_runtime: "openai".to_string(),
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
                "--allowed-model" => config.allowed_models.push(next_arg(&mut args, &arg)?),
                "--allowed-models" => {
                    config.allowed_models = split_csv(&next_arg(&mut args, &arg)?);
                }
                "--default-model" => config.default_model = next_arg(&mut args, &arg)?,
                "--default-runtime" => config.default_runtime = next_arg(&mut args, &arg)?,
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
            ("chisei_grpc_target", &self.chisei_grpc_target),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} must not be empty"));
            }
        }
        if self.budget_tokens <= 0 {
            return Err("budget_tokens must be positive".to_string());
        }
        Ok(())
    }
}

pub async fn run_setup(
    config: GatewaySetupConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect_sekai(&config.chisei_grpc_target).await?;
    let mut sekai = SekaiServiceClient::new(channel.clone());
    let mut chisei = ChiseiServiceClient::new(channel);

    ensure_gateway_objects(&mut sekai, &config).await?;
    ensure_llm_calls_dataset(&mut sekai).await?;
    chisei
        .set_budget_limit(GrpcRequest::new(SetBudgetLimitRequest {
            user_id: format!("agent:{}", config.agent),
            max_tokens: config.budget_tokens,
            period_type: config.budget_period.clone(),
            subject: format!("agent:{}", config.agent),
            project: config.project.clone(),
            agent: config.agent.clone(),
            key_id: config.gateway_key_name.clone(),
        }))
        .await?;
    chisei
        .set_namespace_policy(GrpcRequest::new(SetNamespacePolicyRequest {
            namespace: config.project.clone(),
            allowed_runtimes: vec![config.default_runtime.clone()],
            allowed_models: if config.allowed_models.is_empty() {
                vec![config.default_model.clone()]
            } else {
                config.allowed_models.clone()
            },
            default_runtime: config.default_runtime.clone(),
            default_model: config.default_model.clone(),
            data_class: String::new(),
        }))
        .await?;

    println!("seeded chisei gateway setup");
    println!("  agent: {}", config.agent);
    println!("  project: {}", config.project);
    println!("  user_id: agent:{}", config.agent);
    println!("  gateway key name: {}", config.gateway_key_name);
    println!("  virtual key: {}", config.gateway_key_secret);
    println!(
        "  budget: {} tokens per {}",
        config.budget_tokens, config.budget_period
    );
    println!("  default model: {}", config.default_model);
    Ok(())
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
            println!("name\tproject\tagent\tstatus\tsecret_storage\tupdated");
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
                    }))
                    .await?
                    .into_inner();
                for object in resp.objects.iter() {
                    println!(
                        "{}\t{}\t{}\t{}\t{}\t{}",
                        object.name,
                        object.namespace,
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
                }))
                .await?;
            println!("rotated gateway key {name}");
            println!("run `chisei-gateway refresh` to clear running gateway key caches");
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
                }))
                .await?;
            println!("revoked gateway key {name}");
            println!("run `chisei-gateway refresh` to clear running gateway key caches");
        }
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
            id: key_id.clone(),
            kind: "gateway_key".to_string(),
            name: config.gateway_key_name.clone(),
            namespace: config.project.clone(),
            external_id: format!("gateway_key:{}", config.gateway_key_name),
            properties: HashMap::from([
                ("agent".to_string(), config.agent.clone()),
                ("project".to_string(), config.project.clone()),
                ("status".to_string(), "active".to_string()),
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
            id: policy_id.clone(),
            kind: "policy".to_string(),
            name: config.project.clone(),
            namespace: config.project.clone(),
            external_id: format!("policy:{}", config.project),
            properties: HashMap::from([
                ("namespace".to_string(), config.project.clone()),
                (
                    "allowed_runtimes".to_string(),
                    config.default_runtime.clone(),
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
        }))
        .await?;
    Ok(())
}

async fn ensure_llm_calls_dataset(
    sekai: &mut SekaiServiceClient<GatewayClient>,
) -> Result<(), tonic::Status> {
    let columns = [
        "request_id",
        "timestamp_ms",
        "agent",
        "project",
        "user_id",
        "key_id",
        "provider",
        "model",
        "resolved_model",
        "work_unit_id",
        "pipeline_sampled",
        "sample_reason",
        "sample_rate",
        "status",
        "error_type",
        "refusal_reason",
        "request_bytes",
        "latency_ms",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "cost_usd_micros",
        "cost_usd",
    ]
    .into_iter()
    .map(|name| ColumnDef {
        name: name.to_string(),
        r#type: "string".to_string(),
    })
    .collect();

    match sekai
        .create_dataset(gateway_request(CreateDatasetRequest {
            dataset: Some(Dataset {
                id: "llm_calls".to_string(),
                name: "LLM calls".to_string(),
                columns,
                object_id: String::new(),
                created: Utc::now().timestamp_millis(),
            }),
        }))
        .await
    {
        Ok(_) => Ok(()),
        Err(err)
            if err.code() == tonic::Code::InvalidArgument
                && err.message().contains("UNIQUE constraint failed") =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn gateway_request<T>(message: T) -> GrpcRequest<T> {
    let mut request = GrpcRequest::new(message);
    request
        .metadata_mut()
        .insert("x-principal", "chisei-gateway".parse().unwrap());
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
    "Usage: sekaictl gateway setup [--target <grpc-url>] [--agent <name>] [--project <name>] [--gateway-key-name <name>] [--gateway-key <secret>] [--budget <tokens>] [--budget-period <day|week|month>] [--default-model <model>] [--allowed-model <model>]\n       sekaictl gateway key <create|list|rotate|revoke> [options]\n\nRun `sekaictl gateway key --help` for gateway-key lifecycle commands.".to_string()
}

pub fn key_usage() -> String {
    "Usage: sekaictl gateway key create [<name>] [--target <grpc-url>] [--agent <name>] [--project <name>] [--gateway-key-name <name>] [--gateway-key <secret>] [--budget <tokens>] [--budget-period <day|week|month>] [--default-model <model>] [--allowed-model <model>]\n       sekaictl gateway key list [--target <grpc-url>] [--project <name>]\n       sekaictl gateway key rotate [--target <grpc-url>] --gateway-key-name <name> --gateway-key <new-secret>\n       sekaictl gateway key revoke [--target <grpc-url>] --gateway-key-name <name>".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::sekai::SekaiDb;
    use crate::grpc::chisei_service::ChiseiServiceImpl;
    use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
    use crate::grpc::pb::chisei::chisei_service_server::ChiseiServiceServer;
    use crate::grpc::pb::chisei::{CheckBudgetRequest, ResolvePolicyRequest};
    use crate::grpc::pb::sekai::sekai_service_server::SekaiServiceServer;
    use crate::grpc::sekai_service::SekaiServiceImpl;
    use std::sync::Arc;
    use tonic::transport::Server;

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
        ])
        .unwrap();

        assert_eq!(config.chisei_grpc_target, "http://127.0.0.1:50051");
        assert_eq!(config.agent, "codex-app");
        assert_eq!(config.project, "sekai-chisei");
        assert_eq!(config.gateway_key_secret, "sk-chisei-test");
        assert_eq!(config.budget_tokens, 42);
        assert_eq!(config.allowed_models, vec!["gpt-5.5"]);
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

    fn test_config() -> Config {
        Config {
            grpc_port: 0,
            ops_port: None,
            ops_bind: "127.0.0.1".into(),
            sekai_socket: None,
            db_path: ":memory:".into(),
            anthropic_api_key: None,
            openai_api_key: Some("test-openai-key".into()),
            ollama_url: "http://127.0.0.1:11434".into(),
            native_llm_url: None,
            auth_token: None,
            sample_rate: 0.0,
            sample_risk_threshold: 0.7,
            scoring_enabled: false,
            scoring_interval_secs: 60,
            scoring_model: "claude-opus-4-8".into(),
            scoring_batch_size: 16,
            default_data_class: "unclassified".into(),
            safe_egress_providers: vec![],
            leak_review_model: None,
            tls_cert: None,
            tls_key: None,
            allow_plaintext: false,
        }
    }

    async fn spawn_control_plane() -> (String, Arc<SekaiDb>) {
        let db = Arc::new(SekaiDb::new(":memory:").unwrap());

        let sekai_svc = SekaiServiceImpl::new(db.clone());
        let chisei_svc = ChiseiServiceImpl::new(db.clone(), test_config());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            Server::builder()
                .add_service(SekaiServiceServer::new(sekai_svc))
                .add_service(ChiseiServiceServer::new(chisei_svc))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        (format!("http://{addr}"), db)
    }

    #[tokio::test]
    async fn setup_seeds_gateway_objects_budget_policy_and_dataset() {
        let (target, db) = spawn_control_plane().await;
        run_setup(GatewaySetupConfig {
            chisei_grpc_target: target.clone(),
            agent: "codex-app".to_string(),
            project: "sekai-chisei".to_string(),
            gateway_key_name: "codex-app".to_string(),
            gateway_key_secret: "sk-chisei-codex-app".to_string(),
            budget_tokens: 42,
            budget_period: "day".to_string(),
            allowed_models: vec!["gpt-5.5".to_string()],
            default_model: "gpt-5.5".to_string(),
            default_runtime: "openai".to_string(),
        })
        .await
        .unwrap();

        assert!(
            db.find_by_external_id("project:sekai-chisei")
                .unwrap()
                .is_some()
        );
        assert!(db.find_by_external_id("agent:codex-app").unwrap().is_some());
        assert!(
            db.find_by_external_id("gateway_key:codex-app")
                .unwrap()
                .is_some()
        );
        assert!(
            db.find_by_external_id("budget:codex-app:day")
                .unwrap()
                .is_some()
        );
        let policy = db
            .find_by_external_id("policy:sekai-chisei")
            .unwrap()
            .unwrap();
        assert_eq!(
            policy.properties.get("default_model").map(String::as_str),
            Some("gpt-5.5")
        );
        assert!(db.get_dataset("llm_calls").unwrap().is_some());
        let key = db
            .find_by_external_id("gateway_key:codex-app")
            .unwrap()
            .unwrap();
        let agent = db.find_by_external_id("agent:codex-app").unwrap().unwrap();
        let project = db
            .find_by_external_id("project:sekai-chisei")
            .unwrap()
            .unwrap();
        let budget_obj = db
            .find_by_external_id("budget:codex-app:day")
            .unwrap()
            .unwrap();
        assert_eq!(
            db.get_links(&key.id, "identifies", &crate::domain::Direction::Outgoing)
                .unwrap()
                .first()
                .map(|link| link.to_id.as_str()),
            Some(agent.id.as_str())
        );
        assert_eq!(
            db.get_links(&agent.id, "works_on", &crate::domain::Direction::Outgoing)
                .unwrap()
                .first()
                .map(|link| link.to_id.as_str()),
            Some(project.id.as_str())
        );
        assert_eq!(
            db.get_links(
                &budget_obj.id,
                "limits",
                &crate::domain::Direction::Outgoing
            )
            .unwrap()
            .first()
            .map(|link| link.to_id.as_str()),
            Some(agent.id.as_str())
        );
        assert_eq!(
            db.get_links(
                &policy.id,
                "applies_to",
                &crate::domain::Direction::Outgoing
            )
            .unwrap()
            .first()
            .map(|link| link.to_id.as_str()),
            Some(project.id.as_str())
        );
        let expected_key_hash = hash_gateway_key("sk-chisei-codex-app");
        assert_eq!(
            key.properties.get("key_hash").map(String::as_str),
            Some(expected_key_hash.as_str())
        );
        assert_eq!(
            key.properties.get("status").map(String::as_str),
            Some("active")
        );

        let channel = connect_sekai(&target).await.unwrap();
        let mut chisei = ChiseiServiceClient::new(channel);
        let budget = chisei
            .check_budget(GrpcRequest::new(CheckBudgetRequest {
                user_id: "agent:codex-app".to_string(),
                estimated_tokens: 43,
                subject: "agent:codex-app".to_string(),
                project: "sekai-chisei".to_string(),
                agent: "codex-app".to_string(),
                key_id: "codex-app".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!budget.allowed);

        let resolved = chisei
            .resolve_policy(GrpcRequest::new(ResolvePolicyRequest {
                namespace: "sekai-chisei".to_string(),
                preferred_runtime: "openai".to_string(),
                preferred_model: "gpt-4.1".to_string(),
                subject: "agent:codex-app".to_string(),
                task_class: String::new(),
                project: "sekai-chisei".to_string(),
                agent: "codex-app".to_string(),
                user_id: String::new(),
                key_id: "codex-app".to_string(),
            }))
            .await
            .unwrap()
            .into_inner()
            .resolution
            .unwrap();
        assert_eq!(resolved.model, "gpt-5.5");

        run_gateway_key_command([
            "rotate".to_string(),
            "--target".to_string(),
            target.clone(),
            "--gateway-key-name".to_string(),
            "codex-app".to_string(),
            "--gateway-key".to_string(),
            "sk-chisei-codex-app-rotated".to_string(),
        ])
        .await
        .unwrap();
        let rotated_key = db
            .find_by_external_id("gateway_key:codex-app")
            .unwrap()
            .unwrap();
        assert_eq!(
            rotated_key.properties.get("key_hash").map(String::as_str),
            Some(hash_gateway_key("sk-chisei-codex-app-rotated").as_str())
        );
        assert_eq!(
            rotated_key.properties.get("status").map(String::as_str),
            Some("active")
        );
        assert!(rotated_key.properties.contains_key("rotated_at"));

        run_gateway_key_command([
            "list".to_string(),
            "--target".to_string(),
            target.clone(),
            "--project".to_string(),
            "sekai-chisei".to_string(),
        ])
        .await
        .unwrap();

        run_gateway_key_command([
            "revoke".to_string(),
            "--target".to_string(),
            target,
            "--gateway-key-name".to_string(),
            "codex-app".to_string(),
        ])
        .await
        .unwrap();
        let revoked_key = db
            .find_by_external_id("gateway_key:codex-app")
            .unwrap()
            .unwrap();
        assert_eq!(
            revoked_key.properties.get("status").map(String::as_str),
            Some("revoked")
        );
        assert!(revoked_key.properties.contains_key("revoked_at"));
    }

    #[tokio::test]
    async fn key_create_seeds_gateway_setup() {
        let (target, db) = spawn_control_plane().await;
        run_gateway_key_command([
            "create".to_string(),
            "worker-one".to_string(),
            "--target".to_string(),
            target,
            "--agent".to_string(),
            "worker-one".to_string(),
            "--project".to_string(),
            "sekai-chisei".to_string(),
            "--gateway-key".to_string(),
            "sk-chisei-worker-one".to_string(),
            "--budget".to_string(),
            "100".to_string(),
            "--allowed-model".to_string(),
            "gpt-5.5".to_string(),
        ])
        .await
        .unwrap();

        let key = db
            .find_by_external_id("gateway_key:worker-one")
            .unwrap()
            .unwrap();
        assert_eq!(key.name, "worker-one");
        assert_eq!(
            key.properties.get("agent").map(String::as_str),
            Some("worker-one")
        );
        assert_eq!(
            key.properties.get("key_hash").map(String::as_str),
            Some(hash_gateway_key("sk-chisei-worker-one").as_str())
        );
        assert!(db.get_dataset("llm_calls").unwrap().is_some());
    }
}
