use serde::{Deserialize, Serialize};

use crate::grpc::client::connect_sekai;
use crate::grpc::pb::chisei::SetBudgetLimitRequest;
use crate::grpc::pb::chisei::chisei_service_client::ChiseiServiceClient;
use crate::grpc::pb::sekai::sekai_service_client::SekaiServiceClient;
use crate::grpc::pb::sekai::{
    CreateCredentialRequest, EnsureTeamNamespaceRequest, ListCredentialsRequest,
    RotateCredentialRequest,
};

pub const TEAM_JOIN_BUNDLE_VERSION: &str = "sekai.team-join/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamJoinConfig {
    pub target: String,
    pub namespace: String,
    pub principal: String,
    pub role: String,
    pub shared_budget_tokens: Option<i32>,
    pub delegated_budget_tokens: Option<i32>,
    pub budget_period: String,
    pub allow_plaintext: bool,
    pub rotate_existing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamJoinBundle {
    pub version: String,
    pub endpoint: String,
    pub namespace: String,
    pub namespace_object_id: String,
    pub principal: String,
    pub role: String,
    pub credential: String,
    pub tls_ca_env: Option<String>,
    pub shared_budget_tokens: Option<i32>,
    pub delegated_budget_tokens: Option<i32>,
    pub budget_period: String,
    pub readiness: TeamReadiness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamReadiness {
    pub status: String,
    pub authenticated: bool,
    pub migrations_ready: bool,
    pub namespace_access_ready: bool,
    pub budgets_ready: bool,
    pub transport: String,
    pub degraded_reasons: Vec<String>,
}

impl TeamJoinConfig {
    pub fn from_env_and_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config = Self {
            target: std::env::var("CHISEI_GRPC_URL")
                .or_else(|_| std::env::var("SEKAI_SOCKET"))
                .unwrap_or_else(|_| "./data/sekai.sock".into()),
            namespace: String::new(),
            principal: String::new(),
            role: "viewer".into(),
            shared_budget_tokens: None,
            delegated_budget_tokens: None,
            budget_period: "week".into(),
            allow_plaintext: false,
            rotate_existing: false,
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--target" => config.target = next_arg(&mut args, &arg)?,
                "--namespace" => config.namespace = next_arg(&mut args, &arg)?,
                "--principal" => config.principal = next_arg(&mut args, &arg)?,
                "--role" => config.role = next_arg(&mut args, &arg)?,
                "--shared-budget" => {
                    config.shared_budget_tokens =
                        Some(parse_positive(&next_arg(&mut args, &arg)?, &arg)?)
                }
                "--delegated-budget" => {
                    config.delegated_budget_tokens =
                        Some(parse_positive(&next_arg(&mut args, &arg)?, &arg)?)
                }
                "--budget-period" => config.budget_period = next_arg(&mut args, &arg)?,
                "--allow-plaintext" => config.allow_plaintext = true,
                "--rotate-existing" => config.rotate_existing = true,
                "--help" | "-h" => return Err(usage().into()),
                other => {
                    return Err(format!(
                        "unknown team join argument {other:?}\n\n{}",
                        usage()
                    ));
                }
            }
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        validate_identifier("namespace", &self.namespace)?;
        validate_identifier("principal", &self.principal)?;
        if matches!(
            self.principal.as_str(),
            "root" | "local" | "anonymous" | "chisei-gateway"
        ) {
            return Err(format!(
                "principal {:?} is reserved for control-plane authentication",
                self.principal
            ));
        }
        if !matches!(self.role.as_str(), "viewer" | "editor" | "admin") {
            return Err("role must be viewer, editor, or admin".into());
        }
        if !matches!(self.budget_period.as_str(), "day" | "week" | "month") {
            return Err("budget period must be day, week, or month".into());
        }
        if self.target.starts_with("http://") && !self.allow_plaintext {
            return Err(
                "remote team setup requires https; use --allow-plaintext only on a trusted network"
                    .into(),
            );
        }
        if self.target.trim().is_empty() {
            return Err("target must not be empty".into());
        }
        Ok(())
    }
}

pub async fn run_team_join(config: TeamJoinConfig) -> Result<TeamJoinBundle, String> {
    let channel = connect_sekai(&config.target)
        .await
        .map_err(|error| format!("connect to team control plane: {error}"))?;
    let mut sekai = SekaiServiceClient::new(channel.clone());
    let mut chisei = ChiseiServiceClient::new(channel);
    let active_credential_exists = sekai
        .list_credentials(ListCredentialsRequest {
            tenant_id: String::new(),
        })
        .await
        .map_err(|error| format!("list principal credentials: {error}"))?
        .into_inner()
        .credentials
        .into_iter()
        .any(|credential| {
            credential.principal == config.principal && credential.status == "active"
        });
    if active_credential_exists && !config.rotate_existing {
        return Err(format!(
            "principal {:?} already has an active credential; reuse it or pass --rotate-existing to revoke and replace it",
            config.principal
        ));
    }

    // Rotate before granting new access so the old token never observes the
    // new role. Once issued, the token is always returned, even if later
    // provisioning is degraded, because its plaintext cannot be recovered.
    let credential = if active_credential_exists {
        sekai
            .rotate_credential(RotateCredentialRequest {
                principal: config.principal.clone(),
                managed_team_principal: true,
                tenant_id: String::new(),
            })
            .await
            .map_err(|error| format!("rotate principal credential: {error}"))?
            .into_inner()
            .token
    } else {
        sekai
            .create_credential(CreateCredentialRequest {
                principal: config.principal.clone(),
                managed_team_principal: true,
                tenant_id: String::new(),
            })
            .await
            .map_err(|error| format!("create principal credential: {error}"))?
            .into_inner()
            .token
    };

    let mut degraded_reasons = Vec::new();
    let namespace = sekai
        .ensure_team_namespace(EnsureTeamNamespaceRequest {
            namespace: config.namespace.clone(),
            principal: config.principal.clone(),
            role: config.role.clone(),
        })
        .await;
    let (namespace_object_id, namespace_access_ready) = match namespace {
        Ok(response) => match response.into_inner().namespace {
            Some(namespace) => (namespace.id, true),
            None => {
                degraded_reasons.push("team namespace response omitted namespace".into());
                (String::new(), false)
            }
        },
        Err(error) => {
            degraded_reasons.push(format!("ensure team namespace and access grants: {error}"));
            (String::new(), false)
        }
    };

    let budgets_configured =
        config.shared_budget_tokens.is_some() || config.delegated_budget_tokens.is_some();
    let mut budgets_ready = budgets_configured && namespace_access_ready;
    if namespace_access_ready {
        if let Some(max_tokens) = config.shared_budget_tokens
            && let Err(error) = chisei
                .set_budget_limit(SetBudgetLimitRequest {
                    project: config.namespace.clone(),
                    max_tokens,
                    period_type: config.budget_period.clone(),
                    ..Default::default()
                })
                .await
        {
            budgets_ready = false;
            degraded_reasons.push(format!("set shared namespace budget: {error}"));
        }
        if let Some(max_tokens) = config.delegated_budget_tokens
            && let Err(error) = chisei
                .set_budget_limit(SetBudgetLimitRequest {
                    project: config.namespace.clone(),
                    agent: config.principal.clone(),
                    max_tokens,
                    period_type: config.budget_period.clone(),
                    ..Default::default()
                })
                .await
        {
            budgets_ready = false;
            degraded_reasons.push(format!("set delegated principal budget: {error}"));
        }
    } else if budgets_configured {
        degraded_reasons.push("budget setup skipped until namespace access is ready".into());
    }

    let transport = if config.target.starts_with("https://") {
        "tls"
    } else if config.target.starts_with("http://") {
        degraded_reasons.push("remote transport explicitly allows plaintext".into());
        "plaintext"
    } else {
        "local_socket"
    };
    if !budgets_configured {
        degraded_reasons.push("no shared or delegated budget was configured".into());
    }
    let status = if degraded_reasons.is_empty() {
        "ready"
    } else {
        "degraded"
    };
    Ok(TeamJoinBundle {
        version: TEAM_JOIN_BUNDLE_VERSION.into(),
        endpoint: config.target,
        namespace: config.namespace,
        namespace_object_id,
        principal: config.principal,
        role: config.role,
        credential,
        tls_ca_env: std::env::var("SEKAI_TLS_CA")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        shared_budget_tokens: config.shared_budget_tokens,
        delegated_budget_tokens: config.delegated_budget_tokens,
        budget_period: config.budget_period,
        readiness: TeamReadiness {
            status: status.into(),
            authenticated: true,
            migrations_ready: true,
            namespace_access_ready,
            budgets_ready,
            transport: transport.into(),
            degraded_reasons,
        },
    })
}

pub fn usage() -> &'static str {
    "Usage: sekaictl team join --namespace <name> --principal <name> [--role viewer|editor|admin] [--shared-budget <tokens>] [--delegated-budget <tokens>] [--budget-period day|week|month] [--target <url-or-socket>] [--allow-plaintext] [--rotate-existing]"
}

fn validate_identifier(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(format!("{label} must match [a-zA-Z0-9._-]+"));
    }
    Ok(())
}

fn parse_positive(value: &str, flag: &str) -> Result<i32, String> {
    let parsed = value
        .parse::<i32>()
        .map_err(|_| format!("{flag} must be a positive integer"))?;
    if parsed <= 0 {
        return Err(format!("{flag} must be a positive integer"));
    }
    Ok(parsed)
}

fn next_arg<I>(args: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_secure_remote_team_join() {
        let config = TeamJoinConfig::from_env_and_args(
            [
                "--target",
                "https://sekai.example",
                "--namespace",
                "research",
                "--principal",
                "alice",
                "--role",
                "editor",
                "--shared-budget",
                "100000",
                "--delegated-budget",
                "25000",
            ]
            .map(str::to_string),
        )
        .unwrap();
        assert_eq!(config.role, "editor");
        assert_eq!(config.shared_budget_tokens, Some(100_000));
        assert_eq!(config.delegated_budget_tokens, Some(25_000));
    }

    #[test]
    fn rejects_plaintext_remote_team_join_by_default() {
        let error = TeamJoinConfig::from_env_and_args(
            [
                "--target",
                "http://sekai.example",
                "--namespace",
                "research",
                "--principal",
                "alice",
            ]
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(error.contains("requires https"));
    }

    #[test]
    fn rejects_invalid_scope_and_budget() {
        let invalid_scope = TeamJoinConfig::from_env_and_args(
            ["--namespace", "team one", "--principal", "alice"].map(str::to_string),
        )
        .unwrap_err();
        assert!(invalid_scope.contains("namespace must match"));

        let invalid_budget = TeamJoinConfig::from_env_and_args(
            [
                "--namespace",
                "team-one",
                "--principal",
                "alice",
                "--shared-budget",
                "0",
            ]
            .map(str::to_string),
        )
        .unwrap_err();
        assert!(invalid_budget.contains("positive integer"));

        let reserved = TeamJoinConfig::from_env_and_args(
            ["--namespace", "team-one", "--principal", "chisei-gateway"].map(str::to_string),
        )
        .unwrap_err();
        assert!(reserved.contains("reserved"));
    }
}
